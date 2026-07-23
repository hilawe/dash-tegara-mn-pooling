/**
 * The L1 governance read side shared by the cast-receipt engines (v1 castReceipt.cjs
 * and v2 castReceiptV2.cjs): a minimal JSON-RPC client for the Core node named by
 * FORK_RPC_URL, the hardened current-funding-vote fetch (batch-3 review shape:
 * positional parsing, collateral binding, lowercase normalization, tolerant of
 * unparseable NON-funding records, loud on ambiguity), and the client-side
 * recomputation of Core's own vote hash.
 *
 * The vote hash covers (collateral outpoint, proposal hash, signal, outcome, time),
 * per CGovernanceVote::UpdateHash at the pinned commit 8c9f166a3: a legacy-format
 * CHashWriter stream of the outpoint, a zero byte and 0xffffffff (dummy txin
 * remnants), the parent hash, the two int-serialized enums (signal THEN outcome),
 * and the int64 time, double-SHA256, displayed reversed. Reproduced here and
 * verified against live vote hashes, so a receipt's claimed vote fields can be
 * authenticated against the hash they must have produced. What this proves is FIELD
 * INTEGRITY (these exact fields made this hash); that Core ACCEPTED the vote at the
 * time remains the live watcher's observation.
 */
const crypto = require("crypto");

const VOTE_SIGNALS = { funding: 1, valid: 2, delete: 3, endorsed: 4 };
const VOTE_OUTCOMES = { yes: 1, no: 2, abstain: 3 };

const computeVoteHash = (collateralTxidHex, vout, proposalHex, signal, outcome, time) => {
  if (!(signal in VOTE_SIGNALS)) throw new Error(`unknown vote signal "${signal}"`);
  if (!(outcome in VOTE_OUTCOMES)) throw new Error(`unknown vote outcome "${outcome}"`);
  if (!/^[0-9a-f]{64}$/i.test(collateralTxidHex)) throw new Error("collateral txid is not 64-hex");
  if (!/^[0-9a-f]{64}$/i.test(proposalHex)) throw new Error("proposal hash is not 64-hex");
  if (!Number.isInteger(vout) || vout < 0 || vout > 0xffffffff) throw new Error(`vout ${vout} outside uint32`);
  if (!Number.isSafeInteger(time) || time <= 0) throw new Error(`time ${time} is not a positive safe integer`);
  const le32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
  const le64 = (n) => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; };
  const revHex = (h) => Buffer.from(h, "hex").reverse();
  const stream = Buffer.concat([
    revHex(collateralTxidHex), le32(vout),
    Buffer.from([0]),
    Buffer.from([0xff, 0xff, 0xff, 0xff]),
    revHex(proposalHex),
    le32(VOTE_SIGNALS[signal]), le32(VOTE_OUTCOMES[outcome]),
    le64(time),
  ]);
  const sha256d = crypto.createHash("sha256")
    .update(crypto.createHash("sha256").update(stream).digest()).digest();
  return sha256d.reverse().toString("hex");
};

const forkRpc = async (method, params) => {
  const u = new URL(process.env.FORK_RPC_URL);
  const auth = u.username ? "Basic " + Buffer.from(`${u.username}:${u.password}`).toString("base64") : null;
  u.username = ""; u.password = "";
  const res = await fetch(u.toString(), {
    method: "POST",
    headers: { "content-type": "application/json", ...(auth ? { authorization: auth } : {}) },
    body: JSON.stringify({ jsonrpc: "1.0", id: "cast", method, params }),
  });
  // Core reports RPC-level errors as HTTP 500 WITH a JSON-RPC error body, so parse the
  // body before treating a non-ok status as a transport failure: a caller needs to tell
  // "Core answered with an error" (e.g. an unknown proTxHash) from "Core is unreachable".
  // Both are thrown, but the RPC-error case carries e.rpcError = { code, message } so the
  // caller can act on WHAT Core said, not just that something failed.
  let body = null;
  try { body = await res.json(); } catch { /* no JSON body, transport-level failure */ }
  if (body && body.error) {
    const err = new Error(`fork RPC ${method} error: ${body.error.message}`);
    err.rpcError = { code: body.error.code, message: body.error.message };
    throw err;
  }
  if (!res.ok) throw new Error(`fork RPC ${method} failed: HTTP ${res.status}`);
  return body.result;
};

/**
 * The masternode's current funding vote on the proposal, as Core reports it.
 * getcurrentvotes returns { <voteHash>: "<collateralTxid>-<vout>:<time>:<outcome>:<signal>:<weight>" };
 * filtered by the node's collateral, Core keeps at most one CURRENT vote per signal,
 * and this parser enforces that invariant instead of assuming it: every funding
 * record must reference the requested masternode's collateral, carry a yes/no/abstain
 * outcome and a sane timestamp, and there must be zero or one of them.
 */
/** The masternode's collateral outpoint (protx info), needed for vote-hash recomputation. */
const fetchCollateral = async (proTxHex) => {
  const info = await forkRpc("protx", ["info", proTxHex]);
  return { txid: info.collateralHash, vout: Number(info.collateralIndex) };
};

/** The masternode's #187 share table from protx info (registration verification). Returns null when the node
 *  is not a shared registration (vanilla DIP3 exposes no shares), so the caller can fall
 *  back to an existence-only check; otherwise a normalized array of
 *  { amountDuffs, rewardAddress, refundAddress }. The reward destination follows the #187
 *  rule that a zero-length rewardScript means "use the refund script", surfaced here as
 *  the refund address when the fork exposes no rewardAddress for a share. */
const fetchShareTable = async (proTxHex, atBlockHash) => {
  const params = atBlockHash ? ["info", proTxHex, atBlockHash] : ["info", proTxHex];
  const info = await forkRpc("protx", params);
  const shares = (info.state || {}).shares;
  if (!Array.isArray(shares) || shares.length === 0) return null;
  return shares.map((s) => ({
    amountDuffs: String(s.amount),
    rewardAddress: s.rewardAddress || s.refundAddress || null,
    refundAddress: s.refundAddress || null,
  }));
};

const fetchL1Vote = async (proTxHex, proposalHex) => {
  const info = await forkRpc("protx", ["info", proTxHex]);
  const expectedOutpoint = `${info.collateralHash}-${info.collateralIndex}`;
  const votes = await forkRpc("gobject",
    ["getcurrentvotes", proposalHex, info.collateralHash, String(info.collateralIndex)]);
  const funding = [];
  // a record that does not parse is remembered but does not stop the scan: a future
  // Core adding a signal or field must not hide a perfectly valid funding vote later
  // in the map. If NO funding vote parses and something was unparseable, that is an
  // error, not "no vote".
  const unparseable = [];
  for (const [voteHash, s] of Object.entries(votes)) {
    const parts = String(s).split(":");
    if (parts.length !== 5) { unparseable.push(s); continue; }
    const [outpoint, timeStr, outcomeRaw, signalRaw, weightStr] = parts;
    // Core emits lowercase today; normalize so a future mixed-case change cannot
    // produce a false deviation
    const outcome = outcomeRaw.toLowerCase();
    const signal = signalRaw.toLowerCase();
    if (signal !== "funding") continue;
    if (outpoint !== expectedOutpoint) {
      throw new Error(`funding vote outpoint ${outpoint} is not the masternode's collateral ${expectedOutpoint}`);
    }
    if (!/^[0-9a-f]{64}$/i.test(voteHash)) throw new Error(`unexpected vote hash: ${voteHash}`);
    if (!["yes", "no", "abstain"].includes(outcome)) throw new Error(`unexpected funding vote outcome: ${outcome}`);
    const time = Number(timeStr);
    if (!Number.isSafeInteger(time) || time <= 0) throw new Error(`unexpected vote timestamp: ${timeStr}`);
    if (!/^\d+$/.test(weightStr)) throw new Error(`unexpected vote weight: ${weightStr}`);
    funding.push({ voteHash: voteHash.toLowerCase(), collateral: outpoint, time, outcome, signal });
  }
  if (funding.length > 1) {
    throw new Error(`Core reports ${funding.length} current funding votes for one masternode; expected at most 1`);
  }
  if (funding.length === 0 && unparseable.length > 0) {
    throw new Error(`no funding vote parsed and ${unparseable.length} vote record(s) were unparseable ` +
      `(first: ${unparseable[0]}); refusing to treat that as "no vote"`);
  }
  if (unparseable.length > 0) {
    console.log(`NOTE: ${unparseable.length} non-funding vote record(s) did not parse and were skipped`);
  }
  if (funding.length === 1) {
    // self-check: the parsed fields must reproduce Core's own vote hash; a mismatch
    // means parser or serialization drift in THIS code, not operator behavior
    const v = funding[0];
    const recomputed = computeVoteHash(info.collateralHash, Number(info.collateralIndex),
      proposalHex, v.signal, v.outcome, v.time);
    if (recomputed !== v.voteHash) {
      throw new Error(`internal: parsed vote fields do not reproduce Core's vote hash ` +
        `(${recomputed} vs ${v.voteHash}); parser or serialization drift`);
    }
  }
  return funding[0] || null;
};

module.exports = { forkRpc, fetchL1Vote, fetchCollateral, fetchShareTable, computeVoteHash };
