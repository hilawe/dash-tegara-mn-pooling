/**
 * The pure core of pool formation, shared by the member client (pledge/pledges) and the
 * operator script (formation.cjs) so the convention can never drift between them
 * (independent-review finding). No I/O, no SDK; offline-testable.
 *
 * The FORMING convention: a forming pool's proTxHash placeholder is 16 ZERO BYTES
 * followed by 16 random bytes. This is a reserved APPLICATION namespace, not a protocol
 * rule: a real proTxHash with 128 leading zero bits is computationally out of reach, so
 * a collision is not a practical concern, but every place a real node hash enters the
 * system must refuse hashes inside the reserved namespace (formation.cjs complete does).
 * The collateral target is implied by nodeType.
 */
const crypto = require("crypto");
const { toBig } = require("./compoundJournal.cjs");

const TARGETS = { regular: 100000000000n, evo: 400000000000n }; // 1000 / 4000 DASH
const FORMING_PREFIX_BYTES = 16;

const isFormingHash = (buf) => {
  if (!Buffer.isBuffer(buf) || buf.length !== 32) throw new Error("proTxHash must be a 32-byte buffer");
  return buf.subarray(0, FORMING_PREFIX_BYTES).every((b) => b === 0);
};

/** One aggregate per OWNER (the contract allows one share per owner per pool, so a
 *  member with several pledges gets one share carrying their sum; independent-review
 *  blocker). Rows: [{id, owner, amount(BigInt), at}]. Deterministic order: by first
 *  pledge age, then owner. */
const aggregateByOwner = (rows) => {
  const byOwner = new Map();
  for (const r of [...rows].sort((a, b) => a.at - b.at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))) {
    const agg = byOwner.get(r.owner) || { owner: r.owner, amount: 0n, reqIds: [], at: r.at };
    agg.amount += toBig(r.amount, "pledge amount");
    agg.reqIds.push(r.id);
    byOwner.set(r.owner, agg);
  }
  return [...byOwner.values()];
};

/** Largest-remainder weights over OWNER aggregates that sum exactly to the target:
 *  floor(amount*10000/target) each, then +1 by largest remainder (age order, then owner,
 *  as the deterministic tiebreak) until the sum is exactly 10000. Throws unless the
 *  amounts sum to the target, because weights for a partial set are meaningless (the
 *  resume-recalculation blocker). */
const allocateBps = (owners, target) => {
  const total = owners.reduce((s, o) => s + o.amount, 0n);
  if (total !== target) {
    throw new Error(`allocation requires an exact fill: aggregates sum to ${total}, target ${target}`);
  }
  if (owners.some((o) => o.amount * 10000n < target)) {
    throw new Error("an aggregate below one basis point of the target cannot carry a share");
  }
  const alloc = owners.map((o) => ({
    ...o,
    bps: Number((o.amount * 10000n) / target),
    rem: (o.amount * 10000n) % target,
  }));
  let deficit = 10000 - alloc.reduce((s, a) => s + a.bps, 0);
  const byRem = [...alloc].sort((a, b) =>
    (b.rem > a.rem ? 1 : b.rem < a.rem ? -1 : a.at - b.at || (a.owner < b.owner ? -1 : a.owner > b.owner ? 1 : 0)));
  for (let i = 0; deficit > 0; i = (i + 1) % byRem.length, deficit--) byRem[i].bps += 1;
  return alloc;
};

/** registration verification full L1 registration verification: compare a completion manifest's committed
 *  participation against the #187 share table the masternode was ACTUALLY registered
 *  with. Both sides arrive normalized to [{ amountDuffs: string, rewardAddress: string }]
 *  (the caller derives the manifest side's addresses from its reward scripts and reads
 *  the share side's rewardAddress from protx info).
 *
 *  Returns { ok, mismatches, incomparable, reason }. Hard checks (any mismatch fails
 *  completion): participant count, collateral total, and the MULTISET OF
 *  (amount, reward-destination) PAIRS. The pairing matters: comparing amounts and rewards
 *  as two separate multisets would let a cross-amount reward swap slip through
 *  (600 to A / 400 to B registered as 600 to B / 400 to A has the same amount set and the
 *  same reward set but the wrong allocation), so the tuple is the unit of comparison
 *  (review finding). When a reward destination cannot be resolved on either side, the
 *  result is `incomparable` (a valid #187 reward is P2PKH/P2SH and always resolves, so an
 *  unresolved entry is suspicious); the caller must FAIL CLOSED on that, not proceed.
 *
 *  What this does NOT verify, so it is the recorded registration verification residual and it is BROADER than a
 *  mere owner permutation (review finding): the manifest records no per-member share
 *  OWNER KEY ID and no per-member REFUND (principal) destination, so those two fields are
 *  not checked at all. A registration with ARBITRARY owner keys and ARBITRARY refund
 *  scripts passes as long as the (amount, reward) pairs match, which leaves the principal
 *  destinations unverified. Closing this needs the formation flow to record each member's
 *  owner key id and refund script and compare complete share tuples. */
const bagOf = (arr) => { const m = {}; for (const k of arr) m[k] = (m[k] || 0) + 1; return m; };
const bagEqual = (a, b) => {
  const ka = Object.keys(a); if (ka.length !== Object.keys(b).length) return false;
  return ka.every((k) => a[k] === b[k]);
};
const verifyRegistration = (committed, registered, target) => {
  const mismatches = [];
  if (registered.length !== committed.length) {
    mismatches.push(`registered ${registered.length} share(s), the manifest committed ` +
      `${committed.length} participant(s)`);
  }
  const regSum = registered.reduce((s, x) => s + toBig(x.amountDuffs, "share amount"), 0n);
  if (regSum !== toBig(target, "target")) {
    mismatches.push(`registered shares sum to ${regSum} duffs, target is ${target}`);
  }
  // a reward destination that will not resolve on either side makes the (amount, reward)
  // pairing uncheckable; report it as incomparable so the caller FAILS CLOSED (a real
  // #187 reward is address-resolvable, so this is not a routine case to wave through)
  const needBad = committed.some((x) => !x.rewardAddress || x.rewardAddress === "(unresolved)");
  const haveBad = registered.some((x) => !x.rewardAddress);
  if (needBad || haveBad) {
    return { ok: false, incomparable: true, mismatches,
      reason: "a reward destination could not be resolved on the " +
        (needBad ? "manifest" : "registered") + " side, so the (amount, reward) pairing " +
        "cannot be verified" };
  }
  // the multiset of (amount, reward) PAIRS, so a cross-amount reward swap is caught
  const pairKey = (x) => `${x.amountDuffs}|${x.rewardAddress}`;
  if (!bagEqual(bagOf(committed.map(pairKey)), bagOf(registered.map(pairKey)))) {
    mismatches.push("the (amount, reward destination) pairing differs between the manifest " +
      "and the registered share table");
  }
  return { ok: mismatches.length === 0, mismatches };
};

// ---------------------------------------------------------------------------
// Canonical allocation preimage for the on-ledger completion receipt (v8).
// See docs/COMPLETION_RECEIPT_SPEC.md ("Canonical allocation preimage"). Pure and
// offline, so an independent implementation can reproduce the exact bytes and hash
// from the published golden vector. Commits to the ALLOCATION (poolId + member split),
// NOT the claim provenance (mutable/deletable) and NOT the real node hash: the manifest
// is finalized during formation, before the L1 registration exists, so a preimage that
// carried the real proTxHash could not be produced from the frozen manifest (follow-up
// finding). The node binding is the receipt's top-level proTxHash field, indexed by
// byProTx, not part of this hash.
const ALLOC_DOMAIN = "tegara-completion-allocation";
const ALLOC_FORMAT_VERSION = 1;
const ALLOC_MIN_OWNERS = 1;
const ALLOC_MAX_OWNERS = 8;              // DIRECT covenant participants (M6/C-F); == participantCount 1..8
const ALLOC_MAX_BYTES = 2048;            // the v8 allocationRows byteArray maxItems; the helper must
                                         // match the on-ledger schema, so refuse bytes it would reject
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const DEC_RE = /^[1-9][0-9]*$/;          // base-10, no leading zero
const HEX_EVEN_RE = /^([0-9a-f]{2}){1,34}$/; // lowercase, WHOLE bytes, <=68 chars (a #187 reward script)

/** Decode a base58 identity string to its raw 32 bytes, or null if it is not a well-formed
 *  32-byte identifier. Owners are sorted by these bytes (NOT base58 string order, which is
 *  not the same ordering), so the sort is portable across implementations. Dependency-free
 *  little-endian accumulator, the same decode tally.cjs uses for its identifier check. */
const decodeId32 = (s) => {
  // decode the whole alphabet-valid string, then require EXACTLY 32 decoded bytes: a valid
  // 32-byte id with leading zero bytes is shorter than 43 chars (each leading zero byte is one
  // '1'), so a fixed 42..44 length window is not total over 32-byte ids (review finding). The
  // 44-char cap only bounds pathological input; the byte count is the real gate.
  if (typeof s !== "string" || !/^[1-9A-HJ-NP-Za-km-z]{1,44}$/.test(s)) return null;
  const le = [0];
  for (const ch of s) {
    let carry = B58_ALPHABET.indexOf(ch);
    if (carry < 0) return null;
    for (let i = 0; i < le.length; i++) { carry += le[i] * 58; le[i] = carry & 0xff; carry >>= 8; }
    while (carry) { le.push(carry & 0xff); carry >>= 8; }
  }
  let zeros = 0;
  for (const ch of s) { if (ch === "1") zeros++; else break; }
  const valueBE = (le.length === 1 && le[0] === 0) ? [] : le.slice().reverse(); // LE accumulator -> BE value
  const out = Buffer.concat([Buffer.alloc(zeros, 0), Buffer.from(valueBE)]);
  return out.length === 32 ? out : null;
};

/** Normalize an identifier given as EITHER a base58 string OR raw 32 bytes to a 32-byte Buffer,
 *  or null. Lets the verifier accept both the embedded canonical base58 form and a ledger-native
 *  byteArray for the same top-level field (review finding: the receipt document's poolId /
 *  contractId arrive as bytes, not base58). */
const toId32 = (v) => {
  if (typeof v === "string") return decodeId32(v);
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) { const b = Buffer.from(v); return b.length === 32 ? b : null; }
  return null;
};

/** The age-independent largest-remainder validity condition, SHARED by the builder and the
 *  verifier so they accept exactly the same allocations (review finding: an asymmetric check
 *  lets the builder emit a receipt its own verifier rejects). Returns an error string or null.
 *  allocateBps derives each bps from its amount as floor(amount*10000/target), then distributes
 *  the deficit as +1 to the largest remainders, so every valid bps is floor or floor+1, no owner
 *  is below one basis point (floor>=1), the amounts fill the target exactly, and the bps sum to
 *  10000. This does NOT reproduce the age tiebreak among EQUAL remainders (the receipt omits
 *  pledge age by design), but it rejects a bps set that does not match the amounts at all, e.g.
 *  amounts 50/30/20 carrying 4000/4000/2000 instead of 5000/3000/2000. `entries` is
 *  [{amount: base-10 string, bps: integer}]; `target` is a base-10 string >= 1. */
const allocationConsistencyError = (entries, target) => {
  const T = BigInt(target);
  let amtSum = 0n, bpsSum = 0;
  let minIncRem = null;   // smallest remainder among the rounded-up (floor+1) rows
  let maxFloorRem = null; // largest remainder among the floor rows
  for (const { amount, bps } of entries) {
    const a = BigInt(amount);
    const scaled = a * 10000n;
    const floor = scaled / T;
    const rem = scaled % T;
    if (floor < 1n) return "an owner below one basis point of the target cannot carry a share";
    const b = BigInt(bps);
    if (b === floor) { if (maxFloorRem === null || rem > maxFloorRem) maxFloorRem = rem; }
    else if (b === floor + 1n) { if (minIncRem === null || rem < minIncRem) minIncRem = rem; }
    else return `bps ${bps} is not the largest-remainder share of amount ${amount} at target ${target}`;
    amtSum += a; bpsSum += bps;
  }
  if (amtSum !== T) return `amounts sum to ${amtSum} duffs, not the target ${target}`;
  if (bpsSum !== 10000) return `bps sum ${bpsSum}, expected exactly 10000`;
  // the rounding increment must go to the LARGEST remainders: every rounded-up row must rank at
  // least as high as every floor row. Ties at the cutoff remainder stay interchangeable, because
  // the final tiebreak in allocateBps is pledge age, which the receipt deliberately omits.
  if (minIncRem !== null && maxFloorRem !== null && minIncRem < maxFloorRem) {
    return "the rounding increment is not assigned to the largest remainders";
  }
  return null;
};

/** Build the fixed-shape canonical allocation array from a completion manifest, sorted and
 *  validated. Throws on any malformed field so a bad manifest never yields a receipt that
 *  cannot be re-verified. Shape:
 *    [ domain, formatVersion, contractId, poolId, targetDuffs, [ [owner, amountDuffs, bps, rewardScriptHex], ... ] ] */
const buildAllocationArray = (contractId, manifest) => {
  const fail = (why) => { throw new Error(`allocation preimage invalid (${why})`); };
  if (decodeId32(contractId) === null) fail("contractId is not a base58 32-byte id");
  if (!manifest || typeof manifest !== "object") fail("manifest missing");
  if (decodeId32(manifest.poolId) === null) fail("manifest.poolId is not a base58 32-byte id");
  if (typeof manifest.target !== "string" || !DEC_RE.test(manifest.target)) fail("manifest.target not a base-10 duff string");
  if (!Array.isArray(manifest.owners)) fail("manifest.owners is not an array");
  const n = manifest.owners.length;
  if (n < ALLOC_MIN_OWNERS || n > ALLOC_MAX_OWNERS) fail(`owner count ${n} outside ${ALLOC_MIN_OWNERS}..${ALLOC_MAX_OWNERS}`);

  const seen = new Set();
  const rows = manifest.owners.map((o, i) => {
    if (!o || typeof o !== "object") fail(`owner ${i} is not an object`);
    const id = decodeId32(o.owner);
    if (id === null) fail(`owner ${i} is not a base58 32-byte id`);
    if (seen.has(o.owner)) fail(`owner ${i} is a duplicate`);
    seen.add(o.owner);
    if (typeof o.amountDuffs !== "string" || !DEC_RE.test(o.amountDuffs)) fail(`owner ${i} amountDuffs not a base-10 duff string`);
    if (!Number.isSafeInteger(o.bps) || o.bps < 1 || o.bps > 10000) fail(`owner ${i} bps ${o.bps} outside 1..10000`);
    const scriptLc = typeof o.rewardScriptHex === "string" ? o.rewardScriptHex.toLowerCase() : null;
    if (scriptLc === null || !HEX_EVEN_RE.test(scriptLc)) fail(`owner ${i} rewardScriptHex not even-length lowercase hex`);
    return { id, row: [o.owner, o.amountDuffs, o.bps, scriptLc] };
  });
  // the bps must be the largest-remainder shares of the amounts (checks the sum, the exact fill,
  // and each bps against its amount), the same condition the verifier enforces
  const cErr = allocationConsistencyError(manifest.owners.map((o) => ({ amount: o.amountDuffs, bps: o.bps })), manifest.target);
  if (cErr) fail(cErr);
  rows.sort((a, b) => Buffer.compare(a.id, b.id)); // by DECODED 32-byte owner id
  return [ALLOC_DOMAIN, ALLOC_FORMAT_VERSION, contractId, manifest.poolId, manifest.target, rows.map((r) => r.row)];
};

/** The canonical allocation preimage BYTES (UTF-8 JSON of the fixed-shape array). The bytes
 *  assigned to the receipt's allocationRows field are exactly these (Buffer.from utf8), which
 *  is why the byteArray field must be given a Buffer, never a raw string. */
const allocationPreimage = (contractId, manifest) => {
  const bytes = Buffer.from(JSON.stringify(buildAllocationArray(contractId, manifest)), "utf8");
  if (bytes.length > ALLOC_MAX_BYTES) {
    throw new Error(`allocation preimage invalid (allocationRows ${bytes.length} bytes exceeds the ${ALLOC_MAX_BYTES}-byte schema bound)`);
  }
  return bytes;
};

/** sha256 over the preimage bytes; the receipt's compact allocationHash content id. */
const allocationHash = (bytes) => {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) throw new Error("allocationHash needs bytes");
  return crypto.createHash("sha256").update(bytes).digest();
};

/** Verify a receipt's embedded allocation is self-consistent and canonical, from the receipt
 *  ALONE (the self-contained third-party property). `receipt` carries `allocationRows` (the
 *  embedded bytes) and `allocationHash` (32 bytes), and optionally the top-level `poolId`
 *  (base58), `targetDuffs` (string), and `participantCount` for the correspondence check.
 *  Returns { ok, reason?, poolId, targetDuffs, participantCount }.
 *  Checks: hash recompute + Buffer.equals; parse and validate the array (domain, version, the
 *  EXPECTED contractId, poolId, target, 1..8 rows, strict decoded-byte order, bps sum 10000);
 *  a byte-exact re-serialization so a non-canonical encoding is rejected; and top-level
 *  correspondence. Does NOT prove the shares still exist or match (honesty ceiling). */
const verifyReceiptAllocation = (contractId, receipt) => {
  const bad = (reason) => ({ ok: false, reason });
  // the whole body runs under a guard so ANY unexpected throw on hostile input (a crafted object, a
  // proxied typed array, a getter that throws) fails CLOSED rather than crashing the caller
  try {
  const wantContract = toId32(contractId);
  if (wantContract === null) return bad("expected contractId is not a base58 32-byte id");
  if (!receipt || typeof receipt !== "object") return bad("receipt missing");
  const rowsBytes = receipt.allocationRows;
  if (!Buffer.isBuffer(rowsBytes) && !(rowsBytes instanceof Uint8Array)) return bad("allocationRows is not bytes");
  const rowsBuf = Buffer.from(rowsBytes);
  if (rowsBuf.length > ALLOC_MAX_BYTES) return bad(`allocationRows ${rowsBuf.length} bytes exceeds the ${ALLOC_MAX_BYTES}-byte schema bound`);
  // accept the hash as bytes or a 64-hex string; anything else fails CLOSED, never throws (hostile input)
  const ah = receipt.allocationHash;
  let claimedHash = null;
  if (Buffer.isBuffer(ah) || ah instanceof Uint8Array) claimedHash = Buffer.from(ah);
  else if (typeof ah === "string" && /^[0-9a-f]{64}$/i.test(ah)) claimedHash = Buffer.from(ah, "hex");
  if (claimedHash === null || claimedHash.length !== 32) return bad("allocationHash is not a 32-byte value");
  if (!allocationHash(rowsBuf).equals(claimedHash)) return bad("allocationHash does not match allocationRows");

  let arr;
  try { arr = JSON.parse(rowsBuf.toString("utf8")); } catch (e) { return bad("allocationRows is not valid JSON"); }
  if (!Array.isArray(arr) || arr.length !== 6) return bad("allocation array is not the 6-element shape");
  const [domain, version, cId, poolId, target, rows] = arr;
  if (domain !== ALLOC_DOMAIN) return bad(`domain "${domain}" is not "${ALLOC_DOMAIN}"`);
  if (version !== ALLOC_FORMAT_VERSION) return bad(`formatVersion ${version} is not ${ALLOC_FORMAT_VERSION}`);
  const embContract = toId32(cId);
  if (embContract === null) return bad("embedded contractId is not a base58 32-byte id");
  if (!embContract.equals(wantContract)) return bad("embedded contractId is not the expected contract (cross-contract reuse)");
  if (decodeId32(poolId) === null) return bad("embedded poolId is not a base58 32-byte id");
  if (typeof target !== "string" || !DEC_RE.test(target)) return bad("embedded targetDuffs is not a base-10 duff string");
  if (!Array.isArray(rows) || rows.length < ALLOC_MIN_OWNERS || rows.length > ALLOC_MAX_OWNERS) {
    return bad(`embedded row count outside ${ALLOC_MIN_OWNERS}..${ALLOC_MAX_OWNERS}`);
  }
  let prev = null;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (!Array.isArray(r) || r.length !== 4) return bad(`row ${i} is not a 4-tuple`);
    const [owner, amountDuffs, bps, scriptHex] = r;
    const id = decodeId32(owner);
    if (id === null) return bad(`row ${i} owner is not a base58 32-byte id`);
    if (prev !== null && Buffer.compare(prev, id) >= 0) return bad(`rows not strictly decoded-id-sorted at ${i} (or duplicate owner)`);
    prev = id;
    if (typeof amountDuffs !== "string" || !DEC_RE.test(amountDuffs)) return bad(`row ${i} amountDuffs not a base-10 duff string`);
    if (!Number.isSafeInteger(bps) || bps < 1 || bps > 10000) return bad(`row ${i} bps outside 1..10000`);
    if (typeof scriptHex !== "string" || !HEX_EVEN_RE.test(scriptHex)) return bad(`row ${i} rewardScriptHex not even-length lowercase hex`);
  }
  // the bps must be the largest-remainder shares of the amounts, the amounts fill the target
  // exactly, and the bps sum to 10000 (the SAME condition the builder enforces, so the two never
  // disagree). This catches a bps set that does not match the embedded amounts, beyond bps alone
  const cErr = allocationConsistencyError(rows.map((r) => ({ amount: r[1], bps: r[2] })), target);
  if (cErr) return bad(cErr);
  // byte-exact canonical check: re-serialize the validated array; any insignificant whitespace
  // or non-canonical number/string form in the input fails here even though it parsed
  if (!Buffer.from(JSON.stringify(arr), "utf8").equals(rowsBuf)) return bad("allocationRows is not canonical bytes");
  // top-level correspondence, when the caller supplies those fields; poolId may be a ledger-native
  // byteArray or base58, so compare decoded bytes, not string identity
  if (receipt.poolId != null) {
    const want = toId32(receipt.poolId), have = toId32(poolId);
    if (want === null || have === null || !want.equals(have)) return bad("top-level poolId does not match the embedded allocation");
  }
  if (receipt.targetDuffs != null) {
    // only coerce a primitive; a crafted object (e.g. {toString:null}) would throw on String(), so
    // fail closed on any non-primitive rather than crash (review finding)
    const t = ["number", "bigint", "string"].includes(typeof receipt.targetDuffs) ? String(receipt.targetDuffs) : null;
    if (t !== target) return bad("top-level targetDuffs does not match the embedded allocation");
  }
  if (receipt.participantCount != null && receipt.participantCount !== rows.length) return bad("top-level participantCount does not match the embedded row count");
  return { ok: true, poolId, targetDuffs: target, participantCount: rows.length };
  } catch (e) {
    // a CONSTANT reason: interpolating the caught value could itself throw (a Symbol, or an object
    // whose `message` getter throws), which would defeat the fail-closed guarantee
    return bad("verification stopped on malformed input");
  }
};

module.exports = { TARGETS, isFormingHash, aggregateByOwner, allocateBps, verifyRegistration,
  decodeId32, toId32, buildAllocationArray, allocationPreimage, allocationHash, verifyReceiptAllocation,
  ALLOC_DOMAIN, ALLOC_FORMAT_VERSION, ALLOC_MIN_OWNERS, ALLOC_MAX_OWNERS };
