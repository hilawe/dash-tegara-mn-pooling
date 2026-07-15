/**
 * The governance tally, extracted from governor.cjs so the tally engine, the cast-receipt
 * publisher, and the cast-receipt verifier all compute ONE identical function of the
 * ledger. Pure code, no network.
 *
 * Rules (CrowdNode's five options kept as prior art):
 *   yes / no / abstain   counted directly, weighted by the member's shareBps
 *   delegate (untargeted)  follows the pool's NET ACTIVE vote (majority among the
 *                        direct yes/no weights; a tie or no active votes -> abstain)
 *   delegate (targeted, v5's delegateTo)  follows the NAMED member's DIRECT choice,
 *                        one hop only: if the target's own choice is not a direct
 *                        yes/no/abstain (a chain, a self-target, no preference), the
 *                        weight is withheld. Resolution applies to the OUTCOME only;
 *                        canonical rows keep the raw choice (and the target), so
 *                        myrow's self-authentication is unchanged.
 *   donothing            that weight is withheld entirely (not cast); a member with NO
 *                        recorded preference is treated as donothing
 * The outcome is the plurality of the final yes/no/abstain weights (ties break
 * yes > no > abstain); if every weight is withheld the masternode casts no vote at all
 * (outcome "none").
 */
const crypto = require("crypto");

const DIRECT = ["yes", "no", "abstain"];

/**
 * members: [{ owner: <identity id string>, bps: <int> }] (the pool's current shares)
 * choiceByOwner: Map(owner -> choice string)
 * delegateToByOwner: Map(owner -> target identity id) for targeted delegation (v5);
 *   consulted only for members whose choice is "delegate". Defaults empty, in which
 *   case the result is identical to the pre-v5 function.
 * Returns { rows, weights, net, final, castable, outcome }.
 */
const computeTally = (members, choiceByOwner, delegateToByOwner = new Map()) => {
  const weights = { yes: 0, no: 0, abstain: 0, delegate: 0, withheld: 0 };
  const rows = [];
  // direct choices first, so targeted delegation can only ever follow a DIRECT vote
  // (one hop; a delegate pointing at a delegate resolves to withheld, never a chain)
  const directByOwner = new Map();
  for (const { owner } of members) {
    const c = choiceByOwner.get(owner);
    if (DIRECT.includes(c)) directByOwner.set(owner, c);
  }
  const targeted = { yes: 0, no: 0, abstain: 0, withheld: 0 };
  for (const { owner, bps } of members) {
    const recorded = choiceByOwner.has(owner);
    const choice = choiceByOwner.get(owner) || "donothing";
    const target = choice === "delegate" ? delegateToByOwner.get(owner) : undefined;
    if (choice === "delegate" && target !== undefined) {
      const resolved = target !== owner ? directByOwner.get(target) : undefined;
      targeted[resolved || "withheld"] += bps;
      rows.push({ owner, bps, choice, recorded, delegateTo: target });
      continue;
    }
    const bucket = choice === "donothing" ? "withheld" : choice;
    weights[bucket] += bps;
    rows.push({ owner, bps, choice, recorded });
  }
  const net = weights.yes > weights.no ? "yes" : weights.no > weights.yes ? "no" : "abstain";
  const final = { yes: weights.yes, no: weights.no, abstain: weights.abstain };
  final[net] += weights.delegate; // the untargeted delegates follow the net active vote
  for (const k of DIRECT) final[k] += targeted[k]; // the targeted ones follow their target
  weights.withheld += targeted.withheld;
  const castable = final.yes + final.no + final.abstain;
  const outcome = castable === 0 ? "none"
    : Object.entries(final).sort((a, b) => b[1] - a[1]
      || ["yes", "no", "abstain"].indexOf(a[0]) - ["yes", "no", "abstain"].indexOf(b[0]))[0][0];
  return { rows, weights, net, final, castable, outcome };
};

/**
 * The canonical member rows of a tally: owner-sorted (code-unit comparison, not
 * localeCompare, so the result cannot depend on the runtime's locale tables), one
 * {owner, bps, choice} per member. This IS the byte content a v2 tally snapshot
 * embeds, so a snapshot is self-authenticating: hash the embedded rows through
 * tallyHash and compare.
 */
const canonicalMembers = (tally) =>
  [...tally.rows].sort((a, b) => (a.owner < b.owner ? -1 : a.owner > b.owner ? 1 : 0))
    // rows without a target serialize exactly as format 1 always has, so the pre-v5
    // hashes are unchanged; a targeted row appends delegateTo (format 2)
    .map((r) => (r.delegateTo === undefined
      ? { owner: r.owner, bps: r.bps, choice: r.choice }
      : { owner: r.owner, bps: r.bps, choice: r.choice, delegateTo: r.delegateTo }));

/**
 * Strict validation of canonical member rows BEFORE reconstruction (batch-4 review,
 * major): a snapshot's tallyRows arrive from the ledger, not from this process, so a
 * hostile-but-valid-JSON byte string must be classified as a deviation, never crash
 * the verifier or reconstruct nonsense (duplicate owners, bps off 10000, NaN weights
 * from unknown choices). Returns the rows; throws with a specific reason.
 */
const CHOICES = ["yes", "no", "abstain", "delegate", "donothing"];
// ONE row-cap policy, enforced at BOTH ends (snapshot creation calls this validator
// before publishing, the verifier calls it on every embedded row set), so an
// oversize pool is refused loudly at commit time instead of committing a snapshot
// that forever fails verification (third-model batch-4 finding). 32 matches the
// #187 participant cap this prototype targets; a larger membership needs the next
// contract revision's larger tallyRows byte bound.
const MAX_ROWS = 32;
// a real identifier check, not just the alphabet: the string must DECODE to exactly
// 32 bytes (independent-review finding: "1".repeat(43) passes an alphabet regex but is
// not an identifier). A small local decoder keeps this module dependency-free.
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const isIdentityId = (s) => {
  if (typeof s !== "string" || !/^[1-9A-HJ-NP-Za-km-z]{42,44}$/.test(s)) return false;
  // decode (little-endian accumulator); leading '1' characters are leading zero bytes
  const bytes = [0];
  for (const ch of s) {
    let carry = B58_ALPHABET.indexOf(ch);
    for (let i = 0; i < bytes.length; i++) { carry += bytes[i] * 58; bytes[i] = carry & 0xff; carry >>= 8; }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  let zeros = 0;
  for (const ch of s) { if (ch === "1") zeros++; else break; }
  const valueBytes = (bytes.length === 1 && bytes[0] === 0) ? 0 : bytes.length;
  return zeros + valueBytes === 32;
};
const validateCanonicalRows = (rows, formatVersion = 1) => {
  const fail = (why) => { throw new Error(`canonical rows invalid (${why})`); };
  if (![1, 2].includes(formatVersion)) fail(`unknown format version ${formatVersion}`);
  if (!Array.isArray(rows)) fail("not an array");
  if (rows.length < 1 || rows.length > MAX_ROWS) fail(`row count ${rows.length} outside 1..${MAX_ROWS}`);
  let bpsSum = 0;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (typeof r !== "object" || r === null || Array.isArray(r)) fail(`row ${i} is not an object`);
    const keys = Object.keys(r).sort().join(",");
    if (keys === "bps,choice,owner") {
      // the format-1 shape, valid in both versions
    } else if (formatVersion === 2 && keys === "bps,choice,delegateTo,owner") {
      // format 2's targeted-delegation row: the target field may appear ONLY on a
      // delegate choice, must be a distinct valid identity id
      if (r.choice !== "delegate") fail(`row ${i} carries delegateTo with choice "${r.choice}"`);
      if (!isIdentityId(r.delegateTo)) {
        fail(`row ${i} delegateTo is not a base58 identity id`);
      }
      if (r.delegateTo === r.owner) fail(`row ${i} delegates to itself`);
    } else {
      fail(`row ${i} keys are [${keys}], not a format-${formatVersion} row`);
    }
    if (!isIdentityId(r.owner)) {
      fail(`row ${i} owner is not a base58 identity id`);
    }
    if (i > 0 && !(rows[i - 1].owner < r.owner)) fail(`rows not strictly owner-sorted at ${i} (or duplicate owner)`);
    if (!Number.isSafeInteger(r.bps) || r.bps < 1 || r.bps > 10000) fail(`row ${i} bps ${r.bps} outside 1..10000`);
    if (!CHOICES.includes(r.choice)) fail(`row ${i} choice "${r.choice}" not in [${CHOICES.join(",")}]`);
    bpsSum += r.bps;
  }
  if (bpsSum !== 10000) fail(`bps sum ${bpsSum}, expected exactly 10000`);
  return rows;
};

/**
 * Rebuild a full tally from canonical member rows (the inverse of canonicalMembers
 * for hashing purposes), validating them first. A "donothing" choice in a row and an
 * absent preference produce the same withheld weight in computeTally, so
 * round-tripping through rows reproduces the identical outcome and hash.
 */
const tallyFromRows = (rows, formatVersion = 1) => {
  validateCanonicalRows(rows, formatVersion);
  return computeTally(
    rows.map(({ owner, bps }) => ({ owner, bps })),
    new Map(rows.map(({ owner, choice }) => [owner, choice])),
    new Map(rows.filter((r) => r.delegateTo !== undefined).map((r) => [r.owner, r.delegateTo])),
  );
};

/**
 * The canonical hash of a tally: sha256 over a canonical JSON of the inputs and the
 * outcome, with the member rows sorted by owner id so document arrival order cannot
 * change the hash. Anyone with ledger access recomputes this and compares it to the
 * published receipt; a mismatch means the receipt was not produced from the ledger
 * state it claims.
 */
const tallyHash = (contractId, poolIdStr, proposalHex, tally) => {
  const canonical = {
    contractId,
    poolId: poolIdStr,
    proposalHash: proposalHex.toLowerCase(),
    members: canonicalMembers(tally),
    final: tally.final,
    withheld: tally.weights.withheld,
    outcome: tally.outcome,
  };
  return crypto.createHash("sha256").update(JSON.stringify(canonical)).digest();
};

module.exports = { computeTally, tallyHash, canonicalMembers, tallyFromRows, validateCanonicalRows };
