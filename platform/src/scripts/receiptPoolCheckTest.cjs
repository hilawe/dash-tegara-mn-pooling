/**
 * The shared receipt-to-pool check, offline (phase B of docs/V9_MIGRATION_PLAN.md).
 *
 * THE CASE THIS SUITE EXISTS FOR is the round-four one: a receipt that is internally valid,
 * canonical, and passes `verifyReceiptAllocation` on its own, while the target embedded in
 * its allocation preimage contradicts the pool it names. Under v8 the receipt carried its own
 * top-level target and the allocation verifier caught the disagreement. v9 removes that
 * field, so nothing catches it except a comparison against the pool. The first test below
 * asserts BOTH halves: that the allocation verifier alone still says yes, and that the shared
 * check says no. If someone later re-adds a duplicate field or weakens duty 2, the first half
 * keeps passing and the second fails, which is the signal worth having.
 *
 * Run: node src/scripts/receiptPoolCheckTest.cjs   (exits non-zero on failure)
 */
const core = require("./formationCore.cjs");
const { checkReceiptAgainstPool, checkReceiptsAgainstPools, resolveNodeToPools, toDuffs } = require("./receiptPoolCheck.cjs");

// THE MODULE IS LEDGER-AWARE, because targetDuffs swaps sides at v9: on v8 it is a receipt
// field and the pool carries none, on v9 it is a pool field and the receipt carries none.
// This suite therefore has to SAY which ledger each case is on. An earlier version did not,
// and so was implicitly exercising one shape while appearing to be general. Everything below
// runs pinned to v9 except the explicitly-v8 section at the end.
process.env.LEDGER = "v9";

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const refuses = (name, res, re) => {
  if (res.ok) { fail++; console.error(`FAIL: ${name} (accepted)`); return; }
  ok(name, re.test(res.reason || ""));
};
const withLedger = (v, fn) => {
  const prev = process.env.LEDGER;
  process.env.LEDGER = v;
  try { return fn(); } finally { process.env.LEDGER = prev; }
};

// the published golden vector from formationCoreTest, reused so both suites move together
const GC = "3EbgWjxUoX6J9XbqqxrEktm7tUFBQ5fQyKaiAzXCULxf"; // contract id
const GP = "47doihuxfjfeoqi4PrKLY58Z56J6BhXekMmhW3z63QT8"; // pool id
const OTHER_POOL = "52D4DcjgFZU1KktALjGpcfGoxR1987BEjTXxbnNcNfAc";
const OA = "8sCudmZNvmDC9nXCGRWk1NMStKaeqCaWLa7eYTEKuT8Y";
const OB = "52D4DcjgFZU1KktALjGpcfGoxR1987BEjTXxbnNcNfAc";
const OC = "FZ9HF6oANQxZDXGXGiKh8uXdPfwcp4rwfrzqQJcdRNgv";

const REGULAR = "100000000000"; // 1000 DASH
const EVO = "400000000000";     // 4000 DASH

const manifest = (target = REGULAR, poolId = GP) => {
  // amounts are 50/30/20 percent of the target, so the allocation stays self-consistent at
  // ANY target and the only thing that varies is the number the preimage embeds
  const t = BigInt(target);
  return {
    v: 1, poolId, realHash: "aa".repeat(32), target,
    owners: [
      { owner: OA, amountDuffs: String(t / 2n), bps: 5000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
      { owner: OB, amountDuffs: String(t * 3n / 10n), bps: 3000, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
      { owner: OC, amountDuffs: String(t / 5n), bps: 2000, rewardScriptHex: "76a914" + "33".repeat(20) + "88ac" },
    ],
  };
};

/** a v9-shaped receipt: no top-level nodeType, operatorFeeBps or targetDuffs */
// poolId crosses this seam as a BUFFER, the type the SDK hands readers and the type
// formation.cjs writes (pass-7 wave, note): the fixture used a base58 string, which
// toId32 happens to coerce, so the suite was exercising a friendlier shape than any
// call site does. That is the exact toId32 lesson this project already paid for once,
// so the default is now the real type and `asString` opts into the other one where a
// case deliberately covers it.
const receiptFor = (m, { slotIndex = 0, asString = false } = {}) => {
  const rows = core.allocationPreimage(GC, m);
  return {
    poolId: asString ? m.poolId : Buffer.from(core.decodeId32(m.poolId)),
    // proTxHash is REQUIRED by the published schema and the fixture omitted it entirely
    // (a soundness-review finding): every case here was verifying a receipt the contract could
    // not accept. The default is a real node hash outside the reserved namespace.
    proTxHash: Buffer.from(m.realHash, "hex"),
    slotIndex, formatVersion: 1,
    allocationRows: rows, allocationHash: core.allocationHash(rows),
    participantCount: m.owners.length, l1Verification: "demo-unverified", verificationMethodVersion: 1,
  };
};

// THE DEFAULT FIXTURE MATCHES THE WRITER'S SHAPE (closing wave, CF2): the real v9
// formation writer always creates the pool with a slot book, so a bookless default meant
// most affirmative cases verified against a schema-valid pool the reference writer does
// not produce. The default book is derived from the target (target/2 x 2, coherent for
// both tiers, whose targets are even); `book: null` stays available and EXPLICIT for the
// schema-width cases that deliberately exercise the bookless shape the schema itself
// still allows.
const poolFor = ({ target = REGULAR, nodeType = "regular", slotIndex = 0, book = "auto" } = {}) => ({
  slotIndex, nodeType, operatorFeeBps: 2000, targetDuffs: Number(target),
  ...(book === null ? {}
    : book === "auto" ? { slotDuffs: Number(BigInt(target) / 2n), slotCount: 2 }
    : { slotDuffs: book[0], slotCount: book[1] }),
});

// ---------------------------------------------------------------------------
// 1. THE ROUND-FOUR CASE
// ---------------------------------------------------------------------------
{
  // a receipt whose allocation is entirely self-consistent, but at the EVO target
  const rogue = receiptFor(manifest(EVO));
  const realPool = poolFor({ target: REGULAR, nodeType: "regular" });

  // half one: the allocation verifier alone is satisfied. On a v9 receipt there is no
  // top-level targetDuffs for it to disagree with, so it has nothing to catch.
  const alone = core.verifyReceiptAllocation(GC, rogue);
  ok("round four: the allocation verifier ALONE accepts the contradicting receipt", alone.ok === true);
  ok("round four: and it reports the embedded target it accepted", alone.targetDuffs === EVO);

  // half two: the shared check refuses it, which is the whole point of duty 2
  refuses("round four: the shared check REFUSES it on the embedded target",
    checkReceiptAgainstPool({ contractId: GC, receipt: rogue, pool: realPool, poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA }),
    /embedded target 400000000000 contradicts pool targetDuffs 100000000000/);
}

// ---------------------------------------------------------------------------
// 2. the happy paths
// ---------------------------------------------------------------------------
{
  const m = manifest();
  const r = checkReceiptAgainstPool({
    contractId: GC, receipt: receiptFor(m), pool: poolFor(), poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA });
  ok("a matching receipt and pool pass", r.ok === true);
  ok("and the embedded allocation comes back for the caller", r.ok && r.embedded.participantCount === 3);
}
{
  // with a slot book whose product equals the target
  const r = checkReceiptAgainstPool({
    contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: poolFor({ book: [25000000000, 4] }),
    receiptOwnerId: OA, poolOwnerId: OA });
  ok("a consistent slot book passes", r.ok === true);
}
{
  // an evo pool, to prove the nodeType target is read rather than assumed
  const r = checkReceiptAgainstPool({
    contractId: GC, receipt: receiptFor(manifest(EVO)), poolId: GP,
    pool: poolFor({ target: EVO, nodeType: "evo" }),
    receiptOwnerId: OA, poolOwnerId: OA });
  ok("an evo pool passes at its own target", r.ok === true);
}
{
  // poolId in the shape that actually crosses the seam at the call sites: a document id
  // OBJECT exposing toBuffer(), which is what `pool.getId()` returns from the SDK (and
  // from the harness mock). Every offline case above passes a base58 string, which is
  // exactly how a decoder gap for this shape stayed green while the v9 crash harness
  // caught the classifier reading every completed pool as non-verifying.
  const idObject = { toBuffer: () => core.toId32(GP), toString: () => GP };
  const r = checkReceiptAgainstPool({
    contractId: GC, receipt: receiptFor(manifest()), pool: poolFor(), poolId: idObject,
    receiptOwnerId: OA, poolOwnerId: OA });
  ok("a matching pair passes when poolId is an SDK-style id object", r.ok === true);
  // and the identity precondition still refuses a WRONG pool given in the same shape
  const wrongIdObject = { toBuffer: () => core.toId32(OTHER_POOL), toString: () => OTHER_POOL };
  refuses("an id object naming a different pool is still refused",
    checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), pool: poolFor(),
      poolId: wrongIdObject,
    receiptOwnerId: OA, poolOwnerId: OA }),
    /not the pool this receipt names/);
}

// ---------------------------------------------------------------------------
// 3. duty 3, the pool's own coherence
// ---------------------------------------------------------------------------
refuses("a pool whose target is not its nodeType's target is refused",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest(EVO)), poolId: GP,
    pool: poolFor({ target: EVO, nodeType: "regular" }),
    receiptOwnerId: OA, poolOwnerId: OA }),
  /is not the regular target/);
refuses("an unknown nodeType is refused",
  // the POOL SHAPE GATE now names this first (a confirmation pass, H1); the deeper
  // targetForNodeType refusal remains beneath it for callers of the standalone helpers
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: { ...poolFor(), nodeType: "gold" },
    receiptOwnerId: OA, poolOwnerId: OA }),
  /nodeType is not in the enum/);
// H1's exact reproductions (a confirmation pass): the receipt side has had its shape
// gate since pass 13, and the POOL side never did, so each of these pools, which the
// published v9 contract rejects, verified and classified COMPLETED.
refuses("a v9 pool MISSING operatorFeeBps is refused at the pool shape gate",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: (() => { const p = poolFor(); delete p.operatorFeeBps; return p; })(),
    receiptOwnerId: OA, poolOwnerId: OA }),
  /missing operatorFeeBps/);
refuses("a v9 pool carrying a v8-only field (status) is refused",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: { ...poolFor(), status: "live" },
    receiptOwnerId: OA, poolOwnerId: OA }),
  /carries status, which this ledger's pool schema does not define/);
refuses("a v9 pool with a STRING targetDuffs is refused (the schema types it integer)",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: { ...poolFor(), targetDuffs: "100000000000" },
    receiptOwnerId: OA, poolOwnerId: OA }),
  /targetDuffs is not an integer/);
refuses("a v9 pool with an arbitrary unknown property is refused",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: { ...poolFor(), surprise: 1 },
    receiptOwnerId: OA, poolOwnerId: OA }),
  /carries surprise/);
ok("a $-prefixed system field on the pool does not trip the allowlist",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: { ...poolFor(), $createdAt: 5, $ownerId: OA },
    receiptOwnerId: OA, poolOwnerId: OA }).ok === true);
// OWN properties only (a confirmation pass, H1, which REFUTED the first draft of this
// gate): a pool inheriting every field through the prototype chain has zero own contract
// fields, serializes with none of its required properties, and is not a valid ledger
// document, yet `pool[k]` reads found every field and the pair classified COMPLETED
refuses("a pool INHERITING its fields through the prototype chain is refused",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: Object.create(poolFor()),
    receiptOwnerId: OA, poolOwnerId: OA }),
  /own property, not inherited/);
// the v9 book keeps ITS published bound
refuses("a v9 pool slotCount above the published 512 is refused",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: poolFor({ book: [Number(BigInt(REGULAR) / 513n), 513] }),
    receiptOwnerId: OA, poolOwnerId: OA }),
  /slotCount is not an integer in 1\.\.512/);
refuses("a slot book that does not multiply to the target is refused",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: poolFor({ book: [25000000000, 3] }),
    receiptOwnerId: OA, poolOwnerId: OA }),
  /does not equal targetDuffs/);
refuses("a one-sided slot book is refused",
  // built from the EXPLICIT bookless shape (CF2): the default now carries a full book,
  // so spreading it and overriding one side would produce a two-sided book with a wrong
  // product, a different refusal than the one this case pins
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: { ...poolFor({ book: null }), slotDuffs: 25000000000 },
    receiptOwnerId: OA, poolOwnerId: OA }),
  /one-sided slot book/);
// the DEFAULT fixture agrees with the writer's shape on the fields this suite controls
// (CF2): it carries the slot book the v9 writer always emits and passes the writer's own
// coherence gate. These two assertions establish fixture-side coherence and field
// presence against that gate, NOT full writer parity (the writer's output-building path
// is exercised by the crash harness, not here), which is exactly as wide as this suite
// can claim (checker on this fold narrowed the earlier wording).
{
  let coherent = true;
  try {
    core.requireCoherentSlotEconomics({ nodeType: "regular",
      targetDuffs: BigInt(poolFor().targetDuffs),
      slotDuffs: BigInt(poolFor().slotDuffs), slotCount: poolFor().slotCount });
  } catch { coherent = false; }
  ok("the default pool fixture passes the writer's own slot-economics gate", coherent);
  ok("the default pool fixture carries the slot book the v9 writer always emits",
    poolFor().slotDuffs !== undefined && poolFor().slotCount !== undefined);
  // the BOOKLESS shape the schema still allows keeps a passing case of its own: the old
  // default gave every no-book test that coverage for free, and making the book the
  // default removed it (rule 1, the removed-limitation guarantee), so it is pinned
  // explicitly here
  const bookless = checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()),
    pool: poolFor({ book: null }), poolId: GP, receiptOwnerId: OA, poolOwnerId: OA });
  ok("an explicitly bookless pool still verifies (the schema-optional shape keeps coverage)",
    bookless.ok === true);
}

// ---------------------------------------------------------------------------
// 4. duty 4 and the identity precondition
// ---------------------------------------------------------------------------
refuses("a receipt whose slotIndex differs from the pool's is refused",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest(), { slotIndex: 3 }),
    pool: poolFor({ slotIndex: 1 }), poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA }),
  /slotIndex 3 does not match pool slotIndex 1/);
// AN AGREED value must still sit inside the published 0..31 range (closing confirm-pass
// a review, must-fix): an EQUAL pair at -1 or 32 satisfied the match test while naming a
// slot no contract-accepted document can name. Both out-of-range boundaries are pinned,
// and both in-range boundaries stay accepted, so the bound cannot drift in either
// direction unnoticed.
for (const badIdx of [-1, 32]) {
  // since a review's pool shape gate, the POOL side of the equal pair is refused first;
  // duty 4's own bound stays beneath it as defense in depth (a pool-gate regression must
  // not silently reopen the agreed-out-of-range acceptance), so the pinned property is
  // the refusal naming the 0..31 range, whichever layer names it
  refuses(`an EQUAL slotIndex pair at ${badIdx} is refused (agreement is not validity)`,
    checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest(), { slotIndex: badIdx }),
      pool: poolFor({ slotIndex: badIdx }), poolId: GP,
      receiptOwnerId: OA, poolOwnerId: OA }),
    /0\.\.31/);
}
for (const goodIdx of [0, 31]) {
  ok(`an equal in-range slotIndex pair at the ${goodIdx} boundary still verifies`,
    checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest(), { slotIndex: goodIdx }),
      pool: poolFor({ slotIndex: goodIdx }), poolId: GP,
      receiptOwnerId: OA, poolOwnerId: OA }).ok === true);
}
refuses("a receipt checked against the WRONG pool is refused before any comparison",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()),
    pool: poolFor(), poolId: OTHER_POOL,
    receiptOwnerId: OA, poolOwnerId: OA }),
  /not the pool this receipt names/);
refuses("a receipt bound to another contract is refused",
  checkReceiptAgainstPool({ contractId: OTHER_POOL, receipt: receiptFor(manifest()),
    pool: poolFor(), poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA }),
  /allocation: /);

// ---------------------------------------------------------------------------
// 5. fail-closed on malformed input, never a throw
// ---------------------------------------------------------------------------
for (const [name, args] of [
  ["missing receipt", { contractId: GC, receipt: null, pool: poolFor(), poolId: GP }],
  ["missing pool", { contractId: GC, receipt: receiptFor(manifest()), pool: null, poolId: GP }],
  ["pool target is a float", { contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: { ...poolFor(), targetDuffs: 100000000000.5 } }],
  ["pool target is an object", { contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: { ...poolFor(), targetDuffs: { toString() { throw new Error("boom"); } } } }],
  ["receipt slotIndex is a string", { contractId: GC, poolId: GP, pool: poolFor(),
    receipt: { ...receiptFor(manifest()), slotIndex: "0" } }],
]) {
  let threw = false, res = null;
  try { res = checkReceiptAgainstPool(args); } catch { threw = true; }
  ok(`${name}: refused without throwing`, !threw && res && res.ok === false);
}

// a float target must not compare equal to the exact duff amount
ok("toDuffs rejects a non-integer number", toDuffs(1.5) === null);
ok("toDuffs rejects a negative string", toDuffs("-1") === null);
ok("toDuffs accepts an integer, a bigint and a decimal string",
  toDuffs(7) === 7n && toDuffs(7n) === 7n && toDuffs("7") === 7n);

// ---------------------------------------------------------------------------
// 5b. the UNPARED (v8) shape, where the target lives on the receipt
// ---------------------------------------------------------------------------
// A v8 pool has NO targetDuffs at all. Asking one for it, which the first version of this
// module did, refuses every valid v8 receipt. These cases pin the other carrier.
{
  const unpared = (m, extra = {}) => ({ ...receiptFor(m), nodeType: "regular",
    operatorFeeBps: 2000, targetDuffs: Number(m.target), ...extra });
  const v8pool = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
    proTxHash: Buffer.alloc(32, 0xaa), status: "live" };

  ok("v8: a receipt carrying its own target passes against a pool that has none",
    withLedger("v8", () => checkReceiptAgainstPool({
      contractId: GC, receipt: unpared(manifest()), pool: v8pool, poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA })).ok === true);
  // THE READER ACCEPTS WHAT THE LIVE LEDGER CAN HOLD (a confirmation pass, H2): the live
  // v8 contract is immutable and retains its published slotCount maximum of 10000; the
  // 512 ceiling is a source-contract tightening the CLIENT enforces at create. A coherent
  // 1000-slot live book is a valid on-ledger document and must verify.
  ok("v8: a coherent 1000-slot book, valid on the LIVE ledger, verifies",
    withLedger("v8", () => checkReceiptAgainstPool({
      contractId: GC, receipt: unpared(manifest()),
      pool: { ...v8pool, slotDuffs: 100000000, slotCount: 1000 }, poolId: GP,
      receiptOwnerId: OA, poolOwnerId: OA })).ok === true);
  refuses("v8: a slotCount above the live ledger's published 10000 is refused",
    withLedger("v8", () => checkReceiptAgainstPool({
      contractId: GC, receipt: unpared(manifest()),
      pool: { ...v8pool, slotDuffs: 100000000, slotCount: 10001 }, poolId: GP,
      receiptOwnerId: OA, poolOwnerId: OA })),
    /slotCount is not an integer in 1\.\.10000/);
  // OPTIONAL fields are judged by OWN presence only (a confirmation pass, the
  // false-refusal mirror of a review): a pool whose own serialized shape validly OMITS an
  // optional field must not be refused over a value it merely inherits
  ok("v8: a valid pool inheriting a BAD optional fee through the prototype still verifies",
    withLedger("v8", () => checkReceiptAgainstPool({
      contractId: GC, receipt: unpared(manifest()),
      pool: Object.assign(Object.create({ operatorFeeBps: "bad" }),
        { proTxHash: Buffer.alloc(32, 0xaa), status: "live", slotIndex: 0, nodeType: "regular" }),
      poolId: GP, receiptOwnerId: OA, poolOwnerId: OA })).ok === true);

  refuses("v8: a receipt target that is not the nodeType's target is refused",
    withLedger("v8", () => checkReceiptAgainstPool({
      contractId: GC, receipt: unpared(manifest(EVO)), pool: v8pool, poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA })),
    /receipt targetDuffs 400000000000 is not the regular target/);

  refuses("v8: a receipt nodeType contradicting the pool is refused",
    withLedger("v8", () => checkReceiptAgainstPool({
      contractId: GC, receipt: unpared(manifest(), { nodeType: "evo" }), pool: v8pool, poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA })),
    /receipt nodeType "evo" contradicts pool "regular"/);

  // and the pared shape is refused on v8. The refusal moved EARLIER with the pass-13
  // required-shape gate: it now names the missing field at the shape boundary rather than
  // failing later at the carrier read. Same fail-closed outcome, more specific diagnosis.
  // the pared shape is missing THREE v8 fields, and which one the gate names first is an
  // ordering detail, not the property; asserting one exact name over-specified and broke
  // on the enumeration order
  refuses("v8: a PARED receipt is refused at the shape boundary",
    withLedger("v8", () => checkReceiptAgainstPool({
      contractId: GC, receipt: receiptFor(manifest()), pool: v8pool, poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA })),
    /missing required field (nodeType|operatorFeeBps|targetDuffs)/);
}

// ---------------------------------------------------------------------------
// 6. the batched resolver
// ---------------------------------------------------------------------------
(async () => {
  const good = receiptFor(manifest());
  const rogue = receiptFor(manifest(EVO));
  const orphan = receiptFor(manifest(REGULAR, OTHER_POOL));

  let calls = 0, sawIds = null;
  const fetchPoolsByIds = async (ids) => {
    calls++; sawIds = ids;
    return [{ getId: () => GP, toObject: () => poolFor() }];
  };

  // the batched form REFUSES without owners now (Request 3, disposition REFUSE), so the
  // batch supplies them per receipt; the four cases below still test what they name
  const batchOwners = [0, 1, 2, 3].map(() => ({ receiptOwnerId: OA, poolOwnerId: OA }));
  const results = await checkReceiptsAgainstPools({
    contractId: GC, receipts: [good, rogue, good, orphan], owners: batchOwners, fetchPoolsByIds });

  ok("batched: exactly ONE fetch for four receipts", calls === 1);
  ok("batched: the fetch asked for the two DISTINCT pools only", sawIds.length === 2);
  ok("batched: results are per receipt, in order", results.length === 4);
  ok("batched: the matching receipts pass", results[0].ok === true && results[2].ok === true);
  ok("batched: the contradicting receipt is refused", results[1].ok === false);
  ok("batched: a receipt whose pool is absent is REFUSED, not skipped",
    results[3].ok === false && /no pool found/.test(results[3].reason));
  // and WITHOUT owners the whole batch refuses rather than answering ok unbound
  const unbound = await checkReceiptsAgainstPools({
    contractId: GC, receipts: [good], fetchPoolsByIds });
  ok("batched: records without owners REFUSE, never pass unbound",
    unbound[0].ok === false && /owner binding cannot be checked/.test(unbound[0].reason));

  const empty = await checkReceiptsAgainstPools({ contractId: GC, receipts: [], fetchPoolsByIds: async () => {
    throw new Error("must not fetch for an empty batch");
  } });
  ok("batched: an empty batch fetches nothing", empty.length === 0);

  // -------------------------------------------------------------------------
  // 7. resolving a masternode slot to its pool, the v9 replacement for a query
  //    against a pool field that no longer exists
  // -------------------------------------------------------------------------
  const NODE = Buffer.alloc(32, 0xaa);
  // the fixtures are DOCUMENTS with owners, because node resolution now checks the owner
  // binding rather than declaring it unavailable (Request 3, disposition SUPPLY). A
  // receipt document and its pool document are what the real caller holds.
  const asDoc = (obj, owner, id) => ({ getId: () => id, toObject: () => obj,
    getOwnerId: () => ({ toString: () => owner }) });
  const poolDoc = asDoc(poolFor(), OA, GP);
  const goodReceipt = asDoc({ ...receiptFor(manifest()), proTxHash: NODE }, OA, GP);
  const badReceipt = asDoc({ ...receiptFor(manifest(EVO)), proTxHash: NODE }, OA, GP);

  const resolve = (receipts, pool) => resolveNodeToPools({
    contractId: GC, nodeHash: NODE, slotIndex: 0,
    fetchReceipts: async () => receipts,
    fetchPoolById: async () => pool,
  });

  const hit = await resolve([goodReceipt], poolDoc);
  ok("resolve: a verifying receipt yields its pool", hit.ok === true && hit.pools.length === 1);

  const miss = await resolve([], poolDoc);
  ok("resolve: no receipt is an EMPTY result, not a refusal", miss.ok === true && miss.pools.length === 0);

  const orphanPool = await resolve([goodReceipt], null);
  ok("resolve: a receipt naming a pool that does not exist REFUSES", orphanPool.ok === false);
  ok("resolve: and says the record is unresolvable", /unresolvable record/.test(orphanPool.reason));

  // THE CASE THAT MATTERS. A contradicting receipt must refuse rather than resolve to
  // nothing: the caller treats an empty result as "this node has no pool" and goes on to
  // CREATE one, so a silent skip here would mint a second pool over a contradiction.
  const contradiction = await resolve([badReceipt], poolDoc);
  ok("resolve: a contradicting receipt REFUSES rather than resolving to nothing",
    contradiction.ok === false);
  ok("resolve: and names the verification failure",
    /does not verify against its pool/.test(contradiction.reason));
  // the SUPPLY disposition's own refusal: given records WITHOUT owners, resolution must
  // refuse rather than resolve a node from an unbound receipt (Request 3, criterion 6)
  const ownerless = await resolve([{ ...receiptFor(manifest()), proTxHash: NODE }],
    { getId: () => GP, toObject: () => poolFor() });
  ok("resolve: records without document owners REFUSE, never resolve unbound",
    ownerless.ok === false && /owner binding cannot be checked/.test(ownerless.reason || ""));

  ok("resolve: the refusal is distinguishable from the empty case, which is the whole point",
    contradiction.ok === false && miss.ok === true);

  let threw = false;
  try { await resolveNodeToPools({ contractId: GC, nodeHash: NODE, slotIndex: 0 }); } catch { threw = true; }
  ok("resolve: missing fetchers is a programming error and throws", threw);

  // THE RECEIPT'S poolId FIELD IS BYTES-ONLY at this post-toObject boundary (confirm-pass
// a review, major, superseding the pass-7 note that pinned both representations): the
// schema types it a 32-byte array, so the base58-string form is a document the published
// contract cannot store, and the gate refuses it like allocationHash's string form. The
// poolId function ARGUMENT stays dual-form; both cases in this block pass it as base58
// (GP), which keeps that side of the argument's coercion covered.
{
  const m = manifest();
  const bufReceipt = receiptFor(m);
  const strReceipt = receiptFor(m, { asString: true });
  // the pair proves nothing unless the two fixtures ACTUALLY differ in representation
  // (artifact check: a builder ignoring `asString` would pass both verification
  // assertions), so the difference itself is asserted first
  ok("the fixture produces two genuinely different poolId representations",
    Buffer.isBuffer(bufReceipt.poolId) && typeof strReceipt.poolId === "string");
  const asBuffer = checkReceiptAgainstPool({ contractId: GC, receipt: bufReceipt, pool: poolFor(), poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA });
  const asString = checkReceiptAgainstPool({ contractId: GC, receipt: strReceipt,
    pool: poolFor(), poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA });
  ok("a Buffer poolId verifies (bytes, the form toObject() delivers)", asBuffer.ok === true);
  ok("a base58-string receipt poolId is REFUSED at the shape boundary (the schema forbids it)",
    asString.ok === false && /poolId is not a 32-byte array/.test(asString.reason || ""));
  // THE GATE'S FULL BOUNDARY, not only the Buffer-vs-string pair (a review,
  // finding 1: a string-only refusal, or a dropped Uint8Array branch, would leave the
  // pair green): a 32-byte Uint8Array is the OTHER accepted byte form, and short, long
  // and non-byte values are refused for length or type, not for being strings
  const withPid = (pid) => checkReceiptAgainstPool({ contractId: GC,
    receipt: { ...bufReceipt, poolId: pid }, pool: poolFor(), poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA });
  ok("a 32-byte Uint8Array poolId verifies (the other byte form the gate accepts)",
    withPid(new Uint8Array(bufReceipt.poolId)).ok === true);
  ok("a 31-byte poolId is refused (length, not just type)",
    (() => { const r = withPid(bufReceipt.poolId.subarray(0, 31));
      return r.ok === false && /poolId is not a 32-byte array/.test(r.reason || ""); })());
  ok("a 33-byte poolId is refused",
    (() => { const r = withPid(Buffer.concat([bufReceipt.poolId, Buffer.alloc(1)]));
      return r.ok === false && /poolId is not a 32-byte array/.test(r.reason || ""); })());
  ok("a non-byte poolId object is refused",
    (() => { const r = withPid({ length: 32 });
      return r.ok === false && /poolId is not a 32-byte array/.test(r.reason || ""); })());
}

// ---- a soundness-review finding: the RESERVED FORMING NAMESPACE is not a node ----
// The writer refuses a proTxHash whose first sixteen bytes are zero; the published
// schema bounds only the length, so the shared check is the only place that refusal can
// live for a receipt already on the ledger. Without it the classifier reports COMPLETED
// and backingNode hands the placeholder out as an established node.
{
  const m = manifest();
  const forming = Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 7)]);
  const real = Buffer.alloc(32, 0xab);
  const withHash = (h) => ({ ...receiptFor(m), proTxHash: h });
  const r = checkReceiptAgainstPool({ contractId: GC, receipt: withHash(forming),
    pool: poolFor(), poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA });
  ok("a soundness-review finding: a receipt naming the reserved forming namespace is REFUSED by the shared check",
    r.ok === false && /forming/i.test(r.reason || ""));
  const good = checkReceiptAgainstPool({ contractId: GC, receipt: withHash(real),
    pool: poolFor(), poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA });
  ok("a soundness-review finding: a real node hash still verifies", good.ok === true);
  const missing = checkReceiptAgainstPool({ contractId: GC,
    receipt: { ...receiptFor(m), proTxHash: undefined }, pool: poolFor(), poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA });
  ok("a soundness-review finding: a receipt with no proTxHash is refused", missing.ok === false);
  const short = checkReceiptAgainstPool({ contractId: GC, receipt: withHash(Buffer.alloc(31, 1)),
    pool: poolFor(), poolId: GP,
    receiptOwnerId: OA, poolOwnerId: OA });
  ok("a soundness-review finding: a proTxHash of the wrong length is refused", short.ok === false);
}

// THE REQUIRED SHAPE IS ENFORCED AT THE READER'S OWN BOUNDARY (pass 13, F1). The
// allocation helper checks the top-level correspondences only when the field is present,
// because it also serves draft shapes, and nothing examined the three version and enum
// fields, so a stripped or version-99 receipt passed every duty and classified COMPLETED.
// These are the reviewer's exact reproductions, one per named gap, plus the two the sweep
// added (v8 nodeType and operatorFeeBps).
{
  const m = manifest();
  const base = { contractId: GC, pool: poolFor(), poolId: GP, receiptOwnerId: OA, poolOwnerId: OA };
  const good = receiptFor(m);
  ok("the full receipt still passes (or the refusals below prove nothing)",
    checkReceiptAgainstPool({ ...base, receipt: good }).ok === true);
  // ALL NINE pared-shape required fields, each asserting the BOUNDARY message exactly. The
  // first draft alternated the bare field name into the regex, which matched any downstream
  // refusal mentioning the field, so "enforced at the boundary" was not what it checked
  // (the pre-commit check on this fold constructed exactly that survival).
  for (const k of ["poolId", "proTxHash", "slotIndex", "formatVersion", "allocationRows",
    "allocationHash", "participantCount", "l1Verification", "verificationMethodVersion"]) {
    const { [k]: gone, ...stripped } = good;
    const r = checkReceiptAgainstPool({ ...base, receipt: stripped });
    ok(`a receipt MISSING ${k} is refused AT THE BOUNDARY`,
      r.ok === false && new RegExp(`missing required field ${k}`).test(r.reason || ""));
  }
  // INHERITED FIELDS ARE NOT PRESENT FIELDS: an object whose required fields all live on
  // its prototype carries none of them itself
  refuses("a receipt INHERITING every field is refused",
    checkReceiptAgainstPool({ ...base, receipt: Object.create(good) }),
    /missing required field/);
  // THE OTHER LEDGER'S SHAPE IS REFUSED, not merely tolerated (pass 14, F1): a VALID v8
  // receipt carries the three fields v9 pares away, and the presence-only gate verified
  // it under LEDGER=v9, an affirmative result for a document the selected contract
  // rejects. Each pared-away field alone is a refusal too, so a partial mixture cannot
  // slip through on the strength of the other two being absent.
  const v8only = { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 };
  refuses("a full v8-shaped receipt is refused under the pared ledger",
    checkReceiptAgainstPool({ ...base, receipt: { ...good, ...v8only } }),
    /does not define/);
  for (const [k, v] of Object.entries(v8only)) {
    refuses(`a pared receipt carrying only ${k} is refused`,
      checkReceiptAgainstPool({ ...base, receipt: { ...good, [k]: v } }),
      new RegExp(`receipt carries ${k}`));
    // OWN PRESENCE is what additionalProperties forbids, whatever the value: a
    // null-valued forbidden field slipped the first-draft denylist (checker-constructed)
    refuses(`...and carrying ${k} with a NULL value is refused too`,
      checkReceiptAgainstPool({ ...base, receipt: { ...good, [k]: null } }),
      new RegExp(`receipt carries ${k}`));
  }
  // the allowlist covers ARBITRARY unknown properties, not only the three v8 names the
  // author was looking at
  refuses("an arbitrary property outside the schema is refused",
    checkReceiptAgainstPool({ ...base, receipt: { ...good, surprise: 1 } }),
    /receipt carries surprise/);
  // ...while Platform SYSTEM fields are exempt, as the real contract treats them
  ok("a $-prefixed system field does not trip the allowlist",
    checkReceiptAgainstPool({ ...base, receipt: { ...good, $createdAt: 5 } }).ok === true);
  // an INVENTED $-field is refused: the exemption is the KNOWN system set, not any $-key
  // (packet wave, repository-access review F2; the pass-14 receipt gate had the same $-wildcard the pass-18
  // pool validator was already narrowed away from)
  refuses("an invented $-prefixed field on a receipt is refused",
    checkReceiptAgainstPool({ ...base, receipt: { ...good, $surprise: 1 } }),
    /does not define/);
  // allocationHash is a byteArray HASH32; the hex-string form the duty-1 comparison
  // tolerates is refused at the shape boundary (packet wave, repository-access review F2)
  refuses("a hex-STRING allocationHash is refused at the shape boundary",
    checkReceiptAgainstPool({ ...base, receipt: { ...good,
      allocationHash: Buffer.from(good.allocationHash).toString("hex") } }),
    /allocationHash is not a 32-byte array/);
  refuses("a wrong-length allocationHash byte array is refused",
    checkReceiptAgainstPool({ ...base, receipt: { ...good, allocationHash: Buffer.alloc(31, 3) } }),
    /allocationHash is not a 32-byte array/);
  ok("the 32-byte array allocationHash still passes",
    checkReceiptAgainstPool({ ...base, receipt: good }).ok === true);
  // proTxHash is the SAME byteArray class (closing wave, FA1, the un-swept sibling of the
  // allocationHash fix above): Buffer.from("<32 chars>") is 32 UTF-8 bytes, so a STRING
  // passed the length-only test and a receipt Platform would reject verified. Two string
  // shapes, because a fix recognizing only one exact form survives a single case: a
  // 32-char string (coerces to exactly 32 bytes) and a 64-char hex string (the stored
  // spelling a caller might hand through).
  refuses("a 32-character STRING proTxHash is refused at the shape boundary",
    checkReceiptAgainstPool({ ...base, receipt: { ...good, proTxHash: "A".repeat(32) } }),
    /proTxHash is not a byte array/);
  refuses("a 64-character hex-STRING proTxHash is refused too",
    checkReceiptAgainstPool({ ...base, receipt: { ...good, proTxHash: "ab".repeat(32) } }),
    /proTxHash is not a byte array/);
  ok("a Uint8Array proTxHash still passes (both byte forms are legitimate)",
    checkReceiptAgainstPool({ ...base,
      receipt: { ...good, proTxHash: new Uint8Array(Buffer.from(good.proTxHash)) } }).ok === true);
  // ...and a BAD Uint8Array still refuses, so the byte-form acceptance cannot be satisfied
  // by short-circuiting on the type instead of running the duties (checker-proposed
  // mutation on this fold)
  refuses("a 31-byte Uint8Array proTxHash is refused (type acceptance does not skip the duties)",
    checkReceiptAgainstPool({ ...base, receipt: { ...good, proTxHash: new Uint8Array(31).fill(7) } }),
    /proTxHash is not 32 bytes/);
  // the consts and enum, each pinned by MORE THAN ONE bad value, because a check written
  // as `!== 99` instead of `!== 1` survives a single-value assertion (the checker's
  // constructed mutation for the first draft was exactly "reject only 99")
  for (const v of [99, 2, 0, "1"]) {
    refuses(`formatVersion ${JSON.stringify(v)} is refused`,
      checkReceiptAgainstPool({ ...base, receipt: { ...good, formatVersion: v } }),
      /is not the const 1/);
  }
  for (const v of ["nonsense", "amount-reward-verifiedX", "AMOUNT-REWARD-VERIFIED"]) {
    refuses(`l1Verification ${JSON.stringify(v)} is refused`,
      checkReceiptAgainstPool({ ...base, receipt: { ...good, l1Verification: v } }),
      /is not in the schema's enum/);
  }
  for (const v of [99, 2, 0]) {
    refuses(`verificationMethodVersion ${JSON.stringify(v)} is refused`,
      checkReceiptAgainstPool({ ...base, receipt: { ...good, verificationMethodVersion: v } }),
      /is not the const 1/);
  }
  // the sweep's two v8-only additions: absent nodeType and out-of-range operatorFeeBps
  const v8p = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
    proTxHash: Buffer.alloc(32, 0xaa), status: "live" };
  const unpared8 = { ...receiptFor(m), nodeType: "regular", operatorFeeBps: 2000,
    targetDuffs: Number(m.target) };
  ok("v8: the full unpared receipt still passes",
    withLedger("v8", () => checkReceiptAgainstPool({ ...base, pool: v8p,
      receipt: unpared8 })).ok === true);
  // the three v8-only required fields, absent one at a time
  for (const k of ["nodeType", "operatorFeeBps", "targetDuffs"]) {
    refuses(`v8: an ABSENT ${k} is refused at the boundary`,
      withLedger("v8", () => checkReceiptAgainstPool({ ...base, pool: v8p,
        receipt: (({ [k]: gone, ...rest }) => rest)(unpared8) })),
      new RegExp(`missing required field ${k}`));
  }
  refuses("v8: an out-of-enum nodeType is refused, not only an absent one",
    withLedger("v8", () => checkReceiptAgainstPool({ ...base, pool: v8p,
      receipt: { ...unpared8, nodeType: "gold" } })),
    /nodeType "gold" is not in the schema's enum/);
  // targetDuffs is a schema INTEGER on the v8 receipt (pass 18, F1): the lenient carrier
  // read (toDuffs) also accepts a base-10 STRING, correct at the carrier but wrong at the
  // shape boundary, so the gate refuses a string the contract would reject
  refuses("v8: a STRING targetDuffs is refused at the shape boundary (schema requires integer)",
    withLedger("v8", () => checkReceiptAgainstPool({ ...base, pool: v8p,
      receipt: { ...unpared8, targetDuffs: String(unpared8.targetDuffs) } })),
    /targetDuffs is not a positive integer/);
  refuses("v8: a non-integer targetDuffs is refused",
    withLedger("v8", () => checkReceiptAgainstPool({ ...base, pool: v8p,
      receipt: { ...unpared8, targetDuffs: 1.5 } })),
    /targetDuffs is not a positive integer/);
  ok("v8: the integer targetDuffs still passes",
    withLedger("v8", () => checkReceiptAgainstPool({ ...base, pool: v8p, receipt: unpared8 })).ok === true);
  // the fee range, pinned above and below and at both legal boundaries, so a check
  // rejecting exactly one bad value cannot survive
  for (const v of [10001, 10002, -1, 1.5]) {
    refuses(`v8: operatorFeeBps ${v} is refused`,
      withLedger("v8", () => checkReceiptAgainstPool({ ...base, pool: v8p,
        receipt: { ...unpared8, operatorFeeBps: v } })),
      /operatorFeeBps is not an integer in 0\.\.10000/);
  }
  for (const v of [0, 10000]) {
    ok(`v8: the legal boundary operatorFeeBps ${v} still passes`,
      withLedger("v8", () => checkReceiptAgainstPool({ ...base, pool: v8p,
        receipt: { ...unpared8, operatorFeeBps: v } })).ok === true);
  }
}

// duty 6, the OWNER BINDING (pass 9 major 3, mandatory since pass 10 F5, with its
// declaration escape removed by pass 11 F1). Both owners are REQUIRED. There is no opt-out
// and no result field reporting a skipped binding, because a skipped binding can no longer
// produce an AFFIRMATIVE result. It still produces a result: a refusal.
{
  const m = manifest();
  const base = { contractId: GC, receipt: receiptFor(m), pool: poolFor(), poolId: GP };
  // the pair passes every other duty, or the refusals below prove nothing about duty 6
  ok("matching owners bind", checkReceiptAgainstPool({ ...base, receiptOwnerId: OA, poolOwnerId: OA }).ok === true);
  const mismatch = checkReceiptAgainstPool({ ...base, receiptOwnerId: OA, poolOwnerId: OB });
  ok("a receipt owned by someone other than the pool's operator is refused", mismatch.ok === false);
  // assert the reason carries BOTH identifiers rather than a fixed phrase: the phrase is
  // the author's wording and changes with it, while an operator resolving this refusal
  // needs the two values that disagreed (the phrase-matching version of this assertion
  // broke on a wording fix and told us nothing about the diagnostic's usefulness)
  ok("the refusal names both supplied owners",
    (mismatch.reason || "").includes(OA) && (mismatch.reason || "").includes(OB));
  // EXACTLY ONE identifier and NEITHER identifier each need their own case (artifact
  // check): a mutation refusing only when both are absent, while accepting a caller that
  // supplied one, would leave every both-absent assertion true
  const onlyReceipt = checkReceiptAgainstPool({ ...base, receiptOwnerId: OA });
  const onlyPool = checkReceiptAgainstPool({ ...base, poolOwnerId: OA });
  const neither = checkReceiptAgainstPool(base);
  ok("supplying ONLY the receipt owner is refused", onlyReceipt.ok === false);
  ok("supplying ONLY the pool owner is refused", onlyPool.ok === false);
  ok("supplying NEITHER id is refused, never a silent pass", neither.ok === false);
  ok("each refusal is specifically the binding, not an unrelated duty",
    [onlyReceipt, onlyPool, neither].every((r) => /owner binding/.test(r.reason || "")));

  // THE ESCAPE IS GONE, and this is the assertion that keeps it gone. The parameter no
  // longer exists, so passing it is simply an unrecognized key, and an unrecognized key
  // must buy exactly nothing. Restoring any declaration path flips these three.
  ok("a declaration parameter no longer buys a pass with neither owner",
    checkReceiptAgainstPool({ ...base, ownerBindingUnavailable: "this caller holds pool data only" }).ok === false);
  ok("a declaration parameter no longer buys a pass with one owner",
    checkReceiptAgainstPool({ ...base, poolOwnerId: OA, ownerBindingUnavailable: "x" }).ok === false);
  ok("no result reports a skipped binding, because none can be skipped",
    checkReceiptAgainstPool({ ...base, receiptOwnerId: OA, poolOwnerId: OA })
      .ownerBindingChecked === undefined);
  // supplying a declaration ALONGSIDE real owners is no longer a caller defect, because
  // the key means nothing; the owners decide, and they are matching here
  ok("an unrecognized key alongside real owners changes nothing",
    checkReceiptAgainstPool({ ...base, receiptOwnerId: OA, poolOwnerId: OA,
      ownerBindingUnavailable: "x" }).ok === true);

  // PRESENCE IS NOT AN IDENTITY (pre-commit check on the first draft of this repair). The
  // first fix tested `!== undefined` and compared String(a) to String(b), which admits
  // every pair below: two nulls, two empty strings, two plain objects coercing alike, and
  // a number against its own decimal string. Each would have been an affirmative result
  // over a binding nobody performed, which is the exact defect the parameter removal was
  // supposed to end. They are separate cases on purpose, because a partial repair (say,
  // rejecting null but not {}) would leave the others green.
  for (const [name, r, p] of [
    ["two nulls", null, null],
    ["two empty strings", "", ""],
    ["two plain objects coercing alike", {}, {}],
    ["a number against its own decimal string", 1, "1"],
    ["two identical non-identifier strings", "owner", "owner"],
    ["a real owner against a lookalike object", OA, { toString: () => OA }],
  ]) {
    const res = checkReceiptAgainstPool({ ...base, receiptOwnerId: r, poolOwnerId: p });
    ok(`duty 6 refuses ${name}`, res.ok === false);
    ok(`...and refuses it ON THE BINDING, not some later duty`,
      /owner binding/.test(res.reason || ""));
  }
  // and the shapes a caller legitimately holds all still bind
  ok("a base58 owner string binds",
    checkReceiptAgainstPool({ ...base, receiptOwnerId: OA, poolOwnerId: OA }).ok === true);
  ok("an SDK-style id object binds against the same owner as a string",
    checkReceiptAgainstPool({ ...base, receiptOwnerId: OA,
      poolOwnerId: { toBuffer: () => core.toId32(OA) } }).ok === true);
  ok("and an id object naming a DIFFERENT owner is still refused",
    checkReceiptAgainstPool({ ...base, receiptOwnerId: OA,
      poolOwnerId: { toBuffer: () => core.toId32(OB) } }).ok === false);
  // the comment names a Buffer as an accepted shape, so the suite has to show one rather
  // than let the sentence stand on its own (pre-commit re-check)
  ok("a raw Buffer owner binds against the same owner as a string",
    checkReceiptAgainstPool({ ...base, receiptOwnerId: core.toId32(OA), poolOwnerId: OA }).ok === true);
  ok("and a Buffer of the wrong length is refused, not truncated into a match",
    checkReceiptAgainstPool({ ...base, receiptOwnerId: Buffer.alloc(31, 1),
      poolOwnerId: Buffer.alloc(31, 1) }).ok === false);

  // A TEST THAT WAS HERE IS DELETED RATHER THAN KEPT, and the reason is worth more than the
  // assertion was. It called the pair (OA, OA) and asserted ok, under the heading that it
  // pinned the module's trust boundary and stopped the header's provenance wording from
  // drifting back to the wider claim. It did neither. It was operationally identical to
  // "matching owners bind" a few lines up, and NO test can observe prose: flipping the
  // header back to the wider claim leaves every assertion in this file green. Writing a
  // second copy of a passing call and labelling it with the property one wishes it checked
  // is the same defect as the source-grep control that F5 deleted, which is why it is going
  // the same way. The boundary is documented in the module header, where it can be read,
  // and it is not testable from inside a module that never sees a document.
}

console.log(`receiptPoolCheckTest: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
