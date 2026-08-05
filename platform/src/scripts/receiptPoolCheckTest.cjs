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
    // (a soundness review): every case here was verifying a receipt the contract could
    // not accept. The default is a real node hash outside the reserved namespace.
    proTxHash: Buffer.from(m.realHash, "hex"),
    slotIndex, formatVersion: 1,
    allocationRows: rows, allocationHash: core.allocationHash(rows),
    participantCount: m.owners.length, l1Verification: "demo-unverified", verificationMethodVersion: 1,
  };
};

const poolFor = ({ target = REGULAR, nodeType = "regular", slotIndex = 0, book = null } = {}) => ({
  slotIndex, nodeType, operatorFeeBps: 2000, targetDuffs: Number(target),
  ...(book ? { slotDuffs: book[0], slotCount: book[1] } : {}),
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
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" }),
    /embedded target 400000000000 contradicts pool targetDuffs 100000000000/);
}

// ---------------------------------------------------------------------------
// 2. the happy paths
// ---------------------------------------------------------------------------
{
  const m = manifest();
  const r = checkReceiptAgainstPool({
    contractId: GC, receipt: receiptFor(m), pool: poolFor(), poolId: GP,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" });
  ok("a matching receipt and pool pass", r.ok === true);
  ok("and the embedded allocation comes back for the caller", r.ok && r.embedded.participantCount === 3);
}
{
  // with a slot book whose product equals the target
  const r = checkReceiptAgainstPool({
    contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: poolFor({ book: [25000000000, 4] }),
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" });
  ok("a consistent slot book passes", r.ok === true);
}
{
  // an evo pool, to prove the nodeType target is read rather than assumed
  const r = checkReceiptAgainstPool({
    contractId: GC, receipt: receiptFor(manifest(EVO)), poolId: GP,
    pool: poolFor({ target: EVO, nodeType: "evo" }),
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" });
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
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" });
  ok("a matching pair passes when poolId is an SDK-style id object", r.ok === true);
  // and the identity precondition still refuses a WRONG pool given in the same shape
  const wrongIdObject = { toBuffer: () => core.toId32(OTHER_POOL), toString: () => OTHER_POOL };
  refuses("an id object naming a different pool is still refused",
    checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), pool: poolFor(),
      poolId: wrongIdObject,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" }),
    /not the pool this receipt names/);
}

// ---------------------------------------------------------------------------
// 3. duty 3, the pool's own coherence
// ---------------------------------------------------------------------------
refuses("a pool whose target is not its nodeType's target is refused",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest(EVO)), poolId: GP,
    pool: poolFor({ target: EVO, nodeType: "regular" }),
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" }),
  /is not the regular target/);
refuses("an unknown nodeType is refused",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: { ...poolFor(), nodeType: "gold" },
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" }),
  /is not regular or evo/);
refuses("a slot book that does not multiply to the target is refused",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: poolFor({ book: [25000000000, 3] }),
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" }),
  /does not equal targetDuffs/);
refuses("a one-sided slot book is refused",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()), poolId: GP,
    pool: { ...poolFor(), slotDuffs: 25000000000 },
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" }),
  /one-sided slot book/);

// ---------------------------------------------------------------------------
// 4. duty 4 and the identity precondition
// ---------------------------------------------------------------------------
refuses("a receipt whose slotIndex differs from the pool's is refused",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest(), { slotIndex: 3 }),
    pool: poolFor({ slotIndex: 1 }), poolId: GP,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" }),
  /slotIndex 3 does not match pool slotIndex 1/);
refuses("a receipt checked against the WRONG pool is refused before any comparison",
  checkReceiptAgainstPool({ contractId: GC, receipt: receiptFor(manifest()),
    pool: poolFor(), poolId: OTHER_POOL,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" }),
  /not the pool this receipt names/);
refuses("a receipt bound to another contract is refused",
  checkReceiptAgainstPool({ contractId: OTHER_POOL, receipt: receiptFor(manifest()),
    pool: poolFor(), poolId: GP,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" }),
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
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" })).ok === true);

  refuses("v8: a receipt target that is not the nodeType's target is refused",
    withLedger("v8", () => checkReceiptAgainstPool({
      contractId: GC, receipt: unpared(manifest(EVO)), pool: v8pool, poolId: GP,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" })),
    /receipt targetDuffs 400000000000 is not the regular target/);

  refuses("v8: a receipt nodeType contradicting the pool is refused",
    withLedger("v8", () => checkReceiptAgainstPool({
      contractId: GC, receipt: unpared(manifest(), { nodeType: "evo" }), pool: v8pool, poolId: GP,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" })),
    /receipt nodeType "evo" contradicts pool "regular"/);

  // and the pared shape is refused on v8, since its target is nowhere to be found
  refuses("v8: a PARED receipt has no target to check and is refused",
    withLedger("v8", () => checkReceiptAgainstPool({
      contractId: GC, receipt: receiptFor(manifest()), pool: v8pool, poolId: GP,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" })),
    /receipt targetDuffs is not a duff amount/);
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

  // BOTH representations of poolId reach the check in the wild (the SDK's Buffer, and a
// base58 string from a hand-built or packet fixture), and toId32 is the one coercion
// point; pin that both are accepted so a change there fails here rather than in a live
// run (pass-7 wave, note)
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
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" });
  const asString = checkReceiptAgainstPool({ contractId: GC, receipt: strReceipt,
    pool: poolFor(), poolId: GP,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" });
  ok("a Buffer poolId verifies (the type the SDK and the writer use)", asBuffer.ok === true);
  ok("a base58-string poolId verifies identically (toId32 is the coercion point)",
    asString.ok === true);
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
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" });
  ok("a soundness-review finding: a receipt naming the reserved forming namespace is REFUSED by the shared check",
    r.ok === false && /forming/i.test(r.reason || ""));
  const good = checkReceiptAgainstPool({ contractId: GC, receipt: withHash(real),
    pool: poolFor(), poolId: GP,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" });
  ok("a soundness-review finding: a real node hash still verifies", good.ok === true);
  const missing = checkReceiptAgainstPool({ contractId: GC,
    receipt: { ...receiptFor(m), proTxHash: undefined }, pool: poolFor(), poolId: GP,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" });
  ok("a soundness-review finding: a receipt with no proTxHash is refused", missing.ok === false);
  const short = checkReceiptAgainstPool({ contractId: GC, receipt: withHash(Buffer.alloc(31, 1)),
    pool: poolFor(), poolId: GP,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" });
  ok("a soundness-review finding: a proTxHash of the wrong length is refused", short.ok === false);
}

// duty 6, the OWNER BINDING (pass 9, major 3). Optional by parameter, because callers
// that hold only document data cannot supply owners; supplying ONE is a caller defect.
{
  const m = manifest();
  const base = { contractId: GC, receipt: receiptFor(m), pool: poolFor(), poolId: GP };
  ok("matching owners bind", checkReceiptAgainstPool({ ...base, receiptOwnerId: OA, poolOwnerId: OA }).ok === true);
  const mismatch = checkReceiptAgainstPool({ ...base, receiptOwnerId: OA, poolOwnerId: OB });
  ok("a receipt owned by someone other than the pool's operator is refused", mismatch.ok === false);
  ok("the refusal names both owners", /owned by/.test(mismatch.reason || ""));
  ok("supplying only the receipt owner is refused as a caller defect",
    checkReceiptAgainstPool({ ...base, receiptOwnerId: OA }).ok === false);
  ok("supplying only the pool owner is refused as a caller defect",
    checkReceiptAgainstPool({ ...base, poolOwnerId: OA,
    ownerBindingUnavailable: "offline suite exercising a duty other than the owner binding" }).ok === false);
  // duty 6 FAILS CLOSED (pass 10, F5): supplying neither id is now a refusal, not a
  // silent pass, unless the caller DECLARES it cannot bind and says why
  const silent = checkReceiptAgainstPool(base);
  ok("supplying NEITHER id is refused, never a silent pass", silent.ok === false);
  ok("the refusal names the fail-closed duty", /fails closed/.test(silent.reason || ""));
  const declaredOk = checkReceiptAgainstPool({ ...base,
    ownerBindingUnavailable: "this caller holds pool data only" });
  ok("an explicit declaration proceeds", declaredOk.ok === true);
  ok("...and REPORTS that the binding was not checked",
    declaredOk.ownerBindingChecked === false);
  ok("a real binding reports that it WAS checked",
    checkReceiptAgainstPool({ ...base, receiptOwnerId: OA, poolOwnerId: OA }).ownerBindingChecked === true);
  ok("declaring AND supplying is a caller defect, not a preference",
    checkReceiptAgainstPool({ ...base, receiptOwnerId: OA, poolOwnerId: OA,
      ownerBindingUnavailable: "x" }).ok === false);
  ok("an empty declaration string does not count as a declaration",
    checkReceiptAgainstPool({ ...base, ownerBindingUnavailable: "" }).ok === false);
}

console.log(`receiptPoolCheckTest: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
