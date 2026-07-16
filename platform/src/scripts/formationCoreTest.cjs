/**
 * Offline tests for the formation core (plain `node`, no devnet): the forming-hash
 * convention, owner aggregation (several pledges by one member become one share), and
 * the largest-remainder allocation (exact 10000 bps, exact-fill required, deterministic,
 * no sub-basis-point share).
 */
const core = require("./formationCore.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const throws = (name, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || "")); }
};

const T = core.TARGETS.regular; // 100000000000n
const row = (id, owner, amount, at) => ({ id, owner, amount, at });

// forming-hash convention
ok("forming placeholder", core.isFormingHash(Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 7)])));
ok("real hash not forming", !core.isFormingHash(Buffer.alloc(32, 1)));
throws("wrong length refused", () => core.isFormingHash(Buffer.alloc(31, 0)), /32-byte/);

// aggregation: two pledges by one owner merge, order deterministic by age
{
  const rows = [row("r2", "ownerA", 10000000000n, 20), row("r1", "ownerB", 60000000000n, 10),
    row("r3", "ownerA", 30000000000n, 30)];
  const agg = core.aggregateByOwner(rows);
  ok("aggregates to two owners", agg.length === 2);
  const a = agg.find((o) => o.owner === "ownerA");
  ok("owner sum merged", a.amount === 40000000000n && a.reqIds.join(",") === "r2,r3");
  ok("age order kept", agg[0].owner === "ownerB");
}

// allocation: 600/400 exact
{
  const alloc = core.allocateBps(core.aggregateByOwner([
    row("r1", "A", 60000000000n, 1), row("r2", "B", 40000000000n, 2)]), T);
  ok("600/400 -> 6000/4000", alloc.find((a) => a.owner === "A").bps === 6000
    && alloc.find((a) => a.owner === "B").bps === 4000);
}

// allocation: thirds with remainders still sum to exactly 10000
{
  const alloc = core.allocateBps(core.aggregateByOwner([
    row("r1", "A", 33333333333n, 1), row("r2", "B", 33333333333n, 2),
    row("r3", "C", 33333333334n, 3)]), T);
  const sum = alloc.reduce((s, a) => s + a.bps, 0);
  ok("thirds sum 10000", sum === 10000);
  ok("thirds all positive", alloc.every((a) => a.bps >= 1));
}

// determinism: same input twice gives identical weights
{
  const rows = [row("r1", "A", 12345678900n, 5), row("r2", "B", 87654321100n, 3)];
  const a1 = core.allocateBps(core.aggregateByOwner(rows), T).map((a) => `${a.owner}:${a.bps}`).join("|");
  const a2 = core.allocateBps(core.aggregateByOwner(rows), T).map((a) => `${a.owner}:${a.bps}`).join("|");
  ok("deterministic", a1 === a2);
}

// exact-fill required: a partial set must throw, never re-stretch to 10000 (the resume
// blocker from the independent review)
throws("partial set refused", () => core.allocateBps(core.aggregateByOwner([
  row("r1", "A", 40000000000n, 1)]), T), /exact fill/);

// sub-basis-point aggregate refused
throws("sub-bps refused", () => core.allocateBps(core.aggregateByOwner([
  row("r1", "A", 99999999999n + 1n - 9999999n, 1), row("r2", "B", 9999999n, 2)]), T), /basis point/);

// --- verifyRegistration (L1 registration verification) ---
const C = (amt, addr) => ({ amountDuffs: amt, rewardAddress: addr });
// a good match: two participants, amounts and reward addresses agree, total = target
ok("verify: exact match passes", core.verifyRegistration(
  [C("60000000000", "yAAA"), C("40000000000", "yBBB")],
  [C("60000000000", "yAAA"), C("40000000000", "yBBB")], T.toString()).ok);
// order-independent (multiset): registered shares in a different order still match
ok("verify: order-independent match", core.verifyRegistration(
  [C("60000000000", "yAAA"), C("40000000000", "yBBB")],
  [C("40000000000", "yBBB"), C("60000000000", "yAAA")], T.toString()).ok);
// wrong participant count fails
{
  const r = core.verifyRegistration([C("100000000000", "yAAA")],
    [C("60000000000", "yAAA"), C("40000000000", "yBBB")], T.toString());
  ok("verify: wrong count fails", !r.ok && /share\(s\).*participant\(s\)/.test(r.mismatches.join(";")));
}
// wrong amounts fail even when the total still equals the target (70+30 = 60+40 = 100),
// surfaced via the (amount, reward) pair
{
  const r = core.verifyRegistration(
    [C("60000000000", "yAAA"), C("40000000000", "yBBB")],
    [C("70000000000", "yAAA"), C("30000000000", "yBBB")], T.toString());
  ok("verify: wrong amounts (total preserved) fail", !r.ok && /pairing differs/.test(r.mismatches.join(";")));
}
// wrong total fails
{
  const r = core.verifyRegistration(
    [C("60000000000", "yAAA"), C("40000000000", "yBBB")],
    [C("60000000000", "yAAA"), C("39000000000", "yBBB")], T.toString());
  ok("verify: wrong total fails", !r.ok && /sum to.*target/.test(r.mismatches.join(";")));
}
// wrong reward destination fails (amount, reward) pairing when both sides comparable
{
  const r = core.verifyRegistration(
    [C("60000000000", "yAAA"), C("40000000000", "yBBB")],
    [C("60000000000", "yAAA"), C("40000000000", "yEVIL")], T.toString());
  ok("verify: wrong reward addr fails", !r.ok && /pairing differs/.test(r.mismatches.join(";")));
}
// THE CROSS-AMOUNT REWARD SWAP (review finding): same amount set, same reward set, but
// swapped pairing. Separate-multiset comparison would pass; pair comparison must fail.
{
  const r = core.verifyRegistration(
    [C("60000000000", "yAAA"), C("40000000000", "yBBB")],   // 600->A, 400->B
    [C("60000000000", "yBBB"), C("40000000000", "yAAA")], T.toString()); // 600->B, 400->A
  ok("verify: cross-amount reward swap is caught", !r.ok && /pairing differs/.test(r.mismatches.join(";")));
}
// duplicate amounts with matching pairs still pass (the pair, not the bare amount, is key)
ok("verify: duplicate amounts, matching pairs pass", core.verifyRegistration(
  [C("50000000000", "yAAA"), C("50000000000", "yBBB")],
  [C("50000000000", "yBBB"), C("50000000000", "yAAA")], T.toString()).ok);
// an unresolved manifest reward => INCOMPARABLE (ok:false), so the caller fails closed
{
  const r = core.verifyRegistration(
    [C("60000000000", "(unresolved)"), C("40000000000", "yBBB")],
    [C("60000000000", "yAAA"), C("40000000000", "yBBB")], T.toString());
  ok("verify: unresolved manifest reward is incomparable, not ok", !r.ok && r.incomparable === true);
}
// a null registered address => INCOMPARABLE too (fail closed, do not skip)
{
  const r = core.verifyRegistration(
    [C("60000000000", "yAAA"), C("40000000000", "yBBB")],
    [C("60000000000", null), C("40000000000", "yBBB")], T.toString());
  ok("verify: null share addr is incomparable, not ok", !r.ok && r.incomparable === true);
}

// --- canonical allocation preimage / hash (v8 completion receipt) ---
// A PUBLISHED golden known-answer vector: fixed ids and manifest, pinned canonical bytes and
// sha256. An independent implementation must reproduce these exactly, and any tooling change
// that alters the bytes trips this test. The ids are real base58 32-byte identifiers (sha256 of
// a fixed seed, base58-encoded); pinned here so the vector is self-contained.
const GC = "3EbgWjxUoX6J9XbqqxrEktm7tUFBQ5fQyKaiAzXCULxf"; // contract id
const GP = "47doihuxfjfeoqi4PrKLY58Z56J6BhXekMmhW3z63QT8"; // pool id
const OA = "8sCudmZNvmDC9nXCGRWk1NMStKaeqCaWLa7eYTEKuT8Y";
const OB = "52D4DcjgFZU1KktALjGpcfGoxR1987BEjTXxbnNcNfAc";
const OC = "FZ9HF6oANQxZDXGXGiKh8uXdPfwcp4rwfrzqQJcdRNgv";
const goldenManifest = () => ({
  v: 1, poolId: GP, realHash: "aa".repeat(32), target: "100000000000",
  owners: [
    { owner: OA, amountDuffs: "50000000000", bps: 5000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
    { owner: OB, amountDuffs: "30000000000", bps: 3000, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
    { owner: OC, amountDuffs: "20000000000", bps: 2000, rewardScriptHex: "76A914" + "33".repeat(20) + "88AC" }, // uppercase in, lowercase out
  ],
});
const GOLDEN_PREIMAGE =
  '["tegara-completion-allocation",1,"3EbgWjxUoX6J9XbqqxrEktm7tUFBQ5fQyKaiAzXCULxf",' +
  '"47doihuxfjfeoqi4PrKLY58Z56J6BhXekMmhW3z63QT8","100000000000",' +
  '[["52D4DcjgFZU1KktALjGpcfGoxR1987BEjTXxbnNcNfAc","30000000000",3000,"76a914222222222222222222222222222222222222222288ac"],' +
  '["8sCudmZNvmDC9nXCGRWk1NMStKaeqCaWLa7eYTEKuT8Y","50000000000",5000,"76a914111111111111111111111111111111111111111188ac"],' +
  '["FZ9HF6oANQxZDXGXGiKh8uXdPfwcp4rwfrzqQJcdRNgv","20000000000",2000,"76a914333333333333333333333333333333333333333388ac"]]]';
const GOLDEN_HASH = "a4818aee6eeeea3c5695b1f4cff68bd1512e88f06bc69358c5d2f79bba1f1421";

const gPre = core.allocationPreimage(GC, goldenManifest());
ok("golden preimage bytes match", gPre.toString("utf8") === GOLDEN_PREIMAGE);
ok("golden hash matches", core.allocationHash(gPre).toString("hex") === GOLDEN_HASH);
ok("rewardScriptHex lowercased in canonical form", !gPre.toString("utf8").includes("76A914"));
ok("rows sorted by decoded id, not base58 string", // OB decodes before OA even though "5" < "8" too; assert the actual order
  gPre.toString("utf8").indexOf(OB) < gPre.toString("utf8").indexOf(OA));

// F-K: the golden ids above happen to have identical base58-string and decoded-byte order,
// so a string-sort reimplementation would pass the whole suite. Pin the ONE rule most likely
// to be reimplemented wrongly with a DISAGREEING pair: SID0 (44 chars) sorts BEFORE SID1 by
// base58 string, but AFTER it by decoded 32-byte value. The canonical order must be [SID1, SID0].
{
  const SID0 = "ChfRNchubqXjf2bxaYQzv7QhczADa7PtYECn6763NEvb"; // 44 chars, string-smaller
  const SID1 = "tQTBGHg5TTmgx7pDSVdfdVWnLBSX61K6yCfhNUViTq9";  // 43 chars, byte-smaller
  ok("sort pair: base58-string vs decoded-byte order genuinely disagree",
    SID0 < SID1 && Buffer.compare(core.decodeId32(SID1), core.decodeId32(SID0)) < 0);
  const sortManifest = {
    v: 1, poolId: GP, realHash: "aa".repeat(32), target: "100000000000",
    owners: [
      { owner: SID0, amountDuffs: "50000000000", bps: 5000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
      { owner: SID1, amountDuffs: "50000000000", bps: 5000, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
    ],
  };
  const sPre = core.allocationPreimage(GC, sortManifest).toString("utf8");
  ok("canonical order places the byte-smaller id first (SID1 before SID0)", sPre.indexOf(SID1) < sPre.indexOf(SID0));
  // a STRING-sorted variant of the same rows must be REJECTED by the verifier
  const arr = core.buildAllocationArray(GC, sortManifest);
  arr[5] = [...arr[5]].reverse(); // now [SID0, SID1] = base58-string order, non-canonical
  const stringSorted = Buffer.from(JSON.stringify(arr), "utf8");
  const r = core.verifyReceiptAllocation(GC, {
    allocationRows: stringSorted, allocationHash: core.allocationHash(stringSorted),
    poolId: GP, targetDuffs: "100000000000", participantCount: 2,
  });
  ok("a string-sorted (non-canonical) variant is rejected", !r.ok && /sort|order/i.test(r.reason || ""));
}

// determinism and reorder-invariance
ok("same manifest hashes equal", core.allocationHash(core.allocationPreimage(GC, goldenManifest()))
  .equals(core.allocationHash(core.allocationPreimage(GC, goldenManifest()))));
{
  const m = goldenManifest(); m.owners.reverse(); // arrival order changed
  ok("reordering owners hashes equal (canonical sort)",
    core.allocationHash(core.allocationPreimage(GC, m)).equals(Buffer.from(GOLDEN_HASH, "hex")));
}
// field sensitivity: a change to the allocation changes the hash. Amounts and bps move together
// under the largest-remainder consistency rule, so vary them as a consistent set, not one field.
const gHashBuf = Buffer.from(GOLDEN_HASH, "hex");
{
  // same owners and target, value shifted 5->5.5 / 3->2.5, bps tracking the amounts (still valid)
  const m = goldenManifest();
  m.owners[0].amountDuffs = "55000000000"; m.owners[0].bps = 5500;
  m.owners[1].amountDuffs = "25000000000"; m.owners[1].bps = 2500;
  ok("a re-weighted (still valid) allocation changes hash", !core.allocationHash(core.allocationPreimage(GC, m)).equals(gHashBuf));
}
{
  const m = goldenManifest(); m.owners[0].rewardScriptHex = "76a914" + "44".repeat(20) + "88ac";
  ok("reward script change changes hash", !core.allocationHash(core.allocationPreimage(GC, m)).equals(gHashBuf));
}
{
  const m = goldenManifest(); m.poolId = OA; // a different (valid) pool id
  ok("poolId change changes hash", !core.allocationHash(core.allocationPreimage(GC, m)).equals(gHashBuf));
}
ok("contractId is bound into the hash (cross-contract reuse changes it)",
  !core.allocationHash(core.allocationPreimage(GP, goldenManifest())).equals(gHashBuf)); // GP as a stand-in different id

// build-time validation throws
throws("bps not the largest-remainder share of the amount refused (builder)",
  () => { const m = goldenManifest(); m.owners[0].bps = 4000; core.allocationPreimage(GC, m); }, /largest-remainder/);
throws("bps sum != 10000 refused", () => { const m = goldenManifest(); m.owners[0].bps = 5001; m.owners[1].bps = 3001; core.allocationPreimage(GC, m); }, /bps sum/);
throws("too many owners refused", () => {
  const m = goldenManifest();
  for (let i = 0; i < 6; i++) m.owners.push({ owner: OA, amountDuffs: "1", bps: 1, rewardScriptHex: "76a91400" });
  core.allocationPreimage(GC, m);
}, /owner count/);
throws("zero owners refused", () => core.allocationPreimage(GC, { poolId: GP, target: "1", owners: [] }), /owner count/);
throws("duplicate owner refused", () => { const m = goldenManifest(); m.owners[1].owner = OA; core.allocationPreimage(GC, m); }, /duplicate/);
throws("bad owner id refused", () => { const m = goldenManifest(); m.owners[0].owner = "not-an-id"; core.allocationPreimage(GC, m); }, /base58 32-byte/);
throws("odd-length script refused", () => { const m = goldenManifest(); m.owners[0].rewardScriptHex = "76a9140"; core.allocationPreimage(GC, m); }, /lowercase hex/);
throws("non-string amount refused", () => { const m = goldenManifest(); m.owners[0].amountDuffs = 5; core.allocationPreimage(GC, m); }, /base-10 duff/);
throws("bad contractId refused", () => core.allocationPreimage("nope", goldenManifest()), /contractId/);

// verifyReceiptAllocation (the self-contained third-party check)
const goldenReceipt = () => ({ allocationRows: Buffer.from(GOLDEN_PREIMAGE, "utf8"),
  allocationHash: Buffer.from(GOLDEN_HASH, "hex"), poolId: GP, targetDuffs: "100000000000", participantCount: 3 });
ok("verify: golden receipt ok", core.verifyReceiptAllocation(GC, goldenReceipt()).ok);
{
  const r = goldenReceipt(); r.allocationHash = Buffer.alloc(32, 9);
  ok("verify: hash mismatch not ok", !core.verifyReceiptAllocation(GC, r).ok
    && /allocationHash does not match/.test(core.verifyReceiptAllocation(GC, r).reason));
}
ok("verify: wrong expected contract not ok (cross-contract)",
  !core.verifyReceiptAllocation(GP, goldenReceipt()).ok);
{
  // inject insignificant whitespace, recompute the hash so the hash check passes; the byte-exact
  // canonical re-serialize must still reject it
  const spaced = Buffer.from(GOLDEN_PREIMAGE.replace("[[", "[ ["), "utf8");
  const r = { allocationRows: spaced, allocationHash: core.allocationHash(spaced) };
  const v = core.verifyReceiptAllocation(GC, r);
  ok("verify: non-canonical whitespace rejected", !v.ok && /not canonical/.test(v.reason));
}
{
  // mis-sorted rows: swap the first two, re-hash; the strict decoded-id order check must fail
  const arr = JSON.parse(GOLDEN_PREIMAGE); const t = arr[5][0]; arr[5][0] = arr[5][1]; arr[5][1] = t;
  const bytes = Buffer.from(JSON.stringify(arr), "utf8");
  const v = core.verifyReceiptAllocation(GC, { allocationRows: bytes, allocationHash: core.allocationHash(bytes) });
  ok("verify: mis-sorted rows rejected", !v.ok && /sorted/.test(v.reason));
}
{
  const r = goldenReceipt(); r.participantCount = 4;
  ok("verify: top-level participantCount mismatch not ok",
    !core.verifyReceiptAllocation(GC, r).ok && /participantCount/.test(core.verifyReceiptAllocation(GC, r).reason));
}
{
  const r = goldenReceipt(); r.poolId = OA;
  ok("verify: top-level poolId mismatch not ok",
    !core.verifyReceiptAllocation(GC, r).ok && /poolId/.test(core.verifyReceiptAllocation(GC, r).reason));
}

// --- review round: input-boundary robustness of the verifier and decoder ---
// decodeId32 is total over 32-byte ids: a valid id with leading zero bytes is shorter than 43
// chars (8 zero bytes + 24 0xff -> 41 chars) and must still decode
const SHORT_ID = "11111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKL"; // 8x 0x00 then 24x 0xff
{
  const d = core.decodeId32(SHORT_ID);
  ok("decodeId32 accepts a valid 41-char (leading-zero) id",
    d !== null && d.length === 32 && d.subarray(0, 8).every((b) => b === 0) && d.subarray(8).every((b) => b === 0xff));
}
ok("decodeId32 rejects an alphabet-valid non-32-byte string", core.decodeId32("2") === null);
ok("toId32 accepts raw 32 bytes", core.toId32(Buffer.alloc(32, 1)) !== null);
ok("toId32 rejects wrong-length bytes", core.toId32(Buffer.alloc(31, 1)) === null);

// finding 1: the on-ledger receipt carries poolId as a byteArray, not base58; correspondence must
// still pass on the ledger-native form
{
  const r = goldenReceipt(); r.poolId = core.decodeId32(GP); // 32 raw bytes, as read from the ledger
  ok("verify: ledger-native (bytes) poolId still matches", core.verifyReceiptAllocation(GC, r).ok);
}
// robustness: allocationHash may be given as a 64-hex string
{
  const r = goldenReceipt(); r.allocationHash = GOLDEN_HASH; // hex string form
  ok("verify: hex-string allocationHash accepted", core.verifyReceiptAllocation(GC, r).ok);
}
// finding 5: a malformed allocationHash fails closed, never throws
{
  let threw = false, res = null;
  try { res = core.verifyReceiptAllocation(GC, { allocationRows: Buffer.from(GOLDEN_PREIMAGE, "utf8"), allocationHash: {} }); }
  catch (e) { threw = true; }
  ok("verify: object allocationHash returns not-ok, not a throw", !threw && res && !res.ok);
}
// finding 4: an invalid EXPECTED contractId is rejected up front (not silently string-matched)
ok("verify: invalid expected contractId rejected",
  !core.verifyReceiptAllocation("x", goldenReceipt()).ok
  && /expected contractId/.test(core.verifyReceiptAllocation("x", goldenReceipt()).reason));
// finding 4: an invalid EMBEDDED contractId is rejected even if a caller passes the same junk
{
  const arr = JSON.parse(GOLDEN_PREIMAGE); arr[2] = "x"; // not a base58 id
  const bytes = Buffer.from(JSON.stringify(arr), "utf8");
  const v = core.verifyReceiptAllocation(GC, { allocationRows: bytes, allocationHash: core.allocationHash(bytes) });
  ok("verify: invalid embedded contractId rejected", !v.ok && /embedded contractId/.test(v.reason));
}
// strengthening: embedded amounts must sum to the embedded target
{
  const arr = JSON.parse(GOLDEN_PREIMAGE); arr[4] = "99999999999"; // target below the 100000000000 amount sum
  const bytes = Buffer.from(JSON.stringify(arr), "utf8");
  const v = core.verifyReceiptAllocation(GC, { allocationRows: bytes, allocationHash: core.allocationHash(bytes) });
  ok("verify: amounts not summing to target rejected", !v.ok && /sum to/.test(v.reason));
}
// finding: bps that do not match the amounts must be rejected even when they sum to 10000 and are
// individually in range (rows are [OB:3000, OA:5000, OC:2000]; give OB/OA 4000/4000)
{
  const arr = JSON.parse(GOLDEN_PREIMAGE); arr[5][0][2] = 4000; arr[5][1][2] = 4000; // sum still 10000
  const bytes = Buffer.from(JSON.stringify(arr), "utf8");
  const v = core.verifyReceiptAllocation(GC, { allocationRows: bytes, allocationHash: core.allocationHash(bytes) });
  ok("verify: bps not matching amounts rejected", !v.ok && /largest-remainder/.test(v.reason));
}
// finding: a crafted top-level targetDuffs must fail closed, not throw on String() coercion
{
  let threw = false, res = null;
  try { res = core.verifyReceiptAllocation(GC, { ...goldenReceipt(), targetDuffs: { toString: null, valueOf: null } }); }
  catch (e) { threw = true; }
  ok("verify: crafted targetDuffs object returns not-ok, not a throw", !threw && res && !res.ok);
}

// --- second re-check: ranking, the byte bound, and total fail-closed ---
// the rounding +1 must go to the LARGEST remainder. Thirds at target 100000000000: the .334 owner
// has the larger remainder, so it (OA) must carry 3334; assigning it elsewhere is invalid.
const rankManifest = () => ({
  v: 1, poolId: GP, realHash: "aa".repeat(32), target: "100000000000",
  owners: [
    { owner: OA, amountDuffs: "33333333334", bps: 3334, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
    { owner: OB, amountDuffs: "33333333333", bps: 3333, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
    { owner: OC, amountDuffs: "33333333333", bps: 3333, rewardScriptHex: "76a914" + "33".repeat(20) + "88ac" },
  ],
});
{
  const pre = core.allocationPreimage(GC, rankManifest());
  ok("ranking: correct largest-remainder allocation accepted",
    core.verifyReceiptAllocation(GC, { allocationRows: pre, allocationHash: core.allocationHash(pre) }).ok);
  // move the +1 off the largest-remainder owner: canonical order is [OB, OA, OC]; give OB the 3334
  const arr = JSON.parse(pre.toString("utf8")); arr[5][0][2] = 3334; arr[5][1][2] = 3333; // OB up, OA down
  const bytes = Buffer.from(JSON.stringify(arr), "utf8");
  const v = core.verifyReceiptAllocation(GC, { allocationRows: bytes, allocationHash: core.allocationHash(bytes) });
  ok("ranking: +1 on a smaller remainder rejected (verifier)", !v.ok && /largest remainders/.test(v.reason));
}
throws("ranking: +1 on a smaller remainder rejected (builder)", () => {
  const m = rankManifest(); m.owners[0].bps = 3333; m.owners[1].bps = 3334; core.allocationPreimage(GC, m);
}, /largest remainders/);

// the helper must refuse what the on-ledger 2048-byte schema bound would refuse
throws("oversize preimage refused (builder)", () => {
  const big = "9".repeat(2100); // one owner, amount == target, a ~2.1 KB number
  core.allocationPreimage(GC, { poolId: GP, target: big, owners: [{ owner: OA, amountDuffs: big, bps: 10000, rewardScriptHex: "76a91400" }] });
}, /exceeds the 2048/);
{
  const oversized = Buffer.alloc(3000, 0x20);
  const v = core.verifyReceiptAllocation(GC, { allocationRows: oversized, allocationHash: core.allocationHash(oversized) });
  ok("verify: oversize allocationRows rejected", !v.ok && /exceeds the 2048/.test(v.reason));
}
// total fail-closed: an accessor that throws must not crash the verifier, even when the thrown value
// is hostile to string interpolation (a Symbol, or an object whose `message` getter throws)
for (const [name, thrown] of [
  ["Error", () => new Error("boom")],
  ["Symbol", () => Symbol("boom")],
  ["object with throwing message getter", () => ({ get message() { throw new Error("nested"); } })],
]) {
  const r = {}; Object.defineProperty(r, "allocationRows", { get() { throw thrown(); } });
  let threw = false, res = null;
  try { res = core.verifyReceiptAllocation(GC, r); } catch (e) { threw = true; }
  ok(`verify: a throwing accessor (${name}) fails closed, not a throw`, !threw && res && !res.ok && /aborted/.test(res.reason));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
