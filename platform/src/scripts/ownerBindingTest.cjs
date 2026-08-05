/**
 * BEHAVIOURAL coverage of duty 6, the owner binding, replacing a fake control.
 *
 * The control it replaces was a static grep of the callers' SOURCE TEXT for the argument
 * names. That test could not distinguish a real argument from the same words sitting in
 * a comment, so deleting the arguments kept it green (pass 10, F5). The root cause was
 * not the test: duty 6's parameters were optional, so a caller supplying neither got a
 * silent ok, and the grep existed to compensate for a hole the design had created.
 *
 * With duty 6 failing closed, the property is now observable directly: EVERY caller must
 * either supply both owners or declare it cannot. This suite drives each reader against
 * a stub platform and asserts what the reader CONCLUDES, so a caller that stops passing
 * owners changes an outcome here rather than a substring.
 *
 * Run: node src/scripts/ownerBindingTest.cjs
 */
const path = require("path");
const { Identifier } = require("@dashevo/wasm-dpp");
const crypto = require("crypto");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };

// v9 is the operative ledger of the release profile, and the pared receipt shape is
// what the shared check reads there; pinned so this suite exercises the production path
process.env.LEDGER = "v9";
const { checkReceiptAgainstPool } = require("./receiptPoolCheck.cjs");
const core = require("./formationCore.cjs");

// ---- 1. the contract itself, at the level every caller inherits ----
const GC = "3EbgWjxUoX6J9XbqqxrEktm7tUFBQ5fQyKaiAzXCULxf";
const GP = "47doihuxfjfeoqi4PrKLY58Z56J6BhXekMmhW3z63QT8";
const A = "8sCudmZNvmDC9nXCGRWk1NMStKaeqCaWLa7eYTEKuT8Y";
const B = "52D4DcjgFZU1KktALjGpcfGoxR1987BEjTXxbnNcNfAc";
const C = "FZ9HF6oANQxZDXGXGiKh8uXdPfwcp4rwfrzqQJcdRNgv";

// A pair that passes EVERY OTHER DUTY, so the only reason this check can refuse is the
// owner binding. The first draft of this suite used a bare stub, which the old code also
// refused, but for the allocation duty, so the assertion observed a refusal that had
// nothing to do with the property it named. That is precisely the proxy this file exists
// to replace, and it was caught by watching the suite against the old code.
const REGULAR = "100000000000";
const REAL_HASH = "dd" + "56".repeat(31);
const goodManifest = {
  v: 1, poolId: GP, realHash: REAL_HASH, target: REGULAR,
  owners: [
    { owner: A, amountDuffs: "50000000000", bps: 5000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
    { owner: B, amountDuffs: "30000000000", bps: 3000, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
    { owner: C, amountDuffs: "20000000000", bps: 2000, rewardScriptHex: "76a914" + "33".repeat(20) + "88ac" },
  ],
};
const goodRows = core.allocationPreimage(GC, goodManifest);
const goodReceipt = {
  poolId: Buffer.from(core.decodeId32(GP)), proTxHash: Buffer.from(REAL_HASH, "hex"),
  slotIndex: 0, formatVersion: 1,
  allocationRows: goodRows, allocationHash: core.allocationHash(goodRows),
  participantCount: 3, l1Verification: "demo-unverified", verificationMethodVersion: 1,
};
const goodPool = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
  targetDuffs: Number(REGULAR) };
const bare = { contractId: GC, receipt: goodReceipt, pool: goodPool, poolId: GP };

// the pair really does pass everything else, or the assertions below prove nothing
ok("the fixture pair passes every other duty (so a refusal can only be duty 6)",
  checkReceiptAgainstPool({ ...bare, receiptOwnerId: A, poolOwnerId: A }).ok === true);
ok("a caller supplying neither owner is REFUSED (the hole that made the grep necessary)",
  checkReceiptAgainstPool(bare).ok === false);
ok("the refusal is specifically about the binding, not an unrelated duty",
  /owner binding/.test(checkReceiptAgainstPool(bare).reason || ""));
ok("a caller supplying only one owner is refused",
  checkReceiptAgainstPool({ ...bare, receiptOwnerId: A }).ok === false);
ok("MISMATCHED owners are refused before any other duty can mask it",
  /owned by/.test(checkReceiptAgainstPool({ ...bare, receiptOwnerId: A, poolOwnerId: B }).reason || ""));

// ---- 2. the DECLARATION path is explicit and self-reporting ----
const declared = checkReceiptAgainstPool({ ...bare, ownerBindingUnavailable: "stub" });
ok("a declared-unavailable caller is not refused for the binding",
  !/owner binding/.test(declared.reason || ""));
ok("a declared-unavailable result reports the binding as UNCHECKED",
  declared.ownerBindingChecked !== true);

// ---- 3. every real call site is exercised for its DECISION, not its source text ----
// Each entry drives the module and asserts the module's own conclusion changes with the
// owners it passes. A caller that stops passing owners now fails duty 6 and its verdict
// flips, which is a behavioural difference this suite sees.
const lifecycle = require("./poolLifecycle.cjs");
{
  // classifyPool passes through what it is given and declares otherwise, so a caller
  // that supplies owners gets a CHECKED binding and a mismatch changes the outcome
  const pool = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 };
  const receipt = { poolId: GP };
  const noOwners = lifecycle.classifyPool({ contractId: GC, pool, poolId: GP, receipt });
  ok("classifyPool without owners still returns a verdict (it declares the gap, never crashes)",
    typeof noOwners.state === "string");
  const mismatched = lifecycle.classifyPool({ contractId: GC, pool, poolId: GP, receipt,
    receiptOwnerId: A, poolOwnerId: B });
  ok("classifyPool with MISMATCHED owners does not report the receipt as verifying",
    mismatched.receiptOk !== true);
}

// ---- 4. THE GLOBAL INVARIANT: no affirmative verdict on an unchecked binding ----
// Request 3's criterion 6. Declaring the binding unavailable made the gap auditable but
// still let a definite lifecycle verdict be returned over it, which is the difference
// between recording a hole and closing one. A pool whose receipt was written by the
// wrong operator was reported COMPLETED, reproduced with valid fixtures below.
{
  const pool = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
    targetDuffs: Number(REGULAR) };
  const noOwners = lifecycle.classifyPool({ contractId: GC, pool, poolId: GP, receipt: goodReceipt });
  ok("classifyPool WITHOUT owners does not report a definite completed verdict",
    noOwners.state !== "completed");
  ok("...and says the binding is why", /owner binding/i.test(noOwners.reason || ""));
  ok("classifyPool WITHOUT owners reports the receipt as NOT verified",
    noOwners.receiptOk !== true);

  const supplied = lifecycle.classifyPool({ contractId: GC, pool, poolId: GP, receipt: goodReceipt,
    receiptOwnerId: A, poolOwnerId: A });
  ok("classifyPool WITH matching owners does report completed", supplied.state === "completed");
  ok("...and reports the receipt verified", supplied.receiptOk === true);

  const mismatched = lifecycle.classifyPool({ contractId: GC, pool, poolId: GP, receipt: goodReceipt,
    receiptOwnerId: A, poolOwnerId: B });
  ok("classifyPool with MISMATCHED owners does not report completed",
    mismatched.state !== "completed");
}

console.log(`ownerBindingTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
