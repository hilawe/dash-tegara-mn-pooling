/**
 * ABSENCE AND INCOHERENCE ARE REFUSALS, AND A GUARD NEVER READS ITS DECISION OUT OF PROSE.
 *
 * This suite exists because one defect SHAPE has now been repaired at four separate sites
 * in this codebase, each time as if it were an unrelated incident:
 *
 *   1. both receipt and pool owners absent, and the shared check returned ok having
 *      verified nothing (pass 10, F5),
 *   2. a companion field recording that the owner binding had been skipped, sitting beside
 *      `ok: true` (pass 11, F1),
 *   3. `contractOwner` absent from a harness fixture, and the mock's owner-only constraint
 *      passing vacuously (pass 12, F2),
 *   4. `receiptPresent` absent from a classification, and both downstream guards ignoring a
 *      receipt that had not verified (the pre-commit check on pass 12's own repair),
 *   5. a malformed OUTER abandon-archive envelope leaving `draftState` at "unknown", which
 *      only the parse's try body ever set, so the damaged-evidence refusal never fired and
 *      recovery reported success without the exact archived-draft comparison (pass 14,
 *      F2). SITE 5'S ASSERTION LIVES IN THE HARNESS (formationCrashTest.cjs, the
 *      malformed-envelope case), not here, because the site is a command flow this
 *      offline suite cannot drive; it is listed here so the registry of the shape stays
 *      in one place.
 *
 * Every one was found by a reviewer, none by the suite, and each repair was scoped to its
 * own site. THE POINT OF THIS FILE IS THAT THE SHAPE LIVES IN ONE PLACE. A fifth site added
 * later is meant to be added here too, and the sites section below is the list to extend.
 *
 * The second half is the stronger of the two and is a PROPERTY rather than a set of
 * examples. `mayAbandon` and `admissionVerdict` once decided by searching the
 * classification's REASON TEXT for a phrase. That worked only while exactly one
 * receipt-present refusal existed, and it broke silently the moment a second was added,
 * three review passes before anyone noticed. A property test over a SWEEP of the guards' structural
 * inputs is harder to break that way: it asserts the verdict is a function of the structural
 * fields and is unchanged across three different wordings, for every combination of those
 * fields, including combinations no current code path produces. It does NOT cover the open
 * object domain, so a guard that started reading some OTHER prose field would still pass;
 * what it pins is that the three fields decide, and that the reason does not.
 *
 * Run: node src/scripts/absenceFailsClosedTest.cjs   (exits non-zero on failure)
 */
const core = require("./formationCore.cjs");
const { STATES, classifyPool, mayAbandon, admissionVerdict } = require("./poolLifecycle.cjs");
const { checkReceiptAgainstPool } = require("./receiptPoolCheck.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const withLedger = (v, fn) => {
  const prev = process.env.LEDGER;
  if (v === undefined) delete process.env.LEDGER; else process.env.LEDGER = v;
  try { return fn(); } finally {
    if (prev === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev;
  }
};

const GC = "3EbgWjxUoX6J9XbqqxrEktm7tUFBQ5fQyKaiAzXCULxf";
const GP = "47doihuxfjfeoqi4PrKLY58Z56J6BhXekMmhW3z63QT8";
const OA = "8sCudmZNvmDC9nXCGRWk1NMStKaeqCaWLa7eYTEKuT8Y";
const OB = "52D4DcjgFZU1KktALjGpcfGoxR1987BEjTXxbnNcNfAc";
const OC = "FZ9HF6oANQxZDXGXGiKh8uXdPfwcp4rwfrzqQJcdRNgv";
const REGULAR = "100000000000";

const manifest = (target = REGULAR) => {
  const t = BigInt(target);
  return { v: 1, poolId: GP, realHash: "aa".repeat(32), target,
    owners: [
      { owner: OA, amountDuffs: String(t / 2n), bps: 5000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
      { owner: OB, amountDuffs: String(t * 3n / 10n), bps: 3000, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
      { owner: OC, amountDuffs: String(t / 5n), bps: 2000, rewardScriptHex: "76a914" + "33".repeat(20) + "88ac" },
    ] };
};
const receiptFor = (m) => {
  const rows = core.allocationPreimage(GC, m);
  // poolId as BYTES, the producible form (a review: the schema types it byteArray and
  // the shape gate refuses the base58-string form)
  return { poolId: core.toId32(GP), proTxHash: Buffer.from(m.realHash, "hex"), slotIndex: 0,
    formatVersion: 1, allocationRows: rows, allocationHash: core.allocationHash(rows),
    participantCount: 3, l1Verification: "demo-unverified", verificationMethodVersion: 1 };
};
const v9Pool = () => ({ slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
  targetDuffs: 100000000000 });

// ===========================================================================
// PART 1. THE GUARD PROPERTY, swept over the structural inputs (not the open object domain).
//
// The expectation below is written from the RULE, not read off the implementation, which
// is the playbook's corollary that an expected value computed by the code under test
// proves nothing. The rule, in words:
//
//   Refuse if there is no classification at all.
//   Refuse if the classification is UNUSABLE, meaning it does not carry both structural
//     fields as booleans, or it claims a verified receipt while not being COMPLETED, which
//     the classifier never emits and which no guard should try to interpret.
//   Refuse if the pool COMPLETED (abandoning orphans real state; a completed pool is not
//     open, and no coordination makes a finished pool joinable).
//   Refuse if the classification HELD A RECEIPT that did not verify.
//   Otherwise abandonment is allowed.
//   Otherwise admission is allowed only for a v8 FORMING pool, which says so itself, or on
//     an instruction naming this exact pool.
// ===========================================================================
// AN UNRECOGNIZED STATE IS UNUSABLE TOO (pass 13, F2). The first version of this rule did
// not say so, and that omission is the round's sharpest lesson about property tests: the
// suite SWEPT an unknown-state row and passed, because this expected rule, written by the
// same author as the code under the same unexamined assumption, defaulted OPEN exactly
// where the code did. The specification was silent on unknown states and silence was read
// as permission, in a codebase whose entire doctrine is that silence is a refusal.
const KNOWN_STATES = Object.values(STATES);
const unusableExpected = (c) =>
  typeof c.receiptOk !== "boolean" ||
  typeof c.receiptPresent !== "boolean" ||
  !KNOWN_STATES.includes(c.state) ||
  (c.receiptOk === true && c.state !== STATES.COMPLETED);
const contradictsExpected = (c) => c.receiptPresent === true && c.receiptOk !== true;
const expectAbandon = (c) =>
  !unusableExpected(c) && c.state !== STATES.COMPLETED && !contradictsExpected(c);
const expectAdmit = (c, poolIdStr, participateEnv) => {
  if (unusableExpected(c)) return false;
  if (c.state === STATES.COMPLETED) return false;
  if (contradictsExpected(c)) return false;
  if (c.state === STATES.FORMING) return true;
  // the operator instruction admits ONLY the state the ledger cannot answer (FA2 fold):
  // IN_FLIGHT is an answered state (v8 flipped, or local completion evidence), so no
  // instruction admits it. The earlier rule here let the instruction admit any
  // non-refused state, which was the same permissive default the code had, written by
  // the same author under the same assumption, which is exactly the trap this suite's
  // own header warns about.
  if (c.state !== STATES.UNDETERMINED) return false;
  return Boolean(participateEnv && poolIdStr && participateEnv === poolIdStr);
};

{
  const states = [STATES.COMPLETED, STATES.FORMING, STATES.IN_FLIGHT, STATES.UNDETERMINED,
    "a-state-nobody-has-defined-yet", undefined];
  const okValues = [true, false, undefined];
  const presentValues = [true, false, undefined];
  // THE THREE WORDINGS ARE THE WHOLE POINT of this block. The first carries the phrase the
  // guards used to search for, the second is a real refusal that does not, and the third
  // has no reason at all. If any verdict differs across the three while the structural
  // fields are held fixed, a guard is reading its decision out of prose again.
  const reasons = [
    "a completion receipt exists but does NOT verify against this pool (something)",
    "the receipt's owner binding could not be checked: no owners were supplied",
    undefined,
  ];
  const instructions = [GP, "some-other-pool", undefined];

  let combos = 0, wordingSensitive = 0;
  for (const state of states) {
    for (const receiptOk of okValues) {
      for (const receiptPresent of presentValues) {
        for (const participateEnv of instructions) {
          const verdicts = reasons.map((reason) => {
            const c = { state, receiptOk, receiptPresent, ...(reason === undefined ? {} : { reason }) };
            return {
              abandon: mayAbandon(c).ok,
              admit: admissionVerdict({ classification: c, poolIdStr: GP, participateEnv }).ok,
            };
          });
          combos++;
          // (a) the wording must not move either verdict
          const sameAbandon = verdicts.every((v) => v.abandon === verdicts[0].abandon);
          const sameAdmit = verdicts.every((v) => v.admit === verdicts[0].admit);
          if (!sameAbandon || !sameAdmit) wordingSensitive++;
          // (b) and each verdict must match the rule, independently derived
          const c0 = { state, receiptOk, receiptPresent };
          if (verdicts[0].abandon !== expectAbandon(c0)) {
            fail++;
            console.error(`FAIL: abandon disagrees with the rule for ` +
              `state=${state} receiptOk=${receiptOk} receiptPresent=${receiptPresent}`);
          } else { pass++; }
          if (verdicts[0].admit !== expectAdmit(c0, GP, participateEnv)) {
            fail++;
            console.error(`FAIL: admission disagrees with the rule for ` +
              `state=${state} receiptOk=${receiptOk} receiptPresent=${receiptPresent} ` +
              `participate=${participateEnv}`);
          } else { pass++; }
        }
      }
    }
  }
  // the combination count is NOT asserted. An assertion that the loops ran the number of
  // times the loops were written to run cannot fail for any change outside this file, which
  // makes it decoration, and this round has already deleted one assertion of that shape
  // (the checker on this very suite named it, correctly).
  console.log(`  (guard property swept ${combos} structural combinations x 3 wordings)`);
  ok("NO verdict changes with the wording of the reason (the pass-12 F1 defect)",
    wordingSensitive === 0);
}

// ===========================================================================
// PART 2. THE CLASSIFICATIONS THIS SUITE DRIVES carry the structural fields, and the guards
// agree with the rule on each.
//
// STATED AT ITS REAL WIDTH: these are the return sites the drives below reach, enumerated by
// hand from the classifier as it stands. Nothing here proves the enumeration is complete, and
// a return site added later will not add its own drive. The coverage floor at the end is a
// weak proxy for that, not a guarantee.
//
// Part 1 proves the guards are correct for hand-built inputs. This proves the classifier
// actually produces inputs of that shape, which is the other half: a return site that
// forgot the flag would satisfy part 1 and still break the system.
// ===========================================================================
{
  const good = manifest();
  const seen = new Set();
  const drive = (label, ledger, args) => {
    const c = withLedger(ledger, () => classifyPool(args));
    ok(`[${label}] carries a boolean receiptPresent`, typeof c.receiptPresent === "boolean");
    ok(`[${label}] carries a boolean receiptOk`, typeof c.receiptOk === "boolean");
    ok(`[${label}] receiptPresent agrees with what was passed`,
      c.receiptPresent === Boolean(args.receipt));
    ok(`[${label}] abandon agrees with the rule`, mayAbandon(c).ok === expectAbandon(c));
    ok(`[${label}] admission agrees with the rule`,
      admissionVerdict({ classification: c, poolIdStr: GP, participateEnv: GP }).ok
        === expectAdmit(c, GP, GP));
    seen.add(`${c.state}|${c.receiptOk}|${c.receiptPresent}`);
    return c;
  };

  const FORMING_HASH = Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 7)]);
  const REAL_HASH = Buffer.alloc(32, 0xaa);
  const v8Pool = (hash) => ({ slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
    proTxHash: hash, status: core.isFormingHash(hash) ? "forming" : "live" });
  const unpared = (m) => ({ ...receiptFor(m), nodeType: "regular", operatorFeeBps: 2000,
    targetDuffs: Number(m.target) });

  // one per return site reachable at the time this was written, enumerated by hand
  drive("pool missing", "v9", { contractId: GC, pool: null, poolId: GP, receipt: receiptFor(good) });
  drive("owners absent", "v9", { contractId: GC, pool: v9Pool(), poolId: GP, receipt: receiptFor(good) });
  drive("verifies", "v9", { contractId: GC, pool: v9Pool(), poolId: GP, receipt: receiptFor(good),
    receiptOwnerId: OA, poolOwnerId: OA });
  drive("receipt fails a duty", "v9", { contractId: GC, pool: v9Pool(), poolId: GP,
    receipt: receiptFor(manifest("400000000000")), receiptOwnerId: OA, poolOwnerId: OA });
  drive("owners mismatched", "v9", { contractId: GC, pool: v9Pool(), poolId: GP,
    receipt: receiptFor(good), receiptOwnerId: OA, poolOwnerId: OB });
  drive("v9 receipt-less, no local state", "v9", { contractId: GC, pool: v9Pool(), poolId: GP, receipt: null });
  drive("v9 receipt-less, operator holds state", "v9", { contractId: GC, pool: v9Pool(), poolId: GP,
    receipt: null, operatorHasInFlight: true });
  drive("v8 no proTxHash", "v8", { contractId: GC, pool: { slotIndex: 0, nodeType: "regular",
    operatorFeeBps: 2000 }, poolId: GP, receipt: null });
  drive("v8 short proTxHash", "v8", { contractId: GC, pool: { slotIndex: 0, nodeType: "regular",
    operatorFeeBps: 2000, proTxHash: Buffer.alloc(31, 0) }, poolId: GP, receipt: null });
  drive("v8 forming", "v8", { contractId: GC, pool: v8Pool(FORMING_HASH), poolId: GP, receipt: null });
  drive("v8 flipped, no receipt", "v8", { contractId: GC, pool: v8Pool(REAL_HASH), poolId: GP, receipt: null });
  drive("v8 completed", "v8", { contractId: GC, pool: v8Pool(REAL_HASH), poolId: GP,
    receipt: unpared(good), receiptOwnerId: OA, poolOwnerId: OA });
  drive("malformed input (the catch arm)", "v9", { contractId: GC, poolId: GP,
    pool: { get slotIndex() { throw new Error("boom"); } }, receipt: receiptFor(good),
    receiptOwnerId: OA, poolOwnerId: OA });

  // a coverage floor, so this block noticing nothing is itself visible: if a refactor makes
  // several drives collapse onto one classification, the count drops and this fails
  ok(`the drives produced several distinct classifications (${seen.size})`, seen.size >= 5);
  ok("and COMPLETED is among them (or the happy path stopped being exercised)",
    [...seen].some((k) => k.startsWith(`${STATES.COMPLETED}|`)));
}

// ===========================================================================
// PART 3. THE FOUR SITES WHERE THIS SHAPE HAS ALREADY BEEN REPAIRED.
//
// EXTEND THIS LIST when a fifth appears. Each case asserts that the ABSENCE of the thing a
// check needs produces a refusal rather than a pass.
// ===========================================================================
withLedger("v9", () => {
  const base = { contractId: GC, receipt: receiptFor(manifest()), pool: v9Pool(), poolId: GP };

  // SITE 1 (pass 10, F5): both owners absent
  ok("site 1: the shared check refuses when NEITHER owner is supplied",
    checkReceiptAgainstPool(base).ok === false);
  ok("site 1: and the refusal names the binding (a message check, not proof of which duty ran)",
    /owner binding/.test(checkReceiptAgainstPool(base).reason || ""));

  // SITE 2 (pass 11, F1): no affirmative result may report a skipped check
  const affirmative = checkReceiptAgainstPool({ ...base, receiptOwnerId: OA, poolOwnerId: OA });
  ok("site 2: the affirmative result exists (or the fixture stopped proving anything)",
    affirmative.ok === true);
  ok("site 2: and it carries no top-level ownerBindingChecked field (that exact name only)",
    affirmative.ownerBindingChecked === undefined);
  ok("site 2: and the ownerBindingUnavailable name specifically buys no pass",
    checkReceiptAgainstPool({ ...base, ownerBindingUnavailable: "any reason at all" }).ok === false);

  // SITE 3 (pass 12, F2): the mock's owner-only constraint without its own input
  const mock = require("./formationMockDash.cjs");
  const poolData = { slotIndex: 1, nodeType: "regular", operatorFeeBps: 2000,
    targetDuffs: 100000000000, slotDuffs: 50000000000, slotCount: 2 };
  const refusalFor = (ledger) => {
    try { mock.assertCreateAllowed(ledger, { type: "pool", ownerId: OA, data: poolData }); return ""; }
    catch (e) { return e.message; }
  };
  ok("site 3: the mock refuses an owner-only create when contractOwner is ABSENT",
    /cannot be evaluated/.test(refusalFor({ contractId: GC, docs: [] })));
  // more than one non-identity shape, because the first version of this case tested a blank
  // string alone and the checker pointed out that null, 0, {} and [] would all have survived
  for (const [label, value] of [["a blank string", " "], ["null", null], ["zero", 0],
    ["an empty object", {}], ["an empty array", []], ["a non-base58 string", "not an identity!"]]) {
    ok(`site 3: and when contractOwner is ${label}`,
      /cannot be evaluated/.test(refusalFor({ contractId: GC, docs: [], contractOwner: value })));
  }

  // SITE 4b (this run's checker): an INCOHERENT classification is refused too. A claim of
  // `receiptOk: true` on anything but a COMPLETED classification is not something the
  // classifier emits, so a guard that acts on it is interpreting a caller's mistake.
  const incoherent = { state: STATES.UNDETERMINED, receiptOk: true, receiptPresent: true };
  ok("site 4b: abandon refuses receiptOk:true on a non-COMPLETED classification",
    mayAbandon(incoherent).ok === false);
  ok("site 4b: admission refuses it too",
    admissionVerdict({ classification: incoherent, poolIdStr: GP, participateEnv: GP }).ok === false);
  ok("site 4b: and the same shape with the flag absent is refused",
    mayAbandon({ state: STATES.UNDETERMINED, receiptOk: true }).ok === false);

  // SITE 4 (the pre-commit check on pass 12's repair): receiptPresent absent
  const legacy = { state: STATES.UNDETERMINED, receiptOk: false, reason: "a classification with no flag" };
  ok("site 4: abandon refuses a classification carrying NO receiptPresent",
    mayAbandon(legacy).ok === false);
  ok("site 4: admission refuses it too, instruction or not",
    admissionVerdict({ classification: legacy, poolIdStr: GP, participateEnv: GP }).ok === false);
  // and the licensing case, so the fix is not simply "refuse everything"
  const genuinelyNone = { state: STATES.UNDETERMINED, receiptOk: false, receiptPresent: false };
  ok("site 4: an EXPLICIT receiptPresent:false still licenses both",
    mayAbandon(genuinelyNone).ok === true
      && admissionVerdict({ classification: genuinelyNone, poolIdStr: GP, participateEnv: GP }).ok === true);
});

console.log(`absenceFailsClosedTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
