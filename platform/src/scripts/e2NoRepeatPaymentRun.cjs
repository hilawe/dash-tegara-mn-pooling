/**
 * THE RUNNABLE DEMONSTRATION. Drives `e2NoRepeatPaymentDemo.cjs` through three interruption
 * points, each in a real child process that ends abruptly, and reads what was paid from the
 * EXTERNAL EFFECT LEDGER, which is the harness's own record of what left the machine.
 *
 * Run it directly:  node src/scripts/e2NoRepeatPaymentRun.cjs
 *
 * WHAT WIDENED (2026-09-21). The pool is resolved by the REAL `e2PoolResolution`, so it pays TWO
 * members with amounts the carry-capable calculation produced, and the interruption lands on the
 * SECOND member's payment. The demonstration then asks two questions the single-accrual version
 * could not: was the interrupted member paid twice, and was the member who was ALREADY PAID left
 * alone by the resume.
 *
 * THE EXPECTATION IS BUILT HERE, from the resolution's own rows, and never read back from the
 * ledger it judges. Three review occasions in this project were spent on expectations derived
 * from the artifact under test, so the owed amount per member is taken from the resolution once,
 * before any phase runs, and every assertion compares against that.
 *
 * IT REPORTS WHAT IT DID, not only a verdict: every phase prints the child's exit, whether the
 * locks were still held, and what each member was paid.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-norepeat-"));
process.env.E2_DEMO_ROOT = ROOT;
process.env.TEGARA_ENV_PATH = path.join(ROOT, "env.local");

const D = require("./e2NoRepeatPaymentDemo.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; console.error(`  FAIL  ${name}`); } };

const lockDirs = () => [
  path.join(D.STATE_DIR, `oplock-${D.identityLockName(D.W)}`),
  path.join(D.STATE_DIR, `oplock-${D.identityLockName(D.I)}`),
  path.join(D.STATE_DIR, `oplock-${D.poolRunLockName(D.POOL)}`),
];
const heldLocks = () => lockDirs().filter((p) => fs.existsSync(p));
/** THE OPERATOR STEP, labelled as one. This store never reclaims a stale-looking lock by itself
 *  (two waiters each judging a lock stale could divert it twice), so after an abrupt end the
 *  locks stay held and a resume refuses until a person clears them. The demonstration does that
 *  here, in the open, rather than letting the reader believe the resume is automatic. */
const operatorClearsStaleLocks = () => {
  const held = heldLocks();
  for (const p of held) fs.rmSync(p, { recursive: true, force: true });
  return held.length;
};

const child = (interruptAt, targetAccrual) => {
  const r = spawnSync(process.execPath, [path.join(__dirname, "e2NoRepeatPaymentDemo.cjs")], {
    env: { ...process.env, E2_DEMO_ROLE: "child", E2_DEMO_ROOT: ROOT,
      TEGARA_ENV_PATH: path.join(ROOT, "env.local"),
      E2_DEMO_INTERRUPT: interruptAt || "",
      E2_DEMO_INTERRUPT_ACCRUAL: targetAccrual || "" },
    encoding: "utf8", timeout: 120000 });
  return { status: r.status, out: (r.stdout || "").trim(), err: (r.stderr || "").trim() };
};

// WHAT WAS PAID, BY ACCRUAL, decoded from the bytes that left rather than read from a label. A
// review re-sent the same transfer as uppercase hex and as a Buffer and a label-based count
// missed both, so the harness decodes its own encoding and the count keys on the decoded accrual.
const paymentsFor = (accrualId) => D.externalEffects()
  .filter((e) => e.what === "credit-transfer" && e.accrualId === accrualId);
const allPayments = () => D.externalEffects().filter((e) => e.what === "credit-transfer");
// nothing may leave that this harness did not build: a send is either a decoded transfer or one
// of the other transitions the demo constructs, and anything else is unaccounted for.
const unrecognizedSends = () => D.externalEffects()
  .filter((e) => e.what !== "credit-transfer" && e.what !== "other-transition");

const main = async () => {
  console.log("=== EVERY MEMBER IS PAID WHAT THEY ARE OWED, EXACTLY ONCE, ACROSS AN INTERRUPTION ===");
  console.log(`state root: ${ROOT}`);
  console.log(`external effect ledger: ${D.LEDGER}  (the harness's record of what left the machine)\n`);

  // ---- THE OWED AMOUNTS, taken from the resolution ONCE, before any phase runs ----
  const resolution = await D.resolvePoolForDemo();
  const OWED = resolution.entitlementsForEpoch(D.EPOCH,
    { grossCredits: D.GROSS, feeCredits: D.FEE, memberCount: D.MEMBERS });
  console.log("the pool resolves to these obligations, from the real carry-capable calculation:");
  for (const r of OWED) {
    console.log(`  member ${r.recipientId.slice(0, 8)}...  owed ${r.amountCredits} credits  (accrual ${r.accrualId.slice(0, 8)}...)`);
  }
  ok("the resolved pool owes TWO members, so a single-accrual claim is no longer what is tested",
    OWED.length === 2);
  ok("the two obligations differ, so paying one twice cannot be mistaken for paying both once",
    OWED[0].amountCredits !== OWED[1].amountCredits);
  ok("both obligations are payable rather than carried, so both reach the transfer machinery",
    OWED.every((r) => D.classifyEntitlement(r, D.I) === "payable"));
  ok("the obligations sum to the distributable amount the figures imply",
    OWED.reduce((s, r) => s + BigInt(r.amountCredits), 0n) === BigInt(D.GROSS) - BigInt(D.FEE));
  const FIRST = OWED[0];
  const SECOND = OWED[1]; // the interruption lands on this one
  console.log();

  const freshEpochReadyToPay = async () => {
    operatorClearsStaleLocks();
    fs.rmSync(D.LEDGER, { force: true });
    fs.rmSync(D.STATE_DIR, { recursive: true, force: true });
    fs.rmSync(path.join(ROOT, "env.local"), { force: true });
    D.ensureStore();
    D.setStart(D.POOL, String(D.EPOCH), { dir: undefined });
    const res = await D.resolvePoolForDemo();
    const deps = D.mkDeps(D.POOL, "", res);
    const run = await D.startRun({ poolId: D.POOL, dir: undefined, deps });
    const h = await D.runHeaderStep({ poolId: D.POOL, dir: undefined, deps, run });
    if (h.status !== "captured") throw new Error(`setup expected a captured header, got ${h.status}`);
    const a = await D.runAccrualStep({ poolId: D.POOL, dir: undefined, deps, run, epochIndex: D.EPOCH });
    if (!a.statuses.every((s) => s.status === "written" || s.status === "present")) {
      throw new Error("setup could not write the accrual documents");
    }
  };

  const PHASES = [
    { at: "after-marker-before-send",
      what: "the sent-marker is committed and the process ends BEFORE the second member's payment leaves",
      secondAfterInterrupt: 0, secondFinal: 0, settles: false, exercisesSendGuard: true },
    { at: "after-send-before-capture",
      what: "the second member's payment LEAVES and the process ends BEFORE its record is committed",
      secondAfterInterrupt: 1, secondFinal: 1, settles: true, exercisesSendGuard: true },
    { at: "after-capture-before-documents",
      what: "the receipt capture is journaled and the process ends BEFORE the documents are written",
      secondAfterInterrupt: 1, secondFinal: 1, settles: true,
      // WIDTH, measured by canary: this phase resumes through the document-completion branch and
      // never reaches the send, so it binds completion rather than the no-resend guard.
      exercisesSendGuard: false },
  ];

  let resumed = 0;
  for (const p of PHASES) {
    console.log(`\n--- phase: ${p.at} ---`);
    console.log(`    ${p.what}`);
    await freshEpochReadyToPay();

    const c1 = child(p.at, SECOND.accrualId);
    console.log(`    child exit=${c1.status}  ${c1.out.split("\n").filter(Boolean).join(" | ") || "(ended inside the step)"}`);
    console.log(`    after the interruption: first member ${paymentsFor(FIRST.accrualId).length}, second member ${paymentsFor(SECOND.accrualId).length}`);
    ok(`${p.at}: the FIRST member was paid once before the interruption reached the second`,
      paymentsFor(FIRST.accrualId).length === 1);
    ok(`${p.at}: the interruption left ${p.secondAfterInterrupt} payment(s) for the second member`,
      paymentsFor(SECOND.accrualId).length === p.secondAfterInterrupt);
    ok(`${p.at}: the child really ended abruptly rather than completing`,
      c1.status !== 0 && !/CHILD-DONE/.test(c1.out));

    const held = heldLocks().length;
    console.log(`    locks still held after the abrupt end: ${held} of ${lockDirs().length}`);
    ok(`${p.at}: the abrupt end left its locks held, so a resume cannot start silently`, held > 0);
    console.log(`    OPERATOR STEP: cleared ${operatorClearsStaleLocks()} stale lock(s) so the resume may proceed`);

    // ---- the resume, a FRESH process over the same journal ----
    const c2 = child("", "");
    console.log(`    resume exit=${c2.status}  ${c2.out.split("\n").filter(Boolean).join(" | ") || c2.err.split("\n").slice(-1)[0]}`);
    const firstNow = paymentsFor(FIRST.accrualId);
    const secondNow = paymentsFor(SECOND.accrualId);
    console.log(`    after the resume: first member ${firstNow.length}, second member ${secondNow.length}`);

    // THE MEMBER WHO WAS ALREADY PAID IS LEFT ALONE. This is the question a single-accrual
    // demonstration could not ask at all.
    //
    // WHAT STANDS HERE, measured by canary rather than asserted. TWO independent guards keep a
    // completed accrual away from the send: the short-circuit on a journaled receipt capture, and
    // the no-resend rule on a committed sent-marker. Removing EITHER one alone leaves the other
    // catching it, and only removing BOTH re-pays this member, which the canary showed by doing
    // it. So this assertion observes the pair failing together, and does not by itself establish
    // that either guard is individually load-bearing here.
    ok(`${p.at}: THE ALREADY-PAID FIRST MEMBER IS NOT PAID AGAIN BY THE RESUME (${firstNow.length} payment)`,
      firstNow.length === 1);
    ok(`${p.at}: THE INTERRUPTED SECOND MEMBER IS NOT PAID TWICE (${secondNow.length}, expected ${p.secondFinal})`,
      secondNow.length === p.secondFinal);
    // and every payment is for exactly what the resolution said that member was owed
    ok(`${p.at}: every payment made is for exactly the amount the resolution owed that member`,
      allPayments().length > 0 && allPayments().every((e) => {
        const owed = OWED.find((r) => r.accrualId === e.accrualId);
        return owed && e.amountCredits === owed.amountCredits;
      }));
    ok(`${p.at}: nothing left the machine that this harness did not build`,
      unrecognizedSends().length === 0);
    if (p.settles) {
      ok(`${p.at}: the resume COMPLETED rather than merely reaching some status`,
        /CHILD-DONE/.test(c2.out) && /completed/.test(c2.out));
    } else {
      ok(`${p.at}: the unsent transfer is NOT invented by the resume, and that member stays unpaid`,
        secondNow.length === 0);
    }
    resumed++;
    operatorClearsStaleLocks();
  }

  const guarded = PHASES.filter((p) => p.exercisesSendGuard).map((p) => p.at);
  console.log(`\n=== ${passed} passed, ${failed} failed over ${PHASES.length} interruption points, ${resumed} resumed ===`);
  console.log("WIDTH: the transport is the harness's, not a network, so this establishes the");
  console.log("WRITER's behaviour across an interruption and not the network's deduplication.");
  console.log("      the pool resolution is the REAL module over fake transport; the amounts are its own.");
  console.log(`      ${guarded.length} of ${PHASES.length} phases exercise the NO-RESEND guard (${guarded.join(", ")}).`);
  console.log("      after-capture-before-documents resumes through the document-completion branch");
  console.log("      and never reaches the send, which a canary confirmed; it binds completion, not the guard.");
  console.log("      ONE epoch only. Nothing here covers a run spanning more than one.");
  process.exitCode = failed ? 1 : 0;
};

main().catch((e) => { console.error("DEMONSTRATION FAILED:", (e && e.stack) || e); process.exitCode = 1; });
