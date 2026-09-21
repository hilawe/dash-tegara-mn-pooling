// The distribution run's loop decisions, driven offline (milestone 2).
//
// THE POOLED-COUNT CASE IS THE ONE THAT MATTERS. A coverage rule that counts outcomes across the
// whole run is satisfied by one epoch answered twice and another not at all, and that mix is the
// exact confusion the per-epoch contexts exist to prevent. It is a POSITIVE control here: a
// correct two-epoch run must pass, and the pooled rule must fail on the mix.
const { SETTLED_STATUSES, HEADER_CONTINUE_STATUSES, universeMatchesRun, headerEpochAgrees,
  headerStepOutcome, epochComplete, coveragePerEpoch, runVerdict } =
  require("./e2DistributeRunPlan.cjs");
const { runnerSource, skipNote } = require("./runnerSource.cjs");
let passed = 0, failed = 0, skipped = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error("FAIL:", name, "(no error)"); }
  catch (e) { ok(name, re.test(String(e.message))); }
};

// ---- the universe match ----
ok("a universe equal to the run passes", universeMatchesRun([0, 1], [0, 1]).ok === true);
ok("a one-epoch run still passes, which is what this driver did before", universeMatchesRun([4], [4]).ok === true);
ok("a universe with one epoch too many is refused",
  universeMatchesRun([0, 1, 2], [0, 1]).ok === false);
ok("a universe with one epoch too few is refused",
  universeMatchesRun([0], [0, 1]).ok === false);
ok("an EMPTY universe is refused, which the old single-epoch rule also caught",
  universeMatchesRun([], [0]).ok === false);
ok("a universe holding the right count but the WRONG epochs is refused",
  universeMatchesRun([0, 2], [0, 1]).ok === false);
ok("a REORDERED universe is refused, because the carry threads in order",
  universeMatchesRun([1, 0], [0, 1]).ok === false);
ok("the refusal names both lists so the disagreement is readable",
  /\[0,2\]/.test(universeMatchesRun([0, 2], [0, 1]).why) && /\[0,1\]/.test(universeMatchesRun([0, 2], [0, 1]).why));
throws("a non-list universe refuses", () => universeMatchesRun(null, [0]), /not a list/);
throws("a run covering no epochs refuses", () => universeMatchesRun([0], []), /covers no epochs/);

// ---- the header epoch agreement ----
ok("the writer working this context's epoch agrees", headerEpochAgrees(1, 1).ok === true);
ok("epoch zero agrees, so a falsy read cannot pass for absent", headerEpochAgrees(0, 0).ok === true);
ok("the writer working a DIFFERENT epoch disagrees", headerEpochAgrees(0, 1).ok === false);
ok("the disagreement says what would have gone wrong",
  /one epoch's figures under another's identity/.test(headerEpochAgrees(0, 1).why));
ok("no reported epoch disagrees rather than passing", headerEpochAgrees(null, 1).ok === false
  && headerEpochAgrees(undefined, 1).ok === false);
ok("a non-integer reported epoch disagrees", headerEpochAgrees("1", 1).ok === false);
ok("and the refusal does not CLAIM the writer worked a non-epoch, which strict inequality alone would",
  [null, undefined, "1", 1.5, NaN].every((v) => {
    const why = headerEpochAgrees(v, 1).why;
    return /not a usable epoch number/.test(why) && !/the writer worked epoch/.test(why);
  }));
throws("a malformed context epoch refuses", () => headerEpochAgrees(1, -1), /not a nonnegative integer/);

// ---- coverage, per epoch ----
const ids = { 0: ["a0", "b0"], 1: ["a1", "b1"] };
const positiveIdsFor = (n) => ids[n];
const done = (epochIndex, accrualId) => ({ epochIndex, accrualId, status: "completed" });
{
  const cov = coveragePerEpoch({ runEpochs: [0, 1], positiveIdsFor,
    outcomes: [done(0, "a0"), done(0, "b0"), done(1, "a1"), done(1, "b1")] });
  ok("a correct two-epoch run is covered and settled everywhere",
    cov.length === 2 && cov.every((c) => c.covered && c.settled));
}
{
  // THE POOLED-COUNT CASE. Four outcomes for four expected rows, so any rule counting the run as
  // a whole reads this as complete. Epoch 0 was answered twice and epoch 1 not at all.
  const cov = coveragePerEpoch({ runEpochs: [0, 1], positiveIdsFor,
    outcomes: [done(0, "a0"), done(0, "b0"), done(0, "a0"), done(0, "b0")] });
  ok("one epoch answered twice and another not at all is NOT covered",
    cov[0].covered === false && cov[1].covered === false);
  ok("the totals agree with the pooled count, which is why the pooled rule would have passed",
    cov.reduce((t, c) => t + c.answered, 0) === 4 && cov.reduce((t, c) => t + c.expected, 0) === 4);
}
{
  // EQUAL COUNTS, WRONG IDENTIFIERS. Two outcomes for two expected rows, so a rule comparing
  // counts alone reads this as covered, while one row was answered twice and the other never.
  // The review found the identifier comparison unbound by the cases that only vary counts.
  const cov = coveragePerEpoch({ runEpochs: [0], positiveIdsFor,
    outcomes: [done(0, "a0"), done(0, "a0")] });
  ok("the right COUNT of outcomes under the wrong identifiers is not covered",
    cov[0].covered === false && cov[0].answered === 2 && cov[0].expected === 2);
}
{
  const cov = coveragePerEpoch({ runEpochs: [0], positiveIdsFor,
    outcomes: [done(0, "a0"), done(0, "zz")] });
  ok("an outcome naming an accrual the epoch never owed is not covered", cov[0].covered === false);
}
{
  const cov = coveragePerEpoch({ runEpochs: [0, 1], positiveIdsFor,
    outcomes: [done(0, "a0"), done(0, "b0"), done(1, "a1")] });
  ok("an epoch missing one row is not covered, and the other still is",
    cov[0].covered === true && cov[1].covered === false);
}
{
  const cov = coveragePerEpoch({ runEpochs: [0], positiveIdsFor: () => [],
    outcomes: [] });
  ok("an epoch owing nobody is covered by an empty answer", cov[0].covered === true && cov[0].settled === true);
}
{
  const cov = coveragePerEpoch({ runEpochs: [0], positiveIdsFor: () => ["a0"],
    outcomes: [{ epochIndex: 0, accrualId: "a0", status: "refused" }] });
  ok("a covered epoch whose outcome is not terminal is covered but not settled",
    cov[0].covered === true && cov[0].settled === false);
}
ok("every settled status is accepted", SETTLED_STATUSES.every((status) =>
  coveragePerEpoch({ runEpochs: [0], positiveIdsFor: () => ["a0"],
    outcomes: [{ epochIndex: 0, accrualId: "a0", status }] })[0].settled === true));
throws("an outcome with no epoch index refuses rather than being pooled",
  () => coveragePerEpoch({ runEpochs: [0], positiveIdsFor, outcomes: [{ accrualId: "a0", status: "completed" }] }),
  /carries no epoch index/);
throws("an outcome naming an epoch outside the run refuses",
  () => coveragePerEpoch({ runEpochs: [0], positiveIdsFor, outcomes: [done(9, "x")] }),
  /outside the run/);

// ---- the run's verdict ----
const cov2 = [{ number: 0, covered: true, settled: true }, { number: 1, covered: true, settled: true }];
{
  const v = runVerdict({ perEpoch: cov2, outcomes: [done(0, "a0"), done(1, "a1")] });
  ok("a complete run exits zero", v.done === true && v.exitCode === 0 && v.carriedCount === 0);
}
{
  const v = runVerdict({ perEpoch: cov2,
    outcomes: [done(0, "a0"), { epochIndex: 1, accrualId: "a1", status: "below-minimum-carried" }] });
  ok("a run with an open deferral is terminal but exits three, never zero",
    v.done === true && v.carriedCount === 1 && v.exitCode === 3);
}
{
  const v = runVerdict({ perEpoch: [{ number: 0, covered: true, settled: true }, { number: 1, covered: false, settled: true }],
    outcomes: [done(0, "a0")] });
  ok("an uncovered epoch exits one", v.done === false && v.exitCode === 1);
}
{
  // A RUN THAT STOPPED EARLY IS NOT DONE, however clean the epochs below the stop look. The
  // epochs above were never worked, and an unworked epoch is not a settled one.
  const v = runVerdict({ perEpoch: cov2, outcomes: [done(0, "a0"), done(1, "a1")],
    stoppedEarly: { epochNumber: 1, at: "header", status: "stopped" } });
  ok("a run that stopped early exits one even with every recorded outcome terminal",
    v.covered === false && v.done === false && v.exitCode === 1);
}
{
  const v = runVerdict({ perEpoch: [], outcomes: [] });
  ok("a run covering no epochs is not done", v.done === false && v.exitCode === 1);
}
{
  const v = runVerdict({ perEpoch: cov2, outcomes: [done(0, "a0"), { epochIndex: 1, accrualId: "a1", status: "refused" }] });
  ok("a non-terminal outcome exits one even where coverage holds", v.done === false && v.exitCode === 1);
}

// ---- what the header step's result permits ----
ok("a header that reached the transfer stage continues",
  headerStepOutcome({ status: "header-done-transfers-pending" }).action === "continue"
    && headerStepOutcome({ status: "captured" }).action === "continue");
ok("no incomplete epoch left FINISHES the run rather than stopping it as a failure",
  headerStepOutcome({ status: "already-complete", epochIndex: null }).action === "finish");
ok("a stopped header stops the run", headerStepOutcome({ status: "stopped" }).action === "stop");
ok("an unrecognized status stops rather than continuing, which is the fail-closed direction",
  headerStepOutcome({ status: "something-new" }).action === "stop");
ok("every continuing status is one the driver used to name inline",
  JSON.stringify(HEADER_CONTINUE_STATUSES) === JSON.stringify(["header-done-transfers-pending", "captured"]));
throws("a header result with no status refuses", () => headerStepOutcome({}), /carries no status/);
throws("a missing header result refuses", () => headerStepOutcome(null), /carries no status/);

// ---- whether an epoch may be marked complete ----
ok("an epoch covered and settled may be marked complete",
  epochComplete({ covered: true, settled: true }) === true);
ok("covered but not settled may NOT, so the writer is told there is more to do",
  epochComplete({ covered: true, settled: false }) === false);
ok("settled but not covered may NOT either",
  epochComplete({ covered: false, settled: true }) === false);
throws("a missing entry refuses", () => epochComplete(null), /needs a coverage entry/);

// ---- THE RUNNER BINDING SWEEP ----
// These decisions used to live inside the runner, where a source sweep was the only instrument.
// They are driven above; the sweep now only has to bind the runner to them.
{
  const fs = require("fs");
  const path = require("path");
  const src = runnerSource("e2DistributeRun.mjs");
  if (src === null) { skipped += 1; console.log(skipNote("e2DistributeRun.mjs", "the runner-binding sweep")); } else {
  ok("the runner takes its loop decisions from the shared module",
    /require\("\/app\/src\/scripts\/e2DistributeRunPlan\.cjs"\)/.test(src));
  // THE LOOP'S OWN DECISIONS MOVED WITH IT into e2DistributeEpochLoop.cjs, where its battery
  // drives them rather than recognizing their text. What stays the runner's is the run-level
  // universe match and the final verdict.
  for (const [name, re] of [
    ["the universe match", /runPlan\.universeMatchesRun\(/],
    ["the per-epoch coverage", /runPlan\.coveragePerEpoch\(/],
    ["the run verdict", /runPlan\.runVerdict\(/],
  ]) ok(`the runner calls ${name}`, re.test(src));
  const loopSrc = fs.readFileSync(path.join(__dirname, "e2DistributeEpochLoop.cjs"), "utf8");
  for (const [name, re] of [
    ["the header-epoch agreement", /plan\.headerEpochAgrees\(/],
    ["the header-result decision", /plan\.headerStepOutcome\(/],
    ["the completion predicate", /plan\.epochComplete\(/],
    ["the per-epoch coverage", /plan\.coveragePerEpoch\(/],
  ]) ok(`the loop calls ${name}`, re.test(loopSrc));
  ok("the runner keeps no inline single-epoch universe rule",
    !/run\.universe\.length !== 1/.test(src));
  ok("the runner no longer holds one row set for the whole run",
    !/const rows = rowsForEpoch\(/.test(src));
  ok("neither the runner nor the loop keeps an inline header-status list",
    !/h\.status !== "header-done-transfers-pending"/.test(src)
      && !/h\.status !== "header-done-transfers-pending"/.test(loopSrc));
  ok("the runner checks the declaration's shape before it reads anything",
    /declaredShape\(DECLARED_RAW, FIRST_EPOCH\)/.test(src)
      && src.indexOf("declaredShape(DECLARED_RAW") < src.indexOf("getIdentityBalance"));
  ok("the runner states what per-epoch bundles establish at its real width, not as exclusivity",
    /It is NOT that a bundle is sealed off from the run/.test(src));
  }
}

console.log(`e2DistributeRunPlanTest: ${passed} passed, ${failed} failed` + (skipped ? `, ${skipped} skipped (counted, never folded into passes)` : ""));
process.exitCode = failed ? 1 : 0;
