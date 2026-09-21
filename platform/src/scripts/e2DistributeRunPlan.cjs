/**
 * THE DISTRIBUTION RUN'S LOOP DECISIONS (the F3 refactor, milestone 2), extracted from the driver
 * so an offline battery can drive them.
 *
 * WHY THEY ARE HERE RATHER THAN INLINE. Every one of these was written inside the runner, where
 * the only instrument was a source sweep. Milestone 1 established twice over what that costs: an
 * adapter written inline inside a runner is unreachable by any offline battery, and the sweep
 * standing in for one was defeated by real substitutions on the first serious try. These are the
 * decisions that say which epochs a run may work, whether the writer and the driver agree about
 * the epoch in hand, whether every positive row was answered, and what the run's exit means.
 *
 * NONE OF THEM TOUCHES THE NETWORK OR THE JOURNAL. They take what the run already resolved and
 * answer a verdict, which is what makes them testable and what keeps the runner thin.
 */
const refuse = (m) => { throw new Error(`e2DistributeRunPlan: ${m}`); };

// a classification is TERMINAL FOR AN EPOCH'S MACHINERY and is not a claim that anything was
// paid: a self-share settles without a transfer, and an entitlement below the minimum defers to
// the carry layer
const SETTLED_STATUSES = Object.freeze(["completed", "self-share-settled", "below-minimum-carried"]);

/**
 * THE UNIVERSE MUST BE EXACTLY THE RUN THE CONTEXTS WERE BUILT FOR.
 *
 * The driver used to refuse any universe but a single epoch, which was honest while it held one
 * epoch's values. What replaces that is not a relaxation. The universe the writer resolved and
 * the epochs the contexts cover must be the SAME LIST IN THE SAME ORDER, so a universe holding an
 * epoch with no context, a context for an epoch outside the universe, a reordering and an empty
 * universe all still stop the run.
 */
const universeMatchesRun = (universeNumbers, runEpochs) => {
  if (!Array.isArray(universeNumbers)) refuse("the universe is not a list of epoch numbers");
  if (!Array.isArray(runEpochs) || runEpochs.length === 0) refuse("the run covers no epochs");
  if (universeNumbers.length !== runEpochs.length) {
    return { ok: false, why: `the universe holds ${universeNumbers.length} epoch(s) [${universeNumbers.join(",")}] while the run's contexts cover ${runEpochs.length} [${runEpochs.join(",")}]` };
  }
  for (let i = 0; i < runEpochs.length; i++) {
    if (universeNumbers[i] !== runEpochs[i]) {
      return { ok: false, why: `the universe is [${universeNumbers.join(",")}] and the run's contexts are [${runEpochs.join(",")}]; they differ at position ${i}` };
    }
  }
  return { ok: true };
};

/**
 * THE WRITER PICKS THE EPOCH, SO THE DRIVER CHECKS IT.
 *
 * The header step resolves the next incomplete epoch from the universe itself and takes no epoch
 * argument. The dependency bundle it was handed was built from ONE epoch's context, carrying that
 * epoch's figures and its identifier helper. If the two disagree, the header would rest on one
 * epoch's figures under another epoch's identity, which no later check would notice because both
 * are internally consistent.
 */
const headerEpochAgrees = (headerEpochIndex, contextEpochIndex) => {
  if (!Number.isSafeInteger(contextEpochIndex) || contextEpochIndex < 0) {
    refuse(`the context's epoch ${JSON.stringify(contextEpochIndex)} is not a nonnegative integer`);
  }
  if (!Number.isSafeInteger(headerEpochIndex)) {
    return { ok: false, why: `the header step reported epoch ${JSON.stringify(headerEpochIndex)}, which is not a usable epoch number, while this iteration's context is epoch ${contextEpochIndex}` };
  }
  if (headerEpochIndex !== contextEpochIndex) {
    return { ok: false, why: `the writer worked epoch ${headerEpochIndex} while this iteration's context is epoch ${contextEpochIndex}; the header would rest on one epoch's figures under another's identity` };
  }
  return { ok: true };
};

/**
 * COVERAGE IS CHECKED PER EPOCH, against that epoch's own positive rows.
 *
 * A pooled count over the whole run would be satisfied by any mix that adds up, including one
 * epoch answered twice and another not at all, which is exactly the confusion the per-epoch
 * contexts exist to prevent. Each outcome therefore carries the epoch it belongs to, and each
 * epoch is held to its own rows.
 *
 * `positiveIdsFor(n)` answers that epoch's positive accrual identifiers. `outcomes` carry
 * `{ epochIndex, accrualId, status }`.
 */
const coveragePerEpoch = ({ runEpochs, positiveIdsFor, outcomes, settled = SETTLED_STATUSES }) => {
  if (!Array.isArray(runEpochs) || runEpochs.length === 0) refuse("coveragePerEpoch needs the run's epochs");
  if (typeof positiveIdsFor !== "function") refuse("coveragePerEpoch needs positiveIdsFor");
  if (!Array.isArray(outcomes)) refuse("coveragePerEpoch needs the outcome list");
  const settledSet = new Set(settled);
  for (const o of outcomes) {
    if (!o || !Number.isSafeInteger(o.epochIndex)) {
      refuse("an outcome carries no epoch index, so it cannot be held to any epoch's rows");
    }
    if (!runEpochs.includes(o.epochIndex)) {
      refuse(`an outcome names epoch ${o.epochIndex}, which is outside the run [${runEpochs.join(",")}]`);
    }
  }
  return runEpochs.map((n) => {
    const want = positiveIdsFor(n);
    if (!Array.isArray(want)) refuse(`positiveIdsFor(${n}) did not answer a list`);
    const mine = outcomes.filter((o) => o.epochIndex === n);
    const covered = want.length === mine.length && want.every((id) => mine.some((o) => o.accrualId === id));
    return { number: n, covered, settled: mine.every((o) => settledSet.has(o.status)), answered: mine.length, expected: want.length };
  });
};

/**
 * THE RUN'S VERDICT.
 *
 * `done` means every epoch in the run was reached, every positive row answered, and every outcome
 * terminal. A run that stopped early is not done however clean the epochs below the stop look,
 * because the epochs above it were never worked and an unworked epoch is not a settled one.
 *
 * The exit codes are the driver's existing contract, unchanged: 0 is every accrual settled with
 * no open deferral, 3 is every accrual terminal with deferrals awaiting the carry layer, and 1 is
 * anything less. THE EXIT NEVER CLAIMS GREEN OVER AN UNCONSUMED DEFERRAL.
 */
const runVerdict = ({ perEpoch, outcomes, stoppedEarly = null, settled = SETTLED_STATUSES }) => {
  if (!Array.isArray(perEpoch)) refuse("runVerdict needs the per-epoch coverage");
  if (!Array.isArray(outcomes)) refuse("runVerdict needs the outcome list");
  const settledSet = new Set(settled);
  const covered = stoppedEarly === null && perEpoch.length > 0 && perEpoch.every((c) => c.covered);
  const done = covered && outcomes.every((o) => settledSet.has(o.status));
  const carriedCount = outcomes.filter((o) => o.status === "below-minimum-carried").length;
  const exitCode = !done ? 1 : (carriedCount ? 3 : 0);
  return { covered, done, carriedCount, exitCode };
};

/**
 * WHAT THE HEADER STEP'S RESULT PERMITS.
 *
 * Three answers, because three things can happen and they are not the same. The writer reporting
 * no incomplete epoch left ends the run with nothing to do. A status short of the transfer stage
 * stops this epoch and every epoch above it. Anything else continues.
 *
 * It was an inline pair of conditions in the runner, where nothing could drive it, and the review
 * found that disabling either one went unnoticed by every battery.
 */
const HEADER_CONTINUE_STATUSES = Object.freeze(["header-done-transfers-pending", "captured"]);
const headerStepOutcome = (h) => {
  if (!h || typeof h !== "object" || typeof h.status !== "string") {
    refuse(`the header step answered ${JSON.stringify(h)}, which carries no status`);
  }
  if (h.status === "already-complete") return { action: "finish", status: h.status };
  if (!HEADER_CONTINUE_STATUSES.includes(h.status)) return { action: "stop", status: h.status };
  return { action: "continue", status: h.status };
};

/**
 * WHETHER AN EPOCH MAY BE MARKED COMPLETE, from its own coverage entry.
 *
 * The writer picks the next INCOMPLETE epoch, so this answer is what lets a run advance. It is
 * deliberately both conditions rather than either: every positive row answered AND every outcome
 * terminal. An epoch answered in full whose outcomes are not terminal has not finished, and an
 * epoch whose outcomes are all terminal but whose rows were not all answered has not either.
 */
const epochComplete = (entry) => {
  if (!entry || typeof entry !== "object") refuse("epochComplete needs a coverage entry");
  return entry.covered === true && entry.settled === true;
};

module.exports = { SETTLED_STATUSES, HEADER_CONTINUE_STATUSES, universeMatchesRun, headerEpochAgrees,
  headerStepOutcome, epochComplete, coveragePerEpoch, runVerdict };
