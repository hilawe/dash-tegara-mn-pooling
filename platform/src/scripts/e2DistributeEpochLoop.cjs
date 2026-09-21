/**
 * THE DEPLOYED PER-EPOCH LOOP (milestone 2's integrated unit), extracted so a battery can drive
 * the decisions the driver actually makes rather than recognizing their text.
 *
 * WHY. An independent review showed that replacing the loop's completion condition with one that
 * always continues survived both named suites: the source sweep found the helper call and never
 * bound the USE of its answer. Moving predicates into a module had not made the deployed loop
 * executable. This is that loop, with its steps and its dependency factory injected, so a case
 * can drive it and watch what it decides.
 *
 * WHAT IT OWNS. Which epoch is worked next, whether the writer's chosen epoch agrees with the
 * bundle it was handed, what a header result permits, whether an epoch may be recorded complete,
 * and where a run stops. It owns no ledger call and no journal write; those live in the injected
 * steps, which are the real ones in production.
 *
 * THE COMPLETED RECORD IS OWNED HERE and handed to the dependency factory, because the writer
 * picks the next INCOMPLETE epoch and so the answer to that question is what lets a run advance.
 * It only ever grows, and only with epochs finished with every positive row answered and terminal.
 */
const plan = require("./e2DistributeRunPlan.cjs");

const refuse = (m) => { throw new Error(`e2DistributeEpochLoop: ${m}`); };
const msgOf = (e) => (e && e.message) || String(e);

/**
 * runEpochLoop({ runEpochs, contextFor, epochDepsFor, steps, poolId, dir, run, bootstrap,
 *                classifyEntitlement, log })
 *   -> { outcomes, stoppedEarly, completedEpochs, refusal }
 *
 * `refusal` is a string when the loop stopped the whole run by name, and null otherwise. A
 * refusal is NOT a stop: a stop is an epoch that did not finish, which leaves the epochs above it
 * unworked, while a refusal is a disagreement the run cannot continue through at all.
 */
const runEpochLoop = async ({ runEpochs, contextFor, epochDepsFor, steps, poolId, dir, run,
  bootstrap, classifyEntitlement, writerHex, log }) => {
  if (!Array.isArray(runEpochs) || runEpochs.length === 0) refuse("runEpochLoop needs the run's epochs");
  if (typeof contextFor !== "function") refuse("runEpochLoop needs contextFor");
  if (typeof epochDepsFor !== "function") refuse("runEpochLoop needs epochDepsFor");
  if (typeof classifyEntitlement !== "function") refuse("runEpochLoop needs classifyEntitlement");
  if (typeof log !== "function") refuse("runEpochLoop needs an explicit log function");
  if (typeof writerHex !== "string" || !/^[0-9a-f]{64}$/.test(writerHex)) refuse("runEpochLoop needs the writer identity as 64 lowercase hex; the row classification compares against it");
  for (const k of ["runHeaderStep", "runAccrualStep", "runTransferStep"]) {
    if (!steps || typeof steps[k] !== "function") refuse(`runEpochLoop needs steps.${k}`);
  }
  const outcomes = [];
  const completedEpochs = new Set();
  let stoppedEarly = null;
  let refusal = null;
  for (const epochNumber of runEpochs) {
    const ctx = contextFor(epochNumber);
    const { deps, prefetched, contractNonce, identityNonce, clearLastReservation } = epochDepsFor(ctx, completedEpochs);
    log(`\n=== epoch ${epochNumber} of [${runEpochs.join(",")}] ===`);

  log(bootstrap
    ? "\n--- step 1: the header (fresh build for the bootstrap pool) ---"
    : "\n--- step 1: the header (resume over the canonical phase's records) ---");
  if (bootstrap) {
    // the header build consumes one identity-contract nonce; prefetch it
    // failure-tolerant like the transfer nonces (a resumed header needs
    // none, and the builder refuses loudly on a missing prefetch)
    try { prefetched.headerContractNonce = await contractNonce(); }
    catch (e) { log(`  [nonce] header contract-nonce prefetch unavailable (${msgOf(e)}); a fresh build would refuse`); }
  }
  // THE WRITER PICKS THE EPOCH, NOT THIS LOOP. runHeaderStep resolves the next incomplete epoch
  // from the universe itself and takes no epoch argument, so passing one would claim an
  // influence it does not have. What the loop owes instead is a CHECK: the epoch the writer
  // worked must be the epoch whose context built these dependencies, or the header was derived
  // from one epoch's figures and identity while the writer meant another.
  const h = await steps.runHeaderStep({ poolId: poolId, dir, deps, run });
  log(`  header: ${h.status}${h.note ? ` :: ${h.note}` : ""}`);
  const headerOutcome = plan.headerStepOutcome(h);
  if (headerOutcome.action === "finish") {
    log(`[RESULT] the writer reports no incomplete epoch left in the universe at epoch ${epochNumber}; the run has nothing further to do`);
    stoppedEarly = { epochNumber, at: "header", status: h.status }; break;
  }
  const agree = plan.headerEpochAgrees(h.epochIndex, ctx.epochIndex);
  if (!agree.ok) {
    log(`REFUSING TO CONTINUE: ${agree.why}`);
    refusal = agree.why; break;
  }
  if (headerOutcome.action === "stop") {
    log(`[RESULT] epoch ${epochNumber}'s header step did not reach the transfer stage; stopping here as the statuses direct`);
    stoppedEarly = { epochNumber, at: "header", status: h.status }; break;
  }

  log("\n--- step 2: the accrual documents ---");
  const a = await steps.runAccrualStep({ poolId: poolId, dir, deps, run, epochIndex: ctx.epochIndex });
  for (const s of a.statuses) log(`  accrual ${s.accrualId.slice(0, 12)}...: ${s.status}${s.note ? ` :: ${s.note}` : ""}`);
  if (!a.statuses.every((s) => s.status === "present" || s.status === "written")) {
    log(`[RESULT] epoch ${epochNumber}'s accrual set is incomplete; the epoch stays PREPARED and the run stops here`);
    stoppedEarly = { epochNumber, at: "accruals", status: "incomplete" }; break;
  }

  log("\n--- steps 3 and 4: reservation, transfer, capture, parts, receipt (per positive accrual) ---");
  for (const r of ctx.rows) {
    if (BigInt(r.amountCredits) <= 0n) continue;
    // the proved nonce prefetch for this accrual's synchronous builders,
    // CLASSIFICATION-AWARE AND FAILURE-TOLERANT (the wider-scope pass's
    // finding 1): an excluded row never builds, so it reads no nonce
    // (the writer's contract puts classification before any nonce
    // read), and a prefetch failure must not block the wait-only
    // recovery paths, so a failure leaves the slot null and only an
    // actual fresh build refuses on the missing nonce
    prefetched.identityNonce = null;
    prefetched.contractNonce = null;
    // THE WRITER'S OWN CLASSIFIER decides the prefetch (the closing
    // wave's second outside family, part C: a local re-derivation was a
    // drift surface), so the driver and the writer cannot disagree.
    // THE WHOLE ROW GOES IN, not a rebuilt subset. The previous version passed
    // `{recipientId, amountCredits}` and dropped `carryInCredits`, under this very
    // comment: with carry-capable rows that omission is the one case the member exists
    // for, since a self-share carrying an explicit nonzero carry-in REFUSES inside the
    // classifier and would have classified here as an ordinary self-share.
    const excludedByClassification = classifyEntitlement(r, writerHex) !== "payable";
    if (!excludedByClassification) {
      try { prefetched.identityNonce = await identityNonce(); }
      catch (e) { log(`  [nonce] identity-nonce prefetch unavailable (${msgOf(e)}); recovery proceeds, a fresh build would refuse`); }
      try { prefetched.contractNonce = await contractNonce(); }
      catch (e) { log(`  [nonce] contract-nonce prefetch unavailable (${msgOf(e)}); recovery proceeds, a fresh build would refuse`); }
    }
    clearLastReservation();
    const t = await steps.runTransferStep({ poolId: poolId, dir, deps, run, epochIndex: ctx.epochIndex, accrualId: r.accrualId });
    // the outcome carries the epoch it belongs to, so the coverage check below can hold each
    // epoch to its OWN positive rows rather than to a pooled total that any mix would satisfy
    outcomes.push({ ...t, epochIndex: ctx.epochIndex });
    log(`  accrual ${r.accrualId.slice(0, 12)}...: ${t.status}${t.note ? ` :: ${t.note}` : ""}`);
    if (t.statuses) for (const s of t.statuses) log(`    ${s.part !== undefined ? `part ${s.part}` : "receipt"}: ${s.status}`);
  }
  // THIS EPOCH'S OWN VERDICT, computed from its own rows and its own outcomes, before the run
  // moves on. It is what lets the writer pick the NEXT epoch, so it is deliberately the same
  // per-epoch coverage rule the run's final verdict uses rather than a second one written here.
  const [mine] = plan.coveragePerEpoch({
    runEpochs: [ctx.epochIndex],
    positiveIdsFor: () => ctx.rows.filter((r) => BigInt(r.amountCredits) > 0n).map((r) => r.accrualId),
    outcomes: outcomes.filter((o) => o.epochIndex === ctx.epochIndex),
  });
  if (plan.epochComplete(mine)) {
    completedEpochs.add(ctx.epochIndex);
    log(`  epoch ${ctx.epochIndex} is complete for this run (${mine.answered} of ${mine.expected} positive accrual(s), all terminal)`);
  } else {
    log(`[RESULT] epoch ${ctx.epochIndex} did not complete (${mine.answered} of ${mine.expected} positive accrual(s) answered, ${mine.settled ? "all terminal" : "not all terminal"}); the epochs above it are not worked`);
    stoppedEarly = { epochNumber: ctx.epochIndex, at: "transfers", status: "incomplete" }; break;
  }
  } // end of the run's epoch loop
  return { outcomes, stoppedEarly, completedEpochs, refusal };
};

module.exports = { runEpochLoop };
