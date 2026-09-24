/**
 * The E2 DISTRIBUTION PROCEDURE, steps 1 through 4: the start-epoch
 * configuration mode, the run start (discovery, the lag measurement, the
 * a soundness-review finding binding), STEP 1, the header flow (admission under both identity
 * locks, the write-ahead, the committed sent-marker before any broadcast,
 * the outcome classification, the capture, and the recovery rules), STEP 2,
 * the accrual documents through the document-write rule, and STEPS 3 AND 4,
 * the per-accrual preflight-bounded claim-then-send sequence (the a soundness-review finding
 * reservation, the transfer under the explicit lock handoff, the capture,
 * then parts first and the receipt last) with the wait-only recovery and
 * observation rules. (This header once said the second half was not in this
 * file yet; that sentence outlived the second half's landing by three
 * commits and misled a scoping pass, corrected 2026-08-27.)
 *
 * WHAT IT ESTABLISHES: every durable effect is SEMANTICALLY VALIDATED by
 * the D7 machine BEFORE its bytes commit (appendChecked runs the validator
 * over the would-be journal, so an invalid record refuses instead of
 * poisoning the store) and goes through the D7 append transaction; no
 * broadcast happens before its committed sent-marker; no header is built
 * without the D10 admission passing under exactly the header's lock set;
 * the configured start binds at the pool's first durable record and every
 * later run refuses a disagreeing configuration; and a persisted
 * transition is NEVER rebuilt or re-signed, recovery resends or waits on
 * the exact journaled bytes.
 *
 * WHAT IT DOES NOT ESTABLISH, stated: the network surface is INJECTED
 * (deps), so the bindings the spec pins there, the named creditTransfer
 * callable, the pinned signer, the proved query routes, and C1's verified
 * income inputs, are the deps implementations' obligations, exercised at
 * acceptance stage in the container, not by the offline battery; the
 * battery proves SEQUENCING, DURABILITY ORDERING, REFUSALS and RECOVERY
 * against the real journal, store and admission. The live deps composition
 * (the harness runner) is the acceptance-stage unit that discharges those
 * injected obligations.
 *
 * OPERATOR CONDITIONS (patience expiry, stops, rebuild decisions) are
 * journaled by the OPERATOR through the D7 record kinds; this module
 * returns statuses naming the condition that has become available and
 * never appends a surfacing or decision itself; it DOES append the
 * evidence records the machinery defines (the measurement, write-aheads,
 * markers, error records, captures, and the foreign-document observation
 * that establishes the duplicate path's conditions). The exception class
 * the spec assigns to the run, the preflight declarations
 * (transfer-unencodable, and a soundness-review finding/a soundness-review finding classification pair
 * self-share-settled and transfer-below-minimum), belongs to the
 * transfer steps in the second half.
 *
 * ONE DECLARED ORDER DIVERGENCE, marked in the spec: step 1's prose
 * builds the transition and then obtains the pinned balances, while this
 * module completes the D10 admission (thresholds AND balances) before
 * construction, so a refused admission consumes no identity-contract
 * nonce; the write-ahead still happens only with every threshold met
 * under the same held locks, and balance staleness is bounded by the
 * frontier floor either way.
 */
const envStore = require("./envStore.cjs");
const { validateJournal, openValidatedJournal, K, PROVED_HEADER_ROUTE,
  MIN_TRANSFER_AMOUNT_CREDITS } = require("./e2Journal.cjs");
const { openJournal, appendRecord } = require("./e2JournalStore.cjs");
const { discoverFinalizedEpochs } = require("./e2Discovery.cjs");
const { classifyOutcome, TOKENS } = require("./e2Outcome.cjs");
const { admitHeader, acquireIdentityLocks, advanceFrontierFromCapture } = require("./e2BalanceCheck.cjs");
const { HEADER_KIND, RECEIPT_KIND } = require("./e2CaptureRecord.cjs");

const HEX64 = /^[0-9a-f]{64}$/;
const DEC_U32 = /^(0|[1-9][0-9]*)$/;
const U32_MAX = 4294967295;

// the pinned minimum transfer amount lives in e2Journal.cjs (the
// record-format validator enforces the below-minimum declaration payload
// against it); the classification preflight here checks self-share FIRST
// because the pinned validation refuses sender-equals-recipient before
// the amount

const refuse = (why) => { throw new Error(`e2Distribute: ${why}; refusing`); };

const poolRunLockName = (poolId) => `e2-pool-${poolId}`;
const startKeyOf = (poolId) => `E2_START_EPOCH_${poolId.toUpperCase()}`;

const requirePool = (poolId) => {
  if (typeof poolId !== "string" || !HEX64.test(poolId)) refuse("poolId must be 64 lowercase hex characters");
  return poolId;
};

/**
 * EVERY ROW SET IS VALIDATED AT EVERY CONSUMPTION SITE, against the
 * closed row grammar: recipientId is 64
 * lowercase hex (the identity comparisons' input), accrualId is 32
 * bytes lowercase hex and UNIQUE per set (a duplicate would misbind the
 * per-accrual journal key and the exclusivity tuple), amountCredits is
 * a canonical decimal string (so a malformed amount refuses through
 * this named path, never a raw construction error), and ONE ROW PER
 * MEMBER PER EPOCH holds (the allocation preconditions' owner
 * uniqueness restated here, because the carry rule's per-row minimum
 * comparison is wrong when two rows share an owner). ALL FOUR row
 * consumers call this on the rows they fetch (startRun, runHeaderStep,
 * runAccrualStep and runTransferStep), so a calculation swapped
 * between steps cannot smuggle a malformed set past an earlier check.
 * The accrual site was the gap the closing wave's second outside
 * family found in part D, where the step between header and transfer
 * wrote durable documents from an unvalidated set. The income identity
 * is a REQUIRED argument, so a self-share row carrying an explicit
 * nonzero carryInCredits refuses at every consumption site, not only
 * where classification runs, and no caller can skip the duty by
 * omission (the same wave's part D minor, hardened by the fold
 * screen).
 */
// the carry member's grammar and bounds, one predicate for every
// surface that reads it (validateEntitlementRows and the exported
// classifier), so no caller can reach a raw BigInt construction error
// or a silently accepted malformed member
const validateCarryMember = (row) => {
  if (row.carryInCredits === undefined) return;
  if (typeof row.carryInCredits !== "string" || !DEC_U32.test(row.carryInCredits)) {
    refuse("an entitlement row's carryInCredits must be a canonical decimal string when present");
  }
  if (BigInt(row.carryInCredits) >= MIN_TRANSFER_AMOUNT_CREDITS) {
    refuse("an entitlement row's carryInCredits must be below the pinned minimum (a carried amount never reaches it)");
  }
  if (BigInt(row.carryInCredits) > BigInt(row.amountCredits)) {
    refuse("an entitlement row's carryInCredits cannot exceed its effective amountCredits");
  }
};

const validateEntitlementRows = (rows, incomeIdentity) => {
  // the income identity is REQUIRED, not optional. The fold screen
  // caught that an omissible duty is the unchecked-never-means-passed
  // shape, and a caller that cannot name the income identity cannot
  // enforce the never-receives-carry rule it owes
  if (!HEX64.test(incomeIdentity || "")) {
    refuse("validateEntitlementRows requires the caller's income identity (64 lowercase hex)");
  }
  const seenRecipients = new Set();
  const seenAccruals = new Set();
  for (const row of rows) {
    if (!HEX64.test(row.accrualId || "")) {
      refuse("an entitlement row's accrualId must be 32 bytes lowercase hex");
    }
    if (seenAccruals.has(row.accrualId)) {
      refuse(`two entitlement rows share one accrualId (${row.accrualId.slice(0, 8)}...); the row set's accrual identity is not unique`);
    }
    seenAccruals.add(row.accrualId);
    if (typeof row.amountCredits !== "string" || !DEC_U32.test(row.amountCredits)) {
      refuse("an entitlement row's amountCredits must be a canonical decimal string");
    }
    // the OPTIONAL carry-in member (the decided two-value migration
    // rule's second accepted value derives from it): absent means zero;
    // when present it obeys the carry layer's own invariants through
    // the shared predicate
    validateCarryMember(row);
    if (!HEX64.test(row.recipientId || "")) {
      refuse("an entitlement row's recipientId must be 64 lowercase hex (the payability exclusions compare identities)");
    }
    // the never-receives-carry invariant at EVERY consumption site, so
    // a self-share row with an explicit nonzero carry-in refuses here,
    // not only at classification
    if (row.recipientId === incomeIdentity
        && BigInt(row.carryInCredits || "0") !== 0n) {
      refuse("a self-share row cannot carry a nonzero carryInCredits (the income identity's rows never receive carry)");
    }
    if (seenRecipients.has(row.recipientId)) {
      refuse(`two entitlement rows share one owner (${row.recipientId.slice(0, 8)}...); the allocation's owner uniqueness is violated`);
    }
    seenRecipients.add(row.recipientId);
  }
};

/**
 * THE ONE CLASSIFIER (the closing wave's second outside family, part C:
 * the classification lived in three re-derivations, the measurement,
 * the transfer step and the driver's nonce prefetch, a drift surface).
 * Returns exactly "self-share", "below-minimum" or "payable", in the
 * pinned validation's own order (self-share first). Rows reach it
 * validated (validateEntitlementRows), and the hex check here is the
 * defensive floor for any direct caller.
 */
const classifyEntitlement = (row, incomeIdentity) => {
  // the export is SELF-CONTAINED (the batch confirmation pass): a
  // direct caller gets the same closed grammar the integrated paths
  // assert, so no call surface classifies a row the grammar refuses.
  // That includes the SECOND argument (the wave's repository-access
  // pass), because a malformed or absent income identity cannot
  // recognize a self-share and would answer payable for one
  if (!HEX64.test(incomeIdentity || "")) {
    refuse("classifyEntitlement requires the caller's income identity (64 lowercase hex)");
  }
  if (!HEX64.test(row.recipientId || "")) {
    refuse("an entitlement row's recipientId must be 64 lowercase hex (the payability exclusions compare identities)");
  }
  if (typeof row.amountCredits !== "string" || !DEC_U32.test(row.amountCredits)) {
    refuse("an entitlement row's amountCredits must be a canonical decimal string");
  }
  if (BigInt(row.amountCredits) <= 0n) {
    refuse("only a positive entitlement is classified (zero rows never reach the transfer machinery)");
  }
  // the carry member's grammar on EVERY row. Without this the closing
  // wave's second outside family showed in part D that a direct
  // caller's malformed member was silently accepted on a non-self-share
  // row and reached a raw BigInt construction error on a self-share one

  validateCarryMember(row);
  if (row.recipientId === incomeIdentity) {
    // the carry layer's invariant, enforced AT ITS REACHABLE WIDTH: an
    // EXPLICIT nonzero carry-in on a self-share refuses (no calculation
    // can conformingly hand one a carry-in); an omitted member is the
    // pre-carry shape inside the row trust boundary, indistinguishable
    // by construction (the decided rule declined an era marker)
    if (BigInt(row.carryInCredits || "0") !== 0n) {
      refuse("a self-share row cannot carry a nonzero carryInCredits (the income identity's rows never receive carry)");
    }
    return "self-share";
  }
  if (BigInt(row.amountCredits) < MIN_TRANSFER_AMOUNT_CREDITS) return "below-minimum";
  return "payable";
};

/**
 * The income identity BINDS TO THE INJECTED POOL RESOLVER (the checker
 * round's fold): the classification and the measurement compare rows
 * against deps.identities.income, so a caller-selected value would let a
 * wrong identity silently reclassify a payable row. Every step that runs
 * those comparisons resolves the pool through deps.resolvePool and
 * refuses a disagreeing configuration. WHAT THIS ESTABLISHES is agreement
 * between two injected values; that the resolver actually performs the
 * a soundness-review finding-pinned formation reads is the resolver implementation's deps
 * obligation, the same trust statement as every injected surface here.
 */
const requireIncomeBinding = (deps, poolId, what) => {
  if (typeof deps.resolvePool !== "function") {
    refuse(`${what} needs deps.resolvePool (the a soundness-review finding-pinned formation reads); the income identity must bind to the pool record`);
  }
  const resolved = deps.resolvePool(poolId);
  if (!resolved || resolved.incomeIdentity !== deps.identities.income) {
    refuse(`${what} refuses: deps.identities.income disagrees with the pool record's income identity`);
  }
};

/**
 * THE CANONICAL-GATE CONSULT (the battery definition's rule: every E2 writer
 * except the battery's own one-shot gate path REFUSES to write any E2 record
 * while E2_GATE_CAPTURE is absent or fails the strict lookup). It runs FIRST
 * in each writer entry, before any journal or ledger write. The lookup is an
 * injected dependency like every other external fact this module consumes
 * (production callers pass e2CaptureBattery.verifyGateCapture wired to their
 * journal reader); it must RESOLVE to { admitted: true }, so a stub that
 * returns nothing, throws, or reports anything else refuses, and there is no
 * parameter that waives the consult.
 */
const requireGateAdmission = async (deps, what) => {
  if (typeof (deps && deps.verifyGateCapture) !== "function") {
    refuse(`${what} needs deps.verifyGateCapture (the canonical-gate strict lookup); no E2 record is written without it`);
  }
  let verdict;
  try { verdict = await deps.verifyGateCapture(); }
  catch (e) {
    refuse(`${what} refuses: the canonical-gate strict lookup did not admit (${(e && e.message) || String(e)})`);
  }
  if (!verdict || verdict.admitted !== true) {
    refuse(`${what} refuses: the canonical-gate strict lookup returned no admission`);
  }
};

/**
 * Append one record with the semantics checked FIRST: the D7 validator
 * runs over the would-be record sequence, so an invalid record refuses
 * before any byte commits, never after (a committed invalid record would
 * refuse the whole journal at every later open).
 */
const appendChecked = (poolId, dir, rec) => {
  const { records, committedOffset } = openJournal(poolId, dir);
  validateJournal(poolId, [...records, rec]);
  return appendRecord(poolId, committedOffset, rec, dir);
};

// ---- the configuration mode ----
/**
 * The literal configuration mode `set-start <poolId> <epoch>`: writes the
 * owned E2_START_EPOCH_ key (canonical decimal u32 string). MUTABLE ONLY
 * while no journal record for the pool exists (a soundness-review finding), and the CHECK-AND-COMMIT IS
 * SERIALIZED under the same per-pool operation lock the run's first append
 * holds, so a configuration update and a first record cannot both pass
 * their checks and leave the key disagreeing with the fresh binding.
 */
const setStart = (poolId, epochStr, { dir } = {}) => {
  requirePool(poolId);
  if (typeof epochStr !== "string" || !DEC_U32.test(epochStr) || Number(epochStr) > U32_MAX) {
    refuse("the start epoch must be a canonical decimal u32 string");
  }
  envStore.acquireOpLock(poolRunLockName(poolId));
  try {
    if (openJournal(poolId, dir).records.length > 0) {
      refuse("the pool already has a journal record, so the configured start is bound and immutable (a soundness-review finding); set-start applies only before the first record");
    }
    envStore.updateEnvKey(startKeyOf(poolId), epochStr);
  } finally { envStore.releaseOpLock(poolRunLockName(poolId)); }
  return { poolId, startEpoch: Number(epochStr) };
};

const readConfiguredStartKey = (poolId) => {
  const raw = envStore.loadEnv()[startKeyOf(poolId)];
  if (raw === undefined) return null;
  if (!DEC_U32.test(raw) || Number(raw) > U32_MAX) {
    refuse(`the configured start key ${startKeyOf(poolId)} holds ${JSON.stringify(raw)}, not a canonical decimal u32`);
  }
  return Number(raw);
};

// ---- the lag measure ----
// COMPLETION IS NEVER INFERRED FROM THE JOURNAL: the journal records no
// document-write success, so "without a COMPLETE distribution" is step 5's
// derived lifecycle over platform reads, INJECTED as
// deps.epochDistributionComplete (its unproved status before C1 propagates
// to the measurement exactly as the spec states, and a false or absent
// answer counts the epoch lagging, the conservative direction). The
// journal supplies only the outstanding-amount SUM: positive PAYABLE
// entitlements without a receipt capture, at full value. PAYABLE applies
// step 5's exclusions (a soundness-review finding): a self-share is settled where it
// sits and a below-minimum amount reappears inside a later epoch's
// effective entitlements, so counting either would overstate or
// double-count.
// The return reports BOTH sums over the epoch it is called for, so the
// BELOW-MINIMUM exclusion is visible instead of vanishing (a measurement
// reports what it excluded, not only its verdict). HOW THE CALLER USES
// THE TWO DIFFERS, and that difference is a soundness-review finding correction: `payable`
// is a FLOW and accumulates across incomplete epochs, while `carried` is
// a STOCK and the caller keeps only the frontier epoch's. The
// MACHINERY test comes FIRST for every row (the checker's fold):
// any row whose accrual carries journaled transfer or reservation
// machinery without a receipt keeps the OLD undistributed accounting,
// self-shares included, because unresolved machinery is outstanding
// process state whatever the row's classification would be. With no
// machinery: a SELF-SHARE contributes nothing (its value rests at the
// owner's own identity, nothing outstanding), a below-minimum row
// contributes nothing HERE because it is a deferral rather than a payable,
// and a payable row contributes its amount.
//
// THIS FUNCTION NO LONGER REPORTS THE DEFERRAL, and that separation is
// a soundness-review finding rule taken at its word. The deferral is a property of the CARRY
// RULE alone, computed by the caller from the rows; it does not consult
// the journal, because a below-minimum amount is deferred by rule whatever
// machinery sits on its accrual. Deriving it here instead, with the
// machinery exclusion applied, was a deviation that produced two defects a
// review found: an earlier epoch's stuck amount was reported as payable
// AND folded into the frontier's deferral, and a complete frontier holding
// a stuck below-minimum row reported nothing at all while the carry rule
// required the next epoch to contain it.
//
// THE TWO FIGURES MEASURE DIFFERENT THINGS AND MAY OVERLAP, which is worth
// stating rather than engineering away. `undistributedCredits` is
// outstanding PROCESS state across incomplete epochs; `carriedCredits` is
// the deferral at the frontier by the carry rule. A stuck below-minimum row
// is genuinely both, and reporting it in both is more truthful than
// choosing one and leaving the other silent.
const journalOutstandingPayable = (read, epochIndex, rows, incomeIdentity) => {
  const e = read.perEpoch[epochIndex];
  let payable = 0n;
  for (const r of rows) {
    if (BigInt(r.amountCredits) <= 0n) continue;
    const cls = classifyEntitlement(r, incomeIdentity);
    const a = e && e.accruals[r.accrualId];
    if (a && a.receiptCaptured) continue;
    const hasMachinery = !!(a && (a.transfer || a.reservation));
    if (hasMachinery) { payable += BigInt(r.amountCredits); continue; }
    if (cls === "self-share") continue; // settled where it sits
    if (cls === "below-minimum") continue; // a deferral, not a payable
    payable += BigInt(r.amountCredits);
  }
  return payable;
};

/**
 * THE LIFECYCLE ANSWER, READ THROUGH ONE PREDICATE THAT REFUSES WHAT IT CANNOT READ.
 *
 * Both consumers compare this dependency's answer with `!== true` and neither awaits it,
 * which is a contract that silently misreads the one implementation the specification
 * actually calls for. Step 5's lifecycle is a derivation over PLATFORM READS, so an honest
 * implementation is asynchronous, and a Promise is not strictly equal to `true`. Supplied
 * asynchronously, answers that give lag 1 synchronously give lag 2 instead, with nothing
 * said and nothing failing.
 *
 * THIS DOES NOT MAKE THE SEAM ASYNCHRONOUS, which is a larger decision about where the
 * canonical lifecycle rule should live. It makes the seam refuse an answer it cannot read
 * correctly, so the next implementation that returns a Promise, a truthy string or nothing
 * at all is stopped by name rather than quietly changing what the writer measures and
 * which epoch it selects.
 */
const epochComplete = (deps, epochIndex) => {
  const answer = deps.epochDistributionComplete(epochIndex);
  if (answer !== true && answer !== false) {
    refuse(`deps.epochDistributionComplete must answer a strict boolean for epoch ${epochIndex}, and answered ${answer && typeof answer.then === "function" ? "a Promise (this seam is synchronous: an asynchronous lifecycle check would be read as incomplete for every epoch)" : JSON.stringify(answer)}`);
  }
  return answer;
};

// ---- the run start ----
/**
 * Resolve the configured start (the journaled binding once any record
 * exists, the local key before then, disagreement refusing), enumerate the
 * finalized universe through the ONE shared discovery primitive, compute
 * the lag and the undistributed sum, and append the durable neutral
 * lag-measurement (EVERY run start, lag zero and one included), the pool's
 * first record carrying `configuredStartEpoch`. The first-append
 * check-and-commit holds the same per-pool lock as set-start.
 */
const startRun = async ({ poolId, dir, deps }) => {
  requirePool(poolId);
  if (!deps || typeof deps.fetchRange !== "function" || typeof deps.entitlementsForEpoch !== "function"
    || typeof deps.epochDistributionComplete !== "function") {
    refuse("startRun needs deps.fetchRange (discovery), deps.entitlementsForEpoch and deps.epochDistributionComplete (the step-5 lifecycle over platform reads)");
  }
  if (!deps.identities || !HEX64.test(deps.identities.income || "")) {
    refuse("startRun needs deps.identities.income (hex): the measurement's payability exclusions compare against it");
  }
  requireIncomeBinding(deps, poolId, "startRun");
  envStore.acquireOpLock(poolRunLockName(poolId));
  try {
    const read = openValidatedJournal(poolId, dir);
    const localKey = readConfiguredStartKey(poolId);
    let configuredStart;
    if (read.records.length > 0) {
      configuredStart = read.configuredStartEpoch;
      if (localKey !== null && localKey !== configuredStart) {
        refuse(`the local configured start ${localKey} disagrees with the journaled binding ${configuredStart} (a soundness-review finding)`);
      }
    } else {
      if (localKey === null) {
        refuse(`no configured start: set it with set-start before the pool's first run (${startKeyOf(poolId)})`);
      }
      configuredStart = localKey;
    }

    const discovery = await discoverFinalizedEpochs(configuredStart, deps.fetchRange, deps.discoveryOpts || {});
    const universe = discovery.empty ? [] : discovery.epochs;

    let lag = 0;
    let undistributed = 0n;
    // THE DEFERRED STOCK AT THE FRONTIER (a soundness-review finding), not a sum across epochs.
    // With a carry-capable calculation each epoch's effective amount already
    // contains every earlier epoch's deferral for that member, so adding the
    // epochs together counts one deferral once per epoch it survives into.
    // The frontier is the LAST universe epoch, the newest finalized one
    // (Hilawe, 2026-08-30): the figure exists so that a deferred amount is
    // visible and never vanishes, and stopping at the last COMPLETED epoch
    // would make a deferral sitting in a finalized-but-unworked epoch
    // invisible, which is the disappearance it was added to prevent. The
    // recursion is deterministic and execution-independent by the build
    // spec's own first carry property, so the newest finalized epoch is as
    // well-founded a frontier as any epoch the run has worked.
    // AN EMPTY UNIVERSE REPORTS ZERO, and that is a specified identity rather than a
    // value left over from an unexecuted loop. With no finalized epoch there is no epoch
    // whose entitlements could have been below the minimum, so nothing is deferred, and
    // zero is the deferral rather than a stand-in for one. The measurement is still
    // appended, because the run start's record is what binds the configured start and is
    // owed whether or not discovery found anything.
    let carriedStock = 0n;
    // A DEFERRAL MAY NOT SHRINK OR DISAPPEAR ACROSS EPOCHS, which is the part
    // of the row source's carry-capability the writer can actually see.
    // Replacing the carried figure rather than accumulating it is correct only
    // if each epoch's rows already contain the previous epoch's deferral, and
    // an omitted `carryInCredits` cannot distinguish a zero carry from a
    // pre-carry calculation. THIS CHECK IS A SUBSET AND THE WIDTH IS WORTH
    // STATING: effective is the deferral plus a non-negative owed amount, so a
    // member deferring X must be owed at least X at the next epoch, and a
    // source answering LESS has lost the deferral. A source answering EXACTLY
    // X while the member was owed more is indistinguishable from a conforming
    // one owed nothing, and no check here can separate them, because the owed
    // amount is precisely what the writer delegates. It bounds the TOTAL from
    // below and establishes nothing about ATTRIBUTION, and it cannot: an
    // omitted `carryInCredits` is a cost-free opt-out BY DESIGN, since the
    // build spec's migration rule declined a calculation-era marker, so
    // absence is the pre-carry shape and no record says which era produced a
    // row. The build spec's trust statement stands; this closes the shape
    // where value goes missing, not the shape where it is mis-attributed.
    let deferredPrev = new Map();
    for (const ep of universe) {
      const rows = deps.entitlementsForEpoch(ep.number);
      if (!Array.isArray(rows)) refuse(`deps.entitlementsForEpoch returned no rows for epoch ${ep.number}`);
      // every enumerated epoch's rows have their recipientId validated,
      // COMPLETE ones included: a completeness answer never exempts the
      // identity comparison's input from the check
      validateEntitlementRows(rows, deps.identities.income);
      if (deferredPrev.size > 0) {
        const present = new Set();
        for (const r of rows) {
          present.add(r.recipientId);
          const owedForward = deferredPrev.get(r.recipientId);
          if (owedForward !== undefined && BigInt(r.amountCredits) < owedForward) {
            refuse(`epoch ${ep.number}'s entitlement for ${r.recipientId.slice(0, 8)}... is ${r.amountCredits}, below the ${owedForward} deferred to it by the previous epoch; the calculation is not carry-capable and this run's measurement would understate the deferral`);
          }
        }
        for (const [rid, amt] of deferredPrev) {
          if (!present.has(rid)) {
            refuse(`epoch ${ep.number} carries no row for ${rid.slice(0, 8)}..., to whom the previous epoch deferred ${amt}; a deferral cannot vanish by its member leaving the row set`);
          }
        }
      }
      // WHAT THIS EPOCH DEFERS, by the carry rule alone and derived ONCE. The
      // same map obliges the next epoch to contain these amounts and, at the
      // last universe epoch, IS the reported stock, so the obligation and the
      // report cannot disagree about what is deferred. Per-recipient keying is
      // sound because validateEntitlementRows above refuses a row set in which
      // two rows share an owner.
      deferredPrev = new Map();
      for (const r of rows) {
        if (BigInt(r.amountCredits) <= 0n) continue;
        if (classifyEntitlement(r, deps.identities.income) === "below-minimum") {
          deferredPrev.set(r.recipientId, BigInt(r.amountCredits));
        }
      }
      // REPLACED, never accumulated: after the loop this holds the LAST
      // universe epoch's deferral, which is the stock at the frontier
      carriedStock = 0n;
      for (const amt of deferredPrev.values()) carriedStock += amt;
      if (epochComplete(deps, ep.number) !== true) {
        lag += 1;
        undistributed += journalOutstandingPayable(read, ep.number, rows, deps.identities.income);
      }
    }

    appendChecked(poolId, dir, { v: 1, kind: K.DECLARATION, object: "pool", gen: 1, poolId,
      condition: "lag-measurement", reasoning: "run start", lagCount: lag,
      undistributedCredits: String(undistributed),
      carriedCredits: String(carriedStock),
      ...(read.records.length === 0 ? { configuredStartEpoch: configuredStart } : {}) });

    return { configuredStart, universe, lag, undistributedCredits: String(undistributed),
      carriedCredits: String(carriedStock),
      discoveryProved: discovery.proved,
      // the RUN TOKEN: the pool and the appended measurement's record
      // index, which every header step of THIS run must present (a later
      // run's fresh measurement invalidates it, and a different pool's
      // token never matches, so no step runs under another run's measure)
      runPoolId: poolId,
      measurementSeq: read.records.length,
      distributionLagging: lag > 1 }; // DERIVED, never appended (count above 1)
  } finally { envStore.releaseOpLock(poolRunLockName(poolId)); }
};

// ---- step 1, the header flow ----
const pickNextEpoch = (universe, deps) => {
  // ascending, no skips, no new header while an earlier epoch is
  // incomplete: the target is the FIRST universe epoch the injected
  // step-5 lifecycle does not report COMPLETE; a stalled earlier epoch
  // stalls the run here, and journal evidence never infers completion
  for (const ep of universe) {
    if (epochComplete(deps, ep.number) !== true) return ep.number;
  }
  return null;
};

/**
 * THE OPERATOR'S RESEND, the only way a transition already marked sent is ever sent again. It is
 * licensed exactly when the subject's LAST journal record is a rebroadcast-identical decision in
 * the current generation, which is the journal's own adjacency rule (`e2Journal.cjs`, the
 * sentMarker case). The repeated marker appended next consumes the decision, so the validator
 * refuses a second resend on it, and one decision licenses one resend. The journal is re-read
 * here rather than trusted from earlier in the step, since the answer must describe the journal
 * as it stands when the marker is written. The decision itself is written by
 * `e2OperatorDecision.cjs`, never by this module.
 */
const resendAuthorized = (poolId, dir, { object, epochIndex, accrualId, gen }) => {
  const { records } = openValidatedJournal(poolId, dir);
  const same = (r) => r.object === object && r.epochIndex === epochIndex
    && (r.accrualId ?? null) === (accrualId ?? null) && (r.partIndex ?? null) === null;
  let last = null;
  for (const r of records) if (same(r)) last = r;
  return last !== null && last.kind === K.DECISION && last.action === "rebroadcast-identical"
    && last.condition === `${object}-unresolved` && last.gen === gen;
};

/**
 * THE RESEND ITSELF: the persisted bytes once, then the transition's outcome read from its HASH.
 *
 * ONLY A VERIFIED SUCCESS IS TAKEN FROM THE RESEND'S OWN ANSWER. Any other answer describes the
 * resend, not the transition. Identical bytes may already have executed, and duty D6 bounds their
 * execution at one without saying which submission ran, so a resend can be refused precisely
 * because the original succeeded: its nonce is used, or its document already exists. A review
 * showed the first version recorded such a refusal as the transition's outcome. So every answer
 * short of success is replaced by a WAIT on the persisted hash, which names the original and the
 * resend alike. A node answers bytes it already holds with a duplicate-in-cache refusal (duty D6's
 * double-send run), and the wait then reads the original's result, so a resend of a transition that
 * had executed settles in one run WHEN the wait returns that verified result; an unavailable answer
 * leaves it unresolved. A refusal the WAIT returns is recorded as the ledger's answer about those
 * bytes. STATED ASSUMPTION: the wait reports the outcome of the submission that EXECUTED, which holds
 * for a gateway that answers from the transaction included in a block, since a duplicate refused
 * before inclusion produces no result of its own. The wait never sends anything.
 */
const resendAndAwait = async (deps, hash, bytes) => {
  const sent = await deps.broadcastAndAwait(hash, bytes);
  return classifyOutcome(sent, deps._uniqueIdentityForTest) === TOKENS.SUCCESS ? sent : deps.awaitResult(hash);
};

const headerRecordsOf = (read, epochIndex, gen) =>
  read.records.filter((r) => r.object === "header" && r.epochIndex === epochIndex && r.gen === gen);

// an unconsumed rebuild-corrected decision authorizes ONE new generation:
// present exactly when the decision exists and no later header write-ahead
// of the next generation has consumed it
const unconsumedRebuild = (read, epochIndex, gen) => {
  const decided = read.records.some((r) => r.kind === K.DECISION && r.object === "header"
    && r.epochIndex === epochIndex && r.gen === gen && r.action === "rebuild-corrected");
  const nextOpened = read.records.some((r) => r.kind === K.WRITE_AHEAD && r.object === "header"
    && r.epochIndex === epochIndex && r.gen === gen + 1);
  return decided && !nextOpened;
};

/**
 * Run STEP 1 for the next undistributed epoch. In this exact order for a
 * fresh attempt: the D10 admission under the header's full lock set, the
 * build (construction consumes a nonce, so it happens inside the locks),
 * the durable write-ahead, the committed sent-marker, THEN the broadcast,
 * the awaited result classified through the ONE conforming classifier, the
 * capture journaled, and the writer's frontier advanced from the capture's
 * verified height, still under the locks. RESUME rules per the
 * durable-state table: a write-ahead without its sent-marker has not been
 * broadcast BY THIS BRANCH and resumes by committing S then broadcasting
 * THE PERSISTED BYTES; with the marker set, recovery is WAIT-ONLY on the
 * persisted hash and NOTHING is rebuilt or re-signed. A duplicate refusal
 * resumes ordinarily ONLY when the proved on-ledger document identifier
 * equals the expected one AND every header field equals the recomputation;
 * anything else is the FOREIGN condition, returned as a status for the
 * operator's journaled decision.
 *
 * Returns { status, epochIndex, ... } with status one of: "captured",
 * "already-complete", "refused" (structured error journaled;
 * header-refused available), "stopped", "unresolved-pending" (wait-only;
 * header-unresolved available after patience), "foreign-pending"
 * (header-foreign available), "duplicate-resume-capture-incomplete" (the
 * degraded continuation is the operator's journaled declaration).
 */
const runHeaderStep = async ({ poolId, dir, deps, run }) => {
  requirePool(poolId);
  await requireGateAdmission(deps, "runHeaderStep");
  const need = ["fetchRange", "entitlementsForEpoch", "epochNumbers", "epochDistributionComplete",
    "buildHeaderTransition", "broadcastAndAwait", "awaitResult", "buildHeaderCapture",
    "provedHeaderQuery", "fetchBalanceWithMetadata", "resolvePool"];
  for (const k of need) if (typeof (deps && deps[k]) !== "function") refuse(`runHeaderStep needs deps.${k}`);
  if (!deps.identities || !HEX64.test(deps.identities.writer || "") || !HEX64.test(deps.identities.income || "")) {
    refuse("runHeaderStep needs deps.identities ({ writer, income } hex)");
  }

  if (!run || !Number.isSafeInteger(run.measurementSeq)) {
    refuse("the header step needs its run's token (startRun's return); no step runs without its own fresh measurement");
  }
  if (run.runPoolId !== poolId) {
    refuse("the run token names a different pool; a token never crosses pools");
  }
  // THE WHOLE STEP HOLDS THE PER-POOL RUN LOCK (acquired FIRST, before the
  // identity locks, one consistent order everywhere): the token check and
  // everything after it are serialized against startRun and set-start, so
  // a newer measurement cannot land between the check and the step's
  // journal writes. Inside it, the journal's LATEST lag-measurement must
  // be the one this run appended.
  envStore.acquireOpLock(poolRunLockName(poolId));
  try {
  const read = openValidatedJournal(poolId, dir);
  let latestMeasurement = -1;
  read.records.forEach((r, i) => {
    if (r.kind === K.DECLARATION && r.condition === "lag-measurement") latestMeasurement = i;
  });
  if (latestMeasurement !== run.measurementSeq) {
    refuse(`the journal's latest lag-measurement (record ${latestMeasurement}) is not this run's (record ${run.measurementSeq}); start a fresh run`);
  }

  const discovery = await discoverFinalizedEpochs(read.configuredStartEpoch, deps.fetchRange, deps.discoveryOpts || {});
  const universe = discovery.empty ? [] : discovery.epochs;
  const epochIndex = pickNextEpoch(universe, deps);
  if (epochIndex === null) return { status: "already-complete", epochIndex: null };

  const headerState = (read.perEpoch[epochIndex] && read.perEpoch[epochIndex].header) || null;
  let gen = headerState ? headerState.gen : 1;

  if (headerState && headerState.stopped) return { status: "stopped", epochIndex };
  if (headerState && (headerState.state === "captured" || headerState.captureIncomplete === true)) {
    // the header is done but the epoch is still undistributed: step 1 has
    // nothing left here, the outstanding work is the transfer steps. A
    // torn capture-then-frontier pair (the capture committed, the advance
    // interrupted) is REPAIRED here idempotently: re-advancing from the
    // journaled capture is max-monotone, so a completed pair is a no-op
    const cap = read.records.find((r) => r.kind === HEADER_KIND
      && r.epochIndex === epochIndex && r.gen === headerState.gen);
    if (cap) {
      const locks = acquireIdentityLocks([deps.identities.writer]);
      try {
        advanceFrontierFromCapture({ kind: HEADER_KIND, height: BigInt(cap.inclusionHeight),
          identities: deps.identities }, { dir, locks });
      } finally { locks.release(); }
    }
    return { status: "header-done-transfers-pending", epochIndex };
  }
  if (headerState && headerState.state === "refused") {
    if (unconsumedRebuild(read, epochIndex, gen)) {
      gen += 1; // the journaled decision authorizes exactly one rebuilt attempt
    } else {
      return { status: "refused", epochIndex,
        note: "header-refused is established; the rebuild or stop is the operator's journaled decision" };
    }
  }

  const rows = deps.entitlementsForEpoch(epochIndex);
  validateEntitlementRows(rows, deps.identities.income);
  const numbers = deps.epochNumbers(epochIndex);
  const expectedContents = { poolId, epochIndex, grossCredits: numbers.grossCredits,
    feeCredits: numbers.feeCredits, allocationHash: numbers.allocationHash,
    memberCount: numbers.memberCount, calcVersion: numbers.calcVersion };
  const positives = rows.filter((r) => BigInt(r.amountCredits) > 0n);

  // ---- RESUME: a persisted attempt is never rebuilt, and recovery runs
  // under the header's FULL lock set exactly like a fresh attempt (the
  // resumed send or wait is the same outstanding operation on the same
  // identities, held through the awaited result) ----
  if (headerState && (headerState.state === "written" || headerState.state === "sent") && headerState.gen === gen) {
    const g = headerRecordsOf(read, epochIndex, gen);
    const W = g.find((r) => r.kind === K.WRITE_AHEAD);
    const hasS = g.some((r) => r.kind === K.SENT_MARKER);
    const locks = acquireIdentityLocks([deps.identities.writer, deps.identities.income]);
    try {
      if (!hasS) {
        // not broadcast by this branch: commit S, then send THE PERSISTED BYTES
        appendChecked(poolId, dir, { v: 1, kind: K.SENT_MARKER, object: "header", gen, poolId,
          epochIndex, transitionHash: W.transitionHash });
        const result = await deps.broadcastAndAwait(W.transitionHash, W.transitionBytes);
        return await finishHeaderOutcome({ poolId, dir, deps, epochIndex, gen, W, expectedContents, result, locks });
      }
      // marker set: the operator's journaled resend of THE PERSISTED BYTES if one is licensed,
      // otherwise WAIT-ONLY on the persisted hash; either result goes through the SAME outcome
      // table as an initial await (a refusal journals its error, a duplicate refusal runs the
      // proved-equality gate, ambiguity stays wait-only)
      if (resendAuthorized(poolId, dir, { object: "header", epochIndex, gen })) {
        appendChecked(poolId, dir, { v: 1, kind: K.SENT_MARKER, object: "header", gen, poolId,
          epochIndex, transitionHash: W.transitionHash });
        const resent = await resendAndAwait(deps, W.transitionHash, W.transitionBytes);
        return await finishHeaderOutcome({ poolId, dir, deps, epochIndex, gen, W, expectedContents, result: resent, locks });
      }
      const result = await deps.awaitResult(W.transitionHash);
      return await finishHeaderOutcome({ poolId, dir, deps, epochIndex, gen, W, expectedContents, result, locks });
    } finally { locks.release(); }
  }

  // ---- FRESH ATTEMPT (no write-ahead in the current generation) ----
  const locks = acquireIdentityLocks([deps.identities.writer, deps.identities.income]);
  try {
    await admitHeader({ dir, poolId,
      candidate: { epochIndex, memberCount: numbers.memberCount,
        positiveEntitlements: positives.map((r) => ({ accrualId: r.accrualId, amountCredits: r.amountCredits })) },
      identities: deps.identities, resolvePool: deps.resolvePool,
      fetchBalanceWithMetadata: deps.fetchBalanceWithMetadata,
      feeCeilings: deps.feeCeilings, chainIdPin: deps.chainIdPin, locks });

    // construction consumes a nonce, so it happens inside the locks
    const built = deps.buildHeaderTransition({ poolId, epochIndex, expectedContents });
    const firstHeaderW = !read.records.some((r) => r.kind === K.WRITE_AHEAD && r.object === "header");
    const W = { v: 1, kind: K.WRITE_AHEAD, object: "header", gen, poolId, epochIndex,
      transitionBytes: built.transitionBytes, transitionHash: built.transitionHash,
      expectedDocumentId: built.expectedDocumentId, expectedContents,
      ...(firstHeaderW ? { configuredStartEpoch: read.configuredStartEpoch } : {}) };
    appendChecked(poolId, dir, W);
    appendChecked(poolId, dir, { v: 1, kind: K.SENT_MARKER, object: "header", gen, poolId,
      epochIndex, transitionHash: built.transitionHash });
    // ONLY NOW may anything be sent: the sent-marker's commit point has
    // returned, so a stop after the broadcast cannot orphan the send
    const result = await deps.broadcastAndAwait(built.transitionHash, built.transitionBytes);
    return await finishHeaderOutcome({ poolId, dir, deps, epochIndex, gen, W, expectedContents, result, locks });
  } finally { locks.release(); }
  } finally { envStore.releaseOpLock(poolRunLockName(poolId)); }
};

// the shared outcome tail for a fresh or resumed broadcast
const finishHeaderOutcome = async ({ poolId, dir, deps, epochIndex, gen, W, expectedContents, result, locks }) => {
  // deps._uniqueIdentityForTest mirrors e2Outcome's governed seam EXACTLY:
  // it supplies only the pinned-identity argument, so the closed-shape
  // validation always runs and cannot be replaced; the unique-index
  // identity is unpinned, so the duplicate-refusal branch is unreachable
  // through the production default until the pinning-time read lands, and
  // the seam makes it executable in the battery ONLY (any use outside the
  // test file is a review finding)
  const token = classifyOutcome(result, deps._uniqueIdentityForTest);
  if (token === TOKENS.SUCCESS) {
    return journalHeaderCapture({ poolId, dir, deps, epochIndex, gen, W, expectedContents, result, locks });
  }
  if (token === TOKENS.UNIQUE) {
    // a duplicate refusal with a local write-ahead present is the ordinary
    // resume signal ONLY when the proved on-ledger document identifier
    // equals the expected one and every field equals the recomputation
    const q = await deps.provedHeaderQuery(poolId, epochIndex);
    if (!q || q.found !== true) {
      return { status: "unresolved-pending", epochIndex,
        note: "duplicate refusal but the proved query shows no header; wait-only" };
    }
    // THE ANSWER MUST ATTEST THAT IT WAS PROVED, and one that does not is REFUSED here
    // rather than journaled (a soundness-review finding). What is journaled below carries
    // `route: PROVED_HEADER_ROUTE`, whose literal value says proved, and the journal
    // validator uses an observation on THAT ROUTE as the establishing evidence permitting
    // the degraded continuation past this refusal. The live adapter supplying this
    // dependency was an ordinary document query that obtained no proof and checked no
    // verified-call marker, so an unauthenticated answer with matching fields could
    // authorize that continuation while the durable record asserted it was proved.
    //
    // WHAT THIS CAN AND CANNOT DO, at its real width: the writer cannot verify an
    // attestation, and an adapter that lies is inside the same trust boundary as one that
    // lies about any other injected value. What it closes is the SILENT case, where an
    // adapter that proves nothing says nothing and is believed anyway. The refusal
    // precedes every append, so a failed verification leaves no record claiming a proved
    // route.
    if (q.proved !== true) {
      return { status: "proved-header-unattested", epochIndex,
        note: "the header query answered a document but did not attest that it was proved; refusing rather than journaling it under the proved route (a soundness-review finding)" };
    }
    // the proved result IS the establishing evidence D7 requires before
    // header-foreign or header-capture-incomplete can be surfaced, so it
    // is journaled as the foreign-document observation HERE (an
    // observation is evidence, not an operator condition), with the
    // proved route, before the status returns
    appendChecked(poolId, dir, { v: 1, kind: K.OBSERVATION, object: "header", gen, poolId,
      epochIndex, observationType: "foreign-document", route: PROVED_HEADER_ROUTE,
      observedDocumentId: q.documentId,
      observedFields: (q.fields && typeof q.fields === "object") ? q.fields : {} });
    if (q.documentId !== W.expectedDocumentId) {
      return { status: "foreign-pending", epochIndex,
        note: "the on-ledger header is a different document (header-foreign is the operator condition)" };
    }
    const same = ["grossCredits", "feeCredits", "allocationHash", "memberCount", "calcVersion"]
      .every((k) => q.fields && q.fields[k] === expectedContents[k])
      && q.fields && q.fields.poolId === expectedContents.poolId
      && q.fields.epochIndex === expectedContents.epochIndex;
    if (!same) {
      return { status: "foreign-pending", epochIndex,
        note: "the on-ledger header's fields differ from the recomputation (hard stop)" };
    }
    return { status: "duplicate-resume-capture-incomplete", epochIndex,
      note: "proved equality holds; the degraded continuation is the operator's journaled header-capture-incomplete declaration (the transition-result capture remains unavailable)" };
  }
  if (token === TOKENS.OTHER) {
    appendChecked(poolId, dir, { v: 1, kind: K.ERROR, object: "header", gen, poolId,
      epochIndex, code: Number.isSafeInteger(result && result.code) ? result.code : 0,
      data: typeof (result && result.data) === "string" ? result.data : "",
      message: String((result && result.message) || "execution refusal"),
      errorClass: "execution-refusal" });
    return { status: "refused", epochIndex,
      note: "the structured error is journaled; header-refused is the operator condition" };
  }
  return { status: "unresolved-pending", epochIndex,
    note: "ambiguous outcome journals nothing; recovery is wait-only on the persisted hash" };
};

// the CAPTURE builders may be async (the live capture signer is; the
// battery's sync mocks resolve through the same await unchanged): unlike
// the TRANSITION builders, whose synchronous contract exists for the
// nonce-window reason, a capture consumes no nonce, so awaiting it holds
// no resource beyond the locks already held (the rehearsal run's fix:
// the writer consumed the builder's promise as a record and refused)
const journalHeaderCapture = async ({ poolId, dir, deps, epochIndex, gen, W, expectedContents, result, locks }) => {
  const capture = await deps.buildHeaderCapture({ poolId, epochIndex, gen, writeAhead: W, expectedContents, result });
  if (!capture || capture.kind !== HEADER_KIND) refuse("deps.buildHeaderCapture must return the signed header-capture record");
  appendChecked(poolId, dir, capture);
  // the capture's verified metadata height advances the RECORD WRITER's
  // frontier before any later admission; the fresh path advances under its
  // held lock set, a resumed path acquires just the writer's lock
  const height = BigInt(capture.inclusionHeight);
  let releasable = null;
  try {
    let held = locks;
    if (!held || !held.holds(deps.identities.writer)) {
      held = acquireIdentityLocks([deps.identities.writer]);
      releasable = held;
    }
    advanceFrontierFromCapture({ kind: HEADER_KIND, height, identities: deps.identities }, { dir, locks: held });
  } finally { if (releasable) releasable.release(); }
  return { status: "captured", epochIndex };
};


// ============================================================
// THE SECOND HALF: step 2 (the accrual documents) and step 3 (the
// preflight-bounded reservation-transfer-receipt sequence with the
// explicit lock handoff), plus step 4's no-automatic-rebroadcast rule.
// The same disciplines as the first half: the run token and per-pool
// lock around every step, appendChecked before every byte, persisted
// transitions never rebuilt, operator conditions never appended (the
// run-side declarations the spec assigns, transfer-unencodable and the
// classification pair self-share-settled and transfer-below-minimum, are
// appended here, once per subject), and completion never inferred.
// ============================================================

const requireRunToken = (run, poolId, read) => {
  if (!run || !Number.isSafeInteger(run.measurementSeq)) {
    refuse("the step needs its run's token (startRun's return)");
  }
  if (run.runPoolId !== poolId) refuse("the run token names a different pool; a token never crosses pools");
  let latest = -1;
  read.records.forEach((r, i) => {
    if (r.kind === K.DECLARATION && r.condition === "lag-measurement") latest = i;
  });
  if (latest !== run.measurementSeq) {
    refuse(`the journal's latest lag-measurement (record ${latest}) is not this run's (record ${run.measurementSeq}); start a fresh run`);
  }
};

const { canonicalString: jcs } = require("./canonicalJson.cjs");
// field equality through the canonical serialization, so property insertion
// order can never manufacture a mismatch (the checker's F6)
const canonicalEq = (a, b) => jcs(a) === jcs(b);

/**
 * THE DOCUMENT-WRITE LOOP, one pass (the closed loop of the frozen text):
 * fetch; on ABSENCE submit once and await; a duplicate refusal enters the
 * stale-read wait-only fetch-and-compare; an execution error other than a
 * duplicate refusal journals the structured error and is
 * record-write-refused, a terminal stop; an AMBIGUOUS outcome re-enters
 * the loop at fetch ON THE NEXT INVOCATION (retry permission is bounded
 * by operator patience surfacing record-write-unresolved, which is the
 * OPERATOR's journaled declaration, never this function's). On resume a
 * present document must equal the recomputation; mismatch is a hard
 * stop. Statuses: "present", "written", "mismatch-stop", "refused",
 * "ambiguous".
 */
const documentWriteOnce = async ({ poolId, dir, deps, object, epochIndex, accrualId, partIndex, expected }) => {
  // a subject already terminal in the journal never re-attempts: a
  // journaled execution refusal is record-write-refused (stop only), and
  // a consumed stop is final
  {
    const read = openValidatedJournal(poolId, dir);
    const dkey = partIndex !== undefined ? `${object}:${accrualId}:${partIndex}` : `${object}:${accrualId}`;
    const st = read.perEpoch[epochIndex] && read.perEpoch[epochIndex].documentWriteSubjects[dkey];
    if (st && st.stopped) return { status: "stopped" };
    if (st && st.state === "refused") {
      return { status: "refused", note: "record-write-refused stands (stop is the only action)" };
    }
  }
  const key = { poolId, epochIndex, accrualId, partIndex };
  const found = await deps.documents.fetch(object, key);
  if (found && found.found === true) {
    return canonicalEq(found.fields, expected) ? { status: "present" }
      : { status: "mismatch-stop", note: `the on-ledger ${object} differs from the recomputation (hard stop)` };
  }
  const result = await deps.documents.write(object, key, expected);
  const token = classifyOutcome(result, deps._uniqueIdentityForTest);
  if (token === TOKENS.SUCCESS) return { status: "written" };
  if (token === TOKENS.UNIQUE) {
    // the stale-read rule: wait-only fetch-and-compare, never a resubmit
    const again = await deps.documents.fetch(object, key);
    if (again && again.found === true) {
      return canonicalEq(again.fields, expected) ? { status: "present" }
        : { status: "mismatch-stop", note: `the on-ledger ${object} differs from the recomputation (hard stop)` };
    }
    return { status: "ambiguous", note: "duplicate refusal with a proved absence; wait-only re-fetch next pass" };
  }
  if (token === TOKENS.OTHER) {
    appendChecked(poolId, dir, { v: 1, kind: K.ERROR, object, gen: 1, poolId, epochIndex,
      ...(accrualId ? { accrualId } : {}), ...(partIndex !== undefined ? { partIndex } : {}),
      code: Number.isSafeInteger(result && result.code) ? result.code : 0,
      data: typeof (result && result.data) === "string" ? result.data : "",
      message: String((result && result.message) || "execution refusal"),
      errorClass: "execution-refusal" });
    return { status: "refused", note: "record-write-refused is the operator condition (stop only)" };
  }
  return { status: "ambiguous" };
};

/**
 * STEP 2: one platformAccrual per allocation row (every row, zero
 * entitlements included), under the run token, the per-pool lock and the
 * RECORD-WRITER lock (the accrual write's stated lock set). Stops at the
 * first non-advancing row. Returns { statuses: [{accrualId, status}] }.
 */
const runAccrualStep = async ({ poolId, dir, deps, run, epochIndex }) => {
  requirePool(poolId);
  await requireGateAdmission(deps, "runAccrualStep");
  for (const k of ["entitlementsForEpoch", "accrualPayload"]) {
    if (typeof (deps && deps[k]) !== "function") refuse(`runAccrualStep needs deps.${k}`);
  }
  if (!deps.documents || typeof deps.documents.fetch !== "function" || typeof deps.documents.write !== "function") {
    refuse("runAccrualStep needs deps.documents ({ fetch, write })");
  }
  envStore.acquireOpLock(poolRunLockName(poolId));
  try {
    const read = openValidatedJournal(poolId, dir);
    requireRunToken(run, poolId, read);
    const locks = acquireIdentityLocks([deps.identities.writer]);
    try {
      const rows = deps.entitlementsForEpoch(epochIndex);
      // the fourth consumption site (the closing wave's part D major).
      // Durable accrual documents are never written from a row set the
      // grammar refuses
      validateEntitlementRows(rows, deps.identities.income);
      const statuses = [];
      for (const row of rows) {
        const r = await documentWriteOnce({ poolId, dir, deps, object: "accrual", epochIndex,
          accrualId: row.accrualId, expected: deps.accrualPayload(epochIndex, row) });
        statuses.push({ accrualId: row.accrualId, ...r });
        if (r.status !== "present" && r.status !== "written") break; // no row advances past a stall
      }
      // the step-level answer, so a caller need not re-derive the stall
      // from the per-row statuses (the closing wave's first outside
      // family, part B): complete means every row of a NONEMPTY set
      // advanced (an empty set examined nothing, and a pool always has
      // 1..8 allocation rows, so empty rows are upstream nonconformance,
      // never a completed step; the batch confirmation pass)
      return { statuses,
        complete: rows.length > 0 && statuses.length === rows.length
          && statuses.every((s) => s.status === "present" || s.status === "written") };
    } finally { locks.release(); }
  } finally { envStore.releaseOpLock(poolRunLockName(poolId)); }
};

// subject-state helpers over the read result
const accrualRecordsOf = (read, epochIndex, accrualId, object) =>
  read.records.filter((r) => r.object === object && r.epochIndex === epochIndex && r.accrualId === accrualId);
const findAccrualDeclaration = (read, epochIndex, accrualId, condition) =>
  read.records.find((r) => r.kind === K.DECLARATION && r.condition === condition
    && r.epochIndex === epochIndex && r.accrualId === accrualId) || null;
const hasUnencodable = (read, epochIndex, accrualId) =>
  findAccrualDeclaration(read, epochIndex, accrualId, "transfer-unencodable") !== null;
const unconsumedReservationRebuild = (read, epochIndex, accrualId, gen) => {
  const decided = read.records.some((r) => r.kind === K.DECISION && r.object === "reservation"
    && r.epochIndex === epochIndex && r.accrualId === accrualId && r.gen === gen
    && r.action === "rebuild-reservation");
  const nextOpened = read.records.some((r) => r.kind === K.WRITE_AHEAD && r.object === "reservation"
    && r.epochIndex === epochIndex && r.accrualId === accrualId && r.gen === gen + 1);
  return decided && !nextOpened;
};

/**
 * STEP 3 for ONE positive accrual, in the frozen order, with the frozen
 * lock discipline: BOTH identity locks acquired up front in canonical
 * order (as independent handles so the explicit handoff can release the
 * income lock alone), held from before any build through preflight, both
 * write-aheads, the reservation's completion, the transfer broadcast and
 * the awaited result; after the receipt capture is journaled and the
 * income frontier advanced, the INCOME lock releases and the
 * RECORD-WRITER lock remains held through the part and receipt document
 * writes. A persisted transition is never rebuilt; recovery follows the
 * durable-state rules; there is NO automatic rebroadcast (a repeated
 * transfer sent-marker needs the operator's journaled
 * rebroadcast-identical decision, which this function never appends).
 *
 * THE CLASSIFICATION PREFLIGHT (a soundness-review finding) runs for an accrual with
 * no journaled transfer records, on the row alone, before any build,
 * nonce read, write-ahead or reservation, in the pinned validation's own
 * order: a SELF-SHARE (owner IS the income identity) is settled without
 * a transfer at any amount, and a positive entitlement below the pinned
 * minimum is carried into the member's next-epoch effective entitlement;
 * each appends its accrual-scoped declaration once per subject and the
 * accrual never reaches the transfer machinery. An accrual with
 * journaled transfer state is NOT reclassified: its recovery follows the
 * durable-state rules unchanged. THE JOURNAL CANNOT PROVE such state
 * predates the correction: a conforming corrected writer never creates
 * it (classification precedes construction), so a store containing a
 * transfer write-ahead for a row that now classifies excluded is either
 * pre-correction or non-conforming, indistinguishable from the journal
 * alone, a stated limitation.
 *
 * Statuses: "self-share-settled", "below-minimum-carried",
 * "unencodable-stopped", "reservation-refused",
 * "reservation-unresolved-pending", "reservation-foreign-pending",
 * "wait-only-observation", "receipt-observed", "transfer-refused",
 * "transfer-unresolved-pending", "completed" (capture + parts + receipt
 * document all present or written), "documents-pending" (capture done,
 * some document write stalled), "stopped".
 */
const runTransferStep = async ({ poolId, dir, deps, run, epochIndex, accrualId }) => {
  requirePool(poolId);
  await requireGateAdmission(deps, "runTransferStep");
  const need = ["entitlementsForEpoch", "buildTransferTransition", "buildReservationTransition",
    "reservationDocumentIdOf", "buildReceiptCapture", "fetchReservation", "observeReceipt",
    "broadcastAndAwait", "awaitResult", "receiptPayloads"];
  for (const k of need) if (typeof (deps && deps[k]) !== "function") refuse(`runTransferStep needs deps.${k}`);
  if (!Number.isSafeInteger(deps.transferBytesBound) || deps.transferBytesBound < 1) {
    refuse("runTransferStep needs deps.transferBytesBound (the D3 transitionBytes bound)");
  }
  if (!deps.documents) refuse("runTransferStep needs deps.documents");
  // the classification preflight compares the row's owner against the
  // income identity, so a malformed identities member is a refusal here,
  // never a silent misclassification into the payable path
  if (!deps.identities || !HEX64.test(deps.identities.writer || "") || !HEX64.test(deps.identities.income || "")) {
    refuse("runTransferStep needs deps.identities ({ writer, income } hex)");
  }
  requireIncomeBinding(deps, poolId, "runTransferStep");

  envStore.acquireOpLock(poolRunLockName(poolId));
  try {
    let read = openValidatedJournal(poolId, dir);
    requireRunToken(run, poolId, read);
    const allRows = deps.entitlementsForEpoch(epochIndex);
    validateEntitlementRows(allRows, deps.identities.income);
    const row = allRows.find((x) => x.accrualId === accrualId);
    if (!row || BigInt(row.amountCredits) <= 0n) refuse("runTransferStep runs only for a positive entitlement row");

    // the step's full lock set, canonical order, independent handles for
    // the explicit handoff
    const sorted = [deps.identities.writer, deps.identities.income]
      .filter((v, i, a) => a.indexOf(v) === i)
      .sort((a, b) => Buffer.compare(Buffer.from(a, "hex"), Buffer.from(b, "hex")));
    // independent handles for the handoff, with the shared contract's
    // unwind: a refused later acquisition releases every earlier handle
    // before the error propagates (the checker's F5: a partial set must
    // never stay held)
    const handles = new Map();
    try {
      for (const id of sorted) handles.set(id, acquireIdentityLocks([id]));
    } catch (e) {
      // the unwind SWALLOWS release failures DELIBERATELY (recorded for
      // the closing wave's first outside family): the primary
      // acquisition error is the one the operator must see, and a
      // secondary release failure surfaces on the next acquisition of
      // that lock rather than masking the cause here
      for (const h of [...handles.values()].reverse()) { try { h.release(); } catch { /* unwind */ } }
      throw e;
    }
    const writerHandle = handles.get(deps.identities.writer);
    const incomeHandle = handles.get(deps.identities.income);
    let incomeReleased = false;
    const releaseIncome = () => {
      if (!incomeReleased && incomeHandle !== writerHandle) { incomeHandle.release(); }
      incomeReleased = true;
    };
    try {
      const acc = (read.perEpoch[epochIndex] && read.perEpoch[epochIndex].accruals[accrualId]) || {};
      const tRecs = accrualRecordsOf(read, epochIndex, accrualId, "transfer");
      const tW = tRecs.find((r) => r.kind === K.WRITE_AHEAD);
      const tS = tRecs.some((r) => r.kind === K.SENT_MARKER);
      if ((acc.transfer && acc.transfer.stopped) || (acc.reservation && acc.reservation.stopped)) {
        return { status: "stopped", accrualId };
      }
      if (acc.transfer && acc.transfer.state === "refused") {
        return { status: "transfer-refused", accrualId,
          note: "transfer-refused stands (stop is the only action)" };
      }

      // ---- the observation loop, when this branch is an observer ----
      if (acc.observedByBranch) return { status: "receipt-observed", accrualId };
      const watchOpen = tRecs.some((r) => r.kind === K.OBSERVATION && r.observationType === "watch-open");
      if (watchOpen) {
        const seen = await deps.observeReceipt(poolId, epochIndex, accrualId, tW.transitionHash);
        if (seen && seen.found === true) {
          appendChecked(poolId, dir, { v: 1, kind: K.OBSERVATION, object: "transfer", gen: 1,
            poolId, epochIndex, accrualId, observationType: "receipt-observed",
            route: "documents-byTransition", observedDocumentId: seen.documentId });
          return { status: "receipt-observed", accrualId };
        }
        return { status: "wait-only-observation", accrualId };
      }

      // ---- (e)/(f) resume: the capture already exists. A torn
      // capture-then-frontier pair repairs here idempotently (max-monotone)
      // before the handoff, the transfer-side twin of the header repair ----
      if (acc.receiptCaptured) {
        const cap = read.records.find((r) => r.kind === RECEIPT_KIND
          && r.epochIndex === epochIndex && r.accrualId === accrualId);
        if (cap) {
          advanceFrontierFromCapture({ kind: RECEIPT_KIND, height: BigInt(cap.inclusionHeight),
            identities: deps.identities }, { dir, locks: incomeHandle });
        }
        return await finishDocuments({ poolId, dir, deps, epochIndex, accrualId, read,
          releaseIncome, writerHandle, incomeHandle });
      }

      // ---- (a) honor a journaled classification or refusal, else
      // classify and build. A DECLARATION NEVER SUBSTITUTES FOR THE ROW
      // (of this unit's checker): the classification is
      // REDERIVED from the current row and compared with the journaled
      // record, so a declaration that does not describe this accrual
      // refuses instead of silently suppressing a payable transfer ----
      const rowClass = classifyEntitlement(row, deps.identities.income);
      const selfDecl = findAccrualDeclaration(read, epochIndex, accrualId, "self-share-settled");
      if (selfDecl) {
        if (rowClass !== "self-share"
          || selfDecl.amountCredits !== String(BigInt(row.amountCredits))) {
          refuse("the journaled self-share-settled declaration disagrees with the recomputed row (owner or amount)");
        }
        return { status: "self-share-settled", accrualId };
      }
      const minDecl = findAccrualDeclaration(read, epochIndex, accrualId, "transfer-below-minimum");
      if (minDecl) {
        // the TWO-VALUE comparison (the decided migration rule): the
        // declaration's amount must equal the current EFFECTIVE
        // entitlement or the current OWED-ONLY amount (effective minus
        // the row's carry-in, the value a pre-carry calculation
        // produced); payability is rederived first, so a declaration
        // over a payable row still refuses outright, and with zero
        // carry-in the two values coincide
        const effectiveStr = String(BigInt(row.amountCredits));
        const owedOnlyStr = String(BigInt(row.amountCredits) - BigInt(row.carryInCredits || "0"));
        if (rowClass !== "below-minimum"
          || (minDecl.amountCredits !== effectiveStr && minDecl.amountCredits !== owedOnlyStr)) {
          refuse("the journaled transfer-below-minimum declaration disagrees with the recomputed row (neither the effective nor the owed-only amount)");
        }
        return { status: "below-minimum-carried", accrualId };
      }
      if (hasUnencodable(read, epochIndex, accrualId)) {
        return { status: "unencodable-stopped", accrualId };
      }
      let transferBytes, transferHash;
      if (tW) {
        transferBytes = tW.transitionBytes; transferHash = tW.transitionHash; // never rebuilt
      } else {
        // ---- the classification preflight (a soundness-review finding): before any
        // build, nonce read, write-ahead or reservation, on the row
        // alone, self-share FIRST (the pinned validation's own order).
        // An accrual with journaled transfer state never reaches here
        // (the tW branch above), so pre-correction subjects keep their
        // recovery semantics unchanged. The row was validated at the
        // step's entry and classified once above.
        const amount = BigInt(row.amountCredits);
        if (rowClass === "self-share") {
          appendChecked(poolId, dir, { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1,
            poolId, epochIndex, accrualId, condition: "self-share-settled",
            reasoning: "the owner is the pool's income identity; settled without a transfer (a soundness-review finding)",
            amountCredits: String(amount) });
          return { status: "self-share-settled", accrualId };
        }
        if (rowClass === "below-minimum") {
          appendChecked(poolId, dir, { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1,
            poolId, epochIndex, accrualId, condition: "transfer-below-minimum",
            reasoning: "the effective entitlement is below the pinned minimum; carried to the next epoch (a soundness-review finding)",
            amountCredits: String(amount),
            minimumCredits: String(MIN_TRANSFER_AMOUNT_CREDITS) });
          return { status: "below-minimum-carried", accrualId };
        }
        const built = deps.buildTransferTransition({ poolId, epochIndex, accrualId,
          amountCredits: row.amountCredits, recipientId: row.recipientId });
        const byteLen = built.transitionBytes.length / 2;
        if (byteLen > deps.transferBytesBound) {
          // the ONE run-side declaration: durable, BEFORE any write-ahead
          // or reservation, at most once per subject (checked above), the
          // accrual stopping unsent
          appendChecked(poolId, dir, { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1,
            poolId, epochIndex, accrualId, condition: "transfer-unencodable",
            reasoning: "preflight bound violation", field: "transitionBytes",
            observedLength: byteLen, bound: deps.transferBytesBound });
          return { status: "unencodable-stopped", accrualId };
        }
        // ---- (b) the transfer write-ahead ----
        appendChecked(poolId, dir, { v: 1, kind: K.WRITE_AHEAD, object: "transfer", gen: 1,
          poolId, epochIndex, accrualId, transitionBytes: built.transitionBytes,
          transitionHash: built.transitionHash });
        transferBytes = built.transitionBytes; transferHash = built.transitionHash;
        read = openValidatedJournal(poolId, dir);
      }

      // ---- (c) the reservation claim ----
      const resState = (read.perEpoch[epochIndex].accruals[accrualId] || {}).reservation;
      let gen = resState ? resState.gen : 1;
      if (resState && resState.state === "refused") {
        if (unconsumedReservationRebuild(read, epochIndex, accrualId, gen)) gen += 1;
        else return { status: "reservation-refused", accrualId };
      }
      const rRecs = accrualRecordsOf(read, epochIndex, accrualId, "reservation")
        .filter((r) => r.gen === gen);
      const holderJ = rRecs.some((r) => r.kind === K.RESERVATION_SUCCESS);
      if (!holderJ) {
        let rW = rRecs.find((r) => r.kind === K.WRITE_AHEAD);
        const rS = rRecs.some((r) => r.kind === K.SENT_MARKER);
        let resResult;
        if (rW && rS && resendAuthorized(poolId, dir, { object: "reservation", epochIndex, accrualId, gen })) {
          // the operator's journaled resend of the reservation's PERSISTED bytes
          appendChecked(poolId, dir, { v: 1, kind: K.SENT_MARKER, object: "reservation", gen,
            poolId, epochIndex, accrualId, transitionHash: rW.transitionHash });
          resResult = await resendAndAwait(deps, rW.transitionHash, rW.transitionBytes);
        } else if (rW && rS) {
          // ambiguous reservation outcome: wait-only on ITS persisted hash
          resResult = await deps.awaitResult(rW.transitionHash);
        } else {
          if (!rW) {
            const rBuilt = deps.buildReservationTransition({ poolId, epochIndex, accrualId,
              boundTransferHash: transferHash });
            appendChecked(poolId, dir, { v: 1, kind: K.WRITE_AHEAD, object: "reservation", gen,
              poolId, epochIndex, accrualId, transitionBytes: rBuilt.transitionBytes,
              transitionHash: rBuilt.transitionHash, boundTransferHash: transferHash });
            rW = { transitionBytes: rBuilt.transitionBytes, transitionHash: rBuilt.transitionHash };
          }
          appendChecked(poolId, dir, { v: 1, kind: K.SENT_MARKER, object: "reservation", gen,
            poolId, epochIndex, accrualId, transitionHash: rW.transitionHash });
          resResult = await deps.broadcastAndAwait(rW.transitionHash, rW.transitionBytes);
        }
        const rToken = classifyOutcome(resResult, deps._uniqueIdentityForTest);
        if (rToken === TOKENS.SUCCESS) {
          // THE IDENTIFIER IS ASKED FOR BEFORE THE RECORD IS WRITTEN, and an answer that is not
          // found stops this accrual with a named condition instead of ending the run (a soundness-review finding).
          // The wait-only route above builds nothing, so the old call, which read state set at
          // build time, threw here on every resume and the pool could never settle.
          const resDocId = await deps.reservationDocumentIdOf({ poolId, epochIndex, accrualId });
          if (!resDocId || resDocId.found !== true) {
            return { status: "reservation-unresolved-pending", accrualId,
              note: `the reservation transition succeeded and its document could not be identified (${(resDocId && resDocId.reason) || "the adapter returned no answer"}); no reservation success is recorded, and a later pass can resume IF the read becomes answerable and this accrual's transfer nonce has not since been consumed by another row` };
          }
          appendChecked(poolId, dir, { v: 1, kind: K.RESERVATION_SUCCESS, object: "reservation",
            gen, poolId, epochIndex, accrualId, transitionHash: rW.transitionHash,
            boundTransferHash: transferHash,
            reservationDocumentId: resDocId.documentId });
        } else if (rToken === TOKENS.UNIQUE) {
          // a claim already exists; any on-ledger reservation whose success
          // this branch's journal does not contain is NOT its authority
          const q = await deps.fetchReservation(poolId, epochIndex, accrualId);
          if (!(q && q.found === true)) {
            // the stale-read rule: a duplicate refusal beside a proved
            // absence establishes nothing; wait-only, never foreign
            return { status: "reservation-unresolved-pending", accrualId,
              note: "duplicate refusal with a proved absence; wait-only re-fetch next pass" };
          }
          if (q.boundTransferHash === transferHash) {
            // identical bytes or a lost earlier attempt: WAIT-ONLY
            // observation of the transfer hash (whether identical bytes
            // submitted twice execute once is duty D6's open question)
            appendChecked(poolId, dir, { v: 1, kind: K.OBSERVATION, object: "transfer", gen: 1,
              poolId, epochIndex, accrualId, observationType: "watch-open",
              route: "documents-byTransition", targetTransitionHash: transferHash });
            return { status: "wait-only-observation", accrualId };
          }
          // a differing claim is the foreign condition, evidence journaled
          appendChecked(poolId, dir, { v: 1, kind: K.OBSERVATION, object: "reservation", gen,
            poolId, epochIndex, accrualId, observationType: "foreign-claim",
            route: "documents-byPoolEpoch", targetTransitionHash: rW.transitionHash,
            observedBoundTransferHash: q.boundTransferHash });
          return { status: "reservation-foreign-pending", accrualId,
            note: "reservation-foreign is the operator condition (its foreign-claim evidence is journaled)" };
        } else if (rToken === TOKENS.OTHER) {
          appendChecked(poolId, dir, { v: 1, kind: K.ERROR, object: "reservation", gen, poolId,
            epochIndex, accrualId, code: Number.isSafeInteger(resResult && resResult.code) ? resResult.code : 0,
            data: typeof (resResult && resResult.data) === "string" ? resResult.data : "",
            message: String((resResult && resResult.message) || "execution refusal"),
            errorClass: "execution-refusal" });
          return { status: "reservation-refused", accrualId };
        } else {
          return { status: "reservation-unresolved-pending", accrualId,
            note: "wait-only on the reservation's persisted hash; reservation-unresolved is the operator condition after patience" };
        }
      }

      // ---- (d) the transfer send, from a HOLDER branch only ----
      let transferResult;
      if (!tS) {
        appendChecked(poolId, dir, { v: 1, kind: K.SENT_MARKER, object: "transfer", gen: 1,
          poolId, epochIndex, accrualId, transitionHash: transferHash });
        transferResult = await deps.broadcastAndAwait(transferHash, transferBytes);
      } else if (resendAuthorized(poolId, dir, { object: "transfer", epochIndex, accrualId, gen: 1 })) {
        // marker set, no capture, and the operator journaled a resend: THE PERSISTED BYTES again,
        // never rebuilt, which duty D6 makes at-most-once in execution
        appendChecked(poolId, dir, { v: 1, kind: K.SENT_MARKER, object: "transfer", gen: 1,
          poolId, epochIndex, accrualId, transitionHash: transferHash });
        transferResult = await resendAndAwait(deps, transferHash, transferBytes);
      } else {
        // marker set, no capture, no licensed resend: wait-only on the persisted hash
        transferResult = await deps.awaitResult(transferHash);
      }
      const tToken = classifyOutcome(transferResult, deps._uniqueIdentityForTest);
      if (tToken === TOKENS.OTHER) {
        appendChecked(poolId, dir, { v: 1, kind: K.ERROR, object: "transfer", gen: 1, poolId,
          epochIndex, accrualId, code: Number.isSafeInteger(transferResult && transferResult.code) ? transferResult.code : 0,
          data: typeof (transferResult && transferResult.data) === "string" ? transferResult.data : "",
          message: String((transferResult && transferResult.message) || "execution refusal"),
          errorClass: "execution-refusal" });
        return { status: "transfer-refused", accrualId };
      }
      if (tToken !== TOKENS.SUCCESS) {
        return { status: "transfer-unresolved-pending", accrualId,
          note: "wait-only on the persisted hash; transfer-unresolved is the operator condition after patience" };
      }

      // ---- (e) the verified response journaled BEFORE any receipt write,
      // the income frontier advanced, then the explicit lock handoff ----
      const tWnow = accrualRecordsOf(openValidatedJournal(poolId, dir), epochIndex, accrualId, "transfer")
        .find((r) => r.kind === K.WRITE_AHEAD);
      const capture = await deps.buildReceiptCapture({ poolId, epochIndex, accrualId,
        writeAhead: tWnow, result: transferResult }); // async-capable, like the header capture builder
      if (!capture || capture.kind !== RECEIPT_KIND) refuse("deps.buildReceiptCapture must return the signed receipt-capture record");
      appendChecked(poolId, dir, capture);
      advanceFrontierFromCapture({ kind: RECEIPT_KIND, height: BigInt(capture.inclusionHeight),
        identities: deps.identities }, { dir, locks: incomeHandle });
      return await finishDocuments({ poolId, dir, deps, epochIndex, accrualId,
        read: openValidatedJournal(poolId, dir), releaseIncome, writerHandle, incomeHandle });
    } finally {
      releaseIncome();
      writerHandle.release();
    }
  } finally { envStore.releaseOpLock(poolRunLockName(poolId)); }
};

// (f): the INCOME lock releases first (the explicit handoff), the
// RECORD-WRITER lock stays held through the nonce-bearing part and receipt
// writes, PART DOCUMENTS FIRST, THE RECEIPT LAST
const finishDocuments = async ({ poolId, dir, deps, epochIndex, accrualId, releaseIncome, writerHandle }) => {
  releaseIncome();
  const { parts, receipt } = deps.receiptPayloads(epochIndex, accrualId);
  if (!Array.isArray(parts) || !receipt) refuse("deps.receiptPayloads must return { parts, receipt }");
  // the frozen split: proofPartCount COUNTS the receipt's own first chunk,
  // so the part documents are exactly 1..proofPartCount-1 (the fold
  // re-check's F2: an unchecked array admitted extras outside the
  // contiguous set)
  if (!Number.isSafeInteger(receipt.proofPartCount) || receipt.proofPartCount < 1 || receipt.proofPartCount > 8) {
    refuse("the receipt payload's proofPartCount must be an integer 1..8");
  }
  if (parts.length !== receipt.proofPartCount - 1) {
    refuse(`the parts array (${parts.length}) must be exactly proofPartCount-1 (${receipt.proofPartCount - 1}); the receipt carries the first chunk`);
  }
  const statuses = [];
  for (let i = 0; i < parts.length; i++) {
    const partIndex = i + 1; // the frozen schema's parts are 1-based (the
    // receipt document itself carries the first chunk; partIndex is 1..7)
    const r = await documentWriteOnce({ poolId, dir, deps, object: "part", epochIndex,
      accrualId, partIndex, expected: parts[i] });
    statuses.push({ part: partIndex, ...r });
    if (r.status !== "present" && r.status !== "written") {
      return { status: "documents-pending", accrualId, statuses };
    }
  }
  const rr = await documentWriteOnce({ poolId, dir, deps, object: "receipt", epochIndex,
    accrualId, expected: receipt });
  statuses.push({ receipt: true, ...rr });
  if (rr.status !== "present" && rr.status !== "written") {
    return { status: "documents-pending", accrualId, statuses };
  }
  return { status: "completed", accrualId, statuses };
};

/**
 * THE CONSECUTIVE RUN A POOL'S JOURNAL EVIDENCES, for a caller that must recompute that
 * pool's effective entitlements. The carry recursion needs a consecutive run from the
 * configured start, and a pool's journal is the record of what the writer COMMITTED per
 * epoch, so its journaled headers are where a run can be read from without asking the
 * chain anything.
 *
 * WHY THIS EXISTS AT ALL: the store-wide admission asks a per-pool resolver about whatever
 * epochs each journal happens to hold, one at a time, which is not a run. A resolver
 * answering those from a PRE-CARRY split under-reserves the income identity's funding once
 * any pool's run passes one epoch, because the admission sums those amounts. This is the
 * shape a resolver needs to answer them correctly instead.
 *
 * Returns [{ number, distributableCredits }] ascending from the configured start, or an
 * EMPTY array when the journal evidences no header numbers at all (a pool whose first
 * header has not been written is not an error, it is a pool with nothing to recompute).
 *
 * IT REFUSES ON A GAP rather than skipping it. An epoch missing from the middle of the run
 * is an epoch whose owed amounts never entered the carry, so every later epoch's effective
 * amount would be computed from a carry-in that is short by exactly that epoch's
 * contribution, and the answer would look ordinary.
 */
const runFromJournal = (read) => {
  const start = read.configuredStartEpoch;
  const numbersAt = (n) => {
    const e = read.perEpoch[n];
    if (!e || !e.header || e.header.grossCredits === null || e.header.grossCredits === undefined) return null;
    if (e.header.feeCredits === null || e.header.feeCredits === undefined) return null;
    return { gross: BigInt(e.header.grossCredits), fee: BigInt(e.header.feeCredits),
      allocationHash: e.header.allocationHash, memberCount: e.header.memberCount };
  };
  // AN EMPTY RUN IS AN ANSWER ABOUT THE EVIDENCE, so it is not given without looking at
  // it. With no configured start there is no base for the recursion, and returning empty
  // over a journal that DOES carry header numbers would report "nothing to recompute"
  // about a pool that has plenty, which is the affirmative-result-from-an-unperformed-check
  // shape. Empty is reserved for a journal evidencing no header numbers at all.
  if (!Number.isSafeInteger(start)) {
    const evidenced = Object.keys(read.perEpoch)
      .map(Number).filter((k) => Number.isSafeInteger(k) && numbersAt(k) !== null);
    if (evidenced.length) {
      refuse(`the journal evidences header numbers for epoch ${Math.min(...evidenced)} but binds no configured start, so the carry recursion has no base and no run can be read from it`);
    }
    return [];
  }
  const out = [];
  for (let n = start; ; n++) {
    const num = numbersAt(n);
    if (num === null) {
      // the run ENDS here, and that is only conformant if nothing above it is journaled.
      // A later epoch carrying header numbers over a hole means the hole's owed amounts
      // never entered the carry, and every epoch above it would be recomputed short.
      const higher = Object.keys(read.perEpoch)
        .map(Number).filter((k) => Number.isSafeInteger(k) && k > n && numbersAt(k) !== null);
      if (higher.length) {
        refuse(`the journal evidences epoch ${Math.min(...higher)} but not epoch ${n}; the carry recursion needs a consecutive run from the configured start ${start}, and the missing epoch's owed amounts would be absent from every later epoch's carry-in`);
      }
      break;
    }
    if (num.fee > num.gross) {
      refuse(`epoch ${n}'s journaled header has feeCredits ${num.fee} above grossCredits ${num.gross}; the distributable amount would be negative`);
    }
    // THE RUN MUST NOT SPAN AN ALLOCATION CHANGE. A caller recomputes the whole run under
    // ONE allocation, the pool's current one, so a run whose journaled headers disagree
    // about the allocation hash or the member count would apply today's membership to an
    // epoch that was written under different membership, and the carry threaded through it
    // would be one member's claim credited to another. The single-epoch width used to make
    // this unrepresentable; a run makes it representable, so it is refused by name rather
    // than left to be noticed. Supporting such a transition needs per-epoch allocations,
    // which is a larger change than reading a run.
    if (out.length) {
      const first = out[0];
      if (num.allocationHash !== first.allocationHash || num.memberCount !== first.memberCount) {
        refuse(`epoch ${n}'s journaled header carries a different allocation than epoch ${first.number}'s (hash ${String(num.allocationHash).slice(0, 12)}... memberCount ${num.memberCount} against ${String(first.allocationHash).slice(0, 12)}... and ${first.memberCount}); one allocation is applied to a whole run, so a run spanning a change would recompute an epoch under membership it was not written under`);
      }
    }
    out.push({ number: n, distributableCredits: String(num.gross - num.fee),
      allocationHash: num.allocationHash, memberCount: num.memberCount,
      grossCredits: String(num.gross), feeCredits: String(num.fee) });
  }
  return out;
};

module.exports = { setStart, startRun, runHeaderStep, runAccrualStep, runTransferStep,
  startKeyOf, poolRunLockName, appendChecked, MIN_TRANSFER_AMOUNT_CREDITS,
  classifyEntitlement, runFromJournal };

// the literal CLI configuration mode
if (require.main === module) {
  const [mode, poolId, epoch] = process.argv.slice(2);
  if (mode === "set-start") {
    const r = setStart(poolId, epoch, {});
    console.log(`configured start for pool ${r.poolId.slice(0, 12)}... set to epoch ${r.startEpoch}`);
  } else {
    console.error("usage: e2Distribute.cjs set-start <poolId hex> <epoch>");
    process.exitCode = 2;
  }
}
