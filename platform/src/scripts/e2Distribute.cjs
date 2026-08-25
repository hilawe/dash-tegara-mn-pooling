/**
 * The E2 DISTRIBUTION PROCEDURE's first half: the start-epoch configuration
 * mode, the run start (discovery, the lag measurement, the a soundness-review finding binding),
 * and STEP 1, the header flow (admission under both identity locks, the
 * write-ahead, the committed sent-marker before any broadcast, the outcome
 * classification, the capture, and the recovery rules).
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
 * against the real journal, store and admission. Steps 2 through 4 (the
 * accrual documents and the reservation-transfer-receipt sequence) are the
 * unit's second half and are not in this file yet.
 *
 * OPERATOR CONDITIONS (patience expiry, stops, rebuild decisions) are
 * journaled by the OPERATOR through the D7 record kinds; this module
 * returns statuses naming the condition that has become available and
 * never appends a surfacing or decision itself; it DOES append the
 * evidence records the machinery defines (the measurement, write-aheads,
 * markers, error records, captures, and the foreign-document observation
 * that establishes the duplicate path's conditions). The one exception
 * class the spec assigns to the run, the encoding-preflight declarations,
 * belongs to the transfer steps in the second half.
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
const { validateJournal, openValidatedJournal, K, PROVED_HEADER_ROUTE } = require("./e2Journal.cjs");
const { openJournal, appendRecord } = require("./e2JournalStore.cjs");
const { discoverFinalizedEpochs } = require("./e2Discovery.cjs");
const { classifyOutcome, TOKENS } = require("./e2Outcome.cjs");
const { admitHeader, acquireIdentityLocks, advanceFrontierFromCapture } = require("./e2BalanceCheck.cjs");
const { HEADER_KIND, RECEIPT_KIND } = require("./e2CaptureRecord.cjs");

const HEX64 = /^[0-9a-f]{64}$/;
const DEC_U32 = /^(0|[1-9][0-9]*)$/;
const U32_MAX = 4294967295;

const refuse = (why) => { throw new Error(`e2Distribute: ${why}; refusing`); };

const poolRunLockName = (poolId) => `e2-pool-${poolId}`;
const startKeyOf = (poolId) => `E2_START_EPOCH_${poolId.toUpperCase()}`;

const requirePool = (poolId) => {
  if (typeof poolId !== "string" || !HEX64.test(poolId)) refuse("poolId must be 64 lowercase hex characters");
  return poolId;
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
// journal supplies only the outstanding-amount SUM (positive entitlements
// without a receipt capture, at full value).
const journalOutstandingSum = (read, epochIndex, rows) => {
  const e = read.perEpoch[epochIndex];
  let out = 0n;
  for (const r of rows) {
    if (BigInt(r.amountCredits) <= 0n) continue;
    const a = e && e.accruals[r.accrualId];
    if (!(a && a.receiptCaptured)) out += BigInt(r.amountCredits);
  }
  return out;
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
    for (const ep of universe) {
      const rows = deps.entitlementsForEpoch(ep.number);
      if (!Array.isArray(rows)) refuse(`deps.entitlementsForEpoch returned no rows for epoch ${ep.number}`);
      if (deps.epochDistributionComplete(ep.number) !== true) {
        lag += 1;
        undistributed += journalOutstandingSum(read, ep.number, rows);
      }
    }

    appendChecked(poolId, dir, { v: 1, kind: K.DECLARATION, object: "pool", gen: 1, poolId,
      condition: "lag-measurement", reasoning: "run start", lagCount: lag,
      undistributedCredits: String(undistributed),
      ...(read.records.length === 0 ? { configuredStartEpoch: configuredStart } : {}) });

    return { configuredStart, universe, lag, undistributedCredits: String(undistributed),
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
    if (deps.epochDistributionComplete(ep.number) !== true) return ep.number;
  }
  return null;
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
      // marker set: WAIT-ONLY on the persisted hash, never a resend; the
      // recovered result goes through the SAME outcome table as an
      // initial await (a refusal journals its error, a duplicate refusal
      // runs the proved-equality gate, ambiguity stays wait-only)
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
      feeCeilingCredits: deps.feeCeilingCredits, chainIdPin: deps.chainIdPin, locks });

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

const journalHeaderCapture = ({ poolId, dir, deps, epochIndex, gen, W, expectedContents, result, locks }) => {
  const capture = deps.buildHeaderCapture({ poolId, epochIndex, gen, writeAhead: W, expectedContents, result });
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
// transitions never rebuilt, operator conditions never appended (the one
// run-side declaration the spec assigns, transfer-unencodable, is
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
      const statuses = [];
      for (const row of rows) {
        const r = await documentWriteOnce({ poolId, dir, deps, object: "accrual", epochIndex,
          accrualId: row.accrualId, expected: deps.accrualPayload(epochIndex, row) });
        statuses.push({ accrualId: row.accrualId, ...r });
        if (r.status !== "present" && r.status !== "written") break; // no row advances past a stall
      }
      return { statuses };
    } finally { locks.release(); }
  } finally { envStore.releaseOpLock(poolRunLockName(poolId)); }
};

// subject-state helpers over the read result
const accrualRecordsOf = (read, epochIndex, accrualId, object) =>
  read.records.filter((r) => r.object === object && r.epochIndex === epochIndex && r.accrualId === accrualId);
const hasUnencodable = (read, epochIndex, accrualId) =>
  read.records.some((r) => r.kind === K.DECLARATION && r.condition === "transfer-unencodable"
    && r.epochIndex === epochIndex && r.accrualId === accrualId);
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
 * Statuses: "unencodable-stopped", "reservation-refused",
 * "reservation-unresolved-pending", "reservation-foreign-pending",
 * "wait-only-observation", "receipt-observed", "transfer-refused",
 * "transfer-unresolved-pending", "completed" (capture + parts + receipt
 * document all present or written), "documents-pending" (capture done,
 * some document write stalled), "stopped".
 */
const runTransferStep = async ({ poolId, dir, deps, run, epochIndex, accrualId }) => {
  requirePool(poolId);
  const need = ["entitlementsForEpoch", "buildTransferTransition", "buildReservationTransition",
    "reservationDocumentIdOf", "buildReceiptCapture", "fetchReservation", "observeReceipt",
    "broadcastAndAwait", "awaitResult", "receiptPayloads"];
  for (const k of need) if (typeof (deps && deps[k]) !== "function") refuse(`runTransferStep needs deps.${k}`);
  if (!Number.isSafeInteger(deps.transferBytesBound) || deps.transferBytesBound < 1) {
    refuse("runTransferStep needs deps.transferBytesBound (the D3 transitionBytes bound)");
  }
  if (!deps.documents) refuse("runTransferStep needs deps.documents");

  envStore.acquireOpLock(poolRunLockName(poolId));
  try {
    let read = openValidatedJournal(poolId, dir);
    requireRunToken(run, poolId, read);
    const row = deps.entitlementsForEpoch(epochIndex).find((x) => x.accrualId === accrualId);
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

      // ---- (a) build and preflight, or honor the journaled refusal ----
      if (hasUnencodable(read, epochIndex, accrualId)) {
        return { status: "unencodable-stopped", accrualId };
      }
      let transferBytes, transferHash;
      if (tW) {
        transferBytes = tW.transitionBytes; transferHash = tW.transitionHash; // never rebuilt
      } else {
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
        if (rW && rS) {
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
          appendChecked(poolId, dir, { v: 1, kind: K.RESERVATION_SUCCESS, object: "reservation",
            gen, poolId, epochIndex, accrualId, transitionHash: rW.transitionHash,
            boundTransferHash: transferHash,
            reservationDocumentId: deps.reservationDocumentIdOf(resResult) });
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
      } else {
        // marker set, no capture: wait-only on the persisted hash, never a
        // resend (the rebroadcast needs the operator's journaled decision)
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
      const capture = deps.buildReceiptCapture({ poolId, epochIndex, accrualId,
        writeAhead: tWnow, result: transferResult });
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

module.exports = { setStart, startRun, runHeaderStep, runAccrualStep, runTransferStep,
  startKeyOf, poolRunLockName, appendChecked };

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
