// The deployed per-epoch loop, driven offline, plus its restart matrix (milestone 2's integrated
// unit, closing the review's second finding).
//
// WHY THIS EXISTS. A review replaced the loop's completion condition with one that always
// continues and watched both named suites pass. The decisions had been moved into a module, but
// nothing drove the loop that USES their answers, so a source sweep recognizing the call was the
// only instrument. These cases drive the real loop with injected steps and watch what it decides.
//
// WHAT IS STOOD IN FOR, and what is not. The STEPS are fakes with the real call shapes, because
// the real ones write journals and talk to a ledger. Everything the loop itself owns is real:
// which epoch is worked, whether the writer's epoch agrees with the bundle, what a header result
// permits, whether an epoch is recorded complete, and where the run stops.
const fs = require("fs");
const path = require("path");
const { runEpochLoop } = require("./e2DistributeEpochLoop.cjs");
const { runnerSource, skipNote } = require("./runnerSource.cjs");
let passed = 0, failed = 0, skipped = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error("FAIL:", name, "(resolved)"); }
  catch (e) { ok(name, re.test(String(e.message))); }
};
/** An assertion whose expression may itself throw. AN UNEXPECTED THROW IS A RECORDED FAILURE,
 *  not a crash that ends the process before the summary line: a fault that kills the run reads
 *  to any harness as a detection while observing nothing. */
const okTry = (name, fn) => {
  try { ok(name, fn()); }
  catch (e) { failed++; console.error(`FAIL: ${name} threw unexpectedly: ${(e && e.message) || String(e)}`); }
};
/** The async form, for a driven RUN rather than an expression. Its own first canary earned it:
 *  removing the store's torn-tail truncation made the second run's first append refuse, which
 *  ended the process at the call site with no summary line and every later assertion unrun. A
 *  harness that dies on the defect it was built to observe reports nothing. */
const runTry = async (name, fn) => {
  try { return { ok: true, value: await fn() }; }
  catch (e) { failed++; console.error(`FAIL: ${name} threw unexpectedly: ${(e && e.message) || String(e)}`); return { ok: false, value: null }; }
};

const WRITER = "7d".repeat(32);
const noLog = () => {};

// one context per epoch, carrying only what the loop reads
const ctxFor = (n, rows) => ({ epochIndex: n, rows, figures: { grossCredits: String(1000 * (n + 1)) } });
const rowsOf = (n, count = 2) => Array.from({ length: count }, (_, i) => ({
  accrualId: `acc-${n}-${i}`, amountCredits: "500000", recipientId: `r${i}`, funderHex: `f${i}` }));

// the dependency factory's shape as the driver supplies it: a bundle plus the nonce readers and
// the reservation reset. It RECORDS which epoch it was built for and which completed record it
// was handed, because both are what the loop is supposed to get right.
const mkFactory = () => {
  const built = [];
  return { built, epochDepsFor: (ctx, completedEpochs) => {
    built.push({ epoch: ctx.epochIndex, completedAtBuild: [...completedEpochs] });
    return { deps: { forEpoch: ctx.epochIndex }, prefetched: {},
      contractNonce: async () => 1n, identityNonce: async () => 1n, clearLastReservation: () => {} };
  } };
};

// the steps, with the real call shapes. `plan` says what each call answers, keyed by epoch.
const mkSteps = (plan) => {
  const calls = [];
  return { calls, steps: {
    runHeaderStep: async ({ epochIndex, ...rest }) => {
      const n = plan.headerEpochFor ? plan.headerEpochFor(calls) : plan.nextHeaderEpoch();
      calls.push({ step: "header", epoch: n, deps: rest.deps && rest.deps.forEpoch });
      return plan.header ? plan.header(n) : { status: "header-done-transfers-pending", epochIndex: n };
    },
    runAccrualStep: async ({ epochIndex, deps }) => {
      calls.push({ step: "accrual", epoch: epochIndex, deps: deps && deps.forEpoch });
      return plan.accrual ? plan.accrual(epochIndex)
        : { statuses: rowsOf(epochIndex).map((r) => ({ accrualId: r.accrualId, status: "written" })) };
    },
    runTransferStep: async ({ epochIndex, accrualId, deps }) => {
      calls.push({ step: "transfer", epoch: epochIndex, accrualId, deps: deps && deps.forEpoch });
      return plan.transfer ? plan.transfer(epochIndex, accrualId) : { status: "completed", accrualId };
    },
  } };
};

const runOver = async (epochs, plan = {}, over = {}) => {
  const { built, epochDepsFor } = mkFactory();
  const { calls, steps } = mkSteps({ nextHeaderEpoch: (() => { let i = 0; return () => epochs[i++]; })(), ...plan });
  const result = await runEpochLoop({
    runEpochs: epochs, contextFor: (n) => ctxFor(n, rowsOf(n)), epochDepsFor, steps,
    poolId: "aa".repeat(32), dir: undefined, run: { measurementSeq: 1 }, bootstrap: false,
    classifyEntitlement: () => "payable", writerHex: WRITER, log: noLog, ...over });
  return { result, calls, built };
};

(async () => {
  { // THE POSITIVE CONTROL: two epochs, each worked with its OWN bundle, both recorded complete
    const { result, calls, built } = await runOver([0, 1]);
    ok("both epochs are worked in ascending order",
      JSON.stringify(built.map((b) => b.epoch)) === JSON.stringify([0, 1]));
    ok("each step receives the bundle built for the epoch it is working",
      calls.every((c) => c.deps === c.epoch));
    ok("both epochs are recorded complete", [...result.completedEpochs].sort().join(",") === "0,1");
    ok("the run neither stopped nor refused", result.stoppedEarly === null && result.refusal === null);
    ok("every outcome carries the epoch it belongs to",
      result.outcomes.length === 4 && result.outcomes.every((o) => [0, 1].includes(o.epochIndex)));
    // THE SECOND EPOCH'S BUNDLE IS BUILT AFTER THE FIRST IS RECORDED, which is what lets the
    // writer pick it: the lifecycle answer reads that record.
    ok("the second epoch's bundle is built with the first already recorded complete",
      JSON.stringify(built[0].completedAtBuild) === JSON.stringify([])
        && JSON.stringify(built[1].completedAtBuild) === JSON.stringify([0]));
  }
  { // THE REVIEW'S OWN CASE. An epoch whose transfers are covered but NOT terminal must not be
    // recorded complete, and the run must stop rather than attempting the epoch above it.
    const { result, calls } = await runOver([0, 1], {
      transfer: (n, accrualId) => ({ status: n === 0 ? "refused" : "completed", accrualId }) });
    ok("an epoch with a nonterminal outcome is NOT recorded complete", result.completedEpochs.size === 0);
    ok("the run stops at that epoch", result.stoppedEarly !== null && result.stoppedEarly.epochNumber === 0);
    // this is the assertion the surviving mutation breaks: ignoring the completion answer lets
    // the loop carry on to the next epoch over an unfinished one
    ok("the epoch ABOVE it is never worked", !calls.some((c) => c.epoch === 1));
  }
  { // the writer working an epoch other than the bundle's is a REFUSAL, not a stop
    const { result, calls } = await runOver([0, 1], { header: () => ({ status: "header-done-transfers-pending", epochIndex: 0 }) });
    ok("a disagreement between the writer's epoch and the bundle's refuses the run",
      typeof result.refusal === "string" && /figures under another's identity/.test(result.refusal));
    ok("epoch 0 still completed before the disagreement was reached", result.completedEpochs.has(0));
    ok("nothing past the header was attempted for the disagreeing epoch",
      !calls.some((c) => c.epoch === 1 && c.step !== "header"));
  }
  { // no incomplete epoch left FINISHES rather than failing
    const { result } = await runOver([0, 1], { header: (n) => (n === 0
      ? { status: "header-done-transfers-pending", epochIndex: 0 }
      : { status: "already-complete", epochIndex: null }) });
    ok("the writer reporting nothing left stops the run without a refusal",
      result.refusal === null && result.stoppedEarly !== null && result.stoppedEarly.status === "already-complete");
  }
  { // a header status short of the transfer stage stops the run
    const { result, calls } = await runOver([0, 1], { header: (n) => ({ status: "stopped", epochIndex: n }) });
    ok("a stopped header stops the run at its own epoch",
      result.stoppedEarly !== null && result.stoppedEarly.at === "header" && result.completedEpochs.size === 0);
    ok("no accrual step runs after a stopped header", !calls.some((c) => c.step === "accrual"));
  }
  { // an incomplete accrual set stops the run
    const { result, calls } = await runOver([0, 1], {
      accrual: (n) => ({ statuses: [{ accrualId: `acc-${n}-0`, status: "written" }, { accrualId: `acc-${n}-1`, status: "absent" }] }) });
    ok("an incomplete accrual set stops the run at that epoch",
      result.stoppedEarly !== null && result.stoppedEarly.at === "accruals");
    ok("no transfer runs after an incomplete accrual set", !calls.some((c) => c.step === "transfer"));
  }
  { // a one-epoch run behaves as it always did
    const { result } = await runOver([4]);
    ok("a one-epoch run completes and records its epoch",
      result.completedEpochs.has(4) && result.stoppedEarly === null && result.refusal === null);
  }
  { // a row owing nothing is skipped rather than transferred
    const { result, calls } = await runOver([0], {}, {
      contextFor: (n) => ctxFor(n, [{ accrualId: `acc-${n}-0`, amountCredits: "0", recipientId: "r0" }]) });
    ok("a zero-amount row drives no transfer", !calls.some((c) => c.step === "transfer"));
    ok("the epoch still completes, owing nobody", result.completedEpochs.has(0));
  }

  // ---- THE RESTART MATRIX, PART ONE: THE LOOP ----
  // For each point at which a run can stop, the loop must stop with a NAMED record and leave the
  // epochs above unworked, and a second run over the same state must then complete. The steps are
  // fakes here, so what THIS half establishes is the LOOP's behaviour across an interruption.
  // Part two below drives the same three boundaries over a REAL journal and covers its recovery.
  const BOUNDARIES = [
    { name: "at the header", plan: { header: (n) => (n === 1 ? { status: "stopped", epochIndex: n } : { status: "header-done-transfers-pending", epochIndex: n }) }, at: "header" },
    { name: "at the accrual set", plan: { accrual: (n) => (n === 1
        ? { statuses: [{ accrualId: `acc-${n}-0`, status: "absent" }] }
        : { statuses: rowsOf(n).map((r) => ({ accrualId: r.accrualId, status: "written" })) }) }, at: "accruals" },
    { name: "at a transfer", plan: { transfer: (n, accrualId) => ({ status: n === 1 ? "refused" : "completed", accrualId }) }, at: "transfers" },
  ];
  for (const b of BOUNDARIES) {
    const first = await runOver([0, 1], b.plan);
    ok(`interrupted ${b.name}: the run stops with a named record at epoch 1`,
      first.result.stoppedEarly !== null && first.result.stoppedEarly.at === b.at
        && first.result.stoppedEarly.epochNumber === 1);
    ok(`interrupted ${b.name}: the epoch below it is still recorded complete`,
      first.result.completedEpochs.has(0) && !first.result.completedEpochs.has(1));
    ok(`interrupted ${b.name}: no outcome is recorded for an epoch above the stop`,
      !first.result.outcomes.some((o) => o.epochIndex > 1));
    // THE SECOND RUN, over a state where epoch 0's work is already done. The steps answer
    // "present" for what exists, which is what the real ones do on a resume.
    const second = await runOver([0, 1], {
      accrual: (n) => ({ statuses: rowsOf(n).map((r) => ({ accrualId: r.accrualId, status: n === 0 ? "present" : "written" })) }),
      transfer: (n, accrualId) => ({ status: "completed", accrualId }) });
    ok(`interrupted ${b.name}: a second run completes both epochs`,
      second.result.stoppedEarly === null && second.result.refusal === null
        && [...second.result.completedEpochs].sort().join(",") === "0,1");
  }

  // ---- THE RESTART MATRIX, PART TWO: THE JOURNAL'S OWN RECOVERY ----
  //
  // WHAT THIS ADDS. Part one's steps touch no storage, so it establishes that the LOOP stops and
  // resumes, and says nothing about whether the journal underneath survives the same interruption.
  // That gap was stated rather than closed, and journal-level resume was shown at ONE boundary by
  // a live run. Here the steps append REAL records through the frozen storage contract, the run is
  // interrupted at each of the same three boundaries, a real fault shape is injected into the
  // journal at that point, and a SECOND run resumes over whatever the store recovers.
  //
  // THE FAULT SHAPES ARE THE STORE'S OWN CLASSES, injected by performing the earlier durable
  // actions' file effects and not the later ones, which is how the append transaction's crash
  // matrix is exercised elsewhere. The consequence asserted is not a byte count: it is that the
  // record the interrupted write would have licensed is ABSENT after recovery, that every
  // recovered record equals what its step was told to write, and that the finished journal holds
  // exactly the record set a complete run owes.
  //
  // THE WIDTH OF THE NON-REPETITION CLAIM, stated because a review measured it. "The second run
  // did not repeat a committed step" is checked through RECORD KEYS: no key appears twice, and the
  // final set is exactly the expected one. A step that repeated its external work without
  // journaling a second record would still be invisible to this matrix. What is established is a
  // property of the JOURNAL, not of the steps' side effects.
  {
    const os = require("os");
    const jstore = require("./e2JournalStore.cjs");
    const { canonicalString } = require("./canonicalJson.cjs");
    const JPOOL = "ab".repeat(32);

    // steps that journal what they do, and READ the journal to decide present-versus-written,
    // which is what makes the second run a resume rather than a repeat.
    //
    // EVERY STEP USES THE POOL IT IS HANDED, never a closed-over one. The first version closed
    // over JPOOL, so a review could pass a wrong pool into the loop's step calls and watch all
    // twelve combinations pass. A fake that ignores an argument cannot notice the caller getting
    // that argument wrong, which is the same defect as a fixture that ignores its query.
    const mkJournalSteps = (dir, plan) => {
      const state = { offset: jstore.openJournal(JPOOL, dir).committedOffset };
      const has = (poolId, pred) => jstore.openJournal(poolId, dir).records.some(pred);
      const put = (poolId, r) => { state.offset = jstore.appendRecord(poolId, state.offset, r, dir); };
      const mk = (poolId, object, epochIndex, accrualId) => ({ v: 1, kind: "probe", object, gen: 1,
        poolId, epochIndex, ...(accrualId ? { accrualId } : {}) });
      return { state, steps: {
        runHeaderStep: async ({ poolId }) => {
          const n = plan.nextHeaderEpoch();
          if (plan.stopAt === "header" && n === 1) return { status: "stopped", epochIndex: n };
          if (!has(poolId, (r) => r.object === "header" && r.epochIndex === n)) put(poolId, mk(poolId, "header", n));
          return { status: "header-done-transfers-pending", epochIndex: n };
        },
        runAccrualStep: async ({ poolId, epochIndex }) => {
          if (plan.stopAt === "accruals" && epochIndex === 1) {
            return { statuses: [{ accrualId: `acc-${epochIndex}-0`, status: "absent" }] };
          }
          return { statuses: rowsOf(epochIndex).map((r) => {
            const present = has(poolId, (x) => x.object === "accrual" && x.accrualId === r.accrualId);
            if (!present) put(poolId, mk(poolId, "accrual", epochIndex, r.accrualId));
            return { accrualId: r.accrualId, status: present ? "present" : "written" };
          }) };
        },
        runTransferStep: async ({ poolId, epochIndex, accrualId }) => {
          if (plan.stopAt === "transfers" && epochIndex === 1) return { status: "refused", accrualId };
          if (!has(poolId, (r) => r.object === "transfer" && r.accrualId === accrualId)) {
            put(poolId, mk(poolId, "transfer", epochIndex, accrualId));
          }
          return { status: "completed", accrualId };
        },
      } };
    };
    // THE COMPLETE RECORD SET a finished run must hold: one header per epoch, plus one accrual and
    // one transfer per row. Asserting this, rather than uniqueness and growth, is what notices an
    // append that silently wrote nothing. A review made appendRecord return the old offset without
    // writing, and the matrix reported both epochs complete over nine records instead of ten.
    const keyOf = (r) => `${r.object}:${r.epochIndex}:${r.accrualId || ""}`;

    // ---- THE WRITTEN EXPECTATION TABLE ----
    // NO EXPECTATION IN THIS MATRIX MAY BE READ BACK FROM THE JOURNAL IT JUDGES. Three review
    // occasions found the same class one level further back each time: fakes that discarded their
    // arguments, then a comparison of two readings by the same decoder, then an oracle whose
    // record identity came from `keyOf(r)` on the very record under test, which accepted a decoded
    // epoch incremented by a hundred. Each repair moved the derivation back without removing it.
    // So the expectation is WRITTEN DOWN here, from the plan the steps are given, and everything
    // else is built from the table. An assertion that consults a record to decide what that record
    // should say cannot be written against this without deleting the table first.
    //
    // WHAT EACH BOUNDARY OWES AT ITS INTERRUPTION, read off the step plan and not off any run:
    // the header step writes nothing for epoch 1 when it stops there, the accrual step writes
    // nothing for epoch 1 when it stops there (its header is already down), and the transfer step
    // writes nothing for epoch 1 when it stops there (its header and accruals are already down).
    const epochKeys = (n, parts) => {
      const k = [];
      if (parts.includes("header")) k.push(`header:${n}:`);
      if (parts.includes("accruals")) for (const r of rowsOf(n)) k.push(`accrual:${n}:${r.accrualId}`);
      if (parts.includes("transfers")) for (const r of rowsOf(n)) k.push(`transfer:${n}:${r.accrualId}`);
      return k;
    };
    const EPOCH0_COMPLETE = epochKeys(0, ["header", "accruals", "transfers"]);
    const EXPECTED_AT_BOUNDARY = {
      header: [...EPOCH0_COMPLETE].sort(),
      accruals: [...EPOCH0_COMPLETE, ...epochKeys(1, ["header"])].sort(),
      transfers: [...EPOCH0_COMPLETE, ...epochKeys(1, ["header", "accruals"])].sort(),
    };
    const EXPECTED_KEYS = [...EPOCH0_COMPLETE,
      ...epochKeys(1, ["header", "accruals", "transfers"])].sort();
    // the record each WRITTEN-DOWN key stands for, built from the key in the table rather than
    // from anything the store returned
    const expectedRecordForKey = (key) => {
      const [object, epochIndex, accrualId] = key.split(":");
      return { v: 1, kind: "probe", object, gen: 1, poolId: JPOOL,
        epochIndex: Number(epochIndex), ...(accrualId ? { accrualId } : {}) };
    };
    // THE WHOLE COMPARISON runs over the table: the records the store returns must be exactly the
    // canonical forms of the table's entries, in sorted order. A record whose identity the decoder
    // altered no longer matches any table entry, which is the case the previous oracle missed.
    const journalMatchesTable = (recs, keys) => {
      const got = recs.map((r) => canonicalString(r)).sort();
      const want = keys.map((k) => canonicalString(expectedRecordForKey(k))).sort();
      return JSON.stringify(got) === JSON.stringify(want);
    };
    const runJournaled = async (dir, stopAt) => {
      const { epochDepsFor } = mkFactory();
      const { steps } = mkJournalSteps(dir, {
        nextHeaderEpoch: (() => { let i = 0; return () => [0, 1][i++]; })(), stopAt });
      return runEpochLoop({ runEpochs: [0, 1], contextFor: (n) => ctxFor(n, rowsOf(n)), epochDepsFor,
        steps, poolId: JPOOL, dir, run: { measurementSeq: 1 }, bootstrap: false,
        classifyEntitlement: () => "payable", writerHex: WRITER, log: noLog });
    };

    // the injections, each returning a label for the assertion text
    const FAULTS = [
      { name: "a clean stop", inject: () => {} },
      { name: "a FULL frame written past the committed offset, its boundary never moved",
        inject: (dir) => {
          // the record an interrupted write would have licensed: a transfer for epoch 1 that
          // never happened. If the tail is not truncated, the second run reads it as done.
          const frame = jstore.encodeFrame({ v: 1, kind: "probe", object: "transfer", gen: 1,
            poolId: JPOOL, epochIndex: 1, accrualId: "acc-1-0" });
          fs.appendFileSync(jstore.journalPath(JPOOL, dir), frame);
        },
        absent: (recs) => !recs.some((r) => r.object === "transfer" && r.accrualId === "acc-1-0" && r.epochIndex === 1) },
      { name: "a PARTIAL frame past the committed offset",
        inject: (dir) => { fs.appendFileSync(jstore.journalPath(JPOOL, dir), Buffer.from([0, 0, 1, 255, 7])); } },
      { name: "a stale temporary boundary beside the committed one",
        inject: (dir) => { fs.writeFileSync(`${jstore.boundaryPath(JPOOL, dir)}.tmp`, jstore.encodeBoundary(JPOOL, 999999)); },
        // its removal is part of the contract and nothing checked it, so the check is here
        alsoAfterRecovery: (dir) => !fs.existsSync(`${jstore.boundaryPath(JPOOL, dir)}.tmp`),
        alsoName: "the stale temporary boundary is gone after recovery" },
      // THE ONE SHAPE THAT MUST NOT RECOVER. Every fault above lies BEYOND the committed offset,
      // so none of them exercises the store's refusal on damage AT OR BEFORE it, and a review
      // removed the committed-frame checksum enforcement without the matrix noticing. Discarding
      // a committed record could erase a marker whose send already happened, so the contract is
      // to REFUSE the journal outright rather than to recover it.
      { name: "a flipped byte INSIDE a committed frame's payload", expectsRefusal: true,
        inject: (dir) => {
          const p = jstore.journalPath(JPOOL, dir);
          const buf = fs.readFileSync(p);
          buf[20] ^= 0xff; // inside the first committed frame's payload
          fs.writeFileSync(p, buf);
        } },
      // THE CHECKSUM'S OWN SHAPE. The payload corruption above is refused by whichever rule
      // reaches it first, so removing the committed-frame checksum enforcement still left it
      // refusing, through the JSON or canonical-form check, and the assertion could not tell
      // the two apart. Damaging ONLY the trailing checksum leaves a payload that parses and is
      // canonical, so the checksum rule is the sole thing standing between it and acceptance.
      { name: "a flipped byte in a committed frame's CHECKSUM alone, its payload still valid and canonical",
        expectsRefusal: true,
        inject: (dir) => {
          const p = jstore.journalPath(JPOOL, dir);
          const buf = fs.readFileSync(p);
          const len = buf.readUInt32BE(0);
          buf[4 + len] ^= 0xff; // the first byte of the first frame's 8-byte checksum
          fs.writeFileSync(p, buf);
        } },
    ];

    let resumed = 0, refusedCount = 0;
    for (const b of ["header", "accruals", "transfers"]) {
      for (const f of FAULTS) {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-epochloop-j-"));
        const r1 = await runTry(`journal restart [${b} / ${f.name}]: the first run completes without crashing`,
          () => runJournaled(dir, b));
        if (!r1.ok) { fs.rmSync(dir, { recursive: true, force: true }); continue; }
        const first = r1.value;
        ok(`journal restart [${b} / ${f.name}]: the first run stops at epoch 1 with a named record`,
          first.stoppedEarly !== null && first.stoppedEarly.epochNumber === 1
            && first.completedEpochs.has(0) && !first.completedEpochs.has(1));
        // WHAT THE STORE OWES AT THIS BOUNDARY, checked against the written table BEFORE the
        // second run exists to repair anything. The previous version took its expectation from
        // the journal here and only compared against the table after the second run, so an
        // omitted EARLIER append was silently supplied by that second run and never seen.
        const committed = jstore.openJournal(JPOOL, dir);
        const beforeCount = committed.records.length;
        const beforeOffset = committed.committedOffset;
        okTry(`journal restart [${b} / ${f.name}]: at the interruption the journal holds exactly the ${EXPECTED_AT_BOUNDARY[b].length} records this boundary owes, by the written table`,
          () => journalMatchesTable(committed.records, EXPECTED_AT_BOUNDARY[b]));
        f.inject(dir);
        // THE SHAPE THAT MUST REFUSE takes its own path and stops here: damage at or before the
        // committed offset is not recoverable by contract, so a run that continued would be the
        // defect rather than the evidence.
        if (f.expectsRefusal) {
          let refused = null;
          try { jstore.openJournal(JPOOL, dir); refused = false; }
          catch (e) { refused = /corrupt/.test(e.message) || /refusing/.test(e.message); }
          ok(`journal restart [${b} / ${f.name}]: the store REFUSES rather than recovering, because discarding a committed record could erase a marker whose send already happened`,
            refused === true);
          if (refused === true) refusedCount++;
          fs.rmSync(dir, { recursive: true, force: true });
          continue;
        }
        // (a) the store recovers at the OLD commit; nothing uncommitted survives, and the
        // committed records come back with the CONTENT they were written with
        const recovered = jstore.openJournal(JPOOL, dir);
        okTry(`journal restart [${b} / ${f.name}]: the store recovers at the committed offset, and returns exactly the written table's records for this boundary, so a decoder that alters an identity matches no entry`,
          () => recovered.committedOffset === beforeOffset && recovered.records.length === beforeCount
            && journalMatchesTable(recovered.records, EXPECTED_AT_BOUNDARY[b]));
        if (f.absent) {
          okTry(`journal restart [${b} / ${f.name}]: the record the interrupted write would have licensed is ABSENT after recovery`,
            () => f.absent(recovered.records));
        }
        if (f.alsoAfterRecovery) {
          okTry(`journal restart [${b} / ${f.name}]: ${f.alsoName}`, () => f.alsoAfterRecovery(dir));
        }
        // (b) a second run resumes over the recovered journal and finishes both epochs.
        // IT IS DRIVEN THROUGH runTry because a store that failed to recover makes this run's
        // FIRST APPEND refuse, and an unguarded call there ends the process before any verdict.
        const r2 = await runTry(`journal restart [${b} / ${f.name}]: the second run reaches a verdict rather than dying on the fault`,
          () => runJournaled(dir, null));
        if (!r2.ok) { fs.rmSync(dir, { recursive: true, force: true }); continue; }
        const second = r2.value;
        ok(`journal restart [${b} / ${f.name}]: a second run over the recovered journal completes both epochs`,
          second.stoppedEarly === null && second.refusal === null
            && [...second.completedEpochs].sort().join(",") === "0,1");
        // (c) it RESUMED rather than repeated: epoch 0's committed records are not duplicated,
        // and the journal is still valid after the second run's appends
        const after = jstore.openJournal(JPOOL, dir);
        okTry(`journal restart [${b} / ${f.name}]: the second run added no duplicate record key`, () => {
          const keys = after.records.map(keyOf);
          return new Set(keys).size === keys.length;
        });
        // THE COMPLETE SET, not merely uniqueness and growth. Those two together are satisfied by
        // a run that finished short, which is exactly what a silently-writing-nothing append
        // produces. WIDTH, stated: this pins the RECORD SET. A step that repeated its external
        // work without journaling a second record would still be invisible here.
        okTry(`journal restart [${b} / ${f.name}]: the finished journal holds exactly the ${EXPECTED_KEYS.length} records a complete run owes, each equal to the written table's entry for it`,
          () => JSON.stringify(after.records.map(keyOf).sort()) === JSON.stringify(EXPECTED_KEYS)
            && journalMatchesTable(after.records, EXPECTED_KEYS));
        okTry(`journal restart [${b} / ${f.name}]: the journal is still valid and grew past the fault`,
          () => after.committedOffset > beforeOffset && after.records.length > beforeCount);
        resumed++;
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }
    // THE TALLY IS COUNTED, NOT ASSERTED IN A SENTENCE. The first draft of this line printed
    // "12 runs, each interrupted, recovered and resumed" from a fixed string, and a canary that
    // broke the store's torn-tail truncation left six of those combinations failing while the
    // line went on claiming all twelve had resumed. A report that cannot be wrong about its own
    // work is not reporting it.
    const RECOVERABLE = FAULTS.filter((f) => !f.expectsRefusal).length * 3;
    const UNRECOVERABLE = FAULTS.filter((f) => f.expectsRefusal).length * 3;
    console.log(`  [journal restart matrix] 3 loop boundaries x ${FAULTS.length} fault shapes = ${3 * FAULTS.length} combinations; ${resumed} of ${RECOVERABLE} recovered and resumed to a verdict, ${refusedCount} of ${UNRECOVERABLE} refused as damage at or before the commit must`);
    ok(`every recoverable combination reached a resumed verdict (${resumed} of ${RECOVERABLE})`, resumed === RECOVERABLE);
    ok(`every unrecoverable combination refused instead (${refusedCount} of ${UNRECOVERABLE})`, refusedCount === UNRECOVERABLE);
  }

  // ---- the loop's own required inputs ----
  await rejects("a loop with no epochs refuses", runOver([]), /needs the run's epochs/);
  await rejects("a loop with no step set refuses",
    runOver([0], {}, { steps: { runHeaderStep: async () => ({}) } }), /needs steps\.runAccrualStep/);
  await rejects("a loop with no writer identity refuses",
    runOver([0], {}, { writerHex: "nope" }), /needs the writer identity/);
  await rejects("a loop with no log sink refuses", runOver([0], {}, { log: null }), /needs an explicit log function/);
  await rejects("a loop with no classifier refuses", runOver([0], {}, { classifyEntitlement: null }), /needs classifyEntitlement/);

  // ---- THE RUNNER BINDING SWEEP ----
  {
    const src = runnerSource("e2DistributeRun.mjs");
    if (src === null) { skipped += 1; console.log(skipNote("e2DistributeRun.mjs", "the runner-binding sweep")); } else {
    ok("the runner drives the shared loop rather than writing its own",
      /epochLoop\.runEpochLoop\(\{/.test(src));
    ok("the runner keeps no inline epoch loop", !/for \(const epochNumber of RUN_EPOCHS\)/.test(src));
    ok("the runner hands the loop the real step functions",
      /runHeaderStep: distribute\.runHeaderStep/.test(src)
        && /runAccrualStep: distribute\.runAccrualStep/.test(src)
        && /runTransferStep: distribute\.runTransferStep/.test(src));
    ok("the runner stops the whole run on a loop refusal",
      /if \(loopResult\.refusal\) \{ process\.exitCode = 2; return; \}/.test(src));
    // THE FACTORY MOVED OUT of the runner, so this sweep no longer looks for an inline
    // definition. What it binds now is that the runner builds the factory from the extracted
    // module and hands it to the loop. The PROPERTY the old line was standing in for, that the
    // factory takes the run's completed record rather than closing over its own, is no longer a
    // matter of spelling: `e2DistributeEpochDepsTest.cjs` drives the real factory, refuses a
    // bundle built without that record, and catches a mutation that answers complete regardless.
    ok("the runner builds its dependency factory from the extracted module",
      /const epochDepsFor = epochDeps\.makeEpochDepsFactory\(\{/.test(src)
        && !/const epochDepsFor = \(ctx, completedEpochs\) =>/.test(src));
    }
  }

  console.log(`e2DistributeEpochLoopTest: ${passed} passed, ${failed} failed` + (skipped ? `, ${skipped} skipped (counted, never folded into passes)` : ""));
  process.exitCode = failed ? 1 : 0;
})();
