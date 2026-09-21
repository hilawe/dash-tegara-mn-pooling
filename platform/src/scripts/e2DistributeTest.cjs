/**
 * The distribution procedure's battery, both halves: the set-start
 * configuration mode (mutability boundary, serialization lock), the run
 * start (binding resolution, disagreement refusal, the lag measurement on
 * every run, the derived lagging condition), and the step-1 header flow
 * (admission under the locks, write-ahead then committed sent-marker then
 * broadcast, outcome handling, capture and frontier, and every recovery
 * rule). Drives the REAL journal, store, admission, locks and classifier;
 * the MOCKED surfaces are the deps contract in full (discovery responses,
 * entitlement rows, epoch numbers, the lifecycle completion answer,
 * transition and capture construction, balances, broadcast and proved
 * queries, and the pool resolver), and the mocks ASSERT the ordering
 * invariants: the broadcast
 * and await mocks require both identity lock directories on disk, the
 * broadcast mock requires its committed sent-marker as the last record
 * AND that the sent bytes equal the journaled write-ahead's, and the
 * builder mock requires the held locks. Outcome fixtures are the
 * classifier's own CLOSED shapes, checked against the real classifier
 * before use.
 *
 * THE MUTATION LIST WAS WRITTEN BEFORE THESE TESTS (the playbook rule);
 * the commit message records it.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-e2dist-"));
process.env.TEGARA_ENV_PATH = path.join(TMP, "env.local");

const envStore = require("./envStore.cjs");
const { STATE_DIR } = envStore;
const { openJournal, appendRecord } = require("./e2JournalStore.cjs");
const { openValidatedJournal, K } = require("./e2Journal.cjs");
const { HEADER_KIND } = require("./e2CaptureRecord.cjs");
const { readFrontier, acquireIdentityLocks, identityLockName } = require("./e2BalanceCheck.cjs");
const { classifyOutcome, TOKENS } = require("./e2Outcome.cjs");
const { setStart, startRun, runHeaderStep, runAccrualStep, runTransferStep,
  startKeyOf, poolRunLockName, appendChecked, classifyEntitlement,
  runFromJournal } = require("./e2Distribute.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) { passed++; } else { failed++; console.error("FAIL:", name); } };
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
/** An assertion whose expression may itself throw. AN UNEXPECTED THROW IS A RECORDED
 *  FAILURE, not a crash that ends the process before the summary line: a mutation that
 *  kills the run reads to any harness as a detection while observing nothing. */
const okTry = (name, fn) => {
  try { ok(name, fn()); }
  catch (e) { failed++; console.error(`FAIL: ${name} threw unexpectedly: ${(e && e.message) || String(e)}`); }
};

// pair the env file with its state directory (the mount guard)
fs.writeFileSync(process.env.TEGARA_ENV_PATH,
  "MNEMONIC=m\nSTATE_MIGRATED=1\nSTATE_STORE_ID=00112233aabbccdd\n");
fs.mkdirSync(STATE_DIR, { recursive: true });
fs.writeFileSync(path.join(STATE_DIR, "store.id"), "00112233aabbccdd");

// ---- fixtures ----
const CHAIN = "tegara-test-1";
const W = "11".repeat(32), I = "ee".repeat(32);
const h32 = (f) => f.repeat(64 / f.length);
const A1 = h32("a1"), A2 = h32("a2"), B6 = h32("b6");
const sha = (hex) => crypto.createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");
const caseDir = () => fs.mkdtempSync(path.join(TMP, "case-"));
let poolSeq = 0;
const freshPool = () => {
  poolSeq += 1; // the configured-start key is store-global, so each case gets its own pool
  return "ab".repeat(16) + String(poolSeq).padStart(32, "0").replace(/[^0-9]/g, "0");
};

const hBytes = (epoch, gen = 1) => "0102" + String(epoch).padStart(4, "0") + String(gen).padStart(2, "0");
const numbersOf = () => ({ grossCredits: 1000, feeCredits: 10,
  allocationHash: h32("ee"), memberCount: 2, calcVersion: 1 });

// the classifier's own closed result shapes, PROBED against the real
// classifier so the fixtures cannot drift from its contract
const SUCCESS_RESULT = { outcome: "verified-proof", proof: { p: 1 }, metadata: { height: "1000" },
  proofMsg: "aa", metadataMsg: "bb", unknownFieldsDropped: 0 };
const REFUSAL_RESULT = { outcome: "execution-refusal", code: 7, data: "00", message: "node refusal" };
const AMBIGUOUS_RESULT = { outcome: "transport-failure", reason: "timeout" };
if (classifyOutcome(SUCCESS_RESULT) !== TOKENS.SUCCESS
  || classifyOutcome(REFUSAL_RESULT) !== TOKENS.OTHER
  || classifyOutcome(AMBIGUOUS_RESULT) !== TOKENS.AMBIGUOUS) {
  throw new Error("outcome fixtures no longer match the classifier's contract");
}
// the duplicate-refusal token needs the pinned identity, unpinned in
// production; the governed seam supplies ONLY the identity argument (the
// closed-shape validation always runs), exactly the e2Outcome precedent
const UNIQUE_ID = { code: 7, dataMatches: () => true };

const mkCapture = ({ poolId, epochIndex, gen, writeAhead }) => ({ v: 1, kind: HEADER_KIND,
  object: "header", gen, poolId, epochIndex, transitionBytes: writeAhead.transitionBytes,
  transitionHash: writeAhead.transitionHash, proofMsg: "aa".repeat(20), metadataMsg: "bb".repeat(10),
  contractId: h32("cc"), expectedDocumentId: writeAhead.expectedDocumentId,
  expectedContents: writeAhead.expectedContents, inclusionHeight: "1500",
  heightRoute: "tenderdash-tx", signerIdentity: h32("f0"), signerKeyId: 2, sig: "00".repeat(65) });

const mkDeps = (poolId, dir, over = {}) => {
  const calls = { broadcast: [], await: [], build: [], proved: [], fetch: [], docWrites: [] };
  const ledger = over.ledger || new Map();
  const docKey = (object, key) => [object, key.epochIndex, key.accrualId ?? "", key.partIndex ?? ""].join("|");
  const depsLedger = { ledger, docKey };
  const universeTop = over.universeTop ?? 5;
  // fixture amounts sit ABOVE the pinned MIN_TRANSFER_AMOUNT (100000
  // credits, a soundness-review finding): a below-minimum row would classify as carried and
  // never reach the transfer machinery these cases exercise; the
  // classification's own cases below use sub-minimum amounts deliberately
  const rowsFor = over.rowsFor || ((epoch) => (epoch === 5
    ? [{ accrualId: A1, amountCredits: "1000000", recipientId: h32("71") },
       { accrualId: A2, amountCredits: "500000", recipientId: h32("72") }]
    : [{ accrualId: B6, amountCredits: "700000", recipientId: h32("73") }]));
  const complete = over.complete || (() => false);
  const deps = {
    identities: { writer: W, income: I },
    // the canonical-gate consult, stubbed ADMITTED for the flows these cases
    // exercise (the gate's own refusal cases override it explicitly below);
    // the strict lookup's real behaviour is e2CaptureBatteryTest's subject
    verifyGateCapture: over.verifyGateCapture || (async () => ({ admitted: true })),
    feeCeilings: over.feeCeilings ?? { header: "100", accrual: "100", reservation: "100",
      receipt: "100", part: "100", creditTransfer: "100" },
    chainIdPin: CHAIN,
    discoveryOpts: { width: 8 },
    epochDistributionComplete: (epoch) => complete(epoch),
    ...(over.unique ? { _uniqueIdentityForTest: UNIQUE_ID } : {}),
    fetchRange: async (start, end) => {
      const epochs = [];
      for (let n = start; n <= Math.min(end, universeTop); n++) epochs.push({ number: n });
      return { epochs, proved: true };
    },
    entitlementsForEpoch: rowsFor,
    epochNumbers: () => numbersOf(),
    resolvePool: () => ({ resolved: true, writerIdentity: W, incomeIdentity: I,
      entitlementsForEpoch: (epoch) => rowsFor(epoch) }),
    fetchBalanceWithMetadata: async (id) => {
      calls.fetch.push(id);
      if (over.balance === "throw") throw new Error("verification failed");
      return { balance: over.balance ?? "999999999",
        metadata: { chainId: CHAIN, protocolVersion: 12, height: "1000" } };
    },
    buildHeaderTransition: ({ epochIndex }) => {
      calls.build.push(epochIndex);
      // the build consumes a nonce, so it runs under BOTH held locks: the
      // mock asserts the lock directories exist on disk
      for (const id of [W, I]) {
        if (!fs.existsSync(path.join(STATE_DIR, `oplock-${identityLockName(id)}`))) {
          throw new Error(`buildHeaderTransition called without the held lock of ${id.slice(0, 4)}`);
        }
      }
      const bytes = hBytes(epochIndex, over.gen ?? 1);
      return { transitionBytes: bytes, transitionHash: sha(bytes), expectedDocumentId: h32("dd") };
    },
    broadcastAndAwait: async (hash, bytes) => {
      calls.broadcast.push({ hash, bytes });
      // the broadcast is inside the operation's lock window: both identity
      // lock directories AND the per-pool run lock must be held on disk
      // (the step is serialized against startRun and set-start throughout)
      for (const id of [W, I]) {
        if (!fs.existsSync(path.join(STATE_DIR, `oplock-${identityLockName(id)}`))) {
          throw new Error(`broadcastAndAwait called without the held lock of ${id.slice(0, 4)}`);
        }
      }
      if (!fs.existsSync(path.join(STATE_DIR, `oplock-${poolRunLockName(poolId)}`))) {
        throw new Error("broadcastAndAwait outside the held per-pool run lock");
      }
      // NO BROADCAST BEFORE ITS COMMITTED SENT-MARKER, and the bytes sent
      // must be the JOURNALED write-ahead's for this hash (a broadcast of
      // anything but the persisted bytes is the violation)
      const { records } = openJournal(poolId, dir);
      const last = records[records.length - 1];
      if (!(last && last.kind === K.SENT_MARKER && last.transitionHash === hash)) {
        throw new Error("broadcast before its committed sent-marker (ordering violation)");
      }
      const W_ = records.find((r) => r.kind === K.WRITE_AHEAD && r.transitionHash === hash);
      if (!W_ || W_.transitionBytes !== bytes) {
        throw new Error("broadcast bytes differ from the journaled write-ahead's (persisted-bytes violation)");
      }
      return (over.outcome || (() => SUCCESS_RESULT))(hash, bytes);
    },
    awaitResult: async (hash) => {
      calls.await.push(hash);
      // wait-only recovery is the same outstanding operation: both locks held
      for (const id of [W, I]) {
        if (!fs.existsSync(path.join(STATE_DIR, `oplock-${identityLockName(id)}`))) {
          throw new Error(`awaitResult called without the held lock of ${id.slice(0, 4)}`);
        }
      }
      return (over.awaitOutcome || (() => AMBIGUOUS_RESULT))(hash);
    },
    provedHeaderQuery: async (p, epochIndex) => {
      calls.proved.push(epochIndex);
      return (over.provedQuery || (() => ({ found: false })))(p, epochIndex);
    },
    buildHeaderCapture: over.buildHeaderCapture || mkCapture,
    // ---- the second half's surface ----
    transferBytesBound: over.transferBytesBound ?? 100,
    buildTransferTransition: ({ epochIndex, accrualId }) => {
      calls.build.push(`t:${epochIndex}:${accrualId.slice(0, 4)}`);
      const bytes = over.transferBytesLong
        ? "0a".repeat((over.transferBytesBound ?? 100) + 1)
        : over.transferBytesAt
          ? "0a".repeat(over.transferBytesBound ?? 100)
          : "0a0b" + String(epochIndex).padStart(4, "0") + accrualId.slice(0, 4);
      return { transitionBytes: bytes, transitionHash: sha(bytes) };
    },
    buildReservationTransition: ({ epochIndex, accrualId }) => {
      calls.build.push(`r:${epochIndex}:${accrualId.slice(0, 4)}`);
      const bytes = "0c0d" + String(epochIndex).padStart(4, "0") + accrualId.slice(0, 4);
      return { transitionBytes: bytes, transitionHash: sha(bytes) };
    },
    reservationDocumentIdOf: () => h32("d1"),
    buildReceiptCapture: ({ poolId: p2, epochIndex, accrualId, writeAhead }) => ({ v: 1,
      kind: "tegara.e2.receiptCapture.v1", object: "transfer", gen: 1, poolId: p2, epochIndex,
      accrualId, transitionHash: writeAhead.transitionHash, transitionBytes: writeAhead.transitionBytes,
      proofMsg: "cc".repeat(20), metadataMsg: "dd".repeat(10), inclusionHeight: "1600",
      heightRoute: "tenderdash-tx", signerIdentity: h32("f0"), signerKeyId: 2, sig: "00".repeat(65) }),
    fetchReservation: async (...a) => (over.reservationOnLedger || (() => ({ found: false })))(...a),
    observeReceipt: async (...a) => (over.observe || (() => ({ found: false })))(...a),
    accrualPayload: (epochIndex, row) => ({ poolId, epochIndex, accrualId: row.accrualId,
      credits: row.amountCredits }),
    receiptPayloads: () => ({ parts: [{ p: 1 }, { p: 2 }], receipt: { r: 1, proofPartCount: 3 } }),
    documents: {
      fetch: async (object, key) => {
        const f = ledger.get(docKey(object, key));
        return f ? { found: true, fields: f } : { found: false };
      },
      write: async (object, key, payload) => {
        calls.docWrites.push({ object, partIndex: key.partIndex });
        // the document write's stated lock set: the RECORD WRITER's lock
        // held, the INCOME lock NOT held (the explicit handoff), the pool
        // lock held throughout the step
        if (!fs.existsSync(path.join(STATE_DIR, `oplock-${identityLockName(W)}`))) {
          throw new Error("document write without the held record-writer lock");
        }
        if (fs.existsSync(path.join(STATE_DIR, `oplock-${identityLockName(I)}`))) {
          throw new Error("document write while the income lock is still held (the handoff failed)");
        }
        if (!fs.existsSync(path.join(STATE_DIR, `oplock-${poolRunLockName(poolId)}`))) {
          throw new Error("document write outside the held per-pool run lock");
        }
        if (object === "receipt" || object === "part") {
          // (e) precedes (f): the receipt capture must already be
          // journaled, and the receipt document comes after every part
          const { records } = openJournal(poolId, dir);
          if (!records.some((r) => r.kind === "tegara.e2.receiptCapture.v1"
            && r.accrualId === key.accrualId)) {
            throw new Error("a receipt or part write before its journaled receipt capture");
          }
          if (object === "receipt") {
            // scoped to THIS accrual, 1-based (the frozen partIndex range)
            const partsPresent = [1, 2].every((i) => ledger.has(docKey("part", { ...key, partIndex: i })));
            if (!partsPresent) {
              throw new Error("the receipt document written before every part (parts first, receipt last)");
            }
          }
        }
        const behavior = (over.docBehavior || (() => "ok"))(object, key, calls.docWrites.length);
        if (behavior === "ok") { ledger.set(docKey(object, key), payload); return SUCCESS_RESULT; }
        if (behavior === "ok-silent") { ledger.set(docKey(object, key), payload); return REFUSAL_RESULT; }
        if (behavior === "refuse") return REFUSAL_RESULT;
        return AMBIGUOUS_RESULT;
      },
    },
    ...(over.classify ? { _classifyForTest: over.classify } : {}),
  };
  deps._calls = calls;
  deps._ledger = depsLedger;
  return deps;
};

(async () => {

// ---- the configuration mode ----
{
  const dir = caseDir();
  const pool = freshPool();
  throws("a non-canonical start epoch refuses", () => setStart(pool, "07", { dir }), /canonical decimal u32/);
  throws("an above-u32 start epoch refuses", () => setStart(pool, "4294967296", { dir }), /canonical decimal u32/);
  const r = setStart(pool, "5", { dir });
  ok("set-start writes the owned key", r.startEpoch === 5 && envStore.loadEnv()[startKeyOf(pool)] === "5");
  ok("set-start is repeatable while no journal record exists",
    setStart(pool, "6", { dir }).startEpoch === 6);
  // the first journal record ends mutability
  appendRecord(pool, openJournal(pool, dir).committedOffset, { v: 1, kind: K.DECLARATION,
    object: "pool", gen: 1, poolId: pool, condition: "lag-measurement", reasoning: "r",
    lagCount: 0, undistributedCredits: "0", configuredStartEpoch: 6 }, dir);
  throws("set-start refuses once any journal record exists (a soundness-review finding)",
    () => setStart(pool, "7", { dir }), /bound and immutable/);
}
{
  // the serialization lock: set-start and the run's first append hold the
  // SAME per-pool lock, observed through the lock mechanism itself
  const pool = freshPool();
  const dir = caseDir();
  const names = [];
  const real = envStore.acquireOpLock;
  envStore.acquireOpLock = (name) => { names.push(name); return real(name); };
  try {
    setStart(pool, "5", { dir });
    await startRun({ poolId: pool, dir, deps: mkDeps(pool, dir) });
  } finally { envStore.acquireOpLock = real; }
  const poolLocks = names.filter((n) => n === poolRunLockName(pool));
  ok("set-start and the first-append run path hold the same per-pool lock",
    poolLocks.length === 2);
}
{
  // the PROTECTED INTERVAL, not only the acquisition count: the key write
  // itself must happen while the pool lock directory is held on disk
  const pool = freshPool();
  const dir = caseDir();
  const realUpdate = envStore.updateEnvKey;
  let heldAtWrite = null;
  envStore.updateEnvKey = (k, v) => {
    if (k === startKeyOf(pool)) {
      heldAtWrite = fs.existsSync(path.join(STATE_DIR, `oplock-${poolRunLockName(pool)}`));
    }
    return realUpdate(k, v);
  };
  try { setStart(pool, "5", { dir }); } finally { envStore.updateEnvKey = realUpdate; }
  ok("set-start writes the key INSIDE the held pool lock", heldAtWrite === true);
}

// ---- the run start ----
{
  const pool = freshPool();
  const dir = caseDir();
  await rejects("a run with no configured start refuses",
    startRun({ poolId: pool, dir, deps: mkDeps(pool, dir) }), /no configured start/);
  setStart(pool, "5", { dir });
  const r = await startRun({ poolId: pool, dir, deps: mkDeps(pool, dir) });
  ok("the first run's lag and undistributed sum are the universe's outstanding amounts",
    r.configuredStart === 5 && r.lag === 1 && r.undistributedCredits === "1500000"
    && r.distributionLagging === false);
  const read = openValidatedJournal(pool, dir);
  ok("the pool's FIRST record is the lag measurement carrying the binding",
    read.records.length === 1 && read.records[0].condition === "lag-measurement"
    && read.records[0].configuredStartEpoch === 5 && read.configuredStartEpoch === 5);
  ok("the first measurement carries carriedCredits even when nothing is carried",
    r.carriedCredits === "0" && read.records[0].carriedCredits === "0");
  // a second run appends WITHOUT the binding member and agrees with it
  const r2 = await startRun({ poolId: pool, dir, deps: mkDeps(pool, dir) });
  const read2 = openValidatedJournal(pool, dir);
  ok("every run start appends a measurement, later ones without the binding member",
    r2.lag === 1 && read2.records.length === 2 && !("configuredStartEpoch" in read2.records[1]));
  // a disagreeing local key refuses once the binding is journaled
  envStore.updateEnvKey(startKeyOf(pool), "9");
  await rejects("a local configured start disagreeing with the journaled binding refuses",
    startRun({ poolId: pool, dir, deps: mkDeps(pool, dir) }), /disagrees with the journaled binding/);
  envStore.updateEnvKey(startKeyOf(pool), "5");
}
{
  // the two-epoch lagging case derives distribution-lagging (count above 1)
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const r = await startRun({ poolId: pool, dir, deps: mkDeps(pool, dir, { universeTop: 6 }) });
  ok("two lagging epochs derive distribution-lagging (never appended)",
    r.lag === 2 && r.undistributedCredits === "2200000" && r.distributionLagging === true);
  const lagRec = openValidatedJournal(pool, dir).records[0];
  ok("the measurement records the count and sum literally",
    lagRec.lagCount === 2 && lagRec.undistributedCredits === "2200000");
}
{
  // a fully complete universe measures lag ZERO and still appends (every
  // run start, zero and one included), and the header step reports done
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { complete: () => true });
  const run = await startRun({ poolId: pool, dir, deps });
  ok("a complete universe appends a lag-zero measurement",
    run.lag === 0 && run.distributionLagging === false
    && openValidatedJournal(pool, dir).records[0].lagCount === 0);
  const r = await runHeaderStep({ poolId: pool, dir, deps, run });
  ok("the header step reports a complete universe done", r.status === "already-complete");
}
{
  // COMPLETION IS NEVER INFERRED FROM THE JOURNAL: every receipt captured
  // but the injected step-5 lifecycle says incomplete, so the epoch still
  // counts lagging (the document writes after the capture are unobservable
  // in the journal)
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const seed = mkDeps(pool, dir);
  const run0 = await startRun({ poolId: pool, dir, deps: seed });
  await runHeaderStep({ poolId: pool, dir, deps: seed, run: run0 }); // header captured
  // journal the full happy accruals so every receipt is captured
  const tB = (acc) => "0a0b0005" + acc.slice(0, 4);
  const rB = (acc) => "0c0d0005" + acc.slice(0, 4);
  for (const acc of [A1, A2]) {
    appendChecked(pool, dir, { v: 1, kind: "tegara.e2.journal.writeAhead.v1", object: "transfer",
      gen: 1, poolId: pool, epochIndex: 5, accrualId: acc, transitionBytes: tB(acc), transitionHash: sha(tB(acc)) });
    appendChecked(pool, dir, { v: 1, kind: "tegara.e2.journal.writeAhead.v1", object: "reservation",
      gen: 1, poolId: pool, epochIndex: 5, accrualId: acc, transitionBytes: rB(acc),
      transitionHash: sha(rB(acc)), boundTransferHash: sha(tB(acc)) });
    appendChecked(pool, dir, { v: 1, kind: "tegara.e2.journal.sentMarker.v1", object: "reservation",
      gen: 1, poolId: pool, epochIndex: 5, accrualId: acc, transitionHash: sha(rB(acc)) });
    appendChecked(pool, dir, { v: 1, kind: "tegara.e2.journal.reservationSuccess.v1", object: "reservation",
      gen: 1, poolId: pool, epochIndex: 5, accrualId: acc, transitionHash: sha(rB(acc)),
      boundTransferHash: sha(tB(acc)), reservationDocumentId: h32("d1") });
    appendChecked(pool, dir, { v: 1, kind: "tegara.e2.journal.sentMarker.v1", object: "transfer",
      gen: 1, poolId: pool, epochIndex: 5, accrualId: acc, transitionHash: sha(tB(acc)) });
    appendChecked(pool, dir, { v: 1, kind: "tegara.e2.receiptCapture.v1", object: "transfer",
      gen: 1, poolId: pool, epochIndex: 5, accrualId: acc, transitionHash: sha(tB(acc)),
      transitionBytes: tB(acc), proofMsg: "cc".repeat(20), metadataMsg: "dd".repeat(10),
      inclusionHeight: "1001", heightRoute: "tenderdash-tx", signerIdentity: h32("f0"),
      signerKeyId: 2, sig: "00".repeat(65) });
  }
  const deps = mkDeps(pool, dir); // lifecycle still incomplete (default false)
  const run = await startRun({ poolId: pool, dir, deps });
  ok("captured receipts never infer completion: the epoch still counts lagging with a zero sum",
    run.lag === 1 && run.undistributedCredits === "0");
}
{
  // a STALE run token refuses the header step (a fresh startRun
  // invalidates every earlier run's measurement)
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir);
  const oldRun = await startRun({ poolId: pool, dir, deps });
  await startRun({ poolId: pool, dir, deps }); // a newer run's measurement
  await rejects("a header step under an old run's measurement refuses",
    runHeaderStep({ poolId: pool, dir, deps, run: oldRun }), /is not this run's/);
  // a token never crosses pools, whatever its numeric index
  const pool2 = freshPool();
  const dir2 = caseDir();
  setStart(pool2, "5", { dir: dir2 });
  const deps2 = mkDeps(pool2, dir2);
  const foreignRun = await startRun({ poolId: pool2, dir: dir2, deps: deps2 });
  await rejects("a run token from a different pool refuses whatever its index",
    runHeaderStep({ poolId: pool, dir, deps, run: foreignRun }), /names a different pool/);
}

// ---- the header flow, fresh success ----
{
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir);
  await rejects("the header step refuses before any run-start measurement",
    runHeaderStep({ poolId: pool, dir, deps }), /needs its run's token/);
  const run = await startRun({ poolId: pool, dir, deps });
  const r = await runHeaderStep({ poolId: pool, dir, deps, run });
  const read = openValidatedJournal(pool, dir);
  ok("the fresh header flow captures", r.status === "captured" && r.epochIndex === 5);
  ok("the journal carries W (with the binding member), S, then the capture",
    read.records.length === 4
    && read.records[1].kind === K.WRITE_AHEAD && read.records[1].configuredStartEpoch === 5
    && read.records[2].kind === K.SENT_MARKER
    && read.records[3].kind === HEADER_KIND
    && read.perEpoch[5].header.state === "captured");
  ok("the broadcast saw its committed sent-marker and the build ran under the locks",
    deps._calls.broadcast.length === 1 && deps._calls.build.length === 1);
  const locks = acquireIdentityLocks([W]);
  try {
    // the admission's own balance read already advanced to 1000, so only
    // the capture's higher height distinguishes the capture-path advance
    ok("the capture's verified height advanced the record writer's frontier past the admission's",
      readFrontier(W, { dir, locks }) === 1500n);
  } finally { locks.release(); }
  ok("the admission fetched each distinct identity exactly once",
    deps._calls.fetch.length === 2 && new Set(deps._calls.fetch).size === 2);
}

// ---- the admission screen inside the flow ----
{
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const low = mkDeps(pool, dir, { balance: "100" });
  const run = await startRun({ poolId: pool, dir, deps: low });
  await rejects("an insufficient reserve refuses the header before anything is journaled",
    runHeaderStep({ poolId: pool, dir, deps: low, run }), /below its reserve threshold/);
  ok("the refused attempt journaled nothing (measurement only)",
    openValidatedJournal(pool, dir).records.length === 1);
  ok("nothing was built or broadcast", low._calls.build.length === 0 && low._calls.broadcast.length === 0);
  // the funded rerun proceeds
  const funded = mkDeps(pool, dir);
  const r = await runHeaderStep({ poolId: pool, dir, deps: funded, run });
  ok("the funded rerun captures", r.status === "captured");
}

// ---- ascending selection ----
{
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { universeTop: 6 });
  const run = await startRun({ poolId: pool, dir, deps });
  const r1 = await runHeaderStep({ poolId: pool, dir, deps, run });
  ok("the run targets the FIRST undistributed epoch", r1.status === "captured" && r1.epochIndex === 5);
  // epoch 5's header is captured but its transfers are outstanding: the
  // run stays on epoch 5 (no new header while an earlier epoch is
  // incomplete), and the epoch-5 header being present yields no fresh
  // attempt, so the step reports the stall rather than skipping to 6
  const r2 = await runHeaderStep({ poolId: pool, dir, deps, run });
  ok("an incomplete earlier epoch stalls the run at itself, never skipped",
    r2.epochIndex === 5 && r2.status !== "captured");
}

// ---- outcome handling: refusal, ambiguity ----
{
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { outcome: () => REFUSAL_RESULT });
  const run = await startRun({ poolId: pool, dir, deps });
  const r = await runHeaderStep({ poolId: pool, dir, deps, run });
  const read = openValidatedJournal(pool, dir);
  ok("an execution refusal journals the structured error and stalls",
    r.status === "refused" && read.perEpoch[5].header.state === "refused"
    && read.records[read.records.length - 1].kind === K.ERROR
    && read.records[read.records.length - 1].errorClass === "execution-refusal");
  const r2 = await runHeaderStep({ poolId: pool, dir, deps, run });
  ok("a refused header stalls for the operator's journaled decision", r2.status === "refused");
  // the operator's journaled rebuild authorizes exactly one new generation
  appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "header", gen: 1, poolId: pool,
    epochIndex: 5, condition: "header-refused", reasoning: "operator" });
  appendChecked(pool, dir, { v: 1, kind: K.DECISION, object: "header", gen: 1, poolId: pool,
    epochIndex: 5, condition: "header-refused", action: "rebuild-corrected", d6Status: "open",
    reasoning: "operator" });
  const rebuilt = mkDeps(pool, dir, { gen: 2 });
  const r3 = await runHeaderStep({ poolId: pool, dir, deps: rebuilt, run });
  const read3 = openValidatedJournal(pool, dir);
  ok("the consumed rebuild decision drives a generation-2 attempt to capture",
    r3.status === "captured" && read3.perEpoch[5].header.gen === 2
    && read3.perEpoch[5].header.state === "captured");
}
{
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { outcome: () => AMBIGUOUS_RESULT });
  const run = await startRun({ poolId: pool, dir, deps });
  const before = openValidatedJournal(pool, dir).records.length;
  const r = await runHeaderStep({ poolId: pool, dir, deps, run });
  const read = openValidatedJournal(pool, dir);
  ok("an ambiguous outcome journals nothing beyond W and S (wait-only recovery)",
    r.status === "unresolved-pending" && read.records.length === before + 2
    && read.perEpoch[5].header.state === "sent");
  // the resumed step is WAIT-ONLY: awaitResult is called, broadcast is not
  const resumed = mkDeps(pool, dir, { awaitOutcome: () => SUCCESS_RESULT });
  const r2 = await runHeaderStep({ poolId: pool, dir, deps: resumed, run });
  ok("wait-only recovery captures from the awaited result without any resend",
    r2.status === "captured" && resumed._calls.await.length === 1
    && resumed._calls.broadcast.length === 0 && resumed._calls.build.length === 0);
}
{
  // a RECOVERED refusal goes through the SAME outcome table: the
  // structured error is journaled exactly as on the initial await
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { outcome: () => AMBIGUOUS_RESULT });
  const run = await startRun({ poolId: pool, dir, deps });
  await runHeaderStep({ poolId: pool, dir, deps, run }); // W + S, unresolved
  const recovered = mkDeps(pool, dir, { awaitOutcome: () => REFUSAL_RESULT });
  const r = await runHeaderStep({ poolId: pool, dir, deps: recovered, run });
  const read = openValidatedJournal(pool, dir);
  ok("wait-only recovery journals a recovered refusal's structured error",
    r.status === "refused" && read.perEpoch[5].header.state === "refused"
    && read.records[read.records.length - 1].errorClass === "execution-refusal");
}

// ---- resume: a write-ahead without its marker resends the PERSISTED bytes ----
{
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const seed = mkDeps(pool, dir);
  const run = await startRun({ poolId: pool, dir, deps: seed });
  // build the crash state: W committed, no S (the run stopped between)
  const bytes = hBytes(5, 1);
  appendChecked(pool, dir, { v: 1, kind: K.WRITE_AHEAD, object: "header", gen: 1, poolId: pool,
    epochIndex: 5, transitionBytes: bytes, transitionHash: sha(bytes),
    expectedDocumentId: h32("dd"), expectedContents: { poolId: pool, epochIndex: 5, ...numbersOf() },
    configuredStartEpoch: 5 });
  const deps = mkDeps(pool, dir);
  const r = await runHeaderStep({ poolId: pool, dir, deps, run });
  ok("the W-without-S resume commits S then broadcasts the persisted bytes, never rebuilding",
    r.status === "captured" && deps._calls.build.length === 0
    && deps._calls.broadcast.length === 1 && deps._calls.broadcast[0].bytes === bytes);
}

// ---- the duplicate refusal's proved-equality gate ----
{
  const mk = (provedQuery) => async () => {
    const pool = freshPool();
    const dir = caseDir();
    setStart(pool, "5", { dir });
    const deps = mkDeps(pool, dir, { outcome: () => REFUSAL_RESULT, unique: true, provedQuery });
    const run = await startRun({ poolId: pool, dir, deps });
    deps._journalRecordsAfter = () => openValidatedJournal(pool, dir).records;
    return { r: await runHeaderStep({ poolId: pool, dir, deps, run }), deps };
  };
  const eq = await mk(() => ({ found: true, proved: true, documentId: h32("dd"),
    fields: { poolId: null, epochIndex: 5, ...numbersOf() } }))();
  // fields.poolId must equal; patch it per pool inside the query is
  // awkward, so assert the CLASS: a poolId mismatch is foreign
  ok("a duplicate refusal with a poolId field mismatch is foreign", eq.r.status === "foreign-pending");
  // a FIELD-EQUAL header under a different document identifier is a
  // competing instance's document, foreign by the identifier alone
  {
    const pool2 = freshPool();
    const dir2 = caseDir();
    setStart(pool2, "5", { dir: dir2 });
    const deps2 = mkDeps(pool2, dir2, { outcome: () => REFUSAL_RESULT, unique: true,
      provedQuery: () => ({ found: true, proved: true, documentId: h32("99"),
        fields: { poolId: pool2, epochIndex: 5, ...numbersOf() } }) });
    const run2 = await startRun({ poolId: pool2, dir: dir2, deps: deps2 });
    const r = await runHeaderStep({ poolId: pool2, dir: dir2, deps: deps2, run: run2 });
    ok("a field-equal header under a different document identifier is foreign",
      r.status === "foreign-pending");
  }
  const absent = await mk(() => ({ found: false }))();
  ok("a duplicate refusal with a proved absence stays wait-only",
    absent.r.status === "unresolved-pending");

  // ---- a soundness-review finding: AN ANSWER THAT DOES NOT ATTEST PROOF IS REFUSED, NEVER TRUSTED ----
  // The live adapter supplying this dependency was an ordinary document query that
  // obtained no proof and checked no verified-call marker, and the writer journaled its
  // answer under a route whose literal value says proved, which is what authorizes the
  // degraded continuation. The writer cannot verify an attestation, but it CAN refuse an
  // answer that makes none, which turns a silent omission into a named stop.
  const unattested = await mk(() => ({ found: true, documentId: h32("dd"),
    fields: { poolId: null, epochIndex: 5, ...numbersOf() } }))();
  ok("an answer carrying no proof attestation is REFUSED rather than read as proved evidence",
    unattested.r.status === "proved-header-unattested");
  ok("and nothing is journaled for it, so no route claiming proof is written for an answer that proved nothing",
    (() => { const recs = unattested.deps._journalRecordsAfter();
      return !recs.some((x) => x.observationType === "foreign-document"); })());
  const deniedAttestation = await mk(() => ({ found: true, proved: false, documentId: h32("dd"),
    fields: { poolId: null, epochIndex: 5, ...numbersOf() } }))();
  ok("an answer that explicitly denies proof is refused the same way, not read as a falsy nothing",
    deniedAttestation.r.status === "proved-header-unattested");
}
{
  // the full-equality resume: the proved query returns THIS pool's fields
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { outcome: () => REFUSAL_RESULT, unique: true,
    provedQuery: () => ({ found: true, proved: true, documentId: h32("dd"),
      fields: { poolId: pool, epochIndex: 5, ...numbersOf() } }) });
  const run = await startRun({ poolId: pool, dir, deps });
  const r = await runHeaderStep({ poolId: pool, dir, deps, run });
  ok("proved full equality yields the degraded-continuation status (operator journals the declaration)",
    r.status === "duplicate-resume-capture-incomplete" && deps._calls.proved.length === 1);
  // the proved result is journaled as the PROVED-ROUTE foreign-document
  // observation, the exact establishing evidence the operator's
  // header-capture-incomplete declaration requires
  const read = openValidatedJournal(pool, dir);
  const obs = read.records[read.records.length - 1];
  ok("the proved result is journaled as the establishing observation",
    obs.kind === "tegara.e2.journal.observation.v1"
    && obs.observationType === "foreign-document"
    && obs.route === "documents-byPoolEpoch-proved"
    && obs.observedDocumentId === h32("dd"));
  // ... and the operator's declaration is now appendable against it
  appendChecked(pool, dir, { v: 1, kind: "tegara.e2.journal.declaration.v1", object: "header",
    gen: 1, poolId: pool, epochIndex: 5, condition: "header-capture-incomplete",
    reasoning: "operator" });
  // the assertion reads the journal back (both closing-wave families
  // flagged the constant-true form): the surfacing declaration landed
  // and the journal still validates as a whole
  const withDecl = openValidatedJournal(pool, dir);
  ok("header-capture-incomplete is establishable from the journaled observation",
    withDecl.records.some((x) => x.kind === "tegara.e2.journal.declaration.v1"
      && x.condition === "header-capture-incomplete" && x.epochIndex === 5));
}

// ---- a torn capture-then-frontier pair repairs on the next open ----
{
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir);
  const run = await startRun({ poolId: pool, dir, deps });
  await runHeaderStep({ poolId: pool, dir, deps, run }); // captured, frontier 1500
  // simulate the torn pair: the capture is journaled but the frontier
  // update was lost before it committed
  fs.rmSync(path.join(dir, `e2-frontier-${W}.json`));
  const r = await runHeaderStep({ poolId: pool, dir, deps, run });
  ok("the header-done branch repairs the torn frontier from the journaled capture",
    r.status === "header-done-transfers-pending"
    && (() => { const l = acquireIdentityLocks([W]);
      try { return readFrontier(W, { dir, locks: l }) === 1500n; } finally { l.release(); } })());
}

// ---- appendChecked refuses BEFORE committing ----
{
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  await startRun({ poolId: pool, dir, deps: mkDeps(pool, dir) });
  const before = openJournal(pool, dir);
  throws("an invalid record refuses at the semantic check",
    () => appendChecked(pool, dir, { v: 1, kind: K.SENT_MARKER, object: "header", gen: 1,
      poolId: pool, epochIndex: 5, transitionHash: h32("77") }), /without its writeAhead/);
  const after = openJournal(pool, dir);
  ok("nothing committed for the refused record (the check precedes the append)",
    after.committedOffset === before.committedOffset && after.records.length === before.records.length);
}


// ============================================================
// THE SECOND HALF: step 2 (accrual documents) and step 3 (the
// reservation-transfer-receipt sequence)
// ============================================================

// a helper: bring a pool to the captured-header state
const openEpoch = async (pool, dir, over = {}) => {
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, over);
  const run = await startRun({ poolId: pool, dir, deps });
  const h = await runHeaderStep({ poolId: pool, dir, deps, run });
  if (h.status !== "captured") throw new Error(`openEpoch expected a captured header, got ${h.status}`);
  return { deps, run };
};

// ---- the full happy transfer, then the idempotent resume ----
{
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir);
  const a = await runAccrualStep({ poolId: pool, dir, deps, run, epochIndex: 5 });
  ok("step 2 writes one accrual document per allocation row",
    a.statuses.length === 2 && a.statuses.every((s) => s.status === "written"));
  const r = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 });
  const read = openValidatedJournal(pool, dir);
  const acc = read.perEpoch[5].accruals[A1];
  ok("the transfer step completes the whole sequence", r.status === "completed");
  ok("the journal carries the W-S-J holder chain and the receipt capture",
    acc.reservation.state === "held" && acc.transfer.state === "captured" && acc.receiptCaptured === true);
  ok("the parts were written first (1-based indices), the receipt last",
    deps._calls.docWrites.filter((w) => w.object !== "accrual")
      .map((w) => w.object === "part" ? `part${w.partIndex}` : w.object).join(",") === "part1,part2,receipt");
  const locks = acquireIdentityLocks([I]);
  try {
    ok("the receipt capture's verified height advanced the INCOME identity's frontier",
      readFrontier(I, { dir, locks }) === 1600n);
  } finally { locks.release(); }
  // the resumed step is idempotent: nothing rebuilt, nothing rewritten
  const resumed = mkDeps(pool, dir, { ledger: deps._ledger.ledger });
  const r2 = await runTransferStep({ poolId: pool, dir, deps: resumed, run, epochIndex: 5, accrualId: A1 });
  ok("the resumed completed transfer re-derives completion with no new build or write",
    r2.status === "completed" && resumed._calls.build.length === 0
    && resumed._calls.broadcast.length === 0 && resumed._calls.docWrites.length === 0);
}

// ---- the preflight bound, through the preflight, once per subject ----
{
  const pool = freshPool();
  const dir = caseDir();
  const { deps: base, run } = await openEpoch(pool, dir);
  const long = mkDeps(pool, dir, { transferBytesLong: true });
  const r = await runTransferStep({ poolId: pool, dir, deps: long, run, epochIndex: 5, accrualId: A1 });
  const read = openValidatedJournal(pool, dir);
  const decls = read.records.filter((x) => x.condition === "transfer-unencodable");
  ok("a bound violation stops the accrual unsent with the durable declaration",
    r.status === "unencodable-stopped" && decls.length === 1
    && decls[0].observedLength === 101 && decls[0].bound === 100
    && !read.records.some((x) => x.kind === K.WRITE_AHEAD && x.object === "transfer" && x.accrualId === A1));
  const r2 = await runTransferStep({ poolId: pool, dir, deps: long, run, epochIndex: 5, accrualId: A1 });
  ok("the resumed run appends NO second declaration (once per subject)",
    r2.status === "unencodable-stopped"
    && openValidatedJournal(pool, dir).records.filter((x) => x.condition === "transfer-unencodable").length === 1);
  // the boundary case: exactly AT the bound proceeds
  const atBound = mkDeps(pool, dir, { transferBytesBound: 101, transferBytesAt: true, ledger: base._ledger.ledger });
  const r3 = await runTransferStep({ poolId: pool, dir, deps: atBound, run, epochIndex: 5, accrualId: A2 });
  ok("bytes exactly at the bound pass the preflight", r3.status === "completed");
}

// ---- step 2's resume comparisons and refusals ----
{
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir);
  // a present-and-equal document is idempotent; a differing one is a hard stop
  await runAccrualStep({ poolId: pool, dir, deps, run, epochIndex: 5 });
  const again = await runAccrualStep({ poolId: pool, dir, deps, run, epochIndex: 5 });
  ok("present accrual documents resume as present with no rewrite",
    again.statuses.every((s) => s.status === "present"));
  deps._ledger.ledger.set(deps._ledger.docKey("accrual", { epochIndex: 5, accrualId: A1 }), { altered: true });
  const bad = await runAccrualStep({ poolId: pool, dir, deps, run, epochIndex: 5 });
  ok("a differing on-ledger accrual is a hard stop", bad.statuses[0].status === "mismatch-stop");
  // every field binds: a document differing ONLY in credits is a stop, and
  // an equal document with reordered properties is NOT (canonical equality)
  deps._ledger.ledger.set(deps._ledger.docKey("accrual", { epochIndex: 5, accrualId: A1 }),
    { poolId: pool, epochIndex: 5, accrualId: A1, credits: "999" });
  const creditsOff = await runAccrualStep({ poolId: pool, dir, deps, run, epochIndex: 5 });
  ok("a credits-only difference is a hard stop", creditsOff.statuses[0].status === "mismatch-stop");
  deps._ledger.ledger.set(deps._ledger.docKey("accrual", { epochIndex: 5, accrualId: A1 }),
    { credits: "1000000", accrualId: A1, epochIndex: 5, poolId: pool });
  const reordered = await runAccrualStep({ poolId: pool, dir, deps, run, epochIndex: 5 });
  ok("reordered properties of an equal document are present, never a mismatch",
    reordered.statuses[0].status === "present");
}
{
  const pool = freshPool();
  const dir = caseDir();
  const { deps: seed, run } = await openEpoch(pool, dir);
  const refusing = mkDeps(pool, dir, { docBehavior: () => "refuse" });
  const r = await runAccrualStep({ poolId: pool, dir, deps: refusing, run, epochIndex: 5 });
  const read = openValidatedJournal(pool, dir);
  ok("a document execution refusal journals the error and stalls at record-write-refused",
    r.statuses[0].status === "refused"
    && read.perEpoch[5].documentWriteSubjects[`accrual:${A1}`].state === "refused");
  // the terminal subject never re-attempts
  const retry = mkDeps(pool, dir, { docBehavior: () => "refuse" });
  const r2 = await runAccrualStep({ poolId: pool, dir, deps: retry, run, epochIndex: 5 });
  ok("a terminal record-write-refused subject is never re-attempted",
    r2.statuses[0].status === "refused" && retry._calls.docWrites.length === 0);
}
{
  // the stale-read rule: a duplicate refusal re-fetches and compares,
  // never resubmits (a concurrent writer landed the equal document)
  const pool = freshPool();
  const dir = caseDir();
  const { deps: seed, run } = await openEpoch(pool, dir);
  const deps = mkDeps(pool, dir, { unique: true, docBehavior: () => "ok-silent" });
  const r = await runAccrualStep({ poolId: pool, dir, deps, run, epochIndex: 5 });
  ok("a duplicate document refusal resolves by fetch-and-compare with ONE write",
    r.statuses.every((s) => s.status === "present")
    && deps._calls.docWrites.filter((w) => w.object === "accrual").length === 2);
}

// ---- the run token, the lock order, and the torn-frontier repair ----
{
  // the accrual step refuses a stale run token exactly like the header step
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run: oldRun } = await openEpoch(pool, dir);
  await startRun({ poolId: pool, dir, deps }); // a newer measurement
  await rejects("the accrual step refuses an old run's token",
    runAccrualStep({ poolId: pool, dir, deps, run: oldRun, epochIndex: 5 }), /is not this run's/);
}
{
  // the transfer step acquires its identity locks in ascending raw-byte
  // order, observed through the lock mechanism itself
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir);
  const order = [];
  const real = envStore.acquireOpLock;
  envStore.acquireOpLock = (name) => { order.push(name); return real(name); };
  try { await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 }); }
  finally { envStore.acquireOpLock = real; }
  const idLocks = order.filter((n2) => n2.startsWith("oplock-") === false && n2.includes("e2-identity-"));
  ok("the transfer step's identity locks acquire in ascending raw-byte order",
    idLocks.length === 2 && idLocks[0] === `e2-identity-${W}` && idLocks[1] === `e2-identity-${I}`);
}
{
  // a torn receipt-capture-then-frontier pair repairs on the resumed pass
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir);
  await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 }); // completed, income 1600
  fs.rmSync(path.join(dir, `e2-frontier-${I}.json`));
  const resumed = mkDeps(pool, dir, { ledger: deps._ledger.ledger });
  const r = await runTransferStep({ poolId: pool, dir, deps: resumed, run, epochIndex: 5, accrualId: A1 });
  const locks = acquireIdentityLocks([I]);
  try {
    ok("the resumed transfer repairs the torn income frontier from the journaled capture",
      r.status === "completed" && readFrontier(I, { dir, locks }) === 1600n);
  } finally { locks.release(); }
}

{
  // a refused later acquisition unwinds the earlier handle: nothing leaks
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir);
  const held = acquireIdentityLocks([I]); // the higher lock is taken
  try {
    await rejects("the transfer step refuses when an identity lock is contended",
      runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 }),
      /holds the operation lock/);
  } finally { held.release(); }
  ok("the partial acquisition unwound (the writer lock is free again)",
    (() => { const l = acquireIdentityLocks([W]); l.release(); return true; })());
}

// ---- the reservation outcomes ----
{
  // a reservation refusal journals its error; the operator's
  // rebuild-reservation decision drives exactly one new generation
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir);
  const refuse1 = mkDeps(pool, dir, {
    outcome: (hash, bytes) => bytes.startsWith("0c0d") ? REFUSAL_RESULT : SUCCESS_RESULT });
  const r = await runTransferStep({ poolId: pool, dir, deps: refuse1, run, epochIndex: 5, accrualId: A1 });
  const read = openValidatedJournal(pool, dir);
  ok("a reservation refusal journals the structured error and stalls",
    r.status === "reservation-refused" && read.perEpoch[5].accruals[A1].reservation.state === "refused");
  appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "reservation", gen: 1, poolId: pool,
    epochIndex: 5, accrualId: A1, condition: "reservation-refused", reasoning: "operator" });
  appendChecked(pool, dir, { v: 1, kind: K.DECISION, object: "reservation", gen: 1, poolId: pool,
    epochIndex: 5, accrualId: A1, condition: "reservation-refused", action: "rebuild-reservation",
    d6Status: "open", reasoning: "operator" });
  const retry = mkDeps(pool, dir);
  const r2 = await runTransferStep({ poolId: pool, dir, deps: retry, run, epochIndex: 5, accrualId: A1 });
  const read2 = openValidatedJournal(pool, dir);
  ok("the journaled rebuild-reservation decision drives a generation-2 claim to completion",
    r2.status === "completed" && read2.perEpoch[5].accruals[A1].reservation.gen === 2);
}
{
  // an ambiguous reservation is wait-only on ITS OWN persisted hash
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir);
  const ambiguous = mkDeps(pool, dir, {
    outcome: (hash, bytes) => bytes.startsWith("0c0d") ? AMBIGUOUS_RESULT : SUCCESS_RESULT });
  const r = await runTransferStep({ poolId: pool, dir, deps: ambiguous, run, epochIndex: 5, accrualId: A1 });
  ok("an ambiguous reservation outcome stays wait-only", r.status === "reservation-unresolved-pending");
  const resumed = mkDeps(pool, dir, { awaitOutcome: () => SUCCESS_RESULT });
  const r2 = await runTransferStep({ poolId: pool, dir, deps: resumed, run, epochIndex: 5, accrualId: A1 });
  const resBytes = "0c0d0005" + A1.slice(0, 4);
  ok("the resumed reservation waits on the RESERVATION's persisted hash and completes",
    r2.status === "completed" && resumed._calls.await[0] === sha(resBytes)
    && resumed._calls.broadcast.some((b) => b.bytes.startsWith("0a0b")));
}
{
  // the unique-index claim: an equal bound-transfer hash is an identical
  // claim, wait-only observation; the loop then closes on the observed
  // receipt; a DIFFERING claim is foreign with its evidence journaled
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir);
  const tHash = sha("0a0b0005" + A1.slice(0, 4));
  const equal = mkDeps(pool, dir, { unique: true,
    outcome: (hash, bytes) => bytes.startsWith("0c0d") ? REFUSAL_RESULT : SUCCESS_RESULT,
    reservationOnLedger: () => ({ found: true, boundTransferHash: tHash }) });
  const r = await runTransferStep({ poolId: pool, dir, deps: equal, run, epochIndex: 5, accrualId: A1 });
  const read = openValidatedJournal(pool, dir);
  ok("an equal on-ledger claim enters wait-only observation with the watch journaled",
    r.status === "wait-only-observation"
    && read.records.some((x) => x.observationType === "watch-open" && x.accrualId === A1)
    && !read.records.some((x) => x.kind === K.SENT_MARKER && x.object === "transfer" && x.accrualId === A1));
  // a not-found observation visit journals nothing and stays waiting
  const notYet = mkDeps(pool, dir);
  const rWait = await runTransferStep({ poolId: pool, dir, deps: notYet, run, epochIndex: 5, accrualId: A1 });
  ok("an unfound observation stays wait-only and journals nothing",
    rWait.status === "wait-only-observation"
    && !openValidatedJournal(pool, dir).records.some((x) => x.observationType === "receipt-observed"));
  const observing = mkDeps(pool, dir, { observe: () => ({ found: true, documentId: h32("0d") }) });
  const r2 = await runTransferStep({ poolId: pool, dir, deps: observing, run, epochIndex: 5, accrualId: A1 });
  ok("the observed receipt closes the loop", r2.status === "receipt-observed"
    && openValidatedJournal(pool, dir).perEpoch[5].accruals[A1].observedByBranch === true);
  const after = mkDeps(pool, dir);
  const r3 = await runTransferStep({ poolId: pool, dir, deps: after, run, epochIndex: 5, accrualId: A1 });
  ok("an observed accrual stays observed, never re-sent", r3.status === "receipt-observed"
    && after._calls.broadcast.length === 0);
}
{
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir);
  const foreign = mkDeps(pool, dir, { unique: true,
    outcome: (hash, bytes) => bytes.startsWith("0c0d") ? REFUSAL_RESULT : SUCCESS_RESULT,
    reservationOnLedger: () => ({ found: true, boundTransferHash: h32("99") }) });
  const r = await runTransferStep({ poolId: pool, dir, deps: foreign, run, epochIndex: 5, accrualId: A1 });
  const fc = openValidatedJournal(pool, dir).records.find((x) => x.observationType === "foreign-claim");
  ok("a differing on-ledger claim is the foreign condition with its evidence journaled",
    r.status === "reservation-foreign-pending" && !!fc
    && fc.observedBoundTransferHash === h32("99"));
}
{
  // a claim differing only in its LAST byte is still foreign (full-hash
  // equality, never a prefix comparison)
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir);
  const tHash = sha("0a0b0005" + A1.slice(0, 4));
  const lastByteOff = tHash.slice(0, 62) + (tHash.slice(62) === "00" ? "01" : "00");
  const nearMiss = mkDeps(pool, dir, { unique: true,
    outcome: (hash, bytes) => bytes.startsWith("0c0d") ? REFUSAL_RESULT : SUCCESS_RESULT,
    reservationOnLedger: () => ({ found: true, boundTransferHash: lastByteOff }) });
  const r = await runTransferStep({ poolId: pool, dir, deps: nearMiss, run, epochIndex: 5, accrualId: A1 });
  ok("a claim differing only in its last byte is foreign", r.status === "reservation-foreign-pending");
}
{
  // a duplicate refusal beside a PROVED ABSENCE is a stale read:
  // wait-only, never foreign, nothing journaled
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir);
  const stale = mkDeps(pool, dir, { unique: true,
    outcome: (hash, bytes) => bytes.startsWith("0c0d") ? REFUSAL_RESULT : SUCCESS_RESULT });
  const before = openValidatedJournal(pool, dir).records.length;
  const r = await runTransferStep({ poolId: pool, dir, deps: stale, run, epochIndex: 5, accrualId: A1 });
  const afterRecords = openValidatedJournal(pool, dir).records;
  // the branch journals NOTHING beyond the attempt's own W-W-S records:
  // no foreign-claim, no watch-open, no evidence of any kind
  ok("a duplicate refusal with a proved absence stays wait-only, never foreign, journaling nothing",
    r.status === "reservation-unresolved-pending"
    && afterRecords.length === before + 3
    && !afterRecords.some((x) => x.kind === "tegara.e2.journal.observation.v1"));
}

// ---- the transfer outcomes ----
{
  // a transfer refusal is terminal (stop only) and never re-polled
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir);
  const refuse2 = mkDeps(pool, dir, {
    outcome: (hash, bytes) => bytes.startsWith("0a0b") ? REFUSAL_RESULT : SUCCESS_RESULT });
  const r = await runTransferStep({ poolId: pool, dir, deps: refuse2, run, epochIndex: 5, accrualId: A1 });
  const read = openValidatedJournal(pool, dir);
  ok("a transfer refusal journals the structured error (terminal, stop only)",
    r.status === "transfer-refused" && read.perEpoch[5].accruals[A1].transfer.state === "refused");
  const retry = mkDeps(pool, dir);
  const r2 = await runTransferStep({ poolId: pool, dir, deps: retry, run, epochIndex: 5, accrualId: A1 });
  ok("a refused transfer is never re-polled or re-sent",
    r2.status === "transfer-refused" && retry._calls.await.length === 0 && retry._calls.broadcast.length === 0);
}
{
  // an ambiguous transfer stays wait-only; the resumed wait captures with
  // no resend (no automatic rebroadcast, ever)
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir);
  const ambiguous = mkDeps(pool, dir, {
    outcome: (hash, bytes) => bytes.startsWith("0a0b") ? AMBIGUOUS_RESULT : SUCCESS_RESULT });
  const r = await runTransferStep({ poolId: pool, dir, deps: ambiguous, run, epochIndex: 5, accrualId: A1 });
  ok("an ambiguous transfer stays wait-only", r.status === "transfer-unresolved-pending");
  const resumed = mkDeps(pool, dir, { awaitOutcome: () => SUCCESS_RESULT });
  const r2 = await runTransferStep({ poolId: pool, dir, deps: resumed, run, epochIndex: 5, accrualId: A1 });
  ok("the resumed wait captures from the awaited result with no resend and no rebuild",
    r2.status === "completed" && resumed._calls.broadcast.length === 0 && resumed._calls.build.length === 0);
}
{
  // a stalled part write leaves documents-pending, the receipt unattempted
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir);
  const stall = mkDeps(pool, dir, {
    docBehavior: (object, key) => (object === "part" && key.partIndex === 2) ? "ambiguous" : "ok" });
  const r = await runTransferStep({ poolId: pool, dir, deps: stall, run, epochIndex: 5, accrualId: A1 });
  ok("a stalled part leaves documents-pending with the receipt unattempted",
    r.status === "documents-pending"
    && !stall._calls.docWrites.some((w) => w.object === "receipt"));
  const finish = mkDeps(pool, dir, { ledger: stall._ledger.ledger });
  const r2 = await runTransferStep({ poolId: pool, dir, deps: finish, run, epochIndex: 5, accrualId: A1 });
  ok("the resumed document pass completes parts-then-receipt", r2.status === "completed");
}
{
  // the frozen part split: a payloads answer whose parts array disagrees
  // with proofPartCount-1 refuses before any write
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir);
  const wrongCount = mkDeps(pool, dir);
  wrongCount.receiptPayloads = () => ({ parts: [{ p: 1 }], receipt: { r: 1, proofPartCount: 3 } });
  await rejects("a parts array disagreeing with proofPartCount-1 refuses",
    runTransferStep({ poolId: pool, dir, deps: wrongCount, run, epochIndex: 5, accrualId: A1 }),
    /must be exactly proofPartCount-1/);
}
{
  // a zero entitlement never reaches the transfer step
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir, {
    rowsFor: (epoch) => [{ accrualId: A1, amountCredits: "0", recipientId: h32("71") },
      { accrualId: A2, amountCredits: "1500000", recipientId: h32("72") }] });
  await rejects("the transfer step refuses a zero entitlement row",
    runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 }),
    /only for a positive entitlement row/);
}

// ---- the classification preflight (a soundness-review finding) ----
{
  // a SELF-SHARE settles without a transfer at any amount: the declaration
  // journals once, nothing is built, reserved or sent, and the resumed
  // step re-derives the settled status without a second declaration
  const pool = freshPool();
  const dir = caseDir();
  const rows = () => [{ accrualId: A1, amountCredits: "1000000", recipientId: I }];
  const { deps, run } = await openEpoch(pool, dir, { rowsFor: rows });
  const r = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 });
  const read = openValidatedJournal(pool, dir);
  const decls = read.records.filter((x) => x.condition === "self-share-settled");
  ok("a self-share row settles without a transfer, the declaration journaled with its amount",
    r.status === "self-share-settled" && decls.length === 1
    && decls[0].object === "accrual" && decls[0].accrualId === A1
    && decls[0].amountCredits === "1000000");
  ok("no transfer or reservation machinery ran for the self-share",
    deps._calls.build.every((b) => !String(b).startsWith("t:") && !String(b).startsWith("r:"))
    && deps._calls.broadcast.length === 1 // the header's own broadcast only
    && deps._calls.docWrites.length === 0
    && !read.records.some((x) => x.kind === K.WRITE_AHEAD && x.object !== "header"));
  const again = mkDeps(pool, dir, { rowsFor: rows });
  const r2 = await runTransferStep({ poolId: pool, dir, deps: again, run, epochIndex: 5, accrualId: A1 });
  ok("the resumed self-share appends NO second declaration (once per subject) and sends nothing",
    r2.status === "self-share-settled" && again._calls.broadcast.length === 0
    && openValidatedJournal(pool, dir).records.filter((x) => x.condition === "self-share-settled").length === 1);
}
{
  // a BELOW-MINIMUM entitlement carries: the declaration journals the
  // amount and the pinned minimum, nothing is reserved or sent
  const pool = freshPool();
  const dir = caseDir();
  const rows = () => [{ accrualId: A1, amountCredits: "99999", recipientId: h32("71") }];
  const { deps, run } = await openEpoch(pool, dir, { rowsFor: rows });
  const r = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 });
  const read = openValidatedJournal(pool, dir);
  const decls = read.records.filter((x) => x.condition === "transfer-below-minimum");
  ok("a below-minimum row is carried, the declaration journaled with amount and minimum",
    r.status === "below-minimum-carried" && decls.length === 1
    && decls[0].amountCredits === "99999" && decls[0].minimumCredits === "100000"
    && !read.records.some((x) => x.kind === K.WRITE_AHEAD && x.object !== "header"));
  ok("no transfer machinery ran for the below-minimum row (no build of either kind, no send beyond the header's, no document write)",
    deps._calls.build.every((b) => !String(b).startsWith("t:") && !String(b).startsWith("r:"))
    && deps._calls.broadcast.length === 1
    && deps._calls.docWrites.length === 0);
  const again = mkDeps(pool, dir, { rowsFor: rows });
  const r2 = await runTransferStep({ poolId: pool, dir, deps: again, run, epochIndex: 5, accrualId: A1 });
  ok("the resumed below-minimum appends NO second declaration",
    r2.status === "below-minimum-carried"
    && openValidatedJournal(pool, dir).records.filter((x) => x.condition === "transfer-below-minimum").length === 1);
}
{
  // the boundary: exactly the pinned minimum is payable end to end, and
  // "payable" is observed as the machinery, not only the status string
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir, {
    rowsFor: () => [{ accrualId: A1, amountCredits: "100000", recipientId: h32("71") }] });
  const r = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 });
  ok("an entitlement exactly at the pinned minimum is payable, through the real machinery",
    r.status === "completed"
    && deps._calls.build.some((b) => String(b).startsWith("t:"))
    && deps._calls.broadcast.some((b) => b.bytes.startsWith("0a0b"))
    && deps._calls.docWrites.some((w) => w.object === "receipt")
    && !openValidatedJournal(pool, dir).records.some((x) => x.condition === "transfer-below-minimum"));
}
{
  // one pool, one epoch, a payable row AND a self-share row: the payable
  // one runs the machinery, the self-share settles, and neither
  // classification leaks onto the other subject
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir, {
    rowsFor: () => [{ accrualId: A1, amountCredits: "1000000", recipientId: h32("71") },
      { accrualId: A2, amountCredits: "500000", recipientId: I }] });
  const rPay = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 });
  const rSelf = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A2 });
  const read = openValidatedJournal(pool, dir);
  ok("in a mixed epoch the payable row completes and the self-share settles",
    rPay.status === "completed" && rSelf.status === "self-share-settled");
  ok("each classification binds its own accrual subject only",
    read.records.filter((x) => x.condition === "self-share-settled").length === 1
    && read.records.every((x) => x.condition !== "self-share-settled" || x.accrualId === A2)
    && read.records.some((x) => x.kind === K.WRITE_AHEAD && x.object === "transfer" && x.accrualId === A1)
    && !read.records.some((x) => x.kind === K.WRITE_AHEAD && x.object === "transfer" && x.accrualId === A2));
}
{
  // both exclusions true: SELF-SHARE wins (the pinned validation checks
  // sender-equals-recipient before the amount), never carried
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir, {
    rowsFor: () => [{ accrualId: A1, amountCredits: "495", recipientId: I }] });
  const r = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 });
  const read = openValidatedJournal(pool, dir);
  ok("a below-minimum self-share classifies self-share (the pinned order), never carried",
    r.status === "self-share-settled"
    && read.records.some((x) => x.condition === "self-share-settled")
    && !read.records.some((x) => x.condition === "transfer-below-minimum"));
}
{
  // the carve-out for an EXCLUDED row with journaled transfer state (the
  // wedged canonical epoch's shape): never reclassified, and the realistic
  // outcome for those bytes is the consensus REFUSAL, terminal
  const pool = freshPool();
  const dir = caseDir();
  const rows = () => [{ accrualId: A1, amountCredits: "495", recipientId: I }];
  const { run } = await openEpoch(pool, dir, { rowsFor: rows });
  const bytes = "0a0b0005" + A1.slice(0, 4);
  appendChecked(pool, dir, { v: 1, kind: K.WRITE_AHEAD, object: "transfer", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, transitionBytes: bytes, transitionHash: sha(bytes) });
  const refusing = mkDeps(pool, dir, { rowsFor: rows,
    outcome: (hash, b) => b.startsWith("0a0b") ? REFUSAL_RESULT : SUCCESS_RESULT });
  const r = await runTransferStep({ poolId: pool, dir, deps: refusing, run, epochIndex: 5, accrualId: A1 });
  const read = openValidatedJournal(pool, dir);
  ok("journaled transfer state for an excluded row is never reclassified; the refusal is terminal",
    r.status === "transfer-refused" && refusing._calls.broadcast.some((b) => b.bytes === bytes)
    && !read.records.some((x) => x.condition === "self-share-settled"
      || x.condition === "transfer-below-minimum"));
}
{
  // the persisted bytes stay authoritative for a PAYABLE row too: the
  // journaled write-ahead's bytes DIFFER from what the builder would
  // produce, the resumed step broadcasts exactly the journaled bytes and
  // never calls the builder
  const pool = freshPool();
  const dir = caseDir();
  const rows = () => [{ accrualId: A1, amountCredits: "1000000", recipientId: h32("71") }];
  const { run } = await openEpoch(pool, dir, { rowsFor: rows });
  const bytes = "0a0bffff" + A1.slice(0, 4); // NOT the builder's shape for epoch 5
  appendChecked(pool, dir, { v: 1, kind: K.WRITE_AHEAD, object: "transfer", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, transitionBytes: bytes, transitionHash: sha(bytes) });
  const deps = mkDeps(pool, dir, { rowsFor: rows });
  const r = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 });
  ok("a journaled payable transfer resumes on the persisted bytes with no rebuild",
    r.status === "completed"
    && deps._calls.build.every((b) => !String(b).startsWith("t:"))
    && deps._calls.broadcast.some((b) => b.bytes === bytes)
    && !deps._calls.broadcast.some((b) => b.bytes === "0a0b0005" + A1.slice(0, 4)));
}
{
  // the FULLER wedge shape (the live specimen's: transfer W, the
  // reservation's W-S-J chain, the transfer sent-marker, no result): a
  // resumed step stays wait-only, never classifies, and the validator
  // refuses a classification declaration over that state outright
  const pool = freshPool();
  const dir = caseDir();
  const rows = () => [{ accrualId: A1, amountCredits: "495", recipientId: I }];
  const { run } = await openEpoch(pool, dir, { rowsFor: rows });
  const tB = "0a0b0005" + A1.slice(0, 4);
  const rB = "0c0d0005" + A1.slice(0, 4);
  appendChecked(pool, dir, { v: 1, kind: K.WRITE_AHEAD, object: "transfer", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, transitionBytes: tB, transitionHash: sha(tB) });
  appendChecked(pool, dir, { v: 1, kind: K.WRITE_AHEAD, object: "reservation", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, transitionBytes: rB, transitionHash: sha(rB),
    boundTransferHash: sha(tB) });
  appendChecked(pool, dir, { v: 1, kind: K.SENT_MARKER, object: "reservation", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, transitionHash: sha(rB) });
  appendChecked(pool, dir, { v: 1, kind: "tegara.e2.journal.reservationSuccess.v1", object: "reservation",
    gen: 1, poolId: pool, epochIndex: 5, accrualId: A1, transitionHash: sha(rB),
    boundTransferHash: sha(tB), reservationDocumentId: h32("d1") });
  appendChecked(pool, dir, { v: 1, kind: K.SENT_MARKER, object: "transfer", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, transitionHash: sha(tB) });
  const waiting = mkDeps(pool, dir, { rowsFor: rows }); // awaitOutcome default: ambiguous
  const r = await runTransferStep({ poolId: pool, dir, deps: waiting, run, epochIndex: 5, accrualId: A1 });
  ok("the fuller wedge shape resumes wait-only, never classified, nothing resent",
    r.status === "transfer-unresolved-pending" && waiting._calls.broadcast.length === 0
    && !openValidatedJournal(pool, dir).records.some((x) => x.condition === "self-share-settled"
      || x.condition === "transfer-below-minimum"));
  throws("the validator refuses a classification declaration over journaled transfer state",
    () => appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1,
      poolId: pool, epochIndex: 5, accrualId: A1, condition: "self-share-settled",
      reasoning: "r", amountCredits: "495" }),
    /over existing transfer or reservation records/);
}
{
  // a malformed recipientId refuses loudly at BOTH comparison sites (the
  // classification and the measurement), never a silent fall-through into
  // the payable path
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir, {
    rowsFor: () => [{ accrualId: A1, amountCredits: "1000000", recipientId: h32("71") }] });
  const malformed = mkDeps(pool, dir, {
    rowsFor: () => [{ accrualId: A1, amountCredits: "1000000" }] });
  await rejects("a row without a hex recipientId refuses the transfer step",
    runTransferStep({ poolId: pool, dir, deps: malformed, run, epochIndex: 5, accrualId: A1 }),
    /recipientId must be 64 lowercase hex/);
  const before = openJournal(pool, dir).records.length;
  await rejects("a row without a hex recipientId refuses the measurement too",
    startRun({ poolId: pool, dir, deps: malformed }),
    /recipientId must be 64 lowercase hex/);
  ok("the refused measurement appended nothing",
    openJournal(pool, dir).records.length === before);
  // a COMPLETE answer must not exempt the rows from the check
  const completeButMalformed = mkDeps(pool, dir, { complete: () => true,
    rowsFor: () => [{ accrualId: A1, amountCredits: "1000000" }] });
  await rejects("a completeness answer never exempts rows from validation",
    startRun({ poolId: pool, dir, deps: completeButMalformed }),
    /recipientId must be 64 lowercase hex/);
}
{
  // the closed row grammar refuses through the module's named path,
  // never a raw construction error: a duplicate accrualId and a
  // malformed amount both refuse at the measurement and transfer sites
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir);
  const dupAccrual = mkDeps(pool, dir, { rowsFor: () => [
    { accrualId: A1, amountCredits: "500000", recipientId: h32("71") },
    { accrualId: A1, amountCredits: "600000", recipientId: h32("72") }] });
  await rejects("two rows sharing one accrualId refuse the measurement",
    startRun({ poolId: pool, dir, deps: dupAccrual }),
    /share one accrualId/);
  await rejects("two rows sharing one accrualId refuse the transfer step",
    runTransferStep({ poolId: pool, dir, deps: dupAccrual, run, epochIndex: 5, accrualId: A1 }),
    /share one accrualId/);
  const badAmount = mkDeps(pool, dir, { rowsFor: () => [
    { accrualId: A1, amountCredits: "1e5", recipientId: h32("71") }] });
  await rejects("a malformed amount refuses through the named path",
    startRun({ poolId: pool, dir, deps: badAmount }),
    /amountCredits must be a canonical decimal/);
  await rejects("a malformed amount refuses the transfer step too",
    runTransferStep({ poolId: pool, dir, deps: badAmount, run, epochIndex: 5, accrualId: A1 }),
    /amountCredits must be a canonical decimal/);
  // ... and the HEADER step validates the rows it consumes (a fresh
  // pool whose header is not yet built, so the step reaches the fetch)
  const pool2 = freshPool();
  const dir2 = caseDir();
  setStart(pool2, "5", { dir: dir2 });
  const good2 = mkDeps(pool2, dir2);
  const run2 = await startRun({ poolId: pool2, dir: dir2, deps: good2 });
  const dup2 = mkDeps(pool2, dir2, { rowsFor: () => [
    { accrualId: A1, amountCredits: "500000", recipientId: h32("71") },
    { accrualId: A2, amountCredits: "600000", recipientId: h32("71") }] });
  await rejects("the header step refuses a malformed row set before admission",
    runHeaderStep({ poolId: pool2, dir: dir2, deps: dup2, run: run2 }),
    /share one owner/);
  const badId = mkDeps(pool, dir, { rowsFor: () => [
    { accrualId: "xyz", amountCredits: "500000", recipientId: h32("71") }] });
  await rejects("a malformed accrualId refuses through the named path",
    startRun({ poolId: pool, dir, deps: badId }),
    /accrualId must be 32 bytes lowercase hex/);
}
{
  // the exported classifier is self-contained: a direct caller gets the
  // same closed grammar the integrated paths assert
  const { classifyEntitlement, MIN_TRANSFER_AMOUNT_CREDITS } = require("./e2Distribute.cjs");
  ok("the pinned minimum exports as 100000", MIN_TRANSFER_AMOUNT_CREDITS === 100000n);
  ok("the classifier's three answers hold at the boundaries",
    classifyEntitlement({ recipientId: I, amountCredits: "1000000" }, I) === "self-share"
    && classifyEntitlement({ recipientId: h32("71"), amountCredits: "99999" }, I) === "below-minimum"
    && classifyEntitlement({ recipientId: h32("71"), amountCredits: "100000" }, I) === "payable"
    && classifyEntitlement({ recipientId: I, amountCredits: "495" }, I) === "self-share");
  // CROSS-COMPONENT AGREEMENT (the per-epoch context design, step 3b): the carry-capable row
  // source's own answers, `isSelfShare` and `payable`, agree with this classifier for EVERY
  // positive row it produces over a four-epoch run at the minimum's edges; for a ZERO row the
  // two differ in KIND (this classifier REFUSES a zero row by name, since zero rows never reach
  // the transfer machinery, while the row source reports payable: false and RETAINS the
  // identity-based isSelfShare value, true for the income identity's own zero row), which is
  // stated here rather than left to be found (the reviewer's wording, replacing a first draft
  // that wrongly said the partition also answers "not a self-share")
  {
    const { buildCarryCapableEntitlements } = require("./entitlementCalc.cjs");
    const M = h32("71");
    const calc = buildCarryCapableEntitlements({ configuredStart: 0, incomeIdentity: I,
      allocation: [{ recipientId: I, bps: 5000 }, { recipientId: M, bps: 5000 }], encodingCeiling: 9007199254740991n,
      epochs: [["0", "199998"], ["1", "200000"], ["2", "100000"], ["3", "1"]].map(([n, d]) => ({ number: Number(n), distributableCredits: d })) });
    const expectedOf = (r) => (r.isSelfShare ? "self-share" : r.payable ? "payable" : "below-minimum");
    const rows = [0, 1, 2, 3].flatMap((n) => calc.rowsFor(n));
    const positive = rows.filter((r) => BigInt(r.amountCredits) > 0n);
    const zero = rows.filter((r) => BigInt(r.amountCredits) === 0n);
    ok(`the row source's answers agree with the writer's classifier for every positive row (${positive.length} rows, amounts ${[...new Set(positive.map((r) => r.amountCredits))].join("/")})`,
      positive.length >= 6 && positive.every((r) => classifyEntitlement(r, I) === expectedOf(r)));
    const refusesZero = (r) => { try { classifyEntitlement(r, I); return false; } catch (e) { return /only a positive entitlement is classified/.test(e.message); } };
    // at distributable 1 the income identity's row is zero (the member's carries the previous
    // epoch's deferral in and is positive), so the one zero row is a self-share: its self-share
    // answer is still the identity comparison and payable is false
    ok(`a zero row differs in kind: the classifier refuses it by name while the partition answers not payable, its self-share flag the identity comparison alone (${zero.length} zero row)`,
      zero.length === 1 && zero.every((r) => refusesZero(r) && r.payable === false && r.isSelfShare === (r.recipientId === I)));
  }
  throws("a direct call with a malformed amount refuses through the named path",
    () => classifyEntitlement({ recipientId: h32("71"), amountCredits: "1e5" }, I),
    /amountCredits must be a canonical decimal/);
  throws("a direct call with a non-canonical amount refuses",
    () => classifyEntitlement({ recipientId: h32("71"), amountCredits: "01" }, I),
    /amountCredits must be a canonical decimal/);
  throws("a direct call with a zero amount refuses (only positives classify)",
    () => classifyEntitlement({ recipientId: h32("71"), amountCredits: "0" }, I),
    /only a positive entitlement is classified/);
  throws("a self-share row with a nonzero carry-in refuses (the never-receives-carry invariant)",
    () => classifyEntitlement({ recipientId: I, amountCredits: "70000", carryInCredits: "40000" }, I),
    /never receive carry/);
  ok("a self-share row with an explicit zero carry-in classifies",
    classifyEntitlement({ recipientId: I, amountCredits: "70000", carryInCredits: "0" }, I) === "self-share");
}
{
  // runAccrualStep's complete member: true only for a NONEMPTY set that
  // fully advanced, false on a stall and false on an empty set
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir);
  const a = await runAccrualStep({ poolId: pool, dir, deps, run, epochIndex: 5 });
  ok("a fully advanced accrual step reports complete", a.complete === true);
  const empty = mkDeps(pool, dir, { rowsFor: () => [] });
  const e0 = await runAccrualStep({ poolId: pool, dir, deps: empty, run, epochIndex: 5 });
  ok("an empty row set never reports complete (it examined nothing)",
    e0.complete === false && e0.statuses.length === 0);
  const stall = mkDeps(pool, dir, { docBehavior: () => "ambiguous" });
  const s0 = await runAccrualStep({ poolId: pool, dir, deps: stall, run, epochIndex: 5 });
  ok("a stalled accrual step reports incomplete", s0.complete === false);
}
{
  // the income identity binds to the pool record: a caller-selected value
  // that disagrees with the resolved pool refuses at BOTH comparison sites
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir);
  const misbound = mkDeps(pool, dir);
  misbound.resolvePool = () => ({ resolved: true, writerIdentity: W, incomeIdentity: h32("aa"),
    entitlementsForEpoch: () => [] });
  await rejects("a disagreeing income identity refuses the measurement",
    startRun({ poolId: pool, dir, deps: misbound }),
    /disagrees with the pool record's income identity/);
  await rejects("a disagreeing income identity refuses the transfer step",
    runTransferStep({ poolId: pool, dir, deps: misbound, run, epochIndex: 5, accrualId: A1 }),
    /disagrees with the pool record's income identity/);
  // the binding resolves THE REQUESTED POOL, not whatever the resolver
  // was already holding
  const seenPools = [];
  const recording = mkDeps(pool, dir);
  const realResolve = recording.resolvePool;
  recording.resolvePool = (p) => { seenPools.push(p); return realResolve(p); };
  await startRun({ poolId: pool, dir, deps: recording });
  ok("the income binding resolves the requested pool identifier",
    seenPools.includes(pool));
}
{
  // the measurement's payability exclusions: a self-share and a
  // below-minimum row never count undistributed, a payable row does
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { rowsFor: () => [
    { accrualId: A1, amountCredits: "1000000", recipientId: h32("71") },
    { accrualId: A2, amountCredits: "99999", recipientId: h32("72") },
    { accrualId: B6, amountCredits: "500000", recipientId: I }] });
  const r = await startRun({ poolId: pool, dir, deps });
  ok("undistributed counts only payable entitlements without receipts",
    r.undistributedCredits === "1000000");
  // the excluded below-minimum value is REPORTED, never vanished: the
  // carried sum holds exactly the below-minimum non-self amount, and the
  // journaled measurement carries the member
  const readBack = openValidatedJournal(pool, dir);
  const lagRec = readBack.records[0];
  ok("the below-minimum exclusion is reported as carriedCredits",
    r.carriedCredits === "99999" && lagRec.carriedCredits === "99999"
    && lagRec.undistributedCredits === "1000000");
  ok("the semantic reader surfaces the carried member (a reader that drops it hides the deferral)",
    readBack.latestLagMeasurement.carriedCredits === "99999"
    && readBack.latestLagMeasurement.undistributedCredits === "1000000");
}
{
  // A STUCK BELOW-MINIMUM ROW IS BOTH, and the two figures say so. It is
  // outstanding PROCESS state, because journaled transfer machinery sits on its
  // accrual with no receipt, and it is a DEFERRAL, because the carry rule defers a
  // below-minimum amount whatever machinery sits on it. Reporting it in both is
  // truthful; reporting it in only one is what let an earlier epoch's stuck amount
  // be counted as payable AND folded into the frontier's deferral (a review's
  // finding), and what let a complete frontier report nothing while the carry rule
  // required the next epoch to contain the amount.
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const rows = () => [{ accrualId: A1, amountCredits: "495", recipientId: h32("71") }];
  const deps = mkDeps(pool, dir, { rowsFor: rows });
  const first = await startRun({ poolId: pool, dir, deps });
  ok("a fresh below-minimum row is deferred and owes nothing outstanding",
    first.undistributedCredits === "0" && first.carriedCredits === "495");
  const tB = "0a0b0005" + A1.slice(0, 4);
  appendChecked(pool, dir, { v: 1, kind: K.WRITE_AHEAD, object: "transfer", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, transitionBytes: tB, transitionHash: sha(tB) });
  const second = await startRun({ poolId: pool, dir, deps });
  ok("the same row with journaled machinery is reported in BOTH figures: outstanding process state, and still deferred by the carry rule",
    second.undistributedCredits === "495" && second.carriedCredits === "495");
}
{
  // machinery accounting is PER ACCRUAL, and the distinct amounts bind
  // each row to its side: two below-minimum rows, machinery on exactly
  // one; the machinery-free row (496) is carried, the stuck row (495) is
  // undistributed
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const rows = () => [{ accrualId: A1, amountCredits: "495", recipientId: h32("71") },
    { accrualId: A2, amountCredits: "496", recipientId: h32("72") }];
  const deps = mkDeps(pool, dir, { rowsFor: rows });
  await startRun({ poolId: pool, dir, deps });
  const tB = "0a0b0005" + A1.slice(0, 4);
  appendChecked(pool, dir, { v: 1, kind: K.WRITE_AHEAD, object: "transfer", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, transitionBytes: tB, transitionHash: sha(tB) });
  const r = await startRun({ poolId: pool, dir, deps });
  ok("machinery on one accrual never declassifies its below-minimum sibling: the stuck 495 is outstanding, and BOTH below-minimum rows are deferred",
    r.undistributedCredits === "495" && r.carriedCredits === "991");
}
{
  // COMPLETENESS ENDS THE OUTSTANDING REPORT, NEVER THE DEFERRAL. An earlier version of
  // this case pinned the opposite, both figures zero, which was the direct consequence of
  // deriving the deferral through the journal-aware sum: completeness removed it from one
  // figure and the machinery exclusion from the other, so an amount the carry rule still
  // defers was reported nowhere. That is exactly the disappearance the carried figure
  // exists to prevent, and a review caught the test approving it.
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const rows = () => [{ accrualId: A1, amountCredits: "495", recipientId: h32("71") }];
  let done = false;
  const deps = mkDeps(pool, dir, { rowsFor: rows, complete: () => done });
  await startRun({ poolId: pool, dir, deps });
  const tB = "0a0b0005" + A1.slice(0, 4);
  appendChecked(pool, dir, { v: 1, kind: K.WRITE_AHEAD, object: "transfer", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, transitionBytes: tB, transitionHash: sha(tB) });
  const incomplete = await startRun({ poolId: pool, dir, deps });
  ok("while the epoch is INCOMPLETE the stuck row is outstanding AND deferred",
    incomplete.undistributedCredits === "495" && incomplete.carriedCredits === "495");
  done = true;
  const complete = await startRun({ poolId: pool, dir, deps });
  ok("once the lifecycle calls the epoch COMPLETE it stops being outstanding, and the deferral REMAINS VISIBLE rather than vanishing with it",
    complete.undistributedCredits === "0" && complete.carriedCredits === "495" && complete.lag === 0);
}
{
  // ---- THE LIFECYCLE ANSWER MUST BE A STRICT BOOLEAN ----
  // `epochDistributionComplete` is compared with `!== true` at both call sites and neither
  // awaits it. A real completeness check reads Platform documents and is therefore
  // asynchronous, and a Promise is not strictly equal to true, so an honest asynchronous
  // implementation was read as "every epoch incomplete" with nothing said. Reproduced
  // before this guard: the same answers supplied synchronously gave lag 1, and supplied
  // asynchronously gave lag 2.
  //
  // THE GUARD DOES NOT MAKE THE SEAM ASYNCHRONOUS. That is a larger decision. It makes the
  // seam REFUSE what it cannot correctly read, so the next implementation that gets this
  // wrong is stopped by name instead of quietly changing the measurement.
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  await rejects("an ASYNCHRONOUS completeness answer refuses rather than being read as incomplete",
    startRun({ poolId: pool, dir, deps: mkDeps(pool, dir, { complete: async () => true }) }),
    /must answer a strict boolean/);
  const pool2 = freshPool();
  const dir2 = caseDir();
  setStart(pool2, "5", { dir: dir2 });
  await rejects("a TRUTHY non-boolean answer refuses too, rather than being read as incomplete",
    startRun({ poolId: pool2, dir: dir2, deps: mkDeps(pool2, dir2, { complete: () => "yes" }) }),
    /must answer a strict boolean/);
  const pool3 = freshPool();
  const dir3 = caseDir();
  setStart(pool3, "5", { dir: dir3 });
  await rejects("undefined refuses, rather than defaulting to incomplete",
    startRun({ poolId: pool3, dir: dir3, deps: mkDeps(pool3, dir3, { complete: () => undefined }) }),
    /must answer a strict boolean/);
  // and the same guard protects the epoch SELECTION, not only the measurement
  const pool4 = freshPool();
  const dir4 = caseDir();
  setStart(pool4, "5", { dir: dir4 });
  let answers = 0;
  // startRun's loop consults it once for the single-epoch universe; the SECOND
  // consultation is pickNextEpoch's, inside the header step
  const deps4 = mkDeps(pool4, dir4, { complete: () => (answers++ < 1 ? false : Promise.resolve(true)) });
  const run4 = await startRun({ poolId: pool4, dir: dir4, deps: deps4 });
  await rejects("the epoch selection refuses a non-boolean too, so a bad answer cannot silently pick the first epoch forever",
    runHeaderStep({ poolId: pool4, dir: dir4, deps: deps4, run: run4 }),
    /must answer a strict boolean/);
}
{
  // ---- runFromJournal: THE CONSECUTIVE RUN A POOL'S JOURNAL EVIDENCES ----
  // The store-wide admission asks a per-pool resolver about whatever epochs each journal
  // holds, one at a time, which is not a run. A resolver answering those from a PRE-CARRY
  // split under-reserves the income identity's funding once any pool's run passes one
  // epoch, because the admission sums those amounts. This is the shape that answers them.
  //
  // THE MUTATION LIST WAS WRITTEN BEFORE THESE CASES: the gap refusal dropped so a hole is
  // skipped; the run started at zero rather than the configured start; the fee-above-gross
  // refusal dropped; the distributable amount computed as gross with the fee ignored; and
  // the walk stopped after the first epoch. The commit message records the run.
  //
  // The fixtures go through startRun first, because the journal's own validator requires
  // the pool's first record to be the run-start measurement that binds the configured
  // start (a soundness-review finding). Headers are appended over that, which is the order a real writer
  // produces them in.
  const hdrOn = (pool, dir, epochIndex, gross, fee, first) => appendChecked(pool, dir, {
    v: 1, kind: K.WRITE_AHEAD, object: "header", gen: 1, poolId: pool, epochIndex,
    transitionBytes: "0a0b" + String(epochIndex).padStart(4, "0"),
    transitionHash: sha("0a0b" + String(epochIndex).padStart(4, "0")),
    expectedDocumentId: h32(String(90 + epochIndex).slice(0, 2)),
    expectedContents: { poolId: pool, epochIndex, grossCredits: gross, feeCredits: fee,
      allocationHash: h32("ee"), memberCount: 2, calcVersion: 1 },
    ...(first ? { configuredStartEpoch: 5 } : {}) });

  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  await startRun({ poolId: pool, dir, deps: mkDeps(pool, dir, { rowsFor: () => [] }) });
  hdrOn(pool, dir, 5, 1000, 10, true);
  hdrOn(pool, dir, 6, 2000, 0, false);
  okTry("the run is the journal's consecutive epochs from the configured start, each carrying gross MINUS fee and the header figures it came from",
    () => { const r = runFromJournal(openValidatedJournal(pool, dir));
      return r.length === 2
        && r[0].number === 5 && r[0].distributableCredits === "990"
        && r[0].grossCredits === "1000" && r[0].feeCredits === "10" && r[0].memberCount === 2
        && r[1].number === 6 && r[1].distributableCredits === "2000"
        && r[1].grossCredits === "2000" && r[1].feeCredits === "0"; });
}
{
  // A GAP REFUSES rather than being skipped: the missing epoch's owed amounts never
  // entered the carry, so every epoch above it would be recomputed short by exactly that
  // contribution and the answer would look ordinary.
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  await startRun({ poolId: pool, dir, deps: mkDeps(pool, dir, { rowsFor: () => [] }) });
  const hdr = (epochIndex, gross, first) => appendChecked(pool, dir, {
    v: 1, kind: K.WRITE_AHEAD, object: "header", gen: 1, poolId: pool, epochIndex,
    transitionBytes: "0a0c" + String(epochIndex).padStart(4, "0"),
    transitionHash: sha("0a0c" + String(epochIndex).padStart(4, "0")),
    expectedDocumentId: h32(String(70 + epochIndex).slice(0, 2)),
    expectedContents: { poolId: pool, epochIndex, grossCredits: gross, feeCredits: 0,
      allocationHash: h32("ee"), memberCount: 2, calcVersion: 1 },
    ...(first ? { configuredStartEpoch: 5 } : {}) });
  hdr(5, 1000, true);
  hdr(7, 3000, false);
  throws("a journal evidencing epoch 7 but not 6 refuses the run rather than skipping the hole",
    () => runFromJournal(openValidatedJournal(pool, dir)),
    /evidences epoch 7 but not epoch 6/);
}
{
  // A POOL WITH NO JOURNALED HEADER IS NOT AN ERROR, it is a pool with nothing to
  // recompute, so the run is empty rather than a refusal.
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  await startRun({ poolId: pool, dir, deps: mkDeps(pool, dir, { rowsFor: () => [] }) });
  okTry("a journal with a measurement but no header evidences an EMPTY run, not a refusal",
    () => JSON.stringify(runFromJournal(openValidatedJournal(pool, dir))) === "[]");
}
{
  // THE REMAINING THREE CASES CALL runFromJournal DIRECTLY, because the shapes they cover
  // cannot come through openValidatedJournal: that reader refuses a journal whose first
  // record does not bind the configured start, and it is the exported function a caller
  // reaches. AN UNEXPECTED THROW IS RECORDED AS A FAILURE HERE rather than ending the
  // process, because one of these was a mutation that crashed this suite instead of
  // failing an assertion, which reads as a detection but observes nothing.
  const readOf = (start, perEpoch) => ({ configuredStartEpoch: start, perEpoch });
  const header = (gross, fee) => ({ header: { grossCredits: gross, feeCredits: fee } });

  okTry("the walk begins AT the configured start, so an epoch below it is not in the run even when the journal holds one",
    () => { const r = runFromJournal(readOf(5, {
      3: header(9999, 0), 5: header(1000, 0), 6: header(2000, 0) }));
      return r.length === 2 && r[0].number === 5 && r[1].number === 6
        && r[0].distributableCredits === "1000" && r[1].distributableCredits === "2000"; });
  throws("a journaled header whose fee exceeds its gross refuses rather than yielding a negative distributable amount",
    () => runFromJournal(readOf(5, { 5: header(100, 200) })),
    /feeCredits 200 above grossCredits 100/);
  // AN EMPTY RUN IS AN ANSWER ABOUT THE EVIDENCE. With no configured start there is no
  // base for the recursion, so answering "nothing to recompute" over a journal that DOES
  // carry header numbers would be an affirmative result from a check that never looked.
  throws("a read carrying header numbers but binding no configured start REFUSES rather than answering empty",
    () => runFromJournal(readOf(undefined, { 0: header(1000, 0) })),
    /evidences header numbers for epoch 0 but binds no configured start/);
  okTry("a read with neither a configured start nor any header numbers is genuinely empty",
    () => JSON.stringify(runFromJournal(readOf(undefined, {}))) === "[]");
  // ONE ALLOCATION IS APPLIED TO A WHOLE RUN, so a run spanning an allocation change would
  // recompute an epoch under membership it was not written under, and the carry threaded
  // through it would be one member's claim credited to another.
  const alloc = (gross, hash, members) => ({ header: { grossCredits: gross, feeCredits: 0,
    allocationHash: hash, memberCount: members } });
  throws("a run whose journaled headers disagree about the allocation HASH refuses",
    () => runFromJournal(readOf(5, { 5: alloc(1000, "aa", 2), 6: alloc(2000, "bb", 2) })),
    /carries a different allocation than epoch 5/);
  throws("a run whose journaled headers disagree about the MEMBER COUNT refuses",
    () => runFromJournal(readOf(5, { 5: alloc(1000, "aa", 2), 6: alloc(2000, "aa", 3) })),
    /carries a different allocation than epoch 5/);
  okTry("a run whose headers agree about the allocation is accepted",
    () => runFromJournal(readOf(5, { 5: alloc(1000, "aa", 2), 6: alloc(2000, "aa", 2) })).length === 2);
}
{
  // AN EMPTY UNIVERSE REPORTS ZERO AS A SPECIFIED IDENTITY, not as a value a loop that
  // never ran happened to leave behind. With no finalized epoch, nothing can have been
  // deferred. The measurement is still appended, because it is what binds the configured
  // start on a pool's first run.
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "9", { dir });
  const deps = mkDeps(pool, dir, { universeTop: 5,
    rowsFor: () => { throw new Error("no epoch should be asked for in an empty universe"); } });
  const r = await startRun({ poolId: pool, dir, deps });
  ok("an empty universe reports a deferral of zero, with no lag and nothing undistributed",
    r.universe.length === 0 && r.carriedCredits === "0"
    && r.lag === 0 && r.undistributedCredits === "0");
  ok("and the measurement is still journaled, carrying the configured start it binds",
    (() => { const rec = openValidatedJournal(pool, dir).records[0];
      return rec.carriedCredits === "0" && rec.configuredStartEpoch === 9; })());
}
{
  // ---- a soundness-review finding: THE CARRIED FIGURE IS A STOCK AT THE FRONTIER, NOT A SUM ----
  // These four cases are the ONLY ones in this file with a universe wider than one
  // epoch, which is why the correction was invisible to the suite until now: over a
  // single epoch a sum and a frontier stock are the same number.
  //
  // A carry-capable calculation supplies EFFECTIVE amounts, so epoch 6's row already
  // contains epoch 5's deferral. Epoch 5 defers 40000; epoch 6 is owed another 40000 and
  // carries 40000 in, for an effective 80000 that is still below the pinned minimum.
  // THE DEFERRED VALUE IS 80000. Summing the epochs gives 120000, which counts the first
  // epoch's 40000 twice, once in its own epoch and again inside the second's effective
  // amount.
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { universeTop: 6, rowsFor: (epoch) => (epoch === 5
    ? [{ accrualId: A1, amountCredits: "40000", recipientId: h32("71") }]
    : [{ accrualId: A2, amountCredits: "80000", recipientId: h32("71"), carryInCredits: "40000" }]) });
  const r = await startRun({ poolId: pool, dir, deps });
  ok("the carried figure is the FRONTIER epoch's deferral (80000), not the sum across epochs (120000) that counts one deferral once per epoch it survives into",
    r.carriedCredits === "80000" && r.lag === 2 && r.undistributedCredits === "0");
  const lagRec = openValidatedJournal(pool, dir).records[0];
  ok("and the journaled record carries the stock, since a wrong definition would be written durably",
    lagRec.carriedCredits === "80000");
}
{
  // A ROW SOURCE THAT LOSES A DEFERRAL REFUSES. The frontier stock is correct only if
  // each epoch's rows already contain the previous epoch's deferral, and an omitted
  // carryInCredits cannot tell a zero carry from a calculation that forgot. What CAN be
  // told is a shrinking amount: a member deferred 40000 cannot be owed 30000 next epoch,
  // because effective is that deferral plus something non-negative.
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { universeTop: 6, rowsFor: (epoch) => (epoch === 5
    ? [{ accrualId: A1, amountCredits: "40000", recipientId: h32("71") }]
    : [{ accrualId: A2, amountCredits: "30000", recipientId: h32("71") }]) });
  await rejects("a row source whose next-epoch amount is BELOW the deferral it was handed refuses the run",
    startRun({ poolId: pool, dir, deps }), /below the 40000 deferred to it by the previous epoch/);
  // AND THE CHECK'S WIDTH IS PINNED, not left to be assumed: a source answering EXACTLY
  // the deferral is indistinguishable from a conforming one whose member was owed
  // nothing that epoch, so it is accepted. The owed amount is what the writer delegates.
  const pool2 = freshPool();
  const dir2 = caseDir();
  setStart(pool2, "5", { dir: dir2 });
  const deps2 = mkDeps(pool2, dir2, { universeTop: 6, rowsFor: () => [
    { accrualId: A1, amountCredits: "40000", recipientId: h32("71") }] });
  const r2 = await startRun({ poolId: pool2, dir: dir2, deps: deps2 });
  ok("a source repeating exactly the deferral is ACCEPTED, which is the stated limit of what this check can see",
    r2.carriedCredits === "40000");
}
{
  // AND A DEFERRAL CANNOT VANISH BY ITS MEMBER LEAVING THE ROW SET, which is the same
  // loss wearing a different shape.
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { universeTop: 6, rowsFor: (epoch) => (epoch === 5
    ? [{ accrualId: A1, amountCredits: "40000", recipientId: h32("71") }]
    : [{ accrualId: A2, amountCredits: "500000", recipientId: h32("72") }]) });
  await rejects("a member who was deferred to and is absent from the next epoch's rows refuses the run",
    startRun({ poolId: pool, dir, deps }), /carries no row for .*to whom the previous epoch deferred 40000/);
}
{
  // THE FLOW HALF STILL ACCUMULATES. The correction is to the carried figure alone, and
  // a change that turned undistributed into a stock too would pass every assertion above.
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { universeTop: 6, rowsFor: (epoch) => (epoch === 5
    ? [{ accrualId: A1, amountCredits: "200000", recipientId: h32("71") }]
    : [{ accrualId: A2, amountCredits: "300000", recipientId: h32("72") }]) });
  const r = await startRun({ poolId: pool, dir, deps });
  ok("undistributed SUMS across incomplete epochs (200000 + 300000), because outstanding payables are a flow",
    r.undistributedCredits === "500000" && r.carriedCredits === "0" && r.lag === 2);
}
{
  // A COMPLETED EPOCH'S DEFERRAL IS STILL REPORTED, which the previous scope dropped.
  // Under the carry rule an epoch completing does not settle a below-minimum amount: it
  // is deferred into the next epoch and is still owed to that member.
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { complete: () => true,
    rowsFor: () => [{ accrualId: A1, amountCredits: "70000", recipientId: h32("71") }] });
  const r = await startRun({ poolId: pool, dir, deps });
  ok("a COMPLETE epoch's below-minimum amount is still reported as deferred, with no lag and nothing undistributed",
    r.carriedCredits === "70000" && r.lag === 0 && r.undistributedCredits === "0");
}
{
  // THE FRONTIER IS THE LAST UNIVERSE EPOCH, not the last INCOMPLETE one. Epoch 5 is
  // incomplete and defers 30000; epoch 6 is complete and defers 90000. A frontier that
  // tracked only incomplete epochs would answer 30000.
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { universeTop: 6, complete: (epoch) => epoch === 6,
    rowsFor: (epoch) => (epoch === 5
      ? [{ accrualId: A1, amountCredits: "30000", recipientId: h32("71") }]
      : [{ accrualId: A2, amountCredits: "90000", recipientId: h32("71"), carryInCredits: "30000" }]) });
  const r = await startRun({ poolId: pool, dir, deps });
  ok("the frontier is the newest finalized epoch even when it is COMPLETE and an earlier one is not",
    r.carriedCredits === "90000" && r.lag === 1 && r.undistributedCredits === "0");
}
{
  // a SELF-SHARE with stuck machinery is outstanding process state: it
  // keeps the undistributed accounting instead of vanishing from both
  // sums (a machinery-free self-share stays in neither)
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const rows = () => [{ accrualId: A1, amountCredits: "495", recipientId: I }];
  const deps = mkDeps(pool, dir, { rowsFor: rows });
  const first = await startRun({ poolId: pool, dir, deps });
  ok("a machinery-free self-share appears in neither sum",
    first.undistributedCredits === "0" && first.carriedCredits === "0");
  const tB = "0a0b0005" + A1.slice(0, 4);
  appendChecked(pool, dir, { v: 1, kind: K.WRITE_AHEAD, object: "transfer", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, transitionBytes: tB, transitionHash: sha(tB) });
  const second = await startRun({ poolId: pool, dir, deps });
  ok("a self-share with stuck machinery counts undistributed, never vanishing",
    second.undistributedCredits === "495" && second.carriedCredits === "0");
}
{
  // one row per member per epoch: the allocation's owner uniqueness is
  // restated at the writer's row-consumption site
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { rowsFor: () => [
    { accrualId: A1, amountCredits: "60000", recipientId: h32("71") },
    { accrualId: A2, amountCredits: "60000", recipientId: h32("71") }] });
  await rejects("two entitlement rows sharing one owner refuse the run",
    startRun({ poolId: pool, dir, deps }),
    /two entitlement rows share one owner/);
}
{
  // ... and the SAME refusal fires at the transfer step's own row fetch,
  // so a calculation swapped after startRun cannot smuggle a duplicate
  const pool = freshPool();
  const dir = caseDir();
  const { run } = await openEpoch(pool, dir);
  const swapped = mkDeps(pool, dir, { rowsFor: () => [
    { accrualId: A1, amountCredits: "60000", recipientId: h32("71") },
    { accrualId: A2, amountCredits: "60000", recipientId: h32("71") }] });
  await rejects("two rows sharing one owner refuse the transfer step too",
    runTransferStep({ poolId: pool, dir, deps: swapped, run, epochIndex: 5, accrualId: A1 }),
    /two entitlement rows share one owner/);
}
{
  // a classification is corrected-era at APPEND TIME: it refuses while
  // the journal's latest measurement lacks carriedCredits (the
  // corrected measurement runs first), lands once a carried measurement
  // is the latest, and the monotonic rule then covers every later
  // measurement, so a classified journal's latest measurement always
  // reports
  const pool = freshPool();
  const dir = caseDir();
  appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "pool", gen: 1,
    poolId: pool, condition: "lag-measurement", reasoning: "r", lagCount: 1,
    undistributedCredits: "0", configuredStartEpoch: 5 });
  throws("a classification over a stale latest measurement refuses",
    () => appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1,
      poolId: pool, epochIndex: 5, accrualId: A1, condition: "self-share-settled",
      reasoning: "r", amountCredits: "495" }),
    /latest lag-measurement lacks carriedCredits/);
  appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "pool", gen: 1,
    poolId: pool, condition: "lag-measurement", reasoning: "r", lagCount: 1,
    undistributedCredits: "0", carriedCredits: "495" });
  appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, condition: "self-share-settled",
    reasoning: "r", amountCredits: "495" });
  ok("the classification lands once a carried measurement is the latest",
    openValidatedJournal(pool, dir).records.some((x) => x.condition === "self-share-settled"));
  throws("a later measurement without the member refuses (monotonic)",
    () => appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "pool", gen: 1,
      poolId: pool, condition: "lag-measurement", reasoning: "r", lagCount: 1,
      undistributedCredits: "0" }),
    /monotonic once present/);
}
{
  // a journaled classification never substitutes for the row: a
  // declaration that does not describe the current recomputed row
  // REFUSES the step instead of silently suppressing a payable transfer
  const pool = freshPool();
  const dir = caseDir();
  const rows = () => [{ accrualId: A1, amountCredits: "1000000", recipientId: h32("71") }];
  const { deps, run } = await openEpoch(pool, dir, { rowsFor: rows });
  appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, condition: "self-share-settled",
    reasoning: "r", amountCredits: "1000000" });
  await rejects("a self-share declaration over a payable row refuses on resume",
    runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 }),
    /disagrees with the recomputed row/);
}
{
  // ... and an amount mismatch refuses even when the condition matches
  const pool = freshPool();
  const dir = caseDir();
  const rows = () => [{ accrualId: A1, amountCredits: "500000", recipientId: I }];
  const { deps, run } = await openEpoch(pool, dir, { rowsFor: rows });
  appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, condition: "self-share-settled",
    reasoning: "r", amountCredits: "400000" });
  await rejects("a self-share declaration with a differing amount refuses on resume",
    runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 }),
    /disagrees with the recomputed row/);
}
{
  // ... and a below-minimum declaration whose row is now payable refuses
  const pool = freshPool();
  const dir = caseDir();
  const rows = () => [{ accrualId: A1, amountCredits: "1000000", recipientId: h32("71") }];
  const { deps, run } = await openEpoch(pool, dir, { rowsFor: rows });
  appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, condition: "transfer-below-minimum",
    reasoning: "r", amountCredits: "99999", minimumCredits: "100000" });
  await rejects("a below-minimum declaration over a payable row refuses on resume",
    runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 }),
    /disagrees with the recomputed row/);
}
{
  // startRun requires the income identity: the exclusions compare it, so
  // its absence is a refusal, never a sum over unclassifiable rows
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir);
  const noIncome = { ...deps, identities: { writer: W } };
  await rejects("startRun refuses without the income identity",
    startRun({ poolId: pool, dir, deps: noIncome }), /needs deps\.identities\.income/);
}
{
  // the D7 validator's closed payloads for the classification declarations
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  await startRun({ poolId: pool, dir, deps: mkDeps(pool, dir) });
  const base = { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1, poolId: pool,
    epochIndex: 5, accrualId: A1, reasoning: "r" };
  throws("self-share-settled without amountCredits refuses",
    () => appendChecked(pool, dir, { ...base, condition: "self-share-settled" }),
    /missing member amountCredits/);
  throws("a non-canonical amount refuses",
    () => appendChecked(pool, dir, { ...base, condition: "self-share-settled", amountCredits: "0495" }),
    /amountCredits must be a canonical decimal/);
  throws("transfer-below-minimum without minimumCredits refuses",
    () => appendChecked(pool, dir, { ...base, condition: "transfer-below-minimum", amountCredits: "495" }),
    /missing member minimumCredits/);
  throws("an extra member refuses (the member list is closed)",
    () => appendChecked(pool, dir, { ...base, condition: "self-share-settled", amountCredits: "495", extra: 1 }),
    /extra member/);
  throws("a classification declaration binds the accrual object",
    () => appendChecked(pool, dir, { ...base, object: "epoch", condition: "self-share-settled", amountCredits: "495" }),
    /binds object accrual/);
  throws("a zero amount refuses (a zero entitlement is never classified)",
    () => appendChecked(pool, dir, { ...base, condition: "self-share-settled", amountCredits: "0" }),
    /must be positive/);
  throws("a non-canonical carriedCredits refuses the measurement record",
    () => appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "pool", gen: 1,
      poolId: pool, condition: "lag-measurement", reasoning: "r", lagCount: 0,
      undistributedCredits: "0", carriedCredits: "-5" }),
    /carriedCredits must be a canonical decimal/);
  // the member is MONOTONIC: the startRun above already wrote a
  // measurement carrying it, so a later one without it refuses
  throws("a measurement without carriedCredits after one that carried it refuses",
    () => appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "pool", gen: 1,
      poolId: pool, condition: "lag-measurement", reasoning: "r", lagCount: 0,
      undistributedCredits: "0" }),
    /monotonic once present/);
  throws("a minimum other than the pin refuses",
    () => appendChecked(pool, dir, { ...base, condition: "transfer-below-minimum",
      amountCredits: "495", minimumCredits: "0" }),
    /must equal the pinned minimum/);
  throws("an amount at or above the pinned minimum refuses the below-minimum condition",
    () => appendChecked(pool, dir, { ...base, condition: "transfer-below-minimum",
      amountCredits: "100000", minimumCredits: "100000" }),
    /must be below the pinned minimum/);
  appendChecked(pool, dir, { ...base, condition: "transfer-below-minimum",
    amountCredits: "495", minimumCredits: "100000" });
  const stored = openValidatedJournal(pool, dir).records
    .filter((x) => x.condition === "transfer-below-minimum");
  ok("a well-formed classification declaration validates and commits",
    stored.length === 1 && stored[0].accrualId === A1
    && stored[0].amountCredits === "495" && stored[0].minimumCredits === "100000");
  // EXCLUSIVITY: at most one classification per accrual, either condition
  throws("a duplicate classification declaration refuses",
    () => appendChecked(pool, dir, { ...base, condition: "transfer-below-minimum",
      amountCredits: "495", minimumCredits: "100000" }),
    /second classification declaration/);
  throws("the other classification condition on the same accrual refuses too",
    () => appendChecked(pool, dir, { ...base, condition: "self-share-settled", amountCredits: "495" }),
    /second classification declaration/);
  // ... and transfer machinery over a classified accrual refuses
  const tB = "0a0b0005" + A1.slice(0, 4);
  throws("a transfer write-ahead for a classified accrual refuses",
    () => appendChecked(pool, dir, { v: 1, kind: K.WRITE_AHEAD, object: "transfer", gen: 1,
      poolId: pool, epochIndex: 5, accrualId: A1, transitionBytes: tB, transitionHash: sha(tB) }),
    /record for a classified accrual/);
}

// ---- the two-value migration comparison (the decided carry rule) ----
{
  // a below-minimum declaration written PRE-CARRY carries the owed-only
  // amount; the resumed comparison accepts it alongside the effective
  // amount, and refuses anything else
  const pool = freshPool();
  const dir = caseDir();
  const rows = () => [{ accrualId: A1, amountCredits: "70000", carryInCredits: "40000",
    recipientId: h32("71") }];
  const { deps, run } = await openEpoch(pool, dir, { rowsFor: rows });
  appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, condition: "transfer-below-minimum",
    reasoning: "r", amountCredits: "30000", minimumCredits: "100000" });
  const r1 = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 });
  ok("a pre-carry declaration's owed-only amount is honored on resume",
    r1.status === "below-minimum-carried");
}
{
  // ... the effective amount is honored too, and a third value refuses
  const pool = freshPool();
  const dir = caseDir();
  const rows = () => [{ accrualId: A1, amountCredits: "70000", carryInCredits: "40000",
    recipientId: h32("71") }];
  const { deps, run } = await openEpoch(pool, dir, { rowsFor: rows });
  appendChecked(pool, dir, { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1,
    poolId: pool, epochIndex: 5, accrualId: A1, condition: "transfer-below-minimum",
    reasoning: "r", amountCredits: "70000", minimumCredits: "100000" });
  const r1 = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 });
  ok("the effective amount is honored on resume", r1.status === "below-minimum-carried");
  const pool2 = freshPool();
  const dir2 = caseDir();
  const { deps: d2, run: run2 } = await openEpoch(pool2, dir2, { rowsFor: rows });
  appendChecked(pool2, dir2, { v: 1, kind: K.DECLARATION, object: "accrual", gen: 1,
    poolId: pool2, epochIndex: 5, accrualId: A1, condition: "transfer-below-minimum",
    reasoning: "r", amountCredits: "50000", minimumCredits: "100000" });
  await rejects("a third value refuses (neither effective nor owed-only)",
    runTransferStep({ poolId: pool2, dir: dir2, deps: d2, run: run2, epochIndex: 5, accrualId: A1 }),
    /neither the effective nor the owed-only amount/);
}
{
  // the carry-in member's own grammar and invariants refuse loudly
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const mk = (carry, amount) => mkDeps(pool, dir, { rowsFor: () => [
    { accrualId: A1, amountCredits: amount, carryInCredits: carry, recipientId: h32("71") }] });
  await rejects("a malformed carryInCredits refuses",
    startRun({ poolId: pool, dir, deps: mk("1e4", "70000") }),
    /carryInCredits must be a canonical decimal/);
  await rejects("a carry-in at the pinned minimum refuses (a carried amount never reaches it)",
    startRun({ poolId: pool, dir, deps: mk("100000", "150000") }),
    /below the pinned minimum/);
  await rejects("a carry-in above the effective amount refuses",
    startRun({ poolId: pool, dir, deps: mk("80000", "70000") }),
    /cannot exceed its effective/);
  const okRun = await startRun({ poolId: pool, dir, deps: mk("40000", "70000") });
  ok("a well-formed carried row measures as carried", okRun.carriedCredits === "70000");
}

// ---- the closing wave's part D folds, which are the row grammar at
// every consumption site, the closed classifier export, and the decided
// carry semantics pinned at the declaration and transfer sites ----
{
  // the ACCRUAL step is the fourth consumption site. A calculation
  // swapped in after the header cannot put durable accrual documents
  // under a row set the grammar refuses
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir);
  // the FIRST row is valid and the violation is the SECOND row, a
  // self-share carrying explicit nonzero carry-in, so this case binds
  // three properties at once. The refusal must come from validating
  // the WHOLE set (a first-row-only sweep passes the first row), it
  // must come from the income-identity comparison (a wrong identity
  // argument at this site sees no self-share), and no accrual document
  // may be written for the refused set (no partial writes)
  deps.entitlementsForEpoch = () => [
    { accrualId: A1, amountCredits: "1000000", recipientId: h32("71") },
    { accrualId: A2, amountCredits: "70000", carryInCredits: "40000", recipientId: I }];
  await rejects("the accrual step refuses a swapped-in row set the grammar refuses",
    runAccrualStep({ poolId: pool, dir, deps, run, epochIndex: 5 }),
    /self-share row cannot carry a nonzero carryInCredits/);
  ok("no accrual document was written for the refused set (whole-set refusal, no partial writes)",
    deps._calls.docWrites.filter((w) => w.object === "accrual").length === 0);
}
{
  // the HEADER site through the same swap route. A fresh header step
  // validates the rows it fetches, income identity included
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir);
  const run = await startRun({ poolId: pool, dir, deps });
  deps.entitlementsForEpoch = () => [
    { accrualId: A1, amountCredits: "70000", carryInCredits: "40000", recipientId: I }];
  await rejects("the header step refuses a swapped-in self-share row carrying nonzero carry-in",
    runHeaderStep({ poolId: pool, dir, deps, run }),
    /self-share row cannot carry a nonzero carryInCredits/);
}
{
  // THE UPGRADE BOUNDARY'S ENFORCEMENT (the decided epoch-boundary
  // rule, part A of the wave). Accruals written under one calculation
  // mismatch-stop when a different calculation resumes the epoch, so a
  // mid-epoch upgrade is an operator-visible hard stop, never a silent
  // divergence between the on-ledger amounts and the audit's expected
  // set. The stop's reach is the rows the calculations share (the
  // spec's stated width). A membership-changing swap is the row trust
  // boundary's territory, and its records are caught downstream, a
  // removal or substitution by the audit's expected set, an additive
  // swap by the header commitment (memberCount and the allocation
  // hash, frozen at the epoch's start)
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir);
  const first = await runAccrualStep({ poolId: pool, dir, deps, run, epochIndex: 5 });
  ok("the pre-upgrade accruals write clean", first.complete === true);
  deps.entitlementsForEpoch = () => [
    { accrualId: A1, amountCredits: "1040000", carryInCredits: "40000", recipientId: h32("71") },
    { accrualId: A2, amountCredits: "500000", recipientId: h32("72") }];
  const resumed = await runAccrualStep({ poolId: pool, dir, deps, run, epochIndex: 5 });
  ok("a mid-epoch calculation upgrade surfaces as the accrual mismatch-stop",
    resumed.statuses[0].status === "mismatch-stop" && resumed.complete === false);
}
{
  // a self-share row with an explicit nonzero carry-in refuses at the
  // ROW GRAMMAR, every consumption site, not only at classification.
  // The epoch is COMPLETE, so the classifier never runs and the rows
  // path is the only refusing site (a classify-covered fixture would
  // pass with the rows branch deleted, the mutation check's lesson)
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { complete: () => true, rowsFor: () => [
    { accrualId: A1, amountCredits: "70000", carryInCredits: "40000", recipientId: I }] });
  await rejects("a self-share row carrying nonzero carryInCredits refuses at the row grammar",
    startRun({ poolId: pool, dir, deps }),
    /self-share row cannot carry a nonzero carryInCredits/);
}
{
  // the income identity is a REQUIRED argument of the row grammar, so
  // a caller that cannot name it refuses outright instead of silently
  // skipping the self-share duty (the fold screen's checking). The
  // route is the accrual step, whose entry does not guard the income
  // identity itself, so the grammar's own branch is what refuses
  // (startRun guards income at its entry and never reaches it)
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir);
  delete deps.identities.income;
  await rejects("the row grammar refuses without the caller's income identity",
    runAccrualStep({ poolId: pool, dir, deps, run, epochIndex: 5 }),
    /requires the caller's income identity/);
}
{
  // the exported classifier is a CLOSED grammar for the carry member
  // on every row, so a malformed member refuses through the named path
  // whichever branch the row takes
  throws("a malformed carryInCredits on a non-self-share row refuses through the named path",
    () => classifyEntitlement({ recipientId: h32("71"), amountCredits: "70000", carryInCredits: "1e4" }, I),
    /carryInCredits must be a canonical decimal/);
  throws("a malformed carryInCredits on a self-share row refuses through the named path, never a raw construction error",
    () => classifyEntitlement({ recipientId: I, amountCredits: "70000", carryInCredits: "1e4" }, I),
    /carryInCredits must be a canonical decimal/);
  throws("a carry-in at the pinned minimum refuses through the classifier",
    () => classifyEntitlement({ recipientId: h32("71"), amountCredits: "150000", carryInCredits: "100000" }, I),
    /below the pinned minimum/);
  throws("a carry-in above the amount refuses through the classifier",
    () => classifyEntitlement({ recipientId: h32("71"), amountCredits: "70000", carryInCredits: "70001" }, I),
    /cannot exceed its effective/);
  // the SECOND argument is part of the closed grammar too (the wave's
  // repository-access pass, which reproduced payable answers for an
  // actual self-share under an undefined, malformed and truncated
  // income identity)
  throws("classification without an income identity refuses",
    () => classifyEntitlement({ recipientId: I, amountCredits: "100000" }, undefined),
    /requires the caller's income identity/);
  throws("classification with a malformed income identity refuses",
    () => classifyEntitlement({ recipientId: I, amountCredits: "100000" }, "nothex"),
    /requires the caller's income identity/);
  throws("classification with a truncated income identity refuses",
    () => classifyEntitlement({ recipientId: I, amountCredits: "100000" }, I.slice(0, 62)),
    /requires the caller's income identity/);
}
{
  // a FRESH below-minimum declaration on a row with nonzero carry-in
  // journals the EFFECTIVE amount, never the owed-only value
  const pool = freshPool();
  const dir = caseDir();
  const rows = () => [{ accrualId: A1, amountCredits: "70000", carryInCredits: "40000",
    recipientId: h32("71") }];
  const { deps, run } = await openEpoch(pool, dir, { rowsFor: rows });
  const r = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 });
  const decl = openValidatedJournal(pool, dir).records
    .filter((x) => x.condition === "transfer-below-minimum");
  ok("the fresh declaration journals the effective amount",
    r.status === "below-minimum-carried" && decl.length === 1
    && decl[0].amountCredits === "70000" && decl[0].minimumCredits === "100000"
    && openValidatedJournal(pool, dir).records.filter((x) =>
      x.condition === "self-share-settled").length === 0);
}
{
  // the TRANSFER step validates the WHOLE fetched set, not only the
  // selected row, so an invalid unselected row refuses the step before
  // any write-ahead (the fold screen's checking)
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir);
  deps.entitlementsForEpoch = () => [
    { accrualId: A1, amountCredits: "1000000", recipientId: h32("71") },
    { accrualId: A2, amountCredits: "70000", carryInCredits: "40000", recipientId: I }];
  await rejects("the transfer step refuses when any fetched row violates the grammar",
    runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 }),
    /self-share row cannot carry a nonzero carryInCredits/);
  ok("no transfer write-ahead was journaled for the refused set",
    openValidatedJournal(pool, dir).records.filter((x) =>
      x.kind === K.WRITE_AHEAD && x.object === "transfer").length === 0);
}
{
  // carry-in lifting an amount ACROSS the pin, so the transfer pays
  // the full effective amount (the spec's vector 6 second literal,
  // writer side)
  const pool = freshPool();
  const dir = caseDir();
  const rows = () => [{ accrualId: A1, amountCredits: "100000", carryInCredits: "40000",
    recipientId: h32("71") }];
  const { deps, run } = await openEpoch(pool, dir, { rowsFor: rows });
  const paidAmounts = [];
  const builtHashes = [];
  const submittedHashes = [];
  const origBuild = deps.buildTransferTransition;
  deps.buildTransferTransition = (a) => { paidAmounts.push(a.amountCredits);
    const b = origBuild(a); builtHashes.push(b.transitionHash); return b; };
  const origBroadcast = deps.broadcastAndAwait;
  deps.broadcastAndAwait = async (hash, bytes) => { submittedHashes.push(hash);
    return origBroadcast(hash, bytes); };
  const r = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 });
  const readBack = openValidatedJournal(pool, dir);
  const wa = readBack.records.find((x) => x.kind === K.WRITE_AHEAD && x.object === "transfer"
    && x.epochIndex === 5 && x.accrualId === A1);
  ok("an effective amount at the pin (owed lifted by carry) transfers the full effective",
    r.status === "completed" && paidAmounts.length === 1 && paidAmounts[0] === "100000"
    // the SUBMITTED transition is the one built for the effective
    // amount. The fold screen's checking tightened this twice,
    // first binding the builder call to the journaled write-ahead and
    // then binding the SUBMISSION argument to both, so a decoy
    // submission cannot satisfy it
    && wa !== undefined && wa.transitionHash === builtHashes[0]
    // EVERY submission observed through this dependency maps to a
    // journaled write-ahead, and the transfer's is the built
    // transition. The step submits exactly twice here, the reservation
    // then the transfer, so a submission relocated off this dependency
    // fails the count, and the harness's own sent-marker ordering gate
    // is the seam below it (any broadcast without its committed marker
    // throws)
    && submittedHashes.length === 2
    && ((resWa) => resWa !== undefined
      && submittedHashes[0] === resWa.transitionHash)(readBack.records.find((x) =>
        x.kind === K.WRITE_AHEAD && x.object === "reservation"
        && x.epochIndex === 5 && x.accrualId === A1))
    && submittedHashes[1] === builtHashes[0]
    && submittedHashes[1] === wa.transitionHash
    && readBack.records.filter((x) =>
      x.condition === "transfer-below-minimum" || x.condition === "self-share-settled").length === 0);
}

// ---- async capture builders (the live signer is async; the rehearsal
// run caught the writer consuming the builder's promise as a record) ----
{
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir);
  const origReceiptBuilder = deps.buildReceiptCapture;
  deps.buildHeaderCapture = async (a) => mkCapture(a);
  deps.buildReceiptCapture = async (a) => origReceiptBuilder(a);
  const run = await startRun({ poolId: pool, dir, deps });
  const h = await runHeaderStep({ poolId: pool, dir, deps, run });
  const t = await runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 });
  ok("async capture builders journal their resolved records end to end",
    h.status === "captured" && t.status === "completed");
}

// ---- the canonical-gate consult (the battery's every-writer rule) ----
{
  // a writer with NO gate lookup refuses before any write
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir, {});
  const noGate = { ...deps };
  delete noGate.verifyGateCapture;
  await rejects("the header step refuses without the gate lookup dependency",
    runHeaderStep({ poolId: pool, dir, deps: noGate, run }),
    /needs deps\.verifyGateCapture/);
  await rejects("the accrual step refuses without the gate lookup dependency",
    runAccrualStep({ poolId: pool, dir, deps: noGate, run, epochIndex: 5 }),
    /needs deps\.verifyGateCapture/);
  await rejects("the transfer step refuses without the gate lookup dependency",
    runTransferStep({ poolId: pool, dir, deps: noGate, run, epochIndex: 5, accrualId: A1 }),
    /needs deps\.verifyGateCapture/);
}
{
  // a lookup that THROWS (the strict lookup's refusal shape) refuses the write,
  // and nothing reaches the journal: the case observes the store, not only the
  // error text, so a mutation that catches and continues is caught
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir, {});
  const gated = { ...deps, verifyGateCapture: async () => { throw new Error("E2_GATE_CAPTURE is absent"); } };
  // the epoch-open setup already journaled records, so the observation is the
  // DELTA across the refused call, not the journal's emptiness
  const before = openJournal(pool, dir).records.length;
  await rejects("a throwing gate lookup refuses the header step",
    runHeaderStep({ poolId: pool, dir, deps: gated, run }),
    /the canonical-gate strict lookup did not admit .*absent/);
  const after = openJournal(pool, dir).records.length;
  ok("no journal record was written past the refused gate", after === before);
  // the SAME behaviour on the other two writers (the re-check found only the
  // header exercised past the missing-dep check, so a consult that type-checks
  // the dependency without calling it would leave these two green)
  await rejects("a throwing gate lookup refuses the accrual step",
    runAccrualStep({ poolId: pool, dir, deps: gated, run, epochIndex: 5 }),
    /the canonical-gate strict lookup did not admit/);
  await rejects("a throwing gate lookup refuses the transfer step",
    runTransferStep({ poolId: pool, dir, deps: gated, run, epochIndex: 5, accrualId: A1 }),
    /the canonical-gate strict lookup did not admit/);
  const nonAdmitting = { ...deps, verifyGateCapture: async () => ({}) };
  await rejects("a non-admitting lookup refuses the accrual step",
    runAccrualStep({ poolId: pool, dir, deps: nonAdmitting, run, epochIndex: 5 }),
    /returned no admission/);
  await rejects("a non-admitting lookup refuses the transfer step",
    runTransferStep({ poolId: pool, dir, deps: nonAdmitting, run, epochIndex: 5, accrualId: A1 }),
    /returned no admission/);
}
{
  // a lookup returning anything but { admitted: true } refuses (an empty
  // object, a truthy non-admission, and undefined are all the same refusal:
  // unchecked never means passed)
  const pool = freshPool();
  const dir = caseDir();
  const { deps, run } = await openEpoch(pool, dir, {});
  for (const [label, value] of [["undefined", undefined], ["an empty object", {}],
    ["admitted false", { admitted: false }], ["a truthy non-admission", { ok: true }]]) {
    const gated = { ...deps, verifyGateCapture: async () => value };
    await rejects(`a gate lookup answering ${label} refuses the header step`,
      runHeaderStep({ poolId: pool, dir, deps: gated, run }),
      /returned no admission/);
  }
}

console.log(`e2DistributeTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
})().catch((e) => { console.error("UNCAUGHT:", e); process.exitCode = 1; });
