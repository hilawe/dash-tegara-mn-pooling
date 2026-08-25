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
  startKeyOf, poolRunLockName, appendChecked } = require("./e2Distribute.cjs");

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
  const rowsFor = over.rowsFor || ((epoch) => (epoch === 5
    ? [{ accrualId: A1, amountCredits: "1000", recipientId: h32("71") },
       { accrualId: A2, amountCredits: "500", recipientId: h32("72") }]
    : [{ accrualId: B6, amountCredits: "700", recipientId: h32("73") }]));
  const complete = over.complete || (() => false);
  const deps = {
    identities: { writer: W, income: I },
    feeCeilingCredits: over.ceiling ?? "100",
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
    resolvePool: () => ({ writerIdentity: W, incomeIdentity: I,
      entitlementsForEpoch: (epoch) => rowsFor(epoch) }),
    fetchBalanceWithMetadata: async (id) => {
      calls.fetch.push(id);
      if (over.balance === "throw") throw new Error("verification failed");
      return { balance: over.balance ?? "999999",
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
    r.configuredStart === 5 && r.lag === 1 && r.undistributedCredits === "1500"
    && r.distributionLagging === false);
  const read = openValidatedJournal(pool, dir);
  ok("the pool's FIRST record is the lag measurement carrying the binding",
    read.records.length === 1 && read.records[0].condition === "lag-measurement"
    && read.records[0].configuredStartEpoch === 5 && read.configuredStartEpoch === 5);
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
    r.lag === 2 && r.undistributedCredits === "2200" && r.distributionLagging === true);
  const lagRec = openValidatedJournal(pool, dir).records[0];
  ok("the measurement records the count and sum literally",
    lagRec.lagCount === 2 && lagRec.undistributedCredits === "2200");
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
    return { r: await runHeaderStep({ poolId: pool, dir, deps, run }), deps };
  };
  const eq = await mk(() => ({ found: true, documentId: h32("dd"),
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
      provedQuery: () => ({ found: true, documentId: h32("99"),
        fields: { poolId: pool2, epochIndex: 5, ...numbersOf() } }) });
    const run2 = await startRun({ poolId: pool2, dir: dir2, deps: deps2 });
    const r = await runHeaderStep({ poolId: pool2, dir: dir2, deps: deps2, run: run2 });
    ok("a field-equal header under a different document identifier is foreign",
      r.status === "foreign-pending");
  }
  const absent = await mk(() => ({ found: false }))();
  ok("a duplicate refusal with a proved absence stays wait-only",
    absent.r.status === "unresolved-pending");
}
{
  // the full-equality resume: the proved query returns THIS pool's fields
  const pool = freshPool();
  const dir = caseDir();
  setStart(pool, "5", { dir });
  const deps = mkDeps(pool, dir, { outcome: () => REFUSAL_RESULT, unique: true,
    provedQuery: () => ({ found: true, documentId: h32("dd"),
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
  ok("header-capture-incomplete is establishable from the journaled observation", true);
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
    { credits: "1000", accrualId: A1, epochIndex: 5, poolId: pool });
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
      { accrualId: A2, amountCredits: "1500", recipientId: h32("72") }] });
  await rejects("the transfer step refuses a zero entitlement row",
    runTransferStep({ poolId: pool, dir, deps, run, epochIndex: 5, accrualId: A1 }),
    /only for a positive entitlement row/);
}

console.log(`e2DistributeTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
})().catch((e) => { console.error("UNCAUGHT:", e); process.exitCode = 1; });
