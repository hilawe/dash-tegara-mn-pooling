/**
 * The D10 admission battery: locks (canonical order, contention unwind,
 * serialization), the durable store-wide frontier (monotone, atomic,
 * fail-closed), the pinned balance refusals (chain, version, freshness),
 * the store inventory (grammar, fail-closed refusals, journal-evidenced
 * discharge), the reserve thresholds with the candidate epoch (exact values,
 * grouped by actual identity, the coincident-identity sum), and the patch
 * artifact's preserved-default assertion. Runs offline on harness fixtures
 * and mocks and WRITES NO epochHeader (the closure rule).
 *
 * THE MUTATION LIST WAS WRITTEN BEFORE THESE TESTS (the playbook's
 * substitute for an outside chooser); the commit message records it.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-e2bc-"));
process.env.TEGARA_ENV_PATH = path.join(TMP, "env.local");

const envStore = require("./envStore.cjs");
const { STATE_DIR, updateEnvKey } = envStore;
const { openJournal, appendRecord } = require("./e2JournalStore.cjs");
const { canonicalString } = require("./canonicalJson.cjs");
const { HEADER_KIND, RECEIPT_KIND } = require("./e2CaptureRecord.cjs");
const bc = require("./e2BalanceCheck.cjs");
const { acquireIdentityLocks, readFrontier, advanceFrontier, pinnedBalance,
  enumerateStoreInventory, computeThresholds, admitHeader, frontierPath } = bc;

let passed = 0, failed = 0, skipped = 0;
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
const CEILING = 100n; // perTransition = 200n
const ID_LOW = "11".repeat(32), ID_MID = "88".repeat(32), ID_HIGH = "ee".repeat(32);
const W = ID_LOW, I = ID_HIGH; // the candidate pool's roles
const POOL_A = "aa".repeat(32), POOL_B = "bb".repeat(32), POOL_C = "cc".repeat(32);
const h32 = (f) => f.repeat(64 / f.length);
const ACC = (f) => h32(f);
const sha = (hex) => crypto.createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");
const caseDir = () => fs.mkdtempSync(path.join(TMP, "case-"));

// journal record constructors (real digests, the D7 shapes)
const hBytes = (epoch) => "01020" + String(epoch).padStart(3, "0");
const tBytes = (epoch, acc) => "0a0b0" + String(epoch).padStart(3, "0") + acc.slice(0, 4);
const rBytes = (epoch, acc) => "0c0d0" + String(epoch).padStart(3, "0") + acc.slice(0, 4);
const ec = (poolId, epoch, memberCount) => ({ poolId, epochIndex: epoch, grossCredits: 1000,
  feeCredits: 10, allocationHash: h32("ee"), memberCount, calcVersion: 1 });
const lag = (poolId, first) => ({ v: 1, kind: "tegara.e2.journal.declaration.v1", object: "pool",
  gen: 1, poolId, condition: "lag-measurement", reasoning: "run start", lagCount: 0,
  undistributedCredits: "0", configuredStartEpoch: first });
const headerW = (poolId, epoch, memberCount, first) => ({ v: 1,
  kind: "tegara.e2.journal.writeAhead.v1", object: "header", gen: 1, poolId, epochIndex: epoch,
  transitionBytes: hBytes(epoch), transitionHash: sha(hBytes(epoch)),
  expectedDocumentId: h32("dd"), expectedContents: ec(poolId, epoch, memberCount),
  ...(first ? { configuredStartEpoch: epoch } : {}) });
const marker = (poolId, object, epoch, acc, bytes) => ({ v: 1,
  kind: "tegara.e2.journal.sentMarker.v1", object, gen: 1, poolId, epochIndex: epoch,
  ...(acc ? { accrualId: acc } : {}), transitionHash: sha(bytes) });
const headerCap = (poolId, epoch, memberCount) => ({ v: 1, kind: HEADER_KIND,
  object: "header", gen: 1, poolId, epochIndex: epoch, transitionBytes: hBytes(epoch),
  transitionHash: sha(hBytes(epoch)), proofMsg: "aa".repeat(20), metadataMsg: "bb".repeat(10),
  contractId: h32("cc"), expectedDocumentId: h32("dd"), expectedContents: ec(poolId, epoch, memberCount),
  inclusionHeight: "1000", heightRoute: "tenderdash-tx", signerIdentity: h32("f0"),
  signerKeyId: 2, sig: "00".repeat(65) });
const transferW = (poolId, epoch, acc) => ({ v: 1, kind: "tegara.e2.journal.writeAhead.v1",
  object: "transfer", gen: 1, poolId, epochIndex: epoch, accrualId: acc,
  transitionBytes: tBytes(epoch, acc), transitionHash: sha(tBytes(epoch, acc)) });
const resW = (poolId, epoch, acc) => ({ v: 1, kind: "tegara.e2.journal.writeAhead.v1",
  object: "reservation", gen: 1, poolId, epochIndex: epoch, accrualId: acc,
  transitionBytes: rBytes(epoch, acc), transitionHash: sha(rBytes(epoch, acc)),
  boundTransferHash: sha(tBytes(epoch, acc)) });
const resJ = (poolId, epoch, acc) => ({ v: 1, kind: "tegara.e2.journal.reservationSuccess.v1",
  object: "reservation", gen: 1, poolId, epochIndex: epoch, accrualId: acc,
  transitionHash: sha(rBytes(epoch, acc)), boundTransferHash: sha(tBytes(epoch, acc)),
  reservationDocumentId: h32("d1") });
const receiptCap = (poolId, epoch, acc) => ({ v: 1, kind: RECEIPT_KIND,
  object: "transfer", gen: 1, poolId, epochIndex: epoch, accrualId: acc,
  transitionHash: sha(tBytes(epoch, acc)), transitionBytes: tBytes(epoch, acc),
  proofMsg: "cc".repeat(20), metadataMsg: "dd".repeat(10), inclusionHeight: "1001",
  heightRoute: "tenderdash-tx", signerIdentity: h32("f0"), signerKeyId: 2, sig: "00".repeat(65) });
const happyAccrual = (poolId, epoch, acc) => [
  transferW(poolId, epoch, acc), resW(poolId, epoch, acc),
  marker(poolId, "reservation", epoch, acc, rBytes(epoch, acc)), resJ(poolId, epoch, acc),
  marker(poolId, "transfer", epoch, acc, tBytes(epoch, acc)), receiptCap(poolId, epoch, acc)];
const errRec = (poolId, object, epoch, acc, cls) => ({ v: 1, kind: "tegara.e2.journal.error.v1",
  object, gen: 1, poolId, epochIndex: epoch, ...(acc ? { accrualId: acc } : {}),
  code: 7, data: "00", message: "structured", errorClass: cls });
const surfacing = (poolId, object, epoch, condition, acc) => ({ v: 1,
  kind: "tegara.e2.journal.declaration.v1", object, gen: 1, poolId, epochIndex: epoch,
  ...(acc ? { accrualId: acc } : {}), condition, reasoning: "operator" });
const decision = (poolId, object, epoch, condition, action, acc) => ({ v: 1,
  kind: "tegara.e2.journal.decision.v1", object, gen: 1, poolId, epochIndex: epoch,
  ...(acc ? { accrualId: acc } : {}), condition, action, d6Status: "open", reasoning: "operator" });

const writeJournal = (poolId, records, dir) => {
  let off = openJournal(poolId, dir).committedOffset;
  for (const r of records) off = appendRecord(poolId, off, r, dir);
};

// the candidate epoch fixture: memberCount 2, two positive entitlements
const A1 = ACC("a1"), A2 = ACC("a2"), B1 = ACC("b1"), B2 = ACC("b2");
const candidate = { epochIndex: 7, memberCount: 2,
  positiveEntitlements: [{ accrualId: A1, amountCredits: "1000" }, { accrualId: A2, amountCredits: "500" }] };
// candidate writer count = 1 + 2 + 10*2 = 23 -> 4600; income = 1500 + 2*200 = 1900
const CAND_W = 4600n, CAND_I = 1900n;

const mkFetch = (balances, over = {}) => {
  const calls = [];
  const fn = async (id) => {
    calls.push(id);
    return { balance: balances[id], metadata: { chainId: over.chainId ?? CHAIN,
      protocolVersion: over.protocolVersion ?? 12, height: over.height ?? "100" } };
  };
  fn.calls = calls;
  return fn;
};
const resolverFor = (map) => (poolId) => map[poolId];
const poolAB = (income = I) => ({ writerIdentity: W, incomeIdentity: income,
  entitlementsForEpoch: (epoch) => ({ 5: [{ accrualId: B1, amountCredits: "700" }] }[epoch] || []) });

const admit = (over = {}) => {
  const locks = over.locks || acquireIdentityLocks([W, I]);
  const p = admitHeader({ dir: over.dir, poolId: over.poolId || POOL_A,
    candidate: over.candidate || candidate,
    identities: over.identities || { writer: W, income: I },
    resolvePool: over.resolvePool || resolverFor({}),
    fetchBalanceWithMetadata: over.fetch, feeCeilingCredits: "ceiling" in over ? over.ceiling : "100",
    chainIdPin: "chainIdPin" in over ? over.chainIdPin : CHAIN, locks });
  const done = p.finally(() => { if (!over.locks) locks.release(); });
  return done;
};

(async () => {

// ---- the empty-store candidate case, the false-low refusal, and the
// funded rerun (exact threshold values pin the 10-per-entitlement factor) ----
{
  const dir = caseDir();
  await rejects("the empty store's candidate alone exceeds the balance (false-low refusal)",
    admit({ dir, fetch: mkFetch({ [W]: "4600", [I]: "1899" }) }),
    /below its reserve threshold 1900 \(shortfall 1 credits/);
  const r = await admit({ dir, fetch: mkFetch({ [W]: "4600", [I]: "1900" }) });
  ok("the funded rerun admits at the exact thresholds",
    r.admitted === true && r.thresholds[W] === String(CAND_W) && r.thresholds[I] === String(CAND_I));
}

// ---- the concurrent-pool refusal: another pool's incomplete epoch shares
// both identities, each alone sufficient, combined insufficient ----
{
  const dir = caseDir();
  writeJournal(POOL_B, [lag(POOL_B, 5), headerW(POOL_B, 5, 2, true),
    marker(POOL_B, "header", 5, null, hBytes(5))], dir);
  const resolvePool = resolverFor({ [POOL_B]: poolAB() });
  // pool B epoch 5 remaining: writer (1 header + 2 accruals + 1 res + 9) = 13 -> 2600; income 700 + 200 = 900
  await rejects("a second pool's obligations against the same balance refuse (store-wide sweep)",
    admit({ dir, resolvePool, fetch: mkFetch({ [W]: "4600", [I]: "1900" }) }),
    /below its reserve threshold/);
  const r = await admit({ dir, resolvePool, fetch: mkFetch({ [W]: "7200", [I]: "2800" }) });
  ok("the combined store-wide thresholds admit at their exact values",
    r.thresholds[W] === "7200" && r.thresholds[I] === "2800");
}

// ---- journal-evidenced discharge: the income side per captured receipt;
// the writer's document writes discharge on no journal evidence at all
// (the part and receipt-document writes come after the capture, and a
// later header proves only that the writer moved on) ----
{
  const dir = caseDir();
  writeJournal(POOL_B, [lag(POOL_B, 5), headerW(POOL_B, 5, 2, true),
    marker(POOL_B, "header", 5, null, hBytes(5)), headerCap(POOL_B, 5, 2),
    ...happyAccrual(POOL_B, 5, B1)], dir);
  const resolvePool = resolverFor({ [POOL_B]: poolAB() });
  // income discharged by the capture; writer still owes 2 accrual docs +
  // 9 part-and-receipt-document writes (reservation held) = 11 -> 2200
  const r = await admit({ dir, resolvePool, fetch: mkFetch({ [W]: "6800", [I]: "1900" }) });
  ok("a captured receipt discharges the income side while the writer's document writes stay owed",
    r.thresholds[W] === String(CAND_W + 2200n) && r.thresholds[I] === String(CAND_I));
}
{
  // THE RE-CHECK'S SCENARIO, pinned at its exact boundary: a later epoch's
  // header write-ahead proves only that the writer moved on, so epoch 5's
  // document writes (2 accrual docs + 9 part-and-receipt-document writes =
  // 11 -> 2200) stay counted beside epoch 6's own 1 + 2 = 3 -> 600
  const dir = caseDir();
  writeJournal(POOL_B, [lag(POOL_B, 5), headerW(POOL_B, 5, 2, true),
    marker(POOL_B, "header", 5, null, hBytes(5)), headerCap(POOL_B, 5, 2),
    ...happyAccrual(POOL_B, 5, B1),
    headerW(POOL_B, 6, 2), marker(POOL_B, "header", 6, null, hBytes(6))], dir);
  const resolvePool = resolverFor({ [POOL_B]: poolAB() });
  await rejects("a later header never discharges the earlier epoch's writer obligations",
    admit({ dir, resolvePool, fetch: mkFetch({ [W]: "7399", [I]: "1900" }) }),
    /below its reserve threshold 7400 \(shortfall 1 credits/);
  const r = await admit({ dir, resolvePool, fetch: mkFetch({ [W]: "7400", [I]: "1900" }) });
  ok("the conservative no-inference thresholds admit at their exact values",
    r.thresholds[W] === "7400" && r.thresholds[I] === String(CAND_I));
}
{
  // an uncaptured transfer beside a later header keeps BOTH sides counted
  const dir = caseDir();
  writeJournal(POOL_B, [lag(POOL_B, 5), headerW(POOL_B, 5, 2, true),
    marker(POOL_B, "header", 5, null, hBytes(5)), headerCap(POOL_B, 5, 2),
    transferW(POOL_B, 5, B1),
    headerW(POOL_B, 6, 2), marker(POOL_B, "header", 6, null, hBytes(6))], dir);
  const resolvePool = resolverFor({ [POOL_B]: poolAB() });
  const r = await admit({ dir, resolvePool, fetch: mkFetch({ [W]: "7600", [I]: "2800" }) });
  ok("a later header discharges neither the transfer's amount nor its writer writes",
    r.thresholds[W] === String(CAND_W + 3000n) && r.thresholds[I] === String(CAND_I + 900n));
}
{
  // the ascending discipline against the candidate's OWN journal: a
  // candidate below a journal-visible epoch refuses, an equal epoch is
  // the rebuild path and double-counts conservatively
  const dir = caseDir();
  writeJournal(POOL_A, [lag(POOL_A, 8), headerW(POOL_A, 8, 2, true),
    marker(POOL_A, "header", 8, null, hBytes(8))], dir);
  const resolvePool = resolverFor({ [POOL_A]: { writerIdentity: W, incomeIdentity: I,
    entitlementsForEpoch: () => [] } });
  await rejects("a candidate epoch below its pool's journal-visible epoch refuses",
    admit({ dir, resolvePool, fetch: mkFetch({ [W]: "99999", [I]: "99999" }) }),
    /below the pool's journal-visible epoch 8 \(the flow never writes backward\)/);
}
{
  // the boundary covers EVERY epoch-bearing record: an epoch-scoped
  // zero-earning declaration at 8, with no epoch-8 header, still bounds
  const dir = caseDir();
  writeJournal(POOL_A, [lag(POOL_A, 8),
    { v: 1, kind: "tegara.e2.journal.declaration.v1", object: "epoch", gen: 1,
      poolId: POOL_A, epochIndex: 8, condition: "zero-earning-epoch",
      reasoning: "absent proposer" }], dir);
  const resolvePool = resolverFor({ [POOL_A]: { writerIdentity: W, incomeIdentity: I,
    entitlementsForEpoch: () => [] } });
  await rejects("an epoch-scoped declaration alone bounds the ascending check",
    admit({ dir, resolvePool, fetch: mkFetch({ [W]: "99999", [I]: "99999" }) }),
    /below the pool's journal-visible epoch 8/);
}
{
  // a journal with only pool-scoped records sets no boundary
  const dir = caseDir();
  writeJournal(POOL_A, [lag(POOL_A, 9)], dir);
  const resolvePool = resolverFor({ [POOL_A]: { writerIdentity: W, incomeIdentity: I,
    entitlementsForEpoch: () => [] } });
  const r = await admit({ dir, resolvePool, fetch: mkFetch({ [W]: "9999", [I]: "9999" }) });
  ok("pool-scoped records alone set no epoch boundary", r.admitted === true);
}
{
  const dir = caseDir();
  writeJournal(POOL_A, [lag(POOL_A, 7), headerW(POOL_A, 7, 2, true),
    marker(POOL_A, "header", 7, null, hBytes(7))], dir);
  const resolvePool = resolverFor({ [POOL_A]: { writerIdentity: W, incomeIdentity: I,
    entitlementsForEpoch: () => [] } });
  const r = await admit({ dir, resolvePool, fetch: mkFetch({ [W]: "5200", [I]: "1900" }) });
  ok("an equal candidate epoch (the rebuild path) admits with its journal terms double-counted",
    r.admitted === true && r.thresholds[W] === String(CAND_W + 600n));
}
{
  const dir = caseDir();
  writeJournal(POOL_B, [lag(POOL_B, 5), headerW(POOL_B, 5, 2, true),
    marker(POOL_B, "header", 5, null, hBytes(5)), headerCap(POOL_B, 5, 2),
    ...happyAccrual(POOL_B, 5, B1), transferW(POOL_B, 5, B2)], dir);
  const resolvePool = resolverFor({ [POOL_B]: { ...poolAB(),
    entitlementsForEpoch: () => [{ accrualId: B1, amountCredits: "700" }, { accrualId: B2, amountCredits: "500" }] } });
  // writer: 2 accrual docs + B1 (0 res + 9) + B2 (1 res + 9) = 21 -> 4200; income 500 + 200 = 700
  const r = await admit({ dir, resolvePool, fetch: mkFetch({ [W]: "8800", [I]: "2600" }) });
  ok("per-accrual income discharge beside an outstanding sibling, writer counts both",
    r.thresholds[W] === String(CAND_W + 4200n) && r.thresholds[I] === String(CAND_I + 700n));
}
{
  // a journaled STOP discharges exactly its subject, never the epoch: B1's
  // reservation is stopped, B2 stays outstanding on both sides
  const dir = caseDir();
  writeJournal(POOL_B, [lag(POOL_B, 5), headerW(POOL_B, 5, 2, true),
    marker(POOL_B, "header", 5, null, hBytes(5)), headerCap(POOL_B, 5, 2),
    transferW(POOL_B, 5, B1), resW(POOL_B, 5, B1),
    marker(POOL_B, "reservation", 5, B1, rBytes(5, B1)),
    errRec(POOL_B, "reservation", 5, B1, "execution-refusal"),
    surfacing(POOL_B, "reservation", 5, "reservation-refused", B1),
    decision(POOL_B, "reservation", 5, "reservation-refused", "stop", B1),
    transferW(POOL_B, 5, B2)], dir);
  const resolvePool = resolverFor({ [POOL_B]: { ...poolAB(),
    entitlementsForEpoch: () => [{ accrualId: B1, amountCredits: "700" }, { accrualId: B2, amountCredits: "500" }] } });
  // writer: 2 accrual docs + B2 (1 res + 9) = 12 -> 2400; income 500 + 200 = 700
  const r = await admit({ dir, resolvePool, fetch: mkFetch({ [W]: "7000", [I]: "2600" }) });
  ok("a stop discharges exactly its subject, the sibling stays outstanding on both sides",
    r.thresholds[W] === String(CAND_W + 2400n) && r.thresholds[I] === String(CAND_I + 700n));
}

// ---- a stopped header epoch has no remaining obligations ----
{
  const dir = caseDir();
  writeJournal(POOL_B, [lag(POOL_B, 5), headerW(POOL_B, 5, 2, true),
    marker(POOL_B, "header", 5, null, hBytes(5)),
    errRec(POOL_B, "header", 5, null, "execution-refusal"),
    surfacing(POOL_B, "header", 5, "header-refused"),
    decision(POOL_B, "header", 5, "header-refused", "stop")], dir);
  const r = await admit({ dir, resolvePool: resolverFor({ [POOL_B]: poolAB() }),
    fetch: mkFetch({ [W]: "4600", [I]: "1900" }) });
  ok("a stopped header epoch contributes nothing (stop is terminal for the flow)",
    r.thresholds[W] === String(CAND_W) && r.thresholds[I] === String(CAND_I));
}

// ---- a stopped header with an ATTEMPTED transfer: the writer flow is
// dead (zero writer terms) but the sent transfer's amount stays counted
// until its own subject discharges ----
{
  const dir = caseDir();
  writeJournal(POOL_B, [lag(POOL_B, 5), headerW(POOL_B, 5, 2, true),
    marker(POOL_B, "header", 5, null, hBytes(5)),
    errRec(POOL_B, "header", 5, null, "execution-refusal"),
    surfacing(POOL_B, "header", 5, "header-refused"),
    decision(POOL_B, "header", 5, "header-refused", "stop"),
    ...happyAccrual(POOL_B, 5, B1).slice(0, 5)], dir); // W-S sent, no capture
  const r = await admit({ dir, resolvePool: resolverFor({ [POOL_B]: poolAB() }),
    fetch: mkFetch({ [W]: "4600", [I]: "2800" }) });
  ok("a stopped header zeroes the writer terms while an attempted transfer's amount stays",
    r.thresholds[W] === String(CAND_W) && r.thresholds[I] === String(CAND_I + 900n));
}

// ---- one writer, distinct income identities: obligations group by ACTUAL
// identity, each threshold summing exactly its own group ----
{
  const dir = caseDir();
  writeJournal(POOL_B, [lag(POOL_B, 5), headerW(POOL_B, 5, 2, true),
    marker(POOL_B, "header", 5, null, hBytes(5))], dir);
  writeJournal(POOL_C, [lag(POOL_C, 5), headerW(POOL_C, 5, 2, true),
    marker(POOL_C, "header", 5, null, hBytes(5))], dir);
  const inventory = enumerateStoreInventory({ dir, resolvePool: resolverFor({
    [POOL_B]: poolAB(ID_MID),
    [POOL_C]: { writerIdentity: W, incomeIdentity: ID_HIGH,
      entitlementsForEpoch: () => [{ accrualId: B2, amountCredits: "300" }] },
  }) });
  const t = computeThresholds({ candidate, identities: { writer: W, income: I },
    inventory, feeCeilingCredits: "100" });
  ok("the writer's threshold sums every pool's writer obligations",
    t.get(W) === CAND_W + 2600n + 2600n);
  ok("each income identity's threshold sums exactly its own pool's group",
    t.get(ID_MID) === 900n && t.get(ID_HIGH) === CAND_I + 500n);
}

// ---- the coincident-identity case: one balance against the SUM, never
// separately against two role thresholds ----
{
  const dir = caseDir();
  const X = ID_MID;
  const locks = acquireIdentityLocks([X]);
  try {
    await rejects("a coincident identity refuses at the larger role threshold alone",
      admit({ dir, identities: { writer: X, income: X }, locks,
        fetch: mkFetch({ [X]: String(CAND_W) }) }),
      /below its reserve threshold 6500/);
    const r = await admit({ dir, identities: { writer: X, income: X }, locks,
      fetch: mkFetch({ [X]: "6500" }) });
    ok("a coincident identity admits exactly at the summed threshold",
      r.thresholds[X] === "6500" && Object.keys(r.balances).length === 1);
  } finally { locks.release(); }
}

// ---- the pinned balance refusals: chain, version, freshness ----
{
  const dir = caseDir();
  await rejects("a chainId differing from the owned pin refuses",
    admit({ dir, fetch: mkFetch({ [W]: "9999", [I]: "9999" }, { chainId: "other-chain" }) }),
    /differs from the owned pin/);
  await rejects("an authenticated protocolVersion other than 12 refuses",
    admit({ dir, fetch: mkFetch({ [W]: "9999", [I]: "9999" }, { protocolVersion: 11 }) }),
    /not the pinned 12/);
  await rejects("an unserved result refuses",
    admit({ dir, fetch: async () => { throw new Error("proof verification failed"); } }),
    /did not verify/);
  await rejects("a result without metadata refuses",
    admit({ dir, fetch: async () => ({ balance: "9999" }) }), /unserved or lacks/);
}
{
  // the false-high case: a stale LOW height below the durable frontier
  const dir = caseDir();
  const locks = acquireIdentityLocks([W, I]);
  try {
    advanceFrontier(W, 100n, { dir, locks });
    await rejects("a response height below the frontier refuses (stale evidence)",
      admit({ dir, locks, fetch: mkFetch({ [W]: "9999", [I]: "9999" }, { height: "50" }) }),
      /below the identity's durable frontier 100/);
    const r = await admit({ dir, locks, fetch: mkFetch({ [W]: "9999", [I]: "9999" }, { height: "100" }) });
    ok("a height AT the frontier is acceptable (the floor is monotone, not strict)", r.admitted === true);
  } finally { locks.release(); }
}

// ---- the frontier: store-wide across pools, monotone, atomic, fail-closed ----
{
  const dir = caseDir();
  const locks = acquireIdentityLocks([I]);
  try {
    const fetchHigh = mkFetch({ [I]: "5" }, { height: "200" });
    await pinnedBalance(I, { fetchWithMetadata: fetchHigh, chainIdPin: CHAIN, dir, locks });
    ok("a verified balance read advances the identity's frontier", readFrontier(I, { dir, locks }) === 200n);
    // the SAME identity read for a DIFFERENT pool's admission shares the file
    await rejects("the frontier is store-wide per identity, not per pool",
      pinnedBalance(I, { fetchWithMetadata: mkFetch({ [I]: "5" }, { height: "150" }),
        chainIdPin: CHAIN, dir, locks }), /below the identity's durable frontier 200/);
    ok("a backward advance is a no-op, never a move", advanceFrontier(I, 50n, { dir, locks }) === 200n
      && readFrontier(I, { dir, locks }) === 200n);
    // an interrupted update leaves the prior value intact
    fs.writeFileSync(`${frontierPath(I, dir)}.tmp`, "garbage from a crashed update");
    ok("a leftover temporary does not disturb the committed frontier", readFrontier(I, { dir, locks }) === 200n);
    ok("the next advance replaces the temporary and commits", advanceFrontier(I, 300n, { dir, locks }) === 300n
      && readFrontier(I, { dir, locks }) === 300n);
  } finally { locks.release(); }
}
{
  const dir = caseDir();
  const locks = acquireIdentityLocks([W]);
  try {
    fs.writeFileSync(frontierPath(W, dir), canonicalString({ v: 1, identity: W, height: "10", extra: 1 }));
    throws("a frontier file with an extra member refuses fail closed",
      () => readFrontier(W, { dir, locks }), /exactly v, identity and height/);
    fs.writeFileSync(frontierPath(W, dir), canonicalString({ v: 1, identity: ID_MID, height: "10" }));
    throws("a frontier file naming a different identity refuses",
      () => readFrontier(W, { dir, locks }), /different identity/);
    fs.writeFileSync(frontierPath(W, dir), ` ${canonicalString({ v: 1, identity: W, height: "10" })}`);
    throws("a non-canonical frontier serialization refuses",
      () => readFrontier(W, { dir, locks }), /canonical serialization/);
  } finally { locks.release(); }
}

// ---- the locks: canonical order, contention unwind, serialization ----
{
  const order = [];
  const realAcquire = envStore.acquireOpLock;
  envStore.acquireOpLock = (name) => { order.push(name); return realAcquire(name); };
  let locks;
  try { locks = acquireIdentityLocks([ID_HIGH, ID_LOW, ID_HIGH]); }
  finally { envStore.acquireOpLock = realAcquire; }
  ok("acquisition is in ascending raw-byte order, deduplicated, whatever the argument order",
    order.length === 2 && order[0] === `e2-identity-${ID_LOW}` && order[1] === `e2-identity-${ID_HIGH}`);
  locks.release();
}
{
  // serialization: a second same-identity operation refuses while the first
  // holds, and proceeds after release (both complete)
  const first = acquireIdentityLocks([I]);
  throws("a concurrent same-identity operation is serialized (contention, not interleaving)",
    () => acquireIdentityLocks([W, I]), /holds the operation lock/);
  ok("the loser's partial acquisition was unwound (the writer lock is free again)",
    (() => { const l = acquireIdentityLocks([W]); l.release(); return true; })());
  first.release();
  const second = acquireIdentityLocks([W, I]);
  ok("after release the second operation acquires the full set", second.identities.length === 2);
  second.release();
}
{
  throws("a frontier read without the identity's lock refuses",
    () => readFrontier(W, { dir: caseDir(), locks: null }), /requires that identity's operation lock/);
  const locks = acquireIdentityLocks([W]);
  try {
    await rejects("the header admission requires BOTH identities' locks",
      admit({ dir: caseDir(), locks, fetch: mkFetch({ [W]: "9999", [I]: "9999" }) }),
      /exactly its stated lock set/);
  } finally { locks.release(); }
  // EXACTLY the stated set: a superset is refused too (an extra held lock
  // would block an unrelated identity's sends for the admission's duration)
  const superset = acquireIdentityLocks([W, I, ID_MID]);
  try {
    await rejects("the header admission refuses a superset of its lock set",
      admit({ dir: caseDir(), locks: superset, fetch: mkFetch({ [W]: "9999", [I]: "9999" }) }),
      /exactly its stated lock set/);
  } finally { superset.release(); }
}

// ---- the store inventory's fail-closed refusals ----
{
  const dir = caseDir();
  fs.writeFileSync(path.join(dir, "e2-journal-nothex.jsonl"), "");
  await rejects("a grammar-matching file with a malformed pool identifier refuses",
    admit({ dir, fetch: mkFetch({ [W]: "9999", [I]: "9999" }) }), /malformed pool identifier/);
}
{
  const dir = caseDir();
  fs.writeFileSync(path.join(dir, `e2-journal-${POOL_B}.jsonl`), "not a journal");
  await rejects("an unreadable or invalid journal refuses the admission outright",
    admit({ dir, fetch: mkFetch({ [W]: "9999", [I]: "9999" }) }), /unreadable or invalid/);
}
{
  const dir = caseDir();
  fs.writeFileSync(path.join(dir, "README.txt"), "foreign");
  fs.writeFileSync(path.join(dir, "e2-frontier-notes.md"), "foreign");
  const r = await admit({ dir, fetch: mkFetch({ [W]: "9999", [I]: "9999" }) });
  ok("files not matching the journal grammar are foreign and ignored", r.admitted === true);
}
{
  const dir = caseDir();
  writeJournal(POOL_B, [lag(POOL_B, 5), errRec(POOL_B, "accrual", 5, B1, "execution-refusal")], dir);
  await rejects("an epoch with obligation evidence but no header numbers refuses (cannot quantify)",
    admit({ dir, resolvePool: resolverFor({ [POOL_B]: poolAB() }),
      fetch: mkFetch({ [W]: "9999", [I]: "9999" }) }), /cannot be quantified/);
}
{
  await rejects("a missing fee ceiling refuses rather than defaulting",
    admit({ dir: caseDir(), ceiling: null, fetch: mkFetch({ [W]: "9", [I]: "9" }) }),
    /e2FeeCeilingCredits is not set/);
}

// ---- funding is strictly out of band: the admission's only external action
// is ONE injected fetch per distinct identity ----
{
  const dir = caseDir();
  const fetch = mkFetch({ [W]: "9999", [I]: "9999" });
  await admit({ dir, fetch });
  ok("exactly one balance fetch per distinct identity, nothing else external",
    fetch.calls.length === 2 && new Set(fetch.calls).size === 2);
  const fetch1 = mkFetch({ [ID_MID]: "9999" });
  const locks = acquireIdentityLocks([ID_MID]);
  try { await admit({ dir, identities: { writer: ID_MID, income: ID_MID }, locks, fetch: fetch1 }); }
  finally { locks.release(); }
  ok("a coincident identity is fetched once, not once per role", fetch1.calls.length === 1);
}

// ---- the comparison scope, a DECLARED interface correction: another
// pool's distinct income identity gets its threshold computed (grouping)
// but its comparison belongs to that pool's own admission under its own
// locks; this header adds no obligation to it, never fetches it, and is
// not blocked by its shortfall ----
{
  const dir = caseDir();
  writeJournal(POOL_B, [lag(POOL_B, 5), headerW(POOL_B, 5, 2, true),
    marker(POOL_B, "header", 5, null, hBytes(5))], dir);
  const fetch = mkFetch({ [W]: "9999", [I]: "9999", [ID_MID]: "0" });
  const r = await admit({ dir, resolvePool: resolverFor({ [POOL_B]: poolAB(ID_MID) }), fetch });
  ok("a foreign income identity is neither fetched nor a blocker, its threshold still computed",
    r.admitted === true && !fetch.calls.includes(ID_MID) && r.thresholds[ID_MID] === "900"
    && r.thresholds[W] === String(CAND_W + 2600n));
}

// ---- which evidence advances which identity: capture metadata heights ----
{
  const dir = caseDir();
  const locks = acquireIdentityLocks([W, I]);
  try {
    bc.advanceFrontierFromCapture({ kind: HEADER_KIND, height: 40n,
      identities: { writer: W, income: I } }, { dir, locks });
    ok("a header capture's height advances the RECORD WRITER's frontier",
      readFrontier(W, { dir, locks }) === 40n && readFrontier(I, { dir, locks }) === 0n);
    bc.advanceFrontierFromCapture({ kind: RECEIPT_KIND, height: 70n,
      identities: { writer: W, income: I } }, { dir, locks });
    ok("a receipt capture's height advances the INCOME identity's frontier",
      readFrontier(I, { dir, locks }) === 70n && readFrontier(W, { dir, locks }) === 40n);
    throws("an unknown capture kind advances nothing",
      () => bc.advanceFrontierFromCapture({ kind: "tegara.e2.journal.error.v1", height: 9n,
        identities: { writer: W, income: I } }, { dir, locks }), /not one whose metadata advances/);
  } finally { locks.release(); }
  throws("a capture advance without the advanced identity's lock refuses",
    () => bc.advanceFrontierFromCapture({ kind: HEADER_KIND, height: 41n,
      identities: { writer: W, income: I } }, { dir, locks: null }), /operation lock/);
}
{
  // the closed representation: a non-BigInt height never writes
  const dir = caseDir();
  const locks = acquireIdentityLocks([W]);
  try {
    throws("a numeric (non-BigInt) frontier height refuses",
      () => advanceFrontier(W, 100, { dir, locks }), /non-negative BigInt height/);
    throws("a negative frontier height refuses",
      () => advanceFrontier(W, -1n, { dir, locks }), /non-negative BigInt height/);
    ok("nothing was written by the refused advances", !fs.existsSync(frontierPath(W, dir)));
    // fault injection at the commit boundary: a crash before the rename
    // leaves the prior committed value intact
    advanceFrontier(W, 10n, { dir, locks });
    const realRename = fs.renameSync;
    fs.renameSync = () => { throw new Error("injected: crash before the frontier rename"); };
    let threw = false;
    try { advanceFrontier(W, 99n, { dir, locks }); } catch { threw = true; }
    finally { fs.renameSync = realRename; }
    ok("a crash before the rename leaves the committed frontier intact",
      threw && readFrontier(W, { dir, locks }) === 10n);
    ok("the next advance commits over the debris", advanceFrontier(W, 99n, { dir, locks }) === 99n);
  } finally { locks.release(); }
}

// ---- the default chain-pin path reads the owned composite pin ----
{
  const dir = caseDir();
  updateEnvKey("E2_EXPECTED_CHAIN_ID", canonicalString({ chainId: CHAIN,
    source: { path: "genesis.json", retrievedAt: "2026-08-22" } }));
  const locks = acquireIdentityLocks([W, I]);
  try {
    const r = await admitHeader({ dir, poolId: POOL_A, candidate, identities: { writer: W, income: I },
      resolvePool: resolverFor({}), fetchBalanceWithMetadata: mkFetch({ [W]: "9999", [I]: "9999" }),
      feeCeilingCredits: "100", locks }); // no chainIdPin argument: the owned pin decides
    ok("the default pin path admits against the owned E2_EXPECTED_CHAIN_ID", r.admitted === true);
    await rejects("the default pin path refuses a differing authenticated chainId",
      admitHeader({ dir, poolId: POOL_A, candidate, identities: { writer: W, income: I },
        resolvePool: resolverFor({}),
        fetchBalanceWithMetadata: mkFetch({ [W]: "9999", [I]: "9999" }, { chainId: "other" }),
        feeCeilingCredits: "100", locks }), /differs from the owned pin/);
  } finally { locks.release(); }
}

// ---- the patch artifact: the scalar default preserved verbatim, the one
// additive named export whose body is the default's except its return, and
// the BEHAVIORAL mounted-route assertion (the patch is imported at the SDK
// path it mounts over and both exports are executed) ----
{
  // THIS BLOCK READS LOCAL BUILD ARTIFACTS, NOT THE MODULE UNDER TEST: the SDK
  // patch, the installed SDK source it mirrors, and the acceptance script that
  // mounts it. The curated public export deliberately drops all three (it takes
  // no platform-SDK dependency), so on that tree the block has nothing to
  // compare and is SKIPPED rather than failed. It is skipped ONLY when the
  // artifacts are absent, so the private tree, which has them, always runs it.
  //
  // The skip is COUNTED AND PRINTED, never folded into the pass total: a check
  // that did not run must not report as one, and a suite reporting "N passed"
  // while silently examining less is the failure this guards against.
  const patchPath = path.join(__dirname, "..", "..", "patches", "getIdentityBalance-retainMetadata.js");
  const installedPath = path.join(__dirname, "..", "..", "node_modules",
    "dash-platform-sdk", "src", "identities", "getIdentityBalance.js");
  const acceptancePath = path.join(__dirname, "..", "..", "run_acceptance.sh");
  const absent = [patchPath, installedPath, acceptancePath].filter((f) => !fs.existsSync(f));
  if (absent.length) {
    skipped += 1;
    console.log(`SKIP: the SDK patch-artifact checks (absent here: ${absent.map((f) => path.basename(f)).join(", ")})`);
  } else {
  const patch = fs.readFileSync(patchPath, "utf8");
  const installed = fs.readFileSync(path.join(__dirname, "..", "..", "node_modules",
    "dash-platform-sdk", "src", "identities", "getIdentityBalance.js"), "utf8");
  ok("the installed scalar source appears in the patch verbatim (default export unchanged)",
    patch.includes(installed.trim()));
  const bind = fs.readFileSync(path.join(__dirname, "..", "..", "run_acceptance.sh"), "utf8");
  ok("the patch's bind line is in the acceptance PATCHES",
    bind.includes("patches/getIdentityBalance-retainMetadata.js:/app/node_modules/dash-platform-sdk/src/identities/getIdentityBalance.js"));
  // the named export's BODY equals the default's body except the return
  // line, so no semantic drift (a weakened verification branch included)
  // can hide in the copy
  const defBody = patch.match(/export default async function getIdentityBalance\([\s\S]*?\n\}/);
  const namedBody = patch.match(/export async function getIdentityBalanceWithMetadata\([\s\S]*?\n\}/);
  ok("both exports exist in the patch", !!defBody && !!namedBody);
  const norm = (s) => s.replace(/^export (default )?async function \w+/, "")
    .replace(/return \{ balance: BigInt\(balance\), metadata \};/, "return BigInt(balance);")
    .replace(/\s+/g, " ").trim();
  ok("the named export's body is the default's except the return line",
    norm(namedBody[0]) === norm(defBody[0]));
  // BEHAVIORAL: import the patch AT THE SDK PATH it mounts over (so its
  // relative imports resolve) and drive both exports; a stubbed or
  // reassigned export cannot produce the real function's exact refusal
  const mountDir = path.join(__dirname, "..", "..", "node_modules", "dash-platform-sdk", "src", "identities");
  const mounted = path.join(mountDir, "getIdentityBalance-retainMetadata.mount-test.js");
  fs.copyFileSync(patchPath, mounted);
  try {
    const { pathToFileURL } = require("url");
    const mod = await import(pathToFileURL(mounted).href);
    ok("the mounted module's default export is the scalar function by name",
      typeof mod.default === "function" && mod.default.name === "getIdentityBalance");
    const badPool = { network: "regtest",
      getClient: () => ({ getIdentityBalance: async () => ({ response: { version: { oneofKind: "v1" } } }) }) };
    const id = new Uint8Array(32);
    let msgDefault = "", msgNamed = "";
    try { await mod.default(badPool, id); } catch (e) { msgDefault = e.message; }
    try { await mod.getIdentityBalanceWithMetadata(badPool, id); } catch (e) { msgNamed = e.message; }
    ok("the mounted DEFAULT export executes the real refusal path",
      msgDefault === "Unexpected oneOf type returned from DAPI (must be v0)");
    ok("the mounted NAMED export executes the same refusal path",
      msgNamed === "Unexpected oneOf type returned from DAPI (must be v0)");
    const noProof = { network: "regtest",
      getClient: () => ({ getIdentityBalance: async () => ({ response: { version: { oneofKind: "v0",
        v0: { result: { oneofKind: "balance" }, metadata: {} } } } }) }) };
    let msg2 = "";
    try { await mod.getIdentityBalanceWithMetadata(noProof, id); } catch (e) { msg2 = e.message; }
    ok("the named export refuses an unproved (non-proof) result",
      msg2 === "Unexpected oneOf type returned from DAPI (must be proof)");
  } finally { fs.rmSync(mounted, { force: true }); }
  }
}

// the skip count is REPORTED, never absorbed into the pass total, so a tree
// that examined less says so in its own summary line
console.log(`e2BalanceCheckTest: ${passed} passed, ${failed} failed${skipped ? `, ${skipped} skipped` : ""}`);
if (failed) process.exitCode = 1;
})().catch((e) => { console.error("UNCAUGHT:", e); process.exitCode = 1; });
