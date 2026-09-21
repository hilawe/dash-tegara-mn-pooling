/**
 * TWO-EPOCH ORCHESTRATION PROBE - A NONNORMATIVE SPIKE, NOT A LIFECYCLE IMPLEMENTATION.
 *
 * WHAT IT IS FOR. Every carry piece built since 2026-08-30 is preparatory, because nothing
 * multi-epoch exists anywhere to exercise it: every journal in the live store holds one
 * epoch. Before extracting a shared lifecycle kernel and refactoring the live driver around
 * per-epoch contexts, this answers four interface questions cheaply, by orchestrating two
 * epochs end to end against a fake Platform:
 *
 *   1. What lifecycle result shape does the orchestrator actually need?
 *   2. When must lifecycle evidence be refreshed?
 *   3. How does the run token behave between completed epochs?
 *   4. What data belongs in a per-epoch context?
 *
 * WHAT IT IS NOT, and these are boundaries rather than modesty. It claims NOTHING about
 * canonical lifecycle correctness, full audit completeness, the absence of unknown extra
 * records, production multi-epoch support, or live verification of a soundness-review finding or a soundness-review finding. It is
 * deliberately OUTSIDE the production driver and the audit, it is not wired into the test
 * suite, and it should be deleted or promoted once the interface decision is made rather
 * than quietly becoming the second implementation of the lifecycle rule.
 *
 * THE ASYNCHRONOUS BOUNDARY IS THE POINT. A real completeness check reads Platform
 * documents and is asynchronous, while the writer's seam is synchronous and now REFUSES a
 * Promise by name. This probe therefore tests the smaller alternative honestly:
 *
 *   1. an asynchronous refresh reads the fake ledger,
 *   2. the refresh produces an IMMUTABLE lifecycle snapshot,
 *   3. the writer receives a SYNCHRONOUS strict-boolean lookup backed by that snapshot,
 *   4. after ledger state changes the orchestrator takes a NEW snapshot before selecting
 *      another epoch.
 *
 * If refresh timing or snapshot ownership turns out awkward, that is evidence FOR making
 * the writer boundary asynchronous later, and saying so is a legitimate outcome.
 *
 * LIFECYCLE IS DERIVED FROM DOCUMENTS, NEVER FROM A TEST FLAG. The fake Platform owns the
 * documents and updates them when writer operations succeed. Completion is computed by
 * reading them back. There is no `done` variable anywhere in this file, deliberately: a
 * probe that advanced because a test flipped a boolean would answer none of the four
 * questions.
 *
 * HOW MUCH IS FAKED, stated at its real width rather than as "only the transport". This is
 * a FULL fake Platform dependency adapter. Besides the document surface and the broadcast
 * it also fakes: gate admission, finalized-epoch discovery, the proved-header read, balance
 * evidence, transition construction, capture construction, reservation observation, receipt
 * observation, proof and metadata carriers, and document payloads. That is acceptable for
 * an orchestration spike and it is the reason the spike cannot speak to conformance of any
 * of those surfaces.
 *
 * Run:  node src/scripts/twoEpochOrchestrationProbe.cjs
 */
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-probe-"));
process.env.TEGARA_ENV_PATH = path.join(TMP, "env.local");

const envStore = require("./envStore.cjs");
const { STATE_DIR } = envStore;
fs.writeFileSync(process.env.TEGARA_ENV_PATH,
  "MNEMONIC=m\nSTATE_MIGRATED=1\nSTATE_STORE_ID=00112233aabbccdd\n");
fs.mkdirSync(STATE_DIR, { recursive: true });
fs.writeFileSync(path.join(STATE_DIR, "store.id"), "00112233aabbccdd");

const { setStart, startRun, runHeaderStep, runAccrualStep, runTransferStep,
  poolRunLockName, classifyEntitlement } = require("./e2Distribute.cjs");
const { openValidatedJournal } = require("./e2Journal.cjs");
const { acquireIdentityLocks, identityLockName } = require("./e2BalanceCheck.cjs");
const entitlementCalc = require("./entitlementCalc.cjs");
const { classifyOutcome, TOKENS } = require("./e2Outcome.cjs");

// THE OUTCOME SHAPES ARE PROBED AGAINST THE REAL CLASSIFIER, so this spike cannot drift
// from the contract it is meant to be exercising
const SUCCESS_RESULT = { outcome: "verified-proof", proof: { p: 1 }, metadata: { height: "1600" },
  proofMsg: "aa", metadataMsg: "bb", unknownFieldsDropped: 0 };
if (classifyOutcome(SUCCESS_RESULT) !== TOKENS.SUCCESS) {
  throw new Error("the probe's success fixture no longer matches the outcome classifier");
}

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed += 1; console.log(`  ok    ${name}`); }
  else { failed += 1; console.error(`  FAIL  ${name}`); }
};
const okTry = (name, fn) => {
  try { ok(name, fn()); }
  catch (e) { failed += 1; console.error(`  FAIL  ${name} threw: ${(e && e.message) || String(e)}`); }
};

// ---- the pool, its members, and the figures the four questions are asked over ----
const CHAIN = "tegara-probe-1";
const h32 = (f) => f.repeat(64 / f.length);
const POOL = h32("ab");
// A IS THE INCOME IDENTITY, so its own rows are self-shares and never carry. B is an
// ordinary member and is the subject of the whole demonstration.
const A = h32("ee"), B = h32("71");
const ALLOCATION = [{ recipientId: A, bps: 5000 }, { recipientId: B, bps: 5000 }];
const ALLOCATION_HASH = h32("c3");

// THE FIGURES, chosen so the carry layer is what makes epoch 1 payable:
//   epoch 0: 120000 distributable, 60000 each. B is BELOW the 100000 minimum, so it is
//            deferred and epoch 0 has NO payable row at all.
//   epoch 1: 100000 distributable, 50000 each. B's effective amount is 50000 + 60000 =
//            110000, which reaches the minimum only because of the carry.
const EPOCH_FIGURES = {
  0: { grossCredits: 120000, feeCredits: 0 },
  1: { grossCredits: 100000, feeCredits: 0 },
};
const EPOCHS = [0, 1];
// TWO HASHES, and the difference is the journal's rule rather than a style choice: a
// transition hash is SHA-256 of the DECODED BYTES, which the journal validator checks, while
// a derived identifier is just a stable 64-hex value from a string
const shaBytes = (hex) => crypto.createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");
const idOf = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");

// ---- THE FAKE PLATFORM: it owns documents, and nothing else decides what exists ----
const makeFakePlatform = () => {
  const docs = new Map();
  const key = (object, k) => [object, k.epochIndex, k.accrualId ?? "", k.partIndex ?? ""].join("|");
  // WHAT EACH TRANSITION WOULD PUT ON THE LEDGER, registered when the writer BUILDS it and
  // applied when the writer BROADCASTS it successfully. The header is not written through
  // the document surface at all, it arrives as a state transition, so a fake that only
  // recorded `documents.write` would never show a header and every epoch would look
  // forever incomplete. Modelling this is the difference between a ledger and a log of one
  // API.
  const pending = new Map();
  // THE CHAIN TIP MOVES. The writer advances an identity's durable frontier from each
  // capture's verified height, and the admission REFUSES a balance read whose height is
  // below that frontier as stale evidence. A fake serving a constant height therefore
  // fails the SECOND epoch's admission, which is a finding about refresh rather than a
  // fixture detail: balance evidence has its own freshness rule, distinct from the
  // lifecycle snapshot's.
  let height = 1000;
  return {
    docs,
    key,
    currentHeight: () => String(height),
    registerTransition: (transitionHash, effect) => pending.set(transitionHash, effect),
    applyTransition: (transitionHash) => {
      const effect = pending.get(transitionHash);
      if (!effect) return false;
      docs.set(key(effect.object, effect.key), effect.fields);
      height += 100; // a transition that lands moves the tip
      return true;
    },
    // the writer's document surface
    fetch: async (object, k) => {
      const f = docs.get(key(object, k));
      return f ? { found: true, fields: f } : { found: false };
    },
    write: async (object, k, payload) => {
      // THE WRITER'S STATED LOCK SET, ENFORCED rather than described. An earlier version
      // of this branch computed the identity-lock condition and then did nothing with it,
      // which is a comment claiming a check that no input could fail.
      if (!fs.existsSync(path.join(STATE_DIR, `oplock-${identityLockName(A)}`))) {
        throw new Error("document write without the held record-writer lock");
      }
      if (!fs.existsSync(path.join(STATE_DIR, `oplock-${poolRunLockName(POOL)}`))) {
        throw new Error("document write outside the held per-pool run lock");
      }
      docs.set(key(object, k), payload);
      return SUCCESS_RESULT;
    },
    has: (object, k) => docs.has(key(object, k)),
  };
};

// ---- THE PER-EPOCH CONTEXT: question 4's candidate answer, built once per epoch ----
// Everything the orchestrator needs to work ONE epoch, derived from that epoch's inputs
// and nothing carried over from another epoch's variables.
const makeEpochContext = (calc, epochIndex, figuresTable = EPOCH_FIGURES) => {
  const figures = figuresTable[epochIndex];
  if (!figures) throw new Error(`no figures for epoch ${epochIndex}`);
  const effective = calc.rowsFor(epochIndex);
  const rows = effective.map((r) => ({
    ...r,
    // the document identity is derived from (pool, epoch, recipient), so it is a function
    // of the context rather than of a helper closing over one epoch
    accrualId: idOf(`${POOL}|${epochIndex}|accrual|${r.recipientId}`),
  }));
  // DEEP-FROZEN, so "immutable context" describes the whole structure rather than its top
  // level. Freezing the outer object while its row objects stayed writable would have been
  // a claim about the shape rather than about the data.
  return Object.freeze({
    epochIndex,
    numbers: Object.freeze({ ...figures, allocationHash: ALLOCATION_HASH,
      memberCount: ALLOCATION.length, calcVersion: 1 }),
    rows: Object.freeze(rows.map((r) => Object.freeze(r))),
    // which rows the epoch expects a receipt for, which is exactly step 5's payable set
    payableAccrualIds: Object.freeze(rows
      .filter((r) => classifyEntitlement(r, A) === "payable")
      .map((r) => r.accrualId)),
  });
};

// ---- THE LIFECYCLE: asynchronous derivation from documents, immutable snapshot ----
/**
 * The OPERATIONAL FORWARD predicate only: an epoch is complete when its header document
 * exists, every member has an accrual document, and every PAYABLE row has a receipt.
 * Rows the carry layer defers and the income identity's own self-shares expect no receipt,
 * which is why the context carries the payable set rather than the row count.
 *
 * THIS IS NOT THE CANONICAL RULE. The audit's record-set assurance additionally walks the
 * reverse enumeration, unknown extras and pool-global checks, and keeps its snapshot
 * limitation. Nothing here claims to replace it.
 */
const deriveOperationalComplete = async (platform, ctx) => {
  // asynchronous on purpose: a real derivation reads Platform documents
  await Promise.resolve();
  const k = { epochIndex: ctx.epochIndex };
  if (!platform.has("header", k)) return false;
  for (const r of ctx.rows) {
    if (!platform.has("accrual", { epochIndex: ctx.epochIndex, accrualId: r.accrualId })) return false;
  }
  for (const accrualId of ctx.payableAccrualIds) {
    if (!platform.has("receipt", { epochIndex: ctx.epochIndex, accrualId })) return false;
  }
  return true;
};

/**
 * THE SNAPSHOT. An asynchronous refresh reads the ledger once for every epoch in the run
 * and freezes the answers. The writer then gets a SYNCHRONOUS strict-boolean lookup, which
 * is what its seam requires and what its guard enforces.
 *
 * IT REFUSES AN EPOCH IT DID NOT EVALUATE rather than answering false, because "not in this
 * snapshot" and "evaluated and incomplete" are different statements and only one of them is
 * an answer.
 */
const refreshLifecycle = async (platform, contexts) => {
  const answers = new Map();
  for (const ctx of contexts.values()) {
    answers.set(ctx.epochIndex, await deriveOperationalComplete(platform, ctx));
  }
  const takenAt = answers.size;
  return Object.freeze({
    takenAt,
    lookup: (epochIndex) => {
      if (!answers.has(epochIndex)) {
        throw new Error(`the lifecycle snapshot did not evaluate epoch ${epochIndex}; refusing to answer for it`);
      }
      return answers.get(epochIndex);
    },
    completeEpochs: () => [...answers.entries()].filter(([, v]) => v).map(([n]) => n),
  });
};

// ---- the writer's dependency composition, rebuilt from scratch on every restart ----
const buildDeps = (platform, calc, contexts, snapshotRef, opts = {}) => {
  const ctxOf = (epochIndex) => {
    const c = contexts.get(epochIndex);
    if (!c) throw new Error(`no per-epoch context for epoch ${epochIndex}`);
    return c;
  };
  return {
    identities: { writer: A, income: A },
    chainIdPin: CHAIN,
    discoveryOpts: { width: 8 },
    feeCeilings: { header: "100", accrual: "100", reservation: "100",
      receipt: "100", part: "100", creditTransfer: "100" },
    transferBytesBound: 100,
    verifyGateCapture: async () => ({ admitted: true }),
    fetchRange: async (start, end) => ({ proved: true,
      epochs: EPOCHS.filter((n) => n >= start && n <= end).map((number) => ({ number })) }),
    // THE SYNCHRONOUS LOOKUP BACKED BY THE CURRENT SNAPSHOT. The indirection through
    // `snapshotRef` is the whole question 2: the orchestrator replaces the snapshot, and
    // the writer never sees a Promise.
    epochDistributionComplete: (epochIndex) => snapshotRef.current.lookup(epochIndex),
    entitlementsForEpoch: (epochIndex) => {
      const given = ctxOf(epochIndex).rows.map((r) => ({
        accrualId: r.accrualId, amountCredits: r.amountCredits, recipientId: r.recipientId,
        ...("carryInCredits" in r ? { carryInCredits: r.carryInCredits } : {}) }));
      // WHAT THE WRITER WAS ACTUALLY HANDED, recorded at the moment it asked. The
      // admission candidate is built from exactly this, so recording it here is
      // intercepting the candidate rather than inferring it.
      if (opts.recordRows) opts.recordRows(epochIndex, given);
      return given;
    },
    epochNumbers: (epochIndex) => ({ ...ctxOf(epochIndex).numbers }),
    resolvePool: () => ({ resolved: true, writerIdentity: A, incomeIdentity: A,
      entitlementsForEpoch: (epochIndex) => ctxOf(epochIndex).rows }),
    // READ AT THE CURRENT TIP, never a remembered one
    fetchBalanceWithMetadata: async () => ({ balance: opts.balance ?? "999999999",
      metadata: { chainId: CHAIN, protocolVersion: 12, height: platform.currentHeight() } }),
    provedHeaderQuery: async () => ({ found: false, proved: true }),
    buildHeaderTransition: ({ epochIndex, expectedContents }) => {
      const bytes = "0102" + String(epochIndex).padStart(4, "0") + "01";
      const transitionHash = shaBytes(bytes);
      // the ledger effect this transition WOULD have, applied only if it broadcasts
      platform.registerTransition(transitionHash,
        { object: "header", key: { epochIndex }, fields: { ...expectedContents } });
      return { transitionBytes: bytes, transitionHash,
        expectedDocumentId: idOf(`${POOL}|${epochIndex}|headerdoc`) };
    },
    buildTransferTransition: ({ epochIndex, accrualId }) => {
      const bytes = "0a0b" + String(epochIndex).padStart(4, "0") + accrualId.slice(0, 4);
      return { transitionBytes: bytes, transitionHash: shaBytes(bytes) };
    },
    buildReservationTransition: ({ epochIndex, accrualId }) => {
      const bytes = "0c0d" + String(epochIndex).padStart(4, "0") + accrualId.slice(0, 4);
      return { transitionBytes: bytes, transitionHash: shaBytes(bytes) };
    },
    reservationDocumentIdOf: () => h32("d1"),
    buildHeaderCapture: ({ poolId, epochIndex, gen, writeAhead }) => ({ v: 1,
      kind: "tegara.e2.headerCapture.v1", object: "header", gen, poolId, epochIndex,
      transitionBytes: writeAhead.transitionBytes, transitionHash: writeAhead.transitionHash,
      proofMsg: "aa".repeat(20), metadataMsg: "bb".repeat(10), contractId: h32("cc"),
      expectedDocumentId: writeAhead.expectedDocumentId,
      expectedContents: writeAhead.expectedContents, inclusionHeight: platform.currentHeight(),
      heightRoute: "tenderdash-tx", signerIdentity: h32("f0"), signerKeyId: 2,
      sig: "00".repeat(65) }),
    buildReceiptCapture: ({ poolId, epochIndex, accrualId, writeAhead }) => ({ v: 1,
      kind: "tegara.e2.receiptCapture.v1", object: "transfer", gen: 1, poolId, epochIndex,
      accrualId, transitionHash: writeAhead.transitionHash,
      transitionBytes: writeAhead.transitionBytes, proofMsg: "cc".repeat(20),
      metadataMsg: "dd".repeat(10), inclusionHeight: platform.currentHeight(),
      heightRoute: "tenderdash-tx",
      signerIdentity: h32("f0"), signerKeyId: 2, sig: "00".repeat(65) }),
    fetchReservation: async () => ({ found: false }),
    observeReceipt: async () => ({ found: false }),
    accrualPayload: (epochIndex, row) => ({ poolId: POOL, epochIndex,
      accrualId: row.accrualId, credits: row.amountCredits }),
    receiptPayloads: () => ({ parts: [{ p: 1 }, { p: 2 }], receipt: { r: 1, proofPartCount: 3 } }),
    // A SUCCESSFUL BROADCAST CHANGES THE LEDGER, which is what makes the lifecycle
    // derivation downstream read state rather than intent
    broadcastAndAwait: async (transitionHash) => {
      platform.applyTransition(transitionHash);
      return SUCCESS_RESULT;
    },
    awaitResult: async (transitionHash) => {
      platform.applyTransition(transitionHash);
      return SUCCESS_RESULT;
    },
    documents: { fetch: platform.fetch, write: platform.write },
  };
};

/** everything a run needs, REBUILT FROM SCRATCH so a restart shares no process memory */
const buildRunState = (platform, opts = {}) => {
  const figures = opts.figures || EPOCH_FIGURES;
  const calc = entitlementCalc.buildCarryCapableEntitlements({
    incomeIdentity: A,
    encodingCeiling: entitlementCalc.SCHEMA_CREDIT_CEILING,
    configuredStart: EPOCHS[0],
    allocation: ALLOCATION,
    epochs: EPOCHS.map((number) => ({ number,
      distributableCredits: String(BigInt(figures[number].grossCredits)
        - BigInt(figures[number].feeCredits)) })),
  });
  const contexts = new Map(EPOCHS.map((n) => [n, makeEpochContext(calc, n, figures)]));
  const snapshotRef = { current: null };
  return { calc, contexts, snapshotRef,
    deps: buildDeps(platform, calc, contexts, snapshotRef, opts) };
};

/** work ONE epoch to its operational end, using only its own context */
const workEpoch = async (platform, state, dir, run, epochIndex, hooks = {}) => {
  const ctx = state.contexts.get(epochIndex);
  const h = await runHeaderStep({ poolId: POOL, dir, deps: state.deps, run });
  if (h.epochIndex !== epochIndex) {
    throw new Error(`the header step selected epoch ${h.epochIndex}, not ${epochIndex}`);
  }
  if (h.status !== "captured" && h.status !== "header-done-transfers-pending") {
    throw new Error(`epoch ${epochIndex} header: ${h.status}`);
  }
  // a second observation point: the header exists and NO accrual does yet
  if (typeof hooks.afterHeader === "function") await hooks.afterHeader();
  const a = await runAccrualStep({ poolId: POOL, dir, deps: state.deps, run, epochIndex });
  if (!a.statuses.every((s) => s.status === "written" || s.status === "present")) {
    throw new Error(`epoch ${epochIndex} accruals: ${a.statuses.map((s) => s.status).join(",")}`);
  }
  // A HOOK BETWEEN THE ACCRUALS AND THE TRANSFERS, so a caller can observe the epoch at
  // the one moment that distinguishes "every document written" from "every payable row
  // paid". Without it the probe never separates the two, and a lifecycle that forgot the
  // receipt requirement entirely would still pass every assertion (found by mutating it).
  if (typeof hooks.beforeTransfers === "function") await hooks.beforeTransfers();
  const outcomes = [];
  for (const r of ctx.rows) {
    if (BigInt(r.amountCredits) <= 0n) continue;
    outcomes.push(await runTransferStep({ poolId: POOL, dir, deps: state.deps, run,
      epochIndex, accrualId: r.accrualId }));
  }
  return { header: h, accruals: a, outcomes };
};

// THE SUMMARY IS THE LAST LINE, always. The mutation driver classifies a run by reading it
// there, and a scratch-path line printed afterwards made every mutation look like a crash.
const finish = () => {
  console.log(`(scratch: ${TMP})`);
  console.log(`\ntwoEpochOrchestrationProbe: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
};

(async () => {
console.log("\n=== TWO-EPOCH ORCHESTRATION PROBE (nonnormative spike) ===\n");

// ============================================================
// VARIANT A: one run token, refreshing lifecycle evidence between epochs
// ============================================================
console.log("VARIANT A: continue within one run token, refreshing evidence between epochs");
const dirA = fs.mkdtempSync(path.join(TMP, "runA-"));
const platformA = makeFakePlatform();
const stateA = buildRunState(platformA);
setStart(POOL, "0", { dir: dirA });

// the carry layer's own arithmetic, before any orchestration
const e0 = stateA.contexts.get(0), e1 = stateA.contexts.get(1);
okTry("epoch 0 owes the member 60000, below the pinned minimum, so it defers and epoch 0 has NO payable row",
  () => e0.rows[1].amountCredits === "60000" && e0.payableAccrualIds.length === 0);
okTry("epoch 1 receives exactly 60000 carry-in and computes 110000 effective",
  () => e1.rows[1].carryInCredits === "60000" && e1.rows[1].amountCredits === "110000");
okTry("and epoch 1 has exactly one payable row, the member's",
  () => e1.payableAccrualIds.length === 1 && e1.payableAccrualIds[0] === e1.rows[1].accrualId);

// THE HEADER REQUIREMENT, BOUND DIRECTLY. The writer always writes the header first, so
// the orchestration alone never reaches a state where accruals exist and the header does
// not, and a lifecycle that dropped the header check entirely passed the whole probe.
// Binding it needs the predicate driven at a state the writer cannot produce.
{
  const scratch = makeFakePlatform();
  const scratchState = buildRunState(scratch);
  const ctx0 = scratchState.contexts.get(0);
  for (const r of ctx0.rows) {
    scratch.docs.set(scratch.key("accrual", { epochIndex: 0, accrualId: r.accrualId }), { any: 1 });
  }
  const withoutHeader = await deriveOperationalComplete(scratch, ctx0);
  scratch.docs.set(scratch.key("header", { epochIndex: 0 }), { any: 1 });
  const withHeader = await deriveOperationalComplete(scratch, ctx0);
  okTry("with every accrual present but NO header, the epoch derives incomplete, and adding the header alone completes it",
    () => withoutHeader === false && withHeader === true);
}

// (1) both epochs initially evaluate as incomplete, derived from an EMPTY fake ledger
stateA.snapshotRef.current = await refreshLifecycle(platformA, stateA.contexts);
okTry("both epochs initially derive as incomplete, from documents rather than a flag",
  () => stateA.snapshotRef.current.lookup(0) === false
    && stateA.snapshotRef.current.lookup(1) === false);

const runA1 = await startRun({ poolId: POOL, dir: dirA, deps: stateA.deps });
okTry("the run start measures both epochs lagging and reports the frontier deferral as zero before any work",
  () => runA1.lag === 2 && runA1.carriedCredits === "0");

// (2,3,4) the writer selects epoch 0 and works it
let afterHeader0 = null;
const workedA0 = await workEpoch(platformA, stateA, dirA, runA1, 0, {
  afterHeader: async () => {
    afterHeader0 = {
      snapshot: await refreshLifecycle(platformA, stateA.contexts),
      header: platformA.has("header", { epochIndex: 0 }),
      accrual: platformA.has("accrual", { epochIndex: 0, accrualId: e0.rows[0].accrualId }),
    };
  },
});
okTry("with epoch 0's header written but no accrual yet, the epoch derives INCOMPLETE",
  () => afterHeader0 !== null && afterHeader0.snapshot.lookup(0) === false
    && afterHeader0.header === true && afterHeader0.accrual === false);
okTry("the writer selected epoch 0", () => workedA0.header.epochIndex === 0);
okTry("epoch 0 wrote a header and an accrual per member",
  () => platformA.has("header", { epochIndex: 0 }) && workedA0.accruals.statuses.length === 2);
okTry("the 60000 member row is classified CARRIED, with no transfer machinery attempted",
  () => workedA0.outcomes.some((o) => o.status === "below-minimum-carried")
    && !platformA.has("receipt", { epochIndex: 0, accrualId: e0.rows[1].accrualId }));
okTry("and the income identity's own row settles without a transfer",
  () => workedA0.outcomes.some((o) => o.status === "self-share-settled"));

// (5) a REFRESHED snapshot derives epoch 0 complete from the changed ledger
const beforeRefresh = stateA.snapshotRef.current.lookup(0);
stateA.snapshotRef.current = await refreshLifecycle(platformA, stateA.contexts);
okTry("epoch 0 derives as COMPLETE only after a refresh, and the stale snapshot still said incomplete",
  () => beforeRefresh === false && stateA.snapshotRef.current.lookup(0) === true);
okTry("epoch 1 is still incomplete in the same snapshot",
  () => stateA.snapshotRef.current.lookup(1) === false);

// (6,7,8,9) the next selection is epoch 1, which pays because of the carry
// AND THE ONE OBSERVATION THAT SEPARATES "documents written" FROM "payables paid":
// between epoch 1's accruals and its transfer, every document exists except the receipt,
// and the epoch must still derive INCOMPLETE. A lifecycle that dropped the receipt
// requirement passes everything else in this probe.
// THE OBSERVATIONS ARE TAKEN AT THAT MOMENT, not read back afterwards. Reading the
// platform after workEpoch returns would see the receipt that the transfers went on to
// write, which is how the first version of this assertion failed against correct code.
let midEpoch1 = null;
const workedA1 = await workEpoch(platformA, stateA, dirA, runA1, 1, { beforeTransfers: async () => {
  midEpoch1 = {
    snapshot: await refreshLifecycle(platformA, stateA.contexts),
    header: platformA.has("header", { epochIndex: 1 }),
    accrual: platformA.has("accrual", { epochIndex: 1, accrualId: e1.rows[1].accrualId }),
    receipt: platformA.has("receipt", { epochIndex: 1, accrualId: e1.rows[1].accrualId }),
  };
} });
okTry("with epoch 1's header and accruals written but its payable row unpaid, the epoch still derives INCOMPLETE",
  () => midEpoch1 !== null && midEpoch1.snapshot.lookup(1) === false
    && midEpoch1.header === true && midEpoch1.accrual === true && midEpoch1.receipt === false);
okTry("the next selection is epoch 1, never epoch 0 again", () => workedA1.header.epochIndex === 1);
okTry("epoch 1's payable row completes its transfer and receipt",
  () => workedA1.outcomes.some((o) => o.status === "completed")
    && platformA.has("receipt", { epochIndex: 1, accrualId: e1.rows[1].accrualId }));
// IDENTIFIER SEPARATION, ASSERTED AGAINST THE DERIVATION. Counting keys under an `epoch|1`
// bucket proves only that the fake filed records under epoch 1, because the epoch is a
// separate component of that key: reusing epoch 0's accrual identifier verbatim still
// lands in the epoch 1 bucket and still passes such a count. What binds the property is
// comparing each identifier to what the derivation says it should be, and to the other
// epoch's.
okTry("each epoch's accrual identifiers are exactly what (pool, epoch, recipient) derives",
  () => e0.rows.every((r) => r.accrualId === idOf(`${POOL}|0|accrual|${r.recipientId}`))
    && e1.rows.every((r) => r.accrualId === idOf(`${POOL}|1|accrual|${r.recipientId}`)));
okTry("and NO epoch-1 identifier equals its epoch-0 counterpart, member by member",
  () => e0.rows.length === e1.rows.length
    && e0.rows.every((r, i) => r.recipientId === e1.rows[i].recipientId
      && r.accrualId !== e1.rows[i].accrualId));
okTry("the epoch-1 documents on the fake ledger carry the epoch-1 identifiers, not merely the epoch-1 bucket",
  () => platformA.has("accrual", { epochIndex: 1, accrualId: e1.rows[1].accrualId })
    && !platformA.has("accrual", { epochIndex: 1, accrualId: e0.rows[1].accrualId }));

// (10) a final refresh reports both complete
stateA.snapshotRef.current = await refreshLifecycle(platformA, stateA.contexts);
okTry("a final refresh reports BOTH epochs complete",
  () => stateA.snapshotRef.current.lookup(0) === true
    && stateA.snapshotRef.current.lookup(1) === true);
// THE SNAPSHOT REFUSES AN EPOCH IT DID NOT EVALUATE, rather than answering false. "not in
// this snapshot" and "evaluated and incomplete" are different statements and only one of
// them is an answer, which matters the moment a run's epoch set and a snapshot's disagree.
okTry("the snapshot refuses an epoch it never evaluated instead of answering false",
  () => { try { stateA.snapshotRef.current.lookup(99); return false; }
    catch (e) { return /did not evaluate epoch 99/.test(e.message); } });

const runA2 = await startRun({ poolId: POOL, dir: dirA, deps: stateA.deps });
okTry("and a fresh run start over the completed pool measures no lag and no deferral",
  () => runA2.lag === 0 && runA2.carriedCredits === "0");

// ============================================================
// THE FAKE'S OWN REFUSALS, AND THE CONTEXT'S IMMUTABILITY
// ============================================================
// Both were CLAIMED by this file and neither was exercised. Disabling the identity-lock
// refusal left the probe passing 35 of 35, which means the lock claim was a comment rather
// than a check as far as any evidence went, and freezing the rows was asserted nowhere at
// all. A guard nothing reaches is indistinguishable from a guard that is not there.
console.log("\nTHE FAKE'S OWN REFUSALS, AND THE CONTEXT'S IMMUTABILITY");
{
  const scratch = makeFakePlatform();
  const k = { epochIndex: 0, accrualId: h32("a1") };
  let noLocks = null;
  try { await scratch.write("accrual", k, { any: 1 }); noLocks = "no refusal"; }
  catch (e) { noLocks = e.message; }
  okTry("a document write with NO lock held is refused by the fake, naming the record-writer lock",
    () => /without the held record-writer lock/.test(noLocks));

  const locks = acquireIdentityLocks([A]);
  let noPoolLock = null;
  try {
    try { await scratch.write("accrual", k, { any: 1 }); noPoolLock = "no refusal"; }
    catch (e) { noPoolLock = e.message; }
  } finally { locks.release(); }
  okTry("and with the writer identity lock held but NOT the pool lock, it is refused for the pool lock",
    () => /outside the held per-pool run lock/.test(noPoolLock));
  okTry("neither refused write reached the ledger",
    () => !scratch.has("accrual", k));
}
{
  // DEEP IMMUTABILITY, asserted rather than described. Under strict mode a write to a
  // frozen object throws, so the assertion is that each of the three levels does.
  const probeState = buildRunState(makeFakePlatform());
  const ctx = probeState.contexts.get(1);
  const throwsOnWrite = (fn) => { try { fn(); return false; } catch { return true; } };
  okTry("the context itself is frozen",
    () => throwsOnWrite(() => { ctx.epochIndex = 99; }));
  okTry("its rows ARRAY is frozen",
    () => throwsOnWrite(() => { ctx.rows[0] = null; }));
  okTry("each individual ROW is frozen, which the top-level freeze alone would not give",
    () => throwsOnWrite(() => { ctx.rows[0].amountCredits = "1"; }));
  okTry("and the payable identifier list is frozen",
    () => throwsOnWrite(() => { ctx.payableAccrualIds.push("x"); }));
}

// ============================================================
// THE EPOCH 1 ADMISSION CANDIDATE AND ITS THRESHOLD
// ============================================================
// Observing that admission RAN and did not refuse proves only that the balance supplied
// was large enough. It says nothing about which amount entered the threshold, and that was
// an acceptance requirement rather than a detail.
//
// TWO THINGS ARE BOUND HERE, because neither alone is enough. First the CANDIDATE: the
// writer builds it from exactly the rows this probe hands back, so those rows are recorded
// at the moment the writer asks for them. Second the THRESHOLD's DEPENDENCE on those
// amounts, established differentially. Reproducing the threshold formula here would be a
// second implementation of the arithmetic under test, and it would agree with itself.
//
// THE DIFFERENTIAL VARIES EPOCH 1 ONLY. An earlier version varied epoch 0's distributable
// amount, reasoning that it changes what the member defers. It does, but it also changes
// epoch 0's OWN outstanding obligations, which the admission still counts, so the observed
// difference was 30000 where the carry accounted for 10000. Holding epoch 0 fixed and
// moving epoch 1's gross by 2X moves each of its two positive rows by X, and nothing else.
console.log("\nTHE EPOCH 1 ADMISSION CANDIDATE AND ITS THRESHOLD");
const epoch1Admission = async (epoch1Gross) => {
  const dir = fs.mkdtempSync(path.join(TMP, "thr-"));
  const platform = makeFakePlatform();
  const figures = { 0: { grossCredits: 120000, feeCredits: 0 },
    1: { grossCredits: epoch1Gross, feeCredits: 0 } };
  const seen = new Map();
  const record = (epochIndex, rows) => { if (epochIndex === 1) seen.set("rows", rows); };

  const rich = buildRunState(platform, { figures, recordRows: record });
  setStart(POOL, "0", { dir });
  rich.snapshotRef.current = await refreshLifecycle(platform, rich.contexts);
  const run = await startRun({ poolId: POOL, dir, deps: rich.deps });
  await workEpoch(platform, rich, dir, run, 0);
  rich.snapshotRef.current = await refreshLifecycle(platform, rich.contexts);

  // epoch 1's header at a balance of ONE credit: the admission refuses and names the
  // reserve threshold it required
  const poor = buildRunState(platform, { figures, balance: "1", recordRows: record });
  poor.snapshotRef.current = await refreshLifecycle(platform, poor.contexts);
  const poorRun = await startRun({ poolId: POOL, dir, deps: poor.deps });
  let threshold = null, note = "the admission did not refuse at a balance of 1";
  try { await runHeaderStep({ poolId: POOL, dir, deps: poor.deps, run: poorRun }); }
  catch (e) {
    const m = /reserve threshold (\d+)/.exec(e.message);
    threshold = m ? BigInt(m[1]) : null;
    note = e.message.slice(0, 90);
  }
  return { threshold, note, candidateRows: seen.get("rows") || null };
};

const admit110 = await epoch1Admission(100000);   // member: 50000 owed + 60000 carried = 110000
const admit130 = await epoch1Admission(140000);   // member: 70000 owed + 60000 carried = 130000

okTry("the epoch 1 admission refuses at a balance of one credit and names the reserve threshold it required",
  () => admit110.threshold !== null && admit130.threshold !== null);
// THE CANDIDATE ITSELF: exactly the rows the writer turned into positiveEntitlements
okTry("the rows the writer was handed for epoch 1 carry the member at EXACTLY 110000, with 60000 of it carried in",
  () => { const m = (admit110.candidateRows || []).find((r) => r.recipientId === B);
    return !!m && m.amountCredits === "110000" && m.carryInCredits === "60000"; });
okTry("and the income identity's own row in that same candidate is its 50000 self-share",
  () => { const self = (admit110.candidateRows || []).find((r) => r.recipientId === A);
    return !!self && self.amountCredits === "50000" && !("carryInCredits" in self); });
// THE DEPENDENCE: epoch 1 gross up by 40000 moves each of its two rows by 20000
okTry("raising epoch 1's gross by 40000 raises both its positive rows by 20000 each",
  () => { const m = (admit130.candidateRows || []).find((r) => r.recipientId === B);
    const self = (admit130.candidateRows || []).find((r) => r.recipientId === A);
    return !!m && m.amountCredits === "130000" && !!self && self.amountCredits === "70000"; });
okTry("and the reserve threshold rises by EXACTLY those 40000, so the amounts the candidate carried are what entered it",
  () => admit130.threshold - admit110.threshold === 40000n);
okTry("the threshold is at least the sum of epoch 1's positive rows, which the carried member dominates",
  () => admit110.threshold >= 160000n);

// ============================================================
// VARIANT B: stop after epoch 0, rebuild everything, restart
// ============================================================
console.log("\nVARIANT B: stop after epoch 0, rebuild every dependency, restart on a new token");
const dirB = fs.mkdtempSync(path.join(TMP, "runB-"));
const platformB = makeFakePlatform();
const POOL_B_STATE = buildRunState(platformB);
setStart(POOL, "0", { dir: dirB });
POOL_B_STATE.snapshotRef.current = await refreshLifecycle(platformB, POOL_B_STATE.contexts);
const runB1 = await startRun({ poolId: POOL, dir: dirB, deps: POOL_B_STATE.deps });
await workEpoch(platformB, POOL_B_STATE, dirB, runB1, 0);

// WHAT THIS VARIANT IS, at its real width: SAME-PROCESS DEPENDENCY RECONSTRUCTION over a
// RETAINED fake ledger and a real journal. A new calculation, new contexts, a new
// dependency object and a new snapshot are built, and completion and carry are recomputed
// rather than remembered.
//
// IT IS NOT A PROCESS RESTART, and saying so matters. `platformB` is reused, and it holds
// the document map, the pending-transition map and the height in memory. The carry is also
// recomputed from this file's fixture constants rather than from the journal, since
// `buildRunState` reads EPOCH_FIGURES and never calls runFromJournal. A true restart, and
// a carry reconstructed from journaled headers, belong to the canonical restart matrix.
const restarted = buildRunState(platformB);
restarted.snapshotRef.current = await refreshLifecycle(platformB, restarted.contexts);
okTry("the restart derives epoch 0 complete from the fake ledger alone, with no carried-over state",
  () => restarted.snapshotRef.current.lookup(0) === true
    && restarted.snapshotRef.current.lookup(1) === false);
okTry("and it recomputes the same carry, so epoch 1 is still 110000 with 60000 carried in",
  () => restarted.contexts.get(1).rows[1].amountCredits === "110000"
    && restarted.contexts.get(1).rows[1].carryInCredits === "60000");

const runB2 = await startRun({ poolId: POOL, dir: dirB, deps: restarted.deps });
okTry("the restarted run start measures only epoch 1 lagging",
  () => runB2.lag === 1);
okTry("and it reports the frontier deferral as zero, because epoch 1's carry is now payable",
  () => runB2.carriedCredits === "0");

// THE OLD TOKEN MUST REFUSE once a newer measurement exists
let oldTokenRefused = null;
try {
  await runHeaderStep({ poolId: POOL, dir: dirB, deps: restarted.deps, run: runB1 });
  oldTokenRefused = false;
} catch (e) { oldTokenRefused = /measurement|run token|stale/i.test(e.message) ? e.message : `unexpected: ${e.message}`; }
okTry("the OLD run token refuses after the restarted run start appended a newer measurement",
  () => typeof oldTokenRefused === "string" && !oldTokenRefused.startsWith("unexpected"));

const workedB1 = await workEpoch(platformB, restarted, dirB, runB2, 1);
okTry("the restarted run works epoch 1 to completion on the new token",
  () => workedB1.header.epochIndex === 1 && workedB1.outcomes.some((o) => o.status === "completed"));

restarted.snapshotRef.current = await refreshLifecycle(platformB, restarted.contexts);
okTry("and a final refresh reports both epochs complete across the restart",
  () => restarted.snapshotRef.current.lookup(0) === true
    && restarted.snapshotRef.current.lookup(1) === true);

finish();
})().catch((e) => {
  // AN ORCHESTRATION FAILURE IS A RECORDED FAILURE, not a crash. A mutation that makes the
  // writer select the wrong epoch, or select none, throws out of workEpoch rather than
  // failing an assertion, and a run that dies before its summary reads to the mutation
  // driver as a crash rather than a detection. Three mutations were classified that way
  // before this existed, including two that are precisely the point of the probe.
  failed += 1;
  console.error(`  FAIL  the orchestration did not complete: ${(e && e.message) || String(e)}`);
  finish();
});
