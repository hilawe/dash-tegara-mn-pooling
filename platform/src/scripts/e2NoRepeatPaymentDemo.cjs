/**
 * THE DEMONSTRATION: EVERY MEMBER IS PAID WHAT THEY ARE OWED, EXACTLY ONCE, ACROSS AN INTERRUPTION.
 *
 * WHY THIS EXISTS, and why it is not another unit test. The restart matrix established that the
 * LOOP stops and resumes and that the JOURNAL recovers. Neither establishes the property the
 * product actually rests on, which an independent process review named directly: journal recovery
 * does not show that an EXTERNAL PAYMENT cannot repeat. A credit transfer is irreversible. If a
 * run is interrupted after a transfer reaches the network and before the record of it is
 * committed, a resume that re-sends pays that member twice out of the pool's funds.
 *
 * WHAT WIDENED IT (2026-09-21), and it is the reason the pool resolution was extracted first:
 *
 *   - THE POOL IS RESOLVED FOR REAL. The rows come from `e2PoolResolution`, driven over this
 *     file's fake transport, so the amounts are the carry-capable calculation's over a proved
 *     allocation rather than a literal written here. The WRITER'S row source and the ADMISSION'S
 *     are THE SAME RESOLUTION, so the two seams agree by construction instead of by two fixtures
 *     that happen to match.
 *
 *   - THE POOL PAYS TWO MEMBERS, not one, because a real allocation has more than one owner. The
 *     earlier claim covered a single accrual, which is narrower than the product needs: an
 *     interruption that re-paid the SECOND member while the first was untouched would have gone
 *     unseen.
 *
 *   - THE LEDGER RECORDS THE AMOUNT, decoded from the bytes that left rather than read from a
 *     label, so the demonstration holds what was PAID against what the resolution said was OWED.
 *     A review previously re-sent the same transfer in two other spellings and a label-based
 *     record missed it, which is why identity is decoded and never asserted.
 *
 * WHAT MAKES IT A DEMONSTRATION RATHER THAN A TEST OF THE JOURNAL:
 *
 *   - THE INTERRUPTION IS A REAL PROCESS ENDING. Each phase runs the REAL `runTransferStep` in a
 *     CHILD PROCESS which ends abruptly through `process.exit`, so no `finally` runs, no lock is
 *     released, no buffered write is flushed by unwinding. A simulated restart inside one process
 *     cannot show this, because the process that "crashed" is the one doing the checking.
 *
 *   - THE EVIDENCE IS AN INDEPENDENT RECORD OF THE OUTSIDE WORLD. The injected broadcast adapter
 *     appends one line to an EXTERNAL EFFECT LEDGER on disk BEFORE it returns or ends the
 *     process. That file stands in for the chain. It is written by the harness, never read by the
 *     code under test, and never derived from the journal.
 *
 * WHAT IT ESTABLISHES, at its real width. Across a real process boundary, at each interruption
 * point, the external effect ledger holds AT MOST ONE payment per accrual, and each payment's
 * amount is the one the resolution computed for that member. It uses the harness's transport, not
 * a network, so it establishes the WRITER'S behaviour, not the network's deduplication. It says
 * nothing about a transfer the network itself might duplicate, and it covers ONE epoch.
 *
 * WHAT IT ALSO SHOWS, and it is a cost rather than a guarantee. An abrupt end leaves the operation
 * locks held on disk, and this store never reclaims a stale-looking lock automatically. So the
 * resume is NOT automatic: it refuses until an operator clears them. The demonstration performs
 * that clearing as a LABELLED OPERATOR STEP rather than hiding it.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

// ---- the harness store, established before any project module loads it ----
const ROOT = process.env.E2_DEMO_ROOT
  || fs.mkdtempSync(path.join(os.tmpdir(), "tegara-norepeat-"));
process.env.TEGARA_ENV_PATH = path.join(ROOT, "env.local");

const envStore = require("./envStore.cjs");
const { STATE_DIR } = envStore;

// THE STORE AND ITS STATE DIRECTORY ARE PAIRED, and the pairing is what lets a lock be shared
// ACROSS PROCESSES, which is the whole basis of this demonstration. Both roles run this, and it
// is idempotent, so the child inherits exactly the store the parent set up.
const ensureStore = () => {
  if (!fs.existsSync(process.env.TEGARA_ENV_PATH)) {
    fs.writeFileSync(process.env.TEGARA_ENV_PATH,
      "MNEMONIC=m\nSTATE_MIGRATED=1\nSTATE_STORE_ID=00112233aabbccdd\n");
  }
  fs.mkdirSync(STATE_DIR, { recursive: true });
  const id = path.join(STATE_DIR, "store.id");
  if (!fs.existsSync(id)) fs.writeFileSync(id, "00112233aabbccdd");
};
ensureStore();
// ---- THE INTERRUPTION HOOK ON THE JOURNAL, INSTALLED BEFORE THE WRITER LOADS ----
// `e2Distribute` DESTRUCTURES `appendRecord` out of the store at load time, so a patch applied
// afterwards would never be seen by it. Patching the module object here, before that require
// runs, is what lets a phase end the process on either side of a specific journal append. This
// is the same reason the child is a separate process: the interruption has to be real.
//
// THE POINTS THIS REACHES are the four record kinds the transfer sequence commits, each for the
// object it belongs to, which together with the two adapter-level points below give every window
// an independent review swept by hand.
const jstore = require("./e2JournalStore.cjs");
const { K: JK } = require("./e2Journal.cjs");
const { RECEIPT_KIND } = require("./e2CaptureRecord.cjs");
const journalStage = (rec) => {
  if (!rec || typeof rec !== "object") return null;
  const obj = rec.object;
  if (rec.kind === JK.WRITE_AHEAD && (obj === "transfer" || obj === "reservation")) return `${obj}/writeAhead`;
  if (rec.kind === JK.SENT_MARKER && (obj === "transfer" || obj === "reservation")) return `${obj}/sentMarker`;
  if (rec.kind === JK.RESERVATION_SUCCESS) return "reservation/reservationSuccess";
  if (rec.kind === RECEIPT_KIND && obj === "transfer") return "transfer/receiptCapture";
  return null;
};
// installed unconditionally so the tag mapping is exercised on every run, not only interrupted
// ones; with no interrupt configured `endHereGlobal` is a no-op and the wrapper is transparent
let endHereGlobal = () => {};
const realAppendRecord = jstore.appendRecord;
jstore.appendRecord = (poolId, committedOffset, payloadObj, dir) => {
  const stage = journalStage(payloadObj);
  if (stage) endHereGlobal(`${stage}/before`);
  const out = realAppendRecord(poolId, committedOffset, payloadObj, dir);
  if (stage) endHereGlobal(`${stage}/after`);
  return out;
};

const distribute = require("./e2Distribute.cjs");
const { setStart, startRun, runHeaderStep, runAccrualStep, runTransferStep,
  poolRunLockName } = distribute;
const { identityLockName } = require("./e2BalanceCheck.cjs");
const { openValidatedJournal } = require("./e2Journal.cjs");
const poolResolution = require("./e2PoolResolution.cjs");
const formationCore = require("./formationCore.cjs");
const entitlementCalc = require("./entitlementCalc.cjs");

const h32 = (f) => f.repeat(64 / f.length);
const sha = (hex) => crypto.createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");
const W = h32("11"); // the record writer identity
const I = h32("22"); // the income identity, which is also the pool document's owner
const RECEIPT_OWNER = h32("33");
const OWNER_A = h32("71");
const OWNER_B = h32("72");
const BPS_A = 6000, BPS_B = 4000;
const CHAIN = "demo-chain-pin";
const EPOCH = 5;
const POOL = "ab".repeat(16) + "0".repeat(32);
// FIGURES LARGE ENOUGH THAT BOTH SHARES ARE PAYABLE. Below the pinned per-transfer minimum a row
// classifies as carried and never reaches the transfer machinery this demonstration is about, so
// a smaller fixture would have demonstrated the wrong thing quietly.
const GROSS = "2000000", FEE = "20000";
const MEMBERS = 2;

const b58Of = (hex) => `b58:${hex}`;
const idHex = (v) => {
  const s = typeof v === "string" ? v : String(v);
  return s.startsWith("b58:") ? s.slice(4) : s;
};

// ---- THE EXTERNAL EFFECT LEDGER AND THE DECODER THAT SAYS WHAT A PAYMENT IS ----
// One line per transition that left the machine, appended and fsynced before the adapter returns
// or ends the process. It is the harness's own record, never the journal's, and the payment count
// is read from here and nowhere else.
//
// BOTH LIVE IN `e2PaymentLedger.cjs` rather than here, because the multi-epoch demonstration
// reads the same ledger and is judged by the same decoder. Two copies could disagree about what
// counts as a payment and both would look green while doing so. The decoder is the ORACLE these
// demonstrations are judged by, so it has its own battery: identity is decoded from the bytes,
// never taken from a label, after a review re-sent one transfer as uppercase hex and as a Buffer
// and a label-based record filed both as something else.
const paymentLedger = require("./e2PaymentLedger.cjs");
const { encodeTransfer, decodeTransfer } = paymentLedger;
const LEDGER = path.join(ROOT, "events.jsonl");
// THE NON-PAYMENT SHAPES THIS HARNESS BUILDS ARE DECLARED, so a send matching none of them is
// UNRECOGNIZED rather than absorbed into a catch-all class that nothing can fall outside of.
const OTHER_SHAPES = Object.freeze({ reservation: "0c0d", header: "0102" });
// ONE APPEND-ONLY EVENT LOG, shared with the multi-epoch demonstration. This one records only
// sends, because a single-epoch run makes no completion declarations and so has no moment for the
// log's ORDER to carry; the multi-epoch one needs that ordering and both read the same module.
const effects = paymentLedger.makeEventLog(LEDGER, { otherShapes: OTHER_SHAPES });
const recordExternalEffect = (entry) => effects.record(entry);
const externalEffects = () => effects.events();

const SUCCESS = { outcome: "verified-proof", proof: { p: 1 }, metadata: { height: "1000" },
  proofMsg: "aa", metadataMsg: "bb", unknownFieldsDropped: 0 };

// ---- THE REAL POOL RESOLUTION, over this harness's fake transport ----
// The proved query serves a pool document owned by the income identity and a completion receipt
// carrying the allocation; the journal supplies the epoch. Everything the resolution DECIDES is
// the real module's, which is what the extraction was for.
const allocationRows = () => Buffer.from(JSON.stringify(
  ["tegara-completion-allocation", 1, h32("cc"), POOL, "target",
    [[b58Of(OWNER_A), "500", BPS_A, "sc"], [b58Of(OWNER_B), "500", BPS_B, "sc"]]]), "utf8");
const mkDoc = (idv, owner, props) => ({ id: b58Of(idv), getOwnerId: () => b58Of(owner),
  getProperties: () => props });
const runEpoch = () => ({ number: EPOCH,
  distributableCredits: String(BigInt(GROSS) - BigInt(FEE)),
  allocationHash: h32("7a"), memberCount: MEMBERS, grossCredits: GROSS, feeCredits: FEE });

const resolvePoolForDemo = async () => {
  const rows = allocationRows();
  const resolve = poolResolution.makeResolveProvedPool({
    provedQuery: async (type) => [type === "pool"
      ? mkDoc(POOL, I, { nodeType: "evo" })
      : mkDoc(h32("99"), RECEIPT_OWNER, { allocationRows: rows,
        allocationHash: formationCore.allocationHash(Buffer.from(rows)) })],
    contractId: h32("cc"), writerHex: W, b58Of, idHex,
    encodingCeiling: entitlementCalc.SCHEMA_CREDIT_CEILING,
    openJournalFor: () => ({ configuredStartEpoch: EPOCH, epochs: [runEpoch()] }),
    runFromJournal: (read) => read.epochs,
    docIdForIn: (poolId, epochIndex, type, subject) => ({
      hex: crypto.createHash("sha256")
        .update(`${poolId}:${epochIndex}:${type}:${subject}`).digest("hex") }),
    checkReceiptAgainstPool: () => ({ ok: true }),
  });
  return resolve(POOL);
};

// THE HEADER NUMBERS ARE INTEGERS, which the journal schema requires, while the resolution
// reconciles them as canonical decimal strings. Both readings come from the one pair of constants
// here, so the two cannot drift.
const EPOCH_NUMBERS = { grossCredits: Number(GROSS), feeCredits: Number(FEE),
  allocationHash: h32("ee"), memberCount: MEMBERS, calcVersion: 1 };

// ---- the dependency bundle, with the ONE adapter that reaches the outside world instrumented ----
const mkDeps = (poolId, interruptAt, resolution) => {
  const ledger = new Map();
  const docKey = (object, key) => [object, key.epochIndex, key.accrualId ?? "", key.partIndex ?? ""].join("|");
  // THE WRITER'S ROWS AND THE ADMISSION'S COME FROM THE SAME RESOLUTION, so the two seams cannot
  // disagree about what is owed. The writer's hook takes only an epoch, the admission's also
  // takes the journaled numbers, and both reach the one calculation underneath.
  const rowsFor = (epochIndex) => resolution.entitlementsForEpoch(epochIndex,
    { grossCredits: GROSS, feeCredits: FEE, memberCount: MEMBERS });
  const endHere = (where) => {
    if (interruptAt === where) {
      // an ABRUPT end: no finally runs, no lock is released, nothing is unwound.
      process.exit(9);
    }
  };
  // the journal hook installed at load time shares this one decision, so a phase names a
  // journal point and an adapter point in exactly the same way
  endHereGlobal = endHere;
  return {
    identities: { writer: W, income: I },
    verifyGateCapture: async () => ({ admitted: true }),
    feeCeilings: { header: "100", accrual: "100", reservation: "100", receipt: "100",
      part: "100", creditTransfer: "100" },
    chainIdPin: CHAIN,
    discoveryOpts: { width: 8 },
    epochDistributionComplete: () => false,
    fetchRange: async (start, end) => {
      const epochs = [];
      for (let n = start; n <= Math.min(end, EPOCH); n++) epochs.push({ number: n });
      return { epochs, proved: true };
    },
    entitlementsForEpoch: rowsFor,
    epochNumbers: () => EPOCH_NUMBERS,
    resolvePool: () => resolution,
    fetchBalanceWithMetadata: async () => ({ balance: "999999999999",
      metadata: { chainId: CHAIN, protocolVersion: 12, height: "1000" } }),
    buildHeaderTransition: ({ epochIndex }) => {
      const bytes = "0102" + String(epochIndex).padStart(4, "0") + "01";
      return { transitionBytes: bytes, transitionHash: sha(bytes), expectedDocumentId: h32("dd") };
    },
    buildHeaderCapture: ({ writeAhead, epochIndex }) => ({ v: 1,
      kind: "tegara.e2.headerCapture.v1", object: "header", gen: 1, poolId, epochIndex,
      transitionBytes: writeAhead.transitionBytes, transitionHash: writeAhead.transitionHash,
      proofMsg: "aa".repeat(20), metadataMsg: "bb".repeat(10), contractId: h32("cc"),
      expectedDocumentId: writeAhead.expectedDocumentId,
      expectedContents: writeAhead.expectedContents, inclusionHeight: "1500",
      heightRoute: "tenderdash-tx", signerIdentity: h32("f0"), signerKeyId: 2, sig: "00".repeat(65) }),
    provedHeaderQuery: async () => ({ found: false }),

    // ---- THE ONE ADAPTER THAT REACHES THE OUTSIDE WORLD ----
    broadcastAndAwait: async (hash, bytes) => {
      const decoded = decodeTransfer(bytes);
      // WHICH SEND THIS IS, named so a phase can interrupt the reservation's send and the
      // transfer's send separately. The reservation reaches the ledger too, but it moves no
      // credits; only a decoded transfer counts as a payment.
      const stage = decoded ? "transfer/send" : "reservation/send";
      endHere(`${stage}/before`);
      if (decoded) endHere("after-marker-before-send"); // kept: the original phase name
      // THE ENTRY IS BUILT BY THE SHARED LEDGER from the bytes that left, not from what this
      // adapter believes it is sending, so both demonstrations classify a send identically.
      recordExternalEffect(effects.entryForSend(hash, bytes));
      endHere(`${stage}/after`);
      if (decoded) endHere("after-send-before-capture"); // kept: the original phase name
      return SUCCESS;
    },
    /**
     * the wait-only recovery route. It must NEVER reach the outside world, so it records no
     * external effect: if the writer ever resolved a pending send by sending again, the ledger
     * would gain a line and this demonstration would say so.
     *
     * IT ALSO MUST NOT ANSWER SUCCESS FOR A TRANSITION THAT NEVER LEFT (a soundness-review finding). It did until
     * 2026-09-21, unconditionally, which is the adapter-always-answers-true shape a healthy run
     * cannot detect. The consequence was specific: interrupted with the sent marker committed and
     * the transition not yet sent, the resume asked this route what had happened, was told the
     * transition succeeded, and captured a receipt for a payment that never left. The phase table
     * below recorded the member as staying unpaid, which was true, but the ROUTE it travelled to
     * get there was a fabricated success rather than the unresolved answer the writer handles.
     * The product asked the right question and the harness answered it wrongly.
     *
     * It now answers from the external effect ledger, the harness's own record of what left. A
     * hash that is not in it has NO RESULT, which is a transport failure and not a refusal, so
     * the writer classifies it unresolved and returns its operator condition.
     */
    awaitResult: async (hash) => {
      const left = effects.events().some((e) => e.kind === "send" && e.hash === hash);
      if (left) return SUCCESS;
      return { outcome: "transport-failure",
        reason: "no result for this transition: it never reached the transport" };
    },

    transferBytesBound: 4096,
    buildTransferTransition: ({ accrualId, recipientId, amountCredits }) => {
      // THE RECIPIENT GOES INTO THE BYTES. The earlier envelope dropped the recipient the writer
      // passes, so two obligations differing only in who is paid encoded identically and a
      // recipient error was unobservable through this ledger.
      const bytes = encodeTransfer(accrualId, recipientId, amountCredits);
      return { transitionBytes: bytes, transitionHash: sha(bytes) };
    },
    buildReservationTransition: ({ accrualId }) => {
      const b = "0c0d" + accrualId;
      return { transitionBytes: b, transitionHash: sha(b) };
    },
    // a soundness-review finding shape: answers { found, documentId } and is keyed by the accrual it is asked
    // about, so a resume that built nothing still gets an answer.
    // THE CLAIM READ (NONCE_OWNERSHIP.md) answers "no other accrual claims these bytes", which is
    // TRUE in this harness: one pool, and transfer bytes that differ per accrual. The collision and
    // failure cases live in e2DistributeTest's two-pool cases over a shared ledger.
    transferClaims: async () => ({ claims: [] }),
    reservationDocumentIdOf: ({ accrualId }) => ({ found: true, documentId: sha(accrualId) }),
    buildReceiptCapture: ({ epochIndex, accrualId, writeAhead }) => ({ v: 1,
      kind: "tegara.e2.receiptCapture.v1", object: "transfer", gen: 1, poolId, epochIndex,
      accrualId, transitionHash: writeAhead.transitionHash,
      transitionBytes: writeAhead.transitionBytes, proofMsg: "cc".repeat(20),
      metadataMsg: "dd".repeat(10), inclusionHeight: "1600", heightRoute: "tenderdash-tx",
      signerIdentity: h32("f0"), signerKeyId: 2, sig: "00".repeat(65) }),
    fetchReservation: async () => ({ found: false }),
    observeReceipt: async () => ({ found: false }),
    accrualPayload: (epochIndex, row) => ({ poolId, epochIndex, accrualId: row.accrualId,
      credits: row.amountCredits }),
    receiptPayloads: () => ({ parts: [{ p: 1 }, { p: 2 }], receipt: { r: 1, proofPartCount: 3 } }),
    documents: {
      fetch: async (object, key) => {
        const f = ledger.get(docKey(object, key));
        return f ? { found: true, fields: f } : { found: false };
      },
      write: async (object, key, payload) => {
        // each document write is its own window: the parts are numbered, so part1 and part2 are
        // distinct points rather than one
        const tag = object === "part" ? `part${key.partIndex}` : object;
        endHere(`${tag}/write/before`);
        if (object === "part" || object === "receipt") endHere("after-capture-before-documents");
        ledger.set(docKey(object, key), payload);
        endHere(`${tag}/write/after`);
        return SUCCESS;
      },
    },
  };
};

// ---- the child role: work EVERY payable accrual, possibly ending abruptly inside one ----
// THE INTERRUPTION TARGETS ONE ACCRUAL, named by E2_DEMO_INTERRUPT_ACCRUAL, so a phase can end
// the process while paying the SECOND member and the demonstration can then ask whether the
// first was re-paid. Without that, an interruption in the first member's payment would be the
// only shape ever exercised.
const runChildPhase = async () => {
  const interruptAt = process.env.E2_DEMO_INTERRUPT || "";
  const target = process.env.E2_DEMO_INTERRUPT_ACCRUAL || "";
  const resolution = await resolvePoolForDemo();
  const run = await startRun({ poolId: POOL, dir: undefined,
    deps: mkDeps(POOL, "", resolution) });
  // THE ACCRUAL STEP RUNS IN THE CHILD TOO, which the first version skipped. Its document writes
  // are a real part of the sequence, and leaving them to the parent's setup made the two
  // accrual/write windows unreachable: the child completed normally and the sweep correctly
  // reported it had observed nothing there. A window that cannot fire is not evidence.
  await runAccrualStep({ poolId: POOL, dir: undefined,
    deps: mkDeps(POOL, interruptAt, resolution), run, epochIndex: EPOCH });
  const rows = mkDeps(POOL, "", resolution).entitlementsForEpoch(EPOCH);
  for (const row of rows) {
    // only the named accrual carries the interruption; the others run clean
    const armed = !target || row.accrualId === target;
    const deps = mkDeps(POOL, armed ? interruptAt : "", resolution);
    const r = await runTransferStep({ poolId: POOL, dir: undefined, deps, run,
      epochIndex: EPOCH, accrualId: row.accrualId });
    process.stdout.write(`CHILD-STATUS ${row.accrualId.slice(0, 8)} ${r.status}\n`);
  }
  process.stdout.write("CHILD-DONE\n");
};

module.exports = { ROOT, LEDGER, POOL, EPOCH, W, I, OWNER_A, OWNER_B, GROSS, FEE, MEMBERS,
  externalEffects, ensureStore, mkDeps, runChildPhase, resolvePoolForDemo,
  encodeTransfer, decodeTransfer, STATE_DIR, identityLockName, poolRunLockName,
  setStart, startRun, runHeaderStep, runAccrualStep, runTransferStep, openValidatedJournal,
  classifyEntitlement: distribute.classifyEntitlement };

if (require.main === module && process.env.E2_DEMO_ROLE === "child") {
  runChildPhase().then(() => process.exit(0)).catch((e) => {
    process.stdout.write(`CHILD-ERROR ${(e && e.message) || e}\n`);
    process.exit(1);
  });
}
