/**
 * e2AcquireTest: the offline battery for the ACQUISITION layer of the forward
 * lifecycle kernel (contract sections 3.2 and 3.2.1). Plain `node`, no network.
 *
 * WHAT IT BINDS, enumerated from the interfaces rather than from a findings
 * list, with the counts asserted against the lists they were enumerated from:
 *   1. the evidence interface's TEN fields (four top-level, six per row) and,
 *      for every adapter-fed read, the four failure shapes (unserved, unverified,
 *      unproved route, wrong scope) PASS THROUGH untouched, never stamped;
 *   2. the row-state table read off the kernel's own branches: which reads each
 *      row state owes, by descriptor identity, and which it must NOT issue;
 *   3. the projections acquisition is allowed to derive (funderIds, parts[],
 *      count, servedCount, documentId, fields) and nothing else;
 *   4. the request limits, derived from the contract's cardinality table as
 *      bound plus one, with a full page passed through rather than widened;
 *   5. the immutable query descriptor whose `where` is built FROM its subject, the
 *      receipt reads keyed by (accrualId) alone against the unique byAccrual index
 *      (a soundness-review finding) and what that widens: a wrong-pool receipt refuses and is never
 *      absent, and the sweep's receipt component reports occupancy of the key;
 *   6. the adapter envelope grammar, fourteen sampled malformed shapes refused by name;
 *   7. the one gap the kernel's interface cannot express (an empty answer over an
 *      unproved route), refused by name rather than represented falsely;
 *   8. the execution verdict, called only for a served receipt and passed through;
 *   9. composition: acquired bundles drive the real kernel to each of its four
 *      states from a synthetic store, including two rows whose answers must not
 *      be filed under each other;
 *  10. bounded reacquisition of stale negatives: the bound at 0, 1 and 2, negatives
 *      re-read and positives reused as seen in the ADAPTER's own log, and the three
 *      negative-to-positive transitions (receipt, accrual, non-payable accrual) each
 *      running the duties the new row state owes.
 *
 * WHAT IT DOES NOT ESTABLISH: that any real adapter produces these envelopes
 * (none exists yet), that the kernel is correct (its own suite), or that the
 * misfiling guard fires under an internal defect (the mutation battery,
 * tools/acquire_mutation_check.sh, swaps two rows and watches it refuse).
 */
"use strict";

const K = require("./e2ForwardKernel.cjs");
const A = require("./e2Acquire.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed += 1; console.log(`  PASS: ${name}`); }
  else { failed += 1; console.log(`  FAIL: ${name}`); }
};
const rejects = async (name, p, re) => {
  try { await p; failed += 1; console.log(`  FAIL: ${name} (no refusal)`); }
  catch (e) { const m = (e && e.message) || String(e); ok(`${name} (${m.slice(0, 70)})`, re.test(m)); }
};

// ---- fixture identities, the kernel test's own so the two suites agree ----
const POOL = "11".repeat(32);
const FUNDER_A = "aa".repeat(32);
const FUNDER_B = "bb".repeat(32);
const PLANNED_A = "a1".repeat(32);
const PLANNED_B = "b1".repeat(32);
const OTHER_ID = "cc".repeat(32);
const RES_A = "d1".repeat(32);
const RCPT_A = "d2".repeat(32);
const HDR_ID = "77".repeat(32);
const AH = "ee".repeat(32);
const TH = "ff".repeat(32);
const EPOCH = 7;
const SCOPE = Object.freeze({ contractId: "c-11", chainId: "devnet-x", contractVersion: 11,
  poolId: POOL, epochIndex: EPOCH });
const OTHER_SCOPE = Object.freeze({ ...SCOPE, poolId: "ee".repeat(32) });
const ROUTE = "documents-proved-query";

const member = (funderId, plannedAccrualId, over = {}) => ({
  funderId, plannedAccrualId, effectiveCredits: "900", shareBps: 10000,
  isSelfShare: false, payable: true, ...over,
});
const mkPlan = (over = {}) => K.buildExpectedRecordPlan({
  scope: SCOPE, encodingRefused: false,
  header: { grossCredits: "1000", feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH },
  members: [member(FUNDER_A, PLANNED_A)],
  ...over,
});

// ---- the synthetic store, served through the injected adapter ----
// A store is a list of documents per type; the adapter answers a descriptor by
// matching every `where` clause against the document's fields, returning up to
// the descriptor's limit, at the store's current height. Heights and per-read
// overrides are how the tests drive each failure shape into ONE read.
const doc = (id, fields) => ({ id, fields });
const headerDoc = (over = {}) => doc(HDR_ID, { poolId: POOL, epochIndex: EPOCH, grossCredits: "1000",
  feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH, ...over });
const accrualDoc = (id, funderId, over = {}) => doc(id, { poolId: POOL, funderId, epochIndex: EPOCH,
  amountCredits: "900", shareBps: 10000, ...over });
const reservationDoc = (id, accrualId) => doc(id, { poolId: POOL, accrualId, transitionHash: TH });
const receiptDoc = (id, accrualId, ppc = 3) => doc(id, { poolId: POOL, accrualId, transitionHash: TH, proofPartCount: ppc });
const partDoc = (id, accrualId, partIndex) => doc(id, { poolId: POOL, accrualId, partIndex });

const makeStore = ({ height = "100", docs = {}, overrides = {} } = {}) => {
  const state = { height, docs: { epochHeader: [], platformAccrual: [], transferReservation: [],
    transferReceipt: [], receiptProofPart: [], ...docs }, overrides, log: [] };
  const matches = (d, where) => where.every(([field, op, value]) => op === "==" && d.fields[field] === value);
  const readPage = async (descriptor) => {
    state.log.push(descriptor);
    // an override answers ONE named read (by query name and, for row reads,
    // subject) with a fixed envelope, which is how a single failure shape is
    // driven into a single answer while every other read stays conforming
    const key = `${descriptor.query}:${descriptor.subjectAccrualId || descriptor.where.map((w) => w[2]).join(",")}`;
    for (const [k, v] of Object.entries(state.overrides)) {
      if (k === key || k === descriptor.query) return typeof v === "function" ? v(descriptor) : v;
    }
    const found = state.docs[descriptor.type].filter((d) => matches(d, descriptor.where));
    return { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: state.height,
      documents: found.slice(0, descriptor.limit) };
  };
  return { state, readPage };
};
const verdictFor = (calls) => ({ member: m, receipt }) => {
  if (calls) calls.push({ member: m, receipt });
  return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: m.effectiveCredits };
};
const acquire = (plan, store, executionVerdict = verdictFor()) =>
  A.acquireEpochEvidence({ plan, readPage: store.readPage, executionVerdict });

// a conforming single-row store: the shape the kernel's A1 completes on
const conformingDocs = () => ({
  epochHeader: [headerDoc()],
  platformAccrual: [accrualDoc(PLANNED_A, FUNDER_A)],
  transferReservation: [reservationDoc(RES_A, PLANNED_A)],
  transferReceipt: [receiptDoc(RCPT_A, PLANNED_A, 3)],
  receiptProofPart: [partDoc("e1".repeat(32), PLANNED_A, 1), partDoc("e2".repeat(32), PLANNED_A, 2)],
});

const queriesIssued = (store) => store.state.log.map((d) => d.query);
const codesOf = (r) => r.reasons.map((x) => x.code);
// the accrual identifier a descriptor's where clause ACTUALLY queries, read
// from the adapter's side rather than from the descriptor's subject member
const whereId = (d) => { const w = d.where.find(([f]) => f === "accrualId"); return w ? w[2] : null; };
const isPlainObj = (v) => !!v && typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype;
const canon = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x))
  ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x);

const main = async () => {
  console.log("e2AcquireTest");

  // ================= 1. the descriptor =================
  {
    const plan = mkPlan();
    const store = makeStore({ docs: conformingDocs() });
    const { reads } = await acquire(plan, store);
    const parts = reads.find((r) => r.descriptor.query === "parts");
    const d = parts.descriptor;
    ok("a descriptor is frozen", Object.isFrozen(d) && Object.isFrozen(d.where));
    ok("a descriptor's where is built FROM its subject (the two cannot disagree)",
      d.subjectAccrualId === PLANNED_A && d.where.some(([f, , v]) => f === "accrualId" && v === PLANNED_A));
    ok("a descriptor names its kind, type, query, limit", d.kind === "tegara.e2.queryDescriptor.v1"
      && d.type === "receiptProofPart" && d.query === "parts" && d.limit === 8);
    // THE REQUEST LIMIT IS THE BOUND PLUS ONE, derived in one place from the
    // contract's cardinality table (3.2.1)
    const sweepStore = makeStore({ docs: { epochHeader: [headerDoc()] } });
    const sweepReads = (await acquire(plan, sweepStore)).reads;
    const limits = Object.fromEntries([...reads, ...sweepReads].map((r) => [r.descriptor.query, r.descriptor.limit]));
    const expected = { header: 2, accrualEnumeration: 9, accrual: 2, reservationPinned: 2,
      reservationEnumerated: 2, receipt: 2, parts: 8, sweepReservation: 2, sweepReceipt: 2, sweepParts: 8 };
    ok(`every one of the ten request limits is its bound plus one (${Object.keys(limits).length} observed)`,
      Object.keys(limits).length === 10 && Object.entries(expected).every(([q, l]) => limits[q] === l));
    ok(`the conforming payable row issues exactly the full chain (${queriesIssued(store).join(",")})`,
      queriesIssued(store).join(",") === "header,accrualEnumeration,accrual,reservationPinned,reservationEnumerated,receipt,parts");
    // THE RECEIPT CLAUSE IS (accrualId) ALONE (a soundness-review finding), for both receipt reads,
    // with the subject, the immutability and the limit of two preserved; every
    // other accrual-keyed read keeps (poolId, accrualId)
    const rc = reads.find((r) => r.descriptor.query === "receipt").descriptor;
    const sc = sweepReads.find((r) => r.descriptor.query === "sweepReceipt").descriptor;
    const deepFrozenDesc = (d) => Object.isFrozen(d) && Object.isFrozen(d.where) && d.where.every((c) => Object.isFrozen(c));
    ok("the receipt descriptor's clause is exactly [[accrualId, ==, subject]] with subject, deep freeze (descriptor, list, clause) and limit 2 preserved",
      JSON.stringify(rc.where) === JSON.stringify([["accrualId", "==", PLANNED_A]]) && rc.subjectAccrualId === PLANNED_A && deepFrozenDesc(rc) && rc.limit === 2 && rc.type === "transferReceipt");
    ok("the sweepReceipt descriptor's clause is exactly [[accrualId, ==, subject]], deep-frozen, limit 2",
      JSON.stringify(sc.where) === JSON.stringify([["accrualId", "==", PLANNED_A]]) && sc.subjectAccrualId === PLANNED_A && deepFrozenDesc(sc) && sc.limit === 2);
    // the FIVE other accrual-keyed reads, by identity, each with its COMPLETE
    // clause equal to the plan's pool and that descriptor's own subject
    const poolKeyed = [...reads, ...sweepReads].filter((r) => r.descriptor.subjectAccrualId !== null && !["receipt", "sweepReceipt"].includes(r.descriptor.query));
    ok(`every other accrual-keyed read keeps exactly [[poolId, ==, plan pool], [accrualId, ==, subject]] (${poolKeyed.map((r) => r.descriptor.query).join(",")})`,
      poolKeyed.map((r) => r.descriptor.query).sort().join() === "parts,reservationEnumerated,reservationPinned,sweepParts,sweepReservation"
      && poolKeyed.every((r) => JSON.stringify(r.descriptor.where) === JSON.stringify([["poolId", "==", POOL], ["accrualId", "==", r.descriptor.subjectAccrualId]])));
    // the fake adapter's log shows the clause it RECEIVED is the descriptor's own
    ok("the adapter received exactly the receipt descriptor's clause", store.state.log.find((d) => d.query === "receipt").where === rc.where);
  }

  // ================= 1b. what the narrowed receipt key widens (a soundness-review finding) =================
  {
    const plan = mkPlan();
    // a receipt with the RIGHT accrual and the WRONG pool: served, then refused
    // by the kernel's key check on its fields, never read as an absence
    const docs = conformingDocs();
    docs.transferReceipt = [doc(RCPT_A, { poolId: "ee".repeat(32), accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 3 })];
    const store = makeStore({ docs });
    const { evidence } = await acquire(plan, store);
    const rec = evidence.dependents[FUNDER_A].receipt;
    ok("a wrong-pool receipt under the right accrual is SERVED by the narrowed read (not absent)", rec.status === "served" && rec.fields.poolId === "ee".repeat(32));
    const r = K.evaluateEpochForwardState({ plan, evidence });
    ok("composition: the kernel refuses that receipt as a different key, and never as absent",
      r.state === "refused" && codesOf(r).includes("REFUSED_NONCONFORMING_ANSWER") && !codesOf(r).includes("INCOMPLETE_RECEIPT_ABSENT")
      && r.reasons.some((x) => x.code === "REFUSED_NONCONFORMING_ANSWER" && x.recordKey.startsWith("receipt:")));
    // a proved absence: no receipt under the accrual key in ANY pool
    const docs2 = conformingDocs(); docs2.transferReceipt = [];
    const { evidence: ev2 } = await acquire(plan, makeStore({ docs: docs2 }));
    ok("no receipt under the accrual key anywhere is a proved absence", ev2.dependents[FUNDER_A].receipt.status === "proved-absence");
    // the inspection sweep: a receipt under the planned identifier in ANOTHER
    // pool OCCUPIES the globally unique key and is counted, not made to vanish
    const docs3 = { epochHeader: [headerDoc()], transferReceipt: [doc(RCPT_A, { poolId: "ee".repeat(32), accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 3 })] };
    const { evidence: ev3 } = await acquire(plan, makeStore({ docs: docs3 }));
    const sweep = ev3.dependents[FUNDER_A].machinerySweep;
    ok("the sweep's receipt component counts a receipt under the planned key in another pool (occupancy of the unique key)",
      sweep.receipt.count === 1 && sweep.receipt.subjectAccrualId === PLANNED_A && sweep.reservation.count === 0);
    const r3 = K.evaluateEpochForwardState({ plan, evidence: ev3 });
    const occ = r3.reasons.find((x) => x.code === "REFUSED_DEPENDENTS_WITHOUT_ACCRUAL" && x.recordKey.endsWith(":receipt"));
    ok("composition: the kernel refuses that occupied key by its own code, on the receipt component, counting one record, and does not call the receipt absent",
      r3.state === "refused" && occ !== undefined && /^1 receipt record/.test(occ.diagnostic) && !codesOf(r3).includes("INCOMPLETE_RECEIPT_ABSENT"));
    // through the settling entry, a wrong-pool receipt is a terminal refusal:
    // no refresh round is spent (the refusal is not a stale negative). This
    // observes the round count only; it does not observe a receipt crossing a
    // refresh boundary.
    const evaluate = (pl, ev) => K.evaluateEpochForwardState({ plan: pl, evidence: ev });
    const settled = await A.acquireUntilSettled({ plan, readPage: store.readPage, executionVerdict: verdictFor(), evaluate, maxRounds: 2 });
    ok("a wrong-pool receipt refuses through the settling entry with zero refresh rounds",
      settled.rounds === 0 && settled.result.state === "refused" && codesOf(settled.result).includes("REFUSED_NONCONFORMING_ANSWER"));
  }

  // ================= 2. projections =================
  {
    const plan = mkPlan();
    const store = makeStore({ docs: conformingDocs() });
    const { evidence } = await acquire(plan, store);
    const h = evidence.header;
    ok("a unique read with one document projects served with documentId, fields, servedCount",
      h.status === "served" && h.documentId === HDR_ID && h.fields.grossCredits === "1000" && h.servedCount === 1
      && h.proved === true && h.route === ROUTE && h.height === "100" && h.scope.poolId === POOL);
    ok("the accrual enumeration projects funderIds from the documents it received",
      evidence.accrualEnumeration.status === "served" && evidence.accrualEnumeration.funderIds.join() === FUNDER_A);
    const deps = evidence.dependents[FUNDER_A];
    ok("the part set projects {partIndex, documentId} per document and carries the descriptor's subject",
      deps.partSet.subjectAccrualId === PLANNED_A && deps.partSet.parts.length === 2
      && deps.partSet.parts[0].partIndex === 1 && deps.partSet.parts[0].documentId === "e1".repeat(32));
    ok("a payable served row carries NO machinery sweep (the narrowed interface)", deps.machinerySweep === undefined);
    ok("the execution verdict is passed through beside the served receipt",
      deps.execution.label === "CAPTURE-VERIFIED" && deps.execution.verifiedAmountCredits === "900");
    const r = K.evaluateEpochForwardState({ plan, evidence });
    ok(`composition: the conforming store drives the kernel to complete (${r.state})`, r.state === "complete");
  }
  {
    // zero documents on a proved route project a proved absence; two on a
    // unique key project servedCount 2 and the kernel refuses ambiguity
    const plan = mkPlan();
    const docs = conformingDocs(); docs.transferReservation = [];
    const store = makeStore({ docs });
    const { evidence } = await acquire(plan, store);
    const rp = evidence.dependents[FUNDER_A].reservationPinned;
    ok("a unique read with zero documents projects proved-absence with its provenance",
      rp.status === "proved-absence" && rp.proved === true && rp.height === "100" && rp.route === ROUTE && rp.documentId === undefined);
    const r = K.evaluateEpochForwardState({ plan, evidence });
    ok("composition: a missing reservation beside a served receipt drives the kernel to refused",
      r.state === "refused" && codesOf(r).includes("REFUSED_RESERVATION_PROVED_ABSENT"));
    const docs2 = conformingDocs(); docs2.transferReceipt.push(receiptDoc("d3".repeat(32), PLANNED_A, 3));
    const store2 = makeStore({ docs: docs2 });
    const { evidence: ev2 } = await acquire(plan, store2);
    ok("a unique read serving two documents projects servedCount 2 (a full page is passed through, not widened)",
      ev2.dependents[FUNDER_A].receipt.servedCount === 2 && ev2.dependents[FUNDER_A].receipt.documentId === RCPT_A);
    const r2 = K.evaluateEpochForwardState({ plan, evidence: ev2 });
    ok("composition: the kernel refuses the ambiguous receipt with its own code",
      codesOf(r2).includes("REFUSED_RECEIPT_AMBIGUOUS"));
  }

  // ================= 3. the row-state table, read off the kernel's branches =================
  {
    // PAYABLE, served, identifier MISMATCH: nothing after the accrual
    const plan = mkPlan();
    const docs = conformingDocs(); docs.platformAccrual = [accrualDoc(OTHER_ID, FUNDER_A)];
    const store = makeStore({ docs });
    const { evidence } = await acquire(plan, store);
    ok("payable served MISMATCH: acquisition stops at stage 3, no dependent read issued",
      queriesIssued(store).join(",") === "header,accrualEnumeration,accrual" && evidence.dependents[FUNDER_A] === undefined);
    const r = K.evaluateEpochForwardState({ plan, evidence });
    ok("composition: the kernel refuses the identifier mismatch and requires no dependents",
      r.state === "refused" && codesOf(r).includes("REFUSED_ACCRUAL_DOCUMENT_ID_MISMATCH"));
  }
  {
    // PAYABLE, accrual PROVED ABSENT: the sweep under the PLANNED identifier only
    const plan = mkPlan();
    const store = makeStore({ docs: { epochHeader: [headerDoc()] } });
    const { evidence } = await acquire(plan, store);
    const q = queriesIssued(store);
    ok("payable proved-absent: header, enumeration, accrual, then the three sweep reads by the planned id",
      q.join(",") === "header,accrualEnumeration,accrual,sweepReservation,sweepReceipt,sweepParts"
      && store.state.log.slice(3).length === 3
      && store.state.log.slice(3).every((d) => d.subjectAccrualId === PLANNED_A && whereId(d) === PLANNED_A));
    const sw = evidence.dependents[FUNDER_A].machinerySweep;
    ok("the sweep is THREE answers, each with its own provenance, subject and count",
      ["reservation", "receipt", "parts"].every((c) => sw[c].status === "served" && sw[c].count === 0
        && sw[c].subjectAccrualId === PLANNED_A && sw[c].height === "100" && sw[c].proved === true));
    const r = K.evaluateEpochForwardState({ plan, evidence });
    ok("composition: header served and accrual absent with an empty sweep is incomplete at the accrual",
      r.state === "incomplete" && codesOf(r).includes("INCOMPLETE_ACCRUAL_ABSENT"));
  }
  {
    // PAYABLE, accrual UNRESOLVED (unserved): nothing
    const plan = mkPlan();
    const store = makeStore({ docs: conformingDocs(), overrides: { accrual: { status: "unserved" } } });
    const { evidence } = await acquire(plan, store);
    ok("payable unresolved: no dependent read, the unserved answer passed through",
      queriesIssued(store).join(",") === "header,accrualEnumeration,accrual"
      && evidence.accruals[FUNDER_A].status === "unserved" && evidence.dependents[FUNDER_A] === undefined);
    const r = K.evaluateEpochForwardState({ plan, evidence });
    ok("composition: the kernel reports unproved with the identifier unresolved",
      r.state === "unproved" && codesOf(r).includes("UNPROVED_ACCRUAL_IDENTIFIER_UNRESOLVED"));
  }
  {
    // PAYABLE, served but OUT OF SCOPE: the kernel treats the row as unresolved,
    // so acquisition must key nothing (a sweep by the served id here would add a
    // subject refusal and turn a scope refusal into something else)
    const plan = mkPlan();
    const docs = conformingDocs();
    const store = makeStore({ docs, overrides: { accrual: (d) => ({ status: "served", proved: true, route: ROUTE,
      scope: OTHER_SCOPE, height: "100", documents: docs.platformAccrual }) } });
    const { evidence } = await acquire(plan, store);
    ok("payable served out of scope: no dependent read", queriesIssued(store).join(",") === "header,accrualEnumeration,accrual");
    const r = K.evaluateEpochForwardState({ plan, evidence });
    ok("composition: exactly the scope refusal on the accrual, nothing filed against dependents",
      r.state === "refused" && codesOf(r).join() === "REFUSED_SCOPE_MISMATCH");
    // the same for a served accrual whose KEY fields are another funder's: the
    // kernel calls it nonconforming and unresolved, so nothing is keyed
    const docs2 = conformingDocs();
    const store2 = makeStore({ docs: docs2, overrides: { accrual: () => ({ status: "served", proved: true, route: ROUTE,
      scope: SCOPE, height: "100", documents: [accrualDoc(PLANNED_A, FUNDER_B)] }) } });
    const { evidence: ev2 } = await acquire(plan, store2);
    ok("payable served under another funder's key: no dependent read", queriesIssued(store2).join(",") === "header,accrualEnumeration,accrual");
    const r2 = K.evaluateEpochForwardState({ plan, evidence: ev2 });
    ok("composition: the kernel calls that answer nonconforming, the row has no dependents entry, and nothing else is raised",
      r2.state === "refused" && codesOf(r2).join() === "REFUSED_NONCONFORMING_ANSWER" && ev2.dependents[FUNDER_A] === undefined);
  }
  {
    // NON-PAYABLE rows: sweep only, keyed by the SERVED id when served, PLANNED otherwise
    const nonPayable = (over) => mkPlan({ members: [member(FUNDER_A, PLANNED_A, { isSelfShare: true, payable: false, ...over })] });
    const planNP = nonPayable();
    const store = makeStore({ docs: { epochHeader: [headerDoc()], platformAccrual: [accrualDoc(OTHER_ID, FUNDER_A, { amountCredits: "900" })] } });
    const { evidence } = await acquire(planNP, store);
    const q = queriesIssued(store);
    ok("non-payable, accrual served under ANOTHER id: sweep keyed by the SERVED id, in the where clause the adapter saw and in the subject",
      q.join(",") === "header,accrualEnumeration,accrual,sweepReservation,sweepReceipt,sweepParts"
      && store.state.log.slice(3).length === 3
      && store.state.log.slice(3).every((d) => d.subjectAccrualId === OTHER_ID && whereId(d) === OTHER_ID)
      && evidence.dependents[FUNDER_A].machinerySweep.parts.subjectAccrualId === OTHER_ID);
    // the kernel refuses the identifier mismatch for EVERY row in its accrual
    // loop, non-payable included; what the classification changes is only which
    // dependents are read (the sweep, under the served id) and none of those
    // raises a further reason
    const rOther = K.evaluateEpochForwardState({ plan: planNP, evidence });
    ok(`composition: a self-share row served under another id is refused for the mismatch and for nothing else (${codesOf(rOther).join()})`,
      rOther.state === "refused" && codesOf(rOther).join() === "REFUSED_ACCRUAL_DOCUMENT_ID_MISMATCH");
    const store2 = makeStore({ docs: { epochHeader: [headerDoc()] } });
    await acquire(planNP, store2);
    ok("non-payable, accrual absent: sweep keyed by the PLANNED id",
      store2.state.log.slice(3).length === 3
      && store2.state.log.slice(3).every((d) => d.subjectAccrualId === PLANNED_A && whereId(d) === PLANNED_A));
    const store3 = makeStore({ docs: { epochHeader: [headerDoc()] }, overrides: { accrual: { status: "unverified" } } });
    await acquire(planNP, store3);
    ok("non-payable, accrual unresolved: sweep still owed, keyed by the PLANNED id",
      queriesIssued(store3).filter((x) => x.startsWith("sweep")).length === 3
      && store3.state.log.slice(3).every((d) => d.subjectAccrualId === PLANNED_A && whereId(d) === PLANNED_A));
    const r = K.evaluateEpochForwardState({ plan: planNP, evidence: (await acquire(planNP, makeStore({ docs: { epochHeader: [headerDoc()], platformAccrual: [accrualDoc(PLANNED_A, FUNDER_A)] } }))).evidence });
    ok(`composition: a served self-share row with an empty sweep completes (${r.state})`, r.state === "complete");
  }
  {
    // ENCODING-REFUSED epoch: header, enumeration, every accrual, and the sweep
    // by the PLANNED id for every member regardless of what was served
    const plan = K.buildExpectedRecordPlan({ scope: SCOPE, encodingRefused: true, header: null,
      members: [member(FUNDER_A, PLANNED_A, { payable: false, isSelfShare: false, effectiveCredits: "0" })] });
    const store = makeStore({ docs: { platformAccrual: [accrualDoc(OTHER_ID, FUNDER_A)] } });
    const { evidence } = await acquire(plan, store);
    ok("encoding-refused: the sweep is keyed by the PLANNED id even though an accrual was served",
      queriesIssued(store).join(",") === "header,accrualEnumeration,accrual,sweepReservation,sweepReceipt,sweepParts"
      && store.state.log.slice(3).length === 3
      && store.state.log.slice(3).every((d) => d.subjectAccrualId === PLANNED_A && whereId(d) === PLANNED_A));
    const r = K.evaluateEpochForwardState({ plan, evidence });
    ok("composition: the served accrual under an encoding-refused epoch is refused by the kernel",
      r.state === "refused" && codesOf(r).includes("REFUSED_RECORDS_UNDER_ENCODING_REFUSED_EPOCH"));
    const store2 = makeStore();
    const r2 = K.evaluateEpochForwardState({ plan, evidence: (await acquire(plan, store2)).evidence });
    ok("composition: proved emptiness under an encoding-refused epoch completes", r2.state === "complete");
  }

  // ================= 4. the ten fields and the four failure shapes, pass-through =================
  {
    // THE EVIDENCE INTERFACE IS TEN FIELDS; eight are ADAPTER-FED reads (the
    // machinery sweep being three reads), one is derived per row (execution),
    // one is the grouping (dependents). Enumerated here, count asserted.
    const TOP = ["header", "accruals", "accrualEnumeration", "dependents"];
    const PER_ROW = ["reservationPinned", "reservationEnumerated", "receipt", "execution", "partSet", "machinerySweep"];
    // TOP and PER_ROW are this suite's inventory of the evidence interface (4 top-level, 6 per
    // row). They are DATA, not an assertion: a count of local constants cannot see a field the
    // kernel adds, so no PASS line is claimed for it.
    void TOP; void PER_ROW;
    const FAILURES = [
      ["unserved", () => ({ status: "unserved" })],
      ["unverified", () => ({ status: "unverified" })],
      ["unproved-route", (docsFor) => ({ status: "served", proved: false, route: "bare-read", scope: SCOPE, height: "100", documents: docsFor })],
      ["wrong-scope", (docsFor) => ({ status: "served", proved: true, route: ROUTE, scope: OTHER_SCOPE, height: "100", documents: docsFor })],
    ];
    // THE EXPECTED ANSWER IS BUILT HERE, IN THE TEST, from the envelope the
    // adapter was made to return, and the WHOLE answer is compared, so a
    // stamped or dropped member anywhere in it is a failure rather than only the
    // sampled fields being right
    const expectedFor = (kind, env, subject) => {
      if (env.status !== "served") return { status: env.status };
      const prov = { status: "served", proved: env.proved, route: env.route, scope: env.scope, height: env.height };
      if (kind === "unique") return { ...prov, documentId: env.documents[0].id, fields: env.documents[0].fields, servedCount: env.documents.length };
      if (kind === "enumeration") return { ...prov, funderIds: env.documents.map((d) => d.fields.funderId) };
      if (kind === "parts") return { ...prov, subjectAccrualId: subject, parts: env.documents.map((d) => ({ partIndex: d.fields.partIndex, documentId: d.id })) };
      return { ...prov, subjectAccrualId: subject, count: env.documents.length };
    };
    // every adapter-fed read, with its kind, the path in the bundle it lands
    // in, and the documents the conforming store would have served it (so the
    // served failure shapes carry a real document and are not the empty-unproved gap)
    const READS = [
      ["header", "unique", (ev) => ev.header, () => [headerDoc()]],
      ["accrualEnumeration", "enumeration", (ev) => ev.accrualEnumeration, () => [accrualDoc(PLANNED_A, FUNDER_A)]],
      ["accrual", "unique", (ev) => ev.accruals[FUNDER_A], () => [accrualDoc(PLANNED_A, FUNDER_A)]],
      ["reservationPinned", "unique", (ev) => ev.dependents[FUNDER_A].reservationPinned, () => [reservationDoc(RES_A, PLANNED_A)]],
      ["reservationEnumerated", "unique", (ev) => ev.dependents[FUNDER_A].reservationEnumerated, () => [reservationDoc(RES_A, PLANNED_A)]],
      ["receipt", "unique", (ev) => ev.dependents[FUNDER_A].receipt, () => [receiptDoc(RCPT_A, PLANNED_A)]],
      ["partSet", "parts", (ev) => ev.dependents[FUNDER_A].partSet, () => [partDoc("e1".repeat(32), PLANNED_A, 1)]],
      ["sweep:reservation", "sweep", (ev) => ev.dependents[FUNDER_A].machinerySweep.reservation, () => []],
      ["sweep:receipt", "sweep", (ev) => ev.dependents[FUNDER_A].machinerySweep.receipt, () => []],
      ["sweep:parts", "sweep", (ev) => ev.dependents[FUNDER_A].machinerySweep.parts, () => []],
    ];
    const QUERY_FOR = { partSet: "parts", "sweep:reservation": "sweepReservation", "sweep:receipt": "sweepReceipt", "sweep:parts": "sweepParts" };
    let cases = 0;
    for (const [field, kind, pick, docsFor] of READS) {
      const sweepField = field.startsWith("sweep:");
      // the sweep is owed on a payable row whose accrual is proved absent
      const plan = mkPlan();
      const docs = sweepField ? { epochHeader: [headerDoc()] } : conformingDocs();
      for (const [label, envelope] of FAILURES) {
        const env = envelope(docsFor());
        // the expectation is fixed BEFORE the call, from a copy, so a projection
        // that altered the envelope it was handed cannot also alter what is expected
        const want = canon(expectedFor(kind, JSON.parse(JSON.stringify(env)), PLANNED_A));
        const store = makeStore({ docs, overrides: { [QUERY_FOR[field] || field]: env } });
        const { evidence } = await acquire(plan, store);
        cases += 1;
        ok(`${field} ${label} is projected as exactly the expected projection of the adapter's envelope`,
          canon(pick(evidence)) === want);
      }
    }
    ok(`bookkeeping: every read in this suite's inventory was driven through every failure shape it lists (${cases} of ${READS.length * FAILURES.length})`,
      cases === READS.length * FAILURES.length && READS.length === 10 && FAILURES.length === 4);
    // the SUBJECT is the descriptor's, never the plan's after the fact and never
    // the documents': a sweep observing nothing still carries it
    const plan = mkPlan();
    const store = makeStore({ docs: { epochHeader: [headerDoc()] } });
    const { evidence } = await acquire(plan, store);
    ok("a sweep observing zero records still carries its subject from the descriptor",
      evidence.dependents[FUNDER_A].machinerySweep.reservation.subjectAccrualId === PLANNED_A);
  }

  // ================= 5. the adapter envelope grammar =================
  {
    const plan = mkPlan();
    const bad = (override, re, name) => rejects(name,
      acquire(plan, makeStore({ docs: conformingDocs(), overrides: { header: override } })), re);
    await bad(null, /declare status/, "a null envelope refuses");
    await bad({ status: "verified", documents: [], height: "1" }, /declare status/, "an undeclared status refuses");
    await bad({ status: "served", proved: true, route: ROUTE, scope: SCOPE, documents: [] }, /height/, "a served envelope without a height refuses");
    await bad({ status: "served", proved: true, route: ROUTE, scope: SCOPE, height: 100, documents: [] }, /height/, "a numeric height refuses");
    await bad({ status: "served", proved: "yes", route: ROUTE, scope: SCOPE, height: "1", documents: [headerDoc()] }, /proved/, "a non-boolean proved refuses");
    await bad({ status: "served", proved: true, route: "", scope: SCOPE, height: "1", documents: [headerDoc()] }, /route/, "an empty route refuses");
    await bad({ status: "served", proved: true, route: ROUTE, scope: "x", height: "1", documents: [headerDoc()] }, /scope/, "a non-object scope refuses");
    await bad({ status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "1", documents: [headerDoc(), headerDoc(), headerDoc()] }, /longer than its limit/, "a page longer than its limit refuses");
    await bad({ status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "1", documents: [{ id: "zz", fields: {} }] }, /64-hex/, "a document without a 64-hex id refuses");
    await bad({ status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "1", documents: [doc(HDR_ID, {}), doc(HDR_ID, {})] }, /twice/, "a document served twice in one page refuses");
    await bad({ status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "1", documents: [{ id: HDR_ID }] }, /fields/, "a document without plain fields refuses");
    await bad({ status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "1", documents: [headerDoc()], extra: 1 }, /outside its declared shape/, "an envelope member outside the declared shape refuses");
    await bad({ status: "unserved", documents: [] }, /outside its declared shape/, "an unserved envelope carrying documents refuses");
    await bad((() => { const o = { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "1" }; Object.defineProperty(o, "documents", { get: () => [], enumerable: true }); return o; })(),
      /plain data/, "an accessor-backed member refuses (the envelope is captured as plain data)");
    await rejects("an adapter that throws is a fault reported as such, not evidence",
      acquire(plan, makeStore({ docs: conformingDocs(), overrides: { header: () => { throw new Error("transport down"); } } })),
      /adapter.*failed.*transport down/);
    // THE ONE GAP THE KERNEL'S INTERFACE CANNOT EXPRESS: zero documents over an
    // unproved route. proved-absence requires proved true (the kernel refuses it
    // otherwise), and served requires a document, so nothing true can be built.
    await rejects("zero documents over an unproved route is refused by name rather than represented falsely",
      acquire(plan, makeStore({ docs: conformingDocs(), overrides: { receipt: { status: "served", proved: false, route: "bare", scope: SCOPE, height: "1", documents: [] } } })),
      /empty answer over an unproved route/);
    // enumerations CAN carry an unproved empty answer, since the kernel reads
    // their emptiness as a served empty list, so the same envelope on the part
    // enumeration passes through
    const store = makeStore({ docs: conformingDocs(), overrides: { parts: { status: "served", proved: false, route: "bare", scope: SCOPE, height: "1", documents: [] } } });
    const { evidence } = await acquire(plan, store);
    ok("an unproved empty ENUMERATION passes through (the kernel has a shape for it)",
      evidence.dependents[FUNDER_A].partSet.status === "served" && evidence.dependents[FUNDER_A].partSet.proved === false
      && evidence.dependents[FUNDER_A].partSet.parts.length === 0);
    const r = K.evaluateEpochForwardState({ plan, evidence });
    ok("composition: the kernel reports the unproved part route", codesOf(r).includes("UNPROVED_ROUTE_NOT_PROVED"));
  }

  // ================= 6. the execution verdict =================
  {
    const plan = mkPlan();
    const calls = [];
    const store = makeStore({ docs: conformingDocs() });
    await acquire(plan, store, verdictFor(calls));
    ok("the verdict is requested once, for the served receipt, with the member and the served document",
      calls.length === 1 && calls[0].member.funderId === FUNDER_A && calls[0].receipt.documentId === RCPT_A
      && calls[0].receipt.fields.proofPartCount === 3);
    const docs = conformingDocs(); docs.transferReceipt = [];
    const calls2 = [];
    const { evidence } = await acquire(plan, makeStore({ docs }), verdictFor(calls2));
    ok("no receipt served: the verdict is not requested and execution is null",
      calls2.length === 0 && evidence.dependents[FUNDER_A].execution === null);
    const { evidence: ev3 } = await acquire(plan, makeStore({ docs: conformingDocs() }),
      () => ({ label: "CAPTURE-INVALID", reason: "signature" }));
    ok("a non-verified verdict passes through as returned (never upgraded)",
      ev3.dependents[FUNDER_A].execution.label === "CAPTURE-INVALID");
    const r = K.evaluateEpochForwardState({ plan, evidence: ev3 });
    ok("composition: the kernel refuses on that verdict", codesOf(r).includes("REFUSED_TRANSFER_UNVERIFIED"));
    // the callback receives ITS OWN COPY of the served document: it may write
    // to it freely (so a copy was handed over, not a frozen original) and the
    // captured evidence and the reads log do not change
    let sawMutableCopy = false;
    const { evidence: ev4, reads: reads4 } = await acquire(plan, makeStore({ docs: conformingDocs() }), ({ member: m, receipt }) => {
      try { receipt.fields.proofPartCount = 1; sawMutableCopy = receipt.fields.proofPartCount === 1; } catch { sawMutableCopy = false; }
      return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: m.effectiveCredits };
    });
    ok("the verdict callback receives its own copy: its write takes effect on the copy and the evidence still carries what the adapter served",
      sawMutableCopy && ev4.dependents[FUNDER_A].receipt.fields.proofPartCount === 3
      && reads4.find((r) => r.slot === "receipt").answer.fields.proofPartCount === 3
      && Object.isFrozen(ev4.dependents[FUNDER_A].receipt.fields));
    await rejects("a verdict that is not plain data refuses",
      acquire(plan, makeStore({ docs: conformingDocs() }), () => "verified"), /execution verdict/);
    await rejects("a verdict callback that throws is a fault",
      acquire(plan, makeStore({ docs: conformingDocs() }), () => { throw new Error("verifier down"); }), /verdict.*verifier down/);
  }

  // ================= 7. inputs =================
  {
    // WIDTH: this refuses a MUTABLE plan-shaped literal. It does not establish
    // the plan's origin; the kernel's brand is private, and a frozen literal of
    // the right shape passes. The module header says so.
    await rejects("a mutable plan-shaped literal refuses (origin is assumed, not checked)",
      A.acquireEpochEvidence({ plan: { kind: "tegara.e2.forwardPlan.v1", scope: SCOPE, members: [] }, readPage: async () => ({ status: "unserved" }), executionVerdict: verdictFor() }),
      /mutable plan-shaped literal/);
    await rejects("a missing readPage refuses", A.acquireEpochEvidence({ plan: mkPlan(), executionVerdict: verdictFor() }), /readPage/);
    await rejects("a missing executionVerdict refuses", A.acquireEpochEvidence({ plan: mkPlan(), readPage: async () => ({ status: "unserved" }) }), /executionVerdict/);
  }

  // ================= 8. two rows: every dependent is filed under ITS row =================
  {
    const plan = mkPlan({
      header: { grossCredits: "1000", feeCredits: "100", memberCount: 2, calcVersion: 1, allocationHash: AH },
      members: [member(FUNDER_A, PLANNED_A, { effectiveCredits: "500", shareBps: 5000 }),
        member(FUNDER_B, PLANNED_B, { effectiveCredits: "400", shareBps: 5000 })],
    });
    const RES_B = "d4".repeat(32), RCPT_B = "d5".repeat(32);
    const docs = {
      epochHeader: [headerDoc({ memberCount: 2 })],
      platformAccrual: [accrualDoc(PLANNED_A, FUNDER_A, { amountCredits: "500", shareBps: 5000 }),
        accrualDoc(PLANNED_B, FUNDER_B, { amountCredits: "400", shareBps: 5000 })],
      transferReservation: [reservationDoc(RES_A, PLANNED_A), reservationDoc(RES_B, PLANNED_B)],
      transferReceipt: [receiptDoc(RCPT_A, PLANNED_A, 1), receiptDoc(RCPT_B, PLANNED_B, 1)],
      receiptProofPart: [],
    };
    const store = makeStore({ docs });
    const { evidence, reads } = await acquire(plan, store, ({ member: m }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: m.effectiveCredits }));
    ok("each row's dependents carry that row's served identifier as their subject",
      evidence.dependents[FUNDER_A].partSet.subjectAccrualId === PLANNED_A
      && evidence.dependents[FUNDER_B].partSet.subjectAccrualId === PLANNED_B
      && evidence.dependents[FUNDER_A].receipt.documentId === RCPT_A
      && evidence.dependents[FUNDER_B].receipt.documentId === RCPT_B);
    const dependentReads = reads.filter((r) => r.row !== null && r.descriptor.subjectAccrualId !== null);
    ok("every one of the eight dependent reads' descriptor subject and where clause equal the row it was filed under",
      dependentReads.length === 8
      && dependentReads.every((r) => r.descriptor.subjectAccrualId === (r.row === FUNDER_A ? PLANNED_A : PLANNED_B)
        && whereId(r.descriptor) === r.descriptor.subjectAccrualId));
    const r = K.evaluateEpochForwardState({ plan, evidence });
    ok(`composition: two conforming rows complete (${r.state})`, r.state === "complete");
    ok("the reads log reports what was done: 2 epoch reads plus 5 per payable row (accrual and four dependents)",
      reads.length === 2 + 2 * 5 && reads.filter((r) => r.row === FUNDER_B).length === 5);
  }

  // ================= 9. bounded reacquisition of stale negatives =================
  {
    // the accrual absence is read at 100 while the header is served at 120: the
    // kernel cannot conclude incompleteness from a negative older than a
    // positive (contract 6.1). In this fixture a re-read at a later height
    // resolves it; the served positive is not re-read.
    const plan = mkPlan();
    const evaluate = (p, ev) => K.evaluateEpochForwardState({ plan: p, evidence: ev });
    const staleAccrual = (heights) => {
      let n = 0;
      return () => ({ status: "served", proved: true, route: ROUTE, scope: SCOPE,
        height: heights[Math.min(n++, heights.length - 1)], documents: [] });
    };
    const stale = makeStore({ height: "120", docs: { epochHeader: [headerDoc()] }, overrides: { accrual: staleAccrual(["100"]) } });
    const r1 = evaluate(plan, (await acquire(plan, stale)).evidence);
    ok("before reacquisition the kernel reports the stale negative as temporally unresolved",
      r1.state === "unproved" && codesOf(r1).includes("UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED"));
    // the first accrual read is served at 100, every later one at 130
    const store = makeStore({ height: "120", docs: { epochHeader: [headerDoc()] }, overrides: { accrual: staleAccrual(["100", "130"]) } });
    const settled = await A.acquireUntilSettled({ plan, readPage: store.readPage, executionVerdict: verdictFor(), evaluate, maxRounds: 2 });
    ok(`after one bounded reacquisition round the negative is fresher than the positive and the epoch is incomplete at the accrual (${settled.result.state}, rounds ${settled.rounds})`,
      settled.result.state === "incomplete" && settled.rounds === 1 && codesOf(settled.result).includes("INCOMPLETE_ACCRUAL_ABSENT"));
    // what the ADAPTER saw, not what the module's log says: the served header
    // was read once, every negative twice
    const adapterCounts = (st) => Object.fromEntries(["header", "accrualEnumeration", "accrual", "sweepReservation", "sweepReceipt", "sweepParts"]
      .map((q) => [q, st.state.log.filter((d) => d.query === q).length]));
    ok("the adapter's own log: only NEGATIVE answers were re-read (the accrual absence, the empty enumeration, the three zero-count sweep reads); the served header was not",
      canon(adapterCounts(store)) === canon({ header: 1, accrualEnumeration: 2, accrual: 2, sweepReservation: 2, sweepReceipt: 2, sweepParts: 2 }));
    ok("the module's log agrees and marks the reused positive: 6 reads in each run, the header reused in the second",
      settled.reads.length === 12 && settled.reads.filter((r) => r.reused).length === 1
      && settled.reads.filter((r) => r.reused)[0].slot === "header");
    ok("the re-read answer is what the bundle carries",
      settled.evidence.accruals[FUNDER_A].height === "130");
    // THE BOUND HOLDS: a store that never advances stays unresolved and the loop stops
    const stuck = makeStore({ height: "120", docs: { epochHeader: [headerDoc()] }, overrides: { accrual: staleAccrual(["100"]) } });
    const s2 = await A.acquireUntilSettled({ plan, readPage: stuck.readPage, executionVerdict: verdictFor(), evaluate, maxRounds: 2 });
    ok("the bound holds at maxRounds=2, then the unresolved result is returned rather than a fourth read issued",
      s2.rounds === 2 && s2.result.state === "unproved" && stuck.state.log.filter((d) => d.query === "accrual").length === 3);
    const stuck0 = makeStore({ height: "120", docs: { epochHeader: [headerDoc()] }, overrides: { accrual: staleAccrual(["100"]) } });
    const zero = await A.acquireUntilSettled({ plan, readPage: stuck0.readPage, executionVerdict: verdictFor(), evaluate, maxRounds: 0 });
    ok("maxRounds 0 acquires once and never reacquires", zero.rounds === 0 && zero.reads.length === 6 && stuck0.state.log.length === 6);
    const stuck1 = makeStore({ height: "120", docs: { epochHeader: [headerDoc()] }, overrides: { accrual: staleAccrual(["100"]) } });
    const one = await A.acquireUntilSettled({ plan, readPage: stuck1.readPage, executionVerdict: verdictFor(), evaluate, maxRounds: 1 });
    ok("maxRounds 1 reacquires exactly once", one.rounds === 1 && stuck1.state.log.filter((d) => d.query === "accrual").length === 2);

    // A NEGATIVE THAT BECOMES POSITIVE changes the row's state, and reacquisition
    // must run the duties the NEW state owes, because it re-runs acquisition
    // rather than patching answers into the old bundle.
    {
      // the receipt: absent at 100 beside a reservation served at 120, then
      // served at 130. The verdict must be requested for the newly served
      // receipt, and the epoch completes.
      const docs = conformingDocs();
      let n = 0;
      const calls = [];
      const store2 = makeStore({ height: "120", docs, overrides: { receipt: () => (n++ === 0
        ? { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "100", documents: [] }
        : { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "130", documents: docs.transferReceipt }) } });
      const s = await A.acquireUntilSettled({ plan, readPage: store2.readPage, executionVerdict: verdictFor(calls), evaluate, maxRounds: 2 });
      ok(`receipt absent then served: the verdict is requested once, for the newly served receipt, and the epoch completes (${s.result.state})`,
        s.result.state === "complete" && s.rounds === 1 && calls.length === 1 && calls[0].receipt.documentId === RCPT_A
        && s.evidence.dependents[FUNDER_A].execution.label === "CAPTURE-VERIFIED");
    }
    {
      // the accrual: absent at 100 beside a header served at 120, then served
      // and bound at 130. The full chain is read in the second run, the sweep
      // is not carried over, and the epoch completes.
      const docs = conformingDocs();
      let n = 0;
      const store3 = makeStore({ height: "120", docs, overrides: { accrual: () => (n++ === 0
        ? { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "100", documents: [] }
        : { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "130", documents: docs.platformAccrual }) } });
      const s = await A.acquireUntilSettled({ plan, readPage: store3.readPage, executionVerdict: verdictFor(), evaluate, maxRounds: 2 });
      const deps = s.evidence.dependents[FUNDER_A];
      ok(`accrual absent then served and bound: the full chain is read and the sweep is gone (${s.result.state})`,
        s.result.state === "complete" && s.rounds === 1 && deps.machinerySweep === undefined
        && deps.receipt.status === "served" && deps.partSet.parts.length === 2
        && store3.state.log.filter((d) => d.query === "parts").length === 1);
    }
    {
      // a non-payable row: absent at 100, then served under ANOTHER id at 130,
      // so the sweep must be re-keyed by the served id in the second run
      const planNP = mkPlan({ members: [member(FUNDER_A, PLANNED_A, { isSelfShare: true, payable: false })] });
      let n = 0;
      const store4 = makeStore({ height: "120", docs: { epochHeader: [headerDoc()] }, overrides: { accrual: () => (n++ === 0
        ? { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "100", documents: [] }
        : { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "130", documents: [accrualDoc(OTHER_ID, FUNDER_A)] }) } });
      const s = await A.acquireUntilSettled({ plan: planNP, readPage: store4.readPage, executionVerdict: verdictFor(), evaluate, maxRounds: 2 });
      const secondRunSweeps = store4.state.log.filter((d) => d.query.startsWith("sweep")).slice(3);
      ok(`non-payable absent then served under another id: the second run's sweep is keyed by the served id, and the kernel refuses the mismatch alone (${codesOf(s.result).join()})`,
        s.result.state === "refused" && codesOf(s.result).join() === "REFUSED_ACCRUAL_DOCUMENT_ID_MISMATCH"
        && s.rounds === 1 && secondRunSweeps.length === 3
        && secondRunSweeps.every((d) => whereId(d) === OTHER_ID && d.subjectAccrualId === OTHER_ID)
        && s.evidence.dependents[FUNDER_A].machinerySweep.parts.subjectAccrualId === OTHER_ID);
    }
    {
      // a REUSED served receipt whose PART SET CHANGED between runs has its verdict
      // RECOMPUTED (a soundness-review finding): the parts are stale
      // (empty at 100 beside a receipt served at 120, requiring two parts), the receipt
      // is reused in the second run and read once, and the verdict is requested twice,
      // once over each part set. The once-per-receipt rule was complete while the
      // verdict took only the receipt and is superseded by the applicability key.
      const docs = conformingDocs();
      let n = 0;
      const calls = [];
      const store5 = makeStore({ height: "120", docs, overrides: { parts: () => (n++ === 0
        ? { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "100", documents: [] }
        : { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "130", documents: docs.receiptProofPart }) } });
      const s = await A.acquireUntilSettled({ plan, readPage: store5.readPage, executionVerdict: verdictFor(calls), evaluate, maxRounds: 2 });
      ok(`a reused served receipt with a CHANGED part set has its verdict recomputed: requested twice across two runs, receipt read once by the adapter (${s.result.state}, calls ${calls.length})`,
        s.result.state === "complete" && s.rounds === 1 && calls.length === 2
        && store5.state.log.filter((d) => d.query === "receipt").length === 1
        && calls[0].receipt.documentId === calls[1].receipt.documentId
        && s.evidence.dependents[FUNDER_A].execution.label === "CAPTURE-VERIFIED");
    }
    {
      // an UNSERVED answer is not reused: the pinned reservation is unserved in
      // the first run (beside stale empty parts) and served in the second, and
      // the second run reads it again rather than carrying the failure over
      const docs = conformingDocs();
      let np = 0, nr = 0;
      const store6 = makeStore({ height: "120", docs, overrides: {
        parts: () => (np++ === 0
          ? { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "100", documents: [] }
          : { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "130", documents: docs.receiptProofPart }),
        reservationPinned: () => (nr++ === 0 ? { status: "unserved" }
          : { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "130", documents: docs.transferReservation }),
      } });
      const s = await A.acquireUntilSettled({ plan, readPage: store6.readPage, executionVerdict: verdictFor(), evaluate, maxRounds: 2 });
      ok(`an unserved answer is re-read, not reused: the pinned reservation is read twice and served in the end (${s.result.state})`,
        s.rounds === 1 && store6.state.log.filter((d) => d.query === "reservationPinned").length === 2
        && s.evidence.dependents[FUNDER_A].reservationPinned.status === "served"
        && s.reads.filter((r) => r.slot === "reservationPinned" && r.reused).length === 0);
    }
    {
      // the same for an UNVERIFIED first answer, the other failure strength
      const docs = conformingDocs();
      let np = 0, nr = 0;
      const store7 = makeStore({ height: "120", docs, overrides: {
        parts: () => (np++ === 0
          ? { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "100", documents: [] }
          : { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "130", documents: docs.receiptProofPart }),
        reservationPinned: () => (nr++ === 0 ? { status: "unverified" }
          : { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "130", documents: docs.transferReservation }),
      } });
      const s = await A.acquireUntilSettled({ plan, readPage: store7.readPage, executionVerdict: verdictFor(), evaluate, maxRounds: 2 });
      const rp = s.evidence.dependents[FUNDER_A].reservationPinned;
      ok(`an unverified answer is re-read, not reused: read twice, served in the end with the second read's provenance (${s.result.state})`,
        s.rounds === 1 && store7.state.log.filter((d) => d.query === "reservationPinned").length === 2
        && rp.status === "served" && rp.documentId === RES_A && rp.height === "130"
        && s.reads.filter((r) => r.slot === "reservationPinned" && r.reused).length === 0);
    }
    {
      // a reused receipt keeps the VERDICT ACTUALLY OBTAINED, not one rebuilt from
      // the member: the callback returns a distinctive non-verified verdict with a
      // reason, an injected evaluator forces exactly one refresh and then
      // delegates to the kernel, and the final execution object is that verdict
      const docs = conformingDocs();
      const calls = [];
      const distinctive = { label: "CAPTURE-INVALID", reason: "signature-mismatch-7f", verifiedAmountCredits: "1" };
      let forced = 0;
      const forcing = (p, ev) => (forced++ === 0
        ? { state: "unproved", reasons: [{ code: "UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", recordKey: "forced", diagnostic: "forced once" }] }
        : evaluate(p, ev));
      const store8 = makeStore({ docs });
      const s = await A.acquireUntilSettled({ plan, readPage: store8.readPage,
        executionVerdict: ({ receipt }) => { calls.push(receipt.documentId); return { ...distinctive }; }, evaluate: forcing, maxRounds: 2 });
      ok("a reused receipt carries exactly the verdict obtained for it, reason included, and the callback ran once",
        calls.length === 1 && s.rounds === 1 && canon(s.evidence.dependents[FUNDER_A].execution) === canon(distinctive)
        && store8.state.log.filter((d) => d.query === "receipt").length === 1
        && codesOf(s.result).includes("REFUSED_TRANSFER_UNVERIFIED"));
    }
    // A STALE NONEMPTY LISTING IS A NEGATIVE OBSERVATION TOO (a soundness-review finding): one immutable document's presence stays true at later
    // heights, but the LISTING that contained it is not complete at later heights.
    // The first policy reused every served answer with content, so a part listing
    // holding one of two required parts at height 100 beside a receipt at 120 was
    // reused through every retry round with zero fresh reads, and the loop ended
    // unproved while the adapter already held both parts. A served DOCUMENT is
    // reused; a SET OBSERVATION is re-read.
    const partialListing = (heightsAfterFirst, docsAfterFirst) => {
      const docs = conformingDocs();
      let n = 0;
      const calls = [];
      const store = makeStore({ height: "120", docs, overrides: { parts: () => {
        const i = n++;
        return i === 0
          ? { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "100", documents: docs.receiptProofPart.slice(0, 1) }
          : { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: heightsAfterFirst[Math.min(i - 1, heightsAfterFirst.length - 1)],
            documents: docsAfterFirst(docs) };
      } } });
      return { docs, store, calls, verdict: verdictFor(calls) };
    };
    {
      // the refresh supplies the complete set at 130: refreshed, complete, one round,
      // two part reads, both parts at 130 in the bundle, the receipt and its verdict reused
      const f = partialListing(["130"], (docs) => docs.receiptProofPart);
      const s = await A.acquireUntilSettled({ plan, readPage: f.store.readPage, executionVerdict: f.verdict, evaluate, maxRounds: 2 });
      const ps = s.evidence.dependents[FUNDER_A].partSet;
      // the verdict is requested TWICE here since a soundness-review finding (once per distinct part set), while
      // the receipt is still read once
      ok(`a soundness-review finding: a stale partial part listing is RE-READ, and the complete set completes the epoch (${s.result.state}, rounds ${s.rounds}, verdict calls ${f.calls.length})`,
        s.result.state === "complete" && s.rounds === 1
        && f.store.state.log.filter((d) => d.query === "parts").length === 2
        && ps.parts.length === 2 && ps.height === "130"
        && f.calls.length === 2 && f.store.state.log.filter((d) => d.query === "receipt").length === 1);
    }
    {
      // the refresh keeps supplying a stale, still-incomplete listing: the bound is
      // exhausted, the final evidence is the ACTUAL FINAL observation, and every round
      // re-read the parts. THE SUCCESSIVE OBSERVATIONS ARE DISTINGUISHABLE ON PURPOSE
      // (the confirmation review's follow-up): the first cut of this case returned
      // one part at 100 on every read, so a loop that handed back the FIRST bundle at
      // exhaustion looked identical to one handing back the last. Three parts are
      // required here, and the listing grows from one part at 100 to two at 119, so the
      // returned bundle must carry parts 1 and 2 at 119 and nothing earlier.
      const docs = conformingDocs();
      docs.transferReceipt[0].fields.proofPartCount = 4;
      docs.receiptProofPart.push(partDoc("e3".repeat(32), PLANNED_A, 3));
      const heights = ["100", "110", "119"], counts = [1, 1, 2];
      let n = 0;
      const calls = [];
      const store = makeStore({ height: "120", docs, overrides: { parts: () => {
        const i = Math.min(n++, heights.length - 1);
        return { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: heights[i], documents: docs.receiptProofPart.slice(0, counts[i]) };
      } } });
      const s = await A.acquireUntilSettled({ plan, readPage: store.readPage, executionVerdict: verdictFor(calls), evaluate, maxRounds: 2 });
      const ps = s.evidence.dependents[FUNDER_A].partSet;
      ok(`a soundness-review finding: exhaustion retains the FINAL observation (parts 1,2 at 119), not the first, after three distinguishable part reads (${s.result.state}, rounds ${s.rounds}, height ${ps.height}, parts ${ps.parts.map((x) => x.partIndex).join("+")})`,
        s.result.state === "unproved" && s.rounds === 2 && codesOf(s.result).includes("UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED")
        && n === 3 && ps.height === "119" && ps.parts.map((x) => x.partIndex).join() === "1,2"
        // a soundness-review finding: two distinct part sets across the three reads (one part, the same one
        // part, two parts), so the verdict is requested twice and reused once
        && calls.length === 2 && store.state.log.filter((d) => d.query === "receipt").length === 1);
    }
    {
      // the refresh observes the still-partial listing AT OR AFTER the receipt's height:
      // that is a required part missing at a height where it should exist, and the kernel
      // REFUSES it rather than treating it as ordinary incompleteness or retrying again
      const f = partialListing(["130"], (docs) => docs.receiptProofPart.slice(0, 1));
      const s = await A.acquireUntilSettled({ plan, readPage: f.store.readPage, executionVerdict: f.verdict, evaluate, maxRounds: 2 });
      ok(`a soundness-review finding: a partial listing observed at or after the receipt's height refuses, after exactly one refresh (${s.result.state}, rounds ${s.rounds})`,
        s.result.state === "refused" && s.rounds === 1 && codesOf(s.result).includes("REFUSED_PART_COUNT_MISMATCH")
        && f.store.state.log.filter((d) => d.query === "parts").length === 2);
    }
    {
      // zero rounds never refresh, and the unproved result is returned as it stands
      const f = partialListing(["130"], (docs) => docs.receiptProofPart);
      const s = await A.acquireUntilSettled({ plan, readPage: f.store.readPage, executionVerdict: f.verdict, evaluate, maxRounds: 0 });
      ok("a soundness-review finding: maxRounds 0 does not refresh a stale partial listing and returns the unproved result",
        s.result.state === "unproved" && s.rounds === 0 && f.store.state.log.filter((d) => d.query === "parts").length === 1);
    }
    // ---- a soundness-review finding: the injected verdict is AWAITED and receives the acquired parts and the
    // pinned reservation, as copies (the per-epoch context design, section 6) ----
    {
      // a verdict returned as a Promise is awaited and ITS RESOLVED VALUE reaches the
      // kernel: the seam used to capture the Promise itself through the walk and refuse it
      // as a foreign prototype, so no asynchronous verifier could ever be injected. The
      // resolved verdict is a DISTINCTIVE non-verified one with a reason, so a seam that
      // awaited and then discarded the value (substituting a constant) is caught by the
      // reason reaching the kernel's diagnostic (the pre-commit checker's construction).
      const docs = conformingDocs();
      const store = makeStore({ docs });
      let s = null, threw = null;
      try {
        s = await A.acquireUntilSettled({ plan, readPage: store.readPage,
          executionVerdict: async () => { await new Promise((r) => setTimeout(r, 1)); return { label: "CAPTURE-INVALID", reason: "async-basis-mismatch-3c" }; },
          evaluate, maxRounds: 2 });
      } catch (e) { threw = e.message; }
      const unv = s ? s.result.reasons.find((r) => r.code === "REFUSED_TRANSFER_UNVERIFIED") : null;
      ok(`a soundness-review finding: a verdict resolved by a Promise is awaited and its resolved value reaches the kernel (${s ? `${s.result.state}: ${unv ? unv.diagnostic.slice(0, 80) : "no transfer reason"}` : `threw: ${threw}`})`,
        s !== null && s.result.state === "refused" && !!unv && /async-basis-mismatch-3c/.test(unv.diagnostic)
        && s.evidence.dependents[FUNDER_A].execution.label === "CAPTURE-INVALID");
      // the same seam completes on a resolved CAPTURE-VERIFIED
      const s2 = await A.acquireUntilSettled({ plan, readPage: makeStore({ docs: conformingDocs() }).readPage,
        executionVerdict: async ({ member }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: member.effectiveCredits }), evaluate, maxRounds: 2 });
      ok(`a soundness-review finding: a resolved CAPTURE-VERIFIED completes the epoch (${s2.result.state})`, s2.result.state === "complete");
    }
    {
      // a rejected Promise is the named verifier-fault refusal: the run REJECTS (no bundle,
      // so no dependents entry and no recorded verdict exist to be consulted), the callback
      // ran exactly once, and no read was issued after the member's parts read
      const store = makeStore({ docs: conformingDocs() });
      let calls = 0, returned = null;
      await rejects("a soundness-review finding: a REJECTED verdict Promise is the named verifier-fault refusal, never an unproved result",
        A.acquireEpochEvidence({ plan, readPage: store.readPage, executionVerdict: async () => { calls += 1; throw new Error("proof stage down"); } })
          .then((r) => { returned = r; return r; }),
        /injected execution verdict failed for .*proof stage down.*a verifier fault is not evidence/);
      const q = queriesIssued(store);
      ok(`a soundness-review finding: after the rejection nothing was returned, the callback ran once, and the parts read was the last read issued (${q.join(">")})`,
        returned === null && calls === 1 && q[q.length - 1] === "parts");
    }
    // the RESOLVED value's own defect must be what the refusal names: a Promise is itself a
    // foreign prototype, so a class instance would be refused for the same words with or
    // without the await, which proves nothing. A function is refused for different words.
    await rejects("a soundness-review finding: a verdict Promise resolving to a non-plain value is refused naming the resolved value's defect",
      acquire(plan, makeStore({ docs: conformingDocs() }), async () => () => ({ label: "CAPTURE-VERIFIED" })),
      /execution verdict for .* is not a plain object \(.*is a function, not plain data\)/);
    {
      // the callback receives the EXACT acquired part set, as copies carrying each part's
      // fields, in ascending partIndex whatever order the adapter served them in, equal by
      // identifier and index to the part set the bundle records for that member; and it
      // receives the pinned reservation answer unreshaped (deep-equal to the bundle's) as a
      // copy. The store serves the parts in REVERSE so a missing sort is visible.
      const docs = conformingDocs();
      docs.receiptProofPart.reverse();
      const store = makeStore({ docs });
      const calls = [];
      const s = await A.acquireUntilSettled({ plan, readPage: store.readPage,
        executionVerdict: (call) => { calls.push(call); return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: call.member.effectiveCredits }; },
        evaluate, maxRounds: 2 });
      const dep = s.evidence.dependents[FUNDER_A];
      const call = calls[0];
      const idsGiven = call && call.parts && Array.isArray(call.parts.documents) ? call.parts.documents.map((d) => d.documentId) : null;
      const idsBundle = dep.partSet.parts.map((p) => p.documentId);
      // the bundle keeps the adapter's order (a projection, not a sort), so the two are
      // compared as SETS of identifiers, and the callback's own order is asserted ascending
      ok(`a soundness-review finding: the verdict callback receives the acquired part set with fields, ascending by partIndex, the same identifiers the bundle records (given ${idsGiven && idsGiven.map((x) => x.slice(0, 4)).join("+")}, bundle ${idsBundle.map((x) => x.slice(0, 4)).join("+")})`,
        calls.length === 1 && s.result.state === "complete"
        && idsGiven !== null && call.parts.status === "served"
        && idsGiven.length === idsBundle.length && [...idsGiven].sort().join() === [...idsBundle].sort().join()
        && call.parts.documents.map((d) => d.fields.partIndex).join() === "1,2"
        && call.parts.documents.every((d, i) => d.documentId === dep.partSet.parts.find((p) => p.partIndex === i + 1).documentId)
        && [...dep.partSet.parts.map((p) => p.partIndex)].sort().join() === "1,2");
      ok("a soundness-review finding: the verdict callback receives the pinned reservation answer unreshaped, deep-equal to the bundle's, as a copy",
        calls.length === 1 && isPlainObj(call.reservation) && call.reservation !== dep.reservationPinned
        && canon(call.reservation) === canon(dep.reservationPinned)
        && call.reservation.status === "served" && call.reservation.documentId === RES_A);
      ok("a soundness-review finding: the verdict callback receives the plan member as a copy, deep-equal to the plan's",
        calls.length === 1 && isPlainObj(call.member) && call.member !== plan.members[0] && canon(call.member) === canon(plan.members[0]));
      ok("a soundness-review finding: the callback's copies carry COMPLETE fields, each part's fields and the reservation's fields deep-equal to the adapter's documents",
        calls.length === 1
        && call.parts.documents.every((d) => canon(d.fields) === canon(docs.receiptProofPart.find((p) => p.id === d.documentId).fields))
        && canon(call.reservation.fields) === canon(docs.transferReservation[0].fields));
    }
    {
      // NESTED ISOLATION (the checker's control): the callback writes into nested fields of
      // every argument member; nothing reaches the bundle, the plan or the reads log, and
      // the epoch still completes on the verdict it returned
      const docs = conformingDocs();
      const store = makeStore({ docs });
      const planCanon = canon(plan);
      // a write into a SHARED (frozen) nested object throws inside the callback, which the
      // seam reports as a verifier fault; that throw is caught here and recorded as this
      // case's failure rather than ending the suite
      let s = null, threw = null;
      try {
        s = await A.acquireUntilSettled({ plan, readPage: store.readPage,
          executionVerdict: (call) => {
            call.member.effectiveCredits = "0"; call.member.funderId = "00".repeat(32);
            call.receipt.fields.proofPartCount = 99;
            call.reservation.fields.transitionHash = "ff".repeat(32); call.reservation.status = "unserved";
            call.parts.documents[0].fields.partIndex = 7; call.parts.documents.length = 0;
            return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: plan.members[0].effectiveCredits };
          }, evaluate, maxRounds: 2 });
      } catch (e) { threw = e.message; }
      const dep = s ? s.evidence.dependents[FUNDER_A] : null;
      ok(`a soundness-review finding: nested writes into the callback's argument reach neither the bundle, the plan nor the reads log (${s ? s.result.state : `threw: ${threw}`})`,
        s !== null && s.result.state === "complete" && canon(plan) === planCanon
        && dep.receipt.fields.proofPartCount === 3 && dep.reservationPinned.status === "served"
        && dep.reservationPinned.fields.transitionHash === docs.transferReservation[0].fields.transitionHash
        && dep.partSet.parts.length === 2 && [...dep.partSet.parts.map((p) => p.partIndex)].sort().join() === "1,2"
        && s.reads.filter((r) => r.slot === "parts").every((r) => r.answer.parts.length === 2));
    }
    {
      // THE PARTS READ IS FRESH WHEN THE CALLBACK RUNS, in a SECOND round too: the receipt is
      // unserved on the first read and served on the second, so the callback runs during the
      // refresh, and the parts it receives are the second round's fresh read (a set observation
      // is never reused, a soundness-review finding), with complete copied fields
      const docs = conformingDocs();
      let receiptReads = 0;
      const store = makeStore({ docs, overrides: { receipt: () => (receiptReads++ === 0
        ? { status: "unserved" }
        : { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "140", documents: docs.transferReceipt }) } });
      const calls = [];
      // an unserved receipt alone does not trigger a refresh (only the temporal code does),
      // so the first evaluation is FORCED to the refresh code and the second is the kernel's
      let forced = 0;
      const forcing = (p, ev) => (forced++ === 0
        ? { state: "unproved", reasons: [{ code: "UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", recordKey: "forced", diagnostic: "forced once" }] }
        : evaluate(p, ev));
      const s = await A.acquireUntilSettled({ plan, readPage: store.readPage,
        executionVerdict: (call) => { calls.push({ call, partsReadsSoFar: store.state.log.filter((d) => d.query === "parts").length }); return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: call.member.effectiveCredits }; },
        evaluate: forcing, maxRounds: 2 });
      const partsReads = s.reads.filter((r) => r.slot === "parts");
      ok(`a soundness-review finding: the callback ran in the second round on a freshly served receipt, over that round's FRESH parts read (${s.result.state}, rounds ${s.rounds}, parts reads ${partsReads.length}, reused ${partsReads.filter((r) => r.reused).length})`,
        calls.length === 1 && s.rounds === 1 && s.result.state === "complete" && receiptReads === 2
        && partsReads.length === 2 && partsReads.every((r) => r.reused === false) && calls[0].partsReadsSoFar === 2
        && calls[0].call.parts.documents.every((d) => canon(d.fields) === canon(docs.receiptProofPart.find((p) => p.id === d.documentId).fields)));
    }
    // ---- a soundness-review finding: a verdict is APPLICABLE only to the evidence it was computed over. Reuse is
    // keyed by the receipt AND the part set AND the reservation, so a refresh that changes the
    // parts recomputes the verdict; and a verdict is NOT REQUESTED over an unserved or
    // unverified parts or reservation read (the named result for unserved evidence) ----
    {
      // the reviewer's reproducer: a parts-sensitive verdict is negative over the short first
      // listing and verified over the complete refreshed one; the final bundle completes
      const docs = conformingDocs();
      let partReads = 0, calls = 0;
      const evolving = makeStore({ height: "120", docs, overrides: { parts: () => ({
        status: "served", proved: true, route: ROUTE, scope: SCOPE,
        height: ++partReads === 1 ? "100" : "130",
        documents: partReads === 1 ? docs.receiptProofPart.slice(0, 1) : docs.receiptProofPart }) } });
      const sensitive = async (call) => { calls += 1; return call.parts.documents.length === 2
        ? { label: "CAPTURE-VERIFIED", verifiedAmountCredits: call.member.effectiveCredits }
        : { label: "REFUSED", reason: "parts-incomplete-for-verification" }; };
      const s = await A.acquireUntilSettled({ plan, readPage: evolving.readPage, executionVerdict: sensitive, evaluate, maxRounds: 2 });
      ok(`a soundness-review finding: a refreshed part set recomputes the verdict: two callback calls, the final bundle complete (${s.result.state}, rounds ${s.rounds}, calls ${calls}, part reads ${partReads})`,
        s.result.state === "complete" && s.rounds === 1 && partReads === 2 && calls === 2
        && s.evidence.dependents[FUNDER_A].partSet.parts.length === 2
        && s.evidence.dependents[FUNDER_A].execution.label === "CAPTURE-VERIFIED");
    }
    {
      // unchanged evidence across a forced refresh still reuses the stored verdict (once)
      const store = makeStore({ docs: conformingDocs() });
      let forced = 0, calls = 0;
      const forcing = (p, ev) => (forced++ === 0
        ? { state: "unproved", reasons: [{ code: "UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", recordKey: "forced", diagnostic: "forced once" }] }
        : evaluate(p, ev));
      const s = await A.acquireUntilSettled({ plan, readPage: store.readPage,
        executionVerdict: () => { calls += 1; return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: plan.members[0].effectiveCredits }; },
        evaluate: forcing, maxRounds: 2 });
      ok(`a soundness-review finding: unchanged parts and reservation across a refresh reuse the stored verdict, one call (${calls}, rounds ${s.rounds})`,
        calls === 1 && s.rounds === 1 && s.result.state === "complete");
    }
    // the marker is read through its STRUCTURED members (read, status), not its sentence
    for (const [readName, status] of [["parts", "unserved"], ["parts", "unverified"], ["reservationPinned", "unserved"], ["reservationPinned", "unverified"]]) {
      const store = makeStore({ docs: conformingDocs(), overrides: { [readName]: () => ({ status }) } });
      let calls = 0;
      const run = await A.acquireEpochEvidence({ plan, readPage: store.readPage, executionVerdict: () => { calls += 1; return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: "1" }; } });
      const ex = run.evidence.dependents[FUNDER_A].execution;
      const r = evaluate(plan, run.evidence);
      const expectRead = readName === "parts" ? "parts" : "reservation";
      ok(`a soundness-review finding: an ${status} ${readName} read does not request a verdict; the marker names read=${expectRead} status=${status} structurally, the kernel is unproved and never refused on it (${r.state}: ${codesOf(r).join(",")})`,
        calls === 0 && ex.label === "EVIDENCE-UNRESOLVED" && ex.requested === false && ex.read === expectRead && ex.status === status
        && r.state === "unproved" && !codesOf(r).includes("REFUSED_TRANSFER_UNVERIFIED"));
    }
    {
      // THE KEY'S COMPONENTS, EACH AT ITS REAL WIDTH (the pre-commit checker's construction).
      // Through the public entry only the PART SET and the reservation's STATUS can differ
      // between the runs that consult a stored verdict: a served receipt and a served pinned
      // reservation are unique-key DOCUMENTS and are reused by descriptor identity, so their
      // identifier and hash components are defensive and cannot be varied here, which the
      // case below demonstrates by serving a different reservation on the refresh and
      // observing that the first is kept and the verdict reused. The SAME parts served in a
      // different order reuse, which is what the sorted key buys.
      const forcingOnce = () => { let forced = 0; return (p, ev) => (forced++ === 0
        ? { state: "unproved", reasons: [{ code: "UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", recordKey: "forced", diagnostic: "forced once" }] }
        : evaluate(p, ev)); };
      const RES_B = "d3".repeat(32);
      {
        const docs = conformingDocs();
        let n = 0, calls = 0;
        const store = makeStore({ docs, overrides: { reservationPinned: () => ({ status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "130",
          documents: [n++ === 0 ? reservationDoc(RES_A, PLANNED_A) : reservationDoc(RES_B, PLANNED_A)] }) } });
        const s = await A.acquireUntilSettled({ plan, readPage: store.readPage,
          executionVerdict: () => { calls += 1; return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: plan.members[0].effectiveCredits }; }, evaluate: forcingOnce(), maxRounds: 2 });
        ok(`a soundness-review finding key width: a served pinned reservation is REUSED across the refresh (the adapter's different second document is never read), so its identifier and hash cannot change between the runs that consult a verdict; one call (calls ${calls}, reads ${n}, ${s.result.state})`,
          calls === 1 && n === 1 && s.rounds === 1 && s.result.state === "complete"
          && s.evidence.dependents[FUNDER_A].reservationPinned.documentId === RES_A
          && s.reads.filter((r) => r.slot === "reservationPinned" && r.reused).length === 1);
      }
      {
        const docs = conformingDocs();
        let n = 0, calls = 0;
        const store = makeStore({ docs, overrides: { parts: () => ({ status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "100",
          documents: n++ === 0 ? docs.receiptProofPart : [...docs.receiptProofPart].reverse() }) } });
        const s = await A.acquireUntilSettled({ plan, readPage: store.readPage,
          executionVerdict: () => { calls += 1; return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: plan.members[0].effectiveCredits }; }, evaluate: forcingOnce(), maxRounds: 2 });
        ok(`a soundness-review finding key: the SAME parts served in a different order across the refresh reuse the stored verdict (calls ${calls}, ${s.result.state})`,
          calls === 1 && s.rounds === 1 && s.result.state === "complete");
      }
    }
    {
      // a reservation that resolves on the refresh: no call in round one, one call in round
      // two over the served reservation, and the epoch completes
      const docs = conformingDocs();
      let resReads = 0, calls = 0;
      const store = makeStore({ docs, overrides: { reservationPinned: () => (resReads++ === 0
        ? { status: "unserved" }
        : { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "130", documents: docs.transferReservation }) } });
      let forced = 0;
      const forcing = (p, ev) => (forced++ === 0
        ? { state: "unproved", reasons: [{ code: "UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", recordKey: "forced", diagnostic: "forced once" }] }
        : evaluate(p, ev));
      const s = await A.acquireUntilSettled({ plan, readPage: store.readPage,
        executionVerdict: (call) => { calls += 1; return call.reservation.status === "served"
          ? { label: "CAPTURE-VERIFIED", verifiedAmountCredits: call.member.effectiveCredits } : { label: "REFUSED", reason: "no reservation" }; },
        evaluate: forcing, maxRounds: 2 });
      ok(`a soundness-review finding: a reservation resolving on the refresh is verified then, once, and the epoch completes (${s.result.state}, calls ${calls}, reservation reads ${resReads})`,
        calls === 1 && resReads === 2 && s.rounds === 1 && s.result.state === "complete");
    }
    // ---- a soundness-review finding: a SERVED answer whose route obtained NO PROOF is unresolved evidence. The
    // verifier is never shown the route, so a verdict over it would be a positive label over
    // transport evidence the kernel already marks UNPROVED_ROUTE_NOT_PROVED. Acquisition
    // treats proved: false as unresolved (the marker, no call), the key carries the proof
    // status so a later proved read recomputes, and a served document over an unproved route
    // is NOT reused (a re-read may obtain the proof; the reused one never can). ----
    for (const [readName, expectRead] of [["parts", "parts"], ["reservationPinned", "reservation"]]) {
      const docs = conformingDocs();
      const store = makeStore({ docs, overrides: { [readName]: () => ({ status: "served", proved: false, route: ROUTE, scope: SCOPE, height: "100",
        documents: readName === "parts" ? docs.receiptProofPart : docs.transferReservation }) } });
      let calls = 0;
      const run = await A.acquireEpochEvidence({ plan, readPage: store.readPage, executionVerdict: () => { calls += 1; return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: plan.members[0].effectiveCredits }; } });
      const ex = run.evidence.dependents[FUNDER_A].execution;
      const r = evaluate(plan, run.evidence);
      ok(`a soundness-review finding: a SERVED ${readName} read over an UNPROVED route does not request a verdict; the marker names read=${expectRead} status=unproved-route, the bundle carries no CAPTURE-VERIFIED, the kernel is unproved (${r.state}: ${codesOf(r).join(",")})`,
        calls === 0 && ex.label === "EVIDENCE-UNRESOLVED" && ex.requested === false && ex.read === expectRead && ex.status === "unproved-route"
        && r.state === "unproved" && codesOf(r).includes("UNPROVED_ROUTE_NOT_PROVED") && !codesOf(r).includes("REFUSED_TRANSFER_UNVERIFIED"));
    }
    {
      // the parts read unproved on the first round and proved on the refresh: the marker's key
      // differs from the proved read's, the verdict is requested once, in round two, and the
      // epoch completes
      const docs = conformingDocs();
      let n = 0, calls = 0;
      const store = makeStore({ docs, overrides: { parts: () => ({ status: "served", proved: n++ === 0 ? false : true, route: ROUTE, scope: SCOPE, height: "100", documents: docs.receiptProofPart }) } });
      let forced = 0;
      const forcing = (p, ev) => (forced++ === 0
        ? { state: "unproved", reasons: [{ code: "UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", recordKey: "forced", diagnostic: "forced once" }] }
        : evaluate(p, ev));
      // the ROUND of the call is observed through the adapter's own read count at call time
      // (two parts reads means round two), not inferred from the final state
      let partsReadsAtCall = null;
      const s = await A.acquireUntilSettled({ plan, readPage: store.readPage,
        executionVerdict: () => { calls += 1; partsReadsAtCall = n; return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: plan.members[0].effectiveCredits }; }, evaluate: forcing, maxRounds: 2 });
      ok(`a soundness-review finding key: a parts read proved on the refresh after an unproved first read recomputes (the proof status is in the key): one call, made in round two, complete (calls ${calls}, parts reads at call ${partsReadsAtCall}, ${s.result.state})`,
        calls === 1 && partsReadsAtCall === 2 && s.rounds === 1 && n === 2 && s.result.state === "complete");
    }
    {
      // a served pinned reservation over an unproved route is RE-READ on the refresh, not
      // reused: the second read obtains the proof, the verdict is requested once, complete
      const docs = conformingDocs();
      let n = 0, calls = 0;
      const store = makeStore({ docs, overrides: { reservationPinned: () => ({ status: "served", proved: n++ === 0 ? false : true, route: ROUTE, scope: SCOPE, height: "100", documents: docs.transferReservation }) } });
      let forced = 0;
      const forcing = (p, ev) => (forced++ === 0
        ? { state: "unproved", reasons: [{ code: "UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", recordKey: "forced", diagnostic: "forced once" }] }
        : evaluate(p, ev));
      const s = await A.acquireUntilSettled({ plan, readPage: store.readPage,
        executionVerdict: () => { calls += 1; return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: plan.members[0].effectiveCredits }; }, evaluate: forcing, maxRounds: 2 });
      ok(`a soundness-review finding reuse: a served reservation over an UNPROVED route is re-read on the refresh, never reused, and completes once proved (adapter reads ${n}, calls ${calls}, ${s.result.state}, reused ${s.reads.filter((x) => x.slot === "reservationPinned" && x.reused).length})`,
        n === 2 && calls === 1 && s.rounds === 1 && s.result.state === "complete"
        && s.reads.filter((x) => x.slot === "reservationPinned" && x.reused).length === 0);
      // THE CONTROL that isolates the predicate's proof dependency: the same store serving the
      // reservation PROVED from the first read is read by the adapter ONCE across the same
      // forced refresh (reused), so an unconditional re-read policy would fail here while the
      // case above passes only because the first read was unproved
      const docs2 = conformingDocs();
      let n2 = 0, calls2 = 0, forced2 = 0;
      const store2 = makeStore({ docs: docs2, overrides: { reservationPinned: () => { n2 += 1; return { status: "served", proved: true, route: ROUTE, scope: SCOPE, height: "100", documents: docs2.transferReservation }; } } });
      const forcing2 = (p, ev) => (forced2++ === 0
        ? { state: "unproved", reasons: [{ code: "UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", recordKey: "forced", diagnostic: "forced once" }] }
        : evaluate(p, ev));
      const s2 = await A.acquireUntilSettled({ plan, readPage: store2.readPage,
        executionVerdict: () => { calls2 += 1; return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: plan.members[0].effectiveCredits }; }, evaluate: forcing2, maxRounds: 2 });
      ok(`a soundness-review finding reuse control: the same reservation served PROVED from the first read is read by the adapter once across the same refresh (adapter reads ${n2}, calls ${calls2}, ${s2.result.state})`,
        n2 === 1 && calls2 === 1 && s2.rounds === 1 && s2.result.state === "complete");
    }
    // ---- a soundness-review finding, the third verifier input (the round's second pass): the RECEIPT read served
    // over an unproved route is unresolved evidence too. The first repair covered the parts and
    // the pinned reservation and left the receipt, whose served status alone entered verdict
    // handling. ----
    {
      const docs = conformingDocs();
      const store = makeStore({ docs, overrides: { receipt: () => ({ status: "served", proved: false, route: ROUTE, scope: SCOPE, height: "120", documents: docs.transferReceipt }) } });
      let calls = 0;
      const run = await A.acquireEpochEvidence({ plan, readPage: store.readPage, executionVerdict: () => { calls += 1; return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: plan.members[0].effectiveCredits }; } });
      const ex = run.evidence.dependents[FUNDER_A].execution;
      const r = evaluate(plan, run.evidence);
      ok(`a soundness-review finding receipt: a SERVED receipt read over an UNPROVED route does not request a verdict; the marker names read=receipt status=unproved-route, no CAPTURE-VERIFIED in the bundle, the kernel unproved (calls ${calls}, label ${ex && ex.label}, ${r.state}: ${codesOf(r).join(",")})`,
        calls === 0 && !!ex && ex.label === "EVIDENCE-UNRESOLVED" && ex.requested === false && ex.read === "receipt" && ex.status === "unproved-route"
        && r.state === "unproved" && codesOf(r).includes("UNPROVED_ROUTE_NOT_PROVED") && !codesOf(r).includes("REFUSED_TRANSFER_UNVERIFIED"));
    }
    {
      // the receipt unproved on the first round and proved on the refresh: the unproved receipt
      // is re-read (never reused), the verdict is requested once, in round two, and the epoch
      // completes; the round is observed through the adapter's receipt read count at call time
      const docs = conformingDocs();
      let n = 0, calls = 0, receiptReadsAtCall = null;
      const store = makeStore({ docs, overrides: { receipt: () => ({ status: "served", proved: n++ === 0 ? false : true, route: ROUTE, scope: SCOPE, height: "120", documents: docs.transferReceipt }) } });
      let forced = 0;
      const forcing = (p, ev) => (forced++ === 0
        ? { state: "unproved", reasons: [{ code: "UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", recordKey: "forced", diagnostic: "forced once" }] }
        : evaluate(p, ev));
      const s = await A.acquireUntilSettled({ plan, readPage: store.readPage,
        executionVerdict: () => { calls += 1; receiptReadsAtCall = n; return { label: "CAPTURE-VERIFIED", verifiedAmountCredits: plan.members[0].effectiveCredits }; }, evaluate: forcing, maxRounds: 2 });
      ok(`a soundness-review finding receipt refresh: an unproved receipt is re-read, the proved second read is verified once in round two, complete (receipt reads ${n}, calls ${calls}, at call ${receiptReadsAtCall}, ${s.result.state}, reused ${s.reads.filter((x) => x.slot === "receipt" && x.reused).length})`,
        n === 2 && calls === 1 && receiptReadsAtCall === 2 && s.rounds === 1 && s.result.state === "complete"
        && s.reads.filter((x) => x.slot === "receipt" && x.reused).length === 0);
    }
    ok("the exported acquisition function takes no reuse input (a caller-supplied cache is ignored, every read is fresh)",
      await (async () => {
        const st = makeStore({ docs: conformingDocs() });
        const first = await acquire(plan, st);
        // the planted cache holds SERVED content (what a reuse channel would
        // accept) that differs from the store, so reuse would be visible
        const planted = first.reads.map((r) => ({ ...r, answer: r.answer.status === "served"
          ? { ...r.answer, documentId: OTHER_ID, fields: { ...r.answer.fields, planted: true } } : r.answer }));
        const st2 = makeStore({ docs: conformingDocs() });
        const again = await A.acquireEpochEvidence({ plan, readPage: st2.readPage, executionVerdict: verdictFor(), reuse: planted });
        return st2.state.log.length === 7 && again.reads.every((r) => r.reused === false)
          && again.evidence.header.documentId === HDR_ID && again.evidence.header.fields.planted === undefined;
      })());
    await rejects("maxRounds must be a non-negative safe integer",
      A.acquireUntilSettled({ plan, readPage: stuck.readPage, executionVerdict: verdictFor(), evaluate, maxRounds: -1 }), /maxRounds/);
    await rejects("an evaluate that returns no result refuses",
      A.acquireUntilSettled({ plan, readPage: stuck.readPage, executionVerdict: verdictFor(), evaluate: () => null, maxRounds: 1 }), /evaluate/);
  }

  console.log(`\ne2AcquireTest: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exitCode = 1;
};

main().catch((e) => { console.error(`e2AcquireTest: unexpected throw: ${e.message}`); process.exitCode = 1; });
