/**
 * e2ForwardKernelTest: the acceptance matrix of the forward lifecycle kernel's pure core,
 * bound to the PRODUCTION exports of e2ForwardKernel.cjs.
 *
 * THE MANIFEST IS PART OF THE TEST. Every case identifier of the contract's acceptance
 * matrix (FORWARD_LIFECYCLE_KERNEL_CONTRACT.md revision 5, groups A through H) must be
 * covered by at least one executed case here, and every reason code the kernel can emit
 * must be observed at least once, or THIS TEST FAILS. A matrix row without a test, or a
 * code no fixture produces, is a gap this file reports rather than a silence.
 *
 * THE SCHEMA WALK IS PART OF THE TEST. Every required member of every v11 E2 document
 * type must be accounted for in EXACTLY ONE bucket of the kernel's PLAN_FIELD_COVERAGE
 * (key, compared, execution-verified, or system-managed), and every type must be
 * immutable and non-deletable, which is the premise the temporal rule stands on. WIDTH:
 * the walk proves every field is LISTED in the static coverage metadata; the mutation
 * battery proves the listed comparisons this slice implements actually fire. Neither
 * proves that production behavior outside this module checks a listed field.
 *
 * THE BOUNDARY REGRESSIONS (a soundness-review finding) are the executed counterexamples from the
 * review of the first version: a lookalike snapshot, a lookalike plan, and forbidden-set
 * emptiness concluded from omission. Each must REFUSE or come out unproved, never
 * complete or true.
 *
 * WHAT THIS FILE DOES NOT ESTABLISH: it closes no CN finding. a soundness-review finding needs the audit's
 * production path on the shared plan; a soundness-review finding needs the real fetch returning found[0].id
 * with a production-composition case; a soundness-review finding live half needs the audit regression.
 * G1 here asserts the pure refusal and the projection refusal; that construction,
 * signing and broadcast stay unreachable is the composition test of a later unit.
 */

"use strict";

const path = require("path");
const { pathToFileURL } = require("url");
const K = require("./e2ForwardKernel.cjs");

let passed = 0;
let failed = 0;
const ok = (name, cond) => {
  if (cond) { passed += 1; console.log(`  PASS: ${name}`); }
  else { failed += 1; console.log(`  FAIL: ${name}`); }
};

// ---- the manifest ----
const MATRIX_CASES = [
  "A1", "A2", "A3", "A4", "A5",
  "B1", "B2", "B3", "B4", "B5",
  "C1", "C2", "C3", "C4", "C5",
  "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10",
  "D11", "D12", "D13", "D14", "D15",
  "E1", "E2", "F1", "F2", "G1", "G2", "G3",
  "H1", "H2", "H3", "H4",
];
const covered = new Set();
const codesSeen = new Set();
const cover = (id) => covered.add(id);
const codesOf = (r) => r.reasons.map((x) => x.code);
const note = (r) => { for (const c of codesOf(r)) codesSeen.add(c); return r; };
const throwsCode = (fn, code) => {
  try { fn(); return false; }
  catch (e) { if (String(e.message).includes(code)) { codesSeen.add(code); return true; } return false; }
};
const throwsMatching = (fn, re) => {
  try { fn(); return false; }
  catch (e) { return re.test(String(e.message)); }
};

// ---- fixture identities ----
const POOL = "11".repeat(32);
const POOL2 = "22".repeat(32);
const FUNDER_A = "aa".repeat(32);
const FUNDER_B = "bb".repeat(32);
const PLANNED_A = "a1".repeat(32);
const PLANNED_B = "b1".repeat(32);
const OTHER_ID = "cc".repeat(32);
const RES_ID = "d1".repeat(32);
const RCPT_ID = "d2".repeat(32);
const AH = "ee".repeat(32);
const TH = "ff".repeat(32);
const EPOCH = 7;
const SCOPE = Object.freeze({ contractId: "c-11", chainId: "devnet-x", contractVersion: 11,
  poolId: POOL, epochIndex: EPOCH });
const ROUTE = "documents-proved-query";

// ---- fixture builders ----
const mkPlan = (over = {}) => K.buildExpectedRecordPlan({
  scope: SCOPE,
  encodingRefused: false,
  header: { grossCredits: "1000", feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH },
  members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "900",
    shareBps: 10000, isSelfShare: false, payable: true }],
  ...over,
});

const served = (fields, { height = "100", documentId = OTHER_ID, proved = true, scope = SCOPE, route = ROUTE, servedCount } = {}) =>
  ({ status: "served", proved, route, height, scope, documentId, fields, ...(servedCount !== undefined ? { servedCount } : {}) });
const absent = (height = "100", scope = SCOPE) => ({ status: "proved-absence", proved: true, route: ROUTE, height, scope });
const unserved = () => ({ status: "unserved" });
const unverified = () => ({ status: "unverified" });
// the proved machinery sweep over one row: THREE separate enumerations, one per
// dependent document type, each with its own provenance and its own height
// (a soundness-review finding). The helper keeps the old call sites' spelling (reservationCount and
// the rest) so a case that cares about one count reads the same, while building
// the component shape the kernel now requires.
const sweepPart = ({ count, height, scope, proved, subjectAccrualId }) =>
  ({ status: "served", proved, route: ROUTE, height, scope, subjectAccrualId, count });
const sweep = ({ height = "100", scope = SCOPE, reservationCount = 0, receiptCount = 0,
  partCount = 0, proved = true, subjectAccrualId = PLANNED_A,
  // per-component overrides, for the mixed-height and partial-failure cases
  reservation, receipt, parts } = {}) => ({
  reservation: reservation !== undefined ? reservation
    : sweepPart({ count: reservationCount, height, scope, proved, subjectAccrualId }),
  receipt: receipt !== undefined ? receipt
    : sweepPart({ count: receiptCount, height, scope, proved, subjectAccrualId }),
  parts: parts !== undefined ? parts
    : sweepPart({ count: partCount, height, scope, proved, subjectAccrualId }),
});
// the proved accrual enumeration over (pool, epoch)
const enumAcc = (funderIds, { height = "100", scope = SCOPE, proved = true } = {}) =>
  ({ status: "served", proved, route: ROUTE, height, scope, funderIds });

const headerFields = (over = {}) => ({ poolId: POOL, epochIndex: EPOCH, grossCredits: "1000",
  feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH, ...over });
const accrualFields = (over = {}) => ({ poolId: POOL, funderId: FUNDER_A, epochIndex: EPOCH,
  amountCredits: "900", shareBps: 10000, ...over });

const servedHeader = (over = {}, opt = {}) => served(headerFields(over), { documentId: "77".repeat(32), ...opt });
const servedAccrual = (over = {}, opt = {}) => served(accrualFields(over), { documentId: PLANNED_A, ...opt });

const conformingDeps = (over = {}) => ({
  reservationPinned: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH }, { documentId: RES_ID }),
  reservationEnumerated: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH }, { documentId: RES_ID }),
  receipt: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 3 }, { documentId: RCPT_ID }),
  partSet: { status: "served", proved: true, route: ROUTE, subjectAccrualId: PLANNED_A, height: "100", scope: SCOPE,
    parts: [{ partIndex: 1, documentId: "e1".repeat(32) }, { partIndex: 2, documentId: "e2".repeat(32) }] },
  execution: { label: "CAPTURE-VERIFIED", verifiedAmountCredits: "900" },
  ...over,
});

const conformingEvidence = (over = {}) => ({
  header: servedHeader(),
  accruals: { [FUNDER_A]: servedAccrual() },
  accrualEnumeration: enumAcc([FUNDER_A]),
  dependents: { [FUNDER_A]: conformingDeps() },
  ...over,
});

const evaluate = (plan, evidence) => note(K.evaluateEpochForwardState({ plan, evidence }));

const main = async () => {
  console.log("e2ForwardKernelTest");

  // ================= the schema walk =================
  {
    const ROOT = process.env.TEGARA_PLATFORM_ROOT || path.join(__dirname, "..", "..");
    const contractUrl = pathToFileURL(path.join(ROOT, "dist", "contract", "poolLedger.js")).href;
    const { poolLedgerContract } = await import(contractUrl);
    const { buildV11, E2_TYPES } = require("./contractV11.cjs");
    const v11 = buildV11(poolLedgerContract);
    ok("schema walk covers exactly the five E2 types", E2_TYPES.length === 5
      && E2_TYPES.every((t) => t in K.PLAN_FIELD_COVERAGE)
      && Object.keys(K.PLAN_FIELD_COVERAGE).every((t) => E2_TYPES.includes(t)));
    for (const t of E2_TYPES) {
      const def = v11[t];
      // the temporal rule's premise: record existence is monotonic
      ok(`${t} is immutable (documentsMutable false)`, def.documentsMutable === false);
      ok(`${t} is non-deletable (canBeDeleted false)`, def.canBeDeleted === false);
      const cov = K.PLAN_FIELD_COVERAGE[t];
      const buckets = [cov.key, cov.compared, cov.executionVerified, cov.systemManaged];
      // EXACTLY ONE bucket owns each member: duplicate ownership would let two
      // buckets each assume the other performs the check
      const owned = new Map();
      let duplicated = false;
      for (const b of buckets) for (const f of b) {
        if (owned.has(f)) duplicated = true;
        owned.set(f, true);
      }
      ok(`${t}: no member is owned by two coverage buckets`, !duplicated);
      const uncovered = def.required.filter((f) => !owned.has(f));
      ok(`${t}: every required member is LISTED in the static coverage metadata (a listing, not proof production checks it)`, uncovered.length === 0);
      if (uncovered.length) console.log(`        uncovered: ${uncovered.join(", ")}`);
      const phantom = [...owned.keys()].filter((f) => !f.startsWith("$") && !(f in def.properties));
      ok(`${t}: the coverage names no member the schema lacks`, phantom.length === 0);
    }
  }

  // ================= group A: complete =================
  {
    cover("A1");
    const r = evaluate(mkPlan(), conformingEvidence());
    ok("A1: served and proved exact records evaluate complete", r.state === "complete" && r.reasons.length === 0);
    ok("A1: the height range is reported", r.heightRange !== null && r.heightRange.min === "100" && r.heightRange.max === "100");
    const snap = K.createSnapshot([r], { generation: 0 });
    ok("A1: a complete epoch projects true", K.projectForWriter(snap, EPOCH) === true);
  }
  {
    cover("A2");
    const plan = mkPlan({
      header: { grossCredits: "0", feeCredits: "0", memberCount: 1, calcVersion: 1, allocationHash: AH },
      members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "0",
        shareBps: 10000, isSelfShare: false, payable: false }],
    });
    const r = evaluate(plan, {
      header: servedHeader({ grossCredits: "0", feeCredits: "0" }),
      accruals: { [FUNDER_A]: servedAccrual({ amountCredits: "0" }) },
      accrualEnumeration: enumAcc([FUNDER_A]),
      dependents: { [FUNDER_A]: { machinerySweep: sweep() } },
    });
    ok("A2: an all-zero epoch with header, accruals and proved emptiness is complete", r.state === "complete");
    ok("A2: the zero-earning condition is named", r.condition === "zero-earning-epoch");
  }
  {
    cover("A3");
    const plan = mkPlan({
      header: { grossCredits: "1000", feeCredits: "100", memberCount: 2, calcVersion: 1, allocationHash: AH },
      members: [
        { funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "300",
          shareBps: 6000, isSelfShare: true, payable: false },
        { funderId: FUNDER_B, plannedAccrualId: PLANNED_B, effectiveCredits: "40",
          shareBps: 4000, isSelfShare: false, payable: false },
      ],
    });
    const r = evaluate(plan, {
      header: servedHeader({ memberCount: 2 }),
      accruals: {
        [FUNDER_A]: servedAccrual({ amountCredits: "300", shareBps: 6000 }),
        [FUNDER_B]: servedAccrual({ funderId: FUNDER_B, amountCredits: "40", shareBps: 4000 }, { documentId: PLANNED_B }),
      },
      accrualEnumeration: enumAcc([FUNDER_A, FUNDER_B]),
      dependents: { [FUNDER_A]: { machinerySweep: sweep() },
        [FUNDER_B]: { machinerySweep: sweep({ subjectAccrualId: PLANNED_B }) } },
    });
    ok("A3: an all-nonpayable epoch is complete only over PROVED machinery emptiness", r.state === "complete");
  }
  {
    cover("A4");
    const deps = conformingDeps({
      receipt: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 1 }, { documentId: RCPT_ID }),
      partSet: { status: "served", proved: true, route: ROUTE, subjectAccrualId: PLANNED_A, height: "100", scope: SCOPE, parts: [] },
    });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
    ok("A4: a single-part receipt expects ZERO part documents and is complete", r.state === "complete");
  }
  {
    cover("A5");
    const plan = mkPlan({ encodingRefused: true, header: null });
    const r = evaluate(plan, { header: absent(), accruals: { [FUNDER_A]: absent() },
      accrualEnumeration: enumAcc([]),
      dependents: { [FUNDER_A]: { machinerySweep: sweep() } } });
    ok("A5: an encoding-refused epoch with PROVED emptiness is complete, never lagging", r.state === "complete");
    ok("A5: the encoding-refused condition is named", r.condition === "encoding-refused");
    // A5b (a soundness-review finding): MACHINERY under an encoding-refused epoch must refuse, PER
    // COMPONENT. This branch had NO test at all, which is how the a soundness-review finding repair
    // was able to leave its count read against the new component map (every term
    // `undefined > 0`, permanently false) with the suite green at 137. The
    // suite's own "every reason code is observed" gate did not see it either,
    // because the SAME code is pushed by the header and accrual sites in this
    // branch, so a per-code coverage claim is satisfied while one site is dead.
    {
      const r2 = evaluate(plan, { header: absent(), accruals: { [FUNDER_A]: absent() },
        accrualEnumeration: enumAcc([]),
        dependents: { [FUNDER_A]: { machinerySweep: sweep({ reservationCount: 1, partCount: 2 }) } } });
      ok("A5b: machinery under an encoding-refused epoch refuses",
        r2.state === "refused" && codesOf(r2).includes("REFUSED_RECORDS_UNDER_ENCODING_REFUSED_EPOCH"));
      ok("A5b: EACH positive component refuses on its own key, not one merged verdict",
        r2.reasons.some((x) => x.recordKey.endsWith(":reservation"))
        && r2.reasons.some((x) => x.recordKey.endsWith(":parts")));
      ok("A5b: the component with a ZERO count raises nothing",
        !r2.reasons.some((x) => x.recordKey.endsWith(":receipt")));
    }
  }

  // ================= group B: incomplete, legal prefixes =================
  {
    cover("B1");
    const r = evaluate(mkPlan(), { header: absent(), accruals: { [FUNDER_A]: absent() },
      accrualEnumeration: enumAcc([]),
      dependents: { [FUNDER_A]: { machinerySweep: sweep() } } });
    ok("B1: nothing published is incomplete at the header", r.state === "incomplete"
      && codesOf(r).includes("INCOMPLETE_HEADER_ABSENT"));
    const snap = K.createSnapshot([r], { generation: 0 });
    ok("B1: an incomplete epoch projects false", K.projectForWriter(snap, EPOCH) === false);
  }
  {
    cover("B2");
    const r = evaluate(mkPlan(), { header: servedHeader(), accruals: { [FUNDER_A]: absent() },
      accrualEnumeration: enumAcc([]),
      dependents: { [FUNDER_A]: { machinerySweep: sweep() } } });
    ok("B2: header only is incomplete at the accrual", r.state === "incomplete"
      && codesOf(r).includes("INCOMPLETE_ACCRUAL_ABSENT"));
    ok("B2: the reason names the record", r.reasons.every((x) => typeof x.recordKey === "string" && x.recordKey.length > 0));
  }
  {
    cover("B3");
    const deps = { reservationPinned: absent(), reservationEnumerated: absent(),
      receipt: absent(), partSet: null, execution: null };
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
    ok("B3: header and accruals with no machinery is incomplete at the reservation", r.state === "incomplete"
      && codesOf(r).includes("INCOMPLETE_RESERVATION_ABSENT"));
  }
  {
    cover("B4");
    const deps = conformingDeps({ receipt: absent(), partSet: null, execution: null });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
    ok("B4: reservation present, receipt absent is a legal in-flight prefix", r.state === "incomplete"
      && codesOf(r).includes("INCOMPLETE_RECEIPT_ABSENT"));
  }
  {
    cover("B5"); cover("G2");
    const deps = conformingDeps({ receipt: absent(), execution: null });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
    ok("B5/G2: parts observed while the receipt is absent is incomplete, not refused, with no count claim",
      r.state === "incomplete" && codesOf(r).includes("INCOMPLETE_RECEIPT_ABSENT"));
  }

  // ================= group C: unproved =================
  {
    cover("C1");
    const deps = conformingDeps({ reservationPinned: unserved(), reservationEnumerated: absent(),
      receipt: absent(), partSet: null, execution: null });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
    ok("C1: unserved evidence is unproved, not incomplete", r.state === "unproved"
      && codesOf(r).includes("UNPROVED_QUERY_UNSERVED"));
    ok("C1: the height range is null under unserved evidence", r.heightRange === null);
    const snap = K.createSnapshot([r], { generation: 0 });
    ok("C1: an unproved epoch REFUSES projection by name (the single most important case)",
      throwsCode(() => K.projectForWriter(snap, EPOCH), "PROJECTION_STATE_UNPROVED"));
  }
  {
    cover("C2");
    const r = evaluate(mkPlan(), conformingEvidence({ header: unverified() }));
    ok("C2: a failed proof check is unproved", r.state === "unproved"
      && codesOf(r).includes("UNPROVED_PROOF_UNVERIFIED"));
  }
  {
    cover("C3");
    const r = evaluate(mkPlan(), conformingEvidence({ header: servedHeader({}, { proved: false }) }));
    ok("C3: a served answer from an unproved route is unproved, whatever its payload", r.state === "unproved"
      && codesOf(r).includes("UNPROVED_ROUTE_NOT_PROVED"));
  }
  {
    cover("C4");
    for (const code of K.PRECONDITION_CODES) {
      const r = note(K.unprovedPrecondition({ poolId: POOL, epochIndex: EPOCH, code,
        diagnostic: "a precondition of plan building is unavailable" }));
      ok(`C4: ${code} produces an unproved result`, r.state === "unproved" && codesOf(r).includes(code));
      const snap = K.createSnapshot([r], { generation: 0 });
      ok(`C4: ${code} refuses projection`, throwsCode(() => K.projectForWriter(snap, EPOCH), "PROJECTION_STATE_UNPROVED"));
    }
  }
  {
    cover("C5");
    const r = evaluate(mkPlan(), { header: servedHeader(), accruals: { [FUNDER_A]: unserved() },
      accrualEnumeration: enumAcc([FUNDER_A]), dependents: {} });
    ok("C5: an unserved accrual leaves the dependents unkeyable and is unproved", r.state === "unproved"
      && codesOf(r).includes("UNPROVED_ACCRUAL_IDENTIFIER_UNRESOLVED")
      && codesOf(r).includes("UNPROVED_QUERY_UNSERVED"));
  }

  // ================= group D: refused =================
  {
    cover("D1");
    const fields = [
      ["grossCredits", { grossCredits: "999" }],
      ["feeCredits", { feeCredits: "99" }],
      ["memberCount", { memberCount: 2 }],
      ["calcVersion", { calcVersion: 2 }],
      ["allocationHash", { allocationHash: "00".repeat(32) }],
    ];
    for (const [name, over] of fields) {
      const r = evaluate(mkPlan(), conformingEvidence({ header: servedHeader(over) }));
      ok(`D1: a header ${name} mismatch refuses`, r.state === "refused"
        && codesOf(r).includes("REFUSED_HEADER_MISMATCH"));
    }
    const snap = K.createSnapshot([evaluate(mkPlan(), conformingEvidence({ header: servedHeader({ grossCredits: "999" }) }))], { generation: 0 });
    ok("D1: a refused epoch REFUSES projection by name (never a retry)",
      throwsCode(() => K.projectForWriter(snap, EPOCH), "PROJECTION_STATE_REFUSED"));
  }
  {
    cover("D2");
    const r = evaluate(mkPlan(), conformingEvidence({ accruals: { [FUNDER_A]: servedAccrual({ amountCredits: "800" }) } }));
    ok("D2: an accrual amount mismatch refuses", r.state === "refused"
      && codesOf(r).includes("REFUSED_ACCRUAL_AMOUNT_MISMATCH"));
    const dup = evaluate(mkPlan(), conformingEvidence({ accruals: { [FUNDER_A]: servedAccrual({}, { servedCount: 2 }) } }));
    ok("D2: two accruals served for one funder-epoch refuse (a unique key)",
      codesOf(dup).includes("REFUSED_ACCRUAL_DUPLICATE"));
    const extra = evaluate(mkPlan(), conformingEvidence({ accrualEnumeration: enumAcc([FUNDER_A, FUNDER_B]) }));
    ok("D2: the enumeration serving an accrual outside the recomputed set refuses (a fetched extra)",
      codesOf(extra).includes("REFUSED_ACCRUAL_EXTRA"));
  }
  {
    cover("D3");
    // a soundness-review finding: the amount is RIGHT and the split is WRONG, so any amount-only
    // comparison passes this fixture and the mutation battery removes exactly
    // this comparison to prove the case detects it
    const r = evaluate(mkPlan(), conformingEvidence({ accruals: { [FUNDER_A]: servedAccrual({ shareBps: 5000 }) } }));
    ok("D3 (a soundness-review finding): a shareBps mismatch with a correct amount refuses", r.state === "refused"
      && codesOf(r).includes("REFUSED_ACCRUAL_SHARE_BPS_MISMATCH"));
    ok("D3: the amount comparison did NOT flag this fixture", !codesOf(r).includes("REFUSED_ACCRUAL_AMOUNT_MISMATCH"));
  }
  {
    cover("D4");
    const plan = mkPlan({
      header: { grossCredits: "1000", feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH },
      members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "300",
        shareBps: 10000, isSelfShare: true, payable: false }],
    });
    const r = evaluate(plan, {
      header: servedHeader(),
      accruals: { [FUNDER_A]: servedAccrual({ amountCredits: "300" }) },
      accrualEnumeration: enumAcc([FUNDER_A]),
      dependents: { [FUNDER_A]: { machinerySweep: sweep({ reservationCount: 1 }) } },
    });
    ok("D4: machinery under an excluded row refuses at any height", r.state === "refused"
      && codesOf(r).includes("REFUSED_MACHINERY_UNDER_EXCLUDED_ROW"));
  }
  {
    cover("D5");
    const deps = conformingDeps({
      reservationPinned: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: "12".repeat(32) }, { documentId: RES_ID }),
      reservationEnumerated: absent(),
    });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
    ok("D5: a reservation whose transitionHash differs from its receipt's refuses", r.state === "refused"
      && codesOf(r).includes("REFUSED_RESERVATION_MISMATCH"));
  }
  {
    cover("D6");
    const deps = conformingDeps({
      receipt: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 3 }, { documentId: RCPT_ID, servedCount: 2 }),
      reservationEnumerated: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH }, { documentId: RES_ID, servedCount: 2 }),
    });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
    ok("D6: duplicate receipts and reservations under one accrual refuse", r.state === "refused"
      && codesOf(r).includes("REFUSED_RECEIPT_AMBIGUOUS")
      && codesOf(r).includes("REFUSED_RESERVATION_AMBIGUOUS"));
  }
  {
    cover("D7");
    const deps = conformingDeps({
      reservationEnumerated: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH }, { documentId: "d9".repeat(32) }),
    });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
    ok("D7: the enumeration and the pinned read serving DIFFERENT documents refuses", r.state === "refused"
      && codesOf(r).includes("REFUSED_RESERVATION_MISMATCH"));
  }
  {
    cover("D8");
    const deps = conformingDeps({
      receipt: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 4 }, { documentId: RCPT_ID }),
    });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
    ok("D8: an under-count at or after the receipt's height refuses", r.state === "refused"
      && codesOf(r).includes("REFUSED_PART_COUNT_MISMATCH"));
    const over = conformingDeps({
      partSet: { status: "served", proved: true, route: ROUTE, subjectAccrualId: PLANNED_A, height: "90", scope: SCOPE,
        parts: [{ partIndex: 1 }, { partIndex: 2 }, { partIndex: 3 }] },
      receipt: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 3 }, { documentId: RCPT_ID }),
    });
    const r2 = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: over } }));
    ok("D8: an OVER-count refuses at ANY observation height (records are permanent)", r2.state === "refused"
      && codesOf(r2).includes("REFUSED_PART_COUNT_MISMATCH"));
  }
  {
    cover("D9");
    const bad = conformingDeps({ execution: { label: "CAPTURE-VERIFIED", verifiedAmountCredits: "800" } });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: bad } }));
    ok("D9: a verified amount differing from the entitlement refuses", r.state === "refused"
      && codesOf(r).includes("REFUSED_PART_MISMATCH"));
    const unv = conformingDeps({ execution: { label: "READ-CHECKED", reason: "no capture" } });
    const r2 = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: unv } }));
    ok("D9: an execution verdict below CAPTURE-VERIFIED refuses", r2.state === "refused"
      && codesOf(r2).includes("REFUSED_TRANSFER_UNVERIFIED"));
  }
  {
    cover("D10");
    const plan = mkPlan({ encodingRefused: true, header: null });
    const r = evaluate(plan, { header: servedHeader(), accruals: { [FUNDER_A]: servedAccrual() },
      accrualEnumeration: enumAcc([FUNDER_A]),
      dependents: { [FUNDER_A]: { machinerySweep: sweep() } } });
    ok("D10: records under an encoding-refused epoch refuse, header, accrual and enumeration alike",
      r.state === "refused"
      && codesOf(r).filter((c) => c === "REFUSED_RECORDS_UNDER_ENCODING_REFUSED_EPOCH").length === 3);
  }
  {
    cover("D11");
    const plan = mkPlan({
      members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "40",
        shareBps: 10000, isSelfShare: false, payable: false }],
    });
    const r = evaluate(plan, { header: absent("101"),
      accruals: { [FUNDER_A]: servedAccrual({ amountCredits: "40" }, { height: "100" }) },
      accrualEnumeration: enumAcc([FUNDER_A]),
      dependents: { [FUNDER_A]: { machinerySweep: sweep() } } });
    ok("D11: an accrual with the header's absence proved AT OR AFTER its height refuses", r.state === "refused"
      && codesOf(r).includes("REFUSED_RECORDS_WITHOUT_HEADER"));
  }
  {
    cover("D12");
    const r = evaluate(mkPlan(), { header: servedHeader({}, { height: "101" }),
      accruals: { [FUNDER_A]: absent("101") },
      accrualEnumeration: enumAcc([]),
      dependents: { [FUNDER_A]: { machinerySweep: sweep({ receiptCount: 1, height: "100" }) } } });
    ok("D12: dependents with the accrual's absence proved at or after their height refuse", r.state === "refused"
      && codesOf(r).includes("REFUSED_DEPENDENTS_WITHOUT_ACCRUAL"));
  }
  {
    cover("D13");
    const deps = conformingDeps({
      partSet: { status: "served", proved: true, route: ROUTE, subjectAccrualId: PLANNED_A, height: "100", scope: SCOPE, parts: [] },
    });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
    ok("D13: a receipt with its required parts proved absent at its height refuses (out of order)",
      r.state === "refused" && codesOf(r).includes("REFUSED_RECEIPT_BEFORE_PARTS"));
  }
  {
    cover("D14");
    const r = evaluate(mkPlan(), conformingEvidence({ header: servedHeader({ epochIndex: EPOCH + 1 }) }));
    ok("D14: a served answer for a DIFFERENT key refuses as nonconforming", r.state === "refused"
      && codesOf(r).includes("REFUSED_NONCONFORMING_ANSWER"));
  }
  {
    cover("D15");
    const foreign = { ...SCOPE, chainId: "mainnet-y" };
    const r = evaluate(mkPlan(), { header: servedHeader({}, { height: "100" }),
      accruals: { [FUNDER_A]: servedAccrual({}, { scope: foreign, height: "999" }) },
      accrualEnumeration: enumAcc([FUNDER_A]),
      dependents: {} });
    ok("D15: an answer from a different scope refuses and is never compared", r.state === "refused"
      && codesOf(r).includes("REFUSED_SCOPE_MISMATCH"));
    ok("D15: the out-of-scope answer's height never enters the range",
      r.heightRange !== null && r.heightRange.max === "100");
  }

  // ================= group E: the snapshot boundary =================
  {
    cover("E1");
    const snap = K.createSnapshot([evaluate(mkPlan(), conformingEvidence())], { generation: 0 });
    ok("E1: an epoch absent from the snapshot refuses at lookup, never evaluates on demand",
      throwsCode(() => K.projectForWriter(snap, EPOCH + 1), "PROJECTION_EPOCH_NOT_EVALUATED"));
  }
  {
    cover("E2");
    // epoch 0 has its own expectations; epoch 1's include the carry. Each epoch
    // is evaluated against ITS OWN plan, and epoch 0's completion is unchanged
    // by epoch 1's state.
    const scope0 = { ...SCOPE, epochIndex: 0 };
    const scope1 = { ...SCOPE, epochIndex: 1 };
    const plan0 = mkPlan({ scope: scope0,
      members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "40",
        shareBps: 10000, isSelfShare: false, payable: false }],
      header: { grossCredits: "1000", feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH } });
    const plan1 = mkPlan({ scope: scope1,
      members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_B, effectiveCredits: "940",
        shareBps: 10000, isSelfShare: false, payable: true }],
      header: { grossCredits: "1000", feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH } });
    const hdr0 = served(headerFields({ epochIndex: 0 }), { documentId: "77".repeat(32), scope: scope0 });
    const acc0 = served(accrualFields({ epochIndex: 0, amountCredits: "40" }), { documentId: PLANNED_A, scope: scope0 });
    const r0 = note(K.evaluateEpochForwardState({ plan: plan0,
      evidence: { header: hdr0, accruals: { [FUNDER_A]: acc0 },
        accrualEnumeration: enumAcc([FUNDER_A], { scope: scope0 }),
        dependents: { [FUNDER_A]: { machinerySweep: sweep({ scope: scope0 }) } } } }));
    const r1 = note(K.evaluateEpochForwardState({ plan: plan1,
      evidence: { header: absent("100", scope1),
        accruals: { [FUNDER_A]: absent("100", scope1) },
        accrualEnumeration: enumAcc([], { scope: scope1 }),
        dependents: { [FUNDER_A]: { machinerySweep: sweep({ scope: scope1, subjectAccrualId: PLANNED_B }) } } } }));
    ok("E2: epoch 0 completes on its own expectations while epoch 1 carries the deferral", r0.state === "complete" && r1.state === "incomplete");
    const snap = K.createSnapshot([r0, r1], { generation: 0 });
    ok("E2: the projection answers per epoch", K.projectForWriter(snap, 0) === true && K.projectForWriter(snap, 1) === false);
  }

  // ================= group F: mixed evidence =================
  {
    cover("F1");
    const plan = mkPlan({
      header: { grossCredits: "1000", feeCredits: "100", memberCount: 2, calcVersion: 1, allocationHash: AH },
      members: [
        { funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "500",
          shareBps: 5000, isSelfShare: false, payable: true },
        { funderId: FUNDER_B, plannedAccrualId: PLANNED_B, effectiveCredits: "400",
          shareBps: 5000, isSelfShare: false, payable: true },
      ],
    });
    const r = evaluate(plan, {
      header: servedHeader({ memberCount: 2 }),
      accruals: {
        [FUNDER_A]: servedAccrual({ amountCredits: "999", shareBps: 5000 }),
        [FUNDER_B]: servedAccrual({ funderId: FUNDER_B, amountCredits: "400", shareBps: 5000 }, { documentId: PLANNED_B }),
      },
      accrualEnumeration: enumAcc([FUNDER_A, FUNDER_B]),
      dependents: {
        [FUNDER_A]: { reservationPinned: absent(), reservationEnumerated: absent(), receipt: absent(), partSet: null, execution: null },
        [FUNDER_B]: { reservationPinned: unserved(), reservationEnumerated: absent(), receipt: absent(), partSet: null, execution: null },
      },
    });
    ok("F1: a mismatch beside an unserved query is refused AND retains the unproved reason",
      r.state === "refused"
      && codesOf(r).includes("REFUSED_ACCRUAL_AMOUNT_MISMATCH")
      && codesOf(r).includes("UNPROVED_QUERY_UNSERVED"));
    ok("F1: the height range is null, never a range the result did not earn", r.heightRange === null);
  }
  {
    cover("F2");
    const deps = conformingDeps({ reservationEnumerated: absent("100") });
    deps.reservationPinned = served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH },
      { documentId: RES_ID, height: "101" });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
    ok("F2: a unique-key recovery beside an enumeration gap stays complete for the writer", r.state === "complete");
    const gap = r.observations.find((o) => o.kind === "enumeration-gap");
    ok("F2: the gap observation retains BOTH heights and concludes nothing about the enumeration",
      !!gap && gap.uniqueKeyHeight === "101" && gap.enumerationHeight === "100");
  }

  // ================= group G: identifier binding and parts =================
  {
    cover("G1");
    // G1b (2026-09-08, coverage debt named by an independent review of the mutation
    // battery), RUN BEFORE G1 ON PURPOSE: G1's fixture supplies NO dependents, so a kernel with the
    // identifier comparison REMOVED refuses it anyway, for a missing dependents entry,
    // before any identifier assertion runs, and a throw ends the suite, so a G1b placed
    // after G1 was never reached under that mutant. This fixture supplies COHERENT dependents
    // keyed by the served identifier, so a kernel without the comparison would
    // evaluate the chain and complete; the correct kernel refuses for the identifier
    // mismatch ALONE, and that named refusal is what binds the comparison.
    const depsUnderServed = {
      reservationPinned: served({ poolId: POOL, accrualId: OTHER_ID, transitionHash: TH }, { documentId: RES_ID }),
      reservationEnumerated: served({ poolId: POOL, accrualId: OTHER_ID, transitionHash: TH }, { documentId: RES_ID }),
      receipt: served({ poolId: POOL, accrualId: OTHER_ID, transitionHash: TH, proofPartCount: 3 }, { documentId: RCPT_ID }),
      partSet: { status: "served", proved: true, route: ROUTE, subjectAccrualId: OTHER_ID, height: "100", scope: SCOPE,
        parts: [{ partIndex: 1, documentId: "e1".repeat(32) }, { partIndex: 2, documentId: "e2".repeat(32) }] },
      execution: { label: "CAPTURE-VERIFIED", verifiedAmountCredits: "900" },
    };
    const rb = evaluate(mkPlan(), {
      header: servedHeader(),
      accruals: { [FUNDER_A]: servedAccrual({}, { documentId: OTHER_ID }) },
      accrualEnumeration: enumAcc([FUNDER_A]),
      dependents: { [FUNDER_A]: depsUnderServed },
    });
    ok("G1b (a soundness-review finding): a mismatched identifier beside coherent dependents under the served id refuses for the identifier alone",
      rb.state === "refused" && codesOf(rb).join() === "REFUSED_ACCRUAL_DOCUMENT_ID_MISMATCH");
    // a soundness-review finding: payload-conforming accrual under a DIFFERENT document identifier.
    // The pure core refuses and the projection refuses; that construction,
    // signing and broadcast stay unreachable is the later composition test.
    const r = evaluate(mkPlan(), {
      header: servedHeader(),
      accruals: { [FUNDER_A]: servedAccrual({}, { documentId: OTHER_ID }) },
      accrualEnumeration: enumAcc([FUNDER_A]),
      dependents: {},
    });
    ok("G1 (a soundness-review finding): a conforming accrual under a different served identifier refuses", r.state === "refused"
      && codesOf(r).includes("REFUSED_ACCRUAL_DOCUMENT_ID_MISMATCH"));
    ok("G1: the payload comparisons did not flag the fixture (the identifier alone did)",
      !codesOf(r).includes("REFUSED_ACCRUAL_AMOUNT_MISMATCH") && !codesOf(r).includes("REFUSED_ACCRUAL_SHARE_BPS_MISMATCH"));
    const snap = K.createSnapshot([r], { generation: 0 });
    ok("G1: the projection refuses, so no transfer step is reached through it",
      throwsCode(() => K.projectForWriter(snap, EPOCH), "PROJECTION_STATE_REFUSED"));
  }
  {
    cover("G3");
    for (const [label, parts] of [
      ["noncontiguous [1,3]", [{ partIndex: 1 }, { partIndex: 3 }]],
      ["out-of-range [0]", [{ partIndex: 0 }]],
      ["duplicate [1,1]", [{ partIndex: 1 }, { partIndex: 1 }]],
    ]) {
      const deps = conformingDeps({ receipt: absent(), execution: null,
        partSet: { status: "served", proved: true, route: ROUTE, subjectAccrualId: PLANNED_A, height: "100", scope: SCOPE, parts } });
      const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
      ok(`G3: ${label} part indices refuse with or without the receipt`, r.state === "refused"
        && codesOf(r).includes("REFUSED_PART_INDEX_NONCONFORMING"));
    }
  }

  // ================= group H: the temporal prefix rule (a soundness-review finding) =================
  {
    cover("H1");
    const stale = conformingDeps({ reservationPinned: absent("100"), reservationEnumerated: absent(),
      receipt: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 3 },
        { documentId: RCPT_ID, height: "101" }) });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: stale } }));
    ok("H1: a reservation absence OLDER than the receipt is temporally unresolved, never refused",
      r.state === "unproved" && codesOf(r).includes("UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED")
      && !codesOf(r).includes("REFUSED_RESERVATION_PROVED_ABSENT"));
    const settled = conformingDeps({ reservationPinned: absent("101"), reservationEnumerated: absent(),
      receipt: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 3 },
        { documentId: RCPT_ID, height: "101" }) });
    const r2 = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: settled } }));
    ok("H1: the same absence AT the receipt's height establishes the violation and refuses",
      r2.state === "refused" && codesOf(r2).includes("REFUSED_RESERVATION_PROVED_ABSENT"));
    const noncon = conformingDeps({
      reservationPinned: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: "12".repeat(32) },
        { documentId: RES_ID, height: "102" }),
      reservationEnumerated: absent() });
    const r3 = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: noncon } }));
    ok("H1: a reacquired reservation goes to the ORDINARY conformance rules, so nonconforming still refuses",
      r3.state === "refused" && codesOf(r3).includes("REFUSED_RESERVATION_MISMATCH"));
  }
  {
    cover("H2");
    const partial = conformingDeps({
      partSet: { status: "served", proved: true, route: ROUTE, subjectAccrualId: PLANNED_A, height: "100", scope: SCOPE,
        parts: [{ partIndex: 1 }, { partIndex: 2 }] },
      receipt: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 4 },
        { documentId: RCPT_ID, height: "101" }) });
    const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: partial } }));
    ok("H2: a stale PARTIAL part set is temporally unresolved, not a count refusal",
      r.state === "unproved" && codesOf(r).includes("UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED")
      && !codesOf(r).includes("REFUSED_PART_COUNT_MISMATCH"));
    const zero = conformingDeps({
      partSet: { status: "served", proved: true, route: ROUTE, subjectAccrualId: PLANNED_A, height: "100", scope: SCOPE, parts: [] },
      receipt: served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 3 },
        { documentId: RCPT_ID, height: "101" }) });
    const r2 = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: zero } }));
    ok("H2: a stale EMPTY part set is temporally unresolved too",
      r2.state === "unproved" && codesOf(r2).includes("UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED"));
  }
  {
    cover("H3");
    const plan = mkPlan({
      members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "40",
        shareBps: 10000, isSelfShare: false, payable: false }],
    });
    const r = evaluate(plan, { header: absent("100"),
      accruals: { [FUNDER_A]: servedAccrual({ amountCredits: "40" }, { height: "101" }) },
      accrualEnumeration: enumAcc([FUNDER_A]),
      dependents: { [FUNDER_A]: { machinerySweep: sweep() } } });
    ok("H3: a header absence OLDER than a served accrual is temporally unresolved, never refused",
      r.state === "unproved" && codesOf(r).includes("UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED")
      && !codesOf(r).includes("REFUSED_RECORDS_WITHOUT_HEADER"));
  }
  {
    cover("H4");
    const stale = conformingDeps({ reservationPinned: absent("100"), reservationEnumerated: absent(),
      receipt: absent("100"), partSet: null, execution: null });
    const r = evaluate(mkPlan(), {
      header: servedHeader({}, { height: "105" }),
      accruals: { [FUNDER_A]: servedAccrual({}, { height: "105" }) },
      accrualEnumeration: enumAcc([FUNDER_A]),
      dependents: { [FUNDER_A]: stale },
    });
    ok("H4 (mirrored): a stale absence never declares incompleteness either",
      r.state === "unproved" && codesOf(r).includes("UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED")
      && !codesOf(r).includes("INCOMPLETE_RESERVATION_ABSENT"));
    const fresh = conformingDeps({ reservationPinned: absent("105"), reservationEnumerated: absent("105"),
      receipt: absent("105"), partSet: null, execution: null });
    const r2 = evaluate(mkPlan(), {
      header: servedHeader({}, { height: "105" }),
      accruals: { [FUNDER_A]: servedAccrual({}, { height: "105" }) },
      accrualEnumeration: enumAcc([FUNDER_A]),
      dependents: { [FUNDER_A]: fresh },
    });
    ok("H4: the same absence at the prefix's height IS incomplete", r2.state === "incomplete"
      && codesOf(r2).includes("INCOMPLETE_RESERVATION_ABSENT"));
  }

  // ============ the boundary regressions (a soundness-review finding), executed counterexamples ============
  {
    // a soundness-review finding CE1: a snapshot-shaped object literal with the right kind string
    const legit = evaluate(mkPlan(), conformingEvidence());
    ok("a soundness-review finding CE1: a lookalike snapshot object NEVER projects, whatever its kind string says",
      throwsMatching(() => K.projectForWriter({ kind: "tegara.e2.forwardSnapshot.v1", lookup: () => legit }, 999),
        /createSnapshot/));
    // a soundness-review finding CE2: a cloned plan with an emptied member list
    ok("a soundness-review finding CE2: a lookalike plan (a clone with emptied members) NEVER evaluates",
      throwsMatching(() => K.evaluateEpochForwardState({ plan: { ...mkPlan(), members: [] }, evidence: conformingEvidence() }),
        /buildExpectedRecordPlan/));
    // a soundness-review finding CE3: forbidden-set emptiness concluded from omission
    const planEx = mkPlan({
      header: { grossCredits: "0", feeCredits: "0", memberCount: 1, calcVersion: 1, allocationHash: AH },
      members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "0",
        shareBps: 10000, isSelfShare: false, payable: false }],
    });
    const exBase = {
      header: servedHeader({ grossCredits: "0", feeCredits: "0" }),
      accruals: { [FUNDER_A]: servedAccrual({ amountCredits: "0" }) },
      accrualEnumeration: enumAcc([FUNDER_A]),
    };
    const omitted = evaluate(planEx, { ...exBase, dependents: {} });
    ok("a soundness-review finding CE3a: an OMITTED machinery sweep is unproved, never complete", omitted.state === "unproved"
      && codesOf(omitted).includes("UNPROVED_QUERY_UNSERVED"));
    const unsv = evaluate(planEx, { ...exBase, dependents: { [FUNDER_A]: { machinerySweep: { status: "unserved" } } } });
    ok("a soundness-review finding CE3b: an UNSERVED machinery sweep is unproved, never complete", unsv.state === "unproved");
    const noEnum = evaluate(mkPlan(), conformingEvidence({ accrualEnumeration: undefined }));
    ok("a soundness-review finding CE3c: an OMITTED accrual enumeration is unproved, never complete", noEnum.state === "unproved"
      && codesOf(noEnum).includes("UNPROVED_QUERY_UNSERVED"));
    const unRoute = evaluate(planEx, { ...exBase,
      dependents: { [FUNDER_A]: { machinerySweep: sweep({ proved: false }) } } });
    ok("a soundness-review finding CE3d: a sweep from an unproved route is unproved", unRoute.state === "unproved"
      && codesOf(unRoute).includes("UNPROVED_ROUTE_NOT_PROVED"));
  }

  // ============ a soundness-review finding: every enumeration evaluated in full, and bound to its subject ============
  // The six cases the third review produced. Each was executed against the kernel at
  // `0813dc9` and returned `complete` WITH NO REASONS, which is why they are here: the
  // 117 assertions that existed before them would not have failed if the repair were
  // reverted. Four concern the reservation enumeration being validated structurally and
  // then read only on its served branch; two concern an enumeration whose QUERY SUBJECT
  // is not checked, so evidence gathered for one member can be read for another.
  {
    const resEnumCase = (label, en, expect) => {
      const deps = conformingDeps({ reservationEnumerated: en });
      const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
      ok(`a soundness-review finding ${label}`, r.state === expect && r.state !== "complete");
      if (r.state !== expect) console.log(`        got ${r.state}: ${codesOf(r).join(",") || "(no reasons)"}`);
    };
    // 0: the enumeration was never performed. Added after mutation M11 SURVIVED the
    // first six cases: every one of them supplied SOME enumeration answer, so the
    // omitted branch itself was unbound and could be deleted with the suite green.
    // The general rule this earned: every evidence field needs an ABSENT case, not
    // only its malformed ones.
    resEnumCase("an OMITTED reservation enumeration is unproved, never read as agreement",
      undefined, "unproved");
    // 1: the enumeration could not be served at all
    resEnumCase("an UNSERVED reservation enumeration is unproved, not silent",
      { status: "unserved" }, "unproved");
    // 2: an answer arrived through a route that proves nothing
    resEnumCase("an UNPROVED-ROUTE reservation enumeration is unproved, not silent",
      served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH }, { documentId: RES_ID, proved: false }),
      "unproved");
    // 3: an answer obtained under another pool's scope
    resEnumCase("an OUT-OF-SCOPE reservation enumeration refuses, and is never compared",
      served({ poolId: POOL, accrualId: PLANNED_A, transitionHash: TH },
        { documentId: RES_ID, scope: { ...SCOPE, poolId: POOL2 } }),
      "refused");
    // 4: an answer served for a different accrual than the one asked about
    resEnumCase("a WRONG-KEY reservation enumeration refuses as nonconforming",
      served({ poolId: POOL, accrualId: "bb".repeat(32), transitionHash: TH }, { documentId: RES_ID }),
      "refused");

    // 5: a machinery sweep gathered for one member, read under another
    {
      const plan = mkPlan({
        header: { grossCredits: "1000", feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH },
        members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "40",
          shareBps: 10000, isSelfShare: false, payable: false }],
      });
      const r = evaluate(plan, {
        header: servedHeader(),
        accruals: { [FUNDER_A]: servedAccrual({ amountCredits: "40" }) },
        accrualEnumeration: enumAcc([FUNDER_A]),
        // the sweep was run against a DIFFERENT accrual and is being read for
        // this row. Since a soundness-review finding the subject lives PER COMPONENT, because each
        // component is its own read, so the misfiling is expressed there. A
        // top-level subjectAccrualId is now inert by design, and asserting on
        // that spelling would have tested a field nothing reads.
        dependents: { [FUNDER_A]: { machinerySweep: sweep({ subjectAccrualId: PLANNED_B }) } },
      });
      ok("a soundness-review finding a machinery sweep run against a DIFFERENT accrual is not read as this row's emptiness",
        r.state === "refused" && codesOf(r).includes("REFUSED_NONCONFORMING_ANSWER"));
      if (r.state === "complete") console.log("        got complete with no reasons");
    }

    // 6b (a soundness-review finding): the misfiling can be in ONE component while the other two are
    // correctly subjected. The pre-a soundness-review finding envelope could not express this at all,
    // and it is the shape a per-row assembly bug actually produces.
    {
      const plan = K.buildExpectedRecordPlan({
        scope: SCOPE, encodingRefused: false,
        header: { grossCredits: "1000", feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH },
        members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "40",
          shareBps: 10000, isSelfShare: false, payable: false }],
      });
      const sw = sweep();
      sw.receipt = { ...sw.receipt, subjectAccrualId: PLANNED_B };
      const r = evaluate(plan, {
        header: servedHeader(),
        accruals: { [FUNDER_A]: servedAccrual({ amountCredits: "40" }) },
        accrualEnumeration: enumAcc([FUNDER_A]),
        dependents: { [FUNDER_A]: { machinerySweep: sw } },
      });
      ok("a soundness-review finding ONE mis-subjected sweep component refuses even where the other two are correct",
        r.state === "refused" && codesOf(r).includes("REFUSED_NONCONFORMING_ANSWER"));
      ok("a soundness-review finding the refusal names the offending COMPONENT, not the whole sweep",
        r.reasons.some((x) => x.code === "REFUSED_NONCONFORMING_ANSWER" && x.recordKey.endsWith(":receipt")));
    }

    // 6: a part enumeration gathered for one accrual, read under another
    {
      const deps = conformingDeps({
        partSet: { status: "served", proved: true, route: ROUTE, subjectAccrualId: OTHER_ID,
          height: "100", scope: SCOPE, parts: [{ partIndex: 1 }, { partIndex: 2 }] },
      });
      const r = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
      ok("a soundness-review finding a part enumeration run against a DIFFERENT accrual is not read as this row's part set",
        r.state === "refused" && codesOf(r).includes("REFUSED_NONCONFORMING_ANSWER"));
      if (r.state === "complete") console.log("        got complete with no reasons");
    }

    // AND THE NARROWED INTERFACE, bound deliberately (Decision 2, option B): a fully
    // conforming PAYABLE row with a SERVED accrual stays complete with NO machinery
    // sweep, because every record permitted under it is individually read and compared.
    // Without this case the narrowing is a claim in a comment rather than a behavior.
    {
      const r = evaluate(mkPlan(), conformingEvidence());
      ok("a soundness-review finding a conforming payable row with a served accrual is complete WITHOUT a machinery sweep",
        r.state === "complete" && r.reasons.length === 0);
    }
  }

  // ============ a soundness-review finding: the sweep is THREE observations, not one ============
  // The proved-page interface queries one document type per call, so a sweep is
  // three reads at up to three heights. These cases bind that the components are
  // evaluated INDEPENDENTLY and that each positive observation is judged against
  // the accrual absence using ITS OWN height.
  {
    const nonPayablePlan = () => K.buildExpectedRecordPlan({
      scope: SCOPE, encodingRefused: false,
      header: { grossCredits: "1000", feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH },
      members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "40",
        shareBps: 10000, isSelfShare: false, payable: false }],
    });

    // 1: three PROVED-EMPTY components resolving at three DIFFERENT heights is
    // the ordinary live case (three sequential queries observe three heights),
    // and it must be complete. The heights must all reach the range.
    {
      const r = evaluate(nonPayablePlan(), {
        header: servedHeader({}, { height: "100" }),
        accruals: { [FUNDER_A]: servedAccrual({ amountCredits: "40" }, { height: "100" }) },
        accrualEnumeration: enumAcc([FUNDER_A], { height: "100" }),
        dependents: { [FUNDER_A]: { machinerySweep: sweep({
          reservation: { status: "served", proved: true, route: ROUTE, scope: SCOPE, subjectAccrualId: PLANNED_A, height: "101", count: 0 },
          receipt: { status: "served", proved: true, route: ROUTE, scope: SCOPE, subjectAccrualId: PLANNED_A, height: "102", count: 0 },
          parts: { status: "served", proved: true, route: ROUTE, scope: SCOPE, subjectAccrualId: PLANNED_A, height: "103", count: 0 },
        }) } },
      });
      ok("a soundness-review finding three proved-empty components at three DIFFERENT heights is complete",
        r.state === "complete" && r.reasons.length === 0);
      ok("a soundness-review finding every component height reaches the result range, not just one",
        r.heightRange !== null && r.heightRange.min === "100" && r.heightRange.max === "103");
    }

    // 2: one UNSERVED component beside two proved-empty ones. The unserved read
    // must make the epoch unproved on its own, and must NOT be covered for by
    // its two siblings' emptiness (the a soundness-review finding shape, per type).
    {
      const r = evaluate(nonPayablePlan(), {
        header: servedHeader(),
        accruals: { [FUNDER_A]: servedAccrual({ amountCredits: "40" }) },
        accrualEnumeration: enumAcc([FUNDER_A]),
        dependents: { [FUNDER_A]: { machinerySweep: sweep({ receipt: { status: "unserved" } }) } },
      });
      ok("a soundness-review finding ONE unserved sweep component makes the epoch unproved, uncovered by its siblings",
        r.state === "unproved" && codesOf(r).includes("UNPROVED_QUERY_UNSERVED"));
      ok("a soundness-review finding the unproved reason names the unserved COMPONENT",
        r.reasons.some((x) => x.code === "UNPROVED_QUERY_UNSERVED" && x.recordKey.endsWith(":receipt")));
      ok("a soundness-review finding an unserved component nulls the height range", r.heightRange === null);
    }

    // 3: one component obtained under ANOTHER SCOPE refuses, and is never
    // combined with its in-scope siblings.
    {
      const otherScope = { ...SCOPE, poolId: "ee".repeat(32) };
      const r = evaluate(nonPayablePlan(), {
        header: servedHeader(),
        accruals: { [FUNDER_A]: servedAccrual({ amountCredits: "40" }) },
        accrualEnumeration: enumAcc([FUNDER_A]),
        dependents: { [FUNDER_A]: { machinerySweep: sweep({
          parts: { status: "served", proved: true, route: ROUTE, scope: otherScope, subjectAccrualId: PLANNED_A, height: "100", count: 0 },
        }) } },
      });
      ok("a soundness-review finding ONE out-of-scope sweep component refuses",
        r.state === "refused" && codesOf(r).includes("REFUSED_SCOPE_MISMATCH"));
      ok("a soundness-review finding the scope refusal names the offending COMPONENT",
        r.reasons.some((x) => x.code === "REFUSED_SCOPE_MISMATCH" && x.recordKey.endsWith(":parts")));
    }

    // 4: THE CASE THAT MOTIVATED THE FINDING. A payable row whose accrual is
    // proved absent at 150, with reservations observed at 100 (older than the
    // absence, genuinely out of publication order) and a receipt observed at 200
    // (newer, genuinely unresolved). Each must be judged on ITS OWN height, so
    // BOTH reasons appear. Before a soundness-review finding one height served both and whichever
    // was chosen produced one verdict for both record types.
    {
      const r = evaluate(mkPlan(), {
        header: servedHeader({}, { height: "150" }),
        accruals: { [FUNDER_A]: absent("150") },
        accrualEnumeration: enumAcc([], { height: "150" }),
        dependents: { [FUNDER_A]: { machinerySweep: sweep({
          reservation: { status: "served", proved: true, route: ROUTE, scope: SCOPE, subjectAccrualId: PLANNED_A, height: "100", count: 1 },
          receipt: { status: "served", proved: true, route: ROUTE, scope: SCOPE, subjectAccrualId: PLANNED_A, height: "200", count: 1 },
          parts: { status: "served", proved: true, route: ROUTE, scope: SCOPE, subjectAccrualId: PLANNED_A, height: "100", count: 0 },
        }) } },
      });
      ok("a soundness-review finding the OLDER positive component refuses as out of publication order",
        r.reasons.some((x) => x.code === "REFUSED_DEPENDENTS_WITHOUT_ACCRUAL" && x.recordKey.endsWith(":reservation")));
      ok("a soundness-review finding the LATER positive component is temporally unresolved, not refused",
        r.reasons.some((x) => x.code === "UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED" && x.recordKey.endsWith(":receipt")));
      ok("a soundness-review finding BOTH verdicts are retained; neither record type borrows the other's height",
        r.state === "refused");
    }
  }

  // ================= the module's own boundaries =================
  {
    ok("the plan refuses a payable self-share", (() => {
      try { mkPlan({ members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_A,
        effectiveCredits: "10", shareBps: 100, isSelfShare: true, payable: true }] }); return false; }
      catch (e) { return /never payable/.test(e.message); }
    })());
    ok("the plan refuses a memberCount disagreeing with its members", (() => {
      try { mkPlan({ header: { grossCredits: "1", feeCredits: "0", memberCount: 2, calcVersion: 1, allocationHash: AH } }); return false; }
      catch (e) { return /one fact/.test(e.message); }
    })());
    ok("a result is deeply frozen", (() => {
      const r = evaluate(mkPlan(), conformingEvidence());
      return Object.isFrozen(r) && Object.isFrozen(r.reasons) && (r.heightRange === null || Object.isFrozen(r.heightRange));
    })());
    ok("the snapshot refuses a hand-built result (only kernel results carry a state)", (() => {
      try { K.createSnapshot([{ kind: "tegara.e2.forwardResult.v1", epochIndex: 1, state: "complete" }], { generation: 0 }); return false; }
      catch (e) { return /hand-built/.test(e.message); }
    })());
    ok("a snapshot binds ONE pool and refuses a mix", (() => {
      const r1 = evaluate(mkPlan(), conformingEvidence());
      const r2 = note(K.unprovedPrecondition({ poolId: POOL2, epochIndex: 3,
        code: "UNPROVED_CARRY_UNSEEDED", diagnostic: "other pool" }));
      return throwsMatching(() => K.createSnapshot([r1, r2], { generation: 0 }), /two pools/);
    })());
    ok("an answer without a route is refused as input (provenance travels with every answer)", (() => {
      try {
        const a = servedHeader(); delete a.route;
        evaluate(mkPlan(), conformingEvidence({ header: a }));
        return false;
      } catch (e) { return /route must name the query/.test(e.message); }
    })());
    ok("a proved-absence answer from an unproved route is refused as input", (() => {
      try {
        evaluate(mkPlan(), conformingEvidence({ header: { status: "proved-absence", proved: false, route: ROUTE, height: "1", scope: SCOPE } }));
        return false;
      } catch (e) { return /an unproved read establishes no absence/.test(e.message); }
    })());
    ok("a served receipt with no execution verdict is refused as input (unchecked never means passed)", (() => {
      try {
        const deps = conformingDeps({ execution: null });
        evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: deps } }));
        return false;
      } catch (e) { return /unchecked never means passed/.test(e.message); }
    })());
  }

  // ================= review-found coverage, 2026-09-08 =================
  // Two constructions a repository-access review executed that NEITHER of the
  // two gates observing this region distinguished: the contract-to-code gate
  // sampled ONE coordinate of `scope` (poolId) and never OMITTED a component in
  // its independence probes, and this suite had no case for either, so the
  // reviewer's two mutants (now kernel battery M21 and M22) passed 140
  // assertions here and 79 gate checks. The class, for the fourth time on that
  // gate: a probe writes one instance of a property and claims the property.
  // So the cases here are enumerated over the fixture's own lists rather than
  // hand-picked: one differing value for EACH coordinate of the fixture's scope
  // on EACH component, and EACH component absent in EACH of two forms beside
  // EACH of its siblings positive. WIDTH, STATED: a finite set of substitutions
  // binds those substitutions, not unrestricted ownership, and the count lines
  // below are BOOKKEEPING over the local lists (they cannot see a component or a
  // coordinate the kernel adds); the coordinate count is pinned to the
  // contract's five by hand, and the component list to the manifest's three.
  {
    const plan = mkPlan({
      header: { grossCredits: "1000", feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH },
      members: [{ funderId: FUNDER_A, plannedAccrualId: PLANNED_A, effectiveCredits: "300",
        shareBps: 10000, isSelfShare: true, payable: false }],
    });
    const excluded = (machinerySweep) => evaluate(plan, {
      header: servedHeader(),
      accruals: { [FUNDER_A]: servedAccrual({ amountCredits: "300" }) },
      accrualEnumeration: enumAcc([FUNDER_A]),
      dependents: { [FUNDER_A]: { machinerySweep } },
    });
    const COMPONENTS = ["reservation", "receipt", "parts"];
    const keysOn = (r, c) => r.reasons.filter((x) => x.recordKey.endsWith(`:${c}`));
    const part = (over) => sweepPart({ count: 0, height: "100", scope: SCOPE, proved: true, subjectAccrualId: PLANNED_A, ...over });

    // (a) a component's WHOLE scope is its own. A kernel that borrowed a sibling's
    // chainId agreed with every probe that varied poolId alone.
    const coords = Object.keys(SCOPE);
    let scopeCases = 0;
    for (const c of COMPONENTS) {
      for (const k of coords) {
        const v = SCOPE[k];
        // ONE differing value per coordinate, chosen to pass validateScope
        // (which checks only poolId's hex form and epochIndex's integer form,
        // e2ForwardKernel.cjs:204-211), so the only thing the kernel can object
        // to is the comparison itself
        const differing = k === "poolId" ? "ee".repeat(32) : typeof v === "number" ? v + 1 : `${v}-other`;
        const r = excluded(sweep({ [c]: part({ scope: { ...SCOPE, [k]: differing } }) }));
        scopeCases += 1;
        ok(`scope: ${c} with only ${k} differing refuses on ${c} alone`,
          r.state === "refused"
          && keysOn(r, c).some((x) => x.code === "REFUSED_SCOPE_MISMATCH")
          && COMPONENTS.filter((o) => o !== c).every((o) => keysOn(r, o).length === 0));
      }
    }
    ok(`scope bookkeeping: one value per coordinate was driven on every component (${scopeCases} of ${coords.length * COMPONENTS.length}; the fixture has ${coords.length} coordinates, the contract five)`,
      scopeCases === coords.length * COMPONENTS.length && coords.length === 5);

    // (b) an ABSENT component does not suppress a sibling's observation, tested
    // with EACH other sibling positive in turn. The absent arm returns a result
    // rather than throwing, and an early return placed in it was invisible to
    // probes that always supplied every component. A pre-commit check of the
    // first cut found it paired each absent component with ONE sibling (a cyclic
    // choice), so a kernel that skipped parts whenever reservation was absent
    // passed all six; every pair is driven now.
    let absentCases = 0;
    for (const c of COMPONENTS) {
      for (const sibling of COMPONENTS.filter((o) => o !== c)) {
        for (const form of ["omitted", "null"]) {
          const sw = sweep({ [sibling]: part({ count: 5 }) });
          if (form === "omitted") delete sw[c]; else sw[c] = null;
          const r = excluded(sw);
          absentCases += 1;
          ok(`independence: ${c} ${form} does not suppress the positive ${sibling}`,
            r.state === "refused"
            && keysOn(r, c).some((x) => x.code === "UNPROVED_QUERY_UNSERVED")
            && keysOn(r, sibling).some((x) => x.code === "REFUSED_MACHINERY_UNDER_EXCLUDED_ROW"));
        }
      }
    }
    ok(`independence bookkeeping: every component was absent in both forms beside each sibling (${absentCases} of ${COMPONENTS.length * (COMPONENTS.length - 1) * 2})`,
      absentCases === COMPONENTS.length * (COMPONENTS.length - 1) * 2 && COMPONENTS.length === 3);
  }

  // ================= the manifest =================
  {
    const missingCases = MATRIX_CASES.filter((c) => !covered.has(c));
    ok(`every acceptance-matrix case has an executed test (${covered.size}/${MATRIX_CASES.length})`, missingCases.length === 0);
    if (missingCases.length) console.log(`        missing: ${missingCases.join(", ")}`);
    const allCodes = [...Object.keys(K.REASONS), ...K.PROJECTION_CODES];
    const unseen = allCodes.filter((c) => !codesSeen.has(c));
    ok(`every reason and projection code is observed at least once (${codesSeen.size}/${allCodes.length})`, unseen.length === 0);
    if (unseen.length) console.log(`        unseen: ${unseen.join(", ")}`);
  }

  // ---- THE EXECUTION VERDICT IS NOT EVALUATED OVER UNRESOLVED EVIDENCE (the per-epoch
  // context design, revision 5: the named result for unserved evidence). A served receipt
  // whose part set or pinned reservation read was not served is an UNPROVED situation; the
  // verdict, whatever it says, is deferred and recorded as an observation, never turned into
  // REFUSED_TRANSFER_UNVERIFIED. Acquisition marks such a verdict EVIDENCE-UNRESOLVED
  // without calling the verifier; a real negative verdict over the same evidence is deferred
  // the same way, because precedence would otherwise let a refusal hide the unproved read. ----
  {
    const deferredCodes = (r) => codesOf(r).filter((c) => c === "REFUSED_TRANSFER_UNVERIFIED" || c === "REFUSED_PART_MISMATCH");
    const marker = { label: "EVIDENCE-UNRESOLVED", requested: false, reason: "the parts read was unserved" };
    // U2 runs FIRST: with the deferral removed, U1's marker fixture trips the marker guard
    // and ends the run before an assertion, while U2's real negative verdict fails its own
    // assertion, which is what the battery's M23 must observe
    const r2 = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: conformingDeps({ partSet: unverified(), execution: { label: "REFUSED", reason: "parts-incomplete-for-verification" } }) } }));
    ok(`U2: a REAL negative verdict over an UNVERIFIED part set is deferred too, the state unproved not refused (${r2.state})`,
      r2.state === "unproved" && codesOf(r2).includes("UNPROVED_PROOF_UNVERIFIED") && deferredCodes(r2).length === 0
      && r2.observations.some((o) => o.kind === "execution-verdict-deferred"));
    const r1 = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: conformingDeps({ partSet: unserved(), execution: marker }) } }));
    ok(`U1: a served receipt over an UNSERVED part set with the acquisition marker is unproved, the verdict deferred as an observation carrying its label (${r1.state}: ${codesOf(r1).join(",")})`,
      r1.state === "unproved" && codesOf(r1).includes("UNPROVED_QUERY_UNSERVED") && deferredCodes(r1).length === 0
      && r1.observations.some((o) => o.kind === "execution-verdict-deferred" && o.recordKey === `receipt:${FUNDER_A.slice(0, 8)}` && o.label === "EVIDENCE-UNRESOLVED"));
    const r3 = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: conformingDeps({ reservationPinned: unserved(), execution: marker }) } }));
    ok(`U3: a served receipt over an UNSERVED pinned reservation with the marker is unproved, the verdict deferred (${r3.state})`,
      r3.state === "unproved" && deferredCodes(r3).length === 0 && r3.observations.some((o) => o.kind === "execution-verdict-deferred"));
    // U4 isolates the marker branch: the SAME fixture without the marker completes, so the
    // refusal below comes from the marker beside resolved reads and from nothing else
    const r4c = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: conformingDeps() } }));
    let threw = null;
    try { evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: conformingDeps({ execution: marker }) } })); }
    catch (e) { threw = e.message; }
    ok(`U4: the marker beside RESOLVED parts and reservation is a contract violation and refuses hard, on a fixture that completes without it (${threw ? threw.slice(0, 70) : "no throw"}; control ${r4c.state})`,
      r4c.state === "complete" && threw !== null && /EVIDENCE-UNRESOLVED/.test(threw) && /unchecked never means passed/.test(threw));
    const r6 = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: conformingDeps({ reservationPinned: unverified(), execution: marker }) } }));
    ok(`U6: an UNVERIFIED pinned reservation defers the verdict too (${r6.state}: ${codesOf(r6).join(",")})`,
      r6.state === "unproved" && codesOf(r6).includes("UNPROVED_PROOF_UNVERIFIED") && deferredCodes(r6).length === 0 && r6.observations.some((o) => o.kind === "execution-verdict-deferred"));
    const r7 = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: conformingDeps({ partSet: { ...conformingDeps().partSet, proved: false }, execution: marker }) } }));
    ok(`U7: a part enumeration from an UNPROVED ROUTE defers the verdict (${r7.state}: ${codesOf(r7).join(",")})`,
      r7.state === "unproved" && codesOf(r7).includes("UNPROVED_ROUTE_NOT_PROVED") && deferredCodes(r7).length === 0 && r7.observations.some((o) => o.kind === "execution-verdict-deferred"));
    const r9 = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: conformingDeps({ partSet: unserved(), reservationPinned: unverified(), execution: marker }) } }));
    ok(`U9: BOTH the part set and the pinned reservation unresolved at once defer the verdict exactly once and the state is unproved (${r9.state}: ${codesOf(r9).join(",")})`,
      r9.state === "unproved" && codesOf(r9).includes("UNPROVED_QUERY_UNSERVED") && codesOf(r9).includes("UNPROVED_PROOF_UNVERIFIED")
      && deferredCodes(r9).length === 0 && r9.observations.filter((o) => o.kind === "execution-verdict-deferred").length === 1);
    let threw8 = null;
    try { evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: conformingDeps({ partSet: unserved(), execution: { ...marker, requested: true } }) } })); }
    catch (e) { threw8 = e.message; }
    ok(`U8: a marker that does not state requested: false is refused hard even beside unresolved reads (${threw8 ? threw8.slice(0, 60) : "no throw"})`,
      threw8 !== null && /requested: false/.test(threw8));
    const r5 = evaluate(mkPlan(), conformingEvidence({ dependents: { [FUNDER_A]: conformingDeps({ execution: { label: "READ-CHECKED", reason: "no capture" } }) } }));
    ok("U5: over RESOLVED evidence a negative verdict still refuses (the deferral is not a widening)",
      r5.state === "refused" && codesOf(r5).includes("REFUSED_TRANSFER_UNVERIFIED") && !r5.observations.some((o) => o.kind === "execution-verdict-deferred"));
  }

  // ---- STEP 3 of the per-epoch context design (contract revision 16): the fourth
  // precondition code, for an epoch object that is PRESENT but consumed unproved while C1 is
  // open, and the snapshot's GENERATION, an integer from zero the orchestrator numbers each
  // refresh with and the projection is bound to ----
  {
    ok("S3: UNPROVED_EPOCH_OBJECT_UNPROVED is a precondition code and an unproved reason",
      K.PRECONDITION_CODES.includes("UNPROVED_EPOCH_OBJECT_UNPROVED") && K.REASONS.UNPROVED_EPOCH_OBJECT_UNPROVED === "unproved");
    let r = null, threw = null;
    try {
      r = note(K.unprovedPrecondition({ poolId: POOL, epochIndex: EPOCH, code: "UNPROVED_EPOCH_OBJECT_UNPROVED",
        diagnostic: "the epoch object was served over a route that obtains no proof while C1 is open" }));
    } catch (e) { threw = e.message; }
    ok(`S3: a present-but-unproved epoch object is an unproved precondition result, distinct from the absent one (${r ? r.state : `threw: ${threw}`})`,
      r !== null && r.state === "unproved" && codesOf(r).join() === "UNPROVED_EPOCH_OBJECT_UNPROVED" && r.heightRange === null);
    if (r) {
      const snap = K.createSnapshot([r], { generation: 0 });
      ok("S3: it refuses projection by name (the orchestrator's duty not to build a plan from an unproved figure is step 4's, tested there)", throwsCode(() => K.projectForWriter(snap, EPOCH), "PROJECTION_STATE_UNPROVED"));
    }
    // the generation
    const good = evaluate(mkPlan(), conformingEvidence());
    const s0 = K.createSnapshot([good], { generation: 0 });
    const s7 = K.createSnapshot([good], { generation: 7 });
    ok(`S3: the snapshot carries the generation it was created with, frozen (${s0.generation}, ${s7.generation})`,
      s0.generation === 0 && s7.generation === 7 && Object.isFrozen(s0) && s0 !== s7
      && K.projectForWriter(s0, EPOCH) === true && K.projectForWriter(s7, EPOCH) === true);
    // each malformed shape carries an OTHERWISE VALID generation where the shape is the
    // point, so the refusal is attributable to that shape and not to a missing number (the
    // pre-commit checker's construction); a bigint and a cyclic object are refused by the
    // NAMED refusal, never by a serializer's own error
    const cyclic = {}; cyclic.self = cyclic;
    const cases = [
      ["no options", undefined, /options/],
      ["an empty options object", {}, /own data member generation/],
      ["a negative generation", { generation: -1 }, /non-negative safe-integer generation \(got a value of type number\)/],
      ["a fractional generation", { generation: 1.5 }, /type number/],
      ["a string generation", { generation: "0" }, /type string/],
      ["a bigint generation", { generation: 0n }, /type bigint/],
      ["a cyclic-object generation", { generation: cyclic }, /type object/],
      // THE WIDTH OF "PLAIN" HERE IS THE KERNEL'S OWN PREDICATE: an object that is not an array.
      // A null-prototype object and a class instance carrying an OWN data generation are both
      // accepted (asserted below, so the width is stated and not assumed); an array and a
      // non-object are refused, each carrying a valid generation so the refusal is
      // attributable to the shape alone. The hazard the boundary exists for, an inherited or
      // computed generation, is closed by the own-data-descriptor read whatever the prototype.
      ["an array options object carrying a valid generation", Object.assign([], { generation: 0 }), /plain options object/],
      ["a string in place of the options object", "generation", /plain options object/],
      ["a generation INHERITED through the prototype", Object.create({ generation: 0 }), /own data member generation/],
      ["a generation supplied by an accessor", Object.defineProperty({}, "generation", { get: () => 0, enumerable: true }), /own data member generation/],
    ];
    for (const [what, opts, re] of cases) {
      let t = null;
      try { K.createSnapshot([good], opts); } catch (e) { t = e.message; }
      ok(`S3: createSnapshot with ${what} is refused by the named refusal (${t ? t.slice(0, 70) : "no throw"})`, t !== null && /createSnapshot/.test(t) && re.test(t));
    }
    // THE SAFE-INTEGER BOUNDARY, bound at its edge (the round's F1): the maximum safe integer is
    // accepted and the next integer is refused by the named refusal, so an implementation that
    // widened to any integer is caught
    const sMax = K.createSnapshot([good], { generation: Number.MAX_SAFE_INTEGER });
    let tOver = null;
    try { K.createSnapshot([good], { generation: Number.MAX_SAFE_INTEGER + 1 }); } catch (e) { tOver = e.message; }
    ok(`S3 boundary: the maximum safe integer is accepted and the next integer is refused by the named refusal (${tOver ? tOver.slice(0, 60) : "no throw"})`,
      sMax.generation === Number.MAX_SAFE_INTEGER && tOver !== null && /non-negative safe-integer generation/.test(tOver));
    // THE GETTER IS NEVER INVOKED (the round's F2): an own accessor and an inherited accessor are
    // each refused with their call count still zero, and an own data member SHADOWING an
    // inherited accessor is accepted without the inherited getter running
    let ownCalls = 0, inheritedCalls = 0;
    const ownAccessor = Object.defineProperty({}, "generation", { get: () => { ownCalls += 1; return 0; }, enumerable: true });
    const inheritedProto = Object.defineProperty({}, "generation", { get: () => { inheritedCalls += 1; return 0; }, enumerable: true });
    let tOwn = null, tInh = null;
    try { K.createSnapshot([good], ownAccessor); } catch (e) { tOwn = e.message; }
    try { K.createSnapshot([good], Object.create(inheritedProto)); } catch (e) { tInh = e.message; }
    ok(`S3 getters: an own accessor and an inherited accessor are each refused by name with ZERO invocations (own ${ownCalls}, inherited ${inheritedCalls})`,
      tOwn !== null && /own data member generation/.test(tOwn) && tInh !== null && /own data member generation/.test(tInh) && ownCalls === 0 && inheritedCalls === 0);
    const shadowed = Object.create(inheritedProto);
    Object.defineProperty(shadowed, "generation", { value: 5, enumerable: true, writable: true, configurable: true });
    const sShadow = K.createSnapshot([good], shadowed);
    ok(`S3 getters: an own data member shadowing an inherited accessor is accepted and the inherited getter never runs (inherited ${inheritedCalls})`,
      sShadow.generation === 5 && inheritedCalls === 0);
    const sNull = K.createSnapshot([good], Object.assign(Object.create(null), { generation: 3 }));
    const sInst = K.createSnapshot([good], Object.assign(new (class Opts {})(), { generation: 4 }));
    ok("S3 width: a null-prototype object and a class instance carrying an OWN data generation are accepted by the kernel's plain predicate (an object that is not an array), stated rather than assumed",
      sNull.generation === 3 && sInst.generation === 4);
  }

  console.log(`\ne2ForwardKernelTest: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exitCode = 1;
};

main().catch((e) => { console.error(`e2ForwardKernelTest: unexpected throw: ${e.message}`); process.exitCode = 1; });
