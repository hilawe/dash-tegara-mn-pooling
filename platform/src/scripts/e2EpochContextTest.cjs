/**
 * e2EpochContextTest: the per-epoch context module (step 4), driven OFFLINE against the REAL
 * kernel, the REAL carry-capable row source, the REAL identifier helper with the INSTALLED
 * generator, and the REAL receipt verifier over the verifier test's mock pipeline, with a fake
 * formation resolution and NO LEDGER-READ ADAPTER (the injected functions are the identifier
 * generator, the capture lookup, the verifier's mock pipeline and the capture-basis adapter): the independence property (design
 * section 3, "computed before any epoch-record query is issued and from no epoch-record
 * document") holds for this fixture by its shape, and the module's literal require spellings
 * are checked against a fixed list, a textual check and not a proof.
 *
 * THE EXPECTATIONS ARE DERIVED INDEPENDENTLY of the module where they can be: the owed amounts
 * from the allocation and the figures by arithmetic (a distributable amount every bps row
 * divides exactly, so any remainder rule agrees), the carry from the pinned minimum, and the
 * kernel's verdicts from its own evaluator over hand-built evidence; the planned identifiers
 * are checked against e2DocId over the same inputs, which binds the composition and not the
 * identifier's correctness (step 3c's byte-identity test carries that).
 */
"use strict";
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");
const X = require("./e2EpochContext.cjs");
const K = require("./e2ForwardKernel.cjs");
const D = require("./e2DocId.cjs");
const formationCore = require("./formationCore.cjs");
const entitlementCalc = require("./entitlementCalc.cjs");
const { canonicalString } = require("./canonicalJson.cjs");
const { PART_BOUND_B } = require("./e2ReceiptVerify.cjs");
const { MIN_TRANSFER_AMOUNT_CREDITS } = require("./e2Journal.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) { passed++; console.log(`  PASS: ${name}`); } else { failed++; console.error(`  FAIL: ${name}`); } };
const throws = (name, fn, re) => {
  let t = null;
  try { fn(); } catch (e) { t = e.message; }
  ok(`${name} (${t ? t.slice(0, 90) : "no throw"})`, t !== null && /e2EpochContext/.test(t) && re.test(t));
};
const rejects = async (name, p, re) => {
  let t = null;
  try { await p; } catch (e) { t = e.message; }
  ok(`${name} (${t ? t.slice(0, 90) : "no throw"})`, t !== null && re.test(t));
};

// ---- the fixture: one pool, three owners, the income identity's own row among them ----
const h = (f) => f.repeat(64 / f.length);
const POOL = h("5779");
const A = h("aa11"), B = h("bb22"), C = h("cc33");   // A is the income identity
const CONTRACT_B58 = "8sVj3E2yqQtV3f5mHdq2vG6x7PhZyM2QPZbYjVSNv9L";
const OWNER_B58 = "5jLZJF4RurvAkahXhLLHHgBisEDgs58v8AmP8w7cMqe";
const CONTRACT_HEX = formationCore.toId32(CONTRACT_B58).toString("hex");
const CHAIN = "tegara-test-1";
const AH = h("a10c");
const ALLOCATION = [{ recipientId: A, bps: 5000 }, { recipientId: B, bps: 4990 }, { recipientId: C, bps: 10 }];
const GROSS = "2000000", FEE = "0";             // D = 2,000,000: 1,000,000 / 998,000 / 2,000 exactly
const OWED = { [A]: 1000000n, [B]: 998000n, [C]: 2000n };
const scopeFor = (epochIndex) => ({ contractId: CONTRACT_HEX, chainId: CHAIN, contractVersion: 11, poolId: POOL, epochIndex });
const formation = () => ({ resolved: true, incomeIdentity: A, allocationHash: AH,
  allocation: ALLOCATION.map((a) => ({ ...a })) });
const journaled = (number, gross = GROSS, fee = FEE) => ({ number, grossCredits: gross, feeCredits: fee,
  distributableCredits: String(BigInt(gross) - BigInt(fee)), allocationHash: AH, memberCount: 3 });
const mutable = (o) => JSON.parse(JSON.stringify(o));

const main = async () => {
  console.log("e2EpochContextTest");
  ok(`the pinned minimum is ${MIN_TRANSFER_AMOUNT_CREDITS} so C's owed 2000 is below it and B's 998000 above it (the fixture's premise)`,
    OWED[C] < MIN_TRANSFER_AMOUNT_CREDITS && OWED[B] >= MIN_TRANSFER_AMOUNT_CREDITS && OWED[A] >= MIN_TRANSFER_AMOUNT_CREDITS);
  const root = process.env.TEGARA_PLATFORM_ROOT || path.resolve(__dirname, "../..");
  const dpp = await import(pathToFileURL(require.resolve("pshenmic-dpp", { paths: [root] })).href);
  const generateId = (...a) => dpp.DocumentWASM.generateId(...a);
  ok("the installed generator is a function (the planned-identifier agreement below needs it, and an unperformed check never passes)", typeof dpp.DocumentWASM.generateId === "function");
  const identifiers = () => ({ generateId, ownerId: OWNER_B58, contractId: CONTRACT_B58 });
  const plannedIdOf = (epochIndex, funderId) => D.docIdForIn({ generateId, ownerId: OWNER_B58, contractId: CONTRACT_B58,
    poolId: POOL, epochIndex, type: "platformAccrual", subject: funderId }).hex;
  const build = (over = {}) => X.buildEpochContext({ scope: scopeFor(0), formation: formation(), journalRun: [journaled(0)],
    configuredStart: 0, declaredFigures: null, identifiers: identifiers(), ...over });

  // ---- THE INDEPENDENCE PROPERTY, as a check on the module's imports ----
  {
    const src = fs.readFileSync(path.join(__dirname, "e2EpochContext.cjs"), "utf8");
    const required = [...src.matchAll(/require\(["']([^"']+)["']\)/g)].map((m) => m[1]).sort();
    ok(`the module's literal require(...) spellings name exactly the row source, the identifier helper, formationCore and the receipt verifier (a textual check of imports, not a proof of independence, which the fixture's shape carries: no ledger-read adapter exists in this test) (${required.join(", ")})`,
      required.join(",") === "./e2DocId.cjs,./e2ReceiptVerify.cjs,./entitlementCalc.cjs,./formationCore.cjs");
  }

  // ---- 1. a journaled epoch: figures from the journal, rows from the partition ----
  let ctx0;
  {
    ctx0 = build();
    ok("journaled: figuresSource is journaled-header and the figures are the journal's, with memberCount from the allocation and allocationHash from the formation",
      ctx0.figuresSource === "journaled-header" && ctx0.figures.grossCredits === GROSS && ctx0.figures.feeCredits === FEE
      && ctx0.figures.memberCount === 3 && ctx0.figures.calcVersion === 1 && ctx0.figures.allocationHash === AH
      && ctx0.precondition === null && ctx0.encodingRefused === false && ctx0.kind === X.KIND);
    const rows = ctx0.rows;
    ok("journaled: the rows are in allocation order with the independently computed effective amounts and no carry-in at the configured start",
      rows.length === 3 && rows.map((r) => r.funderId).join() === [A, B, C].join()
      && rows.every((r) => r.effectiveCredits === String(OWED[r.funderId]) && !("carryInCredits" in r)));
    ok("journaled: isSelfShare and payable are the partition's answers (A self-share not payable, B payable, C below the minimum not payable)",
      rows[0].isSelfShare === true && rows[0].payable === false
      && rows[1].isSelfShare === false && rows[1].payable === true
      && rows[2].isSelfShare === false && rows[2].payable === false);
    ok("journaled: shareBps is each allocation row's", rows.map((r) => r.shareBps).join() === "5000,4990,10");
    ok("journaled: every plannedAccrualId equals e2DocId's derivation over the same pool, epoch, type and funder with the installed generator",
      rows.every((r) => r.plannedAccrualId === plannedIdOf(0, r.funderId)) && new Set(rows.map((r) => r.plannedAccrualId)).size === 3);
    ok("the context is deep-frozen, its scope, formation, rows and figures included", Object.isFrozen(ctx0) && Object.isFrozen(ctx0.scope) && Object.isFrozen(ctx0.formation) && Object.isFrozen(ctx0.rows) && Object.isFrozen(ctx0.rows[1]) && Object.isFrozen(ctx0.formation.allocation) && Object.isFrozen(ctx0.formation.allocation[0]) && Object.isFrozen(ctx0.figures));
    // ---- the plan input, through the real kernel ----
    const pi = X.planInputOf(ctx0);
    const plan = K.buildExpectedRecordPlan(pi);
    ok("planInputOf: the real kernel accepts the input; the plan header equals the FORMATION's hash and count (never a served header's) and the figures",
      plan.encodingRefused === false && plan.header.allocationHash === AH && plan.header.memberCount === 3
      && plan.header.grossCredits === GROSS && plan.header.feeCredits === FEE && plan.scope.poolId === POOL && plan.scope.epochIndex === 0);
    ok("planInputOf: the kernel classifies from the rows' partition answers (self-share, payable, below-minimum)",
      plan.members.map((m) => m.classification).join() === "self-share,payable,below-minimum"
      && plan.members.every((m, i) => m.plannedAccrualId === rows[i].plannedAccrualId && m.effectiveCredits === rows[i].effectiveCredits));
    const p1 = X.planInputOf(ctx0);
    let edited = false;
    try { p1.members[1].payable = false; p1.header.grossCredits = "1"; p1.scope.chainId = "edited"; edited = p1.members[1].payable === false && p1.scope.chainId === "edited"; } catch { edited = false; }
    const p2 = X.planInputOf(ctx0);
    ok("planInputOf: each call answers a FRESH mutable object (scope, header and members), so a caller's edit reaches neither the context nor the next call",
      edited && p2.members[1].payable === true && p2.header.grossCredits === GROSS && p2.scope.chainId === CHAIN && ctx0.scope.chainId === CHAIN && ctx0.rows[1].payable === true
      && p1 !== p2 && p1.members !== p2.members && p1.scope !== ctx0.scope && p1.scope !== p2.scope && p1.header !== p2.header && p1.members[1] !== p2.members[1]
      && p1.scope.chainId === "edited" && p1.header.grossCredits === "1" && p1.members[1].payable === false);
  }

  // ---- 2. a declared fresh epoch: appended to the run, the carry reaches it ----
  let ctx1;
  {
    ctx1 = build({ scope: scopeFor(1), declaredFigures: { grossCredits: GROSS, feeCredits: FEE } });
    ok("declared: figuresSource is declared-fixture and the figures are the fixture's",
      ctx1.figuresSource === "declared-fixture" && ctx1.figures.grossCredits === GROSS && ctx1.precondition === null && ctx1.encodingRefused === false);
    const r = ctx1.rows;
    ok("declared: C's epoch-0 owed amount carries into epoch 1 (carryInCredits 2000, effective 4000, still below the minimum), A and B carry nothing",
      r[2].carryInCredits === "2000" && r[2].effectiveCredits === "4000" && r[2].payable === false
      && !("carryInCredits" in r[0]) && !("carryInCredits" in r[1]) && r[1].effectiveCredits === "998000" && r[1].payable === true);
    {
      // a NONZERO fee and figures that differ from epoch 0's: D = 1,900,000 splits to 950,000 / 948,100 / 1,900 exactly
      const c = build({ scope: scopeFor(1), declaredFigures: { grossCredits: "2000000", feeCredits: "100000" } });
      ok("declared with a nonzero fee and figures differing from epoch 0's: the fee is carried on the context, the split uses THIS epoch's distributable, and C's carry-in is epoch 0's owed amount",
        c.figures.feeCredits === "100000" && c.figures.grossCredits === "2000000" && c.rows[0].effectiveCredits === "950000" && c.rows[1].effectiveCredits === "948100"
        && c.rows[2].effectiveCredits === "3900" && c.rows[2].carryInCredits === "2000" && K.buildExpectedRecordPlan(X.planInputOf(c)).header.feeCredits === "100000");
    }
    ok("declared: the planned identifiers are derived for THIS epoch (they differ from epoch 0's and equal the helper's for epoch 1)",
      r.every((x) => x.plannedAccrualId === plannedIdOf(1, x.funderId) && x.plannedAccrualId !== plannedIdOf(0, x.funderId)));
    const plan = K.buildExpectedRecordPlan(X.planInputOf(ctx1));
    ok("declared: the kernel builds the epoch-1 plan with the carried row classified below-minimum", plan.members[2].classification === "below-minimum" && plan.scope.epochIndex === 1);
    ok("journaled beside an AGREEING fixture is journaled-header",
      build({ declaredFigures: { grossCredits: GROSS, feeCredits: FEE } }).figuresSource === "journaled-header");
    ok("a journaled run reaching beyond the epoch still answers the epoch from the run (epoch 0 of a two-epoch run)",
      build({ journalRun: [journaled(0), journaled(1)] }).rows[2].effectiveCredits === "2000");
  }

  // ---- 3. the figures are refused, never chosen ----
  throws("journaled and declared figures disagreeing on gross refuse by name",
    () => build({ journalRun: [journaled(0, "1000", "10")], declaredFigures: { grossCredits: "1100", feeCredits: "10" } }), /must agree field by field.*never a choice/);
  throws("journaled and declared figures agreeing on the derived distributable amount but not on fee refuse (1000/10 against 1100/110)",
    () => build({ journalRun: [journaled(0, "1000", "10")], declaredFigures: { grossCredits: "1100", feeCredits: "110" } }), /must agree field by field/);
  throws("a journaled header whose allocationHash differs from the proved formation's refuses",
    () => build({ journalRun: [{ ...journaled(0), allocationHash: h("beef") }] }), /allocationHash .* while the proved formation's recomputed hash/);
  throws("a journaled header whose memberCount differs from the allocation's row count refuses",
    () => build({ journalRun: [{ ...journaled(0), memberCount: 2 }] }), /memberCount 2 while the proved formation's allocation has 3 rows/);
  throws("a declared epoch that does not immediately follow the journaled run refuses (journal [0], epoch 2)",
    () => build({ scope: scopeFor(2), declaredFigures: { grossCredits: GROSS, feeCredits: FEE } }), /does not immediately follow the journaled run's last epoch 0/);
  throws("a declared epoch over an empty run that is not the configured start refuses",
    () => build({ scope: scopeFor(1), journalRun: [], declaredFigures: { grossCredits: GROSS, feeCredits: FEE } }), /empty journaled run whose configured start is 0/);
  throws("declared fee above gross refuses", () => build({ scope: scopeFor(1), declaredFigures: { grossCredits: "10", feeCredits: "11" } }), /feeCredits above grossCredits/);
  throws("a non-canonical declared gross refuses", () => build({ scope: scopeFor(1), declaredFigures: { grossCredits: "0100", feeCredits: "0" } }), /canonical decimal string/);
  throws("a numeric declared gross refuses", () => build({ scope: scopeFor(1), declaredFigures: { grossCredits: 100, feeCredits: "0" } }), /canonical decimal string/);
  throws("a journal entry whose distributable is not gross minus fee refuses", () => build({ journalRun: [{ ...journaled(0), distributableCredits: "1" }] }), /not grossCredits minus feeCredits/);
  throws("the same epoch journaled twice refuses", () => build({ journalRun: [journaled(0), journaled(0)] }), /carries epoch 0 twice/);
  throws("the same epoch journaled twice refuses even when the requested epoch is another (the whole run is checked before the figures rule)", () => build({ scope: scopeFor(1), journalRun: [journaled(0), journaled(0)] }), /carries epoch 0 twice/);
  throws("an EARLIER journaled epoch whose allocationHash differs from the formation's refuses (the whole run enters the carry under one allocation)",
    () => build({ scope: scopeFor(1), journalRun: [{ ...journaled(0), allocationHash: h("beef") }], declaredFigures: { grossCredits: GROSS, feeCredits: FEE } }), /epoch 0's journaled header carries allocationHash/);
  throws("a THIRD journaled entry whose allocationHash differs refuses (the whole run, not a prefix of it)",
    () => build({ scope: scopeFor(3), journalRun: [journaled(0), journaled(1), { ...journaled(2), allocationHash: h("beef") }], declaredFigures: { grossCredits: GROSS, feeCredits: FEE } }), /epoch 2's journaled header carries allocationHash/);
  throws("an earlier journaled epoch whose memberCount is LARGER than the allocation's refuses (4 beside 3)",
    () => build({ scope: scopeFor(1), journalRun: [{ ...journaled(0), memberCount: 4 }], declaredFigures: { grossCredits: GROSS, feeCredits: FEE } }), /memberCount 4 while the proved formation's allocation has 3 rows/);
  throws("journaled and declared figures with the SAME gross and a different fee refuse", () => build({ declaredFigures: { grossCredits: GROSS, feeCredits: "1" } }), /must agree field by field/);
  throws("an own undefined declaredFigures refuses (the domain is null or a fixture)", () => build({ declaredFigures: undefined }), /undefined is a value nobody set/);
  ok("a declared epoch over an empty run AT the configured start builds (bootstrap)",
    build({ journalRun: [], declaredFigures: { grossCredits: GROSS, feeCredits: FEE } }).figuresSource === "declared-fixture");
  {
    let c = null, cErr = null;
    try { c = build({ scope: scopeFor(5), journalRun: [], configuredStart: 5, declaredFigures: { grossCredits: GROSS, feeCredits: FEE } }); } catch (e) { cErr = e.message; }
    ok(`a nonzero configured start is forwarded to the row source (epoch 5 over an empty run with the start at 5 builds, no carry-in)${cErr ? ` (threw: ${cErr.slice(0, 70)})` : ""}`,
      c !== null && c.figuresSource === "declared-fixture" && c.rows[1].effectiveCredits === "998000" && !("carryInCredits" in c.rows[2]) && c.rows[2].plannedAccrualId === plannedIdOf(5, C));
    const j = build({ journalRun: [journaled(0, "2000000", "100000")] });
    ok("a journaled nonzero fee is the context's and the plan's fee, with the rows split from the journaled distributable",
      j.figuresSource === "journaled-header" && j.figures.feeCredits === "100000" && j.rows[0].effectiveCredits === "950000"
      && K.buildExpectedRecordPlan(X.planInputOf(j)).header.feeCredits === "100000");
  }

  // ---- 4. the fresh-epoch precondition (section 4, rule 2) ----
  {
    const ctxP = build({ scope: scopeFor(1) });
    ok("a fresh epoch with no fixture carries UNPROVED_EPOCH_OBJECT_UNPROVED with a diagnostic naming C1, the provenance label, no figures and no rows",
      ctxP.precondition !== null && ctxP.precondition.code === "UNPROVED_EPOCH_OBJECT_UNPROVED" && /C1/.test(ctxP.precondition.diagnostic)
      && ctxP.figuresSource === "epoch-object-unproved-c1"
      && ctxP.figures === null && ctxP.rows === null && ctxP.encodingRefused === null && Object.isFrozen(ctxP) && Object.isFrozen(ctxP.scope) && Object.isFrozen(ctxP.formation.allocation[0]) && Object.isFrozen(ctxP.precondition));
    throws("planInputOf refuses a precondition context by name, so no plan is built from an unproved figure",
      () => X.planInputOf(ctxP), /precondition UNPROVED_EPOCH_OBJECT_UNPROVED and reaches no plan builder/);
    throws("executionVerdictFor refuses a precondition context (no plan, no verdict owed)",
      () => X.executionVerdictFor(ctxP, { captureFor: () => null, deps: { verifierDeps: {}, verifyCaptureBasis: async () => true } }), /precondition context/);
    const result = K.unprovedPrecondition({ poolId: ctxP.scope.poolId, epochIndex: ctxP.scope.epochIndex, ...ctxP.precondition });
    const snap = K.createSnapshot([result], { generation: 0 });
    let t = null; try { K.projectForWriter(snap, 1); } catch (e) { t = e.message; }
    ok("the kernel accepts the context's precondition as its result and the projection refuses epoch 1 by name (PROJECTION_STATE_UNPROVED naming the code)",
      result.state === "unproved" && t !== null && /PROJECTION_STATE_UNPROVED/.test(t) && /UNPROVED_EPOCH_OBJECT_UNPROVED/.test(t));
    ok("an empty run with no fixture is the same precondition at the configured start",
      build({ journalRun: [] }).precondition.code === "UNPROVED_EPOCH_OBJECT_UNPROVED");
  }

  // ---- 5. an encoding-refused epoch ----
  {
    const C = entitlementCalc.SCHEMA_CREDIT_CEILING;
    let ctxR = null, buildErr = null;
    try { ctxR = build({ journalRun: [], declaredFigures: { grossCredits: String(2n * C + 2n), feeCredits: "0" } }); } catch (e) { buildErr = e.message; }
    ok(`a declared gross whose owed amounts exceed the schema ceiling yields encodingRefused with rows carrying identity, bps, self-share and the planned identifier only${buildErr ? ` (threw: ${buildErr.slice(0, 80)})` : ""}`,
      ctxR !== null && ctxR.encodingRefused === true && ctxR.precondition === null && ctxR.figuresSource === "declared-fixture"
      && ctxR.rows.length === 3 && ctxR.rows.every((r) => !("effectiveCredits" in r) && !("payable" in r) && r.plannedAccrualId === plannedIdOf(0, r.funderId))
      && ctxR.rows[0].isSelfShare === true && ctxR.rows[1].isSelfShare === false && ctxR.rows[0].shareBps === 5000);
    if (ctxR === null) ctxR = build();   // keep the section running so every later case reports
    let pi = null, plan = null, planErr = null;
    try { pi = X.planInputOf(ctxR); plan = K.buildExpectedRecordPlan(pi); } catch (e) { planErr = e.message; }
    ok(`planInputOf: an encoding-refused plan input has no header, and the kernel builds it with every member's planned identifier${planErr ? ` (threw: ${planErr.slice(0, 80)})` : ""}`,
      plan !== null && pi.header === null && pi.encodingRefused === true && plan.encodingRefused && plan.header === null
      && plan.members.map((m) => m.plannedAccrualId).join() === ctxR.rows.map((r) => r.plannedAccrualId).join());
    if (plan === null) plan = K.buildExpectedRecordPlan({ ...X.planInputOf(build()), encodingRefused: true, header: null });
    const S = plan.scope;
    const absent = () => ({ status: "proved-absence", proved: true, route: "r", height: "100", scope: S });
    const sweepPart = (subjectAccrualId) => ({ status: "served", proved: true, route: "r", height: "100", scope: S, subjectAccrualId, count: 0 });
    const evidence = {
      header: absent(),
      accruals: Object.fromEntries(plan.members.map((m) => [m.funderId, absent()])),
      accrualEnumeration: { status: "served", proved: true, route: "r", height: "100", scope: S, funderIds: [] },
      dependents: Object.fromEntries(plan.members.map((m) => [m.funderId, { machinerySweep: {
        reservation: sweepPart(m.plannedAccrualId), receipt: sweepPart(m.plannedAccrualId), parts: sweepPart(m.plannedAccrualId) } }])),
    };
    const r = K.evaluateEpochForwardState({ plan, evidence });
    ok("the real kernel evaluates the encoding-refused plan over proved emptiness as complete under the encoding-refused condition (the placeholder amount is never read)",
      r.state === "complete" && r.condition === "encoding-refused");
    const served = (fields, documentId) => ({ status: "served", proved: true, route: "r", height: "100", scope: S, documentId, fields });
    const r2 = K.evaluateEpochForwardState({ plan, evidence: { ...evidence,
      accruals: { ...evidence.accruals, [B]: served({ poolId: POOL, funderId: B, epochIndex: 0, amountCredits: "1", shareBps: 4990 }, plan.members[1].plannedAccrualId) } } });
    ok("and a record served under a planned funder of the refused epoch refuses by name",
      r2.state === "refused" && r2.reasons.some((x) => x.code === "REFUSED_RECORDS_UNDER_ENCODING_REFUSED_EPOCH"));
  }

  // ---- 6. the canonical identifier form (section 8) ----
  throws("a base58 income identity beside hex funders is REFUSED (never no self-share)",
    () => build({ formation: { ...formation(), incomeIdentity: OWNER_B58 } }), /formation.incomeIdentity must be 64 lowercase hex/);
  throws("an uppercase income identity is refused", () => build({ formation: { ...formation(), incomeIdentity: A.toUpperCase() } }), /not all lowercase/);
  throws("a byte-object recipient is refused", () => build({ formation: { ...formation(), allocation: [{ recipientId: Buffer.from(A, "hex"), bps: 10000 }] } }), /a byte object/);
  throws("a boxed-string pool identifier is refused", () => build({ scope: { ...scopeFor(0), poolId: new String(POOL) } }), /scope.poolId must be a primitive string/);
  throws("an uppercase formation allocation hash is refused", () => build({ formation: { ...formation(), allocationHash: AH.toUpperCase() } }), /formation.allocationHash/);
  throws("a base58 scope contract identifier is refused", () => build({ scope: { ...scopeFor(0), contractId: CONTRACT_B58 } }), /scope.contractId must be 64 lowercase hex/);
  throws("a generator contract identifier that does not decode to the scope's contract refuses (one contract in two forms)",
    () => build({ identifiers: { ...identifiers(), contractId: OWNER_B58 } }), /decodes to .* while scope.contractId is/);
  throws("a generator contract identifier that does not decode refuses", () => build({ identifiers: { ...identifiers(), contractId: "not-an-id" } }), /does not decode to a 32-byte identifier/);
  throws("a contract version other than 11 refuses", () => build({ scope: { ...scopeFor(0), contractVersion: 10 } }), /literal 11/);
  throws("an unresolved formation refuses (the caller's statement of a proved resolution, or nothing)", () => build({ formation: { ...formation(), resolved: false } }), /formation.resolved must be the literal true/);
  throws("a truthy non-literal resolved is refused", () => build({ formation: { ...formation(), resolved: "true" } }), /formation.resolved must be the literal true/);
  throws("a duplicate allocation recipient refuses", () => build({ formation: { ...formation(), allocation: [ALLOCATION[0], ALLOCATION[0]] } }), /twice/);
  throws("a duplicate allocation recipient in two DISTINCT row objects refuses (identity of the recipient, not of the row)", () => build({ formation: { ...formation(), allocation: [{ recipientId: A, bps: 5000 }, { recipientId: A, bps: 5000 }] } }), /twice/);
  throws("a boxed-string recipient is refused and named as one", () => build({ formation: { ...formation(), allocation: [{ recipientId: new String(A), bps: 10000 }] } }), /a boxed string/);
  {
    let reads = 0;
    const alloc = ALLOCATION.map((a) => ({ ...a }));
    Object.defineProperty(alloc, 0, { get: () => { reads += 1; return { recipientId: A, bps: 5000 }; }, enumerable: true, configurable: true });
    let t = null; try { build({ formation: { ...formation(), allocation: alloc } }); } catch (e) { t = e.message; }
    ok(`an allocation array whose index 0 is an accessor is refused with the getter never invoked (reads ${reads})`, t !== null && /formation.allocation.0 must be an own DATA member/.test(t) && reads === 0);
    let jreads = 0;
    const jr = [journaled(0)];
    Object.defineProperty(jr, 0, { get: () => { jreads += 1; return journaled(0); }, enumerable: true, configurable: true });
    let t2 = null; try { build({ journalRun: jr }); } catch (e) { t2 = e.message; }
    ok(`a journal run whose index 0 is an accessor is refused with the getter never invoked (reads ${jreads})`, t2 !== null && /journalRun.0 must be an own DATA member/.test(t2) && jreads === 0);
    const inherited = Object.create([journaled(0)]);
    let t3 = null; try { build({ journalRun: inherited }); } catch (e) { t3 = e.message; }
    ok("a journal run that only inherits its entries is refused (not an array)", t3 !== null && /journalRun must be an array/.test(t3));
  }
  throws("bps outside 1..10000 refuses", () => build({ formation: { ...formation(), allocation: [{ recipientId: A, bps: 10001 }] } }), /1\.\.10000/);
  throws("a non-function generator refuses", () => build({ identifiers: { ...identifiers(), generateId: "g" } }), /generateId must be the injected identifier generator function/);
  throws("a negative configured start refuses", () => build({ configuredStart: -1 }), /configuredStart/);
  throws("a non-array journal run refuses", () => build({ journalRun: null }), /journalRun must be an array/);
  // ---- every input read once through its own data descriptor ----
  {
    let reads = 0;
    const scope = Object.defineProperty({ ...scopeFor(0) }, "poolId", { get: () => { reads += 1; return POOL; }, enumerable: true });
    let t = null; try { build({ scope }); } catch (e) { t = e.message; }
    ok(`an accessor-backed scope member is refused by name with the getter never invoked (reads ${reads})`, t !== null && /own DATA member/.test(t) && reads === 0);
    let t2 = null; try { build({ formation: Object.create(formation()) }); } catch (e) { t2 = e.message; }
    ok("inherited formation members are refused", t2 !== null && /required as an own data member/.test(t2));
    ok("declaredFigures must be stated (null or a fixture), never omitted, so the no-fixture decision is the caller's and explicit",
      (() => { try { X.buildEpochContext({ scope: scopeFor(0), formation: formation(), journalRun: [journaled(0)], configuredStart: 0, identifiers: identifiers() }); return false; } catch (e) { return /options.declaredFigures is required/.test(e.message); } })());
    throws("a non-object options value refuses", () => X.buildEpochContext(null), /one options object/);
    throws("planInputOf refuses a look-alike object", () => X.planInputOf({ kind: X.KIND, rows: [], precondition: null }), /kind string on an object literal proves nothing/);
  }

  // ---- 7. reservationForVerifier ----
  {
    const RES = h("d1"), ACC = h("a1"), TH = h("7e");
    const answer = { status: "served", documentId: RES, fields: { poolId: POOL, accrualId: ACC, transitionHash: TH, extra: "x" },
      proved: true, route: "documents-proved-query", height: "100", scope: scopeFor(0) };
    const v = X.reservationForVerifier(answer);
    ok("a served pinned answer maps to the verifier's { status: served, doc: { poolId, accrualId, transitionHash } } and nothing else",
      JSON.stringify(v) === JSON.stringify({ status: "served", doc: { poolId: POOL, accrualId: ACC, transitionHash: TH } }));
    ok("proved-absence maps to { status: proved-absence } alone", JSON.stringify(X.reservationForVerifier({ status: "proved-absence", proved: true, route: "r", height: "1", scope: scopeFor(0) })) === JSON.stringify({ status: "proved-absence" }));
    ok("unserved maps to unserved", JSON.stringify(X.reservationForVerifier({ status: "unserved" })) === JSON.stringify({ status: "unserved" }));
    ok("unverified maps to unserved (the verifier leaves that aspect unproved)", JSON.stringify(X.reservationForVerifier({ status: "unverified" })) === JSON.stringify({ status: "unserved" }));
    throws("a foreign status refuses", () => X.reservationForVerifier({ status: "verified" }), /status must be served, proved-absence, unserved or unverified/);
    throws("a served answer without a transitionHash refuses", () => X.reservationForVerifier({ ...answer, fields: { poolId: POOL, accrualId: ACC } }), /fields.transitionHash is required/);
    throws("a served answer with an uppercase transitionHash refuses", () => X.reservationForVerifier({ ...answer, fields: { ...answer.fields, transitionHash: TH.toUpperCase() } }), /fields.transitionHash must be 64 lowercase hex/);
    throws("a served answer with a byte-object accrual refuses", () => X.reservationForVerifier({ ...answer, fields: { ...answer.fields, accrualId: Buffer.from(ACC, "hex") } }), /a byte object/);
    throws("a non-object answer refuses", () => X.reservationForVerifier("served"), /must be an object/);
    let reads = 0;
    const acc = Object.defineProperty({ ...answer }, "status", { get: () => { reads += 1; return "served"; }, enumerable: true });
    let t = null; try { X.reservationForVerifier(acc); } catch (e) { t = e.message; }
    ok(`an accessor-backed status is refused without being invoked (reads ${reads})`, t !== null && /own DATA member/.test(t) && reads === 0);
  }

  // ---- 8. the verdict closure through the REAL verifier over the mock pipeline ----
  {
    // the verifier test's mock pinned pipeline, reproduced at its contract: parse the JSON
    // carrier, drop unknown fields, re-encode canonically
    const toHex = (s) => Buffer.from(s, "utf8").toString("hex");
    const fromHex = (x) => Buffer.from(x, "hex").toString("utf8");
    const sha = (hex) => crypto.createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");
    const be64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b.toString("hex"); };
    const PROOF_KNOWN = ["quorumHash", "round", "blockIdHash", "quorumType", "signature", "pad"];
    const META_KNOWN = ["chainId", "protocolVersion", "height", "timeMs", "coreChainLockedHeight", "epoch", "pad"];
    const mockDecode = (known) => (hex) => { const obj = JSON.parse(fromHex(hex)); const out = {}; for (const [k, v] of Object.entries(obj)) if (known.includes(k)) out[k] = v; return { fields: out, reencodedHex: toHex(canonicalString(out)) }; };
    const mkDeps = () => {
      const calls = { stageOne: 0, stageTwo: 0, transfers: [], basis: [] };
      const verifierDeps = {
        decodeProofCarrier: (hex) => { const d = mockDecode(PROOF_KNOWN)(hex); return { reencodedHex: d.reencodedHex, quorumHashHex: d.fields.quorumHash, round: d.fields.round }; },
        decodeMetadata: (hex) => { const d = mockDecode(META_KNOWN)(hex); return { reencodedHex: d.reencodedHex, ...d.fields }; },
        decodeTransfer: (hex) => { calls.transfers.push(hex); return JSON.parse(fromHex(hex)); },
        verifyStageOne: async (a) => { calls.stageOne += 1; return { ok: true, rootHashHex: sha(a.carrierHex) }; },
        verifyStageTwo: async () => { calls.stageTwo += 1; return true; },
      };
      const deps = { verifierDeps, verifyCaptureBasis: async (capture, supersessions) => { calls.basis.push({ capture, supersessions }); return true; } };
      return { deps, calls };
    };
    const ACC = ctx0.rows[1].plannedAccrualId;   // B's planned accrual at epoch 0
    const AMOUNT = ctx0.rows[1].effectiveCredits;
    const proofObj = (padLen) => ({ quorumHash: h("dd"), round: 3, blockIdHash: h("bb"), quorumType: 4, signature: "cd".repeat(Math.max(1, padLen)) });
    const mkCarrier = (padLen) => toHex(canonicalString(proofObj(padLen)));
    const carrierOfLength = (wantL) => { let padLen = 1, hex = mkCarrier(padLen); padLen += wantL - hex.length / 2; hex = mkCarrier(Math.floor(padLen)); while (hex.length / 2 < wantL) { padLen += 1; hex = mkCarrier(padLen); } while (hex.length / 2 > wantL) { padLen -= 1; hex = mkCarrier(padLen); } if (hex.length / 2 !== wantL) throw new Error("carrier length"); return hex; };
    const bigCarrier = carrierOfLength(2 * PART_BOUND_B + 100);   // three chunks: proofBytes plus parts 1 and 2
    const META_OBJ = { chainId: CHAIN, protocolVersion: 12, height: "1000", timeMs: "1690000000000", coreChainLockedHeight: 777, epoch: 5 };
    const META_HEX = toHex(canonicalString(META_OBJ));
    const TRANSFER_HEX = toHex(canonicalString({ senderId: A, recipientId: B, amountCredits: AMOUNT, nonce: "7" }));
    const TH = sha(TRANSFER_HEX);
    const split = (carrierHex) => { const L = carrierHex.length / 2; const count = Math.max(1, Math.ceil(L / PART_BOUND_B)); const proofBytes = carrierHex.slice(0, Math.min(L, PART_BOUND_B) * 2); const parts = []; for (let i = 1; i < count; i++) parts.push({ partIndex: i, bytes: carrierHex.slice(i * PART_BOUND_B * 2, Math.min((i + 1) * PART_BOUND_B, L) * 2) }); return { proofBytes, parts, count }; };
    const sp = split(bigCarrier);
    const receiptFields = { poolId: POOL, accrualId: ACC, transitionHash: TH, transitionBytes: TRANSFER_HEX, proofBytes: sp.proofBytes,
      proofPartCount: sp.count, metadataBytes: META_HEX, blockHeight: be64(1000), coreChainLockedHeight: 777, timeMs: be64("1690000000000"),
      quorumHash: h("dd"), round: 3, $createdAt: 1 };
    // the served documents as acquisition hands them, parts in DESCENDING order to show the
    // closure passes the set through and the verifier orders by index
    const partDocs = [...sp.parts].reverse().map((p) => ({ documentId: h(`e${p.partIndex}`), fields: { poolId: POOL, accrualId: ACC, partIndex: p.partIndex, bytes: p.bytes, $createdAt: 1 } }));
    const capture = { v: 1, kind: "tegara.e2.receiptCapture.v1", object: "transfer", gen: 1, poolId: POOL, epochIndex: 0, accrualId: ACC,
      transitionHash: TH, transitionBytes: TRANSFER_HEX, proofMsg: bigCarrier, metadataMsg: META_HEX, inclusionHeight: "1001",
      heightRoute: "tenderdash-tx", signerIdentity: h("f0"), signerKeyId: 2, sig: "00".repeat(65) };
    const member = () => ({ ...K.buildExpectedRecordPlan(X.planInputOf(ctx0)).members[1] });
    const pinned = (fields) => ({ status: "served", documentId: h("d1"), fields, proved: true, route: "documents-proved-query", height: "100", scope: scopeFor(0) });
    const callFor = (over = {}) => ({ member: member(), receipt: { documentId: h("c0"), fields: mutable(receiptFields) },
      parts: { status: "served", documents: mutable(partDocs) }, reservation: pinned({ poolId: POOL, accrualId: ACC, transitionHash: TH }), ...over });
    const journal = new Map([[ACC, { capture, supersessions: [] }]]);
    const lookups = [];
    const captureFor = (id) => { lookups.push(id); return journal.has(id) ? journal.get(id) : null; };
    const { deps, calls } = mkDeps();
    const verdict = X.executionVerdictFor(ctx0, { captureFor, deps });
    ok("executionVerdictFor answers a function", typeof verdict === "function");
    let v = null, goldenFault = null;
    try { v = await verdict(callFor()); } catch (e) { goldenFault = e.message; }
    ok(`golden: the closure reaches CAPTURE-VERIFIED through the real verifier with the member's amount (${goldenFault ? `threw: ${goldenFault.slice(0, 80)}` : JSON.stringify(v).slice(0, 80)})`,
      v !== null && v.label === "CAPTURE-VERIFIED" && v.verifiedAmountCredits === AMOUNT && v.captureValid === true);
    ok(`golden: the capture was looked up by the member's PLANNED accrual identifier and handed to the basis adapter, and both proof stages ran twice, over the receipt and over the capture record (stages ${calls.stageOne}/${calls.stageTwo})`,
      lookups.length === 1 && lookups[0] === ACC && calls.basis.length === 1 && calls.basis[0].capture === capture
      && calls.stageOne === 2 && calls.stageTwo === 2 && calls.transfers[0] === TRANSFER_HEX);
    // the supersession list reaches the basis adapter with its contents
    {
      const sup = [{ supersededKind: capture.kind, transitionHash: h("55"), gen: 2 }];
      const expected = JSON.stringify(sup[0]);   // snapshotted BEFORE the call, so an in-place edit is visible
      journal.set(ACC, { capture, supersessions: sup });
      const n = calls.basis.length;
      const r = await verdict(callFor());
      ok("the capture's supersession records reach the basis adapter with their contents unchanged (a non-empty list, each record the same object the lookup answered, equal to a snapshot taken before the call)",
        r.label === "CAPTURE-VERIFIED" && calls.basis.length === n + 1 && calls.basis[n].supersessions.length === 1
        && calls.basis[n].supersessions[0] === sup[0] && JSON.stringify(calls.basis[n].supersessions[0]) === expected && calls.basis[n].supersessions !== sup);
      journal.set(ACC, { capture, supersessions: [] });
    }
    // THE CHAIN PIN IS THE CONTEXT'S SCOPE: a context on another chain sends the verifier a
    // pin the decoded metadata does not carry, and the carrier stage refuses it
    {
      const ctxOther = build({ scope: { ...scopeFor(0), chainId: "another-chain" } });
      const r = await X.executionVerdictFor(ctxOther, { captureFor, deps })(callFor());
      ok("the verifier's chain pin is the context's own scope.chainId: a context naming another chain is REFUSED at the carrier stage (the pin is not a second input)",
        r.label === "REFUSED" && /chainId/.test(r.reason) && /pinned/.test(r.reason));
    }
    // THE VERIFIER RECEIVES THE CONTEXT ROW, not the call's member read again: a lookup that
    // alters the call object after the check cannot change the entitlement row
    {
      const call = callFor();
      const altering = (id) => { call.member.effectiveCredits = "500000"; call.member.funderId = h("ff"); return captureFor(id); };
      const r = await X.executionVerdictFor(ctx0, { captureFor: altering, deps })(call);
      ok("a lookup that rewrites the call's member after the check does not reach the verifier: the entitlement row is the context row's (CAPTURE-VERIFIED with the row's amount)",
        r.label === "CAPTURE-VERIFIED" && r.verifiedAmountCredits === AMOUNT);
    }
    // the reservation is normalized THROUGH the closure and judged by the verifier
    const mismatch = await verdict(callFor({ reservation: pinned({ poolId: POOL, accrualId: ACC, transitionHash: h("77") }) }));
    ok("a served pinned reservation whose transitionHash differs from the receipt's is REFUSED by the verifier (a soundness-review finding), so the pinned answer reached it normalized", mismatch.label === "REFUSED" && /a soundness-review finding/.test(mismatch.reason));
    const provedAbsent = await verdict(callFor({ reservation: { status: "proved-absence", proved: true, route: "r", height: "1", scope: scopeFor(0) } }));
    ok("a proved-absence pinned reservation is REFUSED by the verifier (the claim is part of the chain)", provedAbsent.label === "REFUSED" && /proved reservation absence/.test(provedAbsent.reason));
    const unverified = await verdict(callFor({ reservation: { status: "unverified" } }));
    ok("an unverified pinned reservation does not stop the execution verifying (the aspect the verifier leaves unproved is not surfaced by this label, so this observes the label only)", unverified.label === "CAPTURE-VERIFIED");
    // no capture: refused by the verifier, neither stage consulted
    const before1 = calls.stageOne, before2 = calls.stageTwo;
    journal.delete(ACC);
    const noCap = await verdict(callFor());
    ok("no journaled capture under the planned accrual is REFUSED by the verifier (the observed condition is the absence of a local capture) with neither proof stage consulted",
      noCap.label === "REFUSED" && /capture/.test(noCap.reason) && calls.stageOne === before1 && calls.stageTwo === before2);
    // never cached: the journal gaining the record between calls changes the verdict
    journal.set(ACC, { capture, supersessions: [] });
    const lookupsBefore = lookups.length;
    const again = await verdict(callFor());
    ok(`the capture is looked up on EVERY call, never cached: the journal gaining the record between calls turns REFUSED into CAPTURE-VERIFIED (lookups ${lookups.length})`,
      again.label === "CAPTURE-VERIFIED" && lookups.length === lookupsBefore + 1 && lookups.every((x) => x === ACC));
    // never cached, the other direction: the capture REPLACED without an intervening absence
    journal.set(ACC, { capture: { ...capture, transitionHash: h("77") }, supersessions: [] });
    const replaced = await verdict(callFor());
    ok("a capture replaced between calls (no intervening absence) is judged afresh: the replacement's transition hash is not the SHA-256 of its bytes and the capture record is REFUSED by name",
      replaced.label === "REFUSED" && /capture/.test(replaced.reason) && /SHA-256/.test(replaced.reason));
    journal.set(ACC, { capture, supersessions: [] });
    // the served transition bytes are the verifier's, not the capture's: a receipt whose
    // bytes differ from the capture's while its own hash is consistent is REFUSED by the pair
    {
      const otherBytes = toHex(canonicalString({ senderId: A, recipientId: B, amountCredits: AMOUNT, nonce: "8" }));
      const r = await verdict(callFor({ receipt: { documentId: h("c0"), fields: { ...receiptFields, transitionBytes: otherBytes, transitionHash: sha(otherBytes) } },
        reservation: pinned({ poolId: POOL, accrualId: ACC, transitionHash: sha(otherBytes) }) }));
      ok("served transition bytes differing from the capture's, with the served hash AND the pinned reservation consistent with them, are decoded by the verifier AS SERVED and REFUSED at the capture pair (the only remaining disagreement)",
        r.label === "REFUSED" && calls.transfers[calls.transfers.length - 1] === otherBytes && !/a soundness-review finding/.test(r.reason));
    }
    // caller faults, each a throw by name, never a verdict
    const own = async (name, p, re) => rejects(name, p, new RegExp(`e2EpochContext.*(${re.source})`));
    await own("a call for a funder outside this context's plan is a caller fault", verdict(callFor({ member: { ...member(), funderId: h("ff") } })), /not a member of this context's plan/);
    await own("a call whose member carries another planned identifier is a caller fault", verdict(callFor({ member: { ...member(), plannedAccrualId: h("fe") } })), /not a member of this context's plan/);
    await own("a call whose member amount differs from the context's row is a caller fault", verdict(callFor({ member: { ...member(), effectiveCredits: "1" } })), /effectiveCredits 1 while this context's row carries/);
    {
      // a receipt whose ACCRUAL field disagrees with the plan is, like the pool, nonconforming
      // evidence and not a caller fault (acquisition's stage 3 guarantees the accrual
      // document's identifier, not the receipt's field): the verifier refuses it against the
      // capture looked up by the row's planned identifier
      let r = null, thrown = null;
      try { r = await verdict(callFor({ receipt: { documentId: h("c0"), fields: { ...receiptFields, accrualId: h("fd") } } })); } catch (e) { thrown = e.message; }
      ok(`a served receipt whose accrual field is not the member's planned accrual is REFUSED by the verifier (the parts and the capture name the planned accrual), never thrown as a caller fault${thrown ? ` (threw: ${thrown.slice(0, 60)})` : ""}`, r !== null && r.label === "REFUSED" && /foreign accrual|accrualId differs/.test(r.reason) && lookups[lookups.length - 1] === ACC);
    }
    {
      let reads = 0;
      const accObj = { toString: undefined };
      Object.defineProperty(accObj, "toString", { get: () => { reads += 1; return () => ACC; } });
      {
        let r = null, thrown = null;
        try { r = await verdict(callFor({ receipt: { documentId: h("c0"), fields: { ...receiptFields, accrualId: accObj } } })); } catch (e) { thrown = e.message; }
        ok(`a served receipt whose accrualId is an object with an accessor-backed toString is REFUSED by the verifier's own grammar with the accessor never invoked (reads ${reads})${thrown ? ` (threw: ${thrown.slice(0, 60)})` : ""}`, r !== null && r.label === "REFUSED" && /accrualId is not lowercase hex/.test(r.reason) && reads === 0);
      }
      {
        let r = null, thrown = null;
        try { r = await verdict(callFor({ receipt: { documentId: h("c0"), fields: { ...receiptFields, accrualId: Object.create(null) } } })); } catch (e) { thrown = e.message; }
        ok(`a served receipt whose accrualId is a null-prototype object is REFUSED by the verifier's grammar, never a foreign TypeError${thrown ? ` (threw: ${thrown.slice(0, 60)})` : ""}`, r !== null && r.label === "REFUSED" && /accrualId is not lowercase hex/.test(r.reason));
      }
      let preads = 0;
      const docs = mutable(partDocs);
      Object.defineProperty(docs, 0, { get: () => { preads += 1; return partDocs[0]; }, enumerable: true, configurable: true });
      let t = null; try { await verdict(callFor({ parts: { status: "served", documents: docs } })); } catch (e) { t = e.message; }
      ok(`a parts document array whose index 0 is an accessor is refused with the getter never invoked (reads ${preads})`, t !== null && /parts.documents.0 must be an own DATA member/.test(t) && preads === 0);
    }
    {
      // a receipt served under ANOTHER POOL is not a caller fault (acquisition queries receipts
      // by accrual alone and the kernel refuses the nonconforming answer on its fields): the
      // closure hands it to the verifier, which refuses it against the capture's pool
      let r = null, thrown = null;
      try { r = await verdict(callFor({ receipt: { documentId: h("c0"), fields: { ...receiptFields, poolId: h("fc") } } })); } catch (e) { thrown = e.message; }
      ok(`a served receipt under another pool is REFUSED by the verifier (the capture's pool differs), never thrown as a caller fault${thrown ? ` (threw: ${thrown.slice(0, 60)})` : ""}`, r !== null && r.label === "REFUSED" && /pool/.test(r.reason));
    }
    await own("a parts read that was not served is a caller fault (acquisition never requests a verdict over unresolved evidence)", verdict(callFor({ parts: { status: "unserved", documents: null } })), /not a served document set/);
    await own("an unserved parts read beside a valid documents array is still a caller fault (the status is the check, not the array)", verdict(callFor({ parts: { status: "unserved", documents: mutable(partDocs) } })), /not a served document set/);
    await own("a malformed captureFor answer is a caller fault", X.executionVerdictFor(ctx0, { captureFor: () => ({ capture }), deps })(callFor()), /captureFor answer.supersessions is required/);
    await own("a captureFor answering undefined is a caller fault (the domain is null or an answer)", X.executionVerdictFor(ctx0, { captureFor: () => undefined, deps })(callFor()), /undefined is a lookup that returned nothing/);
    await own("a non-object call is a caller fault", verdict(null), /one plain call object/);
    {
      let reads = 0;
      const call = callFor();
      Object.defineProperty(call, "member", { get: () => { reads += 1; return member(); }, enumerable: true });
      let t = null; try { await verdict(call); } catch (e) { t = e.message; }
      ok(`an accessor-backed call member is refused without being invoked (reads ${reads})`, t !== null && /own DATA member/.test(t) && reads === 0);
    }
    // a verifier dependency fault propagates as the fault it is
    const faulty = mkDeps(); faulty.deps.verifyCaptureBasis = async () => { throw new Error("basis down"); };
    await rejects("a capture-basis adapter fault propagates from the verifier, never a verdict", X.executionVerdictFor(ctx0, { captureFor, deps: faulty.deps })(callFor()), /basis down/);
    // an unverifiable receipt is REFUSED, not thrown: the verifier's own reason
    const bad = await verdict(callFor({ receipt: { documentId: h("c0"), fields: { ...receiptFields, round: 4 } } }));
    ok("a receipt whose lifted round differs from the decoded carrier is REFUSED with the verifier's reason", bad.label === "REFUSED" && /round/.test(bad.reason));
    // build-time refusals
    throws("executionVerdictFor refuses a missing captureFor", () => X.executionVerdictFor(ctx0, { deps }), /captureFor is required/);
    throws("executionVerdictFor refuses a non-function captureFor", () => X.executionVerdictFor(ctx0, { captureFor: {}, deps }), /needs captureFor/);
    throws("executionVerdictFor refuses deps without the basis adapter before any read", () => X.executionVerdictFor(ctx0, { captureFor, deps: { verifierDeps: deps.verifierDeps } }), /verifyCaptureBasis/);
    for (const k of ["decodeProofCarrier", "decodeMetadata", "decodeTransfer", "verifyStageOne", "verifyStageTwo"]) {
      const partial = { ...deps.verifierDeps }; delete partial[k];
      throws(`executionVerdictFor refuses verifierDeps missing ${k} before any read (the verifier's own list)`, () => X.executionVerdictFor(ctx0, { captureFor, deps: { verifierDeps: partial, verifyCaptureBasis: deps.verifyCaptureBasis } }), new RegExp(`verifierDeps\\.${k}`));
    }
    throws("executionVerdictFor refuses an empty verifierDeps object", () => X.executionVerdictFor(ctx0, { captureFor, deps: { verifierDeps: {}, verifyCaptureBasis: async () => true } }), /verifierDeps\.decodeProofCarrier/);
    throws("executionVerdictFor refuses a look-alike context", () => X.executionVerdictFor({ kind: X.KIND, rows: [], precondition: null }, { captureFor, deps }), /kind string on an object literal/);
    throws("executionVerdictFor refuses a deep-frozen look-alike context (the brand, not frozenness, is the check)", () => X.executionVerdictFor(Object.freeze({ kind: X.KIND, scope: Object.freeze({ ...scopeFor(0) }), formation: Object.freeze(formation()), rows: Object.freeze([]), precondition: null, encodingRefused: false }), { captureFor, deps }), /kind string on an object literal/);
    // THE DEPENDENCIES ARE CAPTURED AT CONSTRUCTION: an accessor-backed bundle is refused
    // uninvoked, inherited stage functions are refused, and a bundle altered afterwards does
    // not reach a verification
    {
      let reads = 0;
      const opts = { captureFor, deps: {} };
      Object.defineProperty(opts.deps, "verifierDeps", { get: () => { reads += 1; return deps.verifierDeps; }, enumerable: true });
      opts.deps.verifyCaptureBasis = deps.verifyCaptureBasis;
      let t = null; try { X.executionVerdictFor(ctx0, opts); } catch (e) { t = e.message; }
      ok(`an accessor-backed verifierDeps is refused with the getter never invoked (reads ${reads})`, t !== null && /options.deps.verifierDeps must be an own DATA member/.test(t) && reads === 0);
      throws("stage functions inherited through the bundle's prototype are refused", () => X.executionVerdictFor(ctx0, { captureFor, deps: { verifierDeps: Object.create(deps.verifierDeps), verifyCaptureBasis: deps.verifyCaptureBasis } }), /verifierDeps.decodeProofCarrier is required as an own data member/);
      const mine = mkDeps();
      const bundle = { verifierDeps: { ...mine.deps.verifierDeps }, verifyCaptureBasis: mine.deps.verifyCaptureBasis };
      const built = X.executionVerdictFor(ctx0, { captureFor, deps: bundle });
      delete bundle.verifierDeps.verifyStageTwo;
      bundle.verifyCaptureBasis = async () => false;
      let r = null, fault = null;
      try { r = await built(callFor()); } catch (e) { fault = e.message; }
      ok(`a dependency bundle altered after construction (a stage deleted, the basis adapter replaced) does not reach the verifier: the captured functions run and the golden receipt still verifies${fault ? ` (threw: ${fault.slice(0, 70)})` : ""}`,
        r !== null && r.label === "CAPTURE-VERIFIED" && mine.calls.stageTwo === 2 && mine.calls.basis.length === 1);
    }
    // an INHERITED optional served member is refused, not read as absent
    {
      const proto = { round: 3 };
      const fields = Object.assign(Object.create(proto), receiptFields); delete fields.round;
      await own("a served receipt whose round is inherited rather than own is a caller fault (an inherited member is refused, not read as missing)", verdict(callFor({ receipt: { documentId: h("c0"), fields } })), /the call's receipt fields.round is inherited/);
      const pf = mutable(partDocs); const pproto = { bytes: pf[0].fields.bytes }; const f0 = Object.assign(Object.create(pproto), pf[0].fields); delete f0.bytes; pf[0].fields = f0;
      await own("a served part whose bytes are inherited is a caller fault", verdict(callFor({ parts: { status: "served", documents: pf } })), /parts.documents\[0\].fields.bytes is inherited/);
    }
    // an ENCODING-REFUSED context expects no records, so acquisition reads no receipt under
    // its plan and no verdict is ever owed; the closure refuses at build time
    const ctxR = build({ journalRun: [], declaredFigures: { grossCredits: String(2n * entitlementCalc.SCHEMA_CREDIT_CEILING + 2n), feeCredits: "0" } });
    throws("executionVerdictFor refuses an encoding-refused context (no receipt is read under its plan, so no verdict is owed)",
      () => X.executionVerdictFor(ctxR, { captureFor, deps }), /encoding-refused context/);
  }

  console.log(`\ne2EpochContextTest: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exitCode = 1;
};

main().catch((e) => { console.error(`e2EpochContextTest: unexpected throw: ${e.message}\n${e.stack}`); process.exitCode = 1; });
