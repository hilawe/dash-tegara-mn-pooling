/**
 * e2ForwardAdapterTest: the offline battery for the FORWARD ADAPTER (contract
 * section 3.2.1, the boundary that supplies provenance). Plain `node`, no
 * network. The index table comes from the same builder the registered ledger
 * came from (contractV11.cjs over dist/contract/poolLedger.js).
 *
 * WHAT IT BINDS, enumerated from the module's interfaces:
 *   1. construction: the binding's five members, the transport's three, the
 *      ledger table's five types, each refusal by name; and a soundness-review finding, both getter
 *      forms (persistent, self-replacing) on every binding member refused with
 *      ZERO invocations and no adapter returned, the transport and descriptor
 *      accessor controls counted the same way;
 *   2. the descriptor grammar and the BINDING CROSS-CHECK, with EVERY refusal
 *      shown to issue nothing immediately and after one macrotask boundary
 *      (the window the helper observes, no wider), accessor-backed members
 *      refused, and the clause CAPTURE: a clause mutated while a read is
 *      pending does not change what the transport received;
 *   3. index resolution under the ORDERED-PREFIX rule: hand-built descriptors
 *      in each clause shape acquisition builds, and in section 8 the descriptors
 *      acquisition itself issued up to the receipt read (header, enumeration,
 *      accrual, both reservations; the part shape is reached only by hand);
 *      that resolution READS THE SUPPLIED TABLE (a renamed index shows in the
 *      route), and an unservable clause issues nothing;
 *   4. the served envelope: exactly six members, `scope` equal to the BINDING
 *      under two different bindings, `proved` equal to the transport's
 *      declaration with one route string paired with both declarations,
 *      `route` naming transport, type and index, `height` from the page on a
 *      header and on a non-header read, documents as { id, fields } with their
 *      identities, deep freezing down to the document wrapper, a full page
 *      passed through at the descriptor's limit with its checker cursor dropped,
 *      an empty page served empty;
 *   5. unserved and unverified passed through as exactly { status }, one call each;
 *   6. faults propagate on a header read and on a receipt read: a transport
 *      throw, a malformed page, a non-ascending page, a document without plain
 *      fields, a document outside { id, fields };
 *   7. the transport call: one call per read with the binding's contractId,
 *      the descriptor's type, the CAPTURED where, the descriptor's limit,
 *      orderBy null and startAfter null, for every call of a composition run,
 *      and a repeated header or accrual read is a repeated call (a count, which
 *      does not establish that the second answer is fresh);
 *   8. composition with the real acquisition unit and the real kernel to all
 *      four states (complete, incomplete, unproved, refused), with every
 *      transport call of the COMPLETE run compared against its descriptor's
 *      clause over the ledger's own index table, which is the schema-backed
 *      check that found a soundness-review finding and is included here as a regression; and the
 *      widening a soundness-review finding repair brings, a wrong-pool receipt refused and never
 *      absent, receipt absence proved across pools, cross-pool occupancy of the
 *      planned key counted by the sweep.
 *
 * WHAT IT DOES NOT ESTABLISH: that any transport verifies proofs (none is
 * exercised here), that Platform accepts these clauses without orderBy or
 * applies the ordered-prefix rule (the live gate), that the supplied index
 * table is the registered contract's, or which index Platform selects.
 */
"use strict";

const path = require("path");
const { pathToFileURL } = require("url");
const K = require("./e2ForwardKernel.cjs");
const A = require("./e2Acquire.cjs");
const F = require("./e2ForwardAdapter.cjs");
const { buildV11 } = require("./contractV11.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed += 1; console.log(`  PASS: ${name}`); }
  else { failed += 1; console.log(`  FAIL: ${name}`); }
};
const rejects = async (name, p, re) => {
  try { await p; failed += 1; console.log(`  FAIL: ${name} (no refusal)`); }
  catch (e) { const m = (e && e.message) || String(e); ok(`${name} (${m.slice(0, 80)})`, re.test(m)); }
};
const throws = (name, fn, re) => {
  try { fn(); failed += 1; console.log(`  FAIL: ${name} (no refusal)`); }
  catch (e) { const m = (e && e.message) || String(e); ok(`${name} (${m.slice(0, 80)})`, re.test(m)); }
};
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const deepFrozen = (v) => v === null || typeof v !== "object" || (Object.isFrozen(v) && Object.keys(v).every((k) => deepFrozen(v[k])));

// ---- fixture identities, the acquisition test's own so the suites agree ----
const POOL = "11".repeat(32);
const FUNDER_A = "aa".repeat(32);
const PLANNED_A = "a1".repeat(32);
const RES_A = "d1".repeat(32);
const RCPT_A = "d2".repeat(32);
const HDR_ID = "77".repeat(32);
const AH = "ee".repeat(32);
const TH = "ff".repeat(32);
const EPOCH = 7;
const CONTRACT_HEX = "c1".repeat(32);
const BINDING = Object.freeze({ contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11,
  poolId: POOL, epochIndex: EPOCH });
// a SECOND binding, every member different, so scope equality is not equality
// against one fixture
const POOL2 = "22".repeat(32);
const BINDING2 = Object.freeze({ contractId: "c2".repeat(32), chainId: "devnet-y", contractVersion: 12,
  poolId: POOL2, epochIndex: 3 });
const ROUTE = "documents.query(prove,marker)";
const KIND = "tegara.e2.queryDescriptor.v1";

const doc = (id, fields) => ({ id, fields });
const headerDoc = (over = {}) => doc(HDR_ID, { poolId: POOL, epochIndex: EPOCH, grossCredits: "1000",
  feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH, ...over });
const accrualDoc = (id, funderId) => doc(id, { poolId: POOL, funderId, epochIndex: EPOCH, amountCredits: "900", shareBps: 10000 });
const reservationDoc = (id, accrualId) => doc(id, { poolId: POOL, accrualId, transitionHash: TH });
const receiptDoc = (id, accrualId) => doc(id, { poolId: POOL, accrualId, transitionHash: TH, proofPartCount: 3 });
const partDoc = (id, accrualId, partIndex) => doc(id, { poolId: POOL, accrualId, partIndex });
// the kernel's A1 store: a receipt declaring three parts carries part 0 itself
// and parts 1 and 2 as documents, which the kernel completes on
const conformingDocs = () => ({
  epochHeader: [headerDoc()],
  platformAccrual: [accrualDoc(PLANNED_A, FUNDER_A)],
  transferReservation: [reservationDoc(RES_A, PLANNED_A)],
  transferReceipt: [receiptDoc(RCPT_A, PLANNED_A)],
  receiptProofPart: [partDoc("e1".repeat(32), PLANNED_A, 1), partDoc("e2".repeat(32), PLANNED_A, 2)],
});

// a frozen descriptor in acquisition's shape, hand-built where the test needs
// a clause acquisition does not build; `deep` false leaves the clause list
// MUTABLE inside the frozen descriptor (the capture case)
const desc = (type, where, limit = 2, { deep = true } = {}) => Object.freeze({ kind: KIND, query: "test", type,
  where: deep ? Object.freeze(where.map((c) => Object.freeze(c))) : where, limit, subjectAccrualId: null });
const HDR = () => desc("epochHeader", [["poolId", "==", POOL], ["epochIndex", "==", EPOCH]]);

// ---- the synthetic transport: e2ProvedQuery's page contract over a store ----
const makeTransport = ({ route = ROUTE, provesResult = true, docs = {}, height = "100", overrides = {}, gate = null } = {}) => {
  const state = { height, docs: { epochHeader: [], platformAccrual: [], transferReservation: [],
    transferReceipt: [], receiptProofPart: [], ...docs }, overrides, calls: [] };
  const matches = (d, where) => where.every(([field, op, value]) => op === "==" && d.fields[field] === value);
  const fetchVerifiedPage = async (req) => {
    state.calls.push(req);
    if (gate) await gate();                       // a transport that waits before reading its request
    const o = state.overrides[req.type];
    if (o !== undefined) return typeof o === "function" ? o(req) : o;
    const found = state.docs[req.type].filter((d) => matches(d, req.where))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return { status: "verified", height: state.height, documents: found.slice(0, req.limit) };
  };
  return { state, transport: { route, provesResult, fetchVerifiedPage } };
};

const member = (funderId, plannedAccrualId, over = {}) => ({
  funderId, plannedAccrualId, effectiveCredits: "900", shareBps: 10000, isSelfShare: false, payable: true, ...over,
});
const mkPlan = (over = {}) => K.buildExpectedRecordPlan({
  scope: { ...BINDING }, encodingRefused: false,
  header: { grossCredits: "1000", feeCredits: "100", memberCount: 1, calcVersion: 1, allocationHash: AH },
  members: [member(FUNDER_A, PLANNED_A)],
  ...over,
});
const verdict = ({ member: m }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: m.effectiveCredits });
const codesOf = (r) => r.reasons.map((x) => x.code);

const main = async () => {
  const ROOT = process.env.TEGARA_PLATFORM_ROOT || path.join(__dirname, "..", "..");
  const { poolLedgerContract } = await import(pathToFileURL(path.join(ROOT, "dist/contract/poolLedger.js")).href);
  const LEDGER = buildV11(poolLedgerContract);
  const adapterOver = (over = {}) => F.createForwardAdapter({ binding: BINDING, transport: makeTransport().transport, ledger: LEDGER, ...over });
  // an adapter over a logging transport, for the zero-issuance checks
  const logged = (over = {}, { binding = BINDING, ledger = LEDGER } = {}) => {
    const { state, transport } = makeTransport(over);
    return { state, adapter: F.createForwardAdapter({ binding, transport, ledger }) };
  };
  // a refusal that must also have issued nothing
  // WIDTH: the window is one macrotask boundary (setImmediate, then a zero
  // timer); it cannot establish the absence of arbitrarily delayed work
  const refusesUnissued = async (name, { state, adapter }, d, re) => {
    const before = state.calls.length;
    await rejects(name, adapter.readPage(d), re);
    ok(`${name}: issued nothing`, state.calls.length === before);
    await new Promise((r) => setImmediate(r)); await new Promise((r) => setTimeout(r, 0));
    ok(`${name}: issued nothing after a macrotask boundary either`, state.calls.length === before);
  };

  // ================= 1. construction =================
  {
    const a = adapterOver();
    ok("a conforming construction returns a frozen object with readPage", Object.isFrozen(a) && typeof a.readPage === "function" && Object.keys(a).join() === "readPage");
    for (const k of ["contractId", "chainId", "contractVersion", "poolId", "epochIndex"]) {
      const b = { ...BINDING }; delete b[k];
      throws(`binding without ${k} refuses`, () => adapterOver({ binding: b }), new RegExp(`binding\\.${k} is required`));
      throws(`binding with ${k} null refuses`, () => adapterOver({ binding: { ...BINDING, [k]: null } }), new RegExp(`binding\\.${k} is required`));
    }
    throws("binding with a sixth member refuses", () => adapterOver({ binding: { ...BINDING, extra: 1 } }), /outside the five scope members/);
    throws("binding poolId not 64-hex refuses", () => adapterOver({ binding: { ...BINDING, poolId: "zz" } }), /poolId must be 64-hex/);
    throws("binding epochIndex negative refuses", () => adapterOver({ binding: { ...BINDING, epochIndex: -1 } }), /epochIndex must be a non-negative/);
    throws("binding epochIndex as a string refuses", () => adapterOver({ binding: { ...BINDING, epochIndex: "7" } }), /epochIndex must be a non-negative/);
    throws("binding epochIndex fractional refuses", () => adapterOver({ binding: { ...BINDING, epochIndex: 1.5 } }), /epochIndex must be a non-negative/);
    throws("binding contractId empty refuses", () => adapterOver({ binding: { ...BINDING, contractId: "" } }), /contractId must be a non-empty string/);
    throws("binding contractId non-string refuses", () => adapterOver({ binding: { ...BINDING, contractId: 5 } }), /contractId must be a non-empty string/);
    throws("a missing transport refuses", () => adapterOver({ transport: undefined }), /plain transport object/);
    throws("transport.route empty refuses", () => adapterOver({ transport: { route: "", provesResult: true, fetchVerifiedPage: async () => ({}) } }), /transport\.route/);
    throws("transport.route non-string refuses", () => adapterOver({ transport: { route: 3, provesResult: true, fetchVerifiedPage: async () => ({}) } }), /transport\.route/);
    throws("transport.provesResult non-boolean refuses", () => adapterOver({ transport: { route: ROUTE, provesResult: "yes", fetchVerifiedPage: async () => ({}) } }), /provesResult must be a strict boolean/);
    throws("transport.provesResult numeric refuses", () => adapterOver({ transport: { route: ROUTE, provesResult: 1, fetchVerifiedPage: async () => ({}) } }), /provesResult must be a strict boolean/);
    throws("transport.fetchVerifiedPage missing refuses (no own member, caught by the capture helper)", () => adapterOver({ transport: { route: ROUTE, provesResult: true } }), /the transport has no own member fetchVerifiedPage/);
    throws("transport.fetchVerifiedPage present but not a function refuses", () => adapterOver({ transport: { route: ROUTE, provesResult: true, fetchVerifiedPage: {} } }), /fetchVerifiedPage must be a function/);
    // a getter that answers the check and serves something else afterwards
    let reads = 0;
    const shifty = { route: ROUTE, get provesResult() { reads += 1; return reads === 1 ? false : "yes"; }, fetchVerifiedPage: async () => ({ status: "verified", height: "1", documents: [] }) };
    throws("a transport whose provesResult is a getter refuses at construction (captured once, or not at all)", () => adapterOver({ transport: shifty }), /the transport's provesResult is accessor-backed/);
    throws("a transport whose route is a getter refuses", () => adapterOver({ transport: { get route() { return ROUTE; }, provesResult: true, fetchVerifiedPage: async () => ({}) } }), /the transport's route is accessor-backed/);
    // a soundness-review finding: BOTH getter forms on EVERY binding member refuse with ZERO invocations
    for (const k of ["contractId", "chainId", "contractVersion", "poolId", "epochIndex"]) {
      let calls = 0;
      const persistent = { ...BINDING };
      Object.defineProperty(persistent, k, { enumerable: true, configurable: true, get() { calls += 1; return BINDING[k]; } });
      Object.freeze(persistent);   // the FROZEN accessor form, a valid input a frozen-only regression would target
      throws(`binding with a frozen persistent ${k} getter refuses by the accessor name`, () => adapterOver({ binding: persistent }), new RegExp(`the binding's ${k} is accessor-backed`));
      ok(`binding with a frozen persistent ${k} getter: zero invocations`, calls === 0);
      let calls2 = 0;
      const replacing = { ...BINDING };
      Object.defineProperty(replacing, k, { enumerable: true, configurable: true, get() {
        calls2 += 1;
        Object.defineProperty(replacing, k, { value: BINDING[k], enumerable: true, configurable: true, writable: true });
        return BINDING[k];
      } });
      let built = null;
      throws(`binding with a self-replacing ${k} getter refuses by the accessor name (never accepted)`, () => { built = adapterOver({ binding: replacing }); }, new RegExp(`the binding's ${k} is accessor-backed`));
      ok(`binding with a self-replacing ${k} getter: zero invocations and no adapter returned`, calls2 === 0 && built === null);
      throws(`binding with ${k} explicitly undefined refuses as required`, () => adapterOver({ binding: { ...BINDING, [k]: undefined } }), new RegExp(`binding\\.${k} is required`));
      // the counts are read again after a macrotask boundary (setImmediate, then
      // a zero timer): the window this test observes, no wider
      await new Promise((r) => setImmediate(r)); await new Promise((r) => setTimeout(r, 0));
      ok(`binding ${k} getters: still zero invocations after a macrotask boundary`, calls === 0 && calls2 === 0);
    }
    // a NON-ENUMERABLE getter on a scope member: Object.keys skips it, the
    // descriptor read does not, and it is refused with zero invocations
    {
      let ncalls = 0;
      const b = { ...BINDING }; delete b.poolId;
      Object.defineProperty(b, "poolId", { enumerable: false, configurable: true, get() { ncalls += 1; return POOL; } });
      throws("a non-enumerable poolId getter refuses by the accessor name", () => adapterOver({ binding: b }), /the binding's poolId is accessor-backed/);
      ok("a non-enumerable poolId getter: zero invocations", ncalls === 0);
    }
    // error precedence, which the capture-first order changed: an extra key is
    // reported before a missing member, and an earlier accessor before a later
    // missing member
    throws("an extra key beside a missing member reports the extra key", () => { const b = { ...BINDING, extra: 1 }; delete b.poolId; return adapterOver({ binding: b }); }, /outside the five scope members/);
    throws("an accessor on contractId beside a missing epochIndex reports the accessor", () => { const b = { ...BINDING }; delete b.epochIndex; Object.defineProperty(b, "contractId", { enumerable: true, configurable: true, get: () => CONTRACT_HEX }); return adapterOver({ binding: b }); }, /the binding's contractId is accessor-backed/);
    // the transport and descriptor accessor controls, with their counts observed
    {
      let tcalls = 0;
      const t = { route: ROUTE, get provesResult() { tcalls += 1; return true; }, fetchVerifiedPage: async () => ({}) };
      throws("transport getter control refuses", () => adapterOver({ transport: t }), /the transport's provesResult is accessor-backed/);
      ok("transport getter control: zero invocations", tcalls === 0);
      let dcalls = 0;
      const d = Object.freeze({ kind: KIND, query: "test", get type() { dcalls += 1; return "epochHeader"; }, where: Object.freeze([Object.freeze(["poolId", "==", POOL]), Object.freeze(["epochIndex", "==", EPOCH])]), limit: 2, subjectAccrualId: null });
      const L0 = logged();
      await rejects("descriptor getter control refuses", L0.adapter.readPage(d), /the descriptor's type is accessor-backed/);
      ok("descriptor getter control: zero invocations and nothing issued", dcalls === 0 && L0.state.calls.length === 0);
      await new Promise((r) => setImmediate(r)); await new Promise((r) => setTimeout(r, 0));
      ok("transport and descriptor getter controls: still zero invocations and nothing issued after a macrotask boundary", tcalls === 0 && dcalls === 0 && L0.state.calls.length === 0);
    }
    throws("a missing ledger table refuses", () => adapterOver({ ledger: undefined }), /v11 document-type table/);
    const noReceipt = { ...LEDGER }; delete noReceipt.transferReceipt;
    throws("a ledger table without one of the five types refuses", () => adapterOver({ ledger: noReceipt }), /no indices for transferReceipt/);
    throws("a ledger type with an empty index list refuses", () => adapterOver({ ledger: { ...LEDGER, epochHeader: { ...LEDGER.epochHeader, indices: [] } } }), /no indices for epochHeader/);
    throws("an index property naming two properties refuses", () => adapterOver({ ledger: { ...LEDGER, epochHeader: { ...LEDGER.epochHeader, indices: [{ name: "x", properties: [{ a: "asc", b: "asc" }] }] } } }), /must name exactly one property/);
    throws("an index property naming no property refuses", () => adapterOver({ ledger: { ...LEDGER, epochHeader: { ...LEDGER.epochHeader, indices: [{ name: "x", properties: [{}] }] } } }), /must name exactly one property/);
  }

  // ================= 2. the descriptor, the binding cross-check, the capture =================
  {
    const L = logged();
    const good = HDR();
    await refusesUnissued("an unfrozen descriptor refuses", L, { ...good }, /FROZEN descriptor/);
    await refusesUnissued("a descriptor of another kind refuses", L, Object.freeze({ ...good, kind: "other" }), /kind is "other"/);
    await refusesUnissued("a descriptor for a non-E2 type refuses", L, Object.freeze({ ...good, type: "pool" }), /not an E2 document type/);
    await refusesUnissued("an empty where list refuses", L, Object.freeze({ ...good, where: Object.freeze([]) }), /non-empty where clause list/);
    await refusesUnissued("a clause that is not a triple refuses", L, desc("epochHeader", [["poolId", POOL]]), /not a \[property, operator, value\] triple/);
    await refusesUnissued("a range operator refuses", L, desc("epochHeader", [["poolId", "==", POOL], ["epochIndex", ">", 1]]), /operator ">" on epochIndex/);
    await refusesUnissued("a clause value that is an object refuses (no nested value to mutate)", L, desc("epochHeader", [["poolId", "==", { v: POOL }], ["epochIndex", "==", EPOCH]]), /poolId clause carries a value that is neither a string nor a safe integer/);
    await refusesUnissued("a clause value that is a fraction refuses", L, desc("epochHeader", [["poolId", "==", POOL], ["epochIndex", "==", 7.5]]), /epochIndex clause carries a value that is neither/);
    await refusesUnissued("a property named twice refuses", L, desc("epochHeader", [["poolId", "==", POOL], ["poolId", "==", POOL]]), /names poolId twice/);
    await refusesUnissued("an accrual subject named twice refuses", L, desc("transferReservation", [["accrualId", "==", PLANNED_A], ["accrualId", "==", PLANNED_A]]), /names accrualId twice/);
    await refusesUnissued("a clause for another pool refuses (the binding cross-check)", L, desc("epochHeader", [["poolId", "==", "ee".repeat(32)], ["epochIndex", "==", EPOCH]]), /for pool eeeeeeee\.\.\., not this adapter's 11111111/);
    await refusesUnissued("a clause for another epoch refuses (the binding cross-check)", L, desc("epochHeader", [["poolId", "==", POOL], ["epochIndex", "==", EPOCH + 1]]), /for epoch 8, not this adapter's 7/);
    await refusesUnissued("a clause with the epoch as a string refuses (strict equality)", L, desc("epochHeader", [["poolId", "==", POOL], ["epochIndex", "==", String(EPOCH)]]), /for epoch 7, not this adapter's 7/);
    await refusesUnissued("limit 0 refuses", L, desc("epochHeader", [["poolId", "==", POOL], ["epochIndex", "==", EPOCH]], 0), /limit 0 is outside 1\.\.100/);
    await refusesUnissued("limit 101 refuses", L, desc("epochHeader", [["poolId", "==", POOL], ["epochIndex", "==", EPOCH]], 101), /limit 101 is outside/);
    await refusesUnissued("a fractional limit refuses", L, desc("epochHeader", [["poolId", "==", POOL], ["epochIndex", "==", EPOCH]], 1.5), /limit 1\.5 is outside/);
    ok("after every descriptor refusal the transport was never called", L.state.calls.length === 0);
    // DEFERRED issuance would land after the refusal returns, so the log is
    // read again after a macrotask boundary (setImmediate and a zero timer)
    await new Promise((r) => setImmediate(r)); await new Promise((r) => setTimeout(r, 0));
    ok("and still not called after a macrotask boundary (no deferred issuance)", L.state.calls.length === 0);
    // ACCESSOR-BACKED MEMBERS: a frozen descriptor can carry a getter whose
    // value changes between the check and a later read, so it is refused
    let flip = "epochHeader";
    const getterType = Object.freeze({ kind: KIND, query: "test", get type() { return flip; }, where: HDR().where, limit: 2, subjectAccrualId: null });
    await refusesUnissued("a descriptor whose type is a getter refuses (an accessor is not a stable member)", L, getterType, /the descriptor's type is accessor-backed/);
    flip = "transferReceipt";
    const clauseWithGetter = ["epochIndex", "==", null];
    Object.defineProperty(clauseWithGetter, "2", { get: () => EPOCH, enumerable: true, configurable: false });
    Object.freeze(clauseWithGetter);
    const getterClause = Object.freeze({ kind: KIND, query: "test", type: "epochHeader", where: Object.freeze([Object.freeze(["poolId", "==", POOL]), clauseWithGetter]), limit: 2, subjectAccrualId: null });
    ok("the clause-getter fixture is a real array triple whose value position is a getter", Array.isArray(clauseWithGetter) && clauseWithGetter.length === 3 && !Object.prototype.hasOwnProperty.call(Object.getOwnPropertyDescriptor(clauseWithGetter, "2"), "value"));
    await refusesUnissued("a clause value that is a getter refuses on the accessor check itself", L, getterClause, /the epochHeader descriptor's clause 1's 2 is accessor-backed/);
    const getterLimit = Object.freeze({ kind: KIND, query: "test", type: "epochHeader", where: HDR().where, get limit() { return 2; }, subjectAccrualId: null });
    await refusesUnissued("a descriptor whose limit is a getter refuses", L, getterLimit, /the descriptor's limit is accessor-backed/);

    // THE CAPTURE: a mutable clause list inside a frozen descriptor, changed
    // while the transport waits, does not change what the transport reads
    let release;
    const gate = () => new Promise((r) => { release = r; });
    const { state, transport } = makeTransport({ docs: conformingDocs(), gate });
    const a = F.createForwardAdapter({ binding: BINDING, transport, ledger: LEDGER });
    const mutable = desc("epochHeader", [["poolId", "==", POOL], ["epochIndex", "==", EPOCH]], 2, { deep: false });
    const pending = a.readPage(mutable);
    await new Promise((r) => setImmediate(r));   // the transport is now waiting on the gate
    mutable.where[0][2] = "ee".repeat(32);       // the pool clause changes under the pending read
    mutable.where.push(["funderId", "==", FUNDER_A]);
    release();
    const ans = await pending;
    const got = state.calls[0].where;
    ok("the transport receives the captured clause list, not the descriptor's array, and it is frozen",
      got !== mutable.where && Object.isFrozen(got) && got.every((c) => Object.isFrozen(c)) && got.length === 2 && got[0][2] === POOL && got[1][2] === EPOCH);
    ok("the read that was issued is the validated one and serves the header", ans.status === "served" && ans.documents.length === 1 && ans.documents[0].id === HDR_ID);
  }

  // ================= 3. index resolution =================
  {
    const L = logged({ docs: conformingDocs() });
    const a = L.adapter;
    const routeOf = async (d) => (await a.readPage(d)).route;
    ok("header (poolId, epochIndex) resolves locally to epochHeader.byPoolEpoch", await routeOf(HDR()) === `${ROUTE}:epochHeader.byPoolEpoch`);
    ok("the accrual enumeration (poolId, epochIndex) resolves locally to platformAccrual.byPoolEpoch", await routeOf(desc("platformAccrual", [["poolId", "==", POOL], ["epochIndex", "==", EPOCH]], 9)) === `${ROUTE}:platformAccrual.byPoolEpoch`);
    ok("the accrual (poolId, funderId, epochIndex) resolves locally to platformAccrual.byPoolFunderEpoch", await routeOf(desc("platformAccrual", [["poolId", "==", POOL], ["funderId", "==", FUNDER_A], ["epochIndex", "==", EPOCH]])) === `${ROUTE}:platformAccrual.byPoolFunderEpoch`);
    ok("a reservation (poolId, accrualId) resolves locally to transferReservation.byPool", await routeOf(desc("transferReservation", [["poolId", "==", POOL], ["accrualId", "==", PLANNED_A]])) === `${ROUTE}:transferReservation.byPool`);
    ok("parts (poolId, accrualId) resolve locally to receiptProofPart.byPool", await routeOf(desc("receiptProofPart", [["poolId", "==", POOL], ["accrualId", "==", PLANNED_A]], 8)) === `${ROUTE}:receiptProofPart.byPool`);
    // THE GAP, a soundness-review finding: the clause acquisition builds for a receipt
    await refusesUnissued("a receipt (poolId, accrualId) resolves to NO registered index on transferReceipt (a soundness-review finding)", L,
      desc("transferReceipt", [["poolId", "==", POOL], ["accrualId", "==", PLANNED_A]]),
      /no registered index on transferReceipt serves the clause \(poolId, accrualId\); the registered indices are byAccrual\(accrualId\), byTransition\(transitionHash\), byPool\(poolId, blockHeight\)/);
    ok("a receipt by (accrualId) alone resolves locally to transferReceipt.byAccrual (the servable shape)", await routeOf(desc("transferReceipt", [["accrualId", "==", PLANNED_A]])) === `${ROUTE}:transferReceipt.byAccrual`);
    ok("a receipt by (poolId) alone resolves locally to the byPool prefix", await routeOf(desc("transferReceipt", [["poolId", "==", POOL]])) === `${ROUTE}:transferReceipt.byPool`);
    ok("a reservation by (accrualId) alone resolves locally to transferReservation.byAccrual", await routeOf(desc("transferReservation", [["accrualId", "==", PLANNED_A]])) === `${ROUTE}:transferReservation.byAccrual`);
    await refusesUnissued("the ORDERED prefix rule: (epochIndex, poolId) does not resolve to byPoolEpoch", L, desc("epochHeader", [["epochIndex", "==", EPOCH], ["poolId", "==", POOL]]), /no registered index on epochHeader serves the clause \(epochIndex, poolId\)/);
    await refusesUnissued("the ORDERED prefix rule on a three-property index: (poolId, epochIndex, funderId) does not resolve", L, desc("platformAccrual", [["poolId", "==", POOL], ["epochIndex", "==", EPOCH], ["funderId", "==", FUNDER_A]]), /no registered index on platformAccrual serves the clause \(poolId, epochIndex, funderId\)/);
    await refusesUnissued("a clause longer than every index refuses", L, desc("epochHeader", [["poolId", "==", POOL], ["epochIndex", "==", EPOCH], ["memberCount", "==", 1]]), /no registered index on epochHeader/);
    await refusesUnissued("a clause on an unindexed property refuses", L, desc("epochHeader", [["grossCredits", "==", "1"]]), /no registered index on epochHeader serves the clause \(grossCredits\)/);
    await refusesUnissued("a clause on a different unindexed property refuses too", L, desc("transferReservation", [["transitionHash", "==", TH]]), /no registered index on transferReservation serves the clause \(transitionHash\)/);
    // RESOLUTION READS THE SUPPLIED TABLE: a renamed index shows in the route,
    // and an index removed from the table stops resolving
    const renamed = { ...LEDGER, epochHeader: { ...LEDGER.epochHeader, indices: [{ name: "byPoolEpochX", properties: [{ poolId: "asc" }, { epochIndex: "asc" }], unique: true }] } };
    const ar = F.createForwardAdapter({ binding: BINDING, transport: makeTransport({ docs: conformingDocs() }).transport, ledger: renamed });
    ok("resolution reads the supplied table: a renamed header index is named in the route", (await ar.readPage(HDR())).route === `${ROUTE}:epochHeader.byPoolEpochX`);
    const dropped = { ...LEDGER, transferReservation: { ...LEDGER.transferReservation, indices: [{ name: "byAccrual", properties: [{ accrualId: "asc" }], unique: true }] } };
    const LD = logged({ docs: conformingDocs() }, { ledger: dropped });
    await refusesUnissued("resolution reads the supplied table: a reservation (poolId, accrualId) stops resolving when byPool is absent from it", LD, desc("transferReservation", [["poolId", "==", POOL], ["accrualId", "==", PLANNED_A]]), /no registered index on transferReservation serves the clause \(poolId, accrualId\); the registered indices are byAccrual\(accrualId\)/);
    // two indices sharing a prefix: the FIRST declared one resolves, which is
    // this module's rule and not an observation of Platform's choice
    const twin = { ...LEDGER, epochHeader: { ...LEDGER.epochHeader, indices: [{ name: "first", properties: [{ poolId: "asc" }, { epochIndex: "asc" }] }, { name: "second", properties: [{ poolId: "asc" }, { epochIndex: "asc" }] }] } };
    const at = F.createForwardAdapter({ binding: BINDING, transport: makeTransport({ docs: conformingDocs() }).transport, ledger: twin });
    ok("two indices sharing the prefix: the first declared one is named (a derivation, stated as such)", (await at.readPage(HDR())).route === `${ROUTE}:epochHeader.first`);
  }

  // ================= 4. the served envelope =================
  {
    const { transport } = makeTransport({ docs: conformingDocs(), height: "123" });
    const a = F.createForwardAdapter({ binding: BINDING, transport, ledger: LEDGER });
    const ans = await a.readPage(HDR());
    ok("a served answer carries exactly status, proved, route, scope, height, documents",
      Object.keys(ans).sort().join() === "documents,height,proved,route,scope,status" && ans.status === "served");
    ok("scope is the BINDING, member for member", same(ans.scope, BINDING));
    ok("proved is the transport's declaration (true)", ans.proved === true);
    ok("height is the page's height, unchanged", ans.height === "123");
    ok("documents are { id, fields } with the store's fields, whole", ans.documents.length === 1 && Object.keys(ans.documents[0]).join() === "id,fields" && ans.documents[0].id === HDR_ID && same(ans.documents[0].fields, headerDoc().fields));
    ok("the answer is deeply frozen, the document wrapper and its fields included", deepFrozen(ans) && Object.isFrozen(ans.documents[0]) && Object.isFrozen(ans.documents[0].fields));
    // a SECOND adapter under a DIFFERENT binding serves reads for that pool
    // and epoch with THAT binding as scope, so scope is not one fixture
    const docs2 = { epochHeader: [doc("88".repeat(32), { poolId: POOL2, epochIndex: 3, grossCredits: "1", feeCredits: "0", memberCount: 1, calcVersion: 1, allocationHash: AH })] };
    const T2 = makeTransport({ docs: docs2, height: "9" });
    const a2 = F.createForwardAdapter({ binding: BINDING2, transport: T2.transport, ledger: LEDGER });
    const ans2 = await a2.readPage(desc("epochHeader", [["poolId", "==", POOL2], ["epochIndex", "==", 3]]));
    ok("a second adapter under a different binding serves its pool and epoch with THAT binding as scope, and issued its own contractId",
      ans2.status === "served" && same(ans2.scope, BINDING2) && ans2.documents[0].id === "88".repeat(32) && T2.state.calls[0].contractId === BINDING2.contractId);
    await refusesUnissued("that second adapter refuses a clause for the first adapter's pool", { state: T2.state, adapter: a2 }, HDR(), /for pool 11111111\.\.\., not this adapter's 22222222/);
    // the same route string paired with BOTH declarations: proved follows the declaration
    const declaredTrue = F.createForwardAdapter({ binding: BINDING, transport: makeTransport({ route: "documents.fetch", provesResult: true, docs: conformingDocs() }).transport, ledger: LEDGER });
    const declaredFalse = F.createForwardAdapter({ binding: BINDING, transport: makeTransport({ route: "documents.fetch", provesResult: false, docs: conformingDocs() }).transport, ledger: LEDGER });
    const pt = await declaredTrue.readPage(HDR());
    const pf = await declaredFalse.readPage(HDR());
    ok("the same route string with both declarations: proved is the declaration, not the route text",
      pt.proved === true && pf.proved === false && pt.route === pf.route && pf.route === "documents.fetch:epochHeader.byPoolEpoch" && pf.status === "served");
    // a FULL page is passed through with every document and its identities,
    // at the descriptor's limit, with the checker's non-null cursor dropped
    const docs = conformingDocs();
    docs.receiptProofPart = [partDoc("e1".repeat(32), PLANNED_A, 1), partDoc("e2".repeat(32), PLANNED_A, 2), partDoc("e3".repeat(32), PLANNED_A, 3)];
    const TF = makeTransport({ docs, height: "456" });
    const full = F.createForwardAdapter({ binding: BINDING, transport: TF.transport, ledger: LEDGER });
    const fp = await full.readPage(desc("receiptProofPart", [["poolId", "==", POOL], ["accrualId", "==", PLANNED_A]], 3));
    ok("a FULL page (3 of limit 3) is served with all three documents and their identities, requested at limit 3, without the checker's cursor",
      fp.status === "served" && fp.documents.length === 3 && fp.documents.map((d) => d.fields.partIndex).join() === "1,2,3"
      && fp.documents.map((d) => d.id).join() === ["e1", "e2", "e3"].map((h) => h.repeat(32)).join() && TF.state.calls[0].limit === 3 && !("cursor" in fp));
    ok("height is the page's height on a non-header read", fp.height === "456");
    // an EMPTY verified page is served empty
    const empty = F.createForwardAdapter({ binding: BINDING, transport: makeTransport({ docs: {} }).transport, ledger: LEDGER });
    const ep = await empty.readPage(HDR());
    ok("an empty verified page is served with an empty document list (acquisition decides what it means)", ep.status === "served" && ep.documents.length === 0 && ep.proved === true && ep.height === "100");
    // the page checker's cursor member is accepted and ignored
    const withCursor = F.createForwardAdapter({ binding: BINDING, transport: makeTransport({ overrides: { epochHeader: { status: "verified", height: "5", documents: [headerDoc()], cursor: null } } }).transport, ledger: LEDGER });
    const cp = await withCursor.readPage(HDR());
    ok("a page carrying the checker's optional cursor is served without it", cp.status === "served" && cp.documents.length === 1 && !("cursor" in cp));
  }

  // ================= 5. passthrough =================
  {
    for (const status of ["unserved", "unverified"]) {
      const { state, transport } = makeTransport({ overrides: { epochHeader: { status } } });
      const a = F.createForwardAdapter({ binding: BINDING, transport, ledger: LEDGER });
      const ans = await a.readPage(HDR());
      ok(`${status} passes through as exactly { status }, after exactly one call`, Object.keys(ans).join() === "status" && ans.status === status && Object.isFrozen(ans) && state.calls.length === 1);
    }
  }

  // ================= 6. faults propagate, on a header read and on a receipt read =================
  {
    const at = (over) => F.createForwardAdapter({ binding: BINDING, transport: makeTransport(over).transport, ledger: LEDGER });
    const hdr = HDR();
    const rcpt = desc("transferReceipt", [["accrualId", "==", PLANNED_A]]);
    await rejects("a transport that throws propagates as the page checker's fault", at({ overrides: { epochHeader: () => { throw new Error("dapi down"); } } }).readPage(hdr), /e2ProvedQuery: the injected page fetch failed \(dapi down\)/);
    await rejects("a fault on a receipt read propagates the same way", at({ overrides: { transferReceipt: () => { throw new Error("dapi down"); } } }).readPage(rcpt), /e2ProvedQuery: the injected page fetch failed \(dapi down\)/);
    await rejects("a page without a height is the checker's refusal", at({ overrides: { epochHeader: { status: "verified", documents: [] } } }).readPage(hdr), /e2ProvedQuery:.*height/);
    await rejects("a page outside the checker's status set refuses", at({ overrides: { epochHeader: { status: "served" } } }).readPage(hdr), /e2ProvedQuery:.*status verified, unserved or unverified/);
    await rejects("a non-ascending page is the checker's refusal", at({ overrides: { receiptProofPart: { status: "verified", height: "1", documents: [partDoc("e2".repeat(32), PLANNED_A, 2), partDoc("e1".repeat(32), PLANNED_A, 1)] } } }).readPage(desc("receiptProofPart", [["poolId", "==", POOL], ["accrualId", "==", PLANNED_A]], 8)), /not strictly ascending/);
    await rejects("a page longer than the limit is the checker's refusal", at({ overrides: { epochHeader: { status: "verified", height: "1", documents: [headerDoc(), doc("78".repeat(32), {}), doc("79".repeat(32), {})] } } }).readPage(hdr), /no longer than its limit/);
    await rejects("a document without plain fields refuses", at({ overrides: { epochHeader: { status: "verified", height: "1", documents: [{ id: HDR_ID }] } } }).readPage(hdr), /carries no plain fields object/);
    await rejects("a receipt document without plain fields refuses", at({ overrides: { transferReceipt: { status: "verified", height: "1", documents: [{ id: RCPT_A }] } } }).readPage(rcpt), /transferReceipt page's document d2d2d2d2\.\.\. carries no plain fields object/);
    await rejects("a document with a member outside { id, fields } refuses", at({ overrides: { epochHeader: { status: "verified", height: "1", documents: [{ id: HDR_ID, fields: {}, memberCount: 1 }] } } }).readPage(hdr), /carries memberCount, outside the transport's \{ id, fields \} shape/);
    await rejects("a receipt document with a member outside { id, fields } refuses", at({ overrides: { transferReceipt: { status: "verified", height: "1", documents: [{ id: RCPT_A, fields: {}, proofPartCount: 3 }] } } }).readPage(rcpt), /transferReceipt page's document d2d2d2d2\.\.\. carries proofPartCount, outside/);
    await rejects("a document whose fields carry a function is the checker's plain-data refusal", at({ overrides: { epochHeader: { status: "verified", height: "1", documents: [{ id: HDR_ID, fields: { f: () => 1 } }] } } }).readPage(hdr), /not plain data/);
  }

  // ================= 7. the transport call =================
  {
    const { state, transport } = makeTransport({ docs: conformingDocs() });
    const a = F.createForwardAdapter({ binding: BINDING, transport, ledger: LEDGER });
    const d = desc("platformAccrual", [["poolId", "==", POOL], ["funderId", "==", FUNDER_A], ["epochIndex", "==", EPOCH]], 2);
    await a.readPage(d);
    ok("one transport call per read", state.calls.length === 1);
    const c = state.calls[0];
    ok("the call carries the binding's contractId, the descriptor's type, the captured where and limit, orderBy null and startAfter null",
      c.contractId === CONTRACT_HEX && c.type === "platformAccrual" && same(c.where, d.where) && c.limit === 2 && c.orderBy === null && c.startAfter === null
      && Object.keys(c).sort().join() === "contractId,limit,orderBy,startAfter,type,where");
    await a.readPage(d);
    ok("a second accrual read is a second call (nothing is cached here)", state.calls.length === 2);
    await a.readPage(HDR()); await a.readPage(HDR());
    ok("a second header read is a second call too", state.calls.length === 4 && state.calls[2].type === "epochHeader" && state.calls[3].type === "epochHeader");
  }

  // ================= 8. composition with acquisition and the kernel =================
  {
    const drive = async ({ plan = mkPlan(), transportOver = {}, bindingOver = {} } = {}) => {
      const { state, transport } = makeTransport({ docs: conformingDocs(), ...transportOver });
      const adapter = F.createForwardAdapter({ binding: { ...BINDING, ...bindingOver }, transport, ledger: LEDGER });
      const issued = [];
      const readPage = async (d) => { issued.push(d); return adapter.readPage(d); };
      const run = await A.acquireEpochEvidence({ plan, readPage, executionVerdict: verdict });
      return { state, issued, evidence: run.evidence, result: K.evaluateEpochForwardState({ plan, evidence: run.evidence }) };
    };
    // a soundness-review finding REPAIRED: the real acquisition unit's receipt reads now resolve to
    // transferReceipt.byAccrual, and a conforming store drives the kernel to
    // COMPLETE through the real adapter, every call carrying exactly its
    // descriptor's clause (the schema-backed check, included here as a regression)
    {
      const { state, issued, evidence, result } = await drive();
      ok(`composition: a conforming store drives the kernel to complete through the real adapter (${result.state})`, result.state === "complete");
      ok("the full chain was issued and served, the receipt reads riding byAccrual",
        issued.map((d) => d.query).join() === "header,accrualEnumeration,accrual,reservationPinned,reservationEnumerated,receipt,parts"
        && state.calls.length === 7 && evidence.dependents[FUNDER_A].receipt.route === `${ROUTE}:transferReceipt.byAccrual`
        && evidence.dependents[FUNDER_A].reservationPinned.route === `${ROUTE}:transferReservation.byPool`);
      ok("every call carries its descriptor's type, captured where and limit, the binding's contractId, orderBy null and startAfter null",
        state.calls.every((c, i) => c.type === issued[i].type && same(c.where, issued[i].where) && c.limit === issued[i].limit && c.contractId === CONTRACT_HEX && c.orderBy === null && c.startAfter === null));
      ok("the receipt clause the transport received is exactly [[accrualId, ==, subject]], no pool predicate",
        same(state.calls[5].where, [["accrualId", "==", PLANNED_A]]) && state.calls[5].type === "transferReceipt");
    }
    // incomplete: the absent accrual's inspection sweep, all three components resolving
    {
      const { state, result, evidence } = await drive({ transportOver: { docs: { epochHeader: [headerDoc()] } } });
      ok(`composition: an absent accrual with an empty inspection sweep is incomplete through the real adapter (${result.state})`,
        result.state === "incomplete" && codesOf(result).includes("INCOMPLETE_ACCRUAL_ABSENT")
        && evidence.dependents[FUNDER_A].machinerySweep.receipt.route === `${ROUTE}:transferReceipt.byAccrual`
        && state.calls.map((c) => c.type).join() === "epochHeader,platformAccrual,platformAccrual,transferReservation,transferReceipt,receiptProofPart");
    }
    // the payable chain's receipt ABSENCE through the real adapter
    {
      const docs = conformingDocs(); docs.transferReceipt = [];
      const { result, evidence } = await drive({ transportOver: { docs } });
      ok(`composition: a served accrual with no receipt anywhere is a proved absence and incomplete through the real adapter (${result.state})`,
        result.state === "incomplete" && codesOf(result).includes("INCOMPLETE_RECEIPT_ABSENT") && evidence.dependents[FUNDER_A].receipt.status === "proved-absence"
        && evidence.dependents[FUNDER_A].receipt.route === `${ROUTE}:transferReceipt.byAccrual`);
    }
    // cross-pool OCCUPANCY of the planned key through the real adapter and kernel
    {
      const docs = { epochHeader: [headerDoc()], transferReceipt: [doc(RCPT_A, { poolId: POOL2, accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 3 })] };
      const { result, evidence } = await drive({ transportOver: { docs } });
      const sweep = evidence.dependents[FUNDER_A].machinerySweep;
      ok("composition: a receipt under the planned key in another pool is counted by the sweep and refused by the kernel as dependents without an accrual",
        sweep.receipt.count === 1 && result.state === "refused" && result.reasons.some((x) => x.code === "REFUSED_DEPENDENTS_WITHOUT_ACCRUAL" && x.recordKey.endsWith(":receipt")));
    }
    // the widening: a receipt under the right accrual in the WRONG pool refuses, never absent
    {
      const docs = conformingDocs();
      docs.transferReceipt = [doc(RCPT_A, { poolId: POOL2, accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 3 })];
      const { result, evidence } = await drive({ transportOver: { docs } });
      ok("composition: a wrong-pool receipt under the right accrual is served by the adapter and refused by the kernel as a different key, never absent",
        evidence.dependents[FUNDER_A].receipt.status === "served" && result.state === "refused"
        && result.reasons.some((x) => x.code === "REFUSED_NONCONFORMING_ANSWER" && x.recordKey.startsWith("receipt:"))
        && !codesOf(result).includes("INCOMPLETE_RECEIPT_ABSENT"));
    }
    // unproved: unserved pages
    {
      const { result } = await drive({ transportOver: { overrides: { epochHeader: { status: "unserved" }, platformAccrual: { status: "unserved" } } } });
      ok(`composition: unserved pages drive the kernel to unproved (${result.state})`, result.state === "unproved" && codesOf(result).includes("UNPROVED_QUERY_UNSERVED") && !codesOf(result).includes("UNPROVED_PROOF_UNVERIFIED"));
    }
    // unproved: a bare route, stated by the transport and carried by the adapter
    {
      const { result, evidence } = await drive({ transportOver: { route: "documents.fetch", provesResult: false } });
      ok(`composition: a transport declaring no proof drives the kernel to unproved on the route (${result.state})`,
        result.state === "unproved" && codesOf(result).includes("UNPROVED_ROUTE_NOT_PROVED") && evidence.header.route === "documents.fetch:epochHeader.byPoolEpoch" && evidence.header.proved === false);
    }
    // refused: an adapter bound to a different contract version than the plan
    {
      const { result, evidence } = await drive({ bindingOver: { contractVersion: 12 } });
      ok(`composition: an adapter bound to version 12 under a version-11 plan is refused for scope (${result.state})`,
        result.state === "refused" && codesOf(result).includes("REFUSED_SCOPE_MISMATCH") && evidence.header.scope.contractVersion === 12);
      ok("the answer's scope came from the binding and not from the plan (the plan says 11, every answer in the bundle says 12)",
        mkPlan().scope.contractVersion === 11 && evidence.header.scope.contractVersion === 12 && evidence.accruals[FUNDER_A].scope.contractVersion === 12 && evidence.accrualEnumeration.scope.contractVersion === 12);
    }
    // unverified passthrough reaches the kernel's own code, distinct from unserved
    {
      const { result } = await drive({ transportOver: { overrides: { platformAccrual: { status: "unverified" } } } });
      ok(`composition: an unverified accrual page drives the kernel to unproved on proof (${result.state})`, result.state === "unproved" && codesOf(result).includes("UNPROVED_PROOF_UNVERIFIED") && !codesOf(result).includes("UNPROVED_QUERY_UNSERVED"));
    }
  }

  console.log(`\ne2ForwardAdapterTest: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exitCode = 1;
};

main().catch((e) => { console.error(`e2ForwardAdapterTest: unexpected throw: ${e.message}`); process.exitCode = 1; });
