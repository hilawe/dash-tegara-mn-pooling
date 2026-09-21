/**
 * e2ForwardAdapter: THE FORWARD ADAPTER of the forward lifecycle kernel
 * (contract FORWARD_LIFECYCLE_KERNEL_CONTRACT.md, section 3.2.1, "the forward
 * adapter is the boundary that supplies provenance"). It is the Platform-facing
 * implementation of the `readPage(descriptor)` contract acquisition injects
 * (e2Acquire.cjs, "THE INJECTED ADAPTER CONTRACT"), built over ONE proved-query
 * page (e2ProvedQuery.cjs's provedQueryPage, single page, the descriptor's
 * limit) and an injected transport.
 *
 * WHAT IT ESTABLISHES, in one sentence: every statement in a served answer
 * about HOW the read happened (`proved`, `route`, `scope`, `height`) is bound
 * to this adapter's binding, the transport's declaration about itself, the
 * registered index the clause RESOLVES TO under the ordered-prefix rule, and
 * the page's own authenticated height, and none of it is copied from a plan,
 * because this module never sees one. The resolved index is this module's
 * derivation from the declared table; it is not evidence of which index
 * Platform selected, since neither the request nor the page names one.
 *
 * WHERE EACH PROVENANCE MEMBER COMES FROM (contract 3.2.1's provenance table,
 * the adapter's side):
 *   scope    the BINDING this adapter was constructed with (contractId, chainId,
 *            contractVersion, poolId, epochIndex), CROSS-CHECKED against every
 *            clause of the descriptor that names poolId or epochIndex. A
 *            descriptor for another pool or epoch is REFUSED, never issued
 *            under this scope. WIDTH, STATED: for an accrual-keyed read (a
 *            reservation, receipt or part clause carries no epochIndex) the
 *            scope's epochIndex records WHICH ADAPTER issued the read, not a
 *            constraint the query applied to the documents.
 *   proved   the transport's declared `provesResult`, a strict boolean stated
 *            at construction for the route the transport actually uses. A
 *            transport declaring false yields served answers with
 *            `proved: false`, which the kernel reports as
 *            UNPROVED_ROUTE_NOT_PROVED (a soundness-review finding), so that outcome is
 *            reachable through this module rather than stamped away.
 *   route    `<transport.route>:<type>.<index name>`, naming the transport's
 *            route and the registered index the clause resolved to here (a
 *            derivation, see above, not an observation of Platform's choice).
 *   height   the verified page's own authenticated height, unchanged.
 *   documents  { id, fields } per served document, the transport's shape,
 *            passed through after the page checker's walk.
 *
 * THE INDEX TABLE IS THE LEDGER'S OWN DECLARATION. The adapter is constructed
 * with the v11 document-type table produced by contractV11.cjs's buildV11 (the
 * same builder the registered contract came from), and resolves each
 * descriptor's equality clause to the registered index whose property list
 * the clause is an ordered PREFIX of. A clause no registered index serves is
 * REFUSED BY NAME rather than issued or rewritten, because the descriptor is
 * acquisition's record of what was issued and this module must not issue
 * something else under it. THAT REFUSAL FOUND a soundness-review finding: acquisition's receipt
 * reads carried the clause (poolId, accrualId), and `transferReceipt` registers
 * `byAccrual`, `byTransition` and `byPool(poolId, blockHeight)`, none of which
 * that clause prefixes, so the first composition refused at the receipt read.
 * Acquisition's receipt descriptors are now (accrualId) alone against the
 * unique byAccrual index (contract revision 12); the reservation and part types
 * keep (poolId, accrualId) against their byPool index. The test still refuses
 * the old clause by hand and drives the real acquisition unit to every kernel
 * state through this adapter. The refusal is this module's derivation from the
 * declared indices, not a network measurement.
 *
 * THE DESCRIPTOR IS VALIDATED AND EVERY MEMBER USED IS CAPTURED before anything
 * is issued: `kind`, `type`, `limit` and each clause are read through their OWN
 * DATA DESCRIPTORS (an accessor-backed member is refused, since a frozen object
 * can still carry a getter whose value changes between the check and a later
 * read), and readPage uses only the captured values after its await. THE SAME
 * RULE HOLDS AT CONSTRUCTION for the binding's five members and the transport's
 * three, each member's own descriptor inspected BEFORE its value is checked
 * (in sequence, member by member; a missing first member stops the loop
 * before later descriptors are read), so no own scope-member getter on an ordinary
 * object is invoked (a soundness-review finding).
 * WIDTH, STATED: `isPlain` admits an object by its reported prototype, and a
 * Proxy can report Object.prototype while trapping ownKeys or
 * getOwnPropertyDescriptor to run code of its own; what this boundary
 * establishes is a property of ordinary objects, the same width the page
 * checker states for its walk. The
 * transport receives a frozen copy of the validated clauses, never the
 * descriptor's own array, so a mutable clause inside a frozen descriptor
 * cannot change what is read after it was checked (a pre-commit check's
 * constructions, with a transport that waits before reading its request).
 * Nothing is issued for a descriptor that is refused, deferred or otherwise.
 *
 * THE INJECTED TRANSPORT CONTRACT: { route, provesResult, fetchVerifiedPage }
 *   route            a non-empty string naming the transport's query route;
 *   provesResult     strict boolean, whether that route obtains proof;
 *   fetchVerifiedPage  e2ProvedQuery's page contract, called ONCE per read with
 *                    { contractId, type, where, orderBy: null, limit,
 *                    startAfter: null }: { status: "verified", documents,
 *                    height } with every document { id: 64-hex, fields: plain
 *                    object } and the page SORTED ASCENDING BY id (the page
 *                    checker's ascent rule; the live transport re-sorts, which
 *                    changes presentation order and never the proved set), or
 *                    { status: "unserved" } | { status: "unverified" }. The
 *                    where clause reaches the transport as the descriptor
 *                    carries it (64-hex strings and integers); byte conversion
 *                    is the transport's concern.
 *
 * SINGLE PAGE, THE DESCRIPTOR'S LIMIT, NO CURSOR. startAfter is always null and
 * orderBy is always null (an equality-only clause over a registered index; the
 * audit's unique-key reads run live without orderBy). A FULL page is served
 * with every document, because the request limit is the legal bound plus one
 * and a full page is the over-bound set the kernel refuses with codes it has
 * (contract 3.2.1); this module neither widens nor truncates it. The page
 * checker's cursor member is ignored. An EMPTY verified page is served with an
 * empty document list; acquisition converts that to a proved absence on a
 * unique read over a proved route and refuses it over an unproved one (R18).
 *
 * FAULTS PROPAGATE, THEY ARE NOT EVIDENCE. A page the checker refuses (a
 * malformed envelope, a non-ascending page, a limit overrun), a transport that
 * throws, or a document without plain fields all THROW out of readPage;
 * acquisition catches that as an adapter fault and refuses the run naming it
 * (the D8 resolution: nothing here classifies a caught value into an answer).
 *
 * WHAT IT DOES NOT ESTABLISH, stated:
 *   - that the transport's declarations are true. `provesResult` and `route`
 *     are what the transport SAYS about itself; the proof verification behind
 *     a "verified" page is the transport's obligation, as e2ProvedQuery states.
 *   - that the supplied index table IS the registered contract's. It is checked
 *     for shape (the five E2 types, each with a non-empty indices list) and its
 *     origin is assumed.
 *   - that a clause this module refuses is unservable ON THE NETWORK. The
 *     refusal is derived from the declared indices under the ordered-prefix
 *     rule, which is an argument from the declaration, not a live measurement.
 *   - that Platform accepts an equality-only query without orderBy for every
 *     resolved index. The audit's unique-key reads establish it for byAccrual
 *     and byPoolEpoch shapes; the enumeration shapes await the live gate.
 *   - anything about the descriptor's `query` or `subjectAccrualId` members:
 *     the adapter resolves the read from `type`, `where` and `limit` alone and
 *     never reads acquisition's private query names.
 */
"use strict";

const { provedQueryPage } = require("./e2ProvedQuery.cjs");
const { E2_TYPES } = require("./contractV11.cjs");

const HEX64 = /^[0-9a-f]{64}$/;
const DESCRIPTOR_KIND = "tegara.e2.queryDescriptor.v1";
const SCOPE_KEYS = Object.freeze(["contractId", "chainId", "contractVersion", "poolId", "epochIndex"]);
const refuse = (why) => { throw new Error(`e2ForwardAdapter: ${why}; refusing`); };
const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v)
  && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
// freezes the WHOLE graph, descending into containers that are already frozen
// as well: a pre-frozen array holding fresh mutable members would otherwise
// stop the descent one level short (a pre-commit check's construction). The
// graphs frozen here are plain data from the page checker's walk, which admits
// no cycles, so the descent terminates.
const deepFreeze = (v) => {
  if (v && typeof v === "object") {
    Object.freeze(v);
    for (const k of Object.keys(v)) deepFreeze(v[k]);
  }
  return v;
};

// a member read through its OWN DATA DESCRIPTOR: a frozen object can still
// carry a getter, whose value can differ between the check and a later read
// (a pre-commit check's construction, a `type` getter flipping while the
// transport waits), so an accessor-backed member is refused and every member
// used after the await is the value captured here.
const dataMember = (obj, key, what) => {
  const dsc = Object.getOwnPropertyDescriptor(obj, key);
  if (!dsc) refuse(`${what} has no own member ${key}`);
  if (!Object.prototype.hasOwnProperty.call(dsc, "value")) refuse(`${what}'s ${key} is accessor-backed; a getter is not a stable descriptor member`);
  return dsc.value;
};

// ---- the binding, validated the way the kernel validates a scope ----
// CAPTURE FIRST, THEN VALIDATE THE CAPTURED VALUES (a soundness-review finding): the first cut ran a
// requiredness loop over `b[k]` BEFORE the descriptor capture, which invoked a
// getter, so a configurable getter that replaced itself with a data property on
// that first read passed the later check. Nothing below reads a member through
// the binding object; every value comes from its own data descriptor, read once.
// Object.keys does not invoke accessors.
const validateBinding = (b) => {
  if (!isPlain(b)) refuse("createForwardAdapter needs a plain binding object");
  for (const k of Object.keys(b)) {
    if (!SCOPE_KEYS.includes(k)) refuse(`binding carries ${k}, outside the five scope members`);
  }
  const v = {};
  for (const k of SCOPE_KEYS) {
    const dsc = Object.getOwnPropertyDescriptor(b, k);
    if (!dsc) refuse(`binding.${k} is required`);
    if (!Object.prototype.hasOwnProperty.call(dsc, "value")) refuse(`the binding's ${k} is accessor-backed; a getter is not a stable descriptor member`);
    if (dsc.value === undefined || dsc.value === null) refuse(`binding.${k} is required`);
    v[k] = dsc.value;
  }
  if (typeof v.contractId !== "string" || v.contractId.length === 0) refuse("binding.contractId must be a non-empty string");
  if (typeof v.chainId !== "string" || v.chainId.length === 0) refuse("binding.chainId must be a non-empty string");
  if (!HEX64.test(v.poolId || "")) refuse("binding.poolId must be 64-hex");
  if (!Number.isSafeInteger(v.epochIndex) || v.epochIndex < 0) refuse("binding.epochIndex must be a non-negative safe integer");
  return deepFreeze({ contractId: v.contractId, chainId: v.chainId, contractVersion: v.contractVersion,
    poolId: v.poolId, epochIndex: v.epochIndex });
};

// ---- the transport, its declarations CAPTURED ONCE at construction through
// their own data descriptors (the same rule as the descriptor's members: a
// getter could answer the boolean check and serve something else afterwards),
// so what the answers carry is the value that was validated ----
const validateTransport = (t) => {
  if (!isPlain(t)) refuse("createForwardAdapter needs a plain transport object");
  const route = dataMember(t, "route", "the transport");
  if (typeof route !== "string" || route.length === 0) refuse("transport.route must be a non-empty string naming the query route");
  const provesResult = dataMember(t, "provesResult", "the transport");
  if (typeof provesResult !== "boolean") refuse("transport.provesResult must be a strict boolean stating whether the route obtains proof");
  const fetchVerifiedPage = dataMember(t, "fetchVerifiedPage", "the transport");
  if (typeof fetchVerifiedPage !== "function") refuse("transport.fetchVerifiedPage must be a function (e2ProvedQuery's page contract)");
  return Object.freeze({ route, provesResult, fetchVerifiedPage });
};

// ---- the index table, read from the ledger's declaration and held as
// [type] -> [{ name, properties: [prop, ...] }] ----
const indexTableOf = (ledger) => {
  if (!isPlain(ledger)) refuse("createForwardAdapter needs the v11 document-type table (buildV11's result)");
  const table = {};
  for (const type of E2_TYPES) {
    const def = ledger[type];
    if (!isPlain(def) || !Array.isArray(def.indices) || def.indices.length === 0) {
      refuse(`the ledger table declares no indices for ${type}`);
    }
    table[type] = def.indices.map((ix, i) => {
      if (!isPlain(ix) || typeof ix.name !== "string" || ix.name.length === 0 || !Array.isArray(ix.properties) || ix.properties.length === 0) {
        refuse(`${type}.indices[${i}] is not a named index with a property list`);
      }
      const properties = ix.properties.map((p, j) => {
        if (!isPlain(p) || Object.keys(p).length !== 1) refuse(`${type}.indices[${i}].properties[${j}] must name exactly one property`);
        return Object.keys(p)[0];
      });
      return { name: ix.name, properties };
    });
  }
  return deepFreeze(table);
};

// the ORDERED-PREFIX rule: a clause list [p1..pk] is served by an index whose
// property list begins with exactly p1..pk in that order. Set-equality is not
// enough (Platform evaluates clauses in index order), so [epochIndex, poolId]
// does not resolve to byPoolEpoch.
const resolveIndex = (indices, props) => {
  for (const ix of indices) {
    if (ix.properties.length < props.length) continue;
    let all = true;
    for (let i = 0; i < props.length; i += 1) if (ix.properties[i] !== props[i]) { all = false; break; }
    if (all) return ix;
  }
  return null;
};

// ---- the descriptor, held to acquisition's declared shape, and its clause
// list CAPTURED (validate-and-capture, the page checker's own pattern): the
// transport receives a frozen copy built from the values validated here, so a
// clause that is mutable inside a frozen descriptor cannot change between this
// validation and the transport's read. Each clause value must be a string or a
// safe integer, the two scalar shapes the ledger's indexed properties take, so
// there is no nested object to mutate either. ----
const validateDescriptor = (d, binding) => {
  if (!isPlain(d)) refuse("readPage needs a plain descriptor object");
  if (!Object.isFrozen(d)) refuse("readPage needs a FROZEN descriptor (acquisition freezes every descriptor at construction)");
  const kind = dataMember(d, "kind", "the descriptor");
  if (kind !== DESCRIPTOR_KIND) refuse(`the descriptor's kind is ${JSON.stringify(kind)}, not ${DESCRIPTOR_KIND}`);
  const type = dataMember(d, "type", "the descriptor");
  if (!E2_TYPES.includes(type)) refuse(`the descriptor's type ${JSON.stringify(type)} is not an E2 document type`);
  const whereList = dataMember(d, "where", "the descriptor");
  if (!Array.isArray(whereList) || whereList.length === 0) refuse(`the ${type} descriptor needs a non-empty where clause list`);
  const props = [];
  const captured = [];
  for (let i = 0; i < whereList.length; i += 1) {
    const clause = dataMember(whereList, String(i), `the ${type} descriptor's clause list`);
    if (!Array.isArray(clause) || clause.length !== 3) refuse(`the ${type} descriptor carries a clause that is not a [property, operator, value] triple`);
    const prop = dataMember(clause, "0", `the ${type} descriptor's clause ${i}`);
    const op = dataMember(clause, "1", `the ${type} descriptor's clause ${i}`);
    const value = dataMember(clause, "2", `the ${type} descriptor's clause ${i}`);
    if (typeof prop !== "string" || prop.length === 0) refuse(`the ${type} descriptor carries a clause without a property name`);
    if (op !== "==") refuse(`the ${type} descriptor carries operator ${JSON.stringify(op)} on ${prop}; this adapter issues equality clauses only`);
    if (typeof value !== "string" && !Number.isSafeInteger(value)) refuse(`the ${type} descriptor's ${prop} clause carries a value that is neither a string nor a safe integer`);
    if (props.includes(prop)) refuse(`the ${type} descriptor names ${prop} twice`);
    // THE BINDING CROSS-CHECK: a clause naming the pool or the epoch must name
    // THIS adapter's, or the read is for another scope and is not issued here
    if (prop === "poolId" && value !== binding.poolId) refuse(`the ${type} descriptor is for pool ${String(value).slice(0, 8)}..., not this adapter's ${binding.poolId.slice(0, 8)}...`);
    if (prop === "epochIndex" && value !== binding.epochIndex) refuse(`the ${type} descriptor is for epoch ${String(value)}, not this adapter's ${binding.epochIndex}`);
    props.push(prop);
    captured.push(Object.freeze([prop, "==", value]));
  }
  const limit = dataMember(d, "limit", "the descriptor");
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) refuse(`the ${type} descriptor's limit ${String(limit)} is outside 1..100`);
  // EVERYTHING readPage uses after this point is a value captured here
  return { props, where: Object.freeze(captured), type, limit };
};

/**
 * createForwardAdapter({ binding, transport, ledger }) returns a frozen
 * { readPage } satisfying acquisition's injected adapter contract.
 */
const createForwardAdapter = ({ binding, transport, ledger } = {}) => {
  const scope = validateBinding(binding);
  const t = validateTransport(transport);
  const indices = indexTableOf(ledger);

  const readPage = async (descriptor) => {
    const { props, where, type, limit } = validateDescriptor(descriptor, scope);
    const index = resolveIndex(indices[type], props);
    if (index === null) {
      refuse(`no registered index on ${type} serves the clause (${props.join(", ")}); the registered indices are ${indices[type].map((ix) => `${ix.name}(${ix.properties.join(", ")})`).join(", ")}, and this adapter issues nothing under a descriptor it cannot serve as written`);
    }
    // ONE page at the descriptor's limit, no cursor, no ordering, over the
    // CAPTURED clause list. A checker refusal or a transport throw propagates
    // from here as a fault.
    const page = await provedQueryPage({
      contractId: scope.contractId, type, where,
      orderBy: null, limit, startAfter: null, fetchVerifiedPage: t.fetchVerifiedPage,
    });
    if (page.status !== "verified") return deepFreeze({ status: page.status });
    const documents = page.documents.map((d) => {
      // the checker established every document plain with a 64-hex id; the
      // transport's document shape is { id, fields } and nothing else
      for (const k of Object.keys(d)) {
        if (k !== "id" && k !== "fields") refuse(`the ${type} page's document ${d.id.slice(0, 8)}... carries ${k}, outside the transport's { id, fields } shape`);
      }
      if (!isPlain(d.fields)) refuse(`the ${type} page's document ${d.id.slice(0, 8)}... carries no plain fields object`);
      return { id: d.id, fields: d.fields };
    });
    return deepFreeze({
      status: "served",
      proved: t.provesResult,
      route: `${t.route}:${type}.${index.name}`,
      scope: { ...scope },
      height: page.height,
      documents,
    });
  };

  return Object.freeze({ readPage });
};

module.exports = { createForwardAdapter };
