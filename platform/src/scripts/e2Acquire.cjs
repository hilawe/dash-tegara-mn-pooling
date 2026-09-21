/**
 * e2Acquire: THE ACQUISITION LAYER of the forward lifecycle kernel (contract
 * FORWARD_LIFECYCLE_KERNEL_CONTRACT.md, sections 3.2 and 3.2.1). It reads only
 * what the plan names, through an injected forward adapter, and assembles the
 * evidence bundle `evaluateEpochForwardState` consumes.
 *
 * WHAT IT ESTABLISHES, in one sentence: the bundle handed to the kernel is a
 * PROJECTION of what the adapter served, filed under the row each read was
 * issued for, with every statement about HOW a read happened supplied by the
 * adapter and never by this module.
 *
 * THE ONE RULE (contract 3.2.1's provenance table): acquisition is PASS-THROUGH
 * PLUS ASSEMBLY, NEVER STAMPING. `proved`, `route`, `scope` and `height` come
 * from the adapter untouched, so REFUSED_SCOPE_MISMATCH and
 * UNPROVED_ROUTE_NOT_PROVED stay reachable in the kernel. What this module
 * DERIVES, and nothing else: `documentId`, `fields` and `servedCount` from the
 * documents of a unique read; `funderIds`, `parts[]` and `count` from the
 * documents of an enumeration; `subjectAccrualId` from the descriptor; and ONE
 * status conversion, a unique read that served ZERO documents over a PROVED
 * route becomes a `proved-absence` answer, which is the kernel's own name for
 * that observation. The query SUBJECT comes from the immutable descriptor built
 * BEFORE the read, never from the plan after the fact and never from the
 * documents (a sweep observing nothing has no document to read a subject from).
 *
 * THE INJECTED ADAPTER CONTRACT: readPage(descriptor) resolves to
 *   { status: "served", proved, route, scope, height, documents }
 *     the read landed: `proved` is whether its route obtains proof, `route`
 *     names the query, `scope` is what it was obtained under, `height` the
 *     authenticated height as a canonical decimal string, and `documents` up to
 *     descriptor.limit entries of { id: 64-hex, fields: plain object };
 *   { status: "unserved" } | { status: "unverified" }
 *     the two failure strengths, passed through as themselves.
 * The whole envelope is captured as plain data before any member is read (the
 * same walk e2ProvedQuery uses), and the malformed shapes the test samples are
 * refused by name. A throw from the adapter is a FAULT that propagates as a
 * refusal naming it: this module's callers read RETURNED verdicts, and nothing
 * here classifies a caught value (the D8 resolution in e2CaptureRecord.cjs).
 *
 * THE INJECTED VERDICT CONTRACT (a soundness-review finding):
 *   await executionVerdict({ member, receipt, parts, reservation })
 * returns, or resolves to, the transfer execution verdict for a SERVED receipt,
 * a plain object the kernel validates (label CAPTURE-VERIFIED with
 * verifiedAmountCredits, or any other label with an optional reason). THE CALL
 * IS AWAITED, because the one conforming producer of CAPTURE-VERIFIED in this
 * repository, the receipt verifier's composition, is asynchronous; a
 * synchronous verdict remains conforming. It is called once for each receipt a
 * run reads as served and never otherwise; a reacquisition run that REUSES a
 * served receipt reuses the verdict STORED for it and does not call again, and
 * a reused receipt with NO stored verdict (none was obtained on the read that
 * served it) is called for again, exactly as a fresh read would be. Every
 * member of the argument is a fresh plain-data COPY, nested fields included,
 * so nothing the callback writes into it reaches the captured evidence, the
 * plan or the reads log: `member` the plan member; `receipt` { documentId, fields };
 * `parts` { status, documents } where `documents` is EXACTLY the part set this
 * run enumerated for the served accrual, each { documentId, fields } in
 * ascending partIndex, or null when that read was not served; `reservation` the
 * pinned reservation answer as the bundle records it. The journaled CAPTURE is
 * not passed, because acquisition holds no journal; the orchestrator's closure
 * supplies it. A rejected Promise, like a synchronous throw, is a verifier
 * FAULT and a named refusal that stops the run, never an unproved result. A
 * resolved value that is not plain data is refused by name. The return is
 * captured as plain data and passed through, never upgraded.
 *
 * THE RECEIPT CLAUSE IS (accrualId) ALONE, a soundness-review finding (contract revision 12): the
 * ledger registers no (poolId, accrualId) index on transferReceipt, so the
 * `receipt` and `sweepReceipt` descriptors carry the accrual identifier only,
 * against the UNIQUE byAccrual index, while every other accrual-keyed read
 * keeps (poolId, accrualId) against its type's byPool index. The narrowing
 * widens the read: a PROVED absence proves absence in any pool; a served receipt whose
 * pool differs from the plan's is a wrong-key answer the kernel REFUSES on its
 * fields and never an absence; and the sweep's receipt component reports
 * OCCUPANCY of the globally unique accrual key, so a receipt under that
 * identifier in another pool counts and is not made to disappear.
 *
 * FORWARD ENUMERATIONS ARE SINGLE-PAGE READS (contract 3.2.1). The request
 * limit is the legal bound PLUS ONE, derived in ONE place below, so a legal set
 * always returns short and completeness is observed rather than assumed. A FULL
 * page is not unproved and is not widened: it is passed through as served with
 * every document, and the kernel refuses the over-bound set with the codes it
 * already has (ambiguous, duplicate, extra, nonconforming index).
 *
 * THE ROW-STATE TABLE, read off the kernel's own branches (e2ForwardKernel.cjs,
 * the dependents loop), is what decides which reads a row owes:
 *   encoding-refused epoch      header, enumeration, every accrual, and the
 *                               sweep by the PLANNED id for every member
 *   non-payable row             the sweep only, by the SERVED id when the
 *                               accrual resolved served (even under an id that
 *                               differs from the planned one, which the kernel
 *                               refuses in its accrual loop for every row) and
 *                               by the PLANNED id otherwise (absent or
 *                               unresolved alike)
 *   payable, served, id MISMATCH nothing after the accrual (stage 3 stops)
 *   payable, unresolved         nothing (the dependents were not keyable)
 *   payable, proved absent      the sweep by the PLANNED id (the inspection
 *                               the contract's stage 6 permits, and only that)
 *   payable, served and bound   the full chain: pinned reservation, enumerated
 *                               reservation, receipt, parts, and the verdict
 *                               when the receipt was served; NO sweep (the
 *                               narrowed interface)
 * "Resolved served" and "resolved absent" mirror the kernel's own `consider`:
 * status, proved === true, scope equal to the plan's, a 64-hex identifier and
 * the key fields matching. That predicate is duplicated here deliberately,
 * because contract 3.2 stage 2 assigns the scope-bound validation of the served
 * accrual to acquisition. The composition tests in e2AcquireTest exercise the
 * served, absent, unserved, out-of-scope, wrong-key and mismatch resolutions
 * against the real kernel; a divergence in a case they do not vary is not
 * caught by them.
 *
 * REACQUISITION RE-RUNS ACQUISITION, IT DOES NOT PATCH A BUNDLE. When the
 * evaluator reports a stale negative, `acquireUntilSettled` runs the whole
 * acquisition again, REUSING only served DOCUMENTS from unique-key reads (the
 * header, an accrual, a pinned or enumerated reservation, a receipt, each fixed
 * by its unique index and immutable) and RE-READING every SET OBSERVATION
 * whatever it held (the accrual enumeration, the part listing, each sweep
 * component), every proved absence, and every unserved or unverified answer. A
 * document's immutability does not make a listing complete (a soundness-review finding): the first
 * policy reused any served answer with content and a listing holding one of two
 * required parts was reused through every retry with no fresh read. So a negative that
 * has become positive changes the row's state through the same code that
 * decided it the first time: the verdict is requested for a receipt that is now
 * served, the full chain is read for an accrual that is now served and bound,
 * and a non-payable sweep is re-keyed. The reuse channel is PRIVATE to that
 * loop: it is not an input of the exported acquisition function, and what it
 * carries was captured and frozen by the previous run of the same plan. The
 * first cut patched answers into the old bundle and a pre-commit check showed
 * it skipping exactly those duties.
 *
 * WHAT IT DOES NOT ESTABLISH, stated:
 *   - that the adapter's statements are true. It reports what the adapter said.
 *   - that the plan was built by the kernel. The kernel's plan brand is private
 *     to it, so this module checks the plan's kind, frozenness and shape and
 *     ASSUMES its origin; a frozen plan-shaped literal passes this check.
 *   - anything about a layer that is not injected (no Platform read, no proof
 *     verification, no signing) happens here.
 *   - a representation for ZERO documents over an UNPROVED route on a unique
 *     read. The kernel refuses a proved-absence whose route is unproved and a
 *     served answer without a document, so no true bundle member exists for
 *     that observation; this module REFUSES it by name rather than inventing
 *     one. Enumerations have a shape for it (a served empty list) and pass it
 *     through. Recorded in the contract's revision note as an interface gap.
 *   - a reads log when a run REFUSES: `reads` is returned only on success. An
 *     adapter-envelope or projection refusal names the query it arose on; an
 *     input, verdict-callback or assembly refusal names what it was checking;
 *     none reports the reads issued before it.
 *   - that reacquisition settles anything: it attempts at most `maxRounds`
 *     refreshes and returns the FINAL evaluation, whatever it is.
 *   - that the misfiling guard at assembly fires: it is watched by the mutation
 *     battery (tools/acquire_mutation_check.sh), which swaps two rows' filed
 *     answers and requires the refusal.
 */
"use strict";

const { plainDataSnapshot } = require("./e2ProvedQuery.cjs");

const HEX64 = /^[0-9a-f]{64}$/;
const DEC_RE = /^(0|[1-9][0-9]*)$/;
const refuse = (why) => { throw new Error(`e2Acquire: ${why}; refusing`); };
const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v)
  && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
const errText = (e) => {
  try { const m = e && e.message; if (typeof m === "string") return m; } catch { /* fall through */ }
  try { return String(e); } catch { return "(an unreadable thrown value)"; }
};
const deepFreeze = (v) => {
  if (v && typeof v === "object" && !Object.isFrozen(v)) {
    Object.freeze(v);
    for (const k of Object.keys(v)) deepFreeze(v[k]);
  }
  return v;
};
// a fresh plain copy of captured data, for handing to an injected callback
const copyOf = (v) => plainDataSnapshot(v).value;

// the part set handed to the verdict callback (a soundness-review finding): the read's status, and
// when served the documents this run enumerated, each a copy carrying its
// fields, in ascending partIndex. A read that was not served hands the callback
// its status and no documents, never an empty array, which would misrepresent
// an unserved read as a proved empty set.
// the applicability key of a verdict (a soundness-review finding): the receipt's identifier, the part
// set's status and its (identifier, index) pairs sorted, and the pinned
// reservation's status, identifier and transition hash. Two evidence states with
// the same key are indistinguishable to a verifier that reads only what
// acquisition hands it, so a stored verdict is reused exactly when the key is
// unchanged and recomputed otherwise. THE RECEIPT'S AND THE RESERVATION'S
// IDENTIFIER AND HASH COMPONENTS ARE DEFENSIVE: a stored verdict is only ever
// consulted on a REUSED receipt, and a served pinned reservation is likewise
// reused by descriptor identity, so neither can change between the runs that
// consult a verdict; the part set and the reservation's STATUS are the
// components that can, and the tests and the battery cover exactly those.
// each dependency's contribution to the key, as one list per read so the
// battery can remove a whole dependency at once. The PROOF STATUS is a
// component (a soundness-review finding): a read served over an unproved route and the same read
// served proved are different evidence.
const partsKeyOf = (a) => [
  a.status,
  a.status === "served" ? a.proved === true : null,
  a.status === "served" ? a.parts.map((p) => `${p.documentId}#${p.partIndex}`).sort() : null,
];
const reservationKeyOf = (a) => [
  a.status,
  a.status === "served" ? a.proved === true : null,
  a.status === "served" ? [a.documentId, a.fields.transitionHash] : null,
];
const verdictKeyFor = (receipt, partSet, reservationPinned) => JSON.stringify([
  receipt.documentId,
  partsKeyOf(partSet),
  reservationKeyOf(reservationPinned),
]);

// the first read the verifier would need that did NOT RESOLVE: unserved,
// unverified, or SERVED OVER A ROUTE THAT OBTAINED NO PROOF (a soundness-review finding), reported
// as status "unproved-route". The verifier is never shown the route, so a
// verdict over an unproved read would be a positive label over transport
// evidence the kernel already marks UNPROVED_ROUTE_NOT_PROVED. Null when both
// resolved (served and proved, or a proved absence, which is a resolved
// negative the verifier reports on).
// ALL THREE of the verifier's document inputs are gated (the receipt was missed
// by the first a soundness-review finding repair and found by the round's second pass): the receipt
// first, since it is the subject, then the parts, then the reservation.
const unresolvedEvidence = (receipt, partSet, reservationPinned) => {
  for (const [read, a] of [["receipt", receipt], ["parts", partSet], ["reservation", reservationPinned]]) {
    if (a.status === "unserved" || a.status === "unverified") return { read, status: a.status };
    if (a.status === "served" && a.proved !== true) return { read, status: "unproved-route" };
  }
  return null;
};

const partsForVerdict = (partRead) => {
  if (partRead.answer.status !== "served") return { status: partRead.answer.status, documents: null };
  // a served parts read always carries its documents on a fresh read, and a
  // set observation is never reused (a soundness-review finding); an entry that is served yet
  // carries none is refused by name rather than read as an empty set
  if (!Array.isArray(partRead.documents)) refuse("the parts read is served but carries no documents to hand the verdict callback; refusing rather than presenting an empty set");
  const docs = partRead.documents.map((d) => ({ documentId: d.id, fields: copyOf(d.fields) }));
  docs.sort((a, b) => a.fields.partIndex - b.fields.partIndex);
  return { status: "served", documents: docs };
};

// ---- the queries, with the legal bound each one has (contract 3.2.1) ----
// THE REQUEST LIMIT IS THE BOUND PLUS ONE, computed from this table and nowhere
// else, so a later change widening a bound moves every call site with it.
const QUERIES = Object.freeze({
  header:                { type: "epochHeader",         bound: 1, subject: "epoch" },    // unique (poolId, epochIndex)
  accrualEnumeration:    { type: "platformAccrual",     bound: 8, subject: "epoch" },    // memberCount is validated 1..8
  accrual:               { type: "platformAccrual",     bound: 1, subject: "funder" },   // unique (poolId, funderId, epochIndex)
  reservationPinned:     { type: "transferReservation", bound: 1, subject: "accrual" },  // unique (poolId, accrualId)
  reservationEnumerated: { type: "transferReservation", bound: 1, subject: "accrual" },
  receipt:               { type: "transferReceipt",     bound: 1, subject: "accrual", key: "accrualOnly" },  // unique byAccrual (a soundness-review finding)
  parts:                 { type: "receiptProofPart",    bound: 7, subject: "accrual" },  // partIndex 1..7
  sweepReservation:      { type: "transferReservation", bound: 1, subject: "accrual" },
  sweepReceipt:          { type: "transferReceipt",     bound: 1, subject: "accrual", key: "accrualOnly" },
  sweepParts:            { type: "receiptProofPart",    bound: 7, subject: "accrual" },
});
const requestLimit = (query) => QUERIES[query].bound + 1;
const SWEEP = Object.freeze([["reservation", "sweepReservation"], ["receipt", "sweepReceipt"], ["parts", "sweepParts"]]);

/**
 * THE IMMUTABLE QUERY DESCRIPTOR, built before the read. Its `where` is
 * CONSTRUCTED HERE FROM ITS SUBJECT (the epoch scope, the funder, or the accrual
 * identifier), so the clause and the subject cannot disagree, and it is frozen
 * at construction. `subjectAccrualId` is the accrual identifier a dependent read
 * is for, null for the epoch-level and accrual reads.
 */
const describe = (query, { scope, funderId = null, accrualId = null }) => {
  const q = QUERIES[query];
  if (!q) refuse(`internal: unknown query ${query}`);
  let where, subjectAccrualId = null;
  if (q.subject === "epoch") {
    where = [["poolId", "==", scope.poolId], ["epochIndex", "==", scope.epochIndex]];
  } else if (q.subject === "funder") {
    if (!HEX64.test(funderId || "")) refuse(`internal: the ${query} read needs a 64-hex funder`);
    where = [["poolId", "==", scope.poolId], ["funderId", "==", funderId], ["epochIndex", "==", scope.epochIndex]];
  } else {
    if (!HEX64.test(accrualId || "")) refuse(`internal: the ${query} read needs a 64-hex accrual subject`);
    subjectAccrualId = accrualId;
    // THE RECEIPT IS KEYED BY THE ACCRUAL IDENTIFIER ALONE (a soundness-review finding): the ledger
    // registers no (poolId, accrualId) index on transferReceipt, only the UNIQUE
    // byAccrual index, so the receipt clause carries no pool predicate. That
    // WIDENS what the read can return: a PROVED absence under accrualId proves
    // absence for that accrual in any pool, and a served receipt whose pool differs is
    // refused by the kernel's key check on its fields, never read as absent;
    // the sweepReceipt component therefore asks whether the globally unique
    // accrual key is OCCUPIED, and a receipt under it in another pool counts.
    where = q.key === "accrualOnly"
      ? [["accrualId", "==", subjectAccrualId]]
      : [["poolId", "==", scope.poolId], ["accrualId", "==", subjectAccrualId]];
  }
  return deepFreeze({
    kind: "tegara.e2.queryDescriptor.v1",
    query, type: q.type, where, limit: requestLimit(query), subjectAccrualId,
  });
};
// the identity of a descriptor for reuse across runs: its query and its clause
const descriptorKey = (d) => `${d.query}|${JSON.stringify(d.where)}`;

// ---- the adapter envelope, captured and held to its grammar ----
const readEnvelope = async (readPage, descriptor) => {
  let raw;
  try { raw = await readPage(descriptor); }
  catch (e) { refuse(`the injected adapter failed on ${descriptor.query} (${errText(e)}); an adapter fault is not evidence`); }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) refuse(`the adapter's ${descriptor.query} answer must declare status served, unserved or unverified`);
  const { defect, value: env } = plainDataSnapshot(raw);
  if (defect) refuse(`the adapter's ${descriptor.query} answer is not plain data (${defect})`);
  if (!["served", "unserved", "unverified"].includes(env.status)) refuse(`the adapter's ${descriptor.query} answer must declare status served, unserved or unverified`);
  const allowed = env.status === "served" ? ["status", "proved", "route", "scope", "height", "documents"] : ["status"];
  for (const k of Object.keys(env)) {
    if (!allowed.includes(k)) refuse(`the adapter's ${env.status} ${descriptor.query} answer carries ${k}, outside its declared shape`);
  }
  if (env.status !== "served") return { status: env.status };
  if (typeof env.proved !== "boolean") refuse(`the adapter's ${descriptor.query} answer needs a strict-boolean proved`);
  if (typeof env.route !== "string" || env.route.length === 0) refuse(`the adapter's ${descriptor.query} answer needs a route naming the query`);
  if (!isPlain(env.scope)) refuse(`the adapter's ${descriptor.query} answer needs a plain scope object`);
  if (typeof env.height !== "string" || !DEC_RE.test(env.height)) refuse(`the adapter's ${descriptor.query} answer needs its height as a canonical decimal string`);
  if (!Array.isArray(env.documents)) refuse(`the adapter's ${descriptor.query} answer needs a documents array`);
  if (env.documents.length > descriptor.limit) refuse(`the adapter's ${descriptor.query} answer is longer than its limit (${env.documents.length} > ${descriptor.limit})`);
  const seen = new Set();
  for (const d of env.documents) {
    if (!isPlain(d) || typeof d.id !== "string" || !HEX64.test(d.id)) refuse(`every document in the ${descriptor.query} answer carries its 64-hex id`);
    if (seen.has(d.id)) refuse(`the ${descriptor.query} answer serves document ${d.id.slice(0, 8)}... twice`);
    seen.add(d.id);
    if (!isPlain(d.fields)) refuse(`every document in the ${descriptor.query} answer carries plain fields`);
  }
  return env;
};

// ---- the projections acquisition may derive (contract 3.2.1's "Yes" rows) ----
const provenance = (env) => ({ status: "served", proved: env.proved, route: env.route, scope: env.scope, height: env.height });

const projectUnique = (env, descriptor) => {
  if (env.status !== "served") return { status: env.status };
  if (env.documents.length === 0) {
    if (env.proved !== true) {
      refuse(`the ${descriptor.query} read served an empty answer over an unproved route (${env.route}); the kernel's interface has no true shape for that observation (a proved absence needs a proved route, a served answer needs a document), so it is refused rather than represented`);
    }
    // THE ONE STATUS CONVERSION this module performs: served-and-empty over a
    // proved route is what the kernel calls a proved absence
    return { status: "proved-absence", proved: true, route: env.route, scope: env.scope, height: env.height };
  }
  const first = env.documents[0];
  return { ...provenance(env), documentId: first.id, fields: first.fields, servedCount: env.documents.length };
};
const projectAccrualEnumeration = (env) => (env.status !== "served" ? { status: env.status }
  : { ...provenance(env), funderIds: env.documents.map((d) => d.fields.funderId) });
const projectParts = (env, descriptor) => (env.status !== "served" ? { status: env.status }
  : { ...provenance(env), subjectAccrualId: descriptor.subjectAccrualId,
    parts: env.documents.map((d) => ({ partIndex: d.fields.partIndex, documentId: d.id })) });
const projectSweepComponent = (env, descriptor) => (env.status !== "served" ? { status: env.status }
  : { ...provenance(env), subjectAccrualId: descriptor.subjectAccrualId, count: env.documents.length });
const PROJECT = Object.freeze({
  header: projectUnique, accrual: projectUnique, reservationPinned: projectUnique,
  reservationEnumerated: projectUnique, receipt: projectUnique,
  accrualEnumeration: projectAccrualEnumeration, parts: projectParts,
  sweepReservation: projectSweepComponent, sweepReceipt: projectSweepComponent, sweepParts: projectSweepComponent,
});

// WHAT REACQUISITION MAY REUSE (a soundness-review finding): a served DOCUMENT from a unique-key read,
// whose identity is fixed by the unique index and whose content is immutable, and
// nothing else. A SET OBSERVATION (the accrual enumeration, the part listing, each
// sweep component) is re-read on every refresh WHATEVER IT HELD: one immutable
// document's presence stays true at later heights, but the listing that contained
// it is not complete at later heights (contract 6.1, case H2). The first policy
// reused every served answer "with content" and an independent review showed a
// listing holding one of two required parts being reused through both retry rounds
// with zero fresh reads. Absences, unserved and unverified answers are re-read too.
// a served unique-key DOCUMENT is reused (immutable content), but only one
// served over a PROVED route (a soundness-review finding): a document served over an unproved
// route may obtain its proof on a re-read, and the reused one never can
const isReusableDocument = (answer) => answer.status === "served" && typeof answer.documentId === "string" && answer.proved === true;

// ---- the kernel's own resolution of an accrual answer, mirrored (contract 3.2 stage 2) ----
const SCOPE_KEYS = ["contractId", "chainId", "contractVersion", "poolId", "epochIndex"];
const sameScope = (a, b) => isPlain(a) && SCOPE_KEYS.every((k) => a[k] === b[k]);
const resolveAccrual = (answer, plan, m) => {
  if (answer.status === "unserved" || answer.status === "unverified") return { kind: "unresolved" };
  if (answer.proved !== true || !sameScope(answer.scope, plan.scope)) return { kind: "unresolved" };
  if (answer.status === "proved-absence") return { kind: "absent" };
  const f = answer.fields;
  const keyed = f.poolId === plan.scope.poolId && f.funderId === m.funderId && String(f.epochIndex) === String(plan.scope.epochIndex);
  if (!keyed) return { kind: "unresolved" };
  return { kind: "served", servedId: answer.documentId };
};

// the identifier a row's dependent reads are keyed by, recomputed from the plan
// and the accrual answer INDEPENDENTLY of the acquisition loop, so the assembly
// guard compares two derivations rather than one value with itself. Both
// derivations share resolveAccrual, so a defect there is not what the guard
// catches; a defect in the KEYING decision is.
const keyedIdFor = (plan, m, accrualAnswer) => {
  if (plan.encodingRefused) return m.plannedAccrualId;
  const resolved = resolveAccrual(accrualAnswer, plan, m);
  if (m.classification !== "payable") return resolved.kind === "served" ? resolved.servedId : m.plannedAccrualId;
  return resolved.kind === "served" ? resolved.servedId : m.plannedAccrualId;
};

/**
 * acquireEpochEvidence({ plan, readPage, executionVerdict }) resolves to
 *   { evidence, reads }
 * with `evidence` the bundle the kernel consumes and `reads` the ordered list
 * of { descriptor, row, slot, answer, reused } this run produced, so a caller
 * can see WHAT WAS DONE and not only the assembled result. The private
 * `reuse` of acquireRun is the `reads` of the previous run of the SAME plan
 * inside acquireUntilSettled: the served documents it read on unique-key reads
 * (and the verdicts obtained for the receipts among them) are reused by
 * descriptor identity, everything else is read again (a soundness-review finding).
 */
const acquireRun = async ({ plan, readPage, executionVerdict, reuse = null } = {}) => {
  if (!isPlain(plan) || plan.kind !== "tegara.e2.forwardPlan.v1" || !Object.isFrozen(plan) || !Array.isArray(plan.members) || !isPlain(plan.scope)) {
    refuse("acquireEpochEvidence takes a frozen plan shaped by buildExpectedRecordPlan; a mutable plan-shaped literal is refused, and the plan's ORIGIN is assumed rather than checked (the kernel's brand is private)");
  }
  if (typeof readPage !== "function") refuse("acquireEpochEvidence needs the injected readPage adapter");
  if (typeof executionVerdict !== "function") refuse("acquireEpochEvidence needs the injected executionVerdict");
  if (reuse !== null && !Array.isArray(reuse)) refuse("acquireEpochEvidence's reuse must be a previous run's reads array");
  const reusable = new Map();
  for (const r of reuse || []) {
    if (!r || !r.descriptor || !r.answer) refuse("a reuse entry must carry a descriptor and an answer");
    if (isReusableDocument(r.answer)) reusable.set(descriptorKey(r.descriptor), r);
  }

  const reads = [];
  const read = async (query, subject, row = null) => {
    const descriptor = describe(query, subject);
    const prior = reusable.get(descriptorKey(descriptor));
    if (prior) {
      const entry = { descriptor, row, slot: query, answer: prior.answer, reused: true, verdict: prior.verdict,
        verdictKey: prior.verdictKey, documents: prior.documents === undefined ? null : prior.documents };
      reads.push(entry);
      return entry;
    }
    const env = await readEnvelope(readPage, descriptor);
    // the served documents are kept beside the projection for ONE consumer, the
    // verdict callback's part set (a soundness-review finding), which needs each part's fields that
    // projectParts deliberately drops from the bundle
    const entry = { descriptor, row, slot: query, answer: deepFreeze(PROJECT[query](env, descriptor)), reused: false,
      documents: env.status === "served" ? env.documents : null };
    reads.push(entry);
    return entry;
  };
  const scope = plan.scope;

  // stages 1 and 2 (contract 3.2): the header and the enumeration over (pool, epoch)
  const header = (await read("header", { scope })).answer;
  const accrualEnumeration = (await read("accrualEnumeration", { scope })).answer;

  const accruals = {};
  const dependents = {};
  const sweepFor = async (m, accrualId) => {
    const sweep = {};
    for (const [component, query] of SWEEP) {
      sweep[component] = (await read(query, { scope, accrualId }, m.funderId)).answer;
    }
    return sweep;
  };

  for (const m of plan.members) {
    const a = (await read("accrual", { scope, funderId: m.funderId }, m.funderId)).answer;
    accruals[m.funderId] = a;
    const resolved = resolveAccrual(a, plan, m);

    if (plan.encodingRefused) {
      // the kernel's encoding-refused branch expects the sweep under the PLANNED
      // identifier for every member, whatever was served
      dependents[m.funderId] = { machinerySweep: await sweepFor(m, m.plannedAccrualId) };
      continue;
    }
    if (m.classification !== "payable") {
      dependents[m.funderId] = { machinerySweep: await sweepFor(m, resolved.kind === "served" ? resolved.servedId : m.plannedAccrualId) };
      continue;
    }
    if (resolved.kind === "unresolved") continue;               // nothing keyable
    if (resolved.kind === "absent") {                            // the inspection under the planned id
      dependents[m.funderId] = { machinerySweep: await sweepFor(m, m.plannedAccrualId) };
      continue;
    }
    // stage 3: the served identifier against the planned write identifier
    if (resolved.servedId !== m.plannedAccrualId) continue;      // stop; the kernel refuses the row
    const accrualId = resolved.servedId;
    // stages 4 and 5: the reservation both ways, the receipt, and the parts
    // enumerated by the served identifier WHETHER OR NOT the receipt was served
    const reservationPinned = (await read("reservationPinned", { scope, accrualId }, m.funderId)).answer;
    const reservationEnumerated = (await read("reservationEnumerated", { scope, accrualId }, m.funderId)).answer;
    const receiptRead = await read("receipt", { scope, accrualId }, m.funderId);
    const receipt = receiptRead.answer;
    const partRead = await read("parts", { scope, accrualId }, m.funderId);
    const partSet = partRead.answer;
    let execution = null;
    if (receipt.status === "served") {
      // a soundness-review finding: A VERDICT IS APPLICABLE ONLY TO THE EVIDENCE IT WAS COMPUTED OVER.
      // Reuse is keyed by the receipt AND the part set AND the pinned reservation,
      // so a refresh that changes the parts (or resolves the reservation)
      // recomputes the verdict instead of carrying an obsolete one forward. The
      // journaled capture is NOT in the key: acquisition never sees it, and the
      // closure that supplies it reads its journal at call time.
      const key = verdictKeyFor(receipt, partSet, reservationPinned);
      // THE NAMED RESULT FOR UNRESOLVED EVIDENCE: when the receipt read, the parts
      // read or the pinned reservation read did not resolve (unserved, unverified,
      // or served over an unproved route, a soundness-review finding), the verdict is NOT REQUESTED. The verifier could only refuse what it cannot see, and the
      // kernel would then report a refusal where the situation is unproved. The
      // entry carries an acquisition-produced marker naming the read, and the
      // kernel defers the verdict for that row (contract revision 14).
      const unresolved = unresolvedEvidence(receipt, partSet, reservationPinned);
      if (receiptRead.reused && receiptRead.verdict !== undefined && receiptRead.verdictKey === key) {
        execution = receiptRead.verdict;
      } else if (unresolved !== null) {
        // the marker carries the read and its status as STRUCTURED members, so a
        // consumer reads them rather than a sentence; the reason is for people
        execution = deepFreeze({ label: "EVIDENCE-UNRESOLVED", requested: false,
          read: unresolved.read, status: unresolved.status,
          reason: `the ${unresolved.read} read was ${unresolved.status}; the verdict was not requested over evidence the verifier cannot see` });
        receiptRead.verdict = execution;
        receiptRead.verdictKey = key;
      } else {
        let verdict;
        // a soundness-review finding: the call is AWAITED, because the one conforming producer of
        // CAPTURE-VERIFIED (the receipt verifier's composition) is asynchronous,
        // and a synchronous verdict is still conforming since awaiting a plain
        // value yields it. The callback receives COPIES of the served receipt,
        // of EXACTLY the part set this run enumerated for the served accrual
        // (each part's fields included, in ascending partIndex, whatever order
        // the adapter served), of the pinned reservation answer as the bundle
        // records it, and of the plan member, so it cannot alter captured
        // evidence or the reads log. The capture is NOT passed: acquisition
        // holds no journal, and the orchestrator's closure supplies it.
        const call = {
          member: copyOf(m),
          receipt: { documentId: receipt.documentId, fields: copyOf(receipt.fields) },
          parts: partsForVerdict(partRead),
          reservation: copyOf(reservationPinned),
        };
        // a rejected Promise, like a synchronous throw, is a VERIFIER FAULT and
        // a named refusal that stops the run; it is never an unproved result,
        // because a fault in the verifier says nothing about the ledger
        try { verdict = await executionVerdict(call); }
        catch (e) { refuse(`the injected execution verdict failed for ${m.funderId.slice(0, 8)}... (${errText(e)}); a verifier fault is not evidence`); }
        const { defect, value } = plainDataSnapshot(verdict);
        if (defect || !isPlain(value)) refuse(`the execution verdict for ${m.funderId.slice(0, 8)}... is not a plain object (${defect || typeof verdict})`);
        execution = deepFreeze(value);
        receiptRead.verdict = execution;
        receiptRead.verdictKey = key;
      }
    }
    dependents[m.funderId] = { reservationPinned, reservationEnumerated, receipt, execution, partSet };
  }

  // ASSEMBLY CHECKS FILING BEFORE THE BUNDLE IS RETURNED (contract 3.2.1). What
  // it checks, exactly: for every read filed under a row, the funder clause (if
  // any) names that row, and the descriptor's subject equals the identifier the
  // row is keyed by (a SECOND derivation, keyedIdFor); and for every dependents
  // entry, the subjects the filed sweep components or part set carry equal that
  // identifier. It does NOT compare each filed answer against its read entry, so
  // two rows' receipt answers exchanged after their reads would pass it (the
  // two-row test observes receipt identities; the guard does not). It guards
  // against THIS module misfiling by subject, which is why it reads the
  // descriptors rather than trusting the answers.
  const memberOf = new Map(plan.members.map((m) => [m.funderId, m]));
  for (const r of reads) {
    if (r.row === null) continue;
    const m = memberOf.get(r.row);
    if (!m) refuse(`assembly: a read is filed under ${r.row.slice(0, 8)}..., which is not a plan member (misfiled)`);
    const funderField = r.descriptor.where.find(([f]) => f === "funderId");
    if (funderField && funderField[2] !== r.row) refuse(`assembly: the ${r.slot} read for ${r.row.slice(0, 8)}... was issued for funder ${String(funderField[2]).slice(0, 8)}... (misfiled)`);
    if (r.descriptor.subjectAccrualId === null) continue;
    const keyedBy = keyedIdFor(plan, m, accruals[r.row]);
    if (r.descriptor.subjectAccrualId !== keyedBy) {
      refuse(`assembly: the ${r.slot} read filed under ${r.row.slice(0, 8)}... was issued for accrual ${r.descriptor.subjectAccrualId.slice(0, 8)}... where that row is keyed by ${keyedBy.slice(0, 8)}... (misfiled)`);
    }
  }
  for (const [funderId, deps] of Object.entries(dependents)) {
    const m = memberOf.get(funderId);
    const keyedBy = keyedIdFor(plan, m, accruals[funderId]);
    const carried = deps.machinerySweep
      ? SWEEP.map(([c]) => deps.machinerySweep[c] && deps.machinerySweep[c].subjectAccrualId).filter((s) => s !== undefined)
      : [deps.partSet && deps.partSet.subjectAccrualId].filter((s) => s !== undefined);
    for (const s of carried) {
      if (s !== keyedBy) refuse(`assembly: the dependents filed under ${funderId.slice(0, 8)}... carry subject ${String(s).slice(0, 8)}... where that row is keyed by ${keyedBy.slice(0, 8)}... (misfiled)`);
    }
  }

  return { evidence: { header, accruals, accrualEnumeration, dependents }, reads };
};

/**
 * BOUNDED REACQUISITION OF STALE NEGATIVES (contract 6.1 assigns reacquisition
 * to acquisition or the orchestrator, never to the pure evaluator). A negative
 * answer that is OLDER than a served positive cannot establish anything, and
 * the kernel returns UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED for it.
 *
 * acquireUntilSettled({ plan, readPage, executionVerdict, evaluate, maxRounds })
 * resolves to { evidence, result, rounds, reads }. While the injected
 * `evaluate(plan, evidence)` reports that code and rounds remain, acquisition
 * is RUN AGAIN with the previous run's served unique-key documents reused and
 * everything else (set observations, negatives, unserved, unverified) re-read,
 * and the result is re-evaluated. `rounds` is how many such re-runs
 * happened, at most maxRounds. What is returned is the FINAL evaluation,
 * whatever it says: this function attempts bounded refreshes, it does not
 * promise that they settle anything. `reads` concatenates every run's reads,
 * reused entries marked. The evaluator is injected so this module imports
 * nothing from the kernel, and its return is trusted to be a kernel result
 * once it has the shape of one.
 */
const STALE_CODE = "UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED";

const acquireUntilSettled = async ({ plan, readPage, executionVerdict, evaluate, maxRounds = 2 } = {}) => {
  if (typeof evaluate !== "function") refuse("acquireUntilSettled needs the injected evaluate(plan, evidence)");
  if (!Number.isSafeInteger(maxRounds) || maxRounds < 0) refuse("acquireUntilSettled needs a non-negative safe-integer maxRounds");
  const checkResult = (r) => {
    if (!isPlain(r) || !Array.isArray(r.reasons)) refuse("the injected evaluate returned nothing shaped like a kernel result (a plain object with a reasons array)");
    return r;
  };
  let run = await acquireRun({ plan, readPage, executionVerdict });
  const reads = [...run.reads];
  let result = checkResult(evaluate(plan, run.evidence));
  let rounds = 0;
  while (rounds < maxRounds && result.reasons.some((r) => r.code === STALE_CODE)) {
    run = await acquireRun({ plan, readPage, executionVerdict, reuse: run.reads });
    reads.push(...run.reads);
    result = checkResult(evaluate(plan, run.evidence));
    rounds += 1;
  }
  return { evidence: run.evidence, result, rounds, reads };
};

// THE EXPORTED ENTRY TAKES NO REUSE INPUT. A caller-supplied cache would
// skip the envelope capture every fresh read passes through, so the reuse
// channel exists only between runs inside acquireUntilSettled.
const acquireEpochEvidence = async ({ plan, readPage, executionVerdict } = {}) =>
  acquireRun({ plan, readPage, executionVerdict });

module.exports = { acquireEpochEvidence, acquireUntilSettled };
