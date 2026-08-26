/**
 * The E2 AUDIT (duty D8), first half: the executable grade calculator.
 * This file carries the closed label system, the normative calculation
 * (version 1) with its encoding-refusal boundary, the start-source
 * resolution, the interval resolution and branch selection through the ONE
 * shared discovery primitive, the domain classification for the record-set
 * reverse pass, the closed verdict-grade grammar with its precedence, the
 * open-ended annotation rules, and the closed versioned report assembler.
 *
 * WHAT IT ESTABLISHES: every grammar outcome in the frozen audit section
 * is computed by a deterministic function over named inputs, the label
 * vocabulary and its total order are closed, aggregation is by the weakest
 * label, the verdict precedence is refusals then coverage then evidence
 * then the branch ceiling, a late configured start is never out-graded by
 * emptiness, and the report is a closed versioned schema (sub-shapes
 * included) that requires a contract identifier and an expected chain
 * identifier in every verdict; binding those members to the OWNED pins is
 * the runAudit entry's job, so in this half they are recorded as supplied.
 *
 * WHAT IT DOES NOT ESTABLISH, stated: the evidence evaluators (the
 * per-receipt aspects through e2ReceiptVerify, the formation-inputs and
 * contract-integrity proved reads, the bidirectional record-set sweep, the
 * proved-enumeration wrapper and its height ranges) are the unit's second
 * half and are not in this file yet; there is no runAudit entry until they
 * land. Until then every evidence-dependent aspect state reaching
 * gradeVerdict or buildReport is the CALLER'S claim, and so are the
 * COVERAGE BOOLEANS the assembler receives: binding them to the resolver
 * result they came from is the runAudit entry's obligation, and the
 * battery carries a resolver-to-assembler wiring case as the shape that
 * binding must take. Discovery's unproved status before C1 propagates
 * through the shared primitive's own `proved` member and is never
 * upgraded here.
 *
 * FREEZE-RESOLVED DECISIONS, settled in code per the D8 freeze and owed a
 * fold-back review as spec corrections. Decisions (1) and (3) fix how the
 * calculator REPRESENTS and grades those aspect states; producing the
 * states from evidence is the second-half evaluators' job, so in this
 * half they arrive as the caller's claim like every aspect state:
 * (1) the activation-boundary aspect's present label is OPERATOR-PROVIDED
 *     with the resolved start source named in its row (the aspect table
 *     opens the row with UNVERIFIABLE, then rests the start on the
 *     resolved source at operator strength; the row's reported label is
 *     the resting strength, its terminal stays PROVED);
 * (2) a journal-local start disagreement and an unresolvable start are
 *     both REFUSED-INPUT (grammar step 0 produces no report; the
 *     disagreement refusal is a soundness-review finding audit half);
 * (3) the contract-integrity aspect grades PROVED on a proved match,
 *     REFUSED on a proved divergence, UNPROVED on an unserved or
 *     unverified read, terminal PROVED;
 * (4) an empty discovery refuses the DEACTIVATION-BOUNDED branch
 *     outright (a proved boundary means finalized epochs exist, so a
 *     route serving none is disagreeing evidence), and in the open-ended
 *     branch an explicit endEpoch beside the empty result is
 *     REFUSED-INPUT (there is no discovered newest to validate it
 *     against, so the range is outside the validation domain);
 * (5) in the open-ended branch the annotation's endEpoch member must
 *     EQUAL the report interval's endEpoch (the annotation is the
 *     report's own time bound, so a disagreeing pair is malformed);
 * (6) every aspect has a label CEILING, its strongest defined form
 *     (CAPTURE-VERIFIED for transfer execution, PROVED-EVENTS for
 *     balance, PROVED elsewhere), and an evaluated label above it
 *     refuses, because no evidence route the table defines can earn it.
 */
const { discoverFinalizedEpochs } = require("./e2Discovery.cjs");

const HEX64 = /^[0-9a-f]{64}$/;
const U32_MAX = 4294967295;
const U64_MAX = 18446744073709551615n;
// the schema amount ceiling: vector 4c pins 9007199254740992 as the first
// REFUSED grossCredits value, so the ceiling is exactly MAX_SAFE_INTEGER
const ENCODING_CEILING = 9007199254740991n;

const refuse = (why) => { throw new Error(`e2Audit: ${why}; refusing`); };

// canonical decimal strings, TYPE-CHECKED: RegExp.test coerces a Number,
// so a bare regex test would admit numeric fields the schema forbids
const DEC_RE = /^(0|[1-9][0-9]*)$/;
const isDec = (s) => typeof s === "string" && DEC_RE.test(s);

// a display formatter for refusal messages that never itself throws:
// JSON.stringify throws on BigInt and on cycles, which would turn a
// structured refusal into a bare TypeError (the round-3 check's finding 6)
const show = (v) => {
  try { const s = JSON.stringify(v); return s === undefined ? String(v) : s; }
  catch { try { return String(v); } catch { return "[unrepresentable value]"; } }
};
// for interpolating an adapter-supplied FIELD that the plain-data domain
// accepts but a diagnostic expected to be a scalar: a primitive
// interpolates exactly as `${v}` would (String reproduces the same text),
// but an object with a null prototype has no toString and `${obj}` throws
// an untyped TypeError instead of yielding the intended record-set
// refusal (round-53). show() is used only for the non-primitive case, so
// normal integer and string field values read unchanged.
const scalarShow = (v) => (v === null || typeof v !== "object") ? String(v) : show(v);
// Array.isArray on a REVOKED Proxy throws a TypeError (round-57): an injected
// value must be classifiable without an escaping fault, so a throw is treated
// as "not a usable plain object" (true) and the boundary refuses it.
const safeIsArray = (v) => { try { return Array.isArray(v); } catch { return true; } };
// a TOTAL formatter for a CAUGHT value (round-58): a thrown value can be a
// null-prototype object or carry a throwing `message` getter, so reading
// `e.message` or interpolating `e` can throw a SECOND untyped fault out of the
// catch. Every access is guarded, so a diagnostic never escapes as a raw
// TypeError. This is the same class the plain-data catch handled in round 57.
const errText = (e) => {
  try { const m = e && e.message; if (typeof m === "string") return m; } catch { /* fall through */ }
  try { return String(e); } catch { return "(an unreadable thrown value)"; }
};

// closed shapes are PLAIN OWN-PROPERTY objects: prototype-carried members,
// non-enumerable members and symbol keys all refuse, so a "closed literal"
// claim cannot be sidestepped through object mechanics (round-3 finding 3)
const requirePlainClosed = (name, obj, members, required = members) => {
  if (!obj || typeof obj !== "object") refuse(`the report needs the literal ${name} object`);
  const proto = Object.getPrototypeOf(obj);
  if (proto !== Object.prototype && proto !== null) {
    refuse(`${name} must be a plain object (prototype-carried members do not count)`);
  }
  if (Object.getOwnPropertySymbols(obj).length) {
    refuse(`${name} carries symbol-keyed members (its shape is closed)`);
  }
  const extra = Object.getOwnPropertyNames(obj).filter((m) => !members.includes(m));
  if (extra.length) refuse(`${name} carries unknown members ${show(extra)} (its shape is closed)`);
  for (const [k, d] of Object.entries(Object.getOwnPropertyDescriptors(obj))) {
    if (!d.enumerable || !("value" in d)) {
      refuse(`${name}'s ${k} must be a plain enumerable data property (an accessor or hidden member would let the validated value drift from the copied one)`);
    }
  }
  for (const m of required) {
    if (!Object.prototype.hasOwnProperty.call(obj, m)) {
      refuse(`${name}'s ${m} is a required OWN member (an inherited value does not count)`);
    }
  }
};
const stringArray = (name, arr) => {
  if (!Array.isArray(arr)) refuse(`${name} must be an array of nonempty strings`);
  const out = [];
  for (let i = 0; i < arr.length; i++) {
    const d = Object.getOwnPropertyDescriptor(arr, i);
    if (!d || !("value" in d) || !d.enumerable) {
      refuse(`${name} index ${i} must be an own enumerable data element (a hole, accessor or inherited value counts as absent)`);
    }
    if (typeof d.value !== "string" || d.value.length === 0) {
      refuse(`${name} must be an array of nonempty strings (index ${i} is not one)`);
    }
    out.push(d.value);
  }
  return out;
};

/** Grammar step 0: a malformed request produces NO report, only this. */
class AuditInputRefusal extends Error {
  constructor(reason) {
    super(`e2Audit: REFUSED-INPUT: ${reason}`);
    this.grade = "REFUSED-INPUT";
    this.reason = reason;
  }
}
// The module's OWN refusals, recorded by identity at the only site that
// throws them. THE CLASS IS NOT ON THE PUBLIC SURFACE: it sits under
// `__testing`, because `runAudit` converts its own instances into a returned
// `{ verdict: "REFUSED-INPUT", reason }` and a caller never sees one thrown.
// This comment used to say it was exported for consumers, which was a contract
// offered to nobody. Tests
// READ thrown refusals against it, which makes `instanceof` reproducible
// from outside the module: an injected adapter can throw an object
// inheriting the exported prototype, or a Proxy whose getPrototypeOf trap
// names it, and an instanceof-based classifier would convert that adapter
// fault into a structured refusal carrying a reason of the adapter's
// choosing. Membership in this set cannot be reproduced from outside,
// and WeakSet.has reads nothing of the value and throws on nothing
// (primitives, revoked proxies and lying traps all return false).
const OWN_REFUSALS = new WeakSet();
const refuseInput = (reason) => {
  const e = new AuditInputRefusal(reason);
  OWN_REFUSALS.add(e);
  throw e;
};

// ---- the closed label vocabulary, total order, weakest first ----
const LABELS = Object.freeze(["REFUSED", "UNVERIFIABLE", "UNPROVED",
  "OPERATOR-PROVIDED", "ATTESTED", "READ-CHECKED", "CAPTURE-VERIFIED",
  "PROVED-NET", "PROVED", "PROVED-EVENTS"]);
const rankOf = (label) => {
  const r = LABELS.indexOf(label);
  if (r < 0) refuse(`${show(label)} is not in the closed label vocabulary`);
  return r;
};
const labelAtLeast = (label, floor) => rankOf(label) >= rankOf(floor);
/** Per-record labels aggregate by the WEAKEST under the total order. */
const aggregateWeakest = (labels) => {
  if (!Array.isArray(labels) || labels.length === 0) refuse("aggregateWeakest needs a nonempty label array");
  for (const l of labels) rankOf(l); // a singleton reduction never calls the callback
  return labels.reduce((a, b) => (rankOf(b) < rankOf(a) ? b : a));
};

// ---- the aspect registry: thirteen rows, each with its named terminal ----
const ASPECT_TERMINALS = Object.freeze({
  universe: "PROVED",
  activationBoundary: "PROVED",
  deactivationBoundary: "PROVED",
  binding: "PROVED",
  transferExecution: "CAPTURE-VERIFIED", // no stronger form exists
  reservationPresence: "PROVED",
  temporalOrder: "PROVED",
  ordering: "PROVED",
  formationInputs: "PROVED",
  recordSet: "PROVED", // present-day SUCCESS label is READ-CHECKED, below terminal
  shareConformance: "PROVED",
  balance: "PROVED-NET",
  contractIntegrity: "PROVED",
});
const ASPECT_KEYS = Object.freeze(Object.keys(ASPECT_TERMINALS));
const ASPECT_CEILINGS = Object.freeze(Object.fromEntries(ASPECT_KEYS.map((k) => [k,
  k === "transferExecution" ? "CAPTURE-VERIFIED" : k === "balance" ? "PROVED-EVENTS" : "PROVED"])));
// the three PER-RECEIPT aspects, the rows whose label comes from examining
// receipts rather than from a pool-level or interval-level check. Named ONCE
// because the list had been written out by hand at five sites across two
// evaluators, which is a drift the reader cannot see.
const RECEIPT_ASPECT_KEYS = Object.freeze(["transferExecution", "reservationPresence", "ordering"]);

const GRADES = Object.freeze(["REFUSED-INPUT", "REFUSED-REPORT",
  "PARTIAL BY SCOPE", "PARTIAL BY EVIDENCE", "FULL-TO-DATE", "FULL"]);
const BRANCHES = Object.freeze(["deactivation-bounded", "open-ended"]);

const requireU32 = (name, v) => {
  if (!Number.isSafeInteger(v) || v < 0 || v > U32_MAX) refuseInput(`${name} ${show(v)} is not a u32 epoch index`);
  return v;
};

// ---- the normative calculation, version 1 ----
/**
 * Integers throughout, floor division throughout, every intermediate in
 * BigInt (Number arithmetic diverges INSIDE the representable range).
 * Inputs are accepted at their FULL declared wire width; the refusal
 * applies ONLY AT ENCODING: the FIRST computed value in schema order
 * (grossCredits, feeCredits, amountCredits) exceeding the field ceiling
 * makes the epoch `encoding-refused`, total for the epoch. Rows carry the
 * allocation shares `bps` (validated 1..10000, at most 8, sum exactly
 * 10000); full allocation-row conformance (owners, amounts, the
 * largest-remainder rule, the hash) is the formation-inputs aspect's job,
 * not this function's.
 */
const computeNormativeEpoch = ({ totalProcessingFees, totalDistributedStorageFees,
  coreBlockRewards, totalBlocks, proposedCount, operatorFeeBps, rows }) => {
  // u64 quantities arrive as canonical decimal strings or BigInt, NEVER
  // as Number: a Number above 2^53 reaches this function already rounded,
  // so accepting one would convert a wrong value without refusal
  const u64 = (name, v) => {
    let b;
    if (typeof v === "bigint") b = v;
    else if (isDec(v)) b = BigInt(v);
    else refuse(`${name} must be a canonical decimal string or BigInt (a Number may arrive already rounded)`);
    if (b < 0n || b > U64_MAX) refuse(`${name} ${v} is outside the u64 wire width`);
    return b;
  };
  const fees = u64("totalProcessingFees", totalProcessingFees);
  const storage = u64("totalDistributedStorageFees", totalDistributedStorageFees);
  const core = u64("coreBlockRewards", coreBlockRewards);
  const blocks = u64("totalBlocks", totalBlocks);
  if (blocks === 0n) refuse("totalBlocks of zero is a mandatory epoch-object refusal");
  // proposedCount is a u32, entirely inside the exact-Number range, so a
  // safe integer is accepted beside the string and BigInt forms
  const proposed = Number.isSafeInteger(proposedCount) && proposedCount >= 0
    ? BigInt(proposedCount) : u64("proposedCount", proposedCount);
  if (proposed > U32_MAX) refuse("proposedCount is outside the u32 wire width");
  if (proposed > blocks) refuse(`proposedCount ${proposed} exceeds totalBlocks ${blocks} (a mandatory refusal)`);
  if (!Number.isSafeInteger(operatorFeeBps) || operatorFeeBps < 0 || operatorFeeBps > 10000) {
    refuse("operatorFeeBps must be an integer 0..10000");
  }
  if (!Array.isArray(rows) || rows.length < 1 || rows.length > 8) {
    refuse("the allocation rows must number 1..8 (the direct co-owner tier's bound)");
  }
  let bpsSum = 0;
  const rowBps = [];
  for (let i = 0; i < rows.length; i++) {
    const rd = Object.getOwnPropertyDescriptor(rows, i);
    if (!rd || !("value" in rd) || !rd.enumerable) {
      refuse(`allocation row ${i} must be an own enumerable data element`);
    }
    const row = rd.value;
    const bd = row && typeof row === "object" ? Object.getOwnPropertyDescriptor(row, "bps") : null;
    if (!bd || !("value" in bd) || !Number.isSafeInteger(bd.value) || bd.value < 1 || bd.value > 10000) {
      refuse("every allocation row needs an OWN integer bps 1..10000 (inherited or accessor members do not count)");
    }
    rowBps.push(bd.value);
    bpsSum += bd.value;
  }
  if (bpsSum !== 10000) refuse(`the allocation bps sum ${bpsSum} is not exactly 10000`);

  const totalPayout = fees + storage + core; // exact and unbounded
  const G = (totalPayout * proposed) / blocks;
  // the FIRST refused field in schema order is total for the epoch. With
  // every field ceiling at the one ENCODING_CEILING, only grossCredits can
  // trip: fee = floor(G * bps / 10000) <= G and each owed_i <= D <= G, so
  // an encodable G bounds them both. The fee and amount checks below stay
  // for the day the schema pins DISTINCT per-field ceilings.
  if (G > ENCODING_CEILING) {
    return { encodingRefused: { field: "grossCredits", value: String(G) },
      G: String(G), fee: null, D: null, owed: null, r: null };
  }
  const fee = (G * BigInt(operatorFeeBps)) / 10000n;
  if (fee > ENCODING_CEILING) {
    return { encodingRefused: { field: "feeCredits", value: String(fee) },
      G: String(G), fee: String(fee), D: null, owed: null, r: null };
  }
  const D = G - fee;
  const owed = rowBps.map((bps) => (D * BigInt(bps)) / 10000n);
  const over = owed.find((o) => o > ENCODING_CEILING);
  if (over !== undefined) {
    return { encodingRefused: { field: "amountCredits", value: String(over) },
      G: String(G), fee: String(fee), D: String(D), owed: null, r: null };
  }
  const r = D - owed.reduce((a, b) => a + b, 0n);
  return { encodingRefused: null, G: String(G), fee: String(fee), D: String(D),
    owed: rowBps.map((bps, i) => ({ bps, amountCredits: String(owed[i]) })),
    r: String(r) };
};

// ---- the start-source resolution, ONE RESOLVED RESULT (a soundness-review finding) ----
/**
 * The journaled configured start, else the local configuration key, else
 * an explicit startEpoch input, else REFUSED-INPUT. A journaled binding
 * that DISAGREES with a present local configuration key refuses the
 * report outright. Every source is OPERATOR-PROVIDED strength and the
 * resolved source is named in the report. An explicit startEpoch beside a
 * resolved journal or local source does not change the SOURCE; it sets
 * the requested interval start (and must discover from itself).
 */
const resolveStartSource = (input) => {
  if (!input || typeof input !== "object") refuseInput("resolveStartSource needs its input object");
  const { journalBinding, localKey, explicitStartEpoch } = input;
  const opt = (name, v) => (v === null || v === undefined ? null : requireU32(name, v));
  const journal = opt("the journaled configured start", journalBinding);
  const local = opt("the local configured start key", localKey);
  const explicit = opt("the explicit startEpoch input", explicitStartEpoch);
  let source, configuredStart;
  if (journal !== null) {
    if (local !== null && local !== journal) {
      refuseInput(`the local configured start ${local} disagrees with the journaled binding ${journal} (a soundness-review finding)`);
    }
    source = "journal"; configuredStart = journal;
  } else if (local !== null) {
    source = "local-configuration"; configuredStart = local;
  } else if (explicit !== null) {
    source = "explicit-input"; configuredStart = explicit;
  } else {
    refuseInput("no resolvable start source (no journaled binding, no local configuration key, no explicit startEpoch input)");
  }
  return { source, configuredStart, requestedStart: explicit !== null ? explicit : configuredStart };
};

// ---- the interval resolution and branch selection ----
/**
 * The branch is selected by EVIDENCE AVAILABILITY, never an asserted
 * lifecycle status: deactivation-bounded exactly when a proved
 * deactivation boundary is available, open-ended otherwise. Discovery
 * runs from the REQUESTED start through the one shared primitive. The
 * interval is inclusive both ends; a reversed range refuses as malformed
 * input, an explicit end above its branch's ceiling refuses likewise.
 * The empty-interval representation (endEpoch null, zero epochs) is
 * reachable ONLY in the open-ended branch with no explicit end: the
 * bounded branch refuses an empty or short discovery as disagreeing
 * evidence, and an explicit end beside an empty result refuses as
 * outside the domain; what remains is graded by the grammar like every
 * report.
 */
const resolveInterval = async (input) => {
  if (!input || typeof input !== "object") refuseInput("resolveInterval needs its input object");
  const { requestedStart, requestedEnd, configuredStart,
    provedActivation, provedDeactivation, fetchRange, discoveryOpts } = input;
  requireU32("requestedStart", requestedStart);
  requireU32("configuredStart", configuredStart);
  const reqEnd = requestedEnd === null || requestedEnd === undefined
    ? null : requireU32("requestedEnd", requestedEnd);
  const activation = provedActivation === null || provedActivation === undefined
    ? null : requireU32("provedActivation", provedActivation);
  const deactivation = provedDeactivation === null || provedDeactivation === undefined
    ? null : requireU32("provedDeactivation", provedDeactivation);
  if (reqEnd !== null && requestedStart > reqEnd) {
    refuseInput(`the requested range [${requestedStart}, ${reqEnd}] is reversed`);
  }

  const branch = deactivation !== null ? "deactivation-bounded" : "open-ended";
  const discovery = await discoverFinalizedEpochs(requestedStart, fetchRange, discoveryOpts || {});
  const newest = discovery.empty ? null : discovery.newestFinalized;

  let endEpoch;
  if (branch === "deactivation-bounded") {
    // ONE disagreement guard for both forms: a proved boundary implies
    // finalized epochs through it, so an empty discovery and a discovery
    // ending short of the boundary are the same incoherence
    if (discovery.empty || discovery.newestFinalized < deactivation) {
      refuseInput(`a proved deactivation boundary at ${deactivation} beside a discovery ${discovery.empty ? `serving nothing from ${requestedStart}` : `ending at ${discovery.newestFinalized}`} is disagreeing evidence (the boundary implies finalized epochs through it)`);
    }
    if (reqEnd !== null && reqEnd > deactivation) {
      refuseInput(`the explicit endEpoch ${reqEnd} exceeds the proved deactivation boundary ${deactivation}`);
    }
    endEpoch = reqEnd !== null ? reqEnd : deactivation;
  } else if (discovery.empty) {
    if (reqEnd !== null) {
      refuseInput(`the explicit endEpoch ${reqEnd} has no discovered newest finalized epoch to validate against (the range is outside the validation domain)`);
    }
    endEpoch = null; // the empty universe nulls endEpoch
  } else {
    if (reqEnd !== null && reqEnd > newest) {
      refuseInput(`the explicit endEpoch ${reqEnd} exceeds the discovered newest finalized epoch ${newest}`);
    }
    endEpoch = reqEnd !== null ? reqEnd : newest;
  }
  // startEpoch <= endEpoch is REQUIRED of the RESOLVED interval too: a
  // deactivation boundary below the requested start would otherwise
  // default a reversed range past the explicit-range check above
  if (endEpoch !== null && endEpoch < requestedStart) {
    refuseInput(`the resolved interval [${requestedStart}, ${endEpoch}] is reversed`);
  }

  // the universe start rests on the proved activation boundary when it
  // exists and on the configured start until then; a configured start
  // LATER than proved activation is the omitted-prefix coverage violation
  const universeStart = activation !== null ? activation : configuredStart;
  if (deactivation !== null && universeStart > deactivation) {
    refuseInput(`the universe start ${universeStart} sits above the proved deactivation boundary ${deactivation}, which is not a coherent lifecycle (misconfigured start or damaged evidence)`);
  }
  const lateConfiguredStart = activation !== null && configuredStart > activation;
  const universeEnd = newest === null ? null
    : branch === "deactivation-bounded" ? Math.min(newest, deactivation) : newest;
  const universe = universeEnd === null || universeStart > universeEnd
    ? null : { start: universeStart, end: universeEnd };

  // P, the permitted set I \ U: only a pre-activation prefix, each epoch
  // owed a zero-earning verification by the record-set forward pass
  const prefix = endEpoch !== null && requestedStart < universeStart
    ? { start: requestedStart, end: Math.min(universeStart - 1, endEpoch) }
    : null;

  // a requested start ABOVE the universe start is a containment violation
  // even when discovery returns empty: discovery ran from the requested
  // start, so an empty result says nothing about epochs between the
  // universe start and it, and treating emptiness as containment would
  // out-grade the omission (the re-check pass's finding 1)
  const containsUniverse = universe === null
    ? requestedStart <= universeStart
    : requestedStart <= universe.start && endEpoch !== null && endEpoch >= universe.end;
  return {
    branch, discovery,
    interval: { startEpoch: requestedStart, endEpoch },
    universe, prefix,
    coverage: { lateConfiguredStart, containsUniverse, narrowedRange: !containsUniverse },
    emptyResult: discovery.empty,
  };
};

// ---- the domain classification for the record-set reverse pass ----
/**
 * The validation domain D is U together with the permitted prefix P. A
 * record resolving inside U but outside the interval is IGNORED after
 * successful resolution; a prefix record is validated and NEVER an extra;
 * a record outside D is an EXTRA. `insideInterval` names where a failing
 * resolved record's failure lands (per-epoch inside, pool-global outside).
 */
const classifyRecordEpoch = (epochIndex, { universe, interval, prefix }) => {
  requireU32("the resolved record epoch", epochIndex);
  const inInterval = interval.endEpoch !== null
    && epochIndex >= interval.startEpoch && epochIndex <= interval.endEpoch;
  if (prefix && epochIndex >= prefix.start && epochIndex <= prefix.end) {
    return { bucket: "prefix-permitted", insideInterval: inInterval };
  }
  if (universe && epochIndex >= universe.start && epochIndex <= universe.end) {
    return { bucket: inInterval ? "in-scope" : "ignored", insideInterval: inInterval };
  }
  return { bucket: "extra", insideInterval: inInterval };
};

// ---- the closed verdict-grade grammar, with precedence ----
/**
 * Computed in order over a report's inputs: (1) REFUSED-REPORT on any
 * aspect at REFUSED or any in-report refusal, dominating every partial
 * grade; (2) PARTIAL BY SCOPE on any coverage-and-containment violation;
 * (3) PARTIAL BY EVIDENCE on any evaluated aspect below its terminal or
 * an incomplete open-ended annotation (a null member, the empty result
 * included); (4) the branch ceiling, FULL in the deactivation-bounded
 * branch and FULL-TO-DATE in the open-ended branch. Step 0,
 * REFUSED-INPUT, never reaches this function: it produces no report.
 * Only the deactivation-boundary aspect may be unevaluated, and only in
 * the open-ended branch.
 */
const gradeVerdict = ({ branch, aspects, inReportRefusal, coverage, annotation }) => {
  if (!BRANCHES.includes(branch)) refuse(`${show(branch)} is not a branch`);
  if (typeof inReportRefusal !== "boolean") refuse("gradeVerdict needs a boolean inReportRefusal");
  if (!coverage || typeof coverage.lateConfiguredStart !== "boolean"
    || typeof coverage.containsUniverse !== "boolean" || typeof coverage.narrowedRange !== "boolean") {
    refuse("gradeVerdict needs the three named coverage booleans");
  }
  if (!aspects || typeof aspects !== "object") refuse("gradeVerdict needs the aspect map");
  const mapProto = Object.getPrototypeOf(aspects);
  if (mapProto !== Object.prototype && mapProto !== null) {
    refuse("the aspect map must be a plain object (prototype-carried rows do not count)");
  }
  if (Object.getOwnPropertySymbols(aspects).length) {
    refuse("the aspect map carries symbol-keyed members (the aspect set is closed)");
  }
  for (const [k, d] of Object.entries(Object.getOwnPropertyDescriptors(aspects))) {
    if (!d.enumerable || !("value" in d)) {
      refuse(`the aspect map's ${k} must be a plain enumerable data property`);
    }
  }
  const extra = Object.getOwnPropertyNames(aspects).filter((k) => !ASPECT_KEYS.includes(k));
  if (extra.length) refuse(`unknown aspect keys ${show(extra)} (the aspect set is closed)`);
  for (const key of ASPECT_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(aspects, key)) {
      refuse(`aspect ${key} is missing or has no evaluated flag`);
    }
    const a = aspects[key];
    if (!a || typeof a !== "object") refuse(`aspect ${key} is missing or has no evaluated flag`);
    // descriptors FIRST, before any member read: a self-replacing getter
    // must refuse rather than serve a value and then clean the evidence.
    //
    // examinedCount is REQUIRED on the three per-receipt aspects, so a
    // consumer can always read the examined-receipt count; grading
    // deliberately leaves an examinedCount of zero UNCAPPED, which is
    // the frozen empty-set identity (an epoch with no expected receipts
    // inherits the record-set label) (round-40).
    // CLAIM WIDTH (round-54): gradeVerdict/buildReport validate the count's
    // type, cross-aspect equality and the zero-count cap, but a positive
    // count is CALLER-ASSERTED for a direct exported-function caller. Only
    // runAudit binds it to evidence, deriving it from the number of receipt
    // evaluations actually performed; a direct caller submitting a positive
    // count without examining a receipt is outside this function's reach.
    requirePlainClosed(`aspect ${key}`, a,
      ["evaluated", "label", "source", "note", ...(RECEIPT_ASPECT_KEYS.includes(key) ? ["examinedCount"] : [])],
      ["evaluated"]);
    if (Object.prototype.hasOwnProperty.call(a, "examinedCount")
      && (!Number.isSafeInteger(a.examinedCount) || a.examinedCount < 0)) {
      refuse(`aspect ${key} examinedCount must be a nonnegative safe integer when present`);
    }
    if (typeof a.evaluated !== "boolean") {
      refuse(`aspect ${key} is missing or has no evaluated flag`);
    }
    for (const m of ["source", "note"]) {
      if (Object.prototype.hasOwnProperty.call(a, m)
        && (typeof a[m] !== "string" || a[m].length === 0)) {
        refuse(`aspect ${key}'s ${m} must be a nonempty string when present`);
      }
    }
    if (a.evaluated) {
      if (!Object.prototype.hasOwnProperty.call(a, "label")) {
        refuse(`aspect ${key} is evaluated but carries no OWN label (an inherited one does not count)`);
      }
      rankOf(a.label);
      if (!labelAtLeast(ASPECT_CEILINGS[key], a.label)) {
        refuse(`aspect ${key} cannot earn ${a.label}: its strongest defined form is ${ASPECT_CEILINGS[key]} (no evidence route reaches higher)`);
      }
      if (key === "deactivationBoundary" && branch === "open-ended") {
        refuse("the deactivation-boundary aspect is NOT EVALUATED in the open-ended branch (the branch is selected exactly when no proved boundary exists)");
      }
      if (RECEIPT_ASPECT_KEYS.includes(key) && !Object.prototype.hasOwnProperty.call(a, "examinedCount")) {
        refuse(`aspect ${key} must carry its examinedCount (the examined-receipt count is required on the per-receipt aspects)`);
      }
    } else {
      if (!(key === "deactivationBoundary" && branch === "open-ended")) {
        refuse(`aspect ${key} may not be unevaluated (only the deactivation boundary in the open-ended branch is)`);
      }
      if (Object.prototype.hasOwnProperty.call(a, "label")) {
        refuse("an unevaluated aspect row carries no label (an unvalidated label would ride into the report beside the verdict)");
      }
    }
  }
  if (branch === "open-ended") {
    // the FULL annotation grammar runs here, not only a member-presence
    // probe: an undefined member is neither an explicit null nor a value,
    // and treating it as complete would grade past the evidence step
    validateAnnotation(annotation);
  } else if (annotation !== null && annotation !== undefined) {
    refuse("the deactivation-bounded branch carries no open-ended annotation");
  }

  // the three per-receipt aspects carry EQUAL counts (round-42; the claim
  // narrowed round-64). Equality is what this check establishes and all it
  // establishes: three aspects could each carry a count of one over three
  // DIFFERENT receipts and pass, because integers cannot witness set
  // identity. Through `runAudit` the sets genuinely are the same one, by
  // control flow (all three come from the same `receiptEvaluations` walk),
  // but `gradeVerdict` is exported and cannot see that, so it must not claim
  // it. The zero-count labels are NOT forced to the record-set label, because
  // a missing expected receipt contributes its refusal without an evaluation
  // (round-39).
  {
    const counts = RECEIPT_ASPECT_KEYS
      .map((k) => aspects[k].evaluated ? aspects[k].examinedCount : null)
      .filter((c) => c !== null);
    if (counts.some((c) => c !== counts[0])) {
      refuse("the per-receipt aspects carry equal examinedCounts (equality is checked here; that the three counts describe the SAME receipts is established by the entry's control flow, not by this check)");
    }
    // the count is CONSUMED by grading (round-43): with nothing
    // examined, a per-receipt label can come only from record-set
    // inheritance or a degradation contribution, so no label may
    // outrank both. The round-39 missing-expected case stays valid
    // (its contributions are all at or below OPERATOR-PROVIDED).
    if (counts.length && counts[0] === 0) {
      const bound = Math.max(rankOf("OPERATOR-PROVIDED"), rankOf(aspects.recordSet.label));
      for (const k of RECEIPT_ASPECT_KEYS) {
        if (aspects[k].evaluated && rankOf(aspects[k].label) > bound) {
          refuse(`aspect ${k} carries a label its zero examined-receipt count cannot earn (nothing was examined, so the strongest available is record-set inheritance or a degradation)`);
        }
      }
    }
  }
  // (1) refusals dominate every partial grade
  if (inReportRefusal) return "REFUSED-REPORT";
  for (const key of ASPECT_KEYS) {
    if (aspects[key].evaluated && aspects[key].label === "REFUSED") return "REFUSED-REPORT";
  }
  // (2) coverage and containment
  if (coverage.lateConfiguredStart || !coverage.containsUniverse || coverage.narrowedRange) {
    return "PARTIAL BY SCOPE";
  }
  // (3) evidence: any evaluated aspect below terminal, or an incomplete annotation
  for (const key of ASPECT_KEYS) {
    if (aspects[key].evaluated && !labelAtLeast(aspects[key].label, ASPECT_TERMINALS[key])) {
      return "PARTIAL BY EVIDENCE";
    }
  }
  if (branch === "open-ended"
    && (annotation.endEpoch === null || annotation.recordsHeightMax === null)) {
    return "PARTIAL BY EVIDENCE";
  }
  // (4) the branch ceiling
  return branch === "deactivation-bounded" ? "FULL" : "FULL-TO-DATE";
};

// ---- the open-ended annotation, a literal object with explicit nulls ----
const validateAnnotation = (a) => {
  if (!a || typeof a !== "object") refuse("the open-ended branch requires the annotation object with both members, nulls explicit");
  requirePlainClosed("the annotation", a, ["endEpoch", "recordsHeightMax"]);
  if (a.endEpoch !== null && (!Number.isSafeInteger(a.endEpoch) || a.endEpoch < 0 || a.endEpoch > U32_MAX)) {
    refuse("the annotation's endEpoch must be a u32 epoch index or an explicit null");
  }
  if (a.recordsHeightMax !== null && !isDec(a.recordsHeightMax)) {
    refuse("the annotation's recordsHeightMax must be a canonical decimal string or an explicit null");
  }
  return a;
};
const buildOpenEndedAnnotation = ({ endEpoch, recordsHeightMax }) =>
  Object.freeze(validateAnnotation({ endEpoch, recordsHeightMax }));

// ---- the report, a closed versioned schema ----
const REPORT_KIND = "tegara.e2.auditReport.v1";
const rangeOk = (r) => r === null || (r && typeof r === "object"
  && isDec(r.min) && isDec(r.max) && BigInt(r.min) <= BigInt(r.max));
const deepFreeze = (o, seen = new Set()) => {
  if (o && typeof o === "object" && !seen.has(o)) {
    seen.add(o);
    Object.freeze(o);
    for (const v of Object.values(o)) deepFreeze(v, seen);
  }
  return o;
};
/**
 * Assemble and validate the report. Every member is required, the member
 * set and every sub-shape are closed, and the verdict is computed here by
 * the grammar (never supplied). The contract identifier and expected
 * chain identifier are RECORDED AS SUPPLIED: this assembler cannot read
 * the owned environment keys, so binding these members to the actual pins
 * is the runAudit entry's obligation (the second half), and until it
 * lands they carry the caller's word. Overlap is computed only among
 * non-null height ranges and is NOT APPLICABLE, reported as such, when
 * fewer than two exist; overlap is a compatibility statement and NEVER
 * claims a common snapshot.
 */
const buildReport = ({ poolId, contractId, expectedChainId, startSource,
  configuredStart, branch, interval, annotation, coverage, aspects, epochs,
  lag, heightRanges, diagnostics, refusals }) => {
  if (typeof poolId !== "string" || !HEX64.test(poolId)) refuse("the report needs the pool's 64-hex identifier");
  if (typeof contractId !== "string" || contractId.length === 0) {
    refuse("the report requires the supplied contract identifier (the runAudit entry binds it to the owned CONTRACT_V11_ID pin)");
  }
  if (typeof expectedChainId !== "string" || expectedChainId.length === 0) {
    refuse("the report requires the supplied expected chain identifier (the runAudit entry binds it to the owned pin's chainId member)");
  }
  if (!["journal", "local-configuration", "explicit-input"].includes(startSource)) {
    refuse(`${show(startSource)} is not a start source`);
  }
  requireU32("configuredStart", configuredStart);
  const u32Field = (name, v) => {
    if (!Number.isSafeInteger(v) || v < 0 || v > U32_MAX) refuse(`${name} ${show(v)} is not a u32 epoch index`);
  };
  requirePlainClosed("interval", interval, ["startEpoch", "endEpoch"]);
  u32Field("interval.startEpoch", interval.startEpoch);
  if (interval.endEpoch !== null) u32Field("interval.endEpoch", interval.endEpoch);
  if (interval.endEpoch !== null && interval.endEpoch < interval.startEpoch) {
    refuse(`the report interval [${interval.startEpoch}, ${interval.endEpoch}] is reversed`);
  }
  // the branch invariant (round-3 finding 1): a proved deactivation
  // boundary always bounds the interval, so a bounded report with a null
  // end is incoherent evidence, never a gradable state
  if (branch === "deactivation-bounded" && interval.endEpoch === null) {
    refuse("the deactivation-bounded branch requires a non-null interval end (the boundary bounds it)");
  }
  requirePlainClosed("coverage", coverage, ["lateConfiguredStart", "containsUniverse", "narrowedRange"]);
  const abd = aspects && typeof aspects === "object"
    ? Object.getOwnPropertyDescriptor(aspects, "activationBoundary") : null;
  const activationRow = abd && "value" in abd ? abd.value : undefined;
  if (activationRow && typeof activationRow === "object") {
    const sd = Object.getOwnPropertyDescriptor(activationRow, "source");
    if (!sd || !("value" in sd) || sd.value !== startSource) {
      refuse(`the activation-boundary row must name the resolved start source as its OWN data member (got ${show(sd && "value" in sd ? sd.value : undefined)}, the report's is ${show(startSource)})`);
    }
  }
  if (branch === "open-ended") {
    validateAnnotation(annotation);
    if (annotation.endEpoch !== interval.endEpoch) {
      refuse(`the annotation's endEpoch ${show(annotation.endEpoch)} disagrees with the interval's ${show(interval.endEpoch)} (the annotation is the report's own time bound)`);
    }
  }
  if (!Array.isArray(epochs)) refuse("the report needs the per-epoch row array");
  const epochRows = [];
  for (let i = 0; i < epochs.length; i++) {
    const d = Object.getOwnPropertyDescriptor(epochs, i);
    if (!d || !("value" in d) || !d.enumerable) {
      refuse(`the per-epoch row array's index ${i} must be an own enumerable data element`);
    }
    const e = d.value;
    if (!e || typeof e !== "object") {
      refuse("every per-epoch row carries epochIndex, condition (token or null), r (canonical decimal string or null), undistributedCredits (canonical decimal string) and its diagnostics array");
    }
    requirePlainClosed("a per-epoch row", e,
      ["epochIndex", "condition", "r", "diagnostics", "undistributedCredits"]);
    if (!Number.isSafeInteger(e.epochIndex)
      || !(e.condition === null || (typeof e.condition === "string" && e.condition.length > 0))
      || !(e.r === null || isDec(e.r))
      || !isDec(e.undistributedCredits)
      || !Array.isArray(e.diagnostics)) {
      refuse("every per-epoch row carries epochIndex, condition (token or null), r (canonical decimal string or null) and its diagnostics array");
    }
    u32Field("a per-epoch row's epochIndex", e.epochIndex);
    // the row is REBUILT rather than copied, so a member added to the shape must
    // be added here too or it is validated and then silently dropped
    epochRows.push({ epochIndex: e.epochIndex, condition: e.condition, r: e.r,
      diagnostics: stringArray("a per-epoch row's diagnostics", e.diagnostics),
      undistributedCredits: e.undistributedCredits });
  }
  if (lag !== null) {
    requirePlainClosed("lag", lag, ["lagCount", "undistributedCredits"]);
    if (!(Number.isSafeInteger(lag.lagCount) && lag.lagCount >= 0 && isDec(lag.undistributedCredits))) {
      refuse("the lag member is null or { lagCount, undistributedCredits (canonical decimal string) }");
    }
  }
  requirePlainClosed("heightRanges", heightRanges, ["records", "universe", "balance"]);
  for (const cls of ["records", "universe", "balance"]) {
    if (heightRanges[cls] === undefined) refuse(`the ${cls} height-range class is required (null when unattested)`);
    if (heightRanges[cls] !== null) requirePlainClosed(`heightRanges.${cls}`, heightRanges[cls], ["min", "max"]);
    if (!rangeOk(heightRanges[cls])) {
      refuse("the report needs the three nullable per-class height ranges (records, universe, balance)");
    }
  }
  requirePlainClosed("diagnostics", diagnostics, ["extras", "orphans", "poolGlobal"]);
  const diagRows = {};
  for (const cls of ["extras", "orphans", "poolGlobal"]) {
    diagRows[cls] = stringArray(`diagnostics.${cls}`, diagnostics[cls]);
  }
  const refusalRows = stringArray("the in-report refusal list", refusals);
  const nonNull = ["records", "universe", "balance"].filter((k) => heightRanges[k] !== null);
  let overlap = "not-applicable";
  if (nonNull.length >= 2) {
    const mins = nonNull.map((k) => BigInt(heightRanges[k].min));
    const maxs = nonNull.map((k) => BigInt(heightRanges[k].max));
    const lo = mins.reduce((a, b) => (b > a ? b : a));
    const hi = maxs.reduce((a, b) => (b < a ? b : a));
    overlap = { overlaps: lo <= hi };
  }
  const verdict = gradeVerdict({ branch, aspects, inReportRefusal: refusalRows.length > 0,
    coverage, annotation: branch === "open-ended" ? annotation : null });
  const report = {
    v: 1, kind: REPORT_KIND, poolId,
    contractVersion: "v11", contractId, expectedChainId,
    startSource, configuredStart, branch,
    interval: { startEpoch: interval.startEpoch, endEpoch: interval.endEpoch },
    openEnded: branch === "open-ended"
      ? { endEpoch: annotation.endEpoch, recordsHeightMax: annotation.recordsHeightMax }
      : null,
    coverage: { ...coverage },
    aspects: Object.fromEntries(ASPECT_KEYS.map((k) => [k, { ...aspects[k] }])),
    epochs: epochRows,
    lag: lag === null ? null : { ...lag },
    heightRanges: {
      records: heightRanges.records === null ? null : { min: heightRanges.records.min, max: heightRanges.records.max },
      universe: heightRanges.universe === null ? null : { min: heightRanges.universe.min, max: heightRanges.universe.max },
      balance: heightRanges.balance === null ? null : { min: heightRanges.balance.min, max: heightRanges.balance.max },
      overlap },
    diagnostics: diagRows,
    refusals: refusalRows,
    verdict,
  };
  return deepFreeze(report);
};

// ============================================================================
// THE SECOND HALF: the evidence evaluators and the runAudit entry.
//
// WHAT THIS HALF ESTABLISHES: every aspect state the first half accepted
// as the caller's claim is now DERIVED from evidence: the per-receipt
// aspects run the canonical predicate subsets through e2ReceiptVerify
// (transfer execution over RELATIONAL plus CAPTURE-EXECUTION, reservation
// presence over RESERVATION-READ through the pinned proved byAccrual
// query, ordering over the deterministic capture predicate), formation
// inputs run the six-duty pair check, the allocation recomputation and
// the proved identity lookups, contract integrity compares the proved
// contract read against the expected registered payload, and the
// record-set aspect runs BOTH directions (forward per epoch of the
// interval including the permitted prefix, reverse over the five
// pool-wide enumerations with orphan, extra and ignored classification);
// when formation or an enumeration is unavailable, only the structural,
// grammar, prefix and settlement duties that need no allocation rows
// run, and the record set caps at UNPROVED with their refusals standing.
// runAudit binds the resolver outputs, the owned pins, the coverage
// booleans and the aspect states into one report, so THROUGH runAudit
// the evaluator-backed aspects take their labels from the injected
// evidence alone; the DECLARED TRUST INPUTS (expectedContractPayload,
// incomeIdentity, and the two boundary proofs) remain the harness's
// stated obligations, and the exported evaluators remain individually
// callable with caller-built evidence, per the seam list below. Four
// aspects
// (binding, temporalOrder, shareConformance, balance) are PINNED
// UNVERIFIABLE constants pending their own evidence routes: no
// evaluator derives them, and no caller supplies them (round-39).
//
// WHAT IT STILL DOES NOT ESTABLISH, stated: the network reads are
// INJECTED (the discovery fetch, the verified page fetch, the known-key
// proved reads, the receipt-verifier crypto pipeline, and the capture
// signature basis), so their cryptographic and transport obligations are
// the acceptance-stage adapters', exactly as for every prior unit. The
// BOUNDARY PROOFS are the same kind of seam (round-47): provedActivation
// and provedDeactivation are scalar epoch numbers whose PROOF provenance
// is the harness's declared obligation, like incomeIdentity; supplying
// one asserts a proved boundary, and this module validates only its
// grammar and interval consistency, never the proof itself; the
// battery proves the EVALUATION, the classification, the aggregation and
// the report binding over a synthetic world whose fixtures trace to the
// real constructors. Discovery's unproved status before C1 propagates to
// the universe aspect and is never upgraded here.
//
// FREEZE-RESOLVED DECISION (7), joining the header's list: a journal that
// fails D7 validation is REFUSED-INPUT for the audit (the journal is the
// start-source authority and the ordering evidence, and everywhere else
// in the machinery a refused journal is a hard stop, so no report rests
// on one).
//
// THE INJECTED CONTRACT, the acceptance-stage adapter's checkable
// obligations beyond the first half's:
// - fetchVerifiedPage: e2ProvedQuery's page contract (the same two
//   verification stages per page).
// - provedByKey(type, key): the pinned proved single-document read for a
//   KNOWN UNIQUE KEY; resolves to { status: "served", doc, height } |
//   { status: "proved-absence", height } | { status: "unserved" } |
//   { status: "unverified" }. Types used: "pool", "completionReceipt",
//   "identity", "contract", "reservationByAccrual", "receiptByAccrual",
//   "headerByEpoch" (key poolId+epochIndex, the expected-header fallback),
//   "accrualByKey" (key poolId+epochIndex+funderId, the expected-accrual
//   fallback) and "accrualById" (key accrualId, 64-hex; settles a
//   dependent whose accrual no enumeration or fallback resolved).
// - verifyCaptureBasis(capture, supersessions): capture validity clause 1
//   via e2CaptureRecord.selectSupersessionBasis and
//   verifyCaptureSignature with the adapter's key resolution; resolves
//   true exactly when a signature basis verifies.
// ============================================================================
const envStore = require("./envStore.cjs");
const { canonicalString } = require("./canonicalJson.cjs");
const { openValidatedJournal, K } = require("./e2Journal.cjs");
const receiptVerify = require("./e2ReceiptVerify.cjs");
const { HEADER_KIND, RECEIPT_KIND, SUPERSESSION_KIND } = require("./e2CaptureRecord.cjs");
const { checkReceiptAgainstPool } = require("./receiptPoolCheck.cjs");
const formationCore = require("./formationCore.cjs");
const { enumerateProved, plainDataSnapshot } = require("./e2ProvedQuery.cjs");

const startKeyOf = (poolId) => `E2_START_EPOCH_${poolId.toUpperCase()}`;

// identifier equality NORMALIZES to the raw 32 bytes (the spec's round-33
// rule): base58 and 64-hex spellings of one identifier compare equal, and
// anything that decodes to neither compares equal to nothing
const idHex = (v) => {
  if (typeof v === "string" && HEX64.test(v)) return v;
  const d = formationCore.toId32(v); // base58 strings, Buffers and byte views
  return d === null ? null : d.toString("hex");
};
const sameId = (a, b) => {
  const ah = idHex(a), bh = idHex(b);
  return ah !== null && ah === bh;
};
// the normalized KEY for identifier-keyed maps: equivalent spellings of
// one identifier land on one key, and a non-identifier value keys as its
// own string (its mismatch then surfaces in the content comparisons)
const nid = (v) => {
  const h = idHex(v);
  if (h !== null) return h;
  // TOTAL over adapter inputs, and the fallback can never LOOK like an
  // identifier (round-51): String([hex]) is that hex, so a one-element
  // array would coerce into a valid-looking key; only a STRING keeps
  // its own text (for diagnostics), every other non-identifier value is
  // bracketed so no grammar check can accept it. A null-prototype
  // object has no toString, so the coercion is guarded (round-48).
  if (typeof v === "string") return v;
  try { return `[non-identifier ${String(v)}]`; } catch { return "[unstringifiable value]"; }
};
// a credits field is a JSON INTEGER under the safe ceiling: any other
// scalar type is nonconforming however its text reads, so the comparator
// yields null (never equal to a decimal string) for a non-integer
// (round-32)
const intStr = (v) => (Number.isSafeInteger(v) ? String(v) : null);

// every proved-read answer declares one of the four statuses, a SERVED
// answer carries its document as a plain object AND its authenticated
// height as a canonical decimal string, and a proved absence carries the
// height too; anything else is an adapter defect and refuses hard (the
// same boundary the enumeration wrapper enforces per page). Heights on
// non-document reads (identity, contract) are validated here but stay
// OUTSIDE the records range, which covers document evidence only.
// PLAIN DATA at the boundary, over the COMPLETE value graph (the shared
// walk lives in e2ProvedQuery, which also applies it to every enumerated
// document): a getter-backed member is not stable evidence, because each
// read can serve a different value. The property established is one of
// the CAPTURE, not of the input (round-62): a Proxy can report a base
// prototype it does not have, so what the walk guarantees is that the
// returned graph is plain data carrying the validated members. VALIDATE-AND-CAPTURE (round-53): the walk returns a plain-data
// copy reconstructed from the descriptors it validated, and every caller
// reads THAT copy, never the injected object, so a Proxy cannot pass the
// walk and then serve a different value through its get trap. Callers must
// use the returned value, not the argument they passed in.
const requirePlainData = (what, obj) => {
  const { defect, value } = plainDataSnapshot(obj);
  if (defect) refuse(`${what} is not plain data (${defect})`);
  return value;
};

// perform a proved adapter read TOTALLY (round-57; the INVOCATION brought
// inside the guard round-61): a value that is resistant to property access,
// for example a REVOKED Proxy resolved by the adapter's promise, throws at the
// language-level `await` (the promise resolution's thenable check) before
// requireAnswer's own boundary runs. Reading inside a guard converts that into
// a plain adapter-fault refusal rather than an escaping raw TypeError. A normal
// resolved value passes through unchanged.
//
// THE ARGUMENT IS A THUNK, NOT A PROMISE, and that is the whole point of the
// round-61 change: passing the PROMISE evaluates the adapter call BEFORE
// entering this function, so an adapter that throws SYNCHRONOUSLY (rather than
// rejecting) escaped the guard entirely and propagated its raw fault, which is
// exactly what the guard exists to prevent. Taking a thunk puts the invocation
// itself inside the try, so a synchronous throw and a rejection are the same
// event to every caller.
const awaitRead = async (read) => {
  try { return await read(); }
  catch (e) { refuse(`a proved adapter read failed (${errText(e)}); an adapter fault is not evidence`); }
};

const requireAnswer = (ans, what) => {
  // the WHOLE envelope is validated as plain data AND CAPTURED before any
  // member is read (round-41, capture round-53): the caller reads the
  // returned snapshot, so a self-replacing accessor or a Proxy cannot
  // serve one value to a check and another to the consumer
  if (!ans || typeof ans !== "object" || safeIsArray(ans)) {
    // NO member interpolation here (round-52): a rejected envelope's
    // status could be accessor-backed, and even the refusal message
    // must not read it
    refuse(`${what} returned no plain answer envelope (the answer vocabulary is closed)`);
  }
  const snap = requirePlainData(`${what} answer envelope`, ans);
  const status = snap.status; // read from the captured copy, not the argument
  if (!["served", "proved-absence", "unserved", "unverified"].includes(status)) {
    refuse(`${what} returned an undeclared status (${show(status)}); the answer vocabulary is closed`);
  }
  if ((status === "served" || status === "proved-absence") && !isDec(snap.height)) {
    refuse(`${what} answered without its authenticated height as a canonical decimal string`);
  }
  // the union is DISCRIMINATED: members outside the declared variant are
  // contradictory shapes, not tolerated extras (round-40)
  requirePlainClosed(`${what} answer`, snap,
    status === "served" ? ["status", "doc", "height"]
      : status === "proved-absence" ? ["status", "height"] : ["status"],
    ["status"]);
  if (status === "served" && (!snap.doc || typeof snap.doc !== "object" || Array.isArray(snap.doc))) {
    refuse(`${what} served without a document (a plain object, never an array)`);
  }
  return snap;
};

// ---- per-receipt aspect evaluators ----

/**
 * RESERVATION-READ, through the pinned proved byAccrual answer: PROVED on
 * a served conforming chain, REFUSED on a served mismatch OR a proved
 * absence (a soundness-review finding), UNPROVED when the query cannot be served or verified.
 */
const evaluateReservationPresence = (receipt, answer) => {
  // read the CAPTURED plain-data copy, so a directly-passed Proxy answer
  // cannot pass the walk and then serve a different chain (round-53)
  answer = requireAnswer(answer, "the pinned proved reservation read");
  if (answer.status === "served"
    && (typeof answer.doc.id !== "string" || !HEX64.test(answer.doc.id))) {
    refuse("the pinned proved reservation read served a document without its 64-hex identifier (a nonconforming answer)");
  }
  if (answer.status === "served") {
    const d = answer.doc || {};
    if (!sameId(d.poolId, receipt.poolId) || !sameId(d.accrualId, receipt.accrualId)
      || typeof receipt.transitionHash !== "string" || !HEX64.test(receipt.transitionHash)
      || d.transitionHash !== receipt.transitionHash) {
      // the receipt's hash must BE a well-formed 64-hex value before
      // equality means anything (two absent members compare equal
      // without establishing that either record carries a hash,
      // round-33); equality then establishes the reservation's too
      return { label: "REFUSED", reason: "the fetched transferReservation's chain differs from the receipt's (a soundness-review finding)" };
    }
    return { label: "PROVED" };
  }
  if (answer.status === "proved-absence") {
    return { label: "REFUSED", reason: "a proved reservation absence refuses the receipt (a soundness-review finding)" };
  }
  return { label: "UNPROVED", reason: "the pinned proved byAccrual query could not be served or verified" };
};

/**
 * The transfer-execution predicate: RELATIONAL plus CAPTURE-EXECUTION,
 * nothing more (the reservation and ordering checks are EXCLUDED, each
 * governing its own aspect), so verifyReceipt runs with an unserved
 * reservation answer and the reservation aspect is evaluated separately.
 * CAPTURE-VERIFIED exactly when the receipt verifies, its served capture
 * record verifies with a clause-1 signature basis, and the pair equality
 * set holds; REFUSED otherwise (this row's terminal label).
 */
const evaluateTransferExecution = async ({ receipt, parts, entitlementRow, accrual, headerFor,
  incomeIdentity, chainIdPin, capture, supersessions, deps }) => {
  // RELATIONAL: the receipt's pool against its accrual's, the receipt's
  // accrual reference against the accrual itself, and the accrual's
  // (poolId, epochIndex) against an existing header, all checked HERE so
  // the exported evaluator establishes what its contract states
  if (!accrual || typeof accrual !== "object") {
    return { label: "REFUSED", reason: "the receipt's accrual is not available (the RELATIONAL subset)" };
  }
  if (!sameId(receipt.accrualId, accrual.id)) {
    return { label: "REFUSED", reason: "the receipt names a different accrual than the one served (the RELATIONAL subset)" };
  }
  if (!sameId(accrual.poolId, receipt.poolId)) {
    return { label: "REFUSED", reason: "the receipt's pool differs from its accrual's (the RELATIONAL subset)" };
  }
  if (!headerFor) {
    return { label: "REFUSED", reason: "the receipt's accrual names a (poolId, epochIndex) with no header (the RELATIONAL subset)" };
  }
  if (headerFor.epochIndex !== accrual.epochIndex || !sameId(headerFor.poolId, accrual.poolId)) {
    return { label: "REFUSED", reason: "the header does not match the accrual's (poolId, epochIndex) (the RELATIONAL subset)" };
  }
  if (!capture) {
    return { label: "REFUSED", reason: "no served receipt-capture record exists for the receipt (the capture IS the execution evidence)" };
  }
  // THE VERIFIER RETURNS ITS VERDICT (round-65). This reads the STATUS of a
  // value returned by a function it called directly, so there is no question of
  // where a caught object came from: a refusal is evidence because the verifier
  // SAID so in its return, and anything thrown is a fault that propagates. The
  // pipeline is still read once into a local, which is the capture-once rule
  // rather than a provenance defence.
  const verifierDeps = deps.verifierDeps;
  const receiptResult = await receiptVerify.verifyReceipt({ receipt, parts,
    reservation: { status: "unserved" }, entitlementRow, incomeIdentity, chainIdPin,
    deps: verifierDeps });
  if (receiptResult.status === "refused") {
    return { label: "REFUSED", reason: receiptResult.reason };
  }
  let basisOk;
  try { basisOk = await deps.verifyCaptureBasis(capture, supersessions); }
  catch (e) {
    throw new Error(`the capture-basis adapter failed (${errText(e)}); an adapter fault is not evidence; refusing hard`);
  }
  if (typeof basisOk !== "boolean") {
    throw new Error(`the capture-basis adapter returned a non-boolean (${show(basisOk)}); the adapter contract requires true or false; refusing hard`);
  }
  if (basisOk !== true) {
    return { label: "REFUSED", reason: "no capture signature basis verifies (validity clause 1)" };
  }
  const captureResult = await receiptVerify.verifyCaptureRecord({ capture,
    servedFor: { poolId: receipt.poolId, accrualId: receipt.accrualId },
    chainIdPin, deps: verifierDeps });
  if (captureResult.status === "refused") {
    return { label: "REFUSED", reason: captureResult.reason };
  }
  const pairResult = receiptVerify.verifyCapturePair({ capture, receipt, receiptResult, captureResult });
  if (pairResult.status === "refused") {
    return { label: "REFUSED", reason: pairResult.reason };
  }
  return { label: "CAPTURE-VERIFIED", captureValid: true };
};

/**
 * The deterministic ordering predicate: ATTESTED exactly when a VALID
 * served receipt-capture matches the receipt's transitionHash, the
 * pool-epoch's header capture exists and is VALID, both records'
 * heightRoute members are EQUAL (same-route equality, the testable form),
 * and the receipt record's inclusionHeight is STRICTLY greater. Anything
 * short is OPERATOR-PROVIDED, a label degradation, never a refusal. An
 * epoch under header-capture-incomplete has no valid header record, so
 * every receipt under it earns OPERATOR-PROVIDED by construction.
 *
 * `receiptCaptureValid` and `headerCaptureValid` are TRUSTED PRECONDITIONS
 * the caller establishes, not facts this evaluator verifies (round-54): the
 * entry passes `transfer.label === "CAPTURE-VERIFIED"` and the header-capture
 * validation result. This predicate arranges the ordering comparison ON TOP
 * of validated captures; it does not itself establish capture validity, so a
 * direct caller supplying `true` for either boolean asserts that validity
 * rather than proving it.
 */
const evaluateOrdering = ({ receipt, receiptCaptureValid, capture, headerCaptureValid, headerCapture }) => {
  if (!(receiptCaptureValid && capture && capture.transitionHash === receipt.transitionHash)) {
    return { label: "OPERATOR-PROVIDED" };
  }
  if (!(headerCaptureValid && headerCapture)) return { label: "OPERATOR-PROVIDED" };
  // BOTH routes must EXIST as nonempty strings before equality means
  // anything: two absent members compare equal without establishing that
  // either record carries a route (round-30)
  if (typeof capture.heightRoute !== "string" || capture.heightRoute.length === 0
    || capture.heightRoute !== headerCapture.heightRoute) {
    return { label: "OPERATOR-PROVIDED" };
  }
  if (!isDec(capture.inclusionHeight) || !isDec(headerCapture.inclusionHeight)) {
    return { label: "OPERATOR-PROVIDED" }; // a malformed height is a degradation here, never a throw
  }
  if (BigInt(capture.inclusionHeight) > BigInt(headerCapture.inclusionHeight)) {
    return { label: "ATTESTED" };
  }
  return { label: "OPERATOR-PROVIDED" };
};

// ---- the per-pool evaluators ----

/**
 * Formation inputs, per pool over the PINNED PROVED reads: the six-duty
 * pair check, allocation validity with the recomputed allocationHash, the
 * member count, the fee's well-formedness, and every recipient identity's
 * existence. PROVED when every check passes; REFUSED only on PROVED
 * NONCONFORMANCE (a verified response failing a check); a query that
 * cannot be served or verified leaves the aspect UNPROVED, never refused.
 * On success the result carries the parsed allocation rows (owner as
 * 64-hex, bps) and the pool's fee, the recomputation's inputs.
 */
const evaluateFormationInputs = async ({ poolId, contractId, deps }) => {
  // heights of ACCEPTED document answers, collected as the reads land,
  // so a later refusal or unavailability never drops an already-earned
  // height (round-28)
  const documentHeights = [];
  const unproved = (why) => ({ label: "UNPROVED", reason: why, rows: null, pool: null,
    heights: documentHeights.slice() });
  const refused = (why) => ({ label: "REFUSED", reason: why, rows: null, pool: null,
    heights: documentHeights.slice() });
  const poolAns = requireAnswer(await awaitRead(() => deps.provedByKey("pool", { poolId })), "the proved pool read");
  if (poolAns.status === "unserved" || poolAns.status === "unverified") {
    return unproved("the proved pool read could not be served or verified");
  }
  if (typeof poolAns.height === "string") documentHeights.push(poolAns.height);
  if (poolAns.status === "proved-absence") return refused("the pool's proved absence is nonconformance");
  // everything the served POOL already establishes is checked before any
  // later read can go unserved: an independently established
  // nonconformance stays visible whatever the other answers do. The
  // document identity is the Platform SYSTEM field $id, the one identity
  // a ledger-read document actually carries (the $ownerId lesson again).
  const pool = poolAns.doc;
  if (!sameId(pool["$id"], poolId)) {
    refuse(`the pool lookup for ${poolId.slice(0, 8)}... served a DIFFERENT pool (${show(pool["$id"])}); a nonconforming adapter answer`);
  }
  if (pool.nodeType !== "evo") {
    return refused(`the pool's nodeType ${show(pool.nodeType)} is not "evo" (the eligibility predicate)`);
  }
  const receiptAns = requireAnswer(await awaitRead(() => deps.provedByKey("completionReceipt", { poolId })),
    "the proved completion-receipt read");
  if (receiptAns.status === "unserved" || receiptAns.status === "unverified") {
    return unproved("the proved completion-receipt read could not be served or verified");
  }
  if (receiptAns.status === "proved-absence") {
    // a proved absence carries a real proof height, so it counts
    documentHeights.push(receiptAns.height);
    return refused("the completion receipt's proved absence is nonconformance");
  }
  // the pool and completion receipt are DOCUMENT queries, so their
  // authenticated heights enter the records range; the identity and
  // contract reads are not documents and stay outside it (the spec's
  // document-evidence-only rule)
  const fr = receiptAns.doc;
  if (!sameId(fr.poolId, poolId)) {
    // a NONCONFORMING served answer contributes nothing, its height
    // included (round-46): the height joins only after the binding
    return refused("the completion receipt names a different pool than the one under audit");
  }
  documentHeights.push(receiptAns.height);
  // the document owners are the Platform SYSTEM field $ownerId, the
  // one owner representation a ledger-read document actually carries
  // the expected pool identifier is the AUDITED one: substituting the
  // served receipt's own member would let a foreign pair verify itself
  const pair = checkReceiptAgainstPool({ contractId, receipt: fr, pool,
    poolId: Buffer.from(poolId, "hex"), // the audited pool, in the check's byte form
    receiptOwnerId: fr["$ownerId"], poolOwnerId: pool["$ownerId"] });
  if (!pair.ok) return refused(`the six-duty pair check refuses (${pair.reason})`);
  // the allocation verifier runs INSIDE the six-duty pair check (its
  // allocation duty calls formationCore.verifyReceiptAllocation), so a
  // second direct call here would be unobservable redundancy (round-37);
  // the pair refusal above carries the allocation reason when that duty
  // is the one that fails
  let rows;
  try {
    const arr = JSON.parse(Buffer.from(fr.allocationRows).toString("utf8"));
    rows = arr[5].map(([owner, amountDuffs, bps]) => {
      const decoded = formationCore.decodeId32(owner);
      if (decoded === null) throw new Error("an allocation owner does not decode to 32 bytes");
      return { funderId: decoded.toString("hex"), bps, amountDuffs };
    });
  } catch (e) { return refused(`the allocation rows do not parse (${e.message})`); }
  // the member-count correspondence (participantCount against the rows)
  // is enforced inside the pair-and-allocation chain above, so it is not
  // repeated here; the fee's grammar is
  // the fee grammar is enforced INSIDE the six-duty pair check (its
  // pool-shape duty refuses a non-integer or out-of-range
  // operatorFeeBps), so a second check here would be unobservable
  // redundancy (round-37); the pair refusal above carries that reason
  // EVERY row is examined before the verdict: an unserved read never
  // hides another row's proved absence, an early absence never skips a
  // later row's adapter-contract violation (which still refuses hard),
  // and refusals dominate unavailability
  let unservedIdentity = null;
  let absentIdentity = null;
  for (const row of rows) {
    const idAns = requireAnswer(await awaitRead(() => deps.provedByKey("identity", { identityId: row.funderId })),
      "the proved identity lookup");
    if (idAns.status === "unserved" || idAns.status === "unverified") {
      unservedIdentity = row.funderId;
      continue;
    }
    if (idAns.status === "proved-absence") {
      if (absentIdentity === null) absentIdentity = row.funderId;
      continue;
    }
    if (!sameId(idAns.doc.id, row.funderId)) {
      refuse(`the identity lookup for ${row.funderId.slice(0, 8)}... served a DIFFERENT identity (${show(idAns.doc.id)}); a nonconforming adapter answer`);
    }
  }
  if (absentIdentity !== null) {
    return refused(`recipient identity ${absentIdentity.slice(0, 8)}... has a proved absence`);
  }
  if (unservedIdentity !== null) {
    return unproved(`the proved identity lookup for ${unservedIdentity.slice(0, 8)}... could not be served or verified`);
  }
  return { label: "PROVED", rows, pool, heights: documentHeights,
    allocationHashHex: Buffer.from(fr.allocationHash).toString("hex") };
};

/**
 * Contract integrity (the design's authority table, header decision 3):
 * the proved contract read against the exact registered v11 payload,
 * compared canonically; ANY divergence is REFUSED (it prevents a
 * conformance grade until the permitted-change rules are read), an
 * unserved or unverified read is UNPROVED.
 */
const evaluateContractIntegrity = async ({ contractId, expectedContractPayload, deps }) => {
  // WHAT THIS ASPECT ESTABLISHES, exactly: canonical equality between
  // the proved contract read and the SUPPLIED registration payload. The
  // payload's own provenance (that it IS registerV11's stored publication
  // payload and not something derived from a fetch) is the harness's
  // obligation and cannot be established here; a caller feeding the
  // fetched object back in would prove only self-equality.
  if (!expectedContractPayload || typeof expectedContractPayload !== "object"
    || safeIsArray(expectedContractPayload)) {
    refuse("contract integrity needs the supplied registration payload (a plain object: registerV11's stored publication payload, never a value derived from the fetched result)");
  }
  // capture the payload as plain data and compare the CAPTURE (round-53):
  // a Proxy payload could pass the walk and then serve different members
  // to canonicalString, faking equality with the fetched contract
  expectedContractPayload = requirePlainData("the supplied registration payload", expectedContractPayload);
  // THE SUPPLIED PAYLOAD IS VALIDATED BEFORE THE ADAPTER READ (round-61):
  // this check used to sit after the read and after the unserved and
  // proved-absence returns, so a direct caller supplying a malformed payload
  // reached UNPROVED without the payload ever being examined, and an adapter
  // answering "unverified" could therefore sidestep the refusal entirely. A
  // malformed REQUEST is a property of the request alone, so nothing about the
  // world can excuse examining it. (runAudit refuses the same shape at the
  // entry; this is the defense in depth for direct callers, which only holds
  // if it runs on every path.)
  //
  // A registration payload carries no SYSTEM-NAMESPACE ($-prefixed) members,
  // and silently dropping a supplied one would let it hide a real difference
  // (a supplied "$policy" absent from the fetched contract would otherwise
  // compare equal after stripping), so a supplied $-member is refused rather
  // than stripped (round-55).
  const supplied$ = Object.keys(expectedContractPayload).filter((k) => k.startsWith("$"));
  if (supplied$.length) {
    refuse(`the supplied registration payload carries system-namespace members ${show(supplied$)} (a registration payload has none; a $-member would be dropped from the comparison)`);
  }
  const ans = requireAnswer(await awaitRead(() => deps.provedByKey("contract", { contractId })),
    "the proved contract read");
  if (ans.status === "unserved" || ans.status === "unverified") {
    return { label: "UNPROVED", reason: "the proved contract read could not be served or verified" };
  }
  if (ans.status === "proved-absence") {
    return { label: "REFUSED", reason: "the contract's proved absence is nonconformance" };
  }
  if (!sameId(ans.doc["$id"], contractId)) {
    refuse(`the contract lookup served a DIFFERENT contract (${show(ans.doc["$id"])}); a nonconforming adapter answer`);
  }
  // CANONICAL equality over the CONTRACT-DEFINED members, with the fetched
  // document's envelope removed by a CLOSED LIST, never by the $ prefix
  // (round-61). Stripping every $-prefixed fetched name discarded members
  // this module cannot account for: a fetched document carrying the right
  // envelope PLUS an unrecognized "$policy" compared equal, because the
  // extra member disappeared before the comparison. The audit cannot decide
  // whether such a member is a legitimate platform envelope member it has not
  // been taught or a real divergence, and the fail-closed reading of an
  // unrecognized member is that it is a divergence, so it REFUSES rather than
  // dropping it. Widening the list is a deliberate edit here, made when the
  // platform actually adds an envelope member, not a silent tolerance.
  // Member order never decides, and neither side can compare equal by
  // disappearing during serialization.
  // THE LIST IS DELIBERATELY MINIMAL AND EVIDENCE-BASED (narrowed round-62).
  // These are the document-envelope members this repository actually reads or
  // orders by against the platform; nothing else is assumed. The round-61
  // version also listed `$version`, `$format_version`, `$schema` and `$defs`
  // on no evidence, and the last two are the dangerous kind of guess, because
  // a data contract can carry them as REAL CONTENT, so stripping them would
  // have hidden a genuine divergence in exactly the document this aspect
  // exists to compare. An over-narrow list fails the SAFE way: an unlisted
  // member refuses loudly and is fixed by widening this list against the
  // platform's own envelope definition, which is one of the pinning-time
  // reads still owed. An over-wide list fails silently, which is why the
  // benefit of the doubt goes to refusing.
  const ENVELOPE_MEMBERS = ["$id", "$ownerId", "$revision",
    "$createdAt", "$updatedAt",
    "$createdAtBlockHeight", "$updatedAtBlockHeight",
    "$createdAtCoreBlockHeight", "$updatedAtCoreBlockHeight"];
  const fetched$ = Object.keys(ans.doc).filter((k) => k.startsWith("$"));
  const unrecognized$ = fetched$.filter((k) => !ENVELOPE_MEMBERS.includes(k));
  if (unrecognized$.length) {
    return { label: "REFUSED",
      reason: `the proved contract carries system-namespace members ${show(unrecognized$)} outside the known platform envelope, so the comparison cannot account for them` };
  }
  // this strip and a bare `!k.startsWith("$")` are EQUIVALENT HERE, because
  // the refusal above has already established that every remaining
  // $-prefixed fetched name is in the list. The list form is kept as the
  // single statement of which names are envelope members, so relaxing the
  // refusal cannot silently widen what is dropped.
  const stripSystem = (o) => Object.fromEntries(Object.entries(o).filter(([k]) => !ENVELOPE_MEMBERS.includes(k)));
  if (canonicalString(stripSystem(ans.doc)) !== canonicalString(expectedContractPayload)) {
    return { label: "REFUSED", reason: "the proved contract diverges from the registered v11 payload (its contract-defined members)" };
  }
  return { label: "PROVED" };
};

// ---- the record-set and lifecycle evaluation, both directions ----

/**
 * The bidirectional record-set aspect with the per-epoch lifecycle, the
 * per-receipt aspect evaluations it feeds, the orphan and extra sweeps,
 * the lag measure, and the in-report refusals (a prefix epoch failing its
 * zero-earning verification). Success is READ-CHECKED (a COMPOSITE
 * enumeration whose completeness is not snapshot-proved); a fetched
 * mismatch, a fetched extra, an orphan, or a proved absence of an
 * expected known-key record is REFUSED; unavailable evidence is UNPROVED.
 * The completeness cap covers UNKNOWN EXTRAS ONLY and is stated by the
 * READ-CHECKED ceiling, never claimed past it.
 */
const evaluateLedgerRecords = async ({ poolId, contractId, resolution, epochInfo,
  formation, chainIdPin, incomeIdentity, enums, journalRecords, deps }) => {
  const perEpoch = new Map();
  const diagnostics = { extras: [], orphans: [], poolGlobal: [] };
  const refusals = [];
  const recordSetLabels = [];
  const heightCandidates = [];
  let anyQueryUnserved = false;
  const perReceiptEpochLabels = { transferExecution: new Map(), reservationPresence: new Map(), ordering: new Map() };

  const proved = (t) => enums[t] && enums[t].status === "proved";
  // recovered accruals (joined by the pre-formation settlement) and the
  // settlement outcomes, declared HERE so the structural sweeps read
  // them on the unavailable path too (round-34)
  const recoveredAccruals = [];
  const danglingSettled = new Map();
  const allAccruals = () => [...(proved("accrual") ? enums.accrual.documents : []), ...recoveredAccruals];
  // the STRUCTURAL SWEEP over whatever is proved: an established
  // refusal (a duplicate, an orphan, an out-of-domain extra) must
  // survive an unproved sibling or unproved formation. It runs LAZILY,
  // only on the unavailable paths: the all-proved path re-establishes
  // the same findings through its forward and reverse passes AFTER the
  // known-key fallbacks, which can legitimately resolve an enumeration
  // omission that would read as an orphan here.
  // records in an IGNORED epoch (inside the universe, outside the
  // interval) are outside every validation obligation, so no structural
  // finding against them may refuse
  const ignoredEpoch = (epochIndex) => Number.isSafeInteger(epochIndex)
    && classifyRecordEpoch(epochIndex, resolution).bucket === "ignored";
  // record GRAMMAR is structural and holds on EVERY path (round-32): a
  // header or accrual whose epoch index is not a safe integer, or an
  // accrual whose funder cannot form an identifier, is nonconforming on
  // its face, before any recomputation
  const grammarSweep = () => {
    const found = [];
    for (const t of ["header", "accrual"]) {
      if (!proved(t)) continue;
      for (const d of enums[t].documents) {
        if (!Number.isSafeInteger(d.epochIndex)) {
          found.push(`${t} ${String(d.id).slice(0, 8)}... carries a malformed epoch index (${show(d.epochIndex)})`);
        }
      }
    }
    for (const a of allAccruals()) {
      // an IGNORED epoch carries no obligation, its funder grammar
      // included (round-42); a malformed epoch index cannot be
      // classified and stays a structural refusal above
      if (ignoredEpoch(a.epochIndex)) continue;
      if (idHex(a.funderId) === null) {
        found.push(`accrual ${String(a.id).slice(0, 8)}... carries a malformed funder identifier (${show(a.funderId)})`);
      }
    }
    return found;
  };
  // PREFIX duties that need no formation data hold on the unavailable
  // path too (round-33): the zero-earning verification and the
  // no-transfers rule are decidable from the epoch objects and the
  // proved enumerations alone
  const prefixSweep = () => {
    const found = [];
    for (const [epochIndex, epochObject] of epochInfo) {
      if (classifyRecordEpoch(epochIndex, resolution).bucket !== "prefix-permitted") continue;
      const pc = epochObject.proposedCount;
      const pcOk = Number.isSafeInteger(pc) || (typeof pc === "string" && DEC_RE.test(pc));
      if (!pcOk || BigInt(pc) !== 0n) {
        found.push(`prefix epoch ${epochIndex} fails its zero-earning verification (proposedCount ${show(pc)})`);
      }
      if (proved("header")) {
        const h = enums.header.documents.find((x) => x.epochIndex === epochIndex);
        if (h) {
          if (intStr(h.grossCredits) !== "0" || intStr(h.feeCredits) !== "0") {
            // intStr yields null for any non-integer, so this establishes
            // the field is not the JSON integer zero (round-53), never
            // that its represented value is numerically nonzero
            found.push(`prefix epoch ${epochIndex} header does not carry integer-zero credits`);
          }
          // calcVersion and the basic member GRAMMAR need no formation
          // rows (round-36); only the memberCount and allocationHash
          // VALUES do, and those wait for the full path
          if (h.calcVersion !== 1
            || !Number.isSafeInteger(h.memberCount) || h.memberCount < 0
            || typeof h.allocationHash !== "string" || !HEX64.test(h.allocationHash)) {
            found.push(`prefix epoch ${epochIndex} header calcVersion, memberCount or allocationHash is nonconforming`);
          }
        }
      }
      for (const a of allAccruals()) {
        if (a.epochIndex !== epochIndex) continue;
        if (intStr(a.amountCredits) !== "0") {
          found.push(`a prefix accrual in epoch ${epochIndex} does not carry an integer-zero amount`);
        }
        for (const t of ["reservation", "receipt", "part"]) {
          if (!proved(t)) continue;
          if (enums[t].documents.some((dd) => nid(dd.accrualId) === a.id)) {
            found.push(`transfer records exist under a prefix accrual in epoch ${epochIndex} (a zero-earning epoch has no transfers)`);
            break;
          }
        }
      }
    }
    return found;
  };
  const structuralSweep = () => {
    const found = [...grammarSweep(), ...prefixSweep()];
    const seenHeaderEpochs = new Set();
    if (proved("header")) {
      for (const h of enums.header.documents) {
        // a duplicate in an IGNORED epoch is ignored here too: the
        // normal path never refuses ignored records ON RECORD-SET grounds
        // (their envelope, plain-data and audited-pool duties already ran
        // upstream), and the sweep must reach the same classification
        // (round-19; scope narrowed round-60)
        if (ignoredEpoch(h.epochIndex)) continue;
        if (seenHeaderEpochs.has(h.epochIndex)) {
          found.push(`duplicate headers for epoch ${scalarShow(h.epochIndex)} (a fetched extra)`);
        } else seenHeaderEpochs.add(h.epochIndex);
      }
    }
    // the reference GRAMMAR is structural and needs no formation input:
    // a dependent whose accrual reference cannot form a 64-hex key is
    // nonconforming on its face, on every path (round-21)
    for (const t of ["reservation", "receipt", "part"]) {
      if (!proved(t)) continue;
      for (const d of enums[t].documents) {
        const k = nid(d.accrualId);
        if (typeof k !== "string" || !HEX64.test(k)) {
          found.push(`${t} ${String(d.id).slice(0, 8)}... carries a malformed accrual reference (${show(d.accrualId)})`);
        }
      }
    }
    // every dependent resolves or settles, on EVERY path (round-38): a
    // resolved accrual (enumerated or recovered) classifies the
    // dependent's epoch domain, a proved absence or a nonconforming
    // answer refuses, and an undecided settlement is a possible orphan.
    // The encoding-refused rule stays on the full path only, because it
    // needs the formation-derived recomputation.
    for (const t of ["reservation", "receipt", "part"]) {
      if (!proved(t)) continue;
      for (const d of enums[t].documents) {
        const k = nid(d.accrualId);
        if (typeof k !== "string" || !HEX64.test(k)) continue; // refused above
        const acc = accrualById.get(k);
        // a RESOLVED reference needs no per-dependent domain check here:
        // the accrual-level out-of-domain classification below refuses
        // the same state (round-38)
        if (acc) continue;
        const st = danglingSettled.get(k);
        if (st && st.kind === "absent") {
          found.push(`${t} ${String(d.id).slice(0, 8)}... names accrual ${k.slice(0, 8)}..., whose absence is proved (an orphan)`);
        } else if (st && st.kind === "nonconforming") {
          found.push(`the by-identifier read for accrual ${k.slice(0, 8)}... served a nonconforming answer`);
        } else {
          diagnostics.poolGlobal.push(`possible orphan ${t} ${String(d.id).slice(0, 8)}... (its accrual is not in the proved enumeration; unresolved on this path)`);
        }
      }
    }
    {
      // per-accrual MULTIPLICITY and duplicate SLOTS are structural too,
      // recoveries included, whatever the accrual enumeration's state
      const ids = new Set(allAccruals().map((a) => a.id));
      const epochOf = new Map();
      for (const a of allAccruals()) epochOf.set(a.id, a.epochIndex);
      // duplicate ACCRUAL SLOTS are structural too: two proved accruals
      // for one (epoch, funder) pair are fetched extras whatever
      // formation says, needing no formation data to compare (round-31);
      // ignored epochs carry no RECORD-SET or lifecycle obligation once
      // resolved (envelope, plain-data and audited-pool duties still ran
      // upstream), here as everywhere (scope narrowed round-60)
      const slotCount = new Map();
      for (const a of allAccruals()) {
        if (ignoredEpoch(a.epochIndex)) continue;
        // a malformed epoch index is ALREADY a structural refusal from the
        // grammar sweep (round-53): skip the slot key so an interpolation
        // of a null-prototype epoch index cannot throw an untyped
        // TypeError before unavailable() returns the structural refusal
        if (!Number.isSafeInteger(a.epochIndex)) continue;
        const slot = `${a.epochIndex}:${nid(a.funderId)}`;
        slotCount.set(slot, (slotCount.get(slot) || 0) + 1);
      }
      for (const [slot, n] of slotCount) {
        if (n > 1) found.push(`${n} accruals share the slot (epoch:funder) ${slot.slice(0, 20)}... (a fetched extra)`);
      }
      // the n>1 multiplicity rule covers reservations and receipts ONLY,
      // because those are one-per-accrual by construction. PARTS are
      // deliberately excluded (round-54): a receipt legitimately has up to
      // proofPartCount-1 part documents under one accrual, so a per-accrual
      // count above one is not a structural extra. Part surplus, a duplicate
      // part index, and a wrong part count are validated against the
      // receipt's proofPartCount by the transfer aspect (verifyReceipt),
      // which runs on the full (formation-PROVED) path only and refuses the
      // receipt and so the report. This structural sweep deliberately does
      // NOT re-implement that proofPartCount check (round-55 correction: the
      // earlier note wrongly said the unavailable path has no receipt; the
      // receipt and part enumerations can be proved while formation is not).
      // So a part surplus that coincides with unavailable formation is not a
      // structural finding here; it is caught only when formation is proved
      // and verifyReceipt runs. Widening the structural sweep to bound part
      // counts formation-independently is a deliberate future choice, not an
      // omission this sweep silently relies on.
      for (const t of ["reservation", "receipt"]) {
        if (!proved(t)) continue;
        const perAccrual = new Map();
        for (const d of enums[t].documents) {
          const k = nid(d.accrualId);
          if (!ids.has(k)) continue; // orphans reported above
          if (ignoredEpoch(epochOf.get(k))) continue; // ignored records never refuse the record set
          perAccrual.set(k, (perAccrual.get(k) || 0) + 1);
        }
        for (const [k, n] of perAccrual) {
          if (n > 1) found.push(`${n} ${t}s under accrual ${k.slice(0, 8)}... (a fetched extra)`);
        }
      }
    }
    if (proved("header")) {
      for (const d of enums.header.documents) {
        if (Number.isSafeInteger(d.epochIndex)
          && classifyRecordEpoch(d.epochIndex, resolution).bucket === "extra") {
          found.push(`header ${String(d.id).slice(0, 8)}... resolves to epoch ${d.epochIndex}, outside the validation domain`);
        }
      }
    }
    for (const d of allAccruals()) {
      if (Number.isSafeInteger(d.epochIndex)
        && classifyRecordEpoch(d.epochIndex, resolution).bucket === "extra") {
        found.push(`accrual ${String(d.id).slice(0, 8)}... resolves to epoch ${d.epochIndex}, outside the validation domain`);
      }
    }
    return found;
  };
  const unavailable = (why) => {
    const found = structuralSweep();
    for (const f of found) diagnostics.poolGlobal.push(f);
    return {
      recordSet: found.length
        ? { label: "REFUSED", reason: `${why}; ${found.length} structural refusal(s) stand regardless` }
        : { label: "UNPROVED", reason: why },
      aggregates: { transferExecution: "UNPROVED", reservationPresence: "UNPROVED", ordering: "UNPROVED" },
      perEpoch, diagnostics, refusals, receiptEvaluations: [],
      lag: null, heightCandidates, recordsProved: false,
    };
  };
  // the pool binding runs over every PROVED enumeration FIRST, so an
  // unproved sibling never hides a foreign document already served
  for (const t of ["header", "accrual", "reservation", "receipt", "part"]) {
    if (!proved(t)) continue;
    for (const d of enums[t].documents) {
      if (!sameId(d.poolId, poolId)) {
        refuse(`the ${t} enumeration served a document for a DIFFERENT pool (${show(d.poolId)}); a nonconforming adapter answer`);
      }
    }
  }
  // index the PROVED enumerations (round-35: built BEFORE the
  // availability gates, so the settlement and the structural sweeps can
  // read them on every path)
  const headersByEpoch = new Map();
  const pendingEpochIssues = new Map();
  const epochIssue = (epochIndex, msg) => {
    if (!pendingEpochIssues.has(epochIndex)) pendingEpochIssues.set(epochIndex, []);
    pendingEpochIssues.get(epochIndex).push(msg);
  };
  if (proved("header")) {
    for (const h of enums.header.documents) {
      if (headersByEpoch.has(h.epochIndex)) {
        epochIssue(h.epochIndex, `duplicate headers for epoch ${scalarShow(h.epochIndex)} (a fetched extra)`);
      } else headersByEpoch.set(h.epochIndex, h);
    }
  }
  const accrualsByEpoch = new Map();
  const accrualById = new Map();
  if (proved("accrual")) {
    for (const a of enums.accrual.documents) {
      if (!accrualsByEpoch.has(a.epochIndex)) accrualsByEpoch.set(a.epochIndex, []);
      accrualsByEpoch.get(a.epochIndex).push(a);
      // enumerated document ids are wrapper-guaranteed 64-hex, so the key
      // needs no normalization HERE; the lookups normalize their inputs,
      // which arrive as adapter-side references in either spelling
      accrualById.set(a.id, a);
    }
  }
  const byAccrual = (docs) => {
    const m = new Map();
    for (const d of docs) {
      const k = nid(d.accrualId);
      if (!m.has(k)) m.set(k, []);
      m.get(k).push(d);
    }
    return m;
  };
  const reservationsByAccrual = byAccrual(proved("reservation") ? enums.reservation.documents : []);
  const receiptsByAccrual = byAccrual(proved("receipt") ? enums.receipt.documents : []);
  const partsByAccrual = byAccrual(proved("part") ? enums.part.documents : []);

  // PRE-SETTLEMENT (round-23; before the formation gate since round-34,
  // and before the ENUMERATION gate since round-35, because settlement
  // needs only a proved accrual enumeration and the proved dependent
  // enumerations, so its outcomes hold on the unavailable paths too):
  // every dangling accrual reference is settled by the pinned
  // by-identifier read BEFORE the forward pass, and a conforming served
  // document JOINS the resolution indexes with its identifier
  // NORMALIZED (round-35: an equivalent base58 spelling must not defeat
  // the sweeps), so the forward pass runs the SAME conformance checks
  // on a recovered accrual, its dependents included, as on an
  // enumerated one. Joining never upgrades anything: each in-scope or
  // prefix recovery still marks the enumeration INCOMPLETE (UNPROVED).
  // Absent, undecided and nonconforming settlements are handled per
  // dependent in the reverse pass and by the structural sweep.
  const settleDangling = async (accrualIdRaw) => {
    if (danglingSettled.has(accrualIdRaw)) return danglingSettled.get(accrualIdRaw);
    const ans = requireAnswer(await awaitRead(() => deps.provedByKey("accrualById", { accrualId: accrualIdRaw })),
      `accrual ${accrualIdRaw.slice(0, 8)}... (by identifier, for a dangling reference)`);
    let out;
    if (ans.status === "unserved" || ans.status === "unverified") {
      anyQueryUnserved = true;
      out = { kind: "undecided" };
    } else if (ans.status === "proved-absence") {
      heightCandidates.push(ans.height);
      out = { kind: "absent" };
    } else if (!sameId(ans.doc.id, accrualIdRaw) || !sameId(ans.doc.poolId, poolId)
      || !Number.isSafeInteger(ans.doc.epochIndex)) {
      // a nonconforming answer contributes NOTHING, its height included
      out = { kind: "nonconforming" };
    } else {
      heightCandidates.push(ans.height);
      out = { kind: "present", doc: ans.doc };
    }
    danglingSettled.set(accrualIdRaw, out);
    return out;
  };
  // settlement runs whenever a PROVED dependent enumeration carries a
  // reference the resolution does not (round-37: the accrual
  // enumeration's own availability is irrelevant, because the pinned
  // by-identifier read is its own proof)
  for (const t of ["reservation", "receipt", "part"]) {
    if (!proved(t)) continue;
    for (const d of enums[t].documents) {
      const key = nid(d.accrualId);
      if (typeof key !== "string" || !HEX64.test(key)) continue; // refused in the reverse pass and the sweep
      if (accrualById.has(key)) continue;
      const settled = await settleDangling(key);
      if (settled.kind !== "present") continue;
      const joined = { ...settled.doc, id: key };
      accrualById.set(key, joined);
      recoveredAccruals.push(joined);
      if (!accrualsByEpoch.has(joined.epochIndex)) accrualsByEpoch.set(joined.epochIndex, []);
      accrualsByEpoch.get(joined.epochIndex).push(joined);
      const bucket = classifyRecordEpoch(joined.epochIndex, resolution).bucket;
      if (bucket === "in-scope" || bucket === "prefix-permitted") {
        diagnostics.poolGlobal.push(`accrual ${key.slice(0, 8)}... exists by pinned read but is absent from the enumerated resolution (the enumeration is INCOMPLETE on this audit)`);
        recordSetLabels.push("UNPROVED");
      }
    }
  }

  for (const t of ["header", "accrual", "reservation", "receipt", "part"]) {
    if (!proved(t)) {
      return unavailable(`the ${t} enumeration could not be served or verified`);
    }
    heightCandidates.push(enums[t].heightMin, enums[t].heightMax);
  }

  // the income identity is OPERATOR-SUPPLIED to the audit until a pinned
  // identity-resolution read exists (the store's own resolution is
  // branch-local state, not ledger evidence); the sender binding below
  // is therefore only as strong as this input, which the report's
  // transfer aspect already caps at CAPTURE-VERIFIED. incomeIdentity is the
  // value runAudit CAPTURED once at the entry and threaded here (round-55),
  // so the entry validation and every use see one value, never a second
  // read of a mutable deps member.


  // the journal's capture material (the ordering evidence)
  const receiptCaptures = new Map(); // transitionHash -> capture record
  const headerCaptures = new Map();  // epochIndex -> capture record
  const supersessions = [];
  for (const r of journalRecords) {
    if (r.kind === RECEIPT_KIND) receiptCaptures.set(r.transitionHash, r);
    else if (r.kind === HEADER_KIND) headerCaptures.set(r.epochIndex, r);
    else if (r.kind === SUPERSESSION_KIND) supersessions.push(r);
  }
  const supersessionsFor = (c) => supersessions.filter((x) => x.supersededKind === c.kind);
  // header-capture validity, once per epoch (clause 1 basis plus clauses
  // 2, 3, 4 and 6; the pair clause 5 is receipt-relative)
  // capture records carry the contract as 32-byte hex while the pin is
  // base58; every identifier comparison at this boundary NORMALIZES by
  // decoding to the raw bytes (the spec's round-33 rule)
  const contractDecoded = formationCore.decodeId32(contractId);
  const contractHex = contractDecoded === null
    ? contractId : Buffer.from(contractDecoded).toString("hex");
  const headerCaptureValid = new Map();
  const headerCaptureCheck = async (epochIndex) => {
    if (headerCaptureValid.has(epochIndex)) return headerCaptureValid.get(epochIndex);
    const cap = headerCaptures.get(epochIndex);
    let valid = false;
    if (cap) {
      let basis;
      try { basis = await deps.verifyCaptureBasis(cap, supersessionsFor(cap)); }
      catch (e) {
        throw new Error(`the capture-basis adapter failed (${errText(e)}); an adapter fault is not evidence; refusing hard`);
      }
      if (typeof basis !== "boolean") {
        throw new Error(`the capture-basis adapter returned a non-boolean (${show(basis)}); the adapter contract requires true or false; refusing hard`);
      }
      if (basis === true) {
        // the verdict is RETURNED (round-65): a refusal means the capture is
        // invalid, which is evidence; a throw is a fault and propagates
        const headerVerifierDeps = deps.verifierDeps;
        const capResult = await receiptVerify.verifyCaptureRecord({ capture: cap,
          servedFor: { poolId, epochIndex, contractId: contractHex },
          chainIdPin, deps: headerVerifierDeps });
        valid = capResult.status === "verified";
      }
    }
    headerCaptureValid.set(epochIndex, valid);
    return valid;
  };

  // a missing EXPECTED record at a KNOWN UNIQUE KEY: the pinned proved
  // query decides (served = a page omission, refuses nothing; proved
  // absence REFUSES; unservable leaves the aspect UNPROVED)
  // a served known-key answer must BE the requested key's document: a
  // proof for a different key is a nonconforming answer, never a stand-in
  const KEY_BINDS = {
    headerByEpoch: (doc, key) => sameId(doc.poolId, key.poolId) && doc.epochIndex === key.epochIndex,
    accrualByKey: (doc, key) => sameId(doc.poolId, key.poolId)
      && doc.epochIndex === key.epochIndex && sameId(doc.funderId, key.funderId),
    receiptByAccrual: (doc, key) => sameId(doc.accrualId, key.accrualId)
      && sameId(doc.poolId, key.poolId),
  };
  const knownKeyFetch = async (type, key, epochLabels, what) => {
    const ans = requireAnswer(await awaitRead(() => deps.provedByKey(type, key)), `${what} (known-key)`);
    if (ans.status === "unserved" || ans.status === "unverified") {
      epochLabels.push("UNPROVED");
      anyQueryUnserved = true;
      return { doc: null, note: `${what}: the known-key proved query could not be served or verified` };
    }
    if (ans.status === "proved-absence") {
      heightCandidates.push(ans.height); // a proved absence carries a real proof height
      epochLabels.push("REFUSED");
      return { doc: null, note: `${what}: proved absent (an expected record at a known unique key)` };
    }
    // a NONCONFORMING served answer contributes NOTHING, its height
    // included: only a conforming answer's proof enters the range. An answer
    // bound to a DIFFERENT key than the one asked for attests nothing about the
    // key requested, so letting its height widen the published range would show
    // a reader evidence the run does not have. The specification said "every
    // query performed" until 2026-08-25 and now says every query performed AND
    // ACCEPTED (a soundness-review finding); this is the site that decides which.
    if (!KEY_BINDS[type](ans.doc, key)) {
      epochLabels.push("REFUSED");
      return { doc: null, note: `${what}: the served answer is for a DIFFERENT key (a nonconforming answer)` };
    }
    if (typeof ans.doc.id !== "string" || !HEX64.test(ans.doc.id)) {
      epochLabels.push("REFUSED");
      return { doc: null, note: `${what}: the served document carries no 64-hex identifier (a nonconforming answer)` };
    }
    heightCandidates.push(ans.height);
    // an ENUMERATION OMISSION recovered by a unique-key read means the
    // enumeration was INCOMPLETE, exactly as the by-identifier settlement
    // marks a recovered accrual (round-54, F5): a served-conforming
    // known-key stand-in degrades record-set completeness to UNPROVED and
    // reports the omission, rather than standing in silently and leaving the
    // epoch READ-CHECKED. All three known-key call sites sit in the in-scope
    // forward pass, so the omission is always inside a validation domain.
    epochLabels.push("UNPROVED");
    return { doc: ans.doc,
      note: `${what}: recovered by a unique-key read but ABSENT from the enumeration (the enumeration is INCOMPLETE on this audit)` };
  };

  // the FORMATION gate runs AFTER settlement (round-34): everything
  // above needs no allocation rows, so its findings hold on the
  // unavailable path; only the recomputation below needs formation
  if (!formation || formation.label !== "PROVED") {
    return unavailable("the expected sets cannot be recomputed without proved formation inputs");
  }
  const rows = formation.rows;
  const feeBps = formation.pool.operatorFeeBps;

  const intervalEpochs = [];
  if (resolution.interval.endEpoch !== null) {
    for (let e = resolution.interval.startEpoch; e <= resolution.interval.endEpoch; e++) intervalEpochs.push(e);
  }
  const receiptEvaluations = [];
  let lagCount = 0;
  let undistributed = 0n;

  for (const epochIndex of intervalEpochs) {
    const bucket = classifyRecordEpoch(epochIndex, resolution).bucket;
    const epochLabels = [];
    // THE PER-EPOCH UNDISTRIBUTED AMOUNT (a soundness-review finding). The specification requires the
    // report to give this per epoch and the reader kept only a run-wide total,
    // which a reader cannot decompose after the fact: a total says how much went
    // undistributed and never in which epoch. It starts at zero, which is the
    // right value for every row emitted before the receipt walk runs.
    let epochUndistributed = 0n;
    const rowOut = { epochIndex, condition: null, r: null, diagnostics: [],
      undistributedCredits: "0" };
    const epochObject = epochInfo.get(epochIndex);
    if (!epochObject) {
      // UNREACHABLE THROUGH `runAudit`, WHICH IS NOT THE SAME AS UNREACHABLE
      // (scope corrected round-63, after the earlier wording claimed the
      // latter). Through the entry, discovery returns the exact gapless
      // ascending sequence from the requested start through the newest
      // finalized epoch and every resolved interval end sits at or below that
      // newest, so every epoch of I has an object. But this evaluator is
      // EXPORTED and a direct caller supplies `epochInfo` and `resolution`
      // independently, so a direct caller reaches this branch whenever the
      // two disagree, which is exactly the case it is here for. Fail-visible
      // by design (UNPROVED, never silently complete), and gated through the
      // direct-call path rather than asserted unreachable.
      epochLabels.push("UNPROVED");
      rowOut.diagnostics.push("no epoch object was discovered for this epoch");
      perEpoch.set(epochIndex, rowOut);
      recordSetLabels.push(...epochLabels);
      continue;
    }

    if (bucket === "prefix-permitted") {
      // the zero-earning verification, epoch by epoch: the node absent
      // from its proposer set, or the report refuses (an IN-REPORT
      // refusal, grammar step 1)
      const pc = epochObject.proposedCount;
      const pcOk = Number.isSafeInteger(pc) || (typeof pc === "string" && DEC_RE.test(pc));
      if (!pcOk) {
        refusals.push(`prefix epoch ${epochIndex} proposer count is malformed (${show(pc)}); zero-earning is unverifiable`);
      } else if (BigInt(pc) !== 0n) {
        refusals.push(`prefix epoch ${epochIndex} fails its zero-earning verification (proposedCount ${pc})`);
      }
      // prefix records, when any exist, are validated as zero-earning and
      // are NEVER extras; their absence is equally conformant
      const h = headersByEpoch.get(epochIndex);
      if (h) {
        if (intStr(h.grossCredits) !== "0" || intStr(h.feeCredits) !== "0") {
          epochLabels.push("REFUSED");
          rowOut.diagnostics.push("a prefix header does not carry integer-zero credits");
        }
        if (h.calcVersion !== 1
          || (formation.rows && h.memberCount !== formation.rows.length)
          || (formation.allocationHashHex && (typeof h.allocationHash !== "string" || h.allocationHash !== formation.allocationHashHex))) {
          epochLabels.push("REFUSED");
          rowOut.diagnostics.push("a prefix header's calcVersion, memberCount or allocationHash is nonconforming");
        }
      }
      const prefixFunders = new Set();
      for (const a of accrualsByEpoch.get(epochIndex) || []) {
        if (intStr(a.amountCredits) !== "0") {
          epochLabels.push("REFUSED");
          rowOut.diagnostics.push("a prefix accrual does not carry an integer-zero amount");
        }
        if (formation.rows && !formation.rows.some((r) => sameId(r.funderId, a.funderId))) {
          epochLabels.push("REFUSED");
          rowOut.diagnostics.push("a prefix accrual names a funder outside the allocation");
        }
        if (prefixFunders.has(nid(a.funderId))) {
          epochLabels.push("REFUSED");
          rowOut.diagnostics.push("duplicate prefix accruals for one funder (a fetched extra)");
        }
        prefixFunders.add(nid(a.funderId));
        if ((reservationsByAccrual.get(nid(a.id)) || []).length
          || (receiptsByAccrual.get(nid(a.id)) || []).length
          || (partsByAccrual.get(nid(a.id)) || []).length) {
          epochLabels.push("REFUSED");
          rowOut.diagnostics.push("transfer records exist under a prefix accrual (a zero-earning epoch has no transfers)");
        }
      }
      for (const msg of pendingEpochIssues.get(epochIndex) || []) {
        epochLabels.push("REFUSED");
        rowOut.diagnostics.push(msg);
      }
      rowOut.r = null;
      perEpoch.set(epochIndex, rowOut);
      recordSetLabels.push(...(epochLabels.length ? epochLabels : ["READ-CHECKED"]));
      continue;
    }

    // a universe epoch: recompute, then compare the fetched sets
    const normative = computeNormativeEpoch({
      totalProcessingFees: epochObject.totalProcessingFees,
      totalDistributedStorageFees: epochObject.totalDistributedStorageFees,
      coreBlockRewards: epochObject.coreBlockRewards,
      totalBlocks: epochObject.totalBlocks, proposedCount: epochObject.proposedCount,
      operatorFeeBps: feeBps, rows });
    if (normative.encodingRefused !== null) {
      rowOut.condition = "encoding-refused";
      rowOut.r = null;

      // the writer refuses BEFORE the header, so the epoch expects NO
      // records; any fetched record under it is a mismatch
      if (headersByEpoch.has(epochIndex) || (accrualsByEpoch.get(epochIndex) || []).length) {
        epochLabels.push("REFUSED");
        rowOut.diagnostics.push("records exist under an encoding-refused epoch");
      }
      perEpoch.set(epochIndex, rowOut);
      recordSetLabels.push(...(epochLabels.length ? epochLabels : ["READ-CHECKED"]));
      continue; // the named condition is conformant, never counted lagging
    }
    rowOut.r = normative.r;
    const positiveRows = [];
    normative.owed.forEach((o, i) => {
      if (BigInt(o.amountCredits) > 0n) positiveRows.push({ ...rows[i], amountCredits: o.amountCredits });
    });
    if (BigInt(normative.G) === 0n) rowOut.condition = "zero-earning-epoch";
    else if (positiveRows.length === 0) rowOut.condition = "zero-entitlement";

    // FORWARD: the header, present with every compared field equal
    let header = headersByEpoch.get(epochIndex);
    if (!header) {
      const kk = await knownKeyFetch("headerByEpoch", { poolId, epochIndex }, epochLabels,
        `epoch ${epochIndex} header`);
      if (kk.note) rowOut.diagnostics.push(kk.note);
      header = kk.doc;
    }
    let epochComplete = true;
    if (header) {
      const mismatches = [];
      if (intStr(header.grossCredits) !== normative.G) mismatches.push(`grossCredits ${show(header.grossCredits)} != ${normative.G}`);
      if (intStr(header.feeCredits) !== normative.fee) mismatches.push(`feeCredits ${show(header.feeCredits)} != ${normative.fee}`);
      if (header.memberCount !== rows.length) mismatches.push(`memberCount ${scalarShow(header.memberCount)} != ${rows.length}`);
      if (header.calcVersion !== 1) mismatches.push(`calcVersion ${scalarShow(header.calcVersion)} != 1 (the normative calculation is version 1)`);
      // a non-string allocationHash is a mismatch, never a String() throw on
      // a null-prototype value the plain-data domain admits (round-54)
      if (formation.allocationHashHex && (typeof header.allocationHash !== "string" || header.allocationHash !== formation.allocationHashHex)) {
        mismatches.push("allocationHash differs from the formation receipt's");
      }
      if (mismatches.length) {
        epochLabels.push("REFUSED");
        rowOut.diagnostics.push(`header mismatch: ${mismatches.join("; ")}`);
        epochComplete = false;
      }
    } else { epochComplete = false; }

    // FORWARD: the accrual set, exactly the recomputation's
    const fetchedAccruals = accrualsByEpoch.get(epochIndex) || [];
    const expectedByFunder = new Map(normative.owed.map((o, i) => [nid(rows[i].funderId), o.amountCredits]));
    const seenFunders = new Set();
    const accrualFor = new Map();
    for (const a of fetchedAccruals) {
      const fk = nid(a.funderId);
      if (!expectedByFunder.has(fk) || seenFunders.has(fk)) {
        epochLabels.push("REFUSED");
        rowOut.diagnostics.push(`an accrual for ${fk.slice(0, 8)}... is outside the recomputed set (a fetched extra)`);
        epochComplete = false;
        continue;
      }
      seenFunders.add(fk);
      if (intStr(a.amountCredits) !== expectedByFunder.get(fk)) {
        epochLabels.push("REFUSED");
        rowOut.diagnostics.push(`accrual amount ${scalarShow(a.amountCredits)} differs from the recomputed ${expectedByFunder.get(fk)}`);
        epochComplete = false;
      }
      accrualFor.set(fk, a);
    }
    for (const [funderId] of expectedByFunder) {
      if (!seenFunders.has(funderId)) {
        const kk = await knownKeyFetch("accrualByKey", { poolId, epochIndex, funderId },
          epochLabels, `epoch ${epochIndex} accrual for ${funderId.slice(0, 8)}...`);
        if (kk.note) rowOut.diagnostics.push(kk.note);
        if (kk.doc) {
          // the fallback joins the resolution index UNCONDITIONALLY, the
          // same as an enumerated accrual: a nonconforming amount refuses
          // the epoch, but the document exists, so its dependents never
          // read as orphans
          accrualById.set(kk.doc.id, kk.doc); // 64-hex, guaranteed by knownKeyFetch
          if (intStr(kk.doc.amountCredits) !== expectedByFunder.get(funderId)) {
            epochLabels.push("REFUSED");
            rowOut.diagnostics.push(`accrual amount ${scalarShow(kk.doc.amountCredits)} differs from the recomputed ${expectedByFunder.get(funderId)}`);
            epochComplete = false;
          } else {
            accrualFor.set(funderId, kk.doc);
          }
        } else epochComplete = false;
      }
    }

    // FORWARD: reservation, receipt and parts for exactly the POSITIVE
    // entitlements, with the per-receipt aspects evaluated as found.
    //
    // ONE RECORD PER POSITIVE ROW, appended once, complete. The three
    // per-receipt aspects are three faces of ONE evaluation of ONE row. They
    // used to live in three parallel arrays appended by hand at a dozen
    // sites, several of them in branches that leave the iteration early, so
    // "every path contributes to all three" was a convention held by hand. A
    // path contributing to two of the three would have left the arrays
    // disagreeing in length, and the consumer below aggregated each array on
    // its own without ever comparing them, so nothing would have noticed.
    //
    // HOW THIS ARRIVED AT ONE CHECK RATHER THAN FOUR, because the history is
    // the argument. The first version of this change kept a MUTABLE slot that
    // each branch filled member by member. Three review rounds then found one
    // route after another around a half-built object: net-only cardinality,
    // then a silent second assignment where an append could not overwrite,
    // then mutation after the fact, then a writable row index the ordering
    // check rested on. Each was closed with another guard, and each guard
    // admitted the next route. The object was the defect. A record that is
    // built as a plain local value and appended ONCE, complete, has no
    // half-built state to protect, so the write-once members, the fixed-index
    // accessor and the immutability argument are deleted rather than
    // defended. `appendReceiptRow` validates exactly the three labels, takes
    // the row only at the position its index names, and freezes what it
    // appends.
    //
    // WHAT IS DELIBERATELY NOT GUARDED, named in full so the next round does
    // not rediscover it as a finding. `receiptRows` is an ordinary array after
    // the append returns, so a later edit to this evaluator can push to it
    // directly, replace or remove an entry, reorder it, or hand a sequential
    // index that is not this row's. Each of those is a deliberate edit rather
    // than the kind of mistake a branchy body produces on its own, and every
    // one of them was proposed as a route by a review round; guarding them one
    // at a time is what grew the version this replaced. The labels themselves
    // are checked for shape and type, never for VOCABULARY or provenance: a
    // wrong but valid label passes, and only the evaluators above decide
    // which label is right.
    const receiptRows = [];
    const appendReceiptRow = (rowIndex, labels) => {
      // a HARD FAULT, never a report label: each of these is a defect in this
      // evaluator, and a report must not be assembled over one. None can be
      // an in-report refusal either, because the label such a refusal would
      // carry is exactly what is missing.
      if (rowIndex !== receiptRows.length) {
        throw new Error(`e2Audit: epoch ${epochIndex} appends row ${rowIndex} at position ${receiptRows.length} (a row appended twice, or an earlier row appended none); refusing hard`);
      }
      const record = {};
      for (const aspect of RECEIPT_ASPECT_KEYS) {
        // an OWN member, because "carries" is what this says and an inherited
        // label would satisfy a bare property read while the row itself
        // carries nothing
        if (!Object.prototype.hasOwnProperty.call(labels, aspect)
          || typeof labels[aspect] !== "string") {
          throw new Error(`e2Audit: row ${rowIndex} carries no ${aspect} label (${show(labels[aspect])}); refusing hard`);
        }
        record[aspect] = labels[aspect];
      }
      // an UNKNOWN member means the caller and this list disagree about what
      // a per-receipt evaluation is, which is worth refusing rather than
      // quietly dropping, since the dropped one may be the real evaluation.
      // EVERY own key, not the enumerable string ones: a symbol-keyed or
      // non-enumerable member is still a member, and reading fewer keys than
      // the object has would make this check narrower than its own message.
      for (const given of Reflect.ownKeys(labels)) {
        if (!RECEIPT_ASPECT_KEYS.includes(given)) {
          throw new Error(`e2Audit: row ${rowIndex} carries an unknown per-receipt aspect ${show(given)}; refusing hard`);
        }
      }
      receiptRows.push(Object.freeze(record));
    };
    const headerCapOk = await headerCaptureCheck(epochIndex);
    for (const [rowIndex, row] of positiveRows.entries()) {
      const accrual = accrualFor.get(nid(row.funderId));
      if (!accrual) {
        // a missing expected row still CONTRIBUTES to the per-receipt
        // aspects (the round-10 gap: an unexamined row must never leave
        // the aggregates affirmative): no accrual means no execution
        // evidence, no queryable reservation key, and nothing to attest
        appendReceiptRow(rowIndex, { transferExecution: "REFUSED",
          reservationPresence: "UNPROVED", ordering: "OPERATOR-PROVIDED" });
        epochComplete = false;
        undistributed += BigInt(row.amountCredits);
        epochUndistributed += BigInt(row.amountCredits);
        continue;
      }
      const accrualId = nid(accrual.id);
      const fetchedReceipts = receiptsByAccrual.get(accrualId) || [];
      if (fetchedReceipts.length > 1) {
        epochLabels.push("REFUSED");
        rowOut.diagnostics.push(`accrual ${accrualId.slice(0, 8)}... carries ${fetchedReceipts.length} receipts (a fetched extra)`);
        epochComplete = false;
      }
      let receipt = fetchedReceipts[0] || null;
      if (!receipt) {
        const kk = await knownKeyFetch("receiptByAccrual", { poolId, accrualId }, epochLabels,
          `accrual ${accrualId.slice(0, 8)}... receipt`);
        if (kk.note) rowOut.diagnostics.push(kk.note);
        receipt = kk.doc;
        // a served fallback joins the index, so the in-flight sweep never
        // reports a receipt it has already seen (the accrual fix's twin)
        if (receipt) receiptsByAccrual.set(accrualId, [receipt]);
      }
      const accrualReservations = reservationsByAccrual.get(accrualId) || [];
      if (accrualReservations.length > 1) {
        epochLabels.push("REFUSED");
        rowOut.diagnostics.push(`accrual ${accrualId.slice(0, 8)}... carries ${accrualReservations.length} reservations (a fetched extra)`);
        epochComplete = false;
      }
      const fetchedReservation = accrualReservations[0] || null;
      if (!receipt) {
        // the transfer evidence for this owed entitlement is absent; the
        // pinned reservation read still runs (the once-per-positive-row
        // claim), its answer feeding the record-set presence, while the
        // aspect stays UNPROVED (a served reservation cannot bind to a
        // receipt that does not exist)
        // a plain local, left UNDEFINED by a branch that fails to set it,
        // which `appendReceiptRow` then refuses
        let orphanReservation;
        const orphanResAnswer = requireAnswer(await awaitRead(() => deps.provedByKey("reservationByAccrual", { accrualId })),
          "the pinned proved reservation read");
        if (orphanResAnswer.status === "unserved" || orphanResAnswer.status === "unverified") {
          anyQueryUnserved = true;
          orphanReservation = "UNPROVED";
        } else if (orphanResAnswer.status === "proved-absence") {
          heightCandidates.push(orphanResAnswer.height);
          orphanReservation = "REFUSED";
          // the proved absence refuses the record set with or WITHOUT an
          // enumerated reservation (round-35): beside one it is a
          // fetched mismatch, alone it is a missing expected record
          epochLabels.push("REFUSED");
          rowOut.diagnostics.push(fetchedReservation
            ? `accrual ${accrualId.slice(0, 8)}... reservation: the pinned read proves ABSENCE while the enumeration served one (a fetched mismatch)`
            : `accrual ${accrualId.slice(0, 8)}... reservation: proved absent (an expected record at a known unique key)`);
        } else {
          // the served answer binds to the REQUESTED key even with no
          // receipt to chain against: a foreign or unidentified document
          // is a nonconforming answer, never a quiet UNPROVED, and its
          // height never enters the range
          const d = orphanResAnswer.doc;
          if (typeof d.id !== "string" || !HEX64.test(d.id)
            || !sameId(d.poolId, poolId) || !sameId(d.accrualId, accrualId)) {
            epochLabels.push("REFUSED");
            orphanReservation = "REFUSED";
            rowOut.diagnostics.push(`accrual ${accrualId.slice(0, 8)}... reservation: the served answer is for a DIFFERENT key or carries no identifier (a nonconforming answer)`);
          } else {
            heightCandidates.push(orphanResAnswer.height);
            orphanReservation = "UNPROVED";
            // when the enumeration ALSO served a reservation, the two
            // unique-key reads must identify the SAME document (round-59,
            // extending the round-58 identity cross-check to the
            // missing-receipt path): a different identifier is a fetched
            // mismatch that refuses the record set
            if (fetchedReservation && !sameId(fetchedReservation.id, d.id)) {
              epochLabels.push("REFUSED");
              rowOut.diagnostics.push(`accrual ${accrualId.slice(0, 8)}... reservation: the enumeration and the pinned unique-key read serve DIFFERENT documents (a fetched mismatch)`);
            }
            // the served reservation JOINS the lifecycle index when the
            // enumeration omitted it, so the in-flight sweep still
            // reports a proved reservation without its receipt
            if (!fetchedReservation) reservationsByAccrual.set(accrualId, [d]);
          }
        }
        appendReceiptRow(rowIndex, { transferExecution: "REFUSED",
          reservationPresence: orphanReservation, ordering: "OPERATOR-PROVIDED" });
        epochComplete = false;
        undistributed += BigInt(row.amountCredits);
        epochUndistributed += BigInt(row.amountCredits);
        continue;
      }
      if (fetchedReservation && fetchedReservation.transitionHash !== receipt.transitionHash) {
        epochLabels.push("REFUSED");
        rowOut.diagnostics.push(`the enumerated reservation for accrual ${accrualId.slice(0, 8)}... carries a different transitionHash than the receipt (a fetched mismatch)`);
        epochComplete = false;
      }
      const parts = partsByAccrual.get(accrualId) || [];
      const entitlementRow = { recipientId: row.funderId, amountCredits: row.amountCredits };
      const capture = receiptCaptures.get(receipt.transitionHash) || null;
      const transfer = await evaluateTransferExecution({ receipt, parts, entitlementRow,
        accrual, headerFor: header, incomeIdentity, chainIdPin, capture,
        supersessions: capture ? supersessionsFor(capture) : [], deps });
      if (transfer.label !== "CAPTURE-VERIFIED") {
        rowOut.diagnostics.push(`receipt for ${row.funderId.slice(0, 8)}...: ${transfer.reason}`);
        epochComplete = false;
      }
      // ONE pinned reservation read serves BOTH consumers (the round-6
      // double-read gap: two reads can resolve at different heights, and
      // the first answer must never be discarded unevaluated): the
      // record-set presence reads it here, the reservation aspect reads
      // the same answer below
      const resAnswer = requireAnswer(await awaitRead(() => deps.provedByKey("reservationByAccrual", { accrualId })),
        "the pinned proved reservation read");
      // a proved absence carries a real proof height and contributes it
      // WHETHER OR NOT the enumeration also served a reservation (the
      // two reads may resolve at different platform heights)
      if (resAnswer.status === "proved-absence") heightCandidates.push(resAnswer.height);
      if (resAnswer.status === "unserved" || resAnswer.status === "unverified") {
        anyQueryUnserved = true;
        if (!fetchedReservation) {
          epochLabels.push("UNPROVED");
          rowOut.diagnostics.push(`accrual ${accrualId.slice(0, 8)}... reservation: the known-key proved query could not be served or verified`);
          epochComplete = false;
        }
      } else if (resAnswer.status === "proved-absence" && !fetchedReservation) {
        epochLabels.push("REFUSED");
        rowOut.diagnostics.push(`accrual ${accrualId.slice(0, 8)}... reservation: proved absent (an expected record at a known unique key)`);
        epochComplete = false;
      }
      const reservation = evaluateReservationPresence(receipt, resAnswer);
      if (reservation.label === "REFUSED") {
        // a served mismatch or a proved absence is a FETCHED-MISMATCH
        // class finding, so it refuses the record set beside its own
        // aspect (one rule everywhere); a mismatching answer's height
        // never enters the range
        epochLabels.push("REFUSED");
        rowOut.diagnostics.push(`reservation for ${row.funderId.slice(0, 8)}...: ${reservation.reason}`);
        epochComplete = false;
      } else {
        if (typeof resAnswer.height === "string") heightCandidates.push(resAnswer.height);
        if (reservation.label === "UNPROVED") epochComplete = false;
        // a conforming reservation the pinned read SERVED but the
        // enumeration OMITTED is an enumeration incompleteness, exactly as
        // the known-key header/accrual/receipt recovery marks it (round-55,
        // extending the round-54 F5 policy to the reservation path): the
        // reservation ASPECT stays PROVED (the record is present and
        // conforms), and record-set COMPLETENESS degrades to UNPROVED. It
        // does NOT mark the epoch's DISTRIBUTION incomplete (round-59): a
        // recovery means the ENUMERATION missed a record that EXISTS and
        // conforms, not that the distribution failed, so the four recovery
        // paths share one rule (degrade record-set, never lag), matching the
        // known-key paths which set no epochComplete=false.
        if (resAnswer.status === "served" && !fetchedReservation) {
          epochLabels.push("UNPROVED");
          rowOut.diagnostics.push(`accrual ${accrualId.slice(0, 8)}... reservation: recovered by the pinned read but ABSENT from the enumeration (the enumeration is INCOMPLETE on this audit)`);
        }
        // when BOTH the enumeration and the pinned read serve a reservation,
        // they must be the SAME document (round-58): reservationByAccrual is a
        // UNIQUE-KEY read, so a DIFFERENT served identifier means the two
        // reads disagree on which reservation exists at that key, a fetched
        // mismatch that refuses the record set, exactly as a served
        // enumeration beside a pinned proved absence does. The reservation
        // document identifier is `id` (the wrapper validates it 64-hex on the
        // enumerated document, and the pinned answer carries it too).
        if (fetchedReservation && resAnswer.status === "served"
          && !sameId(fetchedReservation.id, resAnswer.doc.id)) {
          epochLabels.push("REFUSED");
          rowOut.diagnostics.push(`accrual ${accrualId.slice(0, 8)}... reservation: the enumeration and the pinned unique-key read serve DIFFERENT documents (a fetched mismatch)`);
          epochComplete = false;
        }
      }
      const ordering = evaluateOrdering({ receipt,
        receiptCaptureValid: transfer.label === "CAPTURE-VERIFIED", capture,
        headerCaptureValid: headerCapOk, headerCapture: headerCaptures.get(epochIndex) || null });
      appendReceiptRow(rowIndex, { transferExecution: transfer.label,
        reservationPresence: reservation.label, ordering: ordering.label });
      receiptEvaluations.push({ epochIndex, accrualId,
        transfer: transfer.label, reservation: reservation.label, ordering: ordering.label });
      if (transfer.label !== "CAPTURE-VERIFIED") {
        undistributed += BigInt(row.amountCredits);
        epochUndistributed += BigInt(row.amountCredits);
      }
    }
    // WHAT THE POSITION CHECK CANNOT SEE. An append is taken only at the
    // position its row index names, so a row appending twice or out of order
    // refuses AT the append. What that cannot catch is a row appending
    // NOTHING with no later append to reveal the gap: the final row skipping,
    // and the degenerate case of every row skipping. This is for those.
    if (receiptRows.length !== positiveRows.length) {
      throw new Error(`e2Audit: epoch ${epochIndex} appended ${receiptRows.length} receipt rows for ${positiveRows.length} positive rows (a row appended none and no later append revealed it); refusing hard`);
    }
    // records under NON-POSITIVE accruals are fetched extras: a zero
    // entitlement has no reservation, receipt or part (the round-1
    // zero-accrual gap). The sweep covers EVERY known accrual of the
    // epoch, enumerated AND known-key fallbacks alike (the round-6 gap)
    const positiveAccrualIds = new Set(positiveRows
      .map((row) => nid((accrualFor.get(nid(row.funderId)) || {}).id)));
    for (const a of accrualFor.values()) {
      const aid = nid(a.id);
      if (positiveAccrualIds.has(aid)) continue;
      if ((reservationsByAccrual.get(aid) || []).length
        || (receiptsByAccrual.get(aid) || []).length
        || (partsByAccrual.get(aid) || []).length) {
        epochLabels.push("REFUSED");
        rowOut.diagnostics.push(`transfer records exist under zero-entitlement accrual ${String(a.id).slice(0, 8)}... (a fetched extra)`);
        epochComplete = false;
      }
    }
    for (const msg of pendingEpochIssues.get(epochIndex) || []) {
      epochLabels.push("REFUSED");
      rowOut.diagnostics.push(msg);
      epochComplete = false;
    }
    for (const aspect of RECEIPT_ASPECT_KEYS) {
      // DERIVED, one label per appended row. The three arrays are three
      // reads of one list, so they carry the same count; and because a row is
      // taken only at the position its own index names, entry i is row i of
      // positiveRows, so the arrays describe the same rows in row order.
      const labels = receiptRows.map((r) => r[aspect]);
      if (labels.length) perReceiptEpochLabels[aspect].set(epochIndex, aggregateWeakest(labels));
      // empty expected receipt set: the epoch's per-receipt labels take
      // the record-set ASPECT'S label, applied after the aspect label is
      // known (the empty-set identity), so nothing is recorded here
    }
    rowOut.undistributedCredits = String(epochUndistributed);
    perEpoch.set(epochIndex, rowOut);
    recordSetLabels.push(...(epochLabels.length ? epochLabels : ["READ-CHECKED"]));
    if (bucket === "in-scope" && !epochComplete) {
      lagCount += 1;
      // amounts already accumulated per missing or unverified receipt;
      // a wholly missing accrual accumulated above
    }
    if (!epochComplete && rowOut.condition === null) rowOut.diagnostics.push("the epoch's distribution is incomplete");
  }

  // REVERSE: resolve every enumerated record to an epoch and classify
  const classifyResolved = (epochIndex, what) => {
    const c = classifyRecordEpoch(epochIndex, resolution);
    if (c.bucket === "ignored") return; // inside U, outside I: ignored after resolution
    if (c.bucket === "extra") {
      diagnostics.extras.push(`${what} resolves to epoch ${epochIndex}, outside the validation domain`);
      recordSetLabels.push("REFUSED");
    }
    // in-scope and prefix records were validated in the forward pass
  };
  for (const f of grammarSweep()) {
    diagnostics.poolGlobal.push(f);
    recordSetLabels.push("REFUSED");
  }
  // grammar-refused records (malformed epoch index) are already
  // refused above and cannot be classified, so the loops skip them
  for (const h of enums.header.documents) {
    if (!Number.isSafeInteger(h.epochIndex)) continue;
    classifyResolved(h.epochIndex, `header ${h.id.slice(0, 8)}...`);
  }
  for (const a of enums.accrual.documents) {
    if (!Number.isSafeInteger(a.epochIndex)) continue;
    classifyResolved(a.epochIndex, `accrual ${a.id.slice(0, 8)}...`);
  }
  // a dependent whose accrual is STILL unresolved after pre-settlement
  // is classified by its settlement: proved absence is a genuine orphan
  // (the reference is nonconforming at a proved height), a nonconforming
  // answer refuses, and an unserved or unverified read leaves the
  // accrual's existence undecided (a possible orphan, UNPROVED, because
  // the composite enumeration is not snapshot-proved and absence from it
  // proves nothing, whole universe or not).
  for (const [name, docs] of [["reservation", enums.reservation.documents],
    ["receipt", enums.receipt.documents], ["part", enums.part.documents]]) {
    for (const d of docs) {
      const key = nid(d.accrualId);
      if (typeof key !== "string" || !HEX64.test(key)) {
        // a malformed reference is refused BEFORE any adapter call: the
        // by-identifier key contract requires 64-hex, and a document
        // whose reference cannot form a key is nonconforming on its face
        diagnostics.poolGlobal.push(`${name} ${String(d.id).slice(0, 8)}... carries a malformed accrual reference (${show(d.accrualId)})`);
        recordSetLabels.push("REFUSED");
        continue;
      }
      const acc = accrualById.get(key);
      if (acc && !Number.isSafeInteger(acc.epochIndex)) continue; // grammar-refused above
      if (!acc) {
        const settled = await settleDangling(key);
        if (settled.kind === "absent") {
          diagnostics.orphans.push(`${name} ${d.id.slice(0, 8)}... names accrual ${String(d.accrualId).slice(0, 8)}..., whose absence is proved`);
          diagnostics.poolGlobal.push(`orphan ${name} ${d.id.slice(0, 8)}... (a pool-level conformance failure at a proved height)`);
          recordSetLabels.push("REFUSED");
        } else if (settled.kind === "present") {
          // defensive only: a present settlement joined the resolution
          // BEFORE the forward pass, so this dependent resolves above;
          // kept fail-visible rather than silently conforming
          diagnostics.poolGlobal.push(`${name} ${d.id.slice(0, 8)}... names an accrual the settlement served but the resolution does not carry (an unexpected state)`);
          recordSetLabels.push("UNPROVED");
        } else if (settled.kind === "nonconforming") {
          diagnostics.poolGlobal.push(`the by-identifier read for accrual ${String(d.accrualId).slice(0, 8)}... served a nonconforming answer`);
          recordSetLabels.push("REFUSED");
        } else {
          diagnostics.poolGlobal.push(`possible orphan ${name} ${d.id.slice(0, 8)}... (the by-identifier read could not be served or verified, so its accrual's existence is undecided)`);
          recordSetLabels.push("UNPROVED");
        }
        continue;
      }
      classifyResolved(acc.epochIndex, `${name} ${d.id.slice(0, 8)}...`);
    }
  }
  // the in-flight sweep: reservations without a matching receipt are
  // reported, never counted complete (the lifecycle already refused
  // completeness for them). An IGNORED epoch carries no obligation, its
  // lifecycle reporting included (round-26).
  for (const [accrualId] of reservationsByAccrual) {
    const acc = accrualById.get(accrualId);
    if (!acc || ignoredEpoch(acc.epochIndex)) continue;
    if (!(receiptsByAccrual.get(accrualId) || []).length) {
      diagnostics.poolGlobal.push(`reservation for accrual ${accrualId.slice(0, 8)}... has no receipt (in-flight or stopped work)`);
    }
  }

  const recordSetLabel = recordSetLabels.length ? aggregateWeakest(recordSetLabels) : "READ-CHECKED";
  const aggregates = {};
  for (const aspect of RECEIPT_ASPECT_KEYS) {
    const labels = [];
    for (const epochIndex of intervalEpochs) {
      const own = perReceiptEpochLabels[aspect].get(epochIndex);
      // the empty-set identity: an epoch with no expected receipts takes
      // the record-set aspect's label, earned vacuously
      labels.push(own !== undefined ? own : recordSetLabel);
    }
    aggregates[aspect] = labels.length ? aggregateWeakest(labels) : recordSetLabel;
  }
  return {
    recordSet: { label: recordSetLabel },
    aggregates, perEpoch, diagnostics, refusals, receiptEvaluations,
    lag: { lagCount, undistributedCredits: String(undistributed) },
    heightCandidates, recordsProved: !anyQueryUnserved,
  };
};

// ---- the entry ----

/**
 * Run the audit: resolve the start source and the interval, derive every
 * aspect state from evidence, and assemble the graded report. Returns the
 * report, or { verdict: "REFUSED-INPUT", reason } for a malformed request
 * (grammar step 0 produces no report).
 */
const runAudit = async ({ poolId, dir, startEpoch = null, endEpoch = null, deps }) => {
  try {
    if (typeof poolId !== "string" || !HEX64.test(poolId)) {
      refuseInput("runAudit needs the pool's 64-hex identifier");
    }
    if (!deps || typeof deps !== "object") refuseInput("runAudit needs its deps object");
    // NORMALIZE ONCE, THEN NEVER READ THE CALLER'S OBJECT AGAIN (round-65).
    // Every member below is read EXACTLY ONCE here, validated, and copied into
    // a frozen capability record that is threaded everywhere in place of the
    // caller's object. This turns the capture-once convention, which earlier
    // rounds enforced member by member as reviewers found each one, into a
    // structural property: after this point there is no mutable deps object in
    // reach, so an accessor cannot serve one value to a validation and another
    // to a use, and no later reader has to remember the rule.
    const caps = {};
    for (const k of ["fetchRange", "fetchVerifiedPage", "provedByKey", "verifyCaptureBasis"]) {
      const fn = deps[k];                       // the single read
      if (typeof fn !== "function") refuseInput(`runAudit needs deps.${k}`);
      caps[k] = fn;
    }
    const rawVerifierDeps = deps.verifierDeps;  // the single read
    if (!rawVerifierDeps || typeof rawVerifierDeps !== "object") {
      refuseInput("runAudit needs deps.verifierDeps (the receipt verifier's pipeline)");
    }
    const verifierCaps = {};
    for (const k of ["decodeProofCarrier", "decodeMetadata", "decodeTransfer", "verifyStageOne", "verifyStageTwo"]) {
      const fn = rawVerifierDeps[k];            // the single read
      if (typeof fn !== "function") {
        refuseInput(`runAudit needs deps.verifierDeps.${k} (the receipt verifier pipeline is incomplete)`);
      }
      verifierCaps[k] = fn;
    }
    caps.verifierDeps = Object.freeze(verifierCaps);
    // CAPTURE the expected payload ONCE at the entry (round-54): validating
    // it here and then re-reading deps.expectedContractPayload later would
    // read a mutable object twice, so a payload the caller mutates between
    // entry validation and the contract-integrity comparison could pass the
    // entry check under one value and be compared under another. The single
    // captured snapshot is the value the comparison uses.
    const rawExpectedPayload = deps.expectedContractPayload; // the single read
    const expectedPayloadSnap = (!rawExpectedPayload
      || typeof rawExpectedPayload !== "object"
      || safeIsArray(rawExpectedPayload))
      ? { defect: "not a plain object", value: undefined }
      : plainDataSnapshot(rawExpectedPayload);
    if (expectedPayloadSnap.defect) {
      refuseInput("runAudit needs deps.expectedContractPayload (the exact registered v11 payload from the registration record, plain data throughout)");
    }
    // a supplied payload carrying a system-namespace ($-prefixed) member is a
    // malformed request, refused AT THE ENTRY as a structured REFUSED-INPUT
    // (round-56): a registration payload has none, and the contract-integrity
    // evaluator's own $-member check throws a plain refusal that runAudit's
    // catch would not convert, so the entry owns the input-refusal typing and
    // the evaluator check stays as defense in depth for direct callers.
    if (Object.keys(expectedPayloadSnap.value).some((k) => k.startsWith("$"))) {
      refuseInput("runAudit needs deps.expectedContractPayload without system-namespace ($-prefixed) members (a registration payload carries none)");
    }
    // CAPTURE the scalar trust inputs ONCE at the entry (round-55), as the
    // expected payload is: an accessor on deps could otherwise return the
    // validated value during entry validation and a different value at a
    // later read, so every downstream use reads these captured locals, never
    // deps again. Strings and numbers are immutable, so the capture is the
    // value; the danger is only a second READ of a mutable deps member.
    const incomeIdentity = deps.incomeIdentity;
    if (typeof incomeIdentity !== "string" || !HEX64.test(incomeIdentity)) {
      refuseInput("runAudit needs deps.incomeIdentity (the operator-supplied income identity, 64-hex, pending a pinned resolution read)");
    }
    const provedActivation = deps.provedActivation ?? null;      // the single read
    const provedDeactivation = deps.provedDeactivation ?? null;  // the single read
    const discoveryOpts = deps.discoveryOpts;                    // the single read
    // the record is now complete and SEALED. Everything below reads `caps`,
    // and the caller's `deps` is not consulted again on any path.
    caps.expectedContractPayload = expectedPayloadSnap.value;
    caps.incomeIdentity = incomeIdentity;
    caps.provedActivation = provedActivation;
    caps.provedDeactivation = provedDeactivation;
    caps.discoveryOpts = discoveryOpts;
    Object.freeze(caps);
    // the freeze is LOAD-BEARING, so it is asserted rather than assumed
    // (playbook rule 4). Without this, removing the freeze changes no observable
    // behaviour and the freeze is decoration; with it, the record's immutability
    // is a property the suite can see. Both halves are checked, because a frozen
    // shell over a mutable pipeline would still let a member be swapped.
    if (!Object.isFrozen(caps) || !Object.isFrozen(caps.verifierDeps)) {
      refuseInput("the normalized capability record must be frozen before it is used (its immutability is what makes the read-once property hold downstream)");
    }

    // the owned pins: the report cannot exist without them
    const env = envStore.loadEnv();
    const contractId = env.CONTRACT_V11_ID;
    if (typeof contractId !== "string" || contractId.length === 0) {
      refuseInput("CONTRACT_V11_ID is not set (the audit reports against the registered contract)");
    }
    if (formationCore.decodeId32(contractId) === null && !HEX64.test(contractId)) {
      refuseInput(`CONTRACT_V11_ID ${show(contractId)} does not decode to a 32-byte contract identifier`);
    }
    let chainIdPin;
    try { chainIdPin = envStore.readChainIdPin().chainId; }
    catch (e) { refuseInput(e.message); }

    // the journal: the start-source authority and the ordering evidence;
    // a journal that fails validation is a hard stop (header decision 7)
    let journal;
    try { journal = openValidatedJournal(poolId, dir); }
    catch (e) { refuseInput(`the journal refuses validation (${e.message})`); }

    const localRaw = env[startKeyOf(poolId)];
    let localKey = null;
    if (localRaw !== undefined) {
      if (!isDec(localRaw) || Number(localRaw) > U32_MAX) {
        refuseInput(`the local configured start key holds ${show(localRaw)}, not a canonical decimal u32`);
      }
      localKey = Number(localRaw);
    }
    const source = resolveStartSource({ journalBinding: journal.configuredStartEpoch,
      localKey, explicitStartEpoch: startEpoch });
    const resolution = await resolveInterval({
      requestedStart: source.requestedStart, requestedEnd: endEpoch,
      configuredStart: source.configuredStart,
      provedActivation: caps.provedActivation, provedDeactivation: caps.provedDeactivation,
      fetchRange: caps.fetchRange, discoveryOpts: caps.discoveryOpts });

    const epochInfo = new Map();
    for (const e of resolution.discovery.epochs) epochInfo.set(e.number, e);

    const formation = await evaluateFormationInputs({ poolId, contractId, deps: caps });
    const contractIntegrity = await evaluateContractIntegrity({ contractId,
      expectedContractPayload: caps.expectedContractPayload, deps: caps });

    const enums = {};
    for (const t of ["header", "accrual", "reservation", "receipt", "part"]) {
      enums[t] = await enumerateProved({ contractId, type: t,
        where: [["poolId", "==", poolId]], orderBy: [["$id", "asc"]],
        fetchVerifiedPage: caps.fetchVerifiedPage });
    }

    const ledger = await evaluateLedgerRecords({ poolId, contractId, resolution,
      epochInfo, formation, chainIdPin, incomeIdentity: caps.incomeIdentity, enums,
      journalRecords: journal.records, deps: caps });

    const branch = resolution.branch;
    // when NO receipt received the per-receipt evaluations, the three
    // aspects' labels were not earned by receipt inspection (they are
    // aggregates over missing-row contributions or empty-set
    // inheritance), and the note says so, LETTING a consumer discount
    // them (the label itself stays as computed; nothing can force a
    // consumer to read the note) (rounds 17, 34 and 39)
    const vacuousNote = ledger.receiptEvaluations.length === 0
      ? "no receipt received the per-receipt evidence evaluations, so this label is not evidence that any receipt was inspected"
      : null;
    // examinedCount is the MACHINE-READABLE examined-receipt count:
    // zero means no receipt received the per-receipt evaluations,
    // whether none was expected or none could be examined (a missing
    // expected receipt contributes its refusal without an evaluation).
    // It does NOT establish that the expected set was empty (round-39).
    const aspects = {
      universe: { evaluated: true, label: resolution.discovery.proved ? "PROVED" : "UNPROVED" },
      // the PROVED labels on the two boundary aspects restate the
      // harness's declared proof claim (the seam named in the header);
      // this module cannot verify boundary proofs and does not (round-47)
      activationBoundary: { evaluated: true,
        label: provedActivation !== null ? "PROVED" : "OPERATOR-PROVIDED",
        source: source.source },
      deactivationBoundary: branch === "deactivation-bounded"
        ? { evaluated: true, label: "PROVED" } : { evaluated: false },
      binding: { evaluated: true, label: "UNVERIFIABLE" },
      transferExecution: { evaluated: true, label: ledger.aggregates.transferExecution,
        examinedCount: ledger.receiptEvaluations.length,
        ...(vacuousNote ? { note: vacuousNote } : {}) },
      reservationPresence: { evaluated: true, label: ledger.aggregates.reservationPresence,
        examinedCount: ledger.receiptEvaluations.length,
        ...(vacuousNote ? { note: vacuousNote } : {}) },
      temporalOrder: { evaluated: true, label: "UNVERIFIABLE" },
      ordering: { evaluated: true, label: ledger.aggregates.ordering,
        examinedCount: ledger.receiptEvaluations.length,
        ...(vacuousNote ? { note: vacuousNote } : {}) },
      formationInputs: { evaluated: true, label: formation.label,
        ...(formation.reason ? { note: formation.reason } : {}) },
      recordSet: { evaluated: true, label: ledger.recordSet.label,
        ...(ledger.recordSet.reason ? { note: ledger.recordSet.reason } : {}) },
      shareConformance: { evaluated: true, label: "UNVERIFIABLE" },
      balance: { evaluated: true, label: "UNVERIFIABLE" },
      contractIntegrity: { evaluated: true, label: contractIntegrity.label,
        ...(contractIntegrity.reason ? { note: contractIntegrity.reason } : {}) },
    };

    // the RECORDS height range: the reduction over the proved ledger-query
    // answers this entry accepted, meaning the enumeration pages, the
    // known-key and by-identifier reads, and the formation document reads
    // (a nonconforming served answer contributes nothing, and heights
    // embedded inside the receipt and capture proof pipelines do not
    // enter; round-60 narrowed this wording to the contributing classes).
    // TWO SEPARATE STATEMENTS, kept distinct after
    // round-53 conflated them: (a) the contract and identity heights do
    // not ENTER the range, because it reports document evidence only; and
    // (b) the range is emitted only when recordsProved holds, which
    // requires PROVED formation and every enumeration served. An unserved
    // read of ANY formation input, the non-document identity read
    // included, makes formation UNPROVED, which routes the ledger
    // evaluation to its unavailable path (recordsProved false), so the
    // whole range is withheld fail-closed rather than published over a
    // partial evaluation. So an unserved identity contributes no height
    // AND nulls the range, and those are not the same fact. Gated by the
    // entry-level unserved-pool, unserved-receipt and unserved-identity
    // regression fixtures.
    let records = null;
    const allHeights = [...ledger.heightCandidates, ...(formation.heights || [])];
    if (ledger.recordsProved && allHeights.length) {
      const hs = allHeights.map(BigInt);
      records = { min: String(hs.reduce((a, b) => (b < a ? b : a))),
        max: String(hs.reduce((a, b) => (b > a ? b : a))) };
    }

    const epochs = [];
    if (resolution.interval.endEpoch !== null) {
      for (let e = resolution.interval.startEpoch; e <= resolution.interval.endEpoch; e++) {
        const row = ledger.perEpoch.get(e);
        epochs.push(row || { epochIndex: e, condition: null, r: null, diagnostics: [],
          undistributedCredits: "0" });
      }
    }

    const annotation = branch === "open-ended"
      ? buildOpenEndedAnnotation({ endEpoch: resolution.interval.endEpoch,
        recordsHeightMax: records === null ? null : records.max })
      : null;

    return buildReport({ poolId, contractId, expectedChainId: chainIdPin,
      startSource: source.source, configuredStart: source.configuredStart,
      branch, interval: resolution.interval, annotation,
      coverage: resolution.coverage, aspects, epochs,
      lag: ledger.lag,
      heightRanges: { records, universe: null, balance: null },
      diagnostics: ledger.diagnostics, refusals: ledger.refusals });
  } catch (e) {
    // classification is by MEMBERSHIP in the module-private refusal set,
    // never by instanceof (round-60, replacing the round-59 guarded
    // instanceof): the class is exported, so instanceof is reproducible by
    // an injected adapter (inherit the exported prototype, or lie through
    // a getPrototypeOf trap) and would convert an adapter fault into a
    // structured refusal carrying a reason of the adapter's choosing, with
    // the reason read itself able to throw. WeakSet.has reads nothing of
    // the value and throws on nothing, so any value this module did not
    // build propagates unchanged as the hard fault it is, and `e.reason`
    // is only ever read from an instance this module built.
    if (OWN_REFUSALS.has(e)) return { verdict: "REFUSED-INPUT", reason: e.reason };
    throw e;
  }
};

// THE PUBLIC SURFACE IS THE ENTRY PLUS THE REPORT'S OWN VOCABULARY (round-65;
// docs/E2_VERIFICATION_BOUNDARY.md, "The public surface").
//
// Why this split earns its keep: several review rounds were spent on claims that
// were TRUE THROUGH `runAudit` and FALSE for a synthetic direct caller which
// existed only because an internal evaluator was exported for testing. Two
// specimens: the three per-receipt aspects carry equal examined counts, which
// the entry establishes by control flow and which three integers cannot witness
// for an arbitrary caller; and the missing-epoch-object branch, unreachable
// through the entry and reachable for a caller supplying its own inputs. Every
// exported internal turns an entry-level invariant into a contract that must
// hold for callers nobody has written.
//
// So the internals stay reachable for THIS repository's tests and stop being a
// supported contract. A caller reaching into `__testing` is doing so knowingly.
module.exports = {
  // the supported entry
  runAudit,
  // the report's closed vocabularies, which a CONSUMER of a report needs in
  // order to read one: the label set and its order, the grade set, the branch
  // set, the report kind, and the aspect rows with their terminals and ceilings
  LABELS, GRADES, BRANCHES, REPORT_KIND,
  ASPECT_KEYS, ASPECT_TERMINALS, ASPECT_CEILINGS,
  // INTERNAL. Exported only so this repository's suites can reach them, and
  // deliberately NOT part of the caller contract. Invariants that hold through
  // the entry are not promised for these.
  __testing: {
    U32_MAX,
    AuditInputRefusal, rankOf, labelAtLeast, aggregateWeakest,
    computeNormativeEpoch, resolveStartSource, resolveInterval,
    classifyRecordEpoch, gradeVerdict, buildOpenEndedAnnotation, buildReport,
    evaluateReservationPresence, evaluateTransferExecution, evaluateOrdering,
    evaluateFormationInputs, evaluateContractIntegrity,
    evaluateLedgerRecords,
  },
};
