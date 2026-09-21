/**
 * e2ForwardKernel: the PURE CORE of the forward lifecycle kernel.
 *
 * Contract: tegara/docs/FORWARD_LIFECYCLE_KERNEL_CONTRACT.md (revision 5). This module is
 * the first slice of that contract, the pure core only: the expected-record plan builder,
 * the deterministic single-epoch evaluator, and the strict writer projection. It performs
 * NO input or output, consults no clock, and holds no state between calls. Asynchronous
 * evidence acquisition is the NEXT unit and deliberately absent here: served identifiers,
 * per-answer heights and bounded reacquisition are produced by acquisition and arrive in
 * this module as plain data.
 *
 * THE BOUNDARY IS BRANDED, NOT NAMED (the second slice's repair, a soundness-review finding). The first
 * version of this module recognized its own plans and snapshots by a `kind` string, which
 * any object literal can carry, so a lookalike snapshot projected `true` for an epoch nobody
 * evaluated and a lookalike plan with an emptied member list evaluated `complete`. Plans,
 * results and snapshots are now all branded in module-private WeakSets, and the evaluator
 * and projection accept ONLY branded inputs, so the only way to a `complete` or a `true`
 * runs through this module's own validation.
 *
 * EMPTINESS IS PROVED, NEVER CONCLUDED FROM OMISSION (the second slice's repair, a soundness-review finding).
 * "Nothing forbidden exists" is a claim like any other: no extra accruals needs a proved
 * accrual ENUMERATION over the epoch, and no machinery under an excluded, absent-accrual or
 * encoding-refused row needs a proved MACHINERY SWEEP over that row. An omitted, unserved,
 * unverified or unproved-route forbidden-set read makes the result `unproved`, never
 * `complete`. The first version accepted omission as emptiness, which is the
 * unchecked-means-passed shape this kernel exists to eliminate.
 *
 * WHERE THE SWEEP IS NOT REQUIRED, stated because the first wording was wider than the
 * code: a PAYABLE row whose accrual was SERVED does not carry a machinery sweep. Every
 * record permitted under such a row is individually read and compared (the pinned
 * reservation, its enumeration, the receipt with its `servedCount`, and the part
 * enumeration), so there is no separate emptiness claim left for a sweep to ground. The
 * sweep grounds the three cases where the expected set is EMPTY and nothing else looks.
 *
 * EVERY ENUMERATION IS EVALUATED IN FULL, NOT ONLY ON ITS SERVED BRANCH (the third slice's
 * repair, a soundness-review finding). The reservation enumeration was validated structurally and then read
 * only where `status === "served"`, so an unserved, unproved-route, out-of-scope or
 * wrong-key enumeration contributed nothing and the epoch still read `complete`. That is
 * a soundness-review finding shape one level down. Enumerations also carry their QUERY SUBJECT, the accrual
 * identifier they were run against, because pool and epoch scope alone cannot tell one
 * member's sweep or part set from another's.
 *
 * WHAT EXISTS OF THE CONTRACT IN THIS SLICE, stated so the boundary is checkable:
 *  - buildExpectedRecordPlan: section 3.1, taking the calculation's OUTPUTS as explicit
 *    inputs (effective amounts, share bps, the carry partition's payable/self-share
 *    answers). Wiring entitlementCalc/epochCarry into the builder is integration work
 *    that belongs with acquisition, not here; the inputs are validated and cross-checked
 *    but not derived.
 *  - evaluateEpochForwardState: sections 3.4, 4, 6 and 6.1 (the legal publication prefix
 *    WITH the temporal rule), 9 (mixed heights allowed, mixed scopes refused).
 *  - projectForWriter / createSnapshot: section 5. A snapshot binds ONE pool.
 *  - unprovedPrecondition: the C4-family results (carry unseeded, formation unavailable,
 *    epoch object absent) that the orchestrator constructs when a plan cannot be built.
 *
 * EXECUTION EVIDENCE IS AN INPUT, NOT A JUDGMENT MADE HERE. Verifying a receipt's
 * transition, proof and metadata bytes needs cryptography and decoding this pure module
 * must not perform; the existing verifier (e2ReceiptVerify) produces that verdict and
 * acquisition hands it in as { label, verifiedAmountCredits }. The evaluator's own pure
 * comparison is verifiedAmountCredits against the plan's effective amount.
 *
 * CLOSURE, stated to keep this module from being mistaken for it: this slice closes NO
 * CN finding. a soundness-review finding closes when the audit's production path consumes the shared plan;
 * a soundness-review finding when the real fetch returns found[0].id with a production-composition test;
 * a soundness-review finding live half needs the audit regression or the audit adopting this kernel.
 * a soundness-review finding and a soundness-review finding are the two findings AGAINST this module's first version, repaired
 * here and bound by regression cases and mutations.
 */

"use strict";

const refuse = (why) => { throw new Error(`e2ForwardKernel: ${why}; refusing`); };

const HEX64 = /^[0-9a-f]{64}$/;
const DEC_RE = /^(0|[1-9][0-9]*)$/;
const isDec = (s) => typeof s === "string" && DEC_RE.test(s);
const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

const deepFreeze = (o, seen = new Set()) => {
  if (o === null || typeof o !== "object" || seen.has(o)) return o;
  seen.add(o);
  for (const k of Object.getOwnPropertyNames(o)) deepFreeze(o[k], seen);
  return Object.freeze(o);
};

// canonical integer normalization for evidence fields, which arrive from a
// normalizer that may carry safe integers or decimal strings (the audit's
// intStr rule): the comparison space is the canonical decimal string
const intStr = (v) => {
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return String(v);
  if (isDec(v)) return v;
  return null;
};

const bigGte = (a, b) => BigInt(a) >= BigInt(b);

// THE BRANDS: module-private, so a `kind` string on an object literal proves
// nothing. Only values these WeakSets hold cross the module's boundaries.
const PLAN_BRAND = new WeakSet();
const RESULT_BRAND = new WeakSet();
const SNAPSHOT_BRAND = new WeakSet();

// ---- the closed result-state and reason-code vocabulary ----

const STATES = Object.freeze(["complete", "incomplete", "unproved", "refused"]);

/** Every reason code, closed. INCOMPLETE_PARTS_ABSENT is deliberately absent
 * (contract revision 4, R11): before the receipt the count is unknown, and
 * after it a missing part is an ordering refusal, so no state produces it. */
const REASONS = Object.freeze({
  INCOMPLETE_HEADER_ABSENT: "incomplete",
  INCOMPLETE_ACCRUAL_ABSENT: "incomplete",
  INCOMPLETE_RESERVATION_ABSENT: "incomplete",
  INCOMPLETE_RECEIPT_ABSENT: "incomplete",
  UNPROVED_QUERY_UNSERVED: "unproved",
  UNPROVED_PROOF_UNVERIFIED: "unproved",
  UNPROVED_ROUTE_NOT_PROVED: "unproved",
  UNPROVED_CARRY_UNSEEDED: "unproved",
  UNPROVED_FORMATION_UNAVAILABLE: "unproved",
  UNPROVED_EPOCH_OBJECT_ABSENT: "unproved",
  // the epoch object is PRESENT but consumed over a route that obtains no proof
  // while open construction C1 stands (the per-epoch context design, section 4,
  // contract revision 16): a fresh epoch's figures from it are not a figures
  // source, so the orchestrator builds no plan and stores this precondition
  UNPROVED_EPOCH_OBJECT_UNPROVED: "unproved",
  UNPROVED_ACCRUAL_IDENTIFIER_UNRESOLVED: "unproved",
  UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED: "unproved",
  REFUSED_HEADER_MISMATCH: "refused",
  REFUSED_ACCRUAL_AMOUNT_MISMATCH: "refused",
  REFUSED_ACCRUAL_SHARE_BPS_MISMATCH: "refused",
  REFUSED_ACCRUAL_EXTRA: "refused",
  REFUSED_ACCRUAL_DUPLICATE: "refused",
  REFUSED_ACCRUAL_DOCUMENT_ID_MISMATCH: "refused",
  REFUSED_RESERVATION_PROVED_ABSENT: "refused",
  REFUSED_RESERVATION_MISMATCH: "refused",
  REFUSED_RESERVATION_AMBIGUOUS: "refused",
  REFUSED_RECEIPT_AMBIGUOUS: "refused",
  REFUSED_TRANSFER_UNVERIFIED: "refused",
  REFUSED_PART_COUNT_MISMATCH: "refused",
  REFUSED_PART_INDEX_NONCONFORMING: "refused",
  REFUSED_PART_MISMATCH: "refused",
  REFUSED_MACHINERY_UNDER_EXCLUDED_ROW: "refused",
  REFUSED_RECORDS_UNDER_ENCODING_REFUSED_EPOCH: "refused",
  REFUSED_RECORDS_WITHOUT_HEADER: "refused",
  REFUSED_DEPENDENTS_WITHOUT_ACCRUAL: "refused",
  REFUSED_RECEIPT_BEFORE_PARTS: "refused",
  REFUSED_NONCONFORMING_ANSWER: "refused",
  REFUSED_SCOPE_MISMATCH: "refused",
});

const PROJECTION_CODES = Object.freeze([
  "PROJECTION_EPOCH_NOT_EVALUATED",
  "PROJECTION_STATE_UNPROVED",
  "PROJECTION_STATE_REFUSED",
]);

/**
 * THE PLAN'S FIELD COVERAGE, per document type, against the v11 schema. This map is what
 * the schema-walk test checks: every REQUIRED member of every type must appear in exactly
 * one of these buckets, so a schema member nobody accounts for is a TEST FAILURE rather
 * than a silent gap (a soundness-review finding). WIDTH, STATED: this is STATIC METADATA, a listing of intended ownership. The
 * walk proves every field is LISTED in exactly one bucket, and the mutation battery
 * proves the listed comparisons this slice implements actually fire; it does not prove
 * that every listed field is checked by production behavior outside this module.
 *  - key: the members that form the record's logical key; bound by the key check.
 *  - compared: members the pure evaluator compares against the plan.
 *  - executionVerified: members whose verification needs cryptography or decoding and is
 *    the receipt verifier's job, arriving here as the execution verdict.
 *  - systemManaged: platform-written members no reader recomputes.
 */
const PLAN_FIELD_COVERAGE = deepFreeze({
  epochHeader: {
    key: ["poolId", "epochIndex"],
    compared: ["grossCredits", "feeCredits", "allocationHash", "memberCount", "calcVersion"],
    executionVerified: [],
    systemManaged: ["$createdAt"],
  },
  platformAccrual: {
    key: ["poolId", "funderId", "epochIndex"],
    compared: ["amountCredits", "shareBps"],
    executionVerified: [],
    systemManaged: ["$createdAt"],
  },
  transferReservation: {
    key: ["poolId", "accrualId"],
    compared: ["transitionHash"],
    executionVerified: [],
    systemManaged: ["$createdAt"],
  },
  transferReceipt: {
    key: ["poolId", "accrualId"],
    compared: ["transitionHash", "proofPartCount"],
    executionVerified: ["transitionBytes", "proofBytes", "metadataBytes", "blockHeight",
      "coreChainLockedHeight", "timeMs", "quorumHash", "round"],
    systemManaged: ["$createdAt"],
  },
  receiptProofPart: {
    key: ["poolId", "accrualId", "partIndex"],
    compared: [],
    executionVerified: ["bytes"],
    systemManaged: ["$createdAt"],
  },
});

// ---- scope ----

const SCOPE_KEYS = Object.freeze(["contractId", "chainId", "contractVersion", "poolId", "epochIndex"]);

const validateScope = (s, name) => {
  if (!isPlain(s)) refuse(`${name} must be a plain scope object`);
  for (const k of SCOPE_KEYS) {
    if (s[k] === undefined || s[k] === null) refuse(`${name}.${k} is required`);
  }
  if (!HEX64.test(s.poolId || "")) refuse(`${name}.poolId must be 64-hex`);
  if (!Number.isSafeInteger(s.epochIndex) || s.epochIndex < 0) refuse(`${name}.epochIndex must be a non-negative safe integer`);
};

const sameScope = (a, b) => SCOPE_KEYS.every((k) => a[k] === b[k]);

// ---- the expected-record plan (contract section 3.1) ----

const CLASSES = Object.freeze(["payable", "self-share", "below-minimum", "zero"]);
// the dependent document types a machinery sweep covers, in a FIXED order so
// the reasons a multi-component failure produces are deterministic. Each name
// is one separate proved read (a soundness-review finding), never a field of one combined answer.
const SWEEP_COMPONENTS = Object.freeze(["reservation", "receipt", "parts"]);

const buildExpectedRecordPlan = (input) => {
  if (!isPlain(input)) refuse("buildExpectedRecordPlan takes one plain options object");
  const { scope, encodingRefused, header, members } = input;
  validateScope(scope, "plan.scope");
  if (typeof encodingRefused !== "boolean") refuse("plan.encodingRefused must be a strict boolean");
  if (!Array.isArray(members)) refuse("plan.members must be an array");

  const outMembers = [];
  const seenFunders = new Set();
  const seenIds = new Set();
  for (const [i, m] of members.entries()) {
    if (!isPlain(m)) refuse(`plan member ${i} must be a plain object`);
    if (!HEX64.test(m.funderId || "")) refuse(`plan member ${i} funderId must be 64-hex`);
    if (!HEX64.test(m.plannedAccrualId || "")) refuse(`plan member ${i} plannedAccrualId must be 64-hex`);
    if (!isDec(m.effectiveCredits)) refuse(`plan member ${i} effectiveCredits must be a canonical decimal string`);
    if (!Number.isSafeInteger(m.shareBps) || m.shareBps < 1 || m.shareBps > 10000) {
      refuse(`plan member ${i} shareBps must be an integer in 1..10000 (the schema's domain)`);
    }
    if (typeof m.isSelfShare !== "boolean" || typeof m.payable !== "boolean") {
      refuse(`plan member ${i} needs strict-boolean isSelfShare and payable (the carry partition's answers)`);
    }
    if (seenFunders.has(m.funderId)) refuse(`plan members carry funder ${m.funderId.slice(0, 8)}... twice`);
    if (seenIds.has(m.plannedAccrualId)) refuse(`plan members carry planned accrual id ${m.plannedAccrualId.slice(0, 8)}... twice`);
    seenFunders.add(m.funderId);
    seenIds.add(m.plannedAccrualId);
    const positive = BigInt(m.effectiveCredits) > 0n;
    if (m.payable && !positive) refuse(`plan member ${i} is payable with a non-positive effective amount, which the carry partition never produces`);
    if (m.payable && m.isSelfShare) refuse(`plan member ${i} is payable AND a self-share; a self-share settles where it sits and is never payable`);
    const classification = m.payable ? "payable"
      : (!positive ? "zero" : (m.isSelfShare ? "self-share" : "below-minimum"));
    outMembers.push({ funderId: m.funderId, plannedAccrualId: m.plannedAccrualId,
      effectiveCredits: m.effectiveCredits, shareBps: m.shareBps, classification });
  }

  let outHeader = null;
  if (encodingRefused) {
    // an encoding-refused epoch expects NO records at all (the writer refuses
    // before the header), so the plan carries no header expectation
    if (header !== null && header !== undefined) {
      refuse("an encoding-refused plan carries no header expectation (the epoch expects no records)");
    }
  } else {
    if (!isPlain(header)) refuse("plan.header must be a plain object (or absent only when encodingRefused)");
    if (!isDec(header.grossCredits) || !isDec(header.feeCredits)) {
      refuse("plan.header grossCredits and feeCredits must be canonical decimal strings");
    }
    if (!Number.isSafeInteger(header.memberCount) || header.memberCount < 1 || header.memberCount > 8) {
      refuse("plan.header.memberCount must be an integer in 1..8 (the schema's domain)");
    }
    if (header.memberCount !== outMembers.length) {
      refuse(`plan.header.memberCount is ${header.memberCount} while the plan carries ${outMembers.length} members; the two are one fact`);
    }
    if (header.calcVersion !== 1) refuse("plan.header.calcVersion must be 1 (the normative calculation's version)");
    if (!HEX64.test(header.allocationHash || "")) refuse("plan.header.allocationHash must be 64-hex");
    outHeader = { grossCredits: header.grossCredits, feeCredits: header.feeCredits,
      memberCount: header.memberCount, calcVersion: 1, allocationHash: header.allocationHash };
  }

  const plan = deepFreeze({
    kind: "tegara.e2.forwardPlan.v1",
    scope: { ...scope },
    encodingRefused,
    header: outHeader,
    members: outMembers,
  });
  PLAN_BRAND.add(plan);
  return plan;
};

// ---- evidence answers ----

const ANSWER_STATUSES = Object.freeze(["served", "proved-absence", "unserved", "unverified"]);

const validateAnswer = (a, name) => {
  if (!isPlain(a)) refuse(`${name} must be a plain answer object`);
  if (!ANSWER_STATUSES.includes(a.status)) refuse(`${name}.status must be one of ${ANSWER_STATUSES.join("/")}`);
  if (a.status === "served" || a.status === "proved-absence") {
    if (typeof a.proved !== "boolean") refuse(`${name}.proved must be a strict boolean`);
    // the ROUTE is the provenance a soundness-review finding is about: which query produced this
    // answer. A bare proved boolean loses it, so the route travels with every
    // resolved answer.
    if (typeof a.route !== "string" || a.route.length === 0) refuse(`${name}.route must name the query that produced the answer`);
    if (!isDec(a.height)) refuse(`${name}.height must be a canonical decimal string`);
    validateScope(a.scope, `${name}.scope`);
  }
  if (a.status === "proved-absence" && a.proved !== true) {
    refuse(`${name} claims a proved absence from an unproved route; an unproved read establishes no absence`);
  }
  if (a.status === "served") {
    if (!isPlain(a.fields)) refuse(`${name}.fields must be a plain object on a served answer`);
    if (a.servedCount !== undefined && (!Number.isSafeInteger(a.servedCount) || a.servedCount < 1)) {
      refuse(`${name}.servedCount must be a positive integer when present`);
    }
  }
};

// ---- the evaluator (contract sections 3.4, 4, 6, 6.1, 9) ----

const evaluateEpochForwardState = ({ plan, evidence }) => {
  if (!PLAN_BRAND.has(plan)) {
    refuse("evaluateEpochForwardState accepts only a plan from buildExpectedRecordPlan; a kind string on an object literal proves nothing (a soundness-review finding)");
  }
  if (!isPlain(evidence)) refuse("evaluateEpochForwardState needs a plain evidence bundle");

  const reasons = [];
  const observations = [];
  const heights = [];       // proved, in-scope observation heights only
  let rangeBroken = false;  // any unserved/unverified/route-unproved answer nulls the range
  const push = (code, recordKey, diagnostic) => {
    if (!(code in REASONS)) refuse(`internal: unknown reason code ${code}`);
    reasons.push({ code, recordKey, diagnostic });
  };

  // WHY EVERY REASON IS COLLECTED AND NONE STOPS THE WALK (contract 3.4): a
  // run that stopped at the first refusal would discard an unproved condition
  // behind it and then report a height range it is not entitled to.

  /** Classify one answer's transport layer. Returns "served" | "absent" |
   * null (null = nothing usable; the reason is already pushed). */
  const consider = (a, name, keyCheck) => {
    validateAnswer(a, name);
    if (a.status === "unserved") { rangeBroken = true; push("UNPROVED_QUERY_UNSERVED", name, "the query could not be served"); return null; }
    if (a.status === "unverified") { rangeBroken = true; push("UNPROVED_PROOF_UNVERIFIED", name, "an answer arrived and its proof did not verify"); return null; }
    if (!sameScope(a.scope, plan.scope)) {
      // an out-of-scope answer is never compared and contributes no height
      push("REFUSED_SCOPE_MISMATCH", name, "the answer was obtained under a different contract, chain, version, pool or epoch");
      return null;
    }
    if (a.proved !== true) {
      rangeBroken = true;
      push("UNPROVED_ROUTE_NOT_PROVED", name, `the answer's route (${a.route}) obtains no proof (a soundness-review finding)`);
      return null;
    }
    if (a.status === "served") {
      if (!HEX64.test(a.documentId || "")) {
        push("REFUSED_NONCONFORMING_ANSWER", name, "the served answer carries no 64-hex document identifier");
        return null;
      }
      if (keyCheck && !keyCheck(a.fields)) {
        push("REFUSED_NONCONFORMING_ANSWER", name, "the served answer is for a DIFFERENT key than the one requested");
        return null;
      }
      heights.push(a.height);
      return "served";
    }
    heights.push(a.height); // a proved absence carries a real proof height
    return "absent";
  };

  /**
   * A MACHINERY SWEEP: three PROVED enumerations, ONE PER DEPENDENT DOCUMENT
   * TYPE, over one row's records. Their SERVED EMPTINESS is what entitles the
   * evaluator to say nothing forbidden exists there (a soundness-review finding).
   *
   * IT IS THREE OBSERVATIONS AND NOT ONE (a soundness-review finding). The proved-page interface
   * queries ONE document type per call (`e2ProvedQuery.cjs:283`), so
   * reservations, receipts and parts are three separate reads that may resolve
   * at three different authenticated heights with three independent proof
   * outcomes. The earlier shape carried one `height`, one `route`, one `scope`
   * and one `proved` for all three, which left NO HONEST VALUE for the height
   * the temporal comparison below uses: with reservations seen at one height and
   * parts at another, the verdict depended on which real height acquisition
   * happened to put in the single field, and the later one downgraded a genuine
   * out-of-publication-order observation to "cannot tell".
   *
   * Returns a map from component name to `{ count, height }` for every component
   * ACCEPTED, and null in that slot for every one that was not, its reason
   * already pushed. THE COMPONENTS ARE INDEPENDENT: one unserved read never
   * suppresses another's observation, and never stands in for it.
   */
  const considerSweep = (sw, key, expectedSubject) => {
    const out = { reservation: null, receipt: null, parts: null };
    if (sw === undefined || sw === null) {
      rangeBroken = true;
      push("UNPROVED_QUERY_UNSERVED", key, "the machinery sweep was not performed; emptiness is never concluded from omission");
      return out;
    }
    if (!isPlain(sw)) refuse(`${key} must be a plain object carrying one answer per dependent document type`);
    for (const name of SWEEP_COMPONENTS) {
      const c = sw[name];
      const ckey = `${key}:${name}`;
      // an OMITTED component is the a soundness-review finding shape per type: a sweep that simply
      // does not mention receipts has not established that none exist
      if (c === undefined || c === null) {
        rangeBroken = true;
        push("UNPROVED_QUERY_UNSERVED", ckey, `the ${name} sweep was not performed; emptiness is never concluded from omission`);
        continue;
      }
      if (!isPlain(c) || !ANSWER_STATUSES.includes(c.status)) refuse(`${ckey} must carry an answer status`);
      if (c.status === "unserved") { rangeBroken = true; push("UNPROVED_QUERY_UNSERVED", ckey, `the ${name} sweep could not be served`); continue; }
      if (c.status === "unverified") { rangeBroken = true; push("UNPROVED_PROOF_UNVERIFIED", ckey, `the ${name} sweep's proof did not verify`); continue; }
      if (c.status === "proved-absence") refuse(`${ckey} is an enumeration; observed emptiness is a served zero count, not a proved-absence answer`);
      if (typeof c.proved !== "boolean" || typeof c.route !== "string" || c.route.length === 0) {
        refuse(`${ckey} needs strict-boolean proved and a route naming the query`);
      }
      if (c.proved !== true) { rangeBroken = true; push("UNPROVED_ROUTE_NOT_PROVED", ckey, `the ${name} sweep's route (${c.route}) obtains no proof`); continue; }
      validateScope(c.scope, `${ckey}.scope`);
      if (!sameScope(c.scope, plan.scope)) { push("REFUSED_SCOPE_MISMATCH", ckey, `the ${name} sweep was obtained under a different scope`); continue; }
      // EVERY ENUMERATION BINDS ITS QUERY SUBJECT (a soundness-review finding), and each component
      // IS its own enumeration issued by its own request, so the subject is
      // checked PER COMPONENT rather than once for the envelope. The envelope
      // carries no provenance at all, because it is a grouping and not an
      // observation, and provenance on a non-observation is the aggregation
      // a soundness-review finding is about.
      if (!HEX64.test(c.subjectAccrualId || "")) refuse(`${ckey}.subjectAccrualId must be the 64-hex accrual identifier the sweep was run against`);
      if (c.subjectAccrualId !== expectedSubject) {
        push("REFUSED_NONCONFORMING_ANSWER", ckey, `the ${name} sweep was run against accrual ${c.subjectAccrualId.slice(0, 8)}... and is being read for ${expectedSubject.slice(0, 8)}...`);
        continue;
      }
      if (!isDec(c.height)) refuse(`${ckey}.height must be a canonical decimal string`);
      if (!Number.isSafeInteger(c.count) || c.count < 0) refuse(`${ckey}.count must be a non-negative safe integer`);
      heights.push(c.height);
      out[name] = { count: c.count, height: c.height };
    }
    return out;
  };

  /**
   * Report each POSITIVE component of a sweep against the row's accrual state,
   * USING THAT COMPONENT'S OWN HEIGHT (a soundness-review finding). Each type is judged on its own
   * observation, so a reservation seen before a proved absence and a part seen
   * after it produce their own separate, correct reasons instead of one verdict
   * borrowed from whichever height was picked.
   */
  const reportSweepPositives = (sweep, key, { excluded, excludedLabel, absentHeight }) => {
    for (const name of SWEEP_COMPONENTS) {
      const c = sweep[name];
      if (!c || c.count === 0) continue;
      const ckey = `${key}:${name}`;
      if (excluded) {
        // forbidden here AT ANY HEIGHT: records are immutable and
        // non-deletable, so presence once is presence forever
        push("REFUSED_MACHINERY_UNDER_EXCLUDED_ROW", ckey,
          `${c.count} ${name} record(s) exist under a ${excludedLabel} row, which is outside the expected receipt set`);
      } else if (bigGte(absentHeight, c.height)) {
        push("REFUSED_DEPENDENTS_WITHOUT_ACCRUAL", ckey,
          `${c.count} ${name} record(s) exist while the accrual's absence is proved at or after THEIR OWN height (${c.height}); out of publication order`);
      } else {
        push("UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", ckey,
          `the accrual absence (height ${absentHeight}) is older than the ${name} observation (height ${c.height}); the accrual may have been written between the reads`);
      }
    }
  };

  /**
   * THE RESERVATION ENUMERATION for one payable row, evaluated in full (a soundness-review finding).
   * The first repaired version validated this answer STRUCTURALLY and then read
   * only its `status === "served"` branches, so an unserved, unproved-route,
   * out-of-scope or wrong-key enumeration contributed nothing at all and the
   * epoch still read `complete`. That is the same emptiness-from-omission shape
   * a soundness-review finding named, one level down, so this evaluator handles every acquisition
   * status the way the accrual enumeration does.
   *
   * Returns { served: bool, documentId?, height } or null with the reason pushed.
   * A `proved-absence` answer means the enumeration RAN and served no
   * reservation at this key, which is the honest shape of an enumeration gap.
   */
  const considerReservationEnumeration = (en, key, expectedAccrualId) => {
    if (en === undefined || en === null) {
      rangeBroken = true;
      push("UNPROVED_QUERY_UNSERVED", key, "the reservation enumeration was not performed; its silence is never read as agreement with the pinned read");
      return null;
    }
    const got = consider(en, key, (f) => f.poolId === plan.scope.poolId && f.accrualId === expectedAccrualId);
    if (got === null) return null;
    if (got === "absent") return { served: false, height: en.height };
    return { served: true, documentId: en.documentId, height: en.height };
  };

  /**
   * THE ACCRUAL ENUMERATION over (pool, epoch): the proved read whose served
   * membership is what entitles the evaluator to say no EXTRA accrual exists.
   * Required on every plan; its omission is unproved, never emptiness.
   */
  const considerAccrualEnumeration = () => {
    const en = evidence.accrualEnumeration;
    if (en === undefined || en === null) {
      rangeBroken = true;
      push("UNPROVED_QUERY_UNSERVED", "accrualEnumeration", "the accrual enumeration was not performed; the absence of extras is never concluded from omission");
      return;
    }
    if (!isPlain(en) || !ANSWER_STATUSES.includes(en.status)) refuse("accrualEnumeration must carry an answer status");
    if (en.status === "unserved") { rangeBroken = true; push("UNPROVED_QUERY_UNSERVED", "accrualEnumeration", "the accrual enumeration could not be served"); return; }
    if (en.status === "unverified") { rangeBroken = true; push("UNPROVED_PROOF_UNVERIFIED", "accrualEnumeration", "the accrual enumeration's proof did not verify"); return; }
    if (en.status === "proved-absence") refuse("accrualEnumeration is an enumeration; observed emptiness is a served empty list, not a proved-absence answer");
    if (typeof en.proved !== "boolean" || typeof en.route !== "string" || en.route.length === 0) {
      refuse("accrualEnumeration needs strict-boolean proved and a route naming the query");
    }
    if (en.proved !== true) { rangeBroken = true; push("UNPROVED_ROUTE_NOT_PROVED", "accrualEnumeration", `the enumeration's route (${en.route}) obtains no proof`); return; }
    validateScope(en.scope, "accrualEnumeration.scope");
    if (!sameScope(en.scope, plan.scope)) { push("REFUSED_SCOPE_MISMATCH", "accrualEnumeration", "the enumeration was obtained under a different scope"); return; }
    if (!Array.isArray(en.funderIds) || !isDec(en.height)) refuse("accrualEnumeration needs funderIds[] and a canonical decimal height");
    heights.push(en.height);
    const planned = new Set(plan.members.map((m) => m.funderId));
    const seen = new Set();
    for (const f of en.funderIds) {
      if (!HEX64.test(f || "")) refuse("accrualEnumeration.funderIds must be 64-hex");
      if (seen.has(f)) {
        push("REFUSED_ACCRUAL_DUPLICATE", `accrual:${f.slice(0, 8)}`, "the enumeration serves one funder-epoch twice (a unique key)");
        continue;
      }
      seen.add(f);
      if (plan.encodingRefused) {
        push("REFUSED_RECORDS_UNDER_ENCODING_REFUSED_EPOCH", `accrual:${f.slice(0, 8)}`, "the enumeration serves an accrual under an encoding-refused epoch");
      } else if (!planned.has(f)) {
        push("REFUSED_ACCRUAL_EXTRA", `accrual:${f.slice(0, 8)}`, "an accrual exists for a funder outside the recomputed set (a fetched extra)");
      }
    }
  };

  // ---- encoding-refused epochs: the conformant condition is PROVED emptiness ----
  if (plan.encodingRefused) {
    const hdr = consider(evidence.header, "header", null);
    if (hdr === "served") push("REFUSED_RECORDS_UNDER_ENCODING_REFUSED_EPOCH", "header", "a header exists under an epoch the writer refused before the header");
    considerAccrualEnumeration();
    for (const m of plan.members) {
      const a = evidence.accruals && evidence.accruals[m.funderId];
      if (a === undefined) refuse(`the evidence bundle carries no accrual answer for planned funder ${m.funderId.slice(0, 8)}...`);
      const got = consider(a, `accrual:${m.funderId.slice(0, 8)}`, null);
      if (got === "served") push("REFUSED_RECORDS_UNDER_ENCODING_REFUSED_EPOCH", `accrual:${m.funderId.slice(0, 8)}`, "an accrual exists under an encoding-refused epoch");
      const deps = evidence.dependents && evidence.dependents[m.funderId];
      const sweep = considerSweep(deps && deps.machinerySweep, `machinery:${m.funderId.slice(0, 8)}`, m.plannedAccrualId);
      // per component (a soundness-review finding). An encoding-refused epoch expects NO records of
      // any type, so each positive component is its own refusal and no height
      // comparison arises: the epoch permits nothing at any height.
      for (const name of SWEEP_COMPONENTS) {
        const c = sweep[name];
        if (!c || c.count === 0) continue;
        push("REFUSED_RECORDS_UNDER_ENCODING_REFUSED_EPOCH", `machinery:${m.funderId.slice(0, 8)}:${name}`,
          `${c.count} ${name} record(s) exist under an encoding-refused epoch`);
      }
    }
    return finish(plan, reasons, observations, heights, rangeBroken, "encoding-refused");
  }

  // ---- the header ----
  const headerKey = (f) => intStr(f.epochIndex) === String(plan.scope.epochIndex) && f.poolId === plan.scope.poolId;
  const hdr = consider(evidence.header, "header", headerKey);
  let headerServedHeight = null;
  let headerAbsentHeight = null;
  if (hdr === "served") {
    headerServedHeight = evidence.header.height;
    const f = evidence.header.fields;
    const mismatches = [];
    if (intStr(f.grossCredits) !== plan.header.grossCredits) mismatches.push(`grossCredits ${f.grossCredits} != ${plan.header.grossCredits}`);
    if (intStr(f.feeCredits) !== plan.header.feeCredits) mismatches.push(`feeCredits ${f.feeCredits} != ${plan.header.feeCredits}`);
    if (f.memberCount !== plan.header.memberCount) mismatches.push(`memberCount ${f.memberCount} != ${plan.header.memberCount}`);
    if (f.calcVersion !== 1) mismatches.push(`calcVersion ${f.calcVersion} != 1`);
    if (typeof f.allocationHash !== "string" || f.allocationHash !== plan.header.allocationHash) mismatches.push("allocationHash differs from the formation receipt's");
    if (mismatches.length) push("REFUSED_HEADER_MISMATCH", "header", `header mismatch: ${mismatches.join("; ")}`);
  } else if (hdr === "absent") {
    headerAbsentHeight = evidence.header.height;
  }

  // the accrual enumeration: required, and the only ground for "no extras"
  considerAccrualEnumeration();

  // the mirrored temporal guard (contract 6.1): an absence may drive an
  // INCOMPLETE conclusion only when it is no older than every served positive
  // in this epoch's evidence; positives are collected first, absences decided
  // after the walk
  const servedPositiveHeights = [];
  if (headerServedHeight !== null) servedPositiveHeights.push(headerServedHeight);
  const pendingIncomplete = []; // { code, recordKey, diagnostic, absenceHeight }
  const incompleteFrom = (code, recordKey, diagnostic, absenceHeight) => {
    pendingIncomplete.push({ code, recordKey, diagnostic, absenceHeight });
  };

  // ---- the accruals ----
  const rows = new Map(); // funderId -> { member, served, idMismatch?, servedId?, height?, absentHeight? }
  for (const m of plan.members) {
    const name = `accrual:${m.funderId.slice(0, 8)}`;
    const a = evidence.accruals && evidence.accruals[m.funderId];
    if (a === undefined) refuse(`the evidence bundle carries no accrual answer for planned funder ${m.funderId.slice(0, 8)}...`);
    const accrualKey = (f) => f.poolId === plan.scope.poolId && f.funderId === m.funderId
      && intStr(f.epochIndex) === String(plan.scope.epochIndex);
    const got = consider(a, name, accrualKey);
    if (got === "served") {
      if (a.servedCount !== undefined && a.servedCount > 1) {
        push("REFUSED_ACCRUAL_DUPLICATE", name, `${a.servedCount} accruals served for one funder-epoch (a unique key)`);
      }
      // a soundness-review finding check, the identifier binding: the served document's identifier
      // against the planned write identifier, BEFORE any dependent is trusted.
      // On a mismatch acquisition stops at stage 3, so no dependent entry is
      // expected for the row and none is required below (idMismatch).
      let idMismatch = false;
      if (a.documentId !== m.plannedAccrualId) {
        idMismatch = true;
        push("REFUSED_ACCRUAL_DOCUMENT_ID_MISMATCH", name,
          `the served accrual's document identifier ${a.documentId.slice(0, 8)}... differs from the planned write identifier ${m.plannedAccrualId.slice(0, 8)}...; dependents derived from the planned identifier would not bind to the served accrual`);
      }
      const f = a.fields;
      if (intStr(f.amountCredits) !== m.effectiveCredits) {
        push("REFUSED_ACCRUAL_AMOUNT_MISMATCH", name, `accrual amount ${f.amountCredits} differs from the recomputed effective ${m.effectiveCredits}`);
      }
      // a soundness-review finding check: the split recorded beside the amount
      if (f.shareBps !== m.shareBps) {
        push("REFUSED_ACCRUAL_SHARE_BPS_MISMATCH", name, `accrual shareBps ${f.shareBps} differs from the recomputed ${m.shareBps} (a soundness-review finding)`);
      }
      servedPositiveHeights.push(a.height);
      rows.set(m.funderId, { member: m, served: true, idMismatch, servedId: a.documentId, height: a.height });
      // records without a header: presence at Hs beside a header absence at Ha
      if (headerAbsentHeight !== null) {
        if (bigGte(headerAbsentHeight, a.height)) {
          push("REFUSED_RECORDS_WITHOUT_HEADER", name, "an accrual exists while the header's absence is proved at or after its height (out of publication order)");
        } else {
          push("UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", name, `the header absence (height ${headerAbsentHeight}) is older than this accrual (height ${a.height}); the header may have been written between the reads`);
        }
      }
    } else if (got === "absent") {
      rows.set(m.funderId, { member: m, served: false, absentHeight: a.height });
      incompleteFrom("INCOMPLETE_ACCRUAL_ABSENT", name, "the accrual is proved absent and the ledger holds a conforming prefix", a.height);
    } else {
      // unserved, unverified, out of scope or nonconforming: the served document
      // identifier is unresolved, so the dependents could not be keyed at all
      if (a.status === "unserved" || a.status === "unverified") {
        push("UNPROVED_ACCRUAL_IDENTIFIER_UNRESOLVED", name, "the accrual was neither served nor proved absent, so its dependents could not be keyed");
      }
      rows.set(m.funderId, { member: m, served: false, absentHeight: null });
    }
  }

  if (headerAbsentHeight !== null) {
    incompleteFrom("INCOMPLETE_HEADER_ABSENT", "header", "no header exists and the ledger holds a conforming prefix", headerAbsentHeight);
  }

  // ---- dependents, per plan member ----
  for (const m of plan.members) {
    const row = rows.get(m.funderId);
    const deps = evidence.dependents && evidence.dependents[m.funderId];
    const tag = m.funderId.slice(0, 8);

    if (m.classification !== "payable") {
      // a non-payable row's conformance IS the proved emptiness of its
      // machinery, and only a served sweep establishes it (a soundness-review finding). The sweep
      // runs by the served identifier when the accrual exists and by the
      // planned identifier otherwise.
      const sweep = considerSweep(deps && deps.machinerySweep, `machinery:${tag}`,
        row.served ? row.servedId : m.plannedAccrualId);
      reportSweepPositives(sweep, `machinery:${tag}`, {
        excluded: row.served || row.absentHeight === null,
        excludedLabel: m.classification,
        absentHeight: row.absentHeight,
      });
      continue;
    }

    // a payable row whose served accrual FAILED the identifier binding:
    // acquisition stopped at stage 3 (contract 3.2), so no dependent was
    // keyed, none is required, and the refusal above already stands
    if (row.served && row.idMismatch) continue;

    // a payable row whose accrual is unresolved: the dependents were not
    // keyable, and the identifier-unresolved reason is already pushed
    if (!row.served && row.absentHeight === null) continue;

    // a payable row whose accrual is PROVED ABSENT: proved emptiness of
    // machinery under the PLANNED identifier is still owed (a soundness-review finding), and any
    // machinery found is out of publication order, temporally guarded
    if (!row.served) {
      const sweep = considerSweep(deps && deps.machinerySweep, `machinery:${tag}`, m.plannedAccrualId);
      reportSweepPositives(sweep, `machinery:${tag}`, {
        excluded: false, excludedLabel: null, absentHeight: row.absentHeight,
      });
      continue;
    }

    // a payable row with a served, identifier-bound accrual: the full chain
    if (!isPlain(deps)) refuse(`the evidence bundle carries no dependents entry for payable funder ${tag}... whose accrual was served`);

    // reservation: one pinned unique-key read, plus the enumeration's view
    let reservation = null;         // served pinned answer
    let reservationAbsent = null;   // proved-absence height
    if (deps.reservationPinned !== null && deps.reservationPinned !== undefined) {
      const resKey = (f) => f.poolId === plan.scope.poolId && f.accrualId === row.servedId;
      const got = consider(deps.reservationPinned, `reservation:${tag}`, resKey);
      if (got === "served") { reservation = deps.reservationPinned; servedPositiveHeights.push(reservation.height); }
      else if (got === "absent") reservationAbsent = deps.reservationPinned.height;
    } else {
      refuse(`the dependents entry for payable funder ${tag}... carries no pinned reservation answer`);
    }
    // the reservation ENUMERATION, evaluated in full rather than read only on
    // its served branch (a soundness-review finding). Its every status is handled by
    // considerReservationEnumeration, so an unserved, unproved-route,
    // out-of-scope or wrong-key answer produces a reason instead of silence.
    const resEnum = considerReservationEnumeration(deps.reservationEnumerated,
      `reservationEnumerated:${tag}`, row.servedId);
    if (resEnum && resEnum.served) {
      const en = deps.reservationEnumerated;
      if (en.servedCount !== undefined && en.servedCount > 1) {
        push("REFUSED_RESERVATION_AMBIGUOUS", `reservation:${tag}`, `${en.servedCount} reservations enumerated for one accrual (a unique key)`);
      }
      if (reservation && resEnum.documentId !== reservation.documentId) {
        push("REFUSED_RESERVATION_MISMATCH", `reservation:${tag}`, "the enumeration and the pinned unique-key read serve DIFFERENT documents for one key");
      }
    } else if (resEnum && !resEnum.served && reservation) {
      // the enumeration RAN and served nothing at this key while the pinned
      // read served a record. The observation carries BOTH heights, taken from
      // validated evidence rather than asserted by the caller, and draws NO
      // conclusion that the enumeration is incomplete unless the heights
      // support it (contract 3.3).
      observations.push({ kind: "enumeration-gap", recordKey: `reservation:${tag}`,
        uniqueKeyHeight: reservation.height, enumerationHeight: resEnum.height,
        scopeMatched: true });
    }

    // receipt
    let receipt = null;
    let receiptAbsent = null;
    if (deps.receipt === null || deps.receipt === undefined) {
      refuse(`the dependents entry for payable funder ${tag}... carries no receipt answer`);
    }
    {
      const rKey = (f) => f.poolId === plan.scope.poolId && f.accrualId === row.servedId;
      const got = consider(deps.receipt, `receipt:${tag}`, rKey);
      if (got === "served") {
        receipt = deps.receipt;
        servedPositiveHeights.push(receipt.height);
        if (receipt.servedCount !== undefined && receipt.servedCount > 1) {
          push("REFUSED_RECEIPT_AMBIGUOUS", `receipt:${tag}`, `${receipt.servedCount} receipts served for one accrual (a unique key)`);
        }
      } else if (got === "absent") receiptAbsent = deps.receipt.height;
    }

    // the part set: enumerated by the served accrual identifier WHETHER OR NOT
    // the receipt is served (contract 3.2 stage 5; revision 3's R8)
    let partIndices = null;   // sorted observed indices
    let partHeight = null;
    // true exactly when the part read produced an UNPROVED reason (not served,
    // not verified, or an unproved route): the verdict is then deferred below
    let partsUnresolved = false;
    if (deps.partSet !== null && deps.partSet !== undefined) {
      const ps = deps.partSet;
      if (!isPlain(ps) || !ANSWER_STATUSES.includes(ps.status)) refuse(`partSet:${tag} must carry an answer status`);
      if (ps.status === "unserved") { rangeBroken = true; partsUnresolved = true; push("UNPROVED_QUERY_UNSERVED", `parts:${tag}`, "the part enumeration could not be served"); }
      else if (ps.status === "unverified") { rangeBroken = true; partsUnresolved = true; push("UNPROVED_PROOF_UNVERIFIED", `parts:${tag}`, "the part enumeration's proof did not verify"); }
      else if (ps.status === "proved-absence") refuse(`partSet:${tag} is an enumeration; observed emptiness is a served empty list, not a proved-absence answer`);
      else {
        if (typeof ps.route !== "string" || ps.route.length === 0) refuse(`partSet:${tag}.route must name the query that produced it`);
        if (ps.proved !== true) { rangeBroken = true; partsUnresolved = true; push("UNPROVED_ROUTE_NOT_PROVED", `parts:${tag}`, `the part enumeration's route (${ps.route}) obtains no proof`); }
        else if (!sameScope(ps.scope, plan.scope)) push("REFUSED_SCOPE_MISMATCH", `parts:${tag}`, "the part enumeration was obtained under a different scope");
        else {
          if (!Array.isArray(ps.parts) || !isDec(ps.height)) refuse(`partSet:${tag} needs parts[] and a canonical decimal height`);
          // THE PART ENUMERATION CARRIES ITS QUERY SUBJECT (a soundness-review finding), for the
          // same reason the machinery sweep does: without it a part set
          // obtained for one member can be filed under another's entry.
          if (!HEX64.test(ps.subjectAccrualId || "")) refuse(`partSet:${tag}.subjectAccrualId must be the 64-hex accrual identifier the enumeration was run against`);
          if (ps.subjectAccrualId !== row.servedId) {
            push("REFUSED_NONCONFORMING_ANSWER", `parts:${tag}`, `the part enumeration was run against accrual ${ps.subjectAccrualId.slice(0, 8)}... and is being read for ${row.servedId.slice(0, 8)}...`);
          } else {
          heights.push(ps.height);
          partHeight = ps.height;
          const idx = ps.parts.map((p) => p.partIndex);
          const seen = new Set();
          let conforming = true;
          for (const i of idx) {
            if (!Number.isSafeInteger(i) || i < 1 || i > 7) { conforming = false; break; }
            if (seen.has(i)) { conforming = false; break; }
            seen.add(i);
          }
          const sorted = [...seen].sort((a, b) => a - b);
          // index conformance is checked in BOTH phases: a duplicate or
          // out-of-range or noncontiguous set is nonconforming whether or not
          // the final count is yet known (contract 6, G3)
          if (conforming) conforming = sorted.every((v, i) => v === i + 1);
          if (!conforming) {
            push("REFUSED_PART_INDEX_NONCONFORMING", `parts:${tag}`, "the observed part indices are duplicated, outside 1..7, or noncontiguous");
          } else {
            partIndices = sorted;
            if (sorted.length > 0) servedPositiveHeights.push(ps.height);
          }
          }
        }
      }
    }

    // ---- the prefix decision for this row (contract 6 with 6.1) ----
    if (receipt) {
      // reservation beside a served receipt
      if (reservationAbsent !== null) {
        if (bigGte(reservationAbsent, receipt.height)) {
          push("REFUSED_RESERVATION_PROVED_ABSENT", `reservation:${tag}`, "the reservation's absence is proved at or after the receipt's height (an expected record at a known unique key)");
        } else {
          push("UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", `reservation:${tag}`, `the reservation absence (height ${reservationAbsent}) is older than the receipt (height ${receipt.height}); the reservation may have been written between the reads`);
        }
      } else if (reservation) {
        const rHash = receipt.fields.transitionHash;
        if (typeof rHash !== "string" || !HEX64.test(rHash) || reservation.fields.transitionHash !== rHash) {
          push("REFUSED_RESERVATION_MISMATCH", `reservation:${tag}`, "the reservation's transitionHash differs from the receipt's (a soundness-review finding)");
        }
      }
      // the part count against the receipt's proofPartCount
      const ppc = receipt.fields.proofPartCount;
      if (!Number.isSafeInteger(ppc) || ppc < 1 || ppc > 8) {
        push("REFUSED_NONCONFORMING_ANSWER", `receipt:${tag}`, `the receipt's proofPartCount ${ppc} is outside the schema's 1..8 domain`);
      } else if (partIndices !== null) {
        const required = ppc - 1;
        if (partIndices.length > required) {
          // extra parts are present forever (immutable, non-deletable), so an
          // over-count refuses at ANY observation height
          push("REFUSED_PART_COUNT_MISMATCH", `parts:${tag}`, `${partIndices.length} part documents exist where the receipt requires exactly ${required}`);
        } else if (partIndices.length < required) {
          if (bigGte(partHeight, receipt.height)) {
            if (partIndices.length === 0) {
              push("REFUSED_RECEIPT_BEFORE_PARTS", `parts:${tag}`, "the receipt exists and its required part documents are proved absent at or after its height (out of publication order)");
            } else {
              push("REFUSED_PART_COUNT_MISMATCH", `parts:${tag}`, `${partIndices.length} part documents observed at or after the receipt's height where it requires ${required}`);
            }
          } else {
            push("UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", `parts:${tag}`, `the part observation (height ${partHeight}) is older than the receipt (height ${receipt.height}); the missing parts may have been written between the reads`);
          }
        }
      }
      // the execution verdict: produced by the receipt verifier upstream,
      // consumed here as evidence (the pure module performs no cryptography)
      const ex = deps.execution;
      if (!isPlain(ex) || typeof ex.label !== "string") {
        refuse(`the dependents entry for payable funder ${tag}... carries a served receipt and no execution verdict; unchecked never means passed`);
      }
      // THE VERDICT IS NOT EVALUATED OVER UNRESOLVED EVIDENCE (contract revision
      // 14, the named result for unserved evidence): when the part read or the
      // pinned reservation read produced an UNPROVED reason, the situation is
      // unproved, and a verdict over evidence the verifier could not see must
      // not turn it into a refusal by precedence. The verdict, whatever it
      // says, is recorded as an observation and the unproved reasons already
      // pushed carry the state. Acquisition marks such a verdict
      // EVIDENCE-UNRESOLVED without requesting it; that marker beside RESOLVED
      // reads is a contract violation, because a verdict was owed.
      // `reservation === null && reservationAbsent === null` means the pinned
      // read neither served nor proved absence: `consider` pushed a reason for
      // it (unproved for an unserved, unverified or unproved-route read; refused
      // for a wrong scope or key, where the deferral is moot since the row is
      // refused on that reason). The row therefore always carries a reason
      // whenever the verdict is deferred, which is what keeps this from being a
      // path to complete without a judged verdict.
      const reservationUnresolved = reservation === null && reservationAbsent === null;
      if (partsUnresolved || reservationUnresolved) {
        if (ex.label === "EVIDENCE-UNRESOLVED" && ex.requested !== false) {
          refuse(`the dependents entry for payable funder ${tag}... carries an EVIDENCE-UNRESOLVED marker that does not state requested: false; a marker is acquisition's statement that no verdict was requested, and one that says otherwise is not that statement`);
        }
        observations.push({ kind: "execution-verdict-deferred", recordKey: `receipt:${tag}`, label: ex.label,
          reason: `the ${partsUnresolved ? "part enumeration" : "pinned reservation read"} produced no resolved evidence; the verdict is not evaluated over evidence the verifier could not see` });
      } else if (ex.label === "EVIDENCE-UNRESOLVED") {
        refuse(`the dependents entry for payable funder ${tag}... carries the acquisition marker EVIDENCE-UNRESOLVED beside resolved part and reservation reads; a verdict was owed and not requested; unchecked never means passed`);
      } else if (ex.label !== "CAPTURE-VERIFIED") {
        push("REFUSED_TRANSFER_UNVERIFIED", `receipt:${tag}`, `the transfer execution verdict is ${ex.label}, not CAPTURE-VERIFIED${ex.reason ? ` (${ex.reason})` : ""}`);
      } else if (intStr(ex.verifiedAmountCredits) !== m.effectiveCredits) {
        push("REFUSED_PART_MISMATCH", `receipt:${tag}`, `the verified transfer amount ${ex.verifiedAmountCredits} differs from the entitlement's effective ${m.effectiveCredits}`);
      }
    } else if (receiptAbsent !== null) {
      if (reservationAbsent !== null) {
        incompleteFrom("INCOMPLETE_RESERVATION_ABSENT", `reservation:${tag}`, "no reservation and no receipt exist for this payable row; the prefix ends before the reservation", reservationAbsent);
      } else if (reservation) {
        incompleteFrom("INCOMPLETE_RECEIPT_ABSENT", `receipt:${tag}`, "a reservation exists and the receipt does not; a legal in-flight prefix", receiptAbsent);
      } else {
        // reservation unresolved (unserved etc.): its reason is already pushed
        incompleteFrom("INCOMPLETE_RECEIPT_ABSENT", `receipt:${tag}`, "the receipt is proved absent", receiptAbsent);
      }
      // parts observed with no receipt: a legal in-flight prefix when the
      // indices conform (B5/G2); no final count claim is possible
    }
  }

  // ---- the mirrored temporal guard resolves the pending incompleteness ----
  // (contract 6.1: negative evidence establishing a missing suffix must be no
  // older than the positive evidence defining the prefix)
  for (const p of pendingIncomplete) {
    const newer = servedPositiveHeights.filter((h) => !bigGte(p.absenceHeight, h));
    if (newer.length === 0) {
      push(p.code, p.recordKey, p.diagnostic);
    } else {
      push("UNPROVED_PREFIX_TEMPORALLY_UNRESOLVED", p.recordKey,
        `the absence (height ${p.absenceHeight}) is older than served evidence (height ${newer[0]}); reacquire at a sufficient height before concluding incompleteness`);
    }
  }

  const condition = plan.header && plan.header.grossCredits === "0" ? "zero-earning-epoch" : null;
  return finish(plan, reasons, observations, heights, rangeBroken, condition);
};

// ---- the result, with precedence and the height range ----

function finish(plan, reasons, observations, heights, rangeBroken, condition) {
  let state = "complete";
  for (const r of reasons) {
    const s = REASONS[r.code];
    if (s === "refused") { state = "refused"; break; }
    if (s === "unproved") state = "unproved";
    else if (s === "incomplete" && state === "complete") state = "incomplete";
  }
  let heightRange = null;
  if (!rangeBroken && heights.length) {
    const hs = heights.map(BigInt);
    heightRange = { min: String(hs.reduce((a, b) => (b < a ? b : a))),
      max: String(hs.reduce((a, b) => (b > a ? b : a))) };
  }
  const result = deepFreeze({
    kind: "tegara.e2.forwardResult.v1",
    poolId: plan.scope.poolId,
    epochIndex: plan.scope.epochIndex,
    state, condition, reasons, observations, heightRange,
  });
  RESULT_BRAND.add(result);
  return result;
}

/**
 * The C4-family results: preconditions of plan building that fail before any
 * evidence exists (carry unseeded, formation unavailable, no epoch object).
 * The orchestrator constructs these so the snapshot still carries a result
 * for the epoch, and the projection refuses it by name.
 */
const PRECONDITION_CODES = Object.freeze(["UNPROVED_CARRY_UNSEEDED",
  "UNPROVED_FORMATION_UNAVAILABLE", "UNPROVED_EPOCH_OBJECT_ABSENT",
  "UNPROVED_EPOCH_OBJECT_UNPROVED"]);

const unprovedPrecondition = ({ poolId, epochIndex, code, diagnostic }) => {
  if (!HEX64.test(poolId || "")) refuse("unprovedPrecondition needs a 64-hex poolId");
  if (!Number.isSafeInteger(epochIndex) || epochIndex < 0) refuse("unprovedPrecondition needs a non-negative safe epochIndex");
  if (!PRECONDITION_CODES.includes(code)) refuse(`unprovedPrecondition takes one of ${PRECONDITION_CODES.join("/")}`);
  if (typeof diagnostic !== "string" || diagnostic.length === 0) refuse("unprovedPrecondition needs a diagnostic");
  const result = deepFreeze({
    kind: "tegara.e2.forwardResult.v1",
    poolId, epochIndex,
    state: "unproved", condition: null,
    reasons: [{ code, recordKey: "epoch", diagnostic }],
    observations: [], heightRange: null,
  });
  RESULT_BRAND.add(result);
  return result;
};

// ---- the snapshot and the strict writer projection (contract section 5) ----

const createSnapshot = (results, options) => {
  if (!Array.isArray(results)) refuse("createSnapshot takes an array of kernel results");
  // THE GENERATION (contract revision 16, the per-epoch context design section 5):
  // the orchestrator numbers every refresh from zero and the projection the
  // writer holds is bound to one numbered snapshot, so an artifact can say which
  // snapshot each selection was made against. It is REQUIRED, not defaulted: a
  // snapshot nobody numbered is one the orchestrator forgot to, and a default of
  // zero would read as the run's first snapshot forever.
  if (!isPlain(options)) refuse("createSnapshot takes a plain options object as its second argument, carrying the generation");
  // the generation is read through its OWN DATA descriptor, never through the
  // prototype and never through an accessor, so an inherited or computed
  // number cannot stand in for the orchestrator's own (the pre-commit checker's
  // construction); the rejected value is described by type, never serialized,
  // so a bigint or a cyclic object gets the named refusal and not a
  // serializer's error
  const gd = Object.getOwnPropertyDescriptor(options, "generation");
  if (!gd || !("value" in gd)) refuse("createSnapshot needs an own data member generation on its options (absent, inherited or an accessor is refused); the orchestrator numbers every refresh from zero");
  const generation = gd.value;
  if (!Number.isSafeInteger(generation) || generation < 0) {
    refuse(`createSnapshot needs a non-negative safe-integer generation (got a value of type ${typeof generation}); the orchestrator numbers every refresh from zero`);
  }
  const byEpoch = new Map();
  let poolId = null;
  for (const r of results) {
    if (!RESULT_BRAND.has(r)) refuse("createSnapshot accepts only results this kernel produced; a hand-built object cannot claim a state");
    if (poolId === null) poolId = r.poolId;
    // ONE POOL PER SNAPSHOT: a projection bound to a snapshot answers for one
    // pool's run, and mixing pools would let epoch N of one pool answer for
    // epoch N of another
    if (r.poolId !== poolId) refuse(`createSnapshot was handed results from two pools (${poolId.slice(0, 8)}... and ${r.poolId.slice(0, 8)}...); a snapshot binds one pool`);
    if (byEpoch.has(r.epochIndex)) refuse(`createSnapshot was handed two results for epoch ${r.epochIndex}`);
    byEpoch.set(r.epochIndex, r);
  }
  const snapshot = Object.freeze({
    kind: "tegara.e2.forwardSnapshot.v1",
    poolId,
    generation,
    epochs: Object.freeze([...byEpoch.keys()].sort((a, b) => a - b)),
    lookup: (epochIndex) => (byEpoch.has(epochIndex) ? byEpoch.get(epochIndex) : undefined),
  });
  SNAPSHOT_BRAND.add(snapshot);
  return snapshot;
};

/**
 * The boolean projection, total, with no default branch. `complete` is true,
 * `incomplete` is false, and EVERYTHING ELSE REFUSES BY NAME: an unproved or
 * refused epoch, and an epoch absent from the snapshot. Returning false for
 * those would send the writer to work an epoch whose state is unknown or
 * known-wrong, which is the failure this kernel exists to close.
 */
const projectForWriter = (snapshot, epochIndex) => {
  if (!isPlain(snapshot) || !SNAPSHOT_BRAND.has(snapshot)) {
    refuse("projectForWriter accepts only a snapshot from createSnapshot; a kind string on an object literal proves nothing (a soundness-review finding)");
  }
  if (!Number.isSafeInteger(epochIndex) || epochIndex < 0) refuse("projectForWriter needs a non-negative safe epochIndex");
  const r = snapshot.lookup(epochIndex);
  if (r === undefined) {
    refuse(`PROJECTION_EPOCH_NOT_EVALUATED: epoch ${epochIndex} is absent from the evaluated snapshot; the projection never evaluates on demand and never treats absence as incomplete`);
  }
  // the correspondence check: with the brand this is an internal invariant of
  // createSnapshot's own map, kept as a hard check because the projection is
  // the last gate before the writer acts on the answer
  if (r.epochIndex !== epochIndex) {
    refuse(`internal: the snapshot served epoch ${r.epochIndex} for a lookup of epoch ${epochIndex}`);
  }
  if (r.state === "complete") return true;
  if (r.state === "incomplete") return false;
  if (r.state === "unproved") {
    refuse(`PROJECTION_STATE_UNPROVED: epoch ${epochIndex}'s state is unproved (${r.reasons.map((x) => x.code).join(", ")}); the run stops by name rather than working an epoch whose state is unknown`);
  }
  refuse(`PROJECTION_STATE_REFUSED: epoch ${epochIndex}'s state is refused (${r.reasons.map((x) => x.code).join(", ")}); retrying cannot correct a record that is already on the ledger and wrong`);
};

module.exports = {
  STATES, REASONS, PROJECTION_CODES, PRECONDITION_CODES, PLAN_FIELD_COVERAGE,
  buildExpectedRecordPlan, evaluateEpochForwardState, unprovedPrecondition,
  createSnapshot, projectForWriter,
};
