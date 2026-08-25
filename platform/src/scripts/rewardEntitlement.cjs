/**
 * rewardEntitlement - build-order item 2 of the REVIEW-COMPLETE design (revision 27):
 * the finality-fixed entitlement classification as a PURE module.
 *
 * The precedence table is the executable matrix of docs/schema/check_vectors.py
 * (verifyRewardDecision), which this module must agree with exactly; the test
 * cross-checks every reward record of the shipped positive vector.
 *
 * The finality model (packet-review blocker 2, removed everywhere): the ONLY finality gate is
 * H <= validated best ChainLock. Later lifecycle transitions are REPORTING data; there
 * is no per-boundary gate. Entitlement takes the TYPED authenticated list(H-1)
 * eligibility (the five-state form + list height + the authenticated list root), never
 * a bare boolean.
 *
 * NARROWED CLAIMS carried from the review cycle: the schedule (and with it the owner
 * vector's SOURCE SELECTION) is structurally TRUSTED_SOURCE (a soundness-review finding); what this module
 * computes over it is the authenticated half: consuming owner-first matching and the
 * arithmetic relative to the trusted vector (a soundness-review finding).
 */
"use strict";

const SCHEDULE_SOURCE = "trusted-core-node:masternode-payments";

function fail(msg) {
  throw new Error(`entitlement: ${msg}`);
}

const DEC_RE = /^(?:0|[1-9][0-9]*)$/;
const SCRIPT_RE = /^(?:[0-9a-f]{2})*$/;

/**
 * The per-output rules, defined ONCE and used by every entry point that consumes an output
 * (repository-access review, MAJOR). They used to live inside assertClassifyInputs, so
 * matchOwnerVector, which is separately exported, applied none of them.
 *
 * The KEY SETS are the normative ones from auditEnvelope.v1.schema.json, where every one of
 * these objects carries `additionalProperties: false`.
 */
const OUTPUT_KEYS = {
  expected: ["script", "amountDuffs"],
  actual: ["script", "amountDuffs", "outputIndex"],
};

function assertClosed(obj, allowed, what) {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) {
      fail(`${what} carries the undeclared field ${JSON.stringify(k)} ` +
           `(the format declares only ${allowed.join(", ")})`);
    }
  }
}

/** script and amount, shared by both output kinds. typeof BEFORE the pattern, always: the
 *  regular expression coerces, so a NUMBER 5 tested as "5" and passed a check that claims to
 *  require a decimal STRING. */
function assertScriptAndAmount(o, what) {
  if (typeof o.script !== "string" || !SCRIPT_RE.test(o.script)) {
    fail(`${what} has a malformed script`);
  }
  if (typeof o.amountDuffs !== "string" || !DEC_RE.test(o.amountDuffs)) {
    fail(`${what} has a malformed amountDuffs (it must be a decimal string)`);
  }
}

function assertExpectedOutput(o) {
  if (!o || typeof o !== "object") fail("an expected output must be an object");
  if ("outputIndex" in o) fail("an EXPECTED output must carry no outputIndex");
  assertClosed(o, OUTPUT_KEYS.expected, "an expected output");
  assertScriptAndAmount(o, "an expected output");
}

function assertActualOutput(o) {
  if (!o || typeof o !== "object") fail("an actual output must be an object");
  assertClosed(o, OUTPUT_KEYS.actual, "an actual output");
  assertScriptAndAmount(o, "an actual output");
  if (!Number.isSafeInteger(o.outputIndex) || o.outputIndex < 0) {
    fail("an actual output has a malformed outputIndex");
  }
}

/**
 * Derive the TYPED five-state eligibility for reward height H from the walk state at
 * H-1 plus the journal and base context (the executable spec's eligibility_at).
 *
 *   stateAtHMinus1 : ABSENT | PRESENT_VALID | PRESENT_INVALID (the list-walk state at
 *                    H-1; at the base itself, the initial state)
 *   listRoot       : the authenticated list root the state was verified against
 *                    (null only for a pre-DML base row, whose H-1 list does not exist)
 *   hMinus1        : H - 1
 *   journal        : { terminalHeight, transitions } from reconstructLifecycle
 *   base           : { kind: "rooted"|"pre-dml", baseMode?: "FIRST_APPEARANCE"|
 *                    "RANGE_LOCAL", pHeight? } (pHeight required for FIRST_APPEARANCE)
 */
function deriveEligibility({ stateAtHMinus1, listRoot, hMinus1, journal, base }) {
  // round 4, MAJOR: a string hMinus1 flowed into the returned listHeight and every
  // comparison below, yielding a plausible typed state instead of a named refusal
  if (!Number.isSafeInteger(hMinus1) || hMinus1 < 0) {
    fail(`hMinus1 must be a safe non-negative integer (got ${JSON.stringify(hMinus1)})`);
  }
  if (stateAtHMinus1 === "PRESENT_VALID" || stateAtHMinus1 === "PRESENT_INVALID") {
    return { state: stateAtHMinus1, listHeight: hMinus1, listRoot };
  }
  if (stateAtHMinus1 !== "ABSENT") fail(`unknown walk state ${JSON.stringify(stateAtHMinus1)}`);
  const term = journal ? journal.terminalHeight : null;
  if (term !== null && term !== undefined && !Number.isSafeInteger(term)) {
    // build review round 3, MAJOR: a STRING terminal height was coerced by comparison
    // and produced ABSENT_TERMINAL, a wrong answer from malformed input
    fail(`journal.terminalHeight must be a safe integer or null (got ${JSON.stringify(term)})`);
  }
  if (term !== null && term !== undefined && term <= hMinus1) {
    return { state: "ABSENT_TERMINAL", listHeight: hMinus1, listRoot };
  }
  if (base && base.kind === "rooted" && base.baseMode === "FIRST_APPEARANCE") {
    if (!Number.isSafeInteger(base.pHeight)) fail("FIRST_APPEARANCE base needs pHeight");
    if (hMinus1 < base.pHeight) {
      return { state: "ABSENT_PRE_APPEARANCE", listHeight: hMinus1, listRoot };
    }
  }
  if (base && base.kind === "pre-dml") {
    // under a pre-DML base the distinction IS provable (the walk starts before any
    // deterministic entry can exist): absence with no prior appearance is pre-appearance
    // TYPED BEFORE COMPARED (round 5, MAJOR): a transition height "abc" compared false, so no
    // appearance was found and the answer came back ABSENT_PRE_APPEARANCE, which is a decision
    // about member eligibility derived from evidence this code could not read.
    const transitions = (journal && journal.transitions) || [];
    for (let i = 0; i < transitions.length; i++) {
      if (!Number.isSafeInteger(transitions[i].height) || transitions[i].height < 0) {
        fail(`journal transition ${i} has a malformed height ${JSON.stringify(transitions[i].height)}`);
      }
    }
    const appeared = transitions.some((t) => t.from === "ABSENT" && t.height <= hMinus1);
    if (!appeared) return { state: "ABSENT_PRE_APPEARANCE", listHeight: hMinus1, listRoot };
  }
  // a range-local base cannot distinguish pre-registration from an earlier removal:
  // fail-closed typing, never terminal
  return { state: "ABSENT_UNKNOWN", listHeight: hMinus1, listRoot };
}

/**
 * OWNER-FIRST CONSUMING attribution (a soundness-review finding): match the trusted expected owner vector
 * against the actual coinbase outputs, consuming by ascending outputIndex; every
 * unconsumed actual output is the complete unexplained remainder (revision 25), any
 * script. Returns { matchedOutputs, unexplainedOutputs }.
 */
function matchOwnerVector(requiredOutputs, actualOutputs) {
  // VALIDATE ITS OWN INPUTS (repository-access review, MAJOR). This function is exported and
  // reachable without classifyEntitlement, and it performed no amount or script validation, so
  // it matched a numeric expected amount 5 against a numeric actual 5 and returned an empty
  // unexplained remainder. The classifier's decimal-string guard protected only the classifier.
  // The shared validators are used here so the two entry points cannot apply different rules.
  if (!Array.isArray(requiredOutputs)) fail("requiredOutputs must be an array");
  if (!Array.isArray(actualOutputs)) fail("actualOutputs must be an array");
  for (const o of requiredOutputs) assertExpectedOutput(o);
  for (const o of actualOutputs) assertActualOutput(o);
  // FAIL CLOSED on duplicate outputIndex (build review, MAJOR): the index is the
  // identity a match consumes, so a duplicated index made one matched output erase a
  // DIFFERENT output from the unexplained remainder while the record still read OWED.
  // The envelope's own rule is index-unique per row; enforce it here rather than
  // relying on an upstream check.
  const seen = new Set();
  for (const o of actualOutputs) {
    if (!Number.isSafeInteger(o.outputIndex)) fail("actual output has a non-integer outputIndex");
    if (seen.has(o.outputIndex)) fail(`duplicate actual outputIndex ${o.outputIndex}`);
    seen.add(o.outputIndex);
  }
  // bucket by (script, amount) so matching is O(actual + expected) rather than a filter
  // and sort per expectation (build review, MAJOR: quadratic work on long rows)
  const buckets = new Map();
  for (const o of [...actualOutputs].sort((a, b) => a.outputIndex - b.outputIndex)) {
    const k = `${o.script}|${o.amountDuffs}`;
    if (!buckets.has(k)) buckets.set(k, []);
    buckets.get(k).push(o);
  }
  const cursor = new Map();
  const used = new Set();
  const matched = [];
  for (const exp of requiredOutputs) {
    const k = `${exp.script}|${exp.amountDuffs}`;
    const list = buckets.get(k);
    if (!list) continue;
    const at = cursor.get(k) || 0;          // each bucket is already index-ascending
    if (at < list.length) {
      cursor.set(k, at + 1);
      used.add(list[at].outputIndex);
      matched.push(list[at]);
    }
  }
  matched.sort((a, b) => a.outputIndex - b.outputIndex);
  const unexplained = actualOutputs
    .filter((o) => !used.has(o.outputIndex))
    .sort((a, b) => a.outputIndex - b.outputIndex);
  return { matchedOutputs: matched, unexplainedOutputs: unexplained };
}

/**
 * classifyEntitlement - the precedence table, pure.
 *
 *   height          : the reward Core height H
 *   chainlockHeight : the validated best ChainLock height (the caller validates it)
 *   eligibility     : the TYPED form from deriveEligibility (ignored while a
 *                     higher-precedence row fires)
 *   scheduleResult  : { kind: "pool-scheduled", requiredOutputs } | { kind: "not-pool" }
 *                     | { kind: "unavailable" }   (the trusted schedule read)
 *   coinbase        : { kind: "available", outputs } | { kind: "unavailable" }
 *   paths           : optional { coreRowPath, rewardPath } for anomaly evidence refs
 *                     (RFC 6901 pointers into the envelope; required only when the
 *                     classification is ANOMALY and serialization is intended)
 *
 * Returns the entitlement object in the envelope's exact serialized shape.
 */
const ELIGIBILITY_STATES = new Set(["PRESENT_VALID", "PRESENT_INVALID",
  "ABSENT_PRE_APPEARANCE", "ABSENT_TERMINAL", "ABSENT_UNKNOWN"]);
const HEX32_RE = /^[0-9a-f]{64}$/;

/**
 * Validate the tagged unions and the eligibility object BEFORE any precedence is applied
 * (build review round 3, MAJOR): unvalidated inputs produced CLASSIFICATIONS instead of
 * errors -- `coinbase: {kind:"garbage"}` returned NOT_PAYEE, and a STRING terminal height
 * was coerced by comparison into ABSENT_TERMINAL. Malformed input must never reach the
 * matrix.
 */
/**
 * The KEY SETS are the normative ones, copied from auditEnvelope.v1.schema.json, where
 * every one of these objects carries `additionalProperties: false`. Undeclared fields are
 * therefore outside the format already, and the gate declines a record carrying them; this
 * check exists because classifyEntitlement is an EXPORTED PRIMITIVE that runs long before
 * the gate, and a caller's typo should name itself here rather than travel as far as the
 * schema layer (property review, P6, reproduced: eligibility, scheduleResult and coinbase
 * each carrying a bogus extra field returned NOT_PAYEE instead of an error).
 */
const KEYS = {
  "scheduleResult.pool-scheduled": ["kind", "requiredOutputs"],
  "scheduleResult.not-pool": ["kind"],
  "scheduleResult.unavailable": ["kind"],
  "coinbase.available": ["kind", "txRaw", "inclusionProof", "outputs"],
  "coinbase.unavailable": ["kind"],
  eligibility: ["state", "listHeight", "listRoot"],
};

function assertClassifyInputs({ eligibility, scheduleResult, coinbase }) {
  if (!scheduleResult || typeof scheduleResult !== "object") fail("scheduleResult must be an object");
  if (!["pool-scheduled", "not-pool", "unavailable"].includes(scheduleResult.kind)) {
    fail(`unknown scheduleResult kind ${JSON.stringify(scheduleResult.kind)}`);
  }
  assertClosed(scheduleResult, KEYS[`scheduleResult.${scheduleResult.kind}`], "scheduleResult");
  if (scheduleResult.kind === "pool-scheduled") {
    if (!Array.isArray(scheduleResult.requiredOutputs)) fail("pool-scheduled needs a requiredOutputs array");
    for (const o of scheduleResult.requiredOutputs) assertExpectedOutput(o);
  }
  if (!coinbase || typeof coinbase !== "object") fail("coinbase must be an object");
  if (!["available", "unavailable"].includes(coinbase.kind)) {
    fail(`unknown coinbase kind ${JSON.stringify(coinbase.kind)}`);
  }
  assertClosed(coinbase, KEYS[`coinbase.${coinbase.kind}`], "coinbase");
  if (coinbase.kind === "available") {
    if (!Array.isArray(coinbase.outputs)) fail("an available coinbase needs an outputs array");
    for (const o of coinbase.outputs) assertActualOutput(o);
  }
  // ELIGIBILITY IS REQUIRED AND VALIDATED UNCONDITIONALLY (property review, P6,
  // reproduced). It used to be optional, on the reasoning that the higher-precedence rows
  // do not consult it: with it absent, H > chainlock still returned {kind:"unfinalized"}.
  // That answer is correct, which is exactly the problem. A caller whose eligibility
  // derivation returned undefined got a decision back instead of an error, so a broken
  // derivation stayed invisible for every unfinalized or unknown height. The typed form is
  // pure and always available to a real caller (deriveEligibility never returns nothing),
  // so requiring it costs nothing and closes the silent path.
  if (eligibility === undefined || eligibility === null || typeof eligibility !== "object") {
    fail("eligibility must be the typed object from deriveEligibility (it is required for every row)");
  }
  assertClosed(eligibility, KEYS.eligibility, "eligibility");
  if (!ELIGIBILITY_STATES.has(eligibility.state)) {
    fail(`unknown eligibility state ${JSON.stringify(eligibility.state)}`);
  }
  if (!Number.isSafeInteger(eligibility.listHeight) || eligibility.listHeight < 0) {
    fail("eligibility.listHeight must be a safe non-negative integer");
  }
  if (eligibility.listRoot !== null && !HEX32_RE.test(eligibility.listRoot || "")) {
    fail("eligibility.listRoot must be 64 lowercase hex or null");
  }
}

function classifyEntitlement({ height, chainlockHeight, eligibility, scheduleResult, coinbase, paths }) {
  if (!Number.isSafeInteger(height) || height < 0) fail("height must be a safe non-negative integer");
  if (!Number.isSafeInteger(chainlockHeight)) fail("chainlockHeight must be a safe integer");
  assertClassifyInputs({ eligibility, scheduleResult, coinbase });

  // THE ONLY FINALITY GATE
  if (height > chainlockHeight) return { kind: "unfinalized" };

  const missing = [];
  if (!scheduleResult || scheduleResult.kind === "unavailable") missing.push("schedule");
  if (!coinbase || coinbase.kind === "unavailable") missing.push("coinbase");
  if (missing.length) return { kind: "unknown", missingInputs: missing.sort() };

  if (!eligibility || typeof eligibility.state !== "string") fail("missing typed eligibility");
  const estate = eligibility.state;

  if (scheduleResult.kind === "not-pool" && estate === "ABSENT_UNKNOWN") {
    return { kind: "unknown", missingInputs: ["eligibility-base"] };
  }

  let classification, reason;
  let coinbaseEvidence = { requiredOutputs: [], matchedOutputs: [], unexplainedOutputs: [] };
  let anomalyCode = null;
  if (scheduleResult.kind === "pool-scheduled") {
    const { matchedOutputs, unexplainedOutputs } = matchOwnerVector(
      scheduleResult.requiredOutputs, coinbase.outputs);
    coinbaseEvidence = {
      requiredOutputs: scheduleResult.requiredOutputs,
      matchedOutputs,
      unexplainedOutputs,
    };
    if (estate !== "PRESENT_VALID") {
      classification = "ANOMALY"; reason = "none"; anomalyCode = "SCHEDULE_LIST_DISAGREEMENT";
    } else if (matchedOutputs.length !== scheduleResult.requiredOutputs.length) {
      classification = "ANOMALY"; reason = "none"; anomalyCode = "COINBASE_MISMATCH";
    } else {
      classification = "OWED"; reason = "none";
    }
  } else if (scheduleResult.kind === "not-pool") {
    ({ classification, reason } = {
      ABSENT_TERMINAL: { classification: "EXCLUDED", reason: "terminal" },
      ABSENT_PRE_APPEARANCE: { classification: "EXCLUDED", reason: "pre-appearance" },
      PRESENT_INVALID: { classification: "EXCLUDED", reason: "suspension" },
      PRESENT_VALID: { classification: "NOT_PAYEE", reason: "none" },
    }[estate] || fail(`no matrix row for not-pool + ${estate}`));
  } else {
    fail(`unknown scheduleResult kind ${JSON.stringify(scheduleResult.kind)}`);
  }

  const anomalies = [];
  if (anomalyCode !== null) {
    if (!paths || !paths.coreRowPath || !paths.rewardPath) {
      fail("ANOMALY classification needs paths.coreRowPath and paths.rewardPath for its evidence refs");
    }
    const target = anomalyCode === "SCHEDULE_LIST_DISAGREEMENT"
      ? `${paths.rewardPath}/entitlement/eligibility`
      : `${paths.rewardPath}/entitlement/coinbaseEvidence`;
    anomalies.push({ code: anomalyCode, evidenceRefs: [paths.coreRowPath, target].sort() });
  }

  return {
    kind: "classified",
    classification,
    exclusionReason: { kind: reason },
    eligibility,
    scheduleSource: SCHEDULE_SOURCE,
    coinbaseEvidence,
    anomalies,
  };
}

module.exports = { deriveEligibility, matchOwnerVector, classifyEntitlement, SCHEDULE_SOURCE };
