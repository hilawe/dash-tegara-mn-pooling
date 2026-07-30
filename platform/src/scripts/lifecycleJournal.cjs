/**
 * reconstructLifecycle - build-order item 1 of the REVIEW-COMPLETE design
 * (docs/LIFECYCLE_JOURNAL_AND_SEAM_DESIGN.md revision 27, "Piece 1"; the executable
 * specification is docs/schema/check_vectors.py, whose journal reconstruction this
 * module must agree with byte-for-byte on the serialized lifecycle form).
 *
 * ONE strict per-block forward pass over the shared list-state stream produces the
 * lifecycle journal: the M6 closure shape
 *   { terminalHeight | null, observedThroughHeight,
 *     suspensions: [{ start, endHeight, endReason }], transitions }
 * where a suspension start is the TAGGED form ({ kind: "observed", banHeight } or
 * { kind: "pre-base" }), endHeight is NEVER null (REVOKED carries R, TERMINATED carries
 * the removal height T equal to terminalHeight, RANGE_END carries exactly
 * observedThroughHeight), and terminalHeight null means NOT OBSERVED THROUGH
 * observedThroughHeight, never "never terminates".
 *
 * FAIL-CLOSED: every stream defect throws (height gap or duplicate, unknown state,
 * entry/state contradiction, any state change after the terminal removal, a bad initial
 * state). The journal is REPORTING and terminal sale-suppression context; it is never a
 * per-reward finality gate (the only finality gate is H <= validated best ChainLock,
 * enforced by the entitlement side, not here).
 *
 * The stream rows are the list-walk ledger rows of the audit envelope: at minimum
 * { height, targetNodeState, targetNodeEntry }, where targetNodeState is one of
 * ABSENT | PRESENT_VALID | PRESENT_INVALID and targetNodeEntry is null exactly when the
 * state is ABSENT (the envelope's own consistency rule). Extra row fields (blockHash,
 * protxDiffRaw, cbTxRaw, listRoot, ...) are ignored here; authenticating them is the
 * walk producer's and the runtime verifiers' duty.
 */
"use strict";

const STATES = new Set(["ABSENT", "PRESENT_VALID", "PRESENT_INVALID"]);

function fail(msg) {
  throw new Error(`lifecycle: ${msg}`);
}

/**
 * Normalize the initial state at the base height. Accepts the envelope's tagged
 * nodeStateAtBase form ({ kind: "present", isValid } | { kind: "absent" }) or one of
 * the three state strings directly. A pre-DML base seeds ABSENT (the walk starts before
 * any deterministic entry can exist); the RANGE_LOCAL absent base is
 * ABSENT-AT-BASE-UNKNOWN for CLAIM purposes, but its journal seed is the same ABSENT
 * (the UNKNOWN distinction lives in eligibility typing, not the journal shape).
 */
function normalizeInitialState(initialState) {
  if (typeof initialState === "string") {
    if (!STATES.has(initialState)) fail(`unknown initial state ${JSON.stringify(initialState)}`);
    return initialState;
  }
  if (initialState && typeof initialState === "object") {
    if (initialState.kind === "present") {
      if (typeof initialState.isValid !== "boolean") fail("present initial state needs boolean isValid");
      return initialState.isValid ? "PRESENT_VALID" : "PRESENT_INVALID";
    }
    if (initialState.kind === "absent") return "ABSENT";
  }
  fail(`unknown initial state ${JSON.stringify(initialState)}`);
}

/**
 * reconstructLifecycle(stream, { proTxHash, fromHeight, toHeight, initialState })
 *
 * stream     : iterable of list-walk rows for heights fromHeight..toHeight inclusive,
 *              strictly consecutive (per-block; a gap fails closed). May be empty only
 *              when toHeight === fromHeight - 1 (an observation window that ends at the
 *              base itself).
 * fromHeight : baseHeight + 1 (the first walked block).
 * toHeight   : observedThroughHeight (the walk runs THROUGH it; the caller owns the
 *              coverage-interval equation obs >= coreAuditRange.toHeight and
 *              obs <= validatedChainLock.height).
 * initialState: the authenticated state AT the base (see normalizeInitialState).
 * proTxHash  : context only (the stream's target entries are opaque committed bytes;
 *              binding them to the proTxHash is the diff-verifying producer's duty).
 */
function reconstructLifecycle(stream, opts) {
  if (!opts || typeof opts !== "object") fail("missing options");
  const { fromHeight, toHeight } = opts;
  if (!Number.isSafeInteger(fromHeight) || fromHeight < 0) fail("fromHeight must be a safe non-negative integer");
  if (!Number.isSafeInteger(toHeight)) fail("toHeight must be a safe integer");
  if (toHeight < fromHeight - 1) fail("empty coverage interval (toHeight < fromHeight - 1)");

  const st0 = normalizeInitialState(opts.initialState);

  const transitions = [];
  const suspensions = [];
  let terminal = null;
  let openBan = st0 === "PRESENT_INVALID" ? { kind: "pre-base" } : null;
  let prev = st0;
  let expected = fromHeight;

  for (const row of stream) {
    if (!row || typeof row !== "object") fail("stream row is not an object");
    if (row.height !== expected) {
      fail(`stream not strictly per-block: expected height ${expected}, got ${JSON.stringify(row.height)}`);
    }
    if (expected > toHeight) fail(`stream row beyond toHeight ${toHeight}`);
    const state = row.targetNodeState;
    if (!STATES.has(state)) fail(`unknown targetNodeState ${JSON.stringify(state)} at height ${row.height}`);
    if (!("targetNodeEntry" in row)) fail(`row ${row.height} lacks targetNodeEntry`);
    if ((row.targetNodeEntry === null) !== (state === "ABSENT")) {
      fail(`targetNodeEntry presence contradicts targetNodeState at height ${row.height}`);
    }

    if (state !== prev) {
      if (terminal !== null) fail(`state change at height ${row.height} after terminal removal at ${terminal}`);
      transitions.push({ height: row.height, from: prev, to: state });
      if (state === "PRESENT_INVALID") {
        openBan = { kind: "observed", banHeight: row.height };
      } else if (prev === "PRESENT_INVALID" && state === "PRESENT_VALID") {
        suspensions.push({ start: openBan, endHeight: row.height, endReason: "REVOKED" });
        openBan = null;
      }
      if (state === "ABSENT") {
        terminal = row.height;
        if (openBan !== null) {
          // removed WHILE suspended: the suspension record does not vanish into the
          // terminal latch (M6); excluded by suspension through T, by terminal from T+1
          suspensions.push({ start: openBan, endHeight: row.height, endReason: "TERMINATED" });
          openBan = null;
        }
      }
      prev = state;
    }
    expected += 1;
  }
  if (expected !== toHeight + 1) {
    fail(`stream ended at height ${expected - 1}, expected coverage through ${toHeight}`);
  }
  if (openBan !== null) {
    // still suspended at the observation endpoint: the exclusion is open-ended, the
    // RECORD is bounded (RANGE_END carries exactly observedThroughHeight)
    suspensions.push({ start: openBan, endHeight: toHeight, endReason: "RANGE_END" });
    openBan = null;
  }

  return {
    terminalHeight: terminal,
    observedThroughHeight: toHeight,
    suspensions,
    transitions,
  };
}

module.exports = { reconstructLifecycle, normalizeInitialState };
