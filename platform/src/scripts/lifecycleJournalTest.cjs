/**
 * Offline fixtures for reconstructLifecycle (build-order item 1). Plain `node`, no
 * devnet. Covers the seven named fixtures of the build order (single ban/revoke,
 * multiple cycles, unrevoked ban ending RANGE_END, terminal removal,
 * terminal-DURING-suspension, register-already-invalid, initial-state-from-base), the
 * fail-closed stream defects, and the CONFORMANCE CROSS-CHECK: the journal rebuilt from
 * the shipped positive vector's list-walk ledger must equal its serialized lifecycle
 * exactly (docs/schema/check_vectors.py is the executable specification).
 */
"use strict";

const fs = require("fs");
const path = require("path");
const { reconstructLifecycle } = require("./lifecycleJournal.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
// canonical (sorted-key) stringify, matching the RFC 8785 comparison the suite uses
const canon = (o) => {
  if (Array.isArray(o)) return `[${o.map(canon).join(",")}]`;
  if (o && typeof o === "object") {
    return `{${Object.keys(o).sort().map(k => `${JSON.stringify(k)}:${canon(o[k])}`).join(",")}}`;
  }
  return JSON.stringify(o);
};
const eq = (name, a, b) => {
  const ja = canon(a), jb = canon(b);
  if (ja === jb) { pass++; } else { fail++; console.error(`FAIL: ${name}\n  got      ${ja}\n  expected ${jb}`); }
};
const throws = (name, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || "")); }
};

// rows helper: states from fromHeight upward, entry presence tied to the state
const rows = (fromHeight, states) => states.map((s, i) => ({
  height: fromHeight + i,
  targetNodeState: s,
  targetNodeEntry: s === "ABSENT" ? null : "ee".repeat(91),
}));
const run = (states, initialState, fromHeight = 1000) => reconstructLifecycle(
  rows(fromHeight, states),
  { proTxHash: "ab".repeat(32), fromHeight, toHeight: fromHeight + states.length - 1, initialState });

// 1. single ban/revoke: PV -> PI (ban 1001) -> PV (revoke 1003)
let j = run(["PRESENT_VALID", "PRESENT_INVALID", "PRESENT_INVALID", "PRESENT_VALID"],
            { kind: "present", isValid: true });
eq("single ban/revoke suspensions", j.suspensions,
   [{ start: { kind: "observed", banHeight: 1001 }, endHeight: 1003, endReason: "REVOKED" }]);
eq("single ban/revoke transitions", j.transitions.map(t => t.height), [1001, 1003]);
ok("single ban/revoke no terminal", j.terminalHeight === null);
ok("observedThroughHeight is toHeight", j.observedThroughHeight === 1003);

// 2. multiple cycles: two ban/revoke rounds
j = run(["PRESENT_INVALID", "PRESENT_VALID", "PRESENT_INVALID", "PRESENT_VALID"],
        { kind: "present", isValid: true });
eq("two cycles", j.suspensions, [
  { start: { kind: "observed", banHeight: 1000 }, endHeight: 1001, endReason: "REVOKED" },
  { start: { kind: "observed", banHeight: 1002 }, endHeight: 1003, endReason: "REVOKED" },
]);

// 3. unrevoked ban ends RANGE_END at observedThroughHeight
j = run(["PRESENT_VALID", "PRESENT_INVALID", "PRESENT_INVALID"], { kind: "present", isValid: true });
eq("unrevoked ban RANGE_END", j.suspensions,
   [{ start: { kind: "observed", banHeight: 1001 }, endHeight: 1002, endReason: "RANGE_END" }]);
ok("RANGE_END carries exactly observedThroughHeight", j.suspensions[0].endHeight === j.observedThroughHeight);

// 4. terminal removal from valid: no suspension, terminal latched
j = run(["PRESENT_VALID", "ABSENT"], { kind: "present", isValid: true });
ok("terminal latched", j.terminalHeight === 1001);
eq("clean terminal has no suspensions", j.suspensions, []);

// 5. terminal DURING suspension: closes TERMINATED at T and sets terminalHeight = T
j = run(["PRESENT_INVALID", "ABSENT"], { kind: "present", isValid: true });
eq("terminal-during-suspension", j.suspensions,
   [{ start: { kind: "observed", banHeight: 1000 }, endHeight: 1001, endReason: "TERMINATED" }]);
ok("TERMINATED endHeight equals terminalHeight", j.suspensions[0].endHeight === j.terminalHeight);

// 6. register-already-invalid (range-local base PRESENT_INVALID): the pre-base sentinel
j = run(["PRESENT_INVALID", "PRESENT_VALID"], { kind: "present", isValid: false });
eq("pre-base suspension", j.suspensions,
   [{ start: { kind: "pre-base" }, endHeight: 1001, endReason: "REVOKED" }]);
// and unrevoked through the endpoint
j = run(["PRESENT_INVALID"], { kind: "present", isValid: false });
eq("pre-base RANGE_END", j.suspensions,
   [{ start: { kind: "pre-base" }, endHeight: 1000, endReason: "RANGE_END" }]);

// 7. initial-state-from-base: absent base, appearance observed, no suspension
j = run(["ABSENT", "PRESENT_VALID", "PRESENT_VALID"], { kind: "absent" });
eq("appearance transition", j.transitions,
   [{ height: 1001, from: "ABSENT", to: "PRESENT_VALID" }]);
ok("appearance has no terminal", j.terminalHeight === null && j.suspensions.length === 0);

// empty observation window (toHeight === fromHeight - 1)
j = reconstructLifecycle([], { fromHeight: 1000, toHeight: 999, initialState: { kind: "absent" } });
eq("empty window", j, { terminalHeight: null, observedThroughHeight: 999, suspensions: [], transitions: [] });

// string initial states are accepted
j = run(["PRESENT_VALID"], "PRESENT_VALID");
ok("string initial state", j.transitions.length === 0);

// ---- fail-closed stream defects ----
throws("height gap", () => reconstructLifecycle(
  [{ height: 1000, targetNodeState: "PRESENT_VALID", targetNodeEntry: "ee" },
   { height: 1002, targetNodeState: "PRESENT_VALID", targetNodeEntry: "ee" }],
  { fromHeight: 1000, toHeight: 1002, initialState: "PRESENT_VALID" }), /expected height 1001/);
throws("short stream", () => reconstructLifecycle(
  rows(1000, ["PRESENT_VALID"]),
  { fromHeight: 1000, toHeight: 1001, initialState: "PRESENT_VALID" }), /ended at height 1000/);
throws("unknown state", () => reconstructLifecycle(
  [{ height: 1000, targetNodeState: "BANNED", targetNodeEntry: "ee" }],
  { fromHeight: 1000, toHeight: 1000, initialState: "PRESENT_VALID" }), /unknown targetNodeState/);
throws("entry contradicts state", () => reconstructLifecycle(
  [{ height: 1000, targetNodeState: "ABSENT", targetNodeEntry: "ee" }],
  { fromHeight: 1000, toHeight: 1000, initialState: "PRESENT_VALID" }), /contradicts/);
throws("reappearance after terminal", () => run(
  ["PRESENT_VALID", "ABSENT", "PRESENT_VALID"], { kind: "present", isValid: true }), /after terminal removal/);
throws("bad initial state", () => run(["PRESENT_VALID"], { kind: "banned" }), /unknown initial state/);
throws("inverted window", () => reconstructLifecycle([], { fromHeight: 1000, toHeight: 998, initialState: "ABSENT" }),
       /empty coverage interval/);

// ---- CONFORMANCE CROSS-CHECK against the shipped positive vector ----
const vecPath = path.join(__dirname, "..", "..", "..", "docs", "schema", "vectors", "positive_minimal.json");
const env = JSON.parse(fs.readFileSync(vecPath, "utf8"));
const bp = env.basePackage;
const initial = bp.kind === "pre-dml" ? { kind: "absent" } : bp.nodeStateAtBase;
const rebuilt = reconstructLifecycle(env.coverage.listWalk, {
  proTxHash: env.poolProTxHash,
  fromHeight: bp.baseBlock.height + 1,
  toHeight: env.lifecycle.observedThroughHeight,
  initialState: initial,
});
eq("positive vector lifecycle reproduced exactly", rebuilt, env.lifecycle);

console.log(`lifecycleJournalTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
