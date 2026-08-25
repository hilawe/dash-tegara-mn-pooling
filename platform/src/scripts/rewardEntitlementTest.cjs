/**
 * Offline fixtures for the finality-fixed entitlement classification (build-order item
 * 2). Plain `node`, no devnet. Covers every row of the precedence table, the typed
 * five-state eligibility derivation (incl. the three ABSENT meanings), owner-first
 * consuming attribution with the complete unexplained remainder, and the CONFORMANCE
 * CROSS-CHECK: every reward record of the shipped positive vector is re-derived from its
 * own core row + walk + journal and must equal the serialized entitlement exactly.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const { reconstructLifecycle } = require("./lifecycleJournal.cjs");
const { deriveEligibility, matchOwnerVector, classifyEntitlement } = require("./rewardEntitlement.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const canon = (o) => {
  if (Array.isArray(o)) return `[${o.map(canon).join(",")}]`;
  if (o && typeof o === "object") return `{${Object.keys(o).sort().map(k => `${JSON.stringify(k)}:${canon(o[k])}`).join(",")}}`;
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

const ROOT = "cc".repeat(32);
const OUT = (script, amountDuffs, outputIndex) => ({ script, amountDuffs, outputIndex });
const ELIG = (state) => ({ state, listHeight: 999, listRoot: ROOT });
const POOL = (...requiredOutputs) => ({ kind: "pool-scheduled", requiredOutputs });
const CB = (...outputs) => ({ kind: "available", outputs });
const PATHS = { coreRowPath: "/coverage/coreLedger/0", rewardPath: "/rewards/0" };

// ---- the finality gate: the ONLY gate is H <= chainlock ----
eq("H above the chainlock is unfinalized", classifyEntitlement({
  height: 1001, chainlockHeight: 1000, eligibility: ELIG("PRESENT_VALID"),
  scheduleResult: { kind: "not-pool" }, coinbase: CB(),
}), { kind: "unfinalized" });
// journal boundaries above the chainlock do NOT gate (they are reporting data): a
// classified result at H <= cl stands regardless of any later transition
const lateJournal = classifyEntitlement({
  height: 1000, chainlockHeight: 1000, eligibility: ELIG("PRESENT_VALID"),
  scheduleResult: { kind: "not-pool" }, coinbase: CB(),
});
ok("no per-boundary gate: classified at H <= chainlock", lateJournal.kind === "classified");

// ---- missing trusted reads ----
eq("both reads missing", classifyEntitlement({
  height: 1000, chainlockHeight: 1000, eligibility: ELIG("PRESENT_VALID"),
  scheduleResult: { kind: "unavailable" }, coinbase: { kind: "unavailable" },
}), { kind: "unknown", missingInputs: ["coinbase", "schedule"] });

// ---- ABSENT_UNKNOWN fails closed ----
eq("ABSENT_UNKNOWN is unknown, never terminal", classifyEntitlement({
  height: 1000, chainlockHeight: 1000, eligibility: ELIG("ABSENT_UNKNOWN"),
  scheduleResult: { kind: "not-pool" }, coinbase: CB(),
}), { kind: "unknown", missingInputs: ["eligibility-base"] });

// ---- the classified rows ----
const o1 = OUT("76a914" + "11".repeat(20) + "88ac", "60000000", 0);
const o2 = OUT("76a914" + "55".repeat(20) + "88ac", "40000000", 1);
const opOut = OUT("76a914" + "99".repeat(20) + "88ac", "25000000", 2);

let ent = classifyEntitlement({
  height: 1000, chainlockHeight: 1000, eligibility: ELIG("PRESENT_VALID"),
  scheduleResult: POOL({ script: o1.script, amountDuffs: o1.amountDuffs },
                       { script: o2.script, amountDuffs: o2.amountDuffs }),
  coinbase: CB(o1, o2, opOut),
});
ok("owner vector fully matched is OWED", ent.classification === "OWED");
eq("matched in ascending index", ent.coinbaseEvidence.matchedOutputs, [o1, o2]);
eq("complete remainder: the operator output lands in unexplained, any script",
   ent.coinbaseEvidence.unexplainedOutputs, [opOut]);

// same-script same-amount collision: owner-first CONSUMING attribution (a soundness-review finding)
const twin = OUT(o1.script, o1.amountDuffs, 3);
ent = classifyEntitlement({
  height: 1000, chainlockHeight: 1000, eligibility: ELIG("PRESENT_VALID"),
  scheduleResult: POOL({ script: o1.script, amountDuffs: o1.amountDuffs }),
  coinbase: CB(o1, twin),
});
eq("consuming match takes the LOWEST index once", ent.coinbaseEvidence.matchedOutputs, [o1]);
eq("the twin is unexplained, not double-counted", ent.coinbaseEvidence.unexplainedOutputs, [twin]);

// underpayment: scheduled but not fully matched -> ANOMALY COINBASE_MISMATCH
ent = classifyEntitlement({
  height: 1000, chainlockHeight: 1000, eligibility: ELIG("PRESENT_VALID"),
  scheduleResult: POOL({ script: o1.script, amountDuffs: o1.amountDuffs },
                       { script: o2.script, amountDuffs: o2.amountDuffs }),
  coinbase: CB(o1), paths: PATHS,
});
ok("underpayment is ANOMALY", ent.classification === "ANOMALY");
eq("COINBASE_MISMATCH cites both sides", ent.anomalies, [{
  code: "COINBASE_MISMATCH",
  evidenceRefs: ["/coverage/coreLedger/0", "/rewards/0/entitlement/coinbaseEvidence"],
}]);

// scheduled while the list excludes -> ANOMALY SCHEDULE_LIST_DISAGREEMENT
ent = classifyEntitlement({
  height: 1000, chainlockHeight: 1000, eligibility: ELIG("PRESENT_INVALID"),
  scheduleResult: POOL({ script: o1.script, amountDuffs: o1.amountDuffs }),
  coinbase: CB(o1), paths: PATHS,
});
eq("schedule/list disagreement anomaly", ent.anomalies, [{
  code: "SCHEDULE_LIST_DISAGREEMENT",
  evidenceRefs: ["/coverage/coreLedger/0", "/rewards/0/entitlement/eligibility"],
}]);
throws("ANOMALY without paths fails closed", () => classifyEntitlement({
  height: 1000, chainlockHeight: 1000, eligibility: ELIG("PRESENT_INVALID"),
  scheduleResult: POOL({ script: o1.script, amountDuffs: o1.amountDuffs }), coinbase: CB(o1),
}), /needs paths/);

// zero-payout: a scheduled empty owner vector is OWED with empty arrays (MF-2 model)
ent = classifyEntitlement({
  height: 1000, chainlockHeight: 1000, eligibility: ELIG("PRESENT_VALID"),
  scheduleResult: POOL(), coinbase: CB(),
});
ok("scheduled zero owner vector is OWED", ent.classification === "OWED");

// the not-pool exclusion rows
for (const [estate, cls, reason] of [
  ["PRESENT_VALID", "NOT_PAYEE", "none"],
  ["PRESENT_INVALID", "EXCLUDED", "suspension"],
  ["ABSENT_TERMINAL", "EXCLUDED", "terminal"],
  ["ABSENT_PRE_APPEARANCE", "EXCLUDED", "pre-appearance"],
]) {
  const e = classifyEntitlement({
    height: 1000, chainlockHeight: 1000, eligibility: ELIG(estate),
    scheduleResult: { kind: "not-pool" }, coinbase: CB(),
  });
  ok(`not-pool ${estate} -> ${cls}/${reason}`,
     e.classification === cls && e.exclusionReason.kind === reason);
  eq(`not-pool ${estate} arrays empty`, e.coinbaseEvidence,
     { requiredOutputs: [], matchedOutputs: [], unexplainedOutputs: [] });
}

// ---- typed eligibility derivation ----
const J = (terminalHeight, transitions = []) => ({ terminalHeight, transitions, suspensions: [], observedThroughHeight: 2000 });
ok("present passes through", deriveEligibility({
  stateAtHMinus1: "PRESENT_INVALID", listRoot: ROOT, hMinus1: 999, journal: J(null), base: { kind: "rooted", baseMode: "RANGE_LOCAL" },
}).state === "PRESENT_INVALID");
ok("absent after terminal is ABSENT_TERMINAL", deriveEligibility({
  stateAtHMinus1: "ABSENT", listRoot: ROOT, hMinus1: 999, journal: J(990), base: { kind: "rooted", baseMode: "RANGE_LOCAL" },
}).state === "ABSENT_TERMINAL");
ok("absent before P under FIRST_APPEARANCE is pre-appearance", deriveEligibility({
  stateAtHMinus1: "ABSENT", listRoot: ROOT, hMinus1: 999, journal: J(null), base: { kind: "rooted", baseMode: "FIRST_APPEARANCE", pHeight: 1005 },
}).state === "ABSENT_PRE_APPEARANCE");
ok("absent with no prior appearance under pre-DML is pre-appearance", deriveEligibility({
  stateAtHMinus1: "ABSENT", listRoot: ROOT, hMinus1: 999, journal: J(null, []), base: { kind: "pre-dml" },
}).state === "ABSENT_PRE_APPEARANCE");
ok("absent under a range-local base is ABSENT_UNKNOWN (fail-closed)", deriveEligibility({
  stateAtHMinus1: "ABSENT", listRoot: ROOT, hMinus1: 999, journal: J(null), base: { kind: "rooted", baseMode: "RANGE_LOCAL" },
}).state === "ABSENT_UNKNOWN");

// duplicate actual outputIndex FAILS CLOSED (build review, MAJOR: one matched output
// used to erase a DIFFERENT output from the remainder while the record read OWED)
throws("duplicate actual outputIndex is refused", () => matchOwnerVector(
  [{ script: "aa", amountDuffs: "5" }],
  [OUT("aa", "5", 0), OUT("bb", "9", 0)]), /duplicate actual outputIndex/);
throws("classifyEntitlement inherits the duplicate-index guard", () => classifyEntitlement({
  height: 1000, chainlockHeight: 1000, eligibility: ELIG("PRESENT_VALID"),
  scheduleResult: POOL({ script: "aa", amountDuffs: "5" }),
  coinbase: CB(OUT("aa", "5", 0), OUT("bb", "9", 0)),
}), /duplicate actual outputIndex/);
// the message moved when the per-output rules became shared validators (a string index is
// now caught by the output-shape check before the duplicate-index pass reaches it); the
// behaviour under test is unchanged, which is that it is refused rather than coerced
throws("a non-integer outputIndex is refused", () => matchOwnerVector(
  [], [{ script: "aa", amountDuffs: "5", outputIndex: "0" }]), /malformed outputIndex/);

// matchOwnerVector direct: multiset repetition consumes distinct indexes
const rep = matchOwnerVector(
  [{ script: "aa", amountDuffs: "5" }, { script: "aa", amountDuffs: "5" }],
  [OUT("aa", "5", 4), OUT("aa", "5", 1), OUT("bb", "7", 2)]);
eq("repeated expectation consumes two distinct indexes ascending",
   rep.matchedOutputs.map(o => o.outputIndex), [1, 4]);
eq("remainder complete", rep.unexplainedOutputs.map(o => o.outputIndex), [2]);

// ---- CONFORMANCE CROSS-CHECK: every reward record of the shipped positive vector ----
const vecPath = path.join(__dirname, "..", "..", "..", "docs", "schema", "vectors", "positive_minimal.json");
const env = JSON.parse(fs.readFileSync(vecPath, "utf8"));
const bp = env.basePackage;
const baseH = bp.baseBlock.height;
const journal = reconstructLifecycle(env.coverage.listWalk, {
  proTxHash: env.poolProTxHash, fromHeight: baseH + 1,
  toHeight: env.lifecycle.observedThroughHeight,
  initialState: bp.kind === "pre-dml" ? { kind: "absent" } : bp.nodeStateAtBase,
});
const st0 = bp.kind === "pre-dml" ? "ABSENT"
  : bp.nodeStateAtBase.kind === "present"
    ? (bp.nodeStateAtBase.isValid ? "PRESENT_VALID" : "PRESENT_INVALID") : "ABSENT";
const walkAt = (h) => h === baseH
  ? { state: st0, root: bp.kind === "rooted" ? bp.listRoot : null }
  : { state: env.coverage.listWalk[h - (baseH + 1)].targetNodeState,
      root: env.coverage.listWalk[h - (baseH + 1)].listRoot };
env.rewards.forEach((rec, i) => {
  const H = rec.rewardCoreHeight;
  const row = env.coverage.coreLedger[i];
  const w = walkAt(H - 1);
  const eligibility = deriveEligibility({
    stateAtHMinus1: w.state, listRoot: w.root, hMinus1: H - 1, journal,
    base: { kind: bp.kind, baseMode: bp.baseMode, pHeight: bp.firstAppearance && bp.firstAppearance.pHeight },
  });
  const rebuilt = classifyEntitlement({
    height: H, chainlockHeight: env.validatedChainLock.height,
    eligibility, scheduleResult: row.scheduleResult,
    coinbase: row.coinbase.kind === "available"
      ? { kind: "available", outputs: row.coinbase.outputs } : { kind: "unavailable" },
    paths: { coreRowPath: `/coverage/coreLedger/${i}`, rewardPath: `/rewards/${i}` },
  });
  eq(`positive vector reward[${i}] (H=${H}) entitlement reproduced exactly`, rebuilt, rec.entitlement);
});

// ---------------------------------------------------------------------------
// P6 of the property review (2026-07-25): the input validator let two shapes through.
// ---------------------------------------------------------------------------

// (a) ELIGIBILITY IS REQUIRED FOR EVERY ROW. It used to be optional because the
// higher-precedence rows do not consult it, so H > chainlock with NO eligibility returned
// {kind:"unfinalized"}. The answer was right, which is why the gap was invisible: a caller
// whose derivation returned nothing got a decision instead of an error.
throws("absent eligibility is refused even where a higher row would fire",
  () => classifyEntitlement({
    height: 1001, chainlockHeight: 1000, eligibility: undefined,
    scheduleResult: { kind: "not-pool" }, coinbase: CB(),
  }), /eligibility must be the typed object/);
throws("null eligibility is refused",
  () => classifyEntitlement({
    height: 1000, chainlockHeight: 1000, eligibility: null,
    scheduleResult: { kind: "unavailable" }, coinbase: { kind: "unavailable" },
  }), /eligibility must be the typed object/);

// (b) UNDECLARED FIELDS. The normative schema sets additionalProperties:false on every one
// of these objects, so a record carrying them is outside the format; this primitive runs
// long before the gate and now says so itself. Reproduced before the fold: all three
// inputs carrying a bogus field returned NOT_PAYEE.
throws("an undeclared field on eligibility is refused",
  () => classifyEntitlement({
    height: 10, chainlockHeight: 100, eligibility: { ...ELIG("PRESENT_VALID"), bogus: 1 },
    scheduleResult: { kind: "not-pool" }, coinbase: CB(),
  }), /eligibility carries the undeclared field "bogus"/);
throws("an undeclared field on scheduleResult is refused",
  () => classifyEntitlement({
    height: 10, chainlockHeight: 100, eligibility: ELIG("PRESENT_VALID"),
    scheduleResult: { kind: "not-pool", bogus: 1 }, coinbase: CB(),
  }), /scheduleResult carries the undeclared field "bogus"/);
throws("an undeclared field on coinbase is refused",
  () => classifyEntitlement({
    height: 10, chainlockHeight: 100, eligibility: ELIG("PRESENT_VALID"),
    scheduleResult: { kind: "not-pool" }, coinbase: { ...CB(), bogus: 1 },
  }), /coinbase carries the undeclared field "bogus"/);
throws("an undeclared field on an expected output is refused",
  () => classifyEntitlement({
    height: 10, chainlockHeight: 100, eligibility: ELIG("PRESENT_VALID"),
    scheduleResult: POOL({ script: "76a914", amountDuffs: "1", bogus: 1 }), coinbase: CB(),
  }), /an expected output carries the undeclared field "bogus"/);
throws("an undeclared field on an actual output is refused",
  () => classifyEntitlement({
    height: 10, chainlockHeight: 100, eligibility: ELIG("PRESENT_VALID"),
    scheduleResult: { kind: "not-pool" },
    coinbase: CB({ script: "76a914", amountDuffs: "1", outputIndex: 0, bogus: 1 }),
  }), /an actual output carries the undeclared field "bogus"/);
// the declared shapes still pass, so the closed key sets match the format rather than
// merely being strict
ok("the declared coinbase shape with txRaw and inclusionProof is accepted",
   classifyEntitlement({
     height: 10, chainlockHeight: 100, eligibility: ELIG("PRESENT_VALID"),
     scheduleResult: { kind: "not-pool" },
     coinbase: { kind: "available", outputs: [], txRaw: "00", inclusionProof: "00" },
   }).kind === "classified");

// A NUMBER IS NOT A DECIMAL STRING (confirmation round 2, MAJOR). The pattern check
// coerced, so a numeric 5 tested as "5" and a non-conforming output reached OWED. The
// production gate refused the envelope afterwards, but this exported classifier returned a
// plausible answer, which is the thing being closed.
throws("a numeric amountDuffs on an expected output is refused",
  () => classifyEntitlement({
    height: 10, chainlockHeight: 100, eligibility: ELIG("PRESENT_VALID"),
    scheduleResult: POOL({ script: "76a914", amountDuffs: 5 }), coinbase: CB(),
  }), /decimal string/);
throws("a numeric amountDuffs on an actual output is refused",
  () => classifyEntitlement({
    height: 10, chainlockHeight: 100, eligibility: ELIG("PRESENT_VALID"),
    scheduleResult: { kind: "not-pool" },
    coinbase: CB({ script: "76a914", amountDuffs: 5, outputIndex: 0 }),
  }), /decimal string/);
ok("the same values as decimal STRINGS still classify",
   classifyEntitlement({
     height: 10, chainlockHeight: 100, eligibility: ELIG("PRESENT_VALID"),
     scheduleResult: POOL({ script: "76a914", amountDuffs: "5" }),
     coinbase: CB({ script: "76a914", amountDuffs: "5", outputIndex: 0 }),
   }).classification === "OWED");

// matchOwnerVector IS SEPARATELY EXPORTED and used to validate nothing (repository-access
// round, MAJOR): it matched a numeric expected 5 against a numeric actual 5 and returned an
// empty unexplained remainder, so the classifier's decimal-string guard protected only the
// classifier. The per-output rules are now shared by both entry points.
throws("matchOwnerVector refuses a numeric expected amount",
  () => matchOwnerVector([{ script: "76a914", amountDuffs: 5 }],
                         [{ script: "76a914", amountDuffs: "5", outputIndex: 0 }]),
  /decimal string/);
throws("matchOwnerVector refuses a numeric actual amount",
  () => matchOwnerVector([{ script: "76a914", amountDuffs: "5" }],
                         [{ script: "76a914", amountDuffs: 5, outputIndex: 0 }]),
  /decimal string/);
throws("matchOwnerVector refuses an undeclared field on an output",
  () => matchOwnerVector([], [{ script: "76a914", amountDuffs: "5", outputIndex: 0, bogus: 1 }]),
  /undeclared field "bogus"/);
throws("matchOwnerVector refuses a non-array argument",
  () => matchOwnerVector(null, []), /requiredOutputs must be an array/);
ok("matchOwnerVector still matches well-formed decimal-string outputs", (() => {
  const r = matchOwnerVector([{ script: "76a914", amountDuffs: "5" }],
                             [{ script: "76a914", amountDuffs: "5", outputIndex: 0 }]);
  return r.matchedOutputs.length === 1 && r.unexplainedOutputs.length === 0;
})());

// round 4, MAJOR: a string hMinus1 flowed into the returned listHeight and every comparison,
// so deriveEligibility returned a plausible typed state for malformed input
throws("deriveEligibility refuses a non-integer hMinus1",
  () => deriveEligibility({ stateAtHMinus1: "ABSENT", listRoot: null, hMinus1: "abc",
                            journal: J(null), base: { kind: "rooted", baseMode: "RANGE_LOCAL" } }),
  /hMinus1 must be a safe non-negative integer/);
throws("deriveEligibility refuses a negative hMinus1",
  () => deriveEligibility({ stateAtHMinus1: "ABSENT", listRoot: null, hMinus1: -1,
                            journal: J(null), base: { kind: "rooted", baseMode: "RANGE_LOCAL" } }),
  /hMinus1 must be a safe non-negative integer/);

console.log(`rewardEntitlementTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
