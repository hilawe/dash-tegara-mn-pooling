// the conclusion gate's deterministic cases: each accepted-duplicate
// shape must refuse BEFORE any terminal read could run, and only the
// both-rejected shape passes
const { requireConcludableDuplicates, isConcludableAnswer, CONCLUDABLE_ANSWER } = require("./e2DoubleBroadcastGate.cjs");
let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error("FAIL:", name, "(no error)"); }
  catch (e) { ok(name, re.test(String(e.message))); }
};
const rejected = { broadcast: "duplicate-in-cache" };
const accepted = { broadcast: "accepted" };
throws("an accepted immediate duplicate refuses the conclusion",
  () => requireConcludableDuplicates(accepted, rejected), /immediate duplicate submission was transport-accepted/);
throws("an accepted post-execution duplicate refuses the conclusion",
  () => requireConcludableDuplicates(rejected, accepted), /post-execution duplicate submission was transport-accepted/);
throws("both accepted refuses the conclusion",
  () => requireConcludableDuplicates(accepted, accepted), /transport-accepted/);
throws("a missing transport answer refuses the conclusion",
  () => requireConcludableDuplicates(undefined, rejected), /transport answer is missing/);
throws("an unexpected transport answer in the immediate position refuses",
  () => requireConcludableDuplicates({ broadcast: "refused" }, rejected), /not the cache-rejected shape/);
throws("an unexpected transport answer in the post-execution position refuses",
  () => requireConcludableDuplicates(rejected, { broadcast: "timeout" }), /not the cache-rejected shape/);
try { requireConcludableDuplicates(rejected, rejected); ok("both cache-rejected duplicates conclude", true); }
catch (e) { ok("both cache-rejected duplicates conclude", false); }
// the ACCEPTANCE SET is exactly one string, probed with variants
// DERIVED from the canonical constant itself (case, whitespace,
// affixes), so a denylist over anticipated names cannot reproduce it
{
  const c = CONCLUDABLE_ANSWER;
  const derived = [c.toUpperCase(), ` ${c}`, `${c} `, `${c}x`, `x${c}`,
    c.slice(0, -1), c.replace("-", "_"), "", "accepted", "refused", "timeout", "queued"];
  ok("the predicate accepts exactly the canonical answer",
    isConcludableAnswer({ broadcast: c }) === true
    && derived.every((v) => isConcludableAnswer({ broadcast: v }) === false)
    && isConcludableAnswer(undefined) === false
    && isConcludableAnswer({ broadcast: 7 }) === false);
  // the gate CONSUMES the predicate, so a variant refuses end to end
  throws("a derived variant refuses through the gate itself",
    () => requireConcludableDuplicates({ broadcast: `${c}x` }, { broadcast: c }),
    /not the cache-rejected shape/);
  // THE SOURCE PIN (the unit screen's checking): no finite probe set can
  // exclude an arbitrary unanticipated acceptance (an or-branch for a
  // fresh string passes every listed and derived probe), so the
  // one-line predicate's SOURCE is pinned exactly; widening the
  // acceptance set requires consciously updating this pin, which is
  // the visible act the probes cannot force
  ok("the predicate's source is exactly the pinned one-string equality",
    String(isConcludableAnswer)
      === '(r) => !!r && typeof r.broadcast === "string" && r.broadcast === CONCLUDABLE_ANSWER');
}
console.log(`e2DoubleBroadcastGateTest: ${passed} passed, ${failed} failed`);
process.exitCode = failed ? 1 : 0;
