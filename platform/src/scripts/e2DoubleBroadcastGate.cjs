/**
 * The D6 double-broadcast run's CONCLUSION GATE, pure and offline so
 * its refusal behavior is testable deterministically (the unit
 * screen's the live run never produces transport-accepted
 * duplicates, so an in-runner branch had no gate). The rule: a
 * TRANSPORT-ACCEPTED duplicate refuses the run's conclusion outright,
 * because no cited rule bounds a pending transition's lifetime, so no
 * later observation establishes that a pending duplicate produces no
 * later effect. A concluding run's duplicates were cache-rejected by
 * construction.
 */
// the POSITIVE predicate, exposed so the acceptance set is testable as
// a set (the unit screen's enumerated refusal fixtures admit
// an enumerated denylist; the predicate's acceptance is exactly one
// string and the test derives its probes from that string)
const CONCLUDABLE_ANSWER = "duplicate-in-cache";
const isConcludableAnswer = (r) => !!r && typeof r.broadcast === "string" && r.broadcast === CONCLUDABLE_ANSWER;

const requireConcludableDuplicates = (immediate, postExecution) => {
  for (const [what, r] of [["immediate", immediate], ["post-execution", postExecution]]) {
    if (!r || typeof r.broadcast !== "string") {
      throw new Error(`the ${what} duplicate's transport answer is missing; nothing to conclude from`);
    }
    if (r.broadcast === "accepted") {
      throw new Error(`the ${what} duplicate submission was transport-accepted; this run cannot bound a pending transition's lifetime and refuses to conclude (rerun; the cache-rejected shape is the concluding one)`);
    }
    // an ALLOWLIST, not a deny of "accepted" (the unit screen's round
    // 6: any unrecognized answer concluding would silently weaken the
    // rule the moment a transport shape changed); only the
    // cache-rejected answer concludes
    if (!isConcludableAnswer(r)) {
      throw new Error(`the ${what} duplicate's transport answer ${JSON.stringify(r.broadcast)} is not the cache-rejected shape; only cache-rejected duplicates conclude, refusing`);
    }
  }
};
module.exports = { requireConcludableDuplicates, isConcludableAnswer, CONCLUDABLE_ANSWER };
