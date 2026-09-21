/**
 * The discovery upgrade's gates AND its production composition, both
 * offline-testable (the D6 conclusion-gate precedent). The pure pieces
 * are entry validation, the interval-answer check, the walk's stepping
 * rule and the coverage rule; the composition (createFetchRange below)
 * is the exact decision chain between the wire and the proved flag,
 * with its one wire call injected, so an offline test can drive it
 * with a fake route and assert that truncated reads, out-of-interval
 * answers, unreached coverage and failures can never produce
 * proved:true.
 *
 * WHAT THE WALK ESTABLISHES, and the route that lets it. The rule is
 * COVERAGE OF AN INTERVAL, not a count of records. The walk requests
 * explicit inclusive intervals from epoch zero up to the finality
 * bound, advances its coverage by the interval an ACCEPTED answer
 * covered, and proves only when that coverage reaches the bound. An
 * epoch inside a covered interval with no returned record is ABSENT BY
 * EVIDENCE, a legitimate outcome that carries no penalty; an epoch
 * outside the covered interval is UNEXAMINED and is never treated as
 * an absence.
 *
 * WHAT A PROVED ANSWER MEANS, at its real width. It means every interval from zero through the
 * claimed finality bound was examined through answers signed at or above the run's reference
 * height on the run's pinned chain, and that the epochs it holds are the ones those answers
 * carried. IT DOES NOT MEAN THE BOUND IS THE TRUE CURRENT EPOCH. That value is read from a
 * metadata field no signature covers. One read above the bound catches an understated claim whose
 * omission falls within one interval width, and an omission further up is not detectable here at
 * all. A caller that needs coverage up to a particular epoch must say so and be refused when the
 * claimed bound falls below it, which is what the forward composition does.
 *
 * WHY THE ROUTE CHANGED, and it is the repair (a soundness-review finding). The
 * earlier walk used the count-based epochs route, whose limit is an
 * element budget over an unbounded range, so a caller cannot state
 * which interval a page examined. On that route an answer shorter than
 * the requested count is the ORDINARY case under a sparse history and
 * establishes neither completeness nor exhaustion, yet the old stepping
 * rule read it as the end of the walk, and the old completeness rule
 * demanded every integer below the current epoch. Both were measured
 * wrong against the bench on 2026-09-20: the history is genuinely
 * sparse (one run had no epoch 398, none from 403 through 407, and an
 * empty span from 1065 through 1631), and the count route returned 19
 * of 20 at one start while the next start returned 18 more. The
 * interval route is additive, agrees with single-epoch reads, and
 * REFUSES a width above its cap rather than truncating, so coverage is
 * expressible there. The evidence is
 * docs/review/controls/2026-09-20-epoch-route-probe.log and the
 * contract is tegara/docs/EPOCH_DISCOVERY_COMPLETENESS_CONTRACT.md.
 */

// THE ROUTE'S OWN CAP, measured rather than assumed, and the measurement
// is described at ITS OWN WIDTH. From start zero the log samples widths
// 10 through 100 and records each served; widths 101, 105, 110, 120,
// 130, 150, 170, 190 and 200 from start zero each failed the proof
// check outright. Width 100 was additionally served at starts 50, 100
// and 200, and width 50 at start 100. It is NOT the case that every
// width was tried at every start. What the log supports is that the
// route serves the sampled widths through 100 and refuses the sampled
// wider ones, failing rather than truncating. The walk stays well
// inside the cap, and a refusal above it is a failed read like any
// other, never a short answer.
const MAX_INTERVAL_WIDTH = 100;
const INTERVAL_STEP = 50;

const validateEpochEntry = (e) => {
  if (!e || !Number.isSafeInteger(e.number) || e.number < 0) {
    throw new Error(`the epoch enumeration served a malformed epoch number (${e && JSON.stringify(e.number)}); refusing`);
  }
  return e.number;
};

// THE INTERVAL BINDING, pure: a verified answer is evidence about the
// interval it was asked for, so an answer carrying a number outside
// that interval, or a repeated number, or one out of ascending order,
// is not evidence about anything and refuses rather than being
// filtered. Filtering would convert a route defect into a silent
// narrowing of the universe.
const validateIntervalAnswer = (numbers, start, end) => {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start) {
    throw new Error(`the walk asked for the interval ${JSON.stringify(start)}..${JSON.stringify(end)}, which is not a forward interval of nonnegative integers; refusing`);
  }
  if (!Array.isArray(numbers)) {
    throw new Error(`the epoch route answered ${JSON.stringify(numbers)} for ${start}..${end}, not an array of entries; refusing`);
  }
  let previous = null;
  for (const n of numbers) {
    if (!Number.isSafeInteger(n) || n < start || n > end) {
      throw new Error(`the epoch route answered epoch ${JSON.stringify(n)} outside the requested interval ${start}..${end}; refusing an answer that is not evidence about what was asked`);
    }
    if (previous !== null && n <= previous) {
      throw new Error(`the epoch route answered ${n} after ${previous} in the interval ${start}..${end}; a repeated or out-of-order number is not a servable enumeration, refusing`);
    }
    previous = n;
  }
  return numbers;
};

// THE FRESHNESS RULE, pure, AND IT COMPARES SIGNED HEIGHTS (a soundness-review finding). The first version of this
// rule compared the response metadata's EPOCH, which is not covered by the Tenderdash signing
// digest: that digest is built over the application version, the core-chain-locked height, the
// time, the application root, the block height and the chain identity, and over nothing else. An
// otherwise valid older answer can therefore keep its root, its signed height and its signature
// while its metadata claims a later epoch, and the epoch comparison passed it. An independent
// control reproduced exactly that, replacing epoch 179 with 189 over an unchanged signing digest.
//
// THE HEIGHT IS INSIDE THAT DIGEST, so an answer cannot claim a newer height without breaking its
// own signature. The run's reference height comes from the same proof-verified read that supplies
// the finality reference, and every accepted interval answer must be at least as recent as it.
const signedHeightOf = (metadata, start, end) => {
  if (!metadata || typeof metadata !== "object") {
    throw new Error(`the epoch route answered ${start}..${end} with no response metadata, so which state it was taken from is unknown; refusing`);
  }
  const raw = metadata.height;
  let h = null;
  if (typeof raw === "bigint" && raw >= 0n) h = raw;
  else if (typeof raw === "number" && Number.isSafeInteger(raw) && raw >= 0) h = BigInt(raw);
  else if (typeof raw === "string" && /^(0|[1-9][0-9]*)$/.test(raw)) h = BigInt(raw);
  if (h === null) {
    throw new Error(`the epoch route's answer for ${start}..${end} carries a metadata height of ${JSON.stringify(String(raw))}, not a nonnegative integer; refusing an answer whose signed position cannot be read`);
  }
  return h;
};

// THE CHAIN IS CHECKED TOO, and it is authenticated for the same reason: the chain identity is
// one of the signing digest's inputs. An answer from another chain would otherwise be a valid
// proof about a world this run is not auditing.
const requireChain = (metadata, chainIdPin, start, end) => {
  const got = metadata && metadata.chainId;
  if (typeof got !== "string" || got.length === 0) {
    throw new Error(`the epoch route's answer for ${start}..${end} carries no chain identity; refusing`);
  }
  if (got !== chainIdPin) {
    throw new Error(`the epoch route answered ${start}..${end} on chain ${JSON.stringify(got)} while this run is pinned to ${JSON.stringify(chainIdPin)}; refusing a proof about another chain`);
  }
  return got;
};

const requireHeightAtLeast = (answerHeight, referenceHeight, start, end) => {
  if (typeof referenceHeight !== "bigint" || referenceHeight < 0n) {
    throw new Error(`the run's reference height ${JSON.stringify(String(referenceHeight))} is not a nonnegative integer; refusing`);
  }
  if (answerHeight < referenceHeight) {
    throw new Error(`the epoch route answered ${start}..${end} at signed height ${answerHeight}, below this run's reference height ${referenceHeight}; an older state can be complete for itself and still omit epochs finalized at the reference, refusing`);
  }
  return answerHeight;
};

// THE STEP CHECK, pure (F7): the walk's stepping rule is replaceable so
// its defensive guards are reachable by a test, and a replaceable rule is
// a governed one. A step must begin exactly where coverage ended, must
// not run backwards, must stay at or below the bound, and must not
// exceed the route's cap. A stepper that skips an interval or asks for
// more than the route serves is refused here rather than silently
// shrinking the coverage claim.
const validateStep = (step, coveredTo, bound) => {
  if (!step || typeof step !== "object") throw new Error(`the stepping rule answered ${JSON.stringify(step)}, not a step; refusing`);
  if (step.done === true) return step;
  const { start, end } = step;
  if (start !== coveredTo + 1) {
    throw new Error(`the stepping rule asked to begin at ${JSON.stringify(start)} while coverage ends at ${coveredTo}; a walk that skips or repeats an interval cannot support a coverage claim, refusing`);
  }
  if (!Number.isSafeInteger(end) || end < start) {
    throw new Error(`the stepping rule answered the interval ${JSON.stringify(start)}..${JSON.stringify(end)}, which is not forward; refusing`);
  }
  if (end > bound) {
    throw new Error(`the stepping rule asked for ${start}..${end}, past the finality bound ${bound}; refusing`);
  }
  if (end - start + 1 > MAX_INTERVAL_WIDTH) {
    throw new Error(`the stepping rule asked for a width of ${end - start + 1}, above the route's cap of ${MAX_INTERVAL_WIDTH}; refusing`);
  }
  return step;
};

// THE STEPPING RULE, pure: where the walk goes next, decided from the
// coverage it has and the bound it must reach, and NEVER from the shape
// of the last answer. coveredTo is the highest epoch index inside the
// coverage union, or -1 before any interval is accepted. A bound below
// zero means the current epoch is zero, so there is no finalized epoch
// to enumerate and the walk is complete on its first step.
const nextInterval = ({ coveredTo, bound, step }) => {
  if (!Number.isSafeInteger(step) || step < 1 || step > MAX_INTERVAL_WIDTH) {
    throw new Error(`the walk's interval width ${JSON.stringify(step)} is not between 1 and the route's cap of ${MAX_INTERVAL_WIDTH}; refusing`);
  }
  if (!Number.isSafeInteger(bound) || bound < -1) {
    throw new Error(`the finality bound ${JSON.stringify(bound)} is not an integer at or above -1; refusing`);
  }
  if (!Number.isSafeInteger(coveredTo) || coveredTo < -1) {
    throw new Error(`the coverage mark ${JSON.stringify(coveredTo)} is not an integer at or above -1; refusing`);
  }
  if (coveredTo >= bound) return { done: true };
  const start = coveredTo + 1;
  return { done: false, start, end: Math.min(start + step - 1, bound) };
};

// THE COVERAGE RULE, pure: the walk's answer may carry a positive label
// only when the interval it actually examined reaches the finality
// bound. Nothing here counts records, because a count cannot tell a
// sparse history from a truncated walk, which is the defect being
// repaired.
const assertCoverageReaches = (coveredTo, bound) => {
  if (!Number.isSafeInteger(bound) || bound < -1) {
    throw new Error(`the finality bound ${JSON.stringify(bound)} is not an integer at or above -1; finality has no reference`);
  }
  if (!Number.isSafeInteger(coveredTo) || coveredTo < -1) {
    throw new Error(`the coverage mark ${JSON.stringify(coveredTo)} is not an integer at or above -1; refusing`);
  }
  if (coveredTo < bound) {
    throw new Error(`the enumeration covered epochs 0..${coveredTo} but the finality bound is ${bound}; the interval above ${coveredTo} was never examined, so it is UNEXAMINED rather than absent, refusing an incomplete proved claim`);
  }
};

// the number of interval reads a complete walk needs, exactly: the
// budget is derived from the bound and the step rather than picked, so
// it cannot be the thing that ends a walk over a real history
const requestBudget = (bound, step) => (bound < 0 ? 0 : Math.ceil((bound + 1) / step));

// an epoch value from the environment, pure: CANONICAL DECIMAL text
// only, so the shell cannot smuggle a value through numeric coercion
// (' ' is 0, '0x10' is 16 and '1e2' is 100 under Number, the third
// confirmation round)
const parseEpochValue = (name, v) => {
  if (v === undefined || v === "") return null;
  if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v) || !Number.isSafeInteger(Number(v))) {
    throw new Error(`${name}=${JSON.stringify(v)} is not a canonical nonnegative integer epoch; refusing (coerced forms like hex, exponents, blanks and leading zeros are not epochs)`);
  }
  return Number(v);
};

// THE PRODUCTION COMPOSITION, extracted from the audit runner so the
// offline battery can bind it (the pure gates were tested
// while the closure composing them was not reachable by any test, so
// deleting the coverage call or flipping the fallback's proved flag
// survived every offline check). The factory owns every decision
// between the wire and the proved flag; the caller supplies only the
// wire call, the verified current epoch, the journal figure sources
// and a log sink. The returned fetchRange is the audit's discovery
// input, and discoveryProved reports whether the injected enumeration
// was accepted complete for this run (the provenance writer's
// condition).
//
// TRUST BOUNDARY, stated: the factory establishes COVERAGE and interval
// discipline over whatever route is injected; the PROOF strength of
// each answer is the injected readEpochInterval's own contract.
// Production injects the finalized-epoch route with its verifier bound
// and refuses any answer whose status is not proved, so there the
// proved flag means proof-verified; a caller injecting an unverified
// source gets a proved flag that means only "coverage of 0..bound was
// accepted from the injected source". The proved flag describes the
// UNIVERSE enumeration, never the requested range: an empty in-range
// subset of a proved universe is still a proved answer.
const createFetchRange = ({ readEpochInterval, currentEpoch, referenceHeight, chainIdPin,
  journalCaps, figuresFor, log, nextIntervalFn }) => {
  // the log sink is REQUIRED (a default sink made silence an
  // implicit opt-out; a caller that wants no logging says so
  // explicitly, and the machine-readable record of a fallback is the
  // proved:false answer itself, not the log line)
  if (typeof log !== "function") throw new Error("createFetchRange requires an explicit log function (pass a no-op deliberately to suppress logging)");
  if (typeof readEpochInterval !== "function") throw new Error("createFetchRange requires the readEpochInterval route (startEpoch, endEpoch) -> { epochs, metadata }");
  // THE REFERENCE IS A SIGNED HEIGHT AND A CHAIN, both required. They come from the same
  // proof-verified read that supplies the finality reference, and without them there is nothing
  // authenticated to compare an answer against (a soundness-review finding).
  const REFERENCE_HEIGHT = (typeof referenceHeight === "bigint") ? referenceHeight
    : (typeof referenceHeight === "number" && Number.isSafeInteger(referenceHeight) && referenceHeight >= 0) ? BigInt(referenceHeight)
    : (typeof referenceHeight === "string" && /^(0|[1-9][0-9]*)$/.test(referenceHeight)) ? BigInt(referenceHeight)
    : null;
  if (REFERENCE_HEIGHT === null) throw new Error(`createFetchRange requires the run's reference signed height as a nonnegative integer (got ${JSON.stringify(String(referenceHeight))})`);
  if (typeof chainIdPin !== "string" || chainIdPin.length === 0) throw new Error("createFetchRange requires the run's chain identity pin");
  // THE STEPPING RULE IS REPLACEABLE, and every step it answers is checked by validateStep
  // above, so the hatch cannot skip an interval, run backwards, pass the bound or exceed the
  // route's cap. It exists because the walk's own defensive guards are otherwise unreachable
  // while the default rule is monotone, and a guard nothing can reach is a guard nothing
  // binds (the review's F7).
  const stepRule = nextIntervalFn === undefined ? nextInterval : nextIntervalFn;
  if (typeof stepRule !== "function") throw new Error("createFetchRange's nextIntervalFn, when supplied, must be a function");
  // ONE audit run is defined against ONE captured current epoch, so
  // the finalized set is computed at most once per factory, lazily on
  // the first fetch, and cached for the run (a later fetchRange call
  // observing a newer universe would mix two reference points inside
  // one report), and the once-and-sticky property holds under
  // CONCURRENT calls too (a check-then-await sequence let two
  // overlapped calls both enumerate and disagree about the fallback):
  // the first call installs the ONE shared enumeration promise
  // synchronously, every caller arriving before settlement awaits that
  // same promise while later callers read the settled state, its
  // settlement is logged once, and its resolution is the accepted Set
  // or undefined after the logged fallback, so concurrent callers can
  // never diverge on the proved flag. "Once" counts enumerations, not
  // wire requests: one enumeration issues one request per interval.
  let finalizedSet = null; // a Set once accepted; undefined after a fallback (sticky)
  let enumerating = null; // the ONE enumeration promise, shared by every caller and retained after settlement
  const enumerateFinalized = async () => {
    if (!Number.isSafeInteger(currentEpoch) || currentEpoch < 0) {
      throw new Error(`the current epoch ${JSON.stringify(currentEpoch)} is not a nonnegative integer; finality has no reference`);
    }
    const bound = currentEpoch - 1; // finalized epochs are strictly below the current one
    const budget = requestBudget(bound, INTERVAL_STEP);
    const found = new Set();
    let coveredTo = -1;
    let used = 0;
    for (;;) {
      const step = validateStep(stepRule({ coveredTo, bound, step: INTERVAL_STEP }), coveredTo, bound);
      if (step.done) break;
      if (used >= budget) {
        throw new Error(`the enumeration used its full budget of ${budget} interval reads and covered only 0..${coveredTo} of 0..${bound}; refusing`);
      }
      used++;
      const previousCovered = coveredTo;
      const answer = await readEpochInterval(step.start, step.end);
      if (!answer || typeof answer !== "object" || !Array.isArray(answer.epochs)) {
        throw new Error(`the epoch route answered no epoch array for ${step.start}..${step.end}; refusing`);
      }
      // THE AUTHENTICATED CHECKS, before the rows are believed about the interval: the chain the
      // answer was signed on, and its signed height against the run's reference
      requireChain(answer.metadata, chainIdPin, step.start, step.end);
      requireHeightAtLeast(signedHeightOf(answer.metadata, step.start, step.end), REFERENCE_HEIGHT, step.start, step.end);
      const numbers = answer.epochs.map(validateEpochEntry); // malformed numbers refuse (the pure gate)
      validateIntervalAnswer(numbers, step.start, step.end); // the interval binding (the pure gate)
      for (const n of numbers) found.add(n);
      // COVERAGE advances by the interval the ACCEPTED answer covered,
      // never by the last row returned. This is the whole repair: a
      // sparse interval and an empty interval both advance the walk,
      // and an answer shorter than its interval ends nothing.
      coveredTo = step.end;
      // the unbounded-walk guard, and the reason the budget above is
      // not the only one: a stepping rule that stopped advancing would
      // otherwise loop forever inside one enumeration rather than
      // refusing by name
      if (coveredTo <= previousCovered) {
        throw new Error(`the walk's coverage did not advance past ${previousCovered}; refusing an unbounded walk`);
      }
    }
    // COVERAGE, asserted rather than implied
    assertCoverageReaches(coveredTo, bound);
    // THE BOUND IS CROSS-CHECKED OVER ONE INTERVAL, AND THAT IS ALL IT ESTABLISHES (a soundness-review finding). The
    // finality reference is read from the response metadata's EPOCH, which the signing digest
    // does not cover, so its value is the serving node's word.
    //
    // WHAT THIS READ DOES: it catches an understated reference whose omitted finalized epochs
    // fall within ONE INTERVAL WIDTH above the claim. That is a real and cheap catch and it is
    // kept.
    //
    // WHAT IT DOES NOT DO, corrected after a focused confirmation defeated the earlier claim that
    // it settled the question: a bounded read cannot establish an unbounded suffix. With
    // finalized epochs 0 through 9 and 100, understating the reference to 10 leaves this read
    // over 10..59 correctly empty while epoch 100 is never looked for. The completeness contract
    // explicitly allows a sparse history with spans longer than this width, so no dense premise
    // rescues it. The residual is stated where the proved answer is described, and the consuming
    // composition refuses a universe reaching above the claimed bound rather than relying on it.
    const probeStart = bound + 1;
    const probeEnd = probeStart + INTERVAL_STEP - 1;
    const probe = await readEpochInterval(probeStart, probeEnd);
    if (!probe || typeof probe !== "object" || !Array.isArray(probe.epochs)) {
      throw new Error(`the bound cross-check for ${probeStart}..${probeEnd} answered no epoch array; refusing`);
    }
    requireChain(probe.metadata, chainIdPin, probeStart, probeEnd);
    requireHeightAtLeast(signedHeightOf(probe.metadata, probeStart, probeEnd), REFERENCE_HEIGHT, probeStart, probeEnd);
    const above = probe.epochs.map(validateEpochEntry);
    validateIntervalAnswer(above, probeStart, probeEnd);
    if (above.length > 0) {
      throw new Error(`the finality reference claims the current epoch is ${currentEpoch}, so nothing at or above it is finalized, yet the route serves finalized epoch(s) ${above.join(",")} within ${probeStart}..${probeEnd}; the reference is understated, refusing`);
    }
    return found;
  };
  const enumerateOnce = () => {
    if (enumerating === null) {
      // the log wording is NEUTRAL here (this factory
      // establishes acceptance and coverage, never proof; the proof
      // strength of an accepted enumeration is the injected route's
      // contract, per the trust boundary above), and the sink is
      // OBSERVABILITY, never control (an unguarded sink call
      // let a throwing sink convert a settled answer into a
      // rejection): a sink error is swallowed here because the
      // machine-readable answer is the proved flag, which must not
      // depend on whether a log line could be written
      const tryLog = (s) => { try { log(s); } catch (_) { /* the sink must not decide the answer */ } };
      enumerating = enumerateFinalized().then(
        (found) => { tryLog(`  [DISCOVERY] the epoch enumeration was accepted: coverage of 0..${currentEpoch - 1} below the current epoch ${currentEpoch}, holding ${found.size} finalized epochs (the remainder of that interval is absent by evidence; proof strength is the injected route's contract)`); return found; },
        (e) => { tryLog(`  [DISCOVERY FALLBACK] the epoch enumeration failed (${(e && e.message) || String(e)}); serving the journal-derived UNPROVED shape, the pre-upgrade width`); return undefined; });
    }
    return enumerating;
  };
  const fetchRange = async (start, end) => {
    // the caps source may be sync (the journal map) or async (the
    // proved income adapter's lazy fetch); awaiting a plain Map is the
    // identity, so both widths ride one line
    const caps = await journalCaps();
    if (finalizedSet === null) finalizedSet = await enumerateOnce(); // sticky: a fallback resolution stays undefined for the run
    if (finalizedSet === undefined) {
      const epochs = [...caps.keys()].filter((n) => n >= start && n <= end)
        .sort((a, b) => a - b).map((n) => figuresFor(n, caps.get(n)));
      return { proved: false, epochs };
    }
    const inRange = [...finalizedSet].filter((n) => n >= start && n <= end).sort((a, b) => a - b);
    // DISCOVERY walks the whole universe, past the audit interval, so
    // an epoch without journaled figures flows through as a BARE
    // NUMBER: the audit reads figures only for epochs it actually
    // evaluates, and if a bare epoch ever enters the evaluated
    // interval the recomputation refuses loudly on the missing
    // figures, which is the fail-closed shape (C1's tooling gap,
    // stated; narrow the interval or run the distribution)
    const epochs = inRange.map((n) => {
      const ec = caps.get(n);
      return ec ? figuresFor(n, ec) : { number: n };
    });
    return { proved: true, epochs };
  };
  return { fetchRange, discoveryProved: () => finalizedSet instanceof Set };
};

// THE SHARED ROUTE WRAPPER (the review's F4): both runners built this inline, so the offline
// batteries could only sweep their source text and three real substitutions survived. The
// wrapper is here, tested, and bound by both runners.
//
// STATED WIDTH: the finalized-epoch answer does not name its own subject pool or identity, and
// this wrapper cannot confirm that the rows describe the interval's own chain rather than
// another. What it does establish is that the answer claimed the proved status, carries an
// epoch array and carries response metadata for the snapshot rule above.
const makeReadEpochInterval = ({ readFinalizedInterval }) => {
  if (typeof readFinalizedInterval !== "function") throw new Error("makeReadEpochInterval requires readFinalizedInterval(startEpoch, endEpoch)");
  return async (startEpoch, endEpoch) => {
    const r = await readFinalizedInterval(startEpoch, endEpoch);
    if (!r || typeof r !== "object") throw new Error(`the finalized-epoch route answered ${JSON.stringify(r)} for ${startEpoch}..${endEpoch}; refusing`);
    if (r.status !== "proved") {
      throw new Error(`the finalized-epoch route answered status ${JSON.stringify(r.status)} for ${startEpoch}..${endEpoch}, not "proved"; a universe is not built from an unproved answer`);
    }
    if (!Array.isArray(r.epochs)) throw new Error(`the finalized-epoch route answered no epoch array for ${startEpoch}..${endEpoch}; refusing`);
    return { epochs: r.epochs, metadata: r.metadata };
  };
};

module.exports = { MAX_INTERVAL_WIDTH, INTERVAL_STEP, validateEpochEntry, validateIntervalAnswer,
  signedHeightOf, requireChain, requireHeightAtLeast, validateStep, nextInterval, assertCoverageReaches,
  requestBudget, parseEpochValue, makeReadEpochInterval, createFetchRange };
