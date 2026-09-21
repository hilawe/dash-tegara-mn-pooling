// The discovery gate's offline battery, rewritten for the INTERVAL walk.
//
// WHAT CHANGED AND WHY IT IS NOT AN INCIDENTAL EDIT. The previous battery asserted that an
// answer shorter than the requested page finished the enumeration, and that a complete
// universe is the contiguous integers below the current epoch. Both were pinned as intended
// behaviour, and both are false against the live platform (a soundness-review finding). Replacing those two assertions is
// the repair's evidence, so the cases below make a SPARSE history a POSITIVE control: a walk
// that stopped on a short answer, or that demanded dense numbering, now fails a case that
// must pass rather than merely passing a case that must fail.
const { MAX_INTERVAL_WIDTH, INTERVAL_STEP, validateEpochEntry, validateIntervalAnswer,
  signedHeightOf, requireChain, requireHeightAtLeast, validateStep, nextInterval, assertCoverageReaches,
  requestBudget, parseEpochValue, makeReadEpochInterval, createFetchRange } = require("./e2EpochDiscoveryGate.cjs");
const { runnerSource, skipNote } = require("./runnerSource.cjs");
let passed = 0, failed = 0, skipped = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error("FAIL:", name, "(no error)"); }
  catch (e) { ok(name, re.test(String(e.message))); }
};

// ---- entry validation ----
ok("a well-formed entry yields its number", validateEpochEntry({ number: 7 }) === 7);
throws("a NaN epoch number refuses", () => validateEpochEntry({ number: NaN }), /malformed epoch number/);
throws("a fractional epoch number refuses", () => validateEpochEntry({ number: 1.5 }), /malformed epoch number/);
throws("a negative epoch number refuses", () => validateEpochEntry({ number: -1 }), /malformed epoch number/);
throws("a string epoch number refuses", () => validateEpochEntry({ number: "7" }), /malformed epoch number/);
throws("a missing entry refuses", () => validateEpochEntry(undefined), /malformed epoch number/);

// ---- the interval binding ----
ok("an answer inside its interval passes", JSON.stringify(validateIntervalAnswer([3, 5, 9], 0, 9)) === JSON.stringify([3, 5, 9]));
ok("an EMPTY answer inside its interval passes (an interval with no record is absence by evidence, not a failure)",
  JSON.stringify(validateIntervalAnswer([], 50, 99)) === JSON.stringify([]));
ok("an answer holding exactly its endpoints passes", JSON.stringify(validateIntervalAnswer([50, 99], 50, 99)) === JSON.stringify([50, 99]));
throws("a number above the interval refuses", () => validateIntervalAnswer([3, 10], 0, 9), /outside the requested interval 0\.\.9/);
throws("a number below the interval refuses", () => validateIntervalAnswer([49, 60], 50, 99), /outside the requested interval 50\.\.99/);
throws("a repeated number refuses", () => validateIntervalAnswer([3, 3], 0, 9), /repeated or out-of-order/);
throws("a descending pair refuses", () => validateIntervalAnswer([5, 3], 0, 9), /repeated or out-of-order/);
throws("a non-array answer refuses", () => validateIntervalAnswer(null, 0, 9), /not an array of entries/);
throws("a reversed interval refuses", () => validateIntervalAnswer([], 9, 0), /not a forward interval/);

// ---- the stepping rule ----
ok("the first step starts at zero and is one width wide",
  JSON.stringify(nextInterval({ coveredTo: -1, bound: 119, step: 50 })) === JSON.stringify({ done: false, start: 0, end: 49 }));
ok("a later step starts one past the coverage mark",
  JSON.stringify(nextInterval({ coveredTo: 49, bound: 119, step: 50 })) === JSON.stringify({ done: false, start: 50, end: 99 }));
ok("the last step is clipped to the bound, never past it",
  JSON.stringify(nextInterval({ coveredTo: 99, bound: 119, step: 50 })) === JSON.stringify({ done: false, start: 100, end: 119 }));
ok("coverage reaching the bound finishes", nextInterval({ coveredTo: 119, bound: 119, step: 50 }).done === true);
ok("a bound of minus one finishes immediately (current epoch zero, no finalized epoch exists)",
  nextInterval({ coveredTo: -1, bound: -1, step: 50 }).done === true);
throws("a width above the route's cap refuses", () => nextInterval({ coveredTo: -1, bound: 9, step: MAX_INTERVAL_WIDTH + 1 }), /not between 1 and the route's cap/);
ok("a width exactly at the cap is allowed", nextInterval({ coveredTo: -1, bound: 999, step: MAX_INTERVAL_WIDTH }).end === MAX_INTERVAL_WIDTH - 1);
throws("a zero width refuses", () => nextInterval({ coveredTo: -1, bound: 9, step: 0 }), /not between 1 and the route's cap/);
throws("a non-integer bound refuses", () => nextInterval({ coveredTo: -1, bound: NaN, step: 50 }), /finality bound/);
throws("a bound below minus one refuses", () => nextInterval({ coveredTo: -1, bound: -2, step: 50 }), /finality bound/);
throws("a non-integer coverage mark refuses", () => nextInterval({ coveredTo: null, bound: 9, step: 50 }), /coverage mark/);
// the two widths are asserted against LITERALS, not against each other: comparing the
// module's own constants would be a tautology that any pair of values satisfies, and the cap
// is a MEASURED property of the route (widths to 100 served, 101 and wider refused, in
// docs/review/controls/2026-09-20-epoch-route-probe.log), so a change to either is a claim
// about the route that needs new evidence
ok("the measured route cap is 100 epoch indices", MAX_INTERVAL_WIDTH === 100);
ok("the deployed width is 50, inside that cap", INTERVAL_STEP === 50);

// ---- the coverage rule ----
assertCoverageReaches(119, 119); ok("coverage exactly at the bound passes", true);
assertCoverageReaches(-1, -1); ok("no coverage under a bound of minus one passes", true);
throws("coverage one short of the bound refuses",
  () => assertCoverageReaches(118, 119), /covered epochs 0\.\.118 but the finality bound is 119/);
throws("no coverage under a real bound refuses", () => assertCoverageReaches(-1, 0), /never examined/);
throws("a non-integer bound refuses in the coverage rule", () => assertCoverageReaches(0, NaN), /finality has no reference/);

// ---- the derived budget ----
ok("a bound below zero needs no reads", requestBudget(-1, 50) === 0);
ok("a bound inside one width needs one read", requestBudget(0, 50) === 1 && requestBudget(49, 50) === 1);
ok("one epoch past a width needs a second read", requestBudget(50, 50) === 2);
ok("the budget is exact at a width multiple", requestBudget(99, 50) === 2 && requestBudget(100, 50) === 3);

// ---- the environment epoch values, canonical decimal only ----
ok("a canonical epoch parses", parseEpochValue("X", "42") === 42);
ok("an absent value is null", parseEpochValue("X", undefined) === null && parseEpochValue("X", "") === null);
throws("a blank refuses (Number would read it as zero)", () => parseEpochValue("X", " "), /not a canonical/);
throws("a hex form refuses (Number would read 0x10 as sixteen)", () => parseEpochValue("X", "0x10"), /not a canonical/);
throws("an exponent form refuses (Number would read 1e2 as one hundred)", () => parseEpochValue("X", "1e2"), /not a canonical/);
throws("a leading zero refuses (not canonical)", () => parseEpochValue("X", "007"), /not a canonical/);
throws("a negative refuses", () => parseEpochValue("X", "-1"), /not a canonical/);
ok("the safe-integer boundary is accepted exactly at the ceiling",
  parseEpochValue("X", String(Number.MAX_SAFE_INTEGER)) === Number.MAX_SAFE_INTEGER);
throws("one past the safe-integer ceiling refuses (the whole-branch-deletion mutation's case)",
  () => parseEpochValue("X", "9007199254740992"), /not a canonical/);

// ---- the freshness rule, on the SIGNED height (a soundness-review finding) ----
// THE CENTRAL CASE IS THE REVIEWER'S OWN CONTROL. The Tenderdash signing digest covers the
// application version, the core-chain-locked height, the time, the application root, the block
// height and the chain identity. It does NOT cover the metadata's epoch. So an older answer can
// carry a later-looking epoch over an unchanged signature, and the first version of this rule
// accepted it. Freshness now rests on the height, which is inside that digest.
const heightOf = (m) => { try { return signedHeightOf(m, 0, 49); } catch (e) { return `threw: ${e.message}`; } };
ok("a numeric signed height is read", heightOf({ height: 1397 }) === 1397n);
ok("a decimal-string height is read", heightOf({ height: "1397" }) === 1397n);
ok("a bigint height is read", heightOf({ height: 1397n }) === 1397n);
ok("the height is read from the SIGNED member, not from one the digest does not cover",
  heightOf({ height: 1397, epoch: 999 }) === 1397n);
throws("absent metadata refuses, because the answer's state is then unknown",
  () => signedHeightOf(undefined, 0, 49), /no response metadata/);
throws("a metadata height that is not an integer refuses",
  () => signedHeightOf({ height: 1.5 }, 0, 49), /not a nonnegative integer/);
throws("an exponent-form height refuses (Number would read 1e2 as one hundred)",
  () => signedHeightOf({ height: "1e2" }, 0, 49), /not a nonnegative integer/);
throws("a negative height refuses", () => signedHeightOf({ height: -1 }, 0, 49), /not a nonnegative integer/);
ok("a height exactly at the reference passes", requireHeightAtLeast(1397n, 1397n, 0, 49) === 1397n);
ok("a NEWER height passes, since a finalized epoch below the bound cannot stop existing",
  requireHeightAtLeast(2000n, 1397n, 0, 49) === 2000n);
throws("an OLDER height refuses, naming both positions",
  () => requireHeightAtLeast(1000n, 1397n, 0, 49), /signed height 1000, below this run's reference height 1397/);
throws("a malformed reference height refuses", () => requireHeightAtLeast(1n, 7, 0, 49), /not a nonnegative integer/);
// THE EPOCH MEMBER IS NOT CONSULTED. Two answers whose metadata differ ONLY in the epoch are the
// same evidence, because that member is outside the signature, and the rule must treat them alike.
ok("two answers differing only in the unsigned epoch are read identically",
  signedHeightOf({ height: 1397, epoch: 179 }, 0, 49) === signedHeightOf({ height: 1397, epoch: 189 }, 0, 49));

// ---- the chain, which the signing digest does cover ----
ok("an answer on the pinned chain passes", requireChain({ chainId: "c1" }, "c1", 0, 9) === "c1");
throws("an answer on another chain refuses",
  () => requireChain({ chainId: "c2" }, "c1", 0, 9), /on chain "c2" while this run is pinned to "c1"/);
throws("an answer with no chain identity refuses",
  () => requireChain({}, "c1", 0, 9), /carries no chain identity/);

// ---- the step check (the review's F7) ----
ok("a done step passes through", validateStep({ done: true }, 5, 9).done === true);
ok("a step beginning exactly where coverage ended passes",
  validateStep({ done: false, start: 50, end: 99 }, 49, 119).start === 50);
throws("a step that SKIPS an interval refuses",
  () => validateStep({ done: false, start: 60, end: 99 }, 49, 119), /begin at 60 while coverage ends at 49/);
throws("a step that REPEATS an interval refuses",
  () => validateStep({ done: false, start: 40, end: 49 }, 49, 119), /begin at 40 while coverage ends at 49/);
throws("a backwards step refuses",
  () => validateStep({ done: false, start: 50, end: 49 }, 49, 119), /not forward/);
throws("a step past the bound refuses",
  () => validateStep({ done: false, start: 50, end: 120 }, 49, 119), /past the finality bound 119/);
throws("a step wider than the route's cap refuses",
  () => validateStep({ done: false, start: 0, end: MAX_INTERVAL_WIDTH }, -1, 9999), /width of 101, above the route's cap/);
throws("a non-step refuses", () => validateStep(null, -1, 9), /not a step/);

// ---- the shared route wrapper (the review's F4), awaited by the main run below rather than
// started beside it, so its results are inside the counted total rather than racing the summary
const wrapperCases = async () => {
  const wrap = (r) => makeReadEpochInterval({ readFinalizedInterval: async () => r });
  const got = await wrap({ status: "proved", epochs: [{ number: 1 }], metadata: { epoch: 7 } })(0, 9);
  ok("the wrapper passes a proved answer's rows AND its metadata through",
    JSON.stringify(got) === JSON.stringify({ epochs: [{ number: 1 }], metadata: { epoch: 7 } }));
  const cases = [
    ["an unproved-plain answer refuses", { status: "unproved-plain", epochs: [], metadata: { epoch: 7 } }, /not "proved"/],
    ["an unverified-carrier answer refuses", { status: "unverified-carrier", metadata: { epoch: 7 } }, /not "proved"/],
    ["an answer with no status refuses", { epochs: [], metadata: { epoch: 7 } }, /not "proved"/],
    ["a proved answer with no epoch array refuses", { status: "proved", metadata: { epoch: 7 } }, /no epoch array/],
    ["a non-object answer refuses", null, /refusing/],
  ];
  for (const [name, r, re] of cases) {
    try { await wrap(r)(0, 9); failed++; console.error("FAIL:", name, "(resolved)"); }
    catch (e) { ok(name, re.test(String(e.message))); }
  }
  // THE ROWS ARE PASSED WHOLE. The review's surviving mutation dropped the last row inside the
  // runner, where nothing executed it; here the wrapper's own output is compared.
  const three = await wrap({ status: "proved", epochs: [{ number: 0 }, { number: 1 }, { number: 2 }], metadata: { epoch: 7 } })(0, 2);
  ok("the wrapper drops no row", JSON.stringify(three.epochs.map((e) => e.number)) === JSON.stringify([0, 1, 2]));
  let noRoute = false;
  try { makeReadEpochInterval({}); } catch (e) { noRoute = /requires readFinalizedInterval/.test(String(e.message)); }
  ok("a wrapper built without the route refuses", noRoute === true);
};

// ---- THE PRODUCTION COMPOSITION, driven by an injected interval route ----
// The fake answers exactly as the finalized-epoch route does: every existing number inside
// the requested inclusive interval, ascending, and nothing else. Figures are opaque to the
// factory, so figuresFor tags its inputs and the assertions check IDENTITY of the returned
// epochs, never counts.
// the route fake answers the wrapper's shape: the rows inside the requested inclusive interval
// PLUS the response metadata the snapshot rule reads. SNAP is high enough that every ordinary
// case passes the snapshot rule, so a case that wants to exercise that rule says so.
const CHAIN = "tegara-test-chain";
const REF_HEIGHT = 5000n;
const rowsOf = (existing, a, b) => existing.filter((n) => n >= a && n <= b).map((n) => ({ number: n }));
// an answer carries the two members the gate authenticates against, the SIGNED HEIGHT and the
// chain identity, and an epoch member that the gate must NOT rely on
const answerOf = (epochs, height = REF_HEIGHT, chainId = CHAIN) => ({ epochs, metadata: { height, chainId, epoch: 7 } });
const routeOver = (existing, height = REF_HEIGHT, chainId = CHAIN) => {
  const calls = [];
  return { calls, fn: async (a, b) => { calls.push([a, b]); return answerOf(rowsOf(existing, a, b), height, chainId); } };
};
const capsOf = (obj) => () => new Map(Object.entries(obj).map(([k, v]) => [Number(k), v]));
// the figure tag must be JSON-VISIBLE even for an absent capture (an undefined member
// disappears under JSON.stringify, which let the no-bare-numbers mutation survive the first
// cut of this battery), so an absent capture tags as null
const testFigures = (n, ec) => ({ number: n, figures: ec === undefined ? null : ec });
const noLog = () => {};
const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);

(async () => {
  { // THE POSITIVE CONTROL THAT PINS a soundness-review finding AND a soundness-review finding TOGETHER: a SPARSE history whose
    // coverage reaches the bound proves, and its universe is exactly the epochs that exist.
    // A walk that stopped on an answer shorter than its interval would cover only 0..49 and
    // fall back here; a rule demanding dense numbering would refuse here. This is the bench's
    // real shape, with a gap of one, a run of five and an empty interval in the middle.
    const existing = [...range(0, 39), ...range(41, 49), ...range(56, 99), ...range(150, 199)];
    const { fn, calls } = routeOver(existing);
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: fn, currentEpoch: 200,
      journalCaps: capsOf({ 41: "cap41" }), figuresFor: testFigures, log: noLog });
    ok("before any fetch, discovery does not read proved", d.discoveryProved() === false);
    const r = await d.fetchRange(0, 199);
    ok("a complete SPARSE history proves", r.proved === true);
    ok("the proved universe is exactly the epochs that exist, gaps and all",
      JSON.stringify(r.epochs.map((e) => e.number)) === JSON.stringify(existing));
    ok("figures attach only where journaled; every other epoch is a bare number",
      JSON.stringify(r.epochs[40]) === JSON.stringify({ number: 41, figures: "cap41" })
        && JSON.stringify(r.epochs[0]) === JSON.stringify({ number: 0 }));
    ok("the walk requested contiguous intervals covering zero through the bound, then ONE read above it",
      JSON.stringify(calls) === JSON.stringify([[0, 49], [50, 99], [100, 149], [150, 199], [200, 249]]));
    ok("after a proving enumeration, discoveryProved reports true", d.discoveryProved() === true);
  }
  { // AN INTERVAL WITH NO RECORD AT ALL does not end the walk. The bench carries a real
    // empty span of more than five hundred indices, so this is the ordinary case and not a
    // contrived one. An implementation that treated an empty answer as the end of history
    // would cover only 0..49 and fall back.
    const existing = [...range(0, 49), ...range(150, 179)];
    const { fn, calls } = routeOver(existing);
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: fn, currentEpoch: 180,
      journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    const r = await d.fetchRange(0, 179);
    ok("an empty interval in the middle does not end the walk", r.proved === true);
    ok("the walk read past the empty interval, and then above the bound",
      JSON.stringify(calls) === JSON.stringify([[0, 49], [50, 99], [100, 149], [150, 179], [180, 229]]));
    ok("the universe skips the empty span", JSON.stringify(r.epochs.map((e) => e.number)) === JSON.stringify(existing));
  }
  { // a DENSE history still proves, so the earlier bench state does not regress
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: routeOver(range(0, 44)).fn, currentEpoch: 45,
      journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    const r = await d.fetchRange(0, 44);
    ok("a dense history proves with the identity of every epoch",
      r.proved === true && JSON.stringify(r.epochs.map((e) => e.number)) === JSON.stringify(range(0, 44)));
  }
  { // a history inside ONE interval terminates on its first answer
    const { fn, calls } = routeOver([0, 3, 7]);
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: fn, currentEpoch: 8,
      journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    const r = await d.fetchRange(0, 7);
    ok("a single-interval history proves on one walk read plus the cross-check", r.proved === true && calls.length === 2);
    ok("the walk read asked for exactly zero through the bound", JSON.stringify(calls[0]) === JSON.stringify([0, 7]));
    ok("the cross-check asked immediately above it", JSON.stringify(calls[1]) === JSON.stringify([8, 57]));
  }
  { // CURRENT EPOCH ZERO: there is no finalized epoch, the walk reads nothing and proves an
    // empty universe rather than refusing
    const { fn, calls } = routeOver([]);
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: fn, currentEpoch: 0,
      journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    const r = await d.fetchRange(0, 0);
    ok("a current epoch of zero proves an empty universe with no WALK read, only the cross-check",
      r.proved === true && r.epochs.length === 0 && calls.length === 1
        && JSON.stringify(calls[0]) === JSON.stringify([0, 49]));
  }
  { // THE FINALITY BOUND IS RESPECTED BY CONSTRUCTION: nothing at or above the current epoch
    // is ever requested, so the universe cannot contain one
    // the current epoch is 30, well inside one interval width, so the clip to the bound is
    // load-bearing here: an unclipped step would ask for 0..49 and read epochs the walk has
    // no business treating as finalized
    const { fn, calls } = routeOver(range(0, 29));
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: fn, currentEpoch: 30,
      journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    const r = await d.fetchRange(0, 60);
    ok("the WALK never asks above the finality bound, and the only read above it is the cross-check",
      JSON.stringify(calls) === JSON.stringify([[0, 29], [30, 79]]));
    ok("the universe holds only epochs below the current one",
      r.proved === true && Math.max(...r.epochs.map((e) => e.number)) === 29);
  }
  { // a route answering ABOVE the requested interval refuses rather than filtering, because
    // filtering would turn a route defect into a silent narrowing
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN,
      readEpochInterval: async (a, b) => answerOf(b > 19 ? [] : [{ number: a }, { number: b + 1 }]),
      currentEpoch: 20, journalCaps: capsOf({ 1: "cap1" }), figuresFor: testFigures, log: noLog });
    const r = await d.fetchRange(0, 19);
    ok("an out-of-interval answer falls back to proved:false", r.proved === false);
    ok("the fallback serves the journal-derived epochs only",
      JSON.stringify(r.epochs) === JSON.stringify([{ number: 1, figures: "cap1" }]));
    ok("after a fallback, discoveryProved reports false", d.discoveryProved() === false);
  }
  { // a route answering a REPEATED number refuses
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async (a) => answerOf([{ number: a }, { number: a }]),
      currentEpoch: 20, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    ok("a repeated number falls back to proved:false", (await d.fetchRange(0, 19)).proved === false);
  }
  { // a route answering OUT OF ORDER refuses
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async (a) => answerOf([{ number: a + 2 }, { number: a + 1 }]),
      currentEpoch: 20, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    ok("an out-of-order answer falls back to proved:false", (await d.fetchRange(0, 19)).proved === false);
  }
  { // a route answering a NON-ARRAY refuses
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async () => [],
      currentEpoch: 20, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    ok("an answer that is a bare array, with no metadata, falls back to proved:false", (await d.fetchRange(0, 19)).proved === false);
  }
  { // a MALFORMED entry cannot produce proved:true, and the coercible "1" is the fixture so
    // a coercing validator cannot survive
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async () => answerOf([{ number: 0 }, { number: "1" }, { number: 2 }]),
      currentEpoch: 3, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    ok("a malformed entry falls back to proved:false", (await d.fetchRange(0, 2)).proved === false);
  }
  { // a malformed entry on a LATER interval refuses too, so a validator applied only to the
    // first answer cannot survive
    let i = 0;
    const answers = [answerOf(range(0, 49).map((n) => ({ number: n }))), answerOf([{ number: 50 }, { number: "51" }])];
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async () => answers[i++], currentEpoch: 60,
      journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    ok("a malformed entry on a later interval falls back to proved:false", (await d.fetchRange(0, 59)).proved === false);
  }
  { // A FAILING READ MID-WALK cannot produce proved:true. The first interval answers, the
    // second throws, so coverage stops at 49 while the bound is 119.
    let i = 0;
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async (a, b) => {
      if (i++ === 0) return answerOf(range(a, b).map((n) => ({ number: n })));
      throw new Error("route down"); },
      currentEpoch: 120, journalCaps: capsOf({ 5: "cap5" }), figuresFor: testFigures, log: noLog });
    const r = await d.fetchRange(0, 119);
    ok("a failing read mid-walk falls back to proved:false", r.proved === false);
    ok("the fallback serves the journaled epoch", JSON.stringify(r.epochs) === JSON.stringify([{ number: 5, figures: "cap5" }]));
  }
  { // a FAILING FIRST READ falls back, and the fallback is STICKY across the run
    const calls = [];
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async () => { calls.push(1); throw new Error("route down"); },
      currentEpoch: 5, journalCaps: capsOf({ 1: "cap1" }), figuresFor: testFigures, log: noLog });
    const r1 = await d.fetchRange(0, 4);
    const r2 = await d.fetchRange(0, 4);
    ok("a failing enumeration falls back to proved:false", r1.proved === false && r2.proved === false);
    ok("the fallback is sticky: the failed enumeration is not retried inside the run", calls.length === 1);
    ok("discoveryProved stays false across the stuck run", d.discoveryProved() === false);
  }
  { // the fallback serves EVERY in-range journaled capture, in order
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async () => { throw new Error("route down"); },
      currentEpoch: 6, journalCaps: capsOf({ 3: "cap3", 1: "cap1", 4: "cap4", 8: "cap8" }), figuresFor: testFigures, log: noLog });
    ok("the fallback serves every in-range capture sorted by epoch",
      JSON.stringify((await d.fetchRange(0, 5)).epochs)
        === JSON.stringify([{ number: 1, figures: "cap1" }, { number: 3, figures: "cap3" }, { number: 4, figures: "cap4" }]));
  }
  { // a malformed CURRENT EPOCH cannot produce proved:true
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: routeOver(range(0, 4)).fn, currentEpoch: NaN,
      journalCaps: capsOf({ 0: "cap0" }), figuresFor: testFigures, log: noLog });
    ok("a malformed current epoch falls back to proved:false", (await d.fetchRange(0, 4)).proved === false);
  }
  { // the log sink and the route are REQUIRED explicit inputs
    let noSink = false, noRoute = false;
    try { createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async () => [], currentEpoch: 1, journalCaps: capsOf({}), figuresFor: testFigures }); }
    catch (e) { noSink = /explicit log function/.test(String(e.message)); }
    ok("a factory built without a log sink refuses", noSink === true);
    try { createFetchRange({ currentEpoch: 1, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog }); }
    catch (e) { noRoute = /readEpochInterval route/.test(String(e.message)); }
    ok("a factory built without the interval route refuses", noRoute === true);
  }
  { // ONE enumeration per run: a second, DISJOINT fetch serves from the cached set
    const { fn, calls } = routeOver(range(0, 4));
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: fn, currentEpoch: 5,
      journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    await d.fetchRange(0, 2);
    const before = calls.length;
    const r2 = await d.fetchRange(3, 4);
    ok("a second, disjoint fetch does not re-enumerate", calls.length === before);
    ok("the cached set still serves range-filtered proved epochs",
      r2.proved === true && JSON.stringify(r2.epochs) === JSON.stringify([{ number: 3 }, { number: 4 }]));
  }
  { // CONCURRENT fetches share the WHOLE multi-interval enumeration, and the fake records the
    // COMPLETE call tuple so a mutation of the requested interval is visible
    const tuples = [];
    const existing = range(0, 119);
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async (a, b) => { tuples.push([a, b]);
      await new Promise((res) => setTimeout(res, 3));
      return answerOf(rowsOf(existing, a, b)); },
      currentEpoch: 120, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    const [ra, rb] = await Promise.all([d.fetchRange(0, 119), d.fetchRange(0, 119)]);
    ok("concurrent multi-interval fetches drive each interval exactly once, then one cross-check",
      JSON.stringify(tuples) === JSON.stringify([[0, 49], [50, 99], [100, 119], [120, 169]]));
    ok("concurrent multi-interval fetches agree on the proved flag", ra.proved === true && rb.proved === true);
  }
  { // concurrent DISJOINT-range fetches still share the ONE enumeration
    const calls = [];
    const existing = range(0, 119);
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async (a, b) => { calls.push([a, b]);
      await new Promise((res) => setTimeout(res, 3));
      return answerOf(rowsOf(existing, a, b)); },
      currentEpoch: 120, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    const [ra, rb] = await Promise.all([d.fetchRange(0, 59), d.fetchRange(60, 119)]);
    ok("concurrent disjoint fetches drive one shared enumeration and one cross-check", calls.length === 4);
    ok("concurrent disjoint fetches split the one universe",
      ra.proved === true && rb.proved === true
        && JSON.stringify(ra.epochs.map((e) => e.number)) === JSON.stringify(range(0, 59))
        && JSON.stringify(rb.epochs.map((e) => e.number)) === JSON.stringify(range(60, 119)));
  }
  { // CONCURRENT fetches over a failing route agree on the fallback
    const calls = [];
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async () => { calls.push(1);
      await new Promise((res) => setTimeout(res, 5)); throw new Error("route down"); },
      currentEpoch: 5, journalCaps: capsOf({ 0: "cap0" }), figuresFor: testFigures, log: noLog });
    const [ra, rb] = await Promise.all([d.fetchRange(0, 4), d.fetchRange(0, 4)]);
    ok("concurrent fetches over a failing route share the one failed enumeration", calls.length === 1);
    ok("concurrent fetches agree on the fallback", ra.proved === false && rb.proved === false);
  }
  { // the settlement is LOGGED, exactly once per run, on the success path
    const events = [];
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async (a, b) => {
      await new Promise((res) => setTimeout(res, 3));
      return answerOf(rowsOf(range(0, 4), a, b)); },
      currentEpoch: 5, journalCaps: capsOf({}), figuresFor: testFigures, log: (s) => events.push(s) });
    await Promise.all([d.fetchRange(0, 4), d.fetchRange(0, 4)]);
    await d.fetchRange(0, 4);
    ok("a proving run logs exactly one discovery event and no fallback event",
      events.length === 1 && /\[DISCOVERY\]/.test(events[0]) && !/FALLBACK/.test(events[0]));
  }
  { // ... and the fallback path
    const events = [];
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async () => { throw new Error("route down"); },
      currentEpoch: 5, journalCaps: capsOf({}), figuresFor: testFigures, log: (s) => events.push(s) });
    await d.fetchRange(0, 4);
    await d.fetchRange(0, 4);
    ok("a falling-back run logs exactly one fallback event",
      events.length === 1 && /\[DISCOVERY FALLBACK\]/.test(events[0]));
  }
  { // a THROWING log sink cannot decide the answer
    // the rejection is OBSERVED here rather than allowed to propagate: an unguarded sink
    // makes fetchRange reject, and a rejection escaping this block would end the run without
    // a named failure, which reads as a crash rather than as this property breaking
    const boom = () => { throw new Error("sink failed"); };
    const settle = async (d) => { try { return (await d.fetchRange(0, 4)).proved; } catch (e) { return `rejected: ${(e && e.message) || String(e)}`; } };
    const dOk = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: routeOver(range(0, 4)).fn, currentEpoch: 5,
      journalCaps: capsOf({}), figuresFor: testFigures, log: boom });
    ok("a throwing sink does not reject a proving run", (await settle(dOk)) === true);
    const dFail = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async () => { throw new Error("route down"); },
      currentEpoch: 5, journalCaps: capsOf({ 0: "cap0" }), figuresFor: testFigures, log: boom });
    ok("a throwing sink does not reject a falling-back run", (await settle(dFail)) === false);
  }
  { // A LONG HISTORY completes inside its derived budget, which is exact rather than picked:
    // the walk over a bound of 1764, the bench's own size, must prove and must use exactly
    // the number of reads the budget names
    const calls = [];
    const existing = range(0, 1764).filter((n) => n % 7 !== 0); // sparse, as the bench is
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async (a, b) => { calls.push(1);
      return answerOf(rowsOf(existing, a, b)); },
      currentEpoch: 1765, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    const r = await d.fetchRange(0, 1764);
    ok("a bench-sized sparse history proves", r.proved === true);
    // the expected count is a LITERAL, computed once by hand from the bound and the width
    // (1765 indices at 50 to a read is 36 reads), never requestBudget's own answer, because
    // comparing the walk against the same function the walk uses proves only that they agree
    ok("it uses exactly 36 walk reads plus one cross-check, the hand-computed number for a bound of 1764 at width 50",
      calls.length === 37);
    ok("the budget function agrees with that hand-computed number", requestBudget(1764, 50) === 36);
  }
  await wrapperCases();

  { // F1 THROUGH THE COMPOSITION: the reviewer's own sequence. The reference is epoch 120 and
    // every answer comes from a valid older snapshot at epoch 80, each complete for ITSELF.
    // Before the snapshot rule this produced proved:true over 80 epochs while 80..119 existed
    // below the run's bound.
    const existing = range(0, 119);
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN,
      readEpochInterval: async (a, b) => answerOf(rowsOf(existing, a, b), REF_HEIGHT - 100n),
      currentEpoch: 120, journalCaps: capsOf({ 5: "cap5" }), figuresFor: testFigures, log: noLog });
    const r = await d.fetchRange(0, 119);
    ok("an answer from a state older than the run's reference falls back to proved:false", r.proved === false);
    ok("the fallback serves the journal-derived epochs only",
      JSON.stringify(r.epochs) === JSON.stringify([{ number: 5, figures: "cap5" }]));
  }
  { // a height exactly at the reference is accepted, so the rule is not simply refusing
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN,
      readEpochInterval: async (a, b) => answerOf(rowsOf(range(0, 9), a, b), REF_HEIGHT),
      currentEpoch: 10, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    ok("a signed height exactly at the reference proves", (await d.fetchRange(0, 9)).proved === true);
  }
  { // THE REVIEWER'S OWN CONTROL, through the composition. Two answers identical except for the
    // metadata's EPOCH member, which no signature covers. The one at an older signed height must
    // refuse whatever its epoch claims, and bumping that epoch must change nothing.
    const older = (epochClaim) => createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN,
      readEpochInterval: async (a, b) => ({ epochs: rowsOf(range(0, 119), a, b),
        metadata: { height: REF_HEIGHT - 100n, chainId: CHAIN, epoch: epochClaim } }),
      currentEpoch: 120, journalCaps: capsOf({ 5: "cap5" }), figuresFor: testFigures, log: noLog });
    const asIs = await older(179).fetchRange(0, 119);
    const bumped = await older(189).fetchRange(0, 119);
    ok("an answer at an older signed height falls back, whatever epoch its metadata claims",
      asIs.proved === false && bumped.proved === false);
    ok("and raising only the unsigned epoch changes nothing about the answer",
      JSON.stringify(asIs) === JSON.stringify(bumped));
  }
  { // an answer from ANOTHER CHAIN refuses, since the chain is signed
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN,
      readEpochInterval: async (a, b) => answerOf(rowsOf(range(0, 9), a, b), REF_HEIGHT, "some-other-chain"),
      currentEpoch: 10, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    ok("an answer signed on another chain falls back to proved:false", (await d.fetchRange(0, 9)).proved === false);
  }
  { // THE BOUND CROSS-CHECK. The finality reference is the serving node's word, and understating
    // it would shrink the universe under a positive label. A finalized epoch AT or above the
    // claimed current epoch contradicts the claim, so the read above the bound settles it.
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN,
      readEpochInterval: routeOver(range(0, 60)).fn,
      currentEpoch: 30, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    ok("a finalized epoch above the claimed bound refuses, rather than proving a short universe",
      (await d.fetchRange(0, 29)).proved === false);
  }
  { // THE CROSS-CHECK'S OWN CHAIN CHECK, bound separately from the walk's. A review found that the
    // battery's chain mutation changed the shared helper globally, so the walk's case caught it
    // and this call site was never tested on its own.
    let call = 0;
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN,
      readEpochInterval: async (a, b) => { call++;
        return call === 1 ? answerOf(rowsOf(range(0, 9), a, b), REF_HEIGHT, CHAIN)
          : answerOf([], REF_HEIGHT, "some-other-chain"); },
      currentEpoch: 10, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    ok("a cross-check answered from another chain cannot settle the bound",
      (await d.fetchRange(0, 9)).proved === false);
  }
  { // A BOUNDED READ CANNOT ESTABLISH AN UNBOUNDED SUFFIX, and the record says so rather than the
    // code pretending otherwise. This is the reviewer's construction: finalized epochs 0 through
    // 9 and 100, with the reference understated to 10. The read over 10..59 is correctly empty,
    // epoch 100 is never looked for, and the walk proves a universe short at the top.
    const existing = [...range(0, 9), 100];
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN,
      readEpochInterval: routeOver(existing).fn, currentEpoch: 10,
      journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    const r = await d.fetchRange(0, 200);
    ok("an understatement whose omission lies beyond one interval is NOT caught here, which is why the claim is stated at that width",
      r.proved === true && r.epochs.length === 10 && !r.epochs.some((e) => e.number === 100));
  }
  { // ... and the same understatement IS caught when the omission falls inside the one read
    const existing = [...range(0, 9), 12];
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN,
      readEpochInterval: routeOver(existing).fn, currentEpoch: 10,
      journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    ok("an understatement whose omission falls within the one read above the bound refuses",
      (await d.fetchRange(0, 200)).proved === false);
  }
  { // ... and the cross-check itself is held to the same authentication as the walk
    let call = 0;
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN,
      readEpochInterval: async (a, b) => { call++;
        return call === 1 ? answerOf(rowsOf(range(0, 9), a, b), REF_HEIGHT)
          : answerOf([], REF_HEIGHT - 1n); },
      currentEpoch: 10, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    ok("a cross-check answered from an older state cannot settle the bound",
      (await d.fetchRange(0, 9)).proved === false);
  }
  { // the factory refuses without an authenticated reference at all
    let noHeight = false, noChain = false;
    try { createFetchRange({ chainIdPin: CHAIN, readEpochInterval: async () => ({ epochs: [] }), currentEpoch: 1, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog }); }
    catch (e) { noHeight = /reference signed height/.test(String(e.message)); }
    ok("a factory built without the reference height refuses", noHeight === true);
    try { createFetchRange({ referenceHeight: REF_HEIGHT, readEpochInterval: async () => ({ epochs: [] }), currentEpoch: 1, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog }); }
    catch (e) { noChain = /chain identity pin/.test(String(e.message)); }
    ok("a factory built without the chain pin refuses", noChain === true);
  }
  { // an answer with NO metadata cannot be placed, so it cannot support coverage
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async (a, b) => ({ epochs: rowsOf(range(0, 9), a, b) }),
      currentEpoch: 10, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog });
    ok("an answer with no metadata falls back to proved:false", (await d.fetchRange(0, 9)).proved === false);
  }
  { // F7: THE THREE DEFENSIVE GUARDS, each reached through an injected stepping rule. The
    // default rule is monotone, so nothing else can reach them, and a guard nothing reaches is
    // a guard nothing binds. Every injected step is itself checked by validateStep, which is
    // what keeps this from being an open hatch.
    const route = async (a, b) => answerOf(rowsOf(range(0, 119), a, b));
    const base = { referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: route, currentEpoch: 120, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog };
    // (a) a stepper that reports done before coverage reaches the bound: the coverage rule
    const early = createFetchRange({ ...base,
      nextIntervalFn: ({ coveredTo, bound, step }) => (coveredTo >= 49 ? { done: true } : nextInterval({ coveredTo, bound, step })) });
    ok("a stepper that stops before the bound cannot produce a positive label", (await early.fetchRange(0, 119)).proved === false);
    // (b) THE REQUEST BUDGET, reached by a stepper that advances one epoch at a time. The
    // budget is derived from the bound and the deployed width, 3 reads for a bound of 119 at
    // width 50, so a stepper needing 120 reads exhausts it and the run cannot carry a positive
    // label. This is the guard binding: before it, such a walk simply ran 120 times.
    const crawling = createFetchRange({ ...base,
      nextIntervalFn: ({ coveredTo, bound }) => (coveredTo >= bound ? { done: true } : { done: false, start: coveredTo + 1, end: coveredTo + 1 }) });
    ok("a stepper that exhausts the derived request budget cannot produce a positive label",
      (await crawling.fetchRange(0, 119)).proved === false);
    // THE BUDGET IS DERIVED FROM THE DEPLOYED WIDTH, so a stepper narrower than that one will
    // exhaust it, which is the correct direction: a walk that needs more reads than the run
    // budgeted refuses instead of running on. A custom stepper that keeps the deployed width
    // still proves, so the guard counts reads rather than objecting to a supplied rule.
    const customButSameWidth = createFetchRange({ ...base,
      nextIntervalFn: ({ coveredTo, bound }) => (coveredTo >= bound
        ? { done: true }
        : { done: false, start: coveredTo + 1, end: Math.min(coveredTo + INTERVAL_STEP, bound) }) });
    ok("a supplied stepper at the deployed width still proves", (await customButSameWidth.fetchRange(0, 119)).proved === true);
    // (c) a stepper that asks for a step validateStep must refuse
    // A STEPPER THAT SKIPS ONE EPOCH AND STAYS INSIDE THE BUDGET. The width and the read count
    // both look ordinary, three reads at width 50, so neither the budget nor the coverage rule
    // notices; only the step check's start condition does. Without it the run would carry a
    // positive label over a universe silently missing epochs 50 and 101.
    const skipping = createFetchRange({ ...base,
      nextIntervalFn: ({ coveredTo, bound }) => {
        if (coveredTo >= bound) return { done: true };
        const start = coveredTo + (coveredTo === -1 ? 1 : 2);
        return { done: false, start, end: Math.min(start + INTERVAL_STEP - 1, bound) };
      } });
    ok("a stepper that skips one epoch, within the budget and at the deployed width, cannot produce a positive label",
      (await skipping.fetchRange(0, 119)).proved === false);
    const tooWide = createFetchRange({ ...base,
      nextIntervalFn: ({ coveredTo, bound }) => (coveredTo >= bound ? { done: true } : { done: false, start: coveredTo + 1, end: Math.min(coveredTo + MAX_INTERVAL_WIDTH + 1, bound) }) });
    ok("a stepper asking wider than the route's cap cannot produce a positive label",
      (await tooWide.fetchRange(0, 119)).proved === false);
    let badFn = false;
    try { createFetchRange({ ...base, nextIntervalFn: 7 }); } catch (e) { badFn = /must be a function/.test(String(e.message)); }
    ok("a non-function stepping rule refuses at construction", badFn === true);
  }
  { // THE BUDGET GUARD, reached by a stepper that advances by zero width. validateStep permits
    // start === coveredTo + 1 with end === start, which is the narrowest legal step, so a
    // stepper that returns to the same interval is caught by the progress guard rather than
    // running forever.
    const d = createFetchRange({ referenceHeight: REF_HEIGHT, chainIdPin: CHAIN, readEpochInterval: async (a, b) => answerOf(rowsOf(range(0, 119), a, b)),
      currentEpoch: 120, journalCaps: capsOf({}), figuresFor: testFigures, log: noLog,
      nextIntervalFn: () => ({ done: false, start: 0, end: 0 }) });
    ok("a stepper that never leaves its first interval cannot produce a positive label",
      (await d.fetchRange(0, 119)).proved === false);
  }

  // ---- THE RUNNER BINDING SWEEP ----
  // The composition above is only as good as what the deployed runners inject into it. These
  // read the two runners' own source beside this test and bind three properties each: the
  // universe is enumerated through the finalized-epoch INTERVAL route, an answer whose status
  // is not proved is refused rather than used, and the count-based route is no longer the
  // discovery input. A sweep is a coarse instrument and it is stated as one; it exists
  // because no offline battery can otherwise see a runner reverting to the old route.
  const fs = require("fs");
  const path = require("path");
  for (const runner of ["e2ForwardTransportRun.mjs", "e2AuditRun.mjs"]) {
    const src = runnerSource(runner);
    if (src === null) { skipped += 1; console.log(skipNote(runner, "the interval-route sweep")); continue; }
    // THE WRAPPER IS NO LONGER INLINE. It used to be written out in each runner, where the
    // only instrument was this sweep's source text, and the review executed three real
    // substitutions that survived it: dropping the last row of the answer, disabling the
    // status check, and answering a fixed identity. The wrapper now lives in the module and
    // is driven by the cases above, so the sweep only has to bind the injection itself.
    ok(`${runner} binds the shared interval wrapper EXACTLY ONCE`,
      src.split("makeReadEpochInterval({").length - 1 === 1);
    ok(`${runner} keeps no inline wrapper body beside it`,
      !/const readEpochInterval = async \(startEpoch, endEpoch\) =>/.test(src));
    ok(`${runner} hands the wrapper the finalized-epoch route with its verifier bound`,
      /readFinalizedInterval: \(startEpoch, endEpoch\) =>\s*\n?\s*getFinalizedEpochInfos\(sdk\.grpcPool, \{ startEpoch, endEpoch, prove: true, verifyProof: makeVerifyProof\(\) \}\)/.test(src));
    ok(`${runner} no longer injects the count-based epochs route into discovery`,
      !/getEpochsInfo:/.test(src));
  }
  ok("the forward runner hands the interval route to the v2 composition",
    (() => { const s2 = runnerSource("e2ForwardTransportRun.mjs");
      if (s2 === null) { return "SKIP"; } return /readEpochInterval,/.test(s2); })() !== false);
  ok("the audit runner hands the interval route to the discovery factory",
    (() => { const s2 = runnerSource("e2AuditRun.mjs");
      if (s2 === null) { return "SKIP"; }
      return new RegExp("createFetchRange\\(\\{\\s*\\n\\s*readEpochInterval,").test(s2); })() !== false);

  console.log(`e2EpochDiscoveryGateTest: ${passed} passed, ${failed} failed` + (skipped ? `, ${skipped} skipped (counted, never folded into passes)` : ""));
  process.exitCode = failed ? 1 : 0;
})();
