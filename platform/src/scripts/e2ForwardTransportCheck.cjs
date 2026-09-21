/**
 * e2ForwardTransportCheck: THE LIVE TRANSPORT CHECK, the acceptance-capable
 * instrument a soundness-review finding asked for. The first runner recorded a failed prediction
 * as an observation and exited zero, so it could not accept anything. This
 * module is the observation flow, the validator and the provenance assembler,
 * pure and offline-testable; the .mjs runner is a thin live composition that
 * supplies the real query, the real identifiers and the real provenance, writes
 * the artifact and turns the verdict into an exit code.
 *
 * WHAT IT ESTABLISHES, in one sentence: a run is compared against a
 * PREDECLARED expectation profile by named checks, each required check that
 * fails is reported with its detail and fails the run in acceptance mode, and
 * the saved artifact identifies what ran, what it ran against, what was
 * supplied by hand, and which profile it was checked against.
 *
 * THE OBSERVATION FLOW (unchanged from the first runner in what it reads, at
 * the bootstrap pool's epoch through the REAL adapter): the header, the accrual
 * enumeration, per funder the accrual and its dependents, the sweep shapes by
 * hand against an absent accrual, the OLD receipt clause issued RAW, and the
 * composition of adapter, acquisition and kernel over a plan DERIVED from the
 * served records with planned identifiers computed by the injected derivation
 * and the self-share classification supplied by the caller. Identifiers are
 * saved IN FULL; display shortening is the printer's business.
 *
 * THE CHECKS, one table, each a named predicate over the observations:
 *   allReadsVerified               every ADAPTER transport call verified (none
 *                                  unserved or unverified), the failures named;
 *                                  the raw old-clause probe is outside the log
 *   headerServedOne                exactly one header document served
 *   enumerationMatchesMemberCount  N served equals header.memberCount, N <= 8
 *   oldClauseRefusedWithIndexError the raw old clause NOT served and its error,
 *                                  percent-decoded, BEGINNING with the platform's
 *                                  own "where clause on non indexed property
 *                                  error: query must be for valid indexes"; any
 *                                  other exception FAILS the check (text is all
 *                                  the transport exposes, so this is anchored
 *                                  text, not a structured error code)
 *   plannedEqualsServed            every planned identifier equals its served one
 *   compositionState               the kernel's state equals the profile's
 *                                  (any of the four; complete is not hardcoded)
 *   compositionReasons             the reason codes equal the profile's list
 *   heightSpanMax                  max height minus min height <= the profile's
 *   sweepAgainstAbsentEmpty        the three sweep components served empty
 * A check the profile lists under `required` fails the run; under `optional`
 * it is reported only. An unknown check name refuses the profile.
 *
 * ONE CAPTURED ARGUMENT. runTransportCheck takes one arguments object: its
 * three functions are read through their own data descriptors, and everything
 * else is captured as plain data in ONE walk before any validation reads a
 * caller's member (the confirmation round found a getter on the target
 * reshaping the profile ahead of the profile's own capture). THE ARTIFACT IS
 * REPRODUCIBLE EVIDENCE: it retains every served document's fields in the
 * transport log, the plan input, the acquisition evidence bundle and the
 * verdict inputs and outputs, and `reconstruct(artifact)` re-evaluates the
 * kernel over them offline and reports whether the result matches what the
 * artifact states.
 *
 * THE PROVENANCE (the review's F2 list, every member required, refused by
 * name when absent): sourceCommit, treeState (clean or dirty), diffSha256 (of
 * the working-tree diff against the commit, the empty diff's hash when clean),
 * inputHashes (runner, check, the whole mounted source tree, ledgerModule,
 * patches by name, at least one), the full
 * contractId, chainId, contractVersion, poolId, epochIndex, the full
 * classificationInput, the expectationProfile's path and sha256, explicit
 * synthetic labels (planValues, transferVerdict, selfShare), and the time.
 *
 * THE V2 MODE (the per-epoch context design, section 7, build-order step 5): a profile of
 * kind `tegara.e2.forwardTransportProfile.v2` selects the CONTEXT-DRIVEN run. Nothing is
 * derived from served records and no self-share list is taken: the caller supplies
 * `contextFor(epochIndex)`, the per-epoch context of e2EpochContext.cjs built from the
 * proved formation, the journal and a declared fixture; `universe`, the finalized epoch set
 * discovery returned at run start, FIXED for the run; and `captureFor` with `deps`, from
 * which THIS module builds each epoch's verdict closure through
 * e2EpochContext.executionVerdictFor, so the verdict owner is the shared verifier by
 * construction. The run captures every universe epoch's plan input BEFORE its first adapter
 * read (the adapter's read count at that moment is recorded), runs the nine v1 observations
 * at the target epoch, then the orchestrator loop of design section 5: generation 0 evaluates
 * every universe epoch (a precondition context becomes the kernel's unprovedPrecondition
 * result, never a plan), one snapshot per generation, and after each universe epoch's
 * selection (the projection answer recorded with its generation; an unproved epoch STALLS,
 * its work skipped, and the run continues) one further generation, so a normal run takes
 * exactly universe.length + 1 generations; a snapshot holding a REFUSED epoch, selected or
 * not, stops the run by name and the artifact records `earlyStop: { afterGeneration, code,
 * epochIndex, reason }`, which only a separate early-stop profile naming the generation, the
 * code and the epoch may accept. The v2 checks, each a predicate over the observations:
 *   planBuiltBeforeAnyRead      every plan input derived at adapter read count zero, and at
 *                               least one derived
 *   planFiguresSource           the target epoch's context label equals the profile's
 *   planHeaderEqualsFormation   every plan header's allocationHash and memberCount equal
 *                               its context's formation (never a served header's)
 *   selfShareDerived            every isSelfShare equals funderId === incomeIdentity, and
 *                               no self-share argument was supplied
 *   identifiersCanonical        every identifier in every plan input is 64 lowercase hex
 *   verdictOwner                the provenance label is shared-verifier and every closure
 *                               was built by executionVerdictFor (constant-capture-verified
 *                               is refused for v2, D3)
 *   freshEpochPrecondition      a universe epoch other than the target carries the C1
 *                               precondition, no plan was built for it, no read was issued
 *                               under it, and the projection refused it by name
 *   universe                    equals the profile's list, unchanged across generations
 *   refreshCountMax             generations taken <= the profile's value and <= universe+1
 *   generationSequence          EXACTLY the profile's list
 *   earlyStop                   null, or { afterGeneration, code, epochIndex } equal to the
 *                               profile's (the reason text is recorded, never matched)
 *
 * WHAT IT DOES NOT ESTABLISH: that the injected query verifies proofs (the
 * transport's obligation), that the profile is the right prediction (its
 * author's), or anything the artifact does not carry.
 */
"use strict";

const crypto = require("crypto");
const { canonicalString } = require("./canonicalJson.cjs");
const { plainDataSnapshot } = require("./e2ProvedQuery.cjs");
const { createForwardAdapter } = require("./e2ForwardAdapter.cjs");
const A = require("./e2Acquire.cjs");
const K = require("./e2ForwardKernel.cjs");
const X = require("./e2EpochContext.cjs");

const HEX64 = /^[0-9a-f]{64}$/;
const refuse = (why) => { throw new Error(`e2ForwardTransportCheck: ${why}; refusing`); };
const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const deepFreeze = (v) => { if (v && typeof v === "object") { Object.freeze(v); for (const k of Object.keys(v)) deepFreeze(v[k]); } return v; };
// EVERY CALLER INPUT IS CAPTURED AS PLAIN DATA AT ENTRY through the page
// checker's own walk (e2ProvedQuery's plainDataSnapshot): it reads own data
// descriptors only, refuses accessors, functions, foreign prototypes and
// cycles, and RECONSTRUCTS a fresh plain graph, so no serializer of the
// caller's (a toJSON, own or inherited) and no later mutation can make the
// evaluated representation differ from the validated one. JSON.stringify is
// never called on a caller's object. WIDTH: a Proxy reporting a plain
// prototype can still trap the descriptor reads, the same width the walk
// states for itself; and the walk cannot see a toJSON installed on
// Object.prototype itself, a process-wide change outside any module's reach.
const capture = (v, what) => { const { defect, value } = plainDataSnapshot(v); if (defect) refuse(`${what} ${what === "the arguments" ? "are" : "is"} not plain data (${defect})`); return value; };
const decodeSafe = (t) => { try { return decodeURIComponent(t); } catch { return t; } };
const msgOf = (e) => { try { const m = e && e.message; if (typeof m === "string") return m; } catch { /* fall through */ } return String(e); };

// ---- the profile ----
const PROFILE_KIND = "tegara.e2.forwardTransportProfile.v1";
const PROFILE_KIND_V2 = "tegara.e2.forwardTransportProfile.v2";
const CHECKS = Object.freeze(["allReadsVerified", "headerServedOne", "enumerationMatchesMemberCount", "oldClauseRefusedWithIndexError",
  "plannedEqualsServed", "compositionState", "compositionReasons", "heightSpanMax", "sweepAgainstAbsentEmpty"]);
const CHECKS_V2_ONLY = Object.freeze(["planBuiltBeforeAnyRead", "planFiguresSource", "planHeaderEqualsFormation", "selfShareDerived",
  "identifiersCanonical", "verdictOwner", "freshEpochPrecondition", "universe", "refreshCountMax", "generationSequence", "earlyStop"]);
const CHECKS_V2 = Object.freeze([...CHECKS, ...CHECKS_V2_ONLY]);
// THE V2 LABELS ARE FIXED: a v2 run derives its plan values, its self-share classification
// and its verdict owner by construction, so the provenance may state nothing else (D3: a
// context run whose complete depends on the constant verdict is not accepted)
const V2_SYNTHETIC = Object.freeze({ planValues: "derived-from-formation-and-calculation", selfShare: "derived-from-income-identity", transferVerdict: "shared-verifier" });
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const kindOf = (p) => (isPlain(p) && own(p, "kind") && p.kind === PROFILE_KIND_V2 ? 2 : 1);
// VALIDATION READS OWN PROPERTIES ONLY (an inherited member would pass a lookup
// and vanish from the JSON copy the run evaluates), and runTransportCheck
// validates the COPIED representation, not the caller's object
const validateProfile = (p) => {
  if (!isPlain(p) || !own(p, "kind") || (p.kind !== PROFILE_KIND && p.kind !== PROFILE_KIND_V2)) refuse(`profile kind must be ${PROFILE_KIND} or ${PROFILE_KIND_V2} (an own property)`);
  const v2 = p.kind === PROFILE_KIND_V2;
  const checks = v2 ? CHECKS_V2 : CHECKS;
  if (own(p, "toJSON")) refuse("profile must not carry a toJSON member (the evaluated copy would differ from the validated object)");
  for (const section of ["required", "optional"]) {
    if (!own(p, section) || !isPlain(p[section])) refuse(`profile.${section} must be an own plain object`);
    if (Object.getPrototypeOf(p[section]) !== Object.prototype && Object.getPrototypeOf(p[section]) !== null) refuse(`profile.${section} must have a plain prototype`);
    for (const k of Object.keys(p[section])) if (!checks.includes(k)) refuse(`profile.${section} names unknown check ${k}`);
  }
  for (const k of (v2 ? ACCEPTANCE_MINIMUM_V2 : ACCEPTANCE_MINIMUM)) if (!own(p.required, k)) refuse(`profile.required must carry ${k} as an own member (an acceptance profile that requires less passes vacuously)`);
  // EVERY SUPPLIED VALUE IS VALIDATED IN ITS OWN SECTION (the checker's construction: a
  // valid required value concealed an invalid optional one under a merged view), and a
  // check named in both sections is refused, since the run would evaluate both
  for (const k of Object.keys(p.optional)) if (own(p.required, k)) refuse(`profile names ${k} under both required and optional`);
  for (const section of ["required", "optional"]) {
    const all = p[section];
    // a member supplied as undefined is refused, not skipped (the exported validator's
    // contract is every supplied value; the run's capture refuses undefined on its own)
    for (const k of Object.keys(all)) if (all[k] === undefined) refuse(`profile.${section}.${k} is supplied as undefined; omit the check or give it a value`);
    if (all.compositionState !== undefined && !K.STATES.includes(all.compositionState)) refuse(`profile compositionState ${JSON.stringify(all.compositionState)} is not a kernel state`);
    if (all.compositionReasons !== undefined && !Array.isArray(all.compositionReasons)) refuse("profile compositionReasons must be an array of codes");
    if (all.heightSpanMax !== undefined && !(Number.isSafeInteger(all.heightSpanMax) && all.heightSpanMax >= 0)) refuse("profile heightSpanMax must be a non-negative safe integer");
    for (const k of ["allReadsVerified", "headerServedOne", "enumerationMatchesMemberCount", "oldClauseRefusedWithIndexError", "plannedEqualsServed", "sweepAgainstAbsentEmpty"]) if (all[k] !== undefined && all[k] !== true) refuse(`profile ${k} takes only true`);
    if (v2) {
      if (all.planFiguresSource !== undefined && !X.FIGURES_SOURCES.includes(all.planFiguresSource)) refuse(`profile planFiguresSource ${JSON.stringify(all.planFiguresSource)} is not a context figures source`);
      if (all.verdictOwner !== undefined && all.verdictOwner !== "shared-verifier") refuse(`profile verdictOwner must be shared-verifier (D3: ${JSON.stringify(all.verdictOwner)} is not accepted for a v2 run)`);
      if (all.universe !== undefined && !(Array.isArray(all.universe) && all.universe.length > 0 && all.universe.every((n, i) => Number.isSafeInteger(n) && n >= 0 && (i === 0 || n > all.universe[i - 1])))) refuse("profile universe must be a non-empty strictly ascending array of non-negative safe integers");
      if (all.refreshCountMax !== undefined && !(Number.isSafeInteger(all.refreshCountMax) && all.refreshCountMax >= 1)) refuse("profile refreshCountMax must be a positive safe integer");
      if (all.generationSequence !== undefined && !(Array.isArray(all.generationSequence) && all.generationSequence.length > 0 && all.generationSequence.every((g, i) => g === i))) refuse("profile generationSequence must be the exact list 0, 1, ... of the generations expected");
      // an expected early stop names its generation, its code and its epoch as STRUCTURED
      // fields (the checker's finding: a reason prefix matched any stop, and "epoch 1"
      // matched epoch 10); the reason text is recorded, never matched
      if (all.earlyStop !== undefined && all.earlyStop !== null && !(isPlain(all.earlyStop) && Number.isSafeInteger(all.earlyStop.afterGeneration) && all.earlyStop.afterGeneration >= 0 && EARLY_STOP_CODES.includes(all.earlyStop.code) && Number.isSafeInteger(all.earlyStop.epochIndex) && all.earlyStop.epochIndex >= 0)) refuse(`profile earlyStop must be null or { afterGeneration, code (one of ${EARLY_STOP_CODES.join("/")}), epochIndex }`);
      if (all.earlyStop && all.generationSequence !== undefined && all.earlyStop.afterGeneration !== all.generationSequence.length - 1) refuse("profile earlyStop.afterGeneration must be the last generation of generationSequence (a stop after generation g leaves generations 0..g)");
      for (const k of ["planBuiltBeforeAnyRead", "planHeaderEqualsFormation", "selfShareDerived", "identifiersCanonical", "freshEpochPrecondition"]) if (all[k] !== undefined && all[k] !== true) refuse(`profile ${k} takes only true`);
    }
  }
  return p;
};
// the two ways a run stops by name: a snapshot holding a REFUSED epoch (any universe epoch,
// selected or not: retrying cannot correct a record that is wrong on the ledger), and the
// refresh bound, which the loop's construction makes unreachable and is kept as a guard
const EARLY_STOP_CODES = Object.freeze(["REFUSED_EPOCH_IN_SNAPSHOT", "REFRESH_BOUND_EXCEEDED"]);
// the per-epoch context's own members, exactly (e2EpochContext.cjs's buildEpochContext)
const CONTEXT_KEYS = Object.freeze(["kind", "scope", "formation", "figuresSource", "figures", "rows", "encodingRefused", "precondition"]);
// the identity is the hash of the CANONICAL serialization (sorted keys, the
// repository's own canonicalJson), so two insertion orders of one profile agree
const profileIdentity = (p) => crypto.createHash("sha256").update(canonicalString(p)).digest("hex");
// ACCEPTANCE MEANS AT LEAST THESE ARE REQUIRED: a profile that requires nothing
// would pass vacuously on every run, which is the unchecked-means-passed shape
const ACCEPTANCE_MINIMUM = Object.freeze(["allReadsVerified", "compositionState"]);
// a v2 acceptance profile must also bind the verdict owner, the exact generation sequence,
// the early-stop record and the universe, or a prematurely stopped or constant-verdict run
// could pass a profile that never asked
const ACCEPTANCE_MINIMUM_V2 = Object.freeze(["allReadsVerified", "compositionState", "verdictOwner", "generationSequence", "earlyStop", "universe"]);

// ---- the provenance ----
const PROVENANCE_KEYS = ["sourceCommit", "treeState", "diffSha256", "inputHashes", "contractId", "chainId", "contractVersion", "poolId", "epochIndex", "classificationInput", "expectationProfile", "synthetic", "at"];
const assembleProvenance = (input, kind = 1) => {
  if (!isPlain(input)) refuse("provenance must be a plain object");
  // CAPTURED FIRST, VALIDATED AFTER, on the capture: a getter, a serializer or
  // a later mutation on the caller's object cannot sit between the two
  const p = capture(input, "provenance");
  for (const k of PROVENANCE_KEYS) if (p[k] === undefined || p[k] === null) refuse(`provenance.${k} is required`);
  if (typeof p.sourceCommit !== "string" || !/^[0-9a-f]{7,40}$/.test(p.sourceCommit)) refuse("provenance.sourceCommit must be a git commit hash (7 to 40 hex)");
  if (typeof p.chainId !== "string" || p.chainId.length === 0) refuse("provenance.chainId must be a non-empty string");
  if (!Number.isSafeInteger(p.contractVersion) || p.contractVersion < 1) refuse("provenance.contractVersion must be a positive integer");
  if (!["clean", "dirty"].includes(p.treeState)) refuse("provenance.treeState must be clean or dirty");
  if (!HEX64.test(p.diffSha256)) refuse("provenance.diffSha256 must be a sha256 hex");
  if (!isPlain(p.inputHashes)) refuse("provenance.inputHashes must be a plain object");
  for (const k of ["runner", "check", "ledgerModule"]) if (!HEX64.test(p.inputHashes[k] || "")) refuse(`provenance.inputHashes.${k} must be a sha256 hex`);
  if (!HEX64.test(p.inputHashes.sourceTree || "")) refuse("provenance.inputHashes.sourceTree must be a sha256 hex over the whole mounted source tree");
  if (!isPlain(p.inputHashes.patches) || Object.keys(p.inputHashes.patches).length === 0) refuse("provenance.inputHashes.patches must name at least one mounted patch with its sha256");
  for (const [n, h] of Object.entries(p.inputHashes.patches)) if (!HEX64.test(h)) refuse(`provenance.inputHashes.patches.${n} must be a sha256 hex`);
  if (!HEX64.test(p.contractId)) refuse("provenance.contractId must be 64-hex");
  if (!HEX64.test(p.poolId)) refuse("provenance.poolId must be 64-hex");
  if (!Number.isSafeInteger(p.epochIndex) || p.epochIndex < 0) refuse("provenance.epochIndex must be a non-negative safe integer");
  if (kind === 2) {
    // a v2 run classifies from the income identity and takes no self-share list
    if (!isPlain(p.classificationInput) || !HEX64.test(p.classificationInput.incomeIdentity || "") || own(p.classificationInput, "selfShares")) refuse("provenance.classificationInput must carry the 64-hex incomeIdentity the run classifies with and no selfShares (a v2 run derives the classification)");
  } else {
    if (!isPlain(p.classificationInput) || !Array.isArray(p.classificationInput.selfShares)) refuse("provenance.classificationInput.selfShares must be an array");
    for (const s of p.classificationInput.selfShares) if (typeof s !== "string" || !HEX64.test(s)) refuse("provenance.classificationInput.selfShares must be 64-hex PRIMITIVE strings in full");
  }
  if (!isPlain(p.expectationProfile) || typeof p.expectationProfile.path !== "string" || p.expectationProfile.path.length === 0 || !HEX64.test(p.expectationProfile.sha256 || "")) refuse("provenance.expectationProfile needs a non-empty path and sha256");
  if (!isPlain(p.synthetic)) refuse("provenance.synthetic must be a plain object");
  for (const k of ["planValues", "transferVerdict", "selfShare"]) if (typeof p.synthetic[k] !== "string" || p.synthetic[k].length === 0) refuse(`provenance.synthetic.${k} must state the label`);
  if (kind === 2) {
    for (const k of Object.keys(V2_SYNTHETIC)) if (p.synthetic[k] !== V2_SYNTHETIC[k]) refuse(`provenance.synthetic.${k} must be ${JSON.stringify(V2_SYNTHETIC[k])} for a v2 run (got ${JSON.stringify(p.synthetic[k])}); the labels are fixed by construction`);
    const extra = Object.keys(p.synthetic).filter((k) => !own(V2_SYNTHETIC, k));
    if (extra.length) refuse(`provenance.synthetic carries ${extra.join(",")} beside the three fixed v2 labels; the record is exactly those three`);
  }
  if (typeof p.at !== "string" || Number.isNaN(Date.parse(p.at))) refuse("provenance.at must be an ISO time");
  const out = {}; for (const k of PROVENANCE_KEYS) out[k] = p[k];
  return deepFreeze(out);
};

// ---- the run ----
// ONE CAPTURED ARGUMENT (the confirmation round's finding): the three function
// members are read through their own data descriptors (an accessor-backed one is
// refused, its getter never invoked), and EVERYTHING ELSE is captured as plain
// data in ONE walk before any validation reads a caller's member. Nothing below
// touches the caller's objects again; there is no per-input capture site left
// for a getter to run ahead of.
const FN_ARGS = Object.freeze(["query", "plannedIdFor", "executionVerdict"]);
const DATA_ARGS = Object.freeze(["ledger", "profile", "provenance", "acceptance", "target", "selfShares"]);
// the v2 arguments: the context supplier and the capture lookup are functions, `deps` is an
// object OF functions read through its own descriptor and handed to executionVerdictFor,
// which captures it (it is not walked, since the walk refuses functions), and `universe`
// is data; the v1-only arguments are refused for a v2 run, so a self-share list or a
// constant verdict cannot reach a context-driven run
const FN_ARGS_V2 = Object.freeze(["query", "contextFor", "captureFor"]);
const REF_ARGS_V2 = Object.freeze(["deps"]);
const DATA_ARGS_V2 = Object.freeze(["ledger", "profile", "provenance", "acceptance", "target", "universe"]);
const readOwnValue = (args, k, what) => {
  const d = Object.getOwnPropertyDescriptor(args, k);
  if (!d) refuse(`runTransportCheck needs ${what} ${k}`);
  if (!Object.prototype.hasOwnProperty.call(d, "value")) refuse(k === "query" || k === "plannedIdFor" || k === "executionVerdict" || k === "contextFor" || k === "captureFor" || k === "deps"
    ? `the argument ${k} is accessor-backed; a getter is not a stable argument`
    : `the arguments are not plain data (the argument ${k} is accessor-backed)`);
  return d.value;
};
const takeArguments = (args) => {
  if (!isPlain(args)) refuse("runTransportCheck needs one plain arguments object");
  // THE PROFILE IS CAPTURED FIRST, ALONE, and the kind that selects the argument set is the
  // CAPTURED copy's: a getter on the caller's `kind` (self-replacing or not) is refused by
  // the capture before it can select a mode, so the profile the run validates is the one
  // whose kind chose the run (the checker's construction: a v1 profile whose kind answered
  // v2 once, selecting the v2 runner with the v1 acceptance minimum)
  const profileCaptured = capture({ profile: readOwnValue(args, "profile", "the argument") }, "the arguments").profile;
  const kind = kindOf(profileCaptured);
  const fnNames = kind === 2 ? FN_ARGS_V2 : FN_ARGS;
  const dataNames = kind === 2 ? DATA_ARGS_V2 : DATA_ARGS;
  const fns = {}, data = {};
  for (const k of fnNames) {
    const v = readOwnValue(args, k, "the injected");
    if (typeof v !== "function") refuse(`the argument ${k} must be a function`);
    fns[k] = v;
  }
  if (kind === 2) {
    for (const k of ["plannedIdFor", "executionVerdict", "selfShares"]) if (own(args, k)) refuse(`a v2 run derives ${k === "selfShares" ? "the self-share classification" : k === "plannedIdFor" ? "the planned identifiers" : "the execution verdict"} from the context and takes no ${k} argument`);
    for (const k of REF_ARGS_V2) {
      const v = readOwnValue(args, k, "the argument");
      if (!isPlain(v)) refuse(`the argument ${k} must be a plain object of the verifier's dependencies`);
      // THE BUNDLE IS VALIDATED HERE, whether or not a closure will be built (the checker's
      // construction: a universe of precondition epochs built no closure and an empty
      // bundle was admitted); the context module captures it again when a closure is built
      const ownOrAbsent = (o, name, where) => { const d = Object.getOwnPropertyDescriptor(o, name); if (!d) return undefined; if (!Object.prototype.hasOwnProperty.call(d, "value")) refuse(`the argument ${where}.${name} is accessor-backed; a getter is not a stable argument`); return d.value; };
      const vd = ownOrAbsent(v, "verifierDeps", "deps");
      if (!isPlain(vd)) refuse("deps.verifierDeps must be a plain object carrying the verifier's stage functions as own data members");
      // THE FUNCTIONS ARE CAPTURED HERE into a frozen private bundle, and that bundle, never
      // the caller's object, is what the closures are built over (the repository-access
      // round's construction: a context supplier replacing a member between entry and the
      // closure's construction would otherwise supply the verifier a function nobody validated)
      const verifierDeps = {};
      for (const f of X.VERIFIER_DEPS) { const fn = ownOrAbsent(vd, f, "deps.verifierDeps"); if (typeof fn !== "function") refuse(`deps.verifierDeps.${f} must be a function (the verifier's pipeline is incomplete)`); verifierDeps[f] = fn; }
      const verifyCaptureBasis = ownOrAbsent(v, "verifyCaptureBasis", "deps");
      if (typeof verifyCaptureBasis !== "function") refuse("deps.verifyCaptureBasis must be a function (the capture-basis adapter)");
      fns[k] = Object.freeze({ verifierDeps: Object.freeze(verifierDeps), verifyCaptureBasis });
    }
  } else if (own(args, "contextFor") || own(args, "captureFor") || own(args, "universe")) {
    refuse("a v1 run derives its plan from served records and takes no contextFor, captureFor or universe argument (a v2 profile selects the context-driven run)");
  }
  for (const k of dataNames) if (k !== "profile") data[k] = readOwnValue(args, k, "the argument");
  return { ...fns, ...capture(data, "the arguments"), profile: profileCaptured, kind };
};

// ---- shared by both modes: the transport log, the provenance binding, the acceptance block ----
const makeTransport = (query, target) => {
  const transportLog = [];
  const fetchVerifiedPage = async ({ contractId, type, where, orderBy, limit, startAfter }) => {
    const entry = { type, where, orderBy, limit, startAfter };
    transportLog.push(entry);
    try {
      if (contractId !== target.contractId) { entry.result = "unserved:contract"; return { status: "unserved" }; }
      if (startAfter !== null && startAfter !== undefined) { entry.result = "unserved:cursor"; return { status: "unserved" }; }
      const { documents, height } = await query(type, where, { orderBy, limit });
      const sorted = [...documents].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
      entry.result = `verified:${sorted.length}@${height}`;
      entry.documents = JSON.parse(JSON.stringify(sorted));   // the served fields, retained as evidence
      return { status: "verified", height, documents: sorted };
    } catch (e) {
      const status = e && e.noMarker ? "unverified" : "unserved";
      entry.result = `${status}:${msgOf(e)}`;
      return { status };
    }
  };
  return { transportLog, transport: { route: "documents.query(prove,marker)", provesResult: true, fetchVerifiedPage } };
};
// THE PROVENANCE IS BOUND TO WHAT RUNS: the scope the artifact records must be the one this
// run uses, or the artifact would describe a different execution
const bindProvenanceToTarget = (prov, target) => {
  for (const k of ["contractId", "chainId", "contractVersion", "poolId", "epochIndex"]) {
    if (prov[k] !== target[k]) refuse(`provenance.${k} (${String(prov[k]).slice(0, 16)}) does not equal the run's target ${k} (${String(target[k]).slice(0, 16)}); an artifact must describe the execution it records`);
  }
};
const deeplyFrozen = (v, seen = new Set()) => { if (v === null || typeof v !== "object") return true; if (seen.has(v)) return true; seen.add(v); if (!Object.isFrozen(v)) return false; return Object.getOwnPropertyNames(v).every((k) => { const d = Object.getOwnPropertyDescriptor(v, k); return "value" in d && deeplyFrozen(d.value, seen); }); };
const acceptanceBlock = (acceptance) => (acceptance ? { mode: "acceptance" } : { mode: "observe", disclaimer: "this run is not an acceptance result; failed required checks do not fail the run in observe mode" });
const exitCodeFor = (acceptance, pass) => (acceptance && !pass ? 1 : 0);

// ---- the observation flow at the target epoch, shared by both modes (observations 4 to 11) ----
const observeTargetEpoch = async ({ adapter, query, obs, POOL, EPOCH }) => {
  const desc = (q, type, where, limit, subjectAccrualId = null) => Object.freeze({ kind: "tegara.e2.queryDescriptor.v1", query: q, type,
    where: Object.freeze(where.map((c) => Object.freeze(c))), limit, subjectAccrualId });
  const summarize = (ans) => (ans.status !== "served" ? { status: ans.status }
    : { status: "served", proved: ans.proved, route: ans.route, height: ans.height, count: ans.documents.length, ids: ans.documents.map((d) => d.id) });

  const header = await adapter.readPage(desc("header", "epochHeader", [["poolId", "==", POOL], ["epochIndex", "==", EPOCH]], 2));
  const headerFields = header.status === "served" && header.documents.length === 1 ? header.documents[0].fields : null;
  obs("4.header", summarize(header));
  const enumeration = await adapter.readPage(desc("accrualEnumeration", "platformAccrual", [["poolId", "==", POOL], ["epochIndex", "==", EPOCH]], 9));
  obs("5.accrualEnumeration", { ...summarize(enumeration), memberCount: headerFields ? headerFields.memberCount : null });
  const funders = enumeration.status === "served" ? enumeration.documents.map((d) => ({ funderId: d.fields.funderId, servedId: d.id, fields: d.fields })) : [];
  let servedAccrualForRaw = null;
  for (const f of funders) {
    const acc = await adapter.readPage(desc("accrual", "platformAccrual", [["poolId", "==", POOL], ["funderId", "==", f.funderId], ["epochIndex", "==", EPOCH]], 2));
    const accId = acc.status === "served" && acc.documents.length ? acc.documents[0].id : null;
    if (accId && !servedAccrualForRaw) servedAccrualForRaw = accId;
    const row = { funder: f.funderId, accrual: summarize(acc), sameAsEnumeration: accId === f.servedId };
    if (accId) {
      row.reservationPinned = summarize(await adapter.readPage(desc("reservationPinned", "transferReservation", [["poolId", "==", POOL], ["accrualId", "==", accId]], 2, accId)));
      row.reservationEnumerated = summarize(await adapter.readPage(desc("reservationEnumerated", "transferReservation", [["poolId", "==", POOL], ["accrualId", "==", accId]], 2, accId)));
      const rcpt = await adapter.readPage(desc("receipt", "transferReceipt", [["accrualId", "==", accId]], 2, accId));
      row.receipt = { ...summarize(rcpt), poolMatches: rcpt.status === "served" && rcpt.documents.length ? rcpt.documents[0].fields.poolId === POOL : null,
        proofPartCount: rcpt.status === "served" && rcpt.documents.length ? rcpt.documents[0].fields.proofPartCount : null };
      const parts = await adapter.readPage(desc("parts", "receiptProofPart", [["poolId", "==", POOL], ["accrualId", "==", accId]], 8, accId));
      row.parts = { ...summarize(parts), indices: parts.status === "served" ? parts.documents.map((d) => d.fields.partIndex).sort((a, b) => a - b) : null };
    }
    obs(`6-9.row.${f.funderId}`, row);
  }
  const ABSENT = crypto.createHash("sha256").update(`absent|${POOL}|${EPOCH}`).digest("hex");
  const sweep = {};
  for (const [name, type, where, limit] of [["reservation", "transferReservation", [["poolId", "==", POOL], ["accrualId", "==", ABSENT]], 2],
    ["receipt", "transferReceipt", [["accrualId", "==", ABSENT]], 2], ["parts", "receiptProofPart", [["poolId", "==", POOL], ["accrualId", "==", ABSENT]], 8]]) {
    sweep[name] = summarize(await adapter.readPage(desc(`sweep${name}`, type, where, limit, ABSENT)));
  }
  obs("10.sweepAgainstAbsent", sweep);
  // 11. the OLD clause, RAW, past the adapter
  let raw;
  try {
    const { documents, height } = await query("transferReceipt", [["poolId", "==", POOL], ["accrualId", "==", servedAccrualForRaw || ABSENT]], { orderBy: null, limit: 2 });
    raw = { served: true, count: documents.length, height };
  } catch (e) { raw = { served: false, error: msgOf(e).slice(0, 2000) }; }
  obs("11.oldReceiptClauseRaw", raw);
  return { header, headerFields, enumeration, funders, sweep, raw };
};

// the nine v1 predicates over the shared observations
const sharedPredicates = ({ transportLog, header, headerFields, enumeration, raw, plannedVsServed, composition, sweep }) => {
  const heights = transportLog.filter((c) => /^verified:/.test(c.result)).map((c) => BigInt(c.result.split("@")[1]));
  return {
    allReadsVerified: () => { const bad = transportLog.filter((c) => !/^verified:/.test(c.result)); return { pass: bad.length === 0 && transportLog.length > 0, detail: bad.length ? `${bad.length} of ${transportLog.length} adapter calls not verified: ${bad.map((c) => `${c.type}:${c.result.slice(0, 80)}`).join("; ")}` : `${transportLog.length} calls verified` }; },
    headerServedOne: () => ({ pass: header.status === "served" && header.documents.length === 1, detail: `header ${header.status}, ${header.status === "served" ? header.documents.length : 0} document(s)` }),
    enumerationMatchesMemberCount: () => { const n = enumeration.status === "served" ? enumeration.documents.length : -1; const mc = headerFields ? headerFields.memberCount : null; return { pass: n >= 1 && n <= 8 && n === mc, detail: `enumeration ${n}, memberCount ${mc}` }; },
    // WIDTH, STATED: the transport exposes the refusal as TEXT only (a gRPC
    // status message, percent-encoded on the wire), so the predicate decodes it
    // and anchors on the platform's own error prefix for a where clause on a
    // non-indexed property; an unrelated message merely containing the words is
    // not accepted. It cannot inspect a structured error code, since none reaches it.
    oldClauseRefusedWithIndexError: () => { const text = decodeSafe(raw.error || ""); return { pass: raw.served === false && /^where clause on non indexed property error: query must be for valid indexes/.test(text), detail: raw.served ? `SERVED ${raw.count} document(s)` : `refused: ${text.slice(0, 160)}` }; },
    plannedEqualsServed: () => ({ pass: plannedVsServed.length > 0 && plannedVsServed.every((x) => x.equal), detail: plannedVsServed.map((x) => `${x.funder.slice(0, 8)}:${x.equal}`).join(",") || "no members" }),
    compositionState: (expected) => ({ pass: composition.state === expected, detail: composition.state ? `state ${composition.state}, reasons ${composition.reasons.join(",") || "none"}` : JSON.stringify(composition) }),
    compositionReasons: (expected) => ({ pass: Array.isArray(composition.codes) && JSON.stringify([...composition.codes].sort()) === JSON.stringify([...expected].sort()), detail: `codes ${(composition.codes || []).join(",") || "none"}, expected ${expected.join(",") || "none"}` }),
    heightSpanMax: (max) => { if (!heights.length) return { pass: false, detail: "no verified heights" }; const span = heights.reduce((a, b) => (a > b ? a : b)) - heights.reduce((a, b) => (a < b ? a : b)); return { pass: span <= BigInt(max), detail: `span ${span} over ${heights.length} reads, max ${max}` }; },
    sweepAgainstAbsentEmpty: () => ({ pass: ["reservation", "receipt", "parts"].every((k) => sweep[k].status === "served" && sweep[k].count === 0 && sweep[k].proved === true), detail: Object.entries(sweep).map(([k, v]) => `${k}:${v.status}:${v.count}`).join(",") }),
  };
};

const evaluateProfile = (profileSnap, predicates) => {
  const results = [];
  for (const [section, required] of [["required", true], ["optional", false]]) {
    for (const [check, param] of Object.entries(profileSnap[section])) {
      const r = predicates[check](param);
      results.push({ check, required, param, pass: r.pass === true, detail: r.detail });
    }
  }
  const pass = results.every((r) => !r.required || r.pass);
  return { pass, results };
};

const runTransportCheck = async (args = {}) => {
  const taken = takeArguments(args);
  if (taken.kind === 2) return runV2(taken);
  const { query, plannedIdFor, executionVerdict, ledger, profile, provenance, acceptance, target: tgt, selfShares: shares } = taken;
  if (typeof acceptance !== "boolean") refuse("runTransportCheck needs a strict-boolean acceptance mode");
  if (!isPlain(tgt) || !HEX64.test(tgt.poolId || "") || !Number.isSafeInteger(tgt.epochIndex) || !HEX64.test(tgt.contractId || "") || typeof tgt.chainId !== "string" || !Number.isSafeInteger(tgt.contractVersion)) refuse("runTransportCheck needs a target scope with 64-hex contractId and poolId, a string chainId, integer contractVersion and epochIndex");
  if (!Array.isArray(shares) || !shares.every((s) => typeof s === "string" && HEX64.test(s))) refuse("selfShares must be an array of 64-hex PRIMITIVE strings");
  // the captures are frozen; validation, evaluation and the identity read them
  const profileSnap = deepFreeze(validateProfile(profile));
  const prov = assembleProvenance(provenance);
  const selfShares = deepFreeze(shares);
  const target = deepFreeze({ contractId: tgt.contractId, chainId: tgt.chainId, contractVersion: tgt.contractVersion, poolId: tgt.poolId, epochIndex: tgt.epochIndex });
  // the scope and the classification the artifact records must be the ones this run uses
  bindProvenanceToTarget(prov, target);
  { const a = [...prov.classificationInput.selfShares].sort(), b = [...selfShares].sort();
    if (a.length !== b.length || a.some((x, i) => x !== b[i])) refuse("provenance.classificationInput.selfShares does not equal the self-shares this run classifies with"); }
  const { poolId: POOL, epochIndex: EPOCH } = target;

  const observations = [];
  const obs = (name, value) => { observations.push({ name, value: JSON.parse(JSON.stringify(value)) }); };
  const { transportLog, transport } = makeTransport(query, target);
  const adapter = createForwardAdapter({ binding: { ...target }, transport, ledger });

  const { header, headerFields, enumeration, funders, sweep, raw } = await observeTargetEpoch({ adapter, query, obs, POOL, EPOCH });
  // 12 and 13. the composition
  obs("12b.selfShareOverride", selfShares);
  let plannedVsServed = [], composition = { skipped: "header or enumeration not served" }, evidence = null;
  if (headerFields && funders.length > 0) {
    const members = funders.map((f) => ({
      funderId: f.funderId, plannedAccrualId: plannedIdFor(f.funderId),
      effectiveCredits: String(f.fields.amountCredits), shareBps: f.fields.shareBps,
      isSelfShare: selfShares.includes(f.funderId), payable: !selfShares.includes(f.funderId),
    }));
    plannedVsServed = members.map((m) => ({ funder: m.funderId, planned: m.plannedAccrualId, served: funders.find((f) => f.funderId === m.funderId).servedId, equal: m.plannedAccrualId === funders.find((f) => f.funderId === m.funderId).servedId }));
    obs("12.plannedVsServed", plannedVsServed);
    // THE PLAN INPUT, THE EVIDENCE BUNDLE AND THE VERDICT INPUTS ARE RETAINED: they are
    // what the composition computed over, and `reconstruct` re-evaluates the kernel
    // over exactly these from the artifact alone
    const planInput = {
      scope: { ...target }, encodingRefused: false,
      header: { grossCredits: String(headerFields.grossCredits), feeCredits: String(headerFields.feeCredits), memberCount: headerFields.memberCount, calcVersion: headerFields.calcVersion, allocationHash: headerFields.allocationHash },
      members,
    };
    const verdictInputs = [], verdicts = [];
    const recordingVerdict = (call) => { verdictInputs.push(JSON.parse(JSON.stringify(call))); const v = executionVerdict(call); verdicts.push(JSON.parse(JSON.stringify(v))); return v; };
    try {
      const plan = K.buildExpectedRecordPlan(planInput);
      const before = transportLog.length;
      const run = await A.acquireEpochEvidence({ plan, readPage: adapter.readPage, executionVerdict: recordingVerdict });
      const result = K.evaluateEpochForwardState({ plan, evidence: run.evidence });
      composition = { state: result.state, reasons: result.reasons.map((r) => `${r.code}@${r.recordKey}`), codes: result.reasons.map((r) => r.code), heightRange: result.heightRange,
        reads: run.reads.map((r) => r.slot), transportCalls: transportLog.slice(before).map((c) => `${c.type}[${c.where.map((w) => w[0]).join(",")}]:${c.result}`) };
      evidence = { planInput: JSON.parse(JSON.stringify(planInput)), bundle: JSON.parse(JSON.stringify(run.evidence)), verdictInputs, verdicts };
    } catch (e) { composition = { refused: msgOf(e).slice(0, 1000) }; evidence = { planInput: JSON.parse(JSON.stringify(planInput)), bundle: null, verdictInputs, verdicts, refused: msgOf(e).slice(0, 1000) }; }
  } else {
    obs("12.plannedVsServed", plannedVsServed);
  }
  obs("13.composition", composition);
  obs("14.verdictNote", `the execution verdict is ${prov.synthetic.transferVerdict}; plan values are ${prov.synthetic.planValues}; the self-share classification is ${prov.synthetic.selfShare}`);

  // ---- the validator ----
  const predicates = sharedPredicates({ transportLog, header, headerFields, enumeration, raw, plannedVsServed, composition, sweep });
  const verdict = evaluateProfile(profileSnap, predicates);   // the v1 verdict, over the snapshotted profile
  const { pass } = verdict;
  const artifact = deepFreeze({
    kind: "tegara.e2.forwardTransportArtifact.v1",
    acceptance: acceptanceBlock(acceptance),
    profileIdentity: profileIdentity(profileSnap), profile: profileSnap,
    provenance: prov, verdict, observations, transportLog: transportLog.map((c) => ({ ...c })),
    evidence,
  });
  const exitCode = exitCodeFor(acceptance, pass);
  return { artifact, verdict, exitCode };
};

/**
 * THE V2 RUN (design sections 5 and 7). The plan inputs come from the contexts and from
 * nothing served; the loop is the orchestrator's refresh rule; the verdict closures are
 * built here from the shared verifier's composition.
 */
const runV2 = async ({ query, contextFor, captureFor, deps, ledger, profile, provenance, acceptance, target: tgt, universe: uni }) => {
  if (typeof acceptance !== "boolean") refuse("runTransportCheck needs a strict-boolean acceptance mode");
  if (!isPlain(tgt) || !HEX64.test(tgt.poolId || "") || !Number.isSafeInteger(tgt.epochIndex) || !HEX64.test(tgt.contractId || "") || typeof tgt.chainId !== "string" || !Number.isSafeInteger(tgt.contractVersion)) refuse("runTransportCheck needs a target scope with 64-hex contractId and poolId, a string chainId, integer contractVersion and epochIndex");
  if (!Array.isArray(uni) || uni.length === 0 || !uni.every((n, i) => Number.isSafeInteger(n) && n >= 0 && (i === 0 || n > uni[i - 1]))) refuse("universe must be a non-empty strictly ascending array of non-negative safe integers (the finalized epoch set discovery returned at run start)");
  if (!uni.includes(tgt.epochIndex)) refuse(`the target epoch ${tgt.epochIndex} is not in the universe [${uni.join(",")}]`);
  const profileSnap = deepFreeze(validateProfile(profile));
  const prov = assembleProvenance(provenance, 2);
  const target = deepFreeze({ contractId: tgt.contractId, chainId: tgt.chainId, contractVersion: tgt.contractVersion, poolId: tgt.poolId, epochIndex: tgt.epochIndex });
  const universe = deepFreeze([...uni]);
  bindProvenanceToTarget(prov, target);
  const { poolId: POOL, epochIndex: EPOCH } = target;

  const observations = [];
  const obs = (name, value) => { observations.push({ name, value: JSON.parse(JSON.stringify(value)) }); };
  const { transportLog, transport } = makeTransport(query, target);
  // ONE ADAPTER PER EPOCH (design section 5, stage 2): the binding is the scope the
  // answers must match and the scope carries the epoch index
  const adapterFor = new Map(universe.map((n) => [n, createForwardAdapter({ binding: { ...target, epochIndex: n }, transport, ledger })]));

  // ---- THE CONTEXTS, CAPTURED BEFORE ANY READ (the independence property observed) ----
  const contexts = new Map(), planInputs = new Map(), readsAtCapture = new Map(), closures = new Map();
  const verdictInputs = [], verdicts = [];
  const contextSummary = {};
  for (const n of universe) {
    const ctxObject = contextFor(n);
    // THE WHOLE CONTEXT IS CAPTURED as plain data through the page checker's walk BEFORE any
    // member is read (a function member, an accessor, a foreign prototype or a cycle is
    // refused there, the kind included, with no getter invoked), it must be deeply frozen,
    // and its own key set must be exactly the context's members (the second pass's
    // construction: a frozen context carrying an extra function passed the shallow checks);
    // the CAPTURED copy is what this run reads and records, while the context object itself
    // is handed to the context module for the plan input and the closure, whose brand it checks
    if (!isPlain(ctxObject)) refuse(`contextFor(${n}) did not answer a plain object`);
    const ctx = deepFreeze(capture(ctxObject, `contextFor(${n})`));
    if (!deeplyFrozen(ctxObject)) refuse(`contextFor(${n}) did not answer a deeply frozen per-epoch context (a frozen outer object over mutable members is refused)`);
    if (JSON.stringify(Object.keys(ctx).sort()) !== JSON.stringify([...CONTEXT_KEYS].sort())) refuse(`contextFor(${n}) answered an object whose members are ${Object.keys(ctx).sort().join(",")}, not the per-epoch context's ${[...CONTEXT_KEYS].sort().join(",")}`);
    if (ctx.kind !== X.KIND || !isPlain(ctx.scope) || ctx.scope.epochIndex !== n || ctx.scope.poolId !== POOL) {
      refuse(`contextFor(${n}) did not answer a per-epoch context for pool ${POOL.slice(0, 8)}... epoch ${n}`);
    }
    if (ctx.scope.contractId !== target.contractId || ctx.scope.chainId !== target.chainId || ctx.scope.contractVersion !== target.contractVersion) refuse(`contextFor(${n}) answered a context bound to another contract, chain or version than the run's target`);
    contexts.set(n, ctx);
    contextSummary[n] = { figuresSource: ctx.figuresSource, precondition: ctx.precondition, encodingRefused: ctx.encodingRefused,
      incomeIdentity: ctx.formation.incomeIdentity, allocationHash: ctx.formation.allocationHash, memberCount: ctx.formation.allocation.length,
      rows: ctx.rows ? ctx.rows.length : null };
    if (ctx.precondition === null) {
      // planInputOf refuses a precondition context by name; executionVerdictFor builds the
      // closure over the shared verifier and refuses an encoding-refused context
      planInputs.set(n, deepFreeze(X.planInputOf(ctxObject)));
      // the read count is recorded when the PLAN INPUT is derived, per plan epoch (a
      // precondition epoch derives none and records nothing; the third pass's point)
      readsAtCapture.set(n, transportLog.length);
      if (ctx.encodingRefused !== true) {
        const closure = X.executionVerdictFor(ctxObject, { captureFor, deps });
        closures.set(n, async (call) => {
          verdictInputs.push({ epochIndex: n, call: JSON.parse(JSON.stringify(call)) });
          const v = await closure(call);   // THE WRAPPER AWAITS: the shared verifier is asynchronous
          verdicts.push({ epochIndex: n, verdict: JSON.parse(JSON.stringify(v)) });
          return v;
        });
      }
    }
  }
  obs("2.contexts", contextSummary);
  obs("3.planInputsCapturedAtReadCount", Object.fromEntries([...readsAtCapture].map(([n, c]) => [n, c])));
  const incomeIdentity = contexts.get(EPOCH).formation.incomeIdentity;
  if (prov.classificationInput.incomeIdentity !== incomeIdentity) refuse(`provenance.classificationInput.incomeIdentity does not equal the target context's income identity; an artifact must describe the execution it records`);

  // ---- the target epoch's observations, as v1 ----
  const { header, headerFields, enumeration, funders, sweep, raw } = await observeTargetEpoch({ adapter: adapterFor.get(EPOCH), query, obs, POOL, EPOCH });
  const targetPlan = planInputs.get(EPOCH) || null;
  const plannedVsServed = targetPlan ? targetPlan.members.map((m) => { const f = funders.find((x) => x.funderId === m.funderId); return { funder: m.funderId, planned: m.plannedAccrualId, served: f ? f.servedId : null, equal: !!f && m.plannedAccrualId === f.servedId }; }) : [];
  obs("12.plannedVsServed", plannedVsServed);

  // ---- THE ORCHESTRATOR LOOP (design section 5) ----
  const generations = [];   // [{ generation, epochs: { n: { state, codes, heightRange } } }]
  const evidenceByEpoch = new Map();   // the LAST evaluation's evidence per epoch
  const evaluateAll = async (generation) => {
    const results = [];
    const summary = {};
    for (const n of universe) {
      const ctx = contexts.get(n);
      let result;
      if (ctx.precondition !== null) {
        result = K.unprovedPrecondition({ poolId: POOL, epochIndex: n, code: ctx.precondition.code, diagnostic: ctx.precondition.diagnostic });
        evidenceByEpoch.set(n, { precondition: ctx.precondition, bundle: null });
      } else {
        const plan = K.buildExpectedRecordPlan(planInputs.get(n));
        const before = transportLog.length;
        const executionVerdict = closures.get(n) || (async () => refuse(`no verdict is owed under the encoding-refused epoch ${n}; acquisition must not have requested one`));
        const run = await A.acquireUntilSettled({ plan, readPage: adapterFor.get(n).readPage, executionVerdict, evaluate: (pl, ev) => K.evaluateEpochForwardState({ plan: pl, evidence: ev }), maxRounds: 2 });
        result = run.result;
        evidenceByEpoch.set(n, { planInput: planInputs.get(n), bundle: JSON.parse(JSON.stringify(run.evidence)), rounds: run.rounds, reads: run.reads.map((r) => r.slot),
          transportCalls: transportLog.slice(before).map((c) => `${c.type}[${c.where.map((w) => w[0]).join(",")}]:${c.result}`) });
      }
      results.push(result);
      summary[n] = { state: result.state, codes: result.reasons.map((r) => r.code), reasons: result.reasons.map((r) => `${r.code}@${r.recordKey}`), heightRange: result.heightRange };
    }
    const snapshot = K.createSnapshot(results, { generation });
    generations.push({ generation, epochs: summary });
    return snapshot;
  };
  const projections = [];   // [{ epochIndex, generation, answer }]
  let earlyStop = null;
  let generation = 0;
  let snapshot = await evaluateAll(generation);
  const bound = universe.length + 1;
  // A SNAPSHOT HOLDING A REFUSED EPOCH STOPS THE RUN BY NAME, whichever epoch and whether or
  // not it was selected yet (the checker's construction: a non-target epoch refused by a
  // record served after its selection would otherwise let the run finish normally)
  const refusedIn = (g) => universe.find((n) => generations[g].epochs[n].state === "refused");
  const stopOn = (g) => { const n = refusedIn(g); if (n === undefined) return false; earlyStop = { afterGeneration: g, code: "REFUSED_EPOCH_IN_SNAPSHOT", epochIndex: n, reason: `epoch ${n} is refused in generation ${g} (${generations[g].epochs[n].codes.join(",")}); retrying cannot correct a record that is wrong on the ledger` }; return true; };
  if (!stopOn(generation)) {
    for (const n of universe) {
      // the selection for epoch n, answered by the projection bound to the current snapshot;
      // ONLY the projection's own named refusals are answers (unproved, refused, not
      // evaluated): any other thrown value is a fault and propagates (the checker's finding)
      let answer;
      try { answer = { value: K.projectForWriter(snapshot, n) }; }
      catch (e) {
        // the code is the WHOLE token before the kernel's own delimiter (a near-match such as
        // a code with a suffix is not an answer, the third pass's construction)
        const code = (msgOf(e).match(/^e2ForwardKernel: (PROJECTION_[A-Z_]+): /) || [])[1] || null;
        if (!K.PROJECTION_CODES.includes(code)) throw e;
        answer = { refusedByName: msgOf(e).slice(0, 300), code };
      }
      projections.push({ epochIndex: n, generation, answer });
      // an unproved epoch STALLS (the writer would not work it) and the run continues; a
      // complete or incomplete epoch's work ends here (this instrument writes nothing)
      if (generation + 1 >= bound + 1) { earlyStop = { afterGeneration: generation, code: "REFRESH_BOUND_EXCEEDED", epochIndex: n, reason: `the refresh bound ${bound} would be exceeded` }; break; }
      generation += 1;
      snapshot = await evaluateAll(generation);
      if (stopOn(generation)) break;
    }
  }
  obs("13.generations", generations);
  obs("13b.projections", projections);
  obs("13c.earlyStop", earlyStop);
  const finalTarget = generations[generations.length - 1].epochs[EPOCH];
  const composition = { state: finalTarget.state, reasons: finalTarget.reasons, codes: finalTarget.codes, heightRange: finalTarget.heightRange, generation: generations.length - 1 };
  obs("13.composition", composition);
  obs("14.verdictNote", `the execution verdict is ${prov.synthetic.transferVerdict}; plan values are ${prov.synthetic.planValues}; the self-share classification is ${prov.synthetic.selfShare}`);

  // ---- the validator ----
  const predicates = {
    ...sharedPredicates({ transportLog, header, headerFields, enumeration, raw, plannedVsServed, composition, sweep }),
    planBuiltBeforeAnyRead: () => { const late = [...readsAtCapture].filter(([, c]) => c !== 0); return { pass: readsAtCapture.size > 0 && readsAtCapture.size === planInputs.size && late.length === 0, detail: late.length ? `plan inputs derived after reads: ${late.map(([n, c]) => `epoch ${n} at ${c}`).join(", ")}` : `${readsAtCapture.size} plan input(s) derived at read count 0${readsAtCapture.size === 0 ? " (none derived, so nothing was examined)" : ""}` }; },
    planFiguresSource: (expected) => ({ pass: contexts.get(EPOCH).figuresSource === expected, detail: `target epoch ${EPOCH} figures source ${contexts.get(EPOCH).figuresSource}, expected ${expected}` }),
    // each of these passes only over WORK IT EXAMINED: at least one plan header compared, at
    // least one member compared, at least one closure built (the second pass's point that a
    // universe of precondition epochs could pass them vacuously)
    planHeaderEqualsFormation: () => { const compared = [...planInputs].filter(([, pi]) => !pi.encodingRefused); const bad = compared.filter(([n, pi]) => pi.header.allocationHash !== contexts.get(n).formation.allocationHash || pi.header.memberCount !== contexts.get(n).formation.allocation.length); return { pass: compared.length > 0 && bad.length === 0, detail: bad.length ? `plan headers differing from the formation at epochs ${bad.map(([n]) => n).join(",")}` : `${compared.length} plan header(s) compared and equal to the formation's hash and count` }; },
    selfShareDerived: () => { const bad = []; let examined = 0; for (const [n, pi] of planInputs) for (const m of pi.members) { examined += 1; if (m.isSelfShare !== (m.funderId === contexts.get(n).formation.incomeIdentity)) bad.push(`${n}:${m.funderId.slice(0, 8)}`); } return { pass: examined > 0 && bad.length === 0, detail: bad.length ? `isSelfShare not derived from the income identity at ${bad.join(",")}` : `${examined} member(s) examined, every isSelfShare equals funderId === incomeIdentity; no self-share argument exists in a v2 run` }; },
    identifiersCanonical: () => { const bad = []; let examined = 0; for (const [n, pi] of planInputs) { examined += 1; for (const k of ["contractId", "poolId"]) if (!HEX64.test(pi.scope[k])) bad.push(`${n}:scope.${k}`); if (pi.header && !HEX64.test(pi.header.allocationHash)) bad.push(`${n}:header.allocationHash`); for (const m of pi.members) for (const k of ["funderId", "plannedAccrualId"]) if (!HEX64.test(m[k])) bad.push(`${n}:${k}`); } return { pass: examined > 0 && bad.length === 0, detail: bad.length ? `non-canonical: ${bad.join(",")}` : `${examined} plan input(s) examined, every identifier 64 lowercase hex${examined === 0 ? " (none examined)" : ""}` }; },
    verdictOwner: (expected) => ({ pass: expected === "shared-verifier" && prov.synthetic.transferVerdict === "shared-verifier" && closures.size > 0 && closures.size === [...planInputs].filter(([, pi]) => !pi.encodingRefused).length, detail: `label ${prov.synthetic.transferVerdict}, ${closures.size} closure(s) built by executionVerdictFor${closures.size === 0 ? " (none built, so no verdict was owned)" : ""}` }),
    freshEpochPrecondition: () => { const fresh = universe.filter((n) => n !== EPOCH && contexts.get(n).precondition !== null && contexts.get(n).precondition.code === "UNPROVED_EPOCH_OBJECT_UNPROVED"); const readsUnder = (n) => transportLog.filter((c) => c.where.some((w) => w[0] === "epochIndex" && w[2] === n)).length; const bad = fresh.filter((n) => planInputs.has(n) || readsUnder(n) !== 0 || !projections.some((p) => p.epochIndex === n && p.answer.code === "PROJECTION_STATE_UNPROVED")); return { pass: fresh.length > 0 && bad.length === 0, detail: fresh.length ? `fresh epoch(s) ${fresh.join(",")}: ${bad.length ? `not upheld at ${bad.join(",")}` : "precondition carried, no plan built, no read issued, projection refused by name"}` : "no universe epoch other than the target carries the C1 precondition" }; },
    universe: (expected) => ({ pass: JSON.stringify(universe) === JSON.stringify(expected) && generations.every((g) => JSON.stringify(Object.keys(g.epochs).map(Number)) === JSON.stringify([...universe])), detail: `universe [${universe.join(",")}] over ${generations.length} generation(s), expected [${expected.join(",")}]` }),
    refreshCountMax: (max) => ({ pass: generations.length <= max && generations.length <= universe.length + 1, detail: `${generations.length} generation(s), max ${max}, bound ${universe.length + 1}` }),
    generationSequence: (expected) => ({ pass: JSON.stringify(generations.map((g) => g.generation)) === JSON.stringify(expected), detail: `generations [${generations.map((g) => g.generation).join(",")}], expected [${expected.join(",")}]` }),
    earlyStop: (expected) => ({ pass: expected === null ? earlyStop === null : (earlyStop !== null && earlyStop.afterGeneration === expected.afterGeneration && earlyStop.code === expected.code && earlyStop.epochIndex === expected.epochIndex), detail: earlyStop === null ? "no early stop" : `stopped after generation ${earlyStop.afterGeneration} (${earlyStop.code} at epoch ${earlyStop.epochIndex}): ${earlyStop.reason.slice(0, 120)}` }),
  };
  const verdict = evaluateProfile(profileSnap, predicates);
  const { pass } = verdict;
  const targetEvidence = evidenceByEpoch.get(EPOCH) || null;
  const evidence = {
    planInput: targetPlan ? JSON.parse(JSON.stringify(targetPlan)) : null,
    bundle: targetEvidence && targetEvidence.bundle ? targetEvidence.bundle : null,
    verdictInputs: verdictInputs.filter((v) => v.epochIndex === EPOCH).map((v) => v.call),
    verdicts: verdicts.filter((v) => v.epochIndex === EPOCH).map((v) => v.verdict),
    epochs: Object.fromEntries([...evidenceByEpoch].map(([n, e]) => [n, e])),
    projections, earlyStop, universe: [...universe],
  };
  const artifact = deepFreeze({
    kind: "tegara.e2.forwardTransportArtifact.v2",
    acceptance: acceptanceBlock(acceptance),
    profileIdentity: profileIdentity(profileSnap), profile: profileSnap,
    provenance: prov, verdict, observations, transportLog: transportLog.map((c) => ({ ...c })),
    evidence,
  });
  const exitCode = exitCodeFor(acceptance, pass);
  return { artifact, verdict, exitCode };
};

/**
 * reconstruct(artifact) re-evaluates the kernel over the artifact's OWN plan
 * input and evidence bundle, offline, and says whether the state and reason
 * codes it obtains equal the ones the artifact reports (`matchesArtifact`).
 * It refuses an artifact that carries no evidence. It does not re-run any
 * read; it establishes that the reported composition follows from the retained
 * evidence, not that the evidence is true.
 */
const reconstruct = (artifact) => {
  if (!isPlain(artifact) || !isPlain(artifact.evidence) || !isPlain(artifact.evidence.planInput)) refuse("reconstruct: the artifact carries no evidence to reconstruct from");
  const ev = capture(artifact.evidence, "the artifact's evidence");
  if (!isPlain(ev.bundle)) refuse("reconstruct: the artifact's composition was refused before a bundle existed; nothing to re-evaluate");
  const plan = K.buildExpectedRecordPlan(ev.planInput);
  const result = K.evaluateEpochForwardState({ plan, evidence: ev.bundle });
  const reported = (artifact.observations || []).find((o) => o.name === "13.composition");
  const reportedState = reported && reported.value ? reported.value.state : undefined;
  const reportedCodes = reported && reported.value && Array.isArray(reported.value.codes) ? [...reported.value.codes].sort() : null;
  const codes = result.reasons.map((r) => r.code).sort();
  const matchesArtifact = reportedState === result.state && reportedCodes !== null && JSON.stringify(reportedCodes) === JSON.stringify(codes);
  return { state: result.state, reasons: result.reasons, heightRange: result.heightRange, matchesArtifact };
};

module.exports = { runTransportCheck, reconstruct, validateProfile, profileIdentity, assembleProvenance, CHECKS, CHECKS_V2, PROFILE_KIND, PROFILE_KIND_V2, ACCEPTANCE_MINIMUM, ACCEPTANCE_MINIMUM_V2, V2_SYNTHETIC };
