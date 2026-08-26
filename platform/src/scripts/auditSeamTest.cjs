/**
 * Offline fixtures for the seam (build-order item 3). Plain `node`, no devnet.
 *
 * The decisive check is REPRODUCTION: strip every DERIVED member (rewards, claimProfile)
 * from each shipped acceptance envelope, rebuild it from the retained evidence alone,
 * and require the canonical bytes and sha256 to match the shipped vector exactly. That
 * is the strongest available statement that this writer and the executable
 * specification (docs/schema/check_vectors.py) agree.
 *
 * The acceptance envelopes beyond the primary positive are rebuilt from the checker
 * itself (python3 -c) so no fixture drifts from the suite.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const {
  buildEnvelope, deriveClaimProfile, recognizeAt, largestRemainder, firstClosing, canonicalize,
} = require("./auditSeam.cjs");

// INDEPENDENT ORACLE (build review, MINOR): the byte checks must not canonicalize both
// sides with the serializer under test, or a weakened serializer passes its own test.
// The Python executable specification emits the canonical bytes and digest; we compare
// OUR bytes to THOSE.
const SCHEMA_DIR_FOR_ORACLE = path.join(__dirname, "..", "..", "..", "docs", "schema");
const pythonCanonical = (exprBuildingEnvelope) => {
  const out = execFileSync("python3", ["-c",
    `import json,hashlib,importlib.util;s=importlib.util.spec_from_file_location("cv","check_vectors.py");` +
    `m=importlib.util.module_from_spec(s);s.loader.exec_module(m);` +
    `e=${exprBuildingEnvelope};b=m.canonical_bytes(e);` +
    `print(json.dumps({"len":len(b),"sha256":hashlib.sha256(b).hexdigest(),"bytes":b.decode("utf-8")}))`],
    { cwd: SCHEMA_DIR_FOR_ORACLE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(out);
};

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
// compare in CANONICAL form (sorted keys), the same equality the wire format uses
const eq = (name, a, b) => {
  const ja = canonicalize(a).toString(), jb = canonicalize(b).toString();
  if (ja === jb) { pass++; } else { fail++; console.error(`FAIL: ${name}\n  got      ${ja}\n  expected ${jb}`); }
};
const throws = (name, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || "")); }
};

const SCHEMA_DIR = path.join(__dirname, "..", "..", "..", "docs", "schema");

// ---- largest remainder: the pinned reproduction, exact rationals, ties ascending ----
eq("equal halves split exactly", largestRemainder("100000000", [
  { numerator: "1", denominator: "2" }, { numerator: "1", denominator: "2" }]),
  ["50000000", "50000000"]);
eq("odd base gives the remainder unit to the lowest tied index", largestRemainder("101", [
  { numerator: "1", denominator: "2" }, { numerator: "1", denominator: "2" }]),
  ["51", "50"]);
eq("three-way thirds: remainder to the two lowest indexes", largestRemainder("100", [
  { numerator: "1", denominator: "3" }, { numerator: "1", denominator: "3" },
  { numerator: "1", denominator: "3" }]), ["34", "33", "33"]);
eq("zero base allocates zero everywhere", largestRemainder("0", [
  { numerator: "1", denominator: "2" }, { numerator: "1", denominator: "2" }]), ["0", "0"]);
// duff-scale values stay exact (BigInt, never float)
eq("large base stays exact", largestRemainder("9007199254740993", [
  { numerator: "1", denominator: "2" }, { numerator: "1", denominator: "2" }]),
  ["4503599627370497", "4503599627370496"]);

// shares must be a PARTITION OF ONE (build review, MAJOR: over-1 shares returned an
// allocation EXCEEDING the base with no error; under-1 shares threw a raw TypeError)
throws("shares summing above 1 are refused, not over-allocated", () => largestRemainder("100",
  [{ numerator: "1", denominator: "1" }, { numerator: "1", denominator: "1" }]), /partition of 1/);
throws("shares summing below 1 are refused, not a raw crash", () => largestRemainder("100",
  [{ numerator: "1", denominator: "100" }]), /partition of 1/);
throws("a zero denominator is refused", () => largestRemainder("100",
  [{ numerator: "1", denominator: "0" }]), /denominator is not positive/);
throws("a negative numerator is refused", () => largestRemainder("100",
  [{ numerator: "-1", denominator: "2" }, { numerator: "3", denominator: "2" }]), /numerator is negative/);
throws("an empty share list is refused", () => largestRemainder("100", []), /non-empty/);
throws("a negative base is refused", () => largestRemainder("-1",
  [{ numerator: "1", denominator: "1" }]), /base is negative/);
ok("unequal but valid shares still allocate exactly", (() => {
  const a = largestRemainder("100", [{ numerator: "1", denominator: "4" },
                                     { numerator: "3", denominator: "4" }]);
  return a.join(",") === "25,75";
})());

// ---- firstClosing ----
const prows = [{ height: 1, coreChainLockedHeight: 995 }, { height: 2, coreChainLockedHeight: 999 },
               { height: 3, coreChainLockedHeight: 1001 }];
ok("closing is the FIRST row reaching H", firstClosing(1000, prows).height === 3);
ok("no closing when no row reaches H", firstClosing(2000, prows) === null);
// the binary search's precondition names itself rather than returning a wrong answer
// (independent review, MINOR: this primitive runs BEFORE the gate sees the evidence)
throws("regressing anchors are refused, not silently mis-searched", () => firstClosing(1000,
  [{ height: 1, coreChainLockedHeight: 999 }, { height: 2, coreChainLockedHeight: 1 }]),
  /anchors regress/);

// ---- claim profile: dependencies and the exclusive aggregate ----
let cp = deriveClaimProfile([], []);
ok("no verifiers run -> trusted-source", cp.aggregate === "trusted-source");
ok("every component names its absent verifier",
   cp.components.recognition.verifiersNotRun[0] === "verifyCheckpointRecognition" &&
   cp.components.schedule.verifiersNotRun.length === 0);
throws("AUTHENTICATED with a missing dependency fails closed",
  () => deriveClaimProfile(["verifyCheckpointRecognition"], []), /depends on non-AUTHENTICATED/);
cp = deriveClaimProfile(["verifyIdentifierConversion", "verifyCoreWalk", "verifyCheckpointRecognition"], []);
ok("satisfied dependencies authenticate", cp.components.recognition.claim === "AUTHENTICATED");
ok("some authenticated + others not -> partial-evidence", cp.aggregate === "partial-evidence");
// the barred components can never authenticate, so the strongest aggregate is unreachable
const allVerifiers = ["verifyCheckpointRecognition", "verifyBasePackage", "verifyCoreWalk",
  "verifyPlatformCommits", "verifyDecodeDispositions", "verifyL1BackingAtHeight",
  "verifyReceiptDuties", "verifyBookConformance", "verifyConservation",
  "verifyTransitionHashes", "verifyIdentifierConversion"];
cp = deriveClaimProfile(allVerifiers, []);
ok("l1Backing stays barred even when its verifier is claimed run",
   cp.components.l1Backing.claim === "TRUSTED_SOURCE");
ok("proof-verified-except-schedule remains UNREACHABLE in v1", cp.aggregate === "partial-evidence");
// result completeness gates the aggregate
cp = deriveClaimProfile(["verifyIdentifierConversion", "verifyCoreWalk", "verifyCheckpointRecognition"],
  [{ entitlement: { kind: "unknown" }, slotFanout: { kind: "none" } }]);
ok("an incomplete record keeps the aggregate at partial-evidence", cp.aggregate === "partial-evidence");

// ---- THE REPRODUCTION CHECK, over every shipped acceptance envelope ----
const DERIVED = ["rewards", "claimProfile"];
const rebuildAndCompare = (label, shipped, pyExpr) => {
  const evidence = { ...shipped };
  for (const k of DERIVED) delete evidence[k];
  const ranVerifiers = Object.entries(shipped.claimProfile.components)
    .filter(([, c]) => c.claim === "AUTHENTICATED")
    .map(([n]) => n)
    .map((n) => ({
      recognition: "verifyCheckpointRecognition", baseProof: "verifyBasePackage",
      coreContinuityFinality: "verifyCoreWalk", platformCommits: "verifyPlatformCommits",
      decoderCoverage: "verifyDecodeDispositions", bookConformance: "verifyBookConformance",
      conservation: "verifyConservation", transitionHashing: "verifyTransitionHashes",
      identifierConversion: "verifyIdentifierConversion",
    }[n]))
    .filter(Boolean);
  const built = buildEnvelope(evidence, { ranVerifiers });
  eq(`${label}: rewards re-derived exactly`, built.envelope.rewards, shipped.rewards);
  eq(`${label}: claimProfile re-derived exactly`, built.envelope.claimProfile, shipped.claimProfile);
  // the oracle is PYTHON's canonicalization of the SHIPPED envelope, computed
  // independently of the serializer under test
  const oracle = pythonCanonical(pyExpr);
  ok(`${label}: canonical bytes match the PYTHON oracle (${oracle.len})`,
     built.canonicalBytes.toString("utf8") === oracle.bytes &&
     built.canonicalBytes.length === oracle.len);
  ok(`${label}: sha256 matches the PYTHON oracle`, built.sha256 === oracle.sha256);
};

// the primary positive, straight from the committed vector file
const positive = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, "vectors", "positive_minimal.json"), "utf8"));
rebuildAndCompare("positive vector", positive, "m.build_positive()");
// its canonical form must also equal the manifest's pinned digest and length
const manifest = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, "vectors", "MANIFEST.json"), "utf8"));
const pb = canonicalize(positive);
ok(`positive matches the manifest length ${manifest.positive.canonicalByteLength}`,
   pb.length === manifest.positive.canonicalByteLength);
ok("positive matches the manifest sha256",
   crypto.createHash("sha256").update(pb).digest("hex") === manifest.positive.canonicalSha256);

// the other acceptance envelopes, emitted BY the checker so no fixture can drift
const builders = [
  ["successor-pool acceptance", "build_successor"],
  ["zero-payout acceptance", "build_zero_payout"],
  ["owner-vector acceptance", "build_owner_vector"],
  ["empty-epoch acceptance", "build_empty_epoch"],
  ["first-appearance acceptance", "build_first_appearance"],
];
for (const [label, fn] of builders) {
  const out = execFileSync("python3", ["-c",
    `import json,importlib.util;s=importlib.util.spec_from_file_location("cv","check_vectors.py");` +
    `m=importlib.util.module_from_spec(s);s.loader.exec_module(m);` +
    `print(json.dumps(m.${fn}()))`],
    { cwd: SCHEMA_DIR, encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  rebuildAndCompare(label, JSON.parse(out), `m.${fn}()`);
}

// ---- recognition: the branches the acceptance envelopes do not all reach ----
const ctxOf = (env) => ({
  checkpoints: env.checkpoints, poolProTxHash: env.poolProTxHash,
  poolL1SlotIndex: env.poolL1SlotIndex, contractId: env.contractId, poolId: env.poolId,
  lifecycle: env.lifecycle, baseHeight: env.basePackage.baseBlock.height,
});
const ctx = ctxOf(positive);
const span = { from: positive.checkpoints[0].epochRange.fromCoreHeight,
               to: positive.checkpoints[positive.checkpoints.length - 1].epochRange.toCoreHeight };
eq("below the first epoch is UNRECOGNIZED", recognizeAt(span.from - 1, ctx),
   { status: "UNRECOGNIZED", bindingRef: null });
eq("above the last adopted epoch is DEFERRED (never UNRECOGNIZED)", recognizeAt(span.to + 1, ctx),
   { status: "DEFERRED", bindingRef: null });
eq("inside the epoch, at/after activation, is RECOGNIZED",
   recognizeAt(positive.rewards[0].rewardCoreHeight, ctx), { status: "RECOGNIZED", bindingRef: 0 });
// pre-activation: the binding is found but the height precedes its activation
const preAct = { ...ctx, checkpoints: JSON.parse(JSON.stringify(positive.checkpoints)) };
preAct.checkpoints[0].extractedBinding.bindings[0].activationCoreHeight = 99999;
eq("a pre-activation height is UNRECOGNIZED with its bindingRef",
   recognizeAt(positive.rewards[0].rewardCoreHeight, preAct), { status: "UNRECOGNIZED", bindingRef: 0 });
// terminal latch and suspension both unrecognize with the bindingRef retained
const H0 = positive.rewards[0].rewardCoreHeight;
eq("after the terminal the position is UNRECOGNIZED",
   recognizeAt(H0, { ...ctx, lifecycle: { ...ctx.lifecycle, terminalHeight: H0 - 1 } }),
   { status: "UNRECOGNIZED", bindingRef: 0 });
eq("inside a suspension the position is UNRECOGNIZED",
   recognizeAt(H0, { ...ctx, lifecycle: { ...ctx.lifecycle,
     suspensions: [{ start: { kind: "observed", banHeight: H0 - 1 }, endHeight: H0, endReason: "RANGE_END" }] } }),
   { status: "UNRECOGNIZED", bindingRef: 0 });

// ---- NO PREPARED CAPTURE CAN ARRIVE THROUGH THE CONTEXT (a review finding 5) ----
// The exported recognizeAt re-derives from the checkpoints in front of it and has no prepared
// parameter, so a caller cannot preload bounds through the context by ANY means. Four earlier
// designs each placed authority in a marker on the caller's object (a flag, an array identity,
// a WeakMap brand, a module-private Symbol slot), and the review defeat was a Proxy whose get
// trap answered any SYMBOL key with a fabricated capture, so a height outside every real epoch
// came back RECOGNIZED. These cases pin the honest outcome.
{
  const outside = span.to + 1;               // genuinely past the last epoch -> DEFERRED
  const below = span.from - 1;               // genuinely before the first    -> UNRECOGNIZED
  // sanity, so the cases below are not vacuous
  eq("baseline: a height past the epochs is DEFERRED", recognizeAt(outside, ctx),
     { status: "DEFERRED", bindingRef: null });

  // a Proxy that answers EVERY property read, symbol keys included, with a fabricated capture
  // whose bounds cover all heights. The a review slot read ctx[PREPARED] would have taken this.
  const fabricated = { bounds: [{ fromCoreHeight: 0, toCoreHeight: Number.MAX_SAFE_INTEGER }],
                       susIntervals: [] };
  const anyKeyProxy = new Proxy(ctxOf(positive), {
    get(target, key, recv) {
      if (typeof key === "symbol") return fabricated;
      return Reflect.get(target, key, recv);
    },
  });
  eq("a Proxy answering any symbol key cannot preload bounds: still DEFERRED",
     recognizeAt(outside, anyKeyProxy), { status: "DEFERRED", bindingRef: null });
  eq("and a below-epoch height stays UNRECOGNIZED through the same Proxy",
     recognizeAt(below, anyKeyProxy), { status: "UNRECOGNIZED", bindingRef: null });

  // the plainer inputs the earlier designs fell to, inert now: own properties under guessed
  // key names whose value is a fabricated capture
  const withOwnProp = ctxOf(positive);
  withOwnProp.prepared = fabricated;
  withOwnProp.PREPARED = fabricated;
  eq("an own prepared/PREPARED property does not preload bounds",
     recognizeAt(outside, withOwnProp), { status: "DEFERRED", bindingRef: null });
}

// ---- canonicalization guards ----
ok("canonical form sorts keys", canonicalize({ b: 1, a: 2 }).toString() === '{"a":2,"b":1}');
throws("a non-safe JSON number is refused", () => canonicalize({ n: 1e300 }), /unsafe JSON number/);
// the FULL RFC 8785 domain guard (build review, MAJOR: the old partial serializer
// accepted these and emitted bytes the normative layer rejects)
throws("undefined is refused, never emitted as invalid JSON",
  () => canonicalize({ a: undefined }), /undefined at/);
throws("a lone surrogate is refused", () => canonicalize({ a: "\ud800" }), /lone high surrogate/);
throws("a lone low surrogate is refused", () => canonicalize({ a: "\udc00" }), /lone low surrogate/);
throws("a non-NFC string is refused", () => canonicalize({ a: "e\u0301" }), /Normalization Form C/);
throws("a BigInt is refused", () => canonicalize({ a: 1n }), /BigInt/);
throws("NaN is refused", () => canonicalize({ a: NaN }), /non-finite/);
ok("a valid surrogate PAIR is accepted", canonicalize({ a: "\ud83d\ude00" }).length > 0);

// ---------------------------------------------------------------------------
// P7 and P8 of the property review (2026-07-25): the index-building searches assumed
// ordered inputs without enforcing them. Each precondition now fails closed, and where an
// indexed path has a scan counterpart the two are required to agree.
// ---------------------------------------------------------------------------
{
  const ev = () => { const e = JSON.parse(JSON.stringify(positive)); delete e.rewards; delete e.claimProfile; return e; };

  // P7, the ownership-anchor search. Reversing the committed positive's slot 0 chain
  // credited a DIFFERENT member for the same reward with no error raised.
  const reversed = ev();
  reversed.slots[0].ownershipChain.reverse();
  throws("a reversed ownership chain fails closed instead of crediting another member",
    () => buildEnvelope(reversed), /ownership anchors regress/);

  const regressed = ev();
  regressed.slots[0].ownershipChain[1].coreChainLockedHeight =
    regressed.slots[0].ownershipChain[0].coreChainLockedHeight - 5;
  throws("a single regressing hop anchor fails closed",
    () => buildEnvelope(regressed), /ownership anchors regress at hop 1/);

  const nonInt = ev();
  nonInt.slots[0].ownershipChain[1].coreChainLockedHeight = "999";
  throws("a non-integer hop anchor fails closed",
    () => buildEnvelope(nonInt), /non-integer coreChainLockedHeight/);

  // P8, the suspension index. Non-numeric endpoints slipped past the overlap guard and
  // then the indexed path disagreed with the scan on 239 of the first 250 heights.
  const badSus = ev();
  badSus.lifecycle.suspensions = [{ start: { kind: "observed", banHeight: "abc" }, endHeight: "xyz" }];
  throws("non-integer suspension bounds fail closed",
    () => buildEnvelope(badSus), /non-integer bounds/);

  const backwards = ev();
  backwards.lifecycle.suspensions = [{ start: { kind: "observed", banHeight: 200 }, endHeight: 150 }];
  throws("a backwards suspension fails closed",
    () => buildEnvelope(backwards), /runs backwards/);
}

// P7, the covering-epoch search. Unordered epochs used to return UNRECOGNIZED where a
// plain scan finds a covering epoch that recognizes the pool, so the two paths disagreed
// silently. The assertion is checked here, and the indexed and scan answers are then
// required to agree over a dense range of heights.
{
  const bind = (cid, pid) => ({ proTxHash: "aa", slotIndex: 0, contractId: cid, poolId: pid, activationCoreHeight: 1 });
  const epoch = (from, to) => ({ epochRange: { fromCoreHeight: from, toCoreHeight: to },
                                 extractedBinding: { bindings: [bind("c", "p")], books: [] } });
  const ctxOver = (cps) => ({
    checkpoints: cps, poolProTxHash: "aa", poolL1SlotIndex: 0, contractId: "c", poolId: "p",
    lifecycle: { suspensions: [], terminalHeight: null }, baseHeight: 1, suspendedAt: () => false,
  });

  throws("unordered epochs fail closed",
    () => recognizeAt(150, ctxOver([epoch(300, 399), epoch(100, 199)])),
    /unordered or overlap/);
  throws("overlapping epochs fail closed",
    () => recognizeAt(250, ctxOver([epoch(100, 299), epoch(200, 399)])),
    /unordered or overlap/);
  throws("an epoch running backwards fails closed",
    () => recognizeAt(150, ctxOver([epoch(399, 300)])), /runs backwards/);

  const cps = [epoch(100, 199), epoch(200, 299), epoch(300, 399)];
  const ctx = ctxOver(cps);
  const scanEpoch = (H) => cps.findIndex(
    (c) => H >= c.epochRange.fromCoreHeight && H <= c.epochRange.toCoreHeight);
  let disagreements = 0;
  for (let H = 50; H <= 450; H++) {
    const viaIndex = recognizeAt(H, ctx);
    const viaScan = scanEpoch(H);
    const indexEpoch = viaIndex.status === "RECOGNIZED" ? viaIndex.bindingRef : -1;
    if (viaScan !== indexEpoch) disagreements++;
  }
  ok("the covering-epoch search and a plain scan agree over 401 heights", disagreements === 0);
}

// ---------------------------------------------------------------------------
// Confirmation round (2026-07-25), a required fix: firstClosing checked its ORDER precondition
// but not the TYPE, and an order guard written with relational operators is silently
// vacuous on non-numeric values. This is the same class as the suspension-bounds defect
// folded the round before, reached through a different exported function.
// ---------------------------------------------------------------------------
{
  const row = (height, anchor) => ({ height, coreChainLockedHeight: anchor });

  throws("a non-integer platform anchor fails closed",
    () => firstClosing(1000, [row(1, "abc"), row(2, "xyz")]),
    /non-integer coreChainLockedHeight/);
  throws("a single non-integer anchor among valid ones fails closed",
    () => firstClosing(150, [row(1, 200), row(2, "abc"), row(3, 300)]),
    /row 1 has a non-integer/);
  throws("a null anchor is not coerced to zero",
    () => firstClosing(10, [row(1, null)]), /non-integer coreChainLockedHeight/);
  throws("a non-integer anchor in the FIRST row fails closed (the old loop began at row 1)",
    () => firstClosing(10, [row(1, "abc"), row(2, 500)]), /row 0 has a non-integer/);

  // the reproduction that made this a must-fix rather than a tidy-up: the search returned a
  // WRONG closing block, not merely a missing one, so every slot allocation for that reward
  // would have recorded the wrong closing block
  const ordered = [row(1, 200), row(2, 250), row(3, 300)];
  const scan = (H, L) => L.find((r) => r.coreChainLockedHeight >= H) || null;
  let disagreements = 0;
  for (let H = 1; H <= 400; H++) {
    if (JSON.stringify(firstClosing(H, ordered)) !== JSON.stringify(scan(H, ordered))) disagreements++;
  }
  ok("the closing-block search and a plain scan agree over 400 heights on valid input",
     disagreements === 0);
}

// The registry mapping now has ONE definition, so the two consumers cannot drift apart.
{
  const { VERIFIER_OF } = require("./verifierRegistry.cjs");
  const writerCopy = require("./envelopeWriter.cjs").VERIFIER_OF;
  ok("the seam and the writer read the SAME mapping object", writerCopy === VERIFIER_OF);
  ok("the mapping still covers every component the claim profile derives",
     Object.keys(VERIFIER_OF).length === 12 && VERIFIER_OF.schedule === null);
}

// ---------------------------------------------------------------------------
// Confirmation a review (2026-07-25). The previous review's fixes were partly reachable
// around, and the exported primitives accepted malformed heights. Each case below is the
// reviewer's own, reproduced before the fix and driven here.
// ---------------------------------------------------------------------------
{
  const bind = () => ({ proTxHash: "aa", slotIndex: 0, contractId: "c", poolId: "p", activationCoreHeight: 1 });
  const epoch = (from, to) => ({ epochRange: { fromCoreHeight: from, toCoreHeight: to },
                                 extractedBinding: { bindings: [bind()], books: [] } });
  const ctxOver = (cps, extra) => ({
    checkpoints: cps, poolProTxHash: "aa", poolL1SlotIndex: 0, contractId: "c", poolId: "p",
    lifecycle: { suspensions: [], terminalHeight: null }, baseHeight: 1,
    suspendedAt: () => false, ...extra,
  });

  // a required fix: the epoch check used to be skippable by a caller-supplied flag. The memo is
  // now a module-private WeakSet, so passing the flag cannot suppress the validation.
  throws("unordered epochs still fail closed when the caller supplies the old flag",
    () => recognizeAt(150, ctxOver([epoch(300, 399), epoch(100, 199)], { epochOrderChecked: true })),
    /unordered or overlap/);

  // MAJOR: the exported suspension fallback skipped the endpoint validation that
  // buildEnvelope applied, so a direct caller got a plausible RECOGNIZED from a malformed
  // journal. Both paths now run one validated construction.
  throws("the exported path validates suspension bounds like the indexed path does",
    () => recognizeAt(150, {
      ...ctxOver([epoch(100, 999)]),
      suspendedAt: undefined,
      lifecycle: { suspensions: [{ start: { kind: "observed", banHeight: "abc" }, endHeight: "xyz" }],
                   terminalHeight: null },
    }), /non-integer bounds/);

  // MAJOR: NaN passed every range test, since both comparisons against it are false
  throws("recognizeAt refuses a NaN height", () => recognizeAt(NaN, ctxOver([epoch(100, 199)])),
    /not a safe non-negative integer/);
  throws("recognizeAt refuses a non-integer height", () => recognizeAt(1.5, ctxOver([epoch(100, 199)])),
    /not a safe non-negative integer/);
  throws("firstClosing refuses a NaN height",
    () => firstClosing(NaN, [{ height: 1, coreChainLockedHeight: 200 }]),
    /not a safe non-negative integer/);
  throws("firstClosing refuses a non-array ledger", () => firstClosing(10, null), /must be an array/);

  // the validated interval construction is shared, so the two paths cannot diverge again
  const { suspensionIntervals, makeSuspendedAt } = require("./auditSeam.cjs");
  const lc = { suspensions: [{ start: { kind: "observed", banHeight: 60 }, endHeight: 80 },
                             { start: { kind: "observed", banHeight: 1200 }, endHeight: 1300 }] };
  const shared = makeSuspendedAt(suspensionIntervals(lc, 1));
  const plainScan = (H) => lc.suspensions.some((s) => s.start.banHeight + 1 <= H && H <= s.endHeight);
  let disagreements = 0;
  for (let H = 1; H <= 1400; H++) if (shared(H) !== plainScan(H)) disagreements++;
  ok("the shared suspension index agrees with a plain scan over 1400 heights", disagreements === 0);
  throws("the shared construction refuses non-integer bounds",
    () => suspensionIntervals({ suspensions: [{ start: { kind: "observed", banHeight: "x" }, endHeight: "y" }] }, 1),
    /non-integer bounds/);
}

// ---------------------------------------------------------------------------
// Repository-access round (2026-07-25). Every case below was reproduced against the tree
// before the fix, and each is the reviewer's own scenario.
// ---------------------------------------------------------------------------
{
  const { assertEpochOrder, suspensionIntervals, makeSuspendedAt, prepareClosingIndex } =
    require("./auditSeam.cjs");
  const bind = () => ({ proTxHash: "aa", slotIndex: 0, contractId: "c", poolId: "p", activationCoreHeight: 1 });
  const epoch = (from, to) => ({ epochRange: { fromCoreHeight: from, toCoreHeight: to },
                                 extractedBinding: { bindings: [bind()], books: [] } });
  const ctxOver = (cps, extra) => ({
    checkpoints: cps, poolProTxHash: "aa", poolL1SlotIndex: 0, contractId: "c", poolId: "p",
    lifecycle: { suspensions: [], terminalHeight: null }, baseHeight: 1, ...extra,
  });

  // a required fix: the memo remembered an array IDENTITY, so mutating the array in place after a
  // successful validation skipped the next check and returned a wrong recognition.
  const cps = [epoch(100, 299), epoch(300, 399)];
  const ctx = ctxOver(cps);
  ok("a valid epoch array recognizes at 250", recognizeAt(250, ctx).status === "RECOGNIZED");
  cps[0].epochRange = { fromCoreHeight: 500, toCoreHeight: 599 };   // in place, same array
  throws("mutating an epoch IN PLACE after validation does not skip the next check",
    () => recognizeAt(250, ctx), /unordered or overlap/);

  // and the captured bounds are what the search reads, so a mutation cannot silently move a
  // height into a different epoch within a prepared context
  const cps2 = [epoch(100, 299), epoch(300, 399)];
  const bounds = assertEpochOrder(cps2);
  ok("assertEpochOrder returns frozen captured bounds",
     Object.isFrozen(bounds) && bounds.length === 2 && bounds[0].toCoreHeight === 299);
  // a review replaced this property. A caller-supplied capture used to be honoured when branded,
  // and that was the defect: the brand pointed at a MUTABLE source, so a capture taken before a
  // mutation stayed trusted after it. Captures now live in a module-private slot, so what a
  // caller puts on the context is ignored and the mutated array is re-validated.
  cps2[0].epochRange = { fromCoreHeight: 1, toCoreHeight: 5 };
  throws("a caller-supplied capture is IGNORED and the mutated array is re-derived",
    () => recognizeAt(250, ctxOver(cps2, { epochBounds: bounds })),
    /no covering epoch|unordered or overlap/);

  // MAJOR: an injected suspendedAt skipped the lifecycle-derived index entirely
  const suspended = ctxOver([epoch(100, 999)], {
    lifecycle: { suspensions: [{ start: { kind: "observed", banHeight: 140 }, endHeight: 160 }],
                 terminalHeight: null },
  });
  ok("a recorded suspension excludes height 150", recognizeAt(150, suspended).status === "UNRECOGNIZED");
  ok("an injected suspendedAt cannot override the lifecycle",
     recognizeAt(150, { ...suspended, suspendedAt: () => false }).status === "UNRECOGNIZED");

  // MAJOR: the exported index function accepted malformed heights
  throws("the suspension index refuses a NaN height",
    () => makeSuspendedAt(suspensionIntervals({ suspensions: [] }, 1))(NaN),
    /safe non-negative height/);
  ok("it still answers a valid height",
     makeSuspendedAt([[100, 200]])(150) === true && makeSuspendedAt([[100, 200]])(50) === false);

  // MAJOR: terminalHeight was the one relational comparison left untyped
  throws("a non-numeric terminalHeight is refused rather than compared",
    () => recognizeAt(250, ctxOver([epoch(100, 299)], {
      lifecycle: { suspensions: [], terminalHeight: "abc" } })),
    /terminalHeight must be a safe integer/);

  // MAJOR: the claimed closing-block index did not exist, so every reward revalidated the
  // whole ledger. It exists now, and it is frozen so a later mutation cannot move a closing
  // block.
  const rows = [{ height: 1, coreChainLockedHeight: 200 }, { height: 2, coreChainLockedHeight: 300 }];
  const idx = prepareClosingIndex(rows);
  // the caller-visible `prepared` marker is GONE (a review, MAJOR: any object carrying
  // prepared:true was trusted outright); preparedness is now a module-private brand
  ok("prepareClosingIndex returns a frozen captured index",
     Object.isFrozen(idx) && Object.isFrozen(idx.anchors) && Object.isFrozen(idx.rows[0]));
  ok("the prepared index and a raw ledger give the same answer",
     JSON.stringify(firstClosing(150, idx)) === JSON.stringify(firstClosing(150, rows)));
  throws("the prepared index still validates its ledger",
    () => prepareClosingIndex([{ height: 1, coreChainLockedHeight: "abc" }]),
    /non-integer coreChainLockedHeight/);
}

// THE REGISTRY RULE EXISTS IN FOUR PLACES AND THEY MUST AGREE (repository-access round,
// MAJOR). Deduplicating across languages is not possible: the mapping lives in the normative
// registry JSON, in the Python executable specification, in this JavaScript module, and
// inverted in runtimeVerifiers. The reviewer's point stands anyway, that the copies agreed by
// luck with nothing checking. Drift is now DETECTED even where it cannot be prevented.
{
  const { VERIFIER_OF } = require("./verifierRegistry.cjs");
  const { COMPONENT_OF } = require("./runtimeVerifiers.cjs");
  const registry = JSON.parse(fs.readFileSync(
    path.join(SCHEMA_DIR, "auditEnvelope.v1.registry.json"), "utf8"));

  const fromRegistry = {};
  for (const [name, comp] of Object.entries(registry.components)) {
    fromRegistry[name] = comp.verifier === undefined ? null : comp.verifier;
  }
  ok("the JavaScript mapping matches the NORMATIVE registry exactly",
     JSON.stringify(Object.entries(fromRegistry).sort()) ===
     JSON.stringify(Object.entries(VERIFIER_OF).sort()));

  // the Python executable specification holds the same table; read it from the checker itself
  const pyMap = JSON.parse(execFileSync("python3", ["-c",
    'import json,importlib.util;s=importlib.util.spec_from_file_location("cv","check_vectors.py");' +
    'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);' +
    'print(json.dumps(m.VERIFIER_OF if hasattr(m,"VERIFIER_OF") else {}))'],
    { cwd: SCHEMA_DIR, encoding: "utf8" }));
  if (Object.keys(pyMap).length) {
    // both sides carry the null-verifier component, so compare the WHOLE table
    ok("the Python mapping matches the JavaScript mapping exactly",
       JSON.stringify(Object.entries(pyMap).sort()) ===
       JSON.stringify(Object.entries(VERIFIER_OF).sort()));
  } else {
    // the same shape of escape hatch as the dependency branch below; if the mapping cannot be
    // read, the comparison did not happen and that is a failure rather than a pass
    ok("the Python checker exposes a mapping to compare", false);
  }

  // THE WIDER RULE TOO, not only the names (a review, MINOR): the dependency graph, the
  // barred set and the combined-component set are copied across the same four places, and a
  // drift there reaches the JavaScript derivation before the Python gate declines the result.
  {
    const { DEPS, BARRED } = require("./auditSeam.cjs");
    const py = JSON.parse(execFileSync("python3", ["-c",
      'import json,importlib.util;s=importlib.util.spec_from_file_location("cv","check_vectors.py");' +
      'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);' +
      'd=lambda o: sorted(o) if isinstance(o,set) else ({k:d(v) for k,v in o.items()} if isinstance(o,dict) else o);' +
      'print(json.dumps({"BARRED":d(getattr(m,"BARRED",[])),' +
      '"COMBINED_REQUIRED":d(getattr(m,"COMBINED_REQUIRED",[])),' +
      '"DEPS":d(getattr(m,"DEPS",{}))}))'],
      { cwd: SCHEMA_DIR, encoding: "utf8" }));

    // THE REGISTRY IS THE FOURTH SOURCE, and it was never consulted for these three rules
    // (a review, MINOR): the comment claimed four-way coverage while the comparison ran between
    // JavaScript and Python only, so a drift in the NORMATIVE document would have gone unseen by
    // the very check that exists to catch drift.
    const registry = JSON.parse(fs.readFileSync(
      path.join(SCHEMA_DIR, "auditEnvelope.v1.registry.json"), "utf8"));
    const regDeps = {};
    const regBarred = [];
    for (const [name, comp] of Object.entries(registry.components)) {
      if (comp.dependencies && comp.dependencies.length) regDeps[name] = comp.dependencies;
      if (comp.structurallyBarredFromAuthenticated) regBarred.push(name);
    }
    const normalise = (o) => JSON.stringify(Object.keys(o).sort().map((k) => [k, [...o[k]].sort()]));
    ok("the dependency graph matches the NORMATIVE REGISTRY", normalise(DEPS) === normalise(regDeps));
    ok("the barred set matches the NORMATIVE REGISTRY",
       JSON.stringify([...BARRED].sort()) === JSON.stringify(regBarred.sort()));
    // the combined set is the registry's own strongest profile, stated as authenticatedRequired
    const strongest = registry.aggregateProfiles["proof-verified-except-schedule"];
    ok("the registry states the combined set as a list of components",
       Array.isArray(strongest.authenticatedRequired) && strongest.authenticatedRequired.length > 0);
    ok("the combined set matches the NORMATIVE REGISTRY",
       JSON.stringify(Object.keys(VERIFIER_OF).filter((n) => n !== "schedule").sort()) ===
       JSON.stringify([...strongest.authenticatedRequired].sort()));

    ok("the BARRED set matches the Python executable specification",
       JSON.stringify([...BARRED].sort()) === JSON.stringify(py.BARRED.sort()));
    // the JavaScript combined set is derived (every component except schedule); Python states
    // it explicitly, so compare the two forms
    const jsCombined = Object.keys(VERIFIER_OF).filter((n) => n !== "schedule").sort();
    ok("the COMBINED_REQUIRED set matches the Python executable specification",
       JSON.stringify(jsCombined) === JSON.stringify([...py.COMBINED_REQUIRED].sort()));
    // NO ESCAPE HATCH FOR AN ABSENT SIDE (a review, MINOR). This used to fall through to a
    // passing branch when the Python graph could not be read, and it could NEVER be read,
    // because DEPS was a local inside check_semantics. So the one comparison that mattered
    // most was vacuous while reporting success. The Python literal is now at module scope
    // (unchanged in content) and its absence is a FAILURE, not a free pass.
    ok("the Python executable specification exposes its dependency graph",
       Object.keys(py.DEPS).length > 0);
    const norm = (o) => JSON.stringify(Object.keys(o).sort().map((k) => [k, [...o[k]].sort()]));
    ok("the dependency graph matches the Python executable specification",
       norm(DEPS) === norm(py.DEPS));
    // and every dependency names a real component
    ok("every dependency edge names a component in the mapping",
       Object.entries(DEPS).every(([k, v]) =>
         k in VERIFIER_OF && v.every((d) => d in VERIFIER_OF)));
    ok("every barred component is a component in the mapping",
       [...BARRED].every((b) => b in VERIFIER_OF));
  }

  // and the INVERSE table in the verifier harness must invert this one
  const inverted = {};
  for (const [comp, verifier] of Object.entries(VERIFIER_OF)) {
    if (verifier !== null) inverted[verifier] = comp;
  }
  ok("runtimeVerifiers' COMPONENT_OF is the exact inverse of the mapping",
     JSON.stringify(Object.entries(inverted).sort()) ===
     JSON.stringify(Object.entries(COMPONENT_OF).sort()));
}

// ---------------------------------------------------------------------------
// Repository-access a review. The previous review's captures were sound but UNBRANDED, so a
// caller could hand in fabricated "prepared" data and get the same wrong answers the
// removed function override used to give. Each case below was reproduced first.
// ---------------------------------------------------------------------------
{
  const { assertEpochOrder, suspensionIntervals, makeSuspendedAt, prepareClosingIndex } =
    require("./auditSeam.cjs");
  const bind = () => ({ proTxHash: "aa", slotIndex: 0, contractId: "c", poolId: "p", activationCoreHeight: 1 });
  const epoch = (from, to) => ({ epochRange: { fromCoreHeight: from, toCoreHeight: to },
                                 extractedBinding: { bindings: [bind()], books: [] } });

  // FABRICATED epoch bounds must be ignored, not trusted. The real epoch is 300..399, so
  // height 150 is outside it; a hand-made bounds array claiming 100..399 used to recognize.
  const realCps = [epoch(300, 399)];
  const honest = {
    checkpoints: realCps, poolProTxHash: "aa", poolL1SlotIndex: 0, contractId: "c", poolId: "p",
    lifecycle: { suspensions: [], terminalHeight: null }, baseHeight: 1,
  };
  ok("height 150 is outside the real epoch", recognizeAt(150, honest).status === "UNRECOGNIZED");
  ok("a FABRICATED epochBounds array is ignored, not trusted",
     recognizeAt(150, { ...honest,
       epochBounds: [{ index: 0, fromCoreHeight: 100, toCoreHeight: 399 }] }).status === "UNRECOGNIZED");
  // A GENUINE capture is ignored too, now: the answer always comes from the evidence in the
  // context. Honouring genuine captures is what made the stale-capture defect possible, since
  // "genuine at preparation time" and "still true now" are different statements.
  ok("even a genuine capture does not widen the real epoch",
     recognizeAt(150, { ...honest,
       epochBounds: assertEpochOrder([epoch(100, 399)]) }).status === "UNRECOGNIZED");
  ok("the real epoch still recognizes its own heights",
     recognizeAt(350, honest).status === "RECOGNIZED");
  // THE a review CASE: a capture taken before the source changed must not survive the change.
  {
    const lc = { suspensions: [] };
    const stale = suspensionIntervals(lc, 1);
    lc.suspensions.push({ start: { kind: "observed", banHeight: 140 }, endHeight: 160 });
    ok("a capture taken BEFORE the lifecycle changed cannot un-suspend height 150",
       recognizeAt(150, { ...honest, checkpoints: [epoch(100, 999)], lifecycle: lc,
                          suspensionIntervals: stale }).status === "UNRECOGNIZED");
  }

  // FABRICATED suspension intervals must be ignored: the lifecycle records 141..160
  const suspended = { ...honest,
    checkpoints: [epoch(100, 999)],
    lifecycle: { suspensions: [{ start: { kind: "observed", banHeight: 140 }, endHeight: 160 }],
                 terminalHeight: null } };
  ok("the recorded suspension excludes height 150",
     recognizeAt(150, suspended).status === "UNRECOGNIZED");
  ok("an EMPTY fabricated suspensionIntervals array cannot un-suspend it",
     recognizeAt(150, { ...suspended, suspensionIntervals: [] }).status === "UNRECOGNIZED");
  ok("a genuine intervals capture is also ignored, and the lifecycle still governs",
     recognizeAt(150, { ...suspended,
       suspensionIntervals: suspensionIntervals(suspended.lifecycle, 1) }).status === "UNRECOGNIZED");

  // the exported membership function validates its tuples
  throws("makeSuspendedAt refuses non-integer interval bounds",
    () => makeSuspendedAt([["abc", "xyz"]]), /well-formed \[start, end\] integer pair/);
  throws("makeSuspendedAt refuses overlapping intervals",
    () => makeSuspendedAt([[10, 100], [50, 200]]), /intervals overlap/);
  throws("makeSuspendedAt refuses a backwards interval",
    () => makeSuspendedAt([[200, 100]]), /well-formed/);

  // the closing index: no caller-settable marker, no retained caller rows
  const rows = [{ height: 1, coreChainLockedHeight: 200 }, { height: 2, coreChainLockedHeight: 300 }];
  const idx2 = prepareClosingIndex(rows);
  // A FABRICATED index must be re-validated. The first version of this check omitted the OLD
  // caller-settable marker, so it would still have passed against the very code it was meant
  // to constrain (a review, MINOR): a regression that trusted `prepared: true` again would not
  // have failed it. Both shapes are driven now, with and without the marker.
  ok("a fabricated index WITHOUT the old marker is re-validated rather than trusted", (() => {
    const fabricated = { anchors: [250], rows: [{ height: 999, coreChainLockedHeight: 1 }] };
    try { firstClosing(250, fabricated); return false; } catch (e) { return /must be an array/.test(e.message); }
  })());
  ok("a fabricated index CARRYING the old `prepared: true` marker is still re-validated", (() => {
    const fabricated = { prepared: true, anchors: [250],
                     rows: [{ height: 999, coreChainLockedHeight: 1 }] };
    try { firstClosing(250, fabricated); return false; } catch (e) { return /must be an array/.test(e.message); }
  })());
  ok("mutating a caller row after preparation cannot change the answer", (() => {
    const before = JSON.stringify(firstClosing(250, idx2));
    rows[1].height = 999; rows[1].coreChainLockedHeight = 1;
    return JSON.stringify(firstClosing(250, idx2)) === before;
  })());

  // the once-per-envelope property, counted rather than asserted
  {
    const ev = JSON.parse(JSON.stringify(positive));
    delete ev.rewards; delete ev.claimProfile;
    const rewardCount = ev.coverage.coreLedger.length;
    prepareClosingIndex.calls = 0;
    buildEnvelope(ev);
    ok(`the closing index is prepared ONCE for ${rewardCount} rewards, not per reward`,
       prepareClosingIndex.calls === 1);
  }
}

console.log(`auditSeamTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
