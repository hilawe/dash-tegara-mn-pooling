/**
 * Offline test for the outcome classifier (plain `node`, no network): every
 * wrapper variant maps to its token, the closed fallbacks hold, every
 * out-of-contract shape refuses (extra members included), and the UNPINNED
 * unique-index identity fails CLOSED (every refusal is the terminal
 * other-error token until the pinning-time read lands). The wrapper-boundary
 * cases here are the classifier's half; the wrapper's own golden cases join
 * in e2RawCaptureTest.cjs when that patch lands, and the full
 * every-variant-times-every-operation-class boundary matrix is asserted by
 * the procedure tests that own the operation context.
 */
const { classifyOutcome, TOKENS, UNIQUE_INDEX_IDENTITY } = require("./e2Outcome.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed++; }
  else { failed++; console.error("FAIL:", name); }
};
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

// the four conforming literals, built fresh per use so a case cannot mutate a shared one
const mkVerified = () => ({ outcome: "verified-proof", proof: { grovedbProof: "aa" },
  metadata: { chainId: "c" }, proofMsg: "abcd", metadataMsg: "0102", unknownFieldsDropped: 0 });
const mkRefusal = (code) => ({ outcome: "execution-refusal", code, data: "00ff", message: "structured" });
const mkMalformed = () => ({ outcome: "malformed-response", reason: "undecodable" });
const mkTransport = () => ({ outcome: "transport-failure", reason: "socket closed" });

// ---- the four variants map to their tokens ----
ok("verified-proof -> success-with-proof", classifyOutcome(mkVerified()) === TOKENS.SUCCESS);
ok("a consensus-coded execution-refusal -> execution-error-other (identity unpinned, fail-closed)",
  classifyOutcome(mkRefusal(40105)) === TOKENS.OTHER);
ok("malformed-response -> ambiguous", classifyOutcome(mkMalformed()) === TOKENS.AMBIGUOUS);
ok("transport-failure -> ambiguous", classifyOutcome(mkTransport()) === TOKENS.AMBIGUOUS);

// ---- the fail-closed pin state is REAL, not assumed: while the identity is
// null, no integer code whatsoever reaches the unique-index token ----
ok("the identity is genuinely unpinned in this build", UNIQUE_INDEX_IDENTITY === null);
for (const code of [0, 1, 1000, 4009, 40105, -7, Number.MAX_SAFE_INTEGER]) {
  ok(`unpinned: code ${code} never classifies unique-index`,
    classifyOutcome(mkRefusal(code)) !== TOKENS.UNIQUE);
}

// ---- ONLY A CONSENSUS CODE IS A REFUSAL (a soundness-review finding). The contrary control is the answer Platform's
// gateway actually returned on 2026-09-23 for a wait whose deadline elapsed, copied from the
// error record the writer journaled in that live run. Before the repair it classified
// execution-error-other and was journaled as a reservation refusal.
{
  const LIVE_TIMEOUT = { outcome: "execution-refusal", code: 13, data: "", message: "Timeout error: deadline has elapsed" };
  ok("the gateway's own timeout answer is AMBIGUOUS, not a refusal",
    classifyOutcome(LIVE_TIMEOUT) === TOKENS.AMBIGUOUS);
  for (let code = 0; code <= 16; code++) {
    ok(`gRPC status ${code} in the structured member is ambiguous`, classifyOutcome(mkRefusal(code)) === TOKENS.AMBIGUOUS);
  }
  // the edges of Platform's consensus range (rs-dapi error_mapping, grpc_code)
  ok("9999, just below the consensus range, is ambiguous", classifyOutcome(mkRefusal(9999)) === TOKENS.AMBIGUOUS);
  ok("10000, the first consensus code, is a refusal", classifyOutcome(mkRefusal(10000)) === TOKENS.OTHER);
  ok("49999, the last consensus code, is a refusal", classifyOutcome(mkRefusal(49999)) === TOKENS.OTHER);
  ok("50000, past the consensus range, is ambiguous", classifyOutcome(mkRefusal(50000)) === TOKENS.AMBIGUOUS);
  ok("a negative code is ambiguous", classifyOutcome(mkRefusal(-7)) === TOKENS.AMBIGUOUS);
  // real consensus codes from the pinned table: a transfer amount refusal, a nonce refusal
  ok("the pinned transfer-amount refusal, 10524, is a refusal", classifyOutcome(mkRefusal(10524)) === TOKENS.OTHER);
  ok("the pinned nonce refusal, 40204, is a refusal", classifyOutcome(mkRefusal(40204)) === TOKENS.OTHER);
  // the range decides before the identity: a pinned identity outside the range cannot make a
  // gateway answer into a unique-index refusal
  ok("an out-of-range code equal to a pinned identity is still ambiguous",
    classifyOutcome(mkRefusal(13), { code: 13, dataMatches: () => true }) === TOKENS.AMBIGUOUS);
  // EVERY code from below zero to past the range, against an expectation written here from the
  // spec rather than imported, so an interior exclusion cannot hide between sampled values
  const expectRefusal = (code) => code >= 10000 && code <= 49999;
  let mismatches = 0;
  for (let code = -5; code <= 60005; code++) {
    const t = classifyOutcome(mkRefusal(code));
    if (t !== (expectRefusal(code) ? TOKENS.OTHER : TOKENS.AMBIGUOUS)) mismatches++;
  }
  ok("every code from -5 to 60005 classifies by the consensus range, with no exception", mismatches === 0);
  ok("a malformed shape still refuses loudly before the range is read",
    (() => { try { classifyOutcome({ ...LIVE_TIMEOUT, extra: 1 }); return false; } catch { return true; } })());
}

// ---- the token set is pinned by EXACT VALUE and uniqueness, not by count
// (the batched checker's finding 7: renaming a token the unpinned branch
// never emits survived a count-only check) ----
ok("token set is closed and frozen", Object.isFrozen(TOKENS));
ok("the four token VALUES are exactly the contract's",
  TOKENS.SUCCESS === "success-with-proof"
  && TOKENS.UNIQUE === "execution-error-unique-index"
  && TOKENS.OTHER === "execution-error-other"
  && TOKENS.AMBIGUOUS === "ambiguous");
ok("the four token values are distinct",
  new Set(Object.values(TOKENS)).size === 4 && Object.keys(TOKENS).length === 4);

// ---- the PINNED-identity branches, executed through the test-only seam (the
// production constant stays null; the seam is the governed hatch the module
// documents, and these cases become the real pinned fixtures at pinning) ----
{
  const identity = { code: 40105, dataMatches: (d) => (d === "aa11" ? true : d === "" ? "malformed" : false) };
  ok("pinned: the exact structural identity classifies unique-index",
    classifyOutcome({ ...mkRefusal(40105), data: "aa11" }, identity) === TOKENS.UNIQUE);
  ok("pinned: decodable non-unique data on the pinned code classifies other",
    classifyOutcome({ ...mkRefusal(40105), data: "bb22" }, identity) === TOKENS.OTHER);
  ok("pinned: MALFORMED data on the pinned code classifies ambiguous, never an execution error",
    classifyOutcome({ ...mkRefusal(40105), data: "" }, identity) === TOKENS.AMBIGUOUS);
  ok("pinned: a different code stays other regardless of data",
    classifyOutcome({ ...mkRefusal(40100), data: "aa11" }, identity) === TOKENS.OTHER);
}

// ---- out-of-contract shapes refuse loudly, extra members included ----
throws("null refuses", () => classifyOutcome(null), /not an object/);
throws("an array refuses", () => classifyOutcome([]), /not an object/);
throws("an unknown outcome refuses", () => classifyOutcome({ outcome: "ok" }), /unknown outcome/);
throws("a verified-proof with an EXTRA member refuses (an extra member is a defect)",
  () => classifyOutcome({ ...mkVerified(), extra: 1 }), /extra member/);
throws("an execution-refusal with an extra member refuses",
  () => classifyOutcome({ ...mkRefusal(1), stack: "x" }), /extra member/);
throws("a verified-proof missing proofMsg refuses",
  () => { const v = mkVerified(); delete v.proofMsg; classifyOutcome(v); }, /missing member/);
throws("a refusal missing its structured code refuses",
  () => { const v = mkRefusal(1); delete v.code; classifyOutcome(v); }, /missing member/);
throws("a non-integer code refuses",
  () => classifyOutcome(mkRefusal("4009")), /code is not an integer/);
throws("uppercase-hex data refuses (the contract's hex is lowercase)",
  () => classifyOutcome({ ...mkRefusal(1), data: "00FF" }), /not lowercase hex/);
throws("an empty proofMsg refuses",
  () => classifyOutcome({ ...mkVerified(), proofMsg: "" }), /proofMsg/);
throws("odd-length hex in metadataMsg refuses",
  () => classifyOutcome({ ...mkVerified(), metadataMsg: "abc" }), /metadataMsg/);
throws("a negative unknownFieldsDropped refuses",
  () => classifyOutcome({ ...mkVerified(), unknownFieldsDropped: -1 }), /unknownFieldsDropped/);
throws("a malformed-response with an empty reason refuses",
  () => classifyOutcome({ outcome: "malformed-response", reason: "" }), /reason/);
throws("a transport-failure with an extra member refuses",
  () => classifyOutcome({ ...mkTransport(), errno: 32 }), /extra member/);

// ---- message text NEVER participates: two refusals differing only in message
// classify identically, and a message crafted to look like a uniqueness error
// stays on the other-error token ----
ok("message text does not steer classification",
  classifyOutcome({ ...mkRefusal(7), message: "duplicate unique index violation" })
  === classifyOutcome({ ...mkRefusal(7), message: "completely different" }));

console.log(`e2OutcomeTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
