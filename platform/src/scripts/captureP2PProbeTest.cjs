/**
 * Fixtures for the peer client's HANDSHAKE STATE MACHINE (round 8, a soundness-review finding).
 *
 * WHY THESE EXIST. Round 8 found that the capture client validated every frame correctly and
 * then dispatched on the command name with no notion of ORDER, so a peer sending a
 * checksum-valid `mnlistdiff` before any `version` produced a completed capture whose common
 * protocol version was recorded as 0. The review also noted the deeper problem: the client's
 * state machine had NO fixture at all. The committed capture's own test checks the bytes and
 * metadata already recorded, not the client that produced them, so the client "would stay green
 * if it reverted to recording the offered version or accepted a response before version
 * negotiation".
 *
 * These drive the rules with no socket and no node. The handshake is exported as a state
 * machine over already-frame-validated messages precisely so that ordering can be tested
 * offline, which is the part that was untestable before.
 *
 * The property under test throughout: an ordering or validation failure must produce NO
 * capture. Refusing is not enough on its own, because the defect was never a crash; it was a
 * plausible, complete-looking record with a false version in it.
 */
"use strict";

const {
  createHandshake, drainFrames, frame,
  validateOfferedVersion, parsePeerVersion,
  MIN_PEER_PROTO_VERSION, VERSION_FIXED_PREFIX,
  CAPTURE_MIN_VERSION, CAPTURE_MAX_VERSION,
} = require("./captureP2PMnListDiffProbe.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const throws = (name, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || "")); }
};

const H0 = "aa".repeat(32);
const H1 = "bb".repeat(32);

/** a session wired to record what it did instead of touching a socket */
const session = (protocolVersion = 70240) => {
  const sent = [], captures = [], refusals = [];
  const s = createHandshake({
    protocolVersion, baseDisplay: H0, tipDisplay: H1, target: "test:0",
    send: (command, payload) => sent.push({ command, payload }),
    capture: (record) => captures.push(record),
    refuse: (reason) => refusals.push(reason),
  });
  return { s, sent, captures, refusals };
};

/** a well-formed version payload stating `v`, long enough to carry the fixed prefix */
const versionBody = (v, length = 64) => {
  const b = Buffer.alloc(length);
  b.writeInt32LE(v, 0);
  return b;
};
const DIFF = Buffer.from("deadbeef", "hex");

// ---- the local offer is validated before we connect ----
ok("an absent offer defaults to the current protocol version", validateOfferedVersion(undefined) === 70240);
ok("a numeric string offer inside the decoder's range is accepted",
   validateOfferedVersion("70235") === 70235);
throws("a nonnumeric offer is refused rather than becoming NaN",
  () => validateOfferedVersion("abc"), /not an integer/);
throws("a fractional offer is refused", () => validateOfferedVersion("70240.5"), /not an integer/);
// THE OFFER IS BOUND BY WHAT THE DECODER READS, NOT BY DASH'S PEER FLOOR (round 10, MAJOR).
// Staying above 70221 keeps a Dash peer talking to us; it does not mean the bytes we collect can
// be parsed. 70229 is the case the review named: a perfectly acceptable peer version, and one
// whose mnlistdiff layout the pinned decoder declines.
throws("an offer below the decoder's range is refused",
  () => validateOfferedVersion(CAPTURE_MIN_VERSION - 1), /outside the range this capture's decoder reads/);
throws("70229 specifically is refused, since the decoder starts at 70230",
  () => validateOfferedVersion(70229), /outside the range this capture's decoder reads/);
throws("an offer above the decoder's range is refused",
  () => validateOfferedVersion(CAPTURE_MAX_VERSION + 1), /outside the range this capture's decoder reads/);
// THE CONSTRUCTOR ENFORCES THE SAME RULE AS THE COMMAND-LINE PATH (round 12, MINOR). It is an
// exported entry point and used to take its offer on trust, so a caller reaching it directly with
// a nonnumeric value produced NaN, both range comparisons against NaN were false, and the session
// completed with a common version that serializes as null. Same unusable capture, different route.
throws("the constructor refuses a nonnumeric offer rather than producing NaN",
  () => createHandshake({ protocolVersion: "abc", baseDisplay: H0, tipDisplay: H1,
                          target: "test:0", send() {}, capture() {}, refuse() {} }),
  /needs an integer protocolVersion/);
throws("the constructor refuses an offer outside the decoder's range",
  () => createHandshake({ protocolVersion: 70229, baseDisplay: H0, tipDisplay: H1,
                          target: "test:0", send() {}, capture() {}, refuse() {} }),
  /outside the range this capture's decoder reads/);
throws("the constructor refuses an absent offer rather than defaulting one",
  () => createHandshake({ baseDisplay: H0, tipDisplay: H1, target: "test:0",
                          send() {}, capture() {}, refuse() {} }),
  /needs an integer protocolVersion/);

ok("both ends of the decoder's range are accepted",
   validateOfferedVersion(CAPTURE_MIN_VERSION) === CAPTURE_MIN_VERSION &&
   validateOfferedVersion(CAPTURE_MAX_VERSION) === CAPTURE_MAX_VERSION);

// ---- the peer's version body is validated the way Core validates it ----
ok("a well-formed peer version parses", parsePeerVersion(versionBody(70240)).version === 70240);
ok("a body shorter than the fixed prefix is refused",
   /shorter than/.test(parsePeerVersion(Buffer.alloc(VERSION_FIXED_PREFIX - 1)).error || ""));
ok("a four-byte body is refused even though the version field fits",
   /shorter than/.test(parsePeerVersion(versionBody(70240, 4)).error || ""));
ok("a peer below the minimum protocol version is refused",
   /below the minimum/.test(parsePeerVersion(versionBody(MIN_PEER_PROTO_VERSION - 1)).error || ""));

// ---- ordering: nothing is accepted before the peer's version ----
// This is the round-8 defect itself. Before the fold each of these produced a capture.
for (const early of ["mnlistdiff", "verack", "ping", "inv"]) {
  const { s, captures, refusals } = session();
  s.handle(early, DIFF);
  ok(`${early} before version is refused`, refusals.length === 1);
  ok(`${early} before version produces NO capture`, captures.length === 0);
  ok(`${early} before version names the reason`, /before the peer's version/.test(refusals[0] || ""));
}

// ---- ordering: the happy path, and the common version it records ----
// THIS CASE USED TO NEGOTIATE 70229 AND REQUIRE SUCCESS (round 10, MAJOR). That is below the
// decoder's supported floor, so the fixture was requiring the client to report a completed
// capture whose bytes the only available consumer declines. It now negotiates a version inside
// the decoder's range, and the out-of-range case below is asserted as a refusal instead.
{
  const { s, sent, captures, refusals } = session(70240);
  s.handle("version", versionBody(70235));
  ok("the peer's version moves the session to AWAIT_VERACK", s.state === "AWAIT_VERACK");
  ok("a verack is sent in reply", sent[0] && sent[0].command === "verack");
  s.handle("verack", Buffer.alloc(0));
  ok("the verack sends the request", sent[1] && sent[1].command === "getmnlistd");
  ok("the request carries both hashes", sent[1].payload.length === 64);
  s.handle("mnlistdiff", DIFF);
  ok("the diff is captured", captures.length === 1 && refusals.length === 0);
  ok("the capture records OUR offer", captures[0].protocolVersionOffered === 70240);
  ok("the capture records the PEER's offer", captures[0].protocolVersionPeerOffered === 70235);
  ok("the common version is the lower of the two, which selects the layout",
     captures[0].protocolVersionCommon === 70235);
  ok("the payload is recorded", captures[0].payloadHex === "deadbeef" && captures[0].byteLength === 4);
}

// ---- the negotiated version must be one the decoder reads (round 10, MAJOR) ----
// The peer is entirely acceptable to Dash here. What is not acceptable is spending a capture on a
// layout nothing in this build can parse, so the session stops BEFORE the request goes out rather
// than collecting bytes and leaving a consumer to discover the problem.
{
  const { s, sent, captures, refusals } = session(70240);
  s.handle("version", versionBody(70229));
  ok("a peer negotiating below the decoder's floor is refused", refusals.length === 1);
  ok("and the refusal names the decoder's range",
     /negotiated protocol version 70229 is outside the range/.test(refusals[0] || ""));
  ok("no request is sent, so no bytes are collected for a layout nothing reads",
     sent.filter((m) => m.command === "getmnlistd").length === 0);
  s.handle("verack", Buffer.alloc(0));
  s.handle("mnlistdiff", DIFF);
  ok("and no capture can follow it", captures.length === 0);
}
{
  // the boundary itself is usable, so the rule refuses only what the decoder truly cannot read
  const { s, captures, refusals } = session(70240);
  s.handle("version", versionBody(CAPTURE_MIN_VERSION));
  s.handle("verack", Buffer.alloc(0));
  s.handle("mnlistdiff", DIFF);
  ok("negotiating exactly the decoder's floor is accepted",
     captures.length === 1 && refusals.length === 0 &&
     captures[0].protocolVersionCommon === CAPTURE_MIN_VERSION);
}

// ---- ordering: a diff after version but BEFORE the request is refused ----
// A peer volunteering a diff mid-handshake must not have it recorded as the answer to a
// request that was never sent.
{
  const { s, captures, refusals } = session();
  s.handle("version", versionBody(70240));
  s.handle("mnlistdiff", DIFF);
  ok("a diff before the request is refused", refusals.length === 1 && captures.length === 0);
  ok("and it names the reason", /before the handshake completed/.test(refusals[0] || ""));
}

// ---- a second version message cannot re-label a negotiation already made ----
{
  const { s, captures, refusals } = session();
  s.handle("version", versionBody(70240));
  s.handle("version", versionBody(70221));
  ok("a second version is refused", refusals.length === 1 && captures.length === 0);
  ok("and it names the reason", /second version/.test(refusals[0] || ""));
}

// ---- a rejected version body never advances the handshake ----
{
  const { s, captures, refusals } = session();
  s.handle("version", versionBody(70240, 4));
  ok("a short version body is refused", refusals.length === 1);
  ok("and no capture follows it", captures.length === 0);
  s.handle("verack", Buffer.alloc(0));
  s.handle("mnlistdiff", DIFF);
  ok("the session is closed, so later messages cannot revive it", captures.length === 0);
}

// ---- a refused session stays refused ----
{
  const { s, captures, refusals } = session();
  s.handle("mnlistdiff", DIFF);
  s.handle("version", versionBody(70240));
  s.handle("verack", Buffer.alloc(0));
  s.handle("mnlistdiff", DIFF);
  ok("a session refused once emits exactly one refusal", refusals.length === 1);
  ok("and never a capture", captures.length === 0);
  ok("and stays CLOSED", s.state === "CLOSED");
}

// ---- the frame reader still rejects what a peer would reject ----
{
  const good = frame("version", versionBody(70240));
  const seenMsgs = [];
  const rest = drainFrames(good, (c) => seenMsgs.push(c), () => {});
  ok("a valid frame is delivered", seenMsgs[0] === "version" && rest.length === 0);

  const badMagic = Buffer.from(good); badMagic[0] ^= 0xff;
  let err = null;
  ok("a wrong-magic frame is not delivered",
     drainFrames(badMagic, () => { err = "delivered"; }, (m) => { err = m; }) === null &&
     /magic/.test(err || ""));

  const badSum = Buffer.from(good); badSum[20] ^= 0xff;
  err = null;
  ok("a checksum mismatch is not delivered",
     drainFrames(badSum, () => { err = "delivered"; }, (m) => { err = m; }) === null &&
     /checksum/.test(err || ""));

  // a partial frame is held, not guessed at
  const partial = good.subarray(0, good.length - 1);
  const held = [];
  ok("a partial frame is buffered rather than delivered",
     drainFrames(partial, (c) => held.push(c), () => {}).length === partial.length &&
     held.length === 0);
}

console.log(`captureP2PProbeTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
