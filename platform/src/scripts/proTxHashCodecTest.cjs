/**
 * Fixtures for the proTxHash conversion helper (build-order item 4). Plain `node`.
 * The pinned NON-SYMMETRIC vector must reproduce both ways, the grammar must fail
 * closed, and the conversion must agree with BOTH shipped consumers of the rule: the
 * conformance suite's decoder (which reverses the payload's raw bytes into the
 * envelope's display form) and the committed positive vector's own identity.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const {
  PINNED_DISPLAY, PINNED_RAW_HEX,
  assertHex32, displayToRaw, displayToRawHex, rawToDisplay, assertRoundTrip,
} = require("./proTxHashCodec.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const throws = (name, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || "")); }
};

// ---- the pinned vector, both ways ----
ok("assertRoundTrip passes", assertRoundTrip() === true);
ok("display -> raw hex reproduces the pinned vector", displayToRawHex(PINNED_DISPLAY) === PINNED_RAW_HEX);
ok("raw hex -> display reproduces the pinned vector", rawToDisplay(PINNED_RAW_HEX) === PINNED_DISPLAY);
ok("raw Buffer -> display reproduces the pinned vector",
   rawToDisplay(Buffer.from(PINNED_RAW_HEX, "hex")) === PINNED_DISPLAY);
ok("the two forms DIFFER (a symmetric vector could not catch a reversal mistake)",
   PINNED_DISPLAY !== PINNED_RAW_HEX);
ok("double reversal is the identity", displayToRawHex(displayToRawHex(PINNED_DISPLAY)) === PINNED_DISPLAY);
ok("displayToRaw returns 32 raw bytes", displayToRaw(PINNED_DISPLAY).length === 32);
// the first display byte is the LAST raw byte (the reversal, asserted directly)
ok("first display byte is the last raw byte",
   PINNED_DISPLAY.slice(0, 2) === PINNED_RAW_HEX.slice(-2));
ok("rawToDisplay does not mutate the caller's Buffer", (() => {
  const b = Buffer.from(PINNED_RAW_HEX, "hex");
  rawToDisplay(b);
  return b.toString("hex") === PINNED_RAW_HEX;
})());

// ---- grammar fails closed ----
throws("uppercase hex is refused, never normalized", () => assertHex32(PINNED_DISPLAY.toUpperCase(), "h"), /lowercase hex/);
throws("short hash is refused", () => displayToRaw("ab"), /64 lowercase hex/);
throws("non-hex is refused", () => displayToRaw("z".repeat(64)), /64 lowercase hex/);
throws("non-string is refused", () => displayToRaw(null), /must be a string/);
throws("a 31-byte Buffer is refused", () => rawToDisplay(Buffer.alloc(31)), /exactly 32/);
throws("a 33-byte Buffer is refused", () => rawToDisplay(Buffer.alloc(33)), /exactly 32/);

// ---- agreement with the shipped conformance suite ----
// the checker pins the same pair as its own constants (POOL_DISPLAY / POOL_RAW)
const checker = fs.readFileSync(
  path.join(__dirname, "..", "..", "..", "docs", "schema", "check_vectors.py"), "utf8");
ok("the checker pins the SAME display hash", checker.includes(PINNED_DISPLAY));
ok("the checker derives raw by reversing the display form (POOL_RAW = ...[::-1])",
   /POOL_RAW\s*=\s*bytes\.fromhex\(POOL_DISPLAY\)\[::-1\]/.test(checker));

// the committed positive vector carries the display form as its pool identity
const positive = JSON.parse(fs.readFileSync(
  path.join(__dirname, "..", "..", "..", "docs", "schema", "vectors", "positive_minimal.json"), "utf8"));
ok("the positive vector's poolProTxHash is the pinned DISPLAY form",
   positive.poolProTxHash === PINNED_DISPLAY);
ok("the vector's identity round-trips through the helper",
   rawToDisplay(displayToRaw(positive.poolProTxHash)) === positive.poolProTxHash);
// every checkpoint binding in the vector names the same display identity, and its raw
// form is what a payload encoder must write
for (const cp of positive.checkpoints) {
  for (const b of cp.extractedBinding.bindings) {
    ok(`binding ${b.slotIndex} proTxHash is valid display hex`, assertHex32(b.proTxHash, "b") === b.proTxHash);
  }
}

// ---- first-appearance identity: the txid IS the proTxHash (display form) ----
// the acceptance envelope derives its pool identity as the double-SHA256 of the retained
// ProRegTx bytes, reversed into display form; reproduce that here with the helper
const crypto = require("crypto");
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const faRaw = sha256(sha256(Buffer.from("99".repeat(120), "hex")));
ok("a ProRegTx txid converts to its display proTxHash via the helper",
   rawToDisplay(faRaw) === faRaw.reverse().toString("hex"));

console.log(`proTxHashCodecTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
