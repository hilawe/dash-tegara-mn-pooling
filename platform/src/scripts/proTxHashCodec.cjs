/**
 * proTxHashCodec - build-order item 4 of the REVIEW-COMPLETE design (revision 27).
 *
 * THE CONVERSION, pinned: the signed checkpoint stores a node's proTxHash as RAW 32
 * CONSENSUS BYTES, while the Core RPC half (and therefore the envelope) carries the
 * lowercase DISPLAY hash, which is the byte-REVERSED internal hash, exactly like a txid.
 * Getting this backwards silently mismatches a real binding against a real node, so the
 * conversion is a named helper with the pinned NON-SYMMETRIC vector from the live devnet
 * node (the two forms differ, so a symmetric-input mistake cannot pass):
 *
 *   display  7838ca79f9866978160af819b677002c7e1151b4665bd15c4c2f11a964d2cdb3
 *   raw      b3cdd264a9112f4c5cd15b66b451117e2c0077b619f80a16786986f979ca3878
 *
 * FAIL-CLOSED: every input is validated for exact 32-byte length and lowercase-hex
 * grammar before conversion (an uppercase or short hash is a caller error, never
 * silently normalized), and `assertRoundTrip` is exported so a deployment can assert the
 * pinned pair at startup.
 */
"use strict";

/** the pinned non-symmetric vector, from the live devnet node */
const PINNED_DISPLAY = "7838ca79f9866978160af819b677002c7e1151b4665bd15c4c2f11a964d2cdb3";
const PINNED_RAW_HEX = "b3cdd264a9112f4c5cd15b66b451117e2c0077b619f80a16786986f979ca3878";

const HEX32 = /^[0-9a-f]{64}$/;

function fail(msg) {
  throw new Error(`proTxHash: ${msg}`);
}

/** validate a lowercase 32-byte hex string (the envelope's hex32 grammar) */
function assertHex32(hex, label) {
  if (typeof hex !== "string") fail(`${label} must be a string`);
  if (!HEX32.test(hex)) {
    fail(`${label} must be exactly 64 lowercase hex characters (got ${JSON.stringify(hex).slice(0, 72)})`);
  }
  return hex;
}

/** reverse the 32 bytes of a validated hex string */
function reverseHex32(hex, label) {
  return Buffer.from(assertHex32(hex, label), "hex").reverse().toString("hex");
}

/** RPC display hash -> raw consensus bytes (Buffer, 32 bytes) */
function displayToRaw(displayHex) {
  return Buffer.from(assertHex32(displayHex, "display hash"), "hex").reverse();
}

/** raw consensus bytes (Buffer or 64-char hex) -> RPC display hash (lowercase hex) */
function rawToDisplay(raw) {
  if (Buffer.isBuffer(raw)) {
    if (raw.length !== 32) fail(`raw bytes must be exactly 32 (got ${raw.length})`);
    return Buffer.from(raw).reverse().toString("hex");
  }
  return reverseHex32(raw, "raw hash hex");
}

/** raw consensus bytes as lowercase hex (the checkpoint payload's stored form) */
function displayToRawHex(displayHex) {
  return displayToRaw(displayHex).toString("hex");
}

/**
 * Assert the pinned pair reproduces BOTH ways, and that the two forms differ (so a
 * symmetric-input mistake cannot pass). Call at startup; throws on any deviation.
 */
function assertRoundTrip() {
  if (PINNED_DISPLAY === PINNED_RAW_HEX) fail("the pinned vector is symmetric; it cannot detect a reversal mistake");
  const raw = displayToRawHex(PINNED_DISPLAY);
  if (raw !== PINNED_RAW_HEX) fail(`display -> raw does not reproduce the pinned vector (got ${raw})`);
  const back = rawToDisplay(Buffer.from(PINNED_RAW_HEX, "hex"));
  if (back !== PINNED_DISPLAY) fail(`raw -> display does not reproduce the pinned vector (got ${back})`);
  if (displayToRawHex(displayToRawHex(PINNED_DISPLAY)) !== PINNED_DISPLAY) {
    fail("double reversal is not the identity");
  }
  return true;
}

module.exports = {
  PINNED_DISPLAY, PINNED_RAW_HEX,
  assertHex32, displayToRaw, displayToRawHex, rawToDisplay, assertRoundTrip,
};
