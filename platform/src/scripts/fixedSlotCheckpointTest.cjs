/**
 * Offline test for the narrow trusted checkpoint (plain `node`, no network). Five nets:
 *
 *   1. THE PUBLISHED BYTE-LEVEL TEST VECTORS the spec requires the build to publish
 *      (section 4, "The build MUST publish valid and invalid BYTE-LEVEL TEST VECTORS").
 *      The valid vector is pinned to the exact hex: the derived domain tag, the full
 *      serialized epoch-1 preimage, its sha256 checkpoint hash, and its ed25519 signature
 *      (ed25519 signing is deterministic, so the signature is reproducible by any
 *      implementation from the same seed). A drift in any constant, width, or field order
 *      breaks these pins loudly. The invalid vectors are net 2.
 *   2. THE MALFORMED-CHECKPOINT MATRIX (spec P7): a bad signature, a duplicate L1
 *      position, a misordered binding, a wrong deployment domain, a wrong format version,
 *      truncation, trailing bytes, a count out of bound, an oversized checkpoint, a wrong
 *      pinned hash, a wrong authority key, and the author-side serialize refusals
 *      (unsorted input, bad widths, out-of-range heights). Each MUST fail with the exact
 *      reason, the deterministic fail-stop across implementations.
 *   3. validEpochSequence, over the ADOPTION ORDER (never normalized): the contiguous pair
 *      accepts; a gap (discontinuity), an overlap, a repeated epoch id (identical or
 *      forked), a misordered delivery, an empty or inverted window, and a window order
 *      contradicting the id order each reject (a review fold replaced the earlier
 *      sort-and-dedupe with these fail-stops).
 *   4. THE THREE-REGION RULE AND RECOGNITION (spec section 4, the P8 offline half):
 *      region 2 (before the floor) is final UNRECOGNIZED, region 3 (past the last window)
 *      DEFERS and replays to the same record once the epoch arrives, the two-epoch
 *      advancement fixture agrees at the heights immediately before, at, and after the new
 *      effective height, activation, suspension boundaries ([B+1, R+1)), and the
 *      H-INCLUSIVE terminal-latch cutoff (recognized at the latch height, excluded after,
 *      absent latch infinite) all match the spec text, and recognition is deterministic
 *      across two independently validated sets from the same bytes (the live-versus-cold
 *      equality, offline form).
 *   5. validateEpochSet fail-stop propagation: one bad epoch in a served set halts with
 *      the offending index; a sequence violation across individually valid epochs halts.
 *
 * The keys here are FIXED TEST SEEDS for vector determinism, not deployment keys.
 */
"use strict";

const crypto = require("crypto");
const m = require("./fixedSlotCheckpoint.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed++; }
  else { failed++; console.error("FAIL:", name); }
};
const throws = (fn) => { try { fn(); return false; } catch { return true; } };

// ---- fixed test constants (vectors derived once; any drift is a semantic change) -----------

const SEED = Buffer.alloc(32, 0x42); // fixed test seed, NOT a deployment key
const PRIV = m.privateKeyFromSeed(SEED);
const PUB = m.rawPublicKey(crypto.createPublicKey(PRIV));
const GENESIS = Buffer.alloc(32, 0x0d); // fixed stand-in Core genesis hash for the vectors
const TAG = m.deriveDomainTag(GENESIS, PUB);

const EXPECTED_PUB_HEX = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
const EXPECTED_TAG_HEX = "d011ea659cff60bcbe49bf0f3058858647a7dd66d6b36c3b877c89d2e4c73a58";
const EXPECTED_E1_HEX =
  "01000000d011ea659cff60bcbe49bf0f3058858647a7dd66d6b36c3b877c89d2e4c73a58" +
  "0100000000000000e803000000000000d0070000000000000300" +
  "1111111111111111111111111111111111111111111111111111111111111111" + "00" +
  "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1" +
  "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" +
  "e803000000000000" +
  "1111111111111111111111111111111111111111111111111111111111111111" + "01" +
  "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1" +
  "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2" +
  "f203000000000000" +
  "2222222222222222222222222222222222222222222222222222222222222222" + "00" +
  "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2" +
  "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3" +
  "b004000000000000";
const EXPECTED_H1_HEX = "5b537680e9b23cb8e165d9e95205efa1428eb7fe9a4b28747c4783a97918648c";
const EXPECTED_S1_HEX =
  "410ae1ff961ffda55427dd4b7494deb6e782ea2afa4576fcdc2272159813abeb" +
  "659c1d7c152ad8bc415cf11ef25dd178f27f9887f55f24050039fca44a164b0f";
const EXPECTED_H2_HEX = "fb533465f14409e09125ba8b2396150441006b9a6af75ea313dca33b20339fa2";
const EXPECTED_S2_HEX =
  "a0339712aaf54dcffe7c6f4c5e94413f003aff7bd085e965f55854e125aacb5b" +
  "7e87ce8f77f3e933f6a191bbaa01160197e6054745836e4815ae02d400d89e0d";

const POS_A = { proTxHash: Buffer.alloc(32, 0x11), slotIndex: 0 };
const POS_B = { proTxHash: Buffer.alloc(32, 0x11), slotIndex: 1 };
const POS_C = { proTxHash: Buffer.alloc(32, 0x22), slotIndex: 0 };

const BINDINGS_1 = [
  { ...POS_A, contractId: Buffer.alloc(32, 0xc1), poolId: Buffer.alloc(32, 0xa1), activationCoreHeight: 1000n },
  { ...POS_B, contractId: Buffer.alloc(32, 0xc1), poolId: Buffer.alloc(32, 0xa2), activationCoreHeight: 1010n },
  { ...POS_C, contractId: Buffer.alloc(32, 0xc2), poolId: Buffer.alloc(32, 0xa3), activationCoreHeight: 1200n },
];
// epoch 2 legitimately RE-BINDS position C to a new pool for its own FUTURE window (the
// round-9 correction: a forward re-binding is NOT a retroactive contradiction)
const BINDINGS_2 = [
  BINDINGS_1[0], BINDINGS_1[1],
  { ...POS_C, contractId: Buffer.alloc(32, 0xc2), poolId: Buffer.alloc(32, 0xa4), activationCoreHeight: 2000n },
];

const E1 = m.serializeCheckpoint({ domainTag: TAG, epochId: 1n, effectiveCoreHeight: 1000n, endExclusiveCoreHeight: 2000n, bindings: BINDINGS_1 });
const H1 = m.checkpointHash(E1);
const S1 = m.signCheckpointHash(H1, PRIV);
const E2 = m.serializeCheckpoint({ domainTag: TAG, epochId: 2n, effectiveCoreHeight: 2000n, endExclusiveCoreHeight: 3000n, bindings: BINDINGS_2 });
const H2 = m.checkpointHash(E2);
const S2 = m.signCheckpointHash(H2, PRIV);

// the pins model the cold-start bundle, which NAMES the scheme (a review fold: the module
// refuses a missing scheme rather than defaulting it)
const PINS = { domainTag: TAG, authorityPublicKey: PUB, scheme: "ed25519" };

// helper: sign arbitrary preimage bytes with the test authority (isolates ONE defect per
// malformed vector, so the reason is the named one, not signature-invalid)
const signed = (bytes) => ({ bytes, signature: m.signCheckpointHash(m.checkpointHash(bytes), PRIV) });

// ---- net 1: the published byte-level vectors ------------------------------------------------

ok("constants: header width 62", m.HEADER_BYTES === 62);
ok("constants: binding width 105", m.BINDING_BYTES === 105);
ok("constants: max bytes 62+512*105", m.MAX_CHECKPOINT_BYTES === 62 + 512 * 105);
ok("constants: format version pinned to 1", m.FORMAT_VERSION === 1);
ok("constants: domain label pinned", m.DOMAIN_LABEL === "tegara-fixedslot-checkpoint-v1");
ok("constants: max bindings 512", m.MAX_BINDINGS === 512);
ok("constants: scheme pinned to ed25519", m.SIGNATURE_SCHEME === "ed25519");

ok("vector: authority public key", PUB.toString("hex") === EXPECTED_PUB_HEX);
ok("vector: derived domain tag", TAG.toString("hex") === EXPECTED_TAG_HEX);
ok("vector: epoch-1 preimage bytes exact", E1.toString("hex") === EXPECTED_E1_HEX);
ok("vector: epoch-1 length 62+3*105", E1.length === 377);
ok("vector: epoch-1 checkpoint hash", H1.toString("hex") === EXPECTED_H1_HEX);
ok("vector: epoch-1 signature (deterministic ed25519)", S1.toString("hex") === EXPECTED_S1_HEX);
ok("vector: epoch-2 checkpoint hash", H2.toString("hex") === EXPECTED_H2_HEX);
ok("vector: epoch-2 signature", S2.toString("hex") === EXPECTED_S2_HEX);

const v1 = m.validCheckpoint({ bytes: E1, signature: S1, pins: PINS });
ok("valid vector validates", v1.valid === true);
ok("valid vector hash surfaced", v1.valid && v1.hash.equals(H1));
ok("valid vector: hash pin accepted when it matches", m.validCheckpoint({ bytes: E1, signature: S1, pins: { ...PINS, checkpointHash: H1 } }).valid === true);

// round-trip: parse(serialize) reproduces every field
{
  const p = m.parseCheckpoint(E1);
  ok("round-trip: parse ok", p.ok === true);
  const c = p.checkpoint;
  ok("round-trip: header fields", c.formatVersion === 1 && c.domainTag.equals(TAG) && c.epochId === 1n && c.effectiveCoreHeight === 1000n && c.endExclusiveCoreHeight === 2000n);
  ok("round-trip: binding count", c.bindings.length === 3);
  ok("round-trip: binding 0", c.bindings[0].proTxHash.equals(POS_A.proTxHash) && c.bindings[0].slotIndex === 0 && c.bindings[0].contractId.equals(BINDINGS_1[0].contractId) && c.bindings[0].poolId.equals(BINDINGS_1[0].poolId) && c.bindings[0].activationCoreHeight === 1000n);
  ok("round-trip: binding 2", c.bindings[2].poolId.equals(BINDINGS_1[2].poolId) && c.bindings[2].activationCoreHeight === 1200n);
}

// ---- net 2: the malformed-checkpoint matrix (each reason exact) ------------------------------

const reasonOf = (args) => { const r = m.validCheckpoint(args); return r.valid ? "VALID" : r.reason; };

// bad signature: flip one byte
{
  const badSig = Buffer.from(S1); badSig[0] ^= 1;
  ok("malformed: bad signature", reasonOf({ bytes: E1, signature: badSig, pins: PINS }) === "signature-invalid");
}
ok("malformed: signature wrong length (63)", reasonOf({ bytes: E1, signature: S1.subarray(0, 63), pins: PINS }) === "signature-encoding");
ok("malformed: signature wrong length (65)", reasonOf({ bytes: E1, signature: Buffer.concat([S1, Buffer.alloc(1)]), pins: PINS }) === "signature-encoding");

// wrong deployment domain: a validly signed checkpoint under ANOTHER tag never validates here
{
  const otherTag = m.deriveDomainTag(Buffer.alloc(32, 0x0e), PUB);
  const foreign = signed(m.serializeCheckpoint({ domainTag: otherTag, epochId: 1n, effectiveCoreHeight: 1000n, endExclusiveCoreHeight: 2000n, bindings: BINDINGS_1 }));
  ok("malformed: wrong deployment domain", reasonOf({ ...foreign, pins: PINS }) === "domain-tag-mismatch");
}

// wrong format version: patch the version field and RE-SIGN, isolating the version defect
{
  const patched = Buffer.from(E1); patched.writeUInt32LE(2, 0);
  ok("malformed: format version not 1", reasonOf({ ...signed(patched), pins: PINS }) === "format-version");
}

// duplicate L1 position: copy binding 0's (proTxHash, slotIndex) over binding 1's, re-sign
{
  const patched = Buffer.from(E1);
  patched.copy(patched, 62 + 105, 62, 62 + 33);
  ok("malformed: duplicate L1 position", reasonOf({ ...signed(patched), pins: PINS }) === "binding-order");
}

// misordered bindings: swap binding blocks 0 and 2, re-sign
{
  const patched = Buffer.from(E1);
  const b0 = Buffer.from(E1.subarray(62, 62 + 105));
  const b2 = Buffer.from(E1.subarray(62 + 210, 62 + 315));
  b2.copy(patched, 62); b0.copy(patched, 62 + 210);
  ok("malformed: misordered bindings", reasonOf({ ...signed(patched), pins: PINS }) === "binding-order");
}

ok("malformed: truncated header", reasonOf({ bytes: E1.subarray(0, 61), signature: S1, pins: PINS }) === "truncated-header");
ok("malformed: truncated bindings", reasonOf({ bytes: E1.subarray(0, E1.length - 1), signature: S1, pins: PINS }) === "truncated-bindings");
ok("malformed: trailing bytes", reasonOf({ bytes: Buffer.concat([E1, Buffer.alloc(1)]), signature: S1, pins: PINS }) === "trailing-bytes");

// count field out of bound / inconsistent with the actual bytes
{
  const patched = Buffer.from(E1); patched.writeUInt16LE(513, 60);
  ok("malformed: count exceeds max", reasonOf({ bytes: patched, signature: S1, pins: PINS }) === "count-exceeds-max");
}
{
  const patched = Buffer.from(E1); patched.writeUInt16LE(2, 60);
  ok("malformed: count understates bytes", reasonOf({ ...signed(patched), pins: PINS }) === "trailing-bytes");
}
{
  const patched = Buffer.from(E1); patched.writeUInt16LE(4, 60);
  ok("malformed: count overstates bytes", reasonOf({ ...signed(patched), pins: PINS }) === "truncated-bindings");
}

ok("malformed: oversized checkpoint", reasonOf({ bytes: Buffer.concat([E1, Buffer.alloc(m.MAX_CHECKPOINT_BYTES)]), signature: S1, pins: PINS }) === "oversized");
ok("malformed: wrong pinned hash refused", reasonOf({ bytes: E1, signature: S1, pins: { ...PINS, checkpointHash: Buffer.alloc(32, 0xff) } }) === "checkpoint-hash-pin-mismatch");
ok("malformed: wrong authority key", reasonOf({ bytes: E1, signature: S1, pins: { ...PINS, authorityPublicKey: m.rawPublicKey(crypto.createPublicKey(m.privateKeyFromSeed(Buffer.alloc(32, 0x43)))) } }) === "signature-invalid");
ok("malformed: unsupported scheme", reasonOf({ bytes: E1, signature: S1, pins: { ...PINS, scheme: "secp256k1" } }) === "unsupported-signature-scheme");
ok("malformed: missing scheme refused, never defaulted", reasonOf({ bytes: E1, signature: S1, pins: { domainTag: TAG, authorityPublicKey: PUB } }) === "pins-missing-scheme");
ok("malformed: pins missing domain tag", reasonOf({ bytes: E1, signature: S1, pins: { authorityPublicKey: PUB, scheme: "ed25519" } }) === "pins-missing-domain-tag");

// the authority key pin is the RAW 32-byte encoding ONLY: a KeyObject is refused at the
// boundary, so a key of another type can never reach the verifier (the review's RSA
// trigger: a 512-bit RSA key yields a 64-byte signature that node crypto would verify)
{
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 512 });
  let rsaSig;
  try { rsaSig = crypto.sign(null, H1, rsa.privateKey); } catch { rsaSig = Buffer.alloc(64); }
  ok("key type: RSA signature is 64 bytes (the trigger is real)", rsaSig.length === 64);
  ok("key type: verifyCheckpointHash refuses a non-ed25519 key", m.verifyCheckpointHash(H1, rsaSig, rsa.publicKey) === false);
  ok("key type: validCheckpoint refuses a KeyObject pin (RSA)", reasonOf({ bytes: E1, signature: rsaSig, pins: { ...PINS, authorityPublicKey: rsa.publicKey } }) === "authority-key-invalid");
  ok("key type: validCheckpoint refuses even an ed25519 KeyObject pin", reasonOf({ bytes: E1, signature: S1, pins: { ...PINS, authorityPublicKey: crypto.createPublicKey(PRIV) } }) === "authority-key-invalid");
}

// author-side serialize refusals (the strict gate never normalizes)
const base = { domainTag: TAG, epochId: 1n, effectiveCoreHeight: 1000n, endExclusiveCoreHeight: 2000n };
ok("serialize: refuses unsorted bindings", throws(() => m.serializeCheckpoint({ ...base, bindings: [BINDINGS_1[2], BINDINGS_1[0]] })));
ok("serialize: refuses duplicate position", throws(() => m.serializeCheckpoint({ ...base, bindings: [BINDINGS_1[0], BINDINGS_1[0]] })));
ok("serialize: refuses activation height above u64", throws(() => m.serializeCheckpoint({ ...base, bindings: [{ ...BINDINGS_1[0], activationCoreHeight: (1n << 64n) }] })));
ok("serialize: refuses negative height", throws(() => m.serializeCheckpoint({ ...base, bindings: [{ ...BINDINGS_1[0], activationCoreHeight: -1n }] })));
ok("serialize: refuses short proTxHash", throws(() => m.serializeCheckpoint({ ...base, bindings: [{ ...BINDINGS_1[0], proTxHash: Buffer.alloc(31, 0x11) }] })));
ok("serialize: refuses slotIndex 256", throws(() => m.serializeCheckpoint({ ...base, bindings: [{ ...BINDINGS_1[0], slotIndex: 256 }] })));
ok("serialize: refuses format version 2", throws(() => m.serializeCheckpoint({ ...base, formatVersion: 2, bindings: BINDINGS_1 })));
ok("serialize: refuses more than 512 bindings", throws(() => {
  const many = [];
  for (let i = 0; i < 513; i++) {
    const h = Buffer.alloc(32); h.writeUInt32BE(i, 0);
    many.push({ proTxHash: h, slotIndex: 0, contractId: Buffer.alloc(32, 1), poolId: Buffer.alloc(32, 2), activationCoreHeight: 1n });
  }
  m.serializeCheckpoint({ ...base, bindings: many });
}));
ok("serialize: accepts exactly 512 bindings", (() => {
  const many = [];
  for (let i = 0; i < 512; i++) {
    const h = Buffer.alloc(32); h.writeUInt32BE(i, 0);
    many.push({ proTxHash: h, slotIndex: 0, contractId: Buffer.alloc(32, 1), poolId: Buffer.alloc(32, 2), activationCoreHeight: 1n });
  }
  const b = m.serializeCheckpoint({ ...base, bindings: many });
  return b.length === m.MAX_CHECKPOINT_BYTES && m.parseCheckpoint(b).ok;
})());

// ---- net 3: validEpochSequence ---------------------------------------------------------------

const adoptedOf = (pairs) => pairs.map(({ bytes, signature }) => {
  const r = m.validCheckpoint({ bytes, signature, pins: PINS });
  if (!r.valid) throw new Error("fixture must be individually valid: " + r.reason);
  return { checkpoint: r.checkpoint, hash: r.hash };
});
const seqReason = (pairs) => { const r = m.validEpochSequence(adoptedOf(pairs)); return r.valid ? "VALID" : r.reason; };
const mkEpoch = (epochId, eff, end, bindings) =>
  signed(m.serializeCheckpoint({ domainTag: TAG, epochId, effectiveCoreHeight: eff, endExclusiveCoreHeight: end, bindings }));

ok("sequence: contiguous pair valid", seqReason([{ bytes: E1, signature: S1 }, { bytes: E2, signature: S2 }]) === "VALID");
ok("sequence: single epoch valid", seqReason([{ bytes: E1, signature: S1 }]) === "VALID");
ok("sequence: gap is a discontinuity", seqReason([{ bytes: E1, signature: S1 }, mkEpoch(2n, 2100n, 3000n, BINDINGS_2)]) === "discontinuity");
ok("sequence: overlap rejected", seqReason([{ bytes: E1, signature: S1 }, mkEpoch(2n, 1500n, 3000n, BINDINGS_2)]) === "overlap");
// a repeated id is fail-stop whether the content differs (forked) or not (a review fold:
// the earlier build deduplicated the identical case and sorted misordered delivery, both a
// silent skip-and-recover the spec forbids; the adoption order is never normalized)
ok("sequence: forked epoch id rejected", seqReason([{ bytes: E1, signature: S1 }, mkEpoch(1n, 2000n, 3000n, BINDINGS_2)]) === "duplicate-epoch-id");
ok("sequence: exact duplicate is fail-stop, never deduplicated", seqReason([{ bytes: E1, signature: S1 }, { bytes: E1, signature: S1 }]) === "duplicate-epoch-id");
ok("sequence: reversed adoption order is fail-stop, never sorted", seqReason([{ bytes: E2, signature: S2 }, { bytes: E1, signature: S1 }]) === "epoch-id-order");
ok("sequence: empty window rejected", seqReason([mkEpoch(1n, 1000n, 1000n, BINDINGS_1)]) === "empty-or-inverted-window");
ok("sequence: inverted window rejected", seqReason([mkEpoch(1n, 2000n, 1000n, BINDINGS_1)]) === "empty-or-inverted-window");
ok("sequence: id order contradicting window order rejected", seqReason([mkEpoch(1n, 2000n, 3000n, BINDINGS_2), mkEpoch(2n, 1000n, 2000n, BINDINGS_1)]) === "overlap");

// ---- net 4: the three-region rule and recognition ---------------------------------------------

// every adopted epoch carries ITS OWN pinned hash (the review blocker: the cold-start
// bundle is the ordered epochs WITH their hashes, one per epoch, and a shared single pin
// cannot cover a multi-epoch set)
const SET = m.validateEpochSet({ epochs: [{ bytes: E1, signature: S1, pinnedHash: H1 }, { bytes: E2, signature: S2, pinnedHash: H2 }], pins: PINS });
ok("validateEpochSet: two-epoch set adopts", SET.ok === true && SET.adopted.length === 2);
const ADOPTED = SET.adopted;
const rec = (H, pos, extra) => m.recognize({ adopted: ADOPTED, rewardHeight: H, ...pos, ...(extra || {}) });

// region 2: before the deployment floor, permanently unrecognized, final
{
  const r = rec(999n, POS_A);
  ok("region 2: before floor is UNRECOGNIZED", r.result === "UNRECOGNIZED" && r.final === true && r.reason === "before-deployment-floor");
}
// region 3: at or above the last end-exclusive height, deferred, never finalized
{
  const r = rec(3000n, POS_A);
  ok("region 3: past last window DEFERS", r.result === "DEFERRED" && r.reason === "not-yet-covered");
}
ok("region 3: far future also DEFERS", rec(1000000n, POS_A).result === "DEFERRED");
ok("interior: last covered height recognized", rec(2999n, POS_A).result === "RECOGNIZED");

// the two-epoch advancement fixture (the round-9 case): position C re-binds at 2000
ok("advancement: height before boundary uses old binding", (() => { const r = rec(1999n, POS_C); return r.result === "RECOGNIZED" && r.binding.poolId.equals(Buffer.alloc(32, 0xa3)) && r.epochId === 1n; })());
ok("advancement: height at boundary uses new binding", (() => { const r = rec(2000n, POS_C); return r.result === "RECOGNIZED" && r.binding.poolId.equals(Buffer.alloc(32, 0xa4)) && r.epochId === 2n; })());
ok("advancement: height after boundary uses new binding", (() => { const r = rec(2001n, POS_C); return r.result === "RECOGNIZED" && r.binding.poolId.equals(Buffer.alloc(32, 0xa4)); })());

// activation: recognized only from activationCoreHeight
ok("activation: below activation is UNRECOGNIZED", rec(1100n, POS_C).reason === "before-activation");
ok("activation: at activation is RECOGNIZED", rec(1200n, POS_C).result === "RECOGNIZED");

// an unbound position is UNRECOGNIZED at H (not deferred, not fail-stop)
ok("no binding: UNRECOGNIZED", rec(1500n, { proTxHash: Buffer.alloc(32, 0x33), slotIndex: 0 }).reason === "no-binding");
ok("no binding: same proTxHash other slot", rec(1500n, { proTxHash: Buffer.alloc(32, 0x22), slotIndex: 1 }).reason === "no-binding");

// suspension boundaries: ban in B=1500, revoke in R=1600, excluded interval [B+1, R+1)
{
  const susp = { suspendedIntervals: [{ start: 1501n, end: 1601n }] };
  ok("suspension: paid at B", rec(1500n, POS_A, susp).result === "RECOGNIZED");
  ok("suspension: excluded at B+1", rec(1501n, POS_A, susp).reason === "suspended");
  ok("suspension: still excluded at R", rec(1600n, POS_A, susp).reason === "suspended");
  ok("suspension: recognized again at R+1", rec(1601n, POS_A, susp).result === "RECOGNIZED");
}

// terminal latch: the H-inclusive cutoff (latch >= H recognized, absent latch infinite)
ok("latch: recognized AT the latch height", rec(1800n, POS_A, { terminalLatchHeight: 1800n }).result === "RECOGNIZED");
ok("latch: excluded after the latch height", rec(1801n, POS_A, { terminalLatchHeight: 1800n }).reason === "after-terminal-latch");
ok("latch: absent latch is infinite", rec(1999n, POS_A, {}).result === "RECOGNIZED");

// deferral-and-replay equality: epoch 2 delivered late reaches the same record
{
  const early = m.validateEpochSet({ epochs: [{ bytes: E1, signature: S1, pinnedHash: H1 }], pins: PINS });
  const before = m.recognize({ adopted: early.adopted, rewardHeight: 2500n, ...POS_C });
  const after = rec(2500n, POS_C);
  ok("replay: deferred while uncovered", before.result === "DEFERRED");
  ok("replay: recognized identically once adopted", after.result === "RECOGNIZED" && after.binding.poolId.equals(Buffer.alloc(32, 0xa4)));
}

// determinism (live-versus-cold, offline form): a second reader independently validating
// the SAME ordered bundle from fresh byte copies resolves every height identically
{
  const other = m.validateEpochSet({ epochs: [{ bytes: Buffer.from(E1), signature: Buffer.from(S1), pinnedHash: Buffer.from(H1) }, { bytes: Buffer.from(E2), signature: Buffer.from(S2), pinnedHash: Buffer.from(H2) }], pins: PINS });
  let same = other.ok;
  for (let h = 990n; same && h <= 3010n; h += 1n) {
    const a = rec(h, POS_C);
    const b = m.recognize({ adopted: other.adopted, rewardHeight: h, ...POS_C });
    same = a.result === b.result && a.reason === b.reason &&
      (a.result !== "RECOGNIZED" || a.binding.poolId.equals(b.binding.poolId));
  }
  ok("determinism: two independent validations of the same bundle agree at every height", same);
}

ok("empty adoption: DEFERS", m.recognize({ adopted: [], rewardHeight: 1500n, ...POS_A }).result === "DEFERRED");

// ---- net 5: validateEpochSet fail-stop propagation --------------------------------------------

{
  const badSig = Buffer.from(S2); badSig[1] ^= 1;
  const r = m.validateEpochSet({ epochs: [{ bytes: E1, signature: S1, pinnedHash: H1 }, { bytes: E2, signature: badSig, pinnedHash: H2 }], pins: PINS });
  ok("fail-stop: bad epoch halts with index", r.ok === false && r.failStop === true && r.reason === "signature-invalid" && r.epochIndex === 1);
}
{
  const gap = mkEpoch(2n, 2100n, 3000n, BINDINGS_2);
  const r = m.validateEpochSet({ epochs: [{ bytes: E1, signature: S1, pinnedHash: H1 }, { ...gap, pinnedHash: m.checkpointHash(gap.bytes) }], pins: PINS });
  ok("fail-stop: sequence violation halts", r.ok === false && r.failStop === true && r.reason === "discontinuity");
}
// the per-epoch hash pin is REQUIRED: an epoch served without one halts (the review
// blocker's alternate trigger, an unpinned epoch would let a re-signed replacement pass)
{
  const r = m.validateEpochSet({ epochs: [{ bytes: E1, signature: S1, pinnedHash: H1 }, { bytes: E2, signature: S2 }], pins: PINS });
  ok("fail-stop: missing hash pin halts with index", r.ok === false && r.failStop === true && r.reason === "missing-checkpoint-hash-pin" && r.epochIndex === 1);
}
// the historical-replacement case: the authority re-signs an ALTERED epoch 2 (same id and
// window, one binding changed); its signature is valid but its bytes do not hash to the
// client's pinned H2, so adoption halts instead of accepting the retroactive change
{
  const altered = mkEpoch(2n, 2000n, 3000n, [BINDINGS_2[0], BINDINGS_2[1], { ...BINDINGS_2[2], poolId: Buffer.alloc(32, 0xa5) }]);
  const r = m.validateEpochSet({ epochs: [{ bytes: E1, signature: S1, pinnedHash: H1 }, { ...altered, pinnedHash: H2 }], pins: PINS });
  ok("fail-stop: a re-signed historical replacement is refused by the hash pin", r.ok === false && r.failStop === true && r.reason === "checkpoint-hash-pin-mismatch" && r.epochIndex === 1);
}
// duplicate and misordered adoption reach validateEpochSet's fail-stop too (not only the
// bare predicate)
{
  const r = m.validateEpochSet({ epochs: [{ bytes: E1, signature: S1, pinnedHash: H1 }, { bytes: E1, signature: S1, pinnedHash: H1 }], pins: PINS });
  ok("fail-stop: duplicate epoch in a served set halts", r.ok === false && r.reason === "duplicate-epoch-id");
}
{
  const r = m.validateEpochSet({ epochs: [{ bytes: E2, signature: S2, pinnedHash: H2 }, { bytes: E1, signature: S1, pinnedHash: H1 }], pins: PINS });
  ok("fail-stop: misordered served set halts", r.ok === false && r.reason === "epoch-id-order");
}
// the two decided clarifications (Hilawe 2026-07-22), pinned as regression vectors:
// an EMPTY epoch (zero bindings) is LEGAL (the wind-down state recognizing nothing in
// its window), and a carried binding's activation may legitimately PRECEDE its epoch's
// own window (no window-relative range check)
{
  const empty = mkEpoch(3n, 3000n, 4000n, []);
  const r = m.validCheckpoint({ bytes: empty.bytes, signature: empty.signature, pins: PINS });
  ok("decision: an empty epoch validates", r.valid === true && r.checkpoint.bindings.length === 0);
  const set3 = m.validateEpochSet({ epochs: [
    { bytes: E1, signature: S1, pinnedHash: H1 },
    { bytes: E2, signature: S2, pinnedHash: H2 },
    { ...empty, pinnedHash: m.checkpointHash(empty.bytes) },
  ], pins: PINS });
  ok("decision: an empty epoch adopts in sequence", set3.ok === true && set3.adopted.length === 3);
  const rEmpty = m.recognize({ adopted: set3.adopted, rewardHeight: 3500n, ...POS_A });
  ok("decision: inside the empty window every position is UNRECOGNIZED (no-binding), not deferred and not fail-stop",
    rEmpty.result === "UNRECOGNIZED" && rEmpty.reason === "no-binding");
}
{
  // a carried binding whose activation (1000) precedes epoch 2's own window [2000, 3000)
  // is ALREADY the standing fixture (POS_A carries activation 1000 into epoch 2); pin the
  // meaning explicitly: recognized inside epoch 2 because H >= activation, with no
  // window-relative activation check
  const r = m.recognize({ adopted: ADOPTED, rewardHeight: 2100n, ...POS_A });
  ok("decision: a carried pre-window activation recognizes in the later epoch", r.result === "RECOGNIZED" && r.epochId === 2n && r.binding.activationCoreHeight === 1000n && 1000n < 2000n);
}

// malformed OUTER structure returns the deterministic fail-stop result, never throws
// (a packet-review finding: the entry point's contract is a result, not an exception)
{
  const a = m.validateEpochSet({ epochs: null, pins: PINS });
  ok("fail-stop: null epoch set returns a result", a.ok === false && a.failStop === true && a.reason === "epochs-not-an-array");
  const b = m.validateEpochSet({ epochs: [{ bytes: E1, signature: S1, pinnedHash: H1 }, null], pins: PINS });
  ok("fail-stop: null entry returns a result with index", b.ok === false && b.reason === "epoch-entry-malformed" && b.epochIndex === 1);
  const c = m.validateEpochSet({ epochs: [42], pins: PINS });
  ok("fail-stop: non-object entry returns a result", c.ok === false && c.reason === "epoch-entry-malformed" && c.epochIndex === 0);
  const d = m.validateEpochSet({ epochs: [{}], pins: PINS });
  ok("fail-stop: empty-object entry halts on the missing pin", d.ok === false && d.reason === "missing-checkpoint-hash-pin" && d.epochIndex === 0);
}

// ---- summary -----------------------------------------------------------------------------------

console.log(`fixedSlotCheckpointTest: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
