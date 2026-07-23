/**
 * The NARROW TRUSTED CHECKPOINT, the governed-prototype pool-recognition component of the
 * fixed-slot design (`tegara/docs/FIXED_SLOT_SHARE_SPEC.md`, section 4, review-complete
 * through round 12). This is the punch-list item the fourth-session handoff owes for P7 and
 * P8: a signed binding list from ONE trusted recognition authority, byte-canonical so two
 * implementations hash and validate it identically, fail-stop on any inconsistency, with no
 * migration or recovery machinery. It is a DISCLOSED TRUST POINT (the authority decides
 * reward-recognition per L1 position; it never touches custody), and the L1 node-to-contract
 * commitment remains the production endpoint that removes it.
 *
 * Pure offline module: plain `node`, `node:crypto` only (ed25519 is built in), no network,
 * no SDK. Everything the spec fixes to the byte is a named constant here, and
 * fixedSlotCheckpointTest.cjs pins the byte-level test vectors the spec requires the build
 * to publish.
 *
 * THE v1 WIRE LAYOUT (spec section 4, all integers UNSIGNED LITTLE-ENDIAN of the stated
 * width, the signature is NOT part of these bytes):
 *
 *   offset  width  field
 *        0      4  format version, EXACTLY 1 for this specification
 *        4     32  deployment/network DOMAIN TAG (derived, see deriveDomainTag)
 *       36      8  epoch id
 *       44      8  effective Core height          \  the epoch's own committed window
 *       52      8  end-exclusive Core height      /  [effective, endExclusive)
 *       60      2  binding count, max 512
 *       62    n*105 bindings, sorted STRICTLY ASCENDING by (proTxHash, slotIndex):
 *                    32  proTxHash            (raw consensus bytes, the byte order Dash Core
 *                                              stores in the deterministic masternode list)
 *                     1  slotIndex
 *                    32  contractId           (raw 32-byte Platform identifier, never base58)
 *                    32  poolId               (raw 32-byte Platform identifier)
 *                     8  activationCoreHeight
 *
 * DOMAIN TAG: sha256("tegara-fixedslot-checkpoint-v1" || coreGenesisBlockHash ||
 * authorityPublicKey), the ASCII label with no trailing null, then the 32-byte Core genesis
 * hash of the deployment's network, then the authority public key in its raw encoding
 * (32 bytes for the ed25519 default). The resulting value is PINNED in the cold-start
 * bundle, so a checkpoint for another deployment or network never validates here.
 *
 * CHECKPOINT HASH: sha256 over exactly the preimage bytes above. SIGNATURE: the deployment
 * pins EXACTLY ONE scheme for its life; this module implements the specification's DEFAULT,
 * ed25519, the 64-byte raw signature computed over the 32-byte CHECKPOINT HASH (not over
 * the preimage again), no additional envelope.
 *
 * FAIL-STOP (spec section 4): a client halts and alerts, with no skip-and-recover, on a
 * checkpoint failing the pinned signature, a MALFORMED checkpoint (`validCheckpoint`
 * fails), or a `validEpochSequence` violation (a duplicate or forked epoch id, an overlap,
 * or an internal discontinuity between two adopted epochs). It does NOT fail-stop merely
 * because no adopted epoch covers a height; that resolves by the THREE-REGION rule:
 *   region 1  an internal discontinuity between two ADOPTED epochs  -> FAIL-STOP
 *   region 2  a height before the first adopted epoch's effective   -> PERMANENTLY
 *             height (the deployment's floor)                          UNRECOGNIZED, final
 *   region 3  a height at or above the last adopted epoch's         -> DEFERRED, finalize
 *             end-exclusive height                                     nothing, replay when
 *                                                                      an epoch is adopted
 * Region 3 never permanently closes through an epoch (the round-11 correction): permanent
 * unrecognition of a SPECIFIC pool comes only from that pool's terminal latch, which is
 * client-side lifecycle knowledge independent of epoch windows, passed into `recognize`
 * by the caller.
 *
 * RECOGNITION (spec section 4, stated once here and implemented verbatim in `recognize`):
 * for reward height H and L1 position (proTxHash, slotIndex), first resolve H's region;
 * otherwise the ONE adopted epoch whose window contains H is authoritative. If that epoch
 * binds the position (else UNRECOGNIZED at H), recognize the bound pool IF
 * H >= activationCoreHeight, H is not inside a suspended interval, and EITHER the pool has
 * no terminal latch OR its latch height is >= H (the H-inclusive cutoff; an absent latch is
 * an infinite cutoff). A successor is NOT automatic from H+1: a replacement node has a new
 * proTxHash and is recognized only by its OWN binding with its own activation height.
 */
"use strict";

const crypto = require("crypto");

// ---- pinned constants (spec section 4, fixed before build) --------------------------------

const FORMAT_VERSION = 1;
const DOMAIN_LABEL = "tegara-fixedslot-checkpoint-v1"; // ASCII, no trailing null
const MAX_BINDINGS = 512;
const SIGNATURE_SCHEME = "ed25519"; // the specification's default; ONE scheme per deployment
const SIGNATURE_BYTES = 64;

const HEADER_BYTES = 4 + 32 + 8 + 8 + 8 + 2; // 62
const BINDING_BYTES = 32 + 1 + 32 + 32 + 8; // 105
const MAX_CHECKPOINT_BYTES = HEADER_BYTES + MAX_BINDINGS * BINDING_BYTES;

const U64_MAX = (1n << 64n) - 1n;

// ---- small helpers -------------------------------------------------------------------------

const isBuf = (x, n) => Buffer.isBuffer(x) && x.length === n;

// accept number | bigint, return a validated u64 BigInt (throws: author-side inputs only)
function toU64(value, name) {
  let v;
  if (typeof value === "bigint") v = value;
  else if (typeof value === "number" && Number.isSafeInteger(value)) v = BigInt(value);
  else throw new TypeError(`${name} must be a safe integer or BigInt`);
  if (v < 0n || v > U64_MAX) throw new RangeError(`${name} out of u64 range`);
  return v;
}

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest();

// bindings sort STRICTLY ascending by (proTxHash bytes, then slotIndex)
function compareBindingKey(a, b) {
  const c = Buffer.compare(a.proTxHash, b.proTxHash);
  return c !== 0 ? c : a.slotIndex - b.slotIndex;
}

// ---- ed25519 raw-encoding helpers ----------------------------------------------------------
// The spec pins the authority public key in its RAW encoding (32 bytes for ed25519). Node's
// KeyObjects speak DER, so these two convert at the boundary. The DER prefixes are the fixed
// SPKI/PKCS8 headers for ed25519 (RFC 8410).

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function publicKeyFromRaw(raw32) {
  if (!isBuf(raw32, 32)) throw new TypeError("raw ed25519 public key must be 32 bytes");
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw32]),
    format: "der",
    type: "spki",
  });
}

function privateKeyFromSeed(seed32) {
  if (!isBuf(seed32, 32)) throw new TypeError("ed25519 seed must be 32 bytes");
  return crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed32]),
    format: "der",
    type: "pkcs8",
  });
}

function rawPublicKey(keyObject) {
  const der = keyObject.export({ format: "der", type: "spki" });
  if (der.length !== ED25519_SPKI_PREFIX.length + 32) throw new TypeError("not an ed25519 public key");
  return der.subarray(ED25519_SPKI_PREFIX.length);
}

// ---- domain tag, hash, sign, verify --------------------------------------------------------

function deriveDomainTag(coreGenesisBlockHash, authorityPublicKeyRaw) {
  if (!isBuf(coreGenesisBlockHash, 32)) throw new TypeError("coreGenesisBlockHash must be 32 bytes");
  if (!isBuf(authorityPublicKeyRaw, 32)) throw new TypeError("authorityPublicKeyRaw must be 32 bytes");
  return sha256(Buffer.concat([Buffer.from(DOMAIN_LABEL, "ascii"), coreGenesisBlockHash, authorityPublicKeyRaw]));
}

const checkpointHash = (preimageBytes) => sha256(preimageBytes);

// sign the 32-byte checkpoint HASH (not the preimage), 64-byte raw signature
function signCheckpointHash(hash32, privateKey) {
  if (!isBuf(hash32, 32)) throw new TypeError("checkpoint hash must be 32 bytes");
  const sig = crypto.sign(null, hash32, privateKey);
  if (sig.length !== SIGNATURE_BYTES) throw new Error("unexpected signature length");
  return sig;
}

function verifyCheckpointHash(hash32, signature, publicKey) {
  if (!isBuf(hash32, 32) || !isBuf(signature, SIGNATURE_BYTES)) return false;
  // the pinned scheme is ed25519; a key of any other type must NOT verify even if its
  // signature happens to be 64 bytes (an independent review demonstrated a 512-bit RSA key
  // producing a 64-byte signature that node crypto would otherwise accept here)
  if (!publicKey || publicKey.asymmetricKeyType !== "ed25519") return false;
  try {
    return crypto.verify(null, hash32, publicKey, signature);
  } catch {
    return false;
  }
}

// ---- author-side serialization (STRICT: refuses non-canonical input, never normalizes) -----

function serializeCheckpoint(cp) {
  const formatVersion = cp.formatVersion === undefined ? FORMAT_VERSION : cp.formatVersion;
  if (formatVersion !== FORMAT_VERSION) throw new RangeError("format version must be exactly 1");
  if (!isBuf(cp.domainTag, 32)) throw new TypeError("domainTag must be 32 bytes");
  const epochId = toU64(cp.epochId, "epochId");
  const effective = toU64(cp.effectiveCoreHeight, "effectiveCoreHeight");
  const endExclusive = toU64(cp.endExclusiveCoreHeight, "endExclusiveCoreHeight");
  if (!Array.isArray(cp.bindings)) throw new TypeError("bindings must be an array");
  if (cp.bindings.length > MAX_BINDINGS) throw new RangeError(`binding count exceeds ${MAX_BINDINGS}`);

  const bindings = cp.bindings.map((b, i) => {
    if (!isBuf(b.proTxHash, 32)) throw new TypeError(`bindings[${i}].proTxHash must be 32 raw bytes`);
    if (!Number.isInteger(b.slotIndex) || b.slotIndex < 0 || b.slotIndex > 255)
      throw new RangeError(`bindings[${i}].slotIndex must be 0..255`);
    if (!isBuf(b.contractId, 32)) throw new TypeError(`bindings[${i}].contractId must be 32 raw bytes`);
    if (!isBuf(b.poolId, 32)) throw new TypeError(`bindings[${i}].poolId must be 32 raw bytes`);
    return {
      proTxHash: b.proTxHash,
      slotIndex: b.slotIndex,
      contractId: b.contractId,
      poolId: b.poolId,
      activationCoreHeight: toU64(b.activationCoreHeight, `bindings[${i}].activationCoreHeight`),
    };
  });
  // canonical order is the AUTHOR's duty; refusing here (rather than sorting silently) keeps
  // a builder bug loud instead of masked
  for (let i = 1; i < bindings.length; i++) {
    if (compareBindingKey(bindings[i - 1], bindings[i]) >= 0)
      throw new RangeError("bindings must be strictly ascending by (proTxHash, slotIndex)");
  }

  const out = Buffer.alloc(HEADER_BYTES + bindings.length * BINDING_BYTES);
  let o = 0;
  out.writeUInt32LE(FORMAT_VERSION, o); o += 4;
  cp.domainTag.copy(out, o); o += 32;
  out.writeBigUInt64LE(epochId, o); o += 8;
  out.writeBigUInt64LE(effective, o); o += 8;
  out.writeBigUInt64LE(endExclusive, o); o += 8;
  out.writeUInt16LE(bindings.length, o); o += 2;
  for (const b of bindings) {
    b.proTxHash.copy(out, o); o += 32;
    out.writeUInt8(b.slotIndex, o); o += 1;
    b.contractId.copy(out, o); o += 32;
    b.poolId.copy(out, o); o += 32;
    out.writeBigUInt64LE(b.activationCoreHeight, o); o += 8;
  }
  return out;
}

// ---- structural parse (returns a reason, never throws on untrusted bytes) ------------------

function parseCheckpoint(bytes) {
  if (!Buffer.isBuffer(bytes)) return { ok: false, reason: "not-a-buffer" };
  if (bytes.length < HEADER_BYTES) return { ok: false, reason: "truncated-header" };
  if (bytes.length > MAX_CHECKPOINT_BYTES) return { ok: false, reason: "oversized" };
  let o = 0;
  const formatVersion = bytes.readUInt32LE(o); o += 4;
  const domainTag = Buffer.from(bytes.subarray(o, o + 32)); o += 32;
  const epochId = bytes.readBigUInt64LE(o); o += 8;
  const effectiveCoreHeight = bytes.readBigUInt64LE(o); o += 8;
  const endExclusiveCoreHeight = bytes.readBigUInt64LE(o); o += 8;
  const count = bytes.readUInt16LE(o); o += 2;
  if (count > MAX_BINDINGS) return { ok: false, reason: "count-exceeds-max" };
  const expected = HEADER_BYTES + count * BINDING_BYTES;
  if (bytes.length < expected) return { ok: false, reason: "truncated-bindings" };
  if (bytes.length > expected) return { ok: false, reason: "trailing-bytes" };
  const bindings = [];
  for (let i = 0; i < count; i++) {
    const proTxHash = Buffer.from(bytes.subarray(o, o + 32)); o += 32;
    const slotIndex = bytes.readUInt8(o); o += 1;
    const contractId = Buffer.from(bytes.subarray(o, o + 32)); o += 32;
    const poolId = Buffer.from(bytes.subarray(o, o + 32)); o += 32;
    const activationCoreHeight = bytes.readBigUInt64LE(o); o += 8;
    bindings.push({ proTxHash, slotIndex, contractId, poolId, activationCoreHeight });
  }
  return {
    ok: true,
    checkpoint: { formatVersion, domainTag, epochId, effectiveCoreHeight, endExclusiveCoreHeight, bindings },
  };
}

// ---- validCheckpoint (spec section 4, the predicate verbatim) -------------------------------
// format version exactly 1, domain tag equal to the pinned derived value, strictly-ascending
// unique (proTxHash, slotIndex) order, count within bound, canonical field widths (enforced
// by the structural parse), the pinned scheme's signature encoding (64 bytes for ed25519),
// and a valid authority signature over the 32-byte checkpoint hash. Anything else is
// MALFORMED and the caller MUST fail-stop. `pins` may also carry `checkpointHash` (the
// client's pinned hash for this epoch): a served checkpoint whose hash differs is REFUSED,
// the wallet/reader pin-mismatch case of P7.

function validCheckpoint({ bytes, signature, pins }) {
  if (!pins || !isBuf(pins.domainTag, 32)) return { valid: false, reason: "pins-missing-domain-tag" };
  // the cold-start bundle NAMES the scheme; a caller that does not state it has no bundle,
  // so a missing scheme is refused rather than defaulted (an independent review finding)
  if (pins.scheme === undefined) return { valid: false, reason: "pins-missing-scheme" };
  if (pins.scheme !== SIGNATURE_SCHEME) return { valid: false, reason: "unsupported-signature-scheme" };
  const parsed = parseCheckpoint(bytes);
  if (!parsed.ok) return { valid: false, reason: parsed.reason };
  const cp = parsed.checkpoint;
  if (cp.formatVersion !== FORMAT_VERSION) return { valid: false, reason: "format-version" };
  if (!cp.domainTag.equals(pins.domainTag)) return { valid: false, reason: "domain-tag-mismatch" };
  for (let i = 1; i < cp.bindings.length; i++) {
    if (compareBindingKey(cp.bindings[i - 1], cp.bindings[i]) >= 0)
      return { valid: false, reason: "binding-order" };
  }
  if (!Buffer.isBuffer(signature) || signature.length !== SIGNATURE_BYTES)
    return { valid: false, reason: "signature-encoding" };
  const hash = checkpointHash(bytes);
  if (pins.checkpointHash !== undefined) {
    if (!isBuf(pins.checkpointHash, 32) || !hash.equals(pins.checkpointHash))
      return { valid: false, reason: "checkpoint-hash-pin-mismatch" };
  }
  // the pin is the RAW 32-byte encoding the spec fixes, and ONLY that: a KeyObject (or any
  // other form) is refused at this boundary, so a key of another type can never reach the
  // verifier through a permissive input path (an independent review demonstrated exactly
  // that with an RSA KeyObject whose signature was coincidentally 64 bytes)
  if (!isBuf(pins.authorityPublicKey, 32)) return { valid: false, reason: "authority-key-invalid" };
  let publicKey;
  try {
    publicKey = publicKeyFromRaw(pins.authorityPublicKey);
  } catch {
    return { valid: false, reason: "authority-key-invalid" };
  }
  if (!verifyCheckpointHash(hash, signature, publicKey)) return { valid: false, reason: "signature-invalid" };
  return { valid: true, checkpoint: cp, hash };
}

// ---- validEpochSequence (spec section 4) ----------------------------------------------------
// Over a deployment's ADOPTED epochs, IN ADOPTION ORDER (the cold-start bundle is ORDERED,
// spec P8): strictly increasing epoch ids, finite non-empty windows, and consecutive
// adopted windows ordered, contiguous, and non-overlapping
// (epoch[k].endExclusiveCoreHeight == epoch[k+1].effectiveCoreHeight for every adopted
// consecutive pair). The input order IS the adoption order and is NEVER normalized: a
// repeated epoch id (identical or forked) and an id that does not increase are each a
// violation, fail-stop, no sort, no dedupe (an independent review finding; silently
// reordering or deduplicating is exactly the skip-and-recover the spec forbids).

function validEpochSequence(adopted) {
  if (!Array.isArray(adopted)) return { valid: false, reason: "not-an-array" };
  for (const e of adopted) {
    if (e.checkpoint.effectiveCoreHeight >= e.checkpoint.endExclusiveCoreHeight)
      return { valid: false, reason: "empty-or-inverted-window" };
  }
  for (let k = 1; k < adopted.length; k++) {
    const prev = adopted[k - 1].checkpoint, next = adopted[k].checkpoint;
    if (next.epochId === prev.epochId) return { valid: false, reason: "duplicate-epoch-id" };
    if (next.epochId < prev.epochId) return { valid: false, reason: "epoch-id-order" };
    if (prev.endExclusiveCoreHeight !== next.effectiveCoreHeight) {
      // region 1: an overlap or a non-contiguous jump between two adopted epochs
      return {
        valid: false,
        reason: prev.endExclusiveCoreHeight > next.effectiveCoreHeight ? "overlap" : "discontinuity",
      };
    }
  }
  return { valid: true, sequence: adopted };
}

// ---- adopt-and-validate: the one entry point a client uses on served epochs ----------------
// The cold-start bundle is the ORDERED set of signed epochs WITH THEIR PINNED HASHES, one
// per epoch (spec P8), so every entry here REQUIRES its own `pinnedHash`, and a served
// epoch whose bytes hash to anything else is refused before its signature is even useful
// (an independent review blocker: a single shared pin cannot cover a multi-epoch set, and
// an absent pin would let a freshly re-signed replacement for a historical epoch validate,
// defeating the immutable-epoch rule). Runs validCheckpoint on every served epoch under
// the shared pins plus its own hash pin, then validEpochSequence over the adopted set in
// adoption order. ANY failure is FAIL-STOP (halt and alert, no skip-and-recover); the
// return carries the reason and the offending index for the alert.

function validateEpochSet({ epochs, pins }) {
  // the entry point PROMISES a deterministic fail-stop result, so a malformed outer
  // structure must return one, never throw (a packet-review finding: a null set or a
  // null entry threw before reaching any reason)
  if (!Array.isArray(epochs)) return { ok: false, failStop: true, reason: "epochs-not-an-array" };
  const adopted = [];
  for (let i = 0; i < epochs.length; i++) {
    if (epochs[i] === null || typeof epochs[i] !== "object")
      return { ok: false, failStop: true, reason: "epoch-entry-malformed", epochIndex: i };
    if (!isBuf(epochs[i].pinnedHash, 32))
      return { ok: false, failStop: true, reason: "missing-checkpoint-hash-pin", epochIndex: i };
    const r = validCheckpoint({
      bytes: epochs[i].bytes,
      signature: epochs[i].signature,
      pins: { ...pins, checkpointHash: epochs[i].pinnedHash },
    });
    if (!r.valid) return { ok: false, failStop: true, reason: r.reason, epochIndex: i };
    adopted.push({ checkpoint: r.checkpoint, hash: r.hash });
  }
  const s = validEpochSequence(adopted);
  if (!s.valid) return { ok: false, failStop: true, reason: s.reason };
  return { ok: true, adopted: s.sequence };
}

// ---- recognition (spec section 4, the function verbatim) ------------------------------------
// `adopted` MUST be a validateEpochSet-validated sequence. `terminalLatchHeight` and
// `suspendedIntervals` are the bound pool's CLIENT-SIDE lifecycle knowledge (the checkpoint
// carries neither): the latch is the H-inclusive cutoff (recognized while latch >= H, absent
// latch = infinite cutoff), and each suspended interval is [start, end) in Core heights (the
// spec's [B+1, R+1) form).

function recognize({ adopted, rewardHeight, proTxHash, slotIndex, terminalLatchHeight, suspendedIntervals }) {
  const H = toU64(rewardHeight, "rewardHeight");
  if (!isBuf(proTxHash, 32)) throw new TypeError("proTxHash must be 32 raw bytes");
  if (!Number.isInteger(slotIndex) || slotIndex < 0 || slotIndex > 255) throw new RangeError("slotIndex must be 0..255");

  // nothing adopted: nothing can finalize, defer (fail-closed) exactly like region 3
  if (!Array.isArray(adopted) || adopted.length === 0) return { result: "DEFERRED", reason: "no-adopted-epoch" };

  const first = adopted[0].checkpoint, last = adopted[adopted.length - 1].checkpoint;
  if (H < first.effectiveCoreHeight)
    return { result: "UNRECOGNIZED", final: true, reason: "before-deployment-floor" }; // region 2
  if (H >= last.endExclusiveCoreHeight)
    return { result: "DEFERRED", reason: "not-yet-covered" }; // region 3: finalize nothing, replay later

  const epoch = adopted.find(
    (e) => e.checkpoint.effectiveCoreHeight <= H && H < e.checkpoint.endExclusiveCoreHeight
  ).checkpoint;
  const binding = epoch.bindings.find((b) => b.proTxHash.equals(proTxHash) && b.slotIndex === slotIndex);
  if (!binding) return { result: "UNRECOGNIZED", reason: "no-binding" };
  if (H < binding.activationCoreHeight) return { result: "UNRECOGNIZED", reason: "before-activation" };
  if (Array.isArray(suspendedIntervals)) {
    for (const iv of suspendedIntervals) {
      const s = toU64(iv.start, "suspendedIntervals.start");
      const e = toU64(iv.end, "suspendedIntervals.end");
      if (s <= H && H < e) return { result: "UNRECOGNIZED", reason: "suspended" };
    }
  }
  if (terminalLatchHeight !== undefined && terminalLatchHeight !== null) {
    const latch = toU64(terminalLatchHeight, "terminalLatchHeight");
    if (latch < H) return { result: "UNRECOGNIZED", reason: "after-terminal-latch" };
  }
  return { result: "RECOGNIZED", binding, epochId: epoch.epochId };
}

module.exports = {
  FORMAT_VERSION,
  DOMAIN_LABEL,
  MAX_BINDINGS,
  SIGNATURE_SCHEME,
  SIGNATURE_BYTES,
  HEADER_BYTES,
  BINDING_BYTES,
  MAX_CHECKPOINT_BYTES,
  deriveDomainTag,
  checkpointHash,
  signCheckpointHash,
  verifyCheckpointHash,
  publicKeyFromRaw,
  privateKeyFromSeed,
  rawPublicKey,
  serializeCheckpoint,
  parseCheckpoint,
  validCheckpoint,
  validEpochSequence,
  validateEpochSet,
  recognize,
};
