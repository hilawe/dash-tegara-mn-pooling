/**
 * THE SHARED SIGNER-KEY RESOLVER (a soundness-review finding), consumed by BOTH live runners.
 *
 * WHAT IT DOES. Given a capture record naming a signer identity and a key id, it reads that
 * identity's published keys through the METADATA-RETAINING route and answers the named key's
 * public-key bytes. A read without proof metadata, a key that is genuinely not published, and
 * a key whose bytes are not a usable public key all REFUSE, so nothing downstream can verify a
 * signature against something this module could not establish.
 *
 * WHY IT EXISTS AS ONE MODULE. Both runners carried their own copy of this lookup and both
 * copies read the key id through `k.getId()` or `k.id`. The route's pinned client answers with
 * `IdentityPublicKeyWASM` objects, whose prototype exposes `keyId` and `data` and which have
 * neither `id` nor `getId`. Every comparison therefore evaluated `undefined === 1`, no key ever
 * matched, and both runners reported "signer key 1 not among identity 7dad14b6...'s published
 * keys" about an identity that publishes exactly that key. The measured shape is in
 * docs/review/controls/2026-09-20-key-shape-probe.log.
 *
 * THE RULE THAT KEEPS THE NEXT SHAPE CHANGE FROM LOOKING LIKE AN ABSENT KEY. A comparison that
 * could not read ANY key's id is not evidence that the wanted key is missing, so this module
 * distinguishes the two. If no entry in the answer yields a readable key id, it refuses by
 * naming the ANSWER's shape rather than the key, because claiming a key is unpublished on the
 * strength of a comparison that never ran is the affirmative-result-from-an-unperformed-check
 * shape pointed backwards: a confident negative nobody measured.
 *
 * THE BYTES ARE READ FROM THE PUBLIC-KEY MEMBER, NEVER FROM THE OBJECT'S SERIALIZATION. The
 * same WASM object also exposes `bytes`, which is the serialized key OBJECT (42 bytes on the
 * measured answer) rather than the public key (33 bytes compressed). Reading the wrong one
 * would hand a verifier a plausible-looking buffer that can never verify anything, so `bytes`
 * is deliberately not among the members consulted, the width is checked, and the bytes must
 * decode to a point on the secp256k1 curve rather than merely being the right length.
 *
 * STATED WIDTH. The key answer does not name its own subject, so this module cannot confirm
 * that the keys it reads belong to the identity the caller asked about; the request binds the
 * subject and the caller's route binding is what establishes it. Substituting a different
 * identity there yields another identity's key, under which a signature fails to verify, so
 * that failure direction is a refusal rather than an acceptance. Both runners' bindings are
 * swept by the battery, because no check inside this module can reach them.
 */
const HEX64 = /^[0-9a-f]{64}$/;
// the curve is loaded lazily and once, the way e2CaptureRecord loads it, because the library
// is an ES module and this one is not
let secpPromise = null;
const secp = () => {
  if (!secpPromise) secpPromise = import("@noble/curves/secp256k1.js").then((m) => m.secp256k1);
  return secpPromise;
};
const assertOnCurve = async (bytes, where) => {
  const hex = Buffer.from(bytes).toString("hex");
  let point = null;
  try { point = (await secp()).Point.fromHex(hex); } catch (e) { point = null; }
  if (point === null) {
    throw new Error(`e2SignerKeys: ${where}'s bytes are the right width but do not decode to a point on the secp256k1 curve; refusing`);
  }
};
const refuse = (m) => { throw new Error(`e2SignerKeys: ${m}`); };

// the members the pinned client and its predecessors have used for the key id, in order; a
// member is accepted only when it yields a nonnegative safe integer, so a getter answering
// undefined, a BigInt or a string never silently becomes a comparison against a number
const KEY_ID_MEMBERS = ["keyId", "id"];
const KEY_ID_METHODS = ["getKeyId", "getId"];
const keyIdOf = (k) => {
  if (!k || (typeof k !== "object" && typeof k !== "function")) return null;
  for (const m of KEY_ID_MEMBERS) {
    const v = k[m];
    if (Number.isSafeInteger(v) && v >= 0) return v;
  }
  for (const m of KEY_ID_METHODS) {
    if (typeof k[m] === "function") {
      let v;
      try { v = k[m](); } catch (_) { v = undefined; }
      if (Number.isSafeInteger(v) && v >= 0) return v;
    }
  }
  return null;
};

// the PUBLIC-KEY bytes, never the object's own serialization
const KEY_DATA_MEMBERS = ["data", "publicKeyData"];
const KEY_DATA_METHODS = ["getData", "getPublicKeyData"];
const keyDataOf = (k) => {
  for (const m of KEY_DATA_MEMBERS) {
    const v = k[m];
    if (typeof v === "string" || v instanceof Uint8Array || Buffer.isBuffer(v)) return v;
  }
  for (const m of KEY_DATA_METHODS) {
    if (typeof k[m] === "function") {
      let v;
      try { v = k[m](); } catch (_) { v = undefined; }
      if (typeof v === "string" || v instanceof Uint8Array || Buffer.isBuffer(v)) return v;
    }
  }
  return null;
};

// a secp256k1 public key is 33 bytes compressed or 65 uncompressed; anything else is refused
// rather than handed to a verifier that would answer false about a key it never received
const PUBLIC_KEY_WIDTHS = [33, 65];
const toPublicKeyBytes = (data, where) => {
  let buf;
  if (typeof data === "string") {
    if (data.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(data)) refuse(`${where}'s public-key member is a string that is not hex; refusing`);
    buf = Buffer.from(data, "hex");
  } else {
    buf = Buffer.from(data);
  }
  if (!PUBLIC_KEY_WIDTHS.includes(buf.length)) {
    refuse(`${where}'s public-key member is ${buf.length} bytes, not a ${PUBLIC_KEY_WIDTHS.join(" or ")}-byte secp256k1 public key (the serialized key OBJECT is a different member and is not a public key); refusing`);
  }
  return new Uint8Array(buf);
};

/**
 * readIdentityKeys(identityBase58) must answer the metadata-retaining route's shape,
 * { keys | publicKeys, metadata }. b58Of converts a 64-hex identity to that route's encoding.
 * The returned resolver caches per (identity, key id) pair for the run.
 */
const makeResolveSignerKey = ({ readIdentityKeys, b58Of }) => {
  if (typeof readIdentityKeys !== "function") refuse("makeResolveSignerKey needs readIdentityKeys, the metadata-retaining key route");
  if (typeof b58Of !== "function") refuse("makeResolveSignerKey needs b58Of, the identity encoder");
  const cache = new Map();
  return async (rec) => {
    // THE RECORD IS READ ONCE, INTO LOCALS, BEFORE ANY AWAIT (the review's F3). The cache key
    // used to be built before the route call while the key id was read again after it, so a
    // caller that retained the record and changed its signerKeyId during the read had key 2
    // selected and stored under key 1. Nothing beyond this point reads `rec` again.
    if (!rec || typeof rec.signerIdentity !== "string" || !HEX64.test(rec.signerIdentity)) {
      refuse(`the record names signerIdentity ${JSON.stringify(rec && rec.signerIdentity)}, not 64 lowercase hex; refusing`);
    }
    if (!Number.isSafeInteger(rec.signerKeyId) || rec.signerKeyId < 0) {
      refuse(`the record names signerKeyId ${JSON.stringify(rec.signerKeyId)}, not a nonnegative integer; refusing`);
    }
    const identity = rec.signerIdentity;
    const keyId = rec.signerKeyId;
    const cacheKey = `${identity}:${keyId}`;
    // EVERY ANSWER IS A FRESH COPY (the review's F2). The cache used to hand out the array it
    // holds, so a caller that changed those bytes in place replaced what every later caller
    // received for that pair, with no further read and no verification of the substitute.
    if (cache.has(cacheKey)) return Uint8Array.from(cache.get(cacheKey));
    const short = `${identity.slice(0, 8)}...`;
    const r = await readIdentityKeys(b58Of(identity));
    // PROOF METADATA IS REQUIRED: the plain route answers keys with no metadata, and a capture
    // basis verified against those would rest on the server's word
    if (!r || !r.metadata) refuse(`signer identity ${short}'s key read carried no proof metadata; refusing`);
    const keys = r.keys ?? r.publicKeys;
    if (!Array.isArray(keys)) refuse(`signer identity ${short}'s key read carried no key array; refusing`);
    if (keys.length === 0) refuse(`signer identity ${short} publishes no keys at all; refusing`);
    const ids = keys.map(keyIdOf);
    const unreadable = ids.filter((v) => v === null).length;
    // THE SHAPE CHECK, and the reason this module exists: a comparison that could read no key
    // id at all says nothing about whether the wanted key is published
    if (unreadable === keys.length) {
      refuse(`signer identity ${short}'s key read answered ${keys.length} entries and NONE carried a readable key id, so whether key ${keyId} is published was never established; the route's key shape has changed and the resolver must be taught it, refusing`);
    }
    const index = ids.indexOf(keyId);
    if (index === -1) {
      // A PARTIALLY READABLE ANSWER STILL DOES NOT SUPPORT "NOT PUBLISHED" (the review's F8).
      // The wanted key could be sitting behind one of the entries whose id could not be read,
      // so the refusal says what was and was not examined rather than asserting absence.
      if (unreadable > 0) {
        refuse(`signer key ${keyId} is not among the ${keys.length - unreadable} readable entries of identity ${short}'s key read (read ${ids.filter((v) => v !== null).join(",")}), and ${unreadable} further entr${unreadable === 1 ? "y" : "ies"} carried no readable key id, so whether it is published was not established; refusing`);
      }
      refuse(`signer key ${keyId} not among identity ${short}'s published keys (read ${ids.join(",")}); refusing`);
    }
    const data = keyDataOf(keys[index]);
    if (data === null) refuse(`identity ${short}'s key ${keyId} carries no readable public-key member; refusing`);
    const where = `identity ${short}'s key ${keyId}`;
    const pub = toPublicKeyBytes(data, where);
    // THE BYTES MUST DECODE TO A POINT ON THE CURVE (the review's F8). Width and hex alone let
    // 33 zero bytes through, which is not a key at all; a verifier handed one answers false,
    // so the direction is safe, and the module's own promise is that what it returns IS a
    // public key rather than bytes of the right length.
    await assertOnCurve(pub, where);
    cache.set(cacheKey, pub);
    return Uint8Array.from(pub);
  };
};

module.exports = { keyIdOf, keyDataOf, toPublicKeyBytes, makeResolveSignerKey, PUBLIC_KEY_WIDTHS };
