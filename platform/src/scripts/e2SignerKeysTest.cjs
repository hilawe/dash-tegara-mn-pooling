// The shared signer-key resolver's battery (a soundness-review finding).
//
// THE CENTRAL FIXTURE IS THE MEASURED SHAPE, not an invented one. The route's pinned client
// answers IdentityPublicKeyWASM objects whose key id and public-key bytes live on the
// PROTOTYPE as accessors named `keyId` and `data`, with no `id`, `getId` or `getData`, and
// whose `bytes` member is the serialized key object rather than the public key. The measured
// answer is docs/review/controls/2026-09-20-key-shape-probe.log, and wasmLikeKey below
// reproduces it, prototype accessors included, because a plain object literal would not
// exercise the lookup the way the deployed route does.
const { keyIdOf, keyDataOf, toPublicKeyBytes, makeResolveSignerKey, PUBLIC_KEY_WIDTHS } = require("./e2SignerKeys.cjs");
const { runnerSource, skipNote } = require("./runnerSource.cjs");
let passed = 0, failed = 0, skipped = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error("FAIL:", name, "(resolved)"); }
  catch (e) { ok(name, re.test(String(e.message))); }
};

// two REAL compressed secp256k1 points, since the resolver now checks the curve. They are
// generated here rather than pasted so the fixture cannot drift into an off-curve value.
const { secp256k1 } = require("@noble/curves/secp256k1.js");
const pubOf = (n) => Buffer.from(secp256k1.getPublicKey(Buffer.from(String(n).padStart(64, "1"), "hex"), true)).toString("hex");
const PUB33 = pubOf(1);
const PUB33_B = pubOf(2);
const ID = "7d".repeat(32);
const ID_B = "9c".repeat(32);

// the measured shape: accessors on the prototype, `bytes` present and NOT the public key
class WasmLikeKey {
  constructor(id, data) { this._raw = { id, data }; }
  get keyId() { return this._raw.id; }
  get data() { return this._raw.data; }
  get bytes() { return new Uint8Array(42); } // the serialized key OBJECT, a decoy of the wrong width
  get purpose() { return "AUTHENTICATION"; }
}
const wasmLikeKey = (id, data = PUB33) => new WasmLikeKey(id, data);
const answer = (keys, metadata = { height: "1" }) => ({ keys, metadata });
const b58Of = (hex) => `b58(${hex.slice(0, 6)})`;
const resolverOver = (readIdentityKeys) => makeResolveSignerKey({ readIdentityKeys, b58Of });
const rec = (keyId = 1, identity = ID) => ({ signerIdentity: identity, signerKeyId: keyId });

// ---- the id accessor, against the measured shape first ----
ok("the MEASURED shape's key id is read from the prototype accessor keyId", keyIdOf(wasmLikeKey(1)) === 1);
ok("key id zero is read, not treated as absent", keyIdOf(wasmLikeKey(0)) === 0);
ok("a legacy plain-object id is still read", keyIdOf({ id: 4 }) === 4);
ok("a legacy getId method is still read", keyIdOf({ getId: () => 5 }) === 5);
ok("a getKeyId method is read", keyIdOf({ getKeyId: () => 6 }) === 6);
ok("an object with no readable id answers null rather than undefined", keyIdOf({ purpose: "AUTHENTICATION" }) === null);
ok("a BigInt id is NOT accepted as a number (strict comparison against a number would never match)", keyIdOf({ keyId: 1n }) === null);
ok("a string id is not accepted", keyIdOf({ keyId: "1" }) === null);
ok("a negative id is not accepted", keyIdOf({ keyId: -1 }) === null);
ok("a throwing accessor answers null rather than propagating", keyIdOf({ getId: () => { throw new Error("boom"); } }) === null);
ok("a null entry answers null", keyIdOf(null) === null);

// ---- the public-key member ----
ok("the MEASURED shape's public key is read from the prototype accessor data", keyDataOf(wasmLikeKey(1)) === PUB33);
ok("a legacy publicKeyData member is read", keyDataOf({ publicKeyData: PUB33 }) === PUB33);
ok("the two fixture keys are distinct valid points", PUB33 !== PUB33_B && PUB33.length === 66 && PUB33_B.length === 66);
ok("a legacy getData method is read", keyDataOf({ getData: () => PUB33 }) === PUB33);
ok("a byte array member is read", keyDataOf({ data: new Uint8Array(33) }) instanceof Uint8Array);
ok("an object with no public-key member answers null", keyDataOf({ keyId: 1 }) === null);
// THE DECOY: `bytes` is the serialized key object, 42 bytes on the measured answer, and it
// must never be read as a public key. A resolver that fell back to it would hand a verifier a
// plausible buffer that can never verify anything, and the signature would read as invalid.
ok("the serialized-object member is NOT consulted for the public key", keyDataOf({ bytes: new Uint8Array(42) }) === null);

ok("a 33-byte hex string converts", toPublicKeyBytes(PUB33, "x").length === 33);
ok("a 65-byte uncompressed key converts", toPublicKeyBytes("04" + "cd".repeat(64), "x").length === 65);
{
  let threw = false;
  try { toPublicKeyBytes(new Uint8Array(42), "identity zz's key 1"); } catch (e) { threw = /42 bytes, not a 33 or 65-byte/.test(String(e.message)) && /identity zz's key 1/.test(String(e.message)); }
  ok("a 42-byte serialized object refuses, naming the width and the key", threw === true);
}
{
  let threw = false;
  try { toPublicKeyBytes("zz".repeat(33), "x"); } catch (e) { threw = /not hex/.test(String(e.message)); }
  ok("a non-hex string refuses", threw === true);
}
ok("the accepted widths are the two secp256k1 encodings", JSON.stringify(PUBLIC_KEY_WIDTHS) === JSON.stringify([33, 65]));

(async () => {
  { // THE POSITIVE CONTROL THAT PINS a soundness-review finding: the measured answer resolves the named key.
    // Before the repair both runners read the id through `getId`/`id`, neither of which the
    // measured object carries, so this case resolved to "not published" for a key that IS.
    const seen = [];
    const resolve = resolverOver(async (id58) => { seen.push(id58); return answer([wasmLikeKey(0), wasmLikeKey(1), wasmLikeKey(2), wasmLikeKey(3)]); });
    const pub = await resolve(rec(1));
    ok("the measured answer resolves the named key's public-key bytes", pub instanceof Uint8Array && pub.length === 33);
    ok("the bytes are the public-key member, not the serialized object", Buffer.from(pub).toString("hex") === PUB33);
    ok("the identity is handed to the route through the encoder", JSON.stringify(seen) === JSON.stringify([b58Of(ID)]));
  }
  { // key zero resolves, so an off-by-one falsiness read cannot hide
    const resolve = resolverOver(async () => answer([wasmLikeKey(0)]));
    ok("key id zero resolves", (await resolve(rec(0))).length === 33);
  }
  { // the per-pair cache reads the route ONCE and is keyed by the WHOLE pair. BOTH components
    // are varied, because the review found that varying only the key id left a cache keyed on
    // the key id alone passing every case, so identity B's key 1 would have been served
    // identity A's bytes.
    let reads = 0;
    const resolve = resolverOver(async () => { reads++; return answer([wasmLikeKey(1, PUB33), wasmLikeKey(2, PUB33_B)]); });
    const a = await resolve(rec(1));
    const b = await resolve(rec(1));
    ok("a repeated pair is served from the cache", reads === 1 && Buffer.from(a).equals(Buffer.from(b)));
    const c = await resolve(rec(2));
    ok("a DIFFERENT key id on the same identity is not served the first key's bytes",
      Buffer.from(c).toString("hex") === PUB33_B);
  }
  { // ... and a DIFFERENT IDENTITY at the same key id is not served the first identity's bytes
    const byIdentity = { [ID]: PUB33, [ID_B]: PUB33_B };
    const resolve = makeResolveSignerKey({ b58Of, readIdentityKeys: async (id58) => {
      const hex = Object.keys(byIdentity).find((h) => b58Of(h) === id58);
      return answer([wasmLikeKey(1, byIdentity[hex])]);
    } });
    const a = await resolve(rec(1, ID));
    const b = await resolve(rec(1, ID_B));
    ok("a DIFFERENT identity at the same key id is not served the first identity's bytes",
      Buffer.from(a).toString("hex") === PUB33 && Buffer.from(b).toString("hex") === PUB33_B);
  }
  { // F2: THE ANSWER IS A COPY. Changing a returned array in place used to replace what every
    // later caller received for that pair, with no further read and nothing verifying the
    // substitute. Both public keys below are valid points, so only ownership is at issue.
    const resolve = resolverOver(async () => answer([wasmLikeKey(1, PUB33)]));
    const first = await resolve(rec(1));
    Buffer.from(PUB33_B, "hex").copy(Buffer.from(first.buffer, first.byteOffset, first.length));
    // the case is worthless unless the write actually landed, so it is asserted rather than
    // assumed: a copy that silently did nothing would make the next assertion pass for the
    // wrong reason
    ok("the returned array really was changed in place (the case is not vacuous)",
      Buffer.from(first).toString("hex") === PUB33_B);
    const second = await resolve(rec(1));
    ok("changing the FIRST answer in place does not change what the next caller receives",
      Buffer.from(second).toString("hex") === PUB33);
    // AND THE CACHE-HIT PATH TOO, which is a different line of code: the first answer is built
    // fresh from the route while every later one comes out of the cache, so a copy on one path
    // and a reference on the other would pass the assertion above and still let the second
    // caller replace what the third receives.
    Buffer.from(PUB33_B, "hex").copy(Buffer.from(second.buffer, second.byteOffset, second.length));
    ok("the cache-hit answer really was changed in place (the case is not vacuous)",
      Buffer.from(second).toString("hex") === PUB33_B);
    const third = await resolve(rec(1));
    ok("changing a CACHE-HIT answer in place does not change what the next caller receives",
      Buffer.from(third).toString("hex") === PUB33);
  }
  { // F3: THE RECORD IS READ ONCE, BEFORE THE AWAIT. Holding the route pending and changing the
    // record's key id used to have key 2 selected and stored under key 1.
    let release;
    const gate = new Promise((res) => { release = res; });
    const resolve = resolverOver(async () => { await gate; return answer([wasmLikeKey(1, PUB33), wasmLikeKey(2, PUB33_B)]); });
    const mutable = { signerIdentity: ID, signerKeyId: 1 };
    const pending = resolve(mutable);
    mutable.signerKeyId = 2;
    release();
    const got = await pending;
    ok("a record changed during the read does not change which key is selected",
      Buffer.from(got).toString("hex") === PUB33);
    const after = await resolve({ signerIdentity: ID, signerKeyId: 1 });
    ok("and the cache under that pair still holds the key that was asked for",
      Buffer.from(after).toString("hex") === PUB33);
  }
  { // F8: the bytes must decode to a point on the curve, not merely be the right width
    await rejects("33 zero bytes refuse, because they are not a point on the curve",
      resolverOver(async () => answer([{ keyId: 1, data: "00".repeat(33) }]))(rec(1)), /do not decode to a point on the secp256k1 curve/);
  }
  { // F8: a PARTIALLY readable answer does not support "not published"
    await rejects("a miss beside unreadable entries says what was not established, never that the key is absent",
      resolverOver(async () => answer([wasmLikeKey(0), { futureId: 1, data: PUB33 }]))(rec(1)),
      /1 further entry carried no readable key id, so whether it is published was not established/);
  }
  // ---- the refusals, each naming its own cause ----
  await rejects("a genuinely unpublished key refuses, listing what was read",
    resolverOver(async () => answer([wasmLikeKey(0), wasmLikeKey(2)]))(rec(1)), /not among identity 7d7d7d7d\.\.\.'s published keys \(read 0,2\)/);
  // THE CASE THE REPAIR ADDS: an answer whose entries carry no readable id says NOTHING about
  // whether the wanted key is published, so it must not be reported as an absent key
  await rejects("an answer with no readable key id refuses by naming the SHAPE, never the key",
    resolverOver(async () => answer([{ purpose: "AUTHENTICATION" }, { purpose: "TRANSFER" }]))(rec(1)),
    /NONE carried a readable key id, so whether key 1 is published was never established/);
  await rejects("a read with no proof metadata refuses",
    resolverOver(async () => ({ keys: [wasmLikeKey(1)] }))(rec(1)), /carried no proof metadata/);
  await rejects("a read with no key array refuses",
    resolverOver(async () => ({ keys: null, metadata: { height: "1" } }))(rec(1)), /carried no key array/);
  await rejects("an identity publishing nothing refuses",
    resolverOver(async () => answer([]))(rec(1)), /publishes no keys at all/);
  await rejects("a matched key with no public-key member refuses",
    resolverOver(async () => answer([{ keyId: 1 }]))(rec(1)), /carries no readable public-key member/);
  await rejects("a matched key whose bytes are the serialized object refuses on width",
    resolverOver(async () => answer([{ keyId: 1, data: new Uint8Array(42) }]))(rec(1)), /42 bytes, not a 33 or 65-byte/);
  await rejects("a malformed signer identity refuses before any read",
    resolverOver(async () => { throw new Error("must not be called"); })({ signerIdentity: "zz", signerKeyId: 1 }), /not 64 lowercase hex/);
  await rejects("a malformed key id refuses before any read",
    resolverOver(async () => { throw new Error("must not be called"); })({ signerIdentity: ID, signerKeyId: "1" }), /not a nonnegative integer/);
  {
    let threw = false;
    try { makeResolveSignerKey({ b58Of }); } catch (e) { threw = /needs readIdentityKeys/.test(String(e.message)); }
    ok("a resolver built without the key route refuses", threw === true);
    threw = false;
    try { makeResolveSignerKey({ readIdentityKeys: async () => ({}) }); } catch (e) { threw = /needs b58Of/.test(String(e.message)); }
    ok("a resolver built without the identity encoder refuses", threw === true);
  }

  // ---- THE RUNNER BINDING SWEEP ----
  // Both runners carried their own copy of this lookup and both copies were wrong the same
  // way, which is a soundness-review finding lesson repeating. These bind each runner to the shared module.
  const fs = require("fs");
  const path = require("path");
  for (const runner of ["e2ForwardTransportRun.mjs", "e2AuditRun.mjs"]) {
    const src = runnerSource(runner);
    if (src === null) { skipped += 1; console.log(skipNote(runner, "the signer-resolver binding sweep")); continue; }
    ok(`${runner} binds the shared resolver EXACTLY ONCE`,
      src.split("makeResolveSignerKey({").length - 1 === 1);
    // the sweep names the OLD LOOKUP's own shapes, not the word getId, because the runners
    // read an identity's own identifier elsewhere through a different object with a
    // legitimate getId fallback; a sweep broad enough to catch that is a sweep that will be
    // silenced rather than fixed
    ok(`${runner} no longer runs its own key-array lookup`, !/keys\.find\(/.test(src));
    ok(`${runner} no longer carries the resolver's refusal wording (it lives in the shared module)`,
      !/not among identity/.test(src));
    ok(`${runner} no longer builds its own public-key buffer from a key member`,
      !/hit\.data \?\? hit\.publicKeyData/.test(src));
    ok(`${runner} keeps no private signer-key cache beside the shared resolver's`, !/signerKeyCache/.test(src));
    // WHICH ROUTE IS INJECTED is not something the module can check for its caller: it sees
    // an answer, not the call that produced it. The plain key route answers without proof
    // metadata, and the module refuses such an answer at runtime, so a runner wired to it
    // fails closed rather than verifying against the server's word. That refusal costs a
    // whole live run to discover, which is why the injection is also swept here.
    ok(`${runner} injects the METADATA-RETAINING key route, not the plain one`,
      /readIdentityKeys: \(id58\) => [A-Za-z.]*getIdentityPublicKeysWithMetadata\(/.test(src));
  }

  console.log(`e2SignerKeysTest: ${passed} passed, ${failed} failed` + (skipped ? `, ${skipped} skipped (counted, never folded into passes)` : ""));
  process.exitCode = failed ? 1 : 0;
})();
