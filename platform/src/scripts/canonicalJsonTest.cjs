/**
 * Fixtures for the shared RFC 8785 serializer and its FULL domain guard (build review,
 * MAJOR: two partial serializers had accepted lone surrogates and non-NFC strings and
 * emitted `undefined` as invalid JSON).
 */
"use strict";
const { canonicalize, canonicalString } = require("./canonicalJson.cjs");
let pass = 0, fail = 0;
const ok = (n, c) => { if (c) pass++; else { fail++; console.error(`FAIL: ${n}`); } };
const throws = (n, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${n} (no error)`); }
  catch (e) { ok(n, re.test((e && e.message) || "")); }
};
ok("keys sort by UTF-16 code unit", canonicalString({ b: 1, A: 2, a: 3 }) === '{"A":2,"a":3,"b":1}');
ok("nested objects sort too", canonicalString({ z: { b: 1, a: 2 } }) === '{"z":{"a":2,"b":1}}');
ok("arrays keep their order", canonicalString([3, 1, 2]) === "[3,1,2]");
ok("null is emitted", canonicalString({ a: null }) === '{"a":null}');
ok("booleans are emitted", canonicalString([true, false]) === "[true,false]");
ok("safe integers are numbers", canonicalString({ h: 9007199254740991 }) === '{"h":9007199254740991}');
ok("output is UTF-8 bytes", Buffer.isBuffer(canonicalize({ a: 1 })));
ok("a valid surrogate pair survives", canonicalString({ a: "😀" }) === '{"a":"😀"}');
throws("undefined is refused", () => canonicalize({ a: undefined }), /undefined at \$\.a/);
throws("undefined in an array is refused", () => canonicalize([undefined]), /undefined at \$\[0\]/);
throws("a function is refused", () => canonicalize({ a: () => 1 }), /function at/);
throws("a symbol is refused", () => canonicalize({ a: Symbol("s") }), /symbol at/);
throws("a BigInt is refused", () => canonicalize({ a: 1n }), /BigInt at/);
throws("NaN is refused", () => canonicalize({ a: NaN }), /non-finite/);
throws("Infinity is refused", () => canonicalize({ a: Infinity }), /non-finite/);
throws("a float is refused", () => canonicalize({ a: 1.5 }), /non-integer or unsafe/);
throws("2^53 is refused", () => canonicalize({ a: 9007199254740992 }), /non-integer or unsafe/);
throws("a lone high surrogate is refused", () => canonicalize({ a: "x\ud800y" }), /lone high surrogate/);
throws("a lone low surrogate is refused", () => canonicalize({ a: "\udc00" }), /lone low surrogate/);
throws("a trailing high surrogate is refused", () => canonicalize({ a: "ab\ud83d" }), /lone high surrogate/);
throws("a non-NFC string is refused", () => canonicalize({ a: "é" }), /Normalization Form C/);
ok("the NFC form of the same text is accepted", canonicalString({ a: "é" }) === '{"a":"é"}');
throws("a non-NFC KEY is refused", () => canonicalize({ ["é"]: 1 }), /Normalization Form C/);
// KEY ORDER is UTF-16 code units (RFC 8785 3.2.3), stated explicitly by the comparator
ok("ASCII keys sort by code unit", canonicalString({ b: 1, a: 2, C: 3 }) === '{"C":3,"a":2,"b":1}');
ok("a prefix key sorts before its extension", canonicalString({ ab: 1, a: 2 }) === '{"a":2,"ab":1}');
ok("the explicit comparator matches the platform default for the envelope's key set",
   canonicalString({ zz: 1, aa: 2, mm: 3 }) ===
   `{${["zz","aa","mm"].sort().map(k => `"${k}":${({zz:1,aa:2,mm:3})[k]}`).join(",")}}`);

// ---------------------------------------------------------------------------
// THE RESOURCE BOUNDS (confirmation round, MINOR). The module states that it fails closed
// with a named error at its depth and node limits, and the specification now says normatively
// that an implementation may decline an oversized record but must never process part of one.
// Both were prose with no check behind them, which is the gap this closes: the fixtures below
// would fail if either limit were removed or turned into a truncation.
// ---------------------------------------------------------------------------
{
  // depth: nest one past the limit, and confirm the limit itself still serializes
  const nest = (n) => { let v = 1; for (let i = 0; i < n; i++) v = { a: v }; return v; };
  ok("a value at the depth limit still serializes", canonicalize(nest(98)).length > 0);
  throws("a value past the depth limit is refused by name",
    () => canonicalize(nest(120)), /nests deeper than 100/);

  // nodes: a wide array is the cheapest way past the node budget
  const wide = new Array(5000001).fill(0);
  throws("a value past the node budget is refused by name",
    () => canonicalize(wide), /exceeds the 5000000-node budget/);

  // the decisive property: the refusal is a THROWN error, never partial output. A truncating
  // implementation would return bytes here instead, and this check would fail.
  let returned = null;
  try { returned = canonicalize(nest(120)); } catch (e) { returned = null; }
  ok("an over-limit value yields NO bytes at all, rather than truncated bytes", returned === null);
}

// SPARSE ARRAYS (confirmation round 2, MUST-FIX). `map` skips holes, so a hole reached
// neither the undefined refusal nor a serialized value: `[Array(1)]` silently became `[]`
// and `[, 1]` became `[,1]`, which is not valid JSON. Both are value-to-bytes divergences
// arising before the normative gate can see them.
{
  throws("a trailing array hole is refused by name",
    () => canonicalize({ a: Array(1) }), /array hole at/);
  throws("a leading array hole is refused by name",
    () => canonicalize({ a: [, 1] }), /array hole at/);
  throws("a hole in the middle is refused by name",
    () => canonicalize({ a: [1, , 2] }), /array hole at/);
  ok("a dense array with an explicit null still serializes",
     canonicalString({ a: [1, null, 2] }) === '{"a":[1,null,2]}');
  // the old behaviour, asserted as ABSENT: whatever comes out must parse as JSON
  let out = null;
  try { out = canonicalString({ a: [, 1] }); } catch (e) { out = null; }
  ok("no invalid-JSON bytes are produced for a sparse array", out === null);
}

// THE CONTAINER DOMAIN (repository-access round, MUST-FIX). Refusing holes was not enough:
// the encoder read containers through Object.keys and array indices and silently ignored
// everything else they carried, so the writer could return an envelope object holding data
// that neither its bytes nor its evidence digest covered.
{
  const withProp = [1, 2];
  withProp.foo = "x";
  throws("an own non-index property on an array is refused",
    () => canonicalize({ a: withProp }), /own non-index property "foo"/);
  throws("a Date is refused rather than serialized as {}",
    () => canonicalize({ d: new Date(0) }), /non-plain object .*Date/);
  throws("a Map is refused rather than serialized as {}",
    () => canonicalize({ m: new Map([["k", 1]]) }), /non-plain object .*Map/);
  throws("a Set is refused", () => canonicalize({ s: new Set([1]) }), /non-plain object .*Set/);
  throws("a class instance is refused", () => {
    class C { constructor() { this.x = 1; } }
    return canonicalize({ c: new C() });
  }, /non-plain object/);
  throws("a symbol-keyed member is refused rather than dropped",
    () => canonicalize({ [Symbol("s")]: 1, ok: 1 }), /symbol-keyed property/);

  // AN ARRAY WITH A REPLACEMENT PROTOTYPE (round 8, MUST-FIX, a soundness-review finding). `Array.isArray` tests the
  // exotic-object kind, not behaviour, so it stays true for a subclass and for an array handed a
  // new prototype. The encoder used to reach members through the array's own inherited `map`, so
  // those arrays chose the function that produced the bytes. The three cases below are the three
  // that were reproduced against the unmodified source, and the third is the one that decides how
  // the rule has to be written: it does not drop a member, it ADDS one the value never held, so a
  // rule phrased against missing elements would have left it in place.
  throws("an Array subclass is refused rather than walked", () => {
    class Sub extends Array {}
    return canonicalize({ a: Sub.from([1, 2]) });
  }, /array with a non-standard prototype/);
  throws("an array whose map would drop its members is refused", () => {
    class Dropping extends Array { map() { return []; } }
    return canonicalize({ a: Dropping.from([1, 2]) });
  }, /array with a non-standard prototype/);
  throws("an array whose map would invent a member is refused", () => {
    const a = [1, 2];
    Object.setPrototypeOf(a, Object.assign(Object.create(Array.prototype),
                                           { map: () => ['"invented"'] }));
    return canonicalize({ a });
  }, /array with a non-standard prototype/);
  ok("an ordinary array still serializes by index",
     canonicalString({ a: [1, "two", null, [3]] }) === '{"a":[1,"two",null,[3]]}');

  // WHAT THE SUITE DOES NOT GUARD HERE, STATED RATHER THAN IMPLIED. The a soundness-review finding fix has two
  // halves: the prototype rule above, and an index walk in the encoder that never consults
  // `map`. Only the first half is guarded. Reverting the index walk on its own leaves every
  // case in this file green, which was measured, not assumed.
  //
  // That is not an oversight left open. Any array that could reach a caller-chosen `map` is
  // already refused by the prototype rule, so an input cannot distinguish the two halves. The
  // only way to reach the walk is to replace `Array.prototype.map` process-wide, and that is
  // outside the model this serializer defends: the object branch builds its own key array and
  // maps over it too, so a process that can pollute the intrinsic prototypes has already
  // defeated the encoder by a route no local check can close.
  //
  // The walk is kept because it makes the encoder stop reading a method off caller-supplied
  // data at all, rather than depending on the prototype rule being complete. It is defence in
  // depth behind a guarded check, and it is recorded as such instead of being given a fixture
  // that would only appear to test it.
  // plain data is unaffected, including a null-prototype object
  ok("a plain nested structure still serializes",
     canonicalString({ a: [1, { b: 2 }], c: null }) === '{"a":[1,{"b":2}],"c":null}');
  ok("a null-prototype plain object still serializes",
     canonicalString(Object.assign(Object.create(null), { a: 1 })) === '{"a":1}');
}

// THE DOMAIN IS ONLY TOTAL IF HIDDEN STATE IS REFUSED TOO (round 4, MAJOR). Object.keys sees
// enumerable string keys only, so a non-enumerable own property serialized to nothing, and an
// accessor could hand back a value while adding another property to the object mid-walk.
{
  const arr = [1, 2];
  Object.defineProperty(arr, "hidden", { value: "x", enumerable: false });
  throws("a non-enumerable own property on an array is refused",
    () => canonicalize({ a: arr }), /non-enumerable own property "hidden"/);
  const obj = { a: 1 };
  Object.defineProperty(obj, "hidden", { value: 2, enumerable: false });
  throws("a non-enumerable own property on an object is refused",
    () => canonicalize({ o: obj }), /non-enumerable own property "hidden"/);
  const mutating = {};
  Object.defineProperty(mutating, "a", {
    enumerable: true, configurable: true, get() { mutating.b = 2; return 1; } });
  throws("an accessor property is refused rather than read",
    () => canonicalize({ g: mutating }), /accessor property "a"/);
  // arrays legitimately carry a non-enumerable length, which must NOT trip the check
  ok("a plain array still serializes", canonicalString({ a: [1, 2, 3] }) === '{"a":[1,2,3]}');
}

// PROXIES (round 6, MINOR: the refusal existed with no fixture behind it, so removing it left
// these tests green). A Proxy is not a value but a hook that runs on every read, which is why it
// defeats guards that describe values. The reproduction that motivated the refusal is driven here.
{
  const target = { a: 1 };
  const mutating = new Proxy(target, {
    get(t, k) { if (k === "a") t.b = 2; return t[k]; },
  });
  throws("a Proxy is refused rather than walked", () => canonicalize({ p: mutating }), /Proxy at/);
  throws("a Proxy at the ROOT is refused too", () => canonicalize(mutating), /Proxy at/);
  // the mechanism it prevents: without the refusal the encoder emits {"a":1} while the object
  // it walked ends up holding b as well, so accepted state sits outside the bytes
  ok("the trap really does mutate on read, which is what makes it dangerous", (() => {
    const t2 = { a: 1 };
    const p2 = new Proxy(t2, { get(t, k) { if (k === "a") t.b = 2; return t[k]; } });
    void p2.a;
    return t2.b === 2;
  })());
  // an ARRAY proxy is refused on the same grounds
  throws("a Proxy wrapping an array is refused",
    () => canonicalize({ a: new Proxy([1, 2], {}) }), /Proxy at/);
  // and a plain object with the same shape still serializes, so the guard is not over-broad
  ok("a plain object of the same shape still serializes",
     canonicalString({ p: { a: 1 } }) === '{"p":{"a":1}}');
}

console.log(`canonicalJsonTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
