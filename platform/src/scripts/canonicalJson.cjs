/**
 * canonicalJson - ONE RFC 8785 (JCS) serializer with the FULL domain guard, shared by
 * every module that emits canonical bytes (build review, MAJOR: two partial serializers
 * had drifted, accepting lone UTF-16 surrogates and non-NFC strings, and emitting
 * literal `undefined` as invalid JSON instead of failing).
 *
 * The envelope's canonical domain, enforced here:
 *  - objects serialize with keys sorted by UTF-16 CODE UNIT (RFC 8785 3.2.3), no
 *    whitespace;
 *  - strings are Unicode Normalization Form C and carry NO lone UTF-16 surrogate
 *    (a lone surrogate is outside the domain and would crash or differ across encoders);
 *  - the ONLY JSON numbers are safe integers (every other integer is a decimal string);
 *  - `undefined`, functions, symbols, NaN, Infinity and BigInt are REFUSED, never
 *    coerced or silently dropped.
 */
"use strict";

const util = require("util");

function fail(msg) {
  throw new Error(`canonicalJson: ${msg}`);
}

// THE TWO RESOURCE BOUNDS, and what they do and do not cover (property review, P10, which
// asked whether every CONFORMING record fits inside them; measured against the committed
// positive vector and the schema rather than asserted).
//
// DEPTH cannot bind. The envelope's nesting is fixed by the schema's structure, not by any
// recursive definition, and the deepest path in the committed positive is 9 levels. Longer
// arrays add breadth, never depth, so no conforming record approaches 100.
//
// NODES CAN bind, and this is a real limit rather than a comfortable margin. The schema
// caps only two arrays (`shares` at 512, and the v1 non-slot component array at 0); the
// ledger arrays that grow with the audited range carry no maxItems. The positive costs 411
// nodes in total, and the per-row costs are 9 for a list-walk row, 18 for a Core ledger
// row, 33 for a platform ledger row and 70 for a reward record. A list-walk-dominated
// envelope therefore reaches 5,000,000 nodes at roughly 555,000 rows, which is on the order
// of two to three years of Core blocks covered by a SINGLE envelope.
//
// That is not a soundness hole: the serializer fails closed with a named error and never
// truncates or emits partial bytes, so the failure is a refusal to emit, not a wrong
// record. It is an interoperability limit, because a reader built on this serializer would
// decline an oversized but conforming record.
//
// THAT IS NOW NORMATIVE, so this is no longer an open question (spec revision 28, disclosed
// residual 7 in docs/AUDIT_ENVELOPE_SCHEMA_V1.md): the ledger arrays stay uncapped on
// purpose, an implementation MAY impose its own bounds, and one that does MUST DECLINE with a
// named error rather than truncate, emit partial bytes, or report a verdict over less than
// the whole record. The refusals below are that rule's implementation, and canonicalJsonTest
// drives both limits so the behaviour cannot quietly become a truncation.
const MAX_DEPTH = 100;
const MAX_NODES = 5000000;

/** the string-domain guard, applied to VALUES and to KEYS alike */
function assertStringDomain(s, at) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) fail(`lone high surrogate at ${at}[${i}]`);
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      fail(`lone low surrogate at ${at}[${i}]`);
    }
  }
  if (s.normalize("NFC") !== s) fail(`string at ${at} is not Unicode Normalization Form C`);
  return s;
}

function encodeValue(o, path, depth, budget) {
  const at = path || "$";
  if (depth > MAX_DEPTH) fail(`value nests deeper than ${MAX_DEPTH} at ${at}`);
  if (++budget.n > MAX_NODES) fail(`value exceeds the ${MAX_NODES}-node budget`);
  if (o === null) return "null";
  const t = typeof o;
  if (t === "boolean") return o ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(o)) fail(`non-finite number at ${at}`);
    if (!Number.isSafeInteger(o)) {
      fail(`non-integer or unsafe JSON number ${o} at ${at} (every other integer is a decimal string)`);
    }
    return String(o);
  }
  if (t === "string") {
    assertStringDomain(o, at);
    return JSON.stringify(o);
  }
  if (t === "bigint") fail(`BigInt at ${at} (serialize as a decimal string)`);
  if (t === "undefined") fail(`undefined at ${at} (a nullable field is serialized as explicit null)`);
  if (t === "function" || t === "symbol") fail(`${t} at ${at}`);
  // THE CONTAINER DOMAIN (repository-access review, a required fix). Refusing sparse holes was
  // not enough, because the encoder read containers through Object.keys and array indices
  // and silently ignored everything else they carried. Reproduced, all silent:
  //   an own non-index property on an array   [1,2] with .foo="x"  ->  [1,2]   (foo erased)
  //   a Date                                  new Date(0)          ->  {}      (all of it)
  //   a Map                                   new Map([["k",1]])   ->  {}      (all of it)
  //   a symbol-keyed member                    {[Symbol()]:1,ok:1}  ->  {"ok":1}
  // Each one lets writeEnvelope return an `envelope` object carrying data that neither its
  // canonical bytes nor its evidence digest cover, which breaks the binding those two exist
  // to provide. The conversion from value to bytes must be TOTAL over what it accepts, so
  // anything it cannot represent is refused by name instead of quietly dropped.
  if (typeof o === "object" && o !== null) {
    // PROXIES ARE REFUSED (a review, MAJOR). Every earlier guard here described a property of a
    // value; a Proxy is not a value but a hook that runs on every read, so it defeats all of
    // them at once. Reproduced: a Proxy whose get trap added a property to its target while
    // returning the first value serialized to {"a":1} while the target ended up
    // {"a":1,"b":2}, so accepted state stayed outside the bytes. The key list is captured
    // before the values are read, and any encoder that walks a structure has that window, so
    // the answer is to refuse the mechanism rather than to try to detect its effects.
    // getPrototypeOf on a Proxy runs the trap, so this check comes FIRST.
    if (util.types.isProxy(o)) {
      fail(`Proxy at ${at} (a value whose reads can change it is outside the canonical domain)`);
    }
    if (Object.getOwnPropertySymbols(o).length > 0) {
      fail(`symbol-keyed property at ${at} (outside the canonical domain)`);
    }
    // ARRAYS ARE NOT EXEMPT FROM THE PROTOTYPE RULE (a review, a required fix, a soundness-review finding). This guard used
    // to run only for non-arrays, so `Array.isArray` was the whole of the array admission test.
    // That is a test of the exotic-object kind, not of behaviour: an Array SUBCLASS, or an array
    // handed a replacement prototype, is still an array by that test while carrying methods its
    // caller wrote. The encoder then reached the members through the array's own inherited `map`,
    // so the caller chose the function that produced the output. Reproduced both ways: a dense
    // two-element array whose `map` returns `[]` serialized to `[]`, dropping accepted state, and
    // one whose `map` returns a value of its own serialized THAT, putting a member in the bytes
    // that the value never held. The second case is why the rule is written against the mechanism
    // rather than against a missing element.
    const proto = Object.getPrototypeOf(o);
    if (Array.isArray(o)) {
      if (proto !== Array.prototype) {
        fail(`array with a non-standard prototype at ${at} ` +
             "(its inherited methods could choose what the bytes contain)");
      }
    } else if (proto !== Object.prototype && proto !== null) {
      fail(`non-plain object at ${at} (${(o.constructor && o.constructor.name) || "unknown type"}); ` +
           "only plain objects and arrays are in the canonical domain");
    }
    // DATA PROPERTIES ONLY, ENUMERABLE ONLY (a review, MAJOR: the domain was still not
    // total). Object.keys sees only enumerable string keys, so a NON-ENUMERABLE own
    // property serialized to nothing, silently: {a:1} with a hidden own property produced
    // {"a":1}, and the gate then validated bytes that do not cover the object's state. An
    // ACCESSOR property is refused outright rather than read: a getter can return a value
    // AND mutate the object while the encoder walks it, so by the time the bytes exist the
    // object holds state they never saw. Refusing accessors removes that whole mechanism
    // instead of trying to detect its effects. The production writer's structuredClone
    // yields only enumerable data properties, so real evidence is unaffected.
    for (const name of Object.getOwnPropertyNames(o)) {
      if (Array.isArray(o) && name === "length") continue;   // the one expected non-enumerable
      const d = Object.getOwnPropertyDescriptor(o, name);
      if (d.get || d.set) {
        fail(`accessor property ${JSON.stringify(name)} at ${at} ` +
             "(only plain data properties are in the canonical domain)");
      }
      if (!d.enumerable) {
        fail(`non-enumerable own property ${JSON.stringify(name)} at ${at} ` +
             "(it would be silently absent from the serialized form)");
      }
    }
  }
  if (Array.isArray(o)) {
    for (const k of Object.keys(o)) {
      // Object.keys on an array yields its index keys plus any own string keys; anything
      // that is not a canonical index is data the encoder would not represent
      if (!/^(?:0|[1-9][0-9]*)$/.test(k) || Number(k) >= o.length) {
        fail(`own non-index property ${JSON.stringify(k)} on the array at ${at} ` +
             "(it would not appear in the serialized form)");
      }
    }
    // SPARSE ARRAYS ARE OUTSIDE THE DOMAIN (confirmation round, a required fix). `map` SKIPS
    // holes rather than visiting them, so a hole neither reached the `undefined` refusal
    // below nor produced a value. Two reproduced outcomes, both bad: `[Array(1)]`
    // serialized to `[]`, silently changing the value, and `[, 1]` serialized to `[,1]`,
    // which is not valid JSON at all. Either is a value-to-bytes divergence arising
    // BEFORE the normative gate can see it, so holes are refused by name here.
    for (let i = 0; i < o.length; i++) {
      if (!Object.prototype.hasOwnProperty.call(o, i)) {
        fail(`array hole at ${at}[${i}] (a sparse array is outside the canonical domain)`);
      }
    }
    // THE ENCODER WALKS THE INDICES ITSELF (a review, a required fix, a soundness-review finding). `o.map` is a property
    // read on caller-supplied data, so whatever function it resolves to decides which members
    // reach the bytes. The prototype guard above already refuses the arrays that can carry a
    // replacement, and this loop removes the mechanism as well, on the same principle the Proxy
    // and accessor rules follow: refuse the mechanism rather than try to detect its effects.
    // `parts` is a local literal, so its `join` is the standard one.
    const parts = [];
    for (let i = 0; i < o.length; i++) {
      parts.push(encodeValue(o[i], `${at}[${i}]`, depth + 1, budget));
    }
    return `[${parts.join(",")}]`;
  }
  if (t === "object") {
    // KEY ORDER: RFC 8785 section 3.2.3 sorts property names as arrays of UTF-16 CODE
    // UNITS compared as unsigned integers, which is exactly JavaScript's default string
    // sort; the two do NOT diverge (one build review suggested code-POINT order
    // instead, which would differ for non-BMP keys). The comparator is written out here
    // so the convention is explicit rather than inherited from a default, and every key
    // in this envelope is ASCII regardless.
    const keys = Object.keys(o).sort((x, y) => {
      const n = Math.min(x.length, y.length);
      for (let i = 0; i < n; i++) {
        const a = x.charCodeAt(i), b = y.charCodeAt(i);
        if (a !== b) return a - b;
      }
      return x.length - y.length;
    });
    // KEYS are in the same domain as values (surrogates and NFC), not merely
    // JSON-escapable: a non-NFC key would serialize to bytes another encoder rejects
    for (const k of keys) assertStringDomain(k, `${at} key ${JSON.stringify(k)}`);
    return `{${keys.map((k) => `${JSON.stringify(k)}:${encodeValue(o[k], `${at}.${k}`, depth + 1, budget)}`).join(",")}}`;
  }
  return fail(`unserializable value of type ${t} at ${at}`);
}

/** canonical UTF-8 bytes of a value inside the envelope's domain */
function canonicalize(value) {
  return Buffer.from(encodeValue(value, "$", 0, { n: 0 }), "utf8");
}

/** convenience: the canonical string form */
const canonicalString = (value) => encodeValue(value, "$", 0, { n: 0 });

module.exports = { canonicalize, canonicalString };
