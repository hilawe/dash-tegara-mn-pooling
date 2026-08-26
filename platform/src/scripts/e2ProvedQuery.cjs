/**
 * The PROVED-ENUMERATION WRAPPER (the frozen audit section's literal
 * contract, a review finding 5, cursor rules a review finding 6, the
 * no-progress refusal a review finding 9). The pinned proved document
 * query DISCARDS its metadata heights, so ENUMERATED document evidence
 * for the audit flows through THIS wrapper, whose page result carries the
 * authenticated height the range reduction needs (known-key reads reach
 * the audit through provedByKey and carry their own heights).
 *
 * WHAT IT ESTABLISHES: pagination follows the exclusive-cursor rule (null
 * on the first call, thereafter the last returned document's identifier;
 * an empty or short page is terminal), every VERIFIED page's height
 * (terminal pages included) enters the min-to-max reduction, document
 * identifiers are STRICTLY ASCENDING across the whole enumeration (the
 * id-ordered cursor contract; a repeat, an echo of the exclusive
 * start-after, or a cursor regression all refuse as the no-progress
 * rule), and an unserved or unverified page makes the WHOLE enumeration
 * UNPROVED with no partial range claimed.
 *
 * WHAT IT DOES NOT ESTABLISH, stated: the per-page proof verification
 * (the same two stages as every proved read) is the injected
 * fetchVerifiedPage's obligation, the acceptance-stage adapter over the
 * installed helpers; this module drives the page machine and never
 * upgrades a page's declared strength. Pages proving at different
 * platform heights is exactly why enumeration alone cannot upgrade the
 * record-set aspect past READ-CHECKED; the range and the overlap
 * statement exist to report that, never to prove a common snapshot.
 *
 * THE INJECTED PAGE CONTRACT: fetchVerifiedPage({ contractId, type,
 * where, orderBy, limit, startAfter }) resolves to
 *   { status: "verified", documents, height }  a verified page, height the
 *     authenticated metadata height as a canonical decimal string, and
 *     every document carrying its 64-hex `id`; the page MAY also carry a
 *     `cursor` member, which must be null or a 64-hex document identifier
 *     (the transport's own page shape) and which this wrapper IGNORES
 *     entirely: pagination advances only on the wrapper's own cursor,
 *     computed from the last returned document (successive reviews, declared
 *     here a review, its grammar enforced a review so that an accepted
 *     envelope means every member it carries conforms);
 *   { status: "unserved" } | { status: "unverified" }  the two failure
 *     strengths, both making the enumeration UNPROVED.
 */
const DEC_RE = /^(0|[1-9][0-9]*)$/;
const HEX64 = /^[0-9a-f]{64}$/;

const refuse = (why) => { throw new Error(`e2ProvedQuery: ${why}; refusing`); };
// a TOTAL formatter for a CAUGHT value: the caught value can be an
// ordinary rejection (whose message is the real cause and should be kept) OR a
// value resistant to inspection (a null-prototype object, a throwing `message`
// getter, a revoked proxy), so every access is guarded. This keeps the true
// cause of an ordinary fetch rejection instead of overstating it.
const errText = (e) => {
  try { const m = e && e.message; if (typeof m === "string") return m; } catch { /* fall through */ }
  try { return String(e); } catch { return "(an unreadable thrown value)"; }
};

// the PLAIN-DATA walk over the COMPLETE value graph: base prototypes
// only (Object, Array, or null), PLUS bare binary leaves (Uint8Array or
// Buffer, captured byte-for-byte below) as the one non-base class
// admitted, and every own member read from a data descriptor. A
// getter-backed value is not stable evidence, because each read through
// it can serve a different value.
//
// WHAT THIS ESTABLISHES IS A PROPERTY OF THE CAPTURE, NOT OF THE INPUT
// (a review, generalizing the review binary-leaf note to the whole
// walk). A Proxy over an extensible target can report Object.prototype
// from its getPrototypeOf trap while wrapping a class instance, so the
// walk cannot decide what the input REALLY is, and does not try. It
// reconstructs a fresh graph of plain objects, arrays, primitives and
// byte containers out of the descriptor values it validated, so whatever
// the input was, the value the consumer reads is plain data carrying
// exactly the validated members. The refusals below therefore say what
// the walk could not CAPTURE, not what the input was.
//
// VALIDATE-AND-CAPTURE, not validate-then-reread: the walk
// reconstructs a fresh plain-data deep copy from the SINGLE descriptor
// read it validates, and the consumer reads the copy, never the original.
// A getter-backed member is refused, but a data DESCRIPTOR is not enough
// on its own: a Proxy can report a plain data descriptor to
// getOwnPropertyDescriptor and then serve a different value through its
// get trap (a configurable data property carries no get==descriptor
// invariant), so a validate-then-reread would check one array and hand
// the caller another. Capturing dsc.value at validation time and reading
// only the capture closes that window, because the value validated is the
// value used. plainDataSnapshot returns { defect, value }: on a clean
// walk, `value` is the captured copy (shared subgraphs preserved as
// shared, which serializes identically); on a defect, `value` is
// undefined and `defect` is the first defect string.
const plainDataSnapshot = (root) => {
  const done = new Map(); // node -> { h: subtree HEIGHT, copy: captured node }
  const path = new Set();
  const INDEX_RE = /^(0|[1-9][0-9]*)$/;
  let defect = null;
  // walk returns { h, copy }, or null with `defect` set. Heights are
  // memoized so a SHARED subtree revisited from a deeper position still
  // counts its full expansion against the depth bound (a review:
  // serialization expands sharing, so the bound must too), and the copy
  // is memoized so the reconstructed graph preserves the sharing. "The
  // JSON value domain" in the messages means this module's plain-data
  // domain: JSON values EXTENDED with bare binary leaves.
  const walk = (v, label) => {
    if (typeof v === "function") { defect = `${label} is a function, not plain data`; return null; }
    // the JSON VALUE DOMAIN, enforced throughout the graph:
    // null, booleans, strings, finite numbers, dense index-only arrays,
    // plain objects, and bare binary leaves; nothing else
    if (typeof v === "symbol") { defect = `${label} is a symbol, outside the JSON value domain`; return null; }
    if (typeof v === "bigint") { defect = `${label} is a bigint, outside the JSON value domain`; return null; }
    if (v === undefined) { defect = `${label} is undefined, outside the JSON value domain`; return null; }
    if (typeof v === "number" && !Number.isFinite(v)) { defect = `${label} is a non-finite number, outside the JSON value domain`; return null; }
    // a primitive is immutable, so it IS its own capture
    if (v === null || typeof v !== "object") return { h: 0, copy: v };
    const memo = done.get(v);
    if (memo !== undefined) {
      if (path.size + memo.h - 1 > 512) { defect = `${label} nests past the JSON domain depth bound`; return null; }
      return memo;
    }
    // a CYCLE is not a JSON value: a node already on the
    // traversal path closes one. Depth is bounded so excessive nesting
    // fails closed instead of exhausting the call stack.
    if (path.has(v)) { defect = `${label} closes a cycle, outside the JSON value domain`; return null; }
    if (path.size > 512) { defect = `${label} nests past the JSON domain depth bound`; return null; }
    const proto = Object.getPrototypeOf(v);
    if (v instanceof Uint8Array) {
      // a binary leaf is plain data ONLY as a bare byte container: the
      // base prototype, index keys alone, and no riders. What these checks
      // establish is a property of the CAPTURE, not of the input:
      // a Proxy over an extensible plain object whose getPrototypeOf trap
      // names Uint8Array.prototype passes both this test and `instanceof`,
      // so the input is not proved to be a real byte container. It does not
      // need to be. Every byte below is read from an OWN DATA DESCRIPTOR and
      // range-checked, and the bytes are copied into a fresh Uint8Array, so
      // whatever the input was, the value the consumer reads is a real byte
      // container carrying exactly the validated bytes.
      if (proto !== Uint8Array.prototype
        && !(typeof Buffer !== "undefined" && proto === Buffer.prototype)) {
        defect = `${label} carries a foreign prototype`; return null;
      }
      if (Object.getOwnPropertySymbols(v).length) { defect = `${label} carries a symbol-keyed rider on a binary leaf`; return null; }
      const names = Object.getOwnPropertyNames(v);
      for (const k of names) {
        if (!INDEX_RE.test(k)) { defect = `member ${label}.${k} rides on a binary leaf`; return null; }
      }
      // capture the bytes by reading each index through its OWN DESCRIPTOR,
      // never through the value: Uint8Array.from would read via
      // the iterator or index getters, which a Uint8Array-shaped Proxy can
      // trap to serve bytes the descriptor walk never validated. The index
      // names must be exactly 0..n-1 and every byte an own data value in
      // 0..255, so the copy IS the validated evidence.
      const bytes = new Uint8Array(names.length);
      for (const k of names) {
        const i = Number(k);
        if (i >= names.length) { defect = `member ${label}.${k} is a binary-leaf index past its length`; return null; }
        const dsc = Object.getOwnPropertyDescriptor(v, k);
        if (!dsc || !Object.prototype.hasOwnProperty.call(dsc, "value")) {
          defect = `member ${label}.${k} is an accessor-backed binary-leaf byte`; return null;
        }
        const b = dsc.value;
        if (typeof b !== "number" || !Number.isInteger(b) || b < 0 || b > 255) {
          defect = `member ${label}.${k} is not a byte value on a binary leaf`; return null;
        }
        bytes[i] = b;
      }
      const result = { h: 1, copy: bytes };
      done.set(v, result);
      return result;
    }
    path.add(v);
    let maxChild = 0;
    let copy = null;
    try {
      if (Array.isArray(v)) {
        if (proto !== Array.prototype) { defect = `${label} carries a foreign prototype`; return null; }
        copy = [];
        // the length is read from the array's OWN DATA DESCRIPTOR, never
        // through `v.length`: a Proxy get trap could otherwise
        // report a short length to hide a sparse hole, or throw an untyped
        // exception. The descriptor read is the same channel every member is
        // validated through.
        const lenDsc = Object.getOwnPropertyDescriptor(v, "length");
        if (!lenDsc || !Object.prototype.hasOwnProperty.call(lenDsc, "value")
          || typeof lenDsc.value !== "number" || !Number.isInteger(lenDsc.value) || lenDsc.value < 0) {
          defect = `${label} has no valid own array length descriptor`; return null;
        }
        const len = lenDsc.value;
        let indexCount = 0;
        for (const k of Reflect.ownKeys(v)) {
          if (k === "length") continue;
          if (typeof k === "symbol") { defect = `${label} carries a symbol-keyed member`; return null; }
          // a NAMED array member would vanish from canonical
          // serialization, and a sparse array would serialize holes it
          // does not carry: both are outside the JSON value domain. A
          // REAL index is an integer below length.
          if (!INDEX_RE.test(k) || Number(k) >= len) {
            defect = `${label} carries a named array member (${String(k)}), outside the JSON value domain`; return null;
          }
          indexCount += 1;
          const dsc = Object.getOwnPropertyDescriptor(v, k);
          // a Proxy may report a key through ownKeys yet return no
          // descriptor for it: that is not a stable data member
          if (!dsc) { defect = `member ${label}.${String(k)} has no own descriptor`; return null; }
          if (!Object.prototype.hasOwnProperty.call(dsc, "value")) {
            defect = `member ${label}.${String(k)} is accessor-backed`; return null;
          }
          if (!dsc.enumerable) { defect = `member ${label}.${String(k)} is non-enumerable (it would vanish from canonical comparison)`; return null; }
          const child = walk(dsc.value, `${label}.${String(k)}`);
          if (!child) return null;
          copy[Number(k)] = child.copy;
          if (child.h > maxChild) maxChild = child.h;
        }
        if (indexCount !== len) { defect = `${label} is a sparse array, outside the JSON value domain`; return null; }
        copy.length = len;
      } else {
        if (proto !== Object.prototype && proto !== null) {
          defect = `${label} carries a foreign prototype`; return null;
        }
        // the capture keeps a null prototype null, so the domain the walk
        // accepted is exactly the domain the consumer reads
        copy = proto === null ? Object.create(null) : {};
        for (const k of Reflect.ownKeys(v)) {
          if (typeof k === "symbol") { defect = `${label} carries a symbol-keyed member`; return null; }
          const dsc = Object.getOwnPropertyDescriptor(v, k);
          if (!dsc) { defect = `member ${label}.${String(k)} has no own descriptor`; return null; }
          if (!Object.prototype.hasOwnProperty.call(dsc, "value")) {
            defect = `member ${label}.${String(k)} is accessor-backed`; return null;
          }
          if (!dsc.enumerable) { defect = `member ${label}.${String(k)} is non-enumerable (it would vanish from canonical comparison)`; return null; }
          const child = walk(dsc.value, `${label}.${String(k)}`);
          if (!child) return null;
          copy[k] = child.copy;
          if (child.h > maxChild) maxChild = child.h;
        }
      }
    } finally {
      path.delete(v);
    }
    const result = { h: 1 + maxChild, copy };
    done.set(v, result);
    return result;
  };
  // the walk is TOTAL over adapter Proxies: a reflective trap
  // (ownKeys, getPrototypeOf, getOwnPropertyDescriptor and the rest the walk
  // uses as its capture channel) can THROW, which would otherwise escape as
  // the adapter's raw error rather than this module's plain-data refusal. Any
  // throw during validation is treated as unstable evidence and returned as a
  // defect, so the boundary refuses rather than propagating an untyped fault.
  let top;
  try {
    top = walk(root, "the value");
  } catch (_e) {
    // a FIXED message, never a read of the thrown value (a review catch,
    // hardened a review): the thrown value can itself be a null-prototype
    // object or carry a throwing `message` getter, so reading or
    // interpolating it would throw a second untyped fault out of the catch.
    // The identity of the thrown value is not needed to refuse.
    return { defect: "the value threw during plain-data validation (a reflective trap threw); a trap that throws is not stable evidence", value: undefined };
  }
  if (defect) return { defect, value: undefined };
  return { defect: null, value: top.copy };
};

// the defect-only predicate, kept for callers that validate without
// consuming the value. Returns the first defect as a string, or null.
const plainDataDefect = (root) => plainDataSnapshot(root).defect;

/**
 * One page under the literal contract. Returns
 * { status: "verified", documents, height, cursor } with cursor the last
 * returned document's identifier, or NULL on a terminal page (empty or
 * short); or passes through { status: "unserved" | "unverified" }.
 */
const provedQueryPage = async ({ contractId, type, where, orderBy,
  limit = 100, startAfter = null, fetchVerifiedPage }) => {
  if (typeof fetchVerifiedPage !== "function") refuse("provedQueryPage needs the injected fetchVerifiedPage");
  if (typeof type !== "string" || type.length === 0) refuse("provedQueryPage needs the document type");
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    refuse(`limit ${limit} is outside the contract's 1..100`);
  }
  if (startAfter !== null && (typeof startAfter !== "string" || !HEX64.test(startAfter))) {
    // the STRING requirement comes first: regular-expression
    // coercion would let a one-element array pass, and a null-prototype
    // value would throw instead of refusing
    refuse("startAfter must be null (the first call) or the previous page's last 64-hex document identifier");
  }
  // await TOTALLY: a page value resistant to property access, for
  // example a revoked Proxy the adapter's promise resolves, throws at the
  // language-level await before the envelope check runs; the guard converts
  // that into a plain refusal rather than an escaping raw fault
  let rawPage;
  try { rawPage = await fetchVerifiedPage({ contractId, type, where, orderBy, limit, startAfter }); }
  catch (e) { refuse(`the injected page fetch failed (${errText(e)}); an adapter fault is not evidence`); }
  // the WHOLE page envelope is validated as plain data AND CAPTURED before
  // any member is read (a review, capture added a review): the walk
  // reconstructs a plain-data copy from the descriptors it validates and
  // every read below is against that copy (`page`), never the injected
  // object, so a Proxy that reports a plain descriptor to the walk and
  // then serves a different value through its get trap cannot hand the
  // consumer an array the walk never saw
  // rawPage here is the AWAIT-RESOLVED value: a revoked proxy has already
  // been refused by the guarded await above, so Array.isArray cannot throw.
  if (!rawPage || typeof rawPage !== "object" || Array.isArray(rawPage)) {
    refuse("the injected page result must declare status verified, unserved or unverified");
  }
  const { defect: envelopeDefect, value: page } = plainDataSnapshot(rawPage);
  if (envelopeDefect) refuse(`the page result is not plain data (${envelopeDefect})`);
  if (!["verified", "unserved", "unverified"].includes(page.status)) {
    refuse("the injected page result must declare status verified, unserved or unverified");
  }
  // the page envelope is a DISCRIMINATED union with exactly ONE declared
  // optional member (a review, the declaration amended a review to match):
  // members outside the declared variant are contradictory shapes, and
  // "cursor" is the declared exception, permitted on a verified page and
  // IGNORED, because this checker computes its own cursor from the
  // documents (successive reviews gate that the adapter's member cannot
  // steer the walk).
  const allowedPage = page.status === "verified" ? ["status", "documents", "height", "cursor"] : ["status"];
  for (const k of Reflect.ownKeys(page)) {
    if (typeof k === "symbol" || !allowedPage.includes(k)) {
      refuse(`the ${page.status} page result carries ${String(k)}, outside its declared shape (a contradictory envelope)`);
    }
  }
  // the optional cursor is IGNORED for steering but still has to CONFORM
  //: admitting it as "any plain data" kept the no-steering
  // guarantee (this wrapper computes its own cursor) while giving up the
  // envelope-exactness one, so an adapter could return an object or array
  // where the transport's page shape has a document identifier and the
  // wrapper would accept the page without a word. An accepted envelope
  // should mean every member it carries has a defined grammar, so the
  // member is held to the same shape the wrapper's own cursor has: null,
  // or a 64-hex document identifier.
  if (Object.prototype.hasOwnProperty.call(page, "cursor")
    && page.cursor !== null
    && (typeof page.cursor !== "string" || !HEX64.test(page.cursor))) {
    refuse("a verified page's cursor member must be null or a 64-hex document identifier (it is ignored for pagination, but an accepted envelope conforms)");
  }
  if (page.status !== "verified") return { status: page.status };
  if (!Array.isArray(page.documents) || page.documents.length > limit) {
    refuse("a verified page carries a document array no longer than its limit");
  }
  if (typeof page.height !== "string" || !DEC_RE.test(page.height)) {
    refuse("a verified page carries its authenticated height as a canonical decimal string (an EMPTY verified page included)");
  }
  let prev = startAfter;
  for (const d of page.documents) {
    // the envelope walk above already established every document as
    // plain data before any member read (a review hoisted the check)
    if (!d || typeof d.id !== "string" || !HEX64.test(d.id)) {
      refuse("every returned document carries its 64-hex identifier");
    }
    // the page itself honors the ordered exclusive-cursor contract:
    // strictly ascending, every identifier ABOVE the cursor
    if (prev !== null && d.id <= prev) {
      refuse(`the page's identifiers are not strictly ascending above the cursor at ${d.id} (a repeated document or a cursor regression breaks the no-progress rule)`);
    }
    prev = d.id;
  }
  const terminal = page.documents.length < limit;
  return { status: "verified", documents: page.documents, height: page.height,
    cursor: terminal ? null : page.documents[page.documents.length - 1].id };
};

/**
 * The full enumeration. Returns
 *   { status: "proved", documents, heightMin, heightMax, pages }
 * with the min-to-max reduction over EVERY verified page's height, or
 *   { status: "unproved" }
 * with NO partial documents and NO partial range when any page is
 * unserved or unverified.
 */
const enumerateProved = async ({ contractId, type, where, orderBy, limit = 100,
  fetchVerifiedPage }) => {
  const documents = [];
  let heightMin = null, heightMax = null, pages = 0;
  let startAfter = null;
  for (;;) {
    const page = await provedQueryPage({ contractId, type, where, orderBy, limit,
      startAfter, fetchVerifiedPage });
    if (page.status !== "verified") return { status: "unproved" };
    pages += 1;
    const h = BigInt(page.height);
    if (heightMin === null || h < BigInt(heightMin)) heightMin = page.height;
    if (heightMax === null || h > BigInt(heightMax)) heightMax = page.height;
    for (const d of page.documents) {
      // the page checker's envelope walk already established every
      // document as plain data before any member read, and
      // strict ascent across the WHOLE enumeration is the page checker's
      // guarantee too: each page proves its identifiers
      // strictly ascending above its exclusive cursor, and the cursor is
      // COMPUTED from the page's own last identifier (never
      // adapter-supplied), so page-local ascent composes into
      // whole-enumeration ascent
      documents.push(d);
    }
    if (page.cursor === null) {
      return { status: "proved", documents, heightMin, heightMax, pages };
    }
    // a cursor equal to startAfter is unreachable here: the cursor is the
    // last returned document's identifier and a document equal to the
    // exclusive start-after already refused above (one guard, not two)
    startAfter = page.cursor;
  }
};

// plainDataDefect is used internally and consumed by nothing; plainDataSnapshot,
// which carries the same answer plus the path, is what callers actually read
module.exports = { provedQueryPage, enumerateProved, plainDataSnapshot };
