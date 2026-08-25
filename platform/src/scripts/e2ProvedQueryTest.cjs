/**
 * Offline battery for the proved-enumeration wrapper (plain `node`, no
 * network): the literal page contract (limit bounds, cursor grammar, the
 * terminal rule on empty and short pages, the empty verified page's
 * height), the min-to-max height reduction over EVERY verified page, the
 * no-progress refusals, and the whole-enumeration UNPROVED rule on an
 * unserved or unverified page with no partial range claimed.
 * Expectations are derived from the frozen contract's own sentences;
 * synthetic pages are built by a ledger closure the tests parameterize.
 */
const { provedQueryPage, enumerateProved, plainDataSnapshot } = require("./e2ProvedQuery.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) { passed++; } else { failed++; console.error("FAIL:", name); } };
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

const id = (n) => n.toString(16).padStart(2, "0").repeat(32);
const docs = (from, count) => Array.from({ length: count }, (_, i) => ({ id: id(from + i), n: from + i }));

// a synthetic verified ledger of `total` documents with per-page heights
// drawn from the given sequence (heights differ across pages on purpose:
// pages proving at different platform states is the reality the range
// reports)
const ledger = (total, heights, log) => {
  let calls = 0;
  return async ({ limit, startAfter }) => {
    const start = startAfter === null ? 0
      : parseInt(startAfter.slice(0, 2), 16) + 1;
    if (log) log.push(start);
    const page = docs(start, Math.max(0, Math.min(limit, total - start)));
    const height = heights[Math.min(heights.length - 1, calls)];
    calls += 1;
    return { status: "verified", documents: page, height };
  };
};

(async () => {
  // ---- the page contract ----
  {
    const p = await provedQueryPage({ type: "receipt", limit: 3, startAfter: null,
      fetchVerifiedPage: ledger(2, ["70"]) });
    ok("a short page is terminal with a null cursor",
      p.status === "verified" && p.documents.length === 2 && p.cursor === null && p.height === "70");
  }
  {
    const p = await provedQueryPage({ type: "receipt", limit: 2, startAfter: null,
      fetchVerifiedPage: ledger(5, ["70"]) });
    ok("a full page's cursor is the LAST returned document's identifier",
      p.cursor === id(1) && p.documents.length === 2);
  }
  {
    const p = await provedQueryPage({ type: "receipt", limit: 4, startAfter: null,
      fetchVerifiedPage: async () => ({ status: "verified", documents: [], height: "55" }) });
    ok("an EMPTY verified page is terminal and still returns its authenticated height",
      p.status === "verified" && p.documents.length === 0 && p.cursor === null && p.height === "55");
  }
  for (const status of ["unserved", "unverified"]) {
    const p = await provedQueryPage({ type: "receipt", limit: 4, startAfter: null,
      fetchVerifiedPage: async () => ({ status }) });
    ok(`an ${status} page passes its status through`, p.status === status);
  }
  await rejects("limit 0 refuses (the contract's 1..100)",
    provedQueryPage({ type: "receipt", limit: 0, startAfter: null,
      fetchVerifiedPage: ledger(1, ["1"]) }), /outside the contract's 1\.\.100/);
  await rejects("limit 101 refuses",
    provedQueryPage({ type: "receipt", limit: 101, startAfter: null,
      fetchVerifiedPage: ledger(1, ["1"]) }), /outside the contract's 1\.\.100/);
  await rejects("a malformed startAfter refuses",
    provedQueryPage({ type: "receipt", limit: 4, startAfter: "xyz",
      fetchVerifiedPage: ledger(1, ["1"]) }), /64-hex document identifier/);
  await rejects("a missing document type refuses",
    provedQueryPage({ limit: 4, startAfter: null, fetchVerifiedPage: ledger(1, ["1"]) }),
    /document type/);
  await rejects("a verified page without a canonical decimal height refuses",
    provedQueryPage({ type: "receipt", limit: 4, startAfter: null,
      fetchVerifiedPage: async () => ({ status: "verified", documents: [], height: 55 }) }),
    /canonical decimal string/);
  await rejects("a verified page longer than its limit refuses",
    provedQueryPage({ type: "receipt", limit: 2, startAfter: null,
      fetchVerifiedPage: async () => ({ status: "verified", documents: docs(0, 3), height: "1" }) }),
    /no longer than its limit/);
  await rejects("a document without its 64-hex id refuses",
    provedQueryPage({ type: "receipt", limit: 2, startAfter: null,
      fetchVerifiedPage: async () => ({ status: "verified", documents: [{ n: 1 }], height: "1" }) }),
    /64-hex identifier/);
  await rejects("an undeclared page status refuses",
    provedQueryPage({ type: "receipt", limit: 2, startAfter: null,
      fetchVerifiedPage: async () => ({ documents: [], height: "1" }) }),
    /declare status/);

  // ---- the enumeration ----
  {
    const log = [];
    const r = await enumerateProved({ type: "receipt", limit: 2,
      fetchVerifiedPage: ledger(5, ["70", "72", "68"], log) });
    ok("the enumeration walks exclusive cursors to the terminal short page",
      r.status === "proved" && r.documents.length === 5 && r.pages === 3
      && log.join(",") === "0,2,4");
    ok("every document arrives exactly once, by identity",
      r.documents.every((d, i) => d.id === id(i)));
    ok("the height range is the min-to-max over EVERY page, terminal included",
      r.heightMin === "68" && r.heightMax === "72");
  }
  {
    // depth beyond the earlier three-page worlds (round-60): a walk that
    // treated some later full page as terminal would truncate silently,
    // so this gate enumerates NINE documents at limit 2, four full pages
    // and a terminal short fifth
    // EVERY page's height PARTICIPATES, which an aggregate can only observe
    // when each page carries an extreme of its own (round-62): with heights
    // whose extremes all sat on early pages, dropping a later page from the
    // reduction left the aggregate unchanged and went unnoticed. Here page 4
    // owns the maximum and page 5 owns the minimum, so omitting either is
    // visible in the result.
    const log = [];
    const r = await enumerateProved({ type: "receipt", limit: 2,
      fetchVerifiedPage: ledger(9, ["70", "72", "71", "75", "68"], log) });
    ok("a five-page enumeration collects all nine documents across its five pages (a bound, not unboundedness)",
      r.status === "proved" && r.documents.length === 9 && r.pages === 5
      && log.join(",") === "0,2,4,6,8"
      && r.documents.every((d, i) => d.id === id(i)));
    ok("the reduction takes its maximum from the FOURTH page and its minimum from the FIFTH",
      r.heightMin === "68" && r.heightMax === "75");
    // min and max are two extremes over five pages, so ONE fixture can never
    // make every page's participation observable: whichever pages own no
    // extreme can be dropped from the reduction with no visible effect. So
    // each page is pinned in turn, by a run in which THAT page carries the
    // unique maximum (round-62).
    for (let p = 1; p <= 5; p++) {
      const heights = ["70", "70", "70", "70", "70"];
      heights[p - 1] = "90";
      const rp = await enumerateProved({ type: "receipt", limit: 2,
        fetchVerifiedPage: ledger(9, heights) });
      ok(`page ${p}'s height enters the reduction (it carries the run's unique maximum)`,
        rp.status === "proved" && rp.pages === 5 && rp.heightMax === "90" && rp.heightMin === "70");
    }
    // and again for the MINIMUM, which is a separate reduction (round-63):
    // the unique-maximum runs above leave every other page at the same
    // height, so a minimum updated on only some pages still reports 70 and
    // survives them all. Each page carries the unique minimum in turn.
    for (let p = 1; p <= 5; p++) {
      const heights = ["70", "70", "70", "70", "70"];
      heights[p - 1] = "50";
      const rp = await enumerateProved({ type: "receipt", limit: 2,
        fetchVerifiedPage: ledger(9, heights) });
      ok(`page ${p}'s height enters the MINIMUM reduction (it carries the run's unique minimum)`,
        rp.status === "proved" && rp.pages === 5 && rp.heightMin === "50" && rp.heightMax === "70");
    }
  }
  {
    // a Date is a class-carried value: admitting it as a special case
    // would silently widen the declared base-prototype domain (round-60)
    await rejects("a Date leaf inside a document is not plain data",
      provedQueryPage({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [{ id: "01".repeat(32), at: new Date(0) }], cursor: null }) }),
      /not plain data/);
    // a Proxy over a CLASS INSTANCE whose getPrototypeOf trap reports
    // Object.prototype passes the prototype test, and that is not a defect
    // (round-62): the walk cannot decide what the input really is, and the
    // property it establishes is about the CAPTURE. So the capture must be
    // an ordinary plain object carrying exactly the validated members, with
    // no trace of the class, and the consumer must read THAT.
    class Foreign { constructor() { this.x = 1; } get trap() { return "never read"; } }
    const lying = new Proxy(new Foreign(), { getPrototypeOf: () => Object.prototype });
    const snap = plainDataSnapshot({ id: "01".repeat(32), nested: lying });
    ok("a prototype-reporting Proxy over a class instance yields an ORDINARY plain-object capture",
      snap.defect === null
      && Object.getPrototypeOf(snap.value.nested) === Object.prototype
      && !(snap.value.nested instanceof Foreign)
      && snap.value.nested.x === 1
      && Object.keys(snap.value.nested).join(",") === "x");
  }
  {
    // an ordinary rejection whose `message` getter itself throws: the
    // total formatter must still produce a plain refusal rather than let
    // the getter's throw replace the refusal (round-60)
    await rejects("a fetch rejection with a throwing message getter still refuses plainly",
      provedQueryPage({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => {
          const e = {};
          Object.defineProperty(e, "message", { get() { throw new Error("the message read must not decide this"); } });
          throw e; } }),
      /page fetch failed/);
  }
  {
    // the PLAIN-DATA boundary per enumerated document: a class instance
    // or an accessor-backed document refuses the enumeration
    class Row { constructor(i) { this._i = i; } get id() { return String(this._i).padStart(64, "0"); } }
    await rejects("an enumerated class-instance document refuses (a foreign prototype is not plain data)",
      enumerateProved({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [new Row(1)], cursor: null }) }),
      /foreign prototype/);
    const gd = { id: "0".repeat(63) + "1" };
    Object.defineProperty(gd, "poolId", { get: () => "x", enumerable: true, configurable: true });
    await rejects("an enumerated accessor-backed document refuses",
      enumerateProved({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [gd], cursor: null }) }),
      /accessor-backed/);
    // NO member is read before the boundary check, the identifier
    // included: a counting getter must never fire
    let reads = 0;
    const spy = {};
    Object.defineProperty(spy, "id", { enumerable: true, configurable: true,
      get: () => { reads += 1; return "01".repeat(32); } });
    await rejects("a getter-backed identifier refuses",
      enumerateProved({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [spy], cursor: null }) }),
      /accessor-backed/);
    ok("the boundary check runs before ANY member read (the identifier getter never fired)",
      reads === 0);
    // the PAGE-LEVEL check is its own gate: a direct provedQueryPage
    // call refuses before any member read too
    let pageReads = 0;
    const pageSpy = {};
    Object.defineProperty(pageSpy, "id", { enumerable: true, configurable: true,
      get: () => { pageReads += 1; return "01".repeat(32); } });
    await rejects("provedQueryPage refuses an accessor-backed document directly",
      provedQueryPage({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [pageSpy], cursor: null }) }),
      /accessor-backed/);
    ok("the page-level check fires before ANY member read (the direct getter never fired)",
      pageReads === 0);
    // EVERY document on the page is checked, not only the first
    let tailReads = 0;
    const tailSpy = {};
    Object.defineProperty(tailSpy, "id", { enumerable: true, configurable: true,
      get: () => { tailReads += 1; return "02".repeat(32); } });
    await rejects("a getter-backed SECOND document refuses the page too",
      provedQueryPage({ type: "receipt", limit: 3,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [{ id: "01".repeat(32) }, tailSpy], cursor: null }) }),
      /accessor-backed/);
    ok("the second document's getter never fired either", tailReads === 0);
    // EVERY document, middle positions included: plain first and last,
    // a counting getter in the MIDDLE
    let midReads = 0;
    const midSpy = {};
    Object.defineProperty(midSpy, "id", { enumerable: true, configurable: true,
      get: () => { midReads += 1; return "02".repeat(32); } });
    await rejects("a getter-backed MIDDLE document refuses the page too",
      provedQueryPage({ type: "receipt", limit: 4,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [{ id: "01".repeat(32) }, midSpy, { id: "03".repeat(32) }], cursor: null }) }),
      /accessor-backed/);
    ok("the middle document's getter never fired", midReads === 0);
    // the page envelope is a DISCRIMINATED union too (round-40)
    await rejects("an unverified page carrying documents and a height is a contradictory envelope",
      provedQueryPage({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "unverified",
          documents: [{ id: "01".repeat(32) }], height: "70" }) }),
      /contradictory envelope/);
    // the PAGE ENVELOPE validates before any member read (round-41)
    let heightReads = 0;
    const spyPage = { status: "verified", documents: [{ id: "01".repeat(32) }], cursor: null };
    Object.defineProperty(spyPage, "height", { enumerable: true, configurable: true,
      get: () => { heightReads += 1; return "70"; } });
    await rejects("an accessor-backed page height refuses the whole page",
      provedQueryPage({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => spyPage }),
      /not plain data/);
    ok("the page height getter never fired", heightReads === 0);
    // A PROXY DEFEATS validate-then-reread, so the wrapper must
    // validate-and-CAPTURE (round-53, finding 1): a Proxy reports a plain
    // data descriptor for `documents` to the walk (which reads
    // descriptors, not the get trap) and then serves a DIFFERENT array
    // through its get trap. A wrapper that re-read `page.documents` after
    // validating would hand back the divergent array the walk never saw; a
    // wrapper that reads only the captured copy returns the validated one.
    // The property under test is that the RETURNED documents are the ones
    // the walk validated, so a later get-trap divergence cannot substitute
    // unchecked evidence.
    {
      const goodId = "a".repeat(64), badId = "b".repeat(64);
      const target = { status: "verified", documents: [{ id: goodId }], height: "5" };
      let docGetTrap = 0;
      const proxyPage = new Proxy(target, { get(t, k, r) {
        if (k === "documents") { docGetTrap += 1; return [{ id: badId }]; }
        return Reflect.get(t, k, r);
      } });
      const captured = await provedQueryPage({ type: "receipt", limit: 2, startAfter: null,
        fetchVerifiedPage: async () => proxyPage });
      ok("a Proxy page that diverges through its get trap yields the CAPTURED documents, never the divergent value",
        captured.status === "verified" && captured.documents.length === 1
        && captured.documents[0].id === goodId && captured.cursor === null);
      // the same divergence carried through the full enumeration: the
      // proved documents are the validated ones, not the get-trap array
      const proxyTarget2 = { status: "verified", documents: [{ id: goodId }], height: "5" };
      const proxyPage2 = new Proxy(proxyTarget2, { get(t, k, r) {
        if (k === "documents") return [{ id: badId }];
        return Reflect.get(t, k, r);
      } });
      const en = await enumerateProved({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => proxyPage2 });
      ok("enumerateProved returns the captured documents under a get-trap divergence",
        en.status === "proved" && en.documents.length === 1 && en.documents[0].id === goodId);
    }
    {
      // a BINARY LEAF must be captured from its own byte descriptors, not
      // read through the value (round-54): Uint8Array.from would consult the
      // iterator or index getters, which a Uint8Array-shaped Proxy can trap
      // to serve bytes the descriptor walk never validated. The captured
      // bytes must be the descriptor bytes.
      const target = new Uint8Array([1]);
      const proxyBin = new Proxy(target, { get(t, k, r) {
        if (k === Symbol.iterator) return function*() { yield 9; };
        return Reflect.get(t, k, r);
      } });
      const snap = plainDataSnapshot(proxyBin);
      ok("a binary-leaf Proxy is captured from its byte descriptors, not its iterator trap",
        snap.defect === null && snap.value instanceof Uint8Array
        && snap.value.length === 1 && snap.value[0] === 1);
      // a real binary leaf still round-trips its bytes
      const plain = plainDataSnapshot({ id: "aa", chunk: Uint8Array.from([7, 8, 255]) });
      ok("an ordinary binary leaf is captured byte-for-byte",
        plain.defect === null && Array.from(plain.value.chunk).join(",") === "7,8,255");
      // an accessor-backed byte on a binary-leaf-shaped object refuses
      const badByte = Object.create(Uint8Array.prototype);
      Object.defineProperty(badByte, "0", { enumerable: true, configurable: true, get: () => 5 });
      const snapBad = plainDataSnapshot(badByte);
      ok("an accessor-backed binary-leaf byte refuses",
        typeof snapBad.defect === "string" && /binary-leaf/.test(snapBad.defect));
    }
    {
      // the ARRAY length must be read from the own descriptor, not through
      // the value (round-55): a Proxy get trap that reports a short length
      // could otherwise hide a sparse hole, and a throwing length trap must
      // not escape as an untyped exception.
      const sparse = [10]; sparse.length = 2; // [10, <hole>], real length 2
      const lyingProxy = new Proxy(sparse, { get(t, k, r) {
        if (k === "length") return 1; return Reflect.get(t, k, r);
      } });
      const snap = plainDataSnapshot(lyingProxy);
      ok("a Proxy that reports a short length to hide a sparse hole is refused as sparse",
        typeof snap.defect === "string" && /sparse array/.test(snap.defect));
      const throwingLen = new Proxy([1, 2], { get(t, k, r) {
        if (k === "length") throw new Error("length trap"); return Reflect.get(t, k, r);
      } });
      const snap2 = plainDataSnapshot(throwingLen);
      ok("a throwing length get-trap does not escape: the own descriptor is read and the array is captured",
        snap2.defect === null && Array.from(snap2.value).join(",") === "1,2");
      // the object-branch symbol-key check is observed HERE, in the walk
      // itself, not only downstream where canonicalString also rejects
      // symbol keys: a symbol-keyed member on a plain object (an enumerated
      // document, an answer) never reaches canonicalString, so the walk must
      // refuse it directly (round-55).
      const symSnap = plainDataSnapshot({ id: "aa", [Symbol("x")]: 1 });
      ok("a symbol-keyed member on a plain object is refused by the walk itself",
        typeof symSnap.defect === "string" && /symbol-keyed member/.test(symSnap.defect));
      // the walk is TOTAL over throwing reflective traps (round-56): a Proxy
      // whose ownKeys, getPrototypeOf or getOwnPropertyDescriptor trap throws
      // must yield a plain-data DEFECT, never escape as the adapter's raw
      // error. The reflective ops are the capture channel, so each is guarded.
      // the thrown value itself may be UNREADABLE (round-57): a null-prototype
      // object or a throwing `message` getter must not make the catch handler
      // throw a second fault, so it reads none of the thrown value.
      const unreadableErr = {}; Object.defineProperty(unreadableErr, "message", { get() { throw new Error("m"); } });
      for (const [name, trap] of [
        ["ownKeys(Error)", { ownKeys() { throw new Error("k"); } }],
        ["getPrototypeOf(Error)", { getPrototypeOf() { throw new Error("p"); } }],
        ["getOwnPropertyDescriptor(Error)", { getOwnPropertyDescriptor() { throw new Error("d"); } }],
        ["ownKeys(null-proto throw)", { ownKeys() { throw Object.create(null); } }],
        ["ownKeys(throwing-message throw)", { ownKeys() { throw unreadableErr; } }]]) {
        let threw = false, snap;
        try { snap = plainDataSnapshot(new Proxy({ id: "aa" }, trap)); } catch { threw = true; }
        ok(`a throwing ${name} trap yields a defect, never an escaping throw`,
          !threw && snap && typeof snap.defect === "string" && /threw during plain-data validation/.test(snap.defect));
      }
      // a REVOKED Proxy resolved by the page fetch is refused, not escaped
      // (round-57): the await unwrap and the Array.isArray classification both
      // throw on a revoked proxy, so both are guarded.
      const rev = Proxy.revocable({ status: "verified" }, {}); rev.revoke();
      let pageErr = null;
      try { await provedQueryPage({ type: "x", startAfter: null, fetchVerifiedPage: async () => rev.proxy }); }
      catch (e) { pageErr = e; }
      // the assertion requires the MODULE's own refusal (its prefix and fixed
      // adapter-fault text) and that the escaping native TypeError did NOT
      // reach the caller (round-58): a looser match would pass on the raw
      // revoked-proxy TypeError the guard is meant to convert.
      ok("a revoked-proxy page is CONVERTED to the module's plain adapter-fault refusal, not the raw native TypeError",
        pageErr instanceof Error && !(pageErr instanceof TypeError)
        && /^e2ProvedQuery: the injected page fetch failed/.test(pageErr.message));
      // an ORDINARY page-fetch rejection keeps its real cause, not a false
      // "resistant to inspection" message (round-59, F4)
      let ordErr = null;
      try { await provedQueryPage({ type: "x", startAfter: null,
        fetchVerifiedPage: async () => { throw new Error("Platform endpoint unavailable"); } }); }
      catch (e) { ordErr = e; }
      ok("an ordinary page-fetch rejection is refused with its REAL cause preserved",
        ordErr instanceof Error && /Platform endpoint unavailable/.test(ordErr.message)
        && /the injected page fetch failed/.test(ordErr.message));
    }
    // the JSON VALUE DOMAIN is enforced throughout the graph (round-43)
    // the combined named-plus-hole array and the cycle (round-44)
    await rejects("a high decimal name compensating a hole is a named member, not an index",
      provedQueryPage({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [{ id: "01".repeat(32),
            tags: (() => { const a = []; a.length = 2; a[0] = "x"; a["4294967295"] = "rider"; return a; })() }],
          cursor: null }) }),
      /named array member/);
    await rejects("a cyclic document is outside the JSON value domain",
      provedQueryPage({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => { const doc = { id: "01".repeat(32) }; doc.self = doc;
          return { status: "verified", height: "70", documents: [doc], cursor: null }; } }),
      /closes a cycle/);
    // a wrong ADAPTER cursor on a full page is ignored: the checker
    // computes its own from the page's last document (round-44)
    const cursorLog = [];
    const rCur = await enumerateProved({ type: "receipt", limit: 2,
      fetchVerifiedPage: async (q) => { cursorLog.push(q.startAfter);
        return q.startAfter === null
          ? { status: "verified", height: "70",
            documents: [{ id: "01".repeat(32) }, { id: "02".repeat(32) }], cursor: "ff".repeat(32) }
          : { status: "verified", height: "70", documents: [], cursor: null }; } });
    ok("the checker's cursor comes from the last document, never the adapter's member",
      rCur.status === "proved" && cursorLog.length === 2 && cursorLog[1] === "02".repeat(32));
    // a LOW adapter cursor is ignored the same way (round-45): the next
    // request still advances past the last collected identifier
    const lowLog = [];
    const rLow = await enumerateProved({ type: "receipt", limit: 2,
      fetchVerifiedPage: async (q) => { lowLog.push(q.startAfter);
        return q.startAfter === null
          ? { status: "verified", height: "70",
            documents: [{ id: "01".repeat(32) }, { id: "02".repeat(32) }], cursor: "01".repeat(32) }
          : { status: "verified", height: "70", documents: [], cursor: null }; } });
    ok("a LOW adapter cursor cannot rewind the walk (no identifier repeats)",
      rLow.status === "proved" && rLow.documents.length === 2
      && lowLog[1] === "02".repeat(32));
    // the ignored cursor still has to CONFORM (round-63): being unread for
    // steering is not a licence to be any shape at all, or an accepted
    // envelope stops meaning that every member it carries has a grammar
    for (const [what, bad] of [["an object", { malformed: true }],
      ["an array", ["01".repeat(32)]], ["a number", 7],
      ["a short string", "01"], ["an uppercase identifier", "AB".repeat(32)],
      ["a boolean", false]]) {
      await rejects(`a verified page whose ignored cursor is ${what} refuses`,
        provedQueryPage({ type: "receipt", limit: 2,
          fetchVerifiedPage: async () => ({ status: "verified", height: "70",
            documents: [{ id: "01".repeat(32) }], cursor: bad }) }),
        /cursor member must be null or a 64-hex document identifier/);
    }
    const okCursor = await provedQueryPage({ type: "receipt", limit: 2,
      fetchVerifiedPage: async () => ({ status: "verified", height: "70",
        documents: [{ id: "01".repeat(32) }], cursor: "ff".repeat(32) }) });
    ok("a CONFORMING ignored cursor is accepted and still does not steer",
      okCursor.status === "verified" && okCursor.cursor === null);
    // the depth bound refuses past 512 levels, and a SHARED subtree
    // still passes (sharing expands under serialization; only cycles
    // and excessive depth refuse) (round-45)
    const mkDeep = (L) => { const d = { id: "01".repeat(32) };
      let cur = d; for (let i = 0; i < L; i++) { cur.next = {}; cur = cur.next; } return d; };
    // the boundary is EXACT (round-46): 510 nested levels pass (the
    // page envelope and document array occupy the first path slots) and
    // 511 refuse
    const okDeep = await provedQueryPage({ type: "receipt", limit: 2,
      fetchVerifiedPage: async () => ({ status: "verified", height: "70",
        documents: [mkDeep(510)], cursor: null }) });
    ok("a document at the depth bound passes", okDeep.status === "verified");
    await rejects("a document one level past the depth bound refuses",
      provedQueryPage({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [mkDeep(511)], cursor: null }) }),
      /depth bound/);
    const shared = { a: 1 };
    const okShared = await provedQueryPage({ type: "receipt", limit: 2,
      fetchVerifiedPage: async () => ({ status: "verified", height: "70",
        documents: [{ id: "01".repeat(32), left: shared, right: shared }], cursor: null }) });
    ok("a shared acyclic subtree passes the walker", okShared.status === "verified");
    // sharing cannot get past the bound (round-47): a subtree first seen
    // shallow still counts its full expansion when referenced deep
    const subtree = {};
    { let cur = subtree; for (let i = 0; i < 300; i++) { cur.next = {}; cur = cur.next; } }
    const prefix = {};
    { let cur = prefix; for (let i = 0; i < 300; i++) { cur.down = {}; cur = cur.down; } cur.tail = subtree; }
    await rejects("a deep reference to a shallow-seen shared subtree still refuses past the bound",
      provedQueryPage({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [{ id: "01".repeat(32), shallow: subtree, deep: prefix }], cursor: null }) }),
      /depth bound/);
    // the SHARED-reuse boundary is exact too (round-48): the same
    // shape passes at a 208-level prefix and refuses at 209
    const mkShared = (L) => { const sub48 = {};
      { let c = sub48; for (let i = 0; i < 300; i++) { c.next = {}; c = c.next; } }
      const pre = {};
      { let c = pre; for (let i = 0; i < L; i++) { c.down = {}; c = c.down; } c.tail = sub48; }
      return { id: "01".repeat(32), shallow: sub48, deep: pre }; };
    const okAt = await provedQueryPage({ type: "receipt", limit: 2,
      fetchVerifiedPage: async () => ({ status: "verified", height: "70",
        documents: [mkShared(208)], cursor: null }) });
    ok("a shared reuse exactly at the bound passes", okAt.status === "verified");
    // a NULL-PROTOTYPE identifier is plain data at the boundary yet no
    // string: the identifier check must refuse it, never crash in the
    // regular expression's coercion (round-49)
    for (const [what, bad] of [["a one-element array cursor", ["01".repeat(32)]],
      ["a null-prototype cursor", Object.create(null)]]) {
      await rejects(`${what} refuses through the declared startAfter path`,
        provedQueryPage({ type: "receipt", limit: 2, startAfter: bad,
          fetchVerifiedPage: async () => ({ status: "verified", height: "70",
            documents: [], cursor: null }) }),
        /startAfter must be null/);
    }
    await rejects("a null-prototype document identifier refuses through the declared path",
      provedQueryPage({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [{ id: Object.create(null) }], cursor: null }) }),
      /64-hex identifier/);
    await rejects("a shared reuse one level past the bound refuses",
      provedQueryPage({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [mkShared(209)], cursor: null }) }),
      /depth bound/);
    for (const [what, doc, re] of [
      ["a named array member", { id: "01".repeat(32), tags: Object.assign(["a"], { rider: "x" }) }, /named array member/],
      ["a sparse array", { id: "01".repeat(32), tags: (() => { const a = []; a[2] = "x"; return a; })() }, /sparse array/],
      ["an undefined leaf", { id: "01".repeat(32), gap: undefined }, /undefined, outside the JSON value domain/],
      ["a non-finite number", { id: "01".repeat(32), n: Infinity }, /non-finite number/],
      ["a bigint leaf", { id: "01".repeat(32), n: 5n }, /bigint, outside the JSON value domain/],
      ["a symbol leaf", { id: "01".repeat(32), sym: Symbol("x") }, /symbol, outside the JSON value domain/],
    ]) {
      await rejects(`${what} in a document is outside the JSON value domain`,
        provedQueryPage({ type: "receipt", limit: 2,
          fetchVerifiedPage: async () => ({ status: "verified", height: "70",
            documents: [doc], cursor: null }) }),
        re);
    }
    // the PAGE itself honors the ordered exclusive-cursor contract
    await rejects("a page internally descending refuses at the page level",
      provedQueryPage({ type: "receipt", limit: 3, startAfter: null,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [{ id: "10".repeat(32) }, { id: "05".repeat(32) }], cursor: null }) }),
      /not strictly ascending above the cursor/);
    await rejects("a page whose identifiers sit at or below the exclusive cursor refuses at the page level",
      provedQueryPage({ type: "receipt", limit: 3, startAfter: "20".repeat(32),
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [{ id: "10".repeat(32) }], cursor: null }) }),
      /not strictly ascending above the cursor/);
    await rejects("a document carrying a function member refuses (a function is not plain data)",
      enumerateProved({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [{ id: "01".repeat(32), helper() {} }], cursor: null }) }),
      /is a function/);
    const bytes = new Uint8Array(2);
    Object.defineProperty(bytes, "probe", { enumerable: true, configurable: true, value: 7 });
    await rejects("a byte container with a rider member refuses (a binary leaf must be bare)",
      enumerateProved({ type: "receipt", limit: 2,
        fetchVerifiedPage: async () => ({ status: "verified", height: "70",
          documents: [{ id: "01".repeat(32), blob: bytes }], cursor: null }) }),
      /rides on a binary leaf/);
  }
  {
    // a total that lands exactly on a page boundary: the next page is
    // EMPTY and terminal, and its height still enters the reduction
    const r = await enumerateProved({ type: "receipt", limit: 2,
      fetchVerifiedPage: ledger(4, ["50", "60", "40"]) });
    ok("a boundary-aligned enumeration ends on the empty page with its height in the range",
      r.status === "proved" && r.documents.length === 4 && r.pages === 3
      && r.heightMin === "40" && r.heightMax === "60");
  }
  {
    // each bound owed to a DIFFERENT non-terminal page: the first page
    // holds the maximum, the middle page the minimum
    const r = await enumerateProved({ type: "receipt", limit: 2,
      fetchVerifiedPage: ledger(5, ["90", "10", "50"]) });
    ok("the first page's height can own a bound (every page enters the reduction)",
      r.heightMin === "10" && r.heightMax === "90");
  }
  {
    const r = await enumerateProved({ type: "receipt", limit: 3,
      fetchVerifiedPage: async () => ({ status: "verified", documents: [], height: "9" }) });
    ok("an empty enumeration is proved with a single-page range",
      r.status === "proved" && r.documents.length === 0 && r.heightMin === "9" && r.heightMax === "9");
  }
  {
    // an unverified page ANYWHERE makes the whole enumeration UNPROVED
    // with no partial documents and no partial range claimed
    let call = 0;
    const flaky = async (args) => {
      call += 1;
      if (call === 2) return { status: "unverified" };
      return ledger(5, ["70"])(args);
    };
    const r = await enumerateProved({ type: "receipt", limit: 2, fetchVerifiedPage: flaky });
    ok("a later unverified page makes the WHOLE enumeration unproved, nothing partial (the exact shape)",
      r.status === "unproved" && Object.keys(r).length === 1);
    let call2 = 0;
    const flaky2 = async (args) => {
      call2 += 1;
      if (call2 === 2) return { status: "unserved" };
      return ledger(5, ["70"])(args);
    };
    const r2 = await enumerateProved({ type: "receipt", limit: 2, fetchVerifiedPage: flaky2 });
    ok("a later UNSERVED page is the same whole-enumeration unproved shape",
      r2.status === "unproved" && Object.keys(r2).length === 1);
  }
  {
    const r = await enumerateProved({ type: "receipt", limit: 2,
      fetchVerifiedPage: async () => ({ status: "unserved" }) });
    ok("an unserved first page is unproved", r.status === "unproved");
  }
  await rejects("a repeated document refuses (the no-progress rule)",
    enumerateProved({ type: "receipt", limit: 2,
      fetchVerifiedPage: async () => ({ status: "verified", documents: docs(0, 2), height: "1" }) }),
    /repeated document/);
  await rejects("a page echoing its exclusive start-after refuses",
    enumerateProved({ type: "receipt", limit: 2,
      fetchVerifiedPage: async ({ startAfter }) => ({ status: "verified",
        documents: startAfter === null ? docs(0, 2) : [{ id: startAfter }, docs(5, 1)[0]],
        height: "1" }) }),
    /no-progress rule|repeated document/);
  await rejects("a cursor REGRESSION refuses even with all-distinct identifiers",
    enumerateProved({ type: "receipt", limit: 2,
      fetchVerifiedPage: async ({ startAfter }) => ({ status: "verified",
        documents: startAfter === null ? [{ id: id(16) }, { id: id(32) }]
          : startAfter === id(32) ? [{ id: id(48) }, { id: id(5) }] : [],
        height: "1" }) }),
    /strictly ascending/);
  await rejects("a cross-page regression refuses even when each page is internally ascending",
    enumerateProved({ type: "receipt", limit: 2,
      fetchVerifiedPage: async ({ startAfter }) => ({ status: "verified",
        documents: startAfter === null ? [{ id: id(16) }, { id: id(32) }]
          : startAfter === id(32) ? [{ id: id(5) }, { id: id(6) }] : [],
        height: "1" }) }),
    /strictly ascending/);

  console.log(`e2ProvedQueryTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
})();
