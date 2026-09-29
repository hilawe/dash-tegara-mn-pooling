// The canonical v11 update's decisions (registerV11Update.cjs): update, already updated after a
// lost response, or refuse; the value published; the signing key; the checks after the update.
const { poolLedgerContract } = require("../../dist/contract/poolLedger.js");
const { buildV11, buildV11WithFinalEpoch } = require("./contractV11.cjs");
const U = require("./registerV11Update.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error("FAIL (no error):", name); }
  catch (e) { if (re.test(e.message)) passed++; else { failed++; console.error("FAIL (wrong error):", name, "->", e.message); } }
};
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error("FAIL (no error):", name); }
  catch (e) { if (re.test(e.message)) passed++; else { failed++; console.error("FAIL (wrong error):", name, "->", e.message); } }
};

const C = "a".repeat(64), W = "b".repeat(64);
const BEFORE = buildV11(poolLedgerContract), AFTER = buildV11WithFinalEpoch(poolLedgerContract);
const served = (over = {}) => ({ idHex: C, ownerIdHex: W, version: 1, schemas: JSON.parse(JSON.stringify(BEFORE)), ...over });
const plan = (s) => U.planV11Update({ served: s, contractIdHex: C, writerIdHex: W, poolLedgerContract });

(async () => {
  // ---- the plan, from what the proved read serves ----
  ok("the published v11 at version 1 is updated", plan(served()).action === "update");
  ok("the updated payload at version 2 is recognized as already updated (a lost response)",
    plan(served({ version: 2, schemas: JSON.parse(JSON.stringify(AFTER)) })).action === "already-updated");
  ok("member order does not decide (schemas compared canonically)",
    plan(served({ schemas: Object.fromEntries(Object.entries(BEFORE).reverse()) })).action === "update");
  throws("the published payload at version 2 refuses", () => plan(served({ version: 2 })), /published v11 payload but the version is 2/);
  throws("the updated payload at version 1 refuses", () => plan(served({ schemas: AFTER })), /updated payload but the version is 1/);
  throws("the updated payload at version 3 refuses", () => plan(served({ version: 3, schemas: AFTER })), /updated payload but the version is 3/);
  {
    const s = JSON.parse(JSON.stringify(BEFORE));
    s.pool.properties.targetDuffs.maximum = 1;
    throws("an unexpected existing payload (one schema field changed) refuses", () => plan(served({ schemas: s })), /match neither/);
    const t = JSON.parse(JSON.stringify(AFTER));
    t.memberFinalEpoch.indices[0].unique = false;
    throws("an updated payload whose new index is not unique refuses", () => plan(served({ version: 2, schemas: t })), /match neither/);
  }
  throws("another contract refuses", () => plan(served({ idHex: "c".repeat(64) })), /not the canonical v11/);
  throws("another owner refuses", () => plan(served({ ownerIdHex: "d".repeat(64) })), /not owned by the writer/);
  throws("a non-integer version refuses", () => plan(served({ version: "1" })), /integer version/);

  // ---- the value published ----
  {
    const current = { id: "ID", ownerId: "OWNER", version: 1, config: { k: 1 }, documentSchemas: JSON.parse(JSON.stringify(BEFORE)) };
    const next = U.updatedContractValue({ currentValue: current, poolLedgerContract });
    ok("the published value is the current one at version 2 with the type added, other members unchanged",
      next.version === 2 && next.id === "ID" && next.ownerId === "OWNER" && next.config.k === 1
      && Object.keys(next.documentSchemas).length === Object.keys(BEFORE).length + 1
      && current.version === 1 && !("memberFinalEpoch" in current.documentSchemas));
    // the added type as the design states it, spelled out here rather than taken from the builder
    const idx = next.documentSchemas.memberFinalEpoch.indices;
    ok("the added type carries exactly one index, unique on (poolId, funderId)",
      idx.length === 1 && idx[0].unique === true
      && JSON.stringify(idx[0].properties) === JSON.stringify([{ poolId: "asc" }, { funderId: "asc" }]));
    throws("a current value that already has the type refuses",
      () => U.updatedContractValue({ currentValue: { ...current, documentSchemas: AFTER }, poolLedgerContract }), /not the published v11 payload/);
    const odd = JSON.parse(JSON.stringify(BEFORE)); delete odd.pool;
    throws("a current value that is not the published payload refuses",
      () => U.updatedContractValue({ currentValue: { ...current, documentSchemas: odd }, poolLedgerContract }), /not the published v11 payload/);
  }

  // ---- the key: identity A's published layout on testnet ----
  const KEYS = [{ keyId: 0, purpose: "AUTHENTICATION", level: "MASTER" }, { keyId: 1, purpose: "AUTHENTICATION", level: "HIGH" },
    { keyId: 2, purpose: "AUTHENTICATION", level: "CRITICAL" }, { keyId: 3, purpose: "TRANSFER", level: "CRITICAL" }];
  ok("the update signs with the CRITICAL authentication key (key 2)", U.chooseSigningKey(KEYS, "CRITICAL").keyId === 2);
  ok("documents sign with the HIGH authentication key (key 1)", U.chooseSigningKey(KEYS, "HIGH").keyId === 1);
  throws("with only a HIGH authentication key, the update refuses rather than falling back",
    () => U.chooseSigningKey(KEYS.filter((k) => k.keyId !== 2), "CRITICAL"), /no authentication key at CRITICAL/);
  throws("a CRITICAL transfer key does not count", () => U.chooseSigningKey([KEYS[3]], "CRITICAL"), /no authentication key/);
  throws("two CRITICAL authentication keys refuse", () => U.chooseSigningKey([KEYS[2], { ...KEYS[2], keyId: 4 }], "CRITICAL"), /2 authentication keys/);
  throws("MASTER is not a level this module signs at", () => U.chooseSigningKey(KEYS, "MASTER"), /HIGH or CRITICAL/);

  // ---- after the update ----
  const good = { readContract: async () => served({ version: 2, schemas: AFTER }),
    resolveFormation: async () => ({ action: "reuse" }), verifyGate: async () => ({ admitted: true }) };
  const after = (deps) => U.verifyAfterUpdate({ deps, contractIdHex: C, writerIdHex: W, poolLedgerContract });
  ok("all three post-update checks pass on the updated contract", (await after(good)).length === 3);
  {
    const calls = [];
    const d = { readContract: async () => served(), resolveFormation: async () => { calls.push("f"); return { action: "reuse" }; },
      verifyGate: async () => { calls.push("g"); return { admitted: true }; } };
    await rejects("a contract still at the published payload fails the first check", after(d), /not the updated payload at version 2/);
    ok("and the later checks do not run", calls.length === 0);
  }
  {
    let gateRan = false;
    await rejects("a formation that no longer reads back refuses",
      after({ ...good, resolveFormation: async () => ({ action: "create" }), verifyGate: async () => { gateRan = true; return { admitted: true }; } }),
      /demo formation did not read back/);
    ok("and the gate check does not run after the formation check fails", gateRan === false);
  }
  await rejects("a gate lookup that does not admit refuses", after({ ...good, verifyGate: async () => ({ admitted: false }) }), /strict lookup did not admit/);
  await rejects("a truthy but non-true admission refuses", after({ ...good, verifyGate: async () => ({ admitted: "yes" }) }), /strict lookup did not admit/);
  await rejects("a failed proved read stops the checks", after({ ...good, readContract: async () => { throw new Error("proof verification failed"); } }), /proof verification failed/);
  await rejects("a missing dependency refuses", after({ readContract: good.readContract }), /needs deps.resolveFormation/);

  // ---- THE UPDATE FLOW, driven end to end over fakes (runV11UpdateFlow) ----
  const crypto = require("crypto");
  const V1 = { tag: "v1" }, V2 = { tag: "v2" };
  const servedOf = (c) => (c === V2 ? served({ version: 2, schemas: JSON.parse(JSON.stringify(AFTER)) }) : served());
  const PEND = (() => { const bytesHex = "cd".repeat(50); return { nonce: "7", bytesHex,
    sha256: crypto.createHash("sha256").update(Buffer.from(bytesHex, "hex")).digest("hex") }; })();
  const mkFlow = ({ contracts = [V1, V2], nonce = 6n, pending = null, token = "success-with-proof",
    formation = "reuse", gatePre = true, gatePost = true, keys = KEYS, size = 13938 } = {}) => {
    const calls = { signKey: [], broadcast: [], wrote: [], cleared: 0, gateWith: [], formation: 0, order: [], reads: 0,
      pendingAtRead: [], readResults: [], clearedAtRead: null, broadcastAtRead: null };
    let store = pending ? { ...pending } : null;
    const deps = {
      matchedKeys: async () => keys,
      readContract: async () => { calls.pendingAtRead.push(store !== null); const c = contracts[Math.min(calls.reads++, contracts.length - 1)]; calls.readResults.push(c); return { contract: c, served: servedOf(c) }; },
      readContractNonce: async () => nonce,
      contractValue: (c) => ({ id: "ID", ownerId: "OWNER", version: c === V2 ? 2 : 1, documentSchemas: JSON.parse(JSON.stringify(c === V2 ? AFTER : BEFORE)) }),
      buildSignedUpdate: async ({ value, key, nonce: n }) => { calls.signKey.push(key.keyId); calls.builtNonce = n; calls.builtVersion = value.version; calls.order.push("build"); return { bytesHex: "ab".repeat(100), size }; },
      broadcast: async (hex) => { calls.broadcast.push(hex); calls.order.push("broadcast"); calls.broadcastAtRead = calls.reads; return token; },
      readPending: async () => store,
      writePending: async (r) => { store = r; calls.wrote.push(r); calls.order.push("writePending"); },
      clearPending: async () => { store = null; calls.cleared++; calls.clearedAtRead = calls.reads; },
      resolveFormation: async () => { calls.formation++; return { action: formation }; },
      verifyGateWith: async (c) => { calls.gateWith.push(c); return { admitted: calls.gateWith.length === 1 ? gatePre : gatePost }; },
      sleep: async () => {}, log: () => {},
    };
    return { deps, calls, store: () => store };
  };
  // THE INVARIANTS EVERY SCENARIO MUST HOLD, checked after each run whatever its outcome (the
  // 2026-09-27 confirmation rounds kept finding branch-specific assertions that watched only a final
  // state, so the rules are stated once and applied everywhere):
  //   a success outcome ran the post-update checks: a later contract read, the formation read and the
  //     gate verified a second time, the gate's last object being the last contract read;
  //   the record is cleared only after a read has returned version 2;
  //   after a broadcast the record is present at every read up to and including the first version-2
  //     read, or every read if none returned version 2;
  //   an unresolved outcome clears nothing and keeps the record.
  const invariants = (label, h, r) => {
    const c = h.calls;
    if (r && (r.outcome === "updated" || r.outcome === "already-updated")) {
      ok(`${label}: the post-update checks ran`, c.reads >= 2 && c.formation === 2 && c.gateWith.length === 2
        && c.gateWith[1] === c.readResults[c.readResults.length - 1] && Array.isArray(r.report) && r.report.length === 3);
    }
    const firstV2 = c.readResults.indexOf(V2);
    if (c.cleared > 0) ok(`${label}: the record was cleared only after a read returned version 2`, firstV2 !== -1 && c.clearedAtRead >= firstV2 + 1);
    if (c.broadcastAtRead !== null) {
      const last = firstV2 === -1 ? c.pendingAtRead.length - 1 : firstV2;
      ok(`${label}: the record was present at every read from the broadcast to version 2`,
        c.pendingAtRead.slice(c.broadcastAtRead, last + 1).every(Boolean));
    }
    if (r && r.outcome === "unresolved") ok(`${label}: an unresolved run kept its record`, c.cleared === 0 && h.store() !== null);
  };
  const run = async (h, confirmed, label = "flow") => {
    let r;
    try { r = await U.runV11UpdateFlow({ deps: h.deps, confirmed, contractIdHex: C, writerIdHex: W, poolLedgerContract }); }
    finally { invariants(label, h, r); }
    return r;
  };

  {
    const h = mkFlow();
    const r = await run(h, true);
    ok("a confirmed update signs with key 2 at CRITICAL, at the next contract nonce, building version 2",
      r.outcome === "updated" && JSON.stringify(h.calls.signKey) === "[2]" && h.calls.builtNonce === 7n && h.calls.builtVersion === 2);
    ok("it broadcasts exactly once, the bytes it built, after recording them as pending",
      h.calls.broadcast.length === 1 && h.calls.broadcast[0] === "ab".repeat(100)
      && JSON.stringify(h.calls.order) === JSON.stringify(["build", "writePending", "broadcast"]));
    ok("the post-update checks run: the formation is read again and the gate is verified against the UPDATED contract object",
      h.calls.formation === 2 && h.calls.gateWith.length === 2 && h.calls.gateWith[0] === V1 && h.calls.gateWith[1] === V2
      && Array.isArray(r.report) && r.report.length === 3);
    ok("the pending record is cleared once the contract reads as updated", h.calls.cleared === 1 && h.store() === null);
  }
  {
    const h = mkFlow();
    const r = await run(h, false);
    ok("a dry run builds and reports but records and broadcasts nothing",
      r.outcome === "dry-run" && r.keyId === 2 && r.size === 13938 && h.calls.broadcast.length === 0 && h.calls.wrote.length === 0);
  }
  {
    const h = mkFlow({ contracts: [V1], token: "ambiguous" });
    const r = await run(h, true);
    ok("a lost response whose re-reads still show version 1 is UNRESOLVED, not a failure and not a success",
      r.outcome === "unresolved" && r.token === "ambiguous");
    ok("an unresolved run broadcast once, re-read six times after it, and kept its pending record",
      h.calls.broadcast.length === 1 && h.calls.reads === 1 + 6 && h.calls.cleared === 0 && h.store() && h.store().nonce === "7");
  }
  {
    const h = mkFlow({ pending: PEND, nonce: 6n });
    const r = await run(h, true);
    ok("a confirmed rerun after an unresolved run resends the IDENTICAL recorded bytes and builds nothing new",
      r.outcome === "updated" && h.calls.signKey.length === 0 && h.calls.broadcast.length === 1 && h.calls.broadcast[0] === PEND.bytesHex);
    ok("and clears the record once the contract reads as updated", h.calls.cleared === 1);
  }
  {
    const h = mkFlow({ pending: PEND, nonce: 6n });
    const r = await run(h, false);
    ok("a dry rerun with a pending record reports the resend and sends nothing",
      r.outcome === "dry-run" && r.resend === true && h.calls.broadcast.length === 0 && h.calls.signKey.length === 0);
  }
  {
    const h = mkFlow({ pending: PEND, contracts: [V2] });
    const r = await run(h, true);
    ok("a rerun that finds the contract updated reports already updated, sends nothing, runs the checks and clears the record",
      r.outcome === "already-updated" && h.calls.broadcast.length === 0 && h.calls.signKey.length === 0
      && h.calls.cleared === 1 && h.calls.gateWith[h.calls.gateWith.length - 1] === V2 && r.report.length === 3);
    ok("and its post-update checks really run: a second contract read, the formation read again, the gate verified again",
      h.calls.reads === 2 && h.calls.formation === 2 && h.calls.gateWith.length === 2);
  }
  for (const confirmed of [true, false]) {
    const h = mkFlow({ pending: PEND, contracts: [V1], nonce: 7n });
    let r;
    try { r = await run(h, confirmed, `nonce advanced, ${confirmed ? "confirmed" : "dry"}`); }
    catch (e) { r = { threw: e.message }; } // a throw here is itself the wrong answer, reported by name below
    ok(`an advanced nonce at version 1 is UNRESOLVED, not a claim that the recorded bytes executed (${confirmed ? "confirmed" : "dry run"})`,
      r.outcome === "unresolved" && r.reason === "nonce-advanced" && r.recordedNonce === "7" && r.currentNonce === "7");
    ok(`and nothing is built or sent, and the record is kept (${confirmed ? "confirmed" : "dry run"})`,
      h.calls.broadcast.length === 0 && h.calls.signKey.length === 0 && h.calls.cleared === 0 && h.store() !== null);
  }
  {
    const h = mkFlow({ pending: PEND, contracts: [V2] });
    const r = await run(h, false, "dry run, already updated, record present");
    ok("a DRY run that finds the contract updated reports it, runs the checks, and does NOT clear the record",
      r.outcome === "already-updated" && r.recordKept === true && h.calls.cleared === 0 && h.store() !== null
      && h.calls.broadcast.length === 0);
  }
  {
    const h = mkFlow({ contracts: [V1, V1, V2], token: "success-with-proof" });
    const r = await run(h, true);
    ok("after a success token the pending record is still present at every re-read until the contract reads as updated",
      r.outcome === "updated" && JSON.stringify(h.calls.pendingAtRead.slice(0, 3)) === JSON.stringify([false, true, true]) && h.calls.cleared === 1);
  }
  {
    const h = mkFlow({ contracts: [V1], token: "success-with-proof" });
    const r = await run(h, true);
    ok("a success token followed by version 1 on every re-read is unresolved, and the record is kept",
      r.outcome === "unresolved" && h.calls.cleared === 0 && h.store() !== null && h.calls.pendingAtRead.slice(1).every(Boolean));
  }
  {
    const h = mkFlow({ contracts: [V2] });
    const r = await run(h, true, "already updated with no record");
    ok("a run that finds the contract already updated with no record reports it and sends nothing",
      r.outcome === "already-updated" && h.calls.broadcast.length === 0 && h.calls.signKey.length === 0 && h.calls.cleared === 0);
  }
  {
    const h = mkFlow({ pending: PEND, nonce: 6n, contracts: [V1], token: "success-with-proof" });
    const r = await run(h, true, "resend with a success token and version 1 throughout");
    ok("a resend whose re-reads stay at version 1 is unresolved and keeps the record, whatever its token said",
      r.outcome === "unresolved" && h.calls.broadcast.length === 1 && h.calls.broadcast[0] === PEND.bytesHex && h.store() !== null);
  }
  await rejects("a malformed pending record stops", run(mkFlow({ pending: { ...PEND, sha256: "0".repeat(64) } }), true), /pending update record is malformed/);
  {
    const h = mkFlow({ keys: KEYS.filter((k) => k.keyId !== 2) });
    await rejects("with no CRITICAL authentication key the flow refuses", run(h, true), /no authentication key at CRITICAL/);
    ok("before building or broadcasting anything", h.calls.signKey.length === 0 && h.calls.broadcast.length === 0);
  }
  {
    const h = mkFlow({ gatePre: false });
    await rejects("a gate that does not admit before the update stops the flow", run(h, true), /did not admit before the update/);
    ok("before anything is built or sent", h.calls.signKey.length === 0 && h.calls.broadcast.length === 0);
  }
  {
    const h = mkFlow({ gatePost: false });
    await rejects("a gate that does not admit after the update fails the run", run(h, true), /strict lookup did not admit/);
    ok("the update itself was confirmed and its record cleared before the failing check", h.calls.broadcast.length === 1 && h.calls.cleared === 1);
  }
  {
    const h = mkFlow({ size: 20481 });
    await rejects("an oversized signed update refuses", run(h, true), /above 20480/);
    ok("without recording or broadcasting it", h.calls.wrote.length === 0 && h.calls.broadcast.length === 0);
  }

  console.log(`registerV11UpdateTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
})().catch((e) => { console.error("UNCAUGHT:", e); process.exitCode = 1; });
