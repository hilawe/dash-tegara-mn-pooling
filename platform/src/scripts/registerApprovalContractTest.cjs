// The approval contract's publication battery. The contract and its create transition are built by
// the pinned DPP from the schema, as the runner builds them. The network is a small world: a map of
// published contracts, identity A's nonce, and a broadcast that publishes the contract its bytes
// carry when their nonce is still ahead of the tip. The runner signs. This battery carries the
// unsigned transition's bytes, which is all the decision reads.
//
// THE MUTATION LIST, written before the cases: record after broadcast instead of before; build new
// bytes while a pending record stands; `>=` to `>` on the recorded nonce; drop the size cap; drop the
// identifier cross-check; drop the config check; clear the record before the read-back; write the
// identifier on a dry run; drop the stored identifier's binding.
const dpp = require("pshenmic-dpp");
const crypto = require("crypto");
const P = require("./registerApprovalContract.cjs");
const { buildApprovalSchemas, CONTRACT_CONFIG } = require("./approvalContract.cjs");
const { canonicalString } = require("./canonicalJson.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const WRITER_HEX = "11".repeat(32);
const WRITER = new dpp.IdentifierWASM(WRITER_HEX);
const hexOf = (id) => Buffer.from(id.bytes()).toString("hex");
const KEYS = [{ keyId: 0, purpose: "AUTHENTICATION", level: "MASTER" }, { keyId: 1, purpose: "AUTHENTICATION", level: "HIGH" },
  { keyId: 2, purpose: "AUTHENTICATION", level: "CRITICAL" }, { keyId: 3, purpose: "TRANSFER", level: "CRITICAL" }];

// every transition this battery builds, so the world's broadcast can tell what bytes publish
const KNOWN = new Map();
const built = (nonce, { schemas = buildApprovalSchemas(), readonly = true } = {}) => {
  const c = new dpp.DataContractWASM(WRITER, nonce, schemas, undefined, undefined, true, 12);
  c.setConfig({ ...CONTRACT_CONFIG, readonly }, 12);
  const bytes = Buffer.from(new dpp.DataContractCreateTransitionWASM(c, nonce).toStateTransition().bytes());
  KNOWN.set(bytes.toString("hex"), { c, nonce });
  return { c, bytes };
};
const servedOf = (c, over = {}) => ({ idHex: hexOf(c.id), ownerIdHex: WRITER_HEX, version: 1,
  schemas: c.getSchemas(), config: c.getConfig(), ...over });

const world = ({ tip = 40n, store = {}, keys = KEYS, lose = false, publishAs = null, buildOver = null } = {}) => {
  const w = { tip, store: { ...store }, contracts: new Map(), broadcasts: [], builds: 0, log: [], pendingAtBroadcast: [] };
  w.deps = {
    matchedKeys: async () => keys,
    readStore: async () => ({ id: w.store.id, pending: w.store.pending === undefined ? null : JSON.parse(w.store.pending) }),
    writeId: async (id) => { w.store.id = id; },
    writePending: async (r) => { w.store.pending = JSON.stringify(r); },
    clearPending: async () => { delete w.store.pending; },
    readIdentityNonce: async () => w.tip,
    readContract: async (idB58) => (w.contracts.has(idB58) ? { status: "present", served: w.contracts.get(idB58) } : { status: "not-found" }),
    buildSignedCreate: async ({ nonce, key }) => {
      w.builds += 1; w.signedWith = key.keyId;
      const { c, bytes } = buildOver ? buildOver(nonce) : built(nonce);
      return { bytesHex: bytes.toString("hex"), size: bytes.length, contractIdB58: c.id.base58(), contractIdHex: hexOf(c.id), serializedSize: c.bytes(12).length };
    },
    contractIdHexFor: async (nonce) => hexOf(dpp.DataContractWASM.generateId(WRITER, nonce)),
    broadcast: async (bytesHex) => {
      w.broadcasts.push(bytesHex);
      w.pendingAtBroadcast.push(w.store.pending);
      const hit = KNOWN.get(bytesHex);
      if (lose || !hit || w.tip >= hit.nonce) return "ambiguous";
      w.tip = hit.nonce;
      w.contracts.set(hit.c.id.base58(), publishAs ? publishAs(hit.c) : servedOf(hit.c));
      return "success-with-proof";
    },
    sleep: async () => {},
    log: (l) => w.log.push(l),
  };
  return w;
};
const run = (w, confirmed) => P.runApprovalPublication({ deps: w.deps, confirmed, writerIdHex: WRITER_HEX });
const rejects = async (name, p, re) => {
  try { await p; ok(`${name} (expected a refusal)`, false); }
  catch (e) { ok(`${name}: ${e.message}`, re.test(e.message)); }
};
const pendingFor = (nonce, over = {}) => {
  const { c, bytes } = built(nonce);
  const hex = bytes.toString("hex");
  return { record: { nonce: String(nonce), bytesHex: hex, sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    contractIdB58: c.id.base58(), contractIdHex: hexOf(c.id), ...over }, c, hex };
};

(async () => {
  // ---- a dry run builds and signs, and records and sends nothing ----
  {
    const w = world();
    const r = await run(w, false);
    const { c, bytes } = built(41n);
    ok(`the dry run plans the next nonce, the HIGH key and the exact bytes (got ${JSON.stringify(r)})`, r.outcome === "dry-run" && r.resend === false
      && r.nonce === "41" && r.keyId === 1 && r.size === bytes.length && r.contractIdB58 === c.id.base58() && w.signedWith === 1);
    ok("and records nothing and broadcasts nothing", w.broadcasts.length === 0 && w.store.pending === undefined && w.store.id === undefined);
    ok("the plan names the sha-256 of the bytes it would send", r.sha256 === crypto.createHash("sha256").update(bytes).digest("hex"));
  }
  // ---- a confirmed run records before its one broadcast, then records the identifier from a read-back ----
  {
    const w = world();
    const r = await run(w, true);
    ok(`the confirmed run publishes (got ${JSON.stringify(r.outcome)})`, r.outcome === "published" && w.broadcasts.length === 1);
    ok("the pending record was in the store when the bytes were broadcast", w.pendingAtBroadcast[0] !== undefined
      && JSON.parse(w.pendingAtBroadcast[0]).bytesHex === w.broadcasts[0]);
    ok("the identifier is recorded and the pending record discharged", w.store.id === r.contractIdB58 && w.store.pending === undefined);
    const again = await run(w, true);
    ok("a second run reads it back as already published and sends nothing", again.outcome === "already-published" && w.broadcasts.length === 1);
  }
  // ---- a pending record: the bytes are never rebuilt ----
  {
    const { record, hex, c } = pendingFor(41n);
    const w = world({ store: { pending: JSON.stringify(record) } });
    const dry = await run(w, false);
    ok("a dry run with a live record reports the resend and builds nothing", dry.outcome === "dry-run" && dry.resend === true && w.builds === 0 && w.broadcasts.length === 0);
    const r = await run(w, true);
    ok("a confirmed run resends the IDENTICAL recorded bytes and publishes", r.outcome === "published" && w.builds === 0 && w.broadcasts[0] === hex
      && w.store.id === c.id.base58() && w.store.pending === undefined);
  }
  {
    const { record } = pendingFor(41n);
    const w = world({ tip: 41n, store: { pending: JSON.stringify(record) } });
    const r = await run(w, true);
    ok(`at the recorded nonce with no contract, UNRESOLVED, nothing sent, the record kept (got ${JSON.stringify(r)})`,
      r.outcome === "unresolved" && r.reason === "nonce-at-or-past" && w.broadcasts.length === 0 && w.builds === 0 && w.store.pending !== undefined);
    ok("and the log does not claim the recorded bytes are dead", w.log.some((l) => /can still execute if it was skipped/.test(l)));
  }
  {
    const { record, c } = pendingFor(41n);
    const w = world({ tip: 41n, store: { pending: JSON.stringify(record) } });
    w.contracts.set(c.id.base58(), servedOf(c));
    const dry = await run(w, false);
    ok("a published contract behind a record: the dry run reports it and writes nothing", dry.outcome === "dry-run" && dry.published === true && w.store.id === undefined);
    const r = await run(w, true);
    ok("and a confirmed run discharges the record", r.outcome === "published" && w.store.id === c.id.base58() && w.store.pending === undefined && w.broadcasts.length === 0);
  }
  await rejects("a pending record whose digest does not match its bytes", run(world({ store: { pending: JSON.stringify(pendingFor(41n, { sha256: "00".repeat(32) }).record) } }), true), /malformed/);

  // ---- the read-back decides, never the broadcast token ----
  {
    const w = world({ lose: true });
    const r = await run(w, true);
    ok(`a broadcast that never reads back is UNRESOLVED and keeps its record (got ${JSON.stringify(r.outcome)})`, r.outcome === "unresolved" && r.reason === "not-read-back"
      && w.store.pending !== undefined && w.store.id === undefined);
  }
  {
    const w = world({ publishAs: (c) => servedOf(c, { config: { ...c.getConfig(), readonly: false } }) });
    await rejects("a read-back whose config is not read-only", run(w, true), /config differs from the source build in readonly/);
    ok("and the identifier is not recorded", w.store.id === undefined && w.store.pending !== undefined);
  }
  {
    // the review's case: a setting outside the ones this project chose, still part of the contract
    const w = world({ publishAs: (c) => servedOf(c, { config: { ...c.getConfig(), documentsKeepHistoryContractDefault: true } }) });
    await rejects("a read-back differing in any other config member", run(w, true), /differs from the source build in documentsKeepHistoryContractDefault/);
    ok("and the identifier is not recorded", w.store.id === undefined);
  }
  {
    // an ADDED member, which a comparison over CONTRACT_CONFIG's own keys would not see (the
    // confirmation round's case, 2026-09-28)
    const w = world({ publishAs: (c) => servedOf(c, { config: { ...c.getConfig(), extraMember: false } }) });
    await rejects("a read-back whose config carries a member the source build does not", run(w, true), /differs from the source build in extraMember/);
  }
  {
    // CONTRACT_CONFIG is what the pinned DPP builds and what a serialization round trip serves, and a
    // contract that went through that round trip passes the read-back whole (schemas included)
    const { c } = built(41n);
    ok("the built contract's config is exactly CONTRACT_CONFIG", canonicalString(c.getConfig()) === canonicalString(CONTRACT_CONFIG));
    const back = dpp.DataContractWASM.fromBytes(c.bytes(12), true, 12);
    ok("a serialization round trip keeps the config exactly", canonicalString(back.getConfig()) === canonicalString(CONTRACT_CONFIG));
    let why = "";
    try { P.requirePublished({ served: servedOf(back), expectedIdHex: hexOf(c.id), writerIdHex: WRITER_HEX }); } catch (e) { why = e.message; }
    ok(`a contract read back through serialization passes the read-back, schemas and config whole (got "${why}")`, why === "");
  }
  {
    const other = buildApprovalSchemas(); other.memberTermsApproval.properties.record.maxItems = 4000;
    const w = world({ publishAs: (c) => servedOf(c, { schemas: other }) });
    await rejects("a read-back whose schemas are not the source build", run(w, true), /not the source build/);
  }
  {
    const w = world({ publishAs: (c) => servedOf(c, { version: 2 }) });
    await rejects("a read-back at another version", run(w, true), /version 2/);
  }
  {
    const w = world({ publishAs: (c) => servedOf(c, { ownerIdHex: "22".repeat(32) }) });
    await rejects("a read-back owned by another identity", run(w, true), /not owned by the writer/);
  }

  // ---- the stored identifier ----
  {
    const w = world();
    await run(w, true);
    const id = w.store.id;
    const { c: other } = built(55n);
    w.contracts.set(id, servedOf(other)); // the stored identifier now serves another contract
    await rejects("a stored identifier that serves a contract with another identifier", run(w, true), /not the expected/);
    w.contracts.delete(id);
    await rejects("a stored identifier that is not read back", run(w, true), /not read back by proof/);
    w.store.id = "not-an-identifier";
    await rejects("a stored identifier that does not decode", run(w, true), /does not decode/);
  }

  // ---- the build ----
  await rejects("no HIGH authentication key", run(world({ keys: KEYS.filter((k) => k.level !== "HIGH") }), false), /no authentication key at HIGH/);
  await rejects("two HIGH authentication keys", run(world({ keys: [...KEYS, { keyId: 4, purpose: "AUTHENTICATION", level: "HIGH" }] }), false), /choose one explicitly/);
  await rejects("a build at another nonce than the tip's next", run(world({ buildOver: (n) => built(n + 1n) }), false), /nonce 41 gives/);
  {
    const big = buildApprovalSchemas();
    for (let i = 0; i < 40; i++) big[`padding${i}`] = JSON.parse(JSON.stringify(big.memberTermsApproval));
    const w = world({ buildOver: (n) => built(n, { schemas: big }) });
    await rejects("a signed publication above the 20,480-byte cap", run(w, true), /above 20480/);
    ok("and nothing was recorded or sent", w.store.pending === undefined && w.broadcasts.length === 0);
  }
  {
    const w = world();
    const realBuild = w.deps.buildSignedCreate;
    w.deps.buildSignedCreate = async (a) => ({ ...(await realBuild(a)), size: 100 });
    await rejects("a reported size that is not the bytes' length", run(w, false), /not the signed bytes' length/);
  }

  // ---- the real sizes, for the execution package ----
  {
    const { c, bytes } = built(41n);
    console.log(`  approval contract: ${c.bytes(12).length} serialized bytes, unsigned create transition ${bytes.length} bytes`);
    ok("the unsigned transition leaves room for a signature under the cap", bytes.length + 512 <= P.MAX_STATE_TRANSITION_SIZE);
    ok("the built contract is read-only", c.getConfig().readonly === true);
  }

  console.log(`registerApprovalContractTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
})().catch((e) => { console.error(e); process.exitCode = 1; });
