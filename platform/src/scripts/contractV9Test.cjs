/**
 * Offline schema test for the v9 draft (plain `node`, no network). Three nets, per the
 * draft review's rounds:
 *   1. buildV8 is pinned against a REVIEWED BASELINE HASH of the canonical SOURCE
 *      construction (which carries two post-publish source-only bound tightenings; the
 *      live ledger retains the looser published values, see the contractV8.cjs
 *      header), so a drift in buildV8 (or in the base contract it derives from)
 *      cannot silently move both sides of the v8-to-v9 comparison.
 *   2. every type v9 does not intend to change must deep-equal its v8 form, and the
 *      types it DOES change (pool, completionReceipt, pledgeSlot) are pinned as
 *      COMPLETE expected objects or exact patches, not spot-checks.
 *   3. the envStore ownership of the v9 publish-record keys is asserted at the source.
 */
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { pathToFileURL } = require("url");
const { buildV8 } = require("./contractV8.cjs");
const { buildV9 } = require("./contractV9.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed++; }
  else { failed++; console.error("FAIL:", name); }
};
// key-order-insensitive deep equality (an external review noted the earlier
// JSON.stringify form could fail on a semantically harmless key reorder; note
// deepStrictEqual THROWS on mismatch, so it must be wrapped, not compared)
const assert = require("assert");
const eq = (a, b) => { try { assert.deepStrictEqual(a, b); return true; } catch { return false; } };

// the sha256 of the SEMANTIC v8 schema (buildV8 output with every description string
// stripped) at the reviewed extraction. It pins the canonical SOURCE construction, not
// the live ledger schema (the source carries two post-publish source-only bound
// tightenings; the ledger keeps its looser published values). Descriptions are excluded
// on purpose: they are prose, and the public derived face genericizes provenance tags
// inside them, so hashing them would fork the baseline between the two faces of the same
// source; the net pins SEMANTIC drift (types, bounds, indices, required, positions,
// modes). If this fails, contractV8.cjs or the base contract changed semantically, and
// NEITHER may change: the live v8 schema is immutable on the ledger.
const V8_BASELINE_SHA256 = "a85ade3674cdb5c9daba4f9ba5ad1c3c22f38e6c8cdde56d90467355b3dfec2d";
const stripDescriptions = (x) => {
  if (Array.isArray(x)) return x.map(stripDescriptions);
  if (x && typeof x === "object") {
    const out = {};
    for (const [k, v] of Object.entries(x)) {
      if (k === "description") continue;
      out[k] = stripDescriptions(v);
    }
    return out;
  }
  return x;
};

const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };

// the COMPLETE expected v9 pool (net 2: a full pin, not a property spot-check)
const EXPECTED_V9_POOL = {
  type: "object",
  documentsMutable: false,
  canBeDeleted: false,
  creationRestrictionMode: 1,
  properties: {
    slotIndex: {
      type: "integer", minimum: 0, maximum: 31, position: 0,
      description: "which #187 share / DIP-0026 payout entry this pool maps to (a creation-time constant, pinned by immutability)",
    },
    nodeType: { type: "string", enum: ["regular", "evo"], maxLength: 10, position: 1 },
    operatorFeeBps: {
      type: "integer", minimum: 0, maximum: 10000, position: 2,
      description: "operator fee in basis points of the pool's owner reward, immutable for the pool's life; the operator IS the document owner ($ownerId) under owner-only creation",
    },
    targetDuffs: {
      type: "integer", minimum: 1, maximum: 400000000000, position: 3,
      description: "the collateral target, pinned explicitly so the pool is self-contained (must match the nodeType's target; clients check, the schema cannot)",
    },
    slotDuffs: {
      type: "integer", minimum: 1, position: 4,
      description: "the fixed slot size in duffs; absent (with slotCount, both-or-neither) means this pool has no slot book; slotDuffs * slotCount = targetDuffs is checked by clients and recomputed by verifiers",
    },
    slotCount: {
      type: "integer", minimum: 1, maximum: 512, position: 5,
      description: "how many equal slots divide the target; bounded at consensus so a legitimate book can never exceed the bounded completion scan",
    },
  },
  required: ["slotIndex", "nodeType", "operatorFeeBps", "targetDuffs", "$createdAt"],
  dependentRequired: { slotDuffs: ["slotCount"], slotCount: ["slotDuffs"] },
  additionalProperties: false,
  indices: [
    { name: "byOwner", properties: [{ $ownerId: "asc" }, { $createdAt: "asc" }] },
  ],
};

(async () => {
  const contractUrl = pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href;
  const { poolLedgerContract } = await import(contractUrl);
  const v8 = buildV8(poolLedgerContract);
  const v9 = buildV9(poolLedgerContract);

  // ---- net 1: the v8 baseline is the reviewed canonical source (semantic form) ----
  ok("buildV8 matches the reviewed canonical source baseline (semantic sha256)",
    crypto.createHash("sha256").update(JSON.stringify(stripDescriptions(v8))).digest("hex") === V8_BASELINE_SHA256);

  // ---- net 2: exact diff. NO new or removed types; only three types change ----
  ok("v9 adds no document types", eq(Object.keys(v8).sort(), Object.keys(v9).sort()));
  ok("poolState does not exist (no lifecycle document; completion is receipt-recorded)", v9.poolState === undefined);
  const CHANGED = new Set(["pool", "completionReceipt", "pledgeSlot"]);
  for (const t of Object.keys(v8)) {
    if (CHANGED.has(t)) continue;
    ok(`type ${t} carried unchanged`, eq(v8[t], v9[t]));
  }

  // pool: the complete pin
  ok("v9 pool equals the complete expected object", eq(v9.pool, EXPECTED_V9_POOL));
  // and the redesign's negative space, stated explicitly
  ok("pool has NO proTxHash/status/operatorIdentityId",
    !("proTxHash" in v9.pool.properties) && !("status" in v9.pool.properties) &&
    !("operatorIdentityId" in v9.pool.properties));

  // completionReceipt: exactly the pared-record patch (the pool-pinned duplicates
  // removed, positions renumbered, the two descriptions restated, unique bySlot)
  {
    const patched = JSON.parse(JSON.stringify(v8.completionReceipt));
    delete patched.properties.nodeType;
    delete patched.properties.operatorFeeBps;
    delete patched.properties.targetDuffs;
    patched.properties.poolId.description =
      "the pool this receipt completes; at most one receipt per pool (unique byPool); that the id resolves to a real pool of this contract is a duty of the shared receipt-to-pool check";
    patched.properties.slotIndex.description =
      "the pool's L1 share mapping; MUST equal the immutable pool's slotIndex (the shared check verifies; the schema cannot), kept here because the unique bySlot index needs it";
    ["poolId", "proTxHash", "slotIndex", "formatVersion", "allocationRows", "allocationHash",
      "participantCount", "l1Verification", "verificationMethodVersion"]
      .forEach((k, i) => { patched.properties[k].position = i; });
    patched.required = patched.required.filter((k) => !["nodeType", "operatorFeeBps", "targetDuffs"].includes(k));
    patched.indices = [
      { name: "byPool", properties: [{ poolId: "asc" }], unique: true },
      { name: "bySlot", properties: [{ proTxHash: "asc" }, { slotIndex: "asc" }], unique: true },
    ];
    ok("completionReceipt diff is exactly the pared record + unique bySlot", eq(patched, v9.completionReceipt));
    ok("receipt no longer duplicates the pool-pinned constants",
      !("nodeType" in v9.completionReceipt.properties) &&
      !("operatorFeeBps" in v9.completionReceipt.properties) &&
      !("targetDuffs" in v9.completionReceipt.properties));
    ok("receipt keeps the completion-time evidence",
      ["proTxHash", "slotIndex", "allocationRows", "allocationHash", "l1Verification"]
        .every((k) => k in v9.completionReceipt.properties));
  }

  // pledgeSlot: the ONLY change is the slotNo bound (and its wording)
  {
    const patched = JSON.parse(JSON.stringify(v8.pledgeSlot));
    patched.properties.slotNo = {
      ...patched.properties.slotNo,
      maximum: 511,
      description: "which equal-size collateral slot of the pool (0..slotCount-1, bounded at consensus to match slotCount's ceiling)",
    };
    ok("pledgeSlot diff is exactly the slotNo consensus bound", eq(patched, v9.pledgeSlot));
  }

  // position hygiene on every v9 type: unique and contiguous from 0
  for (const [t, def] of Object.entries(v9)) {
    const pos = Object.values(def.properties).map((x) => x.position).sort((a, b) => a - b);
    ok(`positions unique+contiguous in ${t}`, pos.every((v, i) => v === i));
  }

  // the shared HASH32 shape stayed intact where the receipt relies on it
  ok("receipt poolId/proTxHash keep the 32-byte shape",
    eq({ ...v9.completionReceipt.properties.poolId, description: undefined, position: undefined },
      { ...HASH32, description: undefined, position: undefined }));

  // ---- net 3: the v9 publish record is protected in envStore ----
  {
    const envStoreSrc = fs.readFileSync(path.join(__dirname, "envStore.cjs"), "utf8");
    const m = envStoreSrc.match(/const OWNED_KEYS = \[([^\]]*)\]/s);
    ok("envStore OWNED_KEYS covers the v9 publish record",
      !!m && m[1].includes('"CONTRACT_V9_PENDING"') && m[1].includes('"CONTRACT_V9_ID"'));
  }

  console.log(`contractV9Test: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
})();
