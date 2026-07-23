/**
 * Offline schema test for the v10 RETAIL-ONLY draft (plain `node`, no network). Four nets,
 * mirroring contractV9Test.cjs:
 *   1. buildV9 is pinned against a REVIEWED SEMANTIC BASELINE HASH of the v9 construction, so
 *      a drift in v9 (or v8, or the base contract it derives from) cannot silently move both
 *      sides of the v9-to-v10 comparison. Descriptions are stripped before hashing (they are
 *      prose; the net pins types, bounds, indices, required, positions, modes).
 *   2. the exact diff: v10 adds slotShare, changes pool, and REMOVES the three direct-tier
 *      types (share, membershipRequest, pledgeSlot; the decision (a) fold); every remaining type
 *      deep-equals its v9 form. slotShare and the v10 pool are pinned as COMPLETE expected
 *      objects, not spot-checks. slotShare's negative space (no value fields, no reward
 *      script, no owner-uniqueness index) is asserted explicitly.
 *   3. the P1 BUILDER-INPUT negative cases (spec section 7 P1(b)): checkRetailPoolInvariants /
 *      buildV10Pool must REJECT a pool that omits retailGroupDuffs, violates the retail
 *      equation, carries the stale v9 == targetDuffs book, or sets retailGroupDuffs >
 *      targetDuffs, and must ACCEPT a conforming pool.
 *   4. position hygiene: every type's positions are unique and contiguous from 0.
 */
const path = require("path");
const crypto = require("crypto");
const { pathToFileURL } = require("url");
const assert = require("assert");
const { buildV9 } = require("./contractV9.cjs");
const { buildV10, checkRetailPoolInvariants, buildV10Pool, MAX_DUFFS, MAX_SLOT_COUNT } = require("./contractV10.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed++; }
  else { failed++; console.error("FAIL:", name); }
};
// key-order-insensitive deep equality (deepStrictEqual THROWS on mismatch, so wrap it)
const eq = (a, b) => { try { assert.deepStrictEqual(a, b); return true; } catch { return false; } };

// the sha256 of the SEMANTIC v9 schema (buildV9 output with descriptions stripped) at the
// reviewed extraction. If this fails, contractV9.cjs / contractV8.cjs / the base contract
// changed semantically, and the v10 diff below can no longer be trusted against a fixed base.
const V9_BASELINE_SHA256 = "31af88bb56ab77334c2df15f13dbe615fba923843135daed5634fa43242448ef";
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

// the COMPLETE expected v10 slotShare type (net 2: a full pin)
const EXPECTED_SLOTSHARE = {
  type: "object",
  documentsMutable: false,
  canBeDeleted: false,
  transferable: 0,
  tradeMode: 1,
  creationRestrictionMode: 1,
  properties: {
    poolId: {
      ...HASH32, position: 0,
      description: "the immutable v9+ pool this slot belongs to",
    },
    slot: {
      type: "integer", minimum: 0, maximum: 511, position: 1,
      description:
        "which equal slot of the pool's book (0..slotCount-1; the 511 ceiling matches the " +
        "pool's consensus slotCount bound; conformance below the pool's own slotCount is a " +
        "reader duty, the schema cannot cross-check)",
    },
  },
  required: ["poolId", "slot"], // $createdAt dropped (Hilawe 2026-07-22, matches the proven live schema)
  additionalProperties: false,
  indices: [
    { name: "bySlot", unique: true, properties: [{ poolId: "asc" }, { slot: "asc" }] },
    { name: "byOwner", properties: [{ $ownerId: "asc" }, { $createdAt: "asc" }] },
  ],
};

(async () => {
  const contractUrl = pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href;
  const { poolLedgerContract } = await import(contractUrl);
  const v9 = buildV9(poolLedgerContract);
  const v10 = buildV10(poolLedgerContract);

  // ---- net 1: the v9 baseline is the reviewed semantic construction ----
  ok("buildV9 matches the reviewed semantic baseline (sha256)",
    crypto.createHash("sha256").update(JSON.stringify(stripDescriptions(v9))).digest("hex") === V9_BASELINE_SHA256);

  // ---- net 2: exact diff. ONE added type (slotShare), ONE changed type (pool), EXACTLY
  // THREE removed types (the direct-tier machinery, Hilawe's decision (a) 2026-07-22);
  // every remaining type deep-equals its v9 form ----
  const REMOVED = ["membershipRequest", "pledgeSlot", "share"];
  ok("v10 keys are exactly v9 - the three direct-tier types + slotShare",
    eq([...Object.keys(v9).filter((k) => !REMOVED.includes(k)), "slotShare"].sort(), Object.keys(v10).sort()));
  ok("slotShare did not exist in v9", v9.slotShare === undefined);
  for (const t of REMOVED) {
    ok(`direct-tier type ${t} existed in v9 and is REMOVED in v10`, v9[t] !== undefined && v10[t] === undefined);
  }
  // the deliberate keeps: the receipt is load-bearing for the L1-backing result, the
  // reward/governance types are shared infrastructure, and `settlement` is a flagged
  // candidate for a LATER scope pass, not silently widened into this decision
  for (const t of ["completionReceipt", "rewardAccrual", "votePreference", "settlement"]) {
    ok(`type ${t} deliberately kept`, v10[t] !== undefined);
  }
  const CHANGED = new Set(["pool", "slotShare"]);
  for (const t of Object.keys(v9)) {
    if (CHANGED.has(t) || REMOVED.includes(t)) continue;
    ok(`type ${t} carried unchanged from v9`, eq(v9[t], v10[t]));
  }

  // pool: the complete pin (v9 pool + retailGroupDuffs at position 6, required += retailGroupDuffs)
  {
    const expectedPool = JSON.parse(JSON.stringify(v9.pool));
    expectedPool.properties.retailGroupDuffs = {
      type: "integer", minimum: 1, maximum: 400000000000, position: 6,
      description:
        "this retail pool's own participant-share amount of the node (one L1 share, the retail split boundary); " +
        "slotDuffs * slotCount == retailGroupDuffs, and retailGroupDuffs <= targetDuffs; " +
        "verified against shareTable[slotIndex] by the L1-backing check (the schema holds only " +
        "the L2 cross-field bounds; clients check the equation, readers check the live L1 share)",
    };
    expectedPool.required = [...v9.pool.required, "retailGroupDuffs"];
    ok("v10 pool equals the complete expected object (v9 pool + retailGroupDuffs)",
      eq(v10.pool, expectedPool));
  }
  ok("retailGroupDuffs is REQUIRED on the v10 pool",
    v10.pool.required.includes("retailGroupDuffs"));
  ok("v10 pool keeps targetDuffs as the node target (unchanged from v9)",
    eq(v9.pool.properties.targetDuffs, v10.pool.properties.targetDuffs));
  ok("v10 pool is immutable / non-deletable / owner-only (carried from v9)",
    v10.pool.documentsMutable === false && v10.pool.canBeDeleted === false &&
    v10.pool.creationRestrictionMode === 1);

  // slotShare: the complete pin, plus its deliberate negative space
  ok("slotShare equals the complete expected object", eq(v10.slotShare, EXPECTED_SLOTSHARE));
  ok("slotShare config flags are exactly the fixed-slot set",
    v10.slotShare.documentsMutable === false && v10.slotShare.canBeDeleted === false &&
    v10.slotShare.transferable === 0 && v10.slotShare.tradeMode === 1 &&
    v10.slotShare.creationRestrictionMode === 1);
  ok("slotShare has NO value fields (no shareBps, no contributionDuffs)",
    !("shareBps" in v10.slotShare.properties) && !("contributionDuffs" in v10.slotShare.properties) &&
    !("contribution" in v10.slotShare.properties));
  ok("slotShare has NO reward-script field",
    !("rewardScript" in v10.slotShare.properties));
  ok("slotShare has ONLY poolId and slot as properties",
    eq(Object.keys(v10.slotShare.properties).sort(), ["poolId", "slot"]));
  {
    const bySlot = v10.slotShare.indices.find((i) => i.name === "bySlot");
    const byOwner = v10.slotShare.indices.find((i) => i.name === "byOwner");
    ok("slotShare bySlot is unique over (poolId, slot)",
      !!bySlot && bySlot.unique === true &&
      eq(bySlot.properties, [{ poolId: "asc" }, { slot: "asc" }]));
    ok("slotShare byOwner exists and is NOT unique (no owner-uniqueness index)",
      !!byOwner && byOwner.unique !== true);
    // constraint 4: no unique (poolId, $ownerId) index anywhere
    const ownerUnique = v10.slotShare.indices.some((i) =>
      i.unique === true &&
      i.properties.some((p) => "$ownerId" in p) &&
      i.properties.some((p) => "poolId" in p));
    ok("slotShare has NO unique (poolId, $ownerId) index (constraint 4)", ownerUnique === false);
  }

  // ---- net 3: the P1 builder-input NEGATIVE cases ----
  const GROUP = 1000000;              // the retail group share (one L1 share)
  const TARGET = 100000000000;        // the whole node target (regular collateral, >> group)
  const good = { targetDuffs: TARGET, retailGroupDuffs: GROUP, slotDuffs: 250000, slotCount: 4 };
  // 250000 * 4 == 1000000 == GROUP, and GROUP <= TARGET

  const rejects = (label, pool) => {
    const errs = checkRetailPoolInvariants(pool);
    ok(`REJECT: ${label} (checkRetailPoolInvariants)`, errs.length > 0);
    let threw = false;
    try { buildV10Pool(pool); } catch { threw = true; }
    ok(`REJECT: ${label} (buildV10Pool throws)`, threw);
  };

  // conforming pool accepted
  ok("ACCEPT: a conforming retail pool passes checkRetailPoolInvariants",
    checkRetailPoolInvariants(good).length === 0);
  ok("ACCEPT: buildV10Pool returns the conforming pool",
    eq(buildV10Pool(good), good));

  // (a) omitting retailGroupDuffs
  {
    const p = { ...good }; delete p.retailGroupDuffs;
    rejects("a pool omitting retailGroupDuffs", p);
  }
  // (b) violating the retail equation (slotDuffs * slotCount != retailGroupDuffs)
  rejects("a pool whose slotDuffs*slotCount != retailGroupDuffs",
    { ...good, slotDuffs: 250001 }); // 250001*4 = 1000004 != 1000000
  // (c) the STALE v9 book: slotDuffs*slotCount == targetDuffs (not retailGroupDuffs)
  rejects("a pool carrying the stale v9 == targetDuffs book",
    { targetDuffs: TARGET, retailGroupDuffs: GROUP, slotDuffs: 25000000000, slotCount: 4 });
    // 25000000000 * 4 == 100000000000 == TARGET != GROUP
  // (d) retailGroupDuffs > targetDuffs
  rejects("a pool with retailGroupDuffs > targetDuffs",
    { targetDuffs: 900000, retailGroupDuffs: 1000000, slotDuffs: 250000, slotCount: 4 });
    // 250000*4 == 1000000 == retailGroupDuffs (equation holds) but 1000000 > 900000

  // the stale case must carry its OWN clear message, not just a generic equation failure
  {
    const stale = { targetDuffs: TARGET, retailGroupDuffs: GROUP, slotDuffs: 25000000000, slotCount: 4 };
    const msg = checkRetailPoolInvariants(stale).join(" ");
    ok("the stale == targetDuffs case is labeled as such", /STALE v9/.test(msg));
  }

  // the UPPER BOUNDS the inherited v9 schema enforces (a v10-builder review finding): the gate
  // must not emit a pool the schema would reject. Exact-bound accepts, bound-plus-one rejects.
  {
    // exact bound: slotCount == MAX_SLOT_COUNT (512), targetDuffs == MAX_DUFFS, equation holds
    const atBound = {
      targetDuffs: MAX_DUFFS, retailGroupDuffs: MAX_SLOT_COUNT,
      slotDuffs: 1, slotCount: MAX_SLOT_COUNT,
    };
    ok("ACCEPT: slotCount == 512 and targetDuffs == MAX_DUFFS (exact schema bounds)",
      checkRetailPoolInvariants(atBound).length === 0);
  }
  // slotCount > 512 (satisfies the equation and the group-to-target relation, but the v9 schema caps slotCount at 512)
  rejects("a pool with slotCount == 513 (over the schema maximum)",
    { targetDuffs: TARGET, retailGroupDuffs: MAX_SLOT_COUNT + 1, slotDuffs: 1, slotCount: MAX_SLOT_COUNT + 1 });
  // targetDuffs > MAX_DUFFS (equation and relation hold, but the schema caps targetDuffs)
  rejects("a pool with targetDuffs == MAX_DUFFS + 1 (over the schema maximum)",
    { targetDuffs: MAX_DUFFS + 1, retailGroupDuffs: 512, slotDuffs: 1, slotCount: 512 });
  // retailGroupDuffs > MAX_DUFFS (relation holds only because targetDuffs is also over-max)
  rejects("a pool with retailGroupDuffs == MAX_DUFFS + 1 (over the schema maximum)",
    { targetDuffs: MAX_DUFFS + 1, retailGroupDuffs: MAX_DUFFS + 1, slotDuffs: MAX_DUFFS + 1, slotCount: 1 });

  // ---- net 4: position hygiene on every v10 type ----
  for (const [t, def] of Object.entries(v10)) {
    const pos = Object.values(def.properties).map((x) => x.position).sort((a, b) => a - b);
    ok(`positions unique+contiguous in ${t}`, pos.every((v, i) => v === i));
  }

  console.log(`contractV10Test: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
})();
