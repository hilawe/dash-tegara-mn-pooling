/**
 * Publish the pool-ledger contract v6, adding the ON-LEDGER PLEDGE RESERVATION the
 * holistic round recorded as the sound answer to formation's concurrent-overfill race
 * (the v5 pledge-time check was advisory: two members reading the same remaining
 * capacity could both submit and overfill, making the exact-fill completion
 * unreachable). Derived from the v1 definition the way registerV3/V4/V5 are, carrying
 * every earlier change forward and adding one document type of its own, so the diff
 * against registerV5.cjs IS the design change:
 *
 *   pledgeSlot: a member's claim on ONE fixed-size collateral slot of a forming pool.
 *     A forming pool is divided into N equal slots (N = target / slotDuffs, so a regular
 *     1000 DASH pool with 100-DASH slots has 10). A member creates a pledgeSlot naming
 *     (poolId, slotNo); the UNIQUE [poolId, slotNo] index makes Platform itself REJECT a
 *     second claim on the same slot, so two concurrent pledges for the last free slot
 *     cannot both win. SCOPE OF THE CONSENSUS GUARANTEE (Option A, refactors review
 *     R1/A1): the ledger enforces exactly that duplicate-slot rejection and nothing
 *     more. Document validation is per-document, so the schema cannot bound slotNo to
 *     the pool's slot count, cannot fix slotDuffs to one pool-wide value, and cannot
 *     require the pool to be forming. Conformance to the slot model is verified at
 *     COMPLETION (formation.cjs refuses and attributes nonconforming claims), and a
 *     nonconforming claim can wedge a forming pool until its owner deletes it; no value
 *     moves either way. The operator-created slot inventory that would move these
 *     bounds on-ledger is the v7 design. A member may hold several slots (several
 *     documents), so contributions still vary in units of the slot size; sub-slot
 *     granularity is out of scope for the reservation. The document carries the
 *     member's own reward script, so formation reads participation and reward
 *     destinations straight from the immutable claims. CANCELLATION REFUTED LIVE
 *     (2026-07-12): this SDK cannot build a delete transition for an immutable
 *     document type (RevisionAbsentError; canBeDeleted does not help), so a v6 claim
 *     is PERMANENT once made, which breaks the cancel-safety requirement. That is why
 *     v7 makes pledgeSlot mutable; do not open new slot books on v6.
 *
 * The v1..v5 ledgers and their ids are untouched; v6 is a fresh namespace persisted as
 * CONTRACT_V6_ID. Run like the other scripts; select it with LEDGER=v6.
 */
const path = require("path");
const { pathToFileURL } = require("url");
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, saveEnv } = require("./envStore.cjs");

const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };
const SCRIPT = { type: "array", byteArray: true, minItems: 1, maxItems: 34 };

(async () => {
  const contractUrl = pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href;
  const { poolLedgerContract } = await import(contractUrl);
  const v6 = JSON.parse(JSON.stringify(poolLedgerContract));

  // ---- carried from v3/v4/v5 (identical to registerV5.cjs) ----
  const accrualIndex = v6.rewardAccrual.indices.find((i) => i.name === "byPoolFunder");
  accrualIndex.unique = true;
  accrualIndex.properties = [
    { poolId: "asc" }, { funderId: "asc" }, { epochHeight: "asc" }, { kind: "asc" },
  ];
  v6.rewardAccrual.properties.shareBps = {
    type: "integer", minimum: 1, maximum: 10000, position: 4,
    description: "the funder's share at distribution time, so every epoch is reconstructible",
  };
  v6.rewardAccrual.properties.kind = {
    type: "string", enum: ["reward", "principal"], maxLength: 10, position: 5,
    description: "what this accrual distributes: an epoch reward or a dissolution's principal return",
  };
  v6.rewardAccrual.required.push("shareBps", "kind");
  v6.rewardAccrual.indices.push({
    name: "byPoolHeight", properties: [{ poolId: "asc" }, { epochHeight: "asc" }],
  });
  v6.settlement = {
    type: "object", documentsMutable: true,
    properties: {
      poolId: { ...HASH32, position: 0 },
      exitId: { ...HASH32, position: 1 }, joinId: { ...HASH32, position: 2 },
      leaverId: { ...HASH32, position: 3 }, joinerId: { ...HASH32, position: 4 },
      amountDuffs: { type: "integer", minimum: 1, position: 5 },
      shareBps: { type: "integer", minimum: 1, maximum: 10000, position: 6 },
      contributionDuffs: { type: "integer", minimum: 0, position: 7 },
      phase: { type: "string", maxLength: 20, position: 8,
        enum: ["prepared", "matched", "share-deleted", "share-recreated", "settled"] },
    },
    required: ["poolId", "exitId", "joinId", "leaverId", "joinerId", "amountDuffs", "shareBps", "phase", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byExit", properties: [{ exitId: "asc" }], unique: true },
      { name: "byJoin", properties: [{ joinId: "asc" }], unique: true },
      { name: "byPoolPhase", properties: [{ poolId: "asc" }, { phase: "asc" }] },
    ],
  };
  v6.pool.properties.status = {
    type: "string", enum: ["forming", "live"], maxLength: 10, position: 5,
    description: "the pool lifecycle: forming (pledge book open, no node yet) or live (a real node backs it)",
  };
  v6.pool.required.push("status");
  v6.membershipRequest.properties.provenance = {
    type: "string", enum: ["fresh", "compound", "pledge"], maxLength: 10, position: 4,
    description: "what funded this request: new capital (fresh, the default when absent), compounded rewards, or a formation pledge",
  };
  v6.membershipRequest.properties.rewardScript = {
    ...SCRIPT, position: 5,
    description: "the member's own L1 reward script, supplied at pledge/join time so formation never derives one for them",
  };
  v6.votePreference.properties.delegateTo = {
    ...HASH32, position: 3,
    description: "with choice delegate: the member identity whose direct choice this weight follows (one hop); absent means follow the pool's leading direct choice",
  };

  // ---- new in v6: the reservation ----
  v6.pledgeSlot = {
    type: "object",
    // immutable, which on this SDK also means UNDELETABLE (no revision, so no delete
    // transition can be built): a v6 claim is permanent once made; see the header
    documentsMutable: false,
    properties: {
      poolId: { ...HASH32, position: 0, description: "the forming pool this slot belongs to" },
      slotNo: { type: "integer", minimum: 0, maximum: 9999, position: 1,
        description: "which equal-size collateral slot of the pool (0..N-1, N = target/slotDuffs)" },
      slotDuffs: { type: "integer", minimum: 1, position: 2,
        description: "the fixed slot size in duffs; every slot of a pool carries the same value" },
      rewardScript: { ...SCRIPT, position: 3, description: "the pledger's own L1 reward destination" },
    },
    required: ["poolId", "slotNo", "slotDuffs", "rewardScript", "$createdAt"],
    additionalProperties: false,
    indices: [
      // the reservation itself: ONE claim per (pool, slot). Platform rejects the
      // duplicate; slot-model conformance (range, size) is verified at completion,
      // see the scope note in the header.
      { name: "bySlot", properties: [{ poolId: "asc" }, { slotNo: "asc" }], unique: true },
      // list a pool's claims, and a member's own claims
      { name: "byPool", properties: [{ poolId: "asc" }] },
      { name: "byOwner", properties: [{ $ownerId: "asc" }, { $createdAt: "asc" }] },
    ],
  };

  const env = loadEnv();
  if (!env.MNEMONIC || !env.IDENTITY_ID) {
    console.error("run register.cjs first (need MNEMONIC, IDENTITY_ID)");
    process.exit(1);
  }
  const clientOpts = { network: process.env.NETWORK || "testnet", wallet: { mnemonic: env.MNEMONIC } };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  try {
    installConsumedFilter(await client.getWalletAccount());
    const identity = await client.platform.identities.get(env.IDENTITY_ID);
    if (env.CONTRACT_V6_ID) { console.log("v6 contract already published:", env.CONTRACT_V6_ID); return; }
    console.log("publishing the pool-ledger v6 contract ...");
    const contract = await client.platform.contracts.create(v6, identity);
    await client.platform.contracts.publish(contract, identity);
    env.CONTRACT_V6_ID = contract.getId().toString();
    saveEnv(env);
    console.log("\n=== POOL-LEDGER V6 PUBLISHED ===");
    console.log("contract id:", env.CONTRACT_V6_ID);
    console.log("(on-ledger pledgeSlot reservation with a unique (poolId, slotNo) index; run with LEDGER=v6)");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
