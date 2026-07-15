/**
 * Publish the pool-ledger contract v3, the production-shape consolidation the reviews
 * pointed at (2026-07-11). Derived from the registered v1 definition so the diff IS the
 * design change:
 *
 *   1. rewardAccrual carries a REQUIRED shareBps and its [poolId, funderId, epochHeight]
 *      index is UNIQUE (both demonstrated on the v2 contract first). With the bps in the
 *      accrual and the accruals' own creation order, EVERY epoch's split is
 *      reconstructible from the ledger alone, churn or no churn, which closes the
 *      "churned epoch unverifiable" gap at its root. (The separate allocation-manifest
 *      document the review floated adds nothing over this for the prototype: the accrual
 *      rows ARE the manifest once they carry the bps and an order.)
 *   2. a new `settlement` document type puts the matcher's handover journal ON the
 *      ledger, visible to every engine, instead of a local file: it binds the two
 *      request ids, snapshots the leaving share's bps and contribution BEFORE any
 *      mutation, and walks the same explicit phases as the local journal. One
 *      settlement per exit request (unique index).
 *
 * The v1 ledger and CONTRACT_ID are untouched; v3 is a fresh namespace persisted as
 * CONTRACT_V3_ID. Run like the other scripts.
 */
const path = require("path");
const { pathToFileURL } = require("url");
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, saveEnv } = require("./envStore.cjs");

const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };

(async () => {
  const contractUrl = pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href;
  const { poolLedgerContract } = await import(contractUrl);

  const v3 = JSON.parse(JSON.stringify(poolLedgerContract));

  // 1. reconstructible accruals
  // KNOWN v3 LIMITATION (review batch-2, B12): epochHeight alone keys a pool's
  // distribution events, but a reward and a dissolution can land at the SAME fork height,
  // and this unique index then cannot hold both. v4 adds a `kind` field
  // ("reward" | "principal") to rewardAccrual inside the unique index (registerV4.cjs).
  v3.rewardAccrual.indices.find((i) => i.name === "byPoolFunder").unique = true;
  v3.rewardAccrual.properties.shareBps = {
    type: "integer", minimum: 1, maximum: 10000, position: 4,
    description: "the funder's share at distribution time, so every epoch is reconstructible",
  };
  v3.rewardAccrual.required.push("shareBps");

  // 2. on-ledger settlements
  v3.settlement = {
    type: "object",
    documentsMutable: true,
    properties: {
      poolId: { ...HASH32, position: 0 },
      exitId: { ...HASH32, position: 1, description: "the exit membershipRequest document id" },
      joinId: { ...HASH32, position: 2, description: "the join membershipRequest document id" },
      leaverId: { ...HASH32, position: 3 },
      joinerId: { ...HASH32, position: 4 },
      amountDuffs: { type: "integer", minimum: 1, position: 5 },
      shareBps: { type: "integer", minimum: 1, maximum: 10000, position: 6 },
      contributionDuffs: { type: "integer", minimum: 0, position: 7 },
      phase: {
        type: "string", maxLength: 20, position: 8,
        enum: ["prepared", "matched", "share-deleted", "share-recreated", "settled"],
      },
    },
    required: ["poolId", "exitId", "joinId", "leaverId", "joinerId", "amountDuffs",
      "shareBps", "phase", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byExit", properties: [{ exitId: "asc" }], unique: true },
      // one settlement per JOIN as well (review finding B9): the already-published demo
      // contract predates this index (republishing would orphan its ledger); every future
      // publish carries it, and the matcher independently verifies snapshots either way
      { name: "byJoin", properties: [{ joinId: "asc" }], unique: true },
      { name: "byPoolPhase", properties: [{ poolId: "asc" }, { phase: "asc" }] },
    ],
  };

  const env = loadEnv();
  if (!env.MNEMONIC || !env.IDENTITY_ID) {
    console.error("run register.cjs first (need MNEMONIC, IDENTITY_ID)");
    process.exit(1);
  }
  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  try {
    installConsumedFilter(await client.getWalletAccount());
    const identity = await client.platform.identities.get(env.IDENTITY_ID);

    if (env.CONTRACT_V3_ID) {
      console.log("v3 contract already published:", env.CONTRACT_V3_ID);
      return;
    }
    console.log("publishing the pool-ledger v3 contract ...");
    const contract = await client.platform.contracts.create(v3, identity);
    await client.platform.contracts.publish(contract, identity);
    env.CONTRACT_V3_ID = contract.getId().toString();
    saveEnv(env);
    console.log("\n=== POOL-LEDGER V3 PUBLISHED ===");
    console.log("contract id:", env.CONTRACT_V3_ID);
    console.log("(reconstructible accruals + on-ledger settlements; run everything with LEDGER=v3)");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
