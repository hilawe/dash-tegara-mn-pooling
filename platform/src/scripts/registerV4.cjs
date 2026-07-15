/**
 * Publish the pool-ledger contract v4, consolidating the two schema notes the batch-2
 * review produced (2026-07-11). Derived from the registered v1 definition the same way
 * registerV3.cjs is, carrying v3's two changes forward and adding two of its own, so the
 * diff against registerV3.cjs IS the design change:
 *
 *   1. (carried from v3) rewardAccrual carries a REQUIRED shareBps, making every epoch's
 *      split reconstructible from the ledger alone, churn or no churn.
 *   2. (carried from v3) a `settlement` document type puts the matcher's handover
 *      journal ON the ledger with explicit phases, one settlement per exit request.
 *   3. (new, closes B12) rewardAccrual carries a REQUIRED `kind` ("reward" for an epoch
 *      distribution, "principal" for a dissolution return) and the unique index becomes
 *      [poolId, funderId, epochHeight, kind]. A reward and a principal return CAN land
 *      at the same fork height (a block can pay the node and confirm its dissolution),
 *      and the v3 key could hold only whichever distributed first.
 *   4. (new, closes B9 for real) the settlement byJoin unique index is IN the published
 *      contract. The registered v3 predates it (its definition gained the index in code
 *      after publish, and republishing v3 would have orphaned its ledger); v4 is the
 *      first publish that actually carries it, so Platform itself now refuses a second
 *      settlement against the same join request.
 *
 * The v1/v2/v3 ledgers and their ids are untouched; v4 is a fresh namespace persisted as
 * CONTRACT_V4_ID. Run like the other scripts; select it with LEDGER=v4.
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

  const v4 = JSON.parse(JSON.stringify(poolLedgerContract));

  // 1 + 3. reconstructible accruals, now keyed by kind as well (B12)
  const accrualIndex = v4.rewardAccrual.indices.find((i) => i.name === "byPoolFunder");
  accrualIndex.unique = true;
  accrualIndex.properties = [
    { poolId: "asc" }, { funderId: "asc" }, { epochHeight: "asc" }, { kind: "asc" },
  ];
  v4.rewardAccrual.properties.shareBps = {
    type: "integer", minimum: 1, maximum: 10000, position: 4,
    description: "the funder's share at distribution time, so every epoch is reconstructible",
  };
  v4.rewardAccrual.properties.kind = {
    type: "string", enum: ["reward", "principal"], maxLength: 10, position: 5,
    description: "what this accrual distributes: an epoch reward or a dissolution's principal return",
  };
  v4.rewardAccrual.required.push("shareBps", "kind");
  // pool-scoped listing needs its own index once byPoolFunder is four properties deep:
  // Drive refuses a query that leaves more than two index properties unconstrained
  // ("query is too far from index", observed live on the first v4 publish), so a
  // poolId-only where no longer matches byPoolFunder. The audit, the rail's replay
  // refusal, and the readback all list a pool's accruals, so v4 carries a dedicated
  // non-unique [poolId, epochHeight] index for them.
  v4.rewardAccrual.indices.push({
    name: "byPoolHeight", properties: [{ poolId: "asc" }, { epochHeight: "asc" }],
  });

  // 2 + 4. on-ledger settlements, byJoin unique in the PUBLISHED contract (B9)
  v4.settlement = {
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

    if (env.CONTRACT_V4_ID) {
      console.log("v4 contract already published:", env.CONTRACT_V4_ID);
      return;
    }
    console.log("publishing the pool-ledger v4 contract ...");
    const contract = await client.platform.contracts.create(v4, identity);
    await client.platform.contracts.publish(contract, identity);
    env.CONTRACT_V4_ID = contract.getId().toString();
    saveEnv(env);
    console.log("\n=== POOL-LEDGER V4 PUBLISHED ===");
    console.log("contract id:", env.CONTRACT_V4_ID);
    console.log("(accrual kind inside the unique key + unique byJoin settlements; run everything with LEDGER=v4)");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
