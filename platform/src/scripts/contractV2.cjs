/**
 * The deferred unique accrual index, demonstrated on a v2 contract (Track C review
 * follow-up). The registered v1 contract's rewardAccrual index [poolId, funderId,
 * epochHeight] is NOT unique, and an index on a registered contract cannot be changed,
 * so the rail defends against duplicate accruals with a read-before-write. This script
 * shows the production shape: a v2 contract identical to v1 except that index is
 * UNIQUE, so Platform itself refuses the duplicate and the read-before-write becomes
 * defense in depth rather than the only line.
 *
 * What it does on the live devnet (the v1 ledger and CONTRACT_ID are untouched):
 *   1. publishes the v2 contract (persisted as CONTRACT_V2_ID; re-runs reuse it),
 *   2. writes a pool and one rewardAccrual under v2,
 *   3. broadcasts an IDENTICAL duplicate accrual and asserts Platform REJECTS it,
 *   4. broadcasts the same accrual at the NEXT epoch height and asserts it lands
 *      (the uniqueness is per [pool, funder, epoch], not a blanket lock).
 *
 * Run like the other scripts (container, --network host, CA mounted).
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { pathToFileURL } = require("url");
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, saveEnv } = require("./envStore.cjs");


(async () => {
  const contractUrl = pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href;
  const { poolLedgerContract } = await import(contractUrl);

  // v2 = v1 with two rewardAccrual changes; everything else byte-identical, so the two
  // versions stay comparable and the diff IS the design change:
  //   1. the [poolId, funderId, epochHeight] index is UNIQUE (Platform refuses duplicates),
  //   2. shareBps is recorded IN the accrual. This is a SECURITY REQUIREMENT, not an
  //      enhancement (review finding F7, 2026-07-11): shares deleted in a membership
  //      churn leave no tombstone, so without the bps in the accrual a churned epoch's
  //      split is unverifiable from the ledger and a skewed allocation passes a sum check.
  const v2 = JSON.parse(JSON.stringify(poolLedgerContract));
  const accrualIndex = v2.rewardAccrual.indices.find((i) => i.name === "byPoolFunder");
  accrualIndex.unique = true;
  v2.rewardAccrual.properties.shareBps = {
    type: "integer", minimum: 1, maximum: 10000, position: 4,
    description: "the funder share at distribution time, so every epoch is reconstructible",
  };
  v2.rewardAccrual.required.push("shareBps");

  const env = loadEnv();
  if (!env.MNEMONIC || !env.IDENTITY_ID) {
    console.error("run register.cjs first (need MNEMONIC, IDENTITY_ID)");
    process.exit(1);
  }
  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
    apps: env.CONTRACT_V2_ID ? { poolLedgerV2: { contractId: env.CONTRACT_V2_ID } } : {},
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  try {
    installConsumedFilter(await client.getWalletAccount());
    let identity = await client.platform.identities.get(env.IDENTITY_ID);

    // a persisted v2 id from before the shareBps requirement is superseded: detect the
    // missing property on the published schema and publish the current shape instead
    if (env.CONTRACT_V2_ID) {
      const existing = await client.platform.contracts.get(env.CONTRACT_V2_ID).catch(() => null);
      const schema = existing && existing.getDocumentSchema
        ? existing.getDocumentSchema("rewardAccrual") : null;
      const hasBps = schema && schema.properties && schema.properties.shareBps;
      if (!hasBps) {
        console.log("persisted v2 contract predates shareBps-in-accrual; publishing the current shape");
        delete env.CONTRACT_V2_ID;
      }
    }
    if (!env.CONTRACT_V2_ID) {
      console.log("publishing the v2 contract (unique accrual index + shareBps in the accrual) ...");
      const contract = await client.platform.contracts.create(v2, identity);
      await client.platform.contracts.publish(contract, identity);
      env.CONTRACT_V2_ID = contract.getId().toString();
      saveEnv(env);
      client.getApps().set("poolLedgerV2", {
        contractId: contract.getId(), contract,
      });
      console.log("v2 contract published:", env.CONTRACT_V2_ID);
    } else {
      console.log("v2 contract already published:", env.CONTRACT_V2_ID);
    }

    // a throwaway pool + accrual under v2
    const pool = await client.platform.documents.create("poolLedgerV2.pool", identity, {
      proTxHash: crypto.randomBytes(32), slotIndex: 0, nodeType: "regular",
      operatorIdentityId: identity.getId().toBuffer(), operatorFeeBps: 2000,
    });
    await client.platform.documents.broadcast({ create: [pool] }, identity);
    console.log("v2 pool created:", pool.getId().toString());

    const accrualFields = {
      poolId: pool.getId().toBuffer(),
      funderId: identity.getId().toBuffer(),
      amountDuffs: 12345,
      epochHeight: 264,
      shareBps: 6000,
    };
    const a1 = await client.platform.documents.create("poolLedgerV2.rewardAccrual", identity, accrualFields);
    await client.platform.documents.broadcast({ create: [a1] }, identity);
    console.log("first accrual accepted at epoch 264");

    // the duplicate MUST be refused by Platform itself
    const a2 = await client.platform.documents.create("poolLedgerV2.rewardAccrual", identity, accrualFields);
    let rejected = false;
    try {
      await client.platform.documents.broadcast({ create: [a2] }, identity);
    } catch (e) {
      rejected = true;
      console.log("duplicate accrual REFUSED by Platform:", ((e && e.message) || "").slice(0, 140));
    }
    if (!rejected) throw new Error("Platform ACCEPTED a duplicate accrual under the unique v2 index");

    // and the next epoch height must still be fine
    const a3 = await client.platform.documents.create("poolLedgerV2.rewardAccrual", identity,
      { ...accrualFields, epochHeight: 265 });
    await client.platform.documents.broadcast({ create: [a3] }, identity);
    console.log("same funder at epoch 265 accepted (uniqueness is per pool/funder/epoch)");

    console.log("\n=== V2 UNIQUE ACCRUAL INDEX DEMONSTRATED: Platform refuses the duplicate; " +
      "the rail's read-before-write becomes defense in depth ===");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
