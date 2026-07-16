/**
 * Publish flow for the pool-ledger contract v9, a source-only DRAFT that is
 * deliberately UNPUBLISHED. The schema, the design rationale, and the adoption
 * checklist live in contractV9.cjs (the pure builder this file consumes);
 * contractV9Test.cjs pins the intended v8-to-v9 diff offline. v8 remains the live
 * ledger, nothing selects v9, and this script refuses to run without an explicit
 * confirm. The flow itself is the registerV8.cjs shape: the registration-wide op
 * lock, the durable publish-intent marker before the irreversible broadcast, and the
 * locked single-key env writes (CONTRACT_V9_PENDING / CONTRACT_V9_ID are protected
 * owned keys in envStore, same as the v8 pair, so a concurrent stale save cannot
 * erase the publish record).
 */
const path = require("path");
const { pathToFileURL } = require("url");
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, updateEnvKey, acquireOpLock, releaseOpLock } = require("./envStore.cjs");
const { buildV9 } = require("./contractV9.cjs");

(async () => {
  // DRAFT GATE: v8 is the working ledger; publishing v9 costs a nonce and a fee and
  // opens a namespace nothing selects. Refuse by default so the draft cannot publish
  // by accident.
  if (process.env.REGISTER_V9_CONFIRM !== "1") {
    console.error("registerV9 is a source-only DRAFT: v8 is the live ledger and no v9 publish " +
      "occasion exists yet. Re-run with REGISTER_V9_CONFIRM=1 only when a new contract version " +
      "is actually warranted (see contractV9.cjs for the adoption checklist).");
    process.exit(1);
  }

  const contractUrl = pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href;
  const { poolLedgerContract } = await import(contractUrl);
  const v9 = buildV9(poolLedgerContract);

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

  // serialize concurrent register runs (same shape as registerV8; see its comments for
  // why the lock is unconditional and why the pending marker precedes the broadcast)
  let heldRegLock = false;
  try {
    acquireOpLock("registerV9"); heldRegLock = true;
    installConsumedFilter(await client.getWalletAccount());
    const identity = await client.platform.identities.get(env.IDENTITY_ID);
    if (loadEnv().CONTRACT_V9_ID) { console.log("v9 contract already published:", loadEnv().CONTRACT_V9_ID); return; }
    env.CONTRACT_V9_PENDING = loadEnv().CONTRACT_V9_PENDING; // re-read under the lock
    if (env.CONTRACT_V9_PENDING === "1" && process.env.REGISTER_V9_FORCE !== "1") {
      throw new Error("a prior v9 publish recorded intent (CONTRACT_V9_PENDING) but no CONTRACT_V9_ID, " +
        "so a previous run may have published a contract whose id was never saved. Check the publishing " +
        "identity's contracts for an orphan before republishing; if none exists, re-run with " +
        "REGISTER_V9_FORCE=1 to publish a fresh one.");
    }
    updateEnvKey("CONTRACT_V9_PENDING", "1"); // intent, before the irreversible broadcast
    console.log("publishing the pool-ledger v9 contract ...");
    const contract = await client.platform.contracts.create(v9, identity);
    await client.platform.contracts.publish(contract, identity);
    env.CONTRACT_V9_ID = contract.getId().toString();
    updateEnvKey("CONTRACT_V9_ID", env.CONTRACT_V9_ID);
    updateEnvKey("CONTRACT_V9_PENDING", undefined); // intent discharged
    console.log("\n=== POOL-LEDGER V9 PUBLISHED ===");
    console.log("contract id:", env.CONTRACT_V9_ID);
    console.log("(v8 + the immutable owner-only pool, the pared completion record, consensus slot bounds; " +
      "run with LEDGER=v9 after the adoption checklist in contractV9.cjs)");
    console.log("POST-PUBLISH PROBES REQUIRED: non-owner pool creation refused, pool replace refused, " +
      "pool delete refused, one-sided slot-field variants refused, receipt bySlot uniqueness enforced.");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (heldRegLock) releaseOpLock("registerV9");
    if (client.disconnect) await client.disconnect();
  }
})();
