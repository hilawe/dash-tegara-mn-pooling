/**
 * Publish the pool-ledger contract v8: v7 plus ONE new document type, the on-ledger
 * COMPLETION RECEIPT. The design is docs/COMPLETION_RECEIPT_SPEC.md (design-reviewed
 * twice, three models each round); the offline helper it depends on is formationCore's
 * allocationPreimage/allocationHash/verifyReceiptAllocation (its own review record).
 *
 * What the receipt is: the immutable on-ledger form of the formation completion record,
 * so a third party can see that a pool completed and exactly what allocation it
 * committed to, from the receipt alone (the canonical allocation preimage is EMBEDDED
 * as allocationRows; allocationHash is its sha256 content id). What it does NOT attest
 * (the honesty ceiling, stated in the spec and repeated here): consensus establishes
 * only that the pool's own operator recorded exactly one immutable receipt per pool;
 * it does not prove the L1 registration matched, that the shares still match, or that
 * the claimed verification level was actually performed.
 *
 * Schema decisions (all forced by the review rounds, see the spec's notes):
 *   - documentsMutable:false + canBeDeleted:false + creationRestrictionMode:1
 *     (owner-only creation, closes receipt squatting; the byPool unique index makes
 *     the receipt one-per-pool, so without owner-only ANY identity could occupy it).
 *   - allocationRows is a bounded byteArray (maxItems 2048; worst case ~1.4 KB at the
 *     8-owner cap), the EXACT bytes of formationCore.allocationPreimage().
 *   - l1Verification is the SCOPED enum (the check's real strength, not "verified").
 *   - participantCount 1..8 is the DIRECT covenant-participant bound, enforced by
 *     formation before COMMIT; it is not a general Platform-allocation count.
 *
 * The v1..v7 ledgers and their ids are untouched; v8 is a fresh namespace persisted as
 * CONTRACT_V8_ID. Run like the other scripts; select it with LEDGER=v8.
 */
const path = require("path");
const { pathToFileURL } = require("url");
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, updateEnvKey, acquireOpLock, releaseOpLock } = require("./envStore.cjs");
const { buildV8 } = require("./contractV8.cjs");

(async () => {
  const contractUrl = pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href;
  const { poolLedgerContract } = await import(contractUrl);
  // the schema construction lives in contractV8.cjs (extracted verbatim so the v9
  // builder and the offline schema test can consume it); this file keeps the flow
  const v8 = buildV8(poolLedgerContract);

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

  // serialize concurrent register runs (round-7 re-check P1): two starts can both load a
  // marker-free env and both publish; a registration-wide op lock makes the second wait.
  // registerV8 requires the shared state dir regardless (it persists owned keys through
  // updateEnvKey, which needs it), so acquire the registration-wide lock unconditionally;
  // its absence is a clear "mount .env.local.state" refusal, the same requirement the
  // pending/ID writes below have.
  let heldRegLock = false;
  try {
    acquireOpLock("registerV8"); heldRegLock = true;
    installConsumedFilter(await client.getWalletAccount());
    const identity = await client.platform.identities.get(env.IDENTITY_ID);
    if (loadEnv().CONTRACT_V8_ID) { console.log("v8 contract already published:", loadEnv().CONTRACT_V8_ID); return; }
    env.CONTRACT_V8_PENDING = loadEnv().CONTRACT_V8_PENDING; // re-read under the lock
    // DURABLE PUBLISH INTENT (round-7 P2): publishing consumes the identity nonce, so a
    // crash AFTER publish but BEFORE the id is persisted must NOT silently republish (that
    // burns another nonce and leaves an orphaned paid contract under an ambiguous
    // namespace). A pending marker recorded before the broadcast makes that state loud:
    // the resume refuses and points the operator at the possible orphan to reconcile by
    // hand. (registerV3..V7 share this write-after-publish shape; recorded as follow-on.)
    if (env.CONTRACT_V8_PENDING === "1" && process.env.REGISTER_V8_FORCE !== "1") {
      throw new Error("a prior v8 publish recorded intent (CONTRACT_V8_PENDING) but no CONTRACT_V8_ID, " +
        "so a previous run may have published a contract whose id was never saved. Check the publishing " +
        "identity's contracts for an orphan before republishing; if none exists, re-run with " +
        "REGISTER_V8_FORCE=1 to publish a fresh one.");
    }
    updateEnvKey("CONTRACT_V8_PENDING", "1"); // intent, before the irreversible broadcast
    console.log("publishing the pool-ledger v8 contract ...");
    const contract = await client.platform.contracts.create(v8, identity);
    await client.platform.contracts.publish(contract, identity);
    // persist ONLY the new id through the locked single-key writer (round-6): a full
    // saveEnv of the snapshot loaded before the network awaits above would replace plain
    // keys from a stale copy and could erase a concurrent onboarding write (e.g. FUNDER_ID)
    env.CONTRACT_V8_ID = contract.getId().toString();
    updateEnvKey("CONTRACT_V8_ID", env.CONTRACT_V8_ID);
    updateEnvKey("CONTRACT_V8_PENDING", undefined); // intent discharged
    console.log("\n=== POOL-LEDGER V8 PUBLISHED ===");
    console.log("contract id:", env.CONTRACT_V8_ID);
    console.log("(v7 + the immutable owner-only completionReceipt; run with LEDGER=v8)");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (heldRegLock) releaseOpLock("registerV8");
    if (client.disconnect) await client.disconnect();
  }
})();
