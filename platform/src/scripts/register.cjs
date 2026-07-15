/**
 * Register the pool-ledger data contract on Dash Platform (env-configurable network + DAPI). Re-runnable:
 *   1st run  -> generates a testnet wallet, saves the mnemonic to .env.local (gitignored),
 *               prints the address to fund from the faucet, and exits.
 *   next run -> once funded, registers a Platform identity, then publishes the contract.
 * State (mnemonic, identity id, contract id) persists in .env.local so re-runs resume.
 */
const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");
const Dash = require("dash");

// the shared env store (holistic-round F2): register.cjs used to write .env.local
// directly with no lock and no atomic replacement, so it could tear or clobber the
// durable journals; it now goes through the same locked, owned-key-preserving path as
// every other writer
const { loadEnv, saveEnv } = require("./envStore.cjs");

(async () => {
  const contractUrl = pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href;
  const { poolLedgerContract } = await import(contractUrl);

  const env = loadEnv();
  const network = process.env.NETWORK || "testnet";
  const clientOpts = { network, wallet: { mnemonic: env.MNEMONIC || null } };
  if (process.env.DAPI_HOST) {
    clientOpts.dapiAddresses = [{
      host: process.env.DAPI_HOST,
      port: parseInt(process.env.DAPI_PORT || "2443", 10),
      protocol: "https",
    }];
  }
  const client = new Dash.Client(clientOpts);

  try {
    console.log(`connecting and syncing wallet on ${network} (first sync can take a minute) ...`);
    const account = await client.getWalletAccount();

    if (!env.MNEMONIC) {
      env.MNEMONIC = client.wallet.exportWallet();
      saveEnv(env);
      console.log("generated a new wallet; mnemonic saved to .env.local (gitignored)");
    }

    const address = account.getUnusedAddress().address;
    const balance = account.getTotalBalance();
    console.log("wallet address :", address);
    console.log("balance (duffs):", balance);

    // an identity registration plus a contract publish needs a few DASH of headroom
    if (balance < 5000000) {
      console.log("\nNeed funds. Send some DASH to the address above, then re-run this script.");
      console.log("  local devnet: fund from the dashmate seed Core wallet, then mine a block");
      console.log("  testnet:      https://faucet.testnet.networks.dash.org/");
      return;
    }

    let identity;
    if (env.IDENTITY_ID) {
      identity = await client.platform.identities.get(env.IDENTITY_ID);
      console.log("using existing identity:", env.IDENTITY_ID);
    } else {
      console.log("registering a Platform identity ...");
      identity = await client.platform.identities.register();
      env.IDENTITY_ID = identity.getId().toString();
      saveEnv(env);
      console.log("identity registered:", env.IDENTITY_ID);
    }

    if (env.CONTRACT_ID) {
      console.log("\npool-ledger contract already published:", env.CONTRACT_ID);
      return;
    }

    // A contract publish costs credits; top up the identity if its balance is low.
    const MIN_CREDITS = 40000000000;
    if (identity.getBalance() < MIN_CREDITS) {
      console.log(`identity credits ${identity.getBalance()} below ${MIN_CREDITS}; topping up ...`);
      await client.platform.identities.topUp(identity.getId(), 200000000); // 2 DASH in duffs
      identity = await client.platform.identities.get(env.IDENTITY_ID);
      console.log("identity credits now:", identity.getBalance());
    }

    console.log("creating the pool-ledger data contract ...");
    const contract = await client.platform.contracts.create(poolLedgerContract, identity);
    const cid = contract.getId().toString();

    const existing = await client.platform.contracts.get(cid).catch(() => null);
    if (existing) {
      env.CONTRACT_ID = cid;
      saveEnv(env);
      console.log("\n=== POOL-LEDGER CONTRACT IS ON PLATFORM ===");
      console.log("contract id:", cid);
      return;
    }

    console.log("publishing contract", cid, "...");
    await client.platform.contracts.publish(contract, identity);
    env.CONTRACT_ID = cid;
    saveEnv(env);
    console.log("\n=== POOL-LEDGER CONTRACT PUBLISHED ===");
    console.log("contract id:", cid);
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 5).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
