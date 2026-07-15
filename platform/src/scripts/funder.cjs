/**
 * Exercise the self-sovereign funder actions against the live pool-ledger contract:
 *   - the operator identity creates a `pool` document (a shared node / #187 slot),
 *   - a separate funder identity creates a `share`, submits a join `membershipRequest`,
 *     and sets a `votePreference`, all signed by the funder itself,
 *   - then read the pool and its shares back from Platform.
 *
 * Reuses the wallet, operator identity, and contract id from .env.local (produced by register.cjs).
 * The funder identity is registered on first run and persisted (FUNDER_ID). A fresh random pool
 * identifier is used per run so the unique indices do not collide.
 *
 * Env: NETWORK, DAPI_HOST[/DAPI_PORT] (same as register.cjs).
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, saveEnv, isV5 } = require("./envStore.cjs");


const MIN_CREDITS = 40000000000;
const TOPUP_DUFFS = 300000000; // 3 DASH
const p2pkh = (h20) => Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), h20, Buffer.from([0x88, 0xac])]);

(async () => {
  const env = loadEnv();
  if (!env.MNEMONIC || !env.IDENTITY_ID || !env.CONTRACT_ID) {
    console.error("run register.cjs first (need MNEMONIC, IDENTITY_ID, CONTRACT_ID in .env.local)");
    process.exit(1);
  }

  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
    apps: { poolLedger: { contractId: env.CONTRACT_ID } },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  const ensureCredits = async (id) => {
    if (id.getBalance() < MIN_CREDITS) {
      console.log(`  topping up ${id.getId().toString()} (credits ${id.getBalance()}) ...`);
      await client.platform.identities.topUp(id.getId(), TOPUP_DUFFS);
      return client.platform.identities.get(id.getId().toString());
    }
    return id;
  };

  try {
    installConsumedFilter(await client.getWalletAccount());

    // operator (already registered by register.cjs)
    let operator = await client.platform.identities.get(env.IDENTITY_ID);
    operator = await ensureCredits(operator);

    // funder identity: register once, persist
    let funder;
    if (env.FUNDER_ID) {
      funder = await client.platform.identities.get(env.FUNDER_ID);
      console.log("funder identity:", env.FUNDER_ID);
    } else {
      console.log("registering funder identity ...");
      funder = await client.platform.identities.register();
      env.FUNDER_ID = funder.getId().toString(); saveEnv(env);
      console.log("funder identity registered:", env.FUNDER_ID);
    }
    funder = await ensureCredits(funder);

    // operator creates a pool
    const proTxHash = crypto.randomBytes(32);
    const poolDoc = await client.platform.documents.create("poolLedger.pool", operator, {
      proTxHash,
      slotIndex: 0,
      nodeType: "regular",
      operatorIdentityId: operator.getId().toBuffer(),
      operatorFeeBps: 2000,
      // v5 requires the lifecycle field; these pools back nodes, hence live (F5)
      ...(isV5() ? { status: "live" } : {}),
    });
    await client.platform.documents.broadcast({ create: [poolDoc] }, operator);
    const poolId = poolDoc.getId();
    console.log("pool created:", poolId.toString());

    // funder creates a share, a join request, and a vote preference.
    // Platform allows only one document transition per state transition, so broadcast each separately.
    const share = await client.platform.documents.create("poolLedger.share", funder, {
      poolId: poolId.toBuffer(),
      shareBps: 1500,
      contributionDuffs: 150000000,
      l1RewardScript: p2pkh(crypto.randomBytes(20)),
    });
    await client.platform.documents.broadcast({ create: [share] }, funder);
    console.log("funder created share:", share.getId().toString());

    const req = await client.platform.documents.create("poolLedger.membershipRequest", funder, {
      poolId: poolId.toBuffer(), kind: "join", amountDuffs: 150000000, status: "pending",
    });
    await client.platform.documents.broadcast({ create: [req] }, funder);
    console.log("funder submitted join request:", req.getId().toString());

    const vote = await client.platform.documents.create("poolLedger.votePreference", funder, {
      poolId: poolId.toBuffer(), proposalHash: crypto.randomBytes(32), choice: "delegate",
    });
    await client.platform.documents.broadcast({ create: [vote] }, funder);
    console.log("funder set vote preference:", vote.getId().toString());

    // read back
    const pools = await client.platform.documents.get("poolLedger.pool", {
      where: [["$id", "==", poolId]],
    });
    const shares = await client.platform.documents.get("poolLedger.share", {
      where: [["poolId", "==", poolId]],
    });
    console.log("\nreadback: pools found =", pools.length, ", shares in pool =", shares.length);
    if (shares.length) {
      const s = shares[0].toObject();
      console.log("  share: shareBps", s.shareBps, "contributionDuffs", s.contributionDuffs,
        "owner", shares[0].getOwnerId().toString());
    }
    console.log("\n=== FUNDER ACTIONS OK on the live pool-ledger contract ===");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
