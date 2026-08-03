/**
 * One-time setup for the cast-receipt live demonstration: a pool document for the given
 * masternode (the operator's write) plus two member shares (each funder's own write,
 * 6000/4000 bps at the usual demo scale), so the governor and the receipt have a real
 * membership to tally. Idempotent: an existing pool for the proTxHash is reused and
 * existing shares are left alone.
 *
 * Run: LEDGER=v4 ... castDemoSetup.cjs <proTxHash 64-hex>
 */
const crypto = require("crypto");
const Dash = require("dash");
const { Identifier } = require("@dashevo/wasm-dpp");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, activeContractId, isV5, hasImmutablePool } = require("./envStore.cjs");
const { resolveNodeToPools } = require("./receiptPoolCheck.cjs");

const p2pkh = (h20) => Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), h20, Buffer.from([0x88, 0xac])]);

(async () => {
  const [proTxHex] = process.argv.slice(2);
  if (!/^[0-9a-f]{64}$/i.test(proTxHex || "")) {
    console.error("usage: castDemoSetup.cjs <proTxHash 64-hex>");
    process.exit(2);
  }
  const env = loadEnv();
  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
    apps: { poolLedger: { contractId: activeContractId(env) } },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  try {
    installConsumedFilter(await client.getWalletAccount());
    const operator = await client.platform.identities.get(env.IDENTITY_ID);

    // discovery: the pool records the node on v8, and only a VERIFIED completion receipt does
    // on v9, so the immutable path goes receipt-first through the shared resolver. A receipt
    // that fails to verify REFUSES rather than resolving to nothing, because nothing here
    // falls through to creating a second pool over a contradiction.
    let pool;
    if (hasImmutablePool()) {
      const res = await resolveNodeToPools({
        contractId: activeContractId(env), nodeHash: Buffer.from(proTxHex, "hex"), slotIndex: 0,
        fetchReceipts: (hash, slot) => client.platform.documents.get("poolLedger.completionReceipt", {
          where: [["proTxHash", "==", hash], ["slotIndex", "==", slot]],
        }),
        fetchPoolById: async (pid) => (await client.platform.documents.get("poolLedger.pool", {
          where: [["$id", "==", Identifier.from(Buffer.from(pid))]],
        }))[0] || null,
      });
      if (!res.ok) throw new Error(`${res.reason} (node ${proTxHex} slot 0)`);
      pool = res.pools[0];
    } else {
      pool = (await client.platform.documents.get("poolLedger.pool", {
        where: [["proTxHash", "==", Buffer.from(proTxHex, "hex")]],
      }))[0];
    }
    if (pool) {
      // reuse only a pool that matches what this setup would have created; silently
      // accepting a repurposed pool announces a demo state that the governor and the
      // receipt would then contradict (batch-3 review finding)
      const po = pool.toObject();
      // v9 drops the duplicate operatorIdentityId because the operator IS the document owner
      // under owner-only creation, so $ownerId is the stronger form of the same check
      const poOperator = hasImmutablePool()
        ? pool.getOwnerId().toString()
        : (po.operatorIdentityId
            ? Identifier.from(Buffer.from(po.operatorIdentityId)).toString() : null);
      if (poOperator !== operator.getId().toString()) {
        throw new Error(`existing pool for this masternode is operated by ${poOperator}, not this ` +
          "identity; refusing to reuse it");
      }
      if (Number(po.operatorFeeBps || 0) !== 2000 || Number(po.slotIndex) !== 0) {
        throw new Error(`existing pool has fee ${Number(po.operatorFeeBps || 0)} bps, slot ` +
          `${Number(po.slotIndex)}; expected 2000 bps, slot 0. Refusing to reuse it`);
      }
      console.log("pool already exists (operator, fee, and slot verified):", pool.getId().toString());
    } else {
      // same refusal as the credit rail, and for the same reason: this creator makes a pool
      // that is LIVE AT BIRTH, which v8 expresses by writing proTxHash and status. v9 has
      // neither, and its equivalent is a completion receipt built from a frozen manifest a
      // demo setup has never held. Minting a receipt-less pool here would produce exactly the
      // permanently ambiguous document the admission rule must fail closed against.
      if (hasImmutablePool()) {
        throw new Error("no pool is recorded for this masternode, and castDemoSetup does not create " +
          "pools on an immutable-pool ledger: a pool that is live at birth needs a completion receipt, " +
          "which only a formation round can produce. Form the pool with formation.cjs first.");
      }
      pool = await client.platform.documents.create("poolLedger.pool", operator, {
        proTxHash: Buffer.from(proTxHex, "hex"),
        slotIndex: 0,
        nodeType: "regular",
        operatorIdentityId: operator.getId().toBuffer(),
        operatorFeeBps: 2000,
        // v5 requires the lifecycle field; these pools back nodes, hence live (F5)
        ...(isV5() ? { status: "live" } : {}),
      });
      await client.platform.documents.broadcast({ create: [pool] }, operator);
      console.log("pool created:", pool.getId().toString());
    }
    const poolId = pool.getId();

    const members = [
      { envKey: "FUNDER_ID", label: "funder1", bps: 6000 },
      { envKey: "FUNDER2_ID", label: "funder2", bps: 4000 },
    ];
    for (const m of members) {
      if (!env[m.envKey]) throw new Error(`${m.envKey} missing; run the rail once to register funders`);
      const identity = await client.platform.identities.get(env[m.envKey]);
      const mine = (await client.platform.documents.get("poolLedger.share", {
        where: [["poolId", "==", poolId], ["$ownerId", "==", identity.getId()]],
      }))[0];
      if (mine) {
        const gotBps = Number(mine.toObject().shareBps);
        if (gotBps !== m.bps) {
          throw new Error(`${m.label} already holds ${gotBps} bps in this pool, expected ${m.bps}; ` +
            "refusing to announce a demo state the tally would contradict");
        }
        console.log(`${m.label} share already exists (${gotBps} bps, verified)`);
        continue;
      }
      const doc = await client.platform.documents.create("poolLedger.share", identity, {
        poolId: poolId.toBuffer(),
        shareBps: m.bps,
        contributionDuffs: m.bps * 100000,
        l1RewardScript: p2pkh(crypto.randomBytes(20)),
      });
      await client.platform.documents.broadcast({ create: [doc] }, identity);
      console.log(`${m.label} share created: ${m.bps} bps`);
    }
    console.log(`\n=== CAST DEMO POOL READY: ${poolId.toString()} (masternode ${proTxHex.slice(0, 16)}...) ===`);
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
