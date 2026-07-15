/**
 * Live demonstration that the v4 contract's unique byJoin settlement index (review
 * finding B9) is enforced by Platform itself: attempt to create a SECOND settlement
 * referencing an already-settled join request (fresh exitId, so the byExit index does
 * not fire first) and expect Drive to refuse it. Mirrors how contractV2.cjs
 * demonstrated the unique accrual index. Read-mostly: on the expected refusal nothing
 * is written; if Platform ever ACCEPTED the duplicate, the script deletes it and exits
 * non-zero.
 *
 * Run: LEDGER=v4 ... demoB9.cjs <settlementDocId>
 */
const crypto = require("crypto");
const Dash = require("dash");
const { Identifier } = require("@dashevo/wasm-dpp");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, activeContractId, isV4 } = require("./envStore.cjs");

(async () => {
  const [settlementIdStr] = process.argv.slice(2);
  if (!settlementIdStr || !isV4()) {
    console.error("usage: LEDGER=v4 node src/scripts/demoB9.cjs <settlement document id>");
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
    const existing = (await client.platform.documents.get("poolLedger.settlement", {
      where: [["$id", "==", Identifier.from(settlementIdStr)]],
    }))[0];
    if (!existing) throw new Error(`no settlement ${settlementIdStr} on the v4 ledger`);
    const o = existing.toObject();
    const owner = existing.getOwnerId().toString();
    const ownerIdentity = await client.platform.identities.get(owner);
    console.log(`existing settlement ${settlementIdStr} (phase ${o.phase}, owner ${owner})`);

    const dup = await client.platform.documents.create("poolLedger.settlement", ownerIdentity, {
      poolId: Buffer.from(o.poolId),
      exitId: crypto.randomBytes(32), // fresh, so byExit does not fire; byJoin must
      joinId: Buffer.from(o.joinId),
      leaverId: Buffer.from(o.leaverId),
      joinerId: Buffer.from(o.joinerId),
      amountDuffs: Number(o.amountDuffs),
      shareBps: Number(o.shareBps),
      contributionDuffs: Number(o.contributionDuffs || 0),
      phase: "prepared",
    });
    // the catch covers ONLY the create broadcast, and only the byJoin refusal counts
    // as confirmation; cleanup after an unexpected acceptance runs separately so its
    // own failure can never be misreported as success (batch-3 review finding)
    let accepted = false;
    try {
      await client.platform.documents.broadcast({ create: [dup] }, ownerIdentity);
      accepted = true;
    } catch (e) {
      const msg = (e && e.message ? e.message : String(e)).split("\n")[0];
      if (!/duplicate unique properties/i.test(msg)) {
        throw new Error(`the duplicate was refused, but NOT by the unique index: ${msg}`);
      }
      console.log("\n=== B9 CONFIRMED ON v4: Platform refused the duplicate-join settlement ===");
      console.log("refusal:", msg);
    }
    if (accepted) {
      process.exitCode = 1;
      console.error("UNEXPECTED: Platform accepted a second settlement for the same join; deleting it");
      try {
        await client.platform.documents.broadcast({ delete: [dup] }, ownerIdentity);
        console.error("cleanup: the duplicate was deleted");
      } catch (e2) {
        console.error(`cleanup FAILED, the duplicate ${dup.getId().toString()} remains on the ledger:`,
          (e2 && e2.message) || e2);
      }
    }
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
