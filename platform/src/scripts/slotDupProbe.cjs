/**
 * The duplicate-claim consensus probe (v6/v7): bypass the client's read-before-write
 * check and DIRECTLY broadcast a pledgeSlot claim for a slot that is already taken, to
 * prove the ledger itself rejects it (the unique (poolId, slotNo) index). This is the
 * double-broadcast proof from the v6 build, kept as a script so the property stays
 * reproducible on every ledger revision.
 *
 * Run (container, like the client): WHO=funderN LEDGER=v6|v7 \
 *   node src/scripts/slotDupProbe.cjs <poolId> <takenSlotNo>
 * Exit 0 = the ledger REJECTED the duplicate (the property holds).
 * Exit 1 = the ledger ACCEPTED it (a soundness regression; investigate immediately).
 */
const Dash = require("dash");
const { Identifier } = require("@dashevo/wasm-dpp");
const { loadEnv, activeContractId, isV6, isV7 } = require("./envStore.cjs");

(async () => {
  const env = loadEnv();
  const [poolIdStr, slotStr] = process.argv.slice(2);
  if (!poolIdStr || !/^\d+$/.test(slotStr || "")) {
    console.error("usage: slotDupProbe.cjs <poolId> <takenSlotNo>");
    process.exit(2);
  }
  if (!isV6()) { console.error("needs LEDGER=v6 or v7"); process.exit(2); }
  const who = /^funder\d+$/.test(process.env.WHO || "") ? process.env.WHO : "funder2";
  const whoNum = parseInt(who.slice(6), 10);
  const myId = env[whoNum === 1 ? "FUNDER_ID" : `FUNDER${whoNum}_ID`];
  if (!myId) { console.error(`${who} has no identity`); process.exit(2); }

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
    const identity = await client.platform.identities.get(myId);
    const account = await client.getWalletAccount();
    const rewardScript = Dash.Core.Script
      .buildPublicKeyHashOut(account.getUnusedAddress().address).toBuffer();
    const slotNo = parseInt(slotStr, 10);
    console.log(`probe: ${who} broadcasts a DIRECT duplicate claim on slot ${slotNo} of ` +
      `${poolIdStr} (no client-side check)`);
    const doc = await client.platform.documents.create("poolLedger.pledgeSlot", identity, {
      poolId: Identifier.from(poolIdStr).toBuffer(), slotNo,
      // v6 claims carry a size; v7 claims are sizeless
      ...(isV7() ? {} : { slotDuffs: 25000000000 }),
      rewardScript,
    });
    try {
      await client.platform.documents.broadcast({ create: [doc] }, identity);
      console.error("\n=== PROBE FAILURE: the ledger ACCEPTED a duplicate slot claim; " +
        "the unique index did not hold ===");
      process.exitCode = 1;
    } catch (e) {
      const msg = (e && e.message) || String(e);
      console.log(`ledger response: ${msg.slice(0, 200)}`);
      if (/duplicate unique/i.test(msg)) {
        console.log("\n=== PROBE OK: the ledger rejected the duplicate claim at consensus " +
          "(unique (poolId, slotNo) index) ===");
      } else {
        console.error("\nrejected, but not with the duplicate-unique-index error; verify the cause");
        process.exitCode = 1;
      }
    }
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
