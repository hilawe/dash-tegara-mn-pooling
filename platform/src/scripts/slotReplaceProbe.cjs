/**
 * The claim-mutation probe (v7): REPLACE an existing pledgeSlot claim's rewardScript
 * while keeping its document id, exactly the post-COMMIT mutation that review finding
 * F-C1 says completion must detect (bare existence rechecking cannot). Kept as a script
 * so the refusal stays reproducible on every ledger revision, like slotDupProbe.cjs.
 *
 * Run (container, like the client): WHO=funderN LEDGER=v7 \
 *   node src/scripts/slotReplaceProbe.cjs <claimId>
 * Exit 0 = the replace was ACCEPTED by the ledger (expected for mutable v7 claims);
 * the point is what formation.cjs `complete` says AFTERWARDS.
 */
const Dash = require("dash");
const { Identifier } = require("@dashevo/wasm-dpp");
const { loadEnv, activeContractId, isV7 } = require("./envStore.cjs");

(async () => {
  const env = loadEnv();
  const [claimIdStr] = process.argv.slice(2);
  if (!claimIdStr) { console.error("usage: slotReplaceProbe.cjs <claimId>"); process.exit(2); }
  if (!isV7()) { console.error("needs LEDGER=v7 (v6 claims are immutable)"); process.exit(2); }
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
    const found = await client.platform.documents.get("poolLedger.pledgeSlot", {
      where: [["$id", "==", Identifier.from(claimIdStr)]],
    });
    if (found.length === 0) throw new Error(`no claim ${claimIdStr}`);
    const claim = found[0];
    if (claim.getOwnerId().toString() !== myId) throw new Error(`claim is not ${who}'s`);
    const identity = await client.platform.identities.get(myId);
    // a GENUINELY different script every run: a fresh random key's P2PKH (the first
    // probe version used getUnusedAddress(), which returned the same address the claim
    // already carried, so the "replace" wrote an identical value and proved nothing)
    const net = process.env.NETWORK === "regtest" ? "testnet" : (process.env.NETWORK || "testnet");
    const newScript = Dash.Core.Script
      .buildPublicKeyHashOut(new Dash.Core.PrivateKey(undefined, net).toAddress()).toBuffer();
    const oldHex = Buffer.from(claim.toObject().rewardScript).toString("hex");
    if (newScript.toString("hex") === oldHex) throw new Error("random script collided; rerun");
    console.log(`probe: ${who} REPLACES claim ${claimIdStr} (same id, rewardScript ` +
      `${oldHex.slice(0, 16)}... -> ${newScript.toString("hex").slice(0, 16)}...)`);
    claim.set("rewardScript", newScript);
    await client.platform.documents.broadcast({ replace: [claim] }, identity);
    console.log("\n=== PROBE OK: the mutable claim was replaced in place; now run formation " +
      "`complete` and expect the F-C1 MUTATED-after-COMMIT refusal ===");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
