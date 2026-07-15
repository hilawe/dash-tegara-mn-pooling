/**
 * The governance tally engine: turns a pool's self-sovereign vote preferences into the
 * ONE vote the masternode can cast on an L1 governance object. Pure read plus a
 * deterministic rule, like the matcher: anyone can run it and verify the operator cast
 * what the members asked for.
 *
 * The five options are CrowdNode's own (kept as prior art in the contract):
 *   yes / no / abstain   counted directly, weighted by the member's shareBps
 *   delegate             follows the pool's NET ACTIVE vote (the majority among the
 *                        direct yes/no weights; a tie or no active votes -> abstain)
 *   donothing            that weight is withheld entirely (not cast)
 * A member with NO recorded preference is treated as donothing: nothing is cast on
 * their behalf without their signature ever having asked for it.
 *
 * The outcome is the plurality of the final yes/no/abstain weights; if every weight is
 * withheld the masternode does not vote at all. Casting itself is the operator's L1 act
 * (`gobject vote-alias <hash> funding <outcome> <proTxHash>` with the node's voting key
 * in the wallet; confirmed against the target Core version at 8c9f166a3, which has
 * vote-alias/vote-many/voteraw and no vote-alt); this engine produces the auditable
 * instruction, it does not touch L1. The tally itself lives in tally.cjs, shared with
 * the cast-receipt publisher and verifier (castReceipt.cjs), and the printed tally hash
 * is what a published receipt must carry.
 *
 * Run: ... governor.cjs <poolId> <proposalHash 64-hex>   (LEDGER=v4 as usual)
 */
const Dash = require("dash");
const { Identifier } = require("@dashevo/wasm-dpp");
const { loadEnv, activeContractId } = require("./envStore.cjs");
const { fetchAll } = require("./query.cjs");
const { computeTally, tallyHash } = require("./tally.cjs");

(async () => {
  const [poolIdStr, proposalHex] = process.argv.slice(2);
  if (!poolIdStr || !/^[0-9a-f]{64}$/i.test(proposalHex || "")) {
    console.error("usage: node src/scripts/governor.cjs <poolId> <proposalHash 64-hex>");
    process.exit(2);
  }
  const env = loadEnv();
  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC, unsafeOptions: { skipSynchronizationBeforeHeight: 1000000 } },
    apps: { poolLedger: { contractId: activeContractId(env) } },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  try {
    const poolId = Identifier.from(poolIdStr);
    const shares = await fetchAll(client, "poolLedger.share", { where: [["poolId", "==", poolId]] });
    if (shares.length === 0) throw new Error("pool has no shares");
    const bpsByOwner = new Map(shares.map((d) => [d.getOwnerId().toString(), Number(d.toObject().shareBps)]));
    const totalBps = [...bpsByOwner.values()].reduce((a, b) => a + b, 0);
    if (totalBps !== 10000) {
      throw new Error(`the pool's current shares sum to ${totalBps} bps, not 10000; refusing to ` +
        "issue a voting instruction for a malformed or mid-churn pool (review finding B8)");
    }

    const prefs = (await fetchAll(client, "poolLedger.votePreference", {
      where: [["poolId", "==", poolId]],
    })).filter((d) => Buffer.from(d.toObject().proposalHash).toString("hex") === proposalHex.toLowerCase());
    // the shared preference-maps helper resolves targeted delegation identically to
    // the cast-receipt publisher (holistic-round F6: the two tools must never compute
    // different tallies from the same ledger)
    const { prefsToMaps } = require("./ledgerTally.cjs");
    const { choiceByOwner, delegateToByOwner } = prefsToMaps(prefs);

    console.log(`pool ${poolIdStr}, proposal ${proposalHex.slice(0, 16)}...`);
    const members = [...bpsByOwner].map(([owner, bps]) => ({ owner, bps }));
    const tally = computeTally(members, choiceByOwner, delegateToByOwner);
    for (const r of tally.rows) {
      console.log(`  ${r.owner.slice(0, 12)}... ${r.bps} bps -> ${r.choice}` +
        (r.recorded ? "" : " (no preference recorded)"));
    }
    const { weights, net, final } = tally;
    console.log(`\ndirect weights: yes ${weights.yes} / no ${weights.no} / abstain ${weights.abstain}; ` +
      `delegate ${weights.delegate} follows the net active vote ("${net}"); withheld ${weights.withheld}`);
    console.log(`final weights: yes ${final.yes} / no ${final.no} / abstain ${final.abstain}`);
    console.log(`tally hash: ${tallyHash(activeContractId(env), poolIdStr, proposalHex, tally).toString("hex")}`);

    if (tally.outcome === "none") {
      console.log("\n=== GOVERNOR: every weight is withheld; the masternode casts NO vote ===");
      return;
    }
    console.log(`\n=== GOVERNOR: the pool's vote is "${tally.outcome.toUpperCase()}" ` +
      `(${final[tally.outcome]} of 10000 bps behind it; the operator casts it on L1 with ` +
      "`gobject vote-alias <proposal> funding " + tally.outcome + " <proTxHash>` and the node's " +
      "voting key, then publishes the cast receipt with castReceipt.cjs) ===");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
