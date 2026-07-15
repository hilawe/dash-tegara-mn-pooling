/**
 * One-shot cleanup of the development-debris pools on the devnet ledger: pools whose
 * share table is incomplete AND which never distributed anything (the audit's warning
 * set). Each document is deleted by the identity that owns it, the same self-sovereign
 * rule as everything else; nothing else is touched, and a pool with any accrual is
 * refused outright.
 *
 * The controlled-identity set is discovered from .env.local by pattern (IDENTITY_ID plus
 * every FUNDER_ID / FUNDERN_ID), and the whole deletion set is preflighted first: if ANY
 * document in a debris pool is owned by an identity this run does not control, the
 * ENTIRE pool is skipped, never partially deleted (review finding F8, 2026-07-11; the
 * old version hardcoded three funders and could orphan a foreign share).
 *
 * Run like the other scripts. Prints what it deletes; re-run is a no-op.
 */
const Dash = require("dash");
const { loadEnv, activeContractId, isV3 } = require("./envStore.cjs");
const { fetchAll } = require("./query.cjs");

(async () => {
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

  const mine = new Set();
  for (const [k, v] of Object.entries(env)) {
    if (k === "IDENTITY_ID" || k === "FUNDER_ID" || /^FUNDER\d+_ID$/.test(k)) mine.add(v);
  }
  const identities = {};
  const identityFor = async (idStr) => {
    if (!identities[idStr]) identities[idStr] = await client.platform.identities.get(idStr);
    return identities[idStr];
  };

  try {
    await client.getWalletAccount();

    const pools = await fetchAll(client, "poolLedger.pool");
    let removed = 0;
    for (const pool of pools) {
      const poolId = pool.getId();
      const shares = await fetchAll(client, "poolLedger.share", {
        where: [["poolId", "==", poolId]],
      });
      const bps = shares.reduce((s, d) => s + Number(d.toObject().shareBps), 0);
      if (shares.length > 0 && bps === 10000) continue; // a complete pool is not debris
      const accruals = await fetchAll(client, "poolLedger.rewardAccrual", {
        where: [["poolId", "==", poolId]],
      });
      if (accruals.length > 0) {
        console.log(`SKIP ${poolId.toString()}: incomplete shares but HAS accruals; not touching it`);
        continue;
      }
      const requests = await fetchAll(client, "poolLedger.membershipRequest", {
        where: [["poolId", "==", poolId], ["status", "==", "pending"]],
      });

      // preflight: every document must be deletable by an identity this run controls,
      // or the pool is left completely intact
      const docs = [...shares, ...requests, pool];
      const foreign = docs.filter((d) => !mine.has(d.getOwnerId().toString()));
      if (foreign.length > 0) {
        console.log(`SKIP ${poolId.toString()}: ${foreign.length} document(s) owned by identities this ` +
          `run does not control (e.g. ${foreign[0].getOwnerId().toString()}); leaving the pool intact`);
        continue;
      }

      console.log(`debris pool ${poolId.toString()} (${shares.length} shares, ${bps} bps): removing`);
      for (const doc of docs) {
        const owner = await identityFor(doc.getOwnerId().toString());
        await client.platform.documents.broadcast({ delete: [doc] }, owner);
        console.log(`  deleted ${doc.getType()} ${doc.getId().toString()} ` +
          `(owner ${doc.getOwnerId().toString().slice(0, 8)}...)`);
        removed++;
      }
    }
    console.log(`\n=== DEBRIS CLEANUP DONE: ${removed} documents deleted ===`);
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
