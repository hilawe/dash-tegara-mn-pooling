/**
 * The vote watcher, the member-run half of the ordering middle rung: observe the
 * masternode's current funding vote on a proposal and publish an immutable,
 * chain-timestamped observation of it (registerVoteObs.cjs explains the trust
 * shape and its limits). Verification (castReceiptV2.cjs verify) surfaces ordering
 * anomalies from observations as loud NOTES (a member observation predating a
 * receipt's snapshot, or a member-observed vote with no receipt), but observations
 * NEVER fail verification: a member could carpet the time window with candidate
 * hashes, so any observation-driven failure would be a member-controlled kill
 * switch. The evidence is surfaced for social adjudication instead.
 *
 * Subcommands (WHO=funderN selects the observing member, default funder1):
 *   observe <poolId> <proposalHash>   fetch the current vote from Core, self-check
 *                                     its hash, publish MY observation (idempotent:
 *                                     one observation per observer per vote)
 *   list <poolId> <proposalHash>      show every observation for the proposal
 *
 * Run like funderClient.cjs (container, LEDGER selects the pool ledger,
 * FORK_RPC_URL names the Core node whose governance state is read).
 */
const Dash = require("dash");
const { Identifier } = require("@dashevo/wasm-dpp");
const { loadEnv, activeContractId } = require("./envStore.cjs");
const { fetchAll } = require("./query.cjs");
const { fetchL1Vote } = require("./l1gov.cjs");

(async () => {
  const [cmd, poolIdStr, proposalHex] = process.argv.slice(2);
  if (!["observe", "list"].includes(cmd) || !poolIdStr || !/^[0-9a-f]{64}$/i.test(proposalHex || "")) {
    console.error("usage: voteWatch.cjs observe|list <poolId> <proposalHash 64-hex>");
    process.exit(2);
  }
  const env = loadEnv();
  if (!env.VOTE_OBS_CONTRACT_ID) {
    console.error("run registerVoteObs.cjs first (need VOTE_OBS_CONTRACT_ID)");
    process.exit(1);
  }
  if (cmd === "observe" && !process.env.FORK_RPC_URL) {
    console.error("FORK_RPC_URL is required to observe (the Core node whose governance state is read)");
    process.exit(2);
  }
  const who = /^funder\d+$/.test(process.env.WHO || "") ? process.env.WHO : "funder1";
  const whoNum = parseInt(who.slice(6), 10);
  const myId = whoNum === 1 ? env.FUNDER_ID : env[`FUNDER${whoNum}_ID`];
  if (!myId) { console.error(`${who} identity is not registered yet`); process.exit(1); }

  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
    apps: {
      poolLedger: { contractId: activeContractId(env) },
      voteObs: { contractId: env.VOTE_OBS_CONTRACT_ID },
    },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  try {
    const poolId = Identifier.from(poolIdStr);
    const pool = (await client.platform.documents.get("poolLedger.pool", {
      where: [["$id", "==", poolId]],
    }))[0];
    if (!pool) throw new Error(`no pool ${poolIdStr} on the ledger`);
    const proTxHex = Buffer.from(pool.toObject().proTxHash).toString("hex");
    const proposalBuf = Buffer.from(proposalHex, "hex");

    if (cmd === "list") {
      const obs = await fetchAll(client, "voteObs.observation", {
        where: [["proposalHash", "==", proposalBuf]],
        orderBy: [["$createdAt", "asc"]],
      });
      console.log(`${obs.length} observation(s) on proposal ${proposalHex.slice(0, 16)}...:`);
      for (const d of obs) {
        const o = d.toObject();
        console.log(`  ${new Date(Number(o.$createdAt)).toISOString()}  vote ` +
          `${Buffer.from(o.voteHash).toString("hex").slice(0, 16)}... (${o.voteOutcome}/${o.voteSignal} ` +
          `@ ${o.voteTimestamp})  by ${d.getOwnerId().toString()}`);
      }
      return;
    }

    // observe: what Core reports right now, hash self-checked inside fetchL1Vote
    const l1 = await fetchL1Vote(proTxHex, proposalHex.toLowerCase());
    if (!l1) { console.log("no current funding vote to observe"); return; }
    console.log(`current vote by ${proTxHex.slice(0, 16)}...: ${l1.outcome} (${l1.signal}) at ${l1.time}, ` +
      `vote hash ${l1.voteHash.slice(0, 16)}...`);

    const identity = await client.platform.identities.get(myId);
    const doc = await client.platform.documents.create("voteObs.observation", identity, {
      proposalHash: proposalBuf,
      proTxHash: Buffer.from(proTxHex, "hex"),
      voteHash: Buffer.from(l1.voteHash, "hex"),
      voteOutcome: l1.outcome,
      voteSignal: l1.signal,
      voteTimestamp: l1.time,
    });
    try {
      await client.platform.documents.broadcast({ create: [doc] }, identity);
      console.log(`\n=== OBSERVATION PUBLISHED by ${who}: ${doc.getId().toString()} ===`);
      console.log("(its $createdAt is Platform-validated: a chain-anchored record that THIS IDENTITY " +
        "published these vote fields by now; it does not itself prove a signed vote existed)");
    } catch (e) {
      const msg = (e && e.message) || String(e);
      if (/duplicate unique properties/i.test(msg)) {
        console.log(`\n=== ${who} ALREADY OBSERVED this vote (one observation per observer per vote) ===`);
        return;
      }
      throw e;
    }
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
