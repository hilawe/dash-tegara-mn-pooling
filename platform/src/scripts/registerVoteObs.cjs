/**
 * Publish the vote-observation contract, the ordering middle rung the batch-5 review
 * discussion settled on (no consensus change needed). The problem it addresses: a
 * governance vote's nTime is operator-set, so the snapshot-first flow can only check
 * timestamp CONSISTENCY, not commit-before-cast order. The observation converts that:
 *
 *   Any member who sees a vote on the wire publishes an immutable observation
 *   ("I saw vote hash X with these fields"). The observation's $createdAt is
 *   PLATFORM-VALIDATED against block time, so it is a chain-anchored "someone
 *   published this vote's hash by time T" bound that cannot be fabricated
 *   retroactively.
 *
 * What an observation is and is NOT (batch-6 review): it is member CORROBORATION,
 * not proof, because a vote's fields are predictable except its second-resolution
 * nTime and nothing here authenticates that a SIGNED vote existed (no RPC at the
 * pinned Core commit exposes the vote's signature; exposing it, for example a
 * verbose getcurrentvotes, is the recorded upstream item that would upgrade this
 * rung to proof). The verifier therefore classifies observation findings as
 * SUSPECT, an investigation-owed failure that accuses no one, counts only CURRENT
 * POOL MEMBERS' observations toward flags, and treats implausibly-early
 * observations as permanent evidence of possible pre-publication. Full analysis in
 * castVerify.cjs.
 *
 * Trust shape: creation is UNRESTRICTED (every member may observe; this is the
 * inverse of the cast contract's owner-only rule) and documents are immutable (an
 * observation, once made, is permanent evidence, including evidence of a FALSE
 * observation).
 *
 * Persisted as VOTE_OBS_CONTRACT_ID; app name voteObs.
 */
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, saveEnv } = require("./envStore.cjs");

const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };

const voteObsContract = {
  observation: {
    type: "object",
    documentsMutable: false,
    canBeDeleted: false,
    properties: {
      proposalHash: { ...HASH32, position: 0 },
      proTxHash: { ...HASH32, position: 1 },
      voteHash: { ...HASH32, position: 2, description: "Core's hash of the observed governance vote" },
      voteOutcome: { type: "string", enum: ["yes", "no", "abstain"], maxLength: 10, position: 3 },
      voteSignal: { type: "string", maxLength: 12, position: 4 },
      voteTimestamp: { type: "integer", minimum: 0, position: 5,
        description: "the vote's claimed nTime as observed (echoed so the hash is checkable)" },
    },
    required: ["proposalHash", "proTxHash", "voteHash", "voteOutcome", "voteSignal",
      "voteTimestamp", "$createdAt"],
    additionalProperties: false,
    indices: [
      // one observation per observer per vote; voteHash-equality queries list a
      // vote's observations (one property unconstrained, within the depth rule)
      { name: "byVoteObserver", properties: [{ voteHash: "asc" }, { $ownerId: "asc" }], unique: true },
      { name: "byProposal", properties: [{ proposalHash: "asc" }, { $createdAt: "asc" }] },
      // per-observer, per-proposal listing (batch-6 second review): verify fetches
      // each CURRENT MEMBER's observations directly through this index instead of a
      // proposal-wide earliest-first pull, so non-member (or hostile-member) spam
      // cannot crowd real member evidence out of a bounded fetch window
      { name: "byProposalObserver",
        properties: [{ proposalHash: "asc" }, { $ownerId: "asc" }, { $createdAt: "asc" }] },
    ],
  },
};

(async () => {
  const env = loadEnv();
  if (!env.MNEMONIC || !env.IDENTITY_ID) {
    console.error("run register.cjs first (need MNEMONIC, IDENTITY_ID)");
    process.exit(1);
  }
  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  try {
    installConsumedFilter(await client.getWalletAccount());
    const identity = await client.platform.identities.get(env.IDENTITY_ID);
    if (env.VOTE_OBS_CONTRACT_ID) {
      console.log("vote-observation contract already published:", env.VOTE_OBS_CONTRACT_ID);
      return;
    }
    console.log("publishing the vote-observation contract ...");
    const contract = await client.platform.contracts.create(voteObsContract, identity);
    await client.platform.contracts.publish(contract, identity);
    env.VOTE_OBS_CONTRACT_ID = contract.getId().toString();
    saveEnv(env);
    console.log("\n=== VOTE-OBSERVATION CONTRACT PUBLISHED ===");
    console.log("contract id:", env.VOTE_OBS_CONTRACT_ID);
    console.log("(immutable observations, open creation; run voteWatch.cjs observe as any member)");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
