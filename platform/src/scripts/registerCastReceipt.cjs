/**
 * Publish the cast-receipt contract, the first rung of the governance mitigation ladder
 * (two independent reviews converged on it, batch-2, 2026-07-11). The trust gap it
 * narrows: the members' tally is deterministic and public on the pool ledger, but the
 * VOTE is cast on L1 by the operator with the node's voting key, and nothing bound the
 * two. The receipt is the operator's own published attestation of what was cast:
 *
 *   poolId + proposalHash   which pool and which L1 governance object
 *   tallyHash               sha256 of the canonical tally (tally.cjs) the cast claims
 *                           to implement; anyone recomputes it from the ledger
 *   outcome                 the tally's outcome ("none" when every weight is withheld)
 *   voteHash / voteOutcome / voteTimestamp / voteSignal
 *                           the L1 vote record as Core reports it
 *                           (`gobject getcurrentvotes`), absent when outcome is "none"
 *   proTxHash               the masternode that voted
 *
 * One receipt per pool per proposal (unique index); replaces update it in place when a
 * vote is re-cast. A deviation is then visible three ways: a receipt whose tallyHash
 * does not reproduce from the ledger, a receipt whose vote record does not match L1, or
 * no receipt at all where the tally demanded a cast. castReceipt.cjs publishes and
 * verifies; this script only registers the contract (persisted as CAST_CONTRACT_ID,
 * separate namespace, no republish of the pool ledger needed).
 */
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, saveEnv } = require("./envStore.cjs");

const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };

const castReceiptContract = {
  castReceipt: {
    type: "object",
    documentsMutable: true,
    properties: {
      poolId: { ...HASH32, position: 0 },
      proposalHash: { ...HASH32, position: 1, description: "the L1 governance object hash" },
      tallyHash: { ...HASH32, position: 2, description: "sha256 of the canonical member tally (tally.cjs)" },
      outcome: {
        type: "string", enum: ["yes", "no", "abstain", "none"], maxLength: 10, position: 3,
        description: "the tally's outcome; none means every weight was withheld and no vote was cast",
      },
      proTxHash: { ...HASH32, position: 4, description: "the masternode whose vote this receipt attests" },
      voteHash: { ...HASH32, position: 5, description: "Core's hash of the governance vote" },
      voteOutcome: { type: "string", enum: ["yes", "no", "abstain"], maxLength: 10, position: 6 },
      voteTimestamp: { type: "integer", minimum: 0, position: 7 },
      voteSignal: { type: "string", maxLength: 12, position: 8 },
    },
    required: ["poolId", "proposalHash", "tallyHash", "outcome", "proTxHash", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byPoolProposal", properties: [{ poolId: "asc" }, { proposalHash: "asc" }], unique: true },
      { name: "byProposal", properties: [{ proposalHash: "asc" }] },
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
    if (env.CAST_CONTRACT_ID) {
      console.log("cast-receipt contract already published:", env.CAST_CONTRACT_ID);
      return;
    }
    console.log("publishing the cast-receipt contract ...");
    const contract = await client.platform.contracts.create(castReceiptContract, identity);
    await client.platform.contracts.publish(contract, identity);
    env.CAST_CONTRACT_ID = contract.getId().toString();
    saveEnv(env);
    console.log("\n=== CAST-RECEIPT CONTRACT PUBLISHED ===");
    console.log("contract id:", env.CAST_CONTRACT_ID);
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
