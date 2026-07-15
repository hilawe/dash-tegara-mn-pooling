/**
 * Publish the cast-governance contract v2, the snapshot-first design the batch-3
 * review converged on (all three reviewers; record
 * the private review records). It replaces the v1 cast
 * receipt's two structural weaknesses at the schema:
 *
 *   1. NO MUTABLE EVIDENCE. Both document types are immutable (documentsMutable
 *      false, canBeDeleted false): a snapshot or receipt, once published, can never
 *      be edited or removed, so a re-cast adds a NEW receipt instead of erasing the
 *      old one, and timing disputes have a permanent trail.
 *   2. OPERATOR-BOUND CREATION (creationRestrictionMode 1, owner-only): only the
 *      contract owner (the operator identity that publishes this contract) can create
 *      documents, so a hostile identity can no longer occupy a receipt slot or forge
 *      an "attestation". Enforcement is probed live after publish; if this Platform
 *      version did not enforce it, the fallback is the v1 client-side owner check,
 *      and the probe result is recorded either way.
 *
 * The two types:
 *
 *   tallySnapshot - the operator's immutable commitment to the members' tally,
 *     published BEFORE casting (the governor's instruction now points here). It
 *     embeds the canonical member rows (tallyRows), so it is SELF-AUTHENTICATING:
 *     anyone can rebuild the tally from the embedded rows and compare the hash,
 *     with no historical Platform queries needed. platformHeight and $createdAt
 *     place it in time. Multiple snapshots per (pool, proposal) are expected as
 *     preferences churn; the newest is the standing commitment.
 *
 *   castReceipt - one immutable receipt per actual L1 vote (unique
 *     [poolId, proposalHash, voteHash]), binding the vote record to the snapshot it
 *     implemented (snapshotId). Verification checks vote-vs-snapshot (historical
 *     honesty) separately from current-tally-vs-current-vote (freshness).
 *
 * A pool of up to ~40 members fits the 4096-byte tallyRows bound (about 100 bytes
 * per row); the #187 slot cap is 32 participants, so the bound holds for the
 * designs this prototype targets. Persisted as CAST_V2_CONTRACT_ID; the v1 cast
 * contract and its receipts remain untouched for the record.
 */
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, saveEnv } = require("./envStore.cjs");

const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };

const castGovV2 = {
  tallySnapshot: {
    type: "object",
    documentsMutable: false,
    canBeDeleted: false,
    creationRestrictionMode: 1,
    properties: {
      poolId: { ...HASH32, position: 0 },
      proposalHash: { ...HASH32, position: 1 },
      tallyHash: { ...HASH32, position: 2, description: "sha256 of the canonical tally (tally.cjs)" },
      outcome: { type: "string", enum: ["yes", "no", "abstain", "none"], maxLength: 10, position: 3 },
      proTxHash: { ...HASH32, position: 4 },
      platformHeight: { type: "integer", minimum: 0, position: 5,
        description: "the Platform height when the snapshot was taken (0 when unavailable)" },
      tallyRows: {
        // minItems 40 ~= one minimal row; the REAL enforcement is
        // validateCanonicalRows at both creation and verification (the PUBLISHED
        // contract carries the older vestigial minItems 2, noted in the findings
        // record; this definition governs future publishes)
        type: "array", byteArray: true, minItems: 40, maxItems: 4096, position: 6,
        description: "canonical JSON member rows [{owner,bps,choice}], the hash preimage's members",
      },
    },
    required: ["poolId", "proposalHash", "tallyHash", "outcome", "proTxHash",
      "platformHeight", "tallyRows", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byPoolProposal", properties: [{ poolId: "asc" }, { proposalHash: "asc" }, { $createdAt: "asc" }] },
    ],
  },
  castReceipt: {
    type: "object",
    documentsMutable: false,
    canBeDeleted: false,
    creationRestrictionMode: 1,
    properties: {
      poolId: { ...HASH32, position: 0 },
      proposalHash: { ...HASH32, position: 1 },
      snapshotId: { ...HASH32, position: 2, description: "the tallySnapshot this cast implemented" },
      voteHash: { ...HASH32, position: 3 },
      voteOutcome: { type: "string", enum: ["yes", "no", "abstain"], maxLength: 10, position: 4 },
      voteTimestamp: { type: "integer", minimum: 0, position: 5 },
      voteSignal: { type: "string", maxLength: 12, position: 6 },
      proTxHash: { ...HASH32, position: 7 },
    },
    required: ["poolId", "proposalHash", "snapshotId", "voteHash", "voteOutcome",
      "voteTimestamp", "voteSignal", "proTxHash", "$createdAt"],
    additionalProperties: false,
    indices: [
      // one immutable receipt per vote; [poolId, proposalHash] prefix queries list a
      // proposal's receipts (one property unconstrained, within the depth rule)
      { name: "byVote", properties: [{ poolId: "asc" }, { proposalHash: "asc" }, { voteHash: "asc" }], unique: true },
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
    if (env.CAST_V2_CONTRACT_ID) {
      console.log("cast-governance v2 contract already published:", env.CAST_V2_CONTRACT_ID);
      return;
    }
    console.log("publishing the cast-governance v2 contract ...");
    const contract = await client.platform.contracts.create(castGovV2, identity);
    await client.platform.contracts.publish(contract, identity);
    env.CAST_V2_CONTRACT_ID = contract.getId().toString();
    saveEnv(env);
    console.log("\n=== CAST-GOVERNANCE V2 PUBLISHED ===");
    console.log("contract id:", env.CAST_V2_CONTRACT_ID);
    console.log("(immutable snapshots and receipts, owner-only creation; run castReceiptV2.cjs)");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
