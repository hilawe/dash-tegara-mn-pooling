/**
 * Publish the cast-governance contract v3, the accumulated schema notes from the
 * batch-3..6 reviews, bundled into one republish (the recorded policy). Derived from
 * the v2 definition in registerCastV2.cjs; the diff against it IS the design change:
 *
 *   1. tallySnapshot carries a REQUIRED `formatVersion` for the canonical row encoding
 *      (1 = the v2 rows {owner,bps,choice}; 2 = v3 rows that may carry an optional
 *      delegateTo per row). Verification selects its row validator by this field, so
 *      the encoding can evolve without breaking self-authentication.
 *   2. The tallyRows bound is corrected and enlarged: the PUBLISHED v2 carried the
 *      vestigial minItems 2 (noted in the findings record); v3 publishes the real
 *      floor (40, one minimal row) and raises the ceiling to 5000 bytes (about 45-50
 *      rows with delegation fields), inside Platform's ~5 KB field cap.
 *   3. castReceipt carries a REQUIRED `kind` ("cast" | "missed"). A MISSED-vote
 *      attestation is the operator's immutable on-ledger admission that no L1 vote
 *      implemented a snapshot by its deadline: voteHash is the all-zeros sentinel,
 *      voteOutcome is "none", voteSignal is "-". The unique [pool, proposal, voteHash]
 *      index then allows exactly one missed attestation per proposal, and verification
 *      treats missed receipts as surfacing, never as votes.
 *
 * The v1/v2 cast contracts and their documents remain untouched for the record; v3 is
 * a fresh namespace persisted as CAST_V3_CONTRACT_ID and selected with CAST=v3.
 */
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, saveEnv } = require("./envStore.cjs");

const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };

const castGovV3 = {
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
        type: "array", byteArray: true, minItems: 40, maxItems: 5000, position: 6,
        description: "canonical JSON member rows, format per formatVersion; the hash preimage's members",
      },
      formatVersion: { type: "integer", minimum: 1, maximum: 2, position: 7,
        description: "the canonical row encoding: 1 = {owner,bps,choice}; 2 = adds optional delegateTo" },
    },
    required: ["poolId", "proposalHash", "tallyHash", "outcome", "proTxHash",
      "platformHeight", "tallyRows", "formatVersion", "$createdAt"],
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
      snapshotId: { ...HASH32, position: 2, description: "the tallySnapshot this receipt is about" },
      voteHash: { ...HASH32, position: 3,
        description: "the L1 vote hash for kind cast; the all-zeros sentinel for kind missed" },
      voteOutcome: { type: "string", enum: ["yes", "no", "abstain", "none"], maxLength: 10, position: 4 },
      voteTimestamp: { type: "integer", minimum: 0, position: 5 },
      voteSignal: { type: "string", maxLength: 12, position: 6 },
      proTxHash: { ...HASH32, position: 7 },
      kind: { type: "string", enum: ["cast", "missed"], maxLength: 10, position: 8,
        description: "cast = an actual L1 vote; missed = the operator's attestation that none happened by the deadline" },
    },
    required: ["poolId", "proposalHash", "snapshotId", "voteHash", "voteOutcome",
      "voteTimestamp", "voteSignal", "proTxHash", "kind", "$createdAt"],
    additionalProperties: false,
    indices: [
      // one immutable receipt per vote; the all-zeros sentinel makes "one missed
      // attestation per proposal" a schema-level uniqueness fact
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
    if (env.CAST_V3_CONTRACT_ID) {
      console.log("cast-governance v3 contract already published:", env.CAST_V3_CONTRACT_ID);
      return;
    }
    console.log("publishing the cast-governance v3 contract ...");
    const contract = await client.platform.contracts.create(castGovV3, identity);
    await client.platform.contracts.publish(contract, identity);
    env.CAST_V3_CONTRACT_ID = contract.getId().toString();
    saveEnv(env);
    console.log("\n=== CAST-GOVERNANCE V3 PUBLISHED ===");
    console.log("contract id:", env.CAST_V3_CONTRACT_ID);
    console.log("(formatVersion, corrected/larger tallyRows bound, missed-vote attestations; select with CAST=v3)");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
