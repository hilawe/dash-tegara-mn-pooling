/**
 * Tegara pool-ledger data contract for Dash Platform.
 *
 * The Layer 2 accounting spine. A pool represents one shared masternode (or one #187 participant slot
 * that a group of retail sub-funders share). Sub-funders, their shares, membership changes, reward
 * accruals, and governance preferences all live here as small indexed documents, well within the 16 KB
 * per-transition and ~5 KB per-field Platform limits.
 *
 * Ownership and self-sovereignty: Platform stamps each document with the identity that created it
 * ($ownerId). A `share`, `membershipRequest`, and `votePreference` are created and signed by the
 * sub-funder themselves, so those actions are self-sovereign with no custodial login. See the README for
 * the honest note on what a data contract can and cannot enforce (schema, not cross-document invariants
 * such as "shares sum to 100%", which the distribution logic and the contribution-time checks handle).
 *
 * Binary fields use Platform's byte-array form. Property `position` values are required by recent
 * Platform versions and must be stable once the contract is registered. Exact index and validation
 * details are tuned against the target Platform version at registration time.
 */

const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 } as const;
const SCRIPT = { type: "array", byteArray: true, minItems: 1, maxItems: 34 } as const; // an L1 output script

export const poolLedgerContract = {
  pool: {
    type: "object",
    documentsMutable: true,
    properties: {
      proTxHash: { ...HASH32, position: 0, description: "the masternode proTxHash this pool backs" },
      slotIndex: {
        type: "integer", minimum: 0, maximum: 31, position: 1,
        description: "which #187 share / DIP-0026 payout entry this pool maps to",
      },
      nodeType: { type: "string", enum: ["regular", "evo"], maxLength: 10, position: 2 },
      operatorIdentityId: { ...HASH32, position: 3, description: "the operator's Platform identity" },
      operatorFeeBps: {
        type: "integer", minimum: 0, maximum: 10000, position: 4,
        description: "operator fee in basis points of the pool's owner reward",
      },
    },
    required: ["proTxHash", "slotIndex", "nodeType", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byProTxHash", properties: [{ proTxHash: "asc" }], unique: true },
      { name: "bySlot", properties: [{ proTxHash: "asc" }, { slotIndex: "asc" }], unique: true },
    ],
  },

  share: {
    type: "object",
    documentsMutable: true,
    properties: {
      poolId: { ...HASH32, position: 0, description: "the pool document id" },
      shareBps: { type: "integer", minimum: 1, maximum: 10000, position: 1 },
      contributionDuffs: { type: "integer", minimum: 0, position: 2 },
      l1RewardScript: { ...SCRIPT, position: 3, description: "where this funder's reward withdraws to on L1" },
    },
    required: ["poolId", "shareBps", "contributionDuffs", "$createdAt"],
    additionalProperties: false,
    // one share per funder ($ownerId) per pool; also list all shares in a pool
    indices: [
      { name: "byPoolOwner", properties: [{ poolId: "asc" }, { $ownerId: "asc" }], unique: true },
      { name: "byPool", properties: [{ poolId: "asc" }] },
    ],
  },

  membershipRequest: {
    type: "object",
    documentsMutable: true,
    properties: {
      poolId: { ...HASH32, position: 0 },
      kind: { type: "string", enum: ["join", "exit"], maxLength: 10, position: 1 },
      amountDuffs: { type: "integer", minimum: 0, position: 2 },
      status: { type: "string", enum: ["pending", "matched", "settled"], maxLength: 20, position: 3 },
    },
    required: ["poolId", "kind", "amountDuffs", "status", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byPoolStatus", properties: [{ poolId: "asc" }, { status: "asc" }] },
      { name: "byOwner", properties: [{ $ownerId: "asc" }, { $createdAt: "asc" }] },
    ],
  },

  rewardAccrual: {
    type: "object",
    documentsMutable: true,
    properties: {
      poolId: { ...HASH32, position: 0 },
      funderId: { ...HASH32, position: 1, description: "the sub-funder credited" },
      amountDuffs: { type: "integer", minimum: 0, position: 2 },
      epochHeight: { type: "integer", minimum: 0, position: 3 },
    },
    required: ["poolId", "funderId", "amountDuffs", "epochHeight", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byPoolFunder", properties: [{ poolId: "asc" }, { funderId: "asc" }, { epochHeight: "asc" }] },
    ],
  },

  votePreference: {
    type: "object",
    documentsMutable: true,
    properties: {
      poolId: { ...HASH32, position: 0 },
      proposalHash: { ...HASH32, position: 1, description: "the governance proposal" },
      // CrowdNode's five options, kept as prior art (delegate = follow the pool's net active vote)
      choice: { type: "string", enum: ["yes", "no", "abstain", "delegate", "donothing"], maxLength: 12, position: 2 },
    },
    required: ["poolId", "proposalHash", "choice", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byPoolOwnerProposal", properties: [{ poolId: "asc" }, { $ownerId: "asc" }, { proposalHash: "asc" }], unique: true },
    ],
  },
} as const;

export type PoolLedgerContract = typeof poolLedgerContract;
