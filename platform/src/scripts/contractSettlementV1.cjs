/**
 * Pure builder for settlementV1, the Path 2 member-signed value-settlement contract
 * (first build milestone of the synthesized supersede design; see
 * tegara/docs/PATH2_DESIGN_SYNTHESIS.md and the validated resolver in
 * tegara/docs/path2_resolver_thinslice.cjs).
 *
 * Two document types, deliberately small:
 *
 *   saleIntent, created and owned by the LEAVER (the current position holder). It names
 *   the position being sold (the leaver's share document id), the price in credits, the
 *   NAMED joiner identity, a nonce, and an expiry height. Open creation: any identity may
 *   post an intent, but an intent only matters if its owner IS the current holder of the
 *   named position, which the resolver checks (the schema cannot).
 *
 *   positionClaim, created and owned by the JOINER. It names the saleIntent it answers,
 *   the credit-transfer transition hash that paid the price, and the joiner's reward
 *   script. The UNIQUE index on intentId is the one property consensus enforces for the
 *   design: at most ONE claim binds an intent, so a race of claims resolves to exactly
 *   one winner and duplicates are refused at consensus, not by clients.
 *
 * What the schema deliberately does NOT try to enforce (the resolver's duties, validated
 * offline by the thin-slice matrix): that the intent's owner holds the position, that the
 * named transfer really moved the exact price from the claim's owner to the intent's
 * owner within the window, and that the claim's owner is the intent's named joiner.
 * Platform cannot express cross-document invariants, so the ACTIVE position is a COMPUTED
 * view: base share, superseded by the unique valid claim when one exists.
 */
const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };
const SCRIPT = { type: "array", byteArray: true, minItems: 1, maxItems: 34 };

function buildSettlementV1() {
  return {
    saleIntent: {
      type: "object",
      documentsMutable: false,      // an intent is a signed offer; changing terms is a NEW intent
      canBeDeleted: true,           // the leaver may withdraw an unclaimed offer
      properties: {
        positionId: { ...HASH32, position: 0,
          description: "the share document id being sold; the intent binds only if its owner currently holds this position (resolver-checked)" },
        poolId: { ...HASH32, position: 1,
          description: "the pool the position belongs to, denormalized for indexed reads" },
        priceCredits: { type: "integer", minimum: 1, position: 2,
          description: "the exact price in credits the named joiner must transfer to the intent owner" },
        joinerId: { ...HASH32, position: 3,
          description: "the ONLY identity whose payment and claim can answer this intent" },
        nonce: { ...HASH32, position: 4,
          description: "a fresh nonce so identical terms produce distinct intents" },
        expiryHeight: { type: "integer", minimum: 1, position: 5,
          description: "the last core height at which a payment can bind this intent (resolver-checked)" },
      },
      required: ["positionId", "poolId", "priceCredits", "joinerId", "nonce", "expiryHeight", "$createdAt"],
      additionalProperties: false,
      indices: [
        { name: "byPosition", properties: [{ positionId: "asc" }, { $createdAt: "asc" }] },
        { name: "byPool", properties: [{ poolId: "asc" }, { $createdAt: "asc" }] },
        { name: "byOwner", properties: [{ $ownerId: "asc" }, { $createdAt: "asc" }] },
      ],
    },
    positionClaim: {
      type: "object",
      documentsMutable: false,      // a claim is evidence; it never changes
      canBeDeleted: false,          // and never disappears (immutable-evidence pattern)
      properties: {
        intentId: { ...HASH32, position: 0,
          description: "the saleIntent this claim answers; UNIQUE, so at most one claim ever binds an intent (the consensus-enforced race winner)" },
        transferHash: { ...HASH32, position: 1,
          description: "the credit-transfer state-transition hash that paid the intent's exact price from this claim's owner to the intent's owner" },
        rewardScript: { ...SCRIPT, position: 2,
          description: "the joiner's own L1 reward destination for the acquired position" },
      },
      required: ["intentId", "transferHash", "rewardScript", "$createdAt"],
      additionalProperties: false,
      indices: [
        { name: "byIntent", properties: [{ intentId: "asc" }], unique: true },
        { name: "byOwner", properties: [{ $ownerId: "asc" }, { $createdAt: "asc" }] },
      ],
    },
  };
}

module.exports = { buildSettlementV1 };
