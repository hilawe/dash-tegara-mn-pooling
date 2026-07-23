/**
 * The Path 2 settlement resolver: the shared "who currently holds this position" seam that
 * the reward and governance readers are meant to route through, so membership is a computed
 * view of public state (SETTLEMENT_DESIGN.md). It carries the a soundness-review finding safety GATE.
 *
 * a soundness-review finding (see the private findings log): a third-party reader CANNOT verify an L2 credit transfer
 * from public state (Platform proves current balance and nonce only, no transfer history). So
 * a reader that superseded a position on the intent+claim BINDING alone could be tricked by a
 * named joiner who claims WITHOUT paying, stranding the leaver. Therefore supersede here is
 * GATED on a caller-supplied `paymentVerified(intent, claim)` predicate that must establish the
 * payment by a reader-checkable means. On current Platform NO such means exists for an L2
 * transfer, so the safe caller passes a predicate that returns false, and the resolver returns
 * the BASE owner (the readers' existing behavior). The gate opens only when payment becomes
 * reader-verifiable: design A's L1-atomic marker (L1 txs are cold-verifiable via DAPI
 * getTransaction) or an upstream proven-transfer capability. This module never supersedes on an
 * unverifiable claim.
 */

// Pure resolver. Inputs are plain shapes so it is unit-testable with no network:
//   base   = { positionId, ownerId, rewardScriptHex }
//   intents = [{ intentId, positionId, sellerId, joinerId, priceCredits, expiryHeight }]
//   claims  = [{ claimId, intentId, joinerId, rewardScriptHex }]   (at most one per intentId, unique index)
//   paymentVerified = (intent, claim) => boolean   the a soundness-review finding gate, caller-supplied
// Returns { activeOwner, rewardScriptHex, superseded, reason }.
function resolveActiveMember(base, intents, claims, paymentVerified) {
  const claimByIntent = new Map();
  for (const c of [...claims].sort((a, b) => String(a.claimId).localeCompare(String(b.claimId)))) {
    if (!claimByIntent.has(c.intentId)) claimByIntent.set(c.intentId, c); // unique binder = first
  }
  for (const intent of intents) {
    if (intent.positionId !== base.positionId) continue;
    if (intent.sellerId !== base.ownerId) continue;               // intent must be by the CURRENT holder
    const claim = claimByIntent.get(intent.intentId);
    if (!claim) continue;
    if (claim.joinerId !== intent.joinerId) continue;             // claim by the NAMED joiner only
    // a soundness-review finding GATE: only supersede if the payment is verifiable by the reader. On current
    // Platform this is false for an L2 transfer, so the base owner stands.
    if (!paymentVerified(intent, claim)) {
      return { activeOwner: base.ownerId, rewardScriptHex: base.rewardScriptHex, superseded: false,
        reason: "claim present but payment not reader-verifiable (a soundness review); base owner stands" };
    }
    return { activeOwner: claim.joinerId, rewardScriptHex: claim.rewardScriptHex, superseded: true,
      reason: "superseded: valid claim with a reader-verified payment" };
  }
  return { activeOwner: base.ownerId, rewardScriptHex: base.rewardScriptHex, superseded: false,
    reason: "no binding claim; base owner" };
}

// The safe payment verifier for CURRENT Platform: an L2 credit transfer is not
// cold-verifiable, so a reader can never confirm it. Always false, on purpose (a soundness review).
const NO_L2_PAYMENT_PROOF = () => false;

/**
 * Read the active membership of a pool as [{ owner, bps, contributionDuffs, rewardScriptHex,
 * baseOwner, superseded }]. When no settlement contract is configured, or with the safe
 * current-Platform verifier, this returns the RAW share membership unchanged (the readers'
 * existing behavior). The supersede overlay activates only when a reader-verifiable payment
 * predicate is supplied, which current Platform cannot satisfy for L2 transfers (a soundness review).
 */
async function readActiveMembership(client, poolId, opts) {
  const { Identifier, fetchAll, settlementContractId, paymentVerified = NO_L2_PAYMENT_PROOF } = opts;
  const shareDocs = await fetchAll(client, "poolLedger.share", { where: [["poolId", "==", poolId]] });
  const base = shareDocs
    .map((d) => ({ d, o: d.toObject(), owner: d.getOwnerId().toString() }))
    .sort((a, b) => Number(a.o.$createdAt) - Number(b.o.$createdAt))
    .map(({ d, o, owner }) => ({
      positionId: d.getId().toString(),
      owner, baseOwner: owner,
      bps: Number(o.shareBps),
      contributionDuffs: Number(o.contributionDuffs),
      rewardScriptHex: o.l1RewardScript ? Buffer.from(o.l1RewardScript).toString("hex") : null,
      superseded: false,
    }));
  if (!settlementContractId) return base; // no settlement layer: raw membership, unchanged

  // settlement layer present: overlay the supersede view, gated by a soundness-review finding
  for (const m of base) {
    const intents = (await client.platform.documents.get("settlement.saleIntent", {
      where: [["positionId", "==", Identifier.from(m.positionId)]] }).catch(() => []))
      .map((d) => ({ intentId: d.getId().toString(), positionId: Identifier.from(Buffer.from(d.toObject().positionId)).toString(),
        sellerId: d.getOwnerId().toString(), joinerId: Identifier.from(Buffer.from(d.toObject().joinerId)).toString(),
        priceCredits: Number(d.toObject().priceCredits), expiryHeight: Number(d.toObject().expiryHeight) }));
    const claims = [];
    for (const it of intents) {
      const cs = await client.platform.documents.get("settlement.positionClaim", {
        where: [["intentId", "==", Identifier.from(it.intentId)]] }).catch(() => []);
      for (const c of cs) claims.push({ claimId: c.getId().toString(), intentId: it.intentId,
        joinerId: c.getOwnerId().toString(), rewardScriptHex: Buffer.from(c.toObject().rewardScript).toString("hex") });
    }
    const r = resolveActiveMember({ positionId: m.positionId, ownerId: m.baseOwner, rewardScriptHex: m.rewardScriptHex },
      intents, claims, paymentVerified);
    m.owner = r.activeOwner; m.rewardScriptHex = r.rewardScriptHex; m.superseded = r.superseded;
  }
  return base;
}

module.exports = { resolveActiveMember, readActiveMembership, NO_L2_PAYMENT_PROOF };
