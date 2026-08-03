/**
 * The pure sweep decision for one pool's documents (phase F of docs/V9_MIGRATION_PLAN.md).
 *
 * Transport-free on purpose: cleanupDebris.cjs performs the queries and broadcasts, and
 * every skip-or-sweep decision lives HERE, so the ledger-routing behaviour (what counts as
 * debris, what a receipt protects, what an immutable pool withholds from the deletion set)
 * is offline-testable without a live Platform. The decision covers documents visible at
 * query time; the caller owns the re-query that narrows the time-of-check window.
 *
 * Inputs are plain data. `ownerIds` carries the owner of EVERY document the sweep would
 * touch, including the pool document itself on every ledger, so the whole-pool-or-nothing
 * ownership preflight (review finding F8) keeps its original scope even where the pool is
 * not deletable.
 */
const planPoolSweep = ({ shareBpsSum, shareCount, accrualCount, receiptCount, ownerIds,
  controlled, receiptLedger, immutablePool }) => {
  // a complete pool is not debris
  if (shareCount > 0 && shareBpsSum === 10000) {
    return { action: "keep", reason: "complete share table" };
  }
  // anything that ever distributed is refused outright
  if (accrualCount > 0) {
    return { action: "skip-accruals", reason: "incomplete shares but HAS accruals" };
  }
  // a pool with a completion receipt is NOT debris, whatever its (mutable, deletable)
  // share table currently sums to; a receipt that fails to verify is an anomaly for
  // hands, not a license to sweep. Receipt PRESENCE is the condition, deliberately
  // broader than the classifier's verified COMPLETED. `receiptLedger` gates the input,
  // because earlier contracts have no receipt type to have queried.
  if (receiptLedger && receiptCount > 0) {
    return { action: "skip-receipt", reason: "a completion receipt exists; a pool with a completion record is not debris" };
  }
  // whole-pool-or-nothing (F8): one foreign-owned document leaves the pool intact
  const foreign = ownerIds.filter((o) => !controlled.has(o));
  if (foreign.length > 0) {
    return { action: "skip-foreign", foreign };
  }
  // the immutable pool document cannot be deleted (canBeDeleted: false) and is withheld
  // from the deletion set, so the sweep cannot fail midway on the contract's refusal
  // after other documents were already deleted
  return { action: "sweep", deletePool: !immutablePool };
};

module.exports = { planPoolSweep };
