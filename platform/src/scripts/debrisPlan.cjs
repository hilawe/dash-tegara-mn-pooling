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
  controlled, receiptLedger, immutablePool, lockHeld = false, newcomerCount = 0,
  poolLive = false, poolPresent = true, settlementCount = 0, permanentClaimCount = 0 }) => {
  // BEFORE EVERYTHING: a pool document that has VANISHED since planning voids every other
  // input (they describe a pool that no longer exists), so the decision short-circuits
  // here and reads nothing else. This input exists so the caller's missing-pool stop is a
  // decision THIS tested function makes, not a caller-local one beside it (closing
  // confirm-pass, minor: three records claimed every skip-or-sweep decision lives here
  // while exactly this one did not).
  if (poolPresent === false) {
    return { action: "skip-vanished",
      reason: "the pool document is gone since planning; the remaining documents describe " +
        "a pool that no longer exists and are left in place" };
  }
  // FIRST among the pool-present decisions: a held completion-protocol lock means a protocol run is active on this pool,
  // which is itself proof the pool is not debris right now (the done-prune contention
  // pattern). Checked before anything else, so a locked pool is never swept whatever its
  // counts say, and the decision lives here with the rest (vetting round, finding 2).
  if (lockHeld) {
    return { action: "skip-locked",
      reason: "a completion-protocol run holds this pool's operation lock; not debris right now" };
  }
  // a document that was not in the enumerated set when the sweep was planned means the
  // pool is no longer the pool the plan covered, whoever owns the newcomer (closing
  // wave, must-fix): concurrency, not ownership, is the signal, so the stop does not
  // wait for the ownership preflight below. The caller computes the count by comparing
  // the fresh document set against the ids it enumerated at planning time.
  if (newcomerCount > 0) {
    return { action: "skip-changed",
      reason: `${newcomerCount} document(s) arrived since the sweep was planned; ` +
        "the pool is no longer the one the plan covered" };
  }
  // A LIVE POOL IS NEVER DEBRIS, whatever its share table sums to (pass 17, F1). On a
  // mutable-pool ledger the flip mutates proTxHash from the forming namespace to a real
  // masternode hash, so a real hash means a node EXISTS behind this pool. The debris flow
  // exists to clean up ABANDONED FORMING pools, and it had no lifecycle input at all, so a
  // controlled operator's one-basis-point non-participant share (which completion ignores)
  // pushed the aggregate off 10000, defeated the "complete" keep, and every document being
  // controlled then returned sweep for a pool whose masternode was live and whose receipt
  // recovery had merely not been published yet. Deleting it orphans the node and destroys
  // the manifest-recovery basis. `poolLive` is the caller's lifecycle read (real,
  // non-forming proTxHash on a mutable ledger); the immutable ledger has no flip and passes
  // false. Checked before the count-based decisions, because liveness outranks every count.
  if (poolLive) {
    return { action: "skip-live",
      reason: "the pool's proTxHash is a real masternode hash: a node is live behind it and " +
        "receipt recovery may simply be unpublished; a live pool is never debris" };
  }
  // a complete pool is not debris
  if (shareCount > 0 && shareBpsSum === 10000) {
    return { action: "keep", reason: "complete share table" };
  }
  // anything that ever distributed is refused outright
  if (accrualCount > 0) {
    return { action: "skip-accruals", reason: "incomplete shares but HAS accruals" };
  }
  // ...and anything that ever SETTLED an exit or join is refused the same way
  // (a confirmation pass, must-fix: settlements are poolId-referencing lifecycle
  // history the sweep never enumerated, so a pool with one could be deleted around it,
  // orphaning the record of a member exit that actually happened)
  if (settlementCount > 0) {
    return { action: "skip-settlements", reason: "incomplete shares but HAS settlements; a pool " +
      "that ever settled an exit or join has member history and is not debris" };
  }
  // a pool with a completion receipt is NOT debris, whatever its (mutable, deletable)
  // share table currently sums to; a receipt that fails to verify is an anomaly for
  // hands, not a license to sweep. Receipt PRESENCE is the condition, deliberately
  // broader than the classifier's verified COMPLETED. `receiptLedger` gates the input,
  // because earlier contracts have no receipt type to have queried.
  if (receiptLedger && receiptCount > 0) {
    return { action: "skip-receipt", reason: "a completion receipt exists; a pool with a completion record is not debris" };
  }
  // AN IMMUTABLE RECEIPT-LESS POOL IS INDETERMINATE, NOT DEBRIS (packet wave, repository-access review F1).
  // Reaching here on the immutable ledger means no verifying receipt exists, and this
  // module's own doctrine (poolLifecycle header) is that a receipt-less immutable pool is
  // OPEN, IN-FLIGHT, or ABANDONED and those are the same document: a member may have a live
  // reservation on an OPEN pool. The earlier design swept such a pool's shares and claims
  // under the controlled-identity preflight, which deletes a live member reservation it
  // cannot distinguish from abandoned debris, on a real Platform path. The admission rule
  // already FAILS CLOSED on exactly this indeterminacy; the sweep must do the same and skip.
  // (On a mutable ledger the pool document answers forming-vs-live, so the count-based sweep
  // below still applies there; only the immutable ledger loses that signal.)
  if (immutablePool) {
    return { action: "skip-indeterminate",
      reason: "an immutable receipt-less pool is open, in-flight or abandoned indistinguishably; " +
        "sweeping its member documents could delete a live reservation, so it is left intact " +
        "(the same fail-closed rule admission uses)" };
  }
  // a PERMANENT claim makes a whole-pool sweep unexecutable (a confirmation pass,
  // major: the v6 reservation is immutable and undeletable by its own schema, so a plan
  // that returned sweep for a pool carrying one approved a sweep that would fail midway,
  // after deleting the shares and requests, leaving the bookkeeping set partially
  // applied). The caller reports how many enumerated claims cannot be deleted on the
  // selected ledger; any at all refuses the pool, the same whole-pool-or-nothing rule
  // ownership enforces.
  if (permanentClaimCount > 0) {
    return { action: "skip-permanent-claims",
      reason: `${permanentClaimCount} reservation(s) on this ledger are permanent (immutable, ` +
        "undeletable), so a whole-pool sweep cannot be executed; deleting around them would " +
        "leave a partially applied sweep" };
  }
  // whole-pool-or-nothing (F8): one foreign-owned document leaves the pool intact
  const foreign = ownerIds.filter((o) => !controlled.has(o));
  if (foreign.length > 0) {
    return { action: "skip-foreign", foreign };
  }
  return { action: "sweep", deletePool: true };
};

module.exports = { planPoolSweep };
