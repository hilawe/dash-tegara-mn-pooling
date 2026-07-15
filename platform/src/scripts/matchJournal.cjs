/**
 * The matching engine's settlement journal (MATCH_STATE in .env.local), the fix for
 * review finding F1 (2026-07-11, raised independently by two reviewers): the existing-pool
 * handover used to delete the leaver's share before its bps, contribution, or reward
 * script were persisted anywhere, and a restart only discovered `pending` requests, so a
 * crash mid-settlement made the pair invisible and the pool's recorded capital
 * unrecoverable from the ledger.
 *
 * One settlement at a time. The journal snapshots the pair AND the old share BEFORE any
 * status changes, then the driver walks explicit phases, persisting after each:
 *
 *   prepared         journal written; nothing on the ledger touched yet
 *   matched          both requests moved pending -> matched
 *   share-deleted    the leaver's share is gone (the snapshot is now the only copy)
 *   share-recreated  the joiner's share exists with the same bps and contribution
 *   settled          both requests moved matched -> settled; caller clears the journal
 *
 * driveSettlement takes the ledger operations as callbacks, so the offline harness can
 * mock them and crash the driver at every phase boundary, restart it, and assert the
 * end state (the crash-point model test the review asked for). The matcher supplies the
 * real Platform operations. Status moves are idempotent: a move whose target state
 * already holds is a no-op, so re-driving a phase after a crash cannot fail on its own
 * earlier progress. On-ledger settlement documents (visible to every engine, not just
 * this operator) are the production shape, recorded for a future contract version.
 */
const STATE_KEY = "MATCH_STATE";
const PHASES = ["prepared", "matched", "share-deleted", "share-recreated", "settled"];

const validate = (state) => {
  if (state.version !== 1) throw new Error(`MATCH_STATE version ${state.version} is not recognized`);
  if (state.settlement) {
    const s = state.settlement;
    if (!PHASES.includes(s.phase)) throw new Error(`MATCH_STATE phase "${s.phase}" is not recognized`);
    if (!s.poolId || !s.exitId || !s.joinId || !s.leaverId || !s.joinerId
      || !Number.isInteger(s.amountDuffs) || s.amountDuffs <= 0
      || !s.share || !Number.isInteger(s.share.shareBps) || s.share.shareBps <= 0
      || !Number.isInteger(s.share.contributionDuffs)) {
      throw new Error("MATCH_STATE settlement record is malformed; refusing to guess");
    }
  }
  return state;
};

const load = (env) => (env[STATE_KEY] ? validate(JSON.parse(env[STATE_KEY])) : { version: 1, settlement: null });

// MATCH_STATE is an OWNED key (holistic-round F2): the journal lands through the locked
// owner write immediately, so a foreign saveEnv with a stale env copy can never clobber
// it; the caller's env object is kept in step for its own later reads.
const { updateEnvKey } = require("./envStore.cjs");
const save = (env, state) => {
  validate(state);
  env[STATE_KEY] = JSON.stringify(state);
  updateEnvKey(STATE_KEY, env[STATE_KEY]);
  return env;
};

/**
 * Drive an open settlement from its current phase to `settled`. ops supplies the ledger:
 *   setStatus(requestId, ownerId, from, to)  idempotent compare-and-set
 *   leaverShareExists()                      the leaver still owns a share in the pool
 *   joinerShareExists()                      the joiner already owns a share in the pool
 *   deleteLeaverShare()
 *   recreateJoinerShare(snapshot)            same bps/contribution, joiner's own script
 *   persist()                                write the journal (called after every phase move)
 */
const driveSettlement = async (state, ops, log = () => {}) => {
  const s = state.settlement;
  if (!s) return;
  if (s.phase === "prepared") {
    await ops.setStatus(s.exitId, s.leaverId, "pending", "matched");
    await ops.setStatus(s.joinId, s.joinerId, "pending", "matched");
    s.phase = "matched"; await ops.persist();
    log("phase: matched");
  }
  if (s.phase === "matched") {
    if (await ops.leaverShareExists()) await ops.deleteLeaverShare();
    s.phase = "share-deleted"; await ops.persist();
    log("phase: share-deleted");
  }
  if (s.phase === "share-deleted") {
    if (!(await ops.joinerShareExists())) await ops.recreateJoinerShare(s.share);
    s.phase = "share-recreated"; await ops.persist();
    log("phase: share-recreated");
  }
  if (s.phase === "share-recreated") {
    await ops.setStatus(s.exitId, s.leaverId, "matched", "settled");
    await ops.setStatus(s.joinId, s.joinerId, "matched", "settled");
    s.phase = "settled"; await ops.persist();
    log("phase: settled");
  }
};

const clearSettlement = (state) => { state.settlement = null; return state; };

module.exports = { STATE_KEY, PHASES, load, save, validate, driveSettlement, clearSettlement };
