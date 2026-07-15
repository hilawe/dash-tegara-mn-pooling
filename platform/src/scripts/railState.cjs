/**
 * The credit-rail's persistent state, modeled as ONE phase-tagged journal (the RAIL_STATE
 * key in .env.local). Replaces the three ad-hoc keys the Track C review flagged
 * (RAIL_SLOT, RAIL_JOURNAL, RAIL_CONSUMED); legacy keys are migrated on load and removed
 * on the next save.
 *
 * Shape (version 2):
 *   {
 *     version: 2,
 *     phase:   recorded snapshot of derivePhase() at save time (corruption check on load),
 *     slot:    the designated slot-reward UTXO record (Track C mirroring), or null
 *              { wif, txid, txHex, outputIndex, address, satoshis },
 *     epoch:   the open epoch journal, or null
 *              { txid, txHex, poolId, remainder, epochHeight, observation, accrualsDone,
 *                entries: [{ label, identityId, satoshis, outputIndex, oneTimeKeyWif,
 *                            beforeCredits, credited, transitionHash }] },
 *     consumed: outpoints ("txid:vout") spent outside the wallet's sight, kept forever.
 *   }
 *
 * Phases (derived from content; the stored field is only a cross-check):
 *   idle          no slot, no epoch
 *   slot-funded   slot present, no epoch (crash window between mirroring and the journal)
 *   epoch-open    epoch present with uncredited entries or accruals pending
 *   epoch-settled epoch present, every entry credited and accruals done (awaiting the
 *                 final readback verification before clearing)
 *
 * This module is pure data logic with no SDK or network dependencies, so the mocked
 * resume harness (railStateTest.cjs) can drive the full state matrix offline.
 */
const STATE_KEY = "RAIL_STATE";
const LEGACY_KEYS = ["RAIL_SLOT", "RAIL_JOURNAL", "RAIL_CONSUMED"];

const derivePhase = (state) => {
  if (state.epoch) {
    const settled = state.epoch.entries.every((e) => e.credited) && state.epoch.accrualsDone;
    return settled ? "epoch-settled" : "epoch-open";
  }
  return state.slot ? "slot-funded" : "idle";
};

const isHex64 = (s) => typeof s === "string" && /^[0-9a-f]{64}$/i.test(s);

/**
 * Whether the epoch's transaction provably spends the slot's designated output, checked at
 * the byte level so this module stays dependency-free: a serialized input carries the
 * 32-byte previous txid in internal (reversed) order followed by the 4-byte little-endian
 * output index, so that exact byte run must appear in the raw transaction hex.
 */
const epochSpendsSlot = (epoch, slot) => {
  if (!epoch || !slot || !epoch.txHex || !isHex64(slot.txid) || !Number.isInteger(slot.outputIndex)) return false;
  const idx = Buffer.alloc(4);
  idx.writeUInt32LE(slot.outputIndex, 0);
  const outpointHex = Buffer.concat([Buffer.from(slot.txid, "hex").reverse(), idx]).toString("hex");
  return epoch.txHex.toLowerCase().includes(outpointHex);
};

const validate = (state) => {
  if (state.version !== 2) {
    throw new Error(`RAIL_STATE version ${state.version} is not recognized; refusing to run on it`);
  }
  if (!Array.isArray(state.consumed)) throw new Error("RAIL_STATE.consumed is not a list");
  if (state.epoch) {
    const ep = state.epoch;
    if (!Array.isArray(ep.entries) || ep.entries.length === 0) {
      throw new Error("RAIL_STATE.epoch has no entries; the record is corrupt");
    }
    if (!isHex64(ep.txid) || typeof ep.txHex !== "string" || ep.txHex.length === 0) {
      throw new Error("RAIL_STATE.epoch transaction record is malformed; the record is corrupt");
    }
    const seenIdx = new Set();
    let funderSum = 0;
    for (const e of ep.entries) {
      if (typeof e.credited !== "boolean" || !e.oneTimeKeyWif
        || !Number.isInteger(e.outputIndex) || e.outputIndex < 0
        || !Number.isInteger(e.satoshis) || e.satoshis <= 0) {
        throw new Error("RAIL_STATE.epoch entry is malformed; the record is corrupt");
      }
      if (seenIdx.has(e.outputIndex)) throw new Error("RAIL_STATE.epoch entries repeat a credit-output index");
      seenIdx.add(e.outputIndex);
      if (e.label !== "operator") funderSum += e.satoshis;
    }
    if (Number.isInteger(ep.remainder) && funderSum !== ep.remainder) {
      throw new Error(`RAIL_STATE.epoch funder entries sum to ${funderSum}, remainder says ${ep.remainder}; ` +
        "the record is corrupt");
    }
  }
  if (state.slot && (!state.slot.wif || !isHex64(state.slot.txid)
    || !Number.isInteger(state.slot.outputIndex) || state.slot.outputIndex < 0
    || !Number.isInteger(state.slot.satoshis) || state.slot.satoshis <= 0)) {
    throw new Error("RAIL_STATE.slot is malformed; the record is corrupt");
  }
  if (state.phase !== undefined && state.phase !== derivePhase(state)) {
    throw new Error(`RAIL_STATE phase "${state.phase}" does not match its content ` +
      `("${derivePhase(state)}"); the record was edited or truncated, refusing to guess`);
  }
  return state;
};

/**
 * Load the rail state from a parsed env map, migrating the three legacy keys if the
 * new key is absent. Migration only reads; the legacy keys disappear on the next save().
 *
 * A legacy slot TOGETHER with a legacy journal migrates only when the two are provably
 * one Track C epoch: the journal must carry an observation whose amount matches the
 * slot, and the journal's transaction must spend the slot's designated output. Anything
 * unprovable is refused with both legacy records left in place, because resuming the
 * journal and then clearing state would discard the only copy of the slot's non-wallet
 * key (review finding F2, 2026-07-11).
 */
const load = (env) => {
  if (env[STATE_KEY]) return validate(JSON.parse(env[STATE_KEY]));
  const state = {
    version: 2,
    slot: env.RAIL_SLOT ? JSON.parse(env.RAIL_SLOT) : null,
    epoch: env.RAIL_JOURNAL ? JSON.parse(env.RAIL_JOURNAL) : null,
    consumed: env.RAIL_CONSUMED ? JSON.parse(env.RAIL_CONSUMED) : [],
  };
  if (state.slot && state.epoch) {
    const obs = state.epoch.observation;
    const linked = obs && obs.amountDuffs === state.slot.satoshis && epochSpendsSlot(state.epoch, state.slot);
    if (!linked) {
      throw new Error("legacy RAIL_SLOT and RAIL_JOURNAL are not provably the same Track C epoch " +
        "(no observation, amount mismatch, or the journal transaction does not spend the slot output); " +
        "refusing to migrate. Recover them separately before re-running.");
    }
  }
  return validate(state);
};

/** Serialize the state into the env map (single key), dropping the legacy keys.
 *  RAIL_STATE is an OWNED key (holistic-round F2): it lands through the locked owner
 *  write immediately (losing it can lose the only persisted key material for an
 *  unfinished credit operation), so a foreign saveEnv with a stale env copy can never
 *  clobber it; the caller's env object is kept in step for its own later reads. */
const { updateEnvKey } = require("./envStore.cjs");
const save = (env, state) => {
  state.phase = derivePhase(state);
  validate(state);
  env[STATE_KEY] = JSON.stringify(state);
  updateEnvKey(STATE_KEY, env[STATE_KEY]);
  for (const k of LEGACY_KEYS) delete env[k];
  return env;
};

/**
 * Decide what a rail run should do with the state it found, BEFORE touching the network.
 * observedAmountDuffs is the Track C observation amount, or null on a wallet-funded run.
 *
 * Returns { action, reason }:
 *   fresh                start a new epoch
 *   resume-slot          Track C: re-use the persisted designated UTXO for this amount
 *   refuse-slot-mismatch Track C: a different epoch's slot is unfinished; do not overwrite
 *   refuse-orphan-slot   wallet-funded run while a Track C slot record exists; running on
 *                        would clear the slot key at settle and make its funds
 *                        unrecoverable (hazard found 2026-07-10, fixed by this refusal)
 *   resume-epoch         an interrupted epoch exists; finish it, never start a new one
 *   verify-settled       the epoch looks settled; re-verify the readback, then clear
 */
const resumeAction = (state, observedAmountDuffs) => {
  const phase = derivePhase(state);
  if (phase === "epoch-settled") {
    return { action: "verify-settled", reason: "every entry credited and accruals done" };
  }
  if (phase === "epoch-open") {
    const pending = state.epoch.entries.filter((e) => !e.credited).length;
    return { action: "resume-epoch",
      reason: `${pending} entries uncredited, accruals ${state.epoch.accrualsDone ? "done" : "pending"}` };
  }
  if (phase === "slot-funded") {
    if (observedAmountDuffs == null) {
      return { action: "refuse-orphan-slot",
        reason: `slot ${state.slot.txid}:${state.slot.outputIndex} holds ${state.slot.satoshis} duffs ` +
          "on a non-wallet key; finish or recover that Track C epoch before a wallet-funded run" };
    }
    if (state.slot.satoshis !== observedAmountDuffs) {
      return { action: "refuse-slot-mismatch",
        reason: `slot holds ${state.slot.satoshis} duffs, observation needs ${observedAmountDuffs}` };
    }
    return { action: "resume-slot", reason: `slot tx ${state.slot.txid} matches the observed amount` };
  }
  return { action: "fresh", reason: "no slot, no epoch" };
};

/** Clear a finished epoch. The slot goes with it ONLY when the epoch provably consumed it
 *  (its asset-lock spends the designated output); an unrelated slot record keeps its key
 *  (review finding F2). The consumed list survives forever. */
const clearEpoch = (state) => {
  if (state.slot && !epochSpendsSlot(state.epoch, state.slot)) {
    state.epoch = null; // the slot stays; phase returns to slot-funded
    return state;
  }
  state.epoch = null;
  state.slot = null;
  return state;
};

module.exports = { STATE_KEY, LEGACY_KEYS, load, save, derivePhase, resumeAction, clearEpoch, epochSpendsSlot };
