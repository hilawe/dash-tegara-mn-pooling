/**
 * Validation for a version-1 epoch observation (the Track C relay inflow exported by
 * feature_tegara_retail_vertical.py). Shared by the credit-rail (loadObservation) and the
 * standalone verifier (verifyObservation.cjs) so there is exactly one implementation of
 * what a well-formed observation is.
 */
const ASSET_LOCK_FEE_DUFFS = 10000; // flat L1 fee when spending the designated reward UTXO

const isHex = (s, len) => typeof s === "string" && s.length === len && /^[0-9a-f]+$/i.test(s);
const isPosInt = (n) => Number.isInteger(n) && n > 0;

/** Throws with a named field on the first schema violation; returns the observation. */
const validateObservation = (obs, label = "observation") => {
  const fail = (why) => { throw new Error(`${label} is not a valid version-1 epoch observation (${why})`); };
  if (obs.version !== 1) fail("version");
  if (obs.network !== "fork-regtest") fail("network");
  if (!isHex(obs.proTxHash, 64)) fail("proTxHash");
  if (!isHex(obs.coinbaseTxid, 64)) fail("coinbaseTxid");
  if (!isHex(obs.blockHash, 64)) fail("blockHash");
  if (!isPosInt(obs.amountDuffs)) fail("amountDuffs");
  if (!isPosInt(obs.height)) fail("height");
  if (!isPosInt(obs.mnRewardDuffs)) fail("mnRewardDuffs");
  if (!isPosInt(obs.shareAmountDuffs)) fail("shareAmountDuffs");
  if (!isPosInt(obs.collateralDuffs)) fail("collateralDuffs");
  if (!isPosInt(obs.registeredHeight)) fail("registeredHeight");
  if (!Number.isInteger(obs.operatorRewardBps) || obs.operatorRewardBps < 0 || obs.operatorRewardBps > 10000) {
    fail("operatorRewardBps");
  }
  if (!Number.isInteger(obs.slotIndex) || obs.slotIndex < 0) fail("slotIndex");
  if (!Number.isInteger(obs.rewardVout) || obs.rewardVout < 0) fail("rewardVout");
  if (typeof obs.rewardAddress !== "string" || obs.rewardAddress.length === 0) fail("rewardAddress");
  if (typeof obs.rewardScriptHex !== "string" || !/^[0-9a-f]+$/i.test(obs.rewardScriptHex)) fail("rewardScriptHex");
  // cross-field consistency (the relay file itself is still trusted; see bridge/README.md)
  if (obs.amountDuffs > obs.mnRewardDuffs) fail("slot amount above the whole masternode reward");
  if (obs.shareAmountDuffs > obs.collateralDuffs) fail("share above the collateral");
  if (obs.registeredHeight > obs.height) fail("payment before registration");
  if (obs.amountDuffs <= ASSET_LOCK_FEE_DUFFS) {
    throw new Error(`observed reward ${obs.amountDuffs} duffs cannot cover the ${ASSET_LOCK_FEE_DUFFS}-duff L1 fee`);
  }
  return obs;
};

/**
 * The slot amount the DIP-0026 amount-weighted split predicts for this observation.
 * The owner reward is the masternode reward minus the L1 operator cut; a non-last slot
 * gets the floored pro-rata amount and the last slot absorbs the rounding remainder.
 *
 * All arithmetic is BigInt: the pro-rata numerator multiplies two duff-scale values
 * (ownerReward times a share of the 1000-DASH collateral, on the order of 1e19), which
 * is far above Number.MAX_SAFE_INTEGER, and Number math computed a wrong floor there
 * (review finding F4, 2026-07-11). Results convert back to Number only because each is
 * itself a duff amount below 2^53.
 */
const expectedSlotAmount = (obs) => {
  const mnReward = BigInt(obs.mnRewardDuffs);
  const operatorCut = (mnReward * BigInt(obs.operatorRewardBps)) / 10000n;
  const ownerReward = mnReward - operatorCut;
  const floor = (ownerReward * BigInt(obs.shareAmountDuffs)) / BigInt(obs.collateralDuffs);
  return { ownerReward: Number(ownerReward), floor: Number(floor) };
};

/**
 * The exact per-slot amounts for a full share table (BigInt floors, the rounding
 * remainder to the LAST slot), used by the live verifier once the DMN share table is in
 * hand (review finding F5).
 */
const exactSlotAmounts = (ownerRewardDuffs, shareAmounts) => {
  const ownerReward = BigInt(ownerRewardDuffs);
  const collateral = shareAmounts.reduce((s, a) => s + BigInt(a), 0n);
  const floors = shareAmounts.map((a) => (ownerReward * BigInt(a)) / collateral);
  const leftover = ownerReward - floors.reduce((s, f) => s + f, 0n);
  return floors.map((f, i) => Number(i === shareAmounts.length - 1 ? f + leftover : f));
};

/**
 * Validation for a version-1 DISSOLUTION observation (the principal-return relay input):
 * the covenant dissolved the shared masternode and paid the group slot's principal (plus
 * any penalty bonus owed to it) to the group's immutable refund address in ONE output.
 * The rail's dissolution mode distributes that amount to the pool's recorded members.
 */
const validateDissolution = (obs, label = "dissolution observation") => {
  const fail = (why) => { throw new Error(`${label} is not a valid version-1 dissolution observation (${why})`); };
  if (obs.version !== 1) fail("version");
  if (obs.kind !== "dissolution") fail("kind");
  if (obs.network !== "fork-regtest") fail("network");
  if (!isHex(obs.proTxHash, 64)) fail("proTxHash");
  if (!isHex(obs.dissolutionTxid, 64)) fail("dissolutionTxid");
  if (!isHex(obs.blockHash, 64)) fail("blockHash");
  if (!isPosInt(obs.amountDuffs)) fail("amountDuffs");
  if (!isPosInt(obs.height)) fail("height");
  if (!isPosInt(obs.collateralDuffs)) fail("collateralDuffs");
  if (!isPosInt(obs.shareAmountDuffs)) fail("shareAmountDuffs");
  if (!Number.isInteger(obs.refundVout) || obs.refundVout < 0) fail("refundVout");
  if (!Number.isInteger(obs.slotIndex) || obs.slotIndex < 0) fail("slotIndex");
  if (typeof obs.refundAddress !== "string" || obs.refundAddress.length === 0) fail("refundAddress");
  if (typeof obs.refundScriptHex !== "string" || !/^[0-9a-f]+$/i.test(obs.refundScriptHex)) fail("refundScriptHex");
  // the refund is the slot's principal plus at most the whole penalty pool, never the
  // entire collateral or more
  if (obs.amountDuffs < obs.shareAmountDuffs) fail("refund below the slot principal");
  if (obs.amountDuffs > obs.collateralDuffs) fail("refund above the node collateral");
  if (obs.amountDuffs <= ASSET_LOCK_FEE_DUFFS) fail("cannot cover the L1 fee");
  return obs;
};

module.exports = { ASSET_LOCK_FEE_DUFFS, validateObservation, validateDissolution,
  expectedSlotAmount, exactSlotAmounts };
