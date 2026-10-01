"use strict";
/**
 * THE COORDINATOR'S HALF of the guided member trial (tegara/docs/GUIDED_MEMBER_TRIAL.md): two
 * proposals for one pool, built from the member's PUBLIC card, one carrying the terms the member
 * agreed to and one altered. Which file is which is drawn at random and written only to the
 * coordinator's answer file, so the member has to tell them apart from the terms.
 *
 * THE ALTERATION leaves every key of the member's own share intact. At revision 1 it moves 100 DASH of
 * the member's contribution to the other member and raises the early-exit penalty. At revision 2 it
 * keeps the amounts and changes the early-exit period and the operator reward, so the member's record
 * of the agreed terms is compared on terms the first pair did not touch. At revision 3 it changes only
 * the member's registration fee share, the smallest figure on the screen and the one term the first two
 * pairs left alone. Only the member knows what was agreed, which is why the member tool compares every
 * proposal with the member's own record.
 */
const crypto = require("crypto");
const { CORE_GENESIS_BY_PLATFORM_CHAIN } = require("./memberApprovalLedger.cjs");

const COIN = 100000000;
// THE TERMS THE MEMBER AGREED TO, stated in the trial guide before any proposal is seen
// THE PROPOSAL IS VERSION 2 since the #7437 format unit (2026-10-01): its agreement carries the registration
// terms in the chain's own shapes (registrationTerms.cjs), the operator reward in basis points
const AGREED = Object.freeze({ memberDuffs: 400 * COIN, otherDuffs: 600 * COIN, earlyPeriodBlocks: 100,
  earlyPenaltyDuffs: 10 * COIN, operatorRewardBps: 500, memberFeeDuffs: 10000 });
const ALTERED = Object.freeze({ memberDuffs: 300 * COIN, otherDuffs: 700 * COIN, earlyPenaltyDuffs: 50 * COIN });
const ALTERED_BY_REVISION = Object.freeze({
  1: ALTERED,
  2: Object.freeze({ earlyPeriodBlocks: 400, operatorRewardBps: 800 }),
  3: Object.freeze({ memberFeeDuffs: 100000 }),
});
const ALTERATION_TEXT = Object.freeze({
  1: "the member's contribution 400 -> 300 DASH (the other member's 600 -> 700) and the early-exit penalty 10 -> 50 DASH; every key unchanged",
  2: "the early-exit period 100 -> 400 blocks and the operator reward 500 -> 800 basis points (5% -> 8%); amounts, penalty and every key unchanged",
  3: "the member's registration fee share 0.0001 -> 0.001 DASH; every other term and every key unchanged",
});
/** The two file names for a revision: 1 and 2 for revision 1, 3 and 4 for revision 2, 5 and 6 for revision 3. */
const fileNames = (revision) => [`proposal-${2 * revision - 1}.json`, `proposal-${2 * revision}.json`];

const POOL_LABEL = "tegara guided member trial pool, 2026-09-30, not on the ledger";

/**
 * card: the member's public card. other: { owner, refund, reward } addresses of the coordinator's
 * test member. ids: { platformChainId, contractId, approvalContractId, approvalContractOwnerB58 }.
 * tipHeight: the testnet Layer 1 height now. rand: () => 0 or 1 (injected, for the battery).
 */
function buildTrialProposals({ card, other, operatorPubKey, votingAddress, ids, tipHeight, revision = 1, rand = () => crypto.randomInt(2) }) {
  if (!Object.hasOwn(ALTERED_BY_REVISION, revision)) throw new Error(`coordinatorTrial: no alteration is defined for revision ${revision}`);
  if (!card || !card.addresses || !card.identityB58) throw new Error("coordinatorTrial: the member card has no identity yet");
  const genesis = CORE_GENESIS_BY_PLATFORM_CHAIN[ids.platformChainId];
  if (!genesis) throw new Error(`coordinatorTrial: no Core chain recorded for ${ids.platformChainId}`);
  const poolId = crypto.createHash("sha256").update(POOL_LABEL).digest("hex");
  const make = (terms) => ({
    kind: "tegara.coowner.proposal", version: 2,
    platformChainId: ids.platformChainId, contractId: ids.contractId,
    approvalContractId: ids.approvalContractId, approvalContractOwnerB58: ids.approvalContractOwnerB58,
    poolId, poolNote: "a trial identifier, not a pool on the ledger", l1GenesisHash: genesis,
    notAfterHeight: tipHeight + 20000, revision,
    agreement: {
      registration: {
        shares: [
          { amount: terms.memberDuffs ?? AGREED.memberDuffs, ownerAddress: card.addresses.owner, refundAddress: card.addresses.refund, rewardAddress: card.addresses.reward },
          { amount: terms.otherDuffs ?? AGREED.otherDuffs, ownerAddress: other.owner, refundAddress: other.refund, rewardAddress: other.reward },
        ],
        operatorPubKey, votingAddress, operatorRewardBps: terms.operatorRewardBps ?? AGREED.operatorRewardBps,
        earlyPeriodBlocks: terms.earlyPeriodBlocks ?? AGREED.earlyPeriodBlocks, earlyPenalty: terms.earlyPenaltyDuffs ?? AGREED.earlyPenaltyDuffs,
      },
      myIndex: 0, myFeeDuffs: terms.memberFeeDuffs ?? AGREED.memberFeeDuffs,
    },
  });
  const agreed = make({});
  const altered = make(ALTERED_BY_REVISION[revision]);
  const alteredFirst = rand() === 1;
  const [first, second] = fileNames(revision);
  return {
    files: { [first]: alteredFirst ? altered : agreed, [second]: alteredFirst ? agreed : altered },
    answer: { revision, agreed: alteredFirst ? second : first, altered: alteredFirst ? first : second, alteration: ALTERATION_TEXT[revision] },
  };
}

module.exports = { AGREED, ALTERED, ALTERED_BY_REVISION, POOL_LABEL, fileNames, buildTrialProposals };
