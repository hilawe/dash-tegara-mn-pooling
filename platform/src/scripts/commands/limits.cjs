module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      // G6: the withdrawal expectations read. RE-DERIVED 2026-09-23 after dashpay/dash#7712 merged
      // into develop and replaced the v24 limit this file used to hardcode, a flat 4000 DASH of
      // gross unlocks per 576 core blocks. That number was never the rule in force on mainnet,
      // because v24 is not active there, and after #7712 it is not the v24 rule either.
      //
      // THE CORE-SIDE RULE DEPENDS ON THE DEPLOYMENT, per `src/evo/creditpool.cpp`,
      // `ConstructCreditPool`, at the #7712 merge commit 1e4d2631:
      //   - v22 withdrawals rule, in force on mainnet and testnet today: the limit for a block is
      //     the credit pool balance or 2000 DASH, whichever is smaller, and a block's unlocks are
      //     checked against it. READ, NOT EXECUTED. Unlike the pre-v22 rule and the old v24 rule,
      //     this branch does not subtract what was unlocked earlier in the window, so it reads as
      //     a per-block cap rather than a per-window one.
      //   - v24, not yet active on mainnet or testnet: a relative net rule. Unlocks may not leave
      //     the pool below its balance one window earlier minus 20% of that balance, never less
      //     than 2000 DASH and with no upper bound, and deposits inside the window are
      //     withdrawable again.
      // WHAT WAS NOT CHECKED is whether Platform applies withdrawal limits of its own on top of
      // Core's, which is why the user-facing text below states no network figure as a number.
      //
      // LIVE CAPACITY IS NOW QUERYABLE ON CORE, just not from here. #7712 added
      // `getcreditpoolinfo`, which reports the exact limit for the next block, in develop builds
      // only. This command reads through the Platform SDK, which has nothing like it. So the one
      // bound stated as a number is the member's own balance, and nothing implies that network
      // capacity is available now.
      const identity = await client.platform.identities.get(myId);
      const balance = BigInt(identity.getBalance());
      const balanceDuffs = balance / 1000n;
      console.log(`${who} ${myId}`);
      console.log(`credits: ${balance} (${DASHfmt(balanceDuffs)} DASH equivalent)`);
      console.log(`\nwithdrawal expectations:`);
      console.log(`  - the most one withdrawal can take is your credit balance: ${DASHfmt(balanceDuffs)} DASH,`);
      console.log("    before fees");
      console.log("  - the network also caps all Platform withdrawals together. The cap depends on the Dash");
      console.log("    Core rules in force and on live network state, and this command cannot read how much");
      console.log("    of it is left right now");
      console.log("  - the v24 upgrade, not yet active on mainnet or testnet, changes that cap to one that");
      console.log("    grows with the amount of Platform credits held, and is never less than 2000 DASH");
      console.log("  - heavy network-wide withdrawal traffic can delay everyone's withdrawals");
      console.log("  - mechanics: a withdrawal is a quorum-signed asset-unlock. It pays your address a few");
      console.log("    core blocks after the transition is accepted, and no single party signs it");
      console.log('  - "withdraw" reports what actually happened, whether or not the network was busy');
      return;
};
