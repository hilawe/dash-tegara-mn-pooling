module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      // G6: the honest expectations read. The throttle values are the deployed v24
      // consensus bounds (validated in the CN-3 analysis); the SDK exposes no live
      // queue or remaining-capacity query, and this says so instead of guessing.
      const identity = await client.platform.identities.get(myId);
      const balance = BigInt(identity.getBalance());
      const balanceDuffs = balance / 1000n;
      const THROTTLE_DUFFS = 400000000000n; // 4000 DASH per ~576 core blocks, network-wide
      const maxNow = balanceDuffs < THROTTLE_DUFFS ? balanceDuffs : THROTTLE_DUFFS;
      console.log(`${who} ${myId}`);
      console.log(`credits: ${balance} (${DASHfmt(balanceDuffs)} DASH equivalent)`);
      console.log(`\nwithdrawal expectations:`);
      // "theoretical upper bound", never "available now": remaining network capacity is
      // not queryable, so implying live availability would overstate what this code can
      // know (independent-review finding)
      console.log(`  - theoretical upper bound for one withdrawal: ${DASHfmt(maxNow)} DASH (your balance,`);
      console.log("    capped by the full-period network limit; excludes fees, and does NOT account for");
      console.log("    capacity other withdrawals have already consumed, which is not queryable)");
      console.log("  - the network throttle: 4000 DASH per ~576 core blocks (about a day), shared by ALL");
      console.log("    Platform withdrawals; heavy network-wide withdrawal traffic delays everyone's");
      console.log("  - mechanics: a withdrawal is a quorum-signed asset-unlock; it pays your address a few");
      console.log("    core blocks after the transition is accepted (no single party signs it)");
      console.log("  - the SDK exposes no live queue or remaining-throttle query, so a withdrawal during");
      console.log('    heavy traffic may sit longer than usual; "withdraw" reports honestly either way');
      return;
};
