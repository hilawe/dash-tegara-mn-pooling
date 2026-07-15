module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const reqs = await myRequests();
      console.log(`${reqs.length} requests by ${who}:`);
      for (const r of reqs) {
        const o = r.toObject();
        console.log(`  ${o.kind} ${DASHfmt(o.amountDuffs)} DASH on pool ` +
          `${short(Identifier.from(Buffer.from(o.poolId)).toString())} [${o.status}] id ${r.getId().toString()}`);
      }
      return;
};
