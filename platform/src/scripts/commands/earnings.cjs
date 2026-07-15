module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const accruals = await myAccruals();
      const byPool = new Map();
      for (const d of accruals) {
        const o = d.toObject();
        const pid = Identifier.from(Buffer.from(o.poolId)).toString();
        if (!byPool.has(pid)) byPool.set(pid, []);
        byPool.get(pid).push({ height: Number(o.epochHeight), duffs: Number(o.amountDuffs),
          kind: o.kind || null });
      }
      // v4 accruals distinguish reward income from returned principal; summing both as
      // "earned" would overstate income by the member's own capital coming home
      // (batch-3 review note). Kind-less pre-v4 accruals are rewards by construction.
      let rewards = 0, principal = 0, rewardCount = 0;
      for (const [pid, list] of byPool) {
        console.log(`pool ${pid}:`);
        for (const e of list.sort((a, b) => a.height - b.height)) {
          console.log(`  epoch ${e.height}${e.kind ? ` [${e.kind}]` : ""}: ${DASHfmt(e.duffs)} DASH`);
          if (e.kind === "principal") { principal += e.duffs; } else { rewards += e.duffs; rewardCount++; }
        }
      }
      console.log(`\ntotal earned by ${who}: ${DASHfmt(rewards)} DASH across ${rewardCount} epochs` +
        (principal > 0 ? `; plus ${DASHfmt(principal)} DASH of returned principal (capital, not income)` : ""));
      return;
};
