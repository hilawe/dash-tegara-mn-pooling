module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const pools = await fetchAll(client, "poolLedger.pool");
      console.log(`${pools.length} pools on the ledger:`);
      for (const p of pools) {
        const o = p.toObject();
        const shares = await client.platform.documents.get("poolLedger.share", {
          where: [["poolId", "==", p.getId()]],
        });
        const bps = shares.reduce((s, d) => s + Number(d.toObject().shareBps), 0);
        const mine = shares.some((d) => d.getOwnerId().toString() === myId) ? "  <- member" : "";
        console.log(`  ${p.getId().toString()}  node ${Buffer.from(o.proTxHash).toString("hex").slice(0, 12)}... ` +
          `slot ${o.slotIndex}, fee ${Number(o.operatorFeeBps)} bps, shares ${bps}/10000${mine}`);
      }
      return;
};
