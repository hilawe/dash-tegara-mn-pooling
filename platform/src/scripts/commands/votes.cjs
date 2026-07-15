module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const [poolIdStr, proposalHex] = args;
      if (!poolIdStr || !/^[0-9a-f]{64}$/i.test(proposalHex || "")) {
        throw new Error("usage: votes <poolId> <proposalHash 64-hex>");
      }
      const prefs = await fetchAll(client, "poolLedger.votePreference", {
        where: [["poolId", "==", Identifier.from(poolIdStr)]],
      });
      const forProposal = prefs.filter((d) =>
        Buffer.from(d.toObject().proposalHash).toString("hex") === proposalHex.toLowerCase());
      console.log(`${forProposal.length} preference(s) on ${proposalHex.slice(0, 16)}...:`);
      for (const d of forProposal) {
        console.log(`  ${d.toObject().choice}  by ${d.getOwnerId().toString()}`);
      }
      return;
};
