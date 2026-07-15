module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const [duffsStr] = args;
      // canonical-integer discipline as in withdraw (review finding B7); the working
      // half lives in depositOwnFunds, shared with onboard
      if (!/^[1-9][0-9]*$/.test(duffsStr || "")) {
        throw new Error("usage: deposit <amountDuffs, canonical positive integer>");
      }
      const credited = await depositOwnFunds(journal.toBig(duffsStr, "deposit amount"), "deposit");
      // the delta is a consistency check that assumes no concurrent activity on this
      // identity; by this point the top-up itself was ACCEPTED, so an odd delta is
      // reported as an inconclusive readback, not as a refused deposit
      // (independent-review finding)
      if (credited === null) {
        console.log("\n=== DEPOSIT SUBMITTED, READBACK INCONCLUSIVE: the top-up was accepted, but the " +
          "balance delta does not match an isolated deposit (concurrent spends or credits on this " +
          "identity?). Re-check with \"portfolio\" ===");
        process.exitCode = 1;
        return;
      }
      console.log(`\n=== DEPOSIT OK: ${who}'s own L1 DASH became credits at ${who}'s own identity ===`);
      return;
};
