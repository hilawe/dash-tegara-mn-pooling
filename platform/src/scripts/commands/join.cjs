module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const [poolIdStr, duffsStr] = args;
      const amountDuffs = parseInt(duffsStr, 10);
      if (!poolIdStr || !Number.isInteger(amountDuffs) || amountDuffs <= 0) {
        throw new Error(`usage: ${cmd} <poolId> <amountDuffs>`);
      }
      const pool = await getPool(poolIdStr);
      if (cmd === "exit") {
        const held = (await myShares()).filter((s) =>
          Identifier.from(Buffer.from(s.toObject().poolId)).toString() === poolIdStr);
        if (held.length === 0) {
          console.log("WARNING: you hold no share in this pool; an exit request cannot be matched");
        }
      }
      const identity = await client.platform.identities.get(myId);
      const doc = await client.platform.documents.create("poolLedger.membershipRequest", identity, {
        poolId: pool.getId().toBuffer(), kind: cmd, amountDuffs, status: "pending",
      });
      await client.platform.documents.broadcast({ create: [doc] }, identity);
      console.log(`${cmd} request submitted by ${who} for ${DASHfmt(amountDuffs)} DASH on pool ${poolIdStr}`);
      console.log(`request id ${doc.getId().toString()} [pending]; the matching engine pairs it with a ` +
        `counterparty (matcher.cjs), or "cancel ${doc.getId().toString()}" withdraws it`);
      return;
};
