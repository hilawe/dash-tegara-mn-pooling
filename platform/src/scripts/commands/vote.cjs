module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const [poolIdStr, proposalHex, choice, delegateTarget] = args;
      const CHOICES = ["yes", "no", "abstain", "delegate", "donothing"];
      if (!poolIdStr || !/^[0-9a-f]{64}$/i.test(proposalHex || "") || !CHOICES.includes(choice)) {
        throw new Error(`usage: vote <poolId> <proposalHash 64-hex> <${CHOICES.join("|")}> [delegateToIdentity]`);
      }
      // v5's targeted delegation: an optional identity whose DIRECT choice this
      // member's weight follows (one hop; resolution rules in tally.cjs)
      if (delegateTarget !== undefined) {
        if (!isV5()) throw new Error("a delegate target needs LEDGER=v5");
        if (choice !== "delegate") throw new Error("a delegate target only makes sense with the delegate choice");
        if (delegateTarget === myId) throw new Error("delegating to yourself withholds your weight; pick a member");
        Identifier.from(delegateTarget); // parse or throw
      }
      await getPool(poolIdStr);
      const identity = await client.platform.identities.get(myId);
      const proposal = Buffer.from(proposalHex, "hex");
      // one preference per member per proposal (unique index); an existing one is
      // UPDATED in place, self-sovereignly, so a member can change their mind
      const mine = (await client.platform.documents.get("poolLedger.votePreference", {
        where: [["poolId", "==", Identifier.from(poolIdStr)],
                ["$ownerId", "==", Identifier.from(myId)],
                ["proposalHash", "==", proposal]],
      }))[0];
      const suffix = delegateTarget ? ` (targeted at ${delegateTarget})` : "";
      if (mine) {
        const prev = mine.toObject().choice;
        // Replace the WHOLE data map via setData. Two reasons, both learned live:
        // set(field, undefined) panics the wasm boundary ("Option::unwrap_throw()
        // on a None value", first hit by a member re-vote through the UI), and a
        // stale delegateTo MUST be cleared on every un-targeted re-vote, because
        // the tally consults it whenever choice is "delegate", so a member going
        // delegate(X) -> yes -> delegate would silently follow X again.
        const o = mine.toObject();
        mine.setData({
          poolId: Buffer.from(o.poolId), proposalHash: Buffer.from(o.proposalHash), choice,
          ...(isV5() && delegateTarget ? { delegateTo: Identifier.from(delegateTarget).toBuffer() } : {}),
        });
        await client.platform.documents.broadcast({ replace: [mine] }, identity);
        console.log(`${who}'s preference on ${proposalHex.slice(0, 16)}... changed ${prev} -> ${choice}${suffix}`);
      } else {
        const doc = await client.platform.documents.create("poolLedger.votePreference", identity, {
          poolId: Identifier.from(poolIdStr).toBuffer(), proposalHash: proposal, choice,
          ...(delegateTarget ? { delegateTo: Identifier.from(delegateTarget).toBuffer() } : {}),
        });
        await client.platform.documents.broadcast({ create: [doc] }, identity);
        console.log(`${who}'s preference on ${proposalHex.slice(0, 16)}... set to ${choice}${suffix}`);
      }
      return;
};
