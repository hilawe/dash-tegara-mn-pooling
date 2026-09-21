module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep,
    hasE2Records, myPlatformAccruals, creditsBig } = ctx;
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

      // THE CREDIT RAIL, shown separately and only on an e2Records ledger (the
      // v11 rail decision): platform accruals are CREDITS with their own epoch
      // numbering (epochIndex, not core heights), summed through creditsBig,
      // and NEVER combined into the DASH totals above
      // a failed credit-rail read is contained and LOUD: the DASH section
      // above already printed, so the failure marks the output partial
      // (non-zero exit) instead of erasing it or passing as complete
      if (hasE2Records()) try {
        const plats = await myPlatformAccruals();
        if (plats.length > 0) {
          const byPoolP = new Map();
          for (const d of plats) {
            const o = d.toObject();
            const pid = Identifier.from(Buffer.from(o.poolId)).toString();
            if (!byPoolP.has(pid)) byPoolP.set(pid, []);
            byPoolP.get(pid).push(o);
          }
          console.log("\nplatform-credit income (the credit rail, separate from the DASH totals above):");
          let credits = 0n;
          for (const [pid, list] of byPoolP) {
            console.log(`pool ${pid}:`);
            for (const o of list.sort((a, b) => Number(a.epochIndex) - Number(b.epochIndex))) {
              const c = creditsBig(o.amountCredits);
              credits += c;
              console.log(`  platform epoch ${o.epochIndex}: ${c} credits`);
            }
          }
          console.log(`platform income total for ${who}: ${credits} credits across ${plats.length} accrual(s)`);
        }
      } catch (e) {
        console.error(`platform-credit income UNAVAILABLE (${(e && e.message) || e}); ` +
          "the DASH figures above stand, this output is PARTIAL");
        process.exitCode = 1;
      }
      return;
};
