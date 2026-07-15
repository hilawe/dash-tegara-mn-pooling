module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const identity = await client.platform.identities.get(myId);
      console.log(`${who} ${myId}`);
      console.log(`credits: ${identity.getBalance()} (${DASHfmt(Number(identity.getBalance()) / 1000)} DASH equivalent)`);

      // one accrual fetch serves the earnings summary AND the per-pool payout timing
      // (G7): last-paid epoch height and epoch count per pool, from ALL members'
      // accruals, since a pool pays everyone at once
      const allAccruals = await fetchAll(client, "poolLedger.rewardAccrual");
      const poolStats = new Map();
      for (const a of allAccruals) {
        const o = a.toObject();
        if (o.kind === "principal") continue;
        const pid = Identifier.from(Buffer.from(o.poolId)).toString();
        const st = poolStats.get(pid) || { last: 0, heights: new Set() };
        const h = Number(o.epochHeight);
        st.last = Math.max(st.last, h); st.heights.add(h);
        poolStats.set(pid, st);
      }

      const shares = await myShares();
      console.log(`\nshares held: ${shares.length}`);
      for (const s of shares) {
        const o = s.toObject();
        const pid = Identifier.from(Buffer.from(o.poolId)).toString();
        const st = poolStats.get(pid);
        // "recorded since" is the share document's own creation time: for a matched
        // join that is exactly when this owner took the share over
        const since = new Date(Number(o.$createdAt)).toISOString();
        console.log(`  pool ${short(pid)} ${Number(o.shareBps)} bps, ` +
          `contribution ${DASHfmt(o.contributionDuffs)} DASH, recorded since ${since}`);
        console.log(`    ${st ? `last paid at core height ${st.last} (${st.heights.size} reward ` +
          `epoch${st.heights.size === 1 ? "" : "s"} recorded; epochs are operator-driven on this devnet)`
          : "no reward epochs recorded for this pool yet"}`);
      }

      const reqs = await myRequests();
      const open = reqs.filter((r) => r.toObject().status !== "settled");
      console.log(`\nrequests: ${reqs.length} total, ${open.length} open`);
      for (const r of open) {
        const o = r.toObject();
        console.log(`  ${o.kind} ${DASHfmt(o.amountDuffs)} DASH on pool ` +
          `${short(Identifier.from(Buffer.from(o.poolId)).toString())} [${o.status}] id ${r.getId().toString()}` +
          `, submitted ${new Date(Number(o.$createdAt)).toISOString()}` +
          (o.status === "pending" ? " (earns after a match settles)" : ""));
      }

      const accruals = allAccruals.filter(isMyAccrual);
      const earned = accruals.filter((d) => d.toObject().kind !== "principal")
        .reduce((s, d) => s + Number(d.toObject().amountDuffs), 0);
      const returned = accruals.filter((d) => d.toObject().kind === "principal")
        .reduce((s, d) => s + Number(d.toObject().amountDuffs), 0);
      console.log(`\nearnings: ${accruals.length} accruals, ${DASHfmt(earned)} DASH earned` +
        (returned > 0 ? ` plus ${DASHfmt(returned)} DASH returned principal` : "") + ` (see "earnings")`);
      return;
};
