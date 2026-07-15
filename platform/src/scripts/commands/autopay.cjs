module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    loadEnv, updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const sub = args[0];
      // read the preference FRESH from disk, not from the startup env copy, and write
      // it through the locked owner path; AUTOPAY_* is an owned prefix in envStore, so
      // a foreign save with a stale copy can neither revert nor erase the toggle
      // (independent-review finding)
      const enabled = loadEnv()[autopayKeyOf()] === "on";
      // the sweep floor keeps R5's no-dust promise: below it, rewards keep accumulating
      const MIN_SWEEP_DUFFS = journal.toBig(process.env.AUTOPAY_MIN_DUFFS || "1000000", "AUTOPAY_MIN_DUFFS");

      if (sub === "on" || sub === "off") {
        updateEnvKey(autopayKeyOf(), sub);
        console.log(`autopay is now ${sub} for ${who} on this ledger` +
          (sub === "on" ? ` (run "autopay run" to sweep, or "watch loop" to sweep on a cadence)` : ""));
        return;
      }

      if (sub === "status") {
        await journal.reconcile(journalContract, myId, requestExists, console.log);
        const earned = await earnedRewardsBig();
        const { consumedDuffs } = journal.summary(journalContract, myId);
        const ceiling = earned - consumedDuffs;
        console.log(`autopay: ${enabled ? "ON" : "OFF"} (floor ${DASHfmt(MIN_SWEEP_DUFFS)} DASH)`);
        console.log(`sweepable now: ${DASHfmt(ceiling)} DASH of uncompounded rewards` +
          (ceiling < MIN_SWEEP_DUFFS ? " (below the floor; a sweep would skip)" : ""));
        return;
      }

      if (sub === "run") {
        if (!enabled) {
          console.log('autopay is OFF; enable with "autopay on" (a sweep only runs when the member chose it)');
          process.exitCode = 1; return;
        }
        try {
          const outcome = await runAutopaySweep(false);
          if (outcome === "unbacked") process.exitCode = 1;
        } catch { process.exitCode = 1; }
        return;
      }

      throw new Error('usage: autopay <on|off|status|run>');
};
