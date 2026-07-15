module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  let myId = ctx.myId;
      // G1: one flow from "has DASH in the wallet" to "funded identity with a pending
      // join request". The KB's eleven onboarding articles collapse into this because
      // identity replaces the account: no email, no 2FA service, no address ceremonies.
      const [depositStr, poolIdStr, joinStr] = args;
      if (!/^[1-9][0-9]*$/.test(depositStr || "") || (poolIdStr && !/^[1-9][0-9]*$/.test(joinStr || ""))) {
        throw new Error("usage: onboard <depositDuffs> [<poolId> <joinDuffs>]");
      }
      const depositBig = journal.toBig(depositStr, "onboard deposit");

      // 1. the identity (the member's account, keyed by their own wallet)
      if (myId) {
        console.log(`step 1: ${who} already has identity ${myId}; reusing it`);
      } else {
        console.log(`step 1: registering ${who}'s Platform identity (keys derived from the wallet) ...`);
        const identity = await client.platform.identities.register();
        myId = identity.getId().toString(); ctx.setMyId(myId);
        updateEnvKey(whoIdKey, myId);
        console.log(`  identity registered: ${myId} (persisted as ${whoIdKey})`);
      }

      // 2. the deposit, honoring the KB's test-deposit instinct: a small probe first,
      // verified, then the remainder (a single deposit when the amount is too small to
      // split usefully)
      const PROBE = 1000000n; // 0.01 DASH
      if (depositBig > PROBE * 2n) {
        console.log("step 2: probe deposit first (start small, verify, then commit) ...");
        const probeCredited = await depositOwnFunds(PROBE, "probe deposit");
        if (probeCredited === null) {
          // the instruction carries the EXACT remainder: a bare "re-run onboard" would
          // deposit a fresh probe plus the full amount again (independent-review finding)
          console.log("the probe's readback was inconclusive; stopping BEFORE the main deposit. " +
            `Verify with "portfolio": if the probe credited, deposit the remainder with ` +
            `"deposit ${(depositBig - PROBE).toString()}" (do NOT re-run onboard with the full ` +
            "amount; deposits are cumulative).");
          process.exitCode = 1; return;
        }
        console.log("  probe verified; depositing the remainder ...");
        if (await depositOwnFunds(depositBig - PROBE, "main deposit") === null) {
          console.log('main deposit readback inconclusive; re-check with "portfolio"');
          process.exitCode = 1; return;
        }
      } else if (await depositOwnFunds(depositBig, "deposit") === null) {
        console.log('deposit readback inconclusive; re-check with "portfolio"');
        process.exitCode = 1; return;
      }

      // 3. discovery, and the optional first join
      const pools = await fetchAll(client, "poolLedger.pool");
      console.log(`step 3: ${pools.length} pool(s) on the ledger (details: the "pools" command)`);
      if (poolIdStr) {
        const pool = await getPool(poolIdStr);
        const joinBig = journal.toBig(joinStr, "join amount");
        const identity = await client.platform.identities.get(myId);
        const doc = await client.platform.documents.create("poolLedger.membershipRequest", identity, {
          poolId: pool.getId().toBuffer(), kind: "join",
          amountDuffs: journal.toSafeNumber(joinBig, "join amount"), status: "pending",
        });
        await client.platform.documents.broadcast({ create: [doc] }, identity);
        console.log(`step 4: join request ${doc.getId().toString()} [pending] for ` +
          `${DASHfmt(joinBig)} DASH on pool ${poolIdStr}`);
      }

      const balance = BigInt((await client.platform.identities.get(myId)).getBalance());
      console.log(`\n=== ONBOARD COMPLETE: ${who} is identity ${myId} with ${balance} credits ` +
        `(${DASHfmt(balance / 1000n)} DASH equivalent)${poolIdStr ? ", join request pending" : ""} ===`);
      console.log("what to safeguard: the wallet seed is the whole backup story; read " +
        "tegara/docs/KEYS_AND_RECOVERY.md");
      return;
};
