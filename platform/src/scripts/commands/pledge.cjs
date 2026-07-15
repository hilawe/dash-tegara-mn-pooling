module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, isV6, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      // On the slot-book ledgers (v6/v7) formation completes FROM pledgeSlot claims and
      // IGNORES join requests, so a pledge here would look accepted and then silently
      // count for nothing (review F-P). Refuse and point at the real participation path.
      if (isV6()) {
        throw new Error(cmd === "pledge"
          ? `this ledger (${process.env.LEDGER}) forms pools from the on-ledger slot book, and ` +
            "formation ignores join-request pledges entirely; participate with " +
            "`reserve <poolId> <slotNo> [rewardAddress]` (free slots: `slots <poolId>`)"
          : `this ledger (${process.env.LEDGER}) tracks formation in the on-ledger slot book, ` +
            "not join requests; read it with `slots <poolId>`");
      }
      // G5, the member side of pool formation. A pledge is an ordinary join request
      // against a FORMING pool (proTxHash placeholder with 16 leading zero bytes, see
      // formation.cjs), cancellable any time before completion. NO funds move at pledge
      // time; the collateral moves only inside the atomic L1 funding registration, so
      // there is no custodial pledge window to worry about.
      const [poolIdStr, duffsStr, rewardAddressArg] = args;
      if (!poolIdStr) throw new Error(`usage: ${cmd} <poolId>${cmd === "pledge" ? " <amountDuffs> [rewardAddress]" : ""}`);
      const pool = await getPool(poolIdStr);
      const po = pool.toObject();
      const core = require("./formationCore.cjs");
      // v5's lifecycle field is authoritative; the placeholder-hash convention decides
      // on the earlier ledgers
      const forming = isV5() && po.status !== undefined
        ? po.status === "forming" : core.isFormingHash(Buffer.from(po.proTxHash));
      const target = core.TARGETS[po.nodeType];
      const joins = (await fetchAll(client, "poolLedger.membershipRequest", {
        where: [["poolId", "==", pool.getId()], ["status", "==", "pending"]],
      })).filter((d) => d.toObject().kind === "join");
      const pledged = joins.reduce((s, d) => s + journal.toBig(d.toObject().amountDuffs, "pledge"), 0n);

      if (cmd === "pledges") {
        console.log(`pool ${poolIdStr}: ${forming ? "FORMING" : "LIVE"} (${po.nodeType})`);
        console.log(`fill: ${DASHfmt(pledged)} / ${DASHfmt(target)} DASH across ${joins.length} pledge(s)` +
          (pledged === target ? "  <- FULL" : ""));
        for (const d of joins) {
          const mine = d.getOwnerId().toString() === myId ? "  <- mine" : "";
          console.log(`  ${DASHfmt(d.toObject().amountDuffs)} DASH by ${d.getOwnerId().toString()} ` +
            `(request ${d.getId().toString()})${mine}`);
        }
        return;
      }

      if (!forming) {
        throw new Error("this pool is LIVE (a real node backs it); use join, which the matching engine pairs");
      }
      if (!/^[1-9][0-9]*$/.test(duffsStr || "")) throw new Error("usage: pledge <poolId> <amountDuffs>");
      const amountBig = journal.toBig(duffsStr, "pledge amount");
      // a pledge below one basis point of the target cannot be given a share weight
      // (shareBps minimum 1), and an overfill would make the exact-fill completion
      // unreachable; both refuse here rather than at completion time
      if (amountBig * 10000n < target) {
        throw new Error(`pledge is below one basis point of the target (minimum ${DASHfmt(target / 10000n)} DASH)`);
      }
      if (pledged + amountBig > target) {
        throw new Error(`pledge overfills the pool: ${DASHfmt(pledged)} of ${DASHfmt(target)} DASH already ` +
          `pledged, ${DASHfmt(target - pledged)} DASH remains`);
      }
      // v5: the member may supply their OWN reward address, so formation never derives
      // a script for them (the review's member-supplied-script note, closed)
      let rewardScriptField = {};
      if (rewardAddressArg) {
        if (!isV5()) throw new Error("a member-supplied reward address needs LEDGER=v5");
        rewardScriptField = { rewardScript:
          Dash.Core.Script.buildPublicKeyHashOut(rewardAddressArg).toBuffer() };
      }
      const identity = await client.platform.identities.get(myId);
      const doc = await client.platform.documents.create("poolLedger.membershipRequest", identity, {
        poolId: pool.getId().toBuffer(), kind: "join",
        amountDuffs: journal.toSafeNumber(amountBig, "pledge amount"), status: "pending",
        ...(isV5() ? { provenance: "pledge", ...rewardScriptField } : {}),
      });
      await client.platform.documents.broadcast({ create: [doc] }, identity);
      const after = pledged + amountBig;
      console.log(`${who} pledged ${DASHfmt(amountBig)} DASH to forming pool ${poolIdStr} ` +
        `(request ${doc.getId().toString()}, cancellable until completion)`);
      console.log(`fill now: ${DASHfmt(after)} / ${DASHfmt(target)} DASH` +
        (after === target ? "  <- FULL, the operator can complete" : ""));
      return;
};
