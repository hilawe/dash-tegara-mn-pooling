module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, isV6, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const [reqIdStr] = args;
      if (!reqIdStr) throw new Error("usage: cancel <requestId | slotClaimId>");
      const found = await client.platform.documents.get("poolLedger.membershipRequest", {
        where: [["$id", "==", Identifier.from(reqIdStr)]],
      });
      // under v6 the id may name a pledgeSlot claim instead (review finding R3: reserve
      // advertises "deletable until completion", so cancel must actually resolve it)
      if (found.length === 0 && isV6()) {
        const claims = await client.platform.documents.get("poolLedger.pledgeSlot", {
          where: [["$id", "==", Identifier.from(reqIdStr)]],
        });
        if (claims.length > 0) {
          const claim = claims[0];
          if (claim.getOwnerId().toString() !== myId) {
            throw new Error("not your slot claim; only the owner can cancel");
          }
          const co = claim.toObject();
          const pool = await getPool(Identifier.from(Buffer.from(co.poolId)).toString());
          const po = pool.toObject();
          const core = require("../formationCore.cjs");
          const forming = po.status !== undefined ? po.status === "forming"
            : core.isFormingHash(Buffer.from(po.proTxHash));
          if (!forming) {
            throw new Error("this pool is LIVE; a slot claim can only be cancelled while the pool is forming");
          }
          const identity = await client.platform.identities.get(myId);
          try {
            await client.platform.documents.broadcast({ delete: [claim] }, identity);
          } catch (e) {
            if (/RevisionAbsent/i.test((e && e.constructor && e.constructor.name) || "") ||
                /revision/i.test((e && e.message) || "")) {
              throw new Error("this claim sits on the v6 ledger, whose pledgeSlot type is immutable, " +
                "and this SDK cannot build a delete for an immutable document (RevisionAbsentError). " +
                "v6 claims are therefore permanent once made; cancellable claims are what the v7 " +
                "ledger's mutable pledgeSlot adds (reserve under LEDGER=v7)");
            }
            throw e;
          }
          // v6 claims carry their size; v7 claims are sizeless and the pool defines it
          const sizeDuffs = co.slotDuffs !== undefined ? co.slotDuffs : po.slotDuffs;
          console.log(`slot claim ${reqIdStr} cancelled (slot ${co.slotNo}` +
            `${sizeDuffs !== undefined ? `, ${DASHfmt(sizeDuffs)} DASH` : ""}, ` +
            "deleted by its owner); the slot is free again");
          return;
        }
      }
      if (found.length === 0) throw new Error(`no request ${reqIdStr}`);
      const doc = found[0];
      if (doc.getOwnerId().toString() !== myId) throw new Error("not your request; only the owner can cancel");
      const status = doc.toObject().status;
      if (status !== "pending") throw new Error(`request is ${status}; only a pending request can be cancelled`);
      const identity = await client.platform.identities.get(myId);
      await client.platform.documents.broadcast({ delete: [doc] }, identity);
      console.log(`request ${reqIdStr} cancelled (deleted by its owner)`);
      // a cancelled compound returns its rewards to the uncompounded ceiling; if the
      // journal update fails here, the deleted document makes the entry reconcilable
      // (any later compound or "compound status" frees it), so say that instead of
      // failing silently (independent-review finding)
      try {
        const returned = journal.release(journalContract, myId, reqIdStr);
        if (returned !== null) {
          console.log(`compound journal: ${DASHfmt(returned)} DASH of rewards count as uncompounded again`);
        }
      } catch (e) {
        console.log(`compound journal update failed (${(e && e.message) || e}); the request document ` +
          'is gone, so the next "compound status" reconcile will free its entry');
        process.exitCode = 1;
      }
      return;
};
