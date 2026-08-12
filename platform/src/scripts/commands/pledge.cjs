module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, isV6,
    hasJoinProvenance, hasMemberRewardScript, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      // On the pledge-slot ledgers (v6 and later; the isV6 alias is the pledgeSlot
      // capability) formation
      // completes FROM pledgeSlot claims and
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
      const core = require("../formationCore.cjs");
      // WHETHER THIS POOL IS OPEN. Where the v5 lifecycle field exists it must AGREE
      // with the placeholder-hash convention, both saying forming (round 18, D-1); the
      // hash alone decides on the earlier ledgers. An immutable pool has neither field
      // and cannot answer at all, so the admission rule below decides instead and this
      // expression is not evaluated there (Buffer.from(undefined) would throw).
      const lifecycle = require("../poolLifecycle.cjs");
      const { hasImmutablePool } = require("../envStore.cjs");
      const { checkReceiptAgainstPool } = require("../receiptPoolCheck.cjs");
      let forming;
      let admission = { ok: true };
      if (hasImmutablePool()) {
        // the member can see the receipt, and nothing else that bears on openness
        const receiptDoc = (await client.platform.documents.get(
          "poolLedger.completionReceipt", { where: [["poolId", "==", pool.getId()]] }))[0] || null;
        const cls = lifecycle.classifyPool({
          contractId: activeContractId(env), pool: po, poolId: pool.getId(),
          receipt: receiptDoc ? receiptDoc.toObject() : null,
          operatorHasInFlight: false, // a member never holds the operator's local state
          // duty 6, SUPPLY: both documents are in hand (Request 3)
          receiptOwnerId: receiptDoc ? receiptDoc.getOwnerId().toString() : undefined,
          poolOwnerId: pool.getOwnerId().toString(),
        });
        admission = lifecycle.admissionVerdict({
          classification: cls, poolIdStr, participateEnv: process.env.TEGARA_PARTICIPATE,
        });
        forming = admission.ok;
      } else {
        // WHERE THE v5 LIFECYCLE FIELD EXISTS, it AND the hash namespace must both say
        // forming; without it (v1-v4) the hash decides alone (confirm-pass round 18,
        // D-1): completion's nothing-to-do check reads the HASH on every mutable ledger
        // (formation.cjs, "already LIVE"), so a v5 pool whose proTxHash flipped to a
        // real hash while status stayed "forming" was admitted here and refused there,
        // the admit-what-completion-refuses family again. The status conjunct is kept
        // where the field exists, because a status the operator set to "live" is the
        // pool's own word that its book is closed, whatever the hash still says.
        // Short-circuited so a non-forming status still refuses without reading the
        // hash, the same evaluation order as before this repair.
        forming = isV5() && po.status !== undefined
          ? po.status === "forming" && core.isFormingHash(Buffer.from(po.proTxHash))
          : core.isFormingHash(Buffer.from(po.proTxHash));
      }
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

      // THE MUTABLE-POOL OPERATOR BINDING, the same rule reserve enforces (confirm-pass
      // round 15, D-1): completion's final pool replacement is signed by the operator on
      // EVERY mutable ledger, so a pool some other identity owns can never complete under
      // this operator, and admitting a pledge into it strands the contribution. The check
      // was v8-gated in formation while the replacement is not. Fail closed on an
      // unreadable contract owner, exactly like reserve.
      if (!hasImmutablePool()) {
        let contractOwner;
        try {
          contractOwner = (await client.platform.contracts.get(activeContractId(env)))
            .getOwnerId().toString();
        } catch (e) {
          throw new Error("the contract's owner could not be read " +
            `(${(e && e.message) || e}), so this pool's operator binding cannot be checked. ` +
            "Completion refuses a pool the operator does not own, so admitting a pledge here " +
            "risks stranding it; refusing instead. Retry when the platform read is healthy.");
        }
        const poolOwner = pool.getOwnerId().toString();
        if (poolOwner !== contractOwner) {
          throw new Error(`pool ${poolIdStr} is owned by ${poolOwner}, not the contract operator ` +
            `(${contractOwner}); completion refuses a pool the operator does not own, so a pledge ` +
            "here could never complete. Do not pledge into this pool.");
        }
      }
      if (!forming) {
        // the admission rule's own words when it decided, because "this pool is LIVE" is a
        // claim an immutable ledger cannot support and a member acting on it would be misled
        throw new Error(admission.ok
          ? "this pool is LIVE (a real node backs it); use join, which the matching engine pairs"
          : admission.reason);
      }
      if (admission.viaInstruction) {
        console.log("proceeding on the operator's advertised participate instruction " +
          "(the ledger cannot confirm this pool is still open; the instruction is your evidence)");
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
      // BOTH owner-bound preflights, the exact-fill path's form of what the slot book
      // gets in reserve.cjs. Sequential preflights over a read snapshot, not atomic
      // (see each helper's own scope note).
      //   the MAXIMUM (closing wave, major; extended to this path by the pass-7 packet
      //   wave, which found pledge had the minimum but not the maximum): a ninth
      //   distinct owner strands the pool at completion's 1..8 aggregate check.
      //   the MINIMUM (pass 7, major 2): the pledge that completes the fill with a
      //   single distinct owner makes a pool completion must refuse. Partial fills by
      //   one owner stay admissible.
      const ownersAfterPledge = new Set([...joins.map((d) => d.getOwnerId().toString()), myId]).size;
      core.requireOwnerCapacity(ownersAfterPledge);
      // UNCONDITIONAL (confirm-pass round 23, major): same rule as reserve, the
      // member's environment cannot speak for the operator's completion profile
      core.requireCompletableOwnerCount({
        distinctOwnersAfterClaim: ownersAfterPledge,
        bookFullAfterClaim: pledged + amountBig === target,
      });
      // the member may supply their OWN reward address, so formation never derives
      // a script for them (the review's member-supplied-script note, closed). Gated on
      // the field's own capability, not isV5, the same class as major 1 of the final
      // pass one line down: rewardScript enters at v5 and is carried by v9.
      let rewardScriptField = {};
      if (rewardAddressArg) {
        if (!hasMemberRewardScript()) throw new Error("a member-supplied reward address needs a ledger with member reward scripts (v5 or later)");
        rewardScriptField = { rewardScript:
          Dash.Core.Script.buildPublicKeyHashOut(rewardAddressArg).toBuffer() };
      }
      const identity = await client.platform.identities.get(myId);
      const doc = await client.platform.documents.create("poolLedger.membershipRequest", identity, {
        poolId: pool.getId().toBuffer(), kind: "join",
        amountDuffs: journal.toSafeNumber(amountBig, "pledge amount"), status: "pending",
        // provenance and rewardScript ride their own capabilities (final pass, major 1)
        ...(hasJoinProvenance() ? { provenance: "pledge" } : {}),
        ...(hasMemberRewardScript() ? rewardScriptField : {}),
      });
      await client.platform.documents.broadcast({ create: [doc] }, identity);
      const after = pledged + amountBig;
      console.log(`${who} pledged ${DASHfmt(amountBig)} DASH to forming pool ${poolIdStr} ` +
        `(request ${doc.getId().toString()}, cancellable until completion)`);
      console.log(`fill now: ${DASHfmt(after)} / ${DASHfmt(target)} DASH` +
        (after === target ? "  <- FULL, the operator can complete" : ""));
      return;
};
