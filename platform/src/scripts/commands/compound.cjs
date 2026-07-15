module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
  if (args[0] === "release") {
      // the manual override for the one conservative-stuck case: a payout entry whose
      // withdrawal verifiably never happened. Freeing an entry whose operation DID
      // happen re-inflates the ceiling and reuses the same rewards, so the deletion
      // only fires with the explicit verification flag; without it, the command shows
      // the entry and instructs (independent-review finding: a warning that does not
      // gate anything is not a guard).
      const [, entryId, flag] = args;
      if (!entryId) throw new Error("usage: compound release <entryId> --verified-never-landed");
      const { entries } = journal.summary(journalContract, myId);
      const entry = entries[entryId];
      if (!entry) { console.log(`no journal entry ${entryId}`); process.exitCode = 1; return; }
      console.log(`entry ${entryId}: ${DASHfmt(BigInt(entry.amount))} DASH ` +
        `[${entry.kind || "compound"}, ${entry.state}]`);
      if (!entry.kind) {
        console.log('note: compound entries are ledger-verifiable; run "compound status" first, ' +
          "which frees this automatically if the join document is gone");
      }
      if (flag !== "--verified-never-landed") {
        console.log("\nnothing released. Releasing re-inflates the ceiling and lets the same rewards " +
          "be used again, so it requires YOUR verification that the underlying operation never " +
          "happened (no join document on the ledger, no payout arrival at the destination). If " +
          `verified, re-run: compound release ${entryId} --verified-never-landed`);
        process.exitCode = 1; return;
      }
      const freed = journal.release(journalContract, myId, entryId);
      if (freed === null) { console.log(`entry ${entryId} disappeared underneath us; nothing released`); process.exitCode = 1; return; }
      console.log(`released ${DASHfmt(freed)} DASH back to the uncompounded ceiling`);
      return;
    return;
  }
      // `compound status`: reconcile (self-healing after any crash) and show the journal
      if (args[0] === "status") {
        await journal.reconcile(journalContract, myId, requestExists, console.log);
        const { entries, consumedDuffs } = journal.summary(journalContract, myId);
        const earned = await earnedRewardsBig();
        console.log(`earned rewards: ${DASHfmt(earned)} DASH; consumed (compounds plus payouts): ` +
          `${DASHfmt(consumedDuffs)} DASH; uncompounded: ${DASHfmt(earned - consumedDuffs)} DASH`);
        // the honest scope of this number (holistic-round F7): credits are fungible, so
        // a plain `withdraw` is NOT attributed against rewards; the ceiling tracks what
        // compound and autopay consumed, not every path value can leave by
        console.log("(the ceiling tracks compound and autopay consumption only; a plain withdraw spends " +
          "fungible credits and is not attributed against it)");
        for (const [id, e] of Object.entries(entries)) {
          console.log(`  ${id}  ${DASHfmt(BigInt(e.amount))} DASH [${e.kind || "compound"}, ${e.state}]`);
        }
        return;
      }

      const [poolIdStr, amountArg] = args;
      if (!poolIdStr || !amountArg) throw new Error('usage: compound <poolId> <amountDuffs|all> (or: compound status)');
      const pool = await getPool(poolIdStr);

      // heal first, so a crash in an earlier run can neither hide freed rewards nor
      // leave a pending entry unaccounted
      await journal.reconcile(journalContract, myId, requestExists, console.log);

      // the ceiling: rewards earned (never returned principal) minus rewards already
      // compounded, all in BigInt (independent-review finding: Number summation can
      // round past MAX_SAFE_INTEGER, and "all" must not bypass the bounds)
      const earned = await earnedRewardsBig();
      const { consumedDuffs } = journal.summary(journalContract, myId);
      const ceiling = earned - consumedDuffs;
      if (ceiling <= 0n) {
        throw new Error(`no uncompounded rewards (earned ${DASHfmt(earned)} DASH, ` +
          `already consumed ${DASHfmt(consumedDuffs)} DASH (compounds plus payouts))`);
      }

      let amountBig;
      if (amountArg === "all") {
        amountBig = ceiling;
      } else {
        if (!/^[1-9][0-9]*$/.test(amountArg)) {
          throw new Error('amount must be a canonical positive integer or "all"');
        }
        amountBig = journal.toBig(amountArg, "compound amount");
        if (amountBig > ceiling) {
          throw new Error(`compound of ${DASHfmt(amountBig)} DASH exceeds the uncompounded ` +
            `rewards ${DASHfmt(ceiling)} DASH`);
        }
      }
      // the document field crosses the SDK's Number boundary; every path (including
      // "all") re-checks safety at the conversion
      if (amountBig > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("amount too large for the document's Number interface");
      }
      const amountDuffs = Number(amountBig);

      const held = (await myShares()).filter((s) =>
        Identifier.from(Buffer.from(s.toObject().poolId)).toString() === poolIdStr);
      if (held.length === 0) {
        console.log("note: no share held in this pool yet, so this compound is a reward-funded fresh join");
      }

      const identity = await client.platform.identities.get(myId);
      const doc = await client.platform.documents.create("poolLedger.membershipRequest", identity, {
        poolId: pool.getId().toBuffer(), kind: "join", amountDuffs, status: "pending",
        // v5: the compound is distinguishable ON the ledger, not only in the local
        // journal (the join-provenance gap, closed)
        ...(isV5() ? { provenance: "compound" } : {}),
      });
      // reserve BEFORE the broadcast (the review's core finding): the ceiling debit is
      // durable before the slow network operation, so a crash after broadcast cannot
      // reuse these rewards; reserve re-checks the ceiling under the lock, so a
      // concurrent run that got there first turns this into a loud refusal
      const remaining = journal.reserve(journalContract, myId, doc.getId().toString(), amountBig, earned);
      try {
        await client.platform.documents.broadcast({ create: [doc] }, identity);
      } catch (e) {
        // a broadcast ERROR is not authoritative evidence the document did not land
        // (holistic-round F1, converged across two reviewers: the response can be lost
        // AFTER Platform accepted, and the ledger is eventually consistent). The
        // reservation therefore stays PENDING, never auto-released here; a quick
        // best-effort probe upgrades it to confirmed if the document is already
        // visible, and otherwise reconcile frees it only past the age gate.
        let landed = false;
        try { landed = await requestExists(doc.getId().toString()); } catch { /* stay pending */ }
        if (landed) {
          journal.confirm(journalContract, myId, doc.getId().toString());
          console.error(`the broadcast reported an error but the join IS on the ledger; ` +
            `reservation confirmed (request ${doc.getId().toString()})`);
        } else {
          console.error(`broadcast failed with: ${(e && e.message) || e}`);
          console.error(`the reservation stays PENDING (the document may still land). ` +
            `"compound status" reconciles it: confirmed if it appears, freed only after the ` +
            `age gate, or use the guarded manual release once you have verified absence.`);
        }
        process.exitCode = 1;
        return;
      }
      journal.confirm(journalContract, myId, doc.getId().toString());

      console.log(`${who} compounds ${DASHfmt(amountBig)} DASH of earned rewards into pool ${poolIdStr}`);
      console.log(`join request ${doc.getId().toString()} [pending]; the matching engine pairs it, ` +
        `or "cancel ${doc.getId().toString()}" returns the rewards to the uncompounded ceiling`);
      console.log(`uncompounded rewards remaining: ${DASHfmt(remaining)} DASH`);
      return;
};
