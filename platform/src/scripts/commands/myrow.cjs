module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const [poolIdStr, proposalHex] = args;
      if (!poolIdStr || !/^[0-9a-f]{64}$/i.test(proposalHex || "")) {
        throw new Error("usage: myrow <poolId> <proposalHash 64-hex>");
      }
      if (!activeCastId(env)) throw new Error("no cast-governance contract (CAST_V2_CONTRACT_ID or CAST=v3)");
      const poolId = Identifier.from(poolIdStr);
      const snaps = await fetchAll(client, "castGov.tallySnapshot", {
        where: [["poolId", "==", poolId], ["proposalHash", "==", Buffer.from(proposalHex, "hex")]],
        orderBy: [["$createdAt", "asc"]],
      });
      if (snaps.length === 0) { console.log("no snapshots for this pool and proposal"); return; }
      const myPrefDoc = (await client.platform.documents.get("poolLedger.votePreference", {
        where: [["poolId", "==", poolId], ["$ownerId", "==", Identifier.from(myId)],
                ["proposalHash", "==", Buffer.from(proposalHex, "hex")]],
      }))[0] || null;
      const myChoice = myPrefDoc ? myPrefDoc.toObject().choice : "donothing";
      const prefUpdated = myPrefDoc ? Number(myPrefDoc.toObject().$updatedAt || myPrefDoc.toObject().$createdAt) : null;
      // my WEIGHT matters as much as my choice: a snapshot that keeps my choice but
      // shrinks my bps neutralizes my vote and still self-authenticates (both
      // batch-5 packet reviewers converged on this), so the standing snapshot's bps
      // is compared against my actual share, same adjudication rules as the choice
      const myShareDoc = (await client.platform.documents.get("poolLedger.share", {
        where: [["poolId", "==", poolId], ["$ownerId", "==", Identifier.from(myId)]],
      }))[0] || null;
      const myBps = myShareDoc ? Number(myShareDoc.toObject().shareBps) : null;
      // my delegation TARGET is part of my instruction too: a snapshot keeping my
      // "delegate" choice but naming a different target redirects my weight and would
      // otherwise self-authenticate (independent-review finding)
      const myTarget = myPrefDoc && myPrefDoc.toObject().delegateTo
        ? Identifier.from(Buffer.from(myPrefDoc.toObject().delegateTo)).toString() : null;
      console.log(`${who} ${myId}\ncurrent preference: ${myChoice}` +
        (myTarget ? ` (targeted at ${myTarget})` : "") +
        (myPrefDoc ? ` (last updated ${new Date(prefUpdated).toISOString()})`
          : " (none recorded, counted as donothing)"));
      console.log(`current share: ${myBps !== null ? `${myBps} bps` : "NONE held in this pool"}`);
      // ONLY the STANDING (latest) snapshot can be adjudicated against my current
      // preference; an older snapshot that differs may simply predate a change I
      // made myself, and the previous preference value is unrecoverable from the
      // ledger (documents are mutable). Older mismatches are reported as
      // informational so an honest history cannot fail forever after one legitimate
      // change (review finding, batch 5). Rows are validated with the SAME validator
      // the verifier uses, so a duplicate or malformed row can never pick a
      // convenient entry.
      const { validateCanonicalRows } = require("./tally.cjs");
      let latestDiverges = false, historicalDiffs = 0;
      for (let i = 0; i < snaps.length; i++) {
        const s = snaps[i];
        const isLatest = i === snaps.length - 1;
        const o = s.toObject();
        const when = new Date(Number(o.$createdAt)).toISOString();
        const tag = isLatest ? "STANDING" : "historical";
        let rows;
        try {
          rows = validateCanonicalRows(JSON.parse(Buffer.from(o.tallyRows).toString("utf8")), Number(o.formatVersion) || 1);
        } catch (e) {
          console.log(`  ${tag} snapshot ${s.getId().toString()} (${when}): rows INVALID ` +
            `(${(e && e.message) || e}); run the verifier`);
          if (isLatest) latestDiverges = true; else historicalDiffs++;
          continue;
        }
        const mine = rows.find((r) => r.owner === myId);
        if (!mine) {
          console.log(`  ${tag} snapshot ${s.getId().toString()} (${when}): I am NOT LISTED` +
            (isLatest ? "" : " (may predate my joining)"));
          if (isLatest) latestDiverges = true; else historicalDiffs++;
          continue;
        }
        const choiceMatch = mine.choice === myChoice;
        // the target must match in BOTH directions: absent on both sides, or the same
        // identity on both (a row naming a different target redirects my weight)
        const rowTarget = mine.delegateTo !== undefined ? mine.delegateTo : null;
        const targetMatch = rowTarget === myTarget;
        const bpsMatch = myBps !== null && mine.bps === myBps;
        const match = choiceMatch && bpsMatch && targetMatch;
        if (!match) { if (isLatest) latestDiverges = true; else historicalDiffs++; }
        const verdictBits = [];
        if (!choiceMatch) {
          verdictBits.push(isLatest ? `choice DIFFERS from my current "${myChoice}"`
            : `choice differs from my current "${myChoice}" (may reflect my own later change)`);
        }
        if (!targetMatch) {
          verdictBits.push(isLatest
            ? `delegation target DIFFERS (row: ${rowTarget || "none"}, mine: ${myTarget || "none"}); my weight was redirected unless I changed it since`
            : `delegation target differs (row: ${rowTarget || "none"}, mine: ${myTarget || "none"}; may reflect my own later change)`);
        }
        if (!bpsMatch) {
          verdictBits.push(myBps === null
            ? (isLatest ? "I hold NO share now; if I never exited, the snapshot misrepresents membership"
              : "I hold no share now (may postdate my exit)")
            : (isLatest ? `bps DIFFERS from my actual ${myBps}; my WEIGHT was misrepresented unless my share changed since`
              : `bps differs from my current ${myBps} (shares churn; not adjudicable from current state alone)`));
        }
        console.log(`  ${tag} snapshot ${s.getId().toString()} (${when}): my row says "${mine.choice}" at ` +
          `${mine.bps} bps${match ? " == my current preference and share"
            : ` <- ${verdictBits.join("; ")}`}`);
      }
      if (latestDiverges) {
        console.log("\n=== MYROW: the STANDING snapshot differs from my current preference or share. " +
          "If I did not change them since that snapshot, the snapshot misrepresented me (choice or " +
          "WEIGHT) and the immutable document is the evidence; if I did change them, the operator " +
          "owes a new snapshot (see verify's STALE) ===");
        process.exitCode = 1;
      } else {
        console.log(`\n=== MYROW OK: the standing snapshot records my preference and weight as I have them now` +
          (historicalDiffs > 0 ? ` (${historicalDiffs} older snapshot(s) differ, which is expected ` +
            "when a preference or share changed over time)" : "") + " ===");
      }
      return;
};
