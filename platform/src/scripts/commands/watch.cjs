module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    loadEnv, updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      // G8: the member-side notifier, self-custody version of CrowdNode's emails. One
      // cycle diffs the member's own view of the ledger against a local watermark and
      // reports what changed; "watch loop [seconds]" repeats. The watermark is advisory
      // presentation state (never funds accounting), so corruption means a fresh
      // baseline, loudly, not a failure.
      const loopMode = args[0] === "loop";
      const intervalSec = loopMode ? parseInt(args[1] || "120", 10) : 0;
      if (loopMode && (!Number.isInteger(intervalSec) || intervalSec < 10)) {
        throw new Error("usage: watch [loop <seconds >= 10>]");
      }

      // the v2 watermark: {v, accruals: {at, ids}, requests: {id: status},
      // shares: {poolId: bps}, snaps: {poolId: {at, ids}}}. The {at, ids} cursor pattern
      // records the ids AT the newest timestamp so documents sharing a creation time are
      // never re-reported or missed (independent-review finding); snapshot cursors are
      // per pool so one pool's failed query cannot eat another's events.
      const validWatermark = (w) => {
        const isCursor = (c) => c && typeof c === "object" && !Array.isArray(c)
          && Number.isFinite(c.at) && Array.isArray(c.ids) && c.ids.every((x) => typeof x === "string");
        const isStrMap = (m, valOk) => m && typeof m === "object" && !Array.isArray(m)
          && Object.values(m).every(valOk);
        return w && typeof w === "object" && !Array.isArray(w) && w.v === 2
          && isCursor(w.accruals)
          && isStrMap(w.requests, (v) => typeof v === "string")
          && isStrMap(w.shares, (v) => Number.isFinite(v))
          && isStrMap(w.snaps, isCursor);
      };
      // advance an {at, ids} cursor and return the docs strictly beyond it
      const beyondCursor = (docs, cursor) => {
        const fresh = docs.filter((d) => {
          const at = Number(d.toObject().$createdAt);
          return at > cursor.at || (at === cursor.at && !cursor.ids.includes(d.getId().toString()));
        });
        let at = cursor.at;
        for (const d of docs) at = Math.max(at, Number(d.toObject().$createdAt));
        const ids = docs.filter((d) => Number(d.toObject().$createdAt) === at).map((d) => d.getId().toString())
          .concat(at === cursor.at ? cursor.ids : []);
        return { fresh, next: { at, ids: [...new Set(ids)] } };
      };

      const cycle = async () => {
        const raw = loadEnv()[watchKeyOf()];
        let base = null;
        if (raw !== undefined) {
          try { base = JSON.parse(raw); } catch { /* handled below */ }
          if (!validWatermark(base)) {
            if (base !== null || raw) console.log("watch state was corrupt or from an older version; " +
              "recording a fresh baseline (advisory state only, nothing lost on the ledger)");
            base = null;
          }
        }
        const first = base === null;
        base = base || { v: 2, accruals: { at: 0, ids: [] }, requests: {}, shares: {}, snaps: {} };
        const alerts = [];

        // 1. new accruals (mine): rewards and returned principal, id-tie-safe cursor
        const mine = await myAccruals();
        const acc = beyondCursor(mine, base.accruals);
        if (!first && acc.fresh.length > 0) {
          let newRewards = 0n, newPrincipal = 0n;
          for (const d of acc.fresh) {
            const o = d.toObject();
            if (o.kind === "principal") newPrincipal += journal.toBig(o.amountDuffs, "accrual");
            else newRewards += journal.toBig(o.amountDuffs, "accrual");
          }
          alerts.push(`${acc.fresh.length} new accrual(s): +${DASHfmt(newRewards)} DASH rewards` +
            (newPrincipal > 0n ? ` and +${DASHfmt(newPrincipal)} DASH returned principal` : ""));
        }

        // 2. request status changes. An unseen PENDING request is my own fresh
        // submission (not news), but an unseen request already matched or settled moved
        // BETWEEN cycles and must be reported (independent-review finding).
        const reqs = await myRequests();
        const curReqs = {};
        for (const r of reqs) {
          const o = r.toObject();
          const id = r.getId().toString();
          curReqs[id] = o.status;
          if (first) continue;
          const was = base.requests[id];
          if (was === undefined) {
            if (o.status !== "pending") {
              alerts.push(`request ${id} (${o.kind} ${DASHfmt(o.amountDuffs)} DASH) appeared already ` +
                `"${o.status}" (moved between watch cycles)`);
            }
          } else if (was !== o.status) {
            alerts.push(`request ${id} (${o.kind} ${DASHfmt(o.amountDuffs)} DASH): ${was} -> ${o.status}`);
          }
        }
        if (!first) {
          for (const id of Object.keys(base.requests)) {
            if (!(id in curReqs)) alerts.push(`request ${id} is gone from the ledger ` +
              "(cancelled here, or something to look into)");
          }
        }

        // 3. share changes per pool (joined, exited, weight changed)
        const shares = await myShares();
        const curShares = {};
        for (const s of shares) {
          const o = s.toObject();
          curShares[Identifier.from(Buffer.from(o.poolId)).toString()] = Number(o.shareBps);
        }
        if (!first) {
          for (const [pid, bps] of Object.entries(curShares)) {
            const was = base.shares[pid];
            if (was === undefined) alerts.push(`new share: ${bps} bps in pool ${short(pid)}`);
            else if (was !== bps) alerts.push(`share weight in pool ${short(pid)}: ${was} -> ${bps} bps`);
          }
          for (const pid of Object.keys(base.shares)) {
            if (!(pid in curShares)) alerts.push(`share in pool ${short(pid)} is gone (exit settled?)`);
          }
        }

        // 4. new tally snapshots for pools I hold, per-pool cursors, with the
        // standing-row check (the myrow core): a new STANDING snapshot whose row for me
        // differs from my current preference or weight is an ALERT
        const nextSnaps = {};
        if (activeCastId(env)) {
          for (const pid of Object.keys(curShares)) {
            const cursor = base.snaps[pid] || { at: 0, ids: [] };
            let snaps;
            try {
              snaps = await fetchAll(client, "castGov.tallySnapshot", {
                where: [["poolId", "==", Identifier.from(pid)]],
              });
            } catch {
              alerts.push(`snapshot watch unavailable for pool ${short(pid)} (query shape); ` +
                "check myrow manually");
              nextSnaps[pid] = cursor; // a failed query must NOT advance this pool's cursor
              continue;
            }
            const { fresh, next } = beyondCursor(snaps, cursor);
            nextSnaps[pid] = next;
            if (first) continue;
            // only the STANDING (latest) snapshot per proposal is adjudicable
            const byProposal = new Map();
            for (const sn of snaps) {
              const o = sn.toObject();
              const ph = Buffer.from(o.proposalHash).toString("hex");
              const cur = byProposal.get(ph);
              if (!cur || Number(o.$createdAt) > Number(cur.toObject().$createdAt)) byProposal.set(ph, sn);
            }
            const freshIds = new Set(fresh.map((d) => d.getId().toString()));
            for (const [ph, standing] of byProposal) {
              if (!freshIds.has(standing.getId().toString())) continue;
              const o = standing.toObject();
              alerts.push(`new tally snapshot on pool ${short(pid)} proposal ${ph.slice(0, 16)}...`);
              try {
                const { validateCanonicalRows } = require("./tally.cjs");
                const rows = validateCanonicalRows(JSON.parse(Buffer.from(o.tallyRows).toString("utf8")), Number(o.formatVersion) || 1);
                const mineRow = rows.find((r) => r.owner === myId);
                const myPref = (await client.platform.documents.get("poolLedger.votePreference", {
                  where: [["poolId", "==", Identifier.from(pid)],
                          ["$ownerId", "==", Identifier.from(myId)],
                          ["proposalHash", "==", Buffer.from(ph, "hex")]],
                }))[0];
                const myChoice = myPref ? myPref.toObject().choice : "donothing";
                // the delegation target is part of the instruction too
                // (independent-review finding)
                const myTarget = myPref && myPref.toObject().delegateTo
                  ? Identifier.from(Buffer.from(myPref.toObject().delegateTo)).toString() : null;
                const rowTarget = mineRow && mineRow.delegateTo !== undefined ? mineRow.delegateTo : null;
                const myBps = curShares[pid];
                if (!mineRow) alerts.push(`  ALERT: I am NOT LISTED in the standing snapshot; run: myrow ${pid} ${ph}`);
                else if (mineRow.choice !== myChoice || mineRow.bps !== myBps || rowTarget !== myTarget) {
                  alerts.push(`  ALERT: my standing row says "${mineRow.choice}"` +
                    `${rowTarget ? ` (target ${short(rowTarget)})` : ""} at ${mineRow.bps} bps but I ` +
                    `hold "${myChoice}"${myTarget ? ` (target ${short(myTarget)})` : ""} at ${myBps} bps; ` +
                    `run: myrow ${pid} ${ph}`);
                }
              } catch (e) {
                alerts.push(`  standing snapshot rows did not validate (${(e && e.message) || e}); ` +
                  `run: myrow ${pid} ${ph}`);
              }
            }
          }
        }

        // 5. the autopay sweep, when the member turned it on
        if (loadEnv()[autopayKeyOf()] === "on") {
          const outcome = await runAutopaySweep(true);
          if (outcome === "swept") alerts.push("autopay swept rewards (details above)");
          if (outcome === "unbacked") alerts.push("ALERT: autopay could not sweep (rewards not backed by credits)");
        }

        // print FIRST, commit the watermark AFTER: an interruption may repeat a report
        // but can never silently lose one (independent-review finding; at-least-once)
        const stamp = new Date().toISOString();
        if (first) console.log(`[${stamp}] baseline recorded (${mine.length} accruals, ` +
          `${Object.keys(curReqs).length} requests, ${Object.keys(curShares).length} shares); ` +
          "changes report from the next cycle");
        else if (alerts.length === 0) console.log(`[${stamp}] no changes`);
        else for (const a of alerts) console.log(`[${stamp}] ${a}`);
        updateEnvKey(watchKeyOf(), JSON.stringify({
          v: 2, accruals: acc.next, requests: curReqs, shares: curShares, snaps: nextSnaps,
        }));
      };

      await cycle();
      while (loopMode) {
        await new Promise((r) => setTimeout(r, intervalSec * 1000));
        await cycle();
      }
      return;
};
