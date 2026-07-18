/**
 * The Track A membership matching engine, exercised against the live pool-ledger contract.
 *
 * SCOPE, corrected 2026-07-17 (findings a soundness-review finding, a soundness-review finding; see the private findings log). This is an
 * ACCOUNTING-ONLY research demonstration, NOT a complete member settlement. Two limits are
 * load-bearing and must not be overstated. (1) It moves Platform SHARE OWNERSHIP only: a join
 * carries an amount but no payment, asset lock, or transaction reference, and settlement changes
 * no L1 owner key, refund script, or collateral, so no value is exchanged between the two members
 * (a soundness review). (2) It signs BOTH members' transitions from ONE wallet (the run's own MNEMONIC), so it
 * can only settle members whose identities derive from that single wallet; it cannot settle
 * members holding unrelated keys (a soundness review). A real member-signed value settlement across unrelated
 * wallets is unresolved design work (a future design round). Do not describe the output
 * below as a self-sovereign or complete membership handover.
 *
 * What the demo DOES show: the pool's recorded share layout can be re-owned without unwinding it,
 * the pairing rule is pure and independently checkable, and the pending -> matched -> settled
 * state machine is crash-recoverable. The share moves from leaver to joiner as an accounting
 * record, share for share.
 *
 *   1. the operator creates a fresh pool; funder1 creates a share (5000 bps),
 *   2. funder1 submits an exit membershipRequest, funder2 submits a join for the same amount,
 *   3. the matching engine queries the pool's pending requests and pairs exit with join
 *      (equal amount, oldest first),
 *   4. each owner marks their own request "matched",
 *   5. settlement: funder1 deletes their share, funder2 creates theirs (same bps, their own
 *      reward script), and both owners mark their requests "settled",
 *   6. readback verifies the pool's single share now belongs to funder2 and both requests
 *      read "settled".
 *
 * Requires .env.local from the earlier scripts (MNEMONIC, IDENTITY_ID, CONTRACT_ID, FUNDER_ID,
 * FUNDER2_ID; run creditRail.cjs first to create FUNDER2_ID). Env: NETWORK, DAPI_HOST[/DAPI_PORT].
 *
 * MATCH_POOL_ID=<pool document id> switches to the EXISTING-POOL mode (the membership-churn
 * flow): no demo setup, the engine reads that pool's pending requests (submitted through the
 * funder client), pairs exit with join, and settles each pair: statuses move by compare-and-set,
 * the leaver deletes their share, and the joiner recreates it with the same bps and
 * contribution under their own reward script. Both owners must be identities this run controls
 * (FUNDER_ID / FUNDER*_ID). The pool's share layout is preserved; only the owner changes.
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { fetchAll } = require("./query.cjs");
const match = require("./matchJournal.cjs");
const { loadEnv, saveEnv, activeContractId, isV3, isV5 } = require("./envStore.cjs");


const MIN_CREDITS = 40000000000;
const TOPUP_DUFFS = 300000000; // 3 DASH
const p2pkh = (h20) => Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), h20, Buffer.from([0x88, 0xac])]);

/**
 * The pairing rule: for one pool, take the pending requests, pair each exit with the oldest
 * pending join of the same amount. Pure function of the ledger; no privileged caller.
 */
function matchRequests(pending) {
  // Number() everywhere: integer document fields can deserialize as BigInt.
  // Tie-break equal timestamps by document id so two engines order identically
  // regardless of query return order (independent-review finding 4).
  const createdAt = (d) => Number(d.toObject().$createdAt);
  const byAge = (a, b) => createdAt(a) - createdAt(b)
    || a.getId().toString().localeCompare(b.getId().toString());
  const joins = pending.filter((d) => d.toObject().kind === "join").sort(byAge);
  const exits = pending.filter((d) => d.toObject().kind === "exit").sort(byAge);
  const pairs = [];
  for (const exit of exits) {
    const i = joins.findIndex((j) => Number(j.toObject().amountDuffs) === Number(exit.toObject().amountDuffs));
    if (i >= 0) pairs.push({ exit, join: joins.splice(i, 1)[0] });
  }
  return pairs;
}

(async () => {
  const env = loadEnv();
  if (!env.MNEMONIC || !env.IDENTITY_ID || !env.CONTRACT_ID || !env.FUNDER_ID || !env.FUNDER2_ID) {
    console.error("run register.cjs, funder.cjs, and creditRail.cjs first (need FUNDER2_ID in .env.local)");
    process.exit(1);
  }

  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
    apps: { poolLedger: { contractId: activeContractId(env) } },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  const ensureCredits = async (id) => {
    if (id.getBalance() < MIN_CREDITS) {
      console.log(`  topping up ${id.getId().toString()} (credits ${id.getBalance()}) ...`);
      await client.platform.identities.topUp(id.getId(), TOPUP_DUFFS);
      return client.platform.identities.get(id.getId().toString());
    }
    return id;
  };

  // re-fetch a document by id so a replace always works from the latest revision
  const fresh = async (type, doc) =>
    (await client.platform.documents.get(type, { where: [["$id", "==", doc.getId()]] }))[0];

  // compare-and-set: a transition names its source state and refuses to fire from any
  // other, so a stale engine can never regress a settled request (finding 3)
  const setStatus = async (doc, identity, fromStatus, toStatus) => {
    const d = await fresh("poolLedger.membershipRequest", doc);
    const current = d.toObject().status;
    // idempotent: re-driving a settlement phase after a crash may replay a move whose
    // target already holds; that is progress, not an error (review finding F1)
    if (current === toStatus) {
      console.log(`  ${d.toObject().kind} request ${d.getId().toString()} already "${toStatus}"; continuing`);
      return;
    }
    if (current !== fromStatus) {
      throw new Error(`refusing ${fromStatus} -> ${toStatus} on ${d.getId().toString()}: ` +
        `current status is "${current}"`);
    }
    d.set("status", toStatus);
    await client.platform.documents.broadcast({ replace: [d] }, identity);
    console.log(`  ${d.toObject().kind} request ${d.getId().toString()} ${fromStatus} -> ${toStatus}` +
      ` (by its owner ${identity.getId().toString()})`);
  };

  try {
    installConsumedFilter(await client.getWalletAccount());

    // the existing-pool mode: settle the requests of a live pool, crash-recoverably
    // (review finding F1: the settlement journal snapshots the pair and the old share
    // BEFORE any ledger mutation, and every run first finishes what a crashed run left)
    if (process.env.MATCH_POOL_ID) {
      const { Identifier } = require("@dashevo/wasm-dpp");
      const poolId = Identifier.from(process.env.MATCH_POOL_ID);

      // every identity this run can sign for, keyed by id string (lazy-loaded)
      const controlled = {};
      for (const [k, v] of Object.entries(env)) {
        if (k === "FUNDER_ID" || /^FUNDER\d+_ID$/.test(k)) controlled[v] = null;
      }
      const identityFor = async (idStr) => {
        if (!(idStr in controlled)) throw new Error(`request owner ${idStr} is not an identity this run controls`);
        if (!controlled[idStr]) controlled[idStr] = await ensureCredits(await client.platform.identities.get(idStr));
        return controlled[idStr];
      };

      const requestById = async (idStr) => {
        const found = await client.platform.documents.get("poolLedger.membershipRequest", {
          where: [["$id", "==", Identifier.from(idStr)]],
        });
        if (found.length === 0) throw new Error(`journaled request ${idStr} is gone from the ledger`);
        return found[0];
      };
      const sharesOf = async (ownerIdStr) => client.platform.documents.get("poolLedger.share", {
        where: [["poolId", "==", poolId], ["$ownerId", "==", Identifier.from(ownerIdStr)]],
      });

      // the real ledger operations behind the settlement driver
      const opsFor = (s) => ({
        setStatus: async (reqId, ownerId, from, to) =>
          setStatus(await requestById(reqId), await identityFor(ownerId), from, to),
        leaverShareExists: async () => (await sharesOf(s.leaverId)).length > 0,
        joinerShareExists: async () => (await sharesOf(s.joinerId)).length > 0,
        deleteLeaverShare: async () => {
          const shares = await sharesOf(s.leaverId);
          await client.platform.documents.broadcast({ delete: [shares[0]] }, await identityFor(s.leaverId));
          console.log(`  leaver's share deleted (${s.share.shareBps} bps, by ${s.leaverId})`);
        },
        recreateJoinerShare: async (snapshot) => {
          const joiner = await identityFor(s.joinerId);
          const doc = await client.platform.documents.create("poolLedger.share", joiner, {
            poolId: poolId.toBuffer(), shareBps: snapshot.shareBps,
            contributionDuffs: snapshot.contributionDuffs, l1RewardScript: p2pkh(crypto.randomBytes(20)),
          });
          await client.platform.documents.broadcast({ create: [doc] }, joiner);
          console.log(`  joiner's share created (${snapshot.shareBps} bps, by ${s.joinerId})`);
        },
        persist: async () => { match.save(env, matchState); saveEnv(env); },
      });

      // v3: the settlement journal lives ON the ledger (a `settlement` document owned by
      // the leaver), visible to every engine; phases advance by document replace. Settled
      // settlements REMAIN as a permanent churn audit trail.
      // a settlement document is only driven after its snapshot is verified against the
      // requests it references (pool, kinds, owners, amount), so a document created by a
      // buggy or dishonest engine cannot steer this one (review finding B9)
      const verifySettlementDoc = async (o) => {
        const exitReq = await requestById(Identifier.from(Buffer.from(o.exitId)).toString());
        const joinReq = await requestById(Identifier.from(Buffer.from(o.joinId)).toString());
        const eo = exitReq.toObject(); const jo = joinReq.toObject();
        const checks = [
          [eo.kind === "exit" && jo.kind === "join", "kinds"],
          [Identifier.from(Buffer.from(eo.poolId)).toString() === poolId.toString()
            && Identifier.from(Buffer.from(jo.poolId)).toString() === poolId.toString(), "pool"],
          [exitReq.getOwnerId().toString() === Identifier.from(Buffer.from(o.leaverId)).toString(), "leaver"],
          [joinReq.getOwnerId().toString() === Identifier.from(Buffer.from(o.joinerId)).toString(), "joiner"],
          [Number(eo.amountDuffs) === Number(o.amountDuffs)
            && Number(jo.amountDuffs) === Number(o.amountDuffs), "amount"],
        ];
        const bad = checks.find(([ok]) => !ok);
        if (bad) throw new Error(`settlement document contradicts its referenced requests (${bad[1]}); refusing to drive it`);
      };
      const driveV3 = async (doc) => {
        const o = doc.toObject();
        await verifySettlementDoc(o);
        const fields = {
          poolId: Identifier.from(Buffer.from(o.poolId)).toString(),
          exitId: Identifier.from(Buffer.from(o.exitId)).toString(),
          joinId: Identifier.from(Buffer.from(o.joinId)).toString(),
          leaverId: Identifier.from(Buffer.from(o.leaverId)).toString(),
          joinerId: Identifier.from(Buffer.from(o.joinerId)).toString(),
          amountDuffs: Number(o.amountDuffs),
          share: { shareBps: Number(o.shareBps), contributionDuffs: Number(o.contributionDuffs || 0) },
          phase: o.phase,
        };
        const state = { version: 1, settlement: fields };
        const leaver = await identityFor(fields.leaverId);
        const ops = opsFor(fields);
        ops.persist = async () => {
          const d = (await client.platform.documents.get("poolLedger.settlement", {
            where: [["$id", "==", doc.getId()]],
          }))[0];
          d.set("phase", fields.phase);
          await client.platform.documents.broadcast({ replace: [d] }, leaver);
        };
        await match.driveSettlement(state, ops, console.log);
      };

      // 1. finish whatever a crashed run left, before looking at new work. A LOCAL
      // settlement journal (v1 mode) must stop a v3 run too: the old code's isV3 branch
      // silently bypassed it, abandoning the stranded pair (review batch-2 blocker, B11)
      const matchState = match.load(env);
      if (isV3() && matchState.settlement) {
        throw new Error("a LOCAL settlement journal exists (pool " + matchState.settlement.poolId +
          ", phase " + matchState.settlement.phase + "); finish it under its own LEDGER setting " +
          (matchState.settlement.contractId ? `(contract ${matchState.settlement.contractId}) ` : "") +
          "before running v3");
      }
      if (isV3()) {
        for (const ph of match.PHASES.filter((p) => p !== "settled")) {
          const open = await fetchAll(client, "poolLedger.settlement", {
            where: [["poolId", "==", poolId], ["phase", "==", ph]],
          });
          for (const doc of open) {
            console.log(`RESUMING an on-ledger settlement ${doc.getId().toString()} (phase ${ph})`);
            await driveV3(doc);
          }
        }
      } else if (matchState.settlement) {
        const s = matchState.settlement;
        if (s.contractId && s.contractId !== activeContractId(env)) {
          throw new Error(`the local settlement journal belongs to contract ${s.contractId}; ` +
            "re-run with the matching LEDGER setting (review finding B5)");
        }
        if (s.poolId !== poolId.toString()) {
          throw new Error(`an unfinished settlement exists for pool ${s.poolId}; run the engine ` +
            "there first (one settlement at a time)");
        }
        console.log(`RESUMING an unfinished settlement (phase ${s.phase}, exit ${s.exitId})`);
        await match.driveSettlement(matchState, opsFor(s), console.log);
        match.clearSettlement(matchState); match.save(env, matchState); saveEnv(env);
        console.log("resumed settlement completed and cleared");
      }

      // 2. reconcile requests stuck in "matched" with no journal: recoverable only while
      // the leaver's share still exists (then the snapshot can be rebuilt live); a
      // matched pair whose share is already gone without a journal is unrecoverable from
      // the ledger and is reported loudly instead of guessed at
      const matched = await fetchAll(client, "poolLedger.membershipRequest", {
        where: [["poolId", "==", poolId], ["status", "==", "matched"]],
      });
      const matchedPairs = matchRequests(matched);
      for (const pair of matchedPairs) {
        const leaverId = pair.exit.getOwnerId().toString();
        const leaverShares = await sharesOf(leaverId);
        if (leaverShares.length === 0) {
          throw new Error(`requests ${pair.exit.getId().toString()} and ${pair.join.getId().toString()} ` +
            "are matched with no journal and the leaver's share is already gone; the share snapshot " +
            "is unrecoverable from the ledger. Restore MATCH_STATE from .env.local.prev if available.");
        }
        console.log("reconciling a matched pair that has no journal (leaver share still present)");
        const so = leaverShares[0].toObject();
        if (isV3()) {
          const leaverIdentity = await identityFor(leaverId);
          const sdoc = await client.platform.documents.create("poolLedger.settlement", leaverIdentity, {
            poolId: poolId.toBuffer(),
            exitId: pair.exit.getId().toBuffer(), joinId: pair.join.getId().toBuffer(),
            leaverId: Identifier.from(leaverId).toBuffer(),
            joinerId: Identifier.from(pair.join.getOwnerId().toString()).toBuffer(),
            amountDuffs: Number(pair.exit.toObject().amountDuffs), shareBps: Number(so.shareBps),
            contributionDuffs: Number(so.contributionDuffs), phase: "matched",
          });
          await client.platform.documents.broadcast({ create: [sdoc] }, leaverIdentity);
          await driveV3(sdoc);
        } else {
          matchState.settlement = {
            contractId: activeContractId(env),
            poolId: poolId.toString(),
            exitId: pair.exit.getId().toString(), joinId: pair.join.getId().toString(),
            leaverId, joinerId: pair.join.getOwnerId().toString(),
            amountDuffs: Number(pair.exit.toObject().amountDuffs),
            share: { shareBps: Number(so.shareBps), contributionDuffs: Number(so.contributionDuffs) },
            phase: "matched",
          };
          match.save(env, matchState); saveEnv(env);
          await match.driveSettlement(matchState, opsFor(matchState.settlement), console.log);
          match.clearSettlement(matchState); match.save(env, matchState); saveEnv(env);
        }
      }

      // 3. new work: pair the pending requests and settle each through the journal
      const pending = await fetchAll(client, "poolLedger.membershipRequest", {
        where: [["poolId", "==", poolId], ["status", "==", "pending"]],
      });
      const pairs = matchRequests(pending);
      console.log(`matching engine on pool ${poolId.toString()}: ${pending.length} pending, ${pairs.length} pair(s)`);

      for (const pair of pairs) {
        const amount = Number(pair.exit.toObject().amountDuffs);
        const leaverId = pair.exit.getOwnerId().toString();
        const joinerId = pair.join.getOwnerId().toString();
        await identityFor(leaverId); await identityFor(joinerId); // controlled or throw, BEFORE journaling

        // the leaver's share in this pool is what changes hands; its recorded
        // contribution must match the amount both sides requested
        const leaverShares = await sharesOf(leaverId);
        if (leaverShares.length !== 1) throw new Error(`leaver holds ${leaverShares.length} shares in the pool, expected 1`);
        const so = leaverShares[0].toObject();
        if (Number(so.contributionDuffs) !== amount) {
          throw new Error(`pair amount ${amount} differs from the leaver's recorded contribution ` +
            `${Number(so.contributionDuffs)}; refusing a partial handover`);
        }

        // the journal snapshot is the ONLY durable copy of the share once it is deleted;
        // it is written before any status change touches the ledger. v3 writes it ON the
        // ledger (owned by the leaver); v1 keeps the local MATCH_STATE journal.
        if (isV3()) {
          const leaverIdentity = await identityFor(leaverId);
          // another engine may have created the settlement for this exit between our
          // pending-query and now; the unique byExit index turns that race into a clean
          // rejection, which we treat as "resume theirs" rather than an error (review
          // batch-2 minor, B10)
          let sdoc = (await client.platform.documents.get("poolLedger.settlement", {
            where: [["exitId", "==", pair.exit.getId()]],
          }))[0] || null;
          if (!sdoc) {
            try {
              sdoc = await client.platform.documents.create("poolLedger.settlement", leaverIdentity, {
                poolId: poolId.toBuffer(),
                exitId: pair.exit.getId().toBuffer(), joinId: pair.join.getId().toBuffer(),
                leaverId: Identifier.from(leaverId).toBuffer(), joinerId: Identifier.from(joinerId).toBuffer(),
                amountDuffs: amount, shareBps: Number(so.shareBps),
                contributionDuffs: Number(so.contributionDuffs), phase: "prepared",
              });
              await client.platform.documents.broadcast({ create: [sdoc] }, leaverIdentity);
              console.log(`on-ledger settlement created: ${sdoc.getId().toString()} (snapshot before any mutation)`);
            } catch (e) {
              if (!/duplicate unique/i.test((e && e.message) || "")) throw e;
              console.log("another engine created this exit's settlement first; resuming theirs");
              sdoc = (await client.platform.documents.get("poolLedger.settlement", {
                where: [["exitId", "==", pair.exit.getId()]],
              }))[0];
              if (!sdoc) throw new Error("settlement creation lost the unique race but the winner is not queryable yet; re-run");
            }
          } else {
            console.log(`a settlement already exists for this exit (${sdoc.getId().toString()}); resuming it`);
          }
          await driveV3(sdoc);
        } else {
          matchState.settlement = {
            contractId: activeContractId(env),
            poolId: poolId.toString(),
            exitId: pair.exit.getId().toString(), joinId: pair.join.getId().toString(),
            leaverId, joinerId, amountDuffs: amount,
            share: { shareBps: Number(so.shareBps), contributionDuffs: Number(so.contributionDuffs) },
            phase: "prepared",
          };
          match.save(env, matchState); saveEnv(env);
          await match.driveSettlement(matchState, opsFor(matchState.settlement), console.log);
          match.clearSettlement(matchState); match.save(env, matchState); saveEnv(env);
        }
      }
      if (pairs.length === 0 && matchedPairs.length === 0 && !matchState.settlement) {
        console.log("nothing to settle");
        return;
      }

      const sharesBack = await client.platform.documents.get("poolLedger.share", {
        where: [["poolId", "==", poolId]],
      });
      console.log(`\nreadback: pool now has ${sharesBack.length} share(s):`);
      for (const s of sharesBack) {
        console.log(`  ${Number(s.toObject().shareBps)} bps owned by ${s.getOwnerId().toString()}`);
      }
      console.log(`\n=== MATCHER OK (existing pool): ${pairs.length + matchedPairs.length} pair(s) settled ===`);
      return;
    }

    const operator = await ensureCredits(await client.platform.identities.get(env.IDENTITY_ID));
    const funder1 = await ensureCredits(await client.platform.identities.get(env.FUNDER_ID));
    const funder2 = await ensureCredits(await client.platform.identities.get(env.FUNDER2_ID));

    // a fresh pool with funder1 as the sole incumbent
    const SHARE_BPS = 5000;
    const AMOUNT = 500000000; // the 5 DASH contribution changing hands
    const poolDoc = await client.platform.documents.create("poolLedger.pool", operator, {
      proTxHash: crypto.randomBytes(32),
      slotIndex: 0,
      nodeType: "regular",
      operatorIdentityId: operator.getId().toBuffer(),
      operatorFeeBps: 2000,
      // v5 requires the lifecycle field; these pools back nodes, hence live (F5)
      ...(isV5() ? { status: "live" } : {}),
    });
    await client.platform.documents.broadcast({ create: [poolDoc] }, operator);
    const poolId = poolDoc.getId();
    console.log("pool created:", poolId.toString());

    const share1 = await client.platform.documents.create("poolLedger.share", funder1, {
      poolId: poolId.toBuffer(), shareBps: SHARE_BPS, contributionDuffs: AMOUNT,
      l1RewardScript: p2pkh(crypto.randomBytes(20)),
    });
    await client.platform.documents.broadcast({ create: [share1] }, funder1);
    console.log(`funder1 holds the share (${SHARE_BPS} bps, ${AMOUNT} duffs)`);

    // the two sides of the market
    const exitReq = await client.platform.documents.create("poolLedger.membershipRequest", funder1, {
      poolId: poolId.toBuffer(), kind: "exit", amountDuffs: AMOUNT, status: "pending",
    });
    await client.platform.documents.broadcast({ create: [exitReq] }, funder1);
    console.log("funder1 submitted an exit request");

    const joinReq = await client.platform.documents.create("poolLedger.membershipRequest", funder2, {
      poolId: poolId.toBuffer(), kind: "join", amountDuffs: AMOUNT, status: "pending",
    });
    await client.platform.documents.broadcast({ create: [joinReq] }, funder2);
    console.log("funder2 submitted a join request");

    // the matching engine: read the ledger, pair exit with join
    const pending = await client.platform.documents.get("poolLedger.membershipRequest", {
      where: [["poolId", "==", poolId], ["status", "==", "pending"]],
    });
    const pairs = matchRequests(pending);
    console.log(`\nmatching engine: ${pending.length} pending requests, ${pairs.length} pair(s) found`);
    if (pairs.length !== 1) throw new Error("expected exactly one exit/join pair");
    const pair = pairs[0];
    if (pair.exit.getId().toString() !== exitReq.getId().toString()
      || pair.join.getId().toString() !== joinReq.getId().toString()) {
      throw new Error("the engine paired the wrong requests");
    }

    // each owner accepts the match on their own document
    await setStatus(exitReq, funder1, "pending", "matched");
    await setStatus(joinReq, funder2, "pending", "matched");

    // settlement: the share changes hands (delete by the leaver, create by the joiner)
    const oldShare = await fresh("poolLedger.share", share1);
    await client.platform.documents.broadcast({ delete: [oldShare] }, funder1);
    console.log("funder1's share deleted (by funder1)");

    const share2 = await client.platform.documents.create("poolLedger.share", funder2, {
      poolId: poolId.toBuffer(), shareBps: SHARE_BPS, contributionDuffs: AMOUNT,
      l1RewardScript: p2pkh(crypto.randomBytes(20)),
    });
    await client.platform.documents.broadcast({ create: [share2] }, funder2);
    console.log("funder2's share created (by funder2)");

    await setStatus(exitReq, funder1, "matched", "settled");
    await setStatus(joinReq, funder2, "matched", "settled");

    // readback: one share in the pool, owned by funder2; both requests settled
    const shares = await client.platform.documents.get("poolLedger.share", {
      where: [["poolId", "==", poolId]],
    });
    const exitBack = await fresh("poolLedger.membershipRequest", exitReq);
    const joinBack = await fresh("poolLedger.membershipRequest", joinReq);
    console.log(`\nreadback: ${shares.length} share(s) in pool; owner ${shares[0] && shares[0].getOwnerId().toString()}`);
    console.log(`  exit request status: ${exitBack.toObject().status}, join request status: ${joinBack.toObject().status}`);
    if (shares.length !== 1
      || shares[0].getOwnerId().toString() !== funder2.getId().toString()
      || Number(shares[0].toObject().shareBps) !== SHARE_BPS
      || exitBack.toObject().status !== "settled"
      || joinBack.toObject().status !== "settled") {
      throw new Error("settlement readback does not match the expected end state");
    }
    console.log("\n=== MATCHER OK: exit paired with join, share handed over, lifecycle settled ===");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
