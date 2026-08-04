/**
 * One-shot cleanup of the development-debris pools on the devnet ledger: pools whose
 * share table is incomplete AND which never distributed anything (the audit's warning
 * set). Each document is deleted by the identity that owns it, the same self-sovereign
 * rule as everything else; nothing else is touched, and a pool with any accrual is
 * refused outright.
 *
 * The controlled-identity set is discovered from .env.local by pattern (IDENTITY_ID plus
 * every FUNDER_ID / FUNDERN_ID), and the whole deletion set is preflighted first: if ANY
 * document in a debris pool is owned by an identity this run does not control, the
 * ENTIRE pool is skipped, never partially deleted (review finding F8, 2026-07-11; the
 * old version hardcoded three funders and could orphan a foreign share).
 *
 * Two ledger-dependent limits (phase F of docs/V9_MIGRATION_PLAN.md):
 * - On a completion-receipt ledger, a pool with ANY receipt is never debris, whatever its
 *   share table says, and is skipped outright: sweeping a completed pool's shares would
 *   orphan its receipt's record, and a receipt that fails to verify is an anomaly to
 *   resolve by hand, not to delete around. The plan is re-run before EVERY delete on
 *   FRESH counts of every document family (receipts, shares, requests, accruals,
 *   ownership), and any document that was not in the planned set stops the sweep
 *   outright, so a completion, a pledge, or a join landing at any point during the
 *   sweep stops the remaining deletions rather than only the first.
 * - On an immutable-pool ledger the pool document CANNOT be deleted (canBeDeleted:
 *   false) and is excluded from the deletion set aloud; its shares and requests are still
 *   cleaned under the same controlled-identity preflight, and the pool remains on the
 *   ledger as the permanent receipt-less document the admission rule fails closed against.
 *
 * Every skip-or-sweep decision is `debrisPlan.cjs`, a transport-free function covered
 * offline by cleanupDebrisPlanTest.cjs; this script fetches, holds each pool's
 * completion-protocol operation lock for the duration of its sweep (a held lock is a
 * skip, per the done-prune pattern), and executes the plan.
 *
 * Run like the other scripts. Prints what it deletes; re-run is a no-op.
 */
const Dash = require("dash");
const { loadEnv, activeContractId, isV3, hasCompletionReceipt, hasImmutablePool,
  hasPledgeSlot, acquireOpLock, releaseOpLock } = require("./envStore.cjs");
const { fetchAll } = require("./query.cjs");
const journal = require("./compoundJournal.cjs");
const { planPoolSweep } = require("./debrisPlan.cjs");

(async () => {
  const env = loadEnv();
  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
    apps: { poolLedger: { contractId: activeContractId(env) } },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  const mine = new Set();
  for (const [k, v] of Object.entries(env)) {
    if (k === "IDENTITY_ID" || k === "FUNDER_ID" || /^FUNDER\d+_ID$/.test(k)) mine.add(v);
  }
  const identities = {};
  const identityFor = async (idStr) => {
    if (!identities[idStr]) identities[idStr] = await client.platform.identities.get(idStr);
    return identities[idStr];
  };

  try {
    await client.getWalletAccount();

    const fetchReceipts = (poolId) => fetchAll(client, "poolLedger.completionReceipt", {
      where: [["poolId", "==", poolId]],
    });

    const pools = await fetchAll(client, "poolLedger.pool");
    let removed = 0;
    for (const pool of pools) {
      const poolId = pool.getId();
      // the per-pool COMPLETION-PROTOCOL lock, same lock formation's complete/receipt/
      // abandon hold: a sweep must not interleave with a completion of the same pool on
      // this host. A held lock means a protocol run is active, which is itself proof the
      // pool is not debris right now, so contention is a skip, not an error (the done
      // prune pattern). A foreign writer on another host stays the documented residual,
      // narrowed by the receipt re-query below.
      const lockName = journal.suffixFor(activeContractId(env), poolId.toString());
      let lockHeld = false;
      try { acquireOpLock(lockName); } catch (e) {
        if (e && e.code === "OPLOCK_CONTENDED") lockHeld = true; else throw e;
      }
      if (lockHeld) {
        // even the contention skip is the PLAN's decision (vetting round, finding 2):
        // the counts are irrelevant under a held lock, and the plan checks it first
        const locked = planPoolSweep({ shareBpsSum: 0, shareCount: 0, accrualCount: 0,
          receiptCount: 0, ownerIds: [], controlled: mine,
          receiptLedger: hasCompletionReceipt(), immutablePool: hasImmutablePool(),
          lockHeld: true });
        // the skip is the PLAN's ACTION, not a structural continue (pass-7 wave, minor):
        // the caller previously called the plan only to borrow its reason string while
        // hardcoding the skip, so a plan that stopped skipping locked pools would have
        // been ignored here. Now a different answer is a loud refusal.
        if (locked.action !== "skip-locked") {
          throw new Error(`the sweep plan did not skip a lock-contended pool (returned ` +
            `${locked.action}); refusing to continue rather than skip on a structural ` +
            "assumption the plan no longer supports");
        }
        console.log(`SKIP ${poolId.toString()}: ${locked.reason}`);
        continue;
      }
      try {
        const shares = await fetchAll(client, "poolLedger.share", {
          where: [["poolId", "==", poolId]],
        });
        const bps = shares.reduce((s, d) => s + Number(d.toObject().shareBps), 0);
        const accruals = await fetchAll(client, "poolLedger.rewardAccrual", {
          where: [["poolId", "==", poolId]],
        });
        const receipts = hasCompletionReceipt() ? await fetchReceipts(poolId) : [];
        // EVERY request status, not only pending (final pass, major 3): matched and
        // settled requests are pool-referencing member documents too, and filtering
        // them out hid them from the ownership preflight, the newcomer stop, and the
        // deletable set at planning and refresh alike.
        // THE DISPOSABILITY ASSUMPTION, stated beside the query (artifact check): a
        // pool reaches the sweep only when it NEVER COMPLETED and NEVER DISTRIBUTED
        // (incomplete share table, zero accruals, zero receipts, all re-checked before
        // every delete), and on such a pool a matched or settled request is the
        // leftover of an aborted matching flow with nothing downstream of it, so
        // status does not confer protection; what protects documents here is
        // ownership (whole-pool-or-nothing), accruals, receipts, and the newcomer
        // stop, each of which refuses the WHOLE pool, never per-status.
        const requests = await fetchAll(client, "poolLedger.membershipRequest", {
          where: [["poolId", "==", poolId]],
        });
        // pledgeSlot claims are pool-referencing member documents too (closing wave,
        // must-fix confirmation): they join the enumeration, the ownership preflight,
        // and the deletable set on every ledger that has the type, or a claim would
        // survive its pool's deletion as an orphan the F8 rule exists to prevent
        const slots = hasPledgeSlot() ? await fetchAll(client, "poolLedger.pledgeSlot", {
          where: [["poolId", "==", poolId]],
        }) : [];

        // every skip-or-sweep decision is the PLAN's, one transport-free function covered
        // offline (cleanupDebrisPlanTest.cjs); this loop only fetches and executes it
        const docs = [...shares, ...requests, ...slots, pool];
        const plan = planPoolSweep({
          shareBpsSum: bps, shareCount: shares.length, accrualCount: accruals.length,
          receiptCount: receipts.length, ownerIds: docs.map((d) => d.getOwnerId().toString()),
          controlled: mine, receiptLedger: hasCompletionReceipt(),
          immutablePool: hasImmutablePool(),
        });
        if (plan.action === "keep") continue; // a complete pool is not debris
        if (plan.action === "skip-accruals") {
          console.log(`SKIP ${poolId.toString()}: ${plan.reason}; not touching it`);
          continue;
        }
        if (plan.action === "skip-receipt") {
          console.log(`SKIP ${poolId.toString()}: ${plan.reason} (${receipts[0].getId().toString()})`);
          continue;
        }
        if (plan.action === "skip-foreign") {
          console.log(`SKIP ${poolId.toString()}: ${plan.foreign.length} document(s) owned by identities this ` +
            `run does not control (e.g. ${plan.foreign[0]}); leaving the pool intact`);
          continue;
        }

        const deletable = plan.deletePool ? docs : docs.filter((d) => d !== pool);
        console.log(`debris pool ${poolId.toString()} (${shares.length} shares, ${bps} bps): removing` +
          (plan.deletePool ? "" : " its shares and requests (the pool document cannot be deleted on " +
            "this ledger and remains as the permanent receipt-less record)"));
        // THE PLAN IS RE-RUN BEFORE EVERY DELETE, not once before the first (vetting
        // round, must-fix), AND EVERY INPUT IS REFRESHED, not only the receipt count
        // (closing wave, must-fix): a share, request, or accrual landing mid-sweep
        // changes the answer exactly like a receipt does, and a document that was not
        // in the planned set at all (newcomerCount) stops the sweep outright, because
        // the pool is no longer the pool the plan covered. The decision is the SAME
        // tested function on fresh counts each time. What remains is one irreducible
        // window PER DELETE, between that delete's re-check and its consensus
        // inclusion, FOR EVERY DOCUMENT FAMILY (receipts, shares, requests, accruals,
        // ownership), because Platform caps a batch at one transition and a
        // conditional check-plus-delete is not expressible.
        const plannedIds = new Set(docs.map((d) => d.getId().toString()));
        for (const doc of deletable) {
          const freshShares = await fetchAll(client, "poolLedger.share", {
            where: [["poolId", "==", poolId]],
          });
          const freshAccruals = await fetchAll(client, "poolLedger.rewardAccrual", {
            where: [["poolId", "==", poolId]],
          });
          const freshReceipts = hasCompletionReceipt() ? await fetchReceipts(poolId) : [];
          const freshRequests = await fetchAll(client, "poolLedger.membershipRequest", {
            where: [["poolId", "==", poolId]],
          });
          const freshSlots = hasPledgeSlot() ? await fetchAll(client, "poolLedger.pledgeSlot", {
            where: [["poolId", "==", poolId]],
          }) : [];
          const freshDocs = [...freshShares, ...freshRequests, ...freshSlots, pool];
          const freshBps = freshShares.reduce((s, d) => s + Number(d.toObject().shareBps), 0);
          const again = planPoolSweep({
            shareBpsSum: freshBps, shareCount: freshShares.length,
            accrualCount: freshAccruals.length, receiptCount: freshReceipts.length,
            ownerIds: freshDocs.map((d) => d.getOwnerId().toString()),
            controlled: mine, receiptLedger: hasCompletionReceipt(),
            immutablePool: hasImmutablePool(),
            newcomerCount: freshDocs.filter((d) => d !== pool
              && !plannedIds.has(d.getId().toString())).length,
          });
          if (again.action !== "sweep") {
            console.log(`STOP ${poolId.toString()}: the per-delete re-check changed the answer ` +
              `(${again.reason || again.action}) before ${doc.getType()} ${doc.getId().toString()}; ` +
              "the remaining documents are left in place");
            break;
          }
          const owner = await identityFor(doc.getOwnerId().toString());
          await client.platform.documents.broadcast({ delete: [doc] }, owner);
          console.log(`  deleted ${doc.getType()} ${doc.getId().toString()} ` +
            `(owner ${doc.getOwnerId().toString().slice(0, 8)}...)`);
          removed++;
        }
      } finally {
        releaseOpLock(lockName);
      }
    }
    console.log(`\n=== DEBRIS CLEANUP DONE: ${removed} documents deleted ===`);
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
