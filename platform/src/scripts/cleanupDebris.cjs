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
 *   resolve by hand, not to delete around. The receipt is re-queried immediately before
 *   the first delete, so a completion landing during the checks skips the pool too.
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
  acquireOpLock, releaseOpLock } = require("./envStore.cjs");
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
      try { acquireOpLock(lockName); } catch (e) {
        if (e && e.code === "OPLOCK_CONTENDED") {
          console.log(`SKIP ${poolId.toString()}: a completion-protocol run holds this pool's ` +
            "operation lock; not debris right now");
          continue;
        }
        throw e;
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
        const requests = await fetchAll(client, "poolLedger.membershipRequest", {
          where: [["poolId", "==", poolId], ["status", "==", "pending"]],
        });

        // every skip-or-sweep decision is the PLAN's, one transport-free function covered
        // offline (cleanupDebrisPlanTest.cjs); this loop only fetches and executes it
        const docs = [...shares, ...requests, pool];
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

        // RE-RUN THE PLAN on a re-queried receipt count immediately before the first
        // delete (the abandon re-fetch pattern): a completion elsewhere could have
        // published a receipt during the fetches above, and sweeping past it would delete
        // a completed pool's share table. The decision is the SAME tested function, on
        // fresh input, so the ledger gate and the threshold cannot drift from the
        // offline-covered logic. The residual window between this re-query and consensus
        // inclusion of the deletes cannot be closed from here: Platform caps a batch at
        // one transition, so a conditional check-plus-delete is not expressible, which is
        // the same documented residual every mutation path in this codebase carries.
        const recheck = hasCompletionReceipt() ? await fetchReceipts(poolId) : [];
        const planNow = planPoolSweep({
          shareBpsSum: bps, shareCount: shares.length, accrualCount: accruals.length,
          receiptCount: recheck.length, ownerIds: docs.map((d) => d.getOwnerId().toString()),
          controlled: mine, receiptLedger: hasCompletionReceipt(),
          immutablePool: hasImmutablePool(),
        });
        if (planNow.action !== "sweep") {
          console.log(`SKIP ${poolId.toString()}: the pre-delete re-check changed the answer ` +
            `(${planNow.reason || planNow.action}); a completion landed during the sweep's checks`);
          continue;
        }

        const deletable = planNow.deletePool ? docs : docs.filter((d) => d !== pool);
        console.log(`debris pool ${poolId.toString()} (${shares.length} shares, ${bps} bps): removing` +
          (planNow.deletePool ? "" : " its shares and requests (the pool document cannot be deleted on " +
            "this ledger and remains as the permanent receipt-less record)"));
        for (const doc of deletable) {
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
