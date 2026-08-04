/**
 * The debris-sweep routing, offline (phase F of docs/V9_MIGRATION_PLAN.md).
 *
 * THE CASE THIS SUITE EXISTS FOR is the ledger-dependent pair: a pool with a completion
 * receipt is never debris even when its mutable share table is broken, and an
 * immutable-pool ledger withholds the pool document from the deletion set while keeping
 * it inside the whole-pool-or-nothing ownership preflight (review finding F8). The plan
 * is transport-free, so every branch is asserted here without a live Platform;
 * cleanupDebris.cjs owns only the fetches, the operation lock, and the broadcasts.
 *
 * Run: node src/scripts/cleanupDebrisPlanTest.cjs   (exits non-zero on failure)
 */
const { planPoolSweep } = require("./debrisPlan.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };

const OP = "operator-id", F1 = "funder-1", F2 = "funder-2", STRANGER = "someone-else";
const base = {
  shareBpsSum: 5000, shareCount: 1, accrualCount: 0, receiptCount: 0,
  ownerIds: [F1, OP], controlled: new Set([OP, F1, F2]),
  receiptLedger: true, immutablePool: false,
};

// a complete pool is not debris
ok("a complete share table keeps the pool",
  planPoolSweep({ ...base, shareBpsSum: 10000, shareCount: 2 }).action === "keep");
ok("an empty share table is not 'complete at 0 bps'",
  planPoolSweep({ ...base, shareBpsSum: 0, shareCount: 0 }).action === "sweep");

// anything that distributed is refused outright
ok("accruals refuse the sweep",
  planPoolSweep({ ...base, accrualCount: 1 }).action === "skip-accruals");

// the receipt protection, and its gate
ok("a receipt protects the pool on a receipt ledger",
  planPoolSweep({ ...base, receiptCount: 1 }).action === "skip-receipt");
ok("the receipt skip outranks the foreign skip (never reported as merely foreign)",
  planPoolSweep({ ...base, receiptCount: 1, ownerIds: [STRANGER, OP] }).action === "skip-receipt");
ok("receiptCount is ignored where the contract has no receipt type",
  planPoolSweep({ ...base, receiptCount: 1, receiptLedger: false }).action === "sweep");

// whole-pool-or-nothing ownership (F8), pool document included
{
  const r = planPoolSweep({ ...base, ownerIds: [F1, STRANGER, OP] });
  ok("one foreign document skips the whole pool", r.action === "skip-foreign");
  ok("the foreign ids are named", r.foreign.length === 1 && r.foreign[0] === STRANGER);
}
ok("a foreign-owned POOL document skips the pool (the pool stays in the preflight)",
  planPoolSweep({ ...base, ownerIds: [F1, STRANGER] }).action === "skip-foreign");

// the deletion set is ledger-dependent
{
  const mutable = planPoolSweep({ ...base });
  ok("a mutable-ledger sweep deletes the pool document", mutable.action === "sweep" && mutable.deletePool === true);
  const immutable = planPoolSweep({ ...base, immutablePool: true });
  ok("an immutable-ledger sweep withholds the pool document",
    immutable.action === "sweep" && immutable.deletePool === false);
}

// the per-delete re-check is THIS SAME FUNCTION on fresh input, so the pair below is the
// re-check's whole contract: unchanged input keeps the answer, a receipt appearing flips it
ok("identical input gives an identical answer (the re-check adds no state)",
  JSON.stringify(planPoolSweep({ ...base })) === JSON.stringify(planPoolSweep({ ...base })));
ok("a receipt appearing between plan and re-check flips sweep to skip",
  planPoolSweep({ ...base }).action === "sweep"
  && planPoolSweep({ ...base, receiptCount: 1 }).action === "skip-receipt");

// the operation-lock contention decision is the plan's too (vetting round, finding 2),
// checked FIRST so a locked pool is never swept whatever its counts say
ok("a held lock skips, whatever the counts",
  planPoolSweep({ ...base, lockHeld: true }).action === "skip-locked");
ok("the lock skip outranks even the complete-table keep",
  planPoolSweep({ ...base, shareBpsSum: 10000, shareCount: 2, lockHeld: true }).action === "skip-locked");
ok("the lock skip carries its reason",
  /operation lock/.test(planPoolSweep({ ...base, lockHeld: true }).reason || ""));
ok("an unlocked pool is unaffected by the new input",
  planPoolSweep({ ...base, lockHeld: false }).action === "sweep");

// mid-sweep arrivals stop the sweep (closing wave, must-fix): a document that was not in
// the enumerated set when the sweep was planned means the pool is no longer the pool the
// plan covered, whoever owns the newcomer, so the per-delete re-check must stop rather
// than keep executing a stale plan
ok("a newcomer document stops the sweep, whatever the counts say",
  planPoolSweep({ ...base, newcomerCount: 1 }).action === "skip-changed");
ok("a self-owned newcomer stops the sweep too (concurrency, not ownership, is the signal)",
  planPoolSweep({ ...base, newcomerCount: 2, ownerIds: [F1, OP] }).action === "skip-changed");
ok("the newcomer skip carries its reason",
  /arrived since the sweep was planned/.test(planPoolSweep({ ...base, newcomerCount: 1 }).reason || ""));
ok("regression pin: the lock skip still outranks the newcomer skip (checked first)",
  planPoolSweep({ ...base, newcomerCount: 1, lockHeld: true }).action === "skip-locked");
ok("regression pin: zero newcomers changes nothing",
  planPoolSweep({ ...base, newcomerCount: 0 }).action === "sweep");

console.log(`cleanupDebrisPlanTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
