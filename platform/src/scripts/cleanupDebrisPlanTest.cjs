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
  // AN IMMUTABLE RECEIPT-LESS POOL IS NOT SWEPT AT ALL (packet wave, repository-access review F1). The old
  // answer swept its member documents (withholding only the undeletable pool doc), which
  // deletes a live reservation on an OPEN pool the immutable ledger cannot distinguish from
  // abandoned debris. This test previously ENCODED THE UNSAFE ANSWER as expected; it now
  // asserts the fail-closed skip, the same indeterminacy the admission rule refuses on.
  const immutable = planPoolSweep({ ...base, immutablePool: true });
  ok("an immutable receipt-less pool is left intact, not swept",
    immutable.action === "skip-indeterminate");
  ok("the skip names the indeterminate lifecycle",
    /open, in-flight or abandoned/.test(immutable.reason || ""));
  // a mutable receipt-less pool is still swept: the pool document answers forming-vs-live
  // there, so the count-based debris decision is safe
  ok("a mutable receipt-less pool is still swept (its lifecycle IS readable)",
    planPoolSweep({ ...base, immutablePool: false }).action === "sweep");
  // a LIVE mutable pool still short-circuits to skip-live before this point
  ok("regression: a live mutable pool still skips as live, not indeterminate",
    planPoolSweep({ ...base, poolLive: true }).action === "skip-live");
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

// A LIVE POOL IS NEVER DEBRIS (pass 17, F1). The plan had no lifecycle input, so a
// controlled operator's one-basis-point non-participant share pushed the aggregate off
// 10000, defeated the complete-table keep, and every document being controlled returned
// sweep for a pool whose masternode was live and whose receipt was merely unpublished.
ok("a LIVE pool is never debris, whatever its share table sums to",
  planPoolSweep({ ...base, poolLive: true }).action === "skip-live");
ok("the reviewer's exact case: aggregate 10001, all controlled, live -> skip not sweep",
  planPoolSweep({ shareBpsSum: 10001, shareCount: 3, accrualCount: 0, receiptCount: 0,
    ownerIds: [F1, F2, OP, OP], controlled: new Set([OP, F1, F2]),
    receiptLedger: true, immutablePool: false, poolLive: true }).action === "skip-live");
ok("the skip-live decision carries its reason",
  /a node is live behind it|never debris/.test(planPoolSweep({ ...base, poolLive: true }).reason || ""));
ok("liveness outranks a foreign document too (checked before the ownership preflight)",
  planPoolSweep({ ...base, poolLive: true, ownerIds: [F1, "stranger"] }).action === "skip-live");
ok("liveness outranks the count-based keep (a live pool with a complete table is kept as live)",
  planPoolSweep({ ...base, poolLive: true, shareBpsSum: 10000, shareCount: 2 }).action === "skip-live");
// but the lock and newcomer skips still outrank liveness (they are checked first, and both
// mean the plan should not act at all)
ok("regression pin: a held lock still outranks liveness",
  planPoolSweep({ ...base, poolLive: true, lockHeld: true }).action === "skip-locked");
ok("regression pin: poolLive false (the default) leaves the sweep decision unchanged",
  planPoolSweep({ ...base }).action === "sweep");

// poolIsLive, the caller's lifecycle read that feeds poolLive (pass 17, F1, and the
// pre-commit check on its own fold). The DIRECT test the plan cases could not be: the
// plan trusts the boolean, so the boolean's derivation is where the value-shape traps
// live. Driven on a MUTABLE ledger (v8), where liveness exists.
{
  const prev = process.env.LEDGER;
  process.env.LEDGER = "v8";
  // require after setting LEDGER so hasImmutablePool reads it; the module is import-safe
  // (its cleanup IIFE is gated on require.main)
  delete require.cache[require.resolve("./cleanupDebris.cjs")];
  const { poolIsLive } = require("./cleanupDebris.cjs");
  const real = Buffer.alloc(32, 0xaa);
  const forming = Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 7)]);
  ok("poolIsLive: a real proTxHash Buffer is live", poolIsLive({ proTxHash: real }) === true);
  ok("poolIsLive: a forming-namespace Buffer is NOT live", poolIsLive({ proTxHash: forming }) === false);
  ok("poolIsLive: a Uint8Array real hash is live", poolIsLive({ proTxHash: new Uint8Array(real) }) === true);
  // THE HEX-STRING TRAP: Buffer.from(hexString) defaults to UTF-8, so a naive read of a
  // 64-char hex string gives 64 bytes and would wrongly report NOT live. The real hash
  // as a hex string must still read live.
  ok("poolIsLive: a real proTxHash as a HEX STRING is live (not UTF-8 misread)",
    poolIsLive({ proTxHash: real.toString("hex") }) === true);
  ok("poolIsLive: a forming hex string is NOT live", poolIsLive({ proTxHash: forming.toString("hex") }) === false);
  ok("poolIsLive: an absent proTxHash is NOT live", poolIsLive({}) === false);
  ok("poolIsLive: a non-hex string is NOT live (not silently coerced)",
    poolIsLive({ proTxHash: "not a hash at all" }) === false);
  ok("poolIsLive: a wrong-length hex string is NOT live", poolIsLive({ proTxHash: "aa" }) === false);
  // on the immutable ledger there is no flip, so nothing is "live" in this sense
  process.env.LEDGER = "v9";
  delete require.cache[require.resolve("./cleanupDebris.cjs")];
  const v9lib = require("./cleanupDebris.cjs");
  ok("poolIsLive: on the immutable ledger a real hash is still NOT live (no flip there)",
    v9lib.poolIsLive({ proTxHash: real }) === false);
  if (prev === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev;
  delete require.cache[require.resolve("./cleanupDebris.cjs")];
}

// a VANISHED pool short-circuits every other input (closing confirm-pass, minor: the
// caller's missing-pool stop was the one skip decision outside this tested function).
// Driven with otherwise-SWEEPABLE inputs, so the case fails if any other rule is
// consulted first.
{
  const { planPoolSweep } = require("./debrisPlan.cjs");
  const gone = planPoolSweep({ poolPresent: false,
    shareBpsSum: 5000, shareCount: 1, accrualCount: 0, receiptCount: 0,
    ownerIds: ["only-owner"], controlled: new Set(["only-owner"]),
    receiptLedger: true, immutablePool: false });
  ok("a vanished pool is skip-vanished, whatever the other inputs say",
    gone.action === "skip-vanished" && /gone since planning/.test(gone.reason));
  ok("...and the bare-minimum call (only poolPresent) decides without reading anything else",
    planPoolSweep({ poolPresent: false }).action === "skip-vanished");
}

// a pool that ever SETTLED an exit or join is refused outright (a confirmation pass,
// must-fix), same rule as accruals, driven with otherwise-sweepable inputs
{
  const { planPoolSweep } = require("./debrisPlan.cjs");
  const settled = planPoolSweep({ shareBpsSum: 5000, shareCount: 1, accrualCount: 0,
    settlementCount: 1, receiptCount: 0,
    ownerIds: ["only-owner"], controlled: new Set(["only-owner"]),
    receiptLedger: true, immutablePool: false });
  ok("a pool with a settlement is skip-settlements, never swept",
    settled.action === "skip-settlements" && /settled an exit or join/.test(settled.reason));
}

// a PERMANENT (v6) reservation refuses the whole pool (a confirmation pass: the
// plan approved a sweep that would fail midway on the undeletable claim, leaving the
// bookkeeping set partially applied), driven with otherwise-sweepable inputs
{
  const { planPoolSweep } = require("./debrisPlan.cjs");
  const perm = planPoolSweep({ shareBpsSum: 5000, shareCount: 1, accrualCount: 0,
    settlementCount: 0, permanentClaimCount: 1, receiptCount: 0,
    ownerIds: ["only-owner"], controlled: new Set(["only-owner"]),
    receiptLedger: true, immutablePool: false });
  ok("a permanent reservation is skip-permanent-claims, never a partial sweep",
    perm.action === "skip-permanent-claims" && /partially applied/.test(perm.reason));
  ok("zero permanent claims changes nothing",
    planPoolSweep({ shareBpsSum: 5000, shareCount: 1, accrualCount: 0, settlementCount: 0,
      permanentClaimCount: 0, receiptCount: 0, ownerIds: ["only-owner"],
      controlled: new Set(["only-owner"]), receiptLedger: true, immutablePool: false,
    }).action === "sweep");
}

console.log(`cleanupDebrisPlanTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
