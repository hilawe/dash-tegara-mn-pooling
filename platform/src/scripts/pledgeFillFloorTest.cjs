/**
 * Offline tests for a soundness-review finding fill-time floor at PLEDGE admission (the legacy exact-fill
 * path, v1-v5, where arbitrary amounts exist): the pledge that completes the fill is
 * refused unless every resulting owner aggregate meets the covenant's per-share floor,
 * while a sub-floor pledge into a pool with space left stays admissible, because that
 * owner can still top up or cancel. Mirrors reserveAdmissionTest's mock-ctx harness.
 */
const { Identifier } = require("@dashevo/wasm-dpp");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };

(async () => {
  const prevLedger = process.env.LEDGER;
  process.env.LEDGER = "v3"; // a pre-slot ledger, so the pledge path is live
  const journal = require("./compoundJournal.cjs");
  const pledge = require("./commands/pledge.cjs");

  const IDENTITY_SENTINEL = "REACHED_IDENTITY_STEP"; // thrown after every admission check
  const POOL_ID = { toBuffer: () => Buffer.alloc(32, 5), toString: () => "pool-1" };
  const forming = Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 7)]);
  // the fixture carries kind and status because the admission path FILTERS on
  // kind === "join" (a fixture without it models an empty book and proves nothing,
  // the playbook's producible-fixture corollary, caught in this test's first run)
  const joinBy = (owner, amountDuffs) => ({
    toObject: () => ({ amountDuffs, kind: "join", status: "pending" }),
    getOwnerId: () => ({ toString: () => owner }) });

  const mkCtx = (joins, amountStr) => ({
    client: { platform: {
      documents: { get: async () => [] },
      contracts: { get: async () => ({ getOwnerId: () => ({ toString: () => "operator" }) }) },
      identities: { get: async () => { throw new Error(IDENTITY_SENTINEL); } },
    }, getWalletAccount: async () => { throw new Error(IDENTITY_SENTINEL); } },
    args: ["pool-1", amountStr], cmd: "pledge", who: "F1",
    DASHfmt: (v) => String(v), short: (s) => s, Identifier,
    Dash: { Core: { Script: { buildPublicKeyHashOut: () => ({ toBuffer: () => Buffer.alloc(25) }) } } },
    fetchAll: async () => joins,
    isV3: () => true, isV5: () => false, isV6: () => false,
    hasJoinProvenance: () => false, hasMemberRewardScript: () => false,
    getPool: async () => ({ toObject: () => ({ nodeType: "regular", proTxHash: forming }),
      getId: () => POOL_ID, getOwnerId: () => ({ toString: () => "operator" }) }),
    journal, env: {}, activeContractId: () => "contract-1",
    myId: "member-new",
  });

  const run = async (joins, amountStr) => {
    try { await pledge(mkCtx(joins, amountStr)); return "returned"; }
    catch (e) { return e.message; }
  };

  // the reviewer's 475/475/50 case: the 50 DASH fill-completing pledge locks the NEW
  // owner below the floor and is refused by name
  const r1 = await run([joinBy("owner-a", "47500000000"), joinBy("owner-b", "47500000000")],
    "5000000000");
  ok("a soundness-review finding: the fill-completing sub-floor pledge is refused",
    /minimum share/.test(r1) && !r1.includes(IDENTITY_SENTINEL));

  // the repaired shape: an EXISTING owner absorbs the 50 DASH remainder (their aggregate
  // becomes 525) and admission passes every check up to the identity step (the sentinel
  // proves that much and no more; the refusal rows are what prove the floor block runs)
  const r2 = await run([joinBy("owner-a", "47500000000"), joinBy("member-new", "47500000000")],
    "5000000000"); // member-new tops up to 525 DASH, both owners >= 100 DASH
  ok("a soundness-review finding: an existing owner absorbing the remainder passes the floor",
    r2.includes(IDENTITY_SENTINEL));

  // the checker-chosen mutation's target (external artifact check, finding 2): a check
  // that inspects only the PLEDGER's aggregate passes every row above. Here the filling
  // pledger meets the floor and a DIFFERENT existing owner does not, so only a loop over
  // every aggregate refuses, and the refusal must name the sub-floor owner, not the
  // pledger
  const r4 = await run([joinBy("owner-a", "5000000000"), joinBy("owner-b", "85000000000")],
    "10000000000"); // member-new fills with exactly 100 DASH; owner-a holds 50
  ok("a soundness-review finding: a fill is refused when a DIFFERENT existing owner is below the floor",
    /minimum share/.test(r4) && /owner-a/.test(r4) && !r4.includes(IDENTITY_SENTINEL));

  // a sub-floor pledge with space LEFT stays admissible (repairable, not stranding)
  const r3 = await run([joinBy("owner-a", "47500000000")], "5000000000");
  ok("a soundness-review finding: a sub-floor pledge into an open pool stays admissible",
    r3.includes(IDENTITY_SENTINEL));

  if (prevLedger === undefined) delete process.env.LEDGER; else process.env.LEDGER = prevLedger;
  console.log(`pledgeFillFloorTest: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
