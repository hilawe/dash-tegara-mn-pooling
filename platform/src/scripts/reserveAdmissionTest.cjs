/**
 * Command-level admission cases for BOTH admission commands, `reserve` and `pledge`
 * (pre-commit artifact check 2026-08-03; pledge added by the pass-7 re-confirmation):
 * the unit suite proves requireCoherentSlotEconomics itself, and THIS suite proves the
 * COMMAND actually routes through it, because a partial fold that added the tested
 * helper while keeping reserve's old product-only inline check would leave every unit
 * case green and the admission gap open (the closing-wave major's exact shape).
 *
 * The command runs against a stub context: getPool returns a v9-shaped pool whose slot
 * book multiplies to the regular tier while its own immutable targetDuffs names the evo
 * tier, the receipt query returns empty, and the coordinated-participation exception is
 * armed. The claims fetch that follows the economics check throws a sentinel, so the
 * assertion can tell a refusal AT the economics check (wanted) from a run that sailed
 * past it (the regression).
 *
 * Run: LEDGER is set inside; node src/scripts/reserveAdmissionTest.cjs
 */
const { Identifier } = require("@dashevo/wasm-dpp");
const crypto = require("crypto");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };

(async () => {
  process.env.LEDGER = "v9";
  const POOL_ID = Identifier.from(crypto.createHash("sha256").update("reserve-admission-pool").digest()).toString();
  process.env.TEGARA_PARTICIPATE = POOL_ID;
  const CONTRACT = Identifier.from(crypto.createHash("sha256").update("reserve-admission-contract").digest()).toString();
  const journal = require("./compoundJournal.cjs");
  const reserve = require("./commands/reserve.cjs");

  const SENTINEL = "REACHED_CLAIMS_FETCH";
  const WALLET_SENTINEL = "REACHED_WALLET_STEP";
  const mkCtx = (po, claims) => ({
    client: { platform: { documents: { get: async () => [] } },
      getWalletAccount: async () => { throw new Error(WALLET_SENTINEL); } },
    args: [POOL_ID, claims ? String(claims.length) : "0"], cmd: "reserve", who: "F1",
    DASHfmt: (v) => String(v), short: (s) => s,
    Identifier,
    Dash: { Core: { Script: { buildPublicKeyHashOut: () => ({ toBuffer: () => Buffer.alloc(25) }) } } },
    fetchAll: async () => { if (!claims) throw new Error(SENTINEL); return claims; },
    isV6: () => true, isV7: () => true,
    getPool: async () => ({ toObject: () => po, getId: () => POOL_ID }),
    journal, env: { CONTRACT_V9_ID: CONTRACT },
    activeContractId: () => CONTRACT,
    myId: "member-1",
  });
  const claimBy = (owner, slotNo) => ({ toObject: () => ({ slotNo }),
    getOwnerId: () => ({ toString: () => owner }) });

  const run = async (po) => {
    try { await reserve(mkCtx(po)); return "returned"; } catch (e) { return e.message; }
  };

  // the closing-wave shape: regular-tier slot book, evo targetDuffs
  const incoherent = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
    targetDuffs: 400000000000, slotDuffs: 50000000000, slotCount: 2 };
  const r1 = await run(incoherent);
  ok("reserve refuses the incoherent pool AT the economics check (targetDuffs named in the error)",
    /targetDuffs/.test(r1) && !r1.includes(SENTINEL));

  // the coherent pool sails past the economics check to the claims fetch
  const coherent = { ...incoherent, targetDuffs: 100000000000 };
  const r2 = await run(coherent);
  ok("reserve passes a coherent pool through to the claims fetch (sentinel reached)",
    r2.includes(SENTINEL));

  // the distinct-owner bound at the COMMAND level (final pass, major 2): a ten-slot
  // coherent pool with eight distinct owners on slots 0-7; a ninth identity's claim is
  // refused AT the capacity guard, while an existing owner's second claim passes the
  // guard through to the wallet step (its own sentinel)
  const tenSlot = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
    targetDuffs: 100000000000, slotDuffs: 10000000000, slotCount: 10 };
  const eight = Array.from({ length: 8 }, (_, i) => claimBy(`owner-${i + 1}`, i));
  const r3 = await (async () => { try { await reserve(mkCtx(tenSlot, eight)); return "returned"; }
    catch (e) { return e.message; } })();
  ok("reserve refuses the claim that would create a ninth distinct owner",
    /distinct owners/.test(r3) && !r3.includes(WALLET_SENTINEL));
  const eightWithMe = [claimBy("member-1", 0), ...Array.from({ length: 7 }, (_, i) => claimBy(`owner-${i + 2}`, i + 1))];
  const r4 = await (async () => { try { await reserve(mkCtx(tenSlot, eightWithMe)); return "returned"; }
    catch (e) { return e.message; } })();
  ok("an existing owner's second claim passes the capacity guard (free slots are irrelevant excess)",
    r4.includes(WALLET_SENTINEL));

  // the PRODUCT-MINIMUM preflight at the COMMAND level (pass 7, major 2): on a two-slot
  // coherent pool, one member taking the LAST free slot alone is refused, while taking
  // the FIRST of two is admitted (the excess-capacity row driven through the command)
  const twoSlot = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
    targetDuffs: 100000000000, slotDuffs: 50000000000, slotCount: 2 };
  const mine0 = [claimBy("member-1", 0)];
  const r5 = await (async () => { try { await reserve(mkCtx(twoSlot, mine0)); return "returned"; }
    catch (e) { return e.message; } })();
  ok("reserve refuses the claim that fills the book with a single owner",
    /single owner/.test(r5) && !r5.includes(WALLET_SENTINEL));
  // the excess-capacity row AT THE COMMAND (the confirmation's point: the helper-level
  // case is not the command's behaviour): the FIRST reservation of a two-slot pool is a
  // single-owner claim with a free slot left, and it must sail through
  const r7 = await (async () => { try { await reserve(mkCtx(twoSlot, [])); return "returned"; }
    catch (e) { return e.message; } })();
  ok("the FIRST reservation of a multi-slot pool is admitted (one owner, capacity left)",
    r7.includes(WALLET_SENTINEL));

  const other0 = [claimBy("owner-2", 0)];
  const r6 = await (async () => { try { await reserve(mkCtx(twoSlot, other0)); return "returned"; }
    catch (e) { return e.message; } })();
  ok("a SECOND owner filling the book is admitted (the pool becomes completable)",
    r6.includes(WALLET_SENTINEL));

  // the MUTABLE-POOL operator binding at the command level (pass 9, major 2): a
  // foreign-owned forming pool must be refused at admission, since completion refuses
  // it outright. Driven on v7, chosen because the guard is gated on
  // `!hasImmutablePool()` and so covers every mutable-pool ledger identically; the
  // cases are named for that capability rather than for one version (artifact check).
  {
    const prev = process.env.LEDGER;
    process.env.LEDGER = "v7"; // a mutable-pool ledger with a slot book
    const mutablePool = { nodeType: "regular", status: "forming",
      slotDuffs: 50000000000, slotCount: 2, operatorFeeBps: 2000 };
    const ctxWith = (poolOwner, contractOwner) => ({
      ...mkCtx(mutablePool, []),
      client: { platform: {
        documents: { get: async () => [] },
        contracts: { get: async () => ({ getOwnerId: () => ({ toString: () => contractOwner }) }) },
      }, getWalletAccount: async () => { throw new Error(WALLET_SENTINEL); } },
      getPool: async () => ({ toObject: () => mutablePool, getId: () => POOL_ID,
        getOwnerId: () => ({ toString: () => poolOwner }) }),
    });
    const bad = await (async () => { try { await reserve(ctxWith("stranger", "operator")); return "returned"; }
      catch (e) { return e.message; } })();
    ok("reserve refuses a mutable-pool pool owned by someone other than the contract operator",
      /not the contract operator/.test(bad) && !bad.includes(WALLET_SENTINEL));
    const good = await (async () => { try { await reserve(ctxWith("operator", "operator")); return "returned"; }
      catch (e) { return e.message; } })();
    ok("reserve admits a mutable-pool pool owned by the contract operator",
      good.includes(WALLET_SENTINEL));
    if (prev === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev;
  }

  // ---- the PLEDGE path's command-level coverage (pass 7 fold-2 re-confirmation) ----
  // pledge is the exact-fill admission path and refuses slot-book ledgers outright, so
  // these cases run it as a v5-style ledger: the pledge that COMPLETES the fill with a
  // single distinct owner is refused, and the one that completes it with a second owner
  // proceeds. Same guard, other caller.
  const pledge = require("./commands/pledge.cjs");
  const IDENT_SENTINEL = "REACHED_IDENTITY_STEP";
  const joinBy = (owner, duffs) => ({
    toObject: () => ({ kind: "join", amountDuffs: duffs }),
    getOwnerId: () => ({ toString: () => owner }),
    getId: () => ({ toString: () => `req-${owner}` }),
  });
  const pledgeCtx = (joins, amount) => ({
    client: { platform: { documents: { get: async () => [] },
      identities: { get: async () => { throw new Error(IDENT_SENTINEL); } } } },
    env: { CONTRACT_V5_ID: CONTRACT }, args: [POOL_ID, amount], cmd: "pledge", who: "F1",
    whoIdKey: "FUNDER_ID", DASHfmt: (v) => String(v), short: (s) => s, Identifier,
    Dash: { Core: { Script: { buildPublicKeyHashOut: () => ({ toBuffer: () => Buffer.alloc(25) }) } } },
    fetchAll: async () => joins,
    updateEnvKey: () => {}, activeContractId: () => CONTRACT, activeCastId: () => null,
    isV3: () => true, isV5: () => true, isV6: () => false,
    hasJoinProvenance: () => true, hasMemberRewardScript: () => true,
    journal, journalContract: CONTRACT,
    getPool: async () => ({ toObject: () => ({ nodeType: "regular", status: "forming" }),
      getId: () => ({ toString: () => POOL_ID, toBuffer: () => Buffer.alloc(32, 9) }) }),
    myShares: async () => [], myRequests: async () => [], isMyAccrual: () => false,
    myAccruals: async () => [], requestExists: async () => true,
    earnedRewardsBig: async () => 0n, autopayKeyOf: () => "A", watchKeyOf: () => "W",
    depositOwnFunds: async () => null, runAutopaySweep: async () => "idle",
    myId: "member-1",
  });
  const prevLedger = process.env.LEDGER;
  process.env.LEDGER = "v5";
  const runPledge = async (joins, amount) => {
    try { await pledge(pledgeCtx(joins, amount)); return "returned"; }
    catch (e) { return e.message; }
  };
  const p1 = await runPledge([joinBy("member-1", "50000000000")], "50000000000");
  ok("pledge refuses the pledge that completes the fill with a single owner",
    /single owner/.test(p1) && !p1.includes(IDENT_SENTINEL));
  const p2 = await runPledge([joinBy("owner-2", "50000000000")], "50000000000");
  ok("pledge admits the pledge that completes the fill with a SECOND owner",
    p2.includes(IDENT_SENTINEL));
  const p3 = await runPledge([joinBy("member-1", "20000000000")], "30000000000");
  ok("pledge admits a partial fill by a single owner (capacity remains)",
    p3.includes(IDENT_SENTINEL));
  // the MAXIMUM on the exact-fill path (pass-7 packet wave, review major 1): pledge had
  // the minimum but not the maximum, so a ninth distinct owner could pledge and strand
  // the pool at completion's 1..8 aggregate check
  const eightPledgers = Array.from({ length: 8 }, (_, i) => joinBy(`owner-${i + 1}`, "10000000000"));
  const p4 = await runPledge(eightPledgers, "20000000000");
  ok("pledge refuses a NINTH distinct owner on the exact-fill path",
    /distinct owners/.test(p4) && !p4.includes(IDENT_SENTINEL));
  const p5 = await runPledge(
    [joinBy("member-1", "10000000000"), ...Array.from({ length: 7 }, (_, i) => joinBy(`owner-${i + 2}`, "10000000000"))],
    "20000000000");
  ok("an existing pledger adding more is admitted (eight owners, not nine)",
    p5.includes(IDENT_SENTINEL));
  if (prevLedger === undefined) delete process.env.LEDGER; else process.env.LEDGER = prevLedger;

  console.log(`reserveAdmissionTest: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
