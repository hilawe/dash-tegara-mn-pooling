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
    // the stub pool now carries an owner, because reserve supplies both document owners
    // to the classifier (Request 3, duty 6 SUPPLY)
    getPool: async () => ({ toObject: () => po, getId: () => POOL_ID,
      getOwnerId: () => ({ toString: () => "operator" }) }),
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

  // the POSITIVE EVO row (EvoNodes E1-2): a coherent evo pool, 2 x 2000 DASH against
  // the evo target, REACHES THE CLAIMS FETCH through the same command (the sentinel is
  // what this observes; persistence is the harness's driven round's subject); until
  // this row evo appeared in this suite only as the value that must be refused
  const coherentEvo = { slotIndex: 0, nodeType: "evo", operatorFeeBps: 2000,
    targetDuffs: 400000000000, slotDuffs: 200000000000, slotCount: 2 };
  const rEvo = await run(coherentEvo);
  ok("reserve passes a coherent EVO pool through to the claims fetch",
    rEvo.includes(SENTINEL));

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
  // ENV-INDEPENDENT (a confirmation pass): the member setting demo in their
  // OWN environment used to buy this admission while the operator's completion, reading
  // its own environment, refuses the one-owner manifest; this pins that the FORMER demo
  // opt-out no longer admits (the value the old code read is the value set here)
  {
    const prevDemo = process.env.FORMATION_ALLOW_UNVERIFIED;
    process.env.FORMATION_ALLOW_UNVERIFIED = "demo";
    const rd = await (async () => { try { await reserve(mkCtx(twoSlot, mine0)); return "returned"; }
      catch (e) { return e.message; } })();
    ok("reserve still refuses the book-closing single-owner claim with the member's demo env set",
      /single owner/.test(rd) && !rd.includes(WALLET_SENTINEL));
    if (prevDemo === undefined) delete process.env.FORMATION_ALLOW_UNVERIFIED;
    else process.env.FORMATION_ALLOW_UNVERIFIED = prevDemo;
  }
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
    // the fixture carries the forming-namespace proTxHash every real mutable-ledger pool
    // has from creation (closing confirm-pass: the earlier hash-less fixture classified
    // UNDETERMINED and was silently admitted through the suite-wide participate
    // instruction, so these cases were not pinning the FORMING admission they named)
    const mutablePool = { nodeType: "regular", status: "forming",
      proTxHash: Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 9)]),
      slotDuffs: 50000000000, slotCount: 2, operatorFeeBps: 2000 };
    const ctxWith = (poolOwner, contractOwner) => ({
      ...mkCtx(mutablePool, []),
      client: { platform: {
        // the v7 contract HAS NO completionReceipt type, and the real lookup fails on an
        // absent type rather than returning an empty page (closing confirm-pass, F1: a
        // stub returning [] for every type hid an unconditional receipt query that broke
        // reserve and slots on v6/v7 outright), so any receipt query here is the defect
        documents: { get: async (type) => {
          throw new Error(`no such document type ${type} on this contract`); } },
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
  const pledgeCtx = (joins, amount, poolOwner = "operator", poolExtra = {}) => ({
    client: { platform: { documents: { get: async () => [] },
      contracts: { get: async () => ({ getOwnerId: () => ({ toString: () => "operator" }) }) },
      identities: { get: async () => { throw new Error(IDENT_SENTINEL); } } } },
    env: { CONTRACT_V5_ID: CONTRACT }, args: [POOL_ID, amount], cmd: "pledge", who: "F1",
    whoIdKey: "FUNDER_ID", DASHfmt: (v) => String(v), short: (s) => s, Identifier,
    Dash: { Core: { Script: { buildPublicKeyHashOut: () => ({ toBuffer: () => Buffer.alloc(25) }) } } },
    fetchAll: async () => joins,
    updateEnvKey: () => {}, activeContractId: () => CONTRACT, activeCastId: () => null,
    isV3: () => true, isV5: () => true, isV6: () => false,
    hasJoinProvenance: () => true, hasMemberRewardScript: () => true,
    journal, journalContract: CONTRACT,
    // a real v5 pool always carries proTxHash (required from v1); the forming-namespace
    // value here is what the review D-1 conjunct reads
    getPool: async () => ({ toObject: () => ({ nodeType: "regular", status: "forming",
      proTxHash: Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 5)]), ...poolExtra }),
      getOwnerId: () => ({ toString: () => poolOwner }),
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
  // ENV-INDEPENDENT (a confirmation pass): same rule as reserve's demo case
  {
    const prevDemo = process.env.FORMATION_ALLOW_UNVERIFIED;
    process.env.FORMATION_ALLOW_UNVERIFIED = "demo";
    const p1d = await runPledge([joinBy("member-1", "50000000000")], "50000000000");
    ok("pledge still refuses the single-owner exact fill with the member's demo env set",
      /single owner/.test(p1d) && !p1d.includes(IDENT_SENTINEL));
    if (prevDemo === undefined) delete process.env.FORMATION_ALLOW_UNVERIFIED;
    else process.env.FORMATION_ALLOW_UNVERIFIED = prevDemo;
  }
  const p2 = await runPledge([joinBy("owner-2", "50000000000")], "50000000000");
  ok("pledge admits the pledge that completes the fill with a SECOND owner",
    p2.includes(IDENT_SENTINEL));
  const p3 = await runPledge([joinBy("member-1", "20000000000")], "30000000000");
  ok("pledge admits a partial fill by a single owner (capacity remains)",
    p3.includes(IDENT_SENTINEL));
  // the MAXIMUM on the exact-fill path (pass 7, a review major finding 1): pledge had
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
  // ADMISSION MIRRORS COMPLETION'S HASH CHECK (a confirmation pass, D-1): complete's
  // nothing-to-do check reads the hash on every mutable ledger, so a v5 pool whose
  // proTxHash flipped to a real hash while status stayed "forming" must refuse here
  // too, or the pledge is admitted into a pool completion refuses as already LIVE
  // two DIFFERENT real hashes, so a constant-specific special case cannot satisfy both
  // (a review, finding 3), and the regex is the refusal's own words rather than
  // any message that happens to contain the word
  for (const [tag, hash] of [["07-bytes", Buffer.alloc(32, 7)],
    ["mixed-bytes", Buffer.concat([Buffer.alloc(16, 0xab), Buffer.alloc(16, 0x01)])]]) {
    const p6 = await (async () => { try {
      await pledge(pledgeCtx([joinBy("owner-2", "50000000000")], "50000000000",
        "operator", { proTxHash: hash }));
      return "returned"; } catch (e) { return e.message; } })();
    ok(`pledge refuses a v5 pool with a real proTxHash (${tag}) even while status says forming`,
      /pool is LIVE/.test(p6) && !p6.includes(IDENT_SENTINEL));
  }
  // and the pool's own word still closes the book on its own: a status past forming
  // refuses even while the hash is still in the forming namespace
  const p7 = await (async () => { try {
    await pledge(pledgeCtx([joinBy("owner-2", "50000000000")], "50000000000",
      "operator", { status: "live" }));
    return "returned"; } catch (e) { return e.message; } })();
  ok("pledge refuses a v5 pool whose status is live even while the hash still says forming",
    /pool is LIVE/.test(p7) && !p7.includes(IDENT_SENTINEL));
  // the pledge block above runs under its own ledger selection, so this block PINS v9
  // rather than inheriting whatever the previous case left (the first draft inherited,
  // and all four cases failed on a v6-shaped read of a v9 pool, which was the fixture
  // being wrong and the code being right, again)
  process.env.LEDGER = "v9";
  // THE CROSS-DOCUMENT RANGE CASE (pass 15, F2). The schema bounds slotNo per LEDGER and
  // cannot state that a claim's slotNo sits below its own pool's slotCount, so a
  // schema-valid foreign claim at slot 511 on a two-slot pool is representable. Reserve
  // used to COUNT such a claim: the owner and book-full preflights ran over the
  // unfiltered map, so a second member's reservation passed every admission guard toward
  // a book completion later refuses. Driven through the real command, exactly like every
  // case above.
  const twoSlotB = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
    targetDuffs: 100000000000, slotDuffs: 50000000000, slotCount: 2 };
  const r8 = await (async () => { try {
    await reserve(mkCtx(twoSlotB, [claimBy("owner-2", 511)])); return "returned"; }
    catch (e) { return e.message; } })();
  ok("reserve REFUSES a book holding an out-of-range foreign claim, before any admission",
    /outside this pool's range 0\.\.1/.test(r8) && !r8.includes(WALLET_SENTINEL));
  const r9 = await (async () => { try {
    await reserve(mkCtx(twoSlotB, [claimBy("owner-2", -1)])); return "returned"; }
    catch (e) { return e.message; } })();
  ok("...and a negative foreign slotNo is refused the same way",
    /outside this pool's range/.test(r9) && !r9.includes(WALLET_SENTINEL));
  const r10 = await (async () => { try {
    await reserve(mkCtx(twoSlotB, [claimBy("owner-2", "not-a-number")])); return "returned"; }
    catch (e) { return e.message; } })();
  ok("...and a non-integer foreign slotNo is refused, not coerced into a count",
    /outside this pool's range/.test(r10) && !r10.includes(WALLET_SENTINEL));
  const r10b = await (async () => { try {
    await reserve(mkCtx(twoSlotB, [claimBy("owner-2", 2)])); return "returned"; }
    catch (e) { return e.message; } })();
  ok("...and slot === slotCount (one past the boundary) is refused",
    /outside this pool's range/.test(r10b) && !r10b.includes(WALLET_SENTINEL));
  // and the legal boundary claim still counts normally. On a FOUR-slot pool the foreign
  // claim sits at slot 3, the exact boundary of 0..3, and the member reserves slot 1
  // (the harness convention reserves slot = number of claims, so the two cannot collide
  // here; the first draft put the boundary claim at the very slot that convention picks,
  // and failed on the collision refusal, the fixture being wrong and the code right).
  const fourSlot = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
    targetDuffs: 100000000000, slotDuffs: 25000000000, slotCount: 4 };
  const r11 = await (async () => { try {
    await reserve(mkCtx(fourSlot, [claimBy("owner-2", 3)])); return "returned"; }
    catch (e) { return e.message; } })();
  ok("a boundary-legal foreign claim (last slot) still admits the second member",
    r11.includes(WALLET_SENTINEL));

  // ---- FA2 (closing wave): the v8 branch used to decide admission from status/hash alone
  //      and never queried the completion receipt, so a member could reserve into a pool
  //      that already carried one, a claim completion refuses. Both ledgers now route
  //      through the same classifier and verdict. These cases run the COMMAND on v8. ----
  process.env.LEDGER = "v8";
  const FORMING_HASH = Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 7)]);
  const REAL_HASH8 = Buffer.alloc(32, 0xab);
  const v8forming = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
    status: "forming", proTxHash: FORMING_HASH, slotDuffs: 50000000000, slotCount: 2 };
  const v8flipped = { ...v8forming, status: "live", proTxHash: REAL_HASH8 };
  // a receipt document the stub returns: it names THIS pool (the real lookup has an
  // equality predicate on poolId, so a mismatched document is not one the query could
  // return, checker on this fold) and does not verify (that is the point: presence must
  // now reach the verdict, and a present-but-unverifying receipt is a contradiction,
  // never ignored and never read as completion)
  const stubReceipt = { toObject: () => ({
    poolId: Buffer.from(Identifier.from(POOL_ID).toBuffer()), proTxHash: REAL_HASH8 }),
    getOwnerId: () => ({ toString: () => "operator" }) };
  const mkCtx8 = (po, { receipt = null } = {}) => {
    const ctx = mkCtx(po);
    ctx.client = { platform: {
      documents: { get: async () => (receipt ? [receipt] : []) },
      contracts: { get: async () => ({ getOwnerId: () => ({ toString: () => "operator" }) }) },
    }, getWalletAccount: async () => { throw new Error(WALLET_SENTINEL); } };
    return ctx;
  };
  const run8 = async (po, opts) => {
    try { await reserve(mkCtx8(po, opts)); return "returned"; } catch (e) { return e.message; }
  };
  const r12 = await run8(v8forming);
  ok("v8: a forming receipt-less pool still admits (reaches the claims fetch)",
    r12.includes(SENTINEL));
  const r13 = await run8(v8forming, { receipt: stubReceipt });
  ok("v8: a forming pool with a completion receipt PRESENT is refused, never admitted",
    !r13.includes(SENTINEL) && !r13.includes(WALLET_SENTINEL) && /receipt/i.test(r13));
  // the instruction is set EXPLICITLY here rather than relied on from the suite header
  // (checker on this fold): this case's whole claim is that a matching instruction does
  // NOT override an answered state, so the instruction's presence must be arranged where
  // the claim is made
  process.env.TEGARA_PARTICIPATE = POOL_ID;
  const r14 = await run8(v8flipped);
  ok("v8: a flipped pool is refused as in flight, and the participate instruction does not override",
    !r14.includes(SENTINEL) && !r14.includes(WALLET_SENTINEL) && /in flight/i.test(r14));
  const v8hashOnly = { ...v8forming };
  delete v8hashOnly.status;
  const r15 = await run8(v8hashOnly);
  ok("v8: a status-less pool still admits off the forming hash (the old arm is preserved)",
    r15.includes(SENTINEL));

  if (prevLedger === undefined) delete process.env.LEDGER; else process.env.LEDGER = prevLedger;

  // A BOOK WIDER THAN COMPLETION'S SCAN never completes (a confirmation pass):
  // the capacity rule is one shared constant, and admission refuses what completion can
  // never enumerate, on both the derived (v6) and pool-data (v7) widths, while the
  // 625-slot book inside the scan window stays admitted
  {
    // UNDER THE REAL v7 LEDGER (a confirmation pass, E-2): these are v7 forming pools
    // and must run under the v7 capability table. The suite's top-level v9 selection
    // made the old fixtures unproducible in the selected contract (the v9 pool caps
    // slotCount at 512, requires targetDuffs and carries no status or proTxHash) while
    // the stubbed isV7 still routed the pool-data width path, so the boundary the block
    // claims was never established on a pool the v7 contract can hold. A v7 pool carries NO
    // targetDuffs (that field arrives at v9); the coherence check binds the slot-book
    // product to the tier target instead. Env-swapped, ledgerVersion() reads dynamically.
    const prevWidth = process.env.LEDGER;
    process.env.LEDGER = "v7";
    const forming7 = () => Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 7)]);
    // a soundness-review finding moved these capacity fixtures to the EVO tier: on regular, the covenant's
    // 100 DASH share floor now refuses every book wider than 10 slots BEFORE the
    // capacity rule can speak, so evo (whose floor is deliberately undefined upstream)
    // is the only tier where the capacity boundary still has a live surface.
    const wide7 = { slotIndex: 0, nodeType: "evo", operatorFeeBps: 2000,
      status: "forming", proTxHash: forming7(),
      slotDuffs: 400000000, slotCount: 1000 };
    const rWide = await run(wide7);
    ok("a coherent 1000-slot v7 book is refused at the capacity rule (completion cannot scan it)",
      /wider than the 640-claim scan/.test(rWide) && !rWide.includes(SENTINEL));
    // a soundness-review finding on the admission surface: the old 625-slot REGULAR fixture (1.6 DASH slots)
    // is now the floor-refusal case, and the refusal names the share floor, not capacity
    const subFloor7 = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
      status: "forming", proTxHash: forming7(),
      slotDuffs: 160000000, slotCount: 625 };
    const rSubFloor = await run(subFloor7);
    ok("a soundness-review finding: a sub-floor regular book is refused at the share floor",
      /minimum share/.test(rSubFloor) && !rSubFloor.includes(SENTINEL));
    const ok625 = { slotIndex: 0, nodeType: "evo", operatorFeeBps: 2000,
      status: "forming", proTxHash: forming7(),
      slotDuffs: 640000000, slotCount: 625 };
    const r625 = await run(ok625);
    ok("the 625-slot book inside the scan window is still admitted past the capacity rule",
      r625.includes(SENTINEL));
    // the BOUNDARY (checker on this fold): 640 is the last enumerable width and is
    // admitted; 641 exactly is arithmetically unconstructible as a coherent book
    // (prime, does not divide the tier), so the nearest reachable wider book, 800, pins
    // the refusal side of the boundary
    const at640 = { slotIndex: 0, nodeType: "evo", operatorFeeBps: 2000,
      status: "forming", proTxHash: forming7(),
      slotDuffs: 625000000, slotCount: 640 };
    const r640 = await run(at640);
    ok("a 640-slot book, exactly the scan ceiling, is admitted", r640.includes(SENTINEL));
    const at800 = { slotIndex: 0, nodeType: "evo", operatorFeeBps: 2000,
      status: "forming", proTxHash: forming7(),
      slotDuffs: 500000000, slotCount: 800 };
    const r800 = await run(at800);
    ok("an 800-slot book, the nearest coherent width past the ceiling, is refused",
      /wider than the 640-claim scan/.test(r800) && !r800.includes(SENTINEL));
    // MOCK-MODEL CONSISTENCY, pinned per fixture (a review, finding 2 narrowed
    // this claim): validatePoolProps is the mock's MODEL of the published v7 pool
    // schema, so these establish the fixtures conform to the model the rest of the
    // suite enforces, not the published contract itself; the model's own fidelity is
    // the round brief's question E surface, exercised by the crash harness's shape-gate
    // cases. Under the restored top-level v9 the same gate refuses every fixture
    // (missing targetDuffs at least), which is the E-2 mutation these checks make
    // visible, one named fixture at a time.
    const { validatePoolProps } = require("./formationMockDash.cjs");
    for (const [name, po] of [["wide7", wide7], ["ok625", ok625], ["at640", at640], ["at800", at800]]) {
      ok(`width fixture ${name} conforms to the mock's model of the published v7 pool schema`,
        (() => { try { validatePoolProps(po); return true; } catch { return false; } })());
    }
    const prev = process.env.LEDGER;
    process.env.LEDGER = "v6";
    const prevSlot = process.env.SLOT_DUFFS;
    process.env.SLOT_DUFFS = "400000000"; // 4 DASH derives a 1000-slot EVO book (a soundness-review finding)
    const v6pool = { nodeType: "evo", status: "forming",
      proTxHash: Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 9)]), operatorFeeBps: 2000 };
    const rV6 = await (async () => { try {
      await reserve({ ...mkCtx(v6pool, []), isV7: () => false,
        client: { platform: {
          documents: { get: async (type) => { throw new Error(`no such document type ${type}`); } },
          contracts: { get: async () => ({ getOwnerId: () => ({ toString: () => "operator" }) }) },
        }, getWalletAccount: async () => { throw new Error(WALLET_SENTINEL); } } });
      return "returned"; } catch (e) { return e.message; } })();
    ok("v6: a SLOT_DUFFS deriving a 1000-slot book is refused at the same capacity rule",
      /wider than the 640-claim scan/.test(rV6) && /SLOT_DUFFS/.test(rV6) && !rV6.includes(WALLET_SENTINEL));
    // a soundness-review finding through the v6 CALL SITE (external artifact check, finding 1): the unit
    // tests of the shared guard cannot show this branch invokes it, so drive it. A
    // 50 DASH SLOT_DUFFS on a REGULAR v6 pool is refused at the share floor.
    process.env.SLOT_DUFFS = "5000000000"; // 50 DASH, below the regular floor
    const v6floorPool = { nodeType: "regular", status: "forming",
      proTxHash: Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 9)]), operatorFeeBps: 2000 };
    const rV6floor = await (async () => { try {
      await reserve({ ...mkCtx(v6floorPool, []), isV7: () => false,
        client: { platform: {
          documents: { get: async (type) => { throw new Error(`no such document type ${type}`); } },
          contracts: { get: async () => ({ getOwnerId: () => ({ toString: () => "operator" }) }) },
        }, getWalletAccount: async () => { throw new Error(WALLET_SENTINEL); } } });
      return "returned"; } catch (e) { return e.message; } })();
    ok("a soundness-review finding: the v6 branch refuses a sub-floor SLOT_DUFFS at the share floor",
      /minimum share/.test(rV6floor) && !rV6floor.includes(WALLET_SENTINEL));
    if (prevSlot === undefined) delete process.env.SLOT_DUFFS; else process.env.SLOT_DUFFS = prevSlot;
    if (prev === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev;
    if (prevWidth === undefined) delete process.env.LEDGER; else process.env.LEDGER = prevWidth;
  }

  // the PLEDGE-side operator binding (a confirmation pass, D-1): completion's final
  // pool replacement is operator-signed on EVERY mutable ledger while the check was
  // v8-gated, so pledge admitted a foreign-owned pool the operator can never complete
  {
    // env-swapped to a MUTABLE ledger (the suite's top-level LEDGER=v9 makes the real
    // envStore report immutable, where the binding correctly defers to consensus
    // owner-only creation and these cases would not exercise it)
    const prev = process.env.LEDGER;
    process.env.LEDGER = "v5";
    const r = await (async () => { try {
      await pledge(pledgeCtx([joinBy("other", 50000000000n)], "25000000000", "stranger"));
      return "returned"; } catch (e) { return e.message; } })();
    ok("pledge refuses a mutable-pool pool owned by someone other than the contract operator",
      /not the contract operator/.test(r) && !r.includes(IDENT_SENTINEL));
    const r2 = await (async () => { try {
      await pledge(pledgeCtx([joinBy("other", 50000000000n)], "25000000000"));
      return "returned"; } catch (e) { return e.message; } })();
    ok("pledge admits the operator-owned pool through to the identity step",
      r2.includes(IDENT_SENTINEL));
    if (prev === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev;
  }

  // the v6 PERMANENT-CLAIM SIZE coherence (a confirmation pass, D-2): v6 claims carry
  // their own slotDuffs, are immutable and undeletable, and completion requires one
  // uniform size, so admission must refuse a locally configured size that mismatches the
  // existing book rather than write a wedge
  {
    const prev = process.env.LEDGER;
    process.env.LEDGER = "v6";
    const prevSlot = process.env.SLOT_DUFFS;
    process.env.SLOT_DUFFS = "10000000000";
    const v6pool = { nodeType: "regular", status: "forming",
      proTxHash: Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 9)]), operatorFeeBps: 2000 };
    const v6claim = (owner, slotNo, slotDuffs) => ({ toObject: () => ({ slotNo, slotDuffs }),
      getOwnerId: () => ({ toString: () => owner }) });
    const v6ctx = (claims) => ({ ...mkCtx(v6pool, claims), isV7: () => false,
      client: { platform: {
        documents: { get: async (type) => { throw new Error(`no such document type ${type}`); } },
        contracts: { get: async () => ({ getOwnerId: () => ({ toString: () => "operator" }) }) },
      }, getWalletAccount: async () => { throw new Error(WALLET_SENTINEL); } } });
    const rMis = await (async () => { try { await reserve(v6ctx([v6claim("owner-2", 0, 5000000000)]));
      return "returned"; } catch (e) { return e.message; } })();
    ok("v6: a locally configured size mismatching the existing PERMANENT claim is refused",
      /PERMANENT claim sized 5000000000/.test(rMis) && !rMis.includes(WALLET_SENTINEL));
    const rOk = await (async () => { try { await reserve(v6ctx([v6claim("owner-2", 0, 10000000000)]));
      return "returned"; } catch (e) { return e.message; } })();
    ok("v6: a matching size passes the coherence check through to the wallet step",
      rOk.includes(WALLET_SENTINEL));
    if (prevSlot === undefined) delete process.env.SLOT_DUFFS; else process.env.SLOT_DUFFS = prevSlot;
    if (prev === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev;
  }

  console.log(`reserveAdmissionTest: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
