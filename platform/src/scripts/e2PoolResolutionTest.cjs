/**
 * THE POOL RESOLUTION'S DECISIONS, driven offline.
 *
 * WHY THIS EXISTS. An independent review removed the single-document cardinality check from the
 * runner's inline proved fetch and watched the whole dependency battery stay green, because that
 * battery receives the resolver as an opaque injected function and never asks what it refuses.
 * Every refusal this module owns is now reachable from a case.
 *
 * HOW EXPECTATIONS ARE FORMED IN THIS FILE, which is the rule three review occasions cost to
 * learn: NOTHING an assertion expects may be read back from the thing it is judging. Every
 * fixture below is built from constants declared at the top, every expected value is computed
 * from those same constants, and no assertion asks the module what it produced in order to decide
 * what it should have produced. Where a real component computes something (the allocation hash),
 * the test computes it the same way from its own inputs rather than copying the module's answer.
 *
 * WHAT IS STOOD IN FOR. The proved query, the identity lookup, the journal, the identifier
 * generator and the pair checker are fakes with the real call shapes. The pair CHECKER is a
 * shared component with its own test; what this file drives is the module's REFUSAL on its
 * verdict, which is the decision the module owns.
 *
 * THE CONTRARY CONTROL IS THE MUTATION BATTERY at the bottom. Each mutation removes exactly one
 * refusal from the module's source and a named probe must observe the difference.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const CLEAN = require("./e2PoolResolution.cjs");
const formationCore = require("./formationCore.cjs");
const entitlementCalc = require("./entitlementCalc.cjs");

const { runnerSource, skipNote } = require("./runnerSource.cjs");
let passed = 0, failed = 0, skipped = 0;
const ok = (name, cond) => { if (cond) { passed++; } else { failed++; console.error("FAIL:", name); } };
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

// ---- THE CONSTANTS EVERY FIXTURE AND EVERY EXPECTATION IS BUILT FROM ----
const h32 = (f) => f.repeat(64 / f.length);
const POOL = h32("ab");
const OTHER_POOL = h32("cd");
const CONTRACT = h32("11");
const WRITER = h32("f0");
const INCOME = h32("22");      // the pool document's OWNER, which becomes the income identity
const OWNER_A = h32("71");
const OWNER_B = h32("72");
const BPS_A = 6000, BPS_B = 4000;
const CHAIN = "resolution-chain-pin";
const PROTOCOL = 12;
// THE REAL SCHEMA CEILING, imported rather than restated, so the fixture cannot drift from the
// value production uses.
const CEILING = entitlementCalc.SCHEMA_CREDIT_CEILING;
const RUN_ALLOC_HASH = h32("7a");
const EPOCH = 5;
const GROSS = "1000", FEE = "10", MEMBERS = 2;

// base58 here is the identity function over hex, so the test can read every identifier it builds
const b58Of = (hex) => `b58:${hex}`;
const idHex = (v) => {
  const s = typeof v === "string" ? v : String(v);
  return s.startsWith("b58:") ? s.slice(4) : s;
};

// THE ALLOCATION ROWS, and the hash computed HERE from them. The module recomputes the hash with
// the same shared function; the test does not copy the module's answer back as its expectation.
const allocationRows = (owners = [[b58Of(OWNER_A), "500", BPS_A, "sc"], [b58Of(OWNER_B), "500", BPS_B, "sc"]]) =>
  Buffer.from(JSON.stringify(["tegara-completion-allocation", 1, CONTRACT, POOL, "target", owners]), "utf8");
const hashOfRows = (rows) => formationCore.allocationHash(Buffer.from(rows)).toString("hex");

const mkDoc = (idHexValue, ownerHexValue, props) => ({
  id: b58Of(idHexValue),
  getOwnerId: () => b58Of(ownerHexValue),
  getProperties: () => props,
});
// THE POOL AND THE RECEIPT ARE DISTINGUISHABLE IN EVERY RESPECT THE MODULE TOUCHES: different
// identifiers, different OWNERS, and disjoint property sets. A review swapped the two in the pair
// check's arguments and supplied the pool's owner as both owners, and neither showed, because the
// fixtures were interchangeable and the checker ignored what it was handed.
const RECEIPT_OWNER = h32("33");
const poolDoc = (over = {}) => mkDoc(over.id || POOL, over.owner || INCOME,
  { nodeType: over.nodeType === undefined ? "evo" : over.nodeType, marker: "pool-properties" });
const receiptDoc = (over = {}) => {
  const rows = over.rows || allocationRows();
  return mkDoc(h32("99"), over.owner || RECEIPT_OWNER, {
    allocationRows: rows,
    allocationHash: Buffer.from(over.storedHash || hashOfRows(rows), "hex"),
    marker: "receipt-properties",
  });
};

// THE DEFAULT PAIR CHECKER READS WHAT IT IS HANDED. A fake returning a fixed verdict cannot tell
// a caller that passed the right arguments from one that swapped them, which is how the swap
// survived. This one refuses anything but the exact call the module is supposed to make.
const strictPairCheck = (a) => {
  if (!a || a.contractId !== CONTRACT) return { ok: false, reason: "wrong contract" };
  if (a.poolId !== b58Of(POOL)) return { ok: false, reason: "wrong pool identifier" };
  if (!a.pool || a.pool.marker !== "pool-properties") return { ok: false, reason: "the pool slot did not carry the pool's properties" };
  if (!a.receipt || a.receipt.marker !== "receipt-properties") return { ok: false, reason: "the receipt slot did not carry the receipt's properties" };
  if (a.poolOwnerId.toString("hex") !== INCOME) return { ok: false, reason: "wrong pool owner" };
  if (a.receiptOwnerId.toString("hex") !== RECEIPT_OWNER) return { ok: false, reason: "wrong receipt owner" };
  return { ok: true };
};

// THE PROVED QUERY ANSWERS THE QUESTION IT WAS ASKED, and refuses one it was not. A review
// queried the receipt under the writer's identifier and the old fake answered anyway, because it
// keyed on the document TYPE and never read the clause.
const whereMatches = (type, where) => {
  if (type === "pool") {
    return Array.isArray(where) && where.length === 1 && where[0][0] === "$id"
      && where[0][2] === b58Of(POOL);
  }
  return Array.isArray(where) && where.length === 1 && where[0][0] === "poolId"
    && Buffer.isBuffer(where[0][2]) && where[0][2].toString("hex") === POOL;
};

// THE JOURNALS ARE PER POOL AND MUTABLE. The old fake ignored the pool it was handed and returned
// one static epoch, so reading another pool's journal, caching it at resolution, and truncating
// the run were all invisible.
const journalFor = (epochs, configuredStart = EPOCH) => ({ configuredStartEpoch: configuredStart, epochs });
// THE EPOCH RECORD IS THE SHAPE `runFromJournal` REALLY EMITS, field for field, including the
// derived `distributableCredits`. A fixture shaped differently from the thing it stands in for
// would let the module pass here and refuse in production, which is the opposite of evidence.
const runEpochs = (over = {}) => {
  const gross = over.gross || GROSS;
  const fee = over.fee || FEE;
  return [{ number: EPOCH,
    distributableCredits: String(BigInt(gross) - BigInt(fee)),
    allocationHash: RUN_ALLOC_HASH,
    memberCount: over.members === undefined ? MEMBERS : over.members,
    grossCredits: gross, feeCredits: fee }];
};

// THE EXPECTED ROWS, DERIVED HERE from this file's own constants rather than read back from the
// module. The distributable amount is gross minus fee; each owner takes its declared share of it;
// the accrual identity is what the type-sensitive generator above produces for a platformAccrual.
const DISTRIBUTABLE = BigInt(GROSS) - BigInt(FEE);
const shareOf = (bps) => String(DISTRIBUTABLE * BigInt(bps) / 10000n);
const EXPECTED_ROWS = [
  { accrualId: `platformAccrual:${POOL.slice(0, 4)}:${EPOCH}:${OWNER_A}`,
    amountCredits: shareOf(BPS_A), recipientId: OWNER_A },
  { accrualId: `platformAccrual:${POOL.slice(0, 4)}:${EPOCH}:${OWNER_B}`,
    amountCredits: shareOf(BPS_B), recipientId: OWNER_B },
];

const mkEnv = (over = {}) => {
  const queries = [];
  const journalReads = [];
  // the store this run's journals live in, keyed by POOL IDENTIFIER and mutable between calls
  const journals = new Map();
  journals.set(POOL, journalFor(over.epochs || runEpochs(), over.configuredStart));
  if (over.journals) for (const [k, v] of over.journals) journals.set(k, v);
  const env = {
    provedQuery: async (type, where, label) => {
      queries.push({ type, where, label });
      if (over.answer) return over.answer(type, where, label);
      if (!whereMatches(type, where)) return []; // asked about something else: nothing is served
      return [type === "pool" ? poolDoc(over.pool || {}) : receiptDoc(over.receipt || {})];
    },
    contractId: CONTRACT,
    writerHex: WRITER,
    b58Of, idHex,
    encodingCeiling: over.encodingCeiling === undefined ? CEILING : over.encodingCeiling,
    openJournalFor: (pid) => {
      journalReads.push(pid);
      const j = journals.get(pid);
      if (!j) throw new Error(`no journal in this store for ${String(pid).slice(0, 12)}...`);
      return j;
    },
    runFromJournal: (read) => read.epochs,
    // the identifier generator is TYPE-SENSITIVE, so generating a header identity where an
    // accrual identity belongs is visible in the row
    docIdForIn: (poolId, epochIndex, type, subject) => ({ hex: `${type}:${poolId.slice(0, 4)}:${epochIndex}:${subject}` }),
    checkReceiptAgainstPool: over.pairCheck || strictPairCheck,
    ...over.env,
  };
  return { env, queries, journals, journalReads };
};

const main = async () => {
  // ================= 1. the environment contract =================
  for (const k of CLEAN.RESOLVE_ENV) {
    const { env } = mkEnv();
    delete env[k];
    throws(`a resolver missing env.${k} refuses by name`,
      () => CLEAN.makeResolveProvedPool(env), new RegExp(`needs env\\.${k}`));
  }
  throws("a resolver with no environment refuses",
    () => CLEAN.makeResolveProvedPool(null), /needs its environment/);
  throws("the proved fetch needs its query", () => CLEAN.makeProvedFetchOne({}), /needs provedQuery/);

  // ================= 2. cardinality =================
  {
    const one = CLEAN.makeProvedFetchOne({ provedQuery: async () => ["only"] });
    ok("exactly one document is returned", (await one("pool", [], "probe")) === "only");
    const none = CLEAN.makeProvedFetchOne({ provedQuery: async () => [] });
    await rejects("no document refuses rather than resolving nothing quietly",
      none("pool", [], "probe"), /expected exactly one document, found 0/);
    const two = CLEAN.makeProvedFetchOne({ provedQuery: async () => ["a", "b"] });
    await rejects("two documents refuse rather than choosing the first",
      two("pool", [], "probe"), /expected exactly one document, found 2/);
    const notList = CLEAN.makeProvedFetchOne({ provedQuery: async () => ({ nope: true }) });
    await rejects("an answer that is not a document list refuses",
      notList("pool", [], "probe"), /did not answer with a document list/);
  }

  // ================= 3. the subject asked for =================
  {
    const { env } = mkEnv({ pool: { id: OTHER_POOL } });
    await rejects("a proved read serving a DIFFERENT pool refuses rather than resolving it",
      CLEAN.makeResolveProvedPool(env)(POOL), /returned a different document/);
  }

  // ================= 4. the pair check's verdict =================
  {
    const { env } = mkEnv({ pairCheck: () => ({ ok: false, reason: "owner mismatch" }) });
    await rejects("a refused pair check stops the resolution, carrying its reason",
      CLEAN.makeResolveProvedPool(env)(POOL), /pair check refused: owner mismatch/);
    // and the checker is asked about THIS pool, with both owners
    const seen = [];
    const { env: env2 } = mkEnv({ pairCheck: (a) => { seen.push(a); return { ok: true }; } });
    await CLEAN.makeResolveProvedPool(env2)(POOL);
    ok("the pair check is asked about the pool that was requested, with each document in its own slot and each owner distinct",
      seen.length === 1 && seen[0].poolId === b58Of(POOL) && seen[0].contractId === CONTRACT
        && seen[0].pool.marker === "pool-properties"
        && seen[0].receipt.marker === "receipt-properties"
        && seen[0].poolOwnerId.toString("hex") === INCOME
        && seen[0].receiptOwnerId.toString("hex") === RECEIPT_OWNER);
  }

  // ================= 5. eligibility =================
  {
    for (const nodeType of ["regular", "", null]) {
      const { env } = mkEnv({ pool: { nodeType } });
      await rejects(`nodeType ${JSON.stringify(nodeType)} refuses the eligibility predicate`,
        CLEAN.makeResolveProvedPool(env)(POOL), /not "evo" \(the eligibility predicate\)/);
    }
  }

  // ================= 6. allocation integrity =================
  {
    const { env } = mkEnv({ receipt: { storedHash: h32("ee") } });
    await rejects("a stored allocation hash that differs from the recomputed one refuses",
      CLEAN.makeResolveProvedPool(env)(POOL), /differs from the receipt's/);
    // the matching case resolves, and the hash the module reports is the one the TEST computed
    const rows = allocationRows();
    const { env: env2 } = mkEnv({ receipt: { rows } });
    const r = await CLEAN.makeResolveProvedPool(env2)(POOL);
    ok("the resolution reports the allocation hash the test computed from its own rows",
      r.allocationHashHex === hashOfRows(rows));
  }

  // ================= 7. ownership =================
  {
    const { env } = mkEnv({ receipt: { rows: allocationRows([]) } });
    await rejects("an allocation with no owners refuses",
      CLEAN.makeResolveProvedPool(env)(POOL), /carries no owners/);
  }

  // ================= 8. what a resolution says =================
  {
    const { env } = mkEnv();
    const r = await CLEAN.makeResolveProvedPool(env)(POOL);
    ok("a resolution attests", r.resolved === true);
    ok("the writer identity is the configured one the test supplied", r.writerIdentity === WRITER);
    ok("the income identity is DERIVED from the pool document's own owner", r.incomeIdentity === INCOME);
    ok("the owners are the allocation's, with their own share values",
      r.owners.length === 2
        && r.owners[0].ownerB58 === b58Of(OWNER_A) && r.owners[0].bps === BPS_A
        && r.owners[1].ownerB58 === b58Of(OWNER_B) && r.owners[1].bps === BPS_B);
    ok("the two owners are distinguishable, so checking both is not checking one twice",
      r.owners[0].ownerB58 !== r.owners[1].ownerB58 && r.owners[0].bps !== r.owners[1].bps);
  }

  // ================= 9. entitlement rows and their refusals =================
  {
    const resolveWith = async (over = {}) => CLEAN.makeResolveProvedPool(mkEnv(over).env)(POOL);
    {
      const r = await resolveWith();
      await rejects("rows with NO numbers refuse an unquantified answer",
        (async () => r.entitlementsForEpoch(EPOCH, undefined))(), /refusing an unquantified answer/);
      await rejects("rows with no grossCredits refuse",
        (async () => r.entitlementsForEpoch(EPOCH, { feeCredits: FEE }))(), /refusing an unquantified answer/);
      await rejects("rows with no feeCredits refuse",
        (async () => r.entitlementsForEpoch(EPOCH, { grossCredits: GROSS }))(), /refusing an unquantified answer/);
      await rejects("an epoch outside the run its journal evidences refuses, naming the range",
        (async () => r.entitlementsForEpoch(EPOCH + 3, { grossCredits: GROSS, feeCredits: FEE }))(),
        /outside the run its journal evidences \(5\.\.5\)/);
      // DEFENCE IN DEPTH, stated because the module's comment must not claim to be the only
      // thing standing here. The mutation battery below removes this module's check and the
      // CALCULATION still refuses the same epoch by its own rule, so what this guard buys is an
      // earlier and more specific diagnostic, not the prevention itself.
      ok("the calculation refuses the same out-of-run epoch on its own, so this guard is a diagnostic layer rather than the sole prevention",
        /is outside this run/.test(entitlementCalc.buildCarryCapableEntitlements
          ? (() => { try { entitlementCalc.buildCarryCapableEntitlements({ incomeIdentity: INCOME,
              encodingCeiling: CEILING, configuredStart: EPOCH,
              allocation: [{ recipientId: OWNER_A, bps: 10000 }], epochs: runEpochs() }).rowsFor(EPOCH + 3);
              return "no refusal"; } catch (e) { return e.message; } })() : "unavailable"));
    }
    {
      const r = await resolveWith();
      await rejects("a gross that disagrees with the journaled run refuses rather than choosing one",
        (async () => r.entitlementsForEpoch(EPOCH, { grossCredits: "999", feeCredits: FEE }))(),
        /refusing rather than choosing one/);
      await rejects("a fee that disagrees with the journaled run refuses",
        (async () => r.entitlementsForEpoch(EPOCH, { grossCredits: GROSS, feeCredits: "11" }))(),
        /refusing rather than choosing one/);
      // THE CASE THE FIELD-BY-FIELD COMPARISON EXISTS FOR. 1000/10 and 1100/110 both derive to
      // 990, so a check on the derived amount alone would call two different headers the same.
      ok("the two headers in the field-by-field case really do derive to the same amount",
        Number(GROSS) - Number(FEE) === 1100 - 110);
      await rejects("a header agreeing on gross MINUS fee but on neither field refuses",
        (async () => r.entitlementsForEpoch(EPOCH, { grossCredits: "1100", feeCredits: "110" }))(),
        /refusing rather than choosing one/);
    }
    {
      const r = await resolveWith();
      await rejects("a memberCount that disagrees refuses",
        (async () => r.entitlementsForEpoch(EPOCH, { grossCredits: GROSS, feeCredits: FEE, memberCount: 9 }))(),
        /refusing rather than choosing one/);
      const rows = r.entitlementsForEpoch(EPOCH, { grossCredits: GROSS, feeCredits: FEE });
      ok("an absent memberCount is allowed, since the check is conditional by contract",
        Array.isArray(rows));
      // THE WHOLE ROW SET, COMPARED AGAINST AMOUNTS DERIVED HERE. Every assertion used to be an
      // `every` over whatever came back, which an EMPTY array satisfies, so a review returned one
      // row, no rows, and a flat "1" for every amount, and all three passed. The expectation is
      // now the complete set, and its amounts are computed from this file's own constants.
      ok("the rows are exactly the two the allocation owes, with the amounts this test derived and accrual identities of the right document type",
        JSON.stringify(rows) === JSON.stringify(EXPECTED_ROWS));
      ok("the two expected amounts are the distributable split by the declared shares, and they differ",
        EXPECTED_ROWS[0].amountCredits === "594" && EXPECTED_ROWS[1].amountCredits === "396"
          && BigInt(EXPECTED_ROWS[0].amountCredits) + BigInt(EXPECTED_ROWS[1].amountCredits)
             === BigInt(GROSS) - BigInt(FEE));
    }
  }

  // ================= 9b. the cases the row assertions could not reach =================
  {
    // THE MATCHING MEMBER COUNT SUCCEEDS. The condition had refusal cases and no equality case,
    // so replacing it with one that refuses whenever a count is supplied at all passed.
    const r = await CLEAN.makeResolveProvedPool(mkEnv().env)(POOL);
    const rows = r.entitlementsForEpoch(EPOCH, { grossCredits: GROSS, feeCredits: FEE, memberCount: MEMBERS });
    ok("a memberCount that AGREES with the journaled run is accepted and the rows come back",
      JSON.stringify(rows) === JSON.stringify(EXPECTED_ROWS));
  }
  {
    // THE POSITIVE-ROW FILTER, reached by a run that distributes nothing. Every row is then zero
    // and the contract says none of them is returned.
    const { env } = mkEnv({ epochs: runEpochs({ gross: "1000", fee: "1000" }) });
    const r = await CLEAN.makeResolveProvedPool(env)(POOL);
    const rows = r.entitlementsForEpoch(EPOCH, { grossCredits: "1000", feeCredits: "1000" });
    ok("a run distributing nothing returns NO rows rather than rows owing zero",
      Array.isArray(rows) && rows.length === 0);
  }
  {
    // THE INCOME IDENTITY IS THE POOL DOCUMENT'S OWNER, and it is load-bearing in the carry.
    // A single epoch cannot show it: the calculation answers the same either way. Over TWO
    // epochs with the income identity among the owners, its own share settles as a self-share
    // and carries nothing, while any other identity in that slot carries it forward.
    const rows = allocationRows([[b58Of(INCOME), "500", BPS_A, "sc"], [b58Of(OWNER_B), "500", BPS_B, "sc"]]);
    const { env } = mkEnv({ receipt: { rows }, epochs: [...runEpochs(), { ...runEpochs()[0], number: EPOCH + 1 }] });
    const r = await CLEAN.makeResolveProvedPool(env)(POOL);
    const second = r.entitlementsForEpoch(EPOCH + 1, { grossCredits: GROSS, feeCredits: FEE });
    // WHAT IS OBSERVABLE HERE IS THE AMOUNT, not a carry member: this seam's rows carry only
    // accrualId, amountCredits and recipientId by contract, so the carry shows up as the SIZE of
    // the second epoch's obligation. With the pool owner in the income slot its own share settles
    // each epoch and never accumulates, giving 594 again. With any other identity there it would
    // be 594 carried plus 594 owed, which is 1188.
    const selfShare = second.find((x) => x.recipientId === INCOME);
    ok("the income identity comes from the pool document's owner: its share settles each epoch, so the second epoch owes it 594 rather than 1188",
      selfShare && selfShare.amountCredits === shareOf(BPS_A));
    const other = second.find((x) => x.recipientId === OWNER_B);
    ok("the other owner's unpaid share DOES accumulate, so the two are distinguished rather than both being quiet",
      other && other.amountCredits === String(2n * BigInt(shareOf(BPS_B))));
    ok("the two second-epoch amounts differ, which is what makes this case able to tell the identities apart",
      selfShare.amountCredits !== other.amountCredits);
  }
  {
    // THE JOURNAL IS THE REQUESTED POOL'S, AND IS READ AT CALL TIME. The old fake ignored the
    // pool it was handed and returned one static object, so reading another pool's journal and
    // caching it at resolution were both invisible.
    const e = mkEnv();
    const r = await CLEAN.makeResolveProvedPool(e.env)(POOL);
    const before = r.entitlementsForEpoch(EPOCH, { grossCredits: GROSS, feeCredits: FEE });
    ok("the journal read is asked for the pool being resolved and no other",
      e.journalReads.length > 0 && e.journalReads.every((p) => p === POOL));
    // the store grows while the run proceeds, which is why the read is not cached
    e.journals.set(POOL, journalFor([...runEpochs(), { ...runEpochs()[0], number: EPOCH + 1 }]));
    const after = r.entitlementsForEpoch(EPOCH + 1, { grossCredits: GROSS, feeCredits: FEE });
    ok("an epoch appended AFTER the resolution is answered, so the journal is read at call time rather than captured",
      before.length === 2 && Array.isArray(after) && after.length === 2);
  }

  // ================= 10. the resolved-or-not classification (a soundness-review finding) =================
  {
    const known = { resolved: true, marker: "the real one" };
    const map = new Map([[POOL, known]]);
    const logs = [];
    const resolver = CLEAN.makePoolResolver({ resolvedPools: map, log: (s) => logs.push(s) });
    ok("a resolved pool answers with its resolution", resolver(POOL) === known);
    const unknown = resolver(OTHER_POOL);
    ok("an unresolved journal answers resolved:false and names itself, never zero entitlements",
      unknown.resolved === false && unknown.unresolvedPoolId === OTHER_POOL
        && !("entitlementsForEpoch" in unknown));
    ok("the refusal is announced with the pool's identifier so the operator learns which journal",
      logs.some((l) => /UNRESOLVED/.test(l) && l.includes(OTHER_POOL.slice(0, 12))));
    throws("the resolver needs its map", () => CLEAN.makePoolResolver({ log: () => {} }), /needs the resolved-pool map/);
    throws("the resolver needs an explicit log",
      () => CLEAN.makePoolResolver({ resolvedPools: new Map() }), /needs an explicit log function/);
  }

  // ================= 11. owner identity, subject and pins (a soundness-review finding) =================
  {
    const owners = [{ ownerB58: b58Of(OWNER_A), bps: BPS_A }, { ownerB58: b58Of(OWNER_B), bps: BPS_B }];
    const good = (b58) => ({ identity: { id: b58 },
      metadata: { chainId: CHAIN, protocolVersion: PROTOCOL } });
    const mk = (lookup) => CLEAN.makeVerifyAllocationOwners({
      lookupIdentity: lookup, idHex, chainIdPin: CHAIN, protocolPin: PROTOCOL });
    const asked = [];
    ok("every owner is checked, and the count is reported",
      (await mk(async (b) => { asked.push(b); return good(b); })(owners)).checked === 2
        && asked.length === 2 && asked[0] !== asked[1]);
    await rejects("an owner that does not resolve refuses",
      mk(async () => ({ identity: null }))(owners), /did not resolve through the proved lookup/);
    await rejects("a lookup answering with a DIFFERENT subject refuses",
      mk(async () => good(b58Of(h32("99"))))(owners), /returned a different identity/);
    await rejects("a lookup off the pinned chain refuses",
      mk(async (b) => ({ identity: { id: b }, metadata: { chainId: "other", protocolVersion: PROTOCOL } }))(owners),
      /fails the pins/);
    await rejects("a lookup at an unpinned protocol version refuses",
      mk(async (b) => ({ identity: { id: b }, metadata: { chainId: CHAIN, protocolVersion: PROTOCOL + 1 } }))(owners),
      /fails the pins/);
    await rejects("an EMPTY owner set refuses rather than passing vacuously",
      mk(async (b) => good(b))([]), /would pass vacuously/);
    // the SECOND owner is checked too, not only the first
    let n = 0;
    await rejects("a lookup that fails only on the SECOND owner still refuses",
      mk(async (b) => { n += 1; return n === 1 ? good(b) : { identity: null }; })(owners),
      /did not resolve through the proved lookup/);
  }

  // ================= 12. the header-to-receipt binding =================
  {
    const target = { resolved: true, owners: [{ ownerB58: "a" }, { ownerB58: "b" }],
      allocationHashHex: h32("aa") };
    throws("an owner count differing from the header's memberCount refuses",
      () => CLEAN.bindHeaderToReceipt({ bootstrap: false, headerAllocationHash: h32("aa"),
        headerMemberCount: 3, target }), /differs from the header's memberCount/);
    const boot = CLEAN.bindHeaderToReceipt({ bootstrap: true, headerAllocationHash: h32("bb"),
      headerMemberCount: 2, target });
    ok("bootstrap TAKES the hash from the proved receipt, overriding the header's",
      boot.allocationHash === h32("aa") && boot.source === "proved-receipt");
    const resume = CLEAN.bindHeaderToReceipt({ bootstrap: false, headerAllocationHash: h32("aa"),
      headerMemberCount: 2, target });
    ok("a resume whose journaled header agrees keeps that value",
      resume.allocationHash === h32("aa") && resume.source === "journaled-header");
    throws("a resume whose journaled header disagrees refuses",
      () => CLEAN.bindHeaderToReceipt({ bootstrap: false, headerAllocationHash: h32("bb"),
        headerMemberCount: 2, target }), /differs from the proved receipt's recomputed/);
    throws("an unresolved target cannot be bound at all",
      () => CLEAN.bindHeaderToReceipt({ bootstrap: false, headerAllocationHash: h32("aa"),
        headerMemberCount: 2, target: { resolved: false } }), /needs a resolved target/);
  }

  // ================= 13. THE MUTATION BATTERY (the contrary control) =================
  const SRC_PATH = path.join(__dirname, "e2PoolResolution.cjs");
  const SRC = fs.readFileSync(SRC_PATH, "utf8");
  const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-poolres-mut-"));

  const MUTATIONS = [
    { id: "P1", what: "the proved fetch stops requiring exactly one document",
      from: "    if (docs.length !== 1) throw new Error(`${label}: expected exactly one document, found ${docs.length}`);",
      to: "",
      probe: async (mod) => {
        const f = mod.makeProvedFetchOne({ provedQuery: async () => ["a", "b"] });
        try { await f("pool", [], "probe"); return "answered"; }
        catch (e) { return /expected exactly one document/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "P2", what: "the resolution stops checking that the served pool is the one asked for",
      from: "    if (idHex(poolDocP.id) !== pid) {",
      to: "    if (false) {",
      probe: async (mod) => {
        const { env } = mkEnv({ pool: { id: OTHER_POOL } });
        try { await mod.makeResolveProvedPool(env)(POOL); return "resolved"; }
        catch (e) { return /returned a different document/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "P3", what: "a refused pair check no longer stops the resolution",
      from: "    if (!pair.ok) throw new Error(`${label}: the pool/receipt pair check refused: ${pair.reason}`);",
      to: "",
      probe: async (mod) => {
        const { env } = mkEnv({ pairCheck: () => ({ ok: false, reason: "owner mismatch" }) });
        try { await mod.makeResolveProvedPool(env)(POOL); return "resolved"; }
        catch (e) { return /pair check refused/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "P4", what: "the eligibility predicate stops refusing a non-evo node",
      from: '    if (poolProps.nodeType !== "evo") {',
      to: "    if (false) {",
      probe: async (mod) => {
        const { env } = mkEnv({ pool: { nodeType: "regular" } });
        try { await mod.makeResolveProvedPool(env)(POOL); return "resolved"; }
        catch (e) { return /eligibility predicate/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "P5", what: "the recomputed allocation hash stops being compared with the stored one",
      from: "    if (rehash !== storedHash) {",
      to: "    if (false) {",
      probe: async (mod) => {
        const { env } = mkEnv({ receipt: { storedHash: h32("ee") } });
        try { await mod.makeResolveProvedPool(env)(POOL); return "resolved"; }
        catch (e) { return /differs from the receipt's/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "P6", what: "an allocation with no owners is accepted",
      from: "    if (poolOwners.length < 1) throw new Error(`${label}: the allocation carries no owners`);",
      to: "",
      probe: async (mod) => {
        const { env } = mkEnv({ receipt: { rows: allocationRows([]) } });
        try { await mod.makeResolveProvedPool(env)(POOL); return "resolved"; }
        catch (e) { return /carries no owners/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    // THE MUTATION REACHES THE PATH RATHER THAN BREAKING BEFORE IT. Deleting the guard outright
    // makes the next line read a member of undefined, and a crash is not a detection, so the
    // harness rightly declined to score it. This mutation keeps the undefined case guarded and
    // drops only the FIELD checks, which is the realistic way the guard erodes: a caller passing
    // a numbers object that carries neither figure is then quantified against nothing.
    { id: "P7", what: "the quantification guard stops checking that the numbers carry both figures",
      from: "        if (!numbers || numbers.grossCredits === undefined || numbers.feeCredits === undefined) {",
      to: "        if (!numbers) {",
      probe: async (mod) => {
        const r = await mod.makeResolveProvedPool(mkEnv().env)(POOL);
        try { r.entitlementsForEpoch(EPOCH, {}); return "answered"; }
        catch (e) {
          if (/unquantified answer/.test(e.message)) return "refused-as-unquantified";
          if (/refusing rather than choosing one/.test(e.message)) return "refused-later-as-mismatch";
          return `other:${e.message}`;
        }
      }, expect: "refused-as-unquantified" },
    { id: "P8", what: "the two sources of the epoch's figures are compared by DERIVED amount instead of field by field",
      from: `        if (String(numbers.grossCredits) !== mine.grossCredits
          || String(numbers.feeCredits) !== mine.feeCredits) {`,
      to: `        if (Number(numbers.grossCredits) - Number(numbers.feeCredits)
          !== Number(mine.grossCredits) - Number(mine.feeCredits)) {`,
      probe: async (mod) => {
        const r = await mod.makeResolveProvedPool(mkEnv().env)(POOL);
        // 1100/110 and 1000/10 agree on 990 and on nothing else
        try { r.entitlementsForEpoch(EPOCH, { grossCredits: "1100", feeCredits: "110" }); return "answered"; }
        catch (e) { return /refusing rather than choosing one/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    // THE DEFECT THAT MATTERS HERE IS ANSWERING ABOUT THE WRONG EPOCH, not crashing. Falling back
    // to the run's first epoch is how such a lookup erodes in practice, and it produces a
    // confident answer computed from figures the asked-for epoch never had.
    { id: "P9", what: "an epoch outside the journal's run silently falls back to the run's first epoch",
      from: "        const mine = epochs.find((e) => e.number === epochIndex);",
      to: "        const mine = epochs.find((e) => e.number === epochIndex) || epochs[0];",
      probe: async (mod) => {
        const r = await mod.makeResolveProvedPool(mkEnv().env)(POOL);
        // WHICH LAYER REFUSED, not merely whether something did. Removing this module's own
        // check does NOT let a wrong-epoch answer through, because the calculation refuses the
        // same epoch by its own rule. The observable difference is therefore the RULE that
        // fired, and binding that is what keeps the module's comment honest about what its
        // guard is for.
        try {
          const rows = r.entitlementsForEpoch(EPOCH + 3, { grossCredits: GROSS, feeCredits: FEE });
          return `answered-with-${rows.length}-rows`;
        }
        catch (e) {
          if (/outside the run its journal evidences/.test(e.message)) return "refused-by-this-module";
          if (/entitlementCalc: epoch \d+ is outside this run/.test(e.message)) return "refused-by-the-calculation";
          return `other:${e.message}`;
        }
      }, expect: "refused-by-this-module" },
    { id: "P10", what: "an unresolved journal is answered as resolved with no entitlements (the a soundness-review finding defect)",
      from: `    log(\`  [UNRESOLVED] store journal \${pid.slice(0, 12)}... has no proved resolution; the admission will refuse rather than quantify its obligations as zero (a soundness-review finding)\`);
    return { resolved: false, unresolvedPoolId: pid };`,
      to: `    return { resolved: true, owners: [], entitlementsForEpoch: () => [] };`,
      probe: async (mod) => {
        const r = mod.makePoolResolver({ resolvedPools: new Map(), log: () => {} })(OTHER_POOL);
        return r.resolved === false ? "refused" : "answered-as-resolved";
      }, expect: "refused" },
    { id: "P11", what: "the owner lookup stops checking that the identity returned is the subject asked for",
      from: "      if (gotId !== idHex(o.ownerB58)) {",
      to: "      if (false) {",
      probe: async (mod) => {
        const v = mod.makeVerifyAllocationOwners({
          lookupIdentity: async () => ({ identity: { id: b58Of(h32("99")) },
            metadata: { chainId: CHAIN, protocolVersion: PROTOCOL } }),
          idHex, chainIdPin: CHAIN, protocolPin: PROTOCOL });
        try { await v([{ ownerB58: b58Of(OWNER_A), bps: BPS_A }]); return "accepted"; }
        catch (e) { return /returned a different identity/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "P12", what: "the owner lookup stops checking the chain and protocol pins",
      from: `      if (!r.metadata || r.metadata.chainId !== chainIdPin
        || Number(r.metadata.protocolVersion) !== protocolPin) {`,
      to: "      if (false) {",
      probe: async (mod) => {
        const v = mod.makeVerifyAllocationOwners({
          lookupIdentity: async (b) => ({ identity: { id: b },
            metadata: { chainId: "other", protocolVersion: PROTOCOL } }),
          idHex, chainIdPin: CHAIN, protocolPin: PROTOCOL });
        try { await v([{ ownerB58: b58Of(OWNER_A), bps: BPS_A }]); return "accepted"; }
        catch (e) { return /fails the pins/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "P13", what: "an EMPTY owner set passes the owner verification vacuously",
      from: `    if (!Array.isArray(owners) || owners.length === 0) {
      refuse("verifyAllocationOwners needs at least one owner; an empty set would pass vacuously");
    }`,
      to: "",
      probe: async (mod) => {
        const v = mod.makeVerifyAllocationOwners({ lookupIdentity: async () => ({ identity: null }),
          idHex, chainIdPin: CHAIN, protocolPin: PROTOCOL });
        try { await v([]); return "passed-vacuously"; }
        catch (e) { return /pass vacuously/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "P14", what: "a resume accepts a journaled header whose allocation hash disagrees with the receipt",
      from: "  if (headerAllocationHash !== target.allocationHashHex) {",
      to: "  if (false) {",
      probe: async (mod) => {
        const target = { resolved: true, owners: [{ ownerB58: "a" }], allocationHashHex: h32("aa") };
        try {
          mod.bindHeaderToReceipt({ bootstrap: false, headerAllocationHash: h32("bb"),
            headerMemberCount: 1, target });
          return "accepted";
        } catch (e) { return /differs from the proved receipt's recomputed/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "P15", what: "the owner count is no longer held against the header's memberCount",
      from: "  if (target.owners.length !== headerMemberCount) {",
      to: "  if (false) {",
      probe: async (mod) => {
        const target = { resolved: true, owners: [{ ownerB58: "a" }, { ownerB58: "b" }], allocationHashHex: h32("aa") };
        try {
          mod.bindHeaderToReceipt({ bootstrap: true, headerAllocationHash: h32("aa"),
            headerMemberCount: 9, target });
          return "accepted";
        } catch (e) { return /differs from the header's memberCount/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },

    // ---- P16 to P25: THE REVIEW'S OWN MUTATIONS ----
    // An independent round constructed these against the first version of this battery and every
    // one survived 82 passing checks. They are adopted in substance, because an author choosing
    // their own mutations proves the least.
    { id: "P16", what: "the journal of the WRITER identity is read instead of the requested pool's",
      from: "        const read = openJournalFor(pid);",
      to: "        const read = openJournalFor(writerHex);",
      probe: async (mod) => {
        const e = mkEnv();
        const r = await mod.makeResolveProvedPool(e.env)(POOL);
        try { r.entitlementsForEpoch(EPOCH, { grossCredits: GROSS, feeCredits: FEE }); }
        catch { /* the store holds no journal for that identity, which is itself the observation */ }
        return e.journalReads.every((p) => p === POOL) ? "asked-for-the-pool" : "asked-for-something-else";
      }, expect: "asked-for-the-pool" },
    { id: "P17", what: "the journal is captured at resolution instead of read at call time",
      edits: [
        ["  return async (pid) => {", "  return async (pid) => {\n    const CAPTURED_READ = openJournalFor(pid);"],
        ["        const read = openJournalFor(pid);", "        const read = CAPTURED_READ;"],
      ],
      probe: async (mod) => {
        const e = mkEnv();
        const r = await mod.makeResolveProvedPool(e.env)(POOL);
        e.journals.set(POOL, journalFor([...runEpochs(), { ...runEpochs()[0], number: EPOCH + 1 }]));
        try {
          const rows = r.entitlementsForEpoch(EPOCH + 1, { grossCredits: GROSS, feeCredits: FEE });
          return Array.isArray(rows) ? "sees-the-appended-epoch" : "other:not-an-array";
        } catch (e2) { return /outside the run its journal evidences/.test(e2.message) ? "blind-to-the-append" : "other:" + e2.message; }
      }, expect: "sees-the-appended-epoch" },
    { id: "P18", what: "only the run's first epoch is kept, so a later epoch cannot be answered",
      from: "        const epochs = runFromJournal(read);",
      to: "        const epochs = runFromJournal(read).slice(0, 1);",
      probe: async (mod) => {
        const e = mkEnv({ epochs: [...runEpochs(), { ...runEpochs()[0], number: EPOCH + 1 }] });
        const r = await mod.makeResolveProvedPool(e.env)(POOL);
        try {
          r.entitlementsForEpoch(EPOCH + 1, { grossCredits: GROSS, feeCredits: FEE });
          return "answers-the-later-epoch";
        } catch (e2) { return /outside the run its journal evidences/.test(e2.message) ? "lost-the-later-epoch" : "other:" + e2.message; }
      }, expect: "answers-the-later-epoch" },
    { id: "P19", what: "the run's first epoch is substituted for the journal's configured start",
      from: "          configuredStart: read.configuredStartEpoch,",
      to: "          configuredStart: epochs[0].number,",
      probe: async (mod) => {
        // a journal BOUND AT 4 whose run starts at 5: the configured start is not the first epoch
        const e = mkEnv({ configuredStart: EPOCH - 1 });
        const r = await mod.makeResolveProvedPool(e.env)(POOL);
        try {
          const rows = r.entitlementsForEpoch(EPOCH, { grossCredits: GROSS, feeCredits: FEE });
          return "answered-" + rows.length;
        } catch (e2) {
          // the calculation refuses a run whose first epoch is not the configured start, naming
          // both numbers. The mutant passes the first epoch as the start, so the two agree by
          // construction and the refusal disappears.
          return "refused:" + (/the configured start is/.test(e2.message) ? "start-mismatch" : "other");
        }
      }, expect: "refused:start-mismatch" },
    { id: "P20", what: "every accrual row is returned with an amount of one credit",
      from: "            amountCredits: r.amountCredits, recipientId: r.recipientId }));",
      to: '            amountCredits: "1", recipientId: r.recipientId }));',
      probe: async (mod) => {
        const r = await mod.makeResolveProvedPool(mkEnv().env)(POOL);
        return JSON.stringify(r.entitlementsForEpoch(EPOCH, { grossCredits: GROSS, feeCredits: FEE }));
      }, expect: JSON.stringify(EXPECTED_ROWS) },
    { id: "P21", what: "only the first entitlement row is returned",
      from: "        return calc.rowsFor(epochIndex)",
      to: "        return calc.rowsFor(epochIndex).slice(0, 1)",
      probe: async (mod) => {
        const r = await mod.makeResolveProvedPool(mkEnv().env)(POOL);
        return r.entitlementsForEpoch(EPOCH, { grossCredits: GROSS, feeCredits: FEE }).length;
      }, expect: 2 },
    { id: "P22", what: "rows owing zero are kept instead of filtered",
      from: "          .filter((r) => BigInt(r.amountCredits) > 0n)",
      to: "",
      probe: async (mod) => {
        const e = mkEnv({ epochs: runEpochs({ gross: "1000", fee: "1000" }) });
        const r = await mod.makeResolveProvedPool(e.env)(POOL);
        return r.entitlementsForEpoch(EPOCH, { grossCredits: "1000", feeCredits: "1000" }).length;
      }, expect: 0 },
    { id: "P23", what: "the entitlement calculation is run under the WRITER identity instead of the pool's income identity",
      from: "          incomeIdentity,\n          encodingCeiling,",
      to: "          incomeIdentity: writerHex,\n          encodingCeiling,",
      probe: async (mod) => {
        const rows = allocationRows([[b58Of(INCOME), "500", BPS_A, "sc"], [b58Of(OWNER_B), "500", BPS_B, "sc"]]);
        const e = mkEnv({ receipt: { rows }, epochs: [...runEpochs(), { ...runEpochs()[0], number: EPOCH + 1 }] });
        const r = await mod.makeResolveProvedPool(e.env)(POOL);
        const second = r.entitlementsForEpoch(EPOCH + 1, { grossCredits: GROSS, feeCredits: FEE });
        const self = second.find((x) => x.recipientId === INCOME);
        return self ? self.amountCredits : "absent";
      }, expect: "594" },
    { id: "P24", what: "the receipt is queried under the writer's identifier rather than the pool's",
      from: '      [["poolId", "==", Buffer.from(pid, "hex")]], `${label} completion receipt`);',
      to: '      [["poolId", "==", Buffer.from(writerHex, "hex")]], `${label} completion receipt`);',
      probe: async (mod) => {
        try { await mod.makeResolveProvedPool(mkEnv().env)(POOL); return "resolved"; }
        catch (e2) { return /expected exactly one document, found 0/.test(e2.message) ? "refused" : "other:" + e2.message; }
      }, expect: "resolved" },
    { id: "P25", what: "a header identity is generated where an accrual identity belongs",
      from: '            accrualId: docIdForIn(pid, epochIndex, "platformAccrual", r.recipientId).hex,',
      to: '            accrualId: docIdForIn(pid, epochIndex, "epochHeader", r.recipientId).hex,',
      probe: async (mod) => {
        const r = await mod.makeResolveProvedPool(mkEnv().env)(POOL);
        return r.entitlementsForEpoch(EPOCH, { grossCredits: GROSS, feeCredits: FEE })[0].accrualId.split(":")[0];
      }, expect: "platformAccrual" },
  ];

  let caught = 0;
  for (const m of MUTATIONS) {
    const edits = m.edits || [[m.from, m.to]];
    let mutantSrc = SRC, bad = null;
    for (const [from, to] of edits) {
      const hits = mutantSrc.split(from).length - 1;
      if (hits !== 1) { bad = `pattern matches ${hits} times, not once: ${JSON.stringify(from.slice(0, 60))}`; break; }
      mutantSrc = mutantSrc.replace(from, to);
    }
    if (bad) { failed++; console.error(`FAIL: ${m.id} ${bad}`); continue; }
    const file = path.join(TMP, `mutant-${m.id}.cjs`);
    fs.writeFileSync(file, mutantSrc.replace(/require\("\.\//g, `require("${__dirname.replace(/\\/g, "/")}/`));
    let mod = null;
    try { delete require.cache[file]; mod = require(file); }
    catch (e) { failed++; console.error(`FAIL: ${m.id} mutant did not load: ${(e && e.message) || e}`); continue; }
    let cleanAnswer;
    try { cleanAnswer = await m.probe(CLEAN); }
    catch (e) { failed++; console.error(`FAIL: ${m.id} probe threw on the CLEAN module: ${(e && e.message) || e}`); continue; }
    if (JSON.stringify(cleanAnswer) !== JSON.stringify(m.expect)) {
      failed++; console.error(`FAIL: ${m.id} probe on the clean module answered ${JSON.stringify(cleanAnswer)}, expected ${JSON.stringify(m.expect)}`);
      continue;
    }
    let mutantAnswer;
    try { mutantAnswer = await m.probe(mod); }
    catch (e) { failed++; console.error(`FAIL: ${m.id} mutant probe threw (a break is not a detection): ${(e && e.message) || e}`); continue; }
    if (String(mutantAnswer).startsWith("other:")) {
      failed++; console.error(`FAIL: ${m.id} mutant failed for an unrelated reason: ${mutantAnswer}`);
      continue;
    }
    ok(`${m.id} is CAUGHT: ${m.what} (clean=${JSON.stringify(cleanAnswer)}, mutant=${JSON.stringify(mutantAnswer)})`,
      JSON.stringify(mutantAnswer) !== JSON.stringify(cleanAnswer));
    if (JSON.stringify(mutantAnswer) !== JSON.stringify(cleanAnswer)) caught++;
  }
  ok(`every one of the ${MUTATIONS.length} mutations is caught by a named probe (${caught} caught)`,
    caught === MUTATIONS.length);
  console.log(`  [mutations] ${MUTATIONS.length} applied to ${path.basename(SRC_PATH)}, ${caught} caught: ${MUTATIONS.map((m) => m.id).join(" ")}`);
  fs.rmSync(TMP, { recursive: true, force: true });

  // ================= 14. the runner drives this module =================
  // STATED WIDTH: a text sweep over the runner's source, which binds the SPELLING of the wiring
  // and not its execution. The decisions themselves are covered above, which is the instrument
  // this sweep used to stand in for.
  {
    const src = runnerSource("e2DistributeRun.mjs");
    if (src === null) { skipped += 1; console.log(skipNote("e2DistributeRun.mjs", "the runner-binding sweep")); } else {
    ok("the runner builds its pool resolution from this module",
      /poolResolution\.makeResolveProvedPool\(\{/.test(src));
    ok("the runner keeps no inline proved-pool resolution",
      !/const resolveProvedPool = async \(pid\) => \{/.test(src));
    ok("the runner takes the resolved-or-not classification from this module",
      /poolResolution\.makePoolResolver\(\{/.test(src)
        && !/return \{ resolved: false, unresolvedPoolId: pid \};/.test(src));
    ok("the runner takes the owner verification and the header binding from this module",
      /poolResolution\.makeVerifyAllocationOwners\(\{/.test(src)
        && /poolResolution\.bindHeaderToReceipt\(\{/.test(src));
    ok("the runner supplies the REAL pair checker rather than the module requiring one",
      /checkReceiptAgainstPool: \(a\) => receiptPoolCheck\.checkReceiptAgainstPool\(a\)/.test(src));
    }
  }

  console.log(`\ne2PoolResolutionTest: ${passed} passed, ${failed} failed` + (skipped ? `, ${skipped} skipped (counted, never folded into passes)` : ""));
  if (failed) process.exitCode = 1;
};
main().catch((e) => { console.error("e2PoolResolutionTest crashed:", (e && e.stack) || e); process.exitCode = 1; });
