/**
 * THE RAIL-SEPARATION SUITE (the v11 adoption table's named owner of the
 * rail cases, the spec's later revisions): the legacy rewardAccrual rows
 * (amountDuffs, epochHeight) and the E2 platformAccrual rows (amountCredits,
 * epochIndex) stay distinct IN THE SURFACES EXERCISED BELOW, the earnings,
 * portfolio and watch displays and the compound, autopay,
 * earnedRewardsBig and runAutopaySweep accounting paths, each case at the
 * width its own block states.
 *
 * The cases drive the REAL closures: buildLedgerHelpers is the extraction
 * buildContext itself composes, the command modules run over a ctx carrying
 * those helpers, the journal is the real compoundJournal on a throwaway env
 * store; the client, the formatter spy and selected env plumbing are
 * synthetic, while the helpers, commands, journal and identifier codec are
 * the real modules. WIDTH, STATED PLAINLY: the
 * injected client is a document TABLE behind the platform.documents.get
 * name; it ignores query filters and pagination, so transport, filtering and
 * paging fidelity are not proven here. Fixtures carry SELECTED field names
 * from the v9/v11 schemas as partial objects, plus one deliberate cross-type
 * row for the loud-refusal case; they are not schema-validated documents.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

// the env store is pointed at a throwaway file BEFORE any module loads it
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "railsep-"));
process.env.TEGARA_ENV_PATH = path.join(TMP, ".env.test");
fs.writeFileSync(process.env.TEGARA_ENV_PATH, "");
fs.mkdirSync(process.env.TEGARA_ENV_PATH + ".state", { recursive: true });
delete process.env.TEGARA_PROFILE; // the release profile would refuse LEDGER=v11

const { Identifier } = require("@dashevo/wasm-dpp");
const { buildLedgerHelpers, creditsBig } = require("./clientContext.cjs");
const envStore = require("./envStore.cjs");
const journal = require("./compoundJournal.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const eq = (name, got, want) => {
  if (got === want) passed++;
  else { failed++; console.error(`FAIL: ${name} (got ${JSON.stringify(got)}, want ${JSON.stringify(want)})`); }
};
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

// ---------------------------------------------------------------------------
// fixtures: SDK-shaped documents over the real Identifier codec
// ---------------------------------------------------------------------------
const MY_BYTES = Buffer.alloc(32, 5);
const MY_ID = Identifier.from(MY_BYTES).toString();
const OTHER_BYTES = Buffer.alloc(32, 6);
const POOL_A = Buffer.alloc(32, 7);
const POOL_B = Buffer.alloc(32, 8);
let docSeq = 0;
const mkDoc = (fields, { ownerId = MY_ID, createdAt = 1000 + ++docSeq } = {}) => {
  const idBytes = Buffer.alloc(32); idBytes.writeUInt32BE(++docSeq, 28);
  const idStr = Identifier.from(idBytes).toString();
  const obj = { ...fields, $createdAt: createdAt };
  return {
    toObject: () => ({ ...obj }),
    getOwnerId: () => ({ toString: () => ownerId }),
    getId: () => ({ toString: () => idStr }),
  };
};
const legacyAccrual = (duffs, over = {}) =>
  mkDoc({ poolId: POOL_A, funderId: MY_BYTES, epochHeight: 500, amountDuffs: duffs, kind: "reward", ...over });
const platformAccrual = (credits, over = {}) =>
  mkDoc({ poolId: POOL_A, funderId: MY_BYTES, epochIndex: 3, amountCredits: credits, shareBps: 5000, ...over });

// the injected client: a document table behind the paginated interface, every
// (type) query recorded so a case can assert what was NOT consulted
const mkClient = (docsByType, extra = {}) => {
  const queries = [];
  return {
    queries,
    platform: {
      documents: {
        get: async (type, query) => { queries.push(type); return (docsByType[type] || []).slice(); },
      },
      identities: extra.identities || {
        get: async () => ({ getBalance: () => 0 }),
      },
    },
    getWalletAccount: extra.getWalletAccount
      || (async () => { throw new Error("the wallet must not be reached in these cases"); }),
  };
};

const JC = "railSepTestContract";
const capture = async (fn) => {
  const lines = [];
  const origLog = console.log, origErr = console.error;
  console.log = (...a) => lines.push(a.join(" "));
  console.error = (...a) => lines.push(a.join(" "));
  try { await fn(); } finally { console.log = origLog; console.error = origErr; }
  return lines;
};
const mkCtx = (client, over = {}) => {
  const state = { myId: MY_ID };
  const helpers = buildLedgerHelpers({ client, state, who: "funder1", journalContract: JC });
  // DASHfmt is a RECORDING spy: the no-conversion cases assert the forbidden
  // operation (formatting a credit-derived value as DASH) never happened,
  // instead of searching the output for two spellings of one number
  const dashfmtCalls = [];
  return {
    __dashfmtCalls: dashfmtCalls,
    client, env: {}, args: [], who: "funder1", journal, journalContract: JC,
    Identifier, DASHfmt: (d) => { dashfmtCalls.push(Number(d)); return (Number(d) / 100000000).toFixed(8); },
    short: (s) => `${s.slice(0, 10)}...`,
    fetchAll: require("./query.cjs").fetchAll,
    loadEnv: envStore.loadEnv, updateEnvKey: envStore.updateEnvKey,
    activeCastId: () => null,
    hasE2Records: envStore.hasE2Records, creditsBig,
    ...helpers,
    get myId() { return state.myId; },
    ...over,
  };
};

(async () => {

// ---------------------------------------------------------------------------
// creditsBig: the credit rail's OWN converter (the duff converter's ceiling is
// the coin supply, BELOW the schema's amountCredits maximum)
// ---------------------------------------------------------------------------
{
  eq("creditsBig accepts the schema's exact amountCredits maximum",
    creditsBig(9007199254740991), 9007199254740991n);
  throws("creditsBig refuses one over the schema maximum", () => creditsBig("9007199254740992"),
    /exceeds the schema's amountCredits maximum/);
  throws("creditsBig refuses a non-canonical value", () => creditsBig("01"), /not a canonical/);
  throws("creditsBig refuses a negative value", () => creditsBig("-3"), /not a canonical/);
  // the accepted domain is checked BEFORE coercion: these all stringify to
  // canonical-looking text and none is a scalar (the checker's shapes)
  throws("creditsBig refuses an array", () => creditsBig([1]), /must be a string, number or bigint/);
  throws("creditsBig refuses a boxed number", () => creditsBig(new Number(1)), /must be a string, number or bigint/);
  throws("creditsBig refuses a toString-carrying object", () => creditsBig({ toString: () => "7" }),
    /must be a string, number or bigint/);
  // the shared-converter shape the rail decision forbids: the duff converter
  // REFUSES a legitimate credit value, which is why credits have their own
  throws("journal.toBig cannot carry the credit maximum (why the rails need two converters)",
    () => journal.toBig(9007199254740991, "x"), /exceeds the coin supply/);
}

// ---------------------------------------------------------------------------
// the helpers: the credit-rail read is capability-gated and funder-filtered
// ---------------------------------------------------------------------------
{
  process.env.LEDGER = "v9";
  const client = mkClient({ "poolLedger.platformAccrual": [platformAccrual(10)] });
  const h = buildLedgerHelpers({ client, state: { myId: MY_ID }, who: "funder1", journalContract: JC });
  eq("on a non-E2 ledger myPlatformAccruals answers empty", (await h.myPlatformAccruals()).length, 0);
  ok("and the platformAccrual type is NEVER queried", !client.queries.includes("poolLedger.platformAccrual"));

  process.env.LEDGER = "v11";
  // the FOREIGN row comes FIRST and both rows carry the SAME amount, so a
  // filter that takes the first row, or one that selects by amount, fails
  // here; the surviving row is bound by DOCUMENT IDENTITY (the
  // checker named the positional and constant-amount holes)
  const foreign = platformAccrual(11, { funderId: OTHER_BYTES });
  const mine = platformAccrual(11);
  const client2 = mkClient({ "poolLedger.platformAccrual": [foreign, mine] });
  const h2 = buildLedgerHelpers({ client: client2, state: { myId: MY_ID }, who: "funder1", journalContract: JC });
  const got = await h2.myPlatformAccruals();
  eq("on v11 myPlatformAccruals answers only MY rows", got.length, 1);
  eq("and the surviving row is MINE by document id, not by position or amount",
    got[0].getId().toString(), mine.getId().toString());
}

// ---------------------------------------------------------------------------
// the factory refuses malformed construction (the extraction must not open a
// wider build path than buildContext guards); the mutable-holder onboard case
// stays constructible
// ---------------------------------------------------------------------------
{
  throws("the factory refuses a client without documents.get",
    () => buildLedgerHelpers({ client: {}, state: { myId: MY_ID }, who: "funder1", journalContract: JC }),
    /needs a client with platform\.documents\.get/);
  throws("the factory refuses a missing state holder",
    () => buildLedgerHelpers({ client: mkClient({}), state: null, who: "funder1", journalContract: JC }),
    /mutable state holder/);
  throws("the factory refuses an ARRAY as the state holder",
    () => buildLedgerHelpers({ client: mkClient({}), state: [], who: "funder1", journalContract: JC }),
    /plain, unfrozen object/);
  throws("the factory refuses a FROZEN holder (setMyId could never write into it)",
    () => buildLedgerHelpers({ client: mkClient({}), state: Object.freeze({ myId: undefined }), who: "funder1", journalContract: JC }),
    /plain, unfrozen object/);
  throws("the factory refuses an exotic instance as the holder",
    () => buildLedgerHelpers({ client: mkClient({}), state: new Date(), who: "funder1", journalContract: JC }),
    /plain, unfrozen object/);
  throws("the factory refuses an empty journal contract",
    () => buildLedgerHelpers({ client: mkClient({}), state: { myId: MY_ID }, who: "funder1", journalContract: "" }),
    /journal contract id/);
  throws("the factory refuses a whitespace journal contract",
    () => buildLedgerHelpers({ client: mkClient({}), state: { myId: MY_ID }, who: "funder1", journalContract: "  " }),
    /journal contract id/);
  throws("the factory refuses a missing member label",
    () => buildLedgerHelpers({ client: mkClient({}), state: { myId: MY_ID }, journalContract: JC }),
    /member label/);
  const onboardShaped = buildLedgerHelpers({ client: mkClient({}), state: { myId: undefined },
    who: "funder1", journalContract: JC });
  ok("a holder with no identity YET constructs (the onboard flow sets it later)",
    typeof onboardShaped.myAccruals === "function");
}

// ---------------------------------------------------------------------------
// earnings: the DASH totals from duffs alone; the credit rail its own section
// ---------------------------------------------------------------------------
{
  process.env.LEDGER = "v11";
  const legacy = [legacyAccrual(200000000), legacyAccrual(100000000, { poolId: POOL_B })];
  const plats = [platformAccrual(70000), platformAccrual(30000, { epochIndex: 4 }),
    platformAccrual(500000, { funderId: OTHER_BYTES })];
  const run = async (docs) => capture(async () =>
    require("./commands/earnings.cjs")(mkCtx(mkClient(docs))));

  const both = await run({ "poolLedger.rewardAccrual": legacy, "poolLedger.platformAccrual": plats });
  const dashTotal = both.find((l) => l.includes("total earned by"));
  ok("earnings sums the DASH total from duffs alone",
    dashTotal !== undefined && dashTotal.includes("3.00000000 DASH"));
  ok("earnings shows the credit rail as its own section",
    both.some((l) => l.includes("platform-credit income")));
  ok("earnings totals MY platform credits exactly, in credits",
    both.some((l) => l.includes("platform income total for funder1: 100000 credits across 2 accrual(s)")));
  ok("BOTH per-epoch platform lines carry their epochIndex and credits",
    both.some((l) => l.includes("platform epoch 3: 70000 credits"))
    && both.some((l) => l.includes("platform epoch 4: 30000 credits")));

  const legacyOnly = await run({ "poolLedger.rewardAccrual": legacy, "poolLedger.platformAccrual": [] });
  eq("the DASH total line is BYTE-IDENTICAL with and without platform rows (never combined)",
    both.find((l) => l.includes("total earned by")),
    legacyOnly.find((l) => l.includes("total earned by")));

  // the FORBIDDEN OPERATION observed directly: the DASH formatter is a spy,
  // and no call to it received the credit sum or a credit-derived value
  {
    const ctx = mkCtx(mkClient({ "poolLedger.rewardAccrual": legacy, "poolLedger.platformAccrual": plats }));
    await capture(async () => require("./commands/earnings.cjs")(ctx));
    // an ALLOWLIST over the NAMED formatter (width: it establishes what THIS
    // formatter received, never that no inline conversion exists; an inline
    // conversion is caught only where the output assertions see its print)
    const LEGIT_DUFF_CALLS = new Set([200000000, 100000000, 300000000]);
    ok("the DASH formatter received ONLY the fixture's duff figures (allowlist; any credit-derived value fails)",
      ctx.__dashfmtCalls.length > 0 && ctx.__dashfmtCalls.every((v) => LEGIT_DUFF_CALLS.has(v)));
  }

  // a failed credit-rail read is contained: the DASH output stands, the
  // failure is loud and the exit is non-zero (partial, never silently whole)
  {
    const ctx = mkCtx(mkClient({ "poolLedger.rewardAccrual": legacy }));
    ctx.myPlatformAccruals = async () => { throw new Error("platform read broke"); };
    const before = process.exitCode;
    const out = await capture(async () => require("./commands/earnings.cjs")(ctx));
    ok("the legacy DASH output survives a failed platform read",
      out.some((l) => l.includes("total earned by")));
    ok("the failure is loud and names the output PARTIAL",
      out.some((l) => l.includes("UNAVAILABLE") && l.includes("PARTIAL")));
    eq("the failed platform read sets a non-zero exit", process.exitCode, 1);
    process.exitCode = before;
  }

  process.env.LEDGER = "v9";
  const v9client = mkClient({ "poolLedger.rewardAccrual": legacy, "poolLedger.platformAccrual": plats });
  const v9out = await capture(async () => require("./commands/earnings.cjs")(mkCtx(v9client)));
  ok("on v9 earnings shows no platform section", !v9out.some((l) => l.includes("platform")));
  ok("and never queries the platformAccrual type", !v9client.queries.includes("poolLedger.platformAccrual"));
}

// ---------------------------------------------------------------------------
// portfolio: one separate credits line, no DASH conversion of credits
// ---------------------------------------------------------------------------
{
  process.env.LEDGER = "v11";
  const docs = {
    "poolLedger.rewardAccrual": [legacyAccrual(200000000)],
    "poolLedger.platformAccrual": [platformAccrual(123456789)],
    "poolLedger.share": [], "poolLedger.membershipRequest": [],
  };
  const pctx = mkCtx(mkClient(docs));
  const out = await capture(async () => require("./commands/portfolio.cjs")(pctx));
  const platLine = out.find((l) => l.startsWith("platform income:"));
  ok("portfolio shows the credit rail on its own line", platLine !== undefined
    && platLine.includes("123456789 credits"));
  // the forbidden operation observed at the FORMATTER via an allowlist: with
  // this fixture set the legitimate calls are the balance conversion (0) and
  // the duff earnings (200000000); anything else is a derivation
  ok("portfolio's DASH formatter received ONLY the fixture's legitimate figures (allowlist)",
    pctx.__dashfmtCalls.length > 0 && pctx.__dashfmtCalls.every((v) => v === 0 || v === 200000000));
  const earnedLine = out.find((l) => l.startsWith("\nearnings:") || l.startsWith("earnings:"));
  ok("portfolio's DASH earnings line comes from duffs alone",
    earnedLine !== undefined && earnedLine.includes("2.00000000 DASH earned"));

  // a failed credit-rail read in portfolio is contained exactly as earnings'
  // (the checker named the ungated catch)
  {
    const fctx = mkCtx(mkClient(docs));
    fctx.myPlatformAccruals = async () => { throw new Error("platform read broke"); };
    const before = process.exitCode;
    const fout = await capture(async () => require("./commands/portfolio.cjs")(fctx));
    ok("portfolio's DASH sections survive a failed platform read",
      fout.some((l) => l.includes("DASH earned")));
    ok("portfolio's failure is loud and marks the output PARTIAL",
      fout.some((l) => l.includes("UNAVAILABLE") && l.includes("PARTIAL")));
    eq("portfolio's failed platform read sets a non-zero exit", process.exitCode, 1);
    process.exitCode = before;
  }
}

// ---------------------------------------------------------------------------
// watch: the credit rail's own cursor and alert; an older watermark without
// the platform member baselines silently instead of false-alerting
// ---------------------------------------------------------------------------
{
  process.env.LEDGER = "v11";
  const table = {
    "poolLedger.rewardAccrual": [], "poolLedger.membershipRequest": [],
    "poolLedger.share": [], "poolLedger.platformAccrual": [],
  };
  const client = mkClient(table);
  const ctx = mkCtx(client);
  const watch = require("./commands/watch.cjs");
  const watchKey = "WATCH_" + journal.suffixFor(JC, MY_ID);

  const out1 = await capture(async () => watch(ctx));
  ok("cycle 1 records a baseline", out1.some((l) => l.includes("baseline recorded")));
  const w1 = JSON.parse(envStore.loadEnv()[watchKey]);
  ok("the baseline watermark carries the platform cursor", w1.platform !== undefined
    && Number.isFinite(w1.platform.at) && Array.isArray(w1.platform.ids));

  table["poolLedger.platformAccrual"].push(platformAccrual(42000, { epochIndex: 9 }));
  const out2 = await capture(async () => watch(ctx));
  ok("cycle 2 alerts the new platform accrual in credits",
    out2.some((l) => l.includes("1 new platform accrual(s): +42000 credits")));
  const platAlert = out2.find((l) => l.includes("new platform accrual"));
  ok("the platform alert carries no DASH-formatted amount",
    platAlert !== undefined && !/\d\.\d{8} DASH/.test(platAlert));

  // cycle 3 runs in a FRESH watch module over a FRESH ctx, so watch-local and
  // ctx-local shadow state cannot carry the cursor; envStore stays cached
  // deliberately, because the stored watermark READ THROUGH IT is the thing
  // under test (width: other cached modules are not re-loaded)
  delete require.cache[require.resolve("./commands/watch.cjs")];
  const watchFresh = require("./commands/watch.cjs");
  const out3 = await capture(async () => watchFresh(mkCtx(client)));
  ok("cycle 3 is quiet (the cursor advanced THROUGH the stored watermark, fresh module and ctx)",
    out3.some((l) => l.includes("no changes")));

  // an OLDER v2 watermark, no platform member, while accruals already exist:
  // the rail baselines and SAYS SO (a stated skip, never a silent one), then
  // alerts only what arrives after
  const w3 = JSON.parse(envStore.loadEnv()[watchKey]);
  delete w3.platform;
  envStore.updateEnvKey(watchKey, JSON.stringify(w3));
  const out4 = await capture(async () => watch(ctx));
  ok("an older watermark without the platform member raises no +credits alert",
    !out4.some((l) => l.includes("new platform accrual")));
  ok("and the rail-only baseline states what it skipped",
    out4.some((l) => l.includes("platform rail baselined: 1 existing platform accrual(s)")));
  ok("and the watermark gains the platform cursor", JSON.parse(envStore.loadEnv()[watchKey]).platform !== undefined);
  table["poolLedger.platformAccrual"].push(platformAccrual(1000, { epochIndex: 10 }));
  const out5 = await capture(async () => watch(ctx));
  ok("after the stated baseline, only the NEW accrual alerts",
    out5.some((l) => l.includes("1 new platform accrual(s): +1000 credits")));

  // a FOREIGN value at w.platform (written by something else entirely) must
  // not invalidate the whole watermark: the legacy rails keep their cursors
  // and a legacy event arriving in the same cycle still alerts (the
  // checker named the missed-legacy-event regression)
  const w5 = JSON.parse(envStore.loadEnv()[watchKey]);
  w5.platform = "legacy-extension";
  envStore.updateEnvKey(watchKey, JSON.stringify(w5));
  table["poolLedger.rewardAccrual"].push(legacyAccrual(50000000));
  const out6 = await capture(async () => watch(ctx));
  ok("a foreign platform value does not re-baseline the legacy rails: the DASH alert fires",
    out6.some((l) => l.includes("new accrual(s): +0.50000000 DASH rewards")));
  ok("while the platform rail itself re-baselines with its statement",
    out6.some((l) => l.includes("platform rail baselined:")));
  {
    const rewritten = JSON.parse(envStore.loadEnv()[watchKey]).platform;
    ok("and the foreign value is replaced by a REAL cursor (shape, not mere inequality)",
      rewritten && typeof rewritten === "object" && !Array.isArray(rewritten)
      && Number.isFinite(rewritten.at) && Array.isArray(rewritten.ids));
  }

  // a FAILED platform read is contained: the legacy alert still fires, the
  // failure is loud, and the stored platform cursor does not advance
  const cursorBefore = JSON.parse(envStore.loadEnv()[watchKey]).platform;
  table["poolLedger.rewardAccrual"].push(legacyAccrual(25000000));
  const failingCtx = mkCtx(client);
  failingCtx.myPlatformAccruals = async () => { throw new Error("platform read broke"); };
  const out7 = await capture(async () => watch(failingCtx));
  ok("a failed platform read does not eat the legacy alert",
    out7.some((l) => l.includes("new accrual(s): +0.25000000 DASH rewards")));
  ok("the failed platform read reports itself",
    out7.some((l) => l.includes("platform watch unavailable")));
  eq("and the stored platform cursor did not advance",
    JSON.stringify(JSON.parse(envStore.loadEnv()[watchKey]).platform), JSON.stringify(cursorBefore));
  envStore.updateEnvKey(watchKey, undefined);
}

// ---------------------------------------------------------------------------
// compound: the ceiling admits ONLY legacy duffs, however large the credits
// ---------------------------------------------------------------------------
{
  process.env.LEDGER = "v11";
  const poolDoc = mkDoc({ nodeType: "evo" });
  const poolIdStr = poolDoc.getId().toString();
  const docs = {
    "poolLedger.rewardAccrual": [legacyAccrual(300000000)],
    "poolLedger.platformAccrual": [platformAccrual(9007199254740991)], // the schema maximum
    "poolLedger.membershipRequest": [], "poolLedger.share": [],
    "poolLedger.pool": [poolDoc],
  };
  const compound = require("./commands/compound.cjs");

  const status = await capture(async () =>
    compound(mkCtx(mkClient(docs), { args: ["status"] })));
  ok("compound status computes the ceiling from duffs alone (3 DASH, not credits)",
    status.some((l) => l.includes("earned rewards: 3.00000000 DASH")));

  // a compound above the duff ceiling refuses even though platform credits
  // dwarf it, and the STATE observation beside the message: the journal
  // recorded no reservation, so the refusal did not consume anything
  const consumedBefore = journal.summary(JC, MY_ID).consumedDuffs;
  await rejects("a compound above the duff ceiling refuses regardless of platform credits",
    (async () => {
      const lines = [];
      const orig = console.log; console.log = (...a) => lines.push(a.join(" "));
      try {
        await compound(mkCtx(mkClient(docs), { args: [poolIdStr, "300000001"] }));
      } finally { console.log = orig; }
    })(),
    /exceeds the uncompounded\s+rewards 3\.00000000 DASH/);
  eq("the refusal reserved nothing in the journal (state, not only the message)",
    journal.summary(JC, MY_ID).consumedDuffs, consumedBefore);
}

// ---------------------------------------------------------------------------
// autopay: the sweepable ceiling from duffs alone; huge credits sweep nothing
// ---------------------------------------------------------------------------
{
  process.env.LEDGER = "v11";
  const docs = {
    "poolLedger.rewardAccrual": [], // NO legacy rewards at all
    "poolLedger.platformAccrual": [platformAccrual(9007199254740991)],
    "poolLedger.membershipRequest": [],
  };
  const autopay = require("./commands/autopay.cjs");
  const apKey = "AUTOPAY_" + journal.suffixFor(JC, MY_ID);

  const status = await capture(async () =>
    autopay(mkCtx(mkClient(docs), { args: ["status"] })));
  ok("autopay status shows nothing sweepable from a credit-only ledger",
    status.some((l) => l.includes("sweepable now: 0.00000000 DASH")));

  envStore.updateEnvKey(apKey, "on");
  const ranCtx = mkCtx(mkClient(docs), { args: ["run"] });
  const run = await capture(async () => autopay(ranCtx));
  ok("autopay run stays idle on a credit-only ledger (the sweep never counts credits)",
    run.some((l) => l.includes("below the") && l.includes("floor; nothing to do")));
  envStore.updateEnvKey(apKey, undefined);
}

// ---------------------------------------------------------------------------
// earnedRewardsBig is loud, never silently zero, on a cross-rail row
// ---------------------------------------------------------------------------
{
  process.env.LEDGER = "v11";
  // a platformAccrual-shaped row (amountCredits, no amountDuffs) smuggled into
  // the rewardAccrual stream must REFUSE at the converter, never count as zero
  const smuggled = mkDoc({ poolId: POOL_A, funderId: MY_BYTES, epochIndex: 3, amountCredits: 5000 });
  const h = buildLedgerHelpers({ client: mkClient({ "poolLedger.rewardAccrual": [smuggled] }),
    state: { myId: MY_ID }, who: "funder1", journalContract: JC });
  await rejects("a credits-shaped row in the duff stream refuses loudly",
    h.earnedRewardsBig(), /reward accrual is not a canonical non-negative integer/);
}

// ---------------------------------------------------------------------------
// the helper surface the commands destructure stays whole
// ---------------------------------------------------------------------------
{
  // WIDTH: this pins the FACTORY's surface (the eleven names buildContext
  // spreads into ctx), each a callable function, never undefined behind a
  // surviving key. The full command ctx carries many more members; their
  // compatibility is buildContext's own composition, not established here.
  const h = buildLedgerHelpers({ client: mkClient({}), state: { myId: MY_ID }, who: "funder1", journalContract: JC });
  eq("the factory surface stays the eleven names buildContext spreads",
    Object.keys(h).sort().join(","),
    ["getPool", "myShares", "myRequests", "isMyAccrual", "myAccruals", "myPlatformAccruals",
      "requestExists", "earnedRewardsBig", "autopayKeyOf", "watchKeyOf", "runAutopaySweep"].sort().join(","));
  ok("every factory member is a function (a key kept over an undefined value fails here)",
    Object.values(h).every((v) => typeof v === "function"));
}

console.log(`railSeparationTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
})().catch((e) => { console.error("UNCAUGHT:", e); process.exitCode = 1; });
