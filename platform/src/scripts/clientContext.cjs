/**
 * The funder client's shared context: everything the command modules close over, built
 * once and passed to whichever command the router selected. This is the extraction the
 * holistic round called for (two reviewers: the ~1400-line inline dispatch had outgrown
 * its shape and shared rules were drifting). Behavior is unchanged; the seam is now
 * explicit and each command is independently readable and testable.
 *
 * myId lives in a mutable `state` holder because `onboard` registers the identity at
 * run time and the deposit/sweep helpers must see the new id; ctx.setMyId updates it and
 * ctx.myId reads it, so a command never captures a stale null.
 */
const Dash = require("dash");
const { Identifier } = require("@dashevo/wasm-dpp");
const { fetchAll } = require("./query.cjs");
const { loadEnv, updateEnvKey, activeContractId, activeCastId, isV3, isV5, isV6, isV7,
  hasDelegateTarget, hasJoinProvenance, hasMemberRewardScript, hasE2Records,
  assertSupportedLedger } = require("./envStore.cjs");
const journal = require("./compoundJournal.cjs");

const DASHfmt = (duffs) => (Number(duffs) / 100000000).toFixed(8);
const short = (s) => `${s.slice(0, 10)}...`;

// THE CREDIT RAIL'S OWN CONVERTER (the v11 rail-separation decision): platform
// accruals carry amountCredits, whose schema maximum (9007199254740991) sits
// ABOVE journal.toBig's ceiling, the DUFF coin supply. Converting credits
// through the duff converter would refuse legitimate values, and the two rails
// sharing a converter is exactly the unit confusion the rail decision forbids.
const MAX_CREDITS = 9007199254740991n;
const creditsBig = (v, what = "platform credits") => {
  // the accepted domain is string | number | bigint, checked BEFORE any
  // coercion: [1], boxed numbers and toString-carrying objects all coerce to
  // canonical-looking text, and a converter that admits them is not
  // validating its input (the rail round's checker named the shapes)
  if (typeof v !== "string" && typeof v !== "number" && typeof v !== "bigint") {
    throw new Error(`${what} must be a string, number or bigint, not ${Object.prototype.toString.call(v)}`);
  }
  const s = typeof v === "bigint" ? v.toString() : String(v);
  if (!/^(0|[1-9][0-9]*)$/.test(s)) {
    throw new Error(`${what} is not a canonical non-negative integer: "${s}"`);
  }
  const b = BigInt(s);
  if (b > MAX_CREDITS) throw new Error(`${what} exceeds the schema's amountCredits maximum: ${s}`);
  return b;
};

/**
 * The ledger-reading and accounting helpers, extracted from buildContext so
 * railSeparationTest.cjs drives the REAL closures over an injected client
 * (the same seam pattern as the E2 modules). buildContext composes them with
 * the live Dash client; the LIVE composition's behaviour is unchanged by the
 * extraction, and the factory validates its own inputs below (a callable
 * client route, a plain-object mutable holder, a nonempty contract id and
 * member label). WIDTH: the holder's myId may be absent AT CONSTRUCTION,
 * deliberately, for the onboard flow; buildContext's fuller preflight
 * (environment, ledger support, identity outside onboarding) stays in
 * buildContext and is NOT re-provided to direct factory callers.
 *
 * THE RAIL DECISION LIVES HERE (E2 build spec adoption table)
 * for the surfaces these helpers serve: the legacy rewardAccrual rows
 * (amountDuffs, epochHeight) and the E2 platformAccrual rows (amountCredits,
 * epochIndex) stay distinct in the reads and sums these helpers perform (a
 * caller who combines the returned documents' fields is outside what a
 * factory can stop; the command surfaces are the tested consumers).
 * earnedRewardsBig and the compound/autopay ceilings read ONLY
 * poolLedger.rewardAccrual; myPlatformAccruals reads ONLY
 * poolLedger.platformAccrual, answers empty without querying on a ledger
 * whose capability table lacks e2Records (the capability follows the LEDGER
 * selector, not the attached contract, the version table's own design), and
 * its amounts are CREDITS, summed through creditsBig.
 */
function buildLedgerHelpers({ client, state, who, journalContract }) {
  // the factory refuses malformed construction rather than returning helpers
  // that silently answer nothing (the extraction must not open a build path
  // wider than the one buildContext guards)
  if (!client || !client.platform || !client.platform.documents
    || typeof client.platform.documents.get !== "function") {
    throw new Error("buildLedgerHelpers needs a client with platform.documents.get");
  }
  // state is the MUTABLE holder, not a snapshot: onboard registers the
  // identity at run time and setMyId writes into it, so myId may legitimately
  // be absent AT CONSTRUCTION; what the factory refuses is the missing holder
  // itself, and the helpers that need an identity fail on use exactly as the
  // pre-extraction closures did
  // the holder must actually be able to HOLD: a frozen object or an exotic
  // instance satisfies "object" while setMyId (the onboard flow) could never
  // write into it (the check froze one to prove it)
  if (!state || typeof state !== "object" || Array.isArray(state) || Object.isFrozen(state)
    || (Object.getPrototypeOf(state) !== Object.prototype && Object.getPrototypeOf(state) !== null)) {
    throw new Error("buildLedgerHelpers needs the mutable state holder ({ myId }): a plain, unfrozen object");
  }
  if (typeof journalContract !== "string" || journalContract.trim().length === 0) {
    throw new Error("buildLedgerHelpers needs the journal contract id (a nonempty string)");
  }
  if (typeof who !== "string" || who.length === 0) {
    throw new Error("buildLedgerHelpers needs the member label (who)");
  }
  const getPool = async (poolIdStr) => {
    const found = await client.platform.documents.get("poolLedger.pool", {
      where: [["$id", "==", Identifier.from(poolIdStr)]],
    });
    if (found.length === 0) throw new Error(`no pool ${poolIdStr} on the ledger`);
    return found[0];
  };
  const myShares = async () => (await fetchAll(client, "poolLedger.share"))
    .filter((d) => d.getOwnerId().toString() === state.myId);
  const myRequests = async () => fetchAll(client, "poolLedger.membershipRequest", {
    where: [["$ownerId", "==", Identifier.from(state.myId)], ["$createdAt", ">", 0]],
    orderBy: [["$createdAt", "asc"]],
  });
  const isMyAccrual = (d) =>
    Identifier.from(Buffer.from(d.toObject().funderId)).toString() === state.myId;
  const myAccruals = async () =>
    (await fetchAll(client, "poolLedger.rewardAccrual")).filter(isMyAccrual);
  // the credit rail's read: gated on the ledger's OWN capability, so a
  // non-E2 ledger never queries a type its contract does not carry
  const myPlatformAccruals = async () => {
    if (!hasE2Records()) return [];
    return (await fetchAll(client, "poolLedger.platformAccrual")).filter(isMyAccrual);
  };

  const requestExists = async (idStr) => (await client.platform.documents.get(
    "poolLedger.membershipRequest", { where: [["$id", "==", Identifier.from(idStr)]] })).length > 0;
  const earnedRewardsBig = async () => (await myAccruals())
    .filter((d) => d.toObject().kind !== "principal")
    .reduce((s, d) => s + journal.toBig(d.toObject().amountDuffs, "reward accrual"), 0n);
  const autopayKeyOf = () => "AUTOPAY_" + journal.suffixFor(journalContract, state.myId);
  const watchKeyOf = () => "WATCH_" + journal.suffixFor(journalContract, state.myId);

  const runAutopaySweep = async (quietIdle) => {
    const MIN_SWEEP_DUFFS = journal.toBig(process.env.AUTOPAY_MIN_DUFFS || "1000000", "AUTOPAY_MIN_DUFFS");
    await journal.reconcile(journalContract, state.myId, requestExists, console.log);
    const earned = await earnedRewardsBig();
    const { consumedDuffs } = journal.summary(journalContract, state.myId);
    const ceiling = earned - consumedDuffs;
    if (ceiling < MIN_SWEEP_DUFFS) {
      if (!quietIdle) console.log(`sweepable rewards ${DASHfmt(ceiling)} DASH are below the ` +
        `${DASHfmt(MIN_SWEEP_DUFFS)} DASH floor; nothing to do`);
      return "idle";
    }
    const identity = await client.platform.identities.get(state.myId);
    const balance = BigInt(identity.getBalance());
    const CREDITS_PER_DUFF = 1000n;
    const FEE_MARGIN_CREDITS = 100000000n;
    const sweepCredits = ceiling * CREDITS_PER_DUFF;
    const sweepCreditsNum = journal.toSafeNumber(sweepCredits, "sweep credits");
    if (sweepCredits + FEE_MARGIN_CREDITS > balance) {
      console.error(`the sweep needs ${sweepCredits} credits plus a fee margin but the balance is ` +
        `${balance}; rewards were already spent or withdrawn, so there is nothing intact to sweep`);
      return "unbacked";
    }
    const account = await client.getWalletAccount();
    const toAddress = account.getUnusedAddress().address;
    const payoutId = journal.newPayoutId();
    journal.reservePayout(journalContract, state.myId, payoutId, ceiling, earned);
    console.log(`${who} sweeps ${DASHfmt(ceiling)} DASH of rewards to their own address ${toAddress} ` +
      `(journal entry ${payoutId})`);
    try {
      await client.platform.identities.withdrawCredits(identity, sweepCreditsNum, { toAddress });
    } catch (e) {
      console.error(`withdrawal submission failed: ${(e && e.message) || e}`);
      console.error("the ceiling stays conservatively consumed. If you verify no payout arrives at " +
        `${toAddress}, free it with: compound release ${payoutId} --verified-never-landed`);
      throw e;
    }
    const after = BigInt((await client.platform.identities.get(state.myId)).getBalance());
    const debited = balance - after;
    console.log(`credits debited: ${debited} (sweep ${sweepCredits} plus the transition fee)`);
    console.log(`the quorum-signed asset-unlock pays ${toAddress} within a few core blocks`);
    console.log(`=== AUTOPAY SWEEP OK: ${DASHfmt(ceiling)} DASH of rewards left Platform for ` +
      `${who}'s own address, no operator involved ===`);
    return "swept";
  };

  return { getPool, myShares, myRequests, isMyAccrual, myAccruals, myPlatformAccruals,
    requestExists, earnedRewardsBig, autopayKeyOf, watchKeyOf, runAutopaySweep };
}

async function buildContext() {
  const env = loadEnv();
  if (!env.MNEMONIC || !env.CONTRACT_ID) {
    console.error("run register.cjs first (need MNEMONIC and CONTRACT_ID)");
    process.exit(1);
  }
  // the supported set lives in envStore's version table, never in a second copy here
  try { assertSupportedLedger(); } catch (e) { console.error(e.message); process.exit(1); }
  const who = /^funder\d+$/.test(process.env.WHO || "") ? process.env.WHO : "funder1";
  const whoNum = parseInt(who.slice(6), 10);
  const whoIdKey = whoNum === 1 ? "FUNDER_ID" : `FUNDER${whoNum}_ID`;
  const state = { myId: env[whoIdKey] };

  const cmd = process.argv[2] || "portfolio";
  const args = process.argv.slice(3);

  if (!state.myId && cmd !== "onboard") {
    console.error(`${who} identity is not registered yet (run: onboard <depositDuffs>)`);
    process.exit(1);
  }

  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
    apps: {
      poolLedger: { contractId: activeContractId(env) },
      ...(activeCastId(env) ? { castGov: { contractId: activeCastId(env) } } : {}),
    },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  const journalContract = activeContractId(env);
  const helpers = buildLedgerHelpers({ client, state, who, journalContract });

  const depositOwnFunds = async (amountDuffsBig, label) => {
    const CREDITS_PER_DUFF = 1000n;
    const amountDuffs = journal.toSafeNumber(amountDuffsBig, "deposit duffs");
    const account = await client.getWalletAccount();
    const walletBefore = account.getTotalBalance();
    if (amountDuffs >= walletBefore) {
      throw new Error(`${label} of ${DASHfmt(amountDuffs)} DASH exceeds the wallet balance ` +
        `${DASHfmt(walletBefore)} (the asset-lock also pays its own L1 fee)`);
    }
    const before = BigInt((await client.platform.identities.get(state.myId)).getBalance());
    console.log(`${who}'s ${label}: ${DASHfmt(amountDuffs)} DASH from their own wallet as credits at ${state.myId}`);
    await client.platform.identities.topUp(Identifier.from(state.myId), amountDuffs);
    const after = BigInt((await client.platform.identities.get(state.myId)).getBalance());
    const credited = after - before;
    const nominal = amountDuffsBig * CREDITS_PER_DUFF;
    console.log(`  credits: ${before} -> ${after} (+${credited} of the nominal ${nominal}; ` +
      "the difference is the lock's processing fee)");
    console.log(`  wallet balance: ${DASHfmt(walletBefore)} -> ${DASHfmt(account.getTotalBalance())} DASH`);
    if (credited <= 0n || credited > nominal) return null;
    return credited;
  };

  return {
    Dash, Identifier, fetchAll, journal, env, cmd, args, who, whoNum, whoIdKey,
    loadEnv, updateEnvKey, activeContractId, activeCastId, isV3, isV5, isV6, isV7,
    hasDelegateTarget, hasJoinProvenance, hasMemberRewardScript, hasE2Records,
    creditsBig, DASHfmt, short,
    client, journalContract, ...helpers, depositOwnFunds,
    get myId() { return state.myId; },
    setMyId(v) { state.myId = v; },
    disconnect: () => (client.disconnect ? client.disconnect() : undefined),
    installFilter: async () => {
      const { installConsumedFilter } = require("./walletGuard.cjs");
      installConsumedFilter(await client.getWalletAccount());
    },
  };
}

module.exports = { buildContext, buildLedgerHelpers, creditsBig };
