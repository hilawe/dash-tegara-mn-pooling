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
const { loadEnv, updateEnvKey, activeContractId, activeCastId, isV3, isV5, isV6, isV7 } = require("./envStore.cjs");
const journal = require("./compoundJournal.cjs");

const DASHfmt = (duffs) => (Number(duffs) / 100000000).toFixed(8);
const short = (s) => `${s.slice(0, 10)}...`;

async function buildContext() {
  const env = loadEnv();
  if (!env.MNEMONIC || !env.CONTRACT_ID) {
    console.error("run register.cjs first (need MNEMONIC and CONTRACT_ID)");
    process.exit(1);
  }
  if (process.env.LEDGER && !["v1", "v3", "v4", "v5", "v6", "v7", "v8"].includes(process.env.LEDGER)) {
    console.error(`unsupported LEDGER value "${process.env.LEDGER}" (use v1, v3, v4, v5, v6, v7, or v8)`);
    process.exit(1);
  }
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

  const journalContract = activeContractId(env);
  const requestExists = async (idStr) => (await client.platform.documents.get(
    "poolLedger.membershipRequest", { where: [["$id", "==", Identifier.from(idStr)]] })).length > 0;
  const earnedRewardsBig = async () => (await myAccruals())
    .filter((d) => d.toObject().kind !== "principal")
    .reduce((s, d) => s + journal.toBig(d.toObject().amountDuffs, "reward accrual"), 0n);
  const autopayKeyOf = () => "AUTOPAY_" + journal.suffixFor(journalContract, state.myId);
  const watchKeyOf = () => "WATCH_" + journal.suffixFor(journalContract, state.myId);

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

  return {
    Dash, Identifier, fetchAll, journal, env, cmd, args, who, whoNum, whoIdKey,
    loadEnv, updateEnvKey, activeContractId, activeCastId, isV3, isV5, isV6, isV7, DASHfmt, short,
    client, getPool, myShares, myRequests, isMyAccrual, myAccruals, journalContract,
    requestExists, earnedRewardsBig, autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep,
    get myId() { return state.myId; },
    setMyId(v) { state.myId = v; },
    disconnect: () => (client.disconnect ? client.disconnect() : undefined),
    installFilter: async () => {
      const { installConsumedFilter } = require("./walletGuard.cjs");
      installConsumedFilter(await client.getWalletAccount());
    },
  };
}

module.exports = { buildContext };
