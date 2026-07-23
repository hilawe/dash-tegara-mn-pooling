/**
 * The Track A reward credit-rail, exercised against the live pool-ledger contract.
 *
 * Models one reward epoch for a pool that fronts a #187 participant slot:
 *   1. the pool's owner-reward share arrives on L1 (the wallet plays the reward address),
 *   2. the rail computes the split: the operator fee off the top (pool.operatorFeeBps),
 *      the remainder pro-rata by the recorded shareBps, flooring dust to the last funder,
 *   3. ONE asset-lock transaction with one credit output per recipient converts the whole
 *      inflow into Platform credits, crediting each identity directly. At no point does any
 *      coordinator identity hold the aggregate, which is the SF-13-avoiding property. The
 *      L1 rules permit this shape: many credit outputs, each P2PKH, with a single OP_RETURN
 *      output whose value equals their sum (assetlocktx.cpp, CheckAssetLockTx),
 *   4. the operator records a rewardAccrual document per funder, and the script reads the
 *      accruals back and checks that they sum to the distributed remainder.
 *
 * Recovery journal (independent-review finding 1, refactored per the Track C follow-up):
 * ALL rail state lives in ONE phase-modeled record (RAIL_STATE in .env.local, same
 * gitignored file as the wallet mnemonic; see railState.cjs for the phases and the
 * resume-decision matrix). The one-time keys that control the credit outputs are
 * persisted BEFORE the L1 broadcast, each entry is marked as it is credited, and each
 * successful top-up records its state-transition hash so a resume can name what landed
 * instead of leaning on balance deltas alone. A crash between broadcast and the last
 * top-up therefore strands nothing; re-running the script resumes the journal instead
 * of starting a new epoch. The legacy RAIL_SLOT/RAIL_JOURNAL/RAIL_CONSUMED keys migrate
 * on load and are dropped on the next save.
 *
 * Proof path (finding 2, updated by the Track C result 2026-07-10): the instant-lock proof
 * is preferred while fresh. On a Track C epoch whose islock is stale, rejected, or no
 * longer served, the rail falls back to a chain asset-lock proof with a hand-built
 * outpoint; that path was VERIFIED LIVE for credit-output indices 1 and 2, so a late
 * resume no longer strands credits (it needs the transaction to be chainlocked). The
 * SDK's own chain-proof helper is still never used, because it cannot express a
 * credit-output index.
 *
 * Balance assertions (finding 5): each recipient's credit delta must land within the
 * fee-adjusted expected range, or the script fails; the accrual readback alone is not
 * treated as success.
 *
 * Reuses .env.local state (MNEMONIC, IDENTITY_ID, CONTRACT_ID, FUNDER_ID) and registers a
 * second funder identity on first run (persisted as FUNDER2_ID). Wallet-funded runs create
 * a fresh random pool per run; Track C runs reuse the pool recorded for the observed
 * masternode (one pool per proTxHash, enforced by the contract).
 *
 * Env: NETWORK, DAPI_HOST[/DAPI_PORT] (same as register.cjs), REWARD_DUFFS (default 1 DASH),
 * RAIL_FUNDERS (how many funder identities to load/register, default 2), RAIL_SHARE_SPEC
 * (comma bps list for a NEW pool's shares, one per funder in order, default "6000,4000").
 *
 * Track C mode (EPOCH_OBSERVATION=<json>): the inflow is a real owner-reward payment
 * that a dips#187 shared masternode's group slot earned on the fork regtest chain, as
 * observed and exported by feature_tegara_retail_vertical.py (see ../../bridge/README.md
 * for the relay design and its stated residuals). In this mode the rail
 *   - mirrors the observed amount to a designated slot-reward address on this chain and
 *     builds the asset-lock spending EXACTLY that UTXO (in production the reward UTXO
 *     and the asset-lock share one chain, so this is the production shape),
 *   - takes the flat L1 fee off the top before the split (the fee comes out of the
 *     reward, as it would in production, not out of the wallet),
 *   - records the real proTxHash and slot index in the pool document and the observed
 *     fork epoch height in the accruals.
 * The designated address is held by the rail's own NON-wallet key (a wallet-owned
 * address would leave a phantom UTXO, see createSlotRewardUtxo). The key and the signed
 * funding transaction are persisted in the state record's slot before broadcast, and a
 * run that finds a slot with no open epoch resumes that funding instead of creating a
 * new one, so no crash window loses the mirrored funds. A wallet-funded run REFUSES to
 * start while a slot record exists, because settling would otherwise clear the slot's
 * non-wallet key and orphan the mirrored funds.
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const Dash = require("dash");
const { Transaction, PrivateKey, Script, Opcode, InstantLock } = require("@dashevo/dashcore-lib");
const walletUtils = require("@dashevo/wallet-lib").utils;
const { Identifier } = require("@dashevo/wasm-dpp");
const broadcastStateTransition = require("dash/build/SDK/Client/Platform/broadcastStateTransition").default;
const rail = require("./railState.cjs");
const { ASSET_LOCK_FEE_DUFFS, validateObservation, validateDissolution } = require("./observation.cjs");
const { fetchAll } = require("./query.cjs");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, saveEnv, activeContractId, isV3, isV4, isV5 } = require("./envStore.cjs");


const MIN_CREDITS = 40000000000;
const TOPUP_DUFFS = 300000000; // 3 DASH
const CREDITS_PER_DUFF = 1000n;
const FEE_MARGIN_CREDITS = 100000000n; // allowance for the top-up transition fee (observed ~7M)
const INSTANT_LOCK_TIMEOUT_MS = 240000;

/**
 * Read and validate a version-1 epoch observation (the Track C relay inflow). The
 * validation itself lives in observation.cjs, shared with the standalone verifier.
 *
 * NOTE: obs.operatorRewardBps is the L1 masternode operator reward, validated as
 * provenance (0 in the fork test, meaning the whole owner reward reached the shares).
 * It is NOT the pool's operatorFeeBps (the rail operator's fee recorded in the pool
 * document); the two are different roles and must never be conflated (a second-pass
 * review suggestion to merge them would have introduced exactly that bug).
 */
const loadObservation = () => {
  const pE = process.env.EPOCH_OBSERVATION;
  const pD = process.env.DISSOLUTION_OBSERVATION;
  if (pE && pD) throw new Error("set EPOCH_OBSERVATION or DISSOLUTION_OBSERVATION, not both");
  if (pE) return validateObservation(JSON.parse(fs.readFileSync(pE, "utf8")), `EPOCH_OBSERVATION ${pE}`);
  if (pD) return validateDissolution(JSON.parse(fs.readFileSync(pD, "utf8")), `DISSOLUTION_OBSERVATION ${pD}`);
  return null;
};
const isDissolution = (obs) => !!(obs && obs.kind === "dissolution");
const p2pkh = (h20) => Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), h20, Buffer.from([0x88, 0xac])]);
const DASH = (duffs) => (duffs / 100000000).toFixed(8);

/**
 * The 36-byte outpoint a chain asset-lock proof references, built by hand because the SDK's
 * getOutPointBuffer validates against tx.outputs (of which a multi-recipient asset-lock has
 * only the OP_RETURN at vout 0) and so cannot express a payload credit-output index.
 *
 *   txHashHex          the dashcore-lib .hash (display byte order); reversing it yields the
 *                      internal 32-byte order Dash proofs require.
 *   creditOutputIndex  the 0-based position in AssetLockPayload.creditOutputs, NOT a tx.vout
 *                      index. This is the index the top-up transition credits.
 *
 * Live-verified 2026-07-10 for credit-output indices 1 and 2 (a Track C resume credited two
 * funders through chain proofs and the per-recipient delta assertions matched). Index 0 (the
 * operator) has only ever been credited through the instant-lock proof, so the chain-proof
 * path for index 0 is constructed the same way but is NOT yet independently confirmed live.
 */
const creditOutputOutpoint = (txHashHex, creditOutputIndex) => {
  const idxBuf = Buffer.alloc(4);
  idxBuf.writeUInt32LE(creditOutputIndex, 0);
  return Buffer.concat([Buffer.from(txHashHex, "hex").reverse(), idxBuf]);
};

// how far below the chainlock height to search when Drive rejects a chain proof and does not
// name an acceptable height. Two independent reviews flagged the retry as brittle, so the
// window is wider than the lag observed live (1-2 blocks) with a margin.
const CHAIN_PROOF_HEIGHT_LOOKBACK = 6;

/**
 * Mirror the observed slot reward onto this chain as a single designated UTXO (Track C).
 * The asset-lock then spends exactly this UTXO, which is the production shape (there the
 * reward UTXO itself is on the same chain).
 *
 * The designated slot key is deliberately NOT a wallet key. The asset-lock that spends
 * the designated UTXO pays no wallet output, so a wallet-owned designated UTXO would
 * never be marked spent in the wallet's view; the phantom would be re-picked by later
 * coin selections and rejected with tx-txlock-conflict (observed live 2026-07-10).
 *
 * Recovery shape (review findings, 2026-07-10): the key, the signed funding transaction,
 * and the output index are persisted in state.slot BEFORE broadcast. A run that finds a
 * slot (and no open epoch) resumes that funding, rebroadcasting if needed, instead of
 * minting a new key over the old one. A slot whose amount does not match the observation
 * is refused upstream by resumeAction, never overwritten.
 */
async function createSlotRewardUtxo(client, env, state, amountDuffs) {
  const account = await client.getWalletAccount();
  const network = client.network;

  if (state.slot) {
    const slot = state.slot;
    if (slot.satoshis !== amountDuffs) {
      // resumeAction refuses this upstream; kept as a belt-and-braces invariant
      throw new Error(`the slot record holds an unfinished mirrored UTXO of ${slot.satoshis} duffs (tx ${slot.txid}); ` +
        "recover or complete that epoch before mirroring a different amount");
    }
    console.log(`resuming the mirrored slot-reward UTXO from the state record (tx ${slot.txid})`);
    // guard against a stale slot whose output was already spent (a failed final clear
    // after a completed epoch, or a hand-edited env). Spending it
    // again would build an asset-lock on a spent outpoint that only fails at broadcast,
    // leaving the slot stuck. gettxout returns null for a spent/absent output; a null
    // for a CONFIRMED funding tx means the designated output is already consumed, so
    // refuse with a recoverable message rather than building a doomed asset-lock
    // (review finding, 2026-07-10).
    const txout = await coreRpc("gettxout", [slot.txid, slot.outputIndex, true]).catch(() => undefined);
    const info = await coreRpc("getrawtransaction", [slot.txid, true]).catch(() => null);
    const confirmed = !!(info && ((info.confirmations || 0) > 0));
    if (txout === null && confirmed) {
      throw new Error(`slot output ${slot.txid}:${slot.outputIndex} is already spent; this epoch's ` +
        "asset-lock likely already went out. Verify the credits landed, then clear the slot from " +
        "RAIL_STATE in .env.local to recover.");
    }
    try {
      await client.getDAPIClient().core.broadcastTransaction(Buffer.from(slot.txHex, "hex"));
    } catch (e) {
      if (!/already|duplicate|in block|known|utxo set/i.test((e && e.message) || "")) throw e;
    }
    if (!(info && (info.instantlock || (info.confirmations || 0) > 0))) {
      await waitForIslockViaCore(slot.txid);
    }
    return {
      key: new PrivateKey(slot.wif),
      utxo: {
        txId: slot.txid,
        outputIndex: slot.outputIndex,
        satoshis: slot.satoshis,
        script: Script.buildPublicKeyHashOut(slot.address).toString(),
        address: slot.address,
      },
    };
  }

  const slotKey = new PrivateKey();
  const address = slotKey.toPublicKey().toAddress(network).toString();

  // skip outpoints recorded as consumed outside the wallet's sight (the one legacy
  // wallet-addressed designated UTXO from the first Track C epoch)
  const utxos = account.getUTXOS().filter((u) =>
    !state.consumed.includes(`${u.txId}:${u.outputIndex}`));
  const spendable = utxos.reduce((s, u) => s + u.satoshis, 0);
  if (spendable < amountDuffs + 1000000) {
    throw new Error(`spendable wallet balance ${spendable} duffs cannot mirror the ${amountDuffs}-duff ` +
      "observed reward; fund it from the dashmate seed Core wallet and mine a block");
  }

  const selection = walletUtils.coinSelection(utxos, [{ satoshis: amountDuffs, address }]);
  const tx = new Transaction()
    .from(selection.utxos)
    .to(address, amountDuffs)
    .change(account.getUnusedAddress("internal").address);
  const signingKeys = account
    .getPrivateKeys(selection.utxos.map((u) => u.address.toString()))
    .map((hd) => hd.privateKey);
  tx.sign(signingKeys);

  const outputIndex = tx.outputs.findIndex((o) =>
    o.satoshis === amountDuffs && o.script.toAddress(network).toString() === address);
  if (outputIndex < 0) throw new Error("designated slot-reward output not found in the funding transaction");

  state.slot = {
    wif: slotKey.toWIF(), txid: tx.hash, txHex: tx.serialize(true),
    outputIndex, address, satoshis: amountDuffs,
  };
  rail.save(env, state); saveEnv(env); // key + signed funding transaction persisted before broadcast
  await account.broadcastTransaction(tx);
  console.log(`slot-reward UTXO mirrored: ${DASH(amountDuffs)} DASH at ${address} (tx ${tx.hash})`);
  await waitForInstantLockOnly(client, tx.hash);
  return {
    key: slotKey,
    utxo: {
      txId: tx.hash,
      outputIndex,
      satoshis: amountDuffs,
      script: Script.buildPublicKeyHashOut(address).toString(),
      address,
    },
  };
}

/**
 * Build and sign one asset-lock transaction with one credit output per recipient.
 * Mirrors the SDK's single-output createAssetLockTransaction, generalized: a fresh one-time
 * key per credit output, one empty OP_RETURN output carrying the summed value, change back
 * to the wallet. Returns the signed transaction plus each recipient's one-time key and
 * credit-output index (the index the asset-lock proof and top-up transition reference).
 *
 * With `funding` (Track C), the transaction spends EXACTLY the designated slot-reward
 * UTXO, with no change output; the L1 fee is the difference between the UTXO and the
 * credit outputs (the caller sizes the split so that difference is ASSET_LOCK_FEE_DUFFS).
 *
 * The wallet-funded selection excludes state.consumed outpoints (spent outside the
 * wallet's sight, so the wallet still offers them). Selecting one gets the whole
 * transaction rejected with bad-txns-inputs-missingorspent, which is exactly what the
 * first post-refactor validation run hit (2026-07-10): the filter existed only in the
 * slot-mirroring path, and the legacy phantom outpoint poisoned a wallet-funded epoch.
 */
async function buildMultiRecipientAssetLock(client, recipients, state, funding = null) {
  const account = await client.getWalletAccount();
  const network = client.network;
  const total = recipients.reduce((s, r) => s + r.satoshis, 0);

  const entries = recipients.map((r, i) => {
    const oneTimeKey = new PrivateKey();
    const address = oneTimeKey.toPublicKey().toAddress(network);
    return {
      ...r,
      outputIndex: i,
      oneTimeKey,
      script: Script.buildPublicKeyHashOut(address).toString(),
    };
  });

  const payload = Transaction.Payload.AssetLockPayload.fromJSON({
    version: 1,
    creditOutputs: entries.map((e) => ({ satoshis: e.satoshis, script: e.script })),
  });

  if (funding) {
    const fee = funding.utxo.satoshis - total;
    if (fee !== ASSET_LOCK_FEE_DUFFS) {
      throw new Error(`split does not consume the designated UTXO exactly (fee would be ${fee} duffs)`);
    }
    const tx = new Transaction(undefined)
      .setType(Transaction.TYPES.TRANSACTION_ASSET_LOCK)
      .from([funding.utxo])
      .addOutput(new Transaction.Output({
        satoshis: total,
        script: new Script().add(Opcode.OP_RETURN).add(Buffer.alloc(0)),
      }))
      .setExtraPayload(payload);
    return { transaction: tx.sign([funding.key]), entries };
  }

  const utxos = account.getUTXOS().filter((u) =>
    !state.consumed.includes(`${u.txId}:${u.outputIndex}`));
  const spendable = utxos.reduce((s, u) => s + u.satoshis, 0);
  if (spendable < total + 1000000) {
    throw new Error(`spendable wallet balance ${spendable} duffs cannot cover the ${total}-duff reward inflow; ` +
      "fund it from the dashmate seed Core wallet and mine a block");
  }

  const selection = walletUtils.coinSelection(utxos, [{
    satoshis: total,
    address: entries[0].oneTimeKey.toPublicKey().toAddress(network).toString(),
  }]);

  const tx = new Transaction(undefined)
    .setType(Transaction.TYPES.TRANSACTION_ASSET_LOCK)
    .from(selection.utxos)
    .addOutput(new Transaction.Output({
      satoshis: total,
      script: new Script().add(Opcode.OP_RETURN).add(Buffer.alloc(0)),
    }))
    .change(account.getUnusedAddress("internal").address)
    .setExtraPayload(payload);

  const signingKeys = account
    .getPrivateKeys(selection.utxos.map((u) => u.address.toString()))
    .map((hd) => hd.privateKey);
  return { transaction: tx.sign(signingKeys), entries };
}

/**
 * Track C: poll the rail operator's Core node for the transaction's instant lock
 * (`getislocks`). The designated-UTXO asset-lock pays no wallet address, so the wallet's
 * transaction stream never sees it and the wallet islock path cannot be used. A rail
 * operator runs a Core node in any case (it is how the reward UTXO is observed), so
 * fetching the islock from it is the production shape, not a workaround. Also works on
 * a resume after the lock already happened, which a subscription could miss.
 */
async function coreRpc(method, params) {
  const url = process.env.CORE_RPC_URL;
  if (!url) {
    throw new Error("Track C needs CORE_RPC_URL (the rail operator's Core node, e.g. " +
      "http://user:pass@127.0.0.1:20302)");
  }
  // fetch refuses credentials inside the URL; carry them as a Basic auth header instead
  const u = new URL(url);
  const auth = u.username ? "Basic " + Buffer.from(`${u.username}:${u.password}`).toString("base64") : null;
  u.username = ""; u.password = "";
  const res = await fetch(u.toString(), {
    method: "POST",
    headers: { "content-type": "application/json", ...(auth ? { authorization: auth } : {}) },
    body: JSON.stringify({ jsonrpc: "1.0", id: "rail", method, params }),
  });
  if (!res.ok) throw new Error(`Core RPC ${method} failed: HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`Core RPC ${method} error: ${body.error.message}`);
  return body.result;
}

async function waitForIslockViaCore(txHash) {
  const deadline = Date.now() + INSTANT_LOCK_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const result = await coreRpc("getislocks", [[txHash]]);
    const hex = Array.isArray(result) && result[0] && result[0].hex;
    if (hex) return InstantLock.fromBuffer(Buffer.from(hex, "hex"));
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error("timed out waiting for the asset-lock instant lock via Core RPC; the " +
    "RAIL_STATE journal in .env.local keeps the one-time keys, so the credits remain recoverable");
}

/**
 * Wait for the transaction's instant lock through the wallet stream (wallet-funded
 * epochs and the Track C slot-funding transaction, both of which pay a wallet address).
 * No proof fallback happens HERE; on Track C epochs the chain-proof fallback lives in
 * creditFromJournal. Throws on timeout; the caller keeps the journal so nothing strands.
 */
async function waitForInstantLockOnly(client, txHash) {
  const account = await client.getWalletAccount();
  const { promise, cancel } = account.waitForInstantLock(txHash);
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          cancel();
          reject(new Error("instant-lock timeout; the RAIL_STATE journal in .env.local keeps the one-time " +
            "keys, so the credits remain recoverable (re-run to retry)"));
        }, INSTANT_LOCK_TIMEOUT_MS);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Assert every entry's credit delta against the before-balance persisted in the journal,
 * so the check holds on the fresh path AND after a resume (re-check residual of finding 5).
 */
async function assertCreditDeltas(client, entries) {
  console.log("\ncredit balance deltas (1 duff = 1000 credits; the transition fee comes out of the credited amount):");
  for (const e of entries) {
    const after = BigInt((await client.platform.identities.get(e.identityId)).getBalance());
    const delta = after - BigInt(e.beforeCredits);
    const expected = BigInt(e.satoshis) * CREDITS_PER_DUFF;
    console.log(`  ${e.label}: +${delta} credits (expected ${expected} minus fee)`);
    if (delta <= 0n || delta > expected || delta < expected - FEE_MARGIN_CREDITS) {
      throw new Error(`${e.label} credit delta ${delta} outside the expected range ` +
        `(${expected - FEE_MARGIN_CREDITS} .. ${expected})`);
    }
  }
}

/**
 * Credit every journal entry not yet credited, updating the journal after each top-up.
 * Each successful top-up records its state-transition hash (sha256 of the serialized
 * transition, the same id broadcastStateTransition waits on) in the entry, so a later
 * resume or audit can name exactly which transition credited which output instead of
 * leaning on balance deltas alone (review follow-up, 2026-07-10).
 */
async function creditFromJournal(client, env, state, transaction) {
  const journal = state.epoch;
  // Track C epochs (journal carries the observation) retrieve the islock from the
  // operator's Core node; wallet-funded epochs keep the wallet islock path. If the
  // transaction is already chainlocked or confirmed and Core no longer serves its
  // islock, proceed WITHOUT one and use chain proofs per entry (review finding,
  // 2026-07-10: the fallback must be reachable when the islock is gone, not only when
  // Drive rejects it as stale).
  let islock = null;
  if (journal.observation) {
    const info = await coreRpc("getrawtransaction", [transaction.hash, true]).catch(() => null);
    const onChain = !!(info && (info.chainlock || (info.confirmations || 0) > 0));
    if (onChain) {
      const r = await coreRpc("getislocks", [[transaction.hash]]).catch(() => null);
      const hex = Array.isArray(r) && r[0] && r[0].hex;
      islock = hex ? InstantLock.fromBuffer(Buffer.from(hex, "hex")) : null;
      if (!islock) console.log("asset-lock is on chain but its islock is no longer served; using chain proofs");
    } else {
      islock = await waitForIslockViaCore(transaction.hash);
    }
  } else {
    islock = await waitForInstantLockOnly(client, transaction.hash);
  }
  await client.platform.initialize();

  for (const e of journal.entries) {
    if (e.credited) continue;

    // idempotency, strongest evidence first (review finding F3, 2026-07-11):
    // 1. a pendingTransitionHash persisted before a broadcast names the exact transition
    //    a crashed attempt may have landed; ask Platform for that hash's result,
    // 2. only as a SANITY fallback, infer from the identity's aggregate balance delta
    //    (which unrelated credits can satisfy or break; never the primary oracle).
    const pendingHashLanded = async () => {
      if (!e.pendingTransitionHash) return false;
      try {
        const result = await Promise.race([
          client.getDAPIClient().platform.waitForStateTransitionResult(
            Buffer.from(e.pendingTransitionHash, "hex"), { prove: true }),
          new Promise((_, rej) => setTimeout(() => rej(new Error("hash-query timeout")), 15000)),
        ]);
        return !result.error;
      } catch { return false; }
    };
    const alreadyLanded = async () => {
      const bal = BigInt((await client.platform.identities.get(e.identityId)).getBalance());
      const delta = bal - BigInt(e.beforeCredits);
      const expected = BigInt(e.satoshis) * CREDITS_PER_DUFF;
      return delta >= expected - FEE_MARGIN_CREDITS && delta <= expected;
    };
    const markRecovered = () => {
      // the last persisted pending hash is the transition that landed
      e.transitionHash = e.pendingTransitionHash || null;
      e.hashProvenance = e.pendingTransitionHash ? "recovered" : "unrecorded";
      delete e.pendingTransitionHash;
    };
    const topUp = async (proof) => {
      const st = await client.platform.identities.utils.createIdentityTopUpTransition(
        proof, new PrivateKey(e.oneTimeKeyWif), Identifier.from(e.identityId),
      );
      const stHash = crypto.createHash("sha256").update(st.toBuffer()).digest("hex");
      // persist the hash BEFORE the broadcast so a crash between acceptance and the
      // journal save still leaves the transition nameable on resume
      e.pendingTransitionHash = stHash;
      rail.save(env, state); saveEnv(env);
      await broadcastStateTransition(client.platform, st, { skipValidation: true });
      // broadcastStateTransition resolves only after waitForStateTransitionResult, so
      // the recorded hash names a transition that actually landed
      e.transitionHash = stHash;
      e.hashProvenance = "confirmed";
      delete e.pendingTransitionHash;
    };

    if (await pendingHashLanded()) {
      console.log(`  ${e.label}'s previously submitted transition is proven on Platform; marking credited`);
      markRecovered();
      e.credited = true;
      rail.save(env, state); saveEnv(env);
      continue;
    }
    // The chain asset-lock proof for this credit output (outpoint built by
    // creditOutputOutpoint, see its note on byte order and which indices are live-verified).
    const chainProofTopUp = async () => {
      const chainlock = await coreRpc("getbestchainlock", []);
      const outPoint = creditOutputOutpoint(transaction.hash, e.outputIndex);
      const viaHeight = (height) =>
        topUp(client.platform.dpp.identity.createChainAssetLockProof(height, outPoint));
      // Two independent reviews flagged this retry as brittle. Build ONE ordered,
      // de-duplicated candidate list and try each: the height Drive names in the rejection
      // first (authoritative when the wording matches), then a descending window below the
      // chainlock height wide enough to absorb a larger consensus-view lag than the 1-2
      // blocks seen live. A failure at any candidate falls through to the next rather than
      // stopping; the alreadyLanded guard keeps a credited entry from being retried.
      let lastErr = null;
      const tried = new Set();
      const attempt = async (height) => {
        if (height == null || height < 0 || tried.has(height)) return false;
        tried.add(height);
        try { await viaHeight(height); return true; } catch (e2) { lastErr = e2; return false; }
      };
      // first pass at the chainlock height; if it names an acceptable height, honor it
      // next. The string parse is an OPTIMIZATION only: if Drive's error wording ever
      // changes, the descending-window loop below still finds the height (F14).
      if (await attempt(chainlock.height)) return;
      const m = ((lastErr && lastErr.message) || "").match(/current consensus core height (\d+)/);
      if (m && await attempt(parseInt(m[1], 10))) return;
      for (let back = 1; back <= CHAIN_PROOF_HEIGHT_LOOKBACK; back++) {
        if (await attempt(chainlock.height - back)) return;
      }
      throw lastErr || new Error("chain asset-lock proof rejected at every candidate height");
    };

    if (!islock) {
      if (await alreadyLanded()) {
        console.log(`  ${e.label}'s balance shows the credit landed (sanity fallback); marking and continuing`);
        markRecovered();
      } else {
        console.log(`  crediting ${e.label} with a chain asset-lock proof (credit output ${e.outputIndex})`);
        await chainProofTopUp();
      }
    } else {
      try {
        await topUp(client.platform.dpp.identity.createInstantAssetLockProof(
          islock.toBuffer(), transaction.toBuffer(), e.outputIndex));
      } catch (err) {
        const msg = (err && err.message) || "";
        const staleIslock = /instant lock proof/i.test(msg);
        // a transition rejected in an earlier resume attempt stays in the Tenderdash tx
        // cache, so an identical rebuild reports "already exists in cache" instead of
        // re-validating; both cases route to the chain-proof retry (different proof
        // bytes, so a different transition hash)
        const cachedReject = /already exists in cache/i.test(msg);
        if (!journal.observation || (!staleIslock && !cachedReject)) throw err;
        if (await alreadyLanded()) {
          console.log(`  ${e.label}'s balance shows the credit landed (sanity fallback); marking and continuing`);
          markRecovered();
        } else {
          console.log(`  islock rejected for ${e.label} (${staleIslock ? "stale" : "cached reject"}); ` +
            `retrying with the chain asset-lock proof (credit output ${e.outputIndex})`);
          await chainProofTopUp();
        }
      }
    }
    e.credited = true;
    rail.save(env, state); saveEnv(env);
    console.log(`  credited ${e.label} (output ${e.outputIndex}, ${DASH(e.satoshis)} DASH) -> identity ${e.identityId}` +
      (e.transitionHash ? ` [transition ${e.transitionHash.slice(0, 16)}... ${e.hashProvenance || ""}]`
        : " [landed in a crash window before hashes were persisted]"));
  }
}

/** Write one rewardAccrual per funder entry and verify the readback sums to the remainder. */
async function recordAndVerifyAccruals(client, env, state, operator) {
  const journal = state.epoch;
  const poolIdBuf = Identifier.from(journal.poolId).toBuffer();
  // what this epoch distributes; v4 records it in the accrual and keys the unique index
  // on it, so a reward and a principal return at the same fork height coexist (B12)
  const kind = journal.observation && journal.observation.kind === "dissolution" ? "principal" : "reward";
  if (!journal.accrualsDone) {
    // idempotent per funder: a crash after some accrual broadcasts but before
    // accrualsDone was saved must not duplicate them on resume (the contract index
    // [poolId, funderId, epochHeight] is not unique, and changing an index on the
    // registered contract is not possible; a unique index is noted for a future contract
    // version). One broadcast per document, verified live: this Platform version rejects
    // batching with "Amount of document transitions must be less or equal to 1".
    for (const e of journal.entries) {
      if (e.label === "operator") continue; // the fee is derivable from pool.operatorFeeBps
      const existing = (await client.platform.documents.get("poolLedger.rewardAccrual", {
        where: [
          ["poolId", "==", Identifier.from(journal.poolId)],
          ["funderId", "==", Identifier.from(e.identityId)],
          ["epochHeight", "==", journal.epochHeight],
        ],
        // the v4 key includes kind, so a reward and a principal return at this height
        // are DIFFERENT records; only a same-kind hit means "already recorded"
      })).filter((d) => !isV4() || d.toObject().kind === kind);
      if (existing.length > 0) {
        console.log(`rewardAccrual already recorded for ${e.label} at height ${journal.epochHeight}; skipping`);
        continue;
      }
      const doc = await client.platform.documents.create("poolLedger.rewardAccrual", operator, {
        poolId: poolIdBuf,
        funderId: Identifier.from(e.identityId).toBuffer(),
        amountDuffs: e.satoshis,
        epochHeight: journal.epochHeight,
        // v3 records the bps at distribution time, making every epoch reconstructible
        // from the ledger alone (churn or no churn); v1 rejects unknown properties.
        // v4 additionally records the kind, which is part of its unique key (B12)
        ...(isV3() ? { shareBps: e.shareBps } : {}),
        ...(isV4() ? { kind } : {}),
      });
      await client.platform.documents.broadcast({ create: [doc] }, operator);
      console.log(`rewardAccrual recorded for ${e.label}: ${e.satoshis} duffs at height ${journal.epochHeight}`);
    }
    journal.accrualsDone = true;
    rail.save(env, state); saveEnv(env);
  }

  // a pool accumulates accruals across epochs, so scope the readback to THIS epoch
  // (client-side; the index is [poolId, funderId, epochHeight] plus kind on v4, where a
  // same-height record of the OTHER kind must not leak into this epoch's sum)
  // v4 queries its dedicated byPoolHeight index (a poolId-only where is "too far from"
  // the four-property byPoolFunder index); pre-v4 keeps the poolId-only query that
  // matches the three-property index. Paged with fetchAll: a single documents.get caps
  // at 100 results, and a >100-member epoch would sum only the first page and fail an
  // otherwise-correct distribution (batch-3 review finding)
  const accruals = (await fetchAll(client, "poolLedger.rewardAccrual", {
    where: isV4()
      ? [["poolId", "==", Identifier.from(journal.poolId)], ["epochHeight", "==", journal.epochHeight]]
      : [["poolId", "==", Identifier.from(journal.poolId)]],
  })).filter((d) => Number(d.toObject().epochHeight) === journal.epochHeight
    && (!isV4() || d.toObject().kind === kind));
  const accrued = accruals.reduce((s, d) => s + Number(d.toObject().amountDuffs), 0); // fields can be BigInt
  console.log(`\nreadback (epoch ${journal.epochHeight}): ${accruals.length} accruals, sum ${accrued} duffs, distributed remainder ${journal.remainder} duffs`);
  if (accrued !== journal.remainder) {
    throw new Error("accrual readback does not match the computed distribution");
  }
}

(async () => {
  const env = loadEnv();
  if (!env.MNEMONIC || !env.IDENTITY_ID || !env.CONTRACT_ID || !env.FUNDER_ID) {
    console.error("run register.cjs and funder.cjs first (need MNEMONIC, IDENTITY_ID, CONTRACT_ID, FUNDER_ID)");
    process.exit(1);
  }

  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
    apps: { poolLedger: { contractId: activeContractId(env) } },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  const ensureCredits = async (id) => {
    if (id.getBalance() < MIN_CREDITS) {
      console.log(`  topping up ${id.getId().toString()} (credits ${id.getBalance()}) ...`);
      await client.platform.identities.topUp(id.getId(), TOPUP_DUFFS);
      return client.platform.identities.get(id.getId().toString());
    }
    return id;
  };

  try {
    // load the phase-modeled state up front; the observation decides which resume actions
    // are legal (a wallet-funded run must refuse to run over a Track C slot record)
    const state = rail.load(env);
    const obs = loadObservation();
    const decision = rail.resumeAction(state, obs ? obs.amountDuffs : null);
    console.log(`rail state phase: ${rail.derivePhase(state)}; action: ${decision.action} (${decision.reason})`);
    if (decision.action.startsWith("refuse-")) throw new Error(decision.reason);
    // an epoch journaled under one contract must never resume under another: the pool id
    // and accruals would land in the wrong ledger namespace (review finding B5)
    if (state.epoch && state.epoch.contractId && state.epoch.contractId !== activeContractId(env)) {
      throw new Error(`the open epoch journal belongs to contract ${state.epoch.contractId} but this ` +
        `run targets ${activeContractId(env)}; re-run with the matching LEDGER setting`);
    }

    // hide consumed outpoints from EVERY wallet consumer, including the SDK's internal
    // asset-lock paths (identities.register / topUp), not just this script's builder
    installConsumedFilter(await client.getWalletAccount());

    // resume an interrupted epoch before anything else; never start a new one over it. The
    // delta assertions run BEFORE any ensureCredits top-up so nothing else moves the balances,
    // and even a journal that looks fully settled has its readback re-verified before clearing
    // (re-check residual of finding 1).
    if (decision.action === "verify-settled" || decision.action === "resume-epoch") {
      const journal = state.epoch;
      if (decision.action === "verify-settled") {
        console.log("found a settled journal; verifying the accrual readback before clearing ...");
        await recordAndVerifyAccruals(client, env, state, null); // accrualsDone, so verify-only
      } else {
        console.log("RESUMING an interrupted epoch from the journal (tx", journal.txid, ")");
        const transaction = new Transaction(journal.txHex);
        // the journal is written BEFORE broadcast, so a crash in that window leaves a
        // valid signed transaction that was never sent; rebroadcast it unless it is
        // already on chain. A confirmed transaction evicted from the mempool rejects a
        // rebroadcast with bad-txns-inputs-missingorspent (its own input is spent by
        // itself), so check the chain FIRST where a Core node is available, and treat
        // that rejection as success only if the transaction is verifiably on chain.
        const txOnChain = async () => {
          if (!journal.observation) return false; // no Core RPC on wallet-funded epochs
          try {
            const info = await coreRpc("getrawtransaction", [transaction.hash, true]);
            return !!(info && (info.instantlock || info.chainlock || (info.confirmations || 0) > 0));
          } catch { return false; }
        };
        if (await txOnChain()) {
          console.log("journaled asset-lock already on chain; skipping rebroadcast");
        } else {
          try {
            await client.getDAPIClient().core.broadcastTransaction(transaction.toBuffer());
            console.log("journaled asset-lock (re)broadcast accepted");
          } catch (e) {
            const msg = (e && e.message) || "";
            const knownShape = /already|duplicate|in block|known|utxo set/i.test(msg);
            const spentButOurs = /missingorspent/i.test(msg) && await txOnChain();
            if (!knownShape && !spentButOurs) throw e;
          }
        }
        await creditFromJournal(client, env, state, transaction);
        await assertCreditDeltas(client, journal.entries);
        const operator = await ensureCredits(await client.platform.identities.get(env.IDENTITY_ID));
        await recordAndVerifyAccruals(client, env, state, operator);
      }
      rail.clearEpoch(state); rail.save(env, state); saveEnv(env);
      console.log(decision.action === "verify-settled" ? "journal verified and cleared"
        : "\n=== CREDIT-RAIL RESUMED AND COMPLETED ===");
      return;
    }

    let operator = await ensureCredits(await client.platform.identities.get(env.IDENTITY_ID));

    // the funder set is open-ended (RAIL_FUNDERS, default 2): funder1 comes from the
    // required FUNDER_ID; any funderN whose FUNDERN_ID is missing is registered and
    // persisted. All loaded funders form the owner-resolution map for reused pools, so
    // a pool whose share changed hands (membership churn) still resolves as long as the
    // new owner is one of this run's funders.
    const RAIL_FUNDERS = parseInt(process.env.RAIL_FUNDERS || "2", 10);
    if (!Number.isInteger(RAIL_FUNDERS) || RAIL_FUNDERS < 1) throw new Error("RAIL_FUNDERS must be a positive integer");
    const funderKey = (i) => (i === 1 ? "FUNDER_ID" : `FUNDER${i}_ID`);
    const funders = [];
    for (let i = 1; i <= RAIL_FUNDERS; i++) {
      const key = funderKey(i);
      let f;
      if (env[key]) {
        f = await client.platform.identities.get(env[key]);
        console.log(`funder${i} identity:`, env[key]);
      } else {
        console.log(`registering funder${i} identity ...`);
        f = await client.platform.identities.register();
        env[key] = f.getId().toString(); saveEnv(env);
        console.log(`funder${i} identity registered:`, env[key]);
      }
      funders.push({ label: `funder${i}`, identity: await ensureCredits(f) });
    }
    // two funder slots resolving to one identity would double-pay it and break the
    // one-credit-output-per-identity rule downstream (review finding F9)
    const funderIds = funders.map((f) => f.identity.getId().toString());
    if (new Set(funderIds).size !== funderIds.length) {
      throw new Error("two FUNDER*_ID entries resolve to the same identity; fix .env.local");
    }

    // Track C: the inflow is the observed slot reward from the fork chain (obs was
    // loaded and validated up front, before the resume decision)
    if (obs && isDissolution(obs)) {
      console.log(`PRINCIPAL RETURN inflow: the covenant dissolved and paid the group slot ` +
        `${DASH(obs.amountDuffs)} DASH at its immutable refund address (fork height ${obs.height}, ` +
        `dissolution ${obs.dissolutionTxid}:${obs.refundVout}, masternode ${obs.proTxHash})`);
    } else if (obs) {
      console.log(`Track C inflow: observed slot ${obs.slotIndex} reward of ${DASH(obs.amountDuffs)} DASH ` +
        `(fork height ${obs.height}, coinbase ${obs.coinbaseTxid}:${obs.rewardVout}, ` +
        `masternode ${obs.proTxHash})`);
    }

    // the pool and its recorded shares. A pool is one masternode slot and persists
    // across epochs (the contract enforces one pool per proTxHash), so a Track C run
    // REUSES the pool and shares already recorded for the observed masternode and only
    // creates them on the slot's first epoch. Wallet-funded runs keep a fresh random
    // pool per run. New pools take their share layout from RAIL_SHARE_SPEC (comma bps
    // list, one entry per funder in order, default "6000,4000"); reused pools take it
    // from the ledger itself.
    const OPERATOR_FEE_BPS = 2000;
    let poolFeeBps = OPERATOR_FEE_BPS;
    let poolId = null;
    let shareSpec = null;

    const existingPools = obs ? await client.platform.documents.get("poolLedger.pool", {
      where: [["proTxHash", "==", Buffer.from(obs.proTxHash, "hex")]],
    }) : [];
    if (existingPools.length > 0) {
      const pool = existingPools[0];
      const poolObj = pool.toObject();
      // never pay the current operator from a pool recorded for a different one
      const poolOperator = poolObj.operatorIdentityId
        ? Identifier.from(Buffer.from(poolObj.operatorIdentityId)).toString() : null;
      if (poolOperator !== operator.getId().toString()) {
        throw new Error(`reused pool's operator identity (${poolOperator}) does not match this run's ` +
          `operator (${operator.getId().toString()})`);
      }
      // the observation must describe THIS pool's slot, not another slot of the same
      // masternode (review finding B3)
      if (obs && Number(poolObj.slotIndex) !== obs.slotIndex) {
        throw new Error(`observation is for slot ${obs.slotIndex} but the pool records slot ` +
          `${Number(poolObj.slotIndex)}; refusing to distribute another slot's funds here`);
      }
      poolId = pool.getId();
      poolFeeBps = Number(poolObj.operatorFeeBps || 0);
      const byOwner = Object.fromEntries(funders.map((f) =>
        [f.identity.getId().toString(), { identity: f.identity, label: f.label }]));
      // paged: a single get caps at 100 documents, and a >100-member pool would
      // silently drop members from the split (second-model batch-3 finding)
      const shareDocs = await fetchAll(client, "poolLedger.share", {
        where: [["poolId", "==", poolId]],
      });
      shareSpec = shareDocs
        .map((d) => ({ doc: d.toObject(), owner: d.getOwnerId().toString() }))
        .sort((a, b) => Number(a.doc.$createdAt) - Number(b.doc.$createdAt))
        .map(({ doc, owner }) => {
          const known = byOwner[owner];
          if (!known) throw new Error(`pool share owned by an identity this run does not control: ${owner}`);
          return { identity: known.identity, label: known.label, shareBps: Number(doc.shareBps),
                   contributionDuffs: Number(doc.contributionDuffs) };
        });
      if (shareSpec.length === 0) throw new Error("existing pool has no recorded shares");
      // a principal return must repay exactly the capital this pool records; a validly
      // bounded observation for a DIFFERENT group share must not pay these members
      // (review finding B4). Legacy demo pools record contributions at a reduced scale,
      // hence the loudly-logged override; production pools record at slot scale.
      if (isDissolution(obs)) {
        const recorded = shareSpec.reduce((s2, x) => s2 + x.contributionDuffs, 0);
        if (recorded !== obs.shareAmountDuffs) {
          if (process.env.RAIL_ALLOW_SCALE_MISMATCH === "1") {
            console.log(`WARNING: recorded contributions (${recorded} duffs) differ from the observed ` +
              `slot principal (${obs.shareAmountDuffs} duffs); proceeding ONLY because ` +
              "RAIL_ALLOW_SCALE_MISMATCH=1 (legacy demo pool)");
          } else {
            throw new Error(`the pool records ${recorded} duffs of contributions but the dissolution ` +
              `observation says the slot principal is ${obs.shareAmountDuffs}; refusing (set ` +
              "RAIL_ALLOW_SCALE_MISMATCH=1 only for a legacy reduced-scale demo pool)");
          }
        }
      }
      console.log(`pool reused: ${poolId.toString()} (operator fee ${poolFeeBps} bps, ` +
        `${shareSpec.length} recorded shares)`);
    } else {
      if (isDissolution(obs)) {
        throw new Error("no pool recorded for this masternode; a principal return distributes to " +
          "EXISTING members and never creates a pool");
      }
      const poolDoc = await client.platform.documents.create("poolLedger.pool", operator, {
        proTxHash: obs ? Buffer.from(obs.proTxHash, "hex") : crypto.randomBytes(32),
        slotIndex: obs ? obs.slotIndex : 0,
        nodeType: "regular",
        operatorIdentityId: operator.getId().toBuffer(),
        operatorFeeBps: OPERATOR_FEE_BPS,
        // v5 requires the lifecycle field; these pools back nodes, hence live (F5)
        ...(isV5() ? { status: "live" } : {}),
      });
      await client.platform.documents.broadcast({ create: [poolDoc] }, operator);
      poolId = poolDoc.getId();
      console.log("pool created:", poolId.toString(), `(operator fee ${OPERATOR_FEE_BPS} bps)`);

      const specBps = (process.env.RAIL_SHARE_SPEC || "6000,4000").split(",").map((s) => parseInt(s, 10));
      if (specBps.length !== funders.length || specBps.some((b) => !Number.isInteger(b) || b <= 0)
        || specBps.reduce((s, b) => s + b, 0) !== 10000) {
        throw new Error("RAIL_SHARE_SPEC must be positive bps summing to 10000, EXACTLY one per funder " +
          `(got "${process.env.RAIL_SHARE_SPEC || "6000,4000"}" for ${funders.length} funders; ` +
          "set RAIL_FUNDERS to match)");
      }
      shareSpec = specBps.map((bps, i) => ({
        identity: funders[i].identity, label: funders[i].label,
        shareBps: bps, contributionDuffs: bps * 100000, // 10000 bps = 1000 DASH scale, as before
      }));
      for (const s of shareSpec) {
        const doc = await client.platform.documents.create("poolLedger.share", s.identity, {
          poolId: poolId.toBuffer(),
          shareBps: s.shareBps,
          contributionDuffs: s.contributionDuffs,
          l1RewardScript: p2pkh(crypto.randomBytes(20)),
        });
        await client.platform.documents.broadcast({ create: [doc] }, s.identity);
        console.log(`share created: ${s.shareBps} bps by ${s.identity.getId().toString()}`);
      }
    }

    // the epoch reward inflow and the split. In Track C mode the flat L1 fee comes off
    // the top (out of the reward, as in production), then the operator fee, then the
    // pro-rata funder shares.
    // idempotent replay: an epoch distributes once per pool. If this observation's
    // epoch already has accruals recorded, report and stop instead of paying it again.
    if (obs && existingPools.length > 0) {
      // v4 keys distribution events by kind as well (B12 closed): a dissolution at a
      // height that already paid a reward is NEW work, not a replay. Pre-v4, whichever
      // distributed first locks the height.
      const obsKind = isDissolution(obs) ? "principal" : "reward";
      const prior = (await fetchAll(client, "poolLedger.rewardAccrual", {
        // v4's byPoolHeight index scopes this to the exact height; pre-v4 has only the
        // three-property byPoolFunder index, which a poolId-only where still matches.
        // Paged: past the 100-document cap a single get would miss later accruals and
        // let an already-distributed epoch pay twice (batch-3 review finding)
        where: isV4()
          ? [["poolId", "==", poolId], ["epochHeight", "==", obs.height]]
          : [["poolId", "==", poolId]],
      })).filter((d) => Number(d.toObject().epochHeight) === obs.height
        && (!isV4() || d.toObject().kind === obsKind));
      if (prior.length > 0) {
        const sum = prior.reduce((s, d) => s + Number(d.toObject().amountDuffs), 0);
        console.log(`\n=== ALREADY DISTRIBUTED: fork height ${obs.height} has ${prior.length} ` +
          `${isV4() ? `"${obsKind}" ` : ""}accruals summing ${sum} duffs for this pool; ` +
          "refusing to pay it twice ===");
        // KNOWN LIMITATION on v3 and below (review batch-2, B12): a reward and a
        // dissolution CAN occur at the same fork height, and the pre-v4 accrual key
        // [poolId, funderId, epochHeight] cannot hold both. v4 fixed this at the schema
        // (kind is inside the unique key, registerV4.cjs).
        if (isDissolution(obs) && !isV4()) {
          console.log("NOTE: if these accruals are a REWARD at the same height, this principal " +
            "return cannot be recorded under the pre-v4 schema (kind is not part of the accrual " +
            "key); republish and run with LEDGER=v4");
        }
        return;
      }
    }

    const REWARD_DUFFS = obs ? obs.amountDuffs
      : parseInt(process.env.REWARD_DUFFS || "100000000", 10); // 1 DASH
    const distributable = obs ? REWARD_DUFFS - ASSET_LOCK_FEE_DUFFS : REWARD_DUFFS;
    // principal is the members' own capital coming home: the operator takes NO cut
    // (the fee bps applies to REWARDS only)
    const operatorCut = isDissolution(obs) ? 0 : Math.floor((distributable * poolFeeBps) / 10000);
    const remainder = distributable - operatorCut;
    const totalBps = shareSpec.reduce((s, x) => s + x.shareBps, 0);
    const funderCuts = shareSpec.map((s) => Math.floor((remainder * s.shareBps) / totalBps));
    funderCuts[funderCuts.length - 1] += remainder - funderCuts.reduce((s, x) => s + x, 0); // dust to last

    console.log(`\n${isDissolution(obs) ? "principal return" : "epoch reward"} inflow: ${DASH(REWARD_DUFFS)} DASH` +
      (obs ? ` (L1 fee off the top: ${DASH(ASSET_LOCK_FEE_DUFFS)} DASH)` : ""));
    console.log(`  operator fee : ${DASH(operatorCut)} DASH`);
    shareSpec.forEach((s, i) =>
      console.log(`  ${s.label} (${s.shareBps} bps): ${DASH(funderCuts[i])} DASH`));

    // recipients follow shareSpec itself (owner-resolved), never array position by
    // assumption (review finding, 2026-07-10)
    const recipients = [
      { label: "operator", identity: operator, satoshis: operatorCut, shareBps: null },
      ...shareSpec.map((s, i) => ({ label: s.label, identity: s.identity, satoshis: funderCuts[i],
        shareBps: s.shareBps })),
    ].filter((r) => r.satoshis > 0);

    // one credit output per identity per epoch: the delta assertions and the
    // already-landed resume check compare per-identity balance movement, so two outputs
    // to one identity would make both unsound (second-pass review finding; latent today
    // because the operator and funder identities are distinct, refused explicitly so it
    // stays that way). An operator who also holds a funder share must be aggregated into
    // one output upstream, not paid twice here.
    const recipientIds = recipients.map((r) => r.identity.getId().toString());
    if (new Set(recipientIds).size !== recipientIds.length) {
      throw new Error("duplicate recipient identity in the epoch split; one credit output per identity per epoch");
    }

    const before = {};
    for (const r of recipients) {
      before[r.label] = (await client.platform.identities.get(r.identity.getId().toString())).getBalance();
    }

    // in Track C mode the accruals record the fork chain's observed epoch height
    let epochHeight = obs ? obs.height : 0;
    if (!obs) {
      try { epochHeight = await client.getDAPIClient().core.getBestBlockHeight(); }
      catch { try { epochHeight = (await client.getDAPIClient().core.getBlockchainStatus()).chain.blocksCount; } catch {} }
    }

    // Track C: mirror the observed reward as the designated UTXO the asset-lock spends
    const funding = obs ? await createSlotRewardUtxo(client, env, state, REWARD_DUFFS) : null;

    // one L1 transaction credits every recipient directly; persist the journal BEFORE broadcast
    console.log("\nbuilding ONE asset-lock transaction with", recipients.length, "credit outputs ...");
    const { transaction, entries } = await buildMultiRecipientAssetLock(client, recipients, state, funding);
    state.epoch = {
      txid: transaction.hash,
      txHex: transaction.serialize(true),
      contractId: activeContractId(env), // a resume under another contract is refused (B5)
      poolId: poolId.toString(),
      remainder,
      epochHeight,
      observation: obs ? {
        kind: obs.kind || "epoch",
        proTxHash: obs.proTxHash,
        slotIndex: obs.slotIndex,
        height: obs.height,
        sourceTxid: isDissolution(obs) ? obs.dissolutionTxid : obs.coinbaseTxid,
        sourceVout: isDissolution(obs) ? obs.refundVout : obs.rewardVout,
        amountDuffs: obs.amountDuffs,
        network: obs.network,
      } : null,
      accrualsDone: false,
      entries: entries.map((e) => ({
        label: e.label,
        identityId: e.identity.getId().toString(),
        satoshis: e.satoshis,
        outputIndex: e.outputIndex,
        oneTimeKeyWif: e.oneTimeKey.toWIF(),
        beforeCredits: String(before[e.label]), // so a resume can still assert the delta
        shareBps: e.shareBps || null, // recorded in the v3 accrual (reconstructible epochs)
        credited: false,
        transitionHash: null, // set by the successful top-up
      })),
    };
    rail.save(env, state); saveEnv(env);

    // The designated-UTXO asset-lock pays no wallet address, so the wallet's propagation
    // wait would never see it; broadcast it through DAPI directly. Wallet-funded epochs
    // keep the wallet broadcast (its change output makes the wallet see the transaction).
    if (funding) {
      await client.getDAPIClient().core.broadcastTransaction(transaction.toBuffer());
    } else {
      const account = await client.getWalletAccount();
      await account.broadcastTransaction(transaction);
    }
    console.log("asset-lock broadcast:", transaction.hash, "(journal persisted first)");

    await creditFromJournal(client, env, state, transaction);

    // every recipient's delta must land in the fee-adjusted expected range
    await assertCreditDeltas(client, state.epoch.entries);

    await recordAndVerifyAccruals(client, env, state, operator);
    rail.clearEpoch(state); rail.save(env, state); saveEnv(env); // epoch fully settled

    console.log("\n=== CREDIT-RAIL OK: one asset-lock, every recipient credited directly, ledger consistent ===");
    if (obs && isDissolution(obs)) {
      console.log(`=== PRINCIPAL RETURN: the covenant refund of ${DASH(obs.amountDuffs)} DASH from masternode ` +
        `${obs.proTxHash.slice(0, 16)}... was distributed to the pool's recorded members directly, no operator cut ===`);
    } else if (obs) {
      console.log(`=== TRACK C: the inflow was the slot ${obs.slotIndex} owner reward the shared masternode ` +
        `${obs.proTxHash.slice(0, 16)}... earned at fork height ${obs.height}, spent as one designated UTXO ===`);
    }
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
