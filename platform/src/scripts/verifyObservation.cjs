/**
 * Standalone verifier for a Track C epoch observation (review follow-up, 2026-07-10).
 * The relay file is the trusted input of the credit-rail, so this tool lets an operator
 * check one independently before feeding it in.
 *
 * Two layers:
 *   offline (always)      schema and cross-field validation (shared with the rail via
 *                         observation.cjs), plus a recomputation of the DIP-0026
 *                         amount-weighted slot amount from the observation's own fields.
 *   live (FORK_RPC_URL)   checks the observation against the fork chain it claims to
 *                         describe: the coinbase transaction exists in the named block,
 *                         pays the named script and amount at the named vout, the block
 *                         height matches, and the masternode's DMN state (protx info,
 *                         which exposes the #187 share table) agrees on the slot amount,
 *                         the reward address, the collateral sum, and the registration
 *                         height.
 *
 * Run: node src/scripts/verifyObservation.cjs <observation.json> [more.json ...]
 *      FORK_RPC_URL=http://user:pass@127.0.0.1:18332 adds the live layer.
 * Exits non-zero if any file fails.
 */
const fs = require("fs");
const { validateObservation, expectedSlotAmount, exactSlotAmounts } = require("./observation.cjs");

const forkRpc = async (method, params) => {
  const u = new URL(process.env.FORK_RPC_URL);
  const auth = u.username ? "Basic " + Buffer.from(`${u.username}:${u.password}`).toString("base64") : null;
  u.username = ""; u.password = "";
  const res = await fetch(u.toString(), {
    method: "POST",
    headers: { "content-type": "application/json", ...(auth ? { authorization: auth } : {}) },
    body: JSON.stringify({ jsonrpc: "1.0", id: "verify", method, params }),
  });
  if (!res.ok) throw new Error(`fork RPC ${method} failed: HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`fork RPC ${method} error: ${body.error.message}`);
  return body.result;
};

const checkOffline = (obs) => {
  validateObservation(obs, "observation");
  const notes = [];
  // recompute the DIP-0026 amount-weighted slot amount from the observation's own
  // fields. A non-last slot gets the exact floor; the last slot absorbs the rounding
  // remainder, so a small excess over the floor is reported, not failed (without the
  // share table the slot's position is unknown offline; the live layer pins it down).
  const { ownerReward, floor } = expectedSlotAmount(obs);
  // the last slot absorbs the rounding remainder, but that remainder is tightly bounded:
  // each other slot loses under 1 duff to its floor and #187 allows at most 8
  // participants, so the excess over the floor can never reach 8 duffs
  const MAX_REMAINDER_DUFFS = 7;
  if (obs.amountDuffs === floor) {
    notes.push(`amount matches the amount-weighted floor exactly (${floor} duffs of ${ownerReward} owner reward)`);
  } else if (obs.amountDuffs > floor && obs.amountDuffs - floor <= MAX_REMAINDER_DUFFS) {
    notes.push(`amount is ${obs.amountDuffs - floor} duffs above the floor (consistent with a ` +
      "last-slot rounding remainder; the live layer can confirm the slot's position)");
  } else {
    throw new Error(`amountDuffs ${obs.amountDuffs} is inconsistent with the amount-weighted split ` +
      `(floor ${floor} from share ${obs.shareAmountDuffs}/${obs.collateralDuffs} of ${ownerReward}; ` +
      `a rounding remainder cannot exceed ${MAX_REMAINDER_DUFFS} duffs)`);
  }
  return notes;
};

const checkLive = async (obs) => {
  const notes = [];
  const fail = (why) => { throw new Error(`live check failed (${why})`); };

  const tx = await forkRpc("getrawtransaction", [obs.coinbaseTxid, true, obs.blockHash]);
  if (tx.blockhash !== obs.blockHash) fail("coinbase not in the named block");
  // the named transaction must BE the block's coinbase, not merely a transaction in the
  // block: position 0 in the block's tx list AND a coinbase-shaped sole input (review
  // finding F6, 2026-07-11; an ordinary same-block transaction passed the old checks)
  const isCoinbaseShaped = Array.isArray(tx.vin) && tx.vin.length === 1 && tx.vin[0].coinbase !== undefined;
  if (!isCoinbaseShaped) fail("the named transaction does not have a coinbase-shaped input");
  const vout = tx.vout && tx.vout[obs.rewardVout];
  if (!vout) fail(`coinbase has no vout ${obs.rewardVout}`);
  const paidDuffs = Math.round(vout.value * 100000000);
  if (paidDuffs !== obs.amountDuffs) fail(`vout pays ${paidDuffs} duffs, observation says ${obs.amountDuffs}`);
  if (vout.scriptPubKey.hex !== obs.rewardScriptHex.toLowerCase()) fail("reward script differs");
  const voutAddresses = vout.scriptPubKey.addresses || (vout.scriptPubKey.address ? [vout.scriptPubKey.address] : []);
  if (!voutAddresses.includes(obs.rewardAddress)) fail("reward address differs");
  notes.push(`coinbase ${obs.coinbaseTxid.slice(0, 16)}... vout ${obs.rewardVout} pays exactly ` +
    `${obs.amountDuffs} duffs to the named script`);

  const block = await forkRpc("getblock", [obs.blockHash]);
  if (block.height !== obs.height) fail(`block height ${block.height} differs from observed ${obs.height}`);
  if (!Array.isArray(block.tx) || block.tx[0] !== obs.coinbaseTxid) {
    fail("the named transaction is not the block's coinbase (tx[0] differs)");
  }
  notes.push(`block ${obs.blockHash.slice(0, 16)}... is at the observed height ${obs.height} ` +
    "and names the transaction as its coinbase");

  // the DMN state is read AT THE EPOCH'S BLOCK, so the check pins the state that earned
  // the reward and still works after the masternode dissolves
  const info = await forkRpc("protx", ["info", obs.proTxHash, obs.blockHash]);
  const st = info.state || {};
  if (st.registeredHeight !== obs.registeredHeight) {
    fail(`DMN state registeredHeight ${st.registeredHeight} differs from observed ${obs.registeredHeight}`);
  }
  const shares = st.shares;
  if (!Array.isArray(shares) || shares.length === 0) fail("DMN state carries no share table (not a shared masternode?)");
  const share = shares[obs.slotIndex];
  if (!share) fail(`share table has no slot ${obs.slotIndex}`);
  if (share.amount !== obs.shareAmountDuffs) {
    fail(`slot ${obs.slotIndex} share is ${share.amount} duffs, observation says ${obs.shareAmountDuffs}`);
  }
  if (share.rewardAddress && share.rewardAddress !== obs.rewardAddress) {
    fail(`slot ${obs.slotIndex} designated reward address ${share.rewardAddress} differs from ${obs.rewardAddress}`);
  }
  const collateralSum = shares.reduce((s, x) => s + x.amount, 0);
  if (collateralSum !== obs.collateralDuffs) {
    fail(`share table sums to ${collateralSum} duffs, observation says collateral ${obs.collateralDuffs}`);
  }
  // with the full share table in hand, EVERY slot's amount is exact: BigInt floors per
  // share, the rounding remainder to the last slot, and the observed slot must equal its
  // entry precisely (review finding F5, 2026-07-11; the old check let a last slot sit
  // anywhere in floor..floor+7)
  const { ownerReward } = expectedSlotAmount(obs);
  const exact = exactSlotAmounts(ownerReward, shares.map((x) => x.amount));
  if (obs.amountDuffs !== exact[obs.slotIndex]) {
    fail(`slot ${obs.slotIndex} must earn exactly ${exact[obs.slotIndex]} duffs by the ` +
      `amount-weighted split of ${ownerReward}, observation says ${obs.amountDuffs}`);
  }
  const isLast = obs.slotIndex === shares.length - 1;
  notes.push(`DMN share table agrees: slot ${obs.slotIndex} of ${shares.length} holds ` +
    `${share.amount} of ${collateralSum} duffs, exact amount ${exact[obs.slotIndex]} confirmed` +
    (isLast ? " (last slot, includes the rounding remainder)" : ""));
  return notes;
};

(async () => {
  const files = process.argv.slice(2);
  if (files.length === 0) {
    console.error("usage: node src/scripts/verifyObservation.cjs <observation.json> [more.json ...]");
    console.error("       FORK_RPC_URL=http://user:pass@host:port adds the live fork-chain layer");
    process.exit(2);
  }
  let failed = 0;
  for (const f of files) {
    try {
      const obs = JSON.parse(fs.readFileSync(f, "utf8"));
      const notes = checkOffline(obs);
      if (process.env.FORK_RPC_URL) notes.push(...await checkLive(obs));
      console.log(`PASS ${f}${process.env.FORK_RPC_URL ? "" : " (offline layer only)"}`);
      for (const n of notes) console.log(`     ${n}`);
    } catch (e) {
      failed++;
      console.error(`FAIL ${f}\n     ${(e && e.message) || e}`);
    }
  }
  if (failed > 0) process.exit(1);
})();
