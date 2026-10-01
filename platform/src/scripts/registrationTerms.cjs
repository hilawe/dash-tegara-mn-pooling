"use strict";
/**
 * THE REGISTRATION TERMS IN THE CHAIN'S OWN SHAPES (the #7437 format unit, 2026-10-01, Hilawe's decision:
 * a version-2 agreement in the chain's shapes). What a member signs is exactly what
 * `protx shared_register_prepare` registers, in the units consensus stores, so nothing is translated
 * between the approval and the registration:
 *
 *   terms = {
 *     shares: [{ amount, ownerAddress, refundAddress, rewardAddress? }],   amounts in duffs; rewardAddress
 *                                                                          ABSENT when omitted (never null or "")
 *     operatorPubKey, votingAddress,
 *     operatorRewardBps,          0 to 10000, the uint16 consensus stores (the RPC takes "5.25", two decimals)
 *     earlyPeriodBlocks,          0 to 420480
 *     earlyPenalty,               duffs, below the smallest share, and 0 when the period is 0
 *   }
 *
 * THE INVARIANT (Hilawe, 2026-10-01): exact agreement between the member-signed terms and the decoded
 * registration, units and defaults included. `agreementWithDecoded` compares every share and term with what
 * the node decoded, in the chain's units: the reward in basis points against the decoded percentage (which
 * the chain formats with at most two decimals, so x100 is exact), and the reward DESTINATION of each share
 * against the decoded reward address, which for an omitted reward is the refund address. The decoded
 * payload reports where rewards go, not whether the serialized script was empty (measured on rc.1, where an
 * omitted reward decodes with the refund address and script in both fields), so the invariant is about
 * destinations, and an "omitted" in the terms is the member's intent recorded, equal to the refund.
 *
 * THE RULES are the chain's (providertx.cpp at the #7437 merge, IsShareListTriviallyValid and the RPC's
 * parsing), and each refusal here names the chain's own reason, as the rc.1 exercise recorded it
 * (fixtures/registration-terms-rc1.json). Display conversion is exact in both directions: 525 <-> "5.25".
 *
 * PURE. Address checks use dashcore-lib with the network given (testnet and regtest share one address
 * format; mainnet is refused until a mainnet pin exists).
 */
const L = require("@dashevo/dashcore-lib");

const COIN = 100000000;
const COLLATERAL = 1000 * COIN;
const MIN_SHARE = 100 * COIN;
const MIN_SHARES = 2, MAX_SHARES = 8;
const MAX_BPS = 10000;
const MAX_EARLY_PERIOD_BLOCKS = 420480;
const BLS_PUBKEY = /^[0-9a-f]{96}$/;
const TERMS_KEYS = Object.freeze(["shares", "operatorPubKey", "votingAddress", "operatorRewardBps", "earlyPeriodBlocks", "earlyPenalty"]);
const SHARE_KEYS = Object.freeze(["amount", "ownerAddress", "refundAddress", "rewardAddress"]);
const isInt = (v) => Number.isSafeInteger(v);
class TermsRefusal extends Error { constructor(why, reason) { super(why); this.reason = reason; } }
const refuse = (why, reason) => { throw new TermsRefusal(why, reason); };

const NETWORKS = Object.freeze({ testnet: "testnet", regtest: "testnet" });
function addressKind(v, network) {
  const net = NETWORKS[network];
  if (!net) refuse(`no address rules are pinned for network ${network}`, "network");
  if (typeof v !== "string") return null;
  let a;
  try { a = new L.Address(v, net); } catch { return null; }
  if (a.toString() !== v) return null;
  return a.isPayToPublicKeyHash() ? "p2pkh" : a.isPayToScriptHash() ? "p2sh" : null;
}
const scriptHexOf = (address, network) => L.Script.fromAddress(new L.Address(address, NETWORKS[network])).toHex();
/** The script of an address, or null when the address is not one of this network's (the invariant names that rather than throwing). */
const scriptHexOrNull = (address, network) => { try { return addressKind(address, network) ? scriptHexOf(address, network) : null; } catch { return null; } };

/** The reward destination of a share: its reward address when it carries one, else its refund address. */
const rewardDestination = (share) => (Object.hasOwn(share, "rewardAddress") ? share.rewardAddress : share.refundAddress);

/** 525 -> "5.25", the exact form the RPC takes; refuses anything but an integer 0..10000. */
function bpsToPercentText(bps) {
  if (!isInt(bps) || bps < 0 || bps > MAX_BPS) refuse(`the operator reward ${bps} is not 0 to 10000 basis points`, "operatorReward");
  return `${Math.floor(bps / 100)}.${String(bps % 100).padStart(2, "0")}`;
}
/** "5.25" -> 525, exact; at most two decimals; null when the text is not such a number. */
function percentTextToBps(text) {
  const m = /^(\d{1,3})(?:\.(\d{1,2}))?$/.exec(String(text).trim());
  if (!m) return null;
  const bps = Number(m[1]) * 100 + Number((m[2] || "").padEnd(2, "0"));
  return bps <= MAX_BPS ? bps : null;
}
/**
 * The decoded payload's operatorReward as basis points, exact, or null for any NUMBER the chain cannot
 * produce. The chain reports (basis points / 100) as a JSON number and nothing else is read: parsed, that
 * is the double nearest to a two-decimal value, whose shortest text IS that two-decimal value (checked over
 * all 10,001 of them), so the number's shortest text goes through the same strict two-decimal reading as
 * typed input. Any other number (5.250000001, a negative, more than two decimals) and any other type (a
 * string, null, a boolean) is refused rather than rounded or coerced; a review found the earlier tolerance
 * accepted 5.250000001 as 525, and its confirmation found a string branch accepting "005.25".
 */
function decodedPercentToBps(v) {
  if (typeof v === "number") return Number.isFinite(v) && !Object.is(v, -0) ? percentTextToBps(String(v)) : null;
  return null; // strings, null, undefined, booleans and objects are not an answer (Number(null) would be 0)
}

/** The terms' shape and the chain's rules. Returns the terms, or throws TermsRefusal naming the chain's reason. */
function requireTerms(t, { network = "testnet" } = {}) {
  if (!t || typeof t !== "object" || Array.isArray(t)) refuse("the terms are not an object", "shape");
  const extra = Object.keys(t).filter((k) => !TERMS_KEYS.includes(k));
  const missing = TERMS_KEYS.filter((k) => !Object.hasOwn(t, k));
  if (extra.length || missing.length) refuse(`the terms' fields are not the registration set (extra ${extra.join(",") || "none"}, missing ${missing.join(",") || "none"})`, "shape");
  if (!Array.isArray(t.shares)) refuse("the share table is not a list", "shape");
  if (t.shares.length < MIN_SHARES || t.shares.length > MAX_SHARES) refuse(`the share table has ${t.shares.length} shares, not ${MIN_SHARES} to ${MAX_SHARES}`, "bad-protx-shares-count");
  if (typeof t.operatorPubKey !== "string" || !BLS_PUBKEY.test(t.operatorPubKey)) refuse("the operator key is not a 96-character lowercase hex public key", "operatorPubKey");
  if (addressKind(t.votingAddress, network) !== "p2pkh") refuse("the voting address is not a P2PKH address", "votingAddress");
  if (!isInt(t.operatorRewardBps) || t.operatorRewardBps < 0 || t.operatorRewardBps > MAX_BPS) refuse(`the operator reward ${t.operatorRewardBps} is not 0 to 10000 basis points`, "operatorReward");
  if (!isInt(t.earlyPeriodBlocks) || t.earlyPeriodBlocks < 0 || t.earlyPeriodBlocks > MAX_EARLY_PERIOD_BLOCKS) refuse(`the early-exit period ${t.earlyPeriodBlocks} is not 0 to ${MAX_EARLY_PERIOD_BLOCKS} blocks`, "bad-protx-shares-early-period");
  let total = 0, min = Infinity;
  const owners = new Set(), refunds = new Set();
  t.shares.forEach((s, i) => {
    const n = i + 1;
    if (!s || typeof s !== "object" || Array.isArray(s)) refuse(`share ${n} is not an object`, "shape");
    const ex = Object.keys(s).filter((k) => !SHARE_KEYS.includes(k));
    if (ex.length) refuse(`share ${n} carries a field the registration does not take, ${ex.join(",")}`, "shape");
    if (!isInt(s.amount) || s.amount < MIN_SHARE || s.amount > COLLATERAL) refuse(`share ${n}'s amount is not a whole amount of at least 100 DASH`, "bad-protx-shares-amount");
    total += s.amount; min = Math.min(min, s.amount);
    if (addressKind(s.ownerAddress, network) !== "p2pkh") refuse(`share ${n}'s owner address is not a P2PKH address`, "ownerAddress");
    if (owners.has(s.ownerAddress)) refuse(`shares share one owner key (${s.ownerAddress})`, "bad-protx-shares-dup-key");
    owners.add(s.ownerAddress);
    const rk = addressKind(s.refundAddress, network);
    if (rk !== "p2pkh" && rk !== "p2sh") refuse(`share ${n}'s refund address is not a P2PKH or P2SH address`, "bad-protx-shares-payee");
    if (refunds.has(s.refundAddress)) refuse(`shares share one refund script (${s.refundAddress})`, "bad-protx-shares-dup-refund");
    refunds.add(s.refundAddress);
    if (Object.hasOwn(s, "rewardAddress")) {
      const kk = addressKind(s.rewardAddress, network);
      if (kk !== "p2pkh" && kk !== "p2sh") refuse(`share ${n}'s reward address is not a P2PKH or P2SH address (leave it out to use the refund address)`, "bad-protx-shares-payee");
    }
  });
  // no refund or reward destination may pay an owner key or the voting key
  for (const [i, s] of t.shares.entries()) {
    for (const [what, a] of [["refund", s.refundAddress], ["reward", rewardDestination(s)]]) {
      if (a === t.votingAddress) refuse(`share ${i + 1}'s ${what} address pays the voting key`, "bad-protx-shares-payee-reuse");
      if (owners.has(a)) refuse(`share ${i + 1}'s ${what} address pays a share owner key`, "bad-protx-shares-payee-reuse");
    }
  }
  if (total !== COLLATERAL) refuse(`the shares add up to ${total} duffs, not the ${COLLATERAL} a regular masternode needs`, "bad-protx-shares-amount-sum");
  if (!isInt(t.earlyPenalty) || t.earlyPenalty < 0 || t.earlyPenalty >= min) refuse(`the early-exit penalty ${t.earlyPenalty} is not below the smallest share (${min})`, "bad-protx-shares-penalty");
  if (t.earlyPeriodBlocks === 0 && t.earlyPenalty !== 0) refuse("the early-exit penalty must be 0 when the early period is 0", "bad-protx-shares-penalty");
  return t;
}

/** The arguments `protx shared_register_prepare` takes, from the terms, exactly (the harness derives the registration from these). */
function rpcArgs(t) {
  requireTerms(t);
  return { shares: t.shares.map((s) => ({ amount: s.amount, refundAddress: s.refundAddress, ...(Object.hasOwn(s, "rewardAddress") ? { rewardAddress: s.rewardAddress } : {}), ownerAddress: s.ownerAddress })),
    coreP2PAddrs: "", operatorPubKey: t.operatorPubKey, votingAddress: t.votingAddress, operatorReward: bpsToPercentText(t.operatorRewardBps),
    earlyPeriodBlocks: t.earlyPeriodBlocks, earlyPenalty: t.earlyPenalty };
}

/**
 * THE INVARIANT. decoded: the `proRegTx` object of `decoderawtransaction`, or the `state` of `protx info` with
 * its `operatorReward` beside it. Returns { ok, differences: [text] }, every difference named, none hidden.
 */
function agreementWithDecoded({ terms, decoded, network = "testnet" }) {
  const d = [];
  const t = requireTerms(terms, { network });
  const pro = decoded && typeof decoded === "object" ? decoded : {};
  const shares = Array.isArray(pro.shares) ? pro.shares : [];
  if (shares.length !== t.shares.length) d.push(`the registration has ${shares.length} shares, the signed terms ${t.shares.length}`);
  t.shares.forEach((s, i) => {
    const r = shares[i];
    // a share the decoding does not report is a difference, never a share with nothing to compare (a review
    // found a null in the decoded table reported as exact agreement)
    if (!r || typeof r !== "object" || Array.isArray(r)) { d.push(`share ${i + 1}: the registration reports no share ${i + 1}`); return; }
    if (String(r.amount) !== String(s.amount)) d.push(`share ${i + 1}: registered amount ${r.amount}, signed ${s.amount}`);
    if (r.ownerAddress !== s.ownerAddress) d.push(`share ${i + 1}: registered owner ${r.ownerAddress}, signed ${s.ownerAddress}`);
    if (r.refundAddress !== s.refundAddress) d.push(`share ${i + 1}: registered refund address ${r.refundAddress}, signed ${s.refundAddress}`);
    const want = rewardDestination(s);
    if (typeof want !== "string" || !want) d.push(`share ${i + 1}: the signed terms name no reward destination`);
    else if (r.rewardAddress !== want) d.push(`share ${i + 1}: rewards go to ${r.rewardAddress}, the signed terms send them to ${want}${Object.hasOwn(s, "rewardAddress") ? "" : " (the refund address, no reward address given)"}`);
    if (typeof r.refundScript === "string" && r.refundScript !== scriptHexOrNull(s.refundAddress, network)) d.push(`share ${i + 1}: the registered refund script is not the signed refund address's`);
    if (typeof r.rewardScript === "string" && r.rewardScript !== scriptHexOrNull(want, network)) d.push(`share ${i + 1}: the registered reward script is not the signed destination's`);
  });
  const bps = decodedPercentToBps(pro.operatorReward);
  if (bps === null) d.push(`the registered operator reward ${JSON.stringify(pro.operatorReward)} is not a percentage with two decimals`);
  else if (bps !== t.operatorRewardBps) d.push(`registered operator reward ${bps} basis points, signed ${t.operatorRewardBps}`);
  if (String(pro.earlyPeriodBlocks) !== String(t.earlyPeriodBlocks)) d.push(`registered early-exit period ${pro.earlyPeriodBlocks}, signed ${t.earlyPeriodBlocks}`);
  if (String(pro.earlyPenalty) !== String(t.earlyPenalty)) d.push(`registered early-exit penalty ${pro.earlyPenalty}, signed ${t.earlyPenalty}`);
  if (pro.pubKeyOperator !== t.operatorPubKey) d.push("the registered operator key is not the signed one");
  if (pro.votingAddress !== t.votingAddress) d.push("the registered voting address is not the signed one");
  return { ok: d.length === 0, differences: d };
}

/** The terms in words, every value shown in exact display conversion. */
function displayTerms(t) {
  requireTerms(t);
  return { operatorReward: `${bpsToPercentText(t.operatorRewardBps)}% (${t.operatorRewardBps} of 10,000 basis points)`,
    shares: t.shares.map((s, i) => ({ number: i + 1, amount: s.amount, ownerAddress: s.ownerAddress, refundAddress: s.refundAddress,
      rewardsGoTo: Object.hasOwn(s, "rewardAddress") ? s.rewardAddress : `${s.refundAddress} (the refund address; no separate reward address)`,
      rewardAddressGiven: Object.hasOwn(s, "rewardAddress") })) };
}

module.exports = { COIN, COLLATERAL, MIN_SHARE, MIN_SHARES, MAX_SHARES, MAX_BPS, MAX_EARLY_PERIOD_BLOCKS, TERMS_KEYS, SHARE_KEYS,
  requireTerms, rpcArgs, agreementWithDecoded, displayTerms, rewardDestination, bpsToPercentText, percentTextToBps, decodedPercentToBps,
  addressKind, scriptHexOf, TermsRefusal };
