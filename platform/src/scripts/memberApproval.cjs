"use strict";
/**
 * MEMBER APPROVAL OF CO-OWNER TERMS (tegara/docs/MEMBER_APPROVAL_DESIGN.md, formation unit 2).
 *
 * A member's terms count at completion only when the member's layer-1 owner key AND its Platform
 * identity have both signed one approval record for this pool, contract and chains, the
 * registration confirmed within the record's window, and the record is that member's highest
 * revision among those presented. Completion then compares the registration with exactly those
 * approved terms through `coownerCompletion.decideCompletion`, unchanged. This replaces the fixture
 * that tied a terms file to an identity in unit 1.
 *
 * PURE. The signature check and the identity keys are supplied: `verifyMessage(address, message,
 * signatureBase64) -> bool` (Dash's signed-message scheme), `addressOfPubkey(hex) -> address`,
 * `scriptOfAddress(address) -> hex`, and the identity keys as the runner read them by proof.
 *
 * WHAT A PASS ESTABLISHES: the holders of the owner key and of the identity key both approved these
 * exact terms for this pool within the window. NOT that two members are two people, only two sets of
 * keys, and not that the approval is stored anywhere on Platform.
 *
 * TWO RECORD VERSIONS (the #7437 format unit, 2026-10-01). VERSION 1 is read and verified exactly as it
 * was written, its agreement in the member tool's first shape (a whole-percent operator reward, every
 * share with a reward address) and its signatures over the version-1 message; nothing in it is
 * reinterpreted, and the three approvals of the testnet trial stay readable. VERSION 2 is the only
 * version written: its agreement carries the registration terms in the chain's own shapes
 * (registrationTerms.cjs: amounts in duffs, the operator reward in basis points, the reward address
 * optional and defaulting to the refund address, the chain's bounds) beside the member's own position
 * and fee share, and at completion the signed terms are compared with the registration as the node
 * decoded it by the invariant in registrationTerms.agreementWithDecoded, units and defaults included.
 * The message each version signs carries its own prefix, so a version-2 record can never verify under
 * a version-1 signature or the reverse.
 */
const crypto = require("crypto");
const { canonicalString } = require("./canonicalJson.cjs");
const completion = require("./coownerCompletion.cjs");
const formationCore = require("./formationCore.cjs");
const terms = require("./registrationTerms.cjs");

const DOMAIN = "tegara.coowner.termsApproval";
const VERSION = 1;          // the first version, read and verified as written
const VERSION_2 = 2;
const VERSION_WRITE = 2;    // the only version new approvals are written in
const PREFIX = "tegara co-owner terms approval v1 ";
const PREFIX_BY_VERSION = Object.freeze({ 1: PREFIX, 2: "tegara co-owner terms approval v2 " });
const AGREEMENT_V2_KEYS = Object.freeze(["registration", "myIndex", "myFeeDuffs"]);
// the address rules a Platform chain's layer 1 uses (testnet and regtest share one address format)
const NETWORK_BY_CHAIN = Object.freeze({ "dash-testnet-51": "testnet" });
const networkOfChain = (chainId) => NETWORK_BY_CHAIN[chainId] || (/regtest|local/.test(String(chainId)) ? "regtest" : null);
const HEX64 = /^[0-9a-f]{64}$/;
const isInt = (v) => Number.isSafeInteger(v);
class ApprovalRefusal extends Error {}
const refuse = (why) => { throw new ApprovalRefusal(why); };

const RECORD_KEYS = ["domain", "version", "platformChainId", "contractId", "poolId", "l1GenesisHash",
  "memberIdentity", "revision", "notAfterHeight", "agreement"];

/** The record's shape, refused rather than repaired: version 1 as it was always checked, version 2 by the chain's rules. */
function requireRecord(r) {
  if (!r || typeof r !== "object") refuse("the approval carries no record");
  const extra = Object.keys(r).filter((k) => !RECORD_KEYS.includes(k));
  const missing = RECORD_KEYS.filter((k) => !(k in r));
  if (extra.length || missing.length) refuse(`the record's fields are not the approval set (extra ${extra.join(",") || "none"}, missing ${missing.join(",") || "none"})`);
  if (r.domain !== DOMAIN || (r.version !== VERSION && r.version !== VERSION_2)) refuse("the record is not a version-1 or version-2 co-owner terms approval");
  for (const k of ["poolId", "l1GenesisHash", "memberIdentity"]) if (!HEX64.test(r[k])) refuse(`the record's ${k} is not 64 lowercase hex`);
  if (!isInt(r.revision) || r.revision < 1) refuse("the record's revision is not a positive integer");
  if (!isInt(r.notAfterHeight) || r.notAfterHeight < 0) refuse("the record's notAfterHeight is not a height");
  const a = r.agreement;
  if (r.version === VERSION) {
    if (!a || !Array.isArray(a.shares) || !isInt(a.myIndex) || !a.shares[a.myIndex]) refuse("the record's agreement names no share for this member");
    return r;
  }
  if (!a || typeof a !== "object" || Array.isArray(a)) refuse("the version-2 record's agreement is not an object");
  const ex = Object.keys(a).filter((k) => !AGREEMENT_V2_KEYS.includes(k)), mi = AGREEMENT_V2_KEYS.filter((k) => !Object.hasOwn(a, k));
  if (ex.length || mi.length) refuse(`the version-2 agreement's fields are not registration, myIndex, myFeeDuffs (extra ${ex.join(",") || "none"}, missing ${mi.join(",") || "none"})`);
  const network = networkOfChain(r.platformChainId);
  if (!network) refuse(`no address rules are pinned for Platform chain ${r.platformChainId}`);
  try { terms.requireTerms(a.registration, { network }); } catch (e) { if (e instanceof terms.TermsRefusal) refuse(`the registration terms are not ones the chain accepts (${e.reason}): ${e.message}`); throw e; }
  if (!isInt(a.myIndex) || !a.registration.shares[a.myIndex]) refuse("the version-2 agreement names no share for this member");
  if (!isInt(a.myFeeDuffs) || a.myFeeDuffs < 0) refuse("the version-2 agreement's fee share is not a whole amount");
  return r;
}

/** The exact message both keys sign; each version has its own prefix. */
function messageFor(record) {
  const r = requireRecord(record);
  return PREFIX_BY_VERSION[r.version] + crypto.createHash("sha256").update(canonicalString(r)).digest("hex");
}

/** The member's own share of a checked record, whichever version. */
const shareOf = (r) => (r.version === VERSION_2 ? r.agreement.registration.shares[r.agreement.myIndex] : r.agreement.shares[r.agreement.myIndex]);

/**
 * One view of a checked record's agreement for display and for the completion's claim logic, whichever
 * version: shares with their effective reward destination, the terms, the reward as text (and in basis
 * points for version 2), and the member's position and fee share. A version-1 agreement is shown, not
 * reinterpreted: its reward is shown as it was written and carries NO basis points, so nothing can compare
 * a version-1 approval with version-2 agreed terms through this view (a review found the earlier x100 feeding
 * status's match label), and the completion still compares version-1 terms exactly as before.
 */
function agreementView(record) {
  const r = requireRecord(record);
  return agreementViewOf(r.version, r.agreement);
}
/** The same view from a version and an agreement alone (a proposal's, before any record exists). */
function agreementViewOf(version, a) {
  if (version !== VERSION && version !== VERSION_2) refuse(`no agreement view for version ${version}`);
  if (version === VERSION) {
    return { version: 1, shares: a.shares.map((s) => ({ amount: s.amount, ownerAddress: s.ownerAddress, refundAddress: s.refundAddress, rewardAddress: s.rewardAddress, rewardAddressGiven: true })),
      earlyPeriodBlocks: a.earlyPeriodBlocks, earlyPenalty: a.earlyPenalty, operatorPubKey: a.operatorPubKey, votingAddress: a.votingAddress,
      operatorRewardText: `${a.operatorReward}%`, myIndex: a.myIndex, myContributionDuffs: a.myContributionDuffs, myFeeDuffs: a.myFeeDuffs };
  }
  const t = a.registration;
  return { version: 2, shares: t.shares.map((s) => ({ amount: s.amount, ownerAddress: s.ownerAddress, refundAddress: s.refundAddress, rewardAddress: terms.rewardDestination(s), rewardAddressGiven: Object.hasOwn(s, "rewardAddress") })),
    earlyPeriodBlocks: t.earlyPeriodBlocks, earlyPenalty: t.earlyPenalty, operatorPubKey: t.operatorPubKey, votingAddress: t.votingAddress,
    operatorRewardBps: t.operatorRewardBps, operatorRewardText: `${terms.bpsToPercentText(t.operatorRewardBps)}%`, myIndex: a.myIndex, myContributionDuffs: t.shares[a.myIndex].amount, myFeeDuffs: a.myFeeDuffs };
}

/**
 * A version-2 agreement in the shape the completion's claim logic and table comparison take (the
 * version-1 shape with every reward destination made explicit and the operator reward as the percentage
 * number the node reports), derived exactly, used only after the invariant has run on the real terms.
 */
function completionShapeOf(record) {
  const r = requireRecord(record);
  if (r.version === VERSION) return r.agreement;
  const v = agreementView(r);
  return { shares: v.shares.map((s) => ({ amount: s.amount, ownerAddress: s.ownerAddress, refundAddress: s.refundAddress, rewardAddress: s.rewardAddress })),
    earlyPeriodBlocks: v.earlyPeriodBlocks, earlyPenalty: v.earlyPenalty, operatorPubKey: v.operatorPubKey, votingAddress: v.votingAddress,
    operatorReward: Number(terms.bpsToPercentText(v.operatorRewardBps)), myIndex: v.myIndex, myContributionDuffs: v.myContributionDuffs, myFeeDuffs: v.myFeeDuffs };
}

/** One served identity key into plain data: { id, purpose, disabled, type, dataHex }. */
function keyOf(k) {
  const get = (m, p) => (typeof k[m] === "function" ? k[m]() : k[p]);
  const data = get("getData", "data");
  const hex = typeof data === "string" ? data : (data instanceof Uint8Array || Buffer.isBuffer(data)) ? Buffer.from(data).toString("hex") : null;
  const disabledAt = get("getDisabledAt", "disabledAt");
  return { id: Number(get("getId", "keyId") ?? k.id), purpose: String(get("getPurpose", "purpose")),
    disabled: disabledAt !== undefined && disabledAt !== null, type: String(get("getType", "keyType") ?? k.type), dataHex: hex };
}

/**
 * The checks a record and its owner signature must pass wherever the approval travels: the
 * version-1 shape, this pool, contract and both chains, the registration within the window, and a
 * valid signature by the share's owner address over the message. Shared by the file path below and
 * the ledger path (memberApprovalLedger.cjs), so the two cannot drift. Returns { r, message, who }
 * or throws ApprovalRefusal.
 */
function verifyRecordAndOwner({ record, ownerSignature, expect, verifyMessage }) {
  const r = requireRecord(record);
  const message = messageFor(r);
  const who = `the approval of ${r.memberIdentity.slice(0, 12)}... revision ${r.revision}`;
  if (r.poolId !== expect.poolIdHex) refuse(`WRONG POOL: ${who} names pool ${r.poolId.slice(0, 12)}..., not ${expect.poolIdHex.slice(0, 12)}...`);
  if (r.contractId !== expect.contractId) refuse(`WRONG CONTRACT: ${who} names contract ${r.contractId}`);
  if (r.platformChainId !== expect.platformChainId) refuse(`WRONG CHAIN: ${who} names Platform chain ${r.platformChainId}`);
  if (r.l1GenesisHash !== expect.l1GenesisHash) refuse(`WRONG CHAIN: ${who} names another layer-1 chain`);
  if (!isInt(expect.registrationHeight)) refuse("the registration height is unknown, so no approval window can be checked");
  if (expect.registrationHeight > r.notAfterHeight) {
    refuse(`STALE: ${who} allows registration up to height ${r.notAfterHeight}, and the registration confirmed at ${expect.registrationHeight}`);
  }
  const ownerAddress = shareOf(r).ownerAddress;
  if (typeof ownerSignature !== "string" || !verifyMessage(ownerAddress, message, ownerSignature)) {
    refuse(`SUBSTITUTION: ${who} carries no valid signature by its share's owner key ${ownerAddress}`);
  }
  return { r, message, who };
}

/**
 * Verify one envelope { record, ownerSignature, identityKeyId, identitySignature } against what the
 * completion expects. Returns { identityHex, revision, agreement, message } or throws ApprovalRefusal.
 */
function verifyEnvelope({ envelope, expect, identityKeys, verifyMessage, addressOfPubkey }) {
  if (!envelope || typeof envelope !== "object") refuse("the approval is not an object");
  const { r, message, who } = verifyRecordAndOwner({ record: envelope.record, ownerSignature: envelope.ownerSignature, expect, verifyMessage });
  const keys = (identityKeys || []).map(keyOf);
  const key = keys.find((k) => k.id === envelope.identityKeyId);
  if (!key) refuse(`${who} names identity key ${envelope.identityKeyId}, which the identity does not have`);
  if (!/AUTH|^0$/.test(key.purpose)) refuse(`${who} is signed with identity key ${key.id}, which is not an authentication key`);
  if (key.disabled) refuse(`${who} is signed with identity key ${key.id}, which is disabled`);
  if (!key.dataHex || !/^0[23][0-9a-f]{64}$/.test(key.dataHex)) refuse(`identity key ${key.id} is not a compressed secp256k1 public key`);
  if (typeof envelope.identitySignature !== "string" || !verifyMessage(addressOfPubkey(key.dataHex), message, envelope.identitySignature)) {
    refuse(`SUBSTITUTION: ${who} carries no valid signature by the identity's key ${key.id}`);
  }
  return { identityHex: r.memberIdentity, revision: r.revision, agreement: r.agreement, version: r.version, record: r, message };
}

/**
 * The whole decision: verify every envelope (ANY failure refuses the completion, since a failed
 * approval in the set means the set was altered), keep each member's highest revision, then run the
 * unchanged completion comparison with those approved terms. Claims are planned from the approved
 * terms (planClaims), which this unit states rather than reads from Platform.
 */
function decideApprovedCompletion({ envelopes, identityKeysByIdentity, expect, verifyMessage, addressOfPubkey,
  scriptOfAddress, b58OfHex, completionInputs }) {
  const refusals = [];
  const verified = [];
  // the registration height comes from the same Core answer the comparison reads, never separately
  const st = completionInputs && completionInputs.protxInfo && completionInputs.protxInfo.state;
  const at = { ...expect, registrationHeight: st ? st.registeredHeight : undefined };
  if (!envelopes || envelopes.length === 0) return { ok: false, refusals: ["no approvals were presented"] };
  // THE COMPLETION IS BOUND TO WHAT THE APPROVALS WERE CHECKED AGAINST (a review found the two could
  // name different pools and a receipt for an unapproved pool completed): the pool and contract come
  // from `expect` alone, and a completion input naming another is refused rather than overridden
  const ci = completionInputs || {};
  if ((ci.poolIdHex !== undefined && ci.poolIdHex !== expect.poolIdHex)
      || (ci.poolIdB58 !== undefined && ci.poolIdB58 !== b58OfHex(expect.poolIdHex))
      || (ci.contractId !== undefined && ci.contractId !== expect.contractId)) {
    return { ok: false, refusals: ["the completion names a pool or contract other than the one the approvals were checked against"] };
  }
  for (const [i, env] of envelopes.entries()) {
    try {
      const id = env && env.record && env.record.memberIdentity;
      verified.push(verifyEnvelope({ envelope: env, expect: at, identityKeys: identityKeysByIdentity[id], verifyMessage, addressOfPubkey }));
    } catch (e) {
      if (!(e instanceof ApprovalRefusal)) throw e;
      refusals.push(`approval ${i}: ${e.message}`);
    }
  }
  if (refusals.length) return { ok: false, refusals };
  // two different approvals at ONE (member, revision) refuse the set whatever order they arrive in
  const seen = new Map();
  for (const v of verified) {
    const k = `${v.identityHex}|${v.revision}`;
    if (seen.has(k) && seen.get(k) !== v.message) {
      return { ok: false, refusals: [`two different approvals of ${v.identityHex.slice(0, 12)}... carry revision ${v.revision}`] };
    }
    seen.set(k, v.message);
  }
  const latest = new Map();
  for (const v of verified) {
    const had = latest.get(v.identityHex);
    if (!had || v.revision > had.revision) latest.set(v.identityHex, v);
  }
  // THE INVARIANT FOR VERSION-2 TERMS: the signed registration terms equal what the node decoded, units
  // and defaults included, before the claim logic sees a derived shape of them
  const network = networkOfChain(expect.platformChainId);
  for (const v of latest.values()) {
    if (v.version !== VERSION_2) continue;
    // st is present here: verifyRecordAndOwner refused every envelope already when no registration height was read
    if (!network) { refusals.push(`${v.identityHex.slice(0, 12)}...'s version-2 terms cannot be compared: no address rules for this chain`); continue; }
    let cmp;
    try { cmp = terms.agreementWithDecoded({ terms: v.agreement.registration, decoded: { ...st, operatorReward: completionInputs.protxInfo.operatorReward }, network }); }
    catch (e) { if (!(e instanceof terms.TermsRefusal)) throw e; refusals.push(`${v.identityHex.slice(0, 12)}...'s terms are not ones the chain accepts (${e.reason}): ${e.message}`); continue; }
    if (!cmp.ok) refusals.push(`${v.identityHex.slice(0, 12)}...'s signed terms differ from the registration: ${cmp.differences.join("; ")}`);
  }
  if (refusals.length) return { ok: false, refusals };
  const shapeOf = (v) => completionShapeOf(v.record);
  const termsSets = [...latest.values()].map((v) => ({ member: `identity ${v.identityHex.slice(0, 12)}...`,
    platformIdentityB58: b58OfHex(v.identityHex), agreement: shapeOf(v) }));
  let claims;
  try {
    const plan = completion.planClaims({ pool: completionInputs.pool, terms: [...latest.values()].map((v) => ({
      member: `identity ${v.identityHex.slice(0, 12)}...`, platformIdentity: { b58: b58OfHex(v.identityHex) }, agreement: shapeOf(v),
      rewardScriptHex: scriptOfAddress(shapeOf(v).shares[shapeOf(v).myIndex].rewardAddress) })) });
    claims = plan.flatMap((p) => p.slots.map((slotNo) => ({ slotNo, ownerB58: p.identityB58, rewardScriptHex: p.rewardScriptHex, createdAt: slotNo })));
  } catch (e) {
    return { ok: false, refusals: [`the approved terms do not fill the pool, so a member may have no valid approval: ${e.message}`] };
  }
  const r = completion.decideCompletion({ ...ci, contractId: expect.contractId, poolIdHex: expect.poolIdHex,
    poolIdB58: b58OfHex(expect.poolIdHex), claims, termsSets });
  return { ...r, approvals: [...latest.values()].map((v) => ({ identityHex: v.identityHex, revision: v.revision })),
    superseded: verified.length - latest.size };
}

module.exports = { DOMAIN, VERSION, VERSION_2, VERSION_WRITE, PREFIX, PREFIX_BY_VERSION, networkOfChain, messageFor, requireRecord, shareOf, agreementView, agreementViewOf, completionShapeOf,
  verifyRecordAndOwner, verifyEnvelope, decideApprovedCompletion, keyOf, ApprovalRefusal };
