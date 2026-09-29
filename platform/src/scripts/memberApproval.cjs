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
 */
const crypto = require("crypto");
const { canonicalString } = require("./canonicalJson.cjs");
const completion = require("./coownerCompletion.cjs");
const formationCore = require("./formationCore.cjs");

const DOMAIN = "tegara.coowner.termsApproval";
const VERSION = 1;
const PREFIX = "tegara co-owner terms approval v1 ";
const HEX64 = /^[0-9a-f]{64}$/;
const isInt = (v) => Number.isSafeInteger(v);
class ApprovalRefusal extends Error {}
const refuse = (why) => { throw new ApprovalRefusal(why); };

const RECORD_KEYS = ["domain", "version", "platformChainId", "contractId", "poolId", "l1GenesisHash",
  "memberIdentity", "revision", "notAfterHeight", "agreement"];

/** The record's shape, refused rather than repaired. */
function requireRecord(r) {
  if (!r || typeof r !== "object") refuse("the approval carries no record");
  const extra = Object.keys(r).filter((k) => !RECORD_KEYS.includes(k));
  const missing = RECORD_KEYS.filter((k) => !(k in r));
  if (extra.length || missing.length) refuse(`the record's fields are not the version-1 set (extra ${extra.join(",") || "none"}, missing ${missing.join(",") || "none"})`);
  if (r.domain !== DOMAIN || r.version !== VERSION) refuse("the record is not a version-1 co-owner terms approval");
  for (const k of ["poolId", "l1GenesisHash", "memberIdentity"]) if (!HEX64.test(r[k])) refuse(`the record's ${k} is not 64 lowercase hex`);
  if (!isInt(r.revision) || r.revision < 1) refuse("the record's revision is not a positive integer");
  if (!isInt(r.notAfterHeight) || r.notAfterHeight < 0) refuse("the record's notAfterHeight is not a height");
  const a = r.agreement;
  if (!a || !Array.isArray(a.shares) || !isInt(a.myIndex) || !a.shares[a.myIndex]) refuse("the record's agreement names no share for this member");
  return r;
}

/** The exact message both keys sign. */
function messageFor(record) {
  return PREFIX + crypto.createHash("sha256").update(canonicalString(requireRecord(record))).digest("hex");
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
  const ownerAddress = r.agreement.shares[r.agreement.myIndex].ownerAddress;
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
  return { identityHex: r.memberIdentity, revision: r.revision, agreement: r.agreement, message };
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
  const termsSets = [...latest.values()].map((v) => ({ member: `identity ${v.identityHex.slice(0, 12)}...`,
    platformIdentityB58: b58OfHex(v.identityHex), agreement: v.agreement }));
  let claims;
  try {
    const plan = completion.planClaims({ pool: completionInputs.pool, terms: [...latest.values()].map((v) => ({
      member: `identity ${v.identityHex.slice(0, 12)}...`, platformIdentity: { b58: b58OfHex(v.identityHex) }, agreement: v.agreement,
      rewardScriptHex: scriptOfAddress(v.agreement.shares[v.agreement.myIndex].rewardAddress) })) });
    claims = plan.flatMap((p) => p.slots.map((slotNo) => ({ slotNo, ownerB58: p.identityB58, rewardScriptHex: p.rewardScriptHex, createdAt: slotNo })));
  } catch (e) {
    return { ok: false, refusals: [`the approved terms do not fill the pool, so a member may have no valid approval: ${e.message}`] };
  }
  const r = completion.decideCompletion({ ...ci, contractId: expect.contractId, poolIdHex: expect.poolIdHex,
    poolIdB58: b58OfHex(expect.poolIdHex), claims, termsSets });
  return { ...r, approvals: [...latest.values()].map((v) => ({ identityHex: v.identityHex, revision: v.revision })),
    superseded: verified.length - latest.size };
}

module.exports = { DOMAIN, VERSION, PREFIX, messageFor, requireRecord, verifyRecordAndOwner, verifyEnvelope, decideApprovedCompletion, keyOf, ApprovalRefusal };
