// The member-approval battery. Its base is the REAL rc.1 registration answer and agreements from
// unit 1 (fixtures/coowner-completion-rc1-R1.json), with the two share owner addresses replaced by
// keys this battery holds, so it can make real Dash signed-message signatures for them. The
// identity keys are generated the same way and served in the SDK's shape. Every refusal is asserted
// by the reason it names, and no refused case may return a receipt.
const fs = require("fs");
const path = require("path");
const L = require("@dashevo/dashcore-lib");
const approval = require("./memberApproval.cjs");
const formationCore = require("./formationCore.cjs");

const FIX = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "coowner-completion-rc1-R1.json"), "utf8"));
let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const clone = (x) => JSON.parse(JSON.stringify(x));

const verifyMessage = (address, message, sig) => { try { return new L.Message(message).verify(address, sig); } catch { return false; } };
const addressOfPubkey = (hex) => new L.PublicKey(hex).toAddress("testnet").toString();
const scriptOfAddress = (addr) => L.Script.buildPublicKeyHashOut(L.Address.fromString(addr)).toHex();
const b58OfHex = (hex) => L.encoding.Base58.encode(Buffer.from(hex, "hex"));
const sign = (pk, message) => new L.Message(message).sign(pk);

const CONTRACT = "GJWKJLZF3PHm8HuUwz4JCL2PkTmvDqcYV2GagYaQ6mq";
const CHAIN = "dash-testnet-51";
const POOL = require("crypto").createHash("sha256").update("member-approval battery pool").digest("hex");
const GENESIS = "11".repeat(32);
const ID = { A: FIX.platformIdentities.memberA.hex, B: FIX.platformIdentities.memberB.hex };
const owner = { A: new L.PrivateKey(undefined, "testnet"), B: new L.PrivateKey(undefined, "testnet") };
const idKey = { A: new L.PrivateKey(undefined, "testnet"), B: new L.PrivateKey(undefined, "testnet") };
const served = (pk, extra = {}) => ({ keyId: 1, purpose: "AUTHENTICATION", data: new Uint8Array(pk.toPublicKey().toBuffer()), ...extra });
const keysBy = { [ID.A]: [served(idKey.A)], [ID.B]: [served(idKey.B)] };

// the real registration with owner addresses this battery can sign for
const info = clone(FIX.protxInfo);
info.state.shares[0].ownerAddress = owner.A.toAddress().toString();
info.state.shares[1].ownerAddress = owner.B.toAddress().toString();
const HEIGHT = info.state.registeredHeight;
const agreementOf = (m, tweak) => {
  const a = clone(FIX.agreements[m === "A" ? "memberA" : "memberB"]);
  a.shares[0].ownerAddress = info.state.shares[0].ownerAddress;
  a.shares[1].ownerAddress = info.state.shares[1].ownerAddress;
  if (tweak) tweak(a);
  return a;
};
const record = (m, { revision = 1, notAfterHeight = HEIGHT + 100, poolId = POOL, tweak } = {}) => ({
  domain: approval.DOMAIN, version: approval.VERSION, platformChainId: CHAIN, contractId: CONTRACT, poolId,
  l1GenesisHash: GENESIS, memberIdentity: ID[m], revision, notAfterHeight, agreement: agreementOf(m, tweak) });
const envelope = (m, opts) => {
  const r = record(m, opts);
  const msg = approval.messageFor(r);
  return { record: r, ownerSignature: sign(owner[m], msg), identityKeyId: 1, identitySignature: sign(idKey[m], msg) };
};
const inputs = () => ({ contractId: CONTRACT, poolIdB58: b58OfHex(POOL), poolIdHex: POOL,
  pool: { slotIndex: 0, nodeType: "regular", targetDuffs: "100000000000", slotDuffs: "10000000000", slotCount: 10 },
  protxInfo: clone(info), proTxDisplayHex: FIX.proTxHash });
const decide = (envelopes, over = {}) => approval.decideApprovedCompletion({ envelopes, identityKeysByIdentity: keysBy,
  expect: { platformChainId: CHAIN, contractId: CONTRACT, poolIdHex: POOL, l1GenesisHash: GENESIS, ...over.expect },
  verifyMessage, addressOfPubkey, scriptOfAddress, b58OfHex, completionInputs: { ...inputs(), ...over.inputs } });
const refuses = (name, envelopes, needle, over) => {
  const r = decide(envelopes, over);
  ok(`${name}: refused, no receipt, naming "${needle}" (got ${JSON.stringify(r.refusals)})`,
    r.ok === false && r.receipt === undefined && r.refusals.some((m) => m.includes(needle)));
};

// ---- two members approving their own terms ----
{
  const r = decide([envelope("A"), envelope("B")]);
  ok(`two members' own approvals complete (got ${JSON.stringify(r.refusals)})`, r.ok === true && r.receipt && r.receipt.l1Verification === "amount-reward-verified");
  ok("each member counted once, at revision 1", JSON.stringify(r.approvals) === JSON.stringify([{ identityHex: ID.A, revision: 1 }, { identityHex: ID.B, revision: 1 }]));
}

// ---- revisions: the highest counts, and approvals of superseded terms do not complete ----
{
  const oldRefund = (a) => { a.shares[1].refundAddress = "yNMNAgh59FiuFqhCRoVJLFHBGUoPtVbzMW"; };
  const r = decide([envelope("A", { tweak: oldRefund }), envelope("B", { tweak: oldRefund }), envelope("A", { revision: 2 }), envelope("B", { revision: 2 })]);
  ok(`with revisions 1 and 2 presented, revision 2 counts and completes (got ${JSON.stringify(r.refusals)})`, r.ok === true && r.superseded === 2);
  refuses("STALE: only approvals of the superseded terms", [envelope("A", { tweak: oldRefund }), envelope("B", { tweak: oldRefund })],
    "share 1's registered refund address");
  refuses("STALE: the registration confirmed after an approval's window", [envelope("A", { notAfterHeight: HEIGHT - 1 }), envelope("B")],
    "STALE");
  refuses("two different approvals with one revision", [envelope("A"), envelope("A", { tweak: oldRefund }), envelope("B")],
    "carry revision 1");
}

// ---- substitution ----
{
  const altered = envelope("B");
  altered.record.agreement.shares[1].refundAddress = "yNMNAgh59FiuFqhCRoVJLFHBGUoPtVbzMW";
  refuses("SUBSTITUTION: the terms changed after signing", [envelope("A"), altered], "SUBSTITUTION");
  const asA = envelope("A");
  const bEnv = envelope("B");
  refuses("SUBSTITUTION: A's record carrying B's identity signature", [{ ...asA, identitySignature: bEnv.identitySignature }, bEnv],
    "valid signature by the identity's key");
  refuses("SUBSTITUTION: A's record signed by a key other than its share's owner", [{ ...asA, ownerSignature: sign(new L.PrivateKey(undefined, "testnet"), approval.messageFor(asA.record)) }, bEnv],
    "valid signature by its share's owner key");
  refuses("SUBSTITUTION: B's terms relabeled as A's identity", [envelope("A"), (() => { const e = envelope("B"); e.record.memberIdentity = ID.A; return e; })()],
    "SUBSTITUTION");
}

// ---- wrong pool, contract and chains ----
const otherPool = require("crypto").createHash("sha256").update("another pool").digest("hex");
refuses("WRONG POOL", [envelope("A", { poolId: otherPool }), envelope("B", { poolId: otherPool })], "WRONG POOL");
refuses("WRONG CONTRACT", [envelope("A"), envelope("B")], "WRONG CONTRACT", { expect: { contractId: "8hgVYBkeTTMg9PttNfYt5M57TE828TU1x3JNg7occUF6" }, inputs: { contractId: "8hgVYBkeTTMg9PttNfYt5M57TE828TU1x3JNg7occUF6" } });
refuses("WRONG PLATFORM CHAIN", [envelope("A"), envelope("B")], "Platform chain", { expect: { platformChainId: "dash-mainnet" } });
refuses("WRONG LAYER-1 CHAIN", [envelope("A"), envelope("B")], "layer-1 chain", { expect: { l1GenesisHash: "22".repeat(32) } });

// ---- members and keys ----
refuses("a member with no approval, leaving the pool unfilled", [envelope("A")], "do not fill the pool");
refuses("no approvals at all", [], "no approvals were presented");
{
  const save = keysBy[ID.A];
  keysBy[ID.A] = [served(idKey.A, { keyId: 2 })];
  refuses("an identity key the identity does not have", [envelope("A"), envelope("B")], "does not have");
  keysBy[ID.A] = [served(idKey.A, { purpose: "TRANSFER" })];
  refuses("an identity key that is not an authentication key", [envelope("A"), envelope("B")], "not an authentication key");
  keysBy[ID.A] = [served(idKey.A, { disabledAt: 1790000000000 })];
  refuses("a disabled identity key", [envelope("A"), envelope("B")], "disabled");
  keysBy[ID.A] = save;
}
refuses("a record with an extra field", [(() => { const e = envelope("A"); e.record.note = "x"; return e; })(), envelope("B")], "approval set");

// ---- the review's cases ----
refuses("the completion naming another pool than the approvals", [envelope("A"), envelope("B")],
  "other than the one the approvals were checked against", { inputs: { poolIdHex: otherPool, poolIdB58: b58OfHex(otherPool) } });
refuses("the completion with the approved pool's hex but another pool's Base58 id", [envelope("A"), envelope("B")],
  "other than the one the approvals were checked against", { inputs: { poolIdHex: POOL, poolIdB58: b58OfHex(otherPool) } });
refuses("the completion with another pool's hex but the approved pool's Base58 id", [envelope("A"), envelope("B")],
  "other than the one the approvals were checked against", { inputs: { poolIdHex: otherPool, poolIdB58: b58OfHex(POOL) } });
refuses("the completion naming another contract than the approvals", [envelope("A"), envelope("B")],
  "other than the one the approvals were checked against", { inputs: { contractId: "8hgVYBkeTTMg9PttNfYt5M57TE828TU1x3JNg7occUF6" } });
refuses("a registration answer without its height", [envelope("A"), envelope("B")], "registration height is unknown",
  { inputs: { protxInfo: (() => { const i = clone(info); delete i.state.registeredHeight; return i; })() } });
const signedWith = (m, edit) => {
  const r = record(m); edit(r);
  let msg; try { msg = approval.messageFor(r); } catch { msg = "x"; }
  return { record: r, ownerSignature: sign(owner[m], msg), identityKeyId: 1, identitySignature: sign(idKey[m], msg) };
};
refuses("a signed record from another domain", [signedWith("A", (r) => { r.domain = "some.other.record"; }), envelope("B")], "version-1 or version-2 co-owner terms approval");
refuses("a version-1 agreement signed as version 2 (a version-1 record relabeled, which must never verify)", [signedWith("A", (r) => { r.version = 2; }), envelope("B")], "version-2 agreement's fields");
refuses("a signed record of a version that does not exist", [signedWith("A", (r) => { r.version = 3; }), envelope("B")], "version-1 or version-2 co-owner terms approval");
{
  const oldRefund = (a) => { a.shares[1].refundAddress = "yNMNAgh59FiuFqhCRoVJLFHBGUoPtVbzMW"; };
  refuses("two different revision-1 approvals arriving after revision 2", [envelope("A", { revision: 2 }), envelope("A"), envelope("A", { tweak: oldRefund }), envelope("B", { revision: 2 })],
    "carry revision 1");
}

// ---- a REAL owner signature, made by Dash Core v24.0.0-rc.1's signmessage in a member's wallet ----
{
  const real = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "member-approval-rc1-envelope.json"), "utf8"));
  const ownerAddr = real.record.agreement.shares[real.record.agreement.myIndex].ownerAddress;
  ok("Core's owner signature verifies against the message this module recomputes from the record",
    verifyMessage(ownerAddr, approval.messageFor(real.record), real.ownerSignature) === true);
  const moved = clone(real.record);
  moved.notAfterHeight += 1;
  ok("and fails once one field of the record changes", verifyMessage(ownerAddr, approval.messageFor(moved), real.ownerSignature) === false);
}

// ---- the message is canonical: key order does not change it ----
{
  const r = record("A");
  const reordered = Object.fromEntries(Object.entries(r).reverse());
  ok("the signed message does not depend on field order", approval.messageFor(r) === approval.messageFor(reordered));
}


// ================= VERSION 2: the registration terms in the chain's shapes =================
// The base is the REAL rc.1 regtest registration derived from version-2 terms (fixtures/
// registration-terms-rc1.json), with its two share owner addresses replaced by keys this battery holds.
// Version-1 records above are untouched by any of this: they still verify and complete as written.
{
  const R = require("./registrationTerms.cjs");
  const F2 = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "registration-terms-rc1.json"), "utf8"));
  const o2 = { A: new L.PrivateKey(undefined, "testnet"), B: new L.PrivateKey(undefined, "testnet") };
  const termsBase = () => { const t = clone(F2.terms); t.shares[0].ownerAddress = o2.A.toAddress().toString(); t.shares[1].ownerAddress = o2.B.toAddress().toString(); return t; };
  const info2 = () => { const i = clone(F2.protxInfo); i.state.shares[0].ownerAddress = o2.A.toAddress().toString(); i.state.shares[1].ownerAddress = o2.B.toAddress().toString(); return i; };
  const H2 = F2.protxInfo.state.registeredHeight;
  const POOL2 = require("crypto").createHash("sha256").update("member-approval battery pool, version 2").digest("hex");
  const rec2 = (m, { revision = 1, tweak, tweakRecord } = {}) => {
    const t = termsBase(); if (tweak) tweak(t);
    const r = { domain: approval.DOMAIN, version: 2, platformChainId: CHAIN, contractId: CONTRACT, poolId: POOL2, l1GenesisHash: GENESIS, memberIdentity: ID[m],
      revision, notAfterHeight: H2 + 100, agreement: { registration: t, myIndex: m === "A" ? 0 : 1, myFeeDuffs: 10000 } };
    if (tweakRecord) tweakRecord(r);
    return r;
  };
  // signed over the version-2 message computed here, not through messageFor, so a record the module refuses can still be signed and presented
  const rawMsg2 = (r) => approval.PREFIX_BY_VERSION[2] + require("crypto").createHash("sha256").update(require("./canonicalJson.cjs").canonicalString(r)).digest("hex");
  const env2 = (m, opts) => { const r = rec2(m, opts); const msg = rawMsg2(r); return { record: r, ownerSignature: sign(o2[m], msg), identityKeyId: 1, identitySignature: sign(idKey[m], msg) }; };
  const inputs2 = (over = {}) => ({ contractId: CONTRACT, poolIdB58: b58OfHex(POOL2), poolIdHex: POOL2,
    pool: { slotIndex: 0, nodeType: "regular", targetDuffs: "100000000000", slotDuffs: "10000000000", slotCount: 10 }, protxInfo: over.protxInfo || info2(), proTxDisplayHex: F2.protxInfo.proTxHash });
  const decide2 = (envelopes, over = {}) => approval.decideApprovedCompletion({ envelopes, identityKeysByIdentity: keysBy,
    expect: { platformChainId: CHAIN, contractId: CONTRACT, poolIdHex: POOL2, l1GenesisHash: GENESIS }, verifyMessage, addressOfPubkey, scriptOfAddress, b58OfHex, completionInputs: inputs2(over) });
  ok("a version-2 record passes requireRecord and signs the version-2 message, the one this battery computes", approval.requireRecord(rec2("A")).version === 2
    && approval.messageFor(rec2("A")) === rawMsg2(rec2("A")) && approval.messageFor(rec2("A")).startsWith("tegara co-owner terms approval v2 "));
  ok("the version-1 prefix is unchanged, so the trial's three approvals verify as written", approval.PREFIX === "tegara co-owner terms approval v1 " && approval.messageFor(record("A")).startsWith(approval.PREFIX));
  {
    const v1 = approval.agreementView(record("A"));
    ok("a version-1 agreement's view carries its reward as written and NO basis points, so no comparison can convert it (the review's case)", v1.version === 1 && v1.operatorRewardText === `${record("A").agreement.operatorReward}%` && !Object.hasOwn(v1, "operatorRewardBps"));
    const asText = record("A"); asText.agreement.operatorReward = "0";
    ok("a version-1 record whose reward is the text \"0\" is viewed as that text, not as the number 0", approval.agreementView(asText).operatorRewardText === "0%" && !Object.hasOwn(approval.agreementView(asText), "operatorRewardBps"));
  }
  {
    const r = decide2([env2("A"), env2("B")]);
    ok(`two members' version-2 approvals complete against the real rc.1 registration (got ${JSON.stringify(r.refusals)})`, r.ok === true && r.receipt && r.receipt.l1Verification === "amount-reward-verified");
    const v = approval.agreementView(rec2("B"));
    ok("the view of B's terms shows rewards going to the refund address, no reward address given, and the reward as 5.25%", v.shares[1].rewardAddress === v.shares[1].refundAddress && v.shares[1].rewardAddressGiven === false
      && v.shares[0].rewardAddressGiven === true && v.operatorRewardBps === 525 && v.operatorRewardText === "5.25%" && v.myContributionDuffs === 40000000000);
    const shape = approval.completionShapeOf(rec2("B"));
    ok("the completion shape carries the effective reward and the percentage number the node reports", shape.shares[1].rewardAddress === shape.shares[1].refundAddress && shape.operatorReward === 5.25 && shape.myContributionDuffs === 40000000000);
  }
  const refuses2 = (name, envelopes, needle, over) => { const r = decide2(envelopes, over); ok(`${name}: refused, no receipt, naming "${needle}" (got ${JSON.stringify(r.refusals)})`, r.ok === false && r.receipt === undefined && r.refusals.some((m) => m.includes(needle))); };
  refuses2("version-2 terms whose reward differs from the registration by one basis point", [env2("A", { tweak: (t) => { t.operatorRewardBps = 524; } }), env2("B", { tweak: (t) => { t.operatorRewardBps = 524; } })], "registered operator reward 525 basis points, signed 524");
  {
    const i = info2(); i.state.shares[1].rewardAddress = i.state.shares[0].rewardAddress; i.state.shares[1].rewardScript = i.state.shares[0].rewardScript;
    refuses2("a registration sending the omitted-reward share's rewards elsewhere", [env2("A"), env2("B")], "share 2: rewards go to", { protxInfo: i });
  }
  {
    const i = info2(); i.state.earlyPenalty += 1;
    refuses2("a registration with another penalty than the signed one", [env2("A"), env2("B")], "registered early-exit penalty", { protxInfo: i });
  }
  refuses2("a version-2 record with terms the chain refuses (the penalty equal to the smallest share)", [env2("A", { tweak: (t) => { t.earlyPenalty = 40000000000; } }), env2("B")], "bad-protx-shares-penalty");
  ok("requireRecord refuses version-2 terms the chain refuses, naming the chain's reason", (() => { try { approval.requireRecord(rec2("A", { tweak: (t) => { t.earlyPenalty = 40000000000; } })); return false; } catch (e) { return e instanceof approval.ApprovalRefusal && /bad-protx-shares-penalty/.test(e.message); } })());
  refuses2("a version-2 record naming a share the member's key did not sign", [(() => { const e = env2("A"); e.record.agreement.myIndex = 1; return e; })(), env2("B")], "SUBSTITUTION");
  refuses2("a version-2 record with a field beside the registration terms", [(() => { const e = env2("A", { tweakRecord: (r) => { r.agreement.note = "x"; } }); return e; })(), env2("B")], "version-2 agreement's fields");
  refuses2("a version-2 record signed over the version-1 message", [(() => { const r = rec2("A"); const msg = approval.PREFIX + require("crypto").createHash("sha256").update(require("./canonicalJson.cjs").canonicalString(r)).digest("hex");
    return { record: r, ownerSignature: sign(o2.A, msg), identityKeyId: 1, identitySignature: sign(idKey.A, msg) }; })(), env2("B")], "SUBSTITUTION");
  {
    const r = decide2([env2("A"), env2("B")], { protxInfo: (() => { const i = info2(); delete i.state; return i; })() });
    ok("version-2 terms with no registration state read are refused at the window check, never compared against nothing", r.ok === false && r.refusals.some((m) => /registration height is unknown/.test(m)));
  }
}

console.log(`memberApprovalTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
