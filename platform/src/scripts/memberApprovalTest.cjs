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
refuses("a record with an extra field", [(() => { const e = envelope("A"); e.record.note = "x"; return e; })(), envelope("B")], "version-1 set");

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
refuses("a signed record from another domain", [signedWith("A", (r) => { r.domain = "some.other.record"; }), envelope("B")], "version-1 co-owner terms approval");
refuses("a signed record of another version", [signedWith("A", (r) => { r.version = 2; }), envelope("B")], "version-1 co-owner terms approval");
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

console.log(`memberApprovalTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
