// The ledger-approval battery (formation unit 3). It drives the whole changed path offline: served
// documents built by the pinned DPP's own constructor from the approval schema, through the page
// fetcher, the unchanged proved-enumeration wrapper, the served-document adapter, both rules and the
// unchanged completion comparison. Its base is the REAL rc.1 registration answer and agreements
// (fixtures/coowner-completion-rc1-R1.json), with the owner addresses replaced by keys this battery
// holds, as unit 2's battery does, and it carries unit 2's REAL Core owner signature.
//
// THE MUTATION LIST, written before the cases (no outside chooser was available at write time):
//   drop SAME CHAIN; drop NOT YET FIXED; drop the page-height floor; `<` to `<=` in ELIGIBLE; pick
//   the lowest revision; count set-aside approvals; drop OWNER; drop the canonical-bytes check; drop
//   termsRevision == record.revision (an old owner-signed record republished at a higher index);
//   drop STALE; verify every eligible revision (the liveness trap); drop PRESENCE; drop the page
//   limit; drop the adapter's length checks; accept another owner's document in a member's page.
// Every refusal is asserted by the reason it names, and no refused case may return a receipt.
const fs = require("fs");
const path = require("path");
const L = require("@dashevo/dashcore-lib");
const dpp = require("pshenmic-dpp");
const approval = require("./memberApproval.cjs");
const ledger = require("./memberApprovalLedger.cjs");
const completion = require("./coownerCompletion.cjs");
const { buildApprovalSchemas, APPROVAL_TYPE } = require("./approvalContract.cjs");
const { canonicalString } = require("./canonicalJson.cjs");

const FIX = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "coowner-completion-rc1-R1.json"), "utf8"));
const REAL = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "member-approval-rc1-envelope.json"), "utf8"));
let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const clone = (x) => JSON.parse(JSON.stringify(x));

const verifyMessage = (address, message, sig) => { try { return new L.Message(message).verify(address, sig); } catch { return false; } };
const scriptOfAddress = (addr) => L.Script.buildPublicKeyHashOut(L.Address.fromString(addr)).toHex();
const b58OfHex = (hex) => L.encoding.Base58.encode(Buffer.from(hex, "hex"));
const sign = (pk, message) => new L.Message(message).sign(pk);

const LEDGER = "GJWKJLZF3PHm8HuUwz4JCL2PkTmvDqcYV2GagYaQ6mq";
const CHAIN = "dash-testnet-51";
const TESTNET_GENESIS = "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c";
const REGTEST_GENESIS = "000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e";
const POOL = require("crypto").createHash("sha256").update("ledger-approval battery pool").digest("hex");
const ID = { A: FIX.platformIdentities.memberA.hex, B: FIX.platformIdentities.memberB.hex };
const STRANGER = "77".repeat(32);
const owner = { A: new L.PrivateKey(undefined, "testnet"), B: new L.PrivateKey(undefined, "testnet") };

// the approval contract, built by the DPP from the schema, as the publication will build it
const WRITER = new dpp.IdentifierWASM("11".repeat(32));
const CONTRACT = new dpp.DataContractWASM(WRITER, 7n, buildApprovalSchemas(), undefined, undefined, true, 12);
const APPROVALS = CONTRACT.id.base58();

// the real registration with owner addresses this battery can sign for
const info = clone(FIX.protxInfo);
info.state.shares[0].ownerAddress = owner.A.toAddress().toString();
info.state.shares[1].ownerAddress = owner.B.toAddress().toString();
const H = info.state.registeredHeight;
const agreementOf = (m, tweak) => {
  const a = clone(FIX.agreements[m === "A" ? "memberA" : "memberB"]);
  a.shares[0].ownerAddress = info.state.shares[0].ownerAddress;
  a.shares[1].ownerAddress = info.state.shares[1].ownerAddress;
  if (tweak) tweak(a);
  return a;
};
const recordOf = (m, { revision = 1, notAfterHeight = H + 100, poolId = POOL, genesis = TESTNET_GENESIS, tweak } = {}) => ({
  domain: approval.DOMAIN, version: approval.VERSION, platformChainId: CHAIN, contractId: LEDGER, poolId,
  l1GenesisHash: genesis, memberIdentity: ID[m], revision, notAfterHeight, agreement: agreementOf(m, tweak) });

// ONE served approval document: the DPP's constructor, the system fields the live query serves
// (probe 2026-09-28: createdAtCoreBlockHeight a number, createdAt a bigint), and a pass through the
// contract's serializer, which refuses a document missing a required field
let entropy = 0;
const docOf = ({ writerHex, record, recordBytes, sig, termsRevision, poolId = POOL, coreHeight = H - 10 }) => {
  const bytes = recordBytes || Buffer.from(canonicalString(record), "utf8");
  const props = { poolId: new Uint8Array(Buffer.from(poolId, "hex")), termsRevision: termsRevision === undefined ? record.revision : termsRevision,
    record: new Uint8Array(bytes), ownerSignature: new Uint8Array(sig) };
  const idBytes = require("crypto").createHash("sha256").update(`battery document ${entropy++}`).digest();
  const d = new dpp.DocumentWASM(props, APPROVAL_TYPE, 1n, CONTRACT.id, new dpp.IdentifierWASM(writerHex), new dpp.IdentifierWASM(idBytes.toString("hex")));
  d.createdAt = 1759000000000n + BigInt(entropy);
  d.createdAtCoreBlockHeight = coreHeight;
  d.bytes(CONTRACT, 12); // the serializer's required-field check, including the core height
  return d;
};
const signed = (m, opts = {}) => {
  const record = recordOf(m, opts);
  return { record, sig: Buffer.from(sign(opts.signer || owner[m], approval.messageFor(record)), "base64") };
};
const approvalDoc = (m, opts = {}) => { const { record, sig } = signed(m, opts); return docOf({ writerHex: opts.writerHex || ID[m], record, sig, coreHeight: opts.coreHeight, termsRevision: opts.termsRevision, poolId: opts.poolId }); };

// the transport: Drive's index query emulated over the document set, ONE page, proved at a height
const transport = (docs, { height = 603336n, fail = false, extraOwnerDoc = null, extraPoolDoc = null } = {}) => {
  const calls = [];
  const provedQuery = async (where, orderBy, limit) => {
    calls.push({ where, orderBy, limit });
    if (fail) throw new Error("proof did not verify");
    const [[f1, , ownerBytes], [f2, , poolBytes]] = where;
    if (f1 !== "$ownerId" || f2 !== "poolId" || !Buffer.isBuffer(ownerBytes) || !Buffer.isBuffer(poolBytes)) return { docs: [], height };
    const hit = docs.filter((d) => Buffer.from(d.ownerId.bytes()).equals(ownerBytes) && Buffer.from(d.properties.poolId).equals(poolBytes));
    if (extraOwnerDoc && hit.length) hit.push(extraOwnerDoc);
    if (extraPoolDoc && hit.length && Buffer.from(extraPoolDoc.ownerId.bytes()).equals(ownerBytes)) hit.push(extraPoolDoc);
    return { docs: hit.slice(0, limit), height: typeof height === "function" ? height(ownerBytes) : height };
  };
  return { fetch: ledger.makeApprovalPageFetcher({ approvalContractId: APPROVALS, provedQuery }), calls };
};

const baseInputs = () => {
  const terms = ["A", "B"].map((m) => ({ member: m, platformIdentity: { b58: b58OfHex(ID[m]) }, agreement: agreementOf(m),
    rewardScriptHex: scriptOfAddress(agreementOf(m).shares[agreementOf(m).myIndex].rewardAddress) }));
  const pool = { slotIndex: 0, nodeType: "regular", targetDuffs: "100000000000", slotDuffs: "10000000000", slotCount: 10 };
  const claims = completion.planClaims({ terms, pool }).flatMap((p) => p.slots.map((slotNo) => ({ slotNo, ownerB58: p.identityB58, rewardScriptHex: p.rewardScriptHex, createdAt: slotNo })));
  return { pool, claims, protxInfo: clone(info), proTxDisplayHex: FIX.proTxHash };
};
const EXPECT = { platformChainId: CHAIN, contractId: LEDGER, approvalContractId: APPROVALS, poolIdHex: POOL, l1GenesisHash: TESTNET_GENESIS };
const ANCHOR = { platformHeight: "603330", coreChainLockedHeight: H + 2 };
const decide = (docs, over = {}) => ledger.decideLedgerApprovedCompletion({ expect: { ...EXPECT, ...over.expect },
  anchor: over.anchor || ANCHOR, fetchVerifiedPage: (over.transport || transport(docs, over.t)).fetch, verifyMessage, b58OfHex,
  completionInputs: { ...baseInputs(), ...over.inputs } });
const refuses = async (name, docs, needle, over) => {
  const r = await decide(docs, over);
  ok(`${name}: refused, no receipt, naming "${needle}" (got ${JSON.stringify(r.refusals)})`,
    r.ok === false && r.receipt === undefined && r.refusals.some((m) => m.includes(needle)));
  return r;
};
const oldRefund = (a) => { a.shares[1].refundAddress = "yNMNAgh59FiuFqhCRoVJLFHBGUoPtVbzMW"; };

(async () => {
  // ---- the schema, validated by the pinned DPP, and the serializer's required-field check ----
  ok("the approval contract builds under full validation, one type", JSON.stringify(Object.keys(CONTRACT.getSchemas())) === JSON.stringify([APPROVAL_TYPE]));
  {
    const { record, sig } = signed("A");
    const d = new dpp.DocumentWASM({ poolId: new Uint8Array(32), termsRevision: 1, record: new Uint8Array(Buffer.from(canonicalString(record))), ownerSignature: new Uint8Array(sig) },
      APPROVAL_TYPE, 1n, CONTRACT.id, new dpp.IdentifierWASM(ID.A));
    d.createdAt = 1n;
    let why = "";
    try { d.bytes(CONTRACT, 12); } catch (e) { why = String(e && (e.message || e)); }
    ok(`a document without $createdAtCoreBlockHeight fails the contract's serializer (got "${why.slice(0, 90)}")`, /created_at_core_block_height/.test(why));
  }

  // ---- two members, each with its own approval written before the registration ----
  {
    const docs = [approvalDoc("A"), approvalDoc("B")];
    const r = await decide(docs);
    ok(`two members' ledger approvals complete (got ${JSON.stringify(r.refusals)})`, r.ok === true && r.receipt && r.receipt.l1Verification === "amount-reward-verified");
    ok("the fixed set names both members at revision 1, by document", r.fixedSet.length === 2
      && r.fixedSet.every((f) => f.revision === 1 && /^[0-9a-f]{64}$/.test(f.documentIdHex)) && r.fixedSet.map((f) => f.identityHex).sort().join() === [ID.A, ID.B].sort().join());
  }

  // ---- RULE 1: the authoritative revision and the fixed set ----
  {
    // revision 1 with superseded terms, revision 2 with the registered terms: revision 2 counts
    const docs = [approvalDoc("A", { tweak: oldRefund }), approvalDoc("B", { tweak: oldRefund }), approvalDoc("A", { revision: 2 }), approvalDoc("B", { revision: 2 })];
    const r = await decide(docs);
    ok(`with revisions 1 and 2 on the ledger, revision 2 counts (got ${JSON.stringify(r.refusals)})`, r.ok === true && r.fixedSet.every((f) => f.revision === 2) && r.superseded.length === 2);
    await refuses("only approvals of the superseded terms", [approvalDoc("A", { tweak: oldRefund }), approvalDoc("B", { tweak: oldRefund })], "share 1's registered refund address");
  }
  {
    // THE OMITTED NEWER REVISION: the file path counts only what it is shown. The ledger reads
    // every approval, so a newer revision with changed terms is found and refuses
    const docs = [approvalDoc("A"), approvalDoc("B"), approvalDoc("B", { revision: 2, tweak: oldRefund })];
    await refuses("a newer revision that no presenter chose to show is read from the ledger", docs, "share 1's registered refund address");
  }
  {
    // THE CUTOFF IS THE STAMPED HEIGHT, never wall-clock order against the registration. An approval
    // stamped BELOW h counts even if it was made after Core confirmed the registration, during
    // Platform's observation delay; stamped AT or ABOVE h it is excluded. Revision 3 carries changed
    // terms, so counting it would refuse the formation.
    const base = [approvalDoc("A"), approvalDoc("B")];
    const late = approvalDoc("B", { revision: 3, tweak: oldRefund, coreHeight: H });
    const r0 = await decide(base);
    const r1 = await decide([...base, late]);
    ok(`an approval created at the registration height is set aside and the formation still completes (got ${JSON.stringify(r1.refusals)})`,
      r1.ok === true && r1.setAside.length === 1 && r1.setAside[0].revision === 3 && r1.setAside[0].createdAtCoreBlockHeight === H);
    ok("and the fixed set is identical with and without it", JSON.stringify(r0.fixedSet) === JSON.stringify(r1.fixedSet));
    const above = approvalDoc("B", { revision: 3, tweak: oldRefund, coreHeight: H + 1 });
    const r2 = await decide([...base, above]);
    ok(`stamped ABOVE the registration height, it is set aside too and the formation completes (got ${JSON.stringify(r2.refusals)})`,
      r2.ok === true && r2.setAside.length === 1 && r2.setAside[0].createdAtCoreBlockHeight === H + 1
      && JSON.stringify(r0.fixedSet) === JSON.stringify(r2.fixedSet));
    const early = approvalDoc("B", { revision: 3, tweak: oldRefund, coreHeight: H - 1 });
    await refuses("stamped one height BELOW, it counts (as an approval made during Platform's observation delay would), and refuses", [...base, early], "share 1's registered refund address");
  }
  await refuses("SAME CHAIN: a registration on another Core chain", [approvalDoc("A"), approvalDoc("B")], "SAME CHAIN", { expect: { l1GenesisHash: REGTEST_GENESIS } });
  await refuses("a Platform chain with no recorded Core chain", [approvalDoc("A"), approvalDoc("B")], "no Core chain is recorded", { expect: { platformChainId: "evo1" } });
  await refuses("NOT YET FIXED: the anchor below the registration height", [approvalDoc("A"), approvalDoc("B")], "NOT YET FIXED",
    { anchor: { platformHeight: "603330", coreChainLockedHeight: H - 1 } });
  {
    const r = await decide([approvalDoc("A"), approvalDoc("B")], { anchor: { platformHeight: "603330", coreChainLockedHeight: H } });
    ok(`an anchor exactly at the registration height fixes the set (got ${JSON.stringify(r.refusals)})`, r.ok === true);
  }
  await refuses("COMPLETE: a page proved below the anchor's Platform height", [approvalDoc("A"), approvalDoc("B")], "below the anchor",
    { t: { height: 603329n } });
  await refuses("COMPLETE: an unproved read", [approvalDoc("A"), approvalDoc("B")], "were not read by proof (unserved)", { t: { fail: true } });
  {
    // a page AT the limit cannot attest completeness: 100 approvals by one member
    const many = Array.from({ length: 100 }, (_, i) => approvalDoc("A", { revision: i + 1, notAfterHeight: H + 100 }));
    await refuses("COMPLETE: a page at the query limit", [...many, approvalDoc("B")], "were not read by proof (unserved)");
  }
  await refuses("PRESENCE: a claimant whose only approval is stamped above the registration height", [approvalDoc("A"), approvalDoc("B", { coreHeight: H + 1 })], "PRESENCE");
  await refuses("PRESENCE: a claimant with no approval at all", [approvalDoc("A")], "PRESENCE");
  await refuses("STALE: the authoritative approval's window closed before the registration",
    [approvalDoc("A", { notAfterHeight: H - 1 }), approvalDoc("B")], "STALE");
  {
    // NO FALLBACK (the review's control, 2026-09-28): a valid lower revision does not stand in for a
    // stale higher one. A selection preferring the highest non-stale revision would complete here
    const r = await refuses("a stale highest revision above a valid lower one",
      [approvalDoc("A"), approvalDoc("A", { revision: 2, notAfterHeight: H - 1 }), approvalDoc("B")], "STALE");
    ok("and the refusal names revision 2, not a completion on revision 1", r.refusals.some((m) => /revision 2/.test(m)));
  }
  {
    // THE LIVENESS TRAP: a superseded revision whose window closed must not block a valid newer one
    const r = await decide([approvalDoc("A", { notAfterHeight: H - 1 }), approvalDoc("A", { revision: 2 }), approvalDoc("B")]);
    ok(`a superseded revision with a closed window does not block the formation (got ${JSON.stringify(r.refusals)})`, r.ok === true && r.superseded.length === 1);
  }
  {
    // approvals by an identity holding no claim are never read, whatever it publishes
    const t = transport([approvalDoc("A"), approvalDoc("B"), approvalDoc("A", { writerHex: STRANGER, revision: 9, tweak: oldRefund })]);
    const r = await decide(null, { transport: t });
    ok(`a stranger's approvals for the pool change nothing (got ${JSON.stringify(r.refusals)})`, r.ok === true);
    ok("and are never queried", t.calls.every((c) => !Buffer.from(c.where[0][2]).equals(Buffer.from(STRANGER, "hex"))) && t.calls.length === 2);
    ok("each query is by owner and pool, as bytes, in the index's order", t.calls.every((c) => c.where[0][0] === "$ownerId" && c.where[1][0] === "poolId"
      && Buffer.isBuffer(c.where[0][2]) && Buffer.isBuffer(c.where[1][2]) && JSON.stringify(c.orderBy) === JSON.stringify([["termsRevision", "asc"]])));
  }

  // ---- RULE 2: the owner identity binding ----
  {
    // B's identity publishes A's owner-signed record under its own identity
    const { record, sig } = signed("A");
    const copied = docOf({ writerHex: ID.B, record, sig });
    await refuses("OWNER: a document whose owner is not the record's member", [approvalDoc("A"), copied], "OWNER");
  }
  {
    // the replay at a higher index: A's identity republishes A's owner-signed revision-1 record
    // (superseded terms) at termsRevision 3, above A's real revision 2
    const { record, sig } = signed("A", { tweak: oldRefund });
    const replay = docOf({ writerHex: ID.A, record, sig, termsRevision: 3 });
    await refuses("an old owner-signed record republished at a higher revision index",
      [approvalDoc("A", { tweak: oldRefund }), approvalDoc("A", { revision: 2 }), replay, approvalDoc("B")], "a revision its record does not carry");
  }
  {
    const { record, sig } = signed("A");
    const pretty = docOf({ writerHex: ID.A, record, sig, recordBytes: Buffer.from(JSON.stringify(record, null, 1)) });
    await refuses("a record stored in a non-canonical encoding", [pretty, approvalDoc("B")], "not store its record in canonical form");
  }
  await refuses("SUBSTITUTION: an owner signature by another key", [approvalDoc("A", { signer: owner.B }), approvalDoc("B")], "SUBSTITUTION");
  {
    const { record, sig } = signed("A");
    const other = require("crypto").createHash("sha256").update("another pool").digest("hex");
    const moved = docOf({ writerHex: ID.A, record, sig, poolId: other });
    let why = "";
    try { ledger.verifyLedgerApproval({ doc: ledger.servedApprovalToPlain(moved), claimantHex: ID.A, expect: { ...EXPECT, registrationHeight: H }, verifyMessage }); }
    catch (e) { why = e.message; }
    ok(`a document indexed under a pool its record does not name refuses (got "${why}")`, /a pool its record does not name/.test(why));
  }

  // ---- the served-document adapter checks what the DPP's serializer does not ----
  {
    const { record, sig } = signed("A");
    const short = docOf({ writerHex: ID.A, record, sig: sig.subarray(0, 64) });
    await refuses("a 64-byte owner signature", [short, approvalDoc("B")], "ownerSignature is 64 bytes");
    const big = docOf({ writerHex: ID.A, record, sig, recordBytes: Buffer.alloc(5000, 32) });
    await refuses("a record above the schema's 4,096 bytes", [big, approvalDoc("B")], "record is 5000 bytes");
    const fake = { id: { base58: () => b58OfHex("aa".repeat(32)) }, ownerId: { base58: () => b58OfHex(ID.A) },
      properties: { poolId: new Uint8Array(Buffer.from(POOL, "hex")), termsRevision: 1, record: new Uint8Array(4), ownerSignature: new Uint8Array(65) }, createdAt: 1n };
    let why = "";
    try { ledger.servedApprovalToPlain(fake); } catch (e) { why = e.message; }
    ok(`a served approval without a creation core height refuses (got "${why}")`, /createdAtCoreBlockHeight/.test(why));
    // the schema's upper bound on termsRevision, which the DPP's serializer would refuse to write but
    // a served value is still checked against (the review's case, 2026-09-28)
    const over = { ...fake, createdAtCoreBlockHeight: 1, properties: { ...fake.properties, termsRevision: 4294967296 } };
    why = "";
    try { ledger.servedApprovalToPlain(over); } catch (e) { why = e.message; }
    ok(`a served termsRevision above 4,294,967,295 refuses (got "${why}")`, /termsRevision \(4294967296, outside 1\.\.4294967295\)/.test(why));
    const high = { ...fake, createdAtCoreBlockHeight: 4294967296 };
    why = "";
    try { ledger.servedApprovalToPlain(high); } catch (e) { why = e.message; }
    ok(`a served core height above the u32 range refuses (got "${why}")`, /createdAtCoreBlockHeight \(4294967296/.test(why));
  }
  {
    // an adapter serving another owner's document inside a member's page
    const t = transport([approvalDoc("A"), approvalDoc("B")], { extraOwnerDoc: approvalDoc("A", { writerHex: STRANGER, revision: 2 }) });
    await refuses("a member's page carrying another owner's approval", null, "served an approval owned by", { transport: t });
  }
  {
    // an adapter serving the member's own approval for ANOTHER pool inside this pool's page
    const other = require("crypto").createHash("sha256").update("another pool").digest("hex");
    const t = transport([approvalDoc("A"), approvalDoc("B")], { extraPoolDoc: approvalDoc("A", { revision: 2, poolId: other }) });
    await refuses("a member's page carrying an approval for another pool", null, "served an approval for pool", { transport: t });
  }
  await refuses("a completion naming another pool than the approvals are read for", [approvalDoc("A"), approvalDoc("B")],
    "names a pool or contract other than", { inputs: { poolIdHex: "ab".repeat(32) } });

  // ---- unit 2's REAL Core owner signature, through the ledger binding ----
  {
    const r = REAL.record;
    const sigBytes = Buffer.from(REAL.ownerSignature, "base64");
    ok("the real Core signature is 65 bytes, the schema's size", sigBytes.length === 65);
    const doc = docOf({ writerHex: r.memberIdentity, record: r, sig: sigBytes, poolId: r.poolId, coreHeight: 600 });
    const plain = ledger.servedApprovalToPlain(doc);
    const v = ledger.verifyLedgerApproval({ doc: plain, claimantHex: r.memberIdentity,
      expect: { platformChainId: r.platformChainId, contractId: r.contractId, poolIdHex: r.poolId, l1GenesisHash: r.l1GenesisHash, registrationHeight: 622 }, verifyMessage });
    ok("the rc.1 wallet's signature verifies through the ledger binding, from bytes stored in a document", v.revision === r.revision && v.identityHex === r.memberIdentity);
    let why = "";
    try {
      await ledger.readFixedApprovals({ claimantsHex: [r.memberIdentity], poolIdHex: r.poolId, registrationHeight: 622, platformChainId: r.platformChainId,
        l1GenesisHash: r.l1GenesisHash, anchor: ANCHOR, approvalContractId: APPROVALS, fetchVerifiedPage: transport([doc]).fetch });
    } catch (e) { why = e.message; }
    ok(`and the regtest registration it was made for is refused by SAME CHAIN, the one rule it cannot pass (got "${why.slice(0, 80)}")`, /^SAME CHAIN/.test(why));
  }

  // ---- the anchor adapter ----
  {
    const a = ledger.anchorFromMetadata({ chainId: CHAIN, height: 603336n, coreChainLockedHeight: 1562110 }, CHAIN);
    ok("the anchor reads a proved read's heights", a.platformHeight === "603336" && a.coreChainLockedHeight === 1562110);
    let why = "";
    try { ledger.anchorFromMetadata({ chainId: "dash-testnet-50", height: 1, coreChainLockedHeight: 1 }, CHAIN); } catch (e) { why = e.message; }
    ok("an anchor on another Platform chain refuses", /not dash-testnet-51/.test(why));
  }

  console.log(`memberApprovalLedgerTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
})().catch((e) => { console.error(e); process.exitCode = 1; });
