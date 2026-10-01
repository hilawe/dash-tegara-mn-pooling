// The approval-write battery, over unit 2's REAL approval files (records and Core owner signatures
// from rc.1 wallets, tegara/evidence/member-approval/2026-09-27/), the ones the A/B demonstration
// writes. The served side is built by the pinned DPP and read through the ledger adapter.
//
// THE MUTATION LIST, written before the cases: skip the canonical re-encoding; accept any signature
// length; call a different record at the same revision already present; accept an accepted duplicate
// or a refusal for another reason as the control passing.
const fs = require("fs");
const path = require("path");
const dpp = require("pshenmic-dpp");
const W = require("./approvalWrite.cjs");
const ledger = require("./memberApprovalLedger.cjs");
const { buildApprovalSchemas, APPROVAL_TYPE } = require("./approvalContract.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => { try { fn(); ok(`${name} (expected a refusal)`, false); } catch (e) { ok(`${name}: ${e.message}`, re.test(e.message)); } };
// the approvals are fixtures beside this battery (copied verbatim from unit 2's evidence), so the
// battery runs from a clone that carries no evidence folder
const APPROVALS = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "member-approval-rc1-approvals.json"), "utf8")).approvals;
const file = (n) => APPROVALS[n];
const A1 = file("memberA-rev1"), A2 = file("memberA-rev2"), B2 = file("memberB-rev2");
const CONTRACT = new dpp.DataContractWASM(new dpp.IdentifierWASM("11".repeat(32)), 12n, buildApprovalSchemas(), undefined, undefined, true, 12);

let n = 0;
const served = (w, over = {}) => {
  const d = new dpp.DocumentWASM({ poolId: new Uint8Array(Buffer.from(over.poolIdHex || w.poolIdHex, "hex")), termsRevision: w.termsRevision,
    record: new Uint8Array(Buffer.from(over.recordHex || w.recordHex, "hex")), ownerSignature: new Uint8Array(Buffer.from(w.ownerSignatureHex, "hex")) },
    APPROVAL_TYPE, 1n, CONTRACT.id, new dpp.IdentifierWASM(over.owner || w.memberIdentityHex), new dpp.IdentifierWASM((++n).toString(16).padStart(64, "0")));
  d.createdAt = 1759000000000n; d.createdAtCoreBlockHeight = 1562400;
  return ledger.servedApprovalToPlain(d);
};

// ---- the document from a real approval file ----
{
  const w = W.documentFromApproval(A2);
  ok("A's revision 2 becomes a document for A's identity, the pool, revision 2", w.memberIdentityHex === A2.record.memberIdentity
    && w.poolIdHex === A2.record.poolId && w.termsRevision === 2);
  ok("the owner signature is its 65 bytes", Buffer.from(w.ownerSignatureHex, "hex").length === 65
    && Buffer.from(w.ownerSignatureHex, "hex").toString("base64") === A2.ownerSignature);
  // the record bytes are what the ledger binding accepts: served back, verified with the real signature
  const v = ledger.verifyLedgerApproval({ doc: served(w), claimantHex: w.memberIdentityHex,
    expect: { platformChainId: A2.record.platformChainId, contractId: A2.record.contractId, poolIdHex: A2.record.poolId,
      l1GenesisHash: A2.record.l1GenesisHash, registrationHeight: 622 },
    verifyMessage: (addr, msg, sig) => { const L = require("@dashevo/dashcore-lib"); try { return new L.Message(msg).verify(addr, sig); } catch { return false; } } });
  ok("and the document it makes passes the ledger binding with the real rc.1 signature", v.revision === 2 && v.identityHex === A2.record.memberIdentity);
}
throws("a signature that is not 65 bytes", () => W.documentFromApproval({ ...A2, ownerSignature: Buffer.alloc(64, 1).toString("base64") }), /not 65 bytes/);
throws("a version-1 agreement relabeled as version 2 is refused by the version-2 rules", () => W.documentFromApproval({ ...A2, record: { ...A2.record, version: 2 } }), /version-2 agreement/);

// ---- the write plan ----
{
  const a1 = W.documentFromApproval(A1), a2 = W.documentFromApproval(A2);
  ok("nothing on the ledger: write", W.planWrite({ wanted: a2, served: [] }) === "write");
  ok("revision 1 present, revision 2 wanted: write", W.planWrite({ wanted: a2, served: [served(a1)] }) === "write");
  ok("the identical approval present: already present, no second write", W.planWrite({ wanted: a2, served: [served(a1), served(a2)] }) === "already-present");
  throws("different bytes already at the wanted revision", () => W.planWrite({ wanted: a2, served: [served(a2, { recordHex: a1.recordHex })] }), /different approval bytes at revision 2/);
  const b2 = W.documentFromApproval(B2);
  throws("a read serving another owner's approval", () => W.planWrite({ wanted: a2, served: [served(b2)] }), /another owner's or pool's/);
  // the same owner, revision and bytes under ANOTHER pool (the closing review's case, 2026-09-28): not
  // "already present", because the pool comparison is its own check
  const otherPool = require("crypto").createHash("sha256").update("another pool").digest("hex");
  throws("a read serving the same owner's approval for another pool", () => W.planWrite({ wanted: a2, served: [served(a2, { poolIdHex: otherPool })] }), /another owner's or pool's/);
}

// ---- the duplicate control ----
const refusal = (code) => ({ outcome: "execution-refusal", code, message: "m", data: "" });
ok("a refusal with code 40105 passes the control", W.duplicateVerdict(refusal(40105)) === "refused-by-unique-index");
ok("40100 (a document already present) does not", W.duplicateVerdict(refusal(40100)) === "refused-otherwise");
ok("another consensus refusal does not", W.duplicateVerdict(refusal(40204)) === "refused-otherwise");
ok("an accepted duplicate fails it", W.duplicateVerdict({ outcome: "verified-proof" }) === "accepted");
ok("a gateway code or no result is unsettled, never a pass", W.duplicateVerdict(refusal(13)) === "unsettled"
  && W.duplicateVerdict({ outcome: "transport-failure" }) === "unsettled" && W.duplicateVerdict(undefined) === "unsettled");
// THIS CONTROL IS CODE-ONLY AND THE SHARED CLASSIFIER IS NOT: the pinned identity also reads the
// payload, so the two disagree on a 40105 whose data does not decode, and must stay separate
{
  const { classifyOutcome, TOKENS } = require("./e2Outcome.cjs");
  const bare = { outcome: "execution-refusal", code: 40105, data: "", message: "m" };
  ok("a 40105 with no payload passes this code-only control but is ambiguous to the pinned classifier",
    W.duplicateVerdict(bare) === "refused-by-unique-index" && classifyOutcome(bare) === TOKENS.AMBIGUOUS);
}

console.log(`approvalWriteTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
