"use strict";
/**
 * WRITING A MEMBER'S APPROVAL to the approval contract (tegara/docs/APPROVAL_CONTRACT_DESIGN.md),
 * the decisions the A/B demonstration's runner (approvalDemoRun.mjs) makes, here so a battery drives
 * them (approvalWriteTest.cjs).
 *
 *   documentFromApproval   a unit 2 approval file into the document's four fields, refusing a record
 *                          that is not canonical or a signature that is not 65 bytes
 *   planWrite              write, already present (identical), or refuse (different bytes at the same
 *                          revision), from the member's own approvals read by proof
 *   duplicateVerdict       the contrary control: a second document at an existing (owner, pool,
 *                          revision) must be refused by consensus FOR THE UNIQUE INDEX, since a refusal
 *                          for any other reason would not show the index holds. It reads the wait
 *                          wrapper's STRUCTURED refusal code, not e2Outcome's token: when the
 *                          demonstration ran, that classifier's identity was unpinned and labeled
 *                          every consensus refusal "other", so the first live run's control could never
 *                          have passed. The classifier was pinned afterwards (consensusErrorPin.cjs,
 *                          code AND payload). This control stays CODE-ONLY and separate, a narrower
 *                          check for one demonstration, and is not the shared identity.
 *
 * The record and signature are carried unchanged. This module signs nothing: the document is signed
 * by the member identity's own key, which is Platform's writer check.
 */
const { canonicalString } = require("./canonicalJson.cjs");
const approval = require("./memberApproval.cjs");
const { OWNER_SIGNATURE_BYTES, RECORD_MAX_BYTES } = require("./approvalContract.cjs");

const refuse = (why) => { throw new Error(`approvalWrite: ${why}; refusing`); };

/** approvalFile: { record, ownerSignature (base64) } as unit 2's member side wrote it. */
function documentFromApproval(approvalFile) {
  if (!approvalFile || typeof approvalFile !== "object") refuse("no approval file");
  const record = approval.requireRecord(approvalFile.record);
  const recordBytes = Buffer.from(canonicalString(record), "utf8");
  if (recordBytes.length > RECORD_MAX_BYTES) refuse(`the record is ${recordBytes.length} bytes, above ${RECORD_MAX_BYTES}`);
  if (typeof approvalFile.ownerSignature !== "string") refuse("the approval carries no owner signature");
  const sig = Buffer.from(approvalFile.ownerSignature, "base64");
  if (sig.length !== OWNER_SIGNATURE_BYTES || sig.toString("base64") !== approvalFile.ownerSignature) {
    refuse(`the owner signature is not ${OWNER_SIGNATURE_BYTES} bytes of canonical base64`);
  }
  return { memberIdentityHex: record.memberIdentity, poolIdHex: record.poolId, termsRevision: record.revision,
    recordHex: recordBytes.toString("hex"), ownerSignatureHex: sig.toString("hex") };
}

/**
 * wanted: documentFromApproval's answer. served: the member's approvals for the pool, read by proof
 * and passed through memberApprovalLedger.servedApprovalToPlain. Returns "write" or "already-present",
 * and refuses when the member already holds different bytes at that revision or the read serves
 * another owner's or pool's document.
 */
function planWrite({ wanted, served }) {
  if (!Array.isArray(served)) refuse("the member's approvals were not read");
  for (const d of served) {
    if (d.ownerId !== wanted.memberIdentityHex || d.poolId !== wanted.poolIdHex) refuse("the read served another owner's or pool's approval");
  }
  const at = served.filter((d) => d.termsRevision === wanted.termsRevision);
  if (at.length === 0) return "write";
  if (at.length === 1 && at[0].record === wanted.recordHex && at[0].ownerSignature === wanted.ownerSignatureHex) return "already-present";
  return refuse(`member ${wanted.memberIdentityHex.slice(0, 12)}... already holds different approval bytes at revision ${wanted.termsRevision}`);
}

// Platform's consensus code for DuplicateUniqueIndexError, rs-dpp errors/consensus/codes.rs at v4.1.1
// (40100 is DocumentAlreadyPresentError, a different refusal). The error's data payload is NOT decoded
// here, so the verdict rests on the code alone: a refusal with code 40105 passes whatever its message
// or data. The runner logs the data's hex since 2026-09-28 (the committed runs before that did not).
const DUPLICATE_UNIQUE_INDEX_CODE = 40105;

/**
 * The duplicate control's result from the wait wrapper's result object: { outcome: "verified-proof" }
 * or { outcome: "execution-refusal", code, message, ... }, or anything else.
 */
function duplicateVerdict(result) {
  if (!result || typeof result !== "object") return "unsettled";
  if (result.outcome === "verified-proof") return "accepted";
  if (result.outcome !== "execution-refusal" || !Number.isSafeInteger(result.code)) return "unsettled";
  if (result.code === DUPLICATE_UNIQUE_INDEX_CODE) return "refused-by-unique-index";
  if (result.code >= 10000 && result.code < 50000) return "refused-otherwise";
  return "unsettled";
}

module.exports = { documentFromApproval, planWrite, duplicateVerdict, DUPLICATE_UNIQUE_INDEX_CODE };
