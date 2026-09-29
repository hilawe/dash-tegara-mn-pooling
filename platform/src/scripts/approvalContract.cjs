"use strict";
/**
 * THE MEMBER-APPROVAL CONTRACT (tegara/docs/APPROVAL_CONTRACT_DESIGN.md, formation unit 3): one
 * document type in a contract of its own, separate from canonical v11. PERMANENT ONCE PUBLISHED,
 * and the contract is read-only, so nothing below can change after publication.
 *
 * A member's identity writes each approval itself. The document carries the canonical record and
 * the owner key's signature over it, and Platform's check of the writer's signature stands in for
 * unit 2's separate identity signature. The unique index is led by `$ownerId`, never by a member
 * property, because Platform enforces uniqueness over the index: a member property would let any
 * identity occupy another member's (pool, revision) slot first. The member's revision is the
 * property `termsRevision`, not `revision`, because a served document already carries its own
 * `revision` (the document's, always 1 for an immutable type) and one name for two things invites an
 * adapter to read the wrong one.
 *
 * `$createdAtCoreBlockHeight` is REQUIRED because the fixed-set rule orders approvals against the
 * registration by it (memberApprovalLedger.cjs). Drive stores a system field only when the type
 * requires it, and the DPP accepts any `$` name in `required` (an invented one passed validation on
 * 2026-09-28), so a passing validation does not show the field is meaningful. That it is stamped
 * from the block's chain-locked height was read in Drive's source, not inferred from validation.
 */
const APPROVAL_TYPE = "memberTermsApproval";
const RECORD_MAX_BYTES = 4096;
const OWNER_SIGNATURE_BYTES = 65;
// signatureSecurityLevelRequirement: 1 CRITICAL, 2 HIGH, 3 MEDIUM. HIGH admits CRITICAL and HIGH keys
const SIGNATURE_LEVEL_HIGH = 2;

const MEMBER_TERMS_APPROVAL = {
  type: "object",
  documentsMutable: false, canBeDeleted: false, creationRestrictionMode: 0,
  transferable: 0, tradeMode: 0,
  signatureSecurityLevelRequirement: SIGNATURE_LEVEL_HIGH,
  properties: {
    poolId:         { type: "array", byteArray: true, minItems: 32, maxItems: 32, position: 0 },
    termsRevision:  { type: "integer", minimum: 1, maximum: 4294967295, position: 1 },
    record:         { type: "array", byteArray: true, minItems: 2, maxItems: RECORD_MAX_BYTES, position: 2 },
    ownerSignature: { type: "array", byteArray: true, minItems: OWNER_SIGNATURE_BYTES, maxItems: OWNER_SIGNATURE_BYTES, position: 3 },
  },
  required: ["poolId", "termsRevision", "record", "ownerSignature", "$createdAt", "$createdAtCoreBlockHeight"],
  additionalProperties: false,
  indices: [
    { name: "byOwnerPoolRevision", properties: [{ $ownerId: "asc" }, { poolId: "asc" }, { termsRevision: "asc" }], unique: true },
  ],
};

/** The publication payload's document schemas, rebuilt from source on every call. */
function buildApprovalSchemas() {
  return { [APPROVAL_TYPE]: JSON.parse(JSON.stringify(MEMBER_TERMS_APPROVAL)) };
}

/**
 * The contract config the publication sets, COMPLETE, and exactly what a published contract must
 * carry. Every member is stated, the DPP's defaults included, because a read-back that compared only
 * the members chosen here would record a contract with any other setting as published (a review of
 * 2026-09-28 changed documentsKeepHistoryContractDefault and the partial comparison passed). The
 * battery checks this object against what the pinned DPP builds and against a serialization round
 * trip, so it is not a second copy that can drift unseen.
 */
const CONTRACT_CONFIG = Object.freeze({
  $formatVersion: "1", readonly: true, canBeDeleted: false, keepsHistory: false,
  documentsKeepHistoryContractDefault: false, documentsMutableContractDefault: true,
  documentsCanBeDeletedContractDefault: true, requiresIdentityEncryptionBoundedKey: null,
  requiresIdentityDecryptionBoundedKey: null, sizedIntegerTypes: true,
});

module.exports = { APPROVAL_TYPE, RECORD_MAX_BYTES, OWNER_SIGNATURE_BYTES, SIGNATURE_LEVEL_HIGH,
  buildApprovalSchemas, CONTRACT_CONFIG };
