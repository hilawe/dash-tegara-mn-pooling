/**
 * Pure builder for the pool-ledger v11 schema: a REGISTERED sibling of v9 that adds
 * the FIVE E2 document types and changes nothing else. The normative source for every
 * fragment below is tegara/docs/E2_BUILD_SPEC.md ("The five document types, as literal
 * builder fragments"); this file transcribes those fragments exactly, and
 * contractV11Test.cjs pins the exact intended diff (five added type keys, every
 * inherited v9 type deeply equal).
 *
 * v11 takes v9's path, NOT v10's: v10 is a source-only builder (documented and
 * rejected for v11 in the adoption table), because E2 eligibility requires pools
 * FORMED on the published v11 contract. v11 deliberately EXCLUDES v10's retail
 * changes.
 *
 * The E2 types' load-bearing properties, all from the build spec:
 *   - every type immutable, non-deletable, owner-only (creationRestrictionMode 1);
 *   - epochHeader byPoolEpoch UNIQUE (one header per pool-epoch; the duplicate
 *     refusal is the resume signal in the distribution procedure);
 *   - platformAccrual byPoolFunderEpoch UNIQUE (one accrual per member-epoch);
 *   - transferReceipt byAccrual and byTransition both UNIQUE (one receipt per
 *     accrual, one per signed transfer), byPool ordered by the 8-byte big-endian
 *     blockHeight copy so byte order equals numeric order;
 *   - receiptProofPart byAccrualPart UNIQUE, partIndex 1..7 (part 0 lives on the
 *     receipt's own proofBytes; the canonical split is in the build spec);
 *   - transferReservation byAccrual UNIQUE: a soundness-review finding decided remedy, the ledger
 *     itself refusing a second claim on one accrual; the schema carries a
 *     32-byte transitionHash field, and the BINDING of that hash to the exact
 *     signed transfer it authorizes is enforced by the distribution procedure
 *     and verifier units, never by this schema;
 *   - the u64 metadata copies (blockHeight, timeMs) are 8-byte byteArrays at
 *     full u64 domain, so no encoding refusal can arise for them after an
 *     irreversible transfer (build spec, round 5, finding 6); the schema
 *     bounds LENGTH only, and the big-endian encoding plus the
 *     decoded-metadata match are the writer's and verifier's checks;
 *   - byte-range maxima marked EMPIRICAL in the spec (transitionBytes 100..2048)
 *     are re-derived under duty D3 before registration; metadataBytes capacity is
 *     owned by duty D1; proofBytes/metadataBytes minima are 1 (length floors only,
 *     semantic validity is the verifier's and the carrier-conformance stage's job).
 */
const { buildV9 } = require("./contractV9.cjs");

// the ledger's 32-byte byteArray shape, literal per the build spec
const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };

function buildV11(poolLedgerContract) {
  const v11 = buildV9(poolLedgerContract);

  v11.epochHeader = {
    type: "object",
    documentsMutable: false, canBeDeleted: false, creationRestrictionMode: 1,
    properties: {
      poolId:         { ...HASH32, position: 0 },
      epochIndex:     { type: "integer", minimum: 0, maximum: 4294967295, position: 1 },
      grossCredits:   { type: "integer", minimum: 0, maximum: 9007199254740991, position: 2 },
      feeCredits:     { type: "integer", minimum: 0, maximum: 9007199254740991, position: 3 },
      allocationHash: { type: "array", byteArray: true, minItems: 32, maxItems: 32, position: 4 },
      memberCount:    { type: "integer", minimum: 1, maximum: 8, position: 5 },
      calcVersion:    { type: "integer", minimum: 1, maximum: 1, position: 6 },
    },
    required: ["poolId", "epochIndex", "grossCredits", "feeCredits", "allocationHash",
      "memberCount", "calcVersion", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byPoolEpoch", properties: [{ poolId: "asc" }, { epochIndex: "asc" }], unique: true },
    ],
  };

  v11.platformAccrual = {
    type: "object",
    documentsMutable: false, canBeDeleted: false, creationRestrictionMode: 1,
    properties: {
      poolId:        { ...HASH32, position: 0 },
      funderId:      { ...HASH32, position: 1 },
      epochIndex:    { type: "integer", minimum: 0, maximum: 4294967295, position: 2 },
      amountCredits: { type: "integer", minimum: 0, maximum: 9007199254740991, position: 3 },
      shareBps:      { type: "integer", minimum: 1, maximum: 10000, position: 4 },
    },
    required: ["poolId", "funderId", "epochIndex", "amountCredits", "shareBps", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byPoolFunderEpoch",
        properties: [{ poolId: "asc" }, { funderId: "asc" }, { epochIndex: "asc" }], unique: true },
      { name: "byPoolEpoch", properties: [{ poolId: "asc" }, { epochIndex: "asc" }] },
    ],
  };

  v11.transferReceipt = {
    type: "object",
    documentsMutable: false, canBeDeleted: false, creationRestrictionMode: 1,
    properties: {
      poolId:          { ...HASH32, position: 0 },
      accrualId:       { ...HASH32, position: 1 },
      transitionHash:  { type: "array", byteArray: true, minItems: 32, maxItems: 32, position: 2 },
      transitionBytes: { type: "array", byteArray: true, minItems: 100, maxItems: 2048, position: 3 },
      proofBytes:      { type: "array", byteArray: true, minItems: 1, maxItems: 5120, position: 4 },
      proofPartCount:  { type: "integer", minimum: 1, maximum: 8, position: 5 },
      metadataBytes:   { type: "array", byteArray: true, minItems: 1, maxItems: 512, position: 6 },
      blockHeight:     { type: "array", byteArray: true, minItems: 8, maxItems: 8, position: 7 },
      coreChainLockedHeight: { type: "integer", minimum: 0, maximum: 4294967295, position: 8 },
      timeMs:          { type: "array", byteArray: true, minItems: 8, maxItems: 8, position: 9 },
      quorumHash:      { type: "array", byteArray: true, minItems: 32, maxItems: 32, position: 10 },
      round:           { type: "integer", minimum: 0, maximum: 4294967295, position: 11 },
    },
    required: ["poolId", "accrualId", "transitionHash", "transitionBytes", "proofBytes",
      "proofPartCount", "metadataBytes", "blockHeight", "coreChainLockedHeight",
      "timeMs", "quorumHash", "round", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byAccrual", properties: [{ accrualId: "asc" }], unique: true },
      { name: "byTransition", properties: [{ transitionHash: "asc" }], unique: true },
      { name: "byPool", properties: [{ poolId: "asc" }, { blockHeight: "asc" }] },
    ],
  };

  v11.receiptProofPart = {
    type: "object",
    documentsMutable: false, canBeDeleted: false, creationRestrictionMode: 1,
    properties: {
      poolId:    { ...HASH32, position: 0 },
      accrualId: { ...HASH32, position: 1 },
      partIndex: { type: "integer", minimum: 1, maximum: 7, position: 2 },
      bytes:     { type: "array", byteArray: true, minItems: 1, maxItems: 5120, position: 3 },
    },
    required: ["poolId", "accrualId", "partIndex", "bytes", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byAccrualPart", properties: [{ accrualId: "asc" }, { partIndex: "asc" }], unique: true },
      { name: "byPool", properties: [{ poolId: "asc" }, { accrualId: "asc" }] },
    ],
  };

  v11.transferReservation = {
    type: "object",
    documentsMutable: false, canBeDeleted: false, creationRestrictionMode: 1,
    properties: {
      poolId:         { ...HASH32, position: 0 },
      accrualId:      { ...HASH32, position: 1 },
      transitionHash: { type: "array", byteArray: true, minItems: 32, maxItems: 32, position: 2 },
    },
    required: ["poolId", "accrualId", "transitionHash", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byAccrual", properties: [{ accrualId: "asc" }], unique: true },
      { name: "byPool", properties: [{ poolId: "asc" }, { accrualId: "asc" }] },
    ],
  };

  return v11;
}

// the five E2 type names, exported so the diff test and the sweep tooling read ONE list
const E2_TYPES = ["epochHeader", "platformAccrual", "transferReceipt",
  "receiptProofPart", "transferReservation"];

module.exports = { buildV11, E2_TYPES };
