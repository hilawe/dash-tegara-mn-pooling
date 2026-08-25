/**
 * Offline exact-diff test for v11 (plain `node`, no network), per the adoption
 * table's builder-test row: v11 against buildV9 is EXACTLY five added document-type
 * keys, and every inherited v9 type is DEEPLY EQUAL (the lineage builders return
 * document-type maps and carry no version member, so the diff asserts the type maps
 * alone; v11 SELECTION is tested separately in the version-table and environment
 * rows). The five expected types are pinned as COMPLETE objects transcribed from
 * the build spec's literal fragments, not spot-checks, per the v9 test's net-2
 * convention.
 */
const path = require("path");
const { pathToFileURL } = require("url");
const { buildV9 } = require("./contractV9.cjs");
const { buildV11, E2_TYPES } = require("./contractV11.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed++; }
  else { failed++; console.error("FAIL:", name); }
};
const assert = require("assert");
const eq = (a, b) => { try { assert.deepStrictEqual(a, b); return true; } catch { return false; } };

const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };

// the five COMPLETE expected E2 types, transcribed from the build spec's fragments
// independently of the builder (the builder is the code under test; these literals
// are the expectation, derived from the spec rather than from the code)
const EXPECTED = {
  epochHeader: {
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
  },
  platformAccrual: {
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
  },
  transferReceipt: {
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
  },
  receiptProofPart: {
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
  },
  transferReservation: {
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
  },
};

(async () => {
  const contractUrl = pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href;
  const { poolLedgerContract } = await import(contractUrl);
  const v9 = buildV9(poolLedgerContract);
  const v11 = buildV11(poolLedgerContract);

  // ---- the exact diff: EXACTLY five added type keys, nothing removed ----
  const v9Keys = Object.keys(v9).sort();
  const v11Keys = Object.keys(v11).sort();
  const added = v11Keys.filter((k) => !v9Keys.includes(k));
  const removed = v9Keys.filter((k) => !v11Keys.includes(k));
  ok("v11 removes no v9 type", removed.length === 0);
  ok("v11 adds exactly the five E2 types",
    eq(added.sort(), [...E2_TYPES].sort()) && added.length === 5);

  // ---- every inherited v9 type is DEEPLY EQUAL (v11 changes nothing it inherits) ----
  for (const t of v9Keys) {
    ok(`inherited type ${t} deeply equal to its v9 form`, eq(v9[t], v11[t]));
  }

  // ---- each added type matches its spec-transcribed complete pin ----
  for (const t of E2_TYPES) {
    ok(`E2 type ${t} matches the build spec's literal fragment`, eq(EXPECTED[t], v11[t]));
  }

  // ---- position hygiene on the added types: unique and contiguous from 0 ----
  for (const t of E2_TYPES) {
    const pos = Object.values(v11[t].properties).map((x) => x.position).sort((a, b) => a - b);
    ok(`positions unique+contiguous in ${t}`, pos.every((v, i) => v === i));
  }

  // ---- the uniqueness spine the E2 procedure rests on, pinned as COMPLETE
  // index objects (name, property membership AND order, the unique flag), not
  // names alone: a spine index dropping a property would otherwise pass a
  // name-only check (the pre-commit checker's finding on this unit) ----
  const uniqIndices = (t) => v11[t].indices.filter((i) => i.unique)
    .sort((a, b) => a.name.localeCompare(b.name));
  ok("epochHeader unique spine is exactly byPoolEpoch(poolId,epochIndex)",
    eq(uniqIndices("epochHeader"),
      [{ name: "byPoolEpoch", properties: [{ poolId: "asc" }, { epochIndex: "asc" }], unique: true }]));
  ok("platformAccrual unique spine is exactly byPoolFunderEpoch(poolId,funderId,epochIndex)",
    eq(uniqIndices("platformAccrual"),
      [{ name: "byPoolFunderEpoch", properties: [{ poolId: "asc" }, { funderId: "asc" }, { epochIndex: "asc" }], unique: true }]));
  ok("transferReceipt unique spine is exactly byAccrual(accrualId)+byTransition(transitionHash)",
    eq(uniqIndices("transferReceipt"),
      [{ name: "byAccrual", properties: [{ accrualId: "asc" }], unique: true },
        { name: "byTransition", properties: [{ transitionHash: "asc" }], unique: true }]));
  ok("receiptProofPart unique spine is exactly byAccrualPart(accrualId,partIndex)",
    eq(uniqIndices("receiptProofPart"),
      [{ name: "byAccrualPart", properties: [{ accrualId: "asc" }, { partIndex: "asc" }], unique: true }]));
  ok("transferReservation unique spine is exactly byAccrual(accrualId) (a soundness-review finding)",
    eq(uniqIndices("transferReservation"),
      [{ name: "byAccrual", properties: [{ accrualId: "asc" }], unique: true }]));

  console.log(`contractV11Test: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
})();
