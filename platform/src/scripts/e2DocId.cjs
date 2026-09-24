/**
 * e2DocId: the deterministic PLANNED WRITE IDENTIFIER of an E2 document, as a pure module
 * (the per-epoch context design, build-order step 3c; contract section 3.2, "the planned
 * write identifier").
 *
 * WHAT IT IS. The live driver derived every document identifier it was about to create
 * inside its own closure: an entropy of sha256 over
 * `tegara.e2.entropy.v1|type|pool|epoch|subject`, fed to the Platform document identifier
 * generator with the writer identity and the contract identifier. The transport runner
 * carried a second copy of the same formula. Two copies of one derivation is the drift the
 * shared modules exist to end, and the orchestrator's context builder (step 4) needs the
 * derivation for any epoch, not for the one a closure was built over. This module is that
 * derivation, once, with no closure and no I/O.
 *
 * WHAT IT ESTABLISHES: the entropy is BYTE-IDENTICAL to the driver's formula for the same
 * inputs (the test reproduces the old formula inline and compares, and drives the installed
 * generator); every input is CANONICAL-ONLY (the design's section 8): the pool a 64-hex
 * lowercase primitive string, the epoch a non-negative safe integer, the type one of the
 * five v11 document types, the subject the grammar that type uses and nothing else, the
 * owner and contract identifiers non-empty primitive strings handed to the generator
 * unread, the generator a function whose result must decode to 32 bytes. A subject or a
 * pool in any other form (base58, uppercase, a byte object, a boxed string) is refused by
 * name, so a mixed representation never reaches the entropy. EVERY INPUT IS READ EXACTLY
 * ONCE, through its own data descriptor, into a local before validation, and validation,
 * hashing and the generator call all use those locals (the preliminary review's F1: an
 * accessor that changed its answer between validation and use could otherwise hash an
 * unvalidated pool or hand the generator a different type); an accessor or an inherited
 * member is refused by name without being invoked.
 *
 * WHAT IT DOES NOT ESTABLISH, stated: the generator is INJECTED (the runners pass a bound
 * `DocumentWASM.generateId`), so the identifier's agreement with what Platform assigns on
 * creation is the generator's obligation, exercised at acceptance stage, not here; the
 * offline test proves the entropy and the plumbing, and byte-identity with the previous
 * inline formula against the installed generator, whose identifiers it checks VARY with the
 * entropy (a constant stub is refused) without authenticating the implementation. THE
 * RESULT CONVERSION IS NARROWER THAN THE OLD WRAPPER'S: that wrapper accepted any
 * string-convertible generator result through `String(id)`; this module accepts a primitive
 * string or an object whose `base58` is a callable method, and refuses anything else, a
 * string-valued `base58` property included.
 *
 * THE SUBJECT GRAMMAR, per type, read from the driver's call sites:
 *   platformAccrual      the funder's 64-hex identity
 *   transferReservation  the accrual's 64-hex document identifier
 *   transferReceipt      the accrual's 64-hex document identifier
 *   receiptProofPart     `<accrual 64-hex>#<partIndex 1..7>` (the splitter emits indices
 *                        from 1 below a part count capped at 8)
 *   epochHeader          `header#<epochIndex>`, canonical digits, the epoch equal to the
 *                        one passed
 */
"use strict";
const crypto = require("crypto");
const formationCore = require("./formationCore.cjs");

const refuse = (msg) => { throw new Error(`e2DocId: ${msg}; refusing`); };

const ENTROPY_DOMAIN = "tegara.e2.entropy.v1";
const DOCUMENT_TYPES = Object.freeze(["epochHeader", "platformAccrual", "transferReservation",
  "transferReceipt", "receiptProofPart"]);
const HEX64 = /^[0-9a-f]{64}$/;
const PART_SUBJECT = /^([0-9a-f]{64})#([1-7])$/;
const HEADER_SUBJECT = /^header#(0|[1-9][0-9]*)$/;

const isPrimitiveString = (v) => typeof v === "string";

// ONE READ PER INPUT: each named member is taken from its OWN DATA descriptor into a
// local, so nothing is read twice and no accessor or inherited member is consulted
const takeOwnData = (input, name, required) => {
  const d = Object.getOwnPropertyDescriptor(input, name);
  if (!d) {
    if (required) refuse(`${name} is required as an own data member of the options`);
    return undefined;
  }
  if (!("value" in d)) refuse(`${name} must be an own DATA member, not an accessor (an accessor is refused without being invoked)`);
  return d.value;
};

const takeInputs = (input, fnName, withGenerator) => {
  if (input === null || typeof input !== "object" || Array.isArray(input)) refuse(`${fnName} takes one options object`);
  const captured = {
    poolId: takeOwnData(input, "poolId", true),
    epochIndex: takeOwnData(input, "epochIndex", true),
    type: takeOwnData(input, "type", true),
    subject: takeOwnData(input, "subject", true),
  };
  if (withGenerator) {
    captured.generateId = takeOwnData(input, "generateId", true);
    captured.ownerId = takeOwnData(input, "ownerId", true);
    captured.contractId = takeOwnData(input, "contractId", true);
  }
  return captured;
};

// the subject's grammar is the type's, and a subject in any other form is refused
// by name rather than hashed into an identifier nobody will ever look up
const validateSubject = (type, subject, epochIndex) => {
  if (!isPrimitiveString(subject)) refuse(`the ${type} subject must be a primitive string (got ${typeof subject})`);
  if (subject.includes("|")) refuse(`the ${type} subject carries the entropy delimiter`);
  switch (type) {
    case "platformAccrual":
      if (!HEX64.test(subject)) refuse("a platformAccrual subject is the funder's 64-hex lowercase identity");
      return;
    case "transferReservation":
    case "transferReceipt":
      if (!HEX64.test(subject)) refuse(`a ${type} subject is the accrual's 64-hex lowercase document identifier`);
      return;
    case "receiptProofPart":
      if (!PART_SUBJECT.test(subject)) refuse("a receiptProofPart subject is `<accrual 64-hex>#<partIndex 1..7>`");
      return;
    case "epochHeader": {
      const m = HEADER_SUBJECT.exec(subject);
      if (!m) refuse("an epochHeader subject is `header#<epochIndex>` in canonical digits");
      if (Number(m[1]) !== epochIndex) refuse(`the epochHeader subject names epoch ${m[1]} while the derivation is for epoch ${epochIndex}`);
      return;
    }
    default:
      refuse(`unknown document type ${JSON.stringify(type)}`);
  }
};

const validateCommon = ({ poolId, epochIndex, type, subject }) => {
  if (!isPrimitiveString(poolId) || !HEX64.test(poolId)) refuse("poolId must be a 64-hex lowercase primitive string");
  if (!Number.isSafeInteger(epochIndex) || epochIndex < 0) refuse("epochIndex must be a non-negative safe integer");
  if (!isPrimitiveString(type) || !DOCUMENT_TYPES.includes(type)) refuse(`type must be one of ${DOCUMENT_TYPES.join("/")}`);
  validateSubject(type, subject, epochIndex);
};

const entropyOf = ({ poolId, epochIndex, type, subject }) =>
  crypto.createHash("sha256").update(`${ENTROPY_DOMAIN}|${type}|${poolId}|${epochIndex}|${subject}`).digest();

/**
 * entropyForIn({ poolId, epochIndex, type, subject }) -> Buffer of 32 bytes, sha256 over
 * `tegara.e2.entropy.v1|type|pool|epoch|subject`, byte-identical to the driver's formula,
 * computed over the captured locals and nothing re-read.
 */
const entropyForIn = (input) => {
  const c = takeInputs(input, "entropyForIn", false);
  validateCommon(c);
  return entropyOf(c);
};

/**
 * docIdForIn({ generateId, ownerId, contractId, poolId, epochIndex, type, subject })
 *   -> { b58, hex, entropy }
 * `generateId(type, ownerId, contractId, entropyBytes)` is the injected Platform generator,
 * called ONCE with the captured locals; its result must be a primitive base58 string or an
 * object whose `base58` is a callable method, decoding to 32 bytes.
 */
const docIdForIn = (input) => {
  const c = takeInputs(input, "docIdForIn", true);
  if (typeof c.generateId !== "function") refuse("generateId must be the injected identifier generator function");
  if (!isPrimitiveString(c.ownerId) || c.ownerId.length === 0) refuse("ownerId must be a non-empty primitive string (the writer identity as the generator takes it)");
  if (!isPrimitiveString(c.contractId) || c.contractId.length === 0) refuse("contractId must be a non-empty primitive string (the contract identifier as the generator takes it)");
  validateCommon(c);
  const entropy = entropyOf(c);
  const id = c.generateId(c.type, c.ownerId, c.contractId, new Uint8Array(entropy));
  const b58 = isPrimitiveString(id) ? id
    : (id !== null && typeof id === "object" && typeof id.base58 === "function" ? id.base58() : null);
  if (!isPrimitiveString(b58) || b58.length === 0) refuse("the generator returned no base58 identifier (a primitive string or an object with a callable base58 method)");
  const d = formationCore.toId32(b58);
  if (!d) refuse("the generator's identifier does not decode to 32 bytes");
  return { b58, hex: d.toString("hex"), entropy };
};

/**
 * reservationIdForTransfer({ generateId, ownerId, contractId, transferHash }) -> { b58, hex, entropy }
 *
 * A reservation identifier DERIVED FROM THE TRANSFER IT BINDS (tegara/docs/NONCE_OWNERSHIP.md, the
 * 2026-09-24 proof of concept). The entropy is sha256 over `tegara.e2.reservation-by-transfer.v1|`
 * and the transfer hash in lowercase hex, and the identifier comes from the injected Platform
 * generator exactly as `docIdForIn`'s does. Two reservations binding byte-identical transfers, built
 * by the same owner in the same contract, therefore get the SAME identifier, and the ledger refuses
 * the second. Nothing in the contract enforces this derivation, so a writer deriving its entropy any
 * other way is outside that uniqueness.
 */
const RESERVATION_BY_TRANSFER_DOMAIN = "tegara.e2.reservation-by-transfer.v1";
const reservationEntropyForTransfer = (transferHash) => {
  if (!isPrimitiveString(transferHash) || !HEX64.test(transferHash)) refuse("the transfer hash must be 64 lowercase hex");
  return crypto.createHash("sha256").update(`${RESERVATION_BY_TRANSFER_DOMAIN}|${transferHash}`).digest();
};
const reservationIdForTransfer = ({ generateId, ownerId, contractId, transferHash } = {}) => {
  if (typeof generateId !== "function") refuse("generateId must be the injected identifier generator function");
  if (!isPrimitiveString(ownerId) || ownerId.length === 0) refuse("ownerId must be a non-empty primitive string (the writer identity as the generator takes it)");
  if (!isPrimitiveString(contractId) || contractId.length === 0) refuse("contractId must be a non-empty primitive string (the contract identifier as the generator takes it)");
  const entropy = reservationEntropyForTransfer(transferHash);
  const id = generateId("transferReservation", ownerId, contractId, new Uint8Array(entropy));
  const b58 = isPrimitiveString(id) ? id
    : (id !== null && typeof id === "object" && typeof id.base58 === "function" ? id.base58() : null);
  if (!isPrimitiveString(b58) || b58.length === 0) refuse("the generator returned no base58 identifier (a primitive string or an object with a callable base58 method)");
  const d = formationCore.toId32(b58);
  if (!d) refuse("the generator's identifier does not decode to 32 bytes");
  return { b58, hex: d.toString("hex"), entropy };
};

module.exports = { ENTROPY_DOMAIN, DOCUMENT_TYPES, entropyForIn, docIdForIn,
  RESERVATION_BY_TRANSFER_DOMAIN, reservationEntropyForTransfer, reservationIdForTransfer };
