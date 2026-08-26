/**
 * The E2 RECEIPT VERIFIER (the refusal predicates duty D8's audit consumes;
 * ownership assigned in the spec's a review finding): the canonical part
 * split and reassembly, the CARRIER-CONFORMANCE STAGE that runs before any
 * cryptographic check, the lifted-field equalities, the decoded-transfer
 * bindings, the mandatory two-stage proof verification, the reservation
 * conformance (a soundness-review finding), and the served capture-record validity clauses with
 * the capture-versus-receipt byte-equality set.
 *
 * WHAT IT ESTABLISHES: a receipt (or served capture) is accepted ONLY when
 * its parts are exactly the canonical contiguous split, its carriers decode
 * and RE-ENCODE BYTE-EQUAL under the pinned pipeline with the pinned chain
 * identifier and protocol version 12, its lifted fields equal the decoded
 * messages, its transition hash is recomputed from its bytes, its decoded
 * sender, recipient and amount equal the pool's income identity and the
 * recomputed entitlement, BOTH proof stages succeed (the signature check
 * alone authenticates a root without establishing this transition's
 * result), and its reservation chain conforms.
 *
 * WHAT IT DOES NOT ESTABLISH, stated: the pinned decode/re-encode pipeline
 * (C2's calls) and the two proof stages are INJECTED deps, so their
 * cryptographic and canonicalization correctness is the acceptance-stage
 * bindings' obligation; the offline battery proves the ORCHESTRATION,
 * every structural refusal, and that acceptance never happens without both
 * stages succeeding and every equality holding. An unservable reservation
 * query leaves that aspect UNPROVED (a status, never a silent pass and
 * never a refusal), per the frozen audit table.
 *
 * THE DEPS CONTRACT, the acceptance-stage adapter's checkable obligations
 * (an adoption-table artifact; the installed signatures are read at the
 * pinned packages):
 * - decodeProofCarrier(hex) and decodeMetadata(hex): the C2 pipeline's
 *   decode of the COMPLETE carrier, returning reencodedHex (the canonical
 *   known-field re-encoding, unknown fields omitted and counted) plus the
 *   decoded members this module compares (quorumHashHex and round from the
 *   Proof; chainId, protocolVersion, height, timeMs, coreChainLockedHeight
 *   and epoch from the metadata); a throw is an undecodable carrier.
 * - decodeTransfer(hex): the pinned wire decode of the signed
 *   IdentityCreditTransfer, returning senderId, recipientId and
 *   amountCredits.
 * - verifyStageOne({ carrierHex, transitionBytes, blockInfo }): wraps the
 *   installed verifyStateTransitionResult(grovedbProof, stateTransition,
 *   blockInfo, knownContracts, platformVersion) with knownContracts
 *   INCLUDING the pinned v11 contract and the pinned platform version;
 *   returns { ok: true, rootHashHex } exactly when the installed call
 *   returns a NON-NULL successful result, with the derived root.
 * - verifyStageTwo({ rootHashHex, carrierHex, metadata }): wraps the
 *   quorum-key resolution and the installed verifyTenderdashProof over the
 *   canonical vote whose StateId binds rootHashHex as appHash; returns
 *   true exactly on a verified signature.
 */
const crypto = require("crypto");

const HEX_RE = /^([0-9a-f]{2})*$/;
const HEX64 = /^[0-9a-f]{64}$/;
const DEC_RE = /^(0|[1-9][0-9]*)$/;
const U64_MAX = 18446744073709551615n;
const U32_MAX = 4294967295;

// the per-part payload bound (equal to the schema's per-part maxItems;
// D3's refusal-boundary probe may move both down together)
const PART_BOUND_B = 5120;
// the allowed route registry, today exactly one route
const ROUTE_REGISTRY = Object.freeze(["tenderdash-tx"]);
const PROTOCOL_VERSION_PIN = 12;

// A MODULE-PRIVATE class used for CONTROL FLOW INSIDE THIS MODULE ONLY. It is
// not exported, no recognizer is exported, and nothing outside this file is ever
// asked to decide whether a caught value is one of these.
//
// THE BOUNDARY RULE (a review, replacing the whole provenance apparatus of rounds
// 61-64; see docs/E2_VERIFICATION_BOUNDARY.md): a verification verdict is
// RETURNED, never thrown. The public entries below catch this module's own class
// inside their own frame and convert it into a returned result. Anything else
// propagates as the fault it is.
//
// This deletes the question that four consecutive reviews could not close.
// An exception carries no trustworthy provenance, so a consumer that classifies
// CAUGHT objects into evidence grades must prove no route exists by which a
// foreign value arrives already classified, which is open-ended. A consumer that
// reads the STATUS of a value RETURNED from a function it called directly has no
// such obligation. Under the recorded trust decision the adapters are local
// reviewed code, so an adapter that throws is a fault that aborts, and the
// registries, recognizers, disown helper and call wrappers are all deleted.
class VerificationRefusal extends Error {}
const refuse = (why) => { throw new VerificationRefusal(`e2ReceiptVerify: ${why}; refusing`); };

// RESULTS THIS MODULE RETURNED, recorded by identity (a soundness-review finding). The pair check
// consumes two verification RESULTS, and before this it accepted anything shaped
// like one: `status: "verified"`, a few members it reads, and a subjectDigest
// that is an ordinary unkeyed hash over values the CALLER supplies. So a caller
// could build both results and receive a verified verdict with no decoder, no
// proof stage and no signature check having run. That was executed, not argued.
//
// WHY THIS IS NOT THE MACHINERY SUCCESSIVE REVIEWS BUILT AND A LATER SESSION DELETED, a
// distinction worth being exact about, because the shapes look alike. That
// machinery tried to decide where a CAUGHT value came from, which is unbounded:
// a throw can arrive by any number of routes, so every route had to be found
// and closed, and each round found another. A RETURNED value has exactly ONE
// producer, the boundary wrapper below, so recording what it returns is a
// closed question with no routes to enumerate. Membership cannot be reproduced
// from outside, and `WeakSet.has` reads nothing of the value and throws on
// nothing.
const OWN_RESULTS = new WeakSet();
const isOwnResult = (r) => OWN_RESULTS.has(r);

// the ONE conversion point, used only by the public entries below
const settleAsync = (inner) => async (args) => {
  try {
    const out = await inner(args);
    const r = { status: "verified", ...out };
    OWN_RESULTS.add(r);
    return r;
  } catch (e) {
    if (e instanceof VerificationRefusal) return { status: "refused", reason: e.message };
    throw e;
  }
};
const settleSync = (inner) => (args) => {
  try {
    const out = inner(args);
    const r = { status: "verified", ...(out || {}) };
    OWN_RESULTS.add(r);
    return r;
  } catch (e) {
    if (e instanceof VerificationRefusal) return { status: "refused", reason: e.message };
    throw e;
  }
};

// a total formatter for a caught value. This is about MESSAGE FORMATTING, not
// provenance: the three decoder catches below interpolate what they caught into
// the refusal they raise (a decode failure being evidence about the carrier is
// the one specified exception in docs/E2_VERIFICATION_BOUNDARY.md), and an
// unreadable value must not turn that refusal into a secondary fault.
const errText = (e) => {
  try { const m = e && e.message; if (typeof m === "string") return m; } catch { /* fall through */ }
  try { return String(e); } catch { return "(an unreadable thrown value)"; }
};

const sha256hex = (hexStr) => crypto.createHash("sha256").update(Buffer.from(hexStr, "hex")).digest("hex");
const hexBytes = (s) => (typeof s === "string" && HEX_RE.test(s)) ? s.length / 2 : -1;
const be64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b.toString("hex"); };

const requireHex = (name, s, bytes) => {
  const n = hexBytes(s);
  if (n < 0) refuse(`${name} is not lowercase hex`);
  if (bytes !== undefined && n !== bytes) refuse(`${name} must be exactly ${bytes} bytes`);
  return n;
};

/**
 * The canonical split recomputed from the reassembled length: partCount =
 * ceil(L / B) (minimum 1), proofBytes carries [0, min(L, B)), part i
 * carries [i*B, min((i+1)*B, L)). THE PARTITION IS THE ONLY CONFORMANT
 * ONE: any deviation refuses (a non-final part shorter or longer than B,
 * an empty final part, a count disagreeing with ceil(L/B)).
 */
const assertCanonicalSplit = ({ proofBytesLen, partLens, proofPartCount }) => {
  const L = proofBytesLen + partLens.reduce((a, b) => a + b, 0);
  const want = Math.max(1, Math.ceil(L / PART_BOUND_B));
  if (proofPartCount !== want) {
    refuse(`proofPartCount ${proofPartCount} disagrees with the canonical ceil(${L}/${PART_BOUND_B}) = ${want}`);
  }
  const expectedFirst = Math.min(L, PART_BOUND_B);
  if (proofBytesLen !== expectedFirst) {
    refuse(`proofBytes carries ${proofBytesLen} bytes where the canonical split puts ${expectedFirst}`);
  }
  for (let i = 0; i < partLens.length; i++) {
    const isFinal = i === partLens.length - 1;
    const expected = isFinal ? L - (i + 1) * PART_BOUND_B : PART_BOUND_B;
    if (isFinal && partLens[i] < 1) refuse(`the final part is empty (the split's final-part domain is 1..${PART_BOUND_B})`);
    if (partLens[i] !== expected) {
      refuse(`part ${i + 1} carries ${partLens[i]} bytes where the canonical split puts ${expected}`);
    }
  }
  return L;
};

/**
 * The part-set validation and canonical reassembly: parts must be exactly
 * the contiguous set 1..proofPartCount-1, every part's pool and accrual
 * must equal the receipt's, the split must be canonical, and the result is
 * the COMPLETE concatenated Proof carrier (proofBytes holds only part
 * zero; decoding it directly would refuse every valid multipart receipt).
 */
const reassembleProof = (receipt, parts) => {
  const want = receipt.proofPartCount - 1;
  if (!Array.isArray(parts)) refuse("the parts input must be an array");
  if (parts.length !== want) {
    refuse(`the receipt declares ${receipt.proofPartCount} parts (including its own first chunk) but ${parts.length} part documents were served`);
  }
  const byIndex = new Map();
  for (const p of parts) {
    if (!Number.isSafeInteger(p.partIndex) || p.partIndex < 1 || p.partIndex > 7) {
      refuse(`part index ${p.partIndex} is outside the schema's 1..7`);
    }
    if (byIndex.has(p.partIndex)) refuse(`duplicate part index ${p.partIndex}`);
    if (p.poolId !== receipt.poolId) refuse(`part ${p.partIndex} names a foreign pool`);
    if (p.accrualId !== receipt.accrualId) refuse(`part ${p.partIndex} names a foreign accrual`);
    requireHex(`part ${p.partIndex} bytes`, p.bytes);
    byIndex.set(p.partIndex, p);
  }
  for (let i = 1; i <= want; i++) {
    if (!byIndex.has(i)) refuse(`the part set is not the contiguous 1..${want} (missing ${i})`);
  }
  const ordered = [];
  for (let i = 1; i <= want; i++) ordered.push(byIndex.get(i).bytes);
  assertCanonicalSplit({ proofBytesLen: hexBytes(receipt.proofBytes),
    partLens: ordered.map((b) => b.length / 2), proofPartCount: receipt.proofPartCount });
  return receipt.proofBytes + ordered.join("");
};

/**
 * THE CARRIER-CONFORMANCE STAGE, first, before any cryptographic check:
 * decode the complete Proof carrier and metadataBytes through the pinned
 * pipeline (injected), re-encode the known fields with unknown fields
 * omitted, REFUSE unless the re-encoding is byte-equal to the supplied
 * bytes, REFUSE unless the decoded chain identifier equals the pinned one,
 * and REFUSE a protocol version other than 12. Returns the decoded pair.
 */
const verifyCarrierConformance = ({ carrierHex, metadataHex, chainIdPin, deps }) => {
  if (typeof chainIdPin !== "string" || chainIdPin.length === 0) refuse("the carrier stage needs the owned chain pin");
  let proof;
  try { proof = deps.decodeProofCarrier(carrierHex); }
  catch (e) { refuse(`the Proof carrier does not decode (${errText(e)})`); }
  if (!proof || typeof proof.reencodedHex !== "string") refuse("the proof decoder returned no re-encoding");
  if (proof.reencodedHex !== carrierHex) {
    refuse("the Proof carrier is not the canonical known-field encoding (the re-encoding differs byte-for-byte)");
  }
  let metadata;
  try { metadata = deps.decodeMetadata(metadataHex); }
  catch (e) { refuse(`metadataBytes does not decode (${errText(e)})`); }
  if (!metadata || typeof metadata.reencodedHex !== "string") refuse("the metadata decoder returned no re-encoding");
  if (metadata.reencodedHex !== metadataHex) {
    refuse("metadataBytes is not the canonical known-field encoding (the re-encoding differs byte-for-byte)");
  }
  if (metadata.chainId !== chainIdPin) {
    refuse(`the decoded chainId ${JSON.stringify(metadata.chainId)} differs from the pinned expected chain identifier`);
  }
  const pv = typeof metadata.protocolVersion === "bigint" ? Number(metadata.protocolVersion) : metadata.protocolVersion;
  if (pv !== PROTOCOL_VERSION_PIN) {
    refuse(`the decoded protocolVersion ${pv} is not the pinned ${PROTOCOL_VERSION_PIN}`);
  }
  return { proof, metadata };
};

// the two-stage verification, both stages MANDATORY: the signature check
// alone authenticates a root without establishing this transition's result
const runTwoStages = async ({ carrierHex, metadata, transitionBytes, deps }) => {
  const stageOne = await deps.verifyStageOne({
    carrierHex, transitionBytes,
    blockInfo: { timeMs: BigInt(metadata.timeMs), height: BigInt(metadata.height),
      coreHeight: metadata.coreChainLockedHeight, epoch: metadata.epoch },
  });
  // THE ROOT MUST BE A ROOT, not merely a string. This checked `typeof ===
  // "string"`, so a stage one answering `{ ok: true, rootHashHex: "not-a-root" }`
  // passed its result to stage two, and a stage two returning true VERIFIED the
  // record over a root that cannot be one. A derived state root is a 32-byte
  // digest, so its hex form is 64 lower-case hex characters, and anything else is
  // a malformed proof-stage result, which the specification names as evidence of
  // nonconformance rather than something to carry forward.
  if (!stageOne || stageOne.ok !== true || typeof stageOne.rootHashHex !== "string"
    || !/^[0-9a-f]{64}$/.test(stageOne.rootHashHex)) {
    refuse("stage one (the state-transition result proof) did not return a non-null successful result with a 64-hex derived root hash");
  }
  const stageTwo = await deps.verifyStageTwo({
    rootHashHex: stageOne.rootHashHex, carrierHex, metadata,
  });
  if (stageTwo !== true) {
    refuse("stage two (the quorum signature over the commit binding the derived root as appHash) did not verify");
  }
  return stageOne;
};

/**
 * Verify one on-ledger transferReceipt with its served parts, entitlement
 * row and reservation answer. Refuses on any conformance failure; returns
 * { status: "verified", reservationAspect, carrierHex, subjectDigest, decoded }.
 * There is no `ok` member and no path has ever set one: the wrapper tags the
 * result with `status`, and every consumer reads that.
 * reservationAspect is "proved" or
 * "unproved" (an unservable or unverifiable reservation query leaves the
 * aspect UNPROVED, never a silent pass and never a refusal; a served
 * mismatch or a proved absence REFUSES).
 *
 * reservation: { status: "served", doc: { poolId, accrualId, transitionHash } }
 *            | { status: "proved-absence" } | { status: "unserved" }
 */
const verifyReceiptInner = async ({ receipt, parts, reservation, entitlementRow,
  incomeIdentity, chainIdPin, deps }) => {
  // A MISSING DEPENDENCY IS A FAULT, NOT A REFUSAL. This used to call refuse(),
  // which the wrapper turns into `{ status: "refused" }`, so `verifyReceipt({})`
  // answered with a statement ABOUT THE RECORD before any record was looked at.
  // A refusal means a clause of the specification is violated by the record; a
  // dependency that is absent says nothing about the record and everything about
  // the caller, so it aborts.
  for (const k of ["decodeProofCarrier", "decodeMetadata", "decodeTransfer", "verifyStageOne", "verifyStageTwo"]) {
    if (typeof (deps && deps[k]) !== "function") {
      throw new Error(`e2ReceiptVerify: deps.${k} is absent or not a function; a missing dependency is a caller fault, never evidence about the record; refusing hard`);
    }
  }
  // structural grammar per the frozen schema
  if (!receipt || typeof receipt !== "object") refuse("the receipt input must be an object");
  requireHex("receipt.poolId", receipt.poolId, 32);
  requireHex("receipt.accrualId", receipt.accrualId, 32);
  requireHex("receipt.transitionHash", receipt.transitionHash, 32);
  const tbLen = requireHex("receipt.transitionBytes", receipt.transitionBytes);
  if (tbLen < 100 || tbLen > 2048) refuse(`transitionBytes length ${tbLen} is outside the schema's 100..2048`);
  const pbLen = requireHex("receipt.proofBytes", receipt.proofBytes);
  if (pbLen < 1 || pbLen > PART_BOUND_B) refuse(`proofBytes length ${pbLen} is outside 1..${PART_BOUND_B}`);
  if (!Number.isSafeInteger(receipt.proofPartCount) || receipt.proofPartCount < 1 || receipt.proofPartCount > 8) {
    refuse("proofPartCount must be an integer 1..8");
  }
  const mbLen = requireHex("receipt.metadataBytes", receipt.metadataBytes);
  if (mbLen < 1 || mbLen > 512) refuse(`metadataBytes length ${mbLen} is outside 1..512`);
  requireHex("receipt.blockHeight", receipt.blockHeight, 8);
  requireHex("receipt.timeMs", receipt.timeMs, 8);
  requireHex("receipt.quorumHash", receipt.quorumHash, 32);
  if (!Number.isSafeInteger(receipt.coreChainLockedHeight) || receipt.coreChainLockedHeight < 0
    || receipt.coreChainLockedHeight > U32_MAX) refuse("coreChainLockedHeight must be a u32 integer");
  if (!Number.isSafeInteger(receipt.round) || receipt.round < 0 || receipt.round > U32_MAX) {
    refuse("round must be a u32 integer");
  }

  // the part set and the canonical reassembly, then the carrier stage FIRST
  const carrierHex = reassembleProof(receipt, parts);
  const { proof, metadata } = verifyCarrierConformance({ carrierHex,
    metadataHex: receipt.metadataBytes, chainIdPin, deps });

  // the lifted fields are INDEXABLE COPIES ONLY: refuse mismatches against
  // the decoded messages (byte-encoded copies against big-endian encodings)
  if (receipt.blockHeight !== be64(metadata.height)) {
    refuse("the lifted blockHeight differs from the big-endian encoding of the decoded height");
  }
  if (receipt.timeMs !== be64(metadata.timeMs)) {
    refuse("the lifted timeMs differs from the big-endian encoding of the decoded timeMs");
  }
  if (receipt.coreChainLockedHeight !== metadata.coreChainLockedHeight) {
    refuse("the lifted coreChainLockedHeight differs from the decoded metadata");
  }
  if (receipt.quorumHash !== proof.quorumHashHex) {
    refuse("the lifted quorumHash differs from the decoded Proof carrier");
  }
  if (receipt.round !== proof.round) {
    refuse("the lifted round differs from the decoded Proof carrier");
  }

  // the transition hash is recomputed, never trusted
  if (receipt.transitionHash !== sha256hex(receipt.transitionBytes)) {
    refuse("transitionHash is not SHA-256 of transitionBytes");
  }

  // sender, recipient and amount come from DECODING transitionBytes,
  // never from lifted fields or the caller's claims
  let transfer;
  try { transfer = deps.decodeTransfer(receipt.transitionBytes); }
  catch (e) { refuse(`transitionBytes does not decode as a credit transfer (${errText(e)})`); }
  if (!HEX64.test(incomeIdentity || "")) refuse("verifyReceipt needs the pool's income identity");
  if (transfer.senderId !== incomeIdentity) {
    refuse("the decoded sender differs from the pool's income identity");
  }
  if (!entitlementRow || transfer.recipientId !== entitlementRow.recipientId) {
    refuse("the decoded recipient differs from the recomputed entitlement's owner");
  }
  if (BigInt(transfer.amountCredits) !== BigInt(entitlementRow.amountCredits)) {
    refuse("the decoded amount differs from the recomputed entitlement");
  }

  // both proof stages, mandatory
  await runTwoStages({ carrierHex, metadata, transitionBytes: receipt.transitionBytes, deps });

  // the reservation conformance (a soundness-review finding): a served mismatch or a proved
  // absence refuses; an unservable query leaves the aspect UNPROVED
  if (!reservation || !["served", "proved-absence", "unserved"].includes(reservation.status)) {
    refuse("the reservation answer must be served, proved-absence or unserved");
  }
  let reservationAspect;
  if (reservation.status === "served") {
    const d = reservation.doc || {};
    if (d.poolId !== receipt.poolId || d.accrualId !== receipt.accrualId
      || d.transitionHash !== receipt.transitionHash) {
      refuse("the fetched transferReservation's transitionHash, accrualId or poolId differs from the receipt's chain (a soundness-review finding)");
    }
    reservationAspect = "proved";
  } else if (reservation.status === "proved-absence") {
    refuse("a proved reservation absence refuses the receipt (a soundness-review finding)");
  } else {
    reservationAspect = "unproved";
  }

  return { reservationAspect, carrierHex,
    // the SUBJECT DIGEST binds this result to the exact verified receipt,
    // so a genuine result from a different receipt cannot stand in for it
    // (the fold re-check's F6)
    subjectDigest: sha256hex(receipt.transitionHash + receipt.transitionBytes + receipt.proofBytes + receipt.metadataBytes),
    decoded: { height: String(metadata.height), chainId: metadata.chainId } };
};

/**
 * The served capture-record validity clauses (the journal's capture kinds
 * as served to auditors), clauses 2 through 6 (clause 1, the supersession
 * basis, lives in e2CaptureRecord.selectSupersessionBasis):
 * (2) transitionHash equals SHA-256 of transitionBytes;
 * (3) the carrier-conformance stage then the two-stage verification of its
 *     proofMsg and metadataMsg against its exact transitionBytes, and for
 *     a header record the binding check that the proved result is the
 *     expected document identifier with the expected contents;
 * (4) its pool, and for the receipt record its accrualId against the
 *     served receipt's accrual, and for the header record its epoch and
 *     contract identifier, equal the records it is served for;
 * (5) is the PAIR check in verifyCapturePair below;
 * (6) inclusionHeight is a canonical non-negative decimal string fitting
 *     u64 and heightRoute is in the allowed route registry, both BEFORE
 *     any numerical comparison.
 */
const CAPTURE_KINDS = Object.freeze(["tegara.e2.headerCapture.v1", "tegara.e2.receiptCapture.v1"]);
const verifyCaptureRecordInner = async ({ capture, servedFor, chainIdPin, deps }) => {
  if (!capture || typeof capture !== "object") refuse("the capture input must be an object");
  // dispatch on the KIND, never the object member, and refuse anything
  // outside the two capture kinds (a non-capture record must never take
  // the receipt-capture branch by default)
  if (!CAPTURE_KINDS.includes(capture.kind)) {
    refuse(`the record kind ${JSON.stringify(capture.kind)} is not a capture kind`);
  }
  const isHeader = capture.kind === CAPTURE_KINDS[0];
  // (6) grammar and registry FIRST
  if (typeof capture.inclusionHeight !== "string" || !DEC_RE.test(capture.inclusionHeight)
    || BigInt(capture.inclusionHeight) > U64_MAX) {
    refuse("inclusionHeight must be a canonical non-negative decimal string fitting u64");
  }
  if (!ROUTE_REGISTRY.includes(capture.heightRoute)) {
    refuse(`heightRoute ${JSON.stringify(capture.heightRoute)} is outside the allowed route registry`);
  }
  // (2)
  if (capture.transitionHash !== sha256hex(capture.transitionBytes)) {
    refuse("the capture's transitionHash is not SHA-256 of its transitionBytes");
  }
  // (4)
  if (!servedFor || capture.poolId !== servedFor.poolId) {
    refuse("the capture's pool differs from the records it is served for");
  }
  if (isHeader) {
    if (capture.epochIndex !== servedFor.epochIndex) {
      refuse("the header capture's epoch differs from the records it is served for");
    }
    if (capture.contractId !== servedFor.contractId) {
      refuse("the header capture's contract identifier differs from the pinned contract");
    }
  } else {
    if (capture.accrualId !== servedFor.accrualId) {
      refuse("the receipt capture's accrualId differs from the served receipt's accrual");
    }
  }
  // (3): the conformance stage, then both proof stages
  const { metadata } = verifyCarrierConformance({ carrierHex: capture.proofMsg,
    metadataHex: capture.metadataMsg, chainIdPin, deps });
  const stageOne = await runTwoStages({ carrierHex: capture.proofMsg, metadata,
    transitionBytes: capture.transitionBytes, deps });
  if (isHeader) {
    const doc = stageOne.provedDocument;
    if (!doc || doc.documentId !== capture.expectedDocumentId) {
      refuse("the proved result is not the header capture's expected document identifier");
    }
    const ec = capture.expectedContents;
    const fieldsEqual = ec && doc.fields
      && ["poolId", "epochIndex", "grossCredits", "feeCredits", "allocationHash", "memberCount", "calcVersion"]
        .every((k) => doc.fields[k] === ec[k]);
    if (!fieldsEqual) {
      refuse("the proved result's contents differ from the header capture's expected contents");
    }
  }
  return { decodedChainId: metadata.chainId,
    subjectDigest: sha256hex(capture.transitionHash + capture.transitionBytes + capture.proofMsg + capture.metadataMsg) };
};

/**
 * Clause (5) plus the exact byte-equality set between a served
 * receipt-capture record and the on-ledger receipt: without these a valid
 * but unrelated capture for the same pool and accrual could earn the
 * label. reassembledProofHex is verifyReceipt's carrier.
 */
const verifyCapturePairInner = ({ capture, receipt, receiptResult, captureResult }) => {
  // the pair takes the two verification RESULTS, so a caller cannot hand
  // it loose values that never went through verifyReceipt and
  // verifyCaptureRecord (the checker's composition note)
  // the results must be VERIFIED ones (a review: the discriminator is `status`,
  // and a refused or unproved result reaching here would otherwise be read for
  // its members as though it had verified)
  // ORIGIN FIRST, then shape (a soundness-review finding). `isOwnResult` is what establishes that
  // this module PRODUCED the result; the shape checks that follow are about
  // the result being the right KIND of result, and on their own they were
  // satisfiable by a caller-built object.
  if (!receiptResult || !isOwnResult(receiptResult) || receiptResult.status !== "verified"
    || typeof receiptResult.carrierHex !== "string"
    || !receiptResult.decoded || typeof receiptResult.decoded.chainId !== "string") {
    refuse("the pair check needs a verified result THIS MODULE returned from verifyReceipt (a caller-built object of the same shape is not one)");
  }
  if (!captureResult || !isOwnResult(captureResult) || captureResult.status !== "verified"
    || typeof captureResult.decodedChainId !== "string") {
    refuse("the pair check needs a verified result THIS MODULE returned from verifyCaptureRecord (a caller-built object of the same shape is not one)");
  }
  // the results must have been produced FOR THESE EXACT SUBJECTS: a
  // genuine result from a different receipt or capture refuses
  if (receiptResult.subjectDigest !== sha256hex(receipt.transitionHash + receipt.transitionBytes + receipt.proofBytes + receipt.metadataBytes)) {
    refuse("the receipt result was produced for a different receipt (the subject digest disagrees)");
  }
  if (captureResult.subjectDigest !== sha256hex(capture.transitionHash + capture.transitionBytes + capture.proofMsg + capture.metadataMsg)) {
    refuse("the capture result was produced for a different capture (the subject digest disagrees)");
  }
  const reassembledProofHex = receiptResult.carrierHex;
  const receiptChainId = receiptResult.decoded.chainId;
  const captureChainId = captureResult.decodedChainId;
  if (capture.transitionBytes !== receipt.transitionBytes) {
    refuse("the capture's transitionBytes differ from the on-ledger receipt's");
  }
  // the transitionHash equality is IMPLIED rather than checked twice: both
  // verifications recompute their side's hash from its bytes, and the
  // bytes equality above binds the two, so a separate hash check would be
  // unreachable for genuinely verified subjects (the same composition the
  // D7 loop settled for the capture-bytes check)
  if (capture.proofMsg !== reassembledProofHex) {
    refuse("the capture's proofMsg differs from the receipt's reassembled Proof bytes");
  }
  if (capture.metadataMsg !== receipt.metadataBytes) {
    refuse("the capture's metadataMsg differs from the receipt's metadataBytes");
  }
  // validity clause 5. UNREACHABLE THROUGH GENUINE RESULTS as the module now
  // stands, and the scope is stated rather than left implied (a soundness-review finding): each side already compared its own decoded chainId against the SAME
  // pin before returning, so two results this module produced cannot disagree
  // here. It was previously reachable only by handing in an EDITED copy of a
  // genuine result, which the origin check now refuses earlier and for a better
  // reason. The clause stays as fail-visible defence against a future path that
  // verifies the two sides under different pins; it is not claimed to be
  // exercised.
  if (receiptChainId.length === 0 || receiptChainId !== captureChainId) {
    refuse("the pair's decoded chain identifiers are not equal (validity clause 5)");
  }
  return {};
};

/**
 * THE COMPOSITE ENTRY: run BOTH verifications for the exact supplied
 * inputs and then the pair equalities, so a consumer cannot pair results
 * that were produced for other subjects (the safest interface; the split
 * functions remain exported for the audit's per-aspect statuses).
 */
const verifyReceiptWithCaptureInner = async ({ capture, servedFor, receipt, parts, reservation,
  entitlementRow, incomeIdentity, chainIdPin, deps }) => {
  // the INNER forms, deliberately: inside this module a refusal is still control
  // flow, so it propagates to this function's own boundary wrapper and is
  // returned once, at the top. Calling the wrapped forms here would receive a
  // refusal as an ordinary value and carry on as though it had verified.
  const receiptResult = await verifyReceiptInner({ receipt, parts, reservation, entitlementRow,
    incomeIdentity, chainIdPin, deps });
  const captureResult = await verifyCaptureRecordInner({ capture, servedFor, chainIdPin, deps });
  // an inner return that got here IS verified (a refusal would have thrown past
  // this line), so the results are tagged before the pair check, which requires
  // the discriminator precisely so an EXTERNAL caller cannot pass a refused or
  // unproved verdict and have its members read as though it had verified
  const rTagged = { status: "verified", ...receiptResult };
  const cTagged = { status: "verified", ...captureResult };
  OWN_RESULTS.add(rTagged); OWN_RESULTS.add(cTagged);
  verifyCapturePairInner({ capture, receipt, receiptResult: rTagged, captureResult: cTagged });
  return { reservationAspect: receiptResult.reservationAspect,
    carrierHex: receiptResult.carrierHex };
};

// the public entries: each returns a verdict, none throws one
const verifyReceipt = settleAsync(verifyReceiptInner);
const verifyCaptureRecord = settleAsync(verifyCaptureRecordInner);
const verifyReceiptWithCapture = settleAsync(verifyReceiptWithCaptureInner);
const verifyCapturePair = settleSync(verifyCapturePairInner);

// THE PUBLIC SURFACE IS THE FOUR ENTRIES THAT RETURN VERDICTS, plus the pinned
// constants a caller needs to interpret one.
//
// `assertCanonicalSplit`, `reassembleProof` and `verifyCarrierConformance` move
// behind the test-only surface (2026-08-24). They are internal stages that still
// THROW this module's private refusal for control flow, and while they sat on the
// public surface they gave outside code a supported way to obtain a genuine
// instance of that class, which made the module's own claim about returned
// verdicts wider than the code. Neither has a production consumer; two are
// reached only by this repository's tests. A caller reaching into `__testing` is
// doing so knowingly and is not promised the entries' contract.
module.exports = {
  PART_BOUND_B, ROUTE_REGISTRY, PROTOCOL_VERSION_PIN,
  verifyReceipt, verifyCaptureRecord, verifyCapturePair, verifyReceiptWithCapture,
  // assertCanonicalSplit is NOT here: it is used internally and no suite drives
  // it directly, so exporting it defended a contract for nobody
  __testing: { reassembleProof, verifyCarrierConformance },
};
