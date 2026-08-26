/**
 * E2 capture records: construction, the domain-prefixed signing preimage, the
 * signature, and the supersession-chain selection rule (E2 build spec, "Receipt
 * ordering" and the journal schema section; the two capture kinds and the
 * captureSupersession kind).
 *
 * WHAT THIS MODULE ESTABLISHES, exactly: the byte-level preimage a capture's
 * signature covers (the UTF-8 domain prefix "tegara-e2-capture-v1\n" followed
 * by the JCS bytes of the record WITHOUT its `sig` member), SHA-256 over it
 * (the preimage digest the gate artifact commits to), signing to the 65-byte
 * recovered-compact form and verifying it, the CLOSED member lists of the two
 * capture kinds and the supersession kind (a missing, mistyped or EXTRA member
 * refuses), and the deterministic supersession selection (candidates matched
 * by supersededKind + subject tuple + gen; a candidate whose transitionHash or
 * preimageHash mismatches is MALFORMED and refuses the capture outright; seq
 * unique and contiguous from 1; the verifier searches DOWNWARD from the
 * maximum seq for the highest candidate whose signature verifies).
 *
 * WHAT IT DOES NOT ESTABLISH (the callers' and later units' checks): the
 * two-stage cryptographic verification of proofMsg/metadataMsg and the
 * carrier-conformance stage (e2ReceiptVerify.cjs); the signer and key
 * REQUIREMENTS (purpose, level, type) and the proved key lookup, which need
 * the pinned identity routes; and the exact wire convention of the recovery
 * byte against Platform's own identity-signature encoding, which is a
 * pinning-time comparison recorded with D9's fixtures. Signing here uses the
 * installed curve library's recovered-compact form and verifies by public
 * key, which is self-consistent for the attestation chain and stated at
 * exactly that width.
 *
 * Amounts and integers inside records are canonical decimal strings per the
 * journal's common rule; byte fields are lowercase hex of their stated length.
 */
const crypto = require("crypto");
const { canonicalString } = require("./canonicalJson.cjs");

const DOMAIN_PREFIX = "tegara-e2-capture-v1\n";
const HEX_RE = /^([0-9a-f]{2})*$/;
const hex = (name, s, bytes) => {
  if (typeof s !== "string" || !HEX_RE.test(s)) return `${name} is not lowercase hex`;
  if (bytes !== undefined && s.length !== bytes * 2) return `${name} is not ${bytes} bytes`;
  return null;
};
const U64_MAX = 18446744073709551615n;
const decStr = (name, s) => {
  if (typeof s !== "string" || !/^(0|[1-9][0-9]*)$/.test(s)) {
    return `${name} is not a canonical decimal string`;
  }
  // heights are u64 on the wire; a value beyond the domain is malformed, not
  // merely large (the batched checker's finding 3)
  if (BigInt(s) > U64_MAX) return `${name} exceeds the u64 domain`;
  return null;
};

// expectedContents is EXACTLY the capture format's literal seven-field value
// (the frozen schema; made a closed typed validation by the batched checker's
// finding 3): the on-ledger header's own field types, integers where the
// schema holds integers, nothing extra, nothing missing.
const validateExpectedContents = (ec) => {
  if (!ec || typeof ec !== "object" || Array.isArray(ec)) return "expectedContents is not an object";
  const want = ["allocationHash", "calcVersion", "epochIndex", "feeCredits",
    "grossCredits", "memberCount", "poolId"];
  const have = Object.keys(ec).sort();
  if (have.join(",") !== want.join(",")) {
    return "expectedContents must carry exactly the seven header fields";
  }
  let e;
  if ((e = hex("expectedContents.poolId", ec.poolId, 32))) return e;
  if (!Number.isSafeInteger(ec.epochIndex) || ec.epochIndex < 0 || ec.epochIndex > 4294967295) {
    return "expectedContents.epochIndex is not a u32 integer";
  }
  for (const f of ["grossCredits", "feeCredits"]) {
    if (!Number.isSafeInteger(ec[f]) || ec[f] < 0 || ec[f] > 9007199254740991) {
      return `expectedContents.${f} is not an integer inside the schema ceiling`;
    }
  }
  if ((e = hex("expectedContents.allocationHash", ec.allocationHash, 32))) return e;
  if (!Number.isSafeInteger(ec.memberCount) || ec.memberCount < 1 || ec.memberCount > 8) {
    return "expectedContents.memberCount is not an integer 1..8";
  }
  if (ec.calcVersion !== 1) return "expectedContents.calcVersion must be the integer 1";
  return null;
};

// the closed member lists, keyed by kind. TWO DIFFERENT PROTOCOLS live here and
// this sentence used to describe only one of them: the per-kind content
// validators return a refusal STRING or null, while `validateRecordShape`
// returns the record and THROWS on a nonconforming one. A caller has to know
// which it is holding, and the journal already treats the two differently.
const HEADER_KIND = "tegara.e2.headerCapture.v1";
const RECEIPT_KIND = "tegara.e2.receiptCapture.v1";
const SUPERSESSION_KIND = "tegara.e2.journal.captureSupersession.v1";

const COMMON_MEMBERS = ["v", "kind", "object", "gen", "poolId"];
const SPECIFIC = {
  [HEADER_KIND]: {
    object: "header",
    members: [...COMMON_MEMBERS, "epochIndex", "transitionBytes", "transitionHash",
      "proofMsg", "metadataMsg", "contractId", "expectedDocumentId", "expectedContents",
      "inclusionHeight", "heightRoute", "signerIdentity", "signerKeyId", "sig"],
  },
  [RECEIPT_KIND]: {
    object: "transfer",
    members: [...COMMON_MEMBERS, "epochIndex", "accrualId", "transitionHash",
      "transitionBytes", "proofMsg", "metadataMsg", "inclusionHeight", "heightRoute",
      "signerIdentity", "signerKeyId", "sig"],
  },
  [SUPERSESSION_KIND]: {
    // carries the SUPERSEDED capture's subject tuple: object "header" with
    // poolId+epochIndex for a header capture, object "transfer" with
    // poolId+epochIndex+accrualId for a receipt capture (the journal's
    // common-member rule; accrualId is validated conditionally below)
    object: null,
    members: [...COMMON_MEMBERS, "epochIndex", "supersededKind", "transitionHash",
      "preimageHash", "seq", "signerIdentity", "signerKeyId", "sig"],
    conditionalMembers: ["accrualId"],
  },
};

// A MODULE-PRIVATE class used for CONTROL FLOW INSIDE THIS MODULE ONLY (round-65;
// see docs/E2_VERIFICATION_BOUNDARY.md). It is not exported, and no recognizer is
// exported, so nothing outside this file is ever asked to decide whether a caught
// value came from here.
//
// The registry, the exported recognizer and the boundary disown helper that rounds
// 61 through 64 built here are DELETED. They existed to answer a question that
// cannot be answered with exceptions (did this thrown value originate in trusted
// verification, or cross an injected callback), and the answer is to stop asking:
// this module's callers read RETURNED verdicts. Under the recorded trust decision
// the injected supersession callback is local reviewed code, so a throw from it is
// a fault that propagates rather than something to be classified.
class VerificationRefusal extends Error {}
const refuse = (why) => { throw new VerificationRefusal(`e2CaptureRecord: ${why}; refusing`); };

const validateRecordShape = (record) => {
  if (!record || typeof record !== "object" || Array.isArray(record)) refuse("record is not an object");
  const spec = SPECIFIC[record.kind];
  if (!spec) refuse(`unknown kind ${JSON.stringify(record.kind)}`);
  for (const m of spec.members) if (!(m in record)) refuse(`missing member ${m} (${record.kind})`);
  const allowed = [...spec.members, ...(spec.conditionalMembers || [])];
  for (const k of Object.keys(record)) {
    if (!allowed.includes(k)) refuse(`extra member ${k} (${record.kind}); the member list is closed`);
  }
  if (record.v !== 1) refuse("v must be the integer 1");
  if (spec.object !== null && record.object !== spec.object) {
    refuse(`object must be "${spec.object}" for ${record.kind}`);
  }
  if (!Number.isSafeInteger(record.gen) || record.gen < 1) refuse("gen must be an integer at least 1");
  let e;
  if ((e = hex("poolId", record.poolId, 32))) refuse(e);
  if (!Number.isSafeInteger(record.epochIndex) || record.epochIndex < 0 || record.epochIndex > 4294967295) {
    refuse("epochIndex must be a u32 integer");
  }
  if ((e = hex("signerIdentity", record.signerIdentity, 32))) refuse(e);
  if (!Number.isSafeInteger(record.signerKeyId) || record.signerKeyId < 0) {
    refuse("signerKeyId must be a non-negative integer");
  }
  if ((e = hex("sig", record.sig, 65))) refuse(e);
  if (record.kind === HEADER_KIND) {
    if ((e = hex("transitionBytes", record.transitionBytes))) refuse(e);
    if ((e = hex("transitionHash", record.transitionHash, 32))) refuse(e);
    // the claimed hash is RECOMPUTED, never taken on faith (the fold
    // re-check's F11: this module compared claimed values only, and the
    // journal's recomputation did not cover the standalone selector path)
    if (record.transitionHash !== sha256overBytes(record.transitionBytes)) {
      refuse("transitionHash is not SHA-256 of transitionBytes");
    }
    if ((e = hex("proofMsg", record.proofMsg)) || record.proofMsg.length === 0) refuse(e || "proofMsg is empty");
    if ((e = hex("metadataMsg", record.metadataMsg)) || record.metadataMsg.length === 0) refuse(e || "metadataMsg is empty");
    if ((e = hex("contractId", record.contractId, 32))) refuse(e);
    if ((e = hex("expectedDocumentId", record.expectedDocumentId, 32))) refuse(e);
    { const ecErr = validateExpectedContents(record.expectedContents); if (ecErr) refuse(ecErr); }
    if ((e = decStr("inclusionHeight", record.inclusionHeight))) refuse(e);
    if (record.heightRoute !== "tenderdash-tx") refuse("heightRoute outside the allowed route registry");
  }
  if (record.kind === RECEIPT_KIND) {
    if ((e = hex("accrualId", record.accrualId, 32))) refuse(e);
    if ((e = hex("transitionHash", record.transitionHash, 32))) refuse(e);
    if ((e = hex("transitionBytes", record.transitionBytes))) refuse(e);
    if (record.transitionHash !== sha256overBytes(record.transitionBytes)) {
      refuse("transitionHash is not SHA-256 of transitionBytes");
    }
    if ((e = hex("proofMsg", record.proofMsg)) || record.proofMsg.length === 0) refuse(e || "proofMsg is empty");
    if ((e = hex("metadataMsg", record.metadataMsg)) || record.metadataMsg.length === 0) refuse(e || "metadataMsg is empty");
    if ((e = decStr("inclusionHeight", record.inclusionHeight))) refuse(e);
    if (record.heightRoute !== "tenderdash-tx") refuse("heightRoute outside the allowed route registry");
  }
  if (record.kind === SUPERSESSION_KIND) {
    if (record.supersededKind !== HEADER_KIND && record.supersededKind !== RECEIPT_KIND) {
      refuse("supersededKind must be one of the two capture kinds");
    }
    const wantObject = record.supersededKind === HEADER_KIND ? "header" : "transfer";
    if (record.object !== wantObject) {
      refuse(`a supersession of ${record.supersededKind} must carry object "${wantObject}"`);
    }
    if (record.supersededKind === RECEIPT_KIND) {
      if (!("accrualId" in record)) refuse("a receipt-capture supersession must carry accrualId (the subject tuple)");
      if ((e = hex("accrualId", record.accrualId, 32))) refuse(e);
    } else if ("accrualId" in record) {
      refuse("a header-capture supersession must not carry accrualId");
    }
    if ((e = hex("transitionHash", record.transitionHash, 32))) refuse(e);
    if ((e = hex("preimageHash", record.preimageHash, 32))) refuse(e);
    if (!Number.isSafeInteger(record.seq) || record.seq < 1) refuse("seq must be an integer at least 1");
  }
  return record;
};

const sha256overBytes = (hexStr) =>
  crypto.createHash("sha256").update(Buffer.from(hexStr, "hex")).digest("hex");

// the signing preimage: the domain prefix, then the JCS bytes of the record
// WITHOUT its sig member (every other member, signerIdentity and signerKeyId
// included, is inside the signed bytes)
const capturePreimage = (record) => {
  const { sig, ...unsigned } = record;
  return Buffer.concat([
    Buffer.from(DOMAIN_PREFIX, "utf8"),
    Buffer.from(canonicalString(unsigned), "utf8"),
  ]);
};
const preimageDigest = (record) =>
  crypto.createHash("sha256").update(capturePreimage(record)).digest("hex");

// signing and verification, the installed curve library's recovered-compact
// form (65 bytes); ESM-only, so loaded once on first use
let secpPromise = null;
const secp = () => {
  if (!secpPromise) secpPromise = import("@noble/curves/secp256k1.js").then((m) => m.secp256k1);
  return secpPromise;
};
const signCapture = async (record, secretKey) => {
  if (record.kind === SUPERSESSION_KIND) {
    refuse("a supersession is signed over the ORIGINAL capture's preimage; use signSupersession " +
      "(the batched checker's finding 2: signing the supersession's own bytes was a spec divergence)");
  }
  const digest = crypto.createHash("sha256").update(capturePreimage({ ...record, sig: "" })).digest();
  const s = await secp();
  const sig = s.sign(digest, secretKey, { prehash: false, format: "recovered" });
  const signed = { ...record, sig: Buffer.from(sig).toString("hex") };
  return validateRecordShape(signed);
};

// THE SUPERSESSION SIGNATURE COVERS THE ORIGINAL CAPTURE'S DOMAIN-PREFIXED
// PREIMAGE (the frozen rule: the successor key signs THE SAME bytes the
// original signature covered, so the content is provably unchanged); the
// supersession record's own members are bookkeeping around that signature,
// not inside it.
const signSupersession = async (originalCapture, supersessionNoSig, secretKey) => {
  validateRecordShape(originalCapture);
  if (supersessionNoSig.kind !== SUPERSESSION_KIND) refuse("signSupersession needs a supersession record");
  const digest = crypto.createHash("sha256").update(capturePreimage(originalCapture)).digest();
  const s = await secp();
  const sig = s.sign(digest, secretKey, { prehash: false, format: "recovered" });
  const signed = { ...supersessionNoSig, sig: Buffer.from(sig).toString("hex") };
  return validateRecordShape(signed);
};
const verifySupersessionSignature = async (originalCapture, supersession, publicKey) => {
  validateRecordShape(originalCapture);
  validateRecordShape(supersession);
  const digest = crypto.createHash("sha256").update(capturePreimage(originalCapture)).digest();
  const s = await secp();
  // THE KEY IS THE CALLER'S OBLIGATION AND THE SIGNATURE IS THE RECORD'S. That
  // split decides what a failure means. A malformed key is a fault and must
  // propagate; malformed signature bytes come from an untrusted record and are
  // evidence about it. The catch below used to cover BOTH, so a null key or a
  // broken curve library reported "this signature does not verify", which is a
  // dependency failure converted into a statement about a member's record, and
  // the specification permits that conversion only for the three decoders.
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 33) {
    throw new Error(`e2CaptureRecord: the resolved public key is not a 33-byte compressed point; a malformed key is a caller fault, never evidence about the record; refusing hard`);
  }
  try {
    return s.verify(Buffer.from(supersession.sig, "hex").subarray(1), digest, publicKey, { prehash: false });
  } catch { return false; } // the RECORD's signature bytes are untrusted: malformed is evidence
};
const verifyCaptureSignature = async (record, publicKey) => {
  validateRecordShape(record);
  const digest = crypto.createHash("sha256").update(capturePreimage(record)).digest();
  const s = await secp();
  // THE KEY IS THE CALLER'S OBLIGATION AND THE SIGNATURE IS THE RECORD'S. That
  // split decides what a failure means. A malformed key is a fault and must
  // propagate; malformed signature bytes come from an untrusted record and are
  // evidence about it. The catch below used to cover BOTH, so a null key or a
  // broken curve library reported "this signature does not verify", which is a
  // dependency failure converted into a statement about a member's record, and
  // the specification permits that conversion only for the three decoders.
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 33) {
    throw new Error(`e2CaptureRecord: the resolved public key is not a 33-byte compressed point; a malformed key is a caller fault, never evidence about the record; refusing hard`);
  }
  try {
    return s.verify(Buffer.from(record.sig, "hex").subarray(1), digest, publicKey, { prehash: false });
  } catch { return false; } // the RECORD's signature bytes are untrusted: malformed is evidence
};
const recoverCaptureSigner = async (record) => {
  validateRecordShape(record);
  const digest = crypto.createHash("sha256").update(capturePreimage(record)).digest();
  const s = await secp();
  return Buffer.from(s.recoverPublicKey(Buffer.from(record.sig, "hex"), digest, { prehash: false })).toString("hex");
};

/**
 * The deterministic supersession selection (spec rounds 12 and 14): given the
 * served capture and every supersession record served with it, plus an async
 * signature check for a candidate (the caller supplies key resolution),
 * returns { basis } where basis is either the winning supersession record or
 * the string "original" (the original's own signature members are the only
 * remaining basis). REFUSES the capture outright on a malformed candidate
 * (content immutability) or a non-contiguous seq set.
 */
const selectSupersessionBasis = async (capture, supersessions, verifiesFn) => {
  validateRecordShape(capture);
  const expectedPreimage = preimageDigest(capture);
  const candidates = [];
  for (const r of supersessions || []) {
    validateRecordShape(r);
    // CANDIDATE KEY: supersededKind + the FULL subject tuple + gen must match
    // the capture (accrualId participates exactly when the capture is a
    // receipt capture, whose subject tuple carries it)
    const subjectMatches = r.supersededKind === capture.kind
      && r.poolId === capture.poolId && r.epochIndex === capture.epochIndex
      && (capture.kind !== RECEIPT_KIND || r.accrualId === capture.accrualId)
      && r.gen === capture.gen;
    if (!subjectMatches) continue; // unrelated, ignored
    if (r.transitionHash !== capture.transitionHash) {
      refuse("a matching-key supersession carries a different transitionHash (content is immutable)");
    }
    if (r.preimageHash !== expectedPreimage) {
      refuse("a matching-key supersession's preimageHash disagrees with the recomputed preimage");
    }
    candidates.push(r);
  }
  if (candidates.length === 0) return { basis: "original" };
  const seqs = candidates.map((c) => c.seq).sort((a, b) => a - b);
  for (let i = 0; i < seqs.length; i++) {
    if (seqs[i] !== i + 1) refuse(`supersession seq set is not unique and contiguous from 1 (${seqs.join(",")})`);
  }
  candidates.sort((a, b) => b.seq - a.seq); // downward from the maximum
  for (const c of candidates) {
    // a throw from the injected callback is a FAULT and propagates: the caller
    // supplies local reviewed code here, and a broken signature checker says
    // nothing about whether a capture conforms.
    //
    // THE CALLBACK ANSWERS WITH A BOOLEAN, AND THAT IS ENFORCED. It used to be
    // read for TRUTHINESS, which a review found meant a verdict object saying
    // `{ status: "refused" }` selected the candidate, because an object is
    // truthy. An explicitly negative verification result chose the basis. The
    // contract was written down nowhere, which is how the two readings drifted:
    // this module wants a boolean, the verification boundary elsewhere in this
    // repository returns a verdict, and a caller following that boundary got a
    // silent affirmative here. Anything that is not a boolean is now a fault.
    const verified = await verifiesFn(c);
    if (typeof verified !== "boolean") {
      throw new Error(`e2CaptureRecord: the signature callback answered with ${verified === null ? "null" : typeof verified} rather than a boolean; a verdict object is NOT a yes; refusing hard`);
    }
    if (verified) return { basis: c };
  }
  return { basis: "original" };
};

module.exports = {
  DOMAIN_PREFIX, HEADER_KIND, RECEIPT_KIND, SUPERSESSION_KIND,
  validateRecordShape, validateExpectedContents, capturePreimage, preimageDigest,
  signCapture, verifyCaptureSignature, recoverCaptureSigner,
  signSupersession, verifySupersessionSignature,
  selectSupersessionBasis,
};
