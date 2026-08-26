/**
 * Offline test for the capture-record module (plain `node`, no network): the
 * signing round trip for both capture kinds, the preimage's sig-exclusion and
 * determinism, the closed member lists (extra members, conditional accrualId),
 * and the deterministic supersession selection with its outright refusals.
 * Key material is GENERATED per run through the installed curve library, so
 * fixtures cannot be memorized, and every expectation is derived from the
 * record the test itself built.
 */
const crypto = require("crypto");
const {
  HEADER_KIND, RECEIPT_KIND, SUPERSESSION_KIND, DOMAIN_PREFIX,
  validateRecordShape, capturePreimage, preimageDigest,
  signCapture, verifyCaptureSignature, recoverCaptureSigner,
  signSupersession, verifySupersessionSignature,
  selectSupersessionBasis,
} = require("./e2CaptureRecord.cjs");
const { canonicalString } = require("./canonicalJson.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed++; }
  else { failed++; console.error("FAIL:", name); }
};
const throwsSync = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

const h32 = (fill) => fill.repeat(64 / fill.length);
const shaHex = (hexStr) => crypto.createHash("sha256").update(Buffer.from(hexStr, "hex")).digest("hex");

const mkHeaderCapture = () => ({
  v: 1, kind: HEADER_KIND, object: "header", gen: 1,
  poolId: h32("ab"), epochIndex: 412,
  transitionBytes: "0102030405", transitionHash: shaHex("0102030405"),
  proofMsg: "aa".repeat(40), metadataMsg: "bb".repeat(20),
  contractId: h32("cc"), expectedDocumentId: h32("dd"),
  expectedContents: { poolId: h32("ab"), epochIndex: 412, grossCredits: 1000,
    feeCredits: 10, allocationHash: h32("ee"), memberCount: 2, calcVersion: 1 },
  inclusionHeight: "123456", heightRoute: "tenderdash-tx",
  signerIdentity: h32("f0"), signerKeyId: 2,
});
const mkReceiptCapture = () => ({
  v: 1, kind: RECEIPT_KIND, object: "transfer", gen: 1,
  poolId: h32("ab"), epochIndex: 412, accrualId: h32("a1"),
  transitionHash: shaHex("0a0b0c"), transitionBytes: "0a0b0c",
  proofMsg: "cc".repeat(50), metadataMsg: "dd".repeat(16),
  inclusionHeight: "123999", heightRoute: "tenderdash-tx",
  signerIdentity: h32("f0"), signerKeyId: 2,
});

(async () => {
  const { secp256k1 } = await import("@noble/curves/secp256k1.js");
  const { secretKey, publicKey } = secp256k1.keygen();
  const pubHex = Buffer.from(publicKey).toString("hex");

  // ---- the signing round trip, both kinds ----
  const signedHeader = await signCapture(mkHeaderCapture(), secretKey);
  ok("header capture signs to a 65-byte recovered form", signedHeader.sig.length === 130);
  ok("header signature verifies under the signing key",
    await verifyCaptureSignature(signedHeader, publicKey) === true);
  ok("the recovered signer equals the signing key", await recoverCaptureSigner(signedHeader) === pubHex);
  const signedReceipt = await signCapture(mkReceiptCapture(), secretKey);
  ok("receipt capture signs and verifies",
    await verifyCaptureSignature(signedReceipt, publicKey) === true);

  // ---- a foreign key does not verify, and one flipped byte in sig fails ----
  const other = secp256k1.keygen();
  ok("a foreign key does not verify", await verifyCaptureSignature(signedHeader, other.publicKey) === false);
  {
    const altered = { ...signedHeader, sig: signedHeader.sig.slice(0, 128) + (signedHeader.sig.slice(128) === "00" ? "01" : "00") };
    ok("a flipped signature byte fails verification",
      await verifyCaptureSignature(altered, publicKey) === false);
  }
  // ---- a changed SIGNED member (signerKeyId is inside the preimage) fails ----
  ok("a changed signerKeyId invalidates the signature",
    await verifyCaptureSignature({ ...signedHeader, signerKeyId: 3 }, publicKey) === false);

  // ---- the preimage excludes ONLY sig, deterministically ----
  ok("two different sig values yield one preimage",
    preimageDigest(signedHeader) === preimageDigest({ ...signedHeader, sig: "ff".repeat(65) }));
  {
    const p = capturePreimage(signedHeader);
    const expect = Buffer.concat([
      Buffer.from(DOMAIN_PREFIX, "utf8"),
      Buffer.from(canonicalString((({ sig, ...r }) => r)(signedHeader)), "utf8"),
    ]);
    ok("the preimage is the domain prefix plus the sigless JCS bytes, exactly", p.equals(expect));
    ok("the digest is SHA-256 of that preimage",
      preimageDigest(signedHeader) === crypto.createHash("sha256").update(expect).digest("hex"));
  }

  // ---- the closed member lists ----
  throwsSync("an extra member refuses", () => validateRecordShape({ ...signedHeader, note: "x" }), /extra member/);
  throwsSync("a wrong object refuses", () => validateRecordShape({ ...signedHeader, object: "transfer" }), /object must be/);
  throwsSync("an unknown route refuses", () => validateRecordShape({ ...signedHeader, heightRoute: "other" }), /route registry/);
  throwsSync("a claimed hash not recomputable from the bytes refuses",
    () => validateRecordShape({ ...signedHeader, transitionHash: h32("11") }), /not SHA-256 of transitionBytes/);
  throwsSync("the receipt kind's claimed hash is recomputed too",
    () => validateRecordShape({ ...signedReceipt, transitionHash: h32("22") }), /not SHA-256 of transitionBytes/);
  throwsSync("a non-canonical inclusionHeight refuses",
    () => validateRecordShape({ ...signedHeader, inclusionHeight: "0123" }), /canonical decimal/);
  throwsSync("uppercase hex refuses", () => validateRecordShape({ ...signedHeader, poolId: h32("AB") }), /lowercase hex/);

  // ---- supersessions: subject-tuple conditional accrualId ----
  const mkSup = (over, seq, extra = {}) => ({
    v: 1, kind: SUPERSESSION_KIND, gen: over.gen, poolId: over.poolId,
    epochIndex: over.epochIndex, supersededKind: over.kind,
    object: over.kind === HEADER_KIND ? "header" : "transfer",
    transitionHash: over.transitionHash, preimageHash: preimageDigest(over),
    seq, signerIdentity: h32("f0"), signerKeyId: 5, ...extra,
  });
  throwsSync("a receipt-capture supersession without accrualId refuses",
    () => validateRecordShape({ ...mkSup(signedReceipt, 1), sig: "00".repeat(65) }), /must carry accrualId/);
  throwsSync("a header-capture supersession WITH accrualId refuses",
    () => validateRecordShape({ ...mkSup(signedHeader, 1), accrualId: h32("a1"), sig: "00".repeat(65) }), /must not carry accrualId/);

  // ---- selection: unrelated ignored, malformed refuses outright, contiguity,
  // downward search, and the original as the last basis ----
  const sup1 = await signSupersession(signedHeader, mkSup(signedHeader, 1), other.secretKey);
  const sup2 = await signSupersession(signedHeader, mkSup(signedHeader, 2), other.secretKey);
  const unrelatedBase = { ...signedHeader, epochIndex: 999 };
  const unrelated = { ...mkSup(unrelatedBase, 1), sig: "00".repeat(65) };
  const verifiesAll = async () => true;
  const verifiesNone = async () => false;
  {
    const r = await selectSupersessionBasis(signedHeader, [sup1, unrelated, sup2], verifiesAll);
    ok("the downward search picks the highest seq that verifies", r.basis === sup2);
  }
  {
    const onlySeq1Verifies = async (c) => c.seq === 1;
    const r = await selectSupersessionBasis(signedHeader, [sup1, sup2], onlySeq1Verifies);
    ok("a failing max seq falls through to the next candidate", r.basis === sup1);
  }
  {
    // THE CALLBACK ANSWERS WITH A BOOLEAN. A review found this read for
    // TRUTHINESS, so a verdict object saying refused selected the candidate,
    // because an object is truthy: an explicitly negative verification result
    // chose the basis. The contract was written down nowhere, which is how a
    // caller following the verification boundary used elsewhere in this
    // repository could hand over a verdict and get a silent yes.
    const refusing = async () => ({ status: "refused", reason: "signature did not verify" });
    await rejects("a verdict object is not a yes: the callback must answer with a boolean",
      selectSupersessionBasis(signedHeader, [sup1, sup2], refusing),
      /answered with object rather than a boolean/);
    const verifying = async () => ({ status: "verified" });
    await rejects("a VERIFIED verdict object is refused too: the contract is the type, not the meaning",
      selectSupersessionBasis(signedHeader, [sup1, sup2], verifying),
      /rather than a boolean/);
    for (const [what, value] of [["null", null], ["undefined", undefined], ["a truthy string", "yes"]]) {
      await rejects(`a callback answering ${what} is a fault, never a selection`,
        selectSupersessionBasis(signedHeader, [sup1, sup2], async () => value),
        /rather than a boolean/);
    }
  }
  {
    // A THROW FROM THE CALLBACK IS A FAULT AND PROPAGATES. The module says so in
    // a comment and nothing bound it: every existing test resolves true or
    // false, so a mutation that swallowed the rejection and moved to the next
    // candidate would have gone unnoticed.
    await rejects("a THROWING signature callback propagates as a fault, never a fall-through",
      selectSupersessionBasis(signedHeader, [sup1, sup2],
        async () => { throw new Error("the curve library is unavailable"); }),
      /the curve library is unavailable/);
  }
  {
    // A MALFORMED KEY IS THE CALLER'S FAULT, NOT EVIDENCE ABOUT THE RECORD. The
    // blanket catch used to report "this signature does not verify" for a null
    // key or a broken curve library, which converts a dependency failure into a
    // statement about a member's record.
    for (const [what, key] of [["null", null], ["a short buffer", new Uint8Array(32)],
      ["a hex string", "02".repeat(33)]]) {
      await rejects(`a public key that is ${what} is a fault, never a false verdict`,
        verifyCaptureSignature(signedHeader, key), /not a 33-byte compressed point/);
    }
    // and the RECORD's own signature bytes stay evidence: malformed is false
    ok("malformed signature bytes in the record are evidence, and verify false",
      await verifyCaptureSignature({ ...signedHeader, sig: "00".repeat(65) }, publicKey) === false);
  }
  {
    const r = await selectSupersessionBasis(signedHeader, [sup1, sup2], verifiesNone);
    ok("no verifying candidate leaves the original as the basis", r.basis === "original");
  }
  {
    const r = await selectSupersessionBasis(signedHeader, [unrelated], verifiesAll);
    ok("only unrelated records also leaves the original", r.basis === "original");
  }
  await rejects("a matching-key candidate with a foreign transitionHash refuses the capture",
    selectSupersessionBasis(signedHeader, [{ ...sup1, transitionHash: h32("77") }], verifiesAll),
    /different transitionHash/);
  await rejects("a matching-key candidate with a wrong preimageHash refuses the capture",
    selectSupersessionBasis(signedHeader, [{ ...sup1, preimageHash: h32("88") }], verifiesAll),
    /preimageHash disagrees/);
  await rejects("a seq gap refuses",
    selectSupersessionBasis(signedHeader, [sup2], verifiesAll), /contiguous from 1/);
  await rejects("a duplicate seq refuses",
    selectSupersessionBasis(signedHeader, [sup1, { ...sup1 }], verifiesAll), /contiguous from 1/);

  // ---- a receipt capture's accrualId participates in the candidate key ----
  {
    const supR = await signSupersession(signedReceipt, mkSup(signedReceipt, 1, { accrualId: signedReceipt.accrualId }), other.secretKey);
    const foreignAccrual = { ...supR, accrualId: h32("b2") };
    const r = await selectSupersessionBasis(signedReceipt, [foreignAccrual], verifiesAll);
    ok("a supersession naming a different accrual is unrelated, not a candidate", r.basis === "original");
    const r2 = await selectSupersessionBasis(signedReceipt, [supR], verifiesAll);
    ok("the matching-accrual supersession is selected", r2.basis === supR);
  }

  // ---- the SUPERSESSION SIGNATURE covers the ORIGINAL capture's preimage
  // (the batched checker's finding 2: signing the supersession's own bytes was
  // a spec divergence and the injected verifier concealed it): a real
  // positive, a wrong-original negative, and the sign-own-bytes refusal ----
  {
    const sup = await signSupersession(signedHeader, mkSup(signedHeader, 1), other.secretKey);
    ok("a supersession signature verifies over the ORIGINAL's preimage",
      await verifySupersessionSignature(signedHeader, sup, other.publicKey) === true);
    ok("the same signature fails against a DIFFERENT original's preimage",
      await verifySupersessionSignature(signedReceipt, { ...sup, supersededKind: signedReceipt.kind,
        object: "transfer", accrualId: signedReceipt.accrualId, epochIndex: signedReceipt.epochIndex,
        transitionHash: signedReceipt.transitionHash, preimageHash: preimageDigest(signedReceipt) },
      other.publicKey) === false);
    ok("the supersession's own-bytes signature would NOT verify (the divergent form is dead)",
      await verifyCaptureSignature(sup, other.publicKey) === false);
    await rejects("signCapture refuses supersession records outright",
      signCapture(mkSup(signedHeader, 1), other.secretKey), /signSupersession/);
    // the selection integrates the REAL verifier, no stub
    const realVerify = (c) => verifySupersessionSignature(signedHeader, c, other.publicKey);
    const r = await selectSupersessionBasis(signedHeader, [sup], realVerify);
    ok("selection with the real preimage verifier picks the signed supersession", r.basis === sup);
  }

  // ---- the candidate key includes gen (the batched checker's finding 8: a
  // matching-subject, DIFFERENT-GENERATION supersession must stay unrelated) ----
  {
    // the candidate is built to be FULLY ACCEPTABLE except for its gen (its
    // transitionHash and preimageHash are the gen-1 capture's own), so a key
    // that drops gen SELECTS it, while the correct key leaves the original;
    // this way the mutation produces a wrong selection, not a throw
    const supGen2 = { ...mkSup(signedHeader, 1), gen: 2, sig: "00".repeat(65) };
    const r = await selectSupersessionBasis(signedHeader, [supGen2], async () => true);
    ok("a matching-subject different-gen supersession is unrelated, never a candidate",
      r.basis === "original");
  }

  // ---- the u64 bound on heights (the batched checker's finding 3) ----
  throwsSync("an inclusionHeight beyond u64 refuses",
    () => validateRecordShape({ ...signedHeader, inclusionHeight: "18446744073709551616" }), /u64/);
  ok("the exact u64 maximum is accepted",
    (() => { validateRecordShape({ ...signedHeader, inclusionHeight: "18446744073709551615" }); return true; })());

  // ---- expectedContents is a CLOSED typed seven-field value ----
  throwsSync("an eighth expectedContents field refuses",
    () => validateRecordShape({ ...signedHeader,
      expectedContents: { ...signedHeader.expectedContents, extra: 1 } }), /exactly the seven/);
  throwsSync("a missing expectedContents field refuses",
    () => validateRecordShape({ ...signedHeader,
      expectedContents: (({ feeCredits, ...r }) => r)(signedHeader.expectedContents) }), /exactly the seven/);
  throwsSync("a string grossCredits refuses (the schema holds integers)",
    () => validateRecordShape({ ...signedHeader,
      expectedContents: { ...signedHeader.expectedContents, grossCredits: "1000" } }), /integer inside the schema ceiling/);
  throwsSync("a memberCount of 9 refuses",
    () => validateRecordShape({ ...signedHeader,
      expectedContents: { ...signedHeader.expectedContents, memberCount: 9 } }), /1\.\.8/);

  console.log(`e2CaptureRecordTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
})();
