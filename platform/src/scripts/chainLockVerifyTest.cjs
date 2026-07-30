/**
 * Fixtures for ChainLock verification, driven by the REAL pinned devnet ChainLock at
 * fixtures/chainlock-devnet-2026-07-25.json (height 8358, captured from the running
 * devnet with its live quorum set).
 *
 * The decisive checks are the two that an earlier no-dependency attempt could not settle:
 * the real signature verifies under Dash's own scheme, and the score-based selection rule
 * independently names the SAME quorum whose key verifies it. The negatives then require the
 * verdict to be false whenever any element of the preimage changes, so the fixtures would
 * catch a verifier that returns true without binding height, block hash, quorum or type.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const {
  deriveRequestId, deriveSignHash, deriveQuorumScore, selectSignatoryQuorum,
  loadBls, verifyChainLockSignature, verifyChainLockAgainstQuorumSet, llmqTypeOf,
} = require("./chainLockVerify.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const throws = (name, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || "")); }
};

const FIXTURE = path.join(__dirname, "fixtures", "chainlock-devnet-2026-07-25.json");
const fixture = JSON.parse(fs.readFileSync(FIXTURE, "utf8"));
const cl = fixture.chainlock;
const quorums = fixture.quorums;

(async () => {
  // ---- the construction, pinned so a refactor cannot silently change the preimage ----
  const requestId = deriveRequestId(cl.height);
  ok("requestId is 32 bytes", Buffer.isBuffer(requestId) && requestId.length === 32);
  ok("requestId matches the pinned value for height 8358",
     requestId.toString("hex") === "98d5d4cce133432e80a8c18e1ad460ea6257ffaf8e3e83d780b2078d41d6a817");
  ok("a different height gives a different requestId",
     deriveRequestId(cl.height + 1).toString("hex") !== requestId.toString("hex"));
  throws("a height beyond uint32 is refused", () => deriveRequestId(2 ** 32), /outside the uint32 range/);
  throws("an unknown llmqType label is refused", () => llmqTypeOf("llmq_nonexistent"), /unknown llmqType label/);
  throws("a malformed quorum hash is refused",
    () => deriveSignHash({ llmqType: "llmq_test", quorumHash: "abc", requestId, msgHash: cl.blockhash }),
    /quorumHash must be 64 lowercase hex/);

  // ---- THE SELECTION RULE, evaluated with no reference to the signature ----
  // The library loads first because the selector now REQUIRES it: selection parses every
  // candidate's key as a curve point, so it cannot answer from lexical checks alone (round 5,
  // MAJOR: the exported selector accepted ff*48, a correctly sized non-point).
  const bls = await loadBls();
  const { selected, scored } = selectSignatoryQuorum(bls, quorums, requestId);
  ok("the pinned set carries two candidate quorums", quorums.length === 2);
  ok("scores are ordered ascending", Buffer.compare(scored[0].score, scored[1].score) < 0);
  ok("the selected quorum is the OLDER one, not the newest",
     selected.height === 8304 && selected.height < 8328);
  ok("the selected score is the pinned lowest score",
     scored[0].score.toString("hex").startsWith("73e27ab27d9cc3b1"));
  throws("a duplicated candidate is refused rather than silently broken",
    () => selectSignatoryQuorum(bls, [quorums[0], quorums[0]], requestId), /appears twice in the set/);

  // ---- THE SIGNATURE, under Dash's own scheme (the instance loaded above) ----
  const verifyWith = (over) => verifyChainLockSignature(bls, {
    height: cl.height, blockHash: cl.blockhash, llmqType: over.type,
    quorumHash: over.quorumHash, quorumPublicKey: over.quorumPublicKey,
    signature: over.signature === undefined ? cl.signature : over.signature,
  });

  ok("the REAL ChainLock verifies under the selected quorum", verifyWith(selected) === true);
  const other = quorums.find((q) => q.quorumHash !== selected.quorumHash);
  ok("it does NOT verify under the other quorum in the same set", verifyWith(other) === false);

  // the duplicate must be caught WHEREVER it sits, not only when it occupies the two lowest
  // scores (confirmation round, MINOR: the first version compared only scored[0] and
  // scored[1], so [lowest, other, other] was accepted)
  throws("a duplicate outside the two lowest scores is also refused",
    () => selectSignatoryQuorum(bls, [selected, other, other], requestId), /appears twice in the set/);

  throws("the SELECTOR itself refuses a correctly sized non-point",
    () => selectSignatoryQuorum(bls, [{ ...selected, quorumPublicKey: "ff".repeat(48) }], requestId),
    /not a valid BLS point/);
  throws("the selector refuses to answer without the library",
    () => selectSignatoryQuorum(null, quorums, requestId), /needs a loaded BLS instance/);

  // the rule and the cryptography must name the same quorum: this is the property that
  // would break first if either the score preimage or the sign-hash preimage changed
  const verifying = quorums.filter((q) => verifyWith(q) === true);
  ok("exactly one quorum in the set verifies", verifying.length === 1);
  ok("the verifying quorum IS the score-selected quorum",
     verifying[0].quorumHash === selected.quorumHash);

  // ---- negatives: every element of the preimage must be bound ----
  ok("a altered height does not verify",
     verifyChainLockSignature(bls, {
       height: cl.height + 1, blockHash: cl.blockhash, llmqType: selected.type,
       quorumHash: selected.quorumHash, quorumPublicKey: selected.quorumPublicKey,
       signature: cl.signature,
     }) === false);
  ok("a altered block hash does not verify",
     verifyChainLockSignature(bls, {
       height: cl.height, blockHash: "00".repeat(32), llmqType: selected.type,
       quorumHash: selected.quorumHash, quorumPublicKey: selected.quorumPublicKey,
       signature: cl.signature,
     }) === false);
  ok("a different llmqType does not verify",
     verifyWith({ ...selected, type: "llmq_devnet" }) === false);
  ok("a flipped signature byte does not verify",
     verifyWith({ ...selected,
       signature: (cl.signature[0] === "0" ? "1" : "0") + cl.signature.slice(1) }) === false);
  ok("a structurally invalid signature is a FALSE verdict, not a thrown error",
     verifyWith({ ...selected, signature: "ff".repeat(96) }) === false);
  throws("a wrong-length signature is refused as out of domain",
    () => verifyWith({ ...selected, signature: "aa" }), /96 bytes of lowercase hex/);
  throws("a wrong-length public key is refused as out of domain",
    () => verifyWith({ ...selected, quorumPublicKey: "aa" }), /48 bytes of lowercase hex/);

  // ---- the whole endpoint check in one call ----
  const outcome = verifyChainLockAgainstQuorumSet(
    bls, { height: cl.height, blockHash: cl.blockhash, signature: cl.signature }, quorums);
  ok("the endpoint check verifies and reports the responsible quorum",
     outcome.verified === true && outcome.selected.quorumHash === selected.quorumHash);
  ok("the endpoint check over a set WITHOUT the signing quorum fails",
     verifyChainLockAgainstQuorumSet(
       bls, { height: cl.height, blockHash: cl.blockhash, signature: cl.signature },
       [other]).verified === false);

  // the score preimage and the sign-hash preimage must stay distinct: the score is the
  // sign hash WITHOUT the message, so a refactor that conflated them would be caught here
  const sh = deriveSignHash({ llmqType: selected.type, quorumHash: selected.quorumHash,
                              requestId, msgHash: cl.blockhash });
  const sc = deriveQuorumScore({ llmqType: selected.type, quorumHash: selected.quorumHash, requestId });
  ok("the sign hash and the selection score are distinct values",
     sh.toString("hex") !== sc.toString("hex"));

  // EVERY CANDIDATE IS VALIDATED, not only the winner (repository-access round, MAJOR).
  // Reproduced: the two real quorums plus an extra llmq_devnet entry with an all-zero public
  // key returned verified:true, because the genuine signer held the lowest score and the
  // malformed member was never examined.
  const bogus = { type: "llmq_devnet", quorumHash: "ab".repeat(32),
                  quorumPublicKey: "00".repeat(48), height: 1 };
  throws("a mixed-type candidate set is refused",
    () => verifyChainLockAgainstQuorumSet(
      bls, { height: cl.height, blockHash: cl.blockhash, signature: cl.signature },
      [...quorums, bogus]), /mixes llmqType/);
  throws("an all-zero public key anywhere in the set is refused",
    () => selectSignatoryQuorum(bls, [...quorums, { ...bogus, type: "llmq_test" }], requestId),
    /all-zero public key/);
  throws("a malformed quorumHash anywhere in the set is refused",
    () => selectSignatoryQuorum(bls, [...quorums, { type: "llmq_test", quorumHash: "abc",
      quorumPublicKey: "aa".repeat(48) }], requestId), /malformed quorumHash/);
  throws("a malformed public key anywhere in the set is refused",
    () => selectSignatoryQuorum(bls, [...quorums, { type: "llmq_test", quorumHash: "cd".repeat(32),
      quorumPublicKey: "aa" }], requestId), /malformed quorumPublicKey/);
  ok("the clean pinned set still selects and verifies",
     verifyChainLockAgainstQuorumSet(
       bls, { height: cl.height, blockHash: cl.blockhash, signature: cl.signature },
       quorums).verified === true);

  // round 4, MAJOR: only the SELECTED key was ever parsed as a curve point, so replacing the
  // unselected quorum's key with ff*48 (correctly sized, not a valid point) still returned
  // verified:true because the real signer held the lowest score.
  {
    const badPoint = quorums.map((q) => (q.quorumHash === selected.quorumHash
      ? q : { ...q, quorumPublicKey: "ff".repeat(48) }));
    throws("a correctly sized INVALID point in an unselected member is refused",
      () => verifyChainLockAgainstQuorumSet(
        bls, { height: cl.height, blockHash: cl.blockhash, signature: cl.signature }, badPoint),
      /not a valid BLS point/);
    ok("the clean set still verifies after that check was added",
       verifyChainLockAgainstQuorumSet(
         bls, { height: cl.height, blockHash: cl.blockhash, signature: cl.signature },
         quorums).verified === true);
  }

  console.log(`chainLockVerifyTest: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => {
  console.error("chainLockVerifyTest threw:", e && e.stack ? e.stack : e);
  process.exit(1);
});
