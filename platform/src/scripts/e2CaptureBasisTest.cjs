/**
 * e2CaptureBasisTest: the offline battery for the shared capture-basis adapter
 * (e2CaptureBasis.cjs, a soundness-review finding repair). Real key pairs from the installed curve library,
 * the repository's own signCapture and signSupersession, and the reviewer's reproduction
 * construction as the first cases. WHAT IT BINDS, the repair's acceptance criteria:
 *   1. a valid original verifies under its own resolved key (one key read, the original's
 *      signer); a 65-zero-byte signature is refused; a valid signature under a DIFFERENT
 *      resolved key is refused;
 *   2. a valid supersession over an original whose own signature is invalid is SELECTED
 *      (the candidate's key resolved, the original's never read) and answers true; the old
 *      callback shape (the candidate's own bytes) would have refused it;
 *   3. the fallback bound explicitly: with every matching supersession invalid, a valid
 *      original passes and an invalid original fails; the selector's subject, sequence and
 *      malformed-candidate rules are kept and a selector refusal answers false; a key that
 *      cannot be resolved answers false with the diagnostic printed;
 *   4. BOTH LIVE RUNNERS bind the name their consumers receive EXACTLY ONCE to the factory's
 *      result over the runner's resolver and sink, define it no other way, hand it on, and
 *      carry no selector call (a SOURCE SWEEP over the two .mjs files beside this test: it
 *      binds the assignment's spelling, not the executed binding, which only the live run
 *      exercises; a wrapper discarding the checked adapter defines the name a second way and
 *      is refused).
 */
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { pathToFileURL } = require("url");
const C = require("./e2CaptureRecord.cjs");
const { makeVerifyCaptureBasis } = require("./e2CaptureBasis.cjs");

const { runnerSource, skipNote } = require("./runnerSource.cjs");
let passed = 0, failed = 0, skipped = 0;
const ok = (name, cond) => { if (cond) { passed += 1; console.log(`  PASS: ${name}`); } else { failed += 1; console.log(`  FAIL: ${name}`); } };
const throws = (name, fn, re) => { try { fn(); failed += 1; console.log(`  FAIL: ${name} (no refusal)`); } catch (e) { const m = (e && e.message) || String(e); ok(`${name} (${m.slice(0, 80)})`, re.test(m)); } };

const fixture = {
  v: 1, kind: C.RECEIPT_KIND, object: "transfer", gen: 1,
  poolId: "ab".repeat(32), epochIndex: 412, accrualId: "a1".repeat(32),
  transitionHash: crypto.createHash("sha256").update(Buffer.from("0a0b0c", "hex")).digest("hex"),
  transitionBytes: "0a0b0c", proofMsg: "cc".repeat(50), metadataMsg: "dd".repeat(16),
  inclusionHeight: "123999", heightRoute: "tenderdash-tx",
  signerIdentity: "f0".repeat(32), signerKeyId: 2,
};
const supersessionFor = (original, seq, signerKeyId) => ({
  v: 1, kind: C.SUPERSESSION_KIND, gen: original.gen, poolId: original.poolId, epochIndex: original.epochIndex, accrualId: original.accrualId,
  supersededKind: original.kind, object: "transfer", transitionHash: original.transitionHash, preimageHash: C.preimageDigest(original), seq,
  signerIdentity: "f0".repeat(32), signerKeyId,
});

const main = async () => {
  const ROOT = process.env.TEGARA_PLATFORM_ROOT || path.join(__dirname, "..", "..");
  const { secp256k1 } = await import(pathToFileURL(require.resolve("@noble/curves/secp256k1.js", { paths: [ROOT] })).href);
  const originalKey = secp256k1.keygen(), successorKey = secp256k1.keygen(), strangerKey = secp256k1.keygen();
  const signed = await C.signCapture(fixture, originalKey.secretKey);
  const invalid = { ...signed, sig: "00".repeat(65) };
  // THE RESOLVER IS KEYED BY THE FULL (signerIdentity, signerKeyId) PAIR and records the
  // record it was handed, so an adapter resolving another identity's key at the same key
  // number, or resolving a fixed record, is observable (the checker's construction: two
  // identities sharing key number 2). Identity F0 owns the original key at 2 and the
  // successor key at 5; identity F1 owns the STRANGER's key at 2; nothing owns key 9.
  const ID_F0 = "f0".repeat(32), ID_F1 = "f1".repeat(32);
  const KEYS = { [`${ID_F0}:2`]: originalKey.publicKey, [`${ID_F0}:5`]: successorKey.publicKey, [`${ID_F1}:2`]: strangerKey.publicKey };
  const mkResolver = (keys = KEYS) => { const reads = []; const records = []; const logs = []; const resolveSignerKey = async (rec) => { records.push(rec); reads.push(`${rec.signerIdentity.slice(0, 2)}:${rec.signerKeyId}`); const k = keys[`${rec.signerIdentity}:${rec.signerKeyId}`]; if (!k) throw new Error(`signer key ${rec.signerKeyId} not among identity ${rec.signerIdentity.slice(0, 8)}...'s published keys`); return k; }; return { reads, records, logs, adapter: makeVerifyCaptureBasis({ resolveSignerKey, log: (s) => logs.push(s) }) }; };

  // ================= 1. the original's own signature =================
  {
    const { reads, records, adapter } = mkResolver();
    ok("a valid original with no supersessions verifies under its own resolved key, with exactly one resolver call handed THE CAPTURE ITSELF (identity f0, key 2)", (await adapter(signed, [])) === true && JSON.stringify(reads) === JSON.stringify(["f0:2"]) && records.length === 1 && records[0] === signed);
  }
  {
    const { reads, logs, adapter } = mkResolver();
    ok("a 65-zero-byte signature with no supersessions is REFUSED (the reviewer's construction, previously accepted with zero reads), with the original's key read and the refusal printed", (await adapter(invalid, [])) === false && JSON.stringify(reads) === JSON.stringify(["f0:2"]) && logs.some((l) => /original capture's signature does not verify/.test(l)));
  }
  {
    // THE SIGNED RECORD IS UNCHANGED (signerKeyId is inside the signed bytes, so altering it
    // would refuse for a second reason); the RESOLVER answers the wrong key for the pair
    const { reads, adapter } = mkResolver({ ...KEYS, [`${ID_F0}:2`]: strangerKey.publicKey });
    ok("a valid signature checked under a DIFFERENT resolved key (the resolver answering another key for the same pair) is refused", (await adapter(signed, [])) === false && JSON.stringify(reads) === JSON.stringify(["f0:2"]));
    // TWO IDENTITIES SHARING KEY NUMBER 2: a record naming identity f1 at key 2, signed under
    // f0's key 2, must be refused; an adapter resolving by key number alone would accept it
    const { reads: r2, adapter: a2 } = mkResolver();
    const namedF1 = await C.signCapture({ ...fixture, signerIdentity: ID_F1 }, originalKey.secretKey);
    ok("a record naming another identity at the same key number, signed under the first identity's key, is refused (the pair resolved, not the number)", (await a2(namedF1, [])) === false && JSON.stringify(r2) === JSON.stringify(["f1:2"]));
    const { adapter: a3 } = mkResolver();
    const namedF1Valid = await C.signCapture({ ...fixture, signerIdentity: ID_F1 }, strangerKey.secretKey);
    ok("control: the same record signed under identity f1's own key 2 verifies", (await a3(namedF1Valid, [])) === true);
  }

  // ================= 2. a valid supersession over an invalid original =================
  const sup1 = await C.signSupersession(invalid, supersessionFor(invalid, 1, 5), successorKey.secretKey);
  {
    const { reads, records, adapter } = mkResolver();
    ok("a valid supersession over an original whose own signature is invalid is SELECTED and answers true, the candidate's key resolved (f0:5, the candidate record handed) and the original's never read", (await adapter(invalid, [sup1])) === true && JSON.stringify(reads) === JSON.stringify(["f0:5"]) && records[0] === sup1);
    ok("control: the candidate's signature is over the original's preimage, so the old callback shape (the candidate's own bytes) refuses it", (await C.verifyCaptureSignature(sup1, successorKey.publicKey)) === false && (await C.verifySupersessionSignature(invalid, sup1, successorKey.publicKey)) === true);
  }

  // ================= 3. the fallback, bound explicitly =================
  const badSup = { ...sup1, sig: "00".repeat(65) };
  {
    const { reads, adapter } = mkResolver();
    const signedBadSup = { ...badSup, preimageHash: C.preimageDigest(signed) };
    ok("every matching supersession invalid over a VALID original: the fallback verifies the original and answers true (candidate key read, then the original's)", (await adapter(signed, [signedBadSup])) === true && JSON.stringify(reads) === JSON.stringify(["f0:5", "f0:2"]));
  }
  {
    const { reads, adapter } = mkResolver();
    ok("every matching supersession invalid over an INVALID original: the fallback verifies the original and answers false", (await adapter(invalid, [badSup])) === false && JSON.stringify(reads) === JSON.stringify(["f0:5", "f0:2"]));
    // TWO CANDIDATES, the first invalid and the second valid (seq 2 over seq 1): the selector
    // tries downward from the maximum, so the valid one is selected and the invalid never read
    const { reads: rTwo, adapter: aTwo } = mkResolver();
    const sup2 = await C.signSupersession(invalid, supersessionFor(invalid, 2, 5), successorKey.secretKey);
    const sup1Bad = { ...sup1, sig: "00".repeat(65) };
    ok("with two matching candidates the valid one (seq 2) is selected over the invalid (seq 1): one candidate key read, the answer true", (await aTwo(invalid, [sup1Bad, sup2])) === true && JSON.stringify(rTwo) === JSON.stringify(["f0:5"]));
    // THE LOWER CANDIDATE IS TRIED TOO (the second pass's gap): an invalid seq 2 over a valid
    // seq 1, both over an invalid original, answers true with the candidate key read twice
    const { reads: rLow, adapter: aLow } = mkResolver();
    const sup2Bad = { ...sup2, sig: "00".repeat(65) };
    ok("an invalid higher candidate (seq 2) does not stop the selection: the valid lower one (seq 1) verifies and answers true", (await aLow(invalid, [sup1, sup2Bad])) === true && JSON.stringify(rLow) === JSON.stringify(["f0:5", "f0:5"]));
  }
  {
    const { reads, adapter } = mkResolver();
    const unrelated = { ...sup1, accrualId: "b2".repeat(32) };
    ok("a supersession with another subject tuple is ignored by the selector (not verified) and the original is verified", (await adapter(signed, [unrelated])) === true && JSON.stringify(reads) === JSON.stringify(["f0:2"]));
  }
  {
    const { reads, logs, adapter } = mkResolver();
    const wrongSeq = { ...sup1, seq: 2 };
    ok("a non-contiguous supersession sequence is the selector's refusal, answered false with the reason printed and no key read", (await adapter(invalid, [wrongSeq])) === false && reads.length === 0 && logs.some((l) => /capture basis unresolved/.test(l) && /seq set/.test(l)));
  }
  {
    const { logs, adapter } = mkResolver();
    const malformed = { ...sup1, preimageHash: "zz" };
    ok("a malformed candidate is the selector's refusal, answered false with the reason printed", (await adapter(invalid, [malformed])) === false && logs.some((l) => /capture basis unresolved/.test(l)));
  }
  {
    const { reads, logs, adapter } = mkResolver();
    const unresolvable = { ...signed, signerKeyId: 9 };
    // A CANDIDATE's key resolution failing is NOT a fall-through to the original (the confirmation
    // round's coverage item): the run answers false with the reason printed, the original never read
    const { reads: rCand, logs: lCand, adapter: aCand } = mkResolver({ [`${ID_F0}:2`]: originalKey.publicKey });
    ok("a matching candidate whose signer key cannot be resolved answers false with the reason printed, the original's key never read (no silent fallback)", (await aCand(signed, [sup1])) === false && JSON.stringify(rCand) === JSON.stringify(["f0:5"]) && lCand.some((l) => /capture basis unresolved/.test(l) && /published keys/.test(l)));
    ok("a signer key that cannot be resolved answers false with the resolver's reason printed (CANNOT-VERIFY, never affirmative)", (await adapter(unresolvable, [])) === false && JSON.stringify(reads) === JSON.stringify(["f0:9"]) && logs.some((l) => /published keys/.test(l)));
  }
  {
    // A THROWING SINK does not turn a settled answer into a rejection (the checker's
    // construction): the invalid original still answers false, the unresolvable key too
    const throwingLog = () => { throw new Error("sink unavailable"); };
    const a = makeVerifyCaptureBasis({ resolveSignerKey: async (rec) => { const k = KEYS[`${rec.signerIdentity}:${rec.signerKeyId}`]; if (!k) throw new Error("no key"); return k; }, log: throwingLog });
    let settled = null; try { settled = await a(invalid, []); } catch (e) { settled = `rejected: ${e.message}`; }
    let settled2 = null; try { settled2 = await a({ ...signed, signerKeyId: 9 }, []); } catch (e) { settled2 = `rejected: ${e.message}`; }
    let settled3 = null; try { settled3 = await a(signed, []); } catch (e) { settled3 = `rejected: ${e.message}`; }
    ok("a throwing logger never makes the promise reject: an invalid original settles false, an unresolvable key settles false, a valid original settles true", settled === false && settled2 === false && settled3 === true);
    // AN UNREADABLE THROWN VALUE (the second pass's construction: a null-prototype object has
    // no message and String() throws on it) still settles false, the fixed text printed
    const logs4 = [];
    const a4 = makeVerifyCaptureBasis({ resolveSignerKey: async () => { throw Object.create(null); }, log: (s) => logs4.push(s) });
    let settled4 = null; try { settled4 = await a4(signed, []); } catch (e) { settled4 = "rejected"; }
    ok("a resolver rejecting with an unreadable value settles false with the fixed diagnostic text", settled4 === false && logs4.some((l) => /unreadable thrown value/.test(l)));
  }
  throws("the factory needs the resolver", () => makeVerifyCaptureBasis({ log: () => {} }), /needs resolveSignerKey/);
  throws("the factory needs an explicit log", () => makeVerifyCaptureBasis({ resolveSignerKey: async () => originalKey.publicKey }), /needs an explicit log/);

  // ================= 4. both live runners consume this module =================
  {
    const runners = ["e2ForwardTransportRun.mjs", "e2AuditRun.mjs"];
    for (const f of runners) {
      const src = runnerSource(f);
      if (src === null) { skipped += 1; console.log(skipNote(f, "the runner-binding sweep")); continue; }
      // THE EXACT BINDING is required (the assignment of the factory's result to the name the
      // consumers receive), any OTHER definition of that name is forbidden, and the name must
      // reach its consumer: a wrapper that builds the checked adapter and then discards it
      // (the checker's construction) defines the name a second way and is refused here.
      // STATED WIDTH: this is a source sweep over text; it binds the assignment's spelling,
      // not the executed binding, which only the live run exercises
      const binding = /const verifyCaptureBasis = makeVerifyCaptureBasis\(\{ resolveSignerKey: resolveSignerKeyOf, log: line \}\);/;
      const definitions = (src.match(/verifyCaptureBasis\s*=/g) || []).length;
      const reachesConsumer = f === "e2AuditRun.mjs" ? /^\s*verifyCaptureBasis,\s*$/m.test(src) : /const deps = \{ verifierDeps, verifyCaptureBasis \};/.test(src);
      ok(`${f} binds verifyCaptureBasis EXACTLY ONCE to the factory's result over the runner's resolver and sink, carries no other ASSIGNMENT to that name, hands that name to its consumer, and carries no selector call spelling (a text sweep)`, binding.test(src) && definitions === 1 && reachesConsumer && !/selectSupersessionBasis\(/.test(src) && /e2CaptureBasis\.cjs/.test(src));
    }
    const others = fs.readdirSync(__dirname).filter((f) => /\.(cjs|mjs)$/.test(f) && !/Test\.cjs$/.test(f) && f !== "e2CaptureBasis.cjs" && f !== "e2CaptureRecord.cjs")
      .filter((f) => /selectSupersessionBasis\(/.test(fs.readFileSync(path.join(__dirname, f), "utf8")));
    ok(`no other non-test module in this directory carries the selector call spelling (${others.join(", ") || "none"}; a text sweep)`, others.length === 0);
  }

  console.log(`\ne2CaptureBasisTest: ${passed} passed, ${failed} failed` + (skipped ? `, ${skipped} skipped (counted, never folded into passes)` : ""));
  if (failed) process.exitCode = 1;
};
main().catch((e) => { console.error("e2CaptureBasisTest crashed:", e && e.stack || e); process.exitCode = 1; });
