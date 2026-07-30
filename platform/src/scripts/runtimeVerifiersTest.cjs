/**
 * Fixtures for the runtime verifiers (the cryptographic half). Plain `node`.
 *
 * The decisive property for each IMPLEMENTED verifier is that it accepts genuine
 * material and REJECTS alteration. The shipped conformance vector carries PLACEHOLDER
 * signature material by design (it exists to exercise structure, not crypto), so the
 * signature fixtures build real ed25519 keys and re-sign the vector's own payload.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  coreChainIdentityHash, v2DomainTag, runVerifiers,
  verifyIdentifierConversion, verifyTransitionHashes, verifyCheckpointRecognition,
  allVerifiers, BLOCKED_VERIFIERS, COMPONENT_OF,
} = require("./runtimeVerifiers.cjs");
// the fixture mines real Dash-shaped blocks, so it needs the real block-hash function
const { blockHashOf } = require("./mnListDiffCodec.cjs");

let pass = 0, fail = 0;
const ok = (n, c) => { if (c) pass++; else { fail++; console.error(`FAIL: ${n}`); } };
const SCHEMA_DIR = path.join(__dirname, "..", "..", "..", "docs", "schema");
const positive = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, "vectors", "positive_minimal.json"), "utf8"));
const evidenceOf = (e) => { const c = JSON.parse(JSON.stringify(e)); delete c.rewards; delete c.claimProfile; return c; };
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();

// ---- the derived chain identity matches the NORMATIVE Python derivation ----
const pyIdentity = require("child_process").execFileSync("python3", ["-c",
  "import importlib.util,sys;s=importlib.util.spec_from_file_location('cv','check_vectors.py');" +
  "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(m.CHAIN_IDENTITY.hex())"],
  { cwd: SCHEMA_DIR, encoding: "utf8" }).trim();
ok("coreChainIdentityHash matches the normative Python derivation byte-for-byte",
   coreChainIdentityHash(positive.network).toString("hex") === pyIdentity);
// a DIFFERENT devnet height-one genesis yields a DIFFERENT identity (the a soundness-review finding property)
const otherDevnet = { ...positive.network, coreDevnetGenesisBlockHash: "cd".repeat(32) };
ok("a different devnet height-one genesis derives a different identity",
   coreChainIdentityHash(otherDevnet).toString("hex") !== pyIdentity);

// ---- verifyIdentifierConversion ----
const ev = evidenceOf(positive);
ok("identifier conversion passes on the shipped identity", verifyIdentifierConversion(ev).ok === true);
const badId = evidenceOf(positive); badId.poolProTxHash = "ab".repeat(32);
ok("...and still passes a well-formed but different identity (no registration to bind)",
   verifyIdentifierConversion(badId).ok === true);
// under FIRST_APPEARANCE the txid MUST be the identity
const faEv = evidenceOf(positive);
faEv.basePackage = { ...faEv.basePackage, baseMode: "FIRST_APPEARANCE",
  firstAppearance: { pHeight: 1000, proRegTxRaw: "99".repeat(120),
                     proRegTxInclusionProof: "de".repeat(40), additionDiffRaw: "de".repeat(40) } };
ok("FIRST_APPEARANCE with a mismatched ProRegTx is REJECTED",
   verifyIdentifierConversion(faEv).ok === false);
const realTxid = sha256(sha256(Buffer.from("99".repeat(120), "hex")));
faEv.poolProTxHash = Buffer.from(realTxid).reverse().toString("hex");
ok("FIRST_APPEARANCE with the true ProRegTx txid is ACCEPTED",
   verifyIdentifierConversion(faEv).ok === true);

// ---- verifyTransitionHashes ----
ok("transition hashes pass on the shipped evidence", verifyTransitionHashes(ev).ok === true);
const alterHash = evidenceOf(positive);
alterHash.slots[0].ownershipChain[0].transitionHash = "ab".repeat(32);
ok("a hop not bound to its retained bytes is REJECTED", verifyTransitionHashes(alterHash).ok === false);
const alterBytes = evidenceOf(positive);
alterBytes.coverage.platformLedger[0].txs[0].rawBytes += "00";
ok("mutating the retained bytes under a hop is REJECTED", verifyTransitionHashes(alterBytes).ok === false);

// ---- verifyCheckpointRecognition: real ed25519 material ----
// the vector's payload already carries the correct domain tag for this chain identity;
// re-sign it with a REAL key and make that key the deployment authority
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const rawPub = publicKey.export({ format: "der", type: "spki" }).subarray(12);
const signed = evidenceOf(positive);

// MINE A REAL HEIGHT-ONE HEADER for the devnet duty (round 4, MUST-FIX: the old fixture
// passed `{coreNode: {}}` and REQUIRED success, so it demanded the wrong outcome for a
// retrieval duty nothing performed). The header extends the vector's height-zero genesis,
// carries the regtest-class compact target 0x207fffff, and is ground until its hash
// satisfies its own proof of work, so the verifier's three checks all run against real
// bytes. The envelope's devnet genesis field is pointed at the mined hash BEFORE the chain
// identity is derived and signed over, keeping the domain-tag binding intact.
// `mutateCoinbase` rewrites the coinbase BEFORE its txid is taken, so a case that alters bytes
// inside the transaction still gets a header mined over the resulting merkle root. Without that
// the altered block would refuse at the hash comparison and never reach the parser, which is the
// vacuous-fixture pattern this cycle keeps finding (round 8, finding 3).
const mineHeightOne = (parentDisplayHex, devnetName = "tegara-fixture-devnet",
                       nBits = 0x207fffff, mutateCoinbase = null) => {
  // A FULL BLOCK, not a header (round 5, MUST-FIX). The verifier now requires the coinbase and
  // requires the header's merkle root to BE the coinbase txid, which is the identity that binds
  // the devnet-name commitment to the verified hash. A fixture that supplied only a header could
  // not exercise any of that, and the previous one did not.
  //
  // The coinbase is built the way Dash builds a devnet genesis coinbase
  // (8c9f166a3:src/chainparams.cpp:43-64): one input with a null prevout whose scriptSig is
  // OP_1 followed by a push of the devnet name, and one OP_RETURN output.
  const nameBytes = Buffer.from(devnetName, "utf8");
  const scriptSig = Buffer.concat([Buffer.from([0x51]),                       // OP_1, BIP34 height
                                   Buffer.from([nameBytes.length]), nameBytes]);
  let coinbase = Buffer.concat([
    Buffer.from([1, 0, 0, 0]),                                                // version 1
    Buffer.from([1]),                                                         // one input
    Buffer.alloc(32),                                                         // null prevout hash
    Buffer.from([0xff, 0xff, 0xff, 0xff]),                                    // null prevout index
    Buffer.from([scriptSig.length]), scriptSig,
    Buffer.from([0xff, 0xff, 0xff, 0xff]),                                    // sequence
    Buffer.from([1]),                                                         // one output
    Buffer.alloc(8),                                                          // zero value
    Buffer.from([1, 0x6a]),                                                   // OP_RETURN
    Buffer.from([0, 0, 0, 0]),                                                // locktime
  ]);
  if (mutateCoinbase) coinbase = mutateCoinbase(coinbase);
  const txid = sha256(sha256(coinbase));

  const header = Buffer.alloc(80);
  header.writeUInt32LE(0x20000000, 0);                                   // version
  Buffer.from(parentDisplayHex, "hex").reverse().copy(header, 4);        // prev block
  txid.copy(header, 36);                                                 // merkle root IS the txid
  header.writeUInt32LE(1721900000, 68);                                  // time
  header.writeUInt32LE(nBits, 72);                                       // nBits
  const exp = nBits >>> 24, man = BigInt(nBits & 0x007fffff);
  const target = exp <= 3 ? man >> (8n * BigInt(3 - exp)) : man << (8n * BigInt(exp - 3));
  // MINE AGAINST THE REAL BLOCK HASH. A Dash block hash is X11; the earlier version of this
  // helper mined against sha256d, which matched the verifier's own mistake and hid it, so no
  // real devnet block would have passed either.
  for (let nonce = 0; ; nonce++) {
    header.writeUInt32LE(nonce, 76);
    const display = blockHashOf(header);
    const internal = Buffer.from(display, "hex").reverse();
    let v = 0n;
    for (let i = internal.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(internal[i]);
    if (v <= target) {
      const blockHex = Buffer.concat([header, Buffer.from([1]), coinbase]).toString("hex");
      return { blockHex, headerHex: header.toString("hex"),
               coinbaseHex: coinbase.toString("hex"), displayHash: display };
    }
  }
};
const mined = mineHeightOne(signed.network.coreGenesisBlockHash);
signed.network = { ...signed.network, coreDevnetGenesisBlockHash: mined.displayHash };
const minedCoreNode = { getBlockHexByHeight: (h) => (h === 1 ? mined.blockHex : null) };
const identity = coreChainIdentityHash(signed.network);
signed.checkpointAuthority = { publicKey: rawPub.toString("hex") };
for (const cp of signed.checkpoints) {
  // the payload's embedded tag must be THIS authority's tag
  const payload = Buffer.from(cp.signedPayloadBytes, "hex");
  v2DomainTag(identity, rawPub).copy(payload, 4);
  const digest = sha256(payload);
  cp.signedPayloadBytes = payload.toString("hex");
  cp.checkpointId = digest.toString("hex");
  cp.signerPublicKey = rawPub.toString("hex");
  cp.signature = crypto.sign(null, digest, privateKey).toString("hex");
}
// on DEVNET the component stays blocked on the height-one duty even when the signatures
// verify -- the honest outcome, with the proved half reported explicitly
const sigRes = verifyCheckpointRecognition(signed);
ok("a genuinely signed checkpoint set PROVES its signatures",
   typeof sigRes.proved === "string" && /signature\(s\) verified/.test(sigRes.proved));
ok("...but devnet stays BLOCKED on the height-one duty (no overclaim)",
   sigRes.ran === false && /height-one/.test(sigRes.blockedOn));
ok("a Core node WITHOUT the retrieval method leaves the duty BLOCKED, never completed",
   (() => { const r = verifyCheckpointRecognition(signed, { coreNode: {} });
            return r.ran === false && /getBlockHexByHeight/.test(r.blockedOn); })());
ok("a Core node serving the REAL height-one block completes the duty",
   verifyCheckpointRecognition(signed, { coreNode: minedCoreNode }).ok === true);
ok("...and the success names what was authenticated",
   /retrieved and authenticated/.test(
     verifyCheckpointRecognition(signed, { coreNode: minedCoreNode }).detail));
ok("a block that hashes to a DIFFERENT devnet genesis is REJECTED", (() => {
  const other = JSON.parse(JSON.stringify(signed));
  other.network = { ...other.network, coreDevnetGenesisBlockHash: "ab".repeat(32) };
  // re-derive and re-sign under the altered identity so only the block check can fail
  const id3 = coreChainIdentityHash(other.network);
  for (const cp of other.checkpoints) {
    const pl = Buffer.from(cp.signedPayloadBytes, "hex");
    v2DomainTag(id3, rawPub).copy(pl, 4);
    const dg = sha256(pl);
    cp.signedPayloadBytes = pl.toString("hex");
    cp.checkpointId = dg.toString("hex");
    cp.signature = crypto.sign(null, dg, privateKey).toString("hex");
  }
  const r = verifyCheckpointRecognition(other, { coreNode: minedCoreNode });
  return r.ran === true && r.ok === false && /hashes to/.test(r.reason);
})());
ok("a block not extending the height-zero genesis is REJECTED", (() => {
  const wrongParent = mineHeightOne("cd".repeat(32));
  const node = { getBlockHexByHeight: () => wrongParent.blockHex };
  const env2 = JSON.parse(JSON.stringify(signed));
  env2.network = { ...env2.network, coreDevnetGenesisBlockHash: wrongParent.displayHash };
  const id4 = coreChainIdentityHash(env2.network);
  for (const cp of env2.checkpoints) {
    const pl = Buffer.from(cp.signedPayloadBytes, "hex");
    v2DomainTag(id4, rawPub).copy(pl, 4);
    const dg = sha256(pl);
    cp.signedPayloadBytes = pl.toString("hex");
    cp.checkpointId = dg.toString("hex");
    cp.signature = crypto.sign(null, dg, privateKey).toString("hex");
  }
  const r = verifyCheckpointRecognition(env2, { coreNode: node });
  return r.ran === true && r.ok === false && /does not extend/.test(r.reason);
})());
ok("an unparseable node response is REJECTED, not treated as done", (() => {
  const r = verifyCheckpointRecognition(signed, { coreNode: { getBlockHexByHeight: () => "zz" } });
  return r.ran === true && r.ok === false && /parseable/.test(r.reason);
})());
// on a non-devnet network there is no height-one duty at all
const asTestnet = JSON.parse(JSON.stringify(signed));
asTestnet.network = { coreNetwork: "testnet",
  coreGenesisBlockHash: "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c",
  platformChainId: asTestnet.network.platformChainId };
{
  const id2 = coreChainIdentityHash(asTestnet.network);
  for (const cp of asTestnet.checkpoints) {
    const p = Buffer.from(cp.signedPayloadBytes, "hex");
    v2DomainTag(id2, rawPub).copy(p, 4);
    const d = sha256(p);
    cp.signedPayloadBytes = p.toString("hex"); cp.checkpointId = d.toString("hex");
    cp.signature = crypto.sign(null, d, privateKey).toString("hex");
  }
}
ok("a non-devnet network completes without a Core node",
   verifyCheckpointRecognition(asTestnet).ok === true);
ok("the shipped placeholder signature is REJECTED (crypto is really checked)",
   verifyCheckpointRecognition(ev).ok === false);
// alter: a valid signature over a DIFFERENT payload
const alteredPayload = JSON.parse(JSON.stringify(signed));
const p0 = Buffer.from(alteredPayload.checkpoints[0].signedPayloadBytes, "hex");
p0[p0.length - 1] ^= 0xff;
alteredPayload.checkpoints[0].signedPayloadBytes = p0.toString("hex");
alteredPayload.checkpoints[0].checkpointId = sha256(p0).toString("hex");
ok("a mutated payload breaks the signature", verifyCheckpointRecognition(alteredPayload).ok === false);
// a foreign signer, even with a valid signature of its own
const foreign = crypto.generateKeyPairSync("ed25519");
const foreignEv = JSON.parse(JSON.stringify(signed));
foreignEv.checkpoints[0].signerPublicKey =
  foreign.publicKey.export({ format: "der", type: "spki" }).subarray(12).toString("hex");
ok("a signer other than the fixed authority is REJECTED",
   verifyCheckpointRecognition(foreignEv).ok === false);
// THE a soundness-review finding PROPERTY: a checkpoint signed for another devnet cannot be reused here
const copied = JSON.parse(JSON.stringify(signed));
copied.network = { ...copied.network, coreDevnetGenesisBlockHash: "cd".repeat(32) };
ok("a checkpoint copied to a DIFFERENT devnet fails the domain tag",
   verifyCheckpointRecognition(copied).ok === false);

// ---- the harness ----
const run = runVerifiers(ev);
ok("the harness runs every registry verifier",
   Object.keys(run.results).length === Object.keys(COMPONENT_OF).length);
ok("blocked verifiers report ran:false with a named dependency",
   Object.values(run.results).filter((r) => r.ran === false)
     .every((r) => typeof r.blockedOn === "string" && r.blockedOn.length > 10));
ok("a blocked verifier NEVER yields an attestation",
   run.attestations.every((a) => !(a.verifier in BLOCKED_VERIFIERS)));
ok("a FAILED verifier yields no attestation",
   !run.attestations.some((a) => a.verifier === "verifyCheckpointRecognition"));
ok("attestations are bound to the evidence digest",
   run.attestations.every((a) => a.evidenceDigest === run.evidenceDigest));
ok("the two implementable verifiers attest on the shipped evidence", run.attestations.length === 2);
const runSigned = runVerifiers(signed, { coreNode: minedCoreNode });
ok("with real signatures and a REAL Core node, recognition also attests", runSigned.attestations.length === 3);
ok("a method-less coreNode mints NO recognition attestation",
   runVerifiers(signed, { coreNode: {} }).attestations.length === 2);
ok("without a Core node it does NOT attest on devnet", runVerifiers(signed).attestations.length === 2);
ok("...and its digest differs from the other evidence set",
   runSigned.evidenceDigest !== run.evidenceDigest);

// ---------------------------------------------------------------------------
// Round 5 (2026-07-26), MUST-FIX and MAJOR. Each case below was reproduced against the tree
// before the fix. The previous version checked a HEADER only, so two of the registry's four
// named checks were never performed, and its nBits handling accepted a target outside the
// 256-bit range, which every hash satisfies.
// ---------------------------------------------------------------------------
{
  const patch = (blockHex, mutate) => {
    const b = Buffer.from(blockHex, "hex");
    mutate(b);
    return b.toString("hex");
  };
  const nodeOf = (hex) => ({ getBlockHexByHeight: () => hex });

  // an nBits whose expansion leaves the 256-bit range is INVALID, not merely weak
  {
    const bad = patch(mined.blockHex, (b) => b.writeUInt32LE(0x2200ffff, 72));
    const r = verifyCheckpointRecognition(signed, { coreNode: nodeOf(bad) });
    ok("an nBits expanding outside the 256-bit range is refused",
       r.ok === false && /valid 256-bit target range|hashes to/.test(r.reason));
  }
  {
    const bad = patch(mined.blockHex, (b) => b.writeUInt32LE(0x20000000, 72));
    const r = verifyCheckpointRecognition(signed, { coreNode: nodeOf(bad) });
    ok("a zero nBits mantissa is refused", r.ok === false);
  }

  // a HEADER with no block body can no longer satisfy the duty
  {
    const r = verifyCheckpointRecognition(signed, { coreNode: nodeOf(mined.headerHex) });
    ok("a header with no coinbase is refused", r.ok === false);
  }

  // the merkle root must BE the coinbase txid; that identity is the whole binding argument
  {
    const bad = patch(mined.blockHex, (b) => { b[36] = b[36] ^ 0xff; });
    const r = verifyCheckpointRecognition(signed, { coreNode: nodeOf(bad) });
    ok("a merkle root that is not the coinbase txid is refused", r.ok === false);
  }

  // an EMPTY devnet-name push fails the registry's nonempty requirement
  {
    const empty = mineHeightOne(signed.network.coreGenesisBlockHash, "");
    const env2 = JSON.parse(JSON.stringify(signed));
    env2.network = { ...env2.network, coreDevnetGenesisBlockHash: empty.displayHash };
    const r = verifyCheckpointRecognition(env2, { coreNode: nodeOf(empty.blockHex) });
    ok("a coinbase with no nonempty devnet-name commitment is refused", r.ok === false);
  }

  // the real block still passes, and the detail says what was actually checked
  {
    const r = verifyCheckpointRecognition(signed, { coreNode: minedCoreNode });
    ok("the mined full block passes every named check", r.ran === true && r.ok === true);
    ok("the detail reports the merkle-bound name commitment rather than asserting it",
       /devnet-name commitment in a coinbase bound by the header's merkle root/.test(r.detail));
  }
}

// MAJOR: hex that Buffer.from would silently truncate must not read as verified evidence.
// Reproduced: rawBytes "zz" decoded to an EMPTY buffer, and with the committed and transition
// hashes both set to the hash of empty bytes the verifier reported success over evidence it had
// never read.
{
  const env = JSON.parse(JSON.stringify(signed));
  const emptyHash = sha256(Buffer.alloc(0)).toString("hex");
  const row = env.coverage.platformLedger[0];
  row.txs[0].rawBytes = "zz";
  row.txs[0].transitionHash = emptyHash;
  for (const slot of env.slots) {
    for (const hop of slot.ownershipChain) hop.transitionHash = emptyHash;
  }
  const r = verifyTransitionHashes(env);
  ok("malformed hex evidence is refused rather than read as empty bytes",
     r.ok === false && /even-length lowercase hex/.test(r.reason));
}

// ---------------------------------------------------------------------------
// verifyCoreWalk (step 4). Two cases, and the FIRST one is the important one: the shipped
// vectors carry placeholder blobs by design, so a verifier that reported success against them
// would be claiming a duty it never performed, which is the defect this project has now found
// three times. It must REFUSE.
// ---------------------------------------------------------------------------
{
  const { verifyCoreWalk } = require("./runtimeVerifiers.cjs");
  const {
    parseMnListDiff, computeListRoot, readCbTxPayload,
  } = require("./mnListDiffCodec.cjs");

  // (1) placeholder evidence is refused, and the reason names the codec rather than being vague
  {
    const shipped = JSON.parse(fs.readFileSync(
      path.join(__dirname, "..", "..", "..", "docs", "schema", "vectors", "positive_minimal.json"),
      "utf8"));
    const r = verifyCoreWalk(shipped);
    ok("the shipped vector's placeholder blobs are REFUSED, not accepted",
       r.ran === true && r.ok === false);
    ok("the refusal names a pinned codec",
       /dash-p2p-mnlistdiff-v1|dash-smlentry-serialization-v1/.test(r.reason || ""));
  }

  // (2) REAL evidence: an envelope fragment built from the pinned wire capture. Here the checks
  // that can run must actually pass, so the fixture constrains the positive direction too.
  {
    const cap = JSON.parse(fs.readFileSync(
      path.join(__dirname, "fixtures", "p2p-mnlistdiff-regtest-2026-07-27.json"), "utf8"));
    const raw = Buffer.from(cap.payloadHex, "hex");
    const diff = parseMnListDiff(raw, { protocolVersion: cap.protocolVersionOffered });
    const payload = readCbTxPayload(diff.cbTx);
    const height = payload.height;
    const outputs = diff.cbTx.vout.map((o) => ({
      script: o.script, amountDuffs: o.valueDuffs, outputIndex: o.index,
    }));
    const env = {
      // the capture is a diff from block 1, whose list is empty, so the base seeds as empty
      basePackage: { kind: "pre-dml", baseBlock: { height: height - 1, blockHash: diff.baseBlockHash } },
      coreHeaderChain: cap.blockHeaderRaw,
      lifecycle: { observedThroughHeight: height },
      coreAuditRange: { fromHeight: height, toHeight: height },
      validatedChainLock: { height: height + 10 },
      coverage: {
        listWalk: [{
          height, blockHash: diff.blockHash,
          protxDiffRaw: cap.payloadHex,
          cbTxRaw: diff.cbTx.raw,
          cbTxInclusionProof: "00",
          listRoot: computeListRoot(diff.mnList),
          targetNodeEntry: null, targetNodeState: "ABSENT",
        }],
        coreLedger: [{
          height, blockHash: diff.blockHash,
          coinbase: { kind: "available", txRaw: diff.cbTx.raw, inclusionProof: "00", outputs },
        }],
      },
    };
    const r = verifyCoreWalk(env, { protocolVersion: cap.protocolVersionOffered });
    ok("real evidence: the recomputed list root matched the coinbase commitment",
       r.checks && r.checks.listRootPerHeight && r.checks.listRootPerHeight.passed === true);
    ok("real evidence: the diff chain is continuous from the base block",
       r.checks.diffChainContinuity.passed === true);
    ok("real evidence: the coinbase outputs were DERIVED from txRaw, not trusted",
       r.checks.coinbaseOutputsDerived.passed === true);
    ok("real evidence: the two ledgers agree at the shared height",
       r.checks.oneChainTwoLedgers.passed === true);
    ok("real evidence: the coverage interval holds", r.checks.coverageInterval.passed === true);
    ok("what it PROVED is reported, not just what it lacks", /list root/.test(r.proved || ""));

    // AND YET IT IS NOT ok: the endpoint ChainLock check has not run, so the component cannot be
    // claimed. This is the property that the last three rounds' must-fixes all violated.
    ok("passing checks do NOT add up to a claim while a named duty is outstanding",
       r.ran === false && r.ok === false);
    ok("the outstanding duty is named", /ChainLock/.test(r.blockedOn || ""));

    // and a real defect in that same evidence is caught rather than smoothed over
    const altered = JSON.parse(JSON.stringify(env));
    altered.coverage.listWalk[0].listRoot = "00".repeat(32);
    const t = verifyCoreWalk(altered, { protocolVersion: cap.protocolVersionOffered });
    ok("an asserted listRoot that is not the recomputed one is refused",
       t.ok === false && /asserted listRoot/.test(t.reason || ""));

    const altered2 = JSON.parse(JSON.stringify(env));
    altered2.coverage.coreLedger[0].coinbase.outputs[0].amountDuffs = "1";
    const t2 = verifyCoreWalk(altered2, { protocolVersion: cap.protocolVersionOffered });
    ok("a coinbase output array that txRaw does not produce is refused",
       t2.ok === false && /not what txRaw parses to/.test(t2.reason || ""));

    const altered3 = JSON.parse(JSON.stringify(env));
    altered3.basePackage.baseBlock.blockHash = "11".repeat(32);
    const t3 = verifyCoreWalk(altered3, { protocolVersion: cap.protocolVersionOffered });
    ok("a walk that does not continue the base block is refused",
       t3.ok === false && /breaking the chain/.test(t3.reason || ""));
  }

  // (3) no attestation may be minted for a component whose verifier did not complete
  {
    const runs = runVerifiers(signed, { coreNode: minedCoreNode });
    ok("verifyCoreWalk mints NO attestation while its duty is outstanding",
       !runs.attestations.some((a) => a.verifier === "verifyCoreWalk"));
  }
}

// ---------------------------------------------------------------------------
// THE DELTA CASE (round 6, MAJOR). Every earlier fixture descended from one capture whose base is
// height 1 with an empty list, so that single diff carried the WHOLE list and the ordinary case
// never arose. This builds a real delta by splicing the captured payload: one of its three entries
// is moved into the BASE list, and the row's diff carries only the other two. The resulting list is
// still the same three, so the coinbase commitment is unchanged and the root must still reproduce.
// Computing the root over the delta alone yields a different value, so this fixture fails against
// the pre-round-6 code.
// ---------------------------------------------------------------------------
{
  const { verifyCoreWalk } = require("./runtimeVerifiers.cjs");
  const {
    parseMnListDiff, computeListRoot, readCbTxPayload,
  } = require("./mnListDiffCodec.cjs");

  const cap = JSON.parse(fs.readFileSync(
    path.join(__dirname, "fixtures", "p2p-mnlistdiff-regtest-2026-07-27.json"), "utf8"));
  const raw = Buffer.from(cap.payloadHex, "hex");
  const whole = parseMnListDiff(raw, { protocolVersion: cap.protocolVersionOffered });
  const payload = readCbTxPayload(whole.cbTx);
  const height = payload.height;

  // splice: drop the FIRST entry from mnList and drop the count from 3 to 2
  const first = whole.mnList[0];
  const at = raw.indexOf(first.raw);
  const entriesEnd = at + whole.mnList.reduce((n, e) => n + e.raw.length, 0);
  const deltaRaw = Buffer.concat([
    raw.subarray(0, at - 1), Buffer.from([whole.mnList.length - 1]),
    ...whole.mnList.slice(1).map((e) => e.raw),
    raw.subarray(entriesEnd),
  ]);
  const delta = parseMnListDiff(deltaRaw, { protocolVersion: cap.protocolVersionOffered });
  ok("the spliced delta carries two of the three entries", delta.mnList.length === 2);
  ok("the delta's own coinbase still commits the THREE-entry root",
     readCbTxPayload(delta.cbTx).merkleRootMNList === payload.merkleRootMNList);
  ok("a root over the delta ALONE is not the committed root, which is the defect's signature",
     computeListRoot(delta.mnList) !== payload.merkleRootMNList);

  const outputs = delta.cbTx.vout.map((o) => ({
    script: o.script, amountDuffs: o.valueDuffs, outputIndex: o.index,
  }));
  const env = {
    // the moved entry is retained at the base, exactly as a rooted base package retains it
    basePackage: {
      kind: "rooted", baseBlock: { height: height - 1, blockHash: delta.baseBlockHash },
      smlEntries: [first.raw.toString("hex")],
    },
    coreHeaderChain: cap.blockHeaderRaw,
    lifecycle: { observedThroughHeight: height },
    coreAuditRange: { fromHeight: height, toHeight: height },
    validatedChainLock: { height: height + 10 },
    coverage: {
      listWalk: [{
        height, blockHash: delta.blockHash, protxDiffRaw: deltaRaw.toString("hex"),
        cbTxRaw: delta.cbTx.raw, cbTxInclusionProof: "00",
        listRoot: payload.merkleRootMNList,
        targetNodeEntry: null, targetNodeState: "ABSENT",
      }],
      coreLedger: [{
        height, blockHash: delta.blockHash,
        coinbase: { kind: "available", txRaw: delta.cbTx.raw, inclusionProof: "00", outputs },
      }],
    },
  };
  const r = verifyCoreWalk(env, { protocolVersion: cap.protocolVersionOffered });
  ok("THE DELTA ROW NOW REPRODUCES THE COMMITTED ROOT after applying it to the base list",
     r.checks && r.checks.listRootPerHeight && r.checks.listRootPerHeight.passed === true);
  ok("the base list was seeded from the rooted package",
     r.checks.baseListSeeded.passed === true && /1 entry/.test(r.checks.baseListSeeded.detail));
  ok("the resulting list holds all three entries again",
     /3 entry\(ies\)/.test(r.checks.listRootPerHeight.detail));

  // and the converse round 6 reported: a full list relabelled as a delta from a DIFFERENT base
  // must no longer pass, because the base list is now read
  const wrongBase = JSON.parse(JSON.stringify(env));
  wrongBase.basePackage.smlEntries = [whole.mnList[1].raw.toString("hex")];
  const w = verifyCoreWalk(wrongBase, { protocolVersion: cap.protocolVersionOffered });
  ok("a base list holding the WRONG entry is refused rather than passing",
     w.ok === false && /list root/.test(w.reason || ""));

  // a deletion naming an entry the list does not hold is malformed evidence, not a no-op
  const badDelete = JSON.parse(JSON.stringify(env));
  badDelete.basePackage.smlEntries = [];
  const b = verifyCoreWalk(badDelete, { protocolVersion: cap.protocolVersionOffered });
  ok("an empty base under a delta row is refused, since the root cannot reproduce",
     b.ok === false);
}

// ---------------------------------------------------------------------------
// ROUND 6 MUST-FIX. Three shapes that Dash consensus rejects and this verifier accepted, each
// returning ran:true ok:true with detail claiming the block had been authenticated, and each
// therefore minting a recognition attestation. Third round on this one verifier, same class every
// time: a duty reported as discharged that was not performed.
// ---------------------------------------------------------------------------
{
  const nodeOf = (hex) => ({ getBlockHexByHeight: () => hex });
  const patch = (hex, mutate) => { const b = Buffer.from(hex, "hex"); mutate(b); return b.toString("hex"); };

  // (1) a target ABOVE the network limit. This one has to be MINED AT that target and then
  // committed and re-signed, because simply editing nBits in a good block changes the header
  // hash, and the verifier would refuse at the hash comparison without ever reaching the limit
  // check. The first version of this fixture did exactly that and passed for the wrong reason,
  // which is the vacuous-fixture pattern this review cycle keeps finding.
  const envAtTarget = (nBits) => {
    const blk = mineHeightOne(signed.network.coreGenesisBlockHash, "tegara-fixture-devnet", nBits);
    const env = JSON.parse(JSON.stringify(signed));
    env.network = { ...env.network, coreDevnetGenesisBlockHash: blk.displayHash };
    const id = coreChainIdentityHash(env.network);
    for (const cp of env.checkpoints) {
      const pl = Buffer.from(cp.signedPayloadBytes, "hex");
      v2DomainTag(id, rawPub).copy(pl, 4);
      const dg = sha256(pl);
      cp.signedPayloadBytes = pl.toString("hex");
      cp.checkpointId = dg.toString("hex");
      cp.signerPublicKey = rawPub.toString("hex");
      cp.signature = crypto.sign(null, dg, privateKey).toString("hex");
    }
    return { env, blk };
  };
  {
    // devnet and regtest cap at ~uint256(0)>>1; 0x2100ffff sits above it and below 2^256
    const { env, blk } = envAtTarget(0x2100ffff);
    const r = verifyCheckpointRecognition(env, { coreNode: nodeOf(blk.blockHex) });
    ok("a target above the network proof-of-work limit is refused", r.ok === false);
    ok("the refusal reaches the LIMIT check, not the hash comparison",
       /proof-of-work limit/.test(r.reason || ""));
  }
  {
    const { env, blk } = envAtTarget(0x2300ffff);   // exponent 35, overflows the compact form
    const r = verifyCheckpointRecognition(env, { coreNode: nodeOf(blk.blockHex) });
    ok("an nBits that overflows the compact form is refused",
       r.ok === false && /overflows/.test(r.reason || ""));
  }

  // (2) a one-input transaction whose prevout is NOT null is not a coinbase
  {
    const bad = patch(mined.blockHex, (b) => {
      // the coinbase begins after the 80-byte header and the one-byte transaction count;
      // its prevout hash sits after version(4) and the input count(1)
      b[80 + 1 + 4 + 1] = 0x01;      // make the prevout hash non-zero
    });
    const r = verifyCheckpointRecognition(signed, { coreNode: nodeOf(bad) });
    ok("a transaction spending a non-null prevout is refused as not a coinbase",
       r.ok === false && /null prevout/.test(r.reason || ""));
  }

  // (3) a valid one-transaction block followed by one extra byte
  {
    const bad = mined.blockHex + "00";
    const r = verifyCheckpointRecognition(signed, { coreNode: nodeOf(bad) });
    ok("a block with trailing bytes after its single transaction is refused",
       r.ok === false && /trailing byte/.test(r.reason || ""));
  }

  // (4) NON-CANONICAL COMPACTSIZE IS OUTSIDE THE WIRE DOMAIN (round 8, MUST-FIX, a soundness-review finding).
  // The height-one parser used to keep its own CompactSize reader, which applied neither the
  // canonical-width rule nor MAX_SIZE. A wider-than-needed encoding parsed cleanly here while
  // Dash Core refuses the same bytes in ReadCompactSize, so the verifier could complete the duty
  // for a block the network would not accept. Both cases below assert the REASON, because a
  // refusal from an earlier check would not show that the reader is the one doing the work.
  {
    // the BLOCK transaction count, `01` widened to `fd0100`. The header is untouched, so the
    // block hash, the parent, the proof-of-work limit and the merkle binding all still pass and
    // the only thing left to refuse is the encoding.
    const widened = mined.blockHex.slice(0, 160) + "fd0100" + mined.blockHex.slice(162);
    const r = verifyCheckpointRecognition(signed, { coreNode: nodeOf(widened) });
    ok("a non-canonical block transaction count is refused", r.ok === false);
    ok("that refusal reaches the CompactSize rule, not an earlier check",
       /non-canonical CompactSize/.test(r.reason || ""));
  }
  {
    // a count INSIDE the transaction, the scriptSig length. This moves the coinbase bytes, so the
    // txid, the merkle root, the mined header and the chain identity all move with it and the
    // checkpoint has to be re-signed for the case to reach the parser at all.
    const blk = mineHeightOne(signed.network.coreGenesisBlockHash, "tegara-fixture-devnet",
                              0x207fffff, (cb) => {
      const sl = cb[41];        // version(4) + input count(1) + prevout(36) = 41
      return Buffer.concat([cb.subarray(0, 41), Buffer.from([0xfd, sl, 0x00]), cb.subarray(42)]);
    });
    const env = JSON.parse(JSON.stringify(signed));
    env.network = { ...env.network, coreDevnetGenesisBlockHash: blk.displayHash };
    const id = coreChainIdentityHash(env.network);
    for (const cp of env.checkpoints) {
      const pl = Buffer.from(cp.signedPayloadBytes, "hex");
      v2DomainTag(id, rawPub).copy(pl, 4);
      const dg = sha256(pl);
      cp.signedPayloadBytes = pl.toString("hex");
      cp.checkpointId = dg.toString("hex");
      cp.signerPublicKey = rawPub.toString("hex");
      cp.signature = crypto.sign(null, dg, privateKey).toString("hex");
    }
    const r = verifyCheckpointRecognition(env, { coreNode: nodeOf(blk.blockHex) });
    ok("a non-canonical scriptSig length inside the coinbase is refused", r.ok === false);
    ok("that refusal also reaches the CompactSize rule",
       /non-canonical CompactSize/.test(r.reason || ""));
  }

  // and none of the three may mint an attestation
  {
    const bad = mined.blockHex + "00";
    const runs = runVerifiers(signed, { coreNode: nodeOf(bad) });
    ok("a refused height-one block mints NO recognition attestation",
       !runs.attestations.some((a) => a.verifier === "verifyCheckpointRecognition"));
  }

  // the genuine block still passes, so the checks refuse the wrong thing and not everything
  {
    const r = verifyCheckpointRecognition(signed, { coreNode: minedCoreNode });
    ok("the real mined block still passes every check", r.ran === true && r.ok === true);
  }
}

// ---------------------------------------------------------------------------
// ROUND 6 MAJOR: the coinbase carrying the list-root commitment was never authenticated. Both
// retained proofs went unused, so the walk read a transaction out of the diff and treated its
// payload as a value Dash Core wrote. Flipping one byte of the tree left every check passing.
// ---------------------------------------------------------------------------
{
  const { verifyCoreWalk } = require("./runtimeVerifiers.cjs");
  const {
    parseMnListDiff, computeListRoot, readCbTxPayload, extractMerkleMatches, indexHeaderChain,
  } = require("./mnListDiffCodec.cjs");
  const cap = JSON.parse(fs.readFileSync(
    path.join(__dirname, "fixtures", "p2p-mnlistdiff-regtest-2026-07-27.json"), "utf8"));
  const raw = Buffer.from(cap.payloadHex, "hex");
  const d = parseMnListDiff(raw, { protocolVersion: cap.protocolVersionOffered });
  const pl = readCbTxPayload(d.cbTx);
  const outputs = d.cbTx.vout.map((o) => ({
    script: o.script, amountDuffs: o.valueDuffs, outputIndex: o.index,
  }));
  const envWith = (payloadHex) => ({
    basePackage: { kind: "pre-dml", baseBlock: { height: pl.height - 1, blockHash: d.baseBlockHash } },
    coreHeaderChain: cap.blockHeaderRaw,
    lifecycle: { observedThroughHeight: pl.height },
    coreAuditRange: { fromHeight: pl.height, toHeight: pl.height },
    validatedChainLock: { height: pl.height + 10 },
    coverage: {
      listWalk: [{
        height: pl.height, blockHash: d.blockHash, protxDiffRaw: payloadHex,
        cbTxRaw: d.cbTx.raw, cbTxInclusionProof: "00",
        listRoot: computeListRoot(d.mnList), targetNodeEntry: null, targetNodeState: "ABSENT",
      }],
      coreLedger: [{
        height: pl.height, blockHash: d.blockHash,
        coinbase: { kind: "available", txRaw: d.cbTx.raw, inclusionProof: "00", outputs },
      }],
    },
  });

  // THE BINDING ITSELF, against the REAL retained header
  {
    const proof = extractMerkleMatches(d.cbTxMerkleTree);
    const header = indexHeaderChain(cap.blockHeaderRaw).get(d.blockHash);
    ok("the retained header hashes to the block the diff names", Boolean(header));
    ok("the coinbase proof yields the header's own merkle root",
       proof.merkleRoot === header.merkleRoot);
    ok("the coinbase txid is among the transactions its proof establishes",
       proof.matched.includes(d.cbTx.txid));
    const r = verifyCoreWalk(envWith(cap.payloadHex), { protocolVersion: cap.protocolVersionOffered });
    ok("the walk reports the coinbase as authenticated, not assumed",
       r.checks.coinbaseAuthenticated.passed === true);
    ok("what it proved now says the coinbase was proven into its block",
       /proven into its block/.test(r.proved || ""));
  }

  // THE REVIEWER'S REPRODUCTION: one flipped byte in the partial merkle tree
  {
    const t = Buffer.from(raw);
    t[raw.indexOf(Buffer.from(d.cbTxMerkleTree.hashes[0], "hex").reverse())] ^= 0xff;
    const r = verifyCoreWalk(envWith(t.toString("hex")), { protocolVersion: cap.protocolVersionOffered });
    ok("a flipped byte in the coinbase proof is REFUSED, where it used to pass",
       r.ok === false && /merkle root/.test(r.reason || ""));
  }

  // a record with no header for the block it names cannot authenticate anything
  {
    const env = envWith(cap.payloadHex);
    env.coreHeaderChain = "00".repeat(80);
    const r = verifyCoreWalk(env, { protocolVersion: cap.protocolVersionOffered });
    ok("a header chain holding no header for the row's block is refused",
       r.ok === false && /no header hashing to/.test(r.reason || ""));
  }
  {
    const env = envWith(cap.payloadHex);
    env.coreHeaderChain = "00".repeat(79);
    const r = verifyCoreWalk(env, { protocolVersion: cap.protocolVersionOffered });
    ok("a header chain that is not a whole number of headers is refused",
       r.ok === false && /80-byte headers/.test(r.reason || ""));
  }

  // A DASH BLOCK HASH IS X11. The retained header proves it: under sha256d it hashes to
  // something else entirely, and only X11 reproduces the block hash the node reports.
  {
    const { blockHashOf } = require("./mnListDiffCodec.cjs");
    const hdr = Buffer.from(cap.blockHeaderRaw, "hex");
    ok("X11 of the retained header IS the block hash", blockHashOf(hdr) === d.blockHash);
    const sha256d = crypto.createHash("sha256").update(
      crypto.createHash("sha256").update(hdr).digest()).digest();
    ok("sha256d of the same header is NOT the block hash, which is the trap",
       Buffer.from(sha256d).reverse().toString("hex") !== d.blockHash);
  }
}

// ---------------------------------------------------------------------------
// ROUND 6 MINOR: two correction claims had code but only partial fixtures. Strict hex was driven
// through ONE field, and the two named type-before-order corrections had no focused case at all.
// A claim with one witness is a claim about that witness.
// ---------------------------------------------------------------------------
{
  // STRICT HEX, through every field that decodes it. Buffer.from(x,"hex") truncates silently, so
  // each of these would otherwise read as short or empty bytes rather than as malformed evidence.
  const bad = "zz";
  {
    const env = JSON.parse(JSON.stringify(signed));
    env.checkpointAuthority = { publicKey: bad };
    const r = verifyCheckpointRecognition(env);
    ok("malformed hex in the checkpoint AUTHORITY key is refused", r.ok === false);
  }
  {
    const env = JSON.parse(JSON.stringify(signed));
    env.checkpoints[0].signedPayloadBytes = bad;
    const r = verifyCheckpointRecognition(env);
    ok("malformed hex in a checkpoint PAYLOAD is refused", r.ok === false);
  }
  {
    const env = JSON.parse(JSON.stringify(signed));
    env.checkpoints[0].signature = bad;
    const r = verifyCheckpointRecognition(env);
    ok("malformed hex in a checkpoint SIGNATURE is refused", r.ok === false);
  }
  {
    const env = JSON.parse(JSON.stringify(signed));
    env.network = { ...env.network, coreGenesisBlockHash: bad };
    const r = verifyCheckpointRecognition(env);
    ok("malformed hex in the NETWORK identity is refused", r.ok === false);
  }
  {
    const r = verifyCheckpointRecognition(signed, { coreNode: { getBlockHexByHeight: () => bad } });
    ok("malformed hex from the Core node is refused", r.ok === false);
  }
  {
    // The ProRegTx branch runs ONLY in FIRST_APPEARANCE mode, and the shipped envelope is
    // RANGE_LOCAL, so the first version of this case set the field on a path that never
    // executed and the verifier correctly returned success. It failed loudly, which is how a
    // fixture should behave when it is aimed at the wrong place; the mode is set here so the
    // branch is actually reached.
    const env = JSON.parse(JSON.stringify(signed));
    env.basePackage.kind = "rooted";
    env.basePackage.baseMode = "FIRST_APPEARANCE";
    env.basePackage.firstAppearance = { ...(env.basePackage.firstAppearance || {}), proRegTxRaw: bad };
    const r = verifyIdentifierConversion(env);
    ok("malformed hex in the ProRegTx bytes is refused",
       r.ok === false && /even-length lowercase hex/.test(r.reason || ""));
    // and the branch really is the one under test: well-formed bytes reach the txid comparison
    const env2 = JSON.parse(JSON.stringify(env));
    env2.basePackage.firstAppearance.proRegTxRaw = "00".repeat(40);
    const r2 = verifyIdentifierConversion(env2);
    ok("well-formed ProRegTx bytes reach the identity comparison instead",
       r2.ok === false && /is not the pool proTxHash/.test(r2.reason || ""));
  }

  // TYPE BEFORE ORDER, for the two corrections the charter named and no fixture drove
  {
    const { recognizeAt } = require("./auditSeam.cjs");
    const epoch = (from, to, act) => ({
      epochRange: { fromCoreHeight: from, toCoreHeight: to },
      extractedBinding: {
        bindings: [{ proTxHash: "aa", slotIndex: 0, contractId: "c", poolId: "p",
                     activationCoreHeight: act }],
        books: [],
      },
    });
    const ctx = (cps, lifecycle) => ({
      checkpoints: cps, poolProTxHash: "aa", poolL1SlotIndex: 0, contractId: "c", poolId: "p",
      lifecycle: lifecycle || { suspensions: [], terminalHeight: null }, baseHeight: 1,
    });
    let refused = false;
    try { recognizeAt(250, ctx([epoch(100, 299, "abc")])); } catch (e) {
      refused = /malformed activationCoreHeight/.test(e.message);
    }
    ok("a malformed activationCoreHeight is refused rather than compared", refused);

    const { deriveEligibility } = require("./rewardEntitlement.cjs");
    let refused2 = false;
    try {
      deriveEligibility({
        stateAtHMinus1: "ABSENT", listRoot: null, hMinus1: 999,
        journal: { terminalHeight: null, transitions: [{ from: "ABSENT", height: "abc" }] },
        base: { kind: "pre-dml" },
      });
    } catch (e) { refused2 = /transition 0 has a malformed height/.test(e.message); }
    ok("a malformed journal transition height is refused rather than compared", refused2);
  }
}

console.log(`runtimeVerifiersTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
