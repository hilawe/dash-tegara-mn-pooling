/**
 * Offline battery for C1's two project-side pieces: the finalized-epoch
 * message module (patches/finalizedEpochs-proto.js) and the wrapper
 * (patches/getFinalizedEpochInfos.js), each mounted as a NEW file in the
 * SDK tree.
 *
 * WHAT THIS SUITE ESTABLISHES, in three layers:
 *
 *   WIRE LAYER: the request ENCODING equals hand-computed golden bytes
 *   (binding the field numbers and wire types to the pinned proto, which a
 *   self-consistent roundtrip alone cannot do), and hand-computed golden
 *   response bytes DECODE to the exact expected members, with every uint64
 *   figure surfacing as a decimal STRING (the stack's long_type_string
 *   convention, so no figure rounds through a JS number).
 *
 *   COMPOSITION LAYER (the discovery unit's composition-binding lesson):
 *   buildRequest's refusals, classifyResponse's match-what-was-requested
 *   rule, and resolveAnswer's closed status grammar are driven directly,
 *   with the piece-3 verifier and the second verification stage injected as
 *   fakes, asserting that figures appear ONLY under unproved-plain (stated)
 *   or proved (both stages passed), and that no path answers proved without
 *   the verifier's root hash surviving the Tenderdash check.
 *
 *   TEXT LAYER: both mount lines present in the probe launcher.
 *
 * WIDTH, STATED: the default export's PLAIN and CARRIER assemblies are
 * driven end to end over a fake transport; the PROVED assembly needs
 * real cryptography and is live-probe territory
 * (e2FinalizedEpochsProbeRun.mjs). The devnet's implementation of the
 * route is the probe's claim, not this suite's.
 *
 * SKIPS: a tree without the patch files (the curated public export) skips,
 * counted and printed. A tree WITH the patches but WITHOUT the installed
 * SDK sources FAILS rather than skips (the vacuous-pass rule).
 */
const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");

const { runnerSource, skipNote } = require("./runnerSource.cjs");
let passed = 0, failed = 0, skipped = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error("FAIL:", name, "(no error)"); }
  catch (e) { ok(name, re.test(String(e.message))); }
};
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error("FAIL:", name, "(no rejection)"); }
  catch (e) { ok(name, re.test(String(e.message))); }
};
const hex = (u8) => Buffer.from(u8).toString("hex");

const ROOT = path.join(__dirname, "..", "..");
// the patch DIRECTORY is overridable so the mutation harness can stage
// mutated copies in scratch space instead of editing the live tree (the
// destructive-operations rule); the default is the real patches directory
// and the launcher text checks always read the live launcher
const PATCH_DIR = process.env.E2_FEG_PATCH_DIR || path.join(ROOT, "patches");
const PATCH_PROTO = path.join(PATCH_DIR, "finalizedEpochs-proto.js");
const PATCH_WRAPPER = path.join(PATCH_DIR, "getFinalizedEpochInfos.js");
const SDK = path.join(ROOT, "node_modules", "dash-platform-sdk");

(async () => {
  const protoHere = fs.existsSync(PATCH_PROTO), wrapperHere = fs.existsSync(PATCH_WRAPPER);
  if (!protoHere && !wrapperHere) {
    // the skip is legitimate ONLY for the default directory: an
    // override pointing at an empty directory would otherwise turn
    // the whole gate into a counted skip while the real patches sit in
    // the tree unexamined)
    if (process.env.E2_FEG_PATCH_DIR) {
      failed++;
      console.error("FAIL: E2_FEG_PATCH_DIR points at a directory with neither patch file; the override is a mutation-harness seam, never a skip route");
      console.log(`e2FinalizedEpochsGateTest: ${passed} passed, ${failed} failed` + (skipped ? `, ${skipped} skipped (counted, never folded into passes)` : ""));
      process.exitCode = 1;
      return;
    }
    skipped++;
    console.log(`e2FinalizedEpochsGateTest: ${passed} passed, ${failed} failed, ${skipped} skipped (patch files absent; the curated export carries no patches)`);
    return;
  }
  // ONE patch present and the other missing is a defect, never a skip
  // (the all-or-nothing skip let a half-present unit pass the
  // package chain as a counted skip)
  if (!protoHere || !wrapperHere) {
    failed++;
    console.error(`FAIL: exactly one of the two patch files exists (proto=${protoHere} wrapper=${wrapperHere}); a partial unit must not skip`);
    console.log(`e2FinalizedEpochsGateTest: ${passed} passed, ${failed} failed`);
    process.exitCode = 1;
    return;
  }
  if (!fs.existsSync(path.join(SDK, "proto", "generated", "platform.js"))) {
    failed++;
    console.error("FAIL: the patches exist but the installed SDK sources do not; this suite would examine nothing (vacuous-pass rule)");
    console.log(`e2FinalizedEpochsGateTest: ${passed} passed, ${failed} failed`);
    process.exitCode = 1;
    return;
  }

  // ---- text layer: the probe launcher mounts both pieces, on LIVE
  // mount lines (an unanchored substring also matched the same
  // string inside a comment, so commenting both mounts out passed) ----
  const launcher = fs.readFileSync(path.join(ROOT, "run_finalized_probe.sh"), "utf8");
  ok("the probe launcher mounts the message module at its SDK path on a live -v line",
    /^\s*-v "\$PWD\/patches\/finalizedEpochs-proto\.js:\/app\/node_modules\/dash-platform-sdk\/proto\/generated\/platformFinalizedEpochs\.js:ro"$/m.test(launcher));
  ok("the probe launcher mounts the wrapper at its SDK path on a live -v line",
    /^\s*-v "\$PWD\/patches\/getFinalizedEpochInfos\.js:\/app\/node_modules\/dash-platform-sdk\/src\/node\/finalizedEpochs\.js:ro"$/m.test(launcher));
  const probeSrc = runnerSource("e2FinalizedEpochsProbeRun.mjs");
  if (probeSrc === null) { skipped += 1; console.log(skipNote("e2FinalizedEpochsProbeRun.mjs", "the probe-runner sweep")); } else {
  ok("the probe runner carries the in-container collision preflight over the stock node index",
    probeSrc.includes("src/node/index.js") && /finalizedEpochs\|FinalizedEpoch/.test(probeSrc)
    && probeSrc.includes("must be reconsidered"));
  ok("the launcher runs the MOUNT-FREE image preflight over both targets on a live line (the mounts hide whatever sits at their targets, so only a mount-free container can answer the collision question)",
    /^\$DOCKER run --rm tegara-sdk node -e .*platformFinalizedEpochs\.js.*src\/node\/finalizedEpochs\.js.*$/m.test(launcher));
  ok("the runner's pin constants and checker wiring are present in text (A TRIPWIRE, not a behavioral proof; the checker's BEHAVIOR is bound executably in feivAdapterTest, and the runner's use of it only a live run shows)",
    probeSrc.includes('const EXPECTED_SDK = "1.4.0"') && probeSrc.includes('const VERIFIED_DAPI_GRPC = ["4.0.0", "4.1.1"]')
    && probeSrc.includes("checkFinalizedEpochsProto") && probeSrc.includes("re-derive before probing"));
  }

  // ---- the copies under test: piece 1 must sit at its REAL mount name so
  // the wrapper's relative import resolves; if the SDK ever ships that
  // file itself, this FAILS so the patch gets reconsidered, never
  // silently overwritten ----
  const protoTarget = path.join(SDK, "proto", "generated", "platformFinalizedEpochs.js");
  const wrapperTarget = path.join(SDK, "src", "node", "__patchUnderTest_finalizedEpochs.mjs");
  // BOTH real mount targets are collision-checked in the HOST tree
  // (only the message module's target was). WIDTH, stated
  //: the mount lands in the IMAGE's tree, which installs from
  // a caret range and can drift from the host tree, so the probe runner
  // carries its own in-container preflight (the stock node index, which
  // is not mounted over, must not name a finalized-epochs route) and
  // that preflight is asserted below in the text layer and executed by
  // every live probe run.
  for (const [label, target] of [["proto/generated/platformFinalizedEpochs.js", protoTarget],
    ["src/node/finalizedEpochs.js", path.join(SDK, "src", "node", "finalizedEpochs.js")]]) {
    if (fs.existsSync(target)) {
      failed++;
      console.error(`FAIL: the SDK tree already carries ${label}; the addition patch would shadow a real file and must be reconsidered`);
      console.log(`e2FinalizedEpochsGateTest: ${passed} passed, ${failed} failed`);
      process.exitCode = 1;
      return;
    }
  }
  fs.copyFileSync(PATCH_PROTO, protoTarget);
  fs.copyFileSync(PATCH_WRAPPER, wrapperTarget);
  try {
    const proto = await import(pathToFileURL(protoTarget).href);
    const wrap = await import(pathToFileURL(wrapperTarget).href);
    const platform = await import(pathToFileURL(path.join(SDK, "proto", "generated", "platform.js")).href);

    // ---- wire layer ----
    const req = wrap.buildRequest({ startEpoch: 5, endEpoch: 9, prove: true });
    ok("the request encodes to the golden bytes (field numbers and wire types bound to the pinned proto)",
      hex(proto.GetFinalizedEpochInfosRequest.toBinary(req)) === "0a0a08051001180920012801");
    ok("both inclusive flags are set on the built request",
      req.version.v0.startEpochIndexIncluded === true && req.version.v0.endEpochIndexIncluded === true);

    // the golden EPOCHS response populates EVERY FinalizedEpochInfo field
    // (1 through 13) and every ResponseMetadata field, hand-computed, so
    // each field number and each uint64's string representation is bound
    // in BOTH directions (a three-field golden left fields 2
    // through 8 and 10 through 12 unbound)
    const goldenResponse = "0a3e0a290a270807106418142005" + "29000000000000f83f"
      + "3009381c402148e8075002580360046a050a01ab10031a11082a1005180320e8072801320470696e58";
    const goldenInfo = { number: 7, firstBlockHeight: "100", firstCoreBlockHeight: 20,
      firstBlockTime: "5", feeMultiplier: 1.5, protocolVersion: 9, totalBlocksInEpoch: "28",
      nextEpochStartCoreBlockHeight: 33, totalProcessingFees: "1000",
      totalDistributedStorageFees: "2", totalCreatedStorageFees: "3", coreBlockRewards: "4",
      blockProposers: [{ proposerId: new Uint8Array([0xab]), blockCount: 3 }] };
    const goldenMeta = { height: "42", coreChainLockedHeight: 5, epoch: 3, timeMs: "1000",
      protocolVersion: 1, chainId: "pinX" };
    const goldenObj = proto.GetFinalizedEpochInfosResponse.create({ version: { oneofKind: "v0", v0: {
      result: { oneofKind: "epochs", epochs: { finalizedEpochInfos: [goldenInfo] } },
      metadata: goldenMeta } } });
    ok("the fully-populated response ENCODES to the golden bytes",
      hex(proto.GetFinalizedEpochInfosResponse.toBinary(goldenObj)) === goldenResponse);
    const resp = proto.GetFinalizedEpochInfosResponse.fromBinary(Buffer.from(goldenResponse, "hex"));
    ok("the golden response decodes to v0 with an epochs result", resp.version.oneofKind === "v0" && resp.version.v0.result.oneofKind === "epochs");
    const gInfo = resp.version.v0.result.epochs.finalizedEpochInfos[0];
    ok("every info field decodes to its exact expected member (identity, all 13 fields)",
      JSON.stringify({ ...gInfo, blockProposers: gInfo.blockProposers.map((p) => ({ proposerId: hex(p.proposerId), blockCount: p.blockCount })) })
      === JSON.stringify({ ...goldenInfo, blockProposers: [{ proposerId: "ab", blockCount: 3 }] }));
    ok("every uint64 figure decodes as a decimal STRING",
      ["firstBlockHeight", "firstBlockTime", "totalBlocksInEpoch", "totalProcessingFees",
        "totalDistributedStorageFees", "totalCreatedStorageFees", "coreBlockRewards"]
        .every((k) => typeof gInfo[k] === "string"));
    ok("every metadata field decodes to its exact expected member",
      JSON.stringify(resp.version.v0.metadata) === JSON.stringify(goldenMeta)
      && typeof resp.version.v0.metadata.height === "string");

    // the golden PROOF response binds the result oneof's field 2 and the
    // generated Proof type's own fields as THIS route consumes them
    const goldenProofResponse = "0a1912130a04deadbeef1201111a012220022a013330041a02082a";
    const respP = proto.GetFinalizedEpochInfosResponse.fromBinary(Buffer.from(goldenProofResponse, "hex"));
    const gp = respP.version.v0.result;
    ok("the golden proof response decodes to the proof result (field 2) with every proof member",
      gp.oneofKind === "proof" && hex(gp.proof.grovedbProof) === "deadbeef"
      && hex(gp.proof.quorumHash) === "11" && hex(gp.proof.signature) === "22"
      && gp.proof.round === 2 && hex(gp.proof.blockIdHash) === "33" && gp.proof.quorumType === 4);

    // the carrier fixture carries EVERY proof member, so preservation is
    // checked for the whole message, not one sampled field
    const proofMsg = platform.Proof.create({ grovedbProof: new Uint8Array([1, 2, 3]),
      quorumHash: new Uint8Array([0x44]), signature: new Uint8Array([0x55]),
      round: 6, blockIdHash: new Uint8Array([0x66]), quorumType: 7 });
    ok("the service route is the stock Platform service name with the one method",
      proto.PlatformFinalizedEpochs.typeName === "org.dash.platform.dapi.v0.Platform"
      && proto.PlatformFinalizedEpochs.methods.length === 1
      && proto.PlatformFinalizedEpochs.methods[0].name === "getFinalizedEpochInfos");

    // ---- buildRequest refusals ----
    throws("a reversed interval refuses", () => wrap.buildRequest({ startEpoch: 9, endEpoch: 5, prove: true }), /reversed/);
    throws("a negative epoch refuses", () => wrap.buildRequest({ startEpoch: -1, endEpoch: 5, prove: true }), /not a uint32/);
    throws("a string epoch refuses (no coercion)", () => wrap.buildRequest({ startEpoch: "5", endEpoch: 9, prove: true }), /not a uint32/);
    throws("a fractional epoch refuses", () => wrap.buildRequest({ startEpoch: 1.5, endEpoch: 9, prove: true }), /not a uint32/);
    throws("an above-uint32 epoch refuses", () => wrap.buildRequest({ startEpoch: 0, endEpoch: 2 ** 32, prove: true }), /not a uint32/);
    throws("a non-boolean prove refuses (truthiness is not a request)", () => wrap.buildRequest({ startEpoch: 0, endEpoch: 2, prove: 1 }), /not a boolean/);

    // ---- classifyResponse: the result must match what was requested ----
    const v0Of = (result, metadata) => ({ version: { oneofKind: "v0", v0: { result, metadata } } });
    const md = platform.ResponseMetadata.create({ height: "9", chainId: "pinT" });
    const carrier = wrap.classifyResponse(v0Of({ oneofKind: "proof", proof: proofMsg }, md), { requestedProve: true });
    ok("a proof result under a proved request classifies as the carrier", carrier.kind === "proof-carrier");
    const plain = wrap.classifyResponse(v0Of({ oneofKind: "epochs", epochs: resp.version.v0.result.epochs }, md), { requestedProve: false });
    ok("an epochs result under a plain request classifies as plain", plain.kind === "plain" && plain.infos.length === 1);
    throws("a plain result under a PROVED request refuses (a downgraded answer is never served)",
      () => wrap.classifyResponse(v0Of({ oneofKind: "epochs", epochs: resp.version.v0.result.epochs }, md), { requestedProve: true }), /downgraded/);
    throws("a proof result under a PLAIN request refuses",
      () => wrap.classifyResponse(v0Of({ oneofKind: "proof", proof: proofMsg }, md), { requestedProve: false }), /not epochs/);
    throws("absent metadata refuses", () => wrap.classifyResponse(v0Of({ oneofKind: "proof", proof: proofMsg }, null), { requestedProve: true }), /no metadata/);
    throws("a non-v0 version refuses", () => wrap.classifyResponse({ version: { oneofKind: "v1" } }, { requestedProve: true }), /must be v0/);
    throws("a NON-BOOLEAN requestedProve refuses (undefined silently entered the plain branch)",
      () => wrap.classifyResponse(v0Of({ oneofKind: "proof", proof: proofMsg }, md), { requestedProve: undefined }), /not a boolean/);
    throws("EMPTY metadata refuses (a default-decoded metadata message passed the null check; provenance requires a chain id)",
      () => wrap.classifyResponse(v0Of({ oneofKind: "proof", proof: proofMsg }, platform.ResponseMetadata.create({ height: "9" })), { requestedProve: true }), /no chain id/);
    throws("an EMPTY grovedb proof refuses the carrier (an empty proof message reached the carrier status)",
      () => wrap.classifyResponse(v0Of({ oneofKind: "proof", proof: platform.Proof.create({}) }, md), { requestedProve: true }), /empty grovedb proof/);
    throws("a PARTIAL proof refuses the carrier (a nonempty grovedb proof beside empty quorum members is no more usable)",
      () => wrap.classifyResponse(v0Of({ oneofKind: "proof",
        proof: platform.Proof.create({ grovedbProof: new Uint8Array([1]) }) }, md), { requestedProve: true }), /empty quorum hash/);
    throws("a proof missing its signature refuses the carrier",
      () => wrap.classifyResponse(v0Of({ oneofKind: "proof",
        proof: platform.Proof.create({ grovedbProof: new Uint8Array([1]), quorumHash: new Uint8Array([2]),
          blockIdHash: new Uint8Array([3]) }) }, md), { requestedProve: true }), /empty signature/);

    // ---- resolveAnswer: the closed status grammar under injected fakes ----
    const range = { startEpoch: 0, endEpoch: 9 };
    const rPlain = await wrap.resolveAnswer(plain, { ...range, verifyProof: null });
    ok("the plain classification answers unproved-plain with mapped string figures",
      rPlain.status === "unproved-plain" && rPlain.epochs[0].number === 7
      && rPlain.epochs[0].totalProcessingFees === "1000" && typeof rPlain.epochs[0].totalProcessingFees === "string");
    const rCarrier = await wrap.resolveAnswer(carrier, { ...range, verifyProof: null });
    ok("the carrier without a verifier answers unverified-carrier and serves NO figures",
      rCarrier.status === "unverified-carrier" && !("epochs" in rCarrier)
      && typeof rCarrier.proofBytesHex === "string" && typeof rCarrier.metadataBytesHex === "string");
    ok("the carrier answer's key set is CLOSED (asserting only the absence of one member name let figures ride under another)",
      JSON.stringify(Object.keys(rCarrier).sort())
      === JSON.stringify(["metadataBytesHex", "note", "proofBytesHex", "status"]));
    const decP = platform.Proof.fromBinary(Buffer.from(rCarrier.proofBytesHex, "hex"));
    ok("the carrier bytes re-decode to EVERY proof member, not one sampled field",
      hex(decP.grovedbProof) === "010203" && hex(decP.quorumHash) === "44"
      && hex(decP.signature) === "55" && decP.round === 6
      && hex(decP.blockIdHash) === "66" && decP.quorumType === 7);
    ok("the carrier's metadata bytes re-decode to the classified metadata (nonemptiness alone let the proof bytes stand in)",
      platform.ResponseMetadata.fromBinary(Buffer.from(rCarrier.metadataBytesHex, "hex")).height === "9");

    // the CONTRACT-COMPLETE verifier fixture: every member the wrapper
    // serves (seven in-range uint64 strings, three uint32s, a finite
    // multiplier, a well-formed proposer array), and a 32-byte root
    const ROOT32 = new Uint8Array(32).fill(9);
    const fullEntry = { number: 3, firstBlockHeight: "1", firstCoreBlockHeight: 20,
      firstBlockTime: "2", feeMultiplier: 1.5, protocolVersion: 9, totalBlocksInEpoch: "10",
      nextEpochStartCoreBlockHeight: 33, totalProcessingFees: "77", totalDistributedStorageFees: "0",
      totalCreatedStorageFees: "0", coreBlockRewards: "0",
      blockProposers: [{ proposerId: new Uint8Array(32).fill(0xcd), blockCount: 2 }] };
    // every fake RECORDS its inputs, and the assertions bind them to the
    // classified carrier (fakes that ignore their arguments
    // establish only return-value flow, so a composition calling the
    // verifier with an empty proof or the wrong interval passed)
    const { LATEST_PLATFORM_VERSION } = await import(pathToFileURL(path.join(SDK, "src", "constants.js")).href);
    const seen = {};
    const goodVerifier = async ({ grovedbProof, startEpoch, endEpoch, platformVersion, metadata }) => {
      seen.verifier = { proof: hex(grovedbProof), startEpoch, endEpoch,
        platformVersion, metadataIsClassified: metadata === carrier.metadata };
      return { rootHash: ROOT32, finalizedEpochInfos: [fullEntry] };
    };
    const calls = { quorum: [], tender: [] };
    const rProved = await wrap.resolveAnswer(carrier, { ...range, verifyProof: goodVerifier,
      quorumKeyOf: async (proof) => { calls.quorum.push(proof === carrier.proof); return "QK"; },
      verifyTenderdash: async (proof, metadata, rootHash, qk) => {
        calls.tender.push([proof === carrier.proof, metadata === carrier.metadata, hex(rootHash), qk]); return true; } });
    ok("the proved path answers proved with the VERIFIER's figures, not the carrier's",
      rProved.status === "proved" && rProved.epochs.length === 1 && rProved.epochs[0].number === 3
      && rProved.epochs[0].totalProcessingFees === "77"
      && JSON.stringify(rProved.epochs[0].blockProposers) === JSON.stringify([{ proposerId: "cd".repeat(32), blockCount: 2 }]));
    ok("the verifier received the classified proof bytes, the requested interval, THE pinned platform version (a numeric check alone let 0 pass) and the classified metadata",
      seen.verifier && seen.verifier.proof === "010203" && seen.verifier.startEpoch === 0
      && seen.verifier.endEpoch === 9 && seen.verifier.platformVersion === LATEST_PLATFORM_VERSION
      && seen.verifier.metadataIsClassified === true);
    ok("the second stage ran over the classified proof and metadata, the verifier's 32-byte root, and the resolved quorum key",
      JSON.stringify(calls.quorum) === JSON.stringify([true])
      && calls.tender.length === 1 && calls.tender[0][0] === true && calls.tender[0][1] === true
      && calls.tender[0][2] === hex(ROOT32) && calls.tender[0][3] === "QK");
    await rejects("a failing Tenderdash check refuses the proved path",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: goodVerifier,
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => false }), /did not verify/);
    await rejects("a TRUTHY NON-BOOLEAN Tenderdash result refuses (the string \"false\" would have read as verified)",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: goodVerifier,
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => "true" }), /did not verify/);
    await rejects("a verifier answering without a root hash refuses",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ finalizedEpochInfos: [fullEntry] }) }), /32-byte root hash/);
    await rejects("an EMPTY root hash refuses (presence alone passed)",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: new Uint8Array(), finalizedEpochInfos: [fullEntry] }) }), /32-byte root hash/);
    await rejects("a STRING root hash refuses",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: "09".repeat(32), finalizedEpochInfos: [fullEntry] }) }), /32-byte root hash/);
    await rejects("a 31-byte root hash refuses",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: new Uint8Array(31).fill(9), finalizedEpochInfos: [fullEntry] }) }), /32-byte root hash/);
    await rejects("a verifier answering without an entry array refuses",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32, finalizedEpochInfos: "nope" }) }), /no entry array/);
    await rejects("a verifier entry MISSING a declared figure member refuses (only the array was checked)",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, coreBlockRewards: undefined }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /in-range uint64 decimal string/);
    await rejects("a verifier entry with a NUMERIC figure refuses (strings only; a number silently rounds)",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, totalProcessingFees: 77 }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /in-range uint64 decimal string/);
    await rejects("a verifier entry without a proposer array refuses",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, blockProposers: undefined }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /no block-proposer array/);
    // the record-shape cases: served members beyond the seven
    // strings must also conform, or the proved label lies
    await rejects("an ABOVE-RANGE uint64 string refuses (canonical syntax alone does not establish the range)",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, firstBlockHeight: "18446744073709551616" }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /in-range uint64/);
    await rejects("an above-uint32 epoch number refuses",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, number: 2 ** 32 }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /uint32 epoch number/);
    await rejects("a MISSING uint32 member refuses (undefined members were served as proved)",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, firstCoreBlockHeight: undefined }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /not a uint32/);
    await rejects("a STRING uint32 member refuses (no coercion)",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, protocolVersion: "9" }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /not a uint32/);
    await rejects("a NON-FINITE fee multiplier refuses",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, feeMultiplier: NaN }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /non-finite fee multiplier/);
    await rejects("a MALFORMED proposer member refuses (a string count, the exact shape)",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, blockProposers: [{ proposerId: new Uint8Array(32).fill(1), blockCount: "3" }] }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /malformed block proposer/);
    await rejects("an EMPTY proposer identifier refuses",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, blockProposers: [{ proposerId: new Uint8Array(), blockCount: 3 }] }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /malformed block proposer/);
    await rejects("a 31-BYTE proposer identifier refuses (identifiers match 32-byte registered hashes, and nonempty alone accepted any width)",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, blockProposers: [{ proposerId: new Uint8Array(31).fill(1), blockCount: 3 }] }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /exactly 32 bytes/);
    await rejects("a 33-BYTE proposer identifier refuses too (both sides of the width)",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, blockProposers: [{ proposerId: new Uint8Array(33).fill(1), blockCount: 3 }] }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /exactly 32 bytes/);
    // EVERY required member's absence refuses, in one loop (the
    // independent round's surviving mutation: removing ONE member
    // from the validator's list survived the named-member cases)
    for (const member of ["firstBlockHeight", "firstBlockTime", "totalBlocksInEpoch",
      "totalProcessingFees", "totalDistributedStorageFees", "totalCreatedStorageFees",
      "coreBlockRewards", "firstCoreBlockHeight", "protocolVersion", "nextEpochStartCoreBlockHeight"]) {
      const without = { ...fullEntry };
      delete without[member]; // actual removal, not an explicit undefined (the confirmation round)
      await rejects(`a verifier entry missing ${member} refuses`,
        wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
          finalizedEpochInfos: [without] }),
          quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /refusing the proved path/);
    }
    // the interval binding: a signed root does not establish
    // that the verifier extracted the REQUESTED keys
    await rejects("a structurally valid entry OUTSIDE the requested interval refuses the proved path (the epoch-42 shape)",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [{ ...fullEntry, number: 42 }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /outside the requested interval/);
    await rejects("a REPEATED epoch number refuses the proved path",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => ({ rootHash: ROOT32,
        finalizedEpochInfos: [fullEntry, { ...fullEntry }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true }), /repeated epoch number/);
    {
      const outOfOrder = await wrap.resolveAnswer(carrier, { ...range,
        verifyProof: async () => ({ rootHash: ROOT32,
          finalizedEpochInfos: [{ ...fullEntry, number: 7 }, { ...fullEntry, number: 3 }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true });
      ok("out-of-order verifier entries are served ascending",
        outOfOrder.status === "proved" && JSON.stringify(outOfOrder.epochs.map((x) => x.number)) === JSON.stringify([3, 7]));
    }
    { // THE COMPLETENESS SPLIT, pinned by test (checking: the
      // intended semantics were implementable either way, so the intent
      // is now load-bearing): the wrapper binds membership, uniqueness
      // and order, and a proved SUBSET, including the EMPTY proved
      // answer (a proved-absence claim), is deliberately valid HERE;
      // full-coverage rules belong to consumers (the live probe and the
      // audit's discovery gate both enforce their own)
      const rEmpty = await wrap.resolveAnswer(carrier, { ...range,
        verifyProof: async () => ({ rootHash: ROOT32, finalizedEpochInfos: [] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true });
      ok("an EMPTY extraction is a valid proved answer at the wrapper, claiming only what it carries (coverage is the consumer's rule)",
        rEmpty.status === "proved" && rEmpty.epochs.length === 0);
      const rSubset = await wrap.resolveAnswer(carrier, { ...range,
        verifyProof: async () => ({ rootHash: ROOT32, finalizedEpochInfos: [{ ...fullEntry, number: 1 }] }),
        quorumKeyOf: async () => "QK", verifyTenderdash: async () => true });
      ok("a proved SUBSET of the interval is valid at the wrapper for the same stated reason",
        rSubset.status === "proved" && JSON.stringify(rSubset.epochs.map((x) => x.number)) === JSON.stringify([1]));
    }
    { // round and quorumType stay AS DECODED on the carrier (the stated
      // policy, now tested at its boundary: protobuf zero defaults on
      // both members still classify as a usable carrier)
      const zeroed = platform.Proof.create({ grovedbProof: new Uint8Array([1]),
        quorumHash: new Uint8Array([2]), signature: new Uint8Array([3]),
        blockIdHash: new Uint8Array([4]), round: 0, quorumType: 0 });
      const c0 = wrap.classifyResponse(v0Of({ oneofKind: "proof", proof: zeroed }, md), { requestedProve: true });
      ok("zero round and quorum type classify as a carrier AND pass through as decoded (the stated policy observed on the values, not only the kind)",
        c0.kind === "proof-carrier" && c0.proof.round === 0 && c0.proof.quorumType === 0);
    }
    { // THE DEFAULT EXPORT'S ASSEMBLY, driven over a fake transport
      // (the principal gap: the battery called
      // the pieces and never the production assembly, so a default
      // export returning a hard-coded proved answer survived every
      // check). The proved assembly needs real crypto and stays
      // live-probe territory; the plain and carrier assemblies run
      // here end to end through the real client dispatch.
      const dispatches = [];
      const transportFor = (response) => ({
        mergeOptions: (o) => o || {},
        unary: (method, input) => { dispatches.push({ method: method && method.name, input });
          return { then: (onF, onR) => Promise.resolve({ response }).then(onF, onR) }; },
      });
      const poolFor = (response) => ({ network: "fake", getClient: () => ({ _transport: transportFor(response) }) });
      const plainResp = proto.GetFinalizedEpochInfosResponse.fromBinary(Buffer.from(goldenResponse, "hex"));
      const dPlain = await wrap.default(poolFor(plainResp), { startEpoch: 0, endEpoch: 9, prove: false });
      ok("the default export assembles the plain route end to end (request, dispatch, classify, resolve)",
        dPlain.status === "unproved-plain" && dPlain.epochs.length === 1 && dPlain.epochs[0].number === 7
        && dPlain.epochs[0].totalProcessingFees === "1000" && dPlain.metadata.chainId === "pinX");
      ok("the dispatch carried the ROUTE and the BUILT REQUEST, observed at the transport (the confirmation round: a fake ignoring its arguments established only return-value flow)",
        dispatches.length === 1 && dispatches[0].method === "getFinalizedEpochInfos"
        && dispatches[0].input.version.v0.prove === false && dispatches[0].input.version.v0.startEpochIndex === 0
        && dispatches[0].input.version.v0.endEpochIndex === 9 && dispatches[0].input.version.v0.startEpochIndexIncluded === true);
      const proofResp = proto.GetFinalizedEpochInfosResponse.create({
        version: { oneofKind: "v0", v0: { result: { oneofKind: "proof", proof: proofMsg }, metadata: md } } });
      const dCarrier = await wrap.default(poolFor(proofResp), { startEpoch: 0, endEpoch: 9, prove: true });
      ok("the default export assembles the carrier route end to end and serves no figures",
        dCarrier.status === "unverified-carrier" && !("epochs" in dCarrier)
        && hex(platform.Proof.fromBinary(Buffer.from(dCarrier.proofBytesHex, "hex")).grovedbProof) === "010203");
      await rejects("the default export refuses a downgraded answer through the whole assembly",
        wrap.default(poolFor(plainResp), { startEpoch: 0, endEpoch: 9, prove: true }), /downgraded/);
    }
    await rejects("a reversed interval refuses resolveAnswer directly (a direct caller is not behind buildRequest)",
      wrap.resolveAnswer(carrier, { startEpoch: 9, endEpoch: 0, verifyProof: null }), /reversed/);
    await rejects("a malformed interval refuses resolveAnswer directly",
      wrap.resolveAnswer(carrier, { startEpoch: "0", endEpoch: 9, verifyProof: null }), /not a uint32/);
    { // THE ADAPTER COMPOSITION (the side-load decision, 2026-08-29): a
      // verifier built from feivAdapter's mapping over a
      // binding-output-shaped result drives the wrapper's proved path
      // end to end, binding adapter and validator together offline
      const { adaptResult } = require("./feivAdapter.cjs");
      const rawBindingResult = { rootHash: Buffer.from("ab".repeat(32), "hex"),
        epochInfos: [{ epochIndex: 2, firstBlockTime: 5n, firstBlockHeight: 62n,
          totalBlocksInEpoch: 11n, firstCoreBlockHeight: 1000, nextEpochStartCoreBlockHeight: 1100,
          totalProcessingFees: 12595244n, totalDistributedStorageFees: 3150258n,
          totalCreatedStorageFees: 33292040n, coreBlockRewards: 2879573674004n,
          feeMultiplierPermille: 1500n, protocolVersion: 12,
          blockProposers: [{ proposer: { bytes: () => new Uint8Array(32).fill(0xab) }, count: 10n }] }] };
      const tenderRoots = [];
      const rAdapted = await wrap.resolveAnswer(carrier, { ...range,
        verifyProof: async () => adaptResult(rawBindingResult),
        quorumKeyOf: async () => "QK",
        verifyTenderdash: async (proof, metadata, rootHash) => { tenderRoots.push(hex(rootHash)); return true; } });
      ok("an adapter-mapped binding result passes the wrapper's full proved-path validation with EVERY mapped member intact (identity, not a sample)",
        rAdapted.status === "proved"
        && JSON.stringify(rAdapted.epochs) === JSON.stringify([{ number: 2,
          firstBlockHeight: "62", firstCoreBlockHeight: 1000, firstBlockTime: "5",
          feeMultiplier: 1.5, protocolVersion: 12, totalBlocksInEpoch: "11",
          nextEpochStartCoreBlockHeight: 1100, totalProcessingFees: "12595244",
          totalDistributedStorageFees: "3150258", totalCreatedStorageFees: "33292040",
          coreBlockRewards: "2879573674004", blockProposers: [{ proposerId: "ab".repeat(32), blockCount: 10 }] }]));
      ok("the adapter's mapped root hash is the one the second stage verified over",
        JSON.stringify(tenderRoots) === JSON.stringify(["ab".repeat(32)]));
    }
    await rejects("a THROWING verifier propagates (a failed verification is louder than absence, never a silent carrier downgrade)",
      wrap.resolveAnswer(carrier, { ...range, verifyProof: async () => { throw new Error("verifier exploded"); } }), /verifier exploded/);
    await rejects("an unknown classification kind refuses",
      wrap.resolveAnswer({ kind: "mystery" }, { ...range, verifyProof: null }), /unknown classification/);
  } finally {
    fs.rmSync(protoTarget, { force: true });
    fs.rmSync(wrapperTarget, { force: true });
  }

  // an OVERRIDE run can never green the gate (a caller could
  // export the override globally and the package chain, which consumes
  // only the exit status, would examine copies instead of the staged
  // tree): the mutation harness reads the summary LINE, so it keeps
  // working, while the exit status refuses regardless of the results
  if (process.env.E2_FEG_PATCH_DIR) {
    console.log(`e2FinalizedEpochsGateTest[OVERRIDE at ${process.env.E2_FEG_PATCH_DIR}]: ${passed} passed, ${failed} failed; exit is non-zero BY DESIGN so an override run can never stand in for the commit gate`);
    process.exitCode = 3;
    return;
  }
  console.log(`e2FinalizedEpochsGateTest: ${passed} passed, ${failed} failed` +
    (skipped ? `, ${skipped} skipped (counted, never folded into passes)` : ""));
  if (failed) process.exitCode = 1;
})();
