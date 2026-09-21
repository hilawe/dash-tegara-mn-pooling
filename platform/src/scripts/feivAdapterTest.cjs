/**
 * Offline battery for the finalized-epoch verifier ADAPTER
 * (feivAdapter.cjs): the faithful shape mapping from the side-loaded
 * binding's observed output to the wrapper's verifier contract.
 *
 * FIXTURE PROVENANCE: the fixture shape below transcribes the
 * binding's output as OBSERVED in the 2026-08-29 isolation run against
 * the saved live carrier (plain objects with epochIndex numbers,
 * bigint figures, a permille multiplier, proposers as
 * { proposer: IdentifierWASM-like with bytes(), count: bigint }); the
 * live probe's proved path is the check that the real binding still
 * emits this shape.
 *
 * WIDTH, STATED: this battery binds the MAPPING. Contract-conformance
 * REFUSALS on malformed mapped records belong to the wrapper's own
 * validator and are bound in e2FinalizedEpochsGateTest (including one
 * adapter-composed proved case); real-proof verification is the live
 * probe's claim.
 */
const { adaptEntry, adaptResult, makeVerifyProof, checkFinalizedEpochsProto } = require("./feivAdapter.cjs");
const fs = require("fs");
const path = require("path");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error("FAIL:", name, "(no error)"); }
  catch (e) { ok(name, re.test(String(e.message))); }
};
const hex = (u8) => Buffer.from(u8).toString("hex");

// the observed binding-output shape, one entry
const idOf = (bytes) => ({ bytes: () => Uint8Array.from(bytes) });
const rawEntry = () => ({
  epochIndex: 2,
  firstBlockTime: 5n, firstBlockHeight: 62n, totalBlocksInEpoch: 11n,
  firstCoreBlockHeight: 1000, nextEpochStartCoreBlockHeight: 1100,
  totalProcessingFees: 12595244n, totalDistributedStorageFees: 3150258n,
  totalCreatedStorageFees: 33292040n, coreBlockRewards: 2879573674004n,
  feeMultiplierPermille: 1500n, protocolVersion: 12,
  blockProposers: [{ proposer: idOf([0xab].concat(Array(31).fill(0x11))), count: 10n }],
});

{
  const m = adaptEntry(rawEntry());
  ok("the mapped entry carries the wrapper contract exactly (identity of every member)",
    JSON.stringify({ ...m, blockProposers: m.blockProposers.map((p) => ({ proposerId: hex(p.proposerId), blockCount: p.blockCount })) })
    === JSON.stringify({ number: 2, firstBlockHeight: "62", firstCoreBlockHeight: 1000,
      firstBlockTime: "5", feeMultiplier: 1.5, protocolVersion: 12, totalBlocksInEpoch: "11",
      nextEpochStartCoreBlockHeight: 1100, totalProcessingFees: "12595244",
      totalDistributedStorageFees: "3150258", totalCreatedStorageFees: "33292040",
      coreBlockRewards: "2879573674004", blockProposers: [{ proposerId: "ab" + "11".repeat(31), blockCount: 10 }] }));
  ok("every uint64 figure maps to a canonical decimal STRING",
    ["firstBlockHeight", "firstBlockTime", "totalBlocksInEpoch", "totalProcessingFees",
      "totalDistributedStorageFees", "totalCreatedStorageFees", "coreBlockRewards"]
      .every((k) => typeof m[k] === "string" && /^(0|[1-9][0-9]*)$/.test(m[k])));
  ok("the permille multiplier converts to the proto's double semantics (1500 permille is 1.5)",
    m.feeMultiplier === 1.5 && Number.isFinite(m.feeMultiplier));
  ok("the unit permille converts exactly (1000 permille is 1.0)",
    adaptEntry({ ...rawEntry(), feeMultiplierPermille: 1000n }).feeMultiplier === 1.0);
  ok("a permille outside exact binary doubles rounds by the division rule, matching the JS literal for the same decimal (a constants-only mutation answering zero elsewhere fails here)",
    adaptEntry({ ...rawEntry(), feeMultiplierPermille: 1234n }).feeMultiplier === 1.234);
  ok("the proposer identifier is the bytes() result as a Uint8Array",
    m.blockProposers[0].proposerId instanceof Uint8Array && hex(m.blockProposers[0].proposerId) === "ab" + "11".repeat(31));
}
{ // an above-uint32 proposer count maps THROUGH as a number the
  // wrapper's validator then refuses (the adapter repairs nothing)
  const m = adaptEntry({ ...rawEntry(), blockProposers: [{ proposer: idOf(Array(32).fill(1)), count: 5000000000n }] });
  ok("an above-uint32 count passes through numerically for the wrapper's validator to refuse",
    m.blockProposers[0].blockCount === 5000000000);
}
throws("a non-bigint figure refuses (the adapter never fabricates a figure)",
  () => adaptEntry({ ...rawEntry(), totalProcessingFees: "12595244" }), /not the bigint the binding serves/);
{ // firstBlockTime's two OBSERVED build shapes both map to the
  // millisecond decimal string (darwin serves a bigint, linux a Date)
  const asDate = adaptEntry({ ...rawEntry(), firstBlockTime: new Date(1787978015234) });
  ok("a Date firstBlockTime maps to its millisecond decimal string", asDate.firstBlockTime === "1787978015234");
  const asBig = adaptEntry({ ...rawEntry(), firstBlockTime: 1787978015234n });
  ok("a bigint firstBlockTime maps to the same decimal string", asBig.firstBlockTime === "1787978015234");
}
throws("a firstBlockTime outside both observed shapes refuses",
  () => adaptEntry({ ...rawEntry(), firstBlockTime: "5" }), /neither of the binding's two observed shapes/);
throws("a pre-1970 Date firstBlockTime refuses (not a nonnegative millisecond count)",
  () => adaptEntry({ ...rawEntry(), firstBlockTime: new Date(-5) }), /not a nonnegative safe millisecond count/);
throws("a missing proposer byte identifier refuses",
  () => adaptEntry({ ...rawEntry(), blockProposers: [{ proposer: {}, count: 1n }] }), /no byte identifier/);
throws("a non-bigint proposer count refuses",
  () => adaptEntry({ ...rawEntry(), blockProposers: [{ proposer: idOf(Array(32).fill(1)), count: 3 }] }), /not a bigint/);
throws("a missing block-proposer array refuses",
  () => adaptEntry({ ...rawEntry(), blockProposers: undefined }), /no block-proposer array/);
throws("a non-object entry refuses", () => adaptEntry(null), /non-object entry/);
{
  const r = adaptResult({ rootHash: Buffer.from("ab".repeat(32), "hex"), epochInfos: [rawEntry()] });
  ok("the result maps the root hash to a Uint8Array and every entry through adaptEntry",
    r.rootHash instanceof Uint8Array && r.rootHash.length === 32
    && r.finalizedEpochInfos.length === 1 && r.finalizedEpochInfos[0].number === 2);
}
throws("a result without an epochInfos array refuses", () => adaptResult({ rootHash: new Uint8Array(32) }), /no epochInfos array/);
// byte sources must be byte CONTAINERS (new Uint8Array(32)
// reads a number as a length and fabricates 32 zero bytes)
throws("a NUMERIC root hash refuses instead of fabricating zero bytes",
  () => adaptResult({ rootHash: 32, epochInfos: [] }), /not a byte container/);
throws("a NUMERIC proposer bytes() result refuses instead of fabricating zero bytes",
  () => adaptEntry({ ...rawEntry(), blockProposers: [{ proposer: { bytes: () => 32 }, count: 1n }] }), /not a byte container/);
throws("a plain-array bytes() result refuses (the binding serves Uint8Array)",
  () => adaptEntry({ ...rawEntry(), blockProposers: [{ proposer: { bytes: () => [1, 2] }, count: 1n }] }), /not a byte container/);
throws("a THROWING bytes() propagates",
  () => adaptEntry({ ...rawEntry(), blockProposers: [{ proposer: { bytes: () => { throw new Error("id exploded"); } }, count: 1n }] }), /id exploded/);

// ---- makeVerifyProof drives its BINDING, shown with an injected fake
// (the factory could have returned a hard-coded function and
// the load-only assertion would pass) ----
(async () => {
  {
    const calls = [];
    const fake = { verifyFinalizedEpochInfosProof: (...args) => { calls.push(args);
      return { rootHash: new Uint8Array(32).fill(7), epochInfos: [rawEntry()] }; } };
    const vp = makeVerifyProof({ binding: fake });
    const gp = Uint8Array.from([9, 9]);
    // the WRAPPER'S EXACT invocation shape, metadata included: this
    // binds INVOCATION-SHAPE COMPATIBILITY (the call succeeds and the
    // six positional binding arguments are exact); that the extra
    // member is ignored is the adapter's stated behavior, which an
    // unused-member assertion cannot observe in JavaScript
    const out = await vp({ grovedbProof: gp, startEpoch: 3, endEpoch: 8, platformVersion: 12, metadata: { chainId: "pinT" } });
    ok("the factory's verifier calls the binding with the proof, both-inclusive bounds and the platform version, in the binding's argument order",
      calls.length === 1 && calls[0][0] === gp && calls[0][1] === 3 && calls[0][2] === true
      && calls[0][3] === 8 && calls[0][4] === true && calls[0][5] === 12);
    ok("the factory's verifier adapts the binding's result through adaptResult (root VALUE, not only width; a length check accepted any constant root)",
      out.rootHash instanceof Uint8Array && Buffer.from(out.rootHash).toString("hex") === "07".repeat(32)
      && out.finalizedEpochInfos[0].number === 2 && out.finalizedEpochInfos[0].totalProcessingFees === "12595244");
  }
  { // a falsey INJECTED binding refuses instead of silently selecting
    // the production alias (truthiness selection took
    // binding:null to the alias)
    let threw = false;
    try { makeVerifyProof({ binding: null }); } catch (e) { threw = /alias pin is wrong/.test(String(e.message)); }
    ok("an explicitly null injected binding refuses at factory time", threw === true);
  }
  { // a SECOND variant with distinct values in every member: one
    // fixed fixture let a mutation hard-code the expected constants,
    // so the mapping must track its input
    const v = adaptEntry({ epochIndex: 9, firstBlockTime: 77n, firstBlockHeight: 88n,
      totalBlocksInEpoch: 99n, firstCoreBlockHeight: 4, nextEpochStartCoreBlockHeight: 6,
      totalProcessingFees: 1n, totalDistributedStorageFees: 2n, totalCreatedStorageFees: 3n,
      coreBlockRewards: 4n, feeMultiplierPermille: 500n, protocolVersion: 7,
      blockProposers: [{ proposer: idOf([0x01, 0x02, 0x03].concat(Array(29).fill(0x22))), count: 1n }] });
    ok("a second variant maps by its own values, not the first fixture's constants",
      JSON.stringify({ ...v, blockProposers: v.blockProposers.map((p) => ({ proposerId: hex(p.proposerId), blockCount: p.blockCount })) })
      === JSON.stringify({ number: 9, firstBlockHeight: "88", firstCoreBlockHeight: 4,
        firstBlockTime: "77", feeMultiplier: 0.5, protocolVersion: 7, totalBlocksInEpoch: "99",
        nextEpochStartCoreBlockHeight: 6, totalProcessingFees: "1", totalDistributedStorageFees: "2",
        totalCreatedStorageFees: "3", coreBlockRewards: "4", blockProposers: [{ proposerId: "010203" + "22".repeat(29), blockCount: 1 }] }));
  }
  {
    const vp = makeVerifyProof({ binding: { verifyFinalizedEpochInfosProof: () => { throw new Error("proof refused"); } } });
    try { await vp({ grovedbProof: new Uint8Array([1]), startEpoch: 0, endEpoch: 1, platformVersion: 12 }); failed++; console.error("FAIL: binding throw did not propagate"); }
    catch (e) { ok("a binding throw propagates through the factory's verifier", /proof refused/.test(String(e.message))); }
  }
  throws("a binding without the verifier function refuses at factory time",
    () => makeVerifyProof({ binding: {} }), /alias pin is wrong/);
  { // the production default loads the real alias
    let fn = null, err = null;
    try { fn = makeVerifyProof(); } catch (e) { err = e; }
    ok("makeVerifyProof with no injection loads the side-loaded alias", err === null && typeof fn === "function");
  }

  // ---- the proto transcription checker, EXECUTED (a
  // source-presence assertion observed literals a dead branch could
  // keep): the real installed proto passes, and each defect shape is
  // watched failing on a mutated text ----
  // the proto path is overridable ONLY so the mutation harness can run
  // this file from a scratch copy that has no node_modules beside it;
  // the default is the installed tree's proto
  const realProto = fs.readFileSync(process.env.E2_FEIV_PROTO_PATH
    || path.join(__dirname, "..", "..", "node_modules", "@dashevo", "dapi-grpc", "protos", "platform", "v0", "platform.proto"), "utf8");
  // fixture mutations are applied INSIDE the block region (a plain
  // replace hits the FIRST occurrence in the file, which for a
  // non-unique anchor sits in an earlier message and mutates nothing
  // the checker reads; this bit the first cut of the dup fixture)
  const inBlock = (anchor, replacement) => {
    const s = realProto.indexOf("message GetFinalizedEpochInfosRequest");
    const head = realProto.slice(0, s), tail = realProto.slice(s);
    if (!tail.includes(anchor)) throw new Error(`fixture anchor not in block region: ${anchor}`);
    return head + tail.replace(anchor, replacement);
  };
  {
    const r = checkFinalizedEpochsProto(realProto);
    ok("the installed proto's finalized-epochs block passes the checker (every transcribed declaration exactly once in its owning message)",
      r.missing.length === 0 && r.duplicated.length === 0);
    ok("the installed block's digest equals the recorded pin (the same value the live runner pins; both records fail together when the block moves)",
      r.digest === "189989f897d14a3848cc564517e056e1c61b7affae1360da07991b46eb97e211");
  }
  {
    const r = checkFinalizedEpochsProto(inBlock("uint64 total_processing_fees = 9", "uint64 total_processing_fees = 99"));
    ok("a renumbered declaration is reported missing", r.missing.some((m) => m.includes("total_processing_fees = 9")));
  }
  {
    const r = checkFinalizedEpochsProto(inBlock("uint64 total_processing_fees = 9", "uint64 total_processing_fees = 99; // uint64 total_processing_fees = 9"));
    ok("a declaration surviving only in a line comment is reported missing",
      r.missing.some((m) => m.includes("total_processing_fees = 9")));
  }
  {
    const r = checkFinalizedEpochsProto(inBlock("uint64 total_processing_fees = 9", "uint64 total_processing_fees = 99; /* uint64 total_processing_fees = 9\n          [ jstype = JS_STRING ]; */"));
    ok("a declaration surviving only in a BLOCK comment is reported missing (only line comments were stripped)",
      r.missing.some((m) => m.includes("total_processing_fees = 9")));
  }
  {
    // THE RELOCATION SHAPE (the named mutation): the declaration
    // leaves its owning message and reappears in a shadow message; a
    // flat block count sees one occurrence and passes, an owner-scoped
    // check reports it missing
    const r = checkFinalizedEpochsProto(inBlock("bool prove = 5;", "} message Shadow { bool prove = 5;"));
    ok("a declaration RELOCATED into a shadow message is reported missing from its owner",
      r.missing.some((m) => m.includes("GetFinalizedEpochInfosRequestV0.bool prove = 5")));
  }
  {
    const r = checkFinalizedEpochsProto(inBlock("bool prove = 5;", "bool prove = 5; bool prove = 5;"));
    ok("a duplicated declaration inside the OWNING message is reported", r.duplicated.some((m) => m.includes("prove = 5")));
  }
  {
    const prefixed = "/* message GetFinalizedEpochInfosRequest { decoy } */\n" + realProto;
    const r = checkFinalizedEpochsProto(prefixed);
    ok("a commented bounding-message name cannot shift the block (comments are stripped before the boundary search)",
      r.missing.length === 0 && r.duplicated.length === 0 && r.digest === checkFinalizedEpochsProto(realProto).digest);
  }
  {
    // NESTED-SCOPE CARVING, bound: an untranscribed extra declaration
    // added inside a NESTED message that happens to spell the same as
    // a parent requirement must not read as the parent's duplicate
    // (the parent's body has nested spans carved out); the digest pin
    // is what flags such an addition in production, not the
    // owner-scoped declaration check
    const r = checkFinalizedEpochsProto(inBlock(
      "repeated FinalizedEpochInfo finalized_epoch_infos =",
      "Proof proof = 2; repeated FinalizedEpochInfo finalized_epoch_infos ="));
    ok("an identical-spelling extra inside a nested message is not the parent's duplicate (nested spans are carved from the parent's body)",
      r.duplicated.length === 0 && r.missing.length === 0
      && r.digest !== checkFinalizedEpochsProto(realProto).digest);
  }
  {
    const r = checkFinalizedEpochsProto("nothing here");
    ok("a text without the block's bounding messages refuses wholesale", r.missing.length === 1 && /bounding message names/.test(r.missing[0]) && r.digest === null);
  }
  {
    // THE SERVICE ROUTE (the rpc declaration
    // lives outside the message block, so a renamed route left the
    // digest unchanged): a renamed rpc is reported missing
    const renamedRpc = realProto.replace("rpc getFinalizedEpochInfos(GetFinalizedEpochInfosRequest)", "rpc getFinalizedEpochInfosV2(GetFinalizedEpochInfosRequest)");
    const r = checkFinalizedEpochsProto(renamedRpc);
    ok("a renamed rpc route is reported missing (the service declaration is part of the transcription)",
      r.missing.some((m) => m.includes("rpc getFinalizedEpochInfos")));
  }
  {
    // THE DECOY-SERVICE SHAPE (the confirmation round): the intended
    // service's route renamed while a decoy service carries the rpc; a
    // whole-text search passed, the Platform-scoped check refuses
    const decoy = realProto.replace("rpc getFinalizedEpochInfos(GetFinalizedEpochInfosRequest)", "rpc getFinalizedEpochInfosV2(GetFinalizedEpochInfosRequest)")
      + "\nservice Decoy { rpc getFinalizedEpochInfos(GetFinalizedEpochInfosRequest)\n      returns (GetFinalizedEpochInfosResponse); }\n";
    const r = checkFinalizedEpochsProto(decoy);
    ok("a decoy service carrying the rpc does not satisfy the Platform-scoped route check",
      r.missing.some((m) => m.includes("rpc getFinalizedEpochInfos")));
  }
  { // a TWO-ENTRY result maps BOTH entries (the independent round's
    // surviving mutation: an adapter retaining only the first entry
    // passed every single-entry fixture)
    const r2 = adaptResult({ rootHash: Buffer.from("cd".repeat(32), "hex"),
      epochInfos: [rawEntry(), { ...rawEntry(), epochIndex: 3, totalProcessingFees: 77n }] });
    ok("a two-entry result maps both entries with their own values",
      r2.finalizedEpochInfos.length === 2 && r2.finalizedEpochInfos[0].number === 2
      && r2.finalizedEpochInfos[1].number === 3 && r2.finalizedEpochInfos[1].totalProcessingFees === "77");
  }

  console.log(`feivAdapterTest: ${passed} passed, ${failed} failed`);
  process.exitCode = failed ? 1 : 0;
})();
