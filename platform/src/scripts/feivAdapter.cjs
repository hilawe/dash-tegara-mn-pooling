/**
 * THE FINALIZED-EPOCH VERIFIER ADAPTER (C1 piece 3's integration, the
 * SIDE-LOAD decision, Hilawe 2026-08-29): adapts the side-loaded
 * package's `verifyFinalizedEpochInfosProof` to the wrapper's injected
 * verifier contract, so the pinned stack stays untouched and exactly
 * ONE route consumes the newer package.
 *
 * THE DEPENDENCY, stated: `pshenmic-dpp-feiv` is an exact-pinned npm
 * alias of pshenmic-dpp 2.0.0-dev.28, which ships the binding the
 * project-pinned 2.0.0-dev.20 predates (the C1 survey update,
 * 2026-08-29). Nothing else in the stack imports the alias; every
 * other verifier stays on the pin. Neither version is assumed better
 * or worse anywhere in this file; the alias exists because dev.28
 * demonstrably ships this one function and the pin demonstrably does
 * not, shown by the isolation run against the saved live carrier.
 *
 * WHAT THE ADAPTER DOES, exactly: a faithful SHAPE mapping from the
 * binding's observed output (epochIndex numbers, bigint figures, an
 * IdentifierWASM proposer with a bytes() method, a permille
 * multiplier) to the wrapper contract's record (canonical decimal
 * strings for the seven uint64 figures, uint32 numbers, a finite
 * feeMultiplier equal to permille divided by one thousand, proposer
 * byte identifiers with uint32 counts). It VALIDATES NOTHING beyond
 * what mapping forces: the wrapper's own validator is the gate, and a
 * malformed mapped record must refuse THERE, never be repaired here.
 * A mapping that cannot proceed (a proposer without a bytes method, a
 * non-bigint where a figure belongs) throws rather than fabricating a
 * member.
 */
const bigToDecimal = (name, v) => {
  if (typeof v !== "bigint") {
    throw new Error(`the verifier's ${name} is ${typeof v}, not the bigint the binding serves; refusing to fabricate a figure`);
  }
  return v.toString(10);
};

// a byte value must arrive as an actual byte container (new
// Uint8Array(32) treats a NUMBER as a requested length and fabricates
// 32 zero bytes, which a downstream width check then accepts)
const asBytes = (name, v) => {
  if (v instanceof Uint8Array) return new Uint8Array(v);
  if (Buffer.isBuffer(v)) return new Uint8Array(v);
  throw new Error(`the verifier's ${name} is not a byte container (${typeof v}); refusing to fabricate bytes`);
};

// firstBlockTime is the ONE member the binding serves in two observed
// shapes, by build: the darwin native build serves a bigint (the
// millisecond count) and the linux native build serves a Date (observed
// 2026-08-29, same package version, same proof); both map to the
// contract's millisecond decimal string, and anything else refuses
const timeToDecimal = (v) => {
  if (typeof v === "bigint") return v.toString(10);
  if (v instanceof Date) {
    const ms = v.getTime();
    if (!Number.isSafeInteger(ms) || ms < 0) {
      throw new Error(`the verifier's firstBlockTime Date is not a nonnegative safe millisecond count (${ms}); refusing`);
    }
    return String(ms);
  }
  throw new Error(`the verifier's firstBlockTime is ${typeof v}, neither of the binding's two observed shapes (bigint, Date); refusing to fabricate a figure`);
};

// one binding entry to one wrapper-contract entry, a faithful mapping
const adaptEntry = (e) => {
  if (!e || typeof e !== "object") throw new Error("the verifier served a non-object entry; refusing");
  const proposers = Array.isArray(e.blockProposers) ? e.blockProposers : (() => {
    throw new Error(`epoch ${e.epochIndex}: the verifier served no block-proposer array; refusing`);
  })();
  return {
    number: e.epochIndex,
    firstBlockHeight: bigToDecimal("firstBlockHeight", e.firstBlockHeight),
    firstCoreBlockHeight: e.firstCoreBlockHeight,
    firstBlockTime: timeToDecimal(e.firstBlockTime),
    // the binding serves the PERMILLE figure; the wrapper contract's
    // feeMultiplier is the proto's double, converted from permille
    feeMultiplier: Number(bigToDecimal("feeMultiplierPermille", e.feeMultiplierPermille)) / 1000,
    protocolVersion: e.protocolVersion,
    totalBlocksInEpoch: bigToDecimal("totalBlocksInEpoch", e.totalBlocksInEpoch),
    nextEpochStartCoreBlockHeight: e.nextEpochStartCoreBlockHeight,
    totalProcessingFees: bigToDecimal("totalProcessingFees", e.totalProcessingFees),
    totalDistributedStorageFees: bigToDecimal("totalDistributedStorageFees", e.totalDistributedStorageFees),
    totalCreatedStorageFees: bigToDecimal("totalCreatedStorageFees", e.totalCreatedStorageFees),
    coreBlockRewards: bigToDecimal("coreBlockRewards", e.coreBlockRewards),
    blockProposers: proposers.map((p, i) => {
      if (!p || !p.proposer || typeof p.proposer.bytes !== "function") {
        throw new Error(`epoch ${e.epochIndex}: proposer ${i} carries no byte identifier; refusing`);
      }
      if (typeof p.count !== "bigint") {
        throw new Error(`epoch ${e.epochIndex}: proposer ${i}'s count is ${typeof p.count}, not a bigint; refusing`);
      }
      // Number() of an above-uint32 count produces a value the
      // wrapper's uint32 validator refuses, which is the intended gate
      return { proposerId: asBytes(`epoch ${e.epochIndex} proposer ${i} identifier`, p.proposer.bytes()), blockCount: Number(p.count) };
    }),
  };
};

// the binding's whole result to the wrapper contract's result
const adaptResult = (r) => {
  if (!r || !Array.isArray(r.epochInfos)) {
    throw new Error("the verifier returned no epochInfos array; refusing");
  }
  return {
    rootHash: asBytes("rootHash", r.rootHash),
    finalizedEpochInfos: r.epochInfos.map(adaptEntry),
  };
};

// THE PROTO TRANSCRIPTION CHECK, pure and offline-testable, structure
// aware. SCOPE: the finalized-epochs block and the Platform service
// route; the generated Proof and ResponseMetadata layouts this stack
// also consumes are OUTSIDE it and are pinned by the exact SDK package
// version instead (the runner's version gate). A flat count between two
// textual sentinels also accepted a declaration RELOCATED into a shadow
// message, kept only in a block comment, or shifted by a commented
// bounding name, so the order
// is deliberate: comments are stripped FIRST (both line and block
// comments), THEN the bounding messages are located, THEN each named
// message body is extracted by brace matching with nested message
// bodies carved out, and each transcribed declaration must appear
// EXACTLY ONCE in its OWNING message's own body. Returns { missing,
// duplicated, digest } where digest is the sha256 of the
// comment-stripped whitespace-normalized block, so a caller can pin
// the whole block's content, not only the transcribed lines.
const TRANSCRIBED_BY_MESSAGE = {
  GetFinalizedEpochInfosRequestV0: [
    "uint32 start_epoch_index = 1", "bool start_epoch_index_included = 2",
    "uint32 end_epoch_index = 3", "bool end_epoch_index_included = 4", "bool prove = 5"],
  FinalizedEpochInfos: ["repeated FinalizedEpochInfo finalized_epoch_infos = 1"],
  FinalizedEpochInfo: [
    "uint32 number = 1", "uint64 first_block_height = 2", "uint32 first_core_block_height = 3",
    "uint64 first_block_time = 4", "double fee_multiplier = 5", "uint32 protocol_version = 6",
    "uint64 total_blocks_in_epoch = 7", "uint32 next_epoch_start_core_block_height = 8",
    "uint64 total_processing_fees = 9", "uint64 total_distributed_storage_fees = 10",
    "uint64 total_created_storage_fees = 11", "uint64 core_block_rewards = 12",
    "repeated BlockProposer block_proposers = 13"],
  BlockProposer: ["bytes proposer_id = 1", "uint32 block_count = 2"],
  GetFinalizedEpochInfosResponseV0: [
    "FinalizedEpochInfos epochs = 1", "Proof proof = 2", "ResponseMetadata metadata = 3"],
};
const stripProtoComments = (text) => text
  .replace(/\/\*[\s\S]*?\*\//g, " ")
  .split("\n").map((l) => l.replace(/\/\/.*$/, "")).join("\n");
// every message body in the text, by name, brace-matched, with nested
// message sub-bodies REMOVED from their parent's body (a declaration
// in a nested message must not satisfy the parent's requirement)
const braceSpan = (text, openIndex) => {
  let depth = 1, i = openIndex + 1;
  while (i < text.length && depth > 0) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}") depth--;
    i++;
  }
  return depth === 0 ? i : -1; // one past the closing brace, or -1 when unbalanced
};
const messageBodies = (stripped) => {
  const bodies = {};
  const re = /message +([A-Za-z0-9_]+) *\{/g;
  let m;
  while ((m = re.exec(stripped)) !== null) {
    const open = re.lastIndex - 1;
    const close = braceSpan(stripped, open);
    if (close === -1) continue; // an unbalanced body is not recorded, so its declarations go missing
    let body = stripped.slice(open + 1, close - 1);
    // carve every NESTED message span out of the parent's body, brace
    // matched (a declaration inside a nested message must never satisfy
    // the parent's requirement)
    const nested = /message +[A-Za-z0-9_]+ *\{/g;
    let cut;
    while ((cut = nested.exec(body)) !== null) {
      const nOpen = nested.lastIndex - 1;
      const nClose = braceSpan(body, nOpen);
      if (nClose === -1) break;
      body = body.slice(0, cut.index) + " " + body.slice(nClose);
      nested.lastIndex = cut.index;
    }
    bodies[m[1]] = body;
  }
  return bodies;
};
const checkFinalizedEpochsProto = (protoText) => {
  const stripped = stripProtoComments(protoText);
  const start = stripped.indexOf("message GetFinalizedEpochInfosRequest");
  const end = stripped.indexOf("message GetContestedResourcesRequest");
  if (start === -1 || end === -1 || end <= start) {
    return { missing: ["the finalized-epochs block itself (its bounding message names were not found in order, comments stripped)"], duplicated: [], digest: null };
  }
  const block = stripped.slice(start, end);
  const bodies = messageBodies(block);
  const missing = [], duplicated = [];
  for (const [owner, decls] of Object.entries(TRANSCRIBED_BY_MESSAGE)) {
    const body = bodies[owner];
    for (const decl of decls) {
      if (body === undefined) { missing.push(`${owner}.${decl} (owning message not found)`); continue; }
      const flat = body.replace(/\s+/g, " ");
      const re = new RegExp(`(^| |;)${decl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} *[;\\[]`, "g");
      const count = (flat.match(re) || []).length;
      if (count === 0) missing.push(`${owner}.${decl}`);
      else if (count > 1) duplicated.push(`${owner}.${decl}`);
    }
  }
  // THE SERVICE ROUTE is part of the transcription too (the
  // the rpc declaration lives OUTSIDE the message
  // block, so a renamed route left the digest unchanged), and it must
  // sit INSIDE the Platform service's own body (the confirmation
  // round: a decoy service carrying the rpc satisfied a whole-text
  // search while the intended service used a renamed route)
  const svcMatch = /service +Platform *\{/.exec(stripped);
  const svcEnd = svcMatch ? braceSpan(stripped, svcMatch.index + svcMatch[0].length - 1) : -1;
  if (!svcMatch || svcEnd === -1) {
    missing.push("service Platform (its body was not found)");
  } else {
    const svcFlat = stripped.slice(svcMatch.index, svcEnd).replace(/\s+/g, " ");
    const rpcCount = (svcFlat.match(/rpc getFinalizedEpochInfos *\( *GetFinalizedEpochInfosRequest *\) *returns *\( *GetFinalizedEpochInfosResponse *\)/g) || []).length;
    if (rpcCount === 0) missing.push("service Platform.rpc getFinalizedEpochInfos(GetFinalizedEpochInfosRequest) returns (GetFinalizedEpochInfosResponse)");
    else if (rpcCount > 1) duplicated.push("service Platform.rpc getFinalizedEpochInfos");
  }
  const digest = require("crypto").createHash("sha256")
    .update(block.replace(/\s+/g, " ")).digest("hex");
  return { missing, duplicated, digest };
};

// the injected verifier the wrapper's proved path consumes; the
// side-loaded binding is required lazily so offline consumers of the
// pure mappers above never load a native module. The binding itself is
// INJECTABLE (a factory whose binding cannot be substituted
// is a factory no offline test can show calling it), and the
// production default is the alias.
const makeVerifyProof = (opts = {}) => {
  // presence, not truthiness (a falsey injected binding
  // silently selected the production alias instead of refusing)
  const feiv = "binding" in opts ? opts.binding : require("pshenmic-dpp-feiv");
  if (!feiv || typeof feiv.verifyFinalizedEpochInfosProof !== "function") {
    throw new Error("the side-loaded package ships no verifyFinalizedEpochInfosProof; the alias pin is wrong, refusing");
  }
  // the wrapper invokes with metadata too; this binding's arity has no
  // metadata parameter, so it is deliberately ignored here (both
  // checking flagged the unstated drop)
  return async ({ grovedbProof, startEpoch, endEpoch, platformVersion, metadata }) => {
    void metadata;
    const raw = feiv.verifyFinalizedEpochInfosProof(
      grovedbProof, startEpoch, true, endEpoch, true, platformVersion);
    return adaptResult(raw);
  };
};

module.exports = { adaptEntry, adaptResult, makeVerifyProof, checkFinalizedEpochsProto };
