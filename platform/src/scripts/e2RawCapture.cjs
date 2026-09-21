/**
 * THE PINNED CARRIER PIPELINE (duty D9's wrapper half, the part that is not the
 * mounted patch). It owns the canonical known-field re-encoding, the
 * unknown-field count, and the four closed result literals the C2 contract
 * defines, so that ONE implementation serves both consumers: the mounted
 * wrapper `patches/waitForStateTransitionResult-rawCapture.js`, which produces
 * captures, and `e2ReceiptVerify.cjs`, which VERIFIES operator-written records
 * it did not produce and declares `decodeProofCarrier` / `decodeMetadata` as
 * injected deps (its deps contract, e2ReceiptVerify.cjs:32-37).
 *
 * WHY THIS MODULE EXISTS AT ALL, since the spec's adoption table names only the
 * patch and the classifier: a mounted patch cannot be imported from the project
 * side (the spec forbids exactly that, requiring the acceptance assertion to
 * check the function AS MOUNTED rather than import the patch file), so golden
 * cases written against the patch would have to duplicate its encoding and
 * would then bind a copy instead of the article. The verifier's deps contract
 * settles it independently: it already requires this pipeline as a named
 * dependency and nothing in the tree supplies one. The divergence is resolved
 * in code and folded back, which is what the D9 freeze directs
 * (E2_BUILD_SPEC.md:142-157).
 *
 * WHAT IT ESTABLISHES: given carrier bytes, whether they ARE the canonical
 * known-field encoding of what they decode to, how many unknown-field entries
 * were dropped, and the decoded members its consumers compare.
 *
 * WHAT IT DOES NOT ESTABLISH: nothing cryptographic. It never verifies a proof,
 * never resolves a quorum key, and never decides whether a record is
 * entitled to anything. Byte-canonicality is not authenticity: a carrier can be
 * perfectly canonical and wholly invented. The two proof stages are the
 * wrapper's and the verifier's business, and both run them separately.
 *
 * THE PINNED CALLS, read at the installed runtime (@protobuf-ts/runtime 2.11.1)
 * rather than from memory:
 *   encode  toBinary(msg, { writeUnknownFields: false })
 *   count   UnknownFieldHandler.list(msg).length
 * Measured this turn on ResponseMetadata carrying one unknown varint: 31 bytes
 * with unknowns, 28 without, and the entry is still listed after encoding, so
 * the omission does not mutate the message. That non-mutation is what lets the
 * verification stages read the SAME decoded objects the encoding came from,
 * which is the equivalence the spec's pipeline (a) count, (b) encode, (c)
 * verify depends on (E2_BUILD_SPEC.md:172-182).
 */

// Resolved through require() of the generated ESM types. That works on the
// container's node (measured v20.20.2 this turn, not assumed: require(esm) was
// expected to fail there and did not) and on the host's v26. The floor is node
// >= 20.19; below that this module must be loaded through dynamic import
// instead, and the acceptance run would fail loudly at load rather than
// silently, which is the behaviour wanted.
const { Proof, ResponseMetadata } = require("dash-platform-sdk/proto/generated/platform.js");
const { UnknownFieldHandler } = require("@protobuf-ts/runtime");

const HEX_RE = /^([0-9a-f]{2})*$/;

const fail = (why) => { throw new Error(`e2RawCapture: ${why}`); };

/**
 * THE VACUITY GUARD, and it is not decoration. The spec defines
 * `unknownFieldsDropped` as the count "across BOTH carrier messages and their
 * nested known messages". Read at the installed generated types this turn, both
 * carriers are ENTIRELY SCALAR (Proof: grovedb_proof, quorum_hash, signature,
 * round, block_id_hash, quorum_type; ResponseMetadata: height,
 * core_chain_locked_height, epoch, time_ms, protocol_version, chain_id), so
 * there is no nested message to traverse and a traversal written for one would
 * be unreachable code. Rather than write dead code or silently assume the shape
 * holds forever, the assumption is CHECKED: if a future protocol revision adds
 * a message-kind field to either carrier, this refuses at construction and the
 * count's definition has to be revisited deliberately instead of quietly
 * undercounting.
 *
 * `kind === "scalar"` is the generated reflection's own discriminator; a
 * message field carries kind "message", a map "map", an enum "enum".
 */
/**
 * THE GUARD RECORDS WHAT IT CHECKED, which makes deleting its invocation a test
 * failure rather than a silent loss. Written after the mutation battery found
 * exactly that hole: with the predicate tested against synthetic types but the
 * invocation unrecorded, removing both calls below left every assertion green.
 * Stated at its real width (the pre-commit check named the residual): the roster
 * makes the invocation observable, not impossible to mimic; a mutation that
 * prefills it with the expected names while deleting the calls would pass the
 * roster assertion. The property
 * the guard protects, both carriers being entirely scalar, is INDEPENDENTLY
 * asserted by the test reading the generated types directly, so the roster is
 * defense-in-depth for the tripwire, not the property's only witness.
 *
 * It is still honest to say what this does NOT do. The guard's firing condition
 * cannot be produced by today's protocol definitions, because both carriers are
 * scalar, so no case makes the real module refuse. What is bound is the
 * predicate (case 8's synthetic types) and the fact that it was applied to both
 * real carrier types (the roster below). The tripwire itself waits on a future
 * protocol revision, and that is the whole reason it exists.
 */
const guardedTypes = [];
const assertNoNestedMessages = (type) => {
  const nested = type.fields.filter((f) => f.kind !== "scalar").map((f) => `${f.name}:${f.kind}`);
  if (nested.length > 0) {
    fail(`${type.typeName} is no longer entirely scalar (${nested.join(", ")}); the ` +
      "unknown-field count is defined across nested known messages too, so that traversal " +
      "must be implemented before this carrier can be counted correctly");
  }
  guardedTypes.push(type.typeName);
  return type.typeName;
};
assertNoNestedMessages(Proof);
assertNoNestedMessages(ResponseMetadata);

const decodeHex = (hex, what) => {
  if (typeof hex !== "string") fail(`${what} must be a hex string`);
  if (!HEX_RE.test(hex)) fail(`${what} must be lowercase hex of whole bytes`);
  return Buffer.from(hex, "hex");
};

/**
 * The pinned pair, applied to one already-decoded message: count the retained
 * unknown-field entries, then encode the KNOWN fields only. Order matters only
 * for legibility here, since the encode does not mutate.
 */
const canonicalize = (type, msg) => ({
  hex: Buffer.from(type.toBinary(msg, { writeUnknownFields: false })).toString("hex"),
  unknowns: UnknownFieldHandler.list(msg).length,
});

/** The pinned decode of one message type, returning the re-encoding and the count. */
const decodeAndCanonicalize = (type, hex, what) => {
  const bytes = decodeHex(hex, what);
  let msg;
  try { msg = type.fromBinary(bytes); }
  catch (e) { fail(`${what} does not decode as ${type.typeName} (${(e && e.message) || String(e)})`); }
  const { hex: reencodedHex, unknowns } = canonicalize(type, msg);
  return { msg, reencodedHex, unknowns };
};

/**
 * decodeProofCarrier(hex): the deps-contract decode of the COMPLETE Proof
 * carrier. `reencodedHex` is what the caller compares byte-for-byte against the
 * bytes it supplied; this module deliberately does NOT make that comparison
 * itself, because the two consumers compare against different things (the
 * verifier against a reassembled multipart carrier, the wrapper against the
 * bytes it just produced) and folding the comparison in here would let a caller
 * believe a check ran that its own bytes never entered.
 */
const decodeProofCarrier = (hex) => {
  const { msg, reencodedHex, unknowns } = decodeAndCanonicalize(Proof, hex, "the Proof carrier");
  return {
    reencodedHex,
    unknownFieldsDropped: unknowns,
    quorumHashHex: Buffer.from(msg.quorumHash).toString("hex"),
    round: msg.round,
  };
};

/**
 * decodeMetadata(hex): the deps-contract decode of ResponseMetadata. `height`
 * and `timeMs` come back as DECIMAL STRINGS, not BigInt, because the generated
 * types were produced with `long_type_string` (read at the generated file's
 * header this turn). The verifier already handles that: it calls BigInt() on
 * both, which accepts a decimal string.
 */
const decodeMetadata = (hex) => {
  const { msg, reencodedHex, unknowns } = decodeAndCanonicalize(ResponseMetadata, hex, "metadataBytes");
  return {
    reencodedHex,
    unknownFieldsDropped: unknowns,
    chainId: msg.chainId,
    protocolVersion: msg.protocolVersion,
    height: msg.height,
    timeMs: msg.timeMs,
    coreChainLockedHeight: msg.coreChainLockedHeight,
    epoch: msg.epoch,
  };
};

/**
 * The wrapper's success-path encoding, from the DECODED message objects the
 * transport handed it (the patch point receives decoded objects, so byte
 * identity with the transport framing cannot be claimed and never is; these are
 * re-encodings, and every member name and every comment here says so).
 * `unknownFieldsDropped` is the TOTAL across both messages, one entry counted
 * once, which is the spec's definition and is exactly a two-term sum here for
 * the reason the vacuity guard above records.
 */
const canonicalizeCarriers = (proofMsg, metadataMsg) => {
  const p = canonicalize(Proof, proofMsg);
  const m = canonicalize(ResponseMetadata, metadataMsg);
  return { proofMsgHex: p.hex, metadataMsgHex: m.hex, unknownFieldsDropped: p.unknowns + m.unknowns };
};

/**
 * THE FOUR CLOSED RESULT LITERALS. They live here rather than inline in the
 * patch so that the golden test binds the objects the mounted wrapper actually
 * returns, and so a member cannot be added in one place and forgotten in the
 * other. The classifier refuses any object carrying a member beyond those
 * named, so an accidental addition here fails the boundary case rather than
 * travelling silently.
 */
const verifiedProof = ({ proof, metadata, proofMsg, metadataMsg, unknownFieldsDropped }) =>
  ({ outcome: "verified-proof", proof, metadata, proofMsg, metadataMsg, unknownFieldsDropped });
const executionRefusal = ({ code, data, message }) =>
  ({ outcome: "execution-refusal", code, data, message });
const malformedResponse = (reason) => ({ outcome: "malformed-response", reason });
const transportFailure = (reason) => ({ outcome: "transport-failure", reason });

module.exports = {
  decodeProofCarrier,
  decodeMetadata,
  canonicalizeCarriers,
  verifiedProof,
  executionRefusal,
  malformedResponse,
  transportFailure,
  // exported for the golden test's synthetic-type case (the guard's own
  // predicate table row "the guard disabled" needs a type it can refuse)
  _assertNoNestedMessages: assertNoNestedMessages,
  // the roster the guard actually ran over at load, so its INVOCATION is
  // observable and not only its predicate
  _guardedTypes: guardedTypes,
  _types: { Proof, ResponseMetadata },
};
