/**
 * Offline golden cases for the pinned carrier pipeline (plain `node`, no
 * network), duty D9's wrapper-side half. The spec asks for GOLDEN CASES rather
 * than byte-stability alone, because a fixed-point check on chosen fixtures
 * establishes no unique encoding rule (E2_BUILD_SPEC.md:247-251): reordered
 * fields, explicit default values, duplicate known fields, unknown fields
 * asserted DROPPED and counted, and encode-decode-encode idempotence.
 *
 * THE FIXTURES ARE BUILT BY AN INDEPENDENT WIRE WRITER, not by the encoder
 * under test. Two separate reasons, kept separate deliberately. INDEPENDENCE:
 * a test's expected value must not be computed by the code it checks, so even
 * the canonical fixtures are hand-written at the wire level. PRODUCIBILITY:
 * THIS PROJECT'S pinned encoder emits one canonical form, so every
 * away-from-canonical fixture has to be written at the wire level too --
 * which says nothing about what OTHER encoders may emit. The fixtures fall in
 * three classes on exactly that question, and each case says which it is
 * where it matters:
 *  - REORDERED and UNKNOWN-FIELD fixtures are what a different conforming
 *    encoder may emit (field order is not semantic; unknown fields come from a
 *    newer schema revision);
 *  - EXPLICIT-DEFAULT and DUPLICATE-FIELD fixtures are LEGAL WIRE INPUT that
 *    parsers must accept but that a conforming proto3 encoder does not normally
 *    emit (section 3 says exactly this about defaults) -- they model a
 *    noncanonical or nonconforming producer at the record boundary;
 *  - the "messy" fixture's wrong-wire-type occurrence and the malformed-hex
 *    cases are beyond any encoder for this schema and model damaged or
 *    hand-built stored records.
 *
 * The refusal predicates over stored records belong to duty D8 and live in
 * e2ReceiptVerifyTest.cjs; this file keeps only the wrapper-side golden cases
 * (ownership assigned at E2_BUILD_SPEC.md:610-612).
 */
const {
  decodeProofCarrier, decodeMetadata, canonicalizeCarriers,
  verifiedProof, executionRefusal, malformedResponse, transportFailure,
  _assertNoNestedMessages, _guardedTypes, _types,
} = require("./e2RawCapture.cjs");
const { classifyOutcome, TOKENS } = require("./e2Outcome.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed++; }
  else { failed++; console.error("FAIL:", name); }
};
const eq = (name, got, want) => {
  if (got === want) { passed++; }
  else { failed++; console.error(`FAIL: ${name}\n  got:  ${got}\n  want: ${want}`); }
};
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

// ---------------------------------------------------------------------------
// An independent protobuf wire writer. Base-128 varints and length-delimited
// fields, written from the wire format itself, sharing no code with the module
// under test.
// ---------------------------------------------------------------------------
const varint = (n) => {
  const out = []; let v = BigInt(n);
  do { let b = Number(v & 0x7fn); v >>= 7n; if (v > 0n) b |= 0x80; out.push(b); } while (v > 0n);
  return Buffer.from(out);
};
const tag = (no, wt) => varint((BigInt(no) << 3n) | BigInt(wt));
const varField = (no, n) => Buffer.concat([tag(no, 0), varint(n)]);
const lenField = (no, buf) => Buffer.concat([tag(no, 2), varint(buf.length), buf]);
const strField = (no, s) => lenField(no, Buffer.from(s, "utf8"));
const hex = (b) => Buffer.concat(b).toString("hex");

// ResponseMetadata field numbers: 1 height (u64), 2 core_chain_locked_height
// (u32), 3 epoch (u32), 4 time_ms (u64), 5 protocol_version (u32), 6 chain_id
// (string). Read from the generated reflection this turn, not from memory.
const MD = { height: 1, cclh: 2, epoch: 3, timeMs: 4, pv: 5, chainId: 6 };
// Proof field numbers: 1 grovedb_proof, 2 quorum_hash, 3 signature (bytes),
// 4 round (u32), 5 block_id_hash (bytes), 6 quorum_type (u32).
const PR = { grovedb: 1, quorumHash: 2, signature: 3, round: 4, blockIdHash: 5, quorumType: 6 };

const CHAIN = "dash-devnet";
const mdCanonical = hex([
  varField(MD.height, 42), varField(MD.cclh, 7), varField(MD.epoch, 3),
  varField(MD.timeMs, 1700000000000), varField(MD.pv, 12), strField(MD.chainId, CHAIN),
]);

const qh = Buffer.alloc(32, 0xab), sig = Buffer.alloc(96, 0xcd), bid = Buffer.alloc(32, 0xef);
const gdb = Buffer.from("0a0b0c", "hex");
const prCanonical = hex([
  lenField(PR.grovedb, gdb), lenField(PR.quorumHash, qh), lenField(PR.signature, sig),
  varField(PR.round, 4), lenField(PR.blockIdHash, bid), varField(PR.quorumType, 106),
]);

// ---------------------------------------------------------------------------
// 1. The canonical fixtures round-trip to THEMSELVES, and the decoded members
//    are the ones the deps contract promises. The equality here is against
//    bytes this file wrote, so a pipeline that simply echoed its input would
//    still have to reproduce them from the decode.
// ---------------------------------------------------------------------------
{
  const m = decodeMetadata(mdCanonical);
  eq("canonical metadata re-encodes to itself", m.reencodedHex, mdCanonical);
  eq("metadata chainId decodes", m.chainId, CHAIN);
  eq("metadata protocolVersion decodes", m.protocolVersion, 12);
  eq("metadata height decodes as a decimal string (long_type_string)", m.height, "42");
  eq("metadata timeMs decodes as a decimal string", m.timeMs, "1700000000000");
  eq("metadata coreChainLockedHeight decodes", m.coreChainLockedHeight, 7);
  eq("metadata epoch decodes", m.epoch, 3);
  eq("a canonical metadata carrier drops nothing", m.unknownFieldsDropped, 0);
  // BigInt() is what e2ReceiptVerify calls on both; a decimal string must survive it
  ok("height and timeMs survive the verifier's BigInt() call",
    BigInt(m.height) === 42n && BigInt(m.timeMs) === 1700000000000n);

  const p = decodeProofCarrier(prCanonical);
  eq("canonical proof re-encodes to itself", p.reencodedHex, prCanonical);
  eq("proof quorumHashHex decodes", p.quorumHashHex, qh.toString("hex"));
  eq("proof round decodes", p.round, 4);
  eq("a canonical proof carrier drops nothing", p.unknownFieldsDropped, 0);
}

// ---------------------------------------------------------------------------
// 2. REORDERED KNOWN FIELDS. Field order is not semantic in protobuf, so this
//    decodes to exactly the same message and MUST re-encode to the canonical
//    order, which differs from the supplied bytes. This is the case that kills
//    mutation M4 (comparing the re-encoding against a re-encoding of itself
//    rather than against the supplied bytes): a self-comparison accepts this.
// ---------------------------------------------------------------------------
{
  const reordered = hex([
    strField(MD.chainId, CHAIN), varField(MD.pv, 12), varField(MD.timeMs, 1700000000000),
    varField(MD.epoch, 3), varField(MD.cclh, 7), varField(MD.height, 42),
  ]);
  ok("the reordered fixture really is different bytes", reordered !== mdCanonical);
  const m = decodeMetadata(reordered);
  eq("reordered metadata decodes to the SAME message", m.chainId, CHAIN);
  eq("reordered metadata re-encodes to the CANONICAL order", m.reencodedHex, mdCanonical);
  ok("so the re-encoding differs from the supplied bytes, which is the refusal signal",
    m.reencodedHex !== reordered);
}

// ---------------------------------------------------------------------------
// 3. EXPLICIT DEFAULT VALUES. proto3 implicit presence means a zero-valued
//    scalar is omitted by a conforming encoder; writing it explicitly is
//    legal on the wire and decodes identically.
// ---------------------------------------------------------------------------
{
  const withZeroEpoch = hex([
    varField(MD.height, 42), varField(MD.cclh, 7), varField(MD.epoch, 0),
    varField(MD.timeMs, 1700000000000), varField(MD.pv, 12), strField(MD.chainId, CHAIN),
  ]);
  const canonicalZeroEpoch = hex([
    varField(MD.height, 42), varField(MD.cclh, 7),
    varField(MD.timeMs, 1700000000000), varField(MD.pv, 12), strField(MD.chainId, CHAIN),
  ]);
  const m = decodeMetadata(withZeroEpoch);
  eq("an explicitly encoded default decodes to the default", m.epoch, 0);
  eq("and re-encodes with the field OMITTED", m.reencodedHex, canonicalZeroEpoch);
  ok("so an explicit default is detectable as non-canonical", m.reencodedHex !== withZeroEpoch);
  // the empty-bytes default on a length-delimited field, the same rule
  const prEmptyGdb = hex([
    lenField(PR.grovedb, Buffer.alloc(0)), lenField(PR.quorumHash, qh),
    lenField(PR.signature, sig), varField(PR.round, 4),
    lenField(PR.blockIdHash, bid), varField(PR.quorumType, 106),
  ]);
  const pCanonEmptyGdb = hex([
    lenField(PR.quorumHash, qh), lenField(PR.signature, sig), varField(PR.round, 4),
    lenField(PR.blockIdHash, bid), varField(PR.quorumType, 106),
  ]);
  eq("an explicitly encoded empty bytes field re-encodes omitted",
    decodeProofCarrier(prEmptyGdb).reencodedHex, pCanonEmptyGdb);
}

// ---------------------------------------------------------------------------
// 4. DUPLICATE KNOWN FIELDS. For a scalar, protobuf's last-one-wins applies, so
//    a duplicate carries a value the canonical form cannot express twice.
// ---------------------------------------------------------------------------
{
  const dup = hex([
    varField(MD.height, 42), varField(MD.cclh, 7), varField(MD.epoch, 3),
    varField(MD.timeMs, 1700000000000), varField(MD.pv, 12),
    strField(MD.chainId, "decoy"), strField(MD.chainId, CHAIN),
  ]);
  const m = decodeMetadata(dup);
  eq("a duplicated scalar resolves last-one-wins", m.chainId, CHAIN);
  eq("and re-encodes to the single canonical occurrence", m.reencodedHex, mdCanonical);
  ok("so a duplicate is detectable as non-canonical", m.reencodedHex !== dup);
  // the sharp form: the FIRST occurrence is the one a careless reader sees, and
  // it differs from the one that binds. A pipeline reporting the first value
  // would report "decoy" here.
  ok("the surviving value is the LAST, not the first", m.chainId !== "decoy");
}

// ---------------------------------------------------------------------------
// 5. UNKNOWN FIELDS, dropped AND counted. This is the case mutations M1, M2 and
//    M3 all die on. M3 (count only the Proof's unknowns) needs unknowns on the
//    METADATA only, so that case is present explicitly.
// ---------------------------------------------------------------------------
{
  const oneUnknown = hex([
    varField(MD.height, 42), varField(MD.cclh, 7), varField(MD.epoch, 3),
    varField(MD.timeMs, 1700000000000), varField(MD.pv, 12), strField(MD.chainId, CHAIN),
    varField(999, 1),
  ]);
  const m = decodeMetadata(oneUnknown);
  eq("an unknown field is DROPPED from the re-encoding", m.reencodedHex, mdCanonical);
  eq("and COUNTED, exactly", m.unknownFieldsDropped, 1);

  const threeUnknowns = hex([
    varField(MD.height, 42), varField(MD.cclh, 7), varField(MD.epoch, 3),
    varField(MD.timeMs, 1700000000000), varField(MD.pv, 12), strField(MD.chainId, CHAIN),
    varField(999, 1), strField(1000, "padding"), lenField(1001, Buffer.alloc(64, 0x5a)),
  ]);
  const m3 = decodeMetadata(threeUnknowns);
  eq("three unknown entries are dropped", m3.reencodedHex, mdCanonical);
  eq("three unknown entries are counted as three, not as one or as a boolean",
    m3.unknownFieldsDropped, 3);

  // FIXED-WIDTH unknown fields too (the pre-commit checker's mutation: a count
  // handling only varint and length-delimited wire types would pass every case
  // above). Wire type 5 is a 32-bit fixed field, wire type 1 a 64-bit one.
  const fixed32 = (no, bytes4) => Buffer.concat([tag(no, 5), bytes4]);
  const fixed64 = (no, bytes8) => Buffer.concat([tag(no, 1), bytes8]);
  const fixedWidthUnknowns = hex([
    varField(MD.height, 42), varField(MD.cclh, 7), varField(MD.epoch, 3),
    varField(MD.timeMs, 1700000000000), varField(MD.pv, 12), strField(MD.chainId, CHAIN),
    fixed32(1002, Buffer.from([1, 2, 3, 4])), fixed64(1003, Buffer.alloc(8, 0x7e)),
  ]);
  const mFixed = decodeMetadata(fixedWidthUnknowns);
  eq("fixed-width unknown fields (wire types 5 and 1) are dropped", mFixed.reencodedHex, mdCanonical);
  eq("and counted", mFixed.unknownFieldsDropped, 2);

  // the capacity concern the drop exists for: unbounded unknown data must not
  // reach the carrier the receipt has to hold
  ok("a large unknown field does not enlarge the canonical carrier",
    Buffer.from(m3.reencodedHex, "hex").length === Buffer.from(mdCanonical, "hex").length);

  const prUnknown = hex([
    lenField(PR.grovedb, gdb), lenField(PR.quorumHash, qh), lenField(PR.signature, sig),
    varField(PR.round, 4), lenField(PR.blockIdHash, bid), varField(PR.quorumType, 106),
    varField(900, 5), varField(901, 6),
  ]);
  const p = decodeProofCarrier(prUnknown);
  eq("proof unknowns dropped", p.reencodedHex, prCanonical);
  eq("proof unknowns counted", p.unknownFieldsDropped, 2);

  // ---- the TOTAL is across BOTH messages (mutation M3) ----
  const proofMsg = _types.Proof.fromBinary(Buffer.from(prUnknown, "hex"));
  const metaMsg = _types.ResponseMetadata.fromBinary(Buffer.from(threeUnknowns, "hex"));
  const both = canonicalizeCarriers(proofMsg, metaMsg);
  eq("the wrapper's count is the SUM across both carriers (2 proof + 3 metadata)",
    both.unknownFieldsDropped, 5);
  eq("the wrapper's proof re-encoding is canonical", both.proofMsgHex, prCanonical);
  eq("the wrapper's metadata re-encoding is canonical", both.metadataMsgHex, mdCanonical);

  // metadata-only unknowns: a count that ignored the metadata reports 0 here
  const cleanProof = _types.Proof.fromBinary(Buffer.from(prCanonical, "hex"));
  eq("unknowns on the METADATA alone still count (kills a proof-only count)",
    canonicalizeCarriers(cleanProof, metaMsg).unknownFieldsDropped, 3);
  // proof-only unknowns: a count that ignored the proof reports 0 here
  const cleanMeta = _types.ResponseMetadata.fromBinary(Buffer.from(mdCanonical, "hex"));
  eq("unknowns on the PROOF alone still count (kills a metadata-only count)",
    canonicalizeCarriers(proofMsg, cleanMeta).unknownFieldsDropped, 2);
  eq("two clean carriers drop nothing",
    canonicalizeCarriers(cleanProof, cleanMeta).unknownFieldsDropped, 0);

  // NON-MUTATION: encoding must not alter the message the verification stages
  // then read. This is the equivalence the spec's (a) count, (b) encode,
  // (c) verify sequence rests on. Observed at its real width (the pre-commit
  // check named the gap): the second pass checks the retained UNKNOWN entries
  // (the count) AND the KNOWN fields (the re-encoding), so a mutation of either
  // side of the message by the first encode is visible; what this cannot see is
  // a mutation that leaves both the canonical encoding and the unknown count
  // fixed, e.g. rewriting an unknown entry's bytes in place.
  const secondPass = canonicalizeCarriers(proofMsg, metaMsg);
  eq("re-running the canonicalization gives the same count (the unknowns survived the encode)",
    secondPass.unknownFieldsDropped, 5);
  eq("and the same known-field bytes (the known fields survived the encode)",
    secondPass.proofMsgHex + "|" + secondPass.metadataMsgHex, prCanonical + "|" + mdCanonical);
}

// ---------------------------------------------------------------------------
// 6. ENCODE-DECODE-ENCODE IDEMPOTENCE. The canonical form is a fixed point, and
//    a non-canonical input reaches it in ONE step rather than converging over
//    several.
// ---------------------------------------------------------------------------
{
  for (const [name, start] of [["metadata", mdCanonical], ["proof", prCanonical]]) {
    const dec = name === "metadata" ? decodeMetadata : decodeProofCarrier;
    const once = dec(start).reencodedHex;
    const twice = dec(once).reencodedHex;
    const thrice = dec(twice).reencodedHex;
    ok(`${name}: encode-decode-encode is idempotent`, once === twice && twice === thrice);
  }
  // this fixture is deliberately BEYOND what a conforming encoder emits: its
  // final chainId occurrence uses the WRONG WIRE TYPE (varint for a string
  // field). Measured at the installed runtime rather than assumed: that
  // occurrence is NOT recorded as an unknown entry (the unknown list stays
  // empty) and the reader consumes it, leaving the field at its default. The
  // case is about one-step convergence of the canonicalizer on arbitrary
  // decodable input, not about encoder divergence, and it says so.
  const messy = hex([
    strField(MD.chainId, CHAIN), varField(MD.epoch, 0), varField(MD.pv, 12),
    varField(MD.height, 42), varField(999, 1), varField(MD.cclh, 7),
    varField(MD.timeMs, 1700000000000), varField(MD.chainId, 0),
  ]);
  const first = decodeMetadata(messy).reencodedHex;
  const second = decodeMetadata(first).reencodedHex;
  eq("an arbitrary decodable fixture (reordered, defaulted, unknown-bearing, plus a " +
    "wrong-wire-type occurrence) canonicalizes in ONE step", first, second);
}

// ---------------------------------------------------------------------------
// 7. UNDECODABLE INPUT THROWS, which the deps contract defines as "an
//    undecodable carrier" and the verifier turns into a refusal naming the
//    carrier rather than a crash.
// ---------------------------------------------------------------------------
{
  throws("truncated bytes throw", () => decodeMetadata("082a1007180320"), /does not decode|metadataBytes/);
  throws("odd-length hex is refused before decoding", () => decodeMetadata("abc"), /whole bytes/);
  throws("uppercase hex is refused (the contract's hex is lowercase)",
    () => decodeMetadata("082A"), /lowercase hex/);
  throws("a non-string is refused", () => decodeMetadata(Buffer.from("082a", "hex")), /hex string/);
  throws("the proof decoder refuses non-hex too", () => decodeProofCarrier("zz"), /lowercase hex/);
  // an empty carrier DECODES (every field takes its default) and is canonical;
  // it is the verifier's equalities, not this pipeline, that reject it, and
  // saying so here stops a later reader crediting this module with the check
  eq("an empty carrier decodes to the all-default message and is canonical",
    decodeMetadata("").reencodedHex, "");
}

// ---------------------------------------------------------------------------
// 8. THE VACUITY GUARD IS REACHABLE. The module claims the spec's
//    nested-known-message traversal is vacuous because both carriers are
//    entirely scalar. That claim is only worth anything if the guard enforcing
//    it can actually refuse, so it is exercised against a synthetic type.
//    Without this case the guard is untested code asserting an assumption.
// ---------------------------------------------------------------------------
{
  // THE INVOCATION, not only the predicate. The mutation battery deleted both
  // module-level guard calls and every other assertion stayed green, so the
  // guard was observable only by reading the source. It now records its roster.
  eq("the guard was applied to BOTH real carriers at load, in order",
    _guardedTypes.join(","),
    `${_types.Proof.typeName},${_types.ResponseMetadata.typeName}`);
  ok("the roster names the real generated types, not placeholders",
    /Proof$/.test(_types.Proof.typeName) && /ResponseMetadata$/.test(_types.ResponseMetadata.typeName));

  ok("both real carriers are entirely scalar today",
    _types.Proof.fields.every((f) => f.kind === "scalar")
    && _types.ResponseMetadata.fields.every((f) => f.kind === "scalar"));
  throws("a carrier gaining a nested MESSAGE field refuses at construction",
    () => _assertNoNestedMessages({ typeName: "Synthetic",
      fields: [{ name: "a", kind: "scalar" }, { name: "inner", kind: "message" }] }),
    /no longer entirely scalar.*inner:message/);
  throws("a carrier gaining a MAP field refuses too",
    () => _assertNoNestedMessages({ typeName: "Synthetic",
      fields: [{ name: "m", kind: "map" }] }), /no longer entirely scalar/);
  ok("an all-scalar synthetic type passes the guard", (() => {
    try { _assertNoNestedMessages({ typeName: "S", fields: [{ name: "a", kind: "scalar" }] }); return true; }
    catch { return false; }
  })());
}

// ---------------------------------------------------------------------------
// 9. THE DISCRIMINATED BOUNDARY. The spec asks the boundary to be exercised by
//    feeding WRAPPER-PRODUCED results to the classifier rather than testing
//    each module in isolation (E2_BUILD_SPEC.md:252-254). These are the literal
//    builders the mounted patch returns, so a member added or renamed on either
//    side fails here.
// ---------------------------------------------------------------------------
{
  const proofMsg = _types.Proof.fromBinary(Buffer.from(prCanonical, "hex"));
  const metaMsg = _types.ResponseMetadata.fromBinary(Buffer.from(mdCanonical, "hex"));
  const c = canonicalizeCarriers(proofMsg, metaMsg);
  const success = verifiedProof({ proof: proofMsg, metadata: metaMsg,
    proofMsg: c.proofMsgHex, metadataMsg: c.metadataMsgHex,
    unknownFieldsDropped: c.unknownFieldsDropped });

  eq("a wrapper-produced verified-proof classifies success-with-proof",
    classifyOutcome(success), TOKENS.SUCCESS);
  eq("a wrapper-produced execution-refusal classifies to the terminal other-error token",
    classifyOutcome(executionRefusal({ code: 4009, data: "00ff", message: "refused" })), TOKENS.OTHER);
  eq("a wrapper-produced malformed-response classifies ambiguous",
    classifyOutcome(malformedResponse("unexpected oneof")), TOKENS.AMBIGUOUS);
  eq("a wrapper-produced transport-failure classifies ambiguous",
    classifyOutcome(transportFailure("socket closed")), TOKENS.AMBIGUOUS);

  // the classifier's closed-member rule is what makes the contract closed, so
  // prove the wrapper's own literal has EXACTLY the named members and no more
  eq("the verified-proof literal carries exactly its six members",
    Object.keys(success).sort().join(","),
    "metadata,metadataMsg,outcome,proof,proofMsg,unknownFieldsDropped");
  eq("the execution-refusal literal carries exactly its four members",
    Object.keys(executionRefusal({ code: 1, data: "", message: "m" })).sort().join(","),
    "code,data,message,outcome");
  eq("the malformed-response literal carries exactly its two members",
    Object.keys(malformedResponse("r")).sort().join(","), "outcome,reason");
  eq("the transport-failure literal carries exactly its two members",
    Object.keys(transportFailure("r")).sort().join(","), "outcome,reason");

  // the hex the wrapper emits must satisfy the classifier's lowercase-hex
  // predicate, which is the assertion mutation M8 (uppercasing) dies on
  ok("the wrapper's carrier hex is lowercase", /^[0-9a-f]*$/.test(c.proofMsgHex + c.metadataMsgHex));
}

console.log(`e2RawCaptureTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
