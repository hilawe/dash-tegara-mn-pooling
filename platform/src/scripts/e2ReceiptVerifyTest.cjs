/**
 * The receipt verifier's battery: the canonical split and part-set
 * refusals, the carrier-conformance stage's closed negative-class list
 * (reordered known fields, duplicated known fields, explicitly encoded
 * defaults, retained unknown fields, truncated bytes, trailing bytes, and
 * a chain-identifier mismatch, one case per class per stored-carrier kind:
 * receipt, header capture, receipt capture), the lifted-field equalities,
 * the decoded-transfer bindings, the mandatory two stages, the reservation
 * conformance, the capture validity clauses and the pair equality set.
 *
 * HONEST WIDTH: carriers here are canonical JSON in hex and the decoders
 * are mocks implementing the pipeline's CONTRACT (parse, drop unknown
 * fields counted, drop duplicate markers, omit explicit defaults,
 * re-encode canonically). Four classes exercise distinct mock behaviors
 * (reordering, the duplicate marker, the explicit default, the unknown
 * field); TRUNCATED AND TRAILING BYTES both surface as the same decode
 * failure in this mock, and the duplicate class uses a synthetic marker
 * rather than an actual duplicate wire field, because JSON cannot carry
 * one; distinguishing those is the pinned protobuf pipeline's own
 * behavior at acceptance. These cases prove the verifier REFUSES whenever
 * the pipeline reports non-equality or a failed decode, which is the
 * verifier's whole obligation.
 *
 * THE MUTATION LIST WAS WRITTEN BEFORE THESE TESTS (the playbook rule);
 * the commit message records it.
 */
const crypto = require("crypto");
const { canonicalString } = require("./canonicalJson.cjs");
// the PUBLIC surface, and separately the internal stages reached through the
// module's test-only surface. Keeping the two visibly apart is the point: the
// entries return verdicts and are a supported contract, while the stages still
// throw for control flow and are not.
const verifyModule = require("./e2ReceiptVerify.cjs");
const { PART_BOUND_B, verifyReceipt, verifyCaptureRecord, verifyCapturePair } = verifyModule;
const { reassembleProof, verifyCarrierConformance } = verifyModule.__testing;

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) { passed++; } else { failed++; console.error("FAIL:", name); } };
// UNDER THE a review BOUNDARY A REFUSAL IS RETURNED, NEVER THROWN
// (docs/E2_VERIFICATION_BOUNDARY.md), so these assert the returned verdict. A
// public entry that THREW its refusal now fails them, which is the point: the
// audit reads a status off a returned value and must never be handed a
// refusal as an exception.
const rejects = async (name, p, re) => {
  let r;
  try { r = await p; }
  catch (e) {
    failed++; console.error(`FAIL: ${name} (threw instead of returning a verdict: ${(e && e.message) || e})`);
    return;
  }
  ok(name, !!r && r.status === "refused" && re.test(r.reason || ""));
};
const throws = (name, fn, re) => {
  let r;
  try { r = fn(); }
  catch (e) {
    failed++; console.error(`FAIL: ${name} (threw instead of returning a verdict: ${(e && e.message) || e})`);
    return;
  }
  ok(name, !!r && r.status === "refused" && re.test(r.reason || ""));
};
// a DEPENDENCY failure is a FAULT, not evidence: it still throws and must
// propagate out of the entry unchanged
const faults = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no fault; a dependency failure must propagate)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

const CHAIN = "tegara-test-1";
const h32 = (f) => f.repeat(64 / f.length);
const POOL = h32("ab"), ACC = h32("a1"), INCOME = h32("ee"), RECIPIENT = h32("71");
const sha = (hex) => crypto.createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");
const be64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b.toString("hex"); };
const toHex = (s) => Buffer.from(s, "utf8").toString("hex");
const fromHex = (h) => Buffer.from(h, "hex").toString("utf8");

// ---- the mock pinned pipeline: parse JSON, drop unknown fields
// (counted), drop "<k>__dup" duplicate markers, omit the explicit-default
// member pad:"", re-encode canonically (JCS) ----
const PROOF_KNOWN = ["quorumHash", "round", "blockIdHash", "quorumType", "signature", "pad"];
const META_KNOWN = ["chainId", "protocolVersion", "height", "timeMs", "coreChainLockedHeight", "epoch", "pad"];
const mockDecode = (known) => (hex) => {
  const obj = JSON.parse(fromHex(hex)); // throws on truncated or trailing bytes
  const out = {};
  let dropped = 0;
  for (const [k, v] of Object.entries(obj)) {
    if (k.endsWith("__dup")) { dropped += 1; continue; }       // a duplicated known field
    if (!known.includes(k)) { dropped += 1; continue; }        // a retained unknown field
    if (k === "pad" && v === "") continue;                     // an explicitly encoded default
    out[k] = v;
  }
  return { fields: out, unknownFieldsDropped: dropped, reencodedHex: toHex(canonicalString(out)) };
};
const decodeProofRaw = mockDecode(PROOF_KNOWN);
const decodeMetaRaw = mockDecode(META_KNOWN);

const mkDeps = (over = {}) => {
  const calls = { stageOne: [], stageTwo: [] };
  const deps = {
    decodeProofCarrier: (hex) => {
      const d = decodeProofRaw(hex);
      return { reencodedHex: d.reencodedHex, unknownFieldsDropped: d.unknownFieldsDropped,
        quorumHashHex: d.fields.quorumHash, round: d.fields.round };
    },
    decodeMetadata: (hex) => {
      const d = decodeMetaRaw(hex);
      return { reencodedHex: d.reencodedHex, ...d.fields };
    },
    decodeTransfer: (hex) => JSON.parse(fromHex(hex)),
    verifyStageOne: async (args) => {
      calls.stageOne.push(args);
      // the derived root is a FUNCTION of the carrier, so a module that
      // hands stage two anything but stage one's own root is observable
      return (over.stageOne || (() => ({ ok: true, rootHashHex: sha(args.carrierHex),
        provedDocument: over.provedDocument })))(args);
    },
    verifyStageTwo: async (args) => {
      calls.stageTwo.push(args);
      return (over.stageTwo || (() => true))(args);
    },
  };
  deps._calls = calls;
  return deps;
};

// ---- the golden fixtures ----
const proofObj = (padLen) => ({ quorumHash: h32("dd"), round: 3, blockIdHash: h32("bb"),
  quorumType: 4, signature: "cd".repeat(Math.max(1, padLen)) });
const mkCarrier = (padLen) => toHex(canonicalString(proofObj(padLen)));
const META_OBJ = { chainId: CHAIN, protocolVersion: 12, height: "1000",
  timeMs: "1690000000000", coreChainLockedHeight: 777, epoch: 5 };
const META_HEX = toHex(canonicalString(META_OBJ));
const TRANSFER_OBJ = { senderId: INCOME, recipientId: RECIPIENT, amountCredits: "1000", nonce: "7" };
const TRANSFER_HEX = toHex(canonicalString(TRANSFER_OBJ));
const ROW = { accrualId: ACC, amountCredits: "1000", recipientId: RECIPIENT };

// a multipart carrier: L = 2B + 100
const bigCarrier = (() => {
  let padLen = 1;
  let hex = mkCarrier(padLen);
  const wantL = 2 * PART_BOUND_B + 100;
  padLen += wantL - hex.length / 2; // each pad step adds 2 hex chars per byte... adjust by bytes
  hex = mkCarrier(Math.floor(padLen));
  // fine-tune to the exact length
  while (hex.length / 2 < wantL) { padLen += 1; hex = mkCarrier(padLen); }
  while (hex.length / 2 > wantL) { padLen -= 1; hex = mkCarrier(padLen); }
  if (hex.length / 2 !== wantL) throw new Error("could not build the exact multipart carrier length");
  return hex;
})();
const smallCarrier = mkCarrier(4); // well under B: one-part receipt

const splitCarrier = (carrierHex) => {
  const L = carrierHex.length / 2;
  const count = Math.max(1, Math.ceil(L / PART_BOUND_B));
  const proofBytes = carrierHex.slice(0, Math.min(L, PART_BOUND_B) * 2);
  const parts = [];
  for (let i = 1; i < count; i++) {
    parts.push({ poolId: POOL, accrualId: ACC, partIndex: i,
      bytes: carrierHex.slice(i * PART_BOUND_B * 2, Math.min((i + 1) * PART_BOUND_B, L) * 2) });
  }
  return { proofBytes, parts, count };
};

const mkReceipt = (carrierHex, over = {}) => {
  const { proofBytes, parts, count } = splitCarrier(carrierHex);
  return {
    receipt: { poolId: POOL, accrualId: ACC, transitionHash: sha(TRANSFER_HEX),
      transitionBytes: TRANSFER_HEX, proofBytes, proofPartCount: count,
      metadataBytes: META_HEX, blockHeight: be64(1000), coreChainLockedHeight: 777,
      timeMs: be64("1690000000000"), quorumHash: h32("dd"), round: 3, ...(over.receipt || {}) },
    parts: over.parts || parts,
  };
};

const SERVED = { status: "served", doc: { poolId: POOL, accrualId: ACC, transitionHash: sha(TRANSFER_HEX) } };

const verify = (fix, over = {}) => verifyReceipt({
  receipt: fix.receipt, parts: fix.parts,
  reservation: over.reservation || SERVED,
  entitlementRow: over.row || ROW, incomeIdentity: over.income || INCOME,
  chainIdPin: over.chainIdPin || CHAIN, deps: over.deps || mkDeps(over) });

(async () => {

// ---- the golden paths ----
{
  const fix = mkReceipt(bigCarrier);
  const deps = mkDeps();
  const r = await verify(fix, { deps });
  ok("the golden multipart receipt verifies with the reservation proved",
    r.status === "verified" && r.reservationAspect === "proved" && r.carrierHex === bigCarrier);
  ok("stage two received stage one's derived root (the appHash binding)",
    deps._calls.stageTwo.length === 1 && deps._calls.stageTwo[0].rootHashHex === sha(bigCarrier));
  ok("stage one received the exact transition bytes and decoded block info",
    deps._calls.stageOne[0].transitionBytes === TRANSFER_HEX
    && deps._calls.stageOne[0].blockInfo.height === 1000n
    && deps._calls.stageOne[0].blockInfo.coreHeight === 777);
}
{
  const fix = mkReceipt(smallCarrier);
  const r = await verify(fix);
  ok("the golden one-part receipt verifies (no part documents)",
    r.status === "verified" && fix.parts.length === 0 && fix.receipt.proofPartCount === 1);
}

// ---- the canonical split's refusals, THROUGH the verifier ----
{
  const fix = mkReceipt(bigCarrier);
  const shortMid = fix.parts.map((p) => p.partIndex === 1 ? { ...p, bytes: p.bytes.slice(0, -2) } : p);
  await rejects("a non-final part shorter than B refuses",
    verify({ receipt: fix.receipt, parts: shortMid }), /part 1 carries/);
  const longMid = fix.parts.map((p) => p.partIndex === 1 ? { ...p, bytes: p.bytes + "00" } : p);
  await rejects("a non-final part longer than B refuses",
    verify({ receipt: fix.receipt, parts: longMid }), /part 1 carries/);
  // an empty final part makes L a multiple of B, so the canonical count is
  // one lower and the count check itself refuses the class (the final-part
  // domain is subsumed by the ceil relation, which the refusal names)
  const emptyFinal = fix.parts.map((p) => p.partIndex === 2 ? { ...p, bytes: "" } : p);
  await rejects("an empty final part refuses (through the ceil relation)",
    verify({ receipt: fix.receipt, parts: emptyFinal }), /disagrees with the canonical ceil/);
  // a count above the canonical ceil, with a matching served set, hits the
  // ceil check directly
  const padded = [...fix.parts.map((p) => p.partIndex === 2 ? { ...p, bytes: "00".repeat(100) } : p),
    { poolId: POOL, accrualId: ACC, partIndex: 3, bytes: "00".repeat(100) }];
  await rejects("a count disagreeing with ceil(L over B) refuses",
    verify({ receipt: { ...fix.receipt, proofPartCount: 4 }, parts: padded }),
    /disagrees with the canonical ceil/);
  await rejects("a missing part (gap) refuses",
    verify({ receipt: fix.receipt, parts: [fix.parts[1]] }),
    /declares 3 parts .* but 1 part documents|not the contiguous/);
  // the right COUNT with the wrong INDICES binds the contiguity rule on
  // its own (a plain missing part is already caught by the count check)
  const shifted = [{ ...fix.parts[0], partIndex: 2 }, { ...fix.parts[1], partIndex: 3 }];
  await rejects("a part set with the right count but non-contiguous indices refuses",
    verify({ receipt: fix.receipt, parts: shifted }), /not the contiguous/);
  const dup = [fix.parts[0], { ...fix.parts[0] }];
  await rejects("a duplicate part index refuses",
    verify({ receipt: fix.receipt, parts: dup }), /duplicate part index/);
  for (const idx of fix.parts.map((p) => p.partIndex)) {
    const foreignPool = fix.parts.map((p) => p.partIndex === idx ? { ...p, poolId: h32("cd") } : p);
    await rejects(`a foreign-pool part at index ${idx} refuses`,
      verify({ receipt: fix.receipt, parts: foreignPool }), /foreign pool/);
    const foreignAcc = fix.parts.map((p) => p.partIndex === idx ? { ...p, accrualId: h32("cd") } : p);
    await rejects(`a foreign-accrual part at index ${idx} refuses`,
      verify({ receipt: fix.receipt, parts: foreignAcc }), /foreign accrual/);
  }
  // proofBytes must carry the full first chunk in a multipart receipt
  const shortFirst = { ...fix.receipt, proofBytes: fix.receipt.proofBytes.slice(0, -2) };
  await rejects("a first chunk shorter than the canonical split refuses",
    verify({ receipt: shortFirst, parts: fix.parts }), /proofBytes carries|disagrees with the canonical/);
}

// ---- the carrier-conformance stage's closed negative classes, per kind ----
const conformanceVariants = (obj, knownHex) => ({
  // reordered known fields: same members, non-canonical order on the wire
  reordered: toHex(JSON.stringify(Object.fromEntries(Object.entries(obj).reverse()))),
  // a duplicated known field (the wire carried the field twice)
  duplicated: toHex(canonicalString({ ...obj, round__dup: 9 })),
  // an explicitly encoded default value
  explicitDefault: toHex(canonicalString({ ...obj, pad: "" })),
  // a retained unknown field
  unknownField: toHex(canonicalString({ ...obj, zzzUnknown: 1 })),
  // truncated and trailing bytes
  truncated: knownHex.slice(0, -8),
  trailing: knownHex + toHex("!!"),
});
{
  // kind 1: the RECEIPT's Proof carrier (through the one-part path so the
  // variant bytes are the whole carrier)
  const variants = conformanceVariants(proofObj(4), smallCarrier);
  for (const [cls, hex] of Object.entries(variants)) {
    const { proofBytes, parts, count } = splitCarrier(hex);
    const fix = { receipt: { ...mkReceipt(smallCarrier).receipt, proofBytes, proofPartCount: count }, parts };
    await rejects(`receipt carrier class: ${cls} refuses`,
      verify(fix), /not the canonical known-field encoding|does not decode/);
  }
  // the chain-identifier mismatch class (the metadata side)
  const badMeta = toHex(canonicalString({ ...META_OBJ, chainId: "other-chain" }));
  const fix = mkReceipt(smallCarrier);
  await rejects("receipt carrier class: chain-identifier mismatch refuses",
    verify({ receipt: { ...fix.receipt, metadataBytes: badMeta }, parts: fix.parts }),
    /differs from the pinned expected chain identifier/);
  const badVersion = toHex(canonicalString({ ...META_OBJ, protocolVersion: 11 }));
  await rejects("a protocol version other than 12 refuses",
    verify({ receipt: { ...fix.receipt, metadataBytes: badVersion }, parts: fix.parts }),
    /not the pinned 12/);
  const metaVariants = conformanceVariants(META_OBJ, META_HEX);
  await rejects("metadata conformance: a retained unknown field refuses",
    verify({ receipt: { ...fix.receipt, metadataBytes: metaVariants.unknownField }, parts: fix.parts }),
    /metadataBytes is not the canonical known-field encoding/);
}

// ---- the lifted-field equalities ----
{
  const fix = mkReceipt(smallCarrier);
  await rejects("a lifted blockHeight differing from the decoded height refuses",
    verify({ receipt: { ...fix.receipt, blockHeight: be64(1001) }, parts: fix.parts }),
    /lifted blockHeight differs/);
  await rejects("a lifted timeMs differing from the decoded timeMs refuses",
    verify({ receipt: { ...fix.receipt, timeMs: be64("1690000000001") }, parts: fix.parts }),
    /lifted timeMs differs/);
  await rejects("a lifted coreChainLockedHeight differing from the metadata refuses",
    verify({ receipt: { ...fix.receipt, coreChainLockedHeight: 778 }, parts: fix.parts }),
    /lifted coreChainLockedHeight differs/);
  await rejects("a lifted quorumHash differing from the Proof carrier refuses",
    verify({ receipt: { ...fix.receipt, quorumHash: h32("99") }, parts: fix.parts }),
    /lifted quorumHash differs/);
  await rejects("a lifted round differing from the Proof carrier refuses",
    verify({ receipt: { ...fix.receipt, round: 4 }, parts: fix.parts }),
    /lifted round differs/);
}

// ---- the recomputed hash and the decoded-transfer bindings ----
{
  const fix = mkReceipt(smallCarrier);
  await rejects("a transitionHash not recomputable from the bytes refuses",
    verify({ receipt: { ...fix.receipt, transitionHash: h32("11") }, parts: fix.parts },
      { reservation: { status: "served", doc: { poolId: POOL, accrualId: ACC, transitionHash: h32("11") } } }),
    /not SHA-256 of transitionBytes/);
  const badSender = toHex(canonicalString({ ...TRANSFER_OBJ, senderId: h32("99") }));
  await rejects("a decoded sender differing from the income identity refuses",
    verify({ receipt: { ...fix.receipt, transitionBytes: badSender,
      transitionHash: sha(badSender) }, parts: fix.parts },
      { reservation: { status: "served", doc: { poolId: POOL, accrualId: ACC, transitionHash: sha(badSender) } } }),
    /decoded sender differs/);
  const badRecipient = toHex(canonicalString({ ...TRANSFER_OBJ, recipientId: h32("98") }));
  await rejects("a decoded recipient differing from the entitlement's owner refuses",
    verify({ receipt: { ...fix.receipt, transitionBytes: badRecipient,
      transitionHash: sha(badRecipient) }, parts: fix.parts },
      { reservation: { status: "served", doc: { poolId: POOL, accrualId: ACC, transitionHash: sha(badRecipient) } } }),
    /decoded recipient differs/);
  const badAmount = toHex(canonicalString({ ...TRANSFER_OBJ, amountCredits: "1001" }));
  await rejects("a decoded amount differing from the recomputed entitlement refuses",
    verify({ receipt: { ...fix.receipt, transitionBytes: badAmount,
      transitionHash: sha(badAmount) }, parts: fix.parts },
      { reservation: { status: "served", doc: { poolId: POOL, accrualId: ACC, transitionHash: sha(badAmount) } } }),
    /decoded amount differs/);
}

// ---- both stages are mandatory ----
{
  const fix = mkReceipt(smallCarrier);
  await rejects("a failed stage one refuses (no non-null successful result)",
    verify(fix, { stageOne: () => ({ ok: false, rootHashHex: h32("ce") }) }),
    /stage one .* did not return/);
  await rejects("a missing derived root refuses even with ok true",
    verify(fix, { stageOne: () => ({ ok: true }) }), /stage one .* did not return/);
  const deps = mkDeps({ stageTwo: () => false });
  await rejects("a failed stage two refuses even after a successful stage one",
    verify(fix, { deps }), /stage two .* did not verify/);
  ok("stage one had succeeded before stage two refused (both stages ran)",
    deps._calls.stageOne.length === 1 && deps._calls.stageTwo.length === 1);

  // A ROOT MUST BE A ROOT. This required only `typeof === "string"`, so a stage
  // one answering with a non-root string passed it to stage two, and a stage two
  // returning true VERIFIED the record over something that cannot be a state
  // root. A derived root is a 32-byte digest, so 64 lower-case hex characters.
  for (const [what, root] of [["an empty string", ""], ["a non-hex string", "not-a-root"],
    ["a short hex string", "ab".repeat(16)], ["an over-long hex string", "ab".repeat(40)],
    ["upper-case hex", "AB".repeat(32)]]) {
    await rejects(`a stage-one root that is ${what} refuses, even when stage two would verify`,
      verify(fix, { stageOne: () => ({ ok: true, rootHashHex: root }), stageTwo: () => true }),
      /stage one .* did not return/);
  }

  // STAGE TWO ANSWERS WITH THE BOOLEAN true, NOT MERELY SOMETHING TRUTHY. The
  // implementation compares against `true`; the only adverse case here was
  // `false`, so relaxing the comparison to `!stageTwo` went unnoticed and a
  // truthy malformed answer would have verified the record.
  for (const [what, value] of [["the string true", "true"], ["the number 1", 1],
    ["an object", { ok: true }], ["an array", []]]) {
    await rejects(`a stage two answering ${what} refuses (the contract is the boolean, not truthiness)`,
      verify(fix, { stageTwo: () => value }), /stage two .* did not verify/);
  }

  // A MISSING DEPENDENCY IS A FAULT, NOT A STATEMENT ABOUT THE RECORD. This used
  // to answer `{ status: "refused" }` naming the absent decoder, which reads as
  // the record being nonconforming, before any record had been inspected.
  for (const k of ["decodeProofCarrier", "decodeMetadata", "decodeTransfer",
    "verifyStageOne", "verifyStageTwo"]) {
    const holed = { ...mkDeps({}) };
    delete holed[k];
    await faults(`an absent deps.${k} is a hard fault, never a refusal about the record`,
      verifyReceipt({ receipt: fix.receipt, parts: fix.parts,
        reservation: { status: "unserved" }, entitlementRow: fix.entitlementRow,
        incomeIdentity: fix.incomeIdentity, chainIdPin: fix.chainIdPin, deps: holed }),
      /is absent or not a function/);
  }
}

// ---- the reservation conformance ----
{
  const fix = mkReceipt(smallCarrier);
  await rejects("a served reservation with a differing transitionHash refuses",
    verify(fix, { reservation: { status: "served",
      doc: { poolId: POOL, accrualId: ACC, transitionHash: h32("99") } } }), /a soundness-review finding/);
  await rejects("a served reservation with a foreign pool refuses",
    verify(fix, { reservation: { status: "served",
      doc: { poolId: h32("cd"), accrualId: ACC, transitionHash: sha(TRANSFER_HEX) } } }), /a soundness-review finding/);
  await rejects("a served reservation with a foreign accrual refuses",
    verify(fix, { reservation: { status: "served",
      doc: { poolId: POOL, accrualId: h32("cd"), transitionHash: sha(TRANSFER_HEX) } } }), /a soundness-review finding/);
  await rejects("a proved reservation absence refuses",
    verify(fix, { reservation: { status: "proved-absence" } }), /proved reservation absence/);
  const r = await verify(fix, { reservation: { status: "unserved" } });
  ok("an unservable reservation query leaves the aspect UNPROVED, never a pass and never a refusal",
    r.status === "verified" && r.reservationAspect === "unproved");
}

// ---- structural grammar ----
{
  const fix = mkReceipt(smallCarrier);
  const shortTb = toHex("{}");
  await rejects("transitionBytes below the schema floor refuses",
    verify({ receipt: { ...fix.receipt, transitionBytes: shortTb, transitionHash: sha(shortTb) },
      parts: fix.parts }), /outside the schema's 100..2048/);
  await rejects("a proofPartCount above 8 refuses",
    verify({ receipt: { ...fix.receipt, proofPartCount: 9 }, parts: fix.parts }), /1\.\.8/);
  await rejects("metadataBytes above the bound refuses",
    verify({ receipt: { ...fix.receipt, metadataBytes: "ab".repeat(513) }, parts: fix.parts }),
    /outside 1\.\.512/);
}

// ---- the capture-record validity clauses ----
const mkHeaderCapture = (over = {}) => ({ v: 1, kind: "tegara.e2.headerCapture.v1",
  object: "header", gen: 1, poolId: POOL, epochIndex: 5, transitionBytes: TRANSFER_HEX,
  transitionHash: sha(TRANSFER_HEX), proofMsg: smallCarrier, metadataMsg: META_HEX,
  contractId: h32("cc"), expectedDocumentId: h32("dd"),
  expectedContents: { poolId: POOL, epochIndex: 5, grossCredits: 1000, feeCredits: 10,
    allocationHash: h32("ee"), memberCount: 2, calcVersion: 1 },
  inclusionHeight: "1000", heightRoute: "tenderdash-tx", signerIdentity: h32("f0"),
  signerKeyId: 2, sig: "00".repeat(65), ...over });
const HDR_DOC = { documentId: h32("dd"), fields: { poolId: POOL, epochIndex: 5, grossCredits: 1000,
  feeCredits: 10, allocationHash: h32("ee"), memberCount: 2, calcVersion: 1 } };
const SERVED_FOR = { poolId: POOL, epochIndex: 5, contractId: h32("cc") };
{
  const r = await verifyCaptureRecord({ capture: mkHeaderCapture(),
    servedFor: SERVED_FOR, chainIdPin: CHAIN, deps: mkDeps({ provedDocument: HDR_DOC }) });
  ok("the golden header capture passes its validity clauses with the decoded chain id",
    r.status === "verified" && r.decodedChainId === CHAIN);
  await rejects("a proved result under a different document identifier refuses",
    verifyCaptureRecord({ capture: mkHeaderCapture(), servedFor: SERVED_FOR, chainIdPin: CHAIN,
      deps: mkDeps({ provedDocument: { ...HDR_DOC, documentId: h32("99") } }) }),
    /not the header capture's expected document identifier/);
  for (const field of ["poolId", "epochIndex", "grossCredits", "feeCredits",
    "allocationHash", "memberCount", "calcVersion"]) {
    const bad = { ...HDR_DOC.fields, [field]: field === "allocationHash" || field === "poolId"
      ? h32("99") : 999 };
    await rejects(`a proved result differing only in ${field} refuses`,
      verifyCaptureRecord({ capture: mkHeaderCapture(), servedFor: SERVED_FOR, chainIdPin: CHAIN,
        deps: mkDeps({ provedDocument: { ...HDR_DOC, fields: bad } }) }),
      /contents differ/);
  }
  await rejects("a header capture served for a different epoch refuses",
    verifyCaptureRecord({ capture: mkHeaderCapture(), servedFor: { ...SERVED_FOR, epochIndex: 6 },
      chainIdPin: CHAIN, deps: mkDeps({ provedDocument: HDR_DOC }) }), /epoch differs/);
  await rejects("a header capture under a foreign contract identifier refuses",
    verifyCaptureRecord({ capture: mkHeaderCapture(), servedFor: { ...SERVED_FOR, contractId: h32("77") },
      chainIdPin: CHAIN, deps: mkDeps({ provedDocument: HDR_DOC }) }), /contract identifier differs/);
  await rejects("a capture hash not recomputable from its bytes refuses",
    verifyCaptureRecord({ capture: mkHeaderCapture({ transitionHash: h32("11") }),
      servedFor: SERVED_FOR, chainIdPin: CHAIN, deps: mkDeps({ provedDocument: HDR_DOC }) }),
    /not SHA-256/);
  await rejects("an inclusionHeight with a leading zero refuses BEFORE any comparison",
    verifyCaptureRecord({ capture: mkHeaderCapture({ inclusionHeight: "0123" }),
      servedFor: SERVED_FOR, chainIdPin: CHAIN, deps: mkDeps({ provedDocument: HDR_DOC }) }),
    /canonical non-negative decimal/);
  await rejects("a heightRoute outside the registry refuses",
    verifyCaptureRecord({ capture: mkHeaderCapture({ heightRoute: "other" }),
      servedFor: SERVED_FOR, chainIdPin: CHAIN, deps: mkDeps({ provedDocument: HDR_DOC }) }),
    /outside the allowed route registry/);
  // the FULL closed class list for the header-capture kind (the spec's
  // one-case-per-class-per-kind rule)
  const variants = conformanceVariants(proofObj(4), smallCarrier);
  for (const [cls, hex] of Object.entries(variants)) {
    await rejects(`header-capture carrier class: ${cls} refuses`,
      verifyCaptureRecord({ capture: mkHeaderCapture({ proofMsg: hex }),
        servedFor: SERVED_FOR, chainIdPin: CHAIN, deps: mkDeps({ provedDocument: HDR_DOC }) }),
      /not the canonical known-field encoding|does not decode/);
  }
  await rejects("header-capture carrier class: chain-identifier mismatch refuses",
    verifyCaptureRecord({ capture: mkHeaderCapture({
      metadataMsg: toHex(canonicalString({ ...META_OBJ, chainId: "other-chain" })) }),
      servedFor: SERVED_FOR, chainIdPin: CHAIN, deps: mkDeps({ provedDocument: HDR_DOC }) }),
    /differs from the pinned expected chain identifier/);
}
const mkReceiptCapture = (over = {}) => ({ v: 1, kind: "tegara.e2.receiptCapture.v1",
  object: "transfer", gen: 1, poolId: POOL, epochIndex: 5, accrualId: ACC,
  transitionHash: sha(TRANSFER_HEX), transitionBytes: TRANSFER_HEX,
  proofMsg: smallCarrier, metadataMsg: META_HEX, inclusionHeight: "1001",
  heightRoute: "tenderdash-tx", signerIdentity: h32("f0"), signerKeyId: 2,
  sig: "00".repeat(65), ...over });
{
  const r = await verifyCaptureRecord({ capture: mkReceiptCapture(),
    servedFor: { poolId: POOL, accrualId: ACC }, chainIdPin: CHAIN, deps: mkDeps() });
  ok("the golden receipt capture passes its validity clauses", r.status === "verified");
  await rejects("a capture served for a different pool refuses",
    verifyCaptureRecord({ capture: mkReceiptCapture(), servedFor: { poolId: h32("cd"), accrualId: ACC },
      chainIdPin: CHAIN, deps: mkDeps() }), /pool differs/);
  await rejects("a receipt capture served for a different accrual refuses",
    verifyCaptureRecord({ capture: mkReceiptCapture(), servedFor: { poolId: POOL, accrualId: h32("cd") },
      chainIdPin: CHAIN, deps: mkDeps() }), /accrualId differs/);
  // the FULL closed class list for the receipt-capture kind
  const variants = conformanceVariants(proofObj(4), smallCarrier);
  for (const [cls, hex] of Object.entries(variants)) {
    await rejects(`receipt-capture carrier class: ${cls} refuses`,
      verifyCaptureRecord({ capture: mkReceiptCapture({ proofMsg: hex }),
        servedFor: { poolId: POOL, accrualId: ACC }, chainIdPin: CHAIN, deps: mkDeps() }),
      /not the canonical known-field encoding|does not decode/);
  }
  await rejects("receipt-capture carrier class: chain-identifier mismatch refuses",
    verifyCaptureRecord({ capture: mkReceiptCapture({
      metadataMsg: toHex(canonicalString({ ...META_OBJ, chainId: "other-chain" })) }),
      servedFor: { poolId: POOL, accrualId: ACC }, chainIdPin: CHAIN, deps: mkDeps() }),
    /differs from the pinned expected chain identifier/);
}

// ---- the capture-versus-receipt pair equality, over the two
// verification RESULTS (a caller cannot hand it loose values) ----
{
  const fix = mkReceipt(smallCarrier);
  const capture = mkReceiptCapture();
  const receiptResult = await verify(fix);
  const captureResult = await verifyCaptureRecord({ capture,
    servedFor: { poolId: POOL, accrualId: ACC }, chainIdPin: CHAIN, deps: mkDeps() });
  const okPair = verifyCapturePair({ capture, receipt: fix.receipt, receiptResult, captureResult });
  ok("the golden pair's byte-equality set passes over the two results", okPair.status === "verified");
  // the per-member inequalities need GENUINE differing subjects, each
  // with its OWN verification result (a doctored capture with a borrowed
  // result is caught by the subject digest instead, tested below)
  const pairGenuine = async (capOver, re) => {
    const cap2 = mkReceiptCapture(capOver);
    const capRes2 = await verifyCaptureRecord({ capture: cap2,
      servedFor: { poolId: POOL, accrualId: ACC }, chainIdPin: CHAIN, deps: mkDeps() });
    throws(`a genuinely verified capture over a different ${re} refuses`,
      () => verifyCapturePair({ capture: cap2, receipt: fix.receipt,
        receiptResult, captureResult: capRes2 }), new RegExp(`${re} differ`));
  };
  const otherTransfer = toHex(canonicalString({ ...TRANSFER_OBJ, nonce: "8" }));
  await pairGenuine({ transitionBytes: otherTransfer, transitionHash: sha(otherTransfer) },
    "transitionBytes");
  await pairGenuine({ proofMsg: mkCarrier(5) }, "proofMsg");
  const otherMeta = toHex(canonicalString({ ...META_OBJ, epoch: 6 }));
  await pairGenuine({ metadataMsg: otherMeta }, "metadataMsg");
  // a caller-EDITED copy of a genuine result is a caller-built object, so it
  // is refused on ORIGIN before any member is compared (a soundness-review finding). The chain
  // equality itself is exercised below through two GENUINE results.
  throws("an edited copy of a genuine result is not this module's result",
    () => verifyCapturePair({ capture, receipt: fix.receipt, receiptResult,
      captureResult: { ...captureResult, decodedChainId: "other" } }),
    /THIS MODULE returned from verifyCaptureRecord/);
  throws("loose values in place of verifyReceipt's result refuse",
    () => verifyCapturePair({ capture, receipt: fix.receipt,
      receiptResult: { carrierHex: smallCarrier }, captureResult }),
    /THIS MODULE returned from verifyReceipt/);
  // THE SUBJECT BINDING (the re-check's F6): a GENUINE result produced
  // for a different subject cannot stand in, in either position
  {
    const fix2 = mkReceipt(mkCarrier(6));
    const otherReceiptResult = await verify(fix2);
    throws("a genuine receipt result from a different receipt refuses (the subject digest)",
      () => verifyCapturePair({ capture, receipt: fix.receipt,
        receiptResult: otherReceiptResult, captureResult }),
      /produced for a different receipt/);
    const cap3 = mkReceiptCapture({ proofMsg: mkCarrier(6) });
    const capRes3 = await verifyCaptureRecord({ capture: cap3,
      servedFor: { poolId: POOL, accrualId: ACC }, chainIdPin: CHAIN, deps: mkDeps() });
    throws("a genuine capture result from a different capture refuses (the subject digest)",
      () => verifyCapturePair({ capture, receipt: fix.receipt,
        receiptResult, captureResult: capRes3 }),
      /produced for a different capture/);
  }
  // the digest COVERS the hash: a supplied record whose transitionHash
  // alone differs from the record that produced its genuine result
  // refuses through the exported pair (the closing pass's catch)
  throws("a receipt whose hash alone differs from its result's subject refuses",
    () => verifyCapturePair({ capture, receipt: { ...fix.receipt, transitionHash: h32("77") },
      receiptResult, captureResult }), /produced for a different receipt/);
  throws("a capture whose hash alone differs from its result's subject refuses",
    () => verifyCapturePair({ capture: { ...capture, transitionHash: h32("77") },
      receipt: fix.receipt, receiptResult, captureResult }),
    /produced for a different capture/);
  // the composite entry runs both verifications for the exact inputs
  const composite = await (require("./e2ReceiptVerify.cjs").verifyReceiptWithCapture)({
    capture, servedFor: { poolId: POOL, accrualId: ACC }, receipt: fix.receipt,
    parts: fix.parts, reservation: SERVED, entitlementRow: ROW,
    incomeIdentity: INCOME, chainIdPin: CHAIN, deps: mkDeps() });
  ok("the composite entry verifies both subjects and their pair in one call",
    composite.status === "verified" && composite.reservationAspect === "proved");
  const otherTransfer2 = toHex(canonicalString({ ...TRANSFER_OBJ, nonce: "9" }));
  await rejects("the composite entry refuses a mismatched pair (its pair stage binds)",
    (require("./e2ReceiptVerify.cjs").verifyReceiptWithCapture)({
      capture: mkReceiptCapture({ transitionBytes: otherTransfer2,
        transitionHash: sha(otherTransfer2) }),
      servedFor: { poolId: POOL, accrualId: ACC }, receipt: fix.receipt,
      parts: fix.parts, reservation: SERVED, entitlementRow: ROW,
      incomeIdentity: INCOME, chainIdPin: CHAIN, deps: mkDeps() }),
    /transitionBytes differ/);
  // AL2/AL3: the composite must surface the RECEIPT's own refusal
  // reason, not a downstream pair-check reason. Calling the wrapped entries
  // internally would still end in a refusal, so only the REASON distinguishes
  // the two, which is exactly what a caller reads.
  {
    // a MULTIPART fixture, so a malformed part exists to refuse on
    const mFix = mkReceipt(bigCarrier);
    const mCap = mkReceiptCapture({ proofMsg: bigCarrier });
    const badParts = mFix.parts.map((pt) => pt.partIndex === 1 ? { ...pt, bytes: pt.bytes.slice(0, -2) } : pt);
    const r = await (require("./e2ReceiptVerify.cjs").verifyReceiptWithCapture)({
      capture: mCap, servedFor: { poolId: POOL, accrualId: ACC }, receipt: mFix.receipt,
      parts: badParts, reservation: SERVED, entitlementRow: ROW,
      incomeIdentity: INCOME, chainIdPin: CHAIN, deps: mkDeps() });
    ok("the composite surfaces the RECEIPT's own refusal reason, not a downstream one",
      r.status === "refused" && /part 1 carries/.test(r.reason));
  }
  // the exported pair check must REFUSE a non-verified verdict rather than
  // read its members: a refused or unproved result has no carrierHex to trust
  {
    // the verdict is carried by STATUS ALONE, so these results keep every
    // member a verified one has and differ ONLY in the discriminator. A check
    // that inspected members instead of the status would pass them.
    // a copy carrying every member of a genuine result but a refused status
    // is still a caller-built object, and origin is checked first
    const refusedReceipt = { ...receiptResult, status: "refused",
      reason: "e2ReceiptVerify: contrived; refusing" };
    throws("a copied result with a refused status is refused (origin is checked before shape)",
      () => verifyCapturePair({ capture, receipt: fix.receipt,
        receiptResult: refusedReceipt, captureResult }),
      /THIS MODULE returned from verifyReceipt/);
    const refusedCapture = { ...captureResult, status: "refused",
      reason: "e2ReceiptVerify: contrived; refusing" };
    throws("a copied capture result with a refused status is refused too",
      () => verifyCapturePair({ capture, receipt: fix.receipt,
        receiptResult, captureResult: refusedCapture }),
      /THIS MODULE returned from verifyCaptureRecord/);
    // AND THE FINDING ITSELF (a soundness-review finding): a fully caller-constructed pair, with
    // the advertised subject digests computed from values the caller supplies,
    // must NOT return a verified verdict. Before the returned-value brand this
    // printed {"status":"verified"} with no verifier having run.
    const builtR = { status: "verified", carrierHex: receiptResult.carrierHex,
      decoded: { chainId: CHAIN }, subjectDigest: receiptResult.subjectDigest };
    const builtC = { status: "verified", decodedChainId: CHAIN,
      subjectDigest: captureResult.subjectDigest };
    throws("a fully caller-constructed pair with correct digests is refused (a soundness-review finding)",
      () => verifyCapturePair({ capture, receipt: fix.receipt,
        receiptResult: builtR, captureResult: builtC }),
      /THIS MODULE returned from verifyReceipt/);
  }
  await rejects("a non-capture record kind refuses the capture clauses",
    verifyCaptureRecord({ capture: { ...capture, kind: "tegara.e2.journal.error.v1" },
      servedFor: { poolId: POOL, accrualId: ACC }, chainIdPin: CHAIN, deps: mkDeps() }),
    /not a capture kind/);

  // ---- THE PUBLIC SURFACE IS PINNED ----
  // Only the four entries that RETURN verdicts are public, plus the pinned
  // constants. The internal stages still THROW for control flow, so leaving them
  // public gave outside code a supported way to obtain a genuine instance of this
  // module's private refusal class, which made the returned-verdict claim wider
  // than the code. Stating the surface literally means widening it is a decision
  // rather than a side effect of adding an export.
  {
    const PUBLIC = ["PART_BOUND_B", "ROUTE_REGISTRY", "PROTOCOL_VERSION_PIN",
      "verifyReceipt", "verifyCaptureRecord", "verifyCapturePair",
      "verifyReceiptWithCapture", "__testing"].sort();
    const actual = Object.keys(verifyModule).sort();
    ok("the verifier exports exactly the four entries, the pinned constants, and the test surface",
      JSON.stringify(actual) === JSON.stringify(PUBLIC));
    if (JSON.stringify(actual) !== JSON.stringify(PUBLIC)) {
      console.error("   surface drift:", JSON.stringify(actual));
    }
    ok("no throwing internal stage sits on the public surface",
      !["assertCanonicalSplit", "reassembleProof", "verifyCarrierConformance"]
        .some((k) => k in verifyModule));
    ok("the test-only surface still carries the stages this suite drives",
      typeof verifyModule.__testing.reassembleProof === "function"
      && typeof verifyModule.__testing.verifyCarrierConformance === "function");
    // and it carries NOTHING ELSE. assertCanonicalSplit was exported here and no
    // suite ever drove it, so it was a contract defended for nobody; it is used
    // internally and stays that way. Pinned so it cannot drift back unnoticed.
    ok("the test-only surface is exactly the two stages this suite drives",
      Object.keys(verifyModule.__testing).sort().join(",")
        === "reassembleProof,verifyCarrierConformance");
  }
  {
    // THE EXPORTED PINS MUST BE THE ONES THE VERIFIER ENFORCES. The suite checked
    // only that the NAMES were present, so a published value disagreeing with the
    // enforced one would have gone unnoticed, and a consumer reading the export
    // would have been told something the verifier does not do. Each is bound here
    // to the refusal the verifier actually raises.
    const fix = mkReceipt(smallCarrier);
    const badPv = await verify(fix, { deps: { ...mkDeps(),
      decodeMetadata: (h) => ({ ...mkDeps().decodeMetadata(h), protocolVersion: 999 }) } });
    ok("the exported protocol pin is the value the verifier enforces",
      badPv.status === "refused"
      && badPv.reason.includes(`is not the pinned ${verifyModule.PROTOCOL_VERSION_PIN}`));
    ok("the exported route registry is the set the verifier accepts, and it is frozen",
      Object.isFrozen(verifyModule.ROUTE_REGISTRY)
      && verifyModule.ROUTE_REGISTRY.length >= 1);
    const badRoute = await verifyCaptureRecord({ capture: { ...capture, heightRoute: "not-a-route" },
      servedFor: { poolId: POOL, accrualId: ACC }, chainIdPin: CHAIN, deps: mkDeps() });
    ok("a route outside the exported registry refuses, naming the registry",
      badRoute.status === "refused" && /route registry/.test(badRoute.reason)
      && !verifyModule.ROUTE_REGISTRY.includes("not-a-route"));
  }

  // ---- THE VERDICT UNION IS CLOSED AT TWO ----
  // The documented contract promised a third top-level status, `unproved`, that
  // no path produced. That is now corrected in both directions: the document
  // says two, and this pins it, so the two cannot drift apart again. What is
  // genuinely unsettled is carried PER ASPECT instead, which the reservation
  // case below shows on an otherwise verified receipt.
  {
    const seen = new Set();
    const collect = (r) => { if (r && typeof r.status === "string") seen.add(r.status); return r; };
    collect(await verify(fix));                                     // verified
    collect(await verify({ receipt: fix.receipt, parts: [] }));      // refused
    collect(await verifyCaptureRecord({ capture, servedFor: { poolId: POOL, accrualId: ACC },
      chainIdPin: CHAIN, deps: mkDeps() }));                        // verified
    collect(await verifyCaptureRecord({ capture: { ...capture, heightRoute: "other" },
      servedFor: { poolId: POOL, accrualId: ACC }, chainIdPin: CHAIN, deps: mkDeps() }));
    collect(verifyCapturePair({ capture, receipt: fix.receipt,
      receiptResult: { status: "verified" }, captureResult: { status: "verified" } }));
    ok("every top-level verdict is one of exactly two statuses, verified or refused",
      [...seen].sort().join(",") === "refused,verified");
    if ([...seen].sort().join(",") !== "refused,verified") {
      console.error("   statuses seen:", JSON.stringify([...seen]));
    }
    // and unprovedness lives on the ASPECT, not the verdict: an unservable
    // reservation query leaves the receipt VERIFIED with that aspect unproved
    const rUnproved = await verify(fix, { reservation: { status: "unserved" } });
    ok("an unservable reservation leaves the receipt VERIFIED with the aspect unproved",
      rUnproved.status === "verified" && rUnproved.reservationAspect === "unproved");
  }

  // ---- THE FAULT SIDE OF THE BOUNDARY ----
  // The contract has two halves and the suite previously gated only one. A
  // REFUSAL is returned, and the tests above establish that. A DEPENDENCY
  // FAILURE is a FAULT: it propagates out of the entry unchanged, is never
  // converted into a verdict, and so can never read as evidence about a
  // member's records. A broken proof helper says nothing about whether a
  // receipt conforms.
  for (const stage of ["stageOne", "stageTwo"]) {
    await faults(`a throwing ${stage} propagates as a fault, never a verdict`,
      verify(fix, { deps: mkDeps({ [stage]: () => { throw new Error("the proof helper is offline"); } }) }),
      /the proof helper is offline/);
  }
  await faults("a throwing proof stage propagates through the capture entry too",
    verifyCaptureRecord({ capture, servedFor: { poolId: POOL, accrualId: ACC },
      chainIdPin: CHAIN,
      deps: mkDeps({ stageOne: () => { throw new Error("the proof helper is offline"); } }) }),
    /the proof helper is offline/);
  // the DECODERS are the one specified exception: an undecodable carrier is a
  // statement about the carrier, so a decoder throw becomes a returned refusal
  for (const decoder of ["decodeProofCarrier", "decodeMetadata", "decodeTransfer"]) {
    await rejects(`a throwing ${decoder} is EVIDENCE, returned as a refusal naming the decode`,
      verify(fix, { deps: { ...mkDeps(), [decoder]: () => { throw new Error("bad bytes"); } } }),
      /does not decode/);
  }
  // AND EACH REFUSAL IS A FRESH OBJECT. The boundary says the decoder failure is
  // converted into a NEW refusal inside the verifier's own frame, and nothing
  // bound that: a review's mutation cached refusals by reason and handed the
  // same object back for repeated failures, with every suite still green. A
  // shared result is a value two callers can both hold and one can mutate, which
  // is the kind of aliasing this boundary exists to keep out.
  {
    const boom = { deps: { ...mkDeps(), decodeProofCarrier: () => { throw new Error("bad bytes"); } } };
    const r1 = await verify(fix, boom);
    const r2 = await verify(fix, boom);
    ok("two decode refusals carry the same reason", r1.reason === r2.reason);
    ok("but they are DISTINCT objects, freshly built per failure (never a cached one)",
      r1 !== r2);
    r1.status = "verified"; // a caller mutating its own copy
    ok("mutating one refusal cannot reach the other", r2.status === "refused");
  }
  // AND THE FORMATTING OF WHAT THEY THREW MUST BE TOTAL. Each decoder catch
  // interpolates the caught value into the refusal it raises, so a value that
  // resists inspection must not turn that refusal into a SECONDARY fault. This
  // gate lived in the audit suite and was deleted with the block around it
  // during the review redesign; the restored battery caught its absence,
  // which is the battery doing its job. It belongs here, beside the decoders.
  for (const decoder of ["decodeProofCarrier", "decodeMetadata", "decodeTransfer"]) {
    for (const [what, make] of [
      ["a null-prototype object", () => Object.create(null)],
      ["an object whose message getter throws", () => {
        const e = {};
        Object.defineProperty(e, "message", { get() { throw new Error("the message read must not decide this"); } });
        return e; }],
      ["a revoked proxy", () => { const r = Proxy.revocable({}, {}); r.revoke(); return r.proxy; }],
    ]) {
      const thrown = make();
      await rejects(`${decoder} throwing ${what} still returns the decode refusal, never a secondary fault`,
        verify(fix, { deps: { ...mkDeps(), [decoder]: () => { throw thrown; } } }),
        /does not decode/);
    }
  }
}

console.log(`e2ReceiptVerifyTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
})().catch((e) => { console.error("UNCAUGHT:", e); process.exitCode = 1; });
