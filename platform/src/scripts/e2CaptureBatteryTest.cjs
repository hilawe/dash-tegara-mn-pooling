/**
 * Offline test for the two-phase capture battery (plain `node`, no network):
 * the splitter against the VERIFIER's reassembly (a cross-module oracle), the
 * D1/D3 coverage assertions, the gate artifact's closed canonical format, the
 * write-once dichotomy on the real env store (identical retry idempotent,
 * conflicting concurrent write refused, deletion refused), the strict
 * lookup's refusals and its byte-normalized identifier rule, BOTH phase
 * drivers over mocked deps (gate completion proved BEFORE any receipt
 * exists), and the probe-contract publisher's byte-identity and refusals.
 *
 * The LIVE halves (real fixture writes, the real transfer and header
 * captures) run in the container against the probe contract; this file proves
 * ORCHESTRATION, every refusal, and that the gate key is written exactly when
 * the canonical capture verifies, never before. Signatures here are REAL
 * (noble secp256k1 through e2CaptureRecord's own signer), so clause-1 cases
 * exercise the true verification path; only the clause-3 stages are mocked at
 * the verifier's deps seam, the same seam every offline verifier case uses.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

// the env store is pointed at a throwaway file BEFORE any module loads it
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "e2battery-"));
process.env.TEGARA_ENV_PATH = path.join(TMP, ".env.test");
fs.writeFileSync(process.env.TEGARA_ENV_PATH, "");
fs.mkdirSync(process.env.TEGARA_ENV_PATH + ".state", { recursive: true });

const battery = require("./e2CaptureBattery.cjs");
const probeContract = require("./e2ProbeContract.cjs");
const captureRecord = require("./e2CaptureRecord.cjs");
const receiptVerify = require("./e2ReceiptVerify.cjs");
const envStore = require("./envStore.cjs");
const { canonicalString } = require("./canonicalJson.cjs");
const { buildV11, E2_TYPES } = require("./contractV11.cjs");
const bs58 = require("bs58");

const { D1_BOUNDS, GATE_KEY, CAPTURE_KIND, PRE_REGISTRATION_ROSTER, CANONICAL_ROSTER,
  splitCarrier, assertD1Coverage, buildGateArtifact, parseGateArtifact,
  verifyGateCapture, runPreRegistrationPhase, runCanonicalPhase } = battery;

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const eq = (name, got, want) => {
  if (got === want) passed++;
  else { failed++; console.error(`FAIL: ${name}\n  got:  ${got}\n  want: ${want}`); }
};
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

const B = D1_BOUNDS.B;
const POOL = "11".repeat(32);
const ACCR = "22".repeat(32);
// one 32-byte identifier in BOTH spellings, for the normalization cases
const ID_BYTES = Buffer.alloc(32, 0x7e);
const ID_HEX = ID_BYTES.toString("hex");
const ID_B58 = bs58.encode(ID_BYTES);

(async () => {

// REAL keys through the same curve library the capture module signs with
const { secp256k1 } = await import("@noble/curves/secp256k1.js");
const { secretKey: SECRET, publicKey: PUBKEY } = secp256k1.keygen(); // compressed 33-byte public
const resolveSignerKey = async () => PUBKEY;

// ---------------------------------------------------------------------------
// 1. THE SPLITTER, its bounds, and the verifier's reassembly as the oracle
// ---------------------------------------------------------------------------
{
  for (const L of [1, 37, B - 1, B, B + 1, 2 * B + 4, 5 * B, 7 * B + 1, 3 * B + 17, 8 * B - 1, 8 * B]) {
    const carrier = crypto.randomBytes(L).toString("hex");
    const s = splitCarrier(carrier);
    eq(`split(${L}): partCount is the canonical ceil`, s.proofPartCount, Math.ceil(L / B));
    const back = receiptVerify.__testing.reassembleProof(
      { proofBytes: s.proofBytes, proofPartCount: s.proofPartCount, poolId: POOL, accrualId: ACCR },
      s.parts.map((p) => ({ partIndex: p.partIndex, bytes: p.bytes, poolId: POOL, accrualId: ACCR })));
    ok(`split(${L}): the VERIFIER reassembles byte-identically`, back === carrier);
  }
  throws("an empty carrier refuses", () => splitCarrier(""), /refuses an empty carrier/);
  throws("8B+1 refuses rather than truncates", () => splitCarrier("00".repeat(8 * B + 1)),
    /exceeds the 8-part capacity/);
  throws("non-hex refuses", () => splitCarrier("zz"), /lowercase hex/);
  // the chunk boundaries carry the RIGHT bytes, pinned directly: a splitter
  // that repeated or shifted a chunk while keeping the count would also fail
  // the reassembly oracle, and this case names the boundary positions
  const marked = Buffer.alloc(2 * B + 3);
  marked[0] = 1; marked[B] = 2; marked[2 * B] = 3;
  const s = splitCarrier(marked.toString("hex"));
  ok("the chunk boundaries carry the marked bytes (0, B, 2B)",
    s.proofBytes.slice(0, 2) === "01" && s.parts[0].bytes.slice(0, 2) === "02"
    && s.parts[1].bytes.slice(0, 2) === "03");
}

// ---------------------------------------------------------------------------
// 2. THE D1/D3 COVERAGE ASSERTIONS are real comparisons, not decoration
// ---------------------------------------------------------------------------
{
  const r = assertD1Coverage({ chainIdByteLength: 17 });
  eq("coverage returns one row per assertion", r.length, 3);
  ok("every row holds for the live figures", r.every((x) => x.holds));
  // the varint boundary, derived INDEPENDENTLY of the module's helper: at
  // L = 127 the derived max is 40+1+1+127 = 169; at L = 128 the length prefix
  // takes two bytes, 40+1+2+128 = 171 (a collapsed one-byte formula gives 170,
  // which is the pre-commit check's undercount)
  const row = (L) => assertD1Coverage({ chainIdByteLength: L })[0].detail;
  ok("L=127 derives 169 (one-byte length prefix)", / = 169 <= /.test(row(127)));
  ok("L=128 derives 171, not 170 (two-byte length prefix)", / = 171 <= /.test(row(128)));
  // the refusal boundary under the CORRECT formula: L=469 -> 40+1+2+469=512
  // covered; L=470 -> 513 refused
  ok("L=469 is exactly covered", / = 512 <= 512/.test(row(469)));
  throws("L=470 FAILS coverage (513 > 512)",
    () => assertD1Coverage({ chainIdByteLength: 470 }), /metadata capacity/);
  throws("a missing length refuses", () => assertD1Coverage({}), /chainId byte length/);
}

// ---------------------------------------------------------------------------
// 3. THE GATE ARTIFACT: closed format, canonical bytes, parse refusals
// ---------------------------------------------------------------------------
{
  const digest = crypto.createHash("sha256").update("x").digest("hex");
  const raw = buildGateArtifact({ contractId: ID_B58, poolId: POOL, epochIndex: 0, gen: 1, preimageDigest: digest });
  const v = parseGateArtifact(raw);
  eq("the artifact round-trips through its parser", canonicalString(v), raw);
  eq("captureKey.kind is the literal", v.captureKey.kind, CAPTURE_KIND);
  throws("a missing captureKey member refuses",
    () => parseGateArtifact(canonicalString({ contractId: ID_B58,
      captureKey: { kind: CAPTURE_KIND, object: "header", poolId: POOL, epochIndex: 0 },
      preimageDigest: digest })), /members must be exactly kind, object, poolId, epochIndex, gen/);
  throws("an extra top-level member refuses",
    () => parseGateArtifact(canonicalString({ contractId: ID_B58, extra: 1,
      captureKey: { kind: CAPTURE_KIND, object: "header", poolId: POOL, epochIndex: 0, gen: 1 },
      preimageDigest: digest })), /members must be exactly contractId, captureKey, preimageDigest/);
  throws("a wrong kind literal refuses",
    () => parseGateArtifact(canonicalString({ contractId: ID_B58,
      captureKey: { kind: "tegara.e2.receiptCapture.v1", object: "header", poolId: POOL, epochIndex: 0, gen: 1 },
      preimageDigest: digest })), /kind must be the literal/);
  throws("an empty contractId refuses",
    () => parseGateArtifact(canonicalString({ contractId: "",
      captureKey: { kind: CAPTURE_KIND, object: "header", poolId: POOL, epochIndex: 0, gen: 1 },
      preimageDigest: digest })), /contractId must be a nonempty string/);
  throws("gen 0 refuses",
    () => buildGateArtifact({ contractId: ID_B58, poolId: POOL, epochIndex: 0, gen: 0, preimageDigest: digest }),
    /gen/);
  throws("whitespace padding refuses (the raw bytes are not canonical)",
    () => parseGateArtifact(raw + " "), /not valid JSON|not the canonical serialization/);
  // a reordered spelling of the SAME value: JSON.parse normalizes key order in
  // representation, so the refusal must come from the raw-bytes equality
  const reordered = `{"preimageDigest":"${digest}","contractId":"${JSON.parse(raw).contractId}","captureKey":${JSON.stringify(v.captureKey)}}`;
  ok("the reordered spelling is different bytes", reordered !== raw);
  throws("a non-canonical member order refuses",
    () => parseGateArtifact(reordered), /not the canonical serialization/);
}

// ---------------------------------------------------------------------------
// 4. THE WRITE-ONCE DICHOTOMY on the REAL env store (concurrent-start
//    handling: identical retry idempotent, differing digest refused)
// ---------------------------------------------------------------------------
{
  const digest = crypto.createHash("sha256").update("first").digest("hex");
  const raw = buildGateArtifact({ contractId: ID_B58, poolId: POOL, epochIndex: 3, gen: 1, preimageDigest: digest });
  envStore.updateEnvKey(GATE_KEY, raw);
  eq("the gate key is set", envStore.loadEnv()[GATE_KEY], raw);
  envStore.updateEnvKey(GATE_KEY, raw); // the identical retry
  eq("an identical retry is an idempotent success", envStore.loadEnv()[GATE_KEY], raw);
  const other = buildGateArtifact({ contractId: ID_B58, poolId: POOL, epochIndex: 3, gen: 1,
    preimageDigest: crypto.createHash("sha256").update("second").digest("hex") });
  throws("a conflicting concurrent write REFUSES and never overwrites",
    () => envStore.updateEnvKey(GATE_KEY, other), /write-once and already holds a different value/);
  eq("the stored value is untouched after the refused write", envStore.loadEnv()[GATE_KEY], raw);
  throws("deletion refuses", () => envStore.updateEnvKey(GATE_KEY, undefined), /cannot be deleted/);
}

// ---------------------------------------------------------------------------
// 5. THE STRICT LOOKUP over a REALLY SIGNED capture (clause 1 is the true
//    path; the clause-3 stages are mocked at the verifier's deps seam)
// ---------------------------------------------------------------------------
const mkSignedHeaderCapture = async ({ poolId = POOL, epochIndex = 7, gen = 1, contractId = ID_HEX } = {}) => {
  const transitionBytes = crypto.randomBytes(120).toString("hex");
  return captureRecord.signCapture({
    v: 1, kind: CAPTURE_KIND, object: "header", gen, poolId, epochIndex,
    transitionBytes,
    transitionHash: crypto.createHash("sha256").update(Buffer.from(transitionBytes, "hex")).digest("hex"),
    proofMsg: crypto.randomBytes(64).toString("hex"),
    metadataMsg: crypto.randomBytes(32).toString("hex"),
    contractId,
    expectedDocumentId: "cc".repeat(32),
    expectedContents: { poolId, epochIndex, grossCredits: 1000, feeCredits: 10,
      allocationHash: "dd".repeat(32), memberCount: 2, calcVersion: 1 },
    inclusionHeight: "41",
    heightRoute: "tenderdash-tx",
    signerIdentity: "ee".repeat(32),
    signerKeyId: 1,
  }, SECRET);
};
// the clause-3 seam: conformance echoes the carrier, stage one proves the
// expected document with the expected contents, stage two verifies
const mkVerifyDeps = (capture) => ({
  decodeProofCarrier: (hex) => ({ reencodedHex: hex, quorumHashHex: "ff".repeat(32), round: 0 }),
  decodeMetadata: (hex) => ({ reencodedHex: hex, chainId: "dashmate_local_52", protocolVersion: 12,
    height: "41", timeMs: "1700000000000", coreChainLockedHeight: 9, epoch: 1 }),
  decodeTransfer: () => { throw new Error("no transfer decode in a header case"); },
  verifyStageOne: async () => ({ ok: true, rootHashHex: "ab".repeat(32),
    provedDocument: { documentId: capture.expectedDocumentId, fields: { ...capture.expectedContents } } }),
  verifyStageTwo: async () => true,
});

{
  const capture = await mkSignedHeaderCapture();
  const digest = captureRecord.preimageDigest(capture);
  const artifact = buildGateArtifact({ contractId: ID_B58, poolId: POOL, epochIndex: 7, gen: 1, preimageDigest: digest });
  const envWith = (over = {}) => () => ({ [GATE_KEY]: artifact, CONTRACT_V11_ID: ID_B58, ...over });
  const lookupDeps = (over = {}) => ({
    resolveCaptureByKey: async (k) =>
      (k.poolId === POOL && k.epochIndex === 7 && k.gen === 1 && k.kind === CAPTURE_KIND) ? capture : null,
    resolveSignerKey,
    readEnv: envWith(),
    chainIdPin: "dashmate_local_52",
    verify: mkVerifyDeps(capture),
    ...over,
  });

  const r = await verifyGateCapture({ deps: lookupDeps() });
  ok("the strict lookup ADMITS a valid gate", r.admitted === true);
  // THE NORMALIZATION RULE: the artifact and env hold base58 while the capture
  // holds hex, all naming the SAME 32 bytes; a string comparison anywhere in
  // the lookup fails this admission
  ok("hex and base58 spellings of one identifier admit together",
    capture.contractId === ID_HEX && ID_B58 !== ID_HEX && r.admitted === true);

  await rejects("an absent gate key refuses",
    verifyGateCapture({ deps: lookupDeps({ readEnv: () => ({ CONTRACT_V11_ID: ID_B58 }) }) }),
    /absent or not a string/);
  await rejects("a differing CONTRACT_V11_ID refuses (decoded-byte comparison)",
    verifyGateCapture({ deps: lookupDeps({ readEnv: envWith({ CONTRACT_V11_ID: bs58.encode(Buffer.alloc(32, 1)) }) }) }),
    /does not equal the current CONTRACT_V11_ID/);
  await rejects("an unresolvable captureKey refuses",
    verifyGateCapture({ deps: lookupDeps({ resolveCaptureByKey: async () => null }) }),
    /no journaled capture resolves/);
  await rejects("a missing signer-key resolver refuses as a caller fault",
    verifyGateCapture({ deps: lookupDeps({ resolveSignerKey: undefined }) }),
    /needs deps\.resolveSignerKey/);

  // an ALTERED journaled capture: same key, one content byte different, so the
  // recomputed preimage digest differs byte-for-byte from the artifact's
  const altered = { ...capture, inclusionHeight: "42" };
  await rejects("an altered capture fails the digest byte-compare",
    verifyGateCapture({ deps: lookupDeps({ resolveCaptureByKey: async () => altered }) }),
    /recomputed preimage digest differs/);

  // a BROKEN SIGNATURE with the artifact digest recomputed to match, isolating
  // clause 1 from the digest compare
  const resigned = { ...capture, sig: "00".repeat(65) };
  await rejects("a capture whose signature does not verify refuses (clause 1)",
    verifyGateCapture({ deps: lookupDeps({
      resolveCaptureByKey: async () => resigned,
      readEnv: () => ({ CONTRACT_V11_ID: ID_B58,
        [GATE_KEY]: buildGateArtifact({ contractId: ID_B58, poolId: POOL, epochIndex: 7, gen: 1,
          preimageDigest: captureRecord.preimageDigest(resigned) }) }) }) }),
    /signature does not verify/);

  // a clause failure (stage two false) refuses THROUGH the verifier's verdict
  await rejects("a failing verification stage refuses through the clause verdict",
    verifyGateCapture({ deps: lookupDeps({
      verify: { ...mkVerifyDeps(capture), verifyStageTwo: async () => false } }) }),
    /fails the validity clauses/);

  // THE RESOLVER IS NOT TRUSTED WITH THE KEY (the re-check's delegation
  // finding): a resolver that ignores gen and serves a valid GENERATION-2
  // capture, with the artifact recomputed to that capture's digest, must
  // refuse on the key-member binding rather than admit
  const gen2 = await mkSignedHeaderCapture({ epochIndex: 7, gen: 2 });
  await rejects("a resolver substituting another generation's capture refuses",
    verifyGateCapture({ deps: lookupDeps({
      resolveCaptureByKey: async () => gen2,
      readEnv: () => ({ CONTRACT_V11_ID: ID_B58,
        [GATE_KEY]: buildGateArtifact({ contractId: ID_B58, poolId: POOL, epochIndex: 7, gen: 1,
          preimageDigest: captureRecord.preimageDigest(gen2) }) }),
      verify: mkVerifyDeps(gen2) }) }),
    /subject members do not equal the artifact's captureKey/);

  // the CONTRACT binding has its own negative (the re-check: the final
  // comparison could be deleted without a failure): a journaled capture naming
  // a DIFFERENT contract, artifact digest matching, must refuse -- and it now
  // refuses through clause 4, whose servedFor is the canonical id
  const foreignContract = await mkSignedHeaderCapture({ epochIndex: 7,
    contractId: Buffer.alloc(32, 0x0f).toString("hex") });
  await rejects("a capture bound to a different contract refuses",
    verifyGateCapture({ deps: lookupDeps({
      resolveCaptureByKey: async () => foreignContract,
      readEnv: () => ({ CONTRACT_V11_ID: ID_B58,
        [GATE_KEY]: buildGateArtifact({ contractId: ID_B58, poolId: POOL, epochIndex: 7, gen: 1,
          preimageDigest: captureRecord.preimageDigest(foreignContract) }) }),
      verify: mkVerifyDeps(foreignContract) }) }),
    /does not equal the current CONTRACT_V11_ID \(decoded-byte comparison\)/);
}

// ---------------------------------------------------------------------------
// 6. THE PRE-REGISTRATION PHASE DRIVER over mocked live deps: the roster is
//    pinned EXACTLY, every case runs, the first failure stops the phase with
//    the report naming what ran
// ---------------------------------------------------------------------------
{
  eq("the pre-registration roster is pinned",
    PRE_REGISTRATION_ROSTER.join("|"),
    ["d1-coverage-mathematical", "splitter-8B-roundtrip", "splitter-8B-plus-1-refuses",
      "splitter-single-part-roundtrip", "capacity-proofBytes-max-accepted",
      "capacity-proofBytes-plus-1-refused", "capacity-metadataBytes-max-accepted",
      "capacity-metadataBytes-plus-1-refused", "capacity-transitionBytes-max-accepted",
      "capacity-transitionBytes-plus-1-refused", "capacity-minimum-boundaries",
      "semantic-credit-transfer-capture", "semantic-header-capture-probe-contract"].join("|"));

  // the mocked live surface: fixture writes accept exactly when every byte
  // field fits its schema bound, which is what the live wire does per the D3
  // probe (5120 accepted at the wire); the transfer and header return REALLY
  // SIGNED captures
  const boundsOf = { transitionBytes: [100, 2048], proofBytes: [1, 5120], metadataBytes: [1, 512], bytes: [1, 5120] };
  const writeFixtureDoc = async (type, fields) => {
    for (const [k, v] of Object.entries(fields)) {
      if (v instanceof Uint8Array && boundsOf[k]) {
        const [lo, hi] = boundsOf[k];
        if (v.length < lo || v.length > hi) {
          return { outcome: "thrown", route: "client-or-broadcast-throw", message: `${k} out of ${lo}..${hi}` };
        }
      }
    }
    return { outcome: "verified-proof", route: "wait-literal" };
  };
  const mkTransferCapture = async (tbLen = 400) => {
    const transitionBytes = crypto.randomBytes(tbLen).toString("hex");
    return captureRecord.signCapture({
      v: 1, kind: "tegara.e2.receiptCapture.v1", object: "transfer", gen: 1,
      poolId: POOL, epochIndex: 7, accrualId: ACCR,
      transitionBytes,
      transitionHash: crypto.createHash("sha256").update(Buffer.from(transitionBytes, "hex")).digest("hex"),
      proofMsg: crypto.randomBytes(6000).toString("hex"),
      metadataMsg: crypto.randomBytes(59).toString("hex"),
      inclusionHeight: "43", heightRoute: "tenderdash-tx",
      signerIdentity: "ee".repeat(32), signerKeyId: 1,
    }, SECRET);
  };
  const headerCapture = await mkSignedHeaderCapture({ epochIndex: 9 });
  const goodDeps = {
    pin: "dashmate_local_52",
    probeContractIdHex: ID_HEX, // the header capture's own contract, driver-named
    writeFixtureDoc,
    resolveSignerKey,
    creditTransfer: async () => ({ outcome: "verified-proof", route: "wait-literal",
      capture: await mkTransferCapture() }),
    headerCapture: async () => ({ outcome: "verified-proof", route: "wait-literal", capture: headerCapture }),
    verify: mkVerifyDeps(headerCapture),
  };
  const report = await runPreRegistrationPhase({ deps: goodDeps });
  eq("the phase ran EVERY roster case", report.length, PRE_REGISTRATION_ROSTER.length);
  ok("every case passed", report.every((r) => r.verdict === "PASS"));
  ok("the report names each case in roster order with a detail line",
    report.every((r, i) => r.case === PRE_REGISTRATION_ROSTER[i] && typeof r.detail === "string"));

  // a fixture surface that ACCEPTS a plus-one write fails the phase AT THAT
  // CASE, with the report naming everything that ran up to it
  const acceptingAll = { ...goodDeps, writeFixtureDoc: async () => ({ outcome: "verified-proof", route: "wait-literal" }) };
  try {
    await runPreRegistrationPhase({ deps: acceptingAll });
    ok("a bound-ignoring surface must fail the phase", false);
  } catch (e) {
    ok("the failure names the refused-bound case", /ACCEPTED where the bound requires refusal/.test(e.message));
    ok("the report attached to the failure names what ran", Array.isArray(e.report)
      && e.report[e.report.length - 1].verdict === "FAIL"
      && e.report.slice(0, -1).every((r) => r.verdict === "PASS"));
  }

  // a transfer whose REAL encoded size falls outside the schema's empirical
  // domain fails the semantic case (duty D3's re-derivation is a CHECK on the
  // real article, not a recording of it)
  const hugeTransfer = { ...goodDeps,
    creditTransfer: async () => ({ outcome: "verified-proof", route: "wait-literal",
      capture: await mkTransferCapture(2049) }) };
  await rejects("a transfer outside the empirical transitionBytes domain fails the phase",
    runPreRegistrationPhase({ deps: hugeTransfer }), /outside the schema's 100\.\.2048/);

  // AN INCONCLUSIVE FAILURE IS NOT A REFUSAL (the re-check's timeout hole): a
  // plus-one case answered with a transport failure must FAIL the phase, never
  // count as the boundary refusing
  const timingOut = { ...goodDeps, writeFixtureDoc: async (type, fields) => {
    for (const [k, v] of Object.entries(fields)) {
      if (v instanceof Uint8Array && k === "proofBytes" && v.length > 5120) {
        return { outcome: "transport-failure", route: "wait-literal", message: "deadline elapsed" };
      }
    }
    return { outcome: "verified-proof", route: "wait-literal" };
  } };
  await rejects("a transport failure on a plus-one case fails the phase as inconclusive",
    runPreRegistrationPhase({ deps: timingOut }), /not a boundary refusal; inconclusive/);

  // a capture whose carrier exceeds the DERIVED maximum fails even though the
  // 8-part schema capacity would still hold it (the re-check: 39,000 < 40,960
  // passed the splitter while exceeding proofMsg_max = 38,039)
  const oversizedCarrier = { ...goodDeps, creditTransfer: async () => {
    const c = await mkTransferCapture(400);
    const resigned = await (async () => {
      const { sig, ...rest } = c;
      return captureRecord.signCapture({ ...rest,
        proofMsg: crypto.randomBytes(39000).toString("hex") }, SECRET);
    })();
    return { outcome: "verified-proof", route: "wait-literal", capture: resigned };
  } };
  await rejects("a carrier beyond the derived proofMsg_max fails the phase",
    runPreRegistrationPhase({ deps: oversizedCarrier }), /exceeds the derived proofMsg_max/);
}

// ---------------------------------------------------------------------------
// 7. THE CANONICAL PHASE: preconditions, verification-before-write ordering,
//    the write-once retry dichotomy, and gate completion BEFORE any receipt
// ---------------------------------------------------------------------------
{
  eq("the canonical roster is pinned", CANONICAL_ROSTER.join("|"),
    ["preconditions-canonical-contract-and-formation", "semantic-header-capture-canonical",
      "gate-key-write-once", "strict-lookup-verifies"].join("|"));

  const canonical = await mkSignedHeaderCapture({ epochIndex: 11, contractId: ID_HEX });
  const store = {}; // the injected env, so the ordering observation reads a plain object
  const mkCanonDeps = (over = {}) => ({
    headerCapture: async () => ({ outcome: "verified-proof", capture: canonical }),
    formationSetupDone: async () => true,
    resolveCaptureByKey: async (k) => (k.epochIndex === 11 ? canonical : null),
    resolveSignerKey,
    readEnv: () => ({ CONTRACT_V11_ID: ID_B58, ...store }),
    writeEnvKey: (k, v) => {
      if (store[k] !== undefined && store[k] !== v) throw new Error(`${k} is write-once and already holds a different value`);
      store[k] = v;
    },
    chainIdPin: "dashmate_local_52",
    verify: mkVerifyDeps(canonical),
    ...over,
  });

  // NO RECEIPT EXISTS ANYWHERE IN THIS FILE'S STORES: gate completion below is
  // therefore proved before any receipt exists, the property the spec assigns
  // this test (the excluded pair-relative clause 5 is what makes it possible)
  const report = await runCanonicalPhase({ deps: mkCanonDeps() });
  eq("the canonical phase ran its whole roster", report.length, CANONICAL_ROSTER.length);
  ok("the gate key exists after the phase", typeof store[GATE_KEY] === "string");
  const parsed = parseGateArtifact(store[GATE_KEY]);
  eq("the written artifact's digest is the canonical capture's",
    parsed.preimageDigest, captureRecord.preimageDigest(canonical));

  // the IDENTICAL RETRY: a rerun writes the same artifact and succeeds
  const report2 = await runCanonicalPhase({ deps: mkCanonDeps() });
  ok("an identical rerun is an idempotent success", report2.every((r) => r.verdict === "PASS"));

  // ORDERING: a capture that fails verification leaves the key UNWRITTEN
  const store2 = {};
  const failing = mkCanonDeps({
    readEnv: () => ({ CONTRACT_V11_ID: ID_B58, ...store2 }),
    writeEnvKey: (k, v) => { store2[k] = v; },
    verify: { ...mkVerifyDeps(canonical), verifyStageTwo: async () => false },
  });
  await rejects("a failing canonical verification stops the phase",
    runCanonicalPhase({ deps: failing }), /fails the validity clauses/);
  ok("and the gate key was NEVER written past the failed verification",
    store2[GATE_KEY] === undefined);

  // the CONFLICTING CONCURRENT START: a second run whose capture differs (a
  // different gen) refuses at the write-once key and the stored value survives
  const conflicting = await mkSignedHeaderCapture({ epochIndex: 11, gen: 2, contractId: ID_HEX });
  const conflictDeps = mkCanonDeps({
    headerCapture: async () => ({ outcome: "verified-proof", capture: conflicting }),
    resolveCaptureByKey: async () => conflicting,
    verify: mkVerifyDeps(conflicting),
  });
  await rejects("a conflicting concurrent start refuses at the write-once key",
    runCanonicalPhase({ deps: conflictDeps }), /write-once and already holds a different value/);
  eq("the first gate survives the conflicting attempt",
    parseGateArtifact(store[GATE_KEY]).preimageDigest, captureRecord.preimageDigest(canonical));

  // PRECONDITIONS
  await rejects("a missing CONTRACT_V11_ID refuses the phase at its first case",
    runCanonicalPhase({ deps: mkCanonDeps({ readEnv: () => ({}) }) }),
    /CONTRACT_V11_ID is not set/);
  await rejects("unfinished formation setup refuses",
    runCanonicalPhase({ deps: mkCanonDeps({ formationSetupDone: async () => false }) }),
    /formation setup on canonical v11 is not done/);

  // TWO GENUINELY INTERLEAVED PHASES over ONE SHARED deps object with different
  // captures (the re-check's race: the earlier draft parked the verified
  // capture on deps, so an interleaving turned a conflict into a false
  // idempotent success). Both phases now hold their capture locally; the
  // shared store's write-once rule decides, and exactly one wins.
  {
    const raceStore = {};
    const captureX = await mkSignedHeaderCapture({ epochIndex: 13, gen: 1, contractId: ID_HEX });
    const captureY = await mkSignedHeaderCapture({ epochIndex: 13, gen: 1, contractId: ID_HEX });
    let releaseX;
    const holdX = new Promise((r) => { releaseX = r; });
    // ONE deps object, genuinely shared by both phases (the re-check: two
    // separate objects could not catch a mutation that parks state on deps).
    // The first headerCapture call serves the stalled capture X, the second
    // serves Y; the verify seam accepts either capture's expectations.
    let calls = 0;
    const sharedVerify = {
      ...mkVerifyDeps(captureX),
      verifyStageOne: async () => ({ ok: true, rootHashHex: "ab".repeat(32),
        provedDocument: null }),
    };
    // provedDocument null would fail the header binding, so serve per-capture:
    sharedVerify.verifyStageOne = async () => ({ ok: true, rootHashHex: "ab".repeat(32),
      provedDocument: calls <= 1
        ? { documentId: captureX.expectedDocumentId, fields: { ...captureX.expectedContents } }
        : { documentId: captureY.expectedDocumentId, fields: { ...captureY.expectedContents } } });
    const sharedDeps = {
      headerCapture: async () => {
        calls += 1;
        if (calls === 1) { await holdX; return { outcome: "verified-proof", capture: captureX }; }
        return { outcome: "verified-proof", capture: captureY };
      },
      formationSetupDone: async () => true,
      resolveCaptureByKey: async (k) => (k.epochIndex === 13 ? captureY : null),
      resolveSignerKey,
      readEnv: () => ({ CONTRACT_V11_ID: ID_B58, ...raceStore }),
      writeEnvKey: (k, v) => {
        if (raceStore[k] !== undefined && raceStore[k] !== v) throw new Error(`${k} is write-once and already holds a different value`);
        raceStore[k] = v;
      },
      chainIdPin: "dashmate_local_52",
      verify: sharedVerify,
    };
    const pX = runCanonicalPhase({ deps: sharedDeps }).then(() => "X-ok", (e) => `X-refused: ${e.message}`);
    const yResult = await runCanonicalPhase({ deps: sharedDeps }).then(() => "Y-ok", (e) => `Y-refused: ${e.message}`);
    releaseX();
    const xResult = await pX;
    eq("the first finisher wins the interleaved start", yResult, "Y-ok");
    ok("the stalled phase REFUSES at the write-once key rather than reading the winner's capture",
      /X-refused: .*write-once and already holds a different value/.test(xResult));
    eq("the stored gate is the winner's", parseGateArtifact(raceStore[GATE_KEY]).preimageDigest,
      captureRecord.preimageDigest(captureY));
  }

  // THE STRANDED-KEY SURFACE (the re-check's ordering finding, at its real
  // width): a strict-lookup failure AFTER the write leaves the key standing and
  // the phase failed; a rerun with the SAME capture is the idempotent success,
  // and only a DIFFERING capture refuses
  {
    const store3 = {};
    const cap = await mkSignedHeaderCapture({ epochIndex: 17, gen: 1, contractId: ID_HEX });
    const base = mkCanonDeps({
      headerCapture: async () => ({ outcome: "verified-proof", capture: cap }),
      resolveCaptureByKey: async () => null, // the journal lost the capture
      readEnv: () => ({ CONTRACT_V11_ID: ID_B58, ...store3 }),
      writeEnvKey: (k, v) => {
        if (store3[k] !== undefined && store3[k] !== v) throw new Error(`${k} is write-once and already holds a different value`);
        store3[k] = v;
      },
      verify: mkVerifyDeps(cap),
    });
    await rejects("a strict-lookup failure after the write fails the phase",
      runCanonicalPhase({ deps: base }), /no journaled capture resolves/);
    ok("and the key REMAINS (the human-decision surface, not a rollback)",
      typeof store3[GATE_KEY] === "string");
    const healed = { ...base, resolveCaptureByKey: async (k) => (k.epochIndex === 17 ? cap : null) };
    const report = await runCanonicalPhase({ deps: healed });
    ok("a rerun with the SAME capture is the idempotent success",
      report.every((r) => r.verdict === "PASS"));
  }
}

// ---------------------------------------------------------------------------
// 8. THE PROBE CONTRACT: byte-identity with buildV11's five types, and the
//    publisher's refusals
// ---------------------------------------------------------------------------
{
  const { poolLedgerContract } = require("../../dist/contract/poolLedger.js");
  const schemas = probeContract.probeSchemas(poolLedgerContract);
  eq("the probe carries exactly the five E2 types", Object.keys(schemas).sort().join(","),
    [...E2_TYPES].sort().join(","));
  const v11 = buildV11(poolLedgerContract);
  // stated at its real width: this establishes PRESENT identity between the two
  // derivations, both of which read buildV11; a coordinated change to buildV11
  // and E2_TYPES moves both sides together, and the guard against THAT is
  // contractV11Test's own exact-diff pin against buildV9, not this assertion
  ok("each probe schema is canonically identical to buildV11's",
    E2_TYPES.every((t) => canonicalString(schemas[t]) === canonicalString(v11[t])));

  let receivedSchemas = null;
  const goodDeps = {
    identityId: ID_B58,
    identityNonce: async () => 1n,
    createContract: (owner, nonce, s) => { receivedSchemas = s; return { id: { toString: () => "ProbeContractId111" }, owner, nonce, s }; },
    broadcastCreate: async () => ({ outcome: "verified-proof" }),
  };
  const r = await probeContract.publishProbeContract({ poolLedgerContract, deps: goodDeps });
  eq("the publisher returns the contract id", r.contractId, "ProbeContractId111");
  // what REACHED createContract is asserted, not what probeSchemas would return
  // (the re-check: a publisher passing {} left the identity assertion green
  // because the mock ignored its schema argument)
  ok("the schemas that REACHED the publisher's create call are the five, canonically identical to buildV11's",
    receivedSchemas !== null
    && Object.keys(receivedSchemas).sort().join(",") === [...E2_TYPES].sort().join(",")
    && E2_TYPES.every((t) => canonicalString(receivedSchemas[t]) === canonicalString(v11[t])));
  await rejects("a publication without a verified proof refuses",
    probeContract.publishProbeContract({ poolLedgerContract,
      deps: { ...goodDeps, broadcastCreate: async () => ({ outcome: "execution-refusal" }) } }),
    /did not commit with a verified proof/);
  await rejects("a missing dep refuses",
    probeContract.publishProbeContract({ poolLedgerContract,
      deps: { identityId: ID_B58, identityNonce: async () => 1n, createContract: goodDeps.createContract } }),
    /needs deps\.broadcastCreate/);
}

console.log(`e2CaptureBatteryTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
})().catch((e) => { console.error("UNCAUGHT:", e); process.exitCode = 1; });
