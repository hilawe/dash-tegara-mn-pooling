/**
 * THE TWO-PHASE CAPTURE BATTERY (duty D9's battery half; the E2 build spec's
 * "First-code-commit duties", the battery definition and the two-phase gate
 * order, with the canonical-gate-capture row of the gate matrix).
 *
 * WHAT THIS MODULE ESTABLISHES: the canonical carrier SPLITTER and its bounds;
 * the D1/D3 coverage assertions (from the documented derivation, never
 * re-derived here); the gate artifact's closed canonical format and its
 * write-once discipline; the STRICT LOOKUP every other E2 writer consults; and
 * the two phase drivers, each a fixed ROSTER of cases whose pass predicate is
 * the conjunction and whose output names every case it ran (a sweep reports
 * WHAT IT DID, so a zero-work pass cannot look like a clean one).
 *
 * WHAT IT DOES NOT ESTABLISH, stated: every cryptographic and ledger fact
 * comes through INJECTED deps (the mounted wrapper's literals, the admission
 * primitive, the journal store, the verification stages), so this module
 * proves ORCHESTRATION and REFUSAL SHAPE; the deps' own correctness is their
 * modules' acceptance evidence. The LIVE canonical phase additionally waits on
 * registerV11 (unbuilt): its code path is complete and offline-tested, and no
 * claim of C2 closure is made until the live canonical rerun has run.
 *
 * COMPOSITION, nothing reimplemented: capture records and signatures from
 * e2CaptureRecord.cjs; validity clauses 2, 3, 4 and 6 from
 * e2ReceiptVerify.verifyCaptureRecord (clause 1 via the capture record's
 * signature machinery; the pair-relative clause 5 is EXCLUDED by the spec,
 * which is what keeps the gate closeable before any receipt exists);
 * identifier comparisons normalize to raw 32 bytes via formationCore.toId32
 * (base58 and hex spellings of one identifier compare equal, the audit's own
 * rule); the artifact's canonical bytes via canonicalJson.canonicalString; the
 * write-once key via envStore.updateEnvKey, whose E2_WRITE_ONCE_KEYS class
 * already enforces set-once / equal-idempotent / differing-refusal.
 */
const crypto = require("crypto");
const { canonicalString } = require("./canonicalJson.cjs");
const envStore = require("./envStore.cjs");
const captureRecord = require("./e2CaptureRecord.cjs");
const receiptVerify = require("./e2ReceiptVerify.cjs");
const formationCore = require("./formationCore.cjs");

const sha256hex = (s) => crypto.createHash("sha256").update(s).digest("hex");
const HEX64 = /^[0-9a-f]{64}$/;
const HEX_RE = /^([0-9a-f]{2})*$/;

const refuse = (why) => { throw new Error(`e2CaptureBattery: ${why}`); };

// ---------------------------------------------------------------------------
// The bounds, from their owning records. B is duty D3's empirical result (the
// 2026-08-27 probe: 5120 bytes into a maxItems-5120 field ACCEPTED at the
// wire, so overhead does not count and B equals the schema bound). The D1
// figures are the documented derivation's normative outputs
// (tegara/docs/E2_D1_CARRIER_BOUNDS.md); they are CONSUMED here and never
// re-derived, so a change to the derivation is a change to that document
// first.
// ---------------------------------------------------------------------------
const D1_BOUNDS = Object.freeze({
  B: 5120,                    // the chunk constant, D3's empirical result
  partCapacity: 8,            // the schema's proofPartCount domain 1..8
  proofMsgMax: 38039,         // D1's derived worst-case complete proofMsg
  metadataFixedFields: 40,    // D1: the five non-chainId fields at their maxima
  metadataCapacity: 512,      // the schema's metadataBytes maxItems
  transitionBytesMin: 100,    // the schema's empirical transitionBytes domain,
  transitionBytesMax: 2048,   //   validated by the semantic capture's real size
});

// the derived metadata maximum, VARINT-AWARE: the chainId length prefix takes
// one byte only through L = 127 (the pre-commit check caught the collapsed
// one-byte form undercounting exactly where a long identifier needs the room)
const lengthVarintBytes = (L) => {
  if (!Number.isSafeInteger(L) || L < 1) refuse("a length needs a positive integer");
  if (L <= 127) return 1;
  if (L <= 16383) return 2;
  return 3; // L < 2^21; the coverage check fails long before this width matters
};
const metadataMaxForPin = (chainIdByteLength) =>
  D1_BOUNDS.metadataFixedFields + 1 + lengthVarintBytes(chainIdByteLength) + chainIdByteLength;

/**
 * The D1/D3 coverage assertions, MATHEMATICAL per the battery definition (the
 * source-derived bound shown at most 8*B, never a synthesized proof at the
 * ceiling). chainIdByteLength is the LIVE pin's, so a future pin cannot
 * silently outgrow the schema.
 */
const assertD1Coverage = ({ chainIdByteLength }) => {
  if (!Number.isSafeInteger(chainIdByteLength) || chainIdByteLength < 1) {
    refuse("assertD1Coverage needs the live pin's chainId byte length");
  }
  const results = [];
  const check = (name, holds, detail) => {
    results.push({ name, holds, detail });
    if (!holds) refuse(`D1 coverage fails: ${name} (${detail})`);
  };
  const mdMax = metadataMaxForPin(chainIdByteLength);
  check("metadata capacity covers the derived maximum",
    mdMax <= D1_BOUNDS.metadataCapacity,
    `40+1+varint(${chainIdByteLength})+${chainIdByteLength} = ${mdMax} <= ${D1_BOUNDS.metadataCapacity}`);
  check("the 8-part capacity covers the derived proofMsg maximum",
    D1_BOUNDS.proofMsgMax <= D1_BOUNDS.partCapacity * D1_BOUNDS.B,
    `${D1_BOUNDS.proofMsgMax} <= ${D1_BOUNDS.partCapacity}*${D1_BOUNDS.B}`);
  check("the worst-case part count stays in the schema domain",
    Math.ceil(D1_BOUNDS.proofMsgMax / D1_BOUNDS.B) <= D1_BOUNDS.partCapacity,
    `ceil(${D1_BOUNDS.proofMsgMax}/${D1_BOUNDS.B}) <= ${D1_BOUNDS.partCapacity}`);
  return results;
};

// ---------------------------------------------------------------------------
// The canonical carrier splitter (write side). The verifier's reassembly and
// split assertions are the read side; the two must be inverses, and the test
// proves the round trip through the VERIFIER's reassembly, not through this
// module's own arithmetic.
// ---------------------------------------------------------------------------
const splitCarrier = (carrierHex) => {
  if (typeof carrierHex !== "string" || !HEX_RE.test(carrierHex)) {
    refuse("splitCarrier needs lowercase hex of whole bytes");
  }
  const L = carrierHex.length / 2;
  if (L === 0) refuse("splitCarrier refuses an empty carrier (the schema's minItems is 1)");
  const capacity = D1_BOUNDS.partCapacity * D1_BOUNDS.B;
  if (L > capacity) {
    refuse(`splitCarrier refuses ${L} bytes: the carrier exceeds the ${D1_BOUNDS.partCapacity}-part capacity ${capacity} (truncation would violate the reassembly identity)`);
  }
  const B2 = D1_BOUNDS.B * 2; // hex chars per part
  const proofPartCount = Math.ceil(L / D1_BOUNDS.B);
  const proofBytes = carrierHex.slice(0, Math.min(carrierHex.length, B2));
  const parts = [];
  for (let i = 1; i < proofPartCount; i++) {
    parts.push({ partIndex: i, bytes: carrierHex.slice(i * B2, (i + 1) * B2) });
  }
  return { proofBytes, parts, proofPartCount };
};

// ---------------------------------------------------------------------------
// The gate artifact: ONE JCS object with members exactly contractId (the
// base58 string exactly as the registration lineage writes it), captureKey (a
// LITERAL NESTED JCS OBJECT with members exactly kind, object, poolId,
// epochIndex, gen) and preimageDigest (lowercase hex SHA-256 of the capture's
// complete domain-prefixed signed preimage).
// ---------------------------------------------------------------------------
const GATE_KEY = "E2_GATE_CAPTURE";
const CAPTURE_KIND = "tegara.e2.headerCapture.v1";

const buildGateArtifact = ({ contractId, poolId, epochIndex, gen, preimageDigest }) => {
  if (typeof contractId !== "string" || contractId.length === 0) refuse("the gate artifact needs the canonical contractId string");
  if (!HEX64.test(poolId || "")) refuse("the gate artifact needs a 64-hex poolId");
  if (!Number.isSafeInteger(epochIndex) || epochIndex < 0 || epochIndex > 4294967295) {
    refuse("the gate artifact needs an epochIndex in 0..4294967295");
  }
  if (!Number.isSafeInteger(gen) || gen < 1) refuse("the gate artifact needs an integer gen of at least 1");
  if (!HEX64.test(preimageDigest || "")) refuse("the gate artifact needs the 64-hex preimage digest");
  return canonicalString({
    contractId,
    captureKey: { kind: CAPTURE_KIND, object: "header", poolId, epochIndex, gen },
    preimageDigest,
  });
};

/**
 * The artifact parser, split out (parseChainIdPin's precedent) so malformed
 * cases are testable without touching the write-once key. The stored value
 * must be ONE JCS value: the raw bytes must equal the canonical serialization
 * of what they parse to, so a reordered or padded encoding refuses.
 */
const parseGateArtifact = (raw) => {
  if (typeof raw !== "string") refuse("the gate artifact is absent or not a string");
  let v;
  try { v = JSON.parse(raw); } catch { refuse("the gate artifact is not valid JSON"); }
  if (!v || typeof v !== "object" || Array.isArray(v)) refuse("the gate artifact must be one object");
  const keys = Object.keys(v).sort().join(",");
  if (keys !== "captureKey,contractId,preimageDigest") {
    refuse(`the gate artifact's members must be exactly contractId, captureKey, preimageDigest (got ${keys})`);
  }
  const k = v.captureKey;
  if (!k || typeof k !== "object" || Array.isArray(k)) refuse("captureKey must be an object");
  const kk = Object.keys(k).sort().join(",");
  if (kk !== "epochIndex,gen,kind,object,poolId") {
    refuse(`captureKey's members must be exactly kind, object, poolId, epochIndex, gen (got ${kk})`);
  }
  if (k.kind !== CAPTURE_KIND) refuse(`captureKey.kind must be the literal ${CAPTURE_KIND}`);
  if (k.object !== "header") refuse('captureKey.object must be the literal "header"');
  if (typeof k.poolId !== "string" || !HEX64.test(k.poolId)) refuse("captureKey.poolId must be 64 lowercase hex");
  if (!Number.isSafeInteger(k.epochIndex) || k.epochIndex < 0 || k.epochIndex > 4294967295) {
    refuse("captureKey.epochIndex must be an integer in 0..4294967295");
  }
  if (!Number.isSafeInteger(k.gen) || k.gen < 1) refuse("captureKey.gen must be an integer of at least 1");
  if (typeof v.contractId !== "string" || v.contractId.length === 0) refuse("contractId must be a nonempty string");
  if (typeof v.preimageDigest !== "string" || !HEX64.test(v.preimageDigest)) {
    refuse("preimageDigest must be 64 lowercase hex");
  }
  if (raw !== canonicalString(v)) {
    refuse("the gate artifact's raw bytes are not the canonical serialization of its value (one JCS value, exactly)");
  }
  return v;
};

// identifier equality at this gate: NORMALIZE to the raw 32 bytes and compare
// bytes, so textual-versus-decoded equality is never an implementer choice.
// formationCore.toId32 handles base58 strings and byte views; the 64-hex
// spelling (the capture record's convention) is decoded here because
// decodeId32's alphabet excludes it, and an identifier in NEITHER spelling is
// a refusal, never a crash (toId32 answers null on undecodable input).
const idTo32 = (v) => {
  if (typeof v === "string" && HEX64.test(v)) return Buffer.from(v, "hex");
  return formationCore.toId32(v);
};
const idBytesEqual = (a, b) => {
  const da = idTo32(a), db = idTo32(b);
  if (!da || !db) {
    refuse("an identifier at the gate decodes to neither 32 raw bytes via base58 nor 64-hex; a comparison over undecodable identifiers is a refusal, never a pass");
  }
  return Buffer.compare(da, db) === 0;
};

/**
 * THE STRICT LOOKUP, the one consult every other E2 writer performs before
 * writing any E2 record. Resolves the journaled capture by the FULL
 * captureKey, recomputes the preimage digest and compares byte-for-byte,
 * re-runs the STANDALONE header-gate predicate (validity clauses 1, 2, 3, 4
 * and 6, EXCLUDING the pair-relative clause 5), and binds the artifact's
 * contractId and the capture's contract identifier to the current
 * CONTRACT_V11_ID, all identifier comparisons over decoded bytes. ANY absence,
 * mismatch or verification failure REFUSES; there is no partial admit.
 *
 * deps: resolveCaptureByKey({kind, object, poolId, epochIndex, gen}) -> the
 * journaled capture record or null; verify deps for clauses 3's stages
 * (decodeProofCarrier, decodeMetadata, verifyStageOne, verifyStageTwo);
 * readEnv() -> the env map (defaults to envStore.loadEnv, injectable so the
 * offline battery drives every branch); contractV11Id() -> the canonical id
 * string (defaults to the env key).
 */
const verifyGateCapture = async ({ deps }) => {
  if (!deps || typeof deps.resolveCaptureByKey !== "function") {
    throw new Error("e2CaptureBattery: verifyGateCapture needs deps.resolveCaptureByKey; a missing dependency is a caller fault, never evidence about the gate");
  }
  const readEnv = deps.readEnv || (() => envStore.loadEnv());
  const env = readEnv();
  const artifact = parseGateArtifact(env[GATE_KEY]);
  const v11 = deps.contractV11Id ? deps.contractV11Id() : env.CONTRACT_V11_ID;
  if (typeof v11 !== "string" || v11.length === 0) refuse("CONTRACT_V11_ID is not set; the gate cannot bind a contract");
  if (!idBytesEqual(artifact.contractId, v11)) {
    refuse("the gate artifact's contractId does not equal the current CONTRACT_V11_ID (decoded-byte comparison)");
  }
  const capture = await deps.resolveCaptureByKey(artifact.captureKey);
  if (!capture) refuse("no journaled capture resolves for the artifact's full captureKey");
  // THE RESOLVER IS NOT TRUSTED WITH THE KEY: every member of the returned
  // capture's own subject is bound to the artifact's captureKey here, so a
  // resolver that ignored a member (a gen, an epoch) cannot substitute a
  // different generation's otherwise-valid capture (the pre-commit check's
  // resolver-delegation finding)
  const k = artifact.captureKey;
  if (capture.kind !== k.kind || capture.object !== k.object
    || capture.poolId !== k.poolId || capture.epochIndex !== k.epochIndex
    || capture.gen !== k.gen) {
    refuse("the resolved capture's own subject members do not equal the artifact's captureKey (kind, object, poolId, epochIndex, gen all bind)");
  }
  const recomputed = captureRecord.preimageDigest(capture);
  if (recomputed !== artifact.preimageDigest) {
    refuse("the journaled capture's recomputed preimage digest differs byte-for-byte from the artifact's");
  }
  // THE DECODED-BYTE CONTRACT BINDING RUNS FIRST and owns its refusal: while
  // the capture's contractId is hex64-validated, clause 4's string equality
  // against the canonical hex is an equivalent second witness, and running
  // this one first keeps it independently exercised rather than shadowed
  if (!idBytesEqual(capture.contractId, v11)) {
    refuse("the journaled capture's contract identifier does not equal the current CONTRACT_V11_ID (decoded-byte comparison)");
  }
  // clause 1: a signature verifies over the domain-prefixed preimage under a
  // key the CALLER resolves (the pinned identity routes in production; the
  // capture module refuses a malformed key as a caller fault). The
  // supersession chain, when one exists, is the capture module's selection.
  if (typeof deps.resolveSignerKey !== "function") {
    throw new Error("e2CaptureBattery: verifyGateCapture needs deps.resolveSignerKey (the 33-byte compressed signer key for clause 1); a missing dependency is a caller fault");
  }
  const signerKey = await deps.resolveSignerKey(capture);
  if (!(await captureRecord.verifyCaptureSignature(capture, signerKey))) {
    refuse("the journaled capture's signature does not verify (validity clause 1)");
  }
  // clauses 2, 3, 4 and 6, through the verifier's own implementation. The
  // servedFor tuple is the gate's subject plus the CANONICAL contract in the
  // capture's own hex spelling (an earlier draft passed the capture's own
  // contractId back to itself, which made clause 4's contract check vacuous;
  // the pre-commit check named it), so clause 4 compares the capture against
  // CONTRACT_V11_ID, and the decoded-byte comparison below stays as the
  // spelling-independent second witness. The verifier SETTLES (status
  // "verified" or "refused"), so its verdict is read, never inferred.
  const v11Hex = idTo32(v11);
  if (!v11Hex) refuse("CONTRACT_V11_ID decodes to neither base58 nor 64-hex; the gate cannot bind a contract");
  const clauseVerdict = await receiptVerify.verifyCaptureRecord({
    capture,
    servedFor: { poolId: artifact.captureKey.poolId,
      epochIndex: artifact.captureKey.epochIndex, contractId: v11Hex.toString("hex") },
    chainIdPin: deps.chainIdPin !== undefined ? deps.chainIdPin : envStore.readChainIdPin().chainId,
    deps: deps.verify,
  });
  if (!clauseVerdict || clauseVerdict.status !== "verified") {
    refuse(`the journaled capture fails the validity clauses (${(clauseVerdict && clauseVerdict.reason) || "no verdict"})`);
  }
  return { admitted: true, artifact };
};

// ---------------------------------------------------------------------------
// The phase rosters. Each phase runs its FIXED roster in order, records one
// verdict per case, refuses at the first failure, and returns the report
// either way (attached to the thrown error on failure), so the output always
// names what ran and what did not.
// ---------------------------------------------------------------------------
const PRE_REGISTRATION_ROSTER = Object.freeze([
  "d1-coverage-mathematical",
  "splitter-8B-roundtrip",
  "splitter-8B-plus-1-refuses",
  "splitter-single-part-roundtrip",
  "capacity-proofBytes-max-accepted",
  "capacity-proofBytes-plus-1-refused",
  "capacity-metadataBytes-max-accepted",
  "capacity-metadataBytes-plus-1-refused",
  "capacity-transitionBytes-max-accepted",
  "capacity-transitionBytes-plus-1-refused",
  "capacity-minimum-boundaries",
  "semantic-credit-transfer-capture",
  "semantic-header-capture-probe-contract",
]);

const CANONICAL_ROSTER = Object.freeze([
  "preconditions-canonical-contract-and-formation",
  "semantic-header-capture-canonical",
  "gate-key-write-once",
  "strict-lookup-verifies",
]);

const runRoster = async (roster, impls) => {
  const report = [];
  for (const name of roster) {
    const impl = impls[name];
    if (typeof impl !== "function") refuse(`the roster case ${name} has no implementation; a missing case must fail loudly, never be skipped`);
    try {
      const detail = await impl();
      report.push({ case: name, verdict: "PASS", detail: detail || null });
    } catch (e) {
      report.push({ case: name, verdict: "FAIL", detail: (e && e.message) || String(e) });
      const err = new Error(`battery case ${name} failed: ${(e && e.message) || String(e)}`);
      err.report = report;
      throw err;
    }
  }
  return report;
};

/**
 * THE PRE-REGISTRATION PHASE, gating v11 publication. Live operations are
 * injected: deps.writeFixtureDoc(type, fields) performs a document create on
 * the PROBE contract through the mounted wrapper and returns
 * { outcome, route, code, message } (route "wait-literal" or
 * "client-or-broadcast-throw"); deps.creditTransfer({ amountCredits }) performs
 * a real transfer and returns { outcome, transitionHex, capture } where
 * capture is the SIGNED capture record its driver built through
 * e2CaptureRecord; deps.headerCapture() performs the probe-contract header
 * write through the admission primitive under its lock set and returns
 * { outcome, capture }; deps.verify carries the clause-3 stages; deps.pin the
 * chain pin string.
 *
 * A fixture case ACCEPTS only on the wrapper's verified-proof literal; a
 * plus-one case REFUSES on either route (the schema refusal surfaces on the
 * client hop as a throw, a wire refusal as an execution-refusal literal), and
 * the route is recorded so the two kinds of evidence are never conflated.
 */
const runPreRegistrationPhase = async ({ deps }) => {
  for (const k of ["writeFixtureDoc", "creditTransfer", "headerCapture", "resolveSignerKey"]) {
    if (typeof (deps && deps[k]) !== "function") refuse(`runPreRegistrationPhase needs deps.${k}`);
  }
  if (typeof deps.pin !== "string" || deps.pin.length === 0) refuse("runPreRegistrationPhase needs deps.pin (the chain pin's chainId)");
  if (typeof deps.probeContractIdHex !== "string" || !HEX64.test(deps.probeContractIdHex)) {
    refuse("runPreRegistrationPhase needs deps.probeContractIdHex (the probe contract, 64-hex); a self-passed contract binding is vacuous and refused rather than labelled");
  }

  const expectAccept = async (r, what) => {
    if (!r || r.outcome !== "verified-proof") {
      refuse(`${what} did not commit (route=${r && r.route}, outcome=${r && r.outcome}, ${String(r && r.message).slice(0, 120)})`);
    }
    return `accepted via ${r.route}`;
  };
  // a refusal case passes ONLY on evidence the BOUNDARY refused: the client or
  // broadcast hop throwing on the invalid document, or the ledger's structured
  // execution refusal. Anything else -- a transport failure, a malformed
  // response, an absent result -- learned NOTHING about the bound and fails the
  // case as inconclusive (the pre-commit check named the timeout-counts-as-
  // refusal hole)
  const expectRefuse = async (r, what) => {
    if (!r) refuse(`${what}: no result at all; the case learned nothing about the bound`);
    if (r.outcome === "verified-proof") refuse(`${what} was ACCEPTED where the bound requires refusal`);
    if (r.outcome !== "thrown" && r.outcome !== "execution-refusal") {
      refuse(`${what}: the failure is ${r.outcome}, not a boundary refusal; inconclusive, so the case fails rather than passes`);
    }
    return `refused via ${r.route}${r.code !== undefined && r.code !== null ? ` code=${r.code}` : ""}`;
  };
  // Uint8Array, NOT Buffer: the installed document builder reads a Buffer's
  // bytes as a character string (watched live: 32 bytes of 0x33 arrived as the
  // ASCII string of 32 threes and failed a u64 conversion), while a plain
  // Uint8Array is carried as the byte array the schema declares
  const bytes = (n, fill = 0x5a) => new Uint8Array(n).fill(fill);
  const H32 = bytes(32, 0x11);
  // transferReceipt carries UNIQUE indices on accrualId and transitionHash, so
  // every fixture takes fresh values for both (watched live: a second write
  // with a repeated accrualId is refused for the INDEX, which files a
  // capacity case's verdict under the wrong rule)
  let fixtureSeq = 0;
  const fresh32 = () => {
    const b = new Uint8Array(32).fill(0x9c);
    const n = ++fixtureSeq;
    b[0] = n & 0xff; b[1] = (n >> 8) & 0xff;
    b[31] = crypto.randomBytes(1)[0];
    return b;
  };
  const receiptFields = (over) => ({
    poolId: H32, accrualId: fresh32(), transitionHash: fresh32(),
    transitionBytes: bytes(D1_BOUNDS.transitionBytesMin), proofBytes: bytes(1),
    proofPartCount: 1, metadataBytes: bytes(1), blockHeight: bytes(8),
    coreChainLockedHeight: 1, timeMs: bytes(8), quorumHash: bytes(32, 0x44), round: 0,
    ...over,
  });

  const impls = {
    "d1-coverage-mathematical": () =>
      assertD1Coverage({ chainIdByteLength: Buffer.byteLength(deps.pin, "utf8") })
        .map((r) => r.detail).join("; "),
    "splitter-8B-roundtrip": () => {
      const L = D1_BOUNDS.partCapacity * D1_BOUNDS.B;
      const carrier = crypto.randomBytes(L).toString("hex");
      const split = splitCarrier(carrier);
      if (split.proofPartCount !== 8) refuse(`8B must split into exactly 8 parts, got ${split.proofPartCount}`);
      const back = receiptVerify.__testing.reassembleProof(
        { proofBytes: split.proofBytes, proofPartCount: split.proofPartCount,
          poolId: "00".repeat(32), accrualId: "11".repeat(32) },
        split.parts.map((p) => ({ partIndex: p.partIndex, bytes: p.bytes,
          poolId: "00".repeat(32), accrualId: "11".repeat(32) })));
      if (back !== carrier) refuse("the verifier's reassembly of the split is not byte-identical to the input");
      return `8 parts, final part ${split.parts[6].bytes.length / 2} bytes, verifier round trip byte-identical`;
    },
    "splitter-8B-plus-1-refuses": () => {
      const over = "00".repeat(D1_BOUNDS.partCapacity * D1_BOUNDS.B + 1);
      try { splitCarrier(over); } catch (e) { return `refused: ${String(e.message).slice(0, 80)}`; }
      refuse("a carrier one byte over the 8-part capacity was split instead of refused");
    },
    "splitter-single-part-roundtrip": () => {
      const carrier = crypto.randomBytes(37).toString("hex");
      const split = splitCarrier(carrier);
      if (split.proofPartCount !== 1 || split.parts.length !== 0 || split.proofBytes !== carrier) {
        refuse("a sub-B carrier must be exactly part 0 with no served parts");
      }
      return "part 0 only, byte-identical";
    },
    "capacity-proofBytes-max-accepted": async () =>
      expectAccept(await deps.writeFixtureDoc("transferReceipt",
        receiptFields({ proofBytes: bytes(D1_BOUNDS.B) })), "proofBytes at 5120"),
    "capacity-proofBytes-plus-1-refused": async () =>
      expectRefuse(await deps.writeFixtureDoc("transferReceipt",
        receiptFields({ proofBytes: bytes(D1_BOUNDS.B + 1) })), "proofBytes at 5121"),
    "capacity-metadataBytes-max-accepted": async () =>
      expectAccept(await deps.writeFixtureDoc("transferReceipt",
        receiptFields({ metadataBytes: bytes(D1_BOUNDS.metadataCapacity) })), "metadataBytes at 512"),
    "capacity-metadataBytes-plus-1-refused": async () =>
      expectRefuse(await deps.writeFixtureDoc("transferReceipt",
        receiptFields({ metadataBytes: bytes(D1_BOUNDS.metadataCapacity + 1) })), "metadataBytes at 513"),
    "capacity-transitionBytes-max-accepted": async () =>
      expectAccept(await deps.writeFixtureDoc("transferReceipt",
        receiptFields({ transitionBytes: bytes(D1_BOUNDS.transitionBytesMax) })), "transitionBytes at 2048"),
    "capacity-transitionBytes-plus-1-refused": async () =>
      expectRefuse(await deps.writeFixtureDoc("transferReceipt",
        receiptFields({ transitionBytes: bytes(D1_BOUNDS.transitionBytesMax + 1) })), "transitionBytes at 2049"),
    "capacity-minimum-boundaries": async () => {
      const okMin = await deps.writeFixtureDoc("receiptProofPart",
        { poolId: H32, accrualId: bytes(32, 0x55), partIndex: 1, bytes: bytes(1) });
      await expectAccept(okMin, "part bytes at the 1-byte minimum");
      const under = await deps.writeFixtureDoc("receiptProofPart",
        { poolId: H32, accrualId: bytes(32, 0x66), partIndex: 2, bytes: bytes(0) });
      await expectRefuse(under, "part bytes at 0");
      const underTb = await deps.writeFixtureDoc("transferReceipt",
        receiptFields({ transitionBytes: bytes(D1_BOUNDS.transitionBytesMin - 1) }));
      await expectRefuse(underTb, "transitionBytes at 99");
      return "min accepted at 1; 0 and 99 refused";
    },
    "semantic-credit-transfer-capture": async () => {
      const t = await deps.creditTransfer({ amountCredits: 100000n });
      await expectAccept(t, "the credit transfer");
      const c = t.capture;
      captureRecord.validateRecordShape(c);
      if (!(await captureRecord.verifyCaptureSignature(c, await deps.resolveSignerKey(c)))) {
        refuse("the transfer capture's signature does not verify");
      }
      if (c.transitionHash !== sha256hex(Buffer.from(c.transitionBytes, "hex"))) {
        // clause 2 as the verifier computes it (hash of the BYTES)
        refuse("the transfer capture's transitionHash is not SHA-256 of its transitionBytes");
      }
      const L = c.transitionBytes.length / 2;
      if (L < D1_BOUNDS.transitionBytesMin || L > D1_BOUNDS.transitionBytesMax) {
        refuse(`the real transfer's transitionBytes length ${L} is outside the schema's ${D1_BOUNDS.transitionBytesMin}..${D1_BOUNDS.transitionBytesMax} (duty D3's empirical re-derivation FAILS and the bound must move)`);
      }
      // the capture is compared against the DERIVED maxima, not only the schema
      // capacities (D1's own rule: a capture beyond the derivation refutes the
      // derivation even where the schema would still hold it)
      const pmL = c.proofMsg.length / 2;
      if (pmL > D1_BOUNDS.proofMsgMax) {
        refuse(`the real transfer's proofMsg length ${pmL} exceeds the derived proofMsg_max ${D1_BOUNDS.proofMsgMax}; the derivation is refuted and must be redone`);
      }
      const mmL = c.metadataMsg.length / 2;
      const mdMax = metadataMaxForPin(Buffer.byteLength(deps.pin, "utf8"));
      if (mmL > mdMax) {
        refuse(`the real transfer's metadataMsg length ${mmL} exceeds the derived metadata maximum ${mdMax} for the live pin; the derivation is refuted and must be redone`);
      }
      // the validity clauses run for the TRANSFER capture too (conformance and
      // both proof stages; the pre-commit check found only the header exercised
      // them), with the verdict read, never inferred from the absence of a throw
      const tv = await receiptVerify.verifyCaptureRecord({ capture: c,
        servedFor: { poolId: c.poolId, accrualId: c.accrualId },
        chainIdPin: deps.pin, deps: deps.verify });
      if (!tv || tv.status !== "verified") {
        refuse(`the transfer capture fails the validity clauses (${(tv && tv.reason) || "no verdict"})`);
      }
      // the receipt-schema encoding and the byte-identical reassembly
      const split = splitCarrier(c.proofMsg);
      const back = receiptVerify.__testing.reassembleProof(
        { proofBytes: split.proofBytes, proofPartCount: split.proofPartCount,
          poolId: c.poolId, accrualId: c.accrualId || "22".repeat(32) },
        split.parts.map((p) => ({ partIndex: p.partIndex, bytes: p.bytes,
          poolId: c.poolId, accrualId: c.accrualId || "22".repeat(32) })));
      if (back !== c.proofMsg) refuse("the transfer capture's carrier does not reassemble byte-identically");
      return `transitionBytes=${L} (in ${D1_BOUNDS.transitionBytesMin}..${D1_BOUNDS.transitionBytesMax}); carrier ${c.proofMsg.length / 2} bytes in ${split.proofPartCount} part(s), reassembly byte-identical`;
    },
    "semantic-header-capture-probe-contract": async () => {
      const h = await deps.headerCapture();
      await expectAccept(h, "the probe-contract header write");
      const c = h.capture;
      captureRecord.validateRecordShape(c);
      if (!(await captureRecord.verifyCaptureSignature(c, await deps.resolveSignerKey(c)))) {
        refuse("the header capture's signature does not verify");
      }
      const hpmL = c.proofMsg.length / 2;
      if (hpmL > D1_BOUNDS.proofMsgMax) {
        refuse(`the header capture's proofMsg length ${hpmL} exceeds the derived proofMsg_max ${D1_BOUNDS.proofMsgMax}`);
      }
      const hmmL = c.metadataMsg.length / 2;
      if (hmmL > metadataMaxForPin(Buffer.byteLength(deps.pin, "utf8"))) {
        refuse(`the header capture's metadataMsg length ${hmmL} exceeds the derived metadata maximum for the live pin`);
      }
      const v = await receiptVerify.verifyCaptureRecord({ capture: c,
        servedFor: { poolId: c.poolId, epochIndex: c.epochIndex, contractId: deps.probeContractIdHex },
        chainIdPin: deps.pin, deps: deps.verify });
      if (!v || v.status !== "verified") {
        refuse(`the header capture fails the validity clauses (${(v && v.reason) || "no verdict"})`);
      }
      return `header capture verified on the probe contract (pool ${c.poolId.slice(0, 12)}, epoch ${c.epochIndex}, contract binding driver-named)`;
    },
  };
  return runRoster(PRE_REGISTRATION_ROSTER, impls);
};

/**
 * THE CANONICAL PHASE, the battery's one-shot gate path. Preconditions per
 * the gate matrix row (CONTRACT_V11_ID present; formation setup done, the
 * pre-header proved reads' subjects existing, established by the injected
 * check); the header semantic capture re-run against canonical v11; on its
 * verification ONLY, the gate key is written atomically in its closed
 * canonical format. The write-once semantics come from envStore's key class:
 * set-when-absent, equal-rewrite idempotent, differing-update refused, so a
 * concurrent start that produced a DIFFERING digest surfaces for human
 * decision rather than overwriting.
 */
const runCanonicalPhase = async ({ deps }) => {
  for (const k of ["headerCapture", "formationSetupDone", "resolveCaptureByKey", "resolveSignerKey"]) {
    if (typeof (deps && deps[k]) !== "function") refuse(`runCanonicalPhase needs deps.${k}`);
  }
  const readEnv = deps.readEnv || (() => envStore.loadEnv());
  const writeKey = deps.writeEnvKey || ((k, v) => envStore.updateEnvKey(k, v));
  // the verified capture is INVOCATION-LOCAL (an earlier draft parked it on the
  // caller-shared deps object, where two interleaved phases could read each
  // other's capture and turn a genuine conflict into a false idempotent
  // success; the pre-commit check constructed the interleaving)
  let verifiedCanonicalCapture = null;

  const impls = {
    "preconditions-canonical-contract-and-formation": async () => {
      const v11 = readEnv().CONTRACT_V11_ID;
      if (typeof v11 !== "string" || v11.length === 0) {
        refuse("CONTRACT_V11_ID is not set: the canonical phase runs strictly after registration");
      }
      const f = await deps.formationSetupDone();
      if (f !== true) refuse("formation setup on canonical v11 is not done (the pre-header proved reads' subjects must exist)");
      return `canonical contract ${String(v11).slice(0, 12)}..., formation setup done`;
    },
    "semantic-header-capture-canonical": async () => {
      const h = await deps.headerCapture();
      if (!h || h.outcome !== "verified-proof") {
        refuse(`the canonical header write did not commit (outcome=${h && h.outcome})`);
      }
      const c = h.capture;
      captureRecord.validateRecordShape(c);
      if (!(await captureRecord.verifyCaptureSignature(c, await deps.resolveSignerKey(c)))) {
        refuse("the canonical header capture's signature does not verify");
      }
      // clause 4 binds against the CANONICAL contract in the capture's hex
      // spelling (self-passing the capture's own contractId makes the clause
      // vacuous, the strict lookup's own fix applied here too)
      const canonHex = idTo32(readEnv().CONTRACT_V11_ID);
      if (!canonHex) refuse("CONTRACT_V11_ID decodes to neither base58 nor 64-hex");
      const v = await receiptVerify.verifyCaptureRecord({ capture: c,
        servedFor: { poolId: c.poolId, epochIndex: c.epochIndex, contractId: canonHex.toString("hex") },
        chainIdPin: deps.chainIdPin !== undefined ? deps.chainIdPin : envStore.readChainIdPin().chainId,
        deps: deps.verify });
      if (!v || v.status !== "verified") {
        refuse(`the canonical header capture fails the validity clauses (${(v && v.reason) || "no verdict"})`);
      }
      if (!idBytesEqual(c.contractId, readEnv().CONTRACT_V11_ID)) {
        refuse("the canonical capture's contract identifier does not equal CONTRACT_V11_ID (decoded-byte comparison)");
      }
      verifiedCanonicalCapture = c;
      return `canonical header capture verified (pool ${c.poolId.slice(0, 12)}, epoch ${c.epochIndex}, gen ${c.gen})`;
    },
    "gate-key-write-once": async () => {
      const c = verifiedCanonicalCapture;
      if (!c) refuse("the gate write runs strictly after the canonical capture verified; no verified capture is held");
      const artifact = buildGateArtifact({ contractId: readEnv().CONTRACT_V11_ID,
        poolId: c.poolId, epochIndex: c.epochIndex, gen: c.gen,
        preimageDigest: captureRecord.preimageDigest(c) });
      // envStore's write-once class supplies the concurrent-start dichotomy:
      // an equal value is the idempotent success, a differing one refuses here.
      // ORDER, at its real width: the spec writes the key exactly when the
      // canonical capture VERIFIES (the clauses above), and the strict lookup
      // that follows is the consumer-side check. A lookup failure AFTER this
      // write (a lost journal, a changed pin) leaves the key standing and the
      // phase FAILED, which is the write-once design's human-decision surface:
      // a rerun with the SAME capture is the idempotent success, and only a
      // DIFFERING capture refuses, exactly as the concurrent-start rule states.
      writeKey(GATE_KEY, artifact);
      return `gate key written (${artifact.length} canonical bytes)`;
    },
    "strict-lookup-verifies": async () => {
      const r = await verifyGateCapture({ deps: {
        resolveCaptureByKey: deps.resolveCaptureByKey, readEnv,
        resolveSignerKey: deps.resolveSignerKey,
        chainIdPin: deps.chainIdPin, verify: deps.verify } });
      if (r.admitted !== true) refuse("the strict lookup did not admit the freshly written gate");
      return "the strict lookup admits the written gate";
    },
  };
  return runRoster(CANONICAL_ROSTER, impls);
};

module.exports = {
  D1_BOUNDS, GATE_KEY, CAPTURE_KIND,
  PRE_REGISTRATION_ROSTER, CANONICAL_ROSTER,
  splitCarrier, assertD1Coverage,
  buildGateArtifact, parseGateArtifact, verifyGateCapture,
  runPreRegistrationPhase, runCanonicalPhase,
};
