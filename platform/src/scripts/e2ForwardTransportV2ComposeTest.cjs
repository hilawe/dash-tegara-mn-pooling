/**
 * e2ForwardTransportV2ComposeTest: the offline battery for the live runner's v2 composition
 * (e2ForwardTransportV2Compose.cjs). Plain `node`, no network: the wire calls are fakes (a
 * proved read serving a pool and its completion receipt built by the pair check's own fixture
 * builders, a validated journal read, an epoch enumeration), and everything downstream is
 * REAL: the pair check, formationCore's hash, runFromJournal, the discovery factory, the
 * context module over the installed generator, the capture-record kinds, and, for the
 * positive control, the transport instrument itself with the verifier test's mock pipeline
 * over the COMMITTED v2 profile.
 *
 * WHAT IT BINDS:
 *   1. the positive control: the composed inputs drive the real instrument to PASS the
 *      committed bootstrap profile (universe [0, 1], epoch 1 fresh), the formation carrying
 *      the pool owner as the income identity and the recomputed hash, the capture found by
 *      planned identifier, the projection and generation sequence as section 7 predicts;
 *   2. the configuration refusals: the profile kind against the mode, the universe end
 *      (absent, non-canonical, below the target), a self-share list, and every malformed
 *      declared-fixture shape INCLUDING an entry for an epoch outside the universe;
 *   3. the resolution refusals: a different served pool, a failed pair check, a non-evo
 *      pool, an altered allocation hash, an unusable metadata epoch;
 *   4. the journal and discovery refusals: no configured start, a reversed interval, an
 *      enumeration fallback, an empty universe;
 *   5. the capture lookup: null for an unknown identifier, the capture with the receipt
 *      supersessions for a known one, a FAULT on two captures under one identifier.
 *
 * WHAT IT DOES NOT ESTABLISH: anything about the live transport, the SDK's proved read, the
 * verifier pipeline the runner builds from the SDK, or the devnet.
 */
"use strict";

const path = require("path");
const crypto = require("crypto");
const fs = require("fs");
const { pathToFileURL } = require("url");
process.env.LEDGER = process.env.LEDGER || "v11";   // the runner's ledger; the pair check selects its shape from it
const core = require("./formationCore.cjs");
const { buildV11 } = require("./contractV11.cjs");
const { canonicalString } = require("./canonicalJson.cjs");
const { PART_BOUND_B } = require("./e2ReceiptVerify.cjs");
const D = require("./e2DocId.cjs");
const captureRecord = require("./e2CaptureRecord.cjs");
const C = require("./e2ForwardTransportCheck.cjs");
const M = require("./e2ForwardTransportV2Compose.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) { passed += 1; console.log(`  PASS: ${name}`); } else { failed += 1; console.log(`  FAIL: ${name}`); } };
const rejects = async (name, p, re) => {
  try { await p; failed += 1; console.log(`  FAIL: ${name} (no refusal)`); }
  catch (e) { const m = (e && e.message) || String(e); ok(`${name} (${m.slice(0, 90)})`, re.test(m)); }
};
const throws = (name, fn, re) => {
  try { fn(); failed += 1; console.log(`  FAIL: ${name} (no refusal)`); }
  catch (e) { const m = (e && e.message) || String(e); ok(`${name} (${m.slice(0, 90)})`, re.test(m)); }
};

// ---- the pair check's golden fixtures (receiptPoolCheckTest), a two-owner evo pool ----
const GC = "3EbgWjxUoX6J9XbqqxrEktm7tUFBQ5fQyKaiAzXCULxf"; // contract id, base58
const GP = "47doihuxfjfeoqi4PrKLY58Z56J6BhXekMmhW3z63QT8"; // pool id, base58
const OA = "8sCudmZNvmDC9nXCGRWk1NMStKaeqCaWLa7eYTEKuT8Y"; // the pool owner, the income identity
const OB = "52D4DcjgFZU1KktALjGpcfGoxR1987BEjTXxbnNcNfAc"; // the payable member
const OC = "FZ9HF6oANQxZDXGXGiKh8uXdPfwcp4rwfrzqQJcdRNgv"; // a stranger
const hexOf = (b58) => core.decodeId32(b58).toString("hex");
const CONTRACT_HEX = hexOf(GC), POOL = hexOf(GP), A = hexOf(OA), B = hexOf(OB);
const B58 = { [POOL]: GP, [A]: OA, [B]: OB, [CONTRACT_HEX]: GC };
const b58Of = (hex) => { if (!B58[hex]) throw new Error(`test b58Of: no base58 for ${hex.slice(0, 8)}`); return B58[hex]; };
const EVO = "400000000000";
const CHAIN = "tegara-test-1";
const manifest = (owners = [[OA, 5000], [OB, 5000]]) => {
  const t = BigInt(EVO);
  return { v: 1, poolId: GP, realHash: "aa".repeat(32), target: EVO,
    owners: owners.map(([owner, bps], i) => ({ owner, amountDuffs: String(t * BigInt(bps) / 10000n), bps, rewardScriptHex: "76a914" + String(11 * (i + 1)).repeat(20).slice(0, 40) + "88ac" })) };
};
const receiptPropsFor = (m) => { const rows = core.allocationPreimage(GC, m); return { poolId: Buffer.from(core.decodeId32(m.poolId)), proTxHash: Buffer.from(m.realHash, "hex"), slotIndex: 0, formatVersion: 1, allocationRows: rows, allocationHash: core.allocationHash(rows), participantCount: m.owners.length, l1Verification: "demo-unverified", verificationMethodVersion: 1 }; };
const poolPropsFor = ({ nodeType = "evo" } = {}) => ({ slotIndex: 0, nodeType, operatorFeeBps: 2000, targetDuffs: Number(EVO), slotDuffs: Number(BigInt(EVO) / 2n), slotCount: 2 });
const docOf = (id, props, owner) => ({ id, getProperties: () => props, getOwnerId: () => owner });
const ALLOC_HASH = core.allocationHash(core.allocationPreimage(GC, manifest())).toString("hex");

// the injected reads, each overridable per case
const mkProvedOne = ({ poolDoc, receiptDoc, epoch = 5 } = {}) => {
  const pd = poolDoc || docOf(GP, poolPropsFor(), OA);
  const rd = receiptDoc || docOf("11".repeat(32), receiptPropsFor(manifest()), OA);
  const calls = [];
  // THE PREDICATE IS SNAPSHOTTED AT CALL TIME, buffers copied, so a caller that repairs its
  // array after the call cannot change what the assertion reads (the third pass's route)
  const snapshot = (where) => where.map(([f, op, v]) => [f, op, Buffer.isBuffer(v) ? Buffer.from(v) : v]);
  return { calls, provedOne: async (type, where, label) => { calls.push({ type, where: snapshot(where), label }); if (type === "pool") return { doc: pd, marker: { metadata: { epoch, height: "1000" }, call: "documents.query" } }; if (type === "completionReceipt") return { doc: rd, marker: { metadata: { epoch, height: "1000" }, call: "documents.query" } }; throw new Error(`${label}: unexpected type ${type}`); } };
};
const GROSS = "2000000", FEE = "0";
const journalHeader = (gross = GROSS, fee = FEE) => ({ grossCredits: gross, feeCredits: fee, allocationHash: ALLOC_HASH, memberCount: 2 });
const mkRead = ({ configuredStartEpoch = 0, perEpoch = { 0: { header: journalHeader() } }, records = [] } = {}) => ({ configuredStartEpoch, perEpoch, records });
// the interval route's fake: every epoch that exists inside the requested inclusive
// interval, ascending, and nothing else. mkEnumeration serves a DENSE history below the
// given current epoch; mkSparseEnumeration serves one with gaps, which is the live shape.
const ENUM_META = { height: "1000", chainId: CHAIN };
const mkEnumeration = (currentEpoch) => async (a, b) => { const out = []; for (let n = a; n <= b && n < currentEpoch; n++) out.push({ number: n }); return { epochs: out, metadata: { ...ENUM_META, epoch: currentEpoch } }; };
const mkSparseEnumeration = (currentEpoch, absent) => async (a, b) => { const out = []; for (let n = a; n <= b && n < currentEpoch; n++) if (!absent.includes(n)) out.push({ number: n }); return { epochs: out, metadata: { ...ENUM_META, epoch: currentEpoch } }; };
const target = (n = 0) => ({ contractId: CONTRACT_HEX, chainId: CHAIN, contractVersion: 11, poolId: POOL, epochIndex: n });

const main = async () => {
  const ROOT = process.env.TEGARA_PLATFORM_ROOT || path.join(__dirname, "..", "..");
  const dpp = await import(pathToFileURL(require.resolve("pshenmic-dpp", { paths: [ROOT] })).href);
  const { poolLedgerContract } = await import(pathToFileURL(path.join(ROOT, "dist/contract/poolLedger.js")).href);
  const ledger = buildV11(poolLedgerContract);
  const OWNER_B58 = "5jLZJF4RurvAkahXhLLHHgBisEDgs58v8AmP8w7cMqe";
  const identifiers = { generateId: (...a) => dpp.DocumentWASM.generateId(...a), ownerId: OWNER_B58, contractId: GC };
  const plannedIdOf = (n, f) => D.docIdForIn({ ...identifiers, poolId: POOL, epochIndex: n, type: "platformAccrual", subject: f }).hex;
  const ACC_A = plannedIdOf(0, A), ACC_B = plannedIdOf(0, B);

  // ---- the verifier fixture (the instrument test's, at the verifier's contract) ----
  const toHex = (t) => Buffer.from(t, "utf8").toString("hex"), fromHex = (x) => Buffer.from(x, "hex").toString("utf8");
  const sha = (hex) => crypto.createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");
  const be64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b.toString("hex"); };
  const PROOF_KNOWN = ["quorumHash", "round", "blockIdHash", "quorumType", "signature", "pad"], META_KNOWN = ["chainId", "protocolVersion", "height", "timeMs", "coreChainLockedHeight", "epoch", "pad"];
  const mockDecode = (known) => (hex) => { const obj = JSON.parse(fromHex(hex)); const out = {}; for (const [k, v] of Object.entries(obj)) if (known.includes(k)) out[k] = v; return { fields: out, reencodedHex: toHex(canonicalString(out)) }; };
  const mkDeps = () => { const calls = { stageOne: 0, stageTwo: 0, basis: 0 }; return { calls, deps: { verifierDeps: {
    decodeProofCarrier: (hex) => { const d = mockDecode(PROOF_KNOWN)(hex); return { reencodedHex: d.reencodedHex, quorumHashHex: d.fields.quorumHash, round: d.fields.round }; },
    decodeMetadata: (hex) => { const d = mockDecode(META_KNOWN)(hex); return { reencodedHex: d.reencodedHex, ...d.fields }; },
    decodeTransfer: (hex) => JSON.parse(fromHex(hex)),
    verifyStageOne: async (a) => { calls.stageOne += 1; return { ok: true, rootHashHex: sha(a.carrierHex) }; },
    verifyStageTwo: async () => { calls.stageTwo += 1; return true; } }, verifyCaptureBasis: async () => { calls.basis += 1; return true; } } }; };
  const h = (f) => f.repeat(64 / f.length);
  const carrierOfLength = (wantL) => { const mk = (n) => toHex(canonicalString({ quorumHash: h("dd"), round: 3, blockIdHash: h("bb"), quorumType: 4, signature: "cd".repeat(Math.max(1, n)) })); let padLen = 1, hex = mk(padLen); padLen += wantL - hex.length / 2; hex = mk(Math.floor(padLen)); while (hex.length / 2 < wantL) { padLen += 1; hex = mk(padLen); } while (hex.length / 2 > wantL) { padLen -= 1; hex = mk(padLen); } return hex; };
  const bigCarrier = carrierOfLength(2 * PART_BOUND_B + 100);
  const META_HEX = toHex(canonicalString({ chainId: CHAIN, protocolVersion: 12, height: "1000", timeMs: "1690000000000", coreChainLockedHeight: 777, epoch: 5 }));
  const AMOUNT_B = "1000000";
  const TRANSFER_HEX = toHex(canonicalString({ senderId: A, recipientId: B, amountCredits: AMOUNT_B, nonce: "7" }));
  const TH = sha(TRANSFER_HEX);
  const L = bigCarrier.length / 2, count = Math.ceil(L / PART_BOUND_B);
  const proofBytes = bigCarrier.slice(0, PART_BOUND_B * 2);
  const partBytes = (i) => bigCarrier.slice(i * PART_BOUND_B * 2, Math.min((i + 1) * PART_BOUND_B, L) * 2);
  const capture = { v: 1, kind: captureRecord.RECEIPT_KIND, object: "transfer", gen: 1, poolId: POOL, epochIndex: 0, accrualId: ACC_B, transitionHash: TH, transitionBytes: TRANSFER_HEX,
    proofMsg: bigCarrier, metadataMsg: META_HEX, inclusionHeight: "1001", heightRoute: "tenderdash-tx", signerIdentity: h("f0"), signerKeyId: 2, sig: "00".repeat(65) };
  const doc = (id, fields) => ({ id, fields });
  const docs = () => ({
    epochHeader: [doc(h("7700"), { poolId: POOL, epochIndex: 0, grossCredits: 2000000, feeCredits: 0, memberCount: 2, calcVersion: 1, allocationHash: ALLOC_HASH })],
    platformAccrual: [doc(ACC_A, { poolId: POOL, funderId: A, epochIndex: 0, amountCredits: 1000000, shareBps: 5000 }), doc(ACC_B, { poolId: POOL, funderId: B, epochIndex: 0, amountCredits: 1000000, shareBps: 5000 })],
    transferReservation: [doc(h("d100"), { poolId: POOL, accrualId: ACC_B, transitionHash: TH })],
    transferReceipt: [doc(h("c000"), { poolId: POOL, accrualId: ACC_B, transitionHash: TH, transitionBytes: TRANSFER_HEX, proofBytes, proofPartCount: count, metadataBytes: META_HEX, blockHeight: be64(1000), coreChainLockedHeight: 777, timeMs: be64("1690000000000"), quorumHash: h("dd"), round: 3 })],
    receiptProofPart: [doc(h("e100"), { poolId: POOL, accrualId: ACC_B, partIndex: 1, bytes: partBytes(1) }), doc(h("e200"), { poolId: POOL, accrualId: ACC_B, partIndex: 2, bytes: partBytes(2) })],
  });
  const INDEX_ERROR = "where%20clause%20on%20non%20indexed%20property%20error:%20query%20must%20be%20for%20valid%20indexes,%20valid%20indexes%20are:%20%7B%22byAccrual%22:%20Index%20%7B%20name:%20%22byAccrual%22";
  const makeQuery = (store) => async (type, where, { limit }) => {
    if (type === "transferReceipt" && where.length === 2) throw new Error(INDEX_ERROR);
    const found = (store[type] || []).filter((d) => where.every(([k, , v]) => d.fields[k] === v)).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return { documents: found.slice(0, limit), height: "100" };
  };
  // the COMMITTED profile, resolved through the platform root so a battery stage (which copies
  // the scripts alone) still reads the real file
  const PROFILE_V2 = JSON.parse(fs.readFileSync(path.join(ROOT, "src", "scripts", "fixtures", "forwardTransportProfile-bootstrap-epochs01-v2.json"), "utf8"));
  const provenance = (incomeIdentity) => ({
    sourceCommit: "0123456789abcdef", treeState: "clean", diffSha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    inputHashes: { runner: "a".repeat(64), check: "b".repeat(64), sourceTree: "f".repeat(64), ledgerModule: "c".repeat(64), patches: { "query.js": "d".repeat(64) } },
    ...target(0), classificationInput: { incomeIdentity }, expectationProfile: { path: "fixtures/x.json", sha256: "e".repeat(64) },
    synthetic: { ...C.V2_SYNTHETIC }, at: "2026-09-18T00:00:00.000Z",
  });
  const compose = (over = {}) => M.composeV2Inputs({ poolId: POOL, contractId: GC, target: target(0), universeEnd: 1, declared: {},
    provedOne: mkProvedOne().provedOne, b58Of, readJournal: () => mkRead({ records: [capture] }), readEpochInterval: mkEnumeration(5), identifiers, log: () => {}, ...over });
  const failedChecks = (v) => v.results.filter((r) => r.required && !r.pass).map((r) => r.check);

  // ================= 1. the positive control through the real instrument =================
  {
    // the resolution ALONE first, so a formation defect is observed here by name rather than
    // as the context builder's downstream refusal (the battery's A8 was wrong-path without it)
    const rf = await M.resolveFormation({ poolId: POOL, contractId: GC, provedOne: mkProvedOne().provedOne, b58Of });
    const rfSorted = [...rf.formation.allocation].sort((x, y) => (x.recipientId < y.recipientId ? -1 : 1));
    ok("resolveFormation alone answers exactly the two owners with their bps, the pool owner as the income identity and the recomputed hash", rf.formation.allocation.length === 2 && JSON.stringify(rfSorted.map((r) => [r.recipientId, r.bps])) === JSON.stringify([[A, 5000], [B, 5000]].sort((x, y) => (x[0] < y[0] ? -1 : 1))) && rf.incomeIdentity === A && rf.formation.allocationHash === ALLOC_HASH && rf.poolMarker.metadata.epoch === 5);
    const inputs = await compose();
    // the allocation's order is the preimage builder's canonical order (it sorts the owners), so
    // the members are compared as a set with exact identities and exact bps
    const allocSorted = [...inputs.formation.allocation].sort((x, y) => (x.recipientId < y.recipientId ? -1 : 1));
    ok("the formation carries the pool owner as the income identity, the recomputed hash and exactly the two owners in canonical form", inputs.incomeIdentity === A && inputs.formation.incomeIdentity === A && inputs.formation.allocationHash === ALLOC_HASH && inputs.formation.allocation.length === 2 && JSON.stringify(allocSorted) === JSON.stringify([{ recipientId: A, bps: 5000 }, { recipientId: B, bps: 5000 }].sort((x, y) => (x.recipientId < y.recipientId ? -1 : 1))) && inputs.formation.resolved === true && Object.isFrozen(inputs.formation));
    ok("the current epoch is the pool read's metadata epoch, the configured start the journal's, the run [0], the universe [0, 1]", inputs.currentEpoch === 5 && inputs.configuredStart === 0 && inputs.journalRun.map((e) => e.number).join() === "0" && inputs.journalRun[0].grossCredits === GROSS && inputs.universe.join() === "0,1");
    const c0 = inputs.contextFor(0), c1 = inputs.contextFor(1);
    ok("epoch 0's context is journaled-header with two rows and epoch 1's carries the C1 precondition", c0.figuresSource === "journaled-header" && c0.rows.length === 2 && c0.precondition === null && c1.precondition !== null && c1.precondition.code === "UNPROVED_EPOCH_OBJECT_UNPROVED" && c1.figuresSource === "epoch-object-unproved-c1");
    ok("the context's rows classify the pool owner as the self-share and carry the planned identifiers", c0.rows.find((r) => r.funderId === A).isSelfShare === true && c0.rows.find((r) => r.funderId === B).isSelfShare === false && c0.rows.find((r) => r.funderId === B).plannedAccrualId === ACC_B);
    throws("contextFor refuses an epoch outside the universe", () => inputs.contextFor(2), /no context was built for that epoch/);
    const found = inputs.captureFor(ACC_B);
    ok("captureFor answers the journaled capture for the planned identifier with its (empty) receipt supersessions", found !== null && found.capture === capture && Array.isArray(found.supersessions) && found.supersessions.length === 0);
    ok("captureFor answers null for a planned identifier the journal does not hold", inputs.captureFor(ACC_A) === null);
    const { deps, calls } = mkDeps();
    const r = await C.runTransportCheck({ query: makeQuery(docs()), ledger, profile: PROFILE_V2, provenance: provenance(inputs.incomeIdentity), acceptance: true, target: target(0),
      contextFor: inputs.contextFor, universe: inputs.universe, captureFor: inputs.captureFor, deps });
    ok(`the composed inputs drive the real instrument to PASS the committed v2 profile (${failedChecks(r.verdict).join(",") || "no failed check"})`, r.verdict.pass === true && r.exitCode === 0 && r.artifact.kind === "tegara.e2.forwardTransportArtifact.v2");
    const obsOf = (name) => r.artifact.observations.find((o) => o.name === name).value;
    ok("the run took generations [0, 1, 2] with epoch 0 complete in every one and epoch 1 unproved, no early stop", JSON.stringify(obsOf("13.generations").map((g) => [g.generation, g.epochs[0].state, g.epochs[1].state])) === JSON.stringify([[0, "complete", "unproved"], [1, "complete", "unproved"], [2, "complete", "unproved"]]) && obsOf("13c.earlyStop") === null);
    ok("the verifier's stages ran through the composed capture lookup (the verdict owner is the shared verifier)", calls.stageOne >= 1 && calls.stageTwo >= 1 && calls.basis >= 1 && r.verdict.results.find((x) => x.check === "verdictOwner").pass === true);
    ok("the plan input was derived at adapter read count zero", JSON.stringify(obsOf("3.planInputsCapturedAtReadCount")) === JSON.stringify({ 0: 0 }));
  }

  // ================= 2. the configuration =================
  {
    ok("requireProfileKind accepts the committed v2 profile under v2 and the v1 kind under v1", M.requireProfileKind(PROFILE_V2, "v2") === C.PROFILE_KIND_V2 && M.requireProfileKind({ kind: C.PROFILE_KIND }, "v1") === C.PROFILE_KIND);
    throws("requireProfileKind refuses the v2 file under v1", () => M.requireProfileKind(PROFILE_V2, "v1"), /not the v1 kind/);
    throws("requireProfileKind refuses a v1 file under v2", () => M.requireProfileKind({ kind: C.PROFILE_KIND }, "v2"), /not the v2 kind/);
    throws("requireProfileKind refuses an unknown mode", () => M.requireProfileKind(PROFILE_V2, "v3"), /must be v1 or v2/);
    const base = { universeEndRaw: "1", declaredRaw: "", selfShareCount: 0, targetEpoch: 0 };
    const parsed = M.parseV2Config(base);
    ok("a bare configuration parses to the end and no fixtures", parsed.universeEnd === 1 && JSON.stringify(parsed.declared) === "{}");
    throws("a missing universe end refuses", () => M.parseV2Config({ ...base, universeEndRaw: "" }), /E2_FORWARD_UNIVERSE_END must be a canonical/);
    throws("a non-canonical universe end (leading zero) refuses", () => M.parseV2Config({ ...base, universeEndRaw: "01" }), /E2_FORWARD_UNIVERSE_END must be a canonical/);
    throws("a hex universe end refuses", () => M.parseV2Config({ ...base, universeEndRaw: "0x10" }), /E2_FORWARD_UNIVERSE_END must be a canonical/);
    throws("a universe end below the target refuses", () => M.parseV2Config({ ...base, universeEndRaw: "0", targetEpoch: 1 }), /below the target epoch/);
    throws("a self-share list refuses under v2", () => M.parseV2Config({ ...base, selfShareCount: 1 }), /takes no list/);
    const good = M.parseV2Config({ ...base, declaredRaw: JSON.stringify({ 1: { grossCredits: "5", feeCredits: "1" } }) });
    ok("a well-formed fixture parses with string values kept", JSON.stringify(good.declared) === JSON.stringify({ 1: { grossCredits: "5", feeCredits: "1" } }));
    throws("non-JSON fixtures refuse", () => M.parseV2Config({ ...base, declaredRaw: "{nope" }), /not JSON/);
    throws("an array of fixtures refuses", () => M.parseV2Config({ ...base, declaredRaw: "[]" }), /object keyed by epoch index/);
    throws("a non-epoch key refuses", () => M.parseV2Config({ ...base, declaredRaw: JSON.stringify({ x: { grossCredits: "5", feeCredits: "1" } }) }), /not an epoch index/);
    throws("a fixture with an extra member refuses", () => M.parseV2Config({ ...base, declaredRaw: JSON.stringify({ 1: { grossCredits: "5", feeCredits: "1", memberCount: 2 } }) }), /exactly \{ grossCredits, feeCredits \}/);
    throws("a numeric gross refuses", () => M.parseV2Config({ ...base, declaredRaw: JSON.stringify({ 1: { grossCredits: 5, feeCredits: "1" } }) }), /grossCredits must be a canonical decimal STRING/);
    throws("a non-decimal gross under an epoch outside the universe refuses at parse time (the first pass's construction)", () => M.parseV2Config({ ...base, declaredRaw: JSON.stringify({ 2: { grossCredits: "invalid", feeCredits: "-1" } }) }), /grossCredits must be a canonical decimal STRING/);
    // THE FEE CHECK ON ITS OWN, with a VALID gross, so a deleted fee branch is observed here
    // and not hidden behind the gross refusal (the second pass's construction)
    throws("a numeric fee beside a valid gross refuses", () => M.parseV2Config({ ...base, declaredRaw: JSON.stringify({ 1: { grossCredits: "5", feeCredits: 1 } }) }), /feeCredits must be a canonical decimal STRING/);
    throws("a negative-string fee beside a valid gross refuses", () => M.parseV2Config({ ...base, declaredRaw: JSON.stringify({ 1: { grossCredits: "5", feeCredits: "-1" } }) }), /feeCredits must be a canonical decimal STRING/);
    // POSITIVE BUT NONCANONICAL fee strings (the third pass's construction: a check narrowed to
    // "not a string or starts with a minus" survives the two cases above)
    throws("a zero-padded fee beside a valid gross refuses", () => M.parseV2Config({ ...base, declaredRaw: JSON.stringify({ 1: { grossCredits: "5", feeCredits: "01" } }) }), /feeCredits must be a canonical decimal STRING/);
    throws("a hex fee beside a valid gross refuses", () => M.parseV2Config({ ...base, declaredRaw: JSON.stringify({ 1: { grossCredits: "5", feeCredits: "0x1" } }) }), /feeCredits must be a canonical decimal STRING/);
    throws("a fee above gross refuses", () => M.parseV2Config({ ...base, declaredRaw: JSON.stringify({ 1: { grossCredits: "5", feeCredits: "6" } }) }), /feeCredits above grossCredits/);
    await rejects("a well-formed fixture for an epoch OUTSIDE the universe refuses at composition", compose({ declared: { 2: { grossCredits: "5", feeCredits: "1" } } }), /outside the universe \[0,1\]/);
    await rejects("a fixture for the JOURNALED epoch 0 that disagrees with its header is the builder's refusal (two sources for one epoch)", compose({ declared: { 0: { grossCredits: "1", feeCredits: "0" } } }), /two sources for one epoch must agree/);
    const withFixture = await compose({ declared: { 1: { grossCredits: "3000000", feeCredits: "0" } } });
    ok("a fixture on the fresh epoch builds a declared-fixture context instead of the precondition", withFixture.contextFor(1).figuresSource === "declared-fixture" && withFixture.contextFor(1).precondition === null);
  }

  // ================= 3. the resolution =================
  {
    const otherPool = docOf(OC, poolPropsFor(), OA);
    await rejects("a served pool other than the one asked for refuses", compose({ provedOne: mkProvedOne({ poolDoc: otherPool }).provedOne }), /returned a different document/);
    await rejects("a receipt owned by someone other than the pool owner fails the pair check", compose({ provedOne: mkProvedOne({ receiptDoc: docOf("11".repeat(32), receiptPropsFor(manifest()), OC) }).provedOne }), /pair check refused/);
    await rejects("a regular pool at the evo target fails the pair check before the eligibility predicate is reached", compose({ provedOne: mkProvedOne({ poolDoc: docOf(GP, poolPropsFor({ nodeType: "regular" }), OA) }).provedOne }), /pair check refused/);
    // a COHERENT regular pool (regular target, regular receipt) passes the pair check and is
    // refused by the module's own eligibility predicate, which is the site this case binds
    const REGULAR = "100000000000";
    const regularManifest = { ...manifest(), target: REGULAR, owners: manifest().owners.map((o) => ({ ...o, amountDuffs: String(BigInt(REGULAR) * BigInt(o.bps) / 10000n) })) };
    const regularPool = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000, targetDuffs: Number(REGULAR), slotDuffs: Number(BigInt(REGULAR) / 2n), slotCount: 2 };
    await rejects("a coherent regular pool passes the pair check and is refused by the eligibility predicate", compose({ provedOne: mkProvedOne({ poolDoc: docOf(GP, regularPool, OA), receiptDoc: docOf("11".repeat(32), receiptPropsFor(regularManifest), OA) }).provedOne }), /nodeType is "regular", not "evo"/);
    const altered = receiptPropsFor(manifest()); altered.allocationHash = Buffer.from("ab".repeat(32), "hex");
    await rejects("a receipt whose stored hash differs from the recomputed one refuses", compose({ provedOne: mkProvedOne({ receiptDoc: docOf("11".repeat(32), altered, OA) }).provedOne }), /pair check refused|recomputed allocation hash/);
    for (const [label, raw] of [["false", false], ["an empty array", []], ["a hex string", "0x10"], ["a negative number", -1], ["a float", 1.5]]) {
      ok(`currentEpochOf refuses ${label}`, M.currentEpochOf(raw) === null);
    }
    ok("currentEpochOf accepts a safe integer, a bigint and a canonical decimal string", M.currentEpochOf(7) === 7 && M.currentEpochOf(7n) === 7 && M.currentEpochOf("7") === 7);
    await rejects("an unusable metadata epoch on the pool read refuses composition", compose({ provedOne: mkProvedOne({ epoch: false }).provedOne }), /not a usable wire value/);
    const { calls, provedOne } = mkProvedOne();
    await compose({ provedOne });
    // THE WHOLE PREDICATE of each read is asserted (field, operator and operand), not only an
    // operand's type (the second pass's constructions: a wrong field or a wrong buffer)
    ok("the resolution issues exactly two proved reads, the pool by $id equal to its base58 form, then the receipt by poolId equal to the exact pool bytes", calls.map((c) => c.type).join() === "pool,completionReceipt" && calls[0].where.length === 1 && calls[0].where[0][0] === "$id" && calls[0].where[0][1] === "==" && calls[0].where[0][2] === GP && calls[1].where.length === 1 && calls[1].where[0][0] === "poolId" && calls[1].where[0][1] === "==" && Buffer.isBuffer(calls[1].where[0][2]) && calls[1].where[0][2].equals(Buffer.from(POOL, "hex")));
    // THE CURRENT EPOCH COMES FROM THE POOL READ'S MARKER, not the receipt read's: the two
    // reads carry distinct metadata here so the source is observable
    // (the receipt read's epoch is LOWER than the pool read's, so a composition taking the wrong
    // marker still discovers a universe and reaches this assertion rather than refusing earlier)
    const distinct = { calls: [], provedOne: async (type, where, label) => { if (type === "pool") return { doc: docOf(GP, poolPropsFor(), OA), marker: { metadata: { epoch: 5, height: "1000" }, call: "documents.query" } }; if (type === "completionReceipt") return { doc: docOf("11".repeat(32), receiptPropsFor(manifest()), OA), marker: { metadata: { epoch: 4, height: "999" }, call: "documents.query" } }; throw new Error(`${label}: unexpected type ${type}`); } };
    const viaPool = await compose({ provedOne: distinct.provedOne, readEpochInterval: mkEnumeration(4) });
    ok("the current epoch is the POOL read's metadata epoch (5), not the receipt read's (4)", viaPool.currentEpoch === 5);
    // AND THE OPPOSITE ORDER, on the resolution alone (the third pass's construction: choosing
    // the larger epoch survives the case above): the receipt read's epoch HIGHER than the pool's
    const higher = async (type, where, label) => { if (type === "pool") return { doc: docOf(GP, poolPropsFor(), OA), marker: { metadata: { epoch: 5, height: "1000" }, call: "documents.query" } }; if (type === "completionReceipt") return { doc: docOf("11".repeat(32), receiptPropsFor(manifest()), OA), marker: { metadata: { epoch: 6, height: "1002" }, call: "documents.query" } }; throw new Error(`${label}: unexpected type ${type}`); };
    const rfHigher = await M.resolveFormation({ poolId: POOL, contractId: GC, provedOne: higher, b58Of });
    ok("the pool marker is returned even when the receipt read's epoch is higher (6 > 5)", rfHigher.poolMarker.metadata.epoch === 5 && rfHigher.poolMarker.metadata.height === "1000");
    // AN UNEQUAL ALLOCATION, so a constant share cannot pass (the second pass's construction)
    const uneven = await M.resolveFormation({ poolId: POOL, contractId: GC, provedOne: mkProvedOne({ receiptDoc: docOf("11".repeat(32), receiptPropsFor(manifest([[OA, 3000], [OB, 7000]])), OA) }).provedOne, b58Of });
    ok("an unequal allocation (3000/7000) is carried with each owner's own bps", uneven.formation.allocation.find((r) => r.recipientId === A).bps === 3000 && uneven.formation.allocation.find((r) => r.recipientId === B).bps === 7000);
  }

  // ================= 4. the journal and discovery =================
  {
    throws("a journal binding no configured start (null) refuses", () => M.journalRunOf(mkRead({ configuredStartEpoch: null, perEpoch: {} })), /binds no configured start/);
    throws("a journal read without the binding member refuses", () => M.journalRunOf({ perEpoch: {}, records: [] }), /binds no configured start/);
    throws("a journal bound at start 0 whose first header is at epoch 1 is runFromJournal's gap refusal, reached only past the binding check", () => M.journalRunOf({ configuredStartEpoch: 0, perEpoch: { 1: { header: journalHeader() } }, records: [] }), /evidences epoch 1 but not epoch 0/);
    throws("a journal read that is not an object refuses", () => M.journalRunOf(null), /needs the validated journal read/);
    ok("an empty journal under a bound start is an empty run", M.journalRunOf(mkRead({ perEpoch: {} })).journalRun.length === 0);
    await rejects("a reversed interval (configured start above the end) refuses before the enumeration", M.discoverUniverse({ readEpochInterval: async () => { throw new Error("must not be called"); }, currentEpoch: 5, referenceHeight: "1000", chainIdPin: CHAIN, configuredStart: 2, universeEnd: 1, log: () => {} }), /interval 2\.\.1 is reversed/);
    await rejects("an enumeration that throws falls back and the fallback REFUSES", M.discoverUniverse({ readEpochInterval: async () => { throw new Error("wire down"); }, currentEpoch: 5, referenceHeight: "1000", chainIdPin: CHAIN, configuredStart: 0, universeEnd: 1, log: () => {} }), /fell back to the unproved shape/);
    await rejects("an enumeration answering OUTSIDE its interval is refused as a fallback, never served", M.discoverUniverse({ readEpochInterval: async (a, b) => ({ epochs: b > 4 ? [] : [{ number: a }, { number: b + 1 }], metadata: { ...ENUM_META, epoch: 5 } }), currentEpoch: 5, referenceHeight: "1000", chainIdPin: CHAIN, configuredStart: 0, universeEnd: 1, log: () => {} }), /fell back to the unproved shape/);
    // A SPARSE history is a POSITIVE control here too: the universe is the epochs that
    // exist, gaps and all, and the run is not refused for being sparse (a soundness-review finding).
    const uSparse = await M.discoverUniverse({ readEpochInterval: mkSparseEnumeration(6, [1, 3]), currentEpoch: 6, referenceHeight: "1000", chainIdPin: CHAIN, configuredStart: 0, universeEnd: 5, log: () => {} });
    ok("a sparse universe is served with its gaps intact", JSON.stringify(uSparse) === JSON.stringify([0, 2, 4, 5]));
    await rejects("an answer signed at a height BELOW the run's reference is refused here too, never served",
      M.discoverUniverse({ readEpochInterval: async (a, b) => { const out = []; for (let n = a; n <= b && n < 6; n++) out.push({ number: n }); return { epochs: out, metadata: { height: "900", chainId: CHAIN, epoch: 99 } }; },
        currentEpoch: 6, referenceHeight: "1000", chainIdPin: CHAIN, configuredStart: 0, universeEnd: 5, log: () => {} }), /fell back to the unproved shape/);
    await rejects("a universe reaching ABOVE the claimed finality bound refuses, rather than resting on it",
      M.discoverUniverse({ readEpochInterval: mkEnumeration(6), currentEpoch: 6, referenceHeight: "1000",
        chainIdPin: CHAIN, configuredStart: 0, universeEnd: 6, log: () => {} }),
      /coverage could be established only through 5/);
    ok("a universe exactly at the claimed bound is allowed",
      (await M.discoverUniverse({ readEpochInterval: mkEnumeration(6), currentEpoch: 6, referenceHeight: "1000",
        chainIdPin: CHAIN, configuredStart: 0, universeEnd: 5, log: () => {} })).length === 6);
    await rejects("an answer signed on ANOTHER CHAIN is refused here too",
      M.discoverUniverse({ readEpochInterval: async (a, b) => { const out = []; for (let n = a; n <= b && n < 6; n++) out.push({ number: n }); return { epochs: out, metadata: { height: "1000", chainId: "other-chain", epoch: 6 } }; },
        currentEpoch: 6, referenceHeight: "1000", chainIdPin: CHAIN, configuredStart: 0, universeEnd: 5, log: () => {} }), /fell back to the unproved shape/);
    await rejects("an empty in-range set refuses", M.discoverUniverse({ readEpochInterval: mkSparseEnumeration(3, [2]), currentEpoch: 3, referenceHeight: "1000", chainIdPin: CHAIN, configuredStart: 2, universeEnd: 2, log: () => {} }), /holds no finalized epoch/);
    const u = await M.discoverUniverse({ readEpochInterval: mkEnumeration(5), currentEpoch: 5, referenceHeight: "1000", chainIdPin: CHAIN, configuredStart: 0, universeEnd: 3, log: () => {} });
    ok("the universe is the in-range finalized set as bare numbers", u.join() === "0,1,2,3");
    const u2 = await M.discoverUniverse({ readEpochInterval: mkSparseEnumeration(9, [2, 3, 4, 5, 6, 7, 8]), currentEpoch: 9, referenceHeight: "1000", chainIdPin: CHAIN, configuredStart: 0, universeEnd: 8, log: () => {} });
    ok("an end past the finalized set, but within the claimed bound, is clipped to the set", u2.join() === "0,1");
  }

  // ================= 4b. the proved read's guards (the round's coverage item) =================
  {
    let marker = undefined;
    const mk = (answer, markerAfter) => M.makeProvedOne({ query: async () => { marker = markerAfter; return answer; }, clearMarker: () => { marker = null; }, readMarker: () => marker });
    const good = { metadata: { epoch: 5 }, call: "documents.query(prove)" };
    const r = await mk([{ id: "x" }], good)("pool", [], "pool x");
    ok("a read with a documents-route marker and one document is served with its marker", r.doc.id === "x" && r.marker === good);
    await rejects("a read leaving NO marker refuses", mk([{ id: "x" }], null)("pool", [], "pool x"), /no verified-call marker/);
    await rejects("a read leaving a marker for ANOTHER route refuses", mk([{ id: "x" }], { metadata: { epoch: 5 }, call: "identities.get" })("pool", [], "pool x"), /no verified-call marker/);
    await rejects("a marker without metadata refuses", mk([{ id: "x" }], { call: "documents.query" })("pool", [], "pool x"), /no verified-call marker/);
    await rejects("two documents refuse", mk([{ id: "x" }, { id: "y" }], good)("pool", [], "pool x"), /expected exactly one document, found 2/);
    await rejects("no document refuses", mk([], good)("pool", [], "pool x"), /expected exactly one document, found 0/);
    // a STALE marker from a previous call is cleared before the call, so a query that sets
    // none is refused rather than served under the old marker
    marker = good;
    const stale = M.makeProvedOne({ query: async () => [{ id: "x" }], clearMarker: () => { marker = null; }, readMarker: () => marker });
    await rejects("a stale marker from an earlier call does not serve this one (cleared before the call)", stale("pool", [], "pool x"), /no verified-call marker/);
    throws("the factory needs its three functions", () => M.makeProvedOne({ query: async () => [] }), /needs query, clearMarker and readMarker/);
    // A SECOND CALL THROUGH ONE READER clears the first call's marker (the second pass's gap:
    // a reader clearing only on its first invocation would serve the second query under it)
    let m2 = undefined; let calls2 = 0;
    const twice = M.makeProvedOne({ query: async () => { calls2 += 1; if (calls2 === 1) m2 = good; return [{ id: `x${calls2}` }]; }, clearMarker: () => { m2 = null; }, readMarker: () => m2 });
    const first = await twice("pool", [], "first");
    await rejects("a second query through the same reader that sets no marker is refused rather than served under the first call's marker", twice("pool", [], "second"), /no verified-call marker/);
    ok("and the first call was served normally", first.doc.id === "x1");
    await rejects("an ARRAY as metadata is refused (non-plain metadata)", mk([{ id: "x" }], { metadata: [1], call: "documents.query" })("pool", [], "pool x"), /no verified-call marker/);
    await rejects("a non-array answer of length one is refused", mk({ length: 1, 0: { id: "x" } }, good)("pool", [], "pool x"), /expected exactly one document, found object/);
  }

  // ================= 5. the capture lookup =================
  {
    const sup = { kind: captureRecord.SUPERSESSION_KIND, supersededKind: captureRecord.RECEIPT_KIND, accrualId: ACC_B, seq: 1 };
    const headerSup = { kind: captureRecord.SUPERSESSION_KIND, supersededKind: captureRecord.HEADER_KIND, seq: 1 };
    const look = M.captureLookupOver([{ kind: "other" }, capture, sup, headerSup, null]);
    const f = look(ACC_B);
    ok("the lookup answers the capture with the RECEIPT supersessions only (a header supersession is not among them)", f.capture === capture && f.supersessions.length === 1 && f.supersessions[0] === sup);
    ok("the lookup answers null for an identifier with no capture", look(ACC_A) === null);
    throws("the lookup refuses a non-canonical identifier as a caller fault", () => look("abc"), /64-hex planned accrual identifier/);
    const dup = M.captureLookupOver([capture, { ...capture, transitionHash: h("ab") }]);
    throws("two captures under one planned identifier FAULT rather than choosing", () => dup(ACC_B), /2 receipt captures under planned accrual/);
    throws("the lookup needs an array", () => M.captureLookupOver(undefined), /needs the journal's records array/);
    await rejects("the composition refuses a target bound to another pool", compose({ target: { ...target(0), poolId: h("99") } }), /bound to the same pool/);
    await rejects("the composition needs the journal reader", compose({ readJournal: undefined }), /needs readJournal/);
  }

  console.log(`\ne2ForwardTransportV2ComposeTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
};

main().catch((e) => { console.error("e2ForwardTransportV2ComposeTest crashed:", e && e.stack || e); process.exitCode = 1; });
