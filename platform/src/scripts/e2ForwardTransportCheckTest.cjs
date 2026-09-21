/**
 * e2ForwardTransportCheckTest: the offline battery for the LIVE TRANSPORT CHECK
 * (e2ForwardTransportCheck.cjs), the acceptance-capable instrument a soundness-review finding asked
 * for. Plain `node`, no network: the check's observation flow is driven with a
 * synthetic query over the adapter test's fixtures, the REAL adapter, the REAL
 * acquisition unit, the REAL kernel and the ledger's own builder, which is the
 * same composition the reviewer's controls exercised.
 *
 * WHAT IT BINDS:
 *   1. the positive control PASSES its profile: every required check passes and
 *      the verdict is pass;
 *   2. the five contrary scenarios each FAIL on the named check: every query
 *      unavailable, every marker missing, an empty header and enumeration, the
 *      old receipt clause SERVED contrary to the profile, and a wrong planned
 *      identifier the kernel refuses; the old-clause check matches the specific
 *      index error and not any exception;
 *   3. an intentionally incomplete fixture PASSES a profile that predicts
 *      incomplete with its named reason, so `complete` is not hardcoded;
 *   4. the profile's identity is the hash of its CANONICAL serialization (two
 *      insertion orders agree), it is snapshotted before the first query, a
 *      profile requiring less than the acceptance minimum refuses, and a
 *      malformed profile refuses;
 *   5. provenance: every member of the review's F2 list is required with a
 *      valid value, a missing or empty one refuses by name, the record is BOUND
 *      to the run's scope and classification, the synthetic labels are
 *      explicit, identifiers are stored in full;
 *   6. the verdict's exit semantics: acceptance mode returns nonzero on any
 *      violated required check, observe mode returns zero with an explicit
 *      disclaimer in the artifact, and a non-required check never fails the run.
 *
 * WHAT IT DOES NOT ESTABLISH: anything about the live transport, the proof
 * pipeline or the devnet; the live composition is the .mjs runner's, exercised
 * only by a real run.
 */
"use strict";

const path = require("path");
const crypto = require("crypto");
const { pathToFileURL } = require("url");
const { buildV11 } = require("./contractV11.cjs");
const C = require("./e2ForwardTransportCheck.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed += 1; console.log(`  PASS: ${name}`); }
  else { failed += 1; console.log(`  FAIL: ${name}`); }
};
const rejects = async (name, p, re) => {
  try { await p; failed += 1; console.log(`  FAIL: ${name} (no refusal)`); }
  catch (e) { const m = (e && e.message) || String(e); ok(`${name} (${m.slice(0, 80)})`, re.test(m)); }
};
const throws = (name, fn, re) => {
  try { fn(); failed += 1; console.log(`  FAIL: ${name} (no refusal)`); }
  catch (e) { const m = (e && e.message) || String(e); ok(`${name} (${m.slice(0, 80)})`, re.test(m)); }
};

// ---- fixtures, the adapter test's own ----
const POOL = "11".repeat(32);
const FUNDER_A = "aa".repeat(32);
const PLANNED_A = "a1".repeat(32);
const RES_A = "d1".repeat(32);
const RCPT_A = "d2".repeat(32);
const HDR_ID = "77".repeat(32);
const AH = "ee".repeat(32);
const TH = "ff".repeat(32);
const EPOCH = 7;
const CONTRACT_HEX = "c1".repeat(32);
const doc = (id, fields) => ({ id, fields });
const conformingDocs = () => ({
  epochHeader: [doc(HDR_ID, { poolId: POOL, epochIndex: EPOCH, grossCredits: 1000, feeCredits: 100, memberCount: 1, calcVersion: 1, allocationHash: AH })],
  platformAccrual: [doc(PLANNED_A, { poolId: POOL, funderId: FUNDER_A, epochIndex: EPOCH, amountCredits: 900, shareBps: 10000 })],
  transferReservation: [doc(RES_A, { poolId: POOL, accrualId: PLANNED_A, transitionHash: TH })],
  transferReceipt: [doc(RCPT_A, { poolId: POOL, accrualId: PLANNED_A, transitionHash: TH, proofPartCount: 3 })],
  receiptProofPart: [doc("e1".repeat(32), { poolId: POOL, accrualId: PLANNED_A, partIndex: 1 }), doc("e2".repeat(32), { poolId: POOL, accrualId: PLANNED_A, partIndex: 2 })],
});
// the refusal AS THE WIRE DELIVERS IT, percent-encoded, which is what the live run saved
const INDEX_ERROR = "where%20clause%20on%20non%20indexed%20property%20error:%20query%20must%20be%20for%20valid%20indexes,%20valid%20indexes%20are:%20%7B%22byAccrual%22:%20Index%20%7B%20name:%20%22byAccrual%22";

// a synthetic query in the check's query contract: (type, where, { limit }) ->
// { documents: [{ id, fields }], height } or a throw (noMarker marks the
// marker-less case)
const makeQuery = ({ mode = "good", docs = conformingDocs(), height = "100" } = {}) => {
  const calls = [];
  const query = async (type, where, { limit }) => {
    calls.push({ type, where: where.map((w) => w[0]), limit });
    if (mode === "unserved") throw new Error("synthetic unavailable transport");
    if (mode === "missing-marker") { const e = new Error(`${type}: no verified-call marker for this route`); e.noMarker = true; throw e; }
    if (type === "transferReceipt" && where.length === 2 && mode !== "old-clause-served") throw new Error(INDEX_ERROR);
    const found = (docs[type] || []).filter((d) => where.every(([k, , v]) => d.fields[k] === v))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return { documents: found.slice(0, limit), height };
  };
  return { query, calls };
};
const plannedIdFor = (mode) => () => (mode === "identifier-mismatch" ? "b1".repeat(32) : PLANNED_A);

const PROFILE = {
  kind: "tegara.e2.forwardTransportProfile.v1",
  required: {
    allReadsVerified: true, headerServedOne: true, enumerationMatchesMemberCount: true,
    oldClauseRefusedWithIndexError: true, plannedEqualsServed: true,
    compositionState: "complete", compositionReasons: [], heightSpanMax: 5, sweepAgainstAbsentEmpty: true,
  },
  optional: {},
};
const provenanceFor = (over = {}) => ({
  sourceCommit: "0123456789abcdef", treeState: "clean", diffSha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  inputHashes: { runner: "a".repeat(64), check: "b".repeat(64), sourceTree: "f".repeat(64), ledgerModule: "c".repeat(64), patches: { "query.js": "d".repeat(64) } },
  contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11, poolId: POOL, epochIndex: EPOCH,
  classificationInput: { selfShares: [] }, expectationProfile: { path: "fixtures/x.json", sha256: "e".repeat(64) },
  synthetic: { planValues: "derived-from-served-records", transferVerdict: "constant-capture-verified", selfShare: "manual-override" },
  at: "2026-09-09T00:00:00.000Z", ...over,
});
const runWith = async ({ mode = "good", docs, profile = PROFILE, selfShares = [], provenance = provenanceFor({ classificationInput: { selfShares } }), acceptance = true, ledger }) => {
  const q = makeQuery({ mode, docs });
  const out = await C.runTransportCheck({
    query: q.query, ledger, profile, provenance, acceptance,
    target: { contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11, poolId: POOL, epochIndex: EPOCH },
    plannedIdFor: plannedIdFor(mode), selfShares, executionVerdict: ({ member }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: member.effectiveCredits }),
  });
  return { ...out, calls: q.calls };
};
const failedChecks = (v) => v.results.filter((r) => r.required && !r.pass).map((r) => r.check);

const main = async () => {
  const ROOT = process.env.TEGARA_PLATFORM_ROOT || path.join(__dirname, "..", "..");
  const { poolLedgerContract } = await import(pathToFileURL(path.join(ROOT, "dist/contract/poolLedger.js")).href);
  const ledger = buildV11(poolLedgerContract);

  // ================= 1. the positive control =================
  {
    const r = await runWith({ ledger });
    ok(`the positive control passes its profile (${failedChecks(r.verdict).join(",") || "no failed check"})`, r.verdict.pass === true && failedChecks(r.verdict).length === 0);
    ok("acceptance mode: exit code 0 on pass", r.exitCode === 0);
    ok("the artifact carries the verdict, the observations, the transport log and the provenance", r.artifact.verdict.pass === true && Array.isArray(r.artifact.observations) && Array.isArray(r.artifact.transportLog) && r.artifact.provenance.sourceCommit === "0123456789abcdef");
    ok("identifiers in the saved observations are FULL, not display-shortened", JSON.stringify(r.artifact.observations).includes(HDR_ID) && JSON.stringify(r.artifact.observations).includes(RCPT_A));
    ok("the profile identity in the artifact is the canonical identity of the evaluated profile, and the file hash is carried separately", r.artifact.provenance.expectationProfile.sha256 === "e".repeat(64) && r.artifact.profileIdentity === C.profileIdentity(PROFILE) && /^[0-9a-f]{64}$/.test(r.artifact.profileIdentity));
    ok("every check the profile names has a result row, required and optional alike", r.verdict.results.map((x) => x.check).sort().join() === Object.keys(PROFILE.required).sort().join());
    ok("the transport log is retained in full (one entry per adapter call, none dropped)", r.artifact.transportLog.length === r.calls.filter((c) => !(c.type === "transferReceipt" && c.where.length === 2)).length && r.artifact.transportLog.length > 0);
    ok("the old clause was issued raw exactly once and refused with the index error", r.calls.filter((c) => c.type === "transferReceipt" && c.where.length === 2).length === 1 && /valid indexes/.test(decodeURIComponent(r.artifact.observations.find((o) => o.name === "11.oldReceiptClauseRaw").value.error)) && /valid%20indexes/.test(r.artifact.observations.find((o) => o.name === "11.oldReceiptClauseRaw").value.error));
  }

  // ================= 2. the five contrary scenarios =================
  {
    const r1 = await runWith({ mode: "unserved", ledger });
    ok(`every query unavailable FAILS on allReadsVerified (${failedChecks(r1.verdict).join(",")})`, r1.verdict.pass === false && failedChecks(r1.verdict).includes("allReadsVerified") && r1.exitCode === 1);
    const r2 = await runWith({ mode: "missing-marker", ledger });
    ok(`every marker missing FAILS on allReadsVerified with unverified reads named (${failedChecks(r2.verdict).join(",")})`, r2.verdict.pass === false && failedChecks(r2.verdict).includes("allReadsVerified") && /unverified/.test(r2.verdict.results.find((x) => x.check === "allReadsVerified").detail) && r2.exitCode === 1);
    const r3 = await runWith({ mode: "empty", docs: {}, ledger });
    ok(`an empty header and enumeration FAILS on headerServedOne and the composition is not skipped silently (${failedChecks(r3.verdict).join(",")})`, r3.verdict.pass === false && failedChecks(r3.verdict).includes("headerServedOne") && failedChecks(r3.verdict).includes("compositionState") && r3.exitCode === 1);
    const r4 = await runWith({ mode: "old-clause-served", ledger });
    ok(`the old clause SERVED fails oldClauseRefusedWithIndexError while everything else passes (${failedChecks(r4.verdict).join(",")})`, r4.verdict.pass === false && failedChecks(r4.verdict).join() === "oldClauseRefusedWithIndexError" && r4.exitCode === 1);
    const r5 = await runWith({ mode: "identifier-mismatch", ledger });
    ok(`a wrong planned identifier FAILS on plannedEqualsServed and on compositionState with the kernel's refusal named (${failedChecks(r5.verdict).join(",")})`,
      r5.verdict.pass === false && failedChecks(r5.verdict).includes("plannedEqualsServed") && failedChecks(r5.verdict).includes("compositionState")
      && /REFUSED_ACCRUAL_DOCUMENT_ID_MISMATCH/.test(r5.verdict.results.find((x) => x.check === "compositionState").detail) && r5.exitCode === 1);
    // the old-clause check matches the SPECIFIC index error, not any exception
    const q = makeQuery({ mode: "good" });
    const query = async (type, where, opts) => { if (type === "transferReceipt" && where.length === 2) throw new Error("synthetic unrelated failure"); return q.query(type, where, opts); };
    const r6 = await C.runTransportCheck({ query, ledger, profile: PROFILE, provenance: provenanceFor(), acceptance: true,
      target: { contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11, poolId: POOL, epochIndex: EPOCH },
      plannedIdFor: plannedIdFor("good"), selfShares: [], executionVerdict: ({ member }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: member.effectiveCredits }) });
    ok(`an unrelated exception on the old clause does NOT satisfy oldClauseRefusedWithIndexError (${failedChecks(r6.verdict).join(",")})`, r6.verdict.pass === false && failedChecks(r6.verdict).join() === "oldClauseRefusedWithIndexError");
    const query7 = async (type, where, opts) => { if (type === "transferReceipt" && where.length === 2) throw new Error("connection closed while fetching valid indexes for non indexed property"); return q.query(type, where, opts); };
    const r7 = await C.runTransportCheck({ query: query7, ledger, profile: PROFILE, provenance: provenanceFor(), acceptance: true,
      target: { contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11, poolId: POOL, epochIndex: EPOCH },
      plannedIdFor: plannedIdFor("good"), selfShares: [], executionVerdict: ({ member }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: member.effectiveCredits }) });
    ok(`an unrelated message that merely CONTAINS the index vocabulary does not satisfy the check (anchored on the platform's prefix) (${failedChecks(r7.verdict).join(",")})`, r7.verdict.pass === false && failedChecks(r7.verdict).join() === "oldClauseRefusedWithIndexError");
    // partial unavailability fails too, naming the failed call
    let n = 0;
    const query8 = async (type, where, opts) => { n += 1; if (n === 4) throw new Error("synthetic single failure"); return q.query(type, where, opts); };
    const r8 = await C.runTransportCheck({ query: query8, ledger, profile: PROFILE, provenance: provenanceFor(), acceptance: true,
      target: { contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11, poolId: POOL, epochIndex: EPOCH },
      plannedIdFor: plannedIdFor("good"), selfShares: [], executionVerdict: ({ member }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: member.effectiveCredits }) });
    ok("ONE unavailable read among verified ones fails allReadsVerified with that call named", failedChecks(r8.verdict).includes("allReadsVerified") && /1 of \d+ adapter calls not verified/.test(r8.verdict.results.find((x) => x.check === "allReadsVerified").detail));
    // a height span past the profile's maximum fails
    let h = 100;
    const query9 = async (type, where, opts) => { h += 3; const out = await q.query(type, where, opts); return { ...out, height: String(h) }; };
    const r9 = await C.runTransportCheck({ query: query9, ledger, profile: PROFILE, provenance: provenanceFor(), acceptance: true,
      target: { contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11, poolId: POOL, epochIndex: EPOCH },
      plannedIdFor: plannedIdFor("good"), selfShares: [], executionVerdict: ({ member }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: member.effectiveCredits }) });
    ok("a height span past heightSpanMax fails that check", failedChecks(r9.verdict).includes("heightSpanMax"));
    // a wrong NONEMPTY expected reason list fails
    const docsI = conformingDocs(); docsI.transferReceipt = []; docsI.receiptProofPart = [];
    const r10 = await runWith({ docs: docsI, ledger, profile: { ...PROFILE, required: { ...PROFILE.required, compositionState: "incomplete", compositionReasons: ["INCOMPLETE_PART_ABSENT"] } } });
    ok("an incomplete prediction with the WRONG reason fails compositionReasons", failedChecks(r10.verdict).join() === "compositionReasons");
  }

  // ================= 3. an intentionally incomplete prediction =================
  {
    const docs = conformingDocs(); docs.transferReceipt = []; docs.receiptProofPart = [];
    const profile = { ...PROFILE, required: { ...PROFILE.required, compositionState: "incomplete", compositionReasons: ["INCOMPLETE_RECEIPT_ABSENT"] } };
    const r = await runWith({ docs, profile, ledger });
    ok(`a profile predicting incomplete with its reason PASSES on the incomplete fixture (${failedChecks(r.verdict).join(",") || "no failed check"})`, r.verdict.pass === true && r.exitCode === 0);
    const r2 = await runWith({ docs, ledger });
    ok("the same fixture FAILS the complete profile on compositionState and compositionReasons", r2.verdict.pass === false && failedChecks(r2.verdict).includes("compositionState") && failedChecks(r2.verdict).includes("compositionReasons"));
    // a self-share member: named in the classification input, swept, and the run states it
    const docs2 = conformingDocs(); docs2.transferReservation = []; docs2.transferReceipt = []; docs2.receiptProofPart = [];
    const r3 = await runWith({ docs: docs2, ledger, selfShares: [FUNDER_A], provenance: provenanceFor({ classificationInput: { selfShares: [FUNDER_A] } }) });
    ok("a member named as a self-share is swept and the composition completes, with the full classification input saved",
      r3.verdict.pass === true && r3.artifact.provenance.classificationInput.selfShares[0] === FUNDER_A && r3.artifact.observations.find((o) => o.name === "12b.selfShareOverride").value[0] === FUNDER_A);
  }

  // ================= 4. the profile =================
  {
    throws("a profile of another kind refuses", () => C.validateProfile({ ...PROFILE, kind: "x" }), /profile kind/);
    throws("a profile with an unknown required check refuses", () => C.validateProfile({ ...PROFILE, required: { ...PROFILE.required, bogus: true } }), /unknown check bogus/);
    throws("a profile whose compositionState is not a kernel state refuses", () => C.validateProfile({ ...PROFILE, required: { ...PROFILE.required, compositionState: "done" } }), /compositionState/);
    const reordered = { optional: {}, required: Object.fromEntries(Object.entries(PROFILE.required).reverse()), kind: PROFILE.kind };
    const changed = { ...PROFILE, required: { ...PROFILE.required, heightSpanMax: 6 } };
    ok("profileIdentity is canonical and content-bound: two insertion orders of one profile hash equal, a one-value change hashes differently, and the reordered one is not plain JSON.stringify",
      C.profileIdentity(PROFILE) === C.profileIdentity(reordered) && C.profileIdentity(PROFILE) !== C.profileIdentity(changed) && JSON.stringify(PROFILE) !== JSON.stringify(reordered));
    throws("a profile that requires nothing refuses (an acceptance profile cannot pass vacuously)", () => C.validateProfile({ kind: PROFILE.kind, required: {}, optional: {} }), /must carry allReadsVerified/);
    // the minimum must be OWN members: inherited ones would pass a lookup and vanish from the copy
    const inherited = { kind: PROFILE.kind, required: Object.create({ allReadsVerified: true, compositionState: "complete" }), optional: {} };
    throws("a profile whose minimum checks are INHERITED refuses (they would vanish from the evaluated copy)", () => C.validateProfile(inherited), /must have a plain prototype|as an own member/);
    await rejects("that inherited profile refuses through the run as well, against an unavailable query (at capture, a foreign prototype)", runWith({ mode: "unserved", profile: inherited, ledger }), /arguments are not plain data .*profile.*foreign prototype/);
    throws("a profile carrying toJSON refuses", () => C.validateProfile({ ...PROFILE, toJSON: () => ({ kind: PROFILE.kind, required: {}, optional: {} }) }), /must not carry a toJSON/);
    // an INHERITED serializer that keeps the minimum and drops another required
    // check: the run captures the profile as plain data (own data descriptors,
    // plain prototypes) and never serializes the caller's object, so it refuses
    const withSerializer = Object.create({ toJSON() { return { kind: PROFILE.kind, required: { allReadsVerified: true, compositionState: "complete" }, optional: {} }; } });
    Object.assign(withSerializer, JSON.parse(JSON.stringify(PROFILE)));
    await rejects("a profile inheriting a toJSON that would drop the old-clause check refuses at capture (foreign prototype), against the old-clause-served fixture", runWith({ mode: "old-clause-served", profile: withSerializer, ledger }), /arguments are not plain data .*profile/);
    // a boxed string self-share: refused as not a primitive, so the saved and the
    // used classification cannot differ
    await rejects("a boxed-string self-share refuses (primitive strings only)", runWith({ ledger, selfShares: [new String(FUNDER_A)], provenance: provenanceFor({ classificationInput: { selfShares: [FUNDER_A] } }) }), /arguments are not plain data .*selfShares/);
    throws("provenance with a boxed-string self-share refuses (at capture, a foreign prototype, before the primitive check could)", () => C.assembleProvenance(provenanceFor({ classificationInput: { selfShares: [new String(FUNDER_A)] } })), /not plain data .*foreign prototype|PRIMITIVE strings/);
    // provenance is captured as plain data too: a getter-backed or serializer-bearing member refuses
    throws("provenance whose member is a getter refuses at capture", () => C.assembleProvenance(Object.defineProperty(provenanceFor(), "poolId", { get: () => POOL, enumerable: true, configurable: true })), /not plain data/);
    const provSer = Object.create({ toJSON() { return { ...provenanceFor(), poolId: "22".repeat(32) }; } }); Object.assign(provSer, provenanceFor());
    throws("provenance inheriting a serializer that would change the pool refuses at capture", () => C.assembleProvenance(provSer), /not plain data/);
    const provHashSer = provenanceFor(); provHashSer.inputHashes.toJSON = () => ({});
    throws("provenance whose input hashes carry a serializer that would empty them refuses at capture (a function is not plain data)", () => C.assembleProvenance(provHashSer), /not plain data .*function/);
    throws("a profile that requires reads but no composition state refuses", () => C.validateProfile({ kind: PROFILE.kind, required: { allReadsVerified: true }, optional: {} }), /must carry compositionState/);
    // a check that is NOT required never fails the run
    const profile = { ...PROFILE, required: { ...PROFILE.required, oldClauseRefusedWithIndexError: undefined }, optional: { oldClauseRefusedWithIndexError: true } };
    delete profile.required.oldClauseRefusedWithIndexError;
    const r = await runWith({ mode: "old-clause-served", profile, ledger });
    ok("an optional check that fails is reported and does not fail the run", r.verdict.pass === true && r.verdict.results.some((x) => x.check === "oldClauseRefusedWithIndexError" && !x.required && !x.pass));
  }

  // ================= 5. provenance =================
  {
    for (const k of ["sourceCommit", "treeState", "diffSha256", "inputHashes", "contractId", "chainId", "contractVersion", "poolId", "epochIndex", "classificationInput", "expectationProfile", "synthetic", "at"]) {
      const p = provenanceFor(); delete p[k];
      throws(`provenance without ${k} refuses`, () => C.assembleProvenance(p), new RegExp(`provenance\\.${k} is required`));
    }
    throws("provenance with a shortened pool identifier refuses", () => C.assembleProvenance(provenanceFor({ poolId: POOL.slice(0, 12) })), /poolId must be 64-hex/);
    throws("provenance whose synthetic labels omit the transfer verdict refuses", () => C.assembleProvenance(provenanceFor({ synthetic: { planValues: "x", selfShare: "y" } })), /synthetic\.transferVerdict/);
    throws("provenance whose input hashes omit the runner refuses", () => C.assembleProvenance(provenanceFor({ inputHashes: { check: "b".repeat(64), ledgerModule: "c".repeat(64), patches: {} } })), /inputHashes\.runner/);
    throws("provenance with a tree state outside clean/dirty refuses", () => C.assembleProvenance(provenanceFor({ treeState: "unknown" })), /treeState/);
    throws("provenance with an empty sourceCommit refuses", () => C.assembleProvenance(provenanceFor({ sourceCommit: "" })), /sourceCommit must be a git commit hash/);
    throws("provenance with an empty chainId refuses", () => C.assembleProvenance(provenanceFor({ chainId: "" })), /chainId must be a non-empty string/);
    throws("provenance with a non-integer contractVersion refuses", () => C.assembleProvenance(provenanceFor({ contractVersion: {} })), /contractVersion must be a positive integer/);
    throws("provenance with no mounted patches named refuses", () => C.assembleProvenance(provenanceFor({ inputHashes: { runner: "a".repeat(64), check: "b".repeat(64), sourceTree: "f".repeat(64), ledgerModule: "c".repeat(64), patches: {} } })), /at least one mounted patch/);
    throws("provenance without the source-tree hash refuses", () => C.assembleProvenance(provenanceFor({ inputHashes: { runner: "a".repeat(64), check: "b".repeat(64), ledgerModule: "c".repeat(64), patches: { x: "d".repeat(64) } } })), /sourceTree/);
    throws("provenance with an empty profile path refuses", () => C.assembleProvenance(provenanceFor({ expectationProfile: { path: "", sha256: "e".repeat(64) } })), /non-empty path/);
    const p = C.assembleProvenance(provenanceFor());
    const deepFrozen = (v) => v === null || typeof v !== "object" || (Object.isFrozen(v) && Object.keys(v).every((k) => deepFrozen(v[k])));
    ok("assembled provenance is DEEPLY frozen and carries every member by name", deepFrozen(p) && ["sourceCommit", "treeState", "diffSha256", "inputHashes", "contractId", "chainId", "contractVersion", "poolId", "epochIndex", "classificationInput", "expectationProfile", "synthetic", "at"].every((k) => p[k] !== undefined));
    // provenance is BOUND to the execution: a scope or classification that differs refuses
    await rejects("provenance naming another pool than the run's target refuses", runWith({ ledger, provenance: provenanceFor({ poolId: "22".repeat(32) }) }), /provenance\.poolId .* does not equal the run's target/);
    await rejects("provenance naming another epoch refuses", runWith({ ledger, provenance: provenanceFor({ epochIndex: 9 }) }), /provenance\.epochIndex/);
    await rejects("provenance whose self-share list differs from the run's refuses", runWith({ ledger, selfShares: [FUNDER_A], provenance: provenanceFor({ classificationInput: { selfShares: [] } }) }), /classificationInput\.selfShares does not equal/);
    // the profile is snapshotted before the first query: a mutation during the run changes nothing
    const mutable = JSON.parse(JSON.stringify(PROFILE));
    const qm = makeQuery({ mode: "unserved" });
    const queryM = async (type, where, opts) => { mutable.required = {}; return qm.query(type, where, opts); };
    const rm = await C.runTransportCheck({ query: queryM, ledger, profile: mutable, provenance: provenanceFor(), acceptance: true,
      target: { contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11, poolId: POOL, epochIndex: EPOCH },
      plannedIdFor: plannedIdFor("good"), selfShares: [], executionVerdict: ({ member }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: member.effectiveCredits }) });
    ok("a profile emptied by an injected query during the run still fails on the snapshotted required checks, and the artifact carries the snapshot", rm.verdict.pass === false && failedChecks(rm.verdict).includes("allReadsVerified") && Object.keys(rm.artifact.profile.required).length === Object.keys(PROFILE.required).length && Object.isFrozen(rm.artifact.profile));
    // the self-share list and the target are COPIED at entry: a mutation from
    // inside the first query changes neither the classification nor the artifact
    const docsS = conformingDocs(); docsS.transferReservation = []; docsS.transferReceipt = []; docsS.receiptProofPart = [];
    const shares = [];
    const tgt = { contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11, poolId: POOL, epochIndex: EPOCH };
    const qs = makeQuery({ mode: "good", docs: docsS });
    let first = true;
    const queryS = async (type, where, opts) => { if (first) { first = false; shares.push(FUNDER_A); tgt.epochIndex = 99; } return qs.query(type, where, opts); };
    const rs = await C.runTransportCheck({ query: queryS, ledger, profile: PROFILE, provenance: provenanceFor(), acceptance: true, target: tgt,
      plannedIdFor: plannedIdFor("good"), selfShares: shares, executionVerdict: ({ member }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: member.effectiveCredits }) });
    ok("a self-share appended and a target mutated from inside the first query change nothing: the member stays payable (incomplete, not swept), the saved classification is the bound empty list, and the target's epoch is the copied one",
      rs.verdict.pass === false && rs.artifact.observations.find((o) => o.name === "12b.selfShareOverride").value.length === 0 && rs.artifact.provenance.classificationInput.selfShares.length === 0
      && rs.artifact.observations.find((o) => o.name === "13.composition").value.state === "incomplete" && rs.artifact.transportLog.some((c) => c.where.some((w) => w[0] === "epochIndex")) && rs.artifact.transportLog.every((c) => c.where.every((w) => w[0] !== "epochIndex" || w[2] === EPOCH)));
  }

  // ================= 5b. one captured argument, and a reproducible artifact =================
  {
    // a getter on the TARGET that reshapes the profile: the reviewer's construction. The
    // check must capture every input before any validation reads a caller's member, so
    // the getter is refused at capture and the nine-check profile is what would govern
    const prof = JSON.parse(JSON.stringify(PROFILE));
    const tgt = { contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11, epochIndex: EPOCH };
    let getterRan = 0;
    Object.defineProperty(tgt, "poolId", { enumerable: true, configurable: true, get() { getterRan += 1; delete prof.required.oldClauseRefusedWithIndexError; return POOL; } });
    const qg = makeQuery({ mode: "old-clause-served" });
    await rejects("a getter on the target that would remove the old-clause requirement is refused at capture, before any validation reads it",
      C.runTransportCheck({ query: qg.query, ledger, profile: prof, provenance: provenanceFor(), acceptance: true, target: tgt, plannedIdFor: plannedIdFor("good"), selfShares: [], executionVerdict: ({ member }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: member.effectiveCredits }) }),
      /arguments are not plain data .*target.*accessor-backed/);
    ok("that getter was never invoked, so the profile still carries nine required checks", getterRan === 0 && Object.keys(prof.required).length === 9);
    // THE GETTER MATRIX (the confirmation round's F1, retained here): both getter
    // forms (persistent, self-replacing) on every target field, on every top-level
    // data argument, on a self-share entry, and on each function argument, each
    // refused with ZERO invocations and ZERO queries, counted at the refusal and
    // again after a macrotask boundary; the nine-check profile intact throughout
    const matrix = [];
    const baseArgs = () => ({ query: null, ledger, profile: JSON.parse(JSON.stringify(PROFILE)), provenance: provenanceFor(), acceptance: true,
      target: { contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11, poolId: POOL, epochIndex: EPOCH }, plannedIdFor: plannedIdFor("good"), selfShares: [FUNDER_A],
      executionVerdict: ({ member }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: member.effectiveCredits }) });
    const plant = (obj, key, value, form, counter) => Object.defineProperty(obj, key, { enumerable: true, configurable: true, get() {
      counter.n += 1;
      if (form === "self-replacing") Object.defineProperty(obj, key, { value, enumerable: true, configurable: true, writable: true });
      return value;
    } });
    for (const form of ["persistent", "self-replacing"]) {
      for (const field of ["contractId", "chainId", "contractVersion", "poolId", "epochIndex"]) matrix.push({ name: `target.${field} ${form}`, place: (a, c) => plant(a.target, field, a.target[field], form, c) });
      for (const arg of ["ledger", "profile", "provenance", "acceptance", "target", "selfShares"]) matrix.push({ name: `argument ${arg} ${form}`, place: (a, c) => plant(a, arg, a[arg], form, c) });
      matrix.push({ name: `selfShares[0] ${form}`, place: (a, c) => plant(a.selfShares, "0", a.selfShares[0], form, c) });
      for (const fn of ["query", "plannedIdFor", "executionVerdict"]) matrix.push({ name: `function ${fn} ${form}`, place: (a, c) => plant(a, fn, a[fn], form, c) });
    }
    let matrixOk = 0;
    for (const m of matrix) {
      const q = makeQuery({ mode: "old-clause-served", docs: (() => { const d = conformingDocs(); d.transferReservation = []; d.transferReceipt = []; d.receiptProofPart = []; return d; })() });
      const a = baseArgs(); a.query = q.query; a.provenance = provenanceFor({ classificationInput: { selfShares: [FUNDER_A] } });
      const counter = { n: 0 };
      m.place(a, counter);
      let refused = null;
      try { await C.runTransportCheck(a); } catch (e) { refused = e.message; }
      await new Promise((r) => setImmediate(r)); await new Promise((r) => setTimeout(r, 0));
      const good = refused !== null && /accessor-backed/.test(refused) && counter.n === 0 && q.calls.length === 0 && Object.keys(a.profile.required).length === 9;
      if (good) matrixOk += 1; else console.log(`  FAIL: getter matrix case ${m.name}: refused=${JSON.stringify(refused && refused.slice(0, 60))} calls=${counter.n} queries=${q.calls.length}`);
    }
    ok(`the getter matrix: ${matrix.length} accessor cases refused with zero invocations and zero queries, the profile intact, counted again after a macrotask boundary (${matrixOk} of ${matrix.length})`, matrixOk === matrix.length && matrix.length === 30);
    // a function-valued argument supplied through a getter is refused too
    const argsG = { query: qg.query, ledger, profile: PROFILE, provenance: provenanceFor(), acceptance: true, target: { contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11, poolId: POOL, epochIndex: EPOCH }, selfShares: [], executionVerdict: ({ member }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: member.effectiveCredits }) };
    Object.defineProperty(argsG, "plannedIdFor", { enumerable: true, configurable: true, get: () => plannedIdFor("good") });
    await rejects("a function argument supplied through a getter is refused (own data property required)", C.runTransportCheck(argsG), /plannedIdFor is accessor-backed/);
    // TWO STORES DIFFERING IN CREDITS PRODUCE DIFFERENT ARTIFACTS, and each is
    // RECONSTRUCTIBLE offline: the kernel re-evaluated over the artifact's own plan
    // input and evidence bundle returns the state and reasons the artifact reports
    const docsB = conformingDocs();
    docsB.epochHeader[0].fields.grossCredits = 2000; docsB.epochHeader[0].fields.feeCredits = 200; docsB.platformAccrual[0].fields.amountCredits = 1800;
    const rA = await runWith({ ledger });
    const rB = await runWith({ docs: docsB, ledger });
    ok("two stores with different credit amounts produce DIFFERENT artifacts (the evidence is retained)", JSON.stringify(rA.artifact) !== JSON.stringify(rB.artifact) && rA.verdict.pass && rB.verdict.pass);
    ok("the artifact retains the served fields the composition computed over (the amounts are readable)", JSON.stringify(rB.artifact.evidence).includes("1800") && JSON.stringify(rB.artifact.evidence).includes("2000") && !JSON.stringify(rA.artifact.evidence).includes("1800"));
    ok("the artifact retains the plan input and the verdict inputs", rB.artifact.evidence.planInput.header.grossCredits === "2000" && rB.artifact.evidence.verdictInputs.length === 1 && rB.artifact.evidence.verdictInputs[0].receipt.documentId === RCPT_A);
    const recA = C.reconstruct(rA.artifact), recB = C.reconstruct(rB.artifact);
    ok("reconstruct: the kernel re-evaluated over the artifact's plan input and bundle returns the reported state and reasons, for both", recA.state === "complete" && recA.reasons.length === 0 && recB.state === "complete" && recA.matchesArtifact === true && recB.matchesArtifact === true);
    const docsI = conformingDocs(); docsI.transferReceipt = []; docsI.receiptProofPart = [];
    const rI = await runWith({ docs: docsI, ledger, profile: { ...PROFILE, required: { ...PROFILE.required, compositionState: "incomplete", compositionReasons: ["INCOMPLETE_RECEIPT_ABSENT"] } } });
    const recI = C.reconstruct(rI.artifact);
    ok("reconstruct on an incomplete artifact returns incomplete with its reason and matches", recI.state === "incomplete" && recI.reasons[0].code === "INCOMPLETE_RECEIPT_ABSENT" && recI.matchesArtifact === true);
    // an altered artifact does not reconstruct to what it reports
    const altered = JSON.parse(JSON.stringify(rI.artifact));
    altered.observations.find((o) => o.name === "13.composition").value.state = "complete";
    const recT = C.reconstruct(altered);
    ok("reconstruct reports a MISMATCH when the artifact's stated state disagrees with what its own evidence evaluates to", recT.state === "incomplete" && recT.matchesArtifact === false);
    throws("reconstruct refuses an artifact without evidence", () => C.reconstruct({ ...rA.artifact, evidence: undefined }), /artifact carries no evidence/);
  }

  // ================= 6. observe mode =================
  {
    const r = await runWith({ mode: "unserved", ledger, acceptance: false });
    ok("observe mode: exit 0 despite failed required checks, with an explicit disclaimer in the artifact",
      r.exitCode === 0 && r.verdict.pass === false && r.artifact.acceptance.mode === "observe" && /not an acceptance/.test(r.artifact.acceptance.disclaimer));
    const r2 = await runWith({ ledger, acceptance: true });
    ok("acceptance mode is labeled as such in the artifact", r2.artifact.acceptance.mode === "acceptance");
  }

  // ================= 7. THE V2 MODE (the per-epoch context design, section 7, step 5) =================
  // The context-driven run over a two-epoch universe: epoch 0 journaled with a served header,
  // two accruals (A the income identity, B payable), B's reservation, receipt and parts, and a
  // journaled capture for B; epoch 1 fresh with no fixture (the C1 precondition). The plan
  // inputs come from the REAL context module over the installed generator, the verdict
  // closures from executionVerdictFor over the REAL receipt verifier with the verifier test's
  // mock pipeline, so CAPTURE-VERIFIED is reached through the shared composition and never
  // through a constant.
  {
    const X = require("./e2EpochContext.cjs");
    const D = require("./e2DocId.cjs");
    const formationCore = require("./formationCore.cjs");
    const { canonicalString } = require("./canonicalJson.cjs");
    const { PART_BOUND_B } = require("./e2ReceiptVerify.cjs");
    const dpp = await import(pathToFileURL(require.resolve("pshenmic-dpp", { paths: [ROOT] })).href);
    const generateId = (...a) => dpp.DocumentWASM.generateId(...a);
    const h = (f) => f.repeat(64 / f.length);
    const POOL2 = h("5779"), A = h("aa11"), B = h("bb22");
    const CONTRACT_B58 = "8sVj3E2yqQtV3f5mHdq2vG6x7PhZyM2QPZbYjVSNv9L", OWNER_B58 = "5jLZJF4RurvAkahXhLLHHgBisEDgs58v8AmP8w7cMqe";
    const CONTRACT2 = formationCore.toId32(CONTRACT_B58).toString("hex");
    const CHAIN = "tegara-test-1", AH2 = h("a10c"), GROSS = "2000000", FEE = "0";
    const scope2 = (n) => ({ contractId: CONTRACT2, chainId: CHAIN, contractVersion: 11, poolId: POOL2, epochIndex: n });
    const formation2 = () => ({ resolved: true, incomeIdentity: A, allocationHash: AH2, allocation: [{ recipientId: A, bps: 5000 }, { recipientId: B, bps: 5000 }] });
    const journaled = (number, gross = GROSS, fee = FEE) => ({ number, grossCredits: gross, feeCredits: fee, distributableCredits: String(BigInt(gross) - BigInt(fee)), allocationHash: AH2, memberCount: 2 });
    const identifiers = { generateId, ownerId: OWNER_B58, contractId: CONTRACT_B58 };
    const buildCtx = (n, over = {}) => X.buildEpochContext({ scope: scope2(n), formation: formation2(), journalRun: [journaled(0)], configuredStart: 0, declaredFigures: null, identifiers, ...over });
    const plannedIdOf = (n, f) => D.docIdForIn({ ...identifiers, poolId: POOL2, epochIndex: n, type: "platformAccrual", subject: f }).hex;
    const ACC_A = plannedIdOf(0, A), ACC_B = plannedIdOf(0, B);
    // the verifier fixture (the verifier test's mock pipeline at its contract)
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
    const carrierOfLength = (wantL) => { const mk = (n) => toHex(canonicalString({ quorumHash: h("dd"), round: 3, blockIdHash: h("bb"), quorumType: 4, signature: "cd".repeat(Math.max(1, n)) })); let padLen = 1, hex = mk(padLen); padLen += wantL - hex.length / 2; hex = mk(Math.floor(padLen)); while (hex.length / 2 < wantL) { padLen += 1; hex = mk(padLen); } while (hex.length / 2 > wantL) { padLen -= 1; hex = mk(padLen); } return hex; };
    const bigCarrier = carrierOfLength(2 * PART_BOUND_B + 100);
    const META_HEX = toHex(canonicalString({ chainId: CHAIN, protocolVersion: 12, height: "1000", timeMs: "1690000000000", coreChainLockedHeight: 777, epoch: 5 }));
    const AMOUNT_B = "1000000";
    const TRANSFER_HEX = toHex(canonicalString({ senderId: A, recipientId: B, amountCredits: AMOUNT_B, nonce: "7" }));
    const TH2 = sha(TRANSFER_HEX);
    const L = bigCarrier.length / 2, count = Math.ceil(L / PART_BOUND_B);
    const proofBytes = bigCarrier.slice(0, PART_BOUND_B * 2);
    const partBytes = (i) => bigCarrier.slice(i * PART_BOUND_B * 2, Math.min((i + 1) * PART_BOUND_B, L) * 2);
    const capture = { v: 1, kind: "tegara.e2.receiptCapture.v1", object: "transfer", gen: 1, poolId: POOL2, epochIndex: 0, accrualId: ACC_B, transitionHash: TH2, transitionBytes: TRANSFER_HEX,
      proofMsg: bigCarrier, metadataMsg: META_HEX, inclusionHeight: "1001", heightRoute: "tenderdash-tx", signerIdentity: h("f0"), signerKeyId: 2, sig: "00".repeat(65) };
    const docs2 = (over = {}) => ({
      epochHeader: [doc(h("7700"), { poolId: POOL2, epochIndex: 0, grossCredits: 2000000, feeCredits: 0, memberCount: 2, calcVersion: 1, allocationHash: AH2, ...(over.header || {}) })],
      platformAccrual: [doc(ACC_A, { poolId: POOL2, funderId: A, epochIndex: 0, amountCredits: 1000000, shareBps: 5000 }), doc(ACC_B, { poolId: POOL2, funderId: B, epochIndex: 0, amountCredits: 1000000, shareBps: 5000 })],
      transferReservation: [doc(h("d100"), { poolId: POOL2, accrualId: ACC_B, transitionHash: TH2 })],
      transferReceipt: [doc(h("c000"), { poolId: POOL2, accrualId: ACC_B, transitionHash: TH2, transitionBytes: TRANSFER_HEX, proofBytes, proofPartCount: count, metadataBytes: META_HEX,
        blockHeight: be64(1000), coreChainLockedHeight: 777, timeMs: be64("1690000000000"), quorumHash: h("dd"), round: 3 })],
      receiptProofPart: [doc(h("e100"), { poolId: POOL2, accrualId: ACC_B, partIndex: 1, bytes: partBytes(1) }), doc(h("e200"), { poolId: POOL2, accrualId: ACC_B, partIndex: 2, bytes: partBytes(2) })],
    });
    const PROFILE_V2 = {
      kind: "tegara.e2.forwardTransportProfile.v2",
      required: { ...PROFILE.required, planBuiltBeforeAnyRead: true, planFiguresSource: "journaled-header", planHeaderEqualsFormation: true, selfShareDerived: true,
        identifiersCanonical: true, verdictOwner: "shared-verifier", freshEpochPrecondition: true, universe: [0, 1], refreshCountMax: 3, generationSequence: [0, 1, 2], earlyStop: null },
      optional: {},
    };
    const provV2 = (over = {}) => provenanceFor({ contractId: CONTRACT2, chainId: CHAIN, poolId: POOL2, epochIndex: 0, classificationInput: { incomeIdentity: A },
      synthetic: { planValues: "derived-from-formation-and-calculation", selfShare: "derived-from-income-identity", transferVerdict: "shared-verifier" }, ...over });
    const runV2 = async ({ mode = "good", docs = docs2(), profile = PROFILE_V2, provenance = provV2(), acceptance = true, contexts, universe = [0, 1], captureFor, depsOf, extra = {} } = {}) => {
      const q = makeQuery({ mode, docs });
      const ctxs = contexts || { 0: buildCtx(0), 1: buildCtx(1) };
      const journal = new Map([[ACC_B, { capture, supersessions: [] }]]);
      const { deps, calls } = depsOf ? depsOf() : mkDeps();
      const out = await C.runTransportCheck({ query: q.query, ledger, profile, provenance, acceptance,
        target: { contractId: CONTRACT2, chainId: CHAIN, contractVersion: 11, poolId: POOL2, epochIndex: 0 },
        contextFor: (n) => ctxs[n], universe, captureFor: captureFor || ((id) => (journal.has(id) ? journal.get(id) : null)), deps, ...extra });
      return { ...out, calls: q.calls, verifierCalls: calls };
    };
    const obsOf = (r, name) => r.artifact.observations.find((o) => o.name === name).value;

    // ---- the positive control ----
    {
      const r = await runV2({});
      ok(`v2: the positive control passes its v2 profile (${failedChecks(r.verdict).join(",") || "no failed check"})`, r.verdict.pass === true && r.exitCode === 0 && r.artifact.kind === "tegara.e2.forwardTransportArtifact.v2");
      ok("v2: every one of the twenty checks has a result row", r.verdict.results.map((x) => x.check).sort().join() === Object.keys(PROFILE_V2.required).sort().join() && r.verdict.results.length === 20);
      ok("v2: the one plan input (epoch 0) was derived at adapter read count zero, and the precondition epoch derived none", JSON.stringify(obsOf(r, "3.planInputsCapturedAtReadCount")) === JSON.stringify({ 0: 0 }));
      ok("v2: the generations are exactly [0, 1, 2] (one at run start, one after each universe epoch's selection) and the early-stop record is null", JSON.stringify(obsOf(r, "13.generations").map((g) => g.generation)) === "[0,1,2]" && obsOf(r, "13c.earlyStop") === null);
      const proj = obsOf(r, "13b.projections");
      ok("v2: the projection answered epoch 0 true at generation 0 and refused epoch 1 by name (PROJECTION_STATE_UNPROVED) at generation 1, each recorded with its generation",
        proj.length === 2 && proj[0].epochIndex === 0 && proj[0].generation === 0 && proj[0].answer.value === true && proj[1].epochIndex === 1 && proj[1].generation === 1 && proj[1].answer.code === "PROJECTION_STATE_UNPROVED");
      ok("v2: epoch 0 is complete in every generation and epoch 1 is unproved with the C1 code in every generation", obsOf(r, "13.generations").every((g) => g.epochs[0].state === "complete" && g.epochs[1].state === "unproved" && g.epochs[1].codes[0] === "UNPROVED_EPOCH_OBJECT_UNPROVED"));
      ok("v2: no read was issued under epoch 1 (no plan was built for the fresh epoch), and the composition reads happened under epoch 0", r.artifact.transportLog.every((c) => c.where.every((w) => w[0] !== "epochIndex" || w[2] === 0)) && r.artifact.transportLog.length > 0);
      ok(`v2: the shared verifier ran through the closure: both proof stages and the basis adapter were called (stages ${r.verifierCalls.stageOne}/${r.verifierCalls.stageTwo}, basis ${r.verifierCalls.basis}), and the recorded verdicts are CAPTURE-VERIFIED with B's amount`,
        r.verifierCalls.stageOne >= 2 && r.verifierCalls.stageTwo >= 2 && r.verifierCalls.basis >= 1 && r.artifact.evidence.verdicts.length >= 1 && r.artifact.evidence.verdicts.every((v) => v.label === "CAPTURE-VERIFIED" && v.verifiedAmountCredits === AMOUNT_B));
      ok("v2: the recording wrapper AWAITED the closure (the recorded verdict is the resolved plain object, not a Promise)", r.artifact.evidence.verdicts.every((v) => v && typeof v === "object" && typeof v.then !== "function" && v.label === "CAPTURE-VERIFIED"));
      ok("v2: the plan input came from the context, not the served header: its header equals the formation's hash and count and the members' self-share is derived from the income identity", r.artifact.evidence.planInput.header.allocationHash === AH2 && r.artifact.evidence.planInput.header.memberCount === 2 && r.artifact.evidence.planInput.members.find((m) => m.funderId === A).isSelfShare === true && r.artifact.evidence.planInput.members.find((m) => m.funderId === B).payable === true);
      ok("v2: the provenance carries the income identity and the fixed v2 labels, and no self-share list exists anywhere in the artifact", r.artifact.provenance.classificationInput.incomeIdentity === A && r.artifact.provenance.synthetic.transferVerdict === "shared-verifier" && !JSON.stringify(r.artifact.observations).includes("selfShareOverride"));
      const rec = C.reconstruct(r.artifact);
      ok("v2: reconstruct re-evaluates the target epoch's final-generation evidence to the reported state", rec.state === "complete" && rec.matchesArtifact === true);
      ok("v2: the artifact's evidence carries every universe epoch, the projections, the early-stop record and the universe", Object.keys(r.artifact.evidence.epochs).join() === "0,1" && r.artifact.evidence.epochs[1].precondition.code === "UNPROVED_EPOCH_OBJECT_UNPROVED" && r.artifact.evidence.projections.length === 2 && JSON.stringify(r.artifact.evidence.universe) === "[0,1]" && r.artifact.evidence.earlyStop === null && "earlyStop" in r.artifact.evidence);
    }
    // ---- the six mutations of design section 7, each as a run the profile must refuse ----
    {
      // (a) the fresh-epoch precondition removed: a runner claiming a fixture for epoch 1 builds a plan from it
      const declared1 = buildCtx(1, { declaredFigures: { grossCredits: GROSS, feeCredits: FEE } });
      const ra = await runV2({ contexts: { 0: buildCtx(0), 1: declared1 } });
      ok(`v2 (a): a plan built for the fresh epoch (a declared fixture where the precondition belongs) FAILS freshEpochPrecondition (${failedChecks(ra.verdict).join(",")})`, ra.verdict.pass === false && failedChecks(ra.verdict).includes("freshEpochPrecondition"));
      // (b) the constant verdict under the shared-verifier label: a v2 run takes no executionVerdict
      await rejects("v2 (b): an executionVerdict argument is refused for a v2 run (the verdict owner is the shared verifier by construction)", runV2({ extra: { executionVerdict: ({ member }) => ({ label: "CAPTURE-VERIFIED", verifiedAmountCredits: member.effectiveCredits }) } }), /takes no executionVerdict argument/);
      throws("v2 (b): a v2 provenance labeled constant-capture-verified refuses", () => C.assembleProvenance(provV2({ synthetic: { planValues: "derived-from-formation-and-calculation", selfShare: "derived-from-income-identity", transferVerdict: "constant-capture-verified" } }), 2), /transferVerdict must be "shared-verifier"/);
      throws("v2 (b): a v2 profile whose verdictOwner is not shared-verifier refuses (D3)", () => C.validateProfile({ ...PROFILE_V2, required: { ...PROFILE_V2.required, verdictOwner: "constant-capture-verified" } }), /verdictOwner must be shared-verifier/);
      // (c) a refresh that adds an epoch: the universe is fixed for the run and the profile names it
      const rc = await runV2({ universe: [0, 1, 2], contexts: { 0: buildCtx(0), 1: buildCtx(1), 2: buildCtx(2, { journalRun: [journaled(0), journaled(1)] }) } });
      ok(`v2 (c): a universe other than the profile's FAILS the universe check and the generation sequence (${failedChecks(rc.verdict).join(",")})`, rc.verdict.pass === false && failedChecks(rc.verdict).includes("universe") && failedChecks(rc.verdict).includes("generationSequence"));
      // (d) a fourth generation: bound by universe.length + 1 and by the profile
      const rd = await runV2({ profile: { ...PROFILE_V2, required: { ...PROFILE_V2.required, refreshCountMax: 2, generationSequence: [0, 1] } } });
      ok(`v2 (d): a profile allowing fewer generations than the run takes FAILS refreshCountMax and generationSequence (three generations were taken) (${failedChecks(rd.verdict).join(",")})`, rd.verdict.pass === false && failedChecks(rd.verdict).includes("refreshCountMax") && failedChecks(rd.verdict).includes("generationSequence"));
      // (e) a base58 income identity: refused by the context builder before any run, and by the provenance
      throws("v2 (e): a base58 income identity is refused by the context builder (never a plan with no self-share)", () => buildCtx(0, { formation: { ...formation2(), incomeIdentity: OWNER_B58 } }), /incomeIdentity must be 64 lowercase hex/);
      throws("v2 (e): a v2 provenance with a base58 income identity refuses", () => C.assembleProvenance(provV2({ classificationInput: { incomeIdentity: OWNER_B58 } }), 2), /classificationInput must carry the 64-hex incomeIdentity/);
      await rejects("v2 (e): a provenance income identity that is not the target context's refuses (the artifact must describe the execution)", runV2({ provenance: provV2({ classificationInput: { incomeIdentity: B } }) }), /incomeIdentity does not equal the target context's/);
      // (f) an early-stopped run under the normal profile: epoch 0 REFUSED (a served header disagreeing with the plan)
      const rf = await runV2({ docs: docs2({ header: { grossCredits: 1999999 } }) });
      ok(`v2 (f): a refused epoch 0 stops the run by name after generation 0 (no selection is made) and FAILS the normal profile on compositionState, generationSequence and earlyStop (${failedChecks(rf.verdict).join(",")})`,
        rf.verdict.pass === false && failedChecks(rf.verdict).includes("generationSequence") && failedChecks(rf.verdict).includes("earlyStop") && failedChecks(rf.verdict).includes("compositionState")
        && obsOf(rf, "13c.earlyStop") !== null && obsOf(rf, "13c.earlyStop").afterGeneration === 0 && obsOf(rf, "13c.earlyStop").code === "REFUSED_EPOCH_IN_SNAPSHOT" && obsOf(rf, "13c.earlyStop").epochIndex === 0
        && obsOf(rf, "13.generations").length === 1 && obsOf(rf, "13b.projections").length === 0 && rf.artifact.evidence.earlyStop.epochIndex === 0);
      const EARLY = { ...PROFILE_V2, required: { ...PROFILE_V2.required, compositionState: "refused", compositionReasons: ["REFUSED_HEADER_MISMATCH"], generationSequence: [0], earlyStop: { afterGeneration: 0, code: "REFUSED_EPOCH_IN_SNAPSHOT", epochIndex: 0 }, freshEpochPrecondition: undefined } };
      delete EARLY.required.freshEpochPrecondition;
      const rf2 = await runV2({ docs: docs2({ header: { grossCredits: 1999999 } }), profile: EARLY });
      ok(`v2 (f): the SEPARATE early-stop profile, naming the stop, accepts the prefix [0] (${failedChecks(rf2.verdict).join(",") || "no failed check"})`, rf2.verdict.pass === true && rf2.exitCode === 0);
      const rf3 = await runV2({ profile: EARLY });
      ok(`v2 (f): the early-stop profile does NOT accept the normal run (no stop happened) (${failedChecks(rf3.verdict).join(",")})`, rf3.verdict.pass === false && failedChecks(rf3.verdict).includes("earlyStop"));
      const EARLY_OTHER = { ...EARLY, required: { ...EARLY.required, earlyStop: { afterGeneration: 0, code: "REFUSED_EPOCH_IN_SNAPSHOT", epochIndex: 1 } } };
      const rf4 = await runV2({ docs: docs2({ header: { grossCredits: 1999999 } }), profile: EARLY_OTHER });
      ok("v2 (f): an early-stop profile naming another epoch does NOT accept the stop at epoch 0 (the epoch is a structured field, not a text prefix)", rf4.verdict.pass === false && failedChecks(rf4.verdict).includes("earlyStop"));
      throws("v2 (f): an early-stop profile whose reason is free text refuses (the stop is named by generation, code and epoch)", () => C.validateProfile({ ...EARLY, required: { ...EARLY.required, earlyStop: { afterGeneration: 0, reason: "P" } } }), /earlyStop must be null or/);
      throws("v2 (f): an early-stop profile whose generation is not the sequence's last refuses", () => C.validateProfile({ ...EARLY, required: { ...EARLY.required, earlyStop: { afterGeneration: 7, code: "REFUSED_EPOCH_IN_SNAPSHOT", epochIndex: 0 } } }), /must be the last generation/);
      // A NON-TARGET EPOCH REFUSED AFTER ITS SELECTION stops the run too: epochs 0 and 1 both
      // journaled and complete, and the third read of epoch 1's header (generation 2) serves a
      // disagreeing gross, so generation 2 holds a refused epoch 1 and the run stops there
      {
        const ACC_A1 = plannedIdOf(1, A), ACC_B1 = plannedIdOf(1, B);
        const TRANSFER1 = toHex(canonicalString({ senderId: A, recipientId: B, amountCredits: AMOUNT_B, nonce: "9" })), TH1 = sha(TRANSFER1);
        const capture1 = { ...capture, epochIndex: 1, accrualId: ACC_B1, transitionHash: TH1, transitionBytes: TRANSFER1 };
        const d = docs2();
        d.epochHeader.push(doc(h("7701"), { poolId: POOL2, epochIndex: 1, grossCredits: 2000000, feeCredits: 0, memberCount: 2, calcVersion: 1, allocationHash: AH2 }));
        d.platformAccrual.push(doc(ACC_A1, { poolId: POOL2, funderId: A, epochIndex: 1, amountCredits: 1000000, shareBps: 5000 }), doc(ACC_B1, { poolId: POOL2, funderId: B, epochIndex: 1, amountCredits: 1000000, shareBps: 5000 }));
        d.transferReservation.push(doc(h("d101"), { poolId: POOL2, accrualId: ACC_B1, transitionHash: TH1 }));
        d.transferReceipt.push(doc(h("c001"), { poolId: POOL2, accrualId: ACC_B1, transitionHash: TH1, transitionBytes: TRANSFER1, proofBytes, proofPartCount: count, metadataBytes: META_HEX, blockHeight: be64(1000), coreChainLockedHeight: 777, timeMs: be64("1690000000000"), quorumHash: h("dd"), round: 3 }));
        d.receiptProofPart.push(doc(h("e101"), { poolId: POOL2, accrualId: ACC_B1, partIndex: 1, bytes: partBytes(1) }), doc(h("e201"), { poolId: POOL2, accrualId: ACC_B1, partIndex: 2, bytes: partBytes(2) }));
        const both = { 0: buildCtx(0, { journalRun: [journaled(0), journaled(1)] }), 1: buildCtx(1, { journalRun: [journaled(0), journaled(1)] }) };
        const journal = new Map([[ACC_B, { capture, supersessions: [] }], [ACC_B1, { capture: capture1, supersessions: [] }]]);
        let headerReads1 = 0;
        const base = makeQuery({ docs: d });
        const changing = async (type, where, opts) => {
          if (type === "epochHeader" && where.some(([k, , v]) => k === "epochIndex" && v === 1)) { headerReads1 += 1; if (headerReads1 >= 3) return { documents: [doc(h("7701"), { ...d.epochHeader[1].fields, grossCredits: 1999999 })], height: "100" }; }
          return base.query(type, where, opts);
        };
        const { deps } = mkDeps();
        const PROFILE_BOTH = { ...PROFILE_V2, required: { ...PROFILE_V2.required, freshEpochPrecondition: undefined } }; delete PROFILE_BOTH.required.freshEpochPrecondition;
        const r = await C.runTransportCheck({ query: changing, ledger, profile: PROFILE_BOTH, provenance: provV2(), acceptance: true,
          target: { contractId: CONTRACT2, chainId: CHAIN, contractVersion: 11, poolId: POOL2, epochIndex: 0 },
          contextFor: (n) => both[n], universe: [0, 1], captureFor: (id) => (journal.has(id) ? journal.get(id) : null), deps });
        const es = obsOf(r, "13c.earlyStop");
        ok(`v2: a non-target epoch refused by a record served AFTER its selection (generation 2) stops the run by name at that generation, and the normal profile fails on earlyStop (${failedChecks(r.verdict).join(",")}; stop ${JSON.stringify(es)})`,
          r.verdict.pass === false && es !== null && es.afterGeneration === 2 && es.code === "REFUSED_EPOCH_IN_SNAPSHOT" && es.epochIndex === 1 && obsOf(r, "13.generations")[2].epochs[1].state === "refused" && obsOf(r, "13.generations")[1].epochs[1].state === "complete" && failedChecks(r.verdict).includes("earlyStop"));
      }
    }
    // ---- the v2 argument boundary ----
    {
      await rejects("v2: a selfShares argument is refused for a v2 run", runV2({ extra: { selfShares: [] } }), /takes no selfShares argument/);
      await rejects("v2: a plannedIdFor argument is refused for a v2 run", runV2({ extra: { plannedIdFor: () => ACC_A } }), /takes no plannedIdFor argument/);
      await rejects("v1: a contextFor argument is refused for a v1 run", C.runTransportCheck({ query: makeQuery().query, ledger, profile: PROFILE, provenance: provenanceFor(), acceptance: true, target: { contractId: CONTRACT_HEX, chainId: "devnet-x", contractVersion: 11, poolId: POOL, epochIndex: EPOCH }, plannedIdFor: plannedIdFor("good"), selfShares: [], executionVerdict: () => ({ label: "CAPTURE-VERIFIED" }), contextFor: () => null }), /takes no contextFor/);
      await rejects("v2: a context for another pool is refused", runV2({ contexts: { 0: X.buildEpochContext({ scope: { ...scope2(0), poolId: h("ffee") }, formation: formation2(), journalRun: [journaled(0)], configuredStart: 0, declaredFigures: null, identifiers }), 1: buildCtx(1) } }), /per-epoch context for pool/);
      await rejects("v2: a context on another chain is refused", runV2({ contexts: { 0: buildCtx(0, { scope: { ...scope2(0), chainId: "other" } }), 1: buildCtx(1) } }), /bound to another contract, chain or version/);
      await rejects("v2: a universe not containing the target epoch is refused", runV2({ universe: [1], contexts: { 1: buildCtx(1) } }), /target epoch 0 is not in the universe/);
      await rejects("v2: a non-ascending universe is refused", runV2({ universe: [1, 0] }), /strictly ascending/);
      await rejects("v2: incomplete verifier dependencies are refused before any read (executionVerdictFor's construction check)", runV2({ depsOf: () => ({ calls: {}, deps: { verifierDeps: {}, verifyCaptureBasis: async () => true } }) }), /verifierDeps\.decodeProofCarrier/);
      throws("v2: a v2 profile missing its acceptance minimum refuses (the universe among them)", () => C.validateProfile({ kind: PROFILE_V2.kind, required: { allReadsVerified: true, compositionState: "complete", verdictOwner: "shared-verifier", generationSequence: [0], earlyStop: null }, optional: {} }), /must carry universe/);
      throws("v2: a v2 profile naming an unknown check refuses", () => C.validateProfile({ ...PROFILE_V2, required: { ...PROFILE_V2.required, bogus: true } }), /unknown check bogus/);
      throws("v1: a v1 profile naming a v2 check refuses", () => C.validateProfile({ ...PROFILE, required: { ...PROFILE.required, universe: [0] } }), /unknown check universe/);
      throws("v2: a generation sequence that is not 0, 1, ... refuses", () => C.validateProfile({ ...PROFILE_V2, required: { ...PROFILE_V2.required, generationSequence: [0, 2] } }), /exact list 0, 1/);
      throws("v2: a v2 profile with a figures source outside the context's labels refuses", () => C.validateProfile({ ...PROFILE_V2, required: { ...PROFILE_V2.required, planFiguresSource: "served-header" } }), /not a context figures source/);
      // a wrong-key served reservation under epoch 0 makes the composition refuse and the run stop early
      const docsW = docs2(); docsW.transferReservation[0].fields.transitionHash = h("7777");
      const rw = await runV2({ docs: docsW });
      ok(`v2: a served reservation whose hash differs from the receipt's refuses epoch 0 and stops the run by name (${failedChecks(rw.verdict).join(",")})`, rw.verdict.pass === false && obsOf(rw, "13c.earlyStop") !== null && /REFUSED_RESERVATION_MISMATCH/.test(obsOf(rw, "13.composition").codes.join()));
      // observe mode carries the disclaimer in v2 too
      const ro = await runV2({ mode: "unserved", acceptance: false });
      ok("v2: observe mode exits 0 with the disclaimer text present despite failed required checks", ro.exitCode === 0 && ro.verdict.pass === false && ro.artifact.acceptance.mode === "observe" && /not an acceptance result/.test(ro.artifact.acceptance.disclaimer));
      // a getter on the profile's kind is refused at capture (a self-replacing getter answering
      // v2 once could otherwise select the v2 runner with a captured v1 profile)
      {
        const prof = JSON.parse(JSON.stringify(PROFILE));
        let reads = 0;
        Object.defineProperty(prof, "kind", { enumerable: true, configurable: true, get() { reads += 1; Object.defineProperty(prof, "kind", { value: PROFILE.kind, enumerable: true, configurable: true, writable: true }); return "tegara.e2.forwardTransportProfile.v2"; } });
        await rejects("a self-replacing getter on profile.kind is refused at the profile's capture, before it can select a mode", runV2({ profile: prof }), /arguments are not plain data .*profile.*accessor/);
        ok(`that kind getter was never invoked (reads ${reads})`, reads === 0);
      }
      // an optional-section value is validated in its own section
      { const req = { ...PROFILE.required }; delete req.heightSpanMax;
        throws("an invalid value under optional is refused (validated in its own section)", () => C.validateProfile({ ...PROFILE, required: req, optional: { heightSpanMax: -1 } }), /heightSpanMax must be a non-negative/); }
      throws("a check named under both sections refuses", () => C.validateProfile({ ...PROFILE_V2, optional: { planBuiltBeforeAnyRead: true } }), /under both required and optional/);
      throws("a check named under both sections refuses even when the required value is valid and the optional one invalid (the checker's concealment construction)", () => C.validateProfile({ ...PROFILE, optional: { heightSpanMax: -1 } }), /under both required and optional|heightSpanMax must be a non-negative/);
      { const req = { ...PROFILE.required }; delete req.sweepAgainstAbsentEmpty;
        throws("a boolean check taking false under optional refuses", () => C.validateProfile({ ...PROFILE, required: req, optional: { sweepAgainstAbsentEmpty: false } }), /takes only true/); }
      // a context that is frozen only at the outer object is refused
      await rejects("a context whose nested precondition is mutable is refused (deeply frozen data required)", runV2({ contexts: { 0: buildCtx(0), 1: Object.freeze({ ...buildCtx(1), precondition: { code: "UNPROVED_EPOCH_OBJECT_UNPROVED", diagnostic: "mutable" } }) } }), /deeply frozen per-epoch context/);
      // the context boundary: an extra function member, an extra plain member and a kind getter
      // are each refused at the whole-context capture, the getter never invoked
      await rejects("a frozen context carrying an extra function member is refused at the whole-context capture", runV2({ contexts: { 0: buildCtx(0), 1: Object.freeze({ ...buildCtx(1), extra: () => 1 }) } }), /contextFor\(1\) is not plain data .*function/);
      await rejects("a frozen context carrying an extra plain member is refused (the member set is exactly the context's)", runV2({ contexts: { 0: buildCtx(0), 1: Object.freeze({ ...buildCtx(1), extra: 1 }) } }), /not the per-epoch context's/);
      {
        let kreads = 0;
        const c1 = { ...buildCtx(1) };
        Object.defineProperty(c1, "kind", { enumerable: true, configurable: true, get() { kreads += 1; return X.KIND; } });
        Object.freeze(c1);
        let t = null; try { await runV2({ contexts: { 0: buildCtx(0), 1: c1 } }); } catch (e) { t = e.message; }
        ok(`a context whose kind is a getter is refused at the capture with the getter never invoked (reads ${kreads})`, t !== null && /contextFor\(1\) is not plain data/.test(t) && kreads === 0);
      }
      // the dependency bundle is validated at entry even when no closure will be built
      await rejects("an empty dependency bundle is refused at entry for a universe of precondition epochs (no closure would be built)", runV2({ universe: [1], contexts: { 1: buildCtx(1) }, provenance: provV2({ epochIndex: 1 }), extra: { target: { contractId: CONTRACT2, chainId: CHAIN, contractVersion: 11, poolId: POOL2, epochIndex: 1 } }, depsOf: () => ({ calls: {}, deps: {} }) }), /deps.verifierDeps must be a plain object/);
      await rejects("a bundle missing one stage function is refused at entry", runV2({ depsOf: () => { const { deps, calls } = mkDeps(); const vd = { ...deps.verifierDeps }; delete vd.verifyStageTwo; return { calls, deps: { verifierDeps: vd, verifyCaptureBasis: deps.verifyCaptureBasis } }; } }), /deps.verifierDeps.verifyStageTwo must be a function/);
      throws("a v2 provenance carrying a fourth synthetic label refuses (the record is exactly the three)", () => C.assembleProvenance(provV2({ synthetic: { planValues: "derived-from-formation-and-calculation", selfShare: "derived-from-income-identity", transferVerdict: "shared-verifier", anotherLabel: "caller-supplied" } }), 2), /beside the three fixed v2 labels/);
      // a universe of precondition epochs only: the work-examining predicates fail rather than pass vacuously
      {
        const r = await runV2({ universe: [1], contexts: { 1: buildCtx(1) }, provenance: provV2({ epochIndex: 1 }), extra: { target: { contractId: CONTRACT2, chainId: CHAIN, contractVersion: 11, poolId: POOL2, epochIndex: 1 } },
          profile: (() => { const req = { ...PROFILE_V2.required, universe: [1], generationSequence: [0, 1], refreshCountMax: 2, compositionState: "unproved", compositionReasons: ["UNPROVED_EPOCH_OBJECT_UNPROVED"] }; delete req.freshEpochPrecondition; return { ...PROFILE_V2, required: req }; })() });
        ok(`a universe of one precondition epoch FAILS verdictOwner, planHeaderEqualsFormation, selfShareDerived, identifiersCanonical and planBuiltBeforeAnyRead (nothing was examined) rather than passing vacuously (${failedChecks(r.verdict).join(",")})`, r.verdict.pass === false && ["verdictOwner", "planHeaderEqualsFormation", "selfShareDerived", "identifiersCanonical", "planBuiltBeforeAnyRead"].every((c) => failedChecks(r.verdict).includes(c)));
      }
      // THE DEPENDENCY FUNCTIONS ARE CAPTURED AT ENTRY: a context supplier that replaces a
      // member of the caller's bundle before the closures are built changes nothing (the
      // round's construction: a refusing basis replaced by an accepting one)
      {
        let originalCalls = 0, replacementCalls = 0;
        const { deps } = mkDeps();
        const bundle = { verifierDeps: { ...deps.verifierDeps }, verifyCaptureBasis: async () => { originalCalls += 1; return false; } };
        const ctxs = { 0: buildCtx(0), 1: buildCtx(1) };
        const q = makeQuery({ docs: docs2() });
        const journal = new Map([[ACC_B, { capture, supersessions: [] }]]);
        const r = await C.runTransportCheck({ query: q.query, ledger, profile: PROFILE_V2, provenance: provV2(), acceptance: true,
          target: { contractId: CONTRACT2, chainId: CHAIN, contractVersion: 11, poolId: POOL2, epochIndex: 0 },
          contextFor: (n) => { bundle.verifyCaptureBasis = async () => { replacementCalls += 1; return true; }; return ctxs[n]; }, universe: [0, 1], captureFor: (id) => (journal.has(id) ? journal.get(id) : null), deps: bundle });
        ok(`a basis adapter replaced on the caller's bundle by contextFor does not reach the verifier: the entry-captured refusing one runs (original ${originalCalls}, replacement ${replacementCalls}) and the run fails on the refused verdict`,
          originalCalls >= 1 && replacementCalls === 0 && r.verdict.pass === false && r.artifact.evidence.verdicts.every((v) => v.label === "REFUSED"));
        // the NESTED stage functions are captured too (the confirmation round's construction: a
        // wrapper forwarding to the caller's object at call time would pass the basis case)
        let stageOriginal = 0, stageReplacement = 0;
        const { deps: deps2 } = mkDeps();
        const bundle2 = { verifierDeps: { ...deps2.verifierDeps, verifyStageTwo: async () => { stageOriginal += 1; return false; } }, verifyCaptureBasis: deps2.verifyCaptureBasis };
        const q2 = makeQuery({ docs: docs2() });
        const r2 = await C.runTransportCheck({ query: q2.query, ledger, profile: PROFILE_V2, provenance: provV2(), acceptance: true,
          target: { contractId: CONTRACT2, chainId: CHAIN, contractVersion: 11, poolId: POOL2, epochIndex: 0 },
          contextFor: (n) => { bundle2.verifierDeps.verifyStageTwo = async () => { stageReplacement += 1; return true; }; return ctxs[n]; }, universe: [0, 1], captureFor: (id) => (journal.has(id) ? journal.get(id) : null), deps: bundle2 });
        ok(`a STAGE function replaced on the caller's nested bundle by contextFor does not reach the verifier either: the entry-captured refusing stage runs (original ${stageOriginal}, replacement ${stageReplacement}) and the run fails on the refused verdict`,
          stageOriginal >= 1 && stageReplacement === 0 && r2.verdict.pass === false && r2.artifact.evidence.verdicts.every((v) => v.label === "REFUSED"));
      }
      // THE SELECTION READS THE LATEST SNAPSHOT: epochs 0 and 1 journaled, epoch 1's receipt
      // absent at generation 0 and served from generation 1, so the selection of epoch 1 (made
      // at generation 1) answers true, and a plan derived from the declared branch is refused
      // by a journaled-header expectation
      {
        const ACC_A1 = plannedIdOf(1, A), ACC_B1 = plannedIdOf(1, B);
        const TRANSFER1 = toHex(canonicalString({ senderId: A, recipientId: B, amountCredits: AMOUNT_B, nonce: "9" })), TH1 = sha(TRANSFER1);
        const capture1 = { ...capture, epochIndex: 1, accrualId: ACC_B1, transitionHash: TH1, transitionBytes: TRANSFER1 };
        const d = docs2();
        d.epochHeader.push(doc(h("7701"), { poolId: POOL2, epochIndex: 1, grossCredits: 2000000, feeCredits: 0, memberCount: 2, calcVersion: 1, allocationHash: AH2 }));
        d.platformAccrual.push(doc(ACC_A1, { poolId: POOL2, funderId: A, epochIndex: 1, amountCredits: 1000000, shareBps: 5000 }), doc(ACC_B1, { poolId: POOL2, funderId: B, epochIndex: 1, amountCredits: 1000000, shareBps: 5000 }));
        d.transferReservation.push(doc(h("d101"), { poolId: POOL2, accrualId: ACC_B1, transitionHash: TH1 }));
        const receipt1 = doc(h("c001"), { poolId: POOL2, accrualId: ACC_B1, transitionHash: TH1, transitionBytes: TRANSFER1, proofBytes, proofPartCount: count, metadataBytes: META_HEX, blockHeight: be64(1000), coreChainLockedHeight: 777, timeMs: be64("1690000000000"), quorumHash: h("dd"), round: 3 });
        const parts1 = [doc(h("e101"), { poolId: POOL2, accrualId: ACC_B1, partIndex: 1, bytes: partBytes(1) }), doc(h("e201"), { poolId: POOL2, accrualId: ACC_B1, partIndex: 2, bytes: partBytes(2) })];
        const both = { 0: buildCtx(0, { journalRun: [journaled(0), journaled(1)] }), 1: buildCtx(1, { journalRun: [journaled(0), journaled(1)] }) };
        const journal = new Map([[ACC_B, { capture, supersessions: [] }], [ACC_B1, { capture: capture1, supersessions: [] }]]);
        let headerReads1 = 0;
        const base = makeQuery({ docs: d });
        const appearing = async (type, where, opts) => {
          if (type === "epochHeader" && where.some(([k, , v]) => k === "epochIndex" && v === 1)) { headerReads1 += 1; if (headerReads1 === 2 && d.transferReceipt.length === 1) { d.transferReceipt.push(receipt1); d.receiptProofPart.push(...parts1); } }
          return base.query(type, where, opts);
        };
        const { deps } = mkDeps();
        const PROFILE_BOTH = (() => { const req = { ...PROFILE_V2.required }; delete req.freshEpochPrecondition; return { ...PROFILE_V2, required: req }; })();
        const r = await C.runTransportCheck({ query: appearing, ledger, profile: PROFILE_BOTH, provenance: provV2(), acceptance: true,
          target: { contractId: CONTRACT2, chainId: CHAIN, contractVersion: 11, poolId: POOL2, epochIndex: 0 },
          contextFor: (n) => both[n], universe: [0, 1], captureFor: (id) => (journal.has(id) ? journal.get(id) : null), deps });
        const gens = obsOf(r, "13.generations"), proj = obsOf(r, "13b.projections");
        ok(`v2: a receipt appearing at generation 1 makes epoch 1 incomplete at generation 0 and complete from generation 1, and the selection of epoch 1 (made against the generation-1 snapshot) answers true (${failedChecks(r.verdict).join(",") || "no failed check"})`,
          r.verdict.pass === true && gens[0].epochs[1].state === "incomplete" && gens[1].epochs[1].state === "complete" && proj[1].epochIndex === 1 && proj[1].generation === 1 && proj[1].answer.value === true);
      }
      {
        const declared0 = buildCtx(0, { journalRun: [], declaredFigures: { grossCredits: GROSS, feeCredits: FEE } });
        const r = await runV2({ contexts: { 0: declared0, 1: buildCtx(1) } });
        ok(`v2: a target context built from a declared fixture FAILS planFiguresSource under a journaled-header expectation, the detail naming declared-fixture (${failedChecks(r.verdict).join(",")})`,
          r.verdict.pass === false && failedChecks(r.verdict).includes("planFiguresSource") && /declared-fixture/.test(r.verdict.results.find((x) => x.check === "planFiguresSource").detail));
      }
      // THE VERIFIER'S ANSWER CONTROLS THE RESULT: a refusing basis adapter makes the closure's
      // verdict REFUSED, the kernel refuses the transfer, generation 0 holds a refused epoch and
      // the run stops there; a throwing stage propagates as acquisition's named refusal
      {
        const r = await runV2({ depsOf: () => { const { deps, calls } = mkDeps(); return { calls, deps: { ...deps, verifyCaptureBasis: async () => { calls.basis += 1; return false; } } }; } });
        const es = obsOf(r, "13c.earlyStop");
        ok(`a refusing capture basis reaches the kernel as a REFUSED verdict: the recorded verdict is REFUSED naming the basis, the composition refuses the transfer, and the run stops after generation 0 (${failedChecks(r.verdict).join(",")})`,
          r.verdict.pass === false && r.artifact.evidence.verdicts.length >= 1 && r.artifact.evidence.verdicts.every((v) => v.label === "REFUSED" && /basis/.test(v.reason))
          && obsOf(r, "13.composition").codes.includes("REFUSED_TRANSFER_UNVERIFIED") && es !== null && es.afterGeneration === 0 && es.epochIndex === 0);
        await rejects("a throwing proof stage propagates as acquisition's named refusal (a verifier fault is not evidence), never a verdict", runV2({ depsOf: () => { const { deps, calls } = mkDeps(); deps.verifierDeps.verifyStageTwo = async () => { throw new Error("stage two down"); }; return { calls, deps }; } }), /injected execution verdict failed .*stage two down/);
      }
      // an unexpected error from the projection propagates as a fault, never an observation
      {
        const Kmod = require("./e2ForwardKernel.cjs");
        const orig = Kmod.projectForWriter;
        Kmod.projectForWriter = () => { throw new Error("projection unavailable"); };
        let t = null; try { await runV2({}); } catch (e) { t = e.message; } finally { Kmod.projectForWriter = orig; }
        ok("v2: a projection fault that is not one of the kernel's named refusals propagates out of the run (never recorded as an answer)", t !== null && /projection unavailable/.test(t));
        Kmod.projectForWriter = () => { throw new Error("e2ForwardKernel: PROJECTION_STATE_UNPROVED2 unexpected failure"); };
        let t2 = null; try { await runV2({}); } catch (e) { t2 = e.message; } finally { Kmod.projectForWriter = orig; }
        ok("v2: a projection error whose code is a NEAR-MATCH of a named refusal (a suffix, no delimiter) propagates too (the whole token before the kernel's delimiter is required)", t2 !== null && /PROJECTION_STATE_UNPROVED2/.test(t2));
      }
      throws("a profile member supplied as undefined is refused by the exported validator (not skipped)", () => C.validateProfile({ ...PROFILE_V2, required: { ...PROFILE_V2.required, verdictOwner: undefined } }), /supplied as undefined/);
      // the committed v2 profile fixture is valid and names the bootstrap run's expectations
      const fs = require("fs");
      const committed = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures/forwardTransportProfile-bootstrap-epochs01-v2.json"), "utf8"));
      const committedEarly = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures/forwardTransportProfile-earlystop-example-v2.json"), "utf8"));
      ok("the committed v2 bootstrap profile validates, requires EVERY v2 check (the key set equals CHECKS_V2), and its identity is the canonical hash", (() => { try { C.validateProfile(committed); } catch { return false; } return Object.keys(committed.required).sort().join() === [...C.CHECKS_V2].sort().join() && C.profileIdentity(committed) === crypto.createHash("sha256").update(require("./canonicalJson.cjs").canonicalString(committed)).digest("hex"); })());
      ok("the committed v2 bootstrap profile's required values equal the design's, member by member", JSON.stringify(committed.required) === JSON.stringify({ ...PROFILE.required, planBuiltBeforeAnyRead: true, planFiguresSource: "journaled-header", planHeaderEqualsFormation: true, selfShareDerived: true, identifiersCanonical: true, verdictOwner: "shared-verifier", freshEpochPrecondition: true, universe: [0, 1], refreshCountMax: 3, generationSequence: [0, 1, 2], earlyStop: null }));
      // THE COMMITTED PROFILES ARE RUN: the normal one accepts the positive control and rejects
      // the early-stopped run, the early-stop one accepts the early-stopped run and rejects the
      // normal one (the third pass: a changed value in a committed file must be caught)
      {
        const rc = await runV2({ profile: committed });
        ok(`the committed bootstrap profile ACCEPTS the positive control run (${failedChecks(rc.verdict).join(",") || "no failed check"})`, rc.verdict.pass === true && rc.exitCode === 0);
        const rc2 = await runV2({ profile: committed, docs: docs2({ header: { grossCredits: 1999999 } }) });
        ok("the committed bootstrap profile REJECTS the early-stopped run", rc2.verdict.pass === false);
        const re = await runV2({ profile: committedEarly, docs: docs2({ header: { grossCredits: 1999999 } }) });
        ok(`the committed early-stop example profile ACCEPTS the early-stopped run (${failedChecks(re.verdict).join(",") || "no failed check"})`, re.verdict.pass === true);
        const re2 = await runV2({ profile: committedEarly });
        ok("the committed early-stop example profile REJECTS the normal run", re2.verdict.pass === false);
      }
      ok("the committed early-stop example profile validates, names the stop by generation, code and epoch, and its generation is the sequence's last", (() => { try { C.validateProfile(committedEarly); } catch { return false; } return committedEarly.required.earlyStop !== null && committedEarly.required.earlyStop.code === "REFUSED_EPOCH_IN_SNAPSHOT" && committedEarly.required.earlyStop.epochIndex === 0 && committedEarly.required.earlyStop.afterGeneration === 0 && committedEarly.required.generationSequence.join() === "0"; })());
    }
  }

  console.log(`\ne2ForwardTransportCheckTest: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exitCode = 1;
};

main().catch((e) => { console.error(`e2ForwardTransportCheckTest: unexpected throw: ${e.message}`); process.exitCode = 1; });
