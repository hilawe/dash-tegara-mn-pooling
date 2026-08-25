/**
 * Offline battery for the E2 audit's first half (plain `node`, no
 * network): the closed label system, the normative calculation against
 * the spec's exact vectors, the start-source resolution (the four
 * D8-named cases), the interval resolution and branch selection with the
 * discovery-totality cases driven THROUGH the audit's own resolution, the
 * domain classification, the verdict-grade grammar's precedence, the
 * annotation grammar, the closed report schema, and the D8 property
 * tests (precedence totality, grade monotonicity, the containment
 * properties, domain classification) over seeded synthetic inputs.
 *
 * The load-bearing oracles (the label order, terminal and ceiling
 * tables, the verdict-grammar restatement, the calculation vectors) are
 * restated LITERALLY from the frozen spec and asserted equal to the
 * module's registries, so a mutated registry cannot move both sides.
 * Convenience fixtures and shape assertions do use imported constants
 * (ASPECT_KEYS, REPORT_KIND, U32_MAX); their protection comes from the
 * literal-table equality checks beside them, not from independence.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

// the second-half world writes owned environment keys and a journal, so
// the store is a per-run temp directory, set BEFORE any module resolves
// its paths; the pair check is ledger-aware, so the ledger is selected
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-e2audit-"));
process.env.TEGARA_ENV_PATH = path.join(TMP, "env.local");
process.env.LEDGER = "v9";

const { canonicalString } = require("./canonicalJson.cjs");
const envStore = require("./envStore.cjs");
const core = require("./formationCore.cjs");
const { appendRecord, openJournal } = require("./e2JournalStore.cjs");
const { K } = require("./e2Journal.cjs");
const { HEADER_KIND: CAP_HEADER, RECEIPT_KIND: CAP_RECEIPT,
  SUPERSESSION_KIND: CAP_SUP } = require("./e2CaptureRecord.cjs");
// the PUBLIC surface (the entry and the report's own vocabulary) and, kept
// visibly separate, the INTERNALS this suite reaches through the module's
// test-only surface. The split is the point: an invariant these internals hold
// through `runAudit` is not promised to an arbitrary direct caller, and several
// review rounds were spent on claims that forgot that (round-65).
const auditModule = require("./e2Audit.cjs");
const {
  LABELS, ASPECT_TERMINALS, ASPECT_KEYS, GRADES, REPORT_KIND, runAudit,
} = auditModule;
const {
  AuditInputRefusal, rankOf, labelAtLeast, aggregateWeakest,
  computeNormativeEpoch, resolveStartSource, resolveInterval,
  classifyRecordEpoch, gradeVerdict, buildOpenEndedAnnotation, buildReport,
  evaluateReservationPresence, evaluateTransferExecution, evaluateOrdering,
  evaluateFormationInputs, evaluateContractIntegrity, evaluateLedgerRecords,
  U32_MAX,
} = auditModule.__testing;

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed++; }
  else { failed++; console.error("FAIL:", name); }
};
const throwsSync = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
const refusesInput = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no refusal)`); }
  catch (e) {
    ok(name, e instanceof AuditInputRefusal && e.grade === "REFUSED-INPUT"
      && re.test(e.message));
  }
};
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
const rejectsInput = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no refusal)`); }
  catch (e) {
    ok(name, e instanceof AuditInputRefusal && e.grade === "REFUSED-INPUT"
      && re.test(e.message));
  }
};

// the spec's label order, restated literally as the test's own oracle
const SPEC_ORDER = ["REFUSED", "UNVERIFIABLE", "UNPROVED", "OPERATOR-PROVIDED",
  "ATTESTED", "READ-CHECKED", "CAPTURE-VERIFIED", "PROVED-NET", "PROVED",
  "PROVED-EVENTS"];
const specRank = (l) => SPEC_ORDER.indexOf(l);
// the spec's terminal table, restated literally so the property oracle
// never reads the module's own registry (a mutated terminal would
// otherwise change both sides of the comparison)
// the spec's strongest defined form per aspect, restated literally
const SPEC_CEILINGS = {
  universe: "PROVED", activationBoundary: "PROVED", deactivationBoundary: "PROVED",
  binding: "PROVED", transferExecution: "CAPTURE-VERIFIED",
  reservationPresence: "PROVED", temporalOrder: "PROVED", ordering: "PROVED",
  formationInputs: "PROVED", recordSet: "PROVED", shareConformance: "PROVED",
  balance: "PROVED-EVENTS", contractIntegrity: "PROVED",
};
const SPEC_TERMINALS = {
  universe: "PROVED", activationBoundary: "PROVED", deactivationBoundary: "PROVED",
  binding: "PROVED", transferExecution: "CAPTURE-VERIFIED",
  reservationPresence: "PROVED", temporalOrder: "PROVED", ordering: "PROVED",
  formationInputs: "PROVED", recordSet: "PROVED", shareConformance: "PROVED",
  balance: "PROVED-NET", contractIntegrity: "PROVED",
};

// a deterministic LCG; the seed is RECORDED here and in the run output
const SEED = 20260822;
let lcg = SEED >>> 0;
const rand = () => { lcg = (Math.imul(lcg, 1664525) + 1013904223) >>> 0; return lcg / 4294967296; };
const randInt = (n) => Math.floor(rand() * n);
const pick = (arr) => arr[randInt(arr.length)];

// a synthetic gapless ledger for discovery, as in e2DiscoveryTest
const ledgerFetch = (newest, provedFlag) => async (start, end) => {
  const epochs = [];
  for (let n = start; n <= end && n <= newest; n++) epochs.push({ number: n });
  return { epochs, proved: provedFlag };
};

const bs58mod = require("bs58");
const toBase58 = (hex) => (bs58mod.default || bs58mod).encode(Buffer.from(hex, "hex"));

// the test's own identifier normalizer for override closures
const sameIdTest = (a, b) => {
  const hex = (v) => {
    if (typeof v === "string" && /^[0-9a-f]{64}$/.test(v)) return v;
    const d = core.toId32(v);
    return d === null ? null : d.toString("hex");
  };
  return hex(a) !== null && hex(a) === hex(b);
};

// a valid all-aspects map at the aspect table's "label now" strengths
const labelsNow = () => ({
  universe: { evaluated: true, label: "UNPROVED" },
  activationBoundary: { evaluated: true, label: "OPERATOR-PROVIDED" },
  deactivationBoundary: { evaluated: false },
  binding: { evaluated: true, label: "UNVERIFIABLE" },
  transferExecution: { evaluated: true, examinedCount: 1, label: "CAPTURE-VERIFIED" },
  reservationPresence: { evaluated: true, examinedCount: 1, label: "PROVED" },
  temporalOrder: { evaluated: true, label: "UNVERIFIABLE" },
  ordering: { evaluated: true, examinedCount: 1, label: "ATTESTED" },
  formationInputs: { evaluated: true, label: "PROVED" },
  recordSet: { evaluated: true, label: "READ-CHECKED" },
  shareConformance: { evaluated: true, label: "UNVERIFIABLE" },
  balance: { evaluated: true, label: "UNVERIFIABLE" },
  contractIntegrity: { evaluated: true, label: "PROVED" },
});
// every aspect at its terminal (the upgraded-evidence future the grammar
// must grade FULL / FULL-TO-DATE)
const RECEIPT_ASPECT_KEYS = ["transferExecution", "reservationPresence", "ordering"];
const labelsAtTerminal = (branch) => Object.fromEntries(ASPECT_KEYS.map((k) => [k,
  k === "deactivationBoundary" && branch === "open-ended"
    ? { evaluated: false }
    : { evaluated: true,
      ...(RECEIPT_ASPECT_KEYS.includes(k) ? { examinedCount: 1 } : {}),
      label: ASPECT_TERMINALS[k] }]));
const cleanCoverage = () => ({ lateConfiguredStart: false, containsUniverse: true, narrowedRange: false });

(async () => {
  // ---- the closed label system ----
  ok("the vocabulary is exactly the spec's ten labels in the spec's order",
    LABELS.length === 10 && LABELS.every((l, i) => l === SPEC_ORDER[i]));
  ok("the grade vocabulary is exactly the spec's six outcomes",
    JSON.stringify([...GRADES]) === JSON.stringify(["REFUSED-INPUT", "REFUSED-REPORT",
      "PARTIAL BY SCOPE", "PARTIAL BY EVIDENCE", "FULL-TO-DATE", "FULL"]));
  ok("the branch vocabulary is exactly the spec's two branches",
    JSON.stringify([...require("./e2Audit.cjs").BRANCHES])
      === JSON.stringify(["deactivation-bounded", "open-ended"]));
  ok("aggregation takes the weakest under the total order",
    aggregateWeakest(["PROVED", "OPERATOR-PROVIDED", "CAPTURE-VERIFIED"]) === "OPERATOR-PROVIDED");
  ok("a REFUSED member dominates aggregation downward",
    aggregateWeakest(["PROVED-EVENTS", "REFUSED"]) === "REFUSED");
  ok("a single label aggregates to itself", aggregateWeakest(["ATTESTED"]) === "ATTESTED");
  throwsSync("an unknown label refuses rank lookup", () => rankOf("PLAUSIBLE"), /closed label vocabulary/);
  throwsSync("aggregation refuses an empty set", () => aggregateWeakest([]), /nonempty/);
  ok("labelAtLeast is inclusive at equality", labelAtLeast("READ-CHECKED", "READ-CHECKED") === true
    && labelAtLeast("ATTESTED", "READ-CHECKED") === false);
  ok("PROVED sits above PROVED-NET (the adjacent pair the order most needs)",
    labelAtLeast("PROVED", "PROVED-NET") === true && labelAtLeast("PROVED-NET", "PROVED") === false);
  ok("a two-member aggregation where neither the last member nor REFUSED is the answer",
    aggregateWeakest(["UNPROVED", "PROVED"]) === "UNPROVED");
  throwsSync("a SINGLETON aggregation still validates its one label (reduce never calls back)",
    () => aggregateWeakest(["PLAUSIBLE"]), /closed label vocabulary/);
  ok("the aspect registry is exactly the spec's thirteen rows with the spec's terminals",
    ASPECT_KEYS.length === 13 && Object.keys(SPEC_TERMINALS).length === 13
    && ASPECT_KEYS.every((k) => ASPECT_TERMINALS[k] === SPEC_TERMINALS[k]));
  {
    const { ASPECT_CEILINGS } = require("./e2Audit.cjs");
    ok("the ceiling registry matches the spec's strongest defined forms, key set and all",
      JSON.stringify(Object.keys(ASPECT_CEILINGS).sort())
        === JSON.stringify(Object.keys(SPEC_CEILINGS).sort())
      && ASPECT_KEYS.every((k) => ASPECT_CEILINGS[k] === SPEC_CEILINGS[k]));
  }

  // ---- the normative calculation: the spec's exact vectors ----
  {
    const v1 = computeNormativeEpoch({ totalProcessingFees: "0", totalDistributedStorageFees: "0",
      coreBlockRewards: "1000000", totalBlocks: "1", proposedCount: 1, operatorFeeBps: 1000,
      rows: [{ bps: 6000 }, { bps: 4000 }] });
    ok("vector 1: every field exact (G, fee, D, owed, bps echo, r), exactly two rows",
      v1.encodingRefused === null && v1.G === "1000000" && v1.fee === "100000"
      && v1.D === "900000" && v1.owed.length === 2 && v1.owed[0].amountCredits === "540000"
      && v1.owed[1].amountCredits === "360000" && v1.owed[0].bps === 6000
      && v1.owed[1].bps === 4000 && v1.r === "0");
    const v1b = computeNormativeEpoch({ totalProcessingFees: "0", totalDistributedStorageFees: "0",
      coreBlockRewards: "1000000", totalBlocks: "1", proposedCount: 1, operatorFeeBps: 233,
      rows: [{ bps: 10000 }] });
    ok("a second fee point: 233 bps of 1000000 is exactly 23300, one row",
      v1b.fee === "23300" && v1b.D === "976700" && v1b.owed.length === 1
      && v1b.owed[0].amountCredits === "976700" && v1b.r === "0");
  }
  {
    const v2 = computeNormativeEpoch({ totalProcessingFees: "1003", totalDistributedStorageFees: "0",
      coreBlockRewards: "0", totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0,
      rows: [{ bps: 3333 }, { bps: 3333 }, { bps: 3334 }] });
    ok("vector 2: exactly three owed rows of 334 with their bps echoed, r 1",
      v2.owed.length === 3 && v2.owed.every((o) => o.amountCredits === "334")
      && v2.owed[0].bps === 3333 && v2.owed[1].bps === 3333 && v2.owed[2].bps === 3334
      && v2.r === "1");
  }
  {
    const v3 = computeNormativeEpoch({ totalProcessingFees: "9", totalDistributedStorageFees: "0",
      coreBlockRewards: "0", totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0,
      rows: [{ bps: 9999 }, { bps: 1 }] });
    ok("vector 3: owed 8/0, r 1, exactly two rows with their bps (the zero-owed member keeps its row)",
      v3.owed.length === 2 && v3.owed[0].amountCredits === "8" && v3.owed[0].bps === 9999
      && v3.owed[1].amountCredits === "0" && v3.owed[1].bps === 1 && v3.r === "1");
  }
  {
    const v4a = computeNormativeEpoch({ totalProcessingFees: "9223372036854775807",
      totalDistributedStorageFees: "9223372036854775807", coreBlockRewards: "1",
      totalBlocks: "8192", proposedCount: 1, operatorFeeBps: 0, rows: [{ bps: 10000 }] });
    ok("vector 4a: the u64-maximum payout gives G 2251799813685247, encodable, one row",
      v4a.encodingRefused === null && v4a.G === "2251799813685247" && v4a.owed.length === 1
      && v4a.owed[0].amountCredits === "2251799813685247" && v4a.r === "0");
  }
  {
    const v4b = computeNormativeEpoch({ totalProcessingFees: "3000000",
      totalDistributedStorageFees: "2000000", coreBlockRewards: "1000000",
      totalBlocks: "100", proposedCount: 0, operatorFeeBps: 0, rows: [{ bps: 10000 }] });
    ok("vector 4b: an absent proposer gives G 0, fee 0, D 0, one zero owed row, r 0",
      v4b.encodingRefused === null && v4b.G === "0" && v4b.fee === "0" && v4b.D === "0"
      && v4b.owed.length === 1 && v4b.owed[0].amountCredits === "0" && v4b.r === "0");
  }
  {
    const v4c = computeNormativeEpoch({ totalProcessingFees: "9007199254740990",
      totalDistributedStorageFees: "1", coreBlockRewards: "1",
      totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0, rows: [{ bps: 10000 }] });
    ok("vector 4c: G 9007199254740992 is the first refused grossCredits value, the refusal TOTAL",
      v4c.encodingRefused !== null && v4c.encodingRefused.field === "grossCredits"
      && v4c.encodingRefused.value === "9007199254740992"
      && v4c.fee === null && v4c.D === null && v4c.owed === null && v4c.r === null);
    const atCeiling = computeNormativeEpoch({ totalProcessingFees: "9007199254740989",
      totalDistributedStorageFees: "1", coreBlockRewards: "1",
      totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0, rows: [{ bps: 10000 }] });
    ok("exactly the ceiling 9007199254740991 is still encodable (the boundary is exact)",
      atCeiling.encodingRefused === null && atCeiling.G === "9007199254740991");
    // the spec's Number-divergence specimen: exact fee 208967022709990
    ok("wide intermediates: fee at G 9007199254740991 with 232 bps is exactly 208967022709990",
      computeNormativeEpoch({ totalProcessingFees: "9007199254740989",
        totalDistributedStorageFees: "1", coreBlockRewards: "1", totalBlocks: "1",
        proposedCount: 1, operatorFeeBps: 232, rows: [{ bps: 10000 }] }).fee === "208967022709990");
  }
  {
    const v5 = computeNormativeEpoch({ totalProcessingFees: "1", totalDistributedStorageFees: "0",
      coreBlockRewards: "0", totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0,
      rows: [{ bps: 5000 }, { bps: 5000 }] });
    ok("vector 5: positive G with no positive entitlement from rounding alone, r 1, two rows with bps",
      v5.G === "1" && v5.fee === "0" && v5.D === "1" && v5.owed.length === 2
      && v5.owed.every((o) => o.amountCredits === "0")
      && v5.owed[0].bps === 5000 && v5.owed[1].bps === 5000 && v5.r === "1");
  }
  throwsSync("totalBlocks zero is a mandatory refusal", () => computeNormativeEpoch({
    totalProcessingFees: "1", totalDistributedStorageFees: "0", coreBlockRewards: "0",
    totalBlocks: "0", proposedCount: 0, operatorFeeBps: 0, rows: [{ bps: 10000 }] }), /totalBlocks of zero/);
  throwsSync("proposedCount above totalBlocks refuses", () => computeNormativeEpoch({
    totalProcessingFees: "1", totalDistributedStorageFees: "0", coreBlockRewards: "0",
    totalBlocks: "5", proposedCount: 6, operatorFeeBps: 0, rows: [{ bps: 10000 }] }), /exceeds totalBlocks/);
  throwsSync("a bps sum short of 10000 refuses", () => computeNormativeEpoch({
    totalProcessingFees: "1", totalDistributedStorageFees: "0", coreBlockRewards: "0",
    totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0, rows: [{ bps: 9999 }] }), /not exactly 10000/);
  throwsSync("nine rows refuse (the co-owner tier's bound)", () => computeNormativeEpoch({
    totalProcessingFees: "1", totalDistributedStorageFees: "0", coreBlockRewards: "0",
    totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0,
    rows: Array.from({ length: 9 }, () => ({ bps: 1112 })) }), /1\.\.8/);
  throwsSync("a u64-overflowing input refuses at the wire width", () => computeNormativeEpoch({
    totalProcessingFees: "18446744073709551616", totalDistributedStorageFees: "0",
    coreBlockRewards: "0", totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0,
    rows: [{ bps: 10000 }] }), /u64 wire width/);
  throwsSync("a negative amount input refuses at the decimal grammar", () => computeNormativeEpoch({
    totalProcessingFees: "-1", totalDistributedStorageFees: "0", coreBlockRewards: "0",
    totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0, rows: [{ bps: 10000 }] }), /canonical decimal string or BigInt/);
  throwsSync("a non-integer amount input refuses at the decimal grammar", () => computeNormativeEpoch({
    totalProcessingFees: "1.5", totalDistributedStorageFees: "0", coreBlockRewards: "0",
    totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0, rows: [{ bps: 10000 }] }), /canonical decimal string or BigInt/);
  throwsSync("a Number u64 quantity refuses (it may arrive already rounded)",
    () => computeNormativeEpoch({ totalProcessingFees: 9007199254740993,
      totalDistributedStorageFees: "0", coreBlockRewards: "0", totalBlocks: "1",
      proposedCount: 1, operatorFeeBps: 0, rows: [{ bps: 10000 }] }), /canonical decimal string or BigInt/);
  throwsSync("a negative BigInt refuses at the wire width", () => computeNormativeEpoch({
    totalProcessingFees: -1n, totalDistributedStorageFees: "0", coreBlockRewards: "0",
    totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0, rows: [{ bps: 10000 }] }), /u64 wire width/);
  {
    const big = computeNormativeEpoch({ totalProcessingFees: 9007199254740993n,
      totalDistributedStorageFees: "0", coreBlockRewards: "0", totalBlocks: "4",
      proposedCount: 1, operatorFeeBps: 0, rows: [{ bps: 10000 }] });
    ok("a BigInt above 2^53 is accepted exactly (floor(9007199254740993/4) = 2251799813685248)",
      big.G === "2251799813685248");
  }
  throwsSync("a proposedCount above the u32 width refuses independently of the blocks bound",
    () => computeNormativeEpoch({ totalProcessingFees: "1", totalDistributedStorageFees: "0",
      coreBlockRewards: "0", totalBlocks: "18446744073709551615", proposedCount: 4294967296,
      operatorFeeBps: 0, rows: [{ bps: 10000 }] }), /u32 wire width/);
  throwsSync("zero allocation rows refuse", () => computeNormativeEpoch({
    totalProcessingFees: "1", totalDistributedStorageFees: "0", coreBlockRewards: "0",
    totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0, rows: [] }), /1\.\.8/);
  throwsSync("a zero-bps row refuses", () => computeNormativeEpoch({
    totalProcessingFees: "1", totalDistributedStorageFees: "0", coreBlockRewards: "0",
    totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0,
    rows: [{ bps: 0 }, { bps: 10000 }] }), /bps 1\.\.10000/);
  throwsSync("a fractional operator fee refuses", () => computeNormativeEpoch({
    totalProcessingFees: "1", totalDistributedStorageFees: "0", coreBlockRewards: "0",
    totalBlocks: "1", proposedCount: 1, operatorFeeBps: 23.2, rows: [{ bps: 10000 }] }), /0\.\.10000/);
  {
    Object.prototype.bps = 10000;
    try {
      throwsSync("an allocation row cannot take its bps from Object.prototype",
        () => computeNormativeEpoch({ totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0,
          rows: [{}] }), /OWN integer bps/);
    } finally { delete Object.prototype.bps; }
  }
  throwsSync("a sparse allocation-row array refuses",
    () => computeNormativeEpoch({ totalProcessingFees: "1", totalDistributedStorageFees: "0",
      coreBlockRewards: "0", totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0,
      rows: Array(1) }), /own enumerable data element/);
  {
    // the getter must never RUN, not merely fail to satisfy the check
    let reads = 0;
    const row = {};
    Object.defineProperty(row, "bps", { get: () => { reads++; return 10000; }, enumerable: true });
    throwsSync("a getter-backed bps refuses (the snapshot is what the arithmetic reads)",
      () => computeNormativeEpoch({ totalProcessingFees: "1", totalDistributedStorageFees: "0",
        coreBlockRewards: "0", totalBlocks: "1", proposedCount: 1, operatorFeeBps: 0,
        rows: [row] }), /OWN integer bps/);
    ok("the bps getter was never invoked", reads === 0);
  }

  // ---- the start-source resolution: the four D8-named cases ----
  {
    const r = resolveStartSource({ journalBinding: 7, localKey: 7, explicitStartEpoch: null });
    ok("journal and local agreeing resolve to the journal", r.source === "journal"
      && r.configuredStart === 7 && r.requestedStart === 7);
  }
  {
    const r = resolveStartSource({ journalBinding: 7, localKey: null, explicitStartEpoch: null });
    ok("journal with no local key resolves to the journal", r.source === "journal"
      && r.configuredStart === 7 && r.requestedStart === 7);
  }
  {
    const r = resolveStartSource({ journalBinding: null, localKey: 4, explicitStartEpoch: null });
    ok("the local fallback with no journal resolves to the configuration",
      r.source === "local-configuration" && r.configuredStart === 4 && r.requestedStart === 4);
  }
  refusesInput("journal-local disagreement refuses the report outright (a soundness-review finding)",
    () => resolveStartSource({ journalBinding: 7, localKey: 9, explicitStartEpoch: null }),
    /disagrees with the journaled binding/);
  {
    const r = resolveStartSource({ journalBinding: null, localKey: null, explicitStartEpoch: 3 });
    ok("the explicit input is the last fallback source", r.source === "explicit-input"
      && r.configuredStart === 3 && r.requestedStart === 3);
  }
  refusesInput("no resolvable source is REFUSED-INPUT",
    () => resolveStartSource({ journalBinding: null, localKey: null, explicitStartEpoch: null }),
    /no resolvable start source/);
  refusesInput("a fractional journal binding refuses at the u32 grammar",
    () => resolveStartSource({ journalBinding: 1.5, localKey: null, explicitStartEpoch: null }),
    /not a u32/);
  refusesInput("a negative explicit start refuses at the u32 grammar",
    () => resolveStartSource({ journalBinding: null, localKey: null, explicitStartEpoch: -1 }),
    /not a u32/);
  {
    const r = resolveStartSource({ journalBinding: 10, localKey: 10, explicitStartEpoch: 2 });
    ok("an explicit earlier start sets the requested start without changing the source",
      r.source === "journal" && r.configuredStart === 10 && r.requestedStart === 2);
  }
  {
    const r = resolveStartSource({ journalBinding: 10, localKey: 10, explicitStartEpoch: 12 });
    ok("an explicit LATER start also sets the requested start (a narrower interval request)",
      r.source === "journal" && r.configuredStart === 10 && r.requestedStart === 12);
    const r2 = resolveStartSource({ journalBinding: null, localKey: 4, explicitStartEpoch: 9 });
    ok("an explicit later start beside the local source behaves the same",
      r2.source === "local-configuration" && r2.configuredStart === 4 && r2.requestedStart === 9);
  }

  // ---- interval resolution: branch selection, defaults, refusals ----
  {
    // a reversed REQUEST refuses BEFORE any discovery read runs (a
    // malformed request performs no fetches; the resolved-interval
    // reversal check downstream would refuse too, but only after reading)
    let fetches = 0;
    const counting = async (s, e) => { fetches++; return ledgerFetch(20, false)(s, e); };
    await rejectsInput("a reversed range is REFUSED-INPUT",
      resolveInterval({ requestedStart: 9, requestedEnd: 3, configuredStart: 9,
        fetchRange: counting }), /reversed/);
    ok("the reversed request performed no discovery fetch", fetches === 0);
  }
  {
    const r = await resolveInterval({ requestedStart: 5, requestedEnd: null, configuredStart: 5,
      provedDeactivation: 12, fetchRange: ledgerFetch(30, false) });
    ok("a proved deactivation boundary selects the bounded branch and its default end",
      r.branch === "deactivation-bounded" && r.interval.endEpoch === 12);
    ok("the bounded universe ends at the boundary, not the newest",
      r.universe.start === 5 && r.universe.end === 12);
  }
  await rejectsInput("an explicit end above the deactivation boundary refuses",
    resolveInterval({ requestedStart: 5, requestedEnd: 13, configuredStart: 5,
      provedDeactivation: 12, fetchRange: ledgerFetch(30, false) }), /exceeds the proved deactivation boundary/);
  await rejectsInput("a bounded DEFAULT end below the requested start refuses as reversed",
    resolveInterval({ requestedStart: 20, requestedEnd: null, configuredStart: 20,
      provedDeactivation: 12, fetchRange: ledgerFetch(30, false) }), /resolved interval \[20, 12\] is reversed/);
  await rejectsInput("a proved boundary beside an EMPTY discovery refuses (disagreeing evidence, both bounded variants)",
    resolveInterval({ requestedStart: 50, requestedEnd: 55, configuredStart: 50,
      provedDeactivation: 60, fetchRange: ledgerFetch(30, false) }), /serving nothing from 50/);
  await rejectsInput("the bounded default-end variant of the empty-discovery state refuses too",
    resolveInterval({ requestedStart: 50, requestedEnd: null, configuredStart: 50,
      provedDeactivation: 60, fetchRange: ledgerFetch(30, false) }), /disagreeing evidence/);
  await rejectsInput("a discovery TRUNCATED below the proved boundary refuses (same disagreement, nonempty form)",
    resolveInterval({ requestedStart: 5, requestedEnd: null, configuredStart: 5,
      provedActivation: 5, provedDeactivation: 12, fetchRange: ledgerFetch(10, true) }),
    /ending at 10 is disagreeing evidence/);
  await rejectsInput("the truncated-discovery refusal holds under an explicit end too",
    resolveInterval({ requestedStart: 5, requestedEnd: 10, configuredStart: 5,
      provedActivation: 5, provedDeactivation: 12, fetchRange: ledgerFetch(10, true) }),
    /ending at 10 is disagreeing evidence/);
  {
    // an EXPLICIT start above the universe start with an EMPTY discovery
    // is still a containment violation: discovery ran from the requested
    // start and says nothing about the omitted epochs (finding 1)
    const r = await resolveInterval({ requestedStart: 30, requestedEnd: null, configuredStart: 5,
      provedActivation: 5, fetchRange: ledgerFetch(20, true) });
    ok("an explicit later start is a coverage violation even when discovery is empty",
      r.emptyResult === true && r.coverage.containsUniverse === false
      && r.coverage.lateConfiguredStart === false);
    const g = gradeVerdict({ branch: r.branch, aspects: labelsAtTerminal("open-ended"),
      inReportRefusal: false, coverage: r.coverage,
      annotation: buildOpenEndedAnnotation({ endEpoch: null, recordsHeightMax: null }) });
    ok("the omitted-start empty report grades PARTIAL BY SCOPE, never out-graded by emptiness",
      g === "PARTIAL BY SCOPE");
  }
  {
    const r = await resolveInterval({ requestedStart: 5, requestedEnd: null, configuredStart: 5,
      fetchRange: ledgerFetch(30, false) });
    ok("no deactivation evidence selects the open-ended branch with the discovered newest",
      r.branch === "open-ended" && r.interval.endEpoch === 30 && r.universe.end === 30);
    ok("an unproved discovery stays unproved through the resolution",
      r.discovery.proved === false);
  }
  {
    const r = await resolveInterval({ requestedStart: 5, requestedEnd: 30, configuredStart: 5,
      fetchRange: ledgerFetch(30, false) });
    ok("an explicit end equal to the discovered newest passes", r.interval.endEpoch === 30);
  }
  await rejectsInput("an explicit end above the discovered newest refuses",
    resolveInterval({ requestedStart: 5, requestedEnd: 31, configuredStart: 5,
      fetchRange: ledgerFetch(30, false) }), /exceeds the discovered newest/);
  {
    const r = await resolveInterval({ requestedStart: 100, requestedEnd: null, configuredStart: 100,
      fetchRange: ledgerFetch(40, true) });
    ok("the empty-first result is the empty representation (endEpoch null, no universe)",
      r.emptyResult === true && r.interval.endEpoch === null && r.universe === null);
  }
  await rejectsInput("an explicit end beside an empty discovery refuses (outside the domain)",
    resolveInterval({ requestedStart: 100, requestedEnd: 120, configuredStart: 100,
      fetchRange: ledgerFetch(40, true) }), /no discovered newest/);
  {
    // discovery totality THROUGH the audit's resolution: boundary-aligned
    const r = await resolveInterval({ requestedStart: 0, requestedEnd: null, configuredStart: 0,
      fetchRange: ledgerFetch(63, true), discoveryOpts: { width: 64 } });
    ok("boundary-aligned discovery resolves end 63 via the later-empty rule", r.interval.endEpoch === 63);
    ok("a proved fetch keeps its proved flag through the resolution", r.discovery.proved === true);
  }
  {
    // later-empty across full ranges
    const r = await resolveInterval({ requestedStart: 0, requestedEnd: null, configuredStart: 0,
      fetchRange: ledgerFetch(191, true), discoveryOpts: { width: 64 } });
    ok("later-empty discovery resolves end 191 with the full epoch set",
      r.interval.endEpoch === 191 && r.discovery.epochs.length === 192
      && r.discovery.epochs.every((e, i) => e.number === i));
  }
  {
    // clipped at the u32 ceiling
    const r = await resolveInterval({ requestedStart: U32_MAX - 5, requestedEnd: null,
      configuredStart: U32_MAX - 5, fetchRange: ledgerFetch(U32_MAX, true), discoveryOpts: { width: 64 } });
    ok("a full response clipped at the u32 ceiling terminates AT the ceiling",
      r.interval.endEpoch === U32_MAX && r.discovery.epochs.length === 6);
  }
  {
    // the late configured start (proved activation earlier than configured)
    const r = await resolveInterval({ requestedStart: 8, requestedEnd: null, configuredStart: 8,
      provedActivation: 5, fetchRange: ledgerFetch(20, true) });
    ok("a configured start later than proved activation is the coverage violation",
      r.coverage.lateConfiguredStart === true && r.universe.start === 5
      && r.coverage.containsUniverse === false && r.coverage.narrowedRange === true);
  }
  {
    const r = await resolveInterval({ requestedStart: 5, requestedEnd: null, configuredStart: 5,
      provedActivation: 5, fetchRange: ledgerFetch(20, true) });
    ok("a configured start equal to proved activation is not late",
      r.coverage.lateConfiguredStart === false && r.coverage.containsUniverse === true);
  }
  {
    // END truncation: an explicit end below the discovered newest leaves
    // universe epochs uncovered, a containment violation from the other side
    const r = await resolveInterval({ requestedStart: 5, requestedEnd: 10, configuredStart: 5,
      provedActivation: 5, fetchRange: ledgerFetch(30, true) });
    ok("an explicit end truncating the universe is a coverage violation",
      r.interval.endEpoch === 10 && r.coverage.containsUniverse === false
      && r.coverage.narrowedRange === true);
  }
  {
    // the permitted prefix: an explicit start below the universe start
    const r = await resolveInterval({ requestedStart: 2, requestedEnd: null, configuredStart: 6,
      provedActivation: 6, fetchRange: ledgerFetch(20, true) });
    ok("an explicit earlier start yields the pre-activation prefix P = [2, 5]",
      r.prefix !== null && r.prefix.start === 2 && r.prefix.end === 5
      && r.universe.start === 6 && r.coverage.containsUniverse === true);
    const pfx = classifyRecordEpoch(3, r);
    ok("the prefix's epochs classify prefix-permitted, never extra",
      pfx.bucket === "prefix-permitted");
    ok("a prefix record inside the interval reports insideInterval true",
      pfx.insideInterval === true);
    ok("the universe start itself is in scope, not prefix",
      classifyRecordEpoch(6, r).bucket === "in-scope");
  }
  {
    // a TRUNCATED prefix: an explicit end below the pre-activation
    // boundary clips P at the interval end, never past it
    const r = await resolveInterval({ requestedStart: 2, requestedEnd: 4, configuredStart: 6,
      provedActivation: 6, fetchRange: ledgerFetch(20, true) });
    ok("the prefix clips at the interval end (P is I minus U, not [start, activation-1])",
      r.prefix !== null && r.prefix.start === 2 && r.prefix.end === 4);
  }
  {
    // the late-start empty case: PARTIAL BY SCOPE survives emptiness
    const r = await resolveInterval({ requestedStart: 30, requestedEnd: null, configuredStart: 30,
      provedActivation: 5, fetchRange: ledgerFetch(20, true) });
    ok("emptiness keeps the late-start coverage violation visible",
      r.emptyResult === true && r.coverage.lateConfiguredStart === true);
  }

  await rejectsInput("a proved activation above the proved deactivation refuses (incoherent lifecycle)",
    resolveInterval({ requestedStart: 5, requestedEnd: null, configuredStart: 5,
      provedActivation: 20, provedDeactivation: 10, fetchRange: ledgerFetch(30, true) }),
    /not a coherent lifecycle/);
  {
    const r = await resolveInterval({ requestedStart: 3, requestedEnd: null, configuredStart: 3,
      fetchRange: ledgerFetch(40, true), discoveryOpts: { width: 7 } });
    ok("a non-default discovery width still resolves the exact newest",
      r.interval.endEpoch === 40 && r.discovery.epochs.length === 38);
  }
  refusesInput("a BigInt start refuses as a STRUCTURED input refusal, never a bare TypeError",
    () => resolveStartSource({ journalBinding: null, localKey: null, explicitStartEpoch: 1n }),
    /not a u32/);

  {
    // an EMPTY interval has an empty permitted prefix: P is I minus U,
    // and an empty I contains nothing to permit (round-4 finding 5)
    const r = await resolveInterval({ requestedStart: 2, requestedEnd: null, configuredStart: 6,
      provedActivation: 6, fetchRange: ledgerFetch(0, true) });
    ok("an empty interval fabricates no prefix",
      r.emptyResult === true && r.prefix === null);
  }
  refusesInput("a null resolveStartSource input refuses structurally, not as a TypeError",
    () => resolveStartSource(null), /needs its input object/);
  await rejectsInput("a null resolveInterval input refuses structurally, not as a TypeError",
    resolveInterval(null), /needs its input object/);
  await rejectsInput("a configured start that IS the universe start refuses above the proved deactivation boundary",
    resolveInterval({ requestedStart: 2, requestedEnd: null, configuredStart: 6,
      provedDeactivation: 4, fetchRange: ledgerFetch(10, true) }),
    /not a coherent lifecycle/);
  refusesInput("a cyclic null-prototype start refuses with a structured message",
    () => {
      const v = Object.create(null); v.self = v;
      resolveStartSource({ journalBinding: null, localKey: null, explicitStartEpoch: v });
    }, /not a u32/);

  // ---- domain classification ----
  {
    const ctx = { universe: { start: 10, end: 20 }, interval: { startEpoch: 10, endEpoch: 15 }, prefix: null };
    const inScope = classifyRecordEpoch(12, ctx);
    ok("in universe and interval is in-scope", inScope.bucket === "in-scope");
    ok("an in-interval record reports insideInterval true (the failure-placement bit)",
      inScope.insideInterval === true);
    const ig = classifyRecordEpoch(18, ctx);
    ok("in universe but outside the interval is IGNORED after resolution",
      ig.bucket === "ignored" && ig.insideInterval === false);
    const ex = classifyRecordEpoch(25, ctx);
    ok("outside the validation domain is an EXTRA", ex.bucket === "extra");
    ok("an out-of-interval extra reports insideInterval false (its failure is pool-global)",
      ex.insideInterval === false);
    const exIn = classifyRecordEpoch(14, { universe: { start: 10, end: 13 },
      interval: { startEpoch: 10, endEpoch: 15 }, prefix: null });
    ok("an extra inside the interval range but outside U stays an extra", exIn.bucket === "extra");
    ok("an in-interval extra reports insideInterval true (its failure is per-epoch)",
      exIn.insideInterval === true);
  }

  // ---- the verdict-grade grammar, each precedence step ----
  {
    const a = labelsNow();
    const g = gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
      coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 30, recordsHeightMax: "900" }) });
    ok("today's label-now strengths grade PARTIAL BY EVIDENCE", g === "PARTIAL BY EVIDENCE");
  }
  {
    const a = labelsNow();
    a.recordSet = { evaluated: true, label: "REFUSED" };
    const g = gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
      coverage: { lateConfiguredStart: true, containsUniverse: false, narrowedRange: true },
      annotation: buildOpenEndedAnnotation({ endEpoch: null, recordsHeightMax: null }) });
    ok("a REFUSED aspect dominates every partial grade", g === "REFUSED-REPORT");
  }
  {
    const g = gradeVerdict({ branch: "open-ended", aspects: labelsNow(), inReportRefusal: true,
      coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 3, recordsHeightMax: "1" }) });
    ok("an in-report refusal alone is REFUSED-REPORT", g === "REFUSED-REPORT");
  }
  {
    const a = labelsNow();
    const g = gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
      coverage: { lateConfiguredStart: true, containsUniverse: true, narrowedRange: false },
      annotation: buildOpenEndedAnnotation({ endEpoch: null, recordsHeightMax: null }) });
    ok("a late configured start out-ranks the evidence step (never out-graded by emptiness)",
      g === "PARTIAL BY SCOPE");
  }
  {
    const g = gradeVerdict({ branch: "open-ended", aspects: labelsAtTerminal("open-ended"),
      inReportRefusal: false, coverage: cleanCoverage(),
      annotation: buildOpenEndedAnnotation({ endEpoch: null, recordsHeightMax: "12" }) });
    ok("a null annotation member alone is PARTIAL BY EVIDENCE (the empty result included)",
      g === "PARTIAL BY EVIDENCE");
  }
  {
    const g = gradeVerdict({ branch: "open-ended", aspects: labelsAtTerminal("open-ended"),
      inReportRefusal: false, coverage: cleanCoverage(),
      annotation: buildOpenEndedAnnotation({ endEpoch: 30, recordsHeightMax: null }) });
    ok("a null recordsHeightMax ALONE is PARTIAL BY EVIDENCE (each member is independently required)",
      g === "PARTIAL BY EVIDENCE");
  }
  {
    const g = gradeVerdict({ branch: "open-ended", aspects: labelsAtTerminal("open-ended"),
      inReportRefusal: false, coverage: cleanCoverage(),
      annotation: buildOpenEndedAnnotation({ endEpoch: 30, recordsHeightMax: "900" }) });
    ok("every evaluated aspect at terminal with a complete annotation is FULL-TO-DATE, the open ceiling",
      g === "FULL-TO-DATE");
  }
  {
    const g = gradeVerdict({ branch: "deactivation-bounded", aspects: labelsAtTerminal("deactivation-bounded"),
      inReportRefusal: false, coverage: cleanCoverage(), annotation: null });
    ok("the FULL grade exists only in the deactivation-bounded branch, every aspect at or above terminal", g === "FULL");
  }
  {
    const a = labelsAtTerminal("deactivation-bounded");
    a.balance = { evaluated: true, label: "PROVED-EVENTS" };
    const g = gradeVerdict({ branch: "deactivation-bounded", aspects: a,
      inReportRefusal: false, coverage: cleanCoverage(), annotation: null });
    ok("a label above terminal still satisfies the verdict (at-or-above, not exact)", g === "FULL");
  }
  throwsSync("an unevaluated aspect other than the deactivation boundary refuses",
    () => {
      const a = labelsAtTerminal("deactivation-bounded");
      a.ordering = { evaluated: false };
      gradeVerdict({ branch: "deactivation-bounded", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: null });
    }, /may not be unevaluated/);
  throwsSync("an unevaluated deactivation boundary in the BOUNDED branch refuses",
    () => gradeVerdict({ branch: "deactivation-bounded", aspects: labelsAtTerminal("open-ended"),
      inReportRefusal: false, coverage: cleanCoverage(), annotation: null }),
    /may not be unevaluated/);
  throwsSync("an unknown aspect key refuses (the aspect set is closed)",
    () => {
      const a = labelsAtTerminal("open-ended");
      a.cadence = { evaluated: true, label: "PROVED" };
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "1" }) });
    }, /unknown aspect keys/);
  throwsSync("the open-ended branch without its annotation refuses",
    () => gradeVerdict({ branch: "open-ended", aspects: labelsAtTerminal("open-ended"),
      inReportRefusal: false, coverage: cleanCoverage(), annotation: null }),
    /requires the annotation/);
  throwsSync("the bounded branch with an annotation refuses",
    () => gradeVerdict({ branch: "deactivation-bounded", aspects: labelsAtTerminal("deactivation-bounded"),
      inReportRefusal: false, coverage: cleanCoverage(),
      annotation: buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "1" }) }),
    /no open-ended annotation/);
  throwsSync("an unevaluated row carrying a label refuses (it would ride into the report unvalidated)",
    () => {
      const a = labelsAtTerminal("open-ended");
      a.deactivationBoundary = { evaluated: false, label: "REFUSED" };
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "1" }) });
    }, /carries no label/);
  throwsSync("an unknown branch name refuses",
    () => gradeVerdict({ branch: "closed", aspects: labelsAtTerminal("open-ended"),
      inReportRefusal: false, coverage: cleanCoverage(),
      annotation: buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "1" }) }),
    /not a branch/);
  throwsSync("a missing aspect row refuses",
    () => {
      const a = labelsAtTerminal("open-ended");
      delete a.ordering;
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "1" }) });
    }, /missing or has no evaluated flag/);
  throwsSync("an aspect row with an unknown member refuses (the row shape is closed)",
    () => {
      const a = labelsAtTerminal("open-ended");
      a.ordering = { evaluated: true, label: "PROVED", perReceipt: [] };
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "1" }) });
    }, /shape is closed/);
  throwsSync("a label above an aspect's strongest defined form refuses (no route earns it)",
    () => {
      const a = labelsAtTerminal("open-ended");
      a.transferExecution = { evaluated: true, label: "PROVED" };
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "1" }) });
    }, /strongest defined form is CAPTURE-VERIFIED/);
  throwsSync("PROVED-EVENTS on a non-transfer, non-balance row refuses (ceilings hold everywhere)",
    () => {
      const a = labelsAtTerminal("open-ended");
      a.universe = { evaluated: true, label: "PROVED-EVENTS" };
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "1" }) });
    }, /strongest defined form is PROVED/);
  throwsSync("PROVED-EVENTS outside the balance row refuses",
    () => {
      const a = labelsAtTerminal("open-ended");
      a.ordering = { evaluated: true, label: "PROVED-EVENTS" };
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "1" }) });
    }, /strongest defined form is PROVED/);
  throwsSync("a self-replacing evaluated getter refuses at the descriptor stage, before any read",
    () => {
      const a = labelsAtTerminal("open-ended");
      const row = {};
      Object.defineProperty(row, "evaluated", { enumerable: true, configurable: true,
        get() { Object.defineProperty(row, "evaluated", { value: true, enumerable: true });
          row.label = "PROVED"; return true; } });
      a.ordering = row;
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "1" }) });
    }, /plain enumerable data property/);
  throwsSync("an evaluated aspect with an out-of-vocabulary label refuses",
    () => {
      const a = labelsAtTerminal("open-ended");
      a.ordering = { evaluated: true, label: "VERIFIED" };
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "1" }) });
    }, /closed label vocabulary/);

  // ---- the annotation grammar ----
  {
    const a = buildOpenEndedAnnotation({ endEpoch: null, recordsHeightMax: null });
    ok("the annotation carries explicit nulls", a.endEpoch === null && a.recordsHeightMax === null
      && Object.isFrozen(a));
  }
  throwsSync("a non-canonical recordsHeightMax refuses",
    () => buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "007" }), /canonical decimal/);
  throwsSync("a fractional annotation endEpoch refuses",
    () => buildOpenEndedAnnotation({ endEpoch: 1.5, recordsHeightMax: null }), /u32 epoch index/);
  throwsSync("an UNDEFINED annotation member refuses at gradeVerdict (undefined is not an explicit null)",
    () => gradeVerdict({ branch: "open-ended", aspects: labelsAtTerminal("open-ended"),
      inReportRefusal: false, coverage: cleanCoverage(),
      annotation: { endEpoch: 3, recordsHeightMax: undefined } }),
    /canonical decimal string or an explicit null/);
  throwsSync("an annotation with an unknown member refuses (its shape is the closed literal)",
    () => gradeVerdict({ branch: "open-ended", aspects: labelsAtTerminal("open-ended"),
      inReportRefusal: false, coverage: cleanCoverage(),
      annotation: { endEpoch: 3, recordsHeightMax: "1", note: "x" } }),
    /unknown members/);

  // ---- object-mechanics closure and branch-evidence coherence (round 3) ----
  throwsSync("an EVALUATED deactivation aspect in the open-ended branch refuses (branch coherence)",
    () => {
      const a = labelsAtTerminal("open-ended");
      a.deactivationBoundary = { evaluated: true, label: "PROVED" };
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 3, recordsHeightMax: "1" }) });
    }, /NOT EVALUATED in the open-ended branch/);
  {
    const a = labelsNow();
    a.contractIntegrity = { evaluated: true, label: "REFUSED" };
    const g = gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
      coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 3, recordsHeightMax: "1" }) });
    ok("a REFUSED contract-integrity aspect refuses the report like any row", g === "REFUSED-REPORT");
  }
  throwsSync("an aspect map inheriting its rows from a prototype refuses",
    () => gradeVerdict({ branch: "open-ended", aspects: Object.create(labelsAtTerminal("open-ended")),
      inReportRefusal: false, coverage: cleanCoverage(),
      annotation: buildOpenEndedAnnotation({ endEpoch: 3, recordsHeightMax: "1" }) }),
    /plain object|missing/);
  throwsSync("an annotation inheriting its members refuses (own members only)",
    () => gradeVerdict({ branch: "open-ended", aspects: labelsAtTerminal("open-ended"),
      inReportRefusal: false, coverage: cleanCoverage(),
      annotation: Object.create({ endEpoch: 3, recordsHeightMax: "1" }) }),
    /plain object|OWN member/);
  throwsSync("a NON-ENUMERABLE undeclared aspect-row member refuses",
    () => {
      const a = labelsAtTerminal("open-ended");
      a.ordering = { evaluated: true, label: "PROVED" };
      Object.defineProperty(a.ordering, "undeclared", { value: 1, enumerable: false });
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 3, recordsHeightMax: "1" }) });
    }, /shape is closed/);
  throwsSync("a symbol-keyed aspect-map member refuses",
    () => {
      const a = labelsAtTerminal("open-ended");
      a[Symbol("x")] = 1;
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 3, recordsHeightMax: "1" }) });
    }, /symbol-keyed/);
  throwsSync("a symbol-keyed annotation member refuses (the sub-shape closure covers symbols)",
    () => {
      const a = { endEpoch: 3, recordsHeightMax: "1" };
      a[Symbol("x")] = 1;
      gradeVerdict({ branch: "open-ended", aspects: labelsAtTerminal("open-ended"),
        inReportRefusal: false, coverage: cleanCoverage(), annotation: a });
    }, /symbol-keyed/);
  throwsSync("a non-string aspect note refuses (report values are plain strings)",
    () => {
      const a = labelsAtTerminal("open-ended");
      a.ordering = { evaluated: true, label: "PROVED", note: { deep: {} } };
      gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
        coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 3, recordsHeightMax: "1" }) });
    }, /nonempty string/);
  {
    // an inherited Object.prototype member is the one route past a
    // plain-prototype check: the map's own prototype IS Object.prototype,
    // so the proto test passes and only the per-member OWN checks stand
    // between the inherited value and a fabricated aspect row or
    // annotation member
    Object.prototype.universe = { evaluated: true, label: "PROVED" };
    try {
      const a = labelsAtTerminal("open-ended");
      delete a.universe;
      throwsSync("an inherited Object.prototype member cannot supply a missing aspect row",
        () => gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
          coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 3, recordsHeightMax: "1" }) }),
        /missing or has no evaluated flag/);
    } finally { delete Object.prototype.universe; }
    Object.prototype.endEpoch = 3;
    try {
      throwsSync("an inherited Object.prototype member cannot supply a missing annotation member",
        () => gradeVerdict({ branch: "open-ended", aspects: labelsAtTerminal("open-ended"),
          inReportRefusal: false, coverage: cleanCoverage(),
          annotation: { recordsHeightMax: "1" } }),
        /OWN member/);
    } finally { delete Object.prototype.endEpoch; }
  }
  ok("the noncanonical decimal \"00\" refuses beside \"007\"",
    (() => { try { buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: "00" }); return false; }
      catch (e) { return /canonical decimal/.test(e.message); } })());

  // ---- the report schema ----
  const poolId = "ab".repeat(32);
  const reportInput = () => ({
    poolId, contractId: "8oS5nqe1JbGm1RXWmZK1eTLbzHU3d9ikMzXKZ9G9Z7C5",
    expectedChainId: "tegara-harness-1",
    startSource: "journal", configuredStart: 5, branch: "open-ended",
    interval: { startEpoch: 5, endEpoch: 30 },
    annotation: buildOpenEndedAnnotation({ endEpoch: 30, recordsHeightMax: "900" }),
    coverage: cleanCoverage(),
    aspects: (() => {
      const a = labelsNow();
      a.activationBoundary = { evaluated: true, label: "OPERATOR-PROVIDED", source: "journal" };
      return a;
    })(),
    epochs: [{ epochIndex: 5, condition: null, r: "1", diagnostics: [] },
      { epochIndex: 6, condition: "zero-earning-epoch", r: "0", diagnostics: [] }],
    lag: { lagCount: 1, undistributedCredits: "540000" },
    heightRanges: { records: { min: "880", max: "912" }, universe: null, balance: null },
    diagnostics: { extras: [], orphans: [], poolGlobal: [] },
    refusals: [],
  });
  {
    const rep = buildReport(reportInput());
    ok("the report carries the closed kind, the supplied identifiers and the verdict",
      rep.kind === REPORT_KIND && rep.v === 1 && rep.contractVersion === "v11"
      && rep.contractId.length > 0 && rep.verdict === "PARTIAL BY EVIDENCE");
    ok("the expectedChainId member is present with the supplied value",
      rep.expectedChainId === "tegara-harness-1");
    ok("the resolved start source is named in the report",
      rep.startSource === "journal" && rep.configuredStart === 5);
    ok("one non-null height range makes overlap NOT APPLICABLE",
      rep.heightRanges.overlap === "not-applicable" && rep.heightRanges.universe === null);
    ok("the per-epoch rows carry the remainder r and the condition tokens",
      rep.epochs[0].r === "1" && rep.epochs[1].condition === "zero-earning-epoch");
    ok("the report is frozen", Object.isFrozen(rep));
    const memberSet = Object.keys(rep).sort().join(",");
    ok("the member set is closed and exact",
      memberSet === ["v", "kind", "poolId", "contractVersion", "contractId", "expectedChainId",
        "startSource", "configuredStart", "branch", "interval", "openEnded", "coverage",
        "aspects", "epochs", "lag", "heightRanges", "diagnostics", "refusals", "verdict"].sort().join(","));
  }
  {
    // the verdict is COMPUTED, never supplied: an attempted override is
    // inert whatever its value
    const inp = reportInput();
    inp.verdict = "FULL";
    ok("a supplied FULL verdict member is ignored and the grammar's verdict stands",
      buildReport(inp).verdict === "PARTIAL BY EVIDENCE");
    const inp2 = reportInput();
    inp2.verdict = "REFUSED-REPORT";
    ok("a supplied refusing verdict member is equally inert",
      buildReport(inp2).verdict === "PARTIAL BY EVIDENCE");
    const inp3 = reportInput();
    inp3.verdict = "PARTIAL BY SCOPE";
    ok("a third supplied verdict value is inert too (no value is honored)",
      buildReport(inp3).verdict === "PARTIAL BY EVIDENCE");
  }
  {
    const rep = buildReport(reportInput());
    ok("the supplied contract identifier is copied exactly, not merely present",
      rep.contractId === "8oS5nqe1JbGm1RXWmZK1eTLbzHU3d9ikMzXKZ9G9Z7C5");
    ok("the report is frozen to its leaves (aspects, interval, epochs, ranges)",
      Object.isFrozen(rep.aspects) && Object.isFrozen(rep.aspects.ordering)
      && Object.isFrozen(rep.interval) && Object.isFrozen(rep.epochs)
      && Object.isFrozen(rep.epochs[0]) && Object.isFrozen(rep.heightRanges)
      && Object.isFrozen(rep.coverage) && Object.isFrozen(rep.diagnostics));
  }
  {
    const inp = reportInput();
    inp.refusals = ["a prefix epoch failed its zero-earning verification"];
    ok("an in-report refusal grades the report REFUSED-REPORT",
      buildReport(inp).verdict === "REFUSED-REPORT");
    const inp2 = reportInput();
    inp2.refusals = ["a record resolved outside the validation domain"];
    ok("any nonempty refusal string refuses, not one recognized message",
      buildReport(inp2).verdict === "REFUSED-REPORT");
  }
  throwsSync("an empty refusal string refuses the report shape",
    () => buildReport({ ...reportInput(), refusals: [""] }), /nonempty strings/);
  throwsSync("a SPARSE refusal array refuses (holes are examined, not skipped)",
    () => buildReport({ ...reportInput(), refusals: Array(1) }), /own enumerable data element/);
  throwsSync("a sparse diagnostics array refuses",
    () => buildReport({ ...reportInput(),
      diagnostics: { extras: Array(1), orphans: [], poolGlobal: [] } }), /own enumerable data element/);
  throwsSync("a sparse per-epoch diagnostics array refuses",
    () => buildReport({ ...reportInput(),
      epochs: [{ epochIndex: 5, condition: null, r: null, diagnostics: Array(1) }] }), /own enumerable data element/);
  throwsSync("an annotation endEpoch disagreeing with the interval refuses",
    () => buildReport({ ...reportInput(),
      annotation: buildOpenEndedAnnotation({ endEpoch: 29, recordsHeightMax: "900" }) }),
    /disagrees with the interval/);
  throwsSync("a numeric per-epoch r is refused (canonical decimal STRINGS only)",
    () => buildReport({ ...reportInput(),
      epochs: [{ epochIndex: 5, condition: null, r: 1, diagnostics: [] }] }), /per-epoch row/);
  throwsSync("a numeric undistributedCredits is refused",
    () => buildReport({ ...reportInput(), lag: { lagCount: 1, undistributedCredits: 540000 } }), /lag member/);
  throwsSync("a numeric annotation recordsHeightMax is refused",
    () => buildOpenEndedAnnotation({ endEpoch: 1, recordsHeightMax: 900 }), /canonical decimal/);
  throwsSync("an over-u32 interval end refuses",
    () => buildReport({ ...reportInput(), interval: { startEpoch: 5, endEpoch: 4294967296 } }),
    /not a u32/);
  throwsSync("an over-u32 per-epoch index refuses",
    () => buildReport({ ...reportInput(),
      epochs: [{ epochIndex: 4294967296, condition: null, r: null, diagnostics: [] }] }), /not a u32/);
  // the sub-shapes are closed too: an undeclared member anywhere refuses
  throwsSync("a per-epoch row with an undeclared member refuses",
    () => buildReport({ ...reportInput(),
      epochs: [{ epochIndex: 5, condition: null, r: null, diagnostics: [], undeclared: true }] }),
    /shape is closed/);
  throwsSync("a lag object with an undeclared member refuses",
    () => buildReport({ ...reportInput(),
      lag: { lagCount: 0, undistributedCredits: "0", undeclared: true } }), /shape is closed/);
  throwsSync("a coverage object with an undeclared member refuses",
    () => buildReport({ ...reportInput(),
      coverage: { ...cleanCoverage(), undeclared: true } }), /shape is closed/);
  throwsSync("a height range with an undeclared member refuses",
    () => buildReport({ ...reportInput(),
      heightRanges: { records: { min: "1", max: "2", undeclared: true }, universe: null, balance: null } }),
    /shape is closed/);
  throwsSync("an annotation with an undeclared member refuses at the report too",
    () => buildReport({ ...reportInput(),
      annotation: { endEpoch: 30, recordsHeightMax: "900", undeclared: true } }), /unknown members/);
  throwsSync("a diagnostics object with an undeclared member refuses",
    () => buildReport({ ...reportInput(),
      diagnostics: { extras: [], orphans: [], poolGlobal: [], undeclared: true } }), /shape is closed/);
  throwsSync("a reversed report interval refuses at the assembler, not only the resolver",
    () => buildReport({ ...reportInput(), interval: { startEpoch: 30, endEpoch: 5 },
      annotation: buildOpenEndedAnnotation({ endEpoch: 5, recordsHeightMax: "900" }) }),
    /is reversed/);
  throwsSync("a BOUNDED report with a null interval end refuses (the boundary bounds it)",
    () => buildReport({ ...reportInput(), branch: "deactivation-bounded",
      interval: { startEpoch: 5, endEpoch: null }, annotation: null,
      aspects: labelsAtTerminal("deactivation-bounded") }),
    /requires a non-null interval end/);
  throwsSync("a coercible poolId object refuses (string type before the pattern)",
    () => buildReport({ ...reportInput(), poolId: { toString: () => "ab".repeat(32) } }),
    /64-hex identifier/);
  throwsSync("a BigInt inside a diagnostics array refuses (report values are plain strings)",
    () => buildReport({ ...reportInput(),
      diagnostics: { extras: [1n], orphans: [], poolGlobal: [] } }),
    /nonempty strings/);
  throwsSync("an inherited height-range member refuses (own members only)",
    () => buildReport({ ...reportInput(),
      heightRanges: { records: Object.create({ min: "1", max: "2" }), universe: null, balance: null } }),
    /plain object/);
  throwsSync("an activation row whose source disagrees with the report's refuses",
    () => {
      const inp = reportInput();
      inp.aspects.activationBoundary = { evaluated: true, label: "OPERATOR-PROVIDED", source: "explicit-input" };
      buildReport(inp);
    }, /must name the resolved start source/);
  throwsSync("an activation row with NO source member refuses at the assembler",
    () => {
      const inp = reportInput();
      inp.aspects.activationBoundary = { evaluated: true, label: "OPERATOR-PROVIDED" };
      buildReport(inp);
    }, /must name the resolved start source/);
  ok("the built report's activation row names the resolved source",
    buildReport(reportInput()).aspects.activationBoundary.source === "journal");
  throwsSync("the source binding holds at every label, not only OPERATOR-PROVIDED (missing at PROVED)",
    () => {
      const inp = reportInput();
      inp.aspects.activationBoundary = { evaluated: true, label: "PROVED" };
      buildReport(inp);
    }, /must name the resolved start source/);
  throwsSync("the source binding holds at every label (disagreeing at PROVED)",
    () => {
      const inp = reportInput();
      inp.startSource = "explicit-input";
      inp.aspects.activationBoundary = { evaluated: true, label: "PROVED", source: "journal" };
      buildReport(inp);
    }, /must name the resolved start source/);
  {
    // input OWNERSHIP: freezing the report must never freeze the caller's
    // annotation or range objects (they are copied, not captured)
    const ann = { endEpoch: 30, recordsHeightMax: "900" };
    const rec = { min: "880", max: "912" };
    const inp = reportInput();
    inp.annotation = ann;
    inp.heightRanges = { records: rec, universe: null, balance: null };
    const rep = buildReport(inp);
    ok("the caller's annotation and range inputs stay unfrozen (the report owns copies)",
      !Object.isFrozen(ann) && !Object.isFrozen(rec)
      && Object.isFrozen(rep.openEnded) && Object.isFrozen(rep.heightRanges.records)
      && rep.openEnded.endEpoch === 30 && rep.heightRanges.records.max === "912");
    ann.endEpoch = 31;
    ok("mutating the caller's annotation after assembly does not reach the report",
      rep.openEnded.endEpoch === 30);
  }
  throwsSync("a NON-ENUMERABLE required member refuses (it would vanish on copy after validating)",
    () => {
      const inp = reportInput();
      const lag = { undistributedCredits: "0" };
      Object.defineProperty(lag, "lagCount", { value: 0, enumerable: false });
      buildReport({ ...inp, lag });
    }, /plain enumerable data property/);
  throwsSync("an accessor member refuses (a getter would let the report drift after assembly)",
    () => {
      const inp = reportInput();
      const ann = { recordsHeightMax: "900" };
      Object.defineProperty(ann, "endEpoch", { get: () => 30, enumerable: true });
      buildReport({ ...inp, annotation: ann });
    }, /plain enumerable data property/);
  throwsSync("an empty-string per-epoch condition refuses (a token is nonempty)",
    () => buildReport({ ...reportInput(),
      epochs: [{ epochIndex: 5, condition: "", r: null, diagnostics: [] }] }), /per-epoch row/);
  {
    const inp = reportInput();
    inp.heightRanges = { records: { min: "880", max: "912" },
      universe: { min: "900", max: "950" }, balance: { min: "905", max: "910" } };
    ok("three overlapping non-null ranges report overlaps true",
      buildReport(inp).heightRanges.overlap.overlaps === true);
    inp.heightRanges = { records: { min: "880", max: "912" },
      universe: { min: "900", max: "950" }, balance: { min: "960", max: "970" } };
    ok("three ranges with one disjoint member report overlaps false",
      buildReport(inp).heightRanges.overlap.overlaps === false);
  }
  {
    const inp = reportInput();
    inp.heightRanges = { records: { min: "880", max: "912" }, universe: { min: "900", max: "950" }, balance: null };
    ok("two overlapping non-null ranges report overlaps true",
      buildReport(inp).heightRanges.overlap.overlaps === true);
    inp.heightRanges = { records: { min: "880", max: "912" }, universe: { min: "913", max: "950" }, balance: null };
    ok("two disjoint non-null ranges report overlaps false",
      buildReport(inp).heightRanges.overlap.overlaps === false);
    inp.heightRanges = { records: { min: "880", max: "912" }, universe: { min: "912", max: "950" }, balance: null };
    ok("two inclusive ranges sharing exactly one height overlap",
      buildReport(inp).heightRanges.overlap.overlaps === true);
  }
  throwsSync("an empty expectedChainId refuses the report",
    () => buildReport({ ...reportInput(), expectedChainId: "" }), /expected chain identifier/);
  throwsSync("a missing contract pin refuses the report",
    () => buildReport({ ...reportInput(), contractId: "" }), /CONTRACT_V11_ID/);
  throwsSync("a malformed per-epoch row refuses",
    () => buildReport({ ...reportInput(), epochs: [{ epochIndex: 5, condition: null, r: "07", diagnostics: [] }] }),
    /per-epoch row/);
  throwsSync("a malformed lag member refuses",
    () => buildReport({ ...reportInput(), lag: { lagCount: -1, undistributedCredits: "0" } }), /lag member/);
  throwsSync("a reversed height range refuses",
    () => buildReport({ ...reportInput(), heightRanges: { records: { min: "10", max: "9" }, universe: null, balance: null } }),
    /height ranges/);

  {
    const res = await resolveInterval({ requestedStart: 5, requestedEnd: null, configuredStart: 5,
      fetchRange: ledgerFetch(30, true) });
    const a = labelsNow();
    a.activationBoundary = { evaluated: true, label: "OPERATOR-PROVIDED", source: "journal" };
    const rep = buildReport({
      poolId, contractId: "8oS5nqe1JbGm1RXWmZK1eTLbzHU3d9ikMzXKZ9G9Z7C5",
      expectedChainId: "tegara-harness-1", startSource: "journal", configuredStart: 5,
      branch: res.branch, interval: res.interval,
      annotation: buildOpenEndedAnnotation({ endEpoch: res.interval.endEpoch, recordsHeightMax: null }),
      coverage: res.coverage, aspects: a, epochs: [],
      lag: null, heightRanges: { records: null, universe: null, balance: null },
      diagnostics: { extras: [], orphans: [], poolGlobal: [] }, refusals: [],
    });
    ok("a resolver result wires into the assembler directly (the second-half entry's shape)",
      rep.branch === "open-ended" && rep.interval.endEpoch === 30
      && rep.openEnded.endEpoch === 30 && rep.verdict === "PARTIAL BY EVIDENCE");
  }

  // ---- round-trip fidelity: the returned report IS the validated input ----
  {
    // fixture one, open-ended: every member and nested member compared
    // against a hand-built expected literal, so no output branch can be
    // replaced behind the verdict (round-6 finding 3)
    const rep = buildReport(reportInput());
    const expected = {
      v: 1, kind: "tegara.e2.auditReport.v1", poolId,
      contractVersion: "v11", contractId: "8oS5nqe1JbGm1RXWmZK1eTLbzHU3d9ikMzXKZ9G9Z7C5",
      expectedChainId: "tegara-harness-1", startSource: "journal", configuredStart: 5,
      branch: "open-ended", interval: { startEpoch: 5, endEpoch: 30 },
      openEnded: { endEpoch: 30, recordsHeightMax: "900" },
      coverage: { lateConfiguredStart: false, containsUniverse: true, narrowedRange: false },
      aspects: {
        universe: { evaluated: true, label: "UNPROVED" },
        activationBoundary: { evaluated: true, label: "OPERATOR-PROVIDED", source: "journal" },
        deactivationBoundary: { evaluated: false },
        binding: { evaluated: true, label: "UNVERIFIABLE" },
        transferExecution: { evaluated: true, examinedCount: 1, label: "CAPTURE-VERIFIED" },
        reservationPresence: { evaluated: true, examinedCount: 1, label: "PROVED" },
        temporalOrder: { evaluated: true, label: "UNVERIFIABLE" },
        ordering: { evaluated: true, examinedCount: 1, label: "ATTESTED" },
        formationInputs: { evaluated: true, label: "PROVED" },
        recordSet: { evaluated: true, label: "READ-CHECKED" },
        shareConformance: { evaluated: true, label: "UNVERIFIABLE" },
        balance: { evaluated: true, label: "UNVERIFIABLE" },
        contractIntegrity: { evaluated: true, label: "PROVED" },
      },
      epochs: [{ epochIndex: 5, condition: null, r: "1", diagnostics: [] },
        { epochIndex: 6, condition: "zero-earning-epoch", r: "0", diagnostics: [] }],
      lag: { lagCount: 1, undistributedCredits: "540000" },
      heightRanges: { records: { min: "880", max: "912" }, universe: null, balance: null,
        overlap: "not-applicable" },
      diagnostics: { extras: [], orphans: [], poolGlobal: [] },
      refusals: [],
      verdict: "PARTIAL BY EVIDENCE",
    };
    ok("fixture one round-trips member for member",
      JSON.stringify(rep) === JSON.stringify(expected));
  }
  {
    // fixture two, bounded FULL with populated lag, ranges, diagnostics
    // and refusal-free epochs, deep-compared the same way
    const a = labelsAtTerminal("deactivation-bounded");
    a.activationBoundary = { evaluated: true, label: "PROVED", source: "explicit-input" };
    const rep = buildReport({
      poolId, contractId: "8oS5nqe1JbGm1RXWmZK1eTLbzHU3d9ikMzXKZ9G9Z7C5",
      expectedChainId: "tegara-harness-1", startSource: "explicit-input", configuredStart: 2,
      branch: "deactivation-bounded", interval: { startEpoch: 2, endEpoch: 4 }, annotation: null,
      coverage: { lateConfiguredStart: false, containsUniverse: true, narrowedRange: false },
      aspects: a,
      epochs: [{ epochIndex: 2, condition: null, r: "0", diagnostics: ["one note"] }],
      lag: { lagCount: 0, undistributedCredits: "0" },
      heightRanges: { records: { min: "10", max: "20" }, universe: { min: "15", max: "25" },
        balance: { min: "18", max: "19" } },
      diagnostics: { extras: ["an extra"], orphans: [], poolGlobal: [] },
      refusals: [],
    });
    const expected = {
      v: 1, kind: "tegara.e2.auditReport.v1", poolId,
      contractVersion: "v11", contractId: "8oS5nqe1JbGm1RXWmZK1eTLbzHU3d9ikMzXKZ9G9Z7C5",
      expectedChainId: "tegara-harness-1", startSource: "explicit-input", configuredStart: 2,
      branch: "deactivation-bounded", interval: { startEpoch: 2, endEpoch: 4 },
      openEnded: null,
      coverage: { lateConfiguredStart: false, containsUniverse: true, narrowedRange: false },
      aspects: {
        universe: { evaluated: true, label: "PROVED" },
        activationBoundary: { evaluated: true, label: "PROVED", source: "explicit-input" },
        deactivationBoundary: { evaluated: true, label: "PROVED" },
        binding: { evaluated: true, label: "PROVED" },
        transferExecution: { evaluated: true, examinedCount: 1, label: "CAPTURE-VERIFIED" },
        reservationPresence: { evaluated: true, examinedCount: 1, label: "PROVED" },
        temporalOrder: { evaluated: true, label: "PROVED" },
        ordering: { evaluated: true, examinedCount: 1, label: "PROVED" },
        formationInputs: { evaluated: true, label: "PROVED" },
        recordSet: { evaluated: true, label: "PROVED" },
        shareConformance: { evaluated: true, label: "PROVED" },
        balance: { evaluated: true, label: "PROVED-NET" },
        contractIntegrity: { evaluated: true, label: "PROVED" },
      },
      epochs: [{ epochIndex: 2, condition: null, r: "0", diagnostics: ["one note"] }],
      lag: { lagCount: 0, undistributedCredits: "0" },
      heightRanges: { records: { min: "10", max: "20" }, universe: { min: "15", max: "25" },
        balance: { min: "18", max: "19" }, overlap: { overlaps: true } },
      diagnostics: { extras: ["an extra"], orphans: [], poolGlobal: [] },
      refusals: [],
      verdict: "FULL",
    };
    ok("fixture two (bounded FULL) round-trips member for member",
      JSON.stringify(rep) === JSON.stringify(expected));
    // the verdict recomputed from the RETURNED members equals the emitted one
    const returnedAspects = Object.fromEntries(Object.entries(rep.aspects)
      .map(([k, v]) => [k, { ...v }]));
    const recomputed = gradeVerdict({ branch: rep.branch, aspects: returnedAspects,
      inReportRefusal: rep.refusals.length > 0, coverage: { ...rep.coverage },
      annotation: rep.branch === "open-ended" ? rep.openEnded : null });
    ok("the emitted verdict recomputes from the returned members", recomputed === rep.verdict);
  }
  {
    // the inherited-value and accessor routes through arrays and rows
    Object.prototype.label = "PROVED";
    try {
      const a = labelsAtTerminal("open-ended");
      a.ordering = { evaluated: true };
      throwsSync("an evaluated row cannot take its label from Object.prototype",
        () => gradeVerdict({ branch: "open-ended", aspects: a, inReportRefusal: false,
          coverage: cleanCoverage(), annotation: buildOpenEndedAnnotation({ endEpoch: 3, recordsHeightMax: "1" }) }),
        /OWN label/);
    } finally { delete Object.prototype.label; }
    Object.prototype.source = "journal";
    try {
      throwsSync("the activation row cannot take its source from Object.prototype",
        () => {
          const inp = reportInput();
          inp.aspects.activationBoundary = { evaluated: true, label: "OPERATOR-PROVIDED" };
          buildReport(inp);
        }, /OWN data member/);
    } finally { delete Object.prototype.source; }
    Array.prototype[0] = "inherited";
    try {
      throwsSync("a sparse array cannot take an element from Array.prototype",
        () => buildReport({ ...reportInput(), refusals: Array(1) }),
        /own enumerable data element/);
    } finally { delete Array.prototype[0]; }
    throwsSync("a getter-backed array index refuses (the snapshot is what enters the report)",
      () => {
        const arr = [];
        Object.defineProperty(arr, 0, { get: () => "valid", enumerable: true });
        arr.length = 1;
        buildReport({ ...reportInput(), refusals: arr });
      }, /own enumerable data element/);
  }

  {
    const a = labelsNow();
    a.activationBoundary = { evaluated: true, label: "OPERATOR-PROVIDED", source: "journal" };
    a.ordering = { evaluated: true, examinedCount: 1, label: "ATTESTED", note: "one receipt below attestation" };
    const rep = buildReport({
      poolId, contractId: "8oS5nqe1JbGm1RXWmZK1eTLbzHU3d9ikMzXKZ9G9Z7C5",
      expectedChainId: "tegara-harness-1", startSource: "journal", configuredStart: 5,
      branch: "open-ended", interval: { startEpoch: 5, endEpoch: 30 },
      annotation: buildOpenEndedAnnotation({ endEpoch: 30, recordsHeightMax: null }),
      coverage: { lateConfiguredStart: false, containsUniverse: false, narrowedRange: true },
      aspects: a, epochs: [],
      lag: null, heightRanges: { records: null, universe: null, balance: null },
      diagnostics: { extras: [], orphans: ["an orphan part"], poolGlobal: ["a pool-global failure"] },
      refusals: ["a record resolved outside the validation domain"],
    });
    ok("fixture three keeps its refusal evidence, diagnostics, note and coverage members",
      rep.verdict === "REFUSED-REPORT"
      && rep.refusals.length === 1
      && rep.refusals[0] === "a record resolved outside the validation domain"
      && rep.diagnostics.orphans[0] === "an orphan part"
      && rep.diagnostics.poolGlobal[0] === "a pool-global failure"
      && rep.aspects.ordering.note === "one receipt below attestation"
      && rep.coverage.containsUniverse === false && rep.coverage.narrowedRange === true);
  }
  {
    // a PLAIN unfrozen annotation object still yields a frozen report
    const inp = reportInput();
    inp.annotation = { endEpoch: 30, recordsHeightMax: "900" };
    const rep = buildReport(inp);
    ok("an unfrozen annotation input leaves the emitted openEnded frozen",
      Object.isFrozen(rep.openEnded) && rep.openEnded.endEpoch === 30);
  }
  throwsSync("a self-replacing MAP getter for the activation row refuses (the row is fetched by descriptor)",
    () => {
      const inp = reportInput();
      const goodRow = { evaluated: true, label: "OPERATOR-PROVIDED", source: "journal" };
      const badRow = { evaluated: true, label: "OPERATOR-PROVIDED", source: "explicit-input" };
      const map = inp.aspects;
      delete map.activationBoundary;
      Object.defineProperty(map, "activationBoundary", { enumerable: true, configurable: true,
        get() { Object.defineProperty(map, "activationBoundary", { value: badRow, enumerable: true });
          return goodRow; } });
      buildReport(inp);
    }, /OWN data member|plain enumerable data property/);
  {
    let sourceReads = 0;
    const inp = reportInput();
    const row = { evaluated: true, label: "OPERATOR-PROVIDED" };
    Object.defineProperty(row, "source", { enumerable: true, configurable: true,
      get() { sourceReads++;
        Object.defineProperty(row, "source", { value: "explicit-input", enumerable: true });
        return "journal"; } });
    inp.aspects.activationBoundary = row;
    throwsSync("a self-replacing source getter refuses at the descriptor read (no value is served once)",
      () => buildReport(inp), /OWN data member/);
    ok("the source getter was never invoked", sourceReads === 0);
  }
  {
    // the recursive frozen walk: EVERY object reached from the report is
    // frozen, not a chosen subset
    const rep = buildReport(reportInput());
    const walk = (o, seen = new Set()) => {
      if (!o || typeof o !== "object" || seen.has(o)) return true;
      seen.add(o);
      const proto = Object.getPrototypeOf(o);
      const plainProto = proto === Object.prototype || proto === Array.prototype || proto === null;
      // every own key at every level is an enumerable data property (an
      // array's own length member is the one structural exception)
      const cleanKeys = Reflect.ownKeys(o).every((k) => {
        if (Array.isArray(o) && k === "length") return true;
        const d = Object.getOwnPropertyDescriptor(o, k);
        return typeof k === "string" && d.enumerable && "value" in d;
      });
      return Object.isFrozen(o) && plainProto && cleanKeys
        && Reflect.ownKeys(o).every((k) => (Array.isArray(o) && k === "length") || walk(o[k], seen));
    };
    ok("every object reachable through ANY own key is frozen with a plain prototype",
      walk(rep));
    ok("the report carries no symbol-keyed or hidden members at the top level",
      Reflect.ownKeys(rep).length === Object.keys(rep).length);
  }
  {
    // an inherited numeric note must be IGNORED, not validated: own-member
    // reads keep ambient prototype state out of validation entirely
    Object.prototype.note = 5;
    try {
      const g = gradeVerdict({ branch: "open-ended", aspects: labelsAtTerminal("open-ended"),
        inReportRefusal: false, coverage: cleanCoverage(),
        annotation: buildOpenEndedAnnotation({ endEpoch: 3, recordsHeightMax: "1" }) });
      ok("an inherited non-string note is ignored by own-member validation", g === "FULL-TO-DATE");
    } finally { delete Object.prototype.note; }
  }
  throwsSync("a sparse per-epoch row ARRAY refuses (the row itself must be an own element)",
    () => buildReport({ ...reportInput(), epochs: Array(1) }), /own enumerable data element/);
  // the descriptor rule has THREE sub-conditions and Array(1) exercises only
  // the hole (round-64, after an accessor and a non-enumerable element both
  // slipped a weakened rule): an ACCESSOR-backed row would re-run its getter
  // on each read, and a NON-ENUMERABLE row would vanish from a serialization,
  // so both are refused as not own-enumerable-data
  throwsSync("an ACCESSOR-backed per-epoch row refuses (a getter is not an own data element)",
    () => { const epochs = [];
      Object.defineProperty(epochs, 0, { enumerable: true, configurable: true,
        get() { return { epochIndex: 5, condition: null, r: null, diagnostics: [] }; } });
      return buildReport({ ...reportInput(), epochs }); },
    /own enumerable data element/);
  throwsSync("a NON-ENUMERABLE per-epoch row refuses (it would vanish from serialization)",
    () => { const epochs = [];
      Object.defineProperty(epochs, 0, { enumerable: false, configurable: true, writable: true,
        value: { epochIndex: 5, condition: null, r: null, diagnostics: [] } });
      return buildReport({ ...reportInput(), epochs }); },
    /own enumerable data element/);
  {
    // identifiers are COPIED, not fixed: alternate values round-trip
    const alt = buildReport({ ...reportInput(), poolId: "cd".repeat(32),
      contractId: "AnotherContractIdentifier1111", expectedChainId: "tegara-other-9" });
    ok("alternate identifiers round-trip (copied, never emitted from a fixture constant)",
      alt.poolId === "cd".repeat(32) && alt.contractId === "AnotherContractIdentifier1111"
      && alt.expectedChainId === "tegara-other-9");
  }
  {
    // non-clean coverage round-trips and grades PARTIAL BY SCOPE
    const inp = reportInput();
    inp.coverage = { lateConfiguredStart: true, containsUniverse: true, narrowedRange: false };
    const rep = buildReport(inp);
    ok("a late-start report keeps its coverage members and grades PARTIAL BY SCOPE",
      rep.coverage.lateConfiguredStart === true && rep.verdict === "PARTIAL BY SCOPE");
  }

  // ---- D8 property tests over seeded synthetic inputs ----
  console.log(`e2AuditTest: property seed ${SEED}`);
  const randomGradeInput = () => {
    const branch = pick(["deactivation-bounded", "open-ended"]);
    const aspects = {};
    const sharedCount = randInt(5); // one examined-receipt set, one count
    for (const k of ASPECT_KEYS) {
      if (k === "deactivationBoundary" && branch === "open-ended") {
        // the coherence rule: this aspect is NOT EVALUATED in the
        // open-ended branch, so valid inputs never evaluate it there
        aspects[k] = { evaluated: false };
      } else {
        // labels draw from the aspect's VALID range, up to its ceiling
        aspects[k] = { evaluated: true,
          label: pick(SPEC_ORDER.slice(0, specRank(SPEC_CEILINGS[k]) + 1)),
          ...(RECEIPT_ASPECT_KEYS.includes(k) ? { examinedCount: sharedCount } : {}) };
      }
    }
    if (sharedCount === 0) {
      // the zero-count cap (round-43): with nothing examined, a receipt
      // label cannot outrank both OPERATOR-PROVIDED and the record set
      const bound = Math.max(specRank("OPERATOR-PROVIDED"), specRank(aspects.recordSet.label));
      for (const k of RECEIPT_ASPECT_KEYS) {
        const lim = Math.min(bound, specRank(SPEC_CEILINGS[k]));
        if (specRank(aspects[k].label) > lim) aspects[k].label = pick(SPEC_ORDER.slice(0, lim + 1));
      }
    }
    const coverage = { lateConfiguredStart: rand() < 0.25,
      containsUniverse: rand() < 0.75, narrowedRange: rand() < 0.25 };
    const annotation = branch === "open-ended"
      ? buildOpenEndedAnnotation({ endEpoch: rand() < 0.3 ? null : (rand() < 0.1 ? 4294967295 : randInt(1000)),
        recordsHeightMax: rand() < 0.3 ? null : String(randInt(100000)) })
      : null;
    return { branch, aspects, inReportRefusal: rand() < 0.2, coverage, annotation };
  };
  // the grammar restated independently as the test's oracle
  const oracle = (inp) => {
    const anyRefused = inp.inReportRefusal
      || ASPECT_KEYS.some((k) => inp.aspects[k].evaluated && inp.aspects[k].label === "REFUSED");
    if (anyRefused) return "REFUSED-REPORT";
    if (inp.coverage.lateConfiguredStart || !inp.coverage.containsUniverse
      || inp.coverage.narrowedRange) return "PARTIAL BY SCOPE";
    const belowTerminal = ASPECT_KEYS.some((k) => inp.aspects[k].evaluated
      && specRank(inp.aspects[k].label) < specRank(SPEC_TERMINALS[k]));
    const incompleteAnnotation = inp.branch === "open-ended"
      && (inp.annotation.endEpoch === null || inp.annotation.recordsHeightMax === null);
    if (belowTerminal || incompleteAnnotation) return "PARTIAL BY EVIDENCE";
    return inp.branch === "deactivation-bounded" ? "FULL" : "FULL-TO-DATE";
  };
  {
    let totalityOk = 0;
    const N = 500;
    for (let i = 0; i < N; i++) {
      const inp = randomGradeInput();
      const g = gradeVerdict(inp);
      if (GRADES.includes(g) && g !== "REFUSED-INPUT" && g === oracle(inp)) totalityOk++;
      else console.error(`totality divergence at iteration ${i}: got ${g}, oracle ${oracle(inp)}`);
    }
    ok(`precedence totality: ${totalityOk}/${N} seeded inputs reach exactly the grammar's outcome`,
      totalityOk === N);
  }
  {
    // grade monotonicity: removing evidence never improves a grade
    const GOODNESS = { "REFUSED-REPORT": 0, "PARTIAL BY SCOPE": 1,
      "PARTIAL BY EVIDENCE": 2, "FULL-TO-DATE": 3, FULL: 4 };
    // only iterations that ACTUALLY degrade evidence enter the count, so
    // an undegradable draw can never pad the result
    let monotone = 0, degradedCount = 0, attempts = 0;
    const N = 500;
    while (degradedCount < N && attempts < N * 4) {
      attempts++;
      const inp = randomGradeInput();
      const before = GOODNESS[gradeVerdict(inp)];
      const degraded = { ...inp, aspects: { ...inp.aspects } };
      const evaluable = ASPECT_KEYS.filter((k) => inp.aspects[k].evaluated
        && specRank(inp.aspects[k].label) > 0);
      if (inp.branch === "open-ended" && rand() < 0.3 && inp.annotation.endEpoch !== null) {
        degraded.annotation = buildOpenEndedAnnotation({ endEpoch: null,
          recordsHeightMax: inp.annotation.recordsHeightMax });
      } else if (evaluable.length > 0) {
        const k = pick(evaluable);
        degraded.aspects[k] = { evaluated: true,
          label: SPEC_ORDER[specRank(inp.aspects[k].label) - 1],
          ...(RECEIPT_ASPECT_KEYS.includes(k) ? { examinedCount: inp.aspects[k].examinedCount } : {}) };
      } else { continue; }
      degradedCount++;
      let after;
      try { after = GOODNESS[gradeVerdict(degraded)]; }
      catch (e) {
        // the ONE expected invalid-degradation shape is the zero-count
        // cap: the STRUCTURE must show it (zero counts, and a receipt
        // label now past the degraded bound), not just the message
        // (round-45); any other exception is a real fault and fails
        const rcK = ["transferExecution", "reservationPresence", "ordering"];
        const zeroed = rcK.every((k) => degraded.aspects[k].evaluated
          && degraded.aspects[k].examinedCount === 0);
        const bound = Math.max(specRank("OPERATOR-PROVIDED"), specRank(degraded.aspects.recordSet.label));
        const exceeds = rcK.some((k) => degraded.aspects[k].evaluated
          && specRank(degraded.aspects[k].label) > bound);
        if (!(zeroed && exceeds && /zero examined-receipt count cannot earn/.test(e.message))) throw e;
        after = 0;
      }
      if (after <= before) monotone++;
      else console.error(`monotonicity violation at attempt ${attempts}: ${before} -> ${after}`);
    }
    ok(`grade monotonicity: ${monotone}/${degradedCount} actual seeded degradations never improve the grade`,
      degradedCount === N && monotone === N);
  }
  {
    // containment: a late start is never out-graded past PARTIAL BY SCOPE
    let contained = 0;
    const N = 300;
    for (let i = 0; i < N; i++) {
      const inp = randomGradeInput();
      inp.coverage.lateConfiguredStart = true;
      const g = gradeVerdict(inp);
      if (g === "REFUSED-REPORT" || g === "PARTIAL BY SCOPE") contained++;
      else console.error(`late-start out-graded at iteration ${i}: ${g}`);
    }
    ok(`containment: ${contained}/${N} late-start inputs stay refused or PARTIAL BY SCOPE`, contained === N);
  }
  {
    // emptiness never out-grades an omission: the empty result WITH a late
    // start is PARTIAL BY SCOPE; without one it is PARTIAL BY EVIDENCE
    const late = await resolveInterval({ requestedStart: 30, requestedEnd: null,
      configuredStart: 30, provedActivation: 5, fetchRange: ledgerFetch(20, true) });
    const emptyAnnotation = buildOpenEndedAnnotation({ endEpoch: null, recordsHeightMax: null });
    const gLate = gradeVerdict({ branch: late.branch, aspects: labelsAtTerminal("open-ended"),
      inReportRefusal: false, coverage: late.coverage, annotation: emptyAnnotation });
    ok("the empty result with a late start grades PARTIAL BY SCOPE", gLate === "PARTIAL BY SCOPE");
    const clean = await resolveInterval({ requestedStart: 30, requestedEnd: null,
      configuredStart: 30, fetchRange: ledgerFetch(20, true) });
    const gClean = gradeVerdict({ branch: clean.branch, aspects: labelsAtTerminal("open-ended"),
      inReportRefusal: false, coverage: clean.coverage, annotation: emptyAnnotation });
    ok("the empty result without a scope violation grades PARTIAL BY EVIDENCE through annotation completeness",
      gClean === "PARTIAL BY EVIDENCE");
  }
  {
    // domain classification: prefix records never extras, out-of-domain
    // records always extras, restated with independent set arithmetic
    // every counted iteration EXAMINES a record: a reversed generated
    // interval is redrawn, never counted
    let domainOk = 0, drawn = 0;
    const N = 500;
    while (drawn < N) {
      const i = drawn;
      const uStart = randInt(50) + 10;
      const uEnd = uStart + randInt(50);
      const iStart = rand() < 0.5 ? uStart - randInt(uStart) : uStart;
      const iEnd = uEnd + (rand() < 0.3 ? -randInt(5) : randInt(10));
      if (iStart > iEnd) continue;
      drawn++;
      const ctx = {
        universe: { start: uStart, end: uEnd },
        interval: { startEpoch: iStart, endEpoch: iEnd },
        prefix: iStart < uStart ? { start: iStart, end: uStart - 1 } : null,
      };
      const e = randInt(uEnd + 20);
      const got = classifyRecordEpoch(e, ctx).bucket;
      const inPrefix = ctx.prefix !== null && e >= ctx.prefix.start && e <= ctx.prefix.end;
      const inU = e >= uStart && e <= uEnd;
      const inI = e >= iStart && e <= iEnd;
      const want = inPrefix ? "prefix-permitted" : inU ? (inI ? "in-scope" : "ignored") : "extra";
      if (got === want) domainOk++;
      else console.error(`domain divergence at iteration ${i}: epoch ${e} got ${got}, want ${want}`);
    }
    ok(`domain classification: ${domainOk}/${N} seeded records classify per the domain rule`, domainOk === N);
  }

  // ==========================================================================
  // THE SECOND HALF: the evidence evaluators and runAudit, over a synthetic
  // world whose fixtures trace to the real constructors (the allocation
  // through formationCore, the pair fixtures in receiptPoolCheckTest's
  // golden shapes, the journal through the real append path, the carriers
  // through the same mock pipeline contract as e2ReceiptVerifyTest).
  // ==========================================================================
  const sha = (hex) => crypto.createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");
  const be64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b.toString("hex"); };
  const toHex = (str) => Buffer.from(str, "utf8").toString("hex");
  const fromHex = (h) => Buffer.from(h, "hex").toString("utf8");
  const h32 = (f) => f.repeat(64 / f.length);

  // the golden base58 vector shared with formationCoreTest and
  // receiptPoolCheckTest, so the suites move together
  const GC = "3EbgWjxUoX6J9XbqqxrEktm7tUFBQ5fQyKaiAzXCULxf";
  const GP = "47doihuxfjfeoqi4PrKLY58Z56J6BhXekMmhW3z63QT8";
  const OA = "8sCudmZNvmDC9nXCGRWk1NMStKaeqCaWLa7eYTEKuT8Y";
  const OB = "52D4DcjgFZU1KktALjGpcfGoxR1987BEjTXxbnNcNfAc";
  const OC = "FZ9HF6oANQxZDXGXGiKh8uXdPfwcp4rwfrzqQJcdRNgv";
  const POOL_HEX = Buffer.from(core.decodeId32(GP)).toString("hex");
  const FA = Buffer.from(core.decodeId32(OA)).toString("hex");
  const FB = Buffer.from(core.decodeId32(OB)).toString("hex");
  const FC = Buffer.from(core.decodeId32(OC)).toString("hex");
  const INCOME = h32("ee");
  const CHAIN = "tegara-audit-1";
  const EVO = "400000000000";

  // the owned pins and the store sentinel, in the per-run temp store
  fs.writeFileSync(process.env.TEGARA_ENV_PATH,
    "MNEMONIC=m\nSTATE_MIGRATED=1\nSTATE_STORE_ID=00112233aabbccdd\n");
  fs.mkdirSync(envStore.STATE_DIR, { recursive: true });
  fs.writeFileSync(path.join(envStore.STATE_DIR, "store.id"), "00112233aabbccdd");
  envStore.updateEnvKey("CONTRACT_V11_ID", GC);
  envStore.updateEnvKey("E2_EXPECTED_CHAIN_ID", canonicalString({ chainId: CHAIN,
    source: { path: "genesis.json", retrievedAt: "2026-08-01" } }));
  envStore.updateEnvKey(`E2_START_EPOCH_${POOL_HEX.toUpperCase()}`, "5");

  // ---- the mock pinned pipeline, the same contract as the verifier's battery ----
  const PROOF_KNOWN = ["quorumHash", "round", "blockIdHash", "quorumType", "signature", "pad"];
  const META_KNOWN = ["chainId", "protocolVersion", "height", "timeMs", "coreChainLockedHeight", "epoch", "pad"];
  const mockDecode = (known) => (hex) => {
    const obj = JSON.parse(fromHex(hex));
    const out = {};
    let dropped = 0;
    for (const [k, v] of Object.entries(obj)) {
      if (!known.includes(k)) { dropped += 1; continue; }
      out[k] = v;
    }
    return { fields: out, unknownFieldsDropped: dropped, reencodedHex: toHex(canonicalString(out)) };
  };
  const decodeProofRaw = mockDecode(PROOF_KNOWN);
  const decodeMetaRaw = mockDecode(META_KNOWN);
  const PROOF_OBJ = { quorumHash: h32("dd"), round: 3, blockIdHash: h32("bb"),
    quorumType: 4, signature: "cd".repeat(40) };
  const CARRIER = toHex(canonicalString(PROOF_OBJ));
  const metaObj = (epoch) => ({ chainId: CHAIN, protocolVersion: 12, height: "1000",
    timeMs: "1690000000000", coreChainLockedHeight: 777, epoch });
  const metaHexOf = (epoch) => toHex(canonicalString(metaObj(epoch)));

  const mkVerifierDeps = (provedDocs) => ({
    decodeProofCarrier: (hex) => {
      const d = decodeProofRaw(hex);
      return { reencodedHex: d.reencodedHex, quorumHashHex: d.fields.quorumHash, round: d.fields.round };
    },
    decodeMetadata: (hex) => {
      const d = decodeMetaRaw(hex);
      return { reencodedHex: d.reencodedHex, ...d.fields };
    },
    decodeTransfer: (hex) => JSON.parse(fromHex(hex)),
    verifyStageOne: async (args) => ({ ok: true, rootHashHex: sha(args.carrierHex),
      provedDocument: provedDocs[args.transitionBytes] }),
    verifyStageTwo: async () => true,
  });

  // ---- the world builder ----
  const mkWorld = (opts = {}) => {
    const manifest = opts.manifest ?? {
      v: 1, poolId: GP, realHash: "aa".repeat(32), target: EVO,
      owners: [
        { owner: OA, amountDuffs: String(BigInt(EVO) / 2n), bps: 5000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
        { owner: OB, amountDuffs: String(BigInt(EVO) * 3n / 10n), bps: 3000, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
        { owner: OC, amountDuffs: String(BigInt(EVO) / 5n), bps: 2000, rewardScriptHex: "76a914" + "33".repeat(20) + "88ac" },
      ],
    };
    const rowsBytes = core.allocationPreimage(GC, manifest);
    const allocHash = core.allocationHash(rowsBytes);
    const fr = {
      poolId: Buffer.from(core.decodeId32(GP)),
      proTxHash: Buffer.from(manifest.realHash, "hex"),
      slotIndex: 0, formatVersion: 1,
      allocationRows: rowsBytes, allocationHash: allocHash,
      participantCount: 3, l1Verification: "demo-unverified", verificationMethodVersion: 1,
      "$ownerId": OA,
    };
    if (opts.mutateFr) opts.mutateFr(fr);
    const pool = { "$id": POOL_HEX, slotIndex: 0, nodeType: opts.nodeType ?? "evo",
      operatorFeeBps: opts.operatorFeeBps ?? 2000,
      targetDuffs: Number(EVO), slotDuffs: Number(BigInt(EVO) / 2n), slotCount: 2, "$ownerId": OA };
    const contractPayload = { "$id": GC, version: "v11",
      documentTypes: ["header", "accrual", "reservation", "receipt", "part"],
      documents: { pool: { required: ["nodeType", "operatorFeeBps"] } } };

    // epoch 5 pays G = 1000000 (fee 200000, owed 400000/240000/160000);
    // epoch 6 is zero-earning (the node absent from its proposer set)
    const epochObjects = [
      { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
        coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
      { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
        coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
    ];
    // derived from the manifest so a wider allocation yields a wider
    // world (D = 800000 at fee 2000bps over G = 1000000)
    const owed5 = manifest.owners.map((o) => [String(800000 * o.bps / 10000),
      Buffer.from(core.decodeId32(o.owner)).toString("hex")]);

    // credits are INTEGER document fields (the schema's position
    // integers under the MAX_SAFE ceiling), matching the journal's
    // expectedContents typing
    const headers = [
      { id: h32("10"), poolId: POOL_HEX, epochIndex: 5, grossCredits: 1000000,
        feeCredits: 200000, memberCount: 3, calcVersion: 1,
        allocationHash: allocHash.toString("hex") },
      { id: h32("11"), poolId: POOL_HEX, epochIndex: 6, grossCredits: 0,
        feeCredits: 0, memberCount: 3, calcVersion: 1,
        allocationHash: allocHash.toString("hex") },
    ];
    const accruals = [];
    owed5.forEach(([amount, funder], i) => accruals.push({
      id: h32(`2${i}`), poolId: POOL_HEX, epochIndex: 5, funderId: funder, amountCredits: Number(amount) }));
    [FA, FB, FC].forEach((funder, i) => accruals.push({
      id: h32(`3${i}`), poolId: POOL_HEX, epochIndex: 6, funderId: funder, amountCredits: 0 }));

    const receipts = [], reservations = [], captures = [], provedDocs = {};
    owed5.forEach(([amount, funder], i) => {
      const t = toHex(canonicalString({ senderId: INCOME, recipientId: funder,
        amountCredits: amount, nonce: String(i + 1), pad: "x".repeat(40) }));
      const accrualId = accruals[i].id;
      receipts.push({ id: h32(`4${i}`), poolId: POOL_HEX, accrualId,
        transitionBytes: t, transitionHash: sha(t), proofBytes: CARRIER, proofPartCount: 1,
        metadataBytes: metaHexOf(5), blockHeight: be64("1000"), timeMs: be64("1690000000000"),
        quorumHash: h32("dd"), coreChainLockedHeight: 777, round: 3 });
      reservations.push({ id: h32(`5${i}`), poolId: POOL_HEX, accrualId, transitionHash: sha(t) });
      captures.push({ v: 1, kind: CAP_RECEIPT, object: "transfer", gen: 1, poolId: POOL_HEX,
        epochIndex: 5, accrualId, transitionHash: sha(t), transitionBytes: t,
        proofMsg: CARRIER, metadataMsg: metaHexOf(5),
        inclusionHeight: opts.receiptInclusionHeight ?? "1001",
        heightRoute: opts.receiptRoute ?? "tenderdash-tx",
        signerIdentity: h32("f0"), signerKeyId: 2, sig: "00".repeat(65) });
    });
    // an optional MULTIPART receipt: the third recipient's proof carrier
    // grows past the canonical part bound, so its receipt holds only the
    // first chunk and one enumerated part document holds the remainder
    const partDocs = [];
    if (opts.multipartReceipt) {
      const bigObj = { ...PROOF_OBJ, signature: "cd".repeat(4000) };
      const bigCarrier = toHex(canonicalString(bigObj));
      const r = receipts[2];
      r.proofBytes = bigCarrier.slice(0, 5120 * 2);
      r.proofPartCount = 2;
      partDocs.push({ id: h32("70"), poolId: POOL_HEX, accrualId: r.accrualId,
        partIndex: 1, bytes: bigCarrier.slice(5120 * 2) });
      captures[2].proofMsg = bigCarrier;
    }

    // the two header captures, their proved-document bindings included
    const hBytes = (epoch) => "0102" + String(epoch).padStart(4, "0") + "01";
    const ecOf = (epoch) => epoch === 5
      ? { poolId: POOL_HEX, epochIndex: 5, grossCredits: 1000000, feeCredits: 200000,
        allocationHash: allocHash.toString("hex"), memberCount: 3, calcVersion: 1 }
      : { poolId: POOL_HEX, epochIndex: 6, grossCredits: 0, feeCredits: 0,
        allocationHash: allocHash.toString("hex"), memberCount: 3, calcVersion: 1 };
    const headerCaps = [5, 6].map((epoch) => {
      provedDocs[hBytes(epoch)] = { documentId: headers[epoch - 5].id, fields: ecOf(epoch) };
      return { v: 1, kind: CAP_HEADER, object: "header", gen: 1, poolId: POOL_HEX,
        epochIndex: epoch, transitionBytes: hBytes(epoch), transitionHash: sha(hBytes(epoch)),
        proofMsg: CARRIER, metadataMsg: metaHexOf(epoch),
        contractId: opts.headerCaptureContract
          ?? Buffer.from(core.decodeId32(GC)).toString("hex"),
        expectedDocumentId: headers[epoch - 5].id, expectedContents: ecOf(epoch),
        inclusionHeight: opts.headerInclusionHeight ?? "1000", heightRoute: "tenderdash-tx",
        signerIdentity: h32("f0"), signerKeyId: 2, sig: "00".repeat(65) };
    });

    const docs = { header: headers, accrual: accruals, reservation: reservations,
      receipt: receipts, part: partDocs };
    if (opts.mutateDocs) opts.mutateDocs(docs);
    const journalRecords = opts.journalRecords !== undefined ? opts.journalRecords
      : [...headerCaps, ...captures];

    const heightsByType = { header: "900", accrual: "901", reservation: "902",
      receipt: "903", part: "904" };
    const fetchVerifiedPage = opts.fetchVerifiedPage ?? (async ({ contractId, type, where, orderBy, limit, startAfter }) => {
      // the adapter checks the exact query it receives (the round-6
      // provenance gap: a wrong or dropped predicate must fail loudly)
      if (opts.strictQueries !== false) {
        if (contractId !== GC) throw new Error(`page adapter: wrong contractId ${contractId}`);
        if (JSON.stringify(where) !== JSON.stringify([["poolId", "==", POOL_HEX]])) {
          throw new Error(`page adapter: wrong where clause ${JSON.stringify(where)}`);
        }
        if (JSON.stringify(orderBy) !== JSON.stringify([["$id", "asc"]])) {
          throw new Error(`page adapter: wrong orderBy ${JSON.stringify(orderBy)}`);
        }
        if (limit !== 100) throw new Error(`page adapter: wrong limit ${limit}`);
      }
      const all = [...docs[type]].sort((a, b) => (a.id < b.id ? -1 : 1));
      const start = startAfter === null ? 0 : all.findIndex((d) => d.id === startAfter) + 1;
      return { status: "verified", documents: all.slice(start, start + limit),
        height: heightsByType[type] };
    });
    const baseProvedByKey = async (type, key) => {
      if (type === "pool") return { status: "served", doc: pool, height: "890" };
      if (type === "completionReceipt") return { status: "served", doc: fr, height: "889" };
      if (type === "identity") {
        return [FA, FB, FC].includes(key.identityId)
          ? { status: "served", doc: { id: key.identityId }, height: "892" }
          : { status: "proved-absence", height: "892" };
      }
      if (type === "contract") return { status: "served", doc: contractPayload, height: "889" };
      if (type === "reservationByAccrual") {
        const doc = docs.reservation.find((r) => sameIdTest(r.accrualId, key.accrualId));
        return doc ? { status: "served", doc, height: "915" } : { status: "proved-absence", height: "915" };
      }
      if (type === "receiptByAccrual") {
        const doc = docs.receipt.find((r) => sameIdTest(r.accrualId, key.accrualId));
        return doc ? { status: "served", doc, height: "916" } : { status: "proved-absence", height: "916" };
      }
      if (type === "headerByEpoch") {
        const doc = docs.header.find((h) => h.epochIndex === key.epochIndex);
        return doc ? { status: "served", doc, height: "917" } : { status: "proved-absence", height: "917" };
      }
      if (type === "accrualByKey") {
        const doc = docs.accrual.find((a) => a.epochIndex === key.epochIndex && sameIdTest(a.funderId, key.funderId));
        return doc ? { status: "served", doc, height: "918" } : { status: "proved-absence", height: "918" };
      }
      if (type === "accrualById") {
        const doc = docs.accrual.find((a) => sameIdTest(a.id, key.accrualId));
        return doc ? { status: "served", doc, height: "919" } : { status: "proved-absence", height: "919" };
      }
      throw new Error(`unexpected provedByKey type ${type}`);
    };
    const deps = {
      fetchRange: opts.fetchRange ?? (async (start, end) => ({
        epochs: epochObjects.filter((e) => e.number >= start && e.number <= end),
        proved: false })),
      provedActivation: opts.provedActivation ?? null,
      provedDeactivation: opts.provedDeactivation ?? null,
      fetchVerifiedPage,
      provedByKey: opts.provedByKey ? opts.provedByKey(baseProvedByKey) : baseProvedByKey,
      verifierDeps: mkVerifierDeps(provedDocs),
      verifyCaptureBasis: opts.verifyCaptureBasis ?? (async () => true),
      incomeIdentity: INCOME,
      // the expected payload is a DEEP CLONE WITHOUT the platform
      // envelope: a registration payload carries no $-members, and object
      // identity never proves equality in these fixtures
      expectedContractPayload: opts.expectedContractPayload
        ?? Object.fromEntries(Object.entries(JSON.parse(JSON.stringify(contractPayload)))
          .filter(([k]) => !k.startsWith("$"))),
    };
    return { deps, docs, pool, fr, manifest, contractPayload, journalRecords,
      captures, headerCaps, accruals, receipts, reservations, allocHash, hBytes, ecOf };
  };

  const happyResolution = async (deps) => resolveInterval({ requestedStart: 5,
    requestedEnd: null, configuredStart: 5, fetchRange: deps.fetchRange });
  const worldEpochInfo = (resolution) => {
    const m = new Map();
    for (const e of resolution.discovery.epochs) m.set(e.number, e);
    return m;
  };
  const runLedger = async (w, over = {}) => {
    const resolution = over.resolution ?? await happyResolution(w.deps);
    const enums = {};
    for (const t of ["header", "accrual", "reservation", "receipt", "part"]) {
      enums[t] = await (require("./e2ProvedQuery.cjs").enumerateProved({
        contractId: GC, type: t, where: [["poolId", "==", POOL_HEX]],
        orderBy: [["$id", "asc"]],
        fetchVerifiedPage: w.deps.fetchVerifiedPage }));
    }
    const formation = over.formation ?? await evaluateFormationInputs({ poolId: POOL_HEX,
      contractId: GC, deps: w.deps });
    return evaluateLedgerRecords({ poolId: POOL_HEX, contractId: GC, resolution,
      epochInfo: over.epochInfo ?? worldEpochInfo(resolution), formation, chainIdPin: CHAIN,
      incomeIdentity: over.incomeIdentity ?? w.deps.incomeIdentity, enums,
      journalRecords: w.journalRecords, deps: w.deps });
  };
  {
    // the missing-epoch-object branch is unreachable THROUGH THE ENTRY, whose
    // discovery is gapless, but this evaluator is EXPORTED and a direct caller
    // supplies epochInfo and resolution independently, so the branch is
    // reachable exactly when those two disagree (round-63, correcting a
    // comment that had claimed unreachability without qualification). A branch
    // described as unreachable and left ungated is a claim a test cannot
    // support, so it is reached here rather than asserted away.
    const w = mkWorld();
    const resolution = await happyResolution(w.deps);
    const gapped = new Map();
    for (const e of resolution.discovery.epochs) { if (e.number !== 6) gapped.set(e.number, e); }
    const led = await runLedger(w, { resolution, epochInfo: gapped });
    const row = led.perEpoch.get(6);
    ok("an interval epoch with no discovered object is UNPROVED and says so, never silently complete",
      row !== undefined && row.condition === null && row.r === null
      && row.diagnostics.some((d) => /no epoch object was discovered/.test(d))
      && led.recordSet.label === "UNPROVED");
  }

  // ---- the formation, contract and per-receipt evaluators ----
  {
    const w = mkWorld();
    const f = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w.deps });
    // the canonical preimage sorts rows ascending by DECODED owner
    // bytes, so the parsed order is the sorted one, not the manifest's
    const byFunder = Object.fromEntries(f.rows.map((r) => [r.funderId, r.bps]));
    ok("the golden world's formation inputs are PROVED with the parsed rows",
      f.label === "PROVED" && f.rows.length === 3
      && byFunder[FA] === 5000 && byFunder[FB] === 3000 && byFunder[FC] === 2000
      && f.pool.operatorFeeBps === 2000);
    ok("formation's height candidates are exactly the pool and completion-receipt reads",
      f.heights.length === 2 && f.heights.includes("890") && f.heights.includes("889"));
    const identityReads = new Set();
    const counting = { ...w.deps, provedByKey: async (type, key) => {
      if (type === "identity") identityReads.add(key.identityId);
      return w.deps.provedByKey(type, key);
    } };
    await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: counting });
    ok("EVERY recipient identity is looked up, by identity (a double read of one cannot stand in)",
      identityReads.size === 3 && [FA, FB, FC].every((f) => identityReads.has(f)));
    // and a FOUR-member pool looks up all four (the duty scales with the
    // allocation, round-44)
    const OD = toBase58(h32("ff")); // all-ff bytes, so this owner sorts LAST
    const w4 = mkWorld({ manifest: {
      v: 1, poolId: GP, realHash: "aa".repeat(32), target: EVO,
      owners: [
        { owner: OA, amountDuffs: String(BigInt(EVO) * 4n / 10n), bps: 4000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
        { owner: OB, amountDuffs: String(BigInt(EVO) * 3n / 10n), bps: 3000, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
        { owner: OC, amountDuffs: String(BigInt(EVO) / 5n), bps: 2000, rewardScriptHex: "76a914" + "33".repeat(20) + "88ac" },
        { owner: OD, amountDuffs: String(BigInt(EVO) / 10n), bps: 1000, rewardScriptHex: "76a914" + "44".repeat(20) + "88ac" },
      ] },
      mutateFr: (fr) => { fr.participantCount = 4; },
      provedByKey: (base) => async (type, key) =>
        type === "identity" ? { status: "served", doc: { id: key.identityId }, height: "892" } : base(type, key) });
    const reads4 = new Set();
    const counting4 = { ...w4.deps, provedByKey: async (type, key) => {
      if (type === "identity") reads4.add(key.identityId);
      return w4.deps.provedByKey(type, key);
    } };
    const f4 = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: counting4 });
    ok("a four-member allocation drives four distinct identity lookups and proves formation",
      f4.label === "PROVED" && f4.rows.length === 4 && reads4.size === 4);
    // and the FOURTH answer is consumed, not merely requested (round-45)
    const FD = Buffer.from(core.decodeId32(OD)).toString("hex");
    const w4of = (ans) => ({ ...w4.deps, provedByKey: async (type, key) =>
      type === "identity" && sameIdTest(key.identityId, FD) ? ans
        : w4.deps.provedByKey(type, key) });
    const f4abs = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC,
      deps: w4of({ status: "proved-absence", height: "892" }) });
    ok("a proved absence on the FOURTH member alone refuses formation",
      f4abs.label === "REFUSED" && f4abs.reason.includes(FD.slice(0, 8)));
    const f4un = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC,
      deps: w4of({ status: "unserved" }) });
    ok("an unserved FOURTH identity read leaves formation UNPROVED",
      f4un.label === "UNPROVED");
    await rejects("a wrong identity served for the FOURTH member alone refuses hard",
      evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC,
        deps: w4of({ status: "served", doc: { id: FA }, height: "892" }) }),
      /DIFFERENT identity/);
    // and a FIFTH member is reached too (round-60): a loop truncated at
    // any bound at or below four passes every fixture above, so the
    // coverage is proved past the largest earlier allocation
    const OE = toBase58(h32("fd"));
    const w5 = mkWorld({ manifest: {
      v: 1, poolId: GP, realHash: "aa".repeat(32), target: EVO,
      owners: [
        { owner: OA, amountDuffs: String(BigInt(EVO) * 3n / 10n), bps: 3000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
        { owner: OB, amountDuffs: String(BigInt(EVO) / 4n), bps: 2500, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
        { owner: OC, amountDuffs: String(BigInt(EVO) / 5n), bps: 2000, rewardScriptHex: "76a914" + "33".repeat(20) + "88ac" },
        { owner: OD, amountDuffs: String(BigInt(EVO) * 3n / 20n), bps: 1500, rewardScriptHex: "76a914" + "44".repeat(20) + "88ac" },
        { owner: OE, amountDuffs: String(BigInt(EVO) / 10n), bps: 1000, rewardScriptHex: "76a914" + "55".repeat(20) + "88ac" },
      ] },
      mutateFr: (fr) => { fr.participantCount = 5; },
      provedByKey: (base) => async (type, key) =>
        type === "identity" ? { status: "served", doc: { id: key.identityId }, height: "892" } : base(type, key) });
    const reads5 = new Set();
    const counting5 = { ...w5.deps, provedByKey: async (type, key) => {
      if (type === "identity") reads5.add(key.identityId);
      return w5.deps.provedByKey(type, key);
    } };
    const f5 = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: counting5 });
    ok("a five-member allocation drives five distinct identity lookups and proves formation",
      f5.label === "PROVED" && f5.rows.length === 5 && reads5.size === 5);
    const FE = Buffer.from(core.decodeId32(OE)).toString("hex");
    const w5of = (ans) => ({ ...w5.deps, provedByKey: async (type, key) =>
      type === "identity" && sameIdTest(key.identityId, FE) ? ans
        : w5.deps.provedByKey(type, key) });
    const f5abs = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC,
      deps: w5of({ status: "proved-absence", height: "892" }) });
    ok("a proved absence on the FIFTH member alone refuses formation (its answer is consumed)",
      f5abs.label === "REFUSED" && f5abs.reason.includes(FE.slice(0, 8)));
    await rejects("a wrong identity served for the FIFTH member alone refuses hard",
      evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC,
        deps: w5of({ status: "served", doc: { id: FA }, height: "892" }) }),
      /DIFFERENT identity/);
  }
  {
    const w = mkWorld({ nodeType: "regular" });
    const f = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w.deps });
    ok("a non-evo pool refuses the formation aspect (the eligibility predicate)",
      f.label === "REFUSED" && /eligibility/.test(f.reason));
  }
  {
    const w = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "pool" ? { status: "unserved" } : base(type, key) });
    const f = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w.deps });
    ok("an unserved pool read leaves formation UNPROVED, never refused", f.label === "UNPROVED");
  }
  {
    const w = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "identity" && key.identityId === FB ? { status: "proved-absence", height: "892" } : base(type, key) });
    const f = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w.deps });
    ok("a recipient identity's proved absence refuses formation",
      f.label === "REFUSED" && /proved absence/.test(f.reason));
    ok("the refused formation still carries the heights its accepted reads earned",
      f.heights.includes("890") && f.heights.includes("889"));
    // a LATER unavailable read keeps every height already earned: pool
    // served, completion receipt unserved
    const wLate = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "completionReceipt" ? { status: "unserved" } : base(type, key) });
    const fLate = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: wLate.deps });
    ok("an unavailable later read keeps the pool height already earned",
      fLate.label === "UNPROVED" && fLate.heights.length === 1 && fLate.heights[0] === "890");
    const wLateId = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "identity" ? { status: "unserved" } : base(type, key) });
    const fLateId = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: wLateId.deps });
    ok("unavailable identity reads keep both formation-document heights",
      fLateId.label === "UNPROVED"
      && fLateId.heights.includes("890") && fLateId.heights.includes("889"));
  }
  {
    // evaluator duties WIRED, not merely present (round-37): the
    // allocation recomputation, the fee grammar, the income-identity
    // binding, the in-scope feeCredits comparison, and the entry's
    // dependency checks each have an isolated adverse gate
    const wAlloc = mkWorld({ mutateFr: (fr) => {
      const rows = Buffer.from(fr.allocationRows);
      rows[rows.length - 1] ^= 1;
      fr.allocationRows = rows;
    } });
    const fAlloc = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: wAlloc.deps });
    ok("allocation rows failing recomputation refuse formation through the pair check's allocation duty",
      fAlloc.label === "REFUSED" && /pair check refuses \(allocation:/.test(fAlloc.reason));
    const wFee = mkWorld({ operatorFeeBps: 1.5 });
    const fFee = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: wFee.deps });
    ok("a non-integer operatorFeeBps refuses formation through the pair check's pool-shape duty",
      fFee.label === "REFUSED" && /pair check refuses.*operatorFeeBps/.test(fFee.reason));
    const wInc37 = mkWorld();
    const tInc = await evaluateTransferExecution({ receipt: wInc37.receipts[0], parts: [],
      entitlementRow: { recipientId: FA, amountCredits: "400000" },
      accrual: wInc37.accruals[0], headerFor: wInc37.docs.header[0],
      incomeIdentity: h32("77"), chainIdPin: CHAIN,
      capture: wInc37.captures[0], supersessions: [], deps: wInc37.deps });
    ok("a receipt whose sender is not the SUPPLIED income identity refuses (the identity is consumed, not re-derived)",
      tInc.label === "REFUSED");
    const wFeeC = mkWorld({ mutateDocs: (docs) => { docs.header[0].feeCredits = 3; } });
    const ledFeeC = await runLedger(wFeeC);
    ok("an in-scope header with a wrong feeCredits refuses against the recomputation",
      ledFeeC.recordSet.label === "REFUSED"
      && ledFeeC.perEpoch.get(5).diagnostics.some((d) => /feeCredits 3/.test(d)));
    for (const missing of ["fetchRange", "fetchVerifiedPage", "provedByKey", "verifyCaptureBasis"]) {
      const wD = mkWorld();
      const rD = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-nodep"),
        deps: { ...wD.deps, [missing]: undefined } });
      ok(`a missing deps.${missing} is a structured REFUSED-INPUT`,
        rD.verdict === "REFUSED-INPUT" && rD.reason.includes(missing));
    }
    // the verifier PIPELINE is validated at the entry too (round-40)
    for (const vk of ["decodeProofCarrier", "decodeMetadata", "decodeTransfer", "verifyStageOne", "verifyStageTwo"]) {
      const wV40 = mkWorld();
      const rV40 = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-nodep"),
        deps: { ...wV40.deps, verifierDeps: { ...wV40.deps.verifierDeps, [vk]: undefined } } });
      ok(`a missing verifierDeps.${vk} is a structured REFUSED-INPUT`,
        rV40.verdict === "REFUSED-INPUT" && rV40.reason.includes(vk));
    }
    // an adapter FAULT in the basis check is never evidence (round-40),
    // on the header path and the RECEIPT path separately (each has its
    // own gate, so each direction gets its own fixture)
    const wThrow = mkWorld({ verifyCaptureBasis: async () => { throw new Error("key resolution unavailable"); } });
    await rejects("a rejecting capture-basis adapter propagates as a hard fault, never as adverse evidence",
      runLedger(wThrow), /adapter fault is not evidence/);
    const wStr = mkWorld({ verifyCaptureBasis: async () => "true" });
    await rejects("a non-boolean capture-basis result is an adapter-contract fault",
      runLedger(wStr), /requires true or false/);
    const wThrowR = mkWorld({ verifyCaptureBasis: async (cap) =>
      cap.kind === CAP_HEADER ? true : Promise.reject(new Error("key resolution unavailable")) });
    await rejects("a receipt-side basis fault propagates hard too (the header path cannot mask it)",
      runLedger(wThrowR), /adapter fault is not evidence/);
    const wStrR = mkWorld({ verifyCaptureBasis: async (cap) =>
      cap.kind === CAP_HEADER ? true : "true" });
    await rejects("a receipt-side non-boolean basis result is an adapter-contract fault too",
      runLedger(wStrR), /requires true or false/);
    // a SELF-SET refusal property is not a refusal (round-42): only the
    // verifier modules' own constructed refusals classify as evidence
    const wSelfSet = mkWorld({ verifyCaptureBasis: async (cap) => cap.kind !== CAP_HEADER });
    await rejects("an adapter error carrying a self-set verificationRefusal property still propagates",
      runLedger({ ...wSelfSet, deps: { ...wSelfSet.deps, verifierDeps: { ...wSelfSet.deps.verifierDeps,
        verifyStageOne: async () => { const e = new Error("proof helper unavailable");
          e.verificationRefusal = true; throw e; } } } }),
      /proof helper unavailable/);
    // classification is by ORIGIN, never textual (round-41; the mechanism
    // became a membership record round-61): a plain adapter error whose
    // message merely ends in "refusing" still propagates.
    // The header basis is disabled in these worlds so the fault fires in
    // the RECEIPT path's catches, the ones under test.
    const wSuffix = mkWorld({ verifyCaptureBasis: async (cap) => cap.kind !== CAP_HEADER });
    await rejects("a plain adapter error ending in the refusal word is NOT verification evidence",
      runLedger({ ...wSuffix, deps: { ...wSuffix.deps, verifierDeps: { ...wSuffix.deps.verifierDeps,
        verifyStageOne: async () => { throw new Error("helper offline; refusing"); } } } }),
      /helper offline/);
    // and a fault that first appears during CAPTURE verification (the
    // second catch) propagates too: with the header basis disabled, the
    // first stage call is the receipt's own and the second is its
    // capture's
    const wLate = mkWorld({ verifyCaptureBasis: async (cap) => cap.kind !== CAP_HEADER });
    let stageCalls = 0;
    const baseStage = wLate.deps.verifierDeps.verifyStageOne;
    // with the header basis disabled, stage calls alternate per row
    // (odd = the receipt's own carrier, even = its capture's), so an
    // even-only fault fires EXCLUSIVELY in the capture-verification
    // catch and cannot be rescued by a later row's receipt catch
    await rejects("an adapter fault during capture verification propagates (the second catch classifies by origin too)",
      runLedger({ ...wLate, deps: { ...wLate.deps, verifierDeps: { ...wLate.deps.verifierDeps,
        verifyStageOne: async (...a) => { stageCalls += 1;
          if (stageCalls % 2 === 0) throw new Error("helper offline late");
          return baseStage(...a); } } } }),
      /helper offline late/);
  }
  {
    // the adverse identity answers ISOLATED PER ROW: whichever single row
    // carries the absence or the wrong identity, formation reacts (no
    // row's answer can be ignored)
    for (const target of [FA, FB, FC]) {
      const wAbs = mkWorld({ provedByKey: (base) => async (type, key) =>
        type === "identity" && key.identityId === target
          ? { status: "proved-absence", height: "892" } : base(type, key) });
      const fAbs = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: wAbs.deps });
      ok(`a proved absence for ${target.slice(0, 6)}... alone refuses formation and names that row`,
        fAbs.label === "REFUSED" && fAbs.reason.includes(target.slice(0, 8)));
      const wWrong = mkWorld({ provedByKey: (base) => async (type, key) =>
        type === "identity" && key.identityId === target
          ? { status: "served", doc: { id: target === FA ? FB : FA }, height: "892" }
          : base(type, key) });
      await rejects(`a wrong identity served for ${target.slice(0, 6)}... alone refuses hard`,
        evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: wWrong.deps }),
        /DIFFERENT identity/);
    }
  }
  {
    const w = mkWorld();
    const wrongOwner = { ...w.fr, "$ownerId": OB };
    const wDeps = { ...w.deps, provedByKey: async (type, key) =>
      type === "completionReceipt" ? { status: "served", doc: wrongOwner, height: "891" }
        : w.deps.provedByKey(type, key) };
    const f = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: wDeps });
    ok("a receipt owned by a different identity refuses the six-duty pair check",
      f.label === "REFUSED" && /pair check/.test(f.reason));
    // a FOREIGN-POOL completion receipt is a nonconforming answer, so
    // its height never enters the range (round-46)
    const wFor = mkWorld();
    const foreignFr = { ...wFor.fr, poolId: Buffer.from(h32("77"), "hex") };
    const fFor = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC,
      deps: { ...wFor.deps, provedByKey: async (type, key) =>
        type === "completionReceipt" ? { status: "served", doc: foreignFr, height: "999999" }
          : wFor.deps.provedByKey(type, key) } });
    ok("a foreign-pool completion receipt refuses AND its height is withheld from the range",
      fFor.label === "REFUSED" && /different pool/.test(fFor.reason)
      && !fFor.heights.includes("999999") && fFor.heights.includes("890"));
  }
  {
    const w = mkWorld();
    const c = await evaluateContractIntegrity({ contractId: GC,
      expectedContractPayload: w.deps.expectedContractPayload, deps: w.deps });
    ok("the matching proved contract read is PROVED", c.label === "PROVED");
    const c2 = await evaluateContractIntegrity({ contractId: GC,
      expectedContractPayload: { version: "v11", documentTypes: [] }, deps: w.deps });
    ok("a diverging contract refuses (it prevents a conformance grade)",
      c2.label === "REFUSED" && /diverges/.test(c2.reason));
    const c2v = await evaluateContractIntegrity({ contractId: GC,
      expectedContractPayload: { ...w.deps.expectedContractPayload, version: "v12" }, deps: w.deps });
    ok("a VERSION-only divergence refuses too (every contract-defined member counts)",
      c2v.label === "REFUSED");
    const nested = JSON.parse(JSON.stringify(w.deps.expectedContractPayload));
    nested.documents.pool.required = ["nodeType"];
    const c2n = await evaluateContractIntegrity({ contractId: GC,
      expectedContractPayload: nested, deps: w.deps });
    ok("a NESTED-member divergence refuses (comparison recurses into nested members, not a top-level shortlist)",
      c2n.label === "REFUSED");
    // divergence in members OUTSIDE any plausible shortlist (round-60):
    // canonical equality covers EVERY contract-defined member, so an extra
    // top-level member and an extra nested member both refuse
    const cExtraTop = await evaluateContractIntegrity({ contractId: GC,
      expectedContractPayload: { ...w.deps.expectedContractPayload, extraRule: "x" }, deps: w.deps });
    ok("an extra top-level member outside any plausible shortlist refuses (this fixture's member, not a proof of totality)",
      cExtraTop.label === "REFUSED");
    const nestedExtra = JSON.parse(JSON.stringify(w.deps.expectedContractPayload));
    nestedExtra.documents.pool.indices = [["slotIndex"]];
    const cExtraNested = await evaluateContractIntegrity({ contractId: GC,
      expectedContractPayload: nestedExtra, deps: w.deps });
    ok("an extra nested member outside the required list refuses (this fixture's nested member)",
      cExtraNested.label === "REFUSED");
    const c3 = await evaluateContractIntegrity({ contractId: GC,
      expectedContractPayload: w.deps.expectedContractPayload,
      deps: { ...w.deps, provedByKey: async () => ({ status: "unverified" }) } });
    ok("an unverified contract read is UNPROVED", c3.label === "UNPROVED");
    // the malformed-payload refusal cannot be SIDESTEPPED by the adapter's
    // answer (round-61): a malformed REQUEST is a property of the request
    // alone, so the supplied payload is validated BEFORE the read and on
    // every path. This case previously reached UNPROVED with the payload
    // never examined (the fixture above supplied the FETCHED shape, envelope
    // included, and the unverified answer returned before the check).
    for (const [what, answer] of [["unverified", { status: "unverified" }],
      ["unserved", { status: "unserved" }],
      ["proved-absent", { status: "proved-absence", height: "889" }]]) {
      await rejects(`a malformed supplied payload is refused even when the contract read is ${what}`,
        evaluateContractIntegrity({ contractId: GC,
          expectedContractPayload: { ...w.deps.expectedContractPayload, $policy: true },
          deps: { ...w.deps, provedByKey: async () => answer } }),
        /system-namespace members/);
    }
    // an UNRECOGNIZED $-member on the FETCHED document is a divergence the
    // comparison cannot account for, never a member to drop silently
    // (round-61): stripping by the $ prefix made this document compare equal
    // to the expected payload, because the extra member disappeared first.
    const cFetchedExtra = await evaluateContractIntegrity({ contractId: GC,
      expectedContractPayload: w.deps.expectedContractPayload,
      deps: { ...w.deps, provedByKey: async () => ({ status: "served", height: "889",
        doc: { ...w.contractPayload, $policy: { rule: "an unaccounted-for member" } } }) } });
    ok("an unrecognized system-namespace member on the fetched contract refuses, never dropped",
      cFetchedExtra.label === "REFUSED" && /outside the known platform envelope/.test(cFetchedExtra.reason));
    // and a RECOGNIZED envelope member is still stripped, so an ordinary
    // fetched document with its envelope still proves. EVERY listed member is
    // exercised (round-62): a list entry no gate reaches is an unchecked
    // assumption about the platform's envelope, and the round-61 list carried
    // four such entries, two of which a data contract can legitimately use as
    // real content.
    const ENVELOPE_UNDER_TEST = { $ownerId: h32("a1"), $revision: 3,
      $createdAt: 1690000000000, $updatedAt: 1690000000001,
      $createdAtBlockHeight: 12, $updatedAtBlockHeight: 13,
      $createdAtCoreBlockHeight: 14, $updatedAtCoreBlockHeight: 15 };
    for (const [member, value] of Object.entries(ENVELOPE_UNDER_TEST)) {
      const cOne = await evaluateContractIntegrity({ contractId: GC,
        expectedContractPayload: w.deps.expectedContractPayload,
        deps: { ...w.deps, provedByKey: async () => ({ status: "served", height: "889",
          doc: { ...w.contractPayload, [member]: value } }) } });
      ok(`the envelope member ${member} is recognized and stripped, so the contract still proves`,
        cOne.label === "PROVED");
    }
    const cEnvelopeOk = await evaluateContractIntegrity({ contractId: GC,
      expectedContractPayload: w.deps.expectedContractPayload,
      deps: { ...w.deps, provedByKey: async () => ({ status: "served", height: "889",
        doc: { ...w.contractPayload, ...ENVELOPE_UNDER_TEST } }) } });
    ok("the whole recognized envelope together is stripped, so an ordinary fetched contract proves",
      cEnvelopeOk.label === "PROVED");
    // members the list deliberately does NOT carry, including two a data
    // contract can legitimately use as its own content, refuse rather than
    // being dropped (round-62): stripping those would hide a divergence in
    // the very document this aspect compares
    for (const member of ["$schema", "$defs", "$version", "$format_version", "$future"]) {
      const cUnknown = await evaluateContractIntegrity({ contractId: GC,
        expectedContractPayload: w.deps.expectedContractPayload,
        deps: { ...w.deps, provedByKey: async () => ({ status: "served", height: "889",
          doc: { ...w.contractPayload, [member]: "an unaccounted-for value" } }) } });
      ok(`the unlisted member ${member} refuses rather than being stripped`,
        cUnknown.label === "REFUSED" && /outside the known platform envelope/.test(cUnknown.reason));
    }
    // the SUPPLIED-payload refusal is over the $ PREFIX, not over one name
    for (const member of ["$policy", "$futurePolicy", "$id", "$ownerId"]) {
      await rejects(`a supplied payload carrying ${member} is refused (the prefix rule, not a name list)`,
        evaluateContractIntegrity({ contractId: GC,
          expectedContractPayload: { ...w.deps.expectedContractPayload, [member]: true },
          deps: w.deps }),
        /system-namespace members/);
    }
    // a supplied payload carrying a $-member cannot slip a difference past
    // the comparison by being stripped (round-55, F4): a registration
    // payload has no system-namespace members, so a supplied $-member is
    // refused rather than dropped. Without this, a supplied "$policy" absent
    // from the fetched contract would compare equal (both stripped).
    await rejects("a supplied registration payload carrying a $-member is refused, not silently stripped",
      evaluateContractIntegrity({ contractId: GC,
        expectedContractPayload: { ...w.deps.expectedContractPayload, $policy: true }, deps: w.deps }),
      /system-namespace members/);
    // a revoked-proxy payload passed DIRECTLY to the exported evaluator is
    // refused cleanly (round-57): the Array.isArray classification throws on a
    // revoked proxy and is guarded, so it refuses rather than escaping raw.
    const revC = Proxy.revocable({ version: "v11" }, {}); revC.revoke();
    await rejects("a revoked-proxy expected payload is refused, never an escaping raw TypeError",
      evaluateContractIntegrity({ contractId: GC, expectedContractPayload: revC.proxy, deps: w.deps }),
      /needs the supplied registration payload/);
    // a PROXY payload cannot fake contract equality: its descriptors report
    // a DIVERGENT payload (which the walk captures and the comparison then
    // uses), while its get trap would serve the matching members to
    // canonicalString. Because the comparison reads the captured copy, the
    // divergence stands and the aspect refuses; a validate-then-reread
    // would have compared the get-trap members and passed vacuously
    // (round-53, finding 1).
    {
      const matching = w.deps.expectedContractPayload;
      const divergent = { ...matching, version: "v12" };
      const proxyPayload = new Proxy(divergent, { get(t, k, r) {
        return Object.prototype.hasOwnProperty.call(matching, k) ? matching[k] : Reflect.get(t, k, r);
      } });
      const cP = await evaluateContractIntegrity({ contractId: GC,
        expectedContractPayload: proxyPayload, deps: w.deps });
      ok("a Proxy payload's captured (divergent) members govern the comparison, so it cannot fake equality through its get trap",
        cP.label === "REFUSED" && /diverges/.test(cP.reason));
    }
  }
  {
    const w = mkWorld();
    const receipt = w.receipts[0];
    ok("a served conforming reservation is PROVED",
      evaluateReservationPresence(receipt, { status: "served",
        doc: w.reservations[0], height: "902" }).label === "PROVED");
    ok("a served reservation with a differing transitionHash refuses (a soundness-review finding)",
      evaluateReservationPresence(receipt, { status: "served",
        doc: { ...w.reservations[0], transitionHash: h32("99") }, height: "902" }).label === "REFUSED");
    ok("a proved reservation absence refuses (a soundness-review finding)",
      evaluateReservationPresence(receipt, { status: "proved-absence", height: "902" }).label === "REFUSED");
    ok("an unservable reservation query is UNPROVED, never a refusal and never a pass",
      evaluateReservationPresence(receipt, { status: "unserved" }).label === "UNPROVED");
    ok("a served reservation with the right hash but a FOREIGN pool refuses (a soundness-review finding)",
      evaluateReservationPresence(receipt, { status: "served",
        doc: { ...w.reservations[0], poolId: h32("99") }, height: "915" }).label === "REFUSED");
    ok("a served reservation naming a DIFFERENT accrual refuses (a soundness-review finding)",
      evaluateReservationPresence(receipt, { status: "served",
        doc: { ...w.reservations[0], accrualId: h32("a1") }, height: "915" }).label === "REFUSED");
    throwsSync("the EXPORTED evaluator validates its own answer boundary (no height, no verdict)",
      () => evaluateReservationPresence(receipt, { status: "served", doc: w.reservations[0] }),
      /authenticated height/);
    // a REVOKED-Proxy answer passed DIRECTLY to the exported evaluator is
    // refused cleanly (round-57): requireAnswer's Array.isArray classification
    // throws on a revoked proxy, so it is guarded, and the answer is rejected
    // as a non-plain envelope rather than escaping as a raw TypeError.
    {
      const rev = Proxy.revocable({ status: "served" }, {}); rev.revoke();
      throwsSync("a revoked-proxy answer is refused as a non-plain envelope, never an escaping raw TypeError",
        () => evaluateReservationPresence(receipt, rev.proxy),
        /no plain answer envelope/);
    }
    // a PROXY answer defeats validate-then-reread: its descriptors report a
    // CONFORMING served doc (which the walk validates and captures) while
    // its get trap would serve a foreign-pool doc that refuses. The
    // exported evaluator must judge on the captured conforming doc, so a
    // get-trap divergence cannot substitute unchecked evidence for the
    // validated answer (round-53, finding 1).
    {
      const conforming = w.reservations[0];
      const divergent = { ...w.reservations[0], poolId: h32("99") };
      const target = { status: "served", doc: conforming, height: "902" };
      const proxyAns = new Proxy(target, { get(t, k, r) {
        if (k === "doc") return divergent;
        return Reflect.get(t, k, r);
      } });
      ok("a Proxy reservation answer is judged on the CAPTURED conforming doc, not its divergent get-trap value",
        evaluateReservationPresence(receipt, proxyAns).label === "PROVED");
    }
  }
  {
    // ASPECT SEPARATION: the transfer-execution predicate EXCLUDES the
    // reservation checks, so a proved-absent reservation refuses ITS
    // aspect while the transfer aspect still verifies
    const w = mkWorld();
    const receipt = w.receipts[0];
    const t = await evaluateTransferExecution({ receipt, parts: [],
      entitlementRow: { recipientId: FA, amountCredits: "400000" },
      accrual: w.accruals[0], headerFor: w.docs.header[0], incomeIdentity: INCOME, chainIdPin: CHAIN,
      capture: w.captures[0], supersessions: [], deps: w.deps });
    ok("the golden receipt earns CAPTURE-VERIFIED", t.label === "CAPTURE-VERIFIED");
    const noCap = await evaluateTransferExecution({ receipt, parts: [],
      entitlementRow: { recipientId: FA, amountCredits: "400000" },
      accrual: w.accruals[0], headerFor: w.docs.header[0], incomeIdentity: INCOME, chainIdPin: CHAIN,
      capture: null, supersessions: [], deps: w.deps });
    ok("a receipt without its served capture refuses (the capture IS the execution evidence)",
      noCap.label === "REFUSED" && /capture/.test(noCap.reason));
    const noBasis = await evaluateTransferExecution({ receipt, parts: [],
      entitlementRow: { recipientId: FA, amountCredits: "400000" },
      accrual: w.accruals[0], headerFor: w.docs.header[0], incomeIdentity: INCOME, chainIdPin: CHAIN,
      capture: w.captures[0], supersessions: [],
      deps: { ...w.deps, verifyCaptureBasis: async () => false } });
    ok("a capture without a verifying signature basis refuses (validity clause 1)",
      noBasis.label === "REFUSED" && /clause 1/.test(noBasis.reason));
    // the transfer evaluator's OWN capture-basis catch formats the caught
    // value totally (round-58, F1): a null-prototype thrown value is a clean
    // adapter-fault Error here (line reached directly, not via the header
    // capture check), never an escaping raw TypeError.
    await rejects("a capture-basis adapter throwing a null-prototype value refuses the transfer with a clean Error, never an escaping raw TypeError",
      evaluateTransferExecution({ receipt, parts: [],
        entitlementRow: { recipientId: FA, amountCredits: "400000" },
        accrual: w.accruals[0], headerFor: w.docs.header[0], incomeIdentity: INCOME, chainIdPin: CHAIN,
        capture: w.captures[0], supersessions: [],
        deps: { ...w.deps, verifyCaptureBasis: async () => { throw Object.create(null); } } }),
      /capture-basis adapter failed/);
    const noHeader = await evaluateTransferExecution({ receipt, parts: [],
      entitlementRow: { recipientId: FA, amountCredits: "400000" },
      accrual: w.accruals[0], headerFor: null, incomeIdentity: INCOME, chainIdPin: CHAIN,
      capture: w.captures[0], supersessions: [], deps: w.deps });
    ok("a receipt whose epoch has no header refuses (the RELATIONAL subset)",
      noHeader.label === "REFUSED" && /RELATIONAL/.test(noHeader.reason));
    const wrongAmount = await evaluateTransferExecution({ receipt, parts: [],
      entitlementRow: { recipientId: FA, amountCredits: "400001" },
      accrual: w.accruals[0], headerFor: w.docs.header[0], incomeIdentity: INCOME, chainIdPin: CHAIN,
      capture: w.captures[0], supersessions: [], deps: w.deps });
    ok("a decoded amount differing from the recomputed entitlement refuses",
      wrongAmount.label === "REFUSED" && /entitlement/.test(wrongAmount.reason));
    const wrongRecipient = await evaluateTransferExecution({ receipt, parts: [],
      entitlementRow: { recipientId: FB, amountCredits: "400000" },
      accrual: w.accruals[0], headerFor: w.docs.header[0], incomeIdentity: INCOME, chainIdPin: CHAIN,
      capture: w.captures[0], supersessions: [], deps: w.deps });
    ok("a decoded recipient differing from the entitlement's owner refuses (the right amount cannot cover it)",
      wrongRecipient.label === "REFUSED" && /recipient/.test(wrongRecipient.reason));
    const wrongHeader = await evaluateTransferExecution({ receipt, parts: [],
      entitlementRow: { recipientId: FA, amountCredits: "400000" },
      accrual: w.accruals[0], headerFor: w.docs.header[1], incomeIdentity: INCOME, chainIdPin: CHAIN,
      capture: w.captures[0], supersessions: [], deps: w.deps });
    ok("a header from a DIFFERENT epoch refuses the relational subset",
      wrongHeader.label === "REFUSED" && /RELATIONAL/.test(wrongHeader.reason));
    const wrongAccrual = await evaluateTransferExecution({ receipt, parts: [],
      entitlementRow: { recipientId: FA, amountCredits: "400000" },
      accrual: w.accruals[1], headerFor: w.docs.header[0], incomeIdentity: INCOME, chainIdPin: CHAIN,
      capture: w.captures[0], supersessions: [], deps: w.deps });
    ok("an accrual the receipt does not name refuses the relational subset",
      wrongAccrual.label === "REFUSED" && /different accrual/.test(wrongAccrual.reason));
    const foreignPoolAccrual = await evaluateTransferExecution({ receipt, parts: [],
      entitlementRow: { recipientId: FA, amountCredits: "400000" },
      accrual: { ...w.accruals[0], poolId: h32("99") },
      headerFor: { ...w.docs.header[0], poolId: h32("99") },
      incomeIdentity: INCOME, chainIdPin: CHAIN,
      capture: w.captures[0], supersessions: [], deps: w.deps });
    ok("an accrual naming a foreign pool refuses the relational subset",
      foreignPoolAccrual.label === "REFUSED" && /pool differs from its accrual/.test(foreignPoolAccrual.reason));
    const pairBroken = await evaluateTransferExecution({ receipt, parts: [],
      entitlementRow: { recipientId: FA, amountCredits: "400000" },
      accrual: w.accruals[0], headerFor: w.docs.header[0], incomeIdentity: INCOME, chainIdPin: CHAIN,
      capture: { ...w.captures[0], metadataMsg: metaHexOf(6) }, supersessions: [], deps: w.deps });
    ok("a capture whose bytes diverge from the receipt refuses (the pair equality set)",
      pairBroken.label === "REFUSED");
  }
  {
    const w = mkWorld();
    const receipt = w.receipts[0];
    const base = { receipt, receiptCaptureValid: true, capture: w.captures[0],
      headerCaptureValid: true, headerCapture: w.headerCaps[0] };
    ok("the golden ordering earns ATTESTED", evaluateOrdering(base).label === "ATTESTED");
    ok("a missing receipt capture degrades to OPERATOR-PROVIDED, never refuses",
      evaluateOrdering({ ...base, capture: null, receiptCaptureValid: false }).label === "OPERATOR-PROVIDED");
    ok("an invalid header capture degrades to OPERATOR-PROVIDED",
      evaluateOrdering({ ...base, headerCaptureValid: false }).label === "OPERATOR-PROVIDED");
    ok("differing height routes degrade (same-route equality is the testable form)",
      evaluateOrdering({ ...base, headerCapture: { ...w.headerCaps[0], heightRoute: "other-route" } }).label === "OPERATOR-PROVIDED");
    ok("routes sharing a prefix but differing at the tail are different routes (round-60)",
      evaluateOrdering({ ...base, headerCapture: { ...w.headerCaps[0], heightRoute: "tenderdash-txx" } }).label === "OPERATOR-PROVIDED");
    ok("an inclusion height EQUAL to the header's degrades (strictly greater is required)",
      evaluateOrdering({ ...base, capture: { ...w.captures[0], inclusionHeight: "1000" } }).label === "OPERATOR-PROVIDED");
    ok("an inclusion height BELOW the header's degrades too (never attested by inequality alone)",
      evaluateOrdering({ ...base, capture: { ...w.captures[0], inclusionHeight: "999" } }).label === "OPERATOR-PROVIDED");
    ok("a valid capture for a DIFFERENT transition degrades (the hash binds the subject)",
      evaluateOrdering({ ...base, capture: { ...w.captures[0], transitionHash: h32("55") } }).label === "OPERATOR-PROVIDED");
  }

  // ---- the record-set evaluation over the golden world ----
  {
    const w = mkWorld();
    const led = await runLedger(w);
    ok("the golden world's record set is READ-CHECKED with no diagnostics on ANY channel",
      led.recordSet.label === "READ-CHECKED" && led.diagnostics.extras.length === 0
      && led.diagnostics.orphans.length === 0 && led.diagnostics.poolGlobal.length === 0
      && led.refusals.length === 0
      && [...led.perEpoch.values()].every((r) => r.diagnostics.length === 0));
    ok("the golden world's lag is zero with a zero undistributed sum",
      led.lag.lagCount === 0 && led.lag.undistributedCredits === "0");
    ok("the per-receipt aggregates: transfer at CAPTURE-VERIFIED capped by the zero epoch's inheritance",
      led.aggregates.transferExecution === "READ-CHECKED"
      && led.aggregates.reservationPresence === "READ-CHECKED");
    ok("ordering aggregates to ATTESTED (weaker than the zero epoch's READ-CHECKED)",
      led.aggregates.ordering === "ATTESTED");
    const e5 = led.perEpoch.get(5), e6 = led.perEpoch.get(6);
    ok("epoch 5 carries r 0 and no condition; epoch 6 is the named zero-earning condition",
      e5.condition === null && e5.r === "0" && e6.condition === "zero-earning-epoch" && e6.r === "0");
  }
  {
    const w = mkWorld({ mutateDocs: (docs) => { docs.header[0].grossCredits = 999999; } });
    const led = await runLedger(w);
    ok("a header field differing from the recomputation refuses the record set",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /grossCredits/.test(d)));
  }
  {
    const w = mkWorld({ mutateDocs: (docs) => { docs.accrual.push({ id: h32("f7"),
      poolId: POOL_HEX, epochIndex: 5, funderId: h32("77"), amountCredits: 5 }); } });
    const led = await runLedger(w);
    ok("an accrual outside the recomputed set is a fetched extra and refuses, named as one",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /fetched extra/.test(d)));
    const w2 = mkWorld({ mutateDocs: (docs) => { docs.accrual[0].amountCredits = 400001; } });
    const led2 = await runLedger(w2);
    ok("an accrual amount differing from the recomputation refuses as a mismatch",
      led2.recordSet.label === "REFUSED"
      && led2.perEpoch.get(5).diagnostics.some((d) => /differs from the recomputed/.test(d)));
  }
  {
    // a NULL-PROTOTYPE field value is inside the plain-data domain the
    // boundary accepts (a null prototype is permitted), so it reaches the
    // recompute diagnostics; a raw `${value}` interpolation of it throws
    // an untyped TypeError (no toString) instead of the intended record-set
    // refusal (round-53, finding 2). scalarShow routes only the
    // non-primitive case through the safe stringifier, so the mismatch
    // yields a clean REFUSED, and a real integer field reads unchanged.
    const wMc = mkWorld({ mutateDocs: (docs) => { docs.header[0].memberCount = Object.create(null); } });
    const ledMc = await runLedger(wMc);
    ok("a header carrying a null-prototype memberCount refuses the record set, never throwing in the mismatch diagnostic",
      ledMc.recordSet.label === "REFUSED"
      && ledMc.perEpoch.get(5).diagnostics.some((d) => /header mismatch: memberCount/.test(d)));
    const wAmt = mkWorld({ mutateDocs: (docs) => { docs.accrual[0].amountCredits = Object.create(null); } });
    const ledAmt = await runLedger(wAmt);
    ok("an accrual carrying a null-prototype amount refuses the record set, never throwing in the mismatch diagnostic",
      ledAmt.recordSet.label === "REFUSED"
      && ledAmt.perEpoch.get(5).diagnostics.some((d) => /accrual amount \{\} differs from the recomputed/.test(d)));
    // the structural SLOT construction on the unavailable path is the third
    // unguarded interpolation: a null-prototype epoch index is flagged by
    // the grammar sweep, and the slot loop must skip it rather than
    // interpolate it into an untyped throw before the structural refusal
    // returns (round-53, finding 2)
    const wSlot = mkWorld({ mutateDocs: (docs) => { docs.accrual[0].epochIndex = Object.create(null); } });
    const ledSlot = await runLedger(wSlot, { formation: { label: "UNPROVED" } });
    ok("a null-prototype epoch index refuses structurally on the unavailable path, never throwing in the slot construction",
      ledSlot.recordSet.label === "REFUSED"
      && ledSlot.diagnostics.poolGlobal.some((d) => /malformed epoch index/.test(d)));
    // the SAME class at the other forward-pass diagnostics (round-54): a
    // null-prototype calcVersion, allocationHash or funder identifier the
    // plain-data domain admits must refuse cleanly, not throw in a raw
    // interpolation or String() conversion
    const wCv = mkWorld({ mutateDocs: (docs) => { docs.header[0].calcVersion = Object.create(null); } });
    const ledCv = await runLedger(wCv);
    ok("a null-prototype calcVersion refuses the record set, never throwing in the mismatch diagnostic",
      ledCv.recordSet.label === "REFUSED"
      && ledCv.perEpoch.get(5).diagnostics.some((d) => /header mismatch: .*calcVersion/.test(d)));
    const wAh = mkWorld({ mutateDocs: (docs) => { docs.header[0].allocationHash = Object.create(null); } });
    const ledAh = await runLedger(wAh);
    ok("a null-prototype allocationHash refuses the record set, never throwing in String()",
      ledAh.recordSet.label === "REFUSED"
      && ledAh.perEpoch.get(5).diagnostics.some((d) => /header mismatch: .*allocationHash/.test(d)));
    const wFn = mkWorld({ mutateDocs: (docs) => { docs.accrual.push({ id: h32("f6"),
      poolId: POOL_HEX, epochIndex: 5, funderId: Object.create(null), amountCredits: 1 }); } });
    const ledFn = await runLedger(wFn);
    ok("a null-prototype funder identifier on an extra accrual refuses cleanly, never throwing in String()",
      ledFn.recordSet.label === "REFUSED"
      && ledFn.perEpoch.get(5).diagnostics.some((d) => /outside the recomputed set/.test(d)));
  }
  {
    const w = mkWorld({ mutateDocs: (docs) => { docs.receipt.push({ ...docs.receipt[0],
      id: h32("f8"), accrualId: h32("f9") }); } });
    const led = await runLedger(w);
    ok("a receipt naming a nonexistent accrual is an ORPHAN, a pool-global failure",
      led.recordSet.label === "REFUSED" && led.diagnostics.orphans.length === 1
      && led.diagnostics.poolGlobal.some((d) => /orphan/.test(d)));
  }
  {
    const w = mkWorld({ mutateDocs: (docs) => { docs.header.push({ id: h32("fa"),
      poolId: POOL_HEX, epochIndex: 40, grossCredits: 1, feeCredits: 0,
      memberCount: 3, calcVersion: 1 }); } });
    const led = await runLedger(w);
    ok("a record resolving outside the validation domain is an EXTRA and refuses",
      led.recordSet.label === "REFUSED"
      && led.diagnostics.extras.some((d) => /epoch 40/.test(d)));
  }
  {
    // a DEPENDENT whose accrual resolves OUTSIDE the validation domain is
    // an extra identified by its own type: the reverse classification
    // runs for the three dependent enumerations, not only for headers
    // and accruals
    const w = mkWorld({ mutateDocs: (docs) => {
      const far = { id: h32("e0"), poolId: docs.header[0].poolId, epochIndex: 40,
        funderId: docs.accrual[0].funderId, amountCredits: 1 };
      docs.accrual.push(far);
      docs.reservation.push({ ...docs.reservation[0], id: h32("e1"), accrualId: far.id });
      docs.receipt.push({ ...docs.receipt[0], id: h32("e2"), accrualId: far.id });
      docs.part.push({ id: h32("e3"), poolId: docs.header[0].poolId, accrualId: far.id });
    } });
    const led = await runLedger(w);
    ok("a dependent resolving outside the validation domain is an EXTRA, per dependent type",
      led.recordSet.label === "REFUSED"
      && ["reservation", "receipt", "part"].every((t) =>
        led.diagnostics.extras.some((d) => d.startsWith(`${t} `) && /epoch 40/.test(d))));
  }
  {
    // a NARROWED interval: records inside U but outside I are IGNORED
    // after resolution, for all five types
    const w = mkWorld();
    const resolution = await resolveInterval({ requestedStart: 5, requestedEnd: 5,
      configuredStart: 5, fetchRange: w.deps.fetchRange });
    const led = await runLedger(w, { resolution });
    ok("records inside the universe but outside a narrowed interval are ignored, not extras",
      led.recordSet.label === "READ-CHECKED" && led.diagnostics.extras.length === 0
      && resolution.coverage.narrowedRange === true);
  }
  {
    // a missing receipt: proved absence refuses AND the amount counts
    // undistributed, the epoch counts lagging
    const w = mkWorld({ mutateDocs: (docs) => { docs.receipt.splice(1, 1); } });
    const led = await runLedger(w);
    ok("a proved-absent expected receipt refuses and the epoch counts lagging",
      led.recordSet.label === "REFUSED" && led.lag.lagCount === 1
      && led.lag.undistributedCredits === "240000");
    ok("the proved ABSENCE's proof height enters the range (absence proofs are real proofs)",
      led.heightCandidates.includes("916"));
    const wTwo = mkWorld({ mutateDocs: (docs) => {
      docs.receipt = docs.receipt.filter((r) => r.accrualId === docs.accrual[1].id);
    } });
    const ledTwo = await runLedger(wTwo);
    ok("the undistributed sum is the exact per-row bookkeeping (two named failures, 560000)",
      ledTwo.lag.undistributedCredits === "560000");
    ok("the missing row CONTRIBUTES to the aggregates (never an unexamined affirmative; the zero epoch inherits the refused record-set label, so ordering lands at REFUSED through the empty-set identity)",
      led.aggregates.transferExecution === "REFUSED"
      && led.aggregates.ordering === "REFUSED");
    // the same world over [5, 5]: no empty epoch's inheritance can mask
    // the missing row's own contribution
    const narrow = await resolveInterval({ requestedStart: 5, requestedEnd: 5,
      configuredStart: 5, fetchRange: w.deps.fetchRange });
    const ledN = await runLedger(w, { resolution: narrow });
    ok("the missing row's contribution stands alone in a narrowed interval",
      ledN.aggregates.transferExecution === "REFUSED");
    // an enumerated reservation beside a pinned PROVED ABSENCE: the
    // absence's proof height still enters the range (round-13 finding 1)
    const wAbs = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "reservationByAccrual"
        ? { status: "proved-absence", height: "2000" } : base(type, key) });
    const ledAbs = await runLedger(wAbs);
    ok("a pinned proved absence beside an enumerated reservation refuses AND contributes its proof height",
      ledAbs.recordSet.label === "REFUSED" && ledAbs.heightCandidates.includes("2000"));
  }
  {
    // an UNSERVED known-key query: UNPROVED, never refused, range nulled
    const w = mkWorld({ mutateDocs: (docs) => { docs.receipt.splice(1, 1); },
      provedByKey: (base) => async (type, key) =>
        type === "receiptByAccrual" ? { status: "unserved" } : base(type, key) });
    const led = await runLedger(w);
    ok("an unserved known-key query leaves the aspect UNPROVED with the records range withheld",
      led.recordSet.label === "UNPROVED" && led.recordsProved === false);
  }
  {
    // an invalid receipt capture (wrong basis) breaks completeness: the
    // transfer aspect refuses, lag counts, undistributed accumulates
    const w = mkWorld({ verifyCaptureBasis: async () => false });
    const led = await runLedger(w);
    ok("unverifiable captures refuse the transfer aspect and count every amount undistributed",
      led.aggregates.transferExecution === "REFUSED" && led.lag.lagCount === 1
      && led.lag.undistributedCredits === "800000");
    ok("ordering degrades to OPERATOR-PROVIDED under the same failed basis, never refusing",
      led.aggregates.ordering === "OPERATOR-PROVIDED");
  }
  {
    // prefix accruals must be ZERO with no dependent records
    const w = mkWorld({ provedActivation: 5,
      mutateDocs: (docs) => {
        docs.accrual.push({ id: h32("f4"), poolId: POOL_HEX, epochIndex: 4, funderId: FA, amountCredits: 7 });
        docs.receipt.push({ ...docs.receipt[0], id: h32("f5"), accrualId: h32("f4") });
      },
      fetchRange: async (start, end) => ({ epochs: [
        { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const resolution = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: w.deps.fetchRange });
    const led = await runLedger(w, { resolution });
    const d4 = led.perEpoch.get(4).diagnostics;
    ok("a nonzero prefix accrual and its transfer records refuse (zero-earning epochs have neither)",
      led.recordSet.label === "REFUSED"
      && d4.some((x) => /prefix accrual does not carry an integer-zero amount/.test(x))
      && d4.some((x) => /transfer records exist under a prefix accrual/.test(x)));
  }
  {
    // the prefix's zero-earning shape is complete: nonzero fees, unknown
    // funders and malformed proposer counts all surface
    const mk = (extra, fetchEpoch4) => mkWorld({ provedActivation: 5,
      mutateDocs: extra,
      fetchRange: async (start, end) => ({ epochs: [
        fetchEpoch4,
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const e4 = { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
      coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 };
    const res = async (w) => runLedger(w, { resolution: await resolveInterval({
      requestedStart: 4, requestedEnd: null, configuredStart: 5, provedActivation: 5,
      fetchRange: w.deps.fetchRange }) });
    const wFee = mk((docs) => { docs.header.push({ id: h32("f6"), poolId: POOL_HEX,
      epochIndex: 4, grossCredits: 0, feeCredits: 5, memberCount: 3, calcVersion: 1 }); }, e4);
    const ledFee = await res(wFee);
    ok("a prefix header with nonzero feeCredits refuses",
      ledFee.recordSet.label === "REFUSED"
      && ledFee.perEpoch.get(4).diagnostics.some((x) => /does not carry integer-zero credits/.test(x)));
    for (const [name, memberOverride] of [
      ["memberCount", { memberCount: 999 }],
      ["calcVersion", { calcVersion: 2 }],
      ["allocationHash", { allocationHash: "bb".repeat(32) }],
    ]) {
      const wIso = mk((docs) => { docs.header.push({ id: h32("f6"), poolId: POOL_HEX,
        epochIndex: 4, grossCredits: 0, feeCredits: 0, memberCount: 3, calcVersion: 1,
        allocationHash: docs.header[0].allocationHash, ...memberOverride }); }, e4);
      const ledIso = await res(wIso);
      ok(`a prefix header with only ${name} foreign refuses (each member held separately)`,
        ledIso.recordSet.label === "REFUSED"
        && ledIso.perEpoch.get(4).diagnostics.some((x) => /calcVersion, memberCount or allocationHash/.test(x)));
    }
    const wStrange = mk((docs) => { docs.accrual.push({ id: h32("f9"), poolId: POOL_HEX,
      epochIndex: 4, funderId: h32("88"), amountCredits: 0 }); }, e4);
    const ledStrange = await res(wStrange);
    ok("a prefix accrual for a funder outside the allocation refuses",
      ledStrange.recordSet.label === "REFUSED"
      && ledStrange.perEpoch.get(4).diagnostics.some((x) => /outside the allocation/.test(x)));
    const wPc = mk(null, { number: 4, totalProcessingFees: "1",
      totalDistributedStorageFees: "0", coreBlockRewards: "0", totalBlocks: "100" });
    const ledPc = await res(wPc);
    ok("a prefix epoch with a MISSING proposer count is an in-report refusal, never verified-zero",
      ledPc.refusals.some((x) => /proposer count is malformed/.test(x)));
  }
  {
    // the prefix: an explicit earlier start with proved activation; the
    // prefix epoch is zero-earning and clean
    const w = mkWorld({ provedActivation: 5,
      fetchRange: async (start, end) => ({ epochs: [
        { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const resolution = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: w.deps.fetchRange });
    const led = await runLedger(w, { resolution });
    ok("a clean pre-activation prefix epoch passes its zero-earning verification",
      led.refusals.length === 0 && led.recordSet.label === "READ-CHECKED");
  }
  {
    // a prefix epoch with a nonzero proposer count is an IN-REPORT refusal
    const w = mkWorld({ provedActivation: 5,
      fetchRange: async (start, end) => ({ epochs: [
        { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 2 },
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const resolution = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: w.deps.fetchRange });
    const led = await runLedger(w, { resolution });
    ok("a prefix epoch failing zero-earning is an in-report refusal (grammar step 1)",
      led.refusals.length === 1 && /zero-earning/.test(led.refusals[0]));
  }
  {
    // an unproved enumeration: the whole record set is UNPROVED and the
    // per-receipt aspects inherit
    const w = mkWorld({ fetchVerifiedPage: async () => ({ status: "unserved" }) });
    const led = await runLedger(w);
    ok("an unproved enumeration leaves the record set and per-receipt aspects UNPROVED",
      led.recordSet.label === "UNPROVED" && led.aggregates.transferExecution === "UNPROVED"
      && led.lag === null && led.recordsProved === false);
  }

  {
    // the round-1 checker's exactness gaps, each now refused
    const dup = mkWorld({ mutateDocs: (docs) => { docs.header.push({ ...docs.header[0], id: h32("f1") }); } });
    const ledDup = await runLedger(dup);
    ok("a DUPLICATE header for an epoch is a fetched extra",
      ledDup.recordSet.label === "REFUSED"
      && ledDup.perEpoch.get(5).diagnostics.some((d) => /duplicate headers/.test(d)));
    const dupRes = mkWorld({ mutateDocs: (docs) => { docs.reservation.push({ ...docs.reservation[0], id: h32("f2") }); } });
    const ledRes = await runLedger(dupRes);
    ok("a second reservation under one accrual is a fetched extra",
      ledRes.recordSet.label === "REFUSED"
      && ledRes.perEpoch.get(5).diagnostics.some((d) => /2 reservations/.test(d)));
    const zeroRec = mkWorld({ mutateDocs: (docs) => { docs.receipt.push({ ...docs.receipt[0],
      id: h32("f3"), accrualId: h32("30") }); } });
    const ledZero = await runLedger(zeroRec);
    ok("a transfer record under a zero-entitlement accrual is a fetched extra",
      ledZero.recordSet.label === "REFUSED"
      && ledZero.perEpoch.get(6).diagnostics.some((d) => /zero-entitlement accrual/.test(d)));
  }
  {
    // a missing-receipt row's reservation answer binds to its key: a
    // foreign served document refuses instead of a quiet UNPROVED, and
    // its height stays out of the range
    const w = mkWorld({ mutateDocs: (docs) => { docs.receipt.splice(0, 1); } });
    const missingAccrualId = w.accruals[0].id;
    w.deps = { ...w.deps, provedByKey: (function (orig) {
      return async (type, key) => {
        if (type === "receiptByAccrual" && sameIdTest(key.accrualId, missingAccrualId)) {
          return { status: "proved-absence", height: "916" };
        }
        if (type === "reservationByAccrual" && sameIdTest(key.accrualId, missingAccrualId)) {
          return { status: "served", doc: { id: h32("f9"), poolId: POOL_HEX,
            accrualId: h32("a7"), transitionHash: h32("11") }, height: "955" };
        }
        return orig(type, key);
      };
    })(w.deps.provedByKey) };
    const led = await runLedger(w);
    ok("a foreign reservation answer on a missing-receipt row refuses and withholds its height",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /DIFFERENT key or carries no identifier/.test(d))
      && !led.heightCandidates.includes("955"));
  }
  {
    // the structural sweep holds MULTIPLICITY too: duplicate receipts
    // under one accrual refuse even beside an unserved part enumeration
    const w = mkWorld({ mutateDocs: (docs) => { docs.receipt.push({ ...docs.receipt[0], id: h32("f2") }); } });
    const deps = { ...w.deps, fetchVerifiedPage: async (args) => {
      if (args.type === "part") return { status: "unserved" };
      const all = [...w.docs[args.type]].sort((a, b) => (a.id < b.id ? -1 : 1));
      const start = args.startAfter === null ? 0 : all.findIndex((d) => d.id === args.startAfter) + 1;
      return { status: "verified", documents: all.slice(start, start + args.limit), height: "900" };
    } };
    const led = await runLedger({ ...w, deps });
    ok("duplicate receipts under one accrual refuse even when a sibling enumeration is unserved",
      led.recordSet.label === "REFUSED"
      && led.diagnostics.poolGlobal.some((d) => /2 receipts under accrual/.test(d)));
  }
  {
    // POSITIVE prefix records: a conforming zero header and zero accruals
    // in the prefix are ALLOWED (their presence refuses nothing)
    const w = mkWorld({ provedActivation: 5,
      mutateDocs: (docs) => {
        docs.header.push({ id: h32("f6"), poolId: POOL_HEX, epochIndex: 4,
          grossCredits: 0, feeCredits: 0, memberCount: 3, calcVersion: 1,
          allocationHash: docs.header[0].allocationHash });
        [FA, FB, FC].forEach((funder, i) => docs.accrual.push({ id: h32(`e${i}`),
          poolId: POOL_HEX, epochIndex: 4, funderId: funder, amountCredits: 0 }));
      },
      fetchRange: async (start, end) => ({ epochs: [
        { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const resolution = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: w.deps.fetchRange });
    const led = await runLedger(w, { resolution });
    ok("a CONFORMING prefix header with zero accruals passes (their presence refuses nothing)",
      led.recordSet.label === "READ-CHECKED" && led.refusals.length === 0
      && led.perEpoch.get(4).diagnostics.length === 0);
  }
  {
    // dangling dependents are settled by the PINNED BY-IDENTIFIER read,
    // never by enumeration absence (rounds 15, 16 and 19): with the read
    // UNSERVED they stay possible orphans, narrowed interval or whole
    // universe alike, and with a PROVED ABSENCE they are genuine
    // orphans, narrowed or not
    const mkDangling = (over) => mkWorld({ mutateDocs: (docs) => {
      docs.receipt.push({ ...docs.receipt[0], id: h32("f8"), accrualId: h32("f9") });
      docs.reservation.push({ ...docs.reservation[0], id: h32("fa"), accrualId: h32("fb") });
      docs.part.push({ id: h32("fc"), poolId: docs.receipt[0].poolId, accrualId: h32("fd") });
    }, ...over });
    const narrowed = await resolveInterval({ requestedStart: 6, requestedEnd: null,
      configuredStart: 5, fetchRange: async (start, end) => ({
        epochs: [{ number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 }]
          .filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const wU = mkDangling({ provedByKey: (base) => async (type, key) =>
      type === "accrualById" ? { status: "unserved" } : base(type, key) });
    const ledN = await runLedger(wU, { resolution: narrowed });
    ok("an unserved by-identifier read leaves dangling dependents possible orphans under a narrowed interval, for every type",
      ledN.recordSet.label === "UNPROVED"
      && ["receipt", "reservation", "part"].every((t) =>
        ledN.diagnostics.poolGlobal.some((d) => d.startsWith(`possible orphan ${t} `)))
      && ledN.diagnostics.orphans.length === 0);
    const ledUFull = await runLedger(wU);
    ok("enumeration absence proves nothing over the whole universe either: still possible orphans, never refusals",
      ledUFull.recordSet.label === "UNPROVED" && ledUFull.diagnostics.orphans.length === 0
      && ledUFull.recordsProved === false);
    const wA = mkDangling({});
    const ledAN = await runLedger(wA, { resolution: narrowed });
    const ledAF = await runLedger(wA);
    ok("a proved absence makes the dangling dependents genuine orphans, narrowed or not, for every dependent type",
      ledAN.diagnostics.orphans.length === 3 && ledAN.recordSet.label === "REFUSED"
      && ledAF.diagnostics.orphans.length === 3 && ledAF.recordSet.label === "REFUSED");
    ok("the by-identifier proved absence contributes its proof height to the range",
      ledAF.heightCandidates.includes("919"));
  }
  {
    // the PLAIN-DATA boundary: a served document with a foreign
    // prototype or an accessor-backed member is not the plain object
    // the adapter contract requires, and refuses hard
    class Wrapper { get id() { return h32("50"); } }
    const w1 = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "reservationByAccrual" ? { status: "served", doc: new Wrapper(), height: "915" } : base(type, key) });
    await rejects("a served document with a foreign prototype refuses hard",
      runLedger(w1), /foreign prototype/);
    const gd = {};
    Object.defineProperty(gd, "id", { get: () => h32("50"), enumerable: true, configurable: true });
    const w2 = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "reservationByAccrual" ? { status: "served", doc: gd, height: "915" } : base(type, key) });
    await rejects("a served document with an accessor-backed member refuses hard",
      runLedger(w2), /accessor-backed/);
    const w3 = mkWorld();
    const gp = { version: "v11" };
    Object.defineProperty(gp, "documentTypes", { get: () => [], enumerable: true, configurable: true });
    await rejects("an accessor-backed expected contract payload refuses hard",
      evaluateContractIntegrity({ contractId: GC, expectedContractPayload: gp, deps: w3.deps }),
      /accessor-backed/);
    // the boundary walks the COMPLETE value graph, not the root alone
    const nestedGetter = {};
    Object.defineProperty(nestedGetter, "pool", { get: () => ({}), enumerable: true, configurable: true });
    const gpNested = { version: "v11", documents: nestedGetter };
    await rejects("a NESTED accessor in the expected payload refuses hard (the graph is walked, not the root alone)",
      evaluateContractIntegrity({ contractId: GC, expectedContractPayload: gpNested, deps: w3.deps }),
      /accessor-backed/);
    // a NON-ENUMERABLE or symbol-keyed member would vanish from the
    // canonical comparison, so the boundary refuses it outright
    const gpHidden = { version: "v11" };
    Object.defineProperty(gpHidden, "extraContractMember", { value: { required: true }, enumerable: false });
    await rejects("a non-enumerable expected-payload member refuses hard (it would vanish from comparison)",
      evaluateContractIntegrity({ contractId: GC, expectedContractPayload: gpHidden, deps: w3.deps }),
      /non-enumerable/);
    const gpSym = { version: "v11", [Symbol("x")]: 1 };
    await rejects("a symbol-keyed expected-payload member refuses hard",
      evaluateContractIntegrity({ contractId: GC, expectedContractPayload: gpSym, deps: w3.deps }),
      /symbol-keyed/);
    // and the ENTRY refuses the same defect as a structured REFUSED-INPUT
    const protoPayload = Object.create({ version: "v11" });
    const rEntry = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-nodep"),
      deps: { ...w3.deps, expectedContractPayload: protoPayload } });
    ok("a prototype-carried expected payload is a structured REFUSED-INPUT at the entry, never an escaping throw",
      rEntry.verdict === "REFUSED-INPUT" && /plain data/.test(rEntry.reason));
    // a supplied $-member is a structured REFUSED-INPUT THROUGH THE ENTRY too
    // (round-56, F1): the evaluator's own $-check throws a plain refusal that
    // runAudit's catch would not convert, so the entry owns the input typing.
    const rDollar = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-nodep"),
      deps: { ...w3.deps, expectedContractPayload: { ...w3.deps.expectedContractPayload, $policy: true } } });
    ok("a supplied $-member expected payload is a structured REFUSED-INPUT at the entry, never an escaping throw",
      rDollar.verdict === "REFUSED-INPUT" && /system-namespace/.test(rDollar.reason));
    // each of the THREE throwing reflective traps on the payload is a
    // structured REFUSED-INPUT through the entry, not an escaping adapter
    // error (round-56 F2, all three covered round-57 F3)
    for (const trap of [
      { ownKeys() { throw new Error("ownKeys trap"); } },
      { getPrototypeOf() { throw new Error("getPrototypeOf trap"); } },
      { getOwnPropertyDescriptor() { throw new Error("gOPD trap"); } }]) {
      const rTrap = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-nodep"),
        deps: { ...w3.deps, expectedContractPayload: new Proxy({ version: "v11" }, trap) } });
      ok("a throwing reflective-trap expected payload is a structured REFUSED-INPUT, never an escaping throw",
        rTrap.verdict === "REFUSED-INPUT" && /plain data/.test(rTrap.reason));
    }
    // a REVOKED-Proxy payload is likewise a structured REFUSED-INPUT: the
    // Array.isArray classification throws on a revoked proxy and is guarded
    // (round-57, F2)
    const revPay = Proxy.revocable({ version: "v11" }, {}); revPay.revoke();
    const rRev = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-nodep"),
      deps: { ...w3.deps, expectedContractPayload: revPay.proxy } });
    ok("a revoked-proxy expected payload is a structured REFUSED-INPUT, never an escaping raw TypeError",
      rRev.verdict === "REFUSED-INPUT" && /plain data/.test(rRev.reason));
  }
  {
    // a MALFORMED accrual reference is refused before any adapter call:
    // no by-identifier key can be formed from it
    let byIdCalls = 0;
    const w = mkWorld({ mutateDocs: (docs) => { docs.part.push({ id: h32("f8"),
      poolId: docs.receipt[0].poolId, accrualId: "not-an-id" }); },
      provedByKey: (base) => async (type, key) => {
        if (type === "accrualById") byIdCalls += 1;
        return base(type, key);
      } });
    const led = await runLedger(w);
    ok("a malformed accrual reference refuses on its face, with no by-identifier call made",
      led.recordSet.label === "REFUSED" && byIdCalls === 0
      && led.diagnostics.poolGlobal.some((d) => /malformed accrual reference/.test(d)));
    // the same refusal holds when formation is UNAVAILABLE: the grammar
    // is structural and needs no formation input
    const wU = mkWorld({ mutateDocs: (docs) => { docs.part.push({ id: h32("f8"),
      poolId: docs.receipt[0].poolId, accrualId: "not-an-id" }); },
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" } : base(type, key) });
    const ledU = await runLedger(wU);
    ok("a malformed accrual reference refuses on the unavailable path too",
      ledU.recordSet.label === "REFUSED"
      && ledU.diagnostics.poolGlobal.some((d) => /malformed accrual reference/.test(d)));
    // a NULL-PROTOTYPE reference is plain data at the boundary yet no
    // identifier: it must refuse through the grammar, never crash the
    // normalizer (round-48)
    const wNP = mkWorld({ mutateDocs: (docs) => { docs.part.push({ id: h32("f9"),
      poolId: docs.receipt[0].poolId, accrualId: Object.create(null) }); } });
    const ledNP = await runLedger(wNP);
    ok("a null-prototype accrual reference refuses as malformed, never as an untyped crash",
      ledNP.recordSet.label === "REFUSED"
      && ledNP.diagnostics.poolGlobal.some((d) => /malformed accrual reference/.test(d)));
    // a ONE-ELEMENT ARRAY around a real identifier cannot coerce into a
    // valid key (round-51), on the normal and unavailable paths alike
    const mutArr = (docs) => { docs.part.push({ id: h32("f9"),
      poolId: docs.receipt[0].poolId, accrualId: [docs.accrual[0].id] }); };
    const ledArr = await runLedger(mkWorld({ mutateDocs: mutArr }));
    ok("an array-wrapped accrual reference refuses as malformed on the normal path",
      ledArr.recordSet.label === "REFUSED"
      && ledArr.diagnostics.poolGlobal.some((d) => /malformed accrual reference/.test(d)));
    const ledArrU = await runLedger(mkWorld({ mutateDocs: mutArr,
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" } : base(type, key) }));
    ok("an array-wrapped accrual reference refuses on the unavailable path too",
      ledArrU.recordSet.label === "REFUSED"
      && ledArrU.diagnostics.poolGlobal.some((d) => /malformed accrual reference/.test(d)));
  }
  {
    // a by-identifier served accrual runs the SAME conformance checks
    // as an enumerated one; only a document matching an unresolved
    // expectation exactly marks the resolution INCOMPLETE
    const side = { id: h32("f9"), poolId: POOL_HEX, epochIndex: 5, funderId: FA, amountCredits: 400000 };
    const mut = (docs) => { docs.receipt.push({ ...docs.receipt[0], id: h32("f8"), accrualId: h32("f9") }); };
    const wP = mkWorld({ mutateDocs: mut, provedByKey: (base) => async (type, key) =>
      type === "accrualById" ? { status: "served", doc: side, height: "919" } : base(type, key) });
    const ledP = await runLedger(wP);
    ok("a recovered accrual for an already-resolved slot refuses through the forward pass as a fetched extra",
      ledP.recordSet.label === "REFUSED" && ledP.diagnostics.orphans.length === 0
      && ledP.perEpoch.get(5).diagnostics.some((d) => /outside the recomputed set/.test(d)));
    // the true-incompleteness case: the expected accrual is omitted by
    // the enumeration and its by-key fallback is unserved, but its REAL
    // dependents remain enumerated and the by-identifier read serves
    // exactly the expected document, which then passes the FULL forward
    // evaluation (receipt included)
    let gone2;
    const mutInc = (docs) => {
      gone2 = docs.accrual.find((a) => a.epochIndex === 5 && a.funderId === FB);
      docs.accrual = docs.accrual.filter((a) => a !== gone2);
    };
    const wInc = mkWorld({ mutateDocs: mutInc, provedByKey: (base) => async (type, key) =>
      type === "accrualByKey" ? { status: "unserved" }
        : type === "accrualById" && sameIdTest(key.accrualId, gone2.id)
          ? { status: "served", doc: gone2, height: "919" } : base(type, key) });
    const ledInc = await runLedger(wInc);
    ok("a recovered accrual matching its expectation passes the full forward evaluation and marks only the resolution incomplete",
      ledInc.recordSet.label === "UNPROVED" && ledInc.diagnostics.orphans.length === 0
      && ledInc.diagnostics.poolGlobal.some((d) => /INCOMPLETE/.test(d))
      && ledInc.heightCandidates.includes("919")
      && ledInc.lag.undistributedCredits === "0");
    // the round-23 must-fix: the recovered accrual conforms but its
    // DEPENDENT does not (the enumerated receipt carries another
    // funder's transfer), so the forward evaluation refuses the receipt
    let gone3;
    const mutBad = (docs) => {
      gone3 = docs.accrual.find((a) => a.epochIndex === 5 && a.funderId === FB);
      docs.accrual = docs.accrual.filter((a) => a !== gone3);
      docs.reservation = docs.reservation.filter((r) => r.accrualId !== gone3.id);
      docs.receipt = docs.receipt.filter((r) => r.accrualId !== gone3.id);
      docs.receipt.push({ ...docs.receipt[0], id: h32("f8"), accrualId: h32("f9") });
    };
    const wBadDep = mkWorld({ mutateDocs: mutBad, provedByKey: (base) => async (type, key) =>
      type === "accrualByKey" ? { status: "unserved" }
        : type === "accrualById"
          ? { status: "served", doc: { ...gone3, id: h32("f9") }, height: "919" } : base(type, key) });
    const narrowBad = await resolveInterval({ requestedStart: 5, requestedEnd: 5,
      configuredStart: 5, fetchRange: wBadDep.deps.fetchRange });
    const ledBadDep = await runLedger(wBadDep, { resolution: narrowBad });
    ok("a nonconforming dependent under a recovered accrual refuses through the full forward evaluation",
      ledBadDep.aggregates.transferExecution === "REFUSED"
      && ledBadDep.lag.undistributedCredits === "240000"
      && ledBadDep.diagnostics.poolGlobal.some((d) => /INCOMPLETE/.test(d)));
    const wForeign = mkWorld({ mutateDocs: mut, provedByKey: (base) => async (type, key) =>
      type === "accrualById" ? { status: "served", doc: { ...side, funderId: h32("55") }, height: "919" } : base(type, key) });
    const ledFor = await runLedger(wForeign);
    ok("a recovered accrual for a funder outside the recomputed set refuses as a fetched extra",
      ledFor.recordSet.label === "REFUSED"
      && ledFor.perEpoch.get(5).diagnostics.some((d) => /outside the recomputed set/.test(d)));
    const wAmt = mkWorld({ mutateDocs: mutBad, provedByKey: (base) => async (type, key) =>
      type === "accrualByKey" ? { status: "unserved" }
        : type === "accrualById"
          ? { status: "served", doc: { ...gone3, id: h32("f9"), amountCredits: 7 }, height: "919" } : base(type, key) });
    const ledAmt = await runLedger(wAmt);
    ok("a recovered accrual with a nonconforming amount refuses against the recomputation",
      ledAmt.recordSet.label === "REFUSED"
      && ledAmt.perEpoch.get(5).diagnostics.some((d) => /differs from the recomputed 240000/.test(d)));
    // the served accrual's EPOCH classifies the dependent: out-of-domain
    // is an extra and refuses, an ignored epoch carries no obligation
    const wX = mkWorld({ mutateDocs: mut, provedByKey: (base) => async (type, key) =>
      type === "accrualById" ? { status: "served", doc: { ...side, epochIndex: 40 }, height: "919" } : base(type, key) });
    const ledX = await runLedger(wX);
    ok("a by-identifier served accrual at an out-of-domain epoch makes the dependent an extra and refuses",
      ledX.recordSet.label === "REFUSED"
      && ledX.diagnostics.extras.some((d) => /epoch 40/.test(d)));
    const narrowed6 = await resolveInterval({ requestedStart: 6, requestedEnd: null,
      configuredStart: 5, fetchRange: async (start, end) => ({
        epochs: [{ number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 }]
          .filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const ledIg = await runLedger(wP, { resolution: narrowed6 });
    ok("a by-identifier served accrual in an IGNORED epoch carries no obligation",
      ledIg.recordSet.label === "READ-CHECKED" && ledIg.diagnostics.extras.length === 0
      && !ledIg.diagnostics.poolGlobal.some((d) => /INCOMPLETE/.test(d)));
    const wN = mkWorld({ mutateDocs: mut, provedByKey: (base) => async (type, key) =>
      type === "accrualById" ? { status: "served", doc: { ...side, poolId: h32("77") }, height: "2001" } : base(type, key) });
    const ledNc = await runLedger(wN);
    ok("a by-identifier answer naming a foreign pool is nonconforming, refuses, and its height is withheld",
      ledNc.recordSet.label === "REFUSED"
      && ledNc.diagnostics.poolGlobal.some((d) => /nonconforming/.test(d))
      && !ledNc.heightCandidates.includes("2001"));
    const wW = mkWorld({ mutateDocs: mut, provedByKey: (base) => async (type, key) =>
      type === "accrualById" ? { status: "served", doc: { ...side, id: h32("aa") }, height: "919" } : base(type, key) });
    const ledW = await runLedger(wW);
    ok("a by-identifier answer for a DIFFERENT accrual is nonconforming and refuses",
      ledW.recordSet.label === "REFUSED"
      && ledW.diagnostics.poolGlobal.some((d) => /nonconforming/.test(d)));
    const wE = mkWorld({ mutateDocs: mut, provedByKey: (base) => async (type, key) =>
      type === "accrualById" ? { status: "served", doc: { ...side, epochIndex: "5" }, height: "919" } : base(type, key) });
    const ledE = await runLedger(wE);
    ok("a by-identifier answer without an integer epoch is nonconforming and refuses",
      ledE.recordSet.label === "REFUSED"
      && ledE.diagnostics.poolGlobal.some((d) => /nonconforming/.test(d)));
  }
  {
    // a by-identifier accrual in a PREFIX epoch runs the prefix rules: a
    // nonzero amount refuses, and a zero amount for an allocation funder
    // leaves only enumeration completeness unproved
    const prefixRange = async (start, end) => ({ epochs: [
      { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
        coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
        coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
      { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
        coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
    ].filter((e) => e.number >= start && e.number <= end), proved: false });
    const mkPrefix = (byIdDoc) => mkWorld({ provedActivation: 5, fetchRange: prefixRange,
      mutateDocs: (docs) => { docs.receipt.push({ ...docs.receipt[0], id: h32("f8"), accrualId: h32("f9") }); },
      provedByKey: (base) => async (type, key) =>
        type === "accrualById" ? { status: "served", doc: byIdDoc, height: "919" } : base(type, key) });
    const prefixResolution = async (w) => resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: w.deps.fetchRange });
    const wPre = mkPrefix({ id: h32("f9"), poolId: POOL_HEX, epochIndex: 4, funderId: FA, amountCredits: 3 });
    const ledPre = await runLedger(wPre, { resolution: await prefixResolution(wPre) });
    ok("a recovered prefix accrual with a nonzero amount refuses through the forward prefix rules",
      ledPre.recordSet.label === "REFUSED"
      && ledPre.perEpoch.get(4).diagnostics.some((d) => /does not carry an integer-zero amount/.test(d)));
    const wPre0 = mkPrefix({ id: h32("f9"), poolId: POOL_HEX, epochIndex: 4, funderId: FA, amountCredits: 0 });
    const ledPre0 = await runLedger(wPre0, { resolution: await prefixResolution(wPre0) });
    ok("even a conforming recovered prefix accrual refuses its DEPENDENT (a prefix epoch has no transfers)",
      ledPre0.recordSet.label === "REFUSED"
      && ledPre0.perEpoch.get(4).diagnostics.some((d) => /no transfers/.test(d)));
  }
  {
    // same-type MULTIPLICITY under a recovered accrual refuses through
    // the forward evaluation, ONE settlement read serving both; and the
    // same pair under an accrual recovered at an IGNORED epoch carries
    // no obligation (round-23)
    let byIdCalls = 0;
    const recovered = { id: h32("f9"), poolId: POOL_HEX, epochIndex: 5, funderId: FB, amountCredits: 240000 };
    const mkw = (byIdDoc) => mkWorld({ mutateDocs: (docs) => {
      const goneAcc = docs.accrual.find((a) => a.epochIndex === 5 && a.funderId === FB);
      docs.accrual = docs.accrual.filter((a) => a !== goneAcc);
      docs.reservation = docs.reservation.filter((r) => r.accrualId !== goneAcc.id);
      docs.receipt = docs.receipt.filter((r) => r.accrualId !== goneAcc.id);
      docs.receipt.push({ ...docs.receipt[0], id: h32("f6"), accrualId: h32("f9") });
      docs.receipt.push({ ...docs.receipt[0], id: h32("f7"), accrualId: h32("f9") });
    }, provedByKey: (base) => async (type, key) => {
      if (type === "accrualById") { byIdCalls += 1; return { status: "served", doc: byIdDoc, height: "919" }; }
      if (type === "accrualByKey") return { status: "unserved" };
      return base(type, key);
    } });
    const w = mkw(recovered);
    const led = await runLedger(w);
    ok("two receipts under a recovered accrual refuse through the forward multiplicity check, one settlement serving both",
      led.recordSet.label === "REFUSED" && byIdCalls === 1
      && led.perEpoch.get(5).diagnostics.some((d) => /2 receipts \(a fetched extra\)|carries 2 receipts/.test(d)));
    byIdCalls = 0;
    const narrowed6 = await resolveInterval({ requestedStart: 6, requestedEnd: null,
      configuredStart: 5, fetchRange: async (start, end) => ({
        epochs: [{ number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 }]
          .filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const wIg = mkw(recovered);
    const ledIg2 = await runLedger(wIg, { resolution: narrowed6 });
    ok("the same pair under an accrual recovered at an IGNORED epoch carries no obligation",
      ledIg2.recordSet.label === "READ-CHECKED"
      && ledIg2.diagnostics.orphans.length === 0 && ledIg2.diagnostics.extras.length === 0);
  }
  {
    // a by-identifier accrual resolving to an ENCODING-REFUSED epoch
    // refuses: that epoch expects no records at all
    const w = mkWorld({ fetchRange: async (start, end) => ({ epochs: [
      { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
        coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
      { number: 6, totalProcessingFees: "900719925474099200", totalDistributedStorageFees: "0",
        coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
    ].filter((e) => e.number >= start && e.number <= end), proved: false }),
    mutateDocs: (docs) => {
      docs.header = docs.header.filter((h) => h.epochIndex !== 6);
      docs.accrual = docs.accrual.filter((a) => a.epochIndex !== 6);
      docs.receipt.push({ ...docs.receipt[0], id: h32("f8"), accrualId: h32("f9") });
    }, provedByKey: (base) => async (type, key) =>
      type === "accrualById"
        ? { status: "served", doc: { id: h32("f9"), poolId: POOL_HEX, epochIndex: 6, funderId: FA, amountCredits: 0 }, height: "919" }
        : base(type, key) });
    const led = await runLedger(w);
    ok("a recovered accrual in an encoding-refused epoch refuses (no records are expected there)",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(6).diagnostics.some((d) => /records exist under an encoding-refused epoch/.test(d))
      && led.perEpoch.get(6).condition === "encoding-refused");
  }
  {
    // structural findings classify epochs exactly like the normal path:
    // a duplicate receipt pair in an IGNORED epoch refuses on neither
    // path, and the same pair inside the domain still refuses on the
    // unavailable path
    const mkDup = () => mkWorld({
      mutateDocs: (docs) => { docs.receipt.push({ ...docs.receipt[0], id: h32("f2") }); },
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" } : base(type, key) });
    const narrowed = await resolveInterval({ requestedStart: 6, requestedEnd: null,
      configuredStart: 5, fetchRange: async (start, end) => ({
        epochs: [{ number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 }]
          .filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const ledN = await runLedger(mkDup(), { resolution: narrowed });
    ok("the sweep ignores a duplicate pair in an ignored epoch, exactly as the normal path would",
      ledN.recordSet.label === "UNPROVED"
      && !ledN.diagnostics.poolGlobal.some((d) => /receipts under/.test(d)));
    const ledF = await runLedger(mkDup());
    ok("the same duplicate pair inside the domain still refuses on the unavailable path",
      ledF.recordSet.label === "REFUSED"
      && ledF.diagnostics.poolGlobal.some((d) => /receipts under/.test(d)));
    // the same classification for DUPLICATE HEADERS, and reservation
    // multiplicity is structural too
    const mkDupH = () => mkWorld({
      mutateDocs: (docs) => { docs.header.push({ ...docs.header[0], id: h32("f3") }); },
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" } : base(type, key) });
    const ledHN = await runLedger(mkDupH(), { resolution: narrowed });
    ok("the sweep ignores duplicate headers in an ignored epoch",
      ledHN.recordSet.label === "UNPROVED"
      && !ledHN.diagnostics.poolGlobal.some((d) => /duplicate headers/.test(d)));
    const ledHF = await runLedger(mkDupH());
    ok("duplicate headers inside the domain still refuse on the unavailable path",
      ledHF.recordSet.label === "REFUSED"
      && ledHF.diagnostics.poolGlobal.some((d) => /duplicate headers/.test(d)));
    const mkDupR = () => mkWorld({
      mutateDocs: (docs) => { docs.reservation.push({ ...docs.reservation[0], id: h32("f4") }); },
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" } : base(type, key) });
    const ledR = await runLedger(mkDupR());
    ok("duplicate reservations refuse on the unavailable path too",
      ledR.recordSet.label === "REFUSED"
      && ledR.diagnostics.poolGlobal.some((d) => /reservations under/.test(d)));
    // duplicate ACCRUAL SLOTS refuse on the unavailable path, and an
    // ignored epoch's pair carries no obligation (round-31)
    const mkDupA = () => mkWorld({
      mutateDocs: (docs) => { docs.accrual.push({ ...docs.accrual[0], id: h32("f5") }); },
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" } : base(type, key) });
    const ledA = await runLedger(mkDupA());
    ok("two proved accruals for one slot refuse on the unavailable path (a fetched extra)",
      ledA.recordSet.label === "REFUSED"
      && ledA.diagnostics.poolGlobal.some((d) => /accruals share the slot/.test(d)));
    const ledAN = await runLedger(mkDupA(), { resolution: narrowed });
    ok("the same duplicate slot in an ignored epoch carries no obligation on the unavailable path",
      ledAN.recordSet.label === "UNPROVED"
      && !ledAN.diagnostics.poolGlobal.some((d) => /accruals share the slot/.test(d)));
  }
  {
    // record GRAMMAR holds on both paths (round-32): a string epoch
    // index and a malformed funder identifier each refuse, with the
    // formation available or not, and a STRING-TYPED credits value never
    // compares equal to its recomputed integer text
    const mutH = (docs) => { docs.header[0].epochIndex = "5"; };
    const mutF = (docs) => { docs.accrual.push({ id: h32("f5"), poolId: docs.header[0].poolId,
      epochIndex: 5, funderId: "not-an-id", amountCredits: 1 }); };
    const unservedPool = { provedByKey: (base) => async (type, key) =>
      type === "pool" ? { status: "unserved" } : base(type, key) };
    for (const [what, mut] of [["a string epoch index", mutH], ["a malformed funder identifier", mutF]]) {
      const ledN = await runLedger(mkWorld({ mutateDocs: mut }));
      ok(`${what} refuses on the normal path`,
        ledN.recordSet.label === "REFUSED"
        && ledN.diagnostics.poolGlobal.some((d) => /malformed epoch index|malformed funder identifier/.test(d)));
      const ledU = await runLedger(mkWorld({ mutateDocs: mut, ...unservedPool }));
      ok(`${what} refuses on the unavailable path too`,
        ledU.recordSet.label === "REFUSED"
        && ledU.diagnostics.poolGlobal.some((d) => /malformed epoch index|malformed funder identifier/.test(d)));
    }
    // an IGNORED epoch's malformed funder carries no obligation
    // (round-42): the epoch classifies safely, so no duty attaches
    const narrowed42 = await resolveInterval({ requestedStart: 6, requestedEnd: null,
      configuredStart: 5, fetchRange: async (start, end) => ({
        epochs: [{ number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 }]
          .filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const ledIgF = await runLedger(mkWorld({ mutateDocs: mutF }), { resolution: narrowed42 });
    ok("a malformed funder identifier in an IGNORED epoch carries no obligation",
      ledIgF.recordSet.label === "READ-CHECKED"
      && !ledIgF.diagnostics.poolGlobal.some((d) => /malformed funder identifier/.test(d)));
    const wStr = mkWorld({ mutateDocs: (docs) => {
      docs.header[0].grossCredits = "1000000";
      docs.accrual[0].amountCredits = String(docs.accrual[0].amountCredits);
    } });
    const ledStr = await runLedger(wStr);
    ok("string-typed credits never compare equal to the recomputation, however their text reads",
      ledStr.recordSet.label === "REFUSED"
      && ledStr.perEpoch.get(5).diagnostics.some((d) => /grossCredits/.test(d))
      && ledStr.perEpoch.get(5).diagnostics.some((d) => /amount/.test(d)));
    const wPre = mkWorld({ provedActivation: 5,
      fetchRange: async (start, end) => ({ epochs: [
        { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }),
      mutateDocs: (docs) => { docs.accrual.push({ id: h32("f5"), poolId: docs.header[0].poolId,
        epochIndex: 4, funderId: docs.accrual[0].funderId, amountCredits: "0" }); } });
    const resPre = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: wPre.deps.fetchRange });
    const ledPre = await runLedger(wPre, { resolution: resPre });
    ok("a string-typed ZERO in a prefix accrual is nonconforming too",
      ledPre.recordSet.label === "REFUSED"
      && ledPre.perEpoch.get(4).diagnostics.some((d) => /does not carry an integer-zero amount/.test(d)));
  }
  {
    // formation-FREE prefix duties hold on the unavailable path
    // (round-33): a nonzero proposer count, a nonzero prefix accrual,
    // and transfer records under it all refuse with the pool read
    // unserved
    const w = mkWorld({ provedActivation: 5,
      fetchRange: async (start, end) => ({ epochs: [
        { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 2 },
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }),
      mutateDocs: (docs) => {
        docs.accrual.push({ id: h32("f5"), poolId: docs.header[0].poolId,
          epochIndex: 4, funderId: docs.accrual[0].funderId, amountCredits: 7 });
        docs.receipt.push({ ...docs.receipt[0], id: h32("f6"), accrualId: h32("f5") });
      },
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" } : base(type, key) });
    const res = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: w.deps.fetchRange });
    const led = await runLedger(w, { resolution: res });
    ok("formation-free prefix duties refuse on the unavailable path",
      led.recordSet.label === "REFUSED"
      && led.diagnostics.poolGlobal.some((d) => /zero-earning verification \(proposedCount 2\)/.test(d))
      && led.diagnostics.poolGlobal.some((d) => /prefix accrual in epoch 4 does not carry an integer-zero amount/.test(d))
      && led.diagnostics.poolGlobal.some((d) => /transfer records exist under a prefix accrual in epoch 4/.test(d)));
    // a zero-credit prefix header with a wrong calcVersion refuses too
    // (round-36): the version check needs no formation rows
    const wV = mkWorld({ provedActivation: 5,
      fetchRange: async (start, end) => ({ epochs: [
        { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }),
      mutateDocs: (docs) => { docs.header.push({ ...docs.header[1], id: h32("f4"),
        epochIndex: 4, grossCredits: 0, feeCredits: 0, calcVersion: 2 }); },
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" } : base(type, key) });
    const resV = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: wV.deps.fetchRange });
    const ledV = await runLedger(wV, { resolution: resV });
    ok("a wrong calcVersion on a zero-credit prefix header refuses on the unavailable path",
      ledV.recordSet.label === "REFUSED"
      && ledV.diagnostics.poolGlobal.some((d) => /calcVersion, memberCount or allocationHash is nonconforming/.test(d)));
    // and a FEE-only nonzero prefix header refuses there too (both
    // credit fields are checked, not only gross)
    const wF = mkWorld({ provedActivation: 5,
      fetchRange: wV.deps.fetchRange,
      mutateDocs: (docs) => { docs.header.push({ ...docs.header[1], id: h32("f4"),
        epochIndex: 4, grossCredits: 0, feeCredits: 5 }); },
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" } : base(type, key) });
    const resF = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: wF.deps.fetchRange });
    const ledF2 = await runLedger(wF, { resolution: resF });
    ok("a fee-only nonzero prefix header refuses on the unavailable path",
      ledF2.recordSet.label === "REFUSED"
      && ledF2.diagnostics.poolGlobal.some((d) => /header does not carry integer-zero credits/.test(d)));
    // the basic member GRAMMAR refuses there too (round-37)
    for (const [what, patch] of [["a non-integer memberCount", { memberCount: 3.5 }],
      ["a NEGATIVE memberCount", { memberCount: -1 }],
      ["a non-string allocationHash", { allocationHash: 7 }],
      ["an EMPTY allocationHash", { allocationHash: "" }],
      ["a non-hex allocationHash", { allocationHash: "zz".repeat(32) }]]) {
      const wG = mkWorld({ provedActivation: 5,
        fetchRange: wV.deps.fetchRange,
        mutateDocs: (docs) => { docs.header.push({ ...docs.header[1], id: h32("f4"),
          epochIndex: 4, grossCredits: 0, feeCredits: 0, ...patch }); },
        provedByKey: (base) => async (type, key) =>
          type === "pool" ? { status: "unserved" } : base(type, key) });
      const resG = await resolveInterval({ requestedStart: 4, requestedEnd: null,
        configuredStart: 5, provedActivation: 5, fetchRange: wG.deps.fetchRange });
      const ledG = await runLedger(wG, { resolution: resG });
      ok(`${what} on a prefix header refuses on the unavailable path`,
        ledG.recordSet.label === "REFUSED"
        && ledG.diagnostics.poolGlobal.some((d) => /calcVersion, memberCount or allocationHash is nonconforming/.test(d)));
    }
    // and a CLEAN prefix on the unavailable path stays a clean
    // UNPROVED, a conforming ZERO prefix accrual included
    const wClean = mkWorld({ provedActivation: 5,
      fetchRange: async (start, end) => ({ epochs: [
        { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }),
      mutateDocs: (docs) => { docs.accrual.push({ id: h32("f7"), poolId: docs.header[0].poolId,
        epochIndex: 4, funderId: docs.accrual[0].funderId, amountCredits: 0 }); },
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" } : base(type, key) });
    const resClean = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: wClean.deps.fetchRange });
    const ledClean = await runLedger(wClean, { resolution: resClean });
    ok("a clean prefix on the unavailable path stays UNPROVED with no prefix diagnostics",
      ledClean.recordSet.label === "UNPROVED"
      && !ledClean.diagnostics.poolGlobal.some((d) => /prefix/.test(d)));
  }
  {
    // the reservation chain equality requires a WELL-FORMED receipt hash
    // (round-33): two absent members compare equal but prove nothing
    const f = evaluateReservationPresence(
      { poolId: POOL_HEX, accrualId: h32("20") },
      { status: "served", height: "915",
        doc: { id: h32("50"), poolId: POOL_HEX, accrualId: h32("20") } });
    ok("a reservation matching a receipt on two ABSENT transition hashes refuses",
      f.label === "REFUSED" && /chain differs/.test(f.reason));
    const f2 = evaluateReservationPresence(
      { poolId: POOL_HEX, accrualId: h32("20"), transitionHash: null },
      { status: "served", height: "915",
        doc: { id: h32("50"), poolId: POOL_HEX, accrualId: h32("20"), transitionHash: null } });
    ok("equal null transition hashes refuse too", f2.label === "REFUSED");
    // the answer union is DISCRIMINATED (round-40): members outside the
    // declared variant are contradictory shapes and refuse hard
    throwsSync("a proved absence carrying a document is a contradictory envelope",
      () => evaluateReservationPresence({ poolId: POOL_HEX, accrualId: h32("20") },
        { status: "proved-absence", height: "915", doc: { id: h32("50") } }),
      /outside|unknown members/);
    throwsSync("an unserved answer carrying a height is a contradictory envelope",
      () => evaluateReservationPresence({ poolId: POOL_HEX, accrualId: h32("20") },
        { status: "unserved", height: "915" }),
      /outside|unknown members/);
    // the ENVELOPE validates before any member read (round-41): a
    // self-replacing status accessor refuses outright
    const spyAns = { doc: { id: h32("50"), poolId: POOL_HEX, accrualId: h32("20") } };
    Object.defineProperty(spyAns, "status", { enumerable: true, configurable: true,
      get() { Object.defineProperty(this, "status", { value: "served", enumerable: true }); return "unserved"; } });
    throwsSync("a self-replacing status accessor on the answer envelope refuses before any read",
      () => evaluateReservationPresence({ poolId: POOL_HEX, accrualId: h32("20") }, spyAns),
      /accessor-backed/);
    // an ARRAY envelope with a throwing status getter refuses without
    // even its refusal message reading the member (round-52)
    let arrReads = 0;
    const arrAns = [];
    Object.defineProperty(arrAns, "status", { enumerable: true, configurable: true,
      get: () => { arrReads += 1; throw new Error("getter ran"); } });
    throwsSync("an array answer envelope refuses without reading its status",
      () => evaluateReservationPresence({ poolId: POOL_HEX, accrualId: h32("20") }, arrAns),
      /no plain answer envelope/);
    ok("the rejected envelope's status getter never fired", arrReads === 0);
    for (const [what, bad] of [["equal short strings", "ab".repeat(31) + "a"],
      ["equal non-hex 64-character strings", "zz".repeat(32)],
      ["equal UPPERCASE hex strings", "AB".repeat(32)]]) {
      const fx = evaluateReservationPresence(
        { poolId: POOL_HEX, accrualId: h32("20"), transitionHash: bad },
        { status: "served", height: "915",
          doc: { id: h32("50"), poolId: POOL_HEX, accrualId: h32("20"), transitionHash: bad } });
      ok(`${what} refuse (the receipt hash must be well-formed 64-hex)`, fx.label === "REFUSED");
    }
  }
  {
    // an unresolved expected-accrual fallback no longer decides a
    // dangling dependent (round-19): the by-identifier read does. With
    // both reads unserved the dependent stays a possible orphan; with
    // the base world's proved absence it is a genuine orphan
    let gone;
    const mut = (docs) => {
      gone = docs.accrual.find((a) => a.epochIndex === 5 && a.funderId === FB);
      docs.accrual = docs.accrual.filter((a) => a !== gone);
      docs.reservation = docs.reservation.filter((r) => r.accrualId !== gone.id);
      docs.receipt = docs.receipt.filter((r) => r.accrualId !== gone.id);
      docs.receipt.push({ ...docs.receipt[0], id: h32("f8"), accrualId: h32("f9") });
    };
    const wU = mkWorld({ mutateDocs: mut, provedByKey: (base) => async (type, key) =>
      (type === "accrualByKey" || type === "accrualById") ? { status: "unserved" } : base(type, key) });
    const ledU = await runLedger(wU);
    ok("an unserved expected-accrual fallback beside an unserved by-identifier read leaves a possible orphan",
      ledU.recordSet.label === "UNPROVED" && ledU.diagnostics.orphans.length === 0
      && ledU.diagnostics.poolGlobal.some((d) => /possible orphan receipt/.test(d)));
    const wA = mkWorld({ mutateDocs: mut });
    const ledA = await runLedger(wA);
    ok("the by-identifier proved absence makes the dependent a genuine orphan",
      ledA.recordSet.label === "REFUSED" && ledA.diagnostics.orphans.length === 1);
  }
  {
    // a fallback-served accrual with a NONCONFORMING amount still joins
    // the resolution index (the document exists), so its dependents are
    // refused for the amount, never reported as orphans
    let gone;
    const mut = (docs) => {
      gone = docs.accrual.find((a) => a.epochIndex === 5 && a.funderId === FB);
      docs.accrual = docs.accrual.filter((a) => a !== gone);
    };
    const w = mkWorld({ mutateDocs: mut, provedByKey: (base) => async (type, key) =>
      type === "accrualByKey" && sameIdTest(key.funderId, FB)
        ? { status: "served", doc: { ...gone, amountCredits: 999 }, height: "918" }
        : base(type, key) });
    const led = await runLedger(w);
    ok("a nonconforming fallback accrual joins resolution: the amount refuses, its dependents are never orphans",
      led.recordSet.label === "REFUSED" && led.diagnostics.orphans.length === 0
      && led.perEpoch.get(5).diagnostics.some((d) => /amount 999 differs/.test(d)));
  }
  {
    // SETTLEMENT runs before the formation gate (round-34): a dangling
    // reference on the unavailable path is settled by the pinned read,
    // so a PROVED absence is a genuine orphan refusal there too, while
    // an UNSERVED read still leaves only a possible orphan
    const mkOrphan = (over) => mkWorld({ mutateDocs: (docs) => { docs.receipt.push({
      ...docs.receipt[0], id: h32("f8"), accrualId: h32("f9") }); },
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" }
          : over && type === "accrualById" ? { status: "unserved" } : base(type, key) });
    const ledAbs = await runLedger(mkOrphan(false));
    ok("a settlement-proved absence refuses as a genuine orphan on the unavailable path too",
      ledAbs.recordSet.label === "REFUSED"
      && ledAbs.diagnostics.poolGlobal.some((d) => /whose absence is proved \(an orphan\)/.test(d)));
    const ledUnd = await runLedger(mkOrphan(true));
    ok("an unserved settlement on the unavailable path still leaves only a possible orphan",
      ledUnd.recordSet.label === "UNPROVED"
      && ledUnd.diagnostics.poolGlobal.some((d) => /possible orphan receipt/.test(d)));
  }
  {
    // a RECOVERED prefix violation refuses on the unavailable path
    // (round-34): the enumeration omits the accrual, the pinned read
    // serves it at a prefix epoch with a nonzero amount, the pool read
    // is unserved
    const w = mkWorld({ provedActivation: 5,
      fetchRange: async (start, end) => ({ epochs: [
        { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }),
      mutateDocs: (docs) => { docs.receipt.push({ ...docs.receipt[0],
        id: h32("f8"), accrualId: h32("f9") }); },
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" }
          : type === "accrualById"
            ? { status: "served", doc: { id: h32("f9"), poolId: POOL_HEX, epochIndex: 4,
              funderId: FA, amountCredits: 7 }, height: "919" } : base(type, key) });
    const res = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: w.deps.fetchRange });
    const led = await runLedger(w, { resolution: res });
    ok("a recovered nonzero prefix accrual refuses on the unavailable path",
      led.recordSet.label === "REFUSED"
      && led.diagnostics.poolGlobal.some((d) => /prefix accrual in epoch 4 does not carry an integer-zero amount/.test(d)));
  }
  {
    // SETTLEMENT survives a missing sibling enumeration (round-35): the
    // part enumeration is unserved, and the dangling receipt's proved
    // absence still refuses as a genuine orphan
    const w = mkWorld({ mutateDocs: (docs) => { docs.receipt.push({ ...docs.receipt[0],
      id: h32("f8"), accrualId: h32("f9") }); },
      fetchVerifiedPage: undefined });
    const deps = { ...w.deps, fetchVerifiedPage: async (q) =>
      q.type === "part" ? { status: "unserved" } : w.deps.fetchVerifiedPage(q) };
    const led = await runLedger({ ...w, deps });
    ok("a proved-absent dangling reference refuses even when a sibling enumeration is unavailable",
      led.recordSet.label === "REFUSED"
      && led.diagnostics.poolGlobal.some((d) => /whose absence is proved \(an orphan\)/.test(d)));
  }
  {
    // settlement survives an UNAVAILABLE ACCRUAL ENUMERATION (round-37):
    // the pinned by-identifier read is its own proof, so a proved
    // absence refuses as an orphan and a recovered prefix violation
    // refuses through the prefix sweep, with no accrual enumeration at
    // all
    const mkNoAcc = (extra) => {
      const w0 = mkWorld({ mutateDocs: (docs) => { docs.receipt.push({ ...docs.receipt[0],
        id: h32("f8"), accrualId: h32("f9") }); }, ...extra });
      return { ...w0, deps: { ...w0.deps, fetchVerifiedPage: async (q) =>
        q.type === "accrual" ? { status: "unserved" } : w0.deps.fetchVerifiedPage(q) } };
    };
    const ledAbs2 = await runLedger(mkNoAcc({}));
    ok("a proved-absent dangling reference refuses even with the accrual enumeration unavailable",
      ledAbs2.recordSet.label === "REFUSED"
      && ledAbs2.diagnostics.poolGlobal.some((d) => /whose absence is proved \(an orphan\)/.test(d)));
    const wPre37 = mkNoAcc({ provedActivation: 5,
      fetchRange: async (start, end) => ({ epochs: [
        { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }),
      provedByKey: (base) => async (type, key) =>
        type === "accrualById"
          ? { status: "served", doc: { id: h32("f9"), poolId: POOL_HEX, epochIndex: 4,
            funderId: FA, amountCredits: 7 }, height: "919" } : base(type, key) });
    const resPre37 = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: wPre37.deps.fetchRange });
    const ledPre37 = await runLedger(wPre37, { resolution: resPre37 });
    ok("a recovered nonzero prefix accrual refuses even with the accrual enumeration unavailable",
      ledPre37.recordSet.label === "REFUSED"
      && ledPre37.diagnostics.poolGlobal.some((d) => /prefix accrual in epoch 4 does not carry an integer-zero amount/.test(d)));
    // a recovered OUT-OF-DOMAIN accrual refuses there too (round-38)
    const wExtra = mkNoAcc({ provedByKey: (base) => async (type, key) =>
      type === "pool" ? { status: "unserved" }
        : type === "accrualById"
          ? { status: "served", doc: { id: h32("f9"), poolId: POOL_HEX, epochIndex: 40,
            funderId: FA, amountCredits: 0 }, height: "919" } : base(type, key) });
    const ledExtra = await runLedger(wExtra);
    ok("a recovered out-of-domain accrual refuses on the unavailable path (the accrual classifies out of domain)",
      ledExtra.recordSet.label === "REFUSED"
      && ledExtra.diagnostics.poolGlobal.some((d) => /outside the validation domain/.test(d)));
    // and an UNDECIDED settlement stays only a possible orphan, proving
    // the OUTCOME (not the enumeration's absence) drives the refusal
    const wUnd = mkNoAcc({ provedByKey: (base) => async (type, key) =>
      type === "accrualById" ? { status: "unserved" } : base(type, key) });
    const ledUnd2 = await runLedger(wUnd);
    ok("an undecided settlement with the accrual enumeration unavailable stays a possible orphan, never a refusal",
      ledUnd2.recordSet.label === "UNPROVED"
      && ledUnd2.diagnostics.poolGlobal.some((d) => /possible orphan receipt/.test(d)));
  }
  {
    // a recovered accrual served under its BASE58 spelling still feeds
    // the sweeps (round-35): the identifier is normalized at the join
    const w = mkWorld({ provedActivation: 5,
      fetchRange: async (start, end) => ({ epochs: [
        { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }),
      mutateDocs: (docs) => { docs.receipt.push({ ...docs.receipt[0],
        id: h32("f8"), accrualId: h32("f9") }); },
      provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "unserved" }
          : type === "accrualById"
            ? { status: "served", doc: { id: toBase58(h32("f9")), poolId: POOL_HEX,
              epochIndex: 4, funderId: FA, amountCredits: 0 }, height: "919" } : base(type, key) });
    const res = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: w.deps.fetchRange });
    const led = await runLedger(w, { resolution: res });
    ok("a base58-spelled recovered accrual still feeds the prefix sweep (transfer under a prefix accrual refuses)",
      led.recordSet.label === "REFUSED"
      && led.diagnostics.poolGlobal.some((d) => /transfer records exist under a prefix accrual in epoch 4/.test(d)));
  }
  {
    // a proved reservation ABSENCE beside an ENUMERATED reservation, on
    // the missing-receipt row, is a fetched mismatch and refuses the
    // record set (round-35)
    let a0;
    const w = mkWorld({ mutateDocs: (docs) => { a0 = docs.accrual[0]; docs.receipt.splice(0, 1); },
      provedByKey: (base) => async (type, key) =>
        type === "receiptByAccrual" && sameIdTest(key.accrualId, a0.id) ? { status: "unserved" }
          : type === "reservationByAccrual" && sameIdTest(key.accrualId, a0.id)
            ? { status: "proved-absence", height: "2000" }
            : base(type, key) });
    const led = await runLedger(w);
    ok("a proved reservation absence beside an enumerated reservation refuses on the missing-receipt row too",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /proves ABSENCE while the enumeration served one/.test(d)));
  }
  {
    // a missing expected ACCRUAL contributes to the aggregates, observed
    // through a narrowed interval so no empty epoch's inheritance can
    // mask the contribution
    const w = mkWorld();
    const gone = w.docs.accrual.find((a) => a.epochIndex === 5);
    w.docs.accrual = w.docs.accrual.filter((a) => a !== gone);
    const resolution = await resolveInterval({ requestedStart: 5, requestedEnd: 5,
      configuredStart: 5, fetchRange: w.deps.fetchRange });
    const led = await runLedger(w, { resolution });
    ok("a missing expected accrual's row contributes REFUSED to the transfer aggregate",
      led.aggregates.transferExecution === "REFUSED"
      && led.aggregates.ordering === "OPERATOR-PROVIDED");
  }
  {
    // MIXED answers: a nonconformance the pool already establishes stays
    // visible past a later unserved read
    const w = mkWorld({ nodeType: "regular", provedByKey: (base) => async (type, key) =>
      type === "completionReceipt" ? { status: "unverified" } : base(type, key) });
    const f = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w.deps });
    ok("a non-evo pool refuses even when the receipt read is unavailable",
      f.label === "REFUSED" && /eligibility/.test(f.reason));
    // FB sorts FIRST in the canonical row order, so ITS read is the
    // unserved one and every later row is proved absent: the refusal must
    // still win over the earlier unavailability
    const w2 = mkWorld({ provedByKey: (base) => async (type, key) => {
      if (type === "identity" && key.identityId === FB) return { status: "unserved" };
      if (type === "identity") return { status: "proved-absence", height: "892" };
      return base(type, key);
    } });
    const f2 = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w2.deps });
    ok("a later identity's proved absence outranks an earlier unserved read",
      f2.label === "REFUSED" && /proved absence/.test(f2.reason));
    const seen3 = new Set();
    const w3 = mkWorld({ provedByKey: (base) => async (type, key) => {
      if (type === "identity") {
        seen3.add(key.identityId);
        if (key.identityId === FB) return { status: "proved-absence", height: "892" };
      }
      return base(type, key);
    } });
    await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w3.deps });
    ok("an early proved absence never skips the later identity rows",
      seen3.size === 3);
    await rejects("a later adapter violation still refuses hard past an early absence",
      (async () => {
        const w4 = mkWorld({ provedByKey: (base) => async (type, key) => {
          if (type === "identity" && key.identityId === FB) return { status: "proved-absence", height: "892" };
          if (type === "identity") return { status: "served", doc: { id: h32("99") }, height: "892" };
          return base(type, key);
        } });
        return evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w4.deps });
      })(), /DIFFERENT identity/);
  }
  await rejects("a foreign document in a PROVED enumeration refuses even beside an unproved sibling",
    (async () => {
      const w = mkWorld({ mutateDocs: (docs) => { docs.header.push({ id: h32("f0"),
        poolId: h32("99"), accrualId: h32("a0") }); } });
      const deps = { ...w.deps, fetchVerifiedPage: async (args) => {
        if (args.type === "accrual") return { status: "unserved" };
        const all = [...w.docs[args.type]].sort((a, b) => (a.id < b.id ? -1 : 1));
        const start = args.startAfter === null ? 0 : all.findIndex((d) => d.id === args.startAfter) + 1;
        return { status: "verified", documents: all.slice(start, start + args.limit), height: "900" };
      } };
      return runLedger({ ...w, deps });
    })(), /DIFFERENT pool/);
  {
    // a prefix header's full shape is held (not only its credits)
    const w = mkWorld({ provedActivation: 5,
      mutateDocs: (docs) => { docs.header.push({ id: h32("f6"), poolId: POOL_HEX,
        epochIndex: 4, grossCredits: 0, feeCredits: 0, memberCount: 999, calcVersion: 2,
        allocationHash: "bb".repeat(32) }); },
      fetchRange: async (start, end) => ({ epochs: [
        { number: 4, totalProcessingFees: "1", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
        { number: 5, totalProcessingFees: "100000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 1 },
        { number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 },
      ].filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const resolution = await resolveInterval({ requestedStart: 4, requestedEnd: null,
      configuredStart: 5, provedActivation: 5, fetchRange: w.deps.fetchRange });
    const led = await runLedger(w, { resolution });
    ok("a zero-credit prefix header with foreign shape members refuses",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(4).diagnostics.some((x) => /calcVersion, memberCount or allocationHash/.test(x)));
  }
  {
    // the known-key fallback binds the served answer to the requested key
    const w = mkWorld({ mutateDocs: (docs) => { docs.header.splice(0, 1); },
      provedByKey: (base) => async (type, key) =>
        type === "headerByEpoch"
          ? { status: "served", doc: { id: h32("10"), poolId: POOL_HEX, epochIndex: 40,
            grossCredits: 1000000, feeCredits: 200000, memberCount: 3, calcVersion: 1,
            allocationHash: "aa".repeat(32) }, height: "900" }
          : base(type, key) });
    const led = await runLedger(w);
    ok("a served known-key answer for a DIFFERENT key refuses instead of standing in",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /DIFFERENT key/.test(d)));
  }
  await rejects("an undeclared proved-read status refuses hard (the answer vocabulary is closed)",
    (async () => {
      const w = mkWorld({ provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "bogus", doc: {} } : base(type, key) });
      return evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w.deps });
    })(), /answer vocabulary is closed/);
  await rejects("a served document read without its height refuses hard",
    (async () => {
      const w = mkWorld({ provedByKey: (base) => async (type, key) =>
        type === "pool" ? { status: "served", doc: {} } : base(type, key) });
      return evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w.deps });
    })(), /authenticated height/);
  await rejects("a served answer without a DOCUMENT refuses hard (identity reads included)",
    (async () => {
      const w = mkWorld({ provedByKey: (base) => async (type, key) =>
        type === "identity" ? { status: "served", height: "892" } : base(type, key) });
      return evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w.deps });
    })(), /served without a document/);
  await rejects("a served contract read without its height refuses hard",
    (async () => {
      const w = mkWorld();
      return evaluateContractIntegrity({ contractId: GC,
        expectedContractPayload: w.deps.expectedContractPayload,
        deps: { ...w.deps, provedByKey: async () => ({ status: "served", doc: w.contractPayload }) } });
    })(), /authenticated height/);
  await rejects("a pool lookup serving a DIFFERENT pool refuses hard",
    (async () => {
      const w = mkWorld();
      const deps = { ...w.deps, provedByKey: async (type, key) =>
        type === "pool" ? { status: "served", doc: { ...w.pool, "$id": h32("99") }, height: "890" }
          : w.deps.provedByKey(type, key) };
      return evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps });
    })(), /DIFFERENT pool/);
  {
    const w = mkWorld();
    const foreignFr = { ...w.fr, poolId: Buffer.from(h32("99"), "hex") };
    const deps = { ...w.deps, provedByKey: async (type, key) =>
      type === "completionReceipt" ? { status: "served", doc: foreignFr, height: "891" }
        : w.deps.provedByKey(type, key) };
    const f = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps });
    ok("a completion receipt naming a different pool refuses (never substituted as the expectation)",
      f.label === "REFUSED" && /different pool/.test(f.reason));
  }
  for (const foreignType of ["header", "accrual", "reservation", "receipt", "part"]) {
    await rejects(`a foreign-pool document in the ${foreignType} enumeration refuses hard`,
      (async () => {
        const w = mkWorld({ mutateDocs: (docs) => {
          docs[foreignType].push({ id: h32("f0"), poolId: h32("99"), accrualId: h32("a0") });
        } });
        return runLedger(w);
      })(), /DIFFERENT pool/);
  }
  await rejects("a contract lookup serving a DIFFERENT contract refuses hard",
    (async () => {
      const w = mkWorld();
      return evaluateContractIntegrity({ contractId: GC,
        expectedContractPayload: w.deps.expectedContractPayload,
        deps: { ...w.deps, provedByKey: async () => ({ status: "served",
          doc: { ...w.contractPayload, "$id": h32("99") }, height: "889" }) } });
    })(), /DIFFERENT contract/);
  await rejects("a served ARRAY document refuses hard (a document is a plain object)",
    (async () => {
      const w = mkWorld({ provedByKey: (base) => async (type, key) =>
        type === "identity" ? { status: "served", doc: [], height: "892" } : base(type, key) });
      return evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w.deps });
    })(), /never an array/);
  await rejects("an identity lookup serving a DIFFERENT identity refuses hard",
    (async () => {
      const w = mkWorld({ provedByKey: (base) => async (type, key) =>
        type === "identity" ? { status: "served", doc: { id: h32("99") }, height: "892" } : base(type, key) });
      return evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w.deps });
    })(), /DIFFERENT identity/);
  {
    // a served known-key document without its identifier is nonconforming
    const w = mkWorld({ mutateDocs: (docs) => { docs.header.splice(0, 1); },
      provedByKey: (base) => async (type, key) =>
        type === "headerByEpoch"
          ? { status: "served", doc: { poolId: POOL_HEX, epochIndex: 5, grossCredits: 1000000,
            feeCredits: 200000, memberCount: 3, calcVersion: 1,
            allocationHash: "aa".repeat(32) }, height: "900" }
          : base(type, key) });
    const led = await runLedger(w);
    ok("a known-key document without its 64-hex identifier refuses as nonconforming",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /no 64-hex identifier/.test(d)));
  }
  {
    // a wrong-key served answer's height never reaches the range
    const w = mkWorld({ mutateDocs: (docs) => { docs.header.splice(0, 1); },
      provedByKey: (base) => async (type, key) =>
        type === "headerByEpoch"
          ? { status: "served", doc: { id: h32("10"), poolId: POOL_HEX, epochIndex: 40,
            grossCredits: 1000000, feeCredits: 200000, memberCount: 3, calcVersion: 1,
            allocationHash: "aa".repeat(32) }, height: "999999" }
          : base(type, key) });
    const led = await runLedger(w);
    ok("a wrong-key answer's height is withheld from the range candidates",
      led.recordSet.label === "REFUSED" && !led.heightCandidates.includes("999999"));
  }
  {
    // wrong-key served answers refuse for the ACCRUAL and RECEIPT
    // fallbacks too, not only the header's
    const wA = mkWorld();
    const stolenA = wA.docs.accrual[0];
    wA.docs.accrual.splice(0, 1);
    const depsA = { ...wA.deps, provedByKey: async (type, key) =>
      type === "accrualByKey" && sameIdTest(key.funderId, stolenA.funderId)
        ? { status: "served", doc: { ...stolenA, funderId: h32("77") }, height: "918" }
        : wA.deps.provedByKey(type, key) };
    const ledA = await runLedger({ ...wA, deps: depsA });
    ok("a served accrual fallback for a DIFFERENT funder refuses",
      ledA.recordSet.label === "REFUSED"
      && ledA.perEpoch.get(5).diagnostics.some((d) => /DIFFERENT key/.test(d)));
    const wR = mkWorld();
    const stolenR = wR.docs.receipt[0];
    wR.docs.receipt.splice(0, 1);
    const depsR = { ...wR.deps, provedByKey: async (type, key) =>
      type === "receiptByAccrual" && sameIdTest(key.accrualId, stolenR.accrualId)
        ? { status: "served", doc: { ...stolenR, accrualId: h32("a1") }, height: "916" }
        : wR.deps.provedByKey(type, key) };
    const ledR = await runLedger({ ...wR, deps: depsR });
    ok("a served receipt fallback for a DIFFERENT accrual refuses",
      ledR.recordSet.label === "REFUSED"
      && ledR.perEpoch.get(5).diagnostics.some((d) => /DIFFERENT key/.test(d)));
    const wP = mkWorld();
    const stolenP = wP.docs.receipt[0];
    wP.docs.receipt.splice(0, 1);
    const depsP = { ...wP.deps, provedByKey: async (type, key) =>
      type === "receiptByAccrual" && sameIdTest(key.accrualId, stolenP.accrualId)
        ? { status: "served", doc: { ...stolenP, poolId: h32("99") }, height: "957" }
        : wP.deps.provedByKey(type, key) };
    const ledP = await runLedger({ ...wP, deps: depsP });
    ok("a served receipt fallback for a FOREIGN POOL refuses and withholds its height",
      ledP.recordSet.label === "REFUSED"
      && ledP.perEpoch.get(5).diagnostics.some((d) => /DIFFERENT key/.test(d))
      && !ledP.heightCandidates.includes("957"));
  }
  {
    // a fallback receipt joins the index: no false in-flight diagnostic
    const w = mkWorld();
    const stolen = w.docs.receipt[0];
    w.docs.receipt.splice(0, 1);
    const deps = { ...w.deps, provedByKey: async (type, key) =>
      type === "receiptByAccrual" && key.accrualId === stolen.accrualId
        ? { status: "served", doc: stolen, height: "942" }
        : w.deps.provedByKey(type, key) };
    const led = await runLedger({ ...w, deps });
    ok("a fallback receipt is never re-reported as an in-flight reservation, and the recovery degrades completeness to UNPROVED (round-54, F5)",
      led.recordSet.label === "UNPROVED"
      && led.perEpoch.get(5).diagnostics.some((d) => /INCOMPLETE/.test(d))
      && !led.diagnostics.poolGlobal.some((d) => /no receipt/.test(d)));
    ok("the fallback receipt's height enters the range candidates (a value no enumeration supplies)",
      led.heightCandidates.includes("942"));
  }
  {
    // a conforming RESERVATION the pinned read serves but the enumeration
    // omitted degrades record-set completeness to UNPROVED, extending the
    // F5 recovery policy to the reservation path (round-55, F2). The
    // reservation ASPECT stays PROVED (the record is present and conforms).
    const w = mkWorld();
    const stolen = w.docs.reservation[0];
    w.docs.reservation.splice(0, 1);
    const deps = { ...w.deps, provedByKey: async (type, key) =>
      type === "reservationByAccrual" && sameIdTest(key.accrualId, stolen.accrualId)
        ? { status: "served", doc: stolen, height: "915" }
        : w.deps.provedByKey(type, key) };
    const led = await runLedger({ ...w, deps });
    ok("a recovered conforming reservation is itself PROVED but degrades record-set completeness to UNPROVED",
      led.receiptEvaluations.every((e) => e.reservation === "PROVED")
      && led.recordSet.label === "UNPROVED"
      && led.perEpoch.get(5).diagnostics.some((d) => /reservation: recovered by the pinned read but ABSENT/.test(d)));
    // the recovery does NOT mark the epoch's DISTRIBUTION incomplete (round-59,
    // F3): a recovered record EXISTS and conforms, so the four recovery paths
    // share one rule, degrade record-set completeness but never lag. The
    // distribution-incomplete diagnostic must be absent and lagCount zero.
    ok("a reservation recovery degrades completeness without marking the distribution incomplete (no lag)",
      led.lag.lagCount === 0
      && !led.perEpoch.get(5).diagnostics.some((d) => /distribution is incomplete/.test(d)));
  }
  {
    // the enumeration and the pinned UNIQUE-KEY reservation read serving
    // DIFFERENT documents is a fetched mismatch that refuses (round-58, F2):
    // both conform to the receipt individually, but a unique-key read cannot
    // serve a different identifier than the enumeration for the same accrual.
    const w = mkWorld();
    const enumRes = w.docs.reservation[0];
    const different = { ...enumRes, id: h32("dd") }; // same content, DIFFERENT id
    const deps = { ...w.deps, provedByKey: async (type, key) =>
      type === "reservationByAccrual" && sameIdTest(key.accrualId, enumRes.accrualId)
        ? { status: "served", doc: different, height: "915" }
        : w.deps.provedByKey(type, key) };
    const led = await runLedger({ ...w, deps });
    ok("enumeration and pinned reservation reads serving different documents refuse the record set",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /serve DIFFERENT documents/.test(d)));
  }
  {
    // the SAME identity cross-check on the MISSING-RECEIPT path (round-59, F1):
    // the receipt is omitted (its known-key read unserved), the enumeration
    // serves reservation R1, and the pinned read serves a DIFFERENT conforming
    // reservation R2. The two unique-key reads disagreeing is a fetched
    // mismatch that refuses, not merely UNPROVED from the absent receipt.
    const w = mkWorld({ mutateDocs: (docs) => { docs.receipt.splice(0, 1); } });
    const enumRes = w.docs.reservation[0];
    const different = { ...enumRes, id: h32("de") };
    const deps = { ...w.deps, provedByKey: async (type, key) =>
      type === "receiptByAccrual" && sameIdTest(key.accrualId, enumRes.accrualId)
        ? { status: "unserved" }
        : type === "reservationByAccrual" && sameIdTest(key.accrualId, enumRes.accrualId)
          ? { status: "served", doc: different, height: "915" }
          : w.deps.provedByKey(type, key) };
    const led = await runLedger({ ...w, deps });
    ok("on the missing-receipt path too, disagreeing reservation reads refuse the record set",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /serve DIFFERENT documents/.test(d)));
  }
  {
    // the identity cross-checks compare WHOLE identifiers (round-60): two
    // documents whose identifiers share a long common prefix and differ
    // only at the tail are still DIFFERENT documents, on both paths
    const w = mkWorld();
    const enumRes = w.docs.reservation[0];
    const nearId = enumRes.id.slice(0, 62) + (enumRes.id.slice(62) === "ff" ? "fe" : "ff");
    const different = { ...enumRes, id: nearId };
    const deps = { ...w.deps, provedByKey: async (type, key) =>
      type === "reservationByAccrual" && sameIdTest(key.accrualId, enumRes.accrualId)
        ? { status: "served", doc: different, height: "915" }
        : w.deps.provedByKey(type, key) };
    const led = await runLedger({ ...w, deps });
    ok("reservation identifiers sharing a prefix but differing at the tail still refuse (receipt present)",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /serve DIFFERENT documents/.test(d)));
    const w2 = mkWorld({ mutateDocs: (docs) => { docs.receipt.splice(0, 1); } });
    const enumRes2 = w2.docs.reservation[0];
    const nearId2 = enumRes2.id.slice(0, 62) + (enumRes2.id.slice(62) === "ff" ? "fe" : "ff");
    const different2 = { ...enumRes2, id: nearId2 };
    const deps2 = { ...w2.deps, provedByKey: async (type, key) =>
      type === "receiptByAccrual" && sameIdTest(key.accrualId, enumRes2.accrualId)
        ? { status: "unserved" }
        : type === "reservationByAccrual" && sameIdTest(key.accrualId, enumRes2.accrualId)
          ? { status: "served", doc: different2, height: "915" }
          : w2.deps.provedByKey(type, key) };
    const led2 = await runLedger({ ...w2, deps: deps2 });
    ok("reservation identifiers sharing a prefix but differing at the tail still refuse (missing receipt)",
      led2.recordSet.label === "REFUSED"
      && led2.perEpoch.get(5).diagnostics.some((d) => /serve DIFFERENT documents/.test(d)));
  }
  {
    // the reservation-to-receipt transitionHash binding compares WHOLE
    // hashes (round-60): a bound hash equal in prefix and differing only
    // at the tail is a fetched mismatch
    const w = mkWorld({ mutateDocs: (docs) => {
      const t = docs.receipt[0].transitionHash;
      docs.reservation[0].transitionHash = t.slice(0, 62) + (t.slice(62) === "ff" ? "fe" : "ff");
    } });
    const led = await runLedger(w);
    ok("a reservation transitionHash differing from the receipt's only at the tail refuses",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /different transitionHash/.test(d)));
  }
  {
    // ---- THE VERIFICATION BOUNDARY (round-65) ----
    // Everything rounds 59 through 64 built here is DELETED with the machinery
    // it defended: the recognizers, the private registries, the disown helper,
    // the call wrappers, and the retained-refusal, recovered-constructor,
    // accessor-lookup and revoked-proxy cases that existed only to prove those
    // could not be defeated. They were answering "did this thrown value come
    // from trusted verification", which exceptions cannot answer.
    //
    // The contract now has two halves and both are gated here, at the seam the
    // audit actually depends on. See docs/E2_VERIFICATION_BOUNDARY.md.
    const w = mkWorld();
    // (1) A REFUSAL IS RETURNED, and the audit grades on it. The verifier is
    // handed a receipt whose reservation chain cannot conform, so it returns
    // a refusal; the transfer aspect must carry it as adverse evidence.
    const refusing = { ...w.deps, verifierDeps: { ...w.deps.verifierDeps,
      verifyStageTwo: async () => false } };
    const refused = await evaluateTransferExecution({ receipt: w.receipts[0], parts: [],
      entitlementRow: { recipientId: FA, amountCredits: "400000" },
      accrual: w.accruals[0], headerFor: w.docs.header[0], incomeIdentity: INCOME,
      chainIdPin: CHAIN, capture: w.captures[0], supersessions: [], deps: refusing });
    ok("a RETURNED refusal from the verifier becomes adverse evidence on the transfer aspect",
      refused.label === "REFUSED" && /stage two/.test(refused.reason));
    // the CAPTURE verdict is read separately from the receipt's (round-65):
    // this capture fails its OWN clauses (a non-canonical inclusion height)
    // while the receipt verifies, so only the capture read can produce the
    // refusal, and ignoring that verdict would grade the epoch as executed
    const badCapture = { ...w.captures[0], inclusionHeight: "0123" };
    const capRefused = await evaluateTransferExecution({ receipt: w.receipts[0], parts: [],
      entitlementRow: { recipientId: FA, amountCredits: "400000" },
      accrual: w.accruals[0], headerFor: w.docs.header[0], incomeIdentity: INCOME,
      chainIdPin: CHAIN, capture: badCapture, supersessions: [], deps: w.deps });
    ok("a refused CAPTURE verdict becomes adverse evidence, read separately from the receipt's",
      capRefused.label === "REFUSED" && /canonical non-negative decimal/.test(capRefused.reason));
    // (2) A DEPENDENCY FAILURE IS A FAULT and propagates. It must never be
    // converted into a label, because a broken proof helper says nothing about
    // whether a receipt conforms. This is the property the whole provenance
    // apparatus was trying to protect, and it now holds by construction: the
    // audit reads a status off a returned value and never inspects a throw.
    for (const stage of ["verifyStageOne", "verifyStageTwo"]) {
      const boom = new Error("the proof helper is offline");
      let thrown = null; let outcome = null;
      try {
        outcome = await evaluateTransferExecution({ receipt: w.receipts[0], parts: [],
          entitlementRow: { recipientId: FA, amountCredits: "400000" },
          accrual: w.accruals[0], headerFor: w.docs.header[0], incomeIdentity: INCOME,
          chainIdPin: CHAIN, capture: w.captures[0], supersessions: [],
          deps: { ...w.deps, verifierDeps: { ...w.deps.verifierDeps,
            [stage]: async () => { throw boom; } } } });
      } catch (e) { thrown = e; }
      ok(`a throwing ${stage} propagates as a fault and never becomes a label`,
        thrown === boom && outcome === null);
    }
    // (3) the same on the HEADER-CAPTURE path, which classifies separately
    {
      const boom = new Error("the proof helper is offline");
      let thrown = null;
      try {
        await runLedger({ ...w, deps: { ...w.deps, verifierDeps: { ...w.deps.verifierDeps,
          verifyStageOne: async () => { throw boom; } } } });
      } catch (e) { thrown = e; }
      ok("a throwing proof stage propagates from the header-capture path too",
        thrown === boom);
    }
    // (4) a verifier that returns a REFUSED verdict for the header capture
    // degrades ordering rather than refusing the run: an invalid capture is
    // evidence about that capture, and the audit says so
    {
      const led = await runLedger({ ...w, deps: { ...w.deps,
        verifyCaptureBasis: async (cap) => cap.kind !== CAP_HEADER } });
      ok("a header capture that fails its basis degrades ordering, never a fault",
        led.aggregates.ordering === "OPERATOR-PROVIDED");
    }
  }
  {
    // a proved-read adapter that throws SYNCHRONOUSLY (rather than returning
    // a rejected promise) is inside the guard too (round-61): the read used
    // to be INVOKED while building the argument, so the call happened before
    // the guard was entered and a synchronous throw escaped raw. The guard
    // takes a thunk, so a synchronous throw and a rejection are one event.
    const w = mkWorld();
    const depsSync = { ...w.deps, provedByKey: (type, key) => {
      if (type === "pool") throw new Error("the decoder is unavailable");
      return w.deps.provedByKey(type, key);
    } };
    await rejects("a SYNCHRONOUSLY throwing proved read is a plain adapter-fault refusal, with its real cause",
      evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: depsSync }),
      /a proved adapter read failed \(the decoder is unavailable\)/);
    // and the same on the contract read, which is a different call site
    const depsSyncC = { ...w.deps, provedByKey: (type, key) => {
      if (type === "contract") throw new Error("the decoder is unavailable");
      return w.deps.provedByKey(type, key);
    } };
    await rejects("a SYNCHRONOUSLY throwing contract read is a plain adapter-fault refusal too",
      evaluateContractIntegrity({ contractId: GC,
        expectedContractPayload: w.deps.expectedContractPayload, deps: depsSyncC }),
      /a proved adapter read failed \(the decoder is unavailable\)/);
    // and through the ENTRY, over the known-key and reservation reads
    const depsSyncR = { ...w.deps, provedByKey: (type, key) => {
      if (type === "reservationByAccrual") throw new Error("the decoder is unavailable");
      return w.deps.provedByKey(type, key);
    } };
    await rejects("a SYNCHRONOUSLY throwing reservation read refuses through the ledger evaluation",
      runLedger({ ...w, deps: depsSyncR }),
      /a proved adapter read failed \(the decoder is unavailable\)/);
    // EVERY read type, not the three that happened to be cited (round-62):
    // one call site left passing an already-invoked promise would let a
    // synchronous decoder fault escape there while these gates stayed true,
    // so each type is driven through a world that reaches it.
    const syncOf = (type) => ({ ...w.deps, provedByKey: (t, key) => {
      if (t === type) throw new Error("the decoder is unavailable");
      return w.deps.provedByKey(t, key);
    } });
    await rejects("a SYNCHRONOUSLY throwing completion-receipt read refuses",
      evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: syncOf("completionReceipt") }),
      /a proved adapter read failed \(the decoder is unavailable\)/);
    await rejects("a SYNCHRONOUSLY throwing identity read refuses",
      evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: syncOf("identity") }),
      /a proved adapter read failed \(the decoder is unavailable\)/);
    // the three known-key fallbacks are reached when the enumeration omits
    // the record, and the by-identifier settlement when an accrual is
    // referenced but unresolved
    const wMissHeader = mkWorld({ mutateDocs: (docs) => { docs.header.splice(0, 1); } });
    await rejects("a SYNCHRONOUSLY throwing header fallback read refuses",
      runLedger({ ...wMissHeader, deps: { ...wMissHeader.deps, provedByKey: (t, key) => {
        if (t === "headerByEpoch") throw new Error("the decoder is unavailable");
        return wMissHeader.deps.provedByKey(t, key); } } }),
      /a proved adapter read failed \(the decoder is unavailable\)/);
    const wMissAccrual = mkWorld({ mutateDocs: (docs) => { docs.accrual.splice(0, 1); } });
    await rejects("a SYNCHRONOUSLY throwing accrual fallback read refuses",
      runLedger({ ...wMissAccrual, deps: { ...wMissAccrual.deps, provedByKey: (t, key) => {
        if (t === "accrualByKey") throw new Error("the decoder is unavailable");
        return wMissAccrual.deps.provedByKey(t, key); } } }),
      /a proved adapter read failed \(the decoder is unavailable\)/);
    const wMissReceipt = mkWorld({ mutateDocs: (docs) => { docs.receipt.splice(0, 1); } });
    await rejects("a SYNCHRONOUSLY throwing receipt fallback read refuses",
      runLedger({ ...wMissReceipt, deps: { ...wMissReceipt.deps, provedByKey: (t, key) => {
        if (t === "receiptByAccrual") throw new Error("the decoder is unavailable");
        return wMissReceipt.deps.provedByKey(t, key); } } }),
      /a proved adapter read failed \(the decoder is unavailable\)/);
    const wDangling = mkWorld({ mutateDocs: (docs) => {
      docs.receipt[0] = { ...docs.receipt[0], accrualId: h32("e7") }; } });
    await rejects("a SYNCHRONOUSLY throwing by-identifier settlement read refuses",
      runLedger({ ...wDangling, deps: { ...wDangling.deps, provedByKey: (t, key) => {
        if (t === "accrualById") throw new Error("the decoder is unavailable");
        return wDangling.deps.provedByKey(t, key); } } }),
      /a proved adapter read failed \(the decoder is unavailable\)/);
  }
  {
    // a capture-basis adapter that throws a NULL-PROTOTYPE value is a clean
    // adapter-fault Error, never an escaping raw TypeError (round-58, F1): the
    // caught value is formatted totally, the same class the plain-data catch
    // handled in round 57.
    const w = mkWorld({ verifyCaptureBasis: async () => { throw Object.create(null); } });
    await rejects("a capture-basis adapter throwing a null-prototype value is a clean adapter-fault Error, never an escaping raw TypeError",
      runLedger(w), /capture-basis adapter failed/);
  }
  await rejects("a proved ABSENCE without its height refuses hard too",
    (async () => {
      const w = mkWorld({ provedByKey: (base) => async (type, key) =>
        type === "reservationByAccrual" ? { status: "proved-absence" } : base(type, key) });
      return runLedger(w);
    })(), /authenticated height/);
  await rejects("a served reservation document without its 64-hex identifier refuses hard",
    (async () => {
      const w = mkWorld({ provedByKey: (base) => async (type, key) => {
        if (type === "reservationByAccrual") {
          const ans = await base(type, key);
          return ans.status === "served"
            ? { ...ans, doc: { poolId: ans.doc.poolId, accrualId: ans.doc.accrualId,
              transitionHash: ans.doc.transitionHash } }
            : ans;
        }
        return base(type, key);
      } });
      return runLedger(w);
    })(), /without its 64-hex identifier/);
  await rejects("an enumeration's foreign document refuses even when formation is unproved",
    (async () => {
      const w = mkWorld({ mutateDocs: (docs) => { docs.header.push({ id: h32("f0"),
        poolId: h32("99"), epochIndex: 7, grossCredits: 0, feeCredits: 0,
        memberCount: 3, calcVersion: 1, allocationHash: "aa".repeat(32) }); },
        provedByKey: (base) => async (type, key) =>
          type === "pool" ? { status: "unserved" } : base(type, key) });
      return runLedger(w);
    })(), /DIFFERENT pool/);
  await rejects("a served reservation read without its height refuses hard at the per-receipt site",
    (async () => {
      const w = mkWorld({ provedByKey: (base) => async (type, key) =>
        type === "reservationByAccrual"
          ? { status: "served", doc: (await base(type, key)).doc } : base(type, key) });
      return runLedger(w);
    })(), /authenticated height/);
  {
    // the accrual fallback runs full conformance and joins the index
    const wBad = mkWorld();
    const stolen = wBad.docs.accrual[0];
    wBad.docs.accrual.splice(0, 1);
    const wBadDeps = { ...wBad.deps, provedByKey: async (type, key) =>
      type === "accrualByKey" && key.funderId === stolen.funderId
        ? { status: "served", doc: { ...stolen, amountCredits: 400001 }, height: "901" }
        : wBad.deps.provedByKey(type, key) };
    const ledBad = await runLedger({ ...wBad, deps: wBadDeps });
    ok("a known-key fallback accrual with a wrong amount refuses like an enumerated one",
      ledBad.recordSet.label === "REFUSED"
      && ledBad.perEpoch.get(5).diagnostics.some((d) => /differs from the recomputed/.test(d)));
    const wGood = mkWorld();
    const kept = wGood.docs.accrual[0];
    wGood.docs.accrual.splice(0, 1);
    const wGoodDeps = { ...wGood.deps, provedByKey: async (type, key) =>
      type === "accrualByKey" && key.funderId === kept.funderId
        ? { status: "served", doc: kept, height: "941" }
        : wGood.deps.provedByKey(type, key) };
    const ledGood = await runLedger({ ...wGood, deps: wGoodDeps });
    ok("a conforming fallback accrual joins the resolution index (its dependents are never orphans) and degrades completeness to UNPROVED (round-54, F5)",
      ledGood.recordSet.label === "UNPROVED" && ledGood.diagnostics.orphans.length === 0
      && ledGood.perEpoch.get(5).diagnostics.some((d) => /INCOMPLETE/.test(d)));
    ok("the fallback accrual's height enters the range candidates (a value no enumeration supplies)",
      ledGood.heightCandidates.includes("941"));
  }
  {
    // contract integrity: no vacuous route and a canonical comparison
    const w = mkWorld();
    await rejects("a missing expected payload refuses hard, never PROVED",
      evaluateContractIntegrity({ contractId: GC, expectedContractPayload: undefined, deps: w.deps }),
      /needs the supplied registration payload/);
    // the supplied payload here is the CLEAN registration shape (round-61):
    // the fetched shape carries the platform envelope, which the supplied
    // payload never does, and supplying it now refuses at the request check
    // before the adapter answer is ever read, which is a different assertion
    // than the adapter-defect one this case is for
    await rejects("a served contract read without a document refuses hard (an adapter defect)",
      evaluateContractIntegrity({ contractId: GC,
        expectedContractPayload: w.deps.expectedContractPayload,
        deps: { ...w.deps, provedByKey: async () => ({ status: "served", doc: undefined, height: "1" }) } }),
      /served without a document|undefined, outside the JSON value domain/);
    const reordered = await evaluateContractIntegrity({ contractId: GC,
      expectedContractPayload: { documents: { pool: { required: ["nodeType", "operatorFeeBps"] } },
        documentTypes: ["header", "accrual", "reservation", "receipt", "part"], version: "v11" },
      deps: w.deps });
    ok("member order never decides contract equality (the comparison is canonical)",
      reordered.label === "PROVED");
  }
  ok("a malformed capture height degrades ordering instead of throwing",
    evaluateOrdering({ receipt: { transitionHash: h32("01") }, receiptCaptureValid: true,
      capture: { transitionHash: h32("01"), heightRoute: "tenderdash-tx", inclusionHeight: "01x" },
      headerCaptureValid: true,
      headerCapture: { heightRoute: "tenderdash-tx", inclusionHeight: "1000" } }).label === "OPERATOR-PROVIDED");
  {
    // the ENUMERATED reservation's own content is evaluated: a fetched
    // mismatch refuses even when the known-key read conforms
    // the known-key reservation answer serves the enumeration's own
    // documents in this world, so the ENUMERATED mismatch is what the
    // refusal isolates
    const w2 = mkWorld({ mutateDocs: (docs) => { docs.reservation[0].transitionHash = h32("99"); } });
    const led = await runLedger(w2);
    ok("an enumerated reservation with a foreign transitionHash is a fetched mismatch",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /different transitionHash than the receipt/.test(d)));
  }
  {
    const w = mkWorld({ mutateDocs: (docs) => { docs.header[0].calcVersion = 2; } });
    const led = await runLedger(w);
    ok("a header with a foreign calcVersion refuses (the calculation is version 1)",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /calcVersion/.test(d)));
    const w2 = mkWorld({ mutateDocs: (docs) => { docs.header[0].allocationHash = "bb".repeat(32); } });
    const led2 = await runLedger(w2);
    ok("a header whose allocationHash differs from the formation receipt's refuses",
      led2.recordSet.label === "REFUSED"
      && led2.perEpoch.get(5).diagnostics.some((d) => /allocationHash differs/.test(d)));
  }
  {
    // a FALLBACK zero-entitlement accrual is swept for dependents too:
    // remove epoch 6's accrual from the enumeration, serve it by known
    // key, and enumerate a receipt under it (the round-6 gap)
    const w = mkWorld();
    const zeroAccrual = w.docs.accrual.find((a) => a.epochIndex === 6 && a.funderId === FA);
    w.docs.accrual = w.docs.accrual.filter((a) => a !== zeroAccrual);
    w.docs.receipt.push({ ...w.docs.receipt[0], id: h32("fb"), accrualId: zeroAccrual.id });
    const deps = { ...w.deps, provedByKey: async (type, key) =>
      type === "accrualByKey" && key.epochIndex === 6 && sameIdTest(key.funderId, FA)
        ? { status: "served", doc: zeroAccrual, height: "918" }
        : w.deps.provedByKey(type, key) };
    const led = await runLedger({ ...w, deps });
    ok("a receipt under a KNOWN-KEY zero-entitlement accrual is a fetched extra",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(6).diagnostics.some((d) => /zero-entitlement accrual/.test(d)));
  }
  {
    // the SINGLE pinned reservation read is the evaluated one: an
    // enumeration omission with a mismatching pinned answer refuses the
    // reservation aspect (no second read exists to launder it)
    const w = mkWorld({ mutateDocs: (docs) => { docs.reservation.splice(0, 1); },
      provedByKey: (base) => async (type, key) => {
        if (type === "reservationByAccrual") {
          const ans = await base(type, key);
          return ans.status === "served"
            ? { ...ans, doc: { ...ans.doc, transitionHash: h32("99") } }
            : { status: "served", doc: { poolId: POOL_HEX, accrualId: key.accrualId,
              transitionHash: h32("99"), id: h32("f9") }, height: "915" };
        }
        return base(type, key);
      } });
    const led = await runLedger(w);
    ok("the one pinned reservation answer is evaluated (a mismatch refuses the aspect AND the record set)",
      led.aggregates.reservationPresence === "REFUSED"
      && led.recordSet.label === "REFUSED");
  }
  {
    // a RESERVATION whose proved absence the pinned query establishes
    // refuses the record set, not only the reservation aspect
    const w = mkWorld({ mutateDocs: (docs) => { docs.reservation.splice(0, 1); } });
    const led = await runLedger(w);
    ok("a proved-absent expected reservation refuses the record set",
      led.recordSet.label === "REFUSED"
      && led.perEpoch.get(5).diagnostics.some((d) => /reservation: proved absent/.test(d))
      && led.aggregates.reservationPresence === "REFUSED");
  }
  {
    // THE MISSING-RECEIPT PATH'S OWN FOUR RESERVATION BRANCHES. Until a
    // mutation pass during the one-record change, NOTHING asserted any of
    // them: the fixtures that reach this path assert the record set and the
    // verdict, which the missing receipt already refuses, so each of the four
    // labels could be replaced with PROVED and all four suites stayed green.
    // An affirmative label on a row whose receipt does not exist is exactly
    // what must not pass, so each case here fails under that substitution.
    // The override is scoped to the ONE accrual whose receipt is gone,
    // because a reservation answer changed for EVERY accrual would move the
    // other rows' labels too and the aggregate would stop discriminating.
    //
    // THE INTERVAL IS NARROWED TO THE ONE EPOCH THAT HOLDS RECORDS, and that
    // is not incidental. Over the default interval the aggregate loops every
    // epoch, and an epoch with no expected receipts inherits the RECORD-SET
    // label, which the missing receipt has already refused. The aggregate is
    // then REFUSED whatever this row's label says, which is precisely why
    // these branches went unasserted for so long: over the ordinary fixture
    // the label is not observable through the returned value at all.
    let goneAccrual = null;
    const missingReceipt = (opts = {}) => mkWorld({
      mutateDocs: (docs) => { goneAccrual = docs.receipt[0].accrualId; docs.receipt.splice(0, 1); },
      ...opts });
    const forGone = (key) => goneAccrual !== null && sameIdTest(key.accrualId, goneAccrual);
    const oneEpoch = async (w) => ({ resolution: await resolveInterval({ requestedStart: 5,
      requestedEnd: 5, configuredStart: 5, fetchRange: w.deps.fetchRange }) });
    {
      const w = missingReceipt({ provedByKey: (base) => async (type, key) =>
        type === "reservationByAccrual" && forGone(key) ? { status: "unserved" } : base(type, key) });
      const led = await runLedger(w, await oneEpoch(w));
      ok("a missing receipt whose reservation read cannot be SERVED leaves the aspect UNPROVED and withholds the proved-records claim",
        led.aggregates.reservationPresence === "UNPROVED" && led.recordsProved === false);
    }
    {
      const w = missingReceipt({ provedByKey: (base) => async (type, key) =>
        type === "reservationByAccrual" && forGone(key) ? { status: "unverified" } : base(type, key) });
      const led = await runLedger(w, await oneEpoch(w));
      ok("a missing receipt whose reservation read cannot be VERIFIED leaves the aspect UNPROVED and withholds the proved-records claim",
        led.aggregates.reservationPresence === "UNPROVED" && led.recordsProved === false);
    }
    {
      // the enumerated reservation goes too, so the pinned read proves its
      // ABSENCE: an expected record missing at a known unique key
      const w = mkWorld({ mutateDocs: (docs) => {
        docs.receipt.splice(0, 1); docs.reservation.splice(0, 1); } });
      const led = await runLedger(w, await oneEpoch(w));
      ok("a missing receipt beside a PROVED-ABSENT reservation refuses the aspect, not only the record set",
        led.aggregates.reservationPresence === "REFUSED" && led.recordSet.label === "REFUSED");
    }
    {
      // a served answer for a DIFFERENT pool is nonconforming, never a quiet
      // UNPROVED, and its height never enters the range
      const w = missingReceipt({ provedByKey: (base) => async (type, key) => {
        if (type !== "reservationByAccrual" || !forGone(key)) return base(type, key);
        return { status: "served", height: "961",
          doc: { id: h32("f7"), poolId: h32("99"), accrualId: key.accrualId } };
      } });
      const led = await runLedger(w, await oneEpoch(w));
      ok("a missing receipt whose reservation answer names a FOREIGN pool refuses the aspect and withholds that height",
        led.aggregates.reservationPresence === "REFUSED"
        && !led.heightCandidates.includes("961"));
    }
    {
      // a CONFORMING served reservation with no receipt to chain against
      // cannot earn PROVED: the aspect stays UNPROVED
      const w = missingReceipt({ provedByKey: (base) => async (type, key) => {
        if (type !== "reservationByAccrual" || !forGone(key)) return base(type, key);
        return { status: "served", height: "962",
          doc: { id: h32("f8"), poolId: POOL_HEX, accrualId: key.accrualId } };
      } });
      const led = await runLedger(w, await oneEpoch(w));
      ok("a CONFORMING reservation with no receipt to bind to stays UNPROVED (it cannot chain to a receipt that does not exist)",
        led.aggregates.reservationPresence === "UNPROVED");
    }
  }
  {
    // equivalent identifier SPELLINGS on the ADAPTER side: a reservation
    // document naming its accrual in base58 still resolves (the receipt's
    // OWN fields stay 64-hex, the verifier's schema grammar). The
    // reservation index and the presence comparison both normalize.
    const w = mkWorld({ mutateDocs: (docs) => {
      docs.reservation[0] = { ...docs.reservation[0],
        accrualId: toBase58(docs.reservation[0].accrualId),
        poolId: GP };
    } });
    const led = await runLedger(w);
    ok("a base58-spelled reservation reference resolves to the same accrual (no orphan, no absence)",
      led.recordSet.label === "READ-CHECKED" && led.diagnostics.orphans.length === 0
      && led.aggregates.reservationPresence === "READ-CHECKED");
  }
  {
    // an identity answer may spell the identity in base58
    const w = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "identity"
        ? { status: "served", doc: { id: toBase58(key.identityId) }, height: "892" }
        : base(type, key) });
    const f = await evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: w.deps });
    ok("a base58-spelled identity answer binds as the SAME identity", f.label === "PROVED");
  }
  {
    // the known-key binds NORMALIZE: a base58 spelling of the same pool
    // is the SAME key, never a different-key refusal. The recovery still
    // degrades completeness to UNPROVED (round-54, F5); the point here is
    // that it is UNPROVED (recovered), not REFUSED (a mis-normalized key).
    const w = mkWorld({ mutateDocs: (docs) => {
      const h = docs.header[0];
      docs.header.splice(0, 1);
      docs._stolenHeader = h;
    } });
    const deps = { ...w.deps, provedByKey: async (type, key) =>
      type === "headerByEpoch" && key.epochIndex === 5
        ? { status: "served", doc: { ...w.docs._stolenHeader, poolId: GP }, height: "900" }
        : w.deps.provedByKey(type, key) };
    const led = await runLedger({ ...w, deps });
    ok("a base58 spelling of the audited pool binds as the SAME key (normalized, UNPROVED recovery, not a different-key REFUSED)",
      led.recordSet.label === "UNPROVED"
      && led.perEpoch.get(5).diagnostics.some((d) => /INCOMPLETE/.test(d)));
  }
  {
    // a header capture bound to the WRONG contract: the capture is
    // invalid, so ordering degrades while nothing refuses
    const w = mkWorld({ headerCaptureContract: h32("77") });
    const led = await runLedger(w);
    ok("a header capture naming a foreign contract degrades ordering to OPERATOR-PROVIDED",
      led.aggregates.ordering === "OPERATOR-PROVIDED"
      && led.aggregates.transferExecution === "READ-CHECKED");
  }

  // ---- runAudit end to end, over a REAL journal built by the append path ----
  {
    const w = mkWorld();
    const JDIR = path.join(TMP, "jr-happy");
    fs.mkdirSync(JDIR, { recursive: true });
    const jAppend = (rec) => {
      const { committedOffset } = openJournal(POOL_HEX, JDIR);
      appendRecord(POOL_HEX, committedOffset, rec, JDIR);
    };
    const rBytesOf = (i) => "0c0d0005" + String(i).padStart(4, "0");
    jAppend({ v: 1, kind: K.DECLARATION, object: "pool", gen: 1, poolId: POOL_HEX,
      condition: "lag-measurement", reasoning: "run start", lagCount: 0,
      undistributedCredits: "0", configuredStartEpoch: 5 });
    jAppend({ v: 1, kind: K.WRITE_AHEAD, object: "header", gen: 1, poolId: POOL_HEX,
      epochIndex: 5, transitionBytes: w.hBytes(5), transitionHash: sha(w.hBytes(5)),
      expectedDocumentId: w.docs.header[0].id, expectedContents: w.ecOf(5),
      configuredStartEpoch: 5 });
    jAppend({ v: 1, kind: K.SENT_MARKER, object: "header", gen: 1, poolId: POOL_HEX,
      epochIndex: 5, transitionHash: sha(w.hBytes(5)) });
    jAppend(w.headerCaps[0]);
    w.captures.forEach((cap, i) => {
      const acc = cap.accrualId;
      jAppend({ v: 1, kind: K.WRITE_AHEAD, object: "transfer", gen: 1, poolId: POOL_HEX,
        epochIndex: 5, accrualId: acc, transitionBytes: cap.transitionBytes,
        transitionHash: cap.transitionHash });
      jAppend({ v: 1, kind: K.WRITE_AHEAD, object: "reservation", gen: 1, poolId: POOL_HEX,
        epochIndex: 5, accrualId: acc, transitionBytes: rBytesOf(i),
        transitionHash: sha(rBytesOf(i)), boundTransferHash: cap.transitionHash });
      jAppend({ v: 1, kind: K.SENT_MARKER, object: "reservation", gen: 1, poolId: POOL_HEX,
        epochIndex: 5, accrualId: acc, transitionHash: sha(rBytesOf(i)) });
      jAppend({ v: 1, kind: K.RESERVATION_SUCCESS, object: "reservation", gen: 1, poolId: POOL_HEX,
        epochIndex: 5, accrualId: acc, transitionHash: sha(rBytesOf(i)),
        boundTransferHash: cap.transitionHash, reservationDocumentId: w.reservations[i].id });
      jAppend({ v: 1, kind: K.SENT_MARKER, object: "transfer", gen: 1, poolId: POOL_HEX,
        epochIndex: 5, accrualId: acc, transitionHash: cap.transitionHash });
      jAppend(cap);
    });
    jAppend({ v: 1, kind: K.WRITE_AHEAD, object: "header", gen: 1, poolId: POOL_HEX,
      epochIndex: 6, transitionBytes: w.hBytes(6), transitionHash: sha(w.hBytes(6)),
      expectedDocumentId: w.docs.header[1].id, expectedContents: w.ecOf(6) });
    jAppend({ v: 1, kind: K.SENT_MARKER, object: "header", gen: 1, poolId: POOL_HEX,
      epochIndex: 6, transitionHash: sha(w.hBytes(6)) });
    jAppend(w.headerCaps[1]);

    const rep = await runAudit({ poolId: POOL_HEX, dir: JDIR, deps: w.deps });
    if (rep.verdict === "REFUSED-INPUT") console.error("E2E refusal:", rep.reason);
    ok("the end-to-end report is a graded report, not a refusal",
      rep.kind === REPORT_KIND && rep.verdict === "PARTIAL BY EVIDENCE");
    ok("the entry binds the owned pins into the report",
      rep.contractId === GC && rep.expectedChainId === CHAIN);
    ok("the start source is the journal's binding, agreeing with the local key",
      rep.startSource === "journal" && rep.configuredStart === 5
      && rep.aspects.activationBoundary.source === "journal");
    ok("the interval is the open-ended default over the discovered universe",
      rep.branch === "open-ended" && rep.interval.startEpoch === 5 && rep.interval.endEpoch === 6);
    ok("the evaluator-backed aspect labels are the evidence's (the four structurally-unverifiable aspects are pinned constants in every report the entry assembles, not every buildReport-constructible one)",
      rep.aspects.universe.label === "UNPROVED"
      && rep.aspects.transferExecution.label === "READ-CHECKED"
      && rep.aspects.reservationPresence.label === "READ-CHECKED"
      && rep.aspects.ordering.label === "ATTESTED"
      && rep.aspects.formationInputs.label === "PROVED"
      && rep.aspects.recordSet.label === "READ-CHECKED"
      && rep.aspects.contractIntegrity.label === "PROVED"
      && rep.aspects.balance.label === "UNVERIFIABLE"
      && rep.aspects.binding.label === "UNVERIFIABLE"
      && rep.aspects.temporalOrder.label === "UNVERIFIABLE"
      && rep.aspects.shareConformance.label === "UNVERIFIABLE");
    ok("the lag and the per-epoch rows are the evaluation's",
      rep.lag.lagCount === 0 && rep.lag.undistributedCredits === "0"
      && rep.epochs.length === 2 && rep.epochs[0].r === "0"
      && rep.epochs[1].condition === "zero-earning-epoch");
    ok("the records height range reduces over every DOCUMENT query, each bound owned by a NON-enumeration read",
      rep.heightRanges.records.min === "889" && rep.heightRanges.records.max === "915"
      && rep.openEnded.recordsHeightMax === "915");
    const walkFrozen = (o, seen = new Set()) => {
      if (!o || typeof o !== "object" || seen.has(o)) return true;
      seen.add(o);
      return Object.isFrozen(o) && Reflect.ownKeys(o).every((k) =>
        (Array.isArray(o) && k === "length") || walkFrozen(o[k], seen));
    };
    ok("the report is deep-frozen through the entry path too (every reachable object)",
      walkFrozen(rep));
  }
  {
    // A THROWN VALUE RESISTANT TO INSPECTION IS OUT OF SCOPE (round-65). The
    // round-59 test that lived here asserted that a revoked Proxy thrown by a
    // verifier stage leaves runAudit with its identity preserved, and it is
    // deleted with the machinery that made that true.
    //
    // The reason is the recorded trust decision, not convenience: adapters are
    // local reviewed code inside the trusted computing base, so a revoked Proxy
    // arriving from one is not a case to model. What remains true, and is
    // what actually matters, is gated in the boundary block above: a thrown
    // value NEVER becomes evidence, because the audit reads a status off a
    // RETURNED verdict and never inspects a throw to decide a label.
    //
    // The residual, stated so it is not discovered as a surprise: if a trusted
    // adapter does throw an uninspectable value, the verifier's own `instanceof`
    // check raises a secondary TypeError and the original value is lost from the
    // message. That degrades FAULT REPORTING. It cannot manufacture evidence,
    // and the audit still aborts. Recorded in docs/E2_VERIFICATION_BOUNDARY.md.
    const w = mkWorld();
    const boom = new Error("the proof helper is offline");
    let thrown = null; let resolved = null;
    try {
      resolved = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-happy"),
        deps: { ...w.deps, verifierDeps: { ...w.deps.verifierDeps,
          verifyStageOne: async () => { throw boom; } } } });
    } catch (e) { thrown = e; }
    ok("an ordinary verifier-stage fault aborts the entry with its identity, and yields no report",
      thrown === boom && resolved === null);
  }
  {
    // DEPENDENCIES ARE NORMALIZED ONCE (round-65). Every member is read exactly
    // once at the entry into a frozen capability record and nothing downstream
    // consults the caller's object again, so an accessor cannot serve one value
    // to a validation and a different one to a use. Earlier rounds enforced this
    // member by member as reviewers found each one; the record makes it
    // structural.
    //
    // The gate counts READS. A member whose accessor is read more than once is
    // a member some later site is still reaching for.
    const w = mkWorld();
    const reads = {};
    const counting = {};
    for (const k of ["fetchRange", "fetchVerifiedPage", "provedByKey", "verifyCaptureBasis",
      "verifierDeps", "expectedContractPayload", "incomeIdentity",
      "provedActivation", "provedDeactivation", "discoveryOpts"]) {
      reads[k] = 0;
      const v = w.deps[k];
      Object.defineProperty(counting, k, {
        enumerable: true, configurable: true,
        get() { reads[k] += 1; return v; },
      });
    }
    const rep = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-happy"), deps: counting });
    ok("the entry still produces its report from the normalized record",
      rep.kind === REPORT_KIND && rep.verdict === "PARTIAL BY EVIDENCE");
    const overRead = Object.entries(reads).filter(([, n]) => n > 1);
    ok("every dependency member is read EXACTLY ONCE from the caller's object",
      overRead.length === 0 && Object.values(reads).every((n) => n <= 1));
    if (overRead.length) console.error("   read more than once:", JSON.stringify(overRead));
  }
  {
    // THE PUBLIC SURFACE IS PINNED (round-65). An evaluator that drifts back
    // onto the public surface silently turns an entry-level invariant into a
    // contract for callers nobody has written, which is what several rounds of
    // claim-width findings were actually about. This states the intended
    // surface literally, so widening it is a decision somebody makes here
    // rather than a side effect of adding an export.
    const PUBLIC = ["runAudit", "LABELS", "GRADES", "BRANCHES", "REPORT_KIND",
      "ASPECT_KEYS", "ASPECT_TERMINALS", "ASPECT_CEILINGS", "__testing"].sort();
    const actual = Object.keys(auditModule).sort();
    ok("the module exports exactly the entry, the report vocabulary, and the test-only surface",
      JSON.stringify(actual) === JSON.stringify(PUBLIC));
    if (JSON.stringify(actual) !== JSON.stringify(PUBLIC)) {
      console.error("   surface drift:", JSON.stringify(actual));
    }
    ok("no evaluator and no report constructor sits on the public surface",
      !Object.keys(auditModule).some((k) => k.startsWith("evaluate")
        || k === "buildReport" || k === "gradeVerdict"));
    ok("the test-only surface still carries the internals this suite drives",
      typeof auditModule.__testing.gradeVerdict === "function"
      && typeof auditModule.__testing.buildReport === "function"
      && typeof auditModule.__testing.evaluateLedgerRecords === "function");
  }
  {
    // the exported class makes instanceof reproducible from outside: a
    // deliberate adapter can throw an object INHERITING the exported
    // prototype, carrying a reason of its own choosing. Classification is
    // by membership in the module-private refusal set (round-60), so the
    // imitation is NOT converted into a structured REFUSED-INPUT and leaves
    // runAudit as the adapter fault it is, identity preserved.
    const w = mkWorld();
    const imitator = Object.assign(Object.create(AuditInputRefusal.prototype),
      { grade: "REFUSED-INPUT", reason: "a reason of the adapter's choosing", message: "an imitation" });
    let stageReached = false;
    const deps = { ...w.deps, verifierDeps: { ...w.deps.verifierDeps,
      verifyStageOne: async () => { stageReached = true; throw imitator; } } };
    let thrown = null; let rejected = false;
    try { await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-happy"), deps }); }
    catch (e) { rejected = true; thrown = e; }
    ok("an adapter fault inheriting the exported refusal prototype is not converted into a refusal verdict",
      stageReached && rejected && thrown === imitator);
  }
  {
    // the second imitation shape: a Proxy whose getPrototypeOf trap NAMES the
    // exported prototype and whose reason getter throws. An instanceof
    // classifier would accept it and then throw a secondary fault on the
    // reason read; the membership classifier reads nothing of it, so the
    // proxy leaves runAudit unchanged.
    const w = mkWorld();
    const lying = new Proxy({}, {
      getPrototypeOf: () => AuditInputRefusal.prototype,
      get: (t, k) => { if (k === "reason") throw new Error("the reason read must never run"); return undefined; } });
    let stageReached = false;
    const deps = { ...w.deps, verifierDeps: { ...w.deps.verifierDeps,
      verifyStageOne: async () => { stageReached = true; throw lying; } } };
    let thrown = null; let rejected = false;
    try { await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-happy"), deps }); }
    catch (e) { rejected = true; thrown = e; }
    ok("an adapter fault whose prototype trap names the exported refusal class leaves runAudit unchanged",
      stageReached && rejected && thrown === lying);
  }
  {
    // a corrupt journal is REFUSED-INPUT (header decision 7): no report
    const w = mkWorld();
    const JDIR = path.join(TMP, "jr-corrupt");
    fs.mkdirSync(JDIR, { recursive: true });
    const jAppend = (rec) => {
      const { committedOffset } = openJournal(POOL_HEX, JDIR);
      appendRecord(POOL_HEX, committedOffset, rec, JDIR);
    };
    // a capture with no preceding write-ahead refuses D7 validation
    jAppend({ v: 1, kind: K.SENT_MARKER, object: "header", gen: 1, poolId: POOL_HEX,
      epochIndex: 5, transitionHash: sha("01") });
    const r = await runAudit({ poolId: POOL_HEX, dir: JDIR, deps: w.deps });
    ok("a journal that fails validation is REFUSED-INPUT, never a graded report",
      r.verdict === "REFUSED-INPUT" && /journal refuses validation/.test(r.reason));
  }
  {
    // an EMPTY journal: the local key is the start source; ordering has no
    // capture material and degrades, which the verdict survives as
    // PARTIAL BY EVIDENCE
    const w = mkWorld();
    const JDIR = path.join(TMP, "jr-empty");
    fs.mkdirSync(JDIR, { recursive: true });
    const rep = await runAudit({ poolId: POOL_HEX, dir: JDIR, deps: w.deps });
    ok("an empty journal resolves the start from the local configuration key",
      rep.startSource === "local-configuration" && rep.configuredStart === 5);
    ok("with no journal capture material every receipt's transfer aspect refuses (no served capture)",
      rep.aspects.transferExecution.label === "REFUSED" && rep.verdict === "REFUSED-REPORT");
  }
  {
    // the unserved known-key world through the WHOLE entry: the records
    // range and the annotation member are withheld together
    const w = mkWorld({ mutateDocs: (docs) => { docs.receipt.splice(1, 1); },
      provedByKey: (base) => async (type, key) =>
        type === "receiptByAccrual" ? { status: "unserved" } : base(type, key) });
    const JDIR = path.join(TMP, "jr-unserved");
    fs.mkdirSync(JDIR, { recursive: true });
    const rep = await runAudit({ poolId: POOL_HEX, dir: JDIR, deps: w.deps });
    ok("an unserved required query nulls the records range and the annotation member together",
      rep.heightRanges.records === null && rep.openEnded.recordsHeightMax === null
      && rep.aspects.recordSet.label === "UNPROVED");
  }
  {
    // adverse evidence THROUGH the entry: each evaluator's result is
    // bound into the report, one adverse world per aspect
    const JDIR = path.join(TMP, "jr-adverse");
    fs.mkdirSync(JDIR, { recursive: true });
    const wF = mkWorld({ nodeType: "regular" });
    const repF = await runAudit({ poolId: POOL_HEX, dir: JDIR, deps: wF.deps });
    ok("a non-eligible pool refuses formation THROUGH the entry",
      repF.aspects.formationInputs.label === "REFUSED" && repF.verdict === "REFUSED-REPORT");
    // UNAVAILABLE formation COMBINED WITH a structural record-set refusal
    // grades cleanly, never throwing in the zero-examined rule (round-54,
    // F6): the unavailable path returns UNPROVED per-receipt aggregates and
    // examinedCount 0 beside a REFUSED record set. UNPROVED (rank 2) does not
    // outrank OPERATOR-PROVIDED (rank 3), so the zero-count rule admits it and
    // the structural REFUSED drives the verdict to REFUSED-REPORT.
    const wUS = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "pool" ? { status: "unserved" } : base(type, key),
      mutateDocs: (docs) => { docs.part.push({ id: h32("e7"), poolId: POOL_HEX, accrualId: h32("ee") }); } });
    const repUS = await runAudit({ poolId: POOL_HEX, dir: JDIR, deps: wUS.deps });
    ok("unavailable formation beside a structural record-set refusal grades to REFUSED-REPORT without throwing",
      repUS.kind === REPORT_KIND && repUS.verdict === "REFUSED-REPORT"
      && repUS.aspects.recordSet.label === "REFUSED"
      && repUS.aspects.formationInputs.label === "UNPROVED"
      && repUS.aspects.transferExecution.label === "UNPROVED"
      && repUS.aspects.transferExecution.examinedCount === 0);
    const wC = mkWorld();
    const repC = await runAudit({ poolId: POOL_HEX, dir: JDIR,
      deps: { ...wC.deps,
        expectedContractPayload: { ...wC.deps.expectedContractPayload, version: "v12" } } });
    ok("a divergent expected contract payload refuses contract integrity THROUGH the entry",
      repC.aspects.contractIntegrity.label === "REFUSED" && repC.verdict === "REFUSED-REPORT");
    // the entry CAPTURES the expected payload once (round-54): a deps whose
    // expectedContractPayload accessor serves a divergent v12 on the entry
    // read and then the matching payload afterward is compared under the
    // captured v12, so it refuses. A re-read from mutable deps would have
    // compared the later matching value and passed.
    {
      const wM = mkWorld();
      const matching = wM.deps.expectedContractPayload;
      const divergent = { ...matching, version: "v12" };
      let reads = 0;
      const depsM = Object.create(null);
      Object.assign(depsM, wM.deps);
      Object.defineProperty(depsM, "expectedContractPayload", { enumerable: true, configurable: true,
        get() { reads += 1; return reads === 1 ? divergent : matching; } });
      const repM = await runAudit({ poolId: POOL_HEX, dir: JDIR, deps: depsM });
      ok("the entry compares the CAPTURED expected payload, so a payload that changes after entry validation still refuses",
        repM.aspects.contractIntegrity.label === "REFUSED" && reads === 1);
    }
    {
      // the entry CAPTURES ALL THREE scalar trust inputs once (round-55 F1,
      // strengthened round-56 F3): deps.incomeIdentity, deps.provedActivation
      // AND deps.provedDeactivation are each read exactly once, so an accessor
      // cannot return one value during entry validation and another during
      // evaluation. The path is a DEACTIVATION-BOUNDED report over the real
      // journal (jr-happy) with actual receipt captures, so the deactivation
      // branch and the receipt-transfer path (which consumes incomeIdentity)
      // both run. Non-null activation and deactivation are supplied so a
      // conditional re-read cannot hide in an unexercised branch.
      const wS = mkWorld();
      let idReads = 0, actReads = 0, deactReads = 0;
      const depsS = Object.create(null);
      Object.assign(depsS, wS.deps);
      const identity = wS.deps.incomeIdentity;
      Object.defineProperty(depsS, "incomeIdentity", { enumerable: true, configurable: true,
        get() { idReads += 1; return identity; } });
      Object.defineProperty(depsS, "provedActivation", { enumerable: true, configurable: true,
        get() { actReads += 1; return 5; } });
      Object.defineProperty(depsS, "provedDeactivation", { enumerable: true, configurable: true,
        get() { deactReads += 1; return 6; } });
      const repS = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-happy"), deps: depsS });
      ok("the entry reads each of the three scalar trust inputs exactly once, on a deactivation-bounded report with real captures",
        repS.kind === REPORT_KIND && repS.branch === "deactivation-bounded"
        && repS.aspects.transferExecution.examinedCount >= 1
        && idReads === 1 && actReads === 1 && deactReads === 1);
      // the captured VALUES govern the result, not just the read count: the
      // non-null provedActivation drives the activation-boundary label to
      // PROVED, the non-null provedDeactivation drives the branch to
      // deactivation-bounded, and the captured incomeIdentity governs receipt
      // verification (a wrong identity would refuse every transfer). A
      // hard-coded value for any of the three would change one of these.
      ok("the captured activation, deactivation AND income identity govern the report (activation PROVED, deactivation-bounded branch, transfers not refused)",
        repS.aspects.activationBoundary.label === "PROVED"
        && repS.branch === "deactivation-bounded"
        && repS.aspects.transferExecution.label !== "REFUSED"
        && repS.aspects.transferExecution.examinedCount >= 1);
    }
    {
      // a proved-read answer that RESOLVES a value resistant to inspection (a
      // revoked proxy) is converted to a plain adapter-fault refusal by the
      // total await, never an escaping raw TypeError (round-57, F2).
      const wH = mkWorld();
      const rev = Proxy.revocable({ status: "served", doc: {}, height: "890" }, {}); rev.revoke();
      const depsH = { ...wH.deps, provedByKey: async (type, key) =>
        type === "pool" ? rev.proxy : wH.deps.provedByKey(type, key) };
      await rejects("a revoked-proxy proved answer is a plain adapter-fault refusal, never an escaping raw TypeError",
        evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: depsH }),
        /a proved adapter read failed/);
      // an ORDINARY proved-read rejection keeps its real cause (round-59, F4)
      const depsO = { ...wH.deps, provedByKey: async (type, key) =>
        type === "pool" ? Promise.reject(new Error("DAPI timeout")) : wH.deps.provedByKey(type, key) };
      await rejects("an ordinary proved-read rejection is refused with its REAL cause preserved",
        evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: depsO }),
        /a proved adapter read failed \(DAPI timeout\)/);
      // the getter shape (round-60): a rejection whose `message` getter
      // itself throws must still refuse plainly, never let the getter's
      // throw replace the refusal
      const eGet = {};
      Object.defineProperty(eGet, "message",
        { get() { throw new Error("the message read must not decide this"); } });
      const depsG = { ...wH.deps, provedByKey: async (type, key) =>
        type === "pool" ? Promise.reject(eGet) : wH.deps.provedByKey(type, key) };
      await rejects("a proved-read rejection with a throwing message getter still refuses plainly",
        evaluateFormationInputs({ poolId: POOL_HEX, contractId: GC, deps: depsG }),
        /a proved adapter read failed/);
    }
    const wR = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "reservationByAccrual" ? { status: "proved-absence", height: "2000" } : base(type, key) });
    const repR = await runAudit({ poolId: POOL_HEX, dir: JDIR, deps: wR.deps });
    ok("a proved-absent pinned reservation refuses reservation presence THROUGH the entry",
      repR.aspects.reservationPresence.label === "REFUSED");
    // the basis failure runs over the REAL journal (jr-happy), where
    // ordering otherwise earns ATTESTED, so the degradation is bound to
    // the basis result and nothing else
    const wO = mkWorld();
    const repO = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-happy"),
      deps: { ...wO.deps, verifyCaptureBasis: async () => false } });
    ok("a failed capture basis degrades ordering and refuses transfer THROUGH the entry",
      repO.aspects.ordering.label === "OPERATOR-PROVIDED"
      && repO.aspects.transferExecution.label === "REFUSED");
    // a record-set refusal survives report assembly: an orphan receipt
    // over the whole universe refuses the record set THROUGH the entry
    const wS = mkWorld({ mutateDocs: (docs) => { docs.receipt.push({ ...docs.receipt[0],
      id: h32("f8"), accrualId: h32("f9") }); } });
    const repS = await runAudit({ poolId: POOL_HEX, dir: JDIR, deps: wS.deps });
    ok("a record-set refusal survives report assembly THROUGH the entry",
      repS.aspects.recordSet.label === "REFUSED" && repS.verdict === "REFUSED-REPORT");
    const pinned = (r) => ["binding", "temporalOrder", "shareConformance", "balance"]
      .every((k) => r.aspects[k].label === "UNVERIFIABLE");
    ok("the four pinned constants hold on each constructed adverse report (all five)",
      pinned(repS) && pinned(repF) && pinned(repC) && pinned(repR) && pinned(repO));
    // a conflicting dependency field is IGNORED, never consulted
    const wConf = mkWorld();
    const repConf = await runAudit({ poolId: POOL_HEX, dir: JDIR,
      deps: { ...wConf.deps, balanceLabel: "PROVED", bindingLabel: "PROVED" } });
    ok("conflicting dependency fields cannot repoint the pinned constants",
      pinned(repConf));
    // an unserved FORMATION read nulls the records range too (any
    // required query unserved makes it null, round-28)
    const wPU = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "pool" ? { status: "unserved" } : base(type, key) });
    const repPU = await runAudit({ poolId: POOL_HEX, dir: JDIR, deps: wPU.deps });
    ok("an unserved pool read nulls the records range through the entry",
      repPU.heightRanges.records === null && repPU.aspects.formationInputs.label === "UNPROVED");
    const wCU = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "completionReceipt" ? { status: "unserved" } : base(type, key) });
    const repCU = await runAudit({ poolId: POOL_HEX, dir: JDIR, deps: wCU.deps });
    ok("an unserved completion-receipt read nulls the records range through the entry",
      repCU.heightRanges.records === null && repCU.aspects.formationInputs.label === "UNPROVED");
    // the empty-set identity is OBSERVABLE: labels earned over an empty
    // receipt set carry the vacuous note, labels earned from real
    // receipt evaluations do not
    const wV = mkWorld();
    const repV = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-happy"),
      startEpoch: 6, endEpoch: 6, deps: wV.deps });
    ok("per-receipt aspect labels earned over an empty receipt set carry the vacuous note",
      /no receipt received the per-receipt evidence evaluations/.test(repV.aspects.transferExecution.note || "")
      && /no receipt received the per-receipt evidence evaluations/.test(repV.aspects.reservationPresence.note || "")
      && /no receipt received the per-receipt evidence evaluations/.test(repV.aspects.ordering.note || ""));
    const repE = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-happy"), deps: wV.deps });
    ok("per-receipt aspect labels earned from real receipt evaluations carry NO vacuous note",
      repE.aspects.transferExecution.note === undefined
      && repE.aspects.reservationPresence.note === undefined
      && repE.aspects.ordering.note === undefined);
    // the pinned constants are pinned across the RESOLVED START too
    // (round-53): repV is a graded report the entry assembled at start 6,
    // so a pinned aspect made conditional on the start or interval (for
    // example balance PROVED only when startEpoch is 6) is caught here,
    // not just on the start-5 reports above. This is the universal the
    // "every report the entry assembles" claim rests on.
    ok("the four pinned constants hold on the entry's start-6 report too, so no pinned aspect is conditional on the resolved start or interval",
      repV.interval.startEpoch === 6 && pinned(repV));
    // an unserved IDENTITY read is a NON-document formation read: its
    // height never enters the records range, and its unavailability makes
    // formation UNPROVED, routing to the unavailable path (recordsProved
    // false) so the whole range is withheld fail-closed, though every
    // DOCUMENT read was served (round-53, finding 3's gate)
    const wIU = mkWorld({ provedByKey: (base) => async (type, key) =>
      type === "identity" ? { status: "unserved" } : base(type, key) });
    const repIU = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-happy"), deps: wIU.deps });
    ok("an unserved non-document identity read nulls the records range through the entry, with every document read served",
      repIU.heightRanges.records === null
      && repIU.aspects.formationInputs.label === "UNPROVED"
      && repIU.aspects.recordSet.label === "UNPROVED");
    // the range rule is a RULE, not a list of the four values tested
    // below (round-60): other negatives, other non-integers, NaN, the
    // infinities and other non-number types are refused the same way
    for (const bad of [-2, -1000000, 1e-3, NaN, Infinity, -Infinity,
      Number.MAX_SAFE_INTEGER + 4, null, true, [], {}, 3n]) {
      const repBad = JSON.parse(JSON.stringify(repE));
      const aspBad = { ...repBad.aspects, transferExecution: { ...repBad.aspects.transferExecution, examinedCount: bad } };
      throwsSync(`examinedCount ${String(bad)} is refused by the range RULE, not a value list`,
        () => gradeVerdict({ branch: repBad.branch, aspects: aspBad,
          inReportRefusal: false, coverage: cleanCoverage(), annotation: repBad.openEnded ?? null }),
        /must be a nonnegative safe integer/);
    }
    for (const bad of [-1, 0.5, Number.MAX_SAFE_INTEGER + 2, "3"]) {
      const repBad = JSON.parse(JSON.stringify(repE));
      const aspBad = { ...repBad.aspects, transferExecution: { ...repBad.aspects.transferExecution, examinedCount: bad } };
      throwsSync(`examinedCount ${String(bad)} is refused by the grade calculator`,
        () => gradeVerdict({ branch: repBad.branch, aspects: aspBad,
          inReportRefusal: false, coverage: cleanCoverage(), annotation: repBad.openEnded ?? null }),
        /must be a nonnegative safe integer/);
    }
    {
      const repBad = JSON.parse(JSON.stringify(repE));
      const aspBad = { ...repBad.aspects, binding: { ...repBad.aspects.binding, examinedCount: 0 } };
      throwsSync("examinedCount on a NON-receipt aspect is refused (its shape stays closed)",
        () => gradeVerdict({ branch: repBad.branch, aspects: aspBad,
          inReportRefusal: false, coverage: cleanCoverage(), annotation: repBad.openEnded ?? null }),
        /carries unknown members/);
      const repMissing = JSON.parse(JSON.stringify(repE));
      const { examinedCount, ...noCount } = repMissing.aspects.transferExecution;
      const aspMissing = { ...repMissing.aspects, transferExecution: noCount };
      throwsSync("a per-receipt aspect WITHOUT its examinedCount is refused (presence is required)",
        () => gradeVerdict({ branch: repMissing.branch, aspects: aspMissing,
          inReportRefusal: false, coverage: cleanCoverage(), annotation: repMissing.openEnded ?? null }),
        /must carry its examinedCount/);
      // one shared examined set, one count (round-42)
      const repUneq = JSON.parse(JSON.stringify(repE));
      const aspUneq = { ...repUneq.aspects,
        reservationPresence: { ...repUneq.aspects.reservationPresence, examinedCount: 7 } };
      throwsSync("unequal per-receipt examinedCounts are refused (equality is the rule; set identity is the entry's control flow, not this check)",
        () => gradeVerdict({ branch: repUneq.branch, aspects: aspUneq,
          inReportRefusal: false, coverage: cleanCoverage(), annotation: repUneq.openEnded ?? null }),
        /carry equal examinedCounts/);
      // TRANSFER alone diverging is refused (round-48)
      const repTr = JSON.parse(JSON.stringify(repE));
      const aspTr = { ...repTr.aspects,
        transferExecution: { ...repTr.aspects.transferExecution, examinedCount: 9 } };
      throwsSync("a transfer count diverging alone is refused (no aspect leaves the shared set)",
        () => gradeVerdict({ branch: repTr.branch, aspects: aspTr,
          inReportRefusal: false, coverage: cleanCoverage(), annotation: repTr.openEnded ?? null }),
        /carry equal examinedCounts/);
      // and ORDERING alone diverging is refused too (round-47)
      const repOrd = JSON.parse(JSON.stringify(repE));
      const aspOrd = { ...repOrd.aspects,
        ordering: { ...repOrd.aspects.ordering, examinedCount: 9 } };
      throwsSync("an ordering count diverging alone is refused (no aspect leaves the shared set)",
        () => gradeVerdict({ branch: repOrd.branch, aspects: aspOrd,
          inReportRefusal: false, coverage: cleanCoverage(), annotation: repOrd.openEnded ?? null }),
        /carry equal examinedCounts/);
      // equality is over the WHOLE counts (round-60): counts sharing a
      // textual prefix and differing in magnitude are still unequal
      for (const [a, b] of [[12, 120], [1, 10], [123, 1234]]) {
        const repPfx = JSON.parse(JSON.stringify(repE));
        const aspPfx = { ...repPfx.aspects };
        for (const k of ["transferExecution", "reservationPresence", "ordering"]) {
          aspPfx[k] = { ...aspPfx[k], examinedCount: a };
        }
        aspPfx.reservationPresence = { ...aspPfx.reservationPresence, examinedCount: b };
        throwsSync(`examinedCounts ${a} and ${b} share a prefix but are unequal, and are refused`,
          () => gradeVerdict({ branch: repPfx.branch, aspects: aspPfx,
            inReportRefusal: false, coverage: cleanCoverage(), annotation: repPfx.openEnded ?? null }),
          /carry equal examinedCounts/);
      }
      // the count is CONSUMED (round-43): zero examined receipts cannot
      // carry labels above inheritance or degradation
      const repZero = JSON.parse(JSON.stringify(repE));
      const aspZero = { ...repZero.aspects };
      for (const k of ["transferExecution", "reservationPresence", "ordering"]) {
        aspZero[k] = { ...aspZero[k], examinedCount: 0 };
      }
      // the cap is a RULE over the label ORDER (round-60): EVERY label
      // above the applicable bound is refused on every per-receipt
      // aspect, not only the three combinations spelled out below. The
      // aspect's own ceiling is respected, so a label the aspect can
      // never carry is skipped rather than expected to refuse here.
      for (const rsLabel of ["READ-CHECKED", "UNPROVED", "REFUSED", "OPERATOR-PROVIDED"]) {
        aspZero.recordSet = { ...aspZero.recordSet, label: rsLabel };
        const bound = Math.max(SPEC_ORDER.indexOf("OPERATOR-PROVIDED"), SPEC_ORDER.indexOf(rsLabel));
        for (const k of ["transferExecution", "reservationPresence", "ordering"]) {
          for (const excessive of SPEC_ORDER.slice(bound + 1)) {
            if (SPEC_ORDER.indexOf(excessive) > SPEC_ORDER.indexOf(SPEC_CEILINGS[k])) continue;
            const aspOne = JSON.parse(JSON.stringify(aspZero));
            aspOne[k].label = excessive;
            throwsSync(`zero examined receipts cannot earn ${excessive} on ${k} past a ${rsLabel} record set (the rule, over the whole order)`,
              () => gradeVerdict({ branch: repZero.branch, aspects: aspOne,
                inReportRefusal: false, coverage: cleanCoverage(), annotation: repZero.openEnded ?? null }),
              /zero examined-receipt count cannot earn/);
          }
        }
      }
      aspZero.recordSet = { ...aspZero.recordSet, label: "READ-CHECKED" };
      for (const rsLabel of ["READ-CHECKED", "UNPROVED", "REFUSED"]) {
        aspZero.recordSet = { ...aspZero.recordSet, label: rsLabel };
        for (const [k, excessive] of [["transferExecution", "CAPTURE-VERIFIED"],
          ["reservationPresence", "PROVED"], ["ordering", "PROVED"]]) {
          const aspOne = JSON.parse(JSON.stringify(aspZero));
          aspOne[k].label = excessive;
          throwsSync(`zero examined receipts cannot earn ${excessive} on ${k} past a ${rsLabel} record set`,
            () => gradeVerdict({ branch: repZero.branch, aspects: aspOne,
              inReportRefusal: false, coverage: cleanCoverage(), annotation: repZero.openEnded ?? null }),
            /zero examined-receipt count cannot earn/);
        }
      }
    }
    // a FOUR-receipt world proves the count is the true length, not a
    // constant that happens to match the golden three (round-49)
    const OD49 = toBase58(h32("ff"));
    const w49 = mkWorld({ manifest: {
      v: 1, poolId: GP, realHash: "aa".repeat(32), target: EVO,
      owners: [
        { owner: OA, amountDuffs: String(BigInt(EVO) * 4n / 10n), bps: 4000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
        { owner: OB, amountDuffs: String(BigInt(EVO) * 3n / 10n), bps: 3000, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
        { owner: OC, amountDuffs: String(BigInt(EVO) / 5n), bps: 2000, rewardScriptHex: "76a914" + "33".repeat(20) + "88ac" },
        { owner: OD49, amountDuffs: String(BigInt(EVO) / 10n), bps: 1000, rewardScriptHex: "76a914" + "44".repeat(20) + "88ac" },
      ] },
      mutateFr: (fr) => { fr.participantCount = 4; },
      provedByKey: (base) => async (type, key) =>
        type === "identity" ? { status: "served", doc: { id: key.identityId }, height: "892" } : base(type, key) });
    const JDIR49 = path.join(TMP, "jr-four");
    fs.mkdirSync(JDIR49, { recursive: true });
    const rep49 = await runAudit({ poolId: POOL_HEX, dir: JDIR49, deps: w49.deps });
    ok("a four-recipient world reports examinedCount 4 through the entry",
      rep49.aspects.transferExecution.examinedCount === 4
      && rep49.aspects.reservationPresence.examinedCount === 4
      && rep49.aspects.ordering.examinedCount === 4);
    // a FIVE-receipt world (round-60): a count clamped anywhere at or
    // below four would pass every smaller world, so the entry count is
    // proved against a set larger than any earlier fixture
    const OE60 = toBase58(h32("fe"));
    const w60 = mkWorld({ manifest: {
      v: 1, poolId: GP, realHash: "aa".repeat(32), target: EVO,
      owners: [
        { owner: OA, amountDuffs: String(BigInt(EVO) * 3n / 10n), bps: 3000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
        { owner: OB, amountDuffs: String(BigInt(EVO) / 4n), bps: 2500, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
        { owner: OC, amountDuffs: String(BigInt(EVO) / 5n), bps: 2000, rewardScriptHex: "76a914" + "33".repeat(20) + "88ac" },
        { owner: OD49, amountDuffs: String(BigInt(EVO) * 3n / 20n), bps: 1500, rewardScriptHex: "76a914" + "44".repeat(20) + "88ac" },
        { owner: OE60, amountDuffs: String(BigInt(EVO) / 10n), bps: 1000, rewardScriptHex: "76a914" + "55".repeat(20) + "88ac" },
      ] },
      mutateFr: (fr) => { fr.participantCount = 5; },
      provedByKey: (base) => async (type, key) =>
        type === "identity" ? { status: "served", doc: { id: key.identityId }, height: "892" } : base(type, key) });
    const JDIR60 = path.join(TMP, "jr-five");
    fs.mkdirSync(JDIR60, { recursive: true });
    const rep60 = await runAudit({ poolId: POOL_HEX, dir: JDIR60, deps: w60.deps });
    ok("a five-recipient world reports examinedCount 5 through the entry",
      rep60.aspects.transferExecution.examinedCount === 5
      && rep60.aspects.reservationPresence.examinedCount === 5
      && rep60.aspects.ordering.examinedCount === 5);
    // the count is EXAMINED receipts, never expected rows (round-50):
    // a missing receipt, a missing accrual, and an all-missing world
    // each lower it exactly
    const JDIR50 = path.join(TMP, "jr-counts");
    fs.mkdirSync(JDIR50, { recursive: true });
    const wMR = mkWorld({ mutateDocs: (docs) => { docs.receipt.splice(0, 1); } });
    const repMR = await runAudit({ poolId: POOL_HEX, dir: JDIR50, deps: wMR.deps });
    ok("one missing receipt lowers the examined count to two",
      repMR.aspects.transferExecution.examinedCount === 2);
    const wMA = mkWorld({ mutateDocs: (docs) => {
      const gone50 = docs.accrual.find((a) => a.epochIndex === 5 && a.funderId === FB);
      docs.accrual = docs.accrual.filter((a) => a !== gone50);
      docs.reservation = docs.reservation.filter((r) => r.accrualId !== gone50.id);
      docs.receipt = docs.receipt.filter((r) => r.accrualId !== gone50.id);
    }, provedByKey: (base) => async (type, key) =>
      (type === "accrualByKey" || type === "accrualById") ? { status: "unserved" } : base(type, key) });
    const repMA = await runAudit({ poolId: POOL_HEX, dir: JDIR50, deps: wMA.deps });
    ok("one missing accrual lowers the examined count to two",
      repMA.aspects.transferExecution.examinedCount === 2);
    const wAllM = mkWorld({ mutateDocs: (docs) => { docs.receipt = []; } });
    const repAllM = await runAudit({ poolId: POOL_HEX, dir: JDIR50, deps: wAllM.deps });
    ok("all expected receipts missing lowers the examined count to zero",
      repAllM.aspects.transferExecution.examinedCount === 0);
    ok("examinedCount is the machine-readable examined-receipt count: zero on the unexamined run, three on the earned run",
      repV.aspects.transferExecution.examinedCount === 0
      && repV.aspects.reservationPresence.examinedCount === 0
      && repV.aspects.ordering.examinedCount === 0
      && repE.aspects.transferExecution.examinedCount === 3
      && repE.aspects.reservationPresence.examinedCount === 3
      && repE.aspects.ordering.examinedCount === 3);
  }
  {
    const w = mkWorld();
    const r = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-nodep"),
      deps: { ...w.deps, incomeIdentity: undefined } });
    ok("a missing income identity is a structured REFUSED-INPUT",
      r.verdict === "REFUSED-INPUT" && /incomeIdentity/.test(r.reason));
  }
  {
    const w = mkWorld();
    const r = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-nodep"),
      deps: { ...w.deps, expectedContractPayload: [] } });
    ok("an ARRAY expected payload is REFUSED-INPUT at the entry (the same predicate as the evaluator)",
      r.verdict === "REFUSED-INPUT" && /plain data/.test(r.reason));
  }
  {
    // a MULTIPART receipt: the enumerated part document is reassembled
    // into the complete proof carrier and the receipt capture-verifies
    const w = mkWorld({ multipartReceipt: true });
    const narrow = await resolveInterval({ requestedStart: 5, requestedEnd: 5,
      configuredStart: 5, fetchRange: w.deps.fetchRange });
    const led = await runLedger(w, { resolution: narrow });
    const fcEval = led.receiptEvaluations.find((r) => sameIdTest(r.accrualId, w.accruals[2].id));
    ok("a multipart receipt reassembles its enumerated part and capture-verifies",
      led.aggregates.transferExecution === "CAPTURE-VERIFIED"
      && fcEval && fcEval.transfer === "CAPTURE-VERIFIED"
      && led.lag.undistributedCredits === "0");
    // the enumerated part CONTROLS verification: change bytes INSIDE the
    // signature value (the reassembled carrier stays valid canonical
    // JSON, so only content comparison can catch it) while the capture
    // still holds the original complete carrier; the receipt must refuse
    // (no alternate route through the capture)
    const wBad = mkWorld({ multipartReceipt: true, mutateDocs: (docs) => {
      const b = docs.part[0].bytes;
      docs.part[0].bytes = b.slice(0, 10) + (b.slice(10, 12) === "65" ? "66" : "65") + b.slice(12);
    } });
    const narrowBad = await resolveInterval({ requestedStart: 5, requestedEnd: 5,
      configuredStart: 5, fetchRange: wBad.deps.fetchRange });
    const ledBad = await runLedger(wBad, { resolution: narrowBad });
    const fcBad = ledBad.receiptEvaluations.find((r) => sameIdTest(r.accrualId, wBad.accruals[2].id));
    ok("a corrupted enumerated part refuses the receipt even though the capture holds the original carrier",
      fcBad && fcBad.transfer !== "CAPTURE-VERIFIED"
      && ledBad.lag.undistributedCredits === "160000");
  }
  {
    // journal SUPERSESSION records route to the basis check, filtered by
    // the SUPERSEDED KIND, for header and receipt captures alike; the
    // strict basis holds the golden labels only when it receives exactly
    // its own kind's record
    const w0 = mkWorld();
    const supH = { kind: CAP_SUP, supersededKind: CAP_HEADER };
    const supR = { kind: CAP_SUP, supersededKind: CAP_RECEIPT };
    const seen = [];
    const w = mkWorld({ journalRecords: [...w0.headerCaps, ...w0.captures, supH, supR],
      verifyCaptureBasis: async (cap, sups) => {
        seen.push([cap.kind, sups.length]);
        return sups.length === 1 && sups[0].supersededKind === cap.kind;
      } });
    const led = await runLedger(w);
    ok("supersession records reach the basis check filtered by superseded kind, for BOTH capture kinds, holding the golden labels",
      led.aggregates.ordering === "ATTESTED"
      && seen.filter(([k]) => k === CAP_HEADER).length === 2
      && seen.filter(([k]) => k === CAP_RECEIPT).length === 3
      && seen.every(([, n]) => n === 1));
    // the basis RESULT controls the labels: a basis that fails exactly
    // when a supersession is present degrades ordering
    const wF = mkWorld({ journalRecords: [...w0.headerCaps, ...w0.captures, supH, supR],
      verifyCaptureBasis: async (cap, sups) => sups.length === 0 });
    const ledFalse = await runLedger(wF);
    ok("a failing supersession-bearing basis degrades ordering and refuses transfer (the result is consumed, not just the call)",
      ledFalse.aggregates.ordering === "OPERATOR-PROVIDED"
      && ledFalse.aggregates.transferExecution === "REFUSED");
    // and the HEADER side alone: a header basis failing exactly when a
    // supersession is present degrades ordering while transfer verifies
    const wHF = mkWorld({ journalRecords: [...w0.headerCaps, ...w0.captures, supH, supR],
      verifyCaptureBasis: async (cap, sups) =>
        cap.kind === CAP_HEADER ? sups.length === 0 : true });
    const ledHF = await runLedger(wHF);
    ok("a header-side supersession-bearing basis failure degrades ordering on its own",
      ledHF.aggregates.ordering === "OPERATOR-PROVIDED"
      && ledHF.aggregates.transferExecution === "READ-CHECKED");
  }
  {
    // ordering's route equality requires BOTH routes to EXIST as
    // nonempty strings: two absent members compare equal without
    // establishing either record carries a route (round-30)
    const mkOrd = (routes) => evaluateOrdering({
      receipt: { transitionHash: h32("01") }, receiptCaptureValid: true,
      capture: { transitionHash: h32("01"), inclusionHeight: "1001", ...routes.r },
      headerCaptureValid: true,
      headerCapture: { inclusionHeight: "1000", ...routes.h } });
    ok("ordering degrades when both routes are ABSENT (absent equals absent proves nothing)",
      mkOrd({ r: {}, h: {} }).label === "OPERATOR-PROVIDED");
    ok("ordering degrades on equal null routes",
      mkOrd({ r: { heightRoute: null }, h: { heightRoute: null } }).label === "OPERATOR-PROVIDED");
    ok("ordering degrades on equal numeric routes",
      mkOrd({ r: { heightRoute: 7 }, h: { heightRoute: 7 } }).label === "OPERATOR-PROVIDED");
    ok("ordering still attests on a real shared route",
      mkOrd({ r: { heightRoute: "tenderdash-tx" }, h: { heightRoute: "tenderdash-tx" } }).label === "ATTESTED");
  }
  {
    // DISTINCT reservation-read heights all reach the reduction
    // (round-49): three reads at "915", "916" and "3000" contribute
    // each value, so the true maximum survives
    let resSeq = 0;
    const wDH = mkWorld({ provedByKey: (base) => async (type, key) => {
      if (type === "reservationByAccrual") {
        const ans = await base(type, key);
        if (ans.status === "served") { resSeq += 1;
          return { ...ans, height: ["915", "916", "3000"][resSeq - 1] ?? "915" }; }
        return ans;
      }
      return base(type, key);
    } });
    const ledDH = await runLedger(wDH);
    ok("every distinct reservation-read height reaches the reduction (the later reads are not collapsed into the first)",
      ledDH.heightCandidates.includes("915") && ledDH.heightCandidates.includes("916")
      && ledDH.heightCandidates.includes("3000"));
    // and the ENTRY's published range carries the true maximum
    resSeq = 0;
    const JDIRDH = path.join(TMP, "jr-distinct");
    fs.mkdirSync(JDIRDH, { recursive: true });
    const repDH = await runAudit({ poolId: POOL_HEX, dir: JDIRDH, deps: wDH.deps });
    ok("the report's records range reduces over every distinct reservation height (max 3000)",
      repDH.heightRanges.records !== null && repDH.heightRanges.records.max === "3000");
  }
  {
    // the in-flight sweep's POSITIVE case: a reservation whose accrual
    // exists but whose receipt is proved absent is reported
    const w = mkWorld({ mutateDocs: (docs) => { docs.receipt.splice(0, 1); } });
    const led = await runLedger(w);
    ok("a reservation without its receipt is reported in-flight beside the refusal",
      led.recordSet.label === "REFUSED"
      && led.diagnostics.poolGlobal.some((d) => /no receipt/.test(d)));
    // the same state in an IGNORED epoch carries no obligation, the
    // lifecycle diagnostic included (round-26)
    const w2 = mkWorld({ mutateDocs: (docs) => { docs.receipt.splice(0, 1); } });
    const narrowed = await resolveInterval({ requestedStart: 6, requestedEnd: null,
      configuredStart: 5, fetchRange: async (start, end) => ({
        epochs: [{ number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 }]
          .filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const ledIg3 = await runLedger(w2, { resolution: narrowed });
    ok("a reservation without its receipt in an IGNORED epoch is not reported (no obligation there)",
      ledIg3.recordSet.label === "READ-CHECKED"
      && !ledIg3.diagnostics.poolGlobal.some((d) => /no receipt/.test(d)));
    // and a NARROWED interval keeps the obligation for its IN-SCOPE
    // epochs: [5, 5] still reports epoch 5's missing receipt
    const w3n = mkWorld({ mutateDocs: (docs) => { docs.receipt.splice(0, 1); } });
    const narrow55 = await resolveInterval({ requestedStart: 5, requestedEnd: 5,
      configuredStart: 5, fetchRange: w3n.deps.fetchRange });
    const led55 = await runLedger(w3n, { resolution: narrow55 });
    ok("a narrowed interval still reports an IN-SCOPE reservation without its receipt",
      led55.diagnostics.poolGlobal.some((d) => /no receipt/.test(d)));
    // a reservation the ENUMERATION omitted but the pinned read serves
    // still reaches the in-flight sweep (round-27)
    let aside;
    const w4 = mkWorld({ mutateDocs: (docs) => {
      docs.receipt.splice(0, 1);
      aside = docs.reservation.splice(0, 1)[0];
    }, provedByKey: (base) => async (type, key) =>
      type === "reservationByAccrual" && sameIdTest(key.accrualId, aside.accrualId)
        ? { status: "served", doc: aside, height: "915" } : base(type, key) });
    const led4 = await runLedger(w4);
    ok("a pinned-read reservation the enumeration omitted is still reported in-flight without its receipt",
      led4.diagnostics.poolGlobal.some((d) => /no receipt/.test(d)));
  }
  {
    // IGNORED coverage for the dependent types: an interval of [6, 6]
    // leaves epoch 5's reservations, receipts, accruals and a part
    // inside the universe but outside the interval, ignored for ALL types
    const w = mkWorld({ mutateDocs: (docs) => { docs.part.push({ id: h32("f5"),
      poolId: docs.receipt[0].poolId, accrualId: docs.accrual[0].id }); } });
    const resolution = await resolveInterval({ requestedStart: 6, requestedEnd: null,
      configuredStart: 5, fetchRange: async (start, end) => ({
        epochs: [{ number: 6, totalProcessingFees: "5000000", totalDistributedStorageFees: "0",
          coreBlockRewards: "0", totalBlocks: "100", proposedCount: 0 }]
          .filter((e) => e.number >= start && e.number <= end), proved: false }) });
    const led = await runLedger(w, { resolution });
    ok("dependent records outside a narrowed interval are ignored, never extras or orphans",
      led.diagnostics.extras.length === 0 && led.diagnostics.orphans.length === 0
      && resolution.coverage.containsUniverse === false);
  }
  {
    // every document query's height reaches the reduction, named one by one
    const w = mkWorld();
    const led = await runLedger(w);
    const hs = new Set(led.heightCandidates);
    ok("the height candidates carry every enumeration and the per-receipt reservation reads",
      ["900", "901", "902", "903", "904", "915"].every((h) => hs.has(h)));
    const reservationReads = [];
    const counted = { ...w.deps, provedByKey: async (type, key) => {
      if (type === "reservationByAccrual") reservationReads.push(key.accrualId);
      return w.deps.provedByKey(type, key);
    } };
    await runLedger({ ...w, deps: counted });
    const readCounts = reservationReads.reduce((m, k) => (m[k] = (m[k] || 0) + 1, m), {});
    ok("the pinned reservation query runs ONCE per positive entitlement, BY IDENTITY",
      reservationReads.length === 3
      && w.accruals.slice(0, 3).every((a) => readCounts[a.id] === 1));
  }
  {
    // a malformed owned contract pin refuses the request outright
    envStore.updateEnvKey("CONTRACT_V11_ID", "x");
    try {
      const w = mkWorld();
      const r = await runAudit({ poolId: POOL_HEX, dir: path.join(TMP, "jr-nodep"), deps: w.deps });
      ok("a contract pin that does not decode to 32 bytes is REFUSED-INPUT",
        r.verdict === "REFUSED-INPUT" && /does not decode/.test(r.reason));
    } finally { envStore.updateEnvKey("CONTRACT_V11_ID", GC); }
  }

  console.log(`e2AuditTest: ${passed} passed, ${failed} failed (seed ${SEED})`);
  if (failed) process.exitCode = 1;
})();
