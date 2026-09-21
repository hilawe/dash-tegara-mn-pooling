/**
 * Offline battery for the INCOME ADAPTER (e2IncomeAdapter.cjs): the
 * audit's proved-income source, from the finalized-epoch reader's
 * answer to the discovery factory's caps-and-figures pair.
 *
 * WHAT THIS SUITE ESTABLISHES: the figure mapping's identity (including
 * the declared-node proposal count, present, absent and split), the
 * consumer-side status switch over the reader's CLOSED grammar
 * (unknown statuses refuse; the two non-proved statuses refuse by
 * name), this consumer's OWN coverage rule (full contiguous coverage,
 * per the completeness split), the lazy single fetch, and the
 * COMPOSITION with the discovery factory (proved caps riding the
 * unchanged createFetchRange, in-interval epochs served with proved
 * figures, out-of-interval epochs bare).
 *
 * WIDTH, STATED: the real reader, verifier and audit consumption are
 * live territory (run_audit.sh with E2_INCOME_SOURCE=proved); this
 * battery drives the adapter with reader-shaped fakes.
 */
const { mapProvedFigures, provedCapsOf, createProvedIncome } = require("./e2IncomeAdapter.cjs");
const { createFetchRange } = require("./e2EpochDiscoveryGate.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error("FAIL:", name, "(no error)"); }
  catch (e) { ok(name, re.test(String(e.message))); }
};
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error("FAIL:", name, "(no rejection)"); }
  catch (e) { ok(name, re.test(String(e.message))); }
};

const NODE = "ab".repeat(32);
const OTHER = "cd".repeat(32);
// a reader-shaped proved entry (the wrapper's mapped output shape)
const entryOf = (n, over = {}) => ({ number: n, firstBlockHeight: "1", firstCoreBlockHeight: 10,
  firstBlockTime: "2", feeMultiplier: 1.0, protocolVersion: 12, totalBlocksInEpoch: "28",
  nextEpochStartCoreBlockHeight: 20, totalProcessingFees: "66056771137",
  totalDistributedStorageFees: "0", totalCreatedStorageFees: "5", coreBlockRewards: "7026365816314",
  blockProposers: [{ proposerId: NODE, blockCount: 9 }, { proposerId: OTHER, blockCount: 19 }],
  ...over });

// ---- mapProvedFigures ----
{
  const f = mapProvedFigures(entryOf(0), NODE);
  ok("the mapped figures carry the audit's exact epoch-figure shape with the DECLARED node's count",
    JSON.stringify(f) === JSON.stringify({ number: 0, totalProcessingFees: "66056771137",
      totalDistributedStorageFees: "0", coreBlockRewards: "7026365816314",
      totalBlocks: "28", proposedCount: 9 }));
  ok("a declared node absent from the proposer set counts zero (a true statement, not an error)",
    mapProvedFigures(entryOf(0), "ef".repeat(32)).proposedCount === 0);
  const split = mapProvedFigures(entryOf(0, { blockProposers: [
    { proposerId: NODE, blockCount: 3 }, { proposerId: NODE, blockCount: 2 },
    { proposerId: NODE, blockCount: 2 }] }), NODE);
  ok("repeated proposer records for the declared node sum across ALL repeats (three records, not the first two)",
    split.proposedCount === 7);
  ok("a node sharing the declared identity's PREFIX does not match (identity equality, not prefix comparison)",
    mapProvedFigures(entryOf(0, { blockProposers: [
      { proposerId: "ab" + "00".repeat(31), blockCount: 5 }, { proposerId: NODE, blockCount: 9 }] }), NODE).proposedCount === 9);
  const other = mapProvedFigures(entryOf(3, { totalProcessingFees: "17", totalDistributedStorageFees: "1",
    coreBlockRewards: "2", totalBlocksInEpoch: "50",
    blockProposers: [{ proposerId: NODE, blockCount: 11 }] }), NODE);
  ok("a second variant maps by its own values (a fixture-constant special case fails here)",
    JSON.stringify(other) === JSON.stringify({ number: 3, totalProcessingFees: "17",
      totalDistributedStorageFees: "1", coreBlockRewards: "2", totalBlocks: "50", proposedCount: 11 }));
}
throws("a proposal-count SUM that leaves the safe range refuses (each addend safe, the sum inexact)",
  () => mapProvedFigures(entryOf(0, { totalBlocksInEpoch: "99999999999999999999", blockProposers: [
    { proposerId: NODE, blockCount: Number.MAX_SAFE_INTEGER }, { proposerId: NODE, blockCount: 2 }] }), NODE),
  /left the safe integer range/);
throws("a count exceeding the epoch's own block total refuses",
  () => mapProvedFigures(entryOf(0, { totalBlocksInEpoch: "1", blockProposers: [
    { proposerId: NODE, blockCount: 2 }] }), NODE), /exceeds epoch 0's total blocks/);
throws("a malformed declared node refuses", () => mapProvedFigures(entryOf(0), "xyz"), /64 lowercase hex/);
throws("a non-decimal figure refuses", () => mapProvedFigures(entryOf(0, { totalProcessingFees: 5 }), NODE), /not a canonical decimal string/);
throws("a missing proposer array refuses", () => mapProvedFigures(entryOf(0, { blockProposers: undefined }), NODE), /no proposer array/);
throws("a malformed proposer record refuses", () => mapProvedFigures(entryOf(0, { blockProposers: [{ proposerId: "ab", blockCount: 1 }] }), NODE), /malformed proposer record/);
throws("a missing epoch number refuses", () => mapProvedFigures({ ...entryOf(0), number: undefined }, NODE), /no valid epoch number/);

// ---- provedCapsOf: the closed status switch and the coverage rule ----
const answerOf = (epochs) => ({ status: "proved", epochs });
{
  const caps = provedCapsOf(answerOf([entryOf(0), entryOf(1), entryOf(2)]), { startEpoch: 0, endEpoch: 2, nodeIdHex: NODE });
  ok("a full contiguous proved answer builds the caps map keyed by epoch",
    caps.size === 3 && caps.get(1).number === 1);
  ok("the exported gate returns NORMALIZED FLAT records (a coverage-only gate returned partially cloned raw rows on the exported surface)",
    JSON.stringify(Object.keys(caps.get(0)).sort()) === JSON.stringify(["coreBlockRewards", "number",
      "proposedCount", "totalBlocks", "totalDistributedStorageFees", "totalProcessingFees"]));
  {
    const retained = answerOf([entryOf(0, { extension: { revision: 1 } })]);
    const c = provedCapsOf(retained, { startEpoch: 0, endEpoch: 0, nodeIdHex: NODE });
    ok("nothing the producer retained is aliased by the gate's result (a nested extension member does not survive into it)",
      !("extension" in c.get(0)) && retained.epochs[0].extension.revision === 1);
  }
  throws("the gate refuses a malformed node identity", () => provedCapsOf(answerOf([entryOf(0)]), { startEpoch: 0, endEpoch: 0, nodeIdHex: "nope" }), /64 lowercase hex/);
}
throws("the unproved-plain status refuses BY NAME (unauthenticated figures never serve the proved posture)",
  () => provedCapsOf({ status: "unproved-plain", epochs: [] }, { startEpoch: 0, endEpoch: 0, nodeIdHex: NODE }), /unauthenticated figures never serve/);
throws("the unverified-carrier status refuses BY NAME",
  () => provedCapsOf({ status: "unverified-carrier" }, { startEpoch: 0, endEpoch: 0, nodeIdHex: NODE }), /unverified carrier/);
throws("an UNDECLARED status refuses (the answer vocabulary is closed)",
  () => provedCapsOf({ status: "mystery", epochs: [] }, { startEpoch: 0, endEpoch: 0, nodeIdHex: NODE }), /undeclared status/);
throws("a missing answer refuses through the same closed switch",
  () => provedCapsOf(undefined, { startEpoch: 0, endEpoch: 0, nodeIdHex: NODE }), /undeclared status/);
throws("a PARTIAL proved answer refuses (this consumer requires full coverage, the completeness split's rule)",
  () => provedCapsOf(answerOf([entryOf(0)]), { startEpoch: 0, endEpoch: 2, nodeIdHex: NODE }), /full coverage/);
throws("an EMPTY proved answer refuses for the same coverage rule",
  () => provedCapsOf(answerOf([]), { startEpoch: 0, endEpoch: 2, nodeIdHex: NODE }), /full coverage/);
throws("a gapped proved answer at the right count refuses (contiguity, not only cardinality)",
  () => provedCapsOf(answerOf([entryOf(0), entryOf(2), entryOf(3)]), { startEpoch: 0, endEpoch: 2, nodeIdHex: NODE }), /not contiguous ascending/);
throws("a reversed figure interval refuses", () => provedCapsOf(answerOf([]), { startEpoch: 2, endEpoch: 0, nodeIdHex: NODE }), /not a valid closed range/);
throws("an open figure interval refuses", () => provedCapsOf(answerOf([]), { startEpoch: 0, endEpoch: null, nodeIdHex: NODE }), /not a valid closed range/);

// ---- createProvedIncome and the discovery-factory composition ----
(async () => {
  { // the lazy single fetch and the provenance record
    const calls = [];
    const inc = createProvedIncome({ nodeIdHex: NODE, startEpoch: 0, endEpoch: 2, log: () => {},
      fetchProved: async ({ startEpoch, endEpoch }) => { calls.push([startEpoch, endEpoch]);
        return answerOf([entryOf(0), entryOf(1), entryOf(2)]); } });
    ok("BEFORE any fetch, the provenance says so: served false and a pending width, never a proof claim (a constant record claimed proof-verified figures pre-fetch)",
      inc.provenance().served === false && /has not completed/.test(inc.provenance().width));
    const c1 = await inc.caps();
    const c2 = await inc.caps();
    ok("the proved answer is fetched once, for exactly the figure interval, and cached",
      JSON.stringify(calls) === JSON.stringify([[0, 2]]) && c1.size === 3 && c2.size === 3);
    ok("every caps() caller receives its OWN COPY (a shared map let one caller's mutation erase another's coverage after the gate had passed)",
      c1 !== c2 && (c1.delete(1), (await inc.caps()).has(1)));
    { // the shared-row and fabricated-row shapes: mutating a
      // returned copy's row changes nothing, and figuresFor serves from
      // the adapter's own accepted store, never the caller's object
      c2.get(1).totalProcessingFees = "999999999";
      ok("mutating a returned copy's ROW does not reach the next caller (deep copies, not shared row objects)",
        (await inc.caps()).get(1).totalProcessingFees === "66056771137");
      const f = inc.figuresFor(1, { ...entryOf(1), totalProcessingFees: "999999999" });
      ok("figuresFor serves the ACCEPTED row's figures even when the caller hands it a fabricated same-number row",
        f.totalProcessingFees === "66056771137");
      let refusedUnknown = false;
      try { inc.figuresFor(9, entryOf(9)); } catch (e) { refusedUnknown = /does not carry/.test(String(e.message)); }
      ok("figuresFor refuses an epoch the accepted answer does not carry", refusedUnknown === true);
    }
    { // ACCEPTANCE VALIDATES WHAT IT OWNS: a coverage-valid
      // answer whose row fails the figure mapper rejects AT caps(),
      // and served stays false, so provenance never claims verified
      // figures over rows the mapper would refuse
      const bad = createProvedIncome({ nodeIdHex: NODE, startEpoch: 0, endEpoch: 0, log: () => {},
        fetchProved: async () => answerOf([entryOf(0, { totalProcessingFees: 5 })]) });
      let rej = false;
      try { await bad.caps(); } catch (e) { rej = /not a canonical decimal string/.test(String(e.message)); }
      ok("a malformed figure refuses AT ACCEPTANCE, not at a later lazy mapping", rej === true);
      ok("after a refused acceptance the provenance still says served:false", bad.provenance().served === false);
    }
    { // the authority stores NORMALIZED FLAT records, so a
      // nested-member alias cannot exist even in principle; the served
      // figure's key set is exactly the audit's six fields and every
      // value is a flat scalar
      const inc3 = createProvedIncome({ nodeIdHex: NODE, startEpoch: 0, endEpoch: 0, log: () => {},
        fetchProved: async () => answerOf([entryOf(0, { extension: { revision: 1 } })]) });
      await inc3.caps();
      const f = inc3.figuresFor(0, { number: 0 });
      ok("the served figure is a flat six-field record (no nested member from the answer survives into the authority)",
        JSON.stringify(Object.keys(f).sort()) === JSON.stringify(["coreBlockRewards", "number",
          "proposedCount", "totalBlocks", "totalDistributedStorageFees", "totalProcessingFees"])
        && Object.values(f).every((v) => typeof v === "string" || typeof v === "number"));
    }
    { // the INGRESS alias: the fetch producer retains its answer
      // objects; the accepted store must hold clones made at the
      // validation gate, so a post-acceptance mutation of the retained
      // answer never reaches a served figure
      const retained = answerOf([entryOf(0), entryOf(1), entryOf(2)]);
      const inc2 = createProvedIncome({ nodeIdHex: NODE, startEpoch: 0, endEpoch: 2, log: () => {},
        fetchProved: async () => retained });
      await inc2.caps();
      retained.epochs[1].totalProcessingFees = "999999999";
      retained.epochs[1].blockProposers[0].blockCount = 1;
      ok("mutating the RETAINED fetch answer after acceptance changes nothing served (validate then own: the store holds ingress clones)",
        inc2.figuresFor(1, entryOf(1)).totalProcessingFees === "66056771137"
        && inc2.figuresFor(1, entryOf(1)).proposedCount === 9
        && (await inc2.caps()).get(1).totalProcessingFees === "66056771137");
    }
    ok("AFTER the verified fetch, the provenance is state-truthful: served true, the source, the declared node, the interval and the G4 width",
      JSON.stringify(inc.provenance()) === JSON.stringify({ incomeSource: "proved", declaredNodeId: NODE,
        figureInterval: { startEpoch: 0, endEpoch: 2 }, served: true,
        width: "figures and per-node proposal counts proof-verified; the pool-to-node binding is declared (gate G4)" }));
  }
  { // a rejecting fetch REFUSES (no fallback posture: the caller sees the rejection)
    const inc = createProvedIncome({ nodeIdHex: NODE, startEpoch: 0, endEpoch: 2, log: () => {},
      fetchProved: async () => { throw new Error("income route down"); } });
    await rejects("a failing proved fetch rejects the caps (income refuses the run, never a silent fallback)",
      inc.caps(), /income route down/);
  }
  throws("the factory refuses a malformed node at construction", () => createProvedIncome({
    nodeIdHex: "nope", startEpoch: 0, endEpoch: 2, log: () => {}, fetchProved: async () => ({}) }), /64 lowercase hex/);
  throws("the factory requires an explicit log function", () => createProvedIncome({
    nodeIdHex: NODE, startEpoch: 0, endEpoch: 2, fetchProved: async () => ({}) }), /explicit log function/);
  throws("the factory requires the injected fetch", () => createProvedIncome({
    nodeIdHex: NODE, startEpoch: 0, endEpoch: 2, log: () => {} }), /injected proved fetch/);
  { // the sink is observability, never control (an unguarded
    // log after served flipped true let a throwing sink reject caps())
    const inc = createProvedIncome({ nodeIdHex: NODE, startEpoch: 0, endEpoch: 0,
      log: () => { throw new Error("sink failed"); },
      fetchProved: async () => answerOf([entryOf(0)]) });
    const c = await inc.caps();
    ok("a throwing sink does not reject acceptance, and served stays truthful",
      c.size === 1 && inc.provenance().served === true
      && inc.figuresFor(0, { number: 0 }).totalProcessingFees === "66056771137");
  }

  { // the requested epoch and the served row are BOUND in figuresFor,
    // and NOTHING serves before an accepted answer exists
    const inc = createProvedIncome({ nodeIdHex: NODE, startEpoch: 0, endEpoch: 0, log: () => {},
      fetchProved: async () => answerOf([entryOf(0)]) });
    let preFetch = false;
    try { inc.figuresFor(0, entryOf(0)); } catch (e) { preFetch = /before any proved answer was accepted/.test(String(e.message)); }
    ok("figuresFor refuses BEFORE any proved answer was accepted (a fabricated row could otherwise be labeled proved pre-fetch)", preFetch === true);
    await inc.caps();
    let threw = false;
    try { inc.figuresFor(0, entryOf(1)); } catch (e) { threw = /misbound row/.test(String(e.message)); }
    ok("figuresFor refuses a row whose epoch differs from the one asked for (the log could name one epoch while another's row was served)", threw === true);
  }
  { // THE COMPOSITION: proved caps ride the unchanged discovery factory;
    // in-interval epochs serve PROVED figures, epochs past the figure
    // interval stay bare (the audit's bare-number refusal owns them)
    const inc = createProvedIncome({ nodeIdHex: NODE, startEpoch: 0, endEpoch: 1, log: () => {},
      fetchProved: async () => answerOf([entryOf(0), entryOf(1)]) });
    const wire = Array.from({ length: 5 }, (_, i) => ({ number: i })); // the route's universe, epochs 0..4 under a current epoch of 5
    const d = createFetchRange({
      referenceHeight: "1000", chainIdPin: "test-chain",
      readEpochInterval: async (a, b) => ({ epochs: wire.filter((e) => e.number >= a && e.number <= b && e.number < 5), metadata: { height: "1000", chainId: "test-chain", epoch: 5 } }),
      currentEpoch: 5, journalCaps: inc.caps, figuresFor: inc.figuresFor, log: () => {} });
    const r = await d.fetchRange(0, 4);
    ok("the composition serves proved figures inside the figure interval and bare numbers past it",
      r.proved === true
      && JSON.stringify(r.epochs[0]) === JSON.stringify({ number: 0, totalProcessingFees: "66056771137",
        totalDistributedStorageFees: "0", coreBlockRewards: "7026365816314", totalBlocks: "28", proposedCount: 9 })
      && JSON.stringify(r.epochs.map((e) => e.number)) === JSON.stringify([0, 1, 2, 3, 4])
      && JSON.stringify(Object.keys(r.epochs[2])) === JSON.stringify(["number"]));
  }
  { // the composition REFUSES the run when the income fetch fails: the
    // async caps rejection propagates out of fetchRange (discovery's
    // enumeration fallback never swallows an income failure)
    const inc = createProvedIncome({ nodeIdHex: NODE, startEpoch: 0, endEpoch: 1, log: () => {},
      fetchProved: async () => ({ status: "unverified-carrier" }) });
    const d = createFetchRange({
      referenceHeight: "1000", chainIdPin: "test-chain",
      readEpochInterval: async (a, b) => ({ epochs: [{ number: 0 }, { number: 1 }].filter((e) => e.number >= a && e.number <= b), metadata: { height: "1000", chainId: "test-chain", epoch: 2 } }),
      currentEpoch: 2, journalCaps: inc.caps, figuresFor: inc.figuresFor, log: () => {} });
    await rejects("an income failure propagates out of the discovery composition (refusing the run, not falling back)",
      d.fetchRange(0, 1), /unverified carrier/);
  }

  console.log(`e2IncomeAdapterTest: ${passed} passed, ${failed} failed`);
  process.exitCode = failed ? 1 : 0;
})();
