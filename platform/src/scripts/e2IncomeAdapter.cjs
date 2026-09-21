/**
 * THE INCOME ADAPTER (C1's last project unit): the audit's per-epoch
 * income figures served from the finalized-epoch reader's PROVED route,
 * retiring the harness-declared width as the default posture.
 *
 * WHERE IT SITS: the audit runner composes discovery through
 * createFetchRange (the discovery gate module), which takes a CAPS map
 * (epoch number to figure source) and a figuresFor mapper. This module
 * builds that pair from a PROVED finalized-epoch answer instead of the
 * journal, so the discovery composition, the audit module and their
 * batteries stay untouched; only the figure SOURCE changes.
 *
 * THE STATUS GRAMMAR IS CONSUMED HERE, per the reader's contract: the
 * answer vocabulary is CLOSED and this consumer switches on it, refusing
 * any status it does not recognize, refusing the two non-proved statuses
 * by name, and enforcing ITS OWN coverage rule (the completeness split:
 * the reader serves proved subsets claiming only what they carry, and
 * every consumer owes its own coverage check): the proved answer must
 * cover the requested figure interval contiguously, in full.
 *
 * THE NODE IDENTITY IS A DECLARED TRUST INPUT, like the audit's
 * incomeIdentity: the pool-to-node binding is gate G4 and remains
 * UNVERIFIABLE, so the operator declares WHICH node's proposal count
 * prices the pool's income, and the proved answer supplies that node's
 * count at proof strength GIVEN the declaration. A declared node absent
 * from an epoch's proposer set counts zero for that epoch, which is a
 * true statement about the declared node, not an error.
 *
 * FAILURE POSTURE, deliberately stricter than discovery's: income is
 * the money math, so a proved-income failure REFUSES THE RUN. There is
 * no automatic fallback to declared figures; the declared source exists
 * only as the operator's explicit configuration choice, and the runner
 * states which source served in the artifact's provenance.
 */
const HEX64 = /^[0-9a-f]{64}$/;
const DEC = /^(0|[1-9][0-9]*)$/;

// one PROVED reader entry to the audit's epoch-figure shape. The reader
// validated the record already; the re-checks here are cheap and exist
// because this module is exported and a direct caller is not behind the
// reader (the closing wave's exported-surface lesson).
const mapProvedFigures = (entry, nodeIdHex) => {
  if (typeof nodeIdHex !== "string" || !HEX64.test(nodeIdHex)) {
    throw new Error("the declared node identity must be 64 lowercase hex characters; refusing");
  }
  if (!entry || !Number.isSafeInteger(entry.number) || entry.number < 0) {
    throw new Error("the proved entry carries no valid epoch number; refusing");
  }
  for (const k of ["totalProcessingFees", "totalDistributedStorageFees", "coreBlockRewards", "totalBlocksInEpoch"]) {
    if (typeof entry[k] !== "string" || !DEC.test(entry[k])) {
      throw new Error(`the proved entry for epoch ${entry.number} has ${k}=${JSON.stringify(entry[k])}, not a canonical decimal string; refusing`);
    }
  }
  if (!Array.isArray(entry.blockProposers)) {
    throw new Error(`the proved entry for epoch ${entry.number} carries no proposer array; refusing`);
  }
  let proposedCount = 0;
  for (const p of entry.blockProposers) {
    if (!p || typeof p.proposerId !== "string" || !HEX64.test(p.proposerId) || !Number.isSafeInteger(p.blockCount) || p.blockCount < 0) {
      throw new Error(`the proved entry for epoch ${entry.number} carries a malformed proposer record; refusing`);
    }
    if (p.proposerId === nodeIdHex) {
      proposedCount += p.blockCount;
      // the SUM must stay range-safe, not only each addend: two safe
      // addends can leave the safe range and arrive rounded
      if (!Number.isSafeInteger(proposedCount)) {
        throw new Error(`the declared node's proposal-count sum left the safe integer range for epoch ${entry.number}; refusing an inexact count`);
      }
    }
  }
  // the count cannot exceed the epoch's own block total (the audit
  // rechecks this, and this module claims protective rechecks for
  // direct callers, so the relationship is enforced here too)
  if (BigInt(proposedCount) > BigInt(entry.totalBlocksInEpoch)) {
    throw new Error(`the declared node's proposal count ${proposedCount} exceeds epoch ${entry.number}'s total blocks ${entry.totalBlocksInEpoch}; refusing`);
  }
  return {
    number: entry.number,
    totalProcessingFees: entry.totalProcessingFees,
    totalDistributedStorageFees: entry.totalDistributedStorageFees,
    coreBlockRewards: entry.coreBlockRewards,
    totalBlocks: entry.totalBlocksInEpoch,
    proposedCount,
  };
};

// the proved answer to a CAPS map of NORMALIZED figure records, ONE
// acceptance gate (a coverage-only gate exported beside a
// lazy figure mapping left partially cloned raw rows on the exported
// surface): the closed status switch, full contiguous coverage of
// [startEpoch, endEpoch], and every row through the figure mapper, so
// the returned map holds only flat validated records that alias
// nothing the producer retained
const provedCapsOf = (answer, { startEpoch, endEpoch, nodeIdHex }) => {
  if (typeof nodeIdHex !== "string" || !HEX64.test(nodeIdHex)) {
    throw new Error("the declared node identity must be 64 lowercase hex characters; refusing");
  }
  if (!Number.isSafeInteger(startEpoch) || startEpoch < 0 || !Number.isSafeInteger(endEpoch)
    || endEpoch < startEpoch) {
    throw new Error(`the figure interval ${JSON.stringify(startEpoch)}..${JSON.stringify(endEpoch)} is not a valid closed range; refusing`);
  }
  const status = answer && answer.status;
  if (status === "unproved-plain") {
    throw new Error("the income source answered unproved-plain; unauthenticated figures never serve the proved income posture, refusing the run");
  }
  if (status === "unverified-carrier") {
    throw new Error("the income source answered an unverified carrier (no verifier bound); refusing the run");
  }
  if (status !== "proved") {
    throw new Error(`the income source answered an undeclared status (${JSON.stringify(status)}); the answer vocabulary is closed, refusing the run`);
  }
  const expected = endEpoch - startEpoch + 1;
  const epochs = Array.isArray(answer.epochs) ? answer.epochs : [];
  if (epochs.length !== expected) {
    throw new Error(`the proved income answer covers ${epochs.length} of the ${expected} requested epochs; this consumer requires full coverage, refusing the run`);
  }
  const caps = new Map();
  for (let i = 0; i < epochs.length; i++) {
    if (!epochs[i] || epochs[i].number !== startEpoch + i) {
      throw new Error(`the proved income answer is not contiguous ascending from ${startEpoch} (index ${i} carries epoch ${epochs[i] && epochs[i].number}); refusing the run`);
    }
    // VALIDATE THEN OWN, completed at this one gate:
    // the row runs the figure mapper HERE, and only the flat validated
    // record enters the map, so nothing the producer retained is
    // aliased in either direction
    caps.set(epochs[i].number, mapProvedFigures(epochs[i], nodeIdHex));
  }
  return caps;
};

// the runner-facing factory: fetches the proved answer ONCE (lazily,
// through the injected fetch, which in production is the mounted
// finalized-epoch reader with the side-loaded verifier injected) and
// returns the (caps, figuresFor) pair the discovery factory consumes,
// plus a provenance record for the artifact
const createProvedIncome = ({ fetchProved, nodeIdHex, startEpoch, endEpoch, log }) => {
  if (typeof fetchProved !== "function") throw new Error("createProvedIncome needs the injected proved fetch; refusing");
  if (typeof log !== "function") throw new Error("createProvedIncome requires an explicit log function; refusing");
  if (typeof nodeIdHex !== "string" || !HEX64.test(nodeIdHex)) {
    throw new Error("the declared node identity must be 64 lowercase hex characters; refusing");
  }
  let capsPromise = null;
  let accepted = null; // the ADAPTER-PRIVATE accepted store: NORMALIZED figure records only
  let served = false; // true only after EVERY row passed the figure mapper at acceptance
  // the sink is OBSERVABILITY, never control (an unguarded
  // log call after served flipped true let a throwing sink reject
  // caps() while provenance read served; the reader set this policy
  // and the adapter follows it)
  const tryLog = (s) => { try { log(s); } catch (_) { /* the sink must not decide the answer */ } };
  const caps = () => {
    if (capsPromise === null) {
      capsPromise = (async () => {
        const answer = await fetchProved({ startEpoch, endEpoch });
        // ONE acceptance gate: status, coverage, contiguity and the
        // figure mapping all inside provedCapsOf, which returns only
        // normalized flat records (validate what you own, completed
        // at the exported gate)
        const normalized = provedCapsOf(answer, { startEpoch, endEpoch, nodeIdHex });
        accepted = normalized;
        served = true;
        tryLog(`  [INCOME] proved figures for epochs ${startEpoch}..${endEpoch} (${normalized.size} epochs) under declared node ${nodeIdHex.slice(0, 12)}... (the figures and the node's proposal counts are proof-verified; the pool-to-node binding itself stays gate G4, declared not proved)`);
        return normalized;
      })();
    }
    // every caller gets its OWN COPY of the flat records (shared
    // containers and shared row objects both let a caller
    // rewrite what the gate had passed)
    return capsPromise.then((m) => new Map([...m].map(([k, v]) => [k, { ...v }])));
  };
  const figuresFor = (n, entry) => {
    // rows are served from the ADAPTER'S OWN ACCEPTED STORE, never
    // from the caller's object (a fabricated same-number row,
    // or a mutated copy, would otherwise be labeled proved); the
    // caller's entry is only checked for the factory-contract binding
    if (accepted === null) {
      throw new Error(`figuresFor asked for epoch ${n} before any proved answer was accepted; refusing`);
    }
    if (!entry || entry.number !== n) {
      throw new Error(`figuresFor asked for epoch ${n} and received ${entry && entry.number}; refusing a misbound row`);
    }
    const row = accepted.get(n);
    if (!row) {
      throw new Error(`figuresFor asked for epoch ${n}, which the accepted proved answer does not carry; refusing`);
    }
    const f = { ...row };
    tryLog(`  [FIGURES] epoch ${n}: PROVED income (processing=${f.totalProcessingFees} distributedStorage=${f.totalDistributedStorageFees} coreRewards=${f.coreBlockRewards} blocks=${f.totalBlocks}) with proposedCount=${f.proposedCount} for the DECLARED node (G4 binding declared, not proved)`);
    return f;
  };
  // the provenance is STATE-TRUTHFUL (a constant record
  // claimed proof-verified figures before any fetch had run): the
  // served flag says whether the verified fetch actually completed,
  // and the width sentence follows it
  return { caps, figuresFor,
    provenance: () => ({ incomeSource: "proved", declaredNodeId: nodeIdHex,
      figureInterval: { startEpoch, endEpoch }, served,
      width: served
        ? "figures and per-node proposal counts proof-verified; the pool-to-node binding is declared (gate G4)"
        : "the proved source is selected and the verified fetch has not completed; nothing is served yet" }) };
};

module.exports = { mapProvedFigures, provedCapsOf, createProvedIncome };
