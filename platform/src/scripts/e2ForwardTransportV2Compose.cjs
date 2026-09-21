/**
 * e2ForwardTransportV2Compose: THE LIVE RUNNER'S V2 COMPOSITION as an offline-testable
 * module (the per-epoch context design, build-order step 6, first item). The live runner
 * `e2ForwardTransportRun.mjs` supplies the wire calls and the container-bound pieces (the
 * marker-checked proved query, the validated journal reader, the epoch enumeration, the
 * identifier generator, the verifier pipeline); this module composes the instrument's v2
 * inputs from those injected functions and from nothing else, so every decision between
 * the wire and `runTransportCheck`'s v2 arguments can be executed offline with fakes,
 * through the real context module, the real journal-run reader, the real pair check and the
 * real discovery factory. The pre-commit checker's finding on the first cut was that the
 * runner had no execution coverage at all, and `node --check` cannot establish argument
 * compatibility or refusal behaviour; this module is the structural answer.
 *
 * WHAT IT ESTABLISHES, in one sentence: given the injected reads, the composed inputs are
 * exactly what section 10's step 6 names (the proved resolution as the driver makes it, the
 * journal run through `runFromJournal`, the declared fixture per epoch, the contexts through
 * `buildEpochContext`, the discovery universe through `createFetchRange`, the capture lookup
 * by planned accrual identifier), and every configuration, resolution, journal, discovery and
 * context defect THIS MODULE CHECKS AT COMPOSITION TIME refuses by name before the instrument
 * is called. Two answers are deliberately deferred to lookup time, since they are per-member
 * inputs the instrument requests: a missing capture answers null (the verifier refuses it),
 * and duplicate captures under one planned identifier fault when that identifier is looked up.
 *
 * THE FUNCTIONS:
 *   requireProfileKind(profile, mode)      the committed file's kind must select the mode
 *   makeProvedOne({ query, clearMarker, readMarker })
 *                                          the proved read's marker and cardinality guards
 *   parseV2Config({ universeEndRaw, declaredRaw, selfShareCount, targetEpoch })
 *                                          -> { universeEnd, declared }
 *   resolveFormation({ poolId, contractId, provedOne, b58Of })
 *                                          -> { formation, incomeIdentity, poolMarker }
 *   currentEpochOf(rawEpoch)               -> number | null, the wire type checked
 *   journalRunOf(read)                     -> { configuredStart, journalRun }
 *   discoverUniverse({ readEpochInterval, currentEpoch, referenceHeight, chainIdPin,
 *                    configuredStart, universeEnd, log })
 *                                          -> universe, refusing a fallback or an empty set
 *   contextsOver({ universe, target, formation, journalRun, configuredStart, declared,
 *                  identifiers, log })     -> { contexts, contextFor }
 *   captureLookupOver(records)             -> captureFor
 *   composeV2Inputs({ ... })               the whole chain in the order the runner needs
 *
 * THE PROVED POOL RESOLUTION is the distribution driver's (`e2DistributeRun.mjs`,
 * `resolveProvedPool`, transcribed since the driver's is inline): the pool by identifier and
 * its completion receipt by pool, exactly one document each through the injected proved
 * read, the served pool equal to the one asked for, the six-duty pair check over both owners,
 * the eligibility predicate, the allocation hash recomputed over the receipt's own rows and
 * required to equal the stored one. The formation handed on is `{ resolved: true,
 * incomeIdentity, allocationHash, allocation }` with every identifier converted to the
 * canonical 64-hex form at that boundary (design section 8). STATED WIDTH: the driver's
 * comment names a proved identity lookup per owner that its body does not perform, and this
 * module performs none either. The resolution IS served data (the pool and the receipt); what
 * the design forbids deriving from served records is the plan's figures and members, which
 * come from the journal and the formation and never from a served epoch header or accrual.
 *
 * THE DECLARED FIXTURES are harness configuration, never evidence. Every supplied entry is
 * validated here in full (an epoch key, decimal string values, fee at most gross), whether
 * or not its epoch is in the universe, and an entry for an epoch OUTSIDE the universe refuses
 * the run, since a fixture nobody will read is a misconfiguration and not a decision.
 *
 * THE DISCOVERY UNIVERSE comes from the gate module's factory over the injected enumeration,
 * with an EMPTY caps map on purpose (this run's figures come from the contexts, never from
 * discovery, so every in-range epoch is a bare number), the interval closed at the configured
 * end and starting at the journal's configured start. A fallback to the unproved shape
 * REFUSES, since the profile's `universe` is a claim about the finalized set; an empty
 * universe refuses; a start above the end refuses before the enumeration runs.
 *
 * THE CAPTURE LOOKUP answers the receipt capture whose `accrualId` equals the planned
 * identifier, with every receipt-capture supersession record (the basis selector matches the
 * subject tuple itself); no capture answers null, which the verifier refuses; MORE THAN ONE
 * FAULTS by name, since this lookup answers one capture per identifier and does not choose.
 *
 * WHAT IT DOES NOT ESTABLISH: that the injected proved read verifies proofs or checks the
 * marker (the runner's), that the journal reader validated the journal (the runner injects
 * `openValidatedJournal`), that the enumeration is proof-verified (the pinned route's), the
 * verifier pipeline's composition (built in the runner from the SDK, exercised only live),
 * and anything about the instrument's own checks.
 */
"use strict";

const formationCore = require("./formationCore.cjs");
const receiptPoolCheck = require("./receiptPoolCheck.cjs");
const distribute = require("./e2Distribute.cjs");
const captureRecord = require("./e2CaptureRecord.cjs");
const X = require("./e2EpochContext.cjs");
const C = require("./e2ForwardTransportCheck.cjs");
const { createFetchRange } = require("./e2EpochDiscoveryGate.cjs");

const refuse = (why) => { throw new Error(`e2ForwardTransportV2Compose: ${why}; refusing`); };
const HEX64 = /^[0-9a-f]{64}$/;
const DEC_RE = /^(0|[1-9][0-9]*)$/;
const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const idHex = (v) => {
  if (v && typeof v.base58 === "function") v = v.base58();
  const d = formationCore.toId32(v);
  if (!d) refuse(`an identifier does not decode to 32 bytes (${typeof v})`);
  return d.toString("hex");
};
const plainOf = (doc) => (typeof doc.getProperties === "function" ? doc.getProperties() : doc.properties);
const ownerHexOf = (doc) => { const o = typeof doc.getOwnerId === "function" ? doc.getOwnerId() : doc.ownerId; return idHex(o); };

// ONE committed profile kind per mode; the file's own kind must select the mode, or the
// instrument would refuse the mismatched argument set only after the resolution reads
const PROFILE_KINDS = Object.freeze({ v1: C.PROFILE_KIND, v2: C.PROFILE_KIND_V2 });
const requireProfileKind = (profile, mode) => {
  if (!Object.prototype.hasOwnProperty.call(PROFILE_KINDS, mode)) refuse(`the profile mode must be v1 or v2, not ${JSON.stringify(mode)}`);
  if (!isPlain(profile) || profile.kind !== PROFILE_KINDS[mode]) refuse(`the profile file has kind ${JSON.stringify(isPlain(profile) ? profile.kind : typeof profile)}, not the ${mode} kind ${PROFILE_KINDS[mode]}`);
  return PROFILE_KINDS[mode];
};

/**
 * parseV2Config({ universeEndRaw, declaredRaw, selfShareCount, targetEpoch })
 *   universeEndRaw   the E2_FORWARD_UNIVERSE_END text, required, canonical decimal
 *   declaredRaw      the E2_FORWARD_DECLARED_FIGURES text or "" (no fixture)
 *   selfShareCount   how many self-share identifiers the launcher supplied (must be zero)
 *   targetEpoch      the run's target epoch (the end must not be below it)
 */
const parseV2Config = ({ universeEndRaw, declaredRaw, selfShareCount, targetEpoch }) => {
  if (!Number.isSafeInteger(targetEpoch) || targetEpoch < 0) refuse("the target epoch must be a non-negative safe integer");
  if (!Number.isSafeInteger(selfShareCount) || selfShareCount < 0) refuse("selfShareCount must be a count");
  if (selfShareCount > 0) refuse("E2_FORWARD_SELF_SHARE is set under the v2 profile; a v2 run derives the self-share classification from the income identity and takes no list");
  const raw = typeof universeEndRaw === "string" ? universeEndRaw : "";
  if (!DEC_RE.test(raw) || !Number.isSafeInteger(Number(raw))) refuse(`E2_FORWARD_UNIVERSE_END must be a canonical non-negative integer, the closed end of the discovery interval (got ${JSON.stringify(universeEndRaw)})`);
  const universeEnd = Number(raw);
  if (universeEnd < targetEpoch) refuse(`E2_FORWARD_UNIVERSE_END ${universeEnd} is below the target epoch ${targetEpoch}`);
  const declared = {};
  const text = typeof declaredRaw === "string" ? declaredRaw : "";
  if (text.length) {
    let parsed;
    try { parsed = JSON.parse(text); } catch (e) { refuse(`E2_FORWARD_DECLARED_FIGURES is not JSON (${(e && e.message) || String(e)})`); }
    if (!isPlain(parsed)) refuse("E2_FORWARD_DECLARED_FIGURES must be an object keyed by epoch index");
    for (const [k, v] of Object.entries(parsed)) {
      if (!DEC_RE.test(k) || !Number.isSafeInteger(Number(k))) refuse(`E2_FORWARD_DECLARED_FIGURES key ${JSON.stringify(k)} is not an epoch index`);
      if (!isPlain(v) || Object.keys(v).sort().join(",") !== "feeCredits,grossCredits") refuse(`E2_FORWARD_DECLARED_FIGURES[${k}] must be exactly { grossCredits, feeCredits }`);
      // EVERY ENTRY IS VALIDATED IN FULL HERE, whether or not its epoch will be read (the
      // checker's construction: an entry for an epoch outside the universe never reached the
      // context builder, so its values escaped validation)
      if (typeof v.grossCredits !== "string" || !DEC_RE.test(v.grossCredits)) refuse(`E2_FORWARD_DECLARED_FIGURES[${k}].grossCredits must be a canonical decimal STRING`);
      if (typeof v.feeCredits !== "string" || !DEC_RE.test(v.feeCredits)) refuse(`E2_FORWARD_DECLARED_FIGURES[${k}].feeCredits must be a canonical decimal STRING`);
      if (BigInt(v.feeCredits) > BigInt(v.grossCredits)) refuse(`E2_FORWARD_DECLARED_FIGURES[${k}] carries feeCredits above grossCredits`);
      declared[String(Number(k))] = { grossCredits: v.grossCredits, feeCredits: v.feeCredits };
    }
  }
  return { universeEnd, declared };
};

/**
 * makeProvedOne({ query, clearMarker, readMarker }) -> async (type, where, label) => { doc, marker }
 * THE ONE PROVED READ's guards (the distribution driver's `provedQuery` with the audit
 * runner's route check), here so they execute offline (the step-6 round's coverage item):
 *   query(type, where)  the runner's wire call (the patched proof-verifying document query)
 *   clearMarker()       removes the process-global verified-call marker before the call
 *   readMarker()        reads it after the call
 * The marker must be a plain object carrying a plain `metadata` member and a `call` name
 * CONTAINING the text `documents` (the audit runner's own test of the route, a substring and
 * not an exact route name, stated), and the call must answer an ARRAY OF LENGTH ONE (the
 * element's validity is the consumer's, so `[null]` passes this guard and refuses downstream);
 * anything else refuses by name. WIDTH: the marker is a process-global set by the
 * patched route, so its binding to THIS call rests on the runner performing its reads
 * serially, which it does; that is the runner's obligation, stated, and the injected hooks
 * are trusted to clear and read that global and nothing else.
 */
const makeProvedOne = ({ query, clearMarker, readMarker } = {}) => {
  if (typeof query !== "function" || typeof clearMarker !== "function" || typeof readMarker !== "function") refuse("makeProvedOne needs query, clearMarker and readMarker functions");
  return async (type, where, label) => {
    clearMarker();
    const docs = await query(type, where);
    const marker = readMarker();
    if (!marker || !isPlain(marker) || !isPlain(marker.metadata) || !/documents/.test(String(marker.call || ""))) refuse(`${label}: the read did not pass through the patched proof-verifying document query (no verified-call marker for the documents route)`);
    if (!Array.isArray(docs) || docs.length !== 1) refuse(`${label}: expected exactly one document, found ${Array.isArray(docs) ? docs.length : typeof docs}`);
    return { doc: docs[0], marker };
  };
};

/**
 * resolveFormation({ poolId, contractId, provedOne, b58Of }) -> { formation, incomeIdentity, poolMarker }
 *   poolId      64-hex
 *   contractId  the contract identifier as the pair check takes it (base58)
 *   provedOne   async (type, where, label) -> { doc, marker }: exactly one document through
 *               the marker-checked proved query, or a throw (the runner's)
 *   b58Of       hex -> base58 (the runner's encoder)
 */
const resolveFormation = async ({ poolId, contractId, provedOne, b58Of }) => {
  if (!HEX64.test(poolId || "")) refuse("resolveFormation needs a 64-hex poolId");
  if (typeof contractId !== "string" || !contractId.length) refuse("resolveFormation needs the contract identifier the pair check takes");
  if (typeof provedOne !== "function" || typeof b58Of !== "function") refuse("resolveFormation needs provedOne and b58Of functions");
  const label = `pool ${poolId.slice(0, 8)}...`;
  const { doc: poolDocP, marker: poolMarker } = await provedOne("pool", [["$id", "==", b58Of(poolId)]], `${label} record`);
  if (!poolDocP) refuse(`${label}: the proved read answered no document`);
  if (idHex(poolDocP.id) !== poolId) refuse(`${label}: the proved read returned a different document (${idHex(poolDocP.id).slice(0, 12)}...)`);
  const { doc: receiptP } = await provedOne("completionReceipt", [["poolId", "==", Buffer.from(poolId, "hex")]], `${label} completion receipt`);
  if (!receiptP) refuse(`${label}: the proved read answered no completion receipt`);
  const pair = receiptPoolCheck.checkReceiptAgainstPool({
    contractId, receipt: plainOf(receiptP), pool: plainOf(poolDocP), poolId: b58Of(poolId),
    receiptOwnerId: Buffer.from(ownerHexOf(receiptP), "hex"), poolOwnerId: Buffer.from(ownerHexOf(poolDocP), "hex") });
  if (!pair.ok) refuse(`${label}: the pool/receipt pair check refused: ${pair.reason}`);
  const poolProps = plainOf(poolDocP);
  if (poolProps.nodeType !== "evo") refuse(`${label}: nodeType is ${JSON.stringify(poolProps.nodeType)}, not "evo" (the eligibility predicate)`);
  const rp = plainOf(receiptP);
  const rehash = formationCore.allocationHash(Buffer.from(rp.allocationRows)).toString("hex");
  const storedHash = Buffer.from(rp.allocationHash).toString("hex");
  if (rehash !== storedHash) refuse(`${label}: the recomputed allocation hash ${rehash.slice(0, 12)}... differs from the receipt's ${storedHash.slice(0, 12)}...`);
  const alloc = JSON.parse(Buffer.from(rp.allocationRows).toString("utf8"));
  // ["tegara-completion-allocation", 1, contractId, poolId, target, [[owner, amountDuffs, bps, script], ...]]
  if (!Array.isArray(alloc) || !Array.isArray(alloc[5]) || alloc[5].length < 1) refuse(`${label}: the allocation carries no owners`);
  const allocation = alloc[5].map((row) => ({ recipientId: idHex(row[0]), bps: row[2] }));
  const incomeIdentity = ownerHexOf(poolDocP);
  const formation = Object.freeze({ resolved: true, incomeIdentity, allocationHash: rehash, allocation: Object.freeze(allocation.map((r) => Object.freeze(r))) });
  return { formation, incomeIdentity, poolMarker };
};

// the wire TYPE is checked, never a coercion (the audit runner's rule: Number(false) and
// Number([]) are 0, so a coercion would let malformed metadata read as epoch zero)
const currentEpochOf = (rawEpoch) => {
  if (typeof rawEpoch === "number" && Number.isSafeInteger(rawEpoch) && rawEpoch >= 0) return rawEpoch;
  if (typeof rawEpoch === "bigint" && rawEpoch >= 0n && rawEpoch <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(rawEpoch);
  if (typeof rawEpoch === "string" && DEC_RE.test(rawEpoch) && Number.isSafeInteger(Number(rawEpoch))) return Number(rawEpoch);
  return null;
};

// the journal run, the writer's own record (a TRUSTED LOCAL INPUT, design section 4): the
// configured-start binding is the run's base, and runFromJournal refuses a gap
const journalRunOf = (read) => {
  if (!isPlain(read)) refuse("journalRunOf needs the validated journal read");
  const configuredStart = read.configuredStartEpoch;
  if (!Number.isSafeInteger(configuredStart) || configuredStart < 0) refuse("the journal binds no configured start; the carry recursion has no base and no context can be built (a bootstrap run writes the binding)");
  const journalRun = distribute.runFromJournal(read);
  return { configuredStart, journalRun };
};

const discoverUniverse = async ({ readEpochInterval, currentEpoch, referenceHeight, chainIdPin,
  configuredStart, universeEnd, log }) => {
  if (typeof readEpochInterval !== "function") refuse("discoverUniverse needs the interval route readEpochInterval(startEpoch, endEpoch)");
  if (!Number.isSafeInteger(currentEpoch) || currentEpoch < 0) refuse("discoverUniverse needs the verified current epoch");
  // THE SIGNED HEIGHT AND THE CHAIN come from the same proof-verified pool read as the epoch, and
  // they are what the gate can actually authenticate an answer against (a soundness-review finding)
  if (referenceHeight === undefined || referenceHeight === null) refuse("discoverUniverse needs the pool read's signed reference height");
  if (typeof chainIdPin !== "string" || chainIdPin.length === 0) refuse("discoverUniverse needs the run's chain identity pin");
  if (!Number.isSafeInteger(configuredStart) || !Number.isSafeInteger(universeEnd)) refuse("discoverUniverse needs integer interval bounds");
  if (configuredStart > universeEnd) refuse(`the discovery interval ${configuredStart}..${universeEnd} is reversed (the start is the journal's configured start)`);
  // THE REQUESTED UNIVERSE MAY NOT REACH ABOVE THE CLAIMED FINALITY BOUND (a soundness-review finding). The bound is
  // read from a metadata field no signature covers, and the gate's read above it catches an
  // understated claim only when the omission falls within one interval width. What this run CAN
  // insist on is that coverage was established as far as it asked: if the served bound sits below
  // the requested end, the walk covered less than the caller wanted and a positive label would
  // describe a narrower universe than the one requested. Refusing here turns a value this run
  // cannot authenticate into one it does not have to trust.
  if (universeEnd > currentEpoch - 1) {
    refuse(`this run asked for a universe through epoch ${universeEnd} while the pool read's metadata claims the current epoch is ${currentEpoch}, so coverage could be established only through ${currentEpoch - 1}; the claimed bound is not an authenticated value and a universe short of the one requested is not the one requested`);
  }
  const { fetchRange, discoveryProved } = createFetchRange({ readEpochInterval, currentEpoch, referenceHeight, chainIdPin, journalCaps: () => new Map(), figuresFor: (n) => ({ number: n }), log: typeof log === "function" ? log : () => {} });
  const range = await fetchRange(configuredStart, universeEnd);
  if (range.proved !== true || discoveryProved() !== true) refuse(`the finalized-epoch enumeration fell back to the unproved shape; a v2 run takes its universe only from the accepted enumeration (current epoch ${currentEpoch}, interval ${configuredStart}..${universeEnd})`);
  const universe = range.epochs.map((e) => e.number);
  if (universe.length === 0) refuse(`the accepted enumeration holds no finalized epoch in ${configuredStart}..${universeEnd} below the current epoch ${currentEpoch}`);
  return universe;
};

// one context per universe epoch, all built BEFORE the instrument runs, so a builder refusal
// (a thrown one; an encoding-refused context is a RETURNED context the instrument takes)
// stops the run by name here
const contextsOver = ({ universe, target, formation, journalRun, configuredStart, declared, identifiers, log }) => {
  if (!Array.isArray(universe) || universe.length === 0) refuse("contextsOver needs a non-empty universe");
  if (!isPlain(declared)) refuse("contextsOver needs the parsed declared fixtures (an object, possibly empty)");
  const outside = Object.keys(declared).filter((k) => !universe.includes(Number(k)));
  if (outside.length) refuse(`E2_FORWARD_DECLARED_FIGURES names epoch(s) ${outside.join(",")} outside the universe [${universe.join(",")}]; a fixture nobody will read is a misconfiguration`);
  const contexts = new Map();
  for (const n of universe) {
    const fixture = Object.prototype.hasOwnProperty.call(declared, String(n)) ? declared[String(n)] : null;
    const ctx = X.buildEpochContext({ scope: { ...target, epochIndex: n }, formation, journalRun, configuredStart, declaredFigures: fixture, identifiers });
    contexts.set(n, ctx);
    if (typeof log === "function") log(`[CONTEXT] epoch ${n}: figuresSource=${ctx.figuresSource} precondition=${ctx.precondition ? ctx.precondition.code : "none"} encodingRefused=${ctx.encodingRefused} rows=${ctx.rows ? ctx.rows.length : "none"}`);
  }
  const contextFor = (n) => {
    if (!contexts.has(n)) refuse(`contextFor(${n}): no context was built for that epoch; the universe is [${universe.join(",")}]`);
    return contexts.get(n);
  };
  return { contexts, contextFor };
};

const captureLookupOver = (records) => {
  if (!Array.isArray(records)) refuse("captureLookupOver needs the journal's records array");
  return (plannedAccrualId) => {
    if (!HEX64.test(plannedAccrualId || "")) refuse("captureFor takes a 64-hex planned accrual identifier (a caller fault)");
    const hits = records.filter((r) => isPlain(r) && r.kind === captureRecord.RECEIPT_KIND && r.accrualId === plannedAccrualId);
    if (hits.length === 0) return null;
    if (hits.length > 1) refuse(`the journal holds ${hits.length} receipt captures under planned accrual ${plannedAccrualId.slice(0, 12)}...; this lookup answers one capture per planned identifier and does not choose`);
    const supersessions = records.filter((r) => isPlain(r) && r.kind === captureRecord.SUPERSESSION_KIND && r.supersededKind === captureRecord.RECEIPT_KIND);
    return { capture: hits[0], supersessions };
  };
};

/**
 * composeV2Inputs({ poolId, contractId, target, universeEnd, declared, provedOne, b58Of,
 *                   readJournal, readEpochInterval, identifiers, log })
 *   -> { formation, incomeIdentity, currentEpoch, configuredStart, journalRun, universe,
 *        contextFor, captureFor }
 * The chain in the runner's order: the resolution (whose marker gives the current epoch),
 * the journal run, the universe, the contexts, the capture lookup.
 */
const composeV2Inputs = async ({ poolId, contractId, target, universeEnd, declared, provedOne, b58Of, readJournal, readEpochInterval, identifiers, log }) => {
  if (!isPlain(target) || target.poolId !== poolId) refuse("composeV2Inputs needs the run's target scope bound to the same pool");
  if (typeof readJournal !== "function") refuse("composeV2Inputs needs readJournal, the validated journal reader");
  const { formation, incomeIdentity, poolMarker } = await resolveFormation({ poolId, contractId, provedOne, b58Of });
  const currentEpoch = currentEpochOf(poolMarker && poolMarker.metadata ? poolMarker.metadata.epoch : undefined);
  if (currentEpoch === null) refuse(`the pool read's verified metadata epoch is not a usable wire value; finality has no reference`);
  // THE REFERENCE HEIGHT, from the SAME proof-verified read. The epoch above is not covered by the
  // proof's signing digest and the height is, so the height is what an interval answer is
  // authenticated against and the epoch is cross-checked by the gate's probe above the bound.
  const referenceHeight = poolMarker && poolMarker.metadata ? poolMarker.metadata.height : undefined;
  if (referenceHeight === undefined || referenceHeight === null) refuse("the pool read's verified metadata carries no height; there is no authenticated reference to compare an interval answer against");
  const read = readJournal();
  const { configuredStart, journalRun } = journalRunOf(read);
  const universe = await discoverUniverse({ readEpochInterval, currentEpoch, referenceHeight,
    chainIdPin: target.chainId, configuredStart, universeEnd, log });
  const { contextFor } = contextsOver({ universe, target, formation, journalRun, configuredStart, declared, identifiers, log });
  const captureFor = captureLookupOver(read.records);
  return { formation, incomeIdentity, currentEpoch, configuredStart, journalRun, universe, contextFor, captureFor };
};

module.exports = { PROFILE_KINDS, requireProfileKind, parseV2Config, makeProvedOne, resolveFormation, currentEpochOf, journalRunOf, discoverUniverse, contextsOver, captureLookupOver, composeV2Inputs };
