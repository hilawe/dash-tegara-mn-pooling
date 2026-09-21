/**
 * e2EpochContext: the orchestrator's PER-EPOCH CONTEXT as a pure module (the per-epoch
 * context design, build-order step 4; kernel contract section 7, "the orchestrator owns the
 * snapshot"). It is the design's sections 3 to 6 and 8 laid out as data, with no I/O, no
 * ledger-read adapter, no journal handle and no ledger read; its injected functions are the
 * identifier generator, the capture lookup, the verifier's pipeline and the capture-basis
 * adapter.
 *
 * WHAT IT ESTABLISHES, in one sentence: from the formation inputs, the journaled run, a
 * declared fixture or its explicit absence, and the identifier generator, ONE immutable context
 * per build call is derived from those inputs and from nothing served, and the plan input the
 * kernel receives is derived from that context alone. Whether the caller read an epoch record
 * BEFORE building is not observable here; the instrument (step 5) observes that ordering. The
 * four exported functions are:
 *
 *   buildEpochContext({ scope, formation, journalRun, configuredStart, declaredFigures,
 *                       identifiers })  -> a deep-frozen, branded context
 *   planInputOf(ctx)                    -> the kernel's plan-builder input, fresh per call
 *   reservationForVerifier(answer)      -> the verifier's three-way reservation shape
 *   executionVerdictFor(ctx, { captureFor, deps })
 *                                       -> the injected verdict closure of design section 6
 *
 * THE FIGURES ARE DECLARED OR REFUSED, NEVER CHOSEN (design section 4), one rule per case:
 *   1. the journaled run carries this epoch's header numbers: they are the figures,
 *      `figuresSource` is `journaled-header`; a declared fixture beside them must agree gross
 *      and fee SEPARATELY (never through the derived distributable amount), or the build
 *      refuses; the journaled allocation hash and member count must equal the formation's;
 *   2. no journaled numbers and no declared fixture: the context carries the precondition
 *      `UNPROVED_EPOCH_OBJECT_UNPROVED` with a diagnostic naming open construction C1, no rows
 *      and no figures, and `figuresSource` is the provenance label `epoch-object-unproved-c1`;
 *      `planInputOf` refuses such a context by name, so no plan input is derived from an
 *      unproved figure through this module (a caller that builds a plan without it is outside
 *      what this module can refuse);
 *   3. no journaled numbers and a declared fixture (harness configuration, never evidence):
 *      the figures are the fixture's, `figuresSource` is `declared-fixture`, and the epoch is
 *      appended to the journaled run for the carry recursion, which requires it to be the next
 *      epoch after the run (or the configured start when the run is empty).
 *
 * THE ROWS ARE THE CARRY PARTITION'S (design section 3, step 3b): `entitlementCalc.
 * buildCarryCapableEntitlements` over the run answers each member's effective amount,
 * `isSelfShare` and `payable`, and this module copies those answers rather than deriving them
 * again. The planned accrual identifier is `e2DocId.docIdForIn` over the scope's pool, this
 * epoch, the platformAccrual type and the member's identity (step 3c). `shareBps` is the
 * allocation row's. The schema ceiling is `entitlementCalc.SCHEMA_CREDIT_CEILING`, stated
 * rather than selected by a caller.
 *
 * AN ENCODING-REFUSED EPOCH (the row source refuses the epoch's rows because an owed or
 * effective amount exceeds the ceiling) is a context with `encodingRefused: true` whose rows
 * carry identity, bps, the identity-derived `isSelfShare` and the planned identifier, no amount
 * and no `payable` answer,
 * since the row source answers none. `planInputOf` then builds the kernel's encoding-refused
 * plan input (no header) and supplies the plan grammar's placeholder amount `"0"` with
 * `payable: false` per member, WHICH THAT KERNEL PATH NEVER READS: under an encoding-refused
 * plan the evaluator checks each member's accrual absent and its machinery empty by funder
 * and planned identifier (e2ForwardKernel.cjs, the encoding-refused branch), and no amount
 * comparison arises. The placeholder is a grammar requirement and not a statement about the
 * entitlement. WIDTH, STATED: the refusal is recognized by the row source's own refusal text
 * for that condition (its `rowsFor` throws for a refused epoch, the design's table); the run
 * is constructed so the epoch is always inside it, so the row source's only other refusal
 * cannot arise here, and any other thrown value propagates as the fault it is.
 *
 * ONE CANONICAL IDENTIFIER FORM (design section 8): every identifier this module COMPARES or
 * places in the context (the scope's pool and contract, the income identity, the allocation
 * hash, every recipient, every journaled hash, the served reservation's three fields) is a
 * PRIMITIVE string of 64 lowercase hex characters, enforced at each `requireHex64` site, and
 * any other form is refused by name (base58, uppercase, a byte object, a boxed string), so the
 * self-share comparison, the planned-identifier derivation and the plan's allocation hash never
 * meet a mixed representation; a base58 income identity beside hex funders is a refusal, never
 * "no self-share". Two boundaries are outside that form by design: the generator's owner and
 * contract identifiers are the base58 strings the generator takes (the contract one must decode
 * to the scope's hex identifier, so the two are one contract in two forms), and the receipt's
 * and parts' served fields are lifted by name for the verifier to validate and are compared
 * to nothing here (a receipt whose pool or accrual field disagrees with the plan is
 * nonconforming evidence the kernel refuses on its fields, not a caller fault).
 *
 * EVERY CALLER INPUT IS READ ONCE, through its own data descriptor into a local, and an
 * accessor or an inherited member is refused without being invoked (the repository's rule
 * since the adapter and the identifier helper rounds). Arrays (the journal run, the
 * allocation, the parts documents, the supersessions) are captured element by element through
 * own descriptors, never through the caller's own map or iteration; the closure reads the
 * call's members the same way, before the capture lookup runs, and hands the verifier the
 * CONTEXT ROW's identity and amount rather than the call's members read again.
 *
 * THE VERDICT CLOSURE (design section 6, as built in step 2): `executionVerdictFor` binds a
 * context to a capture lookup and the verifier's dependencies and returns the function
 * acquisition awaits per served receipt. It looks up the journaled capture by the member's
 * PLANNED accrual identifier on EVERY call (it never caches, because the capture is outside
 * acquisition's applicability key by construction), normalizes the pinned reservation answer
 * through `reservationForVerifier`, lifts the receipt's and each part's named members from
 * the served fields, and calls `e2ReceiptVerify.verifyTransferExecution`, the one producer of
 * `CAPTURE-VERIFIED`, with the entitlement row taken from the CONTEXT ROW the member was
 * bound to, the income identity and the chain pin from the context (the run's pin and the
 * plan's chain are one value, so the pin is not a second input), and the verifier's five stage
 * functions plus the capture-basis adapter CAPTURED at construction into a frozen private
 * bundle, which is what every verification receives. A receipt for which the
 * lookup answers no capture reaches that function with a null capture and is REFUSED by it,
 * the design's conservative outcome; this module observes the absence of a local capture and
 * not who produced the record. A call that is not acquisition's (a member outside this
 * context's plan, a parts read whose status is not served, an accessor-backed member) is a
 * CALLER FAULT and
 * throws by name: acquisition calls only after the served identifier equals the planned one
 * and only over a served receipt and served parts (the pinned reservation may be unverified,
 * which the verifier leaves unproved), so any of those is a contract violation, never evidence
 * about the ledger.
 *
 * WHAT THIS MODULE DOES NOT ESTABLISH, stated: that the formation inputs are the PROVED
 * resolution (the caller's, the driver's `resolveProvedPool`); that the journal run is the
 * writer's own record (a TRUSTED LOCAL INPUT, design section 4, never external evidence); that
 * the declared fixture is anything but harness configuration; that the generator agrees with
 * what Platform assigns on creation (the acceptance stage's); that acquisition calls the
 * closure with copies (acquisition's own test); and nothing about the instrument (step 5), the
 * acceptance run (step 6), the driver's integration or the live run.
 */
"use strict";
const entitlementCalc = require("./entitlementCalc.cjs");
const docId = require("./e2DocId.cjs");
const formationCore = require("./formationCore.cjs");
const receiptVerify = require("./e2ReceiptVerify.cjs");

const refuse = (msg) => { throw new Error(`e2EpochContext: ${msg}; refusing`); };

const KIND = "tegara.e2.epochContext.v1";
const HEX64 = /^[0-9a-f]{64}$/;
const DEC_RE = /^(0|[1-9][0-9]*)$/;
const FIGURES_SOURCES = Object.freeze(["journaled-header", "declared-fixture", "epoch-object-unproved-c1"]);
const PRECONDITION_C1 = "UNPROVED_EPOCH_OBJECT_UNPROVED";
const SCOPE_KEYS = Object.freeze(["contractId", "chainId", "contractVersion", "poolId", "epochIndex"]);
// the verifier's receipt grammar, lifted by name from the served fields
const RECEIPT_MEMBERS = Object.freeze(["poolId", "accrualId", "transitionHash", "transitionBytes", "proofBytes",
  "proofPartCount", "metadataBytes", "blockHeight", "coreChainLockedHeight", "timeMs", "quorumHash", "round"]);
const PART_MEMBERS = Object.freeze(["poolId", "accrualId", "partIndex", "bytes"]);

const isPrimitiveString = (v) => typeof v === "string";
const isHex64 = (v) => isPrimitiveString(v) && HEX64.test(v);
const isDec = (v) => isPrimitiveString(v) && DEC_RE.test(v);
const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isObjectLike = (v) => v !== null && typeof v === "object";

const deepFreeze = (o, seen = new Set()) => {
  if (o === null || typeof o !== "object" || seen.has(o)) return o;
  seen.add(o);
  for (const k of Object.getOwnPropertyNames(o)) deepFreeze(o[k], seen);
  return Object.freeze(o);
};

// THE BRAND: module-private, so a `kind` string on an object literal proves nothing
const CONTEXT_BRAND = new WeakSet();

// ONE READ PER INPUT: each named member is taken from its OWN DATA descriptor into a local,
// so nothing is read twice and no accessor or inherited member is consulted
const takeOwnData = (input, name, where, required) => {
  const d = Object.getOwnPropertyDescriptor(input, name);
  if (!d) {
    if (required) refuse(`${where}.${name} is required as an own data member`);
    // an OPTIONAL member that is absent is undefined; one that is INHERITED is refused, since a
    // prototype-supplied value is not the caller's own statement (the second pass's finding)
    if (name in input) refuse(`${where}.${name} is inherited, not an own data member (an inherited member is refused without being read)`);
    return undefined;
  }
  if (!("value" in d)) refuse(`${where}.${name} must be an own DATA member, not an accessor (an accessor is refused without being invoked)`);
  return d.value;
};
const requireObject = (v, where) => {
  if (!isObjectLike(v) || Array.isArray(v)) refuse(`${where} must be an object`);
  return v;
};
// AN ARRAY IS CAPTURED ELEMENT BY ELEMENT THROUGH OWN DATA DESCRIPTORS, never through the
// caller's own iteration or map (an indexed accessor, an inherited index or an overridden
// map could otherwise substitute entries after the check); the length is read once
const captureArray = (raw, where) => {
  if (!Array.isArray(raw)) refuse(`${where} must be an array`);
  const ld = Object.getOwnPropertyDescriptor(raw, "length");
  const length = ld && "value" in ld ? ld.value : refuse(`${where} must carry its length as an own data member`);
  const out = [];
  for (let i = 0; i < length; i++) out.push(takeOwnData(raw, String(i), where, true));
  return out;
};
const describeForm = (v) => {
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return "a byte object";
  if (v instanceof String) return "a boxed string";
  return typeof v;
};
const requireHex64 = (v, where) => {
  if (!isPrimitiveString(v)) refuse(`${where} must be a primitive string of 64 lowercase hex (got ${describeForm(v)}); every identifier is carried in the one canonical form`);
  if (!HEX64.test(v)) refuse(`${where} must be 64 lowercase hex characters (got ${v.length} characters${/^[0-9a-fA-F]{64}$/.test(v) ? ", not all lowercase" : ""}); every identifier is carried in the one canonical form`);
  return v;
};
const requireDec = (v, where) => {
  if (!isDec(v)) refuse(`${where} must be a canonical decimal string (got ${typeof v})`);
  return v;
};

// ---- the inputs, captured ----

const captureScope = (raw) => {
  requireObject(raw, "scope");
  const s = {};
  for (const k of SCOPE_KEYS) s[k] = takeOwnData(raw, k, "scope", true);
  requireHex64(s.contractId, "scope.contractId");
  if (!isPrimitiveString(s.chainId) || s.chainId.length === 0) refuse("scope.chainId must be a non-empty primitive string (the chain pin)");
  if (s.contractVersion !== 11) refuse(`scope.contractVersion must be the literal 11 (got ${typeof s.contractVersion === "number" ? s.contractVersion : typeof s.contractVersion})`);
  requireHex64(s.poolId, "scope.poolId");
  if (!Number.isSafeInteger(s.epochIndex) || s.epochIndex < 0) refuse("scope.epochIndex must be a non-negative safe integer");
  return s;
};

const captureFormation = (raw) => {
  requireObject(raw, "formation");
  const resolved = takeOwnData(raw, "resolved", "formation", true);
  if (resolved !== true) refuse("formation.resolved must be the literal true, the caller's statement that this is the proved pool resolution (this module checks the statement, not the proof); a resolution not stated as proved is the caller's refusal, not a context");
  const incomeIdentity = requireHex64(takeOwnData(raw, "incomeIdentity", "formation", true), "formation.incomeIdentity");
  const allocationHash = requireHex64(takeOwnData(raw, "allocationHash", "formation", true), "formation.allocationHash");
  const rawAlloc = captureArray(takeOwnData(raw, "allocation", "formation", true), "formation.allocation");
  if (rawAlloc.length < 1) refuse("formation.allocation must be a non-empty array of { recipientId, bps }");
  const seen = new Set();
  const allocation = rawAlloc.map((row, i) => {
    requireObject(row, `formation.allocation[${i}]`);
    const recipientId = requireHex64(takeOwnData(row, "recipientId", `formation.allocation[${i}]`, true), `formation.allocation[${i}].recipientId`);
    const bps = takeOwnData(row, "bps", `formation.allocation[${i}]`, true);
    if (!Number.isSafeInteger(bps) || bps < 1 || bps > 10000) refuse(`formation.allocation[${i}].bps must be an integer in 1..10000 (the schema's domain)`);
    if (seen.has(recipientId)) refuse(`formation.allocation carries the recipient ${recipientId.slice(0, 8)}... twice`);
    seen.add(recipientId);
    return { recipientId, bps };
  });
  return { incomeIdentity, allocationHash, allocation };
};

const captureJournalRun = (raw) => {
  if (!Array.isArray(raw)) refuse("journalRun must be an array (runFromJournal's answer, the writer's own record; empty for a pool with no journaled header)");
  return captureArray(raw, "journalRun").map((e, i) => {
    requireObject(e, `journalRun[${i}]`);
    const where = `journalRun[${i}]`;
    const number = takeOwnData(e, "number", where, true);
    if (!Number.isSafeInteger(number) || number < 0) refuse(`${where}.number must be a non-negative safe integer`);
    const grossCredits = requireDec(takeOwnData(e, "grossCredits", where, true), `${where}.grossCredits`);
    const feeCredits = requireDec(takeOwnData(e, "feeCredits", where, true), `${where}.feeCredits`);
    const distributableCredits = requireDec(takeOwnData(e, "distributableCredits", where, true), `${where}.distributableCredits`);
    const allocationHash = requireHex64(takeOwnData(e, "allocationHash", where, true), `${where}.allocationHash`);
    const memberCount = takeOwnData(e, "memberCount", where, true);
    if (!Number.isSafeInteger(memberCount) || memberCount < 1) refuse(`${where}.memberCount must be a positive safe integer`);
    if (BigInt(feeCredits) > BigInt(grossCredits)) refuse(`${where} carries feeCredits above grossCredits`);
    if (BigInt(grossCredits) - BigInt(feeCredits) !== BigInt(distributableCredits)) refuse(`${where}.distributableCredits is not grossCredits minus feeCredits`);
    return { number, grossCredits, feeCredits, distributableCredits, allocationHash, memberCount };
  });
};

const captureDeclaredFigures = (raw) => {
  if (raw === null) return null;
  // the domain is null or a fixture, stated: an own undefined is a configuration that was
  // never set, not a decision that there is no fixture
  if (raw === undefined) refuse("declaredFigures must be null (no fixture) or { grossCredits, feeCredits }; undefined is a value nobody set");
  requireObject(raw, "declaredFigures");
  const grossCredits = requireDec(takeOwnData(raw, "grossCredits", "declaredFigures", true), "declaredFigures.grossCredits");
  const feeCredits = requireDec(takeOwnData(raw, "feeCredits", "declaredFigures", true), "declaredFigures.feeCredits");
  if (BigInt(feeCredits) > BigInt(grossCredits)) refuse("declaredFigures carries feeCredits above grossCredits; the distributable amount would be negative");
  return { grossCredits, feeCredits };
};

const captureIdentifiers = (raw, scope) => {
  requireObject(raw, "identifiers");
  const generateId = takeOwnData(raw, "generateId", "identifiers", true);
  const ownerId = takeOwnData(raw, "ownerId", "identifiers", true);
  const contractId = takeOwnData(raw, "contractId", "identifiers", true);
  if (typeof generateId !== "function") refuse("identifiers.generateId must be the injected identifier generator function");
  if (!isPrimitiveString(ownerId) || ownerId.length === 0) refuse("identifiers.ownerId must be a non-empty primitive string (the writer identity as the generator takes it)");
  if (!isPrimitiveString(contractId) || contractId.length === 0) refuse("identifiers.contractId must be a non-empty primitive string (the contract identifier as the generator takes it)");
  // the generator's contract and the scope's contract are ONE contract in two forms
  const decoded = formationCore.toId32(contractId);
  if (!decoded) refuse("identifiers.contractId does not decode to a 32-byte identifier");
  if (decoded.toString("hex") !== scope.contractId) {
    refuse(`identifiers.contractId decodes to ${decoded.toString("hex").slice(0, 12)}... while scope.contractId is ${scope.contractId.slice(0, 12)}...; the planned identifiers would be derived under a different contract than the plan is bound to`);
  }
  return { generateId, ownerId, contractId };
};

// the row source's refusal for an encoding-refused epoch, recognized by its own text for
// that condition (its `rowsFor` throws; the design's table names this as the source of
// `encodingRefused`); any other thrown value propagates
const ENCODING_REFUSAL = /^entitlementCalc: epoch \d+ cannot be answered: the run is encoding-refused from epoch \d+/;

/**
 * buildEpochContext({ scope, formation, journalRun, configuredStart, declaredFigures,
 *                     identifiers }) -> context
 *
 * scope            { contractId (64-hex), chainId, contractVersion: 11, poolId (64-hex),
 *                    epochIndex }
 * formation        { resolved: true, incomeIdentity (64-hex), allocationHash (64-hex, the
 *                    receipt's recomputed hash), allocation: [{ recipientId (64-hex), bps }] }
 *                  the PROVED pool resolution, identifiers converted at the boundary
 * journalRun       runFromJournal's array (number, grossCredits, feeCredits,
 *                  distributableCredits, allocationHash, memberCount), possibly empty
 * configuredStart  the run's configured start epoch
 * declaredFigures  null, or { grossCredits, feeCredits } from harness configuration
 * identifiers      { generateId, ownerId, contractId } as e2DocId's docIdForIn takes them
 */
const buildEpochContext = (input) => {
  if (!isPlain(input)) refuse("buildEpochContext takes one options object");
  const scope = captureScope(takeOwnData(input, "scope", "options", true));
  const formation = captureFormation(takeOwnData(input, "formation", "options", true));
  const journalRun = captureJournalRun(takeOwnData(input, "journalRun", "options", true));
  const configuredStart = takeOwnData(input, "configuredStart", "options", true);
  if (!Number.isSafeInteger(configuredStart) || configuredStart < 0) refuse("configuredStart must be a non-negative safe integer (the run's base, which the caller supplying the run knows)");
  const declared = captureDeclaredFigures(takeOwnData(input, "declaredFigures", "options", true));
  const identifiers = captureIdentifiers(takeOwnData(input, "identifiers", "options", true), scope);
  const { epochIndex, poolId } = scope;
  const memberCount = formation.allocation.length;

  // ---- the journaled run belongs to THIS formation, every entry of it, since every entry's
  // distributable amount enters the carry recursion under this allocation (the checker's
  // finding 2: a cross-check on the requested epoch alone let an earlier epoch's amount in
  // under a different membership) ----
  {
    const seenEpochs = new Set();
    for (const j of journalRun) {
      if (seenEpochs.has(j.number)) refuse(`journalRun carries epoch ${j.number} twice`);
      seenEpochs.add(j.number);
      if (j.allocationHash !== formation.allocationHash) {
        refuse(`epoch ${j.number}'s journaled header carries allocationHash ${j.allocationHash.slice(0, 12)}... while the proved formation's recomputed hash is ${formation.allocationHash.slice(0, 12)}...; one allocation is applied to the whole run`);
      }
      if (j.memberCount !== memberCount) {
        refuse(`epoch ${j.number}'s journaled header carries memberCount ${j.memberCount} while the proved formation's allocation has ${memberCount} rows; one allocation is applied to the whole run`);
      }
    }
  }

  // ---- the figures: declared or refused, never chosen (section 4) ----
  const journaled = journalRun.filter((e) => e.number === epochIndex);
  let figuresSource, figures = null, run;
  if (journaled.length === 1) {
    const j = journaled[0];
    if (declared !== null && (declared.grossCredits !== j.grossCredits || declared.feeCredits !== j.feeCredits)) {
      refuse(`epoch ${epochIndex}'s journaled header reads gross=${j.grossCredits} fee=${j.feeCredits} and the declared fixture reads gross=${declared.grossCredits} fee=${declared.feeCredits}; two sources for one epoch must agree field by field, and a disagreement is a refusal, never a choice`);
    }
    figuresSource = "journaled-header";
    figures = { grossCredits: j.grossCredits, feeCredits: j.feeCredits };
    run = journalRun;
  } else if (declared !== null) {
    const last = journalRun.length ? journalRun[journalRun.length - 1].number : null;
    const expectedNext = last === null ? configuredStart : last + 1;
    if (epochIndex !== expectedNext) {
      refuse(last === null
        ? `epoch ${epochIndex} is declared over an empty journaled run whose configured start is ${configuredStart}; the carry recursion's base is at the configured start and a declared epoch elsewhere has no carry-in to compute from`
        : `epoch ${epochIndex} does not immediately follow the journaled run's last epoch ${last}; the carry recursion folds every epoch's owed amount into the next, and a declared epoch beyond the next would skip amounts that never entered its carry-in`);
    }
    figuresSource = "declared-fixture";
    figures = { grossCredits: declared.grossCredits, feeCredits: declared.feeCredits };
    run = [...journalRun, { number: epochIndex,
      distributableCredits: String(BigInt(declared.grossCredits) - BigInt(declared.feeCredits)) }];
  } else {
    // rule 2: a figure obtained from an unproved epoch object IS NOT A FIGURES SOURCE
    const precondition = {
      code: PRECONDITION_C1,
      diagnostic: `epoch ${epochIndex} of pool ${poolId.slice(0, 12)}... has no journaled header numbers and no declared fixture; its only figures source would be the epoch object, which is consumed over a route that obtains no proof while open construction C1 stands, so no plan is built and no completion claim can be reached for this epoch`,
    };
    const ctx = deepFreeze({
      kind: KIND, scope, formation, figuresSource: "epoch-object-unproved-c1",
      figures: null, rows: null, encodingRefused: null, precondition,
    });
    CONTEXT_BRAND.add(ctx);
    return ctx;
  }

  // ---- the rows: the carry partition's own answers (section 3, step 3b) ----
  const calc = entitlementCalc.buildCarryCapableEntitlements({
    epochs: run.map((e) => ({ number: e.number, distributableCredits: e.distributableCredits })),
    allocation: formation.allocation.map((a) => ({ recipientId: a.recipientId, bps: a.bps })),
    incomeIdentity: formation.incomeIdentity,
    encodingCeiling: entitlementCalc.SCHEMA_CREDIT_CEILING,
    configuredStart,
  });
  let partitionRows = null;
  let encodingRefused = false;
  try { partitionRows = calc.rowsFor(epochIndex); }
  catch (e) {
    if (e instanceof Error && ENCODING_REFUSAL.test(e.message)) encodingRefused = true;
    else throw e;
  }
  const plannedIdOf = (funderId) => docId.docIdForIn({
    generateId: identifiers.generateId, ownerId: identifiers.ownerId, contractId: identifiers.contractId,
    poolId, epochIndex, type: "platformAccrual", subject: funderId }).hex;
  let rows;
  if (encodingRefused) {
    rows = formation.allocation.map((a) => ({
      funderId: a.recipientId, shareBps: a.bps, isSelfShare: a.recipientId === formation.incomeIdentity,
      plannedAccrualId: plannedIdOf(a.recipientId) }));
  } else {
    if (partitionRows.length !== memberCount) refuse(`internal: the row source answered ${partitionRows.length} rows for ${memberCount} allocation rows`);
    rows = partitionRows.map((r, i) => {
      const a = formation.allocation[i];
      if (r.recipientId !== a.recipientId) refuse(`internal: the row source's row ${i} is for ${String(r.recipientId).slice(0, 8)}... while the allocation row is ${a.recipientId.slice(0, 8)}...`);
      if (typeof r.isSelfShare !== "boolean" || typeof r.payable !== "boolean") refuse(`internal: the row source's row ${i} carries no strict-boolean partition answers`);
      if (!isDec(r.amountCredits)) refuse(`internal: the row source's row ${i} carries no canonical decimal amount`);
      return { funderId: r.recipientId, effectiveCredits: r.amountCredits, shareBps: a.bps,
        isSelfShare: r.isSelfShare, payable: r.payable,
        ...(r.carryInCredits === undefined ? {} : { carryInCredits: r.carryInCredits }),
        plannedAccrualId: plannedIdOf(r.recipientId) };
    });
  }

  const ctx = deepFreeze({
    kind: KIND, scope, formation, figuresSource,
    figures: { grossCredits: figures.grossCredits, feeCredits: figures.feeCredits, memberCount, calcVersion: 1,
      allocationHash: formation.allocationHash },
    rows, encodingRefused, precondition: null,
  });
  CONTEXT_BRAND.add(ctx);
  return ctx;
};

const requireContext = (ctx, fnName) => {
  if (!isPlain(ctx) || !CONTEXT_BRAND.has(ctx)) refuse(`${fnName} accepts only a context from buildEpochContext; a kind string on an object literal proves nothing`);
};

/**
 * planInputOf(ctx) -> { scope, encodingRefused, header, members }, the kernel's
 * buildExpectedRecordPlan input, a FRESH plain object per call. REFUSES a precondition
 * context by name (design section 5, stage 1), so no plan is built from an unproved figure.
 */
const planInputOf = (ctx) => {
  requireContext(ctx, "planInputOf");
  if (ctx.precondition !== null) {
    refuse(`this context carries the precondition ${ctx.precondition.code} and reaches no plan builder; the orchestrator stores unprovedPrecondition(...) for epoch ${ctx.scope.epochIndex} instead (${ctx.precondition.diagnostic})`);
  }
  const scope = { ...ctx.scope };
  if (ctx.encodingRefused) {
    return { scope, encodingRefused: true, header: null,
      // the plan grammar's placeholder, never read on the kernel's encoding-refused path
      members: ctx.rows.map((r) => ({ funderId: r.funderId, plannedAccrualId: r.plannedAccrualId,
        effectiveCredits: "0", shareBps: r.shareBps, isSelfShare: r.isSelfShare, payable: false })) };
  }
  return { scope, encodingRefused: false,
    header: { grossCredits: ctx.figures.grossCredits, feeCredits: ctx.figures.feeCredits,
      memberCount: ctx.figures.memberCount, calcVersion: 1, allocationHash: ctx.figures.allocationHash },
    members: ctx.rows.map((r) => ({ funderId: r.funderId, plannedAccrualId: r.plannedAccrualId,
      effectiveCredits: r.effectiveCredits, shareBps: r.shareBps, isSelfShare: r.isSelfShare, payable: r.payable })) };
};

/**
 * reservationForVerifier(answer) -> the verifier's ONE reservation shape (e2ReceiptVerify,
 * verifyReceipt): a served pinned answer maps to { status: "served", doc: { poolId,
 * accrualId, transitionHash } } with exactly those three lifted from the answer's fields, a
 * proved-absence answer to { status: "proved-absence" }, and unserved or unverified to
 * { status: "unserved" } (leaving the reservation aspect unproved, as the verifier specifies).
 * Any other status, or a served answer whose three fields are not canonical, is refused.
 */
const reservationForVerifier = (answer) => {
  requireObject(answer, "the reservation answer");
  const status = takeOwnData(answer, "status", "the reservation answer", true);
  if (status === "served") {
    const fields = takeOwnData(answer, "fields", "the reservation answer", true);
    requireObject(fields, "the served reservation answer's fields");
    const doc = {};
    for (const k of ["poolId", "accrualId", "transitionHash"]) {
      doc[k] = requireHex64(takeOwnData(fields, k, "the served reservation answer's fields", true), `the served reservation answer's fields.${k}`);
    }
    return { status: "served", doc };
  }
  if (status === "proved-absence") return { status: "proved-absence" };
  if (status === "unserved" || status === "unverified") return { status: "unserved" };
  refuse(`the reservation answer's status must be served, proved-absence, unserved or unverified (got ${typeof status === "string" ? JSON.stringify(status) : typeof status})`);
};

// the verifier's own dependency list (e2ReceiptVerify.cjs, verifyReceiptInner's first check),
// required here at construction so a misconfigured run stops before any read rather than at
// the first served receipt, or never, when no capture is found first
const VERIFIER_DEPS = Object.freeze(["decodeProofCarrier", "decodeMetadata", "decodeTransfer", "verifyStageOne", "verifyStageTwo"]);

/**
 * executionVerdictFor(ctx, { captureFor, deps }) -> async (call) => verdict
 *
 * captureFor(plannedAccrualId) -> null | { capture, supersessions }: the orchestrator's lookup
 *   into ITS OWN journal for the receipt capture written under that accrual, with the
 *   capture's supersession records; consulted on every call, never cached here.
 * deps        { verifierDeps, verifyCaptureBasis }, exactly the audit's two, the verifier's five
 *             stage functions present.
 * The chain pin the verifier takes is the context's own scope.chainId: the run's pin and the
 * plan's chain are one value (the checker's finding 3), so it is not a second input.
 */
const executionVerdictFor = (ctx, options) => {
  requireContext(ctx, "executionVerdictFor");
  if (ctx.precondition !== null) refuse(`executionVerdictFor: a precondition context (${ctx.precondition.code}) builds no plan, so no verdict is owed for it`);
  if (ctx.encodingRefused === true) refuse("executionVerdictFor: an encoding-refused context expects no records, acquisition reads no receipt under its plan, and no verdict is owed for it");
  if (!isPlain(options)) refuse("executionVerdictFor takes an options object { captureFor, deps }");
  const captureFor = takeOwnData(options, "captureFor", "options", true);
  const rawDeps = takeOwnData(options, "deps", "options", true);
  if (typeof captureFor !== "function") refuse("executionVerdictFor needs captureFor, the orchestrator's journal lookup by planned accrual identifier");
  if (!isPlain(rawDeps)) refuse("executionVerdictFor needs deps { verifierDeps, verifyCaptureBasis } (the verifier's proof stages and the capture-basis adapter), checked before any read so a misconfigured run stops before it starts");
  // THE DEPENDENCIES ARE CAPTURED, not retained by reference (the second pass's finding): each
  // named function is read once through its own data descriptor into a frozen private bundle,
  // and that bundle is what the verifier receives, so a bundle altered after construction, an
  // accessor-backed member or an inherited stage function cannot reach a verification
  const rawVerifierDeps = takeOwnData(rawDeps, "verifierDeps", "options.deps", true);
  const verifyCaptureBasis = takeOwnData(rawDeps, "verifyCaptureBasis", "options.deps", true);
  if (!isPlain(rawVerifierDeps)) refuse("executionVerdictFor needs deps.verifierDeps as a plain object carrying the verifier's five stage functions, checked before any read");
  if (typeof verifyCaptureBasis !== "function") refuse("executionVerdictFor needs deps.verifyCaptureBasis as a function (the capture-basis adapter), checked before any read");
  const verifierDeps = {};
  for (const k of VERIFIER_DEPS) {
    const f = takeOwnData(rawVerifierDeps, k, "options.deps.verifierDeps", true);
    if (typeof f !== "function") refuse(`executionVerdictFor needs deps.verifierDeps.${k} as a function (the verifier's pipeline is incomplete), checked before any read`);
    verifierDeps[k] = f;
  }
  const deps = Object.freeze({ verifierDeps: Object.freeze(verifierDeps), verifyCaptureBasis });
  const rowByFunder = new Map(ctx.rows.map((r) => [r.funderId, r]));
  const { incomeIdentity } = ctx.formation;
  const { chainId: chainIdPin } = ctx.scope;

  return async (call) => {
    if (!isPlain(call)) refuse("the execution verdict takes one plain call object { member, receipt, parts, reservation } (a caller fault, never evidence)");
    // EVERY CALL MEMBER IS READ ONCE INTO A LOCAL BEFORE THE LOOKUP RUNS, and the verifier is
    // handed THE CONTEXT ROW's identity, planned identifier and amount, never the call's
    // members read again (the checker's finding 1: a lookup that altered the call object
    // between the check and the verifier call could otherwise change the entitlement row)
    const member = takeOwnData(call, "member", "the call", true);
    const receipt = takeOwnData(call, "receipt", "the call", true);
    const parts = takeOwnData(call, "parts", "the call", true);
    const reservation = takeOwnData(call, "reservation", "the call", true);
    if (!isPlain(member)) refuse("the call's member must be a plain object (a caller fault)");
    const funderId = takeOwnData(member, "funderId", "the call's member", true);
    const plannedAccrualId = takeOwnData(member, "plannedAccrualId", "the call's member", true);
    const effectiveCredits = takeOwnData(member, "effectiveCredits", "the call's member", true);
    if (!isHex64(funderId) || !isHex64(plannedAccrualId) || !isDec(effectiveCredits)) {
      refuse("the call's member must carry a 64-hex funderId, a 64-hex plannedAccrualId and a canonical decimal effectiveCredits (a caller fault)");
    }
    const row = rowByFunder.get(funderId);
    if (!row || row.plannedAccrualId !== plannedAccrualId) {
      refuse(`the call is for funder ${funderId.slice(0, 8)}... under planned accrual ${plannedAccrualId.slice(0, 8)}..., which is not a member of this context's plan for epoch ${ctx.scope.epochIndex} (a caller fault)`);
    }
    if (row.effectiveCredits !== effectiveCredits) {
      refuse(`the call's member carries effectiveCredits ${effectiveCredits} while this context's row carries ${row.effectiveCredits} (a caller fault)`);
    }
    if (!isPlain(receipt)) refuse("the call's receipt must be { documentId, fields } with plain fields (a caller fault)");
    const rf = takeOwnData(receipt, "fields", "the call's receipt", true);
    if (!isPlain(rf)) refuse("the call's receipt must be { documentId, fields } with plain fields (a caller fault)");
    const receiptForVerifier = {};
    for (const k of RECEIPT_MEMBERS) receiptForVerifier[k] = takeOwnData(rf, k, "the call's receipt fields", false);
    // NO SERVED RECEIPT FIELD IS COMPARED HERE (the repository-access rounds' findings, the
    // pool first and then its sibling the accrual): acquisition queries receipts by accrual
    // alone (a soundness-review finding) and its stage-3 guarantee is about the ACCRUAL DOCUMENT's identifier,
    // not the receipt's fields, so a receipt whose pool or accrual field disagrees with the
    // plan is NONCONFORMING EVIDENCE the kernel refuses on its fields
    // (REFUSED_NONCONFORMING_ANSWER) and the verifier refuses against the capture, never a
    // caller fault. The relational checks are the kernel's (design section 6). Every lifted
    // member is the verifier's to validate, and the lookup below is keyed by the CONTEXT
    // ROW's planned identifier, never by a served field.
    if (!isPlain(parts)) refuse("the call's parts read is not a served document set; acquisition does not request a verdict over unresolved evidence, so this is a caller fault and never a verdict");
    const partsStatus = takeOwnData(parts, "status", "the call's parts", true);
    const partDocs = takeOwnData(parts, "documents", "the call's parts", true);
    if (partsStatus !== "served" || !Array.isArray(partDocs)) {
      refuse("the call's parts read is not a served document set; acquisition does not request a verdict over unresolved evidence, so this is a caller fault and never a verdict");
    }
    const partsForVerifier = captureArray(partDocs, "the call's parts.documents").map((d, i) => {
      if (!isPlain(d)) refuse(`the call's parts.documents[${i}] must be { documentId, fields } with plain fields (a caller fault)`);
      const df = takeOwnData(d, "fields", `the call's parts.documents[${i}]`, true);
      if (!isPlain(df)) refuse(`the call's parts.documents[${i}] must be { documentId, fields } with plain fields (a caller fault)`);
      const p = {};
      for (const k of PART_MEMBERS) p[k] = takeOwnData(df, k, `the call's parts.documents[${i}].fields`, false);
      return p;
    });
    const reservationForVerdict = reservationForVerifier(reservation);
    // THE CAPTURE IS LOOKED UP ON EVERY CALL, never cached: it is outside acquisition's
    // applicability key by construction, and the journal may gain the record between calls.
    // The key is the CONTEXT ROW's planned identifier, equal to the call's by the check above.
    const found = captureFor(row.plannedAccrualId);
    let capture = null, supersessions = [];
    if (found !== null) {
      if (!isPlain(found)) refuse("captureFor must answer null (no capture) or { capture, supersessions: [...] }; undefined is a lookup that returned nothing (a caller fault)");
      const c = takeOwnData(found, "capture", "the captureFor answer", true);
      const s = takeOwnData(found, "supersessions", "the captureFor answer", true);
      if (!isPlain(c) || !Array.isArray(s)) refuse("captureFor must answer null or { capture, supersessions: [...] } (a caller fault)");
      capture = c;
      supersessions = captureArray(s, "the captureFor answer's supersessions");
    }
    return receiptVerify.verifyTransferExecution({
      receipt: receiptForVerifier, parts: partsForVerifier, reservation: reservationForVerdict,
      capture, supersessions,
      entitlementRow: { recipientId: row.funderId, amountCredits: row.effectiveCredits },
      incomeIdentity, chainIdPin, deps,
    });
  };
};

module.exports = { KIND, FIGURES_SOURCES, VERIFIER_DEPS, buildEpochContext, planInputOf, reservationForVerifier, executionVerdictFor };
