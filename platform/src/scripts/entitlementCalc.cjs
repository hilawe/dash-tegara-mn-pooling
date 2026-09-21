/**
 * entitlementCalc - the per-epoch entitlement calculation, as the two rules it is made
 * of, so that the audit's recomputation and the writer's row source consume ONE of each
 * instead of carrying their own.
 *
 * TWO EXPORTS, TWO RULES.
 *
 * `splitOwed` is the ALLOCATION SPLIT: the shape rules for an allocation row set, the
 * floor division that turns a distributable amount into per-member owed amounts, the
 * `amountCredits` encoding refusal, and the remainder the split leaves behind. It was
 * living in three places when this module was written: inside e2Audit's
 * `computeNormativeEpoch`, and twice inline in the harness driver, the second of those
 * under a comment saying its arithmetic "mirrors" the audit's. Mirrored arithmetic is
 * the thing this export exists to end.
 *
 * `buildCarryCapableEntitlements` is the CARRY-CAPABLE ROW SOURCE the multi-epoch driver
 * injects as `deps.entitlementsForEpoch`. It threads epochCarry's recursion across an
 * ordered run of epochs and answers each one's EFFECTIVE rows (owed plus carry-in). It
 * implements no carry rule of its own: every deferral decision is epochCarry's.
 *
 * WHAT THIS MODULE DOES NOT OWN.
 *
 * - THE EPOCH'S GROSS AND FEE. `splitOwed` takes the distributable amount already
 *   computed. The audit derives it from the epoch object through the normative
 *   calculation; the writer takes it from the header numbers it committed to. Those are
 *   genuinely different entry points into the same split, which is why the split is what
 *   is shared and the derivation is not.
 * - DOCUMENT IDENTITY. Rows come back keyed by `recipientId`. The driver attaches its own
 *   deterministic `accrualId`, exactly as epochCarry leaves identity normalization to its
 *   callers.
 * - THE CARRY RULE. epochCarry owns it, including the trust boundary stated in its header,
 *   which this module inherits in full and adds one item to (see below).
 */
"use strict";

const { emptyCarryState, advanceEpoch } = require("./epochCarry.cjs");

/**
 * THE SCHEMA'S CREDIT CEILING, declared once here because it was about to be a third
 * copy. contractV11 declares `maximum: 9007199254740991` for grossCredits, feeCredits
 * and amountCredits alike, and this is that value. It is EXPORTED rather than assumed:
 * every entry point below still takes `encodingCeiling` as a REQUIRED argument, so this
 * module never quietly supplies a ceiling of its own, and a caller says which one it
 * means. The suite binds this constant to what contractV11 actually declares, so a
 * schema change that moved the maximum would fail there rather than here.
 */
const SCHEMA_CREDIT_CEILING = 9007199254740991n;

const refuse = (msg) => { throw new Error(`entitlementCalc: ${msg}`); };

const isBig = (v) => typeof v === "bigint";
/**
 * A PRIMITIVE 64-hex string, with the type checked BEFORE the pattern. A regular
 * expression coerces its argument, so `new String("aa...")` matches while `===` against
 * the primitive of the same text is false: the income identity would stop recognizing its
 * own row, which then carries, and two distinct boxed objects holding identical text would
 * both pass a Set-based uniqueness check because object identity differs. Both are
 * failures of the one-row-per-member property the comparisons here rest on.
 */
const isHex64 = (v) => typeof v === "string" && HEX64.test(v);
const DEC = /^(?:0|[1-9][0-9]*)$/;
const HEX64 = /^[0-9a-f]{64}$/;

/** A NON-NEGATIVE INTEGER quantity, accepted as a canonical decimal string or a BigInt and
 *  NEVER as a Number, which above 2^53 arrives already rounded and would be converted
 *  without refusal (the normative calculation's own rule, kept here because this module
 *  reads the same quantities from a different source). It enforces the FORM and the sign,
 *  not an upper bound: the ceiling check downstream is what bounds the value, and calling
 *  this a u64 domain would claim a range nothing here applies. */
/**
 * THE CEILING IS NOT CALLER-SELECTABLE, it is only caller-STATED. The argument stays
 * required so every call site says which ceiling it means, and this refuses any value
 * that is not the schema's. Before this check a caller could pass a larger positive
 * BigInt and receive amounts the schema rejects, with nothing in the result recording
 * which ceiling produced them, and the audit's fixed literal had permitted no such
 * opt-out. Naming a ceiling is a caller's job; choosing a different one is not.
 */
const assertSchemaCeiling = (encodingCeiling) => {
  if (typeof encodingCeiling !== "bigint" || encodingCeiling <= 0n) {
    refuse("encodingCeiling must be a positive BigInt (the schema's amountCredits ceiling)");
  }
  if (encodingCeiling !== SCHEMA_CREDIT_CEILING) {
    refuse(`encodingCeiling ${encodingCeiling} is not the schema's credit ceiling ${SCHEMA_CREDIT_CEILING}; a different ceiling would encode amounts the contract refuses`);
  }
};

const bigOf = (name, v) => {
  if (isBig(v)) return v;
  if (typeof v === "string" && DEC.test(v)) return BigInt(v);
  refuse(`${name} must be a canonical decimal string or BigInt (a Number may arrive already rounded)`);
};

/**
 * THE ALLOCATION SHAPE, one predicate for every reader of an allocation row set. The
 * bounds are the direct co-owner tier's: 1 to 8 rows, each an OWN enumerable element
 * carrying an OWN integer `bps` in 1..10000, summing to exactly 10000. Own-property
 * descriptors rather than plain reads, because an inherited or accessor `bps` is not a
 * value this calculation may spend.
 */
const readAllocationBps = (rows) => {
  if (!Array.isArray(rows)) {
    refuse("the allocation rows must number 1..8 (the direct co-owner tier's bound)");
  }
  // SNAPSHOT BEFORE COUNTING. `length` is read from the caller, and a Proxy can answer 2
  // to the bounds check and 1 to the loop, so the second allocation row is dropped while
  // the remaining row's 10000 basis points still sum correctly and every check passes.
  // The descriptors are then read from this array, whose length nothing else can move.
  const materialized = Array.prototype.slice.call(rows);
  if (materialized.length < 1 || materialized.length > 8) {
    refuse("the allocation rows must number 1..8 (the direct co-owner tier's bound)");
  }
  let bpsSum = 0;
  const rowBps = [];
  for (let i = 0; i < materialized.length; i++) {
    const rd = Object.getOwnPropertyDescriptor(materialized, i);
    if (!rd || !("value" in rd) || !rd.enumerable) {
      refuse(`allocation row ${i} must be an own enumerable data element`);
    }
    const row = rd.value;
    const bd = row && typeof row === "object" ? Object.getOwnPropertyDescriptor(row, "bps") : null;
    if (!bd || !("value" in bd) || !Number.isSafeInteger(bd.value) || bd.value < 1 || bd.value > 10000) {
      refuse("every allocation row needs an OWN integer bps 1..10000 (inherited or accessor members do not count)");
    }
    rowBps.push(bd.value);
    bpsSum += bd.value;
  }
  if (bpsSum !== 10000) refuse(`the allocation bps sum ${bpsSum} is not exactly 10000`);
  return rowBps;
};

/**
 * The same bounds as readAllocationBps, over an already-materialized vector. splitOwed
 * validates what it is handed rather than trusting the caller to have validated it, so a
 * direct caller gets the same rule the audit's path gets.
 */
const assertBpsVector = (rowBps) => {
  if (!Array.isArray(rowBps) || rowBps.length < 1 || rowBps.length > 8) {
    refuse("the allocation rows must number 1..8 (the direct co-owner tier's bound)");
  }
  let sum = 0;
  for (const bps of rowBps) {
    if (!Number.isSafeInteger(bps) || bps < 1 || bps > 10000) {
      refuse("every allocation row needs an OWN integer bps 1..10000 (inherited or accessor members do not count)");
    }
    sum += bps;
  }
  if (sum !== 10000) refuse(`the allocation bps sum ${sum} is not exactly 10000`);
};

/**
 * Split a distributable amount across the allocation, by floor division in BigInt
 * throughout. Returns { owed, remainder, encodingRefused }.
 *
 *   distributableCredits : D, the amount left after the operator fee, as a canonical
 *                          decimal string or BigInt
 *   rowBps               : the ALREADY-READ basis points, from readAllocationBps. It
 *                          takes the materialized vector rather than the allocation rows
 *                          ON PURPOSE: the rows are read through own-property descriptors
 *                          precisely because they are not trusted, and a second read
 *                          would let a row answer 5000 to the caller that reports the
 *                          split and 6000 to the one that computes it. One read, one
 *                          answer, and the vector cannot change between them
 *   encodingCeiling      : the schema's credit ceiling, stated by the caller and checked
 *
 * The REMAINDER is what floor division leaves undistributed, D minus the sum of the owed
 * amounts. It is reported rather than assigned, because assigning it is a policy this
 * calculation does not hold.
 *
 * An owed amount above the ceiling is REPORTED rather than thrown, because both readers
 * have their own handling for it. IT IS DEFENSIVE RATHER THAN REACHABLE FROM A VALID
 * RECORD: with basis points summing to 10000 every owed amount is at most the
 * distributable amount, and a schema-valid gross and fee put that at or below the
 * ceiling, so no conforming epoch header can produce one. The tests reach it by supplying
 * a distributable amount above the ceiling directly, which the module accepts and this
 * comment does not pretend is a record the format can hold. THE CARRY STEP'S refusal is
 * the one reachable in the real domain, since a valid owed amount plus a prior deferral
 * can cross the ceiling.
 */
const splitOwed = ({ distributableCredits, rowBps, encodingCeiling }) => {
  const D = bigOf("distributableCredits", distributableCredits);
  if (D < 0n) refuse(`distributableCredits ${D} is negative`);
  assertSchemaCeiling(encodingCeiling);
  // COPY FIRST, THEN VALIDATE THE COPY AND COMPUTE FROM IT. `Array.isArray` is true of a
  // Proxy over an array and of an array carrying numeric accessors, either of which can
  // answer 5000 to the validation pass and 10000 to the arithmetic, passing the sum check
  // and then paying out twice the distributable amount. One read per element, into a
  // plain array nothing else holds, is what makes "the vector cannot change between them"
  // a property rather than a hope.
  if (!Array.isArray(rowBps)) refuse("the allocation rows must number 1..8 (the direct co-owner tier's bound)");
  const bps = Array.from(rowBps);
  assertBpsVector(bps);
  const owed = bps.map((b) => (D * BigInt(b)) / 10000n);
  const over = owed.find((o) => o > encodingCeiling);
  if (over !== undefined) {
    return { owed: null, remainder: null,
      encodingRefused: { field: "amountCredits", value: String(over) } };
  }
  return { owed, remainder: D - owed.reduce((a, b) => a + b, 0n), encodingRefused: null };
};

/**
 * Build the carry-capable row source for an ordered run of epochs.
 *
 *   epochs          : [{ number, distributableCredits }], STRICTLY ASCENDING and
 *                     CONTIGUOUS in the sense that matters, namely that the first entry
 *                     is the configured start. The recursion's base is zero carry-in
 *                     there, so a list beginning anywhere else computes every later
 *                     epoch's effective amounts from a carry-in it never established
 *   allocation      : [{ recipientId, bps }], one row per member, recipientId 64 lowercase
 *                     hex and unique
 *   incomeIdentity  : the pool's income identity, 64 lowercase hex; its own row is the
 *                     self-share and never carries
 *   encodingCeiling : the schema's amountCredits ceiling, as a BigInt
 *
 * Returns { rowsFor(epochNumber), epochNumbers }.
 *
 * `rowsFor` answers one epoch's EFFECTIVE rows, in allocation order, each carrying
 * `recipientId`, `amountCredits` (the effective amount as a canonical decimal string),
 * `isSelfShare` and `payable` (strict booleans, THE CARRY PARTITION'S OWN ANSWERS,
 * surfaced since the per-epoch context design's step 3b so that the forward plan
 * builder takes the partition's classification rather than re-deriving it)
 * and, WHEN IT IS NONZERO, `carryInCredits`. Omitting a zero carry-in is not a
 * convenience: the build spec's migration rule reads an omitted member as the pre-carry
 * shape, under which its two-value resume comparison degenerates to the exact
 * single-value one, so a calculation that emitted "0" everywhere would widen that
 * comparison for every row that never carried anything.
 *
 * IT REFUSES RATHER THAN ANSWERING for an epoch outside the run, and for the
 * encoding-refused epoch and every epoch AFTER it. Epochs BELOW the refusal still answer,
 * their amounts having been computed before the run met it. THE SECOND IS FAIL-CLOSED AND DELIBERATE:
 * the writer has no handling for an encoding-refused epoch anywhere in its flow, so
 * answering one with rows would hand it a set it cannot correctly act on, while answering
 * with an empty set would read as an epoch that owes nobody anything. A refusal is the
 * only one of the three that cannot be mistaken for an answer.
 *
 * THE TRUST BOUNDARY IS epochCarry's, INHERITED IN FULL, plus one item of this module's
 * own: the `distributableCredits` are the amounts actually committed for those epochs.
 * Nothing here can check that. THE RUN'S BASE IS NO LONGER ON THIS LIST: `configuredStart`
 * is a required argument and the first epoch is checked against it, because the caller
 * supplying the run is the one caller who knows that number.
 */
const buildCarryCapableEntitlements = ({ epochs, allocation, incomeIdentity,
  encodingCeiling, configuredStart }) => {
  if (!isHex64(incomeIdentity)) {
    refuse("incomeIdentity must be a primitive 64 lowercase hex string (the self-share comparison's input)");
  }
  if (!Array.isArray(epochs) || epochs.length < 1) refuse("epochs must be a non-empty array");
  if (!Array.isArray(allocation)) refuse("allocation must be an array");

  // EVERY VALIDATED VALUE IS READ EXACTLY ONCE, INTO A SNAPSHOT NOTHING ELSE HOLDS, and
  // all later work reads the snapshot. Validating the caller's objects and then reading
  // them again lets a getter or a Proxy answer one thing to the check and another to the
  // calculation: an epoch whose `number` says 6 while being validated and 7 while being
  // stored passes the consecutive check and populates the wrong epoch, and two allocation
  // rows answering distinct recipients to the uniqueness check and the same one afterwards
  // hand the recursion duplicate member keys. The whole point of reading `bps` through an
  // own-property descriptor is that these objects are not trusted, and a second read gives
  // the trust straight back.
  const rawRows = Array.from(allocation);
  const rowBps = readAllocationBps(rawRows);   // the one descriptor read
  const seen = new Set();
  const alloc = rawRows.map((a, i) => {
    if (!a || typeof a !== "object") refuse(`allocation row ${i} must be an object`);
    const recipientId = a.recipientId;         // the one read of this member
    if (!isHex64(recipientId)) {
      refuse(`allocation row ${i} needs a recipientId that is a primitive string of 64 lowercase hex`);
    }
    if (seen.has(recipientId)) {
      refuse(`two allocation rows share the recipient ${recipientId.slice(0, 8)}...; the per-member minimum comparison is only sound under one row per member per epoch`);
    }
    seen.add(recipientId);
    return { recipientId, bps: rowBps[i], isSelfShare: recipientId === incomeIdentity };
  });

  const run = Array.from(epochs, (e, i) => {
    if (!e || typeof e !== "object") refuse(`epoch entry ${i} must be an object`);
    return { number: e.number, distributableCredits: e.distributableCredits };
  });

  // THE RUN BEGINS AT THE CONFIGURED START, enforced rather than stated. The recursion's
  // base is zero carry-in there, so a run beginning anywhere else computes every epoch
  // from a carry-in it never established, and answers with rows that look ordinary. It
  // was a line in the trust boundary below until a review pointed out that the caller
  // supplying the run is exactly the caller who knows this number.
  if (!Number.isSafeInteger(configuredStart) || configuredStart < 0) {
    refuse("configuredStart must be a safe non-negative integer: the run's first epoch is checked against it, because the recursion's base case lives there");
  }

  let prev = null;
  for (let i = 0; i < run.length; i++) {
    const e = run[i];
    if (!Number.isSafeInteger(e.number) || e.number < 0) {
      refuse(`epoch entry ${i} needs a safe non-negative integer number`);
    }
    if (i === 0 && e.number !== configuredStart) {
      refuse(`the run begins at epoch ${e.number} but the configured start is ${configuredStart}; every earlier epoch's owed amount would be missing from the carry this run computes`);
    }
    // CONSECUTIVE, not merely ascending. A gap is not an ordering nicety: the recursion
    // folds EVERY epoch's owed amount into the next epoch's carry-in, so a run of [5, 7]
    // would apply epoch 5's carry to epoch 7 having never added epoch 6's owed amount to
    // it, and answer with effective rows that are simply wrong. Ascending alone accepted
    // exactly that. The audit's own recomputation walks its interval one epoch at a time
    // for the same reason.
    if (prev !== null && e.number !== prev + 1) {
      refuse(`epoch ${e.number} does not immediately follow ${prev}; the run must be consecutive, because the recursion folds every epoch's owed amount into the next epoch's carry-in and a skipped epoch's amount would simply be lost`);
    }
    prev = e.number;
  }
  const epochNumbers = run.map((e) => e.number);   // from the snapshot, never re-read

  // ONE PASS, at build time, so every answer comes from one threading of the recursion
  // rather than from a fresh one per call. A per-call re-derivation would be equivalent
  // only for as long as nobody made it stateful, and this way there is nothing to keep
  // equivalent.
  const byEpoch = new Map();
  let carry = emptyCarryState();
  let refusedAt = null;
  let refusedBy = null;
  for (const e of run) {
    if (refusedAt !== null) {
      // once the run is refused it stays refused: every later epoch's effective amounts
      // depend on a carry state the refused epoch's own owed values never entered
      byEpoch.set(e.number, { refusedAt, refusedBy });
      continue;
    }
    const split = splitOwed({ distributableCredits: e.distributableCredits,
      rowBps, encodingCeiling });
    if (split.encodingRefused !== null) {
      refusedAt = e.number; refusedBy = "owed";
      byEpoch.set(e.number, { refusedAt, refusedBy });
      continue;
    }
    const step = advanceEpoch({
      carryIn: carry,
      encodingCeiling,
      owedRefused: false,
      members: alloc.map((a, i) => ({
        key: a.recipientId, isSelfShare: a.isSelfShare, owedCredits: split.owed[i],
      })),
    });
    if (step.kind === "encoding-refused") {
      // WHICH VALUE REFUSED IS NOT COSMETIC: an epoch whose OWED amounts are each
      // encodable can still refuse because a prior deferral pushes the EFFECTIVE amount
      // over, and a message blaming the owed amounts would send a reader looking at
      // figures that are within the ceiling
      refusedAt = e.number; refusedBy = "effective";
      byEpoch.set(e.number, { refusedAt, refusedBy });
      continue;
    }
    byEpoch.set(e.number, {
      refusedAt: null, refusedBy: null,
      rows: alloc.map((a, i) => {
        const carryIn = carry.get(a.recipientId) || 0n;
        // THE CARRY PARTITION'S OWN ANSWERS TRAVEL ON THE ROW (the per-epoch context
        // design, step 3b; contract section 3.1): `payable` is epochCarry's partition
        // for this member and `isSelfShare` the comparison the row was built with, so
        // the plan builder takes the partition's answer rather than a second
        // derivation of the same rule
        return { recipientId: a.recipientId,
          amountCredits: String(step.effective[i]),
          isSelfShare: a.isSelfShare,
          payable: step.payable[i],
          ...(carryIn === 0n ? {} : { carryInCredits: String(carryIn) }) };
      }),
    });
    carry = step.carryOut;
  }

  return {
    epochNumbers,
    rowsFor: (epochNumber) => {
      const hit = byEpoch.get(epochNumber);
      if (hit === undefined) {
        refuse(`epoch ${epochNumber} is outside this run (${epochNumbers[0]}..${epochNumbers[epochNumbers.length - 1]}); its effective entitlements were never computed and answering from a carry state that never reached it would be a guess`);
      }
      if (hit.refusedAt !== null) {
        refuse(`epoch ${epochNumber} cannot be answered: the run is encoding-refused from epoch ${hit.refusedAt}, whose ${hit.refusedBy === "effective" ? "EFFECTIVE entitlements exceed the schema ceiling once the deferral carried into them is added (its own owed amounts are within it)" : "owed amounts exceed the schema ceiling"}`);
      }
      // a FRESH copy per call, so a caller that mutates what it was handed cannot change
      // what the next caller sees
      return hit.rows.map((r) => ({ ...r }));
    },
  };
};

// `readAllocationBps` is exported for ONE reason: the normative calculation validates the
// allocation shape BEFORE it computes gross and fee, so that a malformed allocation
// REFUSES rather than returning an encoding-refusal it reached first. Folding that check
// into splitOwed alone would have turned a throw into a return for any epoch whose gross
// exceeds the ceiling AND whose allocation is malformed. splitOwed still validates for
// itself, so a direct caller gets the same rule.
module.exports = { SCHEMA_CREDIT_CEILING, readAllocationBps, splitOwed, buildCarryCapableEntitlements };
