/**
 * epochCarry - the E2 build spec's CARRY LAYER as a pure module, so the audit's
 * recomputation and (from the multi-epoch driver on) the writer's row calculation
 * consume ONE implementation of the rule instead of each carrying its own.
 *
 * THE RULE, quoted from `tegara/docs/E2_BUILD_SPEC.md` ("THE CARRY LAYER"), which is the
 * oracle for every value this module returns. The words are the spec's; only the line
 * wrapping differs:
 *
 *     carryIn_i(configuredStart) = 0
 *     effective_i(N)  = owed_i(N) + carryIn_i(N)
 *     carryOut_i(N)   = effective_i(N)   when effective_i(N) > 0, below the pinned
 *                                        minimum, and owner_i is NOT the pool's
 *                                        income identity
 *                     = 0                otherwise
 *     carryIn_i(N+1)  = carryOut_i(N)    when epoch N encodes
 *                     = carryIn_i(N)     when epoch N is ENCODING-REFUSED
 *
 * WHAT THIS MODULE OWNS: the arithmetic, the three-way outcome of an epoch step, and
 * the pass-through rule for a refused epoch. It is pure, does no I/O, and never mutates
 * an argument.
 *
 * WHAT IT DELIBERATELY DOES NOT OWN, because both consumers already answer these and
 * they answer them from different material:
 *
 * - IDENTITY NORMALIZATION. The caller supplies an already-normalized member `key` and
 *   the boolean `isSelfShare`. The audit derives both from adapter values through its
 *   own `nid`/`sameId` (an identifier there may arrive as a Buffer, a WASM identifier
 *   object or base58); the writer compares 64-hex strings. Pulling either normalizer in
 *   here would make the module's answer depend on a decoding layer it cannot check.
 * - THE OWED CALCULATION. `owedCredits` arrives computed. The normative version-1 owed
 *   rule is `computeNormativeEpoch` in e2Audit.cjs.
 * - THE WRITER'S ROW GRAMMAR. `classifyEntitlement` in e2Distribute.cjs validates the
 *   entitlement row's own members (hex ids, decimal strings, the `carryInCredits`
 *   grammar) before classifying. This module takes BigInt quantities that a caller has
 *   already parsed, and refuses them on their VALUES rather than their spelling.
 *
 * THE PINNED MINIMUM comes from e2Journal.cjs, the one place it is defined.
 *
 * WHAT THIS MODULE TAKES ON THE CALLER'S WORD, stated because an extracted rule can
 * enforce less than the same code enforced inline, where its inputs had exactly one
 * producer. Each of these was compulsory by placement before and is a caller obligation
 * now, and none of them is checkable from in here:
 *
 * - `isSelfShare` IS the answer. A caller that reports the income identity's own row as
 *   false makes it payable, and this module cannot tell.
 * - `owedCredits` came from the normative calculation, and `owedRefused` reflects that
 *   calculation's own refusal rather than a caller's choice.
 * - `encodingCeiling` is the schema's ceiling. Any positive BigInt is accepted, so a
 *   caller passing a larger one encodes amounts the schema would refuse.
 * - `key` is normalized, so two spellings of one identity land on one key. Duplicate
 *   detection is over the keys as given.
 * - the run began at the configured start with emptyCarryState(). A caller seeding a
 *   nonzero state starts the recursion somewhere the base case does not describe.
 * - `members` IS THE EPOCH'S COMPLETE MEMBER SET. This one is worth naming on its own
 *   because it is the least visible: a caller that omits a member who happens to defer
 *   nothing is undetectable from in here, since the omitted member leaves no trace in
 *   the carry state either. A caller that omits a member who IS deferring is caught by
 *   the membership guard, so the undetectable case is exactly the one that loses no
 *   value today and quietly changes the recomputed set the next epoch compares against.
 *
 * This is the same shape as the build spec's own trust statement about the writer's
 * injected calculation, and it is stated for the same reason: a non-conforming caller
 * produces a wrong answer that looks exactly like a right one.
 *
 * NOT HERE, and named so it is not looked for: the frontier STOCK the lag measurement
 * owes (a soundness-review finding) belongs to the multi-epoch driver unit together with the change that
 * makes the measurement reachable, per that finding's own instruction.
 */
"use strict";

const { MIN_TRANSFER_AMOUNT_CREDITS } = require("./e2Journal.cjs");

const refuse = (msg) => { throw new Error(`carry: ${msg}`); };

const isBig = (v) => typeof v === "bigint";

/**
 * A carry state is a Map from a member key to that member's carry-in, always a POSITIVE
 * BigInt strictly below the pinned minimum. The upper bound is a property of the layer
 * rather than a convention: `carryOut` is only ever an effective amount that is itself
 * below the minimum, so a state holding anything else did not come from a conforming
 * predecessor and this module refuses to compute over it.
 *
 * THE STATE HOLDS ONLY OUTSTANDING DEFERRALS. A member who defers nothing has NO ENTRY
 * rather than a zero one, so the map's key set means "who is owed a carried residue"
 * and its size is the number of deferrals. That is what lets the membership guard below
 * be exactly a no-value-may-vanish rule: with zero entries stored, a member leaving the
 * set would have refused merely for having once been paid.
 */
const emptyCarryState = () => new Map();

const assertCarryState = (carryIn, what) => {
  if (!(carryIn instanceof Map)) refuse(`${what} must be a Map (use emptyCarryState())`);
  for (const [k, v] of carryIn) {
    if (typeof k !== "string" || k.length === 0) {
      refuse(`${what} holds a non-string member key ${JSON.stringify(k)}`);
    }
    if (!isBig(v)) refuse(`${what} holds a non-BigInt carry-in for ${k.slice(0, 8)}...`);
    if (v <= 0n) {
      refuse(`${what} holds a carry-in of ${v} for ${k.slice(0, 8)}...; the state carries only outstanding deferrals, so a member deferring nothing has no entry rather than a zero one`);
    }
    if (v >= MIN_TRANSFER_AMOUNT_CREDITS) {
      refuse(`${what} holds a carry-in of ${v} for ${k.slice(0, 8)}..., which reaches the pinned minimum ${MIN_TRANSFER_AMOUNT_CREDITS} (a carried amount is always below it)`);
    }
  }
};

/**
 * Validate the member set. ONE ROW PER MEMBER PER EPOCH is load-bearing rather than
 * tidy: the layer compares each member's EFFECTIVE amount against the pinned minimum,
 * and two rows sharing an owner would compare two halves of one claim, so a duplicate
 * key refuses here instead of silently deciding the wrong way.
 *
 * `owedCredits` is required unless the caller has already declared the epoch's owed
 * values unencodable (`owedRefused`), in which case there are no owed values to carry.
 */
const assertMembers = (members, owedRefused) => {
  if (!Array.isArray(members)) refuse("members must be an array");
  // an epoch always has members: the allocation carries 1..8 rows and the normative
  // calculation refuses outside that range, so an empty set is a caller that lost its
  // rows rather than an epoch that has none, and answering it with a conforming-looking
  // encoded result would be the quietest possible way to evaluate nothing
  if (members.length === 0) {
    refuse("members is empty; an epoch's member set is never empty and an empty one would return a conforming result over no rows at all");
  }
  const seen = new Set();
  for (let i = 0; i < members.length; i++) {
    const m = members[i];
    if (!m || typeof m !== "object") refuse(`member ${i} must be an object`);
    if (typeof m.key !== "string" || m.key.length === 0) {
      refuse(`member ${i} needs a non-empty string key (the caller's normalized member identity)`);
    }
    if (seen.has(m.key)) {
      refuse(`two members share the key ${m.key.slice(0, 8)}...; the per-member minimum comparison is only sound under one row per member per epoch`);
    }
    seen.add(m.key);
    if (typeof m.isSelfShare !== "boolean") {
      refuse(`member ${i} needs an explicit boolean isSelfShare (the income identity's rows never receive carry, and an absent answer would silently make one payable)`);
    }
    if (!owedRefused) {
      if (!isBig(m.owedCredits)) refuse(`member ${i} needs a BigInt owedCredits`);
      if (m.owedCredits < 0n) refuse(`member ${i} has a negative owedCredits ${m.owedCredits}`);
    }
  }
};

/**
 * The per-member carry-out rule, the second line of the recursion above. It is private
 * because every caller reaches it through advanceEpoch, which is the only place the
 * effective amount it consumes is computed.
 *
 * THE RULE'S "effective > 0" CONDITION HAS NO BRANCH OF ITS OWN, deliberately. Both
 * inputs to the sum are validated non-negative (owed at the member check, carry-in at
 * the state check), so an effective amount is never negative, and a ZERO one already
 * answers zero through the below-minimum branch. A branch for it would be a guard no
 * input can reach, which reads as protection while testing nothing. If either
 * validation is ever relaxed, this reasoning is what has to be redone.
 */
const carryOutOf = (effective, isSelfShare) => {
  if (isSelfShare) return 0n;
  if (effective < MIN_TRANSFER_AMOUNT_CREDITS) return effective;
  return 0n;
};

/**
 * Advance the carry state across ONE epoch, returning that epoch's effective amounts
 * and the carry state the NEXT epoch begins from. The input state is never mutated; the
 * returned `carryOut` is always a fresh Map.
 *
 *   carryIn         : the carry state this epoch begins from (emptyCarryState() at the
 *                     configured start, where the recursion's base is zero)
 *   members         : [{ key, isSelfShare, owedCredits }], one entry per member, in the
 *                     caller's own order; the returned arrays are indexed to match
 *   encodingCeiling : the schema's amountCredits ceiling as a BigInt. The layer's rule
 *                     is that the encoding refusal runs over the EFFECTIVE amount, so
 *                     the check belongs to this step and not to the owed calculation
 *                     that precedes it
 *   owedRefused     : REQUIRED. True when the owed calculation ALREADY refused this
 *                     epoch (its G, fee or an owed amount exceeded the ceiling); the
 *                     epoch then has no encodable owed values at all and takes the
 *                     pass-through below. It has no default, because a default would
 *                     make an omitted answer indistinguishable from an explicit "no"
 *                     and the omission is the likelier defect of the two
 *
 * Three outcomes, and the two refusing ones differ only in which value refused. Every
 * field each one carries is listed, so a caller never reads an absent member as a value:
 *
 *   { kind: "encoded", refusedBy: null, effective: [BigInt], carryOut: Map,
 *     payable: [boolean] }
 *       `effective` and `payable` are indexed to `members`. A member is payable when it
 *       is not the self-share AND its effective amount reaches the pinned minimum, which
 *       is the layer's own partition: a payable member's carry-out is zero, and a
 *       non-payable one is either the self-share (settled where it sits) or a deferral.
 *
 *   { kind: "encoding-refused", refusedBy: "owed", effective: null, carryOut: Map }
 *       no `refusedValue`: the refusing value belongs to the owed calculation, which
 *       already reported it to the caller that set `owedRefused`.
 *
 *   { kind: "encoding-refused", refusedBy: "effective", effective: null, carryOut: Map,
 *     refusedValue: String }
 *       `refusedValue` is the FIRST effective amount over the ceiling, in member order.
 *
 * THE PASS-THROUGH IS THE POINT OF RETURNING A STATE ON THE REFUSING PATHS. An
 * encoding-refused epoch drops its OWN owed values and its custody ends at the header,
 * but a deferral arriving from an earlier epoch survives it rather than vanishing, so
 * `carryOut` equals `carryIn` there. Returning the state on every path is what stops a
 * caller from implementing that rule itself and getting it wrong in one branch.
 */
const advanceEpoch = ({ carryIn, members, encodingCeiling, owedRefused }) => {
  if (typeof owedRefused !== "boolean") {
    refuse("owedRefused is required and must be a boolean: an omitted answer would read as an epoch whose owed calculation did not refuse");
  }
  assertCarryState(carryIn, "carryIn");
  assertMembers(members, owedRefused);
  if (!isBig(encodingCeiling) || encodingCeiling <= 0n) {
    refuse("encodingCeiling must be a positive BigInt (the schema's amountCredits ceiling)");
  }

  // the pass-through, both refusing paths: a COPY, so a caller holding the previous
  // state cannot have it changed underneath by a later advance
  // EVERY DEFERRING MEMBER MUST STILL BE A MEMBER, on every path including the two that
  // refuse. Carry is per member and a deferral is that member's exact claim, so a
  // carry-in key absent from this epoch's rows would be dropped silently by the map
  // rebuild below and the member's value would simply cease to exist. THE GUARD IS
  // EXACTLY A NO-VALUE-MAY-VANISH RULE and nothing wider: the state holds only positive
  // deferrals, so a member who merely stopped being owed anything has no entry to trip
  // it, and this fires only where a real amount was about to disappear.
  const memberKeys = new Set(members.map((m) => m.key));
  for (const k of carryIn.keys()) {
    if (!memberKeys.has(k)) {
      refuse(`the carry-in state holds ${k.slice(0, 8)}..., which is not a member of this epoch; carry is per member and dropping it would lose that member's deferral`);
    }
  }

  const passThrough = () => new Map(carryIn);

  if (owedRefused) {
    return { kind: "encoding-refused", refusedBy: "owed", effective: null, carryOut: passThrough() };
  }

  const effective = members.map((m) => m.owedCredits + (carryIn.get(m.key) || 0n));
  const over = effective.find((v) => v > encodingCeiling);
  if (over !== undefined) {
    return { kind: "encoding-refused", refusedBy: "effective", effective: null,
      carryOut: passThrough(), refusedValue: String(over) };
  }

  const carryOut = new Map();
  const payable = [];
  for (let i = 0; i < members.length; i++) {
    const out = carryOutOf(effective[i], members[i].isSelfShare);
    // the layer's own bound, asserted rather than assumed: a carry-out that reached the
    // pinned minimum would be a deferral the next epoch's state validation rejects, and
    // finding that one epoch later reads as a corrupt state rather than as this bug
    if (out >= MIN_TRANSFER_AMOUNT_CREDITS) {
      refuse(`computed a carry-out of ${out} for member ${i}, which reaches the pinned minimum ${MIN_TRANSFER_AMOUNT_CREDITS}`);
    }
    if (out !== 0n && members[i].isSelfShare) {
      refuse(`computed a nonzero carry-out for the self-share member ${i} (the income identity's rows never carry)`);
    }
    // ONLY A REAL DEFERRAL IS STORED (see the carry-state note above)
    if (out !== 0n) carryOut.set(members[i].key, out);
    payable.push(!members[i].isSelfShare && effective[i] >= MIN_TRANSFER_AMOUNT_CREDITS);
  }

  return { kind: "encoded", refusedBy: null, effective, carryOut, payable };
};

// the surface is TWO functions on purpose. The pinned minimum is not re-exported: it is
// defined once in e2Journal.cjs, and a second path to one constant would be the drift
// this module exists to remove. Where each reader gets it: this module and e2Distribute
// import it from e2Journal directly, and e2Audit no longer needs it at all, since the
// only comparison it used to make against the minimum moved in here with the rule.
module.exports = { emptyCarryState, advanceEpoch };
