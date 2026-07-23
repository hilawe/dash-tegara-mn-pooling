/**
 * Pure builder for the pool-ledger v10 schema, the RETAIL-ONLY fixed-slot contract, a
 * source-only DRAFT that is deliberately UNPUBLISHED (there is no registerV10.cjs and
 * nothing selects LEDGER=v10; the live ledger is v8 and v9 is itself an unpublished
 * draft). v10 is the contract-schema half of the fixed-slot share specified in
 * `tegara/docs/FIXED_SLOT_SHARE_SPEC.md` (review-complete through round 12). This builder
 * derives from buildV9, so everything not listed below is carried by construction, and
 * contractV10Test.cjs pins the exact intended diff against a reviewed baseline hash of the
 * v9 construction.
 *
 * v10 is a RETAIL-ONLY contract version (spec section 3, a round-4 packet correction).
 * Direct-tier pools stay on the v9-shaped lineage and take nothing from v10. On a v10
 * instance every pool is a retail pool, so the omission of the retail fields is a schema
 * error, not a valid sibling branch. The THREE changes v10 makes to v9 (a review fold
 * corrected this header when change 3 landed):
 *
 *   1. THE POOL GAINS A REQUIRED, IMMUTABLE `retailGroupDuffs` (spec section 3, "the value
 *      base"). It is this retail pool's own participant-share amount of the node (ONE L1
 *      share per the retail split boundary), NOT the whole node target. The retail slot-book identity is
 *      therefore `slotDuffs * slotCount == retailGroupDuffs` (the v9 book divided the WHOLE
 *      `targetDuffs`, the direct-tier formation meaning; pricing or weighting retail slots
 *      from the node target would let a full book recover more than the group share is
 *      worth). `targetDuffs` STAYS on the pool as the node target (the v9 meaning is kept,
 *      spec section 4 result 1 duty (c)), and `retailGroupDuffs <= targetDuffs`. The
 *      L1-backing check (spec section 4 result 2) additionally verifies `retailGroupDuffs`
 *      equals the amount of the proved live L1 share at `shareTable[pool.slotIndex]`, read
 *      directly from the share table, never inferred from a completion allocation-row
 *      ordinal (allocation rows sort by Platform identity, so their order carries no
 *      correspondence to the L1 share table, the round-2 blocker). That live-L1 half is a
 *      reader duty, not something this schema or `checkRetailPoolInvariants` can hold; the
 *      offline invariants here are only the L2 cross-field ones (presence, bounds, the
 *      retail equation, and `retailGroupDuffs <= targetDuffs`).
 *
 *   2. THE `slotShare` DOCUMENT TYPE IS ADDED, exactly as spec section 3 fixes it. It is the
 *      retail membership document, minted by the operator (one per slot) and moved ONLY by a
 *      paid purchase, so that a paid purchase is the only effective membership change:
 *        - documentsMutable: false   (no replace, ever; constraint 3)
 *        - canBeDeleted: false       (no unpaid abandonment; constraint 2)
 *        - transferable: 0           (no unpaid transfer; constraint 1, probed live in cn17)
 *        - tradeMode: 1              (listable and purchasable, the ONLY movement path)
 *        - creationRestrictionMode: 1 (operator-only minting; constraint 5, the only
 *                                      permissioned-issuance primitive Platform exposes)
 *        - unique bySlot index over (poolId, slot)   (constraint 4, at most one live share
 *                                                      per slot; the book is deterministic)
 *        - byOwner index over ($ownerId, $createdAt) (enumeration by holder)
 *      Three DELIBERATE ABSENCES, each doing work (spec section 3):
 *        - NO value fields (no shareBps, no contributionDuffs). Every slot weighs exactly one
 *          slot and the duff value of a slot is the immutable pool's `slotDuffs`; the reader
 *          derives all value from the immutable pool, so a value field that does not exist
 *          cannot be mutated, duplicated, or contradicted (the strongest form of constraint 3).
 *        - NO reward-script field. The reward destination is the owner's identity credits (R4),
 *          so there is no L1 script to go stale or to fail the set-by-current-owner predicate.
 *        - NO unique (poolId, $ownerId) index. One identity may hold any number of slots in one
 *          pool (constraint 4 warns an owner-uniqueness index would wrongly reject a purchase by
 *          a buyer who already holds a slot). Uniqueness is per SLOT, not per owner.
 *
 * THE SCOPE DECISION IS TAKEN (Hilawe, 2026-07-22): retail-only v10 DROPS the open
 * `share` type and the direct-tier `membershipRequest` / `pledgeSlot` machinery (change 3
 * below), so the retail contract carries no open type a confused client can write to.
 * The earlier "leave it as a reader duty" posture was reviewed sound but untidy; the
 * fixture contracts published before this change carry the three types inertly, and the
 * next fresh publish validates the dropped form (the P1 rerun path).
 * The `checkRetailPoolInvariants` / `buildV10Pool` duty enumeration below is the P1 builder-input
 * gate: it REFUSES to emit a pool that omits `retailGroupDuffs`, violates the retail equation,
 * carries the stale v9 `== targetDuffs` book, or sets `retailGroupDuffs > targetDuffs`.
 *
 * ADOPTION is out of scope here (none of it runs today). Whenever v10 publishes it inherits
 * the whole v9 adoption checklist (envStore ledger selection, the shared receipt-to-pool
 * verifier, the reader pins of spec section 6), plus the fixed-slot readers that enumerate
 * `slotShare` and gate on the four eligibility results and the trusted-checkpoint recognition
 * of spec section 4, and the integrated P1-P8 probe as the acceptance test.
 */
const { buildV9 } = require("./contractV9.cjs");

const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };

// The maximum any duff-amount field carries in this schema family (the evo collateral
// target; see contractV8/contractV9). retailGroupDuffs shares it, since a group share can
// in principle be the whole node.
const MAX_DUFFS = 400000000000;
// The consensus slot ceiling: slotShare.slot maxes at 511 to match the pool's slotCount
// bound (v9 slotCount maximum 512, slots 0..slotCount-1). Conformance BELOW the pool's own
// slotCount is a reader duty; the schema cannot cross-check a share against its pool.
const MAX_SLOT = 511;
// The pool's slotCount ceiling the inherited v9 schema enforces (slots 0..slotCount-1, so a
// slotCount of MAX_SLOT_COUNT admits slot MAX_SLOT). The builder gate below enforces this and
// the MAX_DUFFS cap so buildV10Pool never emits a pool the schema would reject.
const MAX_SLOT_COUNT = MAX_SLOT + 1; // 512

function buildV10(poolLedgerContract) {
  const v10 = buildV9(poolLedgerContract);

  // ---- change 1: the pool gains a REQUIRED, immutable retailGroupDuffs (position 6) ----
  // v9 pool positions run 0..5 (slotIndex, nodeType, operatorFeeBps, targetDuffs, slotDuffs,
  // slotCount), so retailGroupDuffs is the next contiguous position.
  v10.pool.properties.retailGroupDuffs = {
    type: "integer", minimum: 1, maximum: MAX_DUFFS, position: 6,
    description:
      "this retail pool's own participant-share amount of the node (one L1 share, the retail split boundary); " +
      "slotDuffs * slotCount == retailGroupDuffs, and retailGroupDuffs <= targetDuffs; " +
      "verified against shareTable[slotIndex] by the L1-backing check (the schema holds only " +
      "the L2 cross-field bounds; clients check the equation, readers check the live L1 share)",
  };
  // REQUIRED at consensus on retail-only v10: an omission is schema-rejected, not a valid
  // direct-shaped sibling (spec section 3).
  v10.pool.required = [...v10.pool.required, "retailGroupDuffs"];

  // ---- change 2: the slotShare document type, exactly as spec section 3 fixes it ----
  v10.slotShare = {
    type: "object",
    documentsMutable: false,       // no replace, ever (constraint 3)
    canBeDeleted: false,           // no unpaid abandonment (constraint 2)
    transferable: 0,               // no unpaid transfer (constraint 1)
    tradeMode: 1,                  // listable and purchasable, the only movement path
    creationRestrictionMode: 1,    // operator-only minting (constraint 5)
    properties: {
      poolId: {
        ...HASH32, position: 0,
        description: "the immutable v9+ pool this slot belongs to",
      },
      slot: {
        type: "integer", minimum: 0, maximum: MAX_SLOT, position: 1,
        description:
          "which equal slot of the pool's book (0..slotCount-1; the 511 ceiling matches the " +
          "pool's consensus slotCount bound; conformance below the pool's own slotCount is a " +
          "reader duty, the schema cannot cross-check)",
      },
    },
    // NO $createdAt in required (Hilawe's decision, 2026-07-22, after the P3b live
    // readback): the publish path strips $-entries and the SDK does not restore the
    // opt-in, so the audited form now MATCHES the proven live schema. Timestamps are not
    // load-bearing anywhere (entitlement orders by the chain anchor) and the settlement
    // capture archive carries timeMs. The byOwner index keeps its $createdAt component,
    // matching the live contract every probe passed on.
    required: ["poolId", "slot"],
    additionalProperties: false,
    indices: [
      // constraint 4: at most one live share per (poolId, slot); the book is deterministic
      { name: "bySlot", unique: true, properties: [{ poolId: "asc" }, { slot: "asc" }] },
      // enumeration by holder; NOT unique (one identity may hold many slots in one pool)
      { name: "byOwner", properties: [{ $ownerId: "asc" }, { $createdAt: "asc" }] },
    ],
  };

  // ---- change 3: the DIRECT-TIER MACHINERY IS REMOVED (Hilawe's decision (a),
  // 2026-07-22, implemented after the P1-P7b probes validated the two-change form).
  // Retail-only v10 drops exactly the three types the decision names:
  //   - `share`: the open self-created direct-tier membership document. On a retail
  //     contract every membership is a slotShare moved by paid purchase; an open type a
  //     confused or hostile client can write to is junk surface (the earlier "reader
  //     duty" posture was sound but untidy, and the decision retires it).
  //   - `membershipRequest` and `pledgeSlot`: the direct-tier join machinery; retail
  //     issuance is born-live operator minting (spec section 2), so neither has a
  //     retail role.
  // KEPT deliberately: `completionReceipt` (load-bearing for the L1-backing result) and
  // `rewardAccrual` / `votePreference` (shared reward/governance infrastructure).
  // `settlement` is kept but CLASSIFIED AS INACTIVE COMPATIBILITY SURFACE on v10 (a
  // review fold): its required exitId/joinId identify the REMOVED membershipRequest
  // workflow and its phases include share-deleted/share-recreated, which assume the
  // REMOVED share type, so it is semantically INERT here. v10 capability guards must
  // refuse settlement readers and writers; a retail settlement workflow, if ever wanted,
  // needs its own schema and its own review, outside this fold.
  delete v10.share;
  delete v10.membershipRequest;
  delete v10.pledgeSlot;

  return v10;
}

/**
 * The P1 builder-input duty enumeration (spec section 7 P1(b), and the retail half of
 * section 4 result 1 duty (c)). Given a candidate pool's numeric fields, return the list of
 * retail-rule violations; an empty list means the pool passes the OFFLINE cross-field
 * invariants. This does NOT reach L1 (the shareTable[slotIndex] equality is result 2, a
 * reader duty), so a pass here is necessary, not sufficient.
 *
 * The checks, in order:
 *   - retailGroupDuffs, targetDuffs, slotDuffs, slotCount are present positive integers.
 *   - retailGroupDuffs is within [1, MAX_DUFFS].
 *   - THE RETAIL SLOT-BOOK IDENTITY: slotDuffs * slotCount == retailGroupDuffs (NOT the v9
 *     == targetDuffs). The STALE v9 book (slotDuffs * slotCount == targetDuffs while
 *     targetDuffs != retailGroupDuffs) is reported with its own clear message.
 *   - retailGroupDuffs <= targetDuffs (the group share is a share OF the node, never more).
 */
function checkRetailPoolInvariants(pool) {
  const errs = [];
  const isPosInt = (v) => Number.isInteger(v) && v >= 1;

  if (pool.retailGroupDuffs === undefined || pool.retailGroupDuffs === null) {
    errs.push("retailGroupDuffs is REQUIRED on a v10 retail pool (spec section 3)");
    return errs; // nothing else is checkable without it
  }
  if (!isPosInt(pool.retailGroupDuffs)) {
    errs.push("retailGroupDuffs must be a positive integer");
  } else if (pool.retailGroupDuffs > MAX_DUFFS) {
    errs.push(`retailGroupDuffs exceeds the maximum ${MAX_DUFFS}`);
  }
  for (const k of ["targetDuffs", "slotDuffs", "slotCount"]) {
    if (!isPosInt(pool[k])) errs.push(`${k} must be a positive integer`);
  }
  // THE UPPER BOUNDS THE INHERITED v9 SCHEMA ENFORCES, so buildV10Pool never emits a pool the
  // schema would reject (a v10-builder review finding): targetDuffs caps at MAX_DUFFS and
  // slotCount caps at MAX_SLOT_COUNT. slotDuffs has NO schema maximum (v9 slotDuffs is
  // minimum-only), so none is imposed here. retailGroupDuffs's cap is checked above.
  if (isPosInt(pool.targetDuffs) && pool.targetDuffs > MAX_DUFFS) {
    errs.push(`targetDuffs exceeds the maximum ${MAX_DUFFS}`);
  }
  if (isPosInt(pool.slotCount) && pool.slotCount > MAX_SLOT_COUNT) {
    errs.push(`slotCount exceeds the maximum ${MAX_SLOT_COUNT}`);
  }
  if (errs.length) return errs;

  const book = pool.slotDuffs * pool.slotCount;
  if (book !== pool.retailGroupDuffs) {
    if (book === pool.targetDuffs && pool.targetDuffs !== pool.retailGroupDuffs) {
      // the exact stale-v9 case the round-3a blocker named: the book divides the WHOLE node
      // target instead of the group share, so a retail pool built on the v9 equation is rejected
      errs.push(
        "STALE v9 slot-book: slotDuffs * slotCount == targetDuffs (the node target), but v10 " +
        "requires slotDuffs * slotCount == retailGroupDuffs (the group share)");
    } else {
      errs.push(
        `retail slot-book identity violated: slotDuffs * slotCount (${book}) != ` +
        `retailGroupDuffs (${pool.retailGroupDuffs})`);
    }
  }
  if (pool.retailGroupDuffs > pool.targetDuffs) {
    errs.push(
      `retailGroupDuffs (${pool.retailGroupDuffs}) exceeds targetDuffs (${pool.targetDuffs}); ` +
      "the group share is a share OF the node target, never more");
  }
  return errs;
}

/**
 * Emit a v10 retail pool's field object, REFUSING (throw) any input that violates the retail
 * rules. This is the P1(b) gate: "the v10 builder refuses to emit a pool violating any retail
 * rule". A conforming operator flow calls this before broadcasting a pool document.
 */
function buildV10Pool(input) {
  const errs = checkRetailPoolInvariants(input);
  if (errs.length) {
    throw new Error("v10 retail pool rejected: " + errs.join("; "));
  }
  return { ...input };
}

module.exports = { buildV10, checkRetailPoolInvariants, buildV10Pool, MAX_DUFFS, MAX_SLOT, MAX_SLOT_COUNT };
