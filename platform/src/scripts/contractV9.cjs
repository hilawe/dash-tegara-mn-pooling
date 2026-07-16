/**
 * Pure builder for the pool-ledger v9 schema, a source-only DRAFT that is deliberately
 * UNPUBLISHED (registerV9.cjs holds the publish flow behind an explicit confirm; nothing
 * selects LEDGER=v9). v8 is the live ledger and is immutable, so the root causes it
 * closes with client-side guards can only land at consensus in a fresh version. This
 * builder derives from buildV8, so everything not listed below is carried by
 * construction; contractV9Test.cjs pins the exact intended diff against a reviewed
 * baseline hash of the v8 construction.
 *
 * The v9 shape settled across FOUR rounds of the draft's independent review, and the
 * rounds converged on a limit worth stating first: Platform data contracts cannot
 * express cross-document invariants, so consensus-level LIVENESS is not expressible in
 * ANY shape (round one killed a mutable pool with an immutable terms companion, no
 * batch atomicity and permanent contradictory terms; round two killed a mutable
 * poolState, rollback/re-point/delete all representable; round three killed
 * receipt-presence-as-liveness, duplicated fields contradictable and the temporal
 * meaning wrong). v9 therefore claims exactly what consensus CAN hold and nothing more:
 *
 *   - The POOL DOCUMENT is IMMUTABLE, NON-DELETABLE, and OWNER-ONLY, carrying every
 *     creation-time constant: slotIndex, nodeType, operatorFeeBps, targetDuffs, and
 *     the slot book (slotDuffs, slotCount, both-or-neither). The mid-completion
 *     economics drift the v8 client closes with freeze-and-compare has no consensus
 *     surface. The operator IS the document owner ($ownerId); there is no duplicate
 *     operator field to contradict it.
 *   - The COMPLETION RECEIPT is the immutable, owner-only, at-most-one-per-pool
 *     COMPLETION RECORD, pared of every TOP-LEVEL field the immutable pool already
 *     pins (nodeType, operatorFeeBps, targetDuffs are REMOVED from the v8 form): the
 *     evidence is the RECEIPT-PLUS-ITS-POOL PAIR, both immutable, and a verifier
 *     fetches both. slotIndex necessarily remains on the receipt (the unique bySlot
 *     (proTxHash, slotIndex) index needs it, replacing v8's non-unique byProTx so two
 *     pools can never claim the same covenant share of one node). The paring does NOT
 *     empty the cross-document surface: the allocationRows PREIMAGE BYTES themselves
 *     embed the manifest's poolId and target (formationCore.allocationPreimage), so a
 *     receipt can still carry an embedded target that contradicts its pool. The ONE
 *     SHARED receipt-to-pool check every consumer routes through therefore owes FOUR
 *     duties (round four of the review demonstrated an internally-valid receipt
 *     embedding a wrong target passing the allocation verifier alone): (1) verify the
 *     allocation with top-level poolId and participantCount correspondence, (2)
 *     compare the preimage's embedded target against pool.targetDuffs, (3) check
 *     pool.targetDuffs against the nodeType's target and the slot-book product, (4)
 *     check receipt.slotIndex against pool.slotIndex. Raw receipt presence, and the
 *     allocation verifier alone, are never predicates by themselves.
 *   - THE TEMPORAL CLAIMS, stated honestly. Completed, currently-active, and
 *     in-flight are ORTHOGONAL determinations with different sources, not one status
 *     axis. A receipt (verified by the shared check) means the pool COMPLETED,
 *     historical only: dissolution leaves the receipt standing, and "currently
 *     active" comes from the live Core check, which must validate the pool's actual
 *     node SHARE (the registration entry the pool claims), not mere node existence.
 *     A verified receipt whose L1 state no longer matches is RECORDED-COMPLETED,
 *     NOT-ACTIVE, ANOMALOUS, a named outcome consumers surface loudly rather than
 *     collapse into either "live" or "forming". Receipt ABSENCE does not mean "open
 *     forming pool": a crash between the L1 registration and the receipt broadcast
 *     leaves a real node behind a receipt-less pool, the IN-FLIGHT state. The
 *     operator's crash-recovery flow (the frozen receipt draft, the `receipt`
 *     recovery command, retain-until-confirmed) tracks it, but that state is LOCAL:
 *     an independent client or third-party observer CANNOT distinguish open,
 *     abandoned, and in-flight receipt-less pools on Platform alone. The adoption
 *     rule is therefore fail-closed: a client without the operator's recovery state
 *     treats every receipt-less pool as potentially in-flight, admits no new
 *     reservations against it, and handles cancellation through the commit-gate
 *     discipline the v8 flow already implements (cancel-safety is preserved, the
 *     gate is about admission, not exit).
 *   - Slot-book bounds land at consensus: slotCount maximum 512 (v8 source carried
 *     it, the live v8 predates it) and pledgeSlot.slotNo maximum 511 to match. The
 *     receipt targetDuffs bound is gone WITH the field (the pool pins the target).
 *   - The slot fields are BOTH-OR-NEITHER via dependentRequired (keyword and form
 *     match the installed Platform dependency's own schemas). PROBE AT PUBLISH by
 *     SUBMITTING both one-sided document variants and confirming rejection; the
 *     fallback if the target version rejects the keyword is to require both outright
 *     and drop no-slot pools from v9.
 *
 * What v9 delivers at consensus, the complete honest list: pools only from the
 * contract owner; pool constants immutable; at most one receipt per pool; no two
 * receipts per (node, covenant share); the slot bounds. Everything else is stated
 * protocol, owed by clients and verifiers:
 *   - the shared receipt-to-pool check with its FOUR duties above
 *   - slotDuffs * slotCount == targetDuffs; targetDuffs matches the nodeType's target
 *   - the orthogonal completed / currently-active / in-flight determinations above,
 *     including the named anomalous outcome and the fail-closed admission rule
 *
 * What v9 deliberately does NOT change: share keeps OPEN, self-sovereign creation.
 * Platform offers only unrestricted, owner-only, and no-creation modes (verified
 * against the Platform docs in the draft review), so the only available restriction
 * would make the operator the author of every member's share. The scoped readbacks and
 * the receipt's embedded canonical allocation hold a foreign share inert instead.
 *
 * Consequences to state plainly, not hide:
 *   - An abandoned forming pool persists on the ledger forever as inert forming debris
 *     (immutable and non-deletable). Its pledge slots remain member-deletable, so
 *     cancel-safety is untouched; it never claims a (proTxHash, slotIndex) key.
 *   - A malformed receipt (wrong slotIndex, foreign poolId) is permanent; the shared
 *     check makes it DETECTABLE, not repairable. The pool it points at (if any) can
 *     never carry a corrected receipt; recovery is a new pool and a new registration.
 *   - The receipt is NOT self-contained under v9: third-party verification fetches the
 *     receipt and its immutable pool (v8 embedded the pool constants instead; that
 *     duplication was the contradiction surface, round three).
 *   - ONE OPERATOR PER CONTRACT INSTANCE: owner-only creation makes the contract owner
 *     the sole operator of that instance, so a second operator publishes their OWN
 *     contract rather than sharing this one. That is the design, not a limitation to
 *     work around, and operator tooling should say so before a second operator appears.
 *
 * ADOPTION CHECKLIST for whenever v9 publishes (none of this runs today; the sites are
 * the review-verified real ones, not examples):
 *   - envStore.cjs owns ledger selection and the version predicates: map LEDGER=v9 to
 *     CONTRACT_V9_ID and replace the exact-match isV7()/isV8() family with capability
 *     predicates (hasSlotBook, hasCompletionReceipt, hasImmutablePool) driven by one
 *     version table. clientContext.cjs and the funder client must accept v9 (both
 *     reject unknown ledgers today).
 *   - ONE SHARED receipt-to-pool verifier module carrying the FOUR duties above;
 *     every liveness/node consumer routes through it, never through raw receipt
 *     presence, and the standalone allocation verifier is subsumed by (or explicitly
 *     defers to) it. When resolving many receipts to their pools, batch the pool
 *     fetches with the `$id in [...]` query form instead of one fetch per receipt.
 *   - THE RECEIPT PIPELINE ITSELF migrates to the pared shape: formation's
 *     receiptPropertiesFromDraft still emits the removed nodeType/operatorFeeBps/
 *     targetDuffs (a v9 broadcast would be schema-rejected), verifyReceiptAgainstDraft
 *     and the draft comparison read the removed properties, requireDraftMatchesPool
 *     gains the v9 target comparison (draft target vs pool.targetDuffs), the `receipt`
 *     recovery display and the retained-manifest reconciliation read receipt fields
 *     that no longer exist, formation's own LEDGER allowlist must admit v9, and the
 *     v8-only mock receipt schema plus the crash harness need v9 variants.
 *   - POOL CREATORS build the v9 shape (no proTxHash/status/operatorIdentityId,
 *     required targetDuffs): formation.cjs `create`, creditRail.cjs, matcher.cjs,
 *     funder.cjs, castDemoSetup.cjs. The NON-FORMATION creators (creditRail, matcher,
 *     funder, castDemoSetup) create pools intended to be live at birth: under v9 each
 *     must ALSO publish a valid completion receipt in its setup flow, or explicitly
 *     refuse v9.
 *   - LIVENESS/NODE READERS move from pool.status / pool.proTxHash to the shared
 *     check: formation.cjs (status; completion preflight; the `receipt` RECOVERY path
 *     and the `abandon` path, which both derive state from pool.proTxHash today and
 *     need redesign for the in-flight distinction), creditRail.cjs (reward processing
 *     AND its pool discovery), castDemoSetup.cjs (discovers pools by pool.proTxHash,
 *     a reader as well as a creator), governor.cjs and the cast receipts,
 *     ledgerAudit.cjs, voteWatch.cjs (reads pool.proTxHash), and the funder-client
 *     `pools`, `pledge`, `reserve`, `cancel` commands. The executable admission rule
 *     for the funder client, which cannot see the operator's recovery state and so
 *     cannot tell open from in-flight from abandoned on Platform data alone:
 *     `pledge` and `reserve` FAIL CLOSED on a receipt-less pool EXCEPT under the
 *     operator's explicit coordination (the advertised participate instruction, the
 *     round's named alternative authority; autonomous admission against a merely
 *     discovered pool is refused); `cancel` follows the commit-gate discipline,
 *     exit is never gated on receipt state.
 *   - cleanupDebris.cjs must refuse (or skip) pool deletion on immutable-pool ledgers.
 *   - The flip step becomes receipt publication only; the L1 handoff is unchanged;
 *     the crash-recovery flow carries the in-flight state as today.
 *   - Offline suites gain v9 cases; the live publish is followed by the probes:
 *     non-owner pool creation refused, pool replace refused, pool delete refused,
 *     one-sided slot-field variants refused (dependentRequired), receipt bySlot
 *     uniqueness enforced (second receipt claiming the same node+slot refused).
 */
const { buildV8 } = require("./contractV8.cjs");

function buildV9(poolLedgerContract) {
  const v9 = buildV8(poolLedgerContract);

  // ---- the immutable pool (the redesign's center) ----
  v9.pool = {
    type: "object",
    documentsMutable: false,
    canBeDeleted: false,             // the pool is the permanent record of its constants
    creationRestrictionMode: 1,      // owner-only; the consensus form of the contract-owner guard
    properties: {
      slotIndex: {
        type: "integer", minimum: 0, maximum: 31, position: 0,
        description: "which #187 share / DIP-0026 payout entry this pool maps to (a creation-time constant, pinned by immutability)",
      },
      nodeType: { type: "string", enum: ["regular", "evo"], maxLength: 10, position: 1 },
      operatorFeeBps: {
        type: "integer", minimum: 0, maximum: 10000, position: 2,
        description: "operator fee in basis points of the pool's owner reward, immutable for the pool's life; the operator IS the document owner ($ownerId) under owner-only creation",
      },
      targetDuffs: {
        type: "integer", minimum: 1, maximum: 400000000000, position: 3,
        description: "the collateral target, pinned explicitly so the pool is self-contained (must match the nodeType's target; clients check, the schema cannot)",
      },
      slotDuffs: {
        type: "integer", minimum: 1, position: 4,
        description: "the fixed slot size in duffs; absent (with slotCount, both-or-neither) means this pool has no slot book; slotDuffs * slotCount = targetDuffs is checked by clients and recomputed by verifiers",
      },
      slotCount: {
        type: "integer", minimum: 1, maximum: 512, position: 5,
        description: "how many equal slots divide the target; bounded at consensus so a legitimate book can never exceed the bounded completion scan",
      },
    },
    required: ["slotIndex", "nodeType", "operatorFeeBps", "targetDuffs", "$createdAt"],
    // both-or-neither for the slot book; PROBE AT PUBLISH with one-sided variants
    dependentRequired: { slotDuffs: ["slotCount"], slotCount: ["slotDuffs"] },
    additionalProperties: false,
    indices: [
      { name: "byOwner", properties: [{ $ownerId: "asc" }, { $createdAt: "asc" }] },
    ],
  };

  // ---- the pared completion record: the receipt-plus-its-pool pair is the evidence ----
  // The fields the immutable pool already pins are REMOVED (their duplication was the
  // round-three contradiction surface); slotIndex stays because the unique bySlot index
  // needs it, and its pool-match is one of the shared check's FOUR duties (see header).
  const r = v9.completionReceipt;
  delete r.properties.nodeType;
  delete r.properties.operatorFeeBps;
  delete r.properties.targetDuffs;
  r.properties.poolId.description =
    "the pool this receipt completes; at most one receipt per pool (unique byPool); that the id resolves to a real pool of this contract is a duty of the shared receipt-to-pool check";
  r.properties.slotIndex.description =
    "the pool's L1 share mapping; MUST equal the immutable pool's slotIndex (the shared check verifies; the schema cannot), kept here because the unique bySlot index needs it";
  ["poolId", "proTxHash", "slotIndex", "formatVersion", "allocationRows", "allocationHash",
    "participantCount", "l1Verification", "verificationMethodVersion"]
    .forEach((k, i) => { r.properties[k].position = i; });
  r.required = r.required.filter((k) => !["nodeType", "operatorFeeBps", "targetDuffs"].includes(k));
  r.indices = [
    { name: "byPool", properties: [{ poolId: "asc" }], unique: true },
    { name: "bySlot", properties: [{ proTxHash: "asc" }, { slotIndex: "asc" }], unique: true },
  ];

  // v8's pool carried status/proTxHash/slot fields inline; the lifecycle claims moved
  // to the receipt pair above, so the v8-inherited pledgeSlot is the only other type
  // v9 touches: slotNo tightens to the same 512-slot ceiling slotCount now enforces
  // at consensus (v8's live schema was already immutable at 9999).
  v9.pledgeSlot.properties.slotNo = {
    ...v9.pledgeSlot.properties.slotNo,
    maximum: 511,
    description: "which equal-size collateral slot of the pool (0..slotCount-1, bounded at consensus to match slotCount's ceiling)",
  };

  return v9;
}

module.exports = { buildV9 };
