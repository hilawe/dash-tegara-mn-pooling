# On-ledger completion receipt, build spec (revised after the three-model design review)

The proper on-ledger form of the formation completion record. C3 (the six-fix round) was "the
code called the manifest part of the durable record and then deleted it"; F-C3 fixed it by
RETAINING the finalized manifest LOCALLY under a `FORMATION_DONE_` owned key. This spec is the
on-ledger version, so a third party can see that a pool completed and what it committed to,
without the operator's local files. It is a new pool-ledger contract version (v8) because it
needs a new document type, and per the project discipline a new contract gets PUBLISHED and
validated live, so the live-publish part belongs in a session with the devnet up.

REVISED 2026-07-14 after a three-model design review (three independent models; the round records stay in the private repo). The first draft was found squattable,
over-claiming, and not self-verifiable; the changes below fold the merged cross-check. Read the
cross-check for why each choice is forced or chosen.

REVISED AGAIN 2026-07-14 after the FOLLOW-UP round over the revised spec (a fresh full three-model
pass, the last gate before build). Both packet passes returned APPROVE-WITH-FIXES and the CLI pass
returned coherent-but-not-build-ready, unanimous on a short completion list, no blockers. Folded
here:

- an exact publishable schema with an explicit `allocationRows` byte bound (FU-1);
- a persisted frozen receipt draft plus a byte-exact verifier so a post-crash resume rebuilds the
  exact receipt (FU-2);
- removal of the real node hash from the allocation preimage, because the finalized manifest
  predates L1 registration and cannot carry it, so the node binding stays a top-level field only
  (the follow-up round's one new correctness finding);
- an explicit Buffer encoding for the embedded bytes;
- a pre-existing odd-length-hex validation fix in formation (FU-3).

The mixed-transition question is settled as pursue-behind-a-probe (see that section).

## What the receipt DOES and does NOT attest (the honesty ceiling, state it everywhere)

The receipt is operator-signed. With the owner-binding below, consensus establishes ONLY that:

- the pool's own operator (its immutable `$ownerId`) recorded exactly one immutable
  completionReceipt for the pool, and
- its embedded allocation and its fields cannot be altered or a second receipt substituted.

It does NOT prove that the L1 registration matched the manifest, that the member shares exist or
match, that the claimed `l1Verification` level was actually performed, that principal
destinations protect principal, or that retail sub-funders have direct covenant protection
(the retail split boundary). A third party VERIFIES the allocation by recomputing the hash from the receipt's OWN
embedded rows (self-contained) and, for a live cross-check, by fetching the pool's `share`
documents and confirming they still match, noting that shares are mutable so a later divergence
means churn, not a false receipt. The receipt adds public immutability and discoverability; it
does not raise the underlying L1 trust level. Every doc that describes it repeats this ceiling.

## The contract (pool-ledger v8 = v7 + one document type)

Copy `registerV7.cjs` to `registerV8.cjs`, carry every v7 change forward, and add the exact
publishable document type below (FU-1: no sketch shorthand, every property has a `position`,
byteArray and string bounds are explicit, const integers are pinned with `minimum == maximum`, and
`additionalProperties: false`). HASH32 is the platform's 32-byte `byteArray` form
(`byteArray: true, minItems: 32, maxItems: 32`), as v7 uses it.

    completionReceipt: {
      type: "object",
      documentsMutable: false,
      canBeDeleted:     false,             // explicit immutable-evidence pattern (M1)
      creationRestrictionMode: 1,          // OWNER-ONLY creation (M1); probe live like cast-receipt
      properties: {
        poolId:         { type: "array", byteArray: true, minItems: 32, maxItems: 32, position: 0 },
        proTxHash:      { type: "array", byteArray: true, minItems: 32, maxItems: 32, position: 1 },
        slotIndex:      { type: "integer", minimum: 0, maximum: 31, position: 2 },  // v7 slot book cap
        nodeType:       { type: "string", enum: ["regular","evo"], position: 3 },
        operatorFeeBps: { type: "integer", minimum: 0, maximum: 10000, position: 4 },
        formatVersion:  { type: "integer", minimum: 1, maximum: 1, position: 5 },   // const 1 (M3/M4)
        allocationRows: { type: "array", byteArray: true, minItems: 1, maxItems: 2048, position: 6 },
                          // EMBEDDED canonical allocation preimage (M3); <=8 owners is ~1.4 KB
                          // worst case, so 2048 is right-sized with headroom (FU-1)
        allocationHash: { type: "array", byteArray: true, minItems: 32, maxItems: 32, position: 7 },
                          // sha256 of allocationRows (compact content id; M3)
        participantCount: { type: "integer", minimum: 1, maximum: 8, position: 8 }, // DIRECT covenant participants (M6/C-F)
        targetDuffs:    { type: "integer", minimum: 1, position: 9 },
        l1Verification: { type: "string",
                          enum: ["amount-reward-verified","node-existence-only","demo-unverified"],
                          position: 10 },
        verificationMethodVersion: { type: "integer", minimum: 1, maximum: 1, position: 11 }, // (M5)
      },
      required: ["poolId","proTxHash","slotIndex","nodeType","operatorFeeBps","formatVersion",
                 "allocationRows","allocationHash","participantCount","targetDuffs",
                 "l1Verification","verificationMethodVersion","$createdAt"],
      additionalProperties: false,
      indices: [
        { name: "byPool",  properties: [{ poolId: "asc" }], unique: true },
        { name: "byProTx", properties: [{ proTxHash: "asc" }] },
      ],
    }

The exact `maxItems` and other bounds are the registerV8 truth. If the live publish rejects any
bound, fix it there and re-pin. Notes on the schema decisions:
- OWNER-ONLY creation (`creationRestrictionMode: 1`) plus verifying the pool's IMMUTABLE
  `$ownerId` before any mutation closes the SQUATTING vector (M1): without it, any identity could
  create the receipt first and occupy the unique `byPool` key forever. If v8 ever needs multiple
  independent operators in one contract, switch to a unique `[poolId, $ownerId]` index and treat
  only the pool-owner's receipt as authoritative; v8 is single-operator, so owner-only is used.
- The receipt EMBEDS `allocationRows` (M3/C-E), the canonical allocation preimage, so a third
  party verifies from the receipt alone. A hash-only receipt is NOT durably verifiable, because
  the shares it would be checked against are mutable and drift after completion. `allocationHash`
  is the compact content id over those bytes.
- `l1Verification` is a SCOPED enum (M5/C-B): `amount-reward-verified` is the check's real strength
  (node existence, count, total, and the (amount, reward-destination) pair multiset, NOT owner
  keys or refund scripts), `node-existence-only` is the non-shared-node fallback, and
  `demo-unverified` is the override path. `verificationMethodVersion` lets a future stronger registration verification
  (owner keys + refund scripts, complete tuples) add a new level without re-meaning old receipts.
- `participantCount` is 1..8 DIRECT covenant participants and is ENFORCED in formation before
  COMMIT (M6/C-F); it is NOT a general Platform-allocation count. v8 formation is the direct
  co-owner flow. The receipt does not represent retail beneficial owners and must not imply the retail split
  is solved.

## Canonical allocation preimage (M4/C-C; the exact bytes, pure and harness-tested, do FIRST)

`allocationRows` and `allocationHash` commit to the ALLOCATION, not the claim provenance. The
review divergence resolved this way because claim snapshots are mutable, deletable, and not
third-party-reproducible, so committing to them would be weaker, not stronger. In `formationCore`, add
`allocationPreimage(contractId, manifest)` returning canonical UTF-8 bytes and
`allocationHash(bytes)` = sha256. The contract id is passed EXPLICITLY because the manifest does not
carry it (FU-2). The preimage is a fixed-shape array, JSON.stringify, UTF-8:

    [ "tegara-completion-allocation",   // domain tag
      1,                                // formatVersion
      <poolLedgerContractId base58>,    // prevents cross-contract reuse
      <poolId base58>,
      <targetDuffs base-10 string>,
      [ [ <owner base58>, <amountDuffs base-10 string>, <bps integer>, <rewardScriptHex lowercase> ],
        ... one per owner, SORTED by the owner's DECODED 32-byte identifier bytes ] ]

The real node hash is DELIBERATELY NOT in the allocation preimage (the follow-up round's one new
correctness finding). The manifest is finalized and members agree to it during formation, BEFORE
the L1 registration exists, while the pool still carries the placeholder forming-hash. The real
proTxHash only exists after registration, so a preimage that included it could not be computed from
the finalized manifest, it would force the manifest to be rewritten post-registration and break its
role as the frozen prior commitment. The allocation is a formation-epoch fact (who gets what share),
and the node is a completion-epoch fact. They are kept separate: the allocation hash commits to the
member split, and `proTxHash` is recorded as a top-level receipt field and indexed by `byProTx`. No
third-party protection is lost, because the receipt is already immutable, owner-only, and unique on
`byPool` (poolId is in the hash) and `byProTx`, so the pool-to-node binding is enforced by the
indices and the pool document, and the honesty ceiling already says the operator is trusted for the
L1 binding either way. The frozen receipt draft (Formation changes) is what keeps the top-level
proTxHash and every other field self-consistent between create and the idempotent re-verify.

Rules: base-10 duff strings with no leading zeroes; bps as integers; lowercase hex for scripts;
owners sorted by decoded identifier bytes (NOT locale string order); no insignificant whitespace;
fixed key/array order. The bytes assigned to the document field are `Buffer.from(JSON.stringify(
preimageArray), 'utf8')` explicitly, since `JSON.stringify` returns a string and the byteArray field
rejects a raw string (review follow-up). Harness cases: same manifest twice hashes equal; reordering
owners hashes equal (canonical); changing any allocation field changes the hash; a PUBLISHED
golden known-answer vector (a fixed input and its expected sha256) pinned so an independent
implementation can reproduce it and a tooling change that alters the bytes is caught. Implement
via a frozenCommitment object (the reviewer's opportunity) so no volatile field can leak in.

Ship a thin offline verify wrapper alongside the helper (all three follow-up passes asked for it):
`verifyReceiptAllocation(contractId, receiptDoc)` that recomputes `allocationHash` from the receipt's
own embedded `allocationRows`, byte-compares, and reports match/mismatch, plus a tiny CLI form
(`verify-allocation`) so an auditor can check an on-ledger receipt from the bytes alone without the
JS SDK or a Platform query. Offline; build, commit, and review this whole piece before the live
contract.

## Wiring (mirror how v7 was added)

- `envStore.cjs`: add `v8` to the LEDGER lists and `activeContractId`; add `CONTRACT_V8_ID`;
  `isV7()` returns true for v8 (v8 keeps sizeless mutable claims); add `isV8 = () => LEDGER==="v8"`
  and include v8 in `isV6`/`isV3`/`isV4`/`isV5`; export `isV8`.
- `clientContext.cjs` and `formation.cjs`: add `v8` to their LEDGER lists; import `isV8`.

## Formation changes

### Fix the odd-length reward-script hex validation (FU-3, pre-existing)

`formation.cjs` validates `rewardScriptHex` with `/^[0-9a-f]{2,68}$/` at line 277 (owner scripts)
and the same pattern at line 297 (claim scripts). That bound accepts ODD-length hex, and
`Buffer.from(oddHex, "hex")` silently truncates the trailing half-byte, so a malformed script can
pass validation and be stored a byte short. Tighten both to require whole bytes, e.g.
`/^([0-9a-f]{2}){1,34}$/` (1 to 34 byte-pairs = 2 to 68 chars). This is in the reviewed
formation code; fix it with the v8 build (or as a standalone commit first, since it is independent
of the receipt work).

### Enforce the direct-participant bound (M6/C-F), before COMMIT

Before COMMIT under `isV8()`, refuse if the manifest has fewer than 1 or more than 8 owners
(after owner aggregation), so `participantCount` is always true and the receipt cannot claim a
count the covenant tier does not permit.

### Thread the verification level out of PREFLIGHT (a)

PREFLIGHT (a) already decides the level; capture it as a variable
(`amount-reward-verified` / `node-existence-only` / `demo-unverified`) for the receipt.

### Persist a FROZEN RECEIPT DRAFT after preflight, before the flip (FU-2)

The retained `FORMATION_DONE_` manifest holds the allocation but NOT slotIndex, nodeType,
operatorFeeBps, or the resolved `l1Verification`, so a resumed publish that rebuilt the receipt from
the manifest alone could write LATER pool values or a different verification level, and a legitimate
existing receipt's field-compare could then falsely mismatch. So after a successful preflight and
BEFORE the flip (or the coupled broadcast), persist an exact frozen receipt draft under an owned key
(e.g. `RECEIPT_DRAFT_<poolId>`): every receipt field, including the EXACT `allocationRows` bytes and
the resolved verification result. Both the create and the idempotent field-verify are driven from
this draft, never recomputed from live pool state. The draft is the single source of the exact
receipt across a crash and resume.

### Write the receipt (after the flip, before clearing the active manifest), STRONG idempotence

Under `isV8()`, after the pool flips live and BEFORE clearing the active manifest key, driving every
field from the FROZEN RECEIPT DRAFT above:
1. Load the EXPECTED receipt from the frozen draft (embedded allocationRows bytes, allocationHash,
   all fields), not from live pool state.
2. Query for an existing `completionReceipt` where poolId == this pool. If one exists, VERIFY its
   `$ownerId` is the operator and EVERY field matches the draft; the allocationRows check is a
   byte-for-byte `Buffer.equals`, not a JSON parse plus deep-equal, and the hash is recomputed from
   the embedded bytes and compared. A mismatch STOPS completion loudly (do not log-and-skip). If it
   matches, log "already recorded" and continue.
3. Else create it (operator-signed) and broadcast, catching ONLY the recognized duplicate-unique
   rejection on `byPool`; on that, re-query the winner and verify field-by-field against the draft
   (retry, preserving the manifest and draft, if not yet queryable). This is the matcher.cjs
   pattern, not a bare query-then-create (C-A).
4. Keep retaining the local `FORMATION_DONE_` manifest and the frozen draft (F-C3); clear the draft
   only once the receipt is confirmed on-ledger.

### Do NOT clear the manifest until the receipt is confirmed (C-G)

Retain the active manifest key until the receipt is confirmed on-ledger, so a crash between the
flip and the receipt is a recoverable "live without receipt" state, not a permanent one.

### Recovery path for already-live-without-receipt (C-G, review L3-1)

Add `receipt <poolId>` (read; pre-client-safe) that prints the receipt AND re-verifies its hash
from the embedded rows, AND make it publish when absent: if the pool is already live and no receipt
exists, load the FROZEN RECEIPT DRAFT (or, if only the manifest survived, rebuild the draft from the
retained `FORMATION_DONE_` manifest plus the pool's own current on-ledger slotIndex/nodeType/fee and
re-run preflight for the verification level), run the same strong idempotent write, and create the
receipt. Driving from the frozen draft is what lets a resumed publish reconstruct the EXACT intended
receipt (FU-2), so the field-verify against an existing receipt is exact rather than approximate.
This removes the completion-without-receipt foot-gun (an operator that crashed or never re-ran can
still publish, driven by the durable local record).

### Tighter coupling via a mixed transition (C-G, review S1): pursue behind a probe

The follow-up round split 2-1 on whether to build the mixed transition, and the split was factual,
not a values call. Two passes hold that a mixed create+replace across two document types in one
`documents.broadcast` batch is native to the SDK; one pass held it is not expressible, citing the
missing document-TRANSFER transition, which is a different, unsupported operation (transfer is not
replace). The resolution takes neither claim on faith: PROBE whether the operator can sign a MIXED
transition (create completionReceipt + replace pool forming->live) in one broadcast, like the v6/v7
transfer probes. If the probe and the live smoke pass, make the coupled transition the NORMAL v8
path (still doing a full share readback immediately before, since participant-owned shares cannot be
in that transition), which removes the live-without-receipt window entirely. If the probe fails, the
retain-until-confirmed frozen draft plus the recovery path above is the guaranteed fallback and
carries v8 unchanged. Either way the build is not blocked on settling the SDK question in advance.

PROBE ANSWER (live, 2026-07-15): the mixed transition is NOT possible on this Platform version,
and the limit is PLATFORM-side, not the SDK: the broadcast is rejected with "Amount of document
transitions must be less or equal to 1" (a documents batch carries at most one transition). So the
2-1 factual split resolved to the reviewer's outcome through neither side's stated mechanism. The
sequential flip-then-receipt path with the retained draft and manifest is the supported v8
mechanism; the probe stays in the code (it runs per completion and falls back loudly), and
FORMATION_NO_MIXED=1 skips it.

## Live validation (needs the devnet up)

1. `registerV8.cjs` publishes v8; persist `CONTRACT_V8_ID`.
2. A v8 formation end to end (create, reserve slots, complete); confirm the receipt lands with the
   right allocationRows/allocationHash, participantCount, targetDuffs, slotIndex, and the scoped
   l1Verification.
3. SQUATTING-REFUSAL probe: a non-operator identity attempts to create the receipt for the pool;
   confirm consensus refuses it (owner-only), so the operator's real receipt is never blocked.
4. IDEMPOTENCE-RESUME probe: re-run `complete` (and the `receipt` publish path); confirm the
   receipt is not duplicated and a field-verify passes.
5. `receipt <poolId>` reads it back and re-verifies the hash from the embedded rows.
6. Then the standard independent review of the whole v8 change.

## Effort and sequencing

The pure `allocationPreimage(contractId, manifest)` / `allocationHash` helper, its harness, the
published golden vector, and the offline `verifyReceiptAllocation` / `verify-allocation` wrapper are
small and offline; do them first as one commit plus review. The odd-length-hex fix (FU-3) is also
independent and can land in that same offline commit. The contract, wiring, formation write with the
frozen draft and strong idempotence, the recovery path, the mixed-transition probe, live publish,
and end-to-end validation are the bulk and need the devnet.
