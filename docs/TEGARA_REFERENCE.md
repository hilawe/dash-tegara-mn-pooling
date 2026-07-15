# Tegara, the design and results of a non-custodial pooled-collateral reference implementation for Dash

One document for the whole build. It consolidates the design decisions, the shipped
mechanisms, the live results, the review history, and the honest limits of the Tegara
reference implementation, drawing on the per-track records under `tegara/docs/`, the
findings logs in the repository root, and the session history in the private session log. Where
this document and a per-track record disagree, the per-track record is the primary source
and this document has a defect to fix. Written 2026-07-12 and revised the same day after an
independent review flagged that an earlier draft oversold the end-to-end retail path. The
qualifications that review added are carried in the text below and gathered in section 8.

## 0. What is a prototype here, and what is not

Read this before the claims. Tegara is a reference implementation and a set of live
prototypes, not a deployed product, and two things about its foundation shape every claim
that follows. First, its principal-safety construction depends on the shared-collateral
covenant of dashpay/dips#187, which is an unmerged draft, and on the version 24 Dash hard
fork that would carry it, which is unscheduled. Tegara adds no new consensus rule of its
own, but it cannot run on today's released consensus rules either. Second, the Layer 1 and
Layer 2 halves were exercised on two separate chains connected by a trusted relay (section
5), not as one integrated system. With those two facts in hand, the rest of the document is
accurate about what was built and proven.

## 1. What Tegara is and why it exists

Tegara is a private, open reference implementation of non-custodial pooled masternode
collateral for Dash. A group of members pools toward the 1000 or 4000 DASH a masternode
requires, members hold their own Platform identity keys, coordination happens on Dash
Platform, and no pooled custodial identity ever holds the group's funds on the Platform
side. The word "non-custodial" carries a boundary this document is careful about. At the
level of a masternode's participants, each participant's principal is protected by a
covenant-fixed refund script (section 4.1), and on the Platform side no intermediary
identity holds member funds. Where a single covenant participant is itself a group of
retail sub-funders (the Track C design), the division of that participant's refunded
principal among its sub-funders is an open product-layer question the prototype does not
solve (section 4.1 and section 8). So "non-custodial" is demonstrated at the participant
boundary and is still open inside a retail group.

The project exists because the incumbent pooling service is winding down its custodial
model and its successor may not be open source. Tegara preserves the non-custodial design
as free software for the Dash network in its own right. The requirements come from three
sources, in a fixed order of authority. The soundness corpus (the CN- and SF- findings
logs) decides how anything is built. The successor project's public asks describe what
users need, and is never treated as architecture, because it predates the primitives this
design stands on. The archived knowledge base of the incumbent service supplies the product
surface, the everyday verbs a pooling member actually uses.

## 2. The architecture in one paragraph

Layer 1 holds the money and Layer 2 holds the coordination. On L1, the covenant of #187
locks the pooled collateral so that the only way it moves is a consensus-enforced
dissolution paying each participant's immutable refund script, and DIP-0026 splits the
masternode's rewards across participant payout scripts at the protocol level. On L2 (Dash
Platform), a data contract called the pool ledger records pools, shares, membership
requests, reward accruals, settlements, vote preferences, and slot reservations, all as
documents signed by the owning member's identity, and the L2 never holds a pooled custodial
balance. Reward credits reach members through per-recipient asset-lock outputs, so no pooled
Platform identity sits in the reward path. That is narrower than "no intermediary at any
point", because the reward flow has an operator honesty window on L1, where the designated
reward output is controlled by the rail's own non-wallet key between the coinbase payment
and the asset-lock transaction that fans it out (section 4.2 and section 8). The one construction
this project established as unsound and never uses is multisig custody with pre-signed
refunds, which fails on Dash because first-party transaction malleability lets a participant
invalidate the refund chain (the malleability finding, reproduced live on regtest and reviewed by three
model families).

## 3. How the design was chosen

The design was not improvised. A clean-room exercise ran first, where the requirements were
packaged without any architecture, independent designs were produced from the requirements
alone, and the designs were compared only after being committed. The comparison converged
on quorum-governed collateral requiring a consensus fork, which competes with the covenant
approach that #187 already specifies, so the fork path was retired and the settled direction
became implementation of DIP-0026 plus #187 plus Platform. Tegara therefore proposes no new
Dash Improvement Proposal, but that creates a dependency worth naming. #187 is an unmerged
draft and its v24 activation is unscheduled, so "no new consensus rules" describes Tegara's
own scope, not a claim that it runs on released consensus code. Two explored-but-not-pursued DIP
drafts are kept under `tegara/dip/` for the record. The full status of the clean-room
exercise is in `docs/CLEANROOM_STATUS.md`.

## 4. What was built, layer by layer

### 4.1 The L1 covenant prototype (Track B and Track C)

The shared-collateral covenant was built end to end on a fork branch off the merged DIP-0026
commit. Its functional test registers a two-participant shared masternode, shows a normal
transaction cannot spend the covenant-locked collateral, and dissolves unilaterally so the
passive participant is refunded in full to their immutable refund script, keyed by proTxHash
and never by a malleable transaction id. That is the malleability-finding closure demonstrated live at the
participant boundary. The retail vertical (Track C) then had a real two-slot shared
masternode earn its owner reward in the coinbase, asserted the amount-weighted DIP-0026
split exactly, and ended with a unilateral dissolution refunding the passive slot.

The important qualification is the retail grouping. In Track C a whole retail group is
represented by one covenant participant slot, and that slot's refund script is a single
designated address. The
sub-funders inside the group do not each hold an individual covenant refund script, so how a
refunded group slot's principal is divided among its sub-funders is an open product-layer
question, which `tegara/docs/TRACK_C_RETAIL_VERTICAL.md` and `tegara/bridge/README.md` both
state plainly. So Track C demonstrates covenant-protected principal at the slot boundary and
leaves the intra-group split unsolved. The fork code lives in a sibling worktree and is
captured as format-patch files under `tegara/l1/187-prototype-commits/`.

### 4.2 The L2 pool ledger and its versions

The pool ledger grew through published contract versions, and the version history is itself
a record of what Platform can and cannot enforce. Versions v1 through v6 are each a strict
superset of the one before, and v7 is deliberately not. The list is worth stating precisely,
because later replay and reconstruction claims depend on which version added what.

- v1 holds the core types (pool, share, membershipRequest, rewardAccrual, votePreference).
- v2 adds the unique accrual index and records each funder's share weight at distribution
  time, which is what makes an epoch reconstructible.
- v3 carries v2's reconstructible accruals forward and adds on-ledger settlements.
- v4 adds the accrual kind to the unique key and a by-height index, after a live lesson
  about Platform's query-depth rule (a query may leave at most two of an index's properties
  unconstrained).
- v5 adds the pool lifecycle status, join provenance, member-supplied reward scripts, and
  one-hop vote delegation.
- v6 adds the pledgeSlot reservation with a unique (poolId, slotNo) index, so two members
  racing for the last free slot cannot both win. That duplicate rejection is the whole
  consensus guarantee, a scope the review process forced into words (section 6).
- v7 is a replacement, not a superset. It moves the slot economics onto the pool document
  (slotDuffs and slotCount as creation-time constants), removes the claim-supplied amount,
  and changes pledgeSlot from immutable to mutable. The mutability is forced by the software
  development kit (SDK), which cannot delete documents of immutable types (section 7), so
  making a claim cancellable meant making the document mutable.

The credit rail distributes epoch rewards as one asset-lock transaction with one credit
output per recipient, verified live for credit-output indices beyond zero with hand-built
outpoints. Per-recipient crediting at inflow needs no pooled Platform identity, which is the
SF-13-avoiding property. It is not a claim of zero operator control anywhere in the reward
path, because the mirrored reward UTXO is held by the rail's non-wallet key until the
asset-lock spends it, an operator honesty window Track C states explicitly. A scale run pushed eight
observations through the rail, refused every replay probe, and reconciled the whole ledger
with a read-only audit (15 pools, 12 distributed epochs, zero inconsistencies).

### 4.3 The member product surface

The funder client is a thin router over one module per command, and it covers the lifecycle
the incumbent's knowledge base defines. The commands are onboard (probe deposit first, then
the remainder), deposit, join and exit, compound with a crash-recoverable journal, autopay,
watch, limits, portfolio, earnings, withdraw, vote with delegation, pledge on the pre-slot
ledgers, and reserve/slots on the slot-book ledgers. Every write is signed by the member's
own identity.
Pool formation is operator-coordinated and its code path is designed to be non-custodial
(members reserve slots on the ledger, funds move only inside the atomic L1 registration, and
completion drives from a committed manifest with field-by-field preflight of every claim
before any mutation, flipping the pool live only after every share exists and the weights
read back at exactly 10000 basis points). Two qualifications stay visible here. The formation
demo runs one shared wallet for every identity and uses an explicit unverified-L1 override,
and the fully verified Platform-to-fork atomic registration was not demonstrated as one
integrated transaction (it is the shape that was built and driven, with the L1 verification
gated by the override in the demo). The finalized manifest is retained as
the durable formation record.

### 4.4 Governance

The cast-receipt contract (three versions) lets the operator publish how member weight was
cast on L1 governance proposals, snapshot-first so members can verify the operator's math
from on-ledger state. The verification core is offline-testable (57 cases) and its honest
ceiling is settled and stated. Member observations of L1 votes are corroboration and
surfacing, never automated enforcement, because without the vote signature no observation
can be told from a fabricated one. Turning the watcher into enforcement needs an upstream
change (a verbose vote-signature exposure in Core), recorded as the one modest ask this
project would take to the Core repository.

### 4.5 Keys and recovery

A member's seed recovers everything that is derived from it, which is the identity's default
keys and its holdings, and that covers the ordinary "lost laptop, kept the paper backup"
case fully. It does not recover things generated outside the seed, namely the separately
generated recovery keys, a member-supplied external reward-script key, or an external
covenant-refund key, each of which `KEYS_AND_RECOVERY.md` qualifies. For the seedless case, the `addkey`
command adds a pair of recovery keys generated outside the seed (authentication at the high
security level, transfer at critical), and the recovery client then proves the seedless story
live with no mnemonic in the process. `status` proves key possession against the on-chain
identity (purpose-checked and disabled-checked), `vote` writes and updates a preference, and
`withdraw` moves credits back to L1. The last two run through a low-level signer that matches
the on-chain key by public-key bytes and purpose, builds transitions through the same Dash
Platform Protocol (DPP) factories the SDK uses, signs with the raw recovery key, and
broadcasts through the SDK's own transport. Key management stays with the seed's master key by
design, so a recovery key cannot rotate keys. The full story is in `KEYS_AND_RECOVERY.md`.

### 4.6 The operation-log state store

All owned durable state (journals, watermarks, manifests, rail and matcher state) lives in
per-key atomically-replaced files under a state directory beside the env file, so journal
writes never rewrite the file carrying the wallet mnemonic. The store's crash and mount story
is defended in depth. A migration intent marker lands before the first migration write, a
random store id pairs the env file to its directory (checked on every read and write),
writers refuse to create the directory implicitly, an ambiguous legacy directory is refused
rather than adopted (with an explicit adoption command for the genuine case), and a shared
lock serializes every mutation with contention surfacing as a loud refusal. Two offline
harnesses pin this. A 40-case matrix covers the guard conditions, and a fault-injection
harness crashes real execution after every mutating filesystem operation of three write paths
and asserts, under both mount conditions, that no owned value is ever silently lost and every
retry converges.

## 5. Live results, and what "live" means here

Two chains, not one. The #187 covenant and the retail vertical ran on the fork's regtest
chain (a container build of the DIP-0026 fork). The Platform layer ran on a stock-Core
dashmate devnet. They were connected by a trusted relay, a JSON epoch observation handed
between the two environments plus a mirrored reward UTXO. There was no trustless cross-chain
verification, and the bridge record says so directly. What was demonstrated is the
production-path shape, on the understanding that in production both halves share one chain
under the v24 upgrade and no cross-chain relay exists (an intra-chain observation and
operator-action boundary still remains, which is why the trustless-relay work stays on the
forward list in section 9). The operation-store and governance-verifier
harnesses are offline tests, not live devnet runs. With that framing, the strongest single
demonstrations are:

- The resilience run stopped the entire Platform coordination layer and showed principal
  exiting through the L1 covenant anyway, with credits intact after restart. The coordination
  layer can die without touching the money, which is the design's central claim at the
  participant boundary.
- The duplicate-claim probe broadcast a second claim on a taken slot directly, bypassing the
  client, and the ledger rejected it with the unique-index error.
- The claim-mutation probe replaced a committed claim in place after the formation manifest
  was frozen, and completion refused with a field-level mismatch report. The probe's own first
  attempt is a recorded honest result, since it wrote a value-equal replacement and completion
  correctly proceeded.
- The seedless withdrawal moved 0.1 DASH out of Platform signed by a recovery key alone, with
  the balance readback confirming the debit.
- The formation L1 check reported, for a demo pool whose node hash was never registered,
  exactly the truth, that Core does not report this node.

## 6. How the work was reviewed, and what that process caught

Non-trivial implementation changes went through independent review by a different model
family, and architecture-bearing work went to three (one command-line channel, two packet
reviewers working from complete inline source with no repository access). Verdicts were
resolved by verification against the code, never by vote. This consolidation document itself
went through that review, which is what added the qualifications in sections 0, 1, 4.1, 4.2,
4.5, 5, and 8. Three episodes define the discipline:

- The covenant prototype's review found an int64 range error in the split math that one
  reviewer missed and two caught independently.
- The refactors round produced a BLOCK against two APPROVEs, where both approving reviewers
  asserted in prose the exact contrary of a finding that verification confirmed (the legacy
  store-adoption gap), and both independently reproduced a second finding's error (calling
  undeletable claims deletable). The findings stood, the fixes landed, and the follow-up round
  closed three-for-three.
- The review process disciplines claims, not just code. The v6 reservation's "closed at
  consensus" wording was narrowed to the precise guarantee (duplicate slot claims are rejected
  at consensus, conformance is verified at completion, and completion is operator-coordinated,
  not consensus-atomic with reservation), and several recovery-story sentences were rewritten
  until they claimed exactly what the code demonstrates.

The findings logs are the private findings log and the private review records in the repository root, one per round, each carrying the verdicts, the cross-checks,
and the fix history.

## 7. The SDK capability boundary

The implementation runs on the Dash JavaScript SDK (dash 7.0.0, wasm-dpp 4.0.0), and a
recurring result of this project is the precise map of where that SDK ends. Each entry below
was established empirically:

1. The high-level write path signs only for wallet-derived identities. Its signer resolves
   private keys through the hierarchical-deterministic wallet, so an imported raw key draws an
   association error even when that key is registered on the identity. The protocol permits any
   identity key to author a transition; the workaround is the low-level signer of section 4.5,
   which this project built.
2. Documents of immutable types cannot be deleted. The delete transition requires a revision
   the immutable type does not carry, the factory raises a revision-absent error, and the
   type-level deletion flag changes nothing. This forced v7's mutable claims.
3. Document transfer and purchase are not buildable. The factory silently ignores the
   transfer, update-price, and purchase action sets, and no transfer transition class is
   exported for low-level construction, although the protocol has the transitions and the error
   types for them exist in the bindings. This blocks the operator slot-inventory design (v8)
   until the SDK catches up.
4. A from-key wallet's fee state can read zero before core sync populates it, which flows into
   transition construction as an invalid fee. Clamped to the protocol floor.
5. Drive refuses document queries that leave more than two of an index's properties
   unconstrained, which shaped the v4 index design.
6. The SDK's convenience paths and its low-level pieces disagree about visibility: the pieces
   needed to sign and broadcast without a wallet exist and work, but nothing exposes them as a
   supported path, so every step of section 4.5 required reading the SDK's own internals.

The pattern behind these is one assumption baked through the convenience layer, that the wallet
is the identity. Everything this project needed beyond that assumption existed in the lower
layers and had to be reached directly.

## 8. Honest limits

The five most consequential are the ones a newcomer's trust assessment turns on, so they come
first:

- CONSENSUS DEPENDENCY. Tegara's principal safety depends on the unmerged #187 covenant and the
  unscheduled v24 hard fork. It cannot run on today's released consensus rules.
- TRUSTED RELAY. The L1 and L2 halves were joined by a trusted JSON observation and a mirrored
  UTXO across two chains, with no trustless cross-chain verification. Only the production-path
  shape was demonstrated.
- INTRA-GROUP PRINCIPAL SPLIT UNSOLVED (the retail split boundary). A retail group is one covenant slot behind one
  refund address, so principal is trustless down to the group-participant boundary but not
  below it; dividing that slot's refunded principal among its sub-funders lands at one
  controller and has no trustless solution under current primitives. The sound resolution is
  a #187 refund-payout-array enhancement. Full analysis: `RETAIL_PRINCIPAL_SPLIT.md`.
- REWARD HONESTY WINDOW. The mirrored reward UTXO is controlled by the rail's non-wallet key
  between the coinbase payment and the asset-lock fan-out. "No pooled Platform identity" is
  proven; "no operator control at any point" is not.
- DEMO CONVENIENCES. The formation demo runs one wallet for every identity and gates the L1
  registration with an explicit unverified override, so key-separation and full L1 verification
  are properties of the construction, not of the demo environment.

The narrower limits:

- Completion is operator-coordinated. Platform validation is per-document, so no schema can
  bind a claim to a pool's lifecycle or another document's fields. The window between the final
  preflight read and the share broadcast is real and stated where it matters.
- The vote watcher corroborates and surfaces, it does not enforce (section 4.4).
- v6 slot claims are permanent (entry 2 of section 7). The v6 register script says this plainly
  and new slot books belong on v7.

## 9. Recorded forward work

- The v8 bundle, waiting on SDK document-transfer support: the operator-created slot inventory
  members take over (a shared conflict point for reservation and completion), the on-ledger
  completion receipt, and the beneficiary-transfer discussion.
- A trustless L1-to-L2 relay to replace the trusted observation bridge (the standing bridge
  design question).
- The intra-group principal-split resolution for retail groups (the retail split boundary), sound direction a #187
  refund-payout-array enhancement, analysis in `RETAIL_PRINCIPAL_SPLIT.md`.
- The upstream vote-signature exposure in Core, the only path from corroboration to enforcement
  for the governance watcher.
- A future contract revision bundling the accumulated schema notes.

## 10. Reading order for a newcomer

1. This document, section 0 first.
2. `tegara/DESIGN.md` and `docs/CLEANROOM_STATUS.md` for how the direction was chosen.
3. the private findings log for why the unsound paths are closed.
4. `tegara/docs/TRACK_C_RETAIL_VERTICAL.md` and `tegara/bridge/README.md` for the retail
   design and its trusted-relay boundary, and `tegara/docs/SCALE_RUN_2026-07-10.md` for the
   deepest live rail run.
5. `KEYS_AND_RECOVERY.md` for the member-safety story.
6. The the private review records, newest first, for how each layer earned its state.
