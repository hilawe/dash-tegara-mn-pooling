# Tegara design

## Direction (decided 2026-07-09, supersedes the earlier DIP-first framing)

Tegara is an IMPLEMENTATION of a non-custodial CrowdNode-like system built on the primitives that
already exist or are already in flight: DIP-0026 (merged), the shared-collateral covenant proposal
dashpay/dips#187 (open, Draft), and Dash Platform (Layer 2). It is NOT a source of new consensus
proposals. Earlier turns drifted into drafting new DIPs (a quorum-governed collateral design, a Platform
reward-binding companion); those are retired to "explored, not pursued" (see the end of this document).
The reason for the pivot: #187 is the maintainer's own trustless covenant for shared collateral, and
building the product on top of it is both the soundest and the most aligned path. The malleability finding (reproduced live) is exactly the evidence #187's own Motivation cites for why a covenant is needed, so the work
already points here.

This document records the architecture and the honest layering. The clean-room exercise that preceded it
(`docs/CLEANROOM_STATUS.md`) remains valid as design-space evidence and is summarized at the end.

## The three layers

1. Principal custody, Layer 1: the shared-collateral covenant proposal (#187). Two to eight participants fund
   the collateral atomically in one registration transaction. The collateral output uses the exact 7-byte
   template `04445348437551` (`"DSHC" OP_DROP OP_TRUE`), spendable only by a consensus-enforced
   dissolution transaction (ProDisTx) that pays each participant's principal to an immutable refund script
   recorded at registration. No participant, operator, or update path can redirect another's principal,
   and exit is always possible (unilateral with an early-period penalty, or unanimous with none). #187
   adds ProDisTx, ProUpShareTx (update a participant's reward script), and ProUpSharedRegTx, extending the
   DIP-0026 version-4 ProRegTx payload with a share table. #187 is a strict superset of DIP-0026 and
   deploys with it in the same release (the v24 upgrade).
2. Reward split, Layer 1: DIP-0026's payout array (merged, PR #7340). The masternode owner reward splits
   on chain across the recorded shares. #187 reuses this directly for the participants' owner reward.
3. Accounting, membership, and retail reward distribution, Layer 2: Dash Platform. This is where Tegara
   adds value, because #187 caps at 8 participants and defers the Platform-side reward distribution.

## The honest layering, two tiers

- Co-owner tier (2 to 8 participants): pure #187. Trustless principal, consensus-enforced refunds and
  reward split. Needs the v24 upgrade (see below). This is a complete small-pool product on its own.
- Retail tier (thousands of funders, the CrowdNode case): put the Platform accounting layer BEHIND a
  #187 participant slot. Many retail sub-funders are tracked on Platform as decentralized state, and one
  #187 participant slot represents that pooled group on chain. The group's owner-reward share (paid on
  chain to that slot per DIP-0026) is then distributed to the sub-funders through the Platform credit
  rail, and each sub-funder withdraws their own credits. This is a product and Platform layer, not a
  consensus change.

The retail tier has two residuals, both bounded and stated plainly. The first is the reward-custody
window while a pooled identity holds an in-flight batch before distribution (the corpus finding SF-13).
It binds rewards only, and it is reduced by distributing at inflow with a single multi-recipient
asset-lock that credits each sub-funder directly, which the source confirms is possible
(`src/evo/assetlocktx.cpp:60-77`). This is a documented product-layer trust point, not a consensus claim.

The second residual is the intra-group PRINCIPAL split (the retail split boundary). The covenant delivers the group's
aggregate principal to the group participant's one refund script trustlessly, so principal is
custody-free down to the group-participant boundary. It is not custody-free below that boundary, where the
division of the aggregate among the sub-funders lands at one script whose controller holds the whole
group's principal at dissolution, and no trustless split is expressible under current primitives (one
refund script per participant, no covenant opcodes, and the malleability finding ruling out pre-signed splits). The
co-owner tier is unaffected. The sound resolution is a #187 refund-payout-array enhancement (reusing
DIP-0026's split mechanism for the refund, not just the reward); the buildable-today fallbacks each
carry a named trust point. Full analysis: `docs/RETAIL_PRINCIPAL_SPLIT.md`.

## Buildable today versus fork-gated

- Buildable today, no fork: the entire Layer 2 layer (the Platform data contract for the pool ledger and
  membership, the reward credit-rail, the funder client with its signed-action interface), plus a
  regtest harness.
- Fork-gated (the v24 upgrade, which carries DIP-0026 and #187, and is not yet scheduled on mainnet):
  #187's covenant custody. Prototyped on the fork in the container (Track B, complete and reviewed
  2026-07-10) and wired to the Layer 2 side (Track C, same day).
- Superseded 2026-07-10 (recorded so it is not revived): the earlier idea of a small-multisig custody
  stand-in for the prototype. The malleability finding shows the multisig-plus-pre-signed-refunds path is unsound on Dash,
  and the real covenant now runs on the fork, so no multisig custody exists anywhere in Tegara. Before
  v24 activates on a public network the answer is "no real principal", never "weaker custody".

## What Tegara is deliberately NOT doing

- No new consensus DIPs. The two drafts we produced are retired: `dip/dip-governed-collateral.md`
  (quorum-governed custody, an alternative the clean-room surfaced but which trusts the masternode quorum
  and competes with #187's trustlessness) and `dip/dip-platform-reward-distribution.md` (found UNSOUND as
  drafted, the consensus-limits analysis). They stay in the repo as explored alternatives and honest findings, not deliverables.
- The malleability finding stays as what motivates #187 (its own Motivation states it). The consensus-limits analysis stays as the honest
  note on why consensus-enforced retail reward-binding (as the public ask literally words it) is a bigger change than it
  looks, and is therefore out of Tegara's scope; the retail reward path is handled at the product layer.

## Non-custodial trust invariant (scoped to direct #187 participants, the retail split boundary)

For a DIRECT #187 participant (a co-owner-tier funder, or any beneficial owner represented by their
own covenant share), principal recovery must never depend on a coordinator, an operator, a committee's
honesty, or Layer 2 liveness. Principal moves only through #187's consensus-enforced dissolution back
to that participant's recorded refund script. Every Layer 2 trust point and the credit-pool throttle
bound rewards only. For a direct participant the worst case for principal is a liveness delay (waiting
for a dissolution), never a loss. If a change violates this for a direct participant, it is a
regression.

The invariant does NOT extend below the participant boundary (the retail split). When a retail group is represented
by ONE participant slot, the covenant returns the group's aggregate principal to the group's one refund
script, and the split among the group's sub-funders is enforced by no consensus rule. For a sub-funder
who is not their own covenant share, the controller of the group refund script can cause loss or
indefinite withholding at dissolution, so the invariant's "never a loss" holds only down to the
group-participant boundary. The distinction that matters is not group size but whether each beneficial
owner is represented by their own covenant share. See `docs/RETAIL_PRINCIPAL_SPLIT.md`.

## Technology

- Layer 2 and the client: TypeScript on Node, using the Dash Platform SDK (`dash`, v7). A local Platform
  network via `dashmate`, or testnet.
- Layer 1: `dashd` regtest in a Linux container, driven via `dash-cli` (the standing workflow, since a
  native self-built daemon is force-terminated on this Mac). The #187 covenant prototype runs on the fork
  build.
- Monorepo under `tegara/` for now.

## Clean-room exercise, retained as evidence (condensed)

Three independent frontier models designed the system from the requirements alone. They converged on the
requirements-forced core this design keeps: principal on Layer 1, accounting and membership on Platform,
rewards separated from principal and routed through Platform at scale, operator paid from rewards. They
also converged on a point that shaped the decision above: retail-scale genuinely-trustless custody is not
free on today's Dash (all three reached for a protocol change and a network-trust model). Since #187
already provides trustless covenant custody for the co-owner tier, Tegara adopts it rather than pursuing
the clean-room's quorum-governed alternative. Full record and the divergences: `docs/CLEANROOM_STATUS.md`.
