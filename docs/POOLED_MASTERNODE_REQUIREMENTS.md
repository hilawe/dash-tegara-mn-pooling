# Requirements for a non-custodial pooled masternode service

@hilawe. 2026-09-19.

Shared with other teams building in this space, so that independent implementations converge on
the same properties rather than each discovering the same limits separately. These are
requirements and the reasoning behind them. They are not a specification, and nothing here
prescribes a particular mechanism. Where a constraint exists because the chain forces it, the
reason is given so you can check it rather than take it on trust.

## The five constraints that cannot be traded away

C1. NO PARTY TAKES CUSTODY OF ANOTHER MEMBER'S FUNDS AT ANY POINT, including transiently during
a settlement. Not the operator, not a coordinator, not a temporary escrow controlled by one
party. This is the property that separates the product from the custodial generation of pooling
services, and a design that holds it everywhere except during one brief window has not held it.

C2. EVERY STATE TRANSITION THAT CHANGES A MEMBER'S POSITION IS SIGNED BY THAT MEMBER'S OWN KEY.
No party signs on another member's behalf and no shared signer exists.

C3. NO MULTISIG-PLUS-PRE-SIGNED-REFUND CUSTODY. This one costs teams the most time, so the
reason matters. Dash has no SegWit, so a transaction identifier commits to its input signatures.
Any input owner can re-sign their own input to produce a different valid identifier for the same
economic transaction. Refunds pre-signed against the original identifier are then unusable, and
the member relying on them has no path back. The construction reads as safe and is not, and the
failure needs only one participant who declines to cooperate. Treat it as unavailable rather
than as a pattern to harden.

C4. THE L1 OWNER KEY AND REFUND DESTINATION ARE IMMUTABLE once the collateral construction is
registered. A change of position cannot be implemented by editing those fields, so any design for
direct participants has to work within that or say plainly that it requires dissolution and
re-registration.

C5. BUILD ON PRIMITIVES THAT EXIST TODAY. If a path genuinely needs a consensus change that has
not shipped, say so rather than designing around an assumption that it will arrive.

## The trust invariant everything else serves

Principal recovery never depends on second-layer liveness or on any actor in the reward path.

Stated concretely, principal moves only through the collateral construction's own refund path,
back to the people who funded it. No second-layer state, no platform identity and no bridge key
can move principal. Every second-layer custody point and every throttle bounds rewards only. The
worst outcome for principal is a liveness cost, where an early exit is unavailable and a member
waits for a timelocked or permissionless fallback, and never a loss.

A change that violates this is a regression rather than a feature, whatever else it improves. We
treat it as the single load-bearing property, and it is worth writing into your own review
criteria in those terms.

## The six properties a finished system must have

R1. VALUE ACTUALLY SETTLES. A joining member's contribution reaches the leaving member or the
pool as value bound to an on-chain fact, a payment, an asset lock or a credit movement carrying a
transition identifier. An amount written into a record with nothing backing it is not settlement.

R2. ATOMIC OR FAIL-SAFE. Either the leaver gives up the position and the joiner gains it with
value settled, or neither happens. A crash or an uncooperative counterparty must never leave the
leaver without a position and without value, nor the joiner having paid with no position. Every
partial state recovers to one of the two clean ends.

R3. NO QUEUE-WEDGING. One invalid or unmatchable pending request must not block unrelated valid
settlements in the same pool.

R4. VERIFIABLE REWARD DESTINATION. A member's recorded reward destination is one that member
controls, bound to their request and to the settlement record, and reproducible exactly by an
independent checker.

R5. INDEPENDENT VERIFIABILITY. A third party holding only public first-layer and second-layer
state can confirm that a completed settlement moved value and changed the position, without
trusting the operator's word for any step. In practice this means publishing enough that someone
else can recompute your answer, not publishing a summary of it.

R6. LIVENESS INDEPENDENT OF THE OPERATOR. Settlement completes, or fails safe, without the
operator being online, cooperative or honest. The operator may coordinate and observe. The
operator must not be able to block, redirect or freeze a settlement.

## What the chain gives you, and the ceiling it imposes

The reward payout array caps at EIGHT destinations in the deployed code, not the thirty-two some
draft text suggests. That single number shapes the whole product. A regular masternode at 1000
DASH divided eight ways puts the floor near 125 DASH per participant, and the higher tier at 4000
DASH divides no more finely. Any service promising small-deposit participation with direct
on-chain payout shares is either using a different mechanism or is not describing what the chain
does.

Serving more members than the cap allows therefore requires a second-layer accounting rail that
receives one on-chain share and distributes within it. That rail is where custody quietly returns
if the design is careless, which is why the trust invariant above restricts it to rewards and
keeps principal on the first layer.

The decentralized masternode shares work merged into Dash Core's development branch on
2026-09-18. It is not in a released version yet and its activation is gated behind the next hard
fork, so treat it as a primitive arriving rather than one you can deploy against today. We expect
to build on it and would rather compare notes than duplicate the integration work.

## Governance participation

Pooled members must keep a real vote. A masternode casts one indivisible vote, so a member's
fractional holding has no natural expression, and the mechanism that solves it is to tally the
members who express a preference and let the balances of those who do not follow that result.
Participation then carries the pool's weight, which gives a small holder a genuine say.
Proportional outcomes across a pool come from operating several nodes and splitting their votes to
match the tally rather than from arithmetic on any single node.

The non-custodial gain here is checkability. If preferences and balances are published, any member
can recompute the tally and confirm the votes cast on chain match it.

## Product honesty, which we treat as a requirement rather than marketing

Two limits should be stated plainly to users rather than softened. The participation floor is real
and follows from the payout cap. On-demand exit does not exist in the first version, because a
position is bound to a collateral construction that cannot be edited, and pretending otherwise
sets up the failure mode that the pre-signed refund pattern already demonstrates.

We also avoid the vocabulary of financial instruments when describing member contributions, and
use funder, member, share, pool, collateral and contribution instead. The regulatory framing in
Europe is live rather than theoretical, and it is the stated reason the previous custodial service
is winding down.

## Where you have freedom

Nothing above prescribes your accounting model, your client, your key handling or your settlement
choreography. The constraints come from the chain and from one custody principle. The properties
are testable statements about the finished system. If your design meets them by a different route,
that is a useful result and worth comparing.

The one request in return is that R5 be taken literally. A service that cannot be checked by an
outsider asks its members for exactly the trust the non-custodial model was meant to remove.
