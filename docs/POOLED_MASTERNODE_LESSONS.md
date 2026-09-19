# What we learned building a non-custodial pooled masternode service

@hilawe. 2026-09-19. Companion to the requirements note. That one states what a finished system
must do. This one states what we found out along the way, so you can skip the parts that cost us
the most.

Everything below was either read from Dash source, verified against a running node, or produced by
a live run on a local network. Where something is an inference rather than a measurement, it says
so. Where we got something wrong and later corrected it, the correction is included, because the
wrong version is usually the intuitive one and you may reach for it too.

## 1. Chain facts that shape the design space

NO SEGWIT MEANS TRANSACTION IDENTIFIERS ARE MALLEABLE BY THE INPUT OWNERS. A transaction
identifier commits to its input signatures, so any input owner can re-sign to produce a different
valid identifier for the same economic transaction. Every construction that pre-signs a refund
against an expected identifier inherits this. One participant declining to cooperate is enough.
This is the single most expensive thing to learn late, because the construction looks correct
until someone tests the uncooperative case.

A REGISTRATION USING EXTERNAL COLLATERAL CAN BE REPLACED BY ANYONE WHO CAN SIGN WITH THE
COLLATERAL KEY. That is long-standing consensus behavior rather than a defect, and it rules out a
whole family of pooling constructions where the collateral sits outside the registration. It is
also why the shared-collateral work mandates internal collateral.

THE REWARD PAYOUT ARRAY CAPS AT EIGHT DESTINATIONS in deployed code. Draft text elsewhere mentions
thirty-two. Eight is what the node enforces, and the difference decides your product. A regular
node at 1000 DASH split eight ways puts the participation floor near 125 DASH.

CORE REQUIRES A MINIMUM PER OWNER SHARE of 100 DASH. Uneven contributions and remainders have to
respect it, so your share table cannot allocate arbitrarily small slices even within the cap.

CONSENSUS REFUSES A CREDIT TRANSFER WHERE SENDER AND RECIPIENT ARE THE SAME IDENTITY. If a pool
member is also the identity that receives the pool's income, their own share can never be paid by
a transfer, at any amount. The settlement for that member has to be defined as requiring no
transfer at all, and any completeness rule that demands a receipt for every member will otherwise
never be satisfiable for that pool. We hit this on a live run, not in review.

THERE IS A MINIMUM TRANSFER AMOUNT. Entitlements below it cannot be paid as transfers. A procedure
that reserves and broadcasts them anyway wedges the accrual with an on-ledger reservation
consumed. Carry the remainder forward instead, and decide the carry rule before you build.

TWO ENCODING DETAILS THAT COST DAYS. Dash block hashes are X11 rather than double SHA-256. Dash
BLS signatures verify only under the legacy scheme, which lives in the `@dashevo/bls` library
inside its basic scheme namespace. Libraries implementing the IETF basic scheme will never verify
them, however correct they look.

## 2. Platform facts

NATIVE DOCUMENT TRANSFER, PURCHASE AND PRICE-UPDATE TRANSITIONS EXIST. We designed an entire
settlement apparatus to work around a limitation that is not there. The document model carries a
transferable flag, a transfer transition that moves a document to a recipient identity, a purchase
transition with a price and a price-too-low error, and an update-price transition. Check these
before designing around their absence.

THE OFFICIAL JAVASCRIPT SDK DOES NOT EXPOSE THE TRADE BUILDERS. The independent
`dash-platform-sdk` package on npm does, covering all six document transitions. If you are on
JavaScript and need transfer or purchase, that is where to look first. Its own documentation
describes input validation and error handling as happy-path, so wrap it defensively at any
boundary that matters.

ONLY REGISTERED INDICES ARE QUERYABLE, AND THE CLAUSE MUST MATCH ONE. A query whose where-clause
does not correspond to a registered index is refused with an error naming the valid indices. This
is not a performance hint, it is a hard constraint on your schema design, and it means your query
shapes and your contract indices have to be designed together. We found this by a refusal on a
receipt read whose clause no registered index served.

PROOF METADATA IS NOT EXPOSED BY DEFAULT ON EVERY ROUTE. Getting verifiable reads meant patching
several SDK routes to retain and surface the response metadata so a caller can confirm a read
actually passed through the proof-verifying path. Design for the possibility that a served answer
carries no proof, and make a read without one unresolved rather than accepted.

THE SYSTEM REWARD-SHARES CONTRACT HONORS ONE SHARE PER MASTERNODE. There is a system data contract
for masternode reward shares, with a document type carrying a recipient identity and a percentage.
On the version we tested, one share per node is honored, so an evolution pool's Platform credit
stream cannot be split among members non-custodially by that route today. This was a real
disappointment and it forced the accounting rail described below.

EPOCH HISTORY CAN BE LEGITIMATELY SPARSE. The epoch index is derived from elapsed block time
rather than incremented, and the platform accounts for skipped epochs. Any enumeration that
assumes every integer epoch carries a record will refuse forever after a gap. We are repairing
exactly this in our own code as of today, and it is worth designing correctly from the start.
Relatedly, a returned page shorter than the requested page size does not establish the end of
history on a sparse route.

THE FIRST PAYOUT MEMBER CONTROLS AN EVOLUTION POOL'S PLATFORM REWARD BALANCE, not the operator.
We had assumed the operator held it. If your design assigns that balance to the wrong party, the
error surfaces only once real rewards accrue.

ONE CORRECTION WORTH PASSING ON. We concluded at one point that the epoch payout to proposers
excluded the Core subsidy portion, and that was refuted at source. It includes it. If your
economics model rests on the split, read the source rather than the summaries.

## 3. Patterns we tried that do not hold

MULTISIG COLLATERAL WITH PRE-SIGNED REFUNDS. Beyond the malleability problem, this family carries
several independent failures. Signature-hash flag combinations that seem to isolate inputs create
footguns. Fixed-fee refunds cannot be bumped, because Dash has no replace-by-fee, so a refund
becomes unspendable if fees move. The child-pays-for-parent repair needs a stable parent
identifier, which is the thing malleability removes. Two spend paths cannot share one refund
commitment when their time locks conflict. We spent weeks here and the family does not recover.

TRUSTLESS COLLATERAL ALONE DOES NOT CLOSE REWARD REDIRECTION. Owner-key redirection survives a
trustless collateral construction combined with multi-party payouts, and operator-key authority
sits outside the funder commitment, so an operator can capture rewards without touching principal.
Whatever you build for principal, treat reward destination authority as a separate problem with
its own answer.

FORBIDDING THE OPERATOR-UPDATE TRANSACTION REMOVES THE ONLY OPERATOR-REPLACEMENT PATH. Locking a
pool down for safety can leave it unable to replace a failed operator. Decide deliberately which
of the two you are trading.

A COVENANT OPCODE CARRIES A CONSENSUS REVIEW SURFACE OF ITS OWN, and a claim that a covenant is
non-recursive needs enforcement rather than assertion. If you go down this path, expect the review
to be about the opcode rather than about your product.

## 4. The architecture we settled on

Principal lives on the first layer and rewards live on the second, and the boundary between them
is the entire trust argument.

Principal moves only through the collateral construction's own refund path, back to the people who
funded it. No second-layer state, no platform identity and no bridge key can move it. Everything
on the second layer bounds rewards only. The worst outcome for principal is a liveness cost, where
an exit is unavailable and a member waits for a timelocked or permissionless fallback, and never a
loss.

We treat a change that violates this as a regression rather than a feature. It is worth adopting
as an explicit review criterion, because the violations are usually convenient rather than
obviously wrong.

## 5. The reward rail, and why it exists

The eight-destination cap means a pool serving more members than that receives one on-chain share
and distributes within it. That internal distribution is where custody quietly returns, which is
why the trust invariant confines it to rewards.

What the rail needs, from our experience: an epoch header recording the period's figures, a
per-member accrual derived from the recorded shares, a reservation before any transfer so a crash
cannot double-pay, the transfer itself, a capture of the resulting proof, and a receipt document
binding it all together. It also needs a journal that survives a crash at any point, because the
recovery cases are where the real defects live.

Two rules we learned to state early. A member's entitlement below the minimum transfer amount
carries forward rather than being reserved and broadcast. A member whose identity is the income
identity settles without a transfer, and the completeness rule excludes them rather than waiting
for a receipt that consensus will never allow.

## 6. Governance

A masternode casts one indivisible vote, so a fractional holding has no natural expression. The
mechanism that gives small holders a real say is to tally the members who express a preference and
let the balances of everyone else follow that result, which means participation carries the pool's
weight. Proportional outcomes across a pool come from running several nodes and splitting their
votes to match the tally, not from arithmetic on one node.

Publishing the preferences and balances is what makes it checkable, so any member can recompute
the tally and confirm the votes cast on chain match it.

## 7. The verification discipline, which is the part we would keep unchanged

Three rules earned their place, and all three came from real defects rather than from theory.

A PATH THAT DID NOT PERFORM A CHECK MUST NEVER RETURN AN AFFIRMATIVE RESULT. Skipped, unavailable,
not attempted and routed around all mean refusal or an explicit unknown. We found several places where
a component reported success alongside a flag recording that it had not actually checked, and a
flag nobody reads is decoration rather than a control.

A SERVED ANSWER IS NOT A VERIFIED ANSWER. Distinguish a read that carried its proof from one that
merely arrived, and treat the latter as unresolved. We had a component call a verifier over
evidence the transport had already marked unproved, producing a positive cryptographic label over
an answer nobody could vouch for.

A CONTROL CANNOT SUPPORT A CLAIM THAT VARIES AMONG INPUTS PRODUCING THE SAME OBSERVATION. The test
is to construct two inputs that look identical to your check but require different outcomes. If
you can build that pair, the check is not evidence for the claim. This caught more real defects
than any other single idea.

## 8. What we have not solved

ON-DEMAND EXIT DOES NOT EXIST in our first version. A position is bound to a collateral
construction whose owner key and refund destination are immutable once registered, so changing who
holds a position is not an edit. We state that to users rather than implying otherwise.

RETAIL SCALE BELOW THE FLOOR is out of reach without the second-layer rail carrying much more
weight than we are willing to give it today.

SPLITTING AN EVOLUTION POOL'S PLATFORM CREDIT STREAM among members non-custodially is not possible
by the system reward-shares route on the version we tested.

DISCOVERY COMPLETENESS OVER A SPARSE EPOCH HISTORY is open in our code as of today, and the
contract for it is in review rather than settled.

## 9. Upstream, as of this writing

The decentralized masternode shares work merged into Dash Core's development branch on 2026-09-18.
It is not in a released version and activation is gated behind the next hard fork. We plan to build
on it. Its final commits change a shared-signing result format in a way that affects older local
exercise scripts on upgrade, which is worth knowing before you pin to it.

## 10. What we would do differently

Test the uncooperative participant first, not last. Every construction we lost weeks to looked
correct against cooperative parties.

Check what the platform already provides before designing around its absence. The native document
transitions cost us an entire apparatus.

Read the deployed source for numbers rather than the proposal text. The payout cap, the subsidy
split and the reward-share behavior each differed from the document we would have trusted.

Treat a passing test suite as evidence about the tests. Several of our worst defects sat under
green suites, and one was pinned in place by an assertion that ratified it.
