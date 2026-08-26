# Tegara in plain terms

Tegara is a working reference design for pooling money toward a Dash masternode without
anyone holding anyone else's funds. This document explains the whole of it in plain
language, what problem it addresses, how the pieces fit, what has actually been
demonstrated and at what level of proof, and what remains open. The limits are part of the
explanation, not an appendix. A reader who wants the precise technical treatment should
read `TEGARA_REFERENCE.md` and `COMPLETION_RECEIPT_SPEC.md` beside this.

## The problem

A masternode is a server that provides services to the Dash network and earns a share of
each block reward for doing so. Running one requires locking a large fixed amount of Dash
as collateral, 1000 DASH for a regular masternode and 4000 DASH for an evolution node.
That is out of reach for most individual holders, so people pool. Several members combine
smaller amounts to back one node together and share its reward.

The hard part is the pooling itself. The obvious way to pool is to hand everyone's money
to a company or a coordinator who runs the node, and that is custody, with everything
custody implies. The members must trust the custodian, the custodian carries regulatory
obligations for holding other people's funds, and a failure at the custodian is a failure
for every member at once. Tegara addresses the other way, pooling where each member keeps
their own keys and the path to recover a member's own contribution never depends on a
coordinator, a committee, or any service staying online.

## Why now

CrowdNode, the largest pooling service for Dash masternodes, is winding down its custodial
model. Its founder has attributed the wind-down to the European Union's Markets in
Crypto-Assets regulation, known as MiCA. That attribution is his, and this document adds
no legal reading of its own. The successor product being built by the same team rebuilds
the idea non-custodially, so that members keep their own keys. Tegara is an open reference
implementation of that non-custodial approach, MIT licensed, built so the method stays
available to the Dash network regardless of how any single product is licensed or run.

## The two-layer split

The design puts money and bookkeeping on different layers of Dash, and everything else
follows from that split.

```
  MEMBERS (each holds their own keys, signs their own records)
     |                                   |
     | collateral, rewards               | reservations, shares,
     | (real value)                      | receipts, votes (records)
     v                                   v
  +--------------------------------+   +----------------------------------+
  | LAYER 1: the Dash blockchain   |   | LAYER 2: Dash Platform           |
  |                                |   |                                  |
  |  the shared-collateral         |   |  the pool's books:               |
  |  covenant holds the 1000 DASH  |   |  - who reserved which slot       |
  |  with each member's share      |   |  - whose share is whose          |
  |  written into consensus rules  |   |  - the completion receipt        |
  |                                |   |  - how rewards divide            |
  |  the coinbase pays each        |   |  - governance preferences        |
  |  member's reward directly      |   |                                  |
  +--------------------------------+   +----------------------------------+
     value lives here                    no value lives here
```

Layer 1 is the Dash blockchain itself. The collateral sits there, inside a proposed
covenant that writes each member's share into the consensus rules, and rewards are paid
there, directly to each member's own destination. Layer 2 is Dash Platform, a data layer
on top of the blockchain. The pool keeps its books there, and every record is signed by
the member it belongs to. Nothing on layer 2 is money. A member whose accounting layer
disappears tomorrow still holds their collateral claim on layer 1, which is the property
the whole design is arranged around.

## The three building blocks

Tegara invents no new blockchain rules of its own. It combines three pieces that exist or
are formally proposed for Dash.

- A multi-party payout mechanism (DIP-0026, merged into Dash Core) lets one masternode
  pay its reward to several destinations at once. The small group of direct participants,
  two to eight people, is paid straight from the blockchain with no intermediary.
- A proposed collateral-sharing covenant (the open proposal dashpay/dips#187) lets those
  participants jointly back one node's collateral under blockchain-enforced conditions,
  including each member's unilateral exit, instead of trusting each other or a
  coordinator. This proposal is not yet part of the public network.
- Dash Platform carries the accounting, the member records, and the pool's completion
  receipt.

## The life of a pool

The accounting layer went through nine ledger revisions as reviews removed ways the
books could mislead. The current ledger, v9, has one organizing idea. THE POOL DOCUMENT
NEVER CHANGES. It is written once, at creation, carrying only the pool's constants, which
slot of the covenant it maps to, the node type, the operator's fee, and the collateral
target. Completion is not an edit to the pool. It is a separate, permanent receipt.

```
  OPERATOR                      MEMBERS                      LEDGER (Platform)
  --------                      -------                      -----------------
  create pool  ---------------------------------------->    pool document
  (constants only,                                          (immutable, forever)
   advertises the pool
   to its members)
                                reserve a slot  -------->    slot claim
                                (own key, own               (deletable by its
                                 reward address)             owner while open)
                                reserve a slot  -------->    slot claim
                                        ...
  register the shared node on the blockchain (layer 1)
                                        |
  complete:                             v
    1. freeze the member list      [verify the layer-1
       and every amount             registration against
    2. check the registration       the frozen list]
    3. members' shares settle  ------------------------->    share records
       (each signed by its                                   (member-signed)
       own member)
    4. publish the receipt  ---------------------------->    completion receipt
       LAST                                                  (immutable, names the
                                                             node, embeds the
                                                             frozen allocation)
```

A member reserves a fixed-size slot in an open pool, signing the reservation with their
own key and naming their own reward destination. While the pool is open, the member can
cancel that reservation without asking anyone. When every slot is claimed, the operator
registers the shared node on the blockchain and runs completion. Completion freezes the
member list and every amount, verifies the blockchain registration against that frozen
list, settles each member's share as a record the member signs, and publishes the
completion receipt last. The receipt is the completion. It names the node, embeds the
exact allocation, and can never be edited or deleted.

Earlier ledger revisions marked completion by editing the pool document, a step the code
called the flip. reviews kept finding ways an edit-in-place could mislead a reader
who caught the books mid-change, so v9 removed the edit entirely. A record that cannot
change cannot be caught mid-change.

## What proves a pool completed

Receipt existence alone proves nothing, and the design treats that as a rule rather than
a nuance. A receipt counts only when it verifies against its pool, five checks in one
shared routine used by every reader.

```
  completion receipt        the pool document
  +------------------+      +------------------+
  | names pool P  ---+----->| is P             |   1. same pool, checked
  | embeds the       |      |                  |      by identity
  |  allocation   ---+--+   |                  |   2. allocation is intact
  | names node N     |  |   |                  |      (hash recomputed from
  | claims slot S ---+--+-->| slot S           |       its own bytes)
  +------------------+  |   | target T         |   3. the embedded total
                        +-->| (self-consistent |      equals the pool's
                            |  with node type) |      target T
                            +------------------+   4. the claimed slot
                                                      matches the pool's
                                                   5. the named node is a
                                                      real node identifier,
                                                      not a placeholder
```

The fifth check was added in August 2026 after an independent review found it missing.
While a pool is still forming its record carries a placeholder in place of a real node
identifier, and the writing side always refused to put such a placeholder on a receipt.
The reading side never checked, so a receipt naming a placeholder passed the other four
checks and would have been read as a completed pool backed by a node that does not exist.
The rule now lives in the shared routine and in every document that states the routine's
duties, because a rule enforced only by the writer is not a rule an independent
implementation can discover.

A receipt that fails any of these establishes nothing, and no reader treats it as merely
absent either. It is surfaced as a contradiction for a person to resolve. This came out
of the design reviews in a specific form. Three separate reviews each proposed some
version of treating a receipt's presence as proof of a live pool, and each was rejected,
because the accounting layer cannot enforce rules that span two documents, so presence
alone can always be made to lie.

## How a member decides whether a pool is joinable

An immutable pool document creates one new problem. A pool that is open, a pool
whose completion is in flight, and a pool that was abandoned all present the same
document, because none of them has a receipt yet. Only the operator, who holds the local
formation state, can tell them apart. The member's client therefore refuses to guess.

```
  member asks: can I reserve a slot in pool P?
        |
        v
  does a receipt exist that VERIFIES against P?
        |                        |
       yes                       no
        |                        |
        v                        v
  REFUSE                does the operator's explicit
  (P completed;          instruction name exactly P?
   it is not open)       (TEGARA_PARTICIPATE=P,
        |                received outside the ledger)
        |                    |             |
        |                   yes            no
        |                    |             |
        |                    v             v
        |               PROCEED         REFUSE
        |               (on the         (open, in-flight and
        |                operator's      abandoned pools are
        |                word, and       the same document;
        |                say so)         guessing can strand
        |                                the reservation)
        v
  a receipt that exists but does NOT verify
  refuses too, as a contradiction to resolve,
  never as if it were absent
```

The one exception is deliberate and narrow. If the operator advertised this specific pool
to the member through some channel outside the ledger, the member states that explicitly,
naming the pool, and the client proceeds on the operator's word while saying that is what
it is doing. This is not a cryptographic proof of anything. It records that the member
acted on a channel the ledger does not provide, which is the limit of what a client can enforce there.

## What has been demonstrated, and at what level

Three kinds of evidence back the design, and they are different kinds, so they are
listed separately.

**Failure injection, offline.** The completion machinery runs against a simulated ledger
that halts the process at every single mutating step, then restarts it, hundreds of
boundaries per run. At every boundary the books either resume to exactly the same receipt
or stop loudly with the recovery evidence intact. Both the current live ledger revision
and v9 run this way on every test run, roughly 1,370 and 1,220 checks respectively, so a
regression on either fails the build. The same suite verifies that the simulated ledger
refuses what the real one refuses, so passing against a lenient simulation does not
count.

**Consensus refusals, live.** After the v9 ledger was published on a local development
network, ten probes confirmed the rules hold at the network itself, not only in client
code. Replacing a pool document is refused. Deleting one is refused. A non-owner creating
pools or receipts is refused. A second receipt for the same pool, or for the same node
and slot, is refused. A half-specified slot layout is refused.

**Full formation rounds, live.** Two complete rounds ran end to end on the published v9
ledger. In the first, the member client refused an uninstructed reservation exactly as
designed, admitted two instructed ones, and completion published its receipt with no pool
edit anywhere. The blockchain half of that round was simulated, and its receipt says so
permanently. The second round removed that simulation. A two-member shared registration was made on a test build of the collateral covenant, completion verified the
registration against the frozen member list, amounts and reward destinations pairwise,
before settling anything, and the resulting receipt permanently records the strongest
verification level the design defines. The receipt records the level because a reader
years later should know what was checked at the time, not what a document claims today.

Each verification level is recorded on the receipt itself:

| Level | What was checked at completion time |
| --- | --- |
| `demo-unverified` | Nothing on the blockchain. The receipt says so. |
| `node-existence-only` | The named node exists on the blockchain. Amounts unchecked. |
| `amount-reward-verified` | The node exists, is genuinely shared, and its share table matches the frozen member list, amount and reward destination pairwise. Share owner keys and refund destinations are outside the frozen list and stay unverified, a recorded residual. |

## What a long review changed, and what it says about the method

Between late July and early August 2026 the assembled design was reviewed repeatedly and
independently, by reviewers working from the complete source and by reviewers reading it
cold with no access to the repository, on top of the earlier per-component checks. That is worth describing plainly, because the shape of
what it found matters more than the count.

Roughly forty defects were found and fixed. Almost none were in the cryptographic or
consensus reasoning, which had already been through its own rounds. They clustered in
three ordinary places instead. Some were rules the code enforced but no document stated,
so an independent implementation reading the specification would have behaved differently
from the reference: the placeholder-node check above is exactly that. Some were guards
that admitted a member to a pool the completion path would later refuse, stranding the
claim rather than losing money. And several were tests that passed while watching
something other than the property they were named for.

That last category is the one worth generalising. A test can observe a proxy: it fails
when the code is broken in the way its author imagined, and passes when the property is
destroyed some other way. This project found several such tests by deliberately breaking
the code and checking that the test noticed, and found others only when a reviewer with
no investment in the code read them. One control had to be deleted outright, because it
searched the source text for the name of an argument rather than observing what the
program did, so removing the argument and leaving the word in a comment kept it green.

The review passes also stopped converging at one point, and the reason was instructive:
each pass was largely finding defects introduced by the previous pass's repairs. Fixing
quickly, in a long unbroken sitting, was manufacturing the next round of findings. The
work was deliberately paused on that basis rather than continued to a clean verdict, and
the later passes were run against a frozen copy of the code so the reviewer saw a fixed
target. Both of those are recorded in the project's own process notes as findings about
the method, not about the design.

None of this is a claim that the design is now correct. It is a description of what the
review actually did and where it kept pointing.

## What it cannot do yet

- The collateral-sharing covenant is not part of the public Dash network. It is an open
  proposal, demonstrated on a private test build, with no activation date. The standing
  rule is no real member principal until the rule activates publicly.
- The first product scope is the direct tier only, two to eight members per pool. The
  entry amount is therefore high, around 125 DASH per person at the smallest split of a
  regular node, and leaving a pool is not something a member can do on demand. Neither
  limit is softened by anything in this document.
- The member join and exit handover after a pool is live moves the accounting record
  only. It does not move value between the two members, and it cannot yet be completed
  across members holding unrelated keys. A member-signed value settlement is designed
  and unbuilt.
- Reward distribution passes through the pool operator, who could delay or misstate a
  payout. Every distribution is recorded so members can check it after the fact, which
  is a check, not a blockchain guarantee.
- The link between the blockchain and the accounting layer in the prototype is a trusted
  relay, not a proven one. In production both halves live on one network and the relay
  disappears, but that is the production design, not the demonstrated state.
- A member who pools through a smaller sub-group inside a pool relies on that sub-group's
  own arrangement for the inner split, not on the blockchain.
- Two members reserving the last places in a pool at the same instant can between them
  produce a pool the completion path will refuse, because the client checks a snapshot of
  who has already reserved and the accounting layer only guarantees that no two members
  take the same place. Nothing is lost when it happens, since completion refuses and the
  places can be released, but the guard is a courtesy check rather than a guarantee, and
  saying otherwise would overstate it. Closing it properly needs either a rule at the
  network level or an operator who serialises admissions, and that choice is open.

## Future directions

**Evolution nodes, the named next platform target.** Everything demonstrated here for
regular masternodes has to be carried to evolution nodes, the 4000 DASH nodes that also
serve Dash Platform itself. The accounting code already carries the evolution amounts and
node type offline, and the shared checks are written against node type rather than a
fixed number, but every live demonstration in this document was a regular node. The
covenant behavior, the payout mechanics, the formation rounds and the verification ladder
all need their evolution-node counterparts exercised. One boundary is not Tegara's to
lift: the shared-collateral proposal scopes itself to regular masternodes, and the
covenant build refuses a shared evolution-node registration at consensus, so the
strongest verification level is out of an evolution pool's reach until that scope
changes upstream. The stated priority is to finish
and vet the regular-masternode line first, then make evolution nodes the next major
effort rather than an afterthought.

**Member-signed value settlement.** The join and exit handover should move value between
the two members in the same signed step that moves the recorded share, across unrelated
keys. This is the largest open design item on the accounting side and has its own
clean-room design track.

**Public-network activation.** The whole principal side waits on the collateral covenant
activating in a public Dash upgrade. Until then the reference keeps the method concrete,
including for reviewers of the proposal itself.

**A proven relay.** In the prototype, reward observations cross from the test blockchain
to the accounting layer through a trusted relay. Production collapses the two onto one
network. Any interim with both halves public deserves a proven link rather than a
trusted one.

**The retail tier, deliberately out of scope.** Letting thousands of small members pool
below the direct tier is designed in outline and excluded from the first product on
purpose, because its trust boundary is the operator, not the blockchain. It returns only
with its own protections.

## Status

Tegara is a reference implementation, not a shipped product, and it is research and
reference only: nothing here is production, and there is no arrangement under which a
member's real principal is committed. The accounting layer runs live on a local Dash
network, the v9 ledger is published there and probed at consensus, and two full formation
rounds have run end to end, one of them verified against a real shared registration on the
covenant's test build. The code is open source under the MIT license, with the
failure-injection suites running on both ledger revisions in every build.

the August review is closed as a body of work but the design is NOT being
described as review-complete. The project's own rule is that the line closes only when a
fresh full review pass returns a clean verdict, and the last pass did not; its remaining
findings are the concurrent-reservation limit named above, which is a design decision
rather than a repair, and the routine follow-up from the passes before it. Saying
review-complete before that has been earned is exactly the kind of claim this document
tries not to make.

What a careful reader should still hold it to is otherwise unchanged in kind: a real
member-signed value settlement, the retail trust boundary, a proven relay, evolution-node
coverage, and public activation of the collateral rule. The reference exists to keep the
method open and to make exactly those remaining problems concrete.
