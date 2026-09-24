# Nonce ownership for a sending identity

This note states which accrual owns a signed payment when several pools pay from one sending
identity, and how the distribution writer keeps one payment per accrual when two pools build
identical transfers. The design is implemented in `platform/src/scripts`, mainly in `e2DocId.cjs`,
`e2Distribute.cjs`, `e2DistributeEpochDeps.cjs`, `e2Journal.cjs` and `e2OperatorDecision.cjs`.

## The problem

A Dash Platform credit transfer carries its sender, its recipient, its amount and the sender's
identity nonce. Nothing in it names a pool or an accrual. Each accrual's transfer takes the ledger's
current nonce plus one, read just before signing, and until this change nothing recorded a nonce
that had been assigned but not yet executed.

So while one pool's transfer is built but not executed, the next transfer by the same sender reads
the same nonce. If it pays the same member the same amount, the two transfers are byte-identical and
only one of them can execute. A wait on that hash returns the one execution's success to either
pool, and both pools could record the member as paid when the member was paid once. If the two
transfers differ in bytes, one of them can never execute, because its nonce has been used.

This was observed on a development network. One pool's transfer stalled before it was sent, a
second pool built identical bytes from the same nonce and executed them, and when the first pool
later sent its transfer it received the second pool's execution. The member's balance did not move.
The ledger's unique receipt index, which refused the first pool's receipt, was what exposed the
duplicate record.

## The ownership invariant

For a sending identity S, a nonce sequence is either S's identity nonce, used by its credit
transfers, or S's nonce for one data contract, used by its document writes there. An owner is one
journaled attempt, identified by its pool, its object (a header, a reservation or a transfer), its
epoch, its accrual where the object has one, and its generation. The invariant has five parts:

1. One owner per nonce. Every nonce carried by a transition S signs, in any sequence, has exactly
   one owner.
2. Ownership is fixed before signing. The owner is recorded durably and atomically before the
   transition is signed.
3. Ownership is never released or reassigned. A nonce whose transition was never sent stays owned,
   because its bytes exist and a recovery path may still send them.
4. Retries keep their nonce, and rebuilds take a new one. A wait or a resend uses the owned nonce
   and the persisted bytes, and a new generation takes a new nonce under its own ownership record.
5. Allocation respects both the ledger and the record. A new nonce is above the ledger's current
   nonce for its sequence and above every nonce already owned in it.

Together these mean that no two owners sign transitions sharing a sequence and a nonce, so no two
owners can produce identical bytes.

## What enforces it, and where enforcement stops

The five parts hold only if every transition S signs takes its nonce from one ownership record under
one lock, a single coordinator per sending identity. On one host that is enforceable in code,
because every signing path takes its nonce from one place. Beyond one host it is not. Nothing local
stops a second coordinator for S on another machine or in a second copy of the record, since the
keys for S work wherever they are present. A second coordinator's transitions become visible only
after they execute, and two coordinators that allocate the same nonce before either executes are
not detected in time. Beyond one host, the single-coordinator scope is an operational assumption.

## Reservations identified by the transfer they bind

Before a transfer is sent, the writer creates a transfer reservation, a document binding the
accrual to the transfer's hash. The contract makes a reservation immutable, undeletable and unique
by accrual, and makes a receipt unique by accrual and by transition hash. Platform derives a
document's identifier as the double SHA-256 of the contract, the owner, the document type and an
entropy value (rs-dpp `generate_document_id_v0`), and refuses a second document at an existing
identifier.

A reservation's entropy is the SHA-256 of the domain string `tegara.e2.reservation-by-transfer.v1`,
a `|` separator and the hex hash of the transfer it binds, and its identifier comes from Platform's
own derivation. Two pools with byte-identical transfers therefore build reservations with the same
identifier, and the ledger refuses the second before anything is sent.

The protection has a stated scope:
- at most one reservation per transfer bytes, within one contract, one document type and one owner,
  the writer identity that creates the reservation;
- only among writers that derive the entropy this way, since the contract does not enforce the
  derivation, and nothing is claimed for a writer that does otherwise;
- not for pools with different writer identities paying from one sending identity, which would need
  a reservation unique by transfer hash, a contract change.

Reservations created before this change keep their accrual-derived identifiers. Every reader fetches
a reservation by its accrual, so both kinds read the same way.

## Who owns a transfer's bytes

Bytes T belong to the accrual that holds a ledger claim on T, either a reservation at the identifier
derived from T or a receipt whose transition hash is T. Each kind of claim is unique on the ledger.
An accrual may record T as its payment only while no other accrual holds a claim on it.

The writer checks for such a claim at three points, and records a collision instead of a payment
when another accrual holds one:
1. when its own reservation create is refused;
2. before a transfer's result is captured, which covers a duplicate answer from the node and a wait
   on a resumed run;
3. on a resumed run that finds an earlier capture.

A claim read that fails records nothing, and the accrual stays unresolved until a later run can make
the check. An older reservation of another accrual, with an accrual-derived identifier, can be found
only through that accrual's receipt, because reservations have no index on the transfer hash.

## Replacement transfers

An accrual whose transfer bytes another accrual owns needs a new transfer at a new nonce. The writer
builds one only when all three of these hold:
1. the ledger proves that the accrual holds no reservation;
2. the ledger shows another accrual's claim on the accrual's current transfer bytes, and that
   evidence is journaled;
3. an operator journals the decision after that evidence, with `e2OperatorDecision.cjs
   rebuild-transfer`.

One payment per accrual still holds. By the first condition and the unique, immutable reservation,
the accrual's only reservation will bind the replacement, and a transfer is sent only when the
accrual's reservation binds that generation's bytes. The accrual can send only its replacement, and
the old bytes' single execution, if there was one, belongs to the other accrual. The journal refuses
a replacement's write-ahead that has no decision, and a replacement's send that has no reservation
bound to its own bytes.

An accrual that already holds a reservation cannot be given a replacement. Its reservation is
immutable and binds the old bytes, so the ledger could not exclude a second binding. For such an
accrual the writer corrects the record by naming the collision, and paying the member needs a
contract change.

## Nonces that can no longer execute

A journaled transition whose nonce Platform will never accept again is named rather than waited on.
`e2NonceWindow.cjs` classifies a nonce against the raw stored value the way rs-dpp's
`validate_identity_nonce_update` does. The stored value's low 40 bits are the highest nonce used,
its high 24 bits mark skipped nonces below that, and the window is 24. A reservation whose nonce can
never execute can be rebuilt, bound to the same transfer, once the ledger proves that no reservation
exists for its accrual.

## What remains open

- Two pools whose transfers share a nonce but differ in bytes produce no false record, since only one
  can execute. If the other pool's reservation already bound its transfer before that transfer
  became unusable, its accrual has no replacement path under the current contract.
- Writers with different identities that share a sending identity, and writers that derive the
  identifier another way, are outside the protection.
- An accrual whose reservation binds bytes another accrual executed can be recorded correctly, but
  its member cannot be paid without a contract change.

## Evidence

The writer's tests run a second pool of the same sending identity against one shared ledger
stand-in. They cover a race to identical bytes, a mixed ledger with an older writer, a collision
between two accruals of one pool, replacement generations up to the third, and a failure matrix for
every ledger read.

On a development network, two pools in separate stores raced to identical transfer bytes. The
second pool's reservation was refused at the first pool's reservation identifier, and it recorded
the collision and sent nothing. After an operator's decision it paid with a new transfer under a
new nonce. The member's balance rose by exactly the two accruals' amounts.
