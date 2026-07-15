# Tegara

An open reference implementation of non-custodial pooled masternode collateral on Dash. Multiple
funders pool toward a masternode's collateral with their own keys, coordinate through Dash
Platform, and no party ever holds anyone else's funds.

Tegara is a research prototype. It runs against a local Dash Platform development network and
touches no real funds. It is published so the non-custodial pooling design space stays open and
reproducible for the Dash ecosystem.

## The design in one paragraph

Layer 1 (the Dash payment chain) holds principal custody. The fully trustless form depends on the
shared-collateral covenant proposed in dashpay/dips#187, under which two to eight participants
fund a masternode's collateral as co-owners with per-participant refund destinations, and on
DIP-0026 (Dash Improvement Proposal 26, multi-party reward payouts, merged). Layer 2 (Dash
Platform) holds everything that is accounting rather than custody, which includes the pool
ledger, member shares, reward distribution, member churn, governance preferences, and the
immutable completion receipts. The split is deliberate. A failure or outage in the accounting
layer must never be able to strand principal, and every trust assumption is written down where it
lives.

## What is here

- `platform/` is the Layer 2 reference. Pool-ledger data contracts (eight revisions, each one a
  reviewed step), pool formation with frozen completion manifests and on-ledger completion
  receipts, a reward credit rail, member churn with matched settlements, a governance stack with
  snapshot-first cast receipts, and offline test harnesses for every pure core.
- `DESIGN.md` records the architecture and the trust model.
- `docs/TEGARA_REFERENCE.md` is the whole-build consolidation.
- `docs/COMPLETION_RECEIPT_SPEC.md` is the design record of the on-ledger completion receipt
  (pool-ledger v8), including its canonical allocation preimage and golden vector.

## What is honest to say about it

- The trustless Layer 1 custody construction is not deployed on any public Dash network today.
  Tegara builds on the covenant proposal rather than substituting a weaker custody construction,
  because a traditional multisig with pre-signed refunds is unsound on Dash (first-party
  transaction malleability, no SegWit).
- The receipts and ledgers prove what the operator recorded, immutably and uniquely. They do not
  by themselves prove what happened on Layer 1. Each document type's comments state exactly what
  is and is not attested.
- This code has been through repeated independent review, and the review discipline is part of
  the method, but it is still a prototype and has not been audited for production use.

## Running the offline pieces

The pure cores (allocation math, canonical preimages, journals, tally verification, the
environment store) test with plain Node, no network:

```bash
cd platform
npm install
npm test
```

The live pieces need a local Dash Platform network (dashmate) and a wallet funded from its
faucet. `platform/README.md` has the container-based run recipe.

## License

MIT. Author Hilawe Semunegus.
