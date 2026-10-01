# Tegara

An open reference implementation of non-custodial pooled masternode collateral on Dash. Multiple
funders pool toward a masternode's collateral with their own keys, coordinate through Dash
Platform, and no party ever holds anyone else's funds.

Tegara is a research prototype that touches no real funds. Its Platform side runs on Dash's public
testnet, and its Layer 1 side runs on the Dash Core v24.0.0-rc.1 release candidate in a local test
network. It is published so the non-custodial pooling design space stays open and reproducible for the
Dash ecosystem.

## The design in one paragraph

Layer 1 (the Dash payment chain) holds principal custody. The fully trustless form depends on shared
masternodes, proposed in dashpay/dips#187 and implemented in Dash Core by dashpay/dash#7437 (merged
2026-09-18, part of the v24 upgrade), under which two to eight participants fund a masternode's
collateral as co-owners with per-participant refund destinations, and on DIP-0026 (Dash Improvement
Proposal 26, multi-party reward payouts, merged). Layer 2 (Dash
Platform) holds everything that is accounting rather than custody, which includes the pool
ledger, member shares, reward distribution, member churn, governance preferences, and the
immutable completion receipts. The split is deliberate. A failure or outage in the accounting
layer must never be able to strand principal, and every trust assumption is written down where it
lives.

## What is here

- `platform/` is the Layer 2 reference. Pool-ledger data contracts through v11 (the one published on
  testnet), a separate member-approval contract, pool formation with frozen completion manifests and
  on-ledger completion receipts, the epoch reward-distribution procedure with its resumable journal and
  proof-based audit, a reward credit rail, member churn with matched settlements, a governance stack
  with snapshot-first cast receipts, and offline test harnesses for every pure core.
- Seed-loss recovery runs on [dash-rawkey-signer](https://github.com/hilawe/dash-rawkey-signer),
  a small standalone library that signs Dash Platform state transitions as an identity using a
  raw private key, with no hierarchical-deterministic wallet seed. A member who has lost their
  wallet seed acts on their identity (withdrawals, votes) using only the recovery keys they added
  while they still had it (`recoverClient.cjs`). The library was extracted from this codebase and
  is useful on its own to any Platform project that needs wallet-free signing.
- `DESIGN.md` records the architecture and the trust model.
- `docs/TEGARA_REFERENCE.md` is the whole-build consolidation.
- `docs/COMPLETION_RECEIPT_SPEC.md` is the design record of the on-ledger completion receipt
  (pool-ledger v8), including its canonical allocation preimage and golden vector.

## What it does not establish

- The trustless Layer 1 custody construction is not active on any public Dash network today. Shared
  masternodes are merged into Dash Core and ship in the v24.0.0-rc.1 release candidate, but the v24
  upgrade has not activated on testnet or mainnet (as of September 30, 2026). Tegara builds on them
  rather than substituting a weaker custody construction, because a traditional multisig with
  pre-signed refunds is unsound on Dash (first-party transaction malleability, no SegWit).
- The receipts and ledgers prove what the operator recorded, immutably and uniquely. They do not
  by themselves prove what happened on Layer 1. Each document type's comments state exactly what
  is and is not attested.
- This code has been through repeated independent review, and the review discipline is part of
  the method, but it is still a prototype and has not been audited for production use.
- Several of the protocol gaps this implementation works around were independently identified
  and prioritized in a public memo from the CrowdNode successor project to Dash Core Group
  (July 2026), among them cancel-safe pooled registration and locking Platform withdrawals to
  the L1 payout array. This codebase demonstrates, in running form, why those asks matter.

## Running the offline pieces

The pure cores (allocation math, canonical preimages, journals, tally verification, the
environment store) test with plain Node, no network:

```bash
cd platform
npm install
npm test
```

`npm test` runs the offline tests of the published modules. The live runners, which drive testnet
and a local Dash Core node, are not published, and neither are a few recent modules that are still
changing, so the published tests cover the published code only.

## License

MIT. Author @hilawe.
