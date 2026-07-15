# The Platform layer (Layer 2 reference)

Everything here is accounting, never custody. The pool ledger, member shares, reward
distribution, member churn, governance, and the completion receipts live on Dash Platform as
data contracts and documents. Principal safety rests only on the Layer 1 construction, so a
failure or outage here must never be able to strand principal.

## Layout

- `src/contract/poolLedger.ts` is the base data contract. The register scripts under
  `src/scripts/` build each revision from it (`registerV3.cjs` through `registerV8.cjs`); every
  revision is a fresh contract namespace selected at run time with `LEDGER=vN`.
- `src/scripts/` holds the operator and member tooling. The main entry points are
  `formation.cjs` (pool formation, completion, receipts), `funderClient.cjs` (member actions),
  `creditRail.cjs` (reward distribution), `matcher.cjs` (churn settlements), `governor.cjs` and
  `castReceiptV2.cjs` (governance), and `verifyAllocation.cjs` (the offline receipt verifier).
- Pure cores are separate modules with offline harnesses, for example `formationCore.cjs`
  (allocation math and the canonical allocation preimage), `tally.cjs`, `compoundJournal.cjs`,
  and `envStore.cjs` (the crash-safe local state store).

## Offline tests

```bash
npm install
npm test
```

Plain Node, no network. The suite covers the environment store's crash matrix, the journals,
the formation core with its published golden vector, tally verification, and the rail state.

## Running live

The live scripts need a local Dash Platform network. The tooling was built and validated against
a dashmate local group (three nodes plus a seed) with the SDK running in a Linux container on the
host network, because the Platform gateway's TLS certificate is issued for the network's own
addresses. The shape of a run:

```bash
docker build -t tegara-sdk -f Dockerfile.sdk .
docker run --rm --network host \
  -e NETWORK=regtest -e DAPI_HOST=<gateway ip> -e GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/ca.crt \
  -v <dashmate gateway bundle.crt>:/ca.crt:ro \
  -v "$PWD/.env.local:/app/.env.local" -v "$PWD/.env.local.state:/app/.env.local.state" \
  tegara-sdk node src/scripts/register.cjs
```

State lives in `.env.local` (wallet mnemonic, identity, contract ids; never commit it) and the
sibling directory `.env.local.state/` (owned durable state, one atomically replaced file per
key). Create the directory once on the host and mount both into every run.

Contract revisions are selected per run, for example `LEDGER=v8` for the receipt ledger. A new
revision is published with its register script and persists its contract id into `.env.local`.
