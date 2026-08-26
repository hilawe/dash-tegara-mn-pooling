# Audit envelope v1, the normative schema companion (v1.21, the revision-27 fold)

The machine-readable companion of `LIFECYCLE_JOURNAL_AND_SEAM_DESIGN.md` (revision 27),
build-order item 0. The design note carries the rules and their reasons; THIS package
carries the closed wire definition and the executable proof that it is closed. across successive reviews the checker came to RE-DERIVE every decision the envelope
asserts instead of accepting labels; the round records in the repo root map every finding.

## The package

- `schema/auditEnvelope.v1.schema.json` - the closed JSON Schema (draft 2020-12). Every
  object closed, every union tagged, hex and decimal-string grammars by pattern. The
  current shape (v1.21): the LIST-WALK LEDGER over the full coverage interval, the
  checkpoint entries with the fixed deployment authority and adopted-epoch pins,
  HEIGHT-LEVEL recognition (one outcome per L1 position, no per-slot recognition and no
  `withheldDuffs`), the closed anomaly-code registry, the `eligibility-base` member of
  `missingInputs` (the ABSENT_UNKNOWN row's serialization), the FIRST_APPEARANCE mode
  requiring proved absence plus the
  retained (P-1) -> P addition diff, per-transaction inclusion proofs and raw bytes for
  EVERY committed transaction, signed Platform headers with validator transition proofs
  and a pinned trust root, the retained Core header chain and quorum derivation, and the
  `artifactRef` content-addressed decoder reference.
- `schema/auditEnvelope.v1.registry.json` (v1.21) - the closed component registry with
  updated evidence paths, the named semantic verifiers, `structurallyBarredFromAuthenticated`
  on `schedule`, `l1Backing`, and `receiptValidity`, and the MUTUALLY EXCLUSIVE
  aggregate-profile matrix (exactly one profile matches any state; result completeness
  gates the aggregate; `proof-verified-except-schedule` stays UNREACHABLE until the two
  deferred verifiers exist).
- `schema/vectors/positive_minimal.json` - a COMPLETE valid envelope. Its purchase
  transaction is the REAL committed devnet transaction (Tenderdash height 470, 189
  bytes), and its checkpoint payload is BUILT BY the canonical v2 layout, so the
  payload byte-match and the raw-to-display proTxHash conversion are exercised for real.
- `schema/vectors/MANIFEST.json` - the positive vector's canonical sha256 and length,
  the EIGHTY-SIX manifest-listed layer-tagged negative vectors (the manifest count and
  per-vector layer tags are the authority; the packet builder refuses to ship if this
  document's stated count disagrees), plus the RAW duplicate-member ingestion case
  asserted directly by the checker (eighty-seven non-conforming cases in all), and the pinned sha256 of the execution-
  profile release document. The negative families: structure and grammar near-misses,
  recognition/payload byte-matching, journal reconstruction, conservation and payout
  arithmetic, ordering and duplicates, dependency and profile rules, the network-identity
  bindings (including the checkpoint-copied-across-devnets misbinding case), and the
  decoder-lineage canonicality rules.
- `schema/execution-profiles/tegara-decoder-v1.json` - the normative execution profile
  the `executionProfile` enum names (revision 17, a soundness-review finding), content-addressed by the
  manifest pin and re-checked on every suite run.
- `schema/proof-codecs/tegara-proof-codecs-v1.json` - the normative proof-codec profile
  the envelope's `proofCodecProfile` enum names (revisions 23-26, a soundness-review finding): every hex-blob
  evidence field's codec named and defined, and TOGETHER WITH the envelope's required
  `verifierBundleDigest` commitment (which identifies the deployment's proof-verifier
  bundle), two deployments cannot encode the same evidence into different canonical
  bytes; content-addressed by the manifest pin and re-checked on every suite run.
- `schema/check_vectors.py` - the executable check: the schema layer plus the SEMANTIC
  layer implementing the note's named verifiers.

Run it:

```bash
python3 tegara/docs/schema/check_vectors.py
```

Requires the `jsonschema` package. Current result: the positive vector passes both
layers, all eighty-six manifest negatives (plus the raw ingestion case) are rejected at their expected layer, and the canonical
form is 15797 bytes with sha256
`f6c656671362f9952c88e766e9e7f328ed3fa976e9cb8999074c6add184d49fe` (the canonical form
changed in revisions 17, 18, 20, 23, and 26, each deliberately: the domain tag, the
lineage environment fields, the explicit transaction indexes, the two-ledger coherence
of the positive, the proofCodecProfile field, then the verifierBundleDigest commitment,
a soundness-review finding). The checker also builds
SIX acceptance envelopes and asserts each serializes both layers: the SUCCESSOR-POOL case
(two epochs, the second re-binding the audited L1 position to a different pool;
CONFIRM-2), the ZERO-PAYOUT case (a scheduled pool with an omitted zero owner payout;
MF-2), the OWNER-VECTOR case (a two-output owner payout whose gross is the sum;
a soundness-review finding), the EMPTY-EPOCH case (a zero-book, zero-binding epoch under gaplessness;
revision-18 MAJ-5), and the FIRST-APPEARANCE case (a derivable synthetic pool identity
whose proTxHash IS the txid of the retained ProRegTx bytes, the P row adding the node
over the absent P-1 base; revision-22, a soundness-review finding named deliverable), alongside the primary
conforming example.

## The checkpoint v2 layout (the signed book carrier, decided in revision 7, reworked in revision 10)

Extends the pinned v1 layout of `fixedSlotCheckpoint.cjs`; all integers unsigned
little-endian; the signature is never part of the preimage:
- header, 62 bytes as v1: version u32 EXACTLY 2; the 32-byte domain tag
  sha256("tegara-fixedslot-checkpoint-v2" || coreChainIdentityHash || authorityPublicKey),
  where coreChainIdentityHash = sha256("TegaraCoreChainIdentity/v1" || coreNetworkCode ||
  coreGenesisBlockHash bytes || coreDevnetGenesisBlockHash bytes or 32 zero bytes) is
  DERIVED from the envelope's network fields, never serialized (revision 17, a soundness-review finding: the
  bare height-zero genesis let two devnets sharing the base derive the same tag, so a
  signed checkpoint could be copied between them; the derived identity makes the copy fail
  the decode); epoch id u64; effective Core height u64; end-exclusive Core height u64 (all
  three <= 2^53-1 so the JSON envelope copies byte-match, effective < endExclusive);
  binding count u16 BEFORE the book count;
- book count u16 (ZERO legal, revision-18 MAJ-5, the empty-epoch acceptance; <= a pinned
  MAX_BOOKS ceiling), then per book (sorted strictly ascending
  by (contractId, poolId)): contractId 32 raw bytes, poolId 32 raw bytes, operatorId 32
  raw bytes, slotCount u16 (1..512, the retail 511-slot ceiling plus one), then slotCount
  share pairs of numerator u64 + denominator u64 in retail-slot order. Each denominator is
  nonzero and in v1 every share is exactly 1/slotCount;
- bindings unchanged at 105 bytes (proTxHash raw consensus bytes, an L1 slotIndex u8,
  contractId, poolId, activationCoreHeight u64), sorted strictly ascending by
  (proTxHash, slotIndex); every binding's (contractId, poolId) must have a book entry.
  The binding's L1 slotIndex is NOT compared against the retail slotCount (two
  independent domains);
- the total payload is bounded by a pinned MAX_PAYLOAD_BYTES ceiling (a signed but
  oversized book table is rejected before allocation);
- checkpoint id = sha256 of the exact preimage; signature = ed25519 over that 32-byte
  hash.
The checker implements this decoder (`decode_v2_payload`); the envelope's
`extractedBinding` and `epochRange` must byte-match the decode, and the payload stores
raw consensus proTxHash bytes while the envelope carries the display form (the decoder
performs the pinned byte-reversal, so the conversion rule is exercised by the vector).

## The semantic layer (the note's named verifiers, all implemented)

- `verifyRewardDecision`: the precedence table as an executable matrix. Every
  classification, exclusion reason, eligibility state, list height, list root, and block
  hash is RE-DERIVED from the ledger rows and the base state; the result matrix
  (entitlement x conservation x fanout, ANOMALY included) is enforced.
- `verifyOwnership`: a position-indexed map from the decode decisions; every hop bound
  to the exact transaction at its position (hash, document, slot, anchor, inner index);
  creation-first chains with seller and buyer continuity, the CREATION MINTED BY THE
  SIGNED BOOK'S OPERATOR (a soundness-review finding); the closing block re-derived
  as the FIRST Platform row reaching H; the snapshot as the last eligible position; the
  owner as its buyer (or the signed book's operator for pre-creation).
- `verifyDecoderSelection`: per-row greatest-fromHeight-not-exceeding; the derived
  decoderId and digest-embedding artifactRef; the exact lineage extent over the platform
  audit interval; and adjacent entries differing in at least one bundle-identity field
  (change points, not deployments; a soundness-review finding).
- `verifyCheckpointRecognition` (semantic portion, a review): the governing `recognize`
  outcome RE-DERIVED per height for the audited L1 position (region resolution,
  activation, suspension and terminal gating from the reconstructed journal) and required
  to match the serialized height-level `recognition`; the v2 decoder takes the signer public key and the
  chain identity DERIVED from the envelope's own `network` fields (name code, height-zero
  genesis, devnet height-one genesis or zeros) DYNAMICALLY for the domain tag, asserts the
  payload's books and bindings are strictly ascending AS COMMITTED, and the
  FIRST_APPEARANCE ProRegTx txid check (sha256d, byte-reversed) runs in the semantic
  layer.
- `verifyLifecycle`: the journal RECONSTRUCTED from the list-walk ledger's per-height
  states and compared EQUAL to the serialized `lifecycle`; the invariants (endHeight
  never null, TERMINATED = terminalHeight, RANGE_END = observedThroughHeight, no
  transition after terminal, suspension ends at or after their ban, terminal within
  observation).
- `verifyConservation`: exact-rational largest-remainder reproduction from the SIGNED
  shares (ties by ascending slotIndex); sum(allocatedDuffs) = slotAllocationBase exactly
  (no per-slot withholding: recognition is height-level, so a recognized OWED height
  allocates the whole book).
- `verifyClaimProfile`: the mutually exclusive aggregates computed from the component
  claims and result completeness; barred components can never claim AUTHENTICATED;
  `verifiersNotRun` coupled to the claim.
- Plus: the coverage-interval equation (`observedThroughHeight >= toHeight`,
  `toHeight <= chainlock`, base-mode range constraints, pre-DML
  `baseHeight = activationHeight - 1`), checkpoint payload byte-matching and share-sum
  validation, epoch gaplessness and range coverage, three-ledger contiguity, anchor
  non-regression, committedHash = sha256(rawBytes) for every transaction, per-inner
  decisions, total array orders with duplicate rejection, RFC 6901 `evidenceRefs`
  resolution, NFC strings, and the no-float rule.

## Disclosed residuals

1. The `not-applicable` conservation member covers every height with no allocable pool
   reward (not scheduled, excluded, unrecognized, deferred).
2. `eligibility-base` in `missingInputs` serializes the ABSENT_UNKNOWN precedence row
   (an eligibility that a range-local base cannot determine is a missing trusted input,
   not a classification).
3. The synthetic evidence fields of the positive vector (signatures, proofs, chains,
   and the `absence-proof` lower-bound blob) are shape-correct placeholders; their
   cryptographic verification is the runtime verifiers' job, named per component in the
   registry, and the `absence-proof` branch stays unreachable in the v1 vectors (the
   positive uses contract-genesis; a content-false absence proof is a runtime
   `verifyBookConformance` rejection). The vector proves the structure, the
   byte-matching, and the arithmetic, not the signatures.
4. RUNTIME PROOF-BLOB CODECS (revision 14 MAJ-7; closed across revisions 23-26,
   a soundness-review finding): the `proof-codecs/tegara-proof-codecs-v1.json` release document maps every
   hex-blob evidence field to a codec; Dash codecs pin their defining sources at
   `8c9f166a3`; Platform codecs are DEFINED by the deployment's content-addressed
   PROOF-VERIFIER BUNDLE (protocol versions and protobuf type names alone are
   insufficient), and the ENVELOPE commits which bundle applies through its required
   `verifierBundleDigest` field (revision 26), the deployment's actual bundle hashing to
   that digest being a runtime duty: the runtime-verified evidence fields
   `coreHeaderChain`, `validatorSetBytes`, `validatorTransitionProof`, `quorumDerivation`,
   the fixed-authority model (no authorization chain, rotation, or threshold machinery exists in v1), and the
   inclusion proofs are unconstrained hex in the schema on purpose: their exact byte
   codecs and retained ranges are FIXED BY THE DEPLOYED VERIFIER (the Tenderdash header
   codec, the Dash quorum/ChainLock encodings), not by this suite, and are pinned in the
   build alongside the runtime verifiers named in the registry. Two conforming runtime
   verifiers pin the same codecs; the vector suite exercises only the structural shape.
   A deployment MUST record the chosen codecs with its verifier implementations so
   independent verifiers produce byte-identical envelopes.
5. MASTERNODE PAYOUT MODEL (revision 15, a soundness-review finding, VALIDATED at
   `8c9f166a3:src/masternode/payments.cpp:74-84`): the retail book's gross is the pool
   masternode's OWNER payout, a VECTOR (`GetOwnerPayouts` returns one entry per share, the
   loop emits one positive output per entry, a zero entry omitted), so `requiredOutputs`
   is 0..N and gross is the sum of the matched owner vector. The OPERATOR reward is a
   separate out-of-book output. A fully truncated owner reward serializes as OWED with
   gross 0 (zero-payout acceptance); an N=2 owner vector is the owner-vector acceptance.
   The owner-payout scripts/amounts are DERIVED at runtime from the audited masternode's
   L1 state, so a false-zero or wrong-L1 selection is a runtime-authenticated rejection;
   the suite (placeholder L1) enforces owner-vector internal consistency and discloses the
   L1 binding.
6. DETERMINISM BINDINGS (revision 16, a confirmation pass): three fields
   that were free strings are now closed or bound, so two conforming producers cannot emit
   different canonical bytes for the same facts.
   - The decoder EXECUTION DESCRIPTOR (`runtime`, `entryPoint`, `inputFormat`) is a closed
     schema enum and is listed in the `decoderCoverage` evidence; the retrieved bundle's
     committed descriptor must equal the serialized descriptor at runtime. Before this,
     `node-20-lts` and `Node.js 20 LTS` both passed for one `artifactDigest`.
   - `coreNetwork` is a closed registry (`mainnet`, `testnet`, `devnet`, `regtest`) and
     Core chain identity is a TUPLE (completed in revision 17, a soundness-review finding): mainnet/testnet bind
     both ways to their canonical genesis hashes (pinned from
     `8c9f166a3:src/chainparams.cpp`); regtest binds ONE WAY to the shared height-zero base
     `000008ca...` (no reverse base-to-name rule, devnet legitimately shares it); devnet
     additionally requires `coreDevnetGenesisBlockHash`, its height-one devnet genesis
     (forbidden for every other network), nonzero and distinct from the base, authenticated
     at runtime. The DERIVED `coreChainIdentityHash` (never serialized) feeds the
     checkpoint domain tag, so a signed checkpoint cannot be copied between two devnets
     sharing the base. Before revision 16, `coreNetwork` was any nonempty string checked
     only for top-level-versus-base agreement.
   - `basePackage.smlEntries` is pinned to ascending entry-byte order with schema duplicate
     rejection; the DIP-4 SML root is recomputed by the runtime verifier by proRegTxHash
     and does not depend on this stored order.
7. IMPLEMENTATION RESOURCE BOUNDS (revision 28, property review P10). The ledger arrays
   that grow with the audited range (`coverage.listWalk`, `coverage.coreLedger`,
   `coverage.platformLedger`, `checkpoints`, `rewards`) carry NO `maxItems`, on purpose: a
   ceiling chosen now would cap a legitimate long-range audit, and the format has no
   envelope-splitting story to fall back on. An implementation MAY therefore impose its own
   resource bounds on parsing, canonicalization and checking, and one that does MUST DECLINE
   the record with a named error. It must never truncate the input, emit partial canonical
   bytes, or report a verdict computed over less than the whole record. A refusal to process
   is a legitimate outcome; a verdict over a truncated record is not.

   The consequence is stated rather than smoothed over: two conforming implementations always
   agree on the canonical bytes and the verdict for any record BOTH can process, but they may
   disagree on WHETHER they can process a very large one. That is an availability difference,
   not a divergence in what the record means. The reference serializer's own bounds are a depth
   of 100 (which no conforming record approaches, since nesting is fixed by this schema and the
   committed positive reaches 9) and 5,000,000 nodes, which binds at roughly 555,000 list-walk
   rows, on the order of two to three years of Core blocks inside a single envelope.

## Versioning

`envelopeVersion` is the decimal string `"1"`. PRE-RELEASE RULE (revision 9, pinned): no
production envelope exists yet, so companion revisions iterate UNDER version 1 until the
design round returns SOUND; FROM ACCEPTANCE ON, any change to the schema file, the
registry, the semantic rules, or the canonicalization bumps the version, and the vectors
regenerate under the new one. The schema file is the tie-breaker wherever prose and
schema could be read differently.
