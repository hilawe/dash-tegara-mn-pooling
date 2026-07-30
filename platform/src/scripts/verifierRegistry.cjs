/**
 * verifierRegistry - THE ONE copy of the registry's component-to-verifier mapping.
 *
 * WHY IT IS ITS OWN MODULE (confirmation round, MINOR). Two modules need this mapping and
 * must not be able to disagree about it: auditSeam derives the claim profile from it, and
 * envelopeWriter checks each attestation's named verifier against it. It was written out in
 * both, so a rename or an added verifier could have landed in one and not the other, leaving
 * the derivation and the validation layers describing different formats. This build has
 * already paid for that shape twice, once with two partial canonical serializers and once
 * with a second encoder inside the lineage module, so the mapping gets the same treatment
 * canonicalJson got: one definition, imported by everyone.
 *
 * The mapping mirrors docs/schema/auditEnvelope.v1.registry.json, which is normative. A
 * component whose verifier is null has none by design and can never be attested.
 */
"use strict";

const VERIFIER_OF = {
  recognition: "verifyCheckpointRecognition",
  baseProof: "verifyBasePackage",
  coreContinuityFinality: "verifyCoreWalk",
  platformCommits: "verifyPlatformCommits",
  decoderCoverage: "verifyDecodeDispositions",
  l1Backing: "verifyL1BackingAtHeight",
  receiptValidity: "verifyReceiptDuties",
  bookConformance: "verifyBookConformance",
  conservation: "verifyConservation",
  transitionHashing: "verifyTransitionHashes",
  identifierConversion: "verifyIdentifierConversion",
  schedule: null,
};

module.exports = { VERIFIER_OF };
