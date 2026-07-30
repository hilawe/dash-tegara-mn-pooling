/**
 * decoderLineage - build-order item 5 of the REVIEW-COMPLETE design (revision 27): the
 * lineage builder/validator plus THE PRODUCTION BUNDLE MANIFEST SCHEMA.
 *
 * The lineage records CHANGE POINTS, not deployments (a soundness review). Nothing in an entry is
 * producer-labelled (a soundness review): `decoderId` is DERIVED from the artifact digest,
 * `artifactRef` is one closed content-addressed grammar embedding that same digest, the
 * execution descriptor is a closed vocabulary, and the environment is a leaf OCI
 * image-manifest digest. The retained extent is EXACT over the Platform audit interval.
 *
 * THE BUNDLE MANIFEST (new here) is the build artifact the envelope's lineage entry
 * points at. It carries `bundleContentDigest`, the sha256 of the self-contained decoder
 * ARTIFACT ITSELF, inside the digest preimage, so `artifactDigest` transitively commits
 * the executable decoder and not merely its metadata (build review, MUST-FIX: without
 * it two different decoders could present the same manifest identity).
 * `validateBundleManifest` enforces the whole schema, and `checkBundleAgainstEntry` is
 * the OFFLINE half of the runtime duty the registry names: the manifest must repeat
 * environmentDigest, platformProtocolVersion, entryPoint and inputFormat, each EQUAL to
 * the serialized lineage entry, and both the entry's digest AND its content-addressed
 * reference must resolve to this bundle. Retrieving the artifact, hashing it against
 * bundleContentDigest, and hashing the OCI image against environmentDigest remain
 * runtime duties (this module compares a manifest already in hand; it cannot fetch).
 */
"use strict";

const crypto = require("crypto");
// THE shared RFC 8785 serializer with the full domain guard. decoderLineage previously
// carried its OWN partial encoder, which two independent build reviews found
// separately: it lacked the NFC and lone-surrogate guards and turned `undefined`
// into literal non-JSON text, so the very artifact the lineage commits could be digested
// out of domain. There is now genuinely ONE serializer.
const { canonicalize } = require("./canonicalJson.cjs");

const RUNTIME = "oci-image-v1";
const EXECUTION_PROFILE = "tegara-decoder-v1";
const ENTRY_POINT = "decode.mjs";
const INPUT_FORMAT = "raw-committed-tx-bytes";
const HEX32 = /^[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

function fail(msg) {
  throw new Error(`decoderLineage: ${msg}`);
}

/** the derived, never producer-chosen identity of a bundle */
const decoderIdFor = (artifactDigest) => {
  if (!HEX32.test(artifactDigest || "")) fail("artifactDigest must be 64 lowercase hex");
  return `decoder-sha256-${artifactDigest.slice(0, 16)}`;
};
/** the closed content-addressed reference grammar, embedding the same digest */
const artifactRefFor = (artifactDigest) => {
  if (!HEX32.test(artifactDigest || "")) fail("artifactDigest must be 64 lowercase hex");
  return `cas:sha256:${artifactDigest}`;
};

/**
 * makeLineageEntry - build one entry with every derivable field DERIVED, so a producer
 * cannot label it differently.
 */
function makeLineageEntry({ fromHeight, artifactDigest, platformProtocolVersion, environmentDigest }) {
  if (!Number.isSafeInteger(fromHeight) || fromHeight < 0) fail("fromHeight must be a safe non-negative integer");
  if (!Number.isSafeInteger(platformProtocolVersion) || platformProtocolVersion < 0) {
    fail("platformProtocolVersion must be a safe non-negative integer");
  }
  if (!DIGEST.test(environmentDigest || "")) fail("environmentDigest must be sha256:<64 lowercase hex>");
  return {
    fromHeight,
    decoderId: decoderIdFor(artifactDigest),
    artifactDigest,
    artifactRef: artifactRefFor(artifactDigest),
    platformProtocolVersion,
    runtime: RUNTIME,
    environmentDigest,
    executionProfile: EXECUTION_PROFILE,
    entryPoint: ENTRY_POINT,
    inputFormat: INPUT_FORMAT,
  };
}

const IDENTITY_FIELDS = ["artifactDigest", "platformProtocolVersion", "environmentDigest"];

/**
 * validateLineage - the canonicality rules, fail-closed:
 *  - strictly increasing fromHeight;
 *  - every field derived correctly and drawn from the closed vocabulary;
 *  - EXACT extent over [platformFromHeight, platformToHeight] (starts at the interval
 *    start; no entry beyond its end);
 *  - adjacent entries DIFFER in at least one bundle-identity field (change points, not
 *    deployments), so one history has exactly one serialization.
 */
const ENTRY_FIELDS = ["fromHeight", "decoderId", "artifactDigest", "artifactRef",
  "platformProtocolVersion", "runtime", "environmentDigest", "executionProfile",
  "entryPoint", "inputFormat"];

function validateLineage(lineage, { platformFromHeight, platformToHeight } = {}) {
  if (!Array.isArray(lineage) || lineage.length === 0) fail("lineage must be a non-empty array");
  // the audit-range arguments are part of the contract, not optional context
  // (build review round 3)
  if (!Number.isSafeInteger(platformFromHeight) || platformFromHeight < 0) {
    fail("platformFromHeight must be a safe non-negative integer");
  }
  if (!Number.isSafeInteger(platformToHeight) || platformToHeight < platformFromHeight) {
    fail("platformToHeight must be a safe integer at or above platformFromHeight");
  }
  for (const e of lineage) {
    if (!e || typeof e !== "object") fail("each lineage entry must be an object");
    for (const k of Object.keys(e)) {
      if (!ENTRY_FIELDS.includes(k)) fail(`lineage entry has undeclared field ${k}`);
    }
    for (const k of ENTRY_FIELDS) if (!(k in e)) fail(`lineage entry lacks ${k}`);
    if (!Number.isSafeInteger(e.fromHeight) || e.fromHeight < 0) {
      fail("entry fromHeight must be a safe NON-NEGATIVE integer");
    }
    if (e.decoderId !== decoderIdFor(e.artifactDigest)) fail(`decoderId ${e.decoderId} is not derived from its artifactDigest`);
    if (e.artifactRef !== artifactRefFor(e.artifactDigest)) fail(`artifactRef ${e.artifactRef} does not embed the artifactDigest`);
    if (e.runtime !== RUNTIME) fail(`runtime must be ${RUNTIME}`);
    if (e.executionProfile !== EXECUTION_PROFILE) fail(`executionProfile must be ${EXECUTION_PROFILE}`);
    if (e.entryPoint !== ENTRY_POINT) fail(`entryPoint must be ${ENTRY_POINT}`);
    if (e.inputFormat !== INPUT_FORMAT) fail(`inputFormat must be ${INPUT_FORMAT}`);
    if (!DIGEST.test(e.environmentDigest || "")) fail("environmentDigest must be sha256:<64 lowercase hex>");
    if (!Number.isSafeInteger(e.platformProtocolVersion) || e.platformProtocolVersion < 0) {
      fail("platformProtocolVersion must be a safe NON-NEGATIVE integer");
    }
  }
  for (let i = 1; i < lineage.length; i++) {
    if (lineage[i].fromHeight <= lineage[i - 1].fromHeight) fail("lineage fromHeight not strictly increasing");
    if (IDENTITY_FIELDS.every((k) => lineage[i][k] === lineage[i - 1][k])) {
      fail("adjacent lineage entries do not differ in any bundle-identity field (redundant split)");
    }
  }
  if (lineage[0].fromHeight !== platformFromHeight) {
    fail(`lineage starts at ${lineage[0].fromHeight}, not the platform audit fromHeight ${platformFromHeight}`);
  }
  if (lineage[lineage.length - 1].fromHeight > platformToHeight) {
    fail("unused decoder lineage entry beyond the platform audit interval");
  }
  return true;
}

/**
 * The pinned selection: for height h, the entry with the GREATEST fromHeight <= h,
 * chosen INDEPENDENTLY of array order (build review, MINOR: taking the last matching
 * element silently returned the wrong entry for an unvalidated, out-of-order lineage).
 */
function selectDecoder(lineage, height) {
  let sel = null;
  for (const e of lineage) {
    if (e.fromHeight <= height && (sel === null || e.fromHeight > sel.fromHeight)) sel = e;
  }
  if (sel === null) fail(`no decoder covers height ${height}`);
  return sel;
}

/**
 * THE PRODUCTION BUNDLE MANIFEST SCHEMA (build-order item 5's deliverable). The bundle
 * is the content-addressed decoder artifact; its canonical manifest is what
 * `artifactDigest` digests, and it REPEATS the execution descriptor so a retrieved
 * bundle can be checked against the envelope's serialized entry.
 */
const BUNDLE_MANIFEST_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "tegara:decoderBundleManifest:v1",
  title: "Tegara decoder bundle manifest, version 1",
  description:
    "The canonical manifest of a decoder BUNDLE. artifactDigest is the sha256 of these canonical manifest bytes with the two SELF-REFERENTIAL fields (artifactDigest, decoderId) excluded from the preimage; because bundleContentDigest -- the sha256 of the self-contained decoder artifact itself -- is INSIDE that preimage, artifactDigest transitively commits the executable decoder as well as its metadata. The manifest embeds the complete resolved dependency closure (the bundle imports nothing outside itself at runtime), repeats the execution descriptor the envelope serializes, and names the exact source revisions. Canonicalization is RFC 8785.",
  type: "object",
  additionalProperties: false,
  required: [
    "manifestVersion", "decoderId", "artifactDigest", "bundleContentDigest",
    "environmentDigest", "executionProfile", "runtime", "entryPoint", "inputFormat",
    "platformProtocolVersion", "sourceRevisions", "dependencyClosure",
  ],
  properties: {
    manifestVersion: { const: "1" },
    decoderId: { type: "string", pattern: "^decoder-sha256-[0-9a-f]{16}$" },
    // the SELF digest is excluded from the digested bytes (see canonicalBundleBytes);
    // it is carried for human/diagnostic use and MUST equal the computed digest
    artifactDigest: { type: "string", pattern: "^[0-9a-f]{64}$" },
    // THE DECODER BYTES THEMSELVES (build review, MUST-FIX): sha256 over the
    // self-contained bundle artifact. It is INSIDE the digest preimage, so
    // artifactDigest transitively commits the executable decoder; without it two
    // different decoders could present the same manifest identity. Hashing the
    // retrieved artifact and comparing is the runtime duty.
    bundleContentDigest: { type: "string", pattern: "^sha256:[0-9a-f]{64}$" },
    environmentDigest: { type: "string", pattern: "^sha256:[0-9a-f]{64}$" },
    executionProfile: { enum: [EXECUTION_PROFILE] },
    runtime: { enum: [RUNTIME] },
    entryPoint: { enum: [ENTRY_POINT] },
    inputFormat: { enum: [INPUT_FORMAT] },
    platformProtocolVersion: { type: "integer", minimum: 0, maximum: 9007199254740991 },
    sourceRevisions: {
      type: "object",
      additionalProperties: false,
      required: ["platform", "decoder"],
      properties: {
        platform: { type: "string", minLength: 1 },
        decoder: { type: "string", minLength: 1 },
      },
    },
    dependencyClosure: {
      type: "array",
      description: "the complete resolved closure, each entry content-addressed; an empty array asserts a genuinely dependency-free bundle",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["name", "version", "digest"],
        properties: {
          name: { type: "string", minLength: 1 },
          version: { type: "string", minLength: 1 },
          digest: { type: "string", pattern: "^sha256:[0-9a-f]{64}$" },
        },
      },
    },
  },
};

/**
 * RFC 8785 canonical bytes of the manifest EXCLUDING both SELF-REFERENTIAL fields, via
 * THE shared serializer (so the full domain guard -- NFC, lone surrogates, safe integers,
 * refusal of undefined/function/symbol/BigInt -- applies to the bundle manifest exactly
 * as it does to the envelope).
 *
 * `artifactDigest` obviously cannot digest itself, and `decoderId` is DERIVED from that
 * digest, so it is equally self-referential: including either would make the digest
 * unsatisfiable (a fixed point). Both are excluded from the preimage and checked
 * afterwards against the computed digest.
 */
function canonicalBundleBytes(manifest) {
  const { artifactDigest, decoderId, ...rest } = manifest;
  return canonicalize(rest);
}

/** the artifact digest of a manifest: sha256 over its canonical self-excluded bytes */
function bundleDigest(manifest) {
  return crypto.createHash("sha256").update(canonicalBundleBytes(manifest)).digest("hex");
}

/** validate a bundle manifest's shape and self-consistency (no fetching) */
function validateBundleManifest(manifest) {
  if (!manifest || typeof manifest !== "object") fail("bundle manifest must be an object");
  const req = BUNDLE_MANIFEST_SCHEMA.required;
  for (const k of req) if (!(k in manifest)) fail(`bundle manifest lacks ${k}`);
  for (const k of Object.keys(manifest)) {
    if (!(k in BUNDLE_MANIFEST_SCHEMA.properties)) fail(`bundle manifest has undeclared field ${k}`);
  }
  if (manifest.manifestVersion !== "1") fail("manifestVersion must be \"1\"");
  if (manifest.runtime !== RUNTIME) fail(`runtime must be ${RUNTIME}`);
  if (manifest.executionProfile !== EXECUTION_PROFILE) fail(`executionProfile must be ${EXECUTION_PROFILE}`);
  if (manifest.entryPoint !== ENTRY_POINT) fail(`entryPoint must be ${ENTRY_POINT}`);
  if (manifest.inputFormat !== INPUT_FORMAT) fail(`inputFormat must be ${INPUT_FORMAT}`);
  if (!DIGEST.test(manifest.environmentDigest || "")) fail("environmentDigest must be sha256:<64 lowercase hex>");
  if (!DIGEST.test(manifest.bundleContentDigest || "")) fail("bundleContentDigest must be sha256:<64 lowercase hex>");
  if (!Number.isSafeInteger(manifest.platformProtocolVersion) || manifest.platformProtocolVersion < 0) {
    fail("platformProtocolVersion must be a safe NON-NEGATIVE integer");
  }
  // the full sourceRevisions shape (build review, MAJOR: only its presence was checked,
  // so `sourceRevisions: 42` and undeclared sub-fields passed)
  const sr = manifest.sourceRevisions;
  if (!sr || typeof sr !== "object" || Array.isArray(sr)) fail("sourceRevisions must be an object");
  for (const k of ["platform", "decoder"]) {
    if (typeof sr[k] !== "string" || sr[k].length === 0) fail(`sourceRevisions.${k} must be a non-empty string`);
  }
  for (const k of Object.keys(sr)) {
    if (k !== "platform" && k !== "decoder") fail(`sourceRevisions has undeclared field ${k}`);
  }
  if (!Array.isArray(manifest.dependencyClosure)) fail("dependencyClosure must be an array");
  for (const d of manifest.dependencyClosure) {
    if (!d || typeof d !== "object" || Array.isArray(d)) fail("dependencyClosure entry must be an object");
    if (typeof d.name !== "string" || d.name.length === 0) fail("dependencyClosure entry needs a non-empty name");
    if (typeof d.version !== "string" || d.version.length === 0) fail("dependencyClosure entry needs a non-empty version");
    if (!DIGEST.test(d.digest || "")) fail("dependencyClosure entry needs a sha256:<64 hex> digest");
    for (const k of Object.keys(d)) {
      if (!["name", "version", "digest"].includes(k)) fail(`dependencyClosure entry has undeclared field ${k}`);
    }
  }
  const computed = bundleDigest(manifest);
  if (manifest.artifactDigest !== computed) {
    fail(`bundle artifactDigest ${manifest.artifactDigest} != the digest of its canonical bytes ${computed}`);
  }
  if (manifest.decoderId !== decoderIdFor(computed)) fail("bundle decoderId is not derived from its own digest");
  return true;
}

/**
 * checkBundleAgainstEntry - the OFFLINE half of the registry's runtime duty: a retrieved
 * bundle manifest must be self-consistent AND repeat every field the envelope's lineage
 * entry serialized. Fetching the bundle and hashing the OCI image stay runtime duties.
 */
function checkBundleAgainstEntry(manifest, entry) {
  validateBundleManifest(manifest);
  if (manifest.artifactDigest !== entry.artifactDigest) {
    fail(`bundle digest ${manifest.artifactDigest} != the lineage entry's ${entry.artifactDigest}`);
  }
  for (const k of ["environmentDigest", "platformProtocolVersion", "entryPoint", "inputFormat",
                   "executionProfile", "runtime", "decoderId"]) {
    if (manifest[k] !== entry[k]) {
      fail(`bundle ${k} ${JSON.stringify(manifest[k])} != the lineage entry's ${JSON.stringify(entry[k])}`);
    }
  }
  // the REFERENCE must resolve to this same bundle (build review, MAJOR: an entry with
  // the right digest but a ref naming another bundle passed the binding)
  if (entry.artifactRef !== artifactRefFor(manifest.artifactDigest)) {
    fail(`lineage artifactRef ${entry.artifactRef} does not reference the validated bundle`);
  }
  return true;
}

module.exports = {
  RUNTIME, EXECUTION_PROFILE, ENTRY_POINT, INPUT_FORMAT, BUNDLE_MANIFEST_SCHEMA,
  decoderIdFor, artifactRefFor, makeLineageEntry, validateLineage, selectDecoder,
  canonicalBundleBytes, bundleDigest, validateBundleManifest, checkBundleAgainstEntry,
};
