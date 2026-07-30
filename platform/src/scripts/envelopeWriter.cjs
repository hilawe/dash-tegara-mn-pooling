/**
 * envelopeWriter - THE PRODUCTION ENTRY POINT for emitting an audit envelope.
 *
 * WHY THIS EXISTS (build review round 3, MUST-FIX). `auditSeam.buildEnvelope` is a
 * DERIVATION PRIMITIVE: it computes the decision surface from evidence and canonicalizes
 * it. It does NOT validate. A reviewer fed it 72 negative-evidence cases; it accepted 67,
 * and 63 of the envelopes it produced were then REJECTED by the normative schema and
 * semantic checker. A writer that emits records the normative reader rejects is emitting
 * garbage, so the derivation primitive must never be the production entry point.
 *
 * THE GATE IS THE EXECUTABLE SPECIFICATION ITSELF. `docs/schema/check_vectors.py` is
 * normative; this module invokes it rather than reimplementing its semantic layer in
 * JavaScript. That is a deliberate choice: a second implementation of ~1000 lines of
 * semantic rules is a second thing to drift, and the whole review cycle was about
 * eliminating divergence. The cost is that writing requires python3 and the schema
 * package on disk; `writeEnvelope` FAILS CLOSED if the gate cannot run, and never
 * returns an ungated envelope.
 *
 * CLAIMS COME FROM VERIFIER RESULTS, NOT FROM STRINGS. The same review found that
 * `ranVerifiers` was a caller-supplied list of names that minted AUTHENTICATED with no
 * verifier having executed. Here a component can only reach AUTHENTICATED by supplying
 * an ATTESTATION: an object recording that a named verifier actually ran and succeeded,
 * over identified evidence. No runtime verifier exists yet, so in practice production
 * callers pass NONE and every component is TRUSTED_SOURCE, which is the honest state.
 *
 * WHAT AN ATTESTATION DOES AND DOES NOT ESTABLISH (property review, P4). An attestation
 * is an in-process object, so this module can check its SHAPE, its NAMED verifier against
 * the registry, and its BINDING to the evidence digest, and it does check all three. It
 * cannot establish PROVENANCE: nothing here proves the named verifier is what produced the
 * `ran`, `ok` and digest assertions, because a caller in the same process can construct
 * the object directly. That is a boundary of the format, not an oversight, and v1 does not
 * claim otherwise. AUTHENTICATED means the WRITER's harness observed the verifier succeed
 * over exactly this evidence. It is not transferable proof to a third party, and the
 * envelope is designed so a third party does not need it: the record commits the
 * interpreting verifier bundle (verifierBundleDigest), so a reader re-runs the verifiers
 * against the retained evidence and reaches its own claim rather than trusting this one.
 */
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const { buildEnvelope } = require("./auditSeam.cjs");

const SCHEMA_DIR = path.join(__dirname, "..", "..", "..", "docs", "schema");

// the members the writer DERIVES; a caller must not bind attestations to them
const DERIVED_MEMBERS = ["rewards", "claimProfile"];

/**
 * The retained evidence, with any derived member the caller left in place removed
 * (independent review, MINOR): the attestation digest must cover EXACTLY the evidence
 * that ends up in the record. Hashing a stale `rewards` array the writer then overwrites
 * bound an honest caller's attestations to data that does not exist in the output.
 *
 * The result is also DETACHED from the caller by a single structured clone, and that
 * one snapshot is what gets digested AND what gets derived from (property review, P5/P9).
 * The order used to be the other way round: digest the caller's object, then let
 * buildEnvelope clone it. A shallow spread snapshots only top-level values, so a NESTED
 * accessor was read once for the digest and again for the clone, and nothing required the
 * two reads to agree. Reproduced against the committed positive vector with a getter on
 * validatedChainLock.height: the digest covered height 1500 while the record carried 1499,
 * so an attestation was bound to a value absent from the output. Snapshotting first makes
 * every later read a read of plain data, so the digest covers the bytes that ship.
 */
function retainedEvidenceOnly(evidence) {
  const out = { ...evidence };
  for (const k of DERIVED_MEMBERS) delete out[k];
  // structuredClone also refuses functions and symbols outright, so evidence cannot
  // smuggle behaviour past the derivation.
  try {
    return structuredClone(out);
  } catch (e) {
    fail(`evidence is outside the serializable domain (${(e && e.message) || e})`);
  }
}

function fail(msg) {
  throw new Error(`envelopeWriter: ${msg}`);
}

/**
 * The verifier each component's AUTHENTICATED claim requires. Imported rather than restated
 * (confirmation round, MINOR): auditSeam's claim-profile derivation reads the same mapping,
 * and two copies could have drifted apart under a rename.
 */
const { VERIFIER_OF } = require("./verifierRegistry.cjs");

/**
 * Turn ATTESTATIONS into the verifier-name list the derivation consumes, refusing
 * anything that is not a genuine record of execution.
 *
 * An attestation is `{ component, verifier, ran: true, ok: true, evidenceDigest }`:
 *   component      the registry component it authenticates
 *   verifier       must EQUAL the verifier the registry names for that component
 *   ran / ok       both must be exactly true (a verifier that did not run, or ran and
 *                  failed, can never contribute a claim)
 *   evidenceDigest a sha256 over the evidence the verifier consumed, so an attestation
 *                  cannot be recycled across envelopes
 */
function verifiersFromAttestations(attestations, evidenceDigest) {
  if (attestations === undefined || attestations === null) return [];
  if (!Array.isArray(attestations)) fail("attestations must be an array");
  const names = [];
  const seen = new Set();
  for (const a of attestations) {
    if (!a || typeof a !== "object") fail("each attestation must be an object");
    if (!(a.component in VERIFIER_OF)) fail(`unknown component ${JSON.stringify(a.component)}`);
    const expected = VERIFIER_OF[a.component];
    if (expected === null) fail(`component ${a.component} has no verifier and can never be attested`);
    if (a.verifier !== expected) {
      fail(`attestation for ${a.component} names ${JSON.stringify(a.verifier)}, not ${expected}`);
    }
    if (a.ran !== true) fail(`attestation for ${a.component} does not record that the verifier RAN`);
    if (a.ok !== true) fail(`attestation for ${a.component} does not record SUCCESS`);
    if (typeof a.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/.test(a.evidenceDigest)) {
      fail(`attestation for ${a.component} lacks a sha256 evidenceDigest`);
    }
    if (a.evidenceDigest !== evidenceDigest) {
      fail(`attestation for ${a.component} was made over DIFFERENT evidence (it cannot be reused here)`);
    }
    if (seen.has(a.component)) fail(`duplicate attestation for ${a.component}`);
    seen.add(a.component);
    names.push(expected);
  }
  return names;
}

/**
 * Run THE NORMATIVE GATE (the executable specification) over a candidate envelope.
 * Returns { valid: true } or { valid: false, layer, error }. Throws only if the gate
 * itself cannot be run, which the caller must treat as a refusal to emit.
 */
function validateAgainstSpecification(envelope, canonicalBytes) {
  // THE ARGUMENT CHECK RUNS OUTSIDE THE TRY (repository-access review, MINOR). It used to sit
  // inside, so a mismatched pair was caught by the broad handler below and reported as though
  // python3 could not be run, which points a caller at the wrong cause entirely.
  const derived = require("./canonicalJson.cjs").canonicalize(envelope);
  if (canonicalBytes && Buffer.compare(Buffer.from(canonicalBytes), derived) !== 0) {
    fail("the supplied bytes are not the canonical form of the supplied envelope");
  }
  let tmp;
  try {
    tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "tegara-gate-")), "candidate.json");
    // Write the CANONICAL bytes, not an ad-hoc JSON.stringify (independent review,
    // MINOR): under the current checker the two parse identically, but the claim "the
    // gated bytes are the returned bytes" should be true by construction rather than by
    // the checker happening to be whitespace- and order-insensitive.
    const bytes = canonicalBytes || derived;
    fs.writeFileSync(tmp, bytes);
    const script = [
      "import json,sys,importlib.util",
      "s=importlib.util.spec_from_file_location('cv','check_vectors.py')",
      "m=importlib.util.module_from_spec(s); s.loader.exec_module(m)",
      "import jsonschema",
      "env=json.load(open(sys.argv[1]))",
      "v=jsonschema.Draft202012Validator(json.load(open(m.SCHEMA_PATH)))",
      "errs=list(v.iter_errors(env))",
      "if errs: print(json.dumps({'valid':False,'layer':'schema','error':'/'.join(map(str,errs[0].path))+': '+errs[0].message})); sys.exit(0)",
      "try:",
      "    m.check_semantics(env)",
      "except m.SemanticError as e:",
      "    print(json.dumps({'valid':False,'layer':'semantic','error':str(e)})); sys.exit(0)",
      "print(json.dumps({'valid':True}))",
    ].join("\n");
    const out = execFileSync("python3", ["-c", script, tmp],
      { cwd: SCHEMA_DIR, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    return JSON.parse(out);
  } catch (e) {
    fail(`the normative gate could not be run (${(e && e.message) || e}); refusing to emit an ungated envelope`);
  } finally {
    if (tmp) { try { fs.rmSync(path.dirname(tmp), { recursive: true, force: true }); } catch (_) { /* best effort */ } }
  }
}

/**
 * writeEnvelope - derive, GATE, and only then return the canonical bytes.
 *
 *   evidence      the retained evidence (no derived members)
 *   attestations  optional records of verifiers that ACTUALLY ran and succeeded; absent
 *                 (the production reality today) every component is TRUSTED_SOURCE
 *
 * Throws if the derived envelope does not satisfy the normative schema and semantic
 * layer. It never returns an envelope the normative reader would reject.
 */
function writeEnvelope(evidence, { attestations } = {}) {
  if (!evidence || typeof evidence !== "object") fail("evidence must be an object");
  const crypto = require("crypto");
  const { canonicalize } = require("./canonicalJson.cjs");
  // SNAPSHOT FIRST, then digest, then derive from the same snapshot. The order matters
  // (property review, P5/P9): the digest must cover the bytes that ship, and only a
  // detached copy makes every later read a read of the same plain data.
  const retained = retainedEvidenceOnly(evidence);
  const evidenceDigest = crypto.createHash("sha256").update(canonicalize(retained)).digest("hex");
  const ranVerifiers = verifiersFromAttestations(attestations, evidenceDigest);

  const built = buildEnvelope(retained, { ranVerifiers });
  // gate EXACTLY the bytes that will be returned
  const gate = validateAgainstSpecification(built.envelope, built.canonicalBytes);
  if (!gate.valid) {
    fail(`the derived envelope is NOT conformant (${gate.layer} layer): ${gate.error}`);
  }
  return { ...built, evidenceDigest, gate: { validated: true, by: "check_vectors.py" } };
}

module.exports = {
  writeEnvelope, validateAgainstSpecification, verifiersFromAttestations, VERIFIER_OF,
};
