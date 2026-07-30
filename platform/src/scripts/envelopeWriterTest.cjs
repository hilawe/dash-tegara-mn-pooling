/**
 * Fixtures for THE PRODUCTION ENTRY POINT (build review round 3, MUST-FIX). The decisive
 * property: evidence that the normative checker would reject must NOT produce an
 * envelope. The reviewer fed the derivation primitive 72 negative-evidence cases and it
 * accepted 67; these fixtures assert the gated writer refuses them.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const { writeEnvelope, validateAgainstSpecification, verifiersFromAttestations } = require("./envelopeWriter.cjs");
const { canonicalize } = require("./canonicalJson.cjs");

let pass = 0, fail = 0;
const ok = (n, c) => { if (c) pass++; else { fail++; console.error(`FAIL: ${n}`); } };
const throws = (n, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${n} (no error)`); }
  catch (e) { ok(n, re.test((e && e.message) || "")); }
};
const SCHEMA_DIR = path.join(__dirname, "..", "..", "..", "docs", "schema");
const evidenceOf = (env) => { const e = { ...env }; delete e.rewards; delete e.claimProfile; return e; };
const positive = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, "vectors", "positive_minimal.json"), "utf8"));
const clone = (o) => JSON.parse(JSON.stringify(o));

// ---- valid evidence still writes, byte-identical to the shipped vector ----
const good = writeEnvelope(evidenceOf(positive));
ok("valid evidence writes", good.gate.validated === true);
ok("bytes are the shipped canonical form", good.canonicalBytes.length === 15797);
ok("digest is the shipped digest",
   good.sha256 === "f6c656671362f9952c88e766e9e7f328ed3fa976e9cb8999074c6add184d49fe");

// ---- THE GATE: evidence the normative checker rejects must NOT be emitted ----
// the reviewer's own case: v1 requires every share to be exactly 1/slotCount
const unequal = evidenceOf(clone(positive));
unequal.checkpoints[0].extractedBinding.books[0].shares =
  [{ numerator: "3", denominator: "4" }, { numerator: "1", denominator: "4" }];
throws("unequal shares are refused, not allocated 75/25",
  () => writeEnvelope(unequal), /NOT conformant/);
// a lifecycle inconsistent with the list-walk ledger
const badLifecycle = evidenceOf(clone(positive));
badLifecycle.lifecycle.terminalHeight = 1001;
throws("a lifecycle contradicting the walk is refused",
  () => writeEnvelope(badLifecycle), /NOT conformant/);
// anchor regression in the platform ledger
const badAnchor = evidenceOf(clone(positive));
badAnchor.coverage.platformLedger[2].coreChainLockedHeight = 1;
// now refused EARLIER than the gate: the closing-block search asserts its own
// precondition, so the failure names the actual problem instead of a downstream symptom
throws("anchor regression is refused", () => writeEnvelope(badAnchor), /anchors regress|NOT conformant/);
// cross-ledger disagreement at a shared height (a soundness review)
const badJoin = evidenceOf(clone(positive));
badJoin.coverage.coreLedger[0].blockHash = "11".repeat(32);
throws("cross-ledger disagreement is refused", () => writeEnvelope(badJoin), /NOT conformant/);
// an invalid decoder selection
const badDecoder = evidenceOf(clone(positive));
badDecoder.coverage.platformLedger[0].decoderId = "decoder-sha256-" + "00".repeat(8);
throws("an invalid decoder selection is refused", () => writeEnvelope(badDecoder), /NOT conformant/);
// a checkpoint whose extracted binding does not byte-match its signed payload
const badBinding = evidenceOf(clone(positive));
badBinding.checkpoints[0].extractedBinding.bindings[0].slotIndex = 3;
throws("a checkpoint mismatch is refused", () => writeEnvelope(badBinding), /NOT conformant/);
// an incomplete ownership history
const badChain = evidenceOf(clone(positive));
badChain.slots[0].ownershipChain = badChain.slots[0].ownershipChain.slice(0, 1);
throws("an incomplete ownership history is refused", () => writeEnvelope(badChain), /NOT conformant/);

// ---- CLAIMS COME FROM ATTESTATIONS, NEVER FROM CALLER STRINGS ----
const digest = crypto.createHash("sha256").update(canonicalize(evidenceOf(positive))).digest("hex");
throws("a bare verifier NAME cannot mint a claim",
  () => writeEnvelope(evidenceOf(clone(positive)), { attestations: ["verifyCoreWalk"] }),
  /must be an object/);
throws("an attestation that did not RUN is refused", () => verifiersFromAttestations(
  [{ component: "identifierConversion", verifier: "verifyIdentifierConversion", ran: false, ok: true, evidenceDigest: digest }], digest),
  /does not record that the verifier RAN/);
throws("an attestation that FAILED is refused", () => verifiersFromAttestations(
  [{ component: "identifierConversion", verifier: "verifyIdentifierConversion", ran: true, ok: false, evidenceDigest: digest }], digest),
  /does not record SUCCESS/);
throws("an attestation naming the WRONG verifier is refused", () => verifiersFromAttestations(
  [{ component: "identifierConversion", verifier: "verifyCoreWalk", ran: true, ok: true, evidenceDigest: digest }], digest),
  /names .*not verifyIdentifierConversion/);
throws("an attestation over OTHER evidence cannot be reused", () => verifiersFromAttestations(
  [{ component: "identifierConversion", verifier: "verifyIdentifierConversion", ran: true, ok: true, evidenceDigest: "ab".repeat(32) }], digest),
  /DIFFERENT evidence/);
throws("the schedule component can never be attested", () => verifiersFromAttestations(
  [{ component: "schedule", verifier: "x", ran: true, ok: true, evidenceDigest: digest }], digest),
  /never be attested/);
throws("a duplicate attestation is refused", () => verifiersFromAttestations(
  [{ component: "identifierConversion", verifier: "verifyIdentifierConversion", ran: true, ok: true, evidenceDigest: digest },
   { component: "identifierConversion", verifier: "verifyIdentifierConversion", ran: true, ok: true, evidenceDigest: digest }], digest),
  /duplicate attestation/);
ok("with NO attestations every component is TRUSTED_SOURCE (the honest state today)",
   Object.values(good.envelope.claimProfile.components).every((c) => c.claim === "TRUSTED_SOURCE") &&
   good.envelope.claimProfile.aggregate === "trusted-source");

// ---- the gate itself ----
ok("validateAgainstSpecification accepts the shipped vector",
   validateAgainstSpecification(positive).valid === true);
const broken = clone(positive); broken.envelopeVersion = "2";
const vr = validateAgainstSpecification(broken);
ok("...and rejects a malformed one at the schema layer", vr.valid === false && vr.layer === "schema");

// ---- the writer does not retain caller references ----
const ev = evidenceOf(clone(positive));
const w = writeEnvelope(ev);
ev.contractId = "MUTATED";
ok("mutating the caller's evidence afterwards cannot stale the result",
   w.envelope.contractId !== "MUTATED" &&
   w.sha256 === crypto.createHash("sha256").update(w.canonicalBytes).digest("hex"));

// ---- THE GATE FAILS CLOSED WHEN IT CANNOT RUN (independent review, MINOR: the most
// valuable missing test -- every other fixture runs where python3 always succeeds, so a
// weakened implementation that SWALLOWED gate errors would pass them all) ----
{
  // run the writer in a child process with PATH emptied, so python3 cannot be found
  const probe = `
    const { writeEnvelope } = require(${JSON.stringify(path.join(__dirname, "envelopeWriter.cjs"))});
    const fs = require("fs");
    const ev = JSON.parse(fs.readFileSync(${JSON.stringify(path.join(SCHEMA_DIR, "vectors", "positive_minimal.json"))}, "utf8"));
    delete ev.rewards; delete ev.claimProfile;
    try { writeEnvelope(ev); console.log("EMITTED"); }
    catch (e) { console.log(/could not be run/.test(e.message) ? "REFUSED" : "OTHER:" + e.message); }
  `;
  const out = require("child_process").execFileSync(process.execPath, ["-e", probe],
    { encoding: "utf8", env: { PATH: "/nonexistent" } }).trim();
  ok("with the gate unrunnable, the writer REFUSES rather than emitting ungated", out === "REFUSED");
}

// ---- the attestation digest covers EXACTLY the retained evidence (independent review) ----
{
  const cleanEv = evidenceOf(positive);
  const sloppy = evidenceOf(positive);
  sloppy.rewards = [{ stale: "a derived member the writer will overwrite" }];
  const a = writeEnvelope(clone(cleanEv));
  const b = writeEnvelope(sloppy);
  ok("a stale derived member in the input does not change the record",
     a.canonicalBytes.equals(b.canonicalBytes));
  ok("...and no longer changes the attestation digest either",
     a.evidenceDigest === b.evidenceDigest);
  ok("the digest is over the retained evidence actually written",
     a.evidenceDigest === crypto.createHash("sha256")
       .update(require("./canonicalJson.cjs").canonicalize(evidenceOf(positive))).digest("hex"));
}

// ---- THE FULL NORMATIVE REJECTION CORPUS (independent review, MINOR: the most valuable
// missing test). Previously only a handful of cases were exercised, so a weakened gate
// that hard-coded exactly those and accepted everything else would still have passed.
// This drives ALL 86 normative rejection cases through writeEnvelope and requires the
// INVARIANT: every case either throws, or emits a record the normative checker ACCEPTS.
// It turns a one-off measurement into a standing guarantee. ----
{
  const corpus = execFileSync("python3", ["-c",
    "import json,importlib.util;s=importlib.util.spec_from_file_location('cv','check_vectors.py');" +
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);p=m.build_positive();" +
    "print(json.dumps([{'name':n,'env':e} for n,l,e in m.negatives(p)]))"],
    { cwd: SCHEMA_DIR, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  const cases = JSON.parse(corpus);
  ok("the corpus is the full normative rejection set", cases.length === 86);
  let declined = 0, emitted = 0;
  const nonConforming = [];
  for (const c of cases) {
    const ev = evidenceOf(c.env);
    let built;
    try { built = writeEnvelope(ev); } catch (e) { declined++; continue; }
    emitted++;
    if (validateAgainstSpecification(built.envelope, built.canonicalBytes).valid !== true) {
      nonConforming.push(c.name);
    }
  }
  ok(`every one of the ${cases.length} cases either declined (${declined}) or emitted a CONFORMING record (${emitted})`,
     nonConforming.length === 0);
  if (nonConforming.length) console.error("  non-conforming:", nonConforming.join(", "));
  ok("the gate is not vacuous: most cases are declined outright", declined >= 60);
}

// ---- the indexed suspension path and the scan fallback AGREE (independent review) ----
{
  const { recognizeAt } = require("./auditSeam.cjs");
  const base = evidenceOf(positive);
  const ctx = {
    checkpoints: base.checkpoints, poolProTxHash: base.poolProTxHash,
    poolL1SlotIndex: base.poolL1SlotIndex, contractId: base.contractId, poolId: base.poolId,
    lifecycle: { ...base.lifecycle, suspensions: [
      { start: { kind: "observed", banHeight: 940 }, endHeight: 960 },
      { start: { kind: "observed", banHeight: 1200 }, endHeight: 1300 }] },
    baseHeight: base.basePackage.baseBlock.height,
  };
  // the fallback path (no index supplied) versus an explicitly indexed one, over a dense
  // range of heights: they must agree at every height
  const iv = ctx.lifecycle.suspensions
    .map((s) => [s.start.banHeight + 1, s.endHeight]).sort((x, y) => x[0] - y[0]);
  const indexed = (H) => { let lo = 0, hi = iv.length - 1;
    while (lo <= hi) { const m = (lo + hi) >> 1; const [a, b] = iv[m];
      if (H < a) hi = m - 1; else if (H > b) lo = m + 1; else return true; } return false; };
  let disagreements = 0;
  for (let H = 900; H <= 1400; H++) {
    const viaFallback = recognizeAt(H, ctx).status;
    const viaIndex = recognizeAt(H, { ...ctx, suspendedAt: indexed }).status;
    if (viaFallback !== viaIndex) disagreements++;
  }
  ok("the indexed suspension path and the scan fallback agree over 501 heights", disagreements === 0);
}

// ---------------------------------------------------------------------------
// The property review (2026-07-25) reported four properties as unconstrained by these
// fixtures. The gaps were real; each is now driven directly.
// ---------------------------------------------------------------------------

// P5/P9: THE ATTESTATION DIGEST MUST COVER THE BYTES THAT SHIP. Before the fold the
// caller's object was digested and only then cloned, so a NESTED accessor was read twice
// with no requirement that the reads agree. This drives exactly that shape.
{
  const ev = evidenceOf(clone(positive));
  const real = ev.validatedChainLock.height;
  let reads = 0;
  Object.defineProperty(ev.validatedChainLock, "height", {
    enumerable: true, configurable: true,
    get() { reads++; return reads === 1 ? real : real - 1; },
  });
  const out = writeEnvelope(ev);
  ok("a nested accessor is read exactly once (the snapshot precedes the digest)", reads === 1);
  ok("the written height is the height that was digested", out.envelope.validatedChainLock.height === real);
  // the digest the writer reports must equal a digest recomputed over what it emitted
  const emitted = evidenceOf(JSON.parse(out.canonicalBytes.toString("utf8")));
  ok("the reported evidenceDigest covers the emitted evidence",
     out.evidenceDigest === crypto.createHash("sha256").update(canonicalize(emitted)).digest("hex"));
}

// P5/P9, the other half: evidence outside the serializable domain is refused by name
// rather than reaching the derivation.
throws("evidence carrying a function is refused",
  () => writeEnvelope({ ...evidenceOf(clone(positive)), rogue: () => 1 }),
  /outside the serializable domain/);

// P3: THE GATED BYTES ARE THE RETURNED BYTES. Capture what the gate was handed by
// validating the returned bytes a second time on their own; a divergence between the two
// would show up as a gate verdict that disagrees with the emitted record.
{
  const out = writeEnvelope(evidenceOf(positive));
  const reparsed = JSON.parse(out.canonicalBytes.toString("utf8"));
  const verdict = validateAgainstSpecification(reparsed, out.canonicalBytes);
  ok("the returned bytes independently satisfy the normative gate", verdict.valid === true);
  ok("the returned bytes are their own canonical form",
     Buffer.compare(out.canonicalBytes, canonicalize(out.envelope)) === 0);
}

// P4: the attestation checks that CAN be made are made. Provenance cannot be established
// in-process (the module header states that boundary); shape, registry agreement and the
// evidence binding can be, and are.
{
  const ev = evidenceOf(positive);
  const digest = writeEnvelope(ev).evidenceDigest;
  const att = (over) => [{ component: "identifierConversion", verifier: "verifyIdentifierConversion",
                           ran: true, ok: true, evidenceDigest: over }];
  ok("an attestation bound to THIS evidence is accepted",
     verifiersFromAttestations(att(digest), digest).length === 1);
  throws("an attestation bound to other evidence cannot be reused",
    () => verifiersFromAttestations(att("0".repeat(64)), digest), /DIFFERENT evidence/);
  throws("a verifier that did not run cannot contribute a claim",
    () => verifiersFromAttestations(
      [{ ...att(digest)[0], ran: false }], digest), /does not record that the verifier RAN/);
  throws("a component the registry gives no verifier can never be attested",
    () => verifiersFromAttestations(
      [{ component: "schedule", verifier: "x", ran: true, ok: true, evidenceDigest: digest }], digest),
    /can never be attested/);
}

// THE MISMATCHED PAIR (repository-access round, MINOR). The helper is exported, and a
// mismatched (envelope, bytes) pair used to be caught by the broad gate handler and reported
// as though python3 could not be run, pointing a caller at the wrong cause.
{
  const good = writeEnvelope(evidenceOf(positive));
  const malformed = clone(good.envelope);
  malformed.envelopeVersion = "999";
  throws("a malformed envelope with another envelope's bytes is refused",
    () => validateAgainstSpecification(malformed, good.canonicalBytes),
    /not the canonical form of the supplied envelope/);
  throws("the refusal names the ARGUMENT MISMATCH, not a missing interpreter",
    () => validateAgainstSpecification(malformed, good.canonicalBytes),
    /^(?!.*could not be run).*$/);
  ok("a matching pair still validates",
     validateAgainstSpecification(good.envelope, good.canonicalBytes).valid === true);
}

// THE BYTES HANDED TO THE GATE, ISOLATED (round 4, MINOR). The earlier fixture reparsed and
// re-validated the RETURNED bytes, which proves they conform but would not fail if a writer
// gated one conforming candidate and returned a different conforming one. This intercepts the
// temporary file the gate is given and compares it with what came back.
{
  const realWriteFileSync = fs.writeFileSync;
  const written = [];
  fs.writeFileSync = function (...args) {
    if (typeof args[0] === "string" && /tegara-gate-/.test(args[0])) written.push(args[1]);
    return realWriteFileSync.apply(this, args);
  };
  let out;
  try {
    out = writeEnvelope(evidenceOf(positive));
  } finally {
    fs.writeFileSync = realWriteFileSync;
  }
  ok("the gate was handed exactly one candidate", written.length === 1);
  ok("the bytes handed to the gate ARE the bytes returned",
     Buffer.compare(Buffer.from(written[0]), out.canonicalBytes) === 0);
}

console.log(`envelopeWriterTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
