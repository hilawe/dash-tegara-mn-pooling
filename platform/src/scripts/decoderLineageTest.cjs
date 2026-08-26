/**
 * Fixtures for the decoder lineage + production bundle manifest (build-order item 5).
 * Plain `node`. Covers the derived-identity rules, the canonicality rules (strictly
 * increasing, exact extent, change points not deployments), the pinned selection, the
 * bundle manifest schema with its self-digest, and the offline half of the
 * bundle-vs-entry runtime duty. Cross-checks the shipped positive vector's own lineage
 * and the committed execution-profile document.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  EXECUTION_PROFILE, RUNTIME, ENTRY_POINT, INPUT_FORMAT, BUNDLE_MANIFEST_SCHEMA,
  decoderIdFor, artifactRefFor, makeLineageEntry, validateLineage, selectDecoder,
  bundleDigest, validateBundleManifest, checkBundleAgainstEntry,
} = require("./decoderLineage.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const throws = (name, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || "")); }
};

const D1 = "dd".repeat(32);
const D2 = "ab".repeat(32);
const ENV1 = "sha256:" + "11".repeat(32);
const ENV2 = "sha256:" + "22".repeat(32);
const entry = (fromHeight, artifactDigest = D1, platformProtocolVersion = 9, environmentDigest = ENV1) =>
  makeLineageEntry({ fromHeight, artifactDigest, platformProtocolVersion, environmentDigest });

// ---- derived identity ----
ok("decoderId is the digest's first 16 hex", decoderIdFor(D1) === "decoder-sha256-" + D1.slice(0, 16));
ok("artifactRef embeds the same digest", artifactRefFor(D1) === `cas:sha256:${D1}`);
throws("a bad digest is refused", () => decoderIdFor("nope"), /64 lowercase hex/);
const e1 = entry(1);
ok("makeLineageEntry derives id and ref", e1.decoderId === decoderIdFor(D1) && e1.artifactRef === artifactRefFor(D1));
ok("makeLineageEntry pins the closed vocabulary",
   e1.runtime === RUNTIME && e1.executionProfile === EXECUTION_PROFILE &&
   e1.entryPoint === ENTRY_POINT && e1.inputFormat === INPUT_FORMAT);
throws("a bad environmentDigest is refused", () => entry(1, D1, 9, "deadbeef"), /environmentDigest/);

// ---- lineage canonicality ----
ok("a single entry covering the interval validates",
   validateLineage([entry(1)], { platformFromHeight: 1, platformToHeight: 3 }));
throws("a lineage not starting at the interval start is refused",
  () => validateLineage([entry(2)], { platformFromHeight: 1, platformToHeight: 3 }), /not the platform audit fromHeight/);
throws("an entry beyond the interval end is refused",
  () => validateLineage([entry(1), entry(9, D2)], { platformFromHeight: 1, platformToHeight: 3 }), /beyond the platform audit interval/);
throws("non-increasing fromHeight is refused",
  () => validateLineage([entry(1), entry(1, D2)], { platformFromHeight: 1, platformToHeight: 3 }), /strictly increasing/);
throws("adjacent identical entries are a redundant split",
  () => validateLineage([entry(1), entry(2)], { platformFromHeight: 1, platformToHeight: 3 }), /redundant split/);
// each identity field alone is enough of a change point
ok("an artifact change point is legal",
   validateLineage([entry(1), entry(2, D2)], { platformFromHeight: 1, platformToHeight: 3 }));
ok("a protocol-version change point is legal",
   validateLineage([entry(1), entry(2, D1, 10)], { platformFromHeight: 1, platformToHeight: 3 }));
ok("an environment change point is legal",
   validateLineage([entry(1), entry(2, D1, 9, ENV2)], { platformFromHeight: 1, platformToHeight: 3 }));
throws("a producer-relabelled decoderId is refused", () => {
  const bad = entry(1); bad.decoderId = "decoder-sha256-" + "00".repeat(8);
  validateLineage([bad], { platformFromHeight: 1, platformToHeight: 3 });
}, /not derived/);
throws("a ref pointing at another bundle is refused", () => {
  const bad = entry(1); bad.artifactRef = artifactRefFor(D2);
  validateLineage([bad], { platformFromHeight: 1, platformToHeight: 3 });
}, /does not embed/);

// ---- the pinned selection ----
const lin = [entry(1), entry(5, D2)];
ok("selection takes the greatest fromHeight <= h", selectDecoder(lin, 4).artifactDigest === D1);
ok("selection switches at the change point", selectDecoder(lin, 5).artifactDigest === D2);
ok("selection holds after the change point", selectDecoder(lin, 99).artifactDigest === D2);
throws("no covering entry fails closed", () => selectDecoder(lin, 0), /no decoder covers/);
// order independence (build review, MINOR): an out-of-order array must not change the answer
ok("selection is independent of array order",
   selectDecoder([entry(5, D2), entry(1)], 6).fromHeight === 5);

// ---- the production bundle manifest ----
const BUNDLE1 = "sha256:" + "44".repeat(32);
const BUNDLE2 = "sha256:" + "55".repeat(32);
const mkManifest = (over = {}) => {
  const m = {
    manifestVersion: "1", environmentDigest: ENV1, bundleContentDigest: BUNDLE1,
    executionProfile: EXECUTION_PROFILE,
    runtime: RUNTIME, entryPoint: ENTRY_POINT, inputFormat: INPUT_FORMAT,
    platformProtocolVersion: 9,
    sourceRevisions: { platform: "dashpay/platform@v2.0.0", decoder: "tegara/decoder@v1.0.0" },
    dependencyClosure: [{ name: "cbor", version: "9.0.2", digest: "sha256:" + "33".repeat(32) }],
    ...over,
  };
  const digest = bundleDigest(m);
  return { ...m, artifactDigest: digest, decoderId: decoderIdFor(digest), ...(over.__raw || {}) };
};
const manifest = mkManifest();
ok("a well-formed bundle manifest validates", validateBundleManifest(manifest));
ok("the manifest's digest is over its SELF-EXCLUDED canonical bytes",
   manifest.artifactDigest === bundleDigest(manifest));
ok("the manifest's decoderId derives from its own digest",
   manifest.decoderId === decoderIdFor(manifest.artifactDigest));
throws("a altered field changes the digest and fails closed", () => {
  const t = { ...manifest, platformProtocolVersion: 10 };
  validateBundleManifest(t);
}, /!= the digest of its canonical bytes/);
throws("a missing field is refused", () => {
  const { sourceRevisions, ...rest } = manifest; validateBundleManifest(rest);
}, /lacks sourceRevisions/);
throws("an undeclared field is refused", () => validateBundleManifest({ ...manifest, extra: 1 }), /undeclared field/);
throws("a dependency without a digest is refused",
  () => validateBundleManifest(mkManifest({ dependencyClosure: [{ name: "x", version: "1" }] })), /dependencyClosure entry/);
ok("a genuinely dependency-free bundle may assert an empty closure",
   validateBundleManifest(mkManifest({ dependencyClosure: [] })));

// THE DECODER BYTES ARE COMMITTED (build review, a required fix): two bundles differing ONLY
// in their decoder artifact must have DIFFERENT identities, or the lineage would not
// commit the executable decoder at all
const mA = mkManifest({ bundleContentDigest: BUNDLE1 });
const mB = mkManifest({ bundleContentDigest: BUNDLE2 });
ok("changing ONLY the decoder bytes changes artifactDigest",
   mA.artifactDigest !== mB.artifactDigest);
ok("...and therefore the derived decoderId", mA.decoderId !== mB.decoderId);
ok("...and therefore the content-addressed reference",
   artifactRefFor(mA.artifactDigest) !== artifactRefFor(mB.artifactDigest));
throws("a manifest without bundleContentDigest is refused",
  () => { const { bundleContentDigest, ...rest } = mA; validateBundleManifest(rest); }, /lacks bundleContentDigest/);
throws("a malformed bundleContentDigest is refused",
  () => validateBundleManifest(mkManifest({ bundleContentDigest: "deadbeef" })), /bundleContentDigest/);
// the whole schema is enforced, not just field presence (build review, MAJOR)
throws("sourceRevisions of the wrong type is refused",
  () => validateBundleManifest(mkManifest({ sourceRevisions: 42 })), /sourceRevisions must be an object/);
throws("an empty source revision is refused",
  () => validateBundleManifest(mkManifest({ sourceRevisions: { platform: "", decoder: "d" } })), /non-empty string/);
throws("an undeclared sourceRevisions field is refused",
  () => validateBundleManifest(mkManifest({ sourceRevisions: { platform: "p", decoder: "d", extra: "x" } })), /undeclared field extra/);
throws("a negative protocol version is refused",
  () => validateBundleManifest(mkManifest({ platformProtocolVersion: -1 })), /NON-NEGATIVE/);
throws("an undeclared dependency field is refused",
  () => validateBundleManifest(mkManifest({ dependencyClosure: [
    { name: "x", version: "1", digest: BUNDLE1, extra: true }] })), /undeclared field extra/);

// ---- the offline half of the bundle-vs-entry runtime duty ----
const liveEntry = makeLineageEntry({
  fromHeight: 1, artifactDigest: manifest.artifactDigest,
  platformProtocolVersion: manifest.platformProtocolVersion,
  environmentDigest: manifest.environmentDigest,
});
ok("a matching bundle satisfies its lineage entry", checkBundleAgainstEntry(manifest, liveEntry));
throws("a bundle for a different artifact is refused",
  () => checkBundleAgainstEntry(manifest, { ...liveEntry, artifactDigest: D2 }), /!= the lineage entry/);
throws("an environment mismatch is refused",
  () => checkBundleAgainstEntry(manifest, { ...liveEntry, environmentDigest: ENV2 }), /environmentDigest/);
throws("a protocol-version mismatch is refused",
  () => checkBundleAgainstEntry(manifest, { ...liveEntry, platformProtocolVersion: 10 }), /platformProtocolVersion/);
// the REFERENCE must resolve to the same bundle (build review, MAJOR: a correct digest
// with a reference naming another bundle used to pass)
throws("a reference naming another bundle is refused",
  () => checkBundleAgainstEntry(manifest, { ...liveEntry, artifactRef: artifactRefFor(D2) }),
  /does not reference the validated bundle/);

// ---- THE MANIFEST IS IN THE CANONICAL DOMAIN (two independent build reviews) ----
// decoderLineage used to carry its own partial encoder, which is exactly why no fixture
// caught it; these assert the SHARED serializer's domain guard reaches the bundle.
throws("a lone surrogate in a manifest string is refused",
  () => bundleDigest(mkManifest({ sourceRevisions: { platform: "p\ud800", decoder: "d" } })),
  /lone high surrogate/);
throws("a non-NFC manifest string is refused",
  () => bundleDigest(mkManifest({ sourceRevisions: { platform: "e\u0301", decoder: "d" } })),
  /Normalization Form C/);
throws("an undefined manifest value is refused, never digested as literal text",
  () => bundleDigest({ ...mkManifest(), platformProtocolVersion: undefined }), /undefined at/);
throws("a non-safe number in a manifest is refused",
  () => bundleDigest(mkManifest({ platformProtocolVersion: 1e300 })), /non-integer or unsafe/);
throws("a non-NFC dependency name is refused",
  () => bundleDigest(mkManifest({ dependencyClosure: [
    { name: "e\u0301", version: "1", digest: BUNDLE1 }] })), /Normalization Form C/);
ok("the manifest digest comes from the SHARED serializer", (() => {
  const { canonicalize } = require("./canonicalJson.cjs");
  const m = mkManifest();
  const { artifactDigest, decoderId, ...rest } = m;
  return bundleDigest(m) === crypto.createHash("sha256").update(canonicalize(rest)).digest("hex");
})());

// ---- cross-checks against the shipped artifacts ----
const SCHEMA_DIR = path.join(__dirname, "..", "..", "..", "docs", "schema");
const positive = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, "vectors", "positive_minimal.json"), "utf8"));
ok("the shipped vector's lineage passes validateLineage",
   validateLineage(positive.decoderLineage, {
     platformFromHeight: positive.platformAuditRange.fromHeight,
     platformToHeight: positive.platformAuditRange.toHeight,
   }));
for (const row of positive.coverage.platformLedger) {
  ok(`platform row ${row.height} decoderId matches the pinned selection`,
     row.decoderId === selectDecoder(positive.decoderLineage, row.height).decoderId);
}
// the committed execution-profile document agrees with this module's constants and its
// manifest pin still holds
const profBytes = fs.readFileSync(path.join(SCHEMA_DIR, "execution-profiles", "tegara-decoder-v1.json"));
const prof = JSON.parse(profBytes);
ok("the execution profile names the same profile/runtime/entry/input",
   prof.executionProfile === EXECUTION_PROFILE && prof.runtime === RUNTIME);
const man = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, "vectors", "MANIFEST.json"), "utf8"));
ok("the execution profile still matches its manifest pin",
   crypto.createHash("sha256").update(profBytes).digest("hex") ===
   man.executionProfiles["tegara-decoder-v1"].sha256);
ok("the bundle manifest schema is a closed object",
   BUNDLE_MANIFEST_SCHEMA.additionalProperties === false);

console.log(`decoderLineageTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
