/**
 * Offline conformance suite for the FOUR identity metadata patches (the v11
 * adoption table's version-pin metadata routes, the spec's later revisions):
 * getIdentityByIdentifier, getIdentityPublicKeys, getIdentityContractNonce
 * and getIdentityNonce, each mounted over its SDK path.
 *
 * WHAT THIS SUITE ESTABLISHES, per patch, in two layers:
 *
 *   TEXT LAYER: the stock default export appears verbatim as a substring (so
 *   mounting leaves default-import consumers on the stock code; a
 *   module-namespace consumer additionally sees ONE new name), the additive
 *   ...WithMetadata export exists, its bind line is in BOTH launchers'
 *   PATCHES, and for the nonce patches the reorder (Tenderdash verification
 *   before the absence-to-zero mapping) holds in text order while the stock
 *   default keeps its own order.
 *
 *   EXECUTION LAYER (the fold: text presence alone is evadable by
 *   comments and dead code): each patch is copied INTO the SDK tree so its
 *   relative imports resolve, imported for real (the namespace compared to
 *   exactly default-plus-one), and BOTH exports are driven over a mock pool
 *   through the refusals REACHABLE WITHOUT CONTROLLING THE IMPORTED PROOF
 *   FUNCTIONS (wrong response kind, non-proof result, absent metadata), each
 *   request asserted to carry prove: true. The proof-parser, verification
 *   and value-mask branches are live-probe territory.
 *
 * WIDTH, STATED: the reorder property itself and the verified-absence row
 * are text-pinned here and EXECUTION-PROVEN only live (idRoutesProbe.mjs
 * drives them against the devnet; real proofs cannot be fabricated offline).
 * The pin-mismatch refusals per read class belong to the consuming E2
 * modules and land with those consumers (the production-distribution row).
 *
 * SKIPS: a tree without the PATCH FILES (the curated public export) skips,
 * counted and printed. A tree WITH the patches but WITHOUT the installed SDK
 * sources FAILS rather than skips: on such a tree this suite would otherwise
 * pass while examining nothing (the vacuous-pass finding).
 */
const fs = require("fs");
const path = require("path");

let passed = 0, failed = 0, skipped = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

const ROOT = path.join(__dirname, "..", "..");
const SDK_IDENTITIES = path.join(ROOT, "node_modules", "dash-platform-sdk", "src", "identities");
const PATCH_LIST = [
  { name: "getIdentityByIdentifier", named: "getIdentityByIdentifierWithMetadata",
    nonce: false, rpc: "getIdentity", args: ["11".repeat(32)] },
  { name: "getIdentityPublicKeys", named: "getIdentityPublicKeysWithMetadata",
    nonce: false, rpc: "getIdentityKeys", args: ["11".repeat(32)] },
  { name: "getIdentityContractNonce", named: "getIdentityContractNonceWithMetadata",
    nonce: true, absent: "contractNonce == null", rpc: "getIdentityContractNonce",
    args: ["11".repeat(32), "22".repeat(32)] },
  { name: "getIdentityNonce", named: "getIdentityNonceWithMetadata",
    nonce: true, absent: "nonce == null", rpc: "getIdentityNonce", args: ["11".repeat(32)] },
];

(async () => {
const anyPatchExists = PATCH_LIST.some((p) =>
  fs.existsSync(path.join(ROOT, "patches", `${p.name}-retainMetadata.js`)));

for (const p of PATCH_LIST) {
  const patchPath = path.join(ROOT, "patches", `${p.name}-retainMetadata.js`);
  const installedPath = path.join(SDK_IDENTITIES, `${p.name}.js`);
  if (!fs.existsSync(patchPath) && !anyPatchExists) {
    skipped += 1;
    console.log(`SKIP: ${p.name} (no patches on this tree; the curated export takes no SDK dependency)`);
    continue;
  }
  // patches exist on this tree: everything they need must exist too, or the
  // suite FAILS (an all-skip pass examined nothing; the finding)
  ok(`${p.name}: the patch file exists on a tree that carries patches`, fs.existsSync(patchPath));
  ok(`${p.name}: the installed SDK source exists beside it (npm install, or this gate stays red)`,
    fs.existsSync(installedPath));
  if (!fs.existsSync(patchPath) || !fs.existsSync(installedPath)) continue;

  const patch = fs.readFileSync(patchPath, "utf8");
  const installed = fs.readFileSync(installedPath, "utf8");
  ok(`${p.name}: the installed source is substantial (an empty file would vacuously "appear" in anything)`,
    installed.trim().length > 500);
  ok(`${p.name}: the installed stock source appears in the patch verbatim (substring; default-import consumers ride the stock code)`,
    patch.includes(installed.trim()));
  for (const launcher of ["run_acceptance.sh", "run_registerV11.sh"]) {
    const lp = path.join(ROOT, launcher);
    // an ACTIVE array entry, not a substring: the same text inside a shell
    // comment must not pass (the relocation evasion)
    const bindRe = new RegExp(`^\\s*-v "\\$PWD/patches/${p.name}-retainMetadata\\.js:` +
      `/app/node_modules/dash-platform-sdk/src/identities/${p.name}\\.js:ro"$`, "m");
    ok(`${p.name}: an ACTIVE bind entry is in ${launcher} (uncommented -v line)`,
      fs.existsSync(lp) && bindRe.test(fs.readFileSync(lp, "utf8")));
  }
  const namedBody = patch.match(new RegExp(`export async function ${p.named}\\([\\s\\S]*?\\n\\}`));
  ok(`${p.name}: the additive ${p.named} export exists`, !!namedBody);
  ok(`${p.name}: two line-anchored export statements (the count is a tripwire, not a proof of surface)`,
    (patch.match(/^export /gm) || []).length === 2);

  if (p.nonce && namedBody) {
    const body = namedBody[0];
    const verifyAt = body.indexOf("verifyTenderdashProof(");
    const absentAt = body.indexOf(p.absent);
    ok(`${p.name}: the WithMetadata body runs the Tenderdash verification BEFORE the absence mapping (text order; execution-proven live)`,
      verifyAt !== -1 && absentAt !== -1 && verifyAt < absentAt);
    ok(`${p.name}: a verified absence still answers zero with the metadata (the accepting row)`,
      body.includes("{ nonce: BigInt(0), metadata }"));
    const defBody = patch.match(new RegExp(`export default async function ${p.name}\\([\\s\\S]*?\\n\\}`));
    ok(`${p.name}: the stock default's own order is unchanged (absence mapped first there)`,
      !!defBody && defBody[0].indexOf(p.absent) < defBody[0].indexOf("verifyTenderdashProof("));
  }

  // ---- THE EXECUTION LAYER: the patch imported for real, both exports
  // driven through the reachable refusals over a mock pool ----
  const underTest = path.join(SDK_IDENTITIES, `__patchUnderTest_${p.name}.mjs`);
  fs.copyFileSync(patchPath, underTest);
  try {
    const mod = await import(require("url").pathToFileURL(underTest).href);
    // the REAL namespace, not a line-anchored count: exactly the stock
    // default plus the one additive name (the indented-export evasion)
    ok(`${p.name}: the module namespace is exactly default plus ${p.named}`,
      Object.keys(mod).sort().join(",") === ["default", p.named].sort().join(","));
    ok(`${p.name}: the imported patch carries a callable default and a callable ${p.named}`,
      typeof mod.default === "function" && typeof mod[p.named] === "function");
    const requests = [];
    const poolWith = (response) => ({ network: "regtest",
      getClient: () => ({ [p.rpc]: async (req) => { requests.push(req); return { response }; } }) });
    for (const [label, fn] of [["default", mod.default], [p.named, mod[p.named]]]) {
      await rejects(`${p.name}.${label}: a wrong response kind refuses with the stock message`,
        fn(poolWith({ version: { oneofKind: "v1" } }), ...p.args), /must be v0/);
      await rejects(`${p.name}.${label}: a non-proof result refuses with the stock message`,
        fn(poolWith({ version: { oneofKind: "v0", v0: { result: { oneofKind: "value" } } } }), ...p.args),
        /must be proof/);
      await rejects(`${p.name}.${label}: absent metadata refuses with the stock message`,
        fn(poolWith({ version: { oneofKind: "v0", v0: { result: { oneofKind: "proof", proof: {} }, metadata: null } } }), ...p.args),
        /Metadata not found/);
    }
    // every request either export formed asked for a PROOF (a prove:false
    // mutation would keep the three refusals green while abandoning the
    // proved route; the check named it)
    ok(`${p.name}: every request from both exports carries prove: true`,
      requests.length === 6 && requests.every((r) => r && r.version && r.version.v0 && r.version.v0.prove === true));
  } finally {
    fs.rmSync(underTest, { force: true });
  }
}

console.log(`identityMetadataPatchesTest: ${passed} passed, ${failed} failed` +
  (skipped ? `, ${skipped} skipped (counted, never folded into passes)` : ""));
if (failed) process.exitCode = 1;
})().catch((e) => { console.error("UNCAUGHT:", e); process.exitCode = 1; });
