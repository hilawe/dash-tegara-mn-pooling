/**
 * The crash-and-mount matrix harness for the operation-log state store (review finding
 * R4, 2026-07-12). Exercises every interleaving the finding named, offline, no devnet:
 * the migration intent marker, the store-id sentinel pairing the env file to its state
 * dir, the pre-existing-directory requirement on every writer path, and the loud
 * refusals for a missing, foreign, or unpaired directory.
 *
 * Run: node src/scripts/envStoreTest.cjs   (exits non-zero on the first failure)
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-est-"));
process.env.TEGARA_ENV_PATH = path.join(TMP, "env.local");

const { ENV_PATH, STATE_DIR, loadEnv, saveEnv, updateEnvKey } = require("./envStore.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const throws = (name, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

const writeEnv = (obj) => fs.writeFileSync(ENV_PATH,
  Object.entries(obj).map(([k, v]) => `${k}=${v}`).join("\n") + "\n");
const readEnvRaw = () => {
  const out = {};
  for (const l of fs.readFileSync(ENV_PATH, "utf8").split("\n")) {
    const m = l.match(/^([A-Z0-9_]+)=(.*)$/); if (m) out[m[1]] = m[2];
  }
  return out;
};
const resetDir = (exists) => {
  fs.rmSync(STATE_DIR, { recursive: true, force: true });
  if (exists) fs.mkdirSync(STATE_DIR);
};
const sentinel = () => {
  try { return fs.readFileSync(path.join(STATE_DIR, "store.id"), "utf8").trim(); } catch { return null; }
};

// 1. pre-migration owned write with NO state dir: refused, values untouched
writeEnv({ MNEMONIC: "m", COMPOUND_A: "j1" });
resetDir(false);
throws("pre-migration write refuses a missing state dir",
  () => updateEnvKey("PLAIN_KEY", "v"), /does not exist.*mount/s);
ok("the owned value never left the env file", readEnvRaw().COMPOUND_A === "j1");
ok("no marker was set by the refused write", readEnvRaw().STATE_MIGRATED === undefined);

// 2. migration completes when the dir pre-exists: marker, sentinel, and the move
resetDir(true);
updateEnvKey("PLAIN_KEY", "v");
{
  const raw = readEnvRaw();
  ok("owned key left the env file", raw.COMPOUND_A === undefined);
  ok("STATE_MIGRATED set", raw.STATE_MIGRATED === "1");
  ok("intent marker cleared after completion", raw.STATE_MIGRATING === undefined);
  ok("store id in the env file", /^[0-9a-f]{16}$/.test(raw.STATE_STORE_ID || ""));
  ok("sentinel matches the env file", sentinel() === raw.STATE_STORE_ID);
  ok("state file carries the value", fs.readFileSync(path.join(STATE_DIR, "COMPOUND_A.val"), "utf8") === "j1");
  ok("loadEnv overlays the migrated value", loadEnv().COMPOUND_A === "j1");
}

// 3. interrupted migration (marker armed, values still in env, dir paired): reads work,
//    the next locked write completes it
{
  const id = "00112233aabbccdd";
  resetDir(true);
  fs.writeFileSync(path.join(STATE_DIR, "store.id"), id);
  writeEnv({ MNEMONIC: "m", COMPOUND_A: "j2", STATE_MIGRATING: "1", STATE_STORE_ID: id });
  ok("mid-migration loadEnv still serves the env-file value", loadEnv().COMPOUND_A === "j2");
  updateEnvKey("PLAIN_KEY", "v2");
  const raw = readEnvRaw();
  ok("re-run completed the migration", raw.STATE_MIGRATED === "1" && raw.STATE_MIGRATING === undefined);
  ok("value moved on completion", raw.COMPOUND_A === undefined && loadEnv().COMPOUND_A === "j2");
}

// 4. interrupted migration with the dir NOT visible: loud refusal (the R4 window)
writeEnv({ MNEMONIC: "m", COMPOUND_A: "j3", STATE_MIGRATING: "1", STATE_STORE_ID: "00112233aabbccdd" });
resetDir(false);
throws("mid-migration run without the dir refuses", () => loadEnv(), /is migrating.*not visible/s);

// 5. migrated env with the dir missing: the original mount guard
writeEnv({ MNEMONIC: "m", STATE_MIGRATED: "1", STATE_STORE_ID: "00112233aabbccdd" });
resetDir(false);
throws("migrated run without the dir refuses", () => loadEnv(), /migrated.*not visible/s);

// 6. migrated env against a FOREIGN dir (sentinel mismatch): refused
resetDir(true);
fs.writeFileSync(path.join(STATE_DIR, "store.id"), "ffffffffffffffff");
throws("a foreign state dir is refused on read", () => loadEnv(), /store id.*expects|belongs/s);
throws("a foreign state dir is refused on write",
  () => updateEnvKey("COMPOUND_B", "x"), /store id|NOT the state directory/s);
ok("nothing was written into the foreign dir",
  !fs.existsSync(path.join(STATE_DIR, "COMPOUND_B.val")));

// 7. migrated env against an EMPTY dir with no sentinel: refused (an accidental
//    container-local mkdir must not pass for the real store)
resetDir(true);
throws("an unpaired empty dir is refused on read", () => loadEnv(), /store id.*\(none\)/s);

// 8. backfill: a store migrated before the sentinel existed gets paired on first write
writeEnv({ MNEMONIC: "m", STATE_MIGRATED: "1" });
resetDir(true);
fs.writeFileSync(path.join(STATE_DIR, "WATCH_W.val"), "w1");
ok("legacy store without a store id still reads", loadEnv().WATCH_W === "w1");
updateEnvKey("PLAIN_KEY", "v3");
{
  const raw = readEnvRaw();
  ok("backfill wrote a store id", /^[0-9a-f]{16}$/.test(raw.STATE_STORE_ID || ""));
  ok("backfill sentinel matches", sentinel() === raw.STATE_STORE_ID);
}

// 8b. a FOREIGN saveEnv whose caller env predates the backfill must preserve the
//     disk's store id (live-caught during the v7 publish: the backfill landed inside
//     the same lock and the foreign write then dropped the id from the env file)
{
  const before = readEnvRaw().STATE_STORE_ID;
  saveEnv({ MNEMONIC: "m", PLAIN_KEY: "v4" }); // caller env lacks STATE_STORE_ID
  ok("foreign save preserved the store id", readEnvRaw().STATE_STORE_ID === before);
  ok("foreign save preserved the marker", readEnvRaw().STATE_MIGRATED === "1");
}

// 9. journalOwner sync-exactly still holds under the pairing: absent keys delete, and a
//    write against a foreign dir refuses before touching any file
{
  const env = loadEnv();
  env.COMPOUND_NEW = "n1";
  delete env.WATCH_W;
  saveEnv(env, { journalOwner: true });
  ok("owner write landed", loadEnv().COMPOUND_NEW === "n1");
  ok("owner sync deleted the absent key", loadEnv().WATCH_W === undefined);
  ok("deletion kept a .prev generation", fs.existsSync(path.join(STATE_DIR, "WATCH_W.val.prev")));
  fs.writeFileSync(path.join(STATE_DIR, "store.id"), "ffffffffffffffff");
  throws("owner write against a foreign dir refuses",
    () => saveEnv(loadEnvRawForOwner(), { journalOwner: true }), /store id|NOT the state directory/s);
}
function loadEnvRawForOwner() {
  // build an owner env WITHOUT loadEnv (loadEnv itself refuses the foreign dir first,
  // which is also correct; this exercises the writer-side gate independently)
  return { ...readEnvRaw(), COMPOUND_NEW: "n2" };
}

// 10. an owned updateEnvKey with a missing dir refuses even when the env file carries
//     no owned keys (the fresh-store first write)
writeEnv({ MNEMONIC: "m" });
resetDir(false);
throws("fresh-store owned write without the dir refuses",
  () => updateEnvKey("AUTOPAY_P", "on"), /does not exist.*mount/s);

// 11. the ambiguous-legacy gate (F-C2): a legacy migrated env (marker, no store id) over
//     an EMPTY unpaired dir is the docker forgotten-mount shape; reads and writes both
//     refuse instead of adopting it, and the explicit override adopts it deliberately
writeEnv({ MNEMONIC: "m", STATE_MIGRATED: "1" });
resetDir(true);
throws("legacy env over an empty dir refuses on read", () => loadEnv(), /probably NOT the real state directory/);
throws("legacy env over an empty dir refuses to adopt on write",
  () => updateEnvKey("PLAIN_KEY", "v5"), /probably NOT the real state directory/);
ok("the refused write paired nothing", sentinel() === null && readEnvRaw().STATE_STORE_ID === undefined);
process.env.TEGARA_STATE_ADOPT = "1";
ok("the explicit override lets the read through", loadEnv().MNEMONIC === "m");
updateEnvKey("PLAIN_KEY", "v5");
{
  const raw = readEnvRaw();
  ok("explicit adoption paired the store", /^[0-9a-f]{16}$/.test(raw.STATE_STORE_ID || "") &&
    sentinel() === raw.STATE_STORE_ID);
}
delete process.env.TEGARA_STATE_ADOPT;

// 12. a FRESH store (no marker) over an empty dir is NOT gated: the first owned write
//     of a never-migrated deployment must pair and proceed without any override
writeEnv({ MNEMONIC: "m" });
resetDir(true);
updateEnvKey("AUTOPAY_P", "on");
ok("fresh-store first write pairs and lands", loadEnv().AUTOPAY_P === "on" &&
  sentinel() === readEnvRaw().STATE_STORE_ID);

// 13. the EXPLICIT adoption operation (the command behind the case-11 refusals): it
//     pairs the ambiguous legacy shape deliberately, reports already-paired stores, and
//     never overrides a conflicting pairing
const { adoptStateDir } = require("./envStore.cjs");
writeEnv({ MNEMONIC: "m", STATE_MIGRATED: "1" });
resetDir(true);
{
  const r = adoptStateDir();
  const raw = readEnvRaw();
  ok("adoption paired the ambiguous legacy store", !r.already &&
    raw.STATE_STORE_ID === r.storeId && sentinel() === r.storeId && r.valCount === 0);
  ok("adoption is idempotent", adoptStateDir().already === true);
  ok("reads work after adoption", loadEnv().MNEMONIC === "m");
}
writeEnv({ MNEMONIC: "m", STATE_MIGRATED: "1", STATE_STORE_ID: "1111111111111111" });
resetDir(true);
fs.writeFileSync(path.join(STATE_DIR, "store.id"), "2222222222222222");
throws("adoption refuses a conflicting pairing", () => adoptStateDir(), /never overrides/);
ok("the conflicting sentinel is untouched", sentinel() === "2222222222222222");

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
