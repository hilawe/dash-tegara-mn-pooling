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

const { ENV_PATH, STATE_DIR, loadEnv, saveEnv, updateEnvKey, lockEnv, unlockEnv } = require("./envStore.cjs");

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

// 9. journalOwner sync is SCOPED to the COMPOUND_ family it owns (a review
//    blocker: the old full-sync deleted every owned prefix absent from the journal's
//    snapshot, so a journal write racing a completion could erase a fresh
//    RECEIPT_DRAFT_ or FORMATION_ manifest). Absent COMPOUND_ keys still delete with a
//    .prev generation; keys of OTHER families survive a journalOwner save that never
//    saw them. The foreign-dir writer gate is unchanged.
{
  updateEnvKey("COMPOUND_DEL", "doomed");
  updateEnvKey("RECEIPT_DRAFT_RACE", "frozen");
  const env = loadEnv();
  env.COMPOUND_NEW = "n1";
  delete env.COMPOUND_DEL;         // in-family: must delete
  delete env.WATCH_W;              // other family: must SURVIVE
  delete env.RECEIPT_DRAFT_RACE;   // other family: must SURVIVE (the draft-race case)
  saveEnv(env, { journalOwner: true });
  ok("owner write landed", loadEnv().COMPOUND_NEW === "n1");
  ok("owner sync deleted the absent IN-FAMILY key", loadEnv().COMPOUND_DEL === undefined);
  ok("in-family deletion kept a .prev generation", fs.existsSync(path.join(STATE_DIR, "COMPOUND_DEL.val.prev")));
  ok("a WATCH_ key survives a journal save that omitted it", loadEnv().WATCH_W !== undefined);
  ok("a RECEIPT_DRAFT_ survives a journal save that omitted it", loadEnv().RECEIPT_DRAFT_RACE === "frozen");
  // the register publish-intent marker AND the contract id are owned, so a stale foreign
  // saveEnv that never saw them cannot clobber them out (a review re-check-2 P1)
  updateEnvKey("CONTRACT_V8_PENDING", "1");
  updateEnvKey("CONTRACT_V8_ID", "theId");
  // the v9 pair is owned for the same reason (v9 draft review, finding 3)
  updateEnvKey("CONTRACT_V9_PENDING", "1");
  updateEnvKey("CONTRACT_V9_ID", "theV9Id");
  saveEnv({ MNEMONIC: "m", SOME: "plain" }); // a foreign save with a stale snapshot
  ok("CONTRACT_V8_PENDING survives a foreign saveEnv", loadEnv().CONTRACT_V8_PENDING === "1");
  ok("CONTRACT_V8_ID survives a foreign saveEnv", loadEnv().CONTRACT_V8_ID === "theId");
  ok("CONTRACT_V9_PENDING survives a foreign saveEnv", loadEnv().CONTRACT_V9_PENDING === "1");
  ok("CONTRACT_V9_ID survives a foreign saveEnv", loadEnv().CONTRACT_V9_ID === "theV9Id");
  // the v11 pair is owned for the same reason as v8's and v9's (E2 adoption table)
  updateEnvKey("CONTRACT_V11_PENDING", "1");
  updateEnvKey("CONTRACT_V11_ID", "theV11Id");
  // the E2 start-epoch family is owned (per-pool configured start, deliberately
  // mutable pre-journal: a soundness-review finding journal binding is the immutability authority)
  updateEnvKey("E2_START_EPOCH_" + "AB".repeat(32), "4123");
  saveEnv({ MNEMONIC: "m", SOME: "plain" }); // another stale foreign save
  ok("CONTRACT_V11_PENDING survives a foreign saveEnv", loadEnv().CONTRACT_V11_PENDING === "1");
  ok("CONTRACT_V11_ID survives a foreign saveEnv", loadEnv().CONTRACT_V11_ID === "theV11Id");
  ok("an E2_START_EPOCH_ key survives a foreign saveEnv",
    loadEnv()["E2_START_EPOCH_" + "AB".repeat(32)] === "4123");
  ok("an E2_START_EPOCH_ key stays operator-mutable (no write-once class)",
    (updateEnvKey("E2_START_EPOCH_" + "AB".repeat(32), "4200"),
      loadEnv()["E2_START_EPOCH_" + "AB".repeat(32)] === "4200"));

  // THE WRITE-ONCE CLASS (E2 specification revisions 31 and 32): set, idempotent equal rewrite,
  // differing-update refusal, deletion refusal (ABSENT KEY INCLUDED), for BOTH
  // E2 keys. The pin value is GENERATED per run (checker finding 4: a reader
  // mutation returning a fixed object survived assertions against a fixed
  // fixture, so the expectation must be a value the code under test has never
  // seen), and written in canonical member order since the reader now requires
  // the stored bytes to BE the JCS serialization.
  const genChain = `tegara_test_chain_${process.pid}_${Math.floor(Math.random() * 1e9)}`;
  const pinObj = { chainId: genChain,
    source: { path: "genesis.json (harness)", retrievedAt: "2026-08-21" } };
  const pinValue = JSON.stringify(pinObj);
  // ANY deletion refuses, the ABSENT key included (no nothing-to-delete carve-out)
  throws("E2 pin deletion refuses even while the key is absent",
    () => updateEnvKey("E2_EXPECTED_CHAIN_ID", undefined), /write-once/);
  for (const [k, v1, v2] of [
    ["E2_EXPECTED_CHAIN_ID", pinValue, JSON.stringify({ chainId: "other",
      source: { path: "x", retrievedAt: "2026-08-21" } })],
    ["E2_GATE_CAPTURE", '{"contractId":"c1"}', '{"contractId":"c2"}'],
  ]) {
    updateEnvKey(k, v1);
    ok(`${k} set when absent`, loadEnv()[k] === v1);
    updateEnvKey(k, v1); // must be a no-op, not a refusal
    ok(`${k} compare-equal rewrite is an idempotent no-op`, loadEnv()[k] === v1);
    throws(`${k} differing update refuses`, () => updateEnvKey(k, v2), /write-once/);
    throws(`${k} deletion refuses`, () => updateEnvKey(k, undefined), /write-once/);
    ok(`${k} still holds its first value after both refusals`, loadEnv()[k] === v1);
  }
  // the equal rewrite COMPLETES interrupted store bookkeeping rather than
  // early-returning past it (checker finding 1): clear the migration marker as
  // an interrupted first write would leave it, rewrite the equal value, and the
  // marker must be repaired
  {
    // simulate the interrupted FIRST write the checker named: the .val landed
    // but the process died before the marker update, leaving an env file with
    // no STATE_MIGRATED/STATE_STORE_ID beside a populated state dir. A foreign
    // save cannot produce this state (it preserves the id by design, which made
    // the first form of this case vacuous and let the early-return mutation
    // survive), so the file is written directly, as the crash genuinely leaves it.
    fs.writeFileSync(ENV_PATH, "MNEMONIC=m\nPLAIN_KEY=v3\n");
    ok("the interrupted state really lacks the marker", readEnvRaw().STATE_MIGRATED === undefined);
    updateEnvKey("E2_GATE_CAPTURE", '{"contractId":"c1"}'); // the equal rewrite
    const raw = readEnvRaw();
    ok("an equal rewrite repairs the migration marker",
      raw.STATE_MIGRATED === "1" && !!raw.STATE_STORE_ID);
  }
  // BOTH pins set survive one more stale foreign save together
  saveEnv({ MNEMONIC: "m", SOME: "plain2" });
  ok("both E2 pins survive a foreign saveEnv together",
    loadEnv().E2_EXPECTED_CHAIN_ID === pinValue && loadEnv().E2_GATE_CAPTURE === '{"contractId":"c1"}');
  // the journal-owner path migrates a plain-seeded NON-FAMILY owned key FROM
  // DISK, never from the caller's snapshot (checker finding 2's reproduction,
  // inverted into a net): seed a fresh owned-prefix key plainly, then run a
  // journal-owner save whose snapshot carries a DIFFERENT value for it
  {
    const poolKey = "E2_START_EPOCH_" + "CD".repeat(32);
    // a PRE-MIGRATION plain seed is a line in the env FILE itself (an old store's
    // shape); the foreign-save path deliberately refuses to write owned keys, so
    // the seed is planted directly, as history genuinely left such stores
    fs.appendFileSync(ENV_PATH, `${poolKey}=111\n`);
    lockEnv();
    try {
      const snapshot = { ...loadEnvRawForOwner(), [poolKey]: "999" }; // a stale/wrong copy
      saveEnv(snapshot, { journalOwner: true });
    } finally { unlockEnv(); }
    ok("journal-owner migration takes the DISK seed, not the snapshot",
      loadEnv()[poolKey] === "111");
    updateEnvKey(poolKey, undefined);
  }

  // THE PIN READER returns the valid composite, and its pure validator refuses
  // every malformed shape (testable without touching the write-once key)
  {
    const { readChainIdPin, parseChainIdPin } = require("./envStore.cjs");
    const assertDSE = require("assert");
    // the COMPLETE returned object must equal the value parsed from the raw the
    // test itself wrote, with a GENERATED chainId the reader has never seen, so
    // a validate-then-return-a-fixed-object reader (the checker's surviving
    // mutation on the first form of this case) cannot satisfy it
    const pin = readChainIdPin();
    let fullEqual = true;
    try { assertDSE.deepStrictEqual(pin, JSON.parse(pinValue)); } catch { fullEqual = false; }
    ok("readChainIdPin returns the COMPLETE parsed stored value (generated pin)", fullEqual);
    ok("the generated chainId round-trips", pin.chainId === genChain);
    const good = { chainId: `c_${Math.floor(Math.random() * 1e9)}`,
      source: { path: "p", retrievedAt: "2026-02-28" } };
    ok("parseChainIdPin returns its own input's parsed value, generated",
      parseChainIdPin(JSON.stringify(good)).chainId === good.chainId);
    for (const [why, bad] of [
      ["not JSON", "{nope"],
      ["not an object", JSON.stringify(["a"])],
      ["extra member", JSON.stringify({ ...good, extra: 1 })],
      ["missing source", JSON.stringify({ chainId: "c" })],
      ["empty chainId", JSON.stringify({ ...good, chainId: "" })],
      ["source not object", JSON.stringify({ ...good, source: "s" })],
      ["source extra member", JSON.stringify({ chainId: "c", source: { path: "p", retrievedAt: "2026-02-28", x: 1 } })],
      ["empty path", JSON.stringify({ chainId: "c", source: { path: "", retrievedAt: "2026-02-28" } })],
      ["path over 512 UTF-8 bytes", JSON.stringify({ chainId: "c", source: { path: "é".repeat(300), retrievedAt: "2026-02-28" } })],
      ["non-lexical date", JSON.stringify({ chainId: "c", source: { path: "p", retrievedAt: "2026-2-8" } })],
      ["impossible calendar date", JSON.stringify({ chainId: "c", source: { path: "p", retrievedAt: "2026-02-30" } })],
      // NON-CANONICAL encodings of a VALID value refuse (one JCS value, checker
      // finding 3): reordered members, whitespace, and an escape variant
      ["reordered members (source first)",
        '{"source":{"path":"p","retrievedAt":"2026-02-28"},"chainId":"c"}'],
      ["whitespace-padded encoding",
        '{ "chainId": "c", "source": { "path": "p", "retrievedAt": "2026-02-28" } }'],
      ["escape-variant encoding (\\u0063 for c)",
        '{"chainId":"\\u0063","source":{"path":"p","retrievedAt":"2026-02-28"}}'],
    ]) {
      throws(`parseChainIdPin refuses: ${why}`, () => parseChainIdPin(bad), /malformed|not valid JSON/);
    }
  }

  updateEnvKey("CONTRACT_V8_PENDING", undefined);
  updateEnvKey("CONTRACT_V8_ID", undefined);
  updateEnvKey("CONTRACT_V9_PENDING", undefined);
  updateEnvKey("CONTRACT_V9_ID", undefined);
  updateEnvKey("CONTRACT_V11_PENDING", undefined);
  updateEnvKey("CONTRACT_V11_ID", undefined);
  updateEnvKey("E2_START_EPOCH_" + "AB".repeat(32), undefined);
  updateEnvKey("RECEIPT_DRAFT_RACE", undefined);
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

// SHORT WRITES: writeSync may return fewer bytes than asked, and both tmp
// writers (the env file, the owned-key files) must land the COMPLETE text
// before the rename commits it (the shape the D7 journal checker found in
// the frame writer; swept here because these are the sibling writeSync
// sites). Injection caps every call at one byte; the committed values must
// round-trip intact.
{
  writeEnv({ MNEMONIC: "m", STATE_MIGRATED: "1", STATE_STORE_ID: "3333333333333333" });
  resetDir(true);
  fs.writeFileSync(path.join(STATE_DIR, "store.id"), "3333333333333333");
  const realWrite = fs.writeSync;
  let calls = 0;
  fs.writeSync = (fd, buf, off, len) => { calls++; return realWrite(fd, buf, off, Math.min(len, 1)); };
  try { updateEnvKey("PLAIN_KEY", "a-value-long-enough-to-need-many-writes"); }
  finally { fs.writeSync = realWrite; }
  ok("short writes still commit the complete env file",
    calls > 1 && readEnvRaw().PLAIN_KEY === "a-value-long-enough-to-need-many-writes"
    && readEnvRaw().STATE_STORE_ID === "3333333333333333");
}
{
  // the OWNED-KEY route drives writeOwnedFile, the second tmp writer (the
  // fold re-check's F12: the first injection case exercised only the plain
  // env-file route while the claim named both writers)
  const realWrite = fs.writeSync;
  let calls = 0;
  fs.writeSync = (fd, buf, off, len) => { calls++; return realWrite(fd, buf, off, Math.min(len, 1)); };
  try { updateEnvKey("RAIL_STATE", '{"a-value":"long-enough-to-need-many-writes"}'); }
  finally { fs.writeSync = realWrite; }
  ok("short writes still commit the complete owned-key file",
    calls > 1 && fs.readFileSync(path.join(STATE_DIR, "RAIL_STATE.val"), "utf8")
      === '{"a-value":"long-enough-to-need-many-writes"}');
}
{
  const realWrite = fs.writeSync;
  fs.writeSync = () => 0;
  let threw = false;
  try { updateEnvKey("PLAIN_KEY", "never-lands"); } catch (e) { threw = /stalled/.test(e.message); }
  finally { fs.writeSync = realWrite; }
  ok("a zero-byte write stall throws and leaves the committed value standing",
    threw && readEnvRaw().PLAIN_KEY === "a-value-long-enough-to-need-many-writes");
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
