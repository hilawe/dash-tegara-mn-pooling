/**
 * Shared .env.local persistence with atomic replacement (review finding F13, 2026-07-11),
 * plus the OPERATION-LOG layout the holistic round converged on: every OWNED durable
 * value (the compound/payout journals, preferences, watch watermarks, formation
 * manifests, RAIL_STATE, MATCH_STATE) lives in its own atomically-replaced file under a
 * sibling state DIRECTORY, so journal writes never rewrite the file that carries the
 * wallet mnemonic, and each family's crash story is a single small file instead of a
 * slice of a shared one. loadEnv() overlays the state files onto the parsed env file, so
 * every existing reader keeps working unchanged; owned keys still present in the env
 * file (pre-migration) are migrated out on the first locked write, and a STATE_MIGRATED
 * marker makes a FORGOTTEN state-dir container mount a loud failure instead of a silent
 * loss of every journal. The same mkdir lock covers both stores.
 *
 * R4 hardening (refactors review, 2026-07-12): the state dir must pre-exist before any
 * owned write (writers never create it implicitly, so a forgotten container mount can
 * never spawn an ephemeral copy), a STATE_MIGRATING intent marker lands in the env file
 * before the first migration write, and a random store id pairs the env file to its
 * state dir (STATE_STORE_ID in the file, store.id in the dir, checked on every read and
 * write). The matrix is pinned by envStoreTest.cjs.
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// TEGARA_ENV_PATH override: the offline harnesses point this at a temp file so their
// journal mutations never touch the real .env.local (the state dir derives from it, so
// the harnesses stay hermetic automatically)
const ENV_PATH = process.env.TEGARA_ENV_PATH || path.join(__dirname, "../../.env.local");
const STATE_DIR = `${ENV_PATH}.state`;

// ---- the owned-state file store (one value per file, atomic replace) ----
const stateFileOf = (key) => path.join(STATE_DIR, `${key}.val`);

// The store-id sentinel (review finding R4): a random id lives BOTH as STATE_STORE_ID in
// the env file and as a store.id file inside the state dir, and the two must match.
// Directory existence alone cannot distinguish the intended mount from an accidental
// empty or container-local one, so every guard and every writer checks the pairing.
const SENTINEL_PATH = () => path.join(STATE_DIR, "store.id");
const readSentinel = () => {
  try { return fs.readFileSync(SENTINEL_PATH(), "utf8").trim(); } catch { return null; }
};
const ensureStateDir = (expectedId) => {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  const have = readSentinel();
  if (have === null) { fs.writeFileSync(SENTINEL_PATH(), expectedId); return; }
  if (have !== expectedId) {
    throw new Error(`state dir ${STATE_DIR} carries store id ${have} but this env file expects ` +
      `${expectedId}; this is NOT the state directory that belongs to ${ENV_PATH} ` +
      "(wrong mount or a foreign copy), refusing to write into it");
  }
};
const readOwnedFiles = () => {
  const out = {};
  if (!fs.existsSync(STATE_DIR)) return out;
  for (const f of fs.readdirSync(STATE_DIR)) {
    if (!f.endsWith(".val")) continue;
    out[f.slice(0, -4)] = fs.readFileSync(path.join(STATE_DIR, f), "utf8");
  }
  return out;
};
const writeOwnedFile = (key, value) => {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  const file = stateFileOf(key);
  if (value === undefined) {
    if (fs.existsSync(file)) { fs.copyFileSync(file, `${file}.prev`); fs.rmSync(file); }
    return;
  }
  const tmp = `${file}.tmp`;
  const fd = fs.openSync(tmp, "w");
  try { fs.writeSync(fd, value); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  if (fs.existsSync(file)) fs.copyFileSync(file, `${file}.prev`);
  fs.renameSync(tmp, file);
};

const loadEnv = () => {
  const env = {};
  if (fs.existsSync(ENV_PATH)) for (const l of fs.readFileSync(ENV_PATH, "utf8").split("\n")) {
    const m = l.match(/^([A-Z0-9_]+)=(.*)$/); if (m) env[m[1]] = m[2];
  }
  // the mount guard: once owned state has migrated to the state dir (or a migration has
  // STARTED, the R4 intent marker), a run that cannot see that dir must fail loudly,
  // never read a world where every journal silently vanished. When the env file carries
  // a store id, the dir's sentinel must match it, so an accidental empty or
  // container-local directory is refused just as loudly as a missing one.
  if (env.STATE_MIGRATED === "1" || env.STATE_MIGRATING === "1") {
    if (!fs.existsSync(STATE_DIR)) {
      throw new Error(`owned state ${env.STATE_MIGRATED === "1" ? "migrated" : "is migrating"} to ` +
        `${STATE_DIR} but that directory is not visible; mount it into the container ` +
        "(see tegara/platform/README.md) instead of running without it");
    }
    if (env.STATE_STORE_ID) {
      const have = readSentinel();
      if (have !== env.STATE_STORE_ID) {
        throw new Error(`state dir ${STATE_DIR} carries store id ${have === null ? "(none)" : have} ` +
          `but the env file expects ${env.STATE_STORE_ID}; this is not the directory that belongs ` +
          `to ${ENV_PATH} (wrong mount or a foreign copy)`);
      }
    } else if (!readSentinel() && !hasOwnedEvidence() && process.env.TEGARA_STATE_ADOPT !== "1") {
      // the read-side half of the F-C2 gate: a LEGACY migrated env (no store id yet)
      // over a dir with no sentinel and no state files would read every journal as
      // silently absent; refuse instead of presenting an empty world
      throw new Error(`this env file says its owned state migrated, but ${STATE_DIR} carries no ` +
        "store.id sentinel and no state files; it is probably NOT the real state directory " +
        "(a forgotten mount appears as exactly this empty auto-created dir). Mount the real " +
        "directory, or if this empty one is genuinely correct, adopt it explicitly (node src/scripts/stateAdopt.cjs, or a one-shot TEGARA_STATE_ADOPT=1 run)");
    }
  }
  // state files OVERLAY the env file (they are the authoritative copy after migration)
  for (const [k, v] of Object.entries(readOwnedFiles())) env[k] = v;
  return env;
};

// LOCK PLACEMENT (round-3 blocker, resolved round-5): the documented container recipe
// bind-mounts exactly TWO paths, the .env.local FILE and the .env.local.state DIRECTORY.
// A lock created merely BESIDE the env file (a sibling) lands in each container's private
// overlay, so two containers would each hold their "own" lock and interleave freely on
// the SHARED env file and state dir. STATE_DIR is the only path mounted as a shared
// DIRECTORY, so BOTH lock families live there UNCONDITIONALLY and fail closed when it is
// absent (round-5 re-check: any conditional/memoized "home" lets one process resolve the
// sibling while another resolves the state dir). This is not a regression:
// `requireStateDirLocked` already refuses every owned write without STATE_DIR and the
// design never creates it implicitly at runtime, so STATE_DIR is present for the whole of
// any real run, or the run refuses state operations regardless.
const envLockPath = () => path.join(STATE_DIR, "env.lock");
const requireLockHome = () => {
  if (!fs.existsSync(STATE_DIR)) {
    throw new Error(`the shared state directory ${STATE_DIR} does not exist, so a cross-process ` +
      "lock cannot be placed; create it on the host (mkdir -p) and mount it into every run " +
      "(see tegara/platform/README.md)");
  }
};

// The env-file lock. compoundJournal.cjs holds it across every journal mutation, and
// FOREIGN saveEnv calls hold it across their reload-and-write so a journal mutation can
// never commit in between and be clobbered (independent-review TOCTOU finding,
// 2026-07-12). Contention is a loud refusal, never a wait, so a clobber is impossible
// and a collision is visible.
// OWNERSHIP-SAFE, NO AUTO-STEAL (round-5 re-check blocker): the earlier 30 s stale
// takeover broke mutual exclusion under a container pause or host suspension (process A
// pauses mid-hold past the timeout, B steals and enters, A resumes and both write, and a
// path-only unlock could then remove B's lock). The env lock now uses the SAME owner-token
// discipline as the operation lock: a held lock is never stolen automatically, release
// removes the lock only when the token is this process's own, and a stale lock is cleared
// by the operator by hand. The hold is a synchronous, no-await region (microseconds), so a
// crash mid-hold is extraordinarily unlikely, and recovery is one `rmdir`.
let heldEnvLock = null; // { token, path }
const lockEnv = () => {
  requireLockHome();
  const p = envLockPath();
  try {
    fs.mkdirSync(p);
  } catch (e) {
    if (e.code !== "EEXIST") throw e;
    let ageSec = "unknown";
    try { ageSec = Math.round((Date.now() - fs.statSync(p).mtimeMs) / 1000); } catch { /* raced */ }
    throw new Error(`another run holds the env lock (${p}, ~${ageSec}s old). If it is alive, retry ` +
      "shortly. If it crashed, verify no other run is alive, then remove the lock directory by hand; " +
      "it is never stolen automatically.");
  }
  const token = `${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
  fs.writeFileSync(path.join(p, "owner"), token);
  heldEnvLock = { token, path: p };
};
const unlockEnv = () => {
  const held = heldEnvLock;
  heldEnvLock = null;
  if (!held) return;
  try {
    const owner = fs.readFileSync(path.join(held.path, "owner"), "utf8");
    if (owner !== held.token) return; // a successor now owns it; never remove theirs
    fs.unlinkSync(path.join(held.path, "owner"));
    fs.rmdirSync(held.path);
  } catch { /* already gone, or not ours */ }
};

// A long-held per-OPERATION lock, distinct from the short env-file lock above: one
// completion-protocol command (complete / receipt / abandon) per pool at a time, held
// across the WHOLE command including its network awaits (round-2 review blocker: two
// concurrent completes could each freeze a different node hash, and the loser's frozen
// draft could then drive an immutable receipt that contradicts the live pool).
// OWNERSHIP-SAFE and FAIL-CLOSED (round-3 review): the lock directory carries an owner
// token, release removes the lock only when the token is this process's own, and a
// stale-looking lock is NEVER stolen automatically (two waiters both judging a lock
// stale could steal it twice; a slow-but-live completion could be stolen from and then
// its release would unlock the thief's successor). A crashed run's lock is cleaned up
// by the operator, explicitly, with the age shown.
// the operation lock ALWAYS lives in the shared STATE_DIR, unconditionally (round-5
// re-check blocker): STATE_DIR is the ONLY path the documented container recipe mounts
// as a shared DIRECTORY (the env file is mounted alone, so its parent is container-
// private), so a home that ever falls back to the env-file sibling would let two
// containers hold "the same" lock in two private overlays. A completion needs STATE_DIR
// anyway (it reads and writes owned FORMATION_/RECEIPT_DRAFT_ keys there), so if the dir
// is absent the lock FAILS CLOSED rather than serializing nothing.
const opLockPath = (name) => path.join(STATE_DIR, `oplock-${name}`);
// name -> { token, path }: the acquired PATH is stored, so release removes exactly the
// directory that was acquired, never stranding the real lock
const opLockHeld = new Map();
const acquireOpLock = (name) => {
  if (!fs.existsSync(STATE_DIR)) {
    throw new Error(`the shared state directory ${STATE_DIR} does not exist, so a completion-protocol ` +
      "lock cannot be shared across processes; refusing (mount .env.local.state, per the run recipe)");
  }
  const p = opLockPath(name);
  try {
    fs.mkdirSync(p);
  } catch (e) {
    if (e.code !== "EEXIST") throw e;
    let ageMin = "unknown";
    try { ageMin = Math.round((Date.now() - fs.statSync(p).mtimeMs) / 60000); } catch { /* raced */ }
    // a TYPED contention error (round-7 re-check): callers that convert "held" into a
    // benign mid-flight skip (done prune) must NOT swallow a real fs error (permissions,
    // a vanished dir) the same way, so mark this one so only it is treated as contention.
    const held = new Error(`another completion-protocol run holds the operation lock for this pool (${p}, ` +
      `~${ageMin} min old). If that run is still alive, wait for it. If it crashed, verify no ` +
      "formation process is running, then remove the lock directory by hand; it is never stolen " +
      "automatically.");
    held.code = "OPLOCK_CONTENDED";
    throw held;
  }
  const token = `${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
  fs.writeFileSync(path.join(p, "owner"), token);
  opLockHeld.set(name, { token, path: p });
};
const releaseOpLock = (name) => {
  const held = opLockHeld.get(name);
  opLockHeld.delete(name);
  if (!held) return;
  try {
    const owner = fs.readFileSync(path.join(held.path, "owner"), "utf8");
    if (owner !== held.token) return; // not ours to release
    fs.unlinkSync(path.join(held.path, "owner"));
    fs.rmdirSync(held.path);
  } catch { /* already gone, or not ours */ }
};

const writeEnvFile = (out) => {
  const body = Object.entries(out).map(([k, v]) => `${k}=${v}`).join("\n") + "\n";
  const tmp = `${ENV_PATH}.tmp`;
  const fd = fs.openSync(tmp, "w");
  try {
    fs.writeSync(fd, body);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  if (fs.existsSync(ENV_PATH)) fs.copyFileSync(ENV_PATH, `${ENV_PATH}.prev`);
  try {
    fs.renameSync(tmp, ENV_PATH);
  } catch (e) {
    // a single-file docker bind mount pins the inode, so nothing can rename over it
    // (EBUSY). Fall back to an in-place copy: not atomic, but by this point the NEW
    // state is fsynced in .tmp and the OLD state copied to .prev, so a write torn by
    // an interruption is recoverable from either neighbor. The .tmp is kept.
    if (!["EBUSY", "EPERM", "EXDEV"].includes(e.code)) throw e;
    fs.copyFileSync(tmp, ENV_PATH);
  }
};

// Key families owned by dedicated writers (the compound journal, the autopay
// preference, the watch watermark, the formation manifest, and the OLDER durable
// journals RAIL_STATE/MATCH_STATE, holistic-round F2), which every FOREIGN saveEnv
// preserves from disk instead of its own possibly-stale copy. Owners write through
// updateEnvKey (or pass journalOwner while already holding the lock).
const OWNED_PREFIXES = ["COMPOUND_", "AUTOPAY_", "WATCH_", "FORMATION_", "RECEIPT_DRAFT_"];
// CONTRACT_V8_PENDING and CONTRACT_V8_ID are OWNED (round-7 re-check P1, tightened in the
// second re-check): the register publish-intent marker AND the resulting contract id must
// both survive a concurrent foreign saveEnv from a process that loaded state before they
// were written; a plain key could be clobbered back out, re-opening the silent-republish
// window. Reads still resolve either way, because loadEnv overlays owned files ON TOP of
// the env file (a value seeded plainly is surfaced until an owner write migrates it).
const OWNED_KEYS = ["RAIL_STATE", "MATCH_STATE", "CONTRACT_V8_PENDING", "CONTRACT_V8_ID"];
const isOwnedKey = (k) => OWNED_KEYS.includes(k) || OWNED_PREFIXES.some((p) => k.startsWith(p));

// The shared writer-side gate (review finding R4): any write that puts owned state into
// the state dir first requires the dir to ALREADY exist (the run recipe creates it on
// the host and mounts it; a missing dir inside a container means the mount was
// forgotten, and creating it here would write into the container's ephemeral overlay),
// then pairs it to this env file through the store-id sentinel. Returns the store id.
const hasOwnedEvidence = () => {
  try { return fs.readdirSync(STATE_DIR).some((f) => f.endsWith(".val")); } catch { return false; }
};
const requireStateDirLocked = (envStoreId, legacyMigrated) => {
  if (!fs.existsSync(STATE_DIR)) {
    throw new Error(`owned state belongs in ${STATE_DIR} but that directory does not exist; ` +
      "create it once on the host (mkdir -p) and mount it into every container run " +
      "(see tegara/platform/README.md), never let a run create it implicitly");
  }
  // the ambiguous-legacy gate (review F-C2): an env file that says its state MIGRATED
  // but carries no store id must not adopt a directory with no sentinel AND no owned
  // state files. A migration only ever runs when owned keys exist, so the true legacy
  // directory always holds .val files; an empty one is the docker auto-created shape of
  // a forgotten mount, and adopting it would pair the env file to the wrong place
  // permanently. TEGARA_STATE_ADOPT=1 is the explicit operator override for a store
  // that is genuinely this empty directory.
  if (legacyMigrated && !readSentinel() && !hasOwnedEvidence() &&
      process.env.TEGARA_STATE_ADOPT !== "1") {
    throw new Error(`this env file says its owned state migrated, but ${STATE_DIR} carries no ` +
      "store.id sentinel and no state files; it is probably NOT the real state directory " +
      "(a forgotten mount appears as exactly this empty auto-created dir). Mount the real " +
      "directory, or if this empty one is genuinely correct, adopt it explicitly (node src/scripts/stateAdopt.cjs, or a one-shot TEGARA_STATE_ADOPT=1 run)");
  }
  const storeId = envStoreId || readSentinel() || crypto.randomBytes(8).toString("hex");
  ensureStateDir(storeId);
  return storeId;
};

// One-shot migration, run inside any locked write: owned keys still living in the env
// FILE move into their own state files and leave the env file for good. R4 ordering:
// the STATE_MIGRATING intent marker and the store id land in the env file BEFORE the
// first state-file write (with the owned values still inside, so nothing is lost), and
// only the final write removes the values and flips the marker to STATE_MIGRATED. An
// interruption anywhere in between leaves a marker that gates every later run.
const migrateOwnedLocked = () => {
  const fileEnv = {};
  if (fs.existsSync(ENV_PATH)) for (const l of fs.readFileSync(ENV_PATH, "utf8").split("\n")) {
    const m = l.match(/^([A-Z0-9_]+)=(.*)$/); if (m) fileEnv[m[1]] = m[2];
  }
  const owned = Object.keys(fileEnv).filter(isOwnedKey);
  const legacy = fileEnv.STATE_MIGRATED === "1" && !fileEnv.STATE_STORE_ID;
  if (owned.length === 0) {
    // backfill for a store migrated before the sentinel existed: pair it now, but only
    // to a directory carrying evidence it is the real one (F-C2, gate inside)
    if (legacy) {
      fileEnv.STATE_STORE_ID = requireStateDirLocked(null, true);
      writeEnvFile(fileEnv);
    }
    return fileEnv;
  }
  const storeId = requireStateDirLocked(fileEnv.STATE_STORE_ID, legacy);
  fileEnv.STATE_STORE_ID = storeId;
  fileEnv.STATE_MIGRATING = "1";
  writeEnvFile(fileEnv); // intent marker armed, owned values still safe in the env file
  for (const k of owned) { writeOwnedFile(k, fileEnv[k]); delete fileEnv[k]; }
  delete fileEnv.STATE_MIGRATING;
  fileEnv.STATE_MIGRATED = "1";
  writeEnvFile(fileEnv);
  return fileEnv;
};

// The EXPLICIT adoption operation (review follow-on, two-model convergence): pair THIS
// env file with the currently visible state dir, deliberately, under the lock. The
// ordinary paths refuse an ambiguous legacy directory (no sentinel, no .val evidence)
// and that refusal names this operation; running it is the operator stating "this
// directory is correct". It never overrides a CONFLICTING pairing (env and dir carrying
// different ids), because that shape means two real stores exist and a human must look.
// Returns a non-secret report for the caller to print.
const adoptStateDir = () => {
  lockEnv();
  try {
    const fileEnv = {};
    if (fs.existsSync(ENV_PATH)) for (const l of fs.readFileSync(ENV_PATH, "utf8").split("\n")) {
      const m = l.match(/^([A-Z0-9_]+)=(.*)$/); if (m) fileEnv[m[1]] = m[2];
    }
    if (!fs.existsSync(STATE_DIR)) {
      throw new Error(`nothing to adopt: ${STATE_DIR} does not exist (create it on the host and ` +
        "mount it, see tegara/platform/README.md)");
    }
    const have = readSentinel();
    const vals = fs.readdirSync(STATE_DIR).filter((f) => f.endsWith(".val"));
    if (fileEnv.STATE_STORE_ID && have === fileEnv.STATE_STORE_ID) {
      return { already: true, storeId: have, valCount: vals.length, valKeys: vals.map((f) => f.slice(0, -4)) };
    }
    if (fileEnv.STATE_STORE_ID && have && have !== fileEnv.STATE_STORE_ID) {
      throw new Error(`refusing to adopt: the env file expects store id ${fileEnv.STATE_STORE_ID} but ` +
        `${STATE_DIR} carries ${have}; two different stores exist and adoption never overrides a ` +
        "conflicting pairing, resolve by hand");
    }
    const storeId = fileEnv.STATE_STORE_ID || have || crypto.randomBytes(8).toString("hex");
    if (have === null) fs.writeFileSync(SENTINEL_PATH(), storeId);
    if (fileEnv.STATE_STORE_ID !== storeId) { fileEnv.STATE_STORE_ID = storeId; writeEnvFile(fileEnv); }
    return { already: false, storeId, valCount: vals.length, valKeys: vals.map((f) => f.slice(0, -4)) };
  } finally { unlockEnv(); }
};

const splitOwned = (env) => {
  const plain = {}; const owned = {};
  for (const [k, v] of Object.entries(env)) (isOwnedKey(k) ? owned : plain)[k] = v;
  return { plain, owned };
};

const saveEnv = (env, opts = {}) => {
  // journalOwner callers already hold the lock and loaded fresh state inside it; their
  // env is the AUTHORITATIVE state OF THEIR OWN FAMILY, so the sync (values written,
  // absent keys deleted) is SCOPED to the COMPOUND_ journal family the one journalOwner
  // caller (compoundJournal.mutate) actually owns. Round-3 review blocker: the earlier
  // full-sync treated every owned prefix as this caller's deletion domain, so a journal
  // write racing a completion from another container (where the env lock was not shared)
  // deleted the freshly frozen RECEIPT_DRAFT_ and could do the same to a FORMATION_
  // manifest. Other families are written only by their owners through updateEnvKey and
  // pass through here untouched.
  if (opts.journalOwner) {
    const { plain, owned } = splitOwned(env);
    const existing = readOwnedFiles();
    if (Object.keys(owned).length > 0 || Object.keys(existing).length > 0) {
      plain.STATE_STORE_ID = requireStateDirLocked(plain.STATE_STORE_ID,
        plain.STATE_MIGRATED === "1" && !plain.STATE_STORE_ID);
      plain.STATE_MIGRATED = "1";
    }
    const inFamily = (k) => k.startsWith("COMPOUND_");
    for (const [k, v] of Object.entries(owned)) if (inFamily(k)) writeOwnedFile(k, v);
    for (const k of Object.keys(existing)) {
      if (inFamily(k) && !(k in owned)) writeOwnedFile(k, undefined);
    }
    // non-family owned keys that were only ever in the env file (pre-migration) still
    // migrate to their own files rather than being dropped from the plain write below
    for (const [k, v] of Object.entries(owned)) {
      if (!inFamily(k) && !(k in existing)) writeOwnedFile(k, v);
    }
    writeEnvFile(plain);
    return;
  }
  // a FOREIGN save never touches owned state at all now (it lives in files the save does
  // not write), so a stale env copy can neither clobber nor resurrect a journal; only
  // the caller's plain keys land, after the one-shot migration clears any pre-migration
  // owned keys out of the env file.
  lockEnv();
  try {
    migrateOwnedLocked();
    const { plain } = splitOwned(env);
    const disk = {};
    if (fs.existsSync(ENV_PATH)) for (const l of fs.readFileSync(ENV_PATH, "utf8").split("\n")) {
      const m = l.match(/^([A-Z0-9_]+)=(.*)$/); if (m) disk[m[1]] = m[2];
    }
    if (disk.STATE_MIGRATED === "1") plain.STATE_MIGRATED = "1";
    // the store id pairs the env file to its state dir; the DISK value is freshest
    // (migrateOwnedLocked may have just backfilled it inside this same lock)
    if (disk.STATE_STORE_ID) plain.STATE_STORE_ID = disk.STATE_STORE_ID;
    writeEnvFile(plain);
  } finally { unlockEnv(); }
};

// The owner-side write for a single key: locked, against the freshest disk state (pass
// undefined to delete). Owned keys land in their own state file; plain keys in the env
// file. This is how AUTOPAY_* toggles, watch watermarks, and formation manifests land,
// so a stale env copy can neither revert nor erase them (independent-review finding).
const updateEnvKey = (key, value) => {
  lockEnv();
  try {
    const fileEnv = migrateOwnedLocked();
    if (isOwnedKey(key)) {
      const storeId = requireStateDirLocked(fileEnv.STATE_STORE_ID,
        fileEnv.STATE_MIGRATED === "1" && !fileEnv.STATE_STORE_ID);
      writeOwnedFile(key, value);
      if (fileEnv.STATE_MIGRATED !== "1" || fileEnv.STATE_STORE_ID !== storeId) {
        fileEnv.STATE_MIGRATED = "1"; fileEnv.STATE_STORE_ID = storeId; writeEnvFile(fileEnv);
      }
    } else {
      if (value === undefined) delete fileEnv[key]; else fileEnv[key] = value;
      writeEnvFile(fileEnv);
    }
  } finally { unlockEnv(); }
};

// Atomically reserve N consecutive FORMATION_ADDR_INDEX values and return the base (F-H):
// the counter is a GLOBAL owned key, and the per-pool operation lock does NOT serialize two
// completions of DIFFERENT pools, so a split lock-free read + later write let both read the
// same base and derive colliding wallet-fallback reward addresses (the F8 collision the
// counter exists to prevent). This read-advance-return runs entirely under the env lock, so
// concurrent reservers get disjoint ranges. The key is owned (FORMATION_ prefix), so the
// freshest value is its .val file.
const reserveAddrIndex = (n) => {
  const key = "FORMATION_ADDR_INDEX";
  lockEnv();
  try {
    const fileEnv = migrateOwnedLocked();
    let base = parseInt(readOwnedFiles()[key] || "0", 10);
    if (!Number.isSafeInteger(base) || base < 0) base = 0;
    const storeId = requireStateDirLocked(fileEnv.STATE_STORE_ID,
      fileEnv.STATE_MIGRATED === "1" && !fileEnv.STATE_STORE_ID);
    writeOwnedFile(key, String(base + n));
    if (fileEnv.STATE_MIGRATED !== "1" || fileEnv.STATE_STORE_ID !== storeId) {
      fileEnv.STATE_MIGRATED = "1"; fileEnv.STATE_STORE_ID = storeId; writeEnvFile(fileEnv);
    }
    return base;
  } finally { unlockEnv(); }
};

/**
 * Which pool-ledger contract this run targets: LEDGER=v3 selects the v3 contract
 * (reconstructible accruals + on-ledger settlements, registerV3.cjs); LEDGER=v4 the v4
 * contract (v3 plus the accrual `kind` inside the unique key and the unique byJoin
 * settlement index, registerV4.cjs); default is the original v1 ledger. Every script
 * maps the "poolLedger" app name to this id, so the document type names stay identical
 * across versions.
 */
const activeContractId = (env) => {
  // an unsupported nonempty selector is a configuration typo, never a silent fallback
  // to the v1 namespace (independent-review finding); validated HERE so every caller
  // gets the same protection
  if (process.env.LEDGER && !["v1", "v3", "v4", "v5", "v6", "v7", "v8"].includes(process.env.LEDGER)) {
    throw new Error(`unsupported LEDGER value "${process.env.LEDGER}" (use v1, v3, v4, v5, v6, v7, or v8)`);
  }
  if (process.env.LEDGER === "v3") {
    if (!env.CONTRACT_V3_ID) throw new Error("LEDGER=v3 but CONTRACT_V3_ID is missing; run registerV3.cjs first");
    return env.CONTRACT_V3_ID;
  }
  if (process.env.LEDGER === "v4") {
    if (!env.CONTRACT_V4_ID) throw new Error("LEDGER=v4 but CONTRACT_V4_ID is missing; run registerV4.cjs first");
    return env.CONTRACT_V4_ID;
  }
  if (process.env.LEDGER === "v5") {
    if (!env.CONTRACT_V5_ID) throw new Error("LEDGER=v5 but CONTRACT_V5_ID is missing; run registerV5.cjs first");
    return env.CONTRACT_V5_ID;
  }
  if (process.env.LEDGER === "v6") {
    if (!env.CONTRACT_V6_ID) throw new Error("LEDGER=v6 but CONTRACT_V6_ID is missing; run registerV6.cjs first");
    return env.CONTRACT_V6_ID;
  }
  if (process.env.LEDGER === "v7") {
    if (!env.CONTRACT_V7_ID) throw new Error("LEDGER=v7 but CONTRACT_V7_ID is missing; run registerV7.cjs first");
    return env.CONTRACT_V7_ID;
  }
  if (process.env.LEDGER === "v8") {
    if (!env.CONTRACT_V8_ID) throw new Error("LEDGER=v8 but CONTRACT_V8_ID is missing; run registerV8.cjs first");
    return env.CONTRACT_V8_ID;
  }
  return env.CONTRACT_ID;
};
// isV3 means "the v3 feature set or later" (bps-carrying accruals, on-ledger
// settlements); each later version is a strict superset, so it answers true for all of
// them. isV4 gates what v4 added (the accrual `kind` in the unique key) and answers
// true for v5 too; isV5 gates v5's own additions (pool status, join provenance and
// reward scripts, delegateTo).
const isV3 = () => ["v3", "v4", "v5", "v6", "v7", "v8"].includes(process.env.LEDGER);
const isV4 = () => ["v4", "v5", "v6", "v7", "v8"].includes(process.env.LEDGER);
const isV5 = () => ["v5", "v6", "v7", "v8"].includes(process.env.LEDGER);
// isV6 means "the pledgeSlot reservation exists" (true for v7 and v8 too); isV7 gates
// what v7 added (slot economics on the pool, sizeless mutable claims), which v8 keeps,
// so it answers true for v8; isV8 gates v8's own addition (the completion receipt)
const isV6 = () => ["v6", "v7", "v8"].includes(process.env.LEDGER);
const isV7 = () => ["v7", "v8"].includes(process.env.LEDGER);
const isV8 = () => process.env.LEDGER === "v8";
// the cast-governance namespace: CAST=v3 selects the v3 contract (formatVersion,
// missed-vote attestations); default is the v2 snapshot-first contract
const activeCastId = (env) => {
  if (process.env.CAST && !["v2", "v3"].includes(process.env.CAST)) {
    throw new Error(`unsupported CAST value "${process.env.CAST}" (use v2 or v3)`);
  }
  if (process.env.CAST === "v3") {
    if (!env.CAST_V3_CONTRACT_ID) throw new Error("CAST=v3 but CAST_V3_CONTRACT_ID is missing; run registerCastV3.cjs first");
    return env.CAST_V3_CONTRACT_ID;
  }
  return env.CAST_V2_CONTRACT_ID;
};
const isCastV3 = () => process.env.CAST === "v3";

module.exports = { ENV_PATH, STATE_DIR, loadEnv, saveEnv, updateEnvKey, reserveAddrIndex, lockEnv, unlockEnv,
  acquireOpLock, releaseOpLock,
  adoptStateDir, activeContractId, isV3, isV4, isV5, isV6, isV7, isV8, activeCastId, isCastV3 };
