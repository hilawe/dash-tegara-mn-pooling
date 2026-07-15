/**
 * The fs-interception crash-matrix harness for the operation-log state store (forward
 * plan phase 3; recorded by two reviewers independently: stop REAL execution at every
 * mutating filesystem boundary, then reload under each mount condition, instead of
 * hand-building end states, which is how the C2 gap survived the hand-built matrix).
 *
 * Mechanism: envStore.cjs calls methods on the shared `fs` singleton at call time, so
 * wrapping those methods here injects faults into the real code paths with NO production
 * changes. The injector crashes AFTER the real operation executes (the "op N persisted,
 * then the process died" model, which also covers a crash after the final op), and it
 * covers EVERY mutating boundary the store touches: content writes, renames, copies,
 * removals, fsync, plus directory and file creation (mkdir/rmdir/openSync), so lock and
 * temp-file boundaries are counted too.
 *
 * For each write path and each boundary K:
 *   SAME MOUNT: loadEnv() must not silently lose any owned value, and re-running the
 *     write must converge to the path's OWN requested end state (checked per path, not a
 *     generic "migrated" flag).
 *   HIDDEN MOUNT (state dir renamed aside): loadEnv() must THROW or return every owned
 *     value; never a silent absence.
 * Offline, plain node, exits non-zero on the first failure.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-ecx-"));
process.env.TEGARA_ENV_PATH = path.join(TMP, "env.local");

const { ENV_PATH, STATE_DIR, loadEnv, saveEnv, updateEnvKey, lockEnv, unlockEnv } = require("./envStore.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };

// the pre-migration seed: two owned values in the env FILE, to be migrated out
const SEED = { COMPOUND_A: "journal-a", WATCH_B: "watermark-b", RECEIPT_DRAFT_X: "draft-x" };
const writeSeed = () => {
  fs.rmSync(STATE_DIR, { recursive: true, force: true });
  fs.rmSync(`${ENV_PATH}.lock`, { recursive: true, force: true });
  fs.rmSync(path.join(STATE_DIR, "env.lock"), { recursive: true, force: true });
  fs.mkdirSync(STATE_DIR);
  fs.writeFileSync(ENV_PATH,
    `MNEMONIC=m\n${Object.entries(SEED).map(([k, v]) => `${k}=${v}`).join("\n")}\n`);
};

// ---- the fault injector over the fs singleton (crash AFTER the real op) ----
const MUTATORS = ["writeFileSync", "renameSync", "copyFileSync", "rmSync", "rmdirSync",
  "writeSync", "fsyncSync", "mkdirSync", "openSync"];
const real = {};
for (const m of MUTATORS) real[m] = fs[m];
let armAfter = Infinity, count = 0;
class InjectedCrash extends Error {}
for (const m of MUTATORS) {
  fs[m] = (...a) => {
    const r = real[m](...a);   // execute the real op first
    count += 1;
    if (count > armAfter) throw new InjectedCrash(`injected after op ${count} (${m})`);
    return r;
  };
}
const runCounting = (fn) => { count = 0; armAfter = Infinity; try { fn(); } catch (e) { if (!(e instanceof InjectedCrash)) throw e; } return count; };
// returns true iff the injected crash actually fired (review finding: a replay that
// performs FEWER ops than the counting run would complete normally at a high k, and its
// end-state assertions would then pass vacuously; the caller asserts this flag)
const armed = (k, fn) => {
  count = 0; armAfter = k;
  let crashed = false;
  try { fn(); } catch (e) { if (e instanceof InjectedCrash) crashed = true; else throw e; } finally { armAfter = Infinity; }
  return crashed;
};
const HIDDEN = `${STATE_DIR}.hidden`;
const hideDir = () => { if (fs.existsSync(STATE_DIR)) real.renameSync(STATE_DIR, HIDDEN); };
const unhideDir = () => { if (fs.existsSync(HIDDEN)) real.renameSync(HIDDEN, STATE_DIR); };

const readState = () => {
  try { return { threw: false, env: loadEnv() }; } catch (e) { return { threw: true, e }; }
};
// "must survive" = values that a CRASH must never silently drop. It excludes keys the
// path intentionally deletes (they may legitimately be absent) and keys it adds (absent
// mid-crash is fine). Defaults to the whole seed for add-only paths.
const noSilentLoss = (r, mustSurvive) => r.threw ||
  Object.entries(mustSurvive).every(([k, v]) => r.env[k] === v);

// each write path declares its OWN requested end state (review finding: a generic
// migrated-flag check let a path lose its actual mutation while staying green) and the
// set that must survive a crash.
const matrixOver = (label, doWrite, expectedEnd, mustSurvive = SEED) => {
  writeSeed();
  const n = runCounting(doWrite);
  ok(`${label}: touches filesystem boundaries (${n})`, n > 0);
  // the clean run must reach the requested end state, so the crash cases have a target
  writeSeed(); doWrite();
  ok(`${label}: clean run reaches the requested end state`, expectedEnd());
  // iterate boundaries until a run completes WITHOUT crashing (that k is past the last
  // real op). This break-on-no-crash structure is the anti-vacuous guarantee the review
  // asked for: an assertion is only ever made on a run that DID crash, so a replay doing
  // fewer ops than expected ends the loop rather than passing an assertion emptily.
  let boundaries = 0;
  for (let k = 0; ; k++) {
    // same mount: crash after k ops, then no crash-loss and a converging retry
    writeSeed();
    if (!armed(k, doWrite)) break; // this k is past the last real op; stop
    boundaries += 1;
    const r1 = readState();
    ok(`${label} k=${k}: same-mount read keeps every must-survive value`,
      !r1.threw && Object.entries(mustSurvive).every(([kk, v]) => r1.env[kk] === v));
    // clear any lock the crashed run left (the store's 30 s staleness or an operator
    // does this; this harness tests STATE convergence, not the lock timer, which
    // envStoreTest covers)
    fs.rmSync(`${ENV_PATH}.lock`, { recursive: true, force: true });
  fs.rmSync(path.join(STATE_DIR, "env.lock"), { recursive: true, force: true });
    let retryErr = null;
    try { doWrite(); } catch (e) { retryErr = e; }
    ok(`${label} k=${k}: the retry converges to THIS path's end state`,
      retryErr === null && expectedEnd());
    // hidden mount: a fresh crash at the same boundary, then read never silently loses.
    // k is already known to be a real boundary (the same-mount armed above crashed),
    // so this armed MUST crash too; assert it rather than ignoring the result, or the
    // no-loss check could run against a non-crashed (complete) state (review finding).
    writeSeed();
    ok(`${label} k=${k}: hidden-mount crash also fired`, armed(k, doWrite));
    hideDir();
    ok(`${label} k=${k}: hidden-mount read never silently loses a must-survive value`,
      noSilentLoss(readState(), mustSurvive));
    unhideDir();
  }
  // a real, non-trivial set of boundaries was crash-tested (the exact count can differ
  // from the clean run's n by the final unlock op, which is immaterial: every one of
  // these `boundaries` runs genuinely crashed and passed its no-loss + convergence
  // assertions)
  ok(`${label}: exercised a real crash boundary set (${boundaries}, clean run n=${n})`,
    boundaries > 0 && boundaries >= n - 1);
};

// path 1: foreign save migrates the owned seed AND lands its own plain key
matrixOver("foreign-save migration",
  () => saveEnv({ MNEMONIC: "m", PLAIN: "p" }),
  () => {
    const env = loadEnv(); const raw = fs.readFileSync(ENV_PATH, "utf8");
    return env.COMPOUND_A === SEED.COMPOUND_A && env.WATCH_B === SEED.WATCH_B &&
      env.RECEIPT_DRAFT_X === SEED.RECEIPT_DRAFT_X &&
      raw.includes("PLAIN=p") && /STATE_MIGRATED=1/.test(raw) && /STATE_STORE_ID=/.test(raw) &&
      !/COMPOUND_A|WATCH_B|RECEIPT_DRAFT_X/.test(raw) && fs.existsSync(path.join(STATE_DIR, "store.id"));
  });

// path 2: owned updateEnvKey migrates the seed AND writes its own owned key
matrixOver("owned updateEnvKey",
  () => updateEnvKey("AUTOPAY_NEW", "on"),
  () => {
    const env = loadEnv();
    return env.COMPOUND_A === SEED.COMPOUND_A && env.WATCH_B === SEED.WATCH_B &&
      env.AUTOPAY_NEW === "on" && fs.existsSync(path.join(STATE_DIR, "AUTOPAY_NEW.val"));
  });

// path 3: journalOwner sync-exactly must ADD a key and DELETE an absent one (the
// deletion is the behavior the review said the unchanged-value case never exercised)
matrixOver("journalOwner sync-exactly",
  () => {
    lockEnv();
    try {
      const env = loadEnv();       // COMPOUND_A + WATCH_B present
      env.COMPOUND_NEW = "added";  // add
      delete env.WATCH_B;          // delete: sync-exactly must remove its state file
      saveEnv(env, { journalOwner: true });
    } finally { unlockEnv(); }
  },
  () => {
    const env = loadEnv();
    return env.COMPOUND_A === SEED.COMPOUND_A && env.COMPOUND_NEW === "added" &&
      env.WATCH_B === undefined && !fs.existsSync(path.join(STATE_DIR, "WATCH_B.val"));
  },
  { COMPOUND_A: SEED.COMPOUND_A });  // WATCH_B is deliberately deleted; only COMPOUND_A must survive a crash

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
