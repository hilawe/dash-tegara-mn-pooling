/**
 * Offline tests for a soundness-review finding: the consumed-output guard must REFUSE when the rail state
 * cannot be read, never report "nothing consumed". An empty environment is a
 * legitimately fresh state and keeps working; an unreadable or corrupt one is a
 * refusal railState already makes, and the guard's old catch turned that refusal into
 * an unfiltered wallet view (the unchecked-never-means-passed shape).
 *
 * Fixture mechanics, learned from a probe run and worth keeping written down: the env
 * path is captured by envStore at require time (TEGARA_ENV_PATH set first), and
 * railState.save MIGRATES owned state into the `<env>.state` directory, after which
 * the env FILE is only a pointer (STATE_MIGRATED=1). The file-only fixture cases
 * therefore run BEFORE the first save, and the post-migration cases drive the guard
 * through the file the way a real run does (loadEnv still opens the env file first,
 * so an unreadable file refuses even when the state lives in the directory).
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-wallet-guard-"));
const envPath = path.join(dir, ".env.local");
process.env.TEGARA_ENV_PATH = envPath;
fs.writeFileSync(envPath, "");
fs.mkdirSync(`${envPath}.state`); // updateEnvKey's cross-process lock home

const rail = require("./railState.cjs");
const { loadEnv } = require("./envStore.cjs");
const { installConsumedFilter } = require("./walletGuard.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };

const PHANTOM = { txId: "aa".repeat(32), outputIndex: 0 };
const OTHER = { txId: "bb".repeat(32), outputIndex: 1 };
const account = () => installConsumedFilter({ getUTXOS: () => [PHANTOM, OTHER] });

// 1. a legitimately EMPTY environment stays working: fresh idle state, nothing
// consumed, no refusal (the row that keeps the fix from over-refusing)
{
  fs.writeFileSync(envPath, "");
  const utxos = account().getUTXOS();
  ok("empty env: fresh state passes BOTH outputs through by identity",
    utxos.length === 2 && utxos[0] === PHANTOM && utxos[1] === OTHER);
}

// 2. a soundness-review finding core: corrupt RAIL_STATE (invalid JSON) must REFUSE, and the refusal must
// carry the underlying reason rather than a bare generic message
{
  fs.writeFileSync(envPath, "RAIL_STATE={corrupt!\n");
  let caught = null;
  try { account().getUTXOS(); } catch (e) { caught = e; }
  ok("corrupt RAIL_STATE: the guard refuses instead of reporting nothing consumed",
    caught !== null && /consumed-output state cannot be read/.test(caught.message));
  // the CAUSE carries the real underlying error object, asserted on the cause itself so
  // a wrapper that appends constant words without preserving the exception fails here
  ok("corrupt RAIL_STATE: the cause is the underlying parse error",
    caught !== null && caught.cause instanceof Error && /JSON/i.test(caught.cause.message));
  // and the OPERATOR-VISIBLE message embeds the cause's own words, so a wrapper that
  // fakes an underlying reason with constant text fails here (mutation M3's survivor)
  ok("corrupt RAIL_STATE: the visible message embeds the real underlying words",
    caught !== null && caught.cause instanceof Error
    && caught.message.includes(caught.cause.message));
}

// 3. the shape-refusal variant: valid JSON that railState's validate refuses
// (consumed is not a list) must surface railState's own words
{
  fs.writeFileSync(envPath, 'RAIL_STATE={"version":2,"slot":null,"epoch":null,"consumed":"nope"}\n');
  let caught = null;
  try { account().getUTXOS(); } catch (e) { caught = e; }
  ok("refused RAIL_STATE shape: the cause is railState's own refusal",
    caught !== null && caught.cause instanceof Error
    && /consumed is not a list/.test(caught.cause.message)
    && /consumed-output state cannot be read/.test(caught.message));
}

// 4. CONTROL: the consumed entry is inserted by the test, then PERSISTED THROUGH THE
// REAL SAVE (railState.save derives the phase, validates, and migrates into the state
// directory), so the stored format is the constructor's own; the guard must filter the
// consumed outpoint from the wallet view
{
  fs.writeFileSync(envPath, "");
  const env = loadEnv();
  const state = rail.load(env);
  state.consumed.push(`${PHANTOM.txId}:${PHANTOM.outputIndex}`);
  rail.save(env, state);
  const utxos = account().getUTXOS();
  ok("control: the consumed outpoint is filtered, the other passes by identity",
    utxos.length === 1 && utxos[0] === OTHER);
}

// 4b. MIGRATED-STATE corruption (external artifact check, finding 3): the consumed
// record now lives in the state DIRECTORY, and corrupting THAT file must refuse too,
// binding the migrated read path and not only the inline env forms
{
  const stateFile = path.join(`${envPath}.state`, "RAIL_STATE.val");
  const original = fs.readFileSync(stateFile);
  fs.writeFileSync(stateFile, "{corrupt!");
  let caught = null;
  try { account().getUTXOS(); } catch (e) { caught = e; }
  fs.writeFileSync(stateFile, original);
  ok("corrupt MIGRATED state record: refusal, with the parse failure as the cause",
    caught !== null && /consumed-output state cannot be read/.test(caught.message)
    && caught.cause instanceof Error);
}

// 5 and 6. a soundness-review finding named case AND same-guard recovery, on ONE installed guard
// (external artifact check, finding 1: a fresh guard per row would let a
// per-installed-guard cache pass every assertion). The consumed record exists in the
// migrated state, the env POINTER file becomes unreadable, and the SAME guard must
// refuse then, and filter again on its very next call once readable, which is what
// actually pins the re-read-per-call behaviour (F12)
{
  const guarded = account();
  // a SUCCESSFUL read happens FIRST, so any per-guard cache is populated before the
  // failure; the refusal below then proves errors are not served from that cache
  // (mutation M5's survivor: without this read the cache is never filled and a
  // cache-on-error guard passes every row)
  const before = guarded.getUTXOS();
  ok("same guard, readable state first: filters before the failure",
    before.length === 1 && before[0] === OTHER);
  fs.chmodSync(envPath, 0o000);
  let result = null, caught = null;
  try { result = guarded.getUTXOS(); } catch (e) { caught = e; }
  fs.chmodSync(envPath, 0o644);
  ok("unreadable env pointer over a consumed record: refusal, never the phantom",
    caught !== null && result === null
    && /consumed-output state cannot be read/.test(caught.message));
  const utxos = guarded.getUTXOS();
  ok("recovery on the SAME guard: the next call filters again",
    utxos.length === 1 && utxos[0] === OTHER);
}

console.log(`walletGuardTest: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
