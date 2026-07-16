/**
 * The child runner for the formation crash harness: hooks `dash` to the mock module,
 * arms the shared fault counter, adds envStore's LOCAL STATE WRITES as fault boundaries
 * (a platform-op-only counter would never interrupt between finalization's consecutive
 * updateEnvKey calls), then runs the REAL formation.cjs with the requested argv.
 *
 *   TEGARA_MOCK_LEDGER      the ledger JSON (required by the mock)
 *   TEGARA_MOCK_CRASH_AFTER integer K: hard-exit 97 after fault boundary K (absent = no fault)
 *   argv: node formationCrashChild.cjs <formation args...>
 */
const path = require("path");
const Module = require("module");

const MOCK = path.join(__dirname, "formationMockDash.cjs");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === "dash") return MOCK;
  return origResolve.call(this, request, ...rest);
};

global.__TEGARA_FAULT = {
  count: 0,
  after: process.env.TEGARA_MOCK_CRASH_AFTER !== undefined
    ? parseInt(process.env.TEGARA_MOCK_CRASH_AFTER, 10) : Infinity,
};

// local durable writes are boundaries too: wrap updateEnvKey BEFORE formation.cjs
// destructures it at require time
const envStore = require("./envStore.cjs");
const realUpdate = envStore.updateEnvKey;
envStore.updateEnvKey = (key, value) => {
  const r = realUpdate(key, value);
  const f = global.__TEGARA_FAULT;
  f.count += 1;
  if (f.count > f.after) {
    process.stderr.write(`[child] injected crash after local write ${f.count - 1} (${key})\n`);
    process.exit(97); // a real crash: no finally, the op lock stays held
  }
  return r;
};

process.argv = [process.argv[0], path.join(__dirname, "formation.cjs"), ...process.argv.slice(2)];
require("./formation.cjs");
