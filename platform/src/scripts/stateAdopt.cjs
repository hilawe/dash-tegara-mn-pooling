/**
 * The explicit state-dir adoption command (review follow-on, two-model convergence,
 * 2026-07-12): pair this env file with the currently visible `.env.local.state/`
 * directory, deliberately. The ordinary read and write paths REFUSE an ambiguous legacy
 * directory (a migrated env file with no store id over a dir with no sentinel and no
 * state files, the docker forgotten-mount shape) and their refusal points here; running
 * this is the operator stating "this directory is correct". It never overrides a
 * conflicting pairing.
 *
 * Run (container, same mounts as everything else, or directly on the host):
 *   node src/scripts/stateAdopt.cjs
 * Prints a non-secret report (store id, state-file count and key names). Offline.
 */
const { ENV_PATH, STATE_DIR, adoptStateDir } = require("./envStore.cjs");

try {
  const r = adoptStateDir();
  console.log(`env file:  ${ENV_PATH}`);
  console.log(`state dir: ${STATE_DIR}`);
  console.log(`state files: ${r.valCount}${r.valCount > 0 ? ` (${r.valKeys.join(", ")})` : ""}`);
  if (r.already) {
    console.log(`already paired (store id ${r.storeId}); nothing to do`);
  } else {
    console.log(`\n=== ADOPTED: store id ${r.storeId} now pairs the env file and the directory ===`);
  }
} catch (e) {
  console.error("ERROR:", (e && e.message) || e);
  process.exitCode = 1;
}
