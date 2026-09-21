/**
 * READ A RUNNER'S SOURCE FOR A TEXT SWEEP, or say plainly that it is not in this tree.
 *
 * WHY THIS EXISTS. Several suites end with a sweep over a live runner's source, binding the
 * SPELLING of a wiring that only a live run executes. Those runners are `.mjs`, and the curated
 * public export deliberately holds every `.mjs` out: the stable `.cjs` surface ships and the live
 * instruments do not. A sweep that read one with `readFileSync` therefore CRASHED on the public
 * tree, taking the whole suite down with it, which the export's own suite gate caught twice in one
 * session. The allowlist is right and the sweeps are right; what was wrong is that a sweep treated
 * a file's presence as guaranteed.
 *
 * ABSENCE IS A COUNTED SKIP, NEVER A PASS. This returns null rather than throwing, and every
 * caller is expected to record a skip and say so in its summary. A sweep that silently did
 * nothing when its subject was missing would be the "unchecked means passed" shape: the assertion
 * would vanish from the count and the suite would read greener than it is. The skip is printed
 * with the reason and the file name so a reader of the public suite's output knows exactly which
 * check did not run and why.
 */
const fs = require("fs");
const path = require("path");

/** The runner's source, or null when it is not in this tree. */
const runnerSource = (name) => {
  const p = path.join(__dirname, name);
  if (!fs.existsSync(p)) return null;
  return fs.readFileSync(p, "utf8");
};

/**
 * The line a caller prints when it skips. It names the file and the reason, so the skip is
 * legible on its own rather than only to someone who knows the export's allowlist.
 */
const skipNote = (name, what) =>
  `  SKIP: ${what} (${name} is not in this tree; the curated export holds the .mjs runners out). ` +
  "This is a SKIPPED check, never a passed one.";

module.exports = { runnerSource, skipNote };
