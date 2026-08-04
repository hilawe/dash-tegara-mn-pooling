/**
 * Every RELATIVE require specifier in src/scripts resolves to a real file (closing
 * wave, major): commands/pledge.cjs loaded `./formationCore.cjs` from inside the
 * commands directory, one level below the module it meant, so the whole retained
 * v1-through-v5 pledge path stopped with MODULE_NOT_FOUND at its first use, and no
 * suite drove the command far enough to notice. Command modules load lazily inside
 * their handler bodies, which is exactly why a broken path stays green until a member
 * hits it. This suite covers the LITERAL-SPECIFIER class in the PLAIN CALL FORMS:
 * a relative specifier written as a string literal in require(...), import(...),
 * `import ... from "..."`, or a bare `import "..."`, with ordinary whitespace,
 * across the .cjs/.mjs files in scripts/ and commands/, each resolved against the
 * requiring file's own directory, so a mis-anchored literal path in those forms fails
 * the suite the moment it is written. STATED BOUNDARIES (pre-commit artifact check): a
 * specifier BUILT at runtime (template or concatenation) is not extractable statically
 * and is not covered, a comment wedged between the callee and its argument is outside
 * the pattern, and resolution uses the CommonJS resolver for .mjs files too, an
 * approximation that accepts a few shapes the ESM loader would refuse (it cannot miss
 * a missing file, which is the defect class this net exists for).
 *
 * Static extraction, not execution: the files are read, never required, so transport
 * modules and env-dependent scripts cost nothing and have no side effects here.
 *
 * Run: node src/scripts/requireResolutionTest.cjs   (exits non-zero on failure)
 */
const fs = require("fs");
const path = require("path");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };

const HERE = __dirname;
const files = [];
for (const dir of [HERE, path.join(HERE, "commands")]) {
  for (const f of fs.readdirSync(dir)) {
    if (/\.(cjs|mjs)$/.test(f)) files.push(path.join(dir, f));
  }
}
ok("the walk finds a plausible module population (both directories, 40+ files)", files.length >= 40);

// literal specifiers starting with ./ or ../ in require(...), dynamic import(...),
// import-from, and bare side-effect imports, tolerating ordinary whitespace around
// the call parenthesis
const SPEC = /(?:require\s*\(\s*|import\s*\(\s*|from\s+|import\s+)["'](\.{1,2}\/[^"']+)["']/g;
let specs = 0;
for (const file of files) {
  const src = fs.readFileSync(file, "utf8");
  for (const m of src.matchAll(SPEC)) {
    specs += 1;
    const spec = m[1];
    let resolved = true;
    try { require.resolve(path.resolve(path.dirname(file), spec)); } catch { resolved = false; }
    ok(`${path.relative(HERE, file)}: ${spec} resolves`, resolved);
  }
}
ok("the extraction saw a plausible specifier population (100+)", specs >= 100);

console.log(`requireResolutionTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
