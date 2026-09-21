/**
 * fetchAll terminates on its own (a soundness-review finding).
 *
 * fetchAll walks a ledger with a startAfter cursor taken from the RETURNED page,
 * so its progress depends entirely on what the node sends back. A node that
 * answers every request with the same full page produces the same cursor every
 * time, and the walk never ends. Nothing in this module checks that identifiers
 * ascend, so unlike the proved-query enumeration there was not even a second
 * rule making it terminate incidentally.
 *
 * The class was found by the audit mutation battery on its sibling: dropping one
 * ordering check there did not fail the module, it HUNG it, and the battery
 * registered the case as caught only because the harness timed the suite out. A
 * sweep for the shape found this function, whose own neighbour fetchUpTo had
 * already been bounded for the related concern of an unbounded collection.
 *
 * These cases assert TERMINATION, so the call count carries the claim: a walk
 * that never stopped would not reach any assertion at all.
 *
 * Run: node src/scripts/queryPaginationTest.cjs   (exits non-zero on failure)
 */
const { fetchAll } = require("./query.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed += 1; } else { failed += 1; console.log(`FAIL: ${name}`); }
};
const rejects = async (name, p, re) => {
  try { await p; failed += 1; console.log(`FAIL: ${name} (resolved, expected a refusal)`); }
  catch (e) {
    if (re.test(e.message)) { passed += 1; }
    else { failed += 1; console.log(`FAIL: ${name} (wrong refusal: ${e.message})`); }
  }
};

// a document as fetchAll reads it: it only ever calls getId() on the last one
const doc = (n) => ({ getId: () => n.toString(16).padStart(2, "0").repeat(32) });
// a client whose documents.get is driven by the supplied page function.
// documents.get(type, options): the fakes take BOTH, since reading the options off
// the first parameter silently yields undefined and an empty page every time.
const clientOf = (getPage) => ({ platform: { documents: { get: getPage } } });

const main = async () => {
  {
    // the ordinary walk still works: two full pages then a short one
    let calls = 0;
    const client = clientOf(async (_type, { limit }) => {
      calls += 1;
      if (calls <= 2) return Array.from({ length: limit }, (_, i) => doc(calls * 100 + i));
      return [doc(9)];
    });
    const out = await fetchAll(client, "poolLedger.settlement");
    ok("a short page ends the walk and every page's documents are kept",
      out.length === 201 && calls === 3);
  }
  {
    // a single short page returns without a second request
    let calls = 0;
    const client = clientOf(async (_type, _opts) => { calls += 1; return [doc(1), doc(2)]; });
    const out = await fetchAll(client, "poolLedger.settlement");
    ok("a first short page returns immediately", out.length === 2 && calls === 1);
  }
  {
    // THE BOUND. Every page is full, so nothing in the page shape ever ends the
    // walk; only the ceiling does. The cursor even advances here, which is the
    // point: advancing is not the same as terminating.
    let calls = 0;
    const client = clientOf(async (_type, { limit }) => {
      calls += 1;
      return Array.from({ length: limit }, (_, i) => doc(calls * 100 + i));
    });
    await rejects("fetchAll refuses rather than walking an endless ledger",
      fetchAll(client, "poolLedger.settlement"), /exceeded 10000 pages/);
    ok("it stops at its ceiling rather than walking forever", calls === 10000);
  }
  {
    // the shape that hangs a cursor-driven walk: the SAME full page forever, so
    // the cursor never changes. The ceiling catches this too, which is the
    // reason the bound is a page count rather than a cursor-advance check.
    let calls = 0;
    const client = clientOf(async (_type, { limit }) => {
      calls += 1;
      return Array.from({ length: limit }, (_, i) => doc(i));
    });
    await rejects("fetchAll refuses a node that repeats one page forever",
      fetchAll(client, "poolLedger.settlement"), /exceeded 10000 pages/);
    ok("the repeated-page walk also stops at the ceiling", calls === 10000);
  }

  console.log(`queryPaginationTest: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
};

main().catch((e) => { console.error(e); process.exit(1); });
