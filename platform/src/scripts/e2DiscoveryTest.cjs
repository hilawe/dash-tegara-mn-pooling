/**
 * Offline test for the shared discovery primitive (plain `node`, no network),
 * driving the frozen contract's named cases with synthetic epoch sets:
 * boundary-aligned, later-empty, clipped and empty-first (duty D8's battery names
 * these), plus the shape refusals and the width bounds. Expectations are derived
 * from the CONTRACT, never from the code under test: each case states the ledger
 * it simulates and computes the expected newest finalized by hand.
 *
 * The shared-call case (both e2Distribute.cjs and e2Audit.cjs importing THIS
 * primitive) is asserted at source below; it upgrades to an execution assertion
 * when those consumers land.
 */
const fs = require("fs");
const path = require("path");
const { discoverFinalizedEpochs, U32_MAX } = require("./e2Discovery.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed++; }
  else { failed++; console.error("FAIL:", name); }
};
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

// a synthetic ledger: finalized epochs are exactly [lo..newest]; the fetch serves
// the inclusive intersection, gapless ascending, at a declared proof strength
const ledgerFetch = (newest, provedFlag, log) => async (start, end) => {
  if (log) log.push([start, end]);
  const epochs = [];
  for (let n = start; n <= end && n <= newest; n++) epochs.push({ number: n });
  return { epochs, proved: provedFlag };
};

(async () => {
  // ---- partial tail inside the first range: newest = h ----
  {
    const r = await discoverFinalizedEpochs(10, ledgerFetch(25, false), { width: 64 });
    ok("partial first range finds the newest", r.empty === false && r.newestFinalized === 25);
    ok("partial first range returns epochs 10..25 (identity, not count)",
      r.epochs.length === 16 && r.epochs[0].number === 10 && r.epochs[15].number === 25);
    ok("unproved fetch yields an unproved result", r.proved === false);
  }

  // ---- BOUNDARY-ALIGNED: newest sits exactly on a range top, the next range is
  // empty, so the LATER-EMPTY rule terminates at the preceding top ----
  {
    const log = [];
    const r = await discoverFinalizedEpochs(0, ledgerFetch(63, true, log), { width: 64 });
    ok("boundary-aligned newest is found via the later-empty rule",
      r.empty === false && r.newestFinalized === 63);
    ok("boundary-aligned case needed exactly two ranges",
      log.length === 2 && log[0][0] === 0 && log[0][1] === 63 && log[1][0] === 64 && log[1][1] === 127);
    ok("proved fetch keeps a proved flag (still capped by C1 at the caller)", r.proved === true);
  }

  // ---- LATER-EMPTY across several full ranges, with EVERY returned epoch
  // asserted by identity across the page boundaries (the batched checker's
  // finding 6: endpoint-and-count checks let a duplicate-middle mutation
  // survive; the full-sequence check is what kills it) ----
  {
    const r = await discoverFinalizedEpochs(0, ledgerFetch(191, true), { width: 64 });
    ok("three full ranges then empty terminates at 191", r.newestFinalized === 191 && r.epochs.length === 192);
    ok("every returned epoch is the exact ascending sequence 0..191, element by element",
      r.epochs.every((e, i) => e.number === i));
  }
  {
    const r = await discoverFinalizedEpochs(10, ledgerFetch(150, true), { width: 32 });
    ok("a multi-page walk from a nonzero start returns exactly 10..150 by identity",
      r.epochs.length === 141 && r.epochs.every((e, i) => e.number === 10 + i));
  }

  // ---- EMPTY FIRST response is the DISTINCT EMPTY RESULT ----
  {
    const r = await discoverFinalizedEpochs(100, ledgerFetch(40, true), { width: 32 });
    ok("empty first response is the distinct empty result",
      r.empty === true && r.newestFinalized === null && r.epochs.length === 0);
  }

  // ---- CLIPPED at the u32 ceiling: a full response ending at the ceiling
  // terminates AT the ceiling, no range past it is requested ----
  {
    const log = [];
    const start = U32_MAX - 9;
    const r = await discoverFinalizedEpochs(start, ledgerFetch(U32_MAX, true, log), { width: 64 });
    ok("a full clipped response terminates AT the u32 ceiling", r.newestFinalized === U32_MAX);
    ok("no range past the ceiling is requested", log.length === 1 && log[0][1] === U32_MAX);
    ok("the clipped range returned exactly the 10 ceiling epochs", r.epochs.length === 10);
  }

  // ---- the response-shape refusals ----
  await rejects("a gapped response refuses",
    discoverFinalizedEpochs(0, async () => ({ epochs: [{ number: 0 }, { number: 2 }], proved: true })),
    /not the exact gapless ascending sequence/);
  await rejects("a response starting past the requested start refuses",
    discoverFinalizedEpochs(5, async () => ({ epochs: [{ number: 6 }], proved: true })),
    /not the exact gapless ascending sequence/);
  await rejects("a descending response refuses",
    discoverFinalizedEpochs(0, async () => ({ epochs: [{ number: 1 }, { number: 0 }], proved: true })),
    /not the exact gapless ascending sequence/);
  await rejects("a response overrunning its range refuses",
    discoverFinalizedEpochs(0, async (s, e) => ({
      epochs: Array.from({ length: e - s + 2 }, (_, i) => ({ number: s + i })), proved: true,
    }), { width: 8 }),
    /overruns its requested range/);
  await rejects("a non-integer epoch number refuses",
    discoverFinalizedEpochs(0, async () => ({ epochs: [{ number: "0" }], proved: true })),
    /no integer epoch number/);
  await rejects("a malformed fetch result refuses",
    discoverFinalizedEpochs(0, async () => ({ epochs: null, proved: true })),
    /malformed result/);

  // ---- input bounds ----
  await rejects("width 0 refuses", discoverFinalizedEpochs(0, ledgerFetch(5, true), { width: 0 }), /outside 1\.\.1024/);
  await rejects("width 1025 refuses", discoverFinalizedEpochs(0, ledgerFetch(5, true), { width: 1025 }), /outside 1\.\.1024/);
  await rejects("a negative start refuses", discoverFinalizedEpochs(-1, ledgerFetch(5, true)), /not a u32/);
  await rejects("a past-ceiling start refuses", discoverFinalizedEpochs(U32_MAX + 1, ledgerFetch(5, true)), /not a u32/);
  await rejects("a missing fetch refuses", discoverFinalizedEpochs(0, undefined), /injected fetchRange/);

  // ---- width 1 exercises the machine at its smallest legal configuration ----
  {
    const r = await discoverFinalizedEpochs(3, ledgerFetch(5, true), { width: 1 });
    ok("width 1 walks single-epoch ranges to the newest", r.newestFinalized === 5 && r.epochs.length === 3);
  }

  // ---- a mixed-strength fetch downgrades the whole result, and the downgrade
  // is STICKY: the unproved page comes FIRST and every later page is proved, so
  // a last-page-wins implementation passes proved=true and fails this case (a
  // first-form of this case had the unproved page last, and the last-page-wins
  // mutation SURVIVED it; the surviving mutation is why the order is pinned) ----
  {
    let call = 0;
    const mixed = async (s, e) => { call++; return { ...(await ledgerFetch(200, call !== 1)(s, e)) }; };
    const r = await discoverFinalizedEpochs(0, mixed, { width: 64 });
    ok("an early unproved page downgrades the whole discovery stickily", r.proved === false);
  }

  // ---- the SHARED-CALL property, at source until the consumers land: the two
  // named consumers import this module and no other file reimplements the range
  // machine (grepping for a second `gapless ascending` implementation) ----
  {
    const dir = __dirname;
    const files = fs.readdirSync(dir).filter((f) => /\.(cjs|mjs)$/.test(f));
    const reimplementors = files.filter((f) => {
      if (f === "e2Discovery.cjs" || f === "e2DiscoveryTest.cjs") return false;
      const src = fs.readFileSync(path.join(dir, f), "utf8");
      return /gapless ascending/i.test(src) && !src.includes('require("./e2Discovery.cjs")');
    });
    ok("no sibling module reimplements discovery without importing the primitive",
      reimplementors.length === 0);
    for (const consumer of ["e2Distribute.cjs", "e2Audit.cjs"]) {
      const p = path.join(dir, consumer);
      if (fs.existsSync(p)) {
        ok(`${consumer} imports the shared primitive`,
          fs.readFileSync(p, "utf8").includes('require("./e2Discovery.cjs")'));
      }
    }
  }

  console.log(`e2DiscoveryTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
})();
