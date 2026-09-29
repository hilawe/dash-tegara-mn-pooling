// The wire pacer's offline battery, on a fake clock. The contrary case is the first one: without
// spacing, three calls start at the same instant, which is the shape the testnet gateway refused.
const { createPacer, parseSpacingMs } = require("./wirePacing.cjs");
let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error("FAIL:", name, "(no error)"); }
  catch (e) { ok(name, re.test(String(e.message))); }
};

// a fake clock whose sleep advances time, and a wire call that records when it started
const fakeClock = () => {
  let t = 1000;
  return { now: () => t, sleep: async (ms) => { t += ms; } };
};
const recorder = (clock) => {
  const starts = [];
  const fn = async (x) => { starts.push(clock.now()); return { echoed: x }; };
  return { starts, fn };
};

(async () => {
  {
    const c = fakeClock(); const r = recorder(c);
    const call = createPacer({ minSpacingMs: 0, ...c })(r.fn);
    await Promise.all([call(1), call(2), call(3)]);
    ok("with no spacing, three calls start at the same instant", r.starts.join() === "1000,1000,1000");
  }
  {
    const c = fakeClock(); const r = recorder(c);
    const call = createPacer({ minSpacingMs: 500, ...c })(r.fn);
    const out = await Promise.all([call("a"), call("b"), call("c")]);
    ok("with 500 ms spacing, the starts are 500 ms apart", r.starts.join() === "1000,1500,2000");
    ok("arguments and answers pass through unchanged, in order",
      out.map((o) => o.echoed).join() === "a,b,c");
  }
  {
    const c = fakeClock(); const r = recorder(c);
    const call = createPacer({ minSpacingMs: 500, ...c })(r.fn);
    await call(1);
    c.sleep(2000);
    await call(2);
    ok("a call made after the spacing has already elapsed does not wait", r.starts.join() === "1000,3000");
  }
  {
    const c = fakeClock(); const starts = [];
    const pace = createPacer({ minSpacingMs: 400, ...c });
    const f = pace(async () => { starts.push(["f", c.now()]); });
    const g = pace(async () => { starts.push(["g", c.now()]); });
    await Promise.all([f(), g(), f()]);
    ok("one pacer spaces two wrapped functions together",
      starts.map(([n, t]) => `${n}${t}`).join() === "f1000,g1400,f1800");
  }
  {
    const c = fakeClock(); const starts = [];
    const pace = createPacer({ minSpacingMs: 300, ...c });
    const bad = pace(async () => { starts.push(c.now()); throw new Error("rate limited"); });
    const good = pace(async () => { starts.push(c.now()); return 7; });
    const [a, b] = await Promise.allSettled([bad(), good()]);
    ok("a rejection reaches its own caller unchanged", a.status === "rejected" && /rate limited/.test(a.reason.message));
    ok("a rejection does not hold up the next call, which still waits its turn",
      b.status === "fulfilled" && b.value === 7 && starts.join() === "1000,1300");
  }
  {
    // the live calls pass two arguments, the gRPC pool and the interval with its proof options
    const c = fakeClock(); const seen = [];
    const call = createPacer({ minSpacingMs: 500, ...c })(async (...a) => { seen.push(a); return a.length; });
    const pool = { pool: true }; const opts = { startEpoch: 5, endEpoch: 9, prove: true };
    const n = await call(pool, opts);
    ok("every argument reaches the wrapped function, by identity",
      n === 2 && seen[0].length === 2 && seen[0][0] === pool && seen[0][1] === opts);
  }
  {
    // a wait that throws once: its own call rejects, and the calls after it still start
    let t = 1000, fails = 1; const starts = [];
    const pace = createPacer({ minSpacingMs: 500, now: () => t,
      sleep: async (ms) => { if (fails-- > 0) throw new Error("timer failed"); t += ms; } });
    const call = pace(async (x) => { starts.push([x, t]); return x; });
    const out = await Promise.allSettled([call(1), call(2), call(3), call(4)]);
    ok("the call whose wait failed rejects with that failure",
      out[1].status === "rejected" && /timer failed/.test(out[1].reason.message));
    ok("the calls after a failed wait still start and answer",
      out[0].value === 1 && out[2].value === 3 && out[3].value === 4 && starts.map(([x]) => x).join() === "1,3,4");
    ok("and they stay spaced", starts.map(([, s]) => s).join() === "1000,1500,2000");
  }
  throws("a negative spacing refuses", () => createPacer({ minSpacingMs: -1 }), /whole number/);
  throws("a fractional spacing refuses", () => createPacer({ minSpacingMs: 1.5 }), /whole number/);
  throws("a spacing above the ceiling refuses", () => createPacer({ minSpacingMs: 60001 }), /whole number/);

  ok("an unset setting takes the fallback", parseSpacingMs(undefined, 500) === 500);
  ok("an empty setting takes the fallback", parseSpacingMs("", 500) === 500);
  ok("a canonical setting is read", parseSpacingMs("750", 500) === 750);
  ok("zero is accepted, which turns spacing off", parseSpacingMs("0", 500) === 0);
  throws("a leading zero refuses", () => parseSpacingMs("0500", 500), /canonical/);
  throws("a unit suffix refuses", () => parseSpacingMs("500ms", 500), /canonical/);
  throws("a negative setting refuses", () => parseSpacingMs("-5", 500), /canonical/);
  throws("a setting above the ceiling refuses", () => parseSpacingMs("60001", 500), /ceiling/);

  console.log(`wirePacingTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
})().catch((e) => { console.error("FAIL: the battery itself threw", e); process.exitCode = 1; });
