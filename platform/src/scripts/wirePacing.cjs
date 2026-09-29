"use strict";
// Spaces the STARTS of wire calls at least minSpacingMs apart, so a long walk of requests stays
// under a gateway's per-minute limit. dashmate's gateway defaults to 150 requests per minute
// (platform.gateway.rateLimiter, read on the testnet evonode 2026-09-27), and the audit's epoch
// walk on testnet is about 385 interval requests (epoch 19217 in steps of 50), so without spacing
// the limiter refuses the walk partway and every read after it in the same minute.
//
// WHAT IT CHANGES: only WHEN a call starts. Arguments and answers pass through untouched, a
// rejection propagates to its own caller, and one rejection does not hold up the next call, whether
// it came from the wrapped function or from the wait before it. One
// pacer shared by several wrapped functions spaces them together, so the total rate is bounded,
// not each function's.
//
// WHAT IT DOES NOT ESTABLISH: that the gateway will serve every request. Other clients share the
// limit on a public node, and the limit is the operator's setting. A refused read still reaches
// the audit as a refused read, and the audit's own labels say what was and was not served.

const MAX_SPACING_MS = 60000;

function parseSpacingMs(raw, fallback) {
  if (raw === undefined || raw === "") return fallback;
  if (typeof raw !== "string" || !/^(0|[1-9][0-9]{0,4})$/.test(raw)) {
    throw new Error(`the wire spacing ${JSON.stringify(raw)} is not a canonical whole number of milliseconds`);
  }
  const n = Number(raw);
  if (n > MAX_SPACING_MS) throw new Error(`the wire spacing ${n} ms is above the ${MAX_SPACING_MS} ms ceiling`);
  return n;
}

function createPacer({ minSpacingMs, now = Date.now, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
  if (!Number.isSafeInteger(minSpacingMs) || minSpacingMs < 0 || minSpacingMs > MAX_SPACING_MS) {
    throw new Error(`minSpacingMs must be a whole number from 0 to ${MAX_SPACING_MS}; got ${JSON.stringify(minSpacingMs)}`);
  }
  let nextStart = -Infinity;
  let queue = Promise.resolve();
  const pace = (fn) => (...args) => {
    const turn = queue.then(async () => {
      const wait = nextStart - now();
      if (wait > 0) await sleep(wait);
      nextStart = now() + minSpacingMs;
    });
    // a failed wait rejects ITS OWN call only; the queue recovers so later calls still start
    queue = turn.catch(() => {});
    return turn.then(() => fn(...args));
  };
  return pace;
}

module.exports = { createPacer, parseSpacingMs, MAX_SPACING_MS };
