/**
 * The nonce window's battery. THE FIRST SEVEN CASES ARE PLATFORM'S OWN, transcribed from the test
 * module of rs-dpp `identity/identity_nonce.rs` at the pinned `37ea011c87`, so the expectations
 * come from the rule's authors rather than from the code under test.
 */
const { nonceUsability } = require("./e2NonceWindow.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed++; console.log(`  PASS: ${name}`); }
  else { failed++; console.log(`FAIL: ${name}`); }
};
const u = (n, raw) => nonceUsability({ transitionNonce: BigInt(n), rawExisting: BigInt(raw) });
const is = (r, verdict, reason) => r.verdict === verdict && r.reason === reason;
const MASK = 0x0FFF000000000000n;

// ---- Platform's test vectors ----
ok("platform: the tip itself is refused as already present at the tip", is(u(50, 50), "never", "at-tip"));
ok("platform: 25 below the tip is refused as too far in the past", is(u(25, 50), "never", "too-far-in-past"));
ok("platform: 25 above the tip is refused as too far in the future, which is not permanent",
  is(u(75, 50), "not-yet", "too-far-in-future"));
ok("platform: 24 below a tip with no skipped nonces is refused as already present in the past",
  is(u(26, 50), "never", "used"));
ok("platform: 24 below a tip whose mask does not mark it is refused the same way",
  is(u(26, 50n | MASK), "never", "used"));
ok("platform: 20 below a tip whose mask marks it as skipped is accepted",
  is(u(30, 50n | MASK), "executable", "skipped"));
ok("platform: 24 above the tip is accepted", is(u(74, 50n | MASK), "executable", "above-tip"));

// ---- the edges and the live case ----
ok("one above the tip is accepted", is(u(51, 50), "executable", "above-tip"));
ok("24 above a tip with no mask is accepted", is(u(74, 50), "executable", "above-tip"));
ok("the bit for position 24 (the top bit) marks that nonce skipped",
  is(u(26, 50n | (1n << 63n)), "executable", "skipped"));
ok("position 1 is the lowest mask bit", is(u(49, 50n | (1n << 40n)), "executable", "skipped")
  && is(u(48, 50n | (1n << 40n)), "never", "used"));
ok("the live reservation of 2026-09-23, nonce 480 against a tip of 623, can never execute",
  is(u(480, 623), "never", "too-far-in-past"));
ok("the tip reported is the stored value's low 40 bits", u(30, 50n | MASK).tip === 50n);

// ---- inputs that are not what the rule reads ----
const throws = (name, fn) => { try { fn(); ok(name, false); } catch (e) { ok(name, /e2NonceWindow/.test(e.message)); } };
throws("a number, not a bigint, is refused", () => nonceUsability({ transitionNonce: 30, rawExisting: 50n }));
throws("a zero transition nonce is refused", () => nonceUsability({ transitionNonce: 0n, rawExisting: 50n }));
throws("a masked tip passed where the raw value belongs is still a bigint, but a negative one is refused",
  () => nonceUsability({ transitionNonce: 30n, rawExisting: -1n }));
throws("a missing stored value is refused rather than read as zero", () => nonceUsability({ transitionNonce: 30n }));

console.log(`\ne2NonceWindowTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
