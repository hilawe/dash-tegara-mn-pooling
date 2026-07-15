/**
 * Offline failure-boundary harness for the compound journal (plain `node`, no devnet).
 * Covers the boundaries the independent review named: reserve-before-broadcast crash
 * recovery, cancel-crash recovery, journal shape validation failing closed, BigInt
 * canonicality, the merge behavior of sequential runs, and the lock refusing a second
 * mutator. Run: TEGARA_ENV_PATH is set INSIDE this file before any require, pointing at
 * a temp file, so the real .env.local is never touched.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-cjt-"));
process.env.TEGARA_ENV_PATH = path.join(TMP, "env.local");
// the state dir must pre-exist (R4: writers refuse to create it implicitly)
fs.mkdirSync(`${process.env.TEGARA_ENV_PATH}.state`);

const { ENV_PATH, loadEnv, saveEnv, updateEnvKey } = require("./envStore.cjs");
const journal = require("./compoundJournal.cjs");

const CID = "JDjkLPVLxM52PHbMbjhAQy6vkFtdUmMQymnd4tV7ZaUA";
const MID = "3ytivjwDVivtumhsY8DG6boo6PEztScu6mr3v3QFFHHg";
const R1 = "A5LGb54unHCFrMiSsUS6gazb92vXweRM1NqSbJPJAX37";
const R2 = "4ybNXSB8rH9R4XGSMNSJ3jVBLGfpVC6avoYHZ4jaHjo5";

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const throws = (name, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || "")); }
};
// the helpers write journal keys directly, so they must claim journal ownership
// (a plain saveEnv now restores COMPOUND_* keys from disk, which is itself under test
// in case 16c)
const reset = () => saveEnv({}, { journalOwner: true });
const rawKey = journal.keyFor(CID, MID);
const setRaw = (v) => { const env = loadEnv(); env[rawKey] = v; saveEnv(env, { journalOwner: true }); };

(async () => {
  // 1-2. reserve: persists a pending entry, returns the remainder
  reset();
  const rem = journal.reserve(CID, MID, R1, 30000000n, 86668971n);
  ok("reserve remainder", rem === 56668971n);
  ok("reserve persisted pending", journal.summary(CID, MID).entries[R1].state === "pending");

  // 3. over-ceiling refuses and persists nothing
  throws("over-ceiling refused", () => journal.reserve(CID, MID, R2, 60000000n, 86668971n),
    /exceeds the uncompounded rewards/);
  ok("over-ceiling not persisted", journal.summary(CID, MID).entries[R2] === undefined);

  // 4. duplicate request id refuses
  throws("duplicate id refused", () => journal.reserve(CID, MID, R1, 1n, 86668971n), /already journaled/);

  // 5. confirm
  journal.confirm(CID, MID, R1);
  ok("confirm", journal.summary(CID, MID).entries[R1].state === "confirmed");

  // 6-7. release returns the amount; unknown id returns null
  ok("release amount", journal.release(CID, MID, R1) === 30000000n);
  ok("release unknown", journal.release(CID, MID, R1) === null);
  ok("release freed ceiling", journal.summary(CID, MID).consumedDuffs === 0n);

  // 8. crash between reserve and broadcast: reconcile frees the pending entry
  reset();
  journal.reserve(CID, MID, R1, 10n, 100n);
  let rep = await journal.reconcile(CID, MID, async () => false, () => {}, { minAgeMs: 0 });
  ok("crash-before-broadcast freed", rep[0].action === "freed" && rep[0].duffs === 10n
    && journal.summary(CID, MID).consumedDuffs === 0n);

  // 9. crash between broadcast and confirm: reconcile promotes to confirmed
  reset();
  journal.reserve(CID, MID, R1, 10n, 100n);
  rep = await journal.reconcile(CID, MID, async () => true, () => {}, { minAgeMs: 0 });
  ok("crash-before-confirm promoted", rep[0].action === "confirmed"
    && journal.summary(CID, MID).entries[R1].state === "confirmed");

  // 10. cancel-crash (document deleted, journal not updated): reconcile frees
  rep = await journal.reconcile(CID, MID, async () => false, () => {}, { minAgeMs: 0 });
  ok("cancel-crash freed", rep[0].action === "freed" && journal.summary(CID, MID).consumedDuffs === 0n);

  // 10b. the reconcile age gate (holistic-round F1): a YOUNG missing entry is KEPT
  // (eventual consistency means absence is not yet trustworthy); an aged one frees;
  // an at-less legacy entry reads as old and frees
  reset();
  journal.reserve(CID, MID, R1, 10n, 100n);
  rep = await journal.reconcile(CID, MID, async () => false); // default 15-minute gate
  ok("young missing entry kept", rep[0].action === "kept-young"
    && journal.summary(CID, MID).consumedDuffs === 10n);
  rep = await journal.reconcile(CID, MID, async () => false, () => {},
    { now: Date.now() + 16 * 60 * 1000 }); // beyond the gate
  ok("aged missing entry freed", rep[0].action === "freed"
    && journal.summary(CID, MID).consumedDuffs === 0n);
  setRaw(JSON.stringify({ contractId: CID, memberId: MID,
    entries: { [R1]: { amount: "10", state: "pending" } } })); // legacy, no at stamp
  rep = await journal.reconcile(CID, MID, async () => false);
  ok("legacy at-less entry frees", rep[0].action === "freed");
  setRaw(JSON.stringify({ contractId: CID, memberId: MID,
    entries: { [R1]: { amount: "10", state: "pending", at: -5 } } }));
  throws("malformed at stamp", () => journal.summary(CID, MID), /malformed at stamp/);
  reset();

  // 10c. a malformed gate override fails CLOSED to the default (re-check finding:
  // parseInt reads "0oops" as 0, disabling the gate)
  for (const bad of ["0oops", "1e3", "NaN", "-1"]) {
    reset();
    journal.reserve(CID, MID, R1, 10n, 100n);
    process.env.COMPOUND_RECONCILE_MIN_AGE_MS = bad;
    rep = await journal.reconcile(CID, MID, async () => false);
    ok(`gate override "${bad}" fails closed`, rep[0].action === "kept-young");
    delete process.env.COMPOUND_RECONCILE_MIN_AGE_MS;
  }
  reset();

  // 11-14. shape validation fails closed
  setRaw("{not json");
  throws("corrupt JSON", () => journal.summary(CID, MID), /corrupt JSON/);
  setRaw(JSON.stringify({ contractId: "other", memberId: MID, entries: {} }));
  throws("foreign contract", () => journal.summary(CID, MID), /different contract or member/);
  setRaw(JSON.stringify({ contractId: CID, memberId: MID, entries: { [R1]: { amount: "-5", state: "pending" } } }));
  throws("negative amount", () => journal.summary(CID, MID), /canonical positive integer/);
  setRaw(JSON.stringify({ contractId: CID, memberId: MID, entries: { [R1]: { amount: {}, state: "confirmed" } } }));
  throws("object amount", () => journal.summary(CID, MID), /canonical positive integer/);

  // 15. toBig canonicality (nothing rounds, nothing non-canonical passes)
  throws("toBig decimal", () => journal.toBig("1.5", "x"), /canonical/);
  throws("toBig negative", () => journal.toBig("-3", "x"), /canonical/);
  throws("toBig exponent", () => journal.toBig("1e5", "x"), /canonical/);
  throws("toBig over supply", () => journal.toBig("2100000000000001", "x"), /coin supply/);
  ok("toBig bigint passthrough", journal.toBig(42n, "x") === 42n);

  // 15b. toSafeNumber guards the SDK Number boundary at the largest safe and first
  // unsafe values (re-check finding: the credits conversion, x1000 of duffs, must be
  // checked on the CREDITS value)
  const MAXSAFE = BigInt(Number.MAX_SAFE_INTEGER);
  ok("toSafeNumber at max safe", journal.toSafeNumber(MAXSAFE, "x") === Number.MAX_SAFE_INTEGER);
  throws("toSafeNumber first unsafe", () => journal.toSafeNumber(MAXSAFE + 1n, "x"), /safe Number range/);
  throws("toSafeNumber negative", () => journal.toSafeNumber(-1n, "x"), /negative/);
  throws("toSafeNumber non-bigint", () => journal.toSafeNumber(5, "x"), /must be a BigInt/);

  // 16. sequential runs merge: two reserves both persist, ceiling spans both
  reset();
  journal.reserve(CID, MID, R1, 40n, 100n);
  journal.reserve(CID, MID, R2, 50n, 100n);
  ok("merged entries", journal.summary(CID, MID).consumedDuffs === 90n);
  throws("merged ceiling enforced", () => journal.reserve(CID, MID,
    "5q9PxYWDPkeeUh7RfCf5wDDbTTNKgBotG5cUuQGk4o5w", 11n, 100n), /exceeds/);

  // 16a. payout entries (G4): share the same ceiling as compounds, always confirmed,
  // never touched by reconcile, releasable explicitly
  reset();
  const P1 = journal.newPayoutId();
  ok("payout id shape", /^payout-[0-9a-f]{32}$/.test(P1));
  journal.reserve(CID, MID, R1, 40n, 100n);
  const remP = journal.reservePayout(CID, MID, P1, 50n, 100n);
  ok("payout shares ceiling", remP === 10n && journal.summary(CID, MID).consumedDuffs === 90n);
  throws("payout over ceiling", () => journal.reservePayout(CID, MID, journal.newPayoutId(), 11n, 100n),
    /exceeds the uncompounded rewards/);
  throws("payout duplicate id", () => journal.reservePayout(CID, MID, P1, 1n, 100n), /already journaled/);
  throws("payout bad id", () => journal.reservePayout(CID, MID, "payout-xyz", 1n, 100n), /not a payout id/);
  rep = await journal.reconcile(CID, MID, async () => false, () => {}, { minAgeMs: 0 });
  ok("reconcile skips payouts", rep.every((r) => r.requestId !== P1)
    && journal.summary(CID, MID).entries[P1] !== undefined);
  ok("payout release", journal.release(CID, MID, P1) === 50n);
  setRaw(JSON.stringify({ contractId: CID, memberId: MID,
    entries: { [P1]: { amount: "5", state: "pending", kind: "payout" } } }));
  throws("payout must be confirmed", () => journal.summary(CID, MID), /must be confirmed/);
  setRaw(JSON.stringify({ contractId: CID, memberId: MID,
    entries: { [P1]: { amount: "5", state: "confirmed", kind: "other" } } }));
  throws("payout bad kind", () => journal.summary(CID, MID), /has kind/);
  setRaw(JSON.stringify({ contractId: CID, memberId: MID,
    entries: { [R1]: { amount: "5", state: "confirmed", kind: "payout" } } }));
  throws("payout key pattern", () => journal.summary(CID, MID), /not a payout id/);

  // 16b. exact-shape validation (re-check findings): empty value, extra top-level
  // property, extra entry property all fail closed
  setRaw("");
  throws("empty value", () => journal.summary(CID, MID), /empty value/);
  setRaw(JSON.stringify({ contractId: CID, memberId: MID, entries: {}, extra: 1 }));
  throws("extra top-level prop", () => journal.summary(CID, MID), /unexpected top-level shape/);
  setRaw(JSON.stringify({ contractId: CID, memberId: MID,
    entries: { [R1]: { amount: "5", state: "pending", note: "x" } } }));
  throws("extra entry prop", () => journal.summary(CID, MID), /unexpected shape/);

  // 16c. a FOREIGN saveEnv (stale env loaded before a journal write) must not clobber
  // the journal (re-check finding: envStore restores COMPOUND_* keys from disk)
  reset();
  const staleEnv = loadEnv(); // loaded BEFORE the reserve below
  journal.reserve(CID, MID, R1, 25n, 100n);
  staleEnv.SOME_OTHER_KEY = "value";
  saveEnv(staleEnv); // foreign caller saving its stale copy
  ok("foreign saveEnv preserves journal", journal.summary(CID, MID).consumedDuffs === 25n);
  ok("foreign saveEnv kept its own key", loadEnv().SOME_OTHER_KEY === "value");

  // 16d. AUTOPAY_* is an owned prefix too (G4 review finding): a stale foreign save can
  // neither revert nor erase the toggle, and the owner path updates and deletes it
  const AK = "AUTOPAY_" + journal.suffixFor(CID, MID);
  const staleEnv2 = loadEnv(); // loaded BEFORE the toggle lands
  updateEnvKey(AK, "on");
  saveEnv(staleEnv2); // stale foreign save, no AUTOPAY key in its copy
  ok("foreign saveEnv preserves autopay", loadEnv()[AK] === "on");
  updateEnvKey(AK, "off");
  ok("updateEnvKey overwrites", loadEnv()[AK] === "off");
  updateEnvKey(AK, undefined);
  ok("updateEnvKey deletes", loadEnv()[AK] === undefined);

  // 17. a held lock refuses a second mutator, loudly, and FOREIGN saveEnv participates
  // in the same lock (review TOCTOU finding: with both sides locking, a journal
  // mutation can never commit between a foreign save's reload and write; the interleave
  // is impossible-by-refusal, which is what these two cases pin down)
  // the lock lives inside the shared state dir when one exists (round-3 review: a
  // sibling of the env FILE is container-private under the documented bind mounts)
  const lockAt = fs.existsSync(`${ENV_PATH}.state`)
    ? path.join(`${ENV_PATH}.state`, "env.lock") : `${ENV_PATH}.lock`;
  fs.mkdirSync(lockAt);
  throws("lock refused (journal mutation)", () => journal.reserve(CID, MID,
    "5q9PxYWDPkeeUh7RfCf5wDDbTTNKgBotG5cUuQGk4o5w", 1n, 100n), /holds the env lock/);
  throws("lock refused (foreign saveEnv)", () => saveEnv({ SOME: "thing" }),
    /holds the env lock/);
  fs.rmdirSync(lockAt);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
