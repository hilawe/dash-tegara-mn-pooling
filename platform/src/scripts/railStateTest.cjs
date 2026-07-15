/**
 * The mocked resume harness over the credit-rail's journal-state matrix (Track C review
 * follow-up, 2026-07-10). Drives railState.cjs through every phase, every legacy-key
 * migration shape, and every resume decision OFFLINE; no SDK, no network, no devnet.
 *
 * Run: node src/scripts/railStateTest.cjs   (exits non-zero on the first failure)
 */
// hermetic: save() now writes through the locked owner path, so the env target must
// be a temp file, never the real .env.local (holistic-round F2 side effect)
process.env.TEGARA_ENV_PATH = require("path").join(
  require("fs").mkdtempSync(require("path").join(require("os").tmpdir(), "tegara-jt-")), "env.local");
// the state dir must pre-exist (R4: writers refuse to create it implicitly)
require("fs").mkdirSync(`${process.env.TEGARA_ENV_PATH}.state`);
const assert = require("assert");
const rail = require("./railState.cjs");

let passed = 0;
const test = (name, fn) => {
  try { fn(); passed++; console.log(`  ok  ${name}`); }
  catch (e) { console.error(`FAIL  ${name}\n      ${e.message}`); process.exit(1); }
};
const throwsWith = (fn, re) => {
  try { fn(); } catch (e) { assert.match(e.message, re); return; }
  assert.fail("expected a throw");
};

// building blocks for the matrix
const slot = (satoshis = 130580357) => ({
  wif: "cV1x000000000000000000000000000000000000000000000000", txid: "aa".repeat(32),
  txHex: "00", outputIndex: 0, address: "yTest", satoshis,
});
const entry = (over = {}) => ({
  label: "funder1", identityId: "id1", satoshis: 100, outputIndex: 1,
  oneTimeKeyWif: "cW", beforeCredits: "0", credited: false, transitionHash: null, ...over,
});
const epoch = (entries, accrualsDone = false) => ({
  txid: "bb".repeat(32), txHex: "00", poolId: "pool1",
  remainder: entries.filter((e) => e.label !== "operator").reduce((s, e) => s + e.satoshis, 0),
  epochHeight: 264, observation: null, accrualsDone, entries,
});
// an epoch provably spending the slot: the raw tx hex contains the reversed slot txid
// followed by the little-endian output index (see railState.epochSpendsSlot)
const linkedEpoch = (sl, entries, accrualsDone = false) => ({
  ...epoch(entries, accrualsDone),
  txHex: "ff" + Buffer.from(sl.txid, "hex").reverse().toString("hex") + "00000000" + "ff",
  observation: { amountDuffs: sl.satoshis },
});
const v2 = (over = {}) => ({ version: 2, slot: null, epoch: null, consumed: [], ...over });

console.log("phase derivation and resume decisions");
test("empty env loads idle and starts fresh", () => {
  const s = rail.load({});
  assert.equal(rail.derivePhase(s), "idle");
  assert.equal(rail.resumeAction(s, null).action, "fresh");
  assert.equal(rail.resumeAction(s, 12345).action, "fresh");
});
test("slot only, matching observed amount, resumes the slot", () => {
  const s = v2({ slot: slot(500) });
  assert.equal(rail.derivePhase(s), "slot-funded");
  assert.equal(rail.resumeAction(s, 500).action, "resume-slot");
});
test("slot only, different observed amount, is refused", () => {
  const s = v2({ slot: slot(500) });
  assert.equal(rail.resumeAction(s, 999).action, "refuse-slot-mismatch");
});
test("slot only, wallet-funded run, is refused (orphan-slot hazard)", () => {
  const s = v2({ slot: slot(500) });
  const d = rail.resumeAction(s, null);
  assert.equal(d.action, "refuse-orphan-slot");
  assert.match(d.reason, /non-wallet key/);
});
test("open epoch with uncredited entries resumes the epoch", () => {
  const s = v2({ epoch: epoch([entry(), entry({ label: "funder2", credited: true })]) });
  assert.equal(rail.derivePhase(s), "epoch-open");
  const d = rail.resumeAction(s, null);
  assert.equal(d.action, "resume-epoch");
  assert.match(d.reason, /1 entries uncredited/);
});
test("epoch with every entry credited but accruals pending still resumes", () => {
  const s = v2({ epoch: epoch([entry({ credited: true })], false) });
  assert.equal(rail.derivePhase(s), "epoch-open");
  assert.match(rail.resumeAction(s, null).reason, /accruals pending/);
});
test("epoch fully credited with accruals done verifies before clearing", () => {
  const s = v2({ epoch: epoch([entry({ credited: true })], true) });
  assert.equal(rail.derivePhase(s), "epoch-settled");
  assert.equal(rail.resumeAction(s, null).action, "verify-settled");
});
test("an open epoch outranks a slot record (epoch resume, not slot resume)", () => {
  const s = v2({ slot: slot(), epoch: epoch([entry()]) });
  assert.equal(rail.resumeAction(s, 130580357).action, "resume-epoch");
});

console.log("legacy-key migration");
test("legacy RAIL_CONSUMED alone migrates and stays idle", () => {
  const env = { RAIL_CONSUMED: JSON.stringify(["aa:0"]) };
  const s = rail.load(env);
  assert.deepEqual(s.consumed, ["aa:0"]);
  assert.equal(rail.resumeAction(s, null).action, "fresh");
});
test("legacy RAIL_SLOT migrates into the slot phase", () => {
  const env = { RAIL_SLOT: JSON.stringify(slot(777)) };
  const s = rail.load(env);
  assert.equal(rail.derivePhase(s), "slot-funded");
  assert.equal(rail.resumeAction(s, 777).action, "resume-slot");
});
test("legacy RAIL_JOURNAL migrates into an open epoch", () => {
  const env = { RAIL_JOURNAL: JSON.stringify(epoch([entry()])) };
  const s = rail.load(env);
  assert.equal(rail.resumeAction(s, null).action, "resume-epoch");
});
test("legacy slot plus an UNRELATED journal refuses to migrate (F2)", () => {
  const env = {
    RAIL_SLOT: JSON.stringify(slot()),
    RAIL_JOURNAL: JSON.stringify(epoch([entry()])), // no observation, does not spend the slot
  };
  throwsWith(() => rail.load(env), /not provably the same Track C epoch/);
  // both legacy records are retained untouched for manual recovery
  assert.ok(env.RAIL_SLOT && env.RAIL_JOURNAL);
});
test("legacy slot plus a LINKED Track C journal migrates and drops legacy keys on save", () => {
  const sl = slot();
  const env = {
    OTHER: "kept",
    RAIL_SLOT: JSON.stringify(sl),
    RAIL_JOURNAL: JSON.stringify(linkedEpoch(sl, [entry()])),
    RAIL_CONSUMED: JSON.stringify(["aa:0", "bb:1"]),
  };
  const s = rail.load(env);
  rail.save(env, s);
  assert.equal(env.RAIL_SLOT, undefined);
  assert.equal(env.RAIL_JOURNAL, undefined);
  assert.equal(env.RAIL_CONSUMED, undefined);
  assert.equal(env.OTHER, "kept");
  const back = rail.load(env);
  assert.deepEqual(back.consumed, ["aa:0", "bb:1"]);
  assert.equal(rail.derivePhase(back), "epoch-open");
});
test("RAIL_STATE outranks stale legacy keys once present", () => {
  const env = {};
  rail.save(env, v2({ consumed: ["new:0"] }));
  env.RAIL_CONSUMED = JSON.stringify(["stale:0"]); // must be ignored
  assert.deepEqual(rail.load(env).consumed, ["new:0"]);
});

console.log("persistence round-trips");
test("save/load round-trips the full record including transition hashes", () => {
  const env = {};
  const s = v2({ epoch: epoch([entry({ credited: true, transitionHash: "cd".repeat(32) })]) });
  rail.save(env, s);
  const back = rail.load(env);
  assert.equal(back.epoch.entries[0].transitionHash, "cd".repeat(32));
  assert.equal(back.phase, "epoch-open");
  assert.deepEqual(back, JSON.parse(JSON.stringify(s))); // save stamped s.phase too
});
test("clearEpoch drops a LINKED epoch and its slot but keeps the consumed list", () => {
  const sl = slot();
  const s = v2({ slot: sl, epoch: linkedEpoch(sl, [entry({ credited: true })], true), consumed: ["aa:0"] });
  rail.clearEpoch(s);
  assert.equal(s.epoch, null);
  assert.equal(s.slot, null);
  assert.deepEqual(s.consumed, ["aa:0"]);
  assert.equal(rail.resumeAction(s, null).action, "fresh");
});
test("clearEpoch KEEPS an unrelated slot (its key must survive; F2)", () => {
  const s = v2({ slot: slot(), epoch: epoch([entry({ credited: true })], true) });
  rail.clearEpoch(s);
  assert.equal(s.epoch, null);
  assert.ok(s.slot, "the slot record must survive an unrelated epoch clear");
  assert.equal(rail.derivePhase(s), "slot-funded");
});

console.log("corruption refusal");
test("unknown version is refused", () => {
  throwsWith(() => rail.load({ RAIL_STATE: JSON.stringify({ version: 3, consumed: [] }) }), /version 3/);
});
test("epoch with no entries is refused", () => {
  throwsWith(() => rail.load({ RAIL_STATE: JSON.stringify(v2({ epoch: epoch([]) })) }), /no entries/);
});
test("malformed entry is refused", () => {
  const bad = v2({ epoch: epoch([{ label: "x" }]) });
  throwsWith(() => rail.load({ RAIL_STATE: JSON.stringify(bad) }), /malformed/);
});
test("malformed slot is refused", () => {
  throwsWith(() => rail.load({ RAIL_STATE: JSON.stringify(v2({ slot: { txid: "aa" } })) }), /slot is malformed/);
});
test("a stored phase that contradicts the content is refused", () => {
  const s = v2({ epoch: epoch([entry()]) });
  s.phase = "idle"; // lies about the open epoch
  throwsWith(() => rail.load({ RAIL_STATE: JSON.stringify(s) }), /does not match its content/);
});
test("a slot missing its outputIndex is refused (G5)", () => {
  const bad = slot(); delete bad.outputIndex;
  throwsWith(() => rail.load({ RAIL_STATE: JSON.stringify(v2({ slot: bad })) }), /slot is malformed/);
});
test("an epoch whose funder entries disagree with the remainder is refused (F10)", () => {
  const ep = epoch([entry()]); ep.remainder = 999;
  throwsWith(() => rail.load({ RAIL_STATE: JSON.stringify(v2({ epoch: ep })) }), /remainder says/);
});
test("an epoch repeating a credit-output index is refused (F10)", () => {
  const ep = epoch([entry(), entry({ label: "funder2" })]); // both outputIndex 1
  throwsWith(() => rail.load({ RAIL_STATE: JSON.stringify(v2({ epoch: ep })) }), /repeat a credit-output index/);
});
test("non-list consumed is refused", () => {
  throwsWith(() => rail.load({ RAIL_STATE: JSON.stringify({ version: 2, consumed: "aa:0" }) }), /not a list/);
});

console.log("observation split math (F4)");
const { expectedSlotAmount } = require("./observation.cjs");
test("the amount-weighted floor is exact where Number math is off by one (F4)", () => {
  // live-found regression vector: naive Math.floor((mn*share)/coll) returns 184467800
  const { floor } = expectedSlotAmount({
    mnRewardDuffs: 307446335, operatorRewardBps: 0,
    shareAmountDuffs: 60000000000, collateralDuffs: 100000000000,
  });
  assert.equal(floor, 184467801);
});

console.log(`\nall ${passed} cases passed`);
