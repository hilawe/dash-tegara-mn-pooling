/**
 * The crash-point harness for the matcher's settlement journal (review finding F1,
 * 2026-07-11). A mocked ledger runs the settlement driver, a crash is injected after
 * EVERY persisted phase boundary (and between the ledger write and the persist), the
 * driver restarts from the persisted journal, and the end state must always be: exit and
 * join settled, exactly one share in the pool, owned by the joiner, same bps and
 * contribution. Offline, no SDK, no devnet.
 *
 * Run: node src/scripts/matchJournalTest.cjs   (exits non-zero on the first failure)
 */
// hermetic: save() now writes through the locked owner path, so the env target must
// be a temp file, never the real .env.local (holistic-round F2 side effect)
process.env.TEGARA_ENV_PATH = require("path").join(
  require("fs").mkdtempSync(require("path").join(require("os").tmpdir(), "tegara-jt-")), "env.local");
// the state dir must pre-exist (R4: writers refuse to create it implicitly)
require("fs").mkdirSync(`${process.env.TEGARA_ENV_PATH}.state`);
const assert = require("assert");
const match = require("./matchJournal.cjs");

let passed = 0;
const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const runAll = async () => {
  for (const { name, fn } of tests) {
    try { await fn(); passed++; console.log(`  ok  ${name}`); }
    catch (e) { console.error(`FAIL  ${name}\n      ${e.message}`); process.exit(1); }
  }
  console.log(`\nall ${passed} cases passed (crash matrix inside case 2)`);
};

const SNAPSHOT = { shareBps: 6000, contributionDuffs: 600000000 };
const freshSettlement = () => ({
  poolId: "pool1", exitId: "exit1", joinId: "join1",
  leaverId: "leaver", joinerId: "joiner", amountDuffs: 600000000,
  share: { ...SNAPSHOT }, phase: "prepared",
});

/** A mocked ledger plus a persistence layer that can crash on the Nth operation. */
const makeWorld = () => {
  const world = {
    statuses: { exit1: "pending", join1: "pending" },
    shares: { leaver: { ...SNAPSHOT }, joiner: null }, // owner -> share or null
    persisted: null, // the journal as last persisted
    opCount: 0,
    crashAt: Infinity,
  };
  const maybeCrash = () => { if (++world.opCount >= world.crashAt) throw new Error("CRASH"); };
  world.opsFor = (state) => ({
    setStatus: async (reqId, ownerId, from, to) => {
      const cur = world.statuses[reqId];
      if (cur === to) return; // idempotent, mirrors the matcher
      if (cur !== from) throw new Error(`compare-and-set refused: ${reqId} is ${cur}, wanted ${from}`);
      maybeCrash();
      world.statuses[reqId] = to;
    },
    leaverShareExists: async () => world.shares.leaver !== null,
    joinerShareExists: async () => world.shares.joiner !== null,
    deleteLeaverShare: async () => { maybeCrash(); world.shares.leaver = null; },
    recreateJoinerShare: async (snap) => { maybeCrash(); world.shares.joiner = { ...snap }; },
    persist: async () => { maybeCrash(); world.persisted = JSON.parse(JSON.stringify(state)); },
  });
  return world;
};

const assertSettled = (world) => {
  assert.equal(world.statuses.exit1, "settled");
  assert.equal(world.statuses.join1, "settled");
  assert.equal(world.shares.leaver, null, "leaver's share must be gone");
  assert.deepEqual(world.shares.joiner, SNAPSHOT, "joiner must hold the snapshot's share");
};

test("the happy path settles in one run", async () => {
  const world = makeWorld();
  const state = { version: 1, settlement: freshSettlement() };
  world.persisted = JSON.parse(JSON.stringify(state));
  await match.driveSettlement(state, world.opsFor(state));
  assertSettled(world);
  assert.equal(state.settlement.phase, "settled");
});

// crash after every ledger/persist operation, then restart from the PERSISTED journal
// (what a real restart reads), on the SAME mocked ledger
test("a crash at every operation still converges after restart", async () => {
  for (let crashAt = 1; crashAt <= 12; crashAt++) {
    const world = makeWorld();
    const state = { version: 1, settlement: freshSettlement() };
    world.persisted = JSON.parse(JSON.stringify(state));
    world.crashAt = crashAt;
    let crashed = false;
    try {
      await match.driveSettlement(state, world.opsFor(state));
    } catch (e) {
      if (e.message !== "CRASH") throw e;
      crashed = true;
    }
    // restart: no more crashes; resume from what was PERSISTED, not in-memory state
    world.crashAt = Infinity;
    const resumed = JSON.parse(JSON.stringify(world.persisted));
    match.validate(resumed);
    await match.driveSettlement(resumed, world.opsFor(resumed));
    assertSettled(world);
    assert.equal(resumed.settlement.phase, "settled");
    if (!crashed) break; // crashAt beyond the total operation count; matrix exhausted
  }
});

test("re-driving a fully settled journal is a no-op", async () => {
  const world = makeWorld();
  const state = { version: 1, settlement: freshSettlement() };
  world.persisted = JSON.parse(JSON.stringify(state));
  await match.driveSettlement(state, world.opsFor(state));
  await match.driveSettlement(state, world.opsFor(state)); // again
  assertSettled(world);
});

test("clearSettlement empties the journal", () => {
  const state = { version: 1, settlement: freshSettlement() };
  match.clearSettlement(state);
  assert.equal(state.settlement, null);
  match.validate(state);
});

test("a malformed settlement is refused", () => {
  const bad = { version: 1, settlement: { ...freshSettlement(), share: { shareBps: 0 } } };
  assert.throws(() => match.validate(bad), /malformed/);
  const badPhase = { version: 1, settlement: { ...freshSettlement(), phase: "nonsense" } };
  assert.throws(() => match.validate(badPhase), /not recognized/);
});

test("save/load round-trips through an env map", () => {
  const env = {};
  const state = { version: 1, settlement: freshSettlement() };
  match.save(env, state);
  const back = match.load(env);
  assert.deepEqual(back, state);
  assert.equal(match.load({}).settlement, null);
});

runAll();
