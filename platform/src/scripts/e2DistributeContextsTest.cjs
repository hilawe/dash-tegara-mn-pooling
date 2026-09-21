// The per-epoch context module's battery (the F3 refactor, milestone 2).
//
// THE CENTRAL CASE IS TWO EPOCHS WITH DIFFERENT FIGURES, and it is a POSITIVE control on
// purpose. The defect this module exists to remove is one figures object held for the length of
// a run, so reintroducing a single shared value has to break a case that must PASS. A battery
// where the old shape only trips a negative case would have passed before the refactor too.
const { buildContexts, validateFigures, validateEpochList, parseDeclaredFigures } = require("./e2DistributeContexts.cjs");
let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error("FAIL:", name, "(no error)"); }
  catch (e) { ok(name, re.test(String(e.message))); }
};

const POOL = "5a".repeat(32);
const FUNDER_A = "7d".repeat(32);
const FUNDER_B = "2c".repeat(32);
const INCOME = "9e".repeat(32);
const CEILING = require("./entitlementCalc.cjs").SCHEMA_CREDIT_CEILING;

// the identifier derivation's injected pieces. generateId RECORDS what it was asked for and
// answers a value that depends on every argument, so a context deriving another epoch's identity
// is visible in the result rather than only in a call log.
// The generator's real contract is (type, ownerId, contractId, entropyBytes) answering a base58
// string that decodes to 32 bytes, which is what the shared derivation checks. The fake answers
// one, derived from EVERY argument, so a context deriving another epoch's identity shows up as a
// different identifier rather than only in a call log.
const bs58 = require("bs58");
const mkIdentifiers = () => {
  const asked = [];
  return { asked, identifiers: {
    generateId: (type, ownerId, contractId, entropy) => {
      asked.push({ type, entropy: Buffer.from(entropy).toString("hex").slice(0, 16) });
      const h = require("crypto").createHash("sha256")
        .update(String(type)).update(String(ownerId)).update(String(contractId)).update(Buffer.from(entropy))
        .digest();
      return bs58.default ? bs58.default.encode(h) : bs58.encode(h);
    },
    ownerId: "OWNER", contractId: "CONTRACT",
  } };
};
const owners = [
  { funderHex: FUNDER_A, bps: 6000, recipientB58: "FunderAb58" },
  { funderHex: FUNDER_B, bps: 4000, recipientB58: "FunderBb58" },
];
const allocation = [
  { recipientId: FUNDER_A, bps: 6000 },
  { recipientId: FUNDER_B, bps: 4000 },
];
const figures = (gross, fee, over = {}) => ({ grossCredits: String(gross), feeCredits: String(fee),
  allocationHash: "ee".repeat(32), memberCount: 2, calcVersion: 1, ...over });
const build = (over = {}) => {
  const { identifiers } = mkIdentifiers();
  return buildContexts({ poolId: POOL, configuredStart: 0, allocation, owners,
    incomeIdentity: INCOME, encodingCeiling: CEILING, identifiers,
    epochs: [{ number: 0, figures: figures(1000000, 0) }, { number: 1, figures: figures(3000000, 500) }],
    ...over });
};

// ---- the figure check ----
ok("a well-formed figures object passes", validateFigures(figures(10, 1), 0).memberCount === 2);
ok("a null allocation hash is allowed, since a bootstrap run fills it from the proved resolution",
  validateFigures(figures(10, 1, { allocationHash: null }), 0).allocationHash === null);
throws("a missing figures object refuses", () => validateFigures(null, 3), /epoch 3 carries no figures/);
throws("a non-integer gross refuses", () => validateFigures(figures("1e6", 0), 0), /grossCredits is/);
throws("a negative fee refuses", () => validateFigures({ ...figures(10, 1), feeCredits: "-1" }, 0), /feeCredits is/);
throws("a fee above the gross refuses", () => validateFigures(figures(10, 11), 4), /fee 11 exceeds its gross 10/);
throws("a fractional member count refuses", () => validateFigures(figures(10, 1, { memberCount: 1.5 }), 0), /memberCount is/);
throws("a short allocation hash refuses", () => validateFigures(figures(10, 1, { allocationHash: "ee" }), 0), /neither null nor 64 lowercase hex/);

// ---- the run list ----
ok("a consecutive run from its base passes",
  JSON.stringify(validateEpochList([{ number: 4 }, { number: 5 }], 4)) === JSON.stringify([4, 5]));
throws("an empty run refuses", () => validateEpochList([], 0), /covers no epochs/);
throws("a GAP refuses, because the carry recursion cannot answer across one",
  () => validateEpochList([{ number: 0 }, { number: 2 }], 0), /not consecutive/);
throws("a REPEAT refuses for the same reason",
  () => validateEpochList([{ number: 0 }, { number: 0 }], 0), /not consecutive/);
throws("a descending run refuses",
  () => validateEpochList([{ number: 1 }, { number: 0 }], 1), /not consecutive/);
throws("a run beginning above its configured start refuses",
  () => validateEpochList([{ number: 3 }, { number: 4 }], 0), /begins at epoch 3 while the configured start is 0/);
throws("a run with no base refuses", () => validateEpochList([{ number: 0 }], null), /has no base/);

// ---- THE CENTRAL POSITIVE CONTROL ----
{
  const c = build();
  const e0 = c.contextFor(0);
  const e1 = c.contextFor(1);
  ok("both epochs are built", JSON.stringify(c.epochNumbers) === JSON.stringify([0, 1]));
  // The two epochs carry DIFFERENT figures. A run holding one shared figures object would give
  // both contexts the same numbers here, and this assertion is what notices.
  ok("each epoch carries ITS OWN figures, not the run's first",
    e0.figures.grossCredits === "1000000" && e1.figures.grossCredits === "3000000"
      && e0.figures.feeCredits === "0" && e1.figures.feeCredits === "500");
  // ... and the rows follow the figures, which is the consequence that actually reaches a member
  const sum = (ctx) => ctx.rows.reduce((t, r) => t + BigInt(r.amountCredits), 0n);
  ok("each epoch's row amounts follow its own distributable credits",
    sum(e0) === 1000000n && sum(e1) === 2999500n);
  ok("the two epochs' row amounts differ, so one shared row set could not serve both",
    JSON.stringify(e0.rows.map((r) => r.amountCredits)) !== JSON.stringify(e1.rows.map((r) => r.amountCredits)));
  // the document identities are per epoch too, which is the other half of the shared-value defect
  ok("each epoch derives its OWN accrual identifiers",
    e0.rows[0].accrualId !== e1.rows[0].accrualId && e0.rows[1].accrualId !== e1.rows[1].accrualId);
  ok("a context's identifier helper is bound to its own epoch",
    e0.docIdFor("platformAccrual", FUNDER_A).hex === e0.rows[0].accrualId
      && e1.docIdFor("platformAccrual", FUNDER_A).hex === e1.rows[0].accrualId);
  ok("the row lookup answers that epoch's own row",
    e0.rowFor(e0.rows[0].accrualId).amountCredits === e0.rows[0].amountCredits
      && e1.rowFor(e0.rows[0].accrualId) === undefined);
  ok("each row carries the owner display fields the driver attaches",
    e0.rows[0].recipientB58 === "FunderAb58" && e0.rows[0].bps === 6000
      && e0.rows[1].recipientB58 === "FunderBb58" && e0.rows[1].bps === 4000);
  ok("a context is frozen, so nothing downstream can edit an epoch's figures in place",
    Object.isFrozen(e0) && Object.isFrozen(e0.figures) && Object.isFrozen(e0.rows) && Object.isFrozen(e0.rows[0]));
}

// ---- THE CARRY THREADS BETWEEN EPOCHS, which is why they are built together ----
{
  // a tiny first epoch leaves a remainder too small to pay, and that remainder must appear in
  // the second epoch's carry-in. Building one context at a time would give epoch 1 a zero
  // carry-in, which is correct only for the first epoch of a run.
  const { identifiers } = mkIdentifiers();
  const c = buildContexts({ poolId: POOL, configuredStart: 0, allocation, owners,
    incomeIdentity: INCOME, encodingCeiling: CEILING, identifiers,
    epochs: [{ number: 0, figures: figures(3, 0) }, { number: 1, figures: figures(1000000, 0) }] });
  const e0 = c.contextFor(0);
  const e1 = c.contextFor(1);
  // three credits split 6000/4000 gives each recipient one credit, which is below the minimum a
  // transfer can carry, so epoch 0 owes them and cannot pay them
  ok("the first epoch's rows are owed but not payable at that size",
    e0.rows.every((r) => r.amountCredits === "1" && r.payable === false));
  // the carried amount is asserted EXACTLY, and against the second epoch's own share plus it,
  // because "something carried" would pass over an amount that threaded the wrong number
  ok("the second epoch's first row is its own share plus exactly the one credit carried in",
    e1.rows[0].carryInCredits === "1" && e1.rows[0].amountCredits === "600001");
  ok("the second epoch's second row likewise",
    e1.rows[1].carryInCredits === "1" && e1.rows[1].amountCredits === "400001");
  ok("and both are payable once the carry lifts them over the minimum",
    e1.rows.every((r) => r.payable === true));
  ok("the first epoch's rows carry in nothing, being the run's base",
    c.contextFor(0).rows.every((r) => r.carryInCredits === undefined));
}

// ---- the declared figures ----
{
  const base = figures(1000000, 0);
  ok("no declaration is a one-epoch run", parseDeclaredFigures("", 0, base).length === 0
    && parseDeclaredFigures(undefined, 0, base).length === 0);
  const d = parseDeclaredFigures('{"1":{"grossCredits":"3000000","feeCredits":"500"}}', 0, base);
  ok("a declaration answers the epoch above the run's first", d.length === 1 && d[0].number === 1);
  // THE TYPE IS PINNED, not just the value. The journal's header record requires an integer, the
  // bootstrap path supplies one, and a declaration left as JSON text writes a header the journal
  // refuses. That is where the first live two-epoch run stopped.
  ok("the declared amounts are NUMBERS, as the journal's header record requires",
    typeof d[0].figures.grossCredits === "number" && d[0].figures.feeCredits === 500
      && d[0].figures.grossCredits === 3000000);
  ok("the pool's own members are inherited, never taken from the declaration",
    d[0].figures.memberCount === base.memberCount && d[0].figures.calcVersion === base.calcVersion
      && d[0].figures.allocationHash === base.allocationHash);
  const ignored = parseDeclaredFigures('{"1":{"grossCredits":"5","feeCredits":"0","memberCount":99,"allocationHash":"ff"}}', 0, base);
  ok("a declaration restating the pool's members is ignored rather than honoured",
    ignored[0].figures.memberCount === base.memberCount && ignored[0].figures.allocationHash === base.allocationHash);
  ok("two declared epochs continue consecutively",
    parseDeclaredFigures('{"1":{"grossCredits":"5","feeCredits":"0"},"2":{"grossCredits":"6","feeCredits":"0"}}', 0, base)
      .map((e) => e.number).join(",") === "1,2");
  throws("a gapped declaration refuses",
    () => parseDeclaredFigures('{"2":{"grossCredits":"5","feeCredits":"0"}}', 0, base), /do not continue consecutively/);
  throws("a declaration at or below the run's first epoch refuses",
    () => parseDeclaredFigures('{"0":{"grossCredits":"5","feeCredits":"0"}}', 0, base), /at or below the run's first epoch/);
  throws("a non-canonical epoch key refuses",
    () => parseDeclaredFigures('{"01":{"grossCredits":"5","feeCredits":"0"}}', 0, base), /not a canonical epoch number/);
  throws("malformed JSON refuses", () => parseDeclaredFigures("{", 0, base), /not JSON/);
  throws("a JSON array refuses", () => parseDeclaredFigures("[]", 0, base), /keyed by epoch number/);
  throws("a non-integer declared amount refuses",
    () => parseDeclaredFigures('{"1":{"grossCredits":"1e6","feeCredits":"0"}}', 0, base), /not a canonical nonnegative integer/);
  throws("an amount above the schema ceiling refuses",
    () => parseDeclaredFigures('{"1":{"grossCredits":"9007199254740992","feeCredits":"0"}}', 0, base), /above the schema's credit ceiling/);
}

// ---- refusals ----
{
  const c = build();
  throws("an epoch outside the run refuses rather than answering",
    () => c.contextFor(2), /outside this run \(0,1\)/);
  throws("a negative epoch refuses too", () => c.contextFor(-1), /outside this run/);
  ok("has reports membership without throwing", c.has(0) === true && c.has(2) === false);
}
throws("a pool identifier that is not 64 lowercase hex refuses",
  () => build({ poolId: "5a" }), /not 64 lowercase hex/);
throws("a missing identifier derivation refuses",
  () => build({ identifiers: { ownerId: "O", contractId: "C" } }), /needs identifiers.generateId/);
throws("a missing owner list refuses", () => build({ owners: [] }), /needs the owner list/);
throws("a recipient absent from the owner list refuses rather than being dropped",
  () => build({ owners: [owners[0]] }), /which is not in the owner list/);

// ---- the run is rebuilt per call, so one caller cannot change another's rows ----
{
  const c = build();
  const first = c.contextFor(0).rows[0];
  ok("a row is frozen against in-place edits",
    (() => { try { first.amountCredits = "999"; } catch (_) { /* strict mode throws */ } return first.amountCredits !== "999"; })());
}

console.log(`e2DistributeContextsTest: ${passed} passed, ${failed} failed`);
process.exitCode = failed ? 1 : 0;
