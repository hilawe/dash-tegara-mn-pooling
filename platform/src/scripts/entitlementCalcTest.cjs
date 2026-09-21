/**
 * entitlementCalc's battery. The module is pure, so this drives it directly.
 *
 * THE EXPECTATIONS COME FROM THE SPECIFICATION AND FROM ARITHMETIC DONE BY HAND, never
 * from the module. The multi-epoch scenario below is the build spec's own third carry
 * vector ("owed = 50000 in two consecutive epochs: epoch N effective = 50000, carried;
 * epoch N+1 effective = 100000, payable"), driven through the real row source rather
 * than through epochCarry directly, so this suite binds the COMPOSITION that suite
 * cannot see.
 *
 * THE MUTATION LIST WAS WRITTEN BEFORE THESE TESTS, per the playbook rule, and
 * tools/entitlement_calc_mutation_check.sh runs it. Three of its cases aim at the
 * OBSERVATION rather than at the behaviour: B1 leaves every amount correct while
 * emitting a zero carry member the migration rule reads as a different calculation era,
 * B7 returns correct rows that a later caller can have changed underneath it, and B9
 * reports the carry-OUT where the carry-IN belongs, which agrees with the carry-in on
 * every epoch that defers nothing.
 */
"use strict";

const path = require("path");
const { pathToFileURL } = require("url");
const { buildV11 } = require("./contractV11.cjs");
const { SCHEMA_CREDIT_CEILING, readAllocationBps, splitOwed,
  buildCarryCapableEntitlements } = require("./entitlementCalc.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) { passed++; } else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
/** an unexpected throw is a RECORDED FAILURE, not a crash that ends the run and takes
 *  every later group with it (the lesson epochCarryTest's mutation battery produced) */
const section = (name, fn) => {
  try { fn(); }
  catch (e) { failed++; console.error(`FAIL: ${name} threw unexpectedly: ${(e && e.message) || String(e)}`); }
};

const CEIL = 9007199254740991n;
const A = "a".repeat(64), B = "b".repeat(64), C = "c".repeat(64);
const half = [{ recipientId: A, bps: 5000 }, { recipientId: B, bps: 5000 }];

// ---- splitOwed: the arithmetic ----
section("splitOwed: the arithmetic", () => {
  const r = splitOwed({ distributableCredits: "100000", rowBps: [5000, 5000], encodingCeiling: CEIL });
  ok("an even split of 100000 across two equal shares is 50000 each with no remainder",
    r.encodingRefused === null && r.owed[0] === 50000n && r.owed[1] === 50000n && r.remainder === 0n);
  const odd = splitOwed({ distributableCredits: "100001", rowBps: [5000, 5000], encodingCeiling: CEIL });
  ok("floor division leaves the odd credit as the REPORTED remainder rather than giving it to anyone",
    odd.owed[0] === 50000n && odd.owed[1] === 50000n && odd.remainder === 1n);
  // by hand: 7 * 3333 / 10000 = 2.3331 -> 2; 7 * 6667 / 10000 = 4.6669 -> 4; sum 6, rem 1
  const uneven = splitOwed({ distributableCredits: 7n, encodingCeiling: CEIL,
    rowBps: [3333, 6667] });
  ok("an uneven split floors EACH share independently, so 7 across 3333/6667 bps is 2 and 4 with 1 left",
    uneven.owed[0] === 2n && uneven.owed[1] === 4n && uneven.remainder === 1n);
  ok("a zero distributable amount owes everyone zero and leaves nothing over",
    (() => { const z = splitOwed({ distributableCredits: "0", rowBps: [5000, 5000], encodingCeiling: CEIL });
      return z.owed[0] === 0n && z.owed[1] === 0n && z.remainder === 0n; })());
  const eight = splitOwed({ distributableCredits: "80000", encodingCeiling: CEIL,
    rowBps: Array.from({ length: 8 }, () => 1250) });
  ok("eight rows at 1250 bps each is the tier's upper bound and splits evenly",
    eight.owed.length === 8 && eight.owed.every((o) => o === 10000n) && eight.remainder === 0n);
});

// ---- splitOwed: the encoding refusal is REPORTED, not thrown ----
section("splitOwed: the encoding refusal", () => {
  // by hand: owed = D * 5000 / 10000 = D/2, so D = 2*(CEIL+1) is the smallest even
  // distributable amount whose per-member owed clears the ceiling by exactly one
  const r = splitOwed({ distributableCredits: String(CEIL * 2n + 2n), rowBps: [5000, 5000], encodingCeiling: CEIL });
  ok("an owed amount above the ceiling is REPORTED as encoding-refused, naming the field and the value",
    r.encodingRefused !== null && r.encodingRefused.field === "amountCredits"
    && r.encodingRefused.value === String(CEIL + 1n) && r.owed === null && r.remainder === null);
  const at = splitOwed({ distributableCredits: String(CEIL * 2n), rowBps: [5000, 5000], encodingCeiling: CEIL });
  ok("an owed amount EXACTLY at the ceiling still encodes (the refusal is strictly above it)",
    at.encodingRefused === null && at.owed[0] === CEIL && at.owed[1] === CEIL);
});

// ---- splitOwed: the allocation shape ----
section("splitOwed: the allocation shape", () => {
  // the DESCRIPTOR reader and the VECTOR predicate are two surfaces with the same bounds:
  // readAllocationBps is the only thing that touches an untrusted row object, and
  // splitOwed validates the materialized vector it is handed
  const call = (rows) => () => readAllocationBps(rows);
  const vec = (rowBps) => () => splitOwed({ distributableCredits: "100000", rowBps, encodingCeiling: CEIL });
  throws("a bps sum below 10000 refuses (value would go undistributed with nobody owed it)",
    call([{ bps: 4000 }, { bps: 5000 }]), /bps sum 9000 is not exactly 10000/);
  throws("a bps sum above 10000 refuses", call([{ bps: 6000 }, { bps: 5000 }]), /bps sum 11000/);
  throws("nine rows refuse (the direct co-owner tier's bound is eight)",
    call(Array.from({ length: 9 }, () => ({ bps: 1111 }))), /must number 1\.\.8/);
  throws("an empty allocation refuses", call([]), /must number 1\.\.8/);
  throws("a bps of zero refuses", call([{ bps: 0 }, { bps: 10000 }]), /OWN integer bps 1\.\.10000/);
  throws("a non-integer bps refuses", call([{ bps: 5000.5 }, { bps: 4999.5 }]), /OWN integer bps/);
  // an INHERITED bps is not a value this calculation may spend
  const inherited = Object.create({ bps: 5000 });
  throws("a bps reached through the prototype chain refuses, rather than being spent",
    call([inherited, { bps: 5000 }]), /OWN integer bps/);
  const accessor = {}; Object.defineProperty(accessor, "bps", { get: () => 5000, enumerable: true });
  throws("a bps behind an accessor refuses", call([accessor, { bps: 5000 }]), /OWN integer bps/);
  const sparse = [{ bps: 5000 }]; sparse[2] = { bps: 5000 };
  throws("a sparse allocation array refuses at its hole rather than reading past it",
    call(sparse), /own enumerable data element/);
  throws("a Number distributable amount refuses (it may arrive already rounded)",
    () => splitOwed({ distributableCredits: 100000, rowBps: [5000, 5000], encodingCeiling: CEIL }),
    /canonical decimal string or BigInt/);
  throws("a negative distributable amount refuses",
    () => splitOwed({ distributableCredits: -1n, rowBps: [5000, 5000], encodingCeiling: CEIL }), /is negative/);
  throws("a non-canonical decimal refuses",
    () => splitOwed({ distributableCredits: "0100", rowBps: [5000, 5000], encodingCeiling: CEIL }),
    /canonical decimal string/);
  throws("a Number ceiling refuses",
    () => splitOwed({ distributableCredits: "1", rowBps: [5000, 5000], encodingCeiling: 900 }), /positive BigInt/);
  // THE CEILING IS STATED, NOT CHOSEN: a larger positive BigInt would encode amounts the
  // contract refuses, and the result records nothing about which ceiling produced it
  throws("a ceiling that is not the schema's refuses, even though it is a positive BigInt",
    () => splitOwed({ distributableCredits: "1", rowBps: [10000], encodingCeiling: CEIL + 1n }),
    /is not the schema's credit ceiling/);
  throws("the same refusal reaches the run builder, which passes the ceiling through",
    () => buildCarryCapableEntitlements({ incomeIdentity: A, allocation: half, configuredStart: 0,
      encodingCeiling: CEIL * 2n, epochs: [{ number: 0, distributableCredits: "1" }] }),
    /is not the schema's credit ceiling/);
  // the vector predicate carries the same bounds as the descriptor reader
  throws("a vector whose bps do not sum to 10000 refuses inside splitOwed itself",
    vec([4000, 5000]), /bps sum 9000/);
  throws("a nine-entry vector refuses", vec(Array.from({ length: 9 }, () => 1111)), /must number 1\.\.8/);
  throws("a non-integer entry refuses", vec([5000.5, 4999.5]), /OWN integer bps/);
});

// ---- the multi-epoch run: the spec's third carry vector, through the real row source ----
section("the multi-epoch run", () => {
  // A is the INCOME identity (its rows are self-shares and never carry); B is a plain
  // member. D = 100000 each epoch at 5000/5000 bps, so each is owed 50000 per epoch.
  // BY HAND: epoch 5 -> B effective 50000, below the 100000 minimum, carried.
  //          epoch 6 -> B effective 50000 + 50000 = 100000, EXACTLY the minimum, payable,
  //                     carry-out zero.
  //          epoch 7 -> B effective 50000 again, carried again.
  //          A is 50000 every epoch and never carries at any amount.
  const calc = buildCarryCapableEntitlements({ configuredStart: 5,
    incomeIdentity: A, allocation: half, encodingCeiling: CEIL,
    epochs: [5, 6, 7].map((number) => ({ number, distributableCredits: "100000" })) });

  const e5 = calc.rowsFor(5), e6 = calc.rowsFor(6), e7 = calc.rowsFor(7);
  ok("epoch 5, the run's base, has zero carry-in, so the member's effective amount is his owed amount alone",
    e5[1].amountCredits === "50000" && !("carryInCredits" in e5[1]));
  ok("epoch 6 carries the deferred 50000 in, reaching exactly the pinned minimum",
    e6[1].amountCredits === "100000" && e6[1].carryInCredits === "50000");
  ok("epoch 7 starts over at 50000, because epoch 6 paid the deferral off rather than deferring it again",
    e7[1].amountCredits === "50000" && !("carryInCredits" in e7[1]));
  ok("the income identity's own rows are 50000 every epoch and NEVER carry, at any amount",
    e5[0].amountCredits === "50000" && e6[0].amountCredits === "50000"
    && e7[0].amountCredits === "50000"
    && !("carryInCredits" in e5[0]) && !("carryInCredits" in e6[0]) && !("carryInCredits" in e7[0]));
  ok("rows come back in allocation order, one per member, carrying the recipient",
    e6.length === 2 && e6[0].recipientId === A && e6[1].recipientId === B);
  ok("the run reports the epochs it covers", JSON.stringify(calc.epochNumbers) === "[5,6,7]");

  // A ZERO CARRY-IN IS OMITTED, NOT EMITTED AS "0". The build spec's migration rule reads
  // an omitted member as the pre-carry shape, under which its two-value resume comparison
  // degenerates to the exact single-value one, so emitting "0" would widen that
  // comparison for every row that never carried anything.
  ok("a zero carry-in is OMITTED rather than emitted as \"0\", which is what keeps the resume comparison single-valued for a row that never carried",
    // the row's exact key set, the partition's two booleans included since step 3b
    Object.keys(e5[1]).sort().join(",") === "amountCredits,isSelfShare,payable,recipientId"
    && Object.keys(e6[1]).sort().join(",") === "amountCredits,carryInCredits,isSelfShare,payable,recipientId");

  // the carry member is the amount coming IN, never the amount going OUT: at epoch 6 the
  // carry-out is zero while the carry-in is 50000, so the two disagree there
  ok("carryInCredits is the amount arriving, not the amount leaving (they differ at the epoch that pays the deferral off)",
    e6[1].carryInCredits === "50000");

  // each call hands back its own copy
  const first = calc.rowsFor(6);
  first[1].amountCredits = "1";
  ok("a caller that mutates the rows it was handed cannot change what the next caller sees",
    calc.rowsFor(6)[1].amountCredits === "100000");
});

// ---- a longer thread, with a member who never reaches the minimum ----
section("a member who never reaches the minimum", () => {
  // D = 20000 at 5000/5000 bps is 10000 owed each per epoch. B accumulates 10000 per
  // epoch and needs TEN epochs to reach the 100000 minimum, so epochs 0..8 all defer and
  // epoch 9 pays. Expectations by hand: carry-in at epoch n is 10000n.
  const calc = buildCarryCapableEntitlements({ configuredStart: 0,
    incomeIdentity: A, allocation: half, encodingCeiling: CEIL,
    epochs: Array.from({ length: 11 }, (_, n) => ({ number: n, distributableCredits: "20000" })) });
  const eff = (n) => calc.rowsFor(n)[1].amountCredits;
  const cin = (n) => calc.rowsFor(n)[1].carryInCredits;
  ok("the effective amount climbs by the owed amount each epoch while it stays below the minimum",
    eff(0) === "10000" && eff(1) === "20000" && eff(4) === "50000" && eff(8) === "90000");
  ok("the carry-in at each epoch is everything deferred before it",
    cin(1) === "10000" && cin(4) === "40000" && cin(9) === "90000");
  ok("the tenth epoch reaches exactly 100000 and pays", eff(9) === "100000");
  // THE PAYOUT IS OBSERVED AT THE NEXT EPOCH, not inferred from the paying one. Epoch 9's
  // own effective amount is the same whether or not its carry-out was cleared, so an
  // eleventh epoch is what makes "nothing carries out of it" a thing this suite can see.
  ok("epoch 10 begins again at its own owed amount with NO carry member, which is where the payout at epoch 9 is actually visible",
    eff(10) === "10000" && !("carryInCredits" in calc.rowsFor(10)[1]));
});

// ---- an encoding-refused epoch refuses the run from there on ----
section("an encoding-refused run", () => {
  const calc = buildCarryCapableEntitlements({ configuredStart: 1,
    incomeIdentity: A, allocation: half, encodingCeiling: CEIL,
    epochs: [{ number: 1, distributableCredits: "100000" },
      { number: 2, distributableCredits: String(CEIL * 4n) },
      { number: 3, distributableCredits: "100000" }] });
  ok("an epoch below the refusal still answers", calc.rowsFor(1)[1].amountCredits === "50000");
  throws("the encoding-refused epoch itself refuses rather than answering with rows or an empty set",
    () => calc.rowsFor(2), /encoding-refused from epoch 2, whose owed amounts exceed/);
  throws("EVERY LATER epoch refuses too, because its effective amounts depend on a carry state the refused epoch's owed values never entered",
    () => calc.rowsFor(3), /encoding-refused from epoch 2/);
});

// ---- the CARRY step's own encoding refusal, which the split never sees ----
section("the carry step's own encoding refusal", () => {
  // A single non-self member at 10000 bps. Epoch 0 owes 1 credit, which carries because
  // it is below the minimum. Epoch 1 owes EXACTLY the ceiling, so the split encodes; the
  // effective amount is ceiling plus the carried 1, so the CARRY step is what refuses.
  // This is a different branch from the split's refusal and the two must both be reached.
  const solo = [{ recipientId: B, bps: 10000 }];
  const calc = buildCarryCapableEntitlements({ incomeIdentity: A, allocation: solo, configuredStart: 0,
    encodingCeiling: CEIL,
    epochs: [{ number: 0, distributableCredits: "1" },
      { number: 1, distributableCredits: String(CEIL) }] });
  ok("epoch 0 defers its single credit, which is what makes the next epoch's effective amount exceed the ceiling",
    calc.rowsFor(0)[0].amountCredits === "1");
  throws("the epoch whose OWED encodes but whose EFFECTIVE does not is refused by the carry step, and the message says which value refused rather than blaming the owed amounts",
    () => calc.rowsFor(1), /EFFECTIVE entitlements exceed the schema ceiling once the deferral carried into them is added/);
});

// ---- the run's boundaries ----
section("the run's boundaries", () => {
  const calc = buildCarryCapableEntitlements({ configuredStart: 5,
    incomeIdentity: A, allocation: half, encodingCeiling: CEIL,
    epochs: [{ number: 5, distributableCredits: "100000" }] });
  throws("an epoch BELOW the run refuses rather than answering from a base it never established",
    () => calc.rowsFor(4), /outside this run \(5\.\.5\)/);
  throws("an epoch ABOVE the run refuses rather than extrapolating",
    () => calc.rowsFor(6), /outside this run/);
  const run = (...numbers) => () => buildCarryCapableEntitlements({ incomeIdentity: A, configuredStart: numbers[0],
    allocation: half, encodingCeiling: CEIL,
    epochs: numbers.map((number) => ({ number, distributableCredits: "1" })) });
  throws("a non-ascending run refuses, because the recursion threads each epoch's carry into the next",
    run(6, 5), /does not immediately follow/);
  throws("a repeated epoch number refuses", run(5, 5), /does not immediately follow/);
  // A GAP IS NOT AN ORDERING NICETY. [5, 7] is ascending, and applying epoch 5's carry to
  // epoch 7 without ever adding epoch 6's owed amount answers with rows that are wrong
  // rather than merely incomplete.
  throws("a run with a GAP refuses, not only one out of order: the skipped epoch's owed amount would simply be lost",
    run(5, 7), /does not immediately follow 5/);
  throws("a gap later in a longer run refuses too", run(5, 6, 7, 9), /does not immediately follow 7/);
  ok("a consecutive run of four is accepted", (() => { run(5, 6, 7, 8)(); return true; })());
  throws("an empty run refuses", () => buildCarryCapableEntitlements({ incomeIdentity: A,
    allocation: half, encodingCeiling: CEIL, epochs: [] }), /non-empty array/);
});

// ---- the build-time refusals ----
section("the build-time refusals", () => {
  const build = (over) => () => buildCarryCapableEntitlements({ incomeIdentity: A, allocation: half, configuredStart: 0,
    encodingCeiling: CEIL, epochs: [{ number: 0, distributableCredits: "100000" }], ...over });
  throws("an absent income identity refuses (nothing could recognize the self-share)", build({ incomeIdentity: undefined }), /64 lowercase hex/);
  throws("a short income identity refuses", build({ incomeIdentity: A.slice(0, 62) }), /64 lowercase hex/);
  throws("an allocation row with no recipientId refuses", build({ allocation: [{ bps: 10000 }] }),
    /recipientId that is a primitive string of 64 lowercase hex/);
  // A REGULAR EXPRESSION COERCES ITS ARGUMENT, so a boxed String matches the pattern while
  // === against the primitive of the same text is false. The income identity would stop
  // recognizing its own row, and two boxed objects of identical text would both survive a
  // Set-based uniqueness check because object identity differs.
  throws("a BOXED income identity refuses, though its text matches the pattern",
    build({ incomeIdentity: new String(A) }), /primitive 64 lowercase hex string/);
  throws("a BOXED recipientId refuses for the same reason",
    build({ allocation: [{ recipientId: new String(A), bps: 5000 }, { recipientId: B, bps: 5000 }] }),
    /primitive string of 64 lowercase hex/);
  // AND A LENGTH THAT CHANGES BETWEEN READS cannot drop a row: the bounds check and the
  // descriptor loop would otherwise see different arrays, so a second row disappears while
  // the first one's 10000 basis points still sum correctly
  throws("an allocation whose length shrinks between the bounds check and the read refuses rather than silently dropping a row",
    () => { let n = 0;
      const shrinking = new Proxy([{ bps: 10000 }, { bps: 10000 }], {
        get(t, k) { if (k === "length") { n += 1; return n <= 2 ? 2 : 1; } return Reflect.get(t, k); } });
      return readAllocationBps(shrinking); },
    /bps sum 20000 is not exactly 10000/);
  throws("two allocation rows sharing a recipient refuse (the per-member minimum comparison needs one row per member)",
    build({ allocation: [{ recipientId: A, bps: 5000 }, { recipientId: A, bps: 5000 }] }), /share the recipient/);
  throws("a malformed bps refuses at BUILD time, not at the first epoch someone asks for",
    build({ allocation: [{ recipientId: A, bps: 5000 }, { recipientId: B, bps: 4000 }] }), /bps sum 9000/);
  throws("a non-integer epoch number refuses", build({ epochs: [{ number: 1.5, distributableCredits: "1" }] }), /safe non-negative integer/);
  // A THIRD identity as the income identity means NO row is a self-share, so BOTH members
  // carry. One epoch cannot show that: the first epoch's amounts are 50000 either way.
  // The second epoch is where a member that carried differs from one that did not.
  ok("with a third identity as the income identity, BOTH members carry, which only the second epoch can show",
    (() => { const c = buildCarryCapableEntitlements({ incomeIdentity: C, allocation: half,
      configuredStart: 0, encodingCeiling: CEIL,
      epochs: [0, 1].map((number) => ({ number, distributableCredits: "100000" })) });
      const e0 = c.rowsFor(0), e1 = c.rowsFor(1);
      return e0[0].amountCredits === "50000" && e0[1].amountCredits === "50000"
        && e1[0].carryInCredits === "50000" && e1[1].carryInCredits === "50000"
        && e1[0].amountCredits === "100000" && e1[1].amountCredits === "100000"; })());
  ok("and when the income identity IS a member, that member alone stops carrying",
    (() => { const c = buildCarryCapableEntitlements({ incomeIdentity: A, allocation: half,
      configuredStart: 0, encodingCeiling: CEIL,
      epochs: [0, 1].map((number) => ({ number, distributableCredits: "100000" })) });
      const e1 = c.rowsFor(1);
      return !("carryInCredits" in e1[0]) && e1[1].carryInCredits === "50000"; })());
});

// ---- the run's base is enforced, not assumed ----
section("the run's base is enforced", () => {
  const at = (start) => () => buildCarryCapableEntitlements({ incomeIdentity: A,
    allocation: half, encodingCeiling: CEIL, configuredStart: start,
    epochs: [{ number: 5, distributableCredits: "100000" }] });
  throws("a run beginning ABOVE the configured start refuses: every earlier epoch's owed amount would be missing from its carry",
    at(4), /the run begins at epoch 5 but the configured start is 4/);
  throws("a run beginning BELOW it refuses too", at(6), /configured start is 6/);
  throws("an absent configured start refuses rather than defaulting to the run's own first epoch",
    at(undefined), /configuredStart must be a safe non-negative integer/);
  ok("a run beginning exactly at the configured start is accepted", (() => { at(5)(); return true; })());
});

// ---- every validated value is read exactly once ----
section("every validated value is read exactly once", () => {
  // a value that ANSWERS DIFFERENTLY on its second read is the whole point: validating one
  // answer and computing from another is how a check passes while the work goes elsewhere
  const twoFaced = (first, later) => {
    let n = 0;
    return { get() { n += 1; return n === 1 ? first : later; } };
  };

  // an epoch number that says 6 while validated and 7 afterwards must not populate 7
  const shifty = {};
  Object.defineProperty(shifty, "number", { ...twoFaced(6, 7), enumerable: true });
  shifty.distributableCredits = "100000";
  const c1 = buildCarryCapableEntitlements({ incomeIdentity: A, allocation: half,
    encodingCeiling: CEIL, configuredStart: 6, epochs: [shifty] });
  ok("the epoch the run answers for is the one that was validated, not the one a later read named",
    JSON.stringify(c1.epochNumbers) === "[6]" && c1.rowsFor(6)[0].amountCredits === "50000");
  throws("and the number the second read named was never populated", () => c1.rowsFor(7), /outside this run/);

  // two rows whose recipients differ on the first read and collide afterwards must be
  // taken at their first answer, so the uniqueness check and the recursion see one set
  const rowA = { bps: 5000 }, rowB = { bps: 5000 };
  Object.defineProperty(rowA, "recipientId", { ...twoFaced(A, B), enumerable: true });
  Object.defineProperty(rowB, "recipientId", { ...twoFaced(B, B), enumerable: true });
  const c2 = buildCarryCapableEntitlements({ incomeIdentity: C, allocation: [rowA, rowB],
    encodingCeiling: CEIL, configuredStart: 0,
    epochs: [{ number: 0, distributableCredits: "100000" }] });
  const got = c2.rowsFor(0).map((r) => r.recipientId);
  ok("the recipients the rows are built for are the ones the uniqueness check saw, so the recursion never receives duplicate members",
    got[0] === A && got[1] === B && got[0] !== got[1]);

  // a bps vector that doubles after its sum is checked would pay out twice the amount
  const sneaky = new Proxy([5000, 5000], {
    get(t, k) {
      if (k === "length" || typeof k === "symbol") return Reflect.get(t, k);
      if (typeof k === "string" && /^\d+$/.test(k)) {
        t[`seen${k}`] = (t[`seen${k}`] || 0) + 1;
        return t[`seen${k}`] === 1 ? 5000 : 10000;
      }
      return Reflect.get(t, k);
    },
  });
  const split = splitOwed({ distributableCredits: "100000", rowBps: sneaky, encodingCeiling: CEIL });
  ok("a bps vector that answers 5000 to the sum check and 10000 to the arithmetic pays out the 5000 it was validated at, not twice the distributable amount",
    split.owed[0] === 50000n && split.owed[1] === 50000n
    && split.owed[0] + split.owed[1] === 100000n);
});

// ---- the self-share never carries, at any amount ----
section("the self-share never carries at any amount", () => {
  // A is income and owed 1 credit an epoch. Over three epochs it stays 1, never 2 or 3,
  // because a self-share is settled where it sits rather than deferred.
  const calc = buildCarryCapableEntitlements({ configuredStart: 0,
    incomeIdentity: A, allocation: [{ recipientId: A, bps: 10000 }], encodingCeiling: CEIL,
    epochs: [0, 1, 2].map((number) => ({ number, distributableCredits: "1" })) });
  ok("a self-share owed 1 credit an epoch stays at 1 every epoch, rather than accumulating to 2 and 3",
    calc.rowsFor(0)[0].amountCredits === "1" && calc.rowsFor(1)[0].amountCredits === "1"
    && calc.rowsFor(2)[0].amountCredits === "1");
  ok("and it never carries a member in",
    !("carryInCredits" in calc.rowsFor(2)[0]));
});

// ---- the exported ceiling IS the contract's declared maximum ----
// A constant that merely looks like the schema's is the drift this export exists to
// end, so it is compared against what contractV11 actually declares for all three
// credit fields rather than against another copy of the literal.
(async () => {
  const contractUrl = pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href;
  const { poolLedgerContract } = await import(contractUrl);
  const v11 = buildV11(poolLedgerContract);
  const declared = {
    grossCredits: v11.epochHeader.properties.grossCredits.maximum,
    feeCredits: v11.epochHeader.properties.feeCredits.maximum,
    amountCredits: v11.platformAccrual.properties.amountCredits.maximum,
  };
  ok("the exported ceiling equals what contractV11 declares as the maximum for amountCredits",
    BigInt(declared.amountCredits) === SCHEMA_CREDIT_CEILING);
  ok("and the header's two credit fields declare the same maximum, which is why one constant serves all three",
    declared.grossCredits === declared.amountCredits && declared.feeCredits === declared.amountCredits);

section("the carry partition's answers travel on each row (the per-epoch context design, step 3b)", () => {
  // the same fixture as the multi-epoch run: A is the income identity, B a plain member,
  // D = 100000 at 5000/5000, so B is below the minimum at epochs 5 and 7 and exactly at it
  // (through the carry) at epoch 6
  const calc = buildCarryCapableEntitlements({ configuredStart: 5,
    incomeIdentity: A, allocation: half, encodingCeiling: CEIL,
    epochs: [5, 6, 7].map((number) => ({ number, distributableCredits: "100000" })) });
  const e5 = calc.rowsFor(5), e6 = calc.rowsFor(6), e7 = calc.rowsFor(7);
  ok("the income identity's row is a self-share every epoch and never payable, whatever its amount",
    [e5, e6, e7].every((e) => e[0].isSelfShare === true && e[0].payable === false));
  ok("the member's row is not a self-share, and is payable exactly when its effective amount reaches the minimum (epoch 6, through the carry)",
    [e5, e6, e7].every((e) => e[1].isSelfShare === false)
    && e5[1].payable === false && e6[1].payable === true && e7[1].payable === false);
  ok("both answers are strict booleans on every row",
    [e5, e6, e7].every((e) => e.every((r) => typeof r.isSelfShare === "boolean" && typeof r.payable === "boolean")));
  const z = buildCarryCapableEntitlements({ configuredStart: 0, incomeIdentity: A, allocation: half,
    encodingCeiling: CEIL, epochs: [{ number: 0, distributableCredits: "1" }] }).rowsFor(0);
  ok("a zero effective amount is not payable, and the self-share flag is the identity comparison alone",
    z[1].amountCredits === "0" && z[1].payable === false && z[1].isSelfShare === false && z[0].isSelfShare === true && z[0].payable === false);
  // THE PARTITION DEPENDENCY, BOUND DIRECTLY (the pre-commit checker's construction): the
  // row's `payable` equals epochCarry's own answer for the same members, computed here
  // independently over the same owed amounts and the same carry-in, index by index
  const { advanceEpoch, emptyCarryState } = require("./epochCarry.cjs");
  const carry5 = new Map([[B, 50000n]]);
  const step6 = advanceEpoch({ carryIn: carry5, encodingCeiling: CEIL, owedRefused: false,
    members: [{ key: A, isSelfShare: true, owedCredits: 50000n }, { key: B, isSelfShare: false, owedCredits: 50000n }] });
  ok("the row's payable IS the carry partition's answer, index by index, over the same owed amounts and carry-in",
    step6.kind === "encoded" && e6.every((r, i) => r.payable === step6.payable[i]) && e6[1].amountCredits === String(step6.effective[1]));
  // REORDERED MEMBERS: the answers follow the allocation's order, so the income identity
  // placed SECOND is the self-share at index 1 and the member at index 0 is payable
  const swapped = buildCarryCapableEntitlements({ configuredStart: 5, incomeIdentity: A,
    allocation: [{ recipientId: B, bps: 5000 }, { recipientId: A, bps: 5000 }], encodingCeiling: CEIL,
    epochs: [5, 6].map((number) => ({ number, distributableCredits: "100000" })) }).rowsFor(6);
  ok("with the allocation reordered, each answer stays with its own member (the income identity second is the self-share at index 1)",
    swapped[0].recipientId === B && swapped[0].isSelfShare === false && swapped[0].payable === true
    && swapped[1].recipientId === A && swapped[1].isSelfShare === true && swapped[1].payable === false);
  // THE MINIMUM'S EDGE: one credit below the pinned minimum is not payable, exactly at it is
  const edge = (d) => buildCarryCapableEntitlements({ configuredStart: 0, incomeIdentity: A, allocation: half,
    encodingCeiling: CEIL, epochs: [{ number: 0, distributableCredits: d }] }).rowsFor(0)[1];
  ok("one credit below the pinned minimum is not payable and exactly the minimum is",
    edge("199998").amountCredits === "99999" && edge("199998").payable === false
    && edge("200000").amountCredits === "100000" && edge("200000").payable === true);
  // THE CONSUMER THIS EXISTS FOR: the forward plan builder takes the row's answers as its
  // members' isSelfShare and payable, and classifies from them, so one rule feeds both
  const K = require("./e2ForwardKernel.cjs");
  const scope = { contractId: "c", chainId: "x", contractVersion: 11, poolId: "0".repeat(64), epochIndex: 6 };
  const memberOf = (r, i) => ({ funderId: r.recipientId, plannedAccrualId: String(i + 1).repeat(64).slice(0, 64),
    effectiveCredits: r.amountCredits, shareBps: 5000, isSelfShare: r.isSelfShare, payable: r.payable });
  const plan6 = K.buildExpectedRecordPlan({ scope, encodingRefused: false,
    header: { grossCredits: "100000", feeCredits: "0", memberCount: 2, calcVersion: 1, allocationHash: "9".repeat(64) },
    members: e6.map(memberOf) });
  const plan5 = K.buildExpectedRecordPlan({ scope: { ...scope, epochIndex: 5 }, encodingRefused: false,
    header: { grossCredits: "100000", feeCredits: "0", memberCount: 2, calcVersion: 1, allocationHash: "9".repeat(64) },
    members: e5.map(memberOf) });
  ok("the plan builder classifies from the row's answers: self-share, payable at epoch 6, below-minimum at epoch 5",
    plan6.members[0].classification === "self-share" && plan6.members[1].classification === "payable"
    && plan5.members[1].classification === "below-minimum");
  throws("a row whose answers were altered into payable AND self-share is refused by the plan builder (the partition never produces it)",
    () => K.buildExpectedRecordPlan({ scope, encodingRefused: false,
      header: { grossCredits: "100000", feeCredits: "0", memberCount: 2, calcVersion: 1, allocationHash: "9".repeat(64) },
      members: e6.map((r, i) => memberOf(i === 0 ? { ...r, payable: true } : r, i)) }), /payable AND a self-share/);
});

const EXPECTED_ASSERTIONS = 83;
if (passed + failed !== EXPECTED_ASSERTIONS) {
  failed++;
  console.error(`FAIL: the suite ran ${passed + failed - 1} assertions, not the ${EXPECTED_ASSERTIONS} it declares; a section stopped short or the declared count was not raised with a new one`);
}
console.log(`entitlementCalcTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
})().catch((e) => { console.error("UNCAUGHT:", e); process.exitCode = 1; });
