/**
 * epochCarry's battery. The module is pure, so this drives it directly with no
 * fixtures on disk and no mocks.
 *
 * THE EXPECTATIONS COME FROM THE SPECIFICATION, NOT FROM THE CODE. Every value in the
 * "boundary literals" block below is transcribed from `tegara/docs/E2_BUILD_SPEC.md`
 * item 6 ("THE CARRY LAYER'S BOUNDARY LITERALS"), which that section declares
 * normative. Deriving them from the module would make this suite agree with whatever
 * the module does.
 *
 * THE MUTATION LIST WAS WRITTEN BEFORE THESE TESTS, per the playbook rule, and the
 * commit message records the run. Two of them aim at the OBSERVATION rather than at the
 * behaviour: M5 keeps every returned value correct while mutating the caller's input
 * state, and M7 leaves the arithmetic intact while widening `payable`.
 */
"use strict";

const { emptyCarryState, advanceEpoch } = require("./epochCarry.cjs");
const { MIN_TRANSFER_AMOUNT_CREDITS } = require("./e2Journal.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) { passed++; } else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
/**
 * Every group of assertions runs inside one of these. AN UNEXPECTED THROW IS A RECORDED
 * FAILURE, NOT A CRASH, and the difference is not cosmetic: the module enforces several
 * of its own design properties with runtime refusals, so a defect in the rule surfaces
 * as an exception from inside an expression an assertion was about to evaluate. Letting
 * that propagate ends the process with no summary line and takes every later group down
 * with it, which reads to any harness reading this suite's result as a crash rather than
 * as a detection. The mutation battery found exactly this: two mutations of the carry-out
 * rule were being recorded as caught while the run was in fact dying before it evaluated
 * anything.
 */
const section = (name, fn) => {
  try { fn(); }
  catch (e) { failed++; console.error(`FAIL: ${name} threw unexpectedly: ${(e && e.message) || String(e)}`); }
};

// the schema's amountCredits ceiling, the value e2Audit passes
const CEIL = 9007199254740991n;
const A = "a".repeat(64), B = "b".repeat(64), C = "c".repeat(64);

// one epoch step, with carry-in supplied as a plain object for brevity
const step = (carry, members, opts = {}) => advanceEpoch({
  carryIn: new Map(Object.entries(carry).map(([k, v]) => [k, BigInt(v)])),
  members, encodingCeiling: CEIL, owedRefused: false, ...opts });
const member = (key, owed, isSelfShare = false) =>
  ({ key, owedCredits: BigInt(owed), isSelfShare });
// the state stores only OUTSTANDING deferrals, so no entry and a zero deferral are one
// answer; this reads them as one so an assertion can say "carries nothing" either way
const outOf = (r, key) => r.carryOut.get(key) || 0n;

// ---- the pinned minimum this suite reasons against ----
ok("the pinned minimum is 100000 (the value every boundary literal below is stated against)",
  MIN_TRANSFER_AMOUNT_CREDITS === 100000n);

// ---- the base case ----
section("the base case", () => {
  const r = step({}, [member(A, 500)]);
  ok("the recursion's base is zero carry-in: an empty state makes effective equal owed",
    r.kind === "encoded" && r.effective[0] === 500n);
  ok("emptyCarryState() is an empty Map", emptyCarryState() instanceof Map && emptyCarryState().size === 0);
});

// ---- THE SPECIFICATION'S BOUNDARY LITERALS (E2_BUILD_SPEC.md item 6) ----
section("THE SPECIFICATION'S BOUNDARY LITERALS (E2_BUILD_SPEC.md item 6)", () => {
  // owed = 99999, carryIn = 0: effective = 99999, below the minimum, carryOut = 99999
  const v1 = step({}, [member(A, 99999)]);
  ok("vector 1: owed 99999 with no carry-in is effective 99999, carried whole, not payable",
    v1.effective[0] === 99999n && outOf(v1, A) === 99999n && v1.payable[0] === false);

  // owed = 1, carryIn = 99999: effective = 100000, EXACTLY the minimum, PAYABLE, carryOut = 0
  const v2 = step({ [A]: 99999 }, [member(A, 1)]);
  ok("vector 2: owed 1 onto a carry-in of 99999 is effective 100000, EXACTLY the minimum, payable, carry-out zero",
    v2.effective[0] === 100000n && v2.payable[0] === true && outOf(v2, A) === 0n);

  // owed = 50000 in two consecutive epochs: N effective 50000 carried; N+1 effective 100000 payable
  const n = step({}, [member(A, 50000)]);
  const n1 = advanceEpoch({ carryIn: n.carryOut, members: [member(A, 50000)], encodingCeiling: CEIL,
    owedRefused: false });
  ok("vector 3: owed 50000 twice running carries at epoch N and pays at N+1, the state threaded from the first step's own output",
    n.effective[0] === 50000n && outOf(n, A) === 50000n && n.payable[0] === false
    && n1.effective[0] === 100000n && n1.payable[0] === true && outOf(n1, A) === 0n);

  // owed = 40000, carryIn = 30000: effective = 70000, carried WHOLE
  const v4 = step({ [A]: 30000 }, [member(A, 40000)]);
  ok("vector 4: owed 40000 onto a carry-in of 30000 carries the WHOLE 70000, never a part of it",
    v4.effective[0] === 70000n && outOf(v4, A) === 70000n && v4.payable[0] === false);

  // SELF-SHARE at 1, 99999, 100000 and 1000000: settled without a transfer, carryOut = 0
  for (const amt of [1, 99999, 100000, 1000000]) {
    const s = step({}, [member(A, amt, true)]);
    ok(`vector 5: a self-share at ${amt} never carries and is never payable (it settles where it sits)`,
      outOf(s, A) === 0n && s.payable[0] === false && s.effective[0] === BigInt(amt));
  }

  // self-share AND below minimum on one row (effective 495): SELF-SHARE wins
  const v6 = step({}, [member(A, 495, true)]);
  ok("vector 6: a self-share row that is also below the minimum carries nothing (self-share takes precedence)",
    v6.effective[0] === 495n && outOf(v6, A) === 0n && v6.payable[0] === false);
});

// ---- the boundary on either side of the minimum, stated as its own pair ----
section("the boundary on either side of the minimum, stated as its own pair", () => {
  const below = step({}, [member(A, 99999)]);
  const at = step({}, [member(A, 100000)]);
  ok("99999 carries and 100000 pays: the comparison is strictly below the minimum, not at or below it",
    outOf(below, A) === 99999n && below.payable[0] === false
    && outOf(at, A) === 0n && at.payable[0] === true);
});

// ---- a zero effective amount ----
section("a zero effective amount", () => {
  const z = step({}, [member(A, 0)]);
  ok("a zero effective amount carries nothing and is not payable",
    z.effective[0] === 0n && outOf(z, A) === 0n && z.payable[0] === false);
  const zc = step({ [A]: 700 }, [member(A, 0)]);
  ok("a zero-owed epoch RECEIVING carry-in is an ordinary epoch: effective equals the carry-in and carries on whole",
    zc.effective[0] === 700n && outOf(zc, A) === 700n && zc.payable[0] === false);
});

// ---- the pass-through rule, both refusing paths ----
section("the pass-through rule, both refusing paths", () => {
  const carried = { [A]: 4000, [B]: 25000 };
  const owedRef = step(carried, [member(A, 0), member(B, 0)], { owedRefused: true });
  ok("an epoch whose OWED calculation refused passes every member's carry through unchanged, and reports no effective amounts",
    owedRef.kind === "encoding-refused" && owedRef.refusedBy === "owed" && owedRef.effective === null
    && outOf(owedRef, A) === 4000n && outOf(owedRef, B) === 25000n && owedRef.carryOut.size === 2);

  const effRef = step(carried, [member(A, CEIL), member(B, 10)]);
  ok("an epoch whose EFFECTIVE amount exceeds the ceiling passes carry through unchanged and names the refusing value",
    effRef.kind === "encoding-refused" && effRef.refusedBy === "effective" && effRef.effective === null
    && effRef.refusedValue === String(CEIL + 4000n)
    && outOf(effRef, A) === 4000n && outOf(effRef, B) === 25000n);

  // the refused epoch's own owed is DROPPED, only prior carry survives: B's 10 owed
  // above did not accumulate onto B's 25000
  ok("a refused epoch DROPS its own owed rather than folding it into the carry (B's carry is its prior 25000, not 25010)",
    outOf(effRef, B) === 25000n);

  const atCeil = step({}, [member(A, CEIL)]);
  ok("an effective amount EXACTLY at the ceiling encodes (the refusal is strictly above it)",
    atCeil.kind === "encoded" && atCeil.effective[0] === CEIL);
});

// ---- the input state is never mutated (M5) ----
section("the input state is never mutated (M5)", () => {
  const input = new Map([[A, 700n]]);
  const r = advanceEpoch({ carryIn: input, members: [member(A, 300)], encodingCeiling: CEIL,
    owedRefused: false });
  ok("advanceEpoch does not mutate the caller's carry-in state, and returns a Map that is not the one it was given",
    input.size === 1 && input.get(A) === 700n && r.carryOut !== input && outOf(r, A) === 1000n);

  const inRef = new Map([[A, 700n]]);
  const rr = advanceEpoch({ carryIn: inRef, members: [member(A, 0)], encodingCeiling: CEIL, owedRefused: true });
  ok("the pass-through returns a COPY, so writing into it cannot reach the state the caller still holds",
    rr.carryOut !== inRef && (rr.carryOut.set(A, 5n), inRef.get(A) === 700n));
});

// ---- the effective-refusal path returns a COPY too (F5) ----
section("the effective-refusal path returns a COPY too (F5)", () => {
  const inRef = new Map([[A, 700n]]);
  const r = advanceEpoch({ carryIn: inRef, members: [member(A, CEIL), member(B, 0)],
    encodingCeiling: CEIL, owedRefused: false });
  ok("the effective-refusal path returns a Map that is not the caller's own",
    r.kind === "encoding-refused" && r.refusedBy === "effective" && r.carryOut !== inRef);
  r.carryOut.set(A, 5n);
  ok("writing into the effective-refusal path's returned state cannot reach the caller's",
    inRef.get(A) === 700n);
});

// ---- refusedValue names the FIRST over-ceiling amount in member order (F6) ----
section("refusedValue names the FIRST over-ceiling amount in member order (F6)", () => {
  // TWO EFFECTIVE amounts over the ceiling, from owed values AT the ceiling plus
  // distinct carry-ins. Owed values ABOVE the ceiling would be a state a conforming
  // caller never pairs with owedRefused false, since the owed calculation refuses them
  // first, so the fixture reaches the effective check the way a real epoch would.
  const r = advanceEpoch({ carryIn: new Map([[A, 1n], [B, 999n]]), encodingCeiling: CEIL,
    owedRefused: false, members: [member(A, CEIL), member(B, CEIL)] });
  ok("with two effective amounts over the ceiling, refusedValue is the FIRST in member order, not the last or the largest",
    r.kind === "encoding-refused" && r.refusedBy === "effective"
    && r.refusedValue === String(CEIL + 1n));
  const rev = advanceEpoch({ carryIn: new Map([[A, 1n], [B, 999n]]), encodingCeiling: CEIL,
    owedRefused: false, members: [member(B, CEIL), member(A, CEIL)] });
  ok("reversing the member order reverses the reported value, which is what makes the previous case observe order at all",
    rev.refusedValue === String(CEIL + 999n));
});

// ---- a carried member must still be a member (the extraction's fail-closed guard) ----
section("a carried member must still be a member (the extraction's fail-closed guard)", () => {
  throws("a carry-in for someone who is not a member of this epoch refuses rather than being dropped",
    () => step({ [A]: 700, [B]: 900 }, [member(A, 100)]), /not a member of this epoch/);
  throws("the same refusal applies on the owed-refused pass-through, where the drop would be just as silent",
    () => step({ [B]: 900 }, [member(A, 0)], { owedRefused: true }), /not a member of this epoch/);
  const kept = step({ [A]: 700 }, [member(A, 100), member(B, 200000)]);
  ok("a member with NO carry-in is fine; only a carry-in with no member refuses",
    kept.kind === "encoded" && outOf(kept, A) === 800n && outOf(kept, B) === 0n);
});

// ---- the state carries only outstanding deferrals ----
section("the state carries only outstanding deferrals", () => {
  const r = step({}, [member(A, 60000), member(B, 200000), member(C, 400, true)]);
  ok("only the deferring member has an entry: a paid member and a self-share leave none",
    r.carryOut.size === 1 && r.carryOut.get(A) === 60000n
    && r.carryOut.has(B) === false && r.carryOut.has(C) === false);
  ok("a member with no entry reads as carrying nothing on the next epoch",
    step({}, [member(B, 100)]).effective[0] === 100n);
  // a member who was paid last epoch must not trip the membership guard when the set
  // legitimately changes, which is what storing zero entries would have caused
  const next = advanceEpoch({ carryIn: r.carryOut, encodingCeiling: CEIL, owedRefused: false,
    members: [member(A, 10000), member(C, 400, true)] });
  ok("a member who deferred nothing can leave the set without refusing; only a deferral cannot vanish",
    next.kind === "encoded" && outOf(next, A) === 70000n);
  throws("but a member who IS deferring cannot leave the set",
    () => advanceEpoch({ carryIn: r.carryOut, encodingCeiling: CEIL, owedRefused: false,
      members: [member(B, 10000)] }), /not a member of this epoch/);
});

// ---- an epoch always has members ----
section("an epoch always has members", () => {
  throws("an empty member set refuses rather than returning a conforming result over no rows",
    () => advanceEpoch({ carryIn: emptyCarryState(), members: [], encodingCeiling: CEIL, owedRefused: false }),
    /members is empty/);
  throws("an empty member set refuses on the owed-refused path too",
    () => advanceEpoch({ carryIn: emptyCarryState(), members: [], encodingCeiling: CEIL, owedRefused: true }),
    /members is empty/);
});

// ---- the refusal answer is never implied ----
section("the refusal answer is never implied", () => {
  throws("an omitted owedRefused refuses rather than defaulting to an epoch that did not refuse",
    () => advanceEpoch({ carryIn: emptyCarryState(), members: [member(A, 5)], encodingCeiling: CEIL }),
    /owedRefused is required/);
  throws("a zero-state entry refuses: the state carries only outstanding deferrals",
    () => advanceEpoch({ carryIn: new Map([[A, 0n]]), members: [member(A, 5)], encodingCeiling: CEIL, owedRefused: false }),
    /only outstanding deferrals/);
});

// ---- several members at once, each independent ----
section("several members at once, each independent", () => {
  const r = step({ [A]: 30000, [C]: 90000 },
    [member(A, 40000), member(B, 200000), member(C, 90000, true)]);
  ok("carry is PER MEMBER: A carries 70000, B pays, and the self-share C carries nothing even holding a stale carry-in",
    outOf(r, A) === 70000n && r.payable[0] === false
    && outOf(r, B) === 0n && r.payable[1] === true
    && outOf(r, C) === 0n && r.payable[2] === false);
  ok("the returned arrays are indexed to the members argument",
    r.effective.length === 3 && r.payable.length === 3
    && r.effective[0] === 70000n && r.effective[1] === 200000n && r.effective[2] === 180000n);
  ok("a member absent from the carry-in state contributes zero rather than refusing",
    r.effective[1] === 200000n);
});

// ---- refusals: the member set ----
section("refusals: the member set", () => {
  throws("two members sharing a key refuse (the per-member minimum comparison needs one row per member)",
    () => step({}, [member(A, 60000), member(A, 60000)]), /share the key/);
  throws("a member with no isSelfShare answer refuses rather than defaulting to payable",
    () => step({}, [{ key: A, owedCredits: 5n }]), /explicit boolean isSelfShare/);
  throws("a non-boolean isSelfShare refuses",
    () => step({}, [{ key: A, owedCredits: 5n, isSelfShare: "no" }]), /explicit boolean isSelfShare/);
  throws("a Number owedCredits refuses (it may arrive already rounded)",
    () => advanceEpoch({ carryIn: emptyCarryState(), members: [{ key: A, owedCredits: 500, isSelfShare: false }], encodingCeiling: CEIL, owedRefused: false }),
    /BigInt owedCredits/);
  throws("a negative owedCredits refuses", () => step({}, [member(A, -1)]), /negative owedCredits/);
  throws("an empty member key refuses", () => step({}, [member("", 5)]), /non-empty string key/);
  throws("a non-array members refuses", () => step({}, "rows"), /members must be an array/);
  throws("a null member refuses", () => step({}, [null]), /member 0 must be an object/);
  // owedRefused does NOT relax the rest of the member grammar
  throws("owedRefused still refuses a duplicate member key",
    () => step({}, [member(A, 0), member(A, 0)], { owedRefused: true }), /share the key/);
});

// ---- refusals: the carry state ----
section("refusals: the carry state", () => {
  throws("a carry-in that REACHES the pinned minimum refuses (no conforming predecessor produces one)",
    () => step({ [A]: 100000 }, [member(A, 1)]), /reaches the pinned minimum/);
  throws("a negative carry-in refuses",
    () => advanceEpoch({ carryIn: new Map([[A, -1n]]), members: [member(A, 1)], encodingCeiling: CEIL, owedRefused: false }),
    /only outstanding deferrals/);
  throws("a Number carry-in refuses",
    () => advanceEpoch({ carryIn: new Map([[A, 500]]), members: [member(A, 1)], encodingCeiling: CEIL, owedRefused: false }),
    /non-BigInt carry-in/);
  throws("a plain object carry-in refuses (the state is a Map)",
    () => advanceEpoch({ carryIn: { [A]: 5n }, members: [member(A, 1)], encodingCeiling: CEIL, owedRefused: false }),
    /must be a Map/);
  throws("a non-string carry-in key refuses",
    () => advanceEpoch({ carryIn: new Map([[7, 5n]]), members: [member(A, 1)], encodingCeiling: CEIL, owedRefused: false }),
    /non-string member key/);
  // the state is validated even when the epoch will pass through, so a corrupt state
  // cannot ride through a refused epoch unexamined
  throws("a corrupt carry state refuses on the owedRefused path too, rather than passing through unexamined",
    () => step({ [A]: 100000 }, [member(A, 0)], { owedRefused: true }), /reaches the pinned minimum/);
});

// ---- refusals: the remaining arguments ----
section("refusals: the remaining arguments", () => {
  throws("a Number encodingCeiling refuses",
    () => advanceEpoch({ carryIn: emptyCarryState(), members: [member(A, 1)], encodingCeiling: 900, owedRefused: false }),
    /positive BigInt/);
  throws("a zero encodingCeiling refuses",
    () => advanceEpoch({ carryIn: emptyCarryState(), members: [member(A, 1)], encodingCeiling: 0n, owedRefused: false }),
    /positive BigInt/);
  throws("a non-boolean owedRefused refuses rather than being read as truthy",
    () => advanceEpoch({ carryIn: emptyCarryState(), members: [member(A, 1)], encodingCeiling: CEIL, owedRefused: "yes" }),
    /owedRefused is required/);
});

// ---- a longer thread: the recursion across five epochs, expectations by hand ----
section("a longer thread: the recursion across five epochs, expectations by hand", () => {
  // A earns 30000 an epoch and never reaches the minimum until epoch 4; B earns
  // 200000 an epoch and is payable every time; the middle epoch is encoding-refused
  // and must pass A's deferral through while dropping that epoch's own owed.
  let state = emptyCarryState();
  const seen = [];
  const owedByEpoch = [30000, 30000, 30000, 30000, 30000];
  for (let e = 0; e < 5; e++) {
    const r = advanceEpoch({ carryIn: state, encodingCeiling: CEIL, owedRefused: e === 2,
      members: [member(A, owedByEpoch[e]), member(B, 200000)] });
    state = r.carryOut;
    seen.push({ kind: r.kind, a: outOf(r, A),
      effA: r.effective ? r.effective[0] : null,
      payableA: r.effective ? r.payable[0] : null });
  }
  // by hand: e0 30000 carried; e1 60000 carried; e2 REFUSED, carry stays 60000 and the
  // epoch's own 30000 is dropped; e3 60000+30000 = 90000 carried; e4 90000+30000 =
  // 120000, at or above the minimum, PAYABLE, carry-out zero
  ok("five epochs with a refused one in the middle: the deferral survives it and the refused epoch's own owed is dropped",
    seen[0].a === 30000n && seen[1].a === 60000n
    && seen[2].kind === "encoding-refused" && seen[2].a === 60000n
    && seen[3].a === 90000n
    && seen[4].a === 0n && seen[4].payableA === true);
  // THE FIFTH EPOCH'S EFFECTIVE AMOUNT IS THE THING THE DROP IS VISIBLE IN, so it is
  // read rather than inferred from the carry-out being zero. Had the refused epoch's own
  // 30000 been folded in, this would be 150000 and every other assertion here would
  // still hold, since 150000 is payable and carries zero exactly as 120000 does.
  ok("the fifth epoch's effective amount is 120000, not the 150000 it would be had the refused epoch's own owed been folded in",
    seen[4].effA === 120000n);
  ok("each earlier epoch's effective amount is its own owed plus the carry it inherited",
    seen[0].effA === 30000n && seen[1].effA === 60000n && seen[3].effA === 90000n
    && seen[2].effA === null);
});

// THE SUITE ASSERTS ITS OWN SIZE. A section that returns early, or one whose assertions
// stop being reached, reduces the count and would otherwise still exit zero, which is a
// green run over fewer checks than anyone thinks are running. A hard equality by design:
// when assertions are added, this number is raised deliberately in the same change.
const EXPECTED_ASSERTIONS = 60;
if (passed + failed !== EXPECTED_ASSERTIONS) {
  failed++;
  console.error(`FAIL: the suite ran ${passed + failed - 1} assertions, not the ${EXPECTED_ASSERTIONS} it declares; a section stopped short or the declared count was not raised with a new one`);
}
console.log(`epochCarryTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
