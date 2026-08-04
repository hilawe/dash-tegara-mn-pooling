/**
 * The ledger version table, offline (phase A of docs/V9_MIGRATION_PLAN.md).
 *
 * The table replaced eight scattered encodings of version knowledge: three copies of the
 * supported-version whitelist and five per-predicate version lists. Two properties matter
 * enough to pin, and both are the kind that fail silently rather than loudly:
 *
 *   1. THE OLD VERSION-NUMBERED PREDICATES MUST ANSWER EXACTLY AS BEFORE for v1 through
 *      v8. They are now aliases over capabilities, and roughly 47 call sites still use the
 *      old names, so a shifted answer would change live v8 behaviour silently. The v1-to-v8
 *      expectations below are transcribed from the version lists as they stood BEFORE the
 *      table, so this suite compares against history rather than against the table it is
 *      testing.
 *   2. v9 SUBTRACTS. Its pool document is immutable and carries no `status`, so
 *      `hasPoolStatus` is FALSE on v9 while its neighbours stay true. An "or later" chain
 *      cannot express that, and the whole reason for writing capabilities out per version
 *      is to keep the removal visible. If someone later "tidies" the table into an
 *      inherited chain, the v9 case here fails.
 *
 * Run: node src/scripts/ledgerVersionTableTest.cjs   (exits non-zero on failure)
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-lvt-"));
process.env.TEGARA_ENV_PATH = path.join(TMP, "env.local");

const S = require("./envStore.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const throws = (name, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
const withLedger = (v, fn) => {
  const prev = process.env.LEDGER;
  if (v === undefined) delete process.env.LEDGER; else process.env.LEDGER = v;
  try { return fn(); } finally {
    if (prev === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev;
  }
};

// ---------------------------------------------------------------------------
// 1. the pre-table answers, transcribed from the version lists as they stood
// ---------------------------------------------------------------------------
// isV3 ["v3".."v8"], isV4 ["v4".."v8"], isV5 ["v5".."v8"], isV6 ["v6".."v8"],
// isV7 ["v7","v8"], isV8 === "v8"
const HISTORICAL = {
  v1: { isV3: false, isV4: false, isV5: false, isV6: false, isV7: false, isV8: false },
  v3: { isV3: true, isV4: false, isV5: false, isV6: false, isV7: false, isV8: false },
  v4: { isV3: true, isV4: true, isV5: false, isV6: false, isV7: false, isV8: false },
  v5: { isV3: true, isV4: true, isV5: true, isV6: false, isV7: false, isV8: false },
  v6: { isV3: true, isV4: true, isV5: true, isV6: true, isV7: false, isV8: false },
  v7: { isV3: true, isV4: true, isV5: true, isV6: true, isV7: true, isV8: false },
  v8: { isV3: true, isV4: true, isV5: true, isV6: true, isV7: true, isV8: true },
};

for (const [v, want] of Object.entries(HISTORICAL)) {
  withLedger(v === "v1" ? undefined : v, () => {
    for (const [pred, expected] of Object.entries(want)) {
      ok(`${v}: ${pred}() is ${expected}`, S[pred]() === expected);
    }
  });
}
// the unset selector is v1, which is what every default run uses
withLedger(undefined, () => {
  ok("unset LEDGER resolves to v1", S.ledgerVersion() === "v1");
  ok("unset LEDGER has no capabilities", S.SUPPORTED_LEDGERS.length > 0 && !S.isV3() && !S.isV8());
});

// ---------------------------------------------------------------------------
// 2. v9, the version the table exists for
// ---------------------------------------------------------------------------
withLedger("v9", () => {
  // the subtraction, which an inherited chain would get wrong
  ok("v9: hasPoolStatus is FALSE (the immutable pool has no status field)", S.hasPoolStatus() === false);
  ok("v9: isV5 alias agrees, so the ~47 existing call sites omit status on v9", S.isV5() === false);
  // everything v8 had and v9 keeps
  ok("v9: hasReconstructibleAccruals", S.hasReconstructibleAccruals() === true);
  ok("v9: hasAccrualKindInKey", S.hasAccrualKindInKey() === true);
  ok("v9: hasPledgeSlot", S.hasPledgeSlot() === true);
  ok("v9: hasSlotBook", S.hasSlotBook() === true);
  ok("v9: hasCompletionReceipt", S.hasCompletionReceipt() === true);
  // the addition
  ok("v9: hasImmutablePool", S.hasImmutablePool() === true);
  // the old aliases pick up v9 from the table, where the old lists never mentioned it
  ok("v9: isV3 alias is true", S.isV3() === true);
  ok("v9: isV7 alias is true", S.isV7() === true);
  ok("v9: isV8 alias is true (v9 keeps the completion receipt)", S.isV8() === true);
});

// no version before v9 claims the immutable pool
for (const v of ["v1", "v3", "v4", "v5", "v6", "v7", "v8"]) {
  withLedger(v === "v1" ? undefined : v, () =>
    ok(`${v}: hasImmutablePool is false`, S.hasImmutablePool() === false));
}

// ---------------------------------------------------------------------------
// 2b. targeted delegation is its OWN capability, not an isV5 rider
// ---------------------------------------------------------------------------
// votePreference.delegateTo enters the schema at v5 (registerV5.cjs) and is carried by
// every later version INCLUDING v9 (contractV9Test pins votePreference unchanged from
// v8). isV5 aliases hasPoolStatus, which v9 subtracts, so gating delegateTo on isV5
// refused a field the published v9 contract accepts (2026-08-03 round, convergence-2
// pass, major B). The capability row makes the two axes independent in the table.
for (const [v, want] of Object.entries({ v1: false, v3: false, v4: false, v5: true, v6: true, v7: true, v8: true, v9: true })) {
  withLedger(v === "v1" ? undefined : v, () =>
    ok(`${v}: hasDelegateTarget is ${want}`, S.hasDelegateTarget() === want));
}
// the divergence the fold exists for: on v9 the two answers differ
withLedger("v9", () =>
  ok("v9: hasDelegateTarget true while isV5 false (the axes are independent)",
    S.hasDelegateTarget() === true && S.isV5() === false));

// the OTHER two v5 member-join fields are their own capabilities too (final pass,
// major 1): membershipRequest.provenance and .rewardScript enter at v5 and are carried
// unchanged through v9, so gating either on isV5 refused fields the published v9
// contract accepts (provenance was the reviewer's finding; rewardScript is the same
// class one line down in pledge.cjs)
for (const [v, want] of Object.entries({ v1: false, v3: false, v4: false, v5: true, v6: true, v7: true, v8: true, v9: true })) {
  withLedger(v === "v1" ? undefined : v, () => {
    ok(`${v}: hasJoinProvenance is ${want}`, S.hasJoinProvenance() === want);
    ok(`${v}: hasMemberRewardScript is ${want}`, S.hasMemberRewardScript() === want);
  });
}
withLedger("v9", () =>
  ok("v9: both join-field capabilities true while isV5 false",
    S.hasJoinProvenance() === true && S.hasMemberRewardScript() === true && S.isV5() === false));

// ---------------------------------------------------------------------------
// 3. selection, and failing closed
// ---------------------------------------------------------------------------
throws("an unsupported selector is refused, never a silent v1 fallback",
  () => withLedger("v42", () => S.activeContractId({ CONTRACT_ID: "x" })), /unsupported LEDGER value "v42"/);
throws("the refusal names the supported set from the table",
  () => withLedger("v42", () => S.assertSupportedLedger()), /v9/);
// a capability on an unknown version is false rather than throwing, so a guard that runs
// before validation cannot accidentally enable a feature
ok("an unknown version has no capabilities", withLedger("v42", () => S.hasImmutablePool()) === false);

throws("v9 selected before publication fails with the register script named",
  () => withLedger("v9", () => S.activeContractId({ CONTRACT_ID: "x" })),
  /CONTRACT_V9_ID is missing; run registerV9\.cjs first/);
ok("v9 selected after publication resolves to its own id",
  withLedger("v9", () => S.activeContractId({ CONTRACT_ID: "x", CONTRACT_V9_ID: "nine" })) === "nine");
ok("v8 still resolves to its own id",
  withLedger("v8", () => S.activeContractId({ CONTRACT_ID: "x", CONTRACT_V8_ID: "eight" })) === "eight");
ok("v1 resolves to the original namespace with no register requirement",
  withLedger(undefined, () => S.activeContractId({ CONTRACT_ID: "one" })) === "one");

// ---------------------------------------------------------------------------
// 3b. exact-version identity, for the sites that genuinely mean one version
// ---------------------------------------------------------------------------
// Aliasing isV8 (an exact match before the table) onto a capability that v9 also has
// would have silently admitted v9 to two places written against the v8 shape: the v8
// squatting probe, and formation.cjs, whose own migration is phases C to E. Both now use
// ledgerIsExactly, and these cases pin that distinction.
ok("ledgerIsExactly is exact where the capability is not",
  withLedger("v9", () => S.hasCompletionReceipt() === true && S.ledgerIsExactly("v8") === false));
ok("ledgerIsExactly('v8') on v8", withLedger("v8", () => S.ledgerIsExactly("v8")) === true);
ok("ledgerIsExactly('v9') on v9", withLedger("v9", () => S.ledgerIsExactly("v9")) === true);
ok("ledgerIsExactly('v1') with the selector unset",
  withLedger(undefined, () => S.ledgerIsExactly("v1")) === true);

// ---------------------------------------------------------------------------
// 4. the table itself stays well formed
// ---------------------------------------------------------------------------
ok("every version has a contract id key", Object.values(S.LEDGER_VERSIONS).every((e) => typeof e.idKey === "string" && e.idKey));
ok("every version except v1 names a register script",
  Object.entries(S.LEDGER_VERSIONS).every(([v, e]) => v === "v1" ? e.register === null : typeof e.register === "string"));
ok("contract id keys are unique", new Set(Object.values(S.LEDGER_VERSIONS).map((e) => e.idKey)).size
  === Object.keys(S.LEDGER_VERSIONS).length);
ok("v9 is selectable", S.SUPPORTED_LEDGERS.includes("v9"));

fs.rmSync(TMP, { recursive: true, force: true });
console.log(`ledgerVersionTableTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
