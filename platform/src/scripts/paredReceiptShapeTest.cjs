/**
 * The two completion-receipt shapes, offline (phase C of docs/V9_MIGRATION_PLAN.md).
 *
 * v8 carries nodeType, operatorFeeBps and targetDuffs at the top of the receipt. v9 pares all
 * three away, because the immutable pool already pins them and duplication was the
 * contradiction surface the v9 review closed. Both contracts set additionalProperties:false,
 * so EACH SHAPE REJECTS THE OTHER: a v9 contract refuses a receipt still carrying the three,
 * and a v8 contract refuses one missing them.
 *
 * That symmetry is the property worth pinning, because a one-directional check would let a
 * half-migrated writer emit v8 fields onto a v9 ledger and only find out on a live broadcast.
 * The mock enforces the schema at create time precisely so the crash matrix cannot accept a
 * receipt the real ledger would reject, and the mock now has to be right in both directions.
 *
 * Note targetDuffs SWAPS SIDES rather than disappearing: on v8 it is a receipt field and the
 * pool has none, on v9 it is a pool field and the receipt has none. Nothing is lost, but the
 * check that pins it moves from verifyReceiptAgainstDraft to requireDraftMatchesPool.
 *
 * Run: node src/scripts/paredReceiptShapeTest.cjs   (exits non-zero on failure)
 */
const { validateReceiptProps } = require("./formationMockDash.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const withLedger = (v, fn) => {
  const prev = process.env.LEDGER;
  if (v === undefined) delete process.env.LEDGER; else process.env.LEDGER = v;
  try { return fn(); } finally {
    if (prev === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev;
  }
};
const accepts = (name, ledger, props) => {
  let err = null;
  withLedger(ledger, () => { try { validateReceiptProps(props); } catch (e) { err = e; } });
  if (err) { fail++; console.error(`FAIL: ${name} (rejected: ${err.message})`); } else pass++;
};
const rejects = (name, ledger, props, re) => {
  let err = null;
  withLedger(ledger, () => { try { validateReceiptProps(props); } catch (e) { err = e; } });
  if (!err) { fail++; console.error(`FAIL: ${name} (accepted)`); return; }
  ok(name, re.test(err.message));
};

const COMMON = {
  poolId: Buffer.alloc(32, 1),
  proTxHash: Buffer.alloc(32, 2),
  slotIndex: 0,
  formatVersion: 1,
  allocationRows: Buffer.from("[]", "utf8"),
  allocationHash: Buffer.alloc(32, 3),
  participantCount: 2,
  l1Verification: "demo-unverified",
  verificationMethodVersion: 1,
};
const V8_ONLY = { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 };
const v8Receipt = () => ({ ...COMMON, ...V8_ONLY });
const v9Receipt = () => ({ ...COMMON });

// ---- each shape is accepted on its own ledger ----
accepts("v8 receipt on v8", "v8", v8Receipt());
accepts("v9 receipt on v9", "v9", v9Receipt());

// ---- and REJECTED on the other, in both directions ----
rejects("a v8-shaped receipt on v9 is rejected as an unknown property", "v9", v8Receipt(),
  /unknown property (nodeType|operatorFeeBps|targetDuffs).*additionalProperties/);
rejects("a v9-shaped receipt on v8 is rejected as missing", "v8", v9Receipt(),
  /missing (nodeType|operatorFeeBps|targetDuffs)/);

// each pared field on its own is enough to be refused by v9, so a partial migration is caught
for (const k of Object.keys(V8_ONLY)) {
  rejects(`v9 refuses a receipt carrying only ${k}`, "v9", { ...COMMON, [k]: V8_ONLY[k] },
    new RegExp(`unknown property ${k}`));
  rejects(`v8 refuses a receipt missing only ${k}`, "v8",
    Object.fromEntries(Object.entries(v8Receipt()).filter(([n]) => n !== k)),
    new RegExp(`missing ${k}`));
}

// ---- the shared fields are still enforced on BOTH shapes ----
for (const ledger of ["v8", "v9"]) {
  const base = ledger === "v8" ? v8Receipt() : v9Receipt();
  rejects(`${ledger}: slotIndex out of range`, ledger, { ...base, slotIndex: 99 }, /slotIndex out of/);
  rejects(`${ledger}: participantCount out of range`, ledger, { ...base, participantCount: 0 },
    /participantCount out of/);
  rejects(`${ledger}: a short poolId`, ledger, { ...base, poolId: Buffer.alloc(31, 1) },
    /poolId is not 32 bytes/);
  rejects(`${ledger}: an l1Verification outside the enum`, ledger,
    { ...base, l1Verification: "trust-me" }, /l1Verification not in the enum/);
  rejects(`${ledger}: formatVersion not 1`, ledger, { ...base, formatVersion: 2 },
    /formatVersion is not const 1/);
}

// the refusal names the shape it was judging, so a failure says which ledger was selected
rejects("the message names the v9 shape", "v9", v8Receipt(), /violates the v9 schema/);
rejects("the message names the v8 shape", "v8", v9Receipt(), /violates the v8 schema/);

console.log(`paredReceiptShapeTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
