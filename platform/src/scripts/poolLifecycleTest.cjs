/**
 * Pool state classification across both ledgers, offline (phase E of
 * docs/V9_MIGRATION_PLAN.md).
 *
 * The property this suite defends is that v9 REFUSES TO GUESS. On v8 a pool document answers
 * "forming or live" by itself. On v9 it cannot, because it is immutable and carries neither
 * proTxHash nor status, so a receipt-less pool is open, in flight and abandoned all at once
 * and the honest answer is UNDETERMINED. Anything that turns that into a definite state
 * without new evidence is the collapse three v9 review rounds each killed, and the cases
 * below fail if someone reintroduces it.
 *
 * The second property is that a receipt which FAILS the shared check is never treated as
 * absent. Downgrading a contradiction into "not completed yet" would invite a second
 * completion attempt over an already-contradicted pool, which is worse than refusing.
 *
 * Run: node src/scripts/poolLifecycleTest.cjs   (exits non-zero on failure)
 */
const core = require("./formationCore.cjs");
const { STATES, classifyPool, mayAbandon, admissionVerdict, backingNode, requireBackingNode } = require("./poolLifecycle.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const withLedger = (v, fn) => {
  const prev = process.env.LEDGER;
  if (v === undefined) delete process.env.LEDGER; else process.env.LEDGER = v;
  try { return fn(); } finally {
    if (prev === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev;
  }
};

const GC = "3EbgWjxUoX6J9XbqqxrEktm7tUFBQ5fQyKaiAzXCULxf";
const GP = "47doihuxfjfeoqi4PrKLY58Z56J6BhXekMmhW3z63QT8";
const OA = "8sCudmZNvmDC9nXCGRWk1NMStKaeqCaWLa7eYTEKuT8Y";
const OB = "52D4DcjgFZU1KktALjGpcfGoxR1987BEjTXxbnNcNfAc";
const OC = "FZ9HF6oANQxZDXGXGiKh8uXdPfwcp4rwfrzqQJcdRNgv";
const REGULAR = "100000000000";
const EVO = "400000000000";
const OTHER = "52D4DcjgFZU1KktALjGpcfGoxR1987BEjTXxbnNcNfAc"; // a different pool id

const manifest = (target = REGULAR) => {
  const t = BigInt(target);
  return { v: 1, poolId: GP, realHash: "aa".repeat(32), target,
    owners: [
      { owner: OA, amountDuffs: String(t / 2n), bps: 5000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
      { owner: OB, amountDuffs: String(t * 3n / 10n), bps: 3000, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
      { owner: OC, amountDuffs: String(t / 5n), bps: 2000, rewardScriptHex: "76a914" + "33".repeat(20) + "88ac" },
    ] };
};
// THE TWO RECEIPT SHAPES ARE NOT INTERCHANGEABLE, and an earlier version of this suite got
// that wrong in a way that mattered: it gave the v8 pool a targetDuffs. A REAL v8 pool has
// none, because on v8 the target lives on the RECEIPT and only moves to the pool at v9. The
// fixtures below are the shapes the contracts actually produce, so the v8 cases exercise the
// unpared path rather than a pool that cannot exist.
const paredReceiptFor = (m) => {
  const rows = core.allocationPreimage(GC, m);
  // every real receipt carries proTxHash (required on both shapes); its earlier absence
  // here was itself a fixture-producibility gap the a soundness-review finding binding exposed. poolId as
  // BYTES for the same producibility reason (round 20: the schema types it byteArray
  // and the shape gate now refuses the base58-string form)
  return { poolId: core.toId32(GP), proTxHash: Buffer.from(m.realHash, "hex"), slotIndex: 0,
    formatVersion: 1, allocationRows: rows,
    allocationHash: core.allocationHash(rows), participantCount: 3,
    l1Verification: "demo-unverified", verificationMethodVersion: 1 };
};
const unparedReceiptFor = (m) => ({
  ...paredReceiptFor(m),
  nodeType: "regular", operatorFeeBps: 2000, targetDuffs: Number(m.target),
});
const FORMING_HASH = Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 7)]);
const REAL_HASH = Buffer.alloc(32, 0xaa);

// v9: immutable, carries the target, no proTxHash and no status
const v9Pool = () => ({ slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 });
// v8: carries proTxHash and status, and NO targetDuffs
const v8Pool = (hash) => ({ slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
  proTxHash: hash,
  // a malformed hash is a deliberate fixture in several cases below, and isFormingHash
  // throws on it, so the status is derived only for a well-formed hash; the malformed
  // cases carry "live" so the round-5 pool shape gate reaches the FIELD UNDER TEST (the
  // hash) instead of refusing on a missing status the case is not about
  status: (Buffer.isBuffer(hash) && hash.length === 32)
    ? (core.isFormingHash(hash) ? "forming" : "live") : "live" });

// ---------------------------------------------------------------------------
// v9: the pool cannot answer, so the receipt does or nothing does
// ---------------------------------------------------------------------------
withLedger("v9", () => {
  const done = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: paredReceiptFor(manifest()),
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
  ok("v9: a verifying receipt means COMPLETED", done.state === STATES.COMPLETED && done.receiptOk === true);

  const none = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: null,
    // receipt-less: duty 6 is not reached, so no owners are needed here and
    // supplying them would hide that a pool with no receipt classifies normally
  });
  ok("v9: receipt-less and no local state is UNDETERMINED, not 'open'", none.state === STATES.UNDETERMINED);
  ok("v9: and it says why, naming the three states it cannot separate",
    /open, in flight and\s+abandoned are the same document/.test(none.reason));

  const mine = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: null, operatorHasInFlight: true,
    // receipt-less: duty 6 is not reached, so no owners are needed here and
    // supplying them would hide that a pool with no receipt classifies normally
  });
  ok("v9: the OPERATOR's own local state narrows it to IN_FLIGHT", mine.state === STATES.IN_FLIGHT);

  // the contradiction case: a receipt at the wrong target must not read as 'no receipt'
  const rogue = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: paredReceiptFor(manifest(EVO)),
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
  ok("v9: a receipt that FAILS the shared check is UNDETERMINED, never absent",
    rogue.state === STATES.UNDETERMINED && rogue.receiptOk === false);
  ok("v9: and it says the receipt contradicts rather than that none exists",
    /does NOT verify against this pool/.test(rogue.reason));
  // and local state must NOT override a contradiction into a confident in-flight
  const rogueMine = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP,
    receipt: paredReceiptFor(manifest(EVO)), operatorHasInFlight: true,
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
  ok("v9: local state does not launder a contradicting receipt into IN_FLIGHT",
    rogueMine.state === STATES.UNDETERMINED);
});

// ---------------------------------------------------------------------------
// v8: the pool document answers by itself
// ---------------------------------------------------------------------------
withLedger("v8", () => {
  const forming = classifyPool({ contractId: GC, pool: v8Pool(FORMING_HASH), poolId: GP, receipt: null,
    // receipt-less: duty 6 is not reached, so no owners are needed here and
    // supplying them would hide that a pool with no receipt classifies normally
  });
  ok("v8: a forming proTxHash means FORMING", forming.state === STATES.FORMING);

  const flipped = classifyPool({ contractId: GC, pool: v8Pool(REAL_HASH), poolId: GP, receipt: null,
    // receipt-less: duty 6 is not reached, so no owners are needed here and
    // supplying them would hide that a pool with no receipt classifies normally
  });
  ok("v8: a real proTxHash with no receipt is IN_FLIGHT", flipped.state === STATES.IN_FLIGHT);

  // BYTES ONLY at the pool-hash read (closing wave, FA1): Buffer.from("<32 chars>") is 32
  // UTF-8 bytes, so a schema-invalid STRING hash classified IN_FLIGHT and backingNode
  // established a node from it. Both string spellings are refused, and the honest state is
  // UNDETERMINED, never a definite lifecycle read off a malformed document.
  for (const [label, s] of [["a 32-char string", "B".repeat(32)], ["a 64-char hex string", "ab".repeat(32)]]) {
    const strung = classifyPool({ contractId: GC, pool: v8Pool(s), poolId: GP, receipt: null });
    ok(`v8: ${label} proTxHash is UNDETERMINED, not a coerced lifecycle`,
      strung.state === STATES.UNDETERMINED && /byte array/.test(strung.reason));
    const bn = backingNode({ pool: v8Pool(s) });
    ok(`v8: backingNode refuses ${label} proTxHash rather than establishing a node`,
      bn.known === false && /byte array/.test(bn.why));
  }

  const done = classifyPool({ contractId: GC, pool: v8Pool(REAL_HASH), poolId: GP, receipt: unparedReceiptFor(manifest()),
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
  ok("v8: a verifying receipt still wins", done.state === STATES.COMPLETED);

  // a soundness-review finding: on the flip ledgers a structurally verifying receipt counts ONLY when the
  // pool's own assertion agrees; each disagreement below is a contradiction to resolve,
  // never COMPLETED and never absence
  {
    const formingWithReceipt = classifyPool({ contractId: GC, pool: v8Pool(FORMING_HASH),
      poolId: GP, receipt: unparedReceiptFor(manifest()),
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
    ok("a soundness-review finding: a verifying receipt over a still-forming v8 pool is a contradiction",
      formingWithReceipt.state === STATES.UNDETERMINED
      && /does NOT verify/.test(formingWithReceipt.reason)
      && /still forming/.test(formingWithReceipt.reason));
    ok("a soundness-review finding: and abandon refuses over it", mayAbandon(formingWithReceipt).ok === false);
    const otherHash = classifyPool({ contractId: GC, pool: v8Pool(Buffer.alloc(32, 0xbb)),
      poolId: GP, receipt: unparedReceiptFor(manifest()),
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
    ok("a soundness-review finding: a receipt naming a different node than the live pool is a contradiction",
      otherHash.state === STATES.UNDETERMINED && /different node/.test(otherHash.reason));
    // ...and the a soundness-review finding agreement arm holds the POOL side to bytes too (closing wave, FA1):
    // a string pool hash beside a fully verifying receipt used to coerce through
    // Buffer.from and could even AGREE with a matching receipt; it is a malformed
    // document, so the state is the contradiction, never COMPLETED
    const strungPool = classifyPool({ contractId: GC, pool: v8Pool("C".repeat(32)),
      poolId: GP, receipt: unparedReceiptFor(manifest()),
      receiptOwnerId: OA, poolOwnerId: OA,
    });
    ok("a soundness-review finding: a STRING pool hash beside a verifying receipt is a contradiction, not COMPLETED",
      strungPool.state === STATES.UNDETERMINED && /not a 32-byte array/.test(strungPool.reason));
    const noReceiptHash = classifyPool({ contractId: GC, pool: v8Pool(REAL_HASH), poolId: GP,
      receipt: { ...unparedReceiptFor(manifest()), proTxHash: undefined },
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
    // the refusal MOVED UPSTREAM with a soundness-review finding: the shared check now rejects a missing or
    // wrong-length proTxHash on every receipt ledger, so this case is caught before the
    // classifier's own v8 comparison ever runs. Same fail-closed outcome, earlier and on
    // both ledgers, so the assertion accepts either wording.
    ok("a soundness-review finding: a receipt missing its proTxHash fails closed on v8",
      noReceiptHash.state === STATES.UNDETERMINED
      // moved upstream again by the pass-13 required-shape gate, which names the field
      && /(missing or malformed|missing or not 32 bytes|missing required field proTxHash)/.test(noReceiptHash.reason));
  }

  ok("v8: a missing proTxHash is UNDETERMINED rather than assumed forming",
    classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: null,
    // receipt-less: duty 6 is not reached, so no owners are needed here and
    // supplying them would hide that a pool with no receipt classifies normally
  }).state === STATES.UNDETERMINED);
  ok("v8: a short proTxHash is UNDETERMINED",
    classifyPool({ contractId: GC, pool: v8Pool(Buffer.alloc(31, 0)), poolId: GP, receipt: null,
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  })
      .state === STATES.UNDETERMINED);
});

// ---------------------------------------------------------------------------
// abandon, the guard that had no v9 equivalent
// ---------------------------------------------------------------------------
withLedger("v9", () => {
  const done = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: paredReceiptFor(manifest()),
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
  ok("abandon is refused for a COMPLETED pool", mayAbandon(done).ok === false);
  ok("and the refusal explains the orphaning risk", /orphan real state/.test(mayAbandon(done).reason));

  const none = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: null,
    // receipt-less: duty 6 is not reached, so no owners are needed here and
    // supplying them would hide that a pool with no receipt classifies normally
  });
  ok("abandon is allowed for a pool with no completion record", mayAbandon(none).ok === true);

  const rogue = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: paredReceiptFor(manifest(EVO)),
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
  ok("abandon is refused while a contradicting receipt is unresolved", mayAbandon(rogue).ok === false);
});
withLedger("v8", () => {
  ok("v8: abandon allowed while forming",
    mayAbandon(classifyPool({ contractId: GC, pool: v8Pool(FORMING_HASH), poolId: GP, receipt: null,
    // receipt-less: duty 6 is not reached, so no owners are needed here and
    // supplying them would hide that a pool with no receipt classifies normally
  })).ok === true);
  ok("v8: abandon allowed pre-receipt after the flip (the v8 command adds its own live guard)",
    mayAbandon(classifyPool({ contractId: GC, pool: v8Pool(REAL_HASH), poolId: GP, receipt: null,
    // receipt-less: duty 6 is not reached, so no owners are needed here and
    // supplying them would hide that a pool with no receipt classifies normally
  })).ok === true);
});

// ---------------------------------------------------------------------------
// the admission rule
// ---------------------------------------------------------------------------
// THE ASYMMETRY IS THE POINT. Pledging fails CLOSED when the ledger cannot say a pool is
// open, because a pledge into an abandoned or in-flight formation strands a member's
// collateral. Cancelling fails OPEN for the same uncertainty, because a client that refuses
// to let someone leave has turned not-knowing into lock-in. These cases fail if a later
// change makes the two symmetric in either direction.
withLedger("v9", () => {
  const open = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: null,
    // receipt-less: duty 6 is not reached, so no owners are needed here and
    // supplying them would hide that a pool with no receipt classifies normally
  });
  const done = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: paredReceiptFor(manifest()),
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });

  const bare = admissionVerdict({ classification: open, poolIdStr: GP });
  ok("v9: a merely discovered pool REFUSES admission", bare.ok === false);
  ok("v9: and the refusal names the three indistinguishable states",
    /open, in flight, or abandoned/.test(bare.reason));
  ok("v9: and it tells the member exactly how to proceed with the operator's instruction",
    bare.reason.includes(`TEGARA_PARTICIPATE=${GP}`));

  const invited = admissionVerdict({ classification: open, poolIdStr: GP, participateEnv: GP });
  ok("v9: the advertised participate instruction admits", invited.ok === true);
  ok("v9: and the caller can tell it went through on an instruction rather than on evidence",
    invited.viaInstruction === true);

  // THE INSTRUCTION MUST NAME THIS POOL. A blanket flag would be set once and then satisfy
  // every later pledge, including one against a pool the member merely found, which is
  // precisely the autonomous admission the rule refuses.
  ok("v9: an instruction naming a DIFFERENT pool does not admit",
    admissionVerdict({ classification: open, poolIdStr: GP, participateEnv: OTHER }).ok === false);
  ok("v9: an empty instruction does not admit",
    admissionVerdict({ classification: open, poolIdStr: GP, participateEnv: "" }).ok === false);

  // completion is a fact, not a judgement, so no instruction overrides it
  ok("v9: a COMPLETED pool refuses even with the instruction",
    admissionVerdict({ classification: done, poolIdStr: GP, participateEnv: GP }).ok === false);
  const rogue = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: paredReceiptFor(manifest(EVO)),
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
  ok("v9: a contradicting receipt refuses even with the instruction",
    admissionVerdict({ classification: rogue, poolIdStr: GP, participateEnv: GP }).ok === false);
});
withLedger("v8", () => {
  const forming = classifyPool({ contractId: GC, pool: v8Pool(FORMING_HASH), poolId: GP, receipt: null,
    // receipt-less: duty 6 is not reached, so no owners are needed here and
    // supplying them would hide that a pool with no receipt classifies normally
  });
  ok("v8: a forming pool admits with no instruction, because the pool itself says it is open",
    admissionVerdict({ classification: forming, poolIdStr: GP }).ok === true);
});
ok("admission refuses a missing classification", admissionVerdict({ poolIdStr: GP }).ok === false);

// ---------------------------------------------------------------------------
// which node does this pool back, and the refusal that guards a written claim
// ---------------------------------------------------------------------------
const NODE_HEX = "aa".repeat(32);
withLedger("v8", () => {
  ok("v8: a flipped pool names its node from the pool itself",
    backingNode({ pool: v8Pool(REAL_HASH) }).hex === NODE_HEX);
  ok("v8: a FORMING pool has no node yet, and says so rather than returning the placeholder",
    backingNode({ pool: v8Pool(FORMING_HASH) }).known === false);
  ok("v8: and the reason names the forming state",
    /still forming/.test(backingNode({ pool: v8Pool(FORMING_HASH) }).why));
});
withLedger("v9", () => {
  const r = { ...paredReceiptFor(manifest()), proTxHash: Buffer.alloc(32, 0xaa) };
  ok("v9: a VERIFIED receipt names the node",
    backingNode({ pool: v9Pool(), receipt: r, receiptOk: true }).hex === NODE_HEX);
  // the case that matters: the receipt is present but did not verify
  ok("v9: an UNVERIFIED receipt establishes nothing, even though it carries a proTxHash",
    backingNode({ pool: v9Pool(), receipt: r, receiptOk: false }).known === false);
  ok("v9: and the reason says the node is not established rather than absent",
    /not established on the ledger/.test(backingNode({ pool: v9Pool(), receipt: r, receiptOk: false }).why));
  ok("v9: no receipt at all is unknown", backingNode({ pool: v9Pool() }).known === false);
  ok("v9: the pool's own fields are never consulted, so a stray proTxHash on it is ignored",
    backingNode({ pool: { ...v9Pool(), proTxHash: Buffer.alloc(32, 0xbb) } }).known === false);
  // the receipt arm holds the hash to BYTES even when the caller claims receiptOk (closing
  // wave, FA1): this arm is deliberately redundant with the shared check for exactly this
  // reason, a caller that verified nothing (or with an older check) must not be able to
  // turn a schema-invalid string into an established node here, the same rule as the
  // forming-namespace refusal beside it
  for (const [label, s] of [["a 32-char string", "D".repeat(32)], ["a 64-char hex string", "ab".repeat(32)]]) {
    ok(`v9: ${label} receipt hash is refused even under a claimed receiptOk`,
      (() => { const b = backingNode({ pool: v9Pool(),
        receipt: { ...r, proTxHash: s }, receiptOk: true });
      return b.known === false && /byte array/.test(b.why); })());
  }
});

// THE EXECUTABLE INVARIANT. A caller that writes a statement about a node must crash rather
// than publish an unestablished one, so this is asserted rather than left to each call site.
{
  let threw = false;
  try { requireBackingNode({ known: false, why: "nope" }, "record a vote observation"); } catch (e) {
    threw = /refusing to record a vote observation: nope/.test(e.message);
  }
  ok("requireBackingNode THROWS on an unknown node", threw);
  ok("requireBackingNode returns the hex when known",
    requireBackingNode({ known: true, hex: NODE_HEX }, "x") === NODE_HEX);
  let threwShort = false;
  try { requireBackingNode({ known: true, hex: "aa" }, "x"); } catch { threwShort = true; }
  ok("requireBackingNode rejects a short hex even when marked known", threwShort);
  // A 64-CHARACTER STRING IS NOT AUTOMATICALLY A NODE ID. A length-only check accepts any
  // text of the right size, and a caller-assembled result can carry anything, so the format
  // is checked rather than the length.
  let threwNonHex = false;
  try { requireBackingNode({ known: true, hex: "z".repeat(64) }, "x"); } catch { threwNonHex = true; }
  ok("requireBackingNode rejects a 64-character NON-HEX string", threwNonHex);
  let threwUpper = false;
  try { requireBackingNode({ known: true, hex: "AA".repeat(32) }, "x"); } catch { threwUpper = true; }
  ok("requireBackingNode rejects uppercase hex, so one canonical form reaches a document", threwUpper);
}

// ---------------------------------------------------------------------------
// never throws
// ---------------------------------------------------------------------------
for (const [name, args] of [
  ["null pool", { contractId: GC, pool: null, poolId: GP }],
  ["pool with a throwing getter", { contractId: GC, poolId: GP,
    pool: { get proTxHash() { throw new Error("boom"); } } }],
  ["garbage receipt", { contractId: GC, pool: v9Pool(), poolId: GP, receipt: 42 }],
]) {
  let threw = false, res = null;
  try { res = withLedger("v9", () => classifyPool(args)); } catch { threw = true; }
  ok(`${name}: classified without throwing`, !threw && res && res.state === STATES.UNDETERMINED);
}
ok("mayAbandon refuses a missing classification", mayAbandon(null).ok === false);

// ---- a soundness-review finding at the CLASSIFIER and the node producer, on the immutable ledger ----
// The v9 path skips the classifier's own hash comparison (the pool asserts nothing), so
// the reserved namespace has to be refused by the shared check and, defensively, by the
// one producer of node identities.
{
  const forming = Buffer.concat([Buffer.alloc(16, 0), Buffer.alloc(16, 7)]);
  withLedger("v9", () => {
    const r = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP,
      receipt: { ...paredReceiptFor(manifest()), proTxHash: forming },
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
    ok("a soundness-review finding: a reserved-namespace receipt is NOT completion on the immutable ledger",
      r.state !== STATES.COMPLETED);
    const node = backingNode({ pool: v9Pool(),
      receipt: { ...paredReceiptFor(manifest()), proTxHash: forming }, receiptOk: true });
    ok("a soundness-review finding: backingNode refuses the reserved namespace even when told the receipt verified",
      node.known === false && /forming/i.test(node.why || ""));
  });
}

// ---------------------------------------------------------------------------
// THE GUARDS COMPOSE FOR EVERY RECEIPT-PRESENT REFUSAL, not just the one whose reason
// happens to carry a particular phrase (pass 12, F1).
//
// Both guards used to test the reason TEXT for "does NOT verify". Request 3 had added a
// second receipt-present refusal, UNDETERMINED because the caller supplied no owners,
// whose reason does not contain that phrase, so admission returned {ok:true,
// viaInstruction:true} and abandonment returned {ok:true} for a pool holding an
// unverified receipt. The cases below drive EACH receipt-present refusal shape through
// both guards, so a third shape added later is covered the day it is written rather
// than the day someone notices.
// ---------------------------------------------------------------------------
withLedger("v9", () => {
  const pool = v9Pool();
  const shapes = [
    ["owners ABSENT (the Request 3 refusal, whose reason lacks the old phrase)",
      { contractId: GC, pool, poolId: GP, receipt: paredReceiptFor(manifest()) }],
    ["owners MISMATCHED (the classic refusal)",
      { contractId: GC, pool, poolId: GP, receipt: paredReceiptFor(manifest()),
        receiptOwnerId: OA, poolOwnerId: OB }],
    ["a receipt that fails a NON-owner duty",
      { contractId: GC, pool, poolId: GP, receipt: paredReceiptFor(manifest(EVO)),
        receiptOwnerId: OA, poolOwnerId: OA }],
  ];
  for (const [name, args] of shapes) {
    const cls = classifyPool(args);
    ok(`receipt-present refusal, ${name}: classification is not COMPLETED`,
      cls.state !== STATES.COMPLETED && cls.receiptOk !== true);
    ok(`...and it reports receiptPresent structurally`, cls.receiptPresent === true);
    ok(`...and ADMISSION refuses it even with a matching participate instruction`,
      admissionVerdict({ classification: cls, poolIdStr: GP, participateEnv: GP }).ok === false);
    ok(`...and ABANDON refuses it`, mayAbandon(cls).ok === false);
  }
  // and the receipt-LESS pool is untouched: the instruction still admits it, and
  // abandoning it is still allowed. Without this pair the fix above could be "refuse
  // everything", which would pass every assertion in the loop and break the product.
  const none = classifyPool({ contractId: GC, pool, poolId: GP, receipt: null });
  ok("a receipt-LESS pool still reports receiptPresent false", none.receiptPresent === false);
  ok("...and admission still admits it on a matching instruction",
    admissionVerdict({ classification: none, poolIdStr: GP, participateEnv: GP }).ok === true);
  ok("...and abandon is still allowed for it", mayAbandon(none).ok === true);

  // A CLASSIFICATION WITHOUT THE FLAG FAILS CLOSED (pre-commit check on this repair). Both
  // guards are exported and take an object from the caller, so one built by hand or left
  // over from before the field existed must not be read as "no receipt". Only an explicit
  // false licenses proceeding.
  const legacy = { state: STATES.UNDETERMINED, receiptOk: false,
    reason: "a stale classification carrying no receiptPresent field" };
  ok("a classification with NO receiptPresent field is refused by admission",
    admissionVerdict({ classification: legacy, poolIdStr: GP, participateEnv: GP }).ok === false);
  ok("...and by abandon", mayAbandon(legacy).ok === false);
});

console.log(`poolLifecycleTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
