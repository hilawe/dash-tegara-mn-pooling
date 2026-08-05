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
  // here was itself a fixture-producibility gap the a soundness-review finding binding exposed
  return { poolId: GP, proTxHash: Buffer.from(m.realHash, "hex"), slotIndex: 0,
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
  // a malformed-length hash is a deliberate fixture in one case below, and isFormingHash
  // throws on it, so the status is only derived when the hash is well formed
  ...(Buffer.isBuffer(hash) && hash.length === 32
    ? { status: core.isFormingHash(hash) ? "forming" : "live" } : {}) });

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
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
  ok("v9: receipt-less and no local state is UNDETERMINED, not 'open'", none.state === STATES.UNDETERMINED);
  ok("v9: and it says why, naming the three states it cannot separate",
    /open, in flight and\s+abandoned are the same document/.test(none.reason));

  const mine = classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: null, operatorHasInFlight: true,
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
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
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
  ok("v8: a forming proTxHash means FORMING", forming.state === STATES.FORMING);

  const flipped = classifyPool({ contractId: GC, pool: v8Pool(REAL_HASH), poolId: GP, receipt: null,
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  });
  ok("v8: a real proTxHash with no receipt is IN_FLIGHT", flipped.state === STATES.IN_FLIGHT);

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
      && /(missing or malformed|missing or not 32 bytes)/.test(noReceiptHash.reason));
  }

  ok("v8: a missing proTxHash is UNDETERMINED rather than assumed forming",
    classifyPool({ contractId: GC, pool: v9Pool(), poolId: GP, receipt: null,
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
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
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
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
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
  })).ok === true);
  ok("v8: abandon allowed pre-receipt after the flip (the v8 command adds its own live guard)",
    mayAbandon(classifyPool({ contractId: GC, pool: v8Pool(REAL_HASH), poolId: GP, receipt: null,
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
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
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
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
    // duty 6 now REQUIRES the owners (Request 3); matching ids so the binding passes
    // and each case still exercises the property its name claims
    receiptOwnerId: OA, poolOwnerId: OA,
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

console.log(`poolLifecycleTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
