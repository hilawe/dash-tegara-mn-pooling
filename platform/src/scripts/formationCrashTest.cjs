/**
 * The failure-injection crash matrix for the formation RECEIPT state machine (round 1's
 * Lens-3 recommendation, and the mechanical base round 4 looks for above), on BOTH receipt
 * ledgers: v8 (the default, pool flips live) and v9 via TEGARA_HARNESS_LEDGER=v9
 * (immutable pool, receipt publication only, no flip). It does for the receipt flow what
 * envStoreCrashTest does for the state store: stop REAL execution at every mutating
 * boundary (each Platform op AND each local durable write), then assert the state either
 * RESUMES to the same receipt or STOPS LOUDLY without clearing recovery evidence, never a
 * silent wrong state.
 *
 * Mechanism: a child process runs the real formation.cjs with `dash` swapped for an
 * in-memory mock ledger (formationMockDash.cjs) and a fault counter that hard-exits 97
 * after boundary K (skipping every finally, exactly like a real crash, so the op lock
 * stays held and drafts stay frozen). The parent, per K: seed a fresh forming pool,
 * `complete` with a crash at K, then DRIVE RECOVERY the way an operator would (clear a
 * crash-held op lock, re-run `complete`, and run `receipt`), and assert the invariants.
 *
 * Independent cases (round 3's awkward-to-run-live re-check items) follow the matrix:
 * two stale op-lock waiters, draft recovery against a stale .val.prev, and an existing
 * receipt against a wrong/forming pool.
 *
 * Offline, plain node, no devnet. Exits non-zero on the first failure.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const { Identifier } = require("@dashevo/wasm-dpp");
const core = require("./formationCore.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-fcx-"));
const ENV_PATH = path.join(ROOT, "env.local");
const STATE_DIR = `${ENV_PATH}.state`;
const LEDGER_PATH = path.join(ROOT, "ledger.json");
const CHILD = path.join(__dirname, "formationCrashChild.cjs");

const newId = () => Identifier.from(crypto.randomBytes(32)).toString();
const SCRIPT_A = "76a914" + "11".repeat(20) + "88ac"; // 25-byte P2PKH-shaped, even hex
const SCRIPT_B = "76a914" + "22".repeat(20) + "88ac";

// stable cast so every run in a matrix targets the same pool/owners
const OP = newId();
const F1 = newId(), F2 = newId();
const POOL = newId();
const CONTRACT = newId(); // allocationPreimage requires a real base58 32-byte contract id

// THE LEDGER UNDER TEST. Parameterised rather than hardcoded so this harness runs against
// both receipt ledgers: v8 (the live default, pool flips) and v9 (immutable pool, receipt
// publication only; see V9_MIGRATION_PLAN.md). Every ledger-dependent fixture and oracle
// below branches on PARED, and the PARENT's own LEDGER is pinned to the same value so the
// shared receipt-to-pool check used by the v9 oracle answers for the ledger under test.
const HARNESS_LEDGER = process.env.TEGARA_HARNESS_LEDGER || "v8";
const PARED = HARNESS_LEDGER === "v9";
process.env.LEDGER = HARNESS_LEDGER;
const { checkReceiptAgainstPool } = require("./receiptPoolCheck.cjs");

const seedLedger = () => ({
  contractId: CONTRACT, contractOwner: OP,
  docs: [
    // the v9 pool is IMMUTABLE and live-state-free: no proTxHash, no status, no
    // operatorIdentityId, and the REQUIRED targetDuffs the paring moved onto it. The book
    // already multiplies to the target (2 x 500 DASH), so the shared check passes without
    // changing the numbers.
    { id: POOL, type: "pool", ownerId: OP, data: PARED
      ? { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
        targetDuffs: 100000000000, slotDuffs: 50000000000, slotCount: 2, $createdAt: 1 }
      : { proTxHash: "00".repeat(16) + crypto.randomBytes(16).toString("hex"), // forming placeholder
        slotIndex: 0, nodeType: "regular", operatorIdentityId: Buffer.from(Identifier.from(OP).toBuffer()).toString("hex"),
        operatorFeeBps: 2000, status: "forming", slotDuffs: 50000000000, slotCount: 2, $createdAt: 1 } },
    { id: newId(), type: "pledgeSlot", ownerId: F1, data: {
      poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"), slotNo: 0, rewardScript: SCRIPT_A, $createdAt: 10 } },
    { id: newId(), type: "pledgeSlot", ownerId: F2, data: {
      poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"), slotNo: 1, rewardScript: SCRIPT_B, $createdAt: 20 } },
  ],
});

const writeSeed = () => {
  fs.rmSync(STATE_DIR, { recursive: true, force: true });
  fs.rmSync(ENV_PATH, { force: true });
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(ENV_PATH,
    `MNEMONIC=m\nIDENTITY_ID=${OP}\nCONTRACT_ID=${CONTRACT}\nCONTRACT_V8_ID=${CONTRACT}\n` +
    `CONTRACT_V9_ID=${CONTRACT}\nFUNDER_ID=${F1}\nFUNDER2_ID=${F2}\n`);
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(seedLedger(), null, 1));
};

const REAL_HASH = "dd" + "56".repeat(31); // a non-forming 32-byte hash

const runChild = (args, crashAfter, extraEnv = {}) => {
  const env = { ...process.env, TEGARA_ENV_PATH: ENV_PATH, TEGARA_MOCK_LEDGER: LEDGER_PATH,
    LEDGER: HARNESS_LEDGER, NETWORK: "regtest", FORMATION_ALLOW_UNVERIFIED: "demo", ...extraEnv };
  if (crashAfter !== undefined) env.TEGARA_MOCK_CRASH_AFTER = String(crashAfter);
  try {
    const out = execFileSync("node", [CHILD, ...args], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status, out: (e.stdout || "") + (e.stderr || "") };
  }
};

// INDEPENDENT expected receipt (round-4 + re-check): the oracle must NOT reuse the code's
// own output NOR the same formationCore helpers it validates (a shared-helper defect would
// otherwise agree with itself). The allocation preimage is rebuilt here from the canonical
// spec directly: the fixed-shape array, owners sorted by their DECODED 32-byte id (via
// wasm-dpp's Identifier, a different decoder than formationCore.decodeId32), JSON.stringify,
// UTF-8, and node's own sha256. If this and formationCore ever disagree, the harness fails,
// which is the point.
const EXPECTED = (() => {
  const owners = [
    { owner: F1, amountDuffs: "50000000000", bps: 5000, script: SCRIPT_A },
    { owner: F2, amountDuffs: "50000000000", bps: 5000, script: SCRIPT_B },
  ].sort((a, b) => Buffer.compare(
    Buffer.from(Identifier.from(a.owner).toBuffer()), Buffer.from(Identifier.from(b.owner).toBuffer())));
  const arr = ["tegara-completion-allocation", 1, CONTRACT, POOL, "100000000000",
    owners.map((o) => [o.owner, o.amountDuffs, o.bps, o.script])];
  const rowsBytes = Buffer.from(JSON.stringify(arr), "utf8");
  return {
    proTxHash: REAL_HASH, slotIndex: 0,
    // the pared receipt DROPS nodeType, operatorFeeBps and targetDuffs (the immutable pool
    // pins them); everything else is identical. The expectation stays INDEPENDENT either
    // way, rebuilt from the canonical spec, never derived through production code.
    ...(PARED ? {} : { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 }),
    formatVersion: 1, participantCount: 2,
    l1Verification: "demo-unverified", verificationMethodVersion: 1,
    allocationRows: rowsBytes.toString("hex"),
    allocationHash: crypto.createHash("sha256").update(rowsBytes).digest("hex"),
  };
})();

// assert an on-ledger receipt matches the INDEPENDENT expectation field by field. On the
// pared ledger the three pool-pinned fields must be ABSENT, not merely unchecked: a receipt
// still carrying one would have been schema-rejected by the real contract.
const assertReceiptCorrect = (label, r) => {
  if (!r) { ok(`${label}: a receipt exists`, false); return; }
  const d = r.data;
  ok(`${label}: owner is the operator`, r.ownerId === OP);
  ok(`${label}: poolId`, Identifier.from(Buffer.from(d.poolId, "hex")).toString() === POOL);
  ok(`${label}: proTxHash == REAL_HASH`, d.proTxHash === EXPECTED.proTxHash);
  ok(`${label}: slotIndex`, Number(d.slotIndex) === EXPECTED.slotIndex);
  if (PARED) {
    ok(`${label}: nodeType absent (pared)`, d.nodeType === undefined);
    ok(`${label}: operatorFeeBps absent (pared)`, d.operatorFeeBps === undefined);
    ok(`${label}: targetDuffs absent (pared)`, d.targetDuffs === undefined);
  } else {
    ok(`${label}: nodeType`, d.nodeType === EXPECTED.nodeType);
    ok(`${label}: operatorFeeBps`, Number(d.operatorFeeBps) === EXPECTED.operatorFeeBps);
    ok(`${label}: targetDuffs`, Number(d.targetDuffs) === EXPECTED.targetDuffs);
  }
  ok(`${label}: formatVersion`, Number(d.formatVersion) === EXPECTED.formatVersion);
  ok(`${label}: participantCount`, Number(d.participantCount) === EXPECTED.participantCount);
  ok(`${label}: l1Verification`, d.l1Verification === EXPECTED.l1Verification);
  ok(`${label}: verificationMethodVersion`, Number(d.verificationMethodVersion) === EXPECTED.verificationMethodVersion);
  ok(`${label}: allocationRows`, d.allocationRows === EXPECTED.allocationRows);
  ok(`${label}: allocationHash`, d.allocationHash === EXPECTED.allocationHash);
};
// the completion record must name exactly REAL_HASH (round-4: poolLive only checked
// non-forming). On v8 the pool itself answers. On v9 the pool has NO equivalent and this
// must not weaken to "a receipt exists": the v9 form is that ONE receipt exists, VERIFIES
// against the pool through the shared five-duty check, and names exactly REAL_HASH
// (checking merely present is the round-4 mistake one document over).
const poolLiveUnderRealHash = () => {
  const p = ledger().docs.find((d) => d.id === POOL);
  if (!PARED) return p.data.status === "live" && p.data.proTxHash === REAL_HASH;
  const rs = receipts();
  if (rs.length !== 1 || rs[0].data.proTxHash !== REAL_HASH) return false;
  const d = rs[0].data;
  const verdict = checkReceiptAgainstPool({
    contractId: CONTRACT,
    receipt: {
      poolId: Buffer.from(d.poolId, "hex"), proTxHash: Buffer.from(d.proTxHash, "hex"),
      slotIndex: Number(d.slotIndex), formatVersion: Number(d.formatVersion),
      allocationRows: Buffer.from(d.allocationRows, "hex"),
      allocationHash: Buffer.from(d.allocationHash, "hex"),
      participantCount: Number(d.participantCount),
      l1Verification: d.l1Verification, verificationMethodVersion: Number(d.verificationMethodVersion),
    },
    pool: p.data, poolId: POOL,
  });
  return verdict.ok === true;
};

// snapshot / restore the whole local + ledger state, so a receipt-command matrix can
// replay from one intermediate seed (live-no-receipt, or half-finalized) per boundary
const SNAP = path.join(ROOT, "snap");
const snapshot = () => {
  fs.rmSync(SNAP, { recursive: true, force: true });
  fs.mkdirSync(SNAP);
  fs.copyFileSync(ENV_PATH, path.join(SNAP, "env.local"));
  fs.copyFileSync(LEDGER_PATH, path.join(SNAP, "ledger.json"));
  fs.cpSync(STATE_DIR, path.join(SNAP, "state"), { recursive: true });
};
const restore = () => {
  fs.rmSync(STATE_DIR, { recursive: true, force: true });
  fs.copyFileSync(path.join(SNAP, "env.local"), ENV_PATH);
  fs.copyFileSync(path.join(SNAP, "ledger.json"), LEDGER_PATH);
  fs.cpSync(path.join(SNAP, "state"), STATE_DIR, { recursive: true });
};

const ledger = () => JSON.parse(fs.readFileSync(LEDGER_PATH, "utf8"));
const receipts = () => ledger().docs.filter((d) => d.type === "completionReceipt");
const clearOpLock = () => { // the operator's documented manual cleanup after a verified-dead run
  for (const d of fs.existsSync(STATE_DIR) ? fs.readdirSync(STATE_DIR) : []) {
    if (d.startsWith("oplock-") || d === "env.lock") fs.rmSync(path.join(STATE_DIR, d), { recursive: true, force: true });
  }
};
// the ACTIVE manifest / draft in-flight evidence, distinct from FORMATION_DONE_ (which
// is the RETAINED record and must survive). The 20-hex suffix bound separates them, since
// "DONE_..." is not 20 hex chars followed by .val.
const hasInFlightEvidence = () => fs.readdirSync(STATE_DIR).some((f) =>
  /^FORMATION_[0-9A-F]{20}\.val$/.test(f) || /^RECEIPT_DRAFT_[0-9A-F]{20}\.val$/.test(f));

// cross-check the INDEPENDENT oracle against formationCore (they must agree; if a shared
// defect ever makes them disagree, this fails loudly rather than the matrix passing
// vacuously against a wrong shared value)
{
  const manifest = { poolId: POOL, target: "100000000000", owners: [
    { owner: F1, amountDuffs: "50000000000", bps: 5000, rewardScriptHex: SCRIPT_A },
    { owner: F2, amountDuffs: "50000000000", bps: 5000, rewardScriptHex: SCRIPT_B }] };
  const coreHash = core.allocationHash(core.allocationPreimage(CONTRACT, manifest)).toString("hex");
  ok("independent oracle agrees with formationCore.allocationHash", coreHash === EXPECTED.allocationHash);
}

// the mock's schema validator actually catches the false-green the round-4 review named
// (a raw string passed where a byteArray is required), in the SHAPE of the ledger under
// test: the pared receipt drops the three pool-pinned fields, and carrying one anyway must
// be rejected the way additionalProperties:false would reject it
{
  const mock = require("./formationMockDash.cjs");
  const good = {
    poolId: Buffer.alloc(32, 1), proTxHash: Buffer.alloc(32, 2), slotIndex: 0,
    ...(PARED ? {} : { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 }),
    formatVersion: 1, allocationRows: Buffer.from("[]"), allocationHash: Buffer.alloc(32, 3),
    participantCount: 2, l1Verification: "demo-unverified", verificationMethodVersion: 1 };
  let threw = false;
  try { mock.validateReceiptProps({ ...good, allocationRows: "not-bytes" }); } catch { threw = true; }
  ok("mock schema rejects a raw-string allocationRows (the false-green case)", threw);
  let okPass = true;
  try { mock.validateReceiptProps(good); } catch { okPass = false; }
  ok("mock schema accepts a well-formed receipt", okPass);
  if (PARED) {
    let rejectedUnpared = false;
    try { mock.validateReceiptProps({ ...good, nodeType: "regular" }); } catch { rejectedUnpared = true; }
    ok("pared mock schema rejects a receipt still carrying nodeType", rejectedUnpared);
    // and the POOL schema: the v8 shape (placeholder hash) must be refused, a one-sided
    // slot book must be refused, and the v9 shape must pass
    const v9pool = { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
      targetDuffs: 100000000000, slotDuffs: 50000000000, slotCount: 2 };
    let poolOk = true;
    try { mock.validatePoolProps(v9pool); } catch { poolOk = false; }
    ok("immutable-pool mock schema accepts the v9 pool shape", poolOk);
    let rejectedHash = false;
    try { mock.validatePoolProps({ ...v9pool, proTxHash: Buffer.alloc(32, 0) }); } catch { rejectedHash = true; }
    ok("immutable-pool mock schema rejects a pool carrying proTxHash", rejectedHash);
    let rejectedOneSided = false;
    try { mock.validatePoolProps({ slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
      targetDuffs: 100000000000, slotDuffs: 50000000000 }); } catch { rejectedOneSided = true; }
    ok("immutable-pool mock schema rejects a one-sided slot book", rejectedOneSided);
    // the numeric bounds must mirror the published schema exactly (vetting round,
    // finding 4): over-max target, zero slot size, over-max slot count all refused
    let overTarget = false, zeroSlot = false, overCount = false;
    try { mock.validatePoolProps({ ...v9pool, targetDuffs: 400000000001 }); } catch { overTarget = true; }
    try { mock.validatePoolProps({ ...v9pool, slotDuffs: 0 }); } catch { zeroSlot = true; }
    try { mock.validatePoolProps({ ...v9pool, slotCount: 513 }); } catch { overCount = true; }
    ok("mock pool schema rejects targetDuffs above the contract maximum", overTarget);
    ok("mock pool schema rejects a zero slotDuffs", zeroSlot);
    ok("mock pool schema rejects slotCount above 512", overCount);

    // the two TRANSITION-level v9 constraints (convergence-2 pass, major E), enforced by
    // the mock's broadcast through the same exported check tested here (the async client
    // surface cannot be driven from this sync orchestrator, the props-validator pattern
    // one block up): the published pool is owner-only at creation
    // (creationRestrictionMode 1), and the pared receipt is unique by
    // (proTxHash, slotIndex) (bySlot), not only by pool (byPool)
    writeSeed();
    const seededLedger = ledger();
    const poolData = { slotIndex: 1, nodeType: "regular", operatorFeeBps: 2000,
      targetDuffs: 100000000000, slotDuffs: 50000000000, slotCount: 2 };
    const threwWith = (rec) => {
      try { mock.assertCreateAllowed(seededLedger, rec); return null; } catch (e) { return e.message; }
    };
    ok("mock refuses pool creation by a non-owner identity (creation restriction mode Owner Only)",
      /creation restriction mode Owner Only/.test(threwWith({ type: "pool", ownerId: F1, data: poolData }) || ""));
    ok("mock accepts pool creation by the contract owner",
      threwWith({ type: "pool", ownerId: OP, data: poolData }) === null);
    const receiptData = { poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
      proTxHash: REAL_HASH, slotIndex: 0 };
    ok("mock accepts the first receipt for a (proTxHash, slotIndex) pair",
      threwWith({ type: "completionReceipt", ownerId: OP, data: receiptData }) === null);
    const OTHER_POOL = Identifier.from(crypto.createHash("sha256").update("other-pool").digest()).toString();
    const withReceipt = { ...seededLedger, docs: [...seededLedger.docs,
      { id: "seeded-receipt", type: "completionReceipt", ownerId: OP, data: receiptData }] };
    const dupSlot = { type: "completionReceipt", ownerId: OP, data: { ...receiptData,
      poolId: Buffer.from(Identifier.from(OTHER_POOL).toBuffer()).toString("hex") } };
    ok("mock refuses a second receipt claiming the same (proTxHash, slotIndex) from another pool (bySlot)",
      /duplicate unique index bySlot/.test((() => {
        try { mock.assertCreateAllowed(withReceipt, dupSlot); return ""; } catch (e) { return e.message; }
      })()));
    const otherSlot = { type: "completionReceipt", ownerId: OP, data: { ...receiptData, slotIndex: 1,
      poolId: Buffer.from(Identifier.from(OTHER_POOL).toBuffer()).toString("hex") } };
    ok("mock accepts the same node hash at a DIFFERENT slot index (bySlot is the pair, not the hash)",
      (() => { try { mock.assertCreateAllowed(withReceipt, otherSlot); return true; } catch { return false; } })());
    ok("mock still refuses a second receipt for the same pool (byPool, carried into the shared check)",
      /duplicate unique index byPool/.test((() => {
        try { mock.assertCreateAllowed(withReceipt, { type: "completionReceipt", ownerId: OP,
          data: { ...receiptData, proTxHash: "ee" + "56".repeat(31), slotIndex: 2 } }); return ""; } catch (e) { return e.message; }
      })()));
    // bySlot must compare by VALUE across representations (pre-commit artifact check): a
    // Buffer carrying the same bytes as a seeded hex string is the same node hash
    const dupSlotBuf = { type: "completionReceipt", ownerId: OP, data: { ...receiptData,
      proTxHash: Buffer.from(REAL_HASH, "hex"),
      poolId: Buffer.from(Identifier.from(OTHER_POOL).toBuffer()).toString("hex") } };
    ok("mock refuses a bySlot duplicate presented as a Buffer against a seeded hex string (value comparison)",
      /duplicate unique index bySlot/.test((() => {
        try { mock.assertCreateAllowed(withReceipt, dupSlotBuf); return ""; } catch (e) { return e.message; }
      })()));
  }
}

// the REPLACE and DELETE transition rows (final pass, major 4): completion receipts are
// immutable AND non-deletable at consensus on every ledger that has them, and the
// immutable pool is non-deletable too; the mock previously accepted a receipt replace
// and silently ignored deletes, both more permissive than Platform. Parity-tested here
// on BOTH harness ledgers through the same exported check broadcast enforces.
{
  const mock = require("./formationMockDash.cjs");
  const t = (kind, type) => {
    try { mock.assertMutationAllowed(kind, { type }); return null; } catch (e) { return e.message; }
  };
  ok("mock refuses a completionReceipt replace (immutable on every receipt ledger)",
    /not mutable/.test(t("replace", "completionReceipt") || ""));
  ok("mock refuses a completionReceipt delete (non-deletable)",
    /cannot be deleted/.test(t("delete", "completionReceipt") || ""));
  ok("mock allows a share replace", t("replace", "share") === null);
  ok("mock allows a share delete", t("delete", "share") === null);
  if (PARED) {
    ok("mock refuses a pool replace on the immutable ledger",
      /not allowed|not mutable/.test(t("replace", "pool") || ""));
    ok("mock refuses a pool delete on the immutable ledger",
      /cannot be deleted|not allowed/.test(t("delete", "pool") || ""));
  } else {
    ok("mock allows a pool replace on the flip ledger", t("replace", "pool") === null);
  }
}

// SHARE schema parity, create and replace (pass 7, major 3): the mock validated only
// pool and completionReceipt creates and applied replaces blind, so a writer emitting
// an unknown or out-of-range share field passed the matrix while the contract refuses
// it. The unknown-property case is the one that bit, because a readback reading only
// known fields cannot see it.
{
  const mock = require("./formationMockDash.cjs");
  const goodShare = { poolId: Buffer.alloc(32, 1), shareBps: 5000,
    contributionDuffs: 50000000000, l1RewardScript: Buffer.alloc(25, 2) };
  const tc = (p) => { try { mock.validateShareProps(p); return null; } catch (e) { return e.message; } };
  ok("mock accepts a well-formed share", tc(goodShare) === null);
  ok("mock rejects a share carrying an unknown property (additionalProperties:false)",
    /unknown property unexpected/.test(tc({ ...goodShare, unexpected: 1 }) || ""));
  ok("mock rejects shareBps above 10000", tc({ ...goodShare, shareBps: 10001 }) !== null);
  ok("mock rejects shareBps of zero (minimum 1)", tc({ ...goodShare, shareBps: 0 }) !== null);
  ok("mock rejects a share missing contributionDuffs",
    /missing required contributionDuffs/.test(tc({ poolId: goodShare.poolId, shareBps: 5000 }) || ""));
  ok("mock rejects an over-long l1RewardScript",
    tc({ ...goodShare, l1RewardScript: Buffer.alloc(35, 2) }) !== null);
  // the remaining implemented constraints, each with its own case (artifact check: a
  // mutation removing any of these left the suite green)
  ok("mock rejects a share whose poolId is not 32 bytes",
    tc({ ...goodShare, poolId: Buffer.alloc(31, 1) }) !== null);
  ok("mock rejects a negative contributionDuffs",
    tc({ ...goodShare, contributionDuffs: -1 }) !== null);
  ok("mock rejects a non-integer contributionDuffs",
    tc({ ...goodShare, contributionDuffs: 1.5 }) !== null);
  ok("mock rejects an empty l1RewardScript (minItems 1)",
    tc({ ...goodShare, l1RewardScript: Buffer.alloc(0) }) !== null);
  const rec = { type: "share", data: { poolId: Buffer.alloc(32, 1).toString("hex"),
    shareBps: 5000, contributionDuffs: 50000000000 } };
  const tr = (pending) => {
    try { mock.assertReplaceAllowed(rec, pending); return null; } catch (e) { return e.message; }
  };
  ok("mock accepts a legitimate share replace", tr({ shareBps: 6000 }) === null);
  ok("mock rejects a share replace introducing an unknown property",
    /unknown property/.test(tr({ sneaky: 1 }) || ""));
  ok("mock rejects a share replace walking shareBps out of range",
    tr({ shareBps: 20000 }) !== null);
  // the key check ISOLATED. On `share` the value validator also refuses an unknown key,
  // so the share cases above pass even with the key check severed (watched: the
  // severing mutation failed nothing). A type with no value validator is where the key
  // check is the only protection, so that is where it must be observed.
  const reqRec = { type: "membershipRequest", data: { status: "pending" } };
  const trq = (pending) => {
    try { mock.assertReplaceAllowed(reqRec, pending); return null; } catch (e) { return e.message; }
  };
  ok("mock accepts a legitimate membershipRequest replace", trq({ status: "matched" }) === null);
  ok("mock rejects a membershipRequest replace introducing an unknown property (key check alone)",
    /unknown property sneaky/.test(trq({ sneaky: 1 }) || ""));
  // THE MAP'S MEMBERSHIP IS PINNED FIRST (artifact re-check: a loop over the map cannot
  // notice a deleted row, because the row's test disappears with it), then every listed
  // type is exercised.
  ok("the replace whitelist covers exactly the expected types",
    Object.keys(mock.REPLACE_KEYS).sort().join(",")
      === "membershipRequest,pledgeSlot,pool,share,votePreference");
  for (const [type, keys] of Object.entries(mock.REPLACE_KEYS)) {
    const r = { type, data: { poolId: Buffer.alloc(32, 1).toString("hex"),
      shareBps: 5000, contributionDuffs: 1 } };
    const attempt = (pending) => {
      try { mock.assertReplaceAllowed(r, pending); return null; } catch (e) { return e.message; }
    };
    ok(`replace whitelist covers ${type}: an unknown key is refused`,
      /unknown property/.test(attempt({ definitelyNotAField: 1 }) || ""));
    ok(`replace whitelist covers ${type}: its own first key is accepted`,
      attempt({ [keys[0]]: type === "share" ? 5000 : "x" }) === null
      || type === "share"); // share also value-validates, covered by its own cases
  }
}

// SIGNER-TO-OWNER AUTHORIZATION parity (pass-7 wave, review major 4): real Platform
// refuses a transition whose signer is not the document's owner, and the mock accepted
// any identity for any transition, so a future wrong-signer regression would pass the
// crash matrix while the real ledger refuses it. Table-driven over all three kinds.
{
  const mock = require("./formationMockDash.cjs");
  const t = (kind, ownerId, signerId) => {
    try { mock.assertAuthorized(kind, { ownerId }, signerId); return null; }
    catch (e) { return e.message; }
  };
  for (const kind of ["create", "replace", "delete"]) {
    ok(`authorization: a ${kind} signed by the document owner is allowed`,
      t(kind, F1, F1) === null);
    ok(`authorization: a ${kind} signed by a DIFFERENT identity is refused`,
      /identity|owner/i.test(t(kind, F1, F2) || ""));
  }
  ok("authorization: a missing signer is refused, never treated as anonymous-allowed",
    t("delete", F1, undefined) !== null);
}

// broadcast-LEVEL delete coverage (artifact check on the transition-rule fold): the
// pure check is parity-tested above, and these CHILD runs prove broadcast actually
// routes deletes through it, that an allowed delete removes the document, and that a
// refused delete leaves the ledger unchanged (the refusal throws before the save, so
// atomicity of the refusal is observed, not assumed)
{
  writeSeed();
  const childEnv = { ...process.env, TEGARA_ENV_PATH: ENV_PATH,
    TEGARA_MOCK_LEDGER: LEDGER_PATH, LEDGER: HARNESS_LEDGER, NETWORK: "regtest" };
  const drive = (script) => {
    try { return { code: 0, out: execFileSync("node", ["-e", script],
      { env: childEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }; }
    catch (e) { return { code: e.status, out: (e.stdout || "") + (e.stderr || "") }; }
  };
  const l0 = ledger();
  // the seeded fixtures are SCHEMA-PRODUCIBLE documents (pass 7, minor 4): the earlier
  // stubs carried only the fields the delete path consults, which is exactly the
  // fixture shortcut the producibility rule forbids, so each is now a complete document
  // and is asserted to pass the mock's own create validators before being seeded
  const mock = require("./formationMockDash.cjs");
  const probeShare = { poolId: Buffer.from(Identifier.from(POOL).toBuffer()),
    shareBps: 5000, contributionDuffs: 50000000000, l1RewardScript: Buffer.from(SCRIPT_A, "hex") };
  // NOTE the validation below runs on what is ACTUALLY SEEDED, read back out of the
  // record after hex encoding (artifact check: validating a separate object and then
  // seeding a transformed copy leaves the two free to drift, so the assertion has to
  // observe the seeded bytes)
  const BYTES = new Set(["poolId", "proTxHash", "allocationRows", "allocationHash", "l1RewardScript"]);
  const propsOfSeeded = (data) => Object.fromEntries(Object.entries(data)
    .filter(([k]) => k !== "$createdAt")
    .map(([k, v]) => [k, BYTES.has(k) ? Buffer.from(v, "hex") : v]));
  const probeReceipt = {
    poolId: Buffer.from(Identifier.from(POOL).toBuffer()), proTxHash: Buffer.from(REAL_HASH, "hex"),
    slotIndex: 0,
    ...(PARED ? {} : { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 }),
    formatVersion: 1, allocationRows: Buffer.from("[]"), allocationHash: Buffer.alloc(32, 3),
    participantCount: 2, l1Verification: "demo-unverified", verificationMethodVersion: 1 };
  const hexed = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) =>
    [k, (Buffer.isBuffer(v) || v instanceof Uint8Array) ? Buffer.from(v).toString("hex") : v]));
  const shareRec = { id: "share-delete-probe", type: "share", ownerId: OP,
    data: { ...hexed(probeShare), $createdAt: 1 } };
  const receiptRec = { id: "receipt-delete-probe", type: "completionReceipt", ownerId: OP,
    data: { ...hexed(probeReceipt), $createdAt: 1 } };
  l0.docs.push(shareRec, receiptRec);
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l0, null, 1));
  // read the seeded documents back OFF THE LEDGER FILE and validate those
  const seeded = (id) => JSON.parse(fs.readFileSync(LEDGER_PATH, "utf8"))
    .docs.find((d) => d.id === id).data;
  let shareProducible = true;
  try { mock.validateShareProps(propsOfSeeded(seeded("share-delete-probe"))); } catch { shareProducible = false; }
  ok("the SEEDED share delete fixture is schema-producible", shareProducible);
  let receiptProducible = true;
  try { mock.validateReceiptProps(propsOfSeeded(seeded("receipt-delete-probe"))); } catch { receiptProducible = false; }
  ok("the SEEDED receipt delete fixture is schema-producible in this ledger's shape", receiptProducible);
  const script = (id, signer = OP) => `
    const mock = require(${JSON.stringify(path.join(__dirname, "formationMockDash.cjs"))});
    const c = new mock.Client({});
    c.platform.documents.broadcast({ delete: [{ __rec: { id: ${JSON.stringify(id)} } }] },
      { getId: () => ({ toString: () => ${JSON.stringify(signer)} }) })
      .then(() => process.exit(0), (e) => { console.error(e.message); process.exit(3); });`;
  // authorization at the BROADCAST level: a delete signed by a non-owner is refused
  // and the document survives (proves broadcast routes assertAuthorized, not only that
  // the pure function refuses)
  const rBad = drive(script("share-delete-probe", F1));
  ok("broadcast refuses a delete signed by a non-owner identity",
    rBad.code === 3 && /signer must be the document owner/.test(rBad.out));
  ok("the wrongly-signed delete left the document in place",
    ledger().docs.some((d) => d.id === "share-delete-probe"));
  const r1 = drive(script("share-delete-probe"));
  ok("broadcast delete of a share succeeds (child exit 0)", r1.code === 0);
  ok("the deleted share is gone from the persisted ledger",
    !ledger().docs.some((d) => d.id === "share-delete-probe"));
  const r2 = drive(script("receipt-delete-probe"));
  ok("broadcast delete of a completionReceipt is refused through the transition check",
    r2.code === 3 && /cannot be deleted/.test(r2.out));
  ok("the refused receipt remains on the persisted ledger (refusal is atomic)",
    ledger().docs.some((d) => d.id === "receipt-delete-probe"));
}

// ---- the clean run establishes the target end state and the boundary count ----
writeSeed();
const clean = runChild(["complete", POOL, REAL_HASH]);
ok("clean complete succeeds", clean.code === 0 && /FORMATION COMPLETE/.test(clean.out));
ok("clean run wrote exactly one receipt", receipts().length === 1);
assertReceiptCorrect("clean receipt", receipts()[0]);
ok("clean run left the pool live under REAL_HASH", poolLiveUnderRealHash());
ok("clean run cleared the active manifest and draft", !hasInFlightEvidence());
ok("clean run RETAINED a FORMATION_DONE_", fs.readdirSync(STATE_DIR).some((f) => f.startsWith("FORMATION_DONE_") && f.endsWith(".val")));

// count the boundaries the clean completion crosses (fresh seed each probe, so N counts
// the boundaries of a ONE-SHOT clean completion, not of a partially-resumed state)
let N = 0;
for (;;) {
  writeSeed();
  const r = runChild(["complete", POOL, REAL_HASH], N);
  if (r.code !== 97) break; // this K is past the last boundary
  N += 1;
  if (N > 200) { ok("boundary count is bounded", false); break; }
}
ok(`clean completion crosses a real boundary set (${N})`, N > 5);
console.log(`crash matrix: ${N} fault boundaries (each Platform op + each local durable write)`);

// ---- the matrix: crash at each boundary, then recover, and check the invariants ----
let recoveredByComplete = 0, recoveredByReceipt = 0, stoppedClean = 0;
for (let k = 0; k < N; k++) {
  writeSeed();
  const crashed = runChild(["complete", POOL, REAL_HASH], k);
  ok(`k=${k}: the injected crash fired`, crashed.code === 97);

  // INVARIANT 1: a crash never leaves more than one receipt, and never a foreign-owned one
  const afterCrash = receipts();
  ok(`k=${k}: at most one receipt after the crash`, afterCrash.length <= 1);
  if (afterCrash.length === 1) ok(`k=${k}: any crash-written receipt is the operator's`, afterCrash[0].ownerId === OP);
  // INVARIANT 1b, COMPLETION-RECORD LAST (flip invariant list item 1, scoped per the
  // a soundness-review finding fold): on a NORMAL run the completion record is written only after the
  // participants' shares, so at no crash boundary OF THIS MATRIX does a receipt exist
  // without both shares on the ledger. That is publication ORDERING on the normal path,
  // asserted here on both ledgers; it is NOT a standing implication, because shares are
  // mutable afterwards and the recovery path publishes from the frozen draft with
  // detection only (its divergence warnings, not this matrix, cover that window).
  if (afterCrash.length === 1) {
    const sh = ledger().docs.filter((d) => d.type === "share");
    ok(`k=${k}: a receipt implies both participants' shares (completion-record last)`,
      [F1, F2].every((f) => sh.some((s) => s.ownerId === f)));
  }

  // RECOVERY as an operator would drive it: clear a possibly-held op lock, then re-run
  // complete (the resume path). A crash BEFORE the flip leaves a forming pool that
  // complete resumes; a crash AFTER the flip may need the receipt publish path.
  clearOpLock();
  const resume = runChild(["complete", POOL, REAL_HASH]);
  let how = null;
  if (resume.code === 0) { how = "complete"; recoveredByComplete++; }
  else {
    // complete refused (e.g. pool already live, no active manifest); the receipt path recovers
    clearOpLock();
    const rec = runChild(["receipt", POOL]);
    if (rec.code === 0) { how = "receipt"; recoveredByReceipt++; }
    else {
      // acceptable ONLY if it stopped loudly, left no receipt to contradict, AND
      // RETAINED the recovery evidence (vetting round, finding 5: "stops loudly" was
      // never the whole guarantee; "without clearing recovery evidence" is the other
      // half, and a branch not checking it enforces less than the header claims). This
      // branch fires on NO boundary of either current ledger, which the recovery-path
      // count line makes visible; it guards future boundary shapes.
      ok(`k=${k}: a non-recovering stop is loud, receiptless, and keeps its evidence`,
        (rec.code === 1 || rec.code === 2) && receipts().length === 0 && hasInFlightEvidence());
      stoppedClean++;
    }
  }

  // INVARIANT 2: after recovery there is exactly one receipt, and it matches the
  // INDEPENDENT expectation on every field (not merely the code's own prior output)
  const finalR = receipts();
  if (how) {
    ok(`k=${k}: recovery converges to exactly one receipt`, finalR.length === 1);
    assertReceiptCorrect(`k=${k} recovered receipt`, finalR[0]);
    ok(`k=${k}: recovery left the pool live under REAL_HASH`, poolLiveUnderRealHash());
    // INVARIANT 3: no dangling in-flight evidence after a successful recovery
    ok(`k=${k}: recovery cleared the active manifest and draft`, !hasInFlightEvidence());
  }
}
ok(`matrix exercised every boundary (complete:${recoveredByComplete} receipt:${recoveredByReceipt} stop:${stoppedClean})`,
  recoveredByComplete + recoveredByReceipt + stoppedClean === N);
console.log(`recovery paths: ${recoveredByComplete} via complete-resume, ${recoveredByReceipt} via ` +
  `receipt-publish, ${stoppedClean} loud-and-receiptless stops (all ${N} boundaries converged or stopped safely)`);

// ---- receipt-command matrix 1: crash while `receipt` PUBLISHES from a live-no-receipt
//      state (round-4 harness gap: recovery runs were never themselves interrupted) ----
{
  writeSeed();
  // reach the recoverable no-receipt intermediate state with the draft + active manifest
  // retained. On v8 that is live-without-receipt (halt after the FLIP); on v9 no flip
  // exists (the hook is refused there), so the same state is settled-without-receipt,
  // reached by halting after SETTLE.
  const halted = runChild(["complete", POOL, REAL_HASH], undefined,
    { FORMATION_HALT_AFTER: PARED ? "shares" : "flip" });
  ok("receipt-matrix setup: halted with no receipt, recovery evidence retained",
    halted.code === 0 && receipts().length === 0 && hasInFlightEvidence()
    && (PARED || poolLiveUnderRealHash()));
  snapshot();
  // count receipt-publish boundaries
  let RN = 0;
  for (;;) { restore(); const r = runChild(["receipt", POOL], RN); if (r.code !== 97) break; RN++; if (RN > 200) break; }
  ok(`receipt publish crosses a boundary set (${RN})`, RN > 3);
  console.log(`receipt-publish matrix: ${RN} fault boundaries`);
  for (let k = 0; k < RN; k++) {
    restore();
    const crashed = runChild(["receipt", POOL], k);
    ok(`receipt-publish k=${k}: crash fired`, crashed.code === 97);
    ok(`receipt-publish k=${k}: at most one receipt after crash`, receipts().length <= 1);
    clearOpLock();
    const rec = runChild(["receipt", POOL]);
    ok(`receipt-publish k=${k}: recovery succeeds`, rec.code === 0);
    ok(`receipt-publish k=${k}: exactly one receipt`, receipts().length === 1);
    assertReceiptCorrect(`receipt-publish k=${k}`, receipts()[0]);
    ok(`receipt-publish k=${k}: in-flight evidence cleared`, !hasInFlightEvidence());
  }
}

// ---- receipt-command matrix 2: crash while `receipt` RECONCILES a half-finalized
//      state (receipt already on-ledger, but the draft/manifest were not yet cleared) ----
{
  restore(); // live, no receipt, draft+manifest present
  runChild(["receipt", POOL]); // publish the receipt...
  // ...then hand-restore the leftover local evidence to simulate a crash BETWEEN the
  // receipt confirm and the finalize clears
  const withReceipt = ledger();
  restore();                                   // brings back draft+manifest (and a no-receipt ledger)
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(withReceipt, null, 1)); // ...but keep the receipt on-ledger
  ok("reconcile setup: receipt on-ledger AND leftover draft/manifest", receipts().length === 1 && hasInFlightEvidence());
  snapshot();
  let CN = 0;
  for (;;) { restore(); const r = runChild(["receipt", POOL], CN); if (r.code !== 97) break; CN++; if (CN > 200) break; }
  // guard against a vacuous pass (round-4 re-check): the reconcile path DOES cross local
  // write boundaries, so CN must be non-zero or the matrix below asserts nothing
  ok(`receipt reconcile crosses a boundary set (${CN})`, CN > 0);
  console.log(`receipt-reconcile matrix: ${CN} fault boundaries`);
  for (let k = 0; k < CN; k++) {
    restore();
    const crashed = runChild(["receipt", POOL], k);
    ok(`receipt-reconcile k=${k}: crash fired`, crashed.code === 97);
    clearOpLock();
    const rec = runChild(["receipt", POOL]);
    ok(`receipt-reconcile k=${k}: recovery succeeds`, rec.code === 0);
    ok(`receipt-reconcile k=${k}: still exactly one receipt`, receipts().length === 1);
    assertReceiptCorrect(`receipt-reconcile k=${k}`, receipts()[0]);
    ok(`receipt-reconcile k=${k}: evidence finalized (cleared)`, !hasInFlightEvidence());
  }
}

// ---- independent case: a legitimate POOL FEE CHANGE after completion must NOT make
//      `receipt` falsely reject the (historical-fee) receipt (round-5 P2) ----
// SKIPPED on the immutable-pool ledger, where the state this case injects CANNOT EXIST:
// the pool's fee is pinned at creation, so "the fee changed after completion" is a fixture
// the real ledger cannot produce, and a fixture that cannot exist proves nothing (the
// be41757 lesson). The consensus refusal itself is exercised by the mock's replace guard.
if (PARED) {
  console.log("fee-change case: skipped on the immutable-pool ledger (fee drift is unrepresentable)");
} else {
  writeSeed();
  runChild(["complete", POOL, REAL_HASH]);
  ok("fee-change setup: one receipt", receipts().length === 1);
  // the operator legitimately raises the pool fee AFTER completion (the pool doc is mutable)
  const l = ledger();
  l.docs.find((d) => d.id === POOL).data.operatorFeeBps = 3500;
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  const r = runChild(["receipt", POOL]);
  ok("receipt still ACCEPTS the receipt after a pool fee change", r.code === 0);
  ok("receipt readback notes the historical fee, not a contradiction", /2000 bps/.test(r.out) && !/contradict/i.test(r.out));
}

// ---- independent case A: two stale op-lock waiters never both proceed ----
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH]); // land a completed pool + receipt
  // fabricate a foreign op-lock with an owner token, as a crashed run would leave
  const suffix = fs.readdirSync(STATE_DIR).find((f) => f.startsWith("FORMATION_DONE_")).replace("FORMATION_DONE_", "").replace(".val", "");
  const lockDir = path.join(STATE_DIR, `oplock-${suffix}`);
  fs.mkdirSync(lockDir, { recursive: true });
  fs.writeFileSync(path.join(lockDir, "owner"), "ghost-pid");
  const blocked = runChild(["receipt", POOL]);
  ok("held op lock blocks a second run (no auto-divert)", blocked.code !== 0 && /operation lock/.test(blocked.out));
  ok("the blocked run left the foreign lock in place", fs.existsSync(lockDir));
  fs.rmSync(lockDir, { recursive: true, force: true });
}

// ---- independent case B: an anomalous receipt is refused, never read past ----
//      On v8 the anomaly is a receipt on a still-FORMING pool (the flip precedes the
//      receipt). On v9 no forming state exists, so the anomaly class is a receipt that
//      does NOT VERIFY against its pool through the shared check, and both `receipt` and
//      a fresh `complete` must refuse over it rather than treat it as absent.
{
  writeSeed();
  // hand-inject a schema-valid but non-verifying receipt (a squatter-style anomaly: its
  // embedded allocation is empty, so it proves nothing about this pool)
  const l = ledger();
  const rows = Buffer.from(JSON.stringify(["tegara-completion-allocation", 1, CONTRACT, POOL, "100000000000", []]), "utf8");
  l.docs.push({ id: newId(), type: "completionReceipt", ownerId: OP, data: {
    poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
    proTxHash: REAL_HASH, slotIndex: 0, formatVersion: 1,
    ...(PARED ? {} : { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 }),
    allocationRows: rows.toString("hex"),
    allocationHash: crypto.createHash("sha256").update(rows).digest("hex"),
    participantCount: 1, l1Verification: "demo-unverified",
    verificationMethodVersion: 1, $createdAt: 5 } });
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  const r = runChild(["receipt", POOL]);
  ok("an anomalous receipt is refused loudly by `receipt`",
    r.code !== 0 && (PARED ? /FAILS verification/ : /forming/i).test(r.out));
  clearOpLock();
  const c = runChild(["complete", POOL, REAL_HASH]);
  ok("a fresh `complete` refuses to start over the contradiction",
    c.code !== 0 && /already exists|second completion|contradiction|FORMING/i.test(c.out));
  ok("the anomalous receipt was not laundered into a completion",
    !poolLiveUnderRealHash());
  // the L1 status reader must not treat the non-verifying receipt as establishing a
  // node, and must give the STATE-SPECIFIC reason, not a bare label (on v8 the pool is
  // still forming; on v9 the receipt fails the shared check)
  clearOpLock();
  const st = runChild(["status", POOL]);
  ok("status checks no node over the anomalous receipt, with the state's own reason",
    /no established node to check/.test(st.out)
    && (PARED ? /no completion receipt verifies/ : /still forming/).test(st.out));
}

// ---- independent case C: a corrupt draft is refused, never written blind ----
//      DETERMINISTIC (round-6): reach a state that certainly HAS a draft (halt at the
//      last pre-receipt boundary, which freezes the draft and retains it), then corrupt it.
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: PARED ? "shares" : "flip" });
  const draftFile = fs.readdirSync(STATE_DIR).find((f) => f.startsWith("RECEIPT_DRAFT_") && f.endsWith(".val"));
  ok("corrupt-draft setup: a draft exists to corrupt", !!draftFile);
  fs.writeFileSync(path.join(STATE_DIR, draftFile), "{ not json");
  const r = runChild(["receipt", POOL]);
  ok("a corrupt draft is refused loudly", r.code !== 0 && /corrupt/i.test(r.out));
  ok("a corrupt draft writes no receipt", receipts().length === 0);
}

// ---- independent case D0: a fee change BEFORE the flip must REFUSE (round-6 re-check:
//      the receipt records the completion-time fee, so a pre-flip drift must never let a
//      stale draft fee freeze into the immutable receipt) ----
// SKIPPED on the immutable-pool ledger for the same unrepresentable-fixture reason as the
// fee-change case above: the pool's fee cannot drift there, before or after anything.
if (PARED) {
  console.log("pre-flip fee-drift case: skipped on the immutable-pool ledger (unrepresentable)");
} else {
  writeSeed();
  const halted = runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "shares" });
  ok("pre-flip-fee setup: halted after settle, before the flip", halted.code === 0 && !poolLiveUnderRealHash());
  const l = ledger();
  l.docs.find((d) => d.id === POOL).data.operatorFeeBps = 4200; // fee drifts while still forming
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  clearOpLock();
  const r = runChild(["complete", POOL, REAL_HASH]);
  ok("pre-flip fee drift REFUSES before the flip", r.code !== 0 && /operatorFeeBps/.test(r.out));
  ok("pre-flip fee drift did not flip the pool", !poolLiveUnderRealHash() && receipts().length === 0);
}

// ---- independent case D: a legitimate POOL FEE CHANGE while the pool is live WITHOUT a
//      receipt (draft present) must NOT brick recovery (round-6: requireDraftMatchesPool
//      used to reject on fee) ----
// SKIPPED on the immutable-pool ledger: the fee cannot change there, so the state this
// case reaches is unrepresentable, and its concern (a live pool whose mutable fee drifted
// during the recovery window) has no v9 counterpart.
if (PARED) {
  console.log("post-flip fee-change case: skipped on the immutable-pool ledger (unrepresentable)");
} else {
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "flip" }); // live, no receipt, draft kept
  ok("fee-recovery setup: live, no receipt, draft present", poolLiveUnderRealHash() && receipts().length === 0 && hasInFlightEvidence());
  const l = ledger();
  l.docs.find((d) => d.id === POOL).data.operatorFeeBps = 4200; // operator raises the fee post-flip
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  const r = runChild(["receipt", POOL]);
  ok("recovery still publishes after a post-flip fee change", r.code === 0 && receipts().length === 1);
  assertReceiptCorrect("fee-recovery receipt", receipts()[0]); // records the HISTORICAL 2000 fee
}

// inject the VALID expected receipt directly into the ledger, in the shape of the ledger
// under test, simulating a completion that landed outside this run (a lost race)
const injectValidReceipt = () => {
  const l = ledger();
  l.docs.push({ id: newId(), type: "completionReceipt", ownerId: OP, data: {
    poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
    proTxHash: EXPECTED.proTxHash, slotIndex: 0, formatVersion: 1,
    ...(PARED ? {} : { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 }),
    allocationRows: EXPECTED.allocationRows, allocationHash: EXPECTED.allocationHash,
    participantCount: 2, l1Verification: "demo-unverified", verificationMethodVersion: 1,
    $createdAt: 5 } });
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
};

// ---- independent case FEE-VS-FROZEN-DRAFT: an existing receipt whose fee CONTRADICTS the original
//      frozen draft must stop loudly. The fee was excluded from the exact comparison
//      because a REBUILT draft sources the current (possibly drifted) pool fee; an
//      ORIGINAL freeze records the completion-time fee, so for it the every-field claim
//      holds. Unpared ledgers only: the pared receipt carries no fee at all. ----
if (!PARED) {
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "flip" });
  ok("fee-vs-draft setup: live, no receipt, ORIGINAL frozen draft present",
    receipts().length === 0 && hasInFlightEvidence());
  const l = ledger();
  l.docs.push({ id: newId(), type: "completionReceipt", ownerId: OP, data: {
    poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
    proTxHash: EXPECTED.proTxHash, slotIndex: 0, formatVersion: 1,
    nodeType: "regular", operatorFeeBps: 3500, targetDuffs: 100000000000, // <- the only difference
    allocationRows: EXPECTED.allocationRows, allocationHash: EXPECTED.allocationHash,
    participantCount: 2, l1Verification: "demo-unverified", verificationMethodVersion: 1,
    $createdAt: 5 } });
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  const r = runChild(["receipt", POOL]);
  ok("a receipt whose fee contradicts the ORIGINAL frozen draft is refused",
    r.code !== 0 && /operatorFeeBps/.test(r.out));
  ok("the fee refusal keeps the local evidence", hasInFlightEvidence());
}

// ---- independent case ARCHIVED-DRAFT RECOVERY: abandon archives the frozen DRAFT beside the manifest,
//      and recovery must COMPARE AGAINST IT. Restoring only the manifest left
//      l1Verification unchecked (no derivable source), so a late receipt attesting a
//      DIFFERENT verification level than the abandoned run had frozen was accepted and
//      finalized, clearing the archive that held the contradiction. ----
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" });
  const ab = runChild(["abandon", POOL]);
  ok("archived-draft setup: abandon archived manifest AND draft", ab.code === 0 && !hasInFlightEvidence());
  // the late receipt: identical to the frozen truth EXCEPT its attested level
  const l = ledger();
  l.docs.push({ id: newId(), type: "completionReceipt", ownerId: OP, data: {
    poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
    proTxHash: EXPECTED.proTxHash, slotIndex: 0, formatVersion: 1,
    ...(PARED ? {} : { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 }),
    allocationRows: EXPECTED.allocationRows, allocationHash: EXPECTED.allocationHash,
    participantCount: 2, l1Verification: "amount-reward-verified", // <- the frozen draft says demo-unverified
    verificationMethodVersion: 1, $createdAt: 5 } });
  if (!PARED) {
    const p2 = l.docs.find((d) => d.id === POOL);
    p2.data.proTxHash = REAL_HASH; p2.data.status = "live";
  }
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  const r = runChild(["receipt", POOL]);
  ok("a receipt contradicting the ARCHIVED frozen draft is refused",
    r.code !== 0 && /l1Verification/.test(r.out));
  ok("that refusal leaves the archive intact for hands",
    fs.readdirSync(STATE_DIR).some((f) => f.startsWith("FORMATION_ABANDONED_") && f.endsWith(".val")));
}

// ---- independent case DAMAGED ARCHIVED DRAFT: a DAMAGED archived draft must
//      REFUSE, never silently fall back to the weaker manifest-only comparison. The
//      archive's EXISTENCE is itself evidence that exact evidence was meant to be there,
//      so treating a damaged one as absent is not the same as never having had it: it
//      re-opens exactly the l1Verification hole the archived-draft recovery closed. ----
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" });
  runChild(["abandon", POOL]);
  const archiveFile = fs.readdirSync(STATE_DIR).find((f) => f.startsWith("FORMATION_ABANDONED_") && f.endsWith(".val"));
  ok("damaged-draft setup: an archive exists", archiveFile !== undefined);
  // damage ONE nibble of the archived draft's allocation hash, leaving l1Verification
  // intact and perfectly readable
  const ap = path.join(STATE_DIR, archiveFile);
  const arch = JSON.parse(fs.readFileSync(ap, "utf8"));
  const d = JSON.parse(arch.draft);
  d.allocationHashHex = (d.allocationHashHex[0] === "a" ? "b" : "a") + d.allocationHashHex.slice(1);
  arch.draft = JSON.stringify(d);
  fs.writeFileSync(ap, JSON.stringify(arch));
  const l = ledger();
  l.docs.push({ id: newId(), type: "completionReceipt", ownerId: OP, data: {
    poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
    proTxHash: EXPECTED.proTxHash, slotIndex: 0, formatVersion: 1,
    ...(PARED ? {} : { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 }),
    allocationRows: EXPECTED.allocationRows, allocationHash: EXPECTED.allocationHash,
    participantCount: 2, l1Verification: "amount-reward-verified", // contradicts the archived draft
    verificationMethodVersion: 1, $createdAt: 5 } });
  if (!PARED) {
    const p2 = l.docs.find((x) => x.id === POOL);
    p2.data.proTxHash = REAL_HASH; p2.data.status = "live";
  }
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  const r = runChild(["receipt", POOL]);
  ok("a DAMAGED archived draft refuses rather than falling back",
    r.code !== 0 && /damaged|corrupt|unusable/i.test(r.out));
  ok("that refusal PRESERVES the archive for hands",
    fs.existsSync(ap));
  // and UNPARSEABLE damage takes the same path (closing-pass confirmation: swallowing
  // the parse error to `undefined` would slip past the refusal into manifest-only
  // recovery, the exact fallback the refusal exists to prevent)
  const arch2 = JSON.parse(fs.readFileSync(ap, "utf8"));
  arch2.draft = "{not valid json";
  fs.writeFileSync(ap, JSON.stringify(arch2));
  const r2 = runChild(["receipt", POOL]);
  ok("an UNPARSEABLE archived draft refuses too, never falls back",
    r2.code !== 0 && /do not parse/.test(r2.out));
  ok("the unparseable refusal also preserves the archive", fs.existsSync(ap));
  // an EMPTY-STRING draft is damage too, and a truthiness test would read it as absent
  const arch3 = JSON.parse(fs.readFileSync(ap, "utf8"));
  arch3.draft = "";
  fs.writeFileSync(ap, JSON.stringify(arch3));
  const r3 = runChild(["receipt", POOL]);
  ok("an EMPTY archived draft refuses too (presence tested explicitly)",
    r3.code !== 0 && /do not parse/.test(r3.out));
}

// ---- independent case E: abandon ARCHIVES before clearing, and receipt RECOVERS from
//      the archive when the completion turns out to have landed anyway (round-7 P1).
//      On v8 the late evidence is the pool live under the abandoned hash; on v9 it is a
//      RECEIPT matching the archived manifest, and with NO receipt the archive must NOT
//      publish on its own (the abandon stands; invariant list item 12). ----
{
  writeSeed();
  const halted = runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" });
  ok("abandon setup: manifest committed, pool still forming, no shares", halted.code === 0 && !poolLiveUnderRealHash());
  const ab = runChild(["abandon", POOL]);
  ok("abandon succeeds and reports the archive", ab.code === 0 && /archived to FORMATION_ABANDONED_/.test(ab.out));
  ok("abandon left an archive key", fs.readdirSync(STATE_DIR).some((f) => f.startsWith("FORMATION_ABANDONED_") && f.endsWith(".val")));
  ok("abandon cleared the active manifest and draft", !hasInFlightEvidence());
  if (PARED) {
    // with no receipt, the archive alone must not resurrect the abandoned completion
    const dry = runChild(["receipt", POOL]);
    ok("with no receipt the abandon STANDS (archive not publishable on its own)",
      dry.code === 0 && /abandon stands/.test(dry.out) && receipts().length === 0);
    injectValidReceipt(); // the lost race: the completion landed after all
  } else {
    // the loss scenario: the pool goes live under the abandoned hash after the abandon
    const l = ledger();
    const p = l.docs.find((d) => d.id === POOL);
    p.data.proTxHash = REAL_HASH; p.data.status = "live";
    fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  }
  const r = runChild(["receipt", POOL]);
  // on v9 the receipt is already on the ledger before this run (the injected lost race),
  // so the count alone would pass vacuously; require the run to say it FINALIZED from the
  // archive source, which only the reconcile path prints
  ok("receipt RECOVERS from the abandon archive", r.code === 0 && receipts().length === 1
    && (!PARED || /finalized/.test(r.out)));
  assertReceiptCorrect("abandon-archive receipt", receipts()[0]);
  ok("finalization CLEARED the abandon archive (round-7 re-check)",
    !fs.readdirSync(STATE_DIR).some((f) => f.startsWith("FORMATION_ABANDONED_") && f.endsWith(".val")));
  ok("archive recovery RETAINED a FORMATION_DONE_ record (F-E re-check)",
    fs.readdirSync(STATE_DIR).some((f) => f.startsWith("FORMATION_DONE_") && f.endsWith(".val")));
}

// ---- independent case J: abandon FAILS CLOSED on a damaged manifest (a soundness review): a
//      parse failure must refuse, never fall open to an empty participant list and clear state ----
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" }); // manifest committed, forming
  const manFile = fs.readdirSync(STATE_DIR).find((f) => /^FORMATION_[0-9A-F]{20}\.val$/.test(f));
  fs.writeFileSync(path.join(STATE_DIR, manFile), "{ not json"); // corrupt the committed manifest
  const ab = runChild(["abandon", POOL]);
  ok("abandon REFUSES on a corrupt manifest (fail closed)", ab.code !== 0 && /unparseable|corrupt/.test(ab.out));
  ok("the corrupt manifest was NOT cleared", fs.existsSync(path.join(STATE_DIR, manFile)));
}

// ---- independent case K: idempotent abandon with NO state returns cleanly (re-check-2:
//      the fail-closed extraction must not throw when there is simply nothing to abandon) ----
{
  writeSeed(); // a forming pool with pledgeSlots but NO committed manifest/draft
  const ab = runChild(["abandon", POOL]);
  ok("abandon with no committed manifest/draft returns cleanly", ab.code === 0 && /no committed manifest/.test(ab.out));
}

// ---- independent case L: repeated `receipt` on a DONE source does NOT rewrite DONE
//      (re-check-2: rewriting resets the prune-age mtime and postpones pruning) ----
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH]); // leaves FORMATION_DONE_
  const doneFile = fs.readdirSync(STATE_DIR).find((f) => f.startsWith("FORMATION_DONE_") && f.endsWith(".val"));
  const mtime0 = fs.statSync(path.join(STATE_DIR, doneFile)).mtimeMs;
  runChild(["receipt", POOL]);
  runChild(["receipt", POOL]);
  const mtime1 = fs.statSync(path.join(STATE_DIR, doneFile)).mtimeMs;
  ok("repeated receipt inspection does not rewrite the DONE record", mtime0 === mtime1);
}

// ---- independent case H: a STALE archive whose committed hash != the live pool hash is
//      IGNORED, so it cannot make a valid receipt read as contradictory (round-7 re-check P2) ----
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH]); // clean: DONE + receipt B under REAL_HASH
  ok("mismatch-archive setup: one valid receipt", receipts().length === 1);
  // plant a stale archive whose manifest commits to a DIFFERENT hash
  const suffix = fs.readdirSync(STATE_DIR).find((f) => f.startsWith("FORMATION_DONE_")).replace("FORMATION_DONE_", "").replace(".val", "");
  const staleManifest = JSON.stringify({ v: 1, poolId: POOL, realHash: "ab".repeat(32), target: "100000000000", owners: [] });
  fs.writeFileSync(path.join(STATE_DIR, `FORMATION_ABANDONED_${suffix}.val`), JSON.stringify({ manifest: staleManifest, draft: null, at: null }));
  // also remove DONE to force the source search past it, exposing the archive
  fs.rmSync(path.join(STATE_DIR, `FORMATION_DONE_${suffix}.val`), { force: true });
  const r = runChild(["receipt", POOL]);
  // the mismatched archive is correctly IGNORED (no local manifest to cross-check), so the
  // receipt self-verifies and is accepted rather than falsely rejected as contradictory
  ok("a hash-mismatched archive does not break the valid receipt read",
    r.code === 0 && /canonical, hash recomputed and matches/.test(r.out) && receipts().length === 1);
}

// ---- independent case F: abandon REFUSES when the completion's evidence is already on
//      the ledger, keeping the manifest for `receipt`. On v8 that evidence is the pool
//      having gone live; on v9 it is a verifying receipt (the classifier reads COMPLETED,
//      and abandoning would orphan the completion's local recovery inputs). ----
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" });
  if (PARED) {
    injectValidReceipt(); // the completion landed before the abandon was attempted
  } else {
    // flip the pool live BEFORE calling abandon (simulating a concurrent flip pre-mutation)
    const l = ledger();
    const p = l.docs.find((d) => d.id === POOL);
    p.data.proTxHash = REAL_HASH; p.data.status = "live";
    fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  }
  const ab = runChild(["abandon", POOL]);
  ok("abandon refuses over the completion evidence",
    ab.code !== 0 && (PARED ? /COMPLETED/ : /LIVE/).test(ab.out));
  ok("abandon kept the manifest (no clear, no archive needed)", hasInFlightEvidence());
  const r = runChild(["receipt", POOL]);
  ok("receipt then publishes or reconciles from the kept manifest", r.code === 0 && receipts().length === 1);
  ok("case F converged to the completion record", poolLiveUnderRealHash());
}

// ---- independent case G: done prune KEEPS a DONE whose sibling DRAFT survives (round-7
//      P2, the pre-round-6 half-finalized DONE+DRAFT legacy state) ----
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH]); // clean: writes DONE, clears active + draft
  const doneFile = fs.readdirSync(STATE_DIR).find((f) => f.startsWith("FORMATION_DONE_") && f.endsWith(".val"));
  const suffix = doneFile.replace("FORMATION_DONE_", "").replace(".val", "");
  // fabricate the legacy crash state: DONE (old) + a leftover DRAFT, no active key
  fs.writeFileSync(path.join(STATE_DIR, `RECEIPT_DRAFT_${suffix}.val`), '{"v":1}');
  const pr = runChild(["done", "prune", "0"]); // cutoff 0 days: everything is "old enough"
  ok("prune keeps a DONE with a surviving sibling draft", pr.code === 0 && /kept .* frozen draft/.test(pr.out));
  ok("the DONE manifest survived the prune", fs.existsSync(path.join(STATE_DIR, doneFile)));
}

// ---- independent case I: a FOREIGN share (any identity, not a participant) must NOT wedge
//      completion or abandon (a soundness review). Before the fix, one planted share broke the flip readback
//      (bpsSum != 10000) and the abandon guard (any share blocks), stranding the pool. ----
const plantForeignShare = () => {
  const l = ledger();
  l.docs.push({ id: newId(), type: "share", ownerId: newId(), data: {
    poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
    shareBps: 1, contributionDuffs: 0, l1RewardScript: "76a914" + "99".repeat(20) + "88ac", $createdAt: 5 } });
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
};
{
  writeSeed();
  plantForeignShare();
  const r = runChild(["complete", POOL, REAL_HASH]);
  ok("a foreign share does NOT wedge completion (a soundness review)", r.code === 0 && receipts().length === 1);
  assertReceiptCorrect("foreign-share-present receipt", receipts()[0]);
}
{
  writeSeed();
  const halted = runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" });
  ok("foreign-abandon setup: manifest committed, forming", halted.code === 0 && !poolLiveUnderRealHash());
  plantForeignShare(); // a foreign share on a forming pool with only the manifest committed
  const ab = runChild(["abandon", POOL]);
  ok("a foreign share does NOT block abandon (a soundness review)", ab.code === 0 && /CLEARED/.test(ab.out));
}

// ---- independent case M: `create` emits the shape of the ledger under test (the matrix
//      seeds its pool directly, so without this no gate ever runs the create path) ----
{
  writeSeed();
  const r = runChild(["create", "regular", "2000"]);
  ok("create succeeds on the ledger under test", r.code === 0);
  const created = ledger().docs.find((d) => d.type === "pool" && d.id !== POOL);
  ok("create wrote a pool document", !!created);
  if (created) {
    const d = created.data;
    if (PARED) {
      ok("created v9 pool carries no proTxHash", d.proTxHash === undefined);
      ok("created v9 pool carries no status", d.status === undefined);
      ok("created v9 pool carries no operatorIdentityId", d.operatorIdentityId === undefined);
      ok("created v9 pool carries the required targetDuffs", Number(d.targetDuffs) === 100000000000);
      ok("create advertises the coordinated participate instruction",
        new RegExp(`TEGARA_PARTICIPATE=${created.id}`).test(r.out));
    } else {
      ok("created v8 pool starts in the forming namespace", /^0{32}/.test(d.proTxHash || ""));
      ok("created v8 pool carries status forming", d.status === "forming");
    }
    ok("created pool carries a two-sided slot book",
      (d.slotDuffs !== undefined) === (d.slotCount !== undefined));
  }
}

// ---- independent case O: the L1 STATUS READER's node identity routes through
//      backingNode on both ledgers. A receipt-less immutable pool names WHY no node is
//      checkable with the state's own reason; a completed pool reaches the
//      established-node branch, and a STUB RPC pins the EXACT identity requested (a
//      reader that reached the right branch with the wrong hash would otherwise pass:
//      the branch tests cannot see which node was asked about). ----
{
  writeSeed();
  if (PARED) {
    const pre = runChild(["status", POOL]);
    ok("status on a receipt-less immutable pool names why no node is checkable",
      pre.code === 0 && /no established node to check/.test(pre.out)
      && /no completion receipt verifies/.test(pre.out));
  }
  runChild(["complete", POOL, REAL_HASH]);
  clearOpLock();
  const st = runChild(["status", POOL]);
  ok("status on a completed pool reads COMPLETED", st.code === 0 && /COMPLETED/.test(st.out));
  ok("status on a completed pool reaches the ESTABLISHED-node branch",
    /L1 check skipped \(no FORK_RPC_URL\)/.test(st.out));
  // the SHARE CROSS-CHECK (pass-7 wave, review minor 5): status is the documented
  // place the receipt allocation meets the live shares, and it now actually compares
  ok("status cross-checks the live shares against the receipt allocation",
    /share\(s\) match the receipt allocation exactly/.test(st.out));
  {
    const l = ledger();
    const sh = l.docs.find((d) => d.type === "share" && d.ownerId === F1);
    sh.data.shareBps = 4999; // a post-completion mutation
    fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
    // F2's share is also DELETED, and the case requires status to NAME the missing
    // owner (artifact check: an implementation comparing live values against anything
    // hard-coded passes a bps-only case; naming which owner is absent requires reading
    // the receipt's own allocation rows)
    const f2Share = l.docs.find((d) => d.type === "share" && d.ownerId === F2);
    l.docs = l.docs.filter((d) => d !== f2Share);
    fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
    const st2 = runChild(["status", POOL]);
    ok("status reports a mutated share as DIVERGENCE and exits nonzero",
      st2.code !== 0 && /SHARE DIVERGENCE/.test(st2.out) && /4999/.test(st2.out));
    ok("status NAMES the missing owner from the receipt allocation",
      new RegExp(`share MISSING for ${F2}`).test(st2.out));
    sh.data.shareBps = 5000; l.docs.push(f2Share);
    fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  }

  // the stubbed Core RPC: a separate process (this harness execs its children
  // synchronously, so an in-process server could never answer), logging each request
  // body and answering a fixed valid protx info. The assertion that matters is on the
  // LOG, that the reader asked about exactly REAL_HASH.
  //
  // SANDBOX GATE first (vetting round, environment note): a review sandbox can forbid
  // loopback listeners outright (EPERM on listen), and there the stub can never come
  // up, so the three RPC checks would fail on the environment rather than the code.
  // That exact condition, and ONLY it, is a loud skip; any other stub failure still
  // fails the run.
  const { spawn, execFileSync: efs } = require("child_process");
  let canListen = true;
  try {
    efs("node", ["-e", `
      const s = require("http").createServer(() => {});
      s.on("error", (e) => { console.error(e.code); process.exit(e.code === "EPERM" ? 42 : 1); });
      s.listen(0, "127.0.0.1", () => { s.close(() => process.exit(0)); });
    `]);
  } catch (e) { if (e.status === 42) canListen = false; }
  if (!canListen) {
    console.log("case O stub-RPC checks: SKIPPED, this environment forbids loopback listeners " +
      "(EPERM on listen); the identity-pinning assertions did not run here");
  } else {
  const RPCLOG = path.join(ROOT, "l1stub.log");
  const PORT = 30000 + (process.pid % 10000);
  fs.writeFileSync(RPCLOG, "");
  const stub = spawn("node", ["-e", `
    const http = require("http"), fs = require("fs");
    http.createServer((req, res) => {
      let b = ""; req.on("data", (c) => b += c);
      req.on("end", () => {
        if (b) fs.appendFileSync(${JSON.stringify(RPCLOG)}, b + "\\n");
        let id = null; try { id = JSON.parse(b).id; } catch {}
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ result: { collateralHash: "cc".repeat(32), collateralIndex: 1, state: {} }, error: null, id }));
      });
    }).listen(${PORT}, "127.0.0.1");
  `], { stdio: "ignore" });
  try {
    let up = false;
    for (let i = 0; i < 50 && !up; i++) {
      try {
        efs("node", ["-e", `require("http").get("http://127.0.0.1:${PORT}/", (r) => process.exit(0)).on("error", () => process.exit(1))`]);
        up = true;
      } catch { /* not listening yet */ }
    }
    ok("the stub Core RPC came up", up);
    const stRpc = runChild(["status", POOL], undefined, { FORK_RPC_URL: `http://u:p@127.0.0.1:${PORT}` });
    ok("status with a reachable Core reports the DMN-list confirmation",
      stRpc.code === 0 && /backing node is in the DMN list/.test(stRpc.out));
    const asked = fs.readFileSync(RPCLOG, "utf8");
    ok("the reader asked Core about EXACTLY the established node's hash",
      new RegExp(`"protx"[\\s\\S]*"info"[\\s\\S]*"${REAL_HASH}"`).test(asked) || asked.includes(`"${REAL_HASH}"`));
  } finally {
    stub.kill();
  }
  }
}

// ---- independent case P (a soundness review): a RESUMED completion compares an
//      existing receipt with the frozen draft BEFORE settlement, so a contradicting
//      receipt stops the run with ZERO participant shares created, not after them ----
{
  writeSeed();
  const halted = runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" });
  ok("a soundness-review finding setup: manifest and draft committed, nothing settled", halted.code === 0
    && ledger().docs.filter((d) => d.type === "share").length === 0);
  // a schema-valid receipt whose node hash contradicts the frozen draft's
  const l = ledger();
  l.docs.push({ id: newId(), type: "completionReceipt", ownerId: OP, data: {
    poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
    proTxHash: "ee" + "57".repeat(31), slotIndex: 0, formatVersion: 1,
    ...(PARED ? {} : { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 }),
    allocationRows: EXPECTED.allocationRows, allocationHash: EXPECTED.allocationHash,
    participantCount: 2, l1Verification: "demo-unverified", verificationMethodVersion: 1,
    $createdAt: 5 } });
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  clearOpLock();
  const c = runChild(["complete", POOL, REAL_HASH]);
  ok("a soundness-review finding: the resume refuses over the contradicting receipt",
    c.code !== 0 && /CONTRADICTS the frozen draft/.test(c.out));
  ok("a soundness-review finding: and it refused BEFORE settlement (zero shares created)",
    ledger().docs.filter((d) => d.type === "share").length === 0);
}

// ---- independent case P2 (closing pass, must-fix): a DRAFT-MATCHING receipt attached
//      to a still-forming v8 pool must ALSO stop the resume pre-settlement. The draft
//      comparison alone let it through (the receipt matches!), and only the pool binding
//      catches that the pool itself contradicts any receipt existing at all. ----
if (!PARED) {
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" });
  const l = ledger();
  l.docs.push({ id: newId(), type: "completionReceipt", ownerId: OP, data: {
    poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
    proTxHash: EXPECTED.proTxHash, slotIndex: 0, formatVersion: 1,
    nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000,
    allocationRows: EXPECTED.allocationRows, allocationHash: EXPECTED.allocationHash,
    participantCount: 2, l1Verification: "demo-unverified", verificationMethodVersion: 1,
    $createdAt: 5 } });
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  clearOpLock();
  const c = runChild(["complete", POOL, REAL_HASH]);
  ok("closing-pass fix: a draft-matching receipt on a FORMING pool refuses the resume",
    c.code !== 0 && /still forming/i.test(c.out));
  ok("closing-pass fix: and it refused BEFORE settlement (zero shares created)",
    ledger().docs.filter((d) => d.type === "share").length === 0);
}

// ---- independent case N: FORMATION_HALT_AFTER=flip is REFUSED on the no-flip ledger
//      (a silently ignored hook would let a harness setup pass vacuously) ----
if (PARED) {
  writeSeed();
  const r = runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "flip" });
  ok("HALT=flip is refused loudly on the immutable-pool ledger",
    r.code !== 0 && /does not exist on an[\s\S]*immutable-pool ledger/.test(r.out));
  ok("the refused run wrote nothing", receipts().length === 0 && !hasInFlightEvidence());
}

fs.rmSync(ROOT, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
