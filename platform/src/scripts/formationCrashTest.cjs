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
// against the pool through the shared six-duty check, and names exactly REAL_HASH
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
    // the harness holds both seeded records, so duty 6 is checked with their real
    // owners rather than declared away (pass 10, F5: duty 6 fails closed)
    receiptOwnerId: rs[0].ownerId, poolOwnerId: p.ownerId,
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
    // A FIXTURE MISSING THE CONSTRAINT'S OWN INPUT IS A BROKEN FIXTURE, NEVER A SATISFIED
    // CONSTRAINT (pass 11, F2). Both owner-only rows were gated on the contract owner
    // being truthy, so a ledger carrying contractId and docs but no contractOwner admitted
    // a create from any identity. Every seed here supplies it, which is exactly why the
    // gap survived: the vacuous branch had no caller, so nothing observed it. These two
    // cases are that observation, one per document type, since a repair to only one row
    // would leave the other silent.
    const ownerless = { ...seededLedger, contractOwner: undefined };
    ok("mock REFUSES a pool create when the ledger carries no contractOwner",
      /cannot be evaluated/.test((() => {
        try { mock.assertCreateAllowed(ownerless, { type: "pool", ownerId: OP, data: poolData }); return ""; }
        catch (e) { return e.message; }
      })()));
    ok("mock REFUSES a receipt create when the ledger carries no contractOwner",
      /cannot be evaluated/.test((() => {
        try {
          mock.assertCreateAllowed(ownerless, { type: "completionReceipt", ownerId: OP,
            data: { poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
              proTxHash: REAL_HASH, slotIndex: 0 } });
          return "";
        } catch (e) { return e.message; }
      })()));
    // A PLACEHOLDER STRING IS NOT AN IDENTITY (pre-commit check on the first draft). That
    // draft only required contractOwner to be a nonempty string, so a ledger and a record
    // both carrying a single space matched each other and passed the Owner Only
    // constraint having established nothing.
    const spaceOwner = { ...seededLedger, contractOwner: " " };
    ok("mock REFUSES when contractOwner is a nonempty string that is not an identity",
      /parses as an identity/.test((() => {
        try { mock.assertCreateAllowed(spaceOwner, { type: "pool", ownerId: " ", data: poolData }); return ""; }
        catch (e) { return e.message; }
      })()));
    // BOTH SIDES canonicalize, so an owner supplied as an Identifier OBJECT is the same
    // owner as the base58 string (pre-commit re-check: parsing only the ledger's side
    // would refuse this legitimately-matching record)
    ok("mock accepts a pool create whose ownerId is an Identifier object for the same identity",
      threwWith({ type: "pool", ownerId: Identifier.from(OP), data: poolData }) === null);

    // THE PLEDGE SLOT WAS NOT MODELLED AT ALL (pass 12, F2). Its published schema bounds
    // slotNo, forbids extra properties, and carries a UNIQUE bySlot index on
    // (poolId, slotNo) that is what stops two members reserving one slot. The mock
    // validated pool, receipt and share creates and let every pledgeSlot through, so a
    // reservation-writer regression could pass this matrix green.
    // the seed ALREADY holds slots 0 and 1 of POOL, so these cases run against real seeded
    // data rather than a synthetic row. A first draft asserted that slot 0 was accepted,
    // which the seed correctly refused: the fixture was wrong, not the code.
    const slotPoolHex = Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex");
    const slotScript = "76a914" + "11".repeat(20) + "88ac";
    const slotAt = (poolHex, n) => ({ poolId: poolHex, slotNo: n, rewardScript: slotScript });
    // the assertion checks the SEED IT NAMES before checking the refusal, because "a free
    // slot of the seeded pool" said against an empty ledger is vacuously true (pre-commit
    // item b: the earlier name was wider than its check)
    ok("the seed this block reasons about actually holds slots 0 and 1 of POOL",
      seededLedger.docs.filter((d) => d.type === "pledgeSlot"
        && d.data.poolId === slotPoolHex).map((d) => d.data.slotNo).sort().join(",") === "0,1");
    ok("mock accepts a pledgeSlot on a FREE slot of the seeded pool",
      threwWith({ type: "pledgeSlot", ownerId: F1, data: slotAt(slotPoolHex, 5) }) === null);
    // the unique index is OWNER-INDEPENDENT: a SECOND member colliding on a slot another
    // member already holds is the case that must be refused, and using a different owner
    // is what distinguishes this index from the per-owner share index above
    ok("mock REFUSES a pledgeSlot on a (poolId, slotNo) another member already holds",
      /duplicate unique index bySlot for pledgeSlot/.test((() => {
        try { mock.assertCreateAllowed(seededLedger, { type: "pledgeSlot", ownerId: OP,
          data: slotAt(slotPoolHex, 0) }); return ""; } catch (e) { return e.message; }
      })()));
    // HEX IS CASE-INSENSITIVE AS AN ENCODING, so uppercase hex for the same bytes is the
    // same key and must also be refused (pre-commit item c: the canonicalizer passed
    // strings through, so a direct caller could slip a duplicate past the index by
    // changing case; the sweep found the same shape at the receipt's bySlot site)
    ok("mock REFUSES the same (poolId, slotNo) written in UPPERCASE hex",
      /duplicate unique index bySlot for pledgeSlot/.test((() => {
        try { mock.assertCreateAllowed(seededLedger, { type: "pledgeSlot", ownerId: OP,
          data: slotAt(slotPoolHex.toUpperCase(), 0) }); return ""; } catch (e) { return e.message; }
      })()));
    // and the index is keyed on the PAIR, not on slotNo alone: the same slot number of a
    // DIFFERENT pool is a different key and must be admitted
    const otherPoolHex = Buffer.from(Identifier.from(
      Identifier.from(crypto.createHash("sha256").update("slot-other-pool").digest()).toString()
    ).toBuffer()).toString("hex");
    ok("mock ACCEPTS the same slotNo on a DIFFERENT pool (the key is the pair, not slotNo)",
      threwWith({ type: "pledgeSlot", ownerId: OP, data: slotAt(otherPoolHex, 0) }) === null);
    // the props validator, driven through the same exported surface as the others
    const slotPropsThrew = (props) => {
      try { mock.validateSlotProps(props); return ""; } catch (e) { return e.message; }
    };
    const slotProps = { poolId: Buffer.from(Identifier.from(POOL).toBuffer()),
      slotNo: 0, rewardScript: Buffer.from("76a914" + "11".repeat(20) + "88ac", "hex") };
    ok("mock pledgeSlot schema accepts a well-formed slot", slotPropsThrew(slotProps) === "");
    ok("mock pledgeSlot schema rejects an unknown property",
      /unknown property/.test(slotPropsThrew({ ...slotProps, surprise: 1 })));
    ok("mock pledgeSlot schema rejects a missing rewardScript",
      /missing required rewardScript/.test(slotPropsThrew({ poolId: slotProps.poolId, slotNo: 0 })));
    // v9 tightened slotNo to 511 to match the slot-count ceiling. This whole block is
    // inside the PARED gate, so only the v9 bound is reachable here and only it is
    // asserted: writing the v8 branch as well would add an arm no run can take, which is
    // the untestable-branch shape this round has twice deleted rather than kept. The
    // validator reads the bound from the same ledger predicate the tree uses, so the v8
    // ceiling is not hardcoded either.
    ok("mock pledgeSlot schema bounds slotNo at the v9 ceiling of 511",
      /slotNo out of 0\.\.511/.test(slotPropsThrew({ ...slotProps, slotNo: 512 })));
    ok("...and admits the last legal slot", slotPropsThrew({ ...slotProps, slotNo: 511 }) === "");
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
  // THE KEY CHECK'S INDEPENDENT OBSERVATION: every listed type now carries a value
  // validator (votePreference was the last, confirm-pass round 8), and none of the value
  // branches reads unknown keys, so the unknown-property refusals below are what observe
  // the key allowlist itself; severing it leaves every value case green and fails exactly
  // these.
  const voteRec = { type: "votePreference", data: { choice: "yes" } };
  const trv = (pending) => {
    try { mock.assertReplaceAllowed(voteRec, pending); return null; } catch (e) { return e.message; }
  };
  ok("mock accepts a legitimate votePreference replace", trv({ choice: "no" }) === null);
  ok("mock rejects a votePreference replace introducing an unknown property (the key check's own observation)",
    /unknown property sneaky/.test(trv({ sneaky: 1 }) || ""));
  // votePreference replace VALUES are schema-bounded too (confirm-pass round 8, major:
  // the documented key-check-only exception was not schema parity, and a governance
  // writer regression walking choice outside the enum or shortening delegateTo passed)
  ok("mock rejects a votePreference replace walking choice outside the enum",
    /choice "not-a-choice" not in the enum/.test(trv({ choice: "not-a-choice" }) || ""));
  ok("mock rejects a votePreference replace with a short delegateTo",
    /delegateTo is not a 32-byte array/.test(trv({ delegateTo: Buffer.alloc(1) }) || ""));
  ok("mock accepts a votePreference replace with a valid 32-byte delegateTo",
    trv({ choice: "delegate", delegateTo: Buffer.alloc(32, 6) }) === null);
  // membershipRequest replace VALUES are schema-bounded (closing confirm-pass, major:
  // the key allowlist alone let status walk outside the enum, which the published
  // contract refuses)
  const reqRec = { type: "membershipRequest", data: { status: "pending" } };
  const trq = (pending) => {
    try { mock.assertReplaceAllowed(reqRec, pending); return null; } catch (e) { return e.message; }
  };
  ok("mock accepts a legitimate membershipRequest replace", trq({ status: "matched" }) === null);
  ok("mock rejects a membershipRequest replace introducing an unknown property",
    /unknown property sneaky/.test(trq({ sneaky: 1 }) || ""));
  ok("mock rejects a membershipRequest replace walking status outside the enum (the confirm-pass sequence)",
    /status "not-a-status" not in the enum/.test(trq({ status: "not-a-status" }) || ""));
  ok("mock rejects a membershipRequest replace walking amountDuffs negative",
    /amountDuffs is not a nonnegative integer/.test(trq({ amountDuffs: -1 }) || ""));
  // pledgeSlot replace VALUES are schema-bounded too (closing confirm-pass round 3,
  // major: the type was listed in the allowlist while its merged values went unchecked,
  // so a replace walking slotNo past the ledger ceiling or emptying the reward script
  // persisted). The ceiling is ledger-dependent, read the same way the create validator
  // reads it, so both harness ledgers pin their own bound.
  const slotRec = { type: "pledgeSlot", data: { slotNo: 0, rewardScript: "76a914" + "11".repeat(20) + "88ac" } };
  const trs = (pending) => {
    try { mock.assertReplaceAllowed(slotRec, pending); return null; } catch (e) { return e.message; }
  };
  const slotCeil = PARED ? 511 : 9999;
  ok("mock accepts a legitimate pledgeSlot replace", trs({ slotNo: 3 }) === null);
  ok("mock rejects a pledgeSlot replace walking slotNo past the ledger ceiling",
    new RegExp(`slotNo out of 0\\.\\.${slotCeil}`).test(trs({ slotNo: slotCeil + 1 }) || ""));
  ok("mock rejects a pledgeSlot replace walking slotNo negative",
    new RegExp(`slotNo out of 0\\.\\.${slotCeil}`).test(trs({ slotNo: -1 }) || ""));
  ok("mock rejects a pledgeSlot replace emptying the reward script",
    /rewardScript is not a 1\.\.34 byteArray/.test(trs({ rewardScript: Buffer.alloc(0) }) || ""));
  ok("mock accepts a pledgeSlot replace with a valid byte reward script",
    trs({ rewardScript: Buffer.from("76a914" + "22".repeat(20) + "88ac", "hex") }) === null);
  // settlement and rewardAccrual replaces (confirm-pass round 11, major: both were absent
  // from REPLACE_KEYS, so the matcher's real phase transition went unvalidated and any
  // accrual replacement passed blind)
  const setRec = { type: "settlement", data: { phase: "prepared" } };
  const trt = (pending) => {
    try { mock.assertReplaceAllowed(setRec, pending); return null; } catch (e) { return e.message; }
  };
  ok("mock accepts the matcher's real settlement phase walk", trt({ phase: "matched" }) === null);
  ok("mock rejects a settlement replace walking phase outside the enum",
    /phase "not-a-phase" not in the enum/.test(trt({ phase: "not-a-phase" }) || ""));
  ok("mock rejects a settlement replace touching a creation-time field",
    /unknown property exitId/.test(trt({ exitId: Buffer.alloc(32, 9) }) || ""));
  const accRec = { type: "rewardAccrual", data: { amountDuffs: 5 } };
  ok("mock rejects ANY rewardAccrual replacement (no legitimate one exists, stated scope)",
    /unknown property amountDuffs/.test((() => { try {
      mock.assertReplaceAllowed(accRec, { amountDuffs: -1 }); return ""; }
      catch (e) { return e.message; } })()));
  // ...and the CREATE validator enforces the same schema (the confirm-pass major's other
  // half: create validated four types and omitted this one)
  const goodReq = { poolId: Buffer.alloc(32, 5), kind: "join", amountDuffs: 50000000000,
    status: "pending", provenance: "pledge", rewardScript: Buffer.alloc(25, 6) };
  const vr = (p) => { try { mock.validateRequestProps(p); return null; } catch (e) { return e.message; } };
  ok("request create: a well-formed request validates", vr(goodReq) === null);
  ok("request create: a status outside the enum is refused",
    /status not in the enum/.test(vr({ ...goodReq, status: "not-a-status" }) || ""));
  ok("request create: a negative amountDuffs is refused",
    /amountDuffs is not a nonnegative integer/.test(vr({ ...goodReq, amountDuffs: -1 }) || ""));
  ok("request create: a hex-STRING poolId is refused (writer values are bytes)",
    /poolId is not a 32-byte array/.test(vr({ ...goodReq, poolId: "05".repeat(32) }) || ""));
  ok("request create: a provenance outside the enum is refused",
    /provenance not in the enum/.test(vr({ ...goodReq, provenance: "stolen-valor" }) || ""));
  ok("request create: an unknown property is refused",
    /unknown property surprise/.test(vr({ ...goodReq, surprise: 1 }) || ""));
  // EVERY validator's required loop demands OWN properties (confirm-pass round 6, E1:
  // `p[k]` read the prototype chain, so Object.create over valid props passed all five
  // validators with zero own fields, and create then stored a record holding only
  // $createdAt, which real DPP refuses). Each is pinned with its own valid fixture
  // accepted and its inherited-only bag refused.
  {
    const goodSlot = { poolId: Buffer.alloc(32, 7), slotNo: 0,
      rewardScript: Buffer.from("76a914" + "33".repeat(20) + "88ac", "hex") };
    const goodShare = { poolId: Buffer.alloc(32, 8), shareBps: 5000, contributionDuffs: 1 };
    const goodReceipt = {
      poolId: Buffer.from(Identifier.from(POOL).toBuffer()),
      proTxHash: Buffer.from(EXPECTED.proTxHash, "hex"), slotIndex: 0, formatVersion: 1,
      allocationRows: Buffer.from(EXPECTED.allocationRows, "hex"),
      allocationHash: Buffer.from(EXPECTED.allocationHash, "hex"),
      participantCount: 2, l1Verification: "demo-unverified", verificationMethodVersion: 1,
      ...(PARED ? {} : { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 }),
    };
    const goodPool = PARED
      ? { slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000,
          slotDuffs: 50000000000, slotCount: 2 }
      : { proTxHash: Buffer.alloc(32, 9), slotIndex: 0, nodeType: "regular", status: "forming",
          operatorIdentityId: Buffer.alloc(32, 4), operatorFeeBps: 2000 };
    const goodVote = { poolId: Buffer.alloc(32, 11), proposalHash: Buffer.alloc(32, 12),
      choice: "delegate", delegateTo: Buffer.alloc(32, 13) };
    for (const [label, validator, good] of [
      ["pool", mock.validatePoolProps, goodPool],
      ["pledgeSlot", mock.validateSlotProps, goodSlot],
      ["share", mock.validateShareProps, goodShare],
      ["completionReceipt", mock.validateReceiptProps, goodReceipt],
      ["membershipRequest", mock.validateRequestProps, goodReq],
      ["votePreference", mock.validateVoteProps, goodVote],
      ["rewardAccrual", mock.validateAccrualProps,
        { poolId: Buffer.alloc(32, 14), funderId: Buffer.alloc(32, 15), amountDuffs: 100,
          epochHeight: 5, shareBps: 5000, kind: "reward" }],
      ["settlement", mock.validateSettlementProps,
        { poolId: Buffer.alloc(32, 16), exitId: Buffer.alloc(32, 17), joinId: Buffer.alloc(32, 18),
          leaverId: Buffer.alloc(32, 19), joinerId: Buffer.alloc(32, 20), amountDuffs: 100,
          shareBps: 5000, phase: "prepared" }],
    ]) {
      const v = (p) => { try { validator(p); return null; } catch (e) { return e.message; } };
      ok(`${label} validator: the valid fixture is accepted`, v(good) === null);
      ok(`${label} validator: an INHERITED-only property bag is refused (own properties, not the prototype)`,
        /missing/.test(v(Object.create(good)) || ""));
    }
    // ...and OPTIONAL fields are judged by OWN presence only (confirm-pass round 7,
    // minor, the false-refusal mirror): a v8 pool with every required field OWN and a
    // slotCount reachable only through the prototype serializes as a valid BOOKLESS pool
    // (create copies own entries), so refusing it as one-sided was stricter than the
    // document the mock would actually store
    if (!PARED) {
      const inheritedBook = Object.assign(Object.create({ slotCount: 2 }), goodPool);
      ok("pool validator: a prototype-only slotCount does not make an own bookless pool one-sided",
        (() => { try { mock.validatePoolProps(inheritedBook); return true; } catch { return false; } })());
    }
  }
  // ...and the CREATE PATH ITSELF routes through the validator (the first mutation run on
  // this fold severed the create wiring and nothing failed, because every case above
  // calls the validator directly; this child drives documents.create, the real path)
  {
    const wiredProbe = `
      const mock = require(${JSON.stringify(path.join(__dirname, "formationMockDash.cjs"))});
      const c = new mock.Client({});
      const id = { getId: () => ({ toString: () => "op" }) };
      c.platform.documents.create("poolLedger.membershipRequest", id,
        { poolId: Buffer.alloc(32, 5), kind: "join", amountDuffs: 1, status: "not-a-status" })
        .then(() => process.exit(0), (e) => { console.error(e.message); process.exit(3); });`;
    const rw = (() => { try { return { code: 0, out: execFileSync("node", ["-e", wiredProbe],
      { env: { ...process.env }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }; }
      catch (e) { return { code: e.status, out: (e.stdout || "") + (e.stderr || "") }; } })();
    ok("the CREATE PATH routes membershipRequest through the validator (wiring, not only the function)",
      rw.code === 3 && /status not in the enum/.test(rw.out));
    // ...and votePreference's wiring is observed the same way (confirm-pass round 8: the
    // severed-wiring mutation failed nothing until this probe existed, the same lesson as
    // the request's probe above)
    const voteProbe = `
      const mock = require(${JSON.stringify(path.join(__dirname, "formationMockDash.cjs"))});
      const c = new mock.Client({});
      const id = { getId: () => ({ toString: () => "op" }) };
      c.platform.documents.create("poolLedger.votePreference", id,
        { poolId: Buffer.alloc(32, 5), proposalHash: Buffer.alloc(32, 6), choice: "not-a-choice" })
        .then(() => process.exit(0), (e) => { console.error(e.message); process.exit(3); });`;
    const rv = (() => { try { return { code: 0, out: execFileSync("node", ["-e", voteProbe],
      { env: { ...process.env }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }; }
      catch (e) { return { code: e.status, out: (e.stdout || "") + (e.stderr || "") }; } })();
    ok("the CREATE PATH routes votePreference through the validator (wiring, not only the function)",
      rv.code === 3 && /choice not in the enum/.test(rv.out));
    // the same wiring observation for the two types round 10 added, applied the day they
    // arrived rather than a round later
    const wiredCase = (type, propsJs) => {
      const probe = `
        const mock = require(${JSON.stringify(path.join(__dirname, "formationMockDash.cjs"))});
        const c = new mock.Client({});
        const id = { getId: () => ({ toString: () => "op" }) };
        c.platform.documents.create(${JSON.stringify(type)}, id, ${propsJs})
          .then(() => process.exit(0), (e) => { console.error(e.message); process.exit(3); });`;
      try { return { code: 0, out: execFileSync("node", ["-e", probe],
        { env: { ...process.env }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }; }
      catch (e) { return { code: e.status, out: (e.stdout || "") + (e.stderr || "") }; }
    };
    const ra = wiredCase("poolLedger.rewardAccrual",
      '{ poolId: Buffer.alloc(32, 1), funderId: Buffer.alloc(32, 2), amountDuffs: 1, epochHeight: 1, shareBps: 1, kind: "not-a-kind" }');
    ok("the CREATE PATH routes rewardAccrual through the validator (wiring)",
      ra.code === 3 && /kind not in the enum/.test(ra.out));
    const se = wiredCase("poolLedger.settlement",
      '{ poolId: Buffer.alloc(32, 1), exitId: Buffer.alloc(32, 2), joinId: Buffer.alloc(32, 3), leaverId: Buffer.alloc(32, 4), joinerId: Buffer.alloc(32, 5), amountDuffs: 1, shareBps: 1, phase: "not-a-phase" }');
    ok("the CREATE PATH routes settlement through the validator (wiring)",
      se.code === 3 && /phase not in the enum/.test(se.out));
    // the strict per-ledger TYPE model (confirm-pass round 12): a poolLedger type absent
    // from the selected contract is refused like the real SDK refuses an undefined
    // document type, never resolved as an empty page (the always-empty answer hid two
    // capability-blind call sites across this round, reserve's and the debris sweep's)
    const v1Probe = `
      process.env.LEDGER = "v1";
      const mock = require(${JSON.stringify(path.join(__dirname, "formationMockDash.cjs"))});
      const c = new mock.Client({});
      c.platform.documents.get("poolLedger.settlement", {})
        .then(() => process.exit(0), (e) => { console.error(e.message); process.exit(3); });`;
    const rt = (() => { try { return { code: 0, out: execFileSync("node", ["-e", v1Probe],
      { env: { ...process.env, LEDGER: "v1" }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }; }
      catch (e) { return { code: e.status, out: (e.stdout || "") + (e.stderr || "") }; } })();
    ok("mock refuses a query for a type the selected ledger does not define (v1 settlement)",
      rt.code === 3 && /not defined by the selected ledger/.test(rt.out));
    // PER-LEDGER PROPERTY SHAPES (confirm-pass round 13, major: the validators assumed
    // the v8 shape everywhere, refusing valid base documents and accepting
    // later-capability fields the earlier contracts refuse). Each case swaps the ledger
    // env and re-requires the mock, the same pattern as the v8 create block.
    {
      const withMock = (ledgerV, fn) => {
        const prev = process.env.LEDGER;
        process.env.LEDGER = ledgerV;
        delete require.cache[require.resolve("./envStore.cjs")];
        delete require.cache[require.resolve("./formationMockDash.cjs")];
        const m = require("./formationMockDash.cjs");
        try { fn(m); } finally {
          if (prev === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev;
          delete require.cache[require.resolve("./envStore.cjs")];
          delete require.cache[require.resolve("./formationMockDash.cjs")];
        }
      };
      const tryV = (fn) => { try { fn(); return null; } catch (e) { return e.message; } };
      const baseAcc = { poolId: Buffer.alloc(32, 21), funderId: Buffer.alloc(32, 22),
        amountDuffs: 100, epochHeight: 5 };
      withMock("v1", (m) => {
        ok("v1: a valid BASE accrual (no shareBps, no kind) is accepted",
          tryV(() => m.validateAccrualProps(baseAcc)) === null);
        ok("v1: an accrual carrying the v3 shareBps is refused (additionalProperties)",
          /unknown property shareBps/.test(tryV(() => m.validateAccrualProps({ ...baseAcc, shareBps: 5000 })) || ""));
        ok("v1: a request carrying the v5 provenance is refused",
          /unknown property provenance/.test(tryV(() => m.validateRequestProps({
            poolId: Buffer.alloc(32, 23), kind: "join", amountDuffs: 1, status: "pending",
            provenance: "pledge" })) || ""));
        ok("v1: a vote carrying the v5 delegateTo is refused",
          /unknown property delegateTo/.test(tryV(() => m.validateVoteProps({
            poolId: Buffer.alloc(32, 24), proposalHash: Buffer.alloc(32, 25), choice: "delegate",
            delegateTo: Buffer.alloc(32, 26) })) || ""));
        ok("v1: a valid BASE pool (no status, no book) is accepted",
          tryV(() => m.validatePoolProps({ proTxHash: Buffer.alloc(32, 27), slotIndex: 0,
            nodeType: "regular" })) === null);
        ok("v1: a pool carrying the v5 status is refused",
          /unknown property status/.test(tryV(() => m.validatePoolProps({
            proTxHash: Buffer.alloc(32, 27), slotIndex: 0, nodeType: "regular",
            status: "forming" })) || ""));
      });
      withMock("v3", (m) => {
        ok("v3: an accrual with shareBps and NO kind is accepted (kind is v4)",
          tryV(() => m.validateAccrualProps({ ...baseAcc, shareBps: 5000 })) === null);
        ok("v3: an accrual carrying the v4 kind is refused",
          /unknown property kind/.test(tryV(() => m.validateAccrualProps({ ...baseAcc,
            shareBps: 5000, kind: "reward" })) || ""));
      });
      withMock("v4", (m) => {
        ok("v4: an accrual without kind is refused (required from its introduction)",
          /missing kind/.test(tryV(() => m.validateAccrualProps({ ...baseAcc, shareBps: 5000 })) || ""));
      });
      // REPLACE allowlists are version-aware too (confirm-pass round 14: the static
      // superset admitted v5/v7 fields into v1 replaces the earlier contracts refuse)
      withMock("v1", (m) => {
        const rep = (type, data, pending) => tryV(() => m.assertReplaceAllowed({ type, data }, pending));
        ok("v1: a pool replace adding the v5 status is refused",
          /unknown property status/.test(rep("pool", { proTxHash: "aa".repeat(32) }, { status: "live" }) || ""));
        ok("v1: a pool replace adding the v7 slot book is refused",
          /unknown property slot/.test(rep("pool", { proTxHash: "aa".repeat(32) },
            { slotDuffs: 1, slotCount: 1 }) || ""));
        ok("v1: a request replace adding the v5 provenance is refused",
          /unknown property provenance/.test(rep("membershipRequest", { status: "pending" },
            { provenance: "pledge" }) || ""));
        ok("v1: a vote replace adding the v5 delegateTo is refused",
          /unknown property delegateTo/.test(rep("votePreference", { choice: "yes" },
            { delegateTo: Buffer.alloc(32, 6) }) || ""));
        // the base accrual index is NOT unique (uniqueness begins at v3), so a valid v1
        // duplicate must be accepted
        const led14 = { docs: [{ type: "rewardAccrual", id: "seeded", ownerId: "op", data: {
          poolId: "08".repeat(32), funderId: "09".repeat(32), epochHeight: 5, amountDuffs: 1 } }] };
        ok("v1: a duplicate (pool, funder, epoch) accrual is ACCEPTED (the base index is not unique)",
          tryV(() => m.assertCreateAllowed(led14, { type: "rewardAccrual", ownerId: "op", data: {
            poolId: "08".repeat(32), funderId: "09".repeat(32), epochHeight: 5, amountDuffs: 2 } })) === null);
      });
      // the v7 book ceiling is the PUBLISHED contract's 10000, not the v8 source's 512
      // (confirm-pass round 15, minor: the reviewer's 625-slot regular book is
      // schema-valid on v7 and totals the tier exactly, and the mock refused it)
      withMock("v7", (m) => {
        ok("v7: a schema-valid 625-slot book is accepted (the published ceiling is 10000)",
          tryV(() => m.validatePoolProps({ proTxHash: Buffer.alloc(32, 31), slotIndex: 0,
            nodeType: "regular", status: "forming", slotDuffs: 160000000, slotCount: 625 })) === null);
        ok("v7: a book above the published 10000 is refused",
          /slotCount out of 1\.\.10000/.test(tryV(() => m.validatePoolProps({
            proTxHash: Buffer.alloc(32, 31), slotIndex: 0, nodeType: "regular",
            status: "forming", slotDuffs: 160000000, slotCount: 10001 })) || ""));
      });
      // the v6 reservation is SIZED, IMMUTABLE and UNDELETABLE
      withMock("v6", (m) => {
        const writerShaped = { poolId: Buffer.alloc(32, 30), slotNo: 0, slotDuffs: 50000000000,
          rewardScript: Buffer.from("76a914" + "44".repeat(20) + "88ac", "hex") };
        ok("v6: the writer-shaped SIZED claim is accepted (slotDuffs required there)",
          tryV(() => m.validateSlotProps(writerShaped)) === null);
        ok("v6: a v7-shaped sizeless claim is refused (missing slotDuffs)",
          /missing required slotDuffs/.test(tryV(() => m.validateSlotProps({
            poolId: Buffer.alloc(32, 30), slotNo: 0,
            rewardScript: Buffer.from("76a914" + "44".repeat(20) + "88ac", "hex") })) || ""));
        ok("v6: a claim replace is refused (immutable)",
          /not mutable/.test(tryV(() => m.assertMutationAllowed("replace",
            { type: "pledgeSlot", data: {} })) || ""));
        ok("v6: a claim delete is refused (undeletable)",
          /cannot be deleted/.test(tryV(() => m.assertMutationAllowed("delete",
            { type: "pledgeSlot", data: {} })) || ""));
      });
      // ...and the v7+ claim stays mutable (the round-14 rule must not overreach)
      withMock("v8", (m) => {
        ok("v8: a claim replace stays allowed (sizeless mutable claims from v7)",
          tryV(() => m.assertMutationAllowed("replace", { type: "pledgeSlot", data: {} })) === null);
      });
    }
    // the UNIQUE byPoolOwnerProposal index at create (confirm-pass round 9, E-1): one
    // owner, one preference per pool and proposal; the same owner's second vote on the
    // same pair is refused, a different proposal or a different owner is not
    const led9 = { docs: [{ type: "votePreference", id: "seeded-v", ownerId: "op",
      data: { poolId: "05".repeat(32), proposalHash: "06".repeat(32), choice: "yes" } }] };
    const cv = (ownerId, poolHex, propHex) => { try {
      mock.assertCreateAllowed(led9, { type: "votePreference", ownerId,
        data: { poolId: poolHex, proposalHash: propHex, choice: "no" } }); return null; }
      catch (e) { return e.message; } };
    ok("vote create: the same owner's second vote on the same pool and proposal is refused",
      /duplicate unique index byPoolOwnerProposal/.test(cv("op", "05".repeat(32), "06".repeat(32)) || ""));
    ok("vote create: the same owner on a DIFFERENT proposal is accepted",
      cv("op", "05".repeat(32), "07".repeat(32)) === null);
    ok("vote create: a DIFFERENT owner on the same pair is accepted",
      cv("other", "05".repeat(32), "06".repeat(32)) === null);
    // the two inherited types' unique indexes (confirm-pass round 10): one accrual per
    // (pool, funder, epoch, kind), and each exit or join settles at most once
    const led10 = { docs: [
      { type: "rewardAccrual", id: "seeded-a", ownerId: "op", data: {
        poolId: "08".repeat(32), funderId: "09".repeat(32), epochHeight: 5, kind: "reward",
        amountDuffs: 100, shareBps: 5000 } },
      { type: "settlement", id: "seeded-s", ownerId: "op", data: {
        poolId: "08".repeat(32), exitId: "0a".repeat(32), joinId: "0b".repeat(32),
        leaverId: "0c".repeat(32), joinerId: "0d".repeat(32), amountDuffs: 100,
        shareBps: 5000, phase: "prepared" } } ] };
    const ca = (data) => { try {
      mock.assertCreateAllowed(led10, { type: "rewardAccrual", ownerId: "op", data }); return null; }
      catch (e) { return e.message; } };
    ok("accrual create: a duplicate (pool, funder, epoch, kind) is refused",
      /duplicate unique index byPoolFunder/.test(ca({ poolId: "08".repeat(32), funderId: "09".repeat(32),
        epochHeight: 5, kind: "reward", amountDuffs: 1, shareBps: 1 }) || ""));
    ok("accrual create: the OTHER kind at the same epoch is accepted",
      ca({ poolId: "08".repeat(32), funderId: "09".repeat(32), epochHeight: 5, kind: "principal",
        amountDuffs: 1, shareBps: 1 }) === null);
    const cs = (data) => { try {
      mock.assertCreateAllowed(led10, { type: "settlement", ownerId: "op", data }); return null; }
      catch (e) { return e.message; } };
    ok("settlement create: a reused exitId is refused whatever the joinId",
      /duplicate unique index byExit/.test(cs({ poolId: "08".repeat(32), exitId: "0a".repeat(32),
        joinId: "0e".repeat(32), leaverId: "0c".repeat(32), joinerId: "0d".repeat(32),
        amountDuffs: 1, shareBps: 1, phase: "prepared" }) || ""));
    ok("settlement create: a reused joinId is refused whatever the exitId",
      /duplicate unique index byJoin/.test(cs({ poolId: "08".repeat(32), exitId: "0f".repeat(32),
        joinId: "0b".repeat(32), leaverId: "0c".repeat(32), joinerId: "0d".repeat(32),
        amountDuffs: 1, shareBps: 1, phase: "prepared" }) || ""));
    ok("settlement create: fresh exit and join ids are accepted",
      cs({ poolId: "08".repeat(32), exitId: "0f".repeat(32), joinId: "0e".repeat(32),
        leaverId: "0c".repeat(32), joinerId: "0d".repeat(32),
        amountDuffs: 1, shareBps: 1, phase: "prepared" }) === null);
    // THE v3 EXCEPTION (confirm-pass round 17, E-1): the registered v3 publish predates
    // the byJoin index (registerV4.cjs is the first carrying it), so on v3 a second
    // settlement against the same join is ACCEPTED by the published schema while a
    // reused exit stays refused; env-swapped, ledgerVersion() reads dynamically
    {
      const prev = process.env.LEDGER;
      process.env.LEDGER = "v3";
      ok("settlement create on v3: a reused joinId is accepted (the registered v3 publish predates byJoin)",
        cs({ poolId: "08".repeat(32), exitId: "1a".repeat(32), joinId: "0b".repeat(32),
          leaverId: "0c".repeat(32), joinerId: "0d".repeat(32),
          amountDuffs: 1, shareBps: 1, phase: "prepared" }) === null);
      ok("settlement create on v3: a reused exitId is still refused (byExit is in the v3 publish)",
        /duplicate unique index byExit/.test(cs({ poolId: "08".repeat(32), exitId: "0a".repeat(32),
          joinId: "1e".repeat(32), leaverId: "0c".repeat(32), joinerId: "0d".repeat(32),
          amountDuffs: 1, shareBps: 1, phase: "prepared" }) || ""));
      // THE RANGE IS PINNED MEMBER BY MEMBER (round-17 checker, finding 1): the suite's
      // default ledger exercises the gate at one point only, so a gate wrongly disabled
      // on any single later ledger would stay green; every publish carrying byJoin is
      // driven here explicitly
      for (const v of ["v4", "v5", "v6", "v7", "v8", "v9"]) {
        process.env.LEDGER = v;
        ok(`settlement create on ${v}: a reused joinId is refused (this publish carries byJoin)`,
          /duplicate unique index byJoin/.test(cs({ poolId: "08".repeat(32), exitId: "1b".repeat(32),
            joinId: "0b".repeat(32), leaverId: "0c".repeat(32), joinerId: "0d".repeat(32),
            amountDuffs: 1, shareBps: 1, phase: "prepared" }) || ""));
      }
      if (prev === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev;
    }
  }
  // THE MAP'S MEMBERSHIP IS PINNED FIRST (artifact re-check: a loop over the map cannot
  // notice a deleted row, because the row's test disappears with it), then every listed
  // type is exercised.
  ok("the replace whitelist covers exactly the expected types",
    Object.keys(mock.REPLACE_KEYS).sort().join(",")
      === "membershipRequest,pledgeSlot,pool,rewardAccrual,settlement,share,votePreference");
  for (const [type, keys] of Object.entries(mock.REPLACE_KEYS)) {
    const r = { type, data: { poolId: Buffer.alloc(32, 1).toString("hex"),
      shareBps: 5000, contributionDuffs: 1 } };
    const attempt = (pending) => {
      try { mock.assertReplaceAllowed(r, pending); return null; } catch (e) { return e.message; }
    };
    ok(`replace whitelist covers ${type}: an unknown key is refused`,
      /unknown property/.test(attempt({ definitelyNotAField: 1 }) || ""));
    // a VALID value per type, so the assertion examines the attempt for every type
    // rather than OR-ing the value-validating ones away (the checker on this fold named
    // the OR a definite vacuous pass; share keeps its historical exemption because its
    // validator also demands the merged document's other fields, covered by its own cases).
    // membershipRequest gained a value validator on the closing confirm-pass, so its
    // first key (status) needs a schema-valid value here like pool's does.
    // rewardAccrual's key list is EMPTY on purpose (no legitimate replacement), so the
    // first-key acceptance case does not apply to it; its refusal-of-anything is pinned
    // separately below. The POOL's first key (status) exists only on the mutable ledgers
    // (round-14: the allowlist is capability-filtered, v9 subtracts poolStatus, and v9's
    // pool replace is refused upstream as immutable anyway), so its acceptance case runs
    // on the mutable pass only.
    if (keys.length > 0 && !(type === "pool" && PARED)) {
      ok(`replace whitelist covers ${type}: its own first key is accepted`,
        attempt({ [keys[0]]: type === "share" ? 5000
          : type === "pool" ? "live"
          : type === "membershipRequest" ? "matched"
          : type === "pledgeSlot" ? 3
          : type === "settlement" ? "matched"
          : type === "votePreference" ? "no" : "x" }) === null
        || type === "share");
    }
  }
  // POOL REPLACE VALUE BOUNDS (pass 16, F2): the flip invariants pinned status and
  // proTxHash and nothing else, so a replace walking slotCount to 0, which the published
  // schema refuses at minimum 1, passed the matrix. The merged document now validates.
  // the flip's replace validator semantics are the MUTABLE ledgers' (round-14: on v9 the
  // pool is immutable and its replace is refused upstream by assertMutationAllowed, which
  // has its own cases; the capability filter correctly strips status there, so driving
  // these value bounds under v9 would only observe the filter, not the bounds)
  if (!PARED) {
    const poolRec = { type: "pool", data: { status: "forming",
      proTxHash: "00".repeat(16) + "11".repeat(16), slotDuffs: 50000000000, slotCount: 2 } };
    const attemptP = (pending) => {
      try { mock.assertReplaceAllowed(poolRec, pending); return null; } catch (e) { return e.message; }
    };
    ok("pool replace: the normal flip is accepted",
      attemptP({ status: "live", proTxHash: Buffer.from("aa".repeat(32), "hex") }) === null);
    // a PENDING (writer) value must be BYTES (closing wave, FA3): the schema types the
    // field byteArray and real Platform rejects the string form, so a hex-string pending
    // value is a writer defect the mock must refuse rather than hex-decode into passing.
    // The STORED form staying hex is the mock's own serialization, covered above.
    ok("pool replace: a hex-STRING pending proTxHash is refused (writer values must be bytes)",
      /proTxHash is not a 32-byte array/.test(attemptP({ status: "live", proTxHash: "aa".repeat(32) }) || ""));
    ok("pool replace: slotCount 0 is refused (the reviewer's exact false-green)",
      /slotCount out of 1\.\.512/.test(attemptP({ slotDuffs: 50000000000, slotCount: 0 }) || ""));
    ok("pool replace: slotCount 513 is refused",
      /slotCount out of 1\.\.512/.test(attemptP({ slotDuffs: 50000000000, slotCount: 513 }) || ""));
    // the one-sided case needs a BOOKLESS base record: the shared base above carries
    // slotDuffs, so merging a slotCount onto it is two-sided. ACCEPTED as of round 18
    // (finding 2): the published v7/v8 pool schemas carry no dependentRequired, so a
    // one-sided merged result is schema-valid on the mutable ledgers and the earlier
    // refusal was the mock being wider than the contract it models. The base is a
    // COMPLETE v8 pool minus the book (round-18 checker, finding 1: the first draft
    // carried only status and proTxHash, a record the schema cannot hold), and both
    // one-sided directions are pinned (its finding 2)
    const bookless = { type: "pool", data: { status: "forming",
      proTxHash: "00".repeat(16) + "11".repeat(16), slotIndex: 0, nodeType: "regular",
      operatorFeeBps: 2000 } };
    const replaceAccepts = (pending) => { try { mock.assertReplaceAllowed(bookless, pending); return true; }
      catch { return false; } };
    ok("pool replace: a one-sided merged book (slotCount only) is accepted (no dependentRequired in the published v7/v8 schemas)",
      replaceAccepts({ slotCount: 4 }));
    ok("pool replace: the other direction (slotDuffs only) is accepted too",
      replaceAccepts({ slotDuffs: 25000000000 }));
    ok("pool replace: an out-of-enum status is refused",
      /not in the enum/.test(attemptP({ status: "banana" }) || ""));
    ok("pool replace: a short proTxHash byte value is refused",
      /proTxHash is not a 32-byte array/.test(attemptP({ proTxHash: Buffer.from("aa".repeat(31), "hex") }) || ""));
    // operatorIdentityId is a 32-byte identity field too, and was in the allowlist
    // unchecked until pass 17, F2
    ok("pool replace: a short operatorIdentityId is refused",
      /operatorIdentityId is not a 32-byte array/.test(attemptP({ operatorIdentityId: Buffer.from("aa", "hex") }) || ""));
    ok("pool replace: a full-length byte operatorIdentityId is accepted",
      attemptP({ operatorIdentityId: Buffer.from("cc".repeat(32), "hex") }) === null);
    ok("pool replace: a hex-STRING operatorIdentityId pending value is refused too",
      /operatorIdentityId is not a 32-byte array/.test(attemptP({ operatorIdentityId: "cc".repeat(32) }) || ""));
    // ...and a seeded-malformed STORED value still cannot ride through a replace unnoticed
    // (the guarantee the old merged-level check provided, kept under the split)
    const storedBad = (v) => (() => { try {
      mock.assertReplaceAllowed({ type: "pool", data: { status: "forming", proTxHash: v } },
        { status: "live" }); return ""; } catch (e) { return e.message; } })();
    ok("pool replace: a malformed STORED proTxHash is still caught on an unrelated replace",
      /proTxHash is not 32 bytes/.test(storedBad("zz")));
    // node's hex decode is LENIENT and stops at the first invalid character (checker on
    // this fold: the decode-then-measure form passed exactly this), so a hex-PREFIXED
    // garbage stored value must be caught by the exact-form rule, not by the decode length
    ok("pool replace: a hex-PREFIXED garbage STORED proTxHash is caught (lenient-decode trap)",
      /proTxHash is not 32 bytes/.test(storedBad("aa".repeat(32) + "zzGARBAGE")));
  }
  // POOL CREATE VALIDATION AND UNIQUE INDEX (pass 18, F2). The v8 pool create was
  // unvalidated (validatePoolProps returned early on non-immutable ledgers), and the
  // unique byProTxHash index was enforced only on the flip replace, not on create. The
  // harness SEEDS v8 pools rather than creating them, so these are direct-call cases like
  // the replace ones above, not a live create path.
  {
    const prev = process.env.LEDGER;
    process.env.LEDGER = "v8";
    delete require.cache[require.resolve("./envStore.cjs")];
    delete require.cache[require.resolve("./formationMockDash.cjs")];
    const m8 = require("./formationMockDash.cjs");
    // WRITER values are BYTES (closing wave, FA3): validatePoolProps runs on the raw
    // create props before the mock's hex serialization, and the schema types these
    // fields byteArray, so the well-formed fixture carries Buffers the way the real
    // writer does, and the hex-string spelling is a refusal case rather than an
    // alternate accepted form
    const goodV8 = { proTxHash: Buffer.from("aa".repeat(32), "hex"), slotIndex: 0, nodeType: "regular",
      operatorIdentityId: Buffer.from("bb".repeat(32), "hex"), operatorFeeBps: 2000, status: "forming" };
    const vp = (p) => { try { m8.validatePoolProps(p); return null; } catch (e) { return e.message; } };
    ok("v8 pool create: a well-formed pool validates", vp(goodV8) === null);
    ok("v8 pool create: an empty pool is refused (was unvalidated before)",
      /missing/.test(vp({}) || ""));
    ok("v8 pool create: a short proTxHash is refused",
      /proTxHash is not a 32-byte array/.test(vp({ ...goodV8, proTxHash: Buffer.from("aa", "hex") }) || ""));
    ok("v8 pool create: a hex-STRING proTxHash is refused (real Platform rejects the string form)",
      /proTxHash is not a 32-byte array/.test(vp({ ...goodV8, proTxHash: "aa".repeat(32) }) || ""));
    ok("v8 pool create: a 32-CHARACTER string proTxHash is refused too (the coercion spelling)",
      /proTxHash is not a 32-byte array/.test(vp({ ...goodV8, proTxHash: "A".repeat(32) }) || ""));
    ok("v8 pool create: a hex-STRING operatorIdentityId is refused too",
      /operatorIdentityId is not a 32-byte array/.test(vp({ ...goodV8, operatorIdentityId: "bb".repeat(32) }) || ""));
    ok("v8 pool create: a Uint8Array proTxHash is accepted (both byte forms are writer-legal)",
      vp({ ...goodV8, proTxHash: new Uint8Array(32).fill(0xaa) }) === null);
    ok("v8 pool create: an out-of-enum status is refused",
      /status not in the enum/.test(vp({ ...goodV8, status: "banana" }) || ""));
    ok("v8 pool create: an unknown property is refused",
      /unknown property/.test(vp({ ...goodV8, surprise: 1 }) || ""));
    // an INVENTED $-field is refused too: additionalProperties:false allows Platform's
    // KNOWN system fields, not any $-prefixed key (pass 18 checker on this fold)
    ok("v8 pool create: an invented $-prefixed property is refused",
      /unknown property/.test(vp({ ...goodV8, $surprise: 1 }) || ""));
    ok("v8 pool create: a real system field ($createdAt) is allowed",
      vp({ ...goodV8, $createdAt: 1 }) === null);
    // one-sided ACCEPTED as of round 18 (finding 2): neither the v7 nor the v8
    // published pool schema carries dependentRequired, so a one-sided book is
    // schema-valid here; only the v9 contract refuses it (pinned in the immutable
    // mock-schema block). Both directions, and the v7 selection too (round-18
    // checker, finding 2: one direction alone leaves a direction-specific
    // survivor)
    ok("v8 pool create: a one-sided slot book (slotCount only) is accepted (the published schema has no dependentRequired)",
      vp({ ...goodV8, slotCount: 2 }) === null);
    ok("v8 pool create: the other direction (slotDuffs only) is accepted too",
      vp({ ...goodV8, slotDuffs: 50000000000 }) === null);
    {
      const prev7 = process.env.LEDGER;
      process.env.LEDGER = "v7";
      ok("v7 pool create: a one-sided slot book is accepted (the v7 publish has no dependentRequired either)",
        vp({ ...goodV8, slotDuffs: 50000000000 }) === null);
      if (prev7 === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev7;
    }
    // the unique byProTxHash index on CREATE, against the other pools in the ledger
    const led = { docs: [{ type: "pool", id: "seeded-A", data: { proTxHash: "aa".repeat(32) } }] };
    const cr = (data) => { try { m8.assertCreateAllowed(led, { type: "pool", ownerId: "op", data }); return null; }
      catch (e) { return e.message; } };
    ok("v8 pool create: a SECOND pool with the same proTxHash is refused by the unique index",
      /duplicate unique index byProTxHash for pool/.test(cr({ proTxHash: "aa".repeat(32) }) || ""));
    ok("v8 pool create: the same hash in UPPERCASE is refused too (case-insensitive)",
      /duplicate unique index byProTxHash for pool/.test(cr({ proTxHash: "AA".repeat(32) }) || ""));
    ok("v8 pool create: a DIFFERENT proTxHash is accepted",
      cr({ proTxHash: "cc".repeat(32) }) === null);
    if (prev === undefined) delete process.env.LEDGER; else process.env.LEDGER = prev;
    delete require.cache[require.resolve("./envStore.cjs")];
    delete require.cache[require.resolve("./formationMockDash.cjs")];
  }
}

// SIGNER-TO-OWNER AUTHORIZATION parity (pass-7 wave, packet-review major 4): real Platform
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
  // WRITER-PRODUCIBLE, not merely schema-producible (pass 14, F5): the earlier fixture
  // carried empty rows and an unrelated all-03 hash, a pair the real writer cannot emit
  // because it derives both fields from one validated draft. EXPECTED is this harness's
  // independent reconstruction of exactly that derivation for POOL's real allocation, so
  // using it makes the fixture a document the reference writer could have written.
  const probeReceipt = {
    poolId: Buffer.from(Identifier.from(POOL).toBuffer()), proTxHash: Buffer.from(REAL_HASH, "hex"),
    slotIndex: 0,
    ...(PARED ? {} : { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 }),
    formatVersion: 1, allocationRows: Buffer.from(EXPECTED.allocationRows, "hex"),
    allocationHash: Buffer.from(EXPECTED.allocationHash, "hex"),
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

  // END-TO-END PLEDGE SLOT CREATES through the real client path, create then broadcast
  // (pre-commit item a). The direct-helper cases earlier prove the exported functions;
  // these prove the WIRING, because deleting the validateSlotProps line from create or
  // the pledgeSlot arm from assertCreateAllowed would leave the direct cases green while
  // real writes sailed through. Same child pattern as the deletes above, same reason.
  if (PARED) {
    const poolHexE2E = Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex");
    const slotScriptE2E = "76a914" + "44".repeat(20) + "88ac";
    const slotCreate = (fields, signer = F1) => `
      const mock = require(${JSON.stringify(path.join(__dirname, "formationMockDash.cjs"))});
      const c = new mock.Client({});
      const identity = { getId: () => ({ toString: () => ${JSON.stringify(signer)} }) };
      c.platform.documents.create("poolLedger.pledgeSlot", identity, ${fields})
        .then((doc) => c.platform.documents.broadcast({ create: [doc] }, identity))
        .then(() => process.exit(0), (e) => { console.error(e.message); process.exit(3); });`;
    const goodFields = `{ poolId: Buffer.from(${JSON.stringify(poolHexE2E)}, "hex"), slotNo: 7,
        rewardScript: Buffer.from(${JSON.stringify(slotScriptE2E)}, "hex") }`;
    const e2eBefore = ledger().docs.filter((d) => d.type === "pledgeSlot").length;
    const g = drive(slotCreate(goodFields));
    ok("end-to-end: a well-formed pledgeSlot create lands through create+broadcast", g.code === 0);
    ok("end-to-end: and it is durably on the persisted ledger",
      ledger().docs.filter((d) => d.type === "pledgeSlot").length === e2eBefore + 1);
    const dup = drive(slotCreate(goodFields, OP));
    ok("end-to-end: a second create on the same (poolId, slotNo) is refused AT BROADCAST",
      dup.code === 3 && /duplicate unique index bySlot for pledgeSlot/.test(dup.out));
    const malformed = drive(slotCreate(`{ poolId: Buffer.from(${JSON.stringify(poolHexE2E)}, "hex"),
        slotNo: 512, rewardScript: Buffer.from(${JSON.stringify(slotScriptE2E)}, "hex") }`));
    ok("end-to-end: an out-of-bounds slotNo is refused AT CREATE by the schema",
      malformed.code === 3 && /slotNo out of 0\.\.511/.test(malformed.out));
    ok("end-to-end: neither refusal left a document behind",
      ledger().docs.filter((d) => d.type === "pledgeSlot").length === e2eBefore + 1);
    // THE bySlot INDEX ON REPLACE (confirm-pass round 24, major): the published
    // pledgeSlot is unique on (poolId, slotNo) and slotNo is a replaceable key, so a
    // replace moving a claim onto the occupied slot 7 must refuse AT BROADCAST, where
    // the other claims are visible, exactly like the pass-17 pool-flip clash. A move
    // to a free slot stays accepted, pinning that the refusal is the collision and not
    // the replace itself.
    const slotReplace = (docId, slotNo, signer = F1) => `
      const mock = require(${JSON.stringify(path.join(__dirname, "formationMockDash.cjs"))});
      const c = new mock.Client({});
      const identity = { getId: () => ({ toString: () => ${JSON.stringify(signer)} }) };
      const doc = { __rec: { id: ${JSON.stringify(docId)} }, __pending: { slotNo: ${slotNo} } };
      c.platform.documents.broadcast({ replace: [doc] }, identity)
        .then(() => process.exit(0), (e) => { console.error(e.message); process.exit(3); });`;
    const mineFields = `{ poolId: Buffer.from(${JSON.stringify(poolHexE2E)}, "hex"), slotNo: 8,
        rewardScript: Buffer.from(${JSON.stringify(slotScriptE2E)}, "hex") }`;
    const g8 = drive(slotCreate(mineFields));
    ok("end-to-end: the second claim lands on the free slot 8", g8.code === 0);
    // selected by the COMPOSITE key, and required to exist (round-24 checker, finding
    // 3: a slotNo-only pick could grab an older claim in another pool)
    const claimAt = (poolHex, slotNo) => ledger().docs.find((d) => d.type === "pledgeSlot"
      && String(d.data.poolId).toLowerCase() === poolHex && Number(d.data.slotNo) === slotNo);
    const moved = claimAt(poolHexE2E, 8);
    ok("end-to-end: the created claim is findable by its composite (poolId, slotNo) key", !!moved);
    const movedId = (moved || {}).id;
    // the refusal must be ATOMIC over the whole claim set (round-24 checker, finding 2:
    // asserting only the moved claim would miss a mutation that deletes the occupant
    // and then throws the expected message)
    const slotSetBefore = JSON.stringify(ledger().docs.filter((d) => d.type === "pledgeSlot"));
    const rClash = drive(slotReplace(movedId, 7));
    ok("end-to-end: a replace moving the claim onto the OCCUPIED slot 7 is refused at broadcast",
      rClash.code === 3 && /duplicate unique index bySlot for pledgeSlot/.test(rClash.out));
    ok("end-to-end: the refused replace left the ENTIRE claim set byte-identical",
      JSON.stringify(ledger().docs.filter((d) => d.type === "pledgeSlot")) === slotSetBefore);
    // SELF-EXCLUSION (round-24 checker, finding 4): a claim rewriting its own current
    // slot number must not clash with itself
    const rSelf = drive(slotReplace(movedId, 8));
    ok("end-to-end: a replace writing the claim's OWN slot number is accepted (no self-clash)",
      rSelf.code === 0 && Number((claimAt(poolHexE2E, 8) || {}).data.slotNo) === 8);
    const rFree = drive(slotReplace(movedId, 9));
    ok("end-to-end: the same replace onto the FREE slot 9 is accepted (the refusal is the collision)",
      rFree.code === 0 && !!claimAt(poolHexE2E, 9));
    // THE KEY IS COMPOSITE (round-24 checker, finding 1: dropping the poolId comparison
    // would make slotNo globally unique and every same-pool case would still pass): a
    // claim in a DIFFERENT pool moves onto slot 7 freely, because pool A's occupied 7
    // does not block pool B's
    const poolBHex = crypto.createHash("sha256").update("slot-replace-pool-B").digest("hex");
    const bFields = `{ poolId: Buffer.from(${JSON.stringify(poolBHex)}, "hex"), slotNo: 10,
        rewardScript: Buffer.from(${JSON.stringify(slotScriptE2E)}, "hex") }`;
    const gB = drive(slotCreate(bFields));
    ok("end-to-end: a claim in a second pool lands", gB.code === 0);
    const rCross = drive(slotReplace((claimAt(poolBHex, 10) || {}).id, 7));
    ok("end-to-end: the second pool's claim moves onto ITS OWN slot 7 (the index is per pool, not global)",
      rCross.code === 0 && !!claimAt(poolBHex, 7));
  }
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
  // the refusal is unchanged; the WORD is now "damaged", the single term this class of
  // draft defect uses across the live key and the archive alike (pass 10, F1)
  ok("a corrupt draft is refused loudly", r.code !== 0 && /damaged/i.test(r.out));
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
    r2.code !== 0 && /DAMAGED/.test(r2.out));
  ok("the unparseable refusal also preserves the archive", fs.existsSync(ap));
  // an EMPTY-STRING draft is damage too, and a truthiness test would read it as absent
  const arch3 = JSON.parse(fs.readFileSync(ap, "utf8"));
  arch3.draft = "";
  fs.writeFileSync(ap, JSON.stringify(arch3));
  const r3 = runChild(["receipt", POOL]);
  ok("an EMPTY archived draft refuses too (presence tested explicitly)",
    r3.code !== 0 && /DAMAGED/.test(r3.out));
  // the ABSENT KEY is damage too: the writer always emits `draft`, using null when
  // there was none, so a missing key cannot be read as an honest absence
  const arch4 = JSON.parse(fs.readFileSync(ap, "utf8"));
  delete arch4.draft;
  fs.writeFileSync(ap, JSON.stringify(arch4));
  const r4 = runChild(["receipt", POOL]);
  ok("an archive MISSING the draft key refuses (the writer always emits it)",
    r4.code !== 0 && /DAMAGED/.test(r4.out));
  // ...while an archive recording `draft: null` is an HONEST absence and must still
  // take the manifest-only path rather than refusing
  const arch5 = JSON.parse(fs.readFileSync(ap, "utf8"));
  arch5.draft = null;
  fs.writeFileSync(ap, JSON.stringify(arch5));
  const r5 = runChild(["receipt", POOL]);
  // POSITIVE assertion, not merely the absence of the damage word (artifact check): the
  // run must SUCCEED and reach the manifest-derivable comparison, which is the path an
  // honest "no draft was archived" is supposed to take
  ok("an archive recording NO draft (null) still recovers, never refuses",
    r5.code === 0 && /matches the retained manifest/.test(r5.out) && !/DAMAGED/.test(r5.out));
  // THE OUTER ENVELOPE ITSELF (pass 14, F2). Every case above malformed something INSIDE
  // a parseable envelope, so the branch where the envelope's own JSON.parse throws was
  // never exercised, and it failed open: the catch cleared the parsed values but left
  // draftState at "unknown", which only the try body ever sets, so the damaged refusal
  // never fired and recovery reported success WITHOUT the exact archived-draft
  // comparison. The archive KEY EXISTING is the evidence that exact evidence belongs
  // here; an envelope that does not parse is the same evidentiary state as a draft that
  // does not parse.
  // TWO malformation shapes, not one literal string (checker-constructed survival: a fix
  // recognizing only the exact test bytes would pass a single case), and preservation is
  // asserted on the BYTES, not on the pathname existing (a delete-and-recreate would
  // satisfy existsSync while destroying the evidence). The real-envelope bytes come from
  // the arch5 object still in scope, NOT from re-reading the file: the r5 recovery above
  // SUCCEEDED, and success finalizes and clears the archive, so the file is gone here
  // (the first draft of this case read the file and crashed on exactly that).
  const goodEnvelope = JSON.stringify(arch5);
  // JSON-VALID malformations included (pass 15, F1): JSON.parse("false") SUCCEEDS, as do
  // "{}" and "[]" and a shape missing the writer's keys, so a throw-driven damage check
  // missed every one of them, which is what the pass-14 fix turned out to be. The check
  // is now positive (the writer's shape or damage), and each of these drives it.
  for (const [label, poison] of [
    ["invalid syntax", "{not valid json at the envelope level"],
    ["a truncated real envelope", goodEnvelope.slice(0, Math.floor(goodEnvelope.length / 2))],
    ["JSON false, which parses fine", "false"],
    ["an empty object, no writer keys", "{}"],
    ["an array", "[]"],
    ["an envelope missing the draft key", JSON.stringify({ manifest: arch5.manifest })],
    ["JSON zero", "0"],
    ["both keys present, manifest value parsing to null (checker-constructed)",
      JSON.stringify({ manifest: "null", draft: null })],
  ]) {
    fs.writeFileSync(ap, poison);
    const r6 = runChild(["receipt", POOL]);
    ok(`a MALFORMED OUTER envelope (${label}) refuses like any other damage, never succeeds`,
      r6.code !== 0 && /DAMAGED/.test(r6.out));
    ok(`...and the refusal preserves the archive BYTES for hands (${label})`,
      fs.existsSync(ap) && fs.readFileSync(ap, "utf8") === poison);
  }
}

// ---- independent case F3 (closing wave, folder-access reviewer): a DRAFT-ONLY abandon
//      archive is a LEGITIMATE writer output, not damage. `abandon` on a pool with a frozen
//      draft but NO committed manifest emits {manifest:null, draft:"<frozen draft>"} (the
//      abandon writer: `manifest: hasManifest ? envHere[key] : null`, owners taken from the
//      frozen rows one branch above it). DRIVEN END-TO-END here so the WRITER itself produces
//      the manifest:null archive rather than the test hand-building it: complete to freeze both,
//      remove the committed-manifest state file (a real manifest-loss the draft-only abandon
//      path exists to handle; loadEnv keys off the .val files), then abandon. The reader's
//      manifest-value gate required a non-empty string, so a literal null was mislabelled
//      DAMAGED. The honest outcome is a REFUSAL that names the draft-only state, NEVER a DAMAGED
//      claim, and it must fire BEFORE the finalize path so no receipt is finalized from a
//      manifest-less archive (no a soundness-review finding regression: the manifest-less archive's frozen draft is
//      not adopted as a finalize source). Both the old and new behaviour refuse, so no value
//      moves; only the reason changes. ----
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" });
  // remove ONLY the committed-manifest .val, leaving the frozen draft, so the next abandon sees
  // hasManifest false / hasDraft true (the draft-only precondition). The ABANDONED_ and DONE_
  // keys are longer than FORMATION_<20hex> and are not matched.
  for (const f of fs.readdirSync(STATE_DIR)) {
    if (/^FORMATION_[0-9A-F]{20}\.val$/.test(f)) fs.rmSync(path.join(STATE_DIR, f));
  }
  const abF3 = runChild(["abandon", POOL]);
  ok("draft-only setup: abandon succeeds on a pool with a draft but no manifest", abF3.code === 0);
  const archiveFileF3 = fs.readdirSync(STATE_DIR).find((f) => f.startsWith("FORMATION_ABANDONED_") && f.endsWith(".val"));
  ok("draft-only setup: the abandon archive exists", archiveFileF3 !== undefined);
  const apF3 = path.join(STATE_DIR, archiveFileF3);
  const archF3 = JSON.parse(fs.readFileSync(apF3, "utf8"));
  // THE WRITER PRODUCED manifest:null (not a hand-built fixture): this is the exact shape F3
  // is about, emitted by the real abandon writer for a draft-only pool, beside the real draft.
  ok("the WRITER emits manifest:null for a draft-only abandon, beside the real frozen draft",
    archF3.manifest === null && typeof archF3.draft === "string");
  const draftOnlyBytes = fs.readFileSync(apF3, "utf8");
  // (a) no receipt on the ledger yet: recovery has nothing to publish and refuses HONESTLY,
  // writing nothing to either the archive or the ledger
  const ledgerBeforeAF3 = fs.readFileSync(LEDGER_PATH, "utf8");
  const rF3 = runChild(["receipt", POOL]);
  ok("a DRAFT-ONLY abandon archive is NOT reported as damaged",
    rF3.code !== 0 && !/damaged|corrupt|unusable/i.test(rF3.out));
  ok("a DRAFT-ONLY abandon archive refuses HONESTLY, naming the missing manifest",
    rF3.code !== 0 && /draft-only/i.test(rF3.out) && /no.*manifest|manifest.*(committed|to publish)/i.test(rF3.out));
  ok("the draft-only refusal preserves the archive bytes for hands",
    fs.existsSync(apF3) && fs.readFileSync(apF3, "utf8") === draftOnlyBytes);
  ok("the draft-only refusal (no receipt) writes nothing to the ledger",
    fs.readFileSync(LEDGER_PATH, "utf8") === ledgerBeforeAF3);
  // (b) a MATCHING receipt already on the ledger: the refusal must STILL fire before the
  // finalize path (no a soundness-review finding regression), so the "verified" success line must never appear AND
  // the archive BYTES must be untouched (a finalize would clear or rewrite the archive; a
  // finalize-then-error mutation is caught by the byte check, not merely by exit code).
  const lF3 = ledger();
  lF3.docs.push({ id: newId(), type: "completionReceipt", ownerId: OP, data: {
    poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
    proTxHash: EXPECTED.proTxHash, slotIndex: 0, formatVersion: 1,
    ...(PARED ? {} : { nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000 }),
    allocationRows: EXPECTED.allocationRows, allocationHash: EXPECTED.allocationHash,
    participantCount: 2, l1Verification: "amount-reward-verified",
    verificationMethodVersion: 1, $createdAt: 5 } });
  if (!PARED) {
    const p2 = lF3.docs.find((x) => x.id === POOL);
    p2.data.proTxHash = REAL_HASH; p2.data.status = "live";
  }
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(lF3, null, 1));
  const ledgerBeforeF3 = fs.readFileSync(LEDGER_PATH, "utf8");
  const r2F3 = runChild(["receipt", POOL]);
  ok("a draft-only archive still refuses with a matching receipt present, never finalizes",
    r2F3.code !== 0 && !/damaged/i.test(r2F3.out) && !/embedded allocation: canonical/.test(r2F3.out));
  ok("the draft-only refusal leaves the archive BYTES untouched with a receipt present",
    fs.existsSync(apF3) && fs.readFileSync(apF3, "utf8") === draftOnlyBytes);
  // the LEDGER is also unchanged: the refusal throws before any finalize write, so a mutation
  // that writes the receipt/ledger before refusing (archive left alone) is caught here, not
  // only by the archive-byte check
  ok("the draft-only refusal writes nothing to the ledger",
    fs.readFileSync(LEDGER_PATH, "utf8") === ledgerBeforeF3);
  // (c) manifest:null is the writer's draft-only shape ONLY beside a PRESENT draft. A null,
  // empty, or unparseable companion draft is off the writer's contract (the draft-only abandon
  // always archives a real frozen draft), so it stays DAMAGE, not a draft-only abandon. These
  // shapes are hand-built because the writer cannot produce them, exactly like the other damage
  // cases above.
  for (const [label, badDraft] of [
    ["a null companion draft", null],
    ["an empty-string companion draft", ""],
    ["an unparseable companion draft", "{not json"],
    ["a JSON-null companion draft", "null"],
  ]) {
    fs.writeFileSync(apF3, JSON.stringify({ manifest: null, draft: badDraft, at: null }));
    const rc = runChild(["receipt", POOL]);
    ok(`manifest:null beside ${label} is DAMAGE, not a draft-only abandon`,
      rc.code !== 0 && /damaged/i.test(rc.out) && !/draft-only/i.test(rc.out));
  }
}

// ---- independent case CF1 (closing wave, second-model review): a REBUILT draft's fee
//      provenance survives persist-crash-reload. The fee-comparability marker used to be a
//      non-enumerable property, dropped by JSON.stringify, and reload stamped every
//      live-key draft as completion-time evidence, so a draft REBUILT after a legitimate
//      post-flip fee change, persisted, and reloaded had its present-day fee compared
//      against the valid historical receipt and recovery refused it. The fact is now a
//      required persisted field, decided at build time. The drafts, the crash, and the
//      recovery run through the REAL writers; the historical receipt is a synthetic
//      fixture inserted into the ledger, the same idiom as the archived-draft cases above.
//      v8 only: the sequence needs a flip and a post-flip fee drift, neither of which
//      exists on the immutable ledger. ----
if (!PARED) {
  // flipped pool, receipt not yet published, manifest retained, draft still frozen
  writeSeed();
  const halted = runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "flip" });
  ok("CF1 setup: halted after the flip with in-flight evidence", halted.code === 0 && hasInFlightEvidence());
  // the FIRST-RUN freeze was built pre-flip, when the current fee IS the completion-time
  // fee, so the writer records it as comparable (the predicate's true half, pinned on the
  // persisted record itself)
  {
    const df = fs.readdirSync(STATE_DIR).find((f) => /^RECEIPT_DRAFT_[0-9A-F]{20}\.val$/.test(f));
    ok("CF1: the first-run pre-flip freeze records its fee as completion-time evidence",
      df !== undefined && JSON.parse(fs.readFileSync(path.join(STATE_DIR, df), "utf8")).feeIsCompletionTime === true);
  }
  // the draft is LOST (the state loss the rebuild path exists for), and the pool fee
  // then drifts legitimately (the fee is mutable after completion, round-5)
  for (const f of fs.readdirSync(STATE_DIR)) {
    if (/^RECEIPT_DRAFT_[0-9A-F]{20}\.val$/.test(f)) fs.rmSync(path.join(STATE_DIR, f));
  }
  {
    const l = ledger();
    const p = l.docs.find((d) => d.id === POOL);
    p.data.operatorFeeBps = 2500; // seeded completion-time fee is 2000
    fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  }
  snapshot();
  // find the boundary where `receipt` has PERSISTED the rebuilt draft but NOT published:
  // the persist-crash-reload window CF1 is about
  let crashedK = null;
  for (let k = 1; k <= 30 && crashedK === null; k++) {
    restore(); clearOpLock();
    const r = runChild(["receipt", POOL], k);
    const draftPersisted = fs.readdirSync(STATE_DIR).some((f) => /^RECEIPT_DRAFT_[0-9A-F]{20}\.val$/.test(f));
    if (r.code === 97 && draftPersisted && receipts().length === 0) crashedK = k;
  }
  ok("CF1 setup: a crash boundary exists after the rebuild-persist and before publication", crashedK !== null);
  if (crashedK !== null) {
    restore(); clearOpLock();
    runChild(["receipt", POOL], crashedK);
    ok("CF1 setup: the rebuilt draft is persisted and no receipt is on the ledger",
      fs.readdirSync(STATE_DIR).some((f) => /^RECEIPT_DRAFT_[0-9A-F]{20}\.val$/.test(f)) && receipts().length === 0);
    // the valid HISTORICAL receipt appears, recording the completion-time fee (2000),
    // published from the original completion evidence
    const l = ledger();
    l.docs.push({ id: newId(), type: "completionReceipt", ownerId: OP, data: {
      poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
      proTxHash: EXPECTED.proTxHash, slotIndex: 0, formatVersion: 1,
      nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000,
      allocationRows: EXPECTED.allocationRows, allocationHash: EXPECTED.allocationHash,
      participantCount: 2, l1Verification: "demo-unverified",
      verificationMethodVersion: 1, $createdAt: 5 } });
    fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
    // recovery resumes: the reloaded draft's fee is a PRESENT-DAY reading (2500), recorded
    // as such, so it must NOT be compared against the historical receipt's 2000, and the
    // reconcile must finalize rather than report a false contradiction
    clearOpLock();
    const resumed = runChild(["receipt", POOL]);
    ok("CF1: recovery over a persisted REBUILT draft accepts the valid historical receipt",
      resumed.code === 0 && !/CONTRADICTS/.test(resumed.out) && !/operatorFeeBps/.test(resumed.out));
    ok("CF1: ...and finalizes the half-finalized completion",
      /local completion state finalized/.test(resumed.out) && !hasInFlightEvidence());
    ok("CF1: the historical receipt is untouched on the ledger", receipts().length === 1);
  }
  // COMPLETE's own rebuild site decides the same predicate (the sibling the receipt-path
  // case cannot reach): resuming complete after the same draft loss on the flipped pool
  // rebuilds from the manifest plus the CURRENT (drifted) fee, and the writer must record
  // that fee as NOT completion-time evidence. Pinned on the persisted record, because the
  // fee-skip behavior it drives is already covered above.
  {
    let completeK = null;
    for (let k = 1; k <= 30 && completeK === null; k++) {
      restore(); clearOpLock();
      const r = runChild(["complete", POOL, REAL_HASH], k);
      const df = fs.readdirSync(STATE_DIR).find((f) => /^RECEIPT_DRAFT_[0-9A-F]{20}\.val$/.test(f));
      if (r.code === 97 && df !== undefined) completeK = k;
    }
    ok("CF1 sibling setup: complete's rebuild persisted a draft before a later crash", completeK !== null);
    if (completeK !== null) {
      const df = fs.readdirSync(STATE_DIR).find((f) => /^RECEIPT_DRAFT_[0-9A-F]{20}\.val$/.test(f));
      ok("CF1 sibling: complete's post-flip rebuild records its fee as NOT completion-time",
        JSON.parse(fs.readFileSync(path.join(STATE_DIR, df), "utf8")).feeIsCompletionTime === false);
    }
  }
  // a LEGACY draft that never recorded its fee provenance is refused loudly, never
  // guessed at (the field is REQUIRED; assuming comparable recreates the false
  // contradiction, assuming not waves off a genuine one)
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "flip" });
  const draftFile = fs.readdirSync(STATE_DIR).find((f) => /^RECEIPT_DRAFT_[0-9A-F]{20}\.val$/.test(f));
  ok("CF1 legacy setup: a frozen draft exists", draftFile !== undefined);
  {
    const dp = path.join(STATE_DIR, draftFile);
    const d = JSON.parse(fs.readFileSync(dp, "utf8"));
    delete d.feeIsCompletionTime;
    fs.writeFileSync(dp, JSON.stringify(d));
  }
  const legacy = runChild(["receipt", POOL]);
  ok("CF1: a draft without the fee-provenance field is refused loudly, not guessed at",
    legacy.code !== 0 && /feeIsCompletionTime/.test(legacy.out));
  // ...and the boolean is NOT a free opt-out (checker on this fold): where the pool state
  // proves the fee cannot have drifted (still forming here), a draft claiming false is an
  // incoherent record and refuses, so editing the persisted flag cannot skip the fee
  // comparison the old code performed
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" });
  const preflipDraft = fs.readdirSync(STATE_DIR).find((f) => /^RECEIPT_DRAFT_[0-9A-F]{20}\.val$/.test(f));
  ok("CF1 opt-out setup: a pre-flip frozen draft exists", preflipDraft !== undefined);
  {
    const dp = path.join(STATE_DIR, preflipDraft);
    const d = JSON.parse(fs.readFileSync(dp, "utf8"));
    ok("CF1 opt-out setup: the pre-flip draft recorded true", d.feeIsCompletionTime === true);
    d.feeIsCompletionTime = false;
    fs.writeFileSync(dp, JSON.stringify(d));
  }
  const optOut = runChild(["complete", POOL, REAL_HASH]);
  ok("CF1: a pre-flip draft claiming NOT-completion-time is refused as an incoherent record",
    optOut.code !== 0 && /incoherent record/.test(optOut.out));
}

// ---- independent case DEBRIS CALLER ENUMERATION (confirm-pass round 11, must-fix):
//      votePreference and settlement are poolId-referencing families the sweep never
//      enumerated, so a sweep could delete a pool around a preference (orphaning it, its
//      owner never consulted) and a settlement's member history protected nothing. Drives
//      the REAL cleanupDebris.cjs through the dash-to-mock hook: a controlled preference
//      is deleted WITH its pool, a FOREIGN preference skips the whole pool, and a
//      settlement skips it outright. v8 only (the immutable ledger's receipt-less pools
//      are skip-indeterminate before any of this applies). ----
if (!PARED) {
  // cleanupDebris guards its main loop on require.main === module, so the hook rides a
  // --require preload and the script itself IS the main module (the audit and cast
  // probes run unconditional IIFEs and could be required from -e; this one cannot)
  const HOOKFILE = path.join(ROOT, "dashHook.cjs");
  fs.writeFileSync(HOOKFILE, `
    const Module = require("module");
    const orig = Module._resolveFilename;
    Module._resolveFilename = function (request, ...rest) {
      if (request === "dash") return ${JSON.stringify(path.join(__dirname, "formationMockDash.cjs"))};
      return orig.call(this, request, ...rest);
    };`);
  const runDebris = () => { try {
    return { code: 0, out: execFileSync("node", ["--require", HOOKFILE,
      path.join(__dirname, "cleanupDebris.cjs")],
      { env: { ...process.env, TEGARA_ENV_PATH: ENV_PATH, TEGARA_MOCK_LEDGER: LEDGER_PATH,
        LEDGER: HARNESS_LEDGER, NETWORK: "regtest" }, encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"] }) };
  } catch (e) { return { code: e.status, out: (e.stdout || "") + (e.stderr || "") }; } };
  const seedSweepable = (extraDocs) => {
    writeSeed();
    const l = ledger();
    const poolHex = Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex");
    // one controlled share at 5000 bps: incomplete, nothing distributed, sweepable
    l.docs.push({ id: newId(), type: "share", ownerId: F1, data: { poolId: poolHex,
      shareBps: 5000, contributionDuffs: 1, l1RewardScript: "76a914" + "11".repeat(20) + "88ac", $createdAt: 1 } });
    for (const d of extraDocs(poolHex)) l.docs.push(d);
    fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  };
  // (a) a CONTROLLED preference is enumerated and deleted with its pool, never orphaned
  seedSweepable((poolHex) => [{ id: newId(), type: "votePreference", ownerId: F2,
    data: { poolId: poolHex, proposalHash: "66".repeat(32), choice: "yes", $createdAt: 2 } }]);
  const rA = runDebris();
  ok("debris caller: a controlled preference is deleted with its pool, not orphaned",
    rA.code === 0 && ledger().docs.every((d) => d.type !== "votePreference" && d.id !== POOL));
  // (b) a FOREIGN preference is in the whole-pool preflight and skips the pool intact
  seedSweepable((poolHex) => [{ id: newId(), type: "votePreference", ownerId: newId(),
    data: { poolId: poolHex, proposalHash: "66".repeat(32), choice: "yes", $createdAt: 2 } }]);
  const rB = runDebris();
  ok("debris caller: a FOREIGN preference skips the whole pool (owner consulted, pool intact)",
    rB.code === 0 && /owned by identities this/.test(rB.out)
    && ledger().docs.some((d) => d.id === POOL)
    && ledger().docs.some((d) => d.type === "votePreference"));
  // (c) a settlement's member history refuses the sweep outright
  seedSweepable((poolHex) => [{ id: newId(), type: "settlement", ownerId: F1,
    data: { poolId: poolHex, exitId: "0a".repeat(32), joinId: "0b".repeat(32),
      leaverId: "0c".repeat(32), joinerId: "0d".repeat(32), amountDuffs: 1, shareBps: 5000,
      phase: "prepared", $createdAt: 2 } }]);
  const rC = runDebris();
  ok("debris caller: a settlement skips the pool outright (member history is not debris)",
    rC.code === 0 && /settled an exit or join/.test(rC.out)
    && ledger().docs.some((d) => d.id === POOL)
    && ledger().docs.some((d) => d.type === "settlement"));
  // (d) the v1 LEDGER has no settlement type at all (confirm-pass round 12, major: the
  // first draft queried it unconditionally, so on v1 the SDK refused the unknown type
  // before the plan could run and the whole sweep wedged; the reserve fold was this exact
  // shape). The strict mock now refuses absent types like the real SDK, so this drives
  // the caller under LEDGER=v1 and requires it to REACH the plan and sweep.
  {
    writeSeed();
    const l = ledger();
    const poolHex = Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex");
    // a v1-shaped pool (no slot book, no operatorIdentityId) with one incomplete share
    const p = l.docs.find((d) => d.id === POOL);
    p.data = { proTxHash: "00".repeat(16) + "11".repeat(16), slotIndex: 0, nodeType: "regular",
      operatorFeeBps: 2000, status: "forming", $createdAt: 1 };
    l.docs = l.docs.filter((d) => d.type === "pool");
    l.docs.push({ id: newId(), type: "share", ownerId: F1, data: { poolId: poolHex,
      shareBps: 5000, contributionDuffs: 1, l1RewardScript: "76a914" + "11".repeat(20) + "88ac", $createdAt: 1 } });
    fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
    const rV1 = (() => { try {
      return { code: 0, out: execFileSync("node", ["--require", HOOKFILE,
        path.join(__dirname, "cleanupDebris.cjs")],
        { env: { ...process.env, TEGARA_ENV_PATH: ENV_PATH, TEGARA_MOCK_LEDGER: LEDGER_PATH,
          LEDGER: "v1", NETWORK: "regtest" }, encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"] }) };
    } catch (e) { return { code: e.status, out: (e.stdout || "") + (e.stderr || "") }; } })();
    ok("debris caller: the v1 ledger reaches the plan and sweeps (no absent-type query wedge)",
      rV1.code === 0 && /debris pool/.test(rV1.out) && !/not defined by the selected ledger/.test(rV1.out));
  }
}

// ---- independent case PRE-V8 OWNER BINDING (confirm-pass round 16, must-fix): the M1
//      owner binding was v8-gated while the final pool replacement is operator-signed on
//      EVERY mutable ledger, so a v1-v7 completion of a foreign-owned pool mutated public
//      records (shares created, requests settled) before dying at the replacement
//      Platform refuses. The guard is unconditional now; this drives the real `complete`
//      under LEDGER=v5 against a foreign-owned pool and requires the refusal BEFORE any
//      ledger mutation. ----
if (!PARED) {
  writeSeed();
  fs.appendFileSync(ENV_PATH, `CONTRACT_V5_ID=${CONTRACT}\n`);
  {
    const l = ledger();
    const p = l.docs.find((d) => d.id === POOL);
    // a v5-shaped pool (status, no slot fields) owned by F1, NOT the operator
    p.ownerId = F1;
    p.data = { proTxHash: "00".repeat(16) + "22".repeat(16), slotIndex: 0, nodeType: "regular",
      operatorFeeBps: 2000, status: "forming", $createdAt: 1 };
    l.docs = l.docs.filter((d) => d.type === "pool");
    // MUTABLE INPUTS PRESENT (checker on this fold): two pending requests that exactly
    // fill the pool, so the pre-fix flow would have settled them and created shares
    // before dying at the replacement; the unchanged-bytes assertion below therefore
    // observes the mutations the old ordering performed, not an empty ledger
    const poolHex5 = Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex");
    l.docs.push(
      { id: newId(), type: "membershipRequest", ownerId: F1, data: { poolId: poolHex5,
        kind: "join", amountDuffs: 50000000000, status: "pending", $createdAt: 2 } },
      { id: newId(), type: "membershipRequest", ownerId: F2, data: { poolId: poolHex5,
        kind: "join", amountDuffs: 50000000000, status: "pending", $createdAt: 3 } });
    fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
    const before = fs.readFileSync(LEDGER_PATH, "utf8");
    const r5 = runChild(["complete", POOL, REAL_HASH], undefined, { LEDGER: "v5" });
    ok("v5: completing a FOREIGN-owned pool refuses at the owner binding, before any mutation",
      r5.code !== 0 && /is owned by .* not this/.test(r5.out) && /M1 owner binding/.test(r5.out));
    ok("v5: the foreign-owner refusal mutates nothing on the ledger",
      fs.readFileSync(LEDGER_PATH, "utf8") === before);
  }
}

// ---- independent case LEGACY CAST READER DELEGATION (confirm-pass round 10, major):
//      castReceipt.cjs built its own choice map and never read delegateTo, the exact
//      divergence ledgerTally.cjs's header says the F6 fold existed to end, so a targeted
//      delegation fell into the untargeted net and the legacy publisher computed a
//      different tally, outcome and hash than the governor from the same ledger. The
//      reviewer's scenario: A 5000 no, B 3000 delegating to C, C 2000 yes; targeted
//      resolution is 5000/5000 with the tie rule selecting yes, while the broken map made
//      it 2000/8000 no. Drives the REAL castReceipt.cjs verify path offline through the
//      dash-to-mock hook; the tally prints before any L1 or cast-ledger fetch, so later
//      environment failures cannot mask the assertion. v8 only for the pool shape. ----
if (!PARED) {
  writeSeed();
  {
    // the cast publisher needs its own contract id in env; the cast-ledger reads come
    // after the tally print and resolve to empty against the mock
    fs.appendFileSync(ENV_PATH, `CAST_CONTRACT_ID=${newId()}\n`);
    const l = ledger();
    const p = l.docs.find((d) => d.id === POOL);
    p.data.proTxHash = REAL_HASH; p.data.status = "live";
    l.docs = l.docs.filter((d) => d.type !== "share" && d.type !== "votePreference");
    const propHex = "77".repeat(32);
    const poolHex = Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex");
    const scr = (b) => "76a914" + b.repeat(20) + "88ac";
    const A = F1, B = F2, C = OP;
    l.docs.push(
      { id: newId(), type: "share", ownerId: A, data: { poolId: poolHex, shareBps: 5000, contributionDuffs: 1, l1RewardScript: scr("11"), $createdAt: 1 } },
      { id: newId(), type: "share", ownerId: B, data: { poolId: poolHex, shareBps: 3000, contributionDuffs: 1, l1RewardScript: scr("22"), $createdAt: 2 } },
      { id: newId(), type: "share", ownerId: C, data: { poolId: poolHex, shareBps: 2000, contributionDuffs: 1, l1RewardScript: scr("33"), $createdAt: 3 } },
      { id: newId(), type: "votePreference", ownerId: A, data: { poolId: poolHex, proposalHash: propHex, choice: "no", $createdAt: 4 } },
      { id: newId(), type: "votePreference", ownerId: B, data: { poolId: poolHex, proposalHash: propHex, choice: "delegate",
        delegateTo: Buffer.from(Identifier.from(C).toBuffer()).toString("hex"), $createdAt: 5 } },
      { id: newId(), type: "votePreference", ownerId: C, data: { poolId: poolHex, proposalHash: propHex, choice: "yes", $createdAt: 6 } });
    fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
    const castProbe = `
      const path = require("path");
      const Module = require("module");
      const MOCK = ${JSON.stringify(path.join(__dirname, "formationMockDash.cjs"))};
      const orig = Module._resolveFilename;
      Module._resolveFilename = function (request, ...rest) {
        if (request === "dash") return MOCK;
        return orig.call(this, request, ...rest);
      };
      process.argv = [process.argv[0], "castReceipt.cjs", "verify", ${JSON.stringify(POOL)}, ${JSON.stringify(propHex)}];
      require(${JSON.stringify(path.join(__dirname, "castReceipt.cjs"))});`;
    const rc = (() => { try { return { code: 0, out: execFileSync("node", ["-e", castProbe],
      { env: { ...process.env, TEGARA_ENV_PATH: ENV_PATH, TEGARA_MOCK_LEDGER: LEDGER_PATH,
        LEDGER: HARNESS_LEDGER, NETWORK: "regtest", FORK_RPC_URL: "http://offline.invalid:1" },
        encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }; }
      catch (e) { return { code: e.status, out: (e.stdout || "") + (e.stderr || "") }; } })();
    ok("legacy cast reader resolves TARGETED delegation (5000/5000, tie rule yes), never 2000/8000",
      /yes 5000 \/ no 5000/.test(rc.out) && /outcome "yes"/.test(rc.out));
  }
}

// ---- independent case AUDIT RECEIPT CONTRADICTION (closing confirm-pass round 4,
//      major): the ledger audit collapsed "no receipt" and "a receipt exists but does
//      not verify" into one node-unknown state, so a ledger holding a contradicting
//      receipt could report AUDIT OK with exit 0 against the script's own header. A
//      present non-verifying receipt now FAILS the audit, with exactly one recognized
//      exception, the documented P6 probe artifact the canonical publish record lists
//      precisely so a later audit recognizes it. This drives the REAL ledgerAudit.cjs
//      offline through the same dash-to-mock module hook the crash child uses. ----
if (PARED) {
  writeSeed();
  const nonVerifying = (id) => {
    const l = ledger();
    l.docs.push({ id, type: "completionReceipt", ownerId: OP, data: {
      poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
      proTxHash: "ab".repeat(32), slotIndex: 0, formatVersion: 1,
      allocationRows: Buffer.from("placeholder-not-a-real-allocation", "utf8").toString("hex"),
      allocationHash: "cd".repeat(32),
      participantCount: 2, l1Verification: "demo-unverified", verificationMethodVersion: 1,
      $createdAt: 5 } });
    fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  };
  const auditProbe = `
    const path = require("path");
    const Module = require("module");
    const MOCK = ${JSON.stringify(path.join(__dirname, "formationMockDash.cjs"))};
    const orig = Module._resolveFilename;
    Module._resolveFilename = function (request, ...rest) {
      if (request === "dash") return MOCK;
      return orig.call(this, request, ...rest);
    };
    require(${JSON.stringify(path.join(__dirname, "ledgerAudit.cjs"))});`;
  const runAudit = () => { try {
    return { code: 0, out: execFileSync("node", ["-e", auditProbe],
      { env: { ...process.env, TEGARA_ENV_PATH: ENV_PATH, TEGARA_MOCK_LEDGER: LEDGER_PATH,
        LEDGER: HARNESS_LEDGER, NETWORK: "regtest" }, encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"] }) };
  } catch (e) { return { code: e.status, out: (e.stdout || "") + (e.stderr || "") }; } };
  nonVerifying(newId());
  const rAudit = runAudit();
  ok("audit: a present receipt that does NOT verify fails the audit, never OK",
    rAudit.code !== 0 && /does NOT verify against it/.test(rAudit.out) && !/LEDGER AUDIT OK/.test(rAudit.out));
  writeSeed();
  nonVerifying("2DWKsvWdFvRZWScvT5zXFWhDDVX8garJB7XP4tHC6M8Z");
  const rProbeArt = runAudit();
  ok("audit: the documented P6 probe artifact is recognized by name, not an inconsistency",
    rProbeArt.code === 0 && /DOCUMENTED P6 probe artifact/.test(rProbeArt.out)
    && !/INCONSISTENT/.test(rProbeArt.out));
}

  // THE UNIQUE byProTxHash INDEX on a pool flip (pass 17, F2), enforced at broadcast where
  // the other pools are visible. Two forming pools; flip A to hash H; a replace flipping B
  // to the same H must be refused, while flipping B to a DIFFERENT hash succeeds.
  {
    // a local child runner and env (both `drive` and `childEnv` above are block-scoped to
    // the delete-probe block; the globals they are built from are module-level)
    const childEnvP = { ...process.env, TEGARA_ENV_PATH: ENV_PATH,
      TEGARA_MOCK_LEDGER: LEDGER_PATH, LEDGER: HARNESS_LEDGER, NETWORK: "regtest" };
    const driveP = (script) => {
      try { return { code: 0, out: execFileSync("node", ["-e", script],
        { env: childEnvP, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }; }
      catch (e) { return { code: e.status, out: (e.stdout || "") + (e.stderr || "") }; }
    };
    const P2 = Identifier.from(crypto.createHash("sha256").update("second-pool-flip").digest()).toString();
    const seedTwo = () => {
      writeSeed();
      const l = ledger();
      l.docs.push({ id: P2, type: "pool", ownerId: OP, data: PARED
        ? { slotIndex: 1, nodeType: "regular", operatorFeeBps: 2000, targetDuffs: 100000000000,
            slotDuffs: 50000000000, slotCount: 2, $createdAt: 1 }
        : { proTxHash: "00".repeat(16) + crypto.randomBytes(16).toString("hex"), slotIndex: 1,
            nodeType: "regular", operatorIdentityId: Buffer.from(Identifier.from(OP).toBuffer()).toString("hex"),
            operatorFeeBps: 2000, status: "forming", slotDuffs: 50000000000, slotCount: 2, $createdAt: 1 } });
      fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
    };
    if (!PARED) {
      const flip = (poolPk, hashHex) => `
        const mock = require(${JSON.stringify(path.join(__dirname, "formationMockDash.cjs"))});
        const c = new mock.Client({});
        const id = { getId: () => ({ toString: () => ${JSON.stringify(OP)} }) };
        (async () => {
          // the probe models the REAL writer, which flips with a Buffer (closing wave,
          // FA3: a pending hex string is now refused as the schema-forbidden string form)
          const doc = { __rec: { id: ${JSON.stringify(poolPk)} }, __pending: { status: "live", proTxHash: Buffer.from(${JSON.stringify(hashHex)}, "hex") } };
          await c.platform.documents.broadcast({ replace: [doc] }, id);
          process.exit(0);
        })().catch((e) => { console.error(e.message); process.exit(3); });`;
      seedTwo();
      const H = "aa".repeat(32);
      const a = driveP(flip(POOL, H));
      ok("pool flip A to H succeeds", a.code === 0);
      const bClash = driveP(flip(P2, H));
      ok("pool flip B to the SAME H is refused by the unique byProTxHash index",
        bClash.code === 3 && /duplicate unique index byProTxHash for pool/.test(bClash.out));
      const bOk = driveP(flip(P2, "bb".repeat(32)));
      ok("pool flip B to a DIFFERENT hash succeeds", bOk.code === 0);
    }
  }

// ---- independent case LOADED-MANIFEST RANGE (pass 16, F1): the fresh claim reader
//      refuses slotNo >= slotCount, and the stored-manifest validator on the RESUME path
//      checked non-negativity and slotCount EQUALITY while never asking the claims to sit
//      inside it, so a snapshot and a ledger claim that were EQUALLY out of range agreed
//      through the preflight and settled. This drives a LOADED manifest, which is the
//      reader the fresh-path test cannot reach. ----
{
  // BOTH ledgers: the validator is shared, and the checker on this fold noted a
  // PARED-only case leaves the other ledger's manifest reader uncovered
  writeSeed();
  const halted = runChild(["complete", POOL, REAL_HASH], undefined,
    { FORMATION_HALT_AFTER: PARED ? "shares" : "flip" });
  ok("manifest-range setup: halted with in-flight evidence", halted.code === 0 && hasInFlightEvidence());
  const mFile = fs.readdirSync(STATE_DIR).find((f) => f.startsWith("FORMATION_")
    && !f.startsWith("FORMATION_ABANDONED_") && !f.startsWith("FORMATION_DONE_") && f.endsWith(".val"));
  ok("manifest-range setup: an active manifest exists", mFile !== undefined);
  const mPath = path.join(STATE_DIR, mFile);
  const mObj = JSON.parse(fs.readFileSync(mPath, "utf8"));
  ok("manifest-range setup: the manifest carries claim snapshots", Array.isArray(mObj.claims) && mObj.claims.length > 0);
  // push the FIRST claim out of range in BOTH places, the snapshot and the ledger claim,
  // so the mutation-detecting preflight agrees with itself (the reviewer's exact pair)
  const edited = mObj.claims[0];
  const oldSlot = edited.slotNo;
  // the TIGHTEST bound, slotNo === slotCount, one past the last legal slot (the checker
  // noted 511 leaves the exact boundary untested)
  edited.slotNo = mObj.slotCount;
  fs.writeFileSync(mPath, JSON.stringify(mObj));
  const led = ledger();
  const lClaim = led.docs.find((d) => d.type === "pledgeSlot" && Number(d.data.slotNo) === Number(oldSlot));
  ok("manifest-range setup: the matching ledger claim exists", lClaim !== undefined);
  if (lClaim) { lClaim.data.slotNo = mObj.slotCount; fs.writeFileSync(LEDGER_PATH, JSON.stringify(led, null, 1)); }
  clearOpLock();
  const r = runChild(["complete", POOL, REAL_HASH]);
  ok("a LOADED manifest with an out-of-range claim snapshot REFUSES, never settles",
    r.code !== 0 && /outside the committed book/.test(r.out));
  ok("...and the refusal names the committed range", /0\.\.1/.test(r.out));
}

// ---- independent case LIVE DRAFT DAMAGE (pass 10, F1): the LIVE draft key gets the
//      same classification the archive path received. A stored value that PARSES to a
//      falsy JSON value (null, false, 0) is damage, not absence: the writer only ever
//      stores a draft object, so anything else means the bytes were altered, and reading
//      it as "no draft" silently drops the exact l1Verification evidence and falls back
//      to the weaker comparison. ----
{
  for (const [label, poison] of [["null", "null"], ["false", "false"], ["zero", "0"],
                                 ["a bare string", "\"draft\""], ["an array", "[]"]]) {
    writeSeed();
    runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: PARED ? "shares" : "flip" });
    const draftFile = fs.readdirSync(STATE_DIR).find((f) => f.startsWith("RECEIPT_DRAFT_") && f.endsWith(".val"));
    if (!draftFile) { ok(`live-draft ${label}: setup produced a draft`, false); continue; }
    fs.writeFileSync(path.join(STATE_DIR, draftFile), poison);
    const r = runChild(["receipt", POOL]);
    // the assertion names DAMAGED, so it must require exactly that: the earlier
    // alternation would have accepted the old "corrupt" wording and so observed only
    // "some refusal happened" (artifact check)
    ok(`a LIVE draft storing ${label} is refused as damaged, never read as absent`,
      r.code !== 0 && /DAMAGED/.test(r.out));
    ok(`...and the ${label} draft file is left in place for hands`,
      fs.existsSync(path.join(STATE_DIR, draftFile)));
  }
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

// ---- independent case J: abandon FAILS CLOSED on a damaged manifest (a soundness-review finding): a
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
//      completion or abandon (a soundness-review finding). Before the fix, one planted share broke the flip readback
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
  ok("a foreign share does NOT wedge completion (a soundness-review finding)", r.code === 0 && receipts().length === 1);
  assertReceiptCorrect("foreign-share-present receipt", receipts()[0]);
}
{
  writeSeed();
  const halted = runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" });
  ok("foreign-abandon setup: manifest committed, forming", halted.code === 0 && !poolLiveUnderRealHash());
  plantForeignShare(); // a foreign share on a forming pool with only the manifest committed
  const ab = runChild(["abandon", POOL]);
  ok("a foreign share does NOT block abandon (a soundness-review finding)", ab.code === 0 && /CLEARED/.test(ab.out));
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
  // the SHARE CROSS-CHECK (pass-7 wave, packet-review minor 5): status is the documented
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

// ---- independent case P (a soundness-review finding): a RESUMED completion compares an
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

// ---- THE DRIVEN EVO ROUND (EvoNodes E1-2): the real create and complete commands,
// driven once at the evo target on this ledger, with the two claims SEEDED DIRECTLY
// between them (the reservation step is not driven here; the admission suite covers
// it). Until this block, evo appeared in the offline suites almost solely as the value
// that must be refused (the plan's gap ledger). The receipt is verified against an
// INDEPENDENT evo oracle, rebuilt from the canonical spec exactly like EXPECTED above
// and sharing no helper with the code under test.
// SLOT_DUFFS is 2000 DASH so the book is 2 x 2000 (the two-member shape at four times
// the regular scale); the 100-DASH default would derive a 40-slot book against the
// 8-owner tier, the plan's G2 friction, which E1-3 addresses separately.
{
  // THE WIDE-BOOK NOTE (EvoNodes E1-3, the plan's G2): the 100-DASH default derives a
  // 40-slot evo book against the 8-owner tier. That shape is LEGAL (members may hold
  // several slots; completion aggregates by owner) and must stay accepted, but the
  // operator who never chose SLOT_DUFFS hears about it loudly, with the
  // one-slot-per-owner size named.
  writeSeed();
  const wideSeed = ledger();
  wideSeed.docs = wideSeed.docs.filter((d) => d.type !== "pool" && d.type !== "pledgeSlot");
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(wideSeed, null, 1));
  const rWide = runChild(["create", "evo", "2000"]); // default SLOT_DUFFS
  ok("evo wide book: the default-slot create still succeeds (a note, not a refusal)",
    rWide.code === 0);
  ok("evo wide book: exactly one pool exists and it carries the 40-slot book",
    ledger().docs.filter((d) => d.type === "pool").length === 1
    && Number(ledger().docs.find((d) => d.type === "pool").data.slotCount) === 40);
  ok("evo wide book: the create names the tier, the aggregation, and the one-slot-per-owner size",
    /NOTE: 40 slots against a tier of at most 8 co-owners/.test(rWide.out)
    && /completion aggregates claims by owner/.test(rWide.out)
    && /SLOT_DUFFS >= 50000000000/.test(rWide.out));

  writeSeed();
  const bare = ledger();
  bare.docs = bare.docs.filter((d) => d.type !== "pool" && d.type !== "pledgeSlot");
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(bare, null, 1));
  const rc = runChild(["create", "evo", "2000"], undefined, { SLOT_DUFFS: "200000000000" });
  ok("evo round: the real create opens an evo pool", rc.code === 0);
  ok("evo round: a two-slot book draws no wide-book note",
    !/NOTE: .* slots against a tier/.test(rc.out));
  // exact cardinality (checker on this fold): the .find below must be finding THE pool,
  // not the first of several
  ok("evo round: exactly one pool exists after create",
    ledger().docs.filter((d) => d.type === "pool").length === 1);
  const evoPool = ledger().docs.find((d) => d.type === "pool");
  ok("evo round: the created pool records nodeType evo",
    !!evoPool && evoPool.data.nodeType === "evo");
  ok("evo round: the book is 2 slots of 2000 DASH",
    !!evoPool && Number(evoPool.data.slotCount) === 2
    && Number(evoPool.data.slotDuffs) === 200000000000);
  if (PARED) {
    ok("evo round: the immutable pool pins the evo target",
      Number(evoPool.data.targetDuffs) === 400000000000);
  } else {
    ok("evo round: the mutable pool opens in the forming namespace",
      /^0{32}[0-9a-f]{32}$/.test(String(evoPool.data.proTxHash))
      && evoPool.data.status === "forming");
  }
  const EPOOL = evoPool.id;
  const led1 = ledger();
  led1.docs.push(
    { id: newId(), type: "pledgeSlot", ownerId: F1, data: {
      poolId: Buffer.from(Identifier.from(EPOOL).toBuffer()).toString("hex"),
      slotNo: 0, rewardScript: SCRIPT_A, $createdAt: 10 } },
    { id: newId(), type: "pledgeSlot", ownerId: F2, data: {
      poolId: Buffer.from(Identifier.from(EPOOL).toBuffer()).toString("hex"),
      slotNo: 1, rewardScript: SCRIPT_B, $createdAt: 20 } });
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(led1, null, 1));
  const done = runChild(["complete", EPOOL, REAL_HASH]);
  ok("evo round: the real complete finishes the evo pool",
    done.code === 0 && /FORMATION COMPLETE/.test(done.out));
  // the INDEPENDENT evo oracle, same construction discipline as EXPECTED
  const EVO_EXPECTED = (() => {
    const owners = [
      { owner: F1, amountDuffs: "200000000000", bps: 5000, script: SCRIPT_A },
      { owner: F2, amountDuffs: "200000000000", bps: 5000, script: SCRIPT_B },
    ].sort((a, b) => Buffer.compare(
      Buffer.from(Identifier.from(a.owner).toBuffer()), Buffer.from(Identifier.from(b.owner).toBuffer())));
    const arr = ["tegara-completion-allocation", 1, CONTRACT, EPOOL, "400000000000",
      owners.map((o) => [o.owner, o.amountDuffs, o.bps, o.script])];
    const rowsBytes = Buffer.from(JSON.stringify(arr), "utf8");
    return { allocationRows: rowsBytes.toString("hex"),
      allocationHash: crypto.createHash("sha256").update(rowsBytes).digest("hex") };
  })();
  const evoReceipts = receipts().filter((d) =>
    Identifier.from(Buffer.from(d.data.poolId, "hex")).toString() === EPOOL);
  ok("evo round: exactly one receipt exists for the evo pool", evoReceipts.length === 1);
  const er = evoReceipts[0];
  if (er) {
    ok("evo round: the receipt's allocation rows match the independent evo oracle",
      er.data.allocationRows === EVO_EXPECTED.allocationRows);
    ok("evo round: the receipt's allocation hash matches the independent evo oracle",
      er.data.allocationHash === EVO_EXPECTED.allocationHash);
    ok("evo round: the receipt names REAL_HASH", er.data.proTxHash === REAL_HASH);
    if (PARED) {
      ok("evo round: the pared receipt carries no nodeType (the pool pins evo)",
        er.data.nodeType === undefined);
      const p = ledger().docs.find((d) => d.id === EPOOL);
      const verdict = checkReceiptAgainstPool({
        contractId: CONTRACT,
        receipt: {
          poolId: Buffer.from(er.data.poolId, "hex"), proTxHash: Buffer.from(er.data.proTxHash, "hex"),
          slotIndex: Number(er.data.slotIndex), formatVersion: Number(er.data.formatVersion),
          allocationRows: Buffer.from(er.data.allocationRows, "hex"),
          allocationHash: Buffer.from(er.data.allocationHash, "hex"),
          participantCount: Number(er.data.participantCount),
          l1Verification: er.data.l1Verification,
          verificationMethodVersion: Number(er.data.verificationMethodVersion),
        },
        pool: p.data, poolId: EPOOL,
        receiptOwnerId: er.ownerId, poolOwnerId: p.ownerId,
      });
      ok("evo round: the shared receipt-to-pool check returns ok for the evo pair",
        verdict.ok === true);
    } else {
      ok("evo round: the receipt carries nodeType evo and the evo target",
        er.data.nodeType === "evo" && Number(er.data.targetDuffs) === 400000000000);
      const p = ledger().docs.find((d) => d.id === EPOOL);
      ok("evo round: the pool flipped live under REAL_HASH",
        p.data.status === "live" && p.data.proTxHash === REAL_HASH);
    }
  }
  // one share PER MEMBER (checker on this fold): count-two-at-5000 alone would pass
  // two shares issued to one owner
  const evoShareOwners = ledger().docs.filter((d) => d.type === "share"
    && Identifier.from(Buffer.from(d.data.poolId, "hex")).toString() === EPOOL
    && Number(d.data.shareBps) === 5000).map((d) => d.ownerId).sort();
  ok("evo round: one 5000-bps share each for F1 and F2",
    evoShareOwners.join(",") === [F1, F2].sort().join(","));
}

fs.rmSync(ROOT, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
