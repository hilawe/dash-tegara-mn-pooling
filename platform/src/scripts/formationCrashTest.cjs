/**
 * The failure-injection crash matrix for the v8 formation RECEIPT state machine (round 1's
 * Lens-3 recommendation, and the mechanical base round 4 hunts above). It does for the
 * receipt flow what envStoreCrashTest does for the state store: stop REAL execution at
 * every mutating boundary (each Platform op AND each local durable write), then assert the
 * state either RESUMES to the same receipt or STOPS LOUDLY without clearing recovery
 * evidence, never a silent wrong state.
 *
 * Mechanism: a child process runs the real formation.cjs with `dash` swapped for an
 * in-memory mock ledger (formationMockDash.cjs) and a fault counter that hard-exits 97
 * after boundary K (bypassing every finally, exactly like a real crash, so the op lock
 * stays held and drafts stay frozen). The parent, per K: seed a fresh forming pool,
 * `complete` with a crash at K, then DRIVE RECOVERY the way an operator would (clear a
 * crash-held op lock, re-run `complete`, and run `receipt`), and assert the invariants.
 *
 * Adversarial cases (round 3's awkward-to-run-live re-check items) follow the matrix:
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

const seedLedger = () => ({
  contractId: CONTRACT, contractOwner: OP,
  docs: [
    { id: POOL, type: "pool", ownerId: OP, data: {
      proTxHash: "00".repeat(16) + crypto.randomBytes(16).toString("hex"), // forming placeholder
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
    `FUNDER_ID=${F1}\nFUNDER2_ID=${F2}\n`);
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(seedLedger(), null, 1));
};

const REAL_HASH = "dd" + "56".repeat(31); // a non-forming 32-byte hash

const runChild = (args, crashAfter, extraEnv = {}) => {
  const env = { ...process.env, TEGARA_ENV_PATH: ENV_PATH, TEGARA_MOCK_LEDGER: LEDGER_PATH,
    LEDGER: "v8", NETWORK: "regtest", FORMATION_ALLOW_UNVERIFIED: "demo", ...extraEnv };
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
    proTxHash: REAL_HASH, slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000,
    formatVersion: 1, participantCount: 2, targetDuffs: 100000000000,
    l1Verification: "demo-unverified", verificationMethodVersion: 1,
    allocationRows: rowsBytes.toString("hex"),
    allocationHash: crypto.createHash("sha256").update(rowsBytes).digest("hex"),
  };
})();

// assert an on-ledger receipt matches the INDEPENDENT expectation field by field
const assertReceiptCorrect = (label, r) => {
  if (!r) { ok(`${label}: a receipt exists`, false); return; }
  const d = r.data;
  ok(`${label}: owner is the operator`, r.ownerId === OP);
  ok(`${label}: poolId`, Identifier.from(Buffer.from(d.poolId, "hex")).toString() === POOL);
  ok(`${label}: proTxHash == REAL_HASH`, d.proTxHash === EXPECTED.proTxHash);
  ok(`${label}: slotIndex`, Number(d.slotIndex) === EXPECTED.slotIndex);
  ok(`${label}: nodeType`, d.nodeType === EXPECTED.nodeType);
  ok(`${label}: operatorFeeBps`, Number(d.operatorFeeBps) === EXPECTED.operatorFeeBps);
  ok(`${label}: formatVersion`, Number(d.formatVersion) === EXPECTED.formatVersion);
  ok(`${label}: participantCount`, Number(d.participantCount) === EXPECTED.participantCount);
  ok(`${label}: targetDuffs`, Number(d.targetDuffs) === EXPECTED.targetDuffs);
  ok(`${label}: l1Verification`, d.l1Verification === EXPECTED.l1Verification);
  ok(`${label}: verificationMethodVersion`, Number(d.verificationMethodVersion) === EXPECTED.verificationMethodVersion);
  ok(`${label}: allocationRows`, d.allocationRows === EXPECTED.allocationRows);
  ok(`${label}: allocationHash`, d.allocationHash === EXPECTED.allocationHash);
};
// the pool must be live under exactly REAL_HASH (round-4: poolLive only checked non-forming)
const poolLiveUnderRealHash = () => {
  const p = ledger().docs.find((d) => d.id === POOL);
  return p.data.status === "live" && p.data.proTxHash === REAL_HASH;
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
const poolLive = () => {
  const p = ledger().docs.find((d) => d.id === POOL);
  return p.data.status === "live" && !/^0{32}/.test(p.data.proTxHash);
};
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
// (a raw string passed where a byteArray is required)
{
  const mock = require("./formationMockDash.cjs");
  const good = {
    poolId: Buffer.alloc(32, 1), proTxHash: Buffer.alloc(32, 2), slotIndex: 0, nodeType: "regular",
    operatorFeeBps: 2000, formatVersion: 1, allocationRows: Buffer.from("[]"), allocationHash: Buffer.alloc(32, 3),
    participantCount: 2, targetDuffs: 100000000000, l1Verification: "demo-unverified", verificationMethodVersion: 1 };
  let threw = false;
  try { mock.validateReceiptProps({ ...good, allocationRows: "not-bytes" }); } catch { threw = true; }
  ok("mock schema rejects a raw-string allocationRows (the false-green case)", threw);
  let okPass = true;
  try { mock.validateReceiptProps(good); } catch { okPass = false; }
  ok("mock schema accepts a well-formed receipt", okPass);
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
      // acceptable ONLY if it stopped loudly AND left no receipt to contradict (nothing to recover)
      ok(`k=${k}: a non-recovering stop is loud and receiptless`,
        (rec.code === 1 || rec.code === 2) && receipts().length === 0);
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
  // reach live-without-receipt with the draft + active manifest retained
  const halted = runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "flip" });
  ok("receipt-matrix setup: halted live with no receipt", halted.code === 0 && poolLiveUnderRealHash() && receipts().length === 0);
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

// ---- adversarial case: a legitimate POOL FEE CHANGE after completion must NOT make
//      `receipt` falsely reject the (historical-fee) receipt (round-5 P2) ----
{
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

// ---- adversarial case A: two stale op-lock waiters never both proceed ----
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH]); // land a completed pool + receipt
  // forge a foreign op-lock with an owner token, as a crashed run would leave
  const suffix = fs.readdirSync(STATE_DIR).find((f) => f.startsWith("FORMATION_DONE_")).replace("FORMATION_DONE_", "").replace(".val", "");
  const lockDir = path.join(STATE_DIR, `oplock-${suffix}`);
  fs.mkdirSync(lockDir, { recursive: true });
  fs.writeFileSync(path.join(lockDir, "owner"), "ghost-pid");
  const blocked = runChild(["receipt", POOL]);
  ok("held op lock blocks a second run (no auto-steal)", blocked.code !== 0 && /operation lock/.test(blocked.out));
  ok("the blocked run left the foreign lock in place", fs.existsSync(lockDir));
  fs.rmSync(lockDir, { recursive: true, force: true });
}

// ---- adversarial case B: a receipt whose pool is still forming is refused ----
{
  writeSeed();
  // hand-inject a schema-valid receipt for a pool that never flipped (a squatter-style anomaly)
  const l = ledger();
  const rows = Buffer.from(JSON.stringify(["tegara-completion-allocation", 1, CONTRACT, POOL, "100000000000", []]), "utf8");
  l.docs.push({ id: newId(), type: "completionReceipt", ownerId: OP, data: {
    poolId: Buffer.from(Identifier.from(POOL).toBuffer()).toString("hex"),
    proTxHash: REAL_HASH, slotIndex: 0, nodeType: "regular", operatorFeeBps: 2000, formatVersion: 1,
    allocationRows: rows.toString("hex"),
    allocationHash: crypto.createHash("sha256").update(rows).digest("hex"),
    participantCount: 1, targetDuffs: 100000000000, l1Verification: "demo-unverified",
    verificationMethodVersion: 1, $createdAt: 5 } });
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  const r = runChild(["receipt", POOL]);
  ok("a receipt on a still-forming pool is refused loudly", r.code !== 0 && /forming/i.test(r.out));
}

// ---- adversarial case C: a corrupt draft is refused, never written blind ----
//      DETERMINISTIC (round-6): reach a state that certainly HAS a draft (halt after the
//      flip, which freezes the draft and retains it), then corrupt it.
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "flip" });
  const draftFile = fs.readdirSync(STATE_DIR).find((f) => f.startsWith("RECEIPT_DRAFT_") && f.endsWith(".val"));
  ok("corrupt-draft setup: a draft exists to corrupt", !!draftFile);
  fs.writeFileSync(path.join(STATE_DIR, draftFile), "{ not json");
  const r = runChild(["receipt", POOL]);
  ok("a corrupt draft is refused loudly", r.code !== 0 && /corrupt/i.test(r.out));
  ok("a corrupt draft writes no receipt", receipts().length === 0);
}

// ---- adversarial case D0: a fee change BEFORE the flip must REFUSE (round-6 re-check:
//      the receipt records the completion-time fee, so a pre-flip drift must never let a
//      stale draft fee freeze into the immutable receipt) ----
{
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

// ---- adversarial case D: a legitimate POOL FEE CHANGE while the pool is live WITHOUT a
//      receipt (draft present) must NOT brick recovery (round-6: requireDraftMatchesPool
//      used to reject on fee) ----
{
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

// ---- adversarial case E: abandon ARCHIVES before clearing, and receipt RECOVERS from
//      the archive if the pool went live during/after the abandon (round-7 P1) ----
{
  writeSeed();
  const halted = runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" });
  ok("abandon setup: manifest committed, pool still forming, no shares", halted.code === 0 && !poolLiveUnderRealHash());
  const ab = runChild(["abandon", POOL]);
  ok("abandon succeeds and reports the archive", ab.code === 0 && /archived to FORMATION_ABANDONED_/.test(ab.out));
  ok("abandon left an archive key", fs.readdirSync(STATE_DIR).some((f) => f.startsWith("FORMATION_ABANDONED_") && f.endsWith(".val")));
  ok("abandon cleared the active manifest and draft", !hasInFlightEvidence());
  // the loss scenario: the pool goes live under the abandoned hash after the abandon
  const l = ledger();
  const p = l.docs.find((d) => d.id === POOL);
  p.data.proTxHash = REAL_HASH; p.data.status = "live";
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  const r = runChild(["receipt", POOL]);
  ok("receipt RECOVERS from the abandon archive", r.code === 0 && receipts().length === 1);
  assertReceiptCorrect("abandon-archive receipt", receipts()[0]);
  ok("finalization CLEARED the abandon archive (round-7 re-check)",
    !fs.readdirSync(STATE_DIR).some((f) => f.startsWith("FORMATION_ABANDONED_") && f.endsWith(".val")));
}

// ---- adversarial case H: a STALE archive whose committed hash != the live pool hash is
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

// ---- adversarial case F: abandon REFUSES if the pool went live before the mutation
//      (re-fetch guard), keeping the manifest for `receipt` ----
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH], undefined, { FORMATION_HALT_AFTER: "commit" });
  // flip the pool live BEFORE calling abandon (simulating a concurrent flip pre-mutation)
  const l = ledger();
  const p = l.docs.find((d) => d.id === POOL);
  p.data.proTxHash = REAL_HASH; p.data.status = "live";
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(l, null, 1));
  const ab = runChild(["abandon", POOL]);
  ok("abandon refuses a live pool", ab.code !== 0 && /LIVE/.test(ab.out));
  ok("abandon kept the manifest (no clear, no archive needed)", hasInFlightEvidence());
  const r = runChild(["receipt", POOL]);
  ok("receipt then publishes from the kept manifest", r.code === 0 && receipts().length === 1);
}

// ---- adversarial case G: done prune KEEPS a DONE whose sibling DRAFT survives (round-7
//      P2, the pre-round-6 half-finalized DONE+DRAFT legacy state) ----
{
  writeSeed();
  runChild(["complete", POOL, REAL_HASH]); // clean: writes DONE, clears active + draft
  const doneFile = fs.readdirSync(STATE_DIR).find((f) => f.startsWith("FORMATION_DONE_") && f.endsWith(".val"));
  const suffix = doneFile.replace("FORMATION_DONE_", "").replace(".val", "");
  // forge the legacy crash state: DONE (old) + a leftover DRAFT, no active key
  fs.writeFileSync(path.join(STATE_DIR, `RECEIPT_DRAFT_${suffix}.val`), '{"v":1}');
  const pr = runChild(["done", "prune", "0"]); // cutoff 0 days: everything is "old enough"
  ok("prune keeps a DONE with a surviving sibling draft", pr.code === 0 && /kept .* frozen draft/.test(pr.out));
  ok("the DONE manifest survived the prune", fs.existsSync(path.join(STATE_DIR, doneFile)));
}

fs.rmSync(ROOT, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
