// The registration runner's demo formation: create when none exists, reuse the committed one
// when it is exactly the demo, refuse anything else (registerV11Formation.cjs).
//
// THE GOLDEN FIXTURE IS TESTNET'S OWN. The ids are the published v11, identities A and B, and the
// demo pool and receipt the 2026-09-27 run committed. The allocation rows are built here from a
// manifest written out in this file, independently of the module's demoManifest, and pinned to
// the allocation hash the receipt actually carries on testnet (read by a proved query that day).
const crypto = require("crypto");
const formationCore = require("./formationCore.cjs");
const F = require("./registerV11Formation.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error("FAIL (no error):", name); }
  catch (e) {
    const m = (e && e.message) || String(e);
    if (re.test(m)) passed++; else { failed++; console.error("FAIL (wrong error):", name, "->", m); }
  }
};

const V11 = "GJWKJLZF3PHm8HuUwz4JCL2PkTmvDqcYV2GagYaQ6mq";
const ID_A = "2ghcNuyk6M6JGchFEkj6QTzAN5xFaSrRDGy7kii5RRNi";
const ID_B = "CxwSMpKPQ58NvGFmta24LDr2kqW4Em92sKUZrXBcrPS";
const POOL_B58 = "D2uQiWX733GdGqHPSSUDBsEdEVYQGJ6aC9fkPQ5g5p5w";
const RECEIPT_B58 = "Fky8vMszZgxG8WDs24ZHpsZoqtXoeeFR2vn4NUrHyEa8";
const OTHER_POOL_B58 = "EMoKJCqe4NGws8WKz9ocmvvYnDvhwjCExuYuPi7G4r2H";
const GOLDEN_ALLOCATION_HASH = "025b78f703604eab77fef97ec9b89d972f5d5aa35dbefa44cf39610302227837";
const hexOf = (b58) => formationCore.decodeId32(b58).toString("hex");
const A_HEX = hexOf(ID_A);
const POOL_HEX = hexOf(POOL_B58);

// the manifest as the runner wrote it on 2026-09-27, spelled out here rather than taken from the module
const ROWS = formationCore.allocationPreimage(V11, {
  poolId: POOL_B58, target: "400000000000",
  owners: [
    { owner: ID_A, amountDuffs: "200000000000", bps: 5000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
    { owner: ID_B, amountDuffs: "200000000000", bps: 5000, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
  ],
});
const NODE = crypto.createHash("sha256").update("tegara canonical-phase demo node").digest();

// served documents in the shape the proved query returns (an id object with base58, properties)
const doc = (idB58, ownerB58, props) => ({ id: { base58: () => idB58 }, ownerId: { base58: () => ownerB58 },
  getProperties: () => ({ ...props }) });
const receiptProps = (over = {}) => ({
  poolId: Buffer.from(POOL_HEX, "hex"), proTxHash: Buffer.from(NODE), slotIndex: 0, formatVersion: 1,
  allocationRows: Buffer.from(ROWS), allocationHash: Buffer.from(GOLDEN_ALLOCATION_HASH, "hex"),
  participantCount: 2, l1Verification: "demo-unverified", verificationMethodVersion: 1, ...over });
const poolProps = (over = {}) => ({ slotIndex: 0, nodeType: "evo", operatorFeeBps: 0, targetDuffs: 400000000000, ...over });
const RECEIPT = (over, owner = ID_A) => doc(RECEIPT_B58, owner, receiptProps(over));
const POOL = (over, owner = ID_A, id = POOL_B58) => doc(id, owner, poolProps(over));

const resolve = ({ receipts = [RECEIPT()], pools = [POOL()], seen = {} } = {}) => F.resolveDemoFormation({
  contractId: V11, idA: ID_A, idB: ID_B, writerIdHex: A_HEX,
  deps: {
    queryReceipts: async () => receipts,
    fetchPoolById: async (bytes) => { seen.poolIdAsked = Buffer.from(bytes).toString("hex"); return pools; },
  } });

(async () => {
  // ---- the golden values are the ones committed on testnet ----
  ok("the manifest spelled out here reproduces the allocation hash the testnet receipt carries",
    formationCore.allocationHash(ROWS).toString("hex") === GOLDEN_ALLOCATION_HASH);
  ok("the module's demoAllocation reproduces the same rows and hash",
    (() => { const a = F.demoAllocation({ contractId: V11, poolIdB58: POOL_B58, idA: ID_A, idB: ID_B });
      return a.rows.equals(ROWS) && a.hash.toString("hex") === GOLDEN_ALLOCATION_HASH; })());
  ok("the demo node hash is the one the testnet receipt carries (prefix read by proof 2026-09-27)",
    F.DEMO_NODE_HASH_HEX.startsWith("0a2ca29e0eb0ba55") && F.DEMO_NODE_HASH_HEX === NODE.toString("hex"));
  {
    const w = F.receiptWhere();
    ok("the unique-index query gives the node hash as a Buffer, the one form that matched live, and asks for the exact slot",
      w.length === 2 && w[0][0] === "proTxHash" && w[0][1] === "==" && Buffer.isBuffer(w[0][2])
      && w[0][2].toString("hex") === NODE.toString("hex")
      && w[1][0] === "slotIndex" && w[1][1] === "==" && w[1][2] === 0);
    w[0][2][0] ^= 0xff;
    ok("the handed-out node hash is a fresh copy, so altering it changes nothing shared",
      F.receiptWhere()[0][2].toString("hex") === NODE.toString("hex") && F.demoNodeHash() !== F.demoNodeHash());
  }

  // ---- create and reuse ----
  ok("no served receipt: create", (await resolve({ receipts: [] })).action === "create");
  {
    const seen = {};
    const r = await resolve({ seen });
    ok("the committed demo formation is reused, naming its pool, and the pool is asked for by the receipt's poolId",
      r.action === "reuse" && r.pool.id.hex === POOL_HEX && r.pool.id.b58 === POOL_B58
      && r.allocation.hash.toString("hex") === GOLDEN_ALLOCATION_HASH && seen.poolIdAsked === POOL_HEX
      && typeof r.poolDoc.getProperties === "function" && typeof r.receiptDoc.getProperties === "function");
  }

  // ---- everything else refuses ----
  await rejects("two receipts on a unique index refuse", resolve({ receipts: [RECEIPT(), RECEIPT()] }), /served 2 receipts/);
  await rejects("a receipt owned by another identity refuses", resolve({ receipts: [RECEIPT({}, ID_B)] }), /receipt is not owned by the writer/);
  await rejects("a receipt without the demo node hash refuses",
    resolve({ receipts: [RECEIPT({ proTxHash: Buffer.alloc(32, 7) })] }), /does not carry the demo node hash/);
  await rejects("a receipt that is not labeled demo-unverified refuses, so a real receipt is never reused as a demo",
    resolve({ receipts: [RECEIPT({ l1Verification: "verified" })] }), /l1Verification/);
  await rejects("a receipt for a different participant count refuses",
    resolve({ receipts: [RECEIPT({ participantCount: 3 })] }), /participantCount/);
  await rejects("a receipt whose poolId is not 32 bytes refuses",
    resolve({ receipts: [RECEIPT({ poolId: Buffer.alloc(31, 1) })] }), /poolId is not 32 bytes/);
  await rejects("a receipt whose pool is not served refuses", resolve({ pools: [] }), /0 pools were served/);
  await rejects("a served pool that is not the one the receipt names refuses",
    resolve({ pools: [POOL({}, ID_A, OTHER_POOL_B58)] }), /not the pool the receipt names/);
  await rejects("a pool owned by another identity refuses", resolve({ pools: [POOL({}, ID_B)] }), /pool is not owned by the writer/);
  await rejects("a pool with a different target refuses", resolve({ pools: [POOL({ targetDuffs: 100000000000 })] }), /targetDuffs/);
  // every demo field binds on its own (review 2026-09-27: exempting any one of these five from the
  // comparison had left every case green)
  await rejects("a receipt in another slot refuses", resolve({ receipts: [RECEIPT({ slotIndex: 1 })] }), /receipt's slotIndex/);
  await rejects("a receipt of another format version refuses", resolve({ receipts: [RECEIPT({ formatVersion: 2 })] }), /formatVersion/);
  await rejects("a receipt of another verification method version refuses",
    resolve({ receipts: [RECEIPT({ verificationMethodVersion: 2 })] }), /verificationMethodVersion/);
  await rejects("a pool in another slot refuses", resolve({ pools: [POOL({ slotIndex: 1 })] }), /pool's slotIndex/);
  await rejects("a pool of another node type refuses", resolve({ pools: [POOL({ nodeType: "regular" })] }), /nodeType/);
  await rejects("a pool with an operator fee refuses", resolve({ pools: [POOL({ operatorFeeBps: 100 })] }), /operatorFeeBps/);
  await rejects("allocation rows that differ from the recomputed ones refuse",
    resolve({ receipts: [RECEIPT({ allocationRows: Buffer.concat([Buffer.from(ROWS), Buffer.from(" ")]) })] }), /allocation rows differ/);
  await rejects("an allocation hash that differs from the recomputed one refuses",
    resolve({ receipts: [RECEIPT({ allocationHash: Buffer.alloc(32, 9) })] }), /allocation hash differs/);
  await rejects("the same receipt checked against another contract refuses (the rows bind the contract)",
    F.resolveDemoFormation({ contractId: OTHER_POOL_B58, idA: ID_A, idB: ID_B, writerIdHex: A_HEX,
      deps: { queryReceipts: async () => [RECEIPT()], fetchPoolById: async () => [POOL()] } }), /allocation rows differ/);
  await rejects("a lookup that answers something other than a list refuses",
    F.resolveDemoFormation({ contractId: V11, idA: ID_A, idB: ID_B, writerIdHex: A_HEX,
      deps: { queryReceipts: async () => null, fetchPoolById: async () => [] } }), /did not answer a list/);
  await rejects("a failed proved read stops the decision rather than reading as none found",
    F.resolveDemoFormation({ contractId: V11, idA: ID_A, idB: ID_B, writerIdHex: A_HEX,
      deps: { queryReceipts: async () => { throw new Error("proof verification failed"); }, fetchPoolById: async () => [] } }),
    /proof verification failed/);

  console.log(`registerV11FormationTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
})().catch((e) => { console.error("UNCAUGHT:", e); process.exitCode = 1; });
