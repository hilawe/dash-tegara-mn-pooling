/**
 * THE REGISTRATION RUNNER'S DEMO FORMATION, and whether a run creates it or reuses the one already
 * on the published v11 (registerV11Run.mjs, "FORMATION SETUP").
 *
 * WHY THIS EXISTS (2026-09-27). The runner is one-shot, but a run can stop after v11 is published
 * and before the gate capture is written, and on testnet one did. Its resume path repeated the
 * formation setup: the pool document committed again, and the completion receipt was refused by
 * the unique index (proTxHash, slotIndex), because the demo node hash is fixed and the first
 * receipt holds that slot. Every retry would have left another orphan pool. So a resumed run now
 * finds the formation the first run committed and reuses it, and creates one only when none exists.
 *
 * WHAT A REUSE ESTABLISHES. The receipt was served by a proof-verified query on its unique index,
 * and its pool by a proof-verified query on the id the receipt names (the runner's reads, injected
 * here). Both must be owned by the writer, carry exactly the demo shape, and agree with each other:
 * the receipt names that pool, and its allocation rows and hash equal the ones recomputed from the
 * contract, the pool id and the two member identities. Anything else REFUSES rather than falling
 * back to creating, because a formation that is present but inconsistent needs a human, and a
 * receipt that is not the demo one (a real l1Verification) must never be reused as a demo.
 *
 * WHAT "NONE FOUND" MEANS, and its limit. Zero receipts from the unique-index query leads to the
 * create path. A query that silently matches nothing would do the same: a live probe on 2026-09-27
 * found that the node hash given as a hex string returns zero documents without an error (a
 * Uint8Array throws, and only a Buffer matches), which is why receiptWhere gives a Buffer. If such
 * a misread happened anyway, the create path's receipt write is refused by Platform's own unique
 * index, as the 2026-09-27 run showed, so it cannot produce a second demo receipt. It can leave an
 * orphan pool document.
 */
const crypto = require("crypto");
const formationCore = require("./formationCore.cjs");

const refuse = (why) => { throw new Error(`registerV11Formation: ${why}; refusing`); };

// the demo node hash: deterministic and clearly synthetic, with l1Verification "demo-unverified",
// the schema's own label for a record with no verified L1 node behind it
// exported as hex and handed out as a fresh Buffer, so no caller can alter the shared value
const DEMO_NODE_HASH_HEX = crypto.createHash("sha256").update("tegara canonical-phase demo node").digest("hex");
const demoNodeHash = () => Buffer.from(DEMO_NODE_HASH_HEX, "hex");
const DEMO_SLOT_INDEX = 0;
const DEMO_TARGET_DUFFS = 400000000000;
const DEMO_POOL_FIELDS = Object.freeze({ slotIndex: DEMO_SLOT_INDEX, nodeType: "evo",
  operatorFeeBps: 0, targetDuffs: DEMO_TARGET_DUFFS });
const DEMO_RECEIPT_FIELDS = Object.freeze({ slotIndex: DEMO_SLOT_INDEX, formatVersion: 1,
  participantCount: 2, l1Verification: "demo-unverified", verificationMethodVersion: 1 });

// the two-member manifest both paths use, split evenly between the two identities
const demoManifest = ({ poolIdB58, idA, idB }) => ({
  poolId: poolIdB58,
  target: String(DEMO_TARGET_DUFFS),
  owners: [
    { owner: idA, amountDuffs: "200000000000", bps: 5000, rewardScriptHex: "76a914" + "11".repeat(20) + "88ac" },
    { owner: idB, amountDuffs: "200000000000", bps: 5000, rewardScriptHex: "76a914" + "22".repeat(20) + "88ac" },
  ],
});

const demoAllocation = ({ contractId, poolIdB58, idA, idB }) => {
  const rows = formationCore.allocationPreimage(contractId, demoManifest({ poolIdB58, idA, idB }));
  return { rows, hash: formationCore.allocationHash(rows) };
};

// the unique-index query. A Buffer is the only value form that matched live (see the header).
const receiptWhere = () => [["proTxHash", "==", demoNodeHash()], ["slotIndex", "==", DEMO_SLOT_INDEX]];

// ---- reading a served document into plain data ----
const idOf = (v, what) => {
  const b58 = v && typeof v.base58 === "function" ? v.base58() : (typeof v === "string" ? v : null);
  const bytes = b58 !== null ? formationCore.decodeId32(b58) : null;
  if (!bytes) refuse(`the served ${what} does not decode to a 32-byte identifier`);
  return { b58, hex: bytes.toString("hex") };
};
const normalizeDoc = (doc, what) => {
  if (!doc || typeof doc !== "object") refuse(`the served ${what} is not a document`);
  const id = idOf(doc.id !== undefined ? doc.id : doc.$id, `${what} id`);
  const owner = idOf(doc.ownerId !== undefined ? doc.ownerId : doc.$ownerId, `${what} owner`);
  const props = typeof doc.getProperties === "function" ? doc.getProperties() : doc.properties;
  if (!props || typeof props !== "object") refuse(`the served ${what} has no properties`);
  const fields = {};
  for (const [k, v] of Object.entries(props)) {
    fields[k] = (v instanceof Uint8Array || Buffer.isBuffer(v)) ? Buffer.from(v).toString("hex")
      : (typeof v === "bigint" ? Number(v) : v);
  }
  return { id, owner, fields };
};

const requireFields = (fields, want, what) => {
  for (const [k, v] of Object.entries(want)) {
    if (fields[k] !== v) refuse(`the ${what}'s ${k} is ${JSON.stringify(fields[k])}, not the demo's ${JSON.stringify(v)}`);
  }
};

/**
 * Decide, from proof-verified reads, whether the demo formation is created or reused.
 * deps.queryReceipts() answers the served receipts on the demo's unique index;
 * deps.fetchPoolById(bytes) answers the served pools with that id. Both are the runner's proved
 * reads and must throw rather than answer when the proof check does not pass.
 * Returns { action: "create" } or { action: "reuse", pool, receipt, poolDoc, receiptDoc,
 * allocation }, and refuses everything else.
 */
const resolveDemoFormation = async ({ deps, contractId, idA, idB, writerIdHex }) => {
  if (!deps || typeof deps.queryReceipts !== "function" || typeof deps.fetchPoolById !== "function") {
    refuse("the formation lookup needs deps.queryReceipts and deps.fetchPoolById");
  }
  for (const [name, v] of [["contractId", contractId], ["idA", idA], ["idB", idB]]) {
    if (typeof v !== "string" || !formationCore.decodeId32(v)) refuse(`${name} must be a base58 identifier`);
  }
  if (typeof writerIdHex !== "string" || !/^[0-9a-f]{64}$/.test(writerIdHex)) refuse("writerIdHex must be 64 lowercase hex characters");

  const served = await deps.queryReceipts();
  if (!Array.isArray(served)) refuse("the receipt lookup did not answer a list");
  if (served.length === 0) return { action: "create" };
  if (served.length > 1) refuse(`the demo's unique index served ${served.length} receipts`);

  const receiptDoc = served[0];
  const receipt = normalizeDoc(receiptDoc, "receipt");
  if (receipt.owner.hex !== writerIdHex) refuse("the served receipt is not owned by the writer");
  if (receipt.fields.proTxHash !== DEMO_NODE_HASH_HEX) refuse("the served receipt does not carry the demo node hash");
  requireFields(receipt.fields, DEMO_RECEIPT_FIELDS, "receipt");
  if (typeof receipt.fields.poolId !== "string" || !/^[0-9a-f]{64}$/.test(receipt.fields.poolId)) {
    refuse("the served receipt's poolId is not 32 bytes");
  }

  const pools = await deps.fetchPoolById(Buffer.from(receipt.fields.poolId, "hex"));
  if (!Array.isArray(pools)) refuse("the pool lookup did not answer a list");
  if (pools.length !== 1) refuse(`the receipt names pool ${receipt.fields.poolId.slice(0, 12)}..., and ${pools.length} pools were served for it`);
  const poolDoc = pools[0];
  const pool = normalizeDoc(poolDoc, "pool");
  if (pool.id.hex !== receipt.fields.poolId) refuse("the served pool is not the pool the receipt names");
  if (pool.owner.hex !== writerIdHex) refuse("the served pool is not owned by the writer");
  requireFields(pool.fields, DEMO_POOL_FIELDS, "pool");

  const allocation = demoAllocation({ contractId, poolIdB58: pool.id.b58, idA, idB });
  if (receipt.fields.allocationRows !== allocation.rows.toString("hex")) {
    refuse("the receipt's allocation rows differ from the ones recomputed for this contract, pool and members");
  }
  if (receipt.fields.allocationHash !== allocation.hash.toString("hex")) {
    refuse("the receipt's allocation hash differs from the one recomputed for this contract, pool and members");
  }
  return { action: "reuse", pool, receipt, poolDoc, receiptDoc, allocation };
};

module.exports = {
  DEMO_NODE_HASH_HEX, demoNodeHash, DEMO_SLOT_INDEX, DEMO_POOL_FIELDS, DEMO_RECEIPT_FIELDS,
  demoManifest, demoAllocation, receiptWhere, resolveDemoFormation,
};
