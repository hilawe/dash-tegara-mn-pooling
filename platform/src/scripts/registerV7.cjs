/**
 * Publish the pool-ledger contract v7: SLOT ECONOMICS ON THE POOL, the Option B revision
 * from the refactors review (findings R1/A1/R2). The prototyped-and-refuted stronger
 * design is recorded first, because its absence shapes this one:
 *
 *   REFUTED FOR THIS SDK: an operator-created slot inventory that members TAKE OVER
 *   (document transfer or purchase) would put capacity, amount, and lifecycle all under
 *   consensus and give reservation/completion a shared conflict point. The protocol has
 *   the transitions (wasm-dpp 4.0.0 ships DocumentNotForSaleError and
 *   DocumentIncorrectPurchasePriceError), but the JS SDK's DocumentFactory builds only
 *   the create/replace/delete action sets: createStateTransition({ transfer: [doc] })
 *   raises NoDocumentsSuppliedError because the key is never read, and no
 *   DocumentTransferTransition class is exported for a low-level construction (probed
 *   offline 2026-07-12, dash 7.0.0 / wasm-dpp 4.0.0). The takeover inventory is the
 *   recorded v8 design for when the SDK exposes those transitions.
 *
 * What v7 DOES change, within what this SDK can express:
 *
 *   pool: gains OPTIONAL slotDuffs and slotCount, written once at creation by the
 *     operator who opens a forming pool. The slot economics become on-ledger pool data,
 *     the single source of truth every client reads (v6's SLOT_DUFFS env convention let
 *     two honest clients see incompatible slot books, review finding A1). A pool
 *     without the fields simply has no slot book (the rail's live pools), and reserve
 *     refuses it. The pool document type stays mutable (completion flips the hash and
 *     status), so the ledger cannot freeze the two fields specifically; the client
 *     discipline is that they are creation-time constants, and completion verifies the
 *     claims against the CURRENT pool values, so a mid-formation change surfaces as a
 *     loud conformance refusal rather than a silent reinterpretation.
 *
 *   pledgeSlot: LOSES slotDuffs. A v7 claim carries only (poolId, slotNo, rewardScript),
 *     so a claim cannot misstate its size at all; its value is defined by the pool it
 *     points at. The only nonconformance left to verify at completion is an
 *     out-of-range slotNo, bounded by the pool's own slotCount. The unique
 *     (poolId, slotNo) index and its duplicate-rejection guarantee are unchanged from
 *     v6, and so is the honest scope statement: duplicate claims are rejected at
 *     consensus, range conformance is verified at completion, and completion remains
 *     operator-coordinated, not consensus-atomic with reservation (finding R2; the v8
 *     takeover design is what would close that).
 *
 * The v1..v6 ledgers and their ids are untouched; v7 is a fresh namespace persisted as
 * CONTRACT_V7_ID. Run like the other scripts; select it with LEDGER=v7.
 */
const path = require("path");
const { pathToFileURL } = require("url");
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, saveEnv } = require("./envStore.cjs");

const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };
const SCRIPT = { type: "array", byteArray: true, minItems: 1, maxItems: 34 };

(async () => {
  const contractUrl = pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href;
  const { poolLedgerContract } = await import(contractUrl);
  const v7 = JSON.parse(JSON.stringify(poolLedgerContract));

  // ---- carried from v3/v4/v5 (identical to registerV5.cjs / registerV6.cjs) ----
  const accrualIndex = v7.rewardAccrual.indices.find((i) => i.name === "byPoolFunder");
  accrualIndex.unique = true;
  accrualIndex.properties = [
    { poolId: "asc" }, { funderId: "asc" }, { epochHeight: "asc" }, { kind: "asc" },
  ];
  v7.rewardAccrual.properties.shareBps = {
    type: "integer", minimum: 1, maximum: 10000, position: 4,
    description: "the funder's share at distribution time, so every epoch is reconstructible",
  };
  v7.rewardAccrual.properties.kind = {
    type: "string", enum: ["reward", "principal"], maxLength: 10, position: 5,
    description: "what this accrual distributes: an epoch reward or a dissolution's principal return",
  };
  v7.rewardAccrual.required.push("shareBps", "kind");
  v7.rewardAccrual.indices.push({
    name: "byPoolHeight", properties: [{ poolId: "asc" }, { epochHeight: "asc" }],
  });
  v7.settlement = {
    type: "object", documentsMutable: true,
    properties: {
      poolId: { ...HASH32, position: 0 },
      exitId: { ...HASH32, position: 1 }, joinId: { ...HASH32, position: 2 },
      leaverId: { ...HASH32, position: 3 }, joinerId: { ...HASH32, position: 4 },
      amountDuffs: { type: "integer", minimum: 1, position: 5 },
      shareBps: { type: "integer", minimum: 1, maximum: 10000, position: 6 },
      contributionDuffs: { type: "integer", minimum: 0, position: 7 },
      phase: { type: "string", maxLength: 20, position: 8,
        enum: ["prepared", "matched", "share-deleted", "share-recreated", "settled"] },
    },
    required: ["poolId", "exitId", "joinId", "leaverId", "joinerId", "amountDuffs", "shareBps", "phase", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byExit", properties: [{ exitId: "asc" }], unique: true },
      { name: "byJoin", properties: [{ joinId: "asc" }], unique: true },
      { name: "byPoolPhase", properties: [{ poolId: "asc" }, { phase: "asc" }] },
    ],
  };
  v7.pool.properties.status = {
    type: "string", enum: ["forming", "live"], maxLength: 10, position: 5,
    description: "the pool lifecycle: forming (pledge book open, no node yet) or live (a real node backs it)",
  };
  v7.pool.required.push("status");
  v7.membershipRequest.properties.provenance = {
    type: "string", enum: ["fresh", "compound", "pledge"], maxLength: 10, position: 4,
    description: "what funded this request: new capital (fresh, the default when absent), compounded rewards, or a formation pledge",
  };
  v7.membershipRequest.properties.rewardScript = {
    ...SCRIPT, position: 5,
    description: "the member's own L1 reward script, supplied at pledge/join time so formation never derives one for them",
  };
  v7.votePreference.properties.delegateTo = {
    ...HASH32, position: 3,
    description: "with choice delegate: the member identity whose direct choice this weight follows (one hop); absent means follow the pool's leading direct choice",
  };

  // ---- new in v7: slot economics ON THE POOL (single on-ledger source of truth) ----
  v7.pool.properties.slotDuffs = {
    type: "integer", minimum: 1, position: 6,
    description: "the fixed slot size in duffs, a creation-time constant of a forming pool; absent means this pool has no slot book",
  };
  v7.pool.properties.slotCount = {
    type: "integer", minimum: 1, maximum: 10000, position: 7,
    description: "how many equal slots divide the target (slotCount * slotDuffs = target), a creation-time constant",
  };

  // ---- the v7 reservation: a claim that cannot misstate its size ----
  v7.pledgeSlot = {
    type: "object",
    // MUTABLE, and deliberately so (live finding, 2026-07-12): this SDK can only build
    // a DELETE transition for mutable document types (an immutable type's documents
    // carry no revision and the factory raises RevisionAbsentError; canBeDeleted does
    // not change that). v6's immutable claims therefore could not be cancelled at all,
    // which breaks the cancel-safety requirement; a member's exit from a
    // reservation outranks the permanent-record property. The durable record of who
    // formed the pool is the shares plus the RETAINED finalized manifest
    // (FORMATION_DONE_*, review F-C3), never the claims, and completion verifies each
    // committed claim field-by-field against its manifest snapshot precisely BECAUSE
    // claims are mutable (F-C1).
    documentsMutable: true,
    properties: {
      poolId: { ...HASH32, position: 0, description: "the forming pool this slot belongs to" },
      slotNo: { type: "integer", minimum: 0, maximum: 9999, position: 1,
        description: "which equal-size collateral slot of the pool (0..slotCount-1, bounds verified at completion against the pool's own slotCount)" },
      rewardScript: { ...SCRIPT, position: 2, description: "the pledger's own L1 reward destination" },
    },
    required: ["poolId", "slotNo", "rewardScript", "$createdAt"],
    additionalProperties: false,
    indices: [
      // ONE claim per (pool, slot): the duplicate is rejected at consensus. Range and
      // economics conformance are verified at completion against the pool's own fields.
      { name: "bySlot", properties: [{ poolId: "asc" }, { slotNo: "asc" }], unique: true },
      { name: "byPool", properties: [{ poolId: "asc" }] },
      { name: "byOwner", properties: [{ $ownerId: "asc" }, { $createdAt: "asc" }] },
    ],
  };

  const env = loadEnv();
  if (!env.MNEMONIC || !env.IDENTITY_ID) {
    console.error("run register.cjs first (need MNEMONIC, IDENTITY_ID)");
    process.exit(1);
  }
  const clientOpts = { network: process.env.NETWORK || "testnet", wallet: { mnemonic: env.MNEMONIC } };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  try {
    installConsumedFilter(await client.getWalletAccount());
    const identity = await client.platform.identities.get(env.IDENTITY_ID);
    if (env.CONTRACT_V7_ID) { console.log("v7 contract already published:", env.CONTRACT_V7_ID); return; }
    console.log("publishing the pool-ledger v7 contract ...");
    const contract = await client.platform.contracts.create(v7, identity);
    await client.platform.contracts.publish(contract, identity);
    env.CONTRACT_V7_ID = contract.getId().toString();
    saveEnv(env);
    console.log("\n=== POOL-LEDGER V7 PUBLISHED ===");
    console.log("contract id:", env.CONTRACT_V7_ID);
    console.log("(slot economics on the pool; sizeless pledgeSlot claims; run with LEDGER=v7)");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
