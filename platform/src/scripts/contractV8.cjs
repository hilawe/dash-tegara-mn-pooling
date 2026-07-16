/**
 * Pure builder for the pool-ledger v8 schema, extracted VERBATIM from registerV8.cjs so
 * the construction is importable offline (the v9 builder derives from it and the schema
 * test deep-compares the two). No network, no env, no side effects.
 *
 * PRECISION on "the v8 source" vs "the live v8 contract": this builder is the canonical
 * SOURCE construction, which since the publish has folded two SOURCE-ONLY bound
 * tightenings recorded for the next version (slotCount maximum 512 and the receipt
 * targetDuffs maximum; see their inline comments). The LIVE on-chain v8 is immutable and
 * retains the looser values it was published with (slotCount 10000, minimum-only
 * targetDuffs), with the client enforcing the tighter bounds. The schema test's baseline
 * hash pins THIS SOURCE, not the ledger. Do not edit the deltas here beyond that: any
 * further change silently diverges the source from what v9 derives from and fails the
 * baseline net.
 */
const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };
const SCRIPT = { type: "array", byteArray: true, minItems: 1, maxItems: 34 };

function buildV8(poolLedgerContract) {
  const v8 = JSON.parse(JSON.stringify(poolLedgerContract));

  // ---- carried from v3/v4/v5 (identical to registerV5.cjs / registerV6.cjs) ----
  const accrualIndex = v8.rewardAccrual.indices.find((i) => i.name === "byPoolFunder");
  accrualIndex.unique = true;
  accrualIndex.properties = [
    { poolId: "asc" }, { funderId: "asc" }, { epochHeight: "asc" }, { kind: "asc" },
  ];
  v8.rewardAccrual.properties.shareBps = {
    type: "integer", minimum: 1, maximum: 10000, position: 4,
    description: "the funder's share at distribution time, so every epoch is reconstructible",
  };
  v8.rewardAccrual.properties.kind = {
    type: "string", enum: ["reward", "principal"], maxLength: 10, position: 5,
    description: "what this accrual distributes: an epoch reward or a dissolution's principal return",
  };
  v8.rewardAccrual.required.push("shareBps", "kind");
  v8.rewardAccrual.indices.push({
    name: "byPoolHeight", properties: [{ poolId: "asc" }, { epochHeight: "asc" }],
  });
  v8.settlement = {
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
  v8.pool.properties.status = {
    type: "string", enum: ["forming", "live"], maxLength: 10, position: 5,
    description: "the pool lifecycle: forming (pledge book open, no node yet) or live (a real node backs it)",
  };
  v8.pool.required.push("status");
  v8.membershipRequest.properties.provenance = {
    type: "string", enum: ["fresh", "compound", "pledge"], maxLength: 10, position: 4,
    description: "what funded this request: new capital (fresh, the default when absent), compounded rewards, or a formation pledge",
  };
  v8.membershipRequest.properties.rewardScript = {
    ...SCRIPT, position: 5,
    description: "the member's own L1 reward script, supplied at pledge/join time so formation never derives one for them",
  };
  v8.votePreference.properties.delegateTo = {
    ...HASH32, position: 3,
    description: "with choice delegate: the member identity whose direct choice this weight follows (one hop); absent means follow the pool's leading direct choice",
  };

  // ---- carried from v7: slot economics ON THE POOL + sizeless mutable claims ----
  v8.pool.properties.slotDuffs = {
    type: "integer", minimum: 1, position: 6,
    description: "the fixed slot size in duffs, a creation-time constant of a forming pool; absent means this pool has no slot book",
  };
  v8.pool.properties.slotCount = {
    // F-G re-check: the live contract keeps maximum 10000 (immutable), with the client
    // enforcing the tighter MAX_SLOT_COUNT ceiling at create; a future re-publish uses 512
    // at consensus so a legit book can never exceed the completion scan bound.
    type: "integer", minimum: 1, maximum: 512, position: 7,
    description: "how many equal slots divide the target (slotCount * slotDuffs = target), a creation-time constant",
  };
  v8.pledgeSlot = {
    type: "object",
    documentsMutable: true, // see registerV7.cjs for why (cancel-safety outranks immutability here)
    properties: {
      poolId: { ...HASH32, position: 0, description: "the forming pool this slot belongs to" },
      slotNo: { type: "integer", minimum: 0, maximum: 9999, position: 1,
        description: "which equal-size collateral slot of the pool (0..slotCount-1, bounds verified at completion against the pool's own slotCount)" },
      rewardScript: { ...SCRIPT, position: 2, description: "the pledger's own L1 reward destination" },
    },
    required: ["poolId", "slotNo", "rewardScript", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "bySlot", properties: [{ poolId: "asc" }, { slotNo: "asc" }], unique: true },
      { name: "byPool", properties: [{ poolId: "asc" }] },
      { name: "byOwner", properties: [{ $ownerId: "asc" }, { $createdAt: "asc" }] },
    ],
  };

  // ---- NEW in v8: the on-ledger completion receipt ----
  v8.completionReceipt = {
    type: "object",
    documentsMutable: false,
    canBeDeleted: false,             // immutable-evidence pattern (cast-receipt precedent)
    creationRestrictionMode: 1,      // OWNER-ONLY creation; probed live after publish
    properties: {
      poolId: { ...HASH32, position: 0,
        description: "the pool this receipt completes; one receipt per pool (unique byPool)" },
      proTxHash: { ...HASH32, position: 1,
        description: "the real L1 node hash the pool flipped to; NOT part of the allocation hash (the manifest predates registration)" },
      slotIndex: { type: "integer", minimum: 0, maximum: 31, position: 2,
        description: "the pool's L1 share mapping (which covenant share of the node this pool holds)" },
      nodeType: { type: "string", enum: ["regular", "evo"], maxLength: 10, position: 3 },
      operatorFeeBps: { type: "integer", minimum: 0, maximum: 10000, position: 4,
        description: "the completion-time operator fee, historical context" },
      formatVersion: { type: "integer", minimum: 1, maximum: 1, position: 5,
        description: "the canonical allocation form version (const 1)" },
      allocationRows: { type: "array", byteArray: true, minItems: 1, maxItems: 2048, position: 6,
        description: "the EMBEDDED canonical allocation preimage, UTF-8 JSON bytes (formationCore.allocationPreimage); self-contained third-party verification" },
      allocationHash: { ...HASH32, position: 7,
        description: "sha256 of allocationRows, the compact content id; recompute from the rows to verify" },
      participantCount: { type: "integer", minimum: 1, maximum: 8, position: 8,
        description: "DIRECT covenant participants (enforced 1..8 by formation before COMMIT); not a general Platform-allocation count" },
      // F-L: two-sided bound like every other integer field. The LIVE v8 contract is
      // immutable and predates this, so it keeps the looser minimum-only bound (defended in
      // depth by validateReceiptDraft's targetDuffs===TARGETS[nodeType] and owner-only
      // creation); this maximum applies to any future re-publish (the evo target is the max).
      targetDuffs: { type: "integer", minimum: 1, maximum: 400000000000, position: 9 },
      l1Verification: { type: "string", maxLength: 24, position: 10,
        enum: ["amount-reward-verified", "node-existence-only", "demo-unverified"],
        description: "the L1 verification level actually performed at completion (scoped; owner keys and refund scripts are the recorded residual)" },
      verificationMethodVersion: { type: "integer", minimum: 1, maximum: 1, position: 11,
        description: "the verification method version this receipt's level refers to (const 1), so a future stronger method does not re-mean old receipts" },
    },
    required: ["poolId", "proTxHash", "slotIndex", "nodeType", "operatorFeeBps", "formatVersion",
      "allocationRows", "allocationHash", "participantCount", "targetDuffs",
      "l1Verification", "verificationMethodVersion", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byPool", properties: [{ poolId: "asc" }], unique: true },
      { name: "byProTx", properties: [{ proTxHash: "asc" }] },
    ],
  };

  return v8;
}

module.exports = { buildV8, HASH32, SCRIPT };
