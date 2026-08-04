/**
 * THE SHARED RECEIPT-TO-POOL CHECK (phase B of docs/V9_MIGRATION_PLAN.md).
 *
 * Under v8 a completion receipt duplicated the pool's constants at its top level, and
 * `verifyReceiptAllocation` compared the allocation preimage's EMBEDDED target against the
 * receipt's own top-level `targetDuffs`. v9 removes those duplicated fields, because
 * duplication was itself the contradiction surface the v9 review closed. That removal has a
 * consequence: ON v9 THE EMBEDDED TARGET IS COMPARED AGAINST NOTHING unless someone compares
 * it against the POOL. Round four of the v9 review demonstrated exactly that, an internally
 * valid receipt embedding a wrong target passing the allocation verifier alone.
 *
 * So the evidence for "this pool completed" is the RECEIPT-PLUS-ITS-POOL PAIR, both
 * immutable, and this module is the one place that check lives. It owes FIVE DUTIES, and a
 * caller that performs any subset has not performed the check:
 *
 *   1. THE ALLOCATION IS VALID AND CANONICAL, with top-level poolId and participantCount
 *      correspondence. Deferred to `formationCore.verifyReceiptAllocation`, which owns the
 *      preimage format. This module does not reimplement it.
 *   2. THE EMBEDDED TARGET MATCHES THE POOL. The preimage bytes carry the manifest's target,
 *      so a receipt can be internally consistent and still describe a different pool's
 *      economics. This is the duty that only exists once the receipt stops carrying its own
 *      copy, and it is the reason this module exists at all.
 *   3. THE POOL'S OWN TARGET IS SELF-CONSISTENT: it equals its nodeType's collateral target,
 *      and where the pool carries a slot book, slotDuffs * slotCount equals it too. Without
 *      this, duty 2 only proves the receipt agrees with a pool that may itself be nonsense.
 *   4. THE RECEIPT'S slotIndex MATCHES THE POOL'S. slotIndex necessarily stays on the v9
 *      receipt because the unique bySlot index needs it, so it is the one duplicated field
 *      left and therefore the one that can still contradict.
 *   5. THE NODE HASH IS OUTSIDE THE RESERVED FORMING NAMESPACE (a soundness review). The published
 *      schema can bound only the LENGTH of proTxHash, and the completion writer refuses a
 *      reserved-prefix value, so without this duty a schema-valid receipt naming a
 *      placeholder node passes every other duty and classifies as COMPLETED. The rule is
 *      part of the stated verifier contract, not of the schema, so an implementation that
 *      reads the schema alone will not derive it.
 *
 * PLUS AN IDENTITY PRECONDITION that is not numbered in the review's list because it is
 * assumed rather than checked there: the pool passed in must BE the pool the receipt names.
 * A caller that fetched the wrong pool would otherwise get a confident answer about a
 * comparison it never made. Checked here explicitly, first.
 *
 * WHAT THIS DOES NOT PROVE, the honesty ceiling carried over from the allocation verifier.
 * A passing result means the pool COMPLETED and its record is internally coherent. It does
 * NOT mean the pool is currently active, that the masternode still exists, or that the L1
 * shares still match. Completed, currently-active and in-flight are ORTHOGONAL
 * determinations with different sources, and collapsing them into one status axis is the
 * mistake three separate v9 review rounds each killed in a different disguise.
 *
 * Every result is fail-closed: any unexpected throw on malformed input returns a refusal
 * rather than propagating, matching `verifyReceiptAllocation`'s guarantee, because these
 * inputs come off the wire.
 */
const core = require("./formationCore.cjs");
const { hasParedReceipt } = require("./envStore.cjs");

/** the collateral target a nodeType must carry, as a BigInt */
const targetForNodeType = (nodeType) =>
  (nodeType === "regular" || nodeType === "evo") ? core.TARGETS[nodeType] : null;

/** Strict duff coercion. Accepts an integer Number, a BigInt, or a base-10 string, which is
 *  the spread the ledger actually produces (the pool schema stores an integer, the
 *  allocation preimage a string). Returns null for anything else, INCLUDING a
 *  non-integer Number, so a float can never compare equal to an exact duff amount. */
const toDuffs = (v) => {
  try {
    if (typeof v === "bigint") return v;
    if (typeof v === "number") return Number.isSafeInteger(v) ? BigInt(v) : null;
    if (typeof v === "string") return /^(0|[1-9][0-9]*)$/.test(v) ? BigInt(v) : null;
    return null;
  } catch { return null; }
};

/**
 * The shared check. `receipt` and `pool` are PLAIN OBJECTS (post `toObject()`), `poolId` is
 * the pool document's own id as base58 or bytes, and `contractId` is the contract the
 * receipt must be bound to.
 * Returns { ok: true, embedded: {...} } or { ok: false, reason }.
 */
const checkReceiptAgainstPool = ({ contractId, receipt, pool, poolId }) => {
  const bad = (reason) => ({ ok: false, reason });
  try {
    if (!receipt || typeof receipt !== "object") return bad("receipt missing");
    if (!pool || typeof pool !== "object") return bad("pool missing");

    // ---- duty 1, deferred to the owner of the preimage format ----
    const alloc = core.verifyReceiptAllocation(contractId, receipt);
    if (!alloc.ok) return bad(`allocation: ${alloc.reason}`);

    // ---- identity precondition: this pool IS the pool the receipt names ----
    const namedPool = core.toId32(alloc.poolId);
    const givenPool = core.toId32(poolId);
    if (namedPool === null) return bad("the receipt's embedded poolId is not a 32-byte id");
    if (givenPool === null) return bad("the supplied poolId is not a 32-byte id");
    if (!namedPool.equals(givenPool)) {
      return bad("the supplied pool is not the pool this receipt names");
    }

    // ---- which document CARRIES the target, which is ledger-dependent ----
    // targetDuffs swaps sides at v9. Before the paring it is a RECEIPT field and the pool has
    // none, so asking a v8 pool for it would refuse every valid v8 receipt. After the paring
    // it is a POOL field and the receipt has none. The invariant being checked is identical
    // either way, so only the carrier moves.
    const pared = hasParedReceipt();
    const carrier = pared ? "pool" : "receipt";
    const carriedTarget = toDuffs(pared ? pool.targetDuffs : receipt.targetDuffs);
    if (carriedTarget === null) return bad(`${carrier} targetDuffs is not a duff amount`);

    // ---- the NODE-DOMAIN duty (a soundness review): the receipt's proTxHash must be a real node
    // identifier, meaning 32 bytes OUTSIDE the reserved forming namespace (16 leading
    // zero bytes, formationCore's application convention). The writer refuses this value
    // and validateReceiptDraft repeats the refusal, but the published schema bounds only
    // the LENGTH, so for a receipt already on the ledger this check is the only place the
    // refusal can live. Without it the classifier answers COMPLETED for a pool whose
    // "node" is a placeholder, and backingNode hands that placeholder to every reader
    // that attributes L1 activity. Applies on EVERY receipt ledger: on the flip ledgers
    // the classifier's pool-hash comparison caught it transitively, which is not the same
    // as checking it. ----
    const receiptHash = receipt.proTxHash == null ? null : Buffer.from(receipt.proTxHash);
    if (!receiptHash || receiptHash.length !== 32) {
      return bad("receipt proTxHash is missing or not 32 bytes");
    }
    if (core.isFormingHash(receiptHash)) {
      return bad("receipt proTxHash is in the reserved forming namespace, which names no real node");
    }

    // ---- duty 3 first, because duty 2 is meaningless against an incoherent pool ----
    const wantTarget = targetForNodeType(pool.nodeType);
    if (wantTarget === null) return bad(`pool nodeType "${String(pool.nodeType)}" is not regular or evo`);
    if (carriedTarget !== wantTarget) {
      return bad(`${carrier} targetDuffs ${carriedTarget} is not the ${pool.nodeType} target ${wantTarget}`);
    }
    // an UNPARED receipt carries its own nodeType, which can therefore contradict the pool's.
    // A pared one does not, and the pool is its only carrier.
    if (!pared && receipt.nodeType !== undefined && receipt.nodeType !== pool.nodeType) {
      return bad(`receipt nodeType "${String(receipt.nodeType)}" contradicts pool "${String(pool.nodeType)}"`);
    }
    const poolTarget = carriedTarget;
    // the slot book is both-or-neither at consensus; a one-sided pool is malformed here too
    const hasSlotDuffs = pool.slotDuffs != null, hasSlotCount = pool.slotCount != null;
    if (hasSlotDuffs !== hasSlotCount) return bad("pool carries a one-sided slot book");
    if (hasSlotDuffs) {
      const slotDuffs = toDuffs(pool.slotDuffs), slotCount = toDuffs(pool.slotCount);
      if (slotDuffs === null || slotCount === null) return bad("pool slot book is not integral");
      if (slotDuffs <= 0n || slotCount <= 0n) return bad("pool slot book is not positive");
      if (slotDuffs * slotCount !== poolTarget) {
        return bad(`pool slot book ${slotDuffs} * ${slotCount} does not equal targetDuffs ${poolTarget}`);
      }
    }

    // ---- duty 2, the one the pared receipt makes load-bearing ----
    // On an unpared ledger verifyReceiptAllocation already compared the embedded target
    // against the receipt's own top-level copy, so this repeats a satisfied check. On a pared
    // ledger that copy is gone and THIS is the only thing pinning the embedded target to
    // anything at all, which is the round-four finding.
    const embeddedTarget = toDuffs(alloc.targetDuffs);
    if (embeddedTarget === null) return bad("the embedded target is not a duff amount");
    if (embeddedTarget !== poolTarget) {
      return bad(`the receipt's embedded target ${embeddedTarget} contradicts ${carrier} targetDuffs ${poolTarget}`);
    }

    // ---- duty 4, the last duplicated field ----
    if (!Number.isSafeInteger(pool.slotIndex)) return bad("pool slotIndex is not an integer");
    if (!Number.isSafeInteger(receipt.slotIndex)) return bad("receipt slotIndex is not an integer");
    if (receipt.slotIndex !== pool.slotIndex) {
      return bad(`receipt slotIndex ${receipt.slotIndex} does not match pool slotIndex ${pool.slotIndex}`);
    }

    return { ok: true, embedded: alloc };
  } catch {
    // a CONSTANT reason: interpolating the caught value could itself throw
    return { ok: false, reason: "the receipt-to-pool check stopped on malformed input" };
  }
};

/**
 * Resolve MANY receipts to their pools and check each pair, with ONE batched pool fetch
 * rather than one per receipt.
 *
 * `fetchPoolsByIds(ids)` receives an array of DISTINCT pool ids, each in the form the receipt
 * carried it (a ledger-native byteArray or base58, whichever the caller's query wants), and
 * must return the matching pool documents. That is where a caller uses the `$id in [...]`
 * query form. It is injected so this module stays offline-testable and holds no transport.
 *
 * Returns one result per input receipt, in order. A receipt whose pool is missing is a
 * refusal, never a skip, because a silently dropped receipt reads downstream as a pool that
 * simply had none.
 */
const checkReceiptsAgainstPools = async ({ contractId, receipts, fetchPoolsByIds }) => {
  if (!Array.isArray(receipts)) throw new Error("receipts must be an array");
  if (typeof fetchPoolsByIds !== "function") throw new Error("fetchPoolsByIds must be a function");

  // The poolId each receipt NAMES, decoded to 32 bytes for keying but NOT yet trusted:
  // whether the fetched pool really is that pool is re-checked per pair below.
  const named = receipts.map((r) => {
    try { return core.toId32(r && r.poolId); } catch { return null; }
  });

  // dedupe by the decoded bytes, but hand the caller back the ORIGINAL id value, which is
  // the form its query wants (a ledger-native byteArray or base58, not our Buffer)
  const wanted = [];
  const seen = new Set();
  named.forEach((id, i) => {
    if (!id) return;
    const key = id.toString("hex");
    if (seen.has(key)) return;
    seen.add(key);
    wanted.push(receipts[i].poolId);
  });

  const fetched = wanted.length ? await fetchPoolsByIds(wanted) : [];
  const byId = new Map();
  for (const p of fetched || []) {
    const obj = (p && typeof p.toObject === "function") ? p.toObject() : p;
    const pid = (p && typeof p.getId === "function") ? p.getId() : (obj && obj.$id);
    const key = core.toId32(pid);
    if (key) byId.set(key.toString("hex"), { obj, poolId: pid });
  }

  return receipts.map((receipt, i) => {
    const id = named[i];
    if (!id) return { ok: false, reason: "receipt poolId is not a 32-byte id" };
    const hit = byId.get(id.toString("hex"));
    if (!hit) return { ok: false, reason: "no pool found for this receipt" };
    return checkReceiptAgainstPool({ contractId, receipt, pool: hit.obj, poolId: hit.poolId });
  });
};

/**
 * WHICH POOL BACKS THIS MASTERNODE SLOT, on a pared-receipt ledger.
 *
 * On v8 the pool records `proTxHash` and one indexed query answers this. On v9 the pool is
 * immutable and records no node at all, so the question has to be asked of the COMPLETION
 * RECEIPT, which keeps `proTxHash` precisely because its unique (proTxHash, slotIndex) index
 * is what stops two pools claiming one covenant share.
 *
 * The result is stronger than the v8 lookup rather than a workaround for a missing field: the
 * pool is reached THROUGH a verified completion record, where v8 trusted a mutable field on
 * the pool itself.
 *
 * Both fetchers are injected, so this holds no transport and is testable offline.
 * `fetchReceipts(nodeHash, slotIndex)` returns the completion receipts for that node and slot;
 * `fetchPoolById(poolId)` returns the pool document or null.
 *
 * Returns { ok, pools } or { ok: false, reason }. A receipt naming a pool that does not exist,
 * or one that does not verify, is a REFUSAL and never an empty result: an empty result reads
 * to a caller as "this node has no pool", which is how a contradiction turns into a freshly
 * minted second pool.
 */
const resolveNodeToPools = async ({ contractId, nodeHash, slotIndex, fetchReceipts, fetchPoolById }) => {
  if (typeof fetchReceipts !== "function" || typeof fetchPoolById !== "function") {
    throw new Error("resolveNodeToPools needs fetchReceipts and fetchPoolById");
  }
  const receipts = await fetchReceipts(nodeHash, slotIndex);
  if (!receipts || receipts.length === 0) return { ok: true, pools: [] };

  const pools = [];
  for (const r of receipts) {
    const ro = (r && typeof r.toObject === "function") ? r.toObject() : r;
    const poolDoc = await fetchPoolById(ro.poolId);
    if (!poolDoc) {
      return { ok: false, reason: "a completion receipt names a pool that does not exist; refusing to " +
        "distribute against an unresolvable record" };
    }
    const obj = (typeof poolDoc.toObject === "function") ? poolDoc.toObject() : poolDoc;
    const pid = (typeof poolDoc.getId === "function") ? poolDoc.getId() : obj.$id;
    const verdict = checkReceiptAgainstPool({ contractId, receipt: ro, pool: obj, poolId: pid });
    if (!verdict.ok) {
      return { ok: false, reason: `a completion receipt does not verify against its pool (${verdict.reason})` };
    }
    pools.push(poolDoc);
  }
  return { ok: true, pools };
};

module.exports = { checkReceiptAgainstPool, checkReceiptsAgainstPools, resolveNodeToPools,
  toDuffs, targetForNodeType };
