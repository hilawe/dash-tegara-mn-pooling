/**
 * ONE ANSWER TO "WHAT STATE IS THIS POOL IN" (phase E of docs/V9_MIGRATION_PLAN.md).
 *
 * The two ledgers keep that answer in different places, and this module is the seam.
 *
 * ON v8 THE POOL DOCUMENT IS THE STATE MACHINE. `proTxHash` starts in the forming namespace
 * (a 16-zero-byte prefix) and the operator's FLIP mutates it to the real masternode hash, so
 * forming and live are readable from the pool alone.
 *
 * ON v9 THE POOL IS IMMUTABLE and carries no `proTxHash` and no `status` at all. Nothing
 * about it ever changes, so there is no flip to observe. The COMPLETION RECEIPT becomes the
 * completion record, which is what the v9 review meant by "the flip step becomes receipt
 * publication only", and a receipt only counts once it passes the shared receipt-to-pool
 * check, never on presence alone.
 *
 * WHAT NEITHER LEDGER CAN TELL YOU FROM PLATFORM DATA is whether a receipt-less pool is
 * OPEN, IN FLIGHT, or ABANDONED. Those are the same document. The operator can distinguish
 * them because it holds the local manifest and receipt draft that its own crash recovery
 * already depends on, which is why `operatorHasInFlight` is passed IN rather than inferred
 * here. Nobody else can, and the funder client's admission rule is the consequence: it fails
 * closed on a receipt-less pool rather than guessing.
 *
 * THIS IS THE SHAPE THREE v9 REVIEW ROUNDS ARRIVED AT BY ELIMINATION. A mutable poolState, an
 * immutable-terms companion, and receipt-presence-as-liveness were each killed, because
 * Platform data contracts cannot express cross-document invariants and so cannot hold a
 * liveness claim that is guaranteed not to contradict. Completed, currently-active and
 * in-flight stay ORTHOGONAL determinations with different sources. Do not collapse them into
 * one status axis; that is the mistake, wearing a new disguise.
 */
const { hasImmutablePool } = require("./envStore.cjs");
const core = require("./formationCore.cjs");
const { checkReceiptAgainstPool } = require("./receiptPoolCheck.cjs");

/** the states this module can actually distinguish, and nothing beyond them */
const STATES = {
  COMPLETED: "completed",       // a completion record exists and verifies
  FORMING: "forming",           // v8 only: the pool says so itself
  IN_FLIGHT: "in-flight",       // the OPERATOR knows, from its own local state
  UNDETERMINED: "undetermined", // receipt-less, and the caller holds no local evidence
};

/**
 * Classify one pool.
 *
 * `pool` and `receipt` are plain objects (post `toObject()`), `receipt` is null when none was
 * found, and `operatorHasInFlight` is the caller's OWN local evidence (an active manifest or
 * a frozen receipt draft). A caller with no such evidence, which is every non-operator,
 * passes false and gets UNDETERMINED rather than a guess.
 *
 * Returns { state, reason, receiptOk } and never throws: a malformed input is UNDETERMINED
 * with the reason attached, because a classifier that throws turns a readable state into an
 * outage at the call site.
 */
const classifyPool = ({ contractId, pool, poolId, receipt = null, operatorHasInFlight = false,
  receiptOwnerId, poolOwnerId }) => {
  try {
    if (!pool || typeof pool !== "object") {
      return { state: STATES.UNDETERMINED, reason: "pool missing", receiptOk: false };
    }

    // a receipt counts only when it passes the shared check, on BOTH ledgers. Raw presence
    // was explicitly killed as a predicate, and on v9 the check is the only thing pinning
    // the embedded target to the pool at all.
    let receiptOk = false, receiptReason = null;
    if (receipt) {
      // DUTY 6 IS REQUIRED HERE, and an unchecked binding is NOT a pass (Request 3,
      // criterion 6). The earlier version declared the binding unavailable and carried
      // on, which made the gap auditable without closing it: a receipt written by the
      // WRONG OPERATOR then produced a definite COMPLETED verdict, because every other
      // duty passes for such a receipt. Recording a hole is not the same as closing one.
      // classifyPool takes plain data and cannot fetch owners itself, so the caller must
      // supply them; every caller in this codebase holds both documents. Callers that
      // genuinely cannot must accept the UNDETERMINED verdict rather than a completed one.
      if (receiptOwnerId === undefined || poolOwnerId === undefined) {
        return { state: STATES.UNDETERMINED, receiptOk: false,
          reason: "the receipt's owner binding could not be checked: classifyPool was " +
            "called without the receipt and pool document owners, and a completed verdict " +
            "over an unchecked binding would report a pool whose receipt may have been " +
            "written by another identity" };
      }
      const res = checkReceiptAgainstPool({ contractId, receipt, pool, poolId,
        receiptOwnerId, poolOwnerId });
      receiptOk = res.ok === true;
      if (!receiptOk) receiptReason = res.reason;
    }
    // ON THE FLIP LEDGERS THE POOL'S OWN ASSERTION MUST AGREE (a soundness review): the
    // shared check binds the receipt to the pool's CONSTANTS, but on v8 the pool also
    // asserts the node and the lifecycle itself, and a structurally verifying receipt
    // over a still-forming pool, or over a pool live under a DIFFERENT hash, is a
    // contradiction to resolve, never a completion. The v9 pool asserts nothing here,
    // which is exactly why the five-duty check is its whole binding.
    if (receiptOk && !hasImmutablePool()) {
      const disagree = (why) => { receiptOk = false; receiptReason = why; };
      const poolHash = pool.proTxHash == null ? null : Buffer.from(pool.proTxHash);
      const receiptHash = receipt.proTxHash == null ? null : Buffer.from(receipt.proTxHash);
      if (!poolHash || poolHash.length !== 32) disagree("the pool's proTxHash is missing or malformed");
      else if (!receiptHash || receiptHash.length !== 32) disagree("the receipt's proTxHash is missing or malformed");
      else if (core.isFormingHash(poolHash)) disagree("the pool is still forming while a receipt exists");
      else if (!poolHash.equals(receiptHash)) disagree("the receipt names a different node than the live pool");
      else if (pool.status !== undefined && pool.status !== "live") disagree(`pool status is "${String(pool.status)}", not live`);
    }
    if (receiptOk) {
      return { state: STATES.COMPLETED, reason: "a completion receipt verifies against this pool", receiptOk: true };
    }
    // a receipt that FAILED the check is never treated as absent: that would silently
    // downgrade a contradiction into "not completed yet" and invite a second attempt
    if (receipt) {
      return { state: STATES.UNDETERMINED, receiptOk: false,
        reason: `a completion receipt exists but does NOT verify against this pool (${receiptReason}); ` +
          "resolve by hand rather than treating this pool as incomplete" };
    }

    if (!hasImmutablePool()) {
      // v8: the pool document answers directly
      const hash = pool.proTxHash;
      if (hash == null) {
        return { state: STATES.UNDETERMINED, reason: "the pool carries no proTxHash", receiptOk: false };
      }
      const buf = Buffer.from(hash);
      if (buf.length !== 32) {
        return { state: STATES.UNDETERMINED, reason: "the pool's proTxHash is not 32 bytes", receiptOk: false };
      }
      if (core.isFormingHash(buf)) {
        return { state: STATES.FORMING, reason: "the pool's proTxHash is in the forming namespace", receiptOk: false };
      }
      // a real hash with no verifying receipt: on v8 the flip happened, so the pool is live
      // even though nothing records the completion. That asymmetry is exactly what v9 fixes.
      return { state: STATES.IN_FLIGHT, receiptOk: false,
        reason: "the pool has flipped to a real proTxHash but no receipt verifies against it" };
    }

    // v9: immutable pool, no receipt. Only the operator's own local state can narrow this.
    if (operatorHasInFlight) {
      return { state: STATES.IN_FLIGHT, receiptOk: false,
        reason: "no verifying receipt, and this caller holds local completion state for the pool" };
    }
    return { state: STATES.UNDETERMINED, receiptOk: false,
      reason: "no verifying receipt, and this caller holds no local state; open, in flight and " +
        "abandoned are the same document on an immutable ledger" };
  } catch {
    return { state: STATES.UNDETERMINED, reason: "classification stopped on malformed input", receiptOk: false };
  }
};

/**
 * May the operator abandon its local state for this pool?
 *
 * On v8 the guard was "the pool is still forming", read from `proTxHash`. On v9 there is no
 * such field and no flip, so the equivalent question is whether a COMPLETION RECORD exists:
 * abandoning local state for a completed pool would orphan the real thing, while abandoning
 * it for a pool that never completed orphans nothing on chain, because an immutable pool with
 * no receipt claims nothing.
 *
 * NOTE the v9 pool document itself is permanent either way. It cannot be deleted, so an
 * abandoned pool stays on the ledger forever as a receipt-less pool. That is not litter to be
 * cleaned up, it is the same document an OPEN pool presents, and it is precisely why the
 * funder client's admission rule fails closed instead of trying to tell them apart.
 */
const mayAbandon = (classification) => {
  if (!classification || typeof classification !== "object") {
    return { ok: false, reason: "no classification supplied" };
  }
  if (classification.state === STATES.COMPLETED) {
    return { ok: false, reason: "the pool COMPLETED; abandoning its manifest would orphan real state" };
  }
  if (classification.receiptOk === false && /does NOT verify/.test(classification.reason || "")) {
    return { ok: false, reason: classification.reason };
  }
  return { ok: true };
};

/**
 * THE ADMISSION RULE, settled by the v9 review and implemented here verbatim.
 *
 * A member deciding whether to pledge into a pool needs to know the pool is OPEN. On v8 the
 * pool says so, through `status` or the forming namespace of `proTxHash`. On v9 it cannot: an
 * immutable pool with no completion receipt is OPEN, IN FLIGHT and ABANDONED at the same
 * time, and the member cannot see the operator's local state that would separate them.
 *
 * So the client FAILS CLOSED. Pledging into what looks like an open pool but is actually an
 * abandoned one, or one whose completion is already in flight, puts a member's collateral
 * behind a formation that will never accept it. Refusing costs a member one round trip to the
 * operator; guessing costs them the pledge.
 *
 * THE ONE EXCEPTION is the operator's explicit coordination, which the review calls the
 * advertised participate instruction. The member asserts, out of band, that this specific pool
 * was advertised to them. `TEGARA_PARTICIPATE` carries that assertion and MUST NAME THE POOL:
 * a blanket flag would be set once and then satisfy every later pledge, including one against
 * a pool the member merely discovered, which is exactly the autonomous admission the rule
 * refuses. Naming the pool means the member had to receive that id through a channel the
 * ledger does not provide.
 *
 * This is deliberately NOT a cryptographic capability. It does not prove the operator said
 * anything; it proves the member acted on something other than a document they found. That is
 * the honest limit of what a client can enforce here, and inventing a token that looks like
 * proof would be worse than stating the limit.
 *
 * A COMPLETED pool refuses regardless of any instruction, because completion is a fact on the
 * ledger rather than a judgement, and no coordination makes a finished pool joinable.
 */
const admissionVerdict = ({ classification, poolIdStr, participateEnv }) => {
  if (!classification || typeof classification !== "object") {
    return { ok: false, reason: "no classification supplied" };
  }
  if (classification.state === STATES.COMPLETED) {
    return { ok: false, reason: "this pool has COMPLETED (a receipt verifies against it); it is not open" };
  }
  if (classification.receiptOk === false && /does NOT verify/.test(classification.reason || "")) {
    return { ok: false, reason: classification.reason };
  }
  if (classification.state === STATES.FORMING) return { ok: true }; // v8 says so itself

  // v9, or anything else the ledger cannot answer
  if (participateEnv && poolIdStr && participateEnv === poolIdStr) {
    return { ok: true, viaInstruction: true };
  }
  return { ok: false, reason:
    "this ledger's pool document cannot say whether the pool is still open: an immutable pool " +
    "with no completion receipt is open, in flight, or abandoned, and they are the same " +
    "document. Refusing rather than guessing, because pledging into an abandoned or in-flight " +
    "formation strands the pledge. If the operator advertised THIS pool to you, say so " +
    `explicitly with TEGARA_PARTICIPATE=${poolIdStr || "<poolId>"}` };
};

/**
 * WHICH MASTERNODE DOES THIS POOL BACK, asked so that "we do not know" is a possible answer.
 *
 * On v8 the pool records `proTxHash` itself, so the question always has an answer once the
 * pool has flipped. On v9 the pool records no node at all and the COMPLETION RECEIPT is the
 * only document that does, so the answer exists only where a receipt VERIFIES against the
 * pool. A receipt that fails the shared check establishes nothing.
 *
 * Returns { known: true, hex } or { known: false, why }. Callers that merely DISPLAY the node
 * print the `why` instead of a blank, because a silently omitted node reads as "this pool has
 * none". Callers that ACT on the node identity, above all the vote observation, must refuse
 * when it is unknown: attributing a governance vote to a node no verified record establishes
 * is a false statement about the chain, not a cosmetic gap.
 */
const backingNode = ({ pool, receipt = null, receiptOk = false }) => {
  try {
    if (!hasImmutablePool()) {
      const h = pool && pool.proTxHash;
      if (h == null) return { known: false, why: "the pool carries no proTxHash" };
      const buf = Buffer.from(h);
      if (buf.length !== 32) return { known: false, why: "the pool's proTxHash is not 32 bytes" };
      if (core.isFormingHash(buf)) return { known: false, why: "the pool is still forming, so no node backs it yet" };
      return { known: true, hex: buf.toString("hex") };
    }
    // immutable pool: only a VERIFIED completion record names the node
    if (!receipt || !receiptOk) {
      return { known: false, why: "no completion receipt verifies against this pool, so the node it " +
        "backs is not established on the ledger" };
    }
    const h = receipt.proTxHash;
    if (h == null) return { known: false, why: "the completion receipt carries no proTxHash" };
    const buf = Buffer.from(h);
    if (buf.length !== 32) return { known: false, why: "the receipt's proTxHash is not 32 bytes" };
    // DEFENSIVE, and deliberately redundant with the shared check (a soundness review): `receiptOk`
    // arrives from the caller, so a caller that verified nothing, or verified with an
    // older check, must still not be able to turn a reserved forming-namespace value
    // into an established node here. This is the one producer of node identities, so it
    // is where the domain rule has to hold unconditionally.
    if (core.isFormingHash(buf)) {
      return { known: false, why: "the receipt's proTxHash is in the reserved forming " +
        "namespace, which names no real node" };
    }
    return { known: true, hex: buf.toString("hex") };
  } catch {
    return { known: false, why: "the backing node could not be read from malformed input" };
  }
};

/**
 * THE DESIGN INVARIANT, EXECUTABLE, AND SCOPED HONESTLY.
 *
 * Any caller about to record a statement ABOUT a node routes the identity through here, so a
 * change that lets an unestablished node reach a written document crashes on its first run
 * instead of publishing a false attribution and waiting for a review round to notice.
 *
 * WHAT THIS ENFORCES IS SHAPE, NOT PROVENANCE. It checks that the result says `known`, and
 * that the hex is a well-formed 32-byte value. It CANNOT prove the result came from
 * `backingNode` rather than being assembled by a caller, because a plain object carries no
 * evidence of its own origin. The provenance guarantee therefore rests on `backingNode` being
 * the only producer in this codebase, which is a convention this function cannot enforce, and
 * claiming otherwise would be the kind of overstatement the assertion exists to prevent.
 */
const HEX64 = /^[0-9a-f]{64}$/;
const requireBackingNode = (result, what) => {
  const bad = (why) => { throw new Error(`refusing to ${what}: ${why}`); };
  if (!result || typeof result !== "object") bad("no backing-node result supplied");
  if (result.known !== true) bad(result.why || "the backing node is unknown");
  // a 64-character string is not automatically a node id: only lowercase hex is, and a
  // caller-built result can carry any text at all
  if (typeof result.hex !== "string" || !HEX64.test(result.hex)) {
    bad("the backing node id is not a 32-byte lowercase hex value");
  }
  return result.hex;
};

module.exports = { STATES, classifyPool, mayAbandon, admissionVerdict, backingNode, requireBackingNode };
