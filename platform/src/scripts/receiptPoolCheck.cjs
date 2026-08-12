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
 * immutable, and this module is the one place that check lives. It owes SIX DUTIES, and a
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
 *   6. THE SUPPLIED RECEIPT AND POOL OWNERS ARE IDENTIFIERS AND ARE EQUAL (pass 9 major 3,
 *      made mandatory by pass 10 F5, published here by pass 11 F1). On v8 pool creation is
 *      unrestricted, so a receipt written by the contract owner against a pool owned by a
 *      different identity satisfies duties 1 through 5 while the reference writer and the
 *      strict reader both refuse it. This duty was enforced in code for two passes while
 *      this list still said FIVE, which meant an independent implementation conforming to
 *      the published contract would accept exactly that pair. Checked FIRST, before duty 1,
 *      because a receipt from the wrong identity is not worth comparing further. Both
 *      owners are required, so no AFFIRMATIVE verdict is reachable without them (a caller
 *      that omits them still gets a verdict: a refusal).
 *
 *      AND HERE IS ITS TRUST BOUNDARY, stated because the pre-commit check found the
 *      earlier wording claiming past it, twice. Duty 6 establishes that the two values it
 *      COMPARED decode as 32-byte document identifiers and are equal. It does NOT establish
 *      their provenance. A caller that passes the pool's owner as both arguments gets an
 *      affirmative result while the receipt's real owner is someone else.
 *
 *      Where each compared value comes from, exactly:
 *        - `checkReceiptAgainstPool` derives NEITHER. Both are its arguments. It receives
 *          plain objects and cannot read a document owner.
 *        - `checkReceiptsAgainstPools` always takes the RECEIPT owner from the caller's
 *          `owners` entry, and takes the POOL owner from the fetched value itself when that
 *          value exposes getOwnerId(), falling back to the `owners` entry otherwise. So the
 *          categorical "this module never reads an owner" is false for that one side, and
 *          saying it that way was itself an overclaim.
 *      Sourcing the remaining values from their own documents is the CALLER'S duty,
 *      discharged and recorded at the call site. Every PRODUCTION call site in this
 *      repository does that from documents it already holds. The offline suites do not, and
 *      are not meant to: they pass fixture constants, because what they exercise is this
 *      module's comparison rather than any caller's sourcing.
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

// Platform's recognized document SYSTEM fields, always allowed alongside a contract's own
// properties. A KNOWN set, NOT any $-prefixed key: an invented $-field is a document the
// contract rejects (packet wave, folder-access review F2; the same narrowing pass 18 made for the pool
// validator, now applied to the receipt shape gate that still had the wildcard).
const SYSTEM_FIELDS = new Set(["$id", "$type", "$ownerId", "$revision", "$createdAt",
  "$updatedAt", "$transferredAt", "$createdAtBlockHeight", "$updatedAtBlockHeight",
  "$transferredAtBlockHeight", "$createdAtCoreBlockHeight", "$updatedAtCoreBlockHeight",
  "$transferredAtCoreBlockHeight", "$protocolVersion"]);

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
 * the pool document's own id as base58 or bytes (the ARGUMENT is dual-form; the receipt's
 * own poolId FIELD must be the 32-byte array the schema types, round 20), and `contractId`
 * is the contract the receipt must be bound to.
 * Returns { ok: true, embedded: {...} } or { ok: false, reason }.
 */
const checkReceiptAgainstPool = ({ contractId, receipt, pool, poolId,
  receiptOwnerId, poolOwnerId }) => {
  const bad = (reason) => ({ ok: false, reason });
  try {
    if (!receipt || typeof receipt !== "object") return bad("receipt missing");
    if (!pool || typeof pool !== "object") return bad("pool missing");

    // ---- duty 6, OWNER BINDING, UNCONDITIONAL ----
    // The spec states that owner binding establishes the pool's OWN operator recorded
    // the receipt. On v8 pool creation is unrestricted, so a receipt written by the
    // contract owner against a pool owned by someone else satisfies every other duty
    // while the reference writer and the strict reader both refuse it.
    //
    // THE HISTORY MATTERS BECAUSE IT REPEATED. The parameters were first OPTIONAL, so a
    // caller supplying neither got a silent pass having verified nothing (pass 10, F5),
    // and a static test that grepped the callers' SOURCE for the argument names was the
    // compensating control, which is no control at all. F5's repair made the duty fail
    // closed but added a DECLARATION escape: a caller could say it was unable to bind and
    // still receive ok, with a companion field recording that the binding had not
    // happened. That is the same defect wearing a label, and pass 11 F1 found it still
    // reachable and still pinned by a test. THE ESCAPE IS GONE. Both owners are required,
    // there is no opt-out to reach for, and no result field records a skipped binding,
    // because a skipped binding can no longer produce an AFFIRMATIVE result. A caller
    // without owners still gets a verdict, a refusal; an earlier draft of this comment
    // said it could obtain no verdict at all, which was false.
    //
    // THE IDENTIFIERS ARE DECODED, NOT STRINGIFIED, and that is not fussiness. A presence
    // test written as `!== undefined` admits null, the empty string, a number and a plain
    // object, and `String(a) !== String(b)` then compares their COERCIONS, so two nulls
    // bind, two `{}` bind as "[object Object]", and 1 binds to "1". That is an affirmative
    // result over a binding nobody performed, which is this duty's defect for the third
    // time in three repairs, and the pre-commit check caught it in the second draft of
    // this very fix. Decoding to the 32-byte document identifier and comparing BYTES is
    // what makes the guarantee real: it accepts the shapes the call sites hold (a base58
    // string, a Buffer, an object exposing toBuffer()) and refuses everything that does
    // not DECODE to a 32-byte identifier. Note the limit of that: decoding is structural,
    // so a duck-typed object returning the right 32 bytes is accepted, and this says
    // nothing about where the value came from. The provenance boundary is in the header.
    const rOwnerId = core.toId32(receiptOwnerId);
    const pOwnerId = core.toId32(poolOwnerId);
    if (rOwnerId === null || pOwnerId === null) {
      return bad("owner binding requires BOTH the receipt and pool document owners, each a " +
        "32-byte document identifier; this check has no unbound mode, so a caller that " +
        "cannot read them cannot obtain an affirmative verdict from it (duty 6)");
    }
    if (!rOwnerId.equals(pOwnerId)) {
      // the message says SUPPLIED, because that is what was compared. Stating it as the
      // documents' actual ownership would be a false diagnostic whenever a caller supplied
      // the wrong value, which is exactly the case this refusal fires on.
      return bad(`the supplied receipt owner ${receiptOwnerId} differs from the supplied pool ` +
        `owner ${poolOwnerId}; a receipt not written by the pool's own operator does not bind ` +
        "to it, and these two do not name one identity");
    }

    // ---- the RECEIPT IS A VALID INSTANCE OF ITS LEDGER'S SHAPE, checked before any duty
    // reasons about its content (pass 13, F1). The allocation helper checks the top-level
    // correspondences ONLY WHEN THE FIELD IS PRESENT, because it also serves draft shapes
    // that legitimately omit them, and nothing anywhere examined formatVersion,
    // l1Verification or verificationMethodVersion, so a receipt stripped of its identity
    // fields, or carrying formatVersion 99, passed every duty and classified COMPLETED.
    // Ledger callers were protected by the consensus schema, which requires every one of
    // these fields; the exported reader's own boundary was narrower than its published
    // contract, which is the same defect duty 6 had two passes ago. The sweep for the
    // shape "schema-required field the reader never examines" also found v8's nodeType
    // (checked only when present) and operatorFeeBps (never examined), so the enforcement
    // below covers the ledger shape completely rather than the three fields a reviewer
    // named. WHAT THIS GATE IS AND IS NOT: presence for every CONTRACT-DEFINED receipt
    // field the ledger's shape requires, plus the value checks the schema states as
    // consts, enums and ranges. $createdAt is schema-required too and is DELIBERATELY not
    // demanded here (pass 16, F4, a narrowing not an omission): it is SYSTEM-SUPPLIED,
    // stamped by Platform at creation, so a ledger-read document always carries it while
    // legitimate PRE-CREATE verification (the probe checks the props it is about to
    // broadcast) never can. Requiring it would refuse the pre-create half of this
    // module's real callers; exempting $-fields from the unknown-key allowlist and not
    // demanding the one $-field the schema names are the same decision applied in both
    // directions.
    // (formatVersion const 1, the three-value l1Verification enum, verificationMethodVersion
    // const 1, and on the unpared shape nodeType's enum and operatorFeeBps's 0..10000). The
    // TYPES of the byte and integer fields are checked by the duties that consume them
    // (proTxHash by a soundness-review finding, which since the closing wave requires the byte-array form and
    // refuses the string spelling, the same boundary rule as allocationHash below;
    // allocationRows and allocationHash by the allocation verifier and the byte gate below;
    // slotIndex by duty 4, targetDuffs by the carrier read), so this gate does not repeat
    // them, and an earlier comment claiming it mirrors the schema "exactly" and "completely"
    // said more than that (the pre-commit check on this fold flagged it).
    const pared0 = hasParedReceipt();
    const requiredShape = ["poolId", "proTxHash", "slotIndex", "formatVersion",
      "allocationRows", "allocationHash", "participantCount", "l1Verification",
      "verificationMethodVersion", ...(pared0 ? [] : ["nodeType", "operatorFeeBps", "targetDuffs"])];
    for (const k of requiredShape) {
      // OWN properties only. `receipt[k]` reads the prototype chain, so a direct caller
      // passing an object that INHERITS these fields would satisfy a presence test while
      // carrying none of them itself; a ledger-deserialized object is always plain, so the
      // stricter read costs nothing (pre-commit check on this fold, question 4).
      if (!Object.hasOwn(receipt, k) || receipt[k] == null) {
        return bad(`receipt is missing required field ${k}; a receipt outside its ledger's ` +
          "published shape verifies nothing, whatever its other fields say");
      }
    }
    // ...AND EVERY FIELD OUTSIDE THE SELECTED LEDGER'S SET IS REFUSED TOO (pass 14, F1).
    // The presence loop above enforced half of `additionalProperties: false` and not the
    // other half: v9's schema DELETES the three v8-only fields, so a valid v8 receipt,
    // which carries all nine shared fields plus those three, satisfied the v9 presence
    // check and verified under LEDGER=v9, an affirmative result for a document the
    // selected contract rejects. Third fold running whose gate enforced what its author
    // was looking at and not the complement stated by the same schema line.
    //
    // WRITTEN AS THE ALLOWLIST THE SCHEMA IS, not as a denylist of the three fields the
    // author was looking at, after the checker on the first draft constructed two
    // survivals a denylist admits: a forbidden field present with a null VALUE (own
    // presence is what additionalProperties forbids, whatever the value), and an
    // arbitrary property outside the schema entirely. `$`-prefixed keys are Platform
    // SYSTEM fields ($createdAt and kin), which live outside a contract's property set,
    // so they are exempt exactly as the real contract treats them.
    for (const k of Object.keys(receipt)) {
      if (SYSTEM_FIELDS.has(k)) continue;   // Platform's KNOWN system fields, not any $-key
      if (!requiredShape.includes(k)) {
        return bad(`receipt carries ${k}, which this ledger's schema does not define ` +
          "(additionalProperties: false); a receipt outside its ledger's published shape " +
          "does not verify under it, whatever its other fields say");
      }
    }
    // allocationHash is a byteArray HASH32 in the schema (packet wave, folder-access review F2). Duty 1
    // (verifyReceiptAllocation) recomputes and compares it but tolerates a hex STRING there,
    // correct for that comparison and wrong at the shape boundary: the schema forbids the
    // string form. And receipt.poolId is the SAME shape (confirm-pass round 20, major):
    // the schema types it a 32-byte array and toObject() decodes it to bytes, so a
    // base58 STRING here has no legitimate arrival form at this post-toObject boundary.
    // The earlier disposition kept it dual-form because hand-built and packet fixtures
    // pass strings, but a fixture the published contract cannot store is not an
    // alternative representation, it is a schema-invalid document, and this gate's whole
    // claim is the selected ledger's published shape. The FUNCTION ARGUMENT `poolId`
    // stays dual-form (base58 or bytes), per the module header; only the receipt FIELD
    // is bound to the schema. proTxHash's own 32-byte check is duty 5 below.
    const ah = receipt.allocationHash;
    if (!((Buffer.isBuffer(ah) || ah instanceof Uint8Array) && Buffer.from(ah).length === 32)) {
      return bad("receipt allocationHash is not a 32-byte array (the schema forbids the hex-string form)");
    }
    const rpid = receipt.poolId;
    if (!((Buffer.isBuffer(rpid) || rpid instanceof Uint8Array) && Buffer.from(rpid).length === 32)) {
      return bad("receipt poolId is not a 32-byte array (the schema forbids the base58-string form)");
    }
    if (receipt.formatVersion !== 1) {
      return bad(`receipt formatVersion ${String(receipt.formatVersion)} is not the const 1 the schema requires`);
    }
    if (!["amount-reward-verified", "node-existence-only", "demo-unverified"].includes(receipt.l1Verification)) {
      return bad(`receipt l1Verification "${String(receipt.l1Verification)}" is not in the schema's enum`);
    }
    if (receipt.verificationMethodVersion !== 1) {
      return bad(`receipt verificationMethodVersion ${String(receipt.verificationMethodVersion)} is not the const 1 the schema requires`);
    }
    if (!pared0) {
      if (!["regular", "evo"].includes(receipt.nodeType)) {
        return bad(`receipt nodeType "${String(receipt.nodeType)}" is not in the schema's enum`);
      }
      if (!(Number.isSafeInteger(receipt.operatorFeeBps)
          && receipt.operatorFeeBps >= 0 && receipt.operatorFeeBps <= 10000)) {
        return bad("receipt operatorFeeBps is not an integer in 0..10000");
      }
      // targetDuffs is a schema INTEGER on the unpared receipt (pass 18, F1). The shape
      // gate claims the receipt is a valid instance of the ledger's shape, but the target
      // carrier read below (toDuffs) accepts a base-10 STRING too, because the ledger
      // legitimately produces both a stored integer and an allocation-preimage string
      // elsewhere. That tolerance is right at the carrier read, wrong at the shape
      // boundary: the v8 schema requires an integer, so a string here is a document the
      // contract rejects, and the gate must say so rather than let the lenient carrier
      // read wave it through. (On a pared ledger the receipt has no targetDuffs; the pool
      // carries it, and the pool is not this gate's subject.)
      if (!Number.isSafeInteger(receipt.targetDuffs) || receipt.targetDuffs < 1) {
        return bad("receipt targetDuffs is not a positive integer (the v8 schema requires an integer)");
      }
    }

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
    // THE TYPE IS PART OF THE DUTY (closing wave, FA1): the schema types proTxHash as a
    // 32-byte byteArray, same as allocationHash above, and `Buffer.from(<string>)` coerces
    // a 32-CHARACTER string into 32 UTF-8 bytes that passed the length test, so a receipt
    // Platform would reject verified here. A document in hand always carries the field as
    // bytes (toObject() decodes it), so a string has no legitimate arrival form at this
    // boundary, exactly like allocationHash and receipt.poolId (round 20; only the
    // poolId function ARGUMENT is legitimately dual-form).
    const rawReceiptHash = receipt.proTxHash;
    if (rawReceiptHash == null) return bad("receipt proTxHash is missing");
    if (!(Buffer.isBuffer(rawReceiptHash) || rawReceiptHash instanceof Uint8Array)) {
      return bad("receipt proTxHash is not a byte array (the schema forbids the string form)");
    }
    const receiptHash = Buffer.from(rawReceiptHash);
    if (receiptHash.length !== 32) {
      return bad("receipt proTxHash is not 32 bytes");
    }
    if (core.isFormingHash(receiptHash)) {
      return bad("receipt proTxHash is in the reserved forming namespace, which names no real node");
    }

    // ---- the POOL IS A VALID INSTANCE OF ITS LEDGER'S SHAPE too (closing confirm-pass
    // round 5, H1: the RECEIPT side has had this gate since pass 13 and the pool side
    // never did, so a pair whose POOL the published contract rejects, a v9 pool missing
    // operatorFeeBps, carrying the v8-only fields, or typing its integers as strings,
    // verified and classified COMPLETED). Same decisions as the receipt gate: presence
    // for the contract-required fields, unknown keys refused with the KNOWN system-field
    // set exempt, the schema's types and bounds enforced at the boundary, and $createdAt
    // deliberately not demanded (system-supplied; pre-create verification legitimately
    // lacks it). ----
    const isInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && (hi === undefined || v <= hi);
    const poolShapeBad = (why) => bad(`pool ${why} (the pool is not a valid instance of this ledger's shape)`);
    {
      const known = pared0
        ? ["slotIndex", "nodeType", "operatorFeeBps", "targetDuffs", "slotDuffs", "slotCount"]
        : ["proTxHash", "slotIndex", "nodeType", "status", "operatorIdentityId",
          "operatorFeeBps", "slotDuffs", "slotCount"];
      for (const k of Object.keys(pool)) {
        if (typeof k === "string" && SYSTEM_FIELDS.has(k)) continue;
        if (!Object.prototype.hasOwnProperty.call(pool, k)) continue;
        if (!known.includes(k)) {
          return poolShapeBad(`carries ${k}, which this ledger's pool schema does not define ` +
            "(additionalProperties: false)");
        }
      }
      const required = pared0
        ? ["slotIndex", "nodeType", "operatorFeeBps", "targetDuffs"]
        : ["proTxHash", "slotIndex", "nodeType", "status"];
      for (const k of required) {
        // OWN properties only, the same rule the receipt gate states (confirm-pass round
        // 6, H1: `pool[k]` read the prototype chain, so Object.create over a valid pool,
        // which serializes with NO required fields and is not a valid ledger document,
        // passed this gate with zero own fields and classified COMPLETED)
        if (!Object.prototype.hasOwnProperty.call(pool, k)) {
          return poolShapeBad(`is missing ${k}, which its schema requires (own property, not inherited)`);
        }
      }
      if (!isInt(pool.slotIndex, 0, 31)) return poolShapeBad("slotIndex is not an integer in 0..31");
      if (!["regular", "evo"].includes(pool.nodeType)) return poolShapeBad("nodeType is not in the enum");
      if (pared0) {
        if (!isInt(pool.operatorFeeBps, 0, 10000)) return poolShapeBad("operatorFeeBps is not an integer in 0..10000");
        if (!isInt(pool.targetDuffs, 1, 400000000000)) {
          return poolShapeBad("targetDuffs is not an integer in the schema's range (the string form is not the published type)");
        }
      } else {
        if (!((Buffer.isBuffer(pool.proTxHash) || pool.proTxHash instanceof Uint8Array)
            && Buffer.from(pool.proTxHash).length === 32)) {
          return poolShapeBad("proTxHash is not a 32-byte array");
        }
        if (!["forming", "live"].includes(pool.status)) return poolShapeBad("status is not in the enum");
        // OPTIONAL fields by own-property too (confirm-pass round 7, minor: a pool whose
        // own serialized shape validly omits an optional field must not be refused over a
        // value it merely inherits, the false-refusal mirror of round 6's false pass)
        if (Object.prototype.hasOwnProperty.call(pool, "operatorIdentityId")
            && !((Buffer.isBuffer(pool.operatorIdentityId) || pool.operatorIdentityId instanceof Uint8Array)
              && Buffer.from(pool.operatorIdentityId).length === 32)) {
          return poolShapeBad("operatorIdentityId is not a 32-byte array");
        }
        if (Object.prototype.hasOwnProperty.call(pool, "operatorFeeBps")
            && !isInt(pool.operatorFeeBps, 0, 10000)) {
          return poolShapeBad("operatorFeeBps is not an integer in 0..10000");
        }
      }
      // own-property presence for the optional book too, same H1 rule. THIS REFUSAL IS
      // THE READER'S OWN COHERENCE RULE, wider than the pre-v9 contracts (confirm-pass
      // round 18, finding 2): only the v9 pool schema enforces both-or-neither
      // (dependentRequired), while the published v7/v8 schemas leave the fields
      // independently optional, so a one-sided pool can legitimately sit on those
      // ledgers. This verifier still refuses it, fail-closed, because a receipt's slot
      // claims cannot be checked against half-stated economics; the classifier reads a
      // failed check as a contradiction to resolve, never as a completion, so the
      // refusal cannot mint a wrong COMPLETED.
      const hasD = Object.prototype.hasOwnProperty.call(pool, "slotDuffs");
      const hasC = Object.prototype.hasOwnProperty.call(pool, "slotCount");
      if (hasD !== hasC) return poolShapeBad("carries a one-sided slot book (this check refuses to reason over half-stated slot economics)");
      if (hasD && !isInt(pool.slotDuffs, 1)) return poolShapeBad("slotDuffs is not a positive integer");
      // THE BOUND IS THE LEDGER THE READER READS (confirm-pass round 6, H2): the LIVE v8
      // contract is immutable and retains its published slotCount maximum of 10000
      // (contractV8.cjs header; the 512 ceiling is a SOURCE-contract tightening the
      // CLIENT enforces at create), so a reader of ON-LEDGER v8 documents must accept
      // what the live schema can hold. v9 was PUBLISHED with 512, so 512 is its real
      // bound. The first draft of this gate applied the source ceiling to v8 and refused
      // a coherent live book of 1000 slots as outside "the ledger shape", which it is not.
      const maxSlots = pared0 ? 512 : 10000;
      if (hasC && !isInt(pool.slotCount, 1, maxSlots)) {
        return poolShapeBad(`slotCount is not an integer in 1..${maxSlots}`);
      }
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
    // the slot book is both-or-neither at consensus ONLY on v9 (dependentRequired); on
    // v7/v8 a one-sided pool is schema-valid and this is the reader's own fail-closed
    // coherence rule, same ground as the shape gate above (round 18, finding 2).
    // own-property presence, same round-7 rule as the shape gate above; a null-valued own
    // book entry is still refused by the integral check below
    const hasSlotDuffs = Object.prototype.hasOwnProperty.call(pool, "slotDuffs") && pool.slotDuffs != null;
    const hasSlotCount = Object.prototype.hasOwnProperty.call(pool, "slotCount") && pool.slotCount != null;
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
    // ...and the AGREED value must sit inside the published range (closing confirm-pass,
    // must-fix): both schemas bound slotIndex 0..31, and an EQUAL pair at -1 or 32
    // satisfied the match test while naming a slot no document the contract accepts can
    // name, so the reader affirmed a pair outside the published format. Same character as
    // the manifest-range and reserve-range folds: agreement between two copies proves
    // nothing about either copy's validity. Since round 5's POOL shape gate above, the
    // pool side is refused before an equal out-of-range pair can reach here, so this
    // check is redundant BY CONSTRUCTION today and is kept deliberately: a pool-gate
    // regression must not silently reopen the agreed-out-of-range acceptance (the same
    // caught-transitively-is-not-checked rule a soundness-review finding states).
    if (receipt.slotIndex < 0 || receipt.slotIndex > 31) {
      return bad(`slotIndex ${receipt.slotIndex} is outside the schema's 0..31 range`);
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
const checkReceiptsAgainstPools = async ({ contractId, receipts, owners, fetchPoolsByIds }) => {
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
    // the pool side of duty 6 is readable here WHEN the fetched value exposes
    // getOwnerId(), so in that case it is read rather than demanded from the caller. A
    // fetcher returning plain data leaves this undefined and the caller's `owners` entry
    // supplies it. This is what the removed `hit.poolOwnerId` branch claimed and never did.
    const powner = (p && typeof p.getOwnerId === "function") ? p.getOwnerId().toString() : undefined;
    if (key) byId.set(key.toString("hex"), { obj, poolId: pid, poolOwnerId: powner });
  }

  return receipts.map((receipt, i) => {
    const id = named[i];
    if (!id) return { ok: false, reason: "receipt poolId is not a 32-byte id" };
    const hit = byId.get(id.toString("hex"));
    if (!hit) return { ok: false, reason: "no pool found for this receipt" };
    // DISPOSITION: REFUSE (Request 3). This form takes injected receipt DATA, so it
    // cannot read the receipt's owner itself and the caller must supply it. The POOL's
    // owner is taken from the fetched value above WHEN THAT VALUE EXPOSES getOwnerId();
    // a fetcher returning plain data still needs the caller's `owners` entry. Two claims
    // that stood here were wider than the code and are corrected (pass 11): a
    // `hit.poolOwnerId` that nothing ever populated, and a `receipt.getOwnerId()` branch
    // that no call site or test in this repository reaches, because every one of them
    // passes receipt DATA, which is the only shape whose `poolId` survives the decode
    // above. Whether some other document interface could reach it is not established
    // here, and the branch is removed rather than left as an untested claim. The refusal
    // is per receipt, in the same shape as every other verdict this function returns.
    const rOwner = owners && owners[i] && owners[i].receiptOwnerId;
    const pOwner = hit.poolOwnerId !== undefined
      ? hit.poolOwnerId : (owners && owners[i] && owners[i].poolOwnerId);
    if (rOwner === undefined || pOwner === undefined) {
      return { ok: false, reason: "the batched check was given records without document owners, " +
        "so the receipt's owner binding cannot be checked; supply owners, or use the " +
        "single-receipt form with both identifiers" };
    }
    return checkReceiptAgainstPool({ contractId, receipt, pool: hit.obj, poolId: hit.poolId,
      receiptOwnerId: rOwner, poolOwnerId: pOwner });
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
    // DISPOSITION: SUPPLY (Request 3). Both documents are in hand here: `r` is a receipt
    // DOCUMENT when the caller passes one, and poolDoc comes from fetchPoolById, so the
    // owners are readable and the binding is checked rather than declared away. When a
    // caller passes plain receipt DATA instead of a document, the owner is genuinely
    // unavailable and this resolution REFUSES rather than returning an affirmative
    // result over an unchecked binding, which is the global invariant.
    const rOwner = (r && typeof r.getOwnerId === "function") ? r.getOwnerId().toString() : undefined;
    const pOwner = (poolDoc && typeof poolDoc.getOwnerId === "function")
      ? poolDoc.getOwnerId().toString() : undefined;
    if (rOwner === undefined || pOwner === undefined) {
      return { ok: false, reason: "node resolution was given records without document owners, so " +
        "the receipt's owner binding cannot be checked; refusing rather than resolving a node " +
        "from a receipt that may have been written by another identity" };
    }
    const verdict = checkReceiptAgainstPool({ contractId, receipt: ro, pool: obj, poolId: pid,
      receiptOwnerId: rOwner, poolOwnerId: pOwner });
    if (!verdict.ok) {
      return { ok: false, reason: `a completion receipt does not verify against its pool (${verdict.reason})` };
    }
    pools.push(poolDoc);
  }
  return { ok: true, pools };
};

module.exports = { checkReceiptAgainstPool, checkReceiptsAgainstPools, resolveNodeToPools,
  toDuffs, targetForNodeType };
