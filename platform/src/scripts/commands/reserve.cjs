// reserve (every ledger carrying the slot-book capability, v6 onward, which INCLUDES v8
// and v9 through the isV6/isV7 capability aliases; the header used to say "v6 or v7",
// narrower than the code, pass 7 minor 5): claim a fixed-size collateral slot of a forming pool on
// the ledger. The unique (poolId, slotNo) index means Platform REJECTS a duplicate
// claim on the same slot, so two honest clients racing for the last free slot cannot
// both win (the v5 pledge-time check could only warn). Scope (Option A, refactors
// review R1/A1): that duplicate rejection is the WHOLE consensus guarantee; slot-model
// conformance is verified at completion by formation.cjs, which refuses and attributes
// nonconforming claims. Under v7 the slot economics are read from the POOL document
// (the single on-ledger source of truth) and a claim is sizeless; under v6 the size is
// a client convention carried on each claim. `slots <poolId>` reads the claim book. A
// member may hold several slots, and cancels one with `cancel <claimId>` while the
// pool is forming.
module.exports = async (ctx) => {
  const { client, args, cmd, who, DASHfmt, short, Identifier, Dash, fetchAll, isV6, isV7,
    getPool, journal, env, activeContractId } = ctx;
  const myId = ctx.myId;
  if (!isV6()) throw new Error("the on-ledger reservation needs a ledger with the slot book (v6 or later; run the matching register script)");

  const [poolIdStr, slotArg, rewardAddressArg] = args;
  if (!poolIdStr) throw new Error(`usage: ${cmd} <poolId>${cmd === "reserve" ? " <slotNo> [rewardAddress]" : ""}`);
  const pool = await getPool(poolIdStr);
  const po = pool.toObject();
  const core = require("../formationCore.cjs");
  const target = core.TARGETS[po.nodeType];
  // WHETHER THIS POOL IS OPEN. An immutable pool carries neither `status` nor `proTxHash` and
  // cannot answer, so the admission rule decides there instead; the expression below would
  // throw on it (Buffer.from(undefined)).
  const lifecycle = require("../poolLifecycle.cjs");
  const { hasImmutablePool } = require("../envStore.cjs");
  let forming;
  let admission = { ok: true };
  // the DISPLAY label for `slots`: on v8 the pool's own state; on an immutable ledger
  // the CLASSIFIER's word, never a live/forming guess, because an admission refusal
  // does not make a pool LIVE, it makes it undetermined, and printing "LIVE" for an
  // undetermined pool is exactly the claim the classifier refuses to make (vetting
  // round, finding 7)
  let stateLabel;
  if (hasImmutablePool()) {
    const receiptDoc = (await client.platform.documents.get(
      "poolLedger.completionReceipt", { where: [["poolId", "==", pool.getId()]] }))[0] || null;
    const cls = lifecycle.classifyPool({
      contractId: activeContractId(env), pool: po, poolId: pool.getId(),
      receipt: receiptDoc ? receiptDoc.toObject() : null,
      operatorHasInFlight: false, // a member never holds the operator's local state
    });
    admission = lifecycle.admissionVerdict({
      classification: cls, poolIdStr, participateEnv: process.env.TEGARA_PARTICIPATE,
    });
    forming = admission.ok;
    stateLabel = cls.state.toUpperCase();
  } else {
    forming = po.status !== undefined ? po.status === "forming"
      : core.isFormingHash(Buffer.from(po.proTxHash));
    stateLabel = forming ? "FORMING" : "LIVE";
  }
  let slotDuffs, slotCount;
  if (isV7()) {
    // v7: the slot economics are POOL DATA, the single on-ledger source of truth
    // (review finding A1); clients read them and never choose their own
    if (!po.slotDuffs || !po.slotCount) {
      throw new Error("this pool carries no slot economics (slotDuffs/slotCount); it has no slot " +
        "book to reserve from (only v7 forming pools created with slot fields do)");
    }
    slotDuffs = journal.toBig(po.slotDuffs, "pool slot size");
    slotCount = Number(po.slotCount);
    // the admission triangle, ONE tested function (closing wave, major): the tier
    // target, the slot-book product, AND the pool's own immutable targetDuffs (v9)
    // must all agree, or the claim strands at completion against
    // requireDraftMatchesPool; pre-v9 pools carry no targetDuffs and check the
    // product alone
    core.requireCoherentSlotEconomics({ nodeType: po.nodeType,
      targetDuffs: po.targetDuffs !== undefined
        ? journal.toBig(po.targetDuffs, "pool target") : undefined,
      slotDuffs, slotCount });
  } else {
    // v6: slot size is a client convention (env override or the 100 DASH default),
    // which is exactly the A1 finding; kept only for the v6 ledger's compatibility
    slotDuffs = BigInt(process.env.SLOT_DUFFS || "10000000000"); // 100 DASH
    if (target % slotDuffs !== 0n) throw new Error(`slot size ${slotDuffs} does not divide the target ${target}`);
    slotCount = Number(target / slotDuffs);
  }

  const claims = await fetchAll(client, "poolLedger.pledgeSlot", {
    where: [["poolId", "==", pool.getId()]],
  });
  const claimed = new Map(claims.map((d) => [Number(d.toObject().slotNo), d.getOwnerId().toString()]));

  if (cmd === "slots") {
    console.log(`pool ${poolIdStr}: ${stateLabel} (${po.nodeType}), ` +
      `${slotCount} slots of ${DASHfmt(slotDuffs)} DASH`);
    console.log(`claimed: ${claimed.size} / ${slotCount}` + (claimed.size === slotCount ? "  <- FULL" : ""));
    for (let n = 0; n < slotCount; n++) {
      const owner = claimed.get(n);
      console.log(`  slot ${n}: ${owner ? `${owner}${owner === myId ? "  <- mine" : ""}` : "free"}`);
    }
    return;
  }

  if (!forming) {
    throw new Error(admission.ok
      ? "this pool is LIVE; reservations are only for forming pools"
      : admission.reason);
  }
  if (admission.viaInstruction) {
    console.log("proceeding on the operator's advertised participate instruction " +
      "(the ledger cannot confirm this pool is still open; the instruction is your evidence)");
  }
  // THE POOL'S OWNER MUST BE THE CONTRACT OPERATOR (pass 9, major 2), the same
  // admit-what-completion-refuses shape as the economics triangle and the owner bounds.
  // Completion applies this binding before it even reads the manifest, so a claim
  // against a foreign-owned pool is stranded from the moment it is made. On the
  // immutable ledger pool creation is owner-only AT CONSENSUS, so the property holds by
  // construction and the fetch is skipped; on v8 pool creation is unrestricted and the
  // check has to be made here. IT FAILS CLOSED (artifact check): an earlier draft
  // proceeded when the contract read failed, so as not to block a member on an unrelated
  // outage, but admitting an UNVERIFIED claim is exactly what this guard exists to
  // prevent and the design's admission rule is fail-closed throughout. An unreadable
  // contract means the binding is unknown, and unknown is refused with the reason named.
  if (!hasImmutablePool()) {
    let contractOwner;
    try {
      contractOwner = (await client.platform.contracts.get(activeContractId(env)))
        .getOwnerId().toString();
    } catch (e) {
      throw new Error("the contract's owner could not be read " +
        `(${(e && e.message) || e}), so this pool's operator binding cannot be checked. ` +
        "Completion refuses a pool the operator does not own, so admitting an unverified " +
        "claim here risks stranding it; refusing instead. Retry when the platform read " +
        "is healthy.");
    }
    const poolOwner = pool.getOwnerId().toString();
    if (poolOwner !== contractOwner) {
      throw new Error(`pool ${poolIdStr} is owned by ${poolOwner}, not the contract operator ` +
        `(${contractOwner}); completion refuses a pool the operator does not own, so a claim ` +
        "here could never complete. Do not reserve on this pool.");
    }
  }
  const slotNo = parseInt(slotArg, 10);
  if (!Number.isInteger(slotNo) || slotNo < 0 || slotNo >= slotCount) {
    throw new Error(`slot must be 0..${slotCount - 1}`);
  }
  if (claimed.has(slotNo)) {
    throw new Error(`slot ${slotNo} is already claimed by ${claimed.get(slotNo)} (the ledger enforces one ` +
      "claim per slot; pick a free slot from `slots`)");
  }
  // the distinct-owner bound (final pass, major 2): completion aggregates BY OWNER and
  // refuses more than eight aggregates, so admission refuses the claim that would
  // create a ninth distinct owner rather than strand it behind an uncompletable book.
  // An existing owner taking another free slot changes nothing and stays admissible.
  // SCOPE, stated precisely (the artifact check's point): this is a SEQUENTIAL
  // PREFLIGHT over a read snapshot, not an atomic bound. Two racing reservers can each
  // read seven owners and both land (the unique slot index makes them take different
  // slots), and completion's own 1..8 aggregate check remains the enforcement that
  // refuses the result. What this guard removes is the COMMON sequential path to a
  // stranded book, not the concurrent one.
  const ownersAfter = new Set([...claimed.values(), myId]).size;
  core.requireOwnerCapacity(ownersAfter);
  // the PRODUCT-MINIMUM preflight (pass 7, major 2): the claim that fills the book with
  // a single owner produces a pool completion must refuse forever, so it is refused
  // here instead. A single-owner claim with free slots left stays admissible, since the
  // second member can still arrive; only the book-closing one is refused. Sequential
  // preflight over a read snapshot, not atomic, exactly like the capacity check above.
  core.requireCompletableOwnerCount({
    distinctOwnersAfterClaim: ownersAfter,
    bookFullAfterClaim: claimed.size + 1 === slotCount,
    demo: process.env.FORMATION_ALLOW_UNVERIFIED === "demo",
  });
  // the member's own reward script (v6 carries it on the claim)
  const rewardScript = rewardAddressArg
    ? Dash.Core.Script.buildPublicKeyHashOut(rewardAddressArg).toBuffer()
    : Dash.Core.Script.buildPublicKeyHashOut((await client.getWalletAccount()).getUnusedAddress().address).toBuffer();

  const identity = await client.platform.identities.get(myId);
  // v7 claims are SIZELESS (they cannot misstate the slot value; the pool defines it);
  // v6 claims still carry the size, which completion verifies for uniformity
  const doc = await client.platform.documents.create("poolLedger.pledgeSlot", identity, {
    poolId: pool.getId().toBuffer(), slotNo,
    ...(isV7() ? {} : { slotDuffs: journal.toSafeNumber(slotDuffs, "slot size") }),
    rewardScript,
  });
  try {
    await client.platform.documents.broadcast({ create: [doc] }, identity);
  } catch (e) {
    if (/duplicate unique/i.test((e && e.message) || "")) {
      throw new Error(`slot ${slotNo} was claimed by someone else first (the ledger's unique index ` +
        "rejected this claim); pick another slot");
    }
    throw e;
  }
  console.log(`${who} reserved slot ${slotNo} of pool ${short(poolIdStr)} ` +
    `(${DASHfmt(slotDuffs)} DASH; claim ${doc.getId().toString()}, ` +
    `${isV7() ? "cancel with `cancel <claimId>` while forming" :
      "PERMANENT on v6 (the SDK cannot delete an immutable document; v7 claims are cancellable)"})`);
  const nowClaimed = claimed.size + 1;
  console.log(`claimed now: ${nowClaimed} / ${slotCount}` +
    (nowClaimed === slotCount ? "  <- FULL, the operator can complete" : ""));
};
