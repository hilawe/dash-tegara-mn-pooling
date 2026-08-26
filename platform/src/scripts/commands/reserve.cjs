// reserve (every ledger carrying on-ledger pledge slots, the pledgeSlot capability,
// v6 onward, which INCLUDES v8
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
  if (!isV6()) throw new Error("the on-ledger reservation needs a ledger with on-ledger pledge slots (v6 or later; run the matching register script)");

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
  // ONE ADMISSION PATH FOR EVERY LEDGER (closing wave, FA2): the v8 branch used to decide
  // from status/forming-hash alone and never queried the completion receipt, so a member
  // could reserve into a still-forming pool that already carried a receipt, a claim
  // `complete` refuses and the reservation strands. Both ledgers now fetch the receipt and
  // route through the SAME classifier and verdict the completion path reasons with, so the
  // two admission points cannot disagree. On v8 the classifier's own arm reads the pool's
  // status and hash (and holds a present receipt to the a soundness-review finding agreement), so nothing the
  // old branch decided is lost. The DISPLAY label is the classifier's word on both
  // ledgers, never a live/forming guess, because an admission refusal does not make a
  // pool LIVE, it makes it undetermined, and printing "LIVE" for an undetermined pool is
  // exactly the claim the classifier refuses to make (vetting round, finding 7).
  // the receipt DOCUMENT TYPE exists only on the completion-receipt ledgers (v8/v9), so
  // the query is capability-gated (closing confirm-pass, F1: the first draft of this fold
  // queried unconditionally, which broke reserve and slots on v6/v7 outright, since the
  // contract there has no such type to resolve). On the earlier ledgers the classifier
  // receives null, exactly the fact the ledger states: no receipt type, no receipt.
  const { hasCompletionReceipt, hasPledgeSlot, hasSlotBook } = require("../envStore.cjs");
  const receiptDoc = hasCompletionReceipt()
    ? (await client.platform.documents.get(
        "poolLedger.completionReceipt", { where: [["poolId", "==", pool.getId()]] }))[0] || null
    : null;
  const cls = lifecycle.classifyPool({
    contractId: activeContractId(env), pool: po, poolId: pool.getId(),
    receipt: receiptDoc ? receiptDoc.toObject() : null,
    operatorHasInFlight: false, // a member never holds the operator's local state
    // duty 6, SUPPLY: both documents are in hand (Request 3)
    receiptOwnerId: receiptDoc ? receiptDoc.getOwnerId().toString() : undefined,
    poolOwnerId: pool.getOwnerId().toString(),
  });
  const admission = lifecycle.admissionVerdict({
    classification: cls, poolIdStr, participateEnv: process.env.TEGARA_PARTICIPATE,
  });
  const stateLabel = cls.state.toUpperCase();
  // the RESERVE path refuses BEFORE the claim book is even fetched: a refused admission
  // must not reason over claims at all, and fetching them first meant the refusal
  // depended on an unrelated read succeeding. `slots` is display and continues below on
  // any pool, refused or not, printing the classifier's word.
  if (cmd !== "slots") {
    if (!admission.ok) throw new Error(admission.reason);
    if (admission.viaInstruction) {
      console.log("proceeding on the operator's advertised participate instruction " +
        "(the ledger cannot confirm this pool is still open; the instruction is your evidence)");
    }
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
    // a soundness-review finding: the v6 client-convention branch gets the same shared guard the v7+ path
    // has, which now also refuses a slot below the covenant's per-share floor
    core.requireCoherentSlotEconomics({ nodeType: po.nodeType, slotDuffs, slotCount });
  }

  // A BOOK WIDER THAN COMPLETION'S CLAIM SCAN CAN NEVER COMPLETE (a confirmation pass,
  // major): completion enumerates at most MAX_PLEDGE_CLAIMS claims and refuses a truncated
  // scan, so a full fill of a wider book is unobservable there, whatever the schema allows
  // (v6 derives the width from local SLOT_DUFFS, v7's published pools go to 10000).
  // Admitting a claim into such a book strands it, permanently on v6. One shared constant,
  // read from the same core module completion reads.
  if (slotCount > core.MAX_PLEDGE_CLAIMS) {
    throw new Error(`this pool's book has ${slotCount} slots, wider than the ` +
      `${core.MAX_PLEDGE_CLAIMS}-claim scan completion can enumerate, so a full fill can ` +
      "never be observed and every claim in it strands; do not reserve on this pool" +
      (isV7() ? "" : " (lower SLOT_DUFFS derives a wider book; align it with a completable width)"));
  }
  const claims = await fetchAll(client, "poolLedger.pledgeSlot", {
    where: [["poolId", "==", pool.getId()]],
  });
const claimed = new Map(claims.map((d) => [Number(d.toObject().slotNo), d.getOwnerId().toString()]));

  if (cmd === "slots") {
    console.log(`pool ${poolIdStr}: ${stateLabel} (${po.nodeType}), ` +
      `${slotCount} slots of ${DASHfmt(slotDuffs)} DASH`);
    console.log(`claimed: ${claimed.size} / ${slotCount}` + (claimed.size === slotCount ? "  <- FULL" : ""));
    // a soundness-review finding: show the remaining collateral before anyone reserves, so the fill state is
    // legible in money rather than only in slots. Count only IN-RANGE claimed slots, so
    // a stray out-of-range claim document cannot make the display understate what is
    // free (external artifact check on this commit: the raw claim count assumed
    // validity this display never established)
    const claimedInRange = [...claimed.keys()]
      .filter((n) => Number.isInteger(n) && n >= 0 && n < slotCount).length;
    const freeSlots = slotCount - claimedInRange;
    console.log(`remaining: ${DASHfmt(slotDuffs * BigInt(freeSlots))} DASH in ${freeSlots} free slot(s)`);
    for (let n = 0; n < slotCount; n++) {
      const owner = claimed.get(n);
      console.log(`  slot ${n}: ${owner ? `${owner}${owner === myId ? "  <- mine" : ""}` : "free"}`);
    }
    return;
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
  // EVERY FETCHED CLAIM IS VALIDATED AGAINST THIS POOL'S OWN RANGE before the RESERVE path
  // counts it
  // (pass 15, F2). The schema bounds slotNo per LEDGER (0..511 on v9) and cannot state the
  // cross-document rule that a claim's slotNo sits below its particular pool's slotCount,
  // so a schema-valid foreign claim at slot 511 on a two-slot pool is representable, and
  // this command previously COUNTED it: the owner and book-full preflights ran over the
  // unfiltered map, so admission could pass toward a book completion later refuses, the
  // exact stranded state the preflights exist to prevent. Completion refuses out-of-range
  // claims already; admission now refuses to reason over them at all rather than admitting
  // a member into a book known to be uncompletable.
  // Placed AFTER the `slots` branch DELIBERATELY (checker on this fold): `slots` is the
  // reporting command, and refusing to REPORT a book holding a foreign claim would hide
  // the very state the refusal below tells the member to resolve. Reporting shows it;
  // reserving into it refuses.
  // ON THE SIZED-CLAIM LEDGER every existing PERMANENT claim's size must equal the size
  // this run would write (a confirmation pass, D-2): v6 claims carry their own
  // slotDuffs, completion requires one uniform size across the book, and the claims are
  // immutable and undeletable, so writing a mismatched one wedges the pool permanently.
  // The size here is local configuration, which is exactly how the drift happens.
  if (hasPledgeSlot() && !hasSlotBook()) {
    for (const d of claims) {
      const existing = BigInt(d.toObject().slotDuffs);
      if (existing !== slotDuffs) {
        throw new Error(`this pool's book holds a PERMANENT claim sized ${existing} duffs by ` +
          `${d.getOwnerId().toString()}, while this run is configured for ${slotDuffs} duffs ` +
          "(SLOT_DUFFS). Completion requires one uniform slot size, and v6 claims cannot be " +
          "replaced or deleted, so writing a mismatched claim would wedge the pool " +
          "permanently; align SLOT_DUFFS with the existing book before reserving");
      }
    }
  }
  for (const d of claims) {
    const n = Number(d.toObject().slotNo);
    if (!Number.isInteger(n) || n < 0 || n >= slotCount) {
      throw new Error(`this pool's book holds a claim at slot ${String(d.toObject().slotNo)} by ` +
        `${d.getOwnerId().toString()}, outside this pool's range 0..${slotCount - 1}. Completion ` +
        "must refuse such a book, so reserving into it would strand your contribution behind an " +
        "uncompletable pool; resolve the foreign claim by hand before reserving");
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
  // a single owner produces a pool completion refuses under the non-demo operator
  // profile, so it is refused
  // here instead. A single-owner claim with free slots left stays admissible, since the
  // second member can still arrive; only the book-closing one is refused. Sequential
  // preflight over a read snapshot, not atomic, exactly like the capacity check above.
  // UNCONDITIONAL (a confirmation pass): the member's own
  // FORMATION_ALLOW_UNVERIFIED must not decide admission, because completion reads the
  // OPERATOR'S environment, and the two disagreeing admitted a one-owner full book
  // completion refuses under the non-demo operator profile
  core.requireCompletableOwnerCount({
    distinctOwnersAfterClaim: ownersAfter,
    bookFullAfterClaim: claimed.size + 1 === slotCount,
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
