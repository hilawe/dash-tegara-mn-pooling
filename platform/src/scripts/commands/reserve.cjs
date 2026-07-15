// reserve (LEDGER=v6 or v7): claim a fixed-size collateral slot of a forming pool on
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
    getPool, journal } = ctx;
  const myId = ctx.myId;
  if (!isV6()) throw new Error("the on-ledger reservation needs LEDGER=v6 or v7 (run registerV6/V7.cjs)");

  const [poolIdStr, slotArg, rewardAddressArg] = args;
  if (!poolIdStr) throw new Error(`usage: ${cmd} <poolId>${cmd === "reserve" ? " <slotNo> [rewardAddress]" : ""}`);
  const pool = await getPool(poolIdStr);
  const po = pool.toObject();
  const core = require("../formationCore.cjs");
  const target = core.TARGETS[po.nodeType];
  const forming = po.status !== undefined ? po.status === "forming"
    : core.isFormingHash(Buffer.from(po.proTxHash));
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
    if (slotDuffs * BigInt(slotCount) !== target) {
      throw new Error(`the pool's slot economics are inconsistent: ${slotCount} x ${slotDuffs} ` +
        `duffs does not equal the ${DASHfmt(target)} DASH target; do not reserve on this pool`);
    }
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
    console.log(`pool ${poolIdStr}: ${forming ? "FORMING" : "LIVE"} (${po.nodeType}), ` +
      `${slotCount} slots of ${DASHfmt(slotDuffs)} DASH`);
    console.log(`claimed: ${claimed.size} / ${slotCount}` + (claimed.size === slotCount ? "  <- FULL" : ""));
    for (let n = 0; n < slotCount; n++) {
      const owner = claimed.get(n);
      console.log(`  slot ${n}: ${owner ? `${owner}${owner === myId ? "  <- mine" : ""}` : "free"}`);
    }
    return;
  }

  if (!forming) throw new Error("this pool is LIVE; reservations are only for forming pools");
  const slotNo = parseInt(slotArg, 10);
  if (!Number.isInteger(slotNo) || slotNo < 0 || slotNo >= slotCount) {
    throw new Error(`slot must be 0..${slotCount - 1}`);
  }
  if (claimed.has(slotNo)) {
    throw new Error(`slot ${slotNo} is already claimed by ${claimed.get(slotNo)} (the ledger enforces one ` +
      "claim per slot; pick a free slot from `slots`)");
  }
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
