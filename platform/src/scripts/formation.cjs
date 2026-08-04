/**
 * Pool formation, the operator side of the waiting room (gap G5): gather member pledges
 * for a node that does not exist yet, then hand off to the covenant registration once
 * the collateral target is reached. The shared convention (forming placeholder, targets,
 * owner aggregation, weight allocation) lives in formationCore.cjs; members pledge with
 * the funder client (`pledge <poolId> <duffs>`, an ordinary cancellable join request).
 * NO funds move at pledge time; the collateral moves only inside the atomic funding
 * registration on L1 (Track B), so there is no custodial pledge window, which is
 * strictly stronger than the incumbent's flow.
 *
 * Subcommands (node src/scripts/formation.cjs <cmd> [...]):
 *   create <regular|evo> <feeBps>       operator opens a forming pool
 *   status <poolId>                     the fill report (notes a committed completion)
 *   complete <poolId> <proTxHash 64hex> drive the completion (demo mode: every pledger
 *                                       must be an identity this run controls)
 *   receipt <poolId>                    (v8) print and verify the pool's on-ledger
 *                                       completion receipt; when the pool is live
 *                                       WITHOUT one, publish it from the frozen draft
 *                                       or the retained manifest (crash recovery)
 *   abandon <poolId>                    clear a committed manifest that cannot complete
 *                                       (post-COMMIT cancellation, registration never
 *                                       happened); FORMING pools only
 *   done [prune <olderThanDays>]        list or prune the retained finalized manifests
 *
 * The completion protocol (shaped by the independent reviews, including the holistic
 * round's registration-verification requirement):
 *   1. COMMIT: aggregate the pending pledges BY OWNER, allocate weights over the exact
 *      fill, resolve each owner's reward script (the member-supplied v5 script wins,
 *      else a wallet derivation off the persistent FORMATION_ADDR_INDEX counter), and
 *      persist it all as an immutable local manifest (FORMATION_* owned env key) BEFORE
 *      any ledger mutation. Everything after drives from the manifest.
 *   2. PREFLIGHT, before any mutation: the L1 registration must VERIFY against Core
 *      (protx info via FORK_RPC_URL; the explicit FORMATION_ALLOW_UNVERIFIED=demo
 *      override prints what was not checked), every committed pledge must still exist
 *      (a post-COMMIT cancellation refuses completion; resolve and `abandon`), and
 *      every already-existing share must match the manifest field-by-field.
 *   3. SETTLE: each owner's share is created (by the owning identity) and each pledge
 *      compare-and-set settled, idempotent for resume.
 *   4. FLIP LAST: only after every share exists and the weights read back at exactly
 *      10000 bps does the operator replace the placeholder (and set status live on v5).
 *      A crash leaves a FORMING pool plus the manifest; re-running with the SAME hash
 *      resumes. After the flip the finalized manifest is RETAINED under a
 *      FORMATION_DONE_ key (review F-C3: with v7 claims mutable, it is the durable
 *      record of which claims formed the pool) and only the ACTIVE key is cleared.
 *
 * Known limits, stated rather than papered over. On v5 and earlier the pledge-time
 * overfill refusal is advisory under concurrency (two racing pledges can overfill;
 * completion then refuses with the exact list to cancel); v6's pledgeSlot reservation
 * closes exactly the duplicate-slot half of that at consensus, and slot-model
 * conformance is verified here at completion (see pendingJoinRows). COORDINATION
 * BOUNDARY (refactors review R2): completion is operator-coordinated, NOT
 * consensus-atomic with reservation or cancellation. The per-id existence check re-runs
 * immediately before each owner's share is created, so a post-COMMIT cancellation
 * refuses completion, but a cancellation landing in the seconds between that check and
 * the share broadcast is not detectable on this ledger (no cross-document conditions).
 * The kept claims mean the unique index keeps guarding slot numbers even after the pool
 * goes live, so a late claim can only land out of range, where it is inert. The
 * operator-created slot inventory that would give completion and reservation a shared
 * conflict point is the v7 design. FORMATION_HALT_AFTER=commit|shares|flip is a
 * deterministic test hook that exits at the named phase boundary so the resume path is
 * exercisable (`flip` only on ledgers that have one; an immutable-pool ledger refuses it).
 */
const crypto = require("crypto");
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { Identifier } = require("@dashevo/wasm-dpp");
const { fetchAll, fetchUpTo } = require("./query.cjs");
// F-G: bound both the LEGITIMATE slot count (enforced at pool creation) and the pledgeSlot
// claim scan. A malformed member can create up to ~10000 out-of-range slotNo claims, and an
// unbounded fetchAll would materialize them all (100s of round-trips) with a giant error
// string. MAX_SLOT_COUNT caps a legit book at creation; MAX_PLEDGE_CLAIMS is the scan
// ceiling, set ABOVE MAX_SLOT_COUNT so a full legit book plus a grief-detection window fits
// before truncation refuses (a truncated scan means far more claims than any legit book).
const MAX_SLOT_COUNT = 512;
const MAX_PLEDGE_CLAIMS = MAX_SLOT_COUNT + 128;
const { loadEnv, updateEnvKey, reserveAddrIndex, activeContractId, isV5, isV6, isV7, isV8,
  acquireOpLock, releaseOpLock, assertSupportedLedger, hasParedReceipt,
  hasImmutablePool } = require("./envStore.cjs");
const journal = require("./compoundJournal.cjs");
const lifecycle = require("./poolLifecycle.cjs");
const { checkReceiptAgainstPool } = require("./receiptPoolCheck.cjs");
const core = require("./formationCore.cjs");

const DASHfmt = (duffs) => (Number(duffs) / 100000000).toFixed(8);

(async () => {
  const env = loadEnv();
  if (!env.MNEMONIC || !env.IDENTITY_ID || !env.CONTRACT_ID) {
    console.error("run register.cjs first (need MNEMONIC, IDENTITY_ID, CONTRACT_ID)");
    process.exit(1);
  }
  // the supported set lives in envStore's version table, never in a second copy here
  try { assertSupportedLedger(); } catch (e) { console.error(e.message); process.exit(1); }
  const cmd = process.argv[2];
  const args = process.argv.slice(3);
  const HALT = process.env.FORMATION_HALT_AFTER || "";
  // `flip` names the gap between the flip and the receipt, which does not exist on an
  // immutable-pool ledger. Refuse it LOUDLY rather than ignore it (invariant list item 7):
  // a test hook that silently does nothing lets a harness setup pass vacuously.
  if (HALT === "flip" && hasImmutablePool()) {
    console.error("FORMATION_HALT_AFTER=flip names a phase boundary that does not exist on an " +
      "immutable-pool ledger (there is no flip); use commit or shares");
    process.exit(1);
  }

  if (cmd === "done") {
    // (hoisted ABOVE the Dash.Client construction: the constructor itself needs a
    // DAPI config, and housekeeping must run with none at all)
    // housekeeping over the RETAINED finalized manifests (review follow-on, review):
    // `done` lists them with ages; `done prune <days>` deletes those older, keeping
    // the .prev generation the owned-file store always leaves behind. This branch
    // runs BEFORE any wallet or Platform work: it is purely local (review finding,
    // the first version initialized the wallet and needed DAPI for offline
    // housekeeping).
    const [sub, daysStr] = args;
    // validate the arguments BEFORE any early return, so a typo is caught whether or not
    // manifests exist, and reject EXTRA arguments too (review findings: "done garbage"
    // once printed the empty message and exited 0; "done prune 30 garbage" was accepted
    // because only two args were read). Exact arity: `done` or `done prune <days>`.
    const validNoArgs = args.length === 0;
    const validPrune = args.length === 2 && sub === "prune" && /^[0-9]+$/.test(daysStr || "");
    if (!validNoArgs && !validPrune) {
      console.error("usage: done [prune <olderThanDays>]");
      process.exit(1);
    }
    const { STATE_DIR } = require("./envStore.cjs");
    const fs = require("fs");
    const entries = Object.entries(loadEnv()).filter(([k]) => k.startsWith("FORMATION_DONE_"));
    if (entries.length === 0) { console.log("no retained finalized manifests"); return; }
    const now = Date.now();
    const rows2 = entries.map(([k, v]) => {
      let poolId = "(unparseable)";
      try { poolId = JSON.parse(v).poolId; } catch { /* reported as unparseable */ }
      let ageDays = null;
      // age is the state file's mtime (multi-model review note): a `touch` during
      // troubleshooting or a metadata-stripping migration RESETS it, which only DELAYS
      // pruning (never premature deletion), so it is operationally safe and kept simple
      try { ageDays = (now - fs.statSync(`${STATE_DIR}/${k}.val`).mtimeMs) / 86400000; } catch { /* no file */ }
      return { k, poolId, ageDays };
    });
    if (sub === undefined) {
      for (const r of rows2) console.log(`${r.k}  pool ${r.poolId}` +
        (r.ageDays !== null ? `  ${r.ageDays.toFixed(1)} day(s) old`
          : "  (age unknown: no state file, the value lives in the env file)"));
      console.log(`${rows2.length} retained manifest(s); prune with: done prune <olderThanDays>`);
      return;
    }
    const cutoff = parseInt(daysStr, 10);
    let pruned = 0, unknown = 0, inflight = 0;
    for (const r of rows2) {
      // NEVER prune a DONE manifest whose matching ACTIVE manifest OR frozen DRAFT still
      // exists (round-6, extended round-7 P2): a completion writes FORMATION_DONE_ then
      // clears FORMATION_ (active) then clears RECEIPT_DRAFT_ as separate locked writes,
      // so during that window the DONE coexists with the active key and/or the draft, and
      // a legacy pre-round-6 crash could leave DONE + DRAFT with no active key, which the
      // current recovery still treats as valid input. Pruning the DONE in any of those
      // states could then let recovery clear the draft with no retained manifest, losing
      // the audit record. Hold the per-pool op lock across the check AND the delete so a
      // concurrent `receipt` cannot interleave. Keep if either sibling exists.
      const suffix = r.k.slice("FORMATION_DONE_".length);
      const activeKey = "FORMATION_" + suffix;
      const draftKey = "RECEIPT_DRAFT_" + suffix;
      let held = false;
      try {
        acquireOpLock(suffix); held = true;
      } catch (e) {
        // ONLY genuine lock contention becomes a benign mid-flight skip (round-7
        // re-check P2): a real fs error (missing dir, permissions) must propagate, not
        // masquerade as "a completion is running" and let prune exit success.
        if (!e || e.code !== "OPLOCK_CONTENDED") throw e;
        inflight += 1;
        console.log(`kept ${r.k} (pool ${r.poolId}): a completion holds this pool's operation lock, ` +
          "never pruned mid-flight");
        continue;
      }
      try {
        const now = loadEnv();
        if (now[activeKey] !== undefined || now[draftKey] !== undefined) {
          inflight += 1;
          console.log(`kept ${r.k} (pool ${r.poolId}): a completion is finalizing (its active manifest ` +
            "or frozen draft still exists), never pruned mid-flight");
        } else if (r.ageDays === null) {
          unknown += 1;
          console.log(`kept ${r.k} (pool ${r.poolId}): age unknown (no state file), never auto-pruned; ` +
            "remove by hand if genuinely stale");
        } else if (r.ageDays > cutoff) {
          updateEnvKey(r.k, undefined);
          console.log(`pruned ${r.k} (pool ${r.poolId}, ${r.ageDays.toFixed(1)} days; a .prev generation remains)`);
          pruned += 1;
        }
      } finally { if (held) releaseOpLock(suffix); }
    }
    console.log(`${pruned} pruned, ${rows2.length - pruned - unknown - inflight} kept by age` +
      (unknown > 0 ? `, ${unknown} kept for unknown age` : "") +
      (inflight > 0 ? `, ${inflight} kept mid-finalization` : ""));
    return;
  }

  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
    apps: { poolLedger: { contractId: activeContractId(env) } },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  const getPool = async (poolIdStr) => {
    const found = await client.platform.documents.get("poolLedger.pool", {
      where: [["$id", "==", Identifier.from(poolIdStr)]],
    });
    if (found.length === 0) throw new Error(`no pool ${poolIdStr} on the ledger`);
    return found[0];
  };
  // v6 draws participation from the on-ledger pledgeSlot CLAIMS; v5 and earlier read
  // pending join requests. Both map to the SAME row shape the manifest builder
  // consumes, so nothing downstream changes. Scope of the v6 guarantee (Option A of the
  // refactors review, findings R1/A1): the unique (poolId, slotNo) index rejects
  // DUPLICATE slot claims at consensus, and everything else about the slot model
  // (slotNo range, one slot size that divides the target) is verified HERE at
  // completion, with any nonconforming claim attributed loudly. Only a claim's owner
  // can delete it, so a nonconforming claim wedges the pool until they cancel (or the
  // pool is abandoned); no value moves either way, exact fill refuses first.
  const pendingJoinRows = async (poolId, po) => {
    if (isV6()) {
      const { docs: claimDocs, truncated } = await fetchUpTo(client, "poolLedger.pledgeSlot",
        MAX_PLEDGE_CLAIMS, { where: [["poolId", "==", poolId]] });
      if (truncated) {
        throw new Error(`this pool has more than ${MAX_PLEDGE_CLAIMS} pledgeSlot claims, far beyond any ` +
          "legitimate slot book; refusing to enumerate (a malformed flood of out-of-range claims). Resolve " +
          "by having the claim owners cancel, then re-run.");
      }
      const claims = claimDocs.map((d) => ({ d, o: d.toObject() }));
      let poolSize = null;
      if (claims.length > 0) {
        const target = core.TARGETS[po.nodeType];
        const describe = (c) => `claim ${c.d.getId().toString()} (slot ${c.o.slotNo}` +
          `${c.o.slotDuffs !== undefined ? `, slotDuffs ${c.o.slotDuffs}` : ""}) by ` +
          c.d.getOwnerId().toString();
        // bound the listed detail (F-G): show a handful, not the whole (possibly flooded) set
        const listSome = (arr) => arr.slice(0, 10).map(describe).join("\n  ") +
          (arr.length > 10 ? `\n  ...and ${arr.length - 10} more` : "");
        let size, slotCount;
        if (isV7()) {
          // v7: the pool's own fields are the single source of truth (A1), and a claim
          // is sizeless, so the only conformance left to verify is the slotNo range
          if (!po.slotDuffs || !po.slotCount) {
            throw new Error("this v7 pool carries no slot economics (slotDuffs/slotCount); " +
              "its slot claims cannot be interpreted, refuse completion");
          }
          size = journal.toBig(po.slotDuffs, "pool slot size");
          slotCount = Number(po.slotCount);
          if (size * BigInt(slotCount) !== target) {
            throw new Error(`the pool's slot economics are inconsistent (${slotCount} x ${size} ` +
              `duffs != the ${DASHfmt(target)} DASH target); refuse completion`);
          }
        } else {
          // v6: the size rides on each claim, so uniformity is part of conformance
          size = journal.toBig(claims[0].o.slotDuffs, "slot size");
          const uniform = claims.every((c) => journal.toBig(c.o.slotDuffs, "slot size") === size);
          if (!uniform || target % size !== 0n) {
            throw new Error("nonconforming slot claims: the pool's claims do not share one slot size " +
              `that divides the ${DASHfmt(target)} DASH target, so the slot book does not follow the ` +
              "advertised model. v6 claims are PERMANENT in this SDK (an immutable document cannot " +
              "be deleted), so the recovery is abandoning this pool and re-forming on v7 (F-C4). " +
              "The full book:\n  " + listSome(claims));
          }
          slotCount = Number(target / size);
        }
        const outOfRange = claims.filter((c) => c.o.slotNo >= slotCount);
        if (outOfRange.length > 0) {
          // the remedy differs by ledger (review F-C4): a v7 claim's owner can cancel
          // it; a v6 claim is permanent and only abandoning the pool recovers
          const remedy = isV7()
            ? "each can be deleted only by its owner (funderClient cancel <claimId>)."
            : "v6 claims are PERMANENT in this SDK; recovery is abandoning this pool and re-forming on v7.";
          throw new Error(`out-of-range slot claims (this pool has slots 0..${slotCount - 1}): ` +
            remedy + "\n  " + listSome(outOfRange));
        }
        poolSize = size;
      }
      return claims.map(({ d, o }) => ({
        id: d.getId().toString(),
        owner: d.getOwnerId().toString(),
        amount: o.slotDuffs !== undefined ? journal.toBig(o.slotDuffs, "slot size") : poolSize,
        at: Number(o.$createdAt),
        slotNo: Number(o.slotNo),
        rewardScriptHex: Buffer.from(o.rewardScript).toString("hex"),
      }));
    }
    return (await fetchAll(client, "poolLedger.membershipRequest", {
    where: [["poolId", "==", poolId], ["status", "==", "pending"]],
  })).filter((d) => d.toObject().kind === "join").map((d) => ({
    id: d.getId().toString(),
    owner: d.getOwnerId().toString(),
    amount: journal.toBig(d.toObject().amountDuffs, "pledge amount"),
    at: Number(d.toObject().$createdAt),
    // v5: the member may have supplied their own reward script at pledge time
    rewardScriptHex: d.toObject().rewardScript
      ? Buffer.from(d.toObject().rewardScript).toString("hex") : null,
  }));
  };
  const manifestKeyOf = (poolIdStr) => "FORMATION_" + journal.suffixFor(activeContractId(env), poolIdStr);

  // Deep manifest validation (re-check blocker: shallow checks let corrupt or foreign
  // intent drive mutations). Applied both to a freshly built manifest (self-check before
  // persisting) and to a loaded one (before it drives anything).
  const validateManifest = (m, poolIdStr, proTxHex, po) => {
    const fail = (why) => { throw new Error(`the completion manifest failed validation (${why}); ` +
      "restore its .val.prev generation in .env.local.state/ or remove the FORMATION_ key after verifying state by hand (a restored generation still passes this validation)"); };
    if (!m || typeof m !== "object" || Array.isArray(m) || m.v !== 1) fail("version/shape");
    if (m.poolId !== poolIdStr) fail("pool id");
    if (m.realHash !== proTxHex.toLowerCase()) {
      throw new Error(`a completion is committed under proTxHash ${m.realHash}; resume with that hash`);
    }
    if (m.target !== core.TARGETS[po.nodeType].toString()) fail("target does not match the pool's nodeType");
    if (!Array.isArray(m.owners) || m.owners.length === 0) fail("owners");
    const seenOwners = new Set(); const seenReqs = new Set();
    let amountSum = 0n, bpsSum = 0;
    // a regex cannot guarantee a 32-byte identifier (e.g. "1".repeat(40) passes base58
    // but is not one); the ONLY faithful check is the parser itself, run here so no
    // settlement mutation can ever start and then trip over a malformed id mid-loop
    // (re-check finding)
    const mustParse = (s, what) => {
      if (typeof s !== "string") fail(`${what} is not a string`);
      try { Identifier.from(s); } catch { fail(`${what} "${s}" is not a valid Platform identifier`); }
    };
    for (const o of m.owners) {
      if (!o || typeof o !== "object") fail("owner entry shape");
      mustParse(o.owner, "owner id");
      if (seenOwners.has(o.owner)) fail(`duplicate owner ${o.owner}`);
      seenOwners.add(o.owner);
      if (typeof o.amountDuffs !== "string" || !/^[1-9][0-9]*$/.test(o.amountDuffs)) fail("owner amount");
      if (!Number.isInteger(o.bps) || o.bps < 1 || o.bps > 10000) fail("owner bps");
      if (!Array.isArray(o.reqIds) || o.reqIds.length === 0) fail("owner reqIds");
      for (const r of o.reqIds) {
        mustParse(r, "request id");
        if (seenReqs.has(r)) fail(`duplicate request id ${r}`);
        seenReqs.add(r);
      }
      // even-length hex only: a {2,68} bound accepts an odd-length string and Buffer.from drops the
      // trailing half-byte, so a malformed script could pass validation a byte short (FU-3)
      if (typeof o.rewardScriptHex !== "string" || !/^([0-9a-f]{2}){1,34}$/.test(o.rewardScriptHex)) fail("reward script");
      amountSum += BigInt(o.amountDuffs); bpsSum += o.bps;
    }
    if (amountSum.toString() !== m.target) fail(`amounts sum ${amountSum}, target ${m.target}`);
    if (bpsSum !== 10000) fail(`weights sum ${bpsSum}, expected 10000`);
    // F-D: the frozen slot economics must still match the (mutable) pool document. Compared
    // against the po passed in, which the resume/pre-flip paths pass freshly fetched, so an
    // operator-credentialed change to slotDuffs/slotCount after COMMIT is caught before the
    // flip rather than silently producing a receipt that disagrees with the live slot book.
    if (m.slotDuffs !== undefined && Number(po.slotDuffs) !== m.slotDuffs) {
      fail(`slotDuffs ${po.slotDuffs} != committed ${m.slotDuffs} (the pool's slot size changed)`);
    }
    if (m.slotCount !== undefined && Number(po.slotCount) !== m.slotCount) {
      fail(`slotCount ${po.slotCount} != committed ${m.slotCount} (the pool's slot count changed)`);
    }
    // per-claim snapshots (F-C1): optional for legacy manifests, but when present they
    // must be complete (one per committed request id) and well-formed, or the manifest
    // cannot be trusted to drive the mutation-detecting preflight
    if (m.claims !== undefined) {
      if (!Array.isArray(m.claims)) fail("claims is not an array");
      const seenClaimIds = new Set();
      for (const c of m.claims) {
        if (!c || typeof c !== "object") fail("claim snapshot shape");
        mustParse(c.id, "claim id");
        if (seenClaimIds.has(c.id)) fail(`duplicate claim snapshot ${c.id}`);
        seenClaimIds.add(c.id);
        if (!seenReqs.has(c.id)) fail(`claim snapshot ${c.id} is not a committed request id`);
        mustParse(c.owner, "claim owner");
        if (c.amountDuffs !== null && (typeof c.amountDuffs !== "string" || !/^[1-9][0-9]*$/.test(c.amountDuffs))) fail("claim amount");
        if (c.slotNo !== null && (!Number.isInteger(c.slotNo) || c.slotNo < 0)) fail("claim slotNo");
        if (c.rewardScriptHex !== null && (typeof c.rewardScriptHex !== "string" || !/^([0-9a-f]{2}){1,34}$/.test(c.rewardScriptHex))) fail("claim reward script");
      }
      if (seenClaimIds.size !== seenReqs.size) fail("claim snapshots do not cover every committed request id");
      // a soundness-review finding: RELATIONALLY bind each claim to the owner allocation it belongs to. Global
      // completeness and uniqueness (above) do not prove a claim belongs to the owner whose
      // reqIds list it, nor that an owner's claim amounts sum to its allocation, so a altered
      // manifest could keep the claims internally consistent while shifting the owner split
      // (and the receipt would then commit an allocation the checked claims do not support).
      const claimById = new Map(m.claims.map((c) => [c.id, c]));
      for (const o of m.owners) {
        let claimSum = 0n, allAmounts = true;
        for (const r of o.reqIds) {
          const c = claimById.get(r);
          if (!c) fail(`owner ${o.owner} reqId ${r} has no claim snapshot`);
          if (c.owner !== o.owner) fail(`claim ${r} is owned by ${c.owner}, not the allocation owner ${o.owner}`);
          if (c.amountDuffs === null) allAmounts = false; else claimSum += BigInt(c.amountDuffs);
        }
        if (allAmounts && claimSum.toString() !== o.amountDuffs) {
          fail(`owner ${o.owner} claim amounts sum to ${claimSum} but its allocation is ${o.amountDuffs}`);
        }
      }
    }
    // v8: the receipt's participantCount is the DIRECT covenant-participant bound
    // (spec M6/C-F), so a manifest outside 1..8 owners must never COMMIT (build path,
    // the self-check before persisting) and must never drive a resume (load path).
    // This is the L1 covenant-share limit, not a general Platform-allocation limit.
    if (isV8() && (m.owners.length < 1 || m.owners.length > 8)) {
      fail(`the receipt ledgers allow 1..8 direct covenant participants, the manifest has ${m.owners.length} owners`);
    }
    // the v1 PRODUCT-TIER minimum (final pass, major 5): consensus admits 1..8, the
    // product tier is 2..8, and only the demo surface keeps the consensus width; the
    // same guard sits on the build path, and this load-path copy holds resumed
    // manifests to it too
    core.requireTierOwnerCount(m.owners.length, { demo: process.env.FORMATION_ALLOW_UNVERIFIED === "demo" });
  };

  // the per-pool OPERATION lock (review blocker): one completion-protocol command
  // (complete / receipt / abandon) per pool at a time, held for the whole command, so
  // two concurrent runs can never interleave manifest/draft writes for the same pool.
  // Released in the outer finally.
  let heldOpLock = null;
  const takePoolOpLock = (poolIdStr) => {
    const name = journal.suffixFor(activeContractId(env), poolIdStr);
    acquireOpLock(name);
    heldOpLock = name;
  };

  try {
    installConsumedFilter(await client.getWalletAccount());
    const operator = await client.platform.identities.get(env.IDENTITY_ID);

    // CONTRACT-OWNER BINDING (a soundness review): the receipt document type is creation-restricted to the
    // CONTRACT owner (creationRestrictionMode:1), a restriction Platform enforces only at
    // receipt broadcast, AFTER shares settle and the pool flips. If the executing operator
    // is not the contract owner, completion would irreversibly flip a live pool it can then
    // never write a receipt for, stranding it outside the receipt protocol (and no one else
    // can recover it, since recovery requires owning the pool). So fail LOUDLY up front, on
    // every mutating command, before any ledger write. v8 is single-operator; this turns a
    // misconfiguration into a clean refusal instead of a bricked pool.
    if (["create", "complete", "receipt", "abandon"].includes(cmd)) {
      const contract = await client.platform.contracts.get(activeContractId(env));
      if (!contract) throw new Error(`the active contract ${activeContractId(env)} is not on the ledger`);
      if (contract.getOwnerId().toString() !== operator.getId().toString()) {
        throw new Error(`this operator (${operator.getId().toString()}) does not own the pool-ledger ` +
          `contract ${activeContractId(env)} (owner ${contract.getOwnerId().toString()}); refusing, ` +
          "because only the contract owner can write completion receipts (creationRestrictionMode). " +
          "Point at your own contract, or publish one with registerV8.cjs.");
      }
    }

    // PREFLIGHT (a) as a function, the L1 REGISTRATION CHECK (holistic-round F4,
    // full): the claimed node must exist on Core AND, when it is a #187 shared
    // registration, its share table must match the manifest (participant count,
    // collateral total, amounts, and reward destinations) before any Platform settlement
    // builds on it. The one residual is the identity-to-share binding (the manifest
    // records no per-member share owner key id), documented in verifyRegistration. A
    // non-shared node exposes no share table, so the check falls back to existence-only
    // and says so. Without a Core node, it refuses unless the demo override is EXPLICIT
    // and it prints what was not verified. RETURNS the v8 receipt's scoped verification
    // level ("amount-reward-verified" | "node-existence-only" | "demo-unverified"), which
    // is why it is a function: `complete` calls it at preflight and `receipt` calls it
    // when rebuilding a lost draft from the retained manifest (spec FU-2 recovery).
    const decideL1Verification = async (proTxHex, manifest, target, poolIdStr) => {
      if (process.env.FORK_RPC_URL) {
        const { fetchCollateral, fetchShareTable } = require("./l1gov.cjs");
        let col;
        try {
          col = await fetchCollateral(proTxHex.toLowerCase());
        } catch (e) {
          throw new Error(`Core does not know masternode ${proTxHex} (${(e && e.message) || e}); ` +
            "refusing to settle a pool on an unverified registration (registration verification). The manifest is kept.");
        }
        // full registration-verification check: when the node is a #187 shared registration, verify its share
        // table (participant count, collateral total, amounts, reward destinations)
        // against the manifest, not just that the node exists. A non-shared node (vanilla
        // DIP3) exposes no share table, so fall back to the existence-only claim honestly.
        const shareTable = await fetchShareTable(proTxHex.toLowerCase());
        if (!shareTable) {
          // CROSS-VERSION FAIL-CLOSED (round-7): an ABSENT share table is ambiguous. A
          // vanilla DIP3 node genuinely has none, but a PRE-capability fork build (before
          // protx info exposed state.shares) returns the SAME empty shape for a real #187
          // shared registration, which would silently downgrade the required allocation
          // check to existence-only. So "not shared" is only a sound conclusion when the
          // operator asserts the Core build exposes shares (FORK_SHARES_CAPABLE=1). Absent
          // that assertion the node's shared-ness is UNKNOWN and completion fails closed,
          // with the explicit demo override the only way past (and it says what it skipped).
          if (process.env.FORK_SHARES_CAPABLE === "1") {
            console.log(`L1 registration verified on Core: node ${proTxHex.slice(0, 16)}... exists ` +
              `(collateral ${col.txid.slice(0, 16)}...:${col.vout}), and this share-capable build ` +
              "exposes NO #187 share table for it (not a shared registration), so amounts could not " +
              "be verified against the manifest");
            return "node-existence-only";
          }
          if (process.env.FORMATION_ALLOW_UNVERIFIED === "demo") {
            console.log(`WARNING: node ${proTxHex.slice(0, 16)}... exists but exposes no #187 share ` +
              "table, and FORK_SHARES_CAPABLE is not set, so whether it is a shared registration is " +
              "UNKNOWN (a pre-capability fork returns the same shape); proceeding under " +
              "FORMATION_ALLOW_UNVERIFIED=demo, the shared allocation is NOT checked");
            return "demo-unverified";
          }
          throw new Error(`node ${proTxHex} exists but exposes no #187 share table, and ` +
            "FORK_SHARES_CAPABLE is not set: a pre-capability Core build returns the same empty shape " +
            "for a real shared registration, so this cannot be treated as existence-only without " +
            "silently skipping the allocation check (registration verification). Set FORK_SHARES_CAPABLE=1 for a build " +
            "whose `protx info` exposes state.shares, or FORMATION_ALLOW_UNVERIFIED=demo for a known " +
            "non-shared demo node. The manifest is kept.");
        }
        // the share-capable, genuinely-shared path: verify the table against the manifest.
        // manifest side -> [{ amountDuffs, rewardAddress }], deriving the address from
        // each owner's reward script where the manifest did not already record one
        const net = process.env.NETWORK === "regtest" ? "testnet" : (process.env.NETWORK || "testnet");
        const toAddr = (o) => {
          // ALWAYS derive from rewardScriptHex, the field the RECEIPT commits to (a soundness review): the
          // stored rewardAddress is display-only and unvalidated, so trusting it could verify
          // an L1 destination different from the reward script the receipt embeds, stamping
          // amount-reward-verified on bytes that were never checked against Core.
          try {
            // Script.toAddress() returns boolean FALSE (not a throw) for a non-address
            // script, so check the value before stringifying (review finding)
            const a = Dash.Core.Script.fromBuffer(Buffer.from(o.rewardScriptHex, "hex")).toAddress(net);
            return a ? a.toString() : "(unresolved)";
          } catch { return "(unresolved)"; }
        };
        const committed = manifest.owners.map((o) => ({ amountDuffs: o.amountDuffs, rewardAddress: toAddr(o) }));
        const res = core.verifyRegistration(committed, shareTable, target.toString());
        if (res.incomparable) {
          // fail closed: a reward destination could not be resolved, so the (amount,
          // reward) pairing is unverified (review finding). The demo override is the
          // only way past, and it says what was not checked.
          if (process.env.FORMATION_ALLOW_UNVERIFIED === "demo") {
            console.log(`WARNING: L1 reward destinations could not be verified (${res.reason}); ` +
              "proceeding under FORMATION_ALLOW_UNVERIFIED=demo, the (amount, reward) pairing is NOT checked");
            return "demo-unverified";
          }
          throw new Error("L1 registration reward destinations could not be verified against the " +
            `manifest (registration verification): ${res.reason}. Refusing to settle; the manifest is kept. Set ` +
            "FORMATION_ALLOW_UNVERIFIED=demo only for a known demo registration.");
        }
        if (!res.ok) {
          throw new Error("L1 registration does NOT match the committed manifest (registration verification): " +
            res.mismatches.join("; ") + ". Refusing to settle; the manifest is kept. Resolve with " +
            "the members, then `abandon " + poolIdStr + "` and re-form.");
        }
        console.log(`L1 registration verified on Core against the manifest (registration verification): ${shareTable.length} ` +
          `share(s), ${DASHfmt(target)} DASH total, (amount, reward) pairing matches. NOTE: share owner ` +
          "keys and refund (principal) destinations are NOT recorded in the manifest, so they are " +
          "unverified (the recorded registration verification residual)");
        return "amount-reward-verified";
      }
      if (process.env.FORMATION_ALLOW_UNVERIFIED === "demo") {
        console.log("WARNING: FORMATION_ALLOW_UNVERIFIED=demo, the L1 registration is NOT verified; " +
          "this pool's on-ledger state asserts a node this run never checked (demo convention only)");
        return "demo-unverified";
      }
      throw new Error("no FORK_RPC_URL to verify the L1 registration against, and the explicit demo " +
        "override (FORMATION_ALLOW_UNVERIFIED=demo) is not set; refusing (registration verification)");
    };

    // The v8 frozen receipt draft key (spec FU-2): every receipt field, including the
    // exact allocationRows bytes and the resolved verification level, persisted after a
    // successful preflight and BEFORE the flip, so a crash-and-resume rebuilds the EXACT
    // intended receipt (never later pool values or a different verification level).
    const receiptDraftKeyOf = (poolIdStr) =>
      "RECEIPT_DRAFT_" + journal.suffixFor(activeContractId(env), poolIdStr);

    // The strong-idempotence receipt write (spec C-A, the matcher.cjs pattern, never a
    // bare query-then-create): driven entirely from the FROZEN DRAFT. Query first; if a
    // receipt exists, verify its owner and EVERY field against the draft byte-exactly
    // (allocationRows via Buffer.equals, the hash recomputed from the embedded bytes)
    // and STOP LOUDLY on any mismatch. Else create, catching ONLY the recognized
    // duplicate-unique rejection, then re-query the winner and verify the same way.
    // Returns the verified on-ledger receipt document.
    const verifyReceiptAgainstDraft = (doc, draft) => {
      const o = doc.toObject();
      const bad = [];
      if (doc.getOwnerId().toString() !== operator.getId().toString()) {
        bad.push(`owner ${doc.getOwnerId().toString()} is not the operator`);
      }
      const rows = Buffer.from(o.allocationRows);
      if (!rows.equals(Buffer.from(draft.allocationRowsHex, "hex"))) bad.push("allocationRows bytes differ");
      if (!core.allocationHash(rows).equals(Buffer.from(o.allocationHash))) {
        bad.push("on-ledger allocationHash does not match its own allocationRows");
      }
      if (!Buffer.from(o.allocationHash).equals(Buffer.from(draft.allocationHashHex, "hex"))) {
        bad.push("allocationHash differs from the draft");
      }
      if (Identifier.from(Buffer.from(o.poolId)).toString() !== draft.poolId) bad.push("poolId differs");
      if (Buffer.from(o.proTxHash).toString("hex") !== draft.proTxHash) bad.push("proTxHash differs");
      if (Number(o.slotIndex) !== draft.slotIndex) bad.push(`slotIndex ${o.slotIndex} != ${draft.slotIndex}`);
      // nodeType and targetDuffs are only ON the receipt before the paring. On v9 they live
      // on the immutable pool, so the draft is compared against the POOL instead, in
      // requireDraftMatchesPool. Reading them here on v9 would compare undefined to a real
      // value and reject every valid receipt.
      if (!hasParedReceipt() && o.nodeType !== draft.nodeType) {
        bad.push(`nodeType ${o.nodeType} != ${draft.nodeType}`);
      }
      // operatorFeeBps (F-I, re-scoped by a soundness-review finding): the fee is compared WHEN THE DRAFT IS
      // THE ORIGINAL FREEZE, and only then. An original draft records the completion-time
      // fee, so a receipt naming a different fee contradicts the frozen truth and the
      // every-field claim of spec C-A must hold for it. A draft REBUILT from the manifest
      // on resume sources the CURRENT pool fee instead, which on a flipped v8 pool may
      // legitimately have drifted since completion, so comparing that one would falsely
      // reject a valid immutable receipt. The origin is carried as a non-enumerable
      // marker, so it can never leak into the persisted draft JSON.
      // ...and only on the ledgers whose RECEIPT carries a fee at all: the pared v9
      // receipt drops operatorFeeBps entirely (the immutable pool pins it), where the
      // draft-to-pool comparison with requireFee is the check instead.
      if (!hasParedReceipt() && draft.__origin === "frozen"
          && Number(o.operatorFeeBps) !== Number(draft.operatorFeeBps)) {
        bad.push(`operatorFeeBps ${Number(o.operatorFeeBps)} != frozen draft ${Number(draft.operatorFeeBps)}`);
      }
      if (Number(o.formatVersion) !== 1) bad.push("formatVersion is not 1");
      if (Number(o.participantCount) !== draft.participantCount) bad.push("participantCount differs");
      if (!hasParedReceipt() && Number(o.targetDuffs) !== draft.targetDuffs) bad.push("targetDuffs differs");
      if (o.l1Verification !== draft.l1Verification) {
        bad.push(`l1Verification "${o.l1Verification}" != draft "${draft.l1Verification}"`);
      }
      if (Number(o.verificationMethodVersion) !== 1) bad.push("verificationMethodVersion is not 1");
      if (bad.length > 0) {
        throw new Error("an existing completionReceipt for this pool CONTRADICTS the frozen draft: " +
          bad.join("; ") + ". Refusing to continue; the manifest and draft are kept, resolve by hand " +
          "(never log-and-skip a mismatched receipt).");
      }
    };
    const writeReceiptIdempotent = async (pool, poolIdStr, draft) => {
      const queryReceipt = async () => (await client.platform.documents.get(
        "poolLedger.completionReceipt", { where: [["poolId", "==", pool.getId()]] }))[0] || null;
      let doc = await queryReceipt();
      if (doc) {
        verifyReceiptAgainstDraft(doc, draft);
        requireReceiptBindsPool(doc.toObject(), (await getPool(poolIdStr)).toObject(), poolIdStr); // round-6: fresh pool bind
        console.log(`completion receipt already recorded (${doc.getId().toString()}), matches the draft and pool`);
        return doc;
      }
      // build the receipt FIRST (documents.create awaits SDK init and the contract
      // fetch internally), THEN re-fetch the FULL pool immediately before broadcast and
      // require it to match the draft on EVERY draft-sourced field (round-4 blocker: the
      // old check read only proTxHash and ran before create's awaits, so an external
      // writer holding operator credentials could change a field, or the hash, inside
      // that window and the immutable receipt would then contradict the pool). The op
      // lock serializes only the three formation commands; a genuinely external writer
      // between this check and consensus inclusion cannot be excluded, because Platform
      // caps a batch at one transition so a condition-flip-and-create is not atomic. That
      // residual is documented, not silently ignored.
      const receipt = await client.platform.documents.create(
        "poolLedger.completionReceipt", operator, receiptPropertiesFromDraft(pool, draft));
      const preBroadcast = (await getPool(poolIdStr)).toObject();
      if (!hasImmutablePool()) {
        // v8: the pool asserts a node itself, so a receipt naming a different one would
        // contradict it. The v9 pool asserts none (invariant list item 8), so this gate's
        // subject does not exist there and the binding that remains is the draft-to-pool
        // constants check below.
        const liveNow = Buffer.from(preBroadcast.proTxHash);
        if (core.isFormingHash(liveNow) || liveNow.toString("hex") !== draft.proTxHash) {
          throw new Error(`the pool is ${core.isFormingHash(liveNow) ? "still FORMING" :
            `live under ${liveNow.toString("hex")}`}, not live under the draft's ` +
            `${draft.proTxHash}; refusing to record a receipt that contradicts the pool ` +
            "(the draft and manifest are kept, resolve by hand)");
        }
        if (preBroadcast.status !== undefined && preBroadcast.status !== "live") {
          throw new Error(`the pool status is "${preBroadcast.status}", not live, immediately before ` +
            "the receipt broadcast; refusing (the draft and manifest are kept, resolve by hand)");
        }
      }
      // slot/node/target vs the fresh pool. The fee context differs by ledger (invariant
      // list item 5): on v8 it is historical here (post-flip, legitimately mutable), on an
      // immutable pool it cannot have drifted, so requiring it costs nothing and a mismatch
      // means the DRAFT is damaged.
      requireDraftMatchesPool(draft, preBroadcast, { requireFee: hasImmutablePool() });
      try {
        await client.platform.documents.broadcast({ create: [receipt] }, operator);
        console.log(`completion receipt created: ${receipt.getId().toString()}`);
      } catch (e) {
        if (!/duplicate unique/i.test((e && e.message) || "")) throw e;
        console.log("a receipt for this pool was created concurrently; verifying the winner");
      }
      doc = await queryReceipt();
      if (!doc) {
        throw new Error("the receipt broadcast went out but the receipt is not queryable yet; " +
          "the manifest and draft are KEPT, re-run to verify (never assume the write landed)");
      }
      verifyReceiptAgainstDraft(doc, draft);
      requireReceiptBindsPool(doc.toObject(), (await getPool(poolIdStr)).toObject(), poolIdStr); // round-6: fresh pool bind
      return doc;
    };

    // v8 OWNER BINDING (spec M1/C-D, the client-side half; review blocker): the
    // creationRestrictionMode proves the receipt creator is the CONTRACT owner, but not
    // that the referenced pool is that owner's (the inherited pool type allows creation
    // by other identities). The pool's IMMUTABLE $ownerId must equal the executing
    // operator BEFORE any completion mutation or receipt write, or the operator could
    // occupy a foreign pool's unique receipt slot.
    const requirePoolOwnedByOperator = (pool, poolIdStr) => {
      if (pool.getOwnerId().toString() !== operator.getId().toString()) {
        throw new Error(`pool ${poolIdStr} is owned by ${pool.getOwnerId().toString()}, not this ` +
          `operator (${operator.getId().toString()}); refusing to complete or record a receipt for ` +
          "a pool this identity does not own (M1 owner binding)");
      }
    };

    // one construction for the receipt's document properties, used by BOTH the mixed
    // probe and the sequential writer so the two can never drift (review, lens 2)
    // On a PARED-RECEIPT ledger (v9) the three fields the immutable pool already pins are
    // omitted: emitting them would be schema-rejected, and their duplication was the
    // contradiction surface the v9 review closed. slotIndex STAYS on both shapes because the
    // unique bySlot index needs it, which is why it is the one duplicated field left and the
    // one the shared receipt-to-pool check still has to compare.
    const receiptPropertiesFromDraft = (pool, draft) => ({
      poolId: pool.getId().toBuffer(),
      proTxHash: Buffer.from(draft.proTxHash, "hex"),
      slotIndex: draft.slotIndex,
      ...(hasParedReceipt() ? {} : {
        nodeType: draft.nodeType,
        operatorFeeBps: draft.operatorFeeBps,
        targetDuffs: draft.targetDuffs,
      }),
      formatVersion: 1,
      allocationRows: Buffer.from(draft.allocationRowsHex, "hex"),
      allocationHash: Buffer.from(draft.allocationHashHex, "hex"),
      participantCount: draft.participantCount,
      l1Verification: draft.l1Verification, verificationMethodVersion: 1,
    });

    // FAIL-CLOSED draft validation (review major): a loaded or rebuilt draft drives an
    // IMMUTABLE write, so a parseable-but-damaged draft must never reach the broadcast.
    // Shape, bounds, and enums first; then the trusted verifyReceiptAllocation over the
    // embedded bytes (canonical form, hash, contract binding, top-level correspondence);
    // then, when the frozen manifest is at hand, every derivable field against it.
    const validateReceiptDraft = (draft, poolIdStr, manifest) => {
      const fail = (why) => { throw new Error(`the frozen receipt draft failed validation (${why}); ` +
        "restore its .val.prev generation in .env.local.state/ or remove the RECEIPT_DRAFT_ key after verifying state by hand (a restored generation still passes full draft validation and the pool comparison)"); };
      if (!draft || typeof draft !== "object" || Array.isArray(draft) || draft.v !== 1) fail("version/shape");
      if (draft.poolId !== poolIdStr) fail("pool id");
      if (typeof draft.proTxHash !== "string" || !/^([0-9a-f]{2}){32}$/.test(draft.proTxHash)) fail("proTxHash");
      if (core.isFormingHash(Buffer.from(draft.proTxHash, "hex"))) fail("proTxHash is in the forming namespace");
      if (!Number.isInteger(draft.slotIndex) || draft.slotIndex < 0 || draft.slotIndex > 31) fail("slotIndex");
      if (!core.TARGETS[draft.nodeType]) fail("nodeType");
      if (!Number.isInteger(draft.operatorFeeBps) || draft.operatorFeeBps < 0 || draft.operatorFeeBps > 10000) fail("operatorFeeBps");
      if (draft.formatVersion !== 1 || draft.verificationMethodVersion !== 1) fail("format/method version");
      if (!Number.isInteger(draft.participantCount) || draft.participantCount < 1 || draft.participantCount > 8) fail("participantCount");
      if (!Number.isSafeInteger(draft.targetDuffs) || draft.targetDuffs < 1) fail("targetDuffs");
      // the nodeType-target INVARIANT (follow-up review): both fields being individually
      // valid does not make them consistent; a draft edited from regular to evo would
      // otherwise keep the 1000-DASH target and become an internally contradictory
      // immutable receipt
      if (String(core.TARGETS[draft.nodeType]) !== String(draft.targetDuffs)) {
        fail(`targetDuffs ${draft.targetDuffs} is not the ${draft.nodeType} target ${core.TARGETS[draft.nodeType]}`);
      }
      if (!["amount-reward-verified", "node-existence-only", "demo-unverified"].includes(draft.l1Verification)) fail("l1Verification");
      if (typeof draft.allocationRowsHex !== "string" || !/^([0-9a-f]{2})+$/.test(draft.allocationRowsHex)) fail("allocationRowsHex");
      if (typeof draft.allocationHashHex !== "string" || !/^[0-9a-f]{64}$/.test(draft.allocationHashHex)) fail("allocationHashHex");
      const check = core.verifyReceiptAllocation(activeContractId(env), {
        allocationRows: Buffer.from(draft.allocationRowsHex, "hex"),
        allocationHash: Buffer.from(draft.allocationHashHex, "hex"),
        poolId: draft.poolId, targetDuffs: String(draft.targetDuffs),
        participantCount: draft.participantCount,
      });
      if (!check.ok) fail(`embedded allocation: ${check.reason}`);
      if (manifest) {
        const rows = core.allocationPreimage(activeContractId(env), manifest);
        if (draft.allocationRowsHex !== rows.toString("hex")) fail("allocationRows contradict the committed manifest");
        if (draft.proTxHash !== manifest.realHash) fail("proTxHash contradicts the committed manifest");
        if (draft.participantCount !== manifest.owners.length) fail("participantCount contradicts the manifest");
        if (String(draft.targetDuffs) !== manifest.target) fail("targetDuffs contradicts the manifest");
      }
    };

    // the draft's pool-sourced fields against the pool document itself (follow-up
    // review): the draft froze slot/node/fee from the pool at preflight time, so a
    // divergence later means either the draft or the pool document was altered, and
    // an immutable receipt must not be written from either uncertainty
    // slotIndex/nodeType are pool CREATION constants and must always match the draft.
    // The operator FEE is CONTEXT-DEPENDENT (round-6 re-check): while the pool is still
    // FORMING the draft's fee must equal the pool's, because the receipt records the
    // completion-time fee and a pre-flip drift would freeze a stale value into the
    // immutable receipt. Once the pool is LIVE (post-flip recovery, readback), the pool
    // fee is legitimately mutable and a difference is historical, not a contradiction.
    // The caller states which context it is in via requireFee.
    const requireDraftMatchesPool = (draft, po, { requireFee } = {}) => {
      const bad = [];
      if (draft.slotIndex !== Number(po.slotIndex)) bad.push(`slotIndex ${draft.slotIndex} != pool ${po.slotIndex}`);
      if (draft.nodeType !== po.nodeType) bad.push(`nodeType ${draft.nodeType} != pool ${po.nodeType}`);
      // THE v9 TARGET COMPARISON. targetDuffs swaps sides at v9: before the paring it is a
      // receipt field and verifyReceiptAgainstDraft compares it to the draft, while the pool
      // carries none. On v9 the pool carries it and the receipt does not, so without this
      // the draft's target would be pinned against nothing and a drifted draft could freeze
      // a wrong target into the allocation preimage of an immutable receipt.
      if (hasParedReceipt()) {
        if (po.targetDuffs === undefined || po.targetDuffs === null) {
          bad.push("the pool carries no targetDuffs, which a pared-receipt ledger requires");
        } else if (Number(draft.targetDuffs) !== Number(po.targetDuffs)) {
          bad.push(`targetDuffs ${draft.targetDuffs} != pool ${po.targetDuffs}`);
        }
      }
      if (requireFee && draft.operatorFeeBps !== Number(po.operatorFeeBps || 0)) {
        bad.push(`operatorFeeBps ${draft.operatorFeeBps} != pool ${Number(po.operatorFeeBps || 0)} ` +
          "(the fee changed before the flip; the receipt must record the completion-time fee)");
      }
      if (bad.length > 0) {
        throw new Error("the frozen receipt draft CONTRADICTS the pool document: " + bad.join("; ") +
          ". Refusing; the draft and manifest are kept, resolve by hand.");
      }
    };
    // an existing on-ledger receipt must bind to the CURRENT pool before it is accepted or
    // before local state is finalized (round-6): re-fetched fresh at the point of use, so a
    // credentialed external pool mutation during an await cannot slip a contradicting
    // receipt past. On v8, hash + status + pool constants; fee excluded (historical, as
    // above). On an immutable pool the hash and status have no pool side (invariant list
    // item 9), so the binding routes through the SHARED five-duty check instead, which is
    // stronger on the fields that do exist: it also pins the receipt's embedded target to
    // the pool, which the v8 binding never did.
    const requireReceiptBindsPool = (receiptObj, poolObj, poolIdStr) => {
      if (hasImmutablePool()) {
        const res = checkReceiptAgainstPool({ contractId: activeContractId(env),
          receipt: receiptObj, pool: poolObj, poolId: poolIdStr });
        if (!res.ok) {
          throw new Error(`the on-ledger receipt does not verify against the current pool ` +
            `(${res.reason}). Refusing; local state is kept, resolve by hand.`);
        }
        return;
      }
      const bad = [];
      const liveHash = Buffer.from(poolObj.proTxHash);
      if (core.isFormingHash(liveHash)) bad.push("the pool is still forming");
      else if (!liveHash.equals(Buffer.from(receiptObj.proTxHash))) bad.push("proTxHash differs from the live pool");
      if (poolObj.status !== undefined && poolObj.status !== "live") bad.push(`pool status is "${poolObj.status}", not live`);
      if (Number(receiptObj.slotIndex) !== Number(poolObj.slotIndex)) bad.push("slotIndex differs from the pool");
      // on a pared receipt there is no nodeType to differ; the pool is its only carrier
      if (!hasParedReceipt() && receiptObj.nodeType !== poolObj.nodeType) {
        bad.push("nodeType differs from the pool");
      }
      if (bad.length > 0) {
        throw new Error("the on-ledger receipt CONTRADICTS the current pool: " + bad.join("; ") +
          ". Refusing; local state is kept, resolve by hand.");
      }
    };

    // WHAT STATE IS THIS POOL IN, asked once and answered the same way everywhere (phase E).
    //
    // On v8 the pool answers by itself, because `proTxHash` starts in the forming namespace
    // and the flip mutates it. On v9 the pool is immutable and carries neither `proTxHash`
    // nor `status`, so the COMPLETION RECEIPT is the state machine and the operator's own
    // local manifest or draft is the only thing that can narrow a receipt-less pool to
    // in-flight. `poolLifecycle` holds that distinction; this wrapper supplies the three
    // inputs it cannot fetch for itself.
    //
    // The local-evidence argument is deliberately the OPERATOR's own state and nothing else.
    // A caller without it gets UNDETERMINED rather than a guess, which is the same reason
    // the funder client's admission rule fails closed.
    const fetchReceiptFor = async (pool) => (await client.platform.documents.get(
      "poolLedger.completionReceipt", { where: [["poolId", "==", pool.getId()]] }))[0] || null;

    const classifyPoolNow = async (pool, poolIdStr, poolObj = null) => {
      const po = poolObj || pool.toObject();
      // only ledgers that HAVE a completion receipt can have one to fetch
      const receiptDoc = isV8() ? await fetchReceiptFor(pool) : null;
      const envNow = loadEnv();
      const operatorHasInFlight = envNow[manifestKeyOf(poolIdStr)] !== undefined
        || envNow[receiptDraftKeyOf(poolIdStr)] !== undefined;
      return {
        ...lifecycle.classifyPool({
          contractId: activeContractId(env), pool: po, poolId: pool.getId(),
          receipt: receiptDoc ? receiptDoc.toObject() : null,
          operatorHasInFlight,
        }),
        receiptDoc,
      };
    };

    // ONE finalization for `complete` and `receipt` (review major): the receipt is
    // confirmed, so retain the finalized manifest under FORMATION_DONE_, clear the
    // ACTIVE key (its presence means "a completion is in flight"), and clear the
    // draft. Shared so recovery can never leave a completion half-finalized (an
    // active manifest with no draft, which a later `complete` would rebuild from
    // CURRENT pool values and falsely contradict the already-confirmed receipt).
    const finalizeCompletion = (poolIdStr, manifest) => {
      const activeKey = manifestKeyOf(poolIdStr);
      const doneKey = "FORMATION_DONE_" + journal.suffixFor(activeContractId(env), poolIdStr);
      // ORDER (round-6): write DONE first, clear the draft next, and clear the ACTIVE key
      // LAST. The active key is the "a completion is in flight" signal that `done prune`
      // checks before deleting a DONE, so keeping it until the very end shrinks the window
      // in which a concurrent prune could delete the just-written DONE to a single write.
      if (manifest) updateEnvKey(doneKey, JSON.stringify(manifest));
      // v8 only: the draft key exists only on the receipt ledgers, and an unconditional
      // extra locked write would add a failure point to a v1..v7 completion
      if (isV8()) {
        updateEnvKey(receiptDraftKeyOf(poolIdStr), undefined);
        // a completed formation SUPERSEDES any prior abandon of the same pool (round-7
        // re-check P2): a stale FORMATION_ABANDONED_ left behind could later be picked as
        // a manifest source and falsely contradict this completion's receipt
        updateEnvKey("FORMATION_ABANDONED_" + journal.suffixFor(activeContractId(env), poolIdStr), undefined);
      }
      updateEnvKey(activeKey, undefined);
      return doneKey;
    };

    if (cmd === "create") {
      const [nodeType, feeStr] = args;
      if (!core.TARGETS[nodeType] || !/^[0-9]{1,5}$/.test(feeStr || "") || parseInt(feeStr, 10) > 10000) {
        throw new Error("usage: create <regular|evo> <feeBps 0..10000>");
      }
      // v7: the slot economics are creation-time POOL DATA (review finding A1), the
      // single on-ledger source every client reads; SLOT_DUFFS configures the OPERATOR
      // at creation only, members never choose a size
      let slotFields = {};
      if (isV7()) {
        const slotDuffs = BigInt(process.env.SLOT_DUFFS || "10000000000"); // 100 DASH
        const target = core.TARGETS[nodeType];
        if (target % slotDuffs !== 0n) {
          throw new Error(`slot size ${slotDuffs} does not divide the ${DASHfmt(target)} DASH target`);
        }
        const slotCount = Number(target / slotDuffs);
        // CREATE ceiling (F-G re-check): bound slotCount at creation so a LEGITIMATE book
        // can never exceed the completion scan cap (MAX_SLOT_COUNT < MAX_PLEDGE_CLAIMS). A
        // larger slotDuffs (fewer, bigger slots) is always available; 512 co-owners of one
        // masternode is already far past any real pool. Without this, a tiny SLOT_DUFFS
        // could mint thousands of valid slots that the bounded scan would then reject.
        if (slotCount > MAX_SLOT_COUNT) {
          throw new Error(`slot size ${slotDuffs} yields ${slotCount} slots, above the ${MAX_SLOT_COUNT} ` +
            "ceiling; use a larger slot size (fewer, bigger slots).");
        }
        slotFields = {
          slotDuffs: journal.toSafeNumber(slotDuffs, "slot size"),
          slotCount,
        };
      }
      // THE POOL SHAPE IS LEDGER-DEPENDENT (invariant list item 13). Through v8 the pool
      // carries the forming placeholder, the operator identity, and (v5+) an explicit
      // status; the flip later mutates it live. The v9 pool is IMMUTABLE and final at
      // creation: no proTxHash, no status, no operatorIdentityId (the $ownerId is the
      // binding), and the REQUIRED targetDuffs the paring moved onto it. Emitting the v8
      // fields there would be schema-rejected (additionalProperties: false).
      const poolProps = hasImmutablePool()
        ? {
          slotIndex: 0, nodeType, operatorFeeBps: parseInt(feeStr, 10),
          targetDuffs: journal.toSafeNumber(core.TARGETS[nodeType], "target"),
        }
        : {
          proTxHash: Buffer.concat([Buffer.alloc(16, 0), crypto.randomBytes(16)]),
          slotIndex: 0, nodeType,
          operatorIdentityId: operator.getId().toBuffer(), operatorFeeBps: parseInt(feeStr, 10),
          // v5 carries the lifecycle explicitly; the placeholder convention stays as
          // belt and braces for the hash itself
          ...(isV5() ? { status: "forming" } : {}),
        };
      const doc = await client.platform.documents.create("poolLedger.pool", operator, {
        ...poolProps,
        ...slotFields,
      });
      await client.platform.documents.broadcast({ create: [doc] }, operator);
      console.log(hasImmutablePool()
        ? `pool created (immutable; its completion state will live on the completion receipt): ${doc.getId().toString()}`
        : `forming pool created: ${doc.getId().toString()}`);
      console.log(`  target ${DASHfmt(core.TARGETS[nodeType])} DASH (${nodeType}), fee ${feeStr} bps`);
      if (isV7()) console.log(`  slot book: ${slotFields.slotCount} slots of ` +
        `${DASHfmt(slotFields.slotDuffs)} DASH (on the pool document)`);
      // the participation instruction matches the ledger (F-P: pledge REFUSES on the
      // slot-book ledgers, so never advertise it there). On an immutable-pool ledger the
      // admission rule fails closed on a receipt-less pool, so the advertised instruction
      // must carry the explicit coordination the rule's one exception requires.
      console.log(isV6()
        ? (hasImmutablePool()
          ? `  members participate with: TEGARA_PARTICIPATE=${doc.getId().toString()} ` +
            `funderClient reserve ${doc.getId().toString()} <slotNo>\n` +
            "  (the explicit TEGARA_PARTICIPATE naming THIS pool is required: a receipt-less " +
            "immutable pool is indistinguishable from an abandoned one, so admission fails " +
            "closed without it)"
          : `  members participate with: funderClient reserve ${doc.getId().toString()} <slotNo>`)
        : `  members pledge with: funderClient pledge ${doc.getId().toString()} <duffs>`);
      return;
    }

    if (cmd === "status") {
      const [poolIdStr] = args;
      if (!poolIdStr) throw new Error("usage: status <poolId>");
      const pool = await getPool(poolIdStr);
      const po = pool.toObject();
      // ONE classification, shared with `complete`, `receipt` and `abandon`. The printed
      // state is the classifier's, not a two-way forming/live guess, because on an immutable
      // ledger a receipt-less pool genuinely IS open, in flight and abandoned at once and
      // printing "FORMING" for it would be a claim the data does not support.
      const cls = await classifyPoolNow(pool, poolIdStr, po);
      const forming = cls.state === lifecycle.STATES.FORMING;
      const target = core.TARGETS[po.nodeType];
      console.log(`pool ${poolIdStr}: ${cls.state.toUpperCase()} (${po.nodeType}, ` +
        `fee ${Number(po.operatorFeeBps)} bps)`);
      console.log(`  ${cls.reason}`);
      if (loadEnv()[manifestKeyOf(poolIdStr)]) {
        console.log("  a completion manifest is COMMITTED; finish it with the same complete command");
      }
      const rows = await pendingJoinRows(pool.getId(), po);
      const pledged = rows.reduce((s, r) => s + r.amount, 0n);
      console.log(`fill: ${DASHfmt(pledged)} / ${DASHfmt(target)} DASH across ${rows.length} pledge(s)` +
        (pledged === target ? "  <- FULL, ready to complete" : ""));
      for (const r of rows) console.log(`  ${DASHfmt(r.amount)} DASH by ${r.owner} (request ${r.id})`);
      // proactive L1 check for a LIVE pool (review follow-on, review): the on-ledger
      // state asserts a node; when Core is reachable, confirm the node is actually in
      // the DMN list rather than waiting for an eventual settlement failure.
      //
      // THE NODE IDENTITY IS ROUTED THROUGH THE DESIGN'S ONE PRODUCER, backingNode: on
      // v8 that is the pool's own proTxHash (the value this check always read), on v9 it
      // is the VERIFYING completion receipt, and a pool with no established node prints
      // WHY rather than a blank, because a check that quietly stops running is worse
      // than one that says it cannot (a receipt-less v9 pool asserts no node at all,
      // and a non-verifying receipt establishes nothing).
      // THE LIVE SHARE CROSS-CHECK (pass-7 wave, review minor 5): this command was
      // DOCUMENTED as the place where a receipt's allocation is compared with the
      // current mutable shares, and it never queried shares at all, so the pointer led
      // operators to a command that could not do what it was pointed to for. When a
      // receipt VERIFIES, its embedded allocation rows are decoded here and held against
      // the live share set, per owner, with every divergence printed and the exit code
      // raised; a receipt-less pool states that there is nothing to cross-check against.
      if (cls.receiptOk && cls.receiptDoc) {
        try {
          const rowsArr = JSON.parse(Buffer.from(cls.receiptDoc.toObject().allocationRows).toString("utf8"));
          const allocRows = rowsArr[5]; // [owner, amountDuffs, bps, scriptHex] tuples
          const liveShares = await fetchAll(client, "poolLedger.share", {
            where: [["poolId", "==", pool.getId()]],
          });
          // one entry per owner is a CONSENSUS guarantee (the share type's unique
          // byPoolOwner index), so the Map cannot silently collapse duplicates
          const byOwner = new Map(liveShares.map((d) => [d.getOwnerId().toString(), d.toObject()]));
          const diverged = [];
          for (const [owner, amountDuffs, bps, scriptHex] of allocRows) {
            const sh = byOwner.get(owner);
            if (!sh) { diverged.push(`share MISSING for ${owner} (receipt allocates ${bps} bps)`); continue; }
            if (Number(sh.shareBps) !== bps) diverged.push(`${owner}: share ${Number(sh.shareBps)} bps != receipt ${bps} bps`);
            if (String(sh.contributionDuffs) !== amountDuffs) {
              diverged.push(`${owner}: contribution ${sh.contributionDuffs} != receipt ${amountDuffs}`);
            }
            // the reward script is the fourth tuple field and the one a diversion would
            // touch; comparing three of four fields would print "match" over it
            const liveScript = sh.l1RewardScript ? Buffer.from(sh.l1RewardScript).toString("hex") : null;
            if (liveScript !== scriptHex) {
              diverged.push(`${owner}: reward script ${liveScript || "(absent)"} != receipt ${scriptHex}`);
            }
            byOwner.delete(owner);
          }
          for (const extra of byOwner.keys()) diverged.push(`EXTRA share by ${extra}, not in the receipt allocation`);
          if (diverged.length === 0) {
            console.log(`share cross-check: ${allocRows.length} live share(s) match the receipt allocation exactly`);
          } else {
            for (const d of diverged) console.log(`SHARE DIVERGENCE: ${d}`);
            console.log("the receipt records the completion-time allocation and the live shares no " +
              "longer match it; which side is wrong is not decidable from here (a post-completion " +
              "share change, an incomplete read, and a bad original snapshot all print exactly " +
              "this), so investigate before relying on either");
            process.exitCode = 1;
          }
        } catch (e) {
          console.log(`share cross-check COULD NOT RUN (${(e && e.message) || e})`);
          process.exitCode = 1;
        }
      } else if (!forming) {
        console.log("share cross-check: no verifying receipt, so there is no completion-time allocation to hold the shares against");
      }
      if (!forming) {
        const node = lifecycle.backingNode({ pool: po,
          receipt: cls.receiptDoc ? cls.receiptDoc.toObject() : null, receiptOk: cls.receiptOk });
        if (!node.known) {
          console.log(`L1 check: no established node to check (${node.why})`);
        } else if (process.env.FORK_RPC_URL) {
          try {
            const { fetchCollateral } = require("./l1gov.cjs");
            const c = await fetchCollateral(node.hex);
            console.log(`L1 check: the backing node is in the DMN list (collateral ${c.txid.slice(0, 16)}...:${c.vout})`);
          } catch (e) {
            // ONLY a genuine protx-not-found from Core supports the missing-node claim
            // (review finding: an HTTP 500, a timeout, an auth failure, or an overloaded
            // Core all mean the check could not run, NOT that the node is gone). Core
            // reports an unknown proTxHash as an RPC error whose message says so; the
            // structured e.rpcError from forkRpc carries it.
            const msg = (e && e.message) || String(e);
            // ONLY Core's confirmed proTx-not-found phrasing counts (live-observed
            // "<hash> not found"). Do NOT match "invalid"/malformed-request errors like
            // "Invalid parameter" or "Invalid address or key": those mean the request
            // was bad, not that the node is absent (review finding). "not found" does
            // not appear in Core's malformed-request messages, so it is the safe signal.
            const notFound = e && e.rpcError && /\bnot\s+found\b/i.test(e.rpcError.message || "");
            if (notFound) {
              console.log(`L1 CHECK FAILED: Core reports NO such node (${e.rpcError.message}); ` +
                "the on-ledger state asserts a node Core does not know, investigate before relying on it");
            } else {
              console.log(`L1 check COULD NOT RUN (${msg}); Core did not give a definite not-found ` +
                "answer, so the backing node's existence is neither confirmed nor denied, retry when " +
                "the RPC is healthy");
            }
            process.exitCode = 1;
          }
        } else {
          console.log("L1 check skipped (no FORK_RPC_URL); the backing node's existence is asserted, not verified");
        }
      }
      return;
    }

    if (cmd === "complete") {
      const [poolIdStr, proTxHex] = args;
      if (!poolIdStr || !/^[0-9a-f]{64}$/i.test(proTxHex || "")) {
        throw new Error("usage: complete <poolId> <real proTxHash, 64 hex>");
      }
      const realHash = Buffer.from(proTxHex, "hex");
      if (core.isFormingHash(realHash)) {
        throw new Error("that hash is inside the reserved FORMING namespace; a real node hash cannot be");
      }
      takePoolOpLock(poolIdStr);
      const pool = await getPool(poolIdStr);
      const po = pool.toObject();
      // the M1 owner binding, BEFORE the manifest is even read (review blocker): the
      // executing operator must own this pool, or completion could occupy a foreign
      // pool's unique receipt slot
      if (isV8()) requirePoolOwnedByOperator(pool, poolIdStr);
      const target = core.TARGETS[po.nodeType];
      const manifestKey = manifestKeyOf(poolIdStr);

      // phase 1, COMMIT (or load the committed manifest on resume)
      let manifest = null;
      const rawManifest = loadEnv()[manifestKey];
      if (rawManifest !== undefined) {
        try { manifest = JSON.parse(rawManifest); } catch { throw new Error("the committed manifest is corrupt; restore its .val.prev generation in .env.local.state/ (a restored generation is re-validated before use)"); }
        validateManifest(manifest, poolIdStr, proTxHex, po);
        console.log("resuming the COMMITTED completion (driving from the manifest, not live state)");
      } else {
        // NOTHING TO DO HERE, asked through the classifier so it means something on both
        // ledgers. On v8 that is "the pool already flipped". On v9 there is no flip, so the
        // equivalent is "a completion receipt already verifies against this pool"; a
        // receipt-less v9 pool is UNDETERMINED and completion is exactly what resolves it,
        // so only COMPLETED refuses. A receipt that CONTRADICTS the pool also refuses, via
        // the classifier's own refusal to read a contradiction as absence.
        const pre = await classifyPoolNow(pool, poolIdStr, po);
        if (pre.state === lifecycle.STATES.COMPLETED) {
          throw new Error("this pool has already COMPLETED (a receipt verifies against it) and no " +
            "completion manifest exists; nothing to do");
        }
        if (pre.receiptDoc && !pre.receiptOk) {
          throw new Error(`a completion receipt exists for this pool but does not verify against it ` +
            `(${pre.reason}). Refusing to start a second completion over a contradiction; resolve by hand.`);
        }
        if (!hasImmutablePool() && !core.isFormingHash(Buffer.from(po.proTxHash))) {
          throw new Error("pool is already LIVE and no completion manifest exists; nothing to do");
        }
        const rows = await pendingJoinRows(pool.getId(), po);
        const pledged = rows.reduce((s, r) => s + r.amount, 0n);
        if (pledged !== target) {
          throw new Error(`pledged ${DASHfmt(pledged)} DASH does not equal the target ${DASHfmt(target)}; ` +
            "completion requires an exact fill (cancel or add pledges; the list is in `status`)");
        }
        const owners = core.aggregateByOwner(rows);
        // the 1..8 bound IMMEDIATELY after aggregation (review minor): before the
        // reward-address derivation advances the durable FORMATION_ADDR_INDEX counter,
        // so an over-bound pool refuses without any local mutation at all.
        // validateManifest re-checks it as defense for resumed manifests.
        if (isV8() && (owners.length < 1 || owners.length > 8)) {
          throw new Error(`the receipt ledgers allow 1..8 direct covenant participants; this pool aggregates to ` +
            `${owners.length} owners. Cancel or consolidate pledges, or form on a non-receipt ledger.`);
        }
        // the v1 PRODUCT-TIER minimum (final pass, major 5), enforced before any local
        // mutation: consensus admits a single owner, the two-to-eight product tier does
        // not, and only the demo surface (FORMATION_ALLOW_UNVERIFIED=demo) completes a
        // single-owner pool
        core.requireTierOwnerCount(owners.length, { demo: process.env.FORMATION_ALLOW_UNVERIFIED === "demo" });
        const alloc = core.allocateBps(owners, target);
        // reward scripts: a MEMBER-SUPPLIED script from the pledge (v5's rewardScript
        // field) wins; the newest pledge that carries one speaks for the owner. The
        // wallet-derived fallback keeps every script spendable by a known key on the
        // pre-v5 ledgers (review blocker: a random hash strands rewards; demo caveat:
        // all identities share this wallet).
        const account = await client.getWalletAccount();
        const memberScript = new Map();
        for (const r of [...rows].sort((a, b) => a.at - b.at)) {
          if (r.rewardScriptHex) memberScript.set(r.owner, r.rewardScriptHex);
        }
        // the fallback derivation index is a PERSISTENT counter (owned FORMATION_ key),
        // never the loop index: restarting at 0 per completion handed different members
        // of different pools the SAME addresses (holistic-round F8, review). ATOMICALLY
        // reserve the range up front (F-H): the counter is global and the per-pool op lock
        // does not serialize two different-pool completions, so a split read+write could
        // hand two pools the same base and re-collide. reserveAddrIndex advances it under
        // the env lock and returns a base disjoint from any concurrent reserver.
        const fallbackCount = alloc.filter((a) => !memberScript.get(a.owner)).length;
        let addrIdx = fallbackCount > 0 ? reserveAddrIndex(fallbackCount) : 0;
        for (let i = 0; i < alloc.length; i++) {
          const supplied = memberScript.get(alloc[i].owner);
          if (supplied) {
            alloc[i].rewardScriptHex = supplied;
            alloc[i].rewardAddress = "(member-supplied script)";
          } else {
            const addr = account.getAddress(addrIdx).address;
            addrIdx += 1;
            alloc[i].rewardScriptHex = Dash.Core.Script.buildPublicKeyHashOut(addr).toBuffer().toString("hex");
            alloc[i].rewardAddress = addr;
          }
        }
        manifest = {
          v: 1, poolId: poolIdStr, realHash: proTxHex.toLowerCase(), target: target.toString(),
          // freeze the slot economics (F-D): slotDuffs/slotCount are creation-time constants
          // of the pool (v7+), but the pool document is mutable, so an operator-credentialed
          // replace could change them after COMMIT undetected; freezing them lets
          // validateManifest catch a drift against the live pool before the flip.
          ...(po.slotDuffs !== undefined ? { slotDuffs: Number(po.slotDuffs) } : {}),
          ...(po.slotCount !== undefined ? { slotCount: Number(po.slotCount) } : {}),
          owners: alloc.map((a) => ({ owner: a.owner, amountDuffs: a.amount.toString(), bps: a.bps,
            reqIds: a.reqIds, rewardScriptHex: a.rewardScriptHex, rewardAddress: a.rewardAddress })),
          // per-claim SNAPSHOTS (review F-C1): mutable claims mean bare existence proves
          // nothing at preflight time; these frozen fields are what each claim must
          // still say for completion to proceed
          claims: rows.map((r) => ({ id: r.id, owner: r.owner, amountDuffs: r.amount.toString(),
            slotNo: r.slotNo !== undefined ? r.slotNo : null,
            rewardScriptHex: r.rewardScriptHex || null })),
        };
        validateManifest(manifest, poolIdStr, proTxHex, po); // self-check before persisting
        updateEnvKey(manifestKey, JSON.stringify(manifest));
        console.log("completion manifest COMMITTED (participants, weights, reward scripts frozen)");
      }

      // every pledger must be controllable BEFORE any mutation (matcher discipline)
      const controlled = {};
      for (const [k, v] of Object.entries(env)) {
        if (k === "FUNDER_ID" || /^FUNDER\d+_ID$/.test(k)) controlled[v] = null;
      }
      const identityFor = async (idStr) => {
        if (!(idStr in controlled)) throw new Error(`pledger ${idStr} is not an identity this run controls`);
        if (!controlled[idStr]) controlled[idStr] = await client.platform.identities.get(idStr);
        return controlled[idStr];
      };
      for (const o of manifest.owners) await identityFor(o.owner);

      // PREFLIGHT (a): the registration verification L1 registration check, extracted to
      // decideL1Verification above so the `receipt` recovery path runs the identical
      // check. It throws to refuse (the manifest is kept) and returns the scoped
      // verification level the v8 receipt records.
      const l1Level = await decideL1Verification(proTxHex, manifest, target, poolIdStr);

      // PREFLIGHT (b), the CANCEL-OR-MUTATE-AFTER-COMMIT CHECK (holistic-round F3 /
      // registration verification, extended by review F-C1): every committed pledge must still exist on the
      // ledger AND still say what the manifest snapshotted (owner, pool, slot, script,
      // amount), or its owner's share must already exist (resume evidence that
      // settlement passed them). Mutable claims (v7) made bare existence meaningless: a
      // replaced claim keeps its id, so the fields are compared, not just found.
      const snapshotOf = new Map((manifest.claims || []).map((c) => [c.id, c]));
      if (!manifest.claims) {
        console.log("NOTE: this manifest predates per-claim snapshots (F-C1); the pre-settlement " +
          "check falls back to existence-only for this completion");
      }
      for (const o of manifest.owners) {
        const ownerShare = await client.platform.documents.get("poolLedger.share", {
          where: [["poolId", "==", pool.getId()], ["$ownerId", "==", Identifier.from(o.owner)]],
        });
        if (ownerShare.length > 0) continue; // settlement already passed this owner
        // v6/v7 committed claims are pledgeSlot documents; v5 and earlier are
        // membershipRequests. A claim that vanished after COMMIT means the member left
        // before the registration could have included them (registration verification).
        const claimType = isV6() ? "poolLedger.pledgeSlot" : "poolLedger.membershipRequest";
        for (const reqId of o.reqIds) {
          const req = await client.platform.documents.get(claimType, {
            where: [["$id", "==", Identifier.from(reqId)]],
          });
          if (req.length === 0) {
            throw new Error(`committed pledge ${reqId} (owner ${o.owner}) is GONE from the ledger: ` +
              "the member cancelled after COMMIT, so the committed allocation no longer has their " +
              "participation. Refusing to settle. Resolve with the members, then `abandon " +
              `${poolIdStr}\` and re-form (registration verification).`);
          }
          const snap = snapshotOf.get(reqId);
          if (!snap) continue; // legacy manifest, noted above
          const doc = req[0];
          const cur = doc.toObject();
          const mismatches = [];
          if (doc.getOwnerId().toString() !== snap.owner) {
            mismatches.push(`owner ${doc.getOwnerId().toString()} != committed ${snap.owner}`);
          }
          if (Identifier.from(Buffer.from(cur.poolId)).toString() !== poolIdStr) {
            mismatches.push(`poolId ${Identifier.from(Buffer.from(cur.poolId)).toString()} != this pool`);
          }
          if (snap.slotNo !== null && snap.slotNo !== undefined && Number(cur.slotNo) !== snap.slotNo) {
            mismatches.push(`slotNo ${cur.slotNo} != committed ${snap.slotNo}`);
          }
          if (cur.amountDuffs !== undefined && snap.amountDuffs !== null &&
              String(cur.amountDuffs) !== snap.amountDuffs) {
            mismatches.push(`amountDuffs ${cur.amountDuffs} != committed ${snap.amountDuffs}`);
          }
          if (snap.rewardScriptHex && cur.rewardScript &&
              Buffer.from(cur.rewardScript).toString("hex") !== snap.rewardScriptHex) {
            mismatches.push("rewardScript changed since COMMIT");
          }
          if (mismatches.length > 0) {
            throw new Error(`committed pledge ${reqId} (owner ${snap.owner}) was MUTATED after ` +
              `COMMIT: ${mismatches.join("; ")}. The claim no longer says what the committed ` +
              "allocation froze, so completion refuses (F-C1). Resolve with the member, then " +
              `\`abandon ${poolIdStr}\` and re-form.`);
          }
        }
      }

      // PREFLIGHT (c), before ANY mutation (re-check blockers: verification inside the
      // mutating loop let earlier owners settle before a later mismatch surfaced, and a
      // wrong live hash was only caught after settlement):
      // (a) the pool's current hash must be the forming placeholder OR the manifest's
      //     real hash, nothing else;
      // (b) every owner's EXISTING share must match the manifest field-by-field, with
      //     both sides of all three fields in the refusal.
      // The pool is RE-FETCHED here so the hash check sees the state at preflight time,
      // not the copy from before manifest processing (re-check finding).
      // THE POOL-VERSUS-MANIFEST NODE CHECK. On v8 the flipped pool names the node, so a
      // manifest naming a different one is a contradiction. On v9 the pool names no node at
      // all, so this specific contradiction is UNREPRESENTABLE there and the equivalent
      // binding is the completion receipt's own proTxHash, which the receipt readers check.
      // Skipping it on v9 is therefore not a weakened check, it is a check whose subject
      // does not exist; the binding it protected moved rather than vanished.
      if (!hasImmutablePool()) {
        const currentHash = Buffer.from((await getPool(poolIdStr)).toObject().proTxHash);
        if (!core.isFormingHash(currentHash) && currentHash.toString("hex") !== manifest.realHash) {
          throw new Error(`the pool is live under ${currentHash.toString("hex")}, which contradicts the ` +
            `committed manifest's ${manifest.realHash}; the manifest is kept, resolve by hand`);
        }
      }
      const existingShares = {};
      for (const o of manifest.owners) {
        const found = await client.platform.documents.get("poolLedger.share", {
          where: [["poolId", "==", pool.getId()], ["$ownerId", "==", Identifier.from(o.owner)]],
        });
        existingShares[o.owner] = found[0] || null;
        if (found[0]) {
          const so = found[0].toObject();
          const ledgerScript = Buffer.from(so.l1RewardScript).toString("hex");
          if (Number(so.shareBps) !== o.bps
            || BigInt(so.contributionDuffs).toString() !== o.amountDuffs
            || ledgerScript !== o.rewardScriptHex) {
            throw new Error(`the existing share for ${o.owner} contradicts the committed manifest ` +
              `(ledger: ${Number(so.shareBps)} bps, ${so.contributionDuffs} duffs, script ${ledgerScript}; ` +
              `manifest: ${o.bps} bps, ${o.amountDuffs} duffs, script ${o.rewardScriptHex}); ` +
              "refusing BEFORE any mutation");
          }
        }
      }

      // v8: persist the FROZEN RECEIPT DRAFT (spec FU-2), after the successful
      // preflight and BEFORE the flip. The retained manifest alone cannot reconstruct
      // the exact receipt after a post-flip crash (it lacks slotIndex, nodeType,
      // operatorFeeBps, and the RESOLVED verification level), so every receipt field,
      // including the exact allocationRows bytes, is frozen here and both the create
      // and the idempotent field-verify drive from this draft, never from live state.
      let receiptDraft = null;
      if (isV8()) {
        if (po.slotIndex === undefined || po.nodeType === undefined) {
          throw new Error("this pool lacks slotIndex/nodeType, so a v8 receipt cannot be recorded; refusing");
        }
        const draftKey = receiptDraftKeyOf(poolIdStr);
        const rowsBuf = core.allocationPreimage(activeContractId(env), manifest);
        const rawDraft = loadEnv()[draftKey];
        if (rawDraft !== undefined) {
          try { receiptDraft = JSON.parse(rawDraft); } catch {
            throw new Error("the frozen receipt draft is corrupt; restore its .val.prev generation in .env.local.state/ (a restored generation is re-validated against the manifest and pool before use)");
          }
          // FULL fail-closed validation, not just the rows check (review major): a
          // parseable-but-damaged draft drives an immutable write, so every field is
          // validated and cross-checked against the frozen manifest before use
          validateReceiptDraft(receiptDraft, poolIdStr, manifest);
          // a soundness-review finding: this draft came off the frozen key, so it IS the completion-time truth
          // and its fee is comparable. Non-enumerable so JSON.stringify never carries it.
          Object.defineProperty(receiptDraft, "__origin", { value: "frozen" });
          // the fee context (invariant list item 5): pre-flip exact on v8, historical once
          // flipped; always exact on an immutable pool, where the fee cannot have drifted
          requireDraftMatchesPool(receiptDraft, po, {
            requireFee: hasImmutablePool() || core.isFormingHash(Buffer.from(po.proTxHash)),
          });
          console.log("resuming with the FROZEN receipt draft (verification level " +
            `${receiptDraft.l1Verification} from the original preflight)`);
        } else {
          receiptDraft = {
            v: 1, poolId: poolIdStr, proTxHash: manifest.realHash,
            slotIndex: Number(po.slotIndex), nodeType: po.nodeType,
            operatorFeeBps: Number(po.operatorFeeBps || 0),
            formatVersion: 1,
            allocationRowsHex: rowsBuf.toString("hex"),
            allocationHashHex: core.allocationHash(rowsBuf).toString("hex"),
            participantCount: manifest.owners.length,
            targetDuffs: journal.toSafeNumber(target, "target"),
            l1Verification: l1Level, verificationMethodVersion: 1,
          };
          validateReceiptDraft(receiptDraft, poolIdStr, manifest); // self-check before persisting
          // a soundness-review finding: REBUILT from the manifest plus the CURRENT pool, so its fee is a
          // present-day reading, not the completion-time one, and must not be compared
          Object.defineProperty(receiptDraft, "__origin", { value: "rebuilt" });
          updateEnvKey(draftKey, JSON.stringify(receiptDraft));
          console.log(`receipt draft FROZEN (${rowsBuf.length} preimage bytes, level ${l1Level})`);
        }
      }

      // a soundness-review finding (vetting round): an existing receipt is compared with the FROZEN DRAFT
      // BEFORE any settlement mutation, on resume as well as first run. The no-manifest
      // classifier preflight covers only first runs, so without this a resumed completion
      // could create participant shares and discover the contradiction only at the
      // receipt write. A receipt that MATCHES the draft is the ordinary post-crash resume
      // and proceeds idempotently; any mismatch stops here, with nothing yet mutated by
      // this run. The final idempotent query still covers a receipt racing in later.
      if (isV8() && receiptDraft) {
        const preSettle = await fetchReceiptFor(pool);
        if (preSettle) {
          verifyReceiptAgainstDraft(preSettle, receiptDraft);
          // the draft comparison alone does not COMPOSE with a soundness-review finding (closing pass,
          // must-fix): a draft-MATCHING receipt over a still-forming v8 pool passed here
          // and settlement mutated before the flip guard refused. The receipt must also
          // bind to the CURRENT pool, through the same helper both writers use, so the
          // still-forming and wrong-hash contradictions stop the resume pre-settlement.
          requireReceiptBindsPool(preSettle.toObject(), (await getPool(poolIdStr)).toObject(), poolIdStr);
          console.log("an existing completion receipt matches the frozen draft and binds to the " +
            "current pool; resuming idempotently past it");
        }
      }

      console.log("=== COVENANT REGISTRATION HANDOFF (the L1 side happens in the fork tooling) ===");
      for (const o of manifest.owners) {
        console.log(`  ${o.owner}  ${DASHfmt(BigInt(o.amountDuffs))} DASH -> ${o.bps} bps, ` +
          `rewards to ${o.rewardAddress}`);
      }
      if (HALT === "commit") { console.log("[test hook] halting after COMMIT"); return; }

      // phase 2, SETTLE from the manifest (idempotent per owner and per request)
      for (const o of manifest.owners) {
        const pledger = await identityFor(o.owner);
        // the preflight above already verified every existing share against the
        // manifest before anything mutated; here it only decides create-vs-skip
        if (existingShares[o.owner]) {
          console.log(`  share for ${o.owner} already exists and matches the manifest; skipping`);
        } else {
          const share = await client.platform.documents.create("poolLedger.share", pledger, {
            poolId: pool.getId().toBuffer(), shareBps: o.bps,
            contributionDuffs: journal.toSafeNumber(BigInt(o.amountDuffs), "contribution"),
            l1RewardScript: Buffer.from(o.rewardScriptHex, "hex"),
          });
          await client.platform.documents.broadcast({ create: [share] }, pledger);
          console.log(`  share created: ${o.bps} bps for ${o.owner} (by the pledger)`);
        }
        // v6 pledgeSlot claims are IMMUTABLE reservations, not status-carrying requests;
        // they stay on the ledger as the permanent record of who reserved what and are
        // not "settled" (nothing to flip). The v5-and-earlier path settles the join
        // request as before.
        if (isV6()) {
          console.log(`  ${o.reqIds.length} slot claim(s) for ${o.owner} left on the ledger ` +
            "(the durable formation record is the shares plus the retained FORMATION_DONE_ manifest)");
          continue;
        }
        for (const reqId of o.reqIds) {
          const req = (await client.platform.documents.get("poolLedger.membershipRequest", {
            where: [["$id", "==", Identifier.from(reqId)]],
          }))[0];
          if (!req) {
            console.log(`  NOTE: pledge ${reqId} is GONE (cancelled after the commit); the share still ` +
              "follows the manifest, which is what the L1 registration used; resolve with the member");
          } else if (req.toObject().status === "pending") {
            req.set("status", "settled");
            await client.platform.documents.broadcast({ replace: [req] }, pledger);
            console.log(`  pledge ${reqId} settled (by its owner)`);
          }
        }
      }

      // readback BEFORE the flip, SCOPED TO THE MANIFEST PARTICIPANTS (a soundness review): query EACH
      // manifest owner's share by (poolId, $ownerId) and verify it field-by-field. Summing
      // ALL pool shares and requiring the total to be exactly 10000 (the old check) let ANY
      // funded identity plant one foreign share on the pool and wedge the flip forever, a
      // permanent availability DoS. The receipt commits to the MANIFEST allocation, not the
      // live share set, so a NON-participant share carries no weight and must not block. Each
      // participant's share is still verified field-by-field (round-6), so a mutated real
      // share is still caught. This also bounds the readback to <=8 indexed lookups instead
      // of an unbounded fetchAll over an dishonest party-inflatable collection (F-G).
      let participantBps = 0;
      for (const o of manifest.owners) {
        const found = await client.platform.documents.get("poolLedger.share", {
          where: [["poolId", "==", pool.getId()], ["$ownerId", "==", Identifier.from(o.owner)]],
        });
        const so = found[0] ? found[0].toObject() : null;
        if (!so) throw new Error(`owner ${o.owner} has no share on the ledger; not flipping`);
        const ledgerScript = Buffer.from(so.l1RewardScript).toString("hex");
        if (Number(so.shareBps) !== o.bps || BigInt(so.contributionDuffs).toString() !== o.amountDuffs
          || ledgerScript !== o.rewardScriptHex) {
          throw new Error(`the share for ${o.owner} was MUTATED after settlement (ledger: ` +
            `${Number(so.shareBps)} bps, ${so.contributionDuffs} duffs, script ${ledgerScript}; manifest: ` +
            `${o.bps} bps, ${o.amountDuffs} duffs, script ${o.rewardScriptHex}); not flipping, resolve by hand`);
        }
        participantBps += Number(so.shareBps);
      }
      // the PARTICIPANTS' shares must sum to exactly 10000 (each already matches its manifest
      // bps, and the manifest bps sum to 10000, so this holds; kept as a live cross-check)
      if (participantBps !== 10000) {
        throw new Error(`the manifest participants' share weights sum to ${participantBps} bps, ` +
          "expected 10000; not flipping (the manifest and draft are kept)");
      }
      const participantShareCount = manifest.owners.length;
      if (HALT === "shares") { console.log("[test hook] halting after SETTLE, before the flip"); return; }

      // phase 3, COMPLETION-RECORD LAST (invariant list item 1, scoped per the a soundness-review finding
      // fold): on a NORMAL run the completion record is published only after a
      // successful participant-share readback, so the ordering guarantee holds at that
      // instant. It is publication ORDERING, not an implication a reader can rely on
      // later: shares are mutable and the recovery path deliberately publishes from the
      // frozen draft with detection only. On the flip ledgers the record is the pool's own
      // flip; on an immutable-pool ledger it is the receipt alone, and THERE IS NO FLIP:
      // the entire flip block below is v8-and-earlier, and the v9 path drops straight
      // through to the receipt publication, which the review named "the flip step becomes
      // receipt publication only". The probe's atomicity has nothing left to protect with
      // one document to write (item 2), the laundering guard's anomaly class is carried by
      // the classifier preflight, verifyReceiptAgainstDraft and the byPool unique index
      // (item 3), and the drift re-checks' subject cannot occur on an immutable pool
      // (items 4 to 6).
      //
      // v8 couples the receipt to the flip when the SDK can express it (spec C-G):
      // the mixed create-receipt + replace-pool transition is PROBED live; if the
      // probe fails, the sequential fallback (flip, then the idempotent receipt
      // write) is safe because the active manifest and the frozen draft are retained
      // until the receipt is confirmed, so "live without receipt" is a recoverable
      // state, not a permanent one. FORMATION_NO_MIXED=1 forces the sequential path
      // (used by the live idempotence-resume probe).
      // F-D: re-assert the frozen slot economics against a FRESH pool object immediately
      // before ANY flip, closing a mid-run operator-credentialed slot change that a
      // load-time validateManifest would miss. Called for the first fetch here AND after
      // the mixed-transition fallback re-fetch (re-check: that path is also a flip path).
      if (!hasImmutablePool()) {
        const requireSlotsMatchFresh = (fo) => {
          if (manifest.slotDuffs !== undefined && Number(fo.slotDuffs) !== manifest.slotDuffs) {
            throw new Error(`the pool's slotDuffs changed to ${fo.slotDuffs} (committed ${manifest.slotDuffs}) ` +
              "before the flip; not flipping (the manifest and draft are kept)");
          }
          if (manifest.slotCount !== undefined && Number(fo.slotCount) !== manifest.slotCount) {
            throw new Error(`the pool's slotCount changed to ${fo.slotCount} (committed ${manifest.slotCount}) ` +
              "before the flip; not flipping (the manifest and draft are kept)");
          }
        };
        let fresh = await getPool(poolIdStr);
        requireSlotsMatchFresh(fresh.toObject());
        let freshHash = Buffer.from(fresh.toObject().proTxHash);
        if (core.isFormingHash(freshHash)) {
          // FLIP-FIRST ordering guard (round-4 blocker): a receipt must never exist while
          // the pool is still forming (the flip precedes the receipt). If one is already
          // there, it is an anomaly (a squatter refused by owner-only would not have
          // landed, so this is our own inconsistent state or a credentialed external
          // write), and flipping the pool "to fit it" would launder that anomaly. Stop
          // loudly BEFORE any flip; do not let the mixed probe's broad catch flip past it.
          if (isV8()) {
            const preExisting = (await client.platform.documents.get("poolLedger.completionReceipt",
              { where: [["poolId", "==", pool.getId()]] }))[0] || null;
            if (preExisting) {
              throw new Error(`a completionReceipt (${preExisting.getId().toString()}) already exists for ` +
                "this pool while it is still FORMING; the flip must precede the receipt, so this is an " +
                "anomalous state. Refusing to flip; the manifest and draft are kept, resolve by hand.");
            }
            // and the pool must still match the frozen draft BEFORE the flip (round-5): if
            // slotIndex/nodeType/fee drifted since the draft froze, flipping first would
            // leave a live pool whose only publishable receipt contradicts it (and a mixed
            // transition, if ever accepted, would atomically record the stale receipt).
            // Catch it here, before either flip path mutates anything.
            requireDraftMatchesPool(receiptDraft, fresh.toObject(), { requireFee: true });
          }
          let flippedByMixed = false;
          if (isV8() && process.env.FORMATION_NO_MIXED !== "1") {
            // the MIXED-TRANSITION PROBE (like the v6/v7 transfer probes): create the
            // receipt from the frozen draft and replace the pool in ONE operator batch
            const receiptDoc = await client.platform.documents.create(
              "poolLedger.completionReceipt", operator, receiptPropertiesFromDraft(pool, receiptDraft));
            fresh.set("proTxHash", realHash);
            fresh.set("status", "live"); // v8 is v5+, the one legitimate forming -> live edge
            try {
              await client.platform.documents.broadcast(
                { create: [receiptDoc], replace: [fresh] }, operator);
              flippedByMixed = true;
              console.log(`pool flipped LIVE with its receipt in ONE transition (mixed probe OK): ` +
                `proTxHash ${proTxHex}, receipt ${receiptDoc.getId().toString()}`);
            } catch (e) {
              // ONLY fall back on the known one-transition-limit rejection (round-4
              // blocker: catching EVERY error meant a duplicate-unique, i.e. a receipt
              // that appeared under a race, would still flip the pool). Anything else,
              // including a duplicate-unique, rethrows WITHOUT flipping.
              // ONLY the one-transition-limit rejection falls back (round-4). Match it by
              // the typed error name (robust to any message wrapping), else by EXACT
              // message equality. A SUBSTRING match is unsafe: a compound message such as
              // "Amount of document transitions must be less or equal to 1; duplicate
              // unique index" would then fall back and flip past a receipt that already
              // exists, re-opening the laundering path (round-4 re-check-2).
              const msg = (e && e.message) || String(e);
              const isTxnLimit = (e && e.name === "MaxDocumentsTransitionsExceededError")
                || msg === "Amount of document transitions must be less or equal to 1";
              if (!isTxnLimit) {
                throw new Error(`the coupled create+replace transition failed for a reason other than the ` +
                  `one-transition limit (${msg}); NOT flipping. The manifest and draft are kept, resolve by hand.`);
              }
              console.log(`MIXED-TRANSITION PROBE hit the one-transition limit; falling back to the ` +
                "sequential flip-then-receipt path (the draft and manifest are retained)");
              // the failed broadcast may have touched the local document objects, so the
              // sequential path re-fetches the pool before mutating anything, and re-asserts
              // the slot economics against THIS fresh object too (F-D re-check: a slot change
              // during the mixed attempt must not slip through the fallback flip)
              fresh = await getPool(poolIdStr);
              requireSlotsMatchFresh(fresh.toObject());
              freshHash = Buffer.from(fresh.toObject().proTxHash);
              // RE-QUERY for a receipt immediately before the sequential flip (round-4
              // re-check): a credentialed external writer could have created one DURING
              // the mixed probe's create/broadcast awaits, and Platform may surface the
              // transition-count error before the uniqueness check, so the earlier
              // pre-flip guard is not enough. The only irreducible window is between this
              // query and consensus inclusion of the flip.
              const raced = (await client.platform.documents.get("poolLedger.completionReceipt",
                { where: [["poolId", "==", pool.getId()]] }))[0] || null;
              if (raced) {
                throw new Error(`a completionReceipt (${raced.getId().toString()}) appeared for this pool ` +
                  "during the coupled-transition attempt, while it is still FORMING; refusing to flip past " +
                  "it. The manifest and draft are kept, resolve by hand.");
              }
              // re-check the draft against the freshly re-fetched pool before the
              // sequential flip too (round-5): the pool could have drifted during the
              // mixed-probe awaits
              // requireFee from the RE-FETCHED hash (round-6 re-check-2): a concurrent
              // actor could have flipped the pool during the mixed attempt, and post-flip
              // the fee is historical
              requireDraftMatchesPool(receiptDraft, fresh.toObject(), { requireFee: core.isFormingHash(freshHash) });
            }
          }
          if (!flippedByMixed) {
            if (core.isFormingHash(freshHash)) {
              fresh.set("proTxHash", realHash);
              if (isV5()) fresh.set("status", "live"); // the one legitimate forming -> live edge
              await client.platform.documents.broadcast({ replace: [fresh] }, operator);
              console.log(`pool flipped LIVE: proTxHash ${proTxHex}`);
            }
            if (HALT === "flip") { console.log("[test hook] halting after the FLIP, before the receipt"); return; }
          }
        } else if (freshHash.toString("hex") === manifest.realHash) {
          console.log("pool already live under the manifest's hash (resume after a post-flip crash)");
        } else {
          // the durable intent is NOT cleared: the on-ledger hash contradicts it, which
          // someone must look at (re-check blocker: never delete intent on a mismatch)
          throw new Error(`the pool is live under ${freshHash.toString("hex")}, which contradicts the ` +
            `committed manifest's ${manifest.realHash}; the manifest is kept, resolve by hand`);
        }
      }

      // v8: the receipt must be CONFIRMED on-ledger before any durable intent is
      // cleared (spec C-G). The strong-idempotence routine verifies whatever is there
      // (the mixed transition's receipt, a prior crashed run's receipt, or none yet)
      // field-by-field against the frozen draft and stops loudly on any mismatch.
      if (isV8()) {
        await writeReceiptIdempotent(pool, poolIdStr, receiptDraft);
      }

      // the finalized manifest is RETAINED under a completed key (review F-C3): with v7
      // claims mutable and deletable, this is the durable local record of which claims
      // and slots formed the pool. Only the ACTIVE key is cleared (its presence is what
      // means "a completion is in flight"), and on v8 only AFTER the receipt above is
      // confirmed; the frozen draft is cleared with it. ONE shared routine with the
      // `receipt` recovery path, so no path can leave a completion half-finalized.
      const doneKey = finalizeCompletion(poolIdStr, manifest);
      console.log(`\n=== FORMATION COMPLETE: ${participantShareCount} share(s), weights sum 10000 bps, ` +
        `${hasImmutablePool() ? "receipt published last (no flip on this ledger)"
          : `flip done last${isV8() ? ", receipt confirmed" : ""}`}, ` +
        `finalized manifest retained as ${doneKey} ===`);
      return;
    }

    if (cmd === "receipt") {
      // read AND recover (spec C-G, review L3-1): prints the pool's completion receipt,
      // re-verifying the embedded allocation from the receipt's own bytes; when the
      // pool is live WITHOUT a receipt (a crash between the flip and the receipt, or a
      // pre-v8 completion migrated forward), publishes it from the FROZEN RECEIPT
      // DRAFT, or rebuilds the draft from the retained FORMATION_DONE_ manifest (the
      // verification level is re-decided by the SAME preflight check).
      if (!isV8()) throw new Error("the receipt command needs a completion-receipt ledger (v8 or later)");
      const [poolIdStr] = args;
      if (!poolIdStr) throw new Error("usage: receipt <poolId>");
      takePoolOpLock(poolIdStr);
      const pool = await getPool(poolIdStr);
      const po = pool.toObject();
      // the M1 owner binding, same gate as `complete` (review blocker): this command
      // can WRITE (the recovery publish), so a pool this identity does not own is
      // refused up front
      requirePoolOwnedByOperator(pool, poolIdStr);
      // the local frozen state, loaded once: the draft, and the manifest (active
      // outranks done, because an active key means a completion is still in flight)
      const draftKey = receiptDraftKeyOf(poolIdStr);
      const activeKey = manifestKeyOf(poolIdStr);
      const doneKey = "FORMATION_DONE_" + journal.suffixFor(activeContractId(env), poolIdStr);
      const envNow = loadEnv();
      let draft = null;
      let draftFromArchive = false;
      if (envNow[draftKey] !== undefined) {
        try { draft = JSON.parse(envNow[draftKey]); } catch {
          throw new Error("the frozen receipt draft is corrupt; restore its .val.prev generation in .env.local.state/ (a restored generation is re-validated against the manifest and pool before use)");
        }
      }
      // the on-ledger receipt is fetched BEFORE the manifest-source selection, because on
      // an immutable-pool ledger the archive filter below needs it
      const existing = (await client.platform.documents.get("poolLedger.completionReceipt", {
        where: [["poolId", "==", pool.getId()]],
      }))[0] || null;
      // sources in priority: ACTIVE (a completion in flight) > DONE (retained record) >
      // ABANDONED (round-7 P1: a completion that landed during/after an abandon still has
      // its recovery inputs here, so `receipt` can finalize rather than strand it).
      // THE STALENESS FILTER IS LEDGER-DEPENDENT (invariant list item 12). On v8 the
      // archive is used ONLY when its committed realHash matches the pool's CURRENT hash
      // (round-7 re-check P2): a stale archive from an EARLIER abandon of this same pool
      // (later re-formed under a different hash) must never be picked as the manifest
      // source, or it would falsely contradict the real completion's receipt. On an
      // immutable pool there is no live hash, and the honest equivalent is STRICTER: the
      // archive is consulted only when an EXISTING RECEIPT matches its committed hash (the
      // lost-race finalize round-7 P1 protects), and never as a source to publish from,
      // because a receipt-less ledger carries no evidence the abandoned completion's
      // registration ever happened, and publishing from the archive alone would resurrect
      // an abandoned completion on no evidence.
      const abandonedKey = "FORMATION_ABANDONED_" + journal.suffixFor(activeContractId(env), poolIdStr);
      let abandonedManifest;
      let abandonedDraft;
      let archiveHadDraft = false;
      if (envNow[abandonedKey] !== undefined) {
        try {
          const archive = JSON.parse(envNow[abandonedKey]);
          const m = archive.manifest;
          const parsed = m ? JSON.parse(m) : null;
          if (parsed) {
            if (!hasImmutablePool()) {
              const liveHex = Buffer.from(po.proTxHash).toString("hex");
              if (parsed.realHash === liveHex) abandonedManifest = m;
            } else if (existing &&
                Buffer.from(existing.toObject().proTxHash).toString("hex") === parsed.realHash) {
              abandonedManifest = m;
            }
          }
          // a soundness-review finding: abandon archives the FROZEN DRAFT beside the manifest, and recovery
          // restored only the manifest, so the reconcile fell back to the
          // derivable-fields-only comparison and printed that l1Verification "has no
          // independent local source" while that source sat unread in the same archive.
          // A late receipt attesting a WEAKER verification level than the abandoned run
          // had frozen would have been accepted and finalized, and the archive holding
          // the contradiction cleared. The draft is restored here whenever the archive's
          // manifest was accepted above, so the exact comparison runs instead.
          // presence is tested EXPLICITLY, never by truthiness (closing-pass
          // confirmation): an empty-string draft is damage, and a falsy test
          // would read it as no draft at all and take the fallback
          if (abandonedManifest && archive.draft !== undefined && archive.draft !== null) {
            archiveHadDraft = true;
            // an UNPARSEABLE draft is damage too (closing-pass confirmation): swallowing
            // the parse error to `undefined` would slip past the refusal below and land
            // in manifest-only recovery, which is the very fallback that refusal exists
            // to prevent. archiveHadDraft records that a draft WAS archived, whether or
            // not its bytes survived.
            try { abandonedDraft = JSON.parse(archive.draft); } catch { abandonedDraft = undefined; }
          }
        } catch { abandonedManifest = undefined; abandonedDraft = undefined; }
      }
      const rawManifest = envNow[activeKey] !== undefined ? envNow[activeKey]
        : (envNow[doneKey] !== undefined ? envNow[doneKey] : abandonedManifest);
      const manifestIsActive = envNow[activeKey] !== undefined;
      // whether the source needs FINALIZING (active or archive), vs an already-final DONE.
      // re-check-2: an existing-DONE source must NOT trigger a finalize, because rewriting
      // DONE on every `receipt` inspection resets its mtime and postpones prune indefinitely.
      const manifestFromArchive = !manifestIsActive && envNow[doneKey] === undefined && abandonedManifest !== undefined;
      let manifest = null;
      if (rawManifest !== undefined) {
        try { manifest = JSON.parse(rawManifest); } catch {
          throw new Error("the retained manifest is corrupt; restore its .val.prev generation in .env.local.state/ (a restored generation is re-validated before use)");
        }
        validateManifest(manifest, poolIdStr, manifest.realHash, po);
      }
      // a soundness-review finding: with no live draft key, the ARCHIVED draft is the exact source, and it is
      // adopted only after passing the same full validation a live draft does.
      // A DAMAGED archived draft REFUSES (closing pass, major 2). The earlier fold
      // dropped it and fell back to the manifest-derivable comparison, reasoning that a
      // corrupt archive should not make recovery worse than it was. That reasoning was
      // WRONG, and the distinction is the whole point of a soundness-review finding: the archive's EXISTENCE
      // is itself evidence that exact evidence was meant to be here, so a damaged draft
      // is NOT the same state as never having had one. Falling back re-opens exactly the
      // l1Verification hole a soundness-review finding closed, and finalizing would then CLEAR the archive
      // holding the damaged bytes. Refusing preserves both the archive and its .val.prev
      // generation for hands.
      if (!draft && archiveHadDraft && !abandonedDraft) {
        throw new Error("the ARCHIVED receipt draft is present but its bytes do not parse. " +
          "This pool's abandon archive says an exact draft existed, so the weaker " +
          "manifest-only comparison must NOT be used in its place (it cannot check " +
          "l1Verification). Refusing and keeping the archive; restore its .val.prev " +
          "generation in .env.local.state/ and re-run, or resolve by hand.");
      }
      if (!draft && abandonedDraft) {
        try {
          validateReceiptDraft(abandonedDraft, poolIdStr, manifest);
          draft = abandonedDraft;
          draftFromArchive = true;
        } catch (e) {
          throw new Error("the ARCHIVED receipt draft is damaged and cannot be validated " +
            `(${(e && e.message) || e}). This pool's abandon archive says an exact draft ` +
            "existed, so the weaker manifest-only comparison must NOT be used in its place " +
            "(it cannot check l1Verification). Refusing and keeping the archive; restore " +
            "its .val.prev generation in .env.local.state/ and re-run, or resolve by hand.");
        }
      }
      if (draft) validateReceiptDraft(draft, poolIdStr, manifest);
      // the archived draft IS an original freeze (abandon persisted it after a successful
      // preflight), so its fee is the completion-time fee and a soundness-review finding comparison applies
      if (draft) {
        Object.defineProperty(draft, "__origin",
          { value: draftFromArchive || envNow[draftKey] !== undefined ? "frozen" : "rebuilt" });
      }

      if (existing) {
        const o = existing.toObject();
        // the receipt must be owned by the pool's operator (round-6): with no local draft
        // there is otherwise nothing binding the receipt's creator to the pool owner
        if (existing.getOwnerId().toString() !== pool.getOwnerId().toString()) {
          throw new Error(`the receipt is owned by ${existing.getOwnerId().toString()} but the pool by ` +
            `${pool.getOwnerId().toString()}; a receipt not written by the pool's operator is an anomaly, ` +
            "resolve by hand");
        }
        // the nodeType -> targetDuffs invariant (round-6): the schema only bounds targetDuffs
        // by a minimum, so a receipt could pair a regular nodeType with an evo target; the
        // two must agree
        if (!hasParedReceipt() && String(core.TARGETS[o.nodeType]) !== String(o.targetDuffs)) {
          // only the UNPARED receipt carries both fields; on a pared one the pool is the
          // sole carrier and the shared check below owns exactly this coherence (duty 3)
          throw new Error(`the receipt's targetDuffs ${o.targetDuffs} is not the ${o.nodeType} target ` +
            `${core.TARGETS[o.nodeType]}; internally contradictory receipt, treat it as suspect`);
        }
        // bind the receipt to CURRENT pool state (round-3, re-fetched round-6): re-read the
        // pool HERE, after the receipt query await, so a credentialed external pool mutation
        // during the window cannot slip a contradicting receipt past. A receipt for a still-
        // forming pool, or one whose hash contradicts the live pool, must stop loudly. The
        // hash and status halves exist only where the pool asserts a node (invariant list
        // item 9); the immutable pool asserts none, and its binding is the shared check.
        const poolNow = (await getPool(poolIdStr)).toObject();
        if (!hasImmutablePool()) {
          const poolHashNow = Buffer.from(poolNow.proTxHash);
          if (core.isFormingHash(poolHashNow)) {
            throw new Error("a completionReceipt exists but the pool is still FORMING; that receipt " +
              "was not written by this flow (the flip precedes the receipt). Local state is kept, " +
              "resolve by hand.");
          }
          if (poolNow.status !== undefined && poolNow.status !== "live") {
            throw new Error(`a completionReceipt exists but the pool status is "${poolNow.status}", not ` +
              "live; local state is kept, resolve by hand");
          }
          if (!poolHashNow.equals(Buffer.from(o.proTxHash))) {
            throw new Error(`the receipt records proTxHash ${Buffer.from(o.proTxHash).toString("hex")} ` +
              `but the pool is live under ${poolHashNow.toString("hex")}; the receipt contradicts the ` +
              "pool, local state is kept, resolve by hand");
          }
        }
        // the pool's CREATION-TIME constants (slotIndex, nodeType) must match the
        // receipt even when no local draft or manifest survives (round-4: after a prune
        // the branches below have nothing to compare against, so this is the only check
        // that binds those fields). The operator FEE is deliberately excluded, because
        // the pool's fee is mutable and may legitimately change after completion, so a
        // later divergence there is not a receipt anomaly. A pared receipt carries no
        // nodeType to differ; slotIndex is the one duplicated field left on it.
        if (poolNow.slotIndex !== undefined && Number(o.slotIndex) !== Number(poolNow.slotIndex)) {
          throw new Error(`the receipt records slotIndex ${Number(o.slotIndex)} but the pool has ` +
            `${Number(poolNow.slotIndex)}; the receipt contradicts the pool, resolve by hand`);
        }
        if (!hasParedReceipt() && poolNow.nodeType !== undefined && o.nodeType !== poolNow.nodeType) {
          throw new Error(`the receipt records nodeType ${o.nodeType} but the pool has ${poolNow.nodeType}; ` +
            "the receipt contradicts the pool, resolve by hand");
        }
        // the verification is ledger-dependent in who carries the target. The unpared
        // receipt carries its own copy, so the standalone allocation verifier suffices; the
        // pared receipt carries none, so the SHARED five-duty check against the pool is the
        // only thing pinning the embedded target to anything (phase B, round-4 finding).
        const check = hasParedReceipt()
          ? checkReceiptAgainstPool({ contractId: activeContractId(env), receipt: o,
            pool: poolNow, poolId: poolIdStr })
          : core.verifyReceiptAllocation(activeContractId(env), {
            allocationRows: Buffer.from(o.allocationRows),
            allocationHash: Buffer.from(o.allocationHash),
            poolId: Buffer.from(o.poolId),
            targetDuffs: String(o.targetDuffs),
            participantCount: Number(o.participantCount),
          });
        const shownNode = hasParedReceipt() ? `${poolNow.nodeType} (pool)` : o.nodeType;
        const shownFee = hasParedReceipt() ? `${Number(poolNow.operatorFeeBps)} bps (pool, pinned)`
          : `${Number(o.operatorFeeBps)} bps`;
        const shownTarget = hasParedReceipt() ? poolNow.targetDuffs : o.targetDuffs;
        console.log(`completion receipt ${existing.getId().toString()} (owner ` +
          `${existing.getOwnerId().toString()}):`);
        console.log(`  pool:          ${Identifier.from(Buffer.from(o.poolId)).toString()}`);
        console.log(`  proTxHash:     ${Buffer.from(o.proTxHash).toString("hex")}`);
        console.log(`  slot ${Number(o.slotIndex)}, ${shownNode}, fee ${shownFee}, ` +
          `target ${DASHfmt(BigInt(shownTarget))} DASH, ${Number(o.participantCount)} participant(s)`);
        console.log(`  l1Verification: ${o.l1Verification} (method v${Number(o.verificationMethodVersion)})`);
        console.log(`  allocationHash: ${Buffer.from(o.allocationHash).toString("hex")}`);
        if (!check.ok) {
          throw new Error(`the receipt FAILS verification ` +
            `${hasParedReceipt() ? "against this pool" : "of its OWN embedded allocation"} ` +
            `(${check.reason}); this receipt does not prove what it claims, treat it as suspect`);
        }
        console.log("  embedded allocation: canonical, hash recomputed and matches (verified from the " +
          `${hasParedReceipt() ? "receipt-plus-pool pair through the shared check" : "receipt alone"}; ` +
          "shares are mutable, so a live cross-check is `status`)");
        // a mismatched existing receipt must ALWAYS stop loudly, in this command too
        // (review major): when local frozen state exists, the receipt is held to it,
        // never merely printed as self-consistent
        if (draft) {
          verifyReceiptAgainstDraft(existing, draft);
          // invariant 5 at its full width on the immutable ledger (vetting round,
          // finding 6): verifyReceiptAgainstDraft deliberately omits the fee (historical
          // on a flipped v8 pool), but on v9 the fee CANNOT drift, so the frozen draft
          // is also held to the pool here, fee included, and a mismatch means a damaged
          // draft rather than a legitimate change
          if (hasImmutablePool()) requireDraftMatchesPool(draft, poolNow, { requireFee: true });
          console.log(draftFromArchive
            ? "  matches the ARCHIVED frozen draft field-by-field (restored from the abandon " +
              "archive, so l1Verification IS independently sourced here)"
            : "  matches the local FROZEN draft field-by-field");
        } else if (manifest) {
          const rows = core.allocationPreimage(activeContractId(env), manifest);
          const bad = [];
          if (!Buffer.from(o.allocationRows).equals(rows)) bad.push("allocationRows contradict the retained manifest");
          if (Buffer.from(o.proTxHash).toString("hex") !== manifest.realHash) bad.push("proTxHash contradicts the retained manifest");
          if (Number(o.participantCount) !== manifest.owners.length) bad.push("participantCount contradicts the manifest");
          // targetDuffs lives on whichever document the ledger says carries it; the
          // manifest's committed target must match that carrier either way
          if (hasParedReceipt()
            ? String(poolNow.targetDuffs) !== manifest.target
            : String(o.targetDuffs) !== manifest.target) {
            bad.push("targetDuffs contradicts the manifest");
          }
          // slotIndex/nodeType are pool CREATION constants and must match, compared
          // against the FRESH poolNow (round-6 re-check: the pre-query po could be stale
          // and falsely reject). The fee is NOT compared to the current pool (round-5),
          // because the pool fee is mutable and may legitimately change after
          // completion (the receipt records the completion-time fee).
          if (Number(o.slotIndex) !== Number(poolNow.slotIndex)
            || (!hasParedReceipt() && o.nodeType !== poolNow.nodeType)) {
            bad.push("slot/node contradict the pool document");
          }
          if (bad.length > 0) {
            throw new Error("the on-ledger receipt CONTRADICTS the retained manifest: " + bad.join("; ") +
              ". Refusing to reconcile; resolve by hand (the manifest is kept).");
          }
          console.log("  matches the retained manifest on every derivable field (l1Verification is the " +
            "receipt's attested value from completion time; it has no independent local source)");
        }
        // reconcile a half-finalized completion (review major): a confirmed matching
        // receipt with an UNFINALIZED local source (active manifest, an abandoned archive,
        // or a leftover draft) means a crash interrupted finalization; finish it here so a
        // later `complete` cannot rebuild from current pool values and falsely contradict
        // this receipt. F-E re-check folded the abandoned-archive source; re-check-2 EXCLUDES
        // an already-final DONE source (manifestFromArchive/manifestIsActive gate), because
        // re-finalizing rewrites DONE and resets its prune-age mtime on every inspection.
        if (manifestIsActive || manifestFromArchive || draft) {
          finalizeCompletion(poolIdStr, manifest || null);
          console.log("  local completion state finalized (manifest retained as done, draft cleared)");
        }
        return;
      }
      // "nothing to recover yet". On v8 that is a pool still in the forming namespace. On v9
      // there is no forming state on the pool, so the recoverable condition is instead
      // "local completion state exists but no receipt does", and a pool with NEITHER has
      // nothing to recover: `complete` is what starts it.
      if (!hasImmutablePool() && core.isFormingHash(Buffer.from(po.proTxHash))) {
        console.log("the pool is still FORMING; a receipt is written by `complete`");
        return;
      }
      if (hasImmutablePool() && !manifestIsActive && !manifestFromArchive && !draft) {
        // a FINALIZED record with no receipt is an ANOMALY here, not a recovery path: DONE
        // is written only after the receipt is confirmed, and the receipt document cannot
        // be deleted (canBeDeleted: false), so this state contradicts the contract and
        // must stop loudly rather than exit as "nothing to recover".
        if (envNow[doneKey] !== undefined) {
          throw new Error("a finalized completion record (FORMATION_DONE_) exists for this pool but " +
            "no receipt is on the ledger, and the receipt document cannot be deleted; this state " +
            "contradicts the contract, resolve by hand (the DONE record is kept)");
        }
        // an unaccepted ABANDON ARCHIVE deliberately does not reach this path (invariant
        // list item 12): with no receipt on the ledger there is no evidence the abandoned
        // completion's registration ever happened, so the abandon stands rather than being
        // republished from the archive alone. Say the archive exists rather than hiding it.
        console.log(envNow[abandonedKey] !== undefined
          ? "no receipt on the ledger; an abandon archive exists for this pool but is not " +
            "publishable on its own (the abandon stands; re-run `complete` to redo the formation)"
          : "no local completion state for this pool and no receipt on the ledger; " +
            "a receipt is written by `complete`");
        return;
      }
      // live without a receipt: the recoverable intermediate state. Publish from the
      // frozen draft; rebuild the draft from the retained manifest when only that
      // survived (its allocation is the frozen commitment; slot/node/fee come from the
      // pool document, and the verification level is re-decided, never assumed).
      if (draft) {
        // the fee context is ledger-dependent (invariant list item 5): historical on a
        // flipped pool, exact on an immutable one where it cannot have drifted
        requireDraftMatchesPool(draft, po, { requireFee: hasImmutablePool() });
        console.log("publishing the receipt from the FROZEN draft (post-crash recovery)");
      } else {
        if (!manifest) {
          throw new Error("no receipt, no frozen draft, and no retained manifest for this pool; " +
            "nothing durable to publish from (the honesty rule: never reconstruct from live state)");
        }
        // the live-hash cross-check has a subject only where the pool asserts a node; the
        // immutable pool asserts none, and the manifest is the operator's durable intent
        if (!hasImmutablePool()) {
          const liveHex = Buffer.from(po.proTxHash).toString("hex");
          if (manifest.realHash !== liveHex) {
            throw new Error(`the retained manifest commits to ${manifest.realHash} but the pool is live ` +
              `under ${liveHex}; refusing to publish a receipt from a contradicted manifest`);
          }
        }
        if (po.slotIndex === undefined || po.nodeType === undefined) {
          throw new Error("this pool lacks slotIndex/nodeType, so a v8 receipt cannot be recorded");
        }
        const target = core.TARGETS[po.nodeType];
        const level = await decideL1Verification(manifest.realHash, manifest, target, poolIdStr);
        const rowsBuf = core.allocationPreimage(activeContractId(env), manifest);
        draft = {
          v: 1, poolId: poolIdStr, proTxHash: manifest.realHash,
          slotIndex: Number(po.slotIndex), nodeType: po.nodeType,
          operatorFeeBps: Number(po.operatorFeeBps || 0), formatVersion: 1,
          allocationRowsHex: rowsBuf.toString("hex"),
          allocationHashHex: core.allocationHash(rowsBuf).toString("hex"),
          participantCount: manifest.owners.length,
          targetDuffs: journal.toSafeNumber(target, "target"),
          l1Verification: level, verificationMethodVersion: 1,
        };
        validateReceiptDraft(draft, poolIdStr, manifest); // self-check before persisting
        updateEnvKey(draftKey, JSON.stringify(draft));
        console.log("receipt draft REBUILT from the retained manifest (allocation from the frozen " +
          `commitment, level ${level} re-decided by the same registration verification check)`);
      }
      // a soundness-review finding (vetting round): the participant-scoped readback is REPEATED immediately
      // before a recovery publication, as DETECTION rather than a gate. The receipt
      // records the frozen completion-time allocation, shares are mutable afterwards,
      // and refusing here would strand a completed pool outside its receipt (the strand
      // the fee precedent already avoids), so a divergence is said loudly and the frozen
      // truth still publishes, the castReceipt discipline.
      {
        // the detection compares the SAME fields the normal readback verifies (weight,
        // contribution, reward script), not a presence-and-weight subset (fold
        // confirmation, 2026-08-03): a narrower recovery check would let exactly the
        // divergences the normal path refuses on pass this one silently
        const expected = manifest
          ? manifest.owners.map((o) => ({ owner: o.owner, bps: o.bps,
            amountDuffs: o.amountDuffs, rewardScriptHex: o.rewardScriptHex }))
          : JSON.parse(Buffer.from(draft.allocationRowsHex, "hex").toString("utf8"))[5]
            .map((r) => ({ owner: r[0], amountDuffs: r[1], bps: r[2], rewardScriptHex: r[3] }));
        for (const e of expected) {
          const found = await client.platform.documents.get("poolLedger.share", {
            where: [["poolId", "==", pool.getId()], ["$ownerId", "==", Identifier.from(e.owner)]],
          });
          const so = found[0] ? found[0].toObject() : null;
          if (!so) {
            console.log(`WARNING: participant ${e.owner} has NO share on the ledger at recovery time; ` +
              "the receipt records the frozen completion-time allocation and publishes anyway, and " +
              "the divergence is live state to reconcile, not a receipt defect");
            continue;
          }
          const drift = [];
          if (Number(so.shareBps) !== e.bps) drift.push(`${Number(so.shareBps)} bps vs frozen ${e.bps}`);
          if (e.amountDuffs !== undefined && BigInt(so.contributionDuffs).toString() !== String(e.amountDuffs)) {
            drift.push(`${so.contributionDuffs} duffs vs frozen ${e.amountDuffs}`);
          }
          if (e.rewardScriptHex && Buffer.from(so.l1RewardScript).toString("hex") !== e.rewardScriptHex) {
            drift.push("reward script differs from the frozen allocation");
          }
          if (drift.length > 0) {
            console.log(`WARNING: participant ${e.owner}'s live share diverges from the frozen ` +
              `allocation (${drift.join("; ")}); publishing the frozen truth anyway (shares are ` +
              "mutable, the receipt is the completion-time record)");
          }
        }
      }
      await writeReceiptIdempotent(pool, poolIdStr, draft);
      // full finalization, not just the draft clear (review major): retain the
      // manifest as done and clear the active key, so `complete` never rebuilds
      // against an already-confirmed receipt. F-E re-check: pass `manifest || null` so a
      // receipt published from the ABANDONED ARCHIVE still writes DONE before the archive
      // is cleared, rather than dropping the durable record.
      finalizeCompletion(poolIdStr, manifest || null);
      console.log("receipt published and confirmed; the live-without-receipt window is closed");
      return;
    }

    if (cmd === "abandon") {
      // the explicit exit from a committed-but-unresolvable completion (a member
      // cancelled after COMMIT, or the registration never happened): clears the
      // manifest so a new formation round can start. Only while the pool is still
      // FORMING; a live pool's manifest contradiction stays for manual resolution.
      const [poolIdStr] = args;
      if (!poolIdStr) throw new Error("usage: abandon <poolId>");
      takePoolOpLock(poolIdStr);
      const pool = await getPool(poolIdStr);
      // THE GUARD, asked so it means something on both ledgers. On v8 "still forming" was
      // read from proTxHash. On v9 there is no such field and no flip, so the equivalent
      // question is whether a COMPLETION RECORD exists: abandoning local state for a
      // completed pool would orphan the real thing, while abandoning it for a pool that
      // never completed orphans nothing, because an immutable pool with no receipt claims
      // nothing. mayAbandon also refuses while a CONTRADICTING receipt is unresolved, which
      // the v8 guard could not express at all.
      //
      // NOTE the v9 pool document survives abandonment permanently, since it cannot be
      // deleted. That is not litter: it is the same document an OPEN pool presents, which is
      // exactly why the funder client's admission rule fails closed rather than trying to
      // tell them apart.
      const cls = await classifyPoolNow(pool, poolIdStr);
      const verdict = lifecycle.mayAbandon(cls);
      if (!verdict.ok) throw new Error(`${verdict.reason}, refusing`);
      if (!hasImmutablePool() && !core.isFormingHash(Buffer.from(pool.toObject().proTxHash))) {
        throw new Error("the pool is LIVE; abandoning its manifest would orphan real state, refusing");
      }
      const key = manifestKeyOf(poolIdStr);
      const draftKey = receiptDraftKeyOf(poolIdStr);
      const envHere = loadEnv();
      const hasManifest = envHere[key] !== undefined;
      const hasDraft = isV8() && envHere[draftKey] !== undefined;
      // nothing to abandon: return cleanly BEFORE the participant extraction (re-check-2:
      // the extraction would otherwise fall into the draft parser and throw on absent state)
      if (!hasManifest && !hasDraft) { console.log("no committed manifest for this pool"); return; }

      // the OWNERS this manifest/draft explains (a soundness review): a crash during SETTLE leaves
      // PARTICIPANT shares on a still-forming pool, and the manifest is their only
      // explanation, so abandon must refuse then. But a FOREIGN share (any identity can
      // plant one) is not explained by the manifest and must NOT block abandon, or it
      // becomes a permanent wedge. Scope the share check to the participants only.
      // FAIL CLOSED on a damaged source (a soundness review): a parse failure here must NOT
      // yield an empty participant list, or abandon would clear state without checking any
      // participant share, destroying a manifest that may explain settled shares (and on
      // v1-v7 there is no archive to recover from). Refuse instead.
      const participantOwners = (() => {
        // require a NONEMPTY owner set (re-check-2): a legitimate manifest/draft always has
        // >=1 owner, so an empty (or unparseable) array is damage and must fail closed, not
        // yield zero participant checks that let abandon clear the source blind.
        if (hasManifest) {
          let owners;
          try { owners = JSON.parse(envHere[key]).owners; } catch { owners = undefined; }
          if (!Array.isArray(owners) || owners.length === 0) throw new Error("the committed manifest is " +
            "unparseable or empty; refusing to abandon (cannot tell which shares it explains). Restore its " +
            ".val.prev generation or resolve by hand.");
          return owners.map((o) => o.owner);
        }
        // draft-only case: extract owners from the frozen allocation rows
        let rows;
        try { rows = JSON.parse(Buffer.from(JSON.parse(envHere[draftKey]).allocationRowsHex, "hex").toString("utf8"))[5]; }
        catch { rows = undefined; }
        if (!Array.isArray(rows) || rows.length === 0) throw new Error("the frozen receipt draft is " +
          "unparseable or empty; refusing to abandon. Restore its .val.prev generation or resolve by hand.");
        return rows.map((r) => r[0]);
      })();
      const participantSharesOnLedger = async () => {
        const present = [];
        for (const owner of participantOwners) {
          const found = await client.platform.documents.get("poolLedger.share", {
            where: [["poolId", "==", pool.getId()], ["$ownerId", "==", Identifier.from(owner)]],
          });
          if (found.length > 0) present.push(owner);
        }
        return present;
      };
      const settledEarly = await participantSharesOnLedger();
      if (settledEarly.length > 0) {
        throw new Error(`${settledEarly.length} PARTICIPANT share(s) already exist on this forming pool ` +
          "(a completion got past SETTLE); the manifest is their only explanation, refusing to delete it. " +
          "Resume `complete` with the committed hash, or unwind the shares with their owners first.");
      }

      // RE-FETCH pool and shares immediately before the mutation (round-7 P1): the checks
      // above ran before this point, and the op lock excludes only the completion-protocol
      // commands, not a member creating a share or an operator-credentialed flip. Deleting
      // the manifest after the pool went live (losing the only inputs `receipt` recovers
      // from) or after a share appeared (losing its only explanation) is the exact
      // evidence loss abandon must not cause. Re-assert both, closing the window to the
      // synchronous clears below.
      const poolNow = (await getPool(poolIdStr)).toObject();
      if (!hasImmutablePool()) {
        if (!core.isFormingHash(Buffer.from(poolNow.proTxHash))) {
          throw new Error("the pool went LIVE since this run started; abandoning now would orphan a live " +
            "pool's recovery inputs. Run `receipt` to publish from the retained manifest instead. Kept.");
        }
      } else {
        // the immutable pool cannot flip, so the late evidence a re-fetch can catch is a
        // RECEIPT having appeared since the classifier ran (invariant list item 11)
        const raced = await fetchReceiptFor(pool);
        if (raced) {
          throw new Error("a completion receipt appeared for this pool since this run started; " +
            "abandoning now would orphan its recovery inputs. Run `receipt` to reconcile instead. Kept.");
        }
      }
      const settledNow = await participantSharesOnLedger(); // participant-scoped (a soundness review), like the early check
      if (settledNow.length > 0) {
        throw new Error(`${settledNow.length} PARTICIPANT share(s) appeared on this forming pool since this ` +
          "run started; the manifest is their only explanation, refusing to delete it. Kept.");
      }

      // ARCHIVE before clearing (round-7 P1): a residual microscopic window remains
      // between the re-fetch and the synchronous clears, and abandon is destructive, so
      // persist the manifest and draft under FORMATION_ABANDONED_ (an owned FORMATION_
      // key) FIRST. `receipt` consults this archive if the pool is later found live under
      // the archived hash, so even a lost race stays recoverable rather than stranded.
      // RECEIPT LEDGERS ONLY (F-J, label widened by the vetting round: isV8 is the
      // completion-receipt capability, so v9 correctly takes this path too): the archive
      // exists solely for the `receipt` recovery path, which
      // is the only reader and the only cleaner. On v1-v7 it would be written but never read
      // or cleared, a permanent state leak, so skip it there.
      const abandonedKey = "FORMATION_ABANDONED_" + journal.suffixFor(activeContractId(env), poolIdStr);
      if (isV8()) {
        updateEnvKey(abandonedKey, JSON.stringify({
          manifest: hasManifest ? envHere[key] : null,
          draft: hasDraft ? envHere[draftKey] : null,
          at: poolNow.proTxHash ? Buffer.from(poolNow.proTxHash).toString("hex") : null,
        }));
      }
      // the frozen receipt draft goes WITH the manifest it froze (follow-up review): draft
      // first, manifest second, so no interleaving leaves a draft without its manifest.
      if (hasDraft) updateEnvKey(draftKey, undefined);
      if (hasManifest) updateEnvKey(key, undefined);
      console.log(`${hasManifest ? "committed manifest" : "leftover receipt draft"}${hasManifest && hasDraft
        ? " and frozen receipt draft" : ""} CLEARED${isV8() ? ` (archived to ${abandonedKey} for recovery)` : ""}. ` +
        "The frozen allocation is abandoned; pledges still on the ledger remain pending (members can cancel " +
        "or keep them for a re-formation).");
      return;
    }

    throw new Error(`unknown command "${cmd}" (create | status | complete | receipt | abandon | done)`);
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (heldOpLock) releaseOpLock(heldOpLock);
    if (client.disconnect) await client.disconnect();
  }
})();
