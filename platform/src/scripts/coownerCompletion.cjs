"use strict";
/**
 * THE CO-OWNER COMPLETION CHECK, the Platform side of co-owned formation (2026-09-27).
 *
 * WHAT IT DECIDES. Whether a pool may be completed against a registered shared masternode, and if
 * so the completion receipt's fields. `decideCompletion` is the one composition the runner calls; it
 * reads nothing itself. It compares three inputs, each produced independently of the others:
 *   1. the members' slot claims on Platform, each written by that member's own identity and naming
 *      that member's reward script (the runner reads them by proof);
 *   2. the registration as Core reports it (`protx info`): each share's owner, refund and reward
 *      addresses and scripts, its amount, the early-exit period and penalty, the operator key, the
 *      voting address and the operator reward;
 *   3. each member's own preserved terms, the complete agreement that member accepted before
 *      signing anything.
 * It REFUSES on any disagreement, before anything is written, and reports every disagreement it
 * finds rather than only the first.
 *
 * HOW A TERMS SET IS TIED TO ITS PLATFORM MEMBER, stated because it is the weakest link. The
 * association is FIXTURE-BASED: a terms set names a Platform identity because the demonstration
 * wrote it that way. Nothing signs that pairing, neither the identity over the owner key nor the
 * owner key over the identity. What IS signed is narrower: the slot claims are written by the
 * member's identity and name a reward script, and completion requires that script to equal the
 * reward script of the registered share the member's terms assign to it. A production flow needs a
 * proven association, which is the deferred member-written record.
 *
 * SEPARATE FROM THE MEMBER'S OWN CHECK. Each member's wallet compares the transaction with its
 * agreement before signing funding inputs (tegara/l1/pasta-build/rc1_member_check.py, a soundness-review finding). This
 * check runs afterwards, on Platform's side, reads what was registered, and shares no code with it.
 *
 * WHAT A PASS SUPPORTS ON THE LEDGER. The receipt records `amount-reward-verified`, the strongest
 * level the contract defines, which is what its allocation carries: the (amount, reward) pairing.
 * The owner, refund and early-exit comparison happens here and is kept in the run's own record. A
 * third party cannot re-check it from Platform alone.
 *
 * THE OPERATOR REWARD'S UNIT. It is compared exactly as the node prints it. The DIP-0026 fork's
 * source prints the registration payload's value divided by 100 (a percentage), rc.1's source was
 * not read, and the demonstration uses 0, where the two forms agree, so the unit is untested.
 */
const formationCore = require("./formationCore.cjs");
const { servedCreatedAt } = require("./e2FinalEpoch.cjs"); // the one conversion of a served $createdAt

const HEX = /^[0-9a-f]*$/;
const HEX64 = /^[0-9a-f]{64}$/;
class CompletionRefusal extends Error {}
const refuse = (why) => { throw new CompletionRefusal(why); };
const isInt = (v) => Number.isSafeInteger(v);

/** The pool's claim book as ONE manifest: the book must be full, every slot claimed once, and each
 *  member's claims must name one reward script. Owners, amounts and weights come from the existing
 *  formation helpers (aggregateByOwner, allocateBps, requireTierOwnerCount). */
function manifestFromClaims({ poolIdB58, pool, claims }) {
  const target = BigInt(pool.targetDuffs);
  const slotDuffs = BigInt(pool.slotDuffs);
  const slotCount = Number(pool.slotCount);
  if (!isInt(slotCount) || slotCount < 1 || slotDuffs * BigInt(slotCount) !== target) {
    refuse(`the pool's slot book (${pool.slotCount} x ${pool.slotDuffs}) does not make its target ${pool.targetDuffs}`);
  }
  if (!Array.isArray(claims)) refuse("the claims are not a list");
  const seen = new Set();
  const scriptByOwner = new Map();
  for (const c of claims) {
    if (!isInt(c.slotNo) || c.slotNo < 0 || c.slotNo >= slotCount) refuse(`a claim names slot ${c.slotNo}, outside 0..${slotCount - 1}`);
    if (seen.has(c.slotNo)) refuse(`slot ${c.slotNo} is claimed twice`);
    seen.add(c.slotNo);
    if (typeof c.rewardScriptHex !== "string" || !HEX.test(c.rewardScriptHex) || c.rewardScriptHex.length === 0) {
      refuse(`the claim on slot ${c.slotNo} carries no reward script`);
    }
    const had = scriptByOwner.get(c.ownerB58);
    if (had !== undefined && had !== c.rewardScriptHex) refuse(`member ${c.ownerB58}'s claims name more than one reward script`);
    scriptByOwner.set(c.ownerB58, c.rewardScriptHex);
  }
  if (seen.size !== slotCount) refuse(`the slot book is not full: ${seen.size} of ${slotCount} slots claimed`);
  const owners = formationCore.aggregateByOwner(claims.map((c) => ({
    id: `${c.slotNo}`, owner: c.ownerB58, amount: slotDuffs, at: Number(c.createdAt) })));
  formationCore.requireTierOwnerCount(owners.length);
  const alloc = formationCore.allocateBps(owners, target);
  return { poolId: poolIdB58, target: String(target), owners: alloc.map((a) => ({
    owner: a.owner, amountDuffs: String(a.amount), bps: a.bps, rewardScriptHex: scriptByOwner.get(a.owner) })) };
}

/** The registration as Core's `protx info` reports it, every field this check compares required. */
function registeredFromCore(info) {
  const st = info && info.state;
  if (!st || !Array.isArray(st.shares) || st.shares.length === 0) refuse("Core's answer carries no share table");
  const shares = st.shares.map((s, i) => {
    for (const k of ["ownerAddress", "refundAddress", "rewardAddress"]) {
      if (typeof s[k] !== "string" || !s[k]) refuse(`Core's share ${i} has no ${k}`);
    }
    for (const k of ["refundScript", "rewardScript"]) {
      if (typeof s[k] !== "string" || !HEX.test(s[k]) || !s[k]) refuse(`Core's share ${i} has no ${k}`);
    }
    if (!isInt(s.amount) || s.amount <= 0) refuse(`Core's share ${i} has no amount`);
    return { ownerAddress: s.ownerAddress, refundAddress: s.refundAddress, rewardAddress: s.rewardAddress,
      refundScript: s.refundScript, rewardScript: s.rewardScript, amount: s.amount };
  });
  if (!isInt(st.earlyPeriodBlocks) || !isInt(st.earlyPenalty)) refuse("Core's answer has no early-exit terms");
  if (typeof st.pubKeyOperator !== "string" || typeof st.votingAddress !== "string") refuse("Core's answer has no operator or voting key");
  if (typeof info.operatorReward !== "number") refuse("Core's answer has no operator reward");
  return { proTxHash: info.proTxHash, shares, earlyPeriodBlocks: st.earlyPeriodBlocks, earlyPenalty: st.earlyPenalty,
    pubKeyOperator: st.pubKeyOperator, votingAddress: st.votingAddress, operatorReward: info.operatorReward };
}

const recordOf = (s) => [s.ownerAddress, s.refundAddress, s.rewardAddress, s.amount];
const TERMS = [["earlyPeriodBlocks", "earlyPeriodBlocks"], ["earlyPenalty", "earlyPenalty"],
  ["pubKeyOperator", "operatorPubKey"], ["votingAddress", "votingAddress"], ["operatorReward", "operatorReward"]];
const commonTerms = (a) => JSON.stringify({ shares: (a.shares || []).map(recordOf),
  terms: TERMS.map(([, k]) => a[k]) });

/** Every disagreement between the claims' manifest, the registration and the members' terms. */
function checkCompletion({ manifest, registered, termsSets }) {
  const refusals = [];
  // 1. the existing registration verification pairing, with reward SCRIPTS as the destination key (the claims carry scripts)
  const pair = formationCore.verifyRegistration(
    manifest.owners.map((o) => ({ amountDuffs: o.amountDuffs, rewardAddress: o.rewardScriptHex })),
    registered.shares.map((s) => ({ amountDuffs: String(s.amount), rewardAddress: s.rewardScript })),
    manifest.target);
  if (!pair.ok) refusals.push(`amount and reward pairing (registration verification): ${pair.reason || pair.mismatches.join("; ")}`);

  // 2. each claiming member has exactly one terms set, and each terms set belongs to a claiming member
  const byIdentity = new Map();
  for (const t of termsSets) {
    if (byIdentity.has(t.platformIdentityB58)) refusals.push(`two terms sets name identity ${t.platformIdentityB58}`);
    byIdentity.set(t.platformIdentityB58, t);
  }
  const claimants = new Set(manifest.owners.map((o) => o.owner));
  for (const o of manifest.owners) {
    if (!byIdentity.has(o.owner)) refusals.push(`member ${o.owner} holds claims but has no preserved terms associated with it`);
  }
  for (const t of termsSets) {
    if (!claimants.has(t.platformIdentityB58)) refusals.push(`the terms set of ${t.member} names identity ${t.platformIdentityB58}, which holds no claim in this pool`);
  }

  // 3. the members agreed the same table and terms (only which share is theirs may differ)
  if (new Set(termsSets.map((t) => commonTerms(t.agreement))).size > 1) {
    refusals.push("the members' preserved terms do not agree with each other");
  }

  // 4. what was registered against what was agreed
  const agreed = termsSets.length ? termsSets[0].agreement : null;
  if (agreed) {
    if ((agreed.shares || []).length !== registered.shares.length) {
      refusals.push(`the registration has ${registered.shares.length} shares, the agreed table ${(agreed.shares || []).length}`);
    }
    registered.shares.forEach((s, i) => {
      const a = (agreed.shares || [])[i];
      if (!a) return;
      [["ownerAddress", "owner"], ["refundAddress", "refund address"], ["rewardAddress", "reward address"], ["amount", "amount"]]
        .forEach(([k, name]) => { if (s[k] !== a[k]) refusals.push(`share ${i}'s registered ${name} ${s[k]} is not the agreed ${a[k]}`); });
    });
    for (const [rk, ak] of TERMS) {
      if (registered[rk] !== agreed[ak]) refusals.push(`the registered ${rk} ${registered[rk]} is not the agreed ${agreed[ak]}`);
    }
  }

  // 5. each share is assigned to at most one member, and each member's CLAIMS are bound to the share
  //    its terms assign by BOTH what the claims carry, the amount and the reward script (a review
  //    found a script-only binding let a member take the 600 DASH share on 400 DASH of claims when
  //    both shares paid one reward script)
  const assignedTo = new Map();
  for (const t of termsSets) {
    const i = t.agreement.myIndex;
    if (assignedTo.has(i)) refusals.push(`${t.member} and ${assignedTo.get(i)} are both assigned share ${i}`);
    else assignedTo.set(i, t.member);
    const own = isInt(i) && Array.isArray(t.agreement.shares) ? t.agreement.shares[i] : undefined;
    if (own && String(own.amount) !== String(t.agreement.myContributionDuffs)) {
      refusals.push(`${t.member}'s terms assign it a share of ${own.amount} but state a contribution of ${t.agreement.myContributionDuffs}`);
    }
  }
  for (const o of manifest.owners) {
    const t = byIdentity.get(o.owner);
    if (!t) continue;
    const i = t.agreement.myIndex;
    const s = registered.shares[i];
    if (!isInt(i) || !s) { refusals.push(`${t.member}'s terms assign share ${i}, which the registration lacks`); continue; }
    if (String(t.agreement.myContributionDuffs) !== o.amountDuffs) {
      refusals.push(`${t.member}'s terms contribute ${t.agreement.myContributionDuffs}, its claims ${o.amountDuffs}`);
    }
    if (String(s.amount) !== o.amountDuffs) {
      refusals.push(`${t.member}'s claims total ${o.amountDuffs}, the share its terms assign holds ${s.amount}`);
    }
    if (s.rewardScript !== o.rewardScriptHex) {
      refusals.push(`${t.member}'s claims name reward script ${o.rewardScriptHex}, the share its terms assign names ${s.rewardScript}`);
    }
  }
  return { ok: refusals.length === 0, refusals };
}

/** The claims each member will write, from the members' terms and the pool: each member takes
 *  consecutive slots in share order, as many as its contribution fills. Refuses unless there are
 *  terms, every share index is assigned once, every contribution is a whole number of slots, and
 *  the contributions fill the pool exactly. Returns [{ member, identityB58, slots, rewardScriptHex }]. */
function planClaims({ terms, pool }) {
  if (!Array.isArray(terms) || terms.length === 0) refuse("there are no preserved terms to claim from");
  const slotDuffs = BigInt(pool.slotDuffs);
  const target = BigInt(pool.targetDuffs);
  const ordered = [...terms].sort((a, b) => a.agreement.myIndex - b.agreement.myIndex);
  ordered.forEach((t, k) => { if (t.agreement.myIndex !== k) refuse(`the terms do not assign shares 0..${ordered.length - 1} once each`); });
  let next = 0;
  let total = 0n;
  const plan = ordered.map((t) => {
    const c = BigInt(t.agreement.myContributionDuffs);
    if (c <= 0n || c % slotDuffs !== 0n) refuse(`${t.member}'s contribution ${c} is not a whole number of ${slotDuffs}-duff slots`);
    if (typeof t.rewardScriptHex !== "string" || !HEX.test(t.rewardScriptHex) || !t.rewardScriptHex) refuse(`${t.member}'s terms carry no reward script`);
    const n = Number(c / slotDuffs);
    total += c;
    const slots = Array.from({ length: n }, (_, i) => next + i);
    next += n;
    return { member: t.member, identityB58: t.platformIdentity.b58, slots, rewardScriptHex: t.rewardScriptHex };
  });
  if (total !== target) refuse(`the contributions total ${total}, not the pool's ${target}`);
  return plan;
}

/** The claim step's read-back check, extracted from the runner so a battery drives it: the book served
 *  after claiming must be full (manifestFromClaims) and every slot must carry the owner and reward
 *  script the plan gave it. Returns null when both hold, else why not. */
function verifyClaimBook({ plan, readBack, poolIdB58, pool }) {
  try { manifestFromClaims({ poolIdB58, pool, claims: readBack }); }
  catch (e) { return `the book read back is not full: ${e.message}`; }
  const want = new Map(plan.flatMap((p) => p.slots.map((n) => [n, `${p.identityB58}|${p.rewardScriptHex}`])));
  const off = readBack.filter((c) => want.get(c.slotNo) !== `${c.ownerB58}|${c.rewardScriptHex}`).map((c) => c.slotNo);
  return off.length ? `slots ${off.join(", ")} differ from the plan` : null;
}

/** The whole decision: the manifest from the claims, the registration from Core, the check, and on a
 *  pass the receipt's fields. A refusal from any step is returned, never thrown past the caller. */
function decideCompletion({ contractId, poolIdB58, poolIdHex, pool, claims, protxInfo, proTxDisplayHex, termsSets }) {
  try {
    if (!HEX64.test(poolIdHex || "")) refuse("the pool id is not 64 lowercase hex");
    if (!HEX64.test(proTxDisplayHex || "")) refuse("the registration hash is not 64 lowercase hex");
    if (protxInfo && protxInfo.proTxHash !== proTxDisplayHex) refuse("Core's answer is for a different registration");
    const manifest = manifestFromClaims({ poolIdB58, pool, claims });
    const registered = registeredFromCore(protxInfo);
    const res = checkCompletion({ manifest, registered, termsSets: termsSets || [] });
    if (!res.ok) return { ok: false, refusals: res.refusals, manifest, registered };
    const rows = formationCore.allocationPreimage(contractId, manifest);
    return { ok: true, refusals: [], manifest, registered, receipt: {
      poolId: Buffer.from(poolIdHex, "hex"), proTxHash: Buffer.from(proTxDisplayHex, "hex"),
      slotIndex: pool.slotIndex, formatVersion: 1, allocationRows: rows,
      allocationHash: formationCore.allocationHash(rows), participantCount: manifest.owners.length,
      l1Verification: "amount-reward-verified", verificationMethodVersion: 1 } };
  } catch (e) {
    if (e instanceof CompletionRefusal) return { ok: false, refusals: [e.message] };
    return { ok: false, refusals: [`the inputs could not be checked: ${e.message}`] };
  }
}

// ---- served documents into the plain data decideCompletion reads (the runner's reads are proved) ----
const idOf = (v, what) => {
  const b58 = v && typeof v.base58 === "function" ? v.base58() : (typeof v === "string" ? v : null);
  const bytes = b58 !== null ? formationCore.decodeId32(b58) : null;
  if (!bytes) refuse(`the served ${what} does not decode to a 32-byte identifier`);
  return { b58, hex: bytes.toString("hex") };
};
const propsOf = (doc, what) => {
  const p = doc && typeof doc.getProperties === "function" ? doc.getProperties() : doc && doc.properties;
  if (!p || typeof p !== "object") refuse(`the served ${what} has no properties`);
  return p;
};
const hexOf = (v) => (v instanceof Uint8Array || Buffer.isBuffer(v)) ? Buffer.from(v).toString("hex") : null;
const numOf = (v) => (typeof v === "bigint" ? Number(v) : v);

/** The pool as decideCompletion reads it, from the one served pool document. */
function poolFromDoc(doc) {
  const p = propsOf(doc, "pool");
  const pool = { slotIndex: numOf(p.slotIndex), nodeType: p.nodeType, targetDuffs: String(numOf(p.targetDuffs)),
    slotDuffs: p.slotDuffs === undefined ? undefined : String(numOf(p.slotDuffs)), slotCount: numOf(p.slotCount) };
  if (!isInt(pool.slotIndex) || pool.slotDuffs === undefined || !isInt(pool.slotCount)) {
    refuse("the served pool has no slot book, so its claims cannot be read as a manifest");
  }
  return { id: idOf(doc.id !== undefined ? doc.id : doc.$id, "pool id"), owner: idOf(doc.ownerId !== undefined ? doc.ownerId : doc.$ownerId, "pool owner"), pool };
}

/** The claims as decideCompletion reads them, from the served pledgeSlot documents of ONE pool. */
function claimsFromDocs(docs, poolIdHex) {
  if (!Array.isArray(docs)) refuse("the served claims are not a list");
  return docs.map((d, i) => {
    const p = propsOf(d, `claim ${i}`);
    if (hexOf(p.poolId) !== poolIdHex) refuse(`served claim ${i} belongs to another pool`);
    const script = hexOf(p.rewardScript);
    if (!script || !isInt(numOf(p.slotNo))) refuse(`served claim ${i} lacks its slot or reward script`);
    const createdAt = servedCreatedAt(d, `claim ${i}`);
    return { slotNo: numOf(p.slotNo), ownerB58: idOf(d.ownerId !== undefined ? d.ownerId : d.$ownerId, `claim ${i} owner`).b58,
      rewardScriptHex: script, createdAt };
  });
}

module.exports = { decideCompletion, manifestFromClaims, registeredFromCore, checkCompletion, poolFromDoc, claimsFromDocs, planClaims, verifyClaimBook, CompletionRefusal };
