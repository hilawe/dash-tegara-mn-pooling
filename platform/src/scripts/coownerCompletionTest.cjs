// The co-owner completion check's offline battery. Its base is a REAL registration: the `protx info`
// answer a Dash Core v24.0.0-rc.1 node gave for a two-member shared masternode, with the two members'
// own agreements from the same run (fixtures/coowner-completion-rc1-R1.json names the run). The slot
// claims are built to match it. Each contrary case changes one input, asserts that the refusal names
// that input, and asserts that no receipt comes back.
const fs = require("fs");
const path = require("path");
const { decideCompletion } = require("./coownerCompletion.cjs");
const formationCore = require("./formationCore.cjs");

const FIX = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "coowner-completion-rc1-R1.json"), "utf8"));
let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const clone = (x) => JSON.parse(JSON.stringify(x));

const CONTRACT = "GJWKJLZF3PHm8HuUwz4JCL2PkTmvDqcYV2GagYaQ6mq";
const POOL_B58 = "8hgVYBkeTTMg9PttNfYt5M57TE828TU1x3JNg7occUF6"; // any well-formed 32-byte id serves offline
const POOL_HEX = formationCore.decodeId32(POOL_B58).toString("hex");
const A = FIX.platformIdentities.memberA.b58;
const B = FIX.platformIdentities.memberB.b58;
const SCRIPT_A = FIX.protxInfo.state.shares[0].rewardScript;
const SCRIPT_B = FIX.protxInfo.state.shares[1].rewardScript;
const OTHER_ADDR = "yNMNAgh59FiuFqhCRoVJLFHBGUoPtVbzMW";

const claimsFor = (split = [6, 4], scripts = [SCRIPT_A, SCRIPT_B]) => {
  const out = [];
  for (let s = 0; s < 10; s++) {
    const a = s < split[0];
    out.push({ slotNo: s, ownerB58: a ? A : B, rewardScriptHex: a ? scripts[0] : scripts[1], createdAt: 1000 + s });
  }
  return out;
};
const base = () => ({
  contractId: CONTRACT, poolIdB58: POOL_B58, poolIdHex: POOL_HEX,
  pool: { slotIndex: 0, nodeType: "regular", targetDuffs: "100000000000", slotDuffs: "10000000000", slotCount: 10 },
  claims: claimsFor(), protxInfo: clone(FIX.protxInfo), proTxDisplayHex: FIX.proTxHash,
  termsSets: [
    { member: "memberA", platformIdentityB58: A, agreement: clone(FIX.agreements.memberA) },
    { member: "memberB", platformIdentityB58: B, agreement: clone(FIX.agreements.memberB) },
  ],
});
const both = (input, fn) => { input.termsSets.forEach((t) => fn(t.agreement)); return input; };
const refuses = (name, input, needle) => {
  const r = decideCompletion(input);
  ok(`${name}: refused, no receipt, naming "${needle}" (got ${JSON.stringify(r.refusals)})`,
    r.ok === false && r.receipt === undefined && r.refusals.some((m) => m.includes(needle)));
  return r;
};

// ---- the matching completion ----
{
  const r = decideCompletion(base());
  ok("the matching inputs complete", r.ok === true && r.refusals.length === 0);
  ok("the manifest carries 600 and 400 DASH at 6000 and 4000 bps",
    r.manifest && JSON.stringify(r.manifest.owners.map((o) => [o.owner, o.amountDuffs, o.bps]))
      === JSON.stringify([[A, "60000000000", 6000], [B, "40000000000", 4000]]));
  ok("the receipt records amount-reward-verified for two participants",
    r.receipt && r.receipt.l1Verification === "amount-reward-verified" && r.receipt.participantCount === 2
      && r.receipt.slotIndex === 0 && r.receipt.proTxHash.toString("hex") === FIX.proTxHash);
  const v = formationCore.verifyReceiptAllocation(CONTRACT,
    { allocationRows: r.receipt.allocationRows, allocationHash: r.receipt.allocationHash, poolId: POOL_B58, participantCount: 2 });
  ok(`the receipt's allocation verifies on its own (${v.reason || "ok"})`, v.ok === true);
}

// ---- disagreements the existing (amount, reward) pairing cannot see ----
{
  const input = both(base(), (a) => { a.shares[1].refundAddress = OTHER_ADDR; });
  const pairing = formationCore.verifyRegistration(
    [{ amountDuffs: "60000000000", rewardAddress: SCRIPT_A }, { amountDuffs: "40000000000", rewardAddress: SCRIPT_B }],
    FIX.protxInfo.state.shares.map((s) => ({ amountDuffs: String(s.amount), rewardAddress: s.rewardScript })), "100000000000");
  ok("the existing amount-reward pairing alone passes this registration", pairing.ok === true);
  refuses("B's agreed refund address differs from the registered one", input, "share 1's registered refund address");
}
refuses("A's agreed owner key differs from the registered one", both(base(), (a) => { a.shares[0].ownerAddress = OTHER_ADDR; }),
  "share 0's registered owner");
refuses("the agreed early-exit penalty differs", both(base(), (a) => { a.earlyPenalty = a.earlyPenalty / 10; }), "earlyPenalty");
refuses("the agreed early period differs", both(base(), (a) => { a.earlyPeriodBlocks = 50; }), "earlyPeriodBlocks");
refuses("the agreed operator key differs", both(base(), (a) => { a.operatorPubKey = "00".repeat(48); }), "pubKeyOperator");
refuses("the agreed voting address differs", both(base(), (a) => { a.votingAddress = OTHER_ADDR; }), "votingAddress");
refuses("the registered shares in the other order", (() => { const i = base(); i.protxInfo.state.shares.reverse(); return i; })(),
  "share 0's registered owner");

// ---- association and agreement between the members ----
refuses("A holds claims with no terms set", (() => { const i = base(); i.termsSets = i.termsSets.slice(1); return i; })(),
  `member ${A} holds claims but has no preserved terms`);
refuses("a terms set names an identity holding no claim", (() => { const i = base(); i.termsSets[1].platformIdentityB58 = POOL_B58; return i; })(),
  "which holds no claim in this pool");
refuses("two terms sets name one identity", (() => { const i = base(); i.termsSets[1].platformIdentityB58 = A; return i; })(),
  "two terms sets name identity");
refuses("the members' terms disagree with each other", (() => { const i = base(); i.termsSets[1].agreement.votingAddress = OTHER_ADDR; return i; })(),
  "do not agree with each other");
refuses("A's terms assign it B's share", (() => { const i = base(); i.termsSets[0].agreement.myIndex = 1; return i; })(),
  "memberA's claims name reward script");

// ---- the claims against the registration and the terms ----
refuses("A's claims name a different reward script", (() => { const i = base(); i.claims = claimsFor([6, 4], ["76a914" + "33".repeat(20) + "88ac", SCRIPT_B]); return i; })(),
  "amount and reward pairing (registration verification)");
refuses("a 5 and 5 claim split against 600 and 400 terms", (() => { const i = base(); i.claims = claimsFor([5, 5]); return i; })(),
  "memberA's terms contribute 60000000000, its claims 50000000000");
refuses("a slot book one claim short", (() => { const i = base(); i.claims = i.claims.slice(0, 9); return i; })(),
  "the slot book is not full");
refuses("one member's claims naming two reward scripts", (() => { const i = base(); i.claims[5].rewardScriptHex = SCRIPT_B; return i; })(),
  "more than one reward script");
refuses("every slot claimed by one member", (() => { const i = base(); i.claims = claimsFor([10, 0]); return i; })(),
  "single-owner");

// ---- Core's answer ----
refuses("Core's answer without a share table", (() => { const i = base(); delete i.protxInfo.state.shares; return i; })(),
  "no share table");
refuses("Core's answer for another registration", (() => { const i = base(); i.proTxDisplayHex = "ab".repeat(32); return i; })(),
  "different registration");
refuses("Core's answer without early-exit terms", (() => { const i = base(); delete i.protxInfo.state.earlyPenalty; return i; })(),
  "no early-exit terms");

// ---- the review's construction: both shares pay ONE reward script, so the script cannot tell them apart ----
const sharedScript = () => {
  const i = base();
  const s0 = i.protxInfo.state.shares[0];
  Object.assign(i.protxInfo.state.shares[1], { rewardAddress: s0.rewardAddress, rewardScript: s0.rewardScript });
  i.termsSets.forEach((t) => { t.agreement.shares[1].rewardAddress = s0.rewardAddress; });
  i.claims = claimsFor([6, 4], [SCRIPT_A, SCRIPT_A]);
  return i;
};
ok("with one reward script on both shares, the correct assignment still completes", decideCompletion(sharedScript()).ok === true);
refuses("B assigned the 600 DASH share on 400 DASH of claims (the review's case)",
  (() => { const i = sharedScript(); i.termsSets[1].agreement.myIndex = 0; return i; })(), "are both assigned share 0");
refuses("the two assignments swapped under one reward script",
  (() => { const i = sharedScript(); i.termsSets[0].agreement.myIndex = 1; i.termsSets[1].agreement.myIndex = 0; return i; })(),
  "memberA's claims total 60000000000, the share its terms assign holds 40000000000");
{
  const i = sharedScript();
  i.protxInfo.state.shares.forEach((s) => { s.amount = 50000000000; });
  i.termsSets.forEach((t) => { t.agreement.shares.forEach((s) => { s.amount = 50000000000; }); t.agreement.myContributionDuffs = 50000000000; });
  i.claims = claimsFor([5, 5], [SCRIPT_A, SCRIPT_A]);
  ok("an equal split under one reward script completes when each member has its own share", decideCompletion(clone(i)).ok === true);
  i.termsSets[1].agreement.myIndex = 0;
  refuses("an equal split with both members assigned share 0", i, "are both assigned share 0");
}

// ---- comparisons the review found no case bound ----
refuses("the agreed reward address differs", both(base(), (a) => { a.shares[0].rewardAddress = OTHER_ADDR; }),
  "share 0's registered reward address");
refuses("the agreed share amounts differ", both(base(), (a) => { a.shares[0].amount = 59000000000; a.shares[1].amount = 41000000000; }),
  "share 0's registered amount");
refuses("the agreed operator reward differs", both(base(), (a) => { a.operatorReward = 1; }), "operatorReward");
refuses("a terms set whose own share contradicts its contribution",
  (() => { const i = base(); i.termsSets[0].agreement.myContributionDuffs = 50000000000; return i; })(),
  "memberA's terms assign it a share of 60000000000 but state a contribution of 50000000000");

// ---- the claim plan the runner writes from ----
{
  const { planClaims } = require("./coownerCompletion.cjs");
  const pool = base().pool;
  const terms = [
    { member: "memberB", platformIdentity: { b58: B }, rewardScriptHex: SCRIPT_B, agreement: clone(FIX.agreements.memberB) },
    { member: "memberA", platformIdentity: { b58: A }, rewardScriptHex: SCRIPT_A, agreement: clone(FIX.agreements.memberA) },
  ];
  const plan = planClaims({ terms, pool });
  ok("the plan gives A slots 0-5 and B slots 6-9 with their own scripts",
    JSON.stringify(plan.map((p) => [p.identityB58, p.slots, p.rewardScriptHex]))
      === JSON.stringify([[A, [0, 1, 2, 3, 4, 5], SCRIPT_A], [B, [6, 7, 8, 9], SCRIPT_B]]));
  const planRefuses = (name, t, needle) => {
    let why = null;
    try { planClaims({ terms: t, pool }); } catch (e) { why = e.message; }
    ok(`${name} (got ${JSON.stringify(why)})`, why !== null && why.includes(needle));
  };
  planRefuses("no terms at all", [], "no preserved terms");
  const { verifyClaimBook } = require("./coownerCompletion.cjs");
  const readBack = claimsFor();
  ok("a full book read back as planned passes", verifyClaimBook({ plan, readBack, poolIdB58: POOL_B58, pool }) === null);
  const short = verifyClaimBook({ plan, readBack: readBack.slice(0, 9), poolIdB58: POOL_B58, pool });
  ok(`a book read back one slot short is refused (got ${JSON.stringify(short)})`, short !== null && short.includes("not full"));
  const swapped = clone(readBack);
  [swapped[0].ownerB58, swapped[6].ownerB58] = [swapped[6].ownerB58, swapped[0].ownerB58];
  [swapped[0].rewardScriptHex, swapped[6].rewardScriptHex] = [swapped[6].rewardScriptHex, swapped[0].rewardScriptHex];
  const sw = verifyClaimBook({ plan, readBack: swapped, poolIdB58: POOL_B58, pool });
  ok(`a full book with slots 0 and 6 exchanged between the members is refused (got ${JSON.stringify(sw)})`, sw === "slots 0, 6 differ from the plan");
  planRefuses("contributions short of the pool", [terms[1]], "not the pool's");
  planRefuses("one share index assigned twice", (() => { const t = clone(terms); t[1].agreement.myIndex = 1; return t; })(), "once each");
  planRefuses("a contribution that is not whole slots", (() => { const t = clone(terms); t[1].agreement.myContributionDuffs = 60500000000; return t; })(), "not a whole number");
}

// ---- the served-document adapters (shapes as the SDK serves them: getProperties, id objects, bigints) ----
{
  const { poolFromDoc, claimsFromDocs } = require("./coownerCompletion.cjs");
  const idObj = (b58) => ({ base58: () => b58 });
  const poolBytes = Buffer.from(POOL_HEX, "hex");
  const doc = (props, owner, extra = {}) => ({ id: idObj(POOL_B58), ownerId: idObj(owner), getProperties: () => props, ...extra });
  const p = poolFromDoc(doc({ slotIndex: 0, nodeType: "regular", operatorFeeBps: 0, targetDuffs: 100000000000n,
    slotDuffs: 10000000000n, slotCount: 10 }, A));
  ok("a served pool reads as the pool decideCompletion expects",
    p.pool.targetDuffs === "100000000000" && p.pool.slotDuffs === "10000000000" && p.pool.slotCount === 10 && p.owner.b58 === A);
  let threw = null;
  try { poolFromDoc(doc({ slotIndex: 0, nodeType: "regular", operatorFeeBps: 0, targetDuffs: 100000000000n }, A)); } catch (e) { threw = e.message; }
  ok("a served pool without a slot book is refused", threw !== null && threw.includes("no slot book"));
  const claimDoc = (slotNo, owner, script, poolBuf = poolBytes) => doc({ poolId: new Uint8Array(poolBuf), slotNo, rewardScript: new Uint8Array(Buffer.from(script, "hex")) },
    owner, { createdAt: 1000n + BigInt(slotNo) });
  const served = claimsFor().map((c) => claimDoc(c.slotNo, c.ownerB58, c.rewardScriptHex));
  const read = claimsFromDocs(served, POOL_HEX);
  ok("served claims read back exactly as the claims the battery builds",
    JSON.stringify(read) === JSON.stringify(claimsFor()));
  const i = base(); i.claims = read;
  ok("and they complete against the real registration", decideCompletion(i).ok === true);
  threw = null;
  try { claimsFromDocs([claimDoc(0, A, SCRIPT_A, Buffer.alloc(32, 7))], POOL_HEX); } catch (e) { threw = e.message; }
  ok("a served claim of another pool is refused", threw !== null && threw.includes("belongs to another pool"));
}

console.log(`coownerCompletionTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
