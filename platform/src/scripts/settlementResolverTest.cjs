/**
 * Tests the settlement resolver's a soundness-review finding SAFETY GATE (plain `node`, no network). The point is
 * to prove the reader cannot be tricked into superseding a position on an unpaid claim, and
 * that it supersedes only when the payment is reader-verifiable.
 */
const { resolveActiveMember, NO_L2_PAYMENT_PROOF } = require("./settlementResolver.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.error("FAIL:", name); } };

const base = { positionId: "p1", ownerId: "leaver", rewardScriptHex: "aa" };
const intent = { intentId: "i1", positionId: "p1", sellerId: "leaver", joinerId: "joiner", priceCredits: 500, expiryHeight: 100 };
const claim = { claimId: "c1", intentId: "i1", joinerId: "joiner", rewardScriptHex: "bb" };

// 1. THE a soundness-review finding ATTACK: a named joiner claims WITHOUT paying. On current Platform the payment is
//    not reader-verifiable, so the gate is closed and the base owner (leaver) must stand.
{
  const r = resolveActiveMember(base, [intent], [claim], NO_L2_PAYMENT_PROOF);
  ok("unpaid claim does NOT supersede (a soundness review)", r.superseded === false && r.activeOwner === "leaver");
  ok("reward stays the base owner's script", r.rewardScriptHex === "aa");
}

// 2. When payment IS reader-verifiable (design A's L1 marker, or an upstream capability), the
//    same claim supersedes: the joiner becomes active with their own reward script.
{
  const verified = () => true;
  const r = resolveActiveMember(base, [intent], [claim], verified);
  ok("verified-payment claim supersedes to the joiner", r.superseded === true && r.activeOwner === "joiner");
  ok("reward becomes the joiner's script", r.rewardScriptHex === "bb");
}

// 3. no settlement documents at all: base owner stands
{
  const r = resolveActiveMember(base, [], [], () => true);
  ok("no intent/claim: base owner", r.superseded === false && r.activeOwner === "leaver");
}

// 4. an intent NOT by the current holder must never supersede, even with a verified payment
{
  const forged = { ...intent, sellerId: "someoneElse" };
  const r = resolveActiveMember(base, [forged], [claim], () => true);
  ok("intent not by the current holder: no supersede", r.superseded === false && r.activeOwner === "leaver");
}

// 5. a claim whose owner is not the intent's NAMED joiner must never supersede
{
  const otherClaim = { ...claim, joinerId: "notTheNamedJoiner" };
  const r = resolveActiveMember(base, [intent], [otherClaim], () => true);
  ok("claim not by the named joiner: no supersede", r.superseded === false && r.activeOwner === "leaver");
}

// 6. two claims for one intent: the unique binder is the first; a verified first claim supersedes once
{
  const c2 = { claimId: "c2", intentId: "i1", joinerId: "joiner", rewardScriptHex: "cc" };
  const r = resolveActiveMember(base, [intent], [claim, c2], () => true);
  ok("double claim binds once (the first), single active owner", r.superseded === true && r.activeOwner === "joiner" && r.rewardScriptHex === "bb");
}

// 7. the DEFAULT verifier is the safe one: NO_L2_PAYMENT_PROOF never verifies
ok("NO_L2_PAYMENT_PROOF is always false (safe default)", NO_L2_PAYMENT_PROOF(intent, claim) === false);

console.log(`settlementResolverTest: ${pass} passed, ${fail} failed`);
if (fail) process.exitCode = 1;
