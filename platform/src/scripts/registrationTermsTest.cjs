// The registration-terms battery. Its base is the REAL rc.1 regtest exercise (tegara/l1/pasta-build/
// run_terms_v2.sh, fixture fixtures/registration-terms-rc1.json): one shared registration derived from
// version-2 terms and accepted by the chain, decoded by the node, and the chain's own refusal at each
// boundary. Every rule here is asserted against that record, so a rule the module states that the chain
// does not is as visible as one it misses.
//
// THE MUTATION LIST, written before the cases: the invariant ignores the reward destination, the operator
// reward, the penalty, the period, a share's amount or owner, or the share count; the default reward is
// taken as absent rather than the refund address; the percentage conversion rounds; the rules drop the
// penalty floor, the zero-period rule, the payee-reuse rule, the duplicate-refund rule, the owner-kind rule,
// the reward-kind rule, the empty-string reward, or the bound on basis points.
const fs = require("fs");
const path = require("path");
const R = require("./registrationTerms.cjs");

const FIX = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "registration-terms-rc1.json"), "utf8"));
let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const clone = (x) => JSON.parse(JSON.stringify(x));
const refusal = (fn) => { try { fn(); return null; } catch (e) { if (e instanceof R.TermsRefusal) return e; throw e; } };
const NET = { network: "regtest" };
const canon = (o) => JSON.stringify(o, (k, v) => (v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).sort().map((x) => [x, v[x]])) : v));
const T = FIX.terms;
const DECODED = FIX.decoded.proRegTx;
const INFO = { ...FIX.protxInfo.state, operatorReward: FIX.protxInfo.operatorReward };

// ================= the accepted registration, derived from the terms =================
ok("the fixture is the rc.1 regtest exercise with one confirmed registration", /v24\.0\.0-rc\.1/.test(FIX.source.build.tag) && FIX.accepted.confirmations >= 1 && FIX.decoded.txid === FIX.accepted.txid);
ok("the terms pass the module's rules on the network they were registered on", refusal(() => R.requireTerms(T, NET)) === null);
ok("the RPC arguments the module derives are the ones the chain accepted, value for value (key order is not an argument)", canon(R.rpcArgs(T)) === canon(FIX.rpcArgs)
  && Object.hasOwn(R.rpcArgs(T).shares[0], "rewardAddress") && !Object.hasOwn(R.rpcArgs(T).shares[1], "rewardAddress"));
ok("the terms carry 5.25% as 525 basis points, a P2SH refund on share 1 and no reward address on share 2", T.operatorRewardBps === 525
  && R.addressKind(T.shares[0].refundAddress, "regtest") === "p2sh" && !Object.hasOwn(T.shares[1], "rewardAddress") && Object.hasOwn(T.shares[0], "rewardAddress"));
{
  const r = R.agreementWithDecoded({ terms: T, decoded: DECODED, network: "regtest" });
  ok(`THE INVARIANT HOLDS against the decoded registration (${r.differences.join("; ") || "no differences"})`, r.ok);
  const r2 = R.agreementWithDecoded({ terms: T, decoded: INFO, network: "regtest" });
  ok("and against protx info's state with its operator reward", r2.ok);
  ok("the decoded registration reports the omitted reward as the refund address and script, which is where the rewards go",
    DECODED.shares[1].rewardAddress === T.shares[1].refundAddress && DECODED.shares[1].rewardScript === DECODED.shares[1].refundScript
    && DECODED.shares[0].rewardAddress === T.shares[0].rewardAddress && DECODED.shares[0].rewardScript !== DECODED.shares[0].refundScript);
  ok("the decoded operator reward is the percentage 5.25, which is 525 basis points exactly", DECODED.operatorReward === 5.25 && R.decodedPercentToBps(DECODED.operatorReward) === 525);
  ok("the registered penalty is one duff below the smallest share, the boundary inside", DECODED.earlyPenalty === 40000000000 - 1 && T.earlyPenalty === DECODED.earlyPenalty);
}
{
  // every field of the decoded registration altered in turn is a named difference
  const alter = [
    ["share 1's amount", (d) => { d.shares[0].amount += 1; }, /share 1: registered amount/],
    ["share 1's owner", (d) => { d.shares[0].ownerAddress = d.shares[1].ownerAddress; }, /share 1: registered owner/],
    ["share 1's refund address", (d) => { d.shares[0].refundAddress = d.shares[1].refundAddress; }, /share 1: registered refund address/],
    ["share 1's reward destination", (d) => { d.shares[0].rewardAddress = d.shares[0].refundAddress; }, /share 1: rewards go to/],
    ["share 2's reward destination (the omitted one, sent elsewhere)", (d) => { d.shares[1].rewardAddress = d.shares[0].rewardAddress; d.shares[1].rewardScript = d.shares[0].rewardScript; }, /share 2: rewards go to .* \(the refund address, no reward address given\)/],
    ["share 2's reward script alone", (d) => { d.shares[1].rewardScript = d.shares[0].rewardScript; }, /share 2: the registered reward script/],
    ["share 1's refund script alone", (d) => { d.shares[0].refundScript = d.shares[1].refundScript; }, /share 1: the registered refund script/],
    ["a missing decoded share (a null in the table, the review's case)", (d) => { d.shares[1] = null; }, /share 2: the registration reports no share 2/],
    ["a decoded share that is a list", (d) => { d.shares[0] = [d.shares[0]]; }, /share 1: the registration reports no share 1/],
    ["the operator reward near a valid hundredth (5.250000001, the review's case)", (d) => { d.operatorReward = 5.250000001; }, /registered operator reward 5\.250000001 is not a percentage with two decimals/],
    ["the operator reward by one basis point", (d) => { d.operatorReward = 5.24; }, /registered operator reward 524 basis points, signed 525/],
    ["the operator reward as a whole percent", (d) => { d.operatorReward = 5; }, /registered operator reward 500 basis points, signed 525/],
    ["the penalty", (d) => { d.earlyPenalty += 1; }, /registered early-exit penalty/],
    ["the period", (d) => { d.earlyPeriodBlocks += 1; }, /registered early-exit period/],
    ["the operator key", (d) => { d.pubKeyOperator = "9".repeat(96); }, /operator key/],
    ["the voting address", (d) => { d.votingAddress = d.shares[0].ownerAddress; }, /voting address/],
    ["the share count", (d) => { d.shares.push(clone(d.shares[1])); }, /registration has 3 shares/],
  ];
  for (const [what, f, re] of alter) {
    const d = clone(DECODED); f(d);
    const r = R.agreementWithDecoded({ terms: T, decoded: d, network: "regtest" });
    ok(`a registration differing in ${what} is named (${r.differences[0] || "nothing"})`, !r.ok && r.differences.some((x) => re.test(x)));
  }
  const t2 = clone(T); t2.shares[1].rewardAddress = t2.shares[1].refundAddress;
  ok("terms that NAME the refund address as the reward agree with the same decoded registration, as the destinations are equal", R.agreementWithDecoded({ terms: t2, decoded: DECODED, network: "regtest" }).ok);
}

// ================= the chain's boundary cases =================
{
  // the chain's own reason, where it gave one, is the reason the module names
  const chainReason = (text) => (/(bad-protx-[a-z-]+)/.exec(text) || [])[1] || null;
  for (const c of FIX.refusals) {
    const e = refusal(() => R.requireTerms(c.terms, NET));
    const want = chainReason(c.text);
    ok(`the chain refused "${c.case}" at ${c.stage} (${want || c.text.split("\n").pop().slice(0, 50)}), and the module refuses it${want ? " for the same reason" : ""} (${e ? e.reason : "ACCEPTED"})`,
      e !== null && (want === null || e.reason === want));
  }
  const byCase = Object.fromEntries(FIX.refusals.map((c) => [c.case, c]));
  ok("a reward over 10000 basis points is refused by the RPC's own bound and by the module's", /100/.test(byCase["reward 10001 bps"].text) && refusal(() => R.requireTerms(byCase["reward 10001 bps"].terms, NET)).reason === "operatorReward");
  ok("a period over the maximum is refused by the RPC's own bound and by the module's", /out of range/.test(byCase["period one over the maximum"].text) && refusal(() => R.requireTerms(byCase["period one over the maximum"].terms, NET)).reason === "bad-protx-shares-early-period");
  ok("a P2SH owner address is refused by the RPC's parsing and by the module's", /invalid share owner address/.test(byCase["a P2SH owner address"].text) && refusal(() => R.requireTerms(byCase["a P2SH owner address"].terms, NET)).reason === "ownerAddress");
  for (const c of FIX.acceptedBoundaries) {
    const t = c.terms;
    const e = refusal(() => R.requireTerms(t, NET));
    const rep = c.termsAsReported;
    const agree = e === null && R.agreementWithDecoded({ terms: t, decoded: rep, network: "regtest" });
    const emptyReward = /empty-string/.test(c.case);
    ok(`the chain prepared "${c.case}" and the module ${emptyReward ? "refuses the empty string while agreeing with what the chain reported" : "accepts it and agrees with the terms the chain reported"}`,
      emptyReward ? (e !== null && e.reason === "bad-protx-shares-payee" && rep.shares[1].rewardAddress === t.shares[1].refundAddress) : (agree && agree.ok));
  }
}

// ================= the rules, each with a case the chain's record does not carry =================
{
  const base = () => clone(T);
  const cases = [
    ["a null reward address", (t) => { t.shares[1].rewardAddress = null; }, "bad-protx-shares-payee"],
    ["a field the registration does not take", (t) => { t.shares[1].note = "x"; }, "shape"],
    ["a term the registration does not take", (t) => { t.extra = 1; }, "shape"],
    ["a missing term", (t) => { delete t.earlyPenalty; }, "shape"],
    ["nine shares", (t) => { t.shares = Array.from({ length: 9 }, (_, i) => ({ ...clone(t.shares[1]), ownerAddress: T.shares[i % 2].ownerAddress })); }, "bad-protx-shares-count"],
    ["one share", (t) => { t.shares = [t.shares[0]]; }, "bad-protx-shares-count"],
    ["a share over the collateral", (t) => { t.shares[0].amount = R.COLLATERAL + 1; t.shares[1].amount = -1; }, "bad-protx-shares-amount"],
    ["a non-integer penalty", (t) => { t.earlyPenalty = 1.5; }, "bad-protx-shares-penalty"],
    ["a negative penalty", (t) => { t.earlyPenalty = -1; }, "bad-protx-shares-penalty"],
    ["a reward address paying an owner key", (t) => { t.shares[0].rewardAddress = t.shares[1].ownerAddress; }, "bad-protx-shares-payee-reuse"],
    ["a refund address paying the voting key", (t) => { t.shares[1].refundAddress = t.votingAddress; }, "bad-protx-shares-payee-reuse"],
    ["a P2SH voting address", (t) => { t.votingAddress = t.shares[0].refundAddress; }, "votingAddress"],
    ["an operator key of 95 characters", (t) => { t.operatorPubKey = t.operatorPubKey.slice(1); }, "operatorPubKey"],
    ["basis points as text", (t) => { t.operatorRewardBps = "525"; }, "operatorReward"],
    ["an address of another network", (t) => { t.shares[0].ownerAddress = "XwQvH6eMt3MqrGz6ZbnVxHDaPp4j2a8RWY"; }, "ownerAddress"],
  ];
  for (const [what, f, reason] of cases) {
    const t = base(); f(t);
    const e = refusal(() => R.requireTerms(t, NET));
    ok(`${what} is refused as ${reason} (${e ? e.reason : "ACCEPTED"})`, e !== null && e.reason === reason);
  }
  ok("an unknown network is refused before any address is judged", refusal(() => R.requireTerms(base(), { network: "mainnet" })).reason === "network");
  ok("the testnet rules accept the regtest addresses (one address format)", refusal(() => R.requireTerms(base(), { network: "testnet" })) === null);
}

// ================= exact display conversion =================
{
  let roundTrips = 0;
  for (let b = 0; b <= 10000; b++) if (R.percentTextToBps(R.bpsToPercentText(b)) === b) roundTrips++;
  ok("every value from 0 to 10000 basis points round-trips through the two-decimal text exactly", roundTrips === 10001);
  ok("the text forms are the RPC's", R.bpsToPercentText(525) === "5.25" && R.bpsToPercentText(500) === "5.00" && R.bpsToPercentText(0) === "0.00" && R.bpsToPercentText(10000) === "100.00" && R.bpsToPercentText(1) === "0.01");
  ok("text with three decimals, a sign, an exponent, a comma or over 100 is not a reward, and surrounding spaces are trimmed", ["5.255", "-1", "1e2", "100.01", "", "5,25", "abc", "5 .2"].every((s) => R.percentTextToBps(s) === null)
    && R.percentTextToBps("5") === 500 && R.percentTextToBps(" 5 ") === 500 && R.percentTextToBps("5.2") === 520 && R.percentTextToBps("100") === 10000 && R.percentTextToBps("0") === 0);
  ok("the decoded percentage converts exactly for every two-decimal value", (() => { for (let b = 0; b <= 10000; b++) if (R.decodedPercentToBps(Number(R.bpsToPercentText(b))) !== b) return false; return true; })());
  ok("a decoded value with three decimals, a negative or an overflow is not a reward", [5.255, -0.01, 100.01, "x", null, undefined].every((v) => R.decodedPercentToBps(v) === null) && R.decodedPercentToBps(0.07) === 7);
  ok("a decoded value near a valid hundredth is refused, not rounded (the review's cases), and only a number is read at all (the confirmation's case, \"005.25\")",
    [5.250000001, 5.2501, 5.254, -0.000000001, 100.000000001, -0, 1e-9, NaN, Infinity, true, {}, [], " 5.25", "5.25", "005.25", "0"].every((v) => R.decodedPercentToBps(v) === null)
    && R.decodedPercentToBps(0) === 0 && R.decodedPercentToBps(100) === 10000 && R.decodedPercentToBps(5.25) === 525);
  ok("the shortest text of every chain value is its two-decimal form, which is what makes the strict reading exact", (() => { for (let b = 0; b <= 10000; b++) if (!/^\d{1,3}(\.\d{1,2})?$/.test(String(b / 100))) return false; return true; })());
  const e = refusal(() => R.bpsToPercentText(10001));
  ok("the text conversion refuses what the chain refuses", e !== null && e.reason === "operatorReward" && refusal(() => R.bpsToPercentText(-1)) !== null && refusal(() => R.bpsToPercentText(5.5)) !== null);
}
{
  const d = R.displayTerms(T);
  ok("the display shows the reward in percent with its basis points, and where an omitted reward goes", d.operatorReward === "5.25% (525 of 10,000 basis points)"
    && d.shares[1].rewardsGoTo === `${T.shares[1].refundAddress} (the refund address; no separate reward address)` && d.shares[1].rewardAddressGiven === false
    && d.shares[0].rewardsGoTo === T.shares[0].rewardAddress && d.shares[0].rewardAddressGiven === true);
  ok("rewardDestination is the reward address when given, else the refund address", R.rewardDestination(T.shares[0]) === T.shares[0].rewardAddress && R.rewardDestination(T.shares[1]) === T.shares[1].refundAddress);
}

console.log(`registrationTermsTest: ${passed} passed, ${failed} failed`);
if (failed) process.exit(1);
