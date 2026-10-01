"use strict";
/**
 * THE MEMBER'S DECISIONS in the guided member trial (tegara/docs/GUIDED_MEMBER_TRIAL.md). The member
 * tool (memberTrialRun.mjs) holds wiring only; everything it decides is here, driven by
 * memberTrialTest.cjs.
 *
 *   checkProposal     is this a well-formed co-owner proposal for the chain it names, and does the
 *                     member's own share name the member's own keys? Refuses what no member should sign.
 *   parseAgreedAnswers, checkAgreed
 *                     the terms the member agreed to, recorded by the member BEFORE seeing a proposal
 *   compareWithAgreed every agreed term against the proposal, term by term (a soundness-review finding)
 *   approvalScreen    the decision first, the aligned comparison, the complete signed details, and the
 *                     exact next command; the same content as values (details) for the local page, and a
 *                     flag when the member refused this proposal before (refusedBefore)
 *   refusalNeedsConfirmation
 *                     refusing a proposal that matches the agreed terms is asked twice
 *   renderTerms, termPairs
 *                     the complete signed details, as lines and as the pairs both are built from
 *   buildRecord, buildApproval
 *                     the approval record (memberApproval.cjs's version-1 record), then its owner signature
 *   runApproval       the whole approval: check, compare, preflight, reconcile with the ledger, the
 *                     member's confirmation, sign, send, wait, read back; stops at the first thing that
 *                     does not hold, and says "may be on the ledger" for any stop after the send (a soundness-review finding)
 *   statusScreen, statusModel
 *                     what the ledger holds for the member, compared with the agreed terms, as lines and
 *                     as values
 *   verifyReadBack    the served document is the member's, for this pool and revision, with these bytes,
 *                     and its signature verifies under the member's owner key
 *
 * WHAT THE MEMBER CONFIRMS DETERMINES WHAT IS SIGNED. Three rules, each driven by the battery, written
 * down after repeated independent checking kept finding a place where an earlier version broke one of them:
 *   1. every value the record copies from the proposal (six proposal fields, the nine agreement fields
 *      and the four fields of each share) has one JSON type and a closed domain, checked on the value
 *      as it will be signed, never on a coerced or trimmed form, and every text value equals its own
 *      canonical form. Nothing else may appear in the agreement or a share.
 *   2. the display shows every one of those values, and distinct values show as distinct text (amounts
 *      in exact integer arithmetic, text values verbatim, which rule 1 keeps free of spaces and breaks).
 *   3. nothing the record does not sign is shown on the confirmation screen.
 *
 * THE AGREED TERMS ARE THE MEMBER'S OWN RECORD. The first version asked the member to type the
 * contribution after showing the proposal and compared the answer with the proposal itself, so typing
 * the figure on the screen approved altered terms, which happened live (a soundness-review finding). The member now records
 * every agreed term first, and a proposal that differs in any of them is refused before anything is
 * signed. The record is only as good as what the member typed into it, and it sits beside the store on
 * the same machine, so it carries the same limit as the store.
 */
const crypto = require("crypto");
const L = require("@dashevo/dashcore-lib");
const approval = require("./memberApproval.cjs");
const terms = require("./registrationTerms.cjs");
const W = require("./approvalWrite.cjs");
const { canonicalString } = require("./canonicalJson.cjs");
const { CORE_GENESIS_BY_PLATFORM_CHAIN } = require("./memberApprovalLedger.cjs");

const COIN = 100000000;
// THE PUBLICATION THE MEMBER AUTHORIZES, pinned on the member's side per Platform chain: the ledger the
// record names, and the approval contract with its owner. A review found the first version taking both
// from the coordinator's proposal, so a second contract with identical rules would have received the
// approval. A proposal naming anything else is refused, and the tool reads and writes only these.
const PINNED_BY_CHAIN = Object.freeze({
  "dash-testnet-51": Object.freeze({ contractId: "GJWKJLZF3PHm8HuUwz4JCL2PkTmvDqcYV2GagYaQ6mq",
    approvalContractId: "TuqDThp5QNNJGUBJiGfRvuYr82TUn6T4USGDbPgfZgL", approvalContractOwnerB58: "2ghcNuyk6M6JGchFEkj6QTzAN5xFaSrRDGy7kii5RRNi" }),
});
const NODE_COLLATERAL = 1000 * COIN; // a regular masternode
const HEX64 = /^[0-9a-f]{64}$/;
const BLS_PUBKEY = /^[0-9a-f]{96}$/;
// THE SIGNED AGREEMENT HAS EXACTLY THESE FIELDS, each of one type. The record signs the whole agreement,
// so a field this tool does not know, or a known field written as another type, would be signed without
// being shown as signed (a confirmation review added an unknown field, and wrote the fee as text, and
// each signed different bytes behind an identical display). Anything else is refused before the member
// is asked. SINCE THE #7437 FORMAT UNIT (2026-10-01) the agreement is VERSION 2: `registration` carries the
// terms in the chain's own shapes (registrationTerms.cjs, the reward in basis points, the reward address
// optional), beside `myIndex` and `myFeeDuffs`. A version-1 proposal is refused; version-1 approvals on the
// ledger are read as written (memberApproval.agreementView).
const AGREEMENT_FIELDS = Object.freeze(["registration", "myIndex", "myFeeDuffs"]);
const SHARE_FIELDS = terms.SHARE_KEYS;
const unknownFields = (o, known) => (o !== null && typeof o === "object" ? Object.keys(o).filter((k) => !known.includes(k)) : []);
// the address check trims spaces and line breaks, so the value must also equal its own parsed form
const isTestnetAddress = (v) => { try { return typeof v === "string" && L.Address.isValid(v, "testnet") && new L.Address(v, "testnet").toString() === v; } catch { return false; } };
const isInt = (v) => Number.isSafeInteger(v);
// EXACT for every safe integer: whole DASH and duffs are split in integer arithmetic, because dividing
// in floating point shows two different amounts near 90 million DASH as the same text
const dash = (duffs) => {
  if (!Number.isSafeInteger(duffs)) return `${duffs} duffs (not a whole amount)`;
  const d = BigInt(Math.abs(duffs));
  const whole = (d / BigInt(COIN)).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const frac = (d % BigInt(COIN)).toString().padStart(8, "0").replace(/0+$/, "");
  return `${duffs < 0 ? "-" : ""}${whole}${frac ? `.${frac}` : ""} DASH`;
};
// afterSend marks a stop that came AFTER the approval was handed to the network: it may be on the ledger,
// and the member must be told to look before trying again (a soundness-review finding)
class TrialStop extends Error { constructor(why, { afterSend = false, signedNotSent = false } = {}) { super(why); this.afterSend = afterSend; this.signedNotSent = signedNotSent; } }
const stop = (why, opts) => { throw new TrialStop(why, opts); };
const CMD = "bash tegara/platform/run_member_trial.sh";

// ---------------- the terms the member agreed to (a soundness-review finding) ----------------
const AGREED_KIND = "tegara.member.agreed-terms";
// version 2 records the operator reward in basis points; a version-1 record (whole percent) is recorded again
const AGREED_FIELDS = Object.freeze(["kind", "version", "myContributionDuffs", "otherContributionsDuffs", "earlyPeriodBlocks",
  "earlyPenaltyDuffs", "operatorRewardBps", "myFeeDuffs", "recordedAt"]);

/** "400", "10", "0.0001" to duffs, exactly, or null: no sign, no exponent, no separators, at most 8 decimals. */
function parseDashAmount(text) {
  if (typeof text !== "string") return null;
  const m = /^(\d{1,12})(?:\.(\d{1,8}))?$/.exec(text.trim());
  if (!m) return null;
  const v = BigInt(m[1]) * BigInt(COIN) + BigInt((m[2] || "").padEnd(8, "0"));
  return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : null;
}
const parseWhole = (text) => (typeof text === "string" && /^\d{1,9}$/.test(text.trim()) ? Number(text.trim()) : null);

/** The member's agreed-terms record: a list of problems, empty when it can be compared with. */
function checkAgreed(agreed) {
  if (!agreed || typeof agreed !== "object" || Array.isArray(agreed)) return ["you have not recorded your agreed terms"];
  const problems = [];
  const bad = (s) => problems.push(s);
  if (agreed.kind === AGREED_KIND && agreed.version === 1) return ["your agreed terms were recorded by the earlier version of this tool (the operator reward in whole percent); record them again"];
  for (const k of Object.keys(agreed)) if (!AGREED_FIELDS.includes(k)) bad(`your agreed terms carry a field this tool does not know, "${k}"`);
  if (agreed.kind !== AGREED_KIND || agreed.version !== 2) bad("your agreed terms are not this tool's version-2 record");
  const others = Array.isArray(agreed.otherContributionsDuffs) ? agreed.otherContributionsDuffs : null;
  if (!others || others.length < 1 || others.length > 7) bad("your agreed terms name one to seven other members' contributions");
  const amounts = [agreed.myContributionDuffs, ...(others || [])];
  if (amounts.some((v) => !isInt(v) || v < 100 * COIN)) bad("every agreed contribution is a whole amount of at least 100 DASH");
  else if (amounts.reduce((x, y) => x + y, 0) !== NODE_COLLATERAL) bad(`your agreed contributions add up to ${dash(amounts.reduce((x, y) => x + y, 0))}, not ${dash(NODE_COLLATERAL)}`);
  if (!isInt(agreed.earlyPeriodBlocks) || agreed.earlyPeriodBlocks < 0) bad("the agreed early-exit period is not a whole number of blocks");
  if (!isInt(agreed.earlyPenaltyDuffs) || agreed.earlyPenaltyDuffs < 0) bad("the agreed early-exit penalty is not a whole amount");
  if (!isInt(agreed.operatorRewardBps) || agreed.operatorRewardBps < 0 || agreed.operatorRewardBps > terms.MAX_BPS) bad("the agreed operator reward is not 0 to 10000 basis points (0.00% to 100.00%)");
  if (!isInt(agreed.myFeeDuffs) || agreed.myFeeDuffs < 0) bad("the agreed registration fee share is not a whole amount");
  if (typeof agreed.recordedAt !== "string") bad("your agreed terms carry no time of recording");
  return problems;
}

/** The member's typed answers to the agree step. Returns { agreed } or { problems }. */
function parseAgreedAnswers({ contribution, others, period, penalty, operator, fee }, now = new Date()) {
  const problems = [];
  const amount = (text, what) => { const v = parseDashAmount(text); if (v === null) problems.push(`${what}: "${text}" is not an amount in DASH (for example 400, 10 or 0.0001)`); return v; };
  const my = amount(contribution, "your contribution");
  const otherParts = typeof others === "string" ? others.split(",").map((t) => t.trim()) : [];
  const otherDuffs = otherParts.map((t) => amount(t, "the other members' contributions"));
  const periodN = parseWhole(period);
  if (periodN === null) problems.push(`the early-exit period: "${period}" is not a whole number of blocks`);
  const penaltyD = amount(penalty, "the early-exit penalty");
  const operatorN = terms.percentTextToBps(operator);
  if (operatorN === null) problems.push(`the operator reward: "${operator}" is not a percentage from 0 to 100 with up to two decimals (for example 5 or 5.25)`);
  const feeD = amount(fee, "your registration fee share");
  if (problems.length) return { problems };
  const agreed = { kind: AGREED_KIND, version: 2, myContributionDuffs: my, otherContributionsDuffs: otherDuffs, earlyPeriodBlocks: periodN,
    earlyPenaltyDuffs: penaltyD, operatorRewardBps: operatorN, myFeeDuffs: feeD, recordedAt: now.toISOString() };
  const more = checkAgreed(agreed);
  return more.length ? { problems: more } : { agreed };
}

const ascending = (vs) => [...vs].sort((x, y) => x - y);
const dashList = (vs) => `${ascending(vs).map((v) => dash(v).replace(/ DASH$/, "")).join(", ")} DASH`;

/** The agreement of a version-2 proposal, or of a held record of either version, as one view (memberApproval.agreementView). */
const viewOf = ({ proposal, record }) => (record ? approval.agreementView(record) : approval.agreementViewOf(proposal.version, proposal.agreement));

/**
 * Every agreed term against the proposal (or a held record, when `record` is given). Each row's `same` is
 * decided on the values, never on their text; the operator reward is compared in basis points and shown as
 * a percentage with two decimals. Returns { rows, differs }. The proposal must already pass checkProposal
 * and the record checkAgreed.
 */
function compareWithAgreed({ proposal, record, agreed }) {
  const a = viewOf({ proposal, record });
  // a version-1 approval is read as written and never compared with version-2 agreed terms: its reward is a
  // whole percent and the agreed terms are basis points, and converting one to decide equality would
  // reinterpret the record (a review found exactly that in status's match label)
  if (a.version !== 2) stop("a version-1 approval is not compared with your agreed terms; it is shown as written");
  const others = a.shares.filter((_, i) => i !== a.myIndex).map((sh) => sh.amount);
  const agreedOthers = agreed.otherContributionsDuffs;
  const sameList = others.length === agreedOthers.length && ascending(others).every((v, i) => v === ascending(agreedOthers)[i]);
  const row = (term, agreedText, proposedText, same) => ({ term, agreed: agreedText, proposed: proposedText, same });
  const rows = [
    row("Your contribution", dash(agreed.myContributionDuffs), dash(a.shares[a.myIndex].amount), agreed.myContributionDuffs === a.shares[a.myIndex].amount),
    row(agreedOthers.length === 1 && others.length === 1 ? "Other member's contribution" : "Other members' contributions", dashList(agreedOthers), dashList(others), sameList),
    row("Early-exit period", `${agreed.earlyPeriodBlocks} blocks`, `${a.earlyPeriodBlocks} blocks`, agreed.earlyPeriodBlocks === a.earlyPeriodBlocks),
    row("Early-exit penalty", dash(agreed.earlyPenaltyDuffs), dash(a.earlyPenalty), agreed.earlyPenaltyDuffs === a.earlyPenalty),
    row("Operator reward", `${terms.bpsToPercentText(agreed.operatorRewardBps)}%`, a.operatorRewardText, agreed.operatorRewardBps === a.operatorRewardBps),
    row("Your registration fee share", dash(agreed.myFeeDuffs), dash(a.myFeeDuffs), agreed.myFeeDuffs === a.myFeeDuffs),
  ];
  return { rows, differs: rows.some((r) => !r.same) };
}

/** Rows of text in aligned columns: the first left-aligned, the rest right-aligned. */
function alignedTable(header, rows) {
  const all = [header, ...rows];
  const width = header.map((_, c) => Math.max(...all.map((r) => String(r[c]).length)));
  return all.map((r) => r.map((cell, c) => (c === 0 ? String(cell).padEnd(width[c]) : String(cell).padStart(width[c]))).join("    ").trimEnd());
}
const comparisonTable = ({ rows }) => alignedTable(["Term", "Agreed", "Proposed"], rows.map((r) => [r.term, r.agreed, r.proposed]))
  .map((line, i) => (i > 0 && !rows[i - 1].same ? `${line}    <- differs` : line));
const nextLines = (why, args) => ["", `Next, ${why}:`, `  ${CMD} ${args}`];

/**
 * card: { addresses: { owner, refund, reward }, identityB58 }. Returns { problems, mine } where
 * problems is a list of plain reasons (empty when the member may go on to judge the terms).
 */
function checkProposal({ proposal, card }) {
  const problems = [];
  const p = proposal || {};
  const bad = (s) => problems.push(s);
  if (p.kind === "tegara.coowner.proposal" && p.version === 1) { bad("this is a version-1 proposal, which this tool no longer approves (the terms are now signed in the chain's own shapes); ask the coordinator for a version-2 proposal"); return { problems, mine: null }; }
  if (p.kind !== "tegara.coowner.proposal" || p.version !== 2) { bad("this is not a version-2 co-owner proposal"); return { problems, mine: null }; }
  // EVERY CHECK COMPARES THE VALUE AS IT WILL BE SIGNED, never a coerced form of it: a second review
  // wrapped the pool id and the chain name in a list, which a pattern test and a key lookup both read as
  // the plain text, while the record signed the list
  const known = (map) => (typeof p.platformChainId === "string" && Object.hasOwn(map, p.platformChainId) ? map[p.platformChainId] : undefined);
  const want = known(CORE_GENESIS_BY_PLATFORM_CHAIN);
  if (want === undefined) bad(`the proposal names Platform chain ${p.platformChainId}, which this tool does not know`);
  else if (p.l1GenesisHash !== want) bad(`the proposal's Layer 1 chain is not the one ${p.platformChainId} follows`);
  if (typeof p.poolId !== "string" || !HEX64.test(p.poolId)) bad("the proposal's poolId is not 64 lowercase hex");
  const pinned = known(PINNED_BY_CHAIN);
  if (!pinned) bad(`this tool has no authorized contracts for Platform chain ${p.platformChainId}`);
  else {
    if (p.contractId !== pinned.contractId) bad(`the proposal names ledger contract ${p.contractId}, not the one you authorize (${pinned.contractId})`);
    if (p.approvalContractId !== pinned.approvalContractId) bad(`the proposal names approval contract ${p.approvalContractId}, not the one you authorize (${pinned.approvalContractId})`);
  }
  if (!isInt(p.revision) || p.revision < 1) bad("the proposal's revision is not a positive integer");
  if (!isInt(p.notAfterHeight) || p.notAfterHeight < 1) bad("the proposal carries no approval window");
  const a = p.agreement !== null && typeof p.agreement === "object" && !Array.isArray(p.agreement) ? p.agreement : {};
  for (const k of unknownFields(a, AGREEMENT_FIELDS)) bad(`the agreement carries a field this tool does not show, "${k}", which your approval would sign unseen`);
  // THE MEMBER'S OWN KEYS FIRST, on the share table as written, so a redirected address is named as the
  // member's problem before the chain's rules name it as the table's (a duplicate refund, say)
  const reg = a.registration !== null && typeof a.registration === "object" && !Array.isArray(a.registration) ? a.registration : null;
  const rawShares = reg && Array.isArray(reg.shares) ? reg.shares : [];
  if (!isInt(a.myIndex) || !rawShares[a.myIndex] || typeof rawShares[a.myIndex] !== "object" || Array.isArray(rawShares[a.myIndex])) {
    bad("the proposal names no share as yours");
    return { problems, mine: null };
  }
  const mine = rawShares[a.myIndex];
  for (const [k, role] of [["ownerAddress", "owner"], ["refundAddress", "refund"]]) {
    if (mine[k] !== card.addresses[role]) bad(`YOUR SHARE'S ${role.toUpperCase()} ADDRESS IS NOT YOURS: it names ${mine[k]}, and your ${role} key is ${card.addresses[role]}`);
  }
  // a reward address, when given, must be the member's own reward key; when omitted the rewards go to the
  // member's own refund key, which the line above has just checked
  if (Object.hasOwn(mine, "rewardAddress") && mine.rewardAddress !== card.addresses.reward) {
    bad(`YOUR SHARE'S REWARD ADDRESS IS NOT YOURS: it names ${mine.rewardAddress}, and your reward key is ${card.addresses.reward}`);
  }
  rawShares.forEach((s, i) => {
    if (i === a.myIndex || !s || typeof s !== "object") return;
    for (const k of ["ownerAddress", "refundAddress", "rewardAddress"]) {
      if (Object.hasOwn(s, k) && Object.values(card.addresses).includes(s[k])) bad(`share ${i + 1}, someone else's, names one of your addresses (${s[k]})`);
    }
  });
  if (!isInt(a.myFeeDuffs) || a.myFeeDuffs < 0) bad("your part of the registration fee is not a whole amount");
  // THEN THE REGISTRATION TERMS BY THE CHAIN'S OWN RULES, each refusal naming the chain's reason, on the
  // chain the proposal names (the same check the record passes at signing and the completion runs at
  // registration)
  const network = approval.networkOfChain(p.platformChainId);
  if (!reg) bad("the agreement carries no registration terms");
  else if (!network) bad(`this tool has no address rules for Platform chain ${p.platformChainId}`);
  else {
    try { terms.requireTerms(reg, { network }); }
    catch (e) { if (!(e instanceof terms.TermsRefusal)) throw e; bad(`the registration terms are not ones the chain accepts (${e.reason}): ${e.message}`); }
  }
  if (card.identityB58 === null || card.identityB58 === undefined) bad("you have no Platform identity yet, so nothing can be approved (run the identity step)");
  return { problems, mine };
}

/**
 * The terms in plain words: EVERY field the approval record signs is shown (a review found the first
 * version leaving out the voting address, the operator key, the other members' addresses and the fee
 * share, so two different signed agreements could look identical). The battery changes each signed
 * field in turn and requires the display to change.
 */
function renderTerms({ proposal }) {
  const pairs = termPairs({ proposal });
  const w = Math.max(...pairs.map(([k]) => k.length));
  return ["SIGNED DETAILS, everything your approval signs:", ...pairs.map(([k, v]) => `  ${k.padEnd(w)}   ${v}`)];
}

/**
 * The signed details as [label, value] pairs, the ONE source for the command line's lines (renderTerms)
 * and the local page, so the page shows every value the command line shows. A label that starts with
 * two spaces belongs to the share above it.
 */
function termPairs({ proposal }) {
  const a = viewOf({ proposal });
  const mine = a.shares[a.myIndex];
  // where the rewards go, in the chain's own default: a share without a reward address pays its refund address
  const rewardsTo = (sh) => (sh.rewardAddressGiven ? sh.rewardAddress : `${sh.refundAddress} (the refund address; no reward address given)`);
  return [
    ["Pool", proposal.poolId],
    ["Platform chain", proposal.platformChainId],
    ["Ledger contract", proposal.contractId],
    ["Terms revision", String(proposal.revision)],
    ["Layer 1 chain", proposal.l1GenesisHash],
    ["Valid until", `Layer 1 height ${proposal.notAfterHeight}`],
    ["Your share", `number ${a.myIndex + 1} of ${a.shares.length}`],
    ["Your contribution", `${dash(mine.amount)} of ${dash(NODE_COLLATERAL)} (${(100 * mine.amount / NODE_COLLATERAL).toFixed(2)}%)`],
    ["Your owner key", mine.ownerAddress],
    ["Your refunds to", mine.refundAddress],
    ["Your rewards to", rewardsTo(mine)],
    ["Your fee share", dash(a.myFeeDuffs)],
    ...a.shares.flatMap((sh, i) => (i === a.myIndex ? [] : [
      [`Share ${i + 1}`, dash(sh.amount)],
      ["  owner key", sh.ownerAddress],
      ["  refunds to", sh.refundAddress],
      ["  rewards to", rewardsTo(sh)]])),
    ["Early exit", a.earlyPeriodBlocks === 0 ? `no early period (the penalty is ${dash(a.earlyPenalty)})`
      : `within ${a.earlyPeriodBlocks} blocks of registration (about ${(a.earlyPeriodBlocks * 157.5 / 3600).toFixed(1)} hours) costs ${dash(a.earlyPenalty)}`],
    ["Operator reward", `${a.operatorRewardText} of the masternode reward (${a.operatorRewardBps} of 10,000 basis points)`],
    ["Operator key", a.operatorPubKey],
    ["Voting address", a.votingAddress],
  ];
}

/** A digest of a parsed proposal or agreed-terms record, as the refusal log has always recorded it. */
const digestOf = (obj) => crypto.createHash("sha256").update(JSON.stringify(obj === undefined ? null : obj)).digest("hex");

/**
 * The member's earlier refusals of this proposal (HELP_LOG item 6). refusals: { entries, unreadable } as
 * memberActions reads the member's refusals.log. Returns { exact, sameName, unreadable }: refusals of
 * these exact contents, refusals of another version of the same file name, and a count of log lines this
 * tool cannot read, so an unreadable log is never read as "no refusal".
 */
function refusedBefore({ file, proposal, refusals }) {
  const entries = (refusals && Array.isArray(refusals.entries)) ? refusals.entries : [];
  const digest = digestOf(proposal);
  return { exact: entries.filter((r) => r.proposalSha256 === digest), sameName: entries.filter((r) => r.file === file && r.proposalSha256 !== digest),
    unreadable: (refusals && Number.isSafeInteger(refusals.unreadable)) ? refusals.unreadable : 0 };
}
const refusalLines = (flag) => [
  ...flag.exact.map((r) => `You refused this exact proposal at ${r.at} ("${r.reason}"). Approve it only if you have changed your mind.`),
  ...flag.sameName.map((r) => `You refused an earlier version of this file at ${r.at} ("${r.reason}"). This version has different contents.`),
  ...(flag.unreadable ? [`Your refusals log has ${flag.unreadable} line${flag.unreadable === 1 ? "" : "s"} this tool cannot read, so an earlier refusal of this proposal cannot be ruled out.`] : []),
];

/**
 * The screen for a proposal: the decision first, then the aligned comparison, then (when it can be
 * approved) the complete signed details, then the exact next command. mode "inspect" or "approve".
 * refusals (optional): the member's refusals log, so a matching proposal the member refused is flagged.
 * Returns { lines, decision: "problems" | "no-agreed-terms" | "differs" | "matches", details }, where
 * details carries the same content as values for the local page: { headline, problems, agreedProblems,
 * rows (the comparison, or null), terms (termPairs, only when it matches), refused, notes (the lines the
 * command line prints after a refusal, so the page shows them only when this says so), next: [{ why, args }] }.
 */
function approvalScreen({ file, proposal, card, agreed, mode, refusals }) {
  const head = ["TESTNET MEMBER APPROVAL", `Proposal ${file}`, ""];
  const NOTES = ["Nothing signed or sent by this attempt.", "An earlier approval may still exist."];
  const nothing = ["", ...NOTES];
  const nextOf = (next) => next.flatMap((n) => nextLines(n.why, n.args));
  const details = (headline, fields) => ({ headline, problems: [], agreedProblems: [], rows: null, terms: null, refused: null, notes: [], next: [], ...fields });
  const { problems } = checkProposal({ proposal, card });
  if (problems.length) {
    const next = [{ why: "to record your refusal", args: `refuse ${file} "fails the tool's checks"` }];
    const headline = "Cannot approve: this proposal fails the tool's own checks.";
    return { decision: "problems", details: details(headline, { problems, notes: NOTES, next }),
      lines: [...head, headline, "", ...problems.map((p) => `  - ${p}`), ...nothing, ...nextOf(next)] };
  }
  const agreedProblems = checkAgreed(agreed);
  if (agreedProblems.length) {
    const next = [{ why: "to record the terms you agreed to", args: "agree" }];
    const headline = "Cannot compare: your agreed terms are not recorded or cannot be read.";
    return { decision: "no-agreed-terms", details: details(headline, { agreedProblems, notes: NOTES, next }),
      lines: [...head, headline, "", ...agreedProblems.map((p) => `  - ${p}`), ...nothing, ...nextOf(next)] };
  }
  const cmp = compareWithAgreed({ proposal, agreed });
  if (cmp.differs) {
    const next = [{ why: "to record your refusal", args: `refuse ${file} "differs from my agreed terms"` },
      { why: "to see what the ledger already holds for you", args: "status" }];
    const headline = "Cannot approve: this proposal differs from your agreed terms.";
    return { decision: "differs", details: details(headline, { rows: cmp.rows, notes: NOTES, next }),
      lines: [...head, headline, "", ...comparisonTable(cmp), ...nothing, ...nextOf(next)] };
  }
  const refused = refusedBefore({ file, proposal, refusals });
  const flagged = refusalLines(refused);
  const next = mode === "inspect" ? [{ why: "to approve it (asks for your passphrase)", args: `approve ${file}` }] : [];
  const headline = "Matches your agreed terms.";
  return { decision: "matches", details: details(headline, { rows: cmp.rows, terms: termPairs({ proposal }), refused, next }),
    lines: [...head, headline, ...(flagged.length ? ["", ...flagged] : []), "", ...comparisonTable(cmp), "", ...renderTerms({ proposal }), ...nextOf(next)] };
}

/**
 * Whether refusing this proposal needs the member to say so twice (HELP_LOG item 6: the member refused
 * the matching proposal by following the wrong instruction). True exactly when it matches the agreed terms.
 */
const refusalNeedsConfirmation = ({ proposal, card, agreed }) => approvalScreen({ file: "", proposal, card, agreed, mode: "inspect" }).decision === "matches";

/** The version-1 approval record for this proposal and identity, and its bytes as the document carries them. Nothing is signed. */
function buildRecord({ proposal, identityHex }) {
  if (!HEX64.test(identityHex || "")) stop("the member identity is not 64 lowercase hex");
  const record = { domain: approval.DOMAIN, version: approval.VERSION_WRITE, platformChainId: proposal.platformChainId,
    contractId: proposal.contractId, poolId: proposal.poolId, l1GenesisHash: proposal.l1GenesisHash,
    memberIdentity: identityHex, revision: proposal.revision, notAfterHeight: proposal.notAfterHeight,
    agreement: JSON.parse(canonicalString(proposal.agreement)) };
  return { record, recordHex: Buffer.from(canonicalString(approval.requireRecord(record)), "utf8").toString("hex") };
}

/** The record, signed with the owner key. */
function buildApproval({ proposal, identityHex, ownerKey }) {
  const { record } = buildRecord({ proposal, identityHex });
  const message = approval.messageFor(record);
  return { record, message, ownerSignature: new L.Message(message).sign(ownerKey) };
}

/** doc: the served approval as servedApprovalToPlain gives it. Returns a list of problems (empty = holds). */
function verifyReadBack({ doc, identityHex, material, ownerAddress, context }) {
  const problems = [];
  if (!doc) return ["no approval was served back"];
  if (doc.ownerId !== identityHex) problems.push("the served approval is owned by another identity");
  if (doc.poolId !== material.poolIdHex) problems.push("the served approval names another pool");
  if (doc.termsRevision !== material.termsRevision) problems.push("the served approval carries another revision");
  if (doc.record !== material.recordHex) problems.push("the served record is not the bytes you signed");
  if (doc.ownerSignature !== material.ownerSignatureHex) problems.push("the served owner signature is not yours");
  let record;
  try { record = JSON.parse(Buffer.from(doc.record, "hex").toString("utf8")); } catch { problems.push("the served record is not JSON"); return problems; }
  // THE RECORD'S OWN FIELDS ARE BOUND TOO (a review showed a valid owner-signed record for another pool,
  // revision and member passing when wrapped in a document indexed under this member's)
  if (!record || record.memberIdentity !== identityHex) problems.push("the record inside names another member");
  if (!record || record.poolId !== material.poolIdHex) problems.push("the record inside names another pool");
  if (!record || record.revision !== material.termsRevision) problems.push("the record inside carries another revision");
  if (context) for (const k of ["platformChainId", "contractId", "l1GenesisHash"]) {
    if (!record || record[k] !== context[k]) problems.push(`the record inside names another ${k}`);
  }
  const sig = Buffer.from(doc.ownerSignature, "hex").toString("base64");
  let ok = false;
  try { ok = new L.Message(approval.messageFor(record)).verify(ownerAddress, sig); } catch { ok = false; }
  if (!ok) problems.push("the served owner signature does not verify under your owner key");
  return problems;
}

/**
 * An approval the ledger serves under this member and pool, as status shows it: the document is read
 * against the REQUESTED pool and the pinned chain and contract, never against its own fields alone.
 */
function checkHeldApproval({ doc, identityHex, poolIdHex, context, ownerAddress }) {
  return verifyReadBack({ doc, identityHex, ownerAddress, context,
    material: { poolIdHex, termsRevision: doc.termsRevision, recordHex: doc.record, ownerSignatureHex: doc.ownerSignature } });
}

/**
 * The whole approval. world: {
 *   preflight()        everything the send and the wait will need, checked before anything is signed:
 *                      the wait's configuration, the signing key, the nonce. Throws when not ready.
 *   readMine() -> { docs }   the member's approvals for this pool, read by proof (throws when not)
 *   send(material)     hands the signed approval to the network. Throws when it is not accepted.
 *   awaitResult() -> { settled: true } | { settled: false, why }   may throw
 * }
 * reservations: the member folder's once-per-revision record (docs/REVIEW_ASSESSMENT.md, 2026-09-30, the
 * send decision's invariants) {
 *   get({ poolIdHex, revision }) -> entry | null
 *   reserve(entry)     ATOMIC: throws when the revision is already reserved, so two runs cannot both send
 *   confirm({ poolIdHex, revision, confirmedHeight, confirmedAt })   marks it seen, never releases it
 * }
 * confirm() -> boolean   the member's own answer after reading the signed details
 * Returns { outcome: "differs" | "declined" | "already-approved" | "approved", ... } or throws TrialStop.
 * EVERY STOP AFTER send() IS CALLED carries afterSend, because from that call on the approval may be on
 * the ledger whatever the tool saw (a soundness-review finding).
 */
async function runApproval({ proposal, card, agreed, ownerKey, identityHex, world, reservations, confirm }) {
  const { problems } = checkProposal({ proposal, card });
  if (problems.length) stop(`this proposal cannot be approved:\n  - ${problems.join("\n  - ")}`);
  const agreedProblems = checkAgreed(agreed);
  if (agreedProblems.length) stop(`your agreed terms cannot be compared with:\n  - ${agreedProblems.join("\n  - ")}`);
  const comparison = compareWithAgreed({ proposal, agreed });
  if (comparison.differs) return { outcome: "differs", comparison };
  if (ownerKey.toAddress().toString() !== card.addresses.owner) stop("the owner key does not match your card");
  if (!reservations || ["get", "reserve", "confirm"].some((f) => typeof reservations[f] !== "function")) {
    stop("the tool has no record of its reservations, so it cannot keep to one send per revision");
  }
  const attempt = { poolIdHex: proposal.poolId, revision: proposal.revision };
  try { await world.preflight(); } catch (e) { stop(`the tool is not ready to send (${e.message})`); }
  const { recordHex } = buildRecord({ proposal, identityHex });
  let before;
  try { before = await world.readMine(); } catch (e) { stop(`your approvals were not read by proof (${e.message})`); }
  // THE LEDGER IS RECONCILED BEFORE THE MEMBER IS ASKED, on the record bytes, which are fixed by the
  // terms (the signature is not: signing here is not deterministic). The same bytes at this revision,
  // signed by the member's owner key, are this approval; different bytes at this revision are refused,
  // since one revision holds one set of terms
  const held = before.docs.filter((d) => d.ownerId === identityHex && d.poolId === proposal.poolId && d.termsRevision === proposal.revision);
  if (held.length > 1) stop(`the ledger serves ${held.length} approvals of yours at revision ${proposal.revision}`);
  if (held.length === 1) {
    if (held[0].record !== recordHex) stop(`you already hold an approval with different terms at revision ${proposal.revision}; a new approval needs a new revision`);
    const same = verifyReadBack({ doc: held[0], identityHex, ownerAddress: card.addresses.owner, context: proposal,
      material: { poolIdHex: proposal.poolId, termsRevision: proposal.revision, recordHex, ownerSignatureHex: held[0].ownerSignature } });
    if (same.length) stop(`an approval of yours with these terms is on the ledger but does not hold:\n  - ${same.join("\n  - ")}`);
    try { reservations.confirm({ ...attempt, confirmedHeight: before.height === undefined ? null : before.height, confirmedAt: new Date().toISOString() }); } catch { /* reporting only */ }
    return { outcome: "already-approved", comparison, documentIdHex: held[0].id, stamped: held[0].createdAtCoreBlockHeight };
  }
  // ONE SEND PER REVISION FROM THIS FOLDER. A proved read can predate a write that has landed, so an
  // empty read shows nothing about an earlier send, and the ledger is never what permits a send. A
  // reservation, once made, is never released: two confirmation rounds each found a way past a record
  // that could be cleared or raced (docs/REVIEW_ASSESSMENT.md, 2026-09-30)
  const reserved = reservations.get(attempt);
  if (reserved) {
    stop(reserved.confirmedAt
      ? `your approval at revision ${proposal.revision} was read back by proof at ${reserved.confirmedAt} (Platform height ${reserved.confirmedHeight}), and this read, at height ${before.height}, does not show it. This attempt sends nothing. Run status again shortly`
      : `an earlier attempt at revision ${proposal.revision} was started at ${reserved.reservedAt} and may have been sent. This read, at Platform height ${before.height}, does not show it, and this attempt sends nothing. Run status again in a few minutes. If it never appears, the way forward is a new revision from the coordinator`);
  }
  if (await confirm() !== true) return { outcome: "declined", comparison };
  // THE RESERVATION COMES BEFORE THE SIGNATURE, so a run that loses it to another has signed nothing
  // (the narrow confirmation of 1cfbcda: the losing run had signed and said it had not)
  try { reservations.reserve({ ...attempt, recordHex, readHeight: before.height === undefined ? null : before.height, reservedAt: new Date().toISOString() }); }
  catch (e) { stop(`revision ${proposal.revision} could not be reserved for this attempt, so nothing was signed or sent (${(e && e.message) || String(e)})`); }
  const signed = buildApproval({ proposal, identityHex, ownerKey });
  const material = W.documentFromApproval({ record: signed.record, ownerSignature: signed.ownerSignature });
  if (material.recordHex !== recordHex) stop("the signed record's bytes are not the reconciled ones. It was signed on this machine and not sent", { signedNotSent: true });
  const after = (why) => stop(`${why}`, { afterSend: true });
  // FROM THE SEND ON, EVERY STOP IS afterSend, including one nobody anticipated: the whole section is
  // one guard, so an unexpected error here cannot come out as a plain error
  try {
    try { await world.send(material); } catch (e) { after(`the send step did not complete, and the approval may or may not have reached the network: ${e.message}`); }
    let r;
    try { r = await world.awaitResult(); } catch (e) { after(`the approval was sent, and waiting for its result failed: ${e.message}`); }
    if (!r || r.settled !== true) after(`the approval was sent, and its result was not seen with proof (${r && r.why})`);
    let read;
    try { read = await world.readMine(); } catch (e) { after(`the approval settled, and reading it back failed: ${e.message}`); }
    const doc = read.docs.find((d) => d.termsRevision === material.termsRevision);
    const readBack = verifyReadBack({ doc, identityHex, material, ownerAddress: card.addresses.owner, context: proposal });
    if (readBack.length) after(`the approval settled, and its read-back does not hold:\n  - ${readBack.join("\n  - ")}`);
    try { reservations.confirm({ ...attempt, confirmedHeight: read.height === undefined ? null : read.height, confirmedAt: new Date().toISOString() }); } catch { /* reporting only */ }
    return { outcome: "approved", comparison, material, documentIdHex: doc.id, stamped: doc.createdAtCoreBlockHeight };
  } catch (e) {
    if (e instanceof TrialStop && e.afterSend) throw e;
    return after(`the approval was sent, and then: ${(e && e.message) || String(e)}`);
  }
}

/** The reservations the ledger now shows with the same bytes and that are not yet marked as seen. */
const confirmedSends = ({ pending, docs }) => pending.filter((p) => !p.confirmedAt && docs.some((d) => d.termsRevision === p.revision && d.record === p.recordHex));

/**
 * What the ledger holds for the member, the decision first. held: [{ doc, record (parsed or null),
 * problems }] as the runner read and checked them. agreed may be null.
 */
function statusScreen({ poolIdHex, height, held, agreed, pending = [] }) {
  const m = statusModel({ poolIdHex, height, held, agreed, pending });
  const lines = ["TESTNET MEMBER APPROVAL", `Status of pool ${poolIdHex}`, ""];
  const unseenLines = m.unseen.flatMap((u) => ["", u.text, UNSEEN_NOTE]);
  if (!m.rows.length) {
    lines.push(m.headline, ...unseenLines);
    return [...lines, ...(m.canCompare ? [] : nextLines("to record the terms you agreed to", "agree"))];
  }
  lines.push(m.headline, m.topLine, "",
    ...alignedTable(["Revision", "Your contribution", "Penalty", "Stamped at Core height", "Signed by you", "Agreed terms"],
      m.rows.map((r) => [String(r.revision), r.contribution, r.penalty, String(r.stamped), r.signedByYou ? "yes" : "no", r.agreed])));
  for (const r of m.rows) if (r.problems.length) lines.push("", `Revision ${r.revision} does not hold:`, ...r.problems.map((p) => `  - ${p}`));
  if (m.top.agreed === "differ") lines.push("", REPLACES_NOTE);
  lines.push(...unseenLines);
  lines.push("", ...WAITS_ON);
  if (!m.canCompare) lines.push(...nextLines("to record the terms you agreed to, so status can compare with them", "agree"));
  return lines;
}
const UNSEEN_NOTE = "approve never sends twice at one revision from this folder. Run status again in a few minutes.";
const REPLACES_NOTE = "An approval at a higher revision that matches your agreed terms replaces it.";
// a held version-1 approval's label in the agreed-terms column: read as written, never compared
const VERSION_1_NOT_COMPARED = "version 1, not compared";
const WAITS_ON = Object.freeze(["The next step waits on the network: the coordinator registers the shared masternode with these terms,",
  "which needs the v24 upgrade active on testnet. It is not active yet."]);

/**
 * What statusScreen shows, as values for the local page: { headline, topLine, canCompare, height,
 * rows: [{ revision, contribution, penalty, stamped, signedByYou, agreed: "match" | "differ" |
 * "not recorded" | "unreadable" | "version 1, not compared", problems }], top: { revision, agreed } | null, unseen: [{ revision, text }],
 * notes }. The rows are in revision order.
 */
function statusModel({ poolIdHex, height, held, agreed, pending = [] }) {
  const canCompare = checkAgreed(agreed).length === 0;
  const unseen = pending.filter((p) => !held.some((h) => h.doc.termsRevision === p.revision && h.doc.record === p.recordHex)).map((p) => ({ revision: p.revision,
    confirmed: Boolean(p.confirmedAt), text: p.confirmedAt
      ? `Your approval at revision ${p.revision} was read back by proof at ${p.confirmedAt} (Platform height ${p.confirmedHeight}). This read, at height ${height}, does not show it.`
      : `An attempt at revision ${p.revision} was started at ${p.reservedAt} and may have been sent. This read, at Platform height ${height}, does not show it.` }));
  const base = { poolIdHex, height, canCompare, unseen, unseenNote: UNSEEN_NOTE, waitsOn: WAITS_ON.join(" ") };
  if (!held.length) {
    return { ...base, headline: `You hold no approval for this pool (read by proof at Platform height ${height}).`, topLine: null, rows: [], top: null, replacesNote: null };
  }
  const top = held.reduce((x, y) => (y.doc.termsRevision > x.doc.termsRevision ? y : x));
  const rows = held.sort((x, y) => x.doc.termsRevision - y.doc.termsRevision).map((h) => {
    let matches = "not recorded";
    if (h.record && h.record.version === approval.VERSION) matches = VERSION_1_NOT_COMPARED;
    else if (canCompare) { try { matches = compareWithAgreed({ record: h.record, agreed }).differs ? "differ" : "match"; } catch { matches = "unreadable"; } }
    let mineAmount = "unreadable", penalty = "unreadable";
    try { const v = approval.agreementView(h.record); mineAmount = dash(v.shares[v.myIndex].amount); penalty = dash(v.earlyPenalty); } catch { /* shown as unreadable */ }
    return { h, revision: h.doc.termsRevision, contribution: mineAmount, penalty, stamped: h.doc.createdAtCoreBlockHeight, signedByYou: h.problems.length === 0,
      agreed: matches, problems: h.problems };
  });
  const topMatches = rows.find((r) => r.h === top).agreed;
  return { ...base,
    headline: `You hold ${held.length} approval${held.length === 1 ? "" : "s"} for this pool, read by proof at Platform height ${height}.`,
    topLine: `Revision ${top.doc.termsRevision}, the highest, is the one that would count at registration${topMatches === "match" ? ", and it matches your agreed terms." : topMatches === "differ" ? ", and it DIFFERS from your agreed terms." : topMatches === VERSION_1_NOT_COMPARED ? ". It was recorded in the earlier format (version 1) and is shown as written, not compared with your agreed terms." : "."}`,
    rows: rows.map(({ h, ...r }) => r), top: { revision: top.doc.termsRevision, agreed: topMatches }, replacesNote: topMatches === "differ" ? REPLACES_NOTE : null };
}

module.exports = { NODE_COLLATERAL, PINNED_BY_CHAIN, CMD, AGREED_KIND, checkProposal, parseDashAmount, parseAgreedAnswers, checkAgreed,
  compareWithAgreed, alignedTable, approvalScreen, refusalNeedsConfirmation, refusedBefore, refusalLines, digestOf, dash, statusScreen, statusModel, confirmedSends,
  renderTerms, termPairs, buildRecord, buildApproval, verifyReadBack, checkHeldApproval, runApproval, TrialStop };
