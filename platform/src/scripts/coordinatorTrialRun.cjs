"use strict";
/**
 * THE COORDINATOR'S STEP of the guided member trial: builds the two proposals from the member's PUBLIC
 * card (coordinatorTrial.cjs decides their content) and writes them to the trial folder, with the
 * answer (which one is altered) kept apart in the coordinator's own directory. Run on the host by
 * run_coordinator_trial.sh, which passes every input in the environment. It signs and sends nothing.
 */
const fs = require("fs");
const path = require("path");
const L = require("@dashevo/dashcore-lib");
const C = require("./coordinatorTrial.cjs");

const env = (k) => { const v = process.env[k]; if (!v) throw new Error(`coordinatorTrialRun: ${k} is not set`); return v; };
const card = JSON.parse(fs.readFileSync(path.join(env("MEMBER_DIR"), "member-card.json"), "utf8"));
const out = env("TRIAL_DIR");
const coord = env("COORD_DIR");
const revision = Number(process.env.REVISION || "1");
for (const f of C.fileNames(revision)) {
  if (fs.existsSync(path.join(out, f))) throw new Error(`coordinatorTrialRun: ${out} already holds ${f}; a revision's proposals are built once`);
}

// the other member and the voting key are the coordinator's own test keys, kept outside the repository
const keysFile = path.join(coord, "other-member.json");
let keys;
if (fs.existsSync(keysFile)) keys = JSON.parse(fs.readFileSync(keysFile, "utf8"));
else {
  const k = () => new L.PrivateKey(undefined, "testnet");
  const made = { owner: k(), refund: k(), reward: k(), voting: k() };
  keys = Object.fromEntries(Object.entries(made).map(([n, pk]) => [n, { wif: pk.toWIF(), address: pk.toAddress().toString() }]));
  fs.mkdirSync(coord, { recursive: true, mode: 0o700 });
  fs.writeFileSync(keysFile, JSON.stringify(keys, null, 2), { mode: 0o600, flag: "wx" });
}
const built = C.buildTrialProposals({ card,
  other: { owner: keys.owner.address, refund: keys.refund.address, reward: keys.reward.address },
  operatorPubKey: env("OPERATOR_PUBKEY"), votingAddress: keys.voting.address,
  ids: { platformChainId: env("PLATFORM_CHAIN_ID"), contractId: env("CONTRACT_V11_ID"),
    approvalContractId: env("APPROVAL_CONTRACT_ID"), approvalContractOwnerB58: env("APPROVAL_OWNER_B58") },
  tipHeight: Number(env("TIP_HEIGHT")), revision });
fs.mkdirSync(out, { recursive: true });
for (const [name, p] of Object.entries(built.files)) fs.writeFileSync(path.join(out, name), JSON.stringify(p, null, 2), { flag: "wx" });
const answerFile = path.join(coord, revision === 1 ? "answer.json" : `answer-revision-${revision}.json`);
fs.writeFileSync(answerFile, JSON.stringify({ ...built.answer, builtAt: new Date().toISOString() }, null, 2), { mode: 0o600, flag: "wx" });
console.log(`Two proposals at revision ${revision} written to ${out} (${C.fileNames(revision).join(", ")}). Which is altered is recorded only in ${answerFile}.`);
