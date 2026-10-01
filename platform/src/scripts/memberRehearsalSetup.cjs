"use strict";
/**
 * THE REHEARSAL'S THROWAWAY MEMBER, for rehearse_member_trial.sh: a fresh store with fresh keys, a made-up
 * identity id (never registered anywhere), the REHEARSAL marker the stand-in ledger requires, and a
 * revision-1 pair of proposals built by the coordinator's own module with throwaway keys for the other
 * member. The altered one is always proposal-2.json, so the rehearsal can assert each outcome.
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const L = require("@dashevo/dashcore-lib");
const S = require("./memberStore.cjs");
const C = require("./coordinatorTrial.cjs");
const T = require("./memberTrial.cjs");

const root = process.argv[2];
const passphrase = process.argv[3];
if (!root || !passphrase) throw new Error("memberRehearsalSetup: give the rehearsal folder and its throwaway passphrase");
const member = path.join(root, "member");
const trial = path.join(root, "trial");
fs.mkdirSync(trial, { recursive: true });
S.createStore(member, passphrase);
fs.writeFileSync(path.join(member, "REHEARSAL"), "a throwaway member for rehearse_member_trial.sh; its keys hold nothing\n");
const identityB58 = L.encoding.Base58.encode(crypto.randomBytes(32));
S.recordIdentity(member, identityB58);
const card = JSON.parse(fs.readFileSync(path.join(member, S.CARD), "utf8"));
const addr = () => new L.PrivateKey(undefined, "testnet").toAddress().toString();
const built = C.buildTrialProposals({ card, other: { owner: addr(), refund: addr(), reward: addr() }, operatorPubKey: "8".repeat(96),
  votingAddress: addr(), ids: { platformChainId: "dash-testnet-51", ...T.PINNED_BY_CHAIN["dash-testnet-51"] }, tipHeight: 1563700, revision: 1, rand: () => 0 });
for (const [name, p] of Object.entries(built.files)) fs.writeFileSync(path.join(trial, name), JSON.stringify(p, null, 2));
if (built.answer.altered !== "proposal-2.json") throw new Error("memberRehearsalSetup: the altered proposal is not proposal-2.json");
console.log(`rehearsal member ready: identity ${identityB58} (made up, never registered), agreed proposal-1.json, altered proposal-2.json`);
