// The guided member trial's battery: the member's key store, the proposal checks, the approval record,
// the write-and-read-back sequence over a fake Platform that carries failure modes, and the
// coordinator's proposal builder.
//
// THE MUTATION LIST, written before the cases: the store saves the phrase in plain text, accepts a
// wrong passphrase, replaces an existing store, or trusts a card that does not match its keys; the
// proposal check drops the key-ownership test for the owner, refund or reward address, the
// someone-else-names-your-address test, the 1000 DASH sum, the 100 DASH floor, the chain check, the
// contribution-statement check, or the identity requirement; the approval writes before the member
// confirms, after a refusal, twice for one revision, after an unsettled write, or reports approval
// without a read-back that holds; and the coordinator's two proposals differ in anything but the
// member's amount, the other member's amount and the penalty.
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const L = require("@dashevo/dashcore-lib");
const S = require("./memberStore.cjs");
const T = require("./memberTrial.cjs");
const C = require("./coordinatorTrial.cjs");
const approval = require("./memberApproval.cjs");
const W = require("./approvalWrite.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => { try { fn(); failed++; console.error(`FAIL: ${name} (no refusal)`); } catch (e) { ok(`${name} (${e.message.slice(0, 80)})`, re.test(e.message)); } };
const clone = (x) => JSON.parse(JSON.stringify(x));
const verifyMessage = (address, message, sig) => { try { return new L.Message(message).verify(address, sig); } catch { return false; } };

const PASS = "correct horse battery staple";
const IDS = { platformChainId: "dash-testnet-51", contractId: "GJWKJLZF3PHm8HuUwz4JCL2PkTmvDqcYV2GagYaQ6mq",
  approvalContractId: "TuqDThp5QNNJGUBJiGfRvuYr82TUn6T4USGDbPgfZgL", approvalContractOwnerB58: "2ghcNuyk6M6JGchFEkj6QTzAN5xFaSrRDGy7kii5RRNi" };
const addr = () => new L.PrivateKey(undefined, "testnet").toAddress().toString();
const OTHER = { owner: addr(), refund: addr(), reward: addr() };
const IDENTITY_B58 = L.encoding.Base58.encode(crypto.createHash("sha256").update("the member identity").digest());
const IDENTITY_HEX = crypto.createHash("sha256").update("the member identity").digest("hex");

(async () => {
  // ================= the member's store =================
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "member-store-"));
  throws("a short passphrase is refused", () => S.createStore(path.join(dir, "x"), "short"), /at least 12/);
  const card0 = S.createStore(dir, PASS);
  const raw = fs.readFileSync(path.join(dir, S.STORE), "utf8");
  const opened = S.openStore(dir, PASS);
  ok("the store opens with the passphrase, and the card is its keys", opened.card.addresses.owner === opened.keys.addresses.owner
    && card0.addresses.refund === opened.keys.addresses.refund && card0.identityB58 === null);
  ok("the phrase is not in the file in plain text", !raw.includes(opened.phrase) && !opened.phrase.split(" ").slice(0, 4).every((w) => raw.includes(w)));
  ok("the store file is readable by its owner only", (fs.statSync(path.join(dir, S.STORE)).mode & 0o077) === 0);
  ok("owner, refund and reward are three different keys", new Set(Object.values(opened.keys.addresses)).size === 3);
  throws("a wrong passphrase does not open the store", () => S.openStore(dir, "the wrong passphrase!"), /does not open/);
  {
    const e1 = S.encrypt(opened.phrase, PASS), e2 = S.encrypt(opened.phrase, PASS);
    ok("every encryption draws a fresh salt and a fresh nonce, so two stores of one phrase differ",
      e1.salt !== e2.salt && e1.iv !== e2.iv && e1.ciphertext !== e2.ciphertext && !/^0+$/.test(e1.salt) && !/^0+$/.test(e1.iv)
      && S.decrypt(e1, PASS) === opened.phrase && S.decrypt(e2, PASS) === opened.phrase);
  }
  throws("an existing store is never replaced", () => S.createStore(dir, PASS), /never replaced/);
  {
    const d2 = fs.mkdtempSync(path.join(os.tmpdir(), "member-store-"));
    S.createStore(d2, PASS);
    const cp = path.join(d2, S.CARD);
    const c = JSON.parse(fs.readFileSync(cp, "utf8")); c.addresses.refund = OTHER.refund; fs.writeFileSync(cp, JSON.stringify(c));
    throws("a card whose refund address was replaced is refused on opening", () => S.openStore(d2, PASS), /refund address is not this store's/);
    const sp = path.join(d2, S.STORE);
    const blob = JSON.parse(fs.readFileSync(sp, "utf8")); blob.ciphertext = blob.ciphertext.replace(/^../, (h) => (h === "00" ? "01" : "00")); fs.writeFileSync(sp, JSON.stringify(blob));
    throws("an altered ciphertext does not open", () => S.openStore(d2, PASS), /does not open/);
  }
  S.recordIdentity(dir, IDENTITY_B58);
  const card = S.openStore(dir, PASS).card;
  throws("a card never switches to another identity", () => S.recordIdentity(dir, "x".repeat(44)), /already names identity/);
  // ================= the restore proof (the backup-and-restore exercise) =================
  {
    // a backup is the two files copied; a restore is the copy in another folder, which must open and sign as its card
    const restore = fs.mkdtempSync(path.join(os.tmpdir(), "member-restore-"));
    for (const f of [S.STORE, S.CARD]) fs.copyFileSync(path.join(dir, f), path.join(restore, f));
    const when = new Date("2026-10-01T12:00:00Z");
    const r = S.proveStore(restore, PASS, { now: () => when });
    ok("a restored copy opens, names the card's addresses and identity, and signs a dated test line", r.addresses.owner === card.addresses.owner && r.addresses.reward === card.addresses.reward
      && r.identityB58 === IDENTITY_B58 && r.testLine === "tegara member store restore check 2026-10-01T12:00:00.000Z" && typeof r.signature === "string" && r.signature.length > 60);
    ok("and the returned signature verifies against the CARD's owner address, checked here independently of the module", new L.Message(r.testLine).verify(card.addresses.owner, r.signature) === true);
    ok("but not against the card's refund address, so the signature is the owner key's and no other", new L.Message(r.testLine).verify(card.addresses.refund, r.signature) === false);
    throws("the restored copy refuses a wrong passphrase like the original", () => S.proveStore(restore, "the wrong passphrase!"), /does not open/);
    const keys = S.openStore(restore, PASS).keys;
    const mismatched = S.signedTestLine({ ownerKey: keys.owner, ownerAddress: card.addresses.refund });
    ok("a test line signed by the owner key does not verify against another address (the contrary control: verified is computed, never assumed)", mismatched.verified === false
      && S.signedTestLine({ ownerKey: keys.owner, ownerAddress: card.addresses.owner }).verified === true);
    {
      // a restore whose card was swapped for someone else's is refused before any signature is made
      const cp = path.join(restore, S.CARD);
      const c = JSON.parse(fs.readFileSync(cp, "utf8")); c.addresses.owner = OTHER.owner; fs.writeFileSync(cp, JSON.stringify(c));
      throws("a restored copy whose card names another owner address is refused, not proved", () => S.proveStore(restore, PASS), /owner address is not this store's/);
    }
    {
      // a card with the right owner and refund addresses but another reward address is refused too (a review found
      // the reward comparison unbound: each of the three addresses is checked on its own)
      const d4 = fs.mkdtempSync(path.join(os.tmpdir(), "member-restore-"));
      for (const f of [S.STORE, S.CARD]) fs.copyFileSync(path.join(dir, f), path.join(d4, f));
      const cp = path.join(d4, S.CARD);
      const c = JSON.parse(fs.readFileSync(cp, "utf8")); c.addresses.reward = OTHER.reward; fs.writeFileSync(cp, JSON.stringify(c));
      throws("a restored copy whose card names another reward address is refused, not proved", () => S.proveStore(d4, PASS), /reward address is not this store's/);
    }
    {
      // a restore of the right card beside SOMEONE ELSE's store file (two backups mixed up) is refused
      const d3 = fs.mkdtempSync(path.join(os.tmpdir(), "member-restore-")); S.createStore(d3, PASS);
      fs.copyFileSync(path.join(dir, S.CARD), path.join(d3, S.CARD));
      throws("a restored card beside another member's store file is refused, not proved", () => S.proveStore(d3, PASS), /address is not this store's/);
    }
    throws("a folder with no store is refused by name", () => S.proveStore(fs.mkdtempSync(path.join(os.tmpdir(), "member-restore-")), PASS), /no member store/);
  }

  // ================= the coordinator's two proposals =================
  const built = (r) => C.buildTrialProposals({ card, other: OTHER, operatorPubKey: "8".repeat(96), votingAddress: addr(), ids: IDS, tipHeight: 1563300, rand: () => r });
  const b0 = built(0), b1 = built(1);
  ok("the draw decides which file is altered, and the answer file says which", b0.answer.altered === "proposal-2.json" && b1.answer.altered === "proposal-1.json");
  const agreed = b0.files[b0.answer.agreed], altered = b0.files[b0.answer.altered];
  {
    const diffs = [];
    const walk = (a, b, p) => { if (typeof a !== "object" || a === null) { if (a !== b) diffs.push(p); return; } for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) walk(a[k], b[k], `${p}.${k}`); };
    walk(agreed, altered, "");
    ok(`the proposals differ only in the member's amount, the other amount and the penalty (got ${diffs.join(", ")})`,
      JSON.stringify(diffs.sort()) === JSON.stringify([".agreement.registration.earlyPenalty", ".agreement.registration.shares.0.amount", ".agreement.registration.shares.1.amount"]));
  }

  // ================= the proposal checks =================
  ok(`the agreed proposal has no problem (got ${JSON.stringify(T.checkProposal({ proposal: agreed, card }).problems)})`, T.checkProposal({ proposal: agreed, card }).problems.length === 0);
  ok("THE ALTERED PROPOSAL ALSO PASSES THE AUTOMATIC CHECKS: only the member's judgment can refuse it",
    T.checkProposal({ proposal: altered, card }).problems.length === 0);
  {
    const lines = T.renderTerms({ proposal: altered }).join("\n");
    ok("the terms show the altered contribution and penalty plainly", /Your contribution\s+300 DASH of 1,000 DASH \(30\.00%\)/.test(lines) && /costs 50 DASH/.test(lines) && /Operator reward\s+5\.00% of the masternode reward/.test(lines));
    const good = T.renderTerms({ proposal: agreed }).join("\n");
    ok("the agreed terms show 400 DASH and a 10 DASH penalty", /Your contribution\s+400 DASH/.test(good) && /costs 10 DASH/.test(good));
  }
  const problemOf = (mutate) => { const p = clone(agreed); mutate(p); return T.checkProposal({ proposal: p, card }).problems.join(" | "); };
  ok("a version-1 proposal is refused by name, with the reason it is no longer approved", /version-1 proposal, which this tool no longer approves/.test(problemOf((p) => { p.version = 1; })));
  // a builder that refuses its own record (a version it cannot sign) is a failure of this case, not a crash of the battery
  const builtVersion = (() => { try { return T.buildRecord({ proposal: agreed, identityHex: IDENTITY_HEX }).record.version; } catch (e) { return `refused (${e.message.slice(0, 60)})`; } })();
  ok(`the record built is version 2, signed over the version-2 message (built: ${builtVersion})`, builtVersion === 2
    && T.buildApproval({ proposal: agreed, identityHex: IDENTITY_HEX, ownerKey: S.openStore(dir, PASS).keys.owner }).message.startsWith("tegara co-owner terms approval v2 "));
  ok("a redirected refund address is named", /REFUND ADDRESS IS NOT YOURS/.test(problemOf((p) => { p.agreement.registration.shares[0].refundAddress = OTHER.refund; })));
  ok("a redirected reward address is named", /REWARD ADDRESS IS NOT YOURS/.test(problemOf((p) => { p.agreement.registration.shares[0].rewardAddress = addr(); })));
  ok("a replaced owner address is named", /OWNER ADDRESS IS NOT YOURS/.test(problemOf((p) => { p.agreement.registration.shares[0].ownerAddress = addr(); })));
  ok("your address in someone else's share is named", /someone else's, names one of your addresses/.test(problemOf((p) => { p.agreement.registration.shares[1].refundAddress = card.addresses.refund; })));
  ok("shares that do not make 1000 DASH are named", /add up to/.test(problemOf((p) => { p.agreement.registration.shares[1].amount -= 1; })));
  ok("a share under 100 DASH is named", /at least 100 DASH/.test(problemOf((p) => { p.agreement.registration.shares[0].amount = 50 * 1e8; p.agreement.registration.shares[1].amount = 950 * 1e8; })));
  ok("another Layer 1 chain is named", /Layer 1 chain is not/.test(problemOf((p) => { p.l1GenesisHash = "00".repeat(32); })));
  ok("an unknown Platform chain is named", /does not know/.test(problemOf((p) => { p.platformChainId = "dash-mainnet"; })));
  ok("version 2 carries no separate contribution statement: the share's amount is the contribution", !Object.hasOwn(agreed.agreement, "myContributionDuffs") && T.compareWithAgreed({ proposal: agreed, agreed: T.parseAgreedAnswers({ contribution: "400", others: "600", period: "100", penalty: "10", operator: "5", fee: "0.0001" }).agreed }).rows[0].proposed === "400 DASH");
  ok("one share is refused", /not 2 to 8/.test(problemOf((p) => { p.agreement.registration.shares = [p.agreement.registration.shares[0]]; })));
  ok("an operator reward above 100 is refused", /0 to 10000 basis points/.test(problemOf((p) => { p.agreement.registration.operatorRewardBps = 10001; })));
  ok("another approval contract is refused (the destination is pinned on the member's side)",
    /not the one you authorize/.test(problemOf((p) => { p.approvalContractId = "4fJLR2GYTPFdomuTVvNy3VRrvWgvkKPzqehEBpNf2nk6"; })));
  ok("another ledger contract is refused", /ledger contract .* not the one you authorize/.test(problemOf((p) => { p.contractId = "4fJLR2GYTPFdomuTVvNy3VRrvWgvkKPzqehEBpNf2nk6"; })));
  ok("the pins are the published testnet contracts", T.PINNED_BY_CHAIN["dash-testnet-51"].approvalContractId === IDS.approvalContractId
    && T.PINNED_BY_CHAIN["dash-testnet-51"].contractId === IDS.contractId);
  // EVERY SIGNED FIELD IS SHOWN: change each field the record signs, one at a time, and the display
  // must change (the review's case: voting address, operator key and fee share changed a signed record
  // behind an identical display)
  {
    const base = T.renderTerms({ proposal: agreed }).join("\n");
    const leaves = [];
    const walk = (o, pth) => { if (o !== null && typeof o === "object") { for (const k of Object.keys(o)) walk(o[k], [...pth, k]); } else leaves.push(pth); };
    walk(agreed.agreement, ["agreement"]);
    for (const k of ["poolId", "contractId", "l1GenesisHash", "revision", "notAfterHeight", "platformChainId"]) leaves.push([k]);
    const unshown = [];
    for (const pth of leaves) {
      const p = clone(agreed);
      let o = p; for (const k of pth.slice(0, -1)) o = o[k];
      const last = pth[pth.length - 1], v = o[last];
      o[last] = typeof v === "number" ? (pth.includes("myIndex") ? 1 - v : v + 1) : /^y/.test(v) ? addr() : `${v}0`;
      if (T.renderTerms({ proposal: p }).join("\n") === base) unshown.push(pth.join("."));
    }
    ok(`every signed field changes the display (${leaves.length} fields; unshown: ${unshown.join(", ") || "none"})`, unshown.length === 0 && leaves.length >= 20);
  }
  // NOTHING OUTSIDE THE SHOWN FIELDS IS SIGNED: a field added anywhere in the agreement, or a signed
  // field written as another type, is refused before the member is asked (the confirmation review's
  // cases: an extra field in the agreement or in a share, and the fee written as text, each signed
  // different bytes behind the same display)
  {
    ok("an added field in the agreement is refused", /does not show, "extraTerm"/.test(problemOf((p) => { p.agreement.extraTerm = 1; })));
    ok("an added field in the other member's share is refused", /share 2 carries a field the registration does not take, extraTerm/.test(problemOf((p) => { p.agreement.registration.shares[1].extraTerm = 1; })));
    ok("an added field in your own share is refused", /share 1 carries a field the registration does not take, note/.test(problemOf((p) => { p.agreement.registration.shares[0].note = "x"; })));
    const withProto = JSON.parse(JSON.stringify(agreed).replace('"agreement":{', '"agreement":{"__proto__":{"x":1},'));
    ok("a __proto__ member read from the proposal file is refused", Object.hasOwn(withProto.agreement, "__proto__")
      && /"__proto__"/.test(T.checkProposal({ proposal: withProto, card }).problems.join(" ")));
    ok("the fee written as text is refused (the review's case)", /registration fee is not a whole amount/.test(problemOf((p) => { p.agreement.myFeeDuffs = String(p.agreement.myFeeDuffs); })));
    ok("an operator key that is not a public key is refused", /operator key is not/.test(problemOf((p) => { p.agreement.registration.operatorPubKey = "an operator"; })));
    ok("a voting address that is not a testnet address is refused", /voting address is not/.test(problemOf((p) => { p.agreement.registration.votingAddress = "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5"; })));
    // every signed leaf written as any other JSON type is refused: a number as text, text as a number,
    // and each value wrapped in a list or an object, or replaced by null or a boolean (the second
    // review's case wrapped the pool id and the chain name in a list)
    const leaves = [];
    const walk = (o, pth) => { if (o !== null && typeof o === "object") { for (const k of Object.keys(o)) walk(o[k], [...pth, k]); } else leaves.push(pth); };
    walk(agreed.agreement, ["agreement"]);
    for (const k of ["poolId", "contractId", "l1GenesisHash", "revision", "notAfterHeight", "platformChainId"]) leaves.push([k]);
    const accepted = [];
    const others = (v) => [typeof v === "number" ? String(v) : 1, [v], { v }, null, true,
      typeof v === "number" ? v + 0.5 : `${v} `, typeof v === "number" ? -v - 1 : ` ${v}\n`];
    for (const pth of leaves) {
      for (let replacement = 0; replacement < others(0).length; replacement++) {
        const p = clone(agreed);
        let o = p; for (const k of pth.slice(0, -1)) o = o[k];
        const last = pth[pth.length - 1];
        o[last] = others(o[last])[replacement];
        if (T.checkProposal({ proposal: p, card }).problems.length === 0) accepted.push(`${pth.join(".")} as ${JSON.stringify(o[last])}`);
      }
    }
    ok(`every signed field written as another JSON type is refused (${leaves.length} fields, 7 variants each; accepted: ${accepted.join(", ") || "none"})`, accepted.length === 0 && leaves.length >= 20);
    ok("the review's cases: the pool id and the chain name wrapped in a list are refused",
      problemOf((p) => { p.poolId = [p.poolId]; }) !== "" && problemOf((p) => { p.platformChainId = [p.platformChainId]; }) !== "");
  }
  // TEXT IS SIGNED AS SHOWN: the address check trims, so a padded address passed and signed different
  // bytes behind what reads as the same address; and the coordinator's unsigned pool note, which could
  // carry a line break and a line of its own, is not shown
  {
    ok("the other member's address with a trailing space is refused", /share 2's reward address is not a P2PKH or P2SH address/.test(problemOf((p) => { p.agreement.registration.shares[1].rewardAddress += " "; })));
    ok("the voting address with a trailing line break is refused", /voting address is not/.test(problemOf((p) => { p.agreement.registration.votingAddress += "\n"; })));
    const noted = { ...clone(agreed), poolNote: "trial)\nYOUR CONTRIBUTION: 400 DASH of 1,000 DASH (40.00%), your share number 1" };
    const shown = T.renderTerms({ proposal: noted }).join("\n");
    ok("the unsigned pool note is not shown on the confirmation screen", !shown.includes("trial)") && !shown.includes("YOUR CONTRIBUTION"));
  }
  // AMOUNTS ARE SHOWN EXACTLY: two penalties one duff apart near the largest safe integer showed as the
  // same text when the display divided in floating point
  {
    const big = Number.MAX_SAFE_INTEGER;
    const show = (v) => { const a = clone(agreed).agreement; return T.renderTerms({ proposal: { ...clone(agreed), agreement: { ...a, registration: { ...a.registration, earlyPenalty: v } } } }).join("\n"); };
    ok("penalties one duff apart near the largest safe integer display differently", show(big) !== show(big - 1) && /costs 90,071,992\.54740991 DASH/.test(show(big)));
    ok("the agreed amounts still read as before", /Your contribution\s+400 DASH of 1,000 DASH \(40\.00%\)/.test(show(10 * 1e8)) && /Your fee share\s+0\.0001 DASH/.test(show(10 * 1e8)));
    ok("a fractional number of basis points is refused before the member is asked (the record cannot carry it)", /basis points/.test(problemOf((p) => { p.agreement.registration.operatorRewardBps = 525.5; })));
  }
  ok("no identity yet is named", /no Platform identity/.test(T.checkProposal({ proposal: agreed, card: { ...card, identityB58: null } }).problems.join(" ")));

  // ================= the approval record =================
  const ownerKey = S.openStore(dir, PASS).keys.owner;
  {
    const a = T.buildApproval({ proposal: agreed, identityHex: IDENTITY_HEX, ownerKey });
    const v = approval.verifyRecordAndOwner({ record: a.record, ownerSignature: a.ownerSignature, verifyMessage,
      expect: { poolIdHex: agreed.poolId, contractId: IDS.contractId, platformChainId: IDS.platformChainId, l1GenesisHash: agreed.l1GenesisHash, registrationHeight: agreed.notAfterHeight } });
    ok("the record is unit 2's version-1 record and its owner signature verifies under the member's owner key", v.r.memberIdentity === IDENTITY_HEX && v.r.revision === 1);
    ok("the approval converts to the approval contract's document form", W.documentFromApproval({ record: a.record, ownerSignature: a.ownerSignature }).termsRevision === 1);
  }

  // ================= the member's agreed terms (a soundness-review finding) =================
  const AGREED_ANSWERS = { contribution: "400", others: "600", period: "100", penalty: "10", operator: "5", fee: "0.0001" };
  const agreedTerms = T.parseAgreedAnswers(AGREED_ANSWERS).agreed;
  ok("the guide's agreed terms parse exactly", agreedTerms && agreedTerms.myContributionDuffs === 400 * 1e8 && agreedTerms.otherContributionsDuffs[0] === 600 * 1e8
    && agreedTerms.earlyPeriodBlocks === 100 && agreedTerms.earlyPenaltyDuffs === 10 * 1e8 && agreedTerms.operatorRewardBps === 500 && agreedTerms.myFeeDuffs === 10000
    && T.checkAgreed(agreedTerms).length === 0);
  {
    const refused = (o) => (T.parseAgreedAnswers({ ...AGREED_ANSWERS, ...o }).problems || []).join(" | ");
    ok("contributions that do not make 1000 DASH are not recorded", /add up to/.test(refused({ others: "500" })));
    ok("an amount with more than 8 decimals is not recorded", /not an amount in DASH/.test(refused({ fee: "0.000000001" })));
    ok("an amount in another form is not recorded (no separators, no exponent, no sign)", ["1,000", "4e2", "-10", " ", "10 DASH"].every((t) => /not an amount/.test(refused({ penalty: t }))));
    ok("a percentage with three decimals is not recorded, and two decimals are", /up to two decimals/.test(refused({ operator: "5.555" })) && T.parseAgreedAnswers({ ...AGREED_ANSWERS, operator: "5.25" }).agreed.operatorRewardBps === 525);
    ok("several other members are recorded", T.parseAgreedAnswers({ ...AGREED_ANSWERS, others: "300, 300" }).agreed.otherContributionsDuffs.length === 2);
    ok("an agreed-terms record with an unknown field cannot be compared with", /does not know/.test(T.checkAgreed({ ...agreedTerms, extra: 1 }).join(" ")));
    ok("no record at all cannot be compared with", /not recorded/.test(T.checkAgreed(null).join(" ")));
    ok("exact amounts: 0.0001 DASH is 10000 duffs and 90071992.54740991 DASH is the largest safe integer",
      T.parseDashAmount("0.0001") === 10000 && T.parseDashAmount("90071992.54740991") === Number.MAX_SAFE_INTEGER && T.parseDashAmount("90071992.54740992") === null);
  }
  // EVERY AGREED TERM IS COMPARED: change each one in the proposal and exactly its row differs
  {
    const base = T.compareWithAgreed({ proposal: agreed, agreed: agreedTerms });
    ok("the agreed proposal matches the agreed terms on every row", !base.differs && base.rows.length === 6 && base.rows.every((r) => r.same));
    ok("the revision-1 altered proposal differs (the live case)", T.compareWithAgreed({ proposal: altered, agreed: agreedTerms }).differs);
    const changes = {
      "Your contribution": (p) => { p.agreement.registration.shares[0].amount = 450 * 1e8; p.agreement.registration.shares[1].amount = 550 * 1e8; },
      "Other member's contribution": (p) => { p.agreement.registration.shares[1].amount = 300 * 1e8; p.agreement.registration.shares.push({ ...p.agreement.registration.shares[1], ownerAddress: addr(), refundAddress: addr(), rewardAddress: addr() }); },
      "Early-exit period": (p) => { p.agreement.registration.earlyPeriodBlocks = 101; },
      "Early-exit penalty": (p) => { p.agreement.registration.earlyPenalty += 1; },
      "Operator reward": (p) => { p.agreement.registration.operatorRewardBps = 550; }, // the same whole percent, a different reward
      "Your registration fee share": (p) => { p.agreement.myFeeDuffs += 1; },
    };
    const wrong = [];
    for (const [term, change] of Object.entries(changes)) {
      const p = clone(agreed); change(p);
      if (T.checkProposal({ proposal: p, card }).problems.length) { wrong.push(`${term}: the changed proposal fails its own checks`); continue; }
      const c = T.compareWithAgreed({ proposal: p, agreed: agreedTerms });
      const differing = c.rows.filter((r) => !r.same).map((r) => r.term.replace(/members' contributions/, "member's contribution"));
      // the total is fixed at 1000 DASH, so the member's own contribution cannot change without another's
      const expected = term === "Your contribution" ? ["Your contribution", "Other member's contribution"] : [term];
      if (!c.differs || JSON.stringify(differing) !== JSON.stringify(expected)) wrong.push(`${term}: rows that differ ${JSON.stringify(differing)}`);
    }
    ok(`each agreed term, changed, differs on its own row and no unrelated one (${wrong.join("; ") || "all six"})`, wrong.length === 0);
    const swapped = clone(agreed); swapped.agreement.registration.shares.reverse(); swapped.agreement.myIndex = 1;
    ok("the member's place in the share table is not an agreed term", !T.compareWithAgreed({ proposal: swapped, agreed: agreedTerms }).differs);
  }
  // THE SCREENS: the decision first, the aligned comparison, the signed details, the exact next command
  {
    const d = T.approvalScreen({ file: "proposal-2.json", proposal: altered, card, agreed: agreedTerms, mode: "approve" });
    const at = (re) => d.lines.findIndex((l) => re.test(l));
    ok("a differing proposal's screen leads with the decision", d.decision === "differs" && d.lines[0] === "TESTNET MEMBER APPROVAL"
      && at(/^Cannot approve: this proposal differs from your agreed terms\.$/) === 3 && at(/^Term\s+Agreed\s+Proposed$/) === 5);
    const table = d.lines.slice(5, 12);
    const rightEdge = (l, word) => l.indexOf(word) + word.length;
    ok("its comparison columns are aligned and the differing rows are marked", table.length === 7
      && table.slice(1).every((l) => rightEdge(l, "DASH") > 0) && new Set(table.map((l) => l.replace(/\s+<- differs$/, "").length)).size <= 2
      && table.filter((l) => /<- differs$/.test(l)).length === 3 && /^Your contribution\s+400 DASH\s+300 DASH\s+<- differs$/.test(table[1]));
    ok("it says nothing was signed or sent, and that an earlier approval may exist", at(/^Nothing signed or sent by this attempt\.$/) > 0 && at(/^An earlier approval may still exist\.$/) > 0);
    ok("it prints the exact next commands on their own lines", d.lines.includes(`  ${T.CMD} refuse proposal-2.json "differs from my agreed terms"`) && d.lines.includes(`  ${T.CMD} status`));
    const m = T.approvalScreen({ file: "proposal-1.json", proposal: agreed, card, agreed: agreedTerms, mode: "inspect" });
    ok("a matching proposal's screen leads with the decision and keeps every signed detail", m.decision === "matches" && m.lines[3] === "Matches your agreed terms."
      && T.renderTerms({ proposal: agreed }).every((l) => m.lines.includes(l)) && m.lines.includes(`  ${T.CMD} approve proposal-1.json`));
    const n = T.approvalScreen({ file: "proposal-1.json", proposal: agreed, card, agreed: null, mode: "inspect" });
    ok("with no agreed terms recorded, the screen says so and names the agree command", n.decision === "no-agreed-terms" && n.lines.includes(`  ${T.CMD} agree`));
  }

  // ================= the approval sequence, over a fake Platform that carries the failure modes =================
  const world = (o = {}) => {
    const s = { docs: [...(o.preexisting || [])], sends: 0, preflights: 0, events: [] };
    return { s, w: {
      preflight: async () => { s.preflights++; s.events.push("preflight"); if (o.preflightFails) throw new Error("simulated: the result wait cannot be configured"); },
      readMine: async () => {
        s.events.push("read");
        if (o.readFails || (o.readFailsAfterSend && s.sends)) throw new Error("simulated: no proof");
        if (o.readJunkAfterSend && s.sends) return {};
        // a proved read from a height before the last write landed (the confirmation review's case)
        if (s.stale) return { docs: clone(s.docs.slice(0, s.docsBeforeLastSend)), height: 100 };
        return { docs: clone(s.docs), height: 101 };
      },
      send: async (m) => {
        s.docsBeforeLastSend = s.docs.length;
        s.sends++; s.events.push("send");
        if (o.sendThrows) throw new Error("simulated: the connection closed after the request was written");
        s.docs.push({ id: crypto.createHash("sha256").update(`doc ${s.sends}`).digest("hex"), ownerId: IDENTITY_HEX, poolId: m.poolIdHex,
          termsRevision: m.termsRevision, record: o.otherBytes ? `${m.recordHex}20` : m.recordHex, ownerSignature: m.ownerSignatureHex,
          createdAtCoreBlockHeight: 1563301, createdAt: 1790700000000 });
      },
      awaitResult: async () => {
        s.events.push("wait");
        if (o.waitThrows) throw new Error("E2_EXPECTED_CHAIN_ID is not set (simulated, the live a soundness-review finding message)");
        if (o.waitReturnsJunk) return undefined;
        return o.unsettled ? { settled: false, why: "ambiguous" } : { settled: true };
      } } };
  };
  // the member folder's reservations, with the runner's semantics: reserve is atomic and nothing releases one
  const mkReservations = (o = {}) => {
    const j = { entries: [], reserves: 0 };
    const same = (a, b) => a.poolIdHex === b.poolIdHex && a.revision === b.revision;
    j.api = {
      get: (k) => j.entries.find((e) => same(e, k)) || null,
      reserve: (e) => {
        j.reserves++;
        if (o.reserveFails) throw new Error("simulated: the member folder is read-only");
        if (j.entries.some((x) => same(x, e))) throw new Error("EEXIST: already reserved");
        j.entries.push({ ...e });
      },
      confirm: (k) => { const r = j.entries.find((x) => same(x, k)); if (r && !r.confirmedAt) Object.assign(r, { confirmedHeight: k.confirmedHeight, confirmedAt: k.confirmedAt }); },
    };
    return j;
  };
  const run = (w, o = {}) => T.runApproval({ proposal: o.proposal || agreed, card: o.card || card, agreed: o.agreed === undefined ? agreedTerms : o.agreed,
    ownerKey: o.ownerKey || ownerKey, identityHex: IDENTITY_HEX, world: w, reservations: o.reservations === undefined ? mkReservations().api : o.reservations,
    confirm: o.confirm || (async () => true) });
  const rejects = async (name, p, re, afterSend) => {
    try { await p; failed++; console.error(`FAIL: ${name} (no stop)`); }
    catch (e) { ok(`${name} (${e.message.slice(0, 70)})`, e instanceof T.TrialStop && re.test(e.message) && (afterSend === undefined || e.afterSend === afterSend)); }
  };
  {
    const { s, w } = world();
    const r = await run(w);
    ok("the successful path: compared, preflighted, sent once, settled and read back", r.outcome === "approved" && s.sends === 1 && r.stamped === 1563301
      && s.events.join(",") === "preflight,read,send,wait,read");
    const again = await run(w);
    ok("approving the same proposal again sends nothing", again.outcome === "already-approved" && s.sends === 1);
  }
  {
    const { s, w } = world();
    let asked = 0;
    const r = await run(w, { proposal: altered, confirm: async () => { asked++; return true; } });
    ok("ALTERED TERMS (a soundness-review finding): refused on the comparison, before the preflight, the question, any read or any send",
      r.outcome === "differs" && r.comparison.differs && asked === 0 && s.events.length === 0);
  }
  {
    const { s, w } = world({ waitThrows: true });
    const j = mkReservations();
    await rejects("AN ACCEPTED WRITE FOLLOWED BY AN ERROR (a soundness-review finding) stops as sent, not as a plain error", run(w, { reservations: j.api }), /the approval was sent, and waiting for its result failed/, true);
    ok("and it was sent exactly once, the revision reserved just before", s.sends === 1 && s.docs.length === 1 && j.reserves === 1 && j.entries.length === 1 && !j.entries[0].confirmedAt);
    let asked = 0;
    const w2 = { ...w, awaitResult: async () => ({ settled: true }) };
    s.stale = true;
    await rejects("A READ FROM BEFORE THE WRITE LANDED: the next run sends nothing, and says the earlier attempt was started and may have been sent",
      run(w2, { reservations: j.api, confirm: async () => { asked++; return true; } }), /earlier attempt at revision 1 was started at .* and may have been sent\. This read, at Platform height 100, does not show it/, false);
    ok("and it neither asked nor sent", s.sends === 1 && asked === 0);
    s.stale = false;
    const r = await run(w2, { reservations: j.api, confirm: async () => { asked++; return true; } });
    ok("RECONCILIATION: once the ledger shows it, the next run finds it, sends nothing, asks nothing, and marks the reservation as seen without releasing it",
      r.outcome === "already-approved" && s.sends === 1 && asked === 0 && j.entries.length === 1 && Boolean(j.entries[0].confirmedAt));
    s.stale = true;
    await rejects("a stale read after the reservation is marked seen still sends nothing", run(w2, { reservations: j.api }), /read back by proof at .* \(Platform height 101\), and this read, at height 100, does not show it/, false);
    ok("and still one send", s.sends === 1);
  }
  {
    // the narrow confirmation's first case: a CONFIRMED approval, then a read from before it landed
    const { s, w } = world();
    const j = mkReservations();
    const r = await run(w, { reservations: j.api });
    ok("the successful path reserves once and marks the reservation as seen", r.outcome === "approved" && j.reserves === 1 && Boolean(j.entries[0].confirmedAt));
    s.stale = true;
    await rejects("a read from before a confirmed approval landed sends nothing again", run(w, { reservations: j.api }), /read back by proof/, false);
    ok("and it was sent once in all", s.sends === 1);
  }
  {
    // its second case: two runs that both read an empty ledger and both confirm
    const { s, w } = world();
    const j = mkReservations();
    let release;
    const gate = new Promise((res) => { release = res; });
    const realSign = L.Message.prototype.sign;
    let signs = 0;
    L.Message.prototype.sign = function (...args) { signs++; return realSign.apply(this, args); };
    const both = [run(w, { reservations: j.api, confirm: () => gate }), run(w, { reservations: j.api, confirm: () => gate })];
    release(true);
    const settled = await Promise.allSettled(both);
    L.Message.prototype.sign = realSign;
    const refused = settled.filter((x) => x.status === "rejected" && x.reason instanceof T.TrialStop && !x.reason.afterSend && /could not be reserved .* so nothing was signed or sent/.test(x.reason.message));
    ok(`TWO RUNS AT ONCE: one signs and sends, and the other is refused at the reservation having signed nothing (signatures ${signs}, sends ${s.sends})`,
      s.sends === 1 && signs === 1 && refused.length === 1 && settled.some((x) => x.status === "fulfilled" && x.value.outcome === "approved"));
  }
  {
    // its third case: a reservation made, then the run ended before the send
    const { s, w } = world();
    const j = mkReservations();
    j.entries.push({ poolIdHex: agreed.poolId, revision: 1, recordHex: "7b7d", readHeight: 100, reservedAt: "2026-09-30T12:00:00.000Z" });
    let message = "";
    try { await run(w, { reservations: j.api }); } catch (e) { message = e.message; }
    ok("a reservation whose send never happened is reported as started and possibly sent, never as sent", /was started at 2026-09-30T12:00:00.000Z and may have been sent/.test(message)
      && !/was sent at/.test(message) && s.sends === 0);
  }
  {
    const { s, w } = world();
    const j = mkReservations({ reserveFails: true });
    await rejects("an attempt that cannot reserve its revision is not signed or sent", run(w, { reservations: j.api }), /could not be reserved .* so nothing was signed or sent/, false);
    ok("and nothing was sent", s.sends === 0);
    await rejects("no reservations at all is refused before anything", run(w, { reservations: null }), /cannot keep to one send per revision/, false);
    const k = mkReservations();
    await run(world().w, { reservations: k.api, confirm: async () => false });
    ok("a declined confirmation reserves nothing", k.reserves === 0 && k.entries.length === 0);
  }
  {
    const { s, w } = world({ sendThrows: true });
    let message = "";
    try { await run(w); } catch (e) { message = e instanceof T.TrialStop && e.afterSend ? e.message : ""; }
    ok("a send step that fails is reported as possibly on the ledger, never as handed to the network (the narrow confirmation of 1cfbcda)",
      /the send step did not complete, and the approval may or may not have reached the network/.test(message) && !/handed to the network|was sent/.test(message) && s.sends === 1);
  }
  { const { s, w } = world({ unsettled: true }); await rejects("an unsettled result stops as sent", run(w), /not seen with proof/, true); ok("with one attempt only", s.sends === 1); }
  { const { w } = world({ waitReturnsJunk: true }); await rejects("a wait that returns nothing stops as sent", run(w), /not seen with proof/, true); }
  { const { w } = world({ readFailsAfterSend: true }); await rejects("a read-back that fails stops as sent", run(w), /reading it back failed/, true); }
  { const { w } = world({ readJunkAfterSend: true }); await rejects("an error nobody anticipated after the send still stops as sent", run(w), /the approval was sent, and then/, true); }
  { const { w } = world({ otherBytes: true }); await rejects("a read-back with other bytes stops as sent", run(w), /read-back does not hold/, true); }
  {
    const { s, w } = world({ preflightFails: true });
    let asked = 0;
    await rejects("a preflight failure stops before anything is signed or sent", run(w, { confirm: async () => { asked++; return true; } }), /not ready to send/, false);
    ok("and nothing was read, asked or sent", s.sends === 0 && asked === 0 && s.events.join(",") === "preflight");
  }
  {
    const { s, w } = world();
    let asked = 0;
    const r = await run(w, { confirm: async () => { asked++; return false; } });
    ok("a member who declines sends nothing", r.outcome === "declined" && s.sends === 0 && asked === 1);
  }
  {
    const { s, w } = world();
    let asked = 0;
    const bad = clone(agreed); bad.agreement.registration.shares[0].refundAddress = OTHER.refund;
    await rejects("a proposal with a redirected refund address stops before the member is even asked", run(w, { proposal: bad, confirm: async () => { asked++; return true; } }), /REFUND ADDRESS IS NOT YOURS/, false);
    ok("and nothing was sent or asked", s.sends === 0 && asked === 0);
  }
  { const { s, w } = world(); await rejects("no recorded agreed terms stops before anything", run(w, { agreed: null }), /cannot be compared with/, false); ok("and nothing happened", s.events.length === 0); }
  {
    // an approval with these exact terms already on the ledger, but carrying a signature that is not the
    // member's, is not "already approved"
    const a0 = T.buildApproval({ proposal: agreed, identityHex: IDENTITY_HEX, ownerKey });
    const m0 = W.documentFromApproval({ record: a0.record, ownerSignature: a0.ownerSignature });
    const otherSigned = { id: "ab".repeat(32), ownerId: IDENTITY_HEX, poolId: m0.poolIdHex, termsRevision: 1, record: m0.recordHex,
      ownerSignature: Buffer.from(new L.Message(a0.message).sign(new L.PrivateKey(undefined, "testnet")), "base64").toString("hex"), createdAtCoreBlockHeight: 1, createdAt: 1 };
    const { s, w } = world({ preexisting: [otherSigned] });
    await rejects("an approval with these terms signed by another key is not taken as yours", run(w), /does not hold/, false);
    ok("and nothing was sent", s.sends === 0);
  }
  { const { s, w } = world({ readFails: true }); await rejects("an unproved read stops before any send", run(w), /not read by proof/, false); ok("and nothing was sent", s.sends === 0); }
  { const { w } = world(); await rejects("another owner key stops", run(w, { ownerKey: new L.PrivateKey(undefined, "testnet") }), /owner key does not match/, false); }
  {
    // the live state after a soundness-review finding: the altered terms approved at revision 1. The agreed terms at revision
    // 1 are refused, and the agreed terms at revision 2 are sent
    const { s, w } = world();
    const a1 = T.buildApproval({ proposal: altered, identityHex: IDENTITY_HEX, ownerKey });
    const m1 = W.documentFromApproval({ record: a1.record, ownerSignature: a1.ownerSignature });
    s.docs.push({ id: "aa".repeat(32), ownerId: IDENTITY_HEX, poolId: m1.poolIdHex, termsRevision: 1, record: m1.recordHex, ownerSignature: m1.ownerSignatureHex, createdAtCoreBlockHeight: 1563621 });
    await rejects("with the altered terms held at revision 1, the agreed terms at revision 1 are refused, never sent", run(w), /different terms at revision 1/, false);
    const r2 = clone(agreed); r2.revision = 2;
    const r = await run(w, { proposal: r2 });
    ok("and the agreed terms at revision 2 are sent and read back", r.outcome === "approved" && s.sends === 1 && s.docs.length === 2);
    const screen = T.statusScreen({ poolIdHex: agreed.poolId, height: 608700, agreed: agreedTerms,
      held: s.docs.map((doc) => ({ doc, record: JSON.parse(Buffer.from(doc.record, "hex").toString("utf8")), problems: [] })) });
    ok("status leads with the highest revision and says it matches, and marks revision 1 as differing",
      /^You hold 2 approvals for this pool/.test(screen[3]) && /^Revision 2, the highest, is the one that would count at registration, and it matches your agreed terms\.$/.test(screen[4])
      && screen.some((l) => /^1\s+300 DASH\s+50 DASH\s+1563621\s+yes\s+differ$/.test(l)) && screen.some((l) => /^2\s+400 DASH\s+10 DASH\s+1563301\s+yes\s+match$/.test(l)));
    const pendingR3 = { poolIdHex: agreed.poolId, revision: 3, recordHex: "7b7d", reservedAt: "2026-09-30T12:00:00.000Z" };
    const withPending = T.statusScreen({ poolIdHex: agreed.poolId, height: 608700, agreed: agreedTerms, pending: [pendingR3],
      held: s.docs.map((doc) => ({ doc, record: JSON.parse(Buffer.from(doc.record, "hex").toString("utf8")), problems: [] })) });
    ok("status names an attempt the read does not show as started and possibly sent, saying what the read shows and not asserting absence",
      withPending.some((l) => /^An attempt at revision 3 was started at .* and may have been sent\. This read, at Platform height 608700, does not show it\.$/.test(l))
      && !withPending.some((l) => /not on the ledger/.test(l))
      && T.confirmedSends({ pending: [pendingR3], docs: s.docs }).length === 0
      && T.confirmedSends({ pending: [{ ...pendingR3, revision: 2, recordHex: s.docs[1].record }], docs: s.docs }).length === 1);
    const only1 = T.statusScreen({ poolIdHex: agreed.poolId, height: 1, agreed: agreedTerms, held: [{ doc: s.docs[0], record: JSON.parse(Buffer.from(s.docs[0].record, "hex").toString("utf8")), problems: [] }] });
    // A HELD VERSION-1 APPROVAL (the trial's three on testnet) is shown as written and never compared with the
    // version-2 agreed terms, whatever its reward says (the review found the earlier x100 deciding "match")
    {
      const v1 = { domain: approval.DOMAIN, version: 1, platformChainId: agreed.platformChainId, contractId: agreed.contractId, poolId: agreed.poolId, l1GenesisHash: agreed.l1GenesisHash,
        memberIdentity: IDENTITY_HEX, revision: 1, notAfterHeight: agreed.notAfterHeight, agreement: { shares: agreed.agreement.registration.shares.map((sh) => ({ ...sh })),
          earlyPeriodBlocks: 100, earlyPenalty: 10 * 1e8, operatorPubKey: agreed.agreement.registration.operatorPubKey, votingAddress: agreed.agreement.registration.votingAddress,
          operatorReward: 5, myIndex: 0, myContributionDuffs: 400 * 1e8, myFeeDuffs: 10000 } };
      const asText = clone(v1); asText.agreement.operatorReward = "0";
      const held1 = (r) => [{ doc: { termsRevision: 1, createdAtCoreBlockHeight: 1, record: "00" }, record: r, problems: [] }];
      const m1 = T.statusModel({ poolIdHex: agreed.poolId, height: 1, agreed: agreedTerms, held: held1(v1) });
      ok("a held version-1 approval is labeled as version 1, not compared, and the top line says it is shown as written", m1.rows[0].agreed === "version 1, not compared" && m1.top.agreed === "version 1, not compared"
        && /recorded in the earlier format \(version 1\) and is shown as written, not compared/.test(m1.topLine) && m1.rows[0].contribution === "400 DASH" && m1.replacesNote === null);
      ok("a version-1 approval whose reward is the text \"0\" is not labeled a match against agreed terms of 0 basis points", T.statusModel({ poolIdHex: agreed.poolId, height: 1,
        agreed: { ...agreedTerms, operatorRewardBps: 0 }, held: held1(asText) }).rows[0].agreed === "version 1, not compared");
      let refused = null; try { T.compareWithAgreed({ record: v1, agreed: agreedTerms }); } catch (e) { refused = e.message; }
      ok("compareWithAgreed refuses a version-1 record by name rather than converting its reward", /version-1 approval is not compared/.test(refused || ""));
      const screen1 = T.statusScreen({ poolIdHex: agreed.poolId, height: 1, agreed: agreedTerms, held: held1(v1) }).join("\n");
      ok("and the command-line status screen carries the label", /version 1, not compared/.test(screen1) && /shown as written/.test(screen1));
    }
    ok("with only the altered approval, status says the highest revision DIFFERS and how it is replaced", only1.some((l) => /DIFFERS from your agreed terms/.test(l)) && only1.some((l) => /higher revision that matches/.test(l)));
  }
  // ================= the coordinator's revision-2 pair =================
  {
    const r2 = (r) => C.buildTrialProposals({ card, other: OTHER, operatorPubKey: "8".repeat(96), votingAddress: addr(), ids: IDS, tipHeight: 1563700, revision: 2, rand: () => r });
    const p = r2(0);
    const a2 = p.files[p.answer.agreed], x2 = p.files[p.answer.altered];
    const diffs = [];
    const walk = (a, b, pth) => { if (typeof a !== "object" || a === null) { if (a !== b) diffs.push(pth); return; } for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) walk(a[k], b[k], `${pth}.${k}`); };
    walk(a2, x2, "");
    ok(`revision 2's pair differs only in the early-exit period and the operator reward (got ${diffs.join(", ")})`,
      JSON.stringify(diffs.sort()) === JSON.stringify([".agreement.registration.earlyPeriodBlocks", ".agreement.registration.operatorRewardBps"]));
    ok("revision 2's files are proposal-3 and proposal-4, both at revision 2, the draw deciding the order",
      JSON.stringify(Object.keys(p.files).sort()) === '["proposal-3.json","proposal-4.json"]' && a2.revision === 2 && x2.revision === 2
      && r2(1).answer.altered !== p.answer.altered);
    ok("revision 2's agreed proposal matches the agreed terms and its altered one does not",
      !T.compareWithAgreed({ proposal: a2, agreed: agreedTerms }).differs && T.compareWithAgreed({ proposal: x2, agreed: agreedTerms }).differs
      && T.checkProposal({ proposal: x2, card }).problems.length === 0);
  }
  // ================= the coordinator's revision-3 pair (the live approve from the page) =================
  {
    const r3 = (r) => C.buildTrialProposals({ card, other: OTHER, operatorPubKey: "8".repeat(96), votingAddress: addr(), ids: IDS, tipHeight: 1563700, revision: 3, rand: () => r });
    const p = r3(0);
    const a3 = p.files[p.answer.agreed], x3 = p.files[p.answer.altered];
    const diffs = [];
    const walk = (a, b, pth) => { if (typeof a !== "object" || a === null) { if (a !== b) diffs.push(pth); return; } for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) walk(a[k], b[k], `${pth}.${k}`); };
    walk(a3, x3, "");
    ok(`revision 3's pair differs only in the member's fee share (got ${diffs.join(", ")})`, JSON.stringify(diffs) === JSON.stringify([".agreement.myFeeDuffs"]) && x3.agreement.myFeeDuffs === 100000);
    ok("revision 3's files are proposal-5 and proposal-6, both at revision 3, the draw deciding the order",
      JSON.stringify(Object.keys(p.files).sort()) === '["proposal-5.json","proposal-6.json"]' && a3.revision === 3 && x3.revision === 3 && r3(1).answer.altered !== p.answer.altered);
    const cmp = T.compareWithAgreed({ proposal: x3, agreed: agreedTerms });
    ok("revision 3's agreed proposal matches the agreed terms and its altered one differs in the fee-share row alone",
      !T.compareWithAgreed({ proposal: a3, agreed: agreedTerms }).differs && cmp.differs && cmp.rows.filter((r) => !r.same).map((r) => r.term).join() === "Your registration fee share"
      && T.checkProposal({ proposal: x3, card }).problems.length === 0);
  }
  {
    // the review's construction: a valid owner-signed record for another pool, revision 7 and another
    // member, wrapped in a document indexed under this member, the trial pool and revision 1
    const other = clone(agreed); other.poolId = "ee".repeat(32); other.revision = 7;
    const a = T.buildApproval({ proposal: other, identityHex: "ab".repeat(32), ownerKey });
    const m = W.documentFromApproval({ record: a.record, ownerSignature: a.ownerSignature });
    const wrapped = { id: "cd".repeat(32), ownerId: IDENTITY_HEX, poolId: agreed.poolId, termsRevision: 1, record: m.recordHex, ownerSignature: m.ownerSignatureHex };
    const probs = T.checkHeldApproval({ doc: wrapped, identityHex: IDENTITY_HEX, poolIdHex: agreed.poolId, ownerAddress: card.addresses.owner,
      context: { platformChainId: IDS.platformChainId, contractId: IDS.contractId, l1GenesisHash: agreed.l1GenesisHash } });
    ok(`a record for another member, pool and revision, wrapped under this member's document, is named three times (${probs.join("; ")})`,
      probs.some((p) => /another member/.test(p)) && probs.some((p) => /another pool/.test(p)) && probs.some((p) => /another revision/.test(p)));
    const good = T.buildApproval({ proposal: agreed, identityHex: IDENTITY_HEX, ownerKey });
    const gm = W.documentFromApproval({ record: good.record, ownerSignature: good.ownerSignature });
    const gdoc = { id: "ef".repeat(32), ownerId: IDENTITY_HEX, poolId: agreed.poolId, termsRevision: 1, record: gm.recordHex, ownerSignature: gm.ownerSignatureHex };
    const ctx = { platformChainId: IDS.platformChainId, contractId: IDS.contractId, l1GenesisHash: agreed.l1GenesisHash };
    ok("the member's own approval holds", T.checkHeldApproval({ doc: gdoc, identityHex: IDENTITY_HEX, poolIdHex: agreed.poolId, ownerAddress: card.addresses.owner, context: ctx }).length === 0);
    ok("a document indexed under another pool, its record naming the requested one, is named as a served mismatch",
      T.checkHeldApproval({ doc: { ...gdoc, poolId: "ee".repeat(32) }, identityHex: IDENTITY_HEX, poolIdHex: agreed.poolId, ownerAddress: card.addresses.owner, context: ctx })
        .some((p) => /the served approval names another pool/.test(p)));
    ok("a document served for another pool is named", T.checkHeldApproval({ doc: gdoc, identityHex: IDENTITY_HEX, poolIdHex: "ee".repeat(32), ownerAddress: card.addresses.owner, context: ctx }).some((p) => /another pool/.test(p)));
    ok("a document indexed at another revision is named", T.verifyReadBack({ doc: { ...gdoc, termsRevision: 2 }, identityHex: IDENTITY_HEX, ownerAddress: card.addresses.owner, context: ctx,
      material: { poolIdHex: agreed.poolId, termsRevision: 1, recordHex: gm.recordHex, ownerSignatureHex: gm.ownerSignatureHex } }).some((p) => /carries another revision/.test(p)));
    ok("a record naming another ledger contract is named", T.checkHeldApproval({ doc: gdoc, identityHex: IDENTITY_HEX, poolIdHex: agreed.poolId, ownerAddress: card.addresses.owner,
      context: { ...ctx, contractId: "4fJLR2GYTPFdomuTVvNy3VRrvWgvkKPzqehEBpNf2nk6" } }).some((p) => /another contractId/.test(p)));
  }
  {
    const doc = { ownerId: "00".repeat(32), poolId: agreed.poolId, termsRevision: 1, record: "7b7d", ownerSignature: "00" };
    const probs = T.verifyReadBack({ doc, identityHex: IDENTITY_HEX, material: { poolIdHex: agreed.poolId, termsRevision: 1, recordHex: "7b7d", ownerSignatureHex: "00" }, ownerAddress: card.addresses.owner });
    ok("a read-back owned by another identity, with a signature that does not verify, is named twice", probs.some((p) => /another identity/.test(p)) && probs.some((p) => /does not verify/.test(p)));
  }

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`memberTrialTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exit(1);
})().catch((e) => { console.error(e); process.exit(1); });
