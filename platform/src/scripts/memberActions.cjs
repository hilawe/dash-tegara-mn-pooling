"use strict";
/**
 * THE MEMBER TOOL'S FOLDER AND THE ACTIONS BOTH OF ITS FACES SHARE: the command line (memberTrialRun.mjs)
 * and the local page (memberUiApi.cjs). Moved here from the command-line runner, where no battery could
 * reach it, so the two faces cannot differ in which proposals they read, where a refusal is recorded, how
 * a revision is reserved, or how status is read. Every decision stays in memberTrial.cjs.
 *
 *   makeMemberFolder({ memberDir, trialDir, now })
 *       proposalFiles, readProposal(file), readCard, readAgreed, writeAgreed(agreed),
 *       reservations { get, reserve, confirm }, reservationsFor(poolIdHex), readRefusals, appendRefusal
 *   readStatus({ folder, openWorld, markSeen })
 *       the member's approvals for the trial's pool, read by proof and checked, in the form statusScreen and
 *       statusModel take; marks as seen each reservation whose approval the read shows, unless markSeen
 *       says not to. markSeen is a boolean or a FUNCTION DECIDED AT THE WRITE, after the proof read, since
 *       a status read can be in flight when an approval starts (the page passes () => no approval active,
 *       so status writes nothing while one runs, whenever the read began)
 *   openWithTries({ ask, open, tries, say })
 *       the passphrase, with a few tries before the run ends (HELP_LOG item 7)
 *   identityHexOf(b58)
 *
 * THE RESERVATIONS, one file per pool and revision, are created with an exclusive write immediately before
 * a send and never deleted, so a member folder sends at most once per revision whatever a stale read shows
 * and however two runs interleave, from either face. Lost or edited, the approval contract's unique index
 * is the backstop (docs/REVIEW_ASSESSMENT.md, 2026-09-30).
 */
const fs = require("fs");
const path = require("path");
const T = require("./memberTrial.cjs");
const S = require("./memberStore.cjs");
const formationCore = require("./formationCore.cjs");
const ledger = require("./memberApprovalLedger.cjs");

const AGREED_FILE = "agreed-terms.json";
const REFUSALS_FILE = "refusals.log";
const PROPOSAL_NAME = /^proposal-\d+\.json$/;
const HEX64 = /^[0-9a-f]{64}$/;
const msgOf = (e) => (e && e.message) || String(e);

function identityHexOf(b58) {
  const d = formationCore.toId32(b58);
  if (!d) throw new Error("the id does not decode");
  return d.toString("hex");
}

function makeMemberFolder({ memberDir, trialDir, now = () => new Date() }) {
  const proposalFiles = () => (fs.existsSync(trialDir) ? fs.readdirSync(trialDir).filter((f) => PROPOSAL_NAME.test(f))
    .sort((a, b) => Number(a.match(/\d+/)[0]) - Number(b.match(/\d+/)[0])) : []);
  // ONLY A NAME THE LISTING SHOWS IS READ, so no request names a path outside the proposals folder
  const readProposal = (file) => {
    const files = proposalFiles();
    if (typeof file !== "string" || !files.includes(file)) {
      throw new T.TrialStop(`there is no proposal named "${file}". The proposals you can use: ${files.length ? files.join(", ") : "none yet"}`);
    }
    return JSON.parse(fs.readFileSync(path.join(trialDir, file), "utf8"));
  };
  const readCard = () => JSON.parse(fs.readFileSync(path.join(memberDir, S.CARD), "utf8"));
  const readAgreed = () => { try { return JSON.parse(fs.readFileSync(path.join(memberDir, AGREED_FILE), "utf8")); } catch { return null; } };
  const writeAgreed = (agreed) => fs.writeFileSync(path.join(memberDir, AGREED_FILE), JSON.stringify(agreed, null, 2), { mode: 0o644 });

  const sends = path.join(memberDir, "sends");
  const reservationFile = ({ poolIdHex, revision }) => {
    if (!HEX64.test(poolIdHex) || !Number.isSafeInteger(revision) || revision < 1) throw new Error("the reservation names no valid pool and revision");
    return path.join(sends, `${poolIdHex}-r${revision}.json`);
  };
  const readReservation = (file) => {
    try { return JSON.parse(fs.readFileSync(file, "utf8")); }
    catch (e) { if (e.code === "ENOENT") return null; throw new Error(`your reservation ${path.basename(file)} cannot be read: ${msgOf(e)}`); }
  };
  const reservations = {
    get: (k) => readReservation(reservationFile(k)),
    reserve: (entry) => { fs.mkdirSync(sends, { recursive: true }); fs.writeFileSync(reservationFile(entry), JSON.stringify(entry, null, 2), { flag: "wx" }); },
    confirm: (k) => {
      const file = reservationFile(k);
      const r = readReservation(file);
      if (!r || r.confirmedAt) return;
      const tmp = `${file}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({ ...r, confirmedHeight: k.confirmedHeight, confirmedAt: k.confirmedAt }, null, 2));
      fs.renameSync(tmp, file);
    },
  };
  const reservationsFor = (poolIdHex) => (fs.existsSync(sends) ? fs.readdirSync(sends).filter((f) => f.startsWith(`${poolIdHex}-r`) && f.endsWith(".json"))
    .map((f) => readReservation(path.join(sends, f))).filter(Boolean) : []);

  // THE REFUSALS LOG, one JSON line per refusal. A line this tool cannot read is COUNTED, never skipped
  // silently, so an unreadable log is not read as "you refused nothing"
  const refusalsPath = path.join(memberDir, REFUSALS_FILE);
  const readRefusals = () => {
    if (!fs.existsSync(refusalsPath)) return { entries: [], unreadable: 0 };
    const entries = [];
    let unreadable = 0;
    for (const text of fs.readFileSync(refusalsPath, "utf8").split("\n")) {
      if (!text.trim()) continue;
      let r = null;
      try { r = JSON.parse(text); } catch { /* counted below */ }
      if (r && typeof r === "object" && typeof r.file === "string" && typeof r.at === "string" && typeof r.reason === "string"
        && typeof r.proposalSha256 === "string" && HEX64.test(r.proposalSha256)) entries.push({ at: r.at, file: r.file, proposalSha256: r.proposalSha256, reason: r.reason });
      else unreadable += 1;
    }
    return { entries, unreadable };
  };
  const appendRefusal = ({ file, proposal, reason }) => {
    const entry = { at: now().toISOString(), file, proposalSha256: T.digestOf(proposal), reason };
    fs.appendFileSync(refusalsPath, `${JSON.stringify(entry)}\n`, { mode: 0o644 });
    return entry;
  };

  return { memberDir, trialDir, proposalFiles, readProposal, readCard, readAgreed, writeAgreed, reservations, reservationsFor, readRefusals, appendRefusal };
}

/**
 * The member's approvals for the trial's pool (the first proposal's pool and chain, as the command line
 * has always read it), each checked against the requested pool and the pinned chain and contract.
 * Returns { noIdentity } | { noProposal } | { poolIdHex, height, held, agreed, pending }. Throws when the
 * read is not a proved read.
 */
async function readStatus({ folder, openWorld, now = () => new Date(), markSeen = true }) {
  const card = folder.readCard();
  if (!card.identityB58) return { noIdentity: true };
  const files = folder.proposalFiles();
  if (!files.length) return { noProposal: true };
  const identityHex = identityHexOf(card.identityB58);
  const trialRef = folder.readProposal(files[0]);
  const pinned = T.PINNED_BY_CHAIN[trialRef.platformChainId];
  if (typeof trialRef.platformChainId !== "string" || !Object.hasOwn(T.PINNED_BY_CHAIN, trialRef.platformChainId) || !pinned) {
    throw new T.TrialStop(`the proposals name Platform chain ${trialRef.platformChainId}, which this tool has no authorized contracts for`);
  }
  const world = await openWorld({ card, identityHex, platformChainId: trialRef.platformChainId, poolIdHex: trialRef.poolId });
  const { docs, height } = await world.readMine();
  const context = { platformChainId: trialRef.platformChainId, contractId: pinned.contractId,
    l1GenesisHash: ledger.CORE_GENESIS_BY_PLATFORM_CHAIN[trialRef.platformChainId] };
  const held = docs.map((doc) => {
    let record = null; try { record = JSON.parse(Buffer.from(doc.record, "hex").toString("utf8")); } catch { /* shown as unreadable */ }
    return { doc, record, problems: T.checkHeldApproval({ doc, identityHex, poolIdHex: trialRef.poolId, ownerAddress: card.addresses.owner, context }) };
  });
  // decided here, with no await between the decision and the writes, so nothing can start in between
  const mayMark = typeof markSeen === "function" ? markSeen() === true : markSeen === true;
  if (mayMark) {
    for (const seen of T.confirmedSends({ pending: folder.reservationsFor(trialRef.poolId), docs })) {
      folder.reservations.confirm({ poolIdHex: seen.poolIdHex, revision: seen.revision, confirmedHeight: height, confirmedAt: now().toISOString() });
    }
  }
  return { poolIdHex: trialRef.poolId, height, held, agreed: folder.readAgreed(), pending: folder.reservationsFor(trialRef.poolId) };
}

/**
 * The member's store, opened with a passphrase asked up to `tries` times (HELP_LOG item 7: one mistyped
 * passphrase ended the run, and the whole command had to be run again). Only a passphrase that does not
 * open the store is asked again; any other refusal ends at once. The last refusal is thrown as it came.
 */
async function openWithTries({ ask, open, tries = 3, say }) {
  for (let i = 1; ; i++) {
    const passphrase = await ask();
    try { return open(passphrase); } catch (e) {
      if (!(e instanceof S.StoreRefusal) || !/does not open/.test(msgOf(e)) || i >= tries) throw e;
      const left = tries - i;
      say(`That passphrase does not open your member store. It is the one you chose at init. ${left} ${left === 1 ? "try" : "tries"} left.`);
    }
  }
}

module.exports = { AGREED_FILE, REFUSALS_FILE, makeMemberFolder, readStatus, openWithTries, identityHexOf };
