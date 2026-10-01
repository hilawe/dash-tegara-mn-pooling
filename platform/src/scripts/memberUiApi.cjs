"use strict";
/**
 * THE LOCAL MEMBER PAGE'S API. The page (tegara/member-ui/page) is served by memberUiRun.mjs on the
 * member's own machine, in the member tool's container, at a loopback address. This module is the whole
 * of what the page can ask for: a composition over the member tool's decisions (memberTrial.cjs) and its
 * folder (memberActions.cjs), driven offline by memberUiTest.cjs. The runner adapts node's http server to
 * handle() and holds nothing else.
 *
 * IT IS IN THE SIGNING PATH. The invariants, written before the mechanism:
 *   1. THE GATE. Every request must carry Host exactly 127.0.0.1:PORT, so a foreign name that resolves to
 *      this address (DNS rebinding) is refused. Every API request must be a POST with Origin exactly
 *      http://127.0.0.1:PORT, a JSON body, no cross-site fetch marker, and the session secret. The session
 *      is issued ONCE, in exchange for the one-time token the member's terminal printed. So another page in
 *      the browser drives nothing, and a local process without the printed link drives nothing.
 *   2. THE SERVER DECIDES. Every decision the page shows is made again here, for the request, by
 *      memberTrial.cjs over the files as they are now. Nothing the page sends can make this approve a
 *      proposal the comparison refuses, and the passphrase is not touched until the decision is "matches".
 *   3. WHAT WAS SHOWN IS WHAT IS SIGNED. An approval request carries the digests of the proposal and the
 *      agreed terms the page displayed, and is refused if either file has changed since. The decision and
 *      the digests are checked at prepare AND AGAIN at the confirming request, over the files as they are
 *      then, so a file changed while the member read the screen declines the run before anything is
 *      signed. runApproval then makes its own checks, and signs only after the typed word "approve".
 *   4. ONE APPROVAL AT A TIME. It ends by the member's answer, by a timeout (a decline), or by its own
 *      outcome. While one is under way, nothing else that changes the member folder is accepted: agree and
 *      refuse are refused, and status reads the ledger but does not mark reservations as seen, decided at
 *      the moment of the write rather than at the request, since a read can be in flight when one starts.
 *   5. THE PASSPHRASE opens the store for that request only. It is never stored, logged or returned.
 *   6. A CLAIM ABOUT SIGNING OR SENDING COMES ONLY FROM THE RECORDED OUTCOME OF THE SPECIFIC ATTEMPT. end()
 *      records, from runApproval's own result, whether the attempt ended with nothing signed or sent (a
 *      decline, a timeout, "differs", "already approved", a stop before the send, which may have reserved
 *      the revision, or a connection that could not be opened, which is recorded without a run), and every
 *      response about that attempt takes nothingSignedOrSent from that record and from nowhere else. A refusal that starts no attempt (prepare, before the store is opened)
 *      says only that no approval was started (attemptStarted false). A generic refusal (the gate, the
 *      session, the spent link, an unknown file, an error) says nothing about any approval. While an attempt
 *      is active, every other request about it is refused with no claim either way (a soundness-review finding), and every stop
 *      after the send says the approval may be on the ledger (runApproval's afterSend), as the command line
 *      does.
 *
 * WHAT IT DOES NOT PROTECT AGAINST: code running as the member on the member's machine, which can read the
 * printed link or the passphrase as it is typed, as memberStore.cjs already says of the command line.
 */
const crypto = require("crypto");
const T = require("./memberTrial.cjs");
const A = require("./memberActions.cjs");

const PENDING_MS = 5 * 60 * 1000;
const MAX_BODY = 64 * 1024;
const MAX_REASON = 500;
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const BASE_HEADERS = Object.freeze({ "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
  "x-frame-options": "DENY", "content-security-policy": CSP, "cross-origin-opener-policy": "same-origin", "cross-origin-resource-policy": "same-origin" });
const HEX64 = /^[0-9a-f]{64}$/;
const msgOf = (e) => (e && e.message) || String(e);
const isInt = (v) => Number.isSafeInteger(v);
const sameSecret = (given, want) => typeof given === "string" && typeof want === "string" && given.length === want.length
  && crypto.timingSafeEqual(Buffer.from(given), Buffer.from(want));
const plain = (duffs) => T.dash(duffs).replace(/ DASH$/, "").replace(/,/g, "");
// nothingSignedOrSent comes ONLY from end()'s record of the attempt (flagOf); attemptStarted false only from
// prepare's refusals before an attempt exists; a generic refusal carries neither
const NOTHING = Object.freeze({ nothingSignedOrSent: true });
const NOT_STARTED = Object.freeze({ attemptStarted: false });

/** The agreed-terms record as the page shows it, and as its form is filled. */
function agreedView(a) {
  const operatorText = require("./registrationTerms.cjs").bpsToPercentText(a.operatorRewardBps);
  return { recordedAt: a.recordedAt, my: T.dash(a.myContributionDuffs), others: a.otherContributionsDuffs.map(T.dash), period: a.earlyPeriodBlocks,
    penalty: T.dash(a.earlyPenaltyDuffs), operator: `${operatorText}%`, operatorBps: a.operatorRewardBps, fee: T.dash(a.myFeeDuffs),
    form: { contribution: plain(a.myContributionDuffs), others: a.otherContributionsDuffs.map(plain).join(", "), period: String(a.earlyPeriodBlocks),
      penalty: plain(a.earlyPenaltyDuffs), operator: operatorText, fee: plain(a.myFeeDuffs) } };
}

/** The share table of a proposal that passed checkProposal, for the page's share cards: each share's reward destination, and whether it was given. */
const sharesOf = (proposal) => {
  const v = require("./memberApproval.cjs").agreementViewOf(proposal.version, proposal.agreement);
  return v.shares.map((sh, i) => ({ number: i + 1, amount: T.dash(sh.amount), mine: i === v.myIndex, ownerAddress: sh.ownerAddress, refundAddress: sh.refundAddress,
    rewardAddress: sh.rewardAddress, rewardAddressGiven: sh.rewardAddressGiven }));
};

/**
 * folder: memberActions.makeMemberFolder(...). openWorld: memberWorld.openMemberWorld. openStore(passphrase)
 * -> { phrase, keys, card }, throwing when the passphrase does not open it. port: the loopback port.
 * token: the one-time token (64 lowercase hex) the runner printed. assets: { "/path": { type, body } }.
 */
function makeMemberUi({ folder, openWorld, openStore, port, token, assets, now = () => new Date(), pendingMs = PENDING_MS,
  randomHex = (n) => crypto.randomBytes(n).toString("hex") }) {
  if (!isInt(port) || port < 1 || port > 65535) throw new Error("the page needs its port");
  if (typeof token !== "string" || !HEX64.test(token)) throw new Error("the page needs a one-time token of 64 hex characters");
  const HOST = `127.0.0.1:${port}`;
  const ORIGIN = `http://${HOST}`;
  let tokenSpent = false;
  let session = null;
  let active = null; // the approval under way: { id, stage: "starting" | "waiting" | "ending", answer, run, timer }
  let lastEnded = null;

  const reply = (status, obj) => ({ status, headers: { ...BASE_HEADERS, "content-type": "application/json; charset=utf-8" }, body: JSON.stringify(obj) });
  const refused = (status, reason, extra = {}) => reply(status, { refused: true, reason, ...extra });

  // ---------------- the one-time link ----------------
  function openSession(body) {
    if (tokenSpent) return refused(403, "This link was already used. The page it opened still works. For a new link, stop the tool with Ctrl-C and start it again.");
    if (!sameSecret(body.token, token)) return refused(403, "This is not the link the tool printed.");
    tokenSpent = true;
    session = randomHex(32);
    return reply(200, { session });
  }

  // ---------------- reading ----------------
  function overview() {
    const card = folder.readCard();
    const agreed = folder.readAgreed();
    const agreedProblems = T.checkAgreed(agreed);
    const refusals = folder.readRefusals();
    const proposals = folder.proposalFiles().map((file) => {
      let proposal;
      try { proposal = folder.readProposal(file); } catch (e) { return { file, decision: "unreadable", headline: `This file cannot be read: ${msgOf(e)}` }; }
      const s = T.approvalScreen({ file, proposal, card, agreed, mode: "inspect", refusals });
      const flag = T.refusedBefore({ file, proposal, refusals });
      return { file, decision: s.decision, headline: s.details.headline, revision: isInt(proposal.revision) ? proposal.revision : null,
        notAfterHeight: isInt(proposal.notAfterHeight) ? proposal.notAfterHeight : null,
        differing: s.details.rows ? s.details.rows.filter((r) => !r.same).map((r) => r.term) : null,
        refusedByYou: flag.exact.length > 0, shares: s.decision === "problems" ? null : sharesOf(proposal) };
    });
    return reply(200, { card: { addresses: card.addresses, identityB58: card.identityB58 || null },
      agreed: agreedProblems.length ? null : agreedView(agreed), agreedProblems, proposals, refusals, busy: Boolean(active), cmd: T.CMD });
  }

  function proposalView(body) {
    const proposal = folder.readProposal(body.file);
    const card = folder.readCard();
    const agreed = folder.readAgreed();
    const refusals = folder.readRefusals();
    const s = T.approvalScreen({ file: body.file, proposal, card, agreed, mode: "inspect", refusals });
    const refused = T.refusedBefore({ file: body.file, proposal, refusals });
    return reply(200, { file: body.file, digest: T.digestOf(proposal), agreedDigest: T.digestOf(agreed), decision: s.decision, ...s.details,
      refused, refusedLines: T.refusalLines(refused), revision: isInt(proposal.revision) ? proposal.revision : null,
      busy: Boolean(active), cmd: T.CMD });
  }

  async function status() {
    let st;
    // while an approval runs, the read marks nothing as seen (invariant 4), decided when the write would
    // happen and not now, since this read may still be in flight when an approval starts
    try { st = await A.readStatus({ folder, openWorld, now, markSeen: () => !active }); } catch (e) { return refused(502, `Your approvals were not read by proof (${msgOf(e)}).`); }
    if (st.noIdentity) return reply(200, { noIdentity: true, headline: "You have no Platform identity yet." });
    if (st.noProposal) return reply(200, { noProposal: true, headline: "There is no proposal yet, so there is no pool to read." });
    return reply(200, { ...T.statusModel(st), cmd: T.CMD });
  }

  // ---------------- writing to the member folder ----------------
  const BUSY = "An approval is waiting for your answer or being sent. Finish or stop it first.";
  function agree(body) {
    if (active) return refused(409, BUSY);
    const existing = folder.readAgreed();
    if (existing && T.checkAgreed(existing).length === 0 && body.replace !== true) {
      return refused(409, "You already recorded agreed terms. Replacing them changes what every proposal is compared with.", { needsReplace: true });
    }
    const fields = ["contribution", "others", "period", "penalty", "operator", "fee"];
    const notText = fields.filter((f) => typeof body[f] !== "string");
    if (notText.length) return refused(400, `These answers are missing: ${notText.join(", ")}.`);
    const r = T.parseAgreedAnswers(Object.fromEntries(fields.map((f) => [f, body[f]])), now());
    if (r.problems) return reply(422, { refused: true, reason: "Not recorded.", problems: r.problems });
    folder.writeAgreed(r.agreed);
    return reply(200, { recorded: true, agreed: agreedView(r.agreed) });
  }

  function refuse(body) {
    if (active) return refused(409, BUSY);
    const proposal = folder.readProposal(body.file);
    if (body.digest !== T.digestOf(proposal)) return refused(409, "This proposal changed since the page showed it. Nothing was recorded. Open it again.", { changed: true });
    const reason = typeof body.reason === "string" ? body.reason.trim() : "";
    if (!reason || reason.length > MAX_REASON) return refused(400, `Give a reason, up to ${MAX_REASON} characters.`);
    // A PROPOSAL THAT MATCHES THE AGREED TERMS IS REFUSED ONLY WHEN THE MEMBER SAYS SO TWICE (HELP_LOG item 6)
    if (T.refusalNeedsConfirmation({ proposal, card: folder.readCard(), agreed: folder.readAgreed() }) && body.confirmMatching !== true) {
      return refused(409, `${body.file} matches your agreed terms. Refusing it records that you do not want to approve it.`, { needsConfirmation: true });
    }
    return reply(200, { recorded: true, entry: folder.appendRefusal({ file: body.file, proposal, reason }) });
  }

  // ---------------- the approval ----------------
  // THE ONE SOURCE of "nothing signed or sent": runApproval's own result, as the command line reads it
  // (declined, differs and already-approved return before anything is reserved; a TrialStop without
  // afterSend or signedNotSent stopped before the send), recorded by end() and read back by flagOf
  const nothingFromResult = (result) => Boolean(result && ((result.ok && ["declined", "differs", "already-approved"].includes(result.ok.outcome))
    || (result.err instanceof T.TrialStop && !result.err.afterSend && !result.err.signedNotSent)));
  const flagOf = (a) => (lastEnded && lastEnded.id === a.id && lastEnded.nothingSent ? NOTHING : {});
  const nothingText = (a) => (flagOf(a).nothingSignedOrSent ? " Nothing signed or sent." : "");

  // EVERY outcome reply spreads the record's flag, including the ones where it is empty, so the record and
  // not the branch decides what is claimed (a flag that ignored the record would reach the approved outcome)
  function outcomeReply(result, a) {
    const { file, proposal } = a;
    const flag = flagOf(a);
    if (result.ok) {
      const r = result.ok;
      if (r.outcome === "declined") return reply(200, { stage: "done", outcome: "declined", headline: `Stopped.${nothingText(a)}`, ...flag });
      if (r.outcome === "differs") return reply(200, { stage: "done", outcome: "differs", headline: `Cannot approve: this proposal differs from your agreed terms.${nothingText(a)}`, ...flag });
      if (r.outcome === "already-approved") {
        return reply(200, { stage: "done", outcome: "already-approved", stamped: r.stamped, ...flag,
          headline: `ALREADY APPROVED: you hold an approval of these exact terms at revision ${proposal.revision}, signed by your owner key.${nothingText(a)}` });
      }
      if (r.outcome === "approved") {
        return reply(200, { stage: "done", outcome: "approved", stamped: r.stamped, ...flag,
          headline: `APPROVED: your approval of ${file} (revision ${proposal.revision}) is on the ledger, read back by proof and signed by your owner key. Stamped at Core height ${r.stamped}.` });
      }
      return reply(500, { stage: "stopped", headline: "Error.", detail: `an outcome this page does not know: ${r.outcome}`, ...flag });
    }
    const e = result.err;
    if (e instanceof T.TrialStop && e.afterSend) {
      return reply(200, { stage: "stopped", afterSend: true, headline: "OUTCOME NOT CONFIRMED: your approval may be on the ledger.", detail: msgOf(e),
        advice: "Do not approve again until status shows what the ledger holds.", ...flag });
    }
    if (e instanceof T.TrialStop && e.signedNotSent) return reply(200, { stage: "stopped", signedNotSent: true, headline: "Cannot continue.", detail: msgOf(e), ...flag });
    if (e instanceof T.TrialStop) return reply(200, { stage: "stopped", headline: "Cannot continue.", detail: msgOf(e), ...flag });
    return reply(500, { stage: "stopped", headline: "Error.", detail: msgOf(e), ...flag });
  }

  // nothingSent is the attempt's recorded outcome: nothingFromResult over runApproval's result, or true for a
  // connection that could not be opened (no run existed)
  function end(a, why, nothingSent) {
    if (active === a) active = null;
    lastEnded = { id: a.id, why, nothingSent };
  }

  function expire(a) {
    if (active !== a || a.stage !== "waiting") return;
    a.stage = "ending";
    a.answer(false);
    a.run.then((result) => end(a, `it waited more than ${Math.round(pendingMs / 60000)} minutes for your answer`, nothingFromResult(result)));
  }

  async function prepare(body) {
    if (active) return refused(409, "An approval is already under way. This request started nothing; the approval's outcome is shown by the request that answers it.");
    const proposal = folder.readProposal(body.file);
    const card = folder.readCard();
    const agreed = folder.readAgreed();
    const s = T.approvalScreen({ file: body.file, proposal, card, agreed, mode: "approve", refusals: folder.readRefusals() });
    // THE SERVER'S OWN DECISION, before the passphrase is touched
    // NO ATTEMPT EXISTS YET: everything up to `active = a` is synchronous, so these refusals say only that
    // none was started, and claim nothing about signing or sending
    if (s.decision !== "matches") return refused(409, s.details.headline, { decision: s.decision, ...NOT_STARTED });
    if (body.digest !== T.digestOf(proposal) || body.agreedDigest !== T.digestOf(agreed)) {
      return refused(409, "This proposal or your agreed terms changed since the page showed them. Open the proposal again.", { changed: true, ...NOT_STARTED });
    }
    if (!card.identityB58) return refused(409, "You have no Platform identity yet.", NOT_STARTED);
    if (typeof body.passphrase !== "string" || !body.passphrase) return refused(400, "Type your member passphrase.", NOT_STARTED);
    let opened;
    try { opened = openStore(body.passphrase); } catch (e) {
      if (/does not open/.test(msgOf(e))) return refused(422, "That passphrase does not open your member store. It is the one you chose at init. Try again.", { passphrase: "wrong", ...NOT_STARTED });
      return refused(409, `Your member store cannot be opened: ${msgOf(e)}`, NOT_STARTED);
    }
    const a = { id: randomHex(16), stage: "starting", file: body.file, proposal };
    active = a; // taken before anything asynchronous, so a second request cannot start another
    try {
      const identityHex = A.identityHexOf(card.identityB58);
      let world;
      try { world = await openWorld({ card, identityHex, platformChainId: proposal.platformChainId, poolIdHex: proposal.poolId, phrase: opened.phrase }); }
      catch (e) { end(a, "the connection to testnet could not be opened", true); return refused(502, `The connection to testnet could not be opened (${msgOf(e)}).`, flagOf(a)); }
      let ready;
      const readyP = new Promise((r) => { ready = r; });
      const answered = new Promise((r) => { a.answer = r; });
      a.run = T.runApproval({ proposal, card, agreed, ownerKey: opened.keys.owner, identityHex, world, reservations: folder.reservations,
        confirm: () => { ready("ready"); return answered; } }).then((ok) => ({ ok }), (err) => ({ err }));
      const first = await Promise.race([readyP, a.run]);
      if (first !== "ready") { end(a, "it finished before asking you", nothingFromResult(first)); return outcomeReply(first, a); }
      a.stage = "waiting";
      a.digest = T.digestOf(proposal);
      a.agreedDigest = T.digestOf(agreed);
      a.timer = setTimeout(() => expire(a), pendingMs);
      if (a.timer.unref) a.timer.unref();
      return reply(200, { stage: "ready", pendingId: a.id, expiresInSeconds: Math.round(pendingMs / 1000), file: body.file, revision: proposal.revision,
        headline: "Ready. Everything the send and the wait need is in place, and this proof read shows no approval of yours at this revision.",
        rows: s.details.rows, terms: s.details.terms, refusedLines: T.refusalLines(s.details.refused) });
    } catch (e) {
      if (active === a && a.stage === "starting") end(a, "an error before you were asked", false);
      throw e;
    }
  }

  /** The files decided again for the confirming request (invariants 2 and 3). Returns a reason, or null. */
  function changedSinceReady(a) {
    let proposal, agreed, s;
    try {
      proposal = folder.readProposal(a.file);
      agreed = folder.readAgreed();
      s = T.approvalScreen({ file: a.file, proposal, card: folder.readCard(), agreed, mode: "approve", refusals: folder.readRefusals() });
    } catch (e) { return `the files could not be read again before signing (${msgOf(e)})`; }
    if (T.digestOf(proposal) !== a.digest || T.digestOf(agreed) !== a.agreedDigest) return "This proposal or your agreed terms changed after the page showed them ready.";
    if (s.decision !== "matches") return [s.details.headline, ...s.details.problems, ...s.details.agreedProblems].join(" ");
    return null;
  }

  async function answer(body, yes) {
    const a = active;
    if (!a || a.stage !== "waiting" || !sameSecret(body.pendingId, a.id)) {
      // WHILE AN APPROVAL IS ACTIVE, NO CLAIM EITHER WAY (a soundness-review finding): its outcome is not recorded yet, so a
      // racing request for it, or for any id, is told only that one is under way
      if (a) return refused(409, "An approval is under way. Its outcome is shown by the request that answered it, and status shows what the ledger holds.");
      const ended = lastEnded && lastEnded.id === body.pendingId ? lastEnded : null;
      if (ended && ended.nothingSent) return refused(409, `This approval ended: ${ended.why}. Nothing was signed or sent by it.`, NOTHING);
      if (ended) return refused(409, `This approval already ended (${ended.why}). Its outcome was shown then, and status shows what the ledger holds.`);
      return refused(409, "No approval is waiting for your answer."); // generic: no attempt, no claim
    }
    clearTimeout(a.timer);
    a.stage = "ending";
    let approve = yes === null ? (typeof body.typed === "string" && body.typed.trim() === "approve") : yes;
    const changed = approve ? changedSinceReady(a) : null;
    if (changed) approve = false;
    a.answer(approve);
    const result = await a.run;
    end(a, changed ? "the files changed before you answered" : "it finished", nothingFromResult(result));
    if (changed) {
      return refused(409, `${changed} ${flagOf(a).nothingSignedOrSent ? "The approval was declined and nothing was signed or sent." : "The approval ended; status shows what the ledger holds."} Open the proposal again.`,
        { changed: true, ...flagOf(a) });
    }
    return outcomeReply(result, a);
  }

  const ROUTES = Object.freeze({
    "/api/session": openSession,
    "/api/overview": overview,
    "/api/proposal": proposalView,
    "/api/status": status,
    "/api/agree": agree,
    "/api/refuse": refuse,
    "/api/approve/prepare": prepare,
    "/api/approve/confirm": (body) => answer(body, null),
    "/api/approve/cancel": (body) => answer(body, false),
  });

  /** req: { method, path, headers (lowercase names, as node gives them), body (text) }. Returns { status, headers, body }. */
  async function handle(req) {
    const h = (req && req.headers) || {};
    if (h.host !== HOST) return refused(403, `This page answers only at ${ORIGIN}.`);
    const url = String(req.path || "").split("?")[0];
    if (!url.startsWith("/api/")) {
      if (req.method !== "GET") return refused(405, "Only GET is served here.");
      const asset = Object.hasOwn(assets || {}, url) ? assets[url] : null;
      if (!asset) return refused(404, "Not found.");
      return { status: 200, headers: { ...BASE_HEADERS, "content-type": asset.type }, body: asset.body };
    }
    if (req.method !== "POST") return refused(405, "The page's requests are POST.");
    if (h.origin !== ORIGIN) return refused(403, "A request from another page is refused.");
    if (h["sec-fetch-site"] !== undefined && h["sec-fetch-site"] !== "same-origin") return refused(403, "A request from another site is refused.");
    if (!/^application\/json\s*(;.*)?$/i.test(h["content-type"] || "")) return refused(415, "The page's requests are JSON.");
    if (typeof req.body !== "string" || req.body.length > MAX_BODY) return refused(413, "The request is too large.");
    let body;
    try { body = JSON.parse(req.body); } catch { return refused(400, "The request is not JSON."); }
    if (!body || typeof body !== "object" || Array.isArray(body)) return refused(400, "The request is not a JSON object.");
    const route = Object.hasOwn(ROUTES, url) ? ROUTES[url] : null;
    if (!route) return refused(404, "Not found.");
    if (url !== "/api/session" && !(session && sameSecret(h["x-tegara-session"], session))) {
      return refused(403, "No valid session. Open the link the tool printed in your terminal.");
    }
    try { return await route(body); } catch (e) {
      if (e instanceof T.TrialStop) return refused(409, msgOf(e)); // generic: not an attempt's outcome
      return reply(500, { refused: true, reason: `Error: ${msgOf(e)}` });
    }
  }

  return { handle, origin: ORIGIN, isBusy: () => Boolean(active) };
}

module.exports = { makeMemberUi, CSP, PENDING_MS };
