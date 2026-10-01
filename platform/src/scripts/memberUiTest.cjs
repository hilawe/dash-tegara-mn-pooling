// The local member page's battery: memberUiApi.cjs driven through handle() offline, over a real member
// folder (a throwaway store and keys, the coordinator's own proposal builder) and a stand-in ledger that
// carries the failure modes the command line met live (an error after the write, a read from before it),
// plus the shared folder actions in memberActions.cjs and the screens' new values in memberTrial.cjs.
//
// THE MUTATION LIST, written before the cases: the gate accepts another Host, a missing or foreign Origin,
// a cross-site fetch marker, a non-JSON body, a GET to the API, no session or a wrong one; the token opens
// two sessions, or a wrong token opens one or spends it; prepare approves on the page's word (skips the
// server's decision), skips either digest, opens the store before the decision, starts a second approval
// while one runs, or signs without the typed word; confirm accepts another id; a timeout does not decline;
// a stop after the send is reported as nothing sent, or a finished approval later as nothing sent; a
// matching proposal is refused without the second word; agreed terms are replaced unasked; agree or refuse
// are accepted while an approval runs; an unreadable refusals line is dropped; the passphrase comes back in
// a response; the page's signed details differ from the command line's; the passphrase gets one try only.
// From the review of 60d6c4f: the one-at-a-time guard narrowed to the
// waiting stage; a racing answer during a send claiming nothing was sent (a soundness-review finding); confirm not deciding the
// files again; status marking a reservation seen during a send; the passphrase reaching a log line or a
// file in the member folder.
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const L = require("@dashevo/dashcore-lib");
const S = require("./memberStore.cjs");
const T = require("./memberTrial.cjs");
const A = require("./memberActions.cjs");
const C = require("./coordinatorTrial.cjs");
const { makeMemberUi } = require("./memberUiApi.cjs");

let passed = 0, failed = 0, skipped = 0;
// EVERYTHING WRITTEN THROUGH THE CONSOLE, THE STREAM WRITERS, OR fs.write AND fs.writeSync TO DESCRIPTORS 1
// AND 2 IS KEPT, so a passphrase reaching a log line is seen (two reviews' surviving mutations). Not seen: a
// write by any other route, a file outside the member folder, a file removed before the scan, a transformed copy.
const logged = [];
for (const k of ["log", "error", "warn", "info", "debug"]) { const orig = console[k].bind(console); console[k] = (...args) => { logged.push(args.map(String).join(" ")); orig(...args); }; }
for (const stream of [process.stdout, process.stderr]) { const orig = stream.write.bind(stream); stream.write = (chunk, ...rest) => { logged.push(String(chunk)); return orig(chunk, ...rest); }; }
{ const orig = fs.writeSync; fs.writeSync = (fd, data, ...rest) => { if (fd === 1 || fd === 2) logged.push(String(data)); return orig(fd, data, ...rest); }; }
{ const orig = fs.write; fs.write = (fd, data, ...rest) => { if (fd === 1 || fd === 2) logged.push(String(data)); return orig(fd, data, ...rest); }; }
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
// A BATTERY THAT ENDS BEFORE ITS LAST CASE IS A FAILURE, never a pass: a mutation that leaves a request
// waiting on a promise nobody resolves drains the event loop, and node then exits 0 without the summary
// line, which a test chain reads as green (seen with U14 on 2026-09-30)
let finished = false;
process.on("exit", (code) => { if (!finished && code === 0) { console.error("FAIL: the battery ended before its last case (a request left waiting?)"); process.exitCode = 1; } });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };
const filesUnder = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? filesUnder(path.join(dir, e.name)) : [fs.readFileSync(path.join(dir, e.name), "utf8")]));

const PASS = "a throwaway battery passphrase";
const PORT = 47110;
const HOST = `127.0.0.1:${PORT}`;
const ORIGIN = `http://${HOST}`;
const TOKEN = crypto.createHash("sha256").update("the battery's one-time token").digest("hex");
const IDENTITY_B58 = L.encoding.Base58.encode(crypto.createHash("sha256").update("the page battery's member").digest());
const addr = () => new L.PrivateKey(undefined, "testnet").toAddress().toString();
const ASSETS = { "/": { type: "text/html; charset=utf-8", body: "<!doctype html><title>page</title>" }, "/member.js": { type: "text/javascript", body: "0" } };
const AGREED_ANSWERS = { contribution: "400", others: "600", period: "100", penalty: "10", operator: "5", fee: "0.0001" };
// THE PAGE'S OWN SENTENCES. The battery runs render.js (below) to bind WHEN a sentence appears; this list
// binds WHICH sentences exist in the page's two scripts: every string and template literal is read (nested
// templates included, an interpolation shown as {}), tags are boundaries, and every sentence found is listed
// here. A sentence added or removed fails by name, so the list is reviewed when it changes.
const PAGE_JS = process.env.TEGARA_MEMBER_PAGE || path.join(__dirname, "..", "..", "..", "member-ui", "page", "member.js");
const RENDER_JS = path.join(path.dirname(PAGE_JS), "render.js");
// THE PAGE MAY NOT BE IN THIS TREE. The curated public export carries the API and this battery but holds
// the page itself (tegara/member-ui) out, the same way it holds the .mjs runners out (runnerSource.cjs).
// Its absence is a COUNTED SKIP of the two page blocks below, printed by name, never a pass: the API
// cases still run, and the summary line carries the skip count separately so the suite cannot read
// greener than it is. With the page present, as in the private tree, every check runs.
const PAGE_PRESENT = fs.existsSync(PAGE_JS) && fs.existsSync(RENDER_JS);
const pageSkipNote = (what) =>
  `  SKIP: ${what} (${path.relative(process.cwd(), PAGE_JS)} is not in this tree; the curated export holds the member page out). ` +
  "This is a SKIPPED check, never a passed one.";
const PAGE_SENTENCES = [
  "All shares add up to 1,000 DASH.",
  "An amount, not a percentage.",
  "An approval is waiting for your answer or being sent.",
  "At least 100 DASH.",
  "Every proposal is compared with these, term by term.",
  "Every proposal is compared with these.",
  "If you restarted the tool, open the new link it printed.",
  "Is it still running in your terminal?",
  "It opens your own store on this machine, goes only to your member tool, and is not kept.",
  "It starts with http://127.0.0.1 and carries a one-time token.",
  "No approval was started by this request.",
  "No proposal matches your agreed terms yet, so no share table is shown here.",
  "None yet.",
  "Not recorded.",
  "Nothing changed.",
  "Nothing is sent anywhere.",
  "Nothing needs sending.",
  "Nothing signed or sent by this attempt.",
  "Open the link the member tool printed in your terminal.",
  "Opening your store, checking everything the send and the wait need, and reading your approvals by proof.",
  "Reading your approvals by proof.",
  "Recorded at {}.",
  "Recorded in your own folder.",
  "Recorded.",
  "Refusing it records that you do not want to approve it.",
  "Refusing records your reason in your own folder and sends nothing.",
  "Replacing them changes what every proposal is compared with.",
  "Asking the tool to reserve this revision, sign with your owner key, send, and wait for the result with proof, or to decline.",
  "Review everything your approval signs, then approve.",
  "Revision {} does not hold.",
  "Saving different values replaces them, and the tool asks you to confirm that.",
  "Separate several with commas.",
  "Share amounts, owner keys and refund addresses are fixed at registration.",
  "The coordinator has not built any proposal yet.",
  "The coordinator reads this file.",
  "The member tool answered {} with nothing this page can read.",
  "The member tool did not answer.",
  "The member tool gave no outcome.",
  "The one you chose at init.",
  "The operator is paid its reward first, and the rest is split by share.",
  "The session this tab held is not the running tool's.",
  "The tool waits up to {} minutes for your answer.",
  "This can take a minute.",
  "This page is not connected to your member tool.",
  "This takes a few seconds.",
  "Type approve to sign and send.",
  "Type your member passphrase.",
  "Up to 8 decimals.",
  "What you and the other members settled on, recorded in your own folder before you look at any proposal.",
  "Whole blocks after registration.",
  "Percent of the masternode reward, up to two decimals, for example 5 or 5.25.",
  "You already recorded agreed terms.",
  "Your refusals log has {} line{} this page cannot read.",
];
function literals(src) {
  const out = []; let i = 0; const n = src.length;
  const prevSig = () => { let j = i - 1; while (j >= 0 && /\s/.test(src[j])) j--; return j >= 0 ? src[j] : ""; };
  const skipLine = () => { while (i < n && src[i] !== "\n") i++; };
  const skipBlock = () => { i += 2; while (i < n && !(src[i] === "*" && src[i + 1] === "/")) i++; i += 2; };
  const skipRegex = () => { i++; let cls = false; while (i < n) { const c = src[i]; if (c === "\\") { i += 2; continue; } if (c === "[") cls = true; else if (c === "]") cls = false; else if (c === "/" && !cls) { i++; break; } else if (c === "\n") break; i++; } while (i < n && /[a-z]/.test(src[i])) i++; };
  const readString = (q) => { let t = ""; i++; while (i < n && src[i] !== q) { if (src[i] === "\\") { t += src[i + 1]; i += 2; continue; } t += src[i]; i++; } i++; out.push(t); };
  const readTemplate = () => { let t = ""; i++; while (i < n && src[i] !== "`") { if (src[i] === "\\") { t += src[i + 1]; i += 2; continue; } if (src[i] === "$" && src[i + 1] === "{") { i += 2; t += "{}"; readExpr(); continue; } t += src[i]; i++; } i++; out.push(t); };
  const readExpr = () => { let depth = 1; while (i < n && depth > 0) { const c = src[i]; if (c === "`") { readTemplate(); continue; } if (c === '"' || c === "'") { readString(c); continue; } if (c === "/" && src[i + 1] === "/") { skipLine(); continue; } if (c === "/" && src[i + 1] === "*") { skipBlock(); continue; } if (c === "/" && /[(,=:[!&|?{};]/.test(prevSig())) { skipRegex(); continue; } if (c === "{") depth++; if (c === "}") { depth--; if (depth === 0) { i++; return; } } i++; } };
  while (i < n) { const c = src[i]; if (c === "/" && src[i + 1] === "/") { skipLine(); continue; } if (c === "/" && src[i + 1] === "*") { skipBlock(); continue; } if (c === "`") { readTemplate(); continue; } if (c === '"' || c === "'") { readString(c); continue; } if (c === "/" && /[(,=:[!&|?{};]/.test(prevSig())) { skipRegex(); continue; } i++; }
  return out;
}
const pageSentences = (src) => {
  const found = new Set();
  for (const lit of literals(src)) {
    const text = lit.replace(/<[^>]*>/g, "\n").replace(/[ \t]+/g, " ");
    for (const part of text.split(/(?<=[.?!])\s+|\n+/)) { const t = part.trim(); if (/^[A-Z].*[.?!]$/.test(t) && t.replace(/\{\}/g, "").trim().length >= 8) found.add(t); }
  }
  return [...found].sort();
};

// ---------------- a throwaway member, and the coordinator's own two proposals ----------------
const root = fs.mkdtempSync(path.join(os.tmpdir(), "member-ui-"));
const memberDir = path.join(root, "member");
const trialDir = path.join(root, "trial");
fs.mkdirSync(trialDir, { recursive: true });
S.createStore(memberDir, PASS);
S.recordIdentity(memberDir, IDENTITY_B58);
const card = JSON.parse(fs.readFileSync(path.join(memberDir, S.CARD), "utf8"));
const built = C.buildTrialProposals({ card, other: { owner: addr(), refund: addr(), reward: addr() }, operatorPubKey: "8".repeat(96), votingAddress: addr(),
  ids: { platformChainId: "dash-testnet-51", ...T.PINNED_BY_CHAIN["dash-testnet-51"] }, tipHeight: 1563700, revision: 1, rand: () => 0 });
for (const [name, p] of Object.entries(built.files)) fs.writeFileSync(path.join(trialDir, name), JSON.stringify(p, null, 2));
const AGREED_FILE = built.answer.agreed;   // proposal-1.json
const ALTERED_FILE = built.answer.altered; // proposal-2.json
const folder = A.makeMemberFolder({ memberDir, trialDir });

// ---------------- the stand-in ledger, with its failure modes ----------------
// gateOpen and gateResult, when set, hold the connection's opening and the result wait, so a case can act
// while an approval is starting or sending
const world = { scenario: "normal", docs: [], sends: 0, opens: [], preflights: 0, openFails: false, gateOpen: null, gateOpenOnce: null, gateResult: null };
const openWorld = async ({ identityHex, poolIdHex, phrase }) => {
  world.opens.push({ withPhrase: typeof phrase === "string" && phrase.length > 0 });
  if (world.openFails) throw new Error("stand-in: the connection could not be opened");
  if (world.gateOpen) await world.gateOpen;
  if (world.gateOpenOnce) { const g = world.gateOpenOnce; world.gateOpenOnce = null; await g; } // holds the next opening only
  const scenario = world.scenario;
  return {
    async preflight() { world.preflights += 1; if (world.preflightFails) throw new Error("stand-in: the preflight found the tool not ready"); },
    async readMine() {
      const docs = scenario === "stale-read" ? world.docs.slice(0, -1) : world.docs;
      return { docs: docs.filter((d) => d.ownerId === identityHex && d.poolId === poolIdHex), height: scenario === "stale-read" ? 1 : 2 };
    },
    async send(m) {
      world.sends += 1;
      world.docs.push({ id: `${String(world.sends).padStart(2, "0")}${"0".repeat(62)}`, ownerId: identityHex, poolId: m.poolIdHex, termsRevision: m.termsRevision,
        record: m.recordHex, ownerSignature: m.ownerSignatureHex, createdAtCoreBlockHeight: 1563700 + world.sends });
    },
    async awaitResult() {
      if (world.gateResult) await world.gateResult;
      if (scenario === "error-after-send") throw new Error("stand-in: the wait failed after the ledger took the write");
      return { settled: true };
    },
  };
};
let storeOpens = 0;
const openStore = (p) => { storeOpens += 1; return S.openStore(memberDir, p); };
const sendsDir = path.join(memberDir, "sends");
const reservationsOnDisk = () => (fs.existsSync(sendsDir) ? fs.readdirSync(sendsDir).filter((f) => f.endsWith(".json")).map((f) => JSON.parse(fs.readFileSync(path.join(sendsDir, f), "utf8"))) : []);
const resetLedger = () => { world.docs = []; world.sends = 0; fs.rmSync(sendsDir, { recursive: true, force: true }); world.scenario = "normal"; };

// ---------------- requests ----------------
const bodies = [];
const passphrasesSent = new Set();
function client(ui) {
  let session = null;
  const call = async (p, body = {}, over = {}) => {
    if (body && typeof body.passphrase === "string") passphrasesSent.add(body.passphrase);
    const headers = { host: HOST, origin: ORIGIN, "content-type": "application/json", "sec-fetch-site": "same-origin", ...(session ? { "x-tegara-session": session } : {}), ...(over.headers || {}) };
    for (const k of Object.keys(headers)) if (headers[k] === undefined) delete headers[k];
    const r = await ui.handle({ method: over.method || "POST", path: p, headers, body: over.raw !== undefined ? over.raw : JSON.stringify(body) });
    bodies.push(r.body);
    let json = null;
    try { json = JSON.parse(r.body); } catch { /* an asset */ }
    return { status: r.status, json, headers: r.headers, raw: r.body };
  };
  return { call, set session(s) { session = s; }, get session() { return session; } };
}
const ui = makeMemberUi({ folder, openWorld, openStore, port: PORT, token: TOKEN, assets: ASSETS });
const c = client(ui);

(async () => {
  // ================= the gate =================
  {
    const page = await c.call("/", undefined, { method: "GET", raw: "" });
    ok("the page is served at the loopback Host, with framing refused and nothing loaded from elsewhere",
      page.status === 200 && page.raw === ASSETS["/"].body && page.headers["x-frame-options"] === "DENY"
      && /frame-ancestors 'none'/.test(page.headers["content-security-policy"]) && /default-src 'none'/.test(page.headers["content-security-policy"])
      && /script-src 'self'(;|$)/.test(page.headers["content-security-policy"]));
    for (const host of ["localhost:47110", "evil.example:47110", "127.0.0.1:47111", "127.0.0.1", undefined]) {
      const r = await c.call("/", undefined, { method: "GET", raw: "", headers: { host } });
      ok(`the page is refused at Host ${host}`, r.status === 403);
    }
    ok("an unknown page path is not found", (await c.call("/member-store.json", undefined, { method: "GET", raw: "" })).status === 404);
    ok("the page is served to GET only", (await c.call("/", {}, { method: "POST" })).status === 405);
  }
  {
    const wrong = await c.call("/api/session", { token: "0".repeat(64) });
    ok("a wrong token opens no session", wrong.status === 403 && !wrong.json.session);
    const rebound = await c.call("/api/session", { token: TOKEN }, { headers: { host: "evil.example:47110" } });
    ok("the right token under a foreign Host opens no session", rebound.status === 403 && !rebound.json.session);
    const foreign = await c.call("/api/session", { token: TOKEN }, { headers: { origin: "https://evil.example" } });
    ok("the right token from a foreign Origin opens no session", foreign.status === 403 && !foreign.json.session);
    const s = await c.call("/api/session", { token: TOKEN });
    ok("the printed token opens a session, after the refused attempts did not spend it", s.status === 200 && /^[0-9a-f]{64}$/.test(s.json.session));
    c.session = s.json.session;
    const again = await c.call("/api/session", { token: TOKEN });
    ok("the token opens one session only", again.status === 403 && /already used/.test(again.json.reason) && !again.json.session);
  }
  {
    const gated = [
      ["no session", { "x-tegara-session": undefined }],
      ["a wrong session", { "x-tegara-session": "f".repeat(64) }],
      ["a foreign Origin", { origin: "https://evil.example" }],
      ["no Origin", { origin: undefined }],
      ["the Origin null", { origin: "null" }],
      ["the localhost Origin", { origin: "http://localhost:47110" }],
      ["a cross-site fetch", { "sec-fetch-site": "cross-site" }],
      ["a same-site fetch", { "sec-fetch-site": "same-site" }],
      ["a foreign Host", { host: "evil.example:47110" }],
    ];
    for (const [what, headers] of gated) {
      const r = await c.call("/api/overview", {}, { headers });
      ok(`the API refuses ${what}`, r.status === 403 && r.json.refused === true && !r.json.card);
    }
    ok("the API refuses a text body", (await c.call("/api/overview", {}, { headers: { "content-type": "text/plain" } })).status === 415);
    ok("the API refuses a GET", (await c.call("/api/overview", undefined, { method: "GET", raw: "" })).status === 405);
    ok("the API refuses a body that is not JSON", (await c.call("/api/overview", undefined, { raw: "{" })).status === 400);
    ok("the API refuses a JSON list", (await c.call("/api/overview", undefined, { raw: "[]" })).status === 400);
    ok("the API refuses a body over its limit", (await c.call("/api/overview", { pad: "x".repeat(70000) })).status === 413);
    ok("an unknown API path is not found", (await c.call("/api/sign", {})).status === 404);
    ok("with everything in place the API answers", (await c.call("/api/overview", {})).status === 200);
  }
  // A GENERIC REFUSAL CLAIMS NOTHING about any approval's signing or sending, whatever is active
  const genericRefusals = async () => [
    ["no session", await c.call("/api/overview", {}, { headers: { "x-tegara-session": undefined } })],
    ["a foreign Origin", await c.call("/api/overview", {}, { headers: { origin: "https://evil.example" } })],
    ["a text body", await c.call("/api/overview", {}, { headers: { "content-type": "text/plain" } })],
    ["a GET", await c.call("/api/overview", undefined, { method: "GET", raw: "" })],
    ["an unknown proposal", await c.call("/api/proposal", { file: "proposal-N.json" })],
    ["the spent link", await c.call("/api/session", { token: TOKEN })],
    ["an answer for no approval", await c.call("/api/approve/cancel", { pendingId: "0".repeat(32) })],
  ];
  // neither field, and no such claim in the reason's prose either (the fourth round's OWN1)
  const noClaim = (rs) => rs.every(([, r]) => r.json && r.json.refused === true && r.json.nothingSignedOrSent === undefined && r.json.attemptStarted === undefined
    && !/nothing (was )?signed|signed or sent|was sent|not sent|no approval was started/i.test(r.json.reason || ""));
  ok("generic refusals with nothing active carry no claim about signing or sending", noClaim(await genericRefusals()) && !ui.isBusy());

  // ================= agreed terms, and the decisions shown =================
  {
    const o = await c.call("/api/overview", {});
    ok("before any agreed terms, every proposal is shown as not comparable", o.json.agreed === null && o.json.agreedProblems.length > 0
      && o.json.proposals.length === 2 && o.json.proposals.every((p) => p.decision === "no-agreed-terms"));
    const v = await c.call("/api/proposal", { file: AGREED_FILE });
    ok("inspecting before any agreed terms names the agree step", v.json.decision === "no-agreed-terms" && v.json.next.some((n) => n.args === "agree") && v.json.terms === null);
    const bad = await c.call("/api/agree", { ...AGREED_ANSWERS, others: "700" });
    ok(`agreed terms that do not add up are not recorded (${bad.json.problems})`, bad.status === 422 && folder.readAgreed() === null);
    const missing = await c.call("/api/agree", { contribution: "400" });
    ok("agreed terms with answers missing are not recorded", missing.status === 400 && folder.readAgreed() === null);
    const good = await c.call("/api/agree", AGREED_ANSWERS);
    ok("the agreed terms are recorded", good.status === 200 && good.json.recorded && T.checkAgreed(folder.readAgreed()).length === 0
      && good.json.agreed.form.contribution === "400" && good.json.agreed.form.fee === "0.0001");
    const unasked = await c.call("/api/agree", { ...AGREED_ANSWERS, contribution: "300", others: "700" });
    ok("recorded agreed terms are not replaced unless the member says so", unasked.status === 409 && unasked.json.needsReplace
      && folder.readAgreed().myContributionDuffs === 400e8);
  }
  let agreedView, alteredView;
  {
    alteredView = (await c.call("/api/proposal", { file: ALTERED_FILE })).json;
    const r = alteredView.rows.find((x) => x.term === "Your contribution");
    ok("the altered proposal is shown as differing, with the contribution row 400 against 300", alteredView.decision === "differs"
      && r && !r.same && r.agreed === "400 DASH" && r.proposed === "300 DASH" && alteredView.terms === null);
    ok("the after-refusal notes come from the tool, and only after a refusal", alteredView.notes.join("|") === "Nothing signed or sent by this attempt.|An earlier approval may still exist.");
    agreedView = (await c.call("/api/proposal", { file: AGREED_FILE })).json;
    const proposal = folder.readProposal(AGREED_FILE);
    ok("the agreed proposal is shown as matching, with every row the same", agreedView.decision === "matches" && agreedView.rows.every((x) => x.same));
    ok("the page's signed details are the command line's, pair for pair", JSON.stringify(agreedView.terms) === JSON.stringify(T.termPairs({ proposal }))
      && T.termPairs({ proposal }).every(([, v]) => T.renderTerms({ proposal }).some((l) => l.endsWith(`   ${v}`))));
    ok("the digests shown are of the files as they are", agreedView.digest === T.digestOf(proposal) && agreedView.agreedDigest === T.digestOf(folder.readAgreed()));
    ok("a matching proposal carries no after-refusal notes", agreedView.notes.length === 0);
    const o = (await c.call("/api/overview", {})).json;
    ok("the overview lists both, the altered one naming the terms that differ", o.proposals.find((p) => p.file === ALTERED_FILE).differing.join("|") === "Your contribution|Other member's contribution|Early-exit penalty"
      && o.proposals.find((p) => p.file === AGREED_FILE).decision === "matches");
  }

  // ================= the contrary example: the altered proposal, straight to the API =================
  {
    const r = await c.call("/api/approve/prepare", { file: ALTERED_FILE, digest: alteredView.digest, agreedDigest: alteredView.agreedDigest, passphrase: PASS });
    ok("an approve request for the altered proposal is refused on the server, before the passphrase is used or the network opened",
      r.status === 409 && r.json.decision === "differs" && r.json.attemptStarted === false && r.json.nothingSignedOrSent === undefined && storeOpens === 0 && world.opens.length === 0 && world.sends === 0);
    const lied = await c.call("/api/approve/prepare", { file: ALTERED_FILE, digest: agreedView.digest, agreedDigest: agreedView.agreedDigest, passphrase: PASS });
    ok("the matching proposal's digests do not carry an approval of the altered one", lied.status === 409 && lied.json.decision === "differs" && storeOpens === 0);
  }
  {
    const stale = await c.call("/api/approve/prepare", { file: AGREED_FILE, digest: alteredView.digest, agreedDigest: agreedView.agreedDigest, passphrase: PASS });
    ok("a proposal digest other than the file's is refused before the passphrase is used", stale.status === 409 && stale.json.changed && storeOpens === 0);
    const staleAgreed = await c.call("/api/approve/prepare", { file: AGREED_FILE, digest: agreedView.digest, agreedDigest: T.digestOf(null), passphrase: PASS });
    ok("an agreed-terms digest other than the record's is refused before the passphrase is used", staleAgreed.status === 409 && staleAgreed.json.changed && storeOpens === 0);
    const unknown = await c.call("/api/approve/prepare", { file: "../member/member-store.json", digest: agreedView.digest, agreedDigest: agreedView.agreedDigest, passphrase: PASS });
    ok("a path outside the proposals is not read", unknown.status === 409 && /there is no proposal named/.test(unknown.json.reason) && storeOpens === 0);
    const wrong = await c.call("/api/approve/prepare", { file: AGREED_FILE, digest: agreedView.digest, agreedDigest: agreedView.agreedDigest, passphrase: "not the passphrase at all" });
    ok("a wrong passphrase is refused, says which passphrase, and opens nothing further", wrong.status === 422 && wrong.json.passphrase === "wrong"
      && /the one you chose at init/.test(wrong.json.reason) && storeOpens === 1 && world.opens.length === 0 && !ui.isBusy());
  }
  const prep = () => c.call("/api/approve/prepare", { file: AGREED_FILE, digest: agreedView.digest, agreedDigest: agreedView.agreedDigest, passphrase: PASS });

  {
    const altered = await c.call("/api/approve/prepare", { file: ALTERED_FILE, digest: alteredView.digest, agreedDigest: alteredView.agreedDigest, passphrase: PASS });
    const noPass = await c.call("/api/approve/prepare", { file: AGREED_FILE, digest: agreedView.digest, agreedDigest: agreedView.agreedDigest });
    const wrongPass = await c.call("/api/approve/prepare", { file: AGREED_FILE, digest: agreedView.digest, agreedDigest: agreedView.agreedDigest, passphrase: "not it, not at all" });
    const staleDigest = await c.call("/api/approve/prepare", { file: AGREED_FILE, digest: alteredView.digest, agreedDigest: agreedView.agreedDigest, passphrase: PASS });
    ok("a refusal before any attempt says only that none was started, and claims nothing about signing or sending",
      [altered, noPass, wrongPass, staleDigest].every((r) => r.json.refused === true && r.json.attemptStarted === false && r.json.nothingSignedOrSent === undefined) && !ui.isBusy());
  }
  // ================= the approval: ready, then the member's answer =================
  {
    const r = await prep();
    ok("the right passphrase reaches ready, with the network opened for signing and the preflight run", r.status === 200 && r.json.stage === "ready"
      && /^[0-9a-f]{32}$/.test(r.json.pendingId) && world.opens.length === 1 && world.opens[0].withPhrase && world.preflights === 1 && world.sends === 0);
    ok("ready shows the server's own comparison and signed details", JSON.stringify(r.json.terms) === JSON.stringify(agreedView.terms) && r.json.rows.every((x) => x.same));
    ok("while one waits, a second approval is refused", (await prep()).status === 409);
    ok("while one waits, agreed terms cannot be replaced", (await c.call("/api/agree", { ...AGREED_ANSWERS, replace: true })).status === 409);
    ok("while one waits, no refusal is recorded", (await c.call("/api/refuse", { file: ALTERED_FILE, digest: alteredView.digest, reason: "x" })).status === 409);
    ok("while one waits, the overview says so", (await c.call("/api/overview", {})).json.busy === true);
    const other = await c.call("/api/approve/confirm", { pendingId: "0".repeat(32), typed: "approve" });
    ok("another id's answer is refused, and the approval still waits", other.status === 409 && ui.isBusy() && world.sends === 0);
    const no = await c.call("/api/approve/confirm", { pendingId: r.json.pendingId, typed: "Approve please" });
    ok("any word but approve is a decline: nothing signed, sent or reserved", no.json.outcome === "declined" && no.json.nothingSignedOrSent
      && world.sends === 0 && reservationsOnDisk().length === 0 && !ui.isBusy());
    const late = await c.call("/api/approve/confirm", { pendingId: r.json.pendingId, typed: "approve" });
    ok("an answer to a declined approval is refused, and says nothing was signed by it", late.status === 409 && late.json.nothingSignedOrSent && world.sends === 0);
  }
  {
    world.scenario = "error-after-send";
    const r = await prep();
    const e = await c.call("/api/approve/confirm", { pendingId: r.json.pendingId, typed: " approve " });
    ok("an error after the write is reported as possibly on the ledger, never as nothing sent", e.json.stage === "stopped" && e.json.afterSend === true
      && /may be on the ledger/.test(e.json.headline) && e.json.nothingSignedOrSent === undefined && world.sends === 1 && reservationsOnDisk().length === 1);
    world.scenario = "stale-read";
    const s = await prep();
    ok("a read from before that write: no second send, and the member is not asked", s.json.stage === "stopped" && /may have been sent/.test(s.json.detail)
      && s.json.nothingSignedOrSent && world.sends === 1 && !ui.isBusy());
    const st = await c.call("/api/status", {});
    ok("status from before the write names the unseen attempt", st.status === 200 && st.json.rows.length === 0 && st.json.unseen.length === 1 && /may have been sent/.test(st.json.unseen[0].text));
    world.scenario = "normal";
    const st2 = await c.call("/api/status", {});
    ok("status after the write shows it, matching the agreed terms, and marks the reservation seen", st2.json.rows.length === 1 && st2.json.top.agreed === "match"
      && st2.json.rows[0].signedByYou && st2.json.unseen.length === 0 && reservationsOnDisk()[0].confirmedAt);
    const again = await prep();
    ok("approving again finds the approval and sends nothing", again.json.stage === "done" && again.json.outcome === "already-approved" && world.sends === 1);
  }
  {
    resetLedger();
    const r = await prep();
    const done = await c.call("/api/approve/confirm", { pendingId: r.json.pendingId, typed: "approve" });
    ok("the successful path: approved, read back, one send, the reservation marked seen", done.json.outcome === "approved" && /read back by proof/.test(done.json.headline)
      && world.sends === 1 && reservationsOnDisk().length === 1 && reservationsOnDisk()[0].confirmedAt && !ui.isBusy());
    const late = await c.call("/api/approve/confirm", { pendingId: r.json.pendingId, typed: "approve" });
    ok("an answer to a finished approval is refused without claiming nothing was sent", late.status === 409 && late.json.nothingSignedOrSent === undefined && world.sends === 1);
    world.scenario = "stale-read";
    const stale = await prep();
    ok("a read from before a confirmed approval: no second send", stale.json.stage === "stopped" && /read back by proof at/.test(stale.json.detail) && world.sends === 1);
    world.scenario = "normal";
  }
  {
    resetLedger();
    const r = await prep();
    const x = await c.call("/api/approve/cancel", { pendingId: r.json.pendingId });
    ok("stopping from the page declines: nothing signed, sent or reserved", x.json.outcome === "declined" && world.sends === 0 && reservationsOnDisk().length === 0);
  }
  {
    resetLedger();
    const ui2 = makeMemberUi({ folder, openWorld, openStore, port: PORT, token: TOKEN, assets: ASSETS, pendingMs: 40 });
    const c2 = client(ui2);
    c2.session = (await c2.call("/api/session", { token: TOKEN })).json.session;
    const r = await c2.call("/api/approve/prepare", { file: AGREED_FILE, digest: agreedView.digest, agreedDigest: agreedView.agreedDigest, passphrase: PASS });
    await sleep(150);
    const late = await c2.call("/api/approve/confirm", { pendingId: r.json.pendingId, typed: "approve" });
    ok("an approval left unanswered times out as a decline: nothing signed, sent or reserved", r.json.stage === "ready" && late.status === 409
      && /waited more than/.test(late.json.reason) && late.json.nothingSignedOrSent && world.sends === 0 && reservationsOnDisk().length === 0 && !ui2.isBusy());
  }
  // ================= the stages a second request can meet (the review of 60d6c4f) =================
  {
    resetLedger();
    const gate = deferred(); world.gateOpen = gate.promise;
    const first = prep();
    await sleep(30);
    // raced against a short wait: a second approval that gets through would wait on the same held gate,
    // and the case must fail by name rather than hang
    const second = await Promise.race([prep(), sleep(300).then(() => ({ status: "still waiting", json: {} }))]);
    ok("while one starts, a second approval is refused without a claim about sending", second.status === 409 && second.json.nothingSignedOrSent === undefined && ui.isBusy() && world.sends === 0);
    const rogue = await c.call("/api/approve/cancel", { pendingId: "0".repeat(32) });
    ok("while one starts, an answer for any id is refused without a claim about sending", rogue.status === 409 && rogue.json.nothingSignedOrSent === undefined);
    gate.resolve(); world.gateOpen = null;
    const r = await first;
    const x = await c.call("/api/approve/cancel", { pendingId: r.json.pendingId });
    ok("the first reaches ready once the connection opens, and is declined from the page", r.json.stage === "ready" && x.json.outcome === "declined" && !ui.isBusy() && world.sends === 0);
  }
  {
    resetLedger();
    const r = await prep();
    const gate = deferred(); world.gateResult = gate.promise;
    const confirming = c.call("/api/approve/confirm", { pendingId: r.json.pendingId, typed: "approve" });
    await sleep(30);
    ok("the send is under way: one send, the reservation on disk and not yet marked seen", world.sends === 1 && ui.isBusy() && reservationsOnDisk().length === 1 && !reservationsOnDisk()[0].confirmedAt);
    const race = await c.call("/api/approve/cancel", { pendingId: r.json.pendingId });
    const race2 = await c.call("/api/approve/confirm", { pendingId: r.json.pendingId, typed: "approve" });
    ok("a racing answer for the sending approval claims nothing about sending (a soundness-review finding)", race.status === 409 && race.json.nothingSignedOrSent === undefined && /under way/.test(race.json.reason)
      && race2.status === 409 && race2.json.nothingSignedOrSent === undefined);
    const second = await prep();
    ok("while one sends, a second approval is refused without a claim about sending", second.status === 409 && second.json.nothingSignedOrSent === undefined);
    const st = await c.call("/api/status", {});
    ok("status during a send reads the ledger but does not mark the reservation seen", st.status === 200 && st.json.rows.length === 1 && !reservationsOnDisk()[0].confirmedAt);
    ok("while one sends, agree and refuse are refused", (await c.call("/api/agree", { ...AGREED_ANSWERS, replace: true })).status === 409
      && (await c.call("/api/refuse", { file: ALTERED_FILE, digest: alteredView.digest, reason: "x" })).status === 409);
    ok("generic refusals during a send carry no claim about signing or sending", noClaim(await genericRefusals()) && ui.isBusy() && world.sends === 1);
    gate.resolve(); world.gateResult = null;
    const done = await confirming;
    ok("the confirming request then reports approved, one send, the reservation marked seen by the run itself", done.json.outcome === "approved" && world.sends === 1 && reservationsOnDisk()[0].confirmedAt && !ui.isBusy());
    ok("the approved outcome carries no claim of nothing sent", done.json.nothingSignedOrSent === undefined && done.json.attemptStarted === undefined);
  }
  {
    resetLedger();
    world.preflightFails = true;
    const r = await prep();
    world.preflightFails = false;
    ok("a stop before the send carries the flag from the record, with its reason", r.json.stage === "stopped" && /not ready to send/.test(r.json.detail)
      && r.json.nothingSignedOrSent === true && world.sends === 0 && reservationsOnDisk().length === 0 && !ui.isBusy());
  }
  {
    resetLedger();
    world.scenario = "error-after-send";
    const r = await prep();
    await c.call("/api/approve/confirm", { pendingId: r.json.pendingId, typed: "approve" });
    world.scenario = "normal";
    ok("after an error following the send, the reservation is on disk and not yet marked seen", reservationsOnDisk().length === 1 && !reservationsOnDisk()[0].confirmedAt);
    const st = await A.readStatus({ folder, openWorld });
    ok("the command line's default marks a seen reservation (readStatus with no markSeen)", st.held.length === 1 && Boolean(reservationsOnDisk()[0].confirmedAt));
    const late = await c.call("/api/approve/cancel", { pendingId: r.json.pendingId });
    ok("after it ended, the same id's answer is refused without claiming nothing was sent", late.status === 409 && late.json.nothingSignedOrSent === undefined);
  }
  {
    resetLedger();
    const r = await prep();
    const file = path.join(trialDir, AGREED_FILE);
    const original = fs.readFileSync(file, "utf8");
    const rewritten = JSON.parse(original); rewritten.agreement.myFeeDuffs = 20000;
    fs.writeFileSync(file, JSON.stringify(rewritten, null, 2));
    const x = await c.call("/api/approve/confirm", { pendingId: r.json.pendingId, typed: "approve" });
    fs.writeFileSync(file, original);
    ok("a proposal changed between ready and approve is decided again and declined, nothing signed or sent", x.status === 409 && x.json.changed && x.json.nothingSignedOrSent
      && world.sends === 0 && reservationsOnDisk().length === 0 && !ui.isBusy());
    const r2 = await prep();
    const agreedFile = path.join(memberDir, A.AGREED_FILE);
    const agreedOriginal = fs.readFileSync(agreedFile, "utf8");
    const sameValues = JSON.parse(agreedOriginal); sameValues.recordedAt = "1999-01-01T00:00:00.000Z";
    fs.writeFileSync(agreedFile, JSON.stringify(sameValues, null, 2));
    const y = await c.call("/api/approve/confirm", { pendingId: r2.json.pendingId, typed: "approve" });
    fs.writeFileSync(agreedFile, agreedOriginal);
    ok("agreed terms rewritten between ready and approve, even to the same values, decline the run", y.status === 409 && y.json.changed && y.json.nothingSignedOrSent && world.sends === 0 && !ui.isBusy());
    const r3 = await prep();
    const z = await c.call("/api/approve/confirm", { pendingId: r3.json.pendingId, typed: "approve" });
    ok("with the files unchanged the same sequence approves", z.json.outcome === "approved" && world.sends === 1);
  }
  {
    // the confirmation of cc723c9: a change the terms comparison does not see (the approval window), and a
    // change the digests do not see but the decision does (the card's owner address)
    resetLedger();
    const file = path.join(trialDir, AGREED_FILE);
    const original = fs.readFileSync(file, "utf8");
    const r = await prep();
    const later = JSON.parse(original); later.notAfterHeight += 1;
    fs.writeFileSync(file, JSON.stringify(later, null, 2));
    const x = await c.call("/api/approve/confirm", { pendingId: r.json.pendingId, typed: "approve" });
    fs.writeFileSync(file, original);
    ok("a proposal whose approval window moved after ready, its terms unchanged, is declined on its digest", x.status === 409 && x.json.changed && world.sends === 0 && reservationsOnDisk().length === 0);
    const cardFile = path.join(memberDir, S.CARD);
    const cardOriginal = fs.readFileSync(cardFile, "utf8");
    const r2 = await prep();
    const otherOwner = JSON.parse(cardOriginal); otherOwner.addresses.owner = addr();
    fs.writeFileSync(cardFile, JSON.stringify(otherOwner, null, 2));
    const y = await c.call("/api/approve/confirm", { pendingId: r2.json.pendingId, typed: "approve" });
    fs.writeFileSync(cardFile, cardOriginal);
    ok("a card whose owner address changed after ready is declined on the decision, the digests unchanged", y.status === 409 && y.json.changed && /OWNER ADDRESS IS NOT YOURS/.test(y.json.reason)
      && world.sends === 0 && reservationsOnDisk().length === 0 && !ui.isBusy());
    const r3b = await prep();
    const noId = JSON.parse(cardOriginal); noId.identityB58 = null;
    fs.writeFileSync(cardFile, JSON.stringify(noId, null, 2));
    const z2 = await c.call("/api/approve/confirm", { pendingId: r3b.json.pendingId, typed: "approve" });
    fs.writeFileSync(cardFile, cardOriginal);
    ok("identity removed from the card after ready is declined on the decision", z2.status === 409 && z2.json.changed && /no Platform identity/.test(z2.json.reason) && world.sends === 0 && !ui.isBusy());
  }
  {
    // a status read ALREADY IN FLIGHT when an approval starts and sends: it must not write either
    resetLedger();
    const gate = deferred(); world.gateOpenOnce = gate.promise;
    const inFlight = c.call("/api/status", {});
    await sleep(30);
    const r = await prep();
    const gateResult = deferred(); world.gateResult = gateResult.promise;
    const confirming = c.call("/api/approve/confirm", { pendingId: r.json.pendingId, typed: "approve" });
    await sleep(30);
    ok("the approval started and sent while the status read was still opening its connection", r.json.stage === "ready" && world.sends === 1 && ui.isBusy() && !reservationsOnDisk()[0].confirmedAt);
    gate.resolve();
    const st = await inFlight;
    ok("the in-flight status read completes, sees the sent approval, and writes nothing while the approval is active", st.status === 200 && st.json.rows.length === 1 && ui.isBusy() && !reservationsOnDisk()[0].confirmedAt);
    gateResult.resolve(); world.gateResult = null;
    const done = await confirming;
    ok("the approval then completes and marks its own reservation seen", done.json.outcome === "approved" && reservationsOnDisk()[0].confirmedAt && !ui.isBusy());
  }
  {
    resetLedger();
    world.openFails = true;
    const r = await prep();
    ok("a connection that cannot be opened ends the attempt, with nothing sent", r.status === 502 && r.json.nothingSignedOrSent && !ui.isBusy() && world.sends === 0);
    ok("status over a connection that cannot be opened is a refusal, not an empty ledger", (await c.call("/api/status", {})).status === 502);
    world.openFails = false;
  }

  // ================= refusals (HELP_LOG item 6) =================
  {
    const log = path.join(memberDir, A.REFUSALS_FILE);
    const plainAsk = await c.call("/api/refuse", { file: AGREED_FILE, digest: agreedView.digest, reason: "I clicked the wrong one" });
    ok("refusing the matching proposal asks a second time, and records nothing", plainAsk.status === 409 && plainAsk.json.needsConfirmation && !fs.existsSync(log));
    const stale = await c.call("/api/refuse", { file: AGREED_FILE, digest: alteredView.digest, reason: "x", confirmMatching: true });
    ok("a refusal of a proposal that changed since it was shown is refused", stale.status === 409 && stale.json.changed && !fs.existsSync(log));
    const empty = await c.call("/api/refuse", { file: ALTERED_FILE, digest: alteredView.digest, reason: "   " });
    ok("a refusal needs a reason", empty.status === 400 && !fs.existsSync(log));
    const alt = await c.call("/api/refuse", { file: ALTERED_FILE, digest: alteredView.digest, reason: "differs from my agreed terms" });
    ok("the altered proposal is refused on the first word", alt.status === 200 && alt.json.recorded && folder.readRefusals().entries.length === 1);
    const yes = await c.call("/api/refuse", { file: AGREED_FILE, digest: agreedView.digest, reason: "changed my mind", confirmMatching: true });
    ok("the matching proposal is refused on the second word", yes.status === 200 && folder.readRefusals().entries.length === 2);
    const v = (await c.call("/api/proposal", { file: AGREED_FILE })).json;
    ok("the refused matching proposal is flagged on the page", v.decision === "matches" && v.refused.exact.length === 1 && v.refused.exact[0].reason === "changed my mind");
    const ready = await c.call("/api/approve/prepare", { file: AGREED_FILE, digest: v.digest, agreedDigest: v.agreedDigest, passphrase: PASS });
    ok("the ready screen repeats the refusal before the member types approve", ready.json.stage === "ready"
      && ready.json.refusedLines.some((l) => /^You refused this exact proposal at .* \("changed my mind"\)/.test(l)));
    await c.call("/api/approve/cancel", { pendingId: ready.json.pendingId });
    const screen = T.approvalScreen({ file: AGREED_FILE, proposal: folder.readProposal(AGREED_FILE), card, agreed: folder.readAgreed(), mode: "approve", refusals: folder.readRefusals() });
    ok("and on the command line's approve screen", screen.lines.some((l) => /^You refused this exact proposal at .* \("changed my mind"\)\. Approve it only if you have changed your mind\.$/.test(l)));
    const plainScreen = T.approvalScreen({ file: AGREED_FILE, proposal: folder.readProposal(AGREED_FILE), card, agreed: folder.readAgreed(), mode: "approve" });
    ok("without refusals the screen is unchanged by the flag", !plainScreen.lines.some((l) => /You refused/.test(l)) && screen.lines.length === plainScreen.lines.length + 2);
    fs.appendFileSync(log, "not a refusal line\n");
    const flagged = T.refusedBefore({ file: AGREED_FILE, proposal: folder.readProposal(AGREED_FILE), refusals: folder.readRefusals() });
    ok("an unreadable refusals line is counted, not dropped", folder.readRefusals().unreadable === 1 && flagged.unreadable === 1 && flagged.exact.length === 1);
    const renamed = T.refusedBefore({ file: AGREED_FILE, proposal: folder.readProposal(ALTERED_FILE), refusals: folder.readRefusals() });
    ok("a refusal of another version of the same file name is told apart, by contents and not by name", renamed.sameName.length === 1 && renamed.exact.length === 1
      && renamed.exact[0].file === ALTERED_FILE && renamed.sameName[0].file === AGREED_FILE && renamed.sameName[0].reason === "changed my mind");
    ok("refusal needs the second word exactly when the proposal matches", T.refusalNeedsConfirmation({ proposal: folder.readProposal(AGREED_FILE), card, agreed: folder.readAgreed() })
      && !T.refusalNeedsConfirmation({ proposal: folder.readProposal(ALTERED_FILE), card, agreed: folder.readAgreed() })
      && !T.refusalNeedsConfirmation({ proposal: folder.readProposal(AGREED_FILE), card, agreed: null }));
    const replaced = await c.call("/api/agree", { ...AGREED_ANSWERS, contribution: "300", others: "700", penalty: "50", replace: true });
    ok("the member can replace agreed terms by saying so", replaced.status === 200 && folder.readAgreed().myContributionDuffs === 300e8);
    const nowAltered = (await c.call("/api/proposal", { file: ALTERED_FILE })).json;
    ok("the comparison follows the agreed terms as recorded now", nowAltered.decision === "matches" && nowAltered.refused.exact.length === 1);
    const oldDigest = await c.call("/api/approve/prepare", { file: ALTERED_FILE, digest: nowAltered.digest, agreedDigest: agreedView.agreedDigest, passphrase: PASS });
    ok("an approval carrying the agreed terms' old digest is refused", oldDigest.status === 409 && oldDigest.json.changed && world.sends === 0);
    await c.call("/api/agree", { ...AGREED_ANSWERS, replace: true });
  }

  // ================= the shared folder actions =================
  {
    const asked = [];
    const said = [];
    const answers = ["wrong passphrase one", "wrong passphrase two", PASS];
    let opened = null;
    try { opened = await A.openWithTries({ ask: async () => { asked.push(1); return answers.shift(); }, open: (p) => S.openStore(memberDir, p), say: (s) => said.push(s) }); }
    catch { /* reported by the case below */ }
    ok("the passphrase gets three tries, each wrong one saying which passphrase and how many remain", opened !== null && opened.card.addresses.owner === card.addresses.owner
      && asked.length === 3 && said.length === 2 && /the one you chose at init\. 2 tries left\.$/.test(said[0]) && /1 try left\.$/.test(said[1]));
    let threw = null;
    try { await A.openWithTries({ ask: async () => "wrong every time", open: (p) => S.openStore(memberDir, p), say: () => {} }); } catch (e) { threw = e; }
    ok("three wrong passphrases end the run with the store's own refusal", threw instanceof S.StoreRefusal && /does not open/.test(threw.message));
    let tries = 0; threw = null;
    try { await A.openWithTries({ ask: async () => { tries += 1; return PASS; }, open: (p) => S.openStore(path.join(root, "nowhere"), p), say: () => {} }); } catch (e) { threw = e; }
    ok("a refusal other than the passphrase ends at once", tries === 1 && threw instanceof S.StoreRefusal && /no member store/.test(threw.message));
    const k = { poolIdHex: "ab".repeat(32), revision: 9 };
    folder.reservations.reserve({ ...k, reservedAt: "t" });
    let second = null;
    try { folder.reservations.reserve({ ...k, reservedAt: "u" }); } catch (e) { second = e; }
    ok("a revision is reserved once", second && second.code === "EEXIST" && folder.reservations.get(k).reservedAt === "t");
    let outside = null;
    try { folder.readProposal("../member/member-card.json"); } catch (e) { outside = e; }
    ok("the folder reads only the proposals it lists", outside instanceof T.TrialStop);
  }
  {
    if (!PAGE_PRESENT) { skipped += 2; console.log(pageSkipNote("the page's sentence list, two checks")); }
    else {
      const found = [...new Set([...pageSentences(fs.readFileSync(RENDER_JS, "utf8")), ...pageSentences(fs.readFileSync(PAGE_JS, "utf8"))])].sort();
      const extra = found.filter((t) => !PAGE_SENTENCES.includes(t)), gone = PAGE_SENTENCES.filter((t) => !found.includes(t));
      ok(`the page states no sentence outside its reviewed list (${found.length} found${extra.length ? `; not listed: ${extra.map((t) => JSON.stringify(t)).join(", ")}` : ""})`, extra.length === 0 && found.length >= 50);
      ok(`every listed sentence is still on the page${gone.length ? ` (gone: ${gone.map((t) => JSON.stringify(t)).join(", ")})` : ""}`, gone.length === 0);
    }
    ok("the extraction reads nested templates, interpolations and regular expressions", JSON.stringify(pageSentences('const a = `<p>Outer ${x ? `<b>Inner one.</b>` : ""} after ${y}.</p>`; const r = /"quoted"/; const s = "Plain sentence here."; // Not this one.'))
      === JSON.stringify(["Inner one.", "Outer {} after {}.", "Plain sentence here."]) && pageSentences("x = `Recorded at ${t}. Saving different values replaces them.`").includes("Saving different values replaces them."));
  }
  if (!PAGE_PRESENT) { skipped += 6; console.log(pageSkipNote("the rendering itself, six checks")); }
  else {
    // THE RENDERING ITSELF, run in node: when a sentence appears, not only which exist
    const R = require(RENDER_JS);
    const o = (await c.call("/api/overview", {})).json;
    const noClaimHtml = (html) => !/Nothing signed or sent|No approval was started/.test(html);
    ok("a refused result shows no claim about signing unless the response carries one", noClaimHtml(R.resultBody({ refused: true, reason: "x" })) && noClaimHtml(R.resultBody({ stage: "stopped", headline: "Cannot continue.", detail: "d" }))
      && /Nothing signed or sent by this attempt\./.test(R.resultBody({ refused: true, reason: "x", nothingSignedOrSent: true }))
      && /No approval was started by this request\./.test(R.resultBody({ refused: true, reason: "x", attemptStarted: false }))
      && !/Nothing signed/.test(R.resultBody({ refused: true, reason: "x", attemptStarted: false })));
    ok("the wrong-passphrase body states only what the response carries", noClaimHtml(R.wrongPassphrase({ reason: "r" }))
      && /No approval was started/.test(R.wrongPassphrase({ reason: "r", attemptStarted: false })) && !/Nothing signed/.test(R.wrongPassphrase({ reason: "r", attemptStarted: false })));
    const line = "Your refusals log has 1 line this tool cannot read, so an earlier refusal of this proposal cannot be ruled out.";
    const pv = R.proposal({ overview: o, proposal: { file: "p", decision: "matches", headline: "Matches your agreed terms.", rows: [], terms: [["Pool", "x"]], refusedLines: [line], next: [] } });
    ok("the proposal view shows the tool's refusal lines and nothing about a refusal of its own", pv.includes(R.esc(line)) && !/You refused|refused this/i.test(pv.replace(R.esc(line), "")));
    const stepOf = (status) => R.steps({ overview: o, status, view: "overview" }).find((st) => st.id === "status").s;
    ok("the status step says None on the ledger only after a read", stepOf(null) === "Read the ledger" && stepOf({ noIdentity: true, headline: "You have no Platform identity yet." }) === "Read the ledger"
      && stepOf({ error: "x" }) === "Read the ledger" && stepOf({ rows: [], top: null, unseen: [] }) === "None on the ledger" && stepOf({ rows: [{}], top: { revision: 2, agreed: "match" }, unseen: [] }) === "Revision 2 on the ledger");
    const differ = { rows: [{ revision: 1, contribution: "x", penalty: "y", stamped: 1, signedByYou: true, agreed: "differ", problems: [] }], top: { revision: 1, agreed: "differ" },
      topLine: "Revision 1, the highest, is the one that would count at registration, and it DIFFERS from your agreed terms.", replacesNote: "An approval at a higher revision that matches your agreed terms replaces it.",
      headline: "You hold 1 approval for this pool, read by proof at Platform height 5.", unseen: [], height: 5, unseenNote: "", waitsOn: "w", canCompare: true };
    const ov = R.overview({ overview: o, status: differ });
    ok("the overview's banner is the status response's own line, shown only after a read", ov.includes(R.esc(differ.topLine)) && ov.includes(R.esc(differ.replacesNote))
      && !/DIFFERS|differs from your agreed/.test(R.overview({ overview: o, status: null })) && /Not read yet/.test(R.overview({ overview: o, status: null }))
      && /None yet/.test(R.overview({ overview: o, status: { rows: [], top: null, unseen: [] } })) && /Not read yet/.test(R.overview({ overview: o, status: { noIdentity: true, headline: "h" } })));
    const sv = R.status({ overview: o, status: { ...differ, unseen: [{ revision: 3, text: "An attempt at revision 3 was started at T and may have been sent. This read, at Platform height 5, does not show it." }], unseenNote: "approve never sends twice." } });
    ok("the status view shows the unseen attempt's text as the tool states it, and the no-identity answer as a headline only", sv.includes("An attempt at revision 3 was started at T and may have been sent.")
      && /You have no Platform identity yet\./.test(R.status({ overview: o, status: { noIdentity: true, headline: "You have no Platform identity yet." } })) && !/None on the ledger|Read by proof/.test(R.status({ overview: o, status: { noIdentity: true, headline: "h" } })));
  }
  {
    const all = bodies.join("\n");
    ok(`no response carries a passphrase the page sent (${passphrasesSent.size} of them)`, passphrasesSent.size >= 2 && [...passphrasesSent].every((p) => !all.includes(p)));
    const logs = logged.join("\n");
    ok("no log line carries a passphrase the page sent", passphrasesSent.size >= 2 && [...passphrasesSent].every((p) => !logs.includes(p)));
    const texts = filesUnder(memberDir);
    ok("no file in the member folder carries a passphrase the page sent", texts.length >= 3 && [...passphrasesSent].every((p) => !texts.some((t) => t.includes(p))));
  }

  fs.rmSync(root, { recursive: true, force: true });
  console.log(`memberUiTest: ${passed} passed, ${failed} failed` + (skipped ? `, ${skipped} skipped (counted, never folded into passes)` : ""));
  finished = true;
  if (failed) process.exit(1);
})().catch((e) => { console.error(e); process.exit(1); });
