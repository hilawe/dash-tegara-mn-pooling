/**
 * THE PER-EPOCH DEPENDENCY FACTORY, driven offline.
 *
 * WHY THIS EXISTS. The factory used to sit inline in `e2DistributeRun.mjs`, where nothing offline
 * could reach it, so every claim about what it decides rested on reading the runner's text. The
 * working method's 2026-09-20 amendment says a decision or an adapter inside a runner is extracted
 * BEFORE it is reviewed, because a review that can only read a runner cannot answer what the
 * runner decides. These cases drive the real factory and watch what it decides.
 *
 * WHAT IS STOOD IN FOR, and what is not. The TRANSPORT is fake: the ledger queries, the nonce and
 * balance reads, the state-transition construction, the journal and the signing keys. Everything
 * the factory itself owns is real and is what these cases exercise: the discovery extent, which
 * calculation fields reach the writer, whose figures answer, the fail-closed lifecycle answer, the
 * proved read's three refusals, the nonce pin checks, the header build's three refusals, once-only
 * nonce consumption, the unique logical bindings, and per-epoch isolation.
 *
 * THE CONTRARY CONTROL IS THE MUTATION BATTERY at the bottom, and it is the half that matters. A
 * healthy positive run cannot tell a real check from one that always answers yes, so each mutation
 * below removes exactly one check from the module's source and a NAMED probe must observe the
 * difference. The runner asserts that the pattern matched, that the mutant loaded, that the probe
 * reached its path, and that the clean module and the mutant disagree; a mutant that merely
 * crashes is recorded as NOT caught, because a break is not a detection.
 *
 * THE MUTATION LIST WAS WRITTEN BEFORE THESE CASES.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const CLEAN = require("./e2DistributeEpochDeps.cjs");
const captureRecord = require("./e2CaptureRecord.cjs");

const { runnerSource, skipNote } = require("./runnerSource.cjs");
let passed = 0, failed = 0, skipped = 0;
const ok = (name, cond) => { if (cond) { passed++; } else { failed++; console.error("FAIL:", name); } };
const okTry = (name, fn) => {
  try { ok(name, fn()); }
  catch (e) { failed++; console.error(`FAIL: ${name} threw unexpectedly: ${(e && e.message) || String(e)}`); }
};
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

const POOL = "ab".repeat(32);
const OTHER_POOL = "cd".repeat(32);
const A_HEX = "f0".repeat(32);
const V11 = "11".repeat(32);
const PIN = "devnet-pin";
const PROTOCOL_PIN = 12;
const sha256hex = (b) => crypto.createHash("sha256").update(b).digest("hex");
const idHex = (v) => (typeof v === "string" ? v : Buffer.from(v).toString("hex"));

// ---- the contexts, carrying only what the factory reads ----
const rowOf = (epoch, i, extra = {}) => ({
  accrualId: sha256hex(Buffer.from(`acc:${epoch}:${i}`)),
  accrualIdB58: `b58-acc-${epoch}-${i}`,
  accrualEntropy: Buffer.alloc(32, i + 1),
  funderHex: sha256hex(Buffer.from(`funder:${i}`)),
  recipientId: sha256hex(Buffer.from(`recip:${i}`)),
  recipientB58: `b58-recip-${i}`,
  amountCredits: String(1000 + i),
  bps: 5000,
  ...extra,
});
const ctxFor = (epoch, rows) => ({
  epochIndex: epoch,
  rows,
  figures: { grossCredits: String(10000 + epoch), feeCredits: String(100 + epoch),
    allocationHash: "ee".repeat(32), memberCount: rows.length, calcVersion: 1 },
  rowFor: (accrualId) => rows.find((r) => r.accrualId === accrualId) || null,
  docIdFor: (type, subject) => ({ b58: `b58-${type}-${subject}`,
    entropy: Buffer.alloc(32, 7), hex: sha256hex(Buffer.from(`${type}:${subject}`)) }),
});
const EP0 = ctxFor(0, [rowOf(0, 0), rowOf(0, 1)]);
const EP1 = ctxFor(1, [rowOf(1, 0, { carryInCredits: "250" })]);

// ---- the fake transport ----
const mkStt = (tag) => {
  const st = { signed: null, tag, sign(priv, pub) { st.signed = { priv, pub }; },
    bytes() { return Buffer.from(tag, "utf8"); } };
  return st;
};
const mkEnv = (over = {}) => {
  const queries = [];
  // WHAT A BUILDER ACTUALLY PUT IN THE TRANSITION, recorded. The first version of these fakes
  // discarded it, so the assertions could only check that bytes came back and that their hash was
  // over those bytes. An independent review used exactly that blindness: replacing the transfer
  // amount with 1 and writing `epochIndex + 1` into the header's fields both survived the whole
  // battery, because nothing looked at the arguments. A fake that throws away what it was asked
  // for cannot answer whether the caller asked for the right thing.
  const createdDocs = [];
  const identityTransitions = [];
  const provedCalls = [];
  const journalRecords = over.journalRecords || [];
  const keyA = { privateKey: crypto.randomBytes(32), publicKey: { keyId: 2 } };
  const transferKey = { privateKey: crypto.randomBytes(32), publicKey: { keyId: 3 } };
  const base = {
    poolId: POOL, contractId: V11, writerIdB58: "b58-ID-A", writerHex: A_HEX,
    chainIdPin: PIN, protocolPin: PROTOCOL_PIN, bootstrap: false,
    runEpochs: [0, 1],
    contextFor: (n) => (n === 0 ? EP0 : n === 1 ? EP1 : (() => { throw new Error(`epoch ${n} is outside this run`); })()),
    sdk: {
      documents: {
        query: async (contractId, type, where) => { queries.push({ contractId, type, where }); return over.queryAnswer ? over.queryAnswer(type, where) : []; },
        createStateTransition: (doc, action, opts) => mkStt(`doc:${doc && doc.type}:${opts && opts.identityContractNonce}`),
      },
      identities: {
        createStateTransition: (name, opts) => {
          identityTransitions.push({ name, ...opts });
          return mkStt(`ident:${name}:${opts && opts.identityNonce}:${opts && opts.amount}`);
        },
      },
    },
    dpp: { IdentifierWASM: class { constructor(v) { this.v = v; } } },
    createDocument: (contractId, type, fields, owner, _u, id58) => {
      const d = { contractId, type, fields, owner, id58 };
      createdDocs.push(d);
      return d;
    },
    keyA, transferKey,
    submitSigned: async (stt) => ({ submitted: stt.tag, proofMsg: "aa".repeat(20), metadataMsg: "bb".repeat(10), metadata: { height: 1234 } }),
    waitOnly: async (stt) => ({ waited: stt }),
    rehydrate: (bytesHex, hash) => mkStt(`rehydrated:${bytesHex}:${hash}`),
    rememberStt: (stt) => Buffer.from(stt.bytes()).toString("hex"),
    transferMetaByBytes: new Map(),
    verifyGateCapture: () => ({ gate: "ok" }),
    resolvePool: (pid) => ({ pool: pid }),
    // THE PROVED FIXTURE RECORDS WHAT IT WAS ASKED, for the same reason. A fixture that ignores
    // its arguments answers the same whatever key the caller resolved, so a caller asking about
    // the wrong epoch reads as an honest absence.
    provedQuery: async (type, where, label) => {
      provedCalls.push({ type, where, label });
      return over.provedAnswer ? over.provedAnswer(type, where, label) : [];
    },
    openJournal: () => ({ records: journalRecords }),
    readContractNonce: async () => ({ nonce: 41n, metadata: { chainId: PIN, protocolVersion: PROTOCOL_PIN } }),
    readIdentityNonce: async () => ({ nonce: 7n, metadata: { chainId: PIN, protocolVersion: PROTOCOL_PIN } }),
    readBalance: async () => ({ balance: 999n, metadata: { chainId: PIN, protocolVersion: PROTOCOL_PIN, height: 555n } }),
    idHex, sha256hex,
  };
  return { env: { ...base, ...over.env }, queries, createdDocs, identityTransitions, provedCalls,
    keyA, transferKey };
};

// build a bundle from the CLEAN module (or a mutant), for one epoch
const bundleOf = (mod, ctx, completed = new Set(), over = {}) => {
  const e = mkEnv(over);
  const factory = mod.makeEpochDepsFactory(e.env);
  const b = factory(ctx, completed);
  return { ...b, ...e };
};
// TWO BUNDLES FROM ONE FACTORY, which `bundleOf` cannot produce because it builds a fresh factory
// each time. The review moved `prefetched` and the reservation pointer from bundle scope up to
// factory scope and watched every assertion pass, precisely because no case had ever asked one
// factory for two bundles. Per-epoch isolation is the property this module exists for, so the
// shape that can break it has to be reachable from a case.
const twoBundlesFromOneFactory = (mod, over = {}) => {
  const e = mkEnv(over);
  const factory = mod.makeEpochDepsFactory(e.env);
  return { first: factory(EP0, new Set()), second: factory(EP1, new Set()), ...e };
};

const main = async () => {
  // ================= 1. the environment contract =================
  for (const k of CLEAN.REQUIRED_ENV) {
    const { env } = mkEnv();
    delete env[k];
    throws(`a factory missing env.${k} refuses by name`,
      () => CLEAN.makeEpochDepsFactory(env), new RegExp(`needs env\\.${k}`));
  }
  throws("a factory with no environment at all refuses",
    () => CLEAN.makeEpochDepsFactory(null), /needs its environment/);
  throws("a factory with an empty epoch list refuses", () => {
    const { env } = mkEnv(); env.runEpochs = []; return CLEAN.makeEpochDepsFactory(env);
  }, /needs the run's epochs/);
  throws("a bundle built with no completed record refuses rather than answering the lifecycle question from nothing",
    () => { const { env } = mkEnv(); CLEAN.makeEpochDepsFactory(env)(EP0, undefined); },
    /needs the run's completed-epoch record/);
  throws("a bundle built with no context refuses",
    () => { const { env } = mkEnv(); CLEAN.makeEpochDepsFactory(env)(null, new Set()); },
    /needs the epoch's context/);

  // ================= 2. discovery answers this run's epochs, and only those =================
  {
    const { deps } = bundleOf(CLEAN, EP0);
    const all = await deps.fetchRange(0, 1);
    ok("discovery answers every epoch of the run",
      all.proved === false && JSON.stringify(all.epochs.map((e) => e.number)) === "[0,1]");
    const narrow = await deps.fetchRange(1, 1);
    ok("discovery asked for a sub-range answers only that range",
      JSON.stringify(narrow.epochs.map((e) => e.number)) === "[1]");
    const above = await deps.fetchRange(2, 9);
    ok("discovery asked above the run answers nothing rather than inventing an epoch",
      above.epochs.length === 0);
    ok("discovery never claims proof (income is unproved, C1 open)", above.proved === false);
  }

  // ================= 3. what reaches the writer =================
  {
    const { deps } = bundleOf(CLEAN, EP0);
    const rows = deps.entitlementsForEpoch(0);
    ok("every positive row of the asked-for epoch reaches the writer", rows.length === 2);
    ok("a row with no carry omits the member entirely rather than sending a zero",
      rows.every((r) => !("carryInCredits" in r)));
    ok("the writer receives the calculation fields and not the driver's document identities",
      rows.every((r) => JSON.stringify(Object.keys(r).sort()) === '["accrualId","amountCredits","recipientId"]'));
    // THE VALUES, not only the member names. The review replaced every forwarded amount with "0"
    // and the battery did not notice, because it checked the row count, the member names, the
    // carry member and one identifier, and never what any row said it owed.
    // EVERY ROW, not the first. A later review forwarded the first row's recipient for every row
    // and this assertion, whose name says "each", passed because it only read row zero's. An
    // assertion that checks one member of a set must not be named for the set.
    ok("each forwarded row carries its OWN amount, recipient and accrual, checked for every row",
      rows.length === EP0.rows.length && rows.every((r, i) =>
        r.amountCredits === EP0.rows[i].amountCredits
        && r.recipientId === EP0.rows[i].recipientId
        && r.accrualId === EP0.rows[i].accrualId));
    ok("the rows are distinguishable, so checking every one is not checking one twice",
      rows[0].recipientId !== rows[1].recipientId && rows[0].accrualId !== rows[1].accrualId);
    // THE CARRY MEMBER IS THE ONE THE WRITER'S REFUSAL EXISTS FOR, so its forwarding is bound
    const carried = deps.entitlementsForEpoch(1);
    ok("a row carrying an explicit carry-in forwards that member to the writer",
      carried.length === 1 && carried[0].carryInCredits === "250");
    // the hook answers ANY epoch in the run by index, deliberately (startRun is run-level)
    ok("the hook answers an epoch other than the bundle's, which is what the run-level start step needs",
      deps.entitlementsForEpoch(1)[0].accrualId === EP1.rows[0].accrualId);
    throws("an epoch outside the run refuses inside the calculation rather than answering with an empty set",
      () => deps.entitlementsForEpoch(9), /outside this run/);
  }

  // ================= 4. whose figures answer =================
  {
    const zero = bundleOf(CLEAN, EP0).deps.epochNumbers();
    const one = bundleOf(CLEAN, EP1).deps.epochNumbers();
    ok("a bundle answers its OWN context's figures",
      zero.grossCredits === "10000" && one.grossCredits === "10001");
    ok("two bundles built from different contexts do not share figures",
      zero.feeCredits !== one.feeCredits && zero.memberCount !== one.memberCount);
  }

  // ================= 5. the lifecycle answer is fail-closed =================
  {
    const empty = bundleOf(CLEAN, EP1, new Set()).deps;
    ok("with nothing recorded complete, every epoch answers false",
      empty.epochDistributionComplete(0) === false && empty.epochDistributionComplete(1) === false);
    const withZero = bundleOf(CLEAN, EP1, new Set([0])).deps;
    ok("only an epoch in the run's own completed record answers true",
      withZero.epochDistributionComplete(0) === true && withZero.epochDistributionComplete(1) === false);
    ok("an epoch the run never touched answers false rather than true",
      withZero.epochDistributionComplete(99) === false);
  }

  // ================= 6. the proved header read's three refusals =================
  {
    const hdrDoc = (poolHex, epoch) => ({ id: "aa".repeat(32),
      getProperties: () => ({ poolId: Buffer.from(poolHex, "hex"), epochIndex: epoch, grossCredits: 5 }) });
    // (a) the marker: makeProvedQuery refuses an answer that did not pass the proving wrapper
    {
      const pq = CLEAN.makeProvedQuery({ query: async () => { delete globalThis.__tegaraResponseMetadata; return []; } });
      await rejects("a read that did not pass through the proof-verifying wrapper refuses rather than answering unlabelled",
        pq("epochHeader", [], "probe"), /no verified-call marker/);
      const pq2 = CLEAN.makeProvedQuery({ query: async () => { globalThis.__tegaraResponseMetadata = { metadata: { height: 1 } }; return ["doc"]; } });
      ok("a read that DID pass the wrapper is returned", JSON.stringify(await pq2("epochHeader", [], "probe")) === '["doc"]');
      // THE CLEARING BEFORE THE QUERY IS LOAD-BEARING, and no case reached it: every negative
      // fixture above clears the marker itself, so deleting the module's own clear changed
      // nothing. A marker left behind by an EARLIER proved read must not vouch for this one.
      globalThis.__tegaraResponseMetadata = { metadata: { height: 42 } }; // stale, from a previous read
      const pqStale = CLEAN.makeProvedQuery({ query: async () => ["doc"] }); // sets no marker of its own
      await rejects("a marker left over from an EARLIER read does not vouch for this one: it is cleared before the query, so an unmarked answer still refuses",
        pqStale("epochHeader", [], "probe"), /no verified-call marker/);
      const pq3 = CLEAN.makeProvedQuery({ query: async () => { globalThis.__tegaraResponseMetadata = {}; return ["doc"]; } });
      await rejects("a marker with no metadata member is not a marker",
        pq3("epochHeader", [], "probe"), /no verified-call marker/);
      throws("makeProvedQuery needs its query", () => CLEAN.makeProvedQuery({}), /needs a query function/);
      delete globalThis.__tegaraResponseMetadata;
    }
    // (b) a verified absence is a different thing from an unverified one
    {
      const { deps } = bundleOf(CLEAN, EP0, new Set(), { provedAnswer: async () => [] });
      const r = await deps.provedHeaderQuery(POOL, 0);
      ok("a verified absence answers found:false AND proved:true", r.found === false && r.proved === true);
    }
    // (c) the count
    {
      const { deps } = bundleOf(CLEAN, EP0, new Set(), { provedAnswer: async () => [hdrDoc(POOL, 0), hdrDoc(POOL, 0)] });
      await rejects("two headers for one pool and epoch refuses rather than choosing one",
        deps.provedHeaderQuery(POOL, 0), /served 2 headers for one pool and epoch; refusing/);
    }
    // (d) the key asked for, on each half
    {
      const wrongPool = bundleOf(CLEAN, EP0, new Set(), { provedAnswer: async () => [hdrDoc(OTHER_POOL, 0)] });
      await rejects("a proved answer about a DIFFERENT POOL is refused here, not left to the writer's field comparison",
        wrongPool.deps.provedHeaderQuery(POOL, 0), /which is not what was asked for; refusing/);
      const wrongEpoch = bundleOf(CLEAN, EP0, new Set(), { provedAnswer: async () => [hdrDoc(POOL, 3)] });
      await rejects("a proved answer about a DIFFERENT EPOCH is refused",
        wrongEpoch.deps.provedHeaderQuery(POOL, 0), /which is not what was asked for; refusing/);
    }
    // (e) the answer that does match
    {
      const b = bundleOf(CLEAN, EP0, new Set(), { provedAnswer: async () => [hdrDoc(POOL, 0)] });
      const r = await b.deps.provedHeaderQuery(POOL, 0);
      ok("a proved answer for the key asked for is returned, attesting",
        r.found === true && r.proved === true && r.fields.epochIndex === 0 && r.fields.poolId === POOL);
      // WHAT IT ASKED FOR, not only what it did with the answer. The review made this hook
      // request `epochIndex + 1` and watched the battery pass: with a header present only at
      // epoch 0, asking for epoch 0 returned a clean verified ABSENCE, because the fixture
      // ignored its arguments and the key check then compared the answer to itself.
      const asked = b.provedCalls[b.provedCalls.length - 1];
      ok("the proved read asks the ledger for the pool and epoch it was given",
        asked.type === "epochHeader"
          && asked.where[0][0] === "poolId" && asked.where[0][2].toString("hex") === POOL
          && asked.where[1][0] === "epochIndex" && asked.where[1][2] === 0);
      const b1 = bundleOf(CLEAN, EP0, new Set(), { provedAnswer: async () => [] });
      await b1.deps.provedHeaderQuery(OTHER_POOL, 3);
      const asked1 = b1.provedCalls[b1.provedCalls.length - 1];
      ok("a different key is asked for differently, so the request tracks its arguments",
        asked1.where[0][2].toString("hex") === OTHER_POOL && asked1.where[1][2] === 3);
    }
  }

  // ================= 7. the nonce pin checks =================
  {
    const good = bundleOf(CLEAN, EP0);
    ok("a contract-nonce read on the pinned chain returns the NEXT nonce", (await good.contractNonce()) === 42n);
    ok("an identity-nonce read on the pinned chain returns the NEXT nonce", (await good.identityNonce()) === 8n);
    const wrongChain = bundleOf(CLEAN, EP0, new Set(), { env: {
      readContractNonce: async () => ({ nonce: 41n, metadata: { chainId: "some-other-chain", protocolVersion: PROTOCOL_PIN } }),
      readIdentityNonce: async () => ({ nonce: 7n, metadata: { chainId: "some-other-chain", protocolVersion: PROTOCOL_PIN } }) } });
    await rejects("a contract-nonce read from an unpinned CHAIN refuses",
      wrongChain.contractNonce(), /contract-nonce read fails the pins/);
    await rejects("an identity-nonce read from an unpinned CHAIN refuses",
      wrongChain.identityNonce(), /identity-nonce read fails the pins/);
    const wrongProto = bundleOf(CLEAN, EP0, new Set(), { env: {
      readContractNonce: async () => ({ nonce: 41n, metadata: { chainId: PIN, protocolVersion: 11 } }),
      readIdentityNonce: async () => ({ nonce: 7n, metadata: { chainId: PIN, protocolVersion: 11 } }) } });
    await rejects("a contract-nonce read at an unpinned PROTOCOL VERSION refuses",
      wrongProto.contractNonce(), /contract-nonce read fails the pins/);
    await rejects("an identity-nonce read at an unpinned PROTOCOL VERSION refuses",
      wrongProto.identityNonce(), /identity-nonce read fails the pins/);
    // BOTH DIRECTIONS. Every contrary fixture above sits BELOW the pin, so a mutation that
    // clamps the response up to the pinned value was invisible. A version ABOVE it is the
    // same refusal, and a check that only catches one side is half a check.
    const aboveProto = bundleOf(CLEAN, EP0, new Set(), { env: {
      readContractNonce: async () => ({ nonce: 41n, metadata: { chainId: PIN, protocolVersion: PROTOCOL_PIN + 1 } }),
      readIdentityNonce: async () => ({ nonce: 7n, metadata: { chainId: PIN, protocolVersion: PROTOCOL_PIN + 1 } }) } });
    await rejects("a contract-nonce read ABOVE the pinned protocol version refuses too",
      aboveProto.contractNonce(), /contract-nonce read fails the pins/);
    await rejects("an identity-nonce read ABOVE the pinned protocol version refuses too",
      aboveProto.identityNonce(), /identity-nonce read fails the pins/);
  }

  // ================= 8. the header build's refusals, and once-only consumption =================
  {
    const contents = { grossCredits: "10000", feeCredits: "100", allocationHash: "ee".repeat(32),
      memberCount: 2, calcVersion: 1 };
    // a RESUME run owns no header construction at all
    const resume = bundleOf(CLEAN, EP0);
    resume.prefetched.headerContractNonce = 42n;
    throws("a resume run refuses to build a fresh header; the canonical journal holds it",
      () => resume.deps.buildHeaderTransition({ poolId: POOL, epochIndex: 0, expectedContents: contents }),
      /the resume run never builds a fresh header/);
    // bootstrap: the prefetch is required
    const boot = bundleOf(CLEAN, EP0, new Set(), { env: { bootstrap: true } });
    throws("a header build with no prefetched nonce refuses rather than building unsigned-for",
      () => boot.deps.buildHeaderTransition({ poolId: POOL, epochIndex: 0, expectedContents: contents }),
      /header contract nonce was not prefetched/);
    // bootstrap: the epoch must be this context's
    const boot2 = bundleOf(CLEAN, EP0, new Set(), { env: { bootstrap: true } });
    boot2.prefetched.headerContractNonce = 42n;
    throws("a header build asked for another epoch refuses to derive an identity under the wrong epoch",
      () => boot2.deps.buildHeaderTransition({ poolId: POOL, epochIndex: 1, expectedContents: contents }),
      /refusing to derive a header identity under the wrong epoch/);
    // the good path, then the SAME bundle refuses a second build: the nonce is consumed once
    const boot3 = bundleOf(CLEAN, EP0, new Set(), { env: { bootstrap: true } });
    boot3.prefetched.headerContractNonce = 42n;
    const built = boot3.deps.buildHeaderTransition({ poolId: POOL, epochIndex: 0, expectedContents: contents });
    ok("a bootstrap header build over a prefetched nonce produces bytes and the expected document id",
      typeof built.transitionBytes === "string" && built.transitionBytes.length > 0
        && built.transitionHash === sha256hex(Buffer.from(built.transitionBytes, "hex"))
        && typeof built.expectedDocumentId === "string");
    // WHAT WENT INTO THE DOCUMENT, not only that a document came out. The review wrote
    // `epochIndex + 1` into these fields while leaving the identity derivation on the right
    // epoch, and the battery passed, because it checked for nonempty bytes and a hash over
    // those same bytes. A header carrying another epoch's index is the exact failure the
    // epoch-agreement refusal two lines above exists to prevent.
    const hdr = boot3.createdDocs[boot3.createdDocs.length - 1];
    // EVERY FIELD THE ASSERTION'S NAME COVERS. `calcVersion` was omitted from the first version
    // and a review changed it under the assertion without the assertion noticing, which is the
    // same defect as naming a set and checking one member of it.
    ok("the header document carries THIS epoch's index and every one of this context's own figures",
      hdr.type === "epochHeader" && hdr.fields.epochIndex === 0
        && hdr.fields.poolId.toString("hex") === POOL
        && hdr.fields.grossCredits === contents.grossCredits
        && hdr.fields.feeCredits === contents.feeCredits
        && hdr.fields.memberCount === contents.memberCount
        && hdr.fields.calcVersion === contents.calcVersion
        && hdr.fields.allocationHash.toString("hex") === contents.allocationHash
        && JSON.stringify(Object.keys(hdr.fields).sort())
          === JSON.stringify(["allocationHash", "calcVersion", "epochIndex", "feeCredits",
            "grossCredits", "memberCount", "poolId"]));
    ok("the prefetched header nonce is cleared by the build", boot3.prefetched.headerContractNonce === null);
    throws("a SECOND header build on the same bundle refuses rather than reusing the consumed nonce",
      () => boot3.deps.buildHeaderTransition({ poolId: POOL, epochIndex: 0, expectedContents: contents }),
      /header contract nonce was not prefetched/);
  }

  // ================= 9. the transfer and reservation builders =================
  {
    const b = bundleOf(CLEAN, EP0);
    const row = EP0.rows[0];
    throws("a transfer build with no prefetched identity nonce refuses",
      () => b.deps.buildTransferTransition({ accrualId: row.accrualId, amountCredits: row.amountCredits }),
      /identity nonce was not prefetched/);
    b.prefetched.identityNonce = 8n;
    const t = b.deps.buildTransferTransition({ accrualId: row.accrualId, amountCredits: row.amountCredits });
    ok("a transfer build over a prefetched nonce produces bytes whose hash is over those bytes",
      t.transitionHash === sha256hex(Buffer.from(t.transitionBytes, "hex")));
    ok("the transfer records its recipient and amount against its own bytes",
      b.env.transferMetaByBytes.get(t.transitionBytes).recipientB58 === row.recipientB58
        && b.env.transferMetaByBytes.get(t.transitionBytes).amountCredits === row.amountCredits);
    // THE TRANSITION ITSELF, not the bookkeeping beside it. The review replaced the amount
    // handed to the transition with 1 and watched everything pass, because the assertions
    // compared the returned bytes with their own hash and then read the separate map, which
    // the mutation left correct. The map is the driver's notes; the transition is what moves
    // credits, and it is the one that has to be right.
    const it = b.identityTransitions[b.identityTransitions.length - 1];
    ok("the transfer transition is a creditTransfer for the asked-for amount, to the row's recipient, over the prefetched nonce",
      it.name === "creditTransfer" && it.amount === BigInt(row.amountCredits)
        && it.recipientId === row.recipientB58 && it.identityNonce === 8n);
    ok("the identity nonce is consumed once", b.prefetched.identityNonce === null);
    throws("a SECOND transfer build refuses rather than reusing the consumed nonce",
      () => b.deps.buildTransferTransition({ accrualId: row.accrualId, amountCredits: row.amountCredits }),
      /identity nonce was not prefetched/);

    // the reservation, and the last-reservation pointer it sets
    throws("a reservation build with no prefetched contract nonce refuses",
      () => b.deps.buildReservationTransition({ poolId: POOL, accrualId: row.accrualId, boundTransferHash: t.transitionHash }),
      /contract nonce was not prefetched/);
    throws("asking for a reservation document id before one is built refuses",
      () => b.deps.reservationDocumentIdOf(), /no reservation was built in this step/);
    b.prefetched.contractNonce = 42n;
    b.deps.buildReservationTransition({ poolId: POOL, accrualId: row.accrualId, boundTransferHash: t.transitionHash });
    ok("after a reservation is built its document id is available",
      typeof b.deps.reservationDocumentIdOf() === "string" && b.deps.reservationDocumentIdOf().length > 0);
    // THE RESERVATION'S NONCE IS CONSUMED ONCE TOO. The transfer builder had this pair and the
    // reservation builder did not, so removing its clear was invisible. Two reservations over
    // one prefetched contract nonce would submit two documents under the same nonce.
    ok("the reservation's contract nonce is consumed once", b.prefetched.contractNonce === null);
    throws("a SECOND reservation build refuses rather than reusing the consumed nonce",
      () => b.deps.buildReservationTransition({ poolId: POOL, accrualId: row.accrualId, boundTransferHash: t.transitionHash }),
      /contract nonce was not prefetched/);
    // the reservation document carries the accrual and the hash it is bound to
    const resDoc = b.createdDocs[b.createdDocs.length - 1];
    ok("the reservation document binds this accrual to the transfer hash it was given",
      resDoc.type === "transferReservation"
        && resDoc.fields.accrualId.toString("hex") === row.accrualId
        && resDoc.fields.transitionHash.toString("hex") === t.transitionHash
        && resDoc.fields.poolId.toString("hex") === POOL);
    b.clearLastReservation();
    throws("clearing the reservation pointer makes a stale id unavailable rather than returning the previous step's",
      () => b.deps.reservationDocumentIdOf(), /no reservation was built in this step/);
  }

  // ================= 10. the unique logical bindings and the fetch =================
  {
    const row = EP0.rows[0];
    const whereOf = (qs) => qs[qs.length - 1].where;
    {
      const b = bundleOf(CLEAN, EP0);
      await b.deps.documents.fetch("accrual", { accrualId: row.accrualId, epochIndex: 0 });
      const w = whereOf(b.queries);
      // THE POOL VALUE IS CHECKED, not just the clause name. The review bound the pool clause to
      // the CONTRACT identifier instead and the battery passed, because it asserted the three
      // clause names and then only read the funder and the epoch back.
      ok("an accrual is recovered through (pool, funder, epoch), not through the driver's id convention, and each clause carries its own value",
        w.length === 3 && w[0][0] === "poolId" && w[1][0] === "funderId" && w[2][0] === "epochIndex"
          && w[0][2].toString("hex") === POOL && w[0][2].toString("hex") !== V11
          && w[1][2].toString("hex") === row.funderHex && w[2][2] === 0);
    }
    {
      const b = bundleOf(CLEAN, EP0);
      await b.deps.documents.fetch("part", { accrualId: row.accrualId, partIndex: 3 });
      const w = whereOf(b.queries);
      ok("a proof part is recovered through (accrual, partIndex)",
        w.length === 2 && w[0][0] === "accrualId" && w[1][0] === "partIndex" && w[1][2] === 3);
    }
    {
      const b = bundleOf(CLEAN, EP0);
      await b.deps.documents.fetch("receipt", { accrualId: row.accrualId });
      const w = whereOf(b.queries);
      ok("a receipt is recovered through its accrual alone",
        w.length === 1 && w[0][0] === "accrualId" && w[0][2].toString("hex") === row.accrualId);
    }
    {
      const one = { getProperties: () => ({ poolId: Buffer.from(POOL, "hex"), amountCredits: 5n }) };
      const b = bundleOf(CLEAN, EP0, new Set(), { queryAnswer: async () => [one] });
      const r = await b.deps.documents.fetch("receipt", { accrualId: row.accrualId });
      ok("a single hit is normalized: bytes to hex, bigints to numbers",
        r.found === true && r.fields.poolId === POOL && r.fields.amountCredits === 5);
      const none = bundleOf(CLEAN, EP0, new Set(), { queryAnswer: async () => [] });
      ok("no hit answers found:false", (await none.deps.documents.fetch("receipt", { accrualId: row.accrualId })).found === false);
      const many = bundleOf(CLEAN, EP0, new Set(), { queryAnswer: async () => [one, one] });
      await rejects("a logical binding that returns more than one document refuses rather than choosing",
        many.deps.documents.fetch("receipt", { accrualId: row.accrualId }), /returned 2 documents; refusing/);
    }
    {
      const b = bundleOf(CLEAN, EP0);
      await rejects("a fetch for an accrual with no entitlement row refuses",
        b.deps.documents.fetch("accrual", { accrualId: "00".repeat(32), epochIndex: 0 }), /no entitlement row/);
    }
  }

  // ================= 11. the capture binds THIS epoch =================
  {
    const b = bundleOf(CLEAN, EP1);
    const cap = await b.deps.buildHeaderCapture({
      writeAhead: { transitionBytes: "0102", expectedDocumentId: "dd".repeat(32) },
      expectedContents: { poolId: POOL, epochIndex: 1, grossCredits: 10001, feeCredits: 101,
        allocationHash: "ee".repeat(32), memberCount: 1, calcVersion: 1 },
      result: { proofMsg: "aa".repeat(20), metadataMsg: "bb".repeat(10), metadata: { height: 1234 } } });
    ok("a capture carries the epoch of the context that built it, not the run's first",
      cap.epochIndex === 1 && cap.poolId === POOL);
    ok("a capture names the writer as its signer and the tenderdash height route",
      cap.signerIdentity === A_HEX && cap.signerKeyId === 2 && cap.heightRoute === "tenderdash-tx"
        && cap.inclusionHeight === "1234");
    // THE SIGNATURE COVERS THE EPOCH, which is the property that matters here: the capture is
    // bound to the context that built it. Recovering the signer from a record whose epoch was
    // altered yields a DIFFERENT key, so the field is inside the signed preimage rather than
    // beside it. (This is a recovery comparison, not a verification against a published key;
    // the fake writer holds no on-chain key, and the claim is stated at that width.)
    const signer = await captureRecord.recoverCaptureSigner(cap);
    const altered = await captureRecord.recoverCaptureSigner({ ...cap, epochIndex: 0 });
    ok("the capture's signature covers its epoch: altering it recovers a different signer",
      /^[0-9a-f]{66}$/.test(signer) && signer !== altered);
  }

  // ================= 12. per-epoch isolation =================
  // THE BUNDLES MUST COME FROM ONE FACTORY, which is the whole point. The first version of this
  // section built two bundles through `bundleOf`, and `bundleOf` makes a fresh factory each time,
  // so the two were isolated by construction and the section asserted nothing. A review moved
  // `prefetched` and the reservation pointer up to factory scope and every assertion still
  // passed. One factory, two bundles, is the only arrangement in which sharing is even possible.
  {
    const { first: zero, second: one } = twoBundlesFromOneFactory(CLEAN);
    zero.prefetched.identityNonce = 8n;
    ok("a nonce prefetched into one epoch's bundle is not visible in another built from the SAME factory",
      one.prefetched.identityNonce === null);
    zero.prefetched.headerContractNonce = 42n;
    ok("the header nonce slot is per bundle as well", one.prefetched.headerContractNonce === null);
    zero.prefetched.contractNonce = 42n;
    zero.deps.buildReservationTransition({ poolId: POOL, accrualId: EP0.rows[0].accrualId, boundTransferHash: "aa".repeat(32) });
    ok("a reservation built in one bundle leaves the pointer of another from the SAME factory unset", (() => {
      try { one.deps.reservationDocumentIdOf(); return false; } catch (e) { return /no reservation was built/.test(e.message); }
    })());
    ok("and the bundle that built it still has its own id", typeof zero.deps.reservationDocumentIdOf() === "string");
    // each bundle answers its own context's figures, from one factory
    ok("two bundles from one factory answer their own epochs' figures",
      zero.deps.epochNumbers().grossCredits === "10000" && one.deps.epochNumbers().grossCredits === "10001");
  }

  // ================= 12b. the lifecycle record is read as it stands =================
  // NOT A REQUIREMENT THE LOOP DEPENDS ON, and it is recorded at that width. The loop builds a
  // fresh bundle per epoch AFTER adding the finished one, so a bundle that copied the record at
  // construction would behave identically. An independent review made exactly that change and
  // nothing observed it. This pins the behaviour that exists rather than claiming the loop needs
  // it, so a later decision to copy is a conscious change instead of a silent one.
  {
    const e = mkEnv();
    const record = new Set();
    const b = CLEAN.makeEpochDepsFactory(e.env)(EP1, record);
    ok("with the record empty the epoch answers false", b.deps.epochDistributionComplete(0) === false);
    record.add(0);
    ok("the bundle reads the run's record as it stands rather than a copy taken at construction",
      b.deps.epochDistributionComplete(0) === true);
  }

  // ================= 13. the balance reshape =================
  {
    const { deps } = bundleOf(CLEAN, EP0);
    const r = await deps.fetchBalanceWithMetadata();
    ok("the balance and height are handed on as canonical decimal strings",
      r.balance === "999" && r.metadata.height === "555" && r.metadata.chainId === PIN);
  }

  // ================= 14. THE MUTATION BATTERY (the contrary control) =================
  // Each entry removes exactly ONE check from the module's source. `probe` returns a value the
  // clean module and the mutant must DISAGREE about; `expect` is the clean module's answer. A
  // mutant whose probe throws is recorded as NOT CAUGHT, because a break is not a detection.
  const SRC_PATH = path.join(__dirname, "e2DistributeEpochDeps.cjs");
  const SRC = fs.readFileSync(SRC_PATH, "utf8");
  const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-epochdeps-mut-"));

  const hdrDoc = (poolHex, epoch) => ({ id: "aa".repeat(32),
    getProperties: () => ({ poolId: Buffer.from(poolHex, "hex"), epochIndex: epoch }) });
  const contents = { grossCredits: "10000", feeCredits: "100", allocationHash: "ee".repeat(32),
    memberCount: 2, calcVersion: 1 };

  const MUTATIONS = [
    { id: "M1", what: "the lifecycle answer stops reading the run's completed record and always says complete",
      from: "epochDistributionComplete: (epochIndex) => completedEpochs.has(epochIndex),",
      to: "epochDistributionComplete: (epochIndex) => true,",
      probe: async (mod) => bundleOf(mod, EP1, new Set()).deps.epochDistributionComplete(1), expect: false },
    { id: "M2", what: "discovery stops bounding its answer to the asked-for range",
      from: "epochs: RUN_EPOCHS.filter((n) => n >= start && n <= end).map((n) => ({ number: n })) }),",
      to: "epochs: RUN_EPOCHS.map((n) => ({ number: n })) }),",
      probe: async (mod) => (await bundleOf(mod, EP0).deps.fetchRange(2, 9)).epochs.length, expect: 0 },
    { id: "M3", what: "the carry member is dropped on the way to the writer",
      from: '...("carryInCredits" in r ? { carryInCredits: r.carryInCredits } : {}) })),',
      to: "})),",
      probe: async (mod) => "carryInCredits" in bundleOf(mod, EP1).deps.entitlementsForEpoch(1)[0], expect: true },
    { id: "M4", what: "the figures stop coming from this bundle's own context",
      from: "epochNumbers: () => ({ grossCredits: ctx.figures.grossCredits,",
      to: "epochNumbers: () => ({ grossCredits: contextFor(RUN_EPOCHS[0]).figures.grossCredits,",
      probe: async (mod) => bundleOf(mod, EP1).deps.epochNumbers().grossCredits, expect: "10001" },
    { id: "M5", what: "the proved read stops checking the key it was asked for",
      from: "if (fields.poolId !== poolId || fields.epochIndex !== epochIndex) {",
      to: "if (false) {",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0, new Set(), { provedAnswer: async () => [hdrDoc(OTHER_POOL, 0)] });
        try { await b.deps.provedHeaderQuery(POOL, 0); return "answered"; }
        catch (e) { return /not what was asked for/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "M6", what: "the proved read stops refusing more than one header",
      from: "if (found.length !== 1) {\n          throw new Error(`${label}: the proved read served ${found.length} headers",
      to: "if (false) {\n          throw new Error(`${label}: the proved read served ${found.length} headers",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0, new Set(), { provedAnswer: async () => [hdrDoc(POOL, 0), hdrDoc(POOL, 0)] });
        try { await b.deps.provedHeaderQuery(POOL, 0); return "answered"; }
        catch (e) { return /served 2 headers/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "M7", what: "the ONE proved read stops checking the verified-call marker",
      from: "if (!globalThis.__tegaraResponseMetadata || !globalThis.__tegaraResponseMetadata.metadata) {",
      to: "if (false) {",
      probe: async (mod) => {
        const pq = mod.makeProvedQuery({ query: async () => { delete globalThis.__tegaraResponseMetadata; return ["unproved"]; } });
        try { await pq("epochHeader", [], "probe"); return "answered"; }
        catch (e) { return /no verified-call marker/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "M8", what: "the contract-nonce read stops checking the chain and protocol pins",
      from: "if (r.metadata.chainId !== pin || Number(r.metadata.protocolVersion) !== PROTOCOL_PIN) {\n        throw new Error(`the proved contract-nonce read fails the pins",
      to: "if (false) {\n        throw new Error(`the proved contract-nonce read fails the pins",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0, new Set(), { env: {
          readContractNonce: async () => ({ nonce: 41n, metadata: { chainId: "other", protocolVersion: PROTOCOL_PIN } }) } });
        try { await b.contractNonce(); return "answered"; }
        catch (e) { return /contract-nonce read fails the pins/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "M9", what: "the identity-nonce read stops checking the chain and protocol pins",
      from: "if (r.metadata.chainId !== pin || Number(r.metadata.protocolVersion) !== PROTOCOL_PIN) {\n        throw new Error(`the proved identity-nonce read fails the pins",
      to: "if (false) {\n        throw new Error(`the proved identity-nonce read fails the pins",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0, new Set(), { env: {
          readIdentityNonce: async () => ({ nonce: 7n, metadata: { chainId: PIN, protocolVersion: 11 } }) } });
        try { await b.identityNonce(); return "answered"; }
        catch (e) { return /identity-nonce read fails the pins/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "M10", what: "the header build stops refusing an epoch other than its context's",
      from: "if (epochIndex !== ctx.epochIndex) {",
      to: "if (false) {",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0, new Set(), { env: { bootstrap: true } });
        b.prefetched.headerContractNonce = 42n;
        try { b.deps.buildHeaderTransition({ poolId: POOL, epochIndex: 1, expectedContents: contents }); return "built"; }
        catch (e) { return /wrong epoch/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "M11", what: "a resume run stops refusing to build a fresh header",
      from: 'if (!BOOTSTRAP) throw new Error("the resume run never builds a fresh header',
      to: 'if (false) throw new Error("the resume run never builds a fresh header',
      probe: async (mod) => {
        const b = bundleOf(mod, EP0);
        b.prefetched.headerContractNonce = 42n;
        try { b.deps.buildHeaderTransition({ poolId: POOL, epochIndex: 0, expectedContents: contents }); return "built"; }
        catch (e) { return /never builds a fresh header/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "M12", what: "the prefetched identity nonce stops being consumed once, so a second build reuses it",
      from: "const nonce = prefetched.identityNonce; prefetched.identityNonce = null; // consumed once",
      to: "const nonce = prefetched.identityNonce;",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0);
        b.prefetched.identityNonce = 8n;
        const row = EP0.rows[0];
        b.deps.buildTransferTransition({ accrualId: row.accrualId, amountCredits: row.amountCredits });
        try { b.deps.buildTransferTransition({ accrualId: row.accrualId, amountCredits: row.amountCredits }); return "built-twice"; }
        catch (e) { return /identity nonce was not prefetched/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "M13", what: "clearing the reservation pointer stops clearing it, so a later step reads the previous one's id",
      from: "clearLastReservation: () => { lastReservationDocIdHex = null; } };",
      to: "clearLastReservation: () => {} };",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0);
        b.prefetched.contractNonce = 42n;
        b.deps.buildReservationTransition({ poolId: POOL, accrualId: EP0.rows[0].accrualId, boundTransferHash: "aa".repeat(32) });
        b.clearLastReservation();
        try { b.deps.reservationDocumentIdOf(); return "stale-id-returned"; }
        catch (e) { return /no reservation was built/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "M14", what: "the logical binding stops refusing an ambiguous answer",
      from: "if (found.length > 1) throw new Error(`the unique logical binding for ${object} returned ${found.length} documents; refusing`);",
      to: "",
      probe: async (mod) => {
        const one = { getProperties: () => ({ poolId: Buffer.from(POOL, "hex") }) };
        const b = bundleOf(mod, EP0, new Set(), { queryAnswer: async () => [one, one] });
        try { await b.deps.documents.fetch("receipt", { accrualId: EP0.rows[0].accrualId }); return "answered"; }
        catch (e) { return /returned 2 documents/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "M15", what: "the environment contract stops refusing a missing member, so a bundle is built with an undefined hook",
      from: "if (env[k] === undefined || env[k] === null) refuse(`makeEpochDepsFactory needs env.${k}`);",
      to: "",
      probe: async (mod) => {
        const { env } = mkEnv();
        delete env.provedQuery;
        try { mod.makeEpochDepsFactory(env); return "accepted"; }
        catch (e) { return /needs env\.provedQuery/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },

    // ---- M16 to M24: THE REVIEWER'S OWN MUTATIONS ----
    // An independent repository-access round constructed these against the first version of this
    // battery and every one of them survived it. They are adopted verbatim in substance rather
    // than paraphrased, because an author-chosen mutation reverts a defect already known and
    // proves the least, and these were chosen by somebody looking for what the author missed.
    { id: "M16", what: "the proved read stops clearing a marker left by an earlier read",
      from: "    delete globalThis.__tegaraResponseMetadata;\n    const docs = await query(type, where);",
      to: "    const docs = await query(type, where);",
      probe: async (mod) => {
        globalThis.__tegaraResponseMetadata = { metadata: { height: 42 } }; // stale
        const pq = mod.makeProvedQuery({ query: async () => ["doc"] }); // sets no marker
        try { await pq("epochHeader", [], "probe"); return "answered"; }
        catch (e) { return /no verified-call marker/.test(e.message) ? "refused" : `other:${e.message}`; }
        finally { delete globalThis.__tegaraResponseMetadata; }
      }, expect: "refused" },
    { id: "M17", what: "the reservation's prefetched nonce stops being consumed once",
      from: "const nonce = prefetched.contractNonce; prefetched.contractNonce = null; // consumed once",
      to: "const nonce = prefetched.contractNonce;",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0);
        b.prefetched.contractNonce = 42n;
        const args = { poolId: POOL, accrualId: EP0.rows[0].accrualId, boundTransferHash: "aa".repeat(32) };
        b.deps.buildReservationTransition(args);
        try { b.deps.buildReservationTransition(args); return "built-twice"; }
        catch (e) { return /contract nonce was not prefetched/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
    { id: "M18", what: "the header document is filled with the NEXT epoch's index while its identity stays on this one",
      from: "        const fields = { poolId: Buffer.from(poolId, \"hex\"), epochIndex,",
      to: "        const fields = { poolId: Buffer.from(poolId, \"hex\"), epochIndex: epochIndex + 1,",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0, new Set(), { env: { bootstrap: true } });
        b.prefetched.headerContractNonce = 42n;
        b.deps.buildHeaderTransition({ poolId: POOL, epochIndex: 0,
          expectedContents: { grossCredits: "10000", feeCredits: "100", allocationHash: "ee".repeat(32), memberCount: 2, calcVersion: 1 } });
        return b.createdDocs[b.createdDocs.length - 1].fields.epochIndex;
      }, expect: 0 },
    { id: "M19", what: "the transfer transition is built for one credit instead of the amount asked for",
      from: "      identityId: ID_A, amount: BigInt(amountCredits), recipientId: row.recipientB58, identityNonce: nonce });",
      to: "      identityId: ID_A, amount: 1n, recipientId: row.recipientB58, identityNonce: nonce });",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0);
        b.prefetched.identityNonce = 8n;
        const row = EP0.rows[0];
        b.deps.buildTransferTransition({ accrualId: row.accrualId, amountCredits: row.amountCredits });
        return String(b.identityTransitions[b.identityTransitions.length - 1].amount);
      }, expect: "1000" },
    { id: "M20", what: "every row reaches the writer owing zero",
      from: "        accrualId: r.accrualId, amountCredits: r.amountCredits, recipientId: r.recipientId,",
      to: "        accrualId: r.accrualId, amountCredits: \"0\", recipientId: r.recipientId,",
      probe: async (mod) => bundleOf(mod, EP0).deps.entitlementsForEpoch(0)[0].amountCredits,
      expect: EP0.rows[0].amountCredits },
    { id: "M21", what: "the accrual's logical binding addresses the CONTRACT identifier as its pool",
      from: "        return [[\"poolId\", \"==\", Buffer.from(POOL, \"hex\")],\n          [\"funderId\", \"==\", Buffer.from(row.funderHex, \"hex\")], [\"epochIndex\", \"==\", key.epochIndex]];",
      to: "        return [[\"poolId\", \"==\", Buffer.from(V11, \"hex\")],\n          [\"funderId\", \"==\", Buffer.from(row.funderHex, \"hex\")], [\"epochIndex\", \"==\", key.epochIndex]];",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0);
        await b.deps.documents.fetch("accrual", { accrualId: EP0.rows[0].accrualId, epochIndex: 0 });
        return b.queries[b.queries.length - 1].where[0][2].toString("hex");
      }, expect: POOL },
    { id: "M22", what: "the proved header read asks the ledger about the NEXT epoch",
      from: "          [[\"poolId\", \"==\", Buffer.from(poolId, \"hex\")], [\"epochIndex\", \"==\", epochIndex]], label);",
      to: "          [[\"poolId\", \"==\", Buffer.from(poolId, \"hex\")], [\"epochIndex\", \"==\", epochIndex + 1]], label);",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0, new Set(), { provedAnswer: async () => [] });
        await b.deps.provedHeaderQuery(POOL, 0);
        return b.provedCalls[b.provedCalls.length - 1].where[1][2];
      }, expect: 0 },
    // THE DESCRIPTION AND THE EDITS AGREE. The first version of M23 named both the prefetch and
    // the reservation pointer and hoisted only the prefetch, which a review called out as a
    // description wider than the mutation. Both are hoisted now, and the probe reads both.
    { id: "M23", what: "the prefetch and the reservation pointer are both hoisted to FACTORY scope, so two bundles share them",
      edits: [
        ["  return (ctx, completedEpochs) => {",
          "  const HOISTED_PREFETCH = { identityNonce: null, contractNonce: null, headerContractNonce: null };\n  let HOISTED_RESERVATION = null;\n  return (ctx, completedEpochs) => {"],
        ["    const prefetched = { identityNonce: null, contractNonce: null, headerContractNonce: null };\n    let lastReservationDocIdHex = null;",
          "    const prefetched = HOISTED_PREFETCH;"],
        ["lastReservationDocIdHex = idHex(b58);", "HOISTED_RESERVATION = idHex(b58);"],
        ["        if (!lastReservationDocIdHex) throw new Error(\"no reservation was built in this step\");\n        return lastReservationDocIdHex;",
          "        if (!HOISTED_RESERVATION) throw new Error(\"no reservation was built in this step\");\n        return HOISTED_RESERVATION;"],
        ["      clearLastReservation: () => { lastReservationDocIdHex = null; } };",
          "      clearLastReservation: () => { HOISTED_RESERVATION = null; } };"],
      ],
      probe: async (mod) => {
        const { first, second } = twoBundlesFromOneFactory(mod);
        first.prefetched.identityNonce = 8n;
        const nonceShared = second.prefetched.identityNonce !== null;
        first.prefetched.contractNonce = 42n;
        first.deps.buildReservationTransition({ poolId: POOL, accrualId: EP0.rows[0].accrualId, boundTransferHash: "aa".repeat(32) });
        let pointerShared = false;
        try { second.deps.reservationDocumentIdOf(); pointerShared = true; } catch { pointerShared = false; }
        return (nonceShared || pointerShared) ? "shared" : "isolated";
      }, expect: "isolated" },
    { id: "M24", what: "the contract-nonce read rewrites the served protocol version to the pinned one before checking it",
      from: "    const contractNonce = async () => {\n      const r = await readContractNonce();",
      to: "    const contractNonce = async () => {\n      const r0 = await readContractNonce();\n      const r = { ...r0, metadata: { ...r0.metadata, protocolVersion: PROTOCOL_PIN } };",
      probe: async (mod) => {
        const b = bundleOf(mod, EP0, new Set(), { env: {
          readContractNonce: async () => ({ nonce: 41n, metadata: { chainId: PIN, protocolVersion: PROTOCOL_PIN + 1 } }) } });
        try { await b.contractNonce(); return "answered"; }
        catch (e) { return /contract-nonce read fails the pins/.test(e.message) ? "refused" : `other:${e.message}`; }
      }, expect: "refused" },
  ];

  let caught = 0;
  for (const m of MUTATIONS) {
    // (1) EVERY PATTERN MUST MATCH, exactly once. A replacement that matches nothing reports
    // success while changing nothing, which is the shape that made this assertion a rule.
    // A mutation may carry SEVERAL edits (hoisting a binding out of a scope needs two), and
    // every one of them is held to the same rule.
    const edits = m.edits || [[m.from, m.to]];
    let mutantSrc = SRC;
    let badPattern = null;
    for (const [from, to] of edits) {
      const hits = mutantSrc.split(from).length - 1;
      if (hits !== 1) { badPattern = `pattern matches ${hits} times, not once: ${JSON.stringify(from.slice(0, 60))}`; break; }
      mutantSrc = mutantSrc.replace(from, to);
    }
    if (badPattern) {
      failed++; console.error(`FAIL: ${m.id} ${badPattern}`);
      continue;
    }
    const file = path.join(TMP, `mutant-${m.id}.cjs`);
    // the mutant must resolve its siblings, so it is written beside them under a temp NAME
    fs.writeFileSync(file, mutantSrc.replace(/require\("\.\//g, `require("${__dirname.replace(/\\/g, "/")}/`));
    // (2) THE MUTANT MUST LOAD. One that does not is a broken mutant, not a caught one.
    let mod = null;
    try { delete require.cache[file]; mod = require(file); }
    catch (e) { failed++; console.error(`FAIL: ${m.id} mutant did not load: ${(e && e.message) || e}`); continue; }
    // (3) THE CLEAN MODULE MUST GIVE THE EXPECTED ANSWER, which binds the probe to the property
    let cleanAnswer;
    try { cleanAnswer = await m.probe(CLEAN); }
    catch (e) { failed++; console.error(`FAIL: ${m.id} probe threw on the CLEAN module: ${(e && e.message) || e}`); continue; }
    if (JSON.stringify(cleanAnswer) !== JSON.stringify(m.expect)) {
      failed++; console.error(`FAIL: ${m.id} probe on the clean module answered ${JSON.stringify(cleanAnswer)}, expected ${JSON.stringify(m.expect)}`);
      continue;
    }
    // (4) THE MUTANT MUST DISAGREE, and by reaching the path rather than by breaking
    let mutantAnswer;
    try { mutantAnswer = await m.probe(mod); }
    catch (e) { failed++; console.error(`FAIL: ${m.id} mutant probe threw (a break is not a detection): ${(e && e.message) || e}`); continue; }
    if (String(mutantAnswer).startsWith("other:")) {
      failed++; console.error(`FAIL: ${m.id} mutant failed for an unrelated reason: ${mutantAnswer}`);
      continue;
    }
    ok(`${m.id} is CAUGHT: ${m.what} (clean=${JSON.stringify(cleanAnswer)}, mutant=${JSON.stringify(mutantAnswer)})`,
      JSON.stringify(mutantAnswer) !== JSON.stringify(cleanAnswer));
    if (JSON.stringify(mutantAnswer) !== JSON.stringify(cleanAnswer)) caught++;
  }
  ok(`every one of the ${MUTATIONS.length} mutations is caught by a named probe (${caught} caught)`,
    caught === MUTATIONS.length);
  // THE PASS REPORTS WHAT IT DID, not only its verdict, so a run that applied no mutation at all
  // is visible instead of looking identical to a clean one (the standing block's item 8).
  console.log(`  [mutations] ${MUTATIONS.length} applied to ${path.basename(SRC_PATH)}, ${caught} caught: ${MUTATIONS.map((m) => m.id).join(" ")}`);
  fs.rmSync(TMP, { recursive: true, force: true });
  delete globalThis.__tegaraResponseMetadata;

  // ================= 15. the runner drives this module =================
  // STATED WIDTH: a text sweep over the runner's source. It binds the SPELLING of the wiring, not
  // its execution, which only a live run exercises. It is here because the decisions themselves
  // are covered by the battery above, which is the instrument the sweep used to stand in for.
  {
    const src = runnerSource("e2DistributeRun.mjs");
    if (src === null) { skipped += 1; console.log(skipNote("e2DistributeRun.mjs", "the runner-binding sweep")); } else {
    ok("the runner builds its dependency factory from this module rather than inline",
      /const epochDepsFor = epochDeps\.makeEpochDepsFactory\(\{/.test(src));
    ok("the runner keeps no inline dependency factory",
      !/const epochDepsFor = \(ctx, completedEpochs\) =>/.test(src));
    ok("the runner's proved read is this module's one marker check, not a second copy",
      /epochDeps\.makeProvedQuery\(\{/.test(src)
        && !/__tegaraResponseMetadata/.test(src));
    ok("the runner still hands the factory to the epoch loop", /epochDepsFor,/.test(src));
    }
  }

  console.log(`\ne2DistributeEpochDepsTest: ${passed} passed, ${failed} failed` + (skipped ? `, ${skipped} skipped (counted, never folded into passes)` : ""));
  if (failed) process.exitCode = 1;
};
main().catch((e) => { console.error("e2DistributeEpochDepsTest crashed:", (e && e.stack) || e); process.exitCode = 1; });
