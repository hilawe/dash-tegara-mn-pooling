/**
 * e2FinalEpochCommandTest: the operator command (e2FinalEpochCommand.cjs) driven offline over a fake
 * ledger, with the REAL plan, the REAL outcome classifier, the REAL identifier derivation over the
 * INSTALLED generator, and the REAL served-document adapter.
 *
 * THE SHARED-IDENTITY RULE (the project's payment-recovery rules, 2026-09-24): every case's ledger also holds a SECOND POOL OF THE
 * SAME WRITER, with its own record for the same member and its own header at the named epoch, so a
 * command that read or wrote across pools is visible. The nonce-collision case is that rule's direct
 * case: the other pool's write takes this write's nonce, and the command must report a refusal, never
 * a record.
 *
 * THE EXPECTATIONS ARE THE INVARIANT'S (FINAL_EPOCH_DESIGN.md, the command's ownership invariant):
 * one identifier per pool and member, recomputed here through e2DocId. Every read happens under the
 * lock the distribution run holds, named here independently as "e2-pool-" and the pool. A result is
 * claimed only from a read-back.
 */
"use strict";
const crypto = require("crypto");
const path = require("path");
const { pathToFileURL } = require("url");
const M = require("./e2FinalEpochCommand.cjs");
const D = require("./e2DocId.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) { passed++; console.log(`  PASS: ${name}`); } else { failed++; console.error(`  FAIL: ${name}`); } };
const rejects = async (name, p, re) => {
  let t = null;
  try { await p; } catch (e) { t = (e && e.message) || String(e); }
  ok(`${name} (${t ? t.slice(0, 100) : "no refusal"})`, t !== null && re.test(t));
};

const h = (f) => f.repeat(64 / f.length);
const POOL = h("1a"), POOL2 = h("2b");            // two pools of ONE writer
const A = h("aa"), B = h("bb"), C = h("cc");      // A and B are the pool's members, C is not
const OWNER_B58 = "5jLZJF4RurvAkahXhLLHHgBisEDgs58v8AmP8w7cMqe";
const CONTRACT_B58 = "8sVj3E2yqQtV3f5mHdq2vG6x7PhZyM2QPZbYjVSNv9L";
const CHAIN = "tegara-test-1", PROTOCOL = 12;
const F = 6;

// the four wrapper literals, in the classifier's closed shapes
const SUCCESS = () => ({ outcome: "verified-proof", proof: {}, metadata: {}, proofMsg: "ab", metadataMsg: "cd", unknownFieldsDropped: 0 });
const REFUSAL = (code = 40204, message = "the nonce is already present") => ({ outcome: "execution-refusal", code, data: "", message });
// a REAL-FORMAT unique-index refusal (code 40105 and the serialized error, in the layout of the real
// testnet payloads, consensusErrorPinTest.cjs) naming the final-epoch type's index
const UNIQUE_REFUSAL = () => ({ outcome: "execution-refusal", code: 40105,
  data: Buffer.concat([Buffer.from([2, 14]), Buffer.alloc(32, 0x5a), Buffer.from([2]),
    Buffer.from([6]), Buffer.from("poolId"), Buffer.from([8]), Buffer.from("funderId")]).toString("hex"),
  message: 'Document has duplicate unique properties ["poolId", "funderId"] with other documents' });
const GATEWAY_TIMEOUT = () => ({ outcome: "execution-refusal", code: 13, data: "", message: "the wait deadline elapsed" });

const main = async () => {
  console.log("e2FinalEpochCommandTest");
  const root = process.env.TEGARA_PLATFORM_ROOT || path.resolve(__dirname, "../..");
  const dpp = await import(pathToFileURL(require.resolve("pshenmic-dpp", { paths: [root] })).href);
  const generateId = (...a) => dpp.DocumentWASM.generateId(...a);
  const planned = (pool, member) => D.finalEpochIdFor({ generateId, ownerId: OWNER_B58, contractId: CONTRACT_B58, poolId: pool, funderId: member });

  /**
   * world(opts): a fake ledger shared by POOL and POOL2, the command's deps over it, and a log of
   * what the command did. opts.onSubmit(ledger) mutates the ledger at submit time and returns the
   * submit's wrapper result, and opts.waits is the sequence waitOnly answers.
   */
  const world = (opts = {}) => {
    const ledger = {
      records: [{ poolId: POOL2, funderId: B, finalEpochIndex: 2, createdAt: 10 }, ...(opts.records || [])],
      headers: [{ poolId: POOL2, epochIndex: F, createdAt: 20 }, ...(opts.headers || [])],
      contractNonce: 7n,
    };
    const seen = { lock: [], held: false, outsideLock: [], nonceReads: 0, builds: [], submits: 0, waits: 0, allocationReads: 0 };
    const guard = (what) => { if (!seen.held) seen.outsideLock.push(what); };
    const docOf = (props, createdAt) => ({ getProperties: () => props, createdAt: BigInt(createdAt) });
    const waits = [...(opts.waits || [])];
    const deps = {
      acquireLock: (name) => { seen.lock.push(["acquire", name]); seen.held = true; },
      releaseLock: (name) => { seen.lock.push(["release", name]); seen.held = false; },
      contractDefinesType: () => { guard("contractDefinesType"); return opts.defines === undefined ? true : opts.defines; },
      resolveAllocation: async () => { guard("resolveAllocation"); seen.allocationReads++; return [A, B]; },
      readJournal: () => { guard("readJournal"); return opts.journal || { configuredStartEpoch: 4, perEpoch: {} }; },
      provedQuery: async (type, where) => {
        guard(`provedQuery:${type}`);
        const pool = Buffer.from(where[0][2]).toString("hex");
        if (type === "memberFinalEpoch" && opts.failReadAfterSubmit && seen.submits > 0) {
          throw new Error("the read-back did not pass through the proving route");
        }
        if (type === "memberFinalEpoch") {
          return ledger.records.filter((r) => opts.unfiltered || r.poolId === pool).map((r) => docOf({
            poolId: Buffer.from(r.poolId, "hex"), funderId: Buffer.from(r.funderId, "hex"), finalEpochIndex: r.finalEpochIndex }, r.createdAt));
        }
        if (type === "epochHeader") {
          return ledger.headers.filter((x) => x.poolId === pool && x.epochIndex === where[1][2])
            .map((x) => docOf({ poolId: Buffer.from(x.poolId, "hex"), epochIndex: x.epochIndex }, x.createdAt));
        }
        throw new Error(`unexpected type ${type}`);
      },
      idHex: (v) => { throw new Error(`idHex should not be reached in this fixture (${typeof v})`); },
      generateId,
      readContractNonce: async () => { guard("readContractNonce"); seen.nonceReads++; return { nonce: ledger.contractNonce, metadata: { chainId: opts.chain || CHAIN, protocolVersion: PROTOCOL } }; },
      buildSigned: (args) => {
        guard("buildSigned");
        seen.builds.push(args);
        return { stt: { built: seen.builds.length }, transitionHash: crypto.createHash("sha256").update(JSON.stringify({ ...args, entropy: Buffer.from(args.entropy).toString("hex"), nonce: String(args.nonce) })).digest("hex") };
      },
      submit: async () => {
        guard("submit"); seen.submits++;
        if (opts.onSubmit) return opts.onSubmit(ledger);
        ledger.records.push({ poolId: POOL, funderId: B, finalEpochIndex: F, createdAt: 15 });
        return SUCCESS();
      },
      waitOnly: async () => {
        guard("waitOnly"); seen.waits++;
        const next = waits.shift();
        if (!next) return GATEWAY_TIMEOUT();
        return typeof next === "function" ? next(ledger) : next;
      },
    };
    return { ledger, seen, deps };
  };
  const run = (w, over = {}) => M.runFinalEpochCommand({ poolId: POOL, funderId: B, finalEpochIndex: F, ownerId: OWNER_B58,
    contractId: CONTRACT_B58, chainIdPin: CHAIN, protocolPin: PROTOCOL, deps: w.deps, maxWaits: 2, ...over });
  // A THROW MUST FAIL A NAMED CASE, NOT END THE BATTERY: the cases about post-write failures read
  // their outcome through this, so an implementation that lets an exception escape fails there
  // (twice a variant that did so was caught only by the whole file crashing)
  const settle = async (w, over) => { try { return await run(w, over); } catch (e) { return { outcome: "THREW", message: (e && e.message) || String(e) }; } };
  const cleanLock = (w) => w.seen.outsideLock.length === 0 && w.seen.held === false
    && JSON.stringify(w.seen.lock) === JSON.stringify([["acquire", `e2-pool-${POOL}`], ["release", `e2-pool-${POOL}`]]);

  // ---- 1. THE SUCCESSFUL CASE ----
  {
    const w = world();
    const r = await run(w);
    const b = w.seen.builds[0];
    ok("the record is written and read back: outcome recorded", r.outcome === "recorded" && r.token === "success-with-proof");
    ok("it is written at the identifier derived from the pool and the member, recomputed here", b.documentIdB58 === planned(POOL, B).b58
      && Buffer.from(b.entropy).equals(planned(POOL, B).entropy) && r.documentId === planned(POOL, B).hex);
    ok("the fields are exactly the pool, the member and the epoch", JSON.stringify(b.fields) === JSON.stringify({ poolId: POOL, funderId: B, finalEpochIndex: F }));
    ok("the nonce is the proved contract nonce plus one", b.nonce === 8n && w.seen.nonceReads === 1);
    ok("every read and the write happen under the lock a distribution run of THIS pool holds, released after", cleanLock(w));
    ok("one build, one submit, no wait", w.seen.builds.length === 1 && w.seen.submits === 1 && w.seen.waits === 0);
    ok("the other pool's record for the same member and its header at the same epoch changed nothing here",
      w.ledger.records.filter((x) => x.poolId === POOL).length === 1 && planned(POOL, B).hex !== planned(POOL2, B).hex);
  }
  // ---- 2. A RERUN, and a record naming another epoch ----
  {
    const w = world({ records: [{ poolId: POOL, funderId: B, finalEpochIndex: F, createdAt: 15 }] });
    const r = await run(w);
    ok("a rerun finds the record and writes nothing: already-recorded, no nonce read, no build, no submit",
      r.outcome === "already-recorded" && w.seen.nonceReads === 0 && w.seen.builds.length === 0 && w.seen.submits === 0 && cleanLock(w));
    const w2 = world({ records: [{ poolId: POOL, funderId: B, finalEpochIndex: 9, createdAt: 15 }] });
    await rejects("a record naming another epoch refuses, and nothing is written", run(w2), /already has final epoch 9/);
    ok("and the lock is released after that refusal", cleanLock(w2) && w2.seen.builds.length === 0);
  }
  // ---- 3. FIXED BEFORE USE: the header on the ledger or in the journal ----
  {
    const w = world({ headers: [{ poolId: POOL, epochIndex: F, createdAt: 30 }] });
    await rejects("a header for the epoch on the ledger refuses", run(w), /header already exists/);
    ok("and nothing is written", w.seen.builds.length === 0 && w.seen.submits === 0);
    const wj = world({ journal: { configuredStartEpoch: 4, perEpoch: { [F]: { header: { gen: 1, state: "written" }, accruals: {} } } } });
    await rejects("a header write-ahead for the epoch in the journal refuses", run(wj), /header already exists/);
    const wr = world({ journal: { configuredStartEpoch: 4, perEpoch: { [F]: { header: { gen: 1, state: "refused" }, accruals: {} } } } });
    await rejects("a header the ledger refused, still in the journal, refuses too (the conservative reading)", run(wr), /header already exists/);
    const wo = world({ journal: { configuredStartEpoch: 4, perEpoch: { [F + 1]: { header: { gen: 1, state: "written" }, accruals: {} } } } });
    ok("a journal header at ANOTHER epoch does not refuse", (await run(wo)).outcome === "recorded");
    ok("the other pool's header at the same epoch does not refuse (every world holds one)", (await run(world())).outcome === "recorded");
  }
  // ---- 4. the plan's other refusals, and the preconditions ----
  {
    await rejects("a member outside the allocation refuses", run(world(), { funderId: C }), /not in this pool's allocation/);
    await rejects("an epoch before the configured start refuses", run(world(), { finalEpochIndex: 3 }), /before the pool's configured start 4/);
    const wa = world({ defines: false });
    await rejects("a contract that does not define the type refuses", run(wa), /does not define memberFinalEpoch/);
    ok("and it refuses before reading the allocation", wa.seen.allocationReads === 0 && cleanLock(wa));
    await rejects("a non-boolean definition answer refuses", run(world({ defines: "yes" })), /not a boolean/);
    await rejects("a journal binding no configured start refuses", run(world({ journal: { configuredStartEpoch: null, perEpoch: {} } })), /binds no configured start/);
    const wp = world({ chain: "another-chain" });
    await rejects("a nonce read failing the chain pin refuses before any build", run(wp), /fails the chain and protocol pins/);
    ok("and nothing is built", wp.seen.builds.length === 0 && cleanLock(wp));
    await rejects("a record read serving another pool's record refuses", run(world({ unfiltered: true })), /another pool's record|names another pool/);
  }
  // ---- 5. SETTLING FROM THE LEDGER ----
  {
    // THE SHARED-IDENTITY NONCE COLLISION: the other pool's write took nonce 8 first, the ledger
    // refuses this one, and no record exists
    // (Platform's nonce refusal is InvalidIdentityNonceError, 40204; this case used 40105, the
    // unique-index code, until the pin made the difference visible, 2026-09-28)
    const wc = world({ onSubmit: () => REFUSAL(40204, "the identity contract nonce 8 is already present") });
    const rc = await run(wc);
    ok("a nonce collision with another pool of the same writer is reported refused, with its code, never recorded",
      rc.outcome === "refused" && rc.code === 40204 && rc.token === "execution-error-other" && cleanLock(wc));
    // THE UNIQUE-INDEX BRANCH, reachable since the pin, settled against a proved re-read:
    // a unique-index refusal says a record exists at the member's key, so a re-read showing NONE is a
    // stale read (unresolved, rerun-safe), never "refused"
    const wu = world({ onSubmit: () => UNIQUE_REFUSAL() });
    const ru = await run(wu);
    ok("a unique-index refusal beside a proved absence is unresolved, never refused",
      ru.outcome === "unresolved" && ru.token === "execution-error-unique-index" && ru.code === 40105 && cleanLock(wu));
    // the record present with the requested epoch: the identity and content comparison settles it
    const wv = world({ onSubmit: (l) => { l.records.push({ poolId: POOL, funderId: B, finalEpochIndex: F, createdAt: 14 }); return UNIQUE_REFUSAL(); } });
    const rv = await run(wv);
    ok("a unique-index refusal with the record reading back at the requested epoch settles already-recorded",
      rv.outcome === "already-recorded" && rv.token === "execution-error-unique-index");
    // the record present with ANOTHER epoch: the plan's own rule refuses, whatever the token
    const ww = world({ onSubmit: (l) => { l.records.push({ poolId: POOL, funderId: B, finalEpochIndex: 11, createdAt: 14 }); return UNIQUE_REFUSAL(); } });
    await rejects("a unique-index refusal with the record at ANOTHER epoch refuses by the plan's rule", run(ww), /already has final epoch 11/);
    // the same code with ANOTHER error's payload (decodable, not the unique index) is an ordinary
    // consensus refusal: beside a proved absence it is refused, never unresolved (the review's case)
    const wo = world({ onSubmit: () => ({ ...REFUSAL(40105, "another error"), data: "0202" + "5a".repeat(32) }) });
    const ro = await run(wo);
    ok("a 40105 carrying another error's payload beside a proved absence is refused, token other",
      ro.outcome === "refused" && ro.token === "execution-error-other" && ro.code === 40105 && cleanLock(wo));
    // CODE-ONLY IS NOT THE PIN: 40105 with an undecodable payload is ambiguous, waited on, and with
    // no record it stays unresolved rather than refused
    const wm = world({ onSubmit: () => REFUSAL(40105, "no payload") });
    const rm = await run(wm);
    ok("a 40105 with an undecodable payload is waited on and ends unresolved, never refused or unique",
      rm.outcome === "unresolved" && rm.token === "ambiguous" && wm.seen.waits >= 1);
    // a concurrent command for the same member wrote first: the ledger refuses this write at the same identifier
    const wd = world({ onSubmit: (l) => { l.records.push({ poolId: POOL, funderId: B, finalEpochIndex: F, createdAt: 14 }); return REFUSAL(40100, "a document with this identifier already exists"); } });
    ok("a refusal while the record exists with the requested epoch settles already-recorded", (await run(wd)).outcome === "already-recorded");
    const we = world({ onSubmit: (l) => { l.records.push({ poolId: POOL, funderId: B, finalEpochIndex: 11, createdAt: 14 }); return REFUSAL(40100, "a document with this identifier already exists"); } });
    await rejects("a refusal while the record exists with ANOTHER epoch refuses by the plan's rule", run(we), /already has final epoch 11/);
    // AMBIGUOUS, then settled by a wait, never by a second build
    const wf = world({ onSubmit: () => GATEWAY_TIMEOUT(), waits: [(l) => { l.records.push({ poolId: POOL, funderId: B, finalEpochIndex: F, createdAt: 15 }); return SUCCESS(); }] });
    const rf = await settle(wf);
    ok("a gateway timeout is waited on, and a later proved success with a read-back is recorded",
      rf.outcome === "recorded" && wf.seen.submits === 1 && wf.seen.waits === 1 && wf.seen.builds.length === 1);
    const wg = world({ onSubmit: () => GATEWAY_TIMEOUT() });
    const rg = await settle(wg);
    ok("ambiguous through every wait with no record is unresolved (neither a record nor a refusal), with its transition hash",
      rg.outcome === "unresolved" && rg.token === "ambiguous" && wg.seen.waits === 2 && wg.seen.builds.length === 1 && /^[0-9a-f]{64}$/.test(rg.transitionHash));
    const wh = world({ onSubmit: (l) => { l.records.push({ poolId: POOL, funderId: B, finalEpochIndex: F, createdAt: 15 }); return { outcome: "transport-failure", reason: "the connection closed" }; } });
    const rh = await run(wh);
    ok("an unsettled write whose record reads back is already-recorded, not recorded (this write did not prove success)", rh.outcome === "already-recorded" && rh.token === "ambiguous" && wh.seen.waits === 2);
    const wi = world({ onSubmit: () => SUCCESS() });
    ok("a proved success whose record does not read back is unresolved, never recorded", (await run(wi)).outcome === "unresolved");
    // a rerun after an unresolved one lands on the same identifier
    const wj = world({ onSubmit: () => GATEWAY_TIMEOUT() });
    const first = await run(wj);
    wj.ledger.records.push({ poolId: POOL, funderId: B, finalEpochIndex: F, createdAt: 15 });
    const second = await run(wj);
    ok("a rerun after an unresolved attempt finds the record the first one wrote, at the same identifier",
      first.outcome === "unresolved" && second.outcome === "already-recorded" && first.documentId === second.documentId && wj.seen.builds.length === 1);
  }
  // ---- 6. the lock on every path, and the journal predicate ----
  {
    // FROM THE BUILT WRITE ON, A FAILURE IS UNRESOLVED WITH THE HASH (the step 4 review's fourth finding)
    const wt = world({ onSubmit: () => { throw new Error("the wire call threw"); } });
    const rt = await settle(wt);
    ok("a throwing submit is unresolved with the full transition hash and the reason, never an exception",
      rt.outcome === "unresolved" && /^[0-9a-f]{64}$/.test(rt.transitionHash) && /could not be read \(the wire call threw\)/.test(rt.message));
    ok("and the lock is released", cleanLock(wt));
    // an ambiguous submit whose later WAIT throws is unresolved with the hash too (the confirmation
    // round's coverage finding: a re-throw after an ambiguous token survived every case)
    const wat = world({ onSubmit: () => GATEWAY_TIMEOUT(), waits: [() => { throw new Error("the wait threw"); }] });
    const rat = await settle(wat);
    ok("an ambiguous submit followed by a throwing wait is unresolved with the full transition hash",
      rat.outcome === "unresolved" && /^[0-9a-f]{64}$/.test(rat.transitionHash) && /could not be read \(the wait threw\)/.test(rat.message) && cleanLock(wat));
    const wrb = world({ failReadAfterSubmit: true });
    const rrb = await settle(wrb);
    ok("a proved success whose read-back fails is unresolved with the full transition hash, never an exception or a record",
      rrb.outcome === "unresolved" && rrb.token === "success-with-proof" && /^[0-9a-f]{64}$/.test(rrb.transitionHash)
      && /read-back after the write failed/.test(rrb.message) && cleanLock(wrb));
    // A RECORD FOR ANOTHER MEMBER never satisfies the read-back, however close its identifier (the
    // step 4 review's sixth finding: a comparison of eight characters survived every battery)
    const nearB = `${B.slice(0, 63)}${B[63] === "b" ? "c" : "b"}`;
    const wn = world({ onSubmit: (l) => { l.records.push({ poolId: POOL, funderId: nearB, finalEpochIndex: F, createdAt: 15 }); return SUCCESS(); } });
    const rn = await run(wn);
    ok("a record for a member differing only in its last character does not settle this member's write",
      rn.outcome === "unresolved" && rn.token === "success-with-proof");
    ok("journalHeaderAt: no epoch entry, a null header, and a header object", M.journalHeaderAt({ perEpoch: {} }, 6) === false
      && M.journalHeaderAt({ perEpoch: { 6: { header: null } } }, 6) === false && M.journalHeaderAt({ perEpoch: { 6: { header: { state: "sent" } } } }, 6) === true);
    ok("journalHeaderAt reads only own entries (an inherited epoch is not a header)", M.journalHeaderAt({ perEpoch: Object.create({ 6: { header: { state: "sent" } } }) }, 6) === false);
    let threwJ = false; try { M.journalHeaderAt({}, 6); } catch (e) { threwJ = /no perEpoch view/.test(e.message); }
    ok("journalHeaderAt refuses a read with no perEpoch view", threwJ);
    await rejects("a missing dependency refuses", M.runFinalEpochCommand({ poolId: POOL, funderId: B, finalEpochIndex: F, ownerId: OWNER_B58,
      contractId: CONTRACT_B58, chainIdPin: CHAIN, protocolPin: PROTOCOL, deps: { ...world().deps, waitOnly: undefined } }), /deps\.waitOnly must be a function/);
  }

  console.log(`\ne2FinalEpochCommandTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
};

main().catch((e) => { console.error("e2FinalEpochCommandTest crashed:", (e && e.stack) || e); process.exitCode = 1; });
