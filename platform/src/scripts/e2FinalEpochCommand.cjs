/**
 * e2FinalEpochCommand: THE OPERATOR COMMAND that writes one member's final-epoch record
 * (tegara/docs/FINAL_EPOCH_DESIGN.md, "WHO DECIDES, AND WHO WRITES" and "THE COMMAND'S OWNERSHIP
 * INVARIANT"), as a composition a battery drives with fakes. The runner (`e2FinalEpochRun.mjs`)
 * supplies the wire calls and nothing that decides.
 *
 * WHAT IT DOES, in order, all under the pool's lock (the lock every distribution run of the pool
 * holds, named here from `e2Distribute.poolRunLockName` so the two cannot drift):
 *   1. refuses unless the PROVED contract defines memberFinalEpoch;
 *   2. reads the pool's allocation (the proved resolution), the pool's journal, the member's record
 *      on the ledger by proof, and the named epoch's header on the ledger by proof;
 *   3. decides through `e2FinalEpoch.planFinalEpochRecord`, with "the header exists" meaning a header
 *      on the ledger OR any header subject for that epoch in the journal;
 *   4. when the plan is to create: reads the writer's contract nonce by proof (pin-checked), builds
 *      the record at the identifier `e2DocId.finalEpochIdFor` derives from the pool and the member,
 *      submits it, and classifies every result through `e2Outcome.classifyOutcome` (a soundness-review finding), waiting
 *      again on an ambiguous one up to a bound and never rebuilding;
 *   5. SETTLES FROM THE LEDGER, by the invariant's item 4. Four outcomes, and only these:
 *        recorded          this write proved success and the record then reads back by proof with
 *                          the requested epoch
 *        already-recorded  the record reads back with the requested epoch and this write did not
 *                          prove success (it was not needed, or it was refused, or it never settled)
 *        refused           the ledger refused this write for a reason OTHER than the unique index,
 *                          and a proved re-read shows no record
 *        unresolved        none of the above. The transition hash is reported, and a rerun is
 *                          safe because every attempt targets the one identifier
 *      A record reading back with ANOTHER epoch refuses through the plan's own rule (a member's
 *      final epoch never changes).
 *
 * THE UNIQUE-INDEX IDENTITY IS PINNED since 2026-09-28 (consensusErrorPin.cjs: code 40105 and a
 * payload that decodes as that error), so a second write at the same key is recognized. Every
 * refusal is still settled by re-reading the record. What the pin changes is one label: a
 * unique-index refusal SAYS a record exists at this member's key, so a proved re-read that shows none
 * is a stale read, reported unresolved and rerun-safe, as the writer's stale-read rule treats a
 * duplicate refusal beside a proved absence. It was reported refused while the command could not
 * tell which refusal it had (FINAL_EPOCH_DESIGN.md, the ownership invariant's item 4, amended).
 *
 * WHAT IT TAKES ON THE CALLER'S WORD: that `provedQuery` verifies proofs and checks the verified-call
 * marker (the runner passes the writer's `makeProvedQuery`), that `resolveAllocation` is the proved
 * pool resolution, that `readJournal` is the validated journal reader, and that `buildSigned` builds
 * exactly the document it is given at the identifier and nonce it is given. The nonce has no owner
 * record (the invariant's item 5): a concurrent write by another pool of the same writer can take the
 * same nonce, and the ledger then refuses one of the two, which this command reports as "refused" when
 * it is this one and never as a record.
 */
"use strict";

const { planFinalEpochRecord, makeFinalEpochReads } = require("./e2FinalEpoch.cjs");
const { classifyOutcome, TOKENS } = require("./e2Outcome.cjs");
const docId = require("./e2DocId.cjs");
const { poolRunLockName } = require("./e2Distribute.cjs");
const { FINAL_EPOCH_TYPE } = require("./contractV11.cjs");

const HEX32 = /^[0-9a-f]{64}$/;
const refuse = (why) => { throw new Error(`e2FinalEpochCommand: ${why}; refusing`); };
const OUTCOMES = Object.freeze(["recorded", "already-recorded", "refused", "unresolved"]);
const DEFAULT_MAX_WAITS = 4;

/**
 * journalHeaderAt(read, epochIndex) -> boolean: whether the pool's validated journal holds a header
 * subject for that epoch, in ANY state (written, sent, captured, refused or annotated). Any state
 * counts, which is the conservative reading: a record is refused even after a header write the
 * ledger refused, and the operator names a later epoch.
 */
const journalHeaderAt = (read, epochIndex) => {
  if (!read || typeof read !== "object" || !read.perEpoch || typeof read.perEpoch !== "object") {
    refuse("the journal read carries no perEpoch view (the validated journal reader's answer is required)");
  }
  if (!Object.prototype.hasOwnProperty.call(read.perEpoch, String(epochIndex))) return false;
  const e = read.perEpoch[String(epochIndex)];
  return !!(e && e.header !== null && e.header !== undefined);
};

const REQUIRED_DEPS = ["acquireLock", "releaseLock", "contractDefinesType", "resolveAllocation", "readJournal",
  "provedQuery", "idHex", "generateId", "readContractNonce", "buildSigned", "submit", "waitOnly"];

/**
 * runFinalEpochCommand({ poolId, funderId, finalEpochIndex, ownerId, contractId, chainIdPin,
 *                        protocolPin, deps, maxWaits, log })
 *   poolId, funderId   64 lowercase hex
 *   finalEpochIndex    u32
 *   ownerId, contractId  the writer and the contract as the identifier generator takes them (base58)
 *   chainIdPin, protocolPin  the run's pins, checked against the nonce read's metadata
 *   deps
 *     acquireLock(name), releaseLock(name)  the store's operation lock
 *     contractDefinesType()      -> boolean, from the PROVED contract definition
 *     resolveAllocation()        async -> [64-hex member], the proved pool resolution's owners
 *     readJournal()              -> the validated journal read (opened under the lock)
 *     provedQuery(type, where, label)  async -> served documents, marker-checked
 *     idHex(v)                   an identifier served as a non-byte value, to 64 hex
 *     generateId(type, owner, contract, entropy)  the Platform identifier generator
 *     readContractNonce()        async -> { nonce: bigint, metadata: { chainId, protocolVersion } }
 *     buildSigned({ documentIdB58, entropy, fields, nonce })  -> { stt, transitionHash }
 *     submit(stt)                async -> the wrapper result (broadcast, then wait)
 *     waitOnly(stt)              async -> the wrapper result (wait only, never a broadcast)
 * -> { outcome, poolId, funderId, finalEpochIndex, documentId, transitionHash, token, code, message }
 */
const runFinalEpochCommand = async ({ poolId, funderId, finalEpochIndex, ownerId, contractId, chainIdPin,
  protocolPin, deps, maxWaits = DEFAULT_MAX_WAITS, log } = {}) => {
  if (typeof poolId !== "string" || !HEX32.test(poolId)) refuse("the pool must be 64 lowercase hex");
  if (typeof funderId !== "string" || !HEX32.test(funderId)) refuse("the member must be 64 lowercase hex");
  if (!Number.isSafeInteger(finalEpochIndex) || finalEpochIndex < 0 || finalEpochIndex > 4294967295) refuse("the final epoch must be a u32 integer");
  if (typeof ownerId !== "string" || !ownerId.length || typeof contractId !== "string" || !contractId.length) refuse("ownerId and contractId are required as the generator takes them");
  if (typeof chainIdPin !== "string" || !chainIdPin.length || !Number.isSafeInteger(protocolPin)) refuse("the chain and protocol pins are required");
  if (!Number.isSafeInteger(maxWaits) || maxWaits < 0) refuse("maxWaits must be a non-negative integer");
  if (!deps || typeof deps !== "object") refuse("deps is required");
  for (const k of REQUIRED_DEPS) if (typeof deps[k] !== "function") refuse(`deps.${k} must be a function`);
  const say = typeof log === "function" ? log : () => {};

  const lockName = poolRunLockName(poolId);
  deps.acquireLock(lockName);
  try {
    // ---- 1. the type must exist, by the proved contract ----
    const defines = deps.contractDefinesType();
    if (defines !== true) {
      refuse(defines === false
        ? `the pool's contract does not define ${FINAL_EPOCH_TYPE}; the contract update must be registered first`
        : "the contract-definition answer is not a boolean from the proved contract");
    }
    // ---- 2. the reads ----
    const allocationFunders = await deps.resolveAllocation();
    if (!Array.isArray(allocationFunders)) refuse("the pool resolution answered no allocation list");
    const journal = deps.readJournal();
    const configuredStart = journal && journal.configuredStartEpoch;
    if (!Number.isSafeInteger(configuredStart) || configuredStart < 0) {
      refuse("the pool's journal binds no configured start, so the pool has not begun distributing and no epoch can be checked against its start");
    }
    const reads = makeFinalEpochReads({ poolId, provedQuery: deps.provedQuery, idHex: deps.idHex,
      contractDefinesType: () => true });
    const readExisting = async () => {
      const all = await reads.queryRecords();
      for (const r of all) if (r.poolId !== poolId) refuse("the record read served another pool's record");
      const mine = all.filter((r) => r.funderId === funderId);
      if (mine.length > 1) refuse(`the record read served ${mine.length} records for one member, which the unique index forbids`);
      return mine.length ? mine[0] : null;
    };
    const existing = await readExisting();
    // EXISTENCE ONLY, so this read does not depend on the header's served creation time, which the
    // ordering rule needs elsewhere and which has not been observed live yet
    const headers = await deps.provedQuery("epochHeader",
      [["poolId", "==", Buffer.from(poolId, "hex")], ["epochIndex", "==", finalEpochIndex]], `header(${finalEpochIndex})`);
    if (!Array.isArray(headers)) refuse("the header read answered something that is not a list");
    if (headers.length > 1) refuse(`the header read served ${headers.length} headers for epoch ${finalEpochIndex}, which the unique index forbids`);
    const headerOnLedger = headers.length === 1;
    const headerInJournal = journalHeaderAt(journal, finalEpochIndex);
    const ident = docId.finalEpochIdFor({ generateId: deps.generateId, ownerId, contractId, poolId, funderId });
    const base = { poolId, funderId, finalEpochIndex, documentId: ident.hex, transitionHash: null, token: null, code: null, message: null };

    // ---- 3. the plan ----
    const plan = planFinalEpochRecord({ poolId, funderId, finalEpochIndex, allocationFunders, configuredStart,
      headerExists: headerOnLedger || headerInJournal, existing });
    if (plan.action === "already-recorded") {
      say(`[FINAL EPOCH] member ${funderId.slice(0, 12)}...'s record for epoch ${finalEpochIndex} already reads back; nothing written`);
      return { outcome: "already-recorded", ...base };
    }

    // ---- 4. the write ----
    const n = await deps.readContractNonce();
    if (!n || typeof n.nonce !== "bigint" || n.nonce < 0n || !n.metadata
      || n.metadata.chainId !== chainIdPin || Number(n.metadata.protocolVersion) !== protocolPin) {
      refuse("the proved contract-nonce read is malformed or fails the chain and protocol pins");
    }
    const nonce = n.nonce + 1n;
    const fields = { poolId, funderId, finalEpochIndex };
    const built = deps.buildSigned({ documentIdB58: ident.b58, entropy: ident.entropy, fields, nonce });
    if (!built || !built.stt || typeof built.transitionHash !== "string" || !HEX32.test(built.transitionHash)) {
      refuse("buildSigned answered no signed transition with a 64-hex hash");
    }
    const stt = built.stt;
    base.transitionHash = built.transitionHash;
    // THE FULL TRANSITION HASH IS PRINTED BEFORE ANYTHING IS SENT, so an operator holds it whatever
    // happens next
    say(`[FINAL EPOCH] writing member ${funderId.slice(0, 12)}...'s record for epoch ${finalEpochIndex} at ${ident.hex}, contract nonce ${nonce}, transition ${built.transitionHash}`);
    // FROM HERE THE WRITE MAY HAVE EXECUTED, so a failure to learn its outcome or to read the record
    // back is UNRESOLVED with the transition hash, never an exception that loses both (the step 4
    // review's fourth finding). A rerun is safe, since every attempt targets the one identifier.
    const unresolved = (why) => {
      say(`[FINAL EPOCH] ${why}; reported unresolved, and rerunning is safe`);
      return { outcome: "unresolved", ...base, message: why };
    };
    let rec, token;
    try {
      rec = await deps.submit(stt);
      token = classifyOutcome(rec);
      for (let i = 0; token === TOKENS.AMBIGUOUS && i < maxWaits; i++) {
        rec = await deps.waitOnly(stt);
        token = classifyOutcome(rec);
      }
    } catch (e) {
      return unresolved(`the write's outcome could not be read (${(e && e.message) || String(e)})`);
    }
    base.token = token;
    if (rec && rec.outcome === "execution-refusal") { base.code = rec.code; base.message = rec.message; }
    if (rec && (rec.outcome === "transport-failure" || rec.outcome === "malformed-response")) base.message = rec.reason;

    // ---- 5. settle from the ledger ----
    let after;
    try { after = await readExisting(); }
    catch (e) { return unresolved(`the read-back after the write failed (${(e && e.message) || String(e)})`); }
    if (after !== null && after.finalEpochIndex !== finalEpochIndex) {
      // the plan's own rule gives the refusal its canonical words
      planFinalEpochRecord({ poolId, funderId, finalEpochIndex, allocationFunders, configuredStart, headerExists: false, existing: after });
      refuse("internal: a record with another epoch was not refused by the plan");
    }
    if (token === TOKENS.SUCCESS) {
      if (after !== null) return { outcome: "recorded", ...base };
      say("[FINAL EPOCH] the write proved success but the record does not read back yet; reported unresolved");
      return { outcome: "unresolved", ...base };
    }
    if (after !== null) return { outcome: "already-recorded", ...base };
    if (token === TOKENS.OTHER) return { outcome: "refused", ...base };
    if (token === TOKENS.UNIQUE) {
      say("[FINAL EPOCH] the ledger refused this write for the unique index, which says a record exists at this member's key, and the proved re-read shows none; a stale read, reported unresolved");
      return { outcome: "unresolved", ...base };
    }
    return { outcome: "unresolved", ...base };
  } finally {
    deps.releaseLock(lockName);
  }
};

module.exports = { OUTCOMES, DEFAULT_MAX_WAITS, journalHeaderAt, runFinalEpochCommand };
