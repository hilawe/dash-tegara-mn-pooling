/**
 * The mock `dash` module for the formation crash harness (formationCrashTest.cjs): an
 * in-memory Platform ledger persisted to a JSON file, so a hard-exit "crash" leaves
 * exactly the state a real crash would and the orchestrator inspects it from outside.
 *
 * FAULT MODEL (the same "op persisted, then the process died" model as the envStore
 * crash matrix, but the boundaries here are the RECEIPT FLOW's awaits and local-state
 * writes): every platform call ticks the shared fault counter in global.__TEGARA_FAULT
 * (the child runner also ticks it from envStore.updateEnvKey), and when the counter
 * passes the armed threshold the process HARD-EXITS with code 97, skipping every
 * finally block, exactly like a real crash (so an op lock stays held, a draft stays
 * frozen, and the orchestrator must handle both, which is the point).
 *
 * Ledger file (env TEGARA_MOCK_LEDGER): { docs: [{ id, type, ownerId, data }] } with
 * byte fields hex-encoded under data. Mutations rewrite the file BEFORE the fault tick,
 * so a crash "after op N" always has op N durable.
 */
const fs = require("fs");
const crypto = require("crypto");
const { Identifier } = require("@dashevo/wasm-dpp");

// resolved lazily, so the module can be required just for validateReceiptProps (the
// harness parity check) without a ledger env var; only actual ledger ops require it
const ledgerPath = () => {
  const p = process.env.TEGARA_MOCK_LEDGER;
  if (!p) throw new Error("TEGARA_MOCK_LEDGER is not set");
  return p;
};

if (!global.__TEGARA_FAULT) global.__TEGARA_FAULT = { count: 0, after: Infinity };
const tick = () => {
  const f = global.__TEGARA_FAULT;
  f.count += 1;
  if (f.count > f.after) {
    // a REAL crash: no finally blocks, no cleanup, state stays exactly as persisted
    process.stderr.write(`[mock] injected crash after op ${f.count - 1}\n`);
    process.exit(97);
  }
};

// byte fields per document type, hex in the JSON, Buffer in toObject()
// Platform's recognized document SYSTEM fields, always allowed alongside a contract's own
// properties. A KNOWN set, not any $-prefixed key: an invented $-field is rejected, which is
// what real additionalProperties:false does (pass 18 checker).
const SYSTEM_FIELDS = new Set(["$id", "$type", "$ownerId", "$revision", "$createdAt",
  "$updatedAt", "$transferredAt", "$createdAtBlockHeight", "$updatedAtBlockHeight",
  "$transferredAtBlockHeight", "$createdAtCoreBlockHeight", "$updatedAtCoreBlockHeight",
  "$transferredAtCoreBlockHeight", "$protocolVersion"]);
// WHICH DOCUMENT TYPES THE SELECTED LEDGER PUBLISHES (confirm-pass round 12): a query or
// create for a poolLedger type absent from the selected contract is refused the way the
// real SDK refuses an undefined document type, instead of returning an empty page that
// hides a capability-blind call site (the reserve fold and the round-12 debris fold were
// BOTH this shape, and both were hidden by the old always-empty answer). Scope: only
// `poolLedger.*` types are modelled; a foreign app's types still resolve empty, since this
// mock models one app. The base types are v1's; the additions mirror the capability table.
const LEDGER_TYPES = () => {
  const S = require("./envStore.cjs");
  const types = new Set(["pool", "share", "membershipRequest", "rewardAccrual", "votePreference"]);
  if (S.isV3()) types.add("settlement");
  if (S.hasPledgeSlot()) types.add("pledgeSlot");
  if (S.hasCompletionReceipt()) types.add("completionReceipt");
  return types;
};
const requireLedgerType = (type) => {
  if (!type.startsWith("poolLedger.")) return type; // foreign app, out of modelled scope
  const short = type.replace(/^poolLedger\./, "");
  if (!LEDGER_TYPES().has(short)) {
    throw new Error(`mock DPP: document type ${short} is not defined by the selected ledger's contract`);
  }
  return short;
};
const BYTE_FIELDS = new Set(["proTxHash", "poolId", "operatorIdentityId", "rewardScript",
  "l1RewardScript", "allocationRows", "allocationHash", "exitId", "joinId", "leaverId",
  "joinerId", "delegateTo", "proposalHash", "tallyHash"]);

const loadLedger = () => JSON.parse(fs.readFileSync(ledgerPath(), "utf8"));
const saveLedger = (l) => {
  const p = ledgerPath();
  const tmp = `${p}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(l, null, 1));
  fs.renameSync(tmp, p);
};

const idOf = (s) => ({ toString: () => s, toBuffer: () => Buffer.from(Identifier.from(s).toBuffer()) });
const asIdString = (v) => {
  if (v == null) throw new Error("mock: null where value");
  if (typeof v === "string") return v;
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return Identifier.from(Buffer.from(v)).toString();
  if (typeof v.toBuffer === "function") return Identifier.from(Buffer.from(v.toBuffer())).toString();
  if (typeof v.toString === "function") return v.toString();
  throw new Error("mock: unsupported where value");
};

// the published completionReceipt schema, enforced by the mock at create time so a receipt
// the real contract would reject cannot pass the crash matrix (round-4 harness blocker).
// Kept in lockstep with registerV8.cjs and contractV9.cjs by hand (a small, rarely-changing
// set).
//
// TWO SHAPES. v8 carries nodeType, operatorFeeBps and targetDuffs at the top level; v9 pares
// all three away because the immutable pool pins them, and `additionalProperties: false`
// means a v9 contract REJECTS a receipt still carrying them. The mock has to reproduce both
// refusals, or the crash matrix would accept a receipt the real ledger would not, in
// whichever direction the run is pointed.
// the v9 POOL schema, enforced at create time on immutable-pool ledgers for the same
// reason as the receipt schema below: contractV9's pool has `additionalProperties: false`
// and REMOVES proTxHash, status and operatorIdentityId while REQUIRING targetDuffs, so a
// create still emitting the v8 shape must fail here the way the real contract would fail
// it, not pass the matrix. Since pass 18 EVERY mutable-ledger pool create is validated by
// the branch below, version-aware since the round-13 fold (status from v5, the slot book
// from v7, per the register chain); the harness still seeds most earlier-ledger pools
// directly rather than creating them.
const validatePoolProps = (p) => {
  if (!require("./envStore.cjs").hasImmutablePool()) {
    // THE MUTABLE-LEDGER (v8) POOL CREATE was previously unvalidated (pass 18, F2), so
    // validatePoolProps returned here and a v8 pool create with missing fields or a wrong
    // shape passed the matrix. The harness SEEDS v8 pools rather than creating them, so no
    // current caller exercised it, but the reference writer has a v8 create path and a
    // future test of it would have been a false green. The v8 pool (contractV8 over the
    // base poolLedger) requires proTxHash, slotIndex, nodeType and status, and carries a
    // 32-byte operatorIdentityId and a 0..10000 operatorFeeBps; additionalProperties is
    // false. The slot fields are INDEPENDENTLY OPTIONAL here (confirm-pass round 18,
    // finding 2): neither the v7 nor the v8 published pool schema carries
    // dependentRequired or lists them as required, so a one-sided book is schema-valid
    // on the mutable ledgers and this model must accept it; only the v9 contract
    // enforces both-or-neither, in the branch below.
    const bad = (why) => { throw new Error(`mock DPP: pool violates the v8 schema (${why})`); };
    const isInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
    // BYTES ONLY (closing wave, FA3): this validator runs at create time on the WRITER'S
    // raw props, before the mock serializes bytes to hex for storage, and the published
    // schema types these fields byteArray. The earlier form also accepted a 64-char hex
    // string, which the schema's byteArray type does not admit, so a string-emitting
    // writer mutation passed the matrix. The real writer builds its hash as
    // `Buffer.from(proTxHex, "hex")` (formation.cjs, the `complete` command) and the
    // crash matrix drives that writer through this validator end to end.
    const is32 = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array) && Buffer.from(v).length === 32;
    const S = require("./envStore.cjs");
    // VERSION-AWARE (confirm-pass round 13): status is a v5 addition and the slot book a
    // v7 one; the base mutable pool has neither, and additionalProperties:false on the
    // earlier contracts refuses them
    const known = new Set(["proTxHash", "slotIndex", "nodeType", "operatorIdentityId",
      "operatorFeeBps",
      ...(S.hasPoolStatus() ? ["status"] : []),
      ...(S.hasSlotBook() ? ["slotDuffs", "slotCount"] : [])]);
    for (const k of Object.keys(p)) {
      // additionalProperties:false rejects unknown CONTRACT properties; Platform's OWN
      // system fields are always allowed, but that is a KNOWN set, not any $-prefixed key
      // (pass 18 checker: a naive `$`-wildcard let an invented `$surprise` through, which
      // real Platform would reject). SYSTEM_FIELDS is the recognized set.
      if (!known.has(k) && !SYSTEM_FIELDS.has(k)) bad(`unknown property ${k} (additionalProperties:false)`);
    }
    // OWN properties only, in every validator's required loop (confirm-pass round 6, E1:
    // `p[k]` read the prototype chain, so Object.create over valid props passed all five
    // validators with zero own fields, and the create path then stored a record holding
    // only $createdAt, which real DPP refuses for missing required properties)
    for (const k of ["proTxHash", "slotIndex", "nodeType",
      ...(S.hasPoolStatus() ? ["status"] : [])]) {
      if (!Object.prototype.hasOwnProperty.call(p, k)) bad(`missing ${k}`);
    }
    if (!is32(p.proTxHash)) bad("proTxHash is not a 32-byte array (the schema forbids the string form)");
    if (!isInt(p.slotIndex, 0, 31)) bad("slotIndex out of 0..31");
    if (!["regular", "evo"].includes(p.nodeType)) bad("nodeType not in the enum");
    if (S.hasPoolStatus() && !["forming", "live"].includes(p.status)) bad("status not in the enum");
    if (Object.prototype.hasOwnProperty.call(p, "operatorIdentityId") && !is32(p.operatorIdentityId)) {
      bad("operatorIdentityId is not a 32-byte array (the schema forbids the string form)");
    }
    if (Object.prototype.hasOwnProperty.call(p, "operatorFeeBps") && !isInt(p.operatorFeeBps, 0, 10000)) bad("operatorFeeBps out of 0..10000");
    if (Object.prototype.hasOwnProperty.call(p, "slotDuffs") && !(Number.isInteger(p.slotDuffs) && p.slotDuffs >= 1)) bad("slotDuffs < 1");
    // the ceiling is LEDGER-DEPENDENT (confirm-pass round 15, minor): v7's only published
    // contract allows 10000; the 512 ceiling is the v8 SOURCE contract's documented
    // writer-side tightening and applies there alone
    const maxBook = S.hasCompletionReceipt() ? 512 : 10000;
    if (Object.prototype.hasOwnProperty.call(p, "slotCount") && !isInt(p.slotCount, 1, maxBook)) bad(`slotCount out of 1..${maxBook}`);
    return;
  }
  const bad = (why) => { throw new Error(`mock DPP: pool violates the v9 schema (${why})`); };
  const isInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
  const required = ["slotIndex", "nodeType", "operatorFeeBps", "targetDuffs"];
  const optional = ["slotDuffs", "slotCount"];
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(p, k)) bad(`missing ${k}`);
  for (const k of Object.keys(p)) {
    if (!required.includes(k) && !optional.includes(k)) bad(`unknown property ${k} (additionalProperties:false)`);
  }
  if (!isInt(p.slotIndex, 0, 31)) bad("slotIndex out of 0..31");
  if (!["regular", "evo"].includes(p.nodeType)) bad("nodeType not in the enum");
  if (!isInt(p.operatorFeeBps, 0, 10000)) bad("operatorFeeBps out of 0..10000");
  // the numeric bounds mirror contractV9 EXACTLY (vetting round, finding 4): a validator
  // narrower than the published schema can accept a fixture the contract cannot emit,
  // which is the false-green shape this whole validator exists to close
  if (!isInt(p.targetDuffs, 1, 400000000000)) bad("targetDuffs out of 1..400000000000");
  // the slot book is both-or-neither (dependentRequired in the contract)
  if (Object.prototype.hasOwnProperty.call(p, "slotDuffs") !== Object.prototype.hasOwnProperty.call(p, "slotCount")) bad("one-sided slot book (dependentRequired)");
  if (Object.prototype.hasOwnProperty.call(p, "slotDuffs") && !(Number.isInteger(p.slotDuffs) && p.slotDuffs >= 1)) {
    bad("slotDuffs is not an integer >= 1");
  }
  if (Object.prototype.hasOwnProperty.call(p, "slotCount") && !isInt(p.slotCount, 1, 512)) bad("slotCount out of 1..512");
};

// the published `share` schema (poolLedger.ts): the mock validated only pool and
// completionReceipt creates, so a writer emitting an unknown or out-of-range share
// field passed the matrix while the real contract rejects it (pass 7, major 3).
// additionalProperties:false is the part that actually bit: an extra property is
// invisible to a readback that only looks at known fields.
const validateShareProps = (p) => {
  const bad = (why) => { throw new Error(`mock DPP: share violates the schema (${why})`); };
  const isBytes = (v, lo, hi) => (Buffer.isBuffer(v) || v instanceof Uint8Array)
    && Buffer.from(v).length >= lo && Buffer.from(v).length <= hi;
  const known = ["poolId", "shareBps", "contributionDuffs", "l1RewardScript"];
  for (const k of Object.keys(p)) {
    if (!known.includes(k)) bad(`unknown property ${k} (additionalProperties:false)`);
  }
  for (const k of ["poolId", "shareBps", "contributionDuffs"]) {
    if (!Object.prototype.hasOwnProperty.call(p, k)) bad(`missing required ${k}`);
  }
  if (!isBytes(p.poolId, 32, 32)) bad("poolId is not 32 bytes");
  if (!(Number.isInteger(p.shareBps) && p.shareBps >= 1 && p.shareBps <= 10000)) {
    bad("shareBps out of 1..10000");
  }
  if (!(Number.isInteger(p.contributionDuffs) && p.contributionDuffs >= 0)) {
    bad("contributionDuffs is not an integer >= 0");
  }
  if (Object.prototype.hasOwnProperty.call(p, "l1RewardScript") && !isBytes(p.l1RewardScript, 1, 34)) {
    bad("l1RewardScript is not a 1..34 byteArray");
  }
};

const validateReceiptProps = (p) => {
  const pared = require("./envStore.cjs").hasParedReceipt();
  const shape = pared ? "v9" : "v8";
  const bad = (why) => { throw new Error(`mock DPP: completionReceipt violates the ${shape} schema (${why})`); };
  const isBytes = (v, n) => (Buffer.isBuffer(v) || v instanceof Uint8Array) && Buffer.from(v).length === n;
  const isInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
  const required = ["poolId", "proTxHash", "slotIndex", "formatVersion",
    "allocationRows", "allocationHash", "participantCount",
    "l1Verification", "verificationMethodVersion",
    ...(pared ? [] : ["nodeType", "operatorFeeBps", "targetDuffs"])];
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(p, k)) bad(`missing ${k}`);
  for (const k of Object.keys(p)) if (!required.includes(k)) bad(`unknown property ${k} (additionalProperties:false)`);
  if (!isBytes(p.poolId, 32)) bad("poolId is not 32 bytes");
  if (!isBytes(p.proTxHash, 32)) bad("proTxHash is not 32 bytes");
  if (!isBytes(p.allocationHash, 32)) bad("allocationHash is not 32 bytes");
  if (!((Buffer.isBuffer(p.allocationRows) || p.allocationRows instanceof Uint8Array)
      && Buffer.from(p.allocationRows).length >= 1 && Buffer.from(p.allocationRows).length <= 2048)) {
    bad("allocationRows is not a 1..2048 byteArray (a raw string would be caught here)");
  }
  if (!isInt(p.slotIndex, 0, 31)) bad("slotIndex out of 0..31");
  if (!pared) {
    if (!["regular", "evo"].includes(p.nodeType)) bad("nodeType not in the enum");
    if (!isInt(p.operatorFeeBps, 0, 10000)) bad("operatorFeeBps out of 0..10000");
    if (!(Number.isInteger(p.targetDuffs) && p.targetDuffs >= 1)) bad("targetDuffs is not an integer >= 1");
  }
  if (p.formatVersion !== 1) bad("formatVersion is not const 1");
  if (!isInt(p.participantCount, 1, 8)) bad("participantCount out of 1..8");
  if (!["amount-reward-verified", "node-existence-only", "demo-unverified"].includes(p.l1Verification)) bad("l1Verification not in the enum");
  if (p.verificationMethodVersion !== 1) bad("verificationMethodVersion is not const 1");
};

/**
 * THE PLEDGE SLOT WAS NOT MODELLED AT ALL (pass 12, F2), which made this mock silent about
 * the one document type a member writes. Its published schema bounds `slotNo` (0..9999 on
 * v8, tightened to 0..511 on v9 to match the slot-count ceiling), forbids extra properties,
 * and carries a UNIQUE `bySlot` index on (poolId, slotNo) that is what stops two members
 * reserving the same slot of one pool. The mock validated pool, receipt and share creates
 * and let every pledgeSlot through, so a reservation-writer regression could pass the crash
 * matrix green while real Platform refused the write. Current fixtures use distinct slots,
 * so no reported count was wrong; the gap was that nothing would have caught it.
 */
const validateSlotProps = (p) => {
  const bad = (why) => { throw new Error(`mock DPP: pledgeSlot violates the schema (${why})`); };
  const S = require("./envStore.cjs");
  const isBytes = (v, lo, hi) => (Buffer.isBuffer(v) || v instanceof Uint8Array)
    && Buffer.from(v).length >= lo && Buffer.from(v).length <= hi;
  // VERSION-AWARE (confirm-pass round 14): the v6 reservation is SIZED (slotDuffs
  // required, the slot economics live on the claim) while v7 moved the economics onto
  // the pool and pared the claim to (poolId, slotNo, rewardScript)
  const sizedClaim = S.hasPledgeSlot() && !S.hasSlotBook();
  const known = ["poolId", "slotNo", "rewardScript", ...(sizedClaim ? ["slotDuffs"] : [])];
  for (const k of Object.keys(p)) {
    if (!known.includes(k)) bad(`unknown property ${k} (additionalProperties:false)`);
  }
  for (const k of known) if (!Object.prototype.hasOwnProperty.call(p, k)) bad(`missing required ${k}`);
  if (!isBytes(p.poolId, 32, 32)) bad("poolId is not 32 bytes");
  if (sizedClaim && !(Number.isInteger(p.slotDuffs) && p.slotDuffs >= 1)) bad("slotDuffs is not a positive integer");
  // the ceiling is LEDGER-DEPENDENT and read from the same predicate the rest of the tree
  // uses, rather than hardcoded, so a mock built for one ledger cannot silently bound the
  // other: v9 tightened slotNo to 511 while v8's live schema stayed at 9999
  const maxSlot = S.hasImmutablePool() ? 511 : 9999;
  if (!(Number.isInteger(p.slotNo) && p.slotNo >= 0 && p.slotNo <= maxSlot)) {
    bad(`slotNo out of 0..${maxSlot}`);
  }
  if (!isBytes(p.rewardScript, 1, 34)) bad("rewardScript is not a 1..34 byteArray");
};

// the published votePreference schema, the LAST type to gain value validation (confirm-pass
// round 8, major: rounds 2-7 pinned it as the documented key-check-only exception, and the
// reviewer rightly held that a documented exception is not schema parity; a governance
// writer emitting a choice outside the enum or a short delegateTo passed the matrix while
// the published contract refuses both). Base shape per poolLedger.ts (poolId and
// proposalHash HASH32, the five-choice enum); delegateTo is the v8 capability addition,
// optional, HASH32.
const validateVoteProps = (p) => {
  const bad = (why) => { throw new Error(`mock DPP: votePreference violates the schema (${why})`); };
  const is32 = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array) && Buffer.from(v).length === 32;
  const known = ["poolId", "proposalHash", "choice",
    ...(require("./envStore.cjs").hasDelegateTarget() ? ["delegateTo"] : [])];
  for (const k of Object.keys(p)) {
    if (!known.includes(k) && !SYSTEM_FIELDS.has(k)) bad(`unknown property ${k} (additionalProperties:false)`);
  }
  for (const k of ["poolId", "proposalHash", "choice"]) {
    if (!Object.prototype.hasOwnProperty.call(p, k)) bad(`missing ${k}`);
  }
  if (!is32(p.poolId)) bad("poolId is not a 32-byte array");
  if (!is32(p.proposalHash)) bad("proposalHash is not a 32-byte array");
  if (!["yes", "no", "abstain", "delegate", "donothing"].includes(p.choice)) bad("choice not in the enum");
  if (Object.prototype.hasOwnProperty.call(p, "delegateTo") && !is32(p.delegateTo)) {
    bad("delegateTo is not a 32-byte array");
  }
};

// the published membershipRequest schema, enforced at create like the other four types
// (closing confirm-pass, major: create validated four types and omitted this one, and the
// replace path did only the key-allowlist check, so a writer emitting status
// "not-a-status" or a negative amountDuffs passed the matrix while the real contract
// refuses both). Base shape per poolLedger.ts (poolId HASH32, kind and status enums,
// amountDuffs a nonnegative integer, additionalProperties false), plus contractV8's two
// optional capability fields (provenance enum, rewardScript 1..34 byteArray). Writer
// values are BYTES for the byte fields, per the same rule as the pool validator.
const validateRequestProps = (p) => {
  const bad = (why) => { throw new Error(`mock DPP: membershipRequest violates the schema (${why})`); };
  const isBytes = (v, lo, hi) => (Buffer.isBuffer(v) || v instanceof Uint8Array)
    && Buffer.from(v).length >= lo && Buffer.from(v).length <= hi;
  const S = require("./envStore.cjs");
  const known = ["poolId", "kind", "amountDuffs", "status",
    ...(S.hasJoinProvenance() ? ["provenance"] : []),
    ...(S.hasMemberRewardScript() ? ["rewardScript"] : [])];
  for (const k of Object.keys(p)) {
    if (!known.includes(k) && !SYSTEM_FIELDS.has(k)) bad(`unknown property ${k} (additionalProperties:false)`);
  }
  for (const k of ["poolId", "kind", "amountDuffs", "status"]) {
    if (!Object.prototype.hasOwnProperty.call(p, k)) bad(`missing ${k}`);
  }
  if (!isBytes(p.poolId, 32, 32)) bad("poolId is not a 32-byte array");
  if (!["join", "exit"].includes(p.kind)) bad("kind not in the enum");
  if (!(Number.isInteger(p.amountDuffs) && p.amountDuffs >= 0)) bad("amountDuffs is not a nonnegative integer");
  if (!["pending", "matched", "settled"].includes(p.status)) bad("status not in the enum");
  if (Object.prototype.hasOwnProperty.call(p, "provenance") && !["fresh", "compound", "pledge"].includes(p.provenance)) {
    bad("provenance not in the enum");
  }
  if (Object.prototype.hasOwnProperty.call(p, "rewardScript") && !isBytes(p.rewardScript, 1, 34)) {
    bad("rewardScript is not a 1..34 byteArray");
  }
};

// the published rewardAccrual and settlement schemas, the two inherited types the mock
// neither value-validated nor uniqueness-checked (confirm-pass round 10, major, which
// refuted the previous round's every-unique-index claim). The v8 accrual requires
// shareBps and kind on top of the base shape; the ledger-dependent kind requirement
// mirrors the capability (v4+ carries kind in the unique key).
const validateAccrualProps = (p) => {
  // VERSION-AWARE (confirm-pass round 13, major: the validators assumed the v8 shape for
  // every ledger, refusing valid base documents and accepting later-capability fields the
  // earlier contracts' additionalProperties:false refuse). shareBps arrived with v3's
  // reconstructible accruals and kind with v4's keyed accruals, each REQUIRED from its
  // introduction, exactly as the register chain states.
  const S = require("./envStore.cjs");
  const bad = (why) => { throw new Error(`mock DPP: rewardAccrual violates the schema (${why})`); };
  const is32 = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array) && Buffer.from(v).length === 32;
  const known = ["poolId", "funderId", "amountDuffs", "epochHeight",
    ...(S.isV3() ? ["shareBps"] : []), ...(S.isV4() ? ["kind"] : [])];
  for (const k of Object.keys(p)) {
    if (!known.includes(k) && !SYSTEM_FIELDS.has(k)) bad(`unknown property ${k} (additionalProperties:false)`);
  }
  for (const k of known) {
    if (!Object.prototype.hasOwnProperty.call(p, k)) bad(`missing ${k}`);
  }
  if (!is32(p.poolId)) bad("poolId is not a 32-byte array");
  if (!is32(p.funderId)) bad("funderId is not a 32-byte array");
  if (!(Number.isInteger(p.amountDuffs) && p.amountDuffs >= 0)) bad("amountDuffs is not a nonnegative integer");
  if (!(Number.isInteger(p.epochHeight) && p.epochHeight >= 0)) bad("epochHeight is not a nonnegative integer");
  if (S.isV3() && !(Number.isInteger(p.shareBps) && p.shareBps >= 1 && p.shareBps <= 10000)) bad("shareBps out of 1..10000");
  if (S.isV4() && !["reward", "principal"].includes(p.kind)) bad("kind not in the enum");
};
const validateSettlementProps = (p) => {
  const bad = (why) => { throw new Error(`mock DPP: settlement violates the schema (${why})`); };
  const is32 = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array) && Buffer.from(v).length === 32;
  const known = ["poolId", "exitId", "joinId", "leaverId", "joinerId", "amountDuffs",
    "shareBps", "contributionDuffs", "phase"];
  for (const k of Object.keys(p)) {
    if (!known.includes(k) && !SYSTEM_FIELDS.has(k)) bad(`unknown property ${k} (additionalProperties:false)`);
  }
  for (const k of ["poolId", "exitId", "joinId", "leaverId", "joinerId", "amountDuffs", "shareBps", "phase"]) {
    if (!Object.prototype.hasOwnProperty.call(p, k)) bad(`missing ${k}`);
  }
  for (const k of ["poolId", "exitId", "joinId", "leaverId", "joinerId"]) {
    if (!is32(p[k])) bad(`${k} is not a 32-byte array`);
  }
  if (!(Number.isInteger(p.amountDuffs) && p.amountDuffs >= 1)) bad("amountDuffs is not a positive integer");
  if (!(Number.isInteger(p.shareBps) && p.shareBps >= 1 && p.shareBps <= 10000)) bad("shareBps out of 1..10000");
  if (Object.prototype.hasOwnProperty.call(p, "contributionDuffs")
      && !(Number.isInteger(p.contributionDuffs) && p.contributionDuffs >= 0)) {
    bad("contributionDuffs is not a nonnegative integer");
  }
  if (!["prepared", "matched", "share-deleted", "share-recreated", "settled"].includes(p.phase)) {
    bad("phase not in the enum");
  }
};

const wrapDoc = (rec) => {

  const pending = {}; // set() stages field changes until broadcast replace
  return {
    __rec: rec, __pending: pending,
    getId: () => idOf(rec.id),
    getOwnerId: () => idOf(rec.ownerId),
    getType: () => rec.type, // the SDK document surface the debris deleter logs by

    set: (k, v) => { pending[k] = v; },
    toObject: () => {
      const o = { $createdAt: rec.data.$createdAt || 1 };
      for (const [k, v] of Object.entries(rec.data)) {
        o[k] = (BYTE_FIELDS.has(k) && typeof v === "string") ? Buffer.from(v, "hex") : v;
      }
      return o;
    },
  };
};

// TRANSITION-level creation constraints, factored out so the sync harness can
// parity-check them the same way it checks the props validators above (the async client
// surface cannot be driven from the orchestrator). Broadcast routes every create through
// here. Two v9 rows were missing before the 2026-08-03 convergence-2 pass (major E): the
// published pool is OWNER-ONLY at creation (creationRestrictionMode 1), and the pared
// receipt is unique by (proTxHash, slotIndex) (bySlot), so two pools can never claim the
// same covenant share of one node. A mock without them accepted states the real ledger
// refuses, the false-green shape this file exists to close.
// AN OWNER-ONLY CONSTRAINT CANNOT PASS BECAUSE THE FIXTURE FORGOT THE OWNER (pass 11, F2).
// Both rows below were written `if (l.contractOwner && ...)`, so a ledger carrying
// contractId and docs but no contractOwner let a create from ANY identity through without
// throwing. The rows model creationRestrictionMode 1 as the contract builder in this
// repository sets it (contractV9.cjs for the pool, contractV8.cjs for the receipt); no
// ownerless counterpart to this fixture state is modelled there, so the vacuous branch was
// a mock admitting what those definitions do not, which is the false-green shape this file
// exists to close. Every current seed supplies the field, so nothing was failing; the point
// is that an absent constraint input is a broken fixture, never a satisfied constraint.
const assertOwnerOnly = (l, rec, docType) => {
  // "present and nonempty" is NOT the same as "an identity", and the pre-commit check on
  // the first draft of this repair made the point with a single space: `contractOwner` and
  // `ownerId` both set to " " matched each other and passed. The constraint's input has to
  // be a DECODABLE identity or the comparison establishes nothing, so it is parsed here.
  const canon = (v) => { try { return Identifier.from(v).toString(); } catch { return null; } };
  const owner = canon(l.contractOwner);
  if (owner === null) {
    throw new Error(`the mock ledger for ${l.contractId} carries no contractOwner that parses as ` +
      `an identity, so the Owner Only creation restriction on ${docType} cannot be evaluated; a ` +
      "fixture missing or malforming the constraint's own input is refused rather than treated " +
      "as satisfying it");
  }
  // BOTH SIDES are canonicalized, not just the ledger's (pre-commit re-check). Parsing one
  // side and comparing it raw against the other would refuse a record whose ownerId is an
  // Identifier object rather than a base58 string, which is a false refusal rather than a
  // false pass, but wrong either way and the kind of asymmetry that reads as correct.
  if (canon(rec.ownerId) !== owner) {
    throw new Error(`Document Creation on ${l.contractId}:${docType} is not allowed ` +
      "because of the document type's creation restriction mode Owner Only");
  }
};

const assertCreateAllowed = (l, rec) => {
  const S = require("./envStore.cjs");
  if (rec.type === "rewardAccrual" && require("./envStore.cjs").isV3()) {
    // THE UNIQUE byPoolFunder INDEX, unique only FROM v3 (confirm-pass round 14: the
    // base index is non-unique and a valid v1 duplicate was being refused): unique on
    // (poolId, funderId, epochHeight, kind), one accrual per funder per epoch per kind
    const asHex = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array)
      ? Buffer.from(v).toString("hex") : String(v).toLowerCase();
    const dup = l.docs.find((r) => r.type === "rewardAccrual"
      && asHex(r.data.poolId) === asHex(rec.data.poolId)
      && asHex(r.data.funderId) === asHex(rec.data.funderId)
      && Number(r.data.epochHeight) === Number(rec.data.epochHeight)
      && String(r.data.kind) === String(rec.data.kind));
    if (dup) throw new Error("duplicate unique index byPoolFunder for rewardAccrual");
  }
  if (rec.type === "settlement") {
    // THE UNIQUE byExit AND byJoin INDEXES (confirm-pass round 10): each exit request and
    // each join request settles at most once, each index unique on its single field.
    // byJoin only FROM v4 (confirm-pass round 17, E-1): the REGISTERED v3 contract
    // predates the byJoin index (its source gained it after publish, and republishing
    // would have orphaned the ledger; registerV4.cjs is the first publish carrying it),
    // so on v3 the published schema ACCEPTS a second settlement against the same join
    // and this model must too. byExit is in the v3 publish and applies wherever the
    // type exists at all.
    const asHex = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array)
      ? Buffer.from(v).toString("hex") : String(v).toLowerCase();
    for (const [field, name] of [["exitId", "byExit"],
      ...(S.isV4() ? [["joinId", "byJoin"]] : [])]) {
      const dup = l.docs.find((r) => r.type === "settlement"
        && asHex(r.data[field]) === asHex(rec.data[field]));
      if (dup) throw new Error(`duplicate unique index ${name} for settlement`);
    }
  }
  if (rec.type === "votePreference") {
    // THE UNIQUE byPoolOwnerProposal INDEX at create (confirm-pass round 9, E-1): the
    // published schema is unique on (poolId, $ownerId, proposalHash), so one owner holds
    // one preference per pool and proposal; the second create is refused, the same
    // duplicate-refusal surface the pool, receipt and slot branches model.
    const asHex = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array)
      ? Buffer.from(v).toString("hex") : String(v).toLowerCase();
    const dup = l.docs.find((r) => r.type === "votePreference"
      && r.ownerId === rec.ownerId
      && asHex(r.data.poolId) === asHex(rec.data.poolId)
      && asHex(r.data.proposalHash) === asHex(rec.data.proposalHash));
    if (dup) throw new Error("duplicate unique index byPoolOwnerProposal for votePreference");
  }
  if (rec.type === "pool") {
    if (S.hasImmutablePool()) assertOwnerOnly(l, rec, "pool");
    // THE UNIQUE byProTxHash INDEX applies at CREATE too, not only at the flip replace
    // (pass 18, F2; pass 17 closed the replace side). Two pools cannot be created with the
    // same proTxHash on any ledger that carries the field. asHex handles the hex/Buffer
    // spread as the other unique checks do. A pool with no proTxHash (a pared v9 create)
    // has nothing to collide on and is skipped.
    if (rec.data.proTxHash !== undefined) {
      const asHex = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array)
        ? Buffer.from(v).toString("hex") : String(v).toLowerCase();
      const want = asHex(rec.data.proTxHash);
      const dup = l.docs.find((r) => r.type === "pool" && r.data.proTxHash !== undefined
        && asHex(r.data.proTxHash) === want);
      if (dup) throw new Error("duplicate unique index byProTxHash for pool");
    }
  }
  if (rec.type === "completionReceipt") {
    assertOwnerOnly(l, rec, "completionReceipt");
    const poolIdStr = Identifier.from(Buffer.from(rec.data.poolId, "hex")).toString();
    const dup = l.docs.find((r) => r.type === "completionReceipt" &&
      Identifier.from(Buffer.from(r.data.poolId, "hex")).toString() === poolIdStr);
    if (dup) throw new Error("duplicate unique index byPool for completionReceipt");
    if (S.hasParedReceipt()) {
      // ledger data is hex-string by construction (create hex-encodes byte fields, the
      // JSON file persists strings), but that guarantee lives in ANOTHER function, so
      // the comparison normalizes rather than assuming it: a Buffer handed in by a
      // future caller must still compare by VALUE, never by object identity
      // (pre-commit artifact check, 2026-08-03)
      // strings are LOWERCASED, not passed through: hex is case-insensitive as an encoding,
      // so "AB" and "ab" name the same bytes, and a pass-through canonicalizer let a direct
      // caller slip a duplicate past the unique index by changing case (pre-commit item c;
      // the same shape existed at BOTH asHex sites, this one included, found by the sweep)
      const asHex = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array)
        ? Buffer.from(v).toString("hex") : String(v).toLowerCase();
      const dupSlot = l.docs.find((r) => r.type === "completionReceipt" &&
        asHex(r.data.proTxHash) === asHex(rec.data.proTxHash) &&
        Number(r.data.slotIndex) === Number(rec.data.slotIndex));
      if (dupSlot) throw new Error("duplicate unique index bySlot for completionReceipt");
    }
  }
  if (rec.type === "share") {
    const dup = l.docs.find((r) => r.type === "share" && r.ownerId === rec.ownerId &&
      r.data.poolId === rec.data.poolId);
    if (dup) throw new Error("duplicate unique index byPoolOwner for share");
  }
  if (rec.type === "pledgeSlot") {
    // the UNIQUE bySlot index on (poolId, slotNo), which is what stops two members
    // reserving one slot of a pool. Owner-independent by construction: the index names
    // neither $ownerId nor anything derived from it, so a SECOND member colliding on the
    // same slot is exactly the case that must be refused (pass 12, F2).
    // strings are LOWERCASED, same reason and same sweep as the receipt site above
    const asHex = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array)
      ? Buffer.from(v).toString("hex") : String(v).toLowerCase();
    const dup = l.docs.find((r) => r.type === "pledgeSlot" &&
      asHex(r.data.poolId) === asHex(rec.data.poolId) &&
      Number(r.data.slotNo) === Number(rec.data.slotNo));
    if (dup) throw new Error("duplicate unique index bySlot for pledgeSlot");
  }
};

// REPLACE and DELETE transition rules (final pass, major 4), the same exported-pure
// pattern as assertCreateAllowed: completion receipts are immutable and non-deletable
// at consensus on EVERY ledger that has the type (documentsMutable: false,
// canBeDeleted: false since v8), and the immutable pool refuses both. Broadcast routes
// every replace and delete through here; the harness parity-tests it directly.
const assertMutationAllowed = (kind, rec) => {
  const S = require("./envStore.cjs");
  if (rec.type === "completionReceipt") {
    if (kind === "replace") {
      throw new Error("Document replace on completionReceipt is not allowed because " +
        "the document type is not mutable");
    }
    if (kind === "delete") {
      throw new Error("Document delete on completionReceipt is not allowed because " +
        "the document type cannot be deleted");
    }
  }
  if (rec.type === "pledgeSlot" && S.hasPledgeSlot() && !S.hasSlotBook()) {
    // the v6 reservation is immutable, which on this SDK also means UNDELETABLE (its own
    // schema comment; cancel.cjs documents v6 claims as permanent). Confirm-pass round 14:
    // the mock permitted both transitions the real contract cannot build.
    if (kind === "replace") {
      throw new Error("Document replace on pledgeSlot is not allowed because " +
        "the document type is not mutable");
    }
    if (kind === "delete") {
      throw new Error("Document delete on pledgeSlot is not allowed because " +
        "the document type cannot be deleted");
    }
  }
  if (rec.type === "pool" && S.hasImmutablePool()) {
    if (kind === "replace") {
      throw new Error("Document replace on pool is not allowed because " +
        "the document type is not mutable");
    }
    if (kind === "delete") {
      throw new Error("Document delete on pool is not allowed because " +
        "the document type cannot be deleted");
    }
  }
};

// per-type property whitelists for the REPLACE path (pass 7, major 3). A pending key
// outside its type's published property set is what `additionalProperties: false`
// refuses, and it is invisible to a readback that reads only known fields.
// COVERAGE, stated exactly (artifact check): key checking applies to THE TYPES LISTED
// BELOW and to no others; a replace of an unlisted type passes unchecked, exactly as it
// did before. The list is the set this harness and the client actually replace.
const REPLACE_KEYS = {
  share: ["shareBps", "contributionDuffs", "l1RewardScript"],
  // settlement's one real transition is the matcher walking `phase` (matcher.cjs); the
  // rest of its fields are creation-time facts. rewardAccrual is listed with NO keys on
  // purpose: neither the harness nor the client ever replaces an accrual, so every
  // pending key is refused, which is deliberately NARROWER than the published mutable
  // schema and stated as such (the same writer-side scope as the mock's slotCount
  // ceiling); a writer suddenly replacing accruals is a regression this exists to catch.
  settlement: ["phase"],
  rewardAccrual: [],
  pool: ["status", "proTxHash", "operatorIdentityId", "slotDuffs", "slotCount"],
  membershipRequest: ["status", "provenance", "rewardScript", "amountDuffs"],
  pledgeSlot: ["slotNo", "rewardScript"],
  votePreference: ["choice", "delegateTo"],
};
// WHICH LISTED REPLACE KEYS EXIST ON THE SELECTED LEDGER (confirm-pass round 14): the
// static map is the v8/v9 superset, and a field a later version introduced must not be
// replaceable-in before its ledger defines it (additionalProperties:false refuses the
// transition on the earlier contracts). Fields without a gate are base fields.
const REPLACE_KEY_GATES = {
  pool: { status: "hasPoolStatus", slotDuffs: "hasSlotBook", slotCount: "hasSlotBook" },
  membershipRequest: { provenance: "hasJoinProvenance", rewardScript: "hasMemberRewardScript" },
  votePreference: { delegateTo: "hasDelegateTarget" },
};
const assertReplaceAllowed = (rec, pending) => {
  const S = require("./envStore.cjs");
  const gates = REPLACE_KEY_GATES[rec.type] || {};
  const allowed = REPLACE_KEYS[rec.type]
    && REPLACE_KEYS[rec.type].filter((k) => !gates[k] || S[gates[k]]());
  if (!allowed) return; // an UNLISTED type is unchecked here, by the stated coverage above
  for (const k of Object.keys(pending || {})) {
    if (!allowed.includes(k)) {
      throw new Error(`mock DPP: ${rec.type} replace sets unknown property ${k} ` +
        "(additionalProperties:false)");
    }
  }
  if (rec.type === "share") {
    // the merged document must satisfy the share schema, so a replace cannot walk a
    // field out of range that the create validator refused
    const merged = { poolId: Buffer.from(rec.data.poolId, "hex"),
      shareBps: rec.data.shareBps, contributionDuffs: rec.data.contributionDuffs,
      ...(rec.data.l1RewardScript !== undefined
        ? { l1RewardScript: Buffer.from(rec.data.l1RewardScript, "hex") } : {}),
      ...pending };
    validateShareProps(merged);
  }
  if (rec.type === "pool") {
    // THE MERGED POOL must satisfy the replaceable fields' schema bounds too (pass 16,
    // F2). The pass-7 disposition said the flip fields were pinned by the flip
    // invariants, which covered status and proTxHash and nothing else, so a replace
    // walking slotCount to 0, a value the published schema refuses (minimum 1), passed
    // the matrix while real Platform would reject the transition. Bounds mirror
    // contractV8's pool SOURCE: status enum, 32-byte proTxHash, slotDuffs >= 1, slotCount
    // 1..512. The slot fields are INDEPENDENTLY OPTIONAL on the mutable ledgers (round
    // 18, finding 2: no published pre-v9 pool schema carries dependentRequired), so the
    // one-sided check below fires only under the immutable-pool capability.
    // STATED SCOPE (closing confirm-pass, note): the
    // 512 slotCount ceiling is the SOURCE contract's tightened bound; the LIVE on-chain
    // v8 is immutable and retains its published 10000 ceiling with the client enforcing
    // the tighter value (contractV8.cjs header), so this mock models the current source
    // contract, not the live one, and a live transition at 513..10000 that the mock
    // refuses is schema-valid on chain while the reference writer never emits it.
    const merged = { ...rec.data, ...pending };
    const bad = (why) => { throw new Error(`mock DPP: pool replace violates the schema (${why})`); };
    if (merged.status !== undefined && !["forming", "live"].includes(merged.status)) {
      bad(`status "${String(merged.status)}" not in the enum`);
    }
    // proTxHash AND operatorIdentityId are both 32-byte identity fields (pass 17, F2:
    // operatorIdentityId was in the replace allowlist but unchecked, so a one-byte value
    // was accepted while the published schema requires HASH32).
    // TWO FORMS, DELIBERATELY DISTINGUISHED (closing wave, FA3): a PENDING value comes
    // from the WRITER and the schema types it byteArray, so it must be bytes, exactly as
    // real Platform demands (the earlier form hex-decoded any string, so a string-emitting
    // writer mutation passed while Platform would reject it). A STORED value in rec.data
    // is the mock's own serialized form (bytes become hex at create), so the merged record
    // legitimately carries 64-hex there, and that form is still bounds-checked so a
    // seeded-malformed record cannot ride through a replace unnoticed.
    // STRICT on both stored spellings (checker on this fold): node's hex decode is
    // LENIENT and stops at the first invalid character, so Buffer.from("<64 hex>zz",
    // "hex") is 32 bytes and a hex-PREFIXED garbage stored value rode through the
    // earlier decode-then-measure form. The stored form is exactly 64 hex characters
    // (the mock's own serialization) or 32 bytes; anything else, including a non-string
    // object, is malformed.
    const asStored32 = (v) => {
      if (Buffer.isBuffer(v) || v instanceof Uint8Array) {
        return Buffer.from(v).length === 32 ? Buffer.from(v) : null;
      }
      if (typeof v === "string" && /^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, "hex");
      return null;
    };
    for (const k of ["proTxHash", "operatorIdentityId"]) {
      if (pending[k] !== undefined) {
        if (!((Buffer.isBuffer(pending[k]) || pending[k] instanceof Uint8Array)
            && Buffer.from(pending[k]).length === 32)) {
          bad(`${k} is not a 32-byte array (writer values must be bytes; the schema forbids the string form)`);
        }
      } else if (merged[k] !== undefined && !asStored32(merged[k])) {
        bad(`${k} is not 32 bytes`);
      }
    }
    const hasD = merged.slotDuffs !== undefined, hasC = merged.slotCount !== undefined;
    // one-sided is contract-enforced ONLY where dependentRequired exists (confirm-pass
    // round 18, finding 2): the v9 pool schema carries it, while the published v7 and
    // v8 schemas leave the two fields independently optional, so a replace whose merged
    // result is one-sided is schema-valid there and this model must accept it. On v9 a
    // pool replace is refused upstream (the immutable pool takes no replace at all), so
    // the gated branch here is defense-in-depth behind that refusal, not a reachable
    // duty of its own.
    if (require("./envStore.cjs").hasImmutablePool() && hasD !== hasC) bad("one-sided slot book (dependentRequired)");
    if (hasD && !(Number.isInteger(merged.slotDuffs) && merged.slotDuffs >= 1)) bad("slotDuffs < 1");
    const maxBookR = require("./envStore.cjs").hasCompletionReceipt() ? 512 : 10000;
    if (hasC && !(Number.isInteger(merged.slotCount) && merged.slotCount >= 1 && merged.slotCount <= maxBookR)) {
      bad(`slotCount out of 1..${maxBookR}`);
    }
  }
  if (rec.type === "pledgeSlot") {
    // the MERGED CLAIM must satisfy the slot schema's value bounds (closing confirm-pass
    // round 3, major: replacement listed slotNo and rewardScript but validated neither,
    // so a replace walking slotNo past the ledger ceiling or emptying the reward script
    // persisted while the published contract refuses both). The ceiling is the same
    // ledger-dependent read the create validator uses.
    const merged = { ...rec.data, ...pending };
    const bad = (why) => { throw new Error(`mock DPP: pledgeSlot replace violates the schema (${why})`); };
    const maxSlot = require("./envStore.cjs").hasImmutablePool() ? 511 : 9999;
    if (merged.slotNo !== undefined
        && !(Number.isInteger(merged.slotNo) && merged.slotNo >= 0 && merged.slotNo <= maxSlot)) {
      bad(`slotNo out of 0..${maxSlot}`);
    }
    if (pending.rewardScript !== undefined) {
      if (!((Buffer.isBuffer(pending.rewardScript) || pending.rewardScript instanceof Uint8Array)
          && Buffer.from(pending.rewardScript).length >= 1 && Buffer.from(pending.rewardScript).length <= 34)) {
        bad("rewardScript is not a 1..34 byteArray (writer values must be bytes)");
      }
    } else if (merged.rewardScript !== undefined
        && !(typeof merged.rewardScript === "string" && /^([0-9a-fA-F]{2}){1,34}$/.test(merged.rewardScript))) {
      bad("rewardScript is not 1..34 bytes");
    }
  }
  if (rec.type === "votePreference") {
    // merged VALUE bounds for the vote too (confirm-pass round 8): the same two-form rule,
    // pending byte fields from the writer as bytes, stored ones as the mock's hex
    const merged = { ...rec.data, ...pending };
    const bad = (why) => { throw new Error(`mock DPP: votePreference replace violates the schema (${why})`); };
    if (merged.choice !== undefined
        && !["yes", "no", "abstain", "delegate", "donothing"].includes(merged.choice)) {
      bad(`choice "${String(merged.choice)}" not in the enum`);
    }
    if (pending.delegateTo !== undefined) {
      if (!((Buffer.isBuffer(pending.delegateTo) || pending.delegateTo instanceof Uint8Array)
          && Buffer.from(pending.delegateTo).length === 32)) {
        bad("delegateTo is not a 32-byte array (writer values must be bytes)");
      }
    } else if (merged.delegateTo !== undefined
        && !(typeof merged.delegateTo === "string" && /^[0-9a-fA-F]{64}$/.test(merged.delegateTo))) {
      bad("delegateTo is not 32 bytes");
    }
  }
  if (rec.type === "settlement") {
    // merged VALUE bounds for the settlement's one replaceable field (confirm-pass round
    // 11, major: the type was absent from REPLACE_KEYS entirely, so the matcher's real
    // phase transition went unvalidated and a phase outside the published enum persisted)
    const merged = { ...rec.data, ...pending };
    const bad = (why) => { throw new Error(`mock DPP: settlement replace violates the schema (${why})`); };
    if (merged.phase !== undefined
        && !["prepared", "matched", "share-deleted", "share-recreated", "settled"].includes(merged.phase)) {
      bad(`phase "${String(merged.phase)}" not in the enum`);
    }
  }
  if (rec.type === "membershipRequest") {
    // the MERGED REQUEST must satisfy the schema's value bounds too (closing
    // confirm-pass, major: the key allowlist alone let a replace walk status to a value
    // outside the enum, which the published contract refuses). Same two-form rule as the
    // pool branch: a PENDING byte field comes from the writer as bytes; a STORED one is
    // the mock's own hex serialization.
    const merged = { ...rec.data, ...pending };
    const bad = (why) => { throw new Error(`mock DPP: membershipRequest replace violates the schema (${why})`); };
    if (merged.status !== undefined && !["pending", "matched", "settled"].includes(merged.status)) {
      bad(`status "${String(merged.status)}" not in the enum`);
    }
    if (merged.amountDuffs !== undefined
        && !(Number.isInteger(merged.amountDuffs) && merged.amountDuffs >= 0)) {
      bad("amountDuffs is not a nonnegative integer");
    }
    if (merged.provenance !== undefined && !["fresh", "compound", "pledge"].includes(merged.provenance)) {
      bad(`provenance "${String(merged.provenance)}" not in the enum`);
    }
    if (pending.rewardScript !== undefined) {
      if (!((Buffer.isBuffer(pending.rewardScript) || pending.rewardScript instanceof Uint8Array)
          && Buffer.from(pending.rewardScript).length >= 1 && Buffer.from(pending.rewardScript).length <= 34)) {
        bad("rewardScript is not a 1..34 byteArray (writer values must be bytes)");
      }
    } else if (merged.rewardScript !== undefined
        && !(typeof merged.rewardScript === "string" && /^([0-9a-fA-F]{2}){1,34}$/.test(merged.rewardScript))) {
      bad("rewardScript is not 1..34 bytes");
    }
  }
};

// SIGNER-TO-OWNER AUTHORIZATION (pass-7 wave, packet-review major 4): real Platform binds
// every document transition to the identity that signs the state transition, so a
// create must set the owner it signs as, and a replace or delete must be signed by the
// existing document's owner. The mock previously accepted any identity for any
// transition, a parity gap in the PERMISSIVE direction: current command paths sign
// correctly, but a wrong-signer regression would have passed the matrix while the real
// ledger refuses it. Exported pure, parity-tested by the harness, wired into broadcast
// for all three transition kinds.
const assertAuthorized = (kind, rec, signerId) => {
  if (typeof signerId !== "string" || signerId.length === 0) {
    throw new Error(`mock: a ${kind} transition carries no signing identity`);
  }
  if (rec.ownerId !== signerId) {
    throw new Error(`mock DPP: ${kind} on a document owned by ${rec.ownerId} signed by ` +
      `identity ${signerId} is not allowed (the signer must be the document owner)`);
  }
};

const matches = (rec, where = []) => {
  for (const [field, op, value] of where) {
    if (op !== "==") throw new Error(`mock: unsupported op ${op}`);
    let actual;
    if (field === "$id") actual = rec.id;
    else if (field === "$ownerId") actual = rec.ownerId;
    else {
      const raw = rec.data[field];
      if (raw === undefined) return false;
      actual = BYTE_FIELDS.has(field) ? Identifier.from(Buffer.from(raw, "hex")).toString() : raw;
    }
    const want = (field === "$id" || field === "$ownerId" || BYTE_FIELDS.has(field))
      ? asIdString(value) : value;
    if (actual !== want) return false;
  }
  return true;
};

class Client {
  constructor(opts) {
    this.__opts = opts;
    this.platform = {
      identities: {
        get: async (id) => { tick(); return { getId: () => idOf(id) }; },
      },
      contracts: {
        // the a soundness-review finding contract-owner guard reads the contract's owner; the seed carries it
        get: async (_id) => { tick(); const l = loadLedger(); return { getOwnerId: () => idOf(l.contractOwner) }; },
      },
      documents: {
        get: async (type, query = {}) => {
          tick();
          requireLedgerType(type);
          const short = type.replace(/^poolLedger\./, "");
          const l = loadLedger();
          let rows = l.docs.filter((r) => r.type === short && matches(r, query.where));
          rows.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
          if (query.startAfter) {
            const after = asIdString(query.startAfter);
            rows = rows.filter((r) => r.id > after);
          }
          // model Platform's hard 100-document page cap even when no limit is passed, so an
          // UNPAGINATED caller (a bare documents.get without fetchAll) cannot silently read a
          // whole large book in the harness while real Platform would truncate it (round-6)
          const PLATFORM_PAGE_CAP = 100;
          const cap = query.limit ? Math.min(query.limit, PLATFORM_PAGE_CAP) : PLATFORM_PAGE_CAP;
          rows = rows.slice(0, cap);
          return rows.map(wrapDoc);
        },
        create: async (type, identity, props) => {
          // model the SDK's real create(): it awaits SDK init and the contract fetch, so
          // it is a genuine fault boundary (round-4 harness finding: the mock's create
          // had no tick, so a crash between create and broadcast was never enumerated)
          tick();
          requireLedgerType(type);
          const short = type.replace(/^poolLedger\./, "");
          // STRICT schema validation for completionReceipt, reproducing the published v8
          // contract (round-4 harness blocker: the mock accepted anything, so a wrong
          // type/length/enum/range or a raw-string byteArray passed the matrix while real
          // Platform would reject it). A create that violates the schema throws here, the
          // same failure surface a real rejection presents.
          if (short === "completionReceipt") validateReceiptProps(props);
          if (short === "pool") validatePoolProps(props);
          if (short === "share") validateShareProps(props);
          if (short === "pledgeSlot") validateSlotProps(props);
          if (short === "membershipRequest") validateRequestProps(props);
          if (short === "votePreference") validateVoteProps(props);
          if (short === "rewardAccrual") validateAccrualProps(props);
          if (short === "settlement") validateSettlementProps(props);
          const data = { $createdAt: Date.now() };
          for (const [k, v] of Object.entries(props)) {
            data[k] = (Buffer.isBuffer(v) || v instanceof Uint8Array)
              ? Buffer.from(v).toString("hex") : v;
          }
          const rec = { id: Identifier.from(crypto.randomBytes(32)).toString(),
            type: short, ownerId: identity.getId().toString(), data, __new: true };
          return wrapDoc(rec);
        },
        broadcast: async (batch, identity) => {
          const l = loadLedger();
          for (const doc of batch.create || []) {
            const rec = doc.__rec;
            // every create routes through the one exported constraint check (parity-tested
            // by the harness); a refusal is a real Platform round-trip, so it still ticks
            try { assertAuthorized("create", rec, identity.getId().toString()); } catch (e) { tick(); throw e; }
            try { assertCreateAllowed(l, rec); } catch (e) { tick(); throw e; }
            delete rec.__new;
            l.docs.push(rec);
          }
          for (const doc of batch.replace || []) {
            const rec = l.docs.find((r) => r.id === doc.__rec.id);
            if (!rec) { tick(); throw new Error(`mock: replace of unknown doc ${doc.__rec.id}`); }
            // every replace routes through the one exported transition check
            // (parity-tested by the harness); a refusal is a real round-trip, so it ticks
            try { assertAuthorized("replace", rec, identity.getId().toString()); } catch (e) { tick(); throw e; }
            try { assertMutationAllowed("replace", rec); } catch (e) { tick(); throw e; }
            // REPLACE is a schema-validated transition too (pass 7, major 3): the mock
            // previously applied pending fields blind, so a replace introducing an
            // unknown or out-of-range field passed while the contract rejects it.
            // SCOPE, stated exactly: the pending KEYS are checked for the types LISTED
            // in REPLACE_KEYS and for no others (an unlisted type passes unchecked,
            // as before), and full merged-VALUE validation runs for EVERY listed type
            // (votePreference was the last to gain it, confirm-pass round 8).
            // The v8 pool flip is ALSO covered here: pool is a listed type, so its
            // merged values are validated in assertReplaceAllowed (a slotCount walked
            // to 0 is refused there), in ADDITION to the flip invariants'
            // field-by-field comparisons (round 21 corrected this comment, which said
            // the flip was pinned by the invariants rather than here).
            try { assertReplaceAllowed(rec, doc.__pending); } catch (e) { tick(); throw e; }
            // THE UNIQUE byProTxHash INDEX applies to a pool flip too (pass 17, F2): the
            // published v8 pool is unique on proTxHash, so two pools cannot flip to the
            // same masternode hash, and the pure replace check could not see it (it has no
            // ledger). Enforced here, where the other pools are visible, on the value the
            // replace would WRITE. asHex handles the hex/Buffer spread the same way the
            // create-side unique checks do.
            if (rec.type === "pool" && doc.__pending.proTxHash !== undefined) {
              const asHex = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array)
                ? Buffer.from(v).toString("hex") : String(v).toLowerCase();
              const want = asHex(doc.__pending.proTxHash);
              const clash = l.docs.find((r) => r.type === "pool" && r.id !== rec.id
                && r.data.proTxHash !== undefined && asHex(r.data.proTxHash) === want);
              if (clash) { tick(); throw new Error("duplicate unique index byProTxHash for pool"); }
            }
            // THE UNIQUE bySlot INDEX applies to a claim's slotNo replace too
            // (confirm-pass round 24, major, the pass-17 byProTxHash rule's sibling):
            // the published pledgeSlot is unique on (poolId, slotNo), so a replace
            // moving a claim onto an occupied slot of the same pool is refused by the
            // contract, and the pure replace check cannot see it (it has no ledger).
            // Enforced here on the value the replace would WRITE.
            if (rec.type === "pledgeSlot" && doc.__pending.slotNo !== undefined) {
              const asHex = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array)
                ? Buffer.from(v).toString("hex") : String(v).toLowerCase();
              const clash = l.docs.find((r) => r.type === "pledgeSlot" && r.id !== rec.id
                && asHex(r.data.poolId) === asHex(rec.data.poolId)
                && Number(r.data.slotNo) === Number(doc.__pending.slotNo));
              if (clash) { tick(); throw new Error("duplicate unique index bySlot for pledgeSlot"); }
            }
            for (const [k, v] of Object.entries(doc.__pending)) {
              rec.data[k] = (Buffer.isBuffer(v) || v instanceof Uint8Array)
                ? Buffer.from(v).toString("hex") : v;
            }
          }
          for (const doc of batch.delete || []) {
            const rec = l.docs.find((r) => r.id === doc.__rec.id);
            if (!rec) { tick(); throw new Error(`mock: delete of unknown doc ${doc.__rec.id}`); }
            try { assertAuthorized("delete", rec, identity.getId().toString()); } catch (e) { tick(); throw e; }
            try { assertMutationAllowed("delete", rec); } catch (e) { tick(); throw e; }
            l.docs = l.docs.filter((r) => r.id !== rec.id);
          }
          if ((batch.create || []).length + (batch.replace || []).length + (batch.delete || []).length > 1) {
            // mirror the live Platform limit discovered by the mixed-transition probe
            tick();
            throw new Error("Amount of document transitions must be less or equal to 1");
          }
          saveLedger(l);
          tick();
          return {};
        },
      },
    };
  }
  async getWalletAccount() {
    return {
      getUTXOS: () => [],
      getAddress: (i) => ({ address: `yMockDerived${i}` }),
    };
  }
  async disconnect() {}
}

module.exports = { Client, validateReceiptProps, validatePoolProps, validateShareProps, validateSlotProps, validateRequestProps, validateVoteProps, validateAccrualProps, validateSettlementProps, assertAuthorized,
  assertCreateAllowed, assertMutationAllowed, assertReplaceAllowed, REPLACE_KEYS, Core: new Proxy({}, { get() {
  throw new Error("mock: Dash.Core was touched; the harness scenarios must supply member reward scripts");
} }) };
