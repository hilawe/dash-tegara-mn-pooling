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
// it, not pass the matrix. The v1-v8 pool create stays unvalidated as before (the harness
// seeds those pools directly rather than creating them), so this validator only ever
// tightens.
const validatePoolProps = (p) => {
  if (!require("./envStore.cjs").hasImmutablePool()) return;
  const bad = (why) => { throw new Error(`mock DPP: pool violates the v9 schema (${why})`); };
  const isInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
  const required = ["slotIndex", "nodeType", "operatorFeeBps", "targetDuffs"];
  const optional = ["slotDuffs", "slotCount"];
  for (const k of required) if (p[k] === undefined) bad(`missing ${k}`);
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
  if ((p.slotDuffs === undefined) !== (p.slotCount === undefined)) bad("one-sided slot book (dependentRequired)");
  if (p.slotDuffs !== undefined && !(Number.isInteger(p.slotDuffs) && p.slotDuffs >= 1)) {
    bad("slotDuffs is not an integer >= 1");
  }
  if (p.slotCount !== undefined && !isInt(p.slotCount, 1, 512)) bad("slotCount out of 1..512");
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
    if (p[k] === undefined) bad(`missing required ${k}`);
  }
  if (!isBytes(p.poolId, 32, 32)) bad("poolId is not 32 bytes");
  if (!(Number.isInteger(p.shareBps) && p.shareBps >= 1 && p.shareBps <= 10000)) {
    bad("shareBps out of 1..10000");
  }
  if (!(Number.isInteger(p.contributionDuffs) && p.contributionDuffs >= 0)) {
    bad("contributionDuffs is not an integer >= 0");
  }
  if (p.l1RewardScript !== undefined && !isBytes(p.l1RewardScript, 1, 34)) {
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
  for (const k of required) if (p[k] === undefined) bad(`missing ${k}`);
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

const wrapDoc = (rec) => {
  const pending = {}; // set() stages field changes until broadcast replace
  return {
    __rec: rec, __pending: pending,
    getId: () => idOf(rec.id),
    getOwnerId: () => idOf(rec.ownerId),
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
const assertCreateAllowed = (l, rec) => {
  const S = require("./envStore.cjs");
  if (rec.type === "pool" && S.hasImmutablePool()) {
    if (l.contractOwner && rec.ownerId !== l.contractOwner) {
      throw new Error(`Document Creation on ${l.contractId}:pool is not allowed ` +
        "because of the document type's creation restriction mode Owner Only");
    }
  }
  if (rec.type === "completionReceipt") {
    if (l.contractOwner && rec.ownerId !== l.contractOwner) {
      throw new Error(`Document Creation on ${l.contractId}:completionReceipt is not allowed ` +
        "because of the document type's creation restriction mode Owner Only");
    }
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
      const asHex = (v) => (Buffer.isBuffer(v) || v instanceof Uint8Array)
        ? Buffer.from(v).toString("hex") : v;
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
  pool: ["status", "proTxHash", "operatorIdentityId", "slotDuffs", "slotCount"],
  membershipRequest: ["status", "provenance", "rewardScript", "amountDuffs"],
  pledgeSlot: ["slotNo", "rewardScript"],
  votePreference: ["choice", "delegateTo"],
};
const assertReplaceAllowed = (rec, pending) => {
  const allowed = REPLACE_KEYS[rec.type];
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
};

// SIGNER-TO-OWNER AUTHORIZATION (pass-7 wave, codexapp major 4): real Platform binds
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
          const short = type.replace(/^poolLedger\./, "");
          // STRICT schema validation for completionReceipt, reproducing the published v8
          // contract (round-4 harness blocker: the mock accepted anything, so a wrong
          // type/length/enum/range or a raw-string byteArray passed the matrix while real
          // Platform would reject it). A create that violates the schema throws here, the
          // same failure surface a real rejection presents.
          if (short === "completionReceipt") validateReceiptProps(props);
          if (short === "pool") validatePoolProps(props);
          if (short === "share") validateShareProps(props);
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
            // as before), and full value validation runs for `share`, the one mutable
            // type this harness replaces. The v8 pool flip is the other replace, and
            // its fields are pinned by the flip invariants and their field-by-field
            // comparisons rather than here.
            try { assertReplaceAllowed(rec, doc.__pending); } catch (e) { tick(); throw e; }
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

module.exports = { Client, validateReceiptProps, validatePoolProps, validateShareProps, assertAuthorized,
  assertCreateAllowed, assertMutationAllowed, assertReplaceAllowed, REPLACE_KEYS, Core: new Proxy({}, { get() {
  throw new Error("mock: Dash.Core was touched; the harness scenarios must supply member reward scripts");
} }) };
