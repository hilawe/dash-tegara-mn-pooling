/**
 * The mock `dash` module for the formation crash harness (formationCrashTest.cjs): an
 * in-memory Platform ledger persisted to a JSON file, so a hard-exit "crash" leaves
 * exactly the state a real crash would and the orchestrator inspects it from outside.
 *
 * FAULT MODEL (the same "op persisted, then the process died" model as the envStore
 * crash matrix, but the boundaries here are the RECEIPT FLOW's awaits and local-state
 * writes): every platform call ticks the shared fault counter in global.__TEGARA_FAULT
 * (the child runner also ticks it from envStore.updateEnvKey), and when the counter
 * passes the armed threshold the process HARD-EXITS with code 97, bypassing every
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

// the published v8 completionReceipt schema, enforced by the mock at create time so a
// receipt the real contract would reject cannot pass the crash matrix (round-4 harness
// blocker). Kept in lockstep with registerV8.cjs by hand (a small, rarely-changing set).
const validateReceiptProps = (p) => {
  const bad = (why) => { throw new Error(`mock DPP: completionReceipt violates the v8 schema (${why})`); };
  const isBytes = (v, n) => (Buffer.isBuffer(v) || v instanceof Uint8Array) && Buffer.from(v).length === n;
  const isInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
  const required = ["poolId", "proTxHash", "slotIndex", "nodeType", "operatorFeeBps", "formatVersion",
    "allocationRows", "allocationHash", "participantCount", "targetDuffs",
    "l1Verification", "verificationMethodVersion"];
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
  if (!["regular", "evo"].includes(p.nodeType)) bad("nodeType not in the enum");
  if (!isInt(p.operatorFeeBps, 0, 10000)) bad("operatorFeeBps out of 0..10000");
  if (p.formatVersion !== 1) bad("formatVersion is not const 1");
  if (!isInt(p.participantCount, 1, 8)) bad("participantCount out of 1..8");
  if (!(Number.isInteger(p.targetDuffs) && p.targetDuffs >= 1)) bad("targetDuffs is not an integer >= 1");
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
          const contractOwner = l.contractOwner;
          for (const doc of batch.create || []) {
            const rec = doc.__rec;
            if (rec.type === "completionReceipt") {
              if (contractOwner && rec.ownerId !== contractOwner) {
                tick();
                throw new Error(`Document Creation on ${l.contractId}:completionReceipt is not allowed ` +
                  "because of the document type's creation restriction mode Owner Only");
              }
              const poolIdStr = Identifier.from(Buffer.from(rec.data.poolId, "hex")).toString();
              const dup = l.docs.find((r) => r.type === "completionReceipt" &&
                Identifier.from(Buffer.from(r.data.poolId, "hex")).toString() === poolIdStr);
              if (dup) { tick(); throw new Error("duplicate unique index byPool for completionReceipt"); }
            }
            if (rec.type === "share") {
              const dup = l.docs.find((r) => r.type === "share" && r.ownerId === rec.ownerId &&
                r.data.poolId === rec.data.poolId);
              if (dup) { tick(); throw new Error("duplicate unique index byPoolOwner for share"); }
            }
            delete rec.__new;
            l.docs.push(rec);
          }
          for (const doc of batch.replace || []) {
            const rec = l.docs.find((r) => r.id === doc.__rec.id);
            if (!rec) { tick(); throw new Error(`mock: replace of unknown doc ${doc.__rec.id}`); }
            for (const [k, v] of Object.entries(doc.__pending)) {
              rec.data[k] = (Buffer.isBuffer(v) || v instanceof Uint8Array)
                ? Buffer.from(v).toString("hex") : v;
            }
          }
          if ((batch.create || []).length + (batch.replace || []).length > 1) {
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

module.exports = { Client, validateReceiptProps, Core: new Proxy({}, { get() {
  throw new Error("mock: Dash.Core was touched; the harness scenarios must supply member reward scripts");
} }) };
