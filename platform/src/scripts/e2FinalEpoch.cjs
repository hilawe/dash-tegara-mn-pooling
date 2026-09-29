/**
 * A MEMBER'S FINAL EPOCH, the decisions (tegara/docs/FINAL_EPOCH_DESIGN.md). Pure: no I/O, no
 * ledger access, nothing mutated. The writer, the audit and the operator's command all decide
 * through here, and their runners hold only the wiring that fetches the inputs.
 *
 * TWO DECISIONS.
 *
 * 1. `finalEpochsFromRecords`: which of a pool's memberFinalEpoch records are EFFECTIVE. A record is
 *    effective when its `$createdAt` is strictly earlier than the `$createdAt` of its epoch's header,
 *    or when that header does not exist. Any other record is LATE. Late records are returned, never
 *    applied: the audit reports them, and the writer refuses to run the pool while any exists.
 *
 * 2. `planFinalEpochRecord`: whether the operator's command may create a record, and whether it
 *    already exists. It refuses a member outside the allocation, an epoch before the configured
 *    start, an epoch whose header exists, and a second final epoch for the same member.
 *
 * AND ONE COMPOSITION, `readEffectiveFinalEpochs`, which every reader uses to turn the ledger's
 * reads into the effective set, so the writer, the pool resolution and the audit cannot disagree
 * about which records apply. Its reads are injected. If the pool's contract does not define the
 * type, no record can exist, and the proved contract definition is the evidence for the empty set.
 * Any read that fails refuses: an unperformed read never answers "no final epochs".
 *
 * A RESIDUAL, stated. A read served from a node that lags the record's creation misses the record.
 * The writer then pays that epoch unraised and carries the amount, the audit (reading fresh)
 * reports the mismatch, and the next epoch refuses the member. Nothing is overpaid.
 *
 * WHAT IT TAKES ON THE CALLER'S WORD. The records are the pool's COMPLETE set, read by proof, and
 * `headerCreatedAtByEpoch` holds every header of the pool that exists, with its stored `$createdAt`.
 * `headerExists` for the command is the caller's combined answer from the ledger and the journal. A
 * caller that omits a record or a header gets a wrong answer that looks right, which is the same
 * trust statement the carry layer makes about its member set.
 */
"use strict";

const { FINAL_EPOCH_TYPE } = require("./contractV11.cjs");

const HEX32 = /^[0-9a-f]{64}$/;
const refuse = (why) => { throw new Error(`e2FinalEpoch: ${why}; refusing`); };
const isEpoch = (n) => Number.isSafeInteger(n) && n >= 0 && n <= 4294967295;
const isTime = (n) => Number.isSafeInteger(n) && n >= 0;

/**
 * finalEpochsFromRecords({ poolId, records, headerCreatedAtByEpoch })
 *   poolId                 : 64 lowercase hex, the pool every record must name
 *   records                : [{ poolId, funderId, finalEpochIndex, createdAt }], hex ids, createdAt
 *                            the record's `$createdAt` in milliseconds
 *   headerCreatedAtByEpoch : Map from epoch number to that header's `$createdAt`
 * -> { finalEpochs: Map(funderId -> epoch), late: [{ funderId, finalEpochIndex, createdAt, headerCreatedAt }] }
 */
const finalEpochsFromRecords = ({ poolId, records, headerCreatedAtByEpoch } = {}) => {
  if (typeof poolId !== "string" || !HEX32.test(poolId)) refuse("poolId must be 64 lowercase hex");
  if (!Array.isArray(records)) refuse("records must be an array (the pool's complete set, empty when there is none)");
  if (!(headerCreatedAtByEpoch instanceof Map)) refuse("headerCreatedAtByEpoch must be a Map (every existing header of the pool)");
  for (const [e, t] of headerCreatedAtByEpoch) {
    if (!isEpoch(e) || !isTime(t)) refuse(`a header entry (${JSON.stringify(e)}, ${JSON.stringify(t)}) is not an epoch number with a millisecond time`);
  }
  const finalEpochs = new Map();
  const late = [];
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (!r || typeof r !== "object") refuse(`record ${i} is not an object`);
    const { poolId: rp, funderId, finalEpochIndex, createdAt } = r;   // one read of each member
    if (rp !== poolId) refuse(`record ${i} names another pool, so the answer is not this pool's set`);
    if (typeof funderId !== "string" || !HEX32.test(funderId)) refuse(`record ${i} has no 64-hex funderId`);
    if (!isEpoch(finalEpochIndex)) refuse(`record ${i} has a final epoch that is not a u32 integer`);
    if (!isTime(createdAt)) refuse(`record ${i} has no millisecond $createdAt, so its order against the header cannot be decided`);
    // the ledger's unique index admits one record per pool and member, so a second one served is an
    // inconsistent answer, not a second final epoch
    if (finalEpochs.has(funderId) || late.some((x) => x.funderId === funderId)) {
      refuse(`two records name member ${funderId.slice(0, 8)}...; the ledger admits one per pool and member`);
    }
    const headerCreatedAt = headerCreatedAtByEpoch.get(finalEpochIndex);
    if (headerCreatedAt !== undefined && !(createdAt < headerCreatedAt)) {
      late.push({ funderId, finalEpochIndex, createdAt, headerCreatedAt });
    } else {
      finalEpochs.set(funderId, finalEpochIndex);
    }
  }
  return { finalEpochs, late };
};

/**
 * planFinalEpochRecord({ poolId, funderId, finalEpochIndex, allocationFunders, configuredStart,
 *                        headerExists, existing })
 *   allocationFunders : the pool's allocation owners, 64 lowercase hex each
 *   headerExists      : whether epoch finalEpochIndex's header exists, on the ledger or in the journal
 *   existing          : the member's record already on the ledger, or null
 * -> { action: "create" } | { action: "already-recorded" }
 */
const planFinalEpochRecord = ({ poolId, funderId, finalEpochIndex, allocationFunders, configuredStart,
  headerExists, existing } = {}) => {
  if (typeof poolId !== "string" || !HEX32.test(poolId)) refuse("poolId must be 64 lowercase hex");
  if (typeof funderId !== "string" || !HEX32.test(funderId)) refuse("the member must be 64 lowercase hex");
  if (!isEpoch(finalEpochIndex)) refuse("the final epoch must be a u32 integer");
  if (!Array.isArray(allocationFunders) || allocationFunders.some((f) => typeof f !== "string" || !HEX32.test(f))) {
    refuse("allocationFunders must be the allocation's 64-hex owners");
  }
  if (!isEpoch(configuredStart)) refuse("configuredStart must be a u32 integer");
  if (typeof headerExists !== "boolean") refuse("headerExists must be an explicit boolean (an omitted answer would read as no header)");
  if (!allocationFunders.includes(funderId)) refuse(`member ${funderId.slice(0, 8)}... is not in this pool's allocation`);
  if (finalEpochIndex < configuredStart) {
    refuse(`epoch ${finalEpochIndex} is before the pool's configured start ${configuredStart}, where nothing is distributed`);
  }
  if (existing !== null) {
    if (!existing || typeof existing !== "object" || existing.poolId !== poolId || existing.funderId !== funderId) {
      refuse("the existing record served is not this pool's record for this member");
    }
    if (existing.finalEpochIndex === finalEpochIndex) return { action: "already-recorded" };
    refuse(`member ${funderId.slice(0, 8)}... already has final epoch ${existing.finalEpochIndex}; a member has one final epoch per pool, and it never changes`);
  }
  if (headerExists) {
    refuse(`epoch ${finalEpochIndex}'s header already exists, so a record now would be late and never apply; name a later epoch`);
  }
  return { action: "create" };
};

/** The writer's gate: a pool with any late record does not run. */
const assertNoLateRecords = (late) => {
  if (!Array.isArray(late)) refuse("late must be the array finalEpochsFromRecords returned");
  if (late.length > 0) {
    const l = late[0];
    refuse(`member ${l.funderId.slice(0, 8)}...'s final epoch ${l.finalEpochIndex} was recorded at ${l.createdAt}, not before that epoch's header at ${l.headerCreatedAt}; the pool's final-epoch state is inconsistent and needs an operator (${late.length} late record${late.length === 1 ? "" : "s"})`);
  }
};

/**
 * readEffectiveFinalEpochs({ poolId, contractDefinesType, queryRecords, headerCreatedAt, lateIs })
 *   contractDefinesType : () => boolean, from the PROVED contract definition
 *   queryRecords        : async () => the pool's records by proof, [{ poolId, funderId,
 *                         finalEpochIndex, createdAt }]
 *   headerCreatedAt     : async (epochIndex) => that header's $createdAt by proof, or null when no
 *                         header exists
 *   lateIs              : "refused" for the writer and the pool resolution, "reported" for the audit
 * -> { finalEpochs, late, basis: "type-absent" | "records-read" }
 */
const readEffectiveFinalEpochs = async ({ poolId, contractDefinesType, queryRecords, headerCreatedAt, lateIs } = {}) => {
  if (lateIs !== "refused" && lateIs !== "reported") refuse('lateIs must be "refused" or "reported"');
  for (const [n, f] of [["contractDefinesType", contractDefinesType], ["queryRecords", queryRecords], ["headerCreatedAt", headerCreatedAt]]) {
    if (typeof f !== "function") refuse(`${n} must be a function`);
  }
  const defines = contractDefinesType();
  if (typeof defines !== "boolean") refuse("contractDefinesType must answer a boolean from the proved contract definition");
  if (!defines) return { finalEpochs: new Map(), late: [], basis: "type-absent" };
  const records = await queryRecords();
  if (!Array.isArray(records)) refuse("the record read answered something that is not a list");
  const headerCreatedAtByEpoch = new Map();
  for (const r of records) {
    const e = r && r.finalEpochIndex;
    if (!isEpoch(e)) refuse("a record's final epoch is not a u32 integer");
    if (headerCreatedAtByEpoch.has(e)) continue;
    const t = await headerCreatedAt(e);
    if (t === null) continue;
    if (!isTime(t)) refuse(`the header read for epoch ${e} answered neither a millisecond time nor null`);
    headerCreatedAtByEpoch.set(e, t);
  }
  const { finalEpochs, late } = finalEpochsFromRecords({ poolId, records, headerCreatedAtByEpoch });
  if (lateIs === "refused") assertNoLateRecords(late);
  return { finalEpochs, late, basis: "records-read" };
};

/**
 * servedCreatedAt(doc, what) -> a served document's `$createdAt` in milliseconds, from the
 * document's `createdAt` member, which the proof-verifying query serves as a bigint or a number.
 * Anything else refuses. Exported so the audit runner attaches `$createdAt` to its enumerated
 * headers and records through this conversion, not a second one of its own.
 */
const servedCreatedAt = (d, what) => {
  const t = d && d.createdAt;
  if (typeof t === "bigint" && t >= 0n && t <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(t);
  if (typeof t === "number" && isTime(t)) return t;
  return refuse(`a served ${what} carries no $createdAt`);
};

/**
 * makeFinalEpochReads({ poolId, provedQuery, contractDefinesType, idHex }) -> the three reads
 * readEffectiveFinalEpochs takes, over a proved query. THE ADAPTER FROM A SERVED DOCUMENT TO A
 * RECORD'S FIELDS LIVES HERE, not in a runner, so a battery can drive it: byte fields may arrive as
 * bytes or as identifiers, `$createdAt` as a bigint, and anything else refuses.
 *   provedQuery : async (type, where, label) => documents, the runner's proof-verifying query
 *   idHex       : the runner's identifier-to-hex conversion, for fields served as identifiers
 */
const makeFinalEpochReads = ({ poolId, provedQuery, contractDefinesType, idHex } = {}) => {
  if (typeof poolId !== "string" || !HEX32.test(poolId)) refuse("poolId must be 64 lowercase hex");
  if (typeof provedQuery !== "function" || typeof contractDefinesType !== "function" || typeof idHex !== "function") {
    refuse("makeFinalEpochReads needs provedQuery, contractDefinesType and idHex functions");
  }
  const poolBytes = Buffer.from(poolId, "hex");
  const bytesHex = (v, what) => {
    if (v instanceof Uint8Array) return Buffer.from(v).toString("hex");
    if (typeof v === "string" || (v && typeof v.base58 === "function")) return idHex(v);
    return refuse(`a served ${what} is neither bytes nor an identifier`);
  };
  const createdAtOf = servedCreatedAt;
  const propsOf = (d) => (d && typeof d.getProperties === "function" ? d.getProperties() : d && d.properties);
  const list = (docs, what) => { if (!Array.isArray(docs)) refuse(`the ${what} read answered something that is not a list`); return docs; };
  return {
    contractDefinesType,
    queryRecords: async () => list(await provedQuery(FINAL_EPOCH_TYPE, [["poolId", "==", poolBytes]], "finalEpochRecords"), "record")
      .map((d) => {
        const f = propsOf(d);
        if (!f || typeof f !== "object") refuse("a served record carries no properties");
        return { poolId: bytesHex(f.poolId, "record's poolId"), funderId: bytesHex(f.funderId, "record's funderId"),
          finalEpochIndex: typeof f.finalEpochIndex === "bigint" ? Number(f.finalEpochIndex) : f.finalEpochIndex,
          createdAt: createdAtOf(d, "record") };
      }),
    headerCreatedAt: async (e) => {
      const hs = list(await provedQuery("epochHeader", [["poolId", "==", poolBytes], ["epochIndex", "==", e]], `finalEpochHeader(${e})`), "header");
      if (hs.length === 0) return null;
      if (hs.length !== 1) refuse(`the header read served ${hs.length} headers for epoch ${e}, which the unique index forbids`);
      return createdAtOf(hs[0], "header");
    },
  };
};

/**
 * assertSameFinalEpochs(built, current): the writer's RE-CHECK at a header write (the step 4
 * review's first finding). A run builds its rows from the effective set it read at its start, which
 * is outside the pool's lock, so the operator's command can create a record between that read and a
 * header write. The header step therefore reads the set again by proof UNDER THE LOCK, before it
 * builds a fresh header, and refuses when it differs in any member or epoch, since a header written
 * then would make the new record effective while the rows ignore it. It refuses rather than
 * rebuilding: the run's rows for every epoch come from one calculation over the whole run. The
 * re-read is only as current as the node answering it, so a lagging node leaves the residual stated
 * at the top of this file.
 */
const assertSameFinalEpochs = (built, current) => {
  if (!(built instanceof Map) || !(current instanceof Map)) {
    refuse("assertSameFinalEpochs compares two Maps, the set the run's rows were built from and the set read now");
  }
  const diffs = [];
  for (const [k, v] of current) {
    if (built.get(k) !== v) diffs.push(`${String(k).slice(0, 8)}... now at ${v}, built ${built.has(k) ? `at ${built.get(k)}` : "with none"}`);
  }
  for (const [k, v] of built) {
    if (!current.has(k)) diffs.push(`${String(k).slice(0, 8)}... built at ${v}, now with none`);
  }
  if (diffs.length) {
    refuse(`the pool's effective final epochs changed since this run's rows were built (${diffs.join(", ")}), and a header written now would ignore that change, so start a fresh run`);
  }
};

module.exports = { finalEpochsFromRecords, planFinalEpochRecord, assertNoLateRecords, readEffectiveFinalEpochs,
  makeFinalEpochReads, servedCreatedAt, assertSameFinalEpochs };
