/**
 * e2FinalEpoch's battery. Every expectation is the design's rule applied by hand
 * (tegara/docs/FINAL_EPOCH_DESIGN.md, ORDERING and WHO DECIDES), not the module's output read back.
 * Identifiers are derived from hashes, and pairs that must be told apart differ only in one
 * character, so a prefix comparison or a reordered identifier cannot pass.
 */
"use strict";
const crypto = require("crypto");
const { finalEpochsFromRecords, planFinalEpochRecord, assertNoLateRecords, readEffectiveFinalEpochs, makeFinalEpochReads,
  servedCreatedAt } = require("./e2FinalEpoch.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
const section = (name, fn) => {
  try { fn(); } catch (e) { failed++; console.error(`FAIL: ${name} threw unexpectedly: ${(e && e.message) || e}`); }
};

const hx = (label) => crypto.createHash("sha256").update(`fixture:${label}`).digest("hex");
const lastDiff = (h) => h.slice(0, 63) + (h[63] === "0" ? "1" : "0");
const X = hx("pool-x"), Y = hx("pool-y");                 // two pools of one sending identity
const M1 = hx("member-1"), M2 = hx("member-2"), M1_LAST = lastDiff(M1);
const rec = (poolId, funderId, finalEpochIndex, createdAt) => ({ poolId, funderId, finalEpochIndex, createdAt });

section("which records are effective", () => {
  const none = finalEpochsFromRecords({ poolId: X, records: [], headerCreatedAtByEpoch: new Map() });
  ok("no records: no final epochs and nothing late", none.finalEpochs.size === 0 && none.late.length === 0);

  const before = finalEpochsFromRecords({ poolId: X, records: [rec(X, M1, 4, 1000)], headerCreatedAtByEpoch: new Map([[4, 1001]]) });
  ok("a record created 1 ms before its epoch's header is effective", before.finalEpochs.get(M1) === 4 && before.late.length === 0);

  const noHeader = finalEpochsFromRecords({ poolId: X, records: [rec(X, M1, 4, 5000)], headerCreatedAtByEpoch: new Map([[3, 100]]) });
  ok("a record whose epoch has no header yet is effective, whatever other headers exist", noHeader.finalEpochs.get(M1) === 4 && noHeader.late.length === 0);

  const same = finalEpochsFromRecords({ poolId: X, records: [rec(X, M1, 4, 1000)], headerCreatedAtByEpoch: new Map([[4, 1000]]) });
  ok("a record created in the same millisecond as its header is LATE (strictly earlier is required)",
    same.finalEpochs.size === 0 && same.late.length === 1 && same.late[0].funderId === M1 && same.late[0].headerCreatedAt === 1000);

  const after = finalEpochsFromRecords({ poolId: X, records: [rec(X, M1, 4, 1002)], headerCreatedAtByEpoch: new Map([[4, 1001]]) });
  ok("a record created after its header is late and not applied", after.finalEpochs.size === 0 && after.late.length === 1);
  throws("the writer's gate refuses a pool with a late record", () => assertNoLateRecords(after.late), /inconsistent and needs an operator/);
  ok("the writer's gate passes a pool with none", (() => { assertNoLateRecords([]); return true; })());

  const two = finalEpochsFromRecords({ poolId: X, records: [rec(X, M1, 4, 10), rec(X, M1_LAST, 6, 11)], headerCreatedAtByEpoch: new Map() });
  ok("two members whose identifiers differ only in the last character keep their own final epochs",
    two.finalEpochs.get(M1) === 4 && two.finalEpochs.get(M1_LAST) === 6 && two.finalEpochs.size === 2);
});

section("the pool boundary, with a second pool of the same sender", () => {
  const xs = finalEpochsFromRecords({ poolId: X, records: [rec(X, M1, 4, 10)], headerCreatedAtByEpoch: new Map() });
  const ys = finalEpochsFromRecords({ poolId: Y, records: [rec(Y, M2, 9, 20)], headerCreatedAtByEpoch: new Map() });
  ok("each pool's set holds only its own member", xs.finalEpochs.has(M1) && !xs.finalEpochs.has(M2) && ys.finalEpochs.has(M2) && !ys.finalEpochs.has(M1));
  throws("a record naming another pool in this pool's answer is refused",
    () => finalEpochsFromRecords({ poolId: X, records: [rec(X, M1, 4, 10), rec(Y, M2, 9, 20)], headerCreatedAtByEpoch: new Map() }), /names another pool/);
  throws("a pool identifier differing only in its last character is another pool",
    () => finalEpochsFromRecords({ poolId: X, records: [rec(lastDiff(X), M1, 4, 10)], headerCreatedAtByEpoch: new Map() }), /names another pool/);
});

section("malformed answers are refused", () => {
  const f = (records, headers = new Map()) => () => finalEpochsFromRecords({ poolId: X, records, headerCreatedAtByEpoch: headers });
  throws("two records for one member are refused", f([rec(X, M1, 4, 10), rec(X, M1, 5, 11)]), /admits one per pool and member/);
  throws("a record with no creation time is refused", f([{ poolId: X, funderId: M1, finalEpochIndex: 4 }]), /\$createdAt/);
  throws("a final epoch that is not an integer is refused", f([rec(X, M1, "4", 10)]), /not a u32 integer/);
  throws("a funder that is not 64 hex is refused", f([rec(X, M1.toUpperCase(), 4, 10)]), /64-hex funderId/);
  throws("records that are not an array are refused", () => finalEpochsFromRecords({ poolId: X, records: null, headerCreatedAtByEpoch: new Map() }), /must be an array/);
  throws("headers that are not a Map are refused", () => finalEpochsFromRecords({ poolId: X, records: [], headerCreatedAtByEpoch: {} }), /must be a Map/);
});

section("the operator's command", () => {
  const base = { poolId: X, funderId: M1, finalEpochIndex: 7, allocationFunders: [M1, M2], configuredStart: 0, headerExists: false, existing: null };
  const plan = (over) => planFinalEpochRecord({ ...base, ...over });
  ok("a member in the allocation, before its epoch's header, with no record: create", plan({}).action === "create");
  throws("a member outside the allocation is refused", () => plan({ funderId: hx("stranger") }), /not in this pool's allocation/);
  throws("a member differing from an allocation owner only in the last character is outside it", () => plan({ funderId: M1_LAST }), /not in this pool's allocation/);
  throws("an epoch before the configured start is refused", () => plan({ configuredStart: 8 }), /before the pool's configured start/);
  throws("an epoch whose header exists is refused as too late", () => plan({ headerExists: true }), /header already exists/);
  ok("the same record already on the ledger is reported, not recreated",
    plan({ existing: { poolId: X, funderId: M1, finalEpochIndex: 7 } }).action === "already-recorded");
  ok("and that holds even once the header exists, so a resumed command is idempotent",
    plan({ existing: { poolId: X, funderId: M1, finalEpochIndex: 7 }, headerExists: true }).action === "already-recorded");
  throws("a different final epoch already recorded is refused, since it never changes",
    () => plan({ existing: { poolId: X, funderId: M1, finalEpochIndex: 5 } }), /already has final epoch 5/);
  throws("an existing record for another pool is refused", () => plan({ existing: { poolId: Y, funderId: M1, finalEpochIndex: 7 } }), /not this pool's record/);
  throws("an omitted header answer is refused", () => plan({ headerExists: undefined }), /explicit boolean/);
});

// ---- THE READING COMPOSITION, with stand-ins that carry every failure mode (a stand-in that
// always answers would turn these into control-flow tests) ----
const asyncCase = async () => {
  const reads = (over = {}) => ({ poolId: X, lateIs: "refused", contractDefinesType: () => true,
    queryRecords: async () => [rec(X, M1, 4, 10)], headerCreatedAt: async (e) => (e === 4 ? 11 : null), ...over });
  const refusedP = async (p) => { try { await p; return ""; } catch (e) { return String(e.message); } };
  const absent = await readEffectiveFinalEpochs(reads({ contractDefinesType: () => false,
    queryRecords: async () => { throw new Error("must not be read"); } }));
  ok("a contract without the type answers the empty set on that basis, without reading records",
    absent.basis === "type-absent" && absent.finalEpochs.size === 0);
  const read = await readEffectiveFinalEpochs(reads());
  ok("a record created before its header is effective through the composition", read.basis === "records-read" && read.finalEpochs.get(M1) === 4);
  ok("a record read that fails refuses rather than answering no final epochs",
    /record read failed/.test(await refusedP(readEffectiveFinalEpochs(reads({ queryRecords: async () => { throw new Error("record read failed"); } })))));
  ok("a header read that fails refuses",
    /header read failed/.test(await refusedP(readEffectiveFinalEpochs(reads({ headerCreatedAt: async () => { throw new Error("header read failed"); } })))));
  ok("a record read answering something that is not a list refuses",
    /not a list/.test(await refusedP(readEffectiveFinalEpochs(reads({ queryRecords: async () => ({ length: 0 }) })))));
  ok("a contract answer that is not a boolean refuses",
    /must answer a boolean/.test(await refusedP(readEffectiveFinalEpochs(reads({ contractDefinesType: () => "yes" })))));
  ok("a header answer that is neither a time nor null refuses",
    /neither a millisecond time nor null/.test(await refusedP(readEffectiveFinalEpochs(reads({ headerCreatedAt: async () => "11" })))));
  const lateReads = reads({ headerCreatedAt: async () => 9 });
  ok("a late record REFUSES the writer and the pool resolution", /inconsistent and needs an operator/.test(await refusedP(readEffectiveFinalEpochs(lateReads))));
  const reported = await readEffectiveFinalEpochs({ ...lateReads, lateIs: "reported" });
  ok("the same late record is REPORTED to the audit and not applied", reported.late.length === 1 && reported.finalEpochs.size === 0);
  ok("a second pool of the same sender served in this pool's read refuses",
    /names another pool/.test(await refusedP(readEffectiveFinalEpochs(reads({ queryRecords: async () => [rec(X, M1, 4, 10), rec(Y, M2, 9, 20)] })))));
  ok("an unknown lateIs refuses", /lateIs must be/.test(await refusedP(readEffectiveFinalEpochs(reads({ lateIs: "ignored" })))));
};

// ---- THE HEADER STEP'S RE-CHECK: assertSameFinalEpochs ----
section("assertSameFinalEpochs", () => {
  const { assertSameFinalEpochs } = require("./e2FinalEpoch.cjs");
  const same = (a, b) => { try { assertSameFinalEpochs(a, b); return true; } catch (e) { return /changed since this run's rows were built/.test(e.message) ? false : e.message; } };
  ok("equal sets confirm, entry order aside", same(new Map([[M1, 4], [M2, 6]]), new Map([[M2, 6], [M1, 4]])) === true);
  ok("two empty sets confirm", same(new Map(), new Map()) === true);
  ok("a member added since refuses", same(new Map([[M1, 4]]), new Map([[M1, 4], [M2, 6]])) === false);
  ok("a member gone since refuses", same(new Map([[M1, 4], [M2, 6]]), new Map([[M1, 4]])) === false);
  ok("the same member at another epoch refuses", same(new Map([[M1, 4]]), new Map([[M1, 5]])) === false);
  throws("a set that is not a Map refuses", () => assertSameFinalEpochs({}, new Map()), /compares two Maps/);
});

// ---- THE READS OVER A PROVED QUERY: the adapter from a served document to a record's fields ----
const readsCase = async () => {
  const refusedP = async (p) => { try { await p; return ""; } catch (e) { return String(e.message); } };
  const calls = [];
  const idHex = (v) => (typeof v === "string" && v.startsWith("id:") ? v.slice(3) : (() => { throw new Error("not an identifier"); })());
  const doc = (props, createdAt) => ({ getProperties: () => props, createdAt });
  const served = { memberFinalEpoch: [], epochHeader: [] };
  const provedQuery = async (type, where, label) => { calls.push({ type, where, label }); return served[type]; };
  const reads = makeFinalEpochReads({ poolId: X, provedQuery, idHex, contractDefinesType: () => true });
  served.memberFinalEpoch = [doc({ poolId: Buffer.from(X, "hex"), funderId: `id:${M1}`, finalEpochIndex: 4 }, 1000n)];
  const got = await reads.queryRecords();
  const q = calls[calls.length - 1];
  ok("the record read is EXACTLY one equality on this pool's bytes, for the final-epoch type",
    q.type === "memberFinalEpoch" && q.where.length === 1 && q.where[0].length === 3 && q.where[0][0] === "poolId"
      && q.where[0][1] === "==" && Buffer.from(q.where[0][2]).toString("hex") === X);
  ok("a served record with byte and identifier fields and a bigint $createdAt becomes the record's fields",
    got.length === 1 && got[0].poolId === X && got[0].funderId === M1 && got[0].finalEpochIndex === 4 && got[0].createdAt === 1000);
  served.memberFinalEpoch = [doc({ poolId: Buffer.from(X, "hex"), funderId: `id:${M1}`, finalEpochIndex: 4 }, undefined)];
  ok("a served record with no $createdAt refuses", /carries no \$createdAt/.test(await refusedP(reads.queryRecords())));
  // EVERY NON-LIST ANSWER REFUSES, for both reads and end to end (the step 4 review's fifth finding:
  // a validator changed to read an undefined answer as an empty list survived every battery)
  for (const [label, answer] of [["nothing", undefined], ["null", null], ["an empty array-like", { length: 0 }]]) {
    served.memberFinalEpoch = answer;
    ok(`a record read answering ${label} refuses`, /is not a list/.test(await refusedP(reads.queryRecords())));
    ok(`and end to end, a type-present read answering ${label} refuses rather than yielding no final epochs`,
      /is not a list/.test(await refusedP(readEffectiveFinalEpochs({ poolId: X, lateIs: "reported", ...reads }))));
    served.epochHeader = answer;
    ok(`a header read answering ${label} refuses`, /is not a list/.test(await refusedP(reads.headerCreatedAt(4))));
  }
  served.epochHeader = [];
  served.memberFinalEpoch = [doc({ poolId: 7, funderId: `id:${M1}`, finalEpochIndex: 4 }, 1n)];
  ok("a served byte field that is neither bytes nor an identifier refuses", /neither bytes nor an identifier/.test(await refusedP(reads.queryRecords())));
  served.memberFinalEpoch = { length: 1 };
  ok("a record read answering something that is not a list refuses", /not a list/.test(await refusedP(reads.queryRecords())));
  served.epochHeader = [];
  ok("no header for the epoch answers null", (await reads.headerCreatedAt(4)) === null);
  const hq = calls[calls.length - 1];
  ok("the header read is EXACTLY the pool and the epoch, both by equality",
    hq.type === "epochHeader" && hq.where.length === 2 && hq.where[0][0] === "poolId" && hq.where[0][1] === "=="
      && Buffer.from(hq.where[0][2]).toString("hex") === X && hq.where[1][0] === "epochIndex" && hq.where[1][1] === "==" && hq.where[1][2] === 4);
  served.epochHeader = [doc({}, 1001n)];
  ok("one header answers its $createdAt", (await reads.headerCreatedAt(4)) === 1001);
  served.epochHeader = [doc({}, 1n), doc({}, 2n)];
  ok("two headers for one epoch refuse", /which the unique index forbids/.test(await refusedP(reads.headerCreatedAt(4))));
  // end to end through the composition, with a second pool of the same sender served by mistake
  served.epochHeader = [doc({}, 1001n)];
  served.memberFinalEpoch = [doc({ poolId: Buffer.from(X, "hex"), funderId: `id:${M1}`, finalEpochIndex: 4 }, 1000n)];
  const eff = await readEffectiveFinalEpochs({ poolId: X, lateIs: "refused", ...reads });
  ok("end to end, a record served before its header is effective", eff.finalEpochs.get(M1) === 4 && eff.basis === "records-read");
  served.memberFinalEpoch.push(doc({ poolId: Buffer.from(Y, "hex"), funderId: `id:${M2}`, finalEpochIndex: 9 }, 5n));
  ok("end to end, another pool's record in this pool's answer refuses",
    /names another pool/.test(await refusedP(readEffectiveFinalEpochs({ poolId: X, lateIs: "refused", ...reads }))));
};

// the conversion the audit runner reuses for its enumerated headers and records
ok("a served bigint creation time converts to milliseconds", servedCreatedAt({ createdAt: 1500n }, "header") === 1500);
throws("a served document without a usable creation time refuses",
  () => servedCreatedAt({ createdAt: -1 }, "header"), /a served header carries no \$createdAt/);

asyncCase().then(readsCase).then(() => {
  console.log(`e2FinalEpochTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
}).catch((e) => { console.error("UNCAUGHT:", e); process.exitCode = 1; });
