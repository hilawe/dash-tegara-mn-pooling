/**
 * THE CANONICAL v11 UPDATE, adding memberFinalEpoch (tegara/docs/FINAL_EPOCH_DESIGN.md), decided
 * from proof-verified reads. The runner is updateV11Run.mjs; everything that decides is here.
 *
 * THE STATE IS READ, NEVER REMEMBERED. The runner reads the contract by proof and this module
 * classifies what it serves, so a response lost after the update was accepted is recognized on
 * the next run by the contract itself, with no local marker to trust or to go stale:
 * - exactly the published v11 payload at version 1: update;
 * - exactly the updated payload at version 2: already updated;
 * - anything else, including either payload at the wrong version: REFUSE.
 * Schemas are compared as canonical JSON of the contract's plain schemas, the same form the audit's
 * contract-integrity aspect compares (e2Audit.cjs, evaluateContractIntegrity), against payloads
 * rebuilt from source (contractV11.cjs), never derived from the fetched contract.
 *
 * THE KEY. Platform refuses a data contract update signed below CRITICAL (the boundary probe's first
 * testnet run, 2026-09-27: "requires one of CRITICAL"), so chooseSigningKey requires an
 * authentication key at exactly the level asked for and never falls back to another.
 *
 * AFTER THE UPDATE, verifyAfterUpdate requires, in order, stopping at the first failure: the
 * contract re-read by proof classifies as already updated; the demo formation still reads back by
 * proof and matches (registerV11Formation's reuse decision); and the gate capture's strict lookup
 * still admits against the updated contract, which keeps its identifier.
 */
const { buildV11, buildV11WithFinalEpoch, FINAL_EPOCH_TYPE } = require("./contractV11.cjs");
const { canonicalString } = require("./canonicalJson.cjs");

const refuse = (why) => { throw new Error(`registerV11Update: ${why}; refusing`); };
const HEX64 = /^[0-9a-f]{64}$/;
const plain = (v) => JSON.parse(JSON.stringify(v, (k, x) => (typeof x === "bigint" ? Number(x) : x)));

const expectedPayloads = (poolLedgerContract) => ({
  before: buildV11(poolLedgerContract),
  after: buildV11WithFinalEpoch(poolLedgerContract),
});

/**
 * served: { idHex, ownerIdHex, version, schemas } from a proof-verified contract read.
 * Returns { action: "update" } or { action: "already-updated" }, and refuses everything else.
 */
const planV11Update = ({ served, contractIdHex, writerIdHex, poolLedgerContract }) => {
  if (!HEX64.test(contractIdHex || "") || !HEX64.test(writerIdHex || "")) refuse("contractIdHex and writerIdHex must be 64 lowercase hex characters");
  if (!served || typeof served !== "object") refuse("no served contract");
  if (served.idHex !== contractIdHex) refuse(`the served contract is ${String(served.idHex).slice(0, 12)}..., not the canonical v11`);
  if (served.ownerIdHex !== writerIdHex) refuse("the served contract is not owned by the writer");
  if (!Number.isInteger(served.version)) refuse("the served contract has no integer version");
  if (!served.schemas || typeof served.schemas !== "object") refuse("the served contract has no schemas");
  const { before, after } = expectedPayloads(poolLedgerContract);
  const got = canonicalString(plain(served.schemas));
  const isBefore = got === canonicalString(before);
  const isAfter = got === canonicalString(after);
  if (isBefore && served.version === 1) return { action: "update", fromVersion: 1, toVersion: 2 };
  if (isAfter && served.version === 2) return { action: "already-updated", version: 2 };
  if (isBefore || isAfter) {
    refuse(`the served schemas are the ${isBefore ? "published v11" : "updated"} payload but the version is ${served.version}`);
  }
  const types = Object.keys(served.schemas).sort();
  refuse(`the served schemas match neither the published v11 nor the updated payload (types: ${types.join(", ")})`);
};

/**
 * The contract value to publish: the served value with memberFinalEpoch added and the version
 * raised by one. The served value's schemas must be the published v11 payload, and the result's
 * schemas must be exactly the updated payload, or this refuses.
 */
const updatedContractValue = ({ currentValue, poolLedgerContract }) => {
  if (!currentValue || typeof currentValue !== "object" || !currentValue.documentSchemas) refuse("no current contract value");
  const { before, after } = expectedPayloads(poolLedgerContract);
  if (canonicalString(plain(currentValue.documentSchemas)) !== canonicalString(before)) {
    refuse("the current contract value is not the published v11 payload");
  }
  if (Object.prototype.hasOwnProperty.call(currentValue.documentSchemas, FINAL_EPOCH_TYPE)) refuse("the type is already present");
  const next = {
    ...currentValue,
    documentSchemas: { ...currentValue.documentSchemas, [FINAL_EPOCH_TYPE]: plain(after[FINAL_EPOCH_TYPE]) },
    version: Number(currentValue.version) + 1,
  };
  if (canonicalString(plain(next.documentSchemas)) !== canonicalString(after)) refuse("the built value is not the updated payload");
  return next;
};

/**
 * matches: the identity's published keys that the wallet's own keys matched, as
 * [{ keyId, purpose, level, ... }]. Returns the one authentication key at exactly `level`.
 */
const chooseSigningKey = (matches, level) => {
  if (!["HIGH", "CRITICAL"].includes(level)) refuse(`level must be HIGH or CRITICAL, not ${level}`);
  if (!Array.isArray(matches)) refuse("no matched keys");
  const hits = matches.filter((m) => m && m.purpose === "AUTHENTICATION" && m.level === level);
  if (hits.length === 0) refuse(`no authentication key at ${level} matched the wallet`);
  if (hits.length > 1) refuse(`${hits.length} authentication keys at ${level} matched; choose one explicitly`);
  return hits[0];
};

/**
 * After a broadcast, or when the plan says already updated. deps.readContract() answers the
 * served shape planV11Update takes; deps.resolveFormation() answers registerV11Formation's
 * decision; deps.verifyGate() answers verifyGateCapture's result. Each read must throw on a
 * failed proof. Stops at the first failure.
 */
const verifyAfterUpdate = async ({ deps, contractIdHex, writerIdHex, poolLedgerContract }) => {
  for (const k of ["readContract", "resolveFormation", "verifyGate"]) {
    if (!deps || typeof deps[k] !== "function") refuse(`verifyAfterUpdate needs deps.${k}`);
  }
  const report = [];
  const plan = planV11Update({ served: await deps.readContract(), contractIdHex, writerIdHex, poolLedgerContract });
  if (plan.action !== "already-updated") refuse("the contract re-read by proof is not the updated payload at version 2");
  report.push("the contract re-read by proof is the updated payload at version 2, same identifier and owner");
  const formation = await deps.resolveFormation();
  if (!formation || formation.action !== "reuse") refuse(`the demo formation did not read back as the committed one (${formation && formation.action})`);
  report.push("the demo pool and its receipt read back by proof and still match");
  const gate = await deps.verifyGate();
  if (!gate || gate.admitted !== true) refuse("the gate capture's strict lookup did not admit after the update");
  report.push("the gate capture's strict lookup admits against the updated contract");
  return report;
};

const crypto = require("crypto");
const MAX_STATE_TRANSITION_SIZE = 20480;
const REREADS = 6;

/**
 * THE WHOLE UPDATE PATH, over injected reads and writes, so its wiring is driven by a battery
 * (the runner supplies only SDK adapters). deps:
 *   matchedKeys()                 the identity's published keys its wallet matched
 *   readContract()                { contract, served } by proof; throws on a failed proof
 *   readContractNonce()           the identity's current contract nonce for v11, by proof (BigInt)
 *   contractValue(contract)       the contract's plain value
 *   buildSignedUpdate({ value, key, nonce })  { bytesHex, size }, signed with exactly `key`
 *   broadcast(bytesHex)           broadcasts those exact bytes and settles; returns an outcome token
 *   readPending(), writePending(record), clearPending()   the owned store entry
 *   resolveFormation(), verifyGateWith(contract)          the demo formation, the gate's strict lookup
 *   sleep(ms), log(line)
 *
 * THE AMBIGUOUS OUTCOME. A pending record { nonce, bytesHex, sha256 } is written BEFORE the one
 * broadcast and cleared only by a CONFIRMED run that reads the contract as updated. A later run that
 * finds a pending record NEVER builds a new transition:
 *   - the contract reads as updated: already updated, post-update checks; a confirmed run clears
 *     the record, a dry run leaves it;
 *   - it reads as version 1 and the identity's contract nonce has not reached the recorded one:
 *     the recorded bytes can still execute, so a confirmed run resends them IDENTICALLY (one nonce,
 *     so they cannot apply twice) and a dry run only reports it;
 *   - it reads as version 1 and the nonce has reached the recorded one: UNRESOLVED. At the recorded
 *     nonce the recorded bytes cannot execute. PAST it they still can, if that nonce was skipped and
 *     lies within 24 of the tip (rs-dpp identity_nonce.rs, validate_identity_nonce_update, read
 *     2026-09-28; this comment said otherwise until then). And an advanced nonce does not show they
 *     did execute: any other write by the identity on this contract advances it too. Nothing is sent
 *     and the record is kept for a human decision.
 * A run whose re-reads still show version 1 after its broadcast returns "unresolved" and keeps the
 * record. Returns { outcome, ... } with outcome one of "dry-run", "updated", "already-updated",
 * "unresolved"; everything else throws.
 *
 * ONE INVOCATION AT A TIME. The record makes SEQUENTIAL retries safe. It does not make concurrent
 * runs safe: each store write takes its own lock, which does not serialize the whole operation. The
 * runner holds a whole-operation lock on its settings store for the run, which serializes runs on
 * that one store and nothing wider.
 */
const runV11UpdateFlow = async ({ deps, confirmed, contractIdHex, writerIdHex, poolLedgerContract }) => {
  for (const k of ["matchedKeys", "readContract", "readContractNonce", "contractValue", "buildSignedUpdate", "broadcast",
    "readPending", "writePending", "clearPending", "resolveFormation", "verifyGateWith", "sleep", "log"]) {
    if (!deps || typeof deps[k] !== "function") refuse(`runV11UpdateFlow needs deps.${k}`);
  }
  const key = chooseSigningKey(await deps.matchedKeys(), "CRITICAL");
  let { contract, served } = await deps.readContract();
  const planOf = (sv) => planV11Update({ served: sv, contractIdHex, writerIdHex, poolLedgerContract });
  let plan = planOf(served);

  // the formation and the gate hold before anything is sent (and, if already updated, before
  // the post-update checks repeat them against the same contract)
  const f0 = await deps.resolveFormation();
  if (!f0 || f0.action !== "reuse") refuse(`the demo formation did not read back before the update (${f0 && f0.action})`);
  const g0 = await deps.verifyGateWith(contract);
  if (!g0 || g0.admitted !== true) refuse("the gate capture's strict lookup did not admit before the update");
  deps.log("PRE-CHECK PASS: the demo formation reads back by proof and the gate capture admits");

  const postChecks = async () => {
    const report = await verifyAfterUpdate({ contractIdHex, writerIdHex, poolLedgerContract, deps: {
      readContract: async () => { const r = await deps.readContract(); contract = r.contract; return r.served; },
      resolveFormation: deps.resolveFormation,
      verifyGate: () => deps.verifyGateWith(contract),
    } });
    for (const r of report) deps.log(`CHECK PASS: ${r}`);
    return report;
  };

  const pending = await deps.readPending();
  if (plan.action === "already-updated") {
    const report = await postChecks();
    if (pending && confirmed) await deps.clearPending();
    return { outcome: "already-updated", report, recordKept: !!pending && !confirmed };
  }

  let bytesHex;
  if (pending) {
    if (!/^[0-9a-f]+$/.test(pending.bytesHex || "") || !/^[0-9]+$/.test(String(pending.nonce))
      || crypto.createHash("sha256").update(Buffer.from(pending.bytesHex, "hex")).digest("hex") !== pending.sha256) {
      refuse("the pending update record is malformed; it needs a human decision");
    }
    const now = BigInt(await deps.readContractNonce());
    if (now >= BigInt(pending.nonce)) {
      deps.log(`UNRESOLVED: the contract reads version 1 and the identity's contract nonce is ${now}, at or past the recorded ${pending.nonce}. At the recorded nonce the recorded bytes cannot execute, and past it they still can if that nonce was skipped and lies within 24 of the tip. Whether they did is not shown. Nothing was sent and the record is kept.`);
      return { outcome: "unresolved", reason: "nonce-advanced", recordedNonce: String(pending.nonce), currentNonce: String(now) };
    }
    if (!confirmed) return { outcome: "dry-run", resend: true, nonce: String(pending.nonce), keyId: key.keyId };
    bytesHex = pending.bytesHex;
    deps.log(`RESENDING the recorded update unchanged (nonce ${pending.nonce}); no new transition is built`);
  } else {
    const nonce = BigInt(await deps.readContractNonce()) + 1n;
    const value = updatedContractValue({ currentValue: deps.contractValue(contract), poolLedgerContract });
    const signed = await deps.buildSignedUpdate({ value, key, nonce });
    if (!signed || typeof signed.bytesHex !== "string" || !Number.isInteger(signed.size)) refuse("the signed update was not returned");
    if (signed.size > MAX_STATE_TRANSITION_SIZE) refuse(`the signed update is ${signed.size} bytes, above ${MAX_STATE_TRANSITION_SIZE}`);
    if (!confirmed) return { outcome: "dry-run", resend: false, nonce: String(nonce), size: signed.size, keyId: key.keyId };
    bytesHex = signed.bytesHex;
    await deps.writePending({ nonce: String(nonce), bytesHex,
      sha256: crypto.createHash("sha256").update(Buffer.from(bytesHex, "hex")).digest("hex") });
  }

  const token = await deps.broadcast(bytesHex);
  deps.log(`broadcast outcome: ${token}`);
  for (let i = 0; i < REREADS; i++) {
    ({ contract, served } = await deps.readContract());
    plan = planOf(served);
    if (plan.action === "already-updated") {
      await deps.clearPending();
      return { outcome: "updated", token, report: await postChecks() };
    }
    if (i < REREADS - 1) await deps.sleep(5000);
  }
  return { outcome: "unresolved", token };
};

module.exports = { planV11Update, updatedContractValue, chooseSigningKey, verifyAfterUpdate, expectedPayloads, runV11UpdateFlow };
