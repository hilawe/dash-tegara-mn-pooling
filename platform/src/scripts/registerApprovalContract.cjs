"use strict";
/**
 * THE APPROVAL CONTRACT'S PUBLICATION (tegara/docs/APPROVAL_CONTRACT_DESIGN.md, "Publication"),
 * decided from proof-verified reads. The runner is registerApprovalContractRun.mjs. Everything that
 * decides is here, so a battery drives it (registerApprovalContractTest.cjs).
 *
 * PUBLICATION IS HILAWE'S DECISION. Without `confirmed` the flow is a DRY RUN: every check runs and
 * the transition is built and signed, and nothing is recorded or broadcast.
 *
 * THE STATE IS READ, NEVER REMEMBERED. A contract's identifier derives from its owner and the
 * identity nonce it is created at, so the flow's one local record is the PENDING RECORD of the
 * signed bytes, written before the one broadcast and cleared only once the contract reads back by
 * proof as exactly the source build. A later run that finds a pending record NEVER builds new bytes:
 *   - the contract reads back as the source build: published, record discharged (confirmed only);
 *   - it is not found and the identity nonce is below the recorded one: the recorded bytes can still
 *     execute, so a confirmed run resends them IDENTICALLY (one identifier, so they cannot publish
 *     twice) and a dry run reports it;
 *   - it is not found and the nonce is at or past the recorded one: UNRESOLVED. A nonce below the
 *     tip still executes if it was skipped and lies within 24 of the tip (rs-dpp
 *     identity_nonce.rs, validate_identity_nonce_update), so an advanced nonce does not show the
 *     bytes are dead. Nothing is sent, and the record is kept for a human decision.
 * "Not found" comes from the patched contract read, which reports absence BEFORE checking the
 * proof's signature, so an absence is not proof-checked. The flow never draws an affirmative result
 * from it: absence only chooses between resending the identical recorded bytes and reporting, and a
 * publication is recorded only from a contract read back by proof.
 *
 * THE KEY. Identity A's one authentication key at HIGH, the level the boundary probe's contract
 * creation used on testnet (2026-09-27). chooseSigningKey never falls back to another level.
 */
const crypto = require("crypto");
const { canonicalString } = require("./canonicalJson.cjs");
const { chooseSigningKey } = require("./registerV11Update.cjs");
const { buildApprovalSchemas, CONTRACT_CONFIG } = require("./approvalContract.cjs");
const { decodeId32 } = require("./formationCore.cjs");

const PENDING_KEY = "APPROVAL_CONTRACT_PENDING";
const ID_KEY = "APPROVAL_CONTRACT_ID";
const MAX_STATE_TRANSITION_SIZE = 20480;
const REREADS = 6;
const HEX64 = /^[0-9a-f]{64}$/;
const refuse = (why) => { throw new Error(`registerApprovalContract: ${why}; refusing`); };
const plain = (v) => JSON.parse(JSON.stringify(v, (k, x) => (typeof x === "bigint" ? Number(x) : x)));
const sha256 = (hex) => crypto.createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");

/**
 * served: { idHex, ownerIdHex, version, schemas, config } from a proof-verified contract read.
 * Returns true when it is exactly the publication this flow makes, and refuses on anything else,
 * naming the difference.
 */
function requirePublished({ served, expectedIdHex, writerIdHex }) {
  if (!served || typeof served !== "object") refuse("no served contract");
  if (served.idHex !== expectedIdHex) refuse(`the served contract is ${String(served.idHex).slice(0, 12)}..., not the expected ${expectedIdHex.slice(0, 12)}...`);
  if (served.ownerIdHex !== writerIdHex) refuse("the served contract is not owned by the writer");
  if (served.version !== 1) refuse(`the served contract is at version ${served.version}, not 1`);
  if (canonicalString(plain(served.schemas || {})) !== canonicalString(buildApprovalSchemas())) {
    refuse(`the served schemas are not the source build (types: ${Object.keys(served.schemas || {}).sort().join(", ")})`);
  }
  // the WHOLE config, never a chosen subset (a review found a partial comparison passed a contract
  // whose other settings differed from the source build)
  if (!served.config || typeof served.config !== "object") refuse("the served contract carries no config");
  if (canonicalString(plain(served.config)) !== canonicalString(CONTRACT_CONFIG)) {
    const diff = Object.keys({ ...CONTRACT_CONFIG, ...served.config }).filter((k) => served.config[k] !== CONTRACT_CONFIG[k]);
    refuse(`the served contract's config differs from the source build in ${diff.join(", ") || "its encoding"}`);
  }
  return true;
}

const pendingOk = (p) => p && typeof p === "object" && /^[0-9]+$/.test(String(p.nonce)) && /^[0-9a-f]+$/.test(p.bytesHex || "")
  && sha256(p.bytesHex) === p.sha256 && typeof p.contractIdB58 === "string" && HEX64.test(p.contractIdHex || "");

/**
 * THE WHOLE PUBLICATION PATH over injected reads and writes. deps:
 *   matchedKeys()                     identity A's published keys its wallet matched
 *   readStore()                       { id, pending } from the settings store (pending parsed, or null)
 *   writeId(idB58), writePending(record), clearPending()
 *   readIdentityNonce()               identity A's current identity nonce, by proof (BigInt)
 *   readContract(idB58)               { status: "present", served } by proof, or { status: "not-found" };
 *                                     throws on any other failure
 *   buildSignedCreate({ nonce, key }) { bytesHex, size, contractIdB58, contractIdHex, serializedSize },
 *                                     the source build with CONTRACT_CONFIG, signed with exactly `key`
 *   contractIdHexFor(nonce)           the identifier a contract by A at `nonce` must have, derived
 *                                     separately from the build
 *   broadcast(bytesHex)               broadcasts those exact bytes, settles, and returns an outcome token
 *   sleep(ms), log(line)
 * Returns { outcome, ... } with outcome one of "dry-run", "published", "already-published",
 * "unresolved". Everything else throws.
 */
async function runApprovalPublication({ deps, confirmed, writerIdHex }) {
  for (const k of ["matchedKeys", "readStore", "writeId", "writePending", "clearPending", "readIdentityNonce",
    "readContract", "buildSignedCreate", "contractIdHexFor", "broadcast", "sleep", "log"]) {
    if (!deps || typeof deps[k] !== "function") refuse(`runApprovalPublication needs deps.${k}`);
  }
  if (!HEX64.test(writerIdHex || "")) refuse("writerIdHex must be 64 lowercase hex characters");
  const key = chooseSigningKey(await deps.matchedKeys(), "HIGH");
  const store = await deps.readStore();

  const readBack = async (idB58, idHex) => {
    const r = await deps.readContract(idB58);
    if (!r || (r.status !== "present" && r.status !== "not-found")) refuse("the contract read answered neither present nor not-found");
    if (r.status === "present") requirePublished({ served: r.served, expectedIdHex: idHex, writerIdHex });
    return r.status;
  };
  const settle = async (pending) => {
    for (let i = 0; i < REREADS; i++) {
      if (await readBack(pending.contractIdB58, pending.contractIdHex) === "present") {
        await deps.writeId(pending.contractIdB58);
        await deps.clearPending();
        return { outcome: "published", contractIdB58: pending.contractIdB58 };
      }
      if (i < REREADS - 1) await deps.sleep(5000);
    }
    return { outcome: "unresolved", reason: "not-read-back", contractIdB58: pending.contractIdB58 };
  };

  if (store && store.id !== undefined && store.id !== null) {
    const stored = typeof store.id === "string" ? decodeId32(store.id) : null;
    if (!stored) refuse(`${ID_KEY} is set but does not decode to a 32-byte identifier; this needs a human decision`);
    const r = await deps.readContract(store.id);
    if (!r || r.status !== "present") refuse(`${ID_KEY} is set but the contract is not read back by proof; this needs a human decision`);
    requirePublished({ served: r.served, expectedIdHex: stored.toString("hex"), writerIdHex });
    return { outcome: "already-published", contractIdB58: store.id };
  }

  const pending = store && store.pending;
  if (pending !== undefined && pending !== null) {
    if (!pendingOk(pending)) refuse(`${PENDING_KEY} is malformed; it needs a human decision`);
    if (await readBack(pending.contractIdB58, pending.contractIdHex) === "present") {
      if (!confirmed) return { outcome: "dry-run", published: true, contractIdB58: pending.contractIdB58 };
      await deps.writeId(pending.contractIdB58);
      await deps.clearPending();
      return { outcome: "published", contractIdB58: pending.contractIdB58 };
    }
    const tip = BigInt(await deps.readIdentityNonce());
    if (tip >= BigInt(pending.nonce)) {
      deps.log(`UNRESOLVED: the contract is not found and identity A's nonce is ${tip}, at or past the recorded ${pending.nonce}. A nonce below the tip can still execute if it was skipped and lies within 24 of the tip, so the recorded bytes are not shown to be dead. Nothing was sent and the record is kept.`);
      return { outcome: "unresolved", reason: "nonce-at-or-past", recordedNonce: String(pending.nonce), currentNonce: String(tip) };
    }
    if (!confirmed) return { outcome: "dry-run", resend: true, nonce: String(pending.nonce), contractIdB58: pending.contractIdB58 };
    deps.log(`RESENDING the recorded publication unchanged (nonce ${pending.nonce}); no new transition is built`);
    deps.log(`broadcast outcome: ${await deps.broadcast(pending.bytesHex)}`);
    return settle(pending);
  }

  const nonce = BigInt(await deps.readIdentityNonce()) + 1n;
  const signed = await deps.buildSignedCreate({ nonce, key });
  if (!signed || typeof signed.bytesHex !== "string" || !Number.isInteger(signed.size) || !HEX64.test(signed.contractIdHex || "")) {
    refuse("the signed publication was not returned");
  }
  if (signed.size !== Buffer.from(signed.bytesHex, "hex").length) refuse("the reported size is not the signed bytes' length");
  if (signed.contractIdHex !== await deps.contractIdHexFor(nonce)) refuse(`the built contract's identifier is not the one identity A's nonce ${nonce} gives`);
  if (signed.size > MAX_STATE_TRANSITION_SIZE) refuse(`the signed publication is ${signed.size} bytes, above ${MAX_STATE_TRANSITION_SIZE}`);
  if (await readBack(signed.contractIdB58, signed.contractIdHex) === "present") refuse("a contract already exists at the identifier of A's next nonce");
  const plan = { nonce: String(nonce), size: signed.size, serializedSize: signed.serializedSize, keyId: key.keyId,
    contractIdB58: signed.contractIdB58, sha256: sha256(signed.bytesHex) };
  if (!confirmed) return { outcome: "dry-run", resend: false, ...plan };
  const record = { nonce: String(nonce), bytesHex: signed.bytesHex, sha256: plan.sha256,
    contractIdB58: signed.contractIdB58, contractIdHex: signed.contractIdHex };
  await deps.writePending(record);
  deps.log(`broadcast outcome: ${await deps.broadcast(signed.bytesHex)}`);
  return { ...(await settle(record)), plan };
}

module.exports = { PENDING_KEY, ID_KEY, MAX_STATE_TRANSITION_SIZE, requirePublished, runApprovalPublication };
