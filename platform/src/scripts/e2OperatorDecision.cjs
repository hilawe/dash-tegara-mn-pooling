/**
 * THE OPERATOR'S RESEND DECISION. When a header, reservation or transfer was marked sent and its
 * outcome stays unresolved, the writer waits on it at every run and never sends it again. That is
 * right while the transition may still be in flight, and it is a dead end when Platform never
 * received it, which a live run with Platform's gateway stopped at the broadcast produced on
 * 2026-09-23. This module is the exit: an operator journals a decision to resend the IDENTICAL
 * persisted bytes, and the next distribution run resends them once and waits for the result.
 *
 * WHAT IT DOES. Under the pool's operation lock, the same lock every distribution run holds, so a
 * decision cannot interleave with a run, it reads the pool's validated journal and refuses unless
 * the subject's current generation is in the "sent" state: written ahead, marked sent, and no
 * outcome recorded. It then appends two records through the writer's validated append, the
 * surfacing declaration `<object>-unresolved` and the decision `rebroadcast-identical`.
 *
 * WHAT IT DOES NOT DO. It sends nothing and reads no network. It does not establish that the
 * transition failed to arrive, and it does not need to, because a resend of identical bytes is
 * safe whether or not the first one arrived, on the basis below. The writer then follows whatever
 * result the resend produces through its ordinary outcome table.
 *
 * THE SAFETY BASIS DIFFERS BY OBJECT, and each decision records its own in the reasoning.
 *   - transfer: duty D6, accepted 2026-08-28 (`tegara/docs/E2_BUILD_SPEC.md`, D6). Identical signed
 *     credit-transfer bytes carry the same identity nonce, which consensus refuses once used, so
 *     they execute at most once.
 *   - reservation: the contract's unique `byAccrual` index (`contractV11.cjs`) admits one
 *     reservation per accrual, however many times its bytes are submitted, and the transfer it is
 *     bound to is never rebuilt.
 *   - header: the contract's unique `byPoolEpoch` index admits one header per pool and epoch.
 * D6 as accepted covers credit transfers only. The document-create cases rest on the unique indexes
 * instead, and no claim is made that identical document-create bytes are refused by their nonce.
 * `d6Status` records D6's state when the decision was taken, as the spec requires.
 *
 * CLI, run on the host with the pool's store selected:
 *   TEGARA_ENV_PATH=<abs path to .env.X> node src/scripts/e2OperatorDecision.cjs unresolved <poolId>
 *     lists every header, reservation and transfer marked sent with no outcome, one per line
 *   TEGARA_ENV_PATH=<abs path to .env.X> node src/scripts/e2OperatorDecision.cjs \
 *     rebroadcast <poolId> <header|reservation|transfer> <epochIndex> [<accrualId>] --reason "<text>"
 *   TEGARA_ENV_PATH=<abs path to .env.X> node src/scripts/e2OperatorDecision.cjs \
 *     rebuild-reservation <poolId> <epochIndex> <accrualId> --reason "<text>"
 *   TEGARA_ENV_PATH=<abs path to .env.X> node src/scripts/e2OperatorDecision.cjs \
 *     rebuild-transfer <poolId> <epochIndex> <accrualId> --reason "<text>"
 *
 * THE REPLACEMENT (docs/NONCE_OWNERSHIP.md, the replacement rule). A new transfer generation is
 * authorized only when the journal holds the collision observation for the current one (R2) and
 * the accrual's reservation has not succeeded; the writer then proves on the ledger that the accrual
 * holds no reservation (R1) before building anything. When the accrual's reservation create was
 * refused, the matching reservation rebuild is journaled too, so the new transfer can be bound.
 *
 * THE REBUILD (a soundness-review finding). A resend helps only while the bytes can still execute. Once the signer's nonce
 * has moved past them for good, identical bytes are refused forever, and a reservation's accrual can
 * be paid only through a NEW reservation bound to the same transfer. The decision is accepted only
 * when the journal already holds the proved observation that the reservation's bytes can never
 * execute, which a distribution run journals when it finds so. The writer then rebuilds only after
 * the ledger proves that no reservation exists for the accrual, so the old bytes never executed
 * either. A transfer has no such exit: its reservation fixes the accrual to that transfer's hash.
 */
const envStore = require("./envStore.cjs");
const { openValidatedJournal, K } = require("./e2Journal.cjs");
const { appendChecked, poolRunLockName } = require("./e2Distribute.cjs");

const refuse = (why) => { throw new Error(`e2OperatorDecision: ${why}; refusing`); };
const HEX32 = /^[0-9a-f]{64}$/;

// D6 was accepted on 2026-08-28; a decision records that state, never a guess about it
const D6_STATUS = "closed";
const BASIS = Object.freeze({
  transfer: "identical credit-transfer bytes execute at most once (duty D6, accepted 2026-08-28)",
  reservation: "the unique byAccrual index admits one reservation per accrual, and the bound transfer is never rebuilt",
  header: "the unique byPoolEpoch index admits one header per pool and epoch",
});

/** The subject's current view from the validated journal, or null when it has none. */
const viewOf = (read, object, epochIndex, accrualId) => {
  const e = read.perEpoch && read.perEpoch[epochIndex];
  if (!e) return null;
  if (object === "header") return e.header || null;
  return (e.accruals && e.accruals[accrualId] && e.accruals[accrualId][object]) || null;
};

/**
 * unresolvedSubjects(read) -> [{ object, epochIndex, accrualId, gen }]
 *
 * Every broadcast subject in the "sent" state, marked sent with no outcome, in epoch then accrual
 * order. This is what an operator can authorize a resend for, and nothing else.
 */
const unresolvedSubjects = (read) => {
  const out = [];
  const epochs = Object.keys((read && read.perEpoch) || {}).map(Number).sort((a, b) => a - b);
  for (const e of epochs) {
    const ep = read.perEpoch[e];
    if (ep.header && ep.header.state === "sent") out.push({ object: "header", epochIndex: e, gen: ep.header.gen });
    for (const a of Object.keys(ep.accruals || {}).sort()) {
      for (const object of ["reservation", "transfer"]) {
        const v = ep.accruals[a][object];
        if (v && v.state === "sent") out.push({ object, epochIndex: e, accrualId: a, gen: v.gen });
      }
    }
  }
  return out;
};

/**
 * listUnresolved(poolId, dir) -> unresolvedSubjects of the pool's journal, read UNDER THE POOL'S
 * LOCK, because opening a journal truncates a partly written final record, which must never race a
 * distribution run that is appending one.
 */
const listUnresolved = (poolId, dir) => {
  if (typeof poolId !== "string" || !HEX32.test(poolId)) refuse("the pool identifier must be 64 lowercase hex");
  envStore.acquireOpLock(poolRunLockName(poolId));
  try { return unresolvedSubjects(openValidatedJournal(poolId, dir)); }
  finally { envStore.releaseOpLock(poolRunLockName(poolId)); }
};

/**
 * authorizeRebroadcast({ poolId, object, epochIndex, accrualId, reasoning, dir })
 *   -> { poolId, object, epochIndex, accrualId, gen, basis }
 */
const authorizeRebroadcast = ({ poolId, object, epochIndex, accrualId, reasoning, dir } = {}) => {
  if (typeof poolId !== "string" || !HEX32.test(poolId)) refuse("the pool identifier must be 64 lowercase hex");
  if (!Object.prototype.hasOwnProperty.call(BASIS, object)) refuse(`the object must be header, reservation or transfer, not ${JSON.stringify(object)}`);
  if (!Number.isSafeInteger(epochIndex) || epochIndex < 0 || epochIndex > 0xffffffff) refuse("the epoch index must be a u32 integer");
  if (object === "header") {
    if (accrualId !== undefined) refuse("a header decision names no accrual");
  } else if (typeof accrualId !== "string" || !HEX32.test(accrualId)) {
    refuse(`a ${object} decision needs the accrual identifier as 64 lowercase hex`);
  }
  if (typeof reasoning !== "string" || reasoning.trim().length === 0) refuse("the operator's reasoning is required");

  envStore.acquireOpLock(poolRunLockName(poolId));
  try {
    const read = openValidatedJournal(poolId, dir);
    const view = viewOf(read, object, epochIndex, accrualId);
    if (!view) refuse(`the journal holds no ${object} for this subject`);
    if (view.state !== "sent") {
      refuse(`the ${object} is ${JSON.stringify(view.state)}, and only one marked sent with no outcome can be resent`);
    }
    const gen = view.gen;
    if (!Number.isSafeInteger(gen) || gen < 1) refuse("the subject's current generation could not be read");
    // already licensed: the subject's last record is a decision no marker has consumed yet
    const same = (r) => r.object === object && r.epochIndex === epochIndex
      && (r.accrualId ?? null) === (accrualId ?? null) && (r.partIndex ?? null) === null;
    const last = read.records.filter(same).pop();
    if (last && last.kind === K.DECISION && last.action === "rebroadcast-identical") {
      refuse("a resend is already authorized and not yet used; run the distribution to act on it");
    }
    const subject = { poolId, epochIndex, ...(object === "header" ? {} : { accrualId }) };
    const basis = BASIS[object];
    appendChecked(poolId, dir, { v: 1, kind: K.DECLARATION, object, gen, ...subject,
      condition: `${object}-unresolved`, reasoning: reasoning.trim() });
    appendChecked(poolId, dir, { v: 1, kind: K.DECISION, object, gen, ...subject,
      condition: `${object}-unresolved`, action: "rebroadcast-identical", d6Status: D6_STATUS,
      reasoning: `${reasoning.trim()} | basis: ${basis}` });
    return { poolId, object, epochIndex, accrualId, gen, basis };
  } finally {
    envStore.releaseOpLock(poolRunLockName(poolId));
  }
};

const REBUILD_BASIS = "the persisted reservation can never execute (a proved nonce observation), the writer rebuilds only " +
  "after the ledger proves no reservation exists for the accrual, and the rebuilt reservation binds the same transfer";

/**
 * authorizeRebuildReservation({ poolId, epochIndex, accrualId, reasoning, dir })
 *   -> { poolId, epochIndex, accrualId, gen, basis }
 */
const authorizeRebuildReservation = ({ poolId, epochIndex, accrualId, reasoning, dir } = {}) => {
  if (typeof poolId !== "string" || !HEX32.test(poolId)) refuse("the pool identifier must be 64 lowercase hex");
  if (!Number.isSafeInteger(epochIndex) || epochIndex < 0 || epochIndex > 0xffffffff) refuse("the epoch index must be a u32 integer");
  if (typeof accrualId !== "string" || !HEX32.test(accrualId)) refuse("a reservation decision needs the accrual identifier as 64 lowercase hex");
  if (typeof reasoning !== "string" || reasoning.trim().length === 0) refuse("the operator's reasoning is required");
  envStore.acquireOpLock(poolRunLockName(poolId));
  try {
    const read = openValidatedJournal(poolId, dir);
    const view = viewOf(read, "reservation", epochIndex, accrualId);
    if (!view) refuse("the journal holds no reservation for this subject");
    if (view.state !== "sent") {
      refuse(`the reservation is ${JSON.stringify(view.state)}, and only one marked sent with no outcome can be rebuilt this way`);
    }
    const gen = view.gen;
    const mine = (r) => r.object === "reservation" && r.epochIndex === epochIndex && r.accrualId === accrualId && r.gen === gen;
    if (!read.records.some((r) => mine(r) && r.kind === K.OBSERVATION && r.observationType === "nonce-unusable")) {
      refuse("the journal holds no proved observation that this reservation's bytes can never execute; run the distribution, which checks and records it");
    }
    if (read.records.some((r) => mine(r) && r.kind === K.DECISION && r.action === "rebuild-reservation")) {
      refuse("a rebuild is already authorized for this generation; run the distribution to act on it");
    }
    const subject = { poolId, epochIndex, accrualId };
    appendChecked(poolId, dir, { v: 1, kind: K.DECLARATION, object: "reservation", gen, ...subject,
      condition: "reservation-bytes-unusable", reasoning: reasoning.trim() });
    appendChecked(poolId, dir, { v: 1, kind: K.DECISION, object: "reservation", gen, ...subject,
      condition: "reservation-bytes-unusable", action: "rebuild-reservation", d6Status: D6_STATUS,
      reasoning: `${reasoning.trim()} | basis: ${REBUILD_BASIS}` });
    return { poolId, epochIndex, accrualId, gen, basis: REBUILD_BASIS };
  } finally {
    envStore.releaseOpLock(poolRunLockName(poolId));
  }
};

const REPLACE_BASIS = "another accrual holds a ledger claim on the current transfer's bytes (a journaled collision " +
  "observation); the writer replaces only after the ledger proves this accrual holds no reservation, so its only " +
  "reservation binds the replacement and one payment per accrual holds";

/**
 * authorizeTransferReplacement({ poolId, epochIndex, accrualId, reasoning, dir })
 *   -> { poolId, epochIndex, accrualId, gen, alsoReservation, basis }
 */
const authorizeTransferReplacement = ({ poolId, epochIndex, accrualId, reasoning, dir } = {}) => {
  if (typeof poolId !== "string" || !HEX32.test(poolId)) refuse("the pool identifier must be 64 lowercase hex");
  if (!Number.isSafeInteger(epochIndex) || epochIndex < 0 || epochIndex > 0xffffffff) refuse("the epoch index must be a u32 integer");
  if (typeof accrualId !== "string" || !HEX32.test(accrualId)) refuse("a transfer decision needs the accrual identifier as 64 lowercase hex");
  if (typeof reasoning !== "string" || reasoning.trim().length === 0) refuse("the operator's reasoning is required");
  envStore.acquireOpLock(poolRunLockName(poolId));
  try {
    const read = openValidatedJournal(poolId, dir);
    const t = viewOf(read, "transfer", epochIndex, accrualId);
    if (!t) refuse("the journal holds no transfer for this subject");
    const gen = t.gen;
    const mine = (object, g) => (r) => r.object === object && r.epochIndex === epochIndex && r.accrualId === accrualId && r.gen === g;
    if (!read.records.some((r) => mine("transfer", gen)(r) && r.kind === K.OBSERVATION && r.observationType === "transfer-owned-elsewhere")) {
      refuse("the journal holds no observation that another accrual claims this transfer's bytes; run the distribution, which checks and records it");
    }
    if (read.records.some((r) => mine("transfer", gen)(r) && r.kind === K.DECISION && r.action === "rebuild-transfer")) {
      refuse("a replacement is already authorized for this generation; run the distribution to act on it");
    }
    const res = viewOf(read, "reservation", epochIndex, accrualId);
    if (res && res.state === "held") {
      refuse("this accrual's reservation succeeded and binds the current bytes; it is immutable under contract v11, so no replacement could be excluded by the ledger");
    }
    const subject = { poolId, epochIndex, accrualId };
    appendChecked(poolId, dir, { v: 1, kind: K.DECLARATION, object: "transfer", gen, ...subject,
      condition: "transfer-owned-elsewhere", reasoning: reasoning.trim() });
    appendChecked(poolId, dir, { v: 1, kind: K.DECISION, object: "transfer", gen, ...subject,
      condition: "transfer-owned-elsewhere", action: "rebuild-transfer", d6Status: D6_STATUS,
      reasoning: `${reasoning.trim()} | basis: ${REPLACE_BASIS}` });
    // the refused reservation must open a new generation too, bound to the replacement
    let alsoReservation = false;
    if (res && res.state === "refused"
      && !read.records.some((r) => mine("reservation", res.gen)(r) && r.kind === K.DECISION && r.action === "rebuild-reservation")) {
      appendChecked(poolId, dir, { v: 1, kind: K.DECLARATION, object: "reservation", gen: res.gen, ...subject,
        condition: "reservation-refused", reasoning: `${reasoning.trim()} (the transfer it bound belongs to another accrual)` });
      appendChecked(poolId, dir, { v: 1, kind: K.DECISION, object: "reservation", gen: res.gen, ...subject,
        condition: "reservation-refused", action: "rebuild-reservation", d6Status: D6_STATUS,
        reasoning: `${reasoning.trim()} | basis: the new reservation binds the replacement transfer` });
      alsoReservation = true;
    }
    return { poolId, epochIndex, accrualId, gen, alsoReservation, basis: REPLACE_BASIS };
  } finally {
    envStore.releaseOpLock(poolRunLockName(poolId));
  }
};

module.exports = { authorizeRebroadcast, authorizeRebuildReservation, authorizeTransferReplacement,
  unresolvedSubjects, listUnresolved, BASIS, REBUILD_BASIS, REPLACE_BASIS, D6_STATUS };

if (require.main === module) {
  const args = process.argv.slice(2);
  const at = args.indexOf("--reason");
  const reasoning = at >= 0 ? args[at + 1] : undefined;
  const pos = at >= 0 ? args.slice(0, at) : args;
  const [mode, poolId, object, epochStr, accrualId] = pos;
  try {
    if (mode === "unresolved") {
      for (const u of listUnresolved(poolId)) {
        console.log([u.object, u.epochIndex, u.accrualId || "-", u.gen].join(" "));
      }
      return;
    }
    if (mode === "rebuild-transfer") {
      const [, pid, ep, acc] = pos;
      if (!/^[0-9]+$/.test(ep || "")) refuse("the epoch index must be a decimal integer");
      const r = authorizeTransferReplacement({ poolId: pid, epochIndex: Number(ep), accrualId: acc, reasoning });
      console.log(`replacement AUTHORIZED for the transfer of pool ${r.poolId.slice(0, 12)}..., epoch ${r.epochIndex}, accrual ${r.accrualId.slice(0, 12)}..., generation ${r.gen}` +
        (r.alsoReservation ? ", with the refused reservation's rebuild" : "") + ".");
      console.log(`basis: ${r.basis}`);
      console.log("the next distribution run proves the accrual holds no reservation, then builds a new transfer and binds it");
      return;
    }
    if (mode === "rebuild-reservation") {
      // positions shift by one: no object argument for this mode
      const [, pid, ep, acc] = pos;
      if (!/^[0-9]+$/.test(ep || "")) refuse("the epoch index must be a decimal integer");
      const r = authorizeRebuildReservation({ poolId: pid, epochIndex: Number(ep), accrualId: acc, reasoning });
      console.log(`rebuild AUTHORIZED for the reservation of pool ${r.poolId.slice(0, 12)}..., epoch ${r.epochIndex}, accrual ${r.accrualId.slice(0, 12)}..., generation ${r.gen}.`);
      console.log(`basis: ${r.basis}`);
      console.log("the next distribution run checks the ledger for no reservation, then builds a new one bound to the same transfer");
      return;
    }
    if (mode !== "rebroadcast") refuse("usage: rebroadcast <poolId> <header|reservation|transfer> <epochIndex> [<accrualId>] --reason \"<text>\"");
    if (!/^[0-9]+$/.test(epochStr || "")) refuse("the epoch index must be a decimal integer");
    const r = authorizeRebroadcast({ poolId, object, epochIndex: Number(epochStr), accrualId, reasoning });
    console.log(`resend AUTHORIZED for the ${r.object} of pool ${r.poolId.slice(0, 12)}..., epoch ${r.epochIndex}` +
      `${r.accrualId ? `, accrual ${r.accrualId.slice(0, 12)}...` : ""}, generation ${r.gen}.`);
    console.log(`basis: ${r.basis}`);
    console.log("the next distribution run resends the identical persisted bytes once and waits for the result");
  } catch (e) {
    console.error(String((e && e.message) || e));
    process.exitCode = 1;
  }
}
