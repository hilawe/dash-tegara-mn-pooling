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

module.exports = { authorizeRebroadcast, unresolvedSubjects, listUnresolved, BASIS, D6_STATUS };

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
