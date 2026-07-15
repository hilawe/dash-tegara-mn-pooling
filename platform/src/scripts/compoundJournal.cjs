/**
 * The compound journal: the LOCAL record of which earned rewards a member has already
 * turned into join requests, enforcing the compound ceiling (earned rewards minus
 * rewards already compounded). The data contract has no provenance field on a join
 * (recorded for the next contract revision), so this ceiling is client-side discipline,
 * not a ledger rule; the ledger sees plain join requests.
 *
 * Protocol (shaped by the independent review of the first version, findings 1-6):
 *   reserve   BEFORE broadcasting the join: under the lock, reload the env, validate the
 *             journal, recompute the ceiling, and persist the entry as "pending". The
 *             debit is durable before the slow network operation, so a crash after
 *             broadcast can never double-spend the ceiling.
 *   confirm   after a successful broadcast: mark the entry "confirmed".
 *   release   remove an entry (a failed broadcast, or a cancelled request).
 *   reconcile heal from any crash: an entry whose request document is MISSING from the
 *             ledger is freed, because request documents are deleted only by their owner
 *             through cancel, so "missing" means either the broadcast never landed or
 *             the request was later cancelled; in both cases the rewards are honestly
 *             uncompounded again. An entry still "pending" whose document EXISTS is
 *             promoted to confirmed (the crash fell between broadcast and confirm).
 *
 * Keying: one env key per (resolved contract id, member identity id), derived by hash
 * because env keys are [A-Z0-9_] and the ids are base58. The ids are ALSO stored inside
 * the value and verified on load, so a key collision or a copied value fails closed.
 * All amounts are canonical decimal strings, summed as BigInt.
 *
 * Locking: the shared env-file lock (envStore.lockEnv, a mkdir lock beside .env.local)
 * serializes journal mutations AND foreign saveEnv calls within one filesystem (host
 * runs, or runs inside one container), so neither side can clobber the other. Two
 * SIMULTANEOUS containers do not share the lock path; for that case the protection is
 * reserve-before-broadcast, which shrinks the race to the instant between two reserves
 * rather than the whole broadcast latency, plus the merge-read under the lock. This
 * residual is a devnet client trade-off and is stated here rather than papered over.
 */
const crypto = require("crypto");
const { loadEnv, saveEnv, lockEnv, unlockEnv } = require("./envStore.cjs");

const STATES = ["pending", "confirmed"];
const CANONICAL = /^(0|[1-9][0-9]*)$/;
const BASE58_ID = /^[1-9A-HJ-NP-Za-km-z]{40,50}$/;
// payout entries (the autopay sweep, G4) consume the same ceiling as compounds: a reward
// can be compounded or paid out, never both. They have no ledger document, so their key
// is a client-minted id and reconcile leaves them alone (nothing on the ledger can
// confirm or refute them; the consumption is conservative by construction).
const PAYOUT_ID = /^payout-[0-9a-f]{32}$/;
const MAX_SUPPLY_DUFFS = 2100000000000000n; // 21M DASH

/** Convert a BigInt to Number only when provably safe; the guard every value must pass
 *  before crossing an SDK Number boundary (independent-review finding: a duffs-level
 *  check does not cover the ×1000 credits conversion). */
const toSafeNumber = (big, what) => {
  if (typeof big !== "bigint") throw new Error(`${what} must be a BigInt`);
  if (big < 0n) throw new Error(`${what} is negative`);
  if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${what} (${big}) exceeds the SDK's safe Number range`);
  }
  return Number(big);
};

/** Parse any amount representation into a validated BigInt (throws on anything
 *  non-canonical, so a rounded Number or a decorated string never reaches the math). */
const toBig = (v, what) => {
  const s = typeof v === "bigint" ? v.toString() : String(v);
  if (!CANONICAL.test(s)) throw new Error(`${what} is not a canonical non-negative integer: "${s}"`);
  const b = BigInt(s);
  if (b > MAX_SUPPLY_DUFFS) throw new Error(`${what} exceeds the coin supply: ${s}`);
  return b;
};

// the shared (contract, member) namespace suffix; AUTOPAY_* preference keys reuse it so
// every member-and-contract-scoped value follows one keying rule
const suffixFor = (contractId, memberId) =>
  crypto.createHash("sha256").update(`${contractId}|${memberId}`).digest("hex").slice(0, 20).toUpperCase();
const keyFor = (contractId, memberId) => "COMPOUND_" + suffixFor(contractId, memberId);

const parseJournal = (raw, contractId, memberId, key) => {
  // only a genuinely ABSENT key means "no journal yet"; an empty or truncated value is
  // treated as corruption, never silently replaced (re-check finding)
  if (raw === undefined) return { contractId, memberId, entries: {} };
  const fail = (why) => {
    throw new Error(`the compound journal ${key} failed validation (${why}); restore from .env.local.prev`);
  };
  if (raw === "") fail("empty value");
  let j;
  try { j = JSON.parse(raw); } catch { fail("corrupt JSON"); }
  if (!j || typeof j !== "object" || Array.isArray(j)) fail("not an object");
  // EXACT shape, nothing extra tolerated (re-check finding): three top-level
  // properties, two per entry
  if (Object.keys(j).sort().join(",") !== "contractId,entries,memberId") fail("unexpected top-level shape");
  if (j.contractId !== contractId || j.memberId !== memberId) fail("recorded for a different contract or member");
  if (!j.entries || typeof j.entries !== "object" || Array.isArray(j.entries)) fail("entries is not an object");
  for (const [id, e] of Object.entries(j.entries)) {
    if (!e || typeof e !== "object" || Array.isArray(e)) fail(`entry ${id} is malformed`);
    // exact shapes: a compound entry (no kind; key is the join document id) or a payout
    // entry (kind "payout", always confirmed; key is the client-minted id), each with an
    // optional `at` write-time stamp (holistic-round F1: reconcile age-gates its frees
    // on it; an entry without one, from before the stamp existed, reads as age 0 and is
    // therefore always old enough)
    const shape = Object.keys(e).sort().join(",");
    if (shape === "amount,state" || shape === "amount,at,state") {
      if (!BASE58_ID.test(id)) fail(`entry key "${id}" is not a document id`);
    } else if (shape === "amount,kind,state" || shape === "amount,at,kind,state") {
      if (e.kind !== "payout") fail(`entry ${id} has kind "${e.kind}"`);
      if (!PAYOUT_ID.test(id)) fail(`entry key "${id}" is not a payout id`);
      if (e.state !== "confirmed") fail(`payout entry ${id} must be confirmed, is "${e.state}"`);
    } else fail(`entry ${id} has an unexpected shape`);
    if (e.at !== undefined && (!Number.isSafeInteger(e.at) || e.at < 0)) {
      fail(`entry ${id} has a malformed at stamp`);
    }
    if (!STATES.includes(e.state)) fail(`entry ${id} has state "${e.state}"`);
    if (typeof e.amount !== "string" || !CANONICAL.test(e.amount) || e.amount === "0") {
      fail(`entry ${id} amount is not a canonical positive integer string`);
    }
    if (BigInt(e.amount) > MAX_SUPPLY_DUFFS) fail(`entry ${id} amount exceeds the coin supply`);
  }
  return j;
};

/** Every mutation is lock -> reload -> validate -> mutate -> save, so concurrent runs on
 *  one filesystem always merge through the freshest on-disk state. The lock is the
 *  shared env-file lock in envStore, which FOREIGN saveEnv calls also hold across their
 *  own reload-and-write (review TOCTOU finding), so neither side can clobber the other;
 *  contention surfaces as a loud refusal. */
const mutate = (contractId, memberId, fn) => {
  lockEnv();
  try {
    const env = loadEnv();
    const key = keyFor(contractId, memberId);
    const journal = parseJournal(env[key], contractId, memberId, key);
    const result = fn(journal);
    env[key] = JSON.stringify(journal);
    saveEnv(env, { journalOwner: true });
    return result;
  } finally { unlockEnv(); }
};

const compoundedTotal = (journal) =>
  Object.values(journal.entries).reduce((s, e) => s + BigInt(e.amount), 0n);

module.exports = {
  toBig,
  toSafeNumber,
  keyFor,
  suffixFor,
  MAX_SUPPLY_DUFFS,

  /** Mint a payout entry id (no ledger document exists for a sweep). */
  newPayoutId() { return `payout-${crypto.randomBytes(16).toString("hex")}`; },

  /** Read-only view: entries and the consumed total (compounds AND payouts, both of
   *  which spend the same ceiling). */
  summary(contractId, memberId) {
    const key = keyFor(contractId, memberId);
    const journal = parseJournal(loadEnv()[key], contractId, memberId, key);
    return { entries: journal.entries, consumedDuffs: compoundedTotal(journal) };
  },

  /** Debit the ceiling BEFORE the broadcast. Recomputes the ceiling under the lock from
   *  the freshest journal; throws (nothing persisted) if the amount no longer fits.
   *  Returns the remaining uncompounded duffs. */
  reserve(contractId, memberId, requestId, amountDuffs, earnedDuffs) {
    const amount = toBig(amountDuffs, "reserve amount");
    const earned = toBig(earnedDuffs, "earned rewards");
    if (amount <= 0n) throw new Error("reserve amount must be positive");
    return mutate(contractId, memberId, (journal) => {
      if (journal.entries[requestId]) throw new Error(`request ${requestId} is already journaled`);
      const ceiling = earned - compoundedTotal(journal);
      if (amount > ceiling) {
        throw new Error(`compound of ${amount} duffs exceeds the uncompounded rewards ${ceiling} duffs`);
      }
      journal.entries[requestId] = { amount: amount.toString(), state: "pending", at: Date.now() };
      return ceiling - amount;
    });
  },

  /** Consume ceiling for a payout sweep (G4). Single-phase: the entry is written
   *  confirmed BEFORE the withdrawal is submitted, so a crash in between errs on the
   *  conservative side (ceiling consumed, no payout), which `compound status` surfaces
   *  and an explicit release can undo after the member verifies no payout landed. */
  reservePayout(contractId, memberId, payoutId, amountDuffs, earnedDuffs) {
    if (!PAYOUT_ID.test(payoutId)) throw new Error(`"${payoutId}" is not a payout id`);
    const amount = toBig(amountDuffs, "payout amount");
    const earned = toBig(earnedDuffs, "earned rewards");
    if (amount <= 0n) throw new Error("payout amount must be positive");
    return mutate(contractId, memberId, (journal) => {
      if (journal.entries[payoutId]) throw new Error(`payout ${payoutId} is already journaled`);
      const ceiling = earned - compoundedTotal(journal);
      if (amount > ceiling) {
        throw new Error(`payout of ${amount} duffs exceeds the uncompounded rewards ${ceiling} duffs`);
      }
      journal.entries[payoutId] = { amount: amount.toString(), state: "confirmed", kind: "payout", at: Date.now() };
      return ceiling - amount;
    });
  },

  /** Mark a reserved entry confirmed after its broadcast succeeded. */
  confirm(contractId, memberId, requestId) {
    mutate(contractId, memberId, (journal) => {
      const e = journal.entries[requestId];
      if (!e) throw new Error(`request ${requestId} is not journaled; reconcile before trusting the ceiling`);
      e.state = "confirmed";
    });
  },

  /** Free an entry (failed broadcast, or the request was cancelled). Returns the freed
   *  duffs as BigInt, or null if the entry was not present. */
  release(contractId, memberId, requestId) {
    return mutate(contractId, memberId, (journal) => {
      const e = journal.entries[requestId];
      if (!e) return null;
      delete journal.entries[requestId];
      return BigInt(e.amount);
    });
  },

  /** Heal after any crash. docExists(requestId) -> Promise<boolean> against the ledger.
   *  An existing document promotes a pending entry to confirmed. A MISSING document
   *  frees the entry ONLY once the entry is older than the reconcile age gate
   *  (holistic-round F1, converged across two reviewers): the ledger is eventually
   *  consistent, so "not found" right after a write is NOT authoritative evidence of
   *  absence, and freeing on it re-opens the ceiling while the document may still land.
   *  A young missing entry is reported and kept; the guarded manual release remains the
   *  member-verified escape hatch. opts: { now, minAgeMs } for tests and tuning
   *  (COMPOUND_RECONCILE_MIN_AGE_MS overrides the default 15 minutes). */
  async reconcile(contractId, memberId, docExists, log = () => {}, opts = {}) {
    const now = opts.now !== undefined ? opts.now : Date.now();
    let minAgeMs = opts.minAgeMs;
    if (minAgeMs === undefined) {
      // a malformed override must fail CLOSED to the default, never disable the gate;
      // the WHOLE value must be a canonical nonnegative integer (parseInt would read
      // "0oops" as 0 and "1e3" as 1, silently weakening the gate; re-check finding)
      const raw = process.env.COMPOUND_RECONCILE_MIN_AGE_MS;
      minAgeMs = (raw !== undefined && /^(0|[1-9][0-9]*)$/.test(raw)
        && Number.isSafeInteger(Number(raw))) ? Number(raw) : 900000;
    }
    const { entries } = this.summary(contractId, memberId);
    const report = [];
    for (const [id, e] of Object.entries(entries)) {
      // payout entries have no ledger document; nothing can confirm or refute them, so
      // reconcile leaves them alone (freeing one is an explicit, member-verified act)
      if (e.kind === "payout") continue;
      const exists = await docExists(id);
      if (!exists) {
        const age = now - (e.at || 0);
        if (age < minAgeMs) {
          report.push({ requestId: id, action: "kept-young" });
          log(`reconcile: request ${id} is not visible on the ledger yet, but the entry is only ` +
            `${Math.round(age / 1000)}s old (gate ${Math.round(minAgeMs / 1000)}s); keeping it ` +
            "reserved until absence is trustworthy");
          continue;
        }
        const freed = this.release(contractId, memberId, id);
        if (freed !== null) {
          report.push({ requestId: id, action: "freed", duffs: freed });
          log(`reconcile: request ${id} is gone from the ledger (never landed, or cancelled) and the ` +
            `entry is past the age gate; ${freed} duffs count as uncompounded again`);
        }
      } else if (e.state === "pending") {
        this.confirm(contractId, memberId, id);
        report.push({ requestId: id, action: "confirmed" });
        log(`reconcile: request ${id} exists on the ledger; pending entry promoted to confirmed`);
      }
    }
    return report;
  },
};
