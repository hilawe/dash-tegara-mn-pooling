/**
 * The E2 ADMISSION module (duty D10, the frozen reserve section as code): the
 * pinned balance observation, the durable per-identity freshness frontier,
 * the per-identity operation locks with their canonical acquisition order,
 * the store inventory through the D7 validator's composed read operation, and
 * the store-wide per-identity reserve thresholds with the candidate epoch.
 *
 * WHAT IT ESTABLISHES: no header is admitted unless every distinct identity's
 * threshold is met over a verified, version-pinned, chain-pinned,
 * frontier-fresh balance, with obligations grouped by ACTUAL identity across
 * every pool journal in the store, and one outstanding nonce-bearing
 * operation per identity among cooperating processes sharing the store's
 * state directory and lock namespace (the filesystem locks' honest scope).
 *
 * WHAT IT DOES NOT ESTABLISH, stated: a stale-but-signed balance at or above
 * the frontier remains possible (the frontier is a monotone floor, not
 * recency); the locks are local courtesy strength, so an instance outside
 * this store's namespace surfaces through the ordinary outcome machinery,
 * never here; and the one-outstanding-operation guarantee over a whole
 * operation (nonce read through awaited result) is DELIVERED BY THE
 * CONSUMERS holding these locks across their operations, while this module
 * enforces only the admission's own window and the header's exact lock set.
 * The reserve check is a SCREEN; the per-transition refusals stay normative
 * (the frozen text's own words).
 *
 * DIVERGENCES FROM THE FROZEN PROSE, resolved in code per the freeze rule
 * (divergences are resolved IN CODE and folded back as reviewed
 * corrections, marked in the spec):
 * - the per-positive-entitlement writer count is 10, one reservation plus
 *   at most 8 parts (the schema's proofPartCount maximum) plus the receipt
 *   document, where the prose's "9" omits one write;
 * - the threshold COMPARISON covers the candidate pool's distinct
 *   identities only; a threshold computed for another pool's distinct
 *   income identity is that pool's own admission's comparison, under its
 *   own locks, and this header adds no obligation to it (the frozen "every
 *   distinct identity" wording read literally would require locks the
 *   header's frozen lock set does not include);
 * - the writer's document writes NEVER discharge on journal evidence,
 *   because none exists: the journal records no document-write success,
 *   the receipt capture precedes the part and receipt-document writes,
 *   and a later epoch's header write-ahead proves only that the writer
 *   MOVED ON, not that the earlier writes landed (the fold re-check
 *   killed the successor inference as the same defect class as the
 *   receipt-capture one). They end only on terminal journaled stops,
 *   the header's for its epoch and an entitlement's own subject stop
 *   for that entitlement.
 *   The screen therefore over-reserves by the document-write fees of
 *   every non-stopped historical epoch, a cost that grows with the
 *   pool's history and is stated rather than inferred away; it can
 *   narrow only when a proved-presence evidence class exists (duty D8's
 *   audit reads are the candidate source).
 *
 * FUNDING IS STRICTLY OUT OF BAND (a soundness-review finding): this module constructs, signs
 * and broadcasts NOTHING. Its only externally-visible action is the injected
 * balance fetch, once per distinct identity, and the frontier file write.
 */
const fs = require("fs");
const path = require("path");
const envStore = require("./envStore.cjs");
const { openValidatedJournal } = require("./e2Journal.cjs");
const { canonicalString } = require("./canonicalJson.cjs");

const HEX64 = /^[0-9a-f]{64}$/;
const PROTOCOL_VERSION_PIN = 12;
// 1 reservation + up to 8 parts (proofPartCount maximum) + 1 receipt document
const WRITER_PER_ENTITLEMENT = 10n;

// DUTY D2'S RECORDED CONSTANTS, the MEASURE path (2026-08-28, the
// committed measurement run e2FeeMeasureRun.mjs on the harness devnet,
// chain pin dashmate_local_52 at protocol 12). Each figure is the
// larger of two samples of a MAXIMUM-payload broadcast's proved
// balance decrease (every schema byteArray at maxItems, every integer
// at its schema maximum; the credit transfer's amount excluded), plus
// ten percent headroom for the observed state-dependent variance (the
// inter-sample spread stayed under thirty percent, and the reserve
// formulas keep their own times-2 on top), rounded up to the next
// million credits (the derivation is asserted by the battery against
// the maxima below). The receipt and part maxima EXCEED the retired
// provisional 100000000 single constant, which therefore undercounted
// the writer reserve; this pin replaces it. The credit transfer's fee
// measured identically at the minimum amount and at a 10^12-credit
// amount, so the amount does not enter its fee at this schedule.
// Repeated measurement runs showed the document maxima DRIFTING
// upward slightly with ledger growth (under two percent per run, the
// first sample of a run the larger), which the ten percent headroom
// absorbs; the maxima below are the recorded authoritative run's, and
// any protocol or fee-schedule change re-measures. THE RE-MEASURE
// TRIGGER is stated rather than left to judgment: when any later
// run's raw maximum comes within five percent of its type's ceiling,
// re-measure and re-record (the drift samples after the authoritative
// run peaked at 279600244 for the receipt against its 305000000
// ceiling, an 8.3 percent margin).
const D2_MEASURED_MAX_FEES = Object.freeze({
  header: "30227725", accrual: "55585023", reservation: "47763004",
  receipt: "276610563", part: "197684183", creditTransfer: "900940",
});
const D2_FEE_CEILINGS = Object.freeze({
  header: "34000000", accrual: "62000000", reservation: "53000000",
  receipt: "305000000", part: "218000000", creditTransfer: "1000000",
});
const CEILING_TYPES = Object.freeze(["header", "accrual", "reservation", "receipt", "part", "creditTransfer"]);

const refuse = (why) => { throw new Error(`e2BalanceCheck: ${why}; refusing admission`); };

const requireHex64 = (name, v) => {
  if (typeof v !== "string" || !HEX64.test(v)) refuse(`${name} must be 64 lowercase hex characters`);
  return v;
};

// ---- the per-identity operation locks (the same filesystem mechanism as the
// per-pool operation lock, keyed by identity, local courtesy strength) ----
const identityLockName = (identityHex) => `e2-identity-${requireHex64("identity", identityHex)}`;

/**
 * Acquire EVERY lock of an operation's stated set up front, in ascending
 * order of the identities' raw 32-byte values, deduplicated (the canonical
 * order, so a header path and a transfer path can never wait in opposite
 * directions). On contention every already-acquired lock of the set is
 * released before the error propagates, so a refused acquisition holds
 * nothing. Returns { identities, holds } for the requireHeld checks and
 * release().
 */
const acquireIdentityLocks = (identityHexes) => {
  const sorted = [...new Set(identityHexes.map((h) => requireHex64("identity", h)))]
    .sort((a, b) => Buffer.compare(Buffer.from(a, "hex"), Buffer.from(b, "hex")));
  const acquired = [];
  try {
    for (const id of sorted) {
      envStore.acquireOpLock(identityLockName(id));
      acquired.push(id);
    }
  } catch (e) {
    for (const id of acquired.reverse()) {
      try { envStore.releaseOpLock(identityLockName(id)); } catch { /* release best-effort on the unwind */ }
    }
    throw e;
  }
  const held = new Set(sorted);
  return {
    identities: sorted,
    holds: (identityHex) => held.has(identityHex),
    release: () => {
      held.clear();
      for (const id of [...sorted].reverse()) envStore.releaseOpLock(identityLockName(id));
    },
  };
};

const requireHeld = (locks, identityHex, what) => {
  if (!locks || typeof locks.holds !== "function" || !locks.holds(identityHex)) {
    refuse(`${what} for ${identityHex.slice(0, 8)}... requires that identity's operation lock (read and updated only under it)`);
  }
};

// ---- the durable per-identity freshness frontier, store-wide ----
const frontierPath = (identityHex, dir) =>
  path.join(dir || envStore.STATE_DIR, `e2-frontier-${requireHex64("identity", identityHex)}.json`);

const DEC_RE = /^(0|[1-9][0-9]*)$/;

/**
 * Read the identity's frontier under its lock. A missing file is frontier
 * zero (the first observation seeds it); a malformed or mismatched file
 * REFUSES fail closed until the operator repairs it from journal evidence.
 */
const readFrontier = (identityHex, { dir, locks }) => {
  requireHeld(locks, identityHex, "the frontier read");
  const p = frontierPath(identityHex, dir);
  if (!fs.existsSync(p)) return 0n;
  const raw = fs.readFileSync(p, "utf8");
  let obj;
  try { obj = JSON.parse(raw); } catch { refuse(`frontier file ${path.basename(p)} is not valid JSON (repair it from journal evidence)`); }
  if (canonicalString(obj) !== raw) refuse(`frontier file ${path.basename(p)} is not the canonical serialization`);
  if (!obj || typeof obj !== "object" || Object.keys(obj).sort().join(",") !== "height,identity,v") {
    refuse(`frontier file ${path.basename(p)} must hold exactly v, identity and height`);
  }
  if (obj.v !== 1) refuse(`frontier file ${path.basename(p)} has an unknown version`);
  if (obj.identity !== identityHex) refuse(`frontier file ${path.basename(p)} names a different identity`);
  if (typeof obj.height !== "string" || !DEC_RE.test(obj.height)) {
    refuse(`frontier file ${path.basename(p)} height must be a canonical decimal string`);
  }
  return BigInt(obj.height);
};

const fsyncFile = (p) => { const fd = fs.openSync(p, "r"); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } };
const fsyncDir = (p) => { const fd = fs.openSync(path.dirname(p), "r"); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } };

/**
 * Advance the identity's frontier max-monotonically under its lock, by
 * write-to-temporary-then-atomic-rename so an interrupted update leaves the
 * prior value intact. A height at or below the current frontier is a no-op:
 * the frontier never moves backward.
 */
const advanceFrontier = (identityHex, height, { dir, locks }) => {
  requireHeld(locks, identityHex, "the frontier update");
  if (typeof height !== "bigint" || height < 0n) refuse("a frontier advance needs a non-negative BigInt height");
  const current = readFrontier(identityHex, { dir, locks });
  if (height <= current) return current;
  const p = frontierPath(identityHex, dir);
  const tmp = `${p}.tmp`;
  fs.writeFileSync(tmp, canonicalString({ v: 1, identity: identityHex, height: String(height) }));
  fsyncFile(tmp);
  fs.renameSync(tmp, p);
  fsyncDir(p);
  return height;
};

// ---- which evidence advances which identity ----
const { HEADER_KIND, RECEIPT_KIND } = require("./e2CaptureRecord.cjs");
const CAPTURE_ADVANCES = { [HEADER_KIND]: "writer", [RECEIPT_KIND]: "income" };

/**
 * A verified capture's metadata height advances the identity that signed
 * and sent the captured transition: the record writer for header captures,
 * the income identity for credit-transfer receipt captures (the frozen
 * which-evidence-advances-which-identity rule). The caller supplies the
 * VERIFIED height from the capture's authenticated metadata, under the
 * advanced identity's lock, before its next admission.
 */
const advanceFrontierFromCapture = ({ kind, height, identities }, { dir, locks }) => {
  const role = CAPTURE_ADVANCES[kind];
  if (!role) refuse(`capture kind ${JSON.stringify(kind)} is not one whose metadata advances a frontier`);
  const id = requireHex64(`the ${role} identity`, identities && identities[role]);
  return advanceFrontier(id, height, { dir, locks });
};

// ---- the pinned balance observation ----
/**
 * Read one identity's balance through the injected patched SDK export (the
 * named export getIdentityBalanceWithMetadata as mounted; injected here so
 * the refusal logic is testable offline). REFUSES: an unserved or unverified
 * result (the fetch throwing, or a result without the closed
 * { balance, metadata } shape); a chainId differing from the owned pin; an
 * authenticated protocolVersion other than 12; and a height below the
 * identity's durable store-wide frontier. On acceptance the frontier
 * advances from the verified height BEFORE admission. No stronger recency is
 * claimed than the monotone floor.
 */
const pinnedBalance = async (identityHex, { fetchWithMetadata, chainIdPin, dir, locks }) => {
  requireHeld(locks, identityHex, "the pinned balance read");
  if (typeof fetchWithMetadata !== "function") refuse("a pinned balance read needs the mounted fetch injected");
  if (typeof chainIdPin !== "string" || chainIdPin.length === 0) refuse("a pinned balance read needs the owned chain pin");
  let result;
  try { result = await fetchWithMetadata(identityHex); }
  catch (e) { refuse(`the balance query did not verify (${(e && e.message) || e})`); }
  if (!result || typeof result !== "object" || result.metadata == null || result.balance == null) {
    refuse("the balance result is unserved or lacks its authenticated metadata");
  }
  const { metadata } = result;
  if (metadata.chainId !== chainIdPin) {
    refuse(`the authenticated chainId ${JSON.stringify(metadata.chainId)} differs from the owned pin`);
  }
  const pv = typeof metadata.protocolVersion === "bigint" ? Number(metadata.protocolVersion) : metadata.protocolVersion;
  if (pv !== PROTOCOL_VERSION_PIN) {
    refuse(`the authenticated protocolVersion ${pv} is not the pinned ${PROTOCOL_VERSION_PIN}`);
  }
  let height;
  try { height = BigInt(metadata.height); } catch { refuse("the authenticated height is not an integer"); }
  if (height < 0n) refuse("the authenticated height is negative");
  const frontier = readFrontier(identityHex, { dir, locks });
  if (height < frontier) {
    refuse(`the response height ${height} is below the identity's durable frontier ${frontier} (stale evidence)`);
  }
  advanceFrontier(identityHex, height, { dir, locks });
  let balance;
  try { balance = BigInt(result.balance); } catch { refuse("the verified balance is not an exact integer"); }
  if (balance < 0n) refuse("the verified balance is negative");
  return { balance, height };
};

// ---- the store inventory through the D7 composed read ----
const JOURNAL_FILE_RE = /^e2-journal-(.+)\.jsonl$/;

const asCredits = (name, v) => {
  let n;
  try { n = BigInt(v); } catch { refuse(`${name} must be an exact integer credit amount`); }
  if (n < 0n) refuse(`${name} must be non-negative`);
  return n;
};

/**
 * Enumerate every pool journal in the store by the storage contract's
 * filename grammar and derive each pool's remaining obligations from the D7
 * validator's composed read result. A file matching the grammar with a
 * malformed or colliding pool identifier, and any unreadable or invalid
 * journal, REFUSES the admission outright, fail closed, never a skipped
 * term; files not matching the grammar are foreign and ignored.
 *
 * resolvePool(poolId) supplies each pool's authenticated formation-derived
 * inputs (the same reads a soundness-review finding pins; fixtures in the battery):
 *   { writerIdentity, incomeIdentity,
 *     entitlementsForEpoch(epochIndex, { grossCredits, feeCredits, memberCount })
 *       -> [{ accrualId, amountCredits }] }   // the positive rows only
 *
 * THE EXACT PREDICATES, journal-evidenced and conservative:
 * - the writer owes, for every epoch whose header subject is not stopped:
 *   the header write unless its state is "captured" or captureIncomplete
 *   is established; every accrual document (memberCount, no success
 *   evidence exists for document writes, and no later record is taken as
 *   an inference of them); and per positive entitlement, the reservation
 *   write unless the reservation reached "held", plus the 9
 *   part-and-receipt-document writes, which neither a captured receipt
 *   nor a later epoch's header discharges. TWO evidence classes end
 *   writer terms and they are distinct: ABSENCE of success evidence
 *   never discharges anything, while a TERMINAL journaled stop (the
 *   header's for the epoch's terms, an entitlement's own reservation or
 *   transfer stop for that entitlement's terms) is subject-scoped
 *   evidence that the writes will never happen;
 * - the income identity owes, per positive entitlement, the full amount
 *   plus one credit transfer until that accrual's receipt capture or a
 *   journaled stop on its subject (a transfer executed but its receipt
 *   capture incomplete is STILL outstanding at full amount);
 * - an epoch whose journal carries obligation evidence but no header numbers
 *   cannot be quantified and REFUSES fail closed;
 * - an epoch declared zero-earning with no other records has no remaining
 *   obligations.
 */
const enumerateStoreInventory = ({ dir, resolvePool }) => {
  const base = dir || envStore.STATE_DIR;
  if (typeof resolvePool !== "function") refuse("the inventory needs the pool resolver (the a soundness-review finding-pinned formation reads)");
  const seen = new Set();
  const poolIds = [];
  for (const f of fs.readdirSync(base)) {
    const m = f.match(JOURNAL_FILE_RE);
    if (!m) continue; // foreign files are ignored
    const id = m[1];
    if (!HEX64.test(id)) refuse(`journal file ${f} matches the grammar with a malformed pool identifier`);
    if (seen.has(id)) refuse(`journal file ${f} collides with another journal's pool identifier`);
    seen.add(id);
    poolIds.push(id);
  }
  const pools = [];
  for (const poolId of poolIds.sort()) {
    let read;
    try { read = openValidatedJournal(poolId, base); }
    catch (e) { refuse(`pool ${poolId.slice(0, 8)}...'s journal is unreadable or invalid (${(e && e.message) || e})`); }
    const resolved = resolvePool(poolId);
    // THE RESOLVER MUST ATTEST THAT THE POOL RESOLVED, and a journal it cannot resolve
    // REFUSES the admission rather than contributing nothing to the threshold (a soundness-review finding).
    // A resolver that answers with no entitlement rows is indistinguishable, at this
    // seam, from a pool that genuinely owes nothing, so a caller unable to resolve a
    // journal could quietly remove that journal's obligations from a store-wide funding
    // sum. The live driver did exactly that for every journal it had not pre-resolved,
    // disclosing it in a comment and a printed line, and a disclosure any caller may
    // supply for free is the escape hatch the ordinary path takes.
    //
    // THE ATTESTATION IS NOT VERIFIABLE HERE, and that is the same trust boundary every
    // injected value sits inside. What this closes is the SILENT case: a resolver that
    // cannot resolve must now say so, and saying so stops the run instead of shrinking
    // the reserve.
    if (!resolved || resolved.resolved !== true) {
      refuse(`pool ${poolId.slice(0, 8)}... did not resolve: the resolver returned no attestation that its formation inputs were established, and its journal's obligations cannot be quantified without them (a soundness-review finding)`);
    }
    if (!HEX64.test(resolved.writerIdentity || "") || !HEX64.test(resolved.incomeIdentity || "")
      || typeof resolved.entitlementsForEpoch !== "function") {
      refuse(`the resolver returned no usable formation identities for pool ${poolId.slice(0, 8)}...`);
    }
    const epochs = [];
    for (const [epochStr, e] of Object.entries(read.perEpoch)) {
      const epochIndex = Number(epochStr);
      // a STOP is terminal for exactly ITS subject: a stopped header ends
      // the epoch's writer flow (nothing further is permitted), a stopped
      // accrual subject discharges that entitlement alone, and a stopped
      // document write affects only itself; no wider discharge is inferred,
      // and a transfer already sent when the header stopped keeps its
      // amount counted until its own subject resolves
      const headerStopped = !!(e.header && e.header.stopped);
      const hasObligationEvidence = e.header !== null || Object.keys(e.accruals).length > 0
        || Object.keys(e.documentWriteSubjects).length > 0;
      if (!hasObligationEvidence) { epochs.push({ epochIndex, complete: true, remaining: null }); continue; }
      if (!e.header || e.header.grossCredits === null) {
        refuse(`pool ${poolId.slice(0, 8)}... epoch ${epochIndex} carries obligation evidence but no header numbers, so its obligations cannot be quantified`);
      }
      const numbers = { grossCredits: e.header.grossCredits, feeCredits: e.header.feeCredits,
        memberCount: e.header.memberCount };
      const rows = resolved.entitlementsForEpoch(epochIndex, numbers);
      if (!Array.isArray(rows)) refuse(`the resolver returned no entitlement rows for pool ${poolId.slice(0, 8)}... epoch ${epochIndex}`);
      const positive = rows.map((r, i) => ({
        accrualId: requireHex64(`entitlement row ${i}'s accrualId`, r.accrualId),
        amountCredits: asCredits(`entitlement row ${i}'s amount`, r.amountCredits),
      }));
      const headerDone = e.header.state === "captured" || e.header.captureIncomplete === true;
      const receiptCaptured = (accrualId) => !!(e.accruals[accrualId] && e.accruals[accrualId].receiptCaptured);
      const subjectStopped = (accrualId) => {
        const a = e.accruals[accrualId];
        return !!(a && ((a.reservation && a.reservation.stopped) || (a.transfer && a.transfer.stopped)));
      };
      // the WRITER's document writes discharge on NO journal evidence,
      // because none exists: the receipt capture precedes the part and
      // receipt-document writes, and a later epoch's header proves only
      // that the writer moved on (the fold re-check killed the successor
      // inference as the same defect class as the receipt-capture one);
      // only a stopped header ends the epoch's writer terms
      const writerFlowEnded = headerStopped;
      // the writer terms are TYPED (duty D2: each transition type
      // carries its own measured ceiling, so a bare count cannot be
      // priced); the guards are exactly the untyped count's
      let headerCount = 0n, accrualCount = 0n, reservationCount = 0n,
        partCount = 0n, receiptCount = 0n;
      if (!writerFlowEnded) {
        headerCount += headerDone ? 0n : 1n;
        accrualCount += BigInt(e.header.memberCount); // accrual documents, no success evidence exists
      }
      // the INCOME side is per accrual, never inferred from writer progress
      let incomeAmount = 0n;
      let incomeTransfers = 0n;
      for (const p of positive) {
        if (subjectStopped(p.accrualId)) continue; // a journaled stop discharges exactly its subject
        // in a stopped-header epoch the flow is dead, so an entitlement
        // with NO journaled transfer subject was never activated and owes
        // nothing; one with a transfer subject was attempted and stays
        // counted until its own discharge
        if (headerStopped && !(e.accruals[p.accrualId] && e.accruals[p.accrualId].transfer)) continue;
        const res = e.accruals[p.accrualId] && e.accruals[p.accrualId].reservation;
        if (!writerFlowEnded) {
          reservationCount += (res && res.state === "held" ? 0n : 1n);
          partCount += 8n; // proofPartCount maximum, unknown pre-receipt
          receiptCount += 1n;
        }
        if (!receiptCaptured(p.accrualId)) {
          incomeAmount += p.amountCredits;
          incomeTransfers += 1n;
        }
      }
      const writerTermsZero = headerCount === 0n && accrualCount === 0n
        && reservationCount === 0n && partCount === 0n && receiptCount === 0n;
      if (writerTermsZero && incomeAmount === 0n && incomeTransfers === 0n) {
        epochs.push({ epochIndex, complete: true, remaining: null });
        continue;
      }
      epochs.push({ epochIndex, complete: false,
        remaining: { headerCount, accrualCount, reservationCount, partCount, receiptCount,
          incomeAmount, incomeTransfers, positiveCount: BigInt(positive.length) } });
    }
    pools.push({ poolId, writerIdentity: resolved.writerIdentity, incomeIdentity: resolved.incomeIdentity,
      highestEpochIndex: read.highestEpochIndex, epochs });
  }
  return pools;
};

// ---- the reserve thresholds, one per DISTINCT raw identity ----
/**
 * Group every role obligation by ACTUAL identity: when the income and
 * record-writer roles resolve to one identity, its single balance is
 * compared against the SUM, never separately against two role thresholds.
 * Returns Map<identityHex, credits(BigInt)>.
 */
const computeThresholds = ({ candidate, identities, inventory, feeCeilings }) => {
  // duty D2's typed ceilings: each transition type priced by its own
  // measured constant, every price doubled (the standing times-2
  // conservatism). All six members are REQUIRED as OWN properties; a
  // missing one refuses rather than defaulting. (The provisional era's
  // ADMISSION check refused a missing value, but the retired driver
  // path DEFAULTED an unset environment key to the provisional figure,
  // so the old surface as a whole did not fail closed; the drivers now
  // pass the recorded pin and no defaulting env path remains.)
  if (!feeCeilings || typeof feeCeilings !== "object") {
    refuse("the typed fee ceilings are not set (duty D2's six recorded constants); a missing value refuses distribution rather than defaulting");
  }
  const per = {};
  const usedCeilings = {};
  for (const t of CEILING_TYPES) {
    // OWN property, explicitly supplied: an inherited member is not a
    // configuration (the unit screen's catch: a prototype could satisfy
    // a plain lookup with no member ever supplied)
    if (!Object.prototype.hasOwnProperty.call(feeCeilings, t)
      || feeCeilings[t] === undefined || feeCeilings[t] === null) {
      refuse(`the ${t} fee ceiling is missing from the typed ceilings (duty D2's six recorded constants; a missing value refuses rather than defaulting)`);
    }
    per[t] = asCredits(`the ${t} fee ceiling`, feeCeilings[t]) * 2n;
    // SNAPSHOT at validation time, before any asynchronous boundary: the
    // echoed set is the exact values the arithmetic used, never a later
    // re-read of the caller's mutable object (the third confirmation
    // round's race)
    usedCeilings[t] = String(per[t] / 2n);
  }
  const add = (map, id, credits) => map.set(id, (map.get(id) || 0n) + credits);
  const thresholds = new Map();
  // the candidate epoch's arithmetic (it has no journal presence yet):
  // 1 header + memberCount accruals + per positive entitlement one
  // reservation, at most 8 parts, and the receipt (WRITER_PER_ENTITLEMENT
  // stays the count identity: 1 + 8 + 1 = 10)
  const positives = candidate.positiveEntitlements;
  const nPos = BigInt(positives.length);
  add(thresholds, identities.writer,
    per.header + BigInt(candidate.memberCount) * per.accrual
    + nPos * (per.reservation + 8n * per.part + per.receipt));
  let candIncome = 0n;
  for (const [i, p] of positives.entries()) candIncome += asCredits(`candidate entitlement ${i}`, p.amountCredits);
  candIncome += nPos * per.creditTransfer; // the candidate's credit transfers
  add(thresholds, identities.income, candIncome);
  // every incomplete epoch of every pool in the store, grouped by its own identities
  for (const pool of inventory) {
    for (const e of pool.epochs) {
      if (e.complete) continue;
      const r = e.remaining;
      add(thresholds, pool.writerIdentity,
        r.headerCount * per.header + r.accrualCount * per.accrual
        + r.reservationCount * per.reservation + r.partCount * per.part
        + r.receiptCount * per.receipt);
      add(thresholds, pool.incomeIdentity, r.incomeAmount + r.incomeTransfers * per.creditTransfer);
    }
  }
  return { thresholds, usedCeilings };
};

// ---- the shared header-admission primitive ----
/**
 * The one admission every header write (the distribution procedure's and both
 * capture-battery phases') must pass, run UNDER the header's full lock set,
 * both identities' locks in canonical order (the caller acquires them with
 * acquireIdentityLocks and holds them through build, sign, write-ahead and
 * broadcast; this primitive verifies they are held and does the admission
 * only). Constructs, signs and broadcasts NOTHING (a soundness-review finding): its only
 * external action is one injected balance fetch per distinct identity.
 *
 * candidate: { epochIndex, memberCount,
 *              positiveEntitlements: [{ accrualId, amountCredits }] }
 * poolId names the candidate's own pool, so the ascending discipline is
 * checked against ITS journal: a candidate below the pool's highest
 * journal-visible epoch refuses (the flow never writes backward), while an
 * EQUAL epoch is the rebuild path and its journal terms then double-count
 * beside the candidate arithmetic, in the conservative direction.
 * Returns { admitted: true, thresholds, balances } (decimal strings) or
 * refuses with the failing identity, its threshold and its balance.
 */
const admitHeader = async ({ dir, poolId, candidate, identities, resolvePool,
  fetchBalanceWithMetadata, feeCeilings, chainIdPin, locks }) => {
  if (feeCeilings === undefined || feeCeilings === null) {
    refuse("the typed fee ceilings are not set (duty D2's six recorded constants under D2_FEE_CEILINGS, or a caller-supplied set); a missing value refuses distribution rather than defaulting");
  }
  requireHex64("the candidate poolId", poolId);
  requireHex64("the writer identity", identities && identities.writer);
  requireHex64("the income identity", identities && identities.income);
  // the header runs under EXACTLY its stated lock set, both identities
  // deduplicated, never a superset (every operation states its exact set;
  // extra held locks would let one run block unrelated identities' sends)
  const headerSet = [...new Set([identities.writer, identities.income])].sort();
  if (!locks || !Array.isArray(locks.identities)
    || locks.identities.length !== headerSet.length
    || !headerSet.every((id) => locks.holds(id))) {
    refuse("the header admission runs under exactly its stated lock set (both identities' locks, deduplicated, nothing more)");
  }
  if (!candidate || !Number.isSafeInteger(candidate.memberCount) || candidate.memberCount < 1
    || !Array.isArray(candidate.positiveEntitlements)) {
    refuse("the candidate epoch needs memberCount and its positive entitlement rows");
  }
  if (!Number.isSafeInteger(candidate.epochIndex) || candidate.epochIndex < 0) {
    refuse("the candidate epoch needs a non-negative integer epochIndex");
  }
  const pin = chainIdPin !== undefined ? chainIdPin : envStore.readChainIdPin().chainId;
  const inventory = enumerateStoreInventory({ dir, resolvePool });
  // the ascending discipline against the candidate's OWN journal: the flow
  // never writes an epoch below one it has already opened (a rebuild of an
  // open epoch is the EQUAL case and is permitted)
  // the boundary reads the D7 result's highestEpochIndex, which covers
  // EVERY epoch-bearing record (an epoch-scoped zero-earning declaration
  // included, which perEpoch does not carry)
  const ownPool = inventory.find((p) => p.poolId === poolId);
  if (ownPool && ownPool.highestEpochIndex !== null
    && candidate.epochIndex < ownPool.highestEpochIndex) {
    refuse(`the candidate epoch ${candidate.epochIndex} is below the pool's journal-visible epoch ${ownPool.highestEpochIndex} (the flow never writes backward)`);
  }
  const { thresholds, usedCeilings } = computeThresholds({ candidate, identities, inventory, feeCeilings });
  // the comparison covers THIS header's distinct identities (one when the
  // roles coincide, its balance against the SUM). Thresholds computed for a
  // different pool's distinct income identity are that pool's own run's
  // comparison, under its own locks, never this one's.
  const own = [...new Set([identities.writer, identities.income])].sort();
  const balances = new Map();
  for (const id of own) {
    const { balance } = await pinnedBalance(id, { fetchWithMetadata: fetchBalanceWithMetadata,
      chainIdPin: pin, dir, locks });
    balances.set(id, balance);
    if (balance < thresholds.get(id)) {
      refuse(`identity ${id.slice(0, 8)}...'s verified balance ${balance} is below its reserve threshold ` +
        `${thresholds.get(id)} (shortfall ${thresholds.get(id) - balance} credits; fund out of band and rerun)`);
    }
  }
  const toObj = (m) => Object.fromEntries([...m.entries()].map(([k, v]) => [k, String(v)]));
  // the ceiling set that admitted is ECHOED, the validation-time
  // snapshot the arithmetic used (a caller-selected set below the
  // recorded pin remains the injected surface's trust statement; the
  // echo makes it auditable BY a consumer that records the result,
  // which is the result's offer, not this function's guarantee)
  return { admitted: true, thresholds: toObj(thresholds), balances: toObj(balances),
    feeCeilingsUsed: usedCeilings };
};

module.exports = {
  PROTOCOL_VERSION_PIN, WRITER_PER_ENTITLEMENT, D2_FEE_CEILINGS, D2_MEASURED_MAX_FEES,
  identityLockName, acquireIdentityLocks,
  frontierPath, readFrontier, advanceFrontier, advanceFrontierFromCapture,
  pinnedBalance, enumerateStoreInventory, computeThresholds, admitHeader,
};
