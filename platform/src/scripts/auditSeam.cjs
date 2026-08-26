/**
 * auditSeam - build-order item 3 of the REVIEW-COMPLETE design (revision 27): the seam
 * that consumes the retained three-ledger evidence and DERIVES the audit envelope's
 * decision surface, then serializes the versioned envelope in its canonical form.
 *
 * Everything here is DERIVED, never accepted as a label (the discipline the review cycle
 * converged on): recognition from the governing function over the signed bindings,
 * entitlement from the precedence table (rewardEntitlement.cjs), ownership from the
 * decode positions, conservation by largest remainder over the SIGNED book shares, the
 * per-component claim profile from the dependency matrix, and the aggregate from the
 * exclusive-profile rule. The executable specification remains
 * docs/schema/check_vectors.py; the test drives this writer from the shipped positive
 * vector's own evidence and requires byte-identical canonical output.
 *
 * NOT THE ENTRY POINT (build review a review, a required fix). `buildEnvelope` DERIVES and
 * canonicalizes; it does NOT validate its evidence. A reviewer fed it 72
 * negative-evidence cases: it accepted 67, and 63 of the envelopes it produced were then
 * REJECTED by the normative schema and semantic checker. PRODUCTION CALLERS MUST USE
 * `envelopeWriter.writeEnvelope`, which gates every derived envelope through the
 * executable specification and refuses to emit a non-conformant record. This module
 * remains exported for testing and for callers that have already validated.
 *
 * SCOPE (the disclosed residual, unchanged): this is the OFFLINE derivation and
 * serialization half. Every cryptographic duty the registry names as runtime
 * (signatures, ChainLocks, inclusion proofs and their leaf positions, the data-root
 * completeness binding, header-field derivation, coinbase parse-and-compare, the
 * owner-payout L1 derivation, devnet height-one authentication, the pool-document
 * operator binding, the contract-creation height, L1 backing, receipt validity, and the
 * proof-verifier bundle the envelope's verifierBundleDigest commits) is the deployed
 * verifier's, and every component whose verifier has not run stays TRUSTED_SOURCE.
 */
"use strict";

const { classifyEntitlement, deriveEligibility } = require("./rewardEntitlement.cjs");
// ONE shared RFC 8785 serializer with the full domain guard (build review, MAJOR: the
// local partial serializer accepted lone surrogates and non-NFC strings and emitted
// `undefined` as invalid JSON)
const { canonicalize } = require("./canonicalJson.cjs");

function fail(msg) {
  throw new Error(`seam: ${msg}`);
}

/** exact rational compare helpers over the signed {numerator, denominator} shares */
const num = (s) => BigInt(s.numerator);
const den = (s) => BigInt(s.denominator);

/** exact rational sum of the shares, reduced, for the partition check */
function sumShares(shares) {
  const gcd = (a, b) => { while (b) { const t = a % b; a = b; b = t; } return a < 0n ? -a : a; };
  let n = 0n, d = 1n;
  for (const sh of shares) {
    const sn = num(sh), sd = den(sh);
    if (sd <= 0n) fail("a share denominator is not positive");
    if (sn < 0n) fail("a share numerator is negative");
    n = n * sd + sn * d;
    d = d * sd;
    const g = gcd(n, d);
    if (g > 1n) { n /= g; d /= g; }
  }
  return { n, d };
}

/**
 * Largest-remainder allocation over the SIGNED book shares, exact rationals, ties by
 * ascending slotIndex (the pinned reproduction rule).
 *
 * FAIL-CLOSED on shares that are not a PARTITION OF ONE (build review, MAJOR): with
 * shares summing above 1 the floors already overshoot, the remainder goes negative, the
 * distribution loop is skipped and the function used to return an allocation EXCEEDING
 * the gross with no error; summing below 1 left a remainder larger than the slot count,
 * which indexed past the order array and threw a raw TypeError instead of a clean
 * rejection. Conservation is the money rule, so this validates rather than trusts.
 */
function largestRemainder(baseDuffs, shares) {
  if (!Array.isArray(shares) || shares.length === 0) fail("shares must be a non-empty array");
  const { n: sn, d: sd } = sumShares(shares);
  if (sn !== sd) fail(`book shares are not a partition of 1 (they sum to ${sn}/${sd})`);
  const base = BigInt(baseDuffs);
  if (base < 0n) fail("allocation base is negative");
  const floors = shares.map((sh) => (base * num(sh)) / den(sh));
  const rem = base - floors.reduce((a, b) => a + b, 0n);
  // with a validated partition this is structurally 0 <= rem < shares.length; assert it
  // rather than trust it, so no arithmetic surprise can silently mis-allocate
  // strictly < shares.length after a valid partition (build review a review: the guard
  // allowed rem === shares.length, contradicting its own stated invariant)
  if (rem < 0n || rem >= BigInt(shares.length)) {
    fail(`largest-remainder residue ${rem} outside [0, ${shares.length - 1}]`);
  }
  // remainder fraction per slot = base*num/den - floor, compared exactly as
  // (base*num - floor*den) / den  ->  cross-multiply to avoid any float
  const order = shares.map((sh, i) => ({ i, n: base * num(sh) - floors[i] * den(sh), d: den(sh) }));
  order.sort((a, b) => {
    const l = a.n * b.d, r = b.n * a.d;
    if (l > r) return -1;
    if (l < r) return 1;
    return a.i - b.i;
  });
  const alloc = floors.slice();
  for (let k = 0; k < Number(rem); k++) alloc[order[k].i] += 1n;
  return alloc.map((x) => x.toString());
}

/**
 * The governing recognize(), per reward height H and per L1 position
 * (poolProTxHash, poolL1SlotIndex), over the adopted signed bindings.
 */
/**
 * The epoch binary search below REQUIRES epochs ordered and non-overlapping. The semantic
 * layer enforces both, but recognizeAt runs BEFORE the gate sees the evidence, and with
 * unordered epochs the indexed path DISAGREES with a plain scan: for epochs presented as
 * [300..399, 100..199], height 150 is covered by a scan (which recognizes the pool) while
 * the span guard on checkpoints[0] returns UNRECOGNIZED, silently under-recognizing a
 * height rather than failing (property review, P7, reproduced). Assert the precondition so
 * the failure names itself, the same treatment firstClosing and the suspension index got.
 *
 * NO MEMO AT ALL, BECAUSE EVERY MEMO HERE WAS WRONG (repository-access review, a required fix,
 * after two earlier attempts). The first version skipped the check when the caller's context
 * carried `epochOrderChecked: true`, which a caller could simply set. The second moved the
 * memo into a module-private WeakSet keyed on the checkpoints array, which a caller cannot
 * fabricate, and that was still wrong: the WeakSet remembers an array IDENTITY, not its contents.
 * Reproduced against the tree: a valid two-epoch array returned RECOGNIZED at height 250,
 * then its first epoch was mutated IN PLACE to make the same array unordered, and the next
 * call skipped validation and returned UNRECOGNIZED where a scan finds the covering epoch.
 *
 * The lesson is that no cache over a mutable object the caller still holds can be sound. So
 * this function now VALIDATES AND CAPTURES: it returns a frozen array of epoch bounds, and the
 * searches read those captured bounds rather than re-reading the caller's array. buildEnvelope
 * captures once and passes the result down, so the per-reward path stays a binary search over
 * validated data; a direct caller pays one linear validation per call, which is the honest
 * price of handing in a mutable array.
 */
/**
 * PREPARED DATA DOES NOT TRAVEL ON THE CONTEXT AT ALL (a review finding 5, and the FIFTH
 * design for one problem). The history is the specification now, because each attempt placed
 * authority in a different kind of marker and every marker fell the same way.
 *
 *   1. A context flag, which any caller could simply set.
 *   2. A WeakSet keyed on the source array's identity, which an in-place mutation defeated:
 *      the array stayed the same object while its contents changed.
 *   3. A WeakMap brand over frozen captures, mapping each capture back to the source it came
 *      from. That closed fabrication and cross-source replay, and still failed, because the
 *      brand recorded a MUTABLE source: intervals prepared over an empty lifecycle stayed
 *      trusted after a suspension was recorded into that same lifecycle.
 *   4. A module-private Symbol slot on a context buildEnvelope built itself. The symbol's
 *      VALUE really was unreachable, and it did not matter: `ctx[PREPARED]` is a property
 *      READ on a caller-supplied object, and a JavaScript Proxy intercepts property reads by
 *      key TYPE. A `get` trap that answers every symbol key with a fabricated capture served
 *      it without ever learning the symbol, and a height outside every real epoch came back
 *      RECOGNIZED. Reproduced in a review.
 *
 * The lesson, stated as the rule this module now follows: a fast path whose authority is read
 * FROM a caller-supplied object cannot be protected by any marker placed ON that object,
 * because the caller answers every read of an object it supplies. Flag, identity, brand,
 * private key, all four are markers, and a fifth marker would fall to a fifth read.
 *
 * So prepared data now travels as a SEPARATE ARGUMENT through module-internal functions
 * (recognizeAtWith, deriveRewardRecordWith) that are not exported and cannot be named from
 * outside. The exported recognizeAt and deriveRewardRecord have NO prepared parameter and
 * re-derive from the evidence in front of them, unconditionally. There is no slot to answer,
 * no brand to satisfy, and no signature through which a capture could arrive, so there is
 * nothing left to fabricate. Production keeps its single preparation per envelope, passed
 * argument to argument inside one synchronous build over evidence the builder cloned.
 */

/**
 * The closing index KEEPS its identity brand, and the difference is worth stating because it is
 * the reason the same technique was sound here and unsound above. A prepared closing index
 * retains no reference to anything the caller can change: its anchors and its rows are frozen
 * COPIES of the fields the search returns. So knowing that this exact object came from
 * prepareClosingIndex is knowing everything about its contents, and identity is a complete
 * answer. The epoch and suspension brands pointed at a live source object instead, where
 * identity said nothing about present contents, which is exactly how the stale capture got in.
 */
const preparedClosingIndexes = new WeakSet();

function assertEpochOrder(checkpoints) {
  if (!Array.isArray(checkpoints) || checkpoints.length === 0) {
    fail("checkpoints must be a non-empty array");
  }
  for (let i = 0; i < checkpoints.length; i++) {
    const er = checkpoints[i] && checkpoints[i].epochRange;
    if (!er || !Number.isSafeInteger(er.fromCoreHeight) || !Number.isSafeInteger(er.toCoreHeight)) {
      fail(`epoch ${i} has a malformed epochRange`);
    }
    if (er.fromCoreHeight > er.toCoreHeight) fail(`epoch ${i} runs backwards`);
    if (i > 0 && er.fromCoreHeight <= checkpoints[i - 1].epochRange.toCoreHeight) {
      fail(`epochs are unordered or overlap at ${i}; the covering-epoch search needs them ascending and disjoint`);
    }
  }
  // CAPTURE the validated bounds. The searches use these, so a later in-place mutation of the
  // caller's array cannot change which epoch a height resolves to.
  const bounds = Object.freeze(checkpoints.map((cp, i) => Object.freeze({
    index: i,
    fromCoreHeight: cp.epochRange.fromCoreHeight,
    toCoreHeight: cp.epochRange.toCoreHeight,
  })));
  return bounds;
}

/**
 * The suspension intervals for a lifecycle, validated then ordered. ONE definition, used by
 * both the indexed path in buildEnvelope and the scan fallback in recognizeAt (confirmation
 * round, MAJOR): buildEnvelope validated its endpoints while the exported fallback did not,
 * so a direct caller with banHeight "abc" and endHeight "xyz" had the interval silently
 * ignored and got a plausible RECOGNIZED back. Two paths over the same data must not apply
 * different rules.
 */
function suspensionIntervals(lifecycle, baseHeight) {
  const intervals = ((lifecycle && lifecycle.suspensions) || []).map((su) => [
    su.start.kind === "observed" ? su.start.banHeight + 1 : baseHeight + 1,
    su.endHeight,
  ]).sort((x, y) => x[0] - y[0]);
  // TYPE BEFORE ORDER: a relational operator against a non-numeric value is false, so an
  // ordering guard alone is vacuous on malformed bounds (reproduced a round earlier as 239 of
  // 250 heights disagreeing between the indexed path and the scan).
  for (let i = 0; i < intervals.length; i++) {
    const [lo, hi] = intervals[i];
    if (!Number.isSafeInteger(lo) || !Number.isSafeInteger(hi)) {
      fail(`suspension ${i} has non-integer bounds [${lo}, ${hi}]`);
    }
    if (lo > hi) fail(`suspension ${i} runs backwards ([${lo}, ${hi}])`);
    if (i > 0 && intervals[i][0] <= intervals[i - 1][1]) {
      fail(`suspension intervals overlap at ${i} ([${intervals[i - 1]}] and [${intervals[i]}]); ` +
           "the journal must close a suspension before the next opens");
    }
  }
  const out = Object.freeze(intervals.map((iv) => Object.freeze(iv.slice())));
  return out;
}

/**
 * Membership by binary search over validated, ordered, disjoint intervals.
 *
 * The returned function TYPES ITS HEIGHT (repository-access review, MAJOR). It is exported
 * through makeSuspendedAt, and both comparisons against NaN are false, so
 * makeSuspendedAt([[100,200]])(NaN) returned TRUE: a height that matches no interval was
 * reported as suspended.
 */
function makeSuspendedAt(intervals) {
  // an exported entry point: a raw array reaches here without passing suspensionIntervals,
  // and malformed tuples made the membership answer plausible instead of failing
  // (a review, MAJOR: makeSuspendedAt([["abc","xyz"]])(150) returned true)
  if (!Array.isArray(intervals)) fail("intervals must be an array");
  for (let i = 0; i < intervals.length; i++) {
    const iv = intervals[i];
    if (!Array.isArray(iv) || iv.length !== 2 ||
        !Number.isSafeInteger(iv[0]) || !Number.isSafeInteger(iv[1]) || iv[0] > iv[1]) {
      fail(`interval ${i} is not a well-formed [start, end] integer pair`);
    }
    if (i > 0 && iv[0] <= intervals[i - 1][1]) {
      fail(`intervals overlap at ${i}; membership needs them ascending and disjoint`);
    }
  }
  return (H) => {
    if (!Number.isSafeInteger(H) || H < 0) {
      fail(`suspension lookup needs a safe non-negative height (got ${JSON.stringify(H)})`);
    }
    let lo = 0, hi = intervals.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const [a0, b0] = intervals[mid];
      if (H < a0) hi = mid - 1;
      else if (H > b0) lo = mid + 1;
      else return true;
    }
    return false;
  };
}

/**
 * recognizeAtWith - the implementation, with the prepared capture as an ARGUMENT. Module
 * internal on purpose: this function is not exported, so no caller can name it, and the
 * `prepared` parameter is therefore reachable only from buildEnvelope's own call chain. It is
 * never read off `ctx`, so nothing a caller does to the context (own properties, prototypes,
 * a Proxy answering any key) can put a capture here. See the design history above the
 * exported wrapper's section for the four marker designs this replaces.
 */
function recognizeAtWith(H, ctx, prepared) {
  const { checkpoints, poolProTxHash, poolL1SlotIndex, contractId, poolId, lifecycle, baseHeight } = ctx;
  // VALIDATE THE HEIGHT (confirmation round, MAJOR). Every range test below is a relational
  // comparison, and both comparisons against NaN are false, so recognizeAt(NaN, validCtx)
  // walked straight into an epoch and returned RECOGNIZED.
  if (!Number.isSafeInteger(H) || H < 0) fail(`height ${H} is not a safe non-negative integer`);
  // The bounds the search reads are VALIDATED AND CAPTURED, never re-read from the caller's
  // array (see assertEpochOrder). buildEnvelope prepares once and passes the capture down this
  // internal chain; the exported entry points pass null and re-derive here, per call.
  const bounds = prepared ? prepared.bounds : assertEpochOrder(checkpoints);
  // NO CALLER-SUPPLIED suspendedAt (repository-access review, MAJOR). An injected function
  // skipped the lifecycle-derived index entirely: with a recorded suspension covering
  // 141..160, height 150 returned UNRECOGNIZED through the derived index and RECOGNIZED with
  // `suspendedAt: () => false`. A caller may pass validated DATA, never BEHAVIOUR, and the
  // data must be branded as coming from THIS lifecycle.
  const suspendedAt = makeSuspendedAt(
    prepared ? prepared.susIntervals : suspensionIntervals(lifecycle, baseHeight));
  // THE TERMINAL HEIGHT IS COMPARED BELOW, so it is typed here (repository-access review,
  // MAJOR). It was the one relational comparison in this function still made without a
  // preceding type check: `terminalHeight: "abc"` returned a plausible RECOGNIZED.
  const term = lifecycle.terminalHeight;
  if (term !== null && term !== undefined && !Number.isSafeInteger(term)) {
    fail(`lifecycle.terminalHeight must be a safe integer or null (got ${JSON.stringify(term)})`);
  }
  const firstFrom = bounds[0].fromCoreHeight;
  const lastTo = bounds[bounds.length - 1].toCoreHeight;
  if (H < firstFrom) return { status: "UNRECOGNIZED", bindingRef: null };
  if (H > lastTo) return { status: "DEFERRED", bindingRef: null };
  // epochs are gapless and ordered (the semantic layer enforces both), so the covering
  // epoch is found by binary search rather than a scan per reward (build review, MAJOR)
  let elo = 0, ehi = bounds.length - 1, ci = -1;
  while (elo <= ehi) {
    const mid = (elo + ehi) >> 1;
    const er = bounds[mid];
    if (H < er.fromCoreHeight) ehi = mid - 1;
    else if (H > er.toCoreHeight) elo = mid + 1;
    else { ci = mid; break; }
  }
  if (ci >= 0) {
    {
      const found = checkpoints[ci].extractedBinding.bindings.filter(
        (b) => b.proTxHash === poolProTxHash && b.slotIndex === poolL1SlotIndex);
      if (!found.length) return { status: "UNRECOGNIZED", bindingRef: null };
      const bd = found[0];
      // a valid SUCCESSOR binding at this L1 position: the audited pool is simply
      // UNRECOGNIZED here (never a hard error, or a legitimate old-pool envelope
      // spanning a re-binding could not serialize)
      if (bd.contractId !== contractId || bd.poolId !== poolId) {
        return { status: "UNRECOGNIZED", bindingRef: null };
      }
      // TYPED BEFORE COMPARED (a review, MAJOR). This was the last relational comparison in the
      // recognition path still made against an unchecked value: a binding carrying
      // activationCoreHeight "abc" compared false both ways and returned a plausible RECOGNIZED.
      if (!Number.isSafeInteger(bd.activationCoreHeight) || bd.activationCoreHeight < 0) {
        fail(`binding at epoch ${ci} has a malformed activationCoreHeight ` +
             `${JSON.stringify(bd.activationCoreHeight)}`);
      }
      if (H < bd.activationCoreHeight) return { status: "UNRECOGNIZED", bindingRef: ci };
      // suspension intervals are precomputed and ordered by the caller (see
      // makeSuspensionIndex); binary search replaces the per-reward scan (build review
      // a review)
      if (suspendedAt(H)) return { status: "UNRECOGNIZED", bindingRef: ci };
      if (term !== null && term !== undefined && term < H) {
        return { status: "UNRECOGNIZED", bindingRef: ci };
      }
      return { status: "RECOGNIZED", bindingRef: ci };
    }
  }
  fail(`height ${H} inside the epoch span has no covering epoch`);
}

/**
 * recognizeAt - the EXPORTED recognition entry point. It has no prepared parameter, takes
 * nothing off the context beyond the evidence fields, and re-derives per call. That is the
 * whole design: the honest path is the only path a caller can reach.
 */
function recognizeAt(H, ctx) {
  return recognizeAtWith(H, ctx, null);
}

/**
 * The FIRST platform row whose Core anchor reaches H (the closing block), or null.
 *
 * THE CACHED INDEX NOW EXISTS (repository-access review, MAJOR). The comment here used to
 * claim that a `makeClosingIndex` cached the anchors once per envelope. No such function was
 * ever written, so every reward revalidated the WHOLE ledger and only then ran its binary
 * search: measured at 3,007,977 anchor reads for 1000 rewards over a 1000-row ledger, which
 * is linear per reward over two uncapped ledgers, exactly the quadratic cost the binary
 * search was introduced to remove. `prepareClosingIndex` validates once and returns captured
 * anchors; `firstClosing` accepts either that prepared index or a raw ledger, validating only
 * in the raw case.
 */
/**
 * Validate a platform ledger once and capture what the search needs. Returns a frozen index,
 * so a later in-place mutation of the caller's ledger cannot change a closing block (the same
 * lesson the epoch memo taught).
 */
function prepareClosingIndex(platformLedger) {
  // COUNTED so the once-per-envelope property has a check behind it (a review, MINOR: the
  // fixtures would still have passed if deriveRewardRecord went back to revalidating the raw
  // ledger for every reward, which is the quadratic cost this index exists to remove)
  prepareClosingIndex.calls += 1;
  if (!Array.isArray(platformLedger)) fail("platformLedger must be an array");
  // TYPE BEFORE ORDER, from row 0: an order guard written with relational operators is
  // vacuous on non-numeric values, and with anchors [200,"abc",300] the search returned the
  // row anchored at 300 where a scan returns 200 (a WRONG closing block, not a missing one).
  for (let i = 0; i < platformLedger.length; i++) {
    if (!Number.isSafeInteger(platformLedger[i].coreChainLockedHeight)) {
      fail(`platform ledger row ${i} has a non-integer coreChainLockedHeight; ` +
           "the closing-block search cannot compare it");
    }
    if (i > 0 && platformLedger[i].coreChainLockedHeight < platformLedger[i - 1].coreChainLockedHeight) {
      fail(`platform ledger anchors regress at row ${i}; the closing-block search needs them non-decreasing`);
    }
  }
  // CAPTURE the row fields the search returns, never the caller's mutable rows (a review,
  // MAJOR: the frozen index retained live rows, so mutating a row after preparation changed
  // the returned closing block, and any object with `prepared: true` was trusted outright).
  const index = Object.freeze({
    anchors: Object.freeze(platformLedger.map((r) => r.coreChainLockedHeight)),
    rows: Object.freeze(platformLedger.map((r) => Object.freeze({
      height: r.height, coreChainLockedHeight: r.coreChainLockedHeight,
    }))),
  });
  preparedClosingIndexes.add(index);
  return index;
}

prepareClosingIndex.calls = 0;

function firstClosing(H, platformLedgerOrIndex) {
  // the same NaN hole as recognizeAt: every comparison against NaN is false, so the search
  // ran to completion and returned null (confirmation round, MAJOR)
  if (!Number.isSafeInteger(H) || H < 0) fail(`height ${H} is not a safe non-negative integer`);
  // the brand, not a caller-settable marker, decides whether the input is prepared
  const index = preparedClosingIndexes.has(platformLedgerOrIndex)
    ? platformLedgerOrIndex
    : prepareClosingIndex(platformLedgerOrIndex);
  const { anchors, rows } = index;
  let lo = 0, hi = anchors.length - 1, found = null;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (anchors[mid] >= H) { found = rows[mid]; hi = mid - 1; }
    else lo = mid + 1;
  }
  return found;
}


/**
 * deriveRewardRecordWith - one reward record (recognition + entitlement + conservation +
 * slotFanout), fully derived from the retained evidence for its height. Module internal: the
 * prepared capture is the second POSITIONAL argument, deliberately outside the options
 * object, because the options object is caller-supplied on the exported path and anything
 * inside it would be one more caller-reachable slot. The exported deriveRewardRecord below
 * takes one argument and passes null.
 */
function deriveRewardRecordWith({ H, index, coreRow, ctx }, prepared) {
  const recognition = recognizeAtWith(H, ctx, prepared);
  const w = ctx.walkAt(H - 1);
  const eligibility = deriveEligibility({
    stateAtHMinus1: w.state, listRoot: w.root, hMinus1: H - 1,
    journal: ctx.lifecycle, base: ctx.base,
  });
  const entitlement = classifyEntitlement({
    height: H,
    chainlockHeight: ctx.chainlockHeight,
    eligibility,
    scheduleResult: coreRow.scheduleResult,
    coinbase: coreRow.coinbase,
    paths: { coreRowPath: `/coverage/coreLedger/${index}`, rewardPath: `/rewards/${index}` },
  });

  // ---- the result matrix: conservation and fanout follow the classification ----
  let conservation, slotFanout;
  if (entitlement.kind !== "classified") {
    const reason = entitlement.kind === "unfinalized" ? "UNFINALIZED" : "UNKNOWN";
    conservation = { kind: "unavailable" };
    slotFanout = { kind: "none", reason };
  } else {
    const cls = entitlement.classification;
    if (cls === "OWED" && recognition.status !== "RECOGNIZED") {
      // owed by Core, but this height is not ours to fan out
      conservation = { kind: "not-applicable" };
      slotFanout = { kind: "none", reason: recognition.status };
    } else if (cls === "OWED") {
      const gross = entitlement.coinbaseEvidence.matchedOutputs
        .reduce((a, o) => a + BigInt(o.amountDuffs), 0n);
      const nonSlot = [];                       // v1: the schema caps this at zero items
      const base = gross - nonSlot.reduce((a, c) => a + BigInt(c.duffs), 0n);
      const hbook = ctx.bookAt(H);
      if (!hbook) fail(`a recognized OWED height ${H} has no audited-pool book in its epoch`);
      const alloc = largestRemainder(base.toString(), hbook.shares);
      const closing = firstClosing(H, ctx.closingIndex);
      const records = hbook.shares.map((share, si) => {
        const snapHop = ctx.lastEligibleHop(si, H);
        let allocation;
        if (closing === null) {
          allocation = { kind: "unclosed" };
        } else if (snapHop) {
          const snap = snapHop;
          allocation = {
            kind: "resolved", ownerAtH: snap.buyer, snapshotPosition: snap.position,
            closingBlock: { platformHeight: closing.height, coreChainLockedHeight: closing.coreChainLockedHeight },
          };
        } else {
          allocation = {
            kind: "resolved", ownerAtH: ctx.operatorId,
            snapshotPosition: { kind: "pre-creation", slotIndex: si },
            closingBlock: { platformHeight: closing.height, coreChainLockedHeight: closing.coreChainLockedHeight },
          };
        }
        return { slotIndex: si, allocation, share, allocatedDuffs: alloc[si] };
      });
      conservation = {
        kind: "calculated", grossDuffs: gross.toString(),
        nonSlotComponents: nonSlot, slotAllocationBaseDuffs: base.toString(),
      };
      slotFanout = { kind: "slots", records };
    } else {
      conservation = { kind: cls === "ANOMALY" ? "unavailable" : "not-applicable" };
      slotFanout = { kind: "none", reason: cls };
    }
  }

  return {
    rewardCoreHeight: H,
    rewardCoreBlockHash: coreRow.blockHash,
    recognition,
    entitlement,
    conservation,
    slotFanout,
  };
}

/** deriveRewardRecord - the EXPORTED form: one argument, no prepared capture, re-derives. */
function deriveRewardRecord(args) {
  return deriveRewardRecordWith(args, null);
}

/**
 * ONE copy of the registry's component-to-verifier mapping, shared with envelopeWriter
 * (confirmation round, MINOR). It used to be written out in both modules, and this build has
 * already been bitten twice by exactly that shape (two partial serializers, then a second
 * encoder inside the lineage module). The claim-profile derivation here and the attestation
 * check in the writer must agree on the mapping, so a rename in one place must not be able
 * to leave the other behind. It lives here because envelopeWriter already imports this
 * module, so the dependency runs one way.
 */
const { VERIFIER_OF } = require("./verifierRegistry.cjs");
const DEPS = {
  recognition: ["identifierConversion", "coreContinuityFinality"],
  baseProof: ["coreContinuityFinality", "identifierConversion"],
  decoderCoverage: ["platformCommits"],
  bookConformance: ["decoderCoverage", "recognition"],
  conservation: ["recognition", "coreContinuityFinality", "bookConformance"],
  transitionHashing: ["decoderCoverage"],
  l1Backing: ["coreContinuityFinality"],
};
const BARRED = new Set(["schedule", "l1Backing", "receiptValidity"]);

/**
 * deriveClaimProfile - the per-component claims and the ONE exclusive aggregate.
 * `ranVerifiers` is the set of registry verifier names the deployment actually RAN and
 * that PASSED; everything else is TRUSTED_SOURCE and names its absent verifier. The
 * dependency matrix is enforced (an AUTHENTICATED component whose dependency is not
 * AUTHENTICATED is a structural failure, not a downgrade), and the aggregate follows the
 * exclusive-profile rule with result completeness gating it.
 */
function deriveClaimProfile(ranVerifiers, rewards) {
  const ran = new Set(ranVerifiers || []);
  const components = {};
  for (const name of Object.keys(VERIFIER_OF)) {
    const v = VERIFIER_OF[name];
    const authenticated = v !== null && ran.has(v) && !BARRED.has(name);
    components[name] = authenticated
      ? { claim: "AUTHENTICATED", verifiersNotRun: [] }
      : { claim: "TRUSTED_SOURCE", verifiersNotRun: v ? [v] : [] };
  }
  for (const [name, c] of Object.entries(components)) {
    if (c.claim !== "AUTHENTICATED") continue;
    for (const d of DEPS[name] || []) {
      if (components[d].claim !== "AUTHENTICATED") {
        fail(`AUTHENTICATED ${name} depends on non-AUTHENTICATED ${d} (run its verifier or claim TRUSTED_SOURCE)`);
      }
    }
  }
  const anyAuth = Object.values(components).some((c) => c.claim === "AUTHENTICATED");
  let incomplete = false;
  for (const rec of rewards) {
    if (rec.entitlement.kind === "unknown" || rec.entitlement.kind === "unfinalized") incomplete = true;
    if (rec.slotFanout.kind === "slots") {
      for (const x of rec.slotFanout.records) if (x.allocation.kind === "unclosed") incomplete = true;
    }
  }
  const combinedRequired = Object.keys(VERIFIER_OF).filter((n) => n !== "schedule");
  let aggregate;
  if (!anyAuth) aggregate = "trusted-source";
  else if (incomplete || combinedRequired.some((n) => components[n].claim !== "AUTHENTICATED")) {
    aggregate = "partial-evidence";
  } else aggregate = "proof-verified-except-schedule";
  return { components, aggregate };
}

/**
 * buildEnvelope - assemble the whole versioned envelope from retained evidence plus the
 * pinned identity/context fields. Returns { envelope, canonicalBytes, sha256 }.
 *
 * evidence: {
 *   network, contractId, poolProTxHash, poolId, poolL1SlotIndex, proofCodecProfile,
 *   verifierBundleDigest, checkpointAuthority, adoptedEpochPins, checkpoints,
 *   basePackage, lifecycle, decoderLineage, validatedChainLock, coreAuditRange,
 *   platformAuditRange, coreHeaderChain, platformTrustRoot, coverage, slots
 * }  (i.e. every envelope member EXCEPT the derived `rewards` and `claimProfile`)
 * ranVerifiers: the registry verifier names that ran AND passed (default none).
 */
function buildEnvelope(evidence, { ranVerifiers = [] } = {}) {
  // DETACH from the caller (build review a review): the result retained nested references,
  // so mutating the input afterwards changed result.envelope while canonicalBytes and its
  // digest stayed stale. structuredClone also rejects functions and symbols outright.
  evidence = structuredClone(evidence);
  const crypto = require("crypto");
  const lifecycle = evidence.lifecycle;
  const baseHeight = evidence.basePackage.baseBlock.height;
  const bp = evidence.basePackage;
  const st0 = bp.kind === "pre-dml" ? "ABSENT"
    : bp.nodeStateAtBase.kind === "present"
      ? (bp.nodeStateAtBase.isValid ? "PRESENT_VALID" : "PRESENT_INVALID") : "ABSENT";
  const walk = evidence.coverage.listWalk;
  const walkAt = (h) => h === baseHeight
    ? { state: st0, root: bp.kind === "rooted" ? bp.listRoot : null }
    : (() => {
        const r = walk[h - (baseHeight + 1)];
        if (!r) fail(`no list-walk row for height ${h}`);
        return { state: r.targetNodeState, root: r.listRoot };
      })();

  // the audited pool's book per epoch (absent in an epoch that re-bound the position)
  // the audited book per epoch, computed ONCE (build review a review: this filtered every
  // epoch's book list for EVERY recognized reward), then selected by binary search over
  // the gapless ordered epochs
  // ordered, disjoint epochs are the precondition of BOTH covering-epoch searches (the one
  // in recognizeAt and bookAt below). Assert once here; recognizeAt then skips its own
  // per-call check via ctx.epochOrderChecked.
  const epochBounds = assertEpochOrder(evidence.checkpoints);
  const bookByEpoch = evidence.checkpoints.map((cp) => {
    const bks = cp.extractedBinding.books.filter(
      (b) => b.contractId === evidence.contractId && b.poolId === evidence.poolId);
    return bks.length ? bks[0] : null;
  });
  const bookAt = (H) => {
    let lo = 0, hi = evidence.checkpoints.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const er = evidence.checkpoints[mid].epochRange;
      if (H < er.fromCoreHeight) hi = mid - 1;
      else if (H > er.toCoreHeight) lo = mid + 1;
      else return bookByEpoch[mid];
    }
    return null;
  };
  const presentBooks = bookByEpoch.filter(Boolean);
  if (!presentBooks.length) fail("the audited pool has no book in any epoch (nothing to audit)");
  const operatorId = presentBooks[0].operatorId;

  // suspension intervals, validated and sorted ONCE, through the same construction the
  // exported recognizeAt path uses. Validation lives in suspensionIntervals so the two paths
  // cannot apply different rules, which is exactly what went wrong before (the indexed path
  // here checked its endpoints while the exported fallback did not).
  const susIntervals = suspensionIntervals(evidence.lifecycle, baseHeight);

  // ownership chains per retail slot, from the retained slot documents. Each chain is
  // ordered by (platformHeight, txIndex, innerIndex) and its ANCHORS are non-decreasing,
  // so the "hops eligible at H" prefix is found by binary search instead of filtering the
  // whole chain for every reward and slot (build review a review).
  const chains = {};
  const anchorsBySlot = {};
  for (const s of evidence.slots) {
    chains[s.slotIndex] = s.ownershipChain;
    const anchors = s.ownershipChain.map((h) => h.coreChainLockedHeight);
    // ASSERT the non-decreasing precondition the search below relies on (property review,
    // P7, reproduced through the production path). With the committed positive vector's
    // slot 0 chain REVERSED (anchors 995, 999 -> 999, 995) the search credited a DIFFERENT
    // member for the same reward, with no error raised: owner Ebb3eVTN.. became 4iYFsZcZ..
    // The normative gate declined both reversals that could be constructed (one on "chain
    // does not start at a creation", one on "hop anchor != platform row anchor"), so no
    // wrong-owner record was emitted, and the defect is confined to this ungated
    // primitive. Confined is not the same as absent: crediting the wrong member is the
    // worst answer this module can produce, so the precondition is checked here rather
    // than inferred from the gate declining later.
    for (let i = 1; i < anchors.length; i++) {
      if (!Number.isSafeInteger(anchors[i])) {
        fail(`slot ${s.slotIndex} hop ${i} has a non-integer coreChainLockedHeight`);
      }
      if (anchors[i] < anchors[i - 1]) {
        fail(`slot ${s.slotIndex} ownership anchors regress at hop ${i} ` +
             `(${anchors[i - 1]} -> ${anchors[i]}); the owner-at-height search needs them non-decreasing`);
      }
    }
    if (anchors.length && !Number.isSafeInteger(anchors[0])) {
      fail(`slot ${s.slotIndex} hop 0 has a non-integer coreChainLockedHeight`);
    }
    anchorsBySlot[s.slotIndex] = anchors;
  }
  // the LAST hop with coreChainLockedHeight < H, or null
  const lastEligibleHop = (si, H) => {
    const anchors = anchorsBySlot[si] || [];
    let lo = 0, hi = anchors.length - 1, found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (anchors[mid] < H) { found = mid; lo = mid + 1; } else hi = mid - 1;
    }
    return found < 0 ? null : chains[si][found];
  };

  const ctx = {
    checkpoints: evidence.checkpoints,
    poolProTxHash: evidence.poolProTxHash,
    poolL1SlotIndex: evidence.poolL1SlotIndex,
    contractId: evidence.contractId,
    poolId: evidence.poolId,
    lifecycle, baseHeight,
    base: { kind: bp.kind, baseMode: bp.baseMode, pHeight: bp.firstAppearance && bp.firstAppearance.pHeight },
    walkAt, bookAt, chains, operatorId, lastEligibleHop,
    closingIndex: prepareClosingIndex(evidence.coverage.platformLedger),
    platformLedger: evidence.coverage.platformLedger,
    chainlockHeight: evidence.validatedChainLock.height,
  };
  // VALIDATED DATA, captured once, rather than behaviour or raw arrays: the epoch bounds and
  // the suspension intervals are what the searches read. The capture is NOT placed on the
  // context. It is passed as an argument down the internal call chain (deriveRewardRecordWith,
  // recognizeAtWith), which no caller can name, so there is no slot on any caller-reachable
  // object through which a fabricated or stale capture could arrive. That is the fifth design
  // for this problem; the four marker designs it replaces are documented above recognizeAtWith.
  const prepared = Object.freeze({ bounds: epochBounds, susIntervals });

  const rewards = evidence.coverage.coreLedger.map((coreRow, index) =>
    deriveRewardRecordWith({ H: coreRow.height, index, coreRow, ctx }, prepared));
  const claimProfile = deriveClaimProfile(ranVerifiers, rewards);

  const envelope = { ...evidence, rewards, claimProfile };
  const bytes = canonicalize(envelope);
  return {
    envelope,
    canonicalBytes: bytes,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
}

module.exports = {
  buildEnvelope, deriveRewardRecord, deriveClaimProfile, recognizeAt,
  largestRemainder, firstClosing, canonicalize, assertEpochOrder,
  suspensionIntervals, makeSuspendedAt, prepareClosingIndex,
  // exported for the CROSS-LANGUAGE DRIFT CHECK (a review, MINOR): these rules are copied in
  // the Python executable specification and the normative registry and cannot be
  // deduplicated, so the fixtures compare them instead
  DEPS, BARRED,
};
