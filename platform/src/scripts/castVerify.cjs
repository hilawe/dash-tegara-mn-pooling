/**
 * The cast-verification decision core, extracted from castReceiptV2.cjs into a pure
 * function over plain objects (the batch-4 lens-3 idea both reviewers endorsed): no
 * network, no wasm-dpp documents, so the offline harness (castVerifyTest.cjs) can
 * drive the full decision table the engine's header documents. castReceiptV2.cjs
 * assembles the state from Platform and Core and prints what this returns; the
 * messages here are the ones the reviews approved, verbatim.
 *
 * Classes: DEVIATIONS (historical honesty broken), STALES (the current ledger no
 * longer agrees with the standing snapshot or vote), NOTES (anomalies and
 * informational flags that do not fail verification), LOGS (narration).
 *
 * State shape (all plain values; hex strings lowercase):
 *   contractId, poolIdStr, proposalHex, poolOperator, proTxHex,
 *   collateral: { txid, vout },
 *   tally (computeTally output for the CURRENT ledger), tHash (Buffer),
 *   snapshots: [{ id, owner, createdAt(ms), tallyHashHex, outcome, proTxHex,
 *                 platformHeight, tallyRowsUtf8 }] in $createdAt ascending order,
 *   receipts:  [{ id, owner, snapshotId, voteHashHex, voteOutcome, voteTimestamp,
 *                 voteSignal, proTxHex }],
 *   l1: { voteHash, outcome, signal, time } | null,
 *   nowHeight (0 when unknown),
 *   observations (optional): [{ id, owner, createdAt(ms), voteHashHex, voteOutcome,
 *                 voteSignal, voteTimestamp, proTxHex }] from the vote-observation
 *                 contract (voteWatch.cjs).
 *
 * OBSERVATIONS are member CORROBORATION, not proof, and NEVER fail verification
 * (batch-6 review + re-check): an observation echoes a vote's fields, all
 * predictable except the second-resolution nTime, and nothing authenticates that a
 * SIGNED vote existed (no RPC at the pinned Core commit exposes the vote's
 * signature; exposing it is the recorded upstream item that would upgrade this rung
 * to proof). A member can CARPET the ~3900-second future window with one candidate
 * hash per second per outcome, so ANY observation-driven verification failure would
 * be a member-controlled, unclearable kill switch. Observation findings are
 * therefore NOTES only: loud "SUSPECT ORDERING" notes for real anomalies, ordinary
 * notes for the rest. They surface evidence for social adjudication; the verdict is
 * driven solely by the cryptographic machinery. Rules:
 *
 *   - Only observations by CURRENT POOL MEMBERS (the tally's owners) produce the
 *     loud ordering notes; non-member observations are logged with no weight (open
 *     creation means arbitrary identities, and identities are not people).
 *   - The echoed fields must reproduce the vote hash and the masternode must match
 *     (else ignored with a NOTE).
 *   - FUTURE-ECHO bound (the only sound time bound): an echoed nTime more than
 *     (grace + cross-clock allowance) AFTER the observation's createdAt is for a
 *     vote Core would never have accepted; ignored with a NOTE. There is no ancient
 *     bound (an old vote on a still-active proposal is legitimate).
 *   - A plausible member observation that predates the RECEIPT's snapshot is a loud
 *     SUSPECT ORDERING note: either the cast came first or a member carpeted the
 *     window; indistinguishable without the vote signature, so surfaced, not failed.
 *   - ORPHAN observations (member observed a vote hash with NO receipt) are a loud
 *     NOTE: a real superseded-and-unattested cast is thereby VISIBLE for social
 *     adjudication (the suppression gap stays closed), without failing on what could
 *     equally be a fabricated hash.
 */
const { tallyFromRows, tallyHash } = require("./tally.cjs");
const { computeVoteHash } = require("./l1gov.cjs");

// clocks differ between the two chains and Core lets a vote's own timestamp run up
// to one hour ahead of adjusted time, so the timestamp-consistency check carries the
// same grace (see the engine's docstring for what this does and does not prove)
const VOTE_TIME_GRACE_SECONDS = 3600;
// Platform block time and Core adjusted time have no enforced bound between them;
// the plausibility window opens by this much extra so a genuine immediate
// observation of a maximally postdated vote cannot land implausibly early
// (batch-6 review, major). 300s is an INTERIM operational margin, not a measured
// bound (no protocol-enforced cross-clock relation exists to measure against);
// override per run via the state's clockSkewAllowanceSeconds and revisit when
// enough cross-chain clock observations accumulate. Widening it widens the member
// framing window by the same amount; member-only weighting and the non-accusatory
// SUSPECT class contain that.
const CLOCK_SKEW_ALLOWANCE_SECONDS = 300;

const verifyCast = (s) => {
  const out = { deviations: [], stales: [], notes: [], logs: [] };
  const deviate = (m) => out.deviations.push(m);
  const goStale = (m) => out.stales.push(m);
  const note = (m) => out.notes.push(m);
  const log = (m) => out.logs.push(m);
  // observation-derived findings are NOTES ONLY, never verdict-affecting (batch-6
  // re-check, blocker): an observation does not authenticate a SIGNED vote, and a
  // member can carpet the ~3900-second future window with one candidate hash per
  // second per outcome, so ANY observation-driven verification FAILURE is a
  // member-controlled, unclearable kill switch. Observations therefore surface
  // ordering anomalies loudly for social adjudication but never fail verification.
  // The upstream vote-signature exposure is what would let these become real
  // DEVIATIONs safely (a signed vote cannot be carpet-fabricated).
  const flag = (m) => out.notes.push(`SUSPECT ORDERING: ${m}`);
  const { contractId, poolIdStr, proposalHex, poolOperator, proTxHex, collateral,
    tally, tHash, snapshots, receipts, l1, nowHeight } = s;
  const observations = s.observations || [];
  const latestSnap = snapshots.length ? snapshots[snapshots.length - 1] : null;

  // validate observations once: the echoed fields must reproduce the vote hash and
  // the masternode must match; anything else is ignored with a note. Only CURRENT
  // POOL MEMBERS' observations carry weight (open creation means arbitrary
  // identities; identities are not people), so a non-member can never trigger a
  // flag of any kind.
  const memberOwners = new Set(tally.rows.map((r) => r.owner));
  const skewSeconds = Number.isFinite(s.clockSkewAllowanceSeconds)
    ? s.clockSkewAllowanceSeconds : CLOCK_SKEW_ALLOWANCE_SECONDS;
  // per-member fetch truncation must be LOUD unconditionally (batch-6 DoS re-check):
  // the caller fetches each member's observations under a per-member cap, and a
  // member self-spamming past it is truncated on their OWN slot only; that has to be
  // reported even when the aggregate stays well under MAX_OBS.
  const truncatedOwners = Array.isArray(s.observationFetchTruncatedOwners)
    ? s.observationFetchTruncatedOwners : [];
  if (truncatedOwners.length > 0) {
    const shown = truncatedOwners.slice(0, 5).map((o) => o.slice(0, 12) + "...").join(", ");
    note(`per-member observation cap hit for ${truncatedOwners.length} member slot(s) ` +
      `(${shown}${truncatedOwners.length > 5 ? ", ..." : ""}); their oldest were kept and later ` +
      "observations not examined. A member self-spamming truncates only their own slot; investigate");
  }
  // a pathologically large membership could still exceed the fetch ceiling at the
  // caller; that overflow is reported here loudly (does not fail verification)
  const slotsSkipped = Number.isFinite(s.observationMemberSlotsSkipped) ? s.observationMemberSlotsSkipped : 0;
  if (slotsSkipped > 0) {
    note(`${slotsSkipped} member slot(s) beyond the observation fetch ceiling were NOT examined ` +
      "for observations; run voteWatch/list per member to inspect them");
  }
  // aggregate backstop (defensive): the caller sizes maxObservations to members x
  // per-member-cap so this never truncates ACROSS members in normal operation; it
  // only fires if a caller passes a smaller bound, and then says so exactly.
  const MAX_OBS = Number.isFinite(s.maxObservations) ? s.maxObservations : 2000;
  let obsInput = observations;
  if (observations.length > MAX_OBS) {
    note(`${observations.length} observations exceed the ${MAX_OBS} processing bound; ` +
      `${observations.length - MAX_OBS} NOT examined (oldest kept)`);
    obsInput = [...observations].sort((a, b) => a.createdAt - b.createdAt).slice(0, MAX_OBS);
  }
  const obsByVote = new Map();
  for (const ob of obsInput) {
    if (ob.proTxHex !== proTxHex) {
      note(`observation ${ob.id} by ${ob.owner} names a different masternode; ignored`);
      continue;
    }
    let echoHash = null;
    try {
      echoHash = computeVoteHash(collateral.txid, collateral.vout,
        proposalHex.toLowerCase(), ob.voteSignal, ob.voteOutcome, Number(ob.voteTimestamp));
    } catch { /* fall through to the mismatch note */ }
    if (echoHash !== ob.voteHashHex) {
      note(`observation ${ob.id} by ${ob.owner} does not reproduce its vote hash; ignored`);
      continue;
    }
    // FUTURE-ECHO bound (the only sound time bound; the earlier "two-sided" framing
    // was algebraically one bound stated twice, fourth-model batch-6 note). A vote's
    // nTime is bounded by Core to at most one hour ahead of true time, and an
    // observer publishes at/after seeing the vote, so a plausible observation
    // satisfies claimed_nTime <= createdAt + grace + skew. There is deliberately NO
    // ancient bound: an old vote on a still-active proposal is legitimate.
    const t = Number(ob.voteTimestamp) * 1000;
    if (t > ob.createdAt + (VOTE_TIME_GRACE_SECONDS + skewSeconds) * 1000) {
      note(`observation ${ob.id} by ${ob.owner}` +
        `${memberOwners.has(ob.owner) ? " (member)" : ""} echoes an implausible time for vote ` +
        `${ob.voteHashHex.slice(0, 12)}... (its claimed nTime is more than the allowed skew after it ` +
        "was published, so no genuine vote seen then could carry it); ignored");
      continue;
    }
    if (!obsByVote.has(ob.voteHashHex)) obsByVote.set(ob.voteHashHex, []);
    obsByVote.get(ob.voteHashHex).push({ ...ob, isMember: memberOwners.has(ob.owner) });
  }
  for (const list of obsByVote.values()) list.sort((a, b) => a.createdAt - b.createdAt);

  const snapById = new Map(snapshots.map((x) => [x.id, x]));
  // per-snapshot validity is retained so a later caller (the missed-attestation
  // branch) can refuse to let an INVALID snapshot be claimed (re-check finding: a
  // deviation alone did not inform the caller)
  const snapValidity = new Map();
  const checkSnapshot = (o, label) => {
    if (snapValidity.has(o.id)) return snapValidity.get(o.id);
    const before = out.deviations.length;
    if (o.owner !== poolOperator) deviate(`${label} is signed by ${o.owner}, not the operator ${poolOperator}`);
    if (o.proTxHex !== proTxHex) deviate(`${label} names a different masternode than the pool records`);
    let rebuilt = null;
    try {
      // the snapshot's own formatVersion selects the row validator (cast v3; absent
      // means the v2 contract's format 1), so the encoding can evolve without
      // breaking self-authentication
      rebuilt = tallyFromRows(JSON.parse(o.tallyRowsUtf8), o.formatVersion || 1);
    } catch (e) {
      deviate(`${label}'s embedded rows are invalid: ${(e && e.message) || e}`);
    }
    if (rebuilt) {
      const rebuiltHash = tallyHash(contractId, poolIdStr, proposalHex, rebuilt);
      if (rebuiltHash.toString("hex") !== o.tallyHashHex) {
        deviate(`${label}'s embedded rows do not reproduce its own tally hash (self-authentication failed)`);
      }
      if (rebuilt.outcome !== o.outcome) {
        deviate(`${label} claims outcome "${o.outcome}" but its own rows tally to "${rebuilt.outcome}"`);
      }
    }
    const valid = out.deviations.length === before;
    snapValidity.set(o.id, valid);
    return valid;
  };

  // 1. every snapshot self-authenticates; platformHeight is author-supplied, so only
  // the impossible is flagged, for every snapshot
  log(`${snapshots.length} snapshot(s), ${receipts.length} receipt(s)`);
  for (const o of snapshots) {
    checkSnapshot(o, `snapshot ${o.id.slice(0, 12)}...`);
    const claimed = Number(o.platformHeight);
    if (claimed > 0 && nowHeight > 0 && claimed > nowHeight) {
      note(`snapshot ${o.id.slice(0, 12)}... claims platform height ${claimed}, above the current ` +
        `${nowHeight}; the field is informational (author-supplied), treat it as suspect`);
    }
  }

  // 2. every receipt is internally consistent with its own committed snapshot, and
  // its vote fields must reproduce its vote hash (field integrity; Core acceptance
  // at the time remains the live watcher's observation)
  const referenced = new Set();
  const ZERO_HASH = "0".repeat(64);
  for (const r of receipts) {
    // a MISSED-vote attestation (cast v3) is the operator's admission that no L1 vote
    // implemented a snapshot; it is surfacing, never a vote, and it is excluded from
    // every vote-matching leg. It gets the SAME integrity discipline as a cast receipt
    // (independent-review finding: an unvalidated missed branch let a malformed
    // attestation pass and suppress the abandoned-commitment note): signer and
    // masternode first, then every sentinel field, then the snapshot must resolve and
    // self-authenticate; only a fully valid attestation marks its snapshot referenced.
    if (r.kind === "missed") {
      let bad = false;
      const dv = (m) => { deviate(m); bad = true; };
      if (r.owner !== poolOperator) dv(`missed attestation ${r.id} is signed by ${r.owner}, not the operator`);
      if (r.proTxHex !== proTxHex) dv(`missed attestation ${r.id} names a different masternode than the pool records`);
      if (r.voteHashHex !== ZERO_HASH) dv(`missed attestation ${r.id} must carry the all-zeros vote hash sentinel`);
      if (r.voteOutcome !== "none") dv(`missed attestation ${r.id} must carry outcome "none", has "${r.voteOutcome}"`);
      if (r.voteSignal !== "-") dv(`missed attestation ${r.id} must carry the "-" signal sentinel, has "${r.voteSignal}"`);
      const snap = snapById.get(r.snapshotId);
      if (!snap) {
        dv(`missed attestation ${r.id} references an unknown snapshot ${r.snapshotId}`);
      } else {
        // an INVALID snapshot cannot be claimed as attested-missed (re-check finding)
        if (!checkSnapshot(snap, `snapshot ${snap.id.slice(0, 12)}... (via missed attestation)`)) bad = true;
        // the attested deadline cannot precede the commitment it claims went unmet
        if (Number(r.voteTimestamp) * 1000 < snap.createdAt) {
          dv(`missed attestation ${r.id} carries a deadline before its snapshot's creation`);
        }
      }
      if (!bad) {
        referenced.add(r.snapshotId);
        note(`missed-vote attestation ${r.id}: the operator attests no L1 vote implemented ` +
          `snapshot ${r.snapshotId} by ${new Date(Number(r.voteTimestamp) * 1000).toISOString()}`);
      }
      continue;
    }
    const before = out.deviations.length;
    if (r.owner !== poolOperator) deviate(`receipt ${r.id} is signed by ${r.owner}, not the operator`);
    if (r.proTxHex !== proTxHex) deviate(`receipt ${r.id} names a different masternode than the pool records`);
    let expectedHash = null;
    try {
      expectedHash = computeVoteHash(collateral.txid, collateral.vout,
        proposalHex.toLowerCase(), r.voteSignal, r.voteOutcome, Number(r.voteTimestamp));
    } catch (e) {
      deviate(`receipt ${r.id} carries vote fields that cannot hash: ${(e && e.message) || e}`);
    }
    if (expectedHash && expectedHash !== r.voteHashHex) {
      deviate(`receipt ${r.id}: the vote fields do not reproduce the vote hash they claim ` +
        "(a field was altered after the fact)");
    }
    const refSnap = snapById.get(r.snapshotId) || null;
    if (!refSnap) {
      deviate(`receipt ${r.id} references a snapshot that does not exist for this pool and proposal`);
      continue;
    }
    if (refSnap.outcome === "none") {
      deviate(`receipt ${r.id} attests a cast whose snapshot said "none" (members said cast nothing)`);
    } else if (refSnap.outcome !== r.voteOutcome) {
      deviate(`receipt ${r.id}: the vote ("${r.voteOutcome}") deviates from its own committed ` +
        `snapshot ("${refSnap.outcome}")`);
    }
    if (Number(refSnap.createdAt) > (Number(r.voteTimestamp) + VOTE_TIME_GRACE_SECONDS) * 1000) {
      deviate(`receipt ${r.id}: the vote's claimed time precedes its snapshot (timestamp ` +
        "consistency failed; commit first, cast second)");
    }
    // member observations CORROBORATE ordering (SUSPECT, not proof; see the header):
    // a plausible member observation predating the receipt's snapshot means either
    // the vote existed before the commitment or a member pre-published a guessed
    // hash, and both demand the same thing, an investigation on permanent evidence.
    // (Plausibility was enforced during common validation, so everything here is
    // already inside the window.)
    const plausible = obsByVote.get(r.voteHashHex) || [];
    if (plausible.length > 0) {
      const memberObs = plausible.filter((o) => o.isMember);
      const owners = new Set(plausible.map((o) => o.owner)).size;
      log(`vote ${r.voteHashHex.slice(0, 12)}...: ${plausible.length} observation(s) by ${owners} ` +
        `identity owner(s), ${memberObs.length} by current pool members, earliest chain-anchored at ` +
        `${new Date(plausible[0].createdAt).toISOString()}`);
      const earliestMember = memberObs[0] || null;
      if (earliestMember && earliestMember.createdAt < Number(refSnap.createdAt)) {
        flag(`receipt ${r.id}: a current member OBSERVED this vote on Platform at ` +
          `${new Date(earliestMember.createdAt).toISOString()}, BEFORE its snapshot was committed at ` +
          `${new Date(Number(refSnap.createdAt)).toISOString()}; either the cast preceded the ` +
          "commitment or a member carpeted the timestamp window with candidate hashes. These are " +
          "indistinguishable without the vote signature, so this is surfaced for investigation and " +
          "does NOT fail verification; the immutable documents carry the evidence");
      }
    }
    // a snapshot counts as implemented only by a receipt that passed every check,
    // so a malformed receipt cannot suppress the abandoned-commitment note
    if (out.deviations.length === before) referenced.add(refSnap.id);
  }
  for (const o of snapshots) {
    if (!referenced.has(o.id) && (!latestSnap || o.id !== latestSnap.id)) {
      note(`snapshot ${o.id.slice(0, 12)}... was never implemented by a cleanly-verifying receipt ` +
        "(abandoned commitment)");
    }
  }

  // ORPHAN observations: a member observed a vote that NO receipt attests. This
  // MUST NOT fail verification (third-model batch-6 finding, blocker): an
  // observation does not authenticate a signed vote, so an orphan is
  // indistinguishable from a fabricated hash, and failing verification on it would
  // hand any current member a zero-cost, unclearable kill switch for the pool's
  // verified status (the operator cannot produce a receipt for a vote that never
  // existed on L1). It is instead surfaced as a loud NOTE, which still closes the
  // original suppression gap (a real superseded-and-unattested cast is VISIBLE for
  // social adjudication) without accusing an operator who has no way to resolve it.
  // The observer saw the vote or did not; the immutable record is the evidence, and
  // humans, not the verifier, decide which.
  const attested = new Set(receipts.map((r) => r.voteHashHex));
  for (const [voteHashHex, list] of obsByVote) {
    if (attested.has(voteHashHex)) continue;
    const memberObs = list.filter((o) => o.isMember);
    if (memberObs.length === 0) {
      note(`${list.length} non-member observation(s) of unattested vote hash ` +
        `${voteHashHex.slice(0, 12)}...; no weight (identities are not members)`);
      continue;
    }
    note(`ORPHAN: ${memberObs.length} current member(s) observed vote hash ` +
      `${voteHashHex.slice(0, 12)}... (earliest ${new Date(memberObs[0].createdAt).toISOString()}) ` +
      "but NO receipt attests it. Either a real cast was superseded without being attested, or a " +
      "member published a hash that never became a vote; these are indistinguishable on-ledger, so " +
      "this is surfaced for investigation and does NOT fail verification (the operator cannot receipt " +
      "a nonexistent vote)");
  }

  // 3. the current vote must be attested and its receipt must match Core exactly
  if (l1) {
    const receipt = receipts.find((r) => r.voteHashHex === l1.voteHash) || null;
    if (!receipt) {
      deviate("the current L1 vote has no receipt (unattested cast)");
    } else {
      log(`receipt for the current vote: ${receipt.id}`);
      if (receipt.voteOutcome !== l1.outcome) deviate(`the current receipt records "${receipt.voteOutcome}" but L1 shows "${l1.outcome}"`);
      if (receipt.voteSignal !== l1.signal) deviate(`the current receipt's signal "${receipt.voteSignal}" is not "${l1.signal}"`);
      if (Number(receipt.voteTimestamp) !== l1.time) deviate(`the current receipt's timestamp ${receipt.voteTimestamp} differs from L1's ${l1.time}`);
    }
  } else {
    if (latestSnap && latestSnap.outcome !== "none") {
      deviate("the standing snapshot demands a cast but no current L1 vote exists");
    }
    if (receipts.length > 0) {
      // anomalous, not accusatory: this Core version cannot withdraw a vote
      note(`${receipts.length} historical receipt(s) exist but Core reports no current ` +
        "funding vote; this Core version cannot withdraw a vote, so investigate (masternode removed, " +
        "or the governance object expired)");
    }
    if (!latestSnap && tally.outcome === "none") {
      log("no snapshot, no vote, and the tally casts nothing; nothing to verify");
    }
  }
  if (!latestSnap && (l1 || tally.outcome !== "none")) {
    deviate("no tally snapshot exists although governance activity was expected or found");
  }

  // freshness: a hash divergence has TWO readings nothing on-ledger can distinguish
  // (honest churn after the snapshot, or a snapshot that never matched); the message
  // names both and the decisive check is member-side (funderClient myrow)
  if (latestSnap && latestSnap.tallyHashHex !== tHash.toString("hex")) {
    if (latestSnap.outcome !== tally.outcome) {
      goStale(`the members' tally is now "${tally.outcome}" but the standing snapshot committed ` +
        `"${latestSnap.outcome}"; either preferences moved since the snapshot or the ` +
        "snapshot never matched the ledger (members: check your own row); the operator owes a " +
        "new snapshot and a re-cast");
    } else {
      note("the tally's composition moved since the snapshot (same outcome); either " +
        "preferences churned or the snapshot's rows never matched (members: check your own row); " +
        "a refresh snapshot is optional");
    }
  }
  if (l1 && tally.outcome !== "none" && l1.outcome !== tally.outcome) {
    goStale(`the current vote ("${l1.outcome}") no longer matches the members' current tally ("${tally.outcome}")`);
  }
  if (l1 && tally.outcome === "none") {
    goStale(`the members now withhold every weight but a vote ("${l1.outcome}") still stands`);
  }

  return out;
};

module.exports = { verifyCast, VOTE_TIME_GRACE_SECONDS };
