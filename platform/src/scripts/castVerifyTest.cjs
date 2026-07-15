/**
 * The offline table-driven harness over the cast-verification decision core
 * (castVerify.cjs), the batch-4 lens-3 idea both packet reviewers endorsed. Runs the
 * full decision surface from castReceiptV2.cjs's header (every snapshot/vote/receipt
 * combination, the hostile-rows cases, the hash and timestamp legs, the anomaly
 * notes, and the freshness classes) with plain node, no devnet, no fork node, same
 * pattern as railStateTest.cjs and matchJournalTest.cjs.
 *
 * EVERY case pins the EXACT deviation, stale, and note counts (batch-5 review: a
 * fragment-only assertion lets an unintended extra classification pass unnoticed),
 * plus the message fragments that name the legs it exercises.
 *
 * Run: node src/scripts/castVerifyTest.cjs
 */
const crypto = require("crypto");
const { computeTally, tallyHash, canonicalMembers } = require("./tally.cjs");
const { computeVoteHash } = require("./l1gov.cjs");
const { verifyCast } = require("./castVerify.cjs");

// fixed identities and chain values (shape-valid, content arbitrary)
const OP = "BA13qbRCcjFwbZ4p9KoURBH8Zhh8EjAB8muDjYkkjvsf";
const M1 = "3ytivjwDVivtumhsY8DG6boo6PEztScu6mr3v3QFFHHg";
const M2 = "4J21aMCugjeBaPfFBHqPWRneyLmMz2frS6cZK8YcuPxm";
const NOT_OP = "APHKjhmpB9sHT1Rj4vyKLjKwQa5uzLdpaiXHyvYh1aCe";
const PT = "ab".repeat(32);
const COL = { txid: "cd".repeat(32), vout: 1 };
const PROP = "12".repeat(32);
const POOL = "PoolId1111111111111111111111111111111111111";
const CONTRACT = "Contract111111111111111111111111111111111111";
const T0 = 1700000000; // base vote time (s); snapshot times in ms relative to it

const mkTally = (prefs) => computeTally(
  [{ owner: M1, bps: 6000 }, { owner: M2, bps: 4000 }],
  new Map(Object.entries(prefs)),
);
const mkSnap = (tally, over = {}) => ({
  id: over.id || "Snap" + crypto.randomBytes(4).toString("hex"),
  owner: OP,
  createdAt: (T0 - 600) * 1000, // 10 minutes before the base vote time
  tallyHashHex: tallyHash(CONTRACT, POOL, PROP, tally).toString("hex"),
  outcome: tally.outcome,
  proTxHex: PT,
  platformHeight: 100,
  tallyRowsUtf8: JSON.stringify(canonicalMembers(tally)),
  ...over,
});
const mkVote = (outcome, time = T0) => ({
  voteHash: computeVoteHash(COL.txid, COL.vout, PROP, "funding", outcome, time),
  outcome, signal: "funding", time,
});
const mkReceipt = (snap, outcome, over = {}) => {
  const time = over.voteTimestamp !== undefined ? over.voteTimestamp : T0;
  return {
    id: over.id || "Rcpt" + crypto.randomBytes(4).toString("hex"),
    owner: OP,
    snapshotId: snap.id,
    voteHashHex: computeVoteHash(COL.txid, COL.vout, PROP, "funding", outcome, time),
    voteOutcome: outcome,
    voteTimestamp: time,
    voteSignal: "funding",
    proTxHex: PT,
    ...over,
  };
};
const mkState = (over = {}) => ({
  contractId: CONTRACT, poolIdStr: POOL, proposalHex: PROP,
  poolOperator: OP, proTxHex: PT, collateral: COL,
  tally: over.tally || mkTally({ [M1]: "yes" }),
  snapshots: [], receipts: [], l1: null, nowHeight: 200,
  ...over,
  tHash: tallyHash(CONTRACT, POOL, PROP, over.tally || mkTally({ [M1]: "yes" })),
});

const cases = [];
const T = (name, state, expect) => cases.push({ name, state, expect });

// ---- the S/V/R decision table ----
{
  const tally = mkTally({ [M1]: "yes" });
  const snap = mkSnap(tally);
  T("clean honest S+V+R", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes")], l1: mkVote("yes") }),
  { dev: 0, stale: 0, notes: 0 });
}
T("nothing anywhere, tally none", mkState({ tally: mkTally({}) }),
  { dev: 0, stale: 0, notes: 0, logHas: "nothing to verify" });
T("no snapshot but tally demands cast", mkState({ tally: mkTally({ [M1]: "yes" }) }),
  { dev: 1, stale: 0, notes: 0, devHas: ["no tally snapshot exists"] });
T("no snapshot but a vote exists", mkState({ l1: mkVote("yes") }),
  { dev: 2, stale: 0, notes: 0,
    devHas: ["no receipt (unattested cast)", "no tally snapshot exists"] });
{
  const tally = mkTally({});
  T("none snapshot, no vote", mkState({ tally, snapshots: [mkSnap(tally)] }),
    { dev: 0, stale: 0, notes: 0 });
}
{
  const tally = mkTally({});
  T("none snapshot, vote exists unattested", mkState({ tally, snapshots: [mkSnap(tally)],
    l1: mkVote("abstain") }),
  { dev: 1, stale: 1, notes: 0, devHas: ["no receipt (unattested cast)"],
    staleHas: ["withhold every weight"] });
}
{
  const tally = mkTally({});
  const snap = mkSnap(tally);
  T("receipt against a none snapshot", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "abstain")], l1: mkVote("abstain") }),
  { dev: 1, stale: 1, notes: 0, devHas: ["snapshot said \"none\""] });
}
{
  const tally = mkTally({ [M1]: "yes" });
  T("snapshot demands cast, no vote", mkState({ tally, snapshots: [mkSnap(tally)] }),
    { dev: 1, stale: 0, notes: 0, devHas: ["demands a cast but no current L1 vote"] });
}
{ // vanished vote with historical receipts: NOTE, not deviation
  const tallyNone = mkTally({});
  const tallyYes = mkTally({ [M1]: "yes" });
  const oldSnap = mkSnap(tallyYes, { createdAt: (T0 - 1200) * 1000 });
  const noneSnap = mkSnap(tallyNone, { createdAt: (T0 + 600) * 1000 });
  T("vanished vote, historical receipt", mkState({ tally: tallyNone,
    snapshots: [oldSnap, noneSnap], receipts: [mkReceipt(oldSnap, "yes")] }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["cannot withdraw a vote"] });
}
// ---- receipt integrity legs ----
{
  const tally = mkTally({ [M1]: "yes" });
  const snap = mkSnap(tally);
  T("receipt owner not operator", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes", { owner: NOT_OP })], l1: mkVote("yes") }),
  { dev: 1, stale: 0, notes: 0, devHas: ["not the operator"] });
  T("receipt masternode mismatch", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes", { proTxHex: "ff".repeat(32) })], l1: mkVote("yes") }),
  { dev: 1, stale: 0, notes: 0, devHas: ["names a different masternode"] });
  T("receipt fields break vote hash", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes", { voteOutcome: "no" })], l1: mkVote("yes") }),
  { dev: 3, stale: 0, notes: 0, devHas: ["do not reproduce the vote hash",
    "deviates from its own committed snapshot", "the current receipt records"] });
  T("receipt fields cannot hash", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes", { voteSignal: "banana" })], l1: mkVote("yes") }),
  { dev: 2, stale: 0, notes: 0, devHas: ["cannot hash", "signal \"banana\""] });
  T("receipt references missing snapshot", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt({ id: "SnapMissing" }, "yes")], l1: mkVote("yes") }),
  { dev: 1, stale: 0, notes: 0, devHas: ["snapshot that does not exist"] });
  T("vote deviates from its snapshot", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "no")], l1: mkVote("no") }),
  { dev: 1, stale: 1, notes: 0, devHas: ["deviates from its own committed snapshot"],
    staleHas: ["no longer matches the members' current tally"] });
  T("claimed time precedes snapshot", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes", { voteTimestamp: T0 - 5000 })],
    l1: mkVote("yes", T0 - 5000) }),
  { dev: 1, stale: 0, notes: 0, devHas: ["timestamp consistency failed"] });
  T("within grace is clean", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes", { voteTimestamp: T0 - 3000 })],
    l1: mkVote("yes", T0 - 3000) }),
  { dev: 0, stale: 0, notes: 0 });
  T("exact grace boundary is clean (strict >)", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes", { voteTimestamp: T0 - 4200 })],
    l1: mkVote("yes", T0 - 4200) }),
  { dev: 0, stale: 0, notes: 0 });
  T("different-time vote lands as unattested", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes", { voteTimestamp: T0 + 9 })], l1: mkVote("yes") }),
  { dev: 1, stale: 0, notes: 0, devHas: ["has no receipt (unattested cast)"] });
  // current-receipt field comparisons, isolated by forcing voteHashHex to Core's
  // (the field-integrity deviation necessarily rides along: consistent-but-different
  // fields produce a different hash, so they can never match Core's hash)
  const coreHash = mkVote("yes").voteHash;
  T("current receipt outcome vs Core", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes", { voteHashHex: coreHash, voteOutcome: "no" })],
    l1: mkVote("yes") }),
  { dev: 3, stale: 0, notes: 0, devHas: ["do not reproduce the vote hash",
    "the current receipt records \"no\" but L1 shows \"yes\""] });
  T("current receipt signal vs Core", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes", { voteHashHex: coreHash, voteSignal: "valid" })],
    l1: mkVote("yes") }),
  { dev: 2, stale: 0, notes: 0, devHas: ["do not reproduce the vote hash",
    "signal \"valid\" is not \"funding\""] });
  T("current receipt timestamp vs Core", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes", { voteHashHex: coreHash, voteTimestamp: T0 + 7 })],
    l1: mkVote("yes") }),
  { dev: 2, stale: 0, notes: 0, devHas: ["do not reproduce the vote hash",
    `timestamp ${T0 + 7} differs from L1's ${T0}`] });
}
// ---- snapshot self-authentication legs ----
{
  const tally = mkTally({ [M1]: "yes" });
  T("snapshot owner not operator", mkState({ tally,
    snapshots: [mkSnap(tally, { owner: NOT_OP })] }),
  { dev: 2, stale: 0, notes: 0, devHas: ["not the operator", "demands a cast"] });
  T("snapshot masternode mismatch", mkState({ tally,
    snapshots: [mkSnap(tally, { proTxHex: "ff".repeat(32) })] }),
  { dev: 2, stale: 0, notes: 0, devHas: ["names a different masternode", "demands a cast"] });
  T("snapshot rows invalid JSON", mkState({ tally,
    snapshots: [mkSnap(tally, { tallyRowsUtf8: "{not json" })] }),
  { dev: 2, stale: 0, notes: 0, devHas: ["embedded rows are invalid", "demands a cast"] });
  T("snapshot rows bad bps sum", mkState({ tally,
    snapshots: [mkSnap(tally, { tallyRowsUtf8: JSON.stringify([
      { owner: M1, bps: 5000, choice: "yes" }, { owner: M2, bps: 4000, choice: "no" }]) })] }),
  { dev: 2, stale: 0, notes: 0, devHas: ["embedded rows are invalid", "demands a cast"] });
  T("snapshot rows do not reproduce hash", mkState({ tally,
    snapshots: [mkSnap(tally, { tallyRowsUtf8: JSON.stringify(canonicalMembers(mkTally({ [M1]: "no" }))) })] }),
  { dev: 3, stale: 0, notes: 0, devHas: ["do not reproduce its own tally hash",
    "its own rows tally to", "demands a cast"] });
  T("snapshot outcome contradicts own rows", mkState({ tally,
    snapshots: [mkSnap(tally, { outcome: "no" })] }),
  { dev: 2, stale: 0, notes: 0, devHas: ["its own rows tally to", "demands a cast"] });
  T("impossible platform height noted", mkState({ tally,
    snapshots: [mkSnap(tally, { platformHeight: 999 })] }),
  { dev: 1, stale: 0, notes: 1, noteHas: ["above the current"] });
  T("unknown current height mutes the note", mkState({ tally, nowHeight: 0,
    snapshots: [mkSnap(tally, { platformHeight: 999 })] }),
  { dev: 1, stale: 0, notes: 0 });
}
// ---- abandoned commitments and multi-snapshot ----
{
  const tally = mkTally({ [M1]: "yes" });
  const snapA = mkSnap(tally, { createdAt: (T0 - 1200) * 1000 });
  const snapB = mkSnap(tally, { createdAt: (T0 - 600) * 1000 });
  T("older unimplemented snapshot noted", mkState({ tally, snapshots: [snapA, snapB],
    receipts: [mkReceipt(snapB, "yes")], l1: mkVote("yes") }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["abandoned commitment"] });
  T("malformed receipt cannot claim its snapshot", mkState({ tally,
    snapshots: [snapA, snapB],
    receipts: [mkReceipt(snapA, "yes", { owner: NOT_OP }), mkReceipt(snapB, "yes")],
    l1: mkVote("yes") }),
  { dev: 1, stale: 0, notes: 1, devHas: ["not the operator"], noteHas: ["abandoned commitment"] });
  T("clean historical receipt claims its snapshot", mkState({ tally,
    snapshots: [snapA, snapB],
    receipts: [mkReceipt(snapA, "yes", { voteTimestamp: T0 - 100 }), mkReceipt(snapB, "yes")],
    l1: mkVote("yes") }),
  { dev: 0, stale: 0, notes: 0 });
}
// ---- missed-vote attestations (cast v3): same integrity discipline as receipts ----
{
  const tally = mkTally({ [M1]: "yes" });
  const snapA = mkSnap(tally, { createdAt: (T0 - 1200) * 1000 });
  const snapB = mkSnap(tally, { createdAt: (T0 - 600) * 1000 });
  const mkMissed = (snap, over = {}) => ({
    id: over.id || "Miss" + crypto.randomBytes(4).toString("hex"),
    owner: OP, snapshotId: snap.id,
    voteHashHex: "0".repeat(64), voteOutcome: "none",
    voteTimestamp: Math.floor(snap.createdAt / 1000) + 300, voteSignal: "-",
    proTxHex: PT, kind: "missed", ...over,
  });
  T("valid missed attestation claims its snapshot", mkState({ tally,
    snapshots: [snapA, snapB], receipts: [mkMissed(snapA), mkReceipt(snapB, "yes")],
    l1: mkVote("yes") }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["missed-vote attestation"] });
  T("malformed missed attestation cannot claim its snapshot", mkState({ tally,
    snapshots: [snapA, snapB],
    receipts: [mkMissed(snapA, { voteOutcome: "yes" }), mkReceipt(snapB, "yes")],
    l1: mkVote("yes") }),
  { dev: 1, stale: 0, notes: 1, devHas: ['must carry outcome "none"'], noteHas: ["abandoned commitment"] });
  T("missed attestation with a foreign signer deviates", mkState({ tally,
    snapshots: [snapA, snapB],
    receipts: [mkMissed(snapA, { owner: NOT_OP }), mkReceipt(snapB, "yes")],
    l1: mkVote("yes") }),
  { dev: 1, stale: 0, notes: 1, devHas: ["not the operator"], noteHas: ["abandoned commitment"] });
  T("missed attestation with unknown snapshot deviates", mkState({ tally,
    snapshots: [snapB],
    receipts: [mkMissed({ id: "SnapUnknown11", createdAt: (T0 - 1200) * 1000 }),
      mkReceipt(snapB, "yes")],
    l1: mkVote("yes") }),
  { dev: 1, stale: 0, notes: 0, devHas: ["unknown snapshot"] });
  T("missed attestation deadline before its snapshot deviates", mkState({ tally,
    snapshots: [snapA, snapB],
    receipts: [mkMissed(snapA, { voteTimestamp: Math.floor(snapA.createdAt / 1000) - 100 }),
      mkReceipt(snapB, "yes")],
    l1: mkVote("yes") }),
  { dev: 1, stale: 0, notes: 1, devHas: ["deadline before its snapshot"], noteHas: ["abandoned commitment"] });
  // an INVALID snapshot cannot be claimed as attested-missed: the self-authentication
  // deviation fires AND the abandoned-commitment note stays (final re-check finding)
  const snapBad = mkSnap(tally, { createdAt: (T0 - 1200) * 1000, tallyHashHex: "ff".repeat(32) });
  T("missed attestation cannot claim an invalid snapshot", mkState({ tally,
    snapshots: [snapBad, snapB],
    receipts: [mkMissed(snapBad), mkReceipt(snapB, "yes")],
    l1: mkVote("yes") }),
  { dev: 1, stale: 0, notes: 1, devHas: ["self-authentication failed"], noteHas: ["abandoned commitment"] });
}
// ---- freshness ----
{
  const oldTally = mkTally({ [M1]: "yes" });
  const newTally = mkTally({ [M1]: "no", [M2]: "no" });
  const snap = mkSnap(oldTally);
  T("tally outcome moved -> stale", mkState({ tally: newTally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes")], l1: mkVote("yes") }),
  { dev: 0, stale: 2, notes: 0,
    staleHas: ["either preferences moved since the snapshot or the"] });
  const sameOutcomeTally = mkTally({ [M1]: "yes", [M2]: "abstain" });
  T("composition moved, same outcome -> note", mkState({ tally: sameOutcomeTally,
    snapshots: [snap], receipts: [mkReceipt(snap, "yes")], l1: mkVote("yes") }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["composition moved"] });
  const noneTally = mkTally({});
  const noneSnap = mkSnap(noneTally, { createdAt: (T0 + 600) * 1000 });
  T("members withdrew to none, vote stands", mkState({ tally: noneTally,
    snapshots: [snap, noneSnap], receipts: [mkReceipt(snap, "yes")], l1: mkVote("yes") }),
  { dev: 0, stale: 1, notes: 0, staleHas: ["withhold every weight"] });
}

// ---- vote observations (member corroboration; SUSPECT class, never proof) ----
{
  const tally = mkTally({ [M1]: "yes" });
  const snap = mkSnap(tally); // createdAt (T0-600)*1000
  const vote = mkVote("yes"); // nTime T0
  const mkObs = (v, over = {}) => ({
    id: "Obs" + crypto.randomBytes(4).toString("hex"),
    owner: M2, // a current pool member
    createdAt: (T0 - 300) * 1000,
    voteHashHex: v.voteHash,
    voteOutcome: v.outcome,
    voteSignal: v.signal,
    voteTimestamp: v.time,
    proTxHex: PT,
    ...over,
  });
  // observations NEVER fail verification (batch-6 re-check): every case here holds
  // dev:0 and stale:0, and ordering anomalies land in notes with the SUSPECT
  // ORDERING prefix. This is the load-bearing property, a member cannot force a
  // non-VERIFIED verdict with any observation, because none can be told from a
  // carpeted/fabricated hash without the vote signature.
  T("member observation after snapshot is clean corroboration", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes")], l1: vote,
    observations: [mkObs(vote)] }),
  { dev: 0, stale: 0, notes: 0, logHas: "1 by current pool members" });
  T("member observation before snapshot is a loud note, not a failure", mkState({ tally,
    snapshots: [snap], receipts: [mkReceipt(snap, "yes")], l1: vote,
    observations: [mkObs(vote, { createdAt: (T0 - 1000) * 1000 })] }),
  { dev: 0, stale: 0, notes: 1, flagHas: ["OBSERVED this vote on Platform", "does NOT fail verification"] });
  T("non-member observation before snapshot carries no weight", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes")], l1: vote,
    observations: [mkObs(vote, { owner: NOT_OP, createdAt: (T0 - 1000) * 1000 })] }),
  { dev: 0, stale: 0, notes: 0, logHas: "0 by current pool members" });
  T("carpet attack: a matched pre-snapshot member hash cannot fail verification",
    mkState({ tally, snapshots: [snap], receipts: [mkReceipt(snap, "yes")], l1: vote,
      // a member pre-published the operator's eventual vote hash BEFORE the snapshot
      // (snapshot createdAt is (T0-600)*1000, so this is earlier)
      observations: [mkObs(vote, { createdAt: (T0 - 900) * 1000 })] }),
  { dev: 0, stale: 0, notes: 1, flagHas: ["OBSERVED this vote on Platform"] });
  T("observation echoing nTime too far ahead of publication is filtered", mkState({ tally,
    snapshots: [snap], receipts: [mkReceipt(snap, "yes")], l1: vote,
    observations: [mkObs(vote, { createdAt: (T0 - 7200) * 1000 })] }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["implausible time"] });
  T("observation with broken field echo ignored", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes")], l1: vote,
    observations: [mkObs(vote, { voteOutcome: "no" })] }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["does not reproduce its vote hash"] });
  T("observation for a different masternode ignored", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes")], l1: vote,
    observations: [mkObs(vote, { proTxHex: "ff".repeat(32) })] }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["different masternode"] });
  const vote2 = mkVote("no", T0 + 50); // a different vote hash, never attested
  T("orphan member observation is a loud NOTE, never a failure", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes")], l1: vote,
    observations: [mkObs(vote2, { createdAt: (T0 + 60) * 1000 })] }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["ORPHAN", "does NOT fail verification"] });
  T("orphan non-member observation is a no-weight note", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes")], l1: vote,
    observations: [mkObs(vote2, { owner: NOT_OP, createdAt: (T0 + 60) * 1000 })] }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["no weight (identities are not members)"] });
  // an old nTime is LEGITIMATE (a vote on a still-active proposal persists), so it
  // cannot be filtered by any time bound; the kill switch is defused by orphan being
  // a NOTE, never a failure (dev:0 stale:0 is the load-bearing assertion)
  T("orphan with ancient nTime is a note, never a kill switch",
    mkState({ tally, snapshots: [snap], receipts: [mkReceipt(snap, "yes")], l1: vote,
      observations: [mkObs(mkVote("no", T0 - 100000), { createdAt: (T0 + 60) * 1000 })] }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["ORPHAN", "does NOT fail verification"] });
  // FUTURE-ECHO bound: reject when nTime is more than grace+skew (3900s) AFTER the
  // observation was published. At the boundary it is plausible; one second past is filtered.
  T("nTime exactly at the future boundary is plausible (orphan note)",
    mkState({ tally, snapshots: [snap], receipts: [mkReceipt(snap, "yes")], l1: vote,
      observations: [mkObs(mkVote("no", T0 + 3900), { createdAt: T0 * 1000 })] }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["ORPHAN"] });
  T("nTime one second past the future boundary is filtered",
    mkState({ tally, snapshots: [snap], receipts: [mkReceipt(snap, "yes")], l1: vote,
      observations: [mkObs(mkVote("no", T0 + 3901), { createdAt: T0 * 1000 })] }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["implausible time"] });
  // the processing bound: more observations than MAX are truncated LOUDLY, not silently
  T("observation flood is bounded with a loud truncation note", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes")], l1: vote, maxObservations: 3,
    observations: Array.from({ length: 10 }, (_, i) =>
      mkObs(mkVote("no", T0 + 100 + i), { createdAt: (T0 + 200 + i) * 1000 })) }),
  { dev: 0, stale: 0, notes: 4, noteHas: ["exceed the 3 processing bound", "NOT examined"] });
  // per-member fetch truncation is LOUD even below the aggregate bound (batch-6 DoS
  // re-check): a member self-spamming past their per-member cap is reported by owner
  T("per-member fetch truncation is loud unconditionally", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes")], l1: vote, observationFetchTruncatedOwners: [M2],
    observations: [mkObs(vote)] }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["per-member observation cap hit for 1 member slot"] });
  // a pathologically large membership beyond the fetch ceiling is reported loudly
  T("skipped member slots beyond the fetch ceiling are reported", mkState({ tally, snapshots: [snap],
    receipts: [mkReceipt(snap, "yes")], l1: vote, observationMemberSlotsSkipped: 3,
    observations: [mkObs(vote)] }),
  { dev: 0, stale: 0, notes: 1, noteHas: ["3 member slot(s) beyond the observation fetch ceiling"] });
}

// ---- runner ----
let failures = 0;
for (const { name, state, expect } of cases) {
  const r = verifyCast(state);
  const problems = [];
  if (r.deviations.length !== expect.dev) {
    problems.push(`expected ${expect.dev} deviation(s), got ${r.deviations.length}: ${JSON.stringify(r.deviations)}`);
  }
  if (r.stales.length !== expect.stale) {
    problems.push(`expected ${expect.stale} stale(s), got ${r.stales.length}: ${JSON.stringify(r.stales)}`);
  }
  if (r.notes.length !== expect.notes) {
    problems.push(`expected ${expect.notes} note(s), got ${r.notes.length}: ${JSON.stringify(r.notes)}`);
  }
  // observations never fail verification (batch-6 re-check): assert no verdict
  // channel ever carries an observation finding, and that the loud ordering flags
  // land in notes with the SUSPECT ORDERING prefix
  for (const frag of expect.flagHas || []) {
    if (!r.notes.some((m) => m.includes("SUSPECT ORDERING") && m.includes(frag))) {
      problems.push(`missing SUSPECT ORDERING note containing "${frag}"`);
    }
  }
  for (const frag of expect.devHas || []) {
    if (!r.deviations.some((m) => m.includes(frag))) problems.push(`missing deviation containing "${frag}"`);
  }
  for (const frag of expect.staleHas || []) {
    if (!r.stales.some((m) => m.includes(frag))) problems.push(`missing stale containing "${frag}"`);
  }
  for (const frag of expect.noteHas || []) {
    if (!r.notes.some((m) => m.includes(frag))) problems.push(`missing note containing "${frag}"`);
  }
  for (const frag of expect.logHas ? [expect.logHas] : []) {
    if (!r.logs.some((m) => m.includes(frag))) problems.push(`missing log containing "${frag}"`);
  }
  if (problems.length) {
    failures++;
    console.error(`FAIL ${name}`);
    for (const p of problems) console.error(`  ${p}`);
  } else {
    console.log(`pass ${name}`);
  }
}
console.log(`\n=== CAST VERIFY HARNESS ${failures === 0 ? `OK (${cases.length} cases)` : `FAILED (${failures}/${cases.length})`} ===`);
if (failures > 0) process.exitCode = 1;
