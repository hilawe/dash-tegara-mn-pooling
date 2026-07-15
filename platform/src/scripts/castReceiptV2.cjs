/**
 * The snapshot-first cast flow (cast-governance contract v2, registerCastV2.cjs).
 * This is the batch-3 review's named next rung: the v1 receipt bound CURRENT ledger
 * state to CURRENT L1 state, so churn after an honest cast made it fail and a replace
 * erased evidence. v2 splits the claim in two, each with permanent evidence:
 *
 *   HISTORICAL HONESTY: before casting, the operator publishes an immutable
 *   tallySnapshot embedding the canonical member rows (self-authenticating: rebuild
 *   the tally from the rows and compare the hash, no historical queries needed).
 *   After casting, an immutable castReceipt binds the actual L1 vote to that
 *   snapshot. A vote that deviates from ITS OWN committed snapshot is a DEVIATION
 *   forever, whatever the ledger does later. Verification scans EVERY snapshot and
 *   EVERY receipt, so a deviating historical cast cannot hide behind a later clean
 *   re-cast. The commit-before-cast test is TIMESTAMP CONSISTENCY, not proof of
 *   order: a vote's nTime is operator-set. The check flags a vote whose CLAIMED
 *   time sits more than the grace before its snapshot; the way to EVADE it is to
 *   POSTDATE nTime (Core allows up to one hour ahead of adjusted time), which hides
 *   a cast-first vote whenever the snapshot follows within the combined window.
 *   Backdating, the other direction, can only self-incriminate here, but it is why
 *   the reverse claim (proving a cast came AFTER its snapshot) is impossible from
 *   nTime alone. Neither direction of an operator-set field is proof; a sound
 *   ordering anchor needs material the operator cannot choose and is recorded as
 *   future work in the findings record.
 *
 *   FRESHNESS: whether the CURRENT tally still agrees with the CURRENT vote. When
 *   members change their preferences, the standing vote goes STALE, the operator
 *   owes a new snapshot + re-cast + new receipt, and until then verify exits
 *   non-zero with the STALE label (distinct from DEVIATION, because the historical
 *   record still shows every past cast was honest).
 *
 * What a snapshot does NOT prove: that its embedded rows matched the ledger at
 * snapshot time. Preferences are mutable documents, so post-hoc reconstruction is
 * impossible by design; the check is social and immediate, any member can run
 * verify while the snapshot stands (its freshness check compares the live ledger),
 * and an operator who snapshots rows the members never wrote is caught then, with
 * the immutable snapshot as the permanent evidence of the false claim.
 *
 * The verify decision surface, compact (S = any snapshot exists, V = a current L1
 * funding vote exists, R = a receipt matching the current vote exists; every
 * snapshot self-authenticates and every receipt is internally checked FIRST,
 * regardless of row):
 *
 *   S V R   outcome
 *   - - -   clean when the current tally is "none", else DEVIATION (no snapshot)
 *   - any   DEVIATION (no snapshot despite governance activity)
 *   S - -   latest "none": clean (plus STALE if the tally moved); else DEVIATION
 *           (demanded cast absent). Historical receipts with no current vote are a
 *           NOTE (anomalous, not accusatory: this Core cannot withdraw a vote)
 *   S V -   DEVIATION (unattested current cast)
 *   S V R   clean when the receipt matches Core exactly, its snapshot
 *           self-authenticates, outcomes agree, and timestamps are consistent;
 *           each failed leg is its own DEVIATION. STALE rides on top whenever the
 *           CURRENT tally disagrees with the standing snapshot or vote.
 *
 * Member VOTE OBSERVATIONS (voteWatch.cjs), when present, are CORROBORATION that
 * NEVER fails verification: an observation does not authenticate a signed vote, and
 * a member can carpet the future-time window with candidate hashes, so any
 * observation-driven failure would be a member-controlled kill switch. Ordering
 * anomalies (a member observation predating a receipt's snapshot, or a
 * member-observed vote with no receipt) surface as loud "SUSPECT ORDERING" / ORPHAN
 * NOTES for social adjudication; the verdict comes only from the cryptographic
 * machinery (full analysis in castVerify.cjs).
 *
 * Subcommands (operator-only where noted):
 *   snapshot <poolId> <proposalHash>          (operator) commit the current tally
 *   publish  <poolId> <proposalHash>          (operator) attest the current L1 vote
 *   verify   <poolId> <proposalHash>          (anyone) full deviation + freshness check
 *   probe    <poolId> <proposalHash>          (test) non-owner creation attempt, expects
 *                                             Platform to refuse (creationRestrictionMode)
 *
 * Env: the usual devnet vars, LEDGER selects the pool-ledger version, FORK_RPC_URL
 * names the Core node whose governance state is read.
 */
const Dash = require("dash");
const { Identifier } = require("@dashevo/wasm-dpp");
const { loadEnv, activeContractId, activeCastId, isCastV3, isV5 } = require("./envStore.cjs");
const { fetchAll, fetchUpTo } = require("./query.cjs");

// the observation fetch is PER CURRENT MEMBER (byProposalObserver index), so
// non-member or hostile-member spam cannot crowd real member evidence out of the
// window (batch-6 review). Each member's set is capped; a member self-spamming past
// the cap truncates only their own slot, reported loudly. MAX_MEMBER_SLOTS bounds
// total work for a pathologically large pool; the aggregate bound passed to
// verifyCast is sized so it never truncates ACROSS members (batch-6 DoS re-check).
const PER_MEMBER_OBS_CAP = 60;
const MAX_MEMBER_SLOTS = 256;
const { computeTally, tallyHash, canonicalMembers, validateCanonicalRows } = require("./tally.cjs");
const { fetchL1Vote, fetchCollateral } = require("./l1gov.cjs");
const { verifyCast } = require("./castVerify.cjs");

const platformHeight = async (client) => {
  try {
    const st = await client.getDAPIClient().platform.getStatus();
    const h = st && ((st.chain && (st.chain.latestBlockHeight ?? st.chain.blocksCount))
      ?? st.latestBlockHeight);
    const n = Number(h);
    return Number.isSafeInteger(n) && n > 0 ? n : 0;
  } catch { return 0; }
};

(async () => {
  const [cmd, poolIdStr, proposalHex] = process.argv.slice(2);
  if (!["snapshot", "publish", "verify", "probe"].includes(cmd) || !poolIdStr
    || !/^[0-9a-f]{64}$/i.test(proposalHex || "")) {
    console.error("usage: castReceiptV2.cjs snapshot|publish|verify|probe <poolId> <proposalHash 64-hex>");
    process.exit(2);
  }
  if (!process.env.FORK_RPC_URL && cmd !== "probe" && cmd !== "snapshot") {
    console.error("FORK_RPC_URL is required (the Core node whose governance state is checked)");
    process.exit(2);
  }
  const env = loadEnv();
  if (!activeCastId(env)) {
    console.error("run registerCastV2.cjs first (need CAST_V2_CONTRACT_ID; or CAST=v3 with registerCastV3.cjs)");
    process.exit(1);
  }
  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
    apps: {
      poolLedger: { contractId: activeContractId(env) },
      castGov: { contractId: activeCastId(env) },
      // the member-run vote-observation namespace (voteWatch.cjs), consumed by
      // verify as chain-anchored ordering evidence when present
      ...(env.VOTE_OBS_CONTRACT_ID ? { voteObs: { contractId: env.VOTE_OBS_CONTRACT_ID } } : {}),
    },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);
  try {
    const poolId = Identifier.from(poolIdStr);
    const proposalBuf = Buffer.from(proposalHex, "hex");
    const pool = (await client.platform.documents.get("poolLedger.pool", {
      where: [["$id", "==", poolId]],
    }))[0];
    if (!pool) throw new Error(`no pool ${poolIdStr} on the ledger`);
    const proTxHex = Buffer.from(pool.toObject().proTxHash).toString("hex");
    const poolOperator = pool.toObject().operatorIdentityId
      ? Identifier.from(Buffer.from(pool.toObject().operatorIdentityId)).toString() : null;
    if (!poolOperator) {
      throw new Error("the pool records no operatorIdentityId; snapshots and receipts cannot be attributed");
    }

    // the current tally, one shared function of the ledger for every subcommand
    const shares = (await fetchAll(client, "poolLedger.share", { where: [["poolId", "==", poolId]] }))
      .map((d) => ({ owner: d.getOwnerId().toString(), bps: Number(d.toObject().shareBps) }));
    const totalBps = shares.reduce((s, x) => s + x.bps, 0);
    if (shares.length === 0 || totalBps !== 10000) {
      throw new Error(`the pool's shares sum to ${totalBps} bps over ${shares.length} shares, not 10000; ` +
        "refusing a malformed or mid-churn pool (same refusal as the governor, B8)");
    }
    const prefs = (await fetchAll(client, "poolLedger.votePreference", {
      where: [["poolId", "==", poolId]],
    })).filter((d) => Buffer.from(d.toObject().proposalHash).toString("hex") === proposalHex.toLowerCase());
    // the shared preference-maps helper (holistic-round F6): presence-based delegateTo
    // extraction, identical in every operator tool; rows keep the raw choice plus the
    // target (format 2)
    const { prefsToMaps } = require("./ledgerTally.cjs");
    const { choiceByOwner, delegateToByOwner } = prefsToMaps(prefs);
    const tally = computeTally(shares, choiceByOwner, delegateToByOwner);
    const tHash = tallyHash(activeContractId(env), poolIdStr, proposalHex, tally);
    console.log(`current tally: yes ${tally.final.yes} / no ${tally.final.no} / abstain ${tally.final.abstain}, ` +
      `withheld ${tally.weights.withheld} -> outcome "${tally.outcome}" (hash ${tHash.toString("hex").slice(0, 16)}...)`);

    const snapshots = (await fetchAll(client, "castGov.tallySnapshot", {
      where: [["poolId", "==", poolId], ["proposalHash", "==", proposalBuf]],
      orderBy: [["$createdAt", "asc"]],
    }));
    const latestSnap = snapshots.length ? snapshots[snapshots.length - 1] : null;

    if (cmd === "probe") {
      // enforcement probe for creationRestrictionMode: a NON-owner identity attempts
      // to create a snapshot; Platform itself must refuse it. DESTRUCTIVE IF THE
      // PREMISE FAILS: on a version that does not enforce owner-only creation the
      // probe writes an UNDELETABLE document into the real contract (immutable
      // types), which could become the standing snapshot. Gated accordingly
      // (batch-4 review, major); this ran once at deployment, 2026-07-11, and the
      // refusal is on record.
      if (process.env.PROBE_CONFIRM !== "leave-probe-evidence") {
        throw new Error("the probe writes permanent evidence if enforcement is off; run it only as a " +
          "one-time deployment test with PROBE_CONFIRM=leave-probe-evidence");
      }
      console.log(`probe target: network ${process.env.NETWORK || "testnet"}, contract ${activeCastId(env)}`);
      const who = env.FUNDER_ID;
      if (!who || who === poolOperator) throw new Error("probe needs FUNDER_ID distinct from the operator");
      const funder = await client.platform.identities.get(who);
      const doc = await client.platform.documents.create("castGov.tallySnapshot", funder, {
        poolId: poolId.toBuffer(), proposalHash: proposalBuf, tallyHash: tHash,
        outcome: tally.outcome, proTxHash: Buffer.from(proTxHex, "hex"),
        platformHeight: 0,
        tallyRows: Buffer.from(JSON.stringify(canonicalMembers(tally))),
        // the probe must be schema-valid so a rejection can only mean the ownership
        // restriction (cast v3 requires formatVersion)
        ...(isCastV3() ? { formatVersion: 1 } : {}),
      });
      try {
        await client.platform.documents.broadcast({ create: [doc] }, funder);
        console.error("UNEXPECTED: Platform ACCEPTED a non-owner snapshot; creationRestrictionMode is " +
          "NOT enforced on this version. The client-side owner checks remain the guard. Deleting is " +
          "impossible (canBeDeleted false); the document stays as probe evidence: " + doc.getId().toString());
        process.exitCode = 1;
      } catch (e) {
        console.log("\n=== OWNER-ONLY CREATION ENFORCED: Platform refused the non-owner snapshot ===");
        console.log("refusal:", ((e && e.message) || String(e)).split("\n")[0]);
      }
      return;
    }

    if (cmd === "snapshot") {
      if (env.IDENTITY_ID !== poolOperator) {
        throw new Error(`this identity is not the pool's operator (${poolOperator}); only the operator snapshots`);
      }
      if (latestSnap && Buffer.from(latestSnap.toObject().tallyHash).equals(tHash)) {
        console.log(`\n=== SNAPSHOT ALREADY CURRENT: ${latestSnap.getId().toString()} commits this exact tally ===`);
        return;
      }
      // the SAME validator the verifier runs gates creation (third-model batch-4
      // major: the row cap was verifier-only, so an oversize pool could commit a
      // snapshot that then always failed verification). One policy, both ends:
      // 32 rows, documented in tally.cjs; larger memberships need the next
      // contract revision's larger tallyRows bound.
      const memberRows = canonicalMembers(tally);
      // format 2 (cast v3) admits the delegateTo rows; a v2 snapshot must not carry
      // them, so a targeted delegation under CAST v2 is refused here by the validator
      const fmt = isCastV3() ? 2 : 1;
      validateCanonicalRows(memberRows, fmt);
      const rows = Buffer.from(JSON.stringify(memberRows));
      const byteBound = isCastV3() ? 5000 : 4096;
      if (rows.length > byteBound) {
        throw new Error(`canonical rows are ${rows.length} bytes, above the ${byteBound}-byte snapshot ` +
          "bound; the schema bound covers the 32-slot designs this prototype targets");
      }
      const operator = await client.platform.identities.get(env.IDENTITY_ID);
      const height = await platformHeight(client);
      const doc = await client.platform.documents.create("castGov.tallySnapshot", operator, {
        poolId: poolId.toBuffer(), proposalHash: proposalBuf, tallyHash: tHash,
        outcome: tally.outcome, proTxHash: Buffer.from(proTxHex, "hex"),
        platformHeight: height, tallyRows: rows,
        ...(isCastV3() ? { formatVersion: fmt } : {}),
      });
      await client.platform.documents.broadcast({ create: [doc] }, operator);
      console.log(`\n=== TALLY SNAPSHOT PUBLISHED: ${doc.getId().toString()} (platform height ${height || "n/a"}) ===`);
      console.log(tally.outcome === "none"
        ? "every weight is withheld; cast NOTHING (a vote now would be a deviation)"
        : "now cast on L1: `gobject vote-alias " + proposalHex.toLowerCase() + " funding " + tally.outcome +
          " " + proTxHex + "`, then run publish to attest the vote");
      return;
    }

    const l1 = await fetchL1Vote(proTxHex, proposalHex.toLowerCase());
    console.log(l1
      ? `current L1 vote by ${proTxHex.slice(0, 16)}...: ${l1.outcome} (${l1.signal}) at ${l1.time}, vote hash ${l1.voteHash.slice(0, 16)}...`
      : `no current L1 funding vote by ${proTxHex.slice(0, 16)}... on this proposal`);
    const receipts = (await fetchAll(client, "castGov.castReceipt", {
      where: [["poolId", "==", poolId], ["proposalHash", "==", proposalBuf]],
    }));

    if (cmd === "publish") {
      if (env.IDENTITY_ID !== poolOperator) {
        throw new Error(`this identity is not the pool's operator (${poolOperator}); only the operator publishes`);
      }
      if (!latestSnap) {
        throw new Error("no tally snapshot exists for this proposal; snapshot FIRST, then cast, then publish");
      }
      const snapObj = latestSnap.toObject();
      if (!l1) {
        if (snapObj.outcome === "none") {
          console.log("\nsnapshot outcome is \"none\" and no vote exists; nothing to attest (correct state)");
          return;
        }
        console.log("\nWARNING: the snapshot demands a cast but no L1 vote exists yet; cast first, then publish.");
        process.exitCode = 1;
        return;
      }
      if (l1.outcome !== snapObj.outcome) {
        console.log(`\nWARNING: the L1 vote ("${l1.outcome}") DEVIATES from the committed snapshot ` +
          `("${snapObj.outcome}"). Publishing the receipt anyway: it permanently records the deviation.`);
      }
      if (!Buffer.from(snapObj.tallyHash).equals(tHash)) {
        console.log("NOTE: the ledger tally has moved since the latest snapshot; if the members' outcome " +
          "changed, snapshot again and re-cast after this attestation");
      }
      const operator = await client.platform.identities.get(env.IDENTITY_ID);
      const doc = await client.platform.documents.create("castGov.castReceipt", operator, {
        poolId: poolId.toBuffer(), proposalHash: proposalBuf,
        snapshotId: latestSnap.getId().toBuffer(),
        voteHash: Buffer.from(l1.voteHash, "hex"), voteOutcome: l1.outcome,
        voteTimestamp: l1.time, voteSignal: l1.signal,
        proTxHash: Buffer.from(proTxHex, "hex"),
        ...(isCastV3() ? { kind: "cast" } : {}),
      });
      try {
        await client.platform.documents.broadcast({ create: [doc] }, operator);
        console.log(`\n=== CAST RECEIPT PUBLISHED (immutable): ${doc.getId().toString()} ===`);
      } catch (e) {
        const msg = (e && e.message) || String(e);
        if (/duplicate unique properties/i.test(msg)) {
          console.log("\n=== THIS VOTE IS ALREADY ATTESTED (one immutable receipt per vote hash) ===");
          return;
        }
        throw e;
      }
      return;
    }

    // verify: the decision core is the PURE function in castVerify.cjs (driven
    // offline by castVerifyTest.cjs across the header's decision table); this block
    // only assembles the state from Platform and Core and prints the result.
    // Historical honesty first, then freshness; every snapshot and every receipt is
    // scanned; historical receipt fields are authenticated against Core's own vote
    // hash; the ordering test is timestamp consistency (see the header).
    const nowHeight = await platformHeight(client);
    const collateral = await fetchCollateral(proTxHex);
    // Fetch observations PER CURRENT MEMBER (batch-6 second review): only members'
    // observations produce the loud ordering/orphan notes, so pulling each member's
    // set directly (byProposalObserver index, oldest-first, per-member cap) means
    // non-member or hostile-member spam cannot crowd real member evidence out of a
    // bounded proposal-wide window. Each member's own set is bounded and any
    // truncation is loud; a member self-spamming only truncates their own slot.
    let observationDocs = [];
    const observationFetchTruncatedOwners = [];
    let observationMemberSlotsSkipped = 0;
    // deterministic member order (code-unit), so the ceiling and any skipped-slot
    // report are reproducible and not attacker-gameable
    const memberOwnerIds = [...new Set(shares.map((x) => x.owner))]
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const fetchSlots = memberOwnerIds.slice(0, MAX_MEMBER_SLOTS);
    observationMemberSlotsSkipped = memberOwnerIds.length - fetchSlots.length;
    if (env.VOTE_OBS_CONTRACT_ID) {
      for (const ownerId of fetchSlots) {
        const r = await fetchUpTo(client, "voteObs.observation", PER_MEMBER_OBS_CAP, {
          where: [["proposalHash", "==", proposalBuf], ["$ownerId", "==", Identifier.from(ownerId)]],
          orderBy: [["$createdAt", "asc"]],
        });
        observationDocs.push(...r.docs);
        if (r.truncated) observationFetchTruncatedOwners.push(ownerId);
      }
    }
    // size the aggregate bound so verifyCast never truncates ACROSS members
    const aggregateObsBound = Math.max(fetchSlots.length * PER_MEMBER_OBS_CAP, 1);
    const result = verifyCast({
      contractId: activeContractId(env),
      poolIdStr,
      proposalHex,
      poolOperator,
      proTxHex,
      collateral,
      tally,
      tHash,
      snapshots: snapshots.map((d) => {
        const o = d.toObject();
        return {
          id: d.getId().toString(),
          owner: d.getOwnerId().toString(),
          createdAt: Number(o.$createdAt),
          tallyHashHex: Buffer.from(o.tallyHash).toString("hex"),
          outcome: o.outcome,
          proTxHex: Buffer.from(o.proTxHash).toString("hex"),
          platformHeight: Number(o.platformHeight),
          tallyRowsUtf8: Buffer.from(o.tallyRows).toString("utf8"),
          // cast v3 snapshots name their row encoding; absent means format 1
          ...(o.formatVersion !== undefined ? { formatVersion: Number(o.formatVersion) } : {}),
        };
      }),
      receipts: receipts.map((d) => {
        const o = d.toObject();
        return {
          id: d.getId().toString(),
          owner: d.getOwnerId().toString(),
          snapshotId: Identifier.from(Buffer.from(o.snapshotId)).toString(),
          voteHashHex: Buffer.from(o.voteHash).toString("hex"),
          voteOutcome: o.voteOutcome,
          voteTimestamp: Number(o.voteTimestamp),
          voteSignal: o.voteSignal,
          proTxHex: Buffer.from(o.proTxHash).toString("hex"),
          // cast v3 receipts carry a kind; a missed-vote attestation is surfacing,
          // never a vote, and verifyCast excludes it from the vote-matching legs
          ...(o.kind !== undefined ? { kind: o.kind } : {}),
        };
      }),
      l1,
      nowHeight,
      maxObservations: aggregateObsBound,
      observationFetchTruncatedOwners,
      observationMemberSlotsSkipped,
      observations: observationDocs.map((d) => {
        const o = d.toObject();
        return {
          id: d.getId().toString(),
          owner: d.getOwnerId().toString(),
          createdAt: Number(o.$createdAt),
          voteHashHex: Buffer.from(o.voteHash).toString("hex"),
          voteOutcome: o.voteOutcome,
          voteSignal: o.voteSignal,
          voteTimestamp: Number(o.voteTimestamp),
          proTxHex: Buffer.from(o.proTxHash).toString("hex"),
        };
      }),
    });
    for (const m of result.logs) console.log(m);
    for (const m of result.notes) console.log(`NOTE: ${m}`);
    for (const m of result.deviations) console.error(`  DEVIATION: ${m}`);
    for (const m of result.stales) console.error(`  STALE: ${m}`);
    const dev = result.deviations.length, st = result.stales.length;
    // observation findings ride in notes and never affect the verdict (batch-6
    // re-check): only the cryptographic machinery (receipt hash authentication,
    // snapshot self-authentication, tally) can fail verification
    const verdict = dev === 0 && st === 0
      ? "VERIFIED: every recorded cast is hash-authentic and consistent with its committed snapshot " +
        "(timestamps consistent; nTime is operator-set), and the standing vote matches the members' will"
      : [dev > 0 ? `FAILED (${dev} deviation(s))` : "", st > 0 ? `STALE (${st})` : ""]
        .filter(Boolean).join(", ");
    console.log(`\n=== CAST RECEIPT V2 ${verdict} ===`);
    if (dev > 0 || st > 0) process.exitCode = 1;
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
