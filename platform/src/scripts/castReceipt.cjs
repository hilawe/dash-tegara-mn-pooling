/**
 * The cast receipt, publish and verify (first rung of the governance mitigation ladder).
 *
 *   publish <poolId> <proposalHash>
 *     The OPERATOR's act. Recomputes the members' tally from the pool ledger
 *     (tally.cjs, the same function the governor prints), reads the masternode's
 *     actual L1 vote from the fork node (`protx info` for the collateral outpoint,
 *     then `gobject getcurrentvotes <proposal> <collateral-txid> <vout>`), and
 *     publishes ONE receipt binding the two, signed by the operator identity. If the
 *     L1 vote does not match the tally, the publish still records the truth and says
 *     so loudly; refusing to publish would only hide the deviation.
 *
 *   verify <poolId> <proposalHash>
 *     ANYONE's act (needs no identity). Reads the receipt, recomputes the tally from
 *     the ledger and compares the tally hash and outcome, refetches the L1 vote and
 *     compares the vote record. Exits non-zero on any deviation, so it slots into the
 *     same discipline as ledgerAudit.cjs.
 *
 * What this does and does not prove: the receipt makes the operator's cast VISIBLE and
 * ATTRIBUTABLE against the members' public tally; it does not prevent a deviating cast
 * (that is the threshold-voting-key rung higher up the ladder). A deviation shows as a
 * receipt that fails verification, or as a missing receipt where the tally demanded a
 * cast, both of which any member can detect from public data.
 *
 * KNOWN LIMITATION (batch-3 review, recorded, not yet built): verification binds the
 * CURRENT ledger tally to the CURRENT L1 vote. There is no tally cutoff: preferences or
 * membership that change after an honest cast make it fail verification until the
 * receipt is republished, an operator can time a publish against a preference change,
 * and a replace erases the prior receipt's content. The fix is the snapshot-first flow
 * (the governor publishes an immutable tally snapshot before the cast instruction, one
 * immutable receipt per vote hash, verification pins to the snapshot), which folds into
 * the next contract version together with operator-bound receipt ownership. Until then
 * the receipt attests consistency NOW, and a re-verify after any change is expected to
 * demand a republish.
 *
 * Env: the usual devnet vars, LEDGER selects the pool-ledger version, and
 * FORK_RPC_URL=http://user:pass@host:port names the Core node whose governance state is
 * checked (the standing fork node in this environment).
 */
const Dash = require("dash");
const { Identifier } = require("@dashevo/wasm-dpp");
const { loadEnv, activeContractId } = require("./envStore.cjs");
const { fetchAll } = require("./query.cjs");
const { computeTally, tallyHash } = require("./tally.cjs");
// the L1 read side (forkRpc + the hardened funding-vote fetch) is shared with the v2
// snapshot-first engine in l1gov.cjs
const { fetchL1Vote } = require("./l1gov.cjs");

(async () => {
  const [cmd, poolIdStr, proposalHex] = process.argv.slice(2);
  if (!["publish", "verify"].includes(cmd) || !poolIdStr || !/^[0-9a-f]{64}$/i.test(proposalHex || "")) {
    console.error("usage: castReceipt.cjs publish|verify <poolId> <proposalHash 64-hex>");
    process.exit(2);
  }
  if (!process.env.FORK_RPC_URL) {
    console.error("FORK_RPC_URL is required (the Core node whose governance state is checked)");
    process.exit(2);
  }
  const env = loadEnv();
  if (!env.CAST_CONTRACT_ID) {
    console.error("run registerCastReceipt.cjs first (need CAST_CONTRACT_ID)");
    process.exit(1);
  }
  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    // no skip-sync shortcut: publish broadcasts documents, and the SDK derives the
    // operator identity's signing key from the synced wallet (the shortcut made the
    // sync itself fail on this devnet's chain height)
    wallet: { mnemonic: env.MNEMONIC },
    apps: {
      poolLedger: { contractId: activeContractId(env) },
      castLedger: { contractId: env.CAST_CONTRACT_ID },
    },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);
  let deviations = 0;
  const deviate = (msg) => { deviations++; console.error(`  DEVIATION: ${msg}`); };

  try {
    // no wallet touch: this script writes documents (operator identity) and reads the
    // ledger; nothing here builds an L1 transaction, so the consumed-outpoint guard
    // does not apply and the wallet never needs to sync
    const poolId = Identifier.from(poolIdStr);
    const pool = (await client.platform.documents.get("poolLedger.pool", {
      where: [["$id", "==", poolId]],
    }))[0];
    if (!pool) throw new Error(`no pool ${poolIdStr} on the ledger`);
    const proTxHex = Buffer.from(pool.toObject().proTxHash).toString("hex");
    // the pool's recorded operator is the ONLY identity whose receipt means anything;
    // without this binding any identity could occupy the unique receipt slot and be
    // read as the operator's attestation (batch-3 review finding, major)
    const poolOperator = pool.toObject().operatorIdentityId
      ? Identifier.from(Buffer.from(pool.toObject().operatorIdentityId)).toString() : null;
    if (!poolOperator) {
      throw new Error("the pool records no operatorIdentityId; a cast receipt cannot be attributed " +
        "for it (fix the pool document first)");
    }

    // the tally, recomputed from the ledger by BOTH subcommands (one shared function)
    const shares = (await fetchAll(client, "poolLedger.share", { where: [["poolId", "==", poolId]] }))
      .map((d) => ({ owner: d.getOwnerId().toString(), bps: Number(d.toObject().shareBps),
                     createdAt: Number(d.toObject().$createdAt) }))
      .sort((a, b) => a.createdAt - b.createdAt);
    const totalBps = shares.reduce((s, x) => s + x.bps, 0);
    if (shares.length === 0 || totalBps !== 10000) {
      throw new Error(`the pool's shares sum to ${totalBps} bps over ${shares.length} shares, not 10000; ` +
        "no receipt can bind a malformed or mid-churn pool (same refusal as the governor, B8)");
    }
    const prefs = (await fetchAll(client, "poolLedger.votePreference", {
      where: [["poolId", "==", poolId]],
    })).filter((d) => Buffer.from(d.toObject().proposalHash).toString("hex") === proposalHex.toLowerCase());
    const choiceByOwner = new Map(prefs.map((d) => [d.getOwnerId().toString(), d.toObject().choice]));
    const tally = computeTally(shares.map(({ owner, bps }) => ({ owner, bps })), choiceByOwner);
    const tHash = tallyHash(activeContractId(env), poolIdStr, proposalHex, tally);
    console.log(`tally: yes ${tally.final.yes} / no ${tally.final.no} / abstain ${tally.final.abstain}, ` +
      `withheld ${tally.weights.withheld} -> outcome "${tally.outcome}"`);
    console.log(`tally hash: ${tHash.toString("hex")}`);

    const l1 = await fetchL1Vote(proTxHex, proposalHex.toLowerCase());
    console.log(l1
      ? `L1 vote by ${proTxHex.slice(0, 16)}...: ${l1.outcome} (${l1.signal}) at ${l1.time}, vote hash ${l1.voteHash.slice(0, 16)}...`
      : `no current L1 funding vote by ${proTxHex.slice(0, 16)}... on this proposal`);

    const existing = (await client.platform.documents.get("castLedger.castReceipt", {
      where: [["poolId", "==", poolId], ["proposalHash", "==", Buffer.from(proposalHex, "hex")]],
    }))[0] || null;

    if (cmd === "publish") {
      // only the pool's recorded operator publishes its receipts; anyone else's
      // document is not an attestation, whatever its fields say
      if (env.IDENTITY_ID !== poolOperator) {
        throw new Error(`this identity (${env.IDENTITY_ID}) is not the pool's recorded operator ` +
          `(${poolOperator}); refusing to publish a receipt it could not attest`);
      }
      if (existing && existing.getOwnerId().toString() !== poolOperator) {
        throw new Error(`a receipt for this pool and proposal already exists but is owned by ` +
          `${existing.getOwnerId().toString()}, not the operator. It cannot be replaced (replaces ` +
          "need the owner's signature) and it is itself evidence: verify flags it as unattributed. " +
          "The schema-level fix (operator-bound receipts) is recorded for the next contract version.");
      }
      const operator = await client.platform.identities.get(env.IDENTITY_ID);
      if (tally.outcome !== "none" && !l1) {
        console.log("\nWARNING: the tally demands a cast but no L1 vote exists yet; publishing a " +
          "receipt without a vote record would attest to nothing. Cast first, then publish.");
        process.exitCode = 1;
        return;
      }
      if (l1 && l1.outcome !== tally.outcome) {
        console.log(`\nWARNING: the L1 vote ("${l1.outcome}") DEVIATES from the members' tally ` +
          `("${tally.outcome}"). Publishing the receipt anyway: the receipt records what actually ` +
          "happened, and hiding it is worse.");
      }
      const fields = {
        poolId: poolId.toBuffer(),
        proposalHash: Buffer.from(proposalHex, "hex"),
        tallyHash: tHash,
        outcome: tally.outcome,
        proTxHash: Buffer.from(proTxHex, "hex"),
        ...(l1 ? {
          voteHash: Buffer.from(l1.voteHash, "hex"),
          voteOutcome: l1.outcome,
          voteTimestamp: l1.time,
          voteSignal: l1.signal,
        } : {}),
      };
      if (existing) {
        // an update replaces a prior attestation; say what changed so the operator's
        // own log keeps the before/after that the ledger does not (third-model idea)
        const prev = existing.toObject();
        console.log(`replacing the prior receipt: tally hash ${Buffer.from(prev.tallyHash).toString("hex").slice(0, 16)}... -> ` +
          `${tHash.toString("hex").slice(0, 16)}..., vote ${prev.voteOutcome || "none"} -> ${l1 ? l1.outcome : "none"}`);
        if (!l1 && prev.voteHash) {
          // a replace cannot REMOVE fields, so an update from vote-present to no-vote
          // recreates the receipt instead of leaving a stale vote record on it
          await client.platform.documents.broadcast({ delete: [existing] }, operator);
          const doc = await client.platform.documents.create("castLedger.castReceipt", operator, fields);
          await client.platform.documents.broadcast({ create: [doc] }, operator);
          console.log(`\n=== CAST RECEIPT RECREATED (stale vote record dropped): ${doc.getId().toString()} ===`);
          return;
        }
        for (const [k, v] of Object.entries(fields)) existing.set(k, v);
        await client.platform.documents.broadcast({ replace: [existing] }, operator);
        console.log(`\n=== CAST RECEIPT UPDATED: ${existing.getId().toString()} ===`);
      } else {
        const doc = await client.platform.documents.create("castLedger.castReceipt", operator, fields);
        await client.platform.documents.broadcast({ create: [doc] }, operator);
        console.log(`\n=== CAST RECEIPT PUBLISHED: ${doc.getId().toString()} ===`);
      }
      return;
    }

    // verify. The L1 state is compared UNCONDITIONALLY: a "none" tally with a live
    // funding vote is the members-said-do-nothing deviation, which the old
    // outcome-gated check silently passed (batch-3 review finding, major).
    if (l1 && tally.outcome === "none") {
      deviate(`the members withheld every weight but a current L1 funding vote exists ("${l1.outcome}")`);
    }
    if (l1 && tally.outcome !== "none" && l1.outcome !== tally.outcome) {
      deviate(`the L1 vote ("${l1.outcome}") deviates from the members' tally ("${tally.outcome}")`);
    }
    if (!l1 && tally.outcome !== "none") {
      deviate("the tally demands a cast but no current L1 vote exists");
    }
    if (!existing) {
      if (tally.outcome !== "none") {
        deviate("no receipt exists although the tally demands a cast");
      } else if (!l1) {
        console.log("no receipt, no cast demanded, no L1 vote; nothing to verify");
      } else {
        deviate("no receipt exists for the vote that was cast");
      }
    } else {
      const r = existing.toObject();
      const owner = existing.getOwnerId().toString();
      console.log(`receipt ${existing.getId().toString()} by ${owner}`);
      // attribution first: a receipt not signed by the pool's recorded operator is
      // not an attestation at all, whatever its fields claim
      if (owner !== poolOperator) {
        deviate(`the receipt is signed by ${owner}, not the pool's recorded operator ${poolOperator}`);
      }
      if (!Buffer.from(r.tallyHash).equals(tHash)) {
        deviate("the receipt's tally hash does not reproduce from the ledger");
      }
      if (r.outcome !== tally.outcome) {
        deviate(`the receipt claims outcome "${r.outcome}" but the ledger tally says "${tally.outcome}"`);
      }
      if (Buffer.from(r.proTxHash).toString("hex") !== proTxHex) {
        deviate("the receipt names a different masternode than the pool records");
      }
      if (l1) {
        if (!r.voteHash) {
          deviate("the receipt omits the L1 vote record that exists");
        } else {
          if (Buffer.from(r.voteHash).toString("hex") !== l1.voteHash) {
            deviate("the receipt's vote hash does not match the current L1 vote (a re-cast leaves " +
              "a stale receipt until the operator republishes)");
          }
          if (r.voteOutcome !== l1.outcome) {
            deviate(`the receipt records vote "${r.voteOutcome}" but L1 shows "${l1.outcome}"`);
          }
          if (r.voteSignal !== l1.signal) {
            deviate(`the receipt's vote signal "${r.voteSignal}" is not the funding vote's "${l1.signal}"`);
          }
          if (Number(r.voteTimestamp) !== l1.time) {
            deviate(`the receipt's vote timestamp ${r.voteTimestamp} differs from L1's ${l1.time}`);
          }
        }
      } else if (r.voteHash) {
        deviate("the receipt carries a vote record but no current L1 vote exists");
      }
    }
    console.log(`\n=== CAST RECEIPT ${deviations === 0 ? "VERIFIED: the operator cast exactly what the members' tally asked" : `FAILED (${deviations} deviation(s))`} ===`);
    if (deviations > 0) process.exitCode = 1;
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
