/**
 * Read-only audit of the whole pool ledger, built for the multi-epoch/multi-pool scale
 * run. Walks every pool on the contract and cross-checks its recorded state:
 *
 *   - shares: the bps sum to 10000 and the contributions are positive,
 *   - accruals: grouped per epochHeight, each epoch's per-funder amounts must reproduce
 *     the rail's split rule exactly (floor per share in creation order, dust to the last),
 *   - observations (optional EPOCHS_DIR): where an epoch file matches the pool's
 *     proTxHash and the accrual height, the epoch's accrual sum must equal the
 *     recomputed distributable remainder (amount minus the flat L1 fee minus the
 *     operator cut), tying the ledger back to the observed L1 inflow.
 *
 * Nothing is written; the script exits non-zero on the first inconsistency. Run it like
 * the other scripts (container, --network host, CA mounted), plus optionally
 * -e EPOCHS_DIR=/app/epochs -v "$PWD/../bridge/epochs:/app/epochs:ro".
 */
const fs = require("fs");
const path = require("path");
const Dash = require("dash");
const { Identifier } = require("@dashevo/wasm-dpp");
const { ASSET_LOCK_FEE_DUFFS, validateObservation, validateDissolution } = require("./observation.cjs");
const { fetchAll } = require("./query.cjs");
const { loadEnv, activeContractId, isV3 } = require("./envStore.cjs");

const DASHfmt = (duffs) => (duffs / 100000000).toFixed(8);

const loadObservations = () => {
  const out = [];
  const readDir = (dir, validator) => {
    if (!dir) return;
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".json"))) {
      const obs = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
      validator(obs, f);
      out.push({ file: f, obs });
    }
  };
  readDir(process.env.EPOCHS_DIR, validateObservation);
  readDir(process.env.DISSOLUTIONS_DIR, validateDissolution);
  return out;
};

(async () => {
  const env = loadEnv();
  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC, unsafeOptions: { skipSynchronizationBeforeHeight: 1000000 } },
    apps: { poolLedger: { contractId: activeContractId(env) } },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);
  let failures = 0;
  const fail = (msg) => { failures++; console.error(`  INCONSISTENT: ${msg}`); };

  try {
    const observations = loadObservations();
    if (observations.length) console.log(`${observations.length} epoch observations loaded for cross-checking\n`);

    const pools = await fetchAll(client, "poolLedger.pool");
    console.log(`auditing ${pools.length} pools on contract ${activeContractId(env)}`);
    let totalAccruedDuffs = 0, totalEpochs = 0, crossChecked = 0, churnedEpochs = 0;

    for (const pool of pools) {
      const p = pool.toObject();
      const poolId = pool.getId();
      const proTxHex = Buffer.from(p.proTxHash).toString("hex");
      const feeBps = Number(p.operatorFeeBps || 0);
      console.log(`\npool ${poolId.toString()} (proTxHash ${proTxHex.slice(0, 16)}..., operator fee ${feeBps} bps)`);

      const shares = (await fetchAll(client, "poolLedger.share", {
        where: [["poolId", "==", poolId]],
      })).map((d) => ({ obj: d.toObject(), owner: d.getOwnerId().toString() }))
        .sort((a, b) => Number(a.obj.$createdAt) - Number(b.obj.$createdAt));
      const totalBps = shares.reduce((s, x) => s + Number(x.obj.shareBps), 0);
      console.log(`  ${shares.length} shares, ${totalBps} bps total ` +
        `(${shares.map((s) => `${Number(s.obj.shareBps)}`).join("/")})`);

      const accruals = (await fetchAll(client, "poolLedger.rewardAccrual", {
        where: [["poolId", "==", poolId]],
      })).map((d) => ({ obj: d.toObject(), owner: d.getOwnerId().toString() }));

      // a FORMING pool (partial or empty share table) is only a warning while nothing
      // has been distributed; a distribution on top of an incomplete table is a failure
      if (shares.length === 0 || totalBps !== 10000) {
        if (accruals.length > 0) {
          fail(`pool distributed with an incomplete share table (${totalBps} bps over ${shares.length} shares)`);
        } else {
          console.log(`  WARNING: incomplete share table (${totalBps} bps over ${shares.length} shares), ` +
            "nothing distributed; a forming pool or development debris");
        }
        continue;
      }
      for (const s of shares) {
        if (Number(s.obj.contributionDuffs) <= 0) fail(`share by ${s.owner} has non-positive contribution`);
      }
      // one group per DISTRIBUTION EVENT. v4 accruals carry a kind ("reward" |
      // "principal") inside the unique key, so a reward and a principal return at the
      // same fork height are two events (B12); kind-less accruals (v1/v3) group by
      // height alone, as before.
      const byEpoch = new Map();
      for (const a of accruals) {
        const h = Number(a.obj.epochHeight);
        const k = `${h}|${a.obj.kind || ""}`;
        if (!byEpoch.has(k)) byEpoch.set(k, { height: h, kind: a.obj.kind || null, list: [] });
        byEpoch.get(k).list.push(a);
      }

      const groups = [...byEpoch.values()].sort((a, b) => a.height - b.height
        || (a.kind || "").localeCompare(b.kind || ""));
      for (const { height, kind, list } of groups) {
        totalEpochs++;
        const sum = list.reduce((s, a) => s + Number(a.obj.amountDuffs), 0);
        totalAccruedDuffs += sum;

        // the rail's split rule, reconstructed from the recorded shares: floor per share
        // in creation order, dust to the last. The reconstruction is only valid for an
        // epoch distributed under the CURRENT membership; after a churn (a share handed
        // over via the matcher) the epoch's own share table is gone (deleted shares
        // leave no tombstone), so such epochs are validated by their observation-tied
        // sum only. The production fix is to record the bps in the accrual document
        // itself in a future contract version, making every epoch reconstructible.
        const funderByShareOwner = new Map();
        for (const a of list) {
          const amt = Number(a.obj.amountDuffs);
          const funderId = Identifier.from(Buffer.from(a.obj.funderId)).toString();
          if (funderByShareOwner.has(funderId)) fail(`epoch ${height}: duplicate accrual for funder ${funderId}`);
          funderByShareOwner.set(funderId, amt);
        }
        // v3 accruals carry the bps AT DISTRIBUTION TIME, so the split is reconstructed
        // from the accruals alone, in their own creation order, membership churn or not.
        // This is the property the v1 ledger cannot offer (see the churn fallback below).
        const withBps = list.filter((a) => a.obj.shareBps !== undefined && a.obj.shareBps !== null);
        const currentOwners = new Set(shares.map((s) => s.owner));
        const sameMembership = funderByShareOwner.size === currentOwners.size
          && [...funderByShareOwner.keys()].every((f) => currentOwners.has(f));
        let churnNote = "";
        let bpsReconstructed = false;
        if (withBps.length === list.length && list.length > 0) {
          // ORDER-INDEPENDENT reconstruction (review finding B6: document timestamps and
          // ids do not encode a creation sequence): every accrual must equal its own
          // floor(sum*bps/10000), except EXACTLY ONE which additionally absorbs the whole
          // rounding remainder. Value conservation and proportionality are pinned; the
          // dust holder's identity (at most participants-1 duffs) is deliberately not.
          const bpsTotal = list.reduce((s2, a) => s2 + Number(a.obj.shareBps), 0);
          if (bpsTotal !== 10000) {
            fail(`epoch ${height}: recorded accrual bps sum to ${bpsTotal}, expected 10000`);
          } else {
            const floors = list.map((a) => Number((BigInt(sum) * BigInt(Number(a.obj.shareBps))) / 10000n));
            const dust = sum - floors.reduce((s2, x) => s2 + x, 0);
            let dustHolders = 0; let ok = true;
            list.forEach((a, i) => {
              const got = Number(a.obj.amountDuffs);
              if (got === floors[i] + dust && dust > 0) { dustHolders++; }
              else if (got !== floors[i]) {
                ok = false;
                fail(`epoch ${height}: accrual with ${Number(a.obj.shareBps)} bps pays ${got} duffs, ` +
                  `its floor is ${floors[i]} (allowed remainder ${dust})`);
              }
            });
            if (ok && dust > 0 && dustHolders !== 1) {
              fail(`epoch ${height}: the ${dust}-duff remainder is held by ${dustHolders} accruals, expected exactly 1`);
            } else if (ok) {
              churnNote = " [reconstructed from recorded bps (v3), churn-proof]";
              bpsReconstructed = true;
            }
          }
        } else if (sameMembership) {
          const cuts = shares.map((s) => Number((BigInt(sum) * BigInt(Number(s.obj.shareBps))) / BigInt(totalBps)));
          cuts[cuts.length - 1] += sum - cuts.reduce((s, x) => s + x, 0);
          shares.forEach((s, i) => {
            const got = funderByShareOwner.get(s.owner);
            if (got !== cuts[i]) {
              fail(`epoch ${height}: ${s.owner} accrued ${got} duffs, split rule says ${cuts[i]}`);
            }
          });
        } else {
          churnNote = " [split UNVERIFIABLE from the v1 ledger: membership churned since; sum tied to observation only]";
          churnedEpochs++;
        }

        // tie the epoch back to the observed L1 inflow where an observation matches.
        // For a churned epoch this is the binding check; without an observation AND
        // without the current membership, the epoch's split is unverifiable from the
        // ledger alone, which is worth failing loudly.
        // a kind-carrying (v4) group must match an observation of the SAME kind, so the
        // reward and the principal return of one height each bind to their own inflow
        const match = observations.find(({ obs }) => obs.proTxHash === proTxHex && obs.height === height
          && (kind === null || (kind === "principal") === (obs.kind === "dissolution")));
        if (!bpsReconstructed && !sameMembership && !match) {
          // an operator can ACKNOWLEDGE a known-unverifiable epoch (for example a churned
          // wallet-funded test pool) via AUDIT_ACKNOWLEDGE="<poolId>@<height>,..."; it is
          // still reported, it just stops failing every future audit
          const acked = (process.env.AUDIT_ACKNOWLEDGE || "").split(",")
            .includes(`${poolId.toString()}@${height}`);
          if (acked) {
            console.log(`  ACKNOWLEDGED: epoch ${height} churned with no covering observation; ` +
              "split unverifiable from the v1 ledger (operator-accepted)");
          } else {
            fail(`epoch ${height}: membership churned since and no observation covers it; ` +
              "the split cannot be verified from the ledger alone " +
              `(acknowledge with AUDIT_ACKNOWLEDGE=${poolId.toString()}@${height} if accepted)`);
          }
        }
        let note = churnNote;
        if (match) {
          crossChecked++;
          const distributable = match.obs.amountDuffs - ASSET_LOCK_FEE_DUFFS;
          // principal returns carry no operator cut; the fee bps applies to rewards only
          const operatorCut = match.obs.kind === "dissolution" ? 0
            : Math.floor((distributable * feeBps) / 10000);
          const remainder = distributable - operatorCut;
          if (sum !== remainder) {
            fail(`epoch ${height}: accruals sum ${sum} duffs, the observed inflow ` +
              `${match.obs.amountDuffs} implies ${remainder} (${match.file})`);
          } else {
            note = ` == observed inflow ${DASHfmt(match.obs.amountDuffs)} minus fee${match.obs.kind === "dissolution" ? " (principal return, no operator cut)" : " and operator cut"} (${match.file})${churnNote}`;
          }
        }
        console.log(`  epoch ${height}${kind ? ` [${kind}]` : ""}: ${list.length} accruals, ${DASHfmt(sum)} DASH${note}`);
      }
      if (byEpoch.size === 0) console.log("  no accruals yet");
    }

    console.log(`\n=== LEDGER AUDIT ${failures === 0 ? "OK" : `FAILED (${failures} inconsistencies)`}: ` +
      `${pools.length} pools, ${totalEpochs} distributed epochs (${crossChecked} cross-checked against ` +
      `observations, ${churnedEpochs} churned with UNVERIFIABLE split), ` +
      `${DASHfmt(totalAccruedDuffs)} DASH accrued to funders ===`);
    if (failures > 0) process.exitCode = 1;
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
