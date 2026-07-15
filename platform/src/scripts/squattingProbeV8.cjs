/**
 * One-time deployment probe for v8's completionReceipt owner-only creation
 * (creationRestrictionMode 1, spec M1/C-D): a NON-owner identity attempts to create a
 * schema-valid receipt; Platform itself must refuse it. This is the consensus-level
 * guarantee that closes receipt squatting (any identity occupying a pool's unique
 * byPool receipt slot before the operator).
 *
 * The probe targets a RANDOM poolId, so even if enforcement were off, the permanent
 * evidence (immutable, undeletable) would occupy a receipt for a pool that does not
 * exist, never a real pool's slot. Still gated like the cast-receipt probe was
 * (batch-4 review): run once at deployment with PROBE_CONFIRM=leave-probe-evidence.
 *
 * Run: LEDGER=v8 PROBE_CONFIRM=leave-probe-evidence node src/scripts/squattingProbeV8.cjs
 */
const crypto = require("crypto");
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, activeContractId, isV8 } = require("./envStore.cjs");

(async () => {
  if (!isV8()) { console.error("run with LEDGER=v8"); process.exit(2); }
  if (process.env.PROBE_CONFIRM !== "leave-probe-evidence") {
    console.error("the probe writes permanent evidence if enforcement is off; run it only as a " +
      "one-time deployment test with PROBE_CONFIRM=leave-probe-evidence");
    process.exit(2);
  }
  const env = loadEnv();
  const clientOpts = { network: process.env.NETWORK || "testnet", wallet: { mnemonic: env.MNEMONIC },
    apps: { poolLedger: { contractId: activeContractId(env) } } };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);
  try {
    installConsumedFilter(await client.getWalletAccount());
    const who = env.FUNDER_ID;
    if (!who || who === env.IDENTITY_ID) throw new Error("probe needs FUNDER_ID distinct from the operator");
    const funder = await client.platform.identities.get(who);
    console.log(`probe: non-operator ${who} attempts a completionReceipt create on contract ` +
      `${activeContractId(env)} (random poolId)`);
    // schema-valid on purpose, so a rejection can only mean the ownership restriction
    const rows = Buffer.from(JSON.stringify(["tegara-completion-allocation", 1, "x", "y", "1", []]), "utf8");
    const doc = await client.platform.documents.create("poolLedger.completionReceipt", funder, {
      poolId: crypto.randomBytes(32), proTxHash: crypto.randomBytes(32),
      slotIndex: 0, nodeType: "regular", operatorFeeBps: 0, formatVersion: 1,
      allocationRows: rows,
      allocationHash: crypto.createHash("sha256").update(rows).digest(),
      participantCount: 1, targetDuffs: 1,
      l1Verification: "demo-unverified", verificationMethodVersion: 1,
    });
    try {
      await client.platform.documents.broadcast({ create: [doc] }, funder);
      console.error("UNEXPECTED: Platform ACCEPTED a non-owner completionReceipt; " +
        "creationRestrictionMode is NOT enforced on this version. The client-side owner checks " +
        "remain the guard; the immutable probe document stays as evidence: " + doc.getId().toString());
      process.exitCode = 1;
    } catch (e) {
      // ONLY the ownership-restriction rejection counts as the probe passing (review
      // major): a network failure, balance error, nonce or signing failure would
      // otherwise print a false green. Anything else rethrows as a probe FAILURE.
      const msg = (e && e.message) || String(e);
      const isRestriction = /creation restriction mode|DocumentCreationNotAllowed|is not allowed because of the document type/i.test(msg)
        || (e && e.name === "DocumentCreationNotAllowedError");
      if (!isRestriction) {
        console.error("the broadcast failed for a reason OTHER than the ownership restriction, so " +
          "this run proves nothing about enforcement: " + msg);
        throw e;
      }
      console.log("REFUSED by Platform on the ownership restriction, as required: " + msg);
      console.log("owner-only creation is ENFORCED at consensus; receipt squatting is closed (M1/C-D)");
    }
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
