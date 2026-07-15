/**
 * Offline validation of the pool-ledger data contract using the Platform protocol (wasm-dpp),
 * via the SDK's own dpp instance. No network needed. Proves the contract definition is
 * structurally valid (document types, property positions, indices, types) and would be accepted.
 */
const path = require("path");
const { pathToFileURL } = require("url");
const Dash = require("dash");

(async () => {
  const { poolLedgerContract } = await import(
    pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href
  );

  const client = new Dash.Client({ network: "testnet" }); // no network call until a request is made
  try {
    await client.platform.initialize(); // loads wasm-dpp, offline
    const dpp = client.platform.dpp;
    const ownerId = Buffer.alloc(32, 7); // dummy 32-byte identity id, offline only

    const dc = dpp.dataContract.create(ownerId, 1n, poolLedgerContract);
    console.log("OK: contract is structurally valid (wasm-dpp accepted it)");
    console.log("  deterministic contract id (for this dummy owner):", dc.getId().toString());
    console.log("  document types:", Object.keys(poolLedgerContract).join(", "));
  } catch (e) {
    console.error("VALIDATION ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
