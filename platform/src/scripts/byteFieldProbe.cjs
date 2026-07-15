/**
 * One-off diagnostic for the dash-rawkey-signer byteArray finding (2026-07-14, for the
 * library maintainer). Constructs+signs a votePreference create through the INSTALLED
 * published library, with the byte fields as Buffer, bare Uint8Array, and plain number
 * array, and reports which pass. No broadcast. Prints the resolved wasm-dpp version and
 * the contract bytes so the maintainer has exactly what they asked for.
 *
 * Run in the tegara-sdk container against the devnet with the library installed.
 */
(async () => {
  const Dash = require("dash");
  const { Identifier } = require("@dashevo/wasm-dpp");
  const { createRawKeySigner, snapshotFromDashIdentity } = await import("dash-rawkey-signer");

  const id = process.env.RECOVER_ID;
  const wif = process.env.RECOVER_AUTH_WIF;
  const contractIdStr = process.env.RECOVER_CONTRACT_ID;
  const poolIdStr = process.env.PROBE_POOL_ID;

  const clientOpts = { network: "testnet", wallet: { privateKey: wif },
    apps: { poolLedger: { contractId: contractIdStr } } };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https" }];
  const client = new Dash.Client(clientOpts);
  try {
    const platform = client.platform;
    await platform.initialize();
    console.log("resolved wasm-dpp version:", require("@dashevo/wasm-dpp/package.json").version);
    console.log("platform protocolVersion:", platform.protocolVersion);

    const identity = await platform.identities.get(id);
    const snapshot = snapshotFromDashIdentity(identity, {
      network: "local", protocolVersion: platform.protocolVersion });
    const contract = await platform.contracts.get(Identifier.from(contractIdStr));
    const contractBytes = contract.toBuffer();
    console.log("contract bytes length:", contractBytes.length);
    console.log("contract bytes (hex, first 120):", Buffer.from(contractBytes).toString("hex").slice(0, 120));
    console.log("contract bytes (hex, FULL):", Buffer.from(contractBytes).toString("hex"));

    const signer = createRawKeySigner({ network: "local" });
    const poolIdBuf = Identifier.from(poolIdStr).toBuffer();
    const proposal = Buffer.from(
      "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11a", "hex");

    const reps = {
      "Buffer":       { poolId: poolIdBuf, proposalHash: proposal },
      "Uint8Array":   { poolId: Uint8Array.from(poolIdBuf), proposalHash: Uint8Array.from(proposal) },
      "number array": { poolId: [...poolIdBuf], proposalHash: [...proposal] },
    };
    for (const [label, bytes] of Object.entries(reps)) {
      try {
        await signer.signDocumentBatch({
          identity: snapshot,
          privateKey: { wif },
          contract: Uint8Array.from(contractBytes),
          actions: [{ action: "create", documentType: "votePreference",
            data: { ...bytes, choice: "yes" } }],
          nonceContext: { contractNonce: 999n }, // offline construction, arbitrary nonce
        });
        console.log(`  ${label}: PASS (constructed + signed)`);
      } catch (e) {
        console.log(`  ${label}: FAIL -> ${((e && e.message) || String(e)).slice(0, 140)}`);
      }
    }
    console.log("PROBE_DONE");
  } catch (e) {
    console.error("PROBE ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
