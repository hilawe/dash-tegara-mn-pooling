// Connectivity check: can the dash SDK reach a DAPI endpoint?
// Endpoint is env-configurable so the same script works against the local devnet (in a container on
// the host network, DAPI_HOST=192.168.5.2) or elsewhere. TLS validates via the dashmate CA supplied
// through GRPC_DEFAULT_SSL_ROOTS_FILE_PATH.
const Dash = require("dash");

const host = process.env.DAPI_HOST || "127.0.0.1";
const port = parseInt(process.env.DAPI_PORT || "2443", 10);

(async () => {
  const client = new Dash.Client({
    dapiAddresses: [{ host, port, protocol: "https" }],
  });
  try {
    const dapi = client.getDAPIClient();
    const height = await dapi.core.getBestBlockHeight();
    console.log(`OK: core best block height = ${height} (via ${host}:${port})`);
    await dapi.platform.getEpochsInfo(0, 1, { prove: false });
    console.log("OK: platform DAPI reachable");
  } catch (e) {
    console.error("CONNECT ERR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
