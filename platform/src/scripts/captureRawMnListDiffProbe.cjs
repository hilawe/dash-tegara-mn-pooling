/**
 * Capture RAW masternode-list diff bytes from a running node, for verifyCoreWalk.
 *
 * WHY RAW AND NOT RPC. The audit format retains `coverage.listWalk[].protxDiffRaw`, typed as
 * hexBytes, so the walk's input is the WIRE form of the diff. Dash's `protx diff` RPC returns
 * JSON, which is a node's PARSE of that wire form, and a parse cannot validate a parser. DAPI
 * carries the wire bytes directly as `bytes masternode_list_diff`
 * (@dashevo/dapi-grpc/protos/core/v0/core.proto:204-206), so that is the source used here.
 *
 * The JSON capture from `protx diff` is still worth having and is pinned separately: it is the
 * INDEPENDENT ORACLE a parser gets checked against, the same role Python's canonicalization
 * plays for the canonical-bytes tests.
 *
 * This is a PROBE, not part of `npm test`: it needs a live node.
 *
 *   node src/scripts/captureRawMnListDiffProbe.cjs [host:port] > capture.json
 *
 * On the local dashmate devnet the gateway ports are the 24x3 / 25x3 / 26x3 series; 127.0.0.1:2443
 * is node 1. The stream is subscription-shaped, so it emits the current diff and then updates;
 * this probe takes the first message and exits.
 */
"use strict";

const path = require("path");
const grpc = require("@grpc/grpc-js");
const protoLoader = require("@grpc/proto-loader");

const PROTO = path.join(__dirname, "..", "..", "node_modules", "@dashevo", "dapi-grpc",
                        "protos", "core", "v0", "core.proto");
const TARGET = process.argv[2] || "127.0.0.1:2443";
const TIMEOUT_MS = 25000;

const def = protoLoader.loadSync(PROTO, {
  keepCase: true, longs: String, defaults: true, oneofs: true,
});
const pkg = grpc.loadPackageDefinition(def);
const Core = pkg.org.dash.platform.dapi.v0.Core;

const client = new Core(TARGET, grpc.credentials.createInsecure());
const call = client.subscribeToMasternodeList({});

let done = false;
const finish = (code, payload) => {
  if (done) return;
  done = true;
  if (payload) process.stdout.write(JSON.stringify(payload, null, 1) + "\n");
  try { call.cancel(); } catch (_) { /* the stream is going away anyway */ }
  process.exit(code);
};

const timer = setTimeout(() => {
  process.stderr.write(`no message within ${TIMEOUT_MS}ms from ${TARGET}\n`);
  finish(2);
}, TIMEOUT_MS);

call.on("data", (msg) => {
  const raw = msg.masternode_list_diff;
  if (!raw || !raw.length) {
    process.stderr.write("a message arrived with an empty diff payload; waiting for the next\n");
    return;
  }
  clearTimeout(timer);
  finish(0, {
    why: "RAW wire bytes of a masternode-list diff, the form the audit format retains as " +
         "coverage.listWalk[].protxDiffRaw. Captured for verifyCoreWalk's parser work.",
    source: `DAPI subscribeToMasternodeList at ${TARGET}`,
    capturedBy: "src/scripts/captureRawMnListDiffProbe.cjs",
    byteLength: raw.length,
    rawHex: Buffer.from(raw).toString("hex"),
  });
});

call.on("error", (e) => {
  clearTimeout(timer);
  process.stderr.write(`stream error from ${TARGET}: ${(e && e.message) || e}\n`);
  finish(3);
});

call.on("end", () => {
  clearTimeout(timer);
  process.stderr.write("the stream ended before any diff arrived\n");
  finish(4);
});
