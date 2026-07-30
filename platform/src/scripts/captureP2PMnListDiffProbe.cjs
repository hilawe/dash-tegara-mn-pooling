/**
 * Capture the P2P `mnlistdiff` payload from a Dash node, which is the ONLY form the audit
 * format accepts for coverage.listWalk[].protxDiffRaw.
 *
 * WHY THIS EXISTS. The pinned codec profile maps that field to `dash-p2p-mnlistdiff-v1`, "the
 * CSimplifiedMNListDiff P2P serialization at 8c9f166a3:src/evo/smldiff.h". Neither node API
 * emits it: `protx diff` returns JSON, and DAPI's subscribeToMasternodeList returns CBOR of the
 * same parsed object despite declaring a `bytes` field (a soundness review). So the bytes have to come from
 * the peer protocol, and no peer library is in the tree. This is a minimal READ-ONLY client:
 * handshake, one request, one response, then it disconnects. It writes nothing to the node.
 *
 * THE PROTOCOL VERSION IS THE WHOLE GAME HERE. That struct serializes DIFFERENTLY depending on
 * the negotiated version [8c9f166a3:src/version.h, src/evo/smldiff.h]:
 *   below 70225 (BLS_SCHEME_PROTO_VERSION)        no nVersion field at all
 *   70225 to 70228                                 nVersion AFTER cbTx
 *   70229 and above (MNLISTDIFF_VERSION_ORDER)     nVersion FIRST
 *   70230 and above (MNLISTDIFF_CHAINLOCKS_...)    plus quorumsCLSigs at the end
 * So "the CSimplifiedMNListDiff P2P serialization" does not by itself determine the bytes, and
 * this probe RECORDS the version it negotiated alongside the payload (a soundness review).
 *
 *   node src/scripts/captureP2PMnListDiffProbe.cjs <host:port> <baseBlockHash> <blockHash> [ver]
 *
 * Hashes are RPC display hex; they go on the wire in internal order, so the probe reverses them.
 * A probe, not part of `npm test`: it needs a live node.
 */
"use strict";

const crypto = require("crypto");
const net = require("net");

const [target, baseDisplay, tipDisplay, verArg] = process.argv.slice(2);
if (!target || !baseDisplay || !tipDisplay) {
  process.stderr.write("usage: <host:port> <baseBlockHashHex> <blockHashHex> [protocolVersion]\n");
  process.exit(64);
}
const [host, portStr] = target.split(":");
const PORT = Number(portStr);
const PROTOCOL_VERSION = Number(verArg || 70240);

// regtest, read from merged source [8c9f166a3:src/chainparams.cpp:837-840]. The local dashmate
// network reports chain "regtest", so this is its magic; mainnet/testnet/devnet differ.
const MAGIC = Buffer.from("fcc1b7dc", "hex");

const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const dsha256 = (b) => sha256(sha256(b));
const uint256 = (displayHex) => {
  if (!/^[0-9a-f]{64}$/.test(displayHex)) throw new Error(`not a 32-byte hex hash: ${displayHex}`);
  return Buffer.from(displayHex, "hex").reverse();
};

function frame(command, payload) {
  const head = Buffer.alloc(24);
  MAGIC.copy(head, 0);
  head.write(command, 4, 12, "ascii");
  head.writeUInt32LE(payload.length, 16);
  dsha256(payload).subarray(0, 4).copy(head, 20);
  return Buffer.concat([head, payload]);
}

function versionPayload() {
  const netAddr = () => {
    const a = Buffer.alloc(26);
    a.writeUInt32LE(0, 0);                       // services (low half)
    return a;                                    // zero address and port is accepted
  };
  const agent = Buffer.from("/tegara-audit-probe:0.1/", "ascii");
  const varstr = Buffer.concat([Buffer.from([agent.length]), agent]);
  const p = Buffer.alloc(4 + 8 + 8);
  p.writeInt32LE(PROTOCOL_VERSION, 0);
  p.writeUInt32LE(0, 4); p.writeUInt32LE(0, 8);  // services = 0 (we serve nothing)
  const secs = Math.floor(Number(process.env.TEGARA_PROBE_TIME || 1753670000));
  p.writeUInt32LE(secs, 12); p.writeUInt32LE(0, 16);
  const nonce = crypto.randomBytes(8);
  const tail = Buffer.alloc(4 + 1);
  tail.writeInt32LE(0, 0);                        // start height
  tail.writeUInt8(0, 4);                          // relay = false
  return Buffer.concat([p, netAddr(), netAddr(), nonce, varstr, tail]);
}

const socket = net.createConnection({ host, port: PORT });
socket.setTimeout(30000);

// The limits and rules a Dash peer applies to a message header before delivering it
// [8c9f166a3:src/net.cpp:731-740 and 796-807, src/net.h:85, src/serialize.h:38].
const MAX_PROTOCOL_MESSAGE_LENGTH = 3 * 1024 * 1024;
const MAX_SIZE = 0x02000000;
const COMMAND_RE = /^[a-z0-9]{1,12}$/;      // printable, no padding after the first NUL

let buf = Buffer.alloc(0);
let sentRequest = false;
let done = false;
let peerVersion = null;
const seen = [];

const finish = (code, payload) => {
  if (done) return;
  done = true;
  if (payload) process.stdout.write(JSON.stringify(payload, null, 1) + "\n");
  socket.destroy();
  process.exit(code);
};

socket.on("connect", () => {
  process.stderr.write(`connected to ${target}, offering protocol ${PROTOCOL_VERSION}\n`);
  socket.write(frame("version", versionPayload()));
});

socket.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  // drain complete messages, VALIDATING THE FRAME the way a peer does (round 6, MAJOR: this read
  // the advertised length and payload and checked nothing, so a malformed frame could be saved as
  // evidence, and this utility is the only route to the bytes the format requires)
  while (buf.length >= 24) {
    // the network magic comes first, so a wrong-network or desynchronised stream stops here
    if (!buf.subarray(0, 4).equals(MAGIC)) {
      process.stderr.write(`frame error: wrong network magic ${buf.subarray(0, 4).toString("hex")}\n`);
      return finish(5);
    }
    const len = buf.readUInt32LE(16);
    // size ceilings BEFORE buffering the payload, so a bogus length cannot make us allocate
    if (len > MAX_SIZE || len > MAX_PROTOCOL_MESSAGE_LENGTH) {
      process.stderr.write(`frame error: declared size ${len} exceeds the protocol limit\n`);
      return finish(5);
    }
    if (buf.length < 24 + len) break;
    const rawCommand = buf.subarray(4, 16);
    const command = rawCommand.toString("ascii").replace(/\0+$/, "");
    // the command must be printable and NUL-padded, never padded with other bytes
    const nul = rawCommand.indexOf(0);
    const padded = nul === -1 ? Buffer.alloc(0) : rawCommand.subarray(nul);
    if (!COMMAND_RE.test(command) || !padded.equals(Buffer.alloc(padded.length))) {
      process.stderr.write(`frame error: invalid command grammar ${rawCommand.toString("hex")}\n`);
      return finish(5);
    }
    const payload = buf.subarray(24, 24 + len);
    // the checksum is the first four bytes of the double SHA-256 of the payload
    const expected = dsha256(payload).subarray(0, 4);
    if (!buf.subarray(20, 24).equals(expected)) {
      process.stderr.write(`frame error: checksum mismatch on ${command}\n`);
      return finish(5);
    }
    buf = buf.subarray(24 + len);
    if (!seen.includes(command)) seen.push(command);

    if (command === "version") {
      // KEEP the peer's version. The wire layout is chosen by the COMMON version, so recording
      // only what we offered would label a correctly received frame with the wrong codec: at
      // 70240 offered against a 70229 peer, the peer serializes the 70229 layout (round 6, MAJOR).
      peerVersion = payload.readInt32LE(0);
      process.stderr.write(`peer offered protocol ${peerVersion}\n`);
      socket.write(frame("verack", Buffer.alloc(0)));
    } else if (command === "verack") {
      if (!sentRequest) {
        sentRequest = true;
        const req = Buffer.concat([uint256(baseDisplay), uint256(tipDisplay)]);
        process.stderr.write("handshake complete, requesting mnlistdiff\n");
        socket.write(frame("getmnlistd", req));
      }
    } else if (command === "ping") {
      socket.write(frame("pong", payload));
    } else if (command === "mnlistdiff") {
      finish(0, {
        why: "The P2P mnlistdiff payload, the serialization the pinned codec profile requires " +
             "for coverage.listWalk[].protxDiffRaw (dash-p2p-mnlistdiff-v1).",
        source: `Dash peer protocol at ${target}`,
        capturedBy: "src/scripts/captureP2PMnListDiffProbe.cjs",
        chain: "regtest",
        protocolVersionOffered: PROTOCOL_VERSION,
        protocolVersionPeerOffered: peerVersion,
        // the version that actually selects the layout, and therefore the one a parser must use
        protocolVersionCommon: Math.min(PROTOCOL_VERSION, peerVersion),
        layoutNote: "at 70229 and above nVersion is FIRST; at 70230 and above quorumsCLSigs is " +
                    "appended. The layout is version-dependent, so this field is part of the " +
                    "capture rather than an aside (a soundness review).",
        baseBlockHash: baseDisplay,
        blockHash: tipDisplay,
        byteLength: payload.length,
        payloadHex: payload.toString("hex"),
        messagesSeen: seen,
      });
    }
  }
});

socket.on("timeout", () => {
  process.stderr.write(`timeout; messages seen: ${seen.join(", ") || "none"}\n`);
  finish(2);
});
socket.on("error", (e) => {
  process.stderr.write(`socket error: ${(e && e.message) || e}\n`);
  finish(3);
});
socket.on("close", () => {
  if (!done) {
    process.stderr.write(`closed before a diff arrived; messages seen: ${seen.join(", ") || "none"}\n`);
    finish(4);
  }
});
