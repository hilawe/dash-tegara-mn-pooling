/**
 * Capture the P2P `mnlistdiff` payload from a Dash node, which is the ONLY form the audit
 * format accepts for coverage.listWalk[].protxDiffRaw.
 *
 * WHY THIS EXISTS. The pinned codec profile maps that field to `dash-p2p-mnlistdiff-v1`, "the
 * CSimplifiedMNListDiff P2P serialization at 8c9f166a3:src/evo/smldiff.h". Neither node API
 * emits it: `protx diff` returns JSON, and DAPI's subscribeToMasternodeList returns CBOR of the
 * same parsed object despite declaring a `bytes` field (a soundness-review finding). So the
 * bytes have to come from the peer protocol, and no peer library is in the tree. This is a
 * minimal READ-ONLY client: handshake, one request, one response, then it disconnects. It
 * writes nothing to the node.
 *
 * THE PROTOCOL VERSION IS THE WHOLE GAME HERE. That struct serializes DIFFERENTLY depending on
 * the negotiated version [8c9f166a3:src/version.h, src/evo/smldiff.h]:
 *   below 70225 (BLS_SCHEME_PROTO_VERSION)        no nVersion field at all
 *   70225 to 70228                                 nVersion AFTER cbTx
 *   70229 and above (MNLISTDIFF_VERSION_ORDER)     nVersion FIRST
 *   70230 and above (MNLISTDIFF_CHAINLOCKS_...)    plus quorumsCLSigs at the end
 * So "the CSimplifiedMNListDiff P2P serialization" does not by itself determine the bytes, and
 * this probe RECORDS the version it negotiated alongside the payload.
 *
 * THE HANDSHAKE IS AN EXPLICIT STATE MACHINE (round 8, a soundness-review finding). Frame validation alone was not
 * enough. The client used to dispatch on the command name with no notion of ORDER, so a peer
 * that sent a checksum-valid `mnlistdiff` before any `version` produced a completed capture
 * while `peerVersion` was still null, and `Math.min(70240, null)` recorded the common version
 * as 0. Dash Core refuses every non-version message until the version handshake has happened
 * [8c9f166a3:src/net_processing.cpp:3941], so a client that does not is not recording the
 * negotiation it claims to record. Three routes were open: a response before `version`, a
 * `version` body too short to contain the fields Core reads, and an unvalidated local offer.
 * All three are closed below, and the state machine is exported so the ordering rules are
 * driven by fixtures rather than only by a live node.
 *
 * WHAT THIS DOES NOT CHECK, stated rather than implied: the version payload's OPTIONAL tail
 * (addrMe, nonce, user agent, start height, relay). Core reads those behind `if (!vRecv.empty())`
 * guards and their encoding varies with what the peers have negotiated. The probe validates the
 * fixed prefix it actually reads a value out of, and uses none of the optional fields.
 *
 *   node src/scripts/captureP2PMnListDiffProbe.cjs <host:port> <baseBlockHash> <blockHash> [ver]
 *
 * Hashes are RPC display hex; they go on the wire in internal order, so the probe reverses them.
 * A probe, not part of the live test chain: the CAPTURE needs a node. Its handshake rules do not,
 * and captureP2PProbeTest.cjs drives them offline.
 */
"use strict";

const crypto = require("crypto");
const net = require("net");

// regtest, read from merged source [8c9f166a3:src/chainparams.cpp:837-840]. The local dashmate
// network reports chain "regtest", so this is its magic; mainnet/testnet/devnet differ.
const MAGIC = Buffer.from("fcc1b7dc", "hex");

// The limits and rules a Dash peer applies to a message header before delivering it
// [8c9f166a3:src/net.cpp:731-740 and 796-807, src/net.h:85, src/serialize.h:38].
const MAX_PROTOCOL_MESSAGE_LENGTH = 3 * 1024 * 1024;
const MAX_SIZE = 0x02000000;
const COMMAND_RE = /^[a-z0-9]{1,12}$/;      // printable, no padding after the first NUL

// The version floor a Dash peer enforces: below this it disconnects rather than talk
// [8c9f166a3:src/version.h:20, and the check at src/net_processing.cpp:3735].
const MIN_PEER_PROTO_VERSION = 70221;
// The fixed prefix Core reads from a version payload before ANY optional field:
// nVersion(4) + nServices(8) + nTime(8) [8c9f166a3:src/net_processing.cpp:3715].
const VERSION_FIXED_PREFIX = 20;

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

function versionPayload(protocolVersion) {
  const netAddr = () => {
    const a = Buffer.alloc(26);
    a.writeUInt32LE(0, 0);                       // services (low half)
    return a;                                    // zero address and port is accepted
  };
  const agent = Buffer.from("/tegara-audit-probe:0.1/", "ascii");
  const varstr = Buffer.concat([Buffer.from([agent.length]), agent]);
  const p = Buffer.alloc(4 + 8 + 8);
  p.writeInt32LE(protocolVersion, 0);
  p.writeUInt32LE(0, 4); p.writeUInt32LE(0, 8);  // services = 0 (we serve nothing)
  const secs = Math.floor(Number(process.env.TEGARA_PROBE_TIME || 1753670000));
  p.writeUInt32LE(secs, 12); p.writeUInt32LE(0, 16);
  const nonce = crypto.randomBytes(8);
  const tail = Buffer.alloc(4 + 1);
  tail.writeInt32LE(0, 0);                        // start height
  tail.writeUInt8(0, 4);                          // relay = false
  return Buffer.concat([p, netAddr(), netAddr(), nonce, varstr, tail]);
}

/**
 * VALIDATE OUR OWN OFFER (round 8, a soundness-review finding). This was `Number(verArg || 70240)` with nothing after
 * it, so a nonnumeric argument became NaN, `Math.min` propagated the NaN, and `JSON.stringify`
 * wrote it as `null` into BOTH the offered and the common-version fields of a capture that
 * otherwise looked complete. The protocol version selects the wire layout, so a capture whose
 * version is null or nonsense is evidence a parser cannot use.
 */
function validateOfferedVersion(raw) {
  if (raw === undefined || raw === null || raw === "") return 70240;
  const v = Number(raw);
  if (!Number.isInteger(v)) {
    throw new Error(`the offered protocol version ${JSON.stringify(raw)} is not an integer`);
  }
  if (v < MIN_PEER_PROTO_VERSION) {
    throw new Error(`the offered protocol version ${v} is below the minimum a Dash peer ` +
                    `accepts (${MIN_PEER_PROTO_VERSION})`);
  }
  return v;
}

/**
 * The peer's stated version, validated the way Core validates it before using it.
 * Returns { version } or { error }.
 */
function parsePeerVersion(payload) {
  if (!Buffer.isBuffer(payload) || payload.length < VERSION_FIXED_PREFIX) {
    return { error: `a version payload of ${payload ? payload.length : 0} byte(s) is shorter ` +
                    `than the ${VERSION_FIXED_PREFIX}-byte fixed prefix Core reads` };
  }
  const version = payload.readInt32LE(0);
  if (version < MIN_PEER_PROTO_VERSION) {
    return { error: `the peer states protocol ${version}, below the minimum ` +
                    `${MIN_PEER_PROTO_VERSION} at which a Dash peer stays connected` };
  }
  return { version };
}

/**
 * The handshake, as an explicit state machine over already-frame-validated messages.
 *
 * States, in the only order the protocol allows:
 *   AWAIT_VERSION  nothing but `version` is accepted
 *   AWAIT_VERACK   the peer's version is known; `verack` completes the handshake
 *   REQUESTED      `getmnlistd` has been sent; `mnlistdiff` may now be accepted
 *   CLOSED         a capture was emitted or the session was refused
 *
 * `send` and `capture` are injected so the rules can be driven without a socket. `refuse` is
 * called with a reason and ENDS the session; it never produces a capture, which is the point:
 * an ordering violation must not be able to yield evidence.
 */
function createHandshake({ protocolVersion, baseDisplay, tipDisplay, target,
                           send, capture, refuse, note }) {
  let state = "AWAIT_VERSION";
  let peerVersion = null;
  const seen = [];
  const say = note || (() => {});

  const stop = (reason) => { state = "CLOSED"; refuse(reason); };

  return {
    get state() { return state; },
    get peerVersion() { return peerVersion; },
    handle(command, payload) {
      if (state === "CLOSED") return;
      if (!seen.includes(command)) seen.push(command);

      // THE ORDERING RULE, ahead of every command branch. Core ignores any non-version message
      // while the peer's version is unknown [8c9f166a3:src/net_processing.cpp:3941]. Ignoring is
      // right for a long-lived node with other peers; for a one-shot capture the same condition
      // means the evidence cannot be trusted, so this refuses instead of continuing.
      if (state === "AWAIT_VERSION" && command !== "version") {
        return stop(`received ${command} before the peer's version, so no protocol version was ` +
                    "negotiated and any payload it carried is unlabelled");
      }

      if (command === "version") {
        // one version per session; a second one would re-label a negotiation already made
        if (state !== "AWAIT_VERSION") {
          return stop("received a second version message after the version was already set");
        }
        const parsed = parsePeerVersion(payload);
        if (parsed.error) return stop(`version message rejected: ${parsed.error}`);
        peerVersion = parsed.version;
        state = "AWAIT_VERACK";
        say(`peer offered protocol ${peerVersion}`);
        send("verack", Buffer.alloc(0));
        return;
      }

      if (command === "verack") {
        if (state !== "AWAIT_VERACK") return;         // a redundant verack is ignored, as in Core
        state = "REQUESTED";
        say("handshake complete, requesting mnlistdiff");
        send("getmnlistd", Buffer.concat([uint256(baseDisplay), uint256(tipDisplay)]));
        return;
      }

      if (command === "ping") { send("pong", payload); return; }

      if (command === "mnlistdiff") {
        // only after WE asked for it. Without this a peer could volunteer a diff mid-handshake
        // and have it recorded as the answer to a request never made.
        if (state !== "REQUESTED") {
          return stop("received mnlistdiff before the handshake completed and the request was sent");
        }
        // both versions are validated integers by construction here: ours at startup, the
        // peer's in parsePeerVersion, so the common version cannot be NaN, null, or 0
        const common = Math.min(protocolVersion, peerVersion);
        state = "CLOSED";
        capture({
          why: "The P2P mnlistdiff payload, the serialization the pinned codec profile requires " +
               "for coverage.listWalk[].protxDiffRaw (dash-p2p-mnlistdiff-v1).",
          source: `Dash peer protocol at ${target}`,
          capturedBy: "src/scripts/captureP2PMnListDiffProbe.cjs",
          chain: "regtest",
          protocolVersionOffered: protocolVersion,
          protocolVersionPeerOffered: peerVersion,
          // the version that actually selects the layout, and therefore the one a parser must use
          protocolVersionCommon: common,
          layoutNote: "at 70229 and above nVersion is FIRST; at 70230 and above quorumsCLSigs is " +
                      "appended. The layout is version-dependent, so this field is part of the " +
                      "capture rather than an aside.",
          baseBlockHash: baseDisplay,
          blockHash: tipDisplay,
          byteLength: payload.length,
          payloadHex: payload.toString("hex"),
          messagesSeen: seen.slice(),
        });
      }
    },
  };
}

/**
 * Pull complete, frame-valid messages out of an accumulating buffer.
 * Returns the unconsumed remainder, or calls `onError` and returns null.
 */
function drainFrames(buf, onMessage, onError) {
  while (buf.length >= 24) {
    // the network magic comes first, so a wrong-network or desynchronised stream stops here
    if (!buf.subarray(0, 4).equals(MAGIC)) {
      onError(`wrong network magic ${buf.subarray(0, 4).toString("hex")}`);
      return null;
    }
    const len = buf.readUInt32LE(16);
    // size ceilings BEFORE buffering the payload, so a bogus length cannot make us allocate
    if (len > MAX_SIZE || len > MAX_PROTOCOL_MESSAGE_LENGTH) {
      onError(`declared size ${len} exceeds the protocol limit`);
      return null;
    }
    if (buf.length < 24 + len) break;
    const rawCommand = buf.subarray(4, 16);
    const command = rawCommand.toString("ascii").replace(/\0+$/, "");
    // the command must be printable and NUL-padded, never padded with other bytes
    const nul = rawCommand.indexOf(0);
    const padded = nul === -1 ? Buffer.alloc(0) : rawCommand.subarray(nul);
    if (!COMMAND_RE.test(command) || !padded.equals(Buffer.alloc(padded.length))) {
      onError(`invalid command grammar ${rawCommand.toString("hex")}`);
      return null;
    }
    const payload = buf.subarray(24, 24 + len);
    // the checksum is the first four bytes of the double SHA-256 of the payload
    const expected = dsha256(payload).subarray(0, 4);
    if (!buf.subarray(20, 24).equals(expected)) {
      onError(`checksum mismatch on ${command}`);
      return null;
    }
    buf = buf.subarray(24 + len);
    onMessage(command, payload);
  }
  return buf;
}

function main() {
  const [target, baseDisplay, tipDisplay, verArg] = process.argv.slice(2);
  if (!target || !baseDisplay || !tipDisplay) {
    process.stderr.write("usage: <host:port> <baseBlockHashHex> <blockHashHex> [protocolVersion]\n");
    process.exit(64);
  }
  let PROTOCOL_VERSION;
  try {
    PROTOCOL_VERSION = validateOfferedVersion(verArg);
  } catch (e) {
    process.stderr.write(`${(e && e.message) || e}\n`);
    process.exit(64);
  }
  const [host, portStr] = target.split(":");
  const PORT = Number(portStr);

  const socket = net.createConnection({ host, port: PORT });
  socket.setTimeout(30000);

  let buf = Buffer.alloc(0);
  let done = false;
  const finish = (code, payload) => {
    if (done) return;
    done = true;
    if (payload) process.stdout.write(JSON.stringify(payload, null, 1) + "\n");
    socket.destroy();
    process.exit(code);
  };

  const session = createHandshake({
    protocolVersion: PROTOCOL_VERSION, baseDisplay, tipDisplay, target,
    send: (command, p) => socket.write(frame(command, p)),
    capture: (record) => finish(0, record),
    refuse: (reason) => { process.stderr.write(`handshake error: ${reason}\n`); finish(6); },
    note: (m) => process.stderr.write(`${m}\n`),
  });

  socket.on("connect", () => {
    process.stderr.write(`connected to ${target}, offering protocol ${PROTOCOL_VERSION}\n`);
    socket.write(frame("version", versionPayload(PROTOCOL_VERSION)));
  });

  socket.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    const rest = drainFrames(buf, (c, p) => session.handle(c, p), (msg) => {
      process.stderr.write(`frame error: ${msg}\n`);
      finish(5);
    });
    if (rest === null) return;
    buf = rest;
  });

  socket.on("timeout", () => {
    process.stderr.write("timeout\n");
    finish(2);
  });
  socket.on("error", (e) => {
    process.stderr.write(`socket error: ${(e && e.message) || e}\n`);
    finish(3);
  });
  socket.on("close", () => {
    if (!done) {
      process.stderr.write("closed before a diff arrived\n");
      finish(4);
    }
  });
}

if (require.main === module) main();

module.exports = {
  createHandshake, drainFrames, frame, versionPayload,
  validateOfferedVersion, parsePeerVersion,
  MIN_PEER_PROTO_VERSION, VERSION_FIXED_PREFIX, MAGIC,
};
