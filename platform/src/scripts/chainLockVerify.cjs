/**
 * chainLockVerify - ChainLock signature verification, the construction and the
 * signing-quorum selection rule, verified against a REAL ChainLock.
 *
 * WHY THIS IS A SEPARATE MODULE. The registry's `verifyCoreWalk` needs three things: this
 * signature check, the proof codecs that parse the retained quorum and witness blobs, and
 * the masternode-list codecs for the walk itself. Only the first is available today, so it
 * lives here as pure functions over explicit arguments rather than over an envelope. That
 * keeps it testable against the pinned real vector now, and reusable unchanged once the
 * codec bundle can hand it envelope-derived bytes.
 *
 * THE SCHEME IS DASH'S OWN, NOT IETF-BASIC. An earlier attempt searched 112 byte-order and
 * llmqType combinations with a general-purpose BLS library and verified nothing, which
 * looked like a construction problem and was not. The construction below was correct all
 * along. Dash keeps its legacy hash-to-curve inside the scheme it still calls
 * BasicSchemeMPL, so verification has to run under Dash's own library
 * (dashpay/bls-signatures, shipped as the WASM build @dashevo/bls). Under it the real
 * pinned devnet ChainLock verifies on the first attempt with no search.
 *
 * THE SIGNER IS NOT THE NEWEST QUORUM. Selection is by score, lowest wins, and over the
 * pinned quorum set the rule picks the OLDER of the two. That is exactly the quorum whose
 * public key verifies the signature, so the rule and the cryptography agree; the fixtures
 * require them to, since a change that breaks either one should fail loudly rather than
 * drift. The rule is mirrored at
 * @dashevo/dashcore-lib/lib/deterministicmnlist/SimplifiedMNList.js:658-672.
 *
 * Source of the construction, on the merged commit:
 *   requestId = dsha256(compactSize("clsig") || "clsig" || uint32LE(height))
 *     [8c9f166a3:src/chainlock/clsig.cpp:14-19]
 *   signHash  = dsha256(uint8 llmqType || quorumHash || requestId || msgHash)
 *     [8c9f166a3:src/bls/signhash.cpp:14-22]
 *   msgHash   = the ChainLocked block hash
 *     [8c9f166a3:src/chainlock/signing.cpp:163-164]
 * Every uint256 enters the preimage in INTERNAL byte order, so RPC display hex is reversed.
 *
 * ASYNC BOUNDARY. The library is WebAssembly, so loading it is asynchronous while the
 * verifiers in runtimeVerifiers are synchronous. `loadBls()` is the memoized async load and
 * `verifyChainLockSignature` is synchronous over an already-loaded instance. Wiring the
 * loaded instance through the verifier harness is the remaining integration step, and it is
 * not needed yet because verifyCoreWalk is still blocked on the codecs.
 */
"use strict";

const crypto = require("crypto");

function fail(msg) {
  throw new Error(`chainLockVerify: ${msg}`);
}

/**
 * llmqType values, from consensus [8c9f166a3:src/llmq/params.h], keyed by the label the
 * RPC reports. A label outside this table fails closed rather than defaulting.
 */
const LLMQ_TYPES = {
  llmq_50_60: 1,
  llmq_400_60: 2,
  llmq_400_85: 3,
  llmq_100_67: 4,
  llmq_60_75: 5,
  llmq_25_67: 6,
  llmq_test: 100,
  llmq_devnet: 101,
  llmq_test_v17: 102,
  llmq_test_dip0024: 103,
  llmq_test_instantsend: 104,
  llmq_devnet_dip0024: 105,
  llmq_test_platform: 106,
  llmq_devnet_platform: 107,
};

function llmqTypeOf(label) {
  if (typeof label === "number") {
    if (!Number.isInteger(label) || label < 0 || label > 255) fail(`llmqType ${label} is not a byte`);
    return label;
  }
  const v = LLMQ_TYPES[label];
  if (v === undefined) fail(`unknown llmqType label ${JSON.stringify(label)}`);
  return v;
}

const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const dsha256 = (b) => sha256(sha256(b));

/** the one-byte compactSize form, the only one reachable here ("clsig" is 5 bytes) */
function compactSize(n) {
  if (!Number.isInteger(n) || n < 0) fail("compactSize needs a non-negative integer length");
  if (n >= 253) fail("compactSize multi-byte form is not implemented (unreachable for this prefix)");
  return Buffer.from([n]);
}

/** 32 bytes in INTERNAL order from RPC display hex */
function uint256Internal(displayHex, what) {
  if (typeof displayHex !== "string" || !/^[0-9a-f]{64}$/.test(displayHex)) {
    fail(`${what} must be 64 lowercase hex characters`);
  }
  return Buffer.from(displayHex, "hex").reverse();
}

/** requestId = dsha256(compactSize("clsig") || "clsig" || uint32LE(height)) */
function deriveRequestId(height) {
  if (!Number.isInteger(height) || height < 0 || height > 0xffffffff) {
    fail(`height ${height} is outside the uint32 range the request id encodes`);
  }
  const prefix = Buffer.from("clsig", "utf8");
  const heightLE = Buffer.alloc(4);
  heightLE.writeUInt32LE(height, 0);
  return dsha256(Buffer.concat([compactSize(prefix.length), prefix, heightLE]));
}

/** signHash = dsha256(uint8 llmqType || quorumHash || requestId || msgHash) */
function deriveSignHash({ llmqType, quorumHash, requestId, msgHash }) {
  if (!Buffer.isBuffer(requestId) || requestId.length !== 32) fail("requestId must be 32 bytes");
  return dsha256(Buffer.concat([
    Buffer.from([llmqTypeOf(llmqType)]),
    uint256Internal(quorumHash, "quorumHash"),
    requestId,
    uint256Internal(msgHash, "msgHash"),
  ]));
}

/** the selection score: the sign-hash preimage WITHOUT the message hash */
function deriveQuorumScore({ llmqType, quorumHash, requestId }) {
  if (!Buffer.isBuffer(requestId) || requestId.length !== 32) fail("requestId must be 32 bytes");
  return dsha256(Buffer.concat([
    Buffer.from([llmqTypeOf(llmqType)]),
    uint256Internal(quorumHash, "quorumHash"),
    requestId,
  ]));
}

/**
 * The signing quorum for a request id: lowest score wins. `quorums` are the candidates of
 * the ChainLock's llmqType at the sign height; assembling that candidate set from retained
 * masternode-list evidence is the part still blocked on the list codecs, so it is the
 * caller's input here rather than something this module derives.
 */
function selectSignatoryQuorum(bls, quorums, requestId) {
  // THE LIBRARY IS REQUIRED, NOT OPTIONAL (a review, MAJOR). The point parse used to live in the
  // endpoint below, so this exported selector answered from lexical checks alone and accepted
  // `ff` repeated 48 times, a correctly sized value that is not a curve point. Selecting a
  // signing quorum from candidates whose keys have not been parsed is not a meaningful
  // operation for this module, so the selector now takes the library and does the parse itself.
  // A caller who cannot supply the library cannot get a selection.
  if (!bls || !bls.G1Element) fail("selectSignatoryQuorum needs a loaded BLS instance");
  if (!Array.isArray(quorums) || quorums.length === 0) fail("no candidate quorums to select from");
  // REJECT DUPLICATE IDENTITIES ACROSS THE WHOLE SET (confirmation round, MINOR). The first
  // version compared only the two LOWEST scores, so a duplicate anywhere else in the set
  // (for instance [lowest, other, other]) was accepted. Selection over a set that names the
  // same quorum twice is ambiguous wherever the repeat sits, so the check is over the set
  // rather than over the winner's neighbourhood.
  // VALIDATE EVERY CANDIDATE, not only the one that wins (repository-access review, MAJOR).
  // Reproduced: a set of the two real llmq_test quorums plus an extra llmq_devnet entry with an
  // all-zero public key returned verified:true, because the genuine signer happened to hold the
  // lowest score and the malformed member was never looked at. A candidate set that the code
  // will not fully examine is a candidate set that can hide anything.
  const identities = new Set();
  let setType = null;
  for (const q of quorums) {
    if (!q || typeof q !== "object") fail("each candidate quorum must be an object");
    const type = llmqTypeOf(q.type);
    // ONE llmqType per set: selection is defined per type at a sign height, so a mixed set is
    // not a well-formed candidate set and its lowest score is not a meaningful winner.
    if (setType === null) setType = type;
    else if (type !== setType) {
      fail(`candidate set mixes llmqType ${setType} and ${type}; selection is defined per type`);
    }
    if (typeof q.quorumHash !== "string" || !/^[0-9a-f]{64}$/.test(q.quorumHash)) {
      fail(`candidate quorum has a malformed quorumHash ${JSON.stringify(q.quorumHash)}`);
    }
    if (typeof q.quorumPublicKey !== "string" || !/^[0-9a-f]{96}$/.test(q.quorumPublicKey)) {
      fail(`candidate quorum ${q.quorumHash} has a malformed quorumPublicKey`);
    }
    if (/^0+$/.test(q.quorumPublicKey)) {
      fail(`candidate quorum ${q.quorumHash} carries an all-zero public key`);
    }
    const identity = `${type}|${q.quorumHash}`;
    if (identities.has(identity)) {
      fail(`candidate quorum ${q.quorumHash} appears twice in the set`);
    }
    identities.add(identity);
  }
  // every candidate's key must be a real point, not only the winner's
  for (const q of quorums) {
    let pk = null;
    try {
      pk = bls.G1Element.fromBytes(Uint8Array.from(Buffer.from(q.quorumPublicKey, "hex")));
    } catch (e) {
      fail(`candidate quorum ${q.quorumHash} carries a key that is not a valid BLS point`);
    } finally {
      if (pk) pk.delete();
    }
  }
  const scored = quorums.map((q) => ({
    quorum: q,
    score: deriveQuorumScore({ llmqType: q.type, quorumHash: q.quorumHash, requestId }),
  }));
  scored.sort((a, b) => Buffer.compare(a.score, b.score));
  // with duplicates already refused, a tie would mean a sha256d collision between two
  // distinct quorum hashes; check anyway rather than assume it away
  for (let i = 1; i < scored.length; i++) {
    if (Buffer.compare(scored[i].score, scored[i - 1].score) === 0) {
      fail("two distinct candidate quorums score identically");
    }
  }
  return { selected: scored[0].quorum, scored };
}

/** memoized async load of Dash's own BLS library (WebAssembly) */
let blsPromise = null;
function loadBls() {
  if (blsPromise === null) blsPromise = require("@dashevo/bls")();
  return blsPromise;
}

/**
 * Verify a ChainLock signature under a quorum public key, synchronously, over an
 * already-loaded library instance.
 *
 * Returns true or false. It does NOT throw on a bad signature (that is a verdict, not an
 * error); it throws only when an input is outside its domain.
 */
function verifyChainLockSignature(bls, { height, blockHash, llmqType, quorumHash, quorumPublicKey, signature }) {
  const { G1Element, G2Element, BasicSchemeMPL } = bls;
  if (typeof signature !== "string" || !/^[0-9a-f]{192}$/.test(signature)) {
    fail("signature must be 96 bytes of lowercase hex (a recovered BLS signature)");
  }
  if (typeof quorumPublicKey !== "string" || !/^[0-9a-f]{96}$/.test(quorumPublicKey)) {
    fail("quorumPublicKey must be 48 bytes of lowercase hex");
  }
  const signHash = deriveSignHash({
    llmqType, quorumHash, requestId: deriveRequestId(height), msgHash: blockHash,
  });

  let sig = null, pk = null;
  try {
    sig = G2Element.fromBytes(Uint8Array.from(Buffer.from(signature, "hex")));
    pk = G1Element.fromBytes(Uint8Array.from(Buffer.from(quorumPublicKey, "hex")));
    return BasicSchemeMPL.verify(pk, Uint8Array.from(signHash), sig) === true;
  } catch (e) {
    // the library is a WASM binding and reports malformed points with opaque messages, so
    // an unparseable point is a FAILED verification rather than a thrown error
    return false;
  } finally {
    // emscripten values are not garbage collected; release them explicitly
    if (sig) sig.delete();
    if (pk) pk.delete();
  }
}

/**
 * The whole endpoint check over a candidate quorum set: select by the score rule, then
 * verify under the selected quorum's public key. Returns the verdict plus the selection,
 * so a caller can report WHICH quorum was held responsible rather than only pass or fail.
 */
function verifyChainLockAgainstQuorumSet(bls, { height, blockHash, signature }, quorums) {
  const requestId = deriveRequestId(height);
  const { selected, scored } = selectSignatoryQuorum(bls, quorums, requestId);
  const verified = verifyChainLockSignature(bls, {
    height, blockHash, llmqType: selected.type, quorumHash: selected.quorumHash,
    quorumPublicKey: selected.quorumPublicKey, signature,
  });
  return { verified, selected, scored, requestId };
}

module.exports = {
  LLMQ_TYPES, llmqTypeOf, deriveRequestId, deriveSignHash, deriveQuorumScore,
  selectSignatoryQuorum, loadBls, verifyChainLockSignature, verifyChainLockAgainstQuorumSet,
};
