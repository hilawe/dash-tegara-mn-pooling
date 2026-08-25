#!/usr/bin/env python3
# check_vectors.py - build and verify the v1 audit-envelope test vectors. The companion
# version and note revision are stated ONCE, in the registry's registryVersion and the
# schema's title/description (the packet builder's drift-guard enforces those); this
# header deliberately carries no version claim so it cannot go stale (MIN-9, revision 18).
#
# Layers exercised:
#   1. SCHEMA: auditEnvelope.v1.schema.json (closed objects, tagged unions, grammars).
#   2. SEMANTIC: the named verifiers of the design note, re-deriving every decision from
#      evidence: verifyRewardDecision (the precedence table as an executable matrix,
#      evidence-bound), verifyOwnership (position-indexed binding, continuity, closing
#      prefix), verifyDecoderSelection, verifyLifecycle (journal RECONSTRUCTED from the
#      list-walk ledger and compared equal, plus the journal invariants),
#      verifyConservation (largest-remainder REPRODUCED from the signed shares),
#      verifyClaimProfile (mutually exclusive aggregates, result-completeness gating),
#      plus the coverage-interval equation, the canonical checkpoint-v2 DECODER with
#      byte-matching, epoch gaplessness, ledger contiguity, anchor non-regression,
#      committed-hash consistency, total array orders, JSON Pointer evidence refs, NFC,
#      and the no-float rule.
#
# Usage:
#   python3 check_vectors.py --write   # (re)build vectors/positive_minimal.json + MANIFEST.json
#   python3 check_vectors.py           # verify: positive passes both layers, every negative fails
#
# The positive vector embeds the REAL committed purchase transaction from the devnet
# block store (Tenderdash height 470, txIndex 0, 189 bytes), and its checkpoint payload
# is BUILT BY the canonical v2 layout so the decoder byte-match is exercised for real.

import copy, hashlib, json, os, struct, sys, unicodedata
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "auditEnvelope.v1.schema.json")
VECTOR_DIR = os.path.join(HERE, "vectors")
POSITIVE_PATH = os.path.join(VECTOR_DIR, "positive_minimal.json")
MANIFEST_PATH = os.path.join(VECTOR_DIR, "MANIFEST.json")
# a soundness-review finding (revision 17): the execution-profile document is content-addressed at the RELEASE
# layer. Its sha256 is pinned in the vector manifest and re-checked on every run, so the
# profile's meaning cannot drift without a new profile name or an envelopeVersion bump.
PROFILE_PATH = os.path.join(HERE, "execution-profiles", "tegara-decoder-v1.json")
# a soundness-review finding (revision 23): the proof-codec profile is content-addressed the same way.
CODEC_PROFILE_PATH = os.path.join(HERE, "proof-codecs", "tegara-proof-codecs-v1.json")

REAL_TX_HEX = (
    "0201ca042c4df8fed57975c15aa58cd687fde21b88867e46f870321689368f41b21f0100"
    "0500017b947da55aa96b204432ea21f30583e73f23df7d3968d0c8219fc468e620e9b501"
    "09736c6f74536861726582473ca11a6e286f53188422a5f15a623d73d3f8d366c47c043b"
    "22b2d859fccf0003fc0ee6b28001014120a7f3d423d8b86c570f6c1cf102bcfa8ce63ca1"
    "ebf5ea1bf0979264e914b9b64e0932bcc4d5daef032b5bdf413b21cd18a0ee851fa82bd2"
    "fa840f3fe4c5f30875"
)

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    for c in b:
        if c == 0:
            out = "1" + out
        else:
            break
    return out

def sha256_hex(hex_str):
    return hashlib.sha256(bytes.fromhex(hex_str)).hexdigest()

def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

# ---- fixed identities (raw bytes -> canonical envelope forms) ------------------------------

POOL_DISPLAY = "7838ca79f9866978160af819b677002c7e1151b4665bd15c4c2f11a964d2cdb3"
POOL_RAW = bytes.fromhex(POOL_DISPLAY)[::-1]         # payload stores raw consensus bytes
CONTRACT_RAW = bytes([0x21]) * 32
OPERATOR_RAW = bytes([0x37]) * 32
POOLID_RAW = bytes([0x59]) * 32
CONTRACT = b58encode(CONTRACT_RAW)
OPERATOR = b58encode(OPERATOR_RAW)
POOLID = b58encode(POOLID_RAW)
BUYER = "Ebb3eVTNx46Kq2JxWWZfXg6cjJHxsMY4KZzJhFssM7Yq"
H32A = "aa" * 32
H32B = "bb" * 32
H32C = "cc" * 32
H32D = "dd" * 32
H32E = "ee" * 32
# a soundness-review finding (revision 17): the decoder id is DERIVED from the bundle digest (its first 16
# hex), so a rename without a content change cannot serialize.
DECODER_ID = "decoder-sha256-" + ("dd" * 32)[:16]
EVBYTES = "de" * 40
SIGNER_PUB = bytes([0x42]) * 32

# Core chain identity (a soundness-review finding). Well-known genesis hashes in RPC display
# form (merged commit 8c9f166a3, src/chainparams.cpp: MAIN line 242, TESTNET line 438,
# DEVNET line 614, REGTEST line 854). mainnet/testnet bind two ways (name <-> genesis).
# regtest and devnet SHARE the height-ZERO base genesis (000008ca...), so regtest binds
# ONE WAY (the label requires the base; no reverse base -> name entry exists), and a
# devnet is identified by its deployment-specific height-ONE devnet genesis block
# (Dash commits the devnet name into the height-one coinbase and mines that block over
# the shared base), carried as network.coreDevnetGenesisBlockHash, required for devnet
# and forbidden elsewhere (schema).
WELL_KNOWN_GENESIS = {
    "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6": "mainnet",
    "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c": "testnet",
}
SHARED_BASE_GENESIS = "000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e"

# The vector is a devnet envelope: the real shared height-zero base plus a placeholder
# height-one devnet genesis (authenticating the height-one block -- hash, prevBlock,
# PoW, the nonempty devnet-name coinbase commitment -- is a RUNTIME verifier duty; the
# suite checks the field conditions and the derived identity only).
GENESIS = bytes.fromhex(SHARED_BASE_GENESIS)
DEVNET_GENESIS_H1 = bytes([0x22]) * 32

# One fixed byte per closed network name, an input to the derived chain identity.
CORE_NETWORK_CODE = {"mainnet": 0, "testnet": 1, "devnet": 2, "regtest": 3}

def core_chain_identity_hash(core_network, genesis_bytes, devnet_h1_bytes):
    # The derived (never serialized) Core chain identity (a soundness-review finding): it feeds
    # domain separation wherever the bare height-zero genesis previously did, so two
    # devnets sharing the base genesis derive DIFFERENT identities and a checkpoint
    # signed for one cannot be copied to the other. Non-devnet networks contribute 32
    # zero bytes in the final position.
    return hashlib.sha256(
        b"TegaraCoreChainIdentity/v1" +
        bytes([CORE_NETWORK_CODE[core_network]]) +
        genesis_bytes +
        (devnet_h1_bytes if devnet_h1_bytes is not None else bytes(32))).digest()

# The vector deployment's identity, used by every payload build/decode below.
CHAIN_IDENTITY = core_chain_identity_hash("devnet", GENESIS, DEVNET_GENESIS_H1)

# ---- checkpoint v2 canonical layout (the SIGNED BOOK CARRIER, design note piece 2) ---------

V2_LABEL = b"tegara-fixedslot-checkpoint-v2"

def v2_domain_tag(chain_identity, signer_pub):
    # Revision 17 (a soundness-review finding): the tag folds in the DERIVED chain identity, not the bare
    # height-zero genesis, so two devnets sharing the base genesis produce different
    # tags and a signed checkpoint cannot be copied between them.
    return hashlib.sha256(V2_LABEL + chain_identity + signer_pub).digest()

def core_block_hash(h):
    # a soundness-review finding (revision 20): ONE block-hash convention shared by the list-walk and Core
    # ledgers (they describe one chain, and the join check requires agreement).
    return ("%02x" % (h % 251)) * 32

def build_v2_payload(epoch_id, effective, end_exclusive, books, bindings,
                     chain_identity, signer_pub):
    out = bytearray()
    out += struct.pack("<I", 2)
    out += v2_domain_tag(chain_identity, signer_pub)
    out += struct.pack("<QQQ", epoch_id, effective, end_exclusive)
    out += struct.pack("<H", len(bindings))
    out += struct.pack("<H", len(books))
    for bk in sorted(books, key=lambda x: (x["contractIdRaw"], x["poolIdRaw"])):
        out += bk["contractIdRaw"] + bk["poolIdRaw"] + bk["operatorIdRaw"] + \
               struct.pack("<H", bk["slotCount"])
        for num, den in bk["shares"]:
            out += struct.pack("<QQ", num, den)
    for bd in sorted(bindings, key=lambda x: (x["proTxHashRaw"], x["slotIndex"])):
        out += bd["proTxHashRaw"] + bytes([bd["slotIndex"]]) + bd["contractIdRaw"] + \
               bd["poolIdRaw"] + struct.pack("<Q", bd["activationCoreHeight"])
    return bytes(out)

MAX_BINDINGS = 512
MAX_BOOKS = 4096
MAX_PAYLOAD_BYTES = 1 << 20        # 1 MiB ceiling (a signed but oversized table is rejected)
JS_SAFE = (1 << 53) - 1

def decode_v2_payload(payload_hex, chain_identity, signer_pub):
    try:
        return _decode_v2(payload_hex, chain_identity, signer_pub)
    except SemanticError:
        raise
    except Exception as e:
        raise SemanticError("malformed checkpoint payload: %s" % type(e).__name__)

def _decode_v2(payload_hex, chain_identity, signer_pub):
    b = bytes.fromhex(payload_hex)
    if len(b) > MAX_PAYLOAD_BYTES:
        raise SemanticError("checkpoint payload exceeds MAX_PAYLOAD_BYTES")
    o = 0
    version = struct.unpack_from("<I", b, o)[0]; o += 4
    if version != 2:
        raise SemanticError("checkpoint payload version is not 2")
    if b[o:o+32] != v2_domain_tag(chain_identity, signer_pub):
        raise SemanticError("checkpoint payload domain tag mismatch")
    o += 32
    epoch_id, effective, end_exclusive = struct.unpack_from("<QQQ", b, o); o += 24
    if effective >= end_exclusive:
        raise SemanticError("epoch window inverted (effective >= endExclusive)")
    if max(epoch_id, effective, end_exclusive) > JS_SAFE:
        raise SemanticError("signed epoch/height exceeds the JSON-safe 2^53-1 envelope cap")
    n_bind = struct.unpack_from("<H", b, o)[0]; o += 2
    if n_bind > MAX_BINDINGS:
        raise SemanticError("binding count beyond the governing 512 limit")
    n_book = struct.unpack_from("<H", b, o)[0]; o += 2
    if n_book > MAX_BOOKS:
        raise SemanticError("book count beyond MAX_BOOKS")
    books = []
    prev_book_key = None
    for _ in range(n_book):
        cid = b[o:o+32]; o += 32
        pid = b[o:o+32]; o += 32
        if prev_book_key is not None and (cid, pid) <= prev_book_key:
            raise SemanticError("payload books not strictly ascending by (contractId, poolId)")
        prev_book_key = (cid, pid)
        oid = b[o:o+32]; o += 32
        sc = struct.unpack_from("<H", b, o)[0]; o += 2
        if sc < 1 or sc > 512:
            raise SemanticError("book slotCount outside 1..512")
        shares = []
        for _ in range(sc):
            num, den = struct.unpack_from("<QQ", b, o); o += 16
            if max(num, den) > JS_SAFE:
                raise SemanticError("signed share numerator/denominator exceeds JSON-safe cap")
            shares.append({"numerator": str(num), "denominator": str(den)})
        books.append({"contractId": b58encode(cid), "poolId": b58encode(pid),
                      "operatorId": b58encode(oid), "slotCount": sc, "shares": shares})
    bindings = []
    prev_bind_key = None
    for _ in range(n_bind):
        ptx = b[o:o+32]; o += 32
        si = b[o]; o += 1
        if prev_bind_key is not None and (ptx, si) <= prev_bind_key:
            raise SemanticError("payload bindings not strictly ascending by (proTxHash, slotIndex)")
        prev_bind_key = (ptx, si)
        cid = b[o:o+32]; o += 32
        pid = b[o:o+32]; o += 32
        act = struct.unpack_from("<Q", b, o)[0]; o += 8
        bindings.append({"proTxHash": ptx[::-1].hex(), "slotIndex": si,
                         "contractId": b58encode(cid), "poolId": b58encode(pid),
                         "activationCoreHeight": act})
    if o != len(b):
        raise SemanticError("checkpoint payload has trailing bytes")
    return {"epochId": epoch_id, "effective": effective, "endExclusive": end_exclusive,
            "books": books, "bindings": bindings}

def make_positive_payload(end_exclusive=1601, binding_pool_raw=None):
    books = [{"contractIdRaw": CONTRACT_RAW, "poolIdRaw": POOLID_RAW,
              "operatorIdRaw": OPERATOR_RAW,
              "slotCount": 2, "shares": [(1, 2), (1, 2)]}]
    bindings = [
        {"proTxHashRaw": POOL_RAW, "slotIndex": 7, "contractIdRaw": CONTRACT_RAW,
         "poolIdRaw": binding_pool_raw or POOLID_RAW, "activationCoreHeight": 900},
    ]
    return build_v2_payload(1, 900, end_exclusive, books, bindings,
                            CHAIN_IDENTITY, SIGNER_PUB)

# ---- the positive vector -------------------------------------------------------------------

def build_positive(end_exclusive=1601, observed=1001):
    tx_hash = sha256_hex(REAL_TX_HEX)
    creation_tx = "ab" * 60
    creation_hash = sha256_hex(creation_tx)
    payload = make_positive_payload(end_exclusive)
    decoded = decode_v2_payload(payload.hex(), CHAIN_IDENTITY, SIGNER_PUB)
    purchase_pos = {"kind": "purchase", "slotIndex": 0, "platformHeight": 2, "txIndex": 0,
                    "docId": CONTRACT, "innerIndex": 0}
    creation_pos = {"kind": "creation", "slotIndex": 0, "platformHeight": 1, "txIndex": 0,
                    "docId": CONTRACT, "innerIndex": 0}
    out = {"script": "76a914" + "11" * 20 + "88ac", "amountDuffs": "100000000", "outputIndex": 0}
    expected = {"script": out["script"], "amountDuffs": out["amountDuffs"]}
    def comp(v):
        return {"claim": "TRUSTED_SOURCE", "verifiersNotRun": [v] if v else []}
    def lw(h, root, state):
        return {"height": h, "blockHash": ("%02x" % (h % 251)) * 32, "protxDiffRaw": EVBYTES,
                "cbTxRaw": "fb" * 80, "cbTxInclusionProof": EVBYTES, "listRoot": root,
                "targetNodeEntry": "ee" * 91, "targetNodeState": state}
    return {
        "envelopeVersion": "1",
        "proofCodecProfile": "tegara-proof-codecs-v1",
        # Revision 26 (a soundness-review finding): the envelope COMMITS the deployment's proof-verifier
        # bundle digest, so the envelope bytes identify which codec interpretation
        # applies (the bundle itself is a BUILD artifact; hashing/retrieval is a runtime
        # duty, and this vector carries a placeholder like other runtime evidence).
        "verifierBundleDigest": "sha256:" + "ab" * 32,
        "network": {"coreNetwork": "devnet", "platformChainId": "dashmate_local_20",
                    "coreGenesisBlockHash": GENESIS.hex(),
                    "coreDevnetGenesisBlockHash": DEVNET_GENESIS_H1.hex()},
        "contractId": CONTRACT,
        "poolProTxHash": POOL_DISPLAY,
        "poolId": POOLID,
        "poolL1SlotIndex": 7,
        "checkpointAuthority": {"publicKey": SIGNER_PUB.hex()},
        "adoptedEpochPins": [{"epochId": 1,
                              "checkpointId": hashlib.sha256(payload).hexdigest()}],
        "checkpoints": [{
            "checkpointId": hashlib.sha256(payload).hexdigest(),
            "epochId": 1,
            "epochRange": {"fromCoreHeight": 900, "toCoreHeight": end_exclusive - 1},
            "signedPayloadBytes": payload.hex(),
            "signature": "ef" * 64,
            "signerPublicKey": SIGNER_PUB.hex(),
            "algorithm": "ed25519",
            "extractedBinding": {"books": decoded["books"], "bindings": decoded["bindings"]}
        }],
        "basePackage": {
            "kind": "rooted", "baseMode": "RANGE_LOCAL", "coreNetwork": "devnet",
            "baseBlock": {"height": 999, "blockHash": H32B},
            "chainlockWitness": EVBYTES, "ancestryProof": EVBYTES,
            "smlEntries": ["fa" * 91], "cbTxRaw": "fb" * 80, "cbTxInclusionProof": EVBYTES,
            "listRoot": H32C,
            "nodeStateAtBase": {"kind": "present", "isValid": True}
        },
        "lifecycle": {"terminalHeight": None, "observedThroughHeight": observed,
                      "suspensions": [], "transitions": []},
        "decoderLineage": [{"fromHeight": 1, "decoderId": DECODER_ID,
                            "artifactDigest": H32D,
                            "artifactRef": "cas:sha256:" + H32D,
                            "runtime": "oci-image-v1",
                            "environmentDigest": "sha256:" + H32E,
                            "executionProfile": "tegara-decoder-v1",
                            "entryPoint": "decode.mjs",
                            "inputFormat": "raw-committed-tx-bytes",
                            "platformProtocolVersion": 9}],
        "claimProfile": {
            "components": {
                "recognition": comp("verifyCheckpointRecognition"),
                "baseProof": comp("verifyBasePackage"),
                "coreContinuityFinality": comp("verifyCoreWalk"),
                "platformCommits": comp("verifyPlatformCommits"),
                "decoderCoverage": comp("verifyDecodeDispositions"),
                "l1Backing": comp("verifyL1BackingAtHeight"),
                "receiptValidity": comp("verifyReceiptDuties"),
                "bookConformance": comp("verifyBookConformance"),
                "conservation": comp("verifyConservation"),
                "transitionHashing": comp("verifyTransitionHashes"),
                "identifierConversion": comp("verifyIdentifierConversion"),
                "schedule": comp(None)
            },
            "aggregate": "trusted-source"
        },
        "validatedChainLock": {"height": 1500, "blockHash": H32A,
                               "quorumPublicKeyMaterial": EVBYTES,
                               "quorumDerivation": EVBYTES},
        "coreHeaderChain": "cd" * 160,
        "platformTrustRoot": "ce" * 40,
        "coreAuditRange": {"fromHeight": 1000, "toHeight": 1001},
        "platformAuditRange": {"fromHeight": 1, "toHeight": 3,
                               "lowerBoundJustification": {"kind": "contract-genesis",
                                                           "contractCreationHeight": 1}},
        "coverage": {
            "listWalk": [lw(1000, H32D, "PRESENT_VALID"), lw(1001, H32E, "PRESENT_VALID")],
            "coreLedger": [
                {"height": 1000, "blockHash": core_block_hash(1000),
                 "scheduleResult": {"kind": "pool-scheduled", "requiredOutputs": [expected]},
                 "coinbase": {"kind": "available", "txRaw": "fb" * 80,
                              "inclusionProof": EVBYTES, "outputs": [out]}},
                {"height": 1001, "blockHash": core_block_hash(1001),
                 "scheduleResult": {"kind": "not-pool"},
                 "coinbase": {"kind": "available", "txRaw": "fb" * 80,
                              "inclusionProof": EVBYTES, "outputs": []}}
            ],
            "coreEndpointChainlockWitness": EVBYTES,
            "platformLedger": [
                {"height": 1, "blockHash": H32A, "headerRaw": "da" * 60,
                 "coreChainLockedHeight": 995, "committedTxCount": 1,
                 "decoderId": DECODER_ID,
                 "txs": [{"kind": "decoded-batch", "txIndex": 0, "committedHash": creation_hash,
                          "rawBytes": creation_tx, "inclusionProof": EVBYTES,
                          "innerCount": 1,
                          "decisions": [{"kind": "retained-position", "innerIndex": 0,
                                         "position": creation_pos,
                                         "economics": {"seller": OPERATOR,
                                                       "buyer": OPERATOR,
                                                       "price": "0"}}]}],
                 "commitSignatures": EVBYTES, "validatorSetBytes": EVBYTES,
                 "validatorTransitionProof": EVBYTES},
                {"height": 2, "blockHash": H32B, "headerRaw": "da" * 60,
                 "coreChainLockedHeight": 999, "committedTxCount": 1,
                 "decoderId": DECODER_ID,
                 "txs": [{"kind": "decoded-batch", "txIndex": 0, "committedHash": tx_hash,
                          "rawBytes": REAL_TX_HEX, "inclusionProof": EVBYTES,
                          "innerCount": 1,
                          "decisions": [{"kind": "retained-position", "innerIndex": 0,
                                         "position": purchase_pos,
                                         "economics": {"seller": OPERATOR,
                                                       "buyer": BUYER,
                                                       "price": "250000000"}}]}],
                 "commitSignatures": EVBYTES, "validatorSetBytes": EVBYTES,
                 "validatorTransitionProof": EVBYTES},
                {"height": 3, "blockHash": H32C, "headerRaw": "da" * 60,
                 "coreChainLockedHeight": 1001, "committedTxCount": 0,
                 "decoderId": DECODER_ID, "txs": [],
                 "commitSignatures": EVBYTES, "validatorSetBytes": EVBYTES,
                 "validatorTransitionProof": EVBYTES}
            ]
        },
        "slots": [
            {"slotIndex": 0, "docId": CONTRACT, "ownershipChain": [
                {"position": creation_pos, "coreChainLockedHeight": 995,
                 "transitionHash": creation_hash, "seller": OPERATOR, "buyer": OPERATOR,
                 "price": "0"},
                {"position": purchase_pos, "coreChainLockedHeight": 999,
                 "transitionHash": tx_hash, "seller": OPERATOR, "buyer": BUYER,
                 "price": "250000000"}
            ]},
            {"slotIndex": 1, "docId": None, "ownershipChain": []}
        ],
        "rewards": [
            {"rewardCoreHeight": 1000, "rewardCoreBlockHash": core_block_hash(1000),
             "recognition": {"status": "RECOGNIZED", "bindingRef": 0},
             "entitlement": {"kind": "classified", "classification": "OWED",
                             "exclusionReason": {"kind": "none"},
                             "eligibility": {"state": "PRESENT_VALID", "listHeight": 999,
                                             "listRoot": H32C},
                             "scheduleSource": "trusted-core-node:masternode-payments",
                             "coinbaseEvidence": {"requiredOutputs": [expected],
                                                  "matchedOutputs": [out],
                                                  "unexplainedOutputs": []},
                             "anomalies": []},
             "conservation": {"kind": "calculated", "grossDuffs": "100000000",
                              "nonSlotComponents": [],
                              "slotAllocationBaseDuffs": "100000000"},
             "slotFanout": {"kind": "slots", "records": [
                 {"slotIndex": 0,
                  "allocation": {"kind": "resolved", "ownerAtH": BUYER,
                                 "snapshotPosition": purchase_pos,
                                 "closingBlock": {"platformHeight": 3,
                                                  "coreChainLockedHeight": 1001}},
                  "share": {"numerator": "1", "denominator": "2"},
                  "allocatedDuffs": "50000000"},
                 {"slotIndex": 1,
                  "allocation": {"kind": "resolved", "ownerAtH": OPERATOR,
                                 "snapshotPosition": {"kind": "pre-creation", "slotIndex": 1},
                                 "closingBlock": {"platformHeight": 3,
                                                  "coreChainLockedHeight": 1001}},
                  "share": {"numerator": "1", "denominator": "2"},
                  "allocatedDuffs": "50000000"}
             ]}},
            {"rewardCoreHeight": 1001, "rewardCoreBlockHash": core_block_hash(1001),
             "recognition": {"status": "RECOGNIZED", "bindingRef": 0},
             "entitlement": {"kind": "classified", "classification": "NOT_PAYEE",
                             "exclusionReason": {"kind": "none"},
                             "eligibility": {"state": "PRESENT_VALID", "listHeight": 1000,
                                             "listRoot": H32D},
                             "scheduleSource": "trusted-core-node:masternode-payments",
                             "coinbaseEvidence": {"requiredOutputs": [],
                                                  "matchedOutputs": [],
                                                  "unexplainedOutputs": []},
                             "anomalies": []},
             "conservation": {"kind": "not-applicable"},
             "slotFanout": {"kind": "none", "reason": "NOT_PAYEE"}}
        ]
    }

# ---------------- semantic layer ----------------

class SemanticError(Exception):
    pass

def require(cond, msg):
    if not cond:
        raise SemanticError(msg)

def require_consecutive(values, first, last, msg):
    # MF-2 (revision 23): interval coverage WITHOUT materializing list(range(...)).
    # Schema-valid heights and counts may reach 2^53-1, so a small malformed envelope
    # must never provoke an enormous allocation before rejection. Cost is O(len(values)),
    # bounded by the actual serialized array.
    require(last >= first - 1, msg)
    require(len(values) == last - first + 1, msg)
    require(all(v == first + i for i, v in enumerate(values)), msg)

VERIFIER_OF = {
    "recognition": "verifyCheckpointRecognition", "baseProof": "verifyBasePackage",
    "coreContinuityFinality": "verifyCoreWalk", "platformCommits": "verifyPlatformCommits",
    "decoderCoverage": "verifyDecodeDispositions", "l1Backing": "verifyL1BackingAtHeight",
    "receiptValidity": "verifyReceiptDuties", "bookConformance": "verifyBookConformance",
    "conservation": "verifyConservation", "transitionHashing": "verifyTransitionHashes",
    "identifierConversion": "verifyIdentifierConversion", "schedule": None,
}
BARRED = {"schedule", "l1Backing", "receiptValidity"}
COMBINED_REQUIRED = [c for c in VERIFIER_OF if c != "schedule"]

def resolve_pointer(env, ptr):
    if not ptr.startswith("/"):
        return False
    cur = env
    for tok in ptr[1:].split("/"):
        tok = tok.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict):
            if tok not in cur:
                return False
            cur = cur[tok]
        elif isinstance(cur, list):
            if not tok.isdigit() or int(tok) >= len(cur):
                return False
            cur = cur[int(tok)]
        else:
            return False
    return True

def strict_pairs(pairs):
    # MAJ-3 (revision 23): RFC 8785 input-domain guard. Python's default json.load
    # SILENTLY keeps the last of conflicting duplicate member names, so a raw envelope
    # with duplicates would be reduced and then pass both layers. Ingestion rejects it.
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate member name %r in raw envelope JSON" % k)
        d[k] = v
    return d

def load_envelope_bytes(raw):
    # The NORMATIVE ingestion path for raw envelope bytes: UTF-8, duplicate member
    # names rejected. Lone UTF-16 surrogates are rejected in the semantic string walk
    # (Python's parser admits "\\ud800" escapes as lone surrogates that would crash
    # canonicalization AFTER acceptance without that check).
    return json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)

# The component dependency graph. HOISTED TO MODULE SCOPE (round 5, MINOR) with its contents
# unchanged: it used to be a local inside check_semantics, so the cross-language drift fixture
# could not read it, looked for a module attribute, found none, and ACCEPTED the absence. A
# drift check that passes when it cannot find one side of the comparison is not a check. The
# JavaScript side of this same graph lives in auditSeam.cjs, and the fixture now requires both
# to be present and equal.
DEPS = {"recognition": ["identifierConversion", "coreContinuityFinality"],
        "baseProof": ["coreContinuityFinality", "identifierConversion"],
        "decoderCoverage": ["platformCommits"],
        "bookConformance": ["decoderCoverage", "recognition"],
        "conservation": ["recognition", "coreContinuityFinality", "bookConformance"],
        "transitionHashing": ["decoderCoverage"],
        "l1Backing": ["coreContinuityFinality"]}

def check_semantics(env):
    # NFC and no floats
    def walk(o):
        if isinstance(o, str):
            require(not any(0xD800 <= ord(c) <= 0xDFFF for c in o),
                    "lone UTF-16 surrogate in string (outside the RFC 8785 domain)")
            require(unicodedata.normalize("NFC", o) == o, "string not NFC")
        elif isinstance(o, list):
            for x in o: walk(x)
        elif isinstance(o, dict):
            for k, v in o.items(): walk(k); walk(v)
        elif isinstance(o, float):
            raise SemanticError("float value present")
    walk(env)

    ca = env["coreAuditRange"]; pa = env["platformAuditRange"]
    cl = env["validatedChainLock"]["height"]
    require(ca["fromHeight"] <= ca["toHeight"], "coreAuditRange inverted")
    require(pa["fromHeight"] <= pa["toHeight"], "platformAuditRange inverted")
    require(ca["toHeight"] <= cl, "coreAuditRange.toHeight beyond chainlock")

    # ---- checkpoints: canonical v2 decode + byte-match, gaplessness, coverage ----
    cps = env["checkpoints"]
    # The domain tag re-derives from the envelope's OWN network fields (never a trusted
    # serialized identity), so a relabelled or re-identified envelope fails the decode.
    env_identity = core_chain_identity_hash(
        env["network"]["coreNetwork"],
        bytes.fromhex(env["network"]["coreGenesisBlockHash"]),
        bytes.fromhex(env["network"]["coreDevnetGenesisBlockHash"])
        if "coreDevnetGenesisBlockHash" in env["network"] else None)
    authority = env["checkpointAuthority"]["publicKey"]
    pins = {p["epochId"]: p["checkpointId"] for p in env["adoptedEpochPins"]}
    require([p["epochId"] for p in env["adoptedEpochPins"]] ==
            sorted(pins.keys()) and len(pins) == len(env["adoptedEpochPins"]),
            "adoptedEpochPins not sorted by distinct epochId")
    prev_epoch = None
    for cp in cps:
        require(cp["signerPublicKey"] == authority,
                "checkpoint signer is not the fixed deployment authority")
        dec = decode_v2_payload(cp["signedPayloadBytes"], env_identity,
                                bytes.fromhex(authority))
        require(cp["epochId"] == dec["epochId"],
                "checkpoint epochId does not byte-match the signed payload")
        require(prev_epoch is None or cp["epochId"] > prev_epoch,
                "epoch ids not distinct and strictly increasing")
        prev_epoch = cp["epochId"]
        require(pins.get(cp["epochId"]) == cp["checkpointId"],
                "checkpoint not pinned by the adopted per-epoch hash pins")
        require(cp["checkpointId"] ==
                hashlib.sha256(bytes.fromhex(cp["signedPayloadBytes"])).hexdigest(),
                "checkpointId != sha256(payload)")
        require(cp["epochRange"]["fromCoreHeight"] == dec["effective"] and
                cp["epochRange"]["toCoreHeight"] == dec["endExclusive"] - 1,
                "epochRange does not byte-match the signed payload")
        require(cp["extractedBinding"] == {"books": dec["books"], "bindings": dec["bindings"]},
                "extractedBinding does not byte-match the decoded payload")
        for bk in dec["books"]:
            require(len(bk["shares"]) == bk["slotCount"], "book shares != slotCount")
            for sh in bk["shares"]:
                require(sh == {"numerator": "1", "denominator": str(bk["slotCount"])},
                        "share is not exactly 1/slotCount (the governing fixed-slot rule)")
        for bd in dec["bindings"]:
            # A binding's L1 slotIndex (0..255) is an independent domain from the retail
            # slotCount; it is NOT compared against the book (round-9 fix). Only the
            # (contractId, poolId) pairing is checked.
            bks = [b for b in dec["books"]
                   if b["contractId"] == bd["contractId"] and b["poolId"] == bd["poolId"]]
            require(len(bks) == 1, "binding (contract, pool) has no book")
    # MAJ-5 (revision 14): the adopted pin set and the retained checkpoint set are a
    # BIJECTION over epoch ids -- every checkpoint is pinned (checked above) AND every pin
    # has a matching checkpoint, so an extra unmatched pin cannot serialize and the
    # adopted epoch set is unambiguous.
    require({p["epochId"] for p in env["adoptedEpochPins"]} ==
            {cp["epochId"] for cp in cps},
            "adoptedEpochPins and checkpoints are not a bijection over epoch ids")
    for i in range(1, len(cps)):
        require(cps[i]["epochRange"]["fromCoreHeight"] ==
                cps[i-1]["epochRange"]["toCoreHeight"] + 1, "epoch gap or overlap")
    require(cps[0]["epochRange"]["fromCoreHeight"] <= ca["fromHeight"], "epochs miss range start")
    require(cps[-1]["epochRange"]["toCoreHeight"] >= ca["toHeight"], "epochs miss range end")
    def book_of(cp):
        # the audited (contractId, poolId) book IF this epoch carries it, else None
        # (a successor epoch that re-binds the L1 position to another pool need not
        # carry the audited pool's book; CONFIRM-2)
        bks = [b for b in cp["extractedBinding"]["books"]
               if b["contractId"] == env["contractId"] and b["poolId"] == env["poolId"]]
        require(len(bks) <= 1, "epoch has a duplicate book for the audited (contract, pool)")
        return bks[0] if bks else None
    books_all = [book_of(cp) for cp in cps]
    present_books = [b for b in books_all if b is not None]
    require(present_books, "the audited pool has no book in any epoch (nothing to audit)")
    slot_count = present_books[0]["slotCount"]
    require(all(b["slotCount"] == slot_count for b in present_books),
            "epochs disagree on slotCount for the audited pool")
    # a soundness-review finding (revision 20): the operator is immutable in v1 (the immutable pool document's
    # owner), so every epoch's book for the audited pool carries ONE operator.
    require(all(b["operatorId"] == present_books[0]["operatorId"] for b in present_books),
            "epochs disagree on the operator for the audited pool")
    def book_at(H):
        for ci, cp in enumerate(cps):
            er = cp["epochRange"]
            if er["fromCoreHeight"] <= H <= er["toCoreHeight"]:
                return books_all[ci]   # non-None exactly when H is RECOGNIZED for us
        return None
    book = present_books[0]
    require(len(env["slots"]) == slot_count, "slots entries != signed slotCount")
    require([s["slotIndex"] for s in env["slots"]] == list(range(slot_count)),
            "slots not exactly one per index in order")

    # ---- coverage-interval equation (round-6: observed >= toHeight) ----
    bp = env["basePackage"]
    require(bp["coreNetwork"] == env["network"]["coreNetwork"],
            "basePackage.coreNetwork != network.coreNetwork")

    # ---- network name bound to the Core genesis hash (MAJOR 3 rev 16; a soundness-review finding rev 17) ----
    # The label is a closed enum (schema). mainnet/testnet bind BOTH WAYS: a well-known
    # genesis forces its canonical name, and the label forces its canonical genesis.
    # regtest binds ONE WAY: the label requires the shared height-zero base, but the base
    # never forces a name (devnet legitimately shares it). devnet requires the shared base
    # PLUS a nonzero height-one devnet genesis distinct from the base (the schema already
    # requires the field for devnet and forbids it elsewhere); authenticating that block is
    # a runtime duty.
    net_name = env["network"]["coreNetwork"]
    gen_hex = env["network"]["coreGenesisBlockHash"]
    require(WELL_KNOWN_GENESIS.get(gen_hex, net_name) == net_name,
            "coreNetwork disagrees with the canonical name for this Core genesis hash")
    require(net_name not in ("mainnet", "testnet") or
            WELL_KNOWN_GENESIS.get(gen_hex) == net_name,
            "a mainnet/testnet label requires its canonical Core genesis hash")
    require(net_name not in ("regtest", "devnet") or gen_hex == SHARED_BASE_GENESIS,
            "a regtest/devnet label requires the shared height-zero base genesis")
    if net_name == "devnet":
        dev_h1 = env["network"]["coreDevnetGenesisBlockHash"]
        require(dev_h1 != gen_hex and dev_h1 != "00" * 32,
                "devnet requires a nonzero height-one devnet genesis distinct from the base")

    # ---- basePackage.smlEntries canonical total order (MAJOR 4, revision 16) ----
    # The note pins a total order for EVERY array; smlEntries had none. Ascending entry
    # bytes is a self-contained canonical order for envelope determinism (the SML merkle
    # root itself is recomputed by the runtime verifier per DIP-4 by proRegTxHash, so this
    # stored order need not equal that sort). Duplicates are rejected by the schema.
    if "smlEntries" in bp:
        require(bp["smlEntries"] == sorted(bp["smlEntries"]),
                "smlEntries not in ascending canonical (entry-bytes) order")
    base_h = bp["baseBlock"]["height"]
    obs = env["lifecycle"]["observedThroughHeight"]
    require(obs >= ca["toHeight"], "observedThroughHeight < toHeight (boundary unobservable)")
    require(obs <= cl, "observedThroughHeight beyond chainlock")
    if bp["kind"] == "rooted" and bp["baseMode"] == "RANGE_LOCAL":
        require(ca["fromHeight"] >= base_h + 1, "range-local audit starts before baseHeight+1")
    if bp["kind"] == "rooted" and bp["baseMode"] == "FIRST_APPEARANCE":
        p = bp["firstAppearance"]["pHeight"]
        require(base_h == p - 1, "first-appearance base must sit at P-1")
        require(ca["fromHeight"] >= p, "first-appearance audit starts before P")
    if bp["kind"] == "pre-dml":
        require(base_h == bp["activationParams"]["activationHeight"] - 1,
                "pre-dml base must sit at activationHeight-1")
        require(ca["fromHeight"] >= bp["activationParams"]["activationHeight"] + 1,
                "pre-dml audit must start at activationHeight+1 or later (the first height with a list root at H-1)")
    if bp["kind"] == "rooted" and bp["baseMode"] == "FIRST_APPEARANCE":
        txid = hashlib.sha256(hashlib.sha256(
            bytes.fromhex(bp["firstAppearance"]["proRegTxRaw"])).digest()).digest()
        require(txid[::-1].hex() == env["poolProTxHash"],
                "ProRegTx txid does not equal poolProTxHash (identifier conversion)")

    # ---- list-walk ledger: full interval, contiguity, journal reconstruction ----
    lwr = env["coverage"]["listWalk"]
    require_consecutive([r["height"] for r in lwr], base_h + 1, obs,
            "list-walk ledger does not cover [baseHeight+1, observedThroughHeight]")
    if bp["kind"] == "rooted":
        st0 = ("PRESENT_VALID" if bp["nodeStateAtBase"]["kind"] == "present" and
               bp["nodeStateAtBase"]["isValid"] else
               "PRESENT_INVALID" if bp["nodeStateAtBase"]["kind"] == "present" else "ABSENT")
    else:
        st0 = "ABSENT"
    for r in lwr:
        require((r["targetNodeEntry"] is None) == (r["targetNodeState"] == "ABSENT"),
                "targetNodeEntry presence contradicts targetNodeState")
    states = [st0] + [r["targetNodeState"] for r in lwr]
    transitions = []
    for i, r in enumerate(lwr):
        if states[i] != states[i + 1]:
            transitions.append({"height": r["height"], "from": states[i], "to": states[i + 1]})
    terminal = None
    suspensions = []
    open_ban = None
    if st0 == "PRESENT_INVALID":
        open_ban = {"kind": "pre-base"}
    for t in transitions:
        require(terminal is None, "transition after terminal removal")
        if t["to"] == "PRESENT_INVALID":
            open_ban = {"kind": "observed", "banHeight": t["height"]}
        elif t["from"] == "PRESENT_INVALID" and t["to"] == "PRESENT_VALID":
            suspensions.append({"start": open_ban, "endHeight": t["height"],
                                "endReason": "REVOKED"})
            open_ban = None
        if t["to"] == "ABSENT":
            terminal = t["height"]
            if open_ban is not None:
                suspensions.append({"start": open_ban, "endHeight": t["height"],
                                    "endReason": "TERMINATED"})
                open_ban = None
    if open_ban is not None:
        suspensions.append({"start": open_ban, "endHeight": obs, "endReason": "RANGE_END"})
    reconstructed = {"terminalHeight": terminal, "observedThroughHeight": obs,
                     "suspensions": suspensions, "transitions": transitions}
    require(env["lifecycle"] == reconstructed,
            "lifecycle does not equal the journal reconstructed from the list-walk ledger")
    if bp["kind"] == "rooted" and bp["baseMode"] == "FIRST_APPEARANCE":
        p = bp["firstAppearance"]["pHeight"]
        if base_h + 1 <= p <= obs:
            prow = lwr[p - (base_h + 1)]
            require(bp["firstAppearance"]["additionDiffRaw"] == prow["protxDiffRaw"],
                    "firstAppearance additionDiffRaw != the retained P-row diff")
            # a soundness-review finding (revision 20): first appearance means the P row ADDS the node. The
            # base sits at P-1 with the node proved absent, so the walked state AT P must
            # be present, or the claimed first-appearance height (and every full-lifetime
            # claim built on it) is wrong even though the diff bytes match.
            require(prow["targetNodeState"] != "ABSENT",
                    "first-appearance P row does not add the node (still absent at P)")
    for s in env["lifecycle"]["suspensions"]:
        if s["endReason"] == "TERMINATED":
            require(s["endHeight"] == env["lifecycle"]["terminalHeight"],
                    "TERMINATED suspension end != terminalHeight")
        if s["endReason"] == "RANGE_END":
            require(s["endHeight"] == obs, "RANGE_END end != observedThroughHeight")
        if s["start"]["kind"] == "observed":
            require(s["endHeight"] >= s["start"]["banHeight"], "suspension ends before its ban")
    if env["lifecycle"]["terminalHeight"] is not None:
        require(env["lifecycle"]["terminalHeight"] <= obs, "terminal beyond observation")

    # ---- core ledger and rewards: one record per row, in order ----
    core_rows = env["coverage"]["coreLedger"]
    require_consecutive([r["height"] for r in core_rows],
            ca["fromHeight"], ca["toHeight"], "core ledger not contiguous")
    require([r["rewardCoreHeight"] for r in env["rewards"]] ==
            [r["height"] for r in core_rows], "rewards not one per core ledger row in order")
    # a soundness-review finding (revision 20): the two Core-side ledgers describe ONE chain, so overlapping
    # heights must agree: same block hash, and (when the coinbase evidence is available)
    # the SAME coinbase transaction bytes as the list-walk row's cbTx. Before this, the
    # lifecycle/eligibility evidence and the reward accounting could come from different
    # blocks at one height and both serialize.
    lw_by_h = {r["height"]: r for r in lwr}
    for r in core_rows:
        w = lw_by_h.get(r["height"])
        if w is not None:
            require(r["blockHash"] == w["blockHash"],
                    "coreLedger and listWalk disagree on the block hash at one height")
            if r["coinbase"]["kind"] == "available":
                require(r["coinbase"]["txRaw"] == w["cbTxRaw"],
                        "coreLedger coinbase bytes != the listWalk cbTx at one height")

    # ---- platform ledger ----
    prows = env["coverage"]["platformLedger"]
    require_consecutive([r["height"] for r in prows],
            pa["fromHeight"], pa["toHeight"], "platform ledger not contiguous")
    anchors = [r["coreChainLockedHeight"] for r in prows]
    require(all(a <= b for a, b in zip(anchors, anchors[1:])), "anchor regression")
    posmap = {}
    committed = {}
    for r in prows:
        require(r["committedTxCount"] == len(r["txs"]), "committedTxCount mismatch")
        # a soundness-review finding (revision 18): every tx carries its committed block position explicitly,
        # contiguous 0..n-1 in array order, so two permutations of the same transactions
        # cannot both serialize (the block-order truth of the indexes themselves is the
        # inclusion proofs' runtime duty).
        require([t["txIndex"] for t in r["txs"]] == list(range(len(r["txs"]))),
                "platform txs not contiguous by txIndex in order")
        for ti, t in enumerate(r["txs"]):
            require(t["committedHash"] == sha256_hex(t["rawBytes"]),
                    "committedHash != sha256(rawBytes)")
            committed[t["committedHash"]] = (r["height"], ti)
            if t["kind"] == "decoded-batch":
                require_consecutive([d["innerIndex"] for d in t["decisions"]], 0,
                        t["innerCount"] - 1, "inner decisions not one per inner index")
                for d in t["decisions"]:
                    if d["kind"] == "retained-position":
                        p = d["position"]
                        require(p["kind"] != "pre-creation", "retained position cannot be pre-creation")
                        require(p["platformHeight"] == r["height"] and p["txIndex"] == ti and
                                p["innerIndex"] == d["innerIndex"],
                                "retained position does not match its own location")
                        key = (p["platformHeight"], p["txIndex"], p["innerIndex"])
                        require(key not in posmap, "duplicate retained position")
                        posmap[key] = {"hash": t["committedHash"], "position": p,
                                       "anchor": r["coreChainLockedHeight"],
                                       "economics": d["economics"]}
    if pa["lowerBoundJustification"]["kind"] == "contract-genesis":
        cch = pa["lowerBoundJustification"]["contractCreationHeight"]
        require(pa["fromHeight"] <= cch,
                "fromHeight above contract creation under contract-genesis justification")
        # a soundness-review finding (revision 19): the offline consistency teeth on the CLAIMED creation
        # height. No document of the contract can exist before the contract does, so any
        # retained position preceding the claimed height proves the claim false-high (the
        # truth of the height itself is the runtime retrieval duty in the registry).
        for s_ in env["slots"]:
            for hop in s_["ownershipChain"]:
                require(hop["position"].get("platformHeight", cch) >= cch,
                        "retained position precedes the claimed contract creation height")
    elif pa["lowerBoundJustification"]["kind"] == "absence-proof":
        # The all-absent content of stateProof is verifyBookConformance's runtime
        # cryptographic duty (disclosed residual); the structural shape is schema-checked.
        require(len(pa["lowerBoundJustification"]["stateProof"]) > 0,
                "empty absence-proof stateProof")

    # ---- verifyDecoderSelection ----
    lineage = env["decoderLineage"]
    require([e["fromHeight"] for e in lineage] ==
            sorted({e["fromHeight"] for e in lineage}), "decoder lineage not strictly increasing")
    # a soundness-review finding (revision 17): lineage entries are BOUND, not producer-labelled. The id is
    # derived from the bundle digest; the content-addressed reference must embed the SAME
    # digest (a ref pointing elsewhere is a different bundle); the retained lineage extent
    # is EXACT over the platform audit interval (an earlier start retains unused prefix
    # history, a fromHeight beyond the interval end is an entry no row can select).
    # platformProtocolVersion and the execution descriptor are repeated inside the bundle's
    # canonical manifest and checked EQUAL at runtime (the suite cannot open the bundle).
    for e in lineage:
        require(e["decoderId"] == "decoder-sha256-" + e["artifactDigest"][:16],
                "decoderId is not derived from the artifact digest")
        require(e["artifactRef"] == "cas:sha256:" + e["artifactDigest"],
                "artifactRef does not embed the artifact digest")
    require(lineage[0]["fromHeight"] == pa["fromHeight"],
            "lineage does not start exactly at the platform audit fromHeight")
    require(all(e["fromHeight"] <= pa["toHeight"] for e in lineage),
            "unused decoder lineage entry beyond the platform audit interval")
    # a soundness-review finding (revision 18): the lineage records CHANGE POINTS, not deployments. Adjacent
    # entries must differ in at least one bundle-identity field, or the same decoder
    # history has two serializations (a one-entry and a redundantly split two-entry form).
    for i in range(1, len(lineage)):
        require(any(lineage[i][k] != lineage[i - 1][k]
                    for k in ("artifactDigest", "platformProtocolVersion",
                              "environmentDigest")),
                "adjacent lineage entries do not differ (redundant split)")
    def select_decoder(h):
        cand = [e for e in lineage if e["fromHeight"] <= h]
        require(cand, "no decoder covers height")
        return cand[-1]["decoderId"]
    for r in prows:
        require(r["decoderId"] == select_decoder(r["height"]),
                "platform row decoderId violates the selection rule")

    # ---- verifyOwnership ----
    row_anchor = {r["height"]: r["coreChainLockedHeight"] for r in prows}
    chains = {}
    for s in env["slots"]:
        keys = []
        prev_buyer = None
        for i, h in enumerate(s["ownershipChain"]):
            p = h["position"]
            require(p["kind"] in ("purchase", "creation"), "chain hop must be a concrete position")
            require(p["slotIndex"] == s["slotIndex"], "chain hop slotIndex mismatch")
            require(s["docId"] is not None and p["docId"] == s["docId"],
                    "chain hop docId mismatch")
            key = (p["platformHeight"], p["txIndex"], p["innerIndex"])
            require(key in posmap, "chain hop cites no decoded position")
            require(posmap[key]["position"] == p, "chain hop position != decoded position")
            require(h["transitionHash"] == posmap[key]["hash"],
                    "transitionHash != the committed bytes at this position")
            eco = posmap[key]["economics"]
            require(h["seller"] == eco["seller"] and h["buyer"] == eco["buyer"] and
                    h["price"] == eco["price"],
                    "chain hop economics != the decoded transaction economics")
            require(h["coreChainLockedHeight"] == row_anchor[p["platformHeight"]],
                    "hop anchor != platform row anchor")
            if i == 0:
                require(p["kind"] == "creation", "chain does not start at a creation")
                require(h["seller"] == h["buyer"], "creation hop seller != buyer (minter)")
                # a soundness-review finding (revision 20): the minter IS the signed book's operator (the note
                # requires every chain to begin with an OPERATOR-minted creation; before
                # this, any identity could serialize as the initial owner and receive
                # later allocations against the issuance rule).
                require(h["buyer"] == book["operatorId"],
                        "creation minter is not the signed book's operator")
            else:
                require(p["kind"] == "purchase", "later hop must be a purchase")
                require(h["seller"] == prev_buyer, "seller continuity broken")
            prev_buyer = h["buyer"]
            keys.append(key)
        require(keys == sorted(keys) and len(set(keys)) == len(keys),
                "ownership chain out of order or duplicated")
        # a minted slot (non-null docId) MUST carry a creation-first chain; a never-minted
        # slot (null docId) MUST have an empty chain (round-9 CLI: a non-null docId with an
        # empty chain was silently treated as pre-creation and paid to the operator)
        require((s["docId"] is None) == (len(s["ownershipChain"]) == 0),
                "docId presence must match ownership-chain non-emptiness")
        chains[s["slotIndex"]] = s["ownershipChain"]
    chain_keys = [(h["position"]["platformHeight"], h["position"]["txIndex"],
                   h["position"]["innerIndex"])
                  for s in env["slots"] for h in s["ownershipChain"]]
    require(sorted(chain_keys) == sorted(posmap.keys()),
            "retained positions and ownership hops are not in bijection")

    def first_closing(H):
        for r in prows:
            if r["coreChainLockedHeight"] >= H:
                return r
        return None

    # ---- verifyRecognition: the governing recognize function, re-derived per slot ----
    def recognize_at(H):
        # The governing recognize(): per L1 position (proTxHash, poolL1SlotIndex); at
        # most ONE (contractId, poolId) is named; the whole retail book inherits it.
        first_from = cps[0]["epochRange"]["fromCoreHeight"]
        last_to = cps[-1]["epochRange"]["toCoreHeight"]
        if H < first_from:
            return {"status": "UNRECOGNIZED", "bindingRef": None}
        if H > last_to:
            return {"status": "DEFERRED", "bindingRef": None}
        for ci, cp in enumerate(cps):
            er = cp["epochRange"]
            if er["fromCoreHeight"] <= H <= er["toCoreHeight"]:
                found = [b for b in cp["extractedBinding"]["bindings"]
                         if b["proTxHash"] == env["poolProTxHash"] and
                         b["slotIndex"] == env["poolL1SlotIndex"]]
                if not found:
                    return {"status": "UNRECOGNIZED", "bindingRef": None}
                bd = found[0]
                if bd["contractId"] != env["contractId"] or bd["poolId"] != env["poolId"]:
                    # a valid SUCCESSOR binding at this L1 position: the audited (old) pool
                    # is UNRECOGNIZED here, the successor is recognized instead (CONFIRM-2:
                    # this must NOT hard-error, or a legitimate old-pool envelope spanning a
                    # future re-binding could not serialize)
                    return {"status": "UNRECOGNIZED", "bindingRef": None}
                if H < bd["activationCoreHeight"]:
                    return {"status": "UNRECOGNIZED", "bindingRef": ci}
                for su in env["lifecycle"]["suspensions"]:
                    lo = (su["start"]["banHeight"] + 1
                          if su["start"]["kind"] == "observed" else base_h + 1)
                    if lo <= H <= su["endHeight"]:
                        return {"status": "UNRECOGNIZED", "bindingRef": ci}
                term = env["lifecycle"]["terminalHeight"]
                if term is not None and term < H:
                    return {"status": "UNRECOGNIZED", "bindingRef": ci}
                return {"status": "RECOGNIZED", "bindingRef": ci}
        raise SemanticError("height inside epoch span has no covering epoch")

    # ---- verifyRewardDecision + result matrix + verifyConservation ----
    operator = book["operatorId"]
    def eligibility_at(H):
        hm1 = H - 1
        if hm1 == base_h:
            state3, root = st0, (bp["listRoot"] if bp["kind"] == "rooted" else None)
        else:
            row = lwr[hm1 - (base_h + 1)]
            state3, root = row["targetNodeState"], row["listRoot"]
        if state3 in ("PRESENT_VALID", "PRESENT_INVALID"):
            return state3, root
        term = env["lifecycle"]["terminalHeight"]
        if term is not None and term <= hm1:
            return "ABSENT_TERMINAL", root
        if bp["kind"] == "rooted" and bp.get("baseMode") == "FIRST_APPEARANCE" and \
           hm1 < bp["firstAppearance"]["pHeight"]:
            return "ABSENT_PRE_APPEARANCE", root
        if bp["kind"] == "pre-dml":
            appeared = [t for t in env["lifecycle"]["transitions"]
                        if t["from"] == "ABSENT" and t["height"] <= hm1]
            if not appeared:
                return "ABSENT_PRE_APPEARANCE", root
        return "ABSENT_UNKNOWN", root

    for r in core_rows:
        if r["coinbase"]["kind"] == "available":
            # MAJ-6 (revision 14): the retained ACTUAL coinbase outputs are in ascending
            # outputIndex order (total, unique), so two producers cannot emit different
            # canonical bytes for the same coinbase.
            oidx = [o["outputIndex"] for o in r["coinbase"]["outputs"]]
            require(oidx == sorted(oidx), "coinbase outputs not in ascending outputIndex order")
            idxs = [o["outputIndex"] for o in r["coinbase"]["outputs"]]
            require(len(set(idxs)) == len(idxs), "duplicate coinbase outputIndex")
    for rec, row in zip(env["rewards"], core_rows):
        H = rec["rewardCoreHeight"]
        require(rec["rewardCoreBlockHash"] == row["blockHash"],
                "rewardCoreBlockHash != core ledger block hash")
        recog = recognize_at(H)
        require(rec["recognition"] == recog,
                "height recognition does not match the governing function")
        ent = rec["entitlement"]
        sched = row["scheduleResult"]
        missing = []
        if sched["kind"] == "unavailable":
            missing.append("schedule")
        if row["coinbase"]["kind"] == "unavailable":
            missing.append("coinbase")
        estate, eroot = eligibility_at(H)
        if H > cl:
            # DEFENSIVE-UNREACHABLE (an independent review, revision 23): the ledger loop is bounded by
            # ca.toHeight and the boundary checks force ca.toHeight <= cl, so H can never
            # exceed cl here for any envelope passing those checks. Kept as the note's
            # stated defensive residual; do NOT try to write a vector reaching it.
            require(ent == {"kind": "unfinalized"}, "expected unfinalized entitlement")
            expect_cons, expect_fan = "unavailable", ("none", "UNFINALIZED")
        elif missing:
            require(ent == {"kind": "unknown", "missingInputs": sorted(missing)},
                    "expected unknown entitlement with the absent trusted reads")
            expect_cons, expect_fan = "unavailable", ("none", "UNKNOWN")
        elif sched["kind"] == "not-pool" and estate == "ABSENT_UNKNOWN":
            require(ent == {"kind": "unknown", "missingInputs": ["eligibility-base"]},
                    "expected unknown entitlement for ABSENT_UNKNOWN")
            expect_cons, expect_fan = "unavailable", ("none", "UNKNOWN")
        else:
            require(ent["kind"] == "classified", "expected classified entitlement")
            require(ent["eligibility"] == {"state": estate, "listHeight": H - 1,
                                           "listRoot": eroot},
                    "eligibility does not match the derived list state")
            derived_matched = []
            if sched["kind"] == "pool-scheduled":
                # a soundness-review finding (revision 15, VALIDATED at 8c9f166a3:src/masternode/payments.cpp:
                # 74-84): the pool masternode's OWNER payout is a VECTOR -- GetOwnerPayouts
                # returns one entry per owner-payout share and the loop emits one positive
                # output per entry (a zero-amount entry, e.g. a truncated last share, is
                # OMITTED), so requiredOutputs is 0..N. The OPERATOR reward is a SEPARATE
                # out-of-book output (POSITIONAL separation, never script inequality; the
                # runtime derivation applies OWNER-FIRST CONSUMING attribution, a soundness-review finding).
                # gross = sum of the matched owner
                # vector. NARROWED CLAIM (revision 25): the owner vector's SOURCE
                # SELECTION is part of the schedule residual (structurally
                # TRUSTED_SOURCE; the serialized SML entry excludes scriptPayout and the
                # payout shares, so no retained evidence authenticates the selection).
                # What IS authenticated: coinbase parsing, CONSUMING owner-first
                # matching, and the arithmetic RELATIVE TO that trusted owner vector.
                # matched = ACTUAL coinbase outputs satisfying the EXPECTED multiset,
                # ascending outputIndex; unexplained = EVERY actual output not consumed
                # by the owner match (revision 25, complete remainder: the operator's
                # output, any script, lands here as informational evidence).
                used = set()
                for exp in sched["requiredOutputs"]:
                    got = [o for o in row["coinbase"]["outputs"]
                           if o["script"] == exp["script"] and
                           o["amountDuffs"] == exp["amountDuffs"] and
                           o["outputIndex"] not in used]
                    if got:
                        got.sort(key=lambda o: o["outputIndex"])
                        used.add(got[0]["outputIndex"])
                        derived_matched.append(got[0])
                derived_matched.sort(key=lambda o: o["outputIndex"])
                derived_unexp = sorted(
                    [o for o in row["coinbase"]["outputs"]
                     if o["outputIndex"] not in used],
                    key=lambda o: o["outputIndex"])
                require(ent["coinbaseEvidence"]["requiredOutputs"] == sched["requiredOutputs"],
                        "coinbaseEvidence.requiredOutputs != schedule requiredOutputs")
                require(ent["coinbaseEvidence"]["matchedOutputs"] == derived_matched,
                        "matchedOutputs not derived from the retained coinbase outputs")
                require(ent["coinbaseEvidence"]["unexplainedOutputs"] == derived_unexp,
                        "unexplainedOutputs not derived by the pinned rule")
                if estate != "PRESENT_VALID":
                    derived, reason = "ANOMALY", "none"
                elif len(derived_matched) != len(sched["requiredOutputs"]):
                    derived, reason = "ANOMALY", "none"
                else:
                    derived, reason = "OWED", "none"
            else:
                # Canonical arrays for every non-pool branch are EMPTY (round-8).
                require(ent["coinbaseEvidence"] == {"requiredOutputs": [],
                                                    "matchedOutputs": [],
                                                    "unexplainedOutputs": []},
                        "non-pool coinbase evidence arrays must be empty")
                derived, reason = {
                    "ABSENT_TERMINAL": ("EXCLUDED", "terminal"),
                    "ABSENT_PRE_APPEARANCE": ("EXCLUDED", "pre-appearance"),
                    "PRESENT_INVALID": ("EXCLUDED", "suspension"),
                    "PRESENT_VALID": ("NOT_PAYEE", "none"),
                }[estate]
            require(ent["classification"] == derived,
                    "classification not derivable from evidence (derived %s)" % derived)
            require(ent["exclusionReason"]["kind"] == reason,
                    "exclusionReason does not match the derived classification")
            if derived == "ANOMALY":
                require(len(ent["anomalies"]) >= 1,
                        "ANOMALY classification requires at least one derived anomaly")
                code = ("SCHEDULE_LIST_DISAGREEMENT" if estate != "PRESENT_VALID"
                        else "COINBASE_MISMATCH")
                require(all(a["code"] == code for a in ent["anomalies"]),
                        "anomaly code does not match the derived disagreement")
                # code-specific evidence targets (round-9 review, major 5): an anomaly
                # must cite BOTH sides of its disagreement, not any two resolving refs.
                hpath = "/coverage/coreLedger/%d" % core_rows.index(row)
                epath = "/rewards/%d/entitlement/eligibility" % env["rewards"].index(rec)
                need = ({hpath, epath} if code == "SCHEDULE_LIST_DISAGREEMENT"
                        else {hpath, "/rewards/%d/entitlement/coinbaseEvidence"
                              % env["rewards"].index(rec)})
                require(len(ent["anomalies"]) == 1,
                        "exactly one derived anomaly is required for the disagreement")
                a0 = ent["anomalies"][0]
                require(set(a0["evidenceRefs"]) == need,
                        "anomaly evidenceRefs must be EXACTLY the two sides of the %s" % code)
            else:
                require(ent["anomalies"] == [],
                        "non-ANOMALY classification must carry no anomalies")
            expect_cons = {"OWED": "calculated", "NOT_PAYEE": "not-applicable",
                           "EXCLUDED": "not-applicable", "ANOMALY": "unavailable"}[derived]
            if derived == "OWED" and recog["status"] != "RECOGNIZED":
                expect_cons = "not-applicable"
                expect_fan = ("none", recog["status"])
            elif derived == "OWED":
                expect_fan = ("slots", None)
            else:
                expect_fan = ("none", derived)
        cons = rec["conservation"]
        fan = rec["slotFanout"]
        require(cons["kind"] == expect_cons, "conservation kind violates the result matrix")
        if expect_fan[0] == "none":
            require(fan["kind"] == "none" and fan["reason"] == expect_fan[1],
                    "slotFanout violates the result matrix")
        else:
            require(fan["kind"] == "slots", "expected slot fanout")
            recs = fan["records"]
            require([x["slotIndex"] for x in recs] == list(range(slot_count)),
                    "fanout not exactly slotCount records in order")
            base = int(cons["slotAllocationBaseDuffs"])
            require(int(cons["grossDuffs"]) -
                    sum(int(c["duffs"]) for c in cons["nonSlotComponents"]) == base,
                    "slotAllocationBase != gross - nonSlotComponents")
            comps = cons["nonSlotComponents"]
            require([c["name"] for c in comps] == sorted(c["name"] for c in comps),
                    "nonSlotComponents not ordered by name")
            hbook = book_at(H)
            require(hbook is not None,
                    "a recognized OWED height has no audited-pool book in its epoch")
            shares = [Fraction(int(sh["numerator"]), int(sh["denominator"]))
                      for sh in hbook["shares"]]
            floors = [int(base * sh.numerator // sh.denominator) for sh in shares]
            rem = base - sum(floors)
            fracs = sorted(range(slot_count),
                           key=lambda i: (-(Fraction(base) * shares[i] - floors[i]), i))
            alloc = list(floors)
            for i in fracs[:rem]:
                alloc[i] += 1
            require(int(cons["grossDuffs"]) ==
                    sum(int(o["amountDuffs"])
                        for o in ent["coinbaseEvidence"]["matchedOutputs"]),
                    "grossDuffs not derived from the matched Core payout")
            allocated_total = 0
            closing = first_closing(H)
            for x in recs:
                si = x["slotIndex"]
                require(x["share"] == hbook["shares"][si],
                        "slot share != signed book share")
                require(x["allocatedDuffs"] == str(alloc[si]),
                        "allocatedDuffs != largest-remainder result")
                allocated_total += alloc[si]
                allo = x["allocation"]
                if allo["kind"] == "resolved":
                    require(closing is not None, "resolved allocation without a closing block")
                    require(allo["closingBlock"] ==
                            {"platformHeight": closing["height"],
                             "coreChainLockedHeight": closing["coreChainLockedHeight"]},
                            "closingBlock is not the FIRST platform row reaching H")
                    chain = chains.get(si, [])
                    eligible = [h for h in chain if h["coreChainLockedHeight"] < H]
                    if eligible:
                        require(allo["snapshotPosition"] == eligible[-1]["position"],
                                "snapshot is not the last eligible position before closing")
                        require(allo["ownerAtH"] == eligible[-1]["buyer"],
                                "ownerAtH != snapshot buyer")
                    else:
                        require(allo["snapshotPosition"] ==
                                {"kind": "pre-creation", "slotIndex": si},
                                "empty chain requires the pre-creation snapshot")
                        require(allo["ownerAtH"] == operator,
                                "pre-creation owner must be the book operator")
                else:
                    require(closing is None, "unclosed allocation despite a closing block")
            require(allocated_total == base,
                    "allocated sum != slotAllocationBase")
        if ent.get("kind") == "classified":
            akeys = [(a["code"], canonical_bytes(a)) for a in ent["anomalies"]]
            require(akeys == sorted(akeys) and len(set(akeys)) == len(akeys),
                    "anomalies not in total order or duplicated")
            for a in ent["anomalies"]:
                for ref in a["evidenceRefs"]:
                    require(resolve_pointer(env, ref), "evidenceRef does not resolve")
                require(a["evidenceRefs"] == sorted(a["evidenceRefs"]) and
                        len(set(a["evidenceRefs"])) == len(a["evidenceRefs"]),
                        "evidenceRefs not sorted and unique")

    # ---- verifyClaimProfile ----
    comps = env["claimProfile"]["components"]
    for name, c in comps.items():
        if c["claim"] == "AUTHENTICATED":
            for d in DEPS.get(name, []):
                require(comps[d]["claim"] == "AUTHENTICATED",
                        "AUTHENTICATED %s depends on non-AUTHENTICATED %s" % (name, d))
    any_auth = False
    for name, c in comps.items():
        if c["claim"] == "AUTHENTICATED":
            require(name not in BARRED, "component %s is barred from AUTHENTICATED" % name)
            require(c["verifiersNotRun"] == [], "AUTHENTICATED with verifiers not run")
            any_auth = True
        else:
            v = VERIFIER_OF[name]
            require(c["verifiersNotRun"] == ([v] if v else []),
                    "TRUSTED component must name its absent verifier")
        require(c["verifiersNotRun"] == sorted(c["verifiersNotRun"]),
                "verifiersNotRun not sorted")
    incomplete = False
    for rec in env["rewards"]:
        if rec["entitlement"]["kind"] in ("unknown", "unfinalized"):
            incomplete = True
        if rec["slotFanout"]["kind"] == "slots":
            for x in rec["slotFanout"]["records"]:
                if x["allocation"]["kind"] == "unclosed":
                    incomplete = True
    if not any_auth:
        expected = "trusted-source"
    elif incomplete or any(comps[c]["claim"] != "AUTHENTICATED" for c in COMBINED_REQUIRED):
        expected = "partial-evidence"
    else:
        expected = "proof-verified-except-schedule"
    require(env["claimProfile"]["aggregate"] == expected,
            "aggregate profile != the one exclusive matching profile (%s)" % expected)

# ---------------- negative mutations ----------------

def negatives(pos):
    def m(name, layer, fn):
        e = copy.deepcopy(pos); fn(e); return (name, layer, e)
    def set_price_number(e):
        e["slots"][0]["ownershipChain"][1]["price"] = 250000000
    def legacy_susp(e):
        e["lifecycle"]["suspensions"] = [{"banHeight": 5, "endHeight": 6,
                                          "endReason": "RANGE_END"}]
    def gross_not_derived(e):
        e["rewards"][0]["conservation"]["grossDuffs"] = "999"
        e["rewards"][0]["conservation"]["slotAllocationBaseDuffs"] = "999"
    def sched_auth(e):
        e["claimProfile"]["components"]["schedule"] = {"claim": "AUTHENTICATED",
                                                       "verifiersNotRun": []}
    def aggregate_overclaim(e):
        e["claimProfile"]["aggregate"] = "proof-verified-except-schedule"
    def remainder_60_40(e):
        rs = e["rewards"][0]["slotFanout"]["records"]
        rs[0]["allocatedDuffs"] = "60000000"
        rs[1]["allocatedDuffs"] = "40000000"
    def sum_mismatch(e):
        e["rewards"][0]["slotFanout"]["records"][0]["allocatedDuffs"] = "50000001"
    def epoch_payload_mismatch(e):
        e["checkpoints"][0]["epochRange"]["toCoreHeight"] = 1000
    def binding_payload_mismatch(e):
        e["checkpoints"][0]["extractedBinding"]["books"][0]["slotCount"] = 3
    def boundary_omitted(e):
        e["lifecycle"]["observedThroughHeight"] = 1000
        e["coverage"]["listWalk"] = e["coverage"]["listWalk"][:1]
    def drop_diff(e):
        e["coverage"]["listWalk"] = e["coverage"]["listWalk"][1:]
    def swap_rewards(e):
        e["rewards"] = [e["rewards"][1], e["rewards"][0]]
        e["coverage"]["coreLedger"] = [e["coverage"]["coreLedger"][1],
                                       e["coverage"]["coreLedger"][0]]
    def anchor_reg(e):
        e["coverage"]["platformLedger"][2]["coreChainLockedHeight"] = 998
    def hash_flip(e):
        t = e["coverage"]["platformLedger"][1]["txs"][0]
        t["committedHash"] = "00" + t["committedHash"][2:]
    def class_not_derivable(e):
        ent = e["rewards"][0]["entitlement"]
        ent["classification"] = "EXCLUDED"
        ent["exclusionReason"] = {"kind": "terminal"}
        e["rewards"][0]["conservation"] = {"kind": "not-applicable"}
        e["rewards"][0]["slotFanout"] = {"kind": "none", "reason": "EXCLUDED"}
    def missing_inner(e):
        t = e["coverage"]["platformLedger"][1]["txs"][0]
        t["innerCount"] = 2
    def bad_decoder(e):
        # a grammar-valid decoder id that is not the lineage selection for this row
        e["coverage"]["platformLedger"][2]["decoderId"] = "decoder-sha256-" + ("ee" * 32)[:16]
    def wrong_position_hash(e):
        h1 = e["slots"][0]["ownershipChain"][1]
        h1["transitionHash"] = e["slots"][0]["ownershipChain"][0]["transitionHash"]
    def late_closing(e):
        for x in e["rewards"][0]["slotFanout"]["records"]:
            x["allocation"]["closingBlock"] = {"platformHeight": 3,
                                               "coreChainLockedHeight": 1002}
    def fa_txid_mismatch(e):
        bp = e["basePackage"]
        bp["baseMode"] = "FIRST_APPEARANCE"
        bp["nodeStateAtBase"] = {"kind": "absent"}
        bp["firstAppearance"] = {"pHeight": 1000, "proRegTxRaw": "99" * 120,
                                 "proRegTxInclusionProof": "de" * 40,
                                 "additionDiffRaw": "de" * 40}
    def wrong_recognition(e):
        e["rewards"][0]["recognition"] = {"status": "UNRECOGNIZED", "bindingRef": None}
    def pre_base_omitted(e):
        e["basePackage"]["nodeStateAtBase"] = {"kind": "present", "isValid": False}
    def omitted_chain_hop(e):
        e["slots"][0]["ownershipChain"] = e["slots"][0]["ownershipChain"][:1]
        rs = e["rewards"][0]["slotFanout"]["records"]
        rs[0]["allocation"]["snapshotPosition"] = \
            e["slots"][0]["ownershipChain"][0]["position"]
        rs[0]["allocation"]["ownerAtH"] = e["slots"][0]["ownershipChain"][0]["buyer"]
    def coinbase_match_not_derived(e):
        ent = e["rewards"][0]["entitlement"]
        ent["coinbaseEvidence"]["matchedOutputs"] = []
        ent["classification"] = "ANOMALY"
        e["rewards"][0]["conservation"] = {"kind": "unavailable"}
        e["rewards"][0]["slotFanout"] = {"kind": "none", "reason": "ANOMALY"}
    def auth_dependency_violation(e):
        e["claimProfile"]["components"]["bookConformance"] = \
            {"claim": "AUTHENTICATED", "verifiersNotRun": []}
        e["claimProfile"]["aggregate"] = "partial-evidence"
    def entry_state_mismatch(e):
        e["coverage"]["listWalk"][0]["targetNodeEntry"] = None
    def unequal_shares(e):
        books = [{"contractIdRaw": CONTRACT_RAW, "poolIdRaw": POOLID_RAW,
                  "operatorIdRaw": OPERATOR_RAW, "slotCount": 2, "shares": [(3, 4), (1, 4)]}]
        bindings = [
            {"proTxHashRaw": POOL_RAW, "slotIndex": 0, "contractIdRaw": CONTRACT_RAW,
             "poolIdRaw": POOLID_RAW, "activationCoreHeight": 900}]
        payload = build_v2_payload(1, 900, 1601, books, bindings, CHAIN_IDENTITY, SIGNER_PUB)
        cp = e["checkpoints"][0]
        cp["signedPayloadBytes"] = payload.hex()
        cp["checkpointId"] = hashlib.sha256(payload).hexdigest()
        dec = decode_v2_payload(payload.hex(), CHAIN_IDENTITY, SIGNER_PUB)
        cp["extractedBinding"] = {"books": dec["books"], "bindings": dec["bindings"]}
        e["adoptedEpochPins"][0]["checkpointId"] = cp["checkpointId"]
    def epoch_pin_mismatch(e):
        e["adoptedEpochPins"][0]["checkpointId"] = "00" * 32
    def authority_mismatch(e):
        e["checkpointAuthority"]["publicKey"] = "43" * 32
    def economics_mismatch(e):
        d = e["coverage"]["platformLedger"][1]["txs"][0]["decisions"][0]
        d["economics"]["buyer"] = OPERATOR
    def coinbase_unavailable_not_unknown(e):
        e["coverage"]["coreLedger"][0]["coinbase"] = {"kind": "unavailable"}
    def spurious_anomaly_on_owed(e):
        e["rewards"][0]["entitlement"]["anomalies"] = [
            {"code": "COINBASE_MISMATCH", "evidenceRefs": ["/contractId", "/poolId"]}]
    def alt_schedule_source(e):
        e["rewards"][0]["entitlement"]["scheduleSource"] = "some-other-source"
    def network_mismatch(e):
        e["basePackage"]["coreNetwork"] = "mainnet"
    def not_pool_nonempty_coinbase(e):
        out = {"script": "76a914" + "11" * 20 + "88ac", "amountDuffs": "1",
               "outputIndex": 0}
        e["rewards"][1]["entitlement"]["coinbaseEvidence"]["matchedOutputs"] = [out]
    def truncated_payload(e):
        cp = e["checkpoints"][0]
        cp["signedPayloadBytes"] = cp["signedPayloadBytes"][:120]
    def pre_dml_activation_mismatch(e):
        # pre-dml base whose baseHeight is activationHeight-2 (must be activationHeight-1)
        e["basePackage"] = {"kind": "pre-dml", "coreNetwork": "devnet",
                            "baseBlock": {"height": 998, "blockHash": H32B},
                            "chainlockWitness": EVBYTES, "ancestryProof": EVBYTES,
                            "activationParams": {"deploymentName": "dip3",
                                                 "activationHeight": 1000}}
    def dup_output_index(e):
        row = e["coverage"]["coreLedger"][0]
        extra = {"script": "76a914" + "22" * 20 + "88ac", "amountDuffs": "1",
                 "outputIndex": 0}
        row["coinbase"]["outputs"] = row["coinbase"]["outputs"] + [extra]
    def minted_doc_empty_chain(e):
        e["slots"][1]["docId"] = e["contractId"]
    def short_signature(e):
        e["checkpoints"][0]["signature"] = "ef"
    def oversized_epoch_id(e):
        # a signed epoch id above the JSON-safe cap cannot byte-match a JSON envelope
        books = [{"contractIdRaw": CONTRACT_RAW, "poolIdRaw": POOLID_RAW,
                  "operatorIdRaw": OPERATOR_RAW, "slotCount": 2, "shares": [(1, 2), (1, 2)]}]
        bindings = [{"proTxHashRaw": POOL_RAW, "slotIndex": 7, "contractIdRaw": CONTRACT_RAW,
                     "poolIdRaw": POOLID_RAW, "activationCoreHeight": 900}]
        out = bytearray()
        out += struct.pack("<I", 2) + v2_domain_tag(CHAIN_IDENTITY, SIGNER_PUB)
        out += struct.pack("<QQQ", (1 << 53), 900, 1601)  # epoch id above 2^53-1
        out += struct.pack("<H", 1) + struct.pack("<H", 1)
        out += CONTRACT_RAW + POOLID_RAW + OPERATOR_RAW + struct.pack("<H", 2)
        out += struct.pack("<QQ", 1, 2) + struct.pack("<QQ", 1, 2)
        out += POOL_RAW + bytes([7]) + CONTRACT_RAW + POOLID_RAW + struct.pack("<Q", 900)
        cp = e["checkpoints"][0]
        cp["signedPayloadBytes"] = bytes(out).hex()
        cp["checkpointId"] = hashlib.sha256(bytes(out)).hexdigest()
        e["adoptedEpochPins"][0]["checkpointId"] = cp["checkpointId"]
    def extra_unmatched_pin(e):
        e["adoptedEpochPins"] = e["adoptedEpochPins"] + [{"epochId": 9, "checkpointId": "00" * 32}]
    def coinbase_outputs_out_of_order(e):
        row = e["coverage"]["coreLedger"][0]
        a = {"script": "76a914" + "11" * 20 + "88ac", "amountDuffs": "100000000", "outputIndex": 0}
        b = {"script": "76a914" + "44" * 20 + "88ac", "amountDuffs": "1", "outputIndex": 1}
        row["coinbase"]["outputs"] = [b, a]   # descending index -> rejected
    def duplicate_anomaly(e):
        e["coverage"]["listWalk"][0]["targetNodeState"] = "PRESENT_INVALID"
        e["coverage"]["listWalk"][0]["targetNodeEntry"] = "ee" * 91
        rec = e["rewards"][0]
        rec["recognition"] = {"status": "UNRECOGNIZED", "bindingRef": 0}
        rec["entitlement"]["classification"] = "ANOMALY"
        rec["entitlement"]["eligibility"]["state"] = "PRESENT_INVALID"
        hp = "/coverage/coreLedger/0"
        ep = "/rewards/0/entitlement/eligibility"
        one = {"code": "SCHEDULE_LIST_DISAGREEMENT", "evidenceRefs": sorted([hp, ep])}
        rec["entitlement"]["anomalies"] = [one, dict(one)]
        rec["conservation"] = {"kind": "unavailable"}
        rec["slotFanout"] = {"kind": "none", "reason": "ANOMALY"}
    def anomaly_refs_unsupported(e):
        # a valid SCHEDULE_LIST_DISAGREEMENT whose refs resolve but do not cite both sides
        e["coverage"]["listWalk"][0]["targetNodeState"] = "PRESENT_INVALID"
        e["coverage"]["listWalk"][0]["targetNodeEntry"] = "ee" * 91
        rec = e["rewards"][0]
        rec["recognition"] = {"status": "UNRECOGNIZED", "bindingRef": 0}
        rec["entitlement"]["classification"] = "ANOMALY"
        rec["entitlement"]["eligibility"]["state"] = "PRESENT_INVALID"
        rec["entitlement"]["anomalies"] = [
            {"code": "SCHEDULE_LIST_DISAGREEMENT", "evidenceRefs": ["/network", "/slots"]}]
        rec["conservation"] = {"kind": "unavailable"}
        rec["slotFanout"] = {"kind": "none", "reason": "ANOMALY"}
    def coinbase_unexplained_pollution(e):
        # an extraneous output at the payee script forced into matchedOutputs
        extra = {"script": "76a914" + "11" * 20 + "88ac", "amountDuffs": "7",
                 "outputIndex": 1}
        row = e["coverage"]["coreLedger"][0]
        row["coinbase"]["outputs"] = row["coinbase"]["outputs"] + [extra]
        ce = e["rewards"][0]["entitlement"]["coinbaseEvidence"]
        ce["matchedOutputs"] = ce["matchedOutputs"] + [extra]
    def owed_with_none_fanout(e):
        e["rewards"][0]["conservation"] = {"kind": "not-applicable"}
        e["rewards"][0]["slotFanout"] = {"kind": "none", "reason": "UNRECOGNIZED"}
    def inverted_epoch_window(e):
        books = [{"contractIdRaw": CONTRACT_RAW, "poolIdRaw": POOLID_RAW,
                  "operatorIdRaw": OPERATOR_RAW, "slotCount": 2, "shares": [(1, 2), (1, 2)]}]
        bindings = [
            {"proTxHashRaw": POOL_RAW, "slotIndex": 0, "contractIdRaw": CONTRACT_RAW,
             "poolIdRaw": POOLID_RAW, "activationCoreHeight": 900}]
        # effective 900 >= endExclusive 900 -> decoder rejects the inverted window
        out = bytearray()
        out += struct.pack("<I", 2) + v2_domain_tag(CHAIN_IDENTITY, SIGNER_PUB)
        out += struct.pack("<QQQ", 1, 900, 900) + struct.pack("<H", 1) + struct.pack("<H", 1)
        out += CONTRACT_RAW + POOLID_RAW + OPERATOR_RAW + struct.pack("<H", 2)
        out += struct.pack("<QQ", 1, 2) + struct.pack("<QQ", 1, 2)
        out += POOL_RAW + bytes([0]) + CONTRACT_RAW + POOLID_RAW + struct.pack("<Q", 900)
        cp = e["checkpoints"][0]
        cp["signedPayloadBytes"] = bytes(out).hex()
        cp["checkpointId"] = hashlib.sha256(bytes(out)).hexdigest()
        e["adoptedEpochPins"][0]["checkpointId"] = cp["checkpointId"]
    def decoder_runtime_freeform(e):
        # MAJOR 2 (revision 16): the execution descriptor is a CLOSED vocabulary now, so a
        # free-form runtime spelling ("Node.js 20 LTS" for "node-20-lts") cannot serialize;
        # two producers can no longer present one artifactDigest with divergent descriptors.
        e["decoderLineage"][0]["runtime"] = "Node.js 20 LTS"
    def network_not_in_registry(e):
        # MAJOR 3 (revision 16): coreNetwork is a closed registry; a free relabel of the
        # same chain ("same-chain-different-label") is not a member.
        e["network"]["coreNetwork"] = "same-chain-different-label"
        e["basePackage"]["coreNetwork"] = "same-chain-different-label"
    def network_public_label_wrong_genesis(e):
        # MAJOR 3 (revision 16): a public-network label ("mainnet") requires its canonical
        # Core genesis hash; the vector's base genesis is not it, so the name binding
        # rejects (the devnet-only field is dropped so the schema's mainnet branch admits
        # the shape and the SEMANTIC layer does the rejecting).
        e["network"]["coreNetwork"] = "mainnet"
        e["basePackage"]["coreNetwork"] = "mainnet"
        del e["network"]["coreDevnetGenesisBlockHash"]
    def sml_entries_out_of_order(e):
        # MAJOR 4 (revision 16): smlEntries must be in ascending canonical (entry-bytes)
        # order; a descending pair is rejected.
        e["basePackage"]["smlEntries"] = ["fb" * 91, "fa" * 91]
    def checkpoint_copied_across_devnets(e):
        # a soundness-review finding (revision 17), the flagship misbinding negative: the SAME signed
        # checkpoints presented under a DIFFERENT devnet identity (another height-one
        # devnet genesis over the same shared base). The re-derived chain identity
        # changes, so the domain tag no longer matches the signed payloads: a checkpoint
        # copied from devnet A to devnet B is rejected even under a reused authority key.
        e["network"]["coreDevnetGenesisBlockHash"] = "33" * 32
    def network_regtest_relabel(e):
        # a soundness-review finding (revision 17): relabel the devnet envelope as regtest (dropping the
        # devnet-only field so the schema admits it). The genesis is the legitimately
        # shared base, but the re-derived identity (network code, no height-one hash)
        # differs from the signed payloads', so the domain tag rejects the relabel.
        e["network"]["coreNetwork"] = "regtest"
        e["basePackage"]["coreNetwork"] = "regtest"
        del e["network"]["coreDevnetGenesisBlockHash"]
    def network_regtest_label_wrong_genesis(e):
        # a soundness-review finding (revision 17): a regtest label with a non-base height-zero genesis
        # (regtest's genesis is FIXED at the shared base in Dash Core).
        e["network"]["coreNetwork"] = "regtest"
        e["basePackage"]["coreNetwork"] = "regtest"
        e["network"]["coreGenesisBlockHash"] = "11" * 32
        del e["network"]["coreDevnetGenesisBlockHash"]
    def devnet_missing_devnet_genesis(e):
        # a soundness-review finding (revision 17): a devnet without its height-one devnet genesis cannot
        # serialize (the schema's devnet branch requires the field).
        del e["network"]["coreDevnetGenesisBlockHash"]
    def devnet_genesis_equals_base(e):
        # a soundness-review finding (revision 17): the height-one devnet genesis must be distinct from the
        # shared height-zero base (equality would collapse the identity back to the base).
        e["network"]["coreDevnetGenesisBlockHash"] = e["network"]["coreGenesisBlockHash"]
    def non_devnet_has_devnet_genesis(e):
        # a soundness-review finding (revision 17): the devnet-only field is forbidden for every other
        # network (schema oneOf).
        e["network"]["coreNetwork"] = "regtest"
        e["basePackage"]["coreNetwork"] = "regtest"
    def unused_decoder_lineage_entry(e):
        # a soundness-review finding (revision 17): an entry beyond the platform audit interval is never
        # selected by any row; retaining it is non-canonical.
        e["decoderLineage"] = e["decoderLineage"] + [{
            "fromHeight": e["platformAuditRange"]["toHeight"] + 100,
            "decoderId": "decoder-sha256-" + ("ee" * 32)[:16],
            "artifactDigest": "ee" * 32, "artifactRef": "cas:sha256:" + "ee" * 32,
            "runtime": "oci-image-v1", "environmentDigest": "sha256:" + "ee" * 32,
            "executionProfile": "tegara-decoder-v1", "entryPoint": "decode.mjs",
            "inputFormat": "raw-committed-tx-bytes", "platformProtocolVersion": 9}]
    def decoder_lineage_early_fromheight(e):
        # a soundness-review finding (revision 17): the retained lineage must start EXACTLY at the platform
        # audit fromHeight; an earlier start retains unused prefix history.
        e["decoderLineage"][0]["fromHeight"] = 0
    def decoder_id_not_derived(e):
        # a soundness-review finding (revision 17): a grammar-valid id whose 16 hex are not the digest's.
        e["decoderLineage"][0]["decoderId"] = "decoder-sha256-" + ("ee" * 32)[:16]
        for r in e["coverage"]["platformLedger"]:
            r["decoderId"] = "decoder-sha256-" + ("ee" * 32)[:16]
    def artifact_ref_digest_mismatch(e):
        # a soundness-review finding (revision 17): a grammar-valid content-addressed ref embedding a
        # DIFFERENT digest points at a different bundle.
        e["decoderLineage"][0]["artifactRef"] = "cas:sha256:" + "ee" * 32
    def environment_digest_bad_grammar(e):
        # a soundness-review finding (revision 17): the environment digest grammar is closed (schema).
        e["decoderLineage"][0]["environmentDigest"] = "sha256:UPPER"
    def execution_profile_not_in_enum(e):
        # a soundness-review finding (revision 17): the execution profile is a closed enum (schema).
        e["decoderLineage"][0]["executionProfile"] = "tegara-decoder-v9"
    def artifact_ref_bad_grammar(e):
        # a soundness-review finding (revision 17): the artifactRef grammar is closed (schema).
        e["decoderLineage"][0]["artifactRef"] = "https://example.com/bundle.tar"
    def platform_txs_out_of_order(e):
        # a soundness-review finding (revision 18): a WRONG SINGLETON index (1 on the only transaction) breaks
        # the contiguous-0..n-1 rule. The genuine two-transaction permutation is the
        # separate platform-two-txs-swapped negative (revision 19); a coherently
        # RENUMBERED permutation passes offline BY DESIGN and is caught by the
        # proof-position equality at runtime (a soundness-review finding).
        e["coverage"]["platformLedger"][0]["txs"][0]["txIndex"] = 1
    def redundant_lineage_split(e):
        # a soundness-review finding (revision 18): the same decoder history serialized as a redundant
        # two-entry split (adjacent entries identical in every bundle-identity field).
        first = e["decoderLineage"][0]
        second = dict(first)
        second["fromHeight"] = 2
        e["decoderLineage"] = [first, second]
    def core_ledgers_same_height_disagree(e):
        # a soundness-review finding (revision 20): the two Core-side ledgers must agree at a shared height.
        # Both the row hash AND its reward copy move together so the join check (not the
        # rewardCoreBlockHash equality) is what rejects.
        e["coverage"]["coreLedger"][0]["blockHash"] = "11" * 32
        e["rewards"][0]["rewardCoreBlockHash"] = "11" * 32
    def creation_not_by_operator(e):
        # a soundness-review finding (revision 20): slot 0's creation minted by a non-operator identity, with
        # the later purchase's seller continuity, both decisions' economics, and the
        # snapshot owner all kept coherent, so ONLY the operator rule rejects.
        chain = e["slots"][0]["ownershipChain"]
        creation, purchase = chain[0], chain[1]
        creation["seller"] = BUYER; creation["buyer"] = BUYER
        purchase["seller"] = BUYER
        for r in e["coverage"]["platformLedger"]:
            for t in r["txs"]:
                if t["kind"] != "decoded-batch":
                    continue
                for d in t["decisions"]:
                    if d["kind"] != "retained-position":
                        continue
                    if d["position"] == creation["position"]:
                        d["economics"] = {"seller": BUYER, "buyer": BUYER, "price": "0"}
                    elif d["position"] == purchase["position"]:
                        d["economics"] = dict(d["economics"], seller=BUYER)
    def first_appearance_no_addition(e):
        # a soundness-review finding (revision 22, ISOLATED per round 8): built FROM the conforming
        # first-appearance acceptance with a VALID transaction identity, the P row
        # flipped to absent, and the journal kept coherent (the appearance moves to
        # 1001), so the P-row addition rule is exactly what rejects.
        e.clear()
        e.update(copy.deepcopy(build_first_appearance()))
        e["coverage"]["listWalk"][0]["targetNodeState"] = "ABSENT"
        e["coverage"]["listWalk"][0]["targetNodeEntry"] = None
        e["lifecycle"]["transitions"] = [{"height": 1001, "from": "ABSENT",
                                          "to": "PRESENT_VALID"}]
    def observed_through_height_beyond_chainlock(e):
        # an independent review (revision 23): the obs <= chainlock guard exists; this is its
        # regression-coverage vector so a future edit cannot drop it silently.
        e["lifecycle"]["observedThroughHeight"] = e["validatedChainLock"]["height"] + 1
    def terminal_during_suspension_mismatch(e):
        # an independent review (revision 23): a removal WHILE SUSPENDED whose journal labels the close
        # RANGE_END instead of TERMINATED. The walk-derived reconstruction emits
        # TERMINATED with endHeight = terminalHeight, and the serialized journal must
        # EQUAL it, so the mislabel rejects on the equality (this vector documents the
        # already-enforced composition; the reward records are never reached).
        e["coverage"]["listWalk"][0]["targetNodeState"] = "PRESENT_INVALID"
        e["coverage"]["listWalk"][1]["targetNodeState"] = "ABSENT"
        e["coverage"]["listWalk"][1]["targetNodeEntry"] = None
        e["lifecycle"] = {"terminalHeight": 1001, "observedThroughHeight": 1001,
                          "suspensions": [{"start": {"kind": "observed",
                                                     "banHeight": 1000},
                                           "endHeight": 1001,
                                           "endReason": "RANGE_END"},],
                          "transitions": [{"height": 1000, "from": "PRESENT_VALID",
                                           "to": "PRESENT_INVALID"},
                                          {"height": 1001, "from": "PRESENT_INVALID",
                                           "to": "ABSENT"}]}
    def range_local_absent_unknown_not_terminal(e):
        # an independent review (revision 23): under a range-local base whose initial state is an
        # unknown-origin ABSENCE, any non-UNKNOWN entitlement claim must fail closed.
        # The retained OWED claim (kept from the positive) rejects on re-derivation;
        # the journal is kept coherent so the classification rule is what fires.
        e["basePackage"]["nodeStateAtBase"] = {"kind": "absent"}
        for r in e["coverage"]["listWalk"]:
            r["targetNodeState"] = "ABSENT"
            r["targetNodeEntry"] = None
        e["lifecycle"]["transitions"] = []
    def pre_dml_range_start_at_activation(e):
        # the no-access review variant (revision 23): a pre-DML audit starting AT the
        # activation height (the first height with a list root at H-1 is
        # activation+1, so fromHeight == activationHeight must reject).
        e["basePackage"] = {"kind": "pre-dml", "coreNetwork": "devnet",
                            "baseBlock": {"height": 999, "blockHash": H32B},
                            "chainlockWitness": EVBYTES, "ancestryProof": EVBYTES,
                            "activationParams": {"deploymentName": "dip3",
                                                 "activationHeight": 1000}}
    def verifier_bundle_digest_bad_grammar(e):
        # a soundness-review finding final (revision 26): the verifier-bundle digest grammar is closed.
        e["verifierBundleDigest"] = "sha256:NOPE"
    def different_script_remainder_omitted(e):
        # Revision 25 (complete remainder): an unused DIFFERENT-SCRIPT output (the
        # operator's, say) must appear in unexplainedOutputs; omitting it cannot
        # serialize (before this, the rule filtered to owner-expected scripts and two
        # implementations could disagree on the remainder).
        extra = {"script": "76a914" + "33" * 20 + "88ac", "amountDuffs": "12345",
                 "outputIndex": 1}
        row = e["coverage"]["coreLedger"][0]
        row["coinbase"]["outputs"] = row["coinbase"]["outputs"] + [extra]
    def proof_codec_profile_not_in_enum(e):
        # a soundness-review finding (revision 23): the proof-codec profile is a closed enum (schema).
        e["proofCodecProfile"] = "tegara-proof-codecs-v9"
    def lone_surrogate_string(e):
        # MAJ-3 (revision 23): a lone UTF-16 surrogate (Python's JSON parser admits the
        # "\ud800" escape) is outside the RFC 8785 domain and previously crashed
        # canonicalization AFTER acceptance; the semantic string walk now rejects it.
        e["network"]["platformChainId"] = "\ud800chain"
    def innercount_above_cap(e):
        # MAJ-3 (revision 22): innerCount above the JSON-safe 2^53-1 cap is a SCHEMA
        # rejection (before this, the checker would try to materialize the range).
        e["coverage"]["platformLedger"][0]["txs"][0]["innerCount"] = (1 << 53)
    def committed_txcount_above_cap(e):
        # MAJ-3 (revision 22): committedTxCount above the cap is a SCHEMA rejection.
        e["coverage"]["platformLedger"][2]["committedTxCount"] = (1 << 53)
    def deployment_name_not_canonical(e):
        # MIN-4 (revision 20): the pre-DML deployment name is the closed constant "dip3";
        # an equivalent spelling cannot serialize (schema).
        e["basePackage"] = {"kind": "pre-dml", "coreNetwork": "devnet",
                            "baseBlock": {"height": 999, "blockHash": H32B},
                            "chainlockWitness": EVBYTES, "ancestryProof": EVBYTES,
                            "activationParams": {"deploymentName": "DIP-0003",
                                                 "activationHeight": 1000}}
    def contract_genesis_after_first_activity(e):
        # a soundness-review finding (revision 19): a false-high claimed contract creation height (the
        # positive's creation position sits at platform height 1, so a claimed creation
        # at 2 is proven false by the retained evidence itself).
        e["platformAuditRange"]["lowerBoundJustification"]["contractCreationHeight"] = 2
    def platform_two_txs_swapped(e):
        # a soundness-review finding (revision 19): two transaction dispositions presented in swapped order
        # (txIndex [1, 0]) cannot serialize; the proof-position equality that binds each
        # index to the committed leaf is the runtime half of the same rule.
        row = e["coverage"]["platformLedger"][2]
        t0 = {"kind": "non-document-tx", "txIndex": 0,
              "committedHash": sha256_hex("aa"), "rawBytes": "aa",
              "inclusionProof": EVBYTES}
        t1 = {"kind": "non-document-tx", "txIndex": 1,
              "committedHash": sha256_hex("bb"), "rawBytes": "bb",
              "inclusionProof": EVBYTES}
        row["txs"] = [t1, t0]
        row["committedTxCount"] = 2
    def chain_identity_reversed_hash_bytes(e):
        # a soundness-review finding closure (revision 18, second-reviewer item): the byte convention is
        # RPC-display hex decoded left to right with NO reversal. A payload whose domain
        # tag was derived from the REVERSED genesis bytes must fail the decode.
        wrong_identity = core_chain_identity_hash("devnet", GENESIS[::-1],
                                                  DEVNET_GENESIS_H1)
        books = [{"contractIdRaw": CONTRACT_RAW, "poolIdRaw": POOLID_RAW,
                  "operatorIdRaw": OPERATOR_RAW, "slotCount": 2, "shares": [(1, 2), (1, 2)]}]
        bindings = [{"proTxHashRaw": POOL_RAW, "slotIndex": 7, "contractIdRaw": CONTRACT_RAW,
                     "poolIdRaw": POOLID_RAW, "activationCoreHeight": 900}]
        p = build_v2_payload(1, 900, 1601, books, bindings, wrong_identity, SIGNER_PUB)
        cp = e["checkpoints"][0]
        cp["signedPayloadBytes"] = p.hex()
        cp["checkpointId"] = hashlib.sha256(p).hexdigest()
        e["adoptedEpochPins"][0]["checkpointId"] = cp["checkpointId"]
    return [
        m("extra-top-level-field", "schema", lambda e: e.update({"extra": True})),
        m("price-as-json-number", "schema", set_price_number),
        m("uppercase-hex-hash", "schema",
          lambda e: e.update({"poolProTxHash": pos["poolProTxHash"].upper()})),
        m("legacy-suspension-shape", "schema", legacy_susp),
        m("gross-not-derived-from-payout", "semantic", gross_not_derived),
        m("schedule-claims-authenticated", "semantic", sched_auth),
        m("aggregate-overclaimed", "semantic", aggregate_overclaim),
        m("largest-remainder-misallocation", "semantic", remainder_60_40),
        m("conservation-sum-mismatch", "semantic", sum_mismatch),
        m("epoch-range-payload-mismatch", "semantic", epoch_payload_mismatch),
        m("extracted-binding-payload-mismatch", "semantic", binding_payload_mismatch),
        m("boundary-terminal-omission", "semantic", boundary_omitted),
        m("dropped-intermediate-diff", "semantic", drop_diff),
        m("rewards-out-of-order", "semantic", swap_rewards),
        m("anchor-regression", "semantic", anchor_reg),
        m("committed-hash-mismatch", "semantic", hash_flip),
        m("classification-not-derivable", "semantic", class_not_derivable),
        m("missing-inner-decision", "semantic", missing_inner),
        m("invalid-decoder-selection", "semantic", bad_decoder),
        m("transition-hash-wrong-position", "semantic", wrong_position_hash),
        m("closing-block-not-first", "semantic", late_closing),
        m("first-appearance-txid-mismatch", "semantic", fa_txid_mismatch),
        m("incorrect-recognition-status", "semantic", wrong_recognition),
        m("pre-base-suspension-omission", "semantic", pre_base_omitted),
        m("omitted-chain-hop", "semantic", omitted_chain_hop),
        m("coinbase-match-not-derived", "semantic", coinbase_match_not_derived),
        m("auth-dependency-violation", "semantic", auth_dependency_violation),
        m("entry-state-mismatch", "semantic", entry_state_mismatch),
        m("unequal-shares", "semantic", unequal_shares),
        m("epoch-pin-mismatch", "semantic", epoch_pin_mismatch),
        m("authority-mismatch", "semantic", authority_mismatch),
        m("economics-mismatch", "semantic", economics_mismatch),
        m("coinbase-unavailable-not-unknown", "semantic", coinbase_unavailable_not_unknown),
        m("truncated-payload", "semantic", truncated_payload),
        m("pre-dml-activation-mismatch", "semantic", pre_dml_activation_mismatch),
        m("coinbase-unexplained-pollution", "semantic", coinbase_unexplained_pollution),
        m("anomaly-refs-not-supporting", "semantic", anomaly_refs_unsupported),
        m("duplicate-coinbase-output-index", "semantic", dup_output_index),
        m("minted-doc-empty-chain", "semantic", minted_doc_empty_chain),
        m("short-signature", "schema", short_signature),
        m("oversized-epoch-id", "semantic", oversized_epoch_id),
        m("duplicate-anomaly", "semantic", duplicate_anomaly),
        m("extra-unmatched-pin", "semantic", extra_unmatched_pin),
        m("coinbase-outputs-out-of-order", "semantic", coinbase_outputs_out_of_order),
        m("owed-with-none-fanout", "semantic", owed_with_none_fanout),
        m("inverted-epoch-window", "semantic", inverted_epoch_window),
        m("spurious-anomaly-on-owed", "semantic", spurious_anomaly_on_owed),
        m("alt-schedule-source", "schema", alt_schedule_source),
        m("network-mismatch", "semantic", network_mismatch),
        m("not-pool-nonempty-coinbase", "semantic", not_pool_nonempty_coinbase),
        m("decoder-runtime-freeform", "schema", decoder_runtime_freeform),
        m("network-not-in-registry", "schema", network_not_in_registry),
        m("network-public-label-wrong-genesis", "semantic", network_public_label_wrong_genesis),
        m("sml-entries-out-of-order", "semantic", sml_entries_out_of_order),
        m("checkpoint-copied-across-devnets", "semantic", checkpoint_copied_across_devnets),
        m("network-regtest-relabel", "semantic", network_regtest_relabel),
        m("network-regtest-label-wrong-genesis", "semantic", network_regtest_label_wrong_genesis),
        m("devnet-missing-devnet-genesis", "schema", devnet_missing_devnet_genesis),
        m("devnet-genesis-equals-base", "semantic", devnet_genesis_equals_base),
        m("non-devnet-has-devnet-genesis", "schema", non_devnet_has_devnet_genesis),
        m("unused-decoder-lineage-entry", "semantic", unused_decoder_lineage_entry),
        m("decoder-lineage-early-fromheight", "semantic", decoder_lineage_early_fromheight),
        m("decoder-id-not-derived", "semantic", decoder_id_not_derived),
        m("artifact-ref-digest-mismatch", "semantic", artifact_ref_digest_mismatch),
        m("environment-digest-bad-grammar", "schema", environment_digest_bad_grammar),
        m("execution-profile-not-in-enum", "schema", execution_profile_not_in_enum),
        m("artifact-ref-bad-grammar", "schema", artifact_ref_bad_grammar),
        m("platform-transactions-out-of-order", "semantic", platform_txs_out_of_order),
        m("redundant-lineage-split", "semantic", redundant_lineage_split),
        m("chain-identity-reversed-hash-bytes", "semantic", chain_identity_reversed_hash_bytes),
        m("contract-genesis-after-first-activity", "semantic", contract_genesis_after_first_activity),
        m("platform-two-txs-swapped", "semantic", platform_two_txs_swapped),
        m("core-ledgers-same-height-disagree", "semantic", core_ledgers_same_height_disagree),
        m("creation-not-by-operator", "semantic", creation_not_by_operator),
        m("first-appearance-no-addition", "semantic", first_appearance_no_addition),
        m("deployment-name-not-canonical", "schema", deployment_name_not_canonical),
        m("innercount-above-cap", "schema", innercount_above_cap),
        m("committed-txcount-above-cap", "schema", committed_txcount_above_cap),
        m("lone-surrogate-string", "semantic", lone_surrogate_string),
        m("verifier-bundle-digest-bad-grammar", "schema",
          verifier_bundle_digest_bad_grammar),
        m("different-script-remainder-omitted", "semantic",
          different_script_remainder_omitted),
        m("proof-codec-profile-not-in-enum", "schema", proof_codec_profile_not_in_enum),
        m("observed-through-height-beyond-chainlock", "semantic",
          observed_through_height_beyond_chainlock),
        m("terminal-during-suspension-mismatch", "semantic",
          terminal_during_suspension_mismatch),
        m("range-local-absent-unknown-not-terminal", "semantic",
          range_local_absent_unknown_not_terminal),
        m("pre-dml-range-start-at-activation", "semantic",
          pre_dml_range_start_at_activation),
    ]

# ---------------- driver ----------------

SUCCESSOR_POOLID_RAW = bytes([0x77]) * 32
SUCCESSOR_POOLID = b58encode(SUCCESSOR_POOLID_RAW)

def build_successor():
    # CONFIRM-2 acceptance: an audit spanning epoch 1 (our pool bound at L1 slot 7) and
    # epoch 2 (the SAME L1 position re-bound to a different successor pool). Our pool must
    # read UNRECOGNIZED across epoch 2, and the whole envelope must SERIALIZE (before the
    # fix, recognize_at hard-errored and this could not be produced).
    e = copy.deepcopy(build_positive())
    # epoch 1: [900, 1000], our pool bound
    p1 = make_positive_payload(end_exclusive=1001)          # our binding, epoch id 1
    d1 = decode_v2_payload(p1.hex(), CHAIN_IDENTITY, SIGNER_PUB)
    # epoch 2: [1001, 1601], the L1 position re-bound to (CONTRACT, SUCCESSOR_POOLID)
    books2 = [{"contractIdRaw": CONTRACT_RAW, "poolIdRaw": SUCCESSOR_POOLID_RAW,
               "operatorIdRaw": OPERATOR_RAW, "slotCount": 2, "shares": [(1, 2), (1, 2)]}]
    binds2 = [{"proTxHashRaw": POOL_RAW, "slotIndex": 7, "contractIdRaw": CONTRACT_RAW,
               "poolIdRaw": SUCCESSOR_POOLID_RAW, "activationCoreHeight": 1001}]
    p2 = build_v2_payload(2, 1001, 1602, books2, binds2, CHAIN_IDENTITY, SIGNER_PUB)
    d2 = decode_v2_payload(p2.hex(), CHAIN_IDENTITY, SIGNER_PUB)
    cid1 = hashlib.sha256(p1).hexdigest()
    cid2 = hashlib.sha256(p2).hexdigest()
    auth = {"publicKey": SIGNER_PUB.hex()}
    def cp(cid, payload, eid, fro, to, dec):
        return {"checkpointId": cid, "epochId": eid,
                "epochRange": {"fromCoreHeight": fro, "toCoreHeight": to},
                "signedPayloadBytes": payload.hex(), "signature": "ef" * 64,
                "signerPublicKey": SIGNER_PUB.hex(), "algorithm": "ed25519",
                "extractedBinding": {"books": dec["books"], "bindings": dec["bindings"]}}
    e["checkpointAuthority"] = auth
    e["checkpoints"] = [cp(cid1, p1, 1, 900, 1000, d1), cp(cid2, p2, 2, 1001, 1601, d2)]
    e["adoptedEpochPins"] = [{"epochId": 1, "checkpointId": cid1},
                             {"epochId": 2, "checkpointId": cid2}]
    e["coreAuditRange"] = {"fromHeight": 1000, "toHeight": 1002}
    e["lifecycle"]["observedThroughHeight"] = 1002
    # list-walk gains height 1002
    lw = e["coverage"]["listWalk"]
    lw.append({"height": 1002, "blockHash": ("%02x" % (1002 % 251)) * 32,
               "protxDiffRaw": "de" * 40, "cbTxRaw": "fb" * 80,
               "cbTxInclusionProof": "de" * 40, "listRoot": "aa" * 32,
               "targetNodeEntry": "ee" * 91, "targetNodeState": "PRESENT_VALID"})
    # core ledger gains height 1002 (not-pool)
    e["coverage"]["coreLedger"].append(
        {"height": 1002, "blockHash": core_block_hash(1002), "scheduleResult": {"kind": "not-pool"},
         "coinbase": {"kind": "available", "txRaw": "fb" * 80,
                      "inclusionProof": "de" * 40, "outputs": []}})
    # H=1000 stays OWED-recognized under epoch 1; H=1001 becomes UNRECOGNIZED under epoch 2
    e["rewards"][1]["recognition"] = {"status": "UNRECOGNIZED", "bindingRef": None}
    e["rewards"].append(
        {"rewardCoreHeight": 1002, "rewardCoreBlockHash": core_block_hash(1002),
         "recognition": {"status": "UNRECOGNIZED", "bindingRef": None},
         "entitlement": {"kind": "classified", "classification": "NOT_PAYEE",
                         "exclusionReason": {"kind": "none"},
                         "eligibility": {"state": "PRESENT_VALID", "listHeight": 1001,
                                         "listRoot": "ee" * 32},
                         "scheduleSource": "trusted-core-node:masternode-payments",
                         "coinbaseEvidence": {"requiredOutputs": [], "matchedOutputs": [],
                                              "unexplainedOutputs": []},
                         "anomalies": []},
         "conservation": {"kind": "not-applicable"},
         "slotFanout": {"kind": "none", "reason": "NOT_PAYEE"}})
    return e

def build_zero_payout():
    # MF-2 acceptance: the pool IS the scheduled payee but Dash truncated the owner share
    # to zero and OMITTED the output. requiredOutputs=[] must serialize as OWED with gross
    # 0 and an all-zero fanout.
    e = copy.deepcopy(build_positive())
    row = e["coverage"]["coreLedger"][0]
    row["scheduleResult"] = {"kind": "pool-scheduled", "requiredOutputs": []}
    row["coinbase"] = {"kind": "available", "txRaw": "fb" * 80,
                       "inclusionProof": "de" * 40, "outputs": []}
    rec = e["rewards"][0]
    ce = rec["entitlement"]["coinbaseEvidence"]
    ce["requiredOutputs"] = []; ce["matchedOutputs"] = []; ce["unexplainedOutputs"] = []
    rec["conservation"] = {"kind": "calculated", "grossDuffs": "0",
                           "nonSlotComponents": [], "slotAllocationBaseDuffs": "0"}
    for x in rec["slotFanout"]["records"]:
        x["allocatedDuffs"] = "0"
    return e

def build_empty_epoch():
    # MAJ-5 acceptance (revision 18): a ZERO-BOOK, zero-binding epoch is decoder-valid
    # and must also SERIALIZE (the schema previously required at least one book, leaving
    # a legal empty epoch unrepresentable). Epoch gaplessness can force an idle
    # deployment to sign an empty epoch, and the audited pool simply reads UNRECOGNIZED
    # across it. Built as the successor construction with epoch 2 carrying no books.
    e = copy.deepcopy(build_successor())
    p2 = build_v2_payload(2, 1001, 1602, [], [], CHAIN_IDENTITY, SIGNER_PUB)
    d2 = decode_v2_payload(p2.hex(), CHAIN_IDENTITY, SIGNER_PUB)
    cid2 = hashlib.sha256(p2).hexdigest()
    cp2 = e["checkpoints"][1]
    cp2["signedPayloadBytes"] = p2.hex()
    cp2["checkpointId"] = cid2
    cp2["extractedBinding"] = {"books": d2["books"], "bindings": d2["bindings"]}
    e["adoptedEpochPins"][1]["checkpointId"] = cid2
    return e

FA_PROREG_RAW = "99" * 120
FA_POOL_RAW = hashlib.sha256(hashlib.sha256(
    bytes.fromhex(FA_PROREG_RAW)).digest()).digest()      # raw consensus bytes = the txid
FA_POOL_DISPLAY = FA_POOL_RAW[::-1].hex()                 # RPC display form

def build_first_appearance():
    # a soundness-review finding named deliverable (revision 22): a CONFORMING FIRST_APPEARANCE acceptance
    # envelope with a DERIVABLE synthetic pool identity (the pool proTxHash IS the txid of
    # the retained ProRegTx bytes, so the identity gate is exercised for real). The base
    # sits at P-1 = 999 with the node proved absent, the P row (1000) ADDS the node, and
    # the Core audit range starts after P so the reward records stay self-contained.
    e = copy.deepcopy(build_positive())
    e["poolProTxHash"] = FA_POOL_DISPLAY
    books = [{"contractIdRaw": CONTRACT_RAW, "poolIdRaw": POOLID_RAW,
              "operatorIdRaw": OPERATOR_RAW, "slotCount": 2, "shares": [(1, 2), (1, 2)]}]
    bindings = [{"proTxHashRaw": FA_POOL_RAW, "slotIndex": 7,
                 "contractIdRaw": CONTRACT_RAW, "poolIdRaw": POOLID_RAW,
                 "activationCoreHeight": 900}]
    p = build_v2_payload(1, 900, 1601, books, bindings, CHAIN_IDENTITY, SIGNER_PUB)
    d = decode_v2_payload(p.hex(), CHAIN_IDENTITY, SIGNER_PUB)
    cid = hashlib.sha256(p).hexdigest()
    cp = e["checkpoints"][0]
    cp["signedPayloadBytes"] = p.hex()
    cp["checkpointId"] = cid
    cp["extractedBinding"] = {"books": d["books"], "bindings": d["bindings"]}
    e["adoptedEpochPins"][0]["checkpointId"] = cid
    bp = e["basePackage"]
    bp["baseMode"] = "FIRST_APPEARANCE"
    bp["nodeStateAtBase"] = {"kind": "absent"}
    bp["firstAppearance"] = {"pHeight": 1000, "proRegTxRaw": FA_PROREG_RAW,
                             "proRegTxInclusionProof": EVBYTES,
                             "additionDiffRaw": e["coverage"]["listWalk"][0]["protxDiffRaw"]}
    e["coreAuditRange"] = {"fromHeight": 1001, "toHeight": 1001}
    e["coverage"]["coreLedger"] = e["coverage"]["coreLedger"][1:]
    e["rewards"] = e["rewards"][1:]
    e["lifecycle"]["transitions"] = [{"height": 1000, "from": "ABSENT",
                                      "to": "PRESENT_VALID"}]
    return e

def build_owner_vector():
    # a soundness-review finding acceptance: the owner payout is a VECTOR -- a pool with TWO owner-payout
    # outputs (gross = sum) must serialize as OWED with the whole book allocated.
    e = copy.deepcopy(build_positive())
    o1 = {"script": "76a914" + "11" * 20 + "88ac", "amountDuffs": "60000000", "outputIndex": 0}
    o2 = {"script": "76a914" + "55" * 20 + "88ac", "amountDuffs": "40000000", "outputIndex": 1}
    row = e["coverage"]["coreLedger"][0]
    row["scheduleResult"] = {"kind": "pool-scheduled",
                             "requiredOutputs": [{"script": o1["script"], "amountDuffs": o1["amountDuffs"]},
                                                 {"script": o2["script"], "amountDuffs": o2["amountDuffs"]}]}
    row["coinbase"] = {"kind": "available", "txRaw": "fb" * 80,
                       "inclusionProof": "de" * 40, "outputs": [o1, o2]}
    ce = e["rewards"][0]["entitlement"]["coinbaseEvidence"]
    ce["requiredOutputs"] = [{"script": o1["script"], "amountDuffs": o1["amountDuffs"]},
                             {"script": o2["script"], "amountDuffs": o2["amountDuffs"]}]
    ce["matchedOutputs"] = [o1, o2]
    ce["unexplainedOutputs"] = []
    # gross 100M unchanged; slots still 50M/50M
    return e

def main():
    import jsonschema
    schema = json.load(open(SCHEMA_PATH))
    validator = jsonschema.Draft202012Validator(schema)
    pos = build_positive()

    # a soundness-review finding (revision 17): the execution-profile release document is present, names the
    # enum value the schema closes over, and its hash matches the manifest pin.
    profile_bytes = open(PROFILE_PATH, "rb").read()
    profile_hash = hashlib.sha256(profile_bytes).hexdigest()
    if json.loads(profile_bytes)["executionProfile"] != "tegara-decoder-v1":
        print("FAIL: execution-profile document does not name tegara-decoder-v1")
        return 1
    codec_bytes = open(CODEC_PROFILE_PATH, "rb").read()
    codec_hash = hashlib.sha256(codec_bytes).hexdigest()
    if json.loads(codec_bytes)["proofCodecProfile"] != "tegara-proof-codecs-v1":
        print("FAIL: proof-codec document does not name tegara-proof-codecs-v1")
        return 1

    if "--write" in sys.argv:
        os.makedirs(VECTOR_DIR, exist_ok=True)
        with open(POSITIVE_PATH, "w") as f:
            json.dump(pos, f, indent=1, sort_keys=True); f.write("\n")

    on_disk = load_envelope_bytes(open(POSITIVE_PATH, "rb").read())
    if on_disk != pos:
        print("FAIL: vectors/positive_minimal.json does not match the builder (rerun --write)")
        return 1

    # MAJ-3 (revision 23): the RAW ingestion guard rejects conflicting duplicate member
    # names (a dict-level mutation cannot express this, so it is asserted here as a raw
    # case rather than in the negatives table).
    dup_raw = b'{"envelopeVersion": "1", "envelopeVersion": "2"}'
    try:
        load_envelope_bytes(dup_raw)
        print("FAIL: raw duplicate-member envelope was not rejected at ingestion")
        return 1
    except ValueError:
        pass
    print("raw duplicate-member ingestion: REJECTED as required (MAJ-3)")

    errs = list(validator.iter_errors(pos))
    if errs:
        print("FAIL: positive vector rejected by the schema:")
        for e in errs[:5]:
            print("  -", "/".join(map(str, e.path)), e.message)
        return 1
    try:
        check_semantics(pos)
    except SemanticError as e:
        print("FAIL: positive vector rejected by the semantic layer:", e)
        return 1
    # CONFIRM-2 acceptance: the successor-pool envelope MUST serialize (schema + semantic).
    succ = build_successor()
    serrs = list(validator.iter_errors(succ))
    if serrs:
        print("FAIL: successor-pool acceptance envelope rejected by the schema:")
        for e in serrs[:5]:
            print("  -", "/".join(map(str, e.path)), e.message)
        return 1
    try:
        check_semantics(succ)
    except SemanticError as e:
        print("FAIL: successor-pool acceptance envelope rejected by the semantic layer:", e)
        return 1
    print("successor-pool acceptance: schema PASS, semantic PASS (CONFIRM-2)")

    zp = build_zero_payout()
    zerrs = list(validator.iter_errors(zp))
    if zerrs:
        print("FAIL: zero-payout acceptance envelope rejected by the schema:")
        for e in zerrs[:5]:
            print("  -", "/".join(map(str, e.path)), e.message)
        return 1
    try:
        check_semantics(zp)
    except SemanticError as e:
        print("FAIL: zero-payout acceptance envelope rejected by the semantic layer:", e)
        return 1
    print("zero-payout acceptance: schema PASS, semantic PASS (MF-2)")

    fa = build_first_appearance()
    faerrs = list(validator.iter_errors(fa))
    if faerrs:
        print("FAIL: first-appearance acceptance envelope rejected by the schema:")
        for e in faerrs[:5]:
            print("  -", "/".join(map(str, e.path)), e.message)
        return 1
    try:
        check_semantics(fa)
    except SemanticError as e:
        print("FAIL: first-appearance acceptance envelope rejected by the semantic layer:", e)
        return 1
    print("first-appearance acceptance: schema PASS, semantic PASS (a soundness-review finding)")

    ee = build_empty_epoch()
    eerrs = list(validator.iter_errors(ee))
    if eerrs:
        print("FAIL: empty-epoch acceptance envelope rejected by the schema:")
        for e in eerrs[:5]:
            print("  -", "/".join(map(str, e.path)), e.message)
        return 1
    try:
        check_semantics(ee)
    except SemanticError as e:
        print("FAIL: empty-epoch acceptance envelope rejected by the semantic layer:", e)
        return 1
    print("empty-epoch acceptance: schema PASS, semantic PASS (MAJ-5)")

    ov = build_owner_vector()
    overrs = list(validator.iter_errors(ov))
    if overrs:
        print("FAIL: owner-vector acceptance envelope rejected by the schema:")
        for e in overrs[:5]:
            print("  -", "/".join(map(str, e.path)), e.message)
        return 1
    try:
        check_semantics(ov)
    except SemanticError as e:
        print("FAIL: owner-vector acceptance envelope rejected by the semantic layer:", e)
        return 1
    print("owner-vector acceptance: schema PASS, semantic PASS (a soundness-review finding)")

    canon = canonical_bytes(pos)
    canon_hash = hashlib.sha256(canon).hexdigest()
    print("positive vector: schema PASS, semantic PASS")
    print("canonical bytes: %d, sha256 %s" % (len(canon), canon_hash))

    results = []
    ok = True
    for name, layer, env in negatives(pos):
        schema_rejects = bool(list(validator.iter_errors(env)))
        sem_rejects = False
        if not schema_rejects:
            try:
                check_semantics(env)
            except SemanticError:
                sem_rejects = True
        rejected = schema_rejects or sem_rejects
        actual = "schema" if schema_rejects else ("semantic" if sem_rejects else "ACCEPTED")
        good = rejected and actual == layer
        ok = ok and good
        results.append({"name": name, "expectedLayer": layer, "actualLayer": actual,
                        "rejected": rejected})
        print("%-38s expected %-8s actual %-8s %s" %
              (name, layer, actual, "ok" if good else "WRONG"))

    if "--write" in sys.argv:
        with open(MANIFEST_PATH, "w") as f:
            json.dump({"positive": {"file": "positive_minimal.json",
                                    "canonicalSha256": canon_hash,
                                    "canonicalByteLength": len(canon)},
                       "executionProfiles": {
                           "tegara-decoder-v1": {
                               "file": "../execution-profiles/tegara-decoder-v1.json",
                               "sha256": profile_hash}},
                       "proofCodecProfiles": {
                           "tegara-proof-codecs-v1": {
                               "file": "../proof-codecs/tegara-proof-codecs-v1.json",
                               "sha256": codec_hash}},
                       "negatives": results}, f, indent=1, sort_keys=True); f.write("\n")
        print("wrote", POSITIVE_PATH, "and", MANIFEST_PATH)
    else:
        # MIN-7 (revision 18): verify mode compares the WHOLE manifest against the
        # computed state, not only the profile pin, so a stale digest, length, negative
        # name, or layer tag can never coexist with a passing run.
        man = json.load(open(MANIFEST_PATH))
        prof = man.get("executionProfiles", {}).get("tegara-decoder-v1", {})
        if prof.get("sha256") != profile_hash:
            print("FAIL: execution-profile document does not match its manifest pin")
            ok = False
        if prof.get("file") != "../execution-profiles/tegara-decoder-v1.json":
            print("FAIL: manifest profile file path is not the shipped location")
            ok = False
        cprof = man.get("proofCodecProfiles", {}).get("tegara-proof-codecs-v1", {})
        if cprof.get("sha256") != codec_hash or \
                cprof.get("file") != "../proof-codecs/tegara-proof-codecs-v1.json":
            print("FAIL: proof-codec document does not match its manifest pin")
            ok = False
        if (man.get("positive", {}).get("canonicalSha256") != canon_hash or
                man.get("positive", {}).get("canonicalByteLength") != len(canon)):
            print("FAIL: manifest canonical digest/length do not match the computed form")
            ok = False
        if man.get("negatives") != results:
            print("FAIL: manifest negative list does not match the computed results")
            ok = False

    print("ALL VECTOR CHECKS PASS" if ok else "VECTOR CHECKS FAILED")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
