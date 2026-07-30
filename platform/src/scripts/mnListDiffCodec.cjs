/**
 * mnListDiffCodec - a parser for the P2P `mnlistdiff` payload, written for the walk.
 *
 * WHY OURS. The audit format requires `coverage.listWalk[].protxDiffRaw` in the P2P
 * serialization (`dash-p2p-mnlistdiff-v1`), and @dashevo/dashcore-lib cannot parse that form: on
 * a real 3645-byte capture it misaligns rather than refusing, because each ENTRY carries its own
 * version on the wire while the library gates entry fields on the DIFF's version (a soundness review). This
 * module models the version rules the way the source does.
 *
 * THE LAYOUT IS PROTOCOL-VERSION DEPENDENT, which is the whole difficulty and the subject of
 * a soundness-review finding. Every branch below cites the source it comes from, at merged commit 8c9f166a3:
 *
 *   src/evo/smldiff.h:65-79      the diff frame. nVersion FIRST at >= 70229
 *                                (MNLISTDIFF_VERSION_ORDER), after cbTx at 70225..70228, absent
 *                                below that; quorumsCLSigs appended at >= 70230.
 *   src/evo/simplifiedmns.h:70-95  the entry. Its OWN nVersion is on the wire at >= 70228
 *                                (SMNLE_VERSIONED_PROTO_VERSION); the address form and the BLS
 *                                key scheme follow the ENTRY's version, not the diff's; nType is
 *                                present once the entry reaches ProTxVersion::BasicBLS.
 *   src/evo/providertx.h:30-37   ProTxVersion: LegacyBLS 1, BasicBLS 2, ExtAddr 3, MultiPayout 4.
 *   src/evo/netinfo.h:465-497    the address wrapper: ExtNetInfo at entry version >= ExtAddr,
 *                                otherwise MnNetInfo, which is one CService.
 *
 * SUPPORTED RANGE. Protocol 70230 through 70240 inclusive, which is the range the v2 codec pin
 * will name (docs/PROOF_CODEC_V2_QUEUE.md). Outside it this module REFUSES rather than guessing,
 * because guessing a layout is how the library produced a misaligned parse instead of an error.
 *
 * BYTE-EXACT BY REQUIREMENT. Each entry records the exact slice it was parsed from, because the
 * walk's list-root check (registry verifierChecks item 2) hashes entries, and a parser that
 * cannot reproduce the bytes it read cannot compute a root that matches consensus.
 *
 * SCOPE: the WHOLE frame. The parse consumes every byte and REFUSES if any remain, because a
 * parser that stops early and reports success is how a caller ends up believing a section was
 * checked when nobody read it.
 */
"use strict";

const crypto = require("crypto");

function fail(msg) {
  throw new Error(`mnListDiffCodec: ${msg}`);
}

const x11 = require("@dashevo/x11-hash-js");

const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const dsha256 = (b) => sha256(sha256(b));

/**
 * A DASH BLOCK HASH IS X11, NOT SHA-256d [8c9f166a3:src/primitives/block.h, CBlockHeader::GetHash].
 * Transaction ids and merkle nodes are sha256d, and a block hash is not, which is easy to miss
 * because everything around it is. Found the hard way: the retained header of the captured block
 * hashes under sha256d to a value that is not its block hash, and under X11 to exactly it.
 * @dashevo/x11-hash-js is already in the tree through the `dash` dependency.
 */
function blockHashOf(header) {
  if (!Buffer.isBuffer(header) || header.length !== 80) fail("a block header is 80 bytes");
  return Buffer.from(x11.digest(header, 1, 1)).reverse().toString("hex");
}

const PROTO = {
  BLS_SCHEME: 70225,
  DMN_TYPE: 70227,
  SMNLE_VERSIONED: 70228,
  MNLISTDIFF_VERSION_ORDER: 70229,
  MNLISTDIFF_CHAINLOCKS: 70230,
  CURRENT: 70240,
};
const PRO_TX_VERSION = { LegacyBLS: 1, BasicBLS: 2, ExtAddr: 3, MultiPayout: 4 };
const MN_TYPE = { Regular: 0, Evo: 1 };
/** the serialization-layer ceiling every CompactSize is range-checked against */
const MAX_SIZE = 0x02000000n;
/** MaxBlockSize()/60, the most transactions a partial merkle tree may claim
 *  [8c9f166a3:src/consensus/consensus.h:11-15 and src/merkleblock.cpp:168-170] */
const MAX_PMT_TRANSACTIONS = Math.floor(2000000 / 60);

/** a reader that refuses to run off the end rather than returning short data */
class Reader {
  constructor(buf) { this.buf = buf; this.off = 0; }
  need(n, what) {
    if (this.off + n > this.buf.length) {
      fail(`${what} needs ${n} bytes at offset ${this.off}, only ${this.buf.length - this.off} remain`);
    }
  }
  read(n, what) { this.need(n, what); const b = this.buf.subarray(this.off, this.off + n); this.off += n; return b; }
  u8(what) { this.need(1, what); return this.buf[this.off++]; }
  u16(what) { this.need(2, what); const v = this.buf.readUInt16LE(this.off); this.off += 2; return v; }
  u16be(what) { this.need(2, what); const v = this.buf.readUInt16BE(this.off); this.off += 2; return v; }
  i32(what) { this.need(4, what); const v = this.buf.readInt32LE(this.off); this.off += 4; return v; }
  u32(what) { this.need(4, what); const v = this.buf.readUInt32LE(this.off); this.off += 4; return v; }
  u64(what) { this.need(8, what); const v = this.buf.readBigUInt64LE(this.off); this.off += 8; return v; }
  /** a uint256 as it appears on the wire, returned in RPC DISPLAY order */
  hash(what) { return Buffer.from(this.read(32, what)).reverse().toString("hex"); }
  /**
   * CompactSize, with the CANONICAL-WIDTH and MAX_SIZE rules Dash applies
   * [8c9f166a3:src/serialize.h:288-317] (round 6, MAJOR: this accepted every width and checked
   * neither, so `fd0300` was read as 3 and a 3647-byte payload parsed cleanly with no remainder;
   * consuming every byte is not the same as being a decoder of the consensus wire domain).
   *
   * A wider form than the value needs is REJECTED, not normalised: two encoders that disagree
   * about which is valid disagree about the bytes, and the whole point of a pinned codec is that
   * they cannot.
   */
  varint(what) {
    const first = this.u8(what);
    let v;
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      v = BigInt(this.u16(what));
      if (v < 253n) fail(`${what} uses a non-canonical CompactSize (${v} fits one byte)`);
    } else if (first === 0xfe) {
      v = BigInt(this.u32(what));
      if (v < 0x10000n) fail(`${what} uses a non-canonical CompactSize (${v} fits two bytes)`);
    } else {
      v = this.u64(what);
      if (v < 0x100000000n) fail(`${what} uses a non-canonical CompactSize (${v} fits four bytes)`);
    }
    if (v > MAX_SIZE) fail(`${what} declares ${v}, above the ${MAX_SIZE} MAX_SIZE limit`);
    return Number(v);
  }
  varbytes(what) { return this.read(this.varint(`${what} length`), what); }
  get remaining() { return this.buf.length - this.off; }
}

/** CService: 16 bytes of address then a BIG-ENDIAN port [src/netaddress.h] */
function readService(r) {
  const raw = Buffer.from(r.read(16, "service address"));
  const port = r.u16be("service port");
  // an IPv4-mapped address ends ::ffff:a.b.c.d; render it that way, else render as hex
  const isV4Mapped = raw.subarray(0, 12).equals(
    Buffer.from("00000000000000000000ffff", "hex"));
  const host = isV4Mapped ? Array.from(raw.subarray(12)).join(".") : raw.toString("hex");
  return { host, port, service: `${host}:${port}` };
}

/**
 * One CSimplifiedMNListEntry. `protocolVersion` selects whether the entry's own version is on
 * the wire; everything after that follows the ENTRY's version, which is the distinction the
 * library gets wrong.
 */
function readEntry(r, protocolVersion) {
  const start = r.off;
  const e = {};
  if (protocolVersion >= PROTO.SMNLE_VERSIONED) {
    e.nVersion = r.u16("entry nVersion");
  } else {
    e.nVersion = PRO_TX_VERSION.LegacyBLS;
  }
  if (e.nVersion < PRO_TX_VERSION.LegacyBLS || e.nVersion > PRO_TX_VERSION.MultiPayout) {
    fail(`entry carries an unknown nVersion ${e.nVersion}`);
  }
  e.proRegTxHash = r.hash("proRegTxHash");
  e.confirmedHash = r.hash("confirmedHash");
  if (e.nVersion >= PRO_TX_VERSION.ExtAddr) {
    // ExtNetInfo. Not decoded in this increment: no capture exercises it, and inventing a layout
    // no fixture drives is how unvalidated parsers get written.
    fail(`entry version ${e.nVersion} uses the extended address form, which this increment does ` +
         "not decode (no capture exercises it yet)");
  }
  e.netInfo = readService(r);
  // the BLS scheme differs by entry version, the LENGTH does not
  e.pubKeyOperator = Buffer.from(r.read(48, "pubKeyOperator")).toString("hex");
  e.blsScheme = e.nVersion === PRO_TX_VERSION.LegacyBLS ? "legacy" : "basic";
  // uint160 values render REVERSED, the same convention as a uint256. platformNodeID below is
  // oracle-confirmed against the node (parsing it in wire order produced the exact byte-reverse
  // of what `protx diff` reports); keyIDVoting follows the same uint160 convention but no field
  // in this capture's oracle renders it as hex, so it is convention rather than measurement.
  e.keyIDVoting = Buffer.from(r.read(20, "keyIDVoting")).reverse().toString("hex");
  e.isValid = r.u8("isValid") !== 0;
  if (protocolVersion >= PROTO.DMN_TYPE && e.nVersion >= PRO_TX_VERSION.BasicBLS) {
    e.nType = r.u16("nType");
    if (e.nType === MN_TYPE.Evo) {
      if (e.nVersion < PRO_TX_VERSION.ExtAddr) e.platformHTTPPort = r.u16("platformHTTPPort");
      e.platformNodeID = Buffer.from(r.read(20, "platformNodeID")).reverse().toString("hex");
    }
  } else {
    e.nType = MN_TYPE.Regular;
  }
  // THE EXACT BYTES, kept because the list root is computed over entry hashes
  e.raw = Buffer.from(r.buf.subarray(start, r.off));
  // THE HASH PREIMAGE IS NOT THE WIRE BYTES. CalcHash writes the entry under SER_GETHASH
  // [src/evo/simplifiedmns.cpp:44-49], and the entry's own nVersion is written only under
  // SER_NETWORK [src/evo/simplifiedmns.h:72-75], so the leading version field present on the
  // wire is ABSENT from what gets hashed. Computing the root over the wire bytes produces a
  // plausible-looking root that matches nothing, which is precisely the failure this project
  // keeps finding, so the preimage is derived here rather than assumed by a caller.
  e.hashPreimage = protocolVersion >= PROTO.SMNLE_VERSIONED ? e.raw.subarray(2) : e.raw;
  e.hash = Buffer.from(dsha256(e.hashPreimage)).reverse().toString("hex");
  return e;
}


const LLMQ_COMMITMENT_VERSION = {
  LEGACY_NON_INDEXED: 1,
  LEGACY_INDEXED: 2,
  BASIC_NON_INDEXED: 3,
  BASIC_INDEXED: 4,
};

/**
 * DYNBITSET: a compact-size count of BITS, then ceil(bits/8) bytes. The count is in BITS, not
 * bytes, which is the kind of detail that silently shifts every subsequent field if assumed.
 */
function readDynBitset(r, what) {
  const bitCount = r.varint(`${what} bit count`);
  const bytes = Buffer.from(r.read(Math.ceil(bitCount / 8), what));
  const bits = [];
  for (let i = 0; i < bitCount; i++) bits.push(((bytes[i >> 3] >> (i & 7)) & 1) === 1);
  return { bitCount, bytes: bytes.toString("hex"), bits, setCount: bits.filter(Boolean).length };
}

/**
 * One llmq::CFinalCommitment [src/llmq/commitment.h:95-115]. Two version-dependent branches, and
 * both change the byte layout:
 *   quorumIndex is present ONLY for the INDEXED versions (2 and 4);
 *   the public key and both signatures use the LEGACY scheme for versions 1 and 2, the basic
 *   scheme for 3 and 4. The lengths do not change, the scheme does, and the scheme is what a
 *   later signature check has to use.
 */
function readFinalCommitment(r) {
  const start = r.off;
  const c = {};
  c.nVersion = r.u16("commitment nVersion");
  if (c.nVersion < LLMQ_COMMITMENT_VERSION.LEGACY_NON_INDEXED ||
      c.nVersion > LLMQ_COMMITMENT_VERSION.BASIC_INDEXED) {
    fail(`quorum commitment carries an unknown nVersion ${c.nVersion}`);
  }
  c.llmqType = r.u8("commitment llmqType");
  c.quorumHash = r.hash("commitment quorumHash");
  const indexed = c.nVersion === LLMQ_COMMITMENT_VERSION.LEGACY_INDEXED ||
                  c.nVersion === LLMQ_COMMITMENT_VERSION.BASIC_INDEXED;
  if (indexed) { r.need(2, "quorumIndex"); c.quorumIndex = r.buf.readInt16LE(r.off); r.off += 2; }
  c.signers = readDynBitset(r, "signers");
  c.validMembers = readDynBitset(r, "validMembers");
  c.blsScheme = (c.nVersion === LLMQ_COMMITMENT_VERSION.LEGACY_NON_INDEXED ||
                 c.nVersion === LLMQ_COMMITMENT_VERSION.LEGACY_INDEXED) ? "legacy" : "basic";
  c.quorumPublicKey = Buffer.from(r.read(48, "quorumPublicKey")).toString("hex");
  c.quorumVvecHash = r.hash("quorumVvecHash");
  c.quorumSig = Buffer.from(r.read(96, "quorumSig")).toString("hex");
  c.membersSig = Buffer.from(r.read(96, "membersSig")).toString("hex");
  c.raw = Buffer.from(r.buf.subarray(start, r.off));
  c.hash = Buffer.from(dsha256(c.raw)).reverse().toString("hex");
  return c;
}

/** CPartialMerkleTree [src/merkleblock.h] */
function readPartialMerkleTree(r) {
  const nTransactions = r.u32("cbTxMerkleTree nTransactions");
  const hashCount = r.varint("cbTxMerkleTree hash count");
  const hashes = [];
  for (let i = 0; i < hashCount; i++) hashes.push(r.hash(`cbTxMerkleTree hash ${i}`));
  const bits = Buffer.from(r.varbytes("cbTxMerkleTree bits"));
  return { nTransactions, hashes, bits: bits.toString("hex") };
}

/**
 * A Dash transaction. Version and type are two int16 fields, and a nonzero type carries an
 * extra payload after the locktime [src/primitives/transaction.h].
 */
function readTransaction(r) {
  const start = r.off;
  const version = r.u16("tx version");
  const type = r.u16("tx type");
  const vinCount = r.varint("tx input count");
  const vin = [];
  for (let i = 0; i < vinCount; i++) {
    const prevoutHash = r.hash(`input ${i} prevout hash`);
    const prevoutIndex = r.u32(`input ${i} prevout index`);
    const script = Buffer.from(r.varbytes(`input ${i} scriptSig`));
    const sequence = r.u32(`input ${i} sequence`);
    vin.push({ prevoutHash, prevoutIndex, scriptSig: script.toString("hex"), sequence });
  }
  const voutCount = r.varint("tx output count");
  const vout = [];
  for (let i = 0; i < voutCount; i++) {
    const value = r.u64(`output ${i} value`);
    const script = Buffer.from(r.varbytes(`output ${i} scriptPubKey`));
    vout.push({ index: i, valueDuffs: value.toString(), script: script.toString("hex") });
  }
  const lockTime = r.u32("tx locktime");
  let extraPayload = null;
  if (type !== 0) extraPayload = Buffer.from(r.varbytes("tx extra payload")).toString("hex");
  const raw = Buffer.from(r.buf.subarray(start, r.off));
  return {
    version, type, vin, vout, lockTime, extraPayload,
    raw: raw.toString("hex"),
    txid: Buffer.from(dsha256(raw)).reverse().toString("hex"),
  };
}

/**
 * Parse a P2P mnlistdiff payload.
 *
 *   parseMnListDiff(buffer, { protocolVersion })
 *
 * Returns the decoded frame plus `undecoded`, which names what this increment deliberately does
 * not read. A caller must not treat a parse as full coverage while that is non-empty.
 */
function parseMnListDiff(payload, { protocolVersion } = {}) {
  if (!Buffer.isBuffer(payload)) fail("payload must be a Buffer");
  if (!Number.isInteger(protocolVersion)) fail("protocolVersion is required (the layout depends on it)");
  if (protocolVersion < PROTO.MNLISTDIFF_CHAINLOCKS || protocolVersion > PROTO.CURRENT) {
    fail(`protocol ${protocolVersion} is outside the supported range ` +
         `${PROTO.MNLISTDIFF_CHAINLOCKS}..${PROTO.CURRENT}; the wire layout differs outside it ` +
         "and this module refuses rather than guessing (a soundness review)");
  }
  const r = new Reader(payload);
  const out = {};
  // nVersion FIRST at this protocol range [smldiff.h:66-68]
  out.nVersion = r.u16("diff nVersion");
  out.baseBlockHash = r.hash("baseBlockHash");
  out.blockHash = r.hash("blockHash");
  out.cbTxMerkleTree = readPartialMerkleTree(r);
  out.cbTx = readTransaction(r);
  const deletedCount = r.varint("deletedMNs count");
  out.deletedMNs = [];
  for (let i = 0; i < deletedCount; i++) out.deletedMNs.push(r.hash(`deletedMN ${i}`));
  const mnCount = r.varint("mnList count");
  out.mnList = [];
  for (let i = 0; i < mnCount; i++) out.mnList.push(readEntry(r, protocolVersion));

  // deletedQuorums: pairs of (llmqType, quorumHash) [smldiff.h:74]
  const deletedQuorumCount = r.varint("deletedQuorums count");
  out.deletedQuorums = [];
  for (let i = 0; i < deletedQuorumCount; i++) {
    const llmqType = r.u8(`deletedQuorum ${i} llmqType`);
    out.deletedQuorums.push({ llmqType, quorumHash: r.hash(`deletedQuorum ${i} quorumHash`) });
  }
  const newQuorumCount = r.varint("newQuorums count");
  out.newQuorums = [];
  for (let i = 0; i < newQuorumCount; i++) out.newQuorums.push(readFinalCommitment(r));

  // quorumsCLSigs: map<CBLSSignature, set<uint16_t>>, present from 70230 [smldiff.h:76-78]
  out.quorumsCLSigs = [];
  if (protocolVersion >= PROTO.MNLISTDIFF_CHAINLOCKS) {
    const mapSize = r.varint("quorumsCLSigs map size");
    for (let i = 0; i < mapSize; i++) {
      const signature = Buffer.from(r.read(96, `quorumsCLSigs ${i} signature`)).toString("hex");
      const setSize = r.varint(`quorumsCLSigs ${i} index count`);
      const quorumIndexes = [];
      for (let j = 0; j < setSize; j++) quorumIndexes.push(r.u16(`quorumsCLSigs ${i} index ${j}`));
      out.quorumsCLSigs.push({ signature, quorumIndexes });
    }
  }

  out.protocolVersion = protocolVersion;
  out.bytesConsumed = r.off;
  out.bytesRemaining = r.remaining;
  out.undecoded = [];
  // THE WHOLE PAYLOAD OR NOTHING. A parser that stops early and reports success is how a caller
  // ends up believing it verified a section nobody read, so trailing bytes are an error.
  if (out.bytesRemaining !== 0) {
    fail(`${out.bytesRemaining} bytes remain after the frame; the payload was not fully decoded`);
  }
  return out;
}



/**
 * CPartialMerkleTree::ExtractMatches [8c9f166a3:src/merkleblock.cpp:105-194].
 *
 * Returns { merkleRoot, matched } where `matched` are the txids the tree proves, or throws. This
 * is what BINDS a coinbase to a block: the extracted root must equal the block header's merkle
 * root, and the coinbase txid must be among the matches. Without it the walk was reading a
 * transaction out of the diff and calling its payload a value Dash Core committed, which round 6
 * showed by flipping one byte of the tree and watching every check still pass.
 *
 * Every refusal below is one the C++ makes, and each matters: an empty set, more hashes than
 * transactions, fewer bits than hashes, a traversal that runs off either array, IDENTICAL left
 * and right branches (the transactions they cover must be distinct, so equality means a fabricated
 * tree), and any bit or hash left unconsumed at the end.
 */
function extractMerkleMatches(pmt) {
  if (!pmt || !Number.isInteger(pmt.nTransactions)) fail("a partial merkle tree needs nTransactions");
  const nTransactions = pmt.nTransactions;
  const hashes = pmt.hashes.map((h) => Buffer.from(h, "hex").reverse());   // back to internal order
  const bitBytes = Buffer.from(pmt.bits, "hex");
  const totalBits = bitBytes.length * 8;
  const bit = (i) => ((bitBytes[i >> 3] >> (i & 7)) & 1) === 1;

  if (nTransactions === 0) fail("the partial merkle tree covers no transactions");
  // THE COUNT BOUND Dash applies [src/merkleblock.cpp:168-170]: a block cannot hold more
  // transactions than its size limit allows at the lower bound of 60 bytes each, so a count above
  // MaxBlockSize()/60 describes a block that cannot exist. Round 7: without it, nTransactions of
  // 0xffffffff was ACCEPTED and returned a root, so a fabricated tree could claim a root for an
  // impossible block. The bound also keeps the tree height small enough that the width arithmetic
  // below stays inside the 32-bit range JavaScript bitwise operators use, which is a second reason
  // it matters here and not only in the C++.
  if (nTransactions > MAX_PMT_TRANSACTIONS) {
    fail(`the partial merkle tree claims ${nTransactions} transactions, above the ` +
         `${MAX_PMT_TRANSACTIONS} a block of the maximum size could hold`);
  }
  if (hashes.length > nTransactions) fail("the tree carries more hashes than transactions");
  if (totalBits < hashes.length) fail("the tree carries fewer bits than hashes");

  const width = (height) => (nTransactions + (1 << height) - 1) >> height;
  let treeHeight = 0;
  while (width(treeHeight) > 1) treeHeight++;

  let bitsUsed = 0, hashUsed = 0;
  const matched = [];
  const traverse = (height, pos) => {
    if (bitsUsed >= totalBits) fail("the partial merkle tree ran off its bit array");
    const parentOfMatch = bit(bitsUsed++);
    if (height === 0 || !parentOfMatch) {
      if (hashUsed >= hashes.length) fail("the partial merkle tree ran off its hash array");
      const h = hashes[hashUsed++];
      if (height === 0 && parentOfMatch) matched.push(Buffer.from(h).reverse().toString("hex"));
      return h;
    }
    const left = traverse(height - 1, pos * 2);
    let right;
    if (pos * 2 + 1 < width(height - 1)) {
      right = traverse(height - 1, pos * 2 + 1);
      if (left.equals(right)) {
        fail("the partial merkle tree repeats a branch, which distinct transactions cannot do");
      }
    } else {
      right = left;
    }
    return dsha256(Buffer.concat([left, right]));
  };
  const root = traverse(treeHeight, 0);
  // all bits consumed, allowing only the padding to the byte boundary
  if (Math.ceil(bitsUsed / 8) !== Math.ceil(totalBits / 8)) {
    fail("the partial merkle tree leaves bits unconsumed");
  }
  if (hashUsed !== hashes.length) fail("the partial merkle tree leaves hashes unconsumed");
  return { merkleRoot: Buffer.from(root).reverse().toString("hex"), matched };
}

/** the 80-byte headers of a retained header chain, indexed by the block hash each one produces */
function indexHeaderChain(headerChainHex) {
  // STRICT HEX FIRST (round 7). Buffer.from(x,"hex") truncates at the first non-hex character, so
  // a chain whose TAIL is malformed decoded to its valid PREFIX and was accepted: one real header
  // followed by "zz" indexed one header and silently discarded the rest. The length check below
  // cannot catch it, because the truncated length is still a multiple of 80. Same defect class as
  // the strict-hex work in the verifier module, in a function that missed it.
  if (typeof headerChainHex !== "string" || headerChainHex.length % 2 !== 0 ||
      !/^(?:[0-9a-f]{2})*$/.test(headerChainHex)) {
    fail("the header chain is not an even-length lowercase hex string");
  }
  const buf = Buffer.from(headerChainHex, "hex");
  if (buf.length === 0 || buf.length % 80 !== 0) {
    fail(`a header chain must be a whole number of 80-byte headers (got ${buf.length} bytes)`);
  }
  const byHash = new Map();
  for (let off = 0; off < buf.length; off += 80) {
    const header = buf.subarray(off, off + 80);
    const hash = blockHashOf(header);
    byHash.set(hash, {
      hash,
      prevBlockHash: Buffer.from(header.subarray(4, 36)).reverse().toString("hex"),
      merkleRoot: Buffer.from(header.subarray(36, 68)).reverse().toString("hex"),
      raw: Buffer.from(header),
    });
  }
  return byHash;
}

/**
 * Parse a STANDALONE masternode entry, the form `basePackage.smlEntries[]` retains under
 * `dash-smlentry-serialization-v1`. Same serialization as an entry inside a diff, so the same
 * reader is used, and the whole blob must be consumed: a trailing byte means the retained
 * evidence is not what the codec says it is.
 */
function parseStandaloneEntry(buf, { protocolVersion } = {}) {
  if (!Buffer.isBuffer(buf)) fail("a base list entry must be a Buffer");
  if (!Number.isInteger(protocolVersion)) fail("protocolVersion is required to read an entry");
  if (protocolVersion < PROTO.MNLISTDIFF_CHAINLOCKS || protocolVersion > PROTO.CURRENT) {
    fail(`protocol ${protocolVersion} is outside the supported range`);
  }
  const r = new Reader(buf);
  const e = readEntry(r, protocolVersion);
  if (r.remaining !== 0) {
    fail(`${r.remaining} bytes remain after a base list entry; it is not a single entry`);
  }
  return e;
}

/**
 * APPLY A DIFF TO A LIST, which is the step the walk was missing (round 6, MAJOR).
 *
 * A CSimplifiedMNListDiff is a DELTA, not a snapshot [8c9f166a3:src/evo/smldiff.cpp:122-151]. It
 * carries removals in `deletedMNs` and new-or-CHANGED entries in `mnList`. Deriving the list at a
 * height therefore means transforming the previous list, and computing a root over `diff.mnList`
 * alone answers a question nobody asked: it is the root of the changes, not of the list.
 *
 * Two details that a naive implementation gets wrong, both stated in
 * docs/CORE_WALK_DUTY_STATEMENT.md before this was written:
 *   an entry in `mnList` REPLACES one with the same proRegTxHash rather than appending, so the
 *     list is keyed rather than concatenated;
 *   a deletion naming an entry the list does not hold is MALFORMED evidence, not a no-op, so it
 *     fails closed rather than being ignored.
 *
 * Returns a new array; the input is not mutated, so a caller cannot lose the previous state.
 */
function applyDiffToList(previousEntries, diff) {
  if (!Array.isArray(previousEntries)) fail("the previous list must be an array");
  if (!diff || !Array.isArray(diff.mnList) || !Array.isArray(diff.deletedMNs)) {
    fail("applyDiffToList needs a parsed diff");
  }
  const byHash = new Map();
  for (const e of previousEntries) {
    if (byHash.has(e.proRegTxHash)) fail(`the previous list holds ${e.proRegTxHash} twice`);
    byHash.set(e.proRegTxHash, e);
  }
  for (const hash of diff.deletedMNs) {
    if (!byHash.has(hash)) {
      fail(`the diff deletes ${hash}, which the list at the previous height does not hold`);
    }
    byHash.delete(hash);
  }
  for (const e of diff.mnList) {
    byHash.set(e.proRegTxHash, e);   // add OR replace, keyed by identity
  }
  return [...byHash.values()];
}

/**
 * The masternode-list root over a set of parsed entries.
 *
 * Two rules, both read from source rather than inferred, and both of which produce a
 * plausible wrong answer if guessed:
 *   ORDER  entries sort by proRegTxHash under base_blob::Compare, a forward memcmp over the
 *          INTERNAL bytes [src/evo/simplifiedmns.cpp:76-78]. That is NOT the display-hex order:
 *          on the pinned capture the two orders differ and only this one reproduces the
 *          committed root.
 *   LEAF   each leaf is the entry's CalcHash, taken over the SER_GETHASH preimage, which omits
 *          the wire-only nVersion [src/evo/simplifiedmns.cpp:44-49].
 * The tree itself duplicates a lone final node at each level, the usual convention.
 */
function computeListRoot(entries) {
  if (!Array.isArray(entries)) fail("computeListRoot needs an array of parsed entries");
  if (entries.length === 0) return Buffer.alloc(32).toString("hex");
  const internal = (displayHex) => Buffer.from(displayHex, "hex").reverse();
  const sorted = entries.slice().sort(
    (a, b) => Buffer.compare(internal(a.proRegTxHash), internal(b.proRegTxHash)));
  let level = sorted.map((e) => {
    if (!Buffer.isBuffer(e.hashPreimage)) fail("an entry carries no hash preimage");
    return dsha256(e.hashPreimage);
  });
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(dsha256(Buffer.concat([level[i], level[i + 1] || level[i]])));
    }
    level = next;
  }
  return Buffer.from(level[0]).reverse().toString("hex");
}

/**
 * The CbTx extra payload, which carries the commitment the list root is checked against
 * [src/evo/cbtx.h]. version(2), height(4), merkleRootMNList(32), and from version 2 a
 * merkleRootQuorums(32). Later versions append more, which this reads past rather than
 * misreporting.
 */
function readCbTxPayload(cbTx) {
  if (!cbTx || typeof cbTx.extraPayload !== "string") fail("the coinbase carries no extra payload");
  const r = new Reader(Buffer.from(cbTx.extraPayload, "hex"));
  const out = {};
  out.version = r.u16("cbTx payload version");
  out.height = r.u32("cbTx payload height");
  out.merkleRootMNList = r.hash("merkleRootMNList");
  if (out.version >= 2) out.merkleRootQuorums = r.hash("merkleRootQuorums");
  out.trailingBytes = r.remaining;
  return out;
}

module.exports = {
  parseMnListDiff, readEntry, readTransaction, readPartialMerkleTree, Reader,
  computeListRoot, readCbTxPayload, readFinalCommitment, readDynBitset,
  parseStandaloneEntry, applyDiffToList, extractMerkleMatches, indexHeaderChain, blockHashOf,
  PROTO, PRO_TX_VERSION, MN_TYPE, LLMQ_COMMITMENT_VERSION,
};
