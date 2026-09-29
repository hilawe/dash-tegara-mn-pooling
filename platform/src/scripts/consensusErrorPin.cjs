"use strict";
/**
 * THE PINNED UNIQUE-INDEX IDENTITY for the outcome classifier (e2Outcome.cjs; tegara/docs/
 * E2_BUILD_SPEC.md, C2, "THE PINNING IS STRUCTURAL"), recorded beside the protocol pin it was read at.
 * Pinned 2026-09-28.
 *
 * THE IDENTITY IS A CODE AND A PAYLOAD, never the code alone. A refusal is the duplicate unique index
 * only when its structured code is 40105 AND its data decodes, exactly and completely, as that error.
 * The A/B demonstration's code-only check (approvalWrite.duplicateVerdict) is a narrower control for
 * one demonstration and is deliberately NOT this.
 *
 * WHERE THE BYTES COME FROM. The gateway's refusal `data` is the serialized ConsensusError, lifted
 * from the transaction result's `info` (rs-dapi platform_service/error_mapping.rs,
 * decode_consensus_error, and wait_for_state_transition_result.rs, both at v4.1.1).
 *
 * THE LAYOUT, read from the pinned protocol definitions at dashpay/platform v4.1.1 (rs-dpp
 * errors/consensus/consensus_error.rs, state/state_error.rs,
 * state/document/duplicate_unique_index_error.rs) and bincode's standard configuration, big-endian:
 *   varint 2    ConsensusError::StateError (DefaultError 0, BasicError 1, StateError 2,
 *               SignatureError 3, FeeError 4)
 *   varint 14   StateError::DuplicateUniqueIndexError (40100's DocumentAlreadyPresentError is 2)
 *   32 bytes    document_id
 *   varint n    duplicating_properties, then n times: varint length, UTF-8 bytes
 * A varint below 251 is one byte; 251, 252 and 253 announce a big-endian u16, u32 and u64. An ENUM
 * INDEX is a u32, so its varint may not use the u64 form (both DPP builds refuse it with
 * "InvalidIntegerType"); a count or a length is a usize and may. Any count is conforming, zero
 * included, since the encoder writes whatever list the error holds.
 *
 * THE DECODE LIMIT. ConsensusError is serialized with `#[platform_serialize(limit = 2000)]`, and
 * bincode 2 counts against it what a decode would allocate: every primitive read claims its type's
 * size (4 for an enum index, 1 for each of the id's 32 bytes, 8 for a count or a length), a list
 * claims 24 bytes per element before reading them (the size of a Rust String) and releases each
 * element's share as it reads it, and a name claims its own bytes. A payload whose running claim
 * passes 2000 is refused by the pinned decoders, so it is malformed here too: 81 one-letter names
 * decode and 82 do not, one name of 1,944 bytes decodes and 1,945 does not. (A confirmation round of
 * 2026-09-29 found the reader accepting 82; the accounting was fitted to the DPP builds' measured
 * boundaries and is checked against them in the battery, boundaries and a seeded random sweep.)
 *
 * AGREEMENT WITH THE ORACLE, and the one deliberate divergence. The reader accepts and refuses what
 * both pinned DPP builds accept and refuse, on every case the battery constructs (non-minimal
 * varints and u64 lengths included), with ONE exception: bytes after the error. The DPP ignores
 * them. This reader calls them malformed, because no encoder writes them, and malformed only makes
 * the classifier answer "ambiguous", which callers wait on and never record as a refusal or a
 * resume. (A review of 2026-09-28 found the reader accepting a u64 enum index and refusing empty
 * and long property lists, both against the oracle; both are corrected.)
 *
 * HOW THE READING WAS CHECKED, and what each check reaches:
 * - two REAL payloads, read-only from our testnet evonode's block results, refusals of the approval
 *   contract's duplicates at Platform heights 604,557 and 604,561
 *   (fixtures/consensus-error-unique-index-testnet.json);
 * - both pinned DPP builds (pshenmic-dpp 2.0.0-dev.20 and dev.28, compiled from Platform's own
 *   source) decode those and the constructed header and reservation payloads into the matching
 *   "has duplicate unique properties" message, and refuse the wrong variant and a truncated body
 *   (consensusErrorPinTest.cjs, where the DPP is a TEST oracle only: its message text is never read
 *   by this module, since message matching is non-conforming);
 * - a big-endian long length decodes in both builds and the little-endian form is refused.
 *
 * WHAT THIS DECIDES, AND NOT. It decides whether the payload IS the duplicate unique-index error. It
 * does not decode other errors: a payload naming another variant is reported as another consensus
 * error without its body being checked, and the classifier's contract maps that to "other". It
 * carries no operation context, so which document the refusal was about is the caller's comparison
 * (the writer's proved identity and content checks).
 */
const { PROTOCOL_VERSION_PIN } = require("./platformProtocolPin.cjs");

const PINNED_AT = Object.freeze({ platformRelease: "v4.1.1", protocolVersion: 13 });
// A protocol move may reorder these enums, so the identity refuses to exist under another pin
// until it is read again, the way the protocol pin itself refuses a moved network.
if (PROTOCOL_VERSION_PIN !== PINNED_AT.protocolVersion) {
  throw new Error(`consensusErrorPin: the unique-index identity was read at protocol ${PINNED_AT.protocolVersion} ` +
    `(Platform ${PINNED_AT.platformRelease}) and the protocol pin is now ${PROTOCOL_VERSION_PIN}; re-read the ` +
    "consensus-error definitions before this identity may classify anything");
}

const DUPLICATE_UNIQUE_INDEX_CODE = 40105; // rs-dpp errors/consensus/codes.rs at v4.1.1
const CONSENSUS_ERROR_VARIANTS = 5;         // DefaultError through FeeError (a test-only variant is not built)
const STATE_ERROR_VARIANT = 2;
const DUPLICATE_UNIQUE_INDEX_VARIANT = 14;
const HEX_RE = /^([0-9a-f]{2})*$/;
const DECODE_LIMIT = 2000;                  // #[platform_serialize(limit = 2000)] on ConsensusError
const RUST_STRING_BYTES = 24;               // size_of::<String>() on the 64-bit builds that decode it

class Malformed extends Error {}

/**
 * bincode's standard varint, big-endian. `u32` true reads an enum index, which may not take the u64
 * form. Throws Malformed past the end, on a u128 tag, or on a u64 tag where a u32 is read.
 */
function readVarint(buf, at, { u32 = false } = {}) {
  if (at >= buf.length) throw new Malformed("a varint runs past the end");
  const b = buf[at];
  if (b < 251) return { value: b, next: at + 1 };
  const width = b === 251 ? 2 : b === 252 ? 4 : b === 253 ? 8 : 0;
  if (width === 0) throw new Malformed(`varint tag ${b} is not a u16, u32 or u64`);
  if (u32 && width === 8) throw new Malformed("an enum index in the u64 form (an enum index is a u32)");
  if (at + 1 + width > buf.length) throw new Malformed("a varint's value runs past the end");
  let v = 0n;
  for (let i = 0; i < width; i++) v = (v << 8n) | BigInt(buf[at + 1 + i]);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Malformed("a varint exceeds the safe integer range");
  return { value: Number(v), next: at + 1 + width };
}

/**
 * dataHex -> { kind: "duplicate-unique-index", documentIdHex, properties }
 *          | { kind: "other-consensus-error", consensusVariant, stateVariant? }
 *          | { kind: "malformed", why }
 */
function decodeConsensusErrorPayload(dataHex) {
  try {
    if (typeof dataHex !== "string" || !HEX_RE.test(dataHex)) throw new Malformed("the data is not lowercase hex");
    const buf = Buffer.from(dataHex, "hex");
    if (buf.length === 0) throw new Malformed("the data is empty");
    let claimed = 0;
    const claim = (n) => {
      claimed += n;
      if (claimed > DECODE_LIMIT) throw new Malformed(`the decode passes the pinned ${DECODE_LIMIT}-byte limit`);
    };
    const outer = readVarint(buf, 0, { u32: true });
    claim(4);
    if (outer.value >= CONSENSUS_ERROR_VARIANTS) throw new Malformed(`consensus error variant ${outer.value} does not exist`);
    if (outer.value !== STATE_ERROR_VARIANT) return { kind: "other-consensus-error", consensusVariant: outer.value };
    const inner = readVarint(buf, outer.next, { u32: true });
    claim(4);
    if (inner.value !== DUPLICATE_UNIQUE_INDEX_VARIANT) {
      return { kind: "other-consensus-error", consensusVariant: outer.value, stateVariant: inner.value };
    }
    let at = inner.next;
    if (at + 32 > buf.length) throw new Malformed("the document id runs past the end");
    const documentIdHex = buf.subarray(at, at + 32).toString("hex");
    at += 32;
    claim(32);
    const count = readVarint(buf, at);
    claim(8);
    at = count.next;
    // every property takes at least its one-byte length, so a count above the remaining bytes cannot
    // be satisfied; refusing it here only saves the loop from running to the end to find that out
    if (count.value > buf.length - at) throw new Malformed(`${count.value} properties in ${buf.length - at} remaining bytes`);
    claim(RUST_STRING_BYTES * count.value);
    const utf8 = new TextDecoder("utf-8", { fatal: true });
    const properties = [];
    for (let i = 0; i < count.value; i++) {
      claimed -= RUST_STRING_BYTES;
      const len = readVarint(buf, at);
      claim(8);
      if (len.next + len.value > buf.length) throw new Malformed(`property ${i} runs past the end`);
      claim(len.value);
      try { properties.push(utf8.decode(buf.subarray(len.next, len.next + len.value))); }
      catch { throw new Malformed(`property ${i} is not UTF-8`); }
      at = len.next + len.value;
    }
    if (at !== buf.length) throw new Malformed(`${buf.length - at} byte(s) follow the error`);
    return { kind: "duplicate-unique-index", documentIdHex, properties };
  } catch (e) {
    if (e instanceof Malformed) return { kind: "malformed", why: e.message };
    throw e;
  }
}

/** The classifier's pinned form: { code, dataMatches(dataHex) -> true | false | "malformed" }. */
const UNIQUE_INDEX_IDENTITY = Object.freeze({
  code: DUPLICATE_UNIQUE_INDEX_CODE,
  dataMatches: (dataHex) => {
    const d = decodeConsensusErrorPayload(dataHex);
    if (d.kind === "duplicate-unique-index") return true;
    if (d.kind === "other-consensus-error") return false;
    return "malformed";
  },
});

module.exports = { PINNED_AT, DUPLICATE_UNIQUE_INDEX_CODE, UNIQUE_INDEX_IDENTITY, decodeConsensusErrorPayload };
