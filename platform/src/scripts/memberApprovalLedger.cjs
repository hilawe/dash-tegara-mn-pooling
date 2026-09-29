"use strict";
/**
 * MEMBER APPROVALS READ FROM THE LEDGER (tegara/docs/APPROVAL_CONTRACT_DESIGN.md, formation unit 3).
 * Unit 2 (memberApproval.cjs) counts the highest revision PRESENTED as files. This module reads each
 * claiming member's approvals from the approval contract by proof, fixes one authoritative approval
 * per member against the registration, and compares the registration with those terms through the
 * unchanged completion comparison (coownerCompletion.decideCompletion).
 *
 * RULE 1, THE FIXED SET, for a registration confirmed at layer-1 height h:
 *   SAME CHAIN   the registration's layer-1 chain is the Core chain the pinned Platform chain follows
 *                (CORE_GENESIS_BY_PLATFORM_CHAIN), or creation heights cannot be ordered against h;
 *   FIXED        an anchor read proved at a chain-locked height of at least h;
 *   COMPLETE     each claimant's approvals for the pool enumerated by proof, every page at or above
 *                the anchor's Platform height;
 *   ELIGIBLE     `$createdAtCoreBlockHeight` below h; later approvals are set aside, never counted;
 *   AUTHORITATIVE the eligible approval with the highest termsRevision, verified in full (a stale one
 *                refuses, with no fallback); lower eligible revisions are superseded and never used;
 *   PRESENCE     every claimant has one.
 * WHY IT IS FINAL: Drive stamps the creation core height from the block's chain-locked height and
 * refuses a block whose chain-locked height falls, so once a proved read shows height h or more,
 * every later approval carries at least h. The design note cites the source.
 *
 * RULE 2, THE BINDING, for the authoritative approval. The document's owner is the claimant and the
 * record's memberIdentity. The document's poolId and termsRevision are the record's. The stored bytes
 * are the record's canonical JSON exactly. And the record passes unit 2's record and owner-signature
 * checks (memberApproval.verifyRecordAndOwner, shared, so the two paths cannot drift). Platform's
 * check of the document's writer stands in for unit 2's identity signature.
 *
 * WHAT THIS DOES NOT DO: verify proofs (the injected provedQuery and the anchor's metadata are the
 * runner's proof-verified reads), read the claim book (the claims come in as completion inputs), or
 * support a registration on a chain the Platform chain does not follow, which includes every regtest
 * demonstration so far.
 */
const { canonicalString } = require("./canonicalJson.cjs");
const approval = require("./memberApproval.cjs");
const completion = require("./coownerCompletion.cjs");
const formationCore = require("./formationCore.cjs");
const { enumerateProved } = require("./e2ProvedQuery.cjs");
const { APPROVAL_TYPE, RECORD_MAX_BYTES, OWNER_SIGNATURE_BYTES } = require("./approvalContract.cjs");

// The Core chain each pinned Platform chain follows, by genesis hash as `getblockhash 0` prints it.
// Testnet's is Dash Core's own assertion (src/chainparams.cpp, CTestNetParams, read at 8c9f166a3).
// A Platform chain absent here refuses: mainnet is added once its chain id is checked.
const CORE_GENESIS_BY_PLATFORM_CHAIN = Object.freeze({
  "dash-testnet-51": "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c",
});

const HEX64 = /^[0-9a-f]{64}$/;
const DEC = /^(0|[1-9][0-9]*)$/;
const isInt = (v) => Number.isSafeInteger(v);
class LedgerApprovalRefusal extends Error {}
const refuse = (why) => { throw new LedgerApprovalRefusal(why); };

// ---- the served document into plain data (the runner's proved query serves DPP documents) ----
const idHexOf = (v, what) => {
  const b58 = v && typeof v.base58 === "function" ? v.base58() : (typeof v === "string" ? v : null);
  const bytes = b58 !== null ? formationCore.decodeId32(b58) : null;
  if (!bytes) refuse(`the served ${what} does not decode to a 32-byte identifier`);
  return bytes.toString("hex");
};
const bytesOf = (v, what, min, max) => {
  if (!(v instanceof Uint8Array)) refuse(`the served approval's ${what} is not bytes`);
  if (v.length < min || v.length > max) refuse(`the served approval's ${what} is ${v.length} bytes, outside ${min}..${max}`);
  return Buffer.from(v);
};
const U32_MAX = 4294967295;
const intOf = (v, what, min, max) => {
  const n = typeof v === "bigint" ? (v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : NaN) : v;
  if (!isInt(n) || n < min || n > max) refuse(`the served approval carries no usable ${what} (${String(v)}, outside ${min}..${max})`);
  return n;
};

/**
 * One served approval document into the plain page shape the enumeration carries. The DPP's
 * serializer checks required fields but not lengths or bounds (observed 2026-09-28), so every bound
 * the schema states is checked again here. A document's own `revision` is NOT the member's revision.
 */
function servedApprovalToPlain(d) {
  if (!d || typeof d !== "object") refuse("a served approval is not an object");
  const p = typeof d.getProperties === "function" ? d.getProperties() : d.properties;
  if (!p || typeof p !== "object") refuse("a served approval has no properties");
  return {
    id: idHexOf(d.id, "approval id"),
    ownerId: idHexOf(d.ownerId, "approval owner"),
    poolId: bytesOf(p.poolId, "poolId", 32, 32).toString("hex"),
    termsRevision: intOf(p.termsRevision, "termsRevision", 1, U32_MAX),
    record: bytesOf(p.record, "record", 2, RECORD_MAX_BYTES).toString("hex"),
    ownerSignature: bytesOf(p.ownerSignature, "ownerSignature", OWNER_SIGNATURE_BYTES, OWNER_SIGNATURE_BYTES).toString("hex"),
    createdAtCoreBlockHeight: intOf(d.createdAtCoreBlockHeight, "$createdAtCoreBlockHeight", 0, U32_MAX),
    createdAt: intOf(d.createdAt, "$createdAt", 0, Number.MAX_SAFE_INTEGER),
  };
}

/**
 * The page fetcher e2ProvedQuery.enumerateProved takes, over the runner's proved query:
 *   provedQuery(where, orderBy, limit) -> { docs, height }, proof-verified, throwing on any failure.
 * It serves ONE page through the type's own index, as the audit's adapter does, and never a second:
 * a request carrying a cursor is unserved, and so is any other contract or type. COMPLETENESS AT THE
 * LIMIT is refused by that rule, not by a count here. A page holding exactly `limit` documents makes
 * the enumeration ask for the next page, which is unserved, so the whole read is unproved.
 * Hex identifiers in `where` are sent as bytes (a hex string compares as text and can verify an
 * empty result).
 */
function makeApprovalPageFetcher({ approvalContractId, provedQuery }) {
  if (typeof approvalContractId !== "string" || typeof provedQuery !== "function") {
    refuse("makeApprovalPageFetcher needs the approval contract id and a proved query");
  }
  return async ({ contractId, type, where, orderBy, limit, startAfter }) => {
    if (contractId !== approvalContractId || type !== APPROVAL_TYPE) return { status: "unserved" };
    if (startAfter !== null && startAfter !== undefined) return { status: "unserved" };
    const lim = isInt(limit) && limit >= 1 && limit <= 100 ? limit : 100;
    const whereBytes = where.map(([f, op, v]) => [f, op, typeof v === "string" && HEX64.test(v) ? Buffer.from(v, "hex") : v]);
    let got;
    try { got = await provedQuery(whereBytes, orderBy, lim); } catch { return { status: "unserved" }; }
    if (!got || !Array.isArray(got.docs)) return { status: "unserved" };
    const height = typeof got.height === "bigint" ? got.height.toString() : String(got.height);
    const documents = got.docs.map(servedApprovalToPlain).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return { status: "verified", documents, height };
  };
}

/** The anchor from a proof-verified read's metadata, on the pinned Platform chain. */
function anchorFromMetadata(meta, platformChainId) {
  if (!meta || typeof meta !== "object") refuse("the anchor read carried no verified metadata");
  if (meta.chainId !== platformChainId) refuse(`the anchor read is on chain ${meta.chainId}, not ${platformChainId}`);
  const platformHeight = typeof meta.height === "bigint" ? meta.height.toString() : String(meta.height);
  const core = typeof meta.coreChainLockedHeight === "bigint" ? Number(meta.coreChainLockedHeight) : meta.coreChainLockedHeight;
  if (!DEC.test(platformHeight) || !isInt(core) || core < 0) refuse("the anchor read's heights are not usable");
  return { platformHeight, coreChainLockedHeight: core };
}

/**
 * RULE 1. Reads every claimant's approvals for the pool and partitions them. Returns
 * [{ claimantHex, eligible, setAside }] in claimant order, or throws LedgerApprovalRefusal.
 */
async function readFixedApprovals({ claimantsHex, poolIdHex, registrationHeight, platformChainId, l1GenesisHash,
  anchor, approvalContractId, fetchVerifiedPage }) {
  const core = CORE_GENESIS_BY_PLATFORM_CHAIN[platformChainId];
  if (core === undefined) refuse(`no Core chain is recorded for Platform chain ${platformChainId}, so approval heights cannot be ordered against the registration`);
  if (l1GenesisHash !== core) {
    refuse(`SAME CHAIN: the registration is on layer-1 chain ${String(l1GenesisHash).slice(0, 16)}..., not the Core chain ${platformChainId} follows, so approval heights cannot be ordered against it`);
  }
  if (!isInt(registrationHeight) || registrationHeight < 1) refuse("the registration height is unknown");
  if (!anchor || !DEC.test(anchor.platformHeight || "") || !isInt(anchor.coreChainLockedHeight)) refuse("no anchor read");
  if (anchor.coreChainLockedHeight < registrationHeight) {
    refuse(`NOT YET FIXED: Platform's chain-locked height ${anchor.coreChainLockedHeight} is below the registration height ${registrationHeight}; retry once it reaches it`);
  }
  if (!HEX64.test(poolIdHex || "")) refuse("the pool id is not 64 lowercase hex");
  if (!Array.isArray(claimantsHex) || claimantsHex.length === 0 || !claimantsHex.every((c) => HEX64.test(c))) {
    refuse("no claimants to read approvals for");
  }
  const out = [];
  for (const m of claimantsHex) {
    const e = await enumerateProved({ contractId: approvalContractId, type: APPROVAL_TYPE,
      where: [["$ownerId", "==", m], ["poolId", "==", poolIdHex]], orderBy: [["termsRevision", "asc"]], fetchVerifiedPage });
    if (e.status !== "proved") refuse(`COMPLETE: the approvals of ${m.slice(0, 12)}... were not read by proof (${e.strength})`);
    if (BigInt(e.heightMin) < BigInt(anchor.platformHeight)) {
      refuse(`COMPLETE: the approvals of ${m.slice(0, 12)}... were read at Platform height ${e.heightMin}, below the anchor's ${anchor.platformHeight}`);
    }
    const eligible = [];
    const setAside = [];
    for (const d of e.documents) {
      if (d.ownerId !== m) refuse(`the read for ${m.slice(0, 12)}... served an approval owned by ${d.ownerId.slice(0, 12)}...`);
      if (d.poolId !== poolIdHex) refuse(`the read for ${m.slice(0, 12)}... served an approval for pool ${d.poolId.slice(0, 12)}...`);
      (d.createdAtCoreBlockHeight < registrationHeight ? eligible : setAside).push(d);
    }
    out.push({ claimantHex: m, eligible, setAside });
  }
  return out;
}

/**
 * RULE 2, for one approval document of a claimant. Returns { identityHex, revision, agreement,
 * message, documentIdHex, createdAtCoreBlockHeight } or throws (LedgerApprovalRefusal or unit 2's
 * ApprovalRefusal).
 */
function verifyLedgerApproval({ doc, claimantHex, expect, verifyMessage }) {
  const at = `approval ${doc.id.slice(0, 12)}... of ${claimantHex.slice(0, 12)}... revision ${doc.termsRevision}`;
  if (doc.ownerId !== claimantHex) refuse(`OWNER: ${at} is owned by ${doc.ownerId.slice(0, 12)}...`);
  const bytes = Buffer.from(doc.record, "hex");
  let record;
  try { record = JSON.parse(bytes.toString("utf8")); } catch { refuse(`${at} does not carry a JSON record`); }
  let canonical;
  try { canonical = canonicalString(record); } catch (e) { refuse(`${at} carries a record with no canonical form (${e.message})`); }
  if (!Buffer.from(canonical, "utf8").equals(bytes)) refuse(`${at} does not store its record in canonical form`);
  if (!record || typeof record !== "object" || record.memberIdentity !== doc.ownerId) {
    refuse(`OWNER: ${at} carries a record for member ${String(record && record.memberIdentity).slice(0, 12)}..., not its owner`);
  }
  if (record.poolId !== doc.poolId) refuse(`${at} is indexed under a pool its record does not name`);
  if (record.revision !== doc.termsRevision) refuse(`${at} is indexed at a revision its record does not carry (${record.revision})`);
  const { r, message } = approval.verifyRecordAndOwner({ record,
    ownerSignature: Buffer.from(doc.ownerSignature, "hex").toString("base64"), expect, verifyMessage });
  return { identityHex: r.memberIdentity, revision: r.revision, agreement: r.agreement, message,
    documentIdHex: doc.id, createdAtCoreBlockHeight: doc.createdAtCoreBlockHeight };
}

/**
 * The whole decision. expect: { platformChainId, contractId (the LEDGER contract, v11),
 * approvalContractId, poolIdHex, l1GenesisHash (of the Core that answered protx info) }.
 * completionInputs: { pool, claims (from the proved claim book), protxInfo, proTxDisplayHex }. A
 * pool or contract named there that is not expect's refuses, as in unit 2. The registration height
 * comes from the same Core answer the comparison reads.
 */
async function decideLedgerApprovedCompletion({ expect, anchor, fetchVerifiedPage, verifyMessage, b58OfHex, completionInputs }) {
  const ci = completionInputs || {};
  const st = ci.protxInfo && ci.protxInfo.state;
  const h = st ? st.registeredHeight : undefined;
  const base = { registrationHeight: h, anchor };
  try {
    if (!expect || !HEX64.test(expect.poolIdHex || "")) refuse("the expected pool id is not 64 lowercase hex");
    if ((ci.poolIdHex !== undefined && ci.poolIdHex !== expect.poolIdHex)
        || (ci.poolIdB58 !== undefined && ci.poolIdB58 !== b58OfHex(expect.poolIdHex))
        || (ci.contractId !== undefined && ci.contractId !== expect.contractId)) {
      refuse("the completion names a pool or contract other than the one the approvals are read for");
    }
    if (!Array.isArray(ci.claims)) refuse("the completion carries no claims");
    const claimantsHex = [...new Set(ci.claims.map((c) => idHexOf(c.ownerB58, "claim owner")))].sort();
    const read = await readFixedApprovals({ claimantsHex, poolIdHex: expect.poolIdHex, registrationHeight: h,
      platformChainId: expect.platformChainId, l1GenesisHash: expect.l1GenesisHash, anchor,
      approvalContractId: expect.approvalContractId, fetchVerifiedPage });
    const fixedSet = [];
    const superseded = [];
    const setAside = [];
    const refusals = [];
    const verified = [];
    for (const { claimantHex, eligible, setAside: later } of read) {
      for (const d of later) setAside.push({ identityHex: claimantHex, documentIdHex: d.id, revision: d.termsRevision, createdAtCoreBlockHeight: d.createdAtCoreBlockHeight });
      if (eligible.length === 0) { refusals.push(`PRESENCE: member ${claimantHex.slice(0, 12)}... holds claims and has no approval created before the registration height ${h}`); continue; }
      const revs = eligible.map((d) => d.termsRevision);
      if (new Set(revs).size !== revs.length) { refusals.push(`member ${claimantHex.slice(0, 12)}... has two approvals at one revision`); continue; }
      const top = eligible.reduce((a, b) => (b.termsRevision > a.termsRevision ? b : a));
      for (const d of eligible) if (d !== top) superseded.push({ identityHex: claimantHex, documentIdHex: d.id, revision: d.termsRevision });
      try {
        const v = verifyLedgerApproval({ doc: top, claimantHex, expect: { ...expect, registrationHeight: h }, verifyMessage });
        verified.push(v);
        fixedSet.push({ identityHex: v.identityHex, documentIdHex: v.documentIdHex, revision: v.revision, createdAtCoreBlockHeight: v.createdAtCoreBlockHeight });
      } catch (e) {
        if (!(e instanceof LedgerApprovalRefusal) && !(e instanceof approval.ApprovalRefusal)) throw e;
        refusals.push(`approval of ${claimantHex.slice(0, 12)}...: ${e.message}`);
      }
    }
    const report = { ...base, fixedSet, superseded, setAside };
    if (refusals.length) return { ok: false, refusals, ...report };
    const termsSets = verified.map((v) => ({ member: `identity ${v.identityHex.slice(0, 12)}...`,
      platformIdentityB58: b58OfHex(v.identityHex), agreement: v.agreement }));
    const r = completion.decideCompletion({ contractId: expect.contractId, poolIdHex: expect.poolIdHex,
      poolIdB58: b58OfHex(expect.poolIdHex), pool: ci.pool, claims: ci.claims, protxInfo: ci.protxInfo,
      proTxDisplayHex: ci.proTxDisplayHex, termsSets });
    return { ...r, ...report };
  } catch (e) {
    if (e instanceof LedgerApprovalRefusal || e instanceof approval.ApprovalRefusal) return { ok: false, refusals: [e.message], ...base };
    return { ok: false, refusals: [`the inputs could not be checked: ${e.message}`], ...base };
  }
}

module.exports = { CORE_GENESIS_BY_PLATFORM_CHAIN, servedApprovalToPlain, makeApprovalPageFetcher, anchorFromMetadata,
  readFixedApprovals, verifyLedgerApproval, decideLedgerApprovedCompletion, LedgerApprovalRefusal };
