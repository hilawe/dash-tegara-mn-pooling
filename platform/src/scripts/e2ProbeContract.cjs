/**
 * THE DISPOSABLE PROBE CONTRACT (the battery definition's pre-registration
 * phase): a harness-published sibling whose five document-type schemas are
 * BYTE-IDENTICAL to buildV11's E2 types, under a throwaway identifier. It
 * establishes acceptance, encoding, verification and journal mechanics for
 * the battery BEFORE the canonical v11 contract exists, so the canonical
 * publication gate never depends on evidence only that publication could
 * produce.
 *
 * WHAT THE PROBE CONTRACT IS NOT: it is never selected by the version table,
 * its records carry no entitlement meaning, and nothing may read its
 * identifier from anywhere but the battery run that published it. It
 * deliberately contains ONLY the five E2 types: the battery's fixture and
 * header cases exercise those types' schemas, and carrying v9's pool types
 * would put entitlement-shaped records on a contract whose records must
 * never mean anything.
 *
 * The byte-identity claim, at its real width: probeSchemas() derives the five
 * types FROM buildV11's own output (the same objects, no transcription), and
 * the test asserts canonical equality against buildV11 directly, which
 * establishes PRESENT identity between two derivations of one source. A
 * coordinated change to buildV11 moves both sides together; the guard against
 * THAT is contractV11Test's exact-diff pin against buildV9, not this module.
 */
const { buildV11, E2_TYPES } = require("./contractV11.cjs");

/**
 * The five E2 type schemas, taken from buildV11's output for the given base
 * contract. Returns a fresh object containing exactly the five types.
 */
const probeSchemas = (poolLedgerContract) => {
  const v11 = buildV11(poolLedgerContract);
  const out = {};
  for (const t of E2_TYPES) {
    if (!v11[t]) throw new Error(`e2ProbeContract: buildV11 is missing the E2 type ${t}`);
    out[t] = v11[t];
  }
  return out;
};

/**
 * Publish the probe contract through the injected SDK route. deps supplies
 * the live pieces so the offline test can drive the flow with mocks:
 *   deps.identityId        the publishing identity (base58 string)
 *   deps.identityNonce()   -> next identity nonce (bigint)
 *   deps.createContract(ownerId, nonce, schemas) -> the contract object
 *   deps.broadcastCreate(contract, nonce) -> the wrapper outcome literal
 * Returns { contractId, outcome }; refuses unless the outcome is the
 * wrapper's verified-proof literal, because a probe contract whose
 * publication was not proof-verified would put every later battery case on
 * an unverified foundation.
 */
const publishProbeContract = async ({ poolLedgerContract, deps }) => {
  for (const k of ["identityNonce", "createContract", "broadcastCreate"]) {
    if (typeof (deps && deps[k]) !== "function") {
      throw new Error(`e2ProbeContract: publishProbeContract needs deps.${k}`);
    }
  }
  if (typeof deps.identityId !== "string" || deps.identityId.length === 0) {
    throw new Error("e2ProbeContract: publishProbeContract needs deps.identityId");
  }
  const schemas = probeSchemas(poolLedgerContract);
  const nonce = await deps.identityNonce();
  const contract = deps.createContract(deps.identityId, nonce, schemas);
  const outcome = await deps.broadcastCreate(contract, nonce);
  if (!outcome || outcome.outcome !== "verified-proof") {
    throw new Error("e2ProbeContract: the probe contract's publication did not commit with a verified proof " +
      `(outcome=${outcome && outcome.outcome}` +
      `${outcome && outcome.message ? `, message: ${String(outcome.message).slice(0, 160)}` : ""}` +
      "); the battery must not run on an unverified foundation");
  }
  const id = contract.id && (contract.id.base58 ? contract.id.base58() : contract.id.toString());
  if (!id) throw new Error("e2ProbeContract: the created contract carries no identifier");
  return { contractId: id, outcome };
};

module.exports = { probeSchemas, publishProbeContract };
