/**
 * WHETHER A SIGNED TRANSITION'S NONCE CAN STILL EXECUTE, decided the way Platform decides it.
 *
 * Mirrors rs-dpp `validate_identity_nonce_update` in `packages/rs-dpp/src/identity/identity_nonce.rs`
 * at the pinned `37ea011c87`, which Platform applies to an identity's credit transfers (the identity
 * nonce) and to its document writes (the per-contract nonce, `batch/identity_contract_nonce/v0`). A
 * stored nonce is one 64-bit value. Its low 40 bits are the tip, the highest nonce used. Its high 24
 * bits mark SKIPPED nonces below the tip, the only ones below the tip that can still be used. Against
 * a transition nonce n and a stored value, the rule is:
 *   n equal to the tip                 refused, already present at the tip
 *   n above the tip by at most 24      accepted
 *   n above the tip by more than 24    refused FOR NOW, too far in the future
 *   n below the tip by more than 24    refused, too far in the past
 *   n below the tip by 1 to 24         accepted only if n's bit in the skipped mask is set,
 *                                      otherwise refused as already present in the past
 *
 * THE ANSWER THAT MATTERS HERE IS "NEVER": the three refusals that can never turn into acceptance,
 * because the tip only grows and a used nonce stays used. "never" says the bytes cannot execute from
 * now on. It does NOT say they never executed, since a transition's own execution uses its nonce too.
 * Whether it executed is established separately, from the ledger.
 *
 * THE INPUT MUST BE THE RAW STORED VALUE, bitmask included. The SDK's nonce readers mask it off, and
 * without it a nonce 1 to 24 below the tip cannot be classified, which is the common case: the
 * signer's next transition usually takes the very nonce a stalled one carried.
 */
const VALUE_FILTER = 0xFFFFFFFFFFn;
const MISSING_FILTER = 0xFFFFFF0000000000n;
const WINDOW = 24n;
const VALUE_BITS = 40n;

const refuse = (why) => { throw new Error(`e2NonceWindow: ${why}; refusing`); };

/**
 * nonceUsability({ transitionNonce, rawExisting }) ->
 *   { verdict: "executable" | "never" | "not-yet", reason, tip }
 */
const nonceUsability = ({ transitionNonce, rawExisting } = {}) => {
  if (typeof transitionNonce !== "bigint" || transitionNonce < 1n || transitionNonce > VALUE_FILTER) {
    refuse("the transition nonce must be a bigint from 1 to 2^40 - 1");
  }
  if (typeof rawExisting !== "bigint" || rawExisting < 0n || rawExisting > 0xFFFFFFFFFFFFFFFFn) {
    refuse("the stored nonce must be the raw 64-bit value as a bigint");
  }
  const tip = rawExisting & VALUE_FILTER;
  const missing = rawExisting & MISSING_FILTER;
  if (transitionNonce === tip) return { verdict: "never", reason: "at-tip", tip };
  if (transitionNonce > tip) {
    return transitionNonce - tip > WINDOW
      ? { verdict: "not-yet", reason: "too-far-in-future", tip }
      : { verdict: "executable", reason: "above-tip", tip };
  }
  const below = tip - transitionNonce;
  if (below > WINDOW) return { verdict: "never", reason: "too-far-in-past", tip };
  // the source reads a zero mask as "already set", then tests the one bit for this position
  if (missing === 0n) return { verdict: "never", reason: "used", tip };
  const bit = 1n << (below - 1n + VALUE_BITS);
  return (missing | bit) !== missing
    ? { verdict: "never", reason: "used", tip }
    : { verdict: "executable", reason: "skipped", tip };
};

module.exports = { nonceUsability, WINDOW, VALUE_FILTER, MISSING_FILTER };
