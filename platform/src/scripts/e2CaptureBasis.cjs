/**
 * e2CaptureBasis: THE CAPTURE-BASIS ADAPTER, shared by both live runners (a soundness-review finding).
 * The shared receipt verifier takes one boolean for validity clause 1, "a signature basis
 * verifies" (e2ReceiptVerify.cjs, verifyTransferExecution), and the audit's header-capture
 * check takes the same boolean. Until this module both runners carried a transcribed adapter
 * that reduced the SELECTOR's answer to a boolean: `selectSupersessionBasis` reports WHICH
 * basis remains (a winning supersession record, or the string "original" meaning the
 * original capture's own signature members are the remaining basis), and it returns
 * "original" WITHOUT invoking the signature callback when no matching candidate exists or
 * none verifies. `!!basis.basis` is true for "original", so the common path (a capture with
 * no supersessions) affirmed clause 1 with zero signer-key reads and no signature checked.
 * The same adapter also verified a supersession candidate against ITS OWN bytes, while a
 * supersession signs the ORIGINAL capture's domain-prefixed preimage
 * (e2CaptureRecord.cjs, signSupersession and verifySupersessionSignature), so a valid
 * supersession verified false and the selector fell back to the unchecked original.
 *
 * WHAT THIS MODULE ESTABLISHES, in one sentence: the boolean it answers is true EXACTLY WHEN
 * a signature was verified under a key resolved for its signer, either a matching
 * supersession candidate's signature over the original's preimage (the selector's rules
 * for subject, sequence and malformed candidates kept), or, when the selector answers
 * "original", the original capture's own signature under the original's signer key; a
 * key that cannot be resolved, a selector refusal, a non-boolean verifier answer, or a
 * signature that does not verify all answer false, never true, and the returned promise
 * never rejects (a throwing sink is swallowed and an unreadable thrown value gets a fixed
 * text; the reason is printed through the injected log only when the sink accepts it, so a
 * throwing or no-op sink can leave a false answer with NO printed diagnostic, never a
 * changed boolean). Which of the two bases was used is not recorded in the boolean; the runner's
 * diagnostics and the resolver's calls are where it is observable.
 *
 *   makeVerifyCaptureBasis({ resolveSignerKey, log }) -> async (capture, supersessions) => boolean
 *
 *   resolveSignerKey(record) -> Uint8Array public key   the runner's, resolving
 *                              record.signerIdentity / record.signerKeyId through the
 *                              metadata-retaining published-keys route; a throw is
 *                              CANNOT-VERIFY (false with the reason printed)
 *   log(line)                  the runner's line sink, required
 *
 * WHAT IT DOES NOT ESTABLISH: that the resolved key belongs to the identity (the resolver's
 * route and its proof metadata), that the capture's bytes are the ledger's (the transition-
 * proof stages), or anything about the record's content beyond its signature.
 */
"use strict";

const captureRecord = require("./e2CaptureRecord.cjs");

const refuse = (why) => { throw new Error(`e2CaptureBasis: ${why}; refusing`); };
// the thrown value is untrusted (a resolver may reject with anything, a null-prototype
// object included), so BOTH reads are guarded and a fixed text stands in when neither works
const msgOf = (e) => { try { const m = e && e.message; if (typeof m === "string") return m; } catch { /* fall through */ } try { return String(e); } catch { return "(an unreadable thrown value)"; } };

const makeVerifyCaptureBasis = ({ resolveSignerKey, log } = {}) => {
  if (typeof resolveSignerKey !== "function") refuse("makeVerifyCaptureBasis needs resolveSignerKey, the runner's signer-key resolver");
  if (typeof log !== "function") refuse("makeVerifyCaptureBasis needs an explicit log function (pass a no-op deliberately to suppress the diagnostics)");
  // THE SINK IS OBSERVABILITY, NEVER CONTROL (the discovery factory's rule, and the checker's
  // construction here): a throwing logger must not turn a settled false into a rejection, so
  // every diagnostic goes through a guarded call and the boolean is decided before it
  const tryLog = (s) => { try { log(s); } catch (_) { /* the sink must not decide the answer */ } };
  return async (capture, supersessions) => {
    try {
      // the selector verifies each MATCHING candidate over the ORIGINAL's preimage under the
      // candidate's own resolved key (the supersession rule), and answers the winning
      // candidate or "original"; each callback answer is checked here as a boolean, so a
      // non-boolean from the record module's verifier is a fault on this path too
      const { basis } = await captureRecord.selectSupersessionBasis(capture, supersessions,
        async (candidate) => {
          const v = await captureRecord.verifySupersessionSignature(capture, candidate, await resolveSignerKey(candidate));
          if (typeof v !== "boolean") refuse("verifySupersessionSignature answered a non-boolean");
          return v;
        });
      if (basis !== "original") {
        if (basis === null || typeof basis !== "object") refuse(`the basis selector answered ${basis === null ? "null" : typeof basis}, neither a candidate record nor "original"`);
        return true;   // that candidate's signature over the original's preimage verified in the callback
      }
      // "original" is a basis TO VERIFY, not a verified one: the original capture's own
      // signature under the original signer's resolved key
      const verified = await captureRecord.verifyCaptureSignature(capture, await resolveSignerKey(capture));
      if (typeof verified !== "boolean") refuse("verifyCaptureSignature answered a non-boolean");
      if (!verified) tryLog(`  [capture basis refused] the original capture's signature does not verify under its signer key (${String(capture && capture.signerIdentity).slice(0, 8)}... key ${capture && capture.signerKeyId}) and no supersession verifies`);
      return verified;
    } catch (e) {
      // CANNOT-VERIFY is answered false with the reason printed, never affirmative and
      // never a silent swallow (the two runners' existing diagnostic contract); the text
      // reaches the sink only if the sink accepts it, the boolean regardless
      tryLog(`  [capture basis unresolved] ${msgOf(e)}`);
      return false;
    }
  };
};

module.exports = { makeVerifyCaptureBasis };
