/**
 * The E2 outcome classifier (duty D9's frozen C2 contract, the classifier half).
 * It accepts EXACTLY one wrapper result object, one of the four CLOSED literals
 * the build spec's C2 section defines, and returns EXACTLY one literal token:
 *
 *   "success-with-proof"           <- { outcome: "verified-proof", ... }
 *   "execution-error-unique-index" <- { outcome: "execution-refusal", ... } whose
 *                                     structured code matches the PINNED
 *                                     unique-index consensus-error identity
 *   "execution-error-other"        <- every other execution-refusal
 *   "ambiguous"                    <- malformed-response and transport-failure
 *
 * The CALLER selects the outcome table's column for its own object (header,
 * reservation, transfer) and applies that column's row for the token; this
 * module carries no operation context by design (specification revision 27, finding 3).
 *
 * THE UNIQUE-INDEX IDENTITY IS A PINNING-TIME READ (specification revision 10, finding 11:
 * the exact structured consensus-error identity is read from the pinned
 * protocol definitions and recorded beside the client pins, with fixtures for
 * header and reservation uniqueness). The installed packages carry no such
 * enumeration (verified during this build unit), so UNTIL THE PIN LANDS the
 * identity below is null and EVERY refusal classifies as
 * "execution-error-other". THIS MODULE CLAIMS TOKEN ROUTING ONLY (the
 * batched checker's finding 5): the run-level consequence, that the
 * other-error rows stop at a human decision and are strictly more
 * conservative than the fetch-and-compare continuation, is the procedure
 * consumer's behaviour and is execution-tested there when it lands. The
 * closed fallbacks are the spec's: an UNKNOWN structured code is
 * "execution-error-other" (the ledger processed and refused; which refusal
 * is unknown), a PINNED code whose promised data payload does not decode is
 * MALFORMED and classifies "ambiguous", never as an execution error, and
 * message-text matching is non-conforming and absent here.
 *
 * Input discipline: the wrapper result is a CLOSED object. A missing member,
 * a wrong type, an unknown `outcome`, or ANY extra member REFUSES loudly (an
 * extra member is a defect per the contract), because classifying a shape the
 * contract does not define would launder a wrapper bug into a recovery path.
 */

// null until the pinning-time read lands; then the STRUCTURAL identity
// recorded beside the client pins, covering BOTH the consensus-error code and
// the error data's decoded shape (the frozen contract's identity is
// structural, not a bare integer; the batched checker's finding 4), with the
// uniqueness fixtures proving it against real header and reservation
// refusals. The pinned form is
//   { code: <integer>, dataMatches: (dataHex) => true | false | "malformed" }
// where dataMatches returns "malformed" when the data bytes cannot be decoded
// as the refusal payload the code promises; per the closed fallbacks, a
// MALFORMED payload classifies AMBIGUOUS, never as an execution error.
const UNIQUE_INDEX_IDENTITY = null;

const TOKENS = Object.freeze({
  SUCCESS: "success-with-proof",
  UNIQUE: "execution-error-unique-index",
  OTHER: "execution-error-other",
  AMBIGUOUS: "ambiguous",
});

const HEX_RE = /^([0-9a-f]{2})*$/;

const refuse = (why) => {
  throw new Error(`e2Outcome: the wrapper result is outside the closed contract (${why}); ` +
    "refusing to classify an undefined shape");
};

const requireClosedMembers = (obj, members) => {
  for (const m of members) if (!(m in obj)) refuse(`missing member ${m}`);
  for (const k of Object.keys(obj)) {
    if (!members.includes(k)) refuse(`extra member ${k}`);
  }
};

// The optional second argument exists for the TEST SUITE ONLY, so the
// pinned-identity branches are executable before the real pin lands; a
// production caller passes nothing and gets the module constant. This is a
// governed escape hatch: narrow (one parameter), observable (any use outside
// the test file is a review finding), and it disappears into the constant
// when the pinning-time read lands.
const classifyOutcome = (result, identityForTest) => {
  const IDENTITY = identityForTest === undefined ? UNIQUE_INDEX_IDENTITY : identityForTest;
  return classifyWith(result, IDENTITY);
};
const classifyWith = (result, IDENTITY) => {
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    refuse("not an object");
  }
  switch (result.outcome) {
    case "verified-proof": {
      requireClosedMembers(result, ["outcome", "proof", "metadata", "proofMsg",
        "metadataMsg", "unknownFieldsDropped"]);
      if (!result.proof || typeof result.proof !== "object") refuse("proof is not an object");
      if (!result.metadata || typeof result.metadata !== "object") refuse("metadata is not an object");
      if (typeof result.proofMsg !== "string" || !HEX_RE.test(result.proofMsg) || result.proofMsg.length === 0) {
        refuse("proofMsg is not nonempty lowercase hex");
      }
      if (typeof result.metadataMsg !== "string" || !HEX_RE.test(result.metadataMsg) || result.metadataMsg.length === 0) {
        refuse("metadataMsg is not nonempty lowercase hex");
      }
      if (!Number.isSafeInteger(result.unknownFieldsDropped) || result.unknownFieldsDropped < 0) {
        refuse("unknownFieldsDropped is not a non-negative integer");
      }
      return TOKENS.SUCCESS;
    }
    case "execution-refusal": {
      requireClosedMembers(result, ["outcome", "code", "data", "message"]);
      if (!Number.isSafeInteger(result.code)) refuse("code is not an integer");
      if (typeof result.data !== "string" || !HEX_RE.test(result.data)) {
        refuse("data is not lowercase hex");
      }
      if (typeof result.message !== "string") refuse("message is not a string");
      if (IDENTITY !== null && result.code === IDENTITY.code) {
        const m = IDENTITY.dataMatches(result.data);
        if (m === true) return TOKENS.UNIQUE;
        // the closed fallback: error data the pinned code promises but which
        // does not decode is MALFORMED, and malformed error data classifies
        // AMBIGUOUS, never as an execution error
        if (m === "malformed") return TOKENS.AMBIGUOUS;
        // decodable data that is simply not a unique-index payload: the
        // ledger processed and refused, which refusal is unknown
        return TOKENS.OTHER;
      }
      // unknown code, or the identity not yet pinned: the ledger processed and
      // refused, which refusal is unknown; fail-closed to the terminal rows
      return TOKENS.OTHER;
    }
    case "malformed-response": {
      requireClosedMembers(result, ["outcome", "reason"]);
      if (typeof result.reason !== "string" || result.reason.length === 0) {
        refuse("reason is not a nonempty string");
      }
      return TOKENS.AMBIGUOUS;
    }
    case "transport-failure": {
      requireClosedMembers(result, ["outcome", "reason"]);
      if (typeof result.reason !== "string" || result.reason.length === 0) {
        refuse("reason is not a nonempty string");
      }
      return TOKENS.AMBIGUOUS;
    }
    default:
      return refuse(`unknown outcome ${JSON.stringify(result.outcome)}`);
  }
};

module.exports = { classifyOutcome, TOKENS, UNIQUE_INDEX_IDENTITY };
