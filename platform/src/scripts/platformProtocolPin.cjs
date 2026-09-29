/**
 * THE ONE PLATFORM PROTOCOL-VERSION PIN for the E2 code. Every E2 module, runner and probe in this
 * directory that checks the protocolVersion of a proved response's metadata reads it from here:
 * the capture verifier (e2ReceiptVerify), the balance admission (e2BalanceCheck), the runners that
 * pass it into the writer, the final-epoch command and the pool resolution (e2DistributeRun,
 * e2FinalEpochRun), and e2DoubleBroadcastRun, e2FeeMeasureRun, e2BoundsProbe and idRoutesProbe. A
 * response at any other version is refused. OUTSIDE THIS RULE: the fixed-slot reader demo
 * (fixedSlotReaderP8.mjs), a separate lineage that takes its pin from its own signed bundle.
 *
 * WHY 13, decided 2026-09-27. Testnet runs protocol 13, and the value had been 12 in eight separate
 * places, the version of the retired local network. Platform's version tables were compared between
 * 12 and 13 (packages/rs-platform-version at tag v4.1.1, with v13.rs, drive_versions/v8.rs, the
 * verify method versions and system_limits/v3.rs also read at master, where the fields version 13
 * has are unchanged and only fields for later versions were added; the running Drive image reports
 * 4.1.2, which has no public tag):
 * - the fee version is FEE_VERSION2 in both, so the fee schedule the D2 ceilings were measured
 *   under is unchanged (e2BalanceCheck says what that does and does not carry);
 * - DRIVE_VERIFY_METHOD_VERSIONS_V2 (13) equals V1 (12) except
 *   verify_compacted_address_balance_changes, which nothing here uses, so the state-transition,
 *   document, contract and identity proof checks are selected at the same method versions;
 * - the other components that changed are DPNS username transfers and sales, token validation, a
 *   document nesting-depth limit of 256, contract meta-schema additions (the keeps*History flags,
 *   which the v11 contract does not use), and the recent address-balance set, and
 *   max_state_transition_size stays 20480.
 *
 * WHAT THAT COMPARISON SUPPORTS, AND WHAT IT DOES NOT. The client still verifies under protocol 12
 * rules: dash-platform-sdk 1.4.0's LATEST_PLATFORM_VERSION (PLATFORM_V12) is what
 * verifyStateTransitionResult receives in the runners and what the mounted query and contract
 * patches pass. So accepting 13 maps protocol 13 responses onto protocol 12 verification. Equal
 * method selectors, an equal fee version and equal limits SUPPORT the reading that those checks
 * give the same answers at 13. They do NOT establish it: what those methods reach through other
 * parts of the version table (serialization and parsing among them) was not traced, and that the
 * changed components touch no operation this project performs (document create, contract create
 * and update, credit transfer) is a reading of the change list, not a trace. The live evidence at
 * 13 so far is the health check's proved contract read with its wrong-key control
 * (docs/TESTNET_SERVER.md). The protocol version itself is signed over, since stage two's StateId
 * carries it as appVersion (tegara/docs/E2_BUILD_SPEC.md, "STAGE TWO").
 *
 * EXACTLY ONE VALUE, not a set. The local network that ran 12 is retired, so accepting 12 would widen
 * the claim to a network in no use. A move to 14 refuses everywhere until this comparison is redone
 * for it, which is the intended failure.
 */
const PROTOCOL_VERSION_PIN = 13;

module.exports = { PROTOCOL_VERSION_PIN };
