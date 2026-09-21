/**
 * Publish flow for the pool-ledger contract v11 (v9's REGISTERED five-type E2
 * sibling, built by contractV11.cjs), in registerV9.cjs's shape: the explicit
 * confirm gate, the registration-wide op lock, the durable publish-intent
 * marker before the irreversible broadcast, and the locked owned-key writes
 * (CONTRACT_V11_PENDING / CONTRACT_V11_ID, protected in envStore for the same
 * silent-republish reason as the v8 and v9 pairs).
 *
 * WHAT v11 ADDS OVER THAT SHAPE is the SCHEMA REGISTRATION gate from the E2
 * build spec's gate matrix, enforced HERE because this is the one place the
 * irreversible act happens:
 *
 *   1. THE D1 REGISTER-GATE ASSERTIONS (tegara/docs/E2_D1_CARRIER_BOUNDS.md,
 *      section 5): the derived carrier bounds cover the schema capacities for
 *      the LIVE pin's chainId length, through the battery's own
 *      assertD1Coverage, never a re-derivation here.
 *   2. THE CONTRACT-SIZE DETERMINATION (same document, section 6), the relabel
 *      owed to this file: at the pinned commit
 *      estimated_contract_max_serialized_size (16384) is consumed only in the
 *      estimated-costs branch, so it is a FEE-ESTIMATION figure, kept here as
 *      a conservative bound on the serialized contract; the registration
 *      constraint proper is max_state_transition_size (20480) on the COMPLETE
 *      SIGNED contract-create transition, asserted separately below, before
 *      the broadcast.
 *   3. THE PRE-REGISTRATION CAPTURE BATTERY, the two-phase gate order's first
 *      phase: publication proceeds only over a battery report this module
 *      RE-CHECKS against the module's own roster (the runner is not trusted
 *      with the roster), every case PASS, same cases, same order. WIDTH,
 *      STATED: this re-check establishes REPORT SHAPE, not execution; a
 *      runner fabricating a roster-shaped report defeats it, so the evidence
 *      that cases actually RAN is the runner's own (the live driver wires
 *      e2CaptureBattery.runPreRegistrationPhase, whose roster machinery refuses
 *      a missing case implementation, that module's own tested behaviour).
 *   4. THE E2 NAMESPACE STAYS CLOSED BY THIS ACT: registration writes the id
 *      pair into the environment store and NOTHING else there (the live
 *      battery necessarily writes its own probe records on its own contract
 *      first). E2_GATE_CAPTURE is written only by the battery's
 *      one-shot canonical phase (e2CaptureBattery.runCanonicalPhase), strictly
 *      after this flow returns. That every E2 writer consults the strict
 *      lookup before writing is the SPEC's design and those writers' own
 *      acceptance evidence, not established here. A pre-existing gate key on
 *      an env with no CONTRACT_V11_ID is refused as inconsistent rather than
 *      republished over.
 *
 * The live pieces are injected (the offline dry-run test drives the refusal
 * and completion paths it names, with no broadcast), WHICH BOUNDS THE
 * DURABILITY CLAIMS: the durable intent
 * marker, the protected owned-key writes and the registration-wide lock hold
 * under the DEFAULT env-store deps (the live driver uses the defaults); an
 * injected replacement carries its own duties, and the injection seam exists
 * for the offline test, never as a supported way around the duties.
 * deps.buildContract() -> { contract } where contract is
 * the WASM object for the EXACT buildV11 publication payload (bytes() is the
 * serialized contract, id the identifier); deps.buildSignedTransition(contract)
 * -> { transition } signed and ready (bytes() is the complete signed
 * transition); deps.broadcastTransition(transition) -> the mounted wrapper's
 * outcome literal, whose truth is the WRAPPER's evidence (this module reads
 * the literal and performs no proof binding of its own);
 * deps.runPreRegistrationBattery() -> the roster report from
 * e2CaptureBattery.runPreRegistrationPhase. The live driver is
 * registerV11Run.mjs.
 */
const envStore = require("./envStore.cjs");
const battery = require("./e2CaptureBattery.cjs");
const { decodeId32 } = require("./formationCore.cjs");

const refuse = (why) => { throw new Error(`registerV11: ${why}`); };

// The pinned platform limits this gate consumes (E2_BUILD_SPEC.md, "The pinned
// platform limits", read at platform commit 37ea011c87, SYSTEM_LIMITS_V2 for
// protocol version 12). CONSUMED here, never re-derived; a change at the pin
// is a change to the spec's table first.
const PLATFORM_LIMITS = Object.freeze({
  // a fee-estimation figure at the pinned commit (its single consuming site is
  // the estimated-costs branch), kept as a conservative bound per the D1
  // document's contract-size determination
  estimatedContractMaxSerializedSize: 16384,
  // the registration constraint proper: the complete signed transition
  maxStateTransitionSize: 20480,
});

/**
 * The D1 register-gate assertions (D1 document, section 5) plus the
 * conservative contract-size bound (section 6). Pure and synchronous so the
 * dry-run test exercises exactly what the live flow runs. Returns the coverage
 * report; any failure refuses.
 */
const assertRegisterGate = ({ pinChainId, serializedContractLength }) => {
  if (typeof pinChainId !== "string" || pinChainId.length === 0) {
    refuse("the register gate needs the stored pin's chainId member; E2_EXPECTED_CHAIN_ID must be set before registration (the gate matrix's pin requirement)");
  }
  const coverage = battery.assertD1Coverage({
    chainIdByteLength: Buffer.byteLength(pinChainId, "utf8"),
  });
  if (!Number.isSafeInteger(serializedContractLength) || serializedContractLength < 1) {
    refuse("the register gate needs the serialized contract's byte length as a positive integer");
  }
  if (serializedContractLength > PLATFORM_LIMITS.estimatedContractMaxSerializedSize) {
    refuse(`the serialized v11 contract is ${serializedContractLength} bytes, over the ` +
      `${PLATFORM_LIMITS.estimatedContractMaxSerializedSize}-byte conservative bound (a fee-estimation ` +
      "figure at the pinned commit, kept per the D1 contract-size determination; the registration " +
      `constraint proper is the ${PLATFORM_LIMITS.maxStateTransitionSize}-byte cap on the complete ` +
      "signed transition, asserted separately before broadcast)");
  }
  return { coverage, serializedContractLength, limits: PLATFORM_LIMITS };
};

/**
 * The battery-report re-check: the report must name EXACTLY the
 * pre-registration roster's cases, in roster order, every verdict PASS. An
 * absent, partial, reordered, renamed or padded report refuses. WIDTH: this
 * establishes the report's SHAPE against the roster, never that the cases
 * executed; a runner fabricating a conforming report defeats it, and the
 * execution evidence belongs to the runner (the live driver wires the real
 * phase driver). Returns the case count it verified.
 */
const assertBatteryReportGreen = (report) => {
  const roster = battery.PRE_REGISTRATION_ROSTER;
  if (!Array.isArray(report)) {
    refuse("the pre-registration battery report is absent or not an array; registration is gated on the battery, and a missing report never passes");
  }
  if (report.length !== roster.length) {
    refuse(`the battery report carries ${report.length} cases where the roster requires ${roster.length}; a partial or padded run never gates registration open`);
  }
  for (let i = 0; i < roster.length; i++) {
    const r = report[i];
    if (!r || r.case !== roster[i]) {
      refuse(`battery report entry ${i} is ${(r && JSON.stringify(r.case)) || "absent"} where the roster requires ${JSON.stringify(roster[i])} (same cases, same order; the runner is not trusted with the roster)`);
    }
    if (r.verdict !== "PASS") {
      refuse(`battery case ${r.case} reports ${JSON.stringify(r.verdict)}, not PASS; registration stays closed`);
    }
  }
  return roster.length;
};

// the registration lineage's id accessor (the probe publisher's shape): the
// WASM identifier exposes base58(), the official lineage toString(); either
// route must yield a base58 string that DECODES to 32 raw bytes, checked
// here, because any object answers toString() with something ("[object
// Object]" is a string, not an identifier; the check named it)
const contractIdOf = (contract) => {
  const raw = contract && contract.id;
  const id = raw && (typeof raw.base58 === "function" ? raw.base58() : raw.toString());
  if (!id || typeof id !== "string" || decodeId32(id) === null) {
    refuse("the created contract carries no identifier that decodes to 32 raw bytes via base58");
  }
  return id;
};

/**
 * The publish flow. deps.confirmed must be literally true (the live driver
 * maps REGISTER_V11_CONFIRM=1 onto it); deps.force re-runs past a recorded
 * publish intent with no saved id, after the human orphan check, exactly as
 * REGISTER_V9_FORCE did. Returns { alreadyPublished, contractId, ... }; every
 * gate failure throws with the pending marker in whatever state the text of
 * the refusal names.
 */
const registerV11 = async ({ deps }) => {
  if (!deps) refuse("registerV11 needs deps");
  for (const k of ["buildContract", "buildSignedTransition", "broadcastTransition", "runPreRegistrationBattery"]) {
    if (typeof deps[k] !== "function") refuse(`registerV11 needs deps.${k}`);
  }
  if (deps.confirmed !== true) {
    refuse("publishing v11 opens a NEW contract namespace in this env, costs a nonce and a fee, and is not undoable; run with REGISTER_V11_CONFIRM=1 only when this env genuinely needs its v11 instance");
  }
  const readEnv = deps.readEnv || (() => envStore.loadEnv());
  const writeEnvKey = deps.writeEnvKey || ((k, v) => envStore.updateEnvKey(k, v));
  const acquireLock = deps.acquireOpLock || (() => envStore.acquireOpLock("registerV11"));
  const releaseLock = deps.releaseOpLock || (() => envStore.releaseOpLock("registerV11"));

  acquireLock();
  try {
    const env = readEnv(); // read under the lock, the registerV9 rule
    if (env.CONTRACT_V11_ID !== undefined) {
      // presence alone is not proof of prior publication: a damaged or
      // hand-edited store can carry any truthy value, and treating it as the
      // canonical id would skip every gate below (the check named
      // it). The stored id must decode like the id this flow itself writes.
      if (typeof env.CONTRACT_V11_ID !== "string" || decodeId32(env.CONTRACT_V11_ID) === null) {
        refuse("CONTRACT_V11_ID is set but does not decode to a 32-byte base58 identifier; this store is inconsistent and needs a human decision, never a silent republish or a silent no-op");
      }
      return { alreadyPublished: true, contractId: env.CONTRACT_V11_ID };
    }
    // ANY defined marker value blocks, not only the "1" this flow writes: a
    // corrupted or foreign value is MORE suspicious than the expected one,
    // never less (the check named the any-other-value hole)
    if (env.CONTRACT_V11_PENDING !== undefined && deps.force !== true) {
      refuse("a prior v11 publish recorded intent (CONTRACT_V11_PENDING) but no CONTRACT_V11_ID, so a previous run may have published a contract whose id was never saved; check the publishing identity's contracts for an orphan before republishing, and re-run with force only when none exists");
    }
    if (env[battery.GATE_KEY] !== undefined) {
      refuse(`${battery.GATE_KEY} is set on an env that carries no CONTRACT_V11_ID; a gate artifact cannot precede the contract it certifies, and the key's write-once class makes this a human decision, never a republish over it`);
    }
    const pinChainId = deps.pinChainId !== undefined ? deps.pinChainId : envStore.readChainIdPin().chainId;

    // gate 1, run FIRST because it is free: the pin's presence and the D1
    // coverage assertions (assertRegisterGate re-runs both later beside the
    // size bound, so the pure function stays whole and testable)
    if (typeof pinChainId !== "string" || pinChainId.length === 0) {
      refuse("the register gate needs the stored pin's chainId member; E2_EXPECTED_CHAIN_ID must be set before registration (the gate matrix's pin requirement)");
    }
    battery.assertD1Coverage({ chainIdByteLength: Buffer.byteLength(pinChainId, "utf8") });

    // gate 3: the pre-registration battery, re-checked against the roster.
    // It runs BEFORE the payload is built because the live battery consumes
    // identity nonces (the probe publication, the credit transfer) and the
    // contract identifier derives from owner plus nonce. WIDTH: this module
    // keeps ONE contract reference from buildContract through the signer and
    // the id write, so measured, signed and recorded refer to one object;
    // that the driver builds it under a nonce still fresh at broadcast is the
    // driver's obligation, not established here.
    const batteryCases = assertBatteryReportGreen(await deps.runPreRegistrationBattery());

    // gate 2a: the conservative contract-size bound, over the length THIS
    // module measures from the payload object (never a length the builder
    // reports about itself)
    const built = await deps.buildContract();
    const contract = built && built.contract;
    if (!contract || typeof contract.bytes !== "function") {
      refuse("deps.buildContract must return the contract WASM object (bytes() is the serialized payload)");
    }
    // the measurement demands REAL BYTES: an arbitrary object with a numeric
    // length member would satisfy a bare .length read while carrying no
    // serialized encoding at all (the check named it)
    const contractBytes = contract.bytes();
    if (!(contractBytes instanceof Uint8Array)) {
      refuse("the contract's bytes() must yield a byte view (Uint8Array); an object with a length member is not a serialization");
    }
    const serializedContractLength = contractBytes.length;
    const gate = assertRegisterGate({ pinChainId, serializedContractLength });
    // the identifier is validated BEFORE anything irreversible: a payload
    // whose id cannot be stored must refuse while refusing is still free
    const contractId = contractIdOf(contract);

    // gate 2b: the registration constraint proper, on the COMPLETE SIGNED
    // transition, measured here and refused BEFORE any intent is recorded or
    // any byte is broadcast
    const signedBuilt = await deps.buildSignedTransition(contract);
    const transition = signedBuilt && signedBuilt.transition;
    if (!transition || typeof transition.bytes !== "function") {
      refuse("deps.buildSignedTransition must return the signed transition (bytes() is the complete signed encoding)");
    }
    // the cap is measured over REAL BYTES (the same rule as the payload above:
    // a bare object with a numeric length member passes nothing here), and
    // the measured bytes are RETAINED so the article broadcast below can be
    // compared byte-for-byte against the article measured (reference identity
    // alone does not establish byte stability; the check named it)
    const signedBytes = transition.bytes();
    if (!(signedBytes instanceof Uint8Array)) {
      refuse("the signed transition's bytes() must yield a byte view (Uint8Array); an unmeasurable article never passes the size cap");
    }
    const measuredSignedBytes = Buffer.from(signedBytes);
    const signedTransitionLength = measuredSignedBytes.length;
    if (signedTransitionLength < 1) {
      refuse("the signed transition's bytes() yields zero bytes; an empty article never passes the size cap");
    }
    if (signedTransitionLength > PLATFORM_LIMITS.maxStateTransitionSize) {
      refuse(`the complete signed contract-create transition is ${signedTransitionLength} bytes, over ` +
        `max_state_transition_size ${PLATFORM_LIMITS.maxStateTransitionSize}; nothing was broadcast`);
    }

    // intent, durably, before the irreversible broadcast (the registerV8 shape)
    writeEnvKey("CONTRACT_V11_PENDING", "1");
    const outcome = await deps.broadcastTransition(transition);
    if (!outcome || outcome.outcome !== "verified-proof") {
      refuse("the v11 publication did not commit with a verified proof " +
        `(outcome=${outcome && outcome.outcome}` +
        `${outcome && outcome.message ? `, message: ${String(outcome.message).slice(0, 160)}` : ""}` +
        "); CONTRACT_V11_PENDING stays set so the next run performs the orphan check");
    }
    // the article that was measured is the article that committed: a drift in
    // the transition's bytes across the broadcast means the recorded id would
    // describe an article this gate never measured, so it refuses with the
    // intent marker standing (the orphan check owns the recovery)
    const postBytes = transition.bytes();
    if (!(postBytes instanceof Uint8Array) || !measuredSignedBytes.equals(Buffer.from(postBytes))) {
      refuse("the transition's bytes changed across the broadcast; the measured article and the committed article cannot be confirmed as one, so CONTRACT_V11_PENDING stays set for the orphan check");
    }
    writeEnvKey("CONTRACT_V11_ID", contractId);
    writeEnvKey("CONTRACT_V11_PENDING", undefined); // intent discharged
    return { alreadyPublished: false, contractId, gate, batteryCases, signedTransitionLength };
  } finally {
    releaseLock();
  }
};

module.exports = { PLATFORM_LIMITS, assertRegisterGate, assertBatteryReportGreen, contractIdOf, registerV11 };
