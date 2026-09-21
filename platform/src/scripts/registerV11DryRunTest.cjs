/**
 * Offline dry-run test for registerV11 (plain `node`, no network, NO
 * BROADCAST anywhere): builds the REAL publish payload (buildV11 over the
 * dist lineage, serialized by the same WASM constructor the live route uses)
 * and measures it against the register gate; drives every branch of the flow
 * over injected deps and spies (the refusal and completion paths named in
 * each block below, not literally every branch); and proves the
 * capture-battery gate wiring from both sides, publication refused unless
 * the battery report re-checks green, and no gate key written by a
 * completed registration (the strict lookup refuses over this env).
 *
 * The two owned-key cases at the end run against the REAL env store on a
 * throwaway TEGARA_ENV_PATH, so the pending/id pair is exercised through
 * updateEnvKey and the op lock rather than through mocks.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

// the env store is pointed at a throwaway file BEFORE any module loads it
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "regv11-"));
process.env.TEGARA_ENV_PATH = path.join(TMP, ".env.test");
fs.writeFileSync(process.env.TEGARA_ENV_PATH, "");
fs.mkdirSync(process.env.TEGARA_ENV_PATH + ".state", { recursive: true });

const battery = require("./e2CaptureBattery.cjs");
const envStore = require("./envStore.cjs");
const { buildV11 } = require("./contractV11.cjs");
const { PLATFORM_LIMITS, assertRegisterGate, assertBatteryReportGreen, contractIdOf, registerV11 } =
  require("./registerV11.cjs");
const bs58 = require("bs58");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const eq = (name, got, want) => {
  if (got === want) passed++;
  else { failed++; console.error(`FAIL: ${name} (got ${JSON.stringify(got)}, want ${JSON.stringify(want)})`); }
};
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};
const rejects = async (name, p, re) => {
  try { await p; failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

const PIN = "dashmate_local_52"; // a live-shaped pin value (17 bytes), not a claim about the current env
// mock contract identifiers must be REAL base58 32-byte ids, because
// contractIdOf refuses anything that does not decode (the fold)
const MOCK_ID = bs58.encode(Buffer.alloc(32, 0x2a));
const MOCK_ID2 = bs58.encode(Buffer.alloc(32, 0x2b));

(async () => {

// ---------------------------------------------------------------------------
// assertRegisterGate
// ---------------------------------------------------------------------------
{
  throws("an absent pin refuses", () => assertRegisterGate({ pinChainId: undefined, serializedContractLength: 100 }),
    /E2_EXPECTED_CHAIN_ID must be set/);
  throws("an empty pin refuses", () => assertRegisterGate({ pinChainId: "", serializedContractLength: 100 }),
    /E2_EXPECTED_CHAIN_ID must be set/);
  throws("a missing contract length refuses", () => assertRegisterGate({ pinChainId: PIN, serializedContractLength: undefined }),
    /serialized contract's byte length/);
  throws("a zero contract length refuses", () => assertRegisterGate({ pinChainId: PIN, serializedContractLength: 0 }),
    /serialized contract's byte length/);

  const atBound = assertRegisterGate({ pinChainId: PIN,
    serializedContractLength: PLATFORM_LIMITS.estimatedContractMaxSerializedSize });
  ok("exactly 16384 serialized bytes passes the conservative bound",
    atBound.serializedContractLength === 16384);
  eq("the coverage report carries the three D1 checks", atBound.coverage.length, 3);
  ok("every coverage check holds for the live-shaped pin", atBound.coverage.every((c) => c.holds === true));
  // identity, not only the aggregate: the three checks are the documented ones
  eq("the coverage checks are the three documented D1 checks, by name",
    atBound.coverage.map((c) => c.name).join("; "),
    "metadata capacity covers the derived maximum; " +
    "the 8-part capacity covers the derived proofMsg maximum; " +
    "the worst-case part count stays in the schema domain");

  throws("16385 serialized bytes refuses, naming the bound's fee-estimation role",
    () => assertRegisterGate({ pinChainId: PIN,
      serializedContractLength: PLATFORM_LIMITS.estimatedContractMaxSerializedSize + 1 }),
    /fee-estimation/);

  // the D1 metadata coverage boundary for the pin length: 40+1+varint(L)+L <= 512
  // holds through L = 469 and fails at 470 (the D1 document's own statement)
  const longestCovered = assertRegisterGate({ pinChainId: "c".repeat(469), serializedContractLength: 100 });
  ok("a 469-byte pin still passes D1 coverage", longestCovered.coverage.every((c) => c.holds === true));
  throws("a 470-byte pin fails D1 coverage through the gate",
    () => assertRegisterGate({ pinChainId: "c".repeat(470), serializedContractLength: 100 }),
    /D1 coverage fails/);
}

// ---------------------------------------------------------------------------
// assertBatteryReportGreen
// ---------------------------------------------------------------------------
const greenReport = () => battery.PRE_REGISTRATION_ROSTER.map((c) => ({ case: c, verdict: "PASS", detail: null }));
{
  eq("a green roster-exact report passes and returns the case count",
    assertBatteryReportGreen(greenReport()), battery.PRE_REGISTRATION_ROSTER.length);
  throws("an absent report refuses", () => assertBatteryReportGreen(undefined), /missing report never passes/);
  throws("a non-array report refuses", () => assertBatteryReportGreen({ all: "PASS" }), /missing report never passes/);
  throws("an empty report refuses", () => assertBatteryReportGreen([]), /partial or padded/);
  throws("a report one case short refuses", () => assertBatteryReportGreen(greenReport().slice(0, -1)),
    /partial or padded/);
  throws("a report with an extra trailing case refuses",
    () => assertBatteryReportGreen([...greenReport(), { case: "extra", verdict: "PASS" }]), /partial or padded/);
  const reordered = greenReport(); [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
  throws("a reordered report refuses (same cases, same order)", () => assertBatteryReportGreen(reordered),
    /same cases, same order/);
  const renamed = greenReport(); renamed[3] = { ...renamed[3], case: "not-a-roster-case" };
  throws("a renamed case refuses", () => assertBatteryReportGreen(renamed), /roster requires/);
  const oneFail = greenReport(); oneFail[5] = { ...oneFail[5], verdict: "FAIL" };
  throws("one FAIL verdict refuses", () => assertBatteryReportGreen(oneFail), /not PASS; registration stays closed/);
  const noVerdict = greenReport(); delete noVerdict[2].verdict;
  throws("an absent verdict refuses", () => assertBatteryReportGreen(noVerdict), /not PASS/);
  const dup = greenReport(); dup[1] = { ...dup[0] }; // duplicate case 0 in slot 1
  throws("a duplicated case refuses (order equality catches it)", () => assertBatteryReportGreen(dup),
    /roster requires/);
}

// ---------------------------------------------------------------------------
// the flow, over injected deps and spies
// ---------------------------------------------------------------------------
const mkWorld = (over = {}) => {
  const env = { ...(over.env || {}) };
  const events = []; // one ordered log across writes, broadcasts and locks
  const world = {
    env, events,
    contract: {
      bytes: () => new Uint8Array(13350),
      id: { base58: () => MOCK_ID },
    },
    transition: { bytes: () => new Uint8Array(13420) },
  };
  world.deps = {
    confirmed: true,
    pinChainId: PIN,
    readEnv: () => ({ ...env }),
    writeEnvKey: (k, v) => {
      events.push(`write:${k}=${v === undefined ? "<del>" : v}`);
      if (v === undefined) delete env[k]; else env[k] = v;
    },
    acquireOpLock: () => events.push("lock:acquire"),
    releaseOpLock: () => events.push("lock:release"),
    buildContract: async () => { events.push("buildContract"); return { contract: world.contract }; },
    runPreRegistrationBattery: async () => { events.push("battery"); return greenReport(); },
    buildSignedTransition: async () => { events.push("sign"); return { transition: world.transition }; },
    broadcastTransition: async () => { events.push("broadcast"); return { outcome: "verified-proof" }; },
    ...(over.deps || {}),
  };
  return world;
};

{ // refusal without the confirm flag, before any lock or write
  const w = mkWorld({ deps: { confirmed: undefined } });
  await rejects("an unconfirmed run refuses", registerV11({ deps: w.deps }), /REGISTER_V11_CONFIRM=1/);
  eq("an unconfirmed run touches nothing", w.events.length, 0);
}

{ // each missing dep refuses by name
  for (const k of ["buildContract", "buildSignedTransition", "broadcastTransition", "runPreRegistrationBattery"]) {
    const w = mkWorld(); delete w.deps[k];
    await rejects(`a missing deps.${k} refuses`, registerV11({ deps: w.deps }),
      new RegExp(`needs deps\\.${k}`));
  }
}

{ // the happy path, with the ordered event log as the oracle
  const w = mkWorld();
  const r = await registerV11({ deps: w.deps });
  eq("the happy path returns the contract id from the CONTRACT OBJECT", r.contractId, MOCK_ID);
  eq("alreadyPublished is false", r.alreadyPublished, false);
  eq("the battery case count is the roster's", r.batteryCases, battery.PRE_REGISTRATION_ROSTER.length);
  eq("the signed length is measured from the transition's own bytes", r.signedTransitionLength, 13420);
  eq("the gate result carries the measured contract length", r.gate.serializedContractLength, 13350);
  // the battery runs BEFORE the payload is built: the live battery consumes
  // identity nonces and the contract id derives from owner plus nonce, so the
  // measured article and the published article stay one object
  eq("the event order is lock, battery, build, sign, pending, broadcast, id, discharge, release",
    w.events.join("|"),
    "lock:acquire|battery|buildContract|sign|write:CONTRACT_V11_PENDING=1|broadcast|" +
    `write:CONTRACT_V11_ID=${MOCK_ID}|write:CONTRACT_V11_PENDING=<del>|lock:release`);
  eq("the env carries the id afterwards", w.env.CONTRACT_V11_ID, MOCK_ID);
  ok("the pending marker is discharged", w.env.CONTRACT_V11_PENDING === undefined);

  // THE GATE WIRING, the other half, at its width: a completed registration
  // writes no gate key, and the battery's strict lookup refuses over THIS
  // env. That E2 writers actually consult the lookup is those modules' own
  // acceptance evidence, not established here.
  ok("registration writes no gate key", w.env[battery.GATE_KEY] === undefined);
  await rejects("the strict lookup still refuses after registration (the E2 namespace stays closed)",
    battery.verifyGateCapture({ deps: {
      resolveCaptureByKey: async () => null,
      resolveSignerKey: async () => new Uint8Array(33),
      readEnv: () => ({ ...w.env }),
    } }),
    /absent or not a string/);
}

{ // already published is a no-op that consults nothing else, and presence
  // alone is not enough: the stored id must decode like the id this flow
  // itself writes (any other value marks a damaged or hand-edited store)
  const w = mkWorld({ env: { CONTRACT_V11_ID: MOCK_ID2 } });
  const r = await registerV11({ deps: w.deps });
  eq("an already-published env answers with the stored id", r.contractId, MOCK_ID2);
  eq("alreadyPublished is true", r.alreadyPublished, true);
  eq("nothing runs beyond the lock pair", w.events.join("|"), "lock:acquire|lock:release");

  const bad = mkWorld({ env: { CONTRACT_V11_ID: "AlreadyThere" } });
  await rejects("a stored id that does not decode refuses instead of answering alreadyPublished",
    registerV11({ deps: bad.deps }), /does not decode to a 32-byte base58 identifier/);
  eq("the inconsistent-store refusal runs nothing beyond the lock pair",
    bad.events.join("|"), "lock:acquire|lock:release");
}

{ // recorded intent with no id refuses without force, proceeds with it
  const w = mkWorld({ env: { CONTRACT_V11_PENDING: "1" } });
  await rejects("pending-without-id refuses (the orphan check)", registerV11({ deps: w.deps }),
    /orphan/);
  ok("the refusal keeps the pending marker", w.env.CONTRACT_V11_PENDING === "1");
  const w2 = mkWorld({ env: { CONTRACT_V11_PENDING: "1" }, deps: { force: true } });
  const r2 = await registerV11({ deps: w2.deps });
  eq("force proceeds past the recorded intent (only force=true is observed; the orphan check itself is the operator's act)", r2.contractId, MOCK_ID);
  // the force path keeps the SHARED order: intent re-recorded before the
  // broadcast, discharged after (a force-conditional reorder must fail here)
  eq("the force path keeps the pending-before-broadcast order",
    w2.events.join("|"),
    "lock:acquire|battery|buildContract|sign|write:CONTRACT_V11_PENDING=1|broadcast|" +
    `write:CONTRACT_V11_ID=${MOCK_ID}|write:CONTRACT_V11_PENDING=<del>|lock:release`);
}

{ // a pre-existing gate key with no id is an inconsistency, never republished over
  const w = mkWorld({ env: { E2_GATE_CAPTURE: "{}" } });
  await rejects("a gate key with no contract id refuses", registerV11({ deps: w.deps }),
    /cannot precede the contract it certifies/);
  // exactly the lock pair: on a store already known inconsistent, nothing may
  // spend (a relocation of this check past the battery must fail here)
  eq("the gate-key refusal runs nothing beyond the lock pair",
    w.events.join("|"), "lock:acquire|lock:release");
}

{ // the pin gate fires inside the flow too
  const w = mkWorld({ deps: { pinChainId: "" } });
  await rejects("an empty pin refuses inside the flow", registerV11({ deps: w.deps }),
    /E2_EXPECTED_CHAIN_ID must be set/);
  ok("no battery runs on a pin refusal", !w.events.includes("battery"));
}

{ // the module measures the payload itself, from bytes(), never a builder claim
  const w = mkWorld();
  w.contract.bytes = () => new Uint8Array(PLATFORM_LIMITS.estimatedContractMaxSerializedSize + 1);
  w.contract.serializedLength = 1; // a decoy self-report the module must ignore
  await rejects("an oversize serialized contract refuses even when the builder self-reports small",
    registerV11({ deps: w.deps }), /fee-estimation/);
  ok("the size refusal signs nothing", !w.events.includes("sign"));
  ok("the size refusal writes no pending marker", !w.events.some((e) => e.startsWith("write:")));
  ok("the size refusal still releases the lock", w.events[w.events.length - 1] === "lock:release");
}

{ // a non-green battery refuses before the payload exists and before any write
  const bad = greenReport(); bad[4] = { ...bad[4], verdict: "FAIL" };
  const w = mkWorld({ deps: { runPreRegistrationBattery: async () => bad } });
  await rejects("a non-green battery refuses", registerV11({ deps: w.deps }), /registration stays closed/);
  ok("no payload is built on a battery refusal", !w.events.includes("buildContract"));
  ok("no transition is signed on a battery refusal", !w.events.includes("sign"));
  ok("no write happens on a battery refusal", !w.events.some((e) => e.startsWith("write:")));
}

{ // the signed-transition cap refuses BEFORE the pending marker and the broadcast
  const w = mkWorld();
  w.transition.bytes = () => new Uint8Array(PLATFORM_LIMITS.maxStateTransitionSize + 1);
  await rejects("a signed transition over 20480 refuses, naming that nothing was broadcast",
    registerV11({ deps: w.deps }), /nothing was broadcast/);
  ok("the oversize-transition refusal broadcasts nothing", !w.events.includes("broadcast"));
  ok("the oversize-transition refusal writes nothing", !w.events.some((e) => e.startsWith("write:")));
}

{ // exactly 20480 signed bytes passes
  const w = mkWorld();
  w.transition.bytes = () => new Uint8Array(PLATFORM_LIMITS.maxStateTransitionSize);
  const r = await registerV11({ deps: w.deps });
  eq("exactly 20480 signed bytes passes the transition cap", r.signedTransitionLength, 20480);
}

{ // a broadcast without a verified proof refuses and KEEPS the intent marker
  const w = mkWorld({ deps: { broadcastTransition: async () => ({ outcome: "execution-refusal", message: "nope" }) } });
  await rejects("a non-verified broadcast outcome refuses", registerV11({ deps: w.deps }),
    /did not commit with a verified proof/);
  eq("the pending marker survives the refused broadcast", w.env.CONTRACT_V11_PENDING, "1");
  ok("no id is written on a refused broadcast", w.env.CONTRACT_V11_ID === undefined);
  ok("the lock is still released", w.events[w.events.length - 1] === "lock:release");
  // and the NEXT run walks into the orphan check
  await rejects("the next run performs the orphan check", registerV11({ deps: { ...w.deps } }), /orphan/);
}

{ // a broadcast that throws (transport) propagates and keeps the marker
  const w = mkWorld({ deps: { broadcastTransition: async () => { throw new Error("socket vanished"); } } });
  await rejects("a broadcast throw propagates", registerV11({ deps: w.deps }), /socket vanished/);
  eq("the pending marker survives the thrown broadcast", w.env.CONTRACT_V11_PENDING, "1");
  ok("no id is written on a thrown broadcast", w.env.CONTRACT_V11_ID === undefined);
  // the EVENT LOG, not only the final state: a write-then-delete of the id
  // would leave the final state clean while the forbidden intermediate state
  // occurred (the check proposed exactly that mutation)
  ok("no id write EVENT ever happens on a thrown broadcast",
    !w.events.some((e) => e.startsWith("write:CONTRACT_V11_ID")));
}

{ // the id comes from the contract object even when the outcome carries a decoy
  const w = mkWorld({ deps: { broadcastTransition: async () => ({ outcome: "verified-proof", contractId: "DecoyFromOutcome" }) } });
  const r = await registerV11({ deps: w.deps });
  eq("the stored id is the contract object's, never the outcome's", r.contractId, MOCK_ID);
  eq("the env id matches", w.env.CONTRACT_V11_ID, MOCK_ID);
  ok("the decoy is never written, even transiently (event log, not final state)",
    !w.events.some((e) => e.includes("DecoyFromOutcome")));
}

{ // ONE ARTICLE through the flow: the signer gets the very contract object the
  // module measured, and the broadcast gets the very transition the signer
  // returned (identity, not shape; the check asked for this binding)
  const w = mkWorld();
  let signerGot = null, broadcastGot = null;
  w.deps.buildSignedTransition = async (c) => { signerGot = c; w.events.push("sign"); return { transition: w.transition }; };
  w.deps.broadcastTransition = async (t) => { broadcastGot = t; w.events.push("broadcast"); return { outcome: "verified-proof" }; };
  await registerV11({ deps: w.deps });
  ok("the signer receives the measured contract object itself", signerGot === w.contract);
  ok("the broadcast receives the signed transition object itself", broadcastGot === w.transition);
}

{ // bytes() must yield a REAL byte view; a bare object with a numeric length
  // member is not a serialization and must refuse, never pass a cap (the
  // check named {length: 1} passing both size checks)
  const w = mkWorld();
  w.transition.bytes = () => ({ not: "bytes" });
  await rejects("an unmeasurable signed transition refuses instead of passing the cap",
    registerV11({ deps: w.deps }), /byte view/);
  ok("the unmeasurable transition broadcasts nothing", !w.events.includes("broadcast"));
  ok("the unmeasurable transition writes nothing", !w.events.some((e) => e.startsWith("write:")));

  const w2 = mkWorld();
  w2.transition.bytes = () => ({ length: 1 });
  await rejects("a length-only object is not a signed transition",
    registerV11({ deps: w2.deps }), /byte view/);
  ok("the length-only transition broadcasts nothing", !w2.events.includes("broadcast"));

  const w3 = mkWorld();
  w3.contract.bytes = () => ({ length: 1 });
  await rejects("a length-only object is not a serialized contract",
    registerV11({ deps: w3.deps }), /byte view/);
  ok("the length-only contract signs nothing", !w3.events.includes("sign"));

  const w4 = mkWorld();
  w4.transition.bytes = () => new Uint8Array(0);
  await rejects("a zero-byte signed transition refuses",
    registerV11({ deps: w4.deps }), /zero bytes/);
}

{ // byte stability across the broadcast: a transition whose bytes drift
  // between the measurement and the committed outcome refuses with the
  // intent marker standing. The drift fixture keeps the SAME LENGTH with
  // different content, so a comparator weakened to length-only fails here
  // (the check proposed exactly that mutation)
  const w = mkWorld();
  let flipped = false;
  w.transition.bytes = () => new Uint8Array(13420).fill(flipped ? 0x01 : 0x00);
  w.deps.broadcastTransition = async () => { flipped = true; return { outcome: "verified-proof" }; };
  await rejects("same-length content drift across the broadcast refuses the id write",
    registerV11({ deps: w.deps }), /changed across the broadcast/);
  eq("the drift refusal keeps the pending marker", w.env.CONTRACT_V11_PENDING, "1");
  ok("the drift refusal writes no id", w.env.CONTRACT_V11_ID === undefined);
}

{ // a contract whose id does not decode refuses BEFORE any intent or broadcast
  // (any object answers toString(); "[object Object]" is not an identifier)
  const w = mkWorld();
  w.contract.id = {};
  await rejects("a non-decoding contract identifier refuses",
    registerV11({ deps: w.deps }), /decodes to 32 raw bytes/);
  ok("the bad-identifier refusal broadcasts nothing", !w.events.includes("broadcast"));
  ok("the bad-identifier refusal writes nothing", !w.events.some((e) => e.startsWith("write:")));

  // valid base58 of the WRONG LENGTH is not an identifier either (a check
  // weakened to "any base58" must fail here; the proposed mutation)
  const w2 = mkWorld();
  w2.contract.id = { base58: () => bs58.encode(Buffer.alloc(16, 0x77)) };
  await rejects("a 16-byte base58 value is not a contract identifier",
    registerV11({ deps: w2.deps }), /decodes to 32 raw bytes/);
  const w3 = mkWorld({ env: { CONTRACT_V11_ID: bs58.encode(Buffer.alloc(16, 0x77)) } });
  await rejects("a 16-byte base58 STORED id refuses instead of answering alreadyPublished",
    registerV11({ deps: w3.deps }), /does not decode to a 32-byte base58 identifier/);
}

{ // the branches listed as unexercised, the cheap ones
  await rejects("no deps at all refuses", registerV11({}), /needs deps/);
  const wNull = mkWorld({ deps: { buildContract: async () => null } });
  await rejects("a null builder result refuses", registerV11({ deps: wNull.deps }), /contract WASM object/);
  const wNoBytes = mkWorld(); wNoBytes.contract = { id: { base58: () => MOCK_ID } };
  wNoBytes.deps.buildContract = async () => ({ contract: wNoBytes.contract });
  await rejects("a contract without callable bytes refuses", registerV11({ deps: wNoBytes.deps }), /contract WASM object/);
  const wNoT = mkWorld({ deps: { buildSignedTransition: async () => ({}) } });
  await rejects("a signed-transition result without the transition refuses",
    registerV11({ deps: wNoT.deps }), /must return the signed transition/);
  const wOdd = mkWorld({ env: { CONTRACT_V11_PENDING: "true" } });
  await rejects("ANY defined pending value blocks, not only the written form",
    registerV11({ deps: wOdd.deps }), /orphan/);
}

{ // a storage failure on the id write after a committed broadcast leaves the
  // durable intent standing (the orphan check owns the recovery)
  const w = mkWorld();
  const realWrite = w.deps.writeEnvKey;
  w.deps.writeEnvKey = (k, v) => {
    if (k === "CONTRACT_V11_ID") throw new Error("disk said no");
    realWrite(k, v);
  };
  await rejects("a failed id write propagates", registerV11({ deps: w.deps }), /disk said no/);
  eq("the pending marker survives the failed id write", w.env.CONTRACT_V11_PENDING, "1");
}

// ---------------------------------------------------------------------------
// the REAL publish payload, built offline through the same WASM constructor
// the live route uses (pshenmic-dpp resolves as dash-platform-sdk's own
// dependency; the live driver and the battery run import it the same way)
// ---------------------------------------------------------------------------
{
  const dpp = require("pshenmic-dpp");
  const { poolLedgerContract } = require("../../dist/contract/poolLedger.js");
  const schema = buildV11(poolLedgerContract);
  const owner = new dpp.IdentifierWASM("11".repeat(32));
  const contract = new dpp.DataContractWASM(owner, 1n, schema, undefined, undefined, true, 12);
  const serialized = contract.bytes();
  ok("the real serialized v11 payload fits the conservative bound",
    serialized.length >= 1 && serialized.length <= PLATFORM_LIMITS.estimatedContractMaxSerializedSize);
  // "the same constructor the live route uses" is COMPARED, not asserted in
  // prose: the SDK's own create function, over the same schema and nonce,
  // must produce byte-identical serialization to the direct constructor.
  // WIDTH: one owner, one nonce, one schema; equivalence for this input, not
  // a general constructor-equivalence proof
  {
    const { pathToFileURL } = require("url");
    const sdkCreate = (await import(pathToFileURL(
      path.join(__dirname, "../../node_modules/dash-platform-sdk/src/dataContracts/create.js")).href)).default;
    const viaSdk = sdkCreate("11".repeat(32), 1n, schema); // the same owner the direct construction used
    ok("the SDK route and the direct constructor serialize byte-identically",
      Buffer.from(viaSdk.bytes()).equals(Buffer.from(serialized)));
  }
  const gate = assertRegisterGate({ pinChainId: PIN, serializedContractLength: serialized.length });
  ok("the register gate passes on the real payload", gate.coverage.every((c) => c.holds === true));
  console.log(`  real v11 payload: ${serialized.length} serialized bytes ` +
    `(bound ${PLATFORM_LIMITS.estimatedContractMaxSerializedSize})`);

  const unsigned = new dpp.DataContractCreateTransitionWASM(contract, 1n).toStateTransition().bytes();
  // width stated: the LIVE flow asserts the SIGNED article; this offline check
  // only establishes that the unsigned encoding leaves signature headroom
  ok("the real unsigned create transition leaves at least 512 bytes of signature headroom under 20480",
    unsigned.length + 512 <= PLATFORM_LIMITS.maxStateTransitionSize);
  console.log(`  real unsigned create transition: ${unsigned.length} bytes (cap ${PLATFORM_LIMITS.maxStateTransitionSize})`);

  const id = contractIdOf(contract);
  ok("contractIdOf answers the base58 identifier (32 raw bytes)", Buffer.from(bs58.decode(id)).length === 32);
  throws("contractIdOf refuses an object with no identifier", () => contractIdOf({}), /no identifier/);
}

// ---------------------------------------------------------------------------
// the owned-key writes through the REAL env store (throwaway TEGARA_ENV_PATH):
// pending lands before broadcast, the id lands owned, the marker discharges;
// then on a fresh refusal path the marker persists durably
// ---------------------------------------------------------------------------
{
  const mkRealDeps = (broadcast) => ({
    confirmed: true, pinChainId: PIN,
    buildContract: async () => ({ contract: { bytes: () => new Uint8Array(13350), id: { base58: () => MOCK_ID2 } } }),
    runPreRegistrationBattery: async () => greenReport(),
    buildSignedTransition: async () => ({ transition: { bytes: () => new Uint8Array(13420) } }),
    broadcastTransition: broadcast,
    // readEnv/writeEnvKey/locks deliberately DEFAULTED to the real env store
  });

  let pendingSeenAtBroadcast = null;
  const r = await registerV11({ deps: mkRealDeps(async () => {
    pendingSeenAtBroadcast = envStore.loadEnv().CONTRACT_V11_PENDING;
    return { outcome: "verified-proof" };
  }) });
  eq("the real store carries the intent at broadcast time (read-after-write through the default store)", pendingSeenAtBroadcast, "1");
  eq("the real store carries the id afterwards", envStore.loadEnv().CONTRACT_V11_ID, MOCK_ID2);
  ok("the real store's marker is discharged", envStore.loadEnv().CONTRACT_V11_PENDING === undefined);
  eq("the flow returned the same id", r.contractId, MOCK_ID2);

  const again = await registerV11({ deps: mkRealDeps(async () => { throw new Error("must not broadcast"); }) });
  eq("a second run against the real store is the already-published no-op", again.alreadyPublished, true);

  // a refused broadcast leaves the durable marker: reset the store's id first
  envStore.updateEnvKey("CONTRACT_V11_ID", undefined);
  await rejects("a refused broadcast against the real store refuses",
    registerV11({ deps: mkRealDeps(async () => ({ outcome: "execution-refusal" })) }),
    /did not commit with a verified proof/);
  eq("the real store keeps the pending marker across the refusal", envStore.loadEnv().CONTRACT_V11_PENDING, "1");
  envStore.updateEnvKey("CONTRACT_V11_PENDING", undefined); // leave the throwaway store clean
}

console.log(`registerV11DryRunTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
})().catch((e) => { console.error("UNCAUGHT:", e); process.exitCode = 1; });
