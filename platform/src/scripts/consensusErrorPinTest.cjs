// The unique-index identity's battery (consensusErrorPin.cjs). Three independent sources: two REAL
// payloads captured read-only from our testnet evonode's block results
// (fixtures/consensus-error-unique-index-testnet.json), payloads built here by a hand encoder that
// shares no code with the decoder, and both pinned DPP builds as the ORACLE: every constructed
// payload below is also put to both builds, and the reader must accept exactly what they accept and
// refuse exactly what they refuse, except the ONE named divergence (bytes after the error, which the
// DPP ignores and the reader calls malformed). The DPP's message is read here only, never by the
// module. (Before a review of 2026-09-28 only one malformed case was put to the oracle, and the
// header claimed all of them.)
//
// THE MUTATION LIST, written before the cases: accept any outer variant as the state error; accept
// any state variant; drop the trailing-bytes check; refuse an empty property list; read a long
// varint little-endian; decode UTF-8 leniently; take a 31-byte id; make dataMatches code-only (always
// true); report another variant as malformed; drop the protocol-pin guard. Added from the review:
// allow the u64 form for an enum index; check UTF-8 only for the first property. From the
// confirmation round: drop the decode limit; count a Rust String as 16 bytes; never release a list
// element's share.
const fs = require("fs");
const path = require("path");
const bs58 = require("bs58").default || require("bs58");
const P = require("./consensusErrorPin.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) passed++; else { failed++; console.error("FAIL:", name); } };
const FIX = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "consensus-error-unique-index-testnet.json"), "utf8"));
const DPPS = { "dev.20": require("pshenmic-dpp"), "dev.28": require("pshenmic-dpp-feiv") };
const oracle = (hex) => Object.fromEntries(Object.entries(DPPS).map(([n, d]) => {
  try { return [n, d.ConsensusErrorWASM.deserialize(new Uint8Array(Buffer.from(hex, "hex"))).message]; }
  catch (e) { return [n, `REFUSED ${String(e && (e.message || e)).slice(0, 60)}`]; }
}));
const m = P.UNIQUE_INDEX_IDENTITY.dataMatches;

// the hand encoder: one-byte varints only, except where a case builds a long one explicitly
const lenPrefixed = (s) => Buffer.concat([Buffer.from([Buffer.byteLength(s)]), Buffer.from(s)]);
const unique = (idHex, props) => Buffer.concat([Buffer.from([2, 14]), Buffer.from(idHex, "hex"),
  Buffer.from([props.length]), ...props.map(lenPrefixed)]).toString("hex");
const ID = "5a".repeat(32);

// ---- the identity's shape and its pin ----
ok("the identity is code 40105 with a payload check", P.UNIQUE_INDEX_IDENTITY.code === 40105 && typeof m === "function");
ok("it records the release and protocol it was read at", P.PINNED_AT.platformRelease === "v4.1.1" && P.PINNED_AT.protocolVersion === 13);
{
  // a moved protocol pin refuses the module at load, until the definitions are read again
  const pinPath = require.resolve("./platformProtocolPin.cjs");
  const modPath = require.resolve("./consensusErrorPin.cjs");
  const saved = require.cache[pinPath];
  require.cache[pinPath] = { id: pinPath, filename: pinPath, loaded: true, exports: { ...saved.exports, PROTOCOL_VERSION_PIN: 14 } };
  delete require.cache[modPath];
  let why = "";
  try { require("./consensusErrorPin.cjs"); } catch (e) { why = e.message; }
  require.cache[pinPath] = saved;
  delete require.cache[modPath];
  require("./consensusErrorPin.cjs");
  ok(`under protocol pin 14 the identity refuses to load (got "${why.slice(0, 70)}")`, /read at protocol 13 .* now 14/.test(why));
}

// ---- the two REAL payloads ----
ok("two real captures, both code 40105", FIX.captures.length === 2 && FIX.captures.every((c) => c.code === 40105));
const REAL_IDS = { 604557: "C2KNkYviHTFSEMU1bg16odPK3eZUAKNmDWVzYF2CZqib", 604561: "HGF4QDga3nkPSpKUUkeLjrt61eNXf1tcvkE5br6hiU9r" };
for (const c of FIX.captures) {
  const d = P.decodeConsensusErrorPayload(c.serializedErrorHex);
  const idB58 = d.documentIdHex && bs58.encode(Buffer.from(d.documentIdHex, "hex"));
  ok(`height ${c.platformHeight}: decodes as the duplicate unique index, document ${idB58}`,
    d.kind === "duplicate-unique-index" && idB58 === REAL_IDS[c.platformHeight]
    && JSON.stringify(d.properties) === JSON.stringify(["$ownerId", "poolId", "termsRevision"]));
  ok(`height ${c.platformHeight}: the identity matches it`, m(c.serializedErrorHex) === true);
  const o = oracle(c.serializedErrorHex);
  ok(`height ${c.platformHeight}: both DPP builds read the same document and properties`,
    Object.values(o).every((msg) => msg.includes(REAL_IDS[c.platformHeight]) && msg.includes('["$ownerId", "poolId", "termsRevision"]')));
}
ok("the 604,561 capture's document is the one its run's log names (the log line is carried in the fixture)",
  FIX.captures.find((c) => c.platformHeight === 604561).runLogLine.includes(`Document ${REAL_IDS[604561]} has duplicate unique properties`));

// ---- the spec's named fixtures: header and reservation uniqueness, constructed and oracle-checked ----
for (const [name, props] of [["header (byPoolEpoch)", ["poolId", "epochIndex"]], ["reservation (byAccrual)", ["accrualId"]],
  ["final epoch (byPoolFunder)", ["poolId", "funderId"]]]) {
  const hex = unique(ID, props);
  const o = oracle(hex);
  ok(`${name}: both DPP builds read it as the duplicate unique index`,
    Object.values(o).every((msg) => msg.includes("has duplicate unique properties") && msg.includes(JSON.stringify(props).replace(/","/g, '", "'))));
  const d = P.decodeConsensusErrorPayload(hex);
  ok(`${name}: the decoder agrees`, d.kind === "duplicate-unique-index" && d.documentIdHex === ID && JSON.stringify(d.properties) === JSON.stringify(props));
}

// ---- another consensus error: decodable, not this one, so "other" ----
{
  const already = Buffer.concat([Buffer.from([2, 2]), Buffer.from(ID, "hex")]).toString("hex");
  ok("the oracle reads 02 02 as a document already present", Object.values(oracle(already)).every((s) => /is already present/.test(s)));
  ok("the identity reports it as another consensus error (false)", m(already) === false
    && P.decodeConsensusErrorPayload(already).stateVariant === 2);
  ok("a basic error prefix is another consensus error", m("01" + "00".repeat(8)) === false);
  ok("the default error (00) is another consensus error", m("00") === false);
}

// ---- EVERY EDGE AGAINST THE ORACLE: accepted by both builds and the reader, or refused by both
// builds and the reader, except the one named divergence ----
const refusedByBoth = (hex) => Object.values(oracle(hex)).every((s) => s.startsWith("REFUSED"));
const acceptedByBoth = (hex) => Object.values(oracle(hex)).every((s) => !s.startsWith("REFUSED"));
const accepted = {
  "an empty property list": "020e" + ID + "00",
  "65 properties": "020e" + ID + "41" + "0170".repeat(65),
  "a non-minimal u16 outer variant": "fb0002" + "0e" + ID + "010170",
  "a non-minimal u32 state variant": "02fc0000000e" + ID + "010170",
  "a non-minimal count": "020e" + ID + "fb0001" + "0170",
  "a count in the u64 form": "020e" + ID + "fd0000000000000001" + "0170",
  "a length in the u64 form": "020e" + ID + "01" + "fd0000000000000001" + "70",
};
for (const [name, hex] of Object.entries(accepted)) {
  ok(`conforming, ${name}: both DPP builds accept it and the identity matches`, acceptedByBoth(hex) && m(hex) === true
    && P.decodeConsensusErrorPayload(hex).kind === "duplicate-unique-index");
}
ok("the empty list decodes as no properties", JSON.stringify(P.decodeConsensusErrorPayload(accepted["an empty property list"]).properties) === "[]");
const malformed = {
  "empty data": "",
  "an outer variant that does not exist (5)": "05",
  "a state error with nothing after it": "02",
  "a truncated document id": "020e" + "5a".repeat(20),
  "no property count": "020e" + ID,
  "a property that runs past the end": "020e" + ID + "01" + "09" + Buffer.from("poolId").toString("hex"),
  "a property that is not UTF-8": "020e" + ID + "01" + "02" + "c328",
  "a SECOND property that is not UTF-8": "020e" + ID + "02" + "0170" + "02c328",
  "a u128 varint tag": "020e" + ID + "fe",
  "an outer variant in the u64 form": "fd00000000000000020e" + ID + "010170",
  "a state variant in the u64 form": "02fd000000000000000e" + ID + "010170",
  "a count larger than the bytes left": "020e" + ID + "05" + "0170",
};
for (const [name, hex] of Object.entries(malformed)) {
  ok(`malformed, ${name}: both DPP builds refuse it and so does the identity`, refusedByBoth(hex) && m(hex) === "malformed"
    && P.decodeConsensusErrorPayload(hex).kind === "malformed");
}
{
  // THE ONE DIVERGENCE: bytes after the error. The DPP ignores them; no encoder writes them; the
  // reader calls them malformed, so the classifier waits rather than acting on them
  const trailing = unique(ID, ["accrualId"]) + "07";
  ok("the named divergence: bytes after the error are accepted by both DPP builds and malformed here",
    acceptedByBoth(trailing) && m(trailing) === "malformed");
}

// ---- THE DECODE LIMIT (2000, counted as bincode 2 counts it): exact boundaries, then a seeded sweep
// of payloads around them, each put to both DPP builds (the confirmation round's case, 2026-09-29) ----
{
  const vi = (n) => (n < 251 ? Buffer.from([n]) : Buffer.from([251, n >> 8, n & 255]));
  const pay = (ks) => Buffer.concat([Buffer.from([2, 14]), Buffer.from(ID, "hex"), vi(ks.length),
    ...ks.map((k) => Buffer.concat([vi(k), Buffer.alloc(k, 0x70)]))]).toString("hex");
  const agrees = (hex) => {
    const both = acceptedByBoth(hex), neither = refusedByBoth(hex);
    const mine = m(hex) === true;
    return (both && mine) || (neither && !mine);
  };
  for (const [name, ks, want] of [
    ["81 one-letter names decode", Array(81).fill(1), true],
    ["82 one-letter names pass the limit (the round's payload)", Array(82).fill(1), false],
    ["one name of 1,944 bytes decodes", [1944], true],
    ["one name of 1,945 bytes passes the limit", [1945], false],
    ["a long first name beside an empty one decodes at 1,920", [1920, 0], true],
    ["and passes the limit at 1,921", [1921, 0], false],
    ["an empty first name beside a long one decodes at 1,936", [0, 1936], true],
    ["and passes the limit at 1,937", [0, 1937], false],
  ]) {
    const hex = pay(ks);
    ok(`limit: ${name}, as both DPP builds decide`, agrees(hex) && (m(hex) === true) === want);
  }
  // a deterministic generator, so a failure names a payload that can be rebuilt
  let seed = 20260929;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  let disagreements = 0, accepted = 0, refused = 0;
  for (let t = 0; t < 400; t++) {
    const shape = rnd(3);
    const ks = shape === 0 ? Array.from({ length: 70 + rnd(20) }, () => rnd(20))
      : shape === 1 ? Array.from({ length: 1 + rnd(6) }, () => 300 + rnd(400))
        : Array.from({ length: 20 + rnd(60) }, () => 10 + rnd(30));
    const hex = pay(ks);
    if (!agrees(hex)) disagreements++;
    if (m(hex) === true) accepted++; else refused++;
  }
  ok(`limit: 400 seeded payloads near the boundary, the reader agrees with both DPP builds on every one (${accepted} accepted, ${refused} refused)`,
    disagreements === 0 && accepted > 50 && refused > 50);
}

// ---- a long name: the big-endian varint ----
{
  const long = "p".repeat(300);
  const be = Buffer.concat([Buffer.from([2, 14]), Buffer.from(ID, "hex"), Buffer.from([1, 251, 0x01, 0x2c]), Buffer.from(long)]).toString("hex");
  const le = Buffer.concat([Buffer.from([2, 14]), Buffer.from(ID, "hex"), Buffer.from([1, 251, 0x2c, 0x01]), Buffer.from(long)]).toString("hex");
  ok("a 300-byte name with a big-endian length decodes, as in both DPP builds",
    P.decodeConsensusErrorPayload(be).properties[0] === long && Object.values(oracle(be)).every((s) => s.includes(long)));
  ok("the little-endian form is malformed, as both DPP builds refuse it",
    m(le) === "malformed" && Object.values(oracle(le)).every((s) => s.startsWith("REFUSED")));
}

// ---- not code-only: the identity reads the payload ----
ok("a payload the demonstration's code-only check would pass is not a unique-index payload here", m("00") === false && m("") === "malformed");

console.log(`consensusErrorPinTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
