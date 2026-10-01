"use strict";
/**
 * THE MEMBER'S OWN KEY STORE for the guided member trial (tegara/docs/GUIDED_MEMBER_TRIAL.md). It is
 * the member's, not the coordinator's: it lives outside the repository in a directory only the member
 * tool mounts, and it is encrypted with a passphrase the member types, so nothing on the coordinator's
 * side can sign as the member without it.
 *
 * WHAT IT HOLDS. One recovery phrase, encrypted (scrypt, then AES-256-GCM). Every key derives from it:
 *   the Platform identity wallet     the SDK's own paths for the phrase (the funding address and the
 *                                    identity keys), used by the member tool's identity step
 *   the Layer 1 share keys           m/44'/1'/7'/0/0 owner, /1 refund, /2 reward (testnet coin type,
 *                                    account 7', apart from the SDK wallet's account 0')
 * The public card (addresses and, once registered, the identity id) is written beside it in plain
 * text, since it is exactly what the member hands the coordinator.
 *
 * WHAT IT DOES NOT DO. It does not protect against someone who can read the member's passphrase as it
 * is typed, or run code as the member. The separation is by passphrase and by process, on one machine.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const L = require("@dashevo/dashcore-lib");

const STORE = "member-store.json";
const CARD = "member-card.json";
const KDF = Object.freeze({ N: 1 << 15, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 });
const SHARE_PATH = "m/44'/1'/7'/0";
class StoreRefusal extends Error {}
const refuse = (why) => { throw new StoreRefusal(why); };

const keyFrom = (passphrase, salt) => crypto.scryptSync(passphrase, salt, KDF.keylen, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: KDF.maxmem });

function encrypt(phrase, passphrase) {
  if (typeof passphrase !== "string" || passphrase.length < 12) refuse("the passphrase must be at least 12 characters");
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", keyFrom(passphrase, salt), iv);
  const ct = Buffer.concat([c.update(phrase, "utf8"), c.final()]);
  return { version: 1, kdf: { name: "scrypt", N: KDF.N, r: KDF.r, p: KDF.p }, salt: salt.toString("hex"),
    iv: iv.toString("hex"), tag: c.getAuthTag().toString("hex"), ciphertext: ct.toString("hex") };
}

function decrypt(blob, passphrase) {
  if (!blob || blob.version !== 1 || !blob.kdf || blob.kdf.name !== "scrypt" || blob.kdf.N !== KDF.N) refuse("the member store is not a version-1 store");
  try {
    const d = crypto.createDecipheriv("aes-256-gcm", keyFrom(passphrase, Buffer.from(blob.salt, "hex")), Buffer.from(blob.iv, "hex"));
    d.setAuthTag(Buffer.from(blob.tag, "hex"));
    return Buffer.concat([d.update(Buffer.from(blob.ciphertext, "hex")), d.final()]).toString("utf8");
  } catch { return refuse("the passphrase does not open this member store"); }
}

/** The share keys and their addresses, derived from the phrase. */
function shareKeys(phrase) {
  const root = new L.Mnemonic(phrase).toHDPrivateKey("", "testnet");
  const at = (i) => root.deriveChild(`${SHARE_PATH}/${i}`).privateKey;
  const [owner, refund, reward] = [0, 1, 2].map(at);
  return { owner, refund, reward, addresses: { owner: owner.toAddress().toString(), refund: refund.toAddress().toString(), reward: reward.toAddress().toString() } };
}

/** Creates a new store in dir, refusing to replace one. Returns the public card. */
function createStore(dir, passphrase) {
  const file = path.join(dir, STORE);
  if (fs.existsSync(file)) refuse(`${file} already exists; a member store is never replaced`);
  const phrase = new L.Mnemonic().toString();
  const blob = encrypt(phrase, passphrase);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(blob, null, 2), { mode: 0o600, flag: "wx" });
  const card = { addresses: shareKeys(phrase).addresses, identityB58: null };
  fs.writeFileSync(path.join(dir, CARD), JSON.stringify(card, null, 2), { mode: 0o644 });
  return card;
}

function openStore(dir, passphrase) {
  const file = path.join(dir, STORE);
  if (!fs.existsSync(file)) refuse(`no member store at ${file}; run init first`);
  const phrase = decrypt(JSON.parse(fs.readFileSync(file, "utf8")), passphrase);
  const card = JSON.parse(fs.readFileSync(path.join(dir, CARD), "utf8"));
  const keys = shareKeys(phrase);
  // the plain card must describe these keys, or it was replaced
  for (const k of ["owner", "refund", "reward"]) if (card.addresses[k] !== keys.addresses[k]) refuse(`the member card's ${k} address is not this store's`);
  return { phrase, keys, card };
}

/**
 * THE RESTORE PROOF (the backup-and-restore exercise, a prerequisite of any collateral-bearing pilot since
 * a passphrase was lost on 2026-10-01). A test line is signed with the owner key and verified against the
 * CARD's owner address, Dash's signed-message format, so a store copied into another folder is shown to
 * open, to derive the keys its card names, and to sign as that card. Returns { testLine, signature,
 * verified }. `verified` is computed, never assumed, and proveStore below refuses on it.
 */
function signedTestLine({ ownerKey, ownerAddress, now = () => new Date() }) {
  const testLine = `tegara member store restore check ${now().toISOString()}`;
  const signature = new L.Message(testLine).sign(ownerKey);
  let verified = false;
  try { verified = new L.Message(testLine).verify(ownerAddress, signature) === true; } catch { verified = false; }
  return { testLine, signature, verified };
}

/**
 * Opens the store in dir (which already refuses a card that does not describe the store's keys), signs
 * the test line and verifies it against the card. Returns { addresses, identityB58, testLine, signature }
 * or throws StoreRefusal; it never returns with an unverified signature.
 */
function proveStore(dir, passphrase, { now } = {}) {
  const { keys, card } = openStore(dir, passphrase);
  const t = signedTestLine({ ownerKey: keys.owner, ownerAddress: card.addresses.owner, now });
  if (t.verified !== true) refuse("the test signature by this store's owner key does not verify against your card's owner address");
  return { addresses: card.addresses, identityB58: card.identityB58 ?? null, testLine: t.testLine, signature: t.signature };
}

function recordIdentity(dir, identityB58) {
  const p = path.join(dir, CARD);
  const card = JSON.parse(fs.readFileSync(p, "utf8"));
  if (card.identityB58 && card.identityB58 !== identityB58) refuse(`the card already names identity ${card.identityB58}`);
  card.identityB58 = identityB58;
  fs.writeFileSync(p, JSON.stringify(card, null, 2), { mode: 0o644 });
  return card;
}

module.exports = { STORE, CARD, SHARE_PATH, encrypt, decrypt, shareKeys, createStore, openStore, signedTestLine, proveStore, recordIdentity, StoreRefusal };
