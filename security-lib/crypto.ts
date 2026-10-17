/**
 * Encryption at rest for the engagement store.
 *
 * The store holds scanner output, HTTP transcripts and — by deliberate policy —
 * live credentials in the clear. That is the right call inside the engagement
 * directory and the wrong thing to leave on a disk that gets stolen, imaged or
 * synced to a backup the operator does not control.
 *
 * Design constraints, all of which shaped what follows:
 *
 *  - **Opt-in.** With no key configured the store is plaintext, exactly as
 *    before. Turning encryption on must not be a prerequisite for using the
 *    tool, and turning it on must not make existing engagements unreadable.
 *  - **Self-describing.** An encrypted value is an envelope carrying its own
 *    algorithm and KDF parameters, so a reader can tell ciphertext from
 *    plaintext without external metadata, and parameters can change later
 *    without a migration.
 *  - **No new dependencies.** scrypt and AES-256-GCM are in `node:crypto`.
 *  - **File granularity.** Whole files for the store and evidence, one envelope
 *    per line for the append-only audit trail, which has to stay appendable.
 *
 * Threat model, stated honestly: this protects data at rest — a lost laptop, a
 * copied directory, a backup. It does not protect against a process running as
 * the same user, and it cannot: the key has to be readable for the tools to work.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto"
import { existsSync, readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

/** Key derivation parameters. Kept in the envelope so they can be raised later. */
const SCRYPT = { N: 1 << 15, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 }
const ALG = "aes-256-gcm"
const MARK = "nullbyte-encrypted"
const VERSION = 1

export interface Envelope {
  /** discriminator: presence of this key is how a reader recognises ciphertext */
  $: typeof MARK
  v: number
  alg: string
  kdf: string
  /** scrypt cost parameters, so decryption does not depend on today's defaults */
  N: number
  r: number
  p: number
  /** per-value salt and IV, base64 */
  salt: string
  iv: string
  /** GCM authentication tag, base64 */
  tag: string
  /** ciphertext, base64 */
  ct: string
}

export class StoreKeyError extends Error {
  readonly detail: string

  constructor(detail: string) {
    super(
      `${detail} The store appears to be encrypted but the key is not available. ` +
        `Set NULLBYTE_STORE_KEY (a passphrase) or place the key file at ${keyFilePath()} ` +
        `(mode 0600), or set plugins.encrypt_store=false in ${join(homedir(), ".config", "nullbyte", "security.json")} ` +
        `to store in the clear. Without the exact key the data cannot be recovered — there is no backdoor.`,
    )
    this.name = "StoreKeyError"
    this.detail = detail
  }
}

/** Where a key file is looked for when the passphrase is not in the environment. */
export function keyFilePath(): string {
  return process.env.NULLBYTE_STORE_KEY_FILE ?? join(homedir(), ".config", "nullbyte", "security.key")
}

/**
 * The configured passphrase, or undefined when none is set.
 *
 * The environment wins over the file so a one-off run can use a different key
 * without touching the operator's stored one.
 */
export function storePassphrase(): string | undefined {
  const env = process.env.NULLBYTE_STORE_KEY
  if (env && env.trim()) return env.trim()

  const path = keyFilePath()
  if (!existsSync(path)) return undefined
  const raw = readFileSync(path, "utf8").trim()
  return raw || undefined
}

export function encryptionConfigured(): boolean {
  return storePassphrase() !== undefined
}

/** The global policy file, read directly to keep this module dependency-free. */
function policyPath(): string {
  return process.env.NULLBYTE_SECURITY_POLICY ?? join(homedir(), ".config", "nullbyte", "security.json")
}

/**
 * True when the operator has *required* encryption (`plugins.encrypt_store`).
 *
 * Distinct from "a key happens to be set": required means writing plaintext is a
 * failure, not a fallback. Silently storing in the clear when the operator
 * believes they are encrypted is the one outcome worth refusing to do.
 */
export function encryptionRequired(): boolean {
  try {
    const v = JSON.parse(readFileSync(policyPath(), "utf8")) as Record<string, any>
    return v?.plugins?.encrypt_store === true
  } catch {
    return false
  }
}

/** True when a value is one of our envelopes. */
export function isEnvelope(value: unknown): value is Envelope {
  if (!value || typeof value !== "object") return false
  const e = value as Record<string, unknown>
  return e.$ === MARK && typeof e.ct === "string" && typeof e.iv === "string" && typeof e.salt === "string"
}

function derive(passphrase: string, salt: Buffer, N: number, r: number, p: number): Buffer {
  return scryptSync(passphrase, salt, SCRYPT.keylen, { N, r, p, maxmem: SCRYPT.maxmem })
}

/**
 * Encrypt a string, returning the envelope as a single-line JSON string.
 *
 * Single-line on purpose: the audit trail is JSONL, so an envelope has to be
 * usable as one line without escaping.
 */
export function encryptValue(plaintext: string, passphrase: string): string {
  const salt = randomBytes(16)
  const iv = randomBytes(12)
  const key = derive(passphrase, salt, SCRYPT.N, SCRYPT.r, SCRYPT.p)
  const cipher = createCipheriv(ALG, key, iv)
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()])
  const env: Envelope = {
    $: MARK,
    v: VERSION,
    alg: ALG,
    kdf: "scrypt",
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ct: ct.toString("base64"),
  }
  return JSON.stringify(env)
}

/**
 * Decrypt an envelope. Throws StoreKeyError rather than returning garbage: a
 * tampered ciphertext fails the GCM tag, and that must surface as corruption,
 * not as a plausible-looking plaintext.
 */
export function decryptValue(env: Envelope, passphrase: string): string {
  const key = derive(passphrase, Buffer.from(env.salt, "base64"), env.N, env.r, env.p)
  const decipher = createDecipheriv(env.alg, key, Buffer.from(env.iv, "base64"))
  decipher.setAuthTag(Buffer.from(env.tag, "base64"))
  return Buffer.concat([decipher.update(Buffer.from(env.ct, "base64")), decipher.final()]).toString("utf8")
}

/** Named separately from findings StoreCorruptError: they are unrelated failures. */
export class EnvelopeCorruptError extends Error {
  constructor(detail: string) {
    super(
      `the encrypted value could not be decrypted (${detail}). The ciphertext has been altered, ` +
        `or it was written with a different key.`,
    )
    this.name = "EnvelopeCorruptError"
  }
}

/* ------------------------------------------------------------- high level --- */

/**
 * Encode a value for storage: an envelope when a key is configured, the
 * plaintext otherwise.
 */
export function seal(plaintext: string): string {
  const pass = storePassphrase()
  if (pass) return encryptValue(plaintext, pass)
  if (encryptionRequired()) {
    throw new StoreKeyError("encryption is required by plugins.encrypt_store but no key is configured.")
  }
  return plaintext
}

/**
 * Decode a value read from storage.
 *
 * Plaintext passes through untouched, which is what makes turning encryption on
 * non-destructive: a mixed store reads correctly, so an operator can enable it
 * and let new writes be encrypted as old ones are re-written.
 */
export function open(stored: string): string {
  const trimmed = stored.trim()
  // cheap discriminator first: an envelope is always a JSON object
  if (!trimmed.startsWith("{")) return stored

  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch {
    return stored
  }
  if (!isEnvelope(parsed)) return stored

  const pass = storePassphrase()
  if (!pass) throw new StoreKeyError("this value is encrypted.")
  try {
    return decryptValue(parsed, pass)
  } catch (e: any) {
    throw new EnvelopeCorruptError(e?.message ?? String(e))
  }
}

/** A short, non-reversible label for the configured key, for diagnostics. */
export function keyFingerprint(): string | undefined {
  const pass = storePassphrase()
  if (!pass) return undefined
  const salt = Buffer.from("nullbyte-key-fingerprint")
  return derive(pass, salt, 1 << 12, 8, 1).toString("hex").slice(0, 16)
}
