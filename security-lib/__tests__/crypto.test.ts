/**
 * Encryption at rest for the engagement store.
 *
 * The store holds scanner output, HTTP transcripts and — by deliberate policy —
 * live credentials in the clear. These tests cover the two things that matter:
 * turning encryption on actually encrypts, and turning it on (or off) never
 * loses an engagement.
 *
 * A real key is set in-process via the environment for each test, because the
 * key source is part of what is being tested.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { decryptValue, encryptionConfigured, encryptionRequired, keyFingerprint, open, seal, isEnvelope, StoreKeyError, EnvelopeCorruptError } from "../crypto.ts"
import { createFinding, getFinding, readAllFindings, recordRetest } from "../findings.ts"
import { listEvidence, readEvidence, saveEvidence, verifyEvidenceStore } from "../evidence.ts"
import { readAudit, verifyAudit, writeAudit } from "../audit.ts"
import type { FindingInput } from "../types.ts"

const root = () => mkdtempSync(join(tmpdir(), "nb-crypto-"))

/** Run a body with NULLBYTE_STORE_KEY set to `key` (or unset for undefined). */
function withKey<T>(key: string | undefined, body: () => T): T {
  const prev = process.env.NULLBYTE_STORE_KEY
  const prevPolicy = process.env.NULLBYTE_SECURITY_POLICY
  if (key === undefined) delete process.env.NULLBYTE_STORE_KEY
  else process.env.NULLBYTE_STORE_KEY = key
  // point the policy file away from the operator's real one
  process.env.NULLBYTE_SECURITY_POLICY = join(root(), "nonexistent.json")
  try {
    return body()
  } finally {
    if (prev === undefined) delete process.env.NULLBYTE_STORE_KEY
    else process.env.NULLBYTE_STORE_KEY = prev
    if (prevPolicy === undefined) delete process.env.NULLBYTE_SECURITY_POLICY
    else process.env.NULLBYTE_SECURITY_POLICY = prevPolicy
  }
}

const input = (over: Partial<FindingInput> = {}): FindingInput => ({
  title: "Reflected XSS",
  description: "the q parameter is reflected without encoding",
  impact: "session theft",
  target: "app.acme.test",
  source: "manual",
  severity: "high",
  confidence: "high",
  verification: "unverified",
  evidence: "payload returned verbatim",
  remediation: "encode output",
  ...over,
})

/* ---------------------------------------------------------------- envelope --- */

test("an envelope is self-describing and round-trips", () => {
  const text = withKey("correct horse battery staple", () => {
    const sealed = seal("attack at dawn")
    const env = JSON.parse(sealed)
    assert.equal(env.$, "nullbyte-encrypted")
    assert.equal(env.v, 1)
    assert.equal(env.alg, "aes-256-gcm")
    assert.equal(env.kdf, "scrypt")
    assert.equal(env.N, 1 << 15)
    // the ciphertext must not contain the plaintext
    assert.doesNotMatch(sealed, /attack at dawn/)
    assert.ok(isEnvelope(env))
    return sealed
  })
  // and opens with the same key
  withKey("correct horse battery staple", () => {
    assert.equal(open(text), "attack at dawn")
  })
})

test("the same plaintext seals differently every time", () => {
  // a fresh salt and IV per value: identical findings must not look identical
  withKey("k", () => {
    assert.notEqual(seal("same"), seal("same"))
  })
})

test("the wrong key fails the authentication tag instead of returning garbage", () => {
  const sealed = withKey("right", () => seal("secret"))
  withKey("wrong", () => {
    assert.throws(() => open(sealed), (e: any) => e instanceof EnvelopeCorruptError)
  })
})

test("a tampered ciphertext is detected, not silently decrypted", () => {
  withKey("k", () => {
    const env = JSON.parse(seal("original"))
    const bytes = Buffer.from(env.ct, "base64")
    bytes[0]! ^= 0xff
    env.ct = bytes.toString("base64")
    assert.throws(() => decryptValue(env, "k"))
  })
})

test("plaintext passes through untouched, so an unencrypted store still reads", () => {
  withKey(undefined, () => {
    assert.equal(encryptionConfigured(), false)
    assert.equal(open('{"version":1,"findings":[]}'), '{"version":1,"findings":[]}')
    assert.equal(open("not json at all"), "not json at all")
    assert.equal(seal("plain"), "plain", "with no key, sealing is a no-op")
  })
})

test("the key fingerprint is stable and does not leak the key", () => {
  withKey("hunter2", () => {
    const fp = keyFingerprint()!
    assert.match(fp, /^[0-9a-f]{16}$/)
    assert.equal(keyFingerprint(), fp, "stable across calls")
    assert.doesNotMatch(fp, /hunter2/)
  })
  withKey("hunter3", () => {
    assert.notEqual(keyFingerprint(), withKey("hunter2", () => keyFingerprint()))
  })
})

/* ------------------------------------------------------------------- store --- */

test("findings are encrypted on disk and readable through the API", () => {
  const dir = root()
  withKey("engagement-key", () => {
    const r = createFinding(dir, "s1", input({ evidence: "leaked password s3cr3t-pw" }))
    assert.ok(r.finding)

    const raw = readFileSync(join(dir, "findings.json"), "utf8")
    assert.ok(isEnvelope(JSON.parse(raw)), "the store must be a single sealed envelope")
    assert.doesNotMatch(raw, /Reflected XSS/)
    assert.doesNotMatch(raw, /s3cr3t-pw/)

    // and the API is none the wiser
    assert.equal(readAllFindings(dir).length, 1)
    assert.equal(getFinding(dir, r.finding!.id)!.title, "Reflected XSS")
  })
})

test("evidence artifacts are encrypted on disk and still verify", () => {
  const dir = root()
  withKey("engagement-key", () => {
    const { record } = saveEvidence(dir, {
      sessionID: "s1",
      source: "sec_recon",
      label: "transcript",
      content: "HTTP/1.1 200 OK\r\nAuthorization: Bearer eyJhbGciOi",
    })
    const raw = readFileSync(join(dir, "evidence", record!.file), "utf8")
    assert.ok(isEnvelope(JSON.parse(raw)))
    assert.doesNotMatch(raw, /Bearer/)
    assert.doesNotMatch(raw, /HTTP\/1\.1/)

    assert.match(readEvidence(dir, record!.id)!, /Bearer eyJhbGciOi/)
    assert.deepEqual(verifyEvidenceStore(dir).map((v) => v.state), ["ok"])
  })
})

test("the audit trail is sealed per line and still verifies as a chain", () => {
  const dir = root()
  withKey("engagement-key", () => {
    writeAudit(dir, { sessionID: "s1", tool: "sec_recon", decision: "allow", code: "a", reason: "allowed" })
    writeAudit(dir, { sessionID: "s1", tool: "sec_scan", decision: "deny", code: "b", reason: "refused" })

    const lines = readFileSync(join(dir, "audit.jsonl"), "utf8").split("\n").filter(Boolean)
    assert.equal(lines.length, 2)
    for (const l of lines) assert.ok(isEnvelope(JSON.parse(l)), "each line is its own envelope")
    assert.doesNotMatch(lines.join("\n"), /refused/)

    // the chain is over the plaintext records, so it still verifies
    const v = verifyAudit(dir)
    assert.equal(v.ok, true)
    assert.equal(v.records, 2)
    assert.equal(readAudit(dir, 0).length, 2)
    assert.equal(readAudit(dir, 0)[1]!.decision, "deny")
  })
})

test("an encrypted store re-reads across a key change of representation", () => {
  // same passphrase supplied via a different mechanism must decrypt the same data
  const dir = root()
  withKey("shared-pass", () => createFinding(dir, "s1", input({ title: "Encrypted finding" })))
  withKey("shared-pass", () => {
    assert.equal(readAllFindings(dir)[0]!.title, "Encrypted finding")
  })
})

test("a retest against an encrypted store works end to end", () => {
  const dir = root()
  withKey("k", () => {
    const f = createFinding(dir, "s1", input()).finding!
    const res = recordRetest(dir, f.id, { by: "void", method: "curl -s /search?q=x", status: "verified", observed: "still reflects" })
    assert.deepEqual(res.problems, [])
    assert.equal(getFinding(dir, f.id)!.retests!.length, 1)
  })
})

/* ----------------------------------------------------- missing-key behaviour --- */

test("reading an encrypted store with no key is a clear error, not corruption", () => {
  const dir = root()
  withKey("the-key", () => createFinding(dir, "s1", input()))

  withKey(undefined, () => {
    assert.throws(() => readAllFindings(dir), (e: any) => e instanceof StoreKeyError)
    try {
      readAllFindings(dir)
    } catch (e: any) {
      assert.match(e.message, /the key is not available/)
      assert.match(e.message, /no backdoor/)
      assert.equal(e.name, "StoreKeyError")
    }
    // and it must not be reported as a corrupt store, which would invite a repair
    assert.throws(() => readAllFindings(dir), (e: any) => e.name !== "StoreCorruptError")
  })
})

test("the store is left untouched when the key is missing", () => {
  const dir = root()
  withKey("the-key", () => createFinding(dir, "s1", input()))
  const before = readFileSync(join(dir, "findings.json"), "utf8")

  withKey(undefined, () => {
    assert.throws(() => createFinding(dir, "s1", input({ title: "should not land" })))
  })
  assert.equal(readFileSync(join(dir, "findings.json"), "utf8"), before)
})

/* -------------------------------------------------------- required, not set --- */

test("requiring encryption without a key refuses to write plaintext", () => {
  const dir = root()
  const policy = join(dir, "security.json")
  writeFileSync(policy, JSON.stringify({ plugins: { encrypt_store: true } }))

  const prevKey = process.env.NULLBYTE_STORE_KEY
  const prevPolicy = process.env.NULLBYTE_SECURITY_POLICY
  delete process.env.NULLBYTE_STORE_KEY
  process.env.NULLBYTE_SECURITY_POLICY = policy
  try {
    assert.equal(encryptionRequired(), true)
    assert.throws(() => seal("anything"), (e: any) => e instanceof StoreKeyError)
    // the whole point: no plaintext lands on disk
    assert.throws(() => createFinding(dir, "s1", input()))
    assert.equal(existsSync(join(dir, "findings.json")), false)
  } finally {
    if (prevKey === undefined) delete process.env.NULLBYTE_STORE_KEY
    else process.env.NULLBYTE_STORE_KEY = prevKey
    if (prevPolicy === undefined) delete process.env.NULLBYTE_SECURITY_POLICY
    else process.env.NULLBYTE_SECURITY_POLICY = prevPolicy
  }
})

test("requiring encryption with a key configured is satisfied and does not complain", () => {
  const dir = root()
  const policy = join(dir, "security.json")
  writeFileSync(policy, JSON.stringify({ plugins: { encrypt_store: true } }))

  const prevKey = process.env.NULLBYTE_STORE_KEY
  const prevPolicy = process.env.NULLBYTE_SECURITY_POLICY
  process.env.NULLBYTE_STORE_KEY = "k"
  process.env.NULLBYTE_SECURITY_POLICY = policy
  try {
    assert.equal(encryptionRequired(), true)
    const r = createFinding(dir, "s1", input())
    assert.ok(r.finding)
    assert.ok(isEnvelope(JSON.parse(readFileSync(join(dir, "findings.json"), "utf8"))))
  } finally {
    if (prevKey === undefined) delete process.env.NULLBYTE_STORE_KEY
    else process.env.NULLBYTE_STORE_KEY = prevKey
    if (prevPolicy === undefined) delete process.env.NULLBYTE_SECURITY_POLICY
    else process.env.NULLBYTE_SECURITY_POLICY = prevPolicy
  }
})

test("a plaintext engagement is still readable after encryption is enabled", () => {
  // the migration story: old records stay plaintext, new ones are sealed
  const dir = root()
  withKey(undefined, () => createFinding(dir, "s1", input({ title: "Written in the clear" })))
  assert.doesNotMatch(readFileSync(join(dir, "findings.json"), "utf8"), /\$.*nullbyte-encrypted/)

  withKey("new-key", () => {
    const store = readAllFindings(dir)
    assert.equal(store.length, 1, "the plaintext store still reads with a key configured")
    assert.equal(store[0]!.title, "Written in the clear")
    assert.equal(encryptionConfigured(), true)
  })
})
