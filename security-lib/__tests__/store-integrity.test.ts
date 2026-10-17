/**
 * Store integrity.
 *
 * The engagement store is read-modify-write, so an unreadable store used to be
 * indistinguishable from an empty one — and the next write then erased it. The
 * failure these tests pin down is total, silent loss of an engagement's
 * findings and evidence.
 *
 * Two properties:
 *   1. An unreadable store is fatal and is never overwritten.
 *   2. Writes are atomic, so a crash cannot leave a partial file to begin with.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, mkdirSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createFinding, readAllFindings, StoreCorruptError } from "../findings.ts"
import { listEvidence, readEvidence, saveEvidence, verifyEvidence, verifyEvidenceStore, EvidenceIndexCorruptError, EvidenceIntegrityError } from "../evidence.ts"
import { atomicWriteFile, atomicWriteJson } from "../atomic.ts"
import type { FindingInput } from "../types.ts"

const root = () => mkdtempSync(join(tmpdir(), "nb-integrity-"))

const finding = (over: Partial<FindingInput> = {}): FindingInput => ({
  title: "Reflected XSS in search",
  description: "the q parameter is reflected without encoding",
  impact: "session theft",
  target: "127.0.0.1:8080",
  source: "manual",
  severity: "high",
  confidence: "high",
  evidence: "payload returned verbatim",
  remediation: "encode output",
  ...over,
})

const corrupted = (dir: string, file: string) => {
  const p = join(dir, file)
  writeFileSync(p, readFileSync(p, "utf8").slice(0, 40))
  return readFileSync(p, "utf8")
}

/* ------------------------------------------------------- findings store --- */

test("a corrupt findings store is fatal, not empty", () => {
  const dir = root()
  createFinding(dir, "s1", finding())
  const truncated = corrupted(dir, "findings.json")

  assert.throws(() => readAllFindings(dir), (e: any) => e instanceof StoreCorruptError)
  // the message must be actionable, and must say the file was left alone
  try {
    readAllFindings(dir)
  } catch (e: any) {
    assert.match(e.message, /could not be read/)
    assert.match(e.message, /left untouched/)
    assert.equal(e.path, join(dir, "findings.json"))
  }
  assert.equal(readFileSync(join(dir, "findings.json"), "utf8"), truncated, "the store must not be touched")
})

test("a corrupt store blocks the write that would otherwise destroy it", () => {
  const dir = root()
  createFinding(dir, "s1", finding({ title: "First" }))
  createFinding(dir, "s1", finding({ title: "Second" }))
  const truncated = corrupted(dir, "findings.json")

  assert.throws(() => createFinding(dir, "s1", finding({ title: "Third" })), (e: any) => e instanceof StoreCorruptError)
  assert.equal(readFileSync(join(dir, "findings.json"), "utf8"), truncated, "the truncated bytes must survive the attempt")
})

test("a structural corruption is caught too, not just a parse failure", () => {
  const dir = root()
  createFinding(dir, "s1", finding())
  writeFileSync(join(dir, "findings.json"), JSON.stringify({ version: 1, findings: "nope" }))
  assert.throws(() => readAllFindings(dir), (e: any) => e instanceof StoreCorruptError)
  writeFileSync(join(dir, "findings.json"), "{}")
  assert.throws(() => readAllFindings(dir), (e: any) => e instanceof StoreCorruptError)
})

test("an absent store is still a normal empty store", () => {
  const dir = root()
  assert.deepEqual(readAllFindings(dir), [], "no file yet is not corruption")
  const r = createFinding(dir, "s1", finding())
  assert.ok(r.finding, "and the first write still works")
})

test("a healthy store round-trips and leaves no temp files behind", () => {
  const dir = root()
  createFinding(dir, "s1", finding({ title: "First" }))
  createFinding(dir, "s1", finding({ title: "Second" }))
  assert.equal(readAllFindings(dir).length, 2)

  const stray = readdirSync(dir).filter((f) => f.includes(".tmp-"))
  assert.deepEqual(stray, [], "an atomic write must clean up after itself")
})

/* ------------------------------------------------------- evidence store --- */

test("a corrupt evidence index is fatal, not empty", () => {
  const dir = root()
  saveEvidence(dir, { sessionID: "s1", source: "sec_recon", label: "headers", content: "HTTP/1.1 200 OK" })
  const idx = join(dir, "evidence", "index.json")
  const truncated = (writeFileSync(idx, readFileSync(idx, "utf8").slice(0, 12)), readFileSync(idx, "utf8"))

  assert.throws(() => listEvidence(dir), (e: any) => e instanceof EvidenceIndexCorruptError)
  assert.throws(() => saveEvidence(dir, { sessionID: "s1", source: "x", label: "y", content: "z" }), (e: any) =>
    e instanceof EvidenceIndexCorruptError,
  )
  assert.equal(readFileSync(idx, "utf8"), truncated, "the index must not be touched")
})

test("evidence hashes cover exactly the bytes on disk, including truncation", () => {
  const dir = root()
  // over the 256 KiB evidence limit, so the store appends its truncation marker
  const big = "A".repeat(300 * 1024)
  const { record } = saveEvidence(dir, { sessionID: "s1", source: "sec_scan", label: "big log", content: big })
  assert.ok(record)
  assert.equal(record!.truncated, true)

  const onDisk = readFileSync(join(dir, "evidence", record!.file), "utf8")
  const digest = createHash("sha256").update(onDisk).digest("hex")
  assert.equal(record!.sha256, digest, "the recorded hash must verify against the stored file")
})

/* -------------------------------------------------- evidence integrity --- */

test("a tampered artifact fails its hash and is refused", () => {
  const dir = root()
  const { record } = saveEvidence(dir, { sessionID: "s1", source: "sec_recon", label: "headers", content: "HTTP/1.1 200 OK" })
  assert.equal(readEvidence(dir, record!.id), "HTTP/1.1 200 OK")

  writeFileSync(join(dir, "evidence", record!.file), "HTTP/1.1 200 OK\nX-Injected: yes")

  assert.throws(() => readEvidence(dir, record!.id), (e: any) => e instanceof EvidenceIntegrityError)
  try {
    readEvidence(dir, record!.id)
  } catch (e: any) {
    assert.equal(e.id, record!.id)
    assert.equal(e.expected, record!.sha256)
    assert.notEqual(e.actual, record!.sha256)
    assert.match(e.message, /cannot be relied on as evidence/)
  }
})

test("verifyEvidenceStore reports each artifact's state", () => {
  const dir = root()
  const a = saveEvidence(dir, { sessionID: "s1", source: "sec_recon", label: "a", content: "alpha" }).record!
  const b = saveEvidence(dir, { sessionID: "s1", source: "sec_scan", label: "b", content: "bravo" }).record!
  assert.deepEqual(verifyEvidenceStore(dir).map((v) => v.state), ["ok", "ok"])

  writeFileSync(join(dir, "evidence", b.file), "bravo, edited")
  assert.deepEqual(verifyEvidenceStore(dir).map((v) => v.state), ["ok", "modified"])
  assert.equal(verifyEvidence(dir, a.id).state, "ok")

  rmSync(join(dir, "evidence", a.file))
  assert.equal(verifyEvidence(dir, a.id).state, "missing")
  assert.equal(verifyEvidence(dir, "E-nope").state, "missing")
})

test("a truncated artifact still verifies — the hash covers what was written", () => {
  const dir = root()
  const { record } = saveEvidence(dir, {
    sessionID: "s1",
    source: "sec_scan",
    label: "big",
    content: "A".repeat(300 * 1024),
  })
  assert.equal(record!.truncated, true)
  assert.equal(verifyEvidence(dir, record!.id).state, "ok", "a truncated artifact is intact, not tampered")
  assert.equal(readEvidence(dir, record!.id)?.startsWith("A".repeat(100)), true)
})

test("a report refuses to embed an altered artifact", () => {
  const dir = root()
  const { record } = saveEvidence(dir, { sessionID: "s1", source: "sec_recon", label: "transcript", content: "GET /admin 200" })
  writeFileSync(join(dir, "evidence", record!.file), "GET /admin 403")

  // this is the path sec_report takes for evidence=full
  assert.throws(() => readEvidence(dir, record!.id), (e: any) => e instanceof EvidenceIntegrityError)
})

/* ----------------------------------------------------------- atomic I/O --- */

test("atomicWriteFile replaces content and never exposes a partial file", () => {
  const dir = root()
  const p = join(dir, "state.json")
  atomicWriteJson(p, { a: 1 })
  assert.deepEqual(JSON.parse(readFileSync(p, "utf8")), { a: 1 })
  atomicWriteJson(p, { a: 2 })
  assert.deepEqual(JSON.parse(readFileSync(p, "utf8")), { a: 2 })
  assert.deepEqual(
    readdirSync(dir).filter((f) => f.includes(".tmp-")),
    [],
  )
})

test("a failed atomic write leaves the previous file intact and no debris", () => {
  const dir = root()
  const p = join(dir, "state.txt")
  atomicWriteFile(p, "original")
  // a directory cannot be opened for writing, so openSync fails after mkdir
  mkdirSync(join(dir, "sub"))
  assert.throws(() => atomicWriteFile(join(dir, "sub"), "nope"))
  assert.equal(readFileSync(p, "utf8"), "original")
  assert.deepEqual(
    readdirSync(dir).filter((f) => f.includes(".tmp-")),
    [],
    "the temp file must be cleaned up on failure",
  )
  assert.equal(existsSync(join(dir, "sub")), true)
})
