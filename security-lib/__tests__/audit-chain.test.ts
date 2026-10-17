/**
 * Audit trail integrity.
 *
 * The trail records what was authorized, what was refused, and which hosts were
 * in scope — the report's coverage claims are derived from it. It was a plain
 * append-only log with a swallowed write error, so it could be edited, trimmed
 * or fail to write with nothing to show for it. These tests pin the two
 * guarantees that make it trustworthy: it is hash-chained, and it fails loudly.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  AUDIT_GENESIS,
  AuditCorruptError,
  AuditWriteError,
  auditPath,
  auditRecordHash,
  readAudit,
  verifyAudit,
  writeAudit,
} from "../audit.ts"
import type { AuditRecord } from "../types.ts"

const root = () => mkdtempSync(join(tmpdir(), "nb-audit-"))

const rec = (code: string, over: Partial<AuditRecord> = {}) => ({
  sessionID: "s1",
  agent: "void",
  tool: "sec_recon",
  decision: "allow" as const,
  code,
  reason: `decision ${code}`,
  ...over,
})

const lines = (root: string) => readFileSync(auditPath(root), "utf8").split("\n").filter(Boolean)

/* ------------------------------------------------------------- chaining --- */

test("each record links to the one before it", () => {
  const dir = root()
  writeAudit(dir, rec("a"))
  writeAudit(dir, rec("b"))
  writeAudit(dir, rec("c"))

  const [a, b, c] = lines(dir).map((l) => JSON.parse(l) as AuditRecord)
  assert.equal(a!.seq, 1)
  assert.equal(a!.prev, AUDIT_GENESIS)
  assert.equal(b!.seq, 2)
  assert.equal(b!.prev, a!.hash)
  assert.equal(c!.seq, 3)
  assert.equal(c!.prev, b!.hash)
  assert.equal(a!.hash, auditRecordHash(a!))

  const v = verifyAudit(dir)
  assert.equal(v.records, 3)
  assert.equal(v.ok, true)
  assert.deepEqual(v.problems, [])
  assert.equal(v.head, c!.hash)
})

test("the digest does not depend on key order", () => {
  const dir = root()
  const { hash: _drop, ...bare } = { ts: "t", tool: "x", decision: "allow", code: "c", reason: "r", hash: "ignored" } as AuditRecord
  const reordered = { reason: "r", code: "c", decision: "allow", tool: "x", ts: "t" } as unknown as AuditRecord
  assert.equal(auditRecordHash(bare as AuditRecord), auditRecordHash(reordered))
})

/* ---------------------------------------------------------- tamper cases --- */

const chain = (dir: string) => {
  writeAudit(dir, rec("one"))
  writeAudit(dir, rec("two", { decision: "deny" }))
  writeAudit(dir, rec("three"))
}

test("an edited record is detected", () => {
  const dir = root()
  chain(dir)
  const rows = lines(dir)
  const second = JSON.parse(rows[1]!) as AuditRecord
  second.reason = "nothing to see here"
  rows[1] = JSON.stringify(second)
  writeFileSync(auditPath(dir), rows.join("\n") + "\n")

  const v = verifyAudit(dir)
  assert.equal(v.ok, false)
  assert.deepEqual(v.problems.map((p) => [p.line, p.kind]), [[2, "altered"]])
})

test("a deleted record is detected as a gap and a broken link", () => {
  const dir = root()
  chain(dir)
  const rows = lines(dir)
  rows.splice(1, 1) // drop the middle record
  writeFileSync(auditPath(dir), rows.join("\n") + "\n")

  const v = verifyAudit(dir)
  assert.equal(v.ok, false)
  assert.deepEqual(v.problems.map((p) => p.kind), ["sequence", "broken-link"])
  assert.deepEqual(v.problems.map((p) => p.line), [2, 2])
})

test("a truncated or corrupt line is reported, not skipped", () => {
  const dir = root()
  chain(dir)
  writeFileSync(auditPath(dir), lines(dir).join("\n") + "\n" + lines(dir)[0]!.slice(0, 30) + "\n")

  const v = verifyAudit(dir)
  assert.equal(v.ok, false)
  assert.equal(v.problems.at(-1)!.kind, "unparseable")
  assert.equal(v.problems.at(-1)!.line, 4)
})

test("records written before chaining are counted, not silently trusted", () => {
  const dir = root()
  mkdirSync(dir, { recursive: true })
  writeFileSync(auditPath(dir), JSON.stringify({ ts: "t", tool: "sec_scan", decision: "allow", code: "legacy", reason: "old" }) + "\n")
  writeAudit(dir, rec("new"))

  const v = verifyAudit(dir)
  assert.equal(v.unchained, 1)
  assert.equal(v.records, 2)
  // the new record still starts its own chain
  assert.equal(v.ok, true)
})

test("verifyAudit on an absent trail is trivially intact", () => {
  const v = verifyAudit(root())
  assert.equal(v.records, 0)
  assert.equal(v.ok, true)
  assert.equal(v.head, undefined)
  assert.equal(v.unchained, 0)
  assert.deepEqual(v.problems, [])
})

/* ---------------------------------------------------------- fail loudly --- */

test("a write that cannot happen is fatal, not swallowed", () => {
  const dir = root()
  const blocker = join(dir, "not-a-dir")
  writeFileSync(blocker, "x")
  // root sits underneath a regular file, so directory creation must fail
  assert.throws(() => writeAudit(join(blocker, "security"), rec("a")), (e: any) => e instanceof AuditWriteError)
  try {
    writeAudit(join(blocker, "security"), rec("a"))
  } catch (e: any) {
    assert.match(e.message, /was NOT recorded/)
    assert.match(e.message, /refused rather than allowed unlogged/)
  }
})

test("appending to a corrupt trail is refused rather than forking the chain", () => {
  const dir = root()
  chain(dir)
  writeFileSync(auditPath(dir), lines(dir).join("\n") + "\n" + "{not json}\n")
  const before = readFileSync(auditPath(dir), "utf8")

  assert.throws(() => writeAudit(dir, rec("four")), (e: any) => e instanceof AuditCorruptError)
  assert.equal(readFileSync(auditPath(dir), "utf8"), before, "the trail must be left exactly as found")
})

test("readAudit stays lenient for display while verify detects the damage", () => {
  const dir = root()
  chain(dir)
  writeFileSync(auditPath(dir), lines(dir).join("\n") + "\n" + "{not json}\n")
  assert.equal(readAudit(dir, 0).length, 3, "display keeps working")
  assert.equal(verifyAudit(dir).ok, false, "integrity does not")
})
