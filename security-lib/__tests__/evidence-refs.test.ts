/**
 * Evidence reference verification.
 *
 * The rule that matters most: only an explicit ENOENT/ENOTDIR establishes
 * absence. A permission or I/O failure must never be reported as "the artifact
 * is missing", because that would invalidate a finding that is actually sound.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { chmodSync, mkdtempSync, mkdirSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  MAX_EVIDENCE_REF_LENGTH,
  classifyEvidenceRef,
  summarizeEvidenceRefs,
  verifyEvidenceRefs,
} from "../evidence-refs.ts"
import { saveEvidence } from "../evidence.ts"

const root = () => mkdtempSync(join(tmpdir(), "nb-refs-"))

test("references are classified into evidence ids, paths and invalid", () => {
  assert.equal(classifyEvidenceRef("E-1a2b3c4d").kind, "evidence-id")
  assert.equal(classifyEvidenceRef("./src/auth.ts:42").kind, "path")
  assert.equal(classifyEvidenceRef("file:src/auth.ts:42").value, "src/auth.ts", "the line suffix is stripped")
  assert.equal(classifyEvidenceRef("/var/log/app.log").kind, "path")
})

test("non-artifact references are rejected with a reason", () => {
  const cases: Array<[string, RegExp]> = [
    ["https://example.com/x", /URLs are not evidence/],
    ["//host/share", /UNC/],
    ["\\\\host\\share", /UNC/],
    ["C:\\tmp\\x.txt", /drive-letter/],
    ["src/auth.ts", /relative references must start/],
    ["", /empty/],
    ["x".repeat(MAX_EVIDENCE_REF_LENGTH + 1), /longer than/],
  ]
  for (const [ref, pattern] of cases) {
    const c = classifyEvidenceRef(ref)
    assert.equal(c.kind, "invalid", `${ref} should be invalid`)
    assert.match(c.reason ?? "", pattern)
  }
  assert.equal(classifyEvidenceRef("bad\x01path").kind, "invalid", "control characters are rejected")
})

test("a real file resolves and an absent file is reported as missing", () => {
  const dir = root()
  writeFileSync(join(dir, "evidence.txt"), "raw output")
  const report = verifyEvidenceRefs(dir, dir, ["./evidence.txt", "./nope.txt"])
  assert.deepEqual(report.verified, ["./evidence.txt"])
  assert.deepEqual(report.missing, ["./nope.txt"])
  assert.equal(report.ok, false)
})

test("a directory is not evidence", () => {
  const dir = root()
  mkdirSync(join(dir, "sub"))
  const report = verifyEvidenceRefs(dir, dir, ["./sub"])
  assert.deepEqual(report.missing, ["./sub"])
})

test("a permission failure is 'unchecked', never 'missing'", (t) => {
  if (process.platform === "win32") return t.skip("Windows does not enforce POSIX mode bits")
  const dir = root()
  const locked = join(dir, "locked")
  mkdirSync(locked)
  writeFileSync(join(locked, "secret.txt"), "x")
  chmodSync(locked, 0o000)
  try {
    const report = verifyEvidenceRefs(dir, dir, ["./locked/secret.txt"])
    if (process.getuid?.() === 0) return // root ignores mode bits; the rule cannot be exercised
    assert.deepEqual(report.missing, [], "a permission failure must not be reported as absence")
    assert.deepEqual(report.unchecked, ["./locked/secret.txt"])
    assert.equal(report.ok, true, "an unreadable reference must not invalidate the finding")
  } finally {
    chmodSync(locked, 0o755)
  }
})

test("evidence store ids are resolved against the engagement", () => {
  const dir = root()
  const saved = saveEvidence(dir, { sessionID: "s1", source: "sec_recon", label: "tls", content: "handshake transcript" })
  const report = verifyEvidenceRefs(dir, dir, [saved.record!.id, "E-00000000"])
  assert.deepEqual(report.verified, [saved.record!.id])
  assert.deepEqual(report.missing, ["E-00000000"])
})

test("references are deduplicated and bounded", () => {
  const dir = root()
  writeFileSync(join(dir, "a.txt"), "x")
  const report = verifyEvidenceRefs(dir, dir, ["./a.txt", "./a.txt", "  ./a.txt  "])
  assert.equal(report.checked.length, 1)
  assert.equal(report.verified.length, 1)
})

test("the summary distinguishes resolved, unresolved and unchecked", () => {
  const dir = root()
  writeFileSync(join(dir, "ok.txt"), "x")
  const report = verifyEvidenceRefs(dir, dir, ["./ok.txt", "./gone.txt"])
  const text = summarizeEvidenceRefs(report)
  assert.match(text, /1\/2 references resolved/)
  assert.match(text, /unresolved: \.\/gone\.txt/)
  assert.match(summarizeEvidenceRefs(verifyEvidenceRefs(dir, dir, [])), /no evidence references/)
})
