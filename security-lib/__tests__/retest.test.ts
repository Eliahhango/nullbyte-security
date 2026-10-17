/**
 * sec_retest — re-checking a finding's reproduction.
 *
 * A finding is a dated claim about a running system. Before this, the store
 * could only ever record the first observation, so a report could describe as
 * confirmed something that stopped reproducing weeks ago, with nothing on disk
 * showing it had ever been re-checked.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createFinding, getFinding, readAllFindings, recordRetest, StoreCorruptError } from "../findings.ts"
import { renderHtml, renderMarkdown } from "../report.ts"
import type { FindingInput } from "../types.ts"

const root = () => mkdtempSync(join(tmpdir(), "nb-retest-"))

const input = (over: Partial<FindingInput> = {}): FindingInput => ({
  title: "Reflected XSS in search",
  description: "the q parameter is reflected without encoding",
  impact: "session theft",
  target: "127.0.0.1:8080",
  endpoint: "/search",
  source: "manual",
  severity: "high",
  confidence: "high",
  verification: "unverified",
  evidence: "payload returned verbatim",
  reproduction: "GET /search?q=<script>alert(1)</script>",
  remediation: "encode output",
  ...over,
})

/** create a finding already closed as confirmed */
function confirmed(dir: string) {
  const r = createFinding(dir, "s1", input({ closure: "confirmed", demonstrated_by: "the payload is returned verbatim" }))
  assert.ok(r.finding, JSON.stringify(r.problems))
  assert.equal(r.finding!.closure, "confirmed")
  return r.finding!
}

const retest = (status: any, over: any = {}) => ({
  by: "void",
  method: "curl -s '/search?q=<script>alert(1)</script>'",
  status,
  observed: "payload returned verbatim",
  ...over,
})

/* ------------------------------------------------------------- recording --- */

test("a retest records before/after and updates verification", () => {
  const dir = root()
  const f = confirmed(dir)
  assert.equal(f.verification, "unverified")

  const res = recordRetest(dir, f.id, retest("verified"))
  assert.deepEqual(res.problems, [])
  assert.equal(res.entry!.before, "unverified")
  assert.equal(res.entry!.after, "verified")
  assert.equal(res.finding!.verification, "verified")
  assert.equal(res.finding!.closure, "confirmed", "a confirming retest does not disturb the closure")
  assert.equal(res.finding!.revision, f.revision + 1)
})

test("retests are append-only and keep their order", () => {
  const dir = root()
  const f = confirmed(dir)
  recordRetest(dir, f.id, retest("inconclusive"))
  recordRetest(dir, f.id, retest("verified"))

  const after = getFinding(dir, f.id)!
  assert.equal(after.retests!.length, 2)
  assert.deepEqual(after.retests!.map((r) => r.after), ["inconclusive", "verified"])
  assert.deepEqual(after.retests!.map((r) => r.before), ["unverified", "inconclusive"])
})

test("a retest is stamped with who, when and which revision it checked", () => {
  const dir = root()
  const f = confirmed(dir)
  const res = recordRetest(dir, f.id, retest("verified", { command: "curl -i /search?q=1", evidenceId: "E-abc123", exitCode: 0 }))
  const e = res.entry!
  assert.equal(e.by, "void")
  assert.equal(e.command, "curl -i /search?q=1")
  assert.equal(e.evidence_id, "E-abc123")
  assert.equal(e.exit_code, 0)
  assert.equal(e.revision, f.revision, "it records the revision it was performed against")
  assert.match(e.at, /^\d{4}-\d{2}-\d{2}T/)
})

/* ---------------------------------------------------------- contradictions --- */

test("a refuted retest reopens a confirmed finding", () => {
  const dir = root()
  const f = confirmed(dir)

  const res = recordRetest(dir, f.id, retest("refuted", { observed: "the response now escapes the payload" }))
  assert.equal(res.reopened, true)
  assert.equal(res.finding!.closure, "open_proof_gap")
  assert.equal(res.finding!.closure_downgraded, true)
  assert.equal(res.finding!.status, "open")
  assert.equal(res.finding!.verification, "refuted")
  assert.equal(res.entry!.reopened, true)
  assert.match(res.problems!.join(" "), /contradicts the recorded closure/)
  assert.match(res.problems!.join(" "), /reopened to open_proof_gap/)
})

test("a verified retest reopens a ruled-out finding", () => {
  const dir = root()
  const r = createFinding(dir, "s1", input({ closure: "ruled_out", ruled_out_by: "output encoding in the templating layer", ruled_out_at: "view.py:88" }))
  assert.ok(r.finding, JSON.stringify(r.problems))
  assert.equal(r.finding!.closure, "ruled_out")
  assert.equal(r.finding!.status, "false-positive")

  const res = recordRetest(dir, r.finding!.id, retest("verified", { observed: "the payload is reflected unescaped" }))
  assert.equal(res.reopened, true)
  assert.equal(res.finding!.closure, "open_proof_gap")
  assert.equal(res.finding!.status, "open", "a false positive that reproduces is a live finding again")
})

test("a contradiction is still recorded rather than refused", () => {
  const dir = root()
  const f = confirmed(dir)
  recordRetest(dir, f.id, retest("refuted"))
  const after = getFinding(dir, f.id)!
  assert.equal(after.retests!.length, 1, "the history keeps the evidence of the contradiction")
  assert.equal(after.verification, "refuted")
})

/* ------------------------------------------------------------- refusals --- */

test("an incomplete retest is refused and writes nothing", () => {
  const dir = root()
  const f = confirmed(dir)
  const before = getFinding(dir, f.id)!.revision

  assert.ok(recordRetest(dir, f.id, retest("verified", { method: "" })).problems!.length)
  assert.ok(recordRetest(dir, f.id, retest("verified", { observed: "  " })).problems!.length)
  assert.ok(recordRetest(dir, f.id, retest("verified", { by: "" })).problems!.length)

  const after = getFinding(dir, f.id)!
  assert.equal(after.revision, before, "a refused retest must not churn a revision")
  assert.equal(after.retests, undefined)
})

test("retesting an unknown finding is a clean failure", () => {
  const dir = root()
  confirmed(dir)
  const res = recordRetest(dir, "F-nope", retest("verified"))
  assert.deepEqual(res.problems, ["finding F-nope not found"])
})

test("a corrupt store blocks a retest, like every other write", () => {
  const dir = root()
  const f = confirmed(dir)
  const p = join(dir, "findings.json")
  writeFileSync(p, '{"findings": [{"id": "F-1", "title": "trunc')
  assert.throws(() => recordRetest(dir, f.id, retest("verified")), (e: any) => e instanceof StoreCorruptError)
})

/* --------------------------------------------------------------- report --- */

test("the report carries the retest history", () => {
  const dir = root()
  const f = confirmed(dir)
  recordRetest(dir, f.id, retest("inconclusive", { observed: "timed out" }))
  recordRetest(dir, f.id, retest("refuted", { command: "curl -s /search?q=x | grep -c '<script>'", observed: "escaped" }))

  const after = getFinding(dir, f.id)!
  const md = renderMarkdown({ findings: [after], evidence: [], sessionID: "s1" } as any)
  assert.match(md, /\*\*Retest history\*\*/)
  assert.match(md, /unverified → inconclusive/)
  assert.match(md, /inconclusive → refuted/)
  // a pipe in the recorded command must not split the table row
  const row = md.split("\n").find((l) => l.includes("grep -c"))!
  assert.ok(row.includes("\\| grep -c"), `the pipe should be escaped: ${row}`)
  const unescaped = row.replace(/\\\|/g, "").split("|").length
  assert.equal(unescaped, 6, `4 columns means 5 delimiters, got: ${row}`)

  const html = renderHtml({ findings: [after], evidence: [], sessionID: "s1" } as any)
  assert.match(html, /<h3>Retest history<\/h3>/)
  assert.match(html, /inconclusive → refuted/)
})

test("a finding without retests renders no retest section", () => {
  const dir = root()
  const f = confirmed(dir)
  const md = renderMarkdown({ findings: [getFinding(dir, f.id)!], evidence: [], sessionID: "s1" } as any)
  assert.doesNotMatch(md, /Retest history/)
})

test("retests survive a store round-trip", () => {
  const dir = root()
  const f = confirmed(dir)
  recordRetest(dir, f.id, retest("verified", { command: "nmap -sV 127.0.0.1", exitCode: 0 }))
  const reread = readAllFindings(dir).find((x) => x.id === f.id)!
  assert.equal(reread.retests!.length, 1)
  assert.equal(reread.retests![0]!.command, "nmap -sV 127.0.0.1")
})
