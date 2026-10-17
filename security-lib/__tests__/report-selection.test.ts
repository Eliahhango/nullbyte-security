/**
 * Report data isolation.
 *
 * The findings store is engagement-wide and append-only. Without an explicit
 * filter a report generated in one session absorbs every earlier session's
 * findings — including findings that belong to a different host. These tests
 * pin the filter and the post-condition that no foreign finding can survive.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { selectReportData, describeDrops, hostOf } from "../report-selection.ts"
import { createFinding } from "../findings.ts"
import { renderHtml } from "../report.ts"
import { secReport } from "../tools/report.ts"
import type { Finding } from "../types.ts"
import type { EvidenceRecord } from "../evidence.ts"

const tmp = () => mkdtempSync(join(tmpdir(), "nb-sel-"))

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "F-1",
    sessionID: "s1",
    title: "t",
    description: "d",
    impact: "i",
    target: "a.example.com",
    source: "manual",
    severity: "high",
    confidence: "high",
    verification: "verified",
    evidence: "e",
    remediation: "r",
    status: "open",
    closure: "open_proof_gap",
    fingerprint: "fp",
    revision: 1,
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-01T00:00:00.000Z",
    ...over,
  } as Finding
}

function artifact(over: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return {
    id: "E-1",
    sha256: "a".repeat(64),
    sessionID: "s1",
    source: "curl",
    label: "l",
    target: "a.example.com",
    created_at: "2026-01-01T00:00:00.000Z",
    bytes: 1,
    redacted: true,
    file: "E-1.txt",
    ...over,
  }
}

/* ---------------------------------------------------------------- hostOf --- */

test("hostOf normalises bare hosts, host:port and URLs", () => {
  assert.equal(hostOf("127.0.0.1:8080"), "127.0.0.1")
  assert.equal(hostOf("http://127.0.0.1:8080/.env"), "127.0.0.1")
  assert.equal(hostOf("EXAMPLE.com"), "example.com")
  assert.equal(hostOf("https://sub.example.com/x"), "sub.example.com")
  assert.equal(hostOf(undefined), null)
  assert.equal(hostOf("  "), null)
})

/* ------------------------------------------------------------- isolation --- */

test("session selection excludes findings from every other session", () => {
  const res = selectReportData(
    [finding({ id: "A", sessionID: "s1" }), finding({ id: "B", sessionID: "s2", target: "b.example.com" })],
    [],
    { sessionID: "s1" },
  )
  assert.deepEqual(res.findings.map((f) => f.id), ["A"])
  assert.equal(res.drops.otherSession, 1)
  assert.deepEqual(res.foreignHosts, ["b.example.com"])
})

test("target selection excludes findings on other hosts", () => {
  const res = selectReportData(
    [finding({ id: "A", target: "a.example.com" }), finding({ id: "B", target: "b.example.com" })],
    [],
    { host: "a.example.com" },
  )
  assert.deepEqual(res.findings.map((f) => f.id), ["A"])
  assert.equal(res.drops.otherHost, 1)
})

test("target selection matches host:port findings by host alone", () => {
  const res = selectReportData([finding({ id: "A", target: "127.0.0.1:8080" })], [], { host: "127.0.0.1" })
  assert.deepEqual(res.findings.map((f) => f.id), ["A"])
})

test("out-of-scope hosts never reach the report", () => {
  const res = selectReportData(
    [finding({ id: "A", target: "in.example.com" }), finding({ id: "B", target: "out.example.com" })],
    [],
    { isAuthorized: (h) => h === "in.example.com" },
  )
  assert.deepEqual(res.findings.map((f) => f.id), ["A"])
  assert.equal(res.drops.outOfScope, 1)
})

test("evidence is filtered by the same session boundary", () => {
  const res = selectReportData([], [artifact({ id: "E-1", sessionID: "s1" }), artifact({ id: "E-2", sessionID: "s2" })], {
    sessionID: "s1",
  })
  assert.deepEqual(res.evidence.map((e) => e.id), ["E-1"])
  assert.equal(res.drops.evidence, 1)
})

test("evidence on an out-of-scope host is excluded", () => {
  const res = selectReportData([], [artifact({ target: "out.example.com" })], { isAuthorized: () => false })
  assert.equal(res.evidence.length, 0)
  assert.equal(res.drops.evidence, 1)
})

test("the post-condition holds: no foreign finding can survive selection", () => {
  // a mixed set spanning two sessions and three hosts
  const all = [
    finding({ id: "A", sessionID: "s1", target: "a.example.com" }),
    finding({ id: "B", sessionID: "s1", target: "b.example.com" }),
    finding({ id: "C", sessionID: "s2", target: "a.example.com" }),
  ]
  const res = selectReportData(all, [], { sessionID: "s1", host: "a.example.com" })
  assert.deepEqual(res.findings.map((f) => f.id), ["A"])
  for (const f of res.findings) {
    assert.equal(hostOf(f.target), "a.example.com")
    assert.equal(f.sessionID, "s1")
  }
})

test("no filters means no drops — engagement coverage is explicit, not accidental", () => {
  const res = selectReportData([finding({ id: "A", sessionID: "s1" }), finding({ id: "B", sessionID: "s2" })], [], {})
  assert.equal(res.findings.length, 2)
  assert.equal(res.drops.otherSession, 0)
})

test("describeDrops is empty when nothing was excluded", () => {
  assert.equal(describeDrops({ otherSession: 0, otherHost: 0, outOfScope: 0, evidence: 0 }, []), "")
})

test("describeDrops names the counts and the foreign hosts", () => {
  const line = describeDrops({ otherSession: 2, otherHost: 0, outOfScope: 1, evidence: 3 }, ["b.example.com"])
  assert.match(line, /2 from another scan session/)
  assert.match(line, /1 outside the authorized scope/)
  assert.match(line, /3 evidence record/)
  assert.match(line, /b\.example\.com/)
})

/* --------------------------------------------------- through the tool ------ */

test("sec_report defaults to this session and does not mix in another session's target", async () => {
  const project = tmp()
  const ctx: any = { worktree: project, directory: project, sessionID: "s1", agent: "void" }
  const root = join(project, ".nullbyte", "security")

  const base = {
    description: "d",
    impact: "i",
    source: "manual",
    severity: "high" as const,
    confidence: "high" as const,
    verification: "verified" as const,
    evidence: "e",
    remediation: "r",
  }

  createFinding(root, "s1", { ...base, title: "SESSION-ONE", target: "a.example.com" })
  createFinding(root, "s2", { ...base, title: "SESSION-TWO", target: "b.example.com" })

  const md = await secReport.execute({ action: "preview" }, ctx)

  assert.match(md, /SESSION-ONE/)
  assert.equal(md.includes("SESSION-TWO"), false, "a finding from another session leaked into the report")
  assert.match(md, /Coverage: this scan session/)
})

test("coverage=engagement includes every session, deliberately", async () => {
  const project = tmp()
  const ctx: any = { worktree: project, directory: project, sessionID: "s1", agent: "void" }
  const root = join(project, ".nullbyte", "security")
  const base = {
    description: "d",
    impact: "i",
    source: "manual",
    severity: "high" as const,
    confidence: "high" as const,
    verification: "verified" as const,
    evidence: "e",
    remediation: "r",
  }
  createFinding(root, "s1", { ...base, title: "SESSION-ONE", target: "a.example.com" })
  createFinding(root, "s2", { ...base, title: "SESSION-TWO", target: "b.example.com" })

  const md = await secReport.execute({ action: "preview", coverage: "engagement" }, ctx)
  assert.match(md, /SESSION-ONE/)
  assert.match(md, /SESSION-TWO/)
})

/* ---------------------------------------------------------------- layout --- */

test("the stylesheet pins the layout rules that fix overflow and page breaks", () => {
  const html = renderHtml({ engagement: "e", scopeSummary: "s", sessionID: "s1", findings: [], evidence: [] })
  // full-width, non-splitting cards
  assert.match(html, /\.finding\s*\{[^}]*width:\s*100%/)
  assert.match(html, /\.finding\s*\{[^}]*max-width:\s*100%/)
  assert.match(html, /\.finding\s*\{[^}]*box-sizing:\s*border-box/)
  assert.match(html, /page-break-inside:\s*avoid/)
  assert.match(html, /break-inside:\s*avoid/)
  // long unbroken strings wrap instead of escaping the card
  assert.match(html, /overflow-wrap:\s*anywhere/)
  assert.match(html, /word-break:\s*break-word/)
  assert.match(html, /min-width:\s*0/)
  // grid is constrained and consistent
  assert.match(html, /grid-template-columns:\s*repeat\(auto-fit,\s*minmax\(220px,\s*1fr\)\)/)
  assert.match(html, /gap:\s*8px 16px/)
  // uniform page margins
  assert.match(html, /padding:\s*40px 48px/)
})

test("severity badges get their background from a compound selector", () => {
  // `.sev-x .badge` is a descendant selector and never matched the summary
  // table's badge, which carries the severity class itself — leaving the label
  // white on white. It must be `.badge.sev-x`.
  const html = renderHtml({ engagement: "e", scopeSummary: "s", sessionID: "s1", findings: [], evidence: [] })
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    assert.match(html, new RegExp(`\\.badge\\.sev-${sev}\\s*\\{[^}]*background`), `${sev} badge has no background rule`)
  }
  assert.equal(/\.sev-critical\s+\.badge\s*\{/.test(html), false, "descendant selector is back")
})

test("metadata renders as stacked label/value cells, not a wide inline pair", () => {
  const f = finding({ id: "F-1", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" })
  const html = renderHtml({ engagement: "e", scopeSummary: "s", sessionID: "s1", findings: [f], evidence: [] })
  assert.match(html, /<div class="cell"><span class="k">CVSS vector<\/span><span class="v"><code>/)
  // the long vector is present and unescaped-but-intact; wrapping is CSS's job
  assert.match(html, /CVSS:3\.1\/AV:N\/AC:L\/PR:N\/UI:R\/S:U\/C:N\/I:L\/A:N/)
})
