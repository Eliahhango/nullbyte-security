/**
 * CVSS scoring, the finding store, evidence capture and report rendering.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { existsSync, mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { calculateCvss31, getCvss31Severity, validateCvssBreakdown } from "../cvss31.ts"
import { createFinding, getFinding, listFindings, severitySummary, updateFinding, readAllFindings } from "../findings.ts"
import { listEvidence, readEvidence, saveEvidence } from "../evidence.ts"
import { renderJson, renderMarkdown, writeReport } from "../report.ts"
import type { CvssBreakdown, FindingInput } from "../types.ts"

const root = () => mkdtempSync(join(tmpdir(), "nb-find-"))

/* ----------------------------------------------------------------- CVSS --- */

const NETWORK_RCE: CvssBreakdown = {
  attack_vector: "N",
  attack_complexity: "L",
  privileges_required: "N",
  user_interaction: "N",
  scope: "U",
  confidentiality: "H",
  integrity: "H",
  availability: "H",
}

test("CVSS 3.1 base scores match the specification", () => {
  assert.equal(calculateCvss31(NETWORK_RCE).score, 9.8)
  assert.equal(calculateCvss31(NETWORK_RCE).severity, "critical")
  assert.equal(
    calculateCvss31({ ...NETWORK_RCE, user_interaction: "R", scope: "C", confidentiality: "L", integrity: "L", availability: "N" }).score,
    6.1,
  )
  assert.equal(calculateCvss31({ ...NETWORK_RCE, attack_complexity: "H", confidentiality: "N", integrity: "N", availability: "H" }).score, 5.9)
})

test("CVSS vector string is well formed and severity bands are right", () => {
  const r = calculateCvss31(NETWORK_RCE)
  assert.equal(r.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
  assert.equal(getCvss31Severity(0), "info")
  assert.equal(getCvss31Severity(3.9), "low")
  assert.equal(getCvss31Severity(4.0), "medium")
  assert.equal(getCvss31Severity(7.0), "high")
  assert.equal(getCvss31Severity(9.0), "critical")
})

test("invalid metric sets are rejected", () => {
  assert.ok(validateCvssBreakdown({ attack_vector: "X" }).length > 0)
  assert.deepEqual(validateCvssBreakdown(NETWORK_RCE), [])
})

/* ------------------------------------------------------------- findings --- */

function finding(overrides: Partial<FindingInput> = {}): FindingInput {
  return {
    title: "Reflected XSS in search parameter",
    description: "The q parameter is reflected into the response without encoding.",
    impact: "An attacker can execute script in a victim's session.",
    target: "app.example.com",
    endpoint: "/search",
    method: "GET",
    source: "sec_scan",
    severity: "high",
    confidence: "high",
    verification: "verified",
    evidence: "GET /search?q=<script>alert(1)</script> returned 200 with the payload unencoded.",
    remediation: "HTML-encode all reflected output.",
    ...overrides,
  }
}

test("create derives severity from CVSS when metrics are supplied", () => {
  const r = createFinding(root(), "s1", finding({ cvss_breakdown: NETWORK_RCE, severity: "low" }))
  assert.equal(r.problems.length, 0)
  assert.equal(r.finding?.severity, "critical")
  assert.equal(r.finding?.cvss_score, 9.8)
  assert.match(r.finding!.id, /^F-/)
  // A bare `verification: "verified"` flag is a claim, not evidence: the closure
  // stays open until something actually demonstrates the behaviour.
  assert.equal(r.finding?.closure, "open_proof_gap")
  assert.equal(r.finding?.status, "open")
})

test("a finding is only confirmed when something demonstrates it", () => {
  const dir = root()
  const claimed = createFinding(
    dir,
    "s1",
    finding({ closure: "confirmed", demonstrated_by: "the scanner reported it" }),
  )
  assert.equal(claimed.finding?.closure, "open_proof_gap", "an assertion must not be granted confirmed")
  assert.equal(claimed.finding?.status, "open")
  assert.equal(claimed.closureDowngraded, true)
  assert.ok(claimed.problems.some((p) => /reproduction|evidence reference/.test(p)))

  const proven = createFinding(
    dir,
    "s1",
    finding({
      title: "Server-side template injection in the invoice template",
      description: "The invoice name field is rendered through the template engine without sandboxing.",
      endpoint: "/invoice",
      closure: "confirmed",
      demonstrated_by: "the response evaluated a template expression, returning the arithmetic result",
      reproduction: "POST /invoice name={{7*7}} returned 49 in the rendered document",
    }),
  )
  assert.equal(proven.finding?.closure, "confirmed")
  assert.equal(proven.finding?.status, "confirmed")
  assert.equal(proven.closureDowngraded, undefined)
})

test("ruled_out requires a named control and where it runs", () => {
  const dir = root()
  const vague = createFinding(dir, "s1", finding({ closure: "ruled_out" }))
  assert.equal(vague.finding?.closure, "open_proof_gap", "a bare assurance must not rule a finding out")
  assert.ok(vague.problems.some((p) => p.includes("ruled_out_by")))

  const named = createFinding(
    dir,
    "s1",
    finding({
      title: "NoSQL operator injection in the login filter",
      closure: "ruled_out",
      ruled_out_by: "parameterised binding rejects operator objects before the query runs",
      ruled_out_at: "src/auth/login.ts:88",
    }),
  )
  assert.equal(named.finding?.closure, "ruled_out")
  assert.equal(named.finding?.status, "false-positive")
})

test("open_proof_gap is always accepted — a real bug is never lost", () => {
  const r = createFinding(root(), "s1", finding({ closure: "open_proof_gap", confidence: "low", limitations: "could not reach the backend" }))
  assert.equal(r.finding?.closure, "open_proof_gap")
  assert.equal(r.closureDowngraded, undefined)
  assert.equal(r.problems.length, 0)
})

test("create requires limitations when confidence is not high", () => {
  const r = createFinding(root(), "s1", finding({ confidence: "medium", limitations: undefined }))
  assert.equal(r.finding, undefined)
  assert.ok(r.problems.some((p) => p.includes("limitations")))
})

test("create rejects a malformed CVE/CWE and a missing severity", () => {
  const r = createFinding(root(), "s1", finding({ cve: "CVE-123", cwe: "79" }))
  assert.ok(r.problems.some((p) => p.includes("cve")))
  assert.ok(r.problems.some((p) => p.includes("cwe")))
  const noSev = createFinding(root(), "s1", finding({ severity: undefined }))
  assert.ok(noSev.problems.some((p) => p.includes("cvss_breakdown")))
})

test("identical findings are deduplicated by fingerprint", () => {
  const dir = root()
  const first = createFinding(dir, "s1", finding())
  const second = createFinding(dir, "s1", finding({ description: "restated differently" }))
  assert.equal(second.finding, undefined)
  assert.equal(second.duplicateOf?.id, first.finding?.id)
  assert.equal(readAllFindings(dir).length, 1)
})

test("a different endpoint is a distinct finding", () => {
  const dir = root()
  createFinding(dir, "s1", finding())
  createFinding(dir, "s1", finding({ endpoint: "/api/search" }))
  assert.equal(readAllFindings(dir).length, 2)
})

test("evidence is redacted on write", () => {
  const r = createFinding(root(), "s1", finding({ evidence: "cookie: session=abc; api_key = supersecretvalue123" }))
  assert.match(r.finding!.evidence, /REDACTED/)
  assert.doesNotMatch(r.finding!.evidence, /supersecretvalue123/)
})

test("list, filter and severity summary", () => {
  const dir = root()
  createFinding(dir, "s1", finding())
  createFinding(dir, "s1", finding({ title: "Missing HSTS", severity: "low", endpoint: "/", cvss_breakdown: undefined, verification: "unverified", confidence: "high" }))
  assert.equal(listFindings(dir).length, 2)
  assert.equal(listFindings(dir)[0].severity, "high")
  assert.equal(listFindings(dir, { minSeverity: "high" }).length, 1)
  const summary = severitySummary(readAllFindings(dir))
  assert.equal(summary.high, 1)
  assert.equal(summary.low, 1)
})

test("update requires a reason and bumps the revision", () => {
  const dir = root()
  const id = createFinding(dir, "s1", finding()).finding!.id
  assert.ok(updateFinding(dir, id, { severity: "critical" }, "").problems.length > 0)
  const ok = updateFinding(
    dir,
    id,
    { severity: "critical", counterevidence: "the WAF was checked and did not block the payload" },
    "operator re-rated after review",
  )
  assert.equal(ok.finding?.severity, "critical")
  assert.equal(ok.finding?.revision, 2)
  assert.equal(getFinding(dir, id)?.severity, "critical")
})

test("status cannot be set directly, and a stale revision is refused", () => {
  const dir = root()
  const id = createFinding(dir, "s1", finding()).finding!.id

  // `status` is not a writable field at all — the store derives it, so a
  // status-only update is refused rather than silently promoting the finding.
  const attempt = updateFinding(dir, id, { status: "confirmed" } as never, "try to promote it")
  assert.equal(attempt.finding, undefined)
  assert.match(attempt.problems.join(" "), /no effective change/)
  assert.equal(getFinding(dir, id)?.status, "open", "status must stay derived from closure")
  assert.equal(getFinding(dir, id)?.closure, "open_proof_gap")
  assert.equal(getFinding(dir, id)?.revision, 1, "a refused update must not churn the revision")

  // optimistic concurrency: the second writer using the old revision loses
  const first = updateFinding(dir, id, { impact: "restated impact" }, "clarify", { expectedRevision: 1 })
  assert.equal(first.finding?.revision, 2)
  const stale = updateFinding(dir, id, { impact: "other edit" }, "concurrent edit", { expectedRevision: 1 })
  assert.equal(stale.finding, undefined)
  assert.equal(stale.conflict, true)
  assert.match(stale.problems.join(" "), /conflict/)
})

test("evidence references are verified: absent refs are flagged, unreadable ones are not", () => {
  const dir = root()
  const r = createFinding(
    dir,
    "s1",
    finding({ evidence_refs: ["./does-not-exist.txt", "E-deadbeef"] }),
  )
  assert.equal(r.finding?.evidence_check?.length, 2)
  assert.deepEqual(
    r.finding?.evidence_check?.map((c) => c.state),
    ["missing", "missing"],
  )

  // a real file resolves
  const real = createFinding(
    dir,
    "s1",
    finding({ title: "Another issue", endpoint: "/other", evidence_refs: ["./findings.json"] }),
  )
  assert.equal(real.finding?.evidence_check?.[0].state, "exists")
})

test("semantic similarity flags a near-duplicate without merging it", () => {
  const dir = root()
  createFinding(dir, "s1", finding())
  // same endpoint and CWE, restated wording — treated as the same flaw
  const dupe = createFinding(
    dir,
    "s1",
    finding({ title: "XSS reflected in the search query parameter", description: "The search query parameter is reflected into the response without encoding." }),
  )
  assert.equal(dupe.finding, undefined)
  assert.equal(dupe.duplicateReason, "semantic")

  // a genuinely different surface is a distinct finding
  const distinct = createFinding(
    dir,
    "s1",
    finding({ title: "Server-side template injection in the invoice template", description: "The invoice name field is rendered through the template engine.", endpoint: "/invoice" }),
  )
  assert.ok(distinct.finding, "a different surface must not be merged")
})

/* ------------------------------------------------------------- evidence --- */

test("evidence is stored redacted with a hash and read back by id", () => {
  const dir = root()
  const saved = saveEvidence(dir, {
    sessionID: "s1",
    source: "sec_recon",
    label: "tls transcript",
    content: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij",
    target: "app.example.com",
  })
  assert.equal(saved.problems.length, 0)
  assert.equal(saved.record?.sha256.length, 64)
  assert.equal(saved.record?.redacted, true)
  const back = readEvidence(dir, saved.record!.id)
  assert.match(back!, /REDACTED/)
  assert.equal(listEvidence(dir).length, 1)
  assert.equal(readEvidence(dir, "E-nope"), undefined)
})

test("empty evidence is refused", () => {
  assert.ok(saveEvidence(root(), { sessionID: "s", source: "x", label: "l", content: "   " }).problems.length > 0)
})

/* --------------------------------------------------------------- report --- */

test("markdown report carries the finding, score and limitations", () => {
  const dir = root()
  createFinding(dir, "s1", finding({ cvss_breakdown: NETWORK_RCE }))
  const md = renderMarkdown({
    engagement: "unit",
    scopeSummary: "authorized_all",
    sessionID: "s1",
    findings: readAllFindings(dir),
    evidence: listEvidence(dir),
    limitations: "Only the /search endpoint was tested.",
  })
  assert.match(md, /# Security Assessment — unit/)
  assert.match(md, /Reflected XSS/)
  assert.match(md, /CVSS 3\.1 9\.8/)
  assert.match(md, /Only the \/search endpoint was tested/)
})

test("export writes markdown and json", () => {
  const dir = root()
  createFinding(dir, "s1", finding())
  const input = {
    engagement: "unit",
    scopeSummary: "authorized_all",
    sessionID: "s1",
    findings: readAllFindings(dir),
    evidence: [],
    limitations: "lab only",
  }
  const res = writeReport(dir, input, "unit-report")
  assert.equal(existsSync(res.markdownPath), true)
  assert.equal(existsSync(res.jsonPath), true)
  assert.match(res.markdownPath, /unit-report\.md$/)
  const parsed = JSON.parse(readFileSync(res.jsonPath, "utf8"))
  assert.equal(parsed.findings.length, 1)
  assert.equal(JSON.parse(renderJson(input)).findings[0].title, "Reflected XSS in search parameter")
})
