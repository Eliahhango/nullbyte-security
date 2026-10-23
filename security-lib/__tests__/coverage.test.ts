import test from "node:test"
import assert from "node:assert/strict"
import { existsSync, mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createFinding } from "../findings.ts"
import {
  coverageSummary,
  listCoverage,
  recordCoverage,
  renderCoverageJson,
  selectCoverage,
  updateCoverage,
} from "../coverage.ts"
import { renderMarkdown, writeReport } from "../report.ts"
import { renderSarif } from "../interop.ts"
import { secReport } from "../tools/report.ts"
import { saveThreatModel } from "../threat-model.ts"
import type { FindingInput } from "../types.ts"

const root = () => mkdtempSync(join(tmpdir(), "nb-coverage-"))

function finding(overrides: Partial<FindingInput> = {}): FindingInput {
  return {
    title: "Missing authorization on admin endpoint",
    description: "A regular user can call the admin endpoint.",
    impact: "Privilege escalation.",
    target: "app.example.com",
    endpoint: "/admin",
    source: "sec_scan",
    severity: "high",
    confidence: "high",
    verification: "verified",
    evidence: "GET /admin returned 200 for a regular user.",
    remediation: "Enforce role checks server-side.",
    ...overrides,
  }
}

test("reported coverage requires an existing finding and non-reported outcomes require evidence", () => {
  const dir = root()
  const missing = recordCoverage(dir, "s1", {
    surface: "/admin",
    risk_area: "authorization",
    outcome: "reported",
  })
  assert.ok(missing.problems.some((p) => /finding_id/.test(p)))

  const unknown = recordCoverage(dir, "s1", {
    surface: "/admin",
    risk_area: "authorization",
    outcome: "reported",
    finding_id: "F-nope",
  })
  assert.ok(unknown.problems.some((p) => /does not exist/.test(p)))

  const noEvidence = recordCoverage(dir, "s1", {
    surface: "/login",
    risk_area: "authentication",
    outcome: "ruled_out",
  })
  assert.ok(noEvidence.problems.some((p) => /requires evidence/.test(p)))
})

test("the ledger rejects duplicates and updates keep a revision history", () => {
  const dir = root()
  const created = recordCoverage(dir, "s1", {
    target: "app.example.com",
    surface: "/login",
    risk_area: "authentication",
    outcome: "no_issue_found",
    evidence: "Tried default credentials and lockout; both controls held.",
    recorded_by: "agent-a",
  })
  assert.equal(created.problems.length, 0)
  const id = created.entry!.id

  const duplicate = recordCoverage(dir, "s1", {
    target: "APP.EXAMPLE.COM",
    surface: " /login ",
    risk_area: "Authentication",
    outcome: "needs_follow_up",
    evidence: "Retest MFA bypass.",
  })
  assert.equal(duplicate.entry, undefined)
  assert.equal(duplicate.existing?.id, id)

  const updated = updateCoverage(dir, id, {
    outcome: "ruled_out",
    evidence: "Account lockout and rate limiting both blocked the attempt.",
    recorded_by: "agent-b",
  })
  assert.equal(updated.problems.length, 0)
  assert.equal(updated.entry?.revision, 2)
  assert.equal(updated.entry?.outcome, "ruled_out")
  assert.equal(updated.entry?.history.length, 2)
  assert.equal(updated.entry?.history[1]?.by, "agent-b")
})

test("summary counts outcomes and finds findings with no linked coverage", () => {
  const dir = root()
  const one = createFinding(dir, "s1", finding())
  assert.ok(one.finding)
  const second = createFinding(dir, "s1", finding({ title: "Verbose error page", target: "api.example.com", endpoint: "/v1/users" }))
  assert.ok(second.finding)

  recordCoverage(dir, "s1", {
    target: "app.example.com",
    surface: "/admin",
    risk_area: "authorization",
    outcome: "reported",
    finding_id: one.finding!.id,
  })
  recordCoverage(dir, "s1", {
    target: "app.example.com",
    surface: "/login",
    risk_area: "authentication",
    outcome: "no_issue_found",
    evidence: "Login throttling held.",
  })
  recordCoverage(dir, "s1", {
    target: "api.example.com",
    surface: "/v1/users",
    risk_area: "error handling",
    outcome: "needs_follow_up",
    evidence: "Retest with an invalid content type.",
  })

  const entries = listCoverage(dir)
  const summary = coverageSummary(entries, [one.finding!, second.finding!])
  assert.equal(summary.total, 3)
  assert.equal(summary.by_outcome.reported, 1)
  assert.equal(summary.by_outcome.no_issue_found, 1)
  assert.equal(summary.by_outcome.needs_follow_up, 1)
  assert.equal(summary.findings_without_coverage.length, 1)
  assert.equal(summary.findings_without_coverage[0]?.id, second.finding!.id)

  assert.equal(selectCoverage(entries, { sessionID: "s1" }).length, 3)
  assert.equal(selectCoverage(entries, { host: "app.example.com" }).length, 2)
})

test("report renders the ledger and writes a coverage sidecar", () => {
  const dir = root()
  const op = recordCoverage(dir, "s1", {
    target: "app.example.com",
    surface: "/login",
    risk_area: "authentication",
    outcome: "no_issue_found",
    evidence: "Tried default credentials and lockout; both controls held.",
  })
  assert.ok(op.entry)

  const input = {
    engagement: "test",
    scopeSummary: "app.example.com",
    sessionID: "s1",
    findings: [],
    evidence: [],
    coverage: [op.entry!],
  }
  const md = renderMarkdown(input)
  assert.match(md, /## Coverage/)
  assert.match(md, /No issue found/)
  assert.match(md, /Covered surfaces/)

  const empty = renderMarkdown({ ...input, coverage: [] })
  assert.match(empty, /No coverage ledger entries were recorded/)

  const written = writeReport(dir, input, { name: "cov", formats: ["json"] })
  assert.ok(written.coveragePath)
  assert.ok(existsSync(written.coveragePath!))
  const sidecar = JSON.parse(readFileSync(written.coveragePath!, "utf8"))
  assert.equal(sidecar.summary.total, 1)
  assert.equal(sidecar.entries[0].id, op.entry!.id)

  const json = JSON.parse(renderCoverageJson([op.entry!], []))
  assert.equal(json.schema_version, 1)

  const sarif = JSON.parse(renderSarif(input))
  assert.equal(sarif.runs[0].invocations[0].properties.coverage.total, 1)
  assert.match(sarif.runs[0].invocations[0].toolExecutionNotifications[1].message.text, /coverage: 1 observation/)
})


test("sec_report selects the session ledger and embeds the target threat model", async () => {
  const project = mkdtempSync(join(tmpdir(), "nb-coverage-tool-"))
  const ctx: any = { worktree: project, directory: project, sessionID: "s1", agent: "void" }
  const root = join(project, ".nullbyte", "security")

  const created = createFinding(root, "s1", finding())
  assert.ok(created.finding)
  const op = recordCoverage(root, "s1", {
    target: "app.example.com",
    surface: "/admin",
    risk_area: "authorization",
    outcome: "reported",
    finding_id: created.finding!.id,
  })
  assert.ok(op.entry)
  saveThreatModel(root, "app.example.com", "THREAT-MODEL-TEXT: anonymous actor reaches the admin boundary.", "void")

  const md = await secReport.execute({ action: "preview" }, ctx)
  assert.match(md, /## Coverage/)
  assert.match(md, /Covered surfaces/)
  assert.match(md, /THREAT-MODEL-TEXT/)

  const out = await secReport.execute({ action: "export", format: "json" }, ctx)
  const coveragePath = /coverage\s+(\S+\.coverage\.json)/.exec(out)?.[1]
  assert.ok(coveragePath, out)
  assert.ok(existsSync(coveragePath!))
  const sidecar = JSON.parse(readFileSync(coveragePath!, "utf8"))
  assert.equal(sidecar.entries[0].id, op.entry!.id)
})
