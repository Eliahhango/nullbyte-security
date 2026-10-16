/**
 * Report generation and export.
 *
 * Produces a structured markdown report plus a machine-readable JSON export,
 * covering the Stage F requirements: severity, affected asset/endpoint,
 * evidence + reproduction, confidence/verification status, impact, remediation,
 * evidence references, and explicit limitations / untested areas.
 */

import { writeFileSync } from "node:fs"
import { join } from "node:path"
import { ensureDir } from "./paths.ts"
import { severitySummary } from "./findings.ts"
import { redactSecrets } from "./redact.ts"
import type { EvidenceRecord } from "./evidence.ts"
import type { Finding, Severity } from "./types.ts"

export interface ReportInput {
  engagement: string
  scopeSummary: string
  sessionID: string
  findings: Finding[]
  evidence: EvidenceRecord[]
  limitations?: string
  generatedAt?: string
  /** tool/agent provenance for the report header */
  provenance?: string
}

const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
}

function esc(s: string | undefined): string {
  if (!s) return "_(not recorded)_"
  return s.replace(/\r/g, "")
}

export function renderMarkdown(input: ReportInput): string {
  const generatedAt = input.generatedAt ?? new Date().toISOString()
  const counts = severitySummary(input.findings)
  const lines: string[] = []

  lines.push(`# Security Assessment — ${input.engagement}`)
  lines.push("")
  lines.push(`- Generated: ${generatedAt}`)
  lines.push(`- Session: ${input.sessionID}`)
  if (input.provenance) lines.push(`- Produced by: ${input.provenance}`)
  lines.push(`- Findings: ${input.findings.length}`)
  lines.push("")

  lines.push("## Authorized scope")
  lines.push("")
  lines.push("```")
  lines.push(esc(input.scopeSummary))
  lines.push("```")
  lines.push("")

  lines.push("## Summary")
  lines.push("")
  lines.push("| Severity | Count |")
  lines.push("| --- | --- |")
  for (const sev of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    lines.push(`| ${SEV_LABEL[sev]} | ${counts[sev]} |`)
  }
  lines.push("")

  if (input.findings.length === 0) {
    lines.push("No findings were recorded. This is not evidence of absence: see Limitations.")
    lines.push("")
  }

  lines.push("## Findings")
  lines.push("")
  const ordered = [...input.findings].sort(
    (a, b) => ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 })[b.severity] - ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 })[a.severity],
  )
  ordered.forEach((f, i) => {
    lines.push(`### ${i + 1}. ${esc(f.title)}`)
    lines.push("")
    lines.push(`- **ID:** ${f.id}`)
    lines.push(`- **Severity:** ${SEV_LABEL[f.severity]}${f.cvss_score !== undefined ? ` (CVSS 3.1 ${f.cvss_score.toFixed(1)})` : ""}`)
    if (f.cvss_vector) lines.push(`- **CVSS vector:** \`${f.cvss_vector}\``)
    lines.push(`- **Status:** ${f.status}`)
    lines.push(`- **Confidence:** ${f.confidence}`)
    lines.push(`- **Verification:** ${f.verification}`)
    lines.push(`- **Affected asset:** ${esc(f.target)}${f.endpoint ? ` → ${esc(f.endpoint)}` : ""}${f.method ? ` (${f.method})` : ""}`)
    if (f.cve) lines.push(`- **CVE:** ${f.cve}`)
    if (f.cwe) lines.push(`- **CWE:** ${f.cwe}`)
    lines.push(`- **Detected by:** ${f.source}`)
    lines.push("")
    lines.push("**Description**")
    lines.push("")
    lines.push(esc(f.description))
    lines.push("")
    lines.push("**Impact**")
    lines.push("")
    lines.push(esc(f.impact))
    lines.push("")
    lines.push("**Evidence**")
    lines.push("")
    lines.push("```")
    lines.push(esc(f.evidence))
    lines.push("```")
    lines.push("")
    if (f.reproduction) {
      lines.push("**Reproduction**")
      lines.push("")
      lines.push("```")
      lines.push(esc(f.reproduction))
      lines.push("```")
      lines.push("")
    }
    lines.push("**Remediation**")
    lines.push("")
    lines.push(esc(f.remediation))
    lines.push("")
    if (f.limitations) {
      lines.push("**Limitations / assumptions**")
      lines.push("")
      lines.push(esc(f.limitations))
      lines.push("")
    }
    if (f.evidence_refs?.length) {
      lines.push("**Evidence references**")
      lines.push("")
      for (const ref of f.evidence_refs) lines.push(`- ${ref}`)
      lines.push("")
    }
  })

  lines.push("## Evidence index")
  lines.push("")
  if (input.evidence.length === 0) {
    lines.push("_No raw evidence artifacts were stored._")
  } else {
    lines.push("| ID | Source | Target | Label | Bytes | Redacted | SHA-256 |")
    lines.push("| --- | --- | --- | --- | --- | --- | --- |")
    for (const e of input.evidence) {
      lines.push(
        `| ${e.id} | ${e.source} | ${e.target ?? "-"} | ${e.label.replace(/\|/g, "\\|")} | ${e.bytes} | ${e.redacted ? "yes" : "no"} | \`${e.sha256.slice(0, 16)}…\` |`,
      )
    }
  }
  lines.push("")

  lines.push("## Limitations and untested areas")
  lines.push("")
  lines.push(esc(input.limitations ?? "No limitations were recorded by the operator."))
  lines.push("")

  lines.push("---")
  lines.push("")
  lines.push("_Generated by the NullByte security capability layer. Findings are bounded by the authorized scope above; nothing outside it was tested._")

  return lines.join("\n")
}

export function renderJson(input: ReportInput): string {
  return JSON.stringify(
    {
      engagement: input.engagement,
      generated_at: input.generatedAt ?? new Date().toISOString(),
      session: input.sessionID,
      provenance: input.provenance,
      scope: input.scopeSummary,
      summary: severitySummary(input.findings),
      findings: input.findings,
      evidence: input.evidence,
      limitations: input.limitations ?? null,
    },
    null,
    2,
  )
}

export interface WriteReportResult {
  markdownPath: string
  jsonPath: string
  markdown: string
}

export function writeReport(root: string, input: ReportInput, name?: string): WriteReportResult {
  const dir = ensureDir(join(root, "reports"))
  const stamp = (input.generatedAt ?? new Date().toISOString()).replace(/[:.]/g, "-")
  const base = (name ?? `report-${stamp}`).replace(/[^A-Za-z0-9._-]/g, "_")
  const markdown = redactSecrets(renderMarkdown(input))
  const json = renderJson(input)
  const markdownPath = join(dir, `${base}.md`)
  const jsonPath = join(dir, `${base}.json`)
  writeFileSync(markdownPath, markdown, { mode: 0o600 })
  writeFileSync(jsonPath, json, { mode: 0o600 })
  return { markdownPath, jsonPath, markdown }
}
