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
import { htmlToPdf } from "./pdf.ts"
import { closureSummary, severitySummary } from "./findings.ts"
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
  const closures = closureSummary(input.findings)
  lines.push(
    `Closure: **${closures.confirmed}** confirmed, **${closures.open_proof_gap}** open proof gap, ` +
      `**${closures.ruled_out}** ruled out. A proof gap is not a dismissal — it means the candidate was ` +
      `plausible and neither confirmed nor excluded within this engagement.`,
  )
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
    lines.push(`- **Closure:** ${f.closure}${f.closure_downgraded ? " (downgraded from the requested state — the claim was not supported)" : ""}`)
    lines.push(`- **Confidence:** ${f.confidence}`)
    lines.push(`- **Verification:** ${f.verification}`)
    if (f.fix_effort) lines.push(`- **Fix effort:** ${f.fix_effort}`)
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
    if (f.demonstrated_by) {
      lines.push("**Demonstrated by**")
      lines.push("")
      lines.push(esc(f.demonstrated_by))
      lines.push("")
    }
    if (f.ruled_out_by) {
      lines.push("**Ruled out by**")
      lines.push("")
      lines.push(`${esc(f.ruled_out_by)}${f.ruled_out_at ? ` — at ${esc(f.ruled_out_at)}` : ""}`)
      lines.push("")
    }
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
    if (f.counterevidence) {
      lines.push("**Counterevidence considered**")
      lines.push("")
      lines.push(esc(f.counterevidence))
      lines.push("")
    }
    if (f.severity_change_conditions) {
      lines.push("**Severity changes if**")
      lines.push("")
      lines.push(esc(f.severity_change_conditions))
      lines.push("")
    }
    if (f.assumptions) {
      lines.push("**Assumptions**")
      lines.push("")
      lines.push(esc(f.assumptions))
      lines.push("")
    }
    if (f.limitations) {
      lines.push("**Limitations / assumptions**")
      lines.push("")
      lines.push(esc(f.limitations))
      lines.push("")
    }
    if (f.evidence_refs?.length) {
      lines.push("**Evidence references**")
      lines.push("")
      const stateOf = new Map((f.evidence_check ?? []).map((c) => [c.ref, c.state]))
      for (const ref of f.evidence_refs) {
        const state = stateOf.get(ref)
        lines.push(`- ${ref}${state ? ` — ${state}` : ""}`)
      }
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
      closure_summary: closureSummary(input.findings),
      findings: input.findings,
      evidence: input.evidence,
      limitations: input.limitations ?? null,
    },
    null,
    2,
  )
}

/* ------------------------------------------------------------------ html --- */

/**
 * Findings carry target-controlled text (banners, response bodies), so every
 * value is escaped. The document is self-contained — inline CSS, no scripts, no
 * external assets — so it renders offline and prints identically.
 */
function escHtml(s: string | undefined): string {
  if (!s) return "<em>(not recorded)</em>"
  return s
    .replace(/\r/g, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
}

function block(title: string, body: string | undefined): string {
  if (!body) return ""
  return `<section><h3>${escHtml(title)}</h3><pre>${escHtml(body)}</pre></section>`
}

const SEV_CLASS: Record<Severity, string> = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
}

export function renderHtml(input: ReportInput): string {
  const generatedAt = input.generatedAt ?? new Date().toISOString()
  const counts = severitySummary(input.findings)
  const closures = closureSummary(input.findings)
  const ordered = [...input.findings].sort(
    (a, b) => ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 })[b.severity] - ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 })[a.severity],
  )

  const findingHtml = ordered
    .map((f, i) => {
      const meta: string[] = [
        `<div><span class="k">ID</span><span class="v">${escHtml(f.id)}</span></div>`,
        `<div><span class="k">Severity</span><span class="v"><span class="badge ${SEV_CLASS[f.severity]}">${escHtml(SEV_LABEL[f.severity])}</span>${
          f.cvss_score !== undefined ? ` CVSS 3.1 ${f.cvss_score.toFixed(1)}` : ""
        }</span></div>`,
        f.cvss_vector ? `<div><span class="k">CVSS vector</span><span class="v"><code>${escHtml(f.cvss_vector)}</code></span></div>` : "",
        `<div><span class="k">Status</span><span class="v">${escHtml(f.status)}</span></div>`,
        `<div><span class="k">Closure</span><span class="v">${escHtml(f.closure)}${
          f.closure_downgraded ? " <em>(downgraded — the claim was not supported)</em>" : ""
        }</span></div>`,
        `<div><span class="k">Confidence</span><span class="v">${escHtml(f.confidence)}</span></div>`,
        `<div><span class="k">Verification</span><span class="v">${escHtml(f.verification)}</span></div>`,
        f.fix_effort ? `<div><span class="k">Fix effort</span><span class="v">${escHtml(f.fix_effort)}</span></div>` : "",
        `<div><span class="k">Affected asset</span><span class="v">${escHtml(f.target)}${f.endpoint ? ` → ${escHtml(f.endpoint)}` : ""}${
          f.method ? ` (${escHtml(f.method)})` : ""
        }</span></div>`,
        f.cve ? `<div><span class="k">CVE</span><span class="v">${escHtml(f.cve)}</span></div>` : "",
        f.cwe ? `<div><span class="k">CWE</span><span class="v">${escHtml(f.cwe)}</span></div>` : "",
        `<div><span class="k">Detected by</span><span class="v">${escHtml(f.source)}</span></div>`,
      ]
        .filter(Boolean)
        .join("")

      const refs = f.evidence_refs?.length
        ? (() => {
            const stateOf = new Map((f.evidence_check ?? []).map((c) => [c.ref, c.state]))
            return `<section><h3>Evidence references</h3><ul>${f.evidence_refs
              .map((r) => `<li><code>${escHtml(r)}</code>${stateOf.get(r) ? ` — ${escHtml(stateOf.get(r))}` : ""}</li>`)
              .join("")}</ul></section>`
          })()
        : ""

      return `<article class="finding ${SEV_CLASS[f.severity]}">
<h2><span class="num">${i + 1}</span> ${escHtml(f.title)}</h2>
<div class="meta">${meta}</div>
${block("Description", f.description)}
${block("Impact", f.impact)}
${block("Demonstrated by", f.demonstrated_by)}
${f.ruled_out_by ? block("Ruled out by", `${f.ruled_out_by}${f.ruled_out_at ? ` — at ${f.ruled_out_at}` : ""}`) : ""}
${block("Evidence", f.evidence)}
${block("Reproduction", f.reproduction)}
${block("Remediation", f.remediation)}
${block("Counterevidence considered", f.counterevidence)}
${block("Severity changes if", f.severity_change_conditions)}
${block("Assumptions", f.assumptions)}
${block("Limitations", f.limitations)}
${refs}
</article>`
    })
    .join("\n")

  const evidenceHtml = input.evidence.length
    ? `<table><thead><tr><th>ID</th><th>Source</th><th>Target</th><th>Label</th><th>Bytes</th><th>Redacted</th><th>SHA-256</th></tr></thead><tbody>${input.evidence
        .map(
          (e) =>
            `<tr><td><code>${escHtml(e.id)}</code></td><td>${escHtml(e.source)}</td><td>${escHtml(e.target ?? "-")}</td><td>${escHtml(
              e.label,
            )}</td><td>${e.bytes}</td><td>${e.redacted ? "yes" : "no"}</td><td><code>${escHtml(e.sha256.slice(0, 16))}…</code></td></tr>`,
        )
        .join("")}</tbody></table>`
    : "<p><em>No raw evidence artifacts were stored.</em></p>"

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment — ${escHtml(input.engagement)}</title>
<style>
  :root { --ink:#111; --muted:#666; --line:#ddd; --bg:#fff; }
  * { box-sizing: border-box; }
  body { font: 14px/1.55 -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; color: var(--ink); background: var(--bg); margin: 0; padding: 40px; max-width: 900px; }
  h1 { font-size: 26px; margin: 0 0 6px; }
  h2 { font-size: 18px; margin: 0 0 10px; border-bottom: 2px solid var(--line); padding-bottom: 6px; }
  h3 { font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin: 14px 0 4px; }
  .sub { color: var(--muted); margin-bottom: 24px; }
  .sub span { margin-right: 14px; white-space: nowrap; }
  table { border-collapse: collapse; width: 100%; margin: 8px 0 20px; }
  th, td { border: 1px solid var(--line); padding: 6px 8px; text-align: left; font-size: 13px; }
  th { background: #f6f6f6; }
  pre { background: #f8f8f8; border: 1px solid var(--line); border-radius: 4px; padding: 10px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; font-size: 12.5px; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
  .finding { border: 1px solid var(--line); border-left-width: 5px; border-radius: 5px; padding: 16px 18px; margin: 0 0 22px; page-break-inside: avoid; }
  .finding .num { color: var(--muted); font-weight: 400; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 2px 18px; margin-bottom: 6px; }
  .meta .k { display: inline-block; min-width: 110px; color: var(--muted); }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; color: #fff; }
  .sev-critical { border-left-color: #b00020; } .sev-critical .badge { background: #b00020; }
  .sev-high     { border-left-color: #d9480f; } .sev-high .badge     { background: #d9480f; }
  .sev-medium   { border-left-color: #b8860b; } .sev-medium .badge   { background: #b8860b; }
  .sev-low      { border-left-color: #2b6cb0; } .sev-low .badge      { background: #2b6cb0; }
  .sev-info     { border-left-color: #666; }    .sev-info .badge     { background: #666; }
  footer { margin-top: 36px; padding-top: 14px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12.5px; }
  @media print { body { padding: 0; } .finding { page-break-inside: avoid; } }
</style>
</head>
<body>
<h1>Security Assessment — ${escHtml(input.engagement)}</h1>
<div class="sub">
  <span>Generated: ${escHtml(generatedAt)}</span>
  <span>Session: ${escHtml(input.sessionID)}</span>
  <span>Findings: ${input.findings.length}</span>
</div>
${input.provenance ? `<p class="sub">Produced by: ${escHtml(input.provenance)}</p>` : ""}

<h2>Authorized scope</h2>
<pre>${escHtml(input.scopeSummary)}</pre>

<h2>Summary</h2>
<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>
${(["critical", "high", "medium", "low", "info"] as Severity[])
  .map((s) => `<tr><td><span class="badge ${SEV_CLASS[s]}">${escHtml(SEV_LABEL[s])}</span></td><td>${counts[s]}</td></tr>`)
  .join("")}
</tbody></table>
<p>Closure: <strong>${closures.confirmed}</strong> confirmed, <strong>${closures.open_proof_gap}</strong> open proof gap, <strong>${
    closures.ruled_out
  }</strong> ruled out. A proof gap is not a dismissal — it means the candidate was plausible and neither confirmed nor excluded within this engagement.</p>

<h2>Findings</h2>
${input.findings.length === 0 ? "<p>No findings were recorded. This is not evidence of absence: see Limitations.</p>" : findingHtml}

<h2>Evidence index</h2>
${evidenceHtml}

<h2>Limitations and untested areas</h2>
<p>${escHtml(input.limitations ?? "No limitations were recorded by the operator.")}</p>

<footer>Generated by the NullByte security capability layer. Findings are bounded by the authorized scope above; nothing outside it was tested.</footer>
</body>
</html>
`
}

/* --------------------------------------------------------------- writing --- */

export type ReportFormat = "md" | "json" | "html" | "pdf"

export const ALL_FORMATS: ReportFormat[] = ["md", "json", "html", "pdf"]

export interface WriteReportOptions {
  /** base filename, without extension */
  name?: string
  /** formats to emit; defaults to every format */
  formats?: ReportFormat[]
  /** directory to write into; defaults to `<root>/reports` */
  outDir?: string
}

export interface WrittenFile {
  format: ReportFormat
  path: string
}

export interface WriteReportResult {
  dir: string
  files: WrittenFile[]
  /** present when pdf was requested */
  pdf?: { ok: boolean; reason?: string; hint?: string }
  markdown: string
  html: string
  markdownPath?: string
  jsonPath?: string
}

/**
 * Write the report. Every emitted artifact is redacted first — including the
 * HTML that feeds the PDF — so a secret in a finding cannot reach a deliverable.
 */
export function writeReport(root: string, input: ReportInput, opts: WriteReportOptions = {}): WriteReportResult {
  const dir = ensureDir(opts.outDir ?? join(root, "reports"))
  const stamp = (input.generatedAt ?? new Date().toISOString()).replace(/[:.]/g, "-")
  const base = (opts.name ?? `report-${stamp}`).replace(/[^A-Za-z0-9._-]/g, "_")
  const formats = opts.formats?.length ? opts.formats : ALL_FORMATS

  const markdown = redactSecrets(renderMarkdown(input))
  const html = redactSecrets(renderHtml(input))
  const files: WrittenFile[] = []
  const out: WriteReportResult = { dir, files, markdown, html }

  const emit = (format: ReportFormat, ext: string, body: string) => {
    if (!formats.includes(format)) return
    const path = join(dir, `${base}.${ext}`)
    writeFileSync(path, body, { mode: 0o600 })
    files.push({ format, path })
  }

  emit("md", "md", markdown)
  emit("json", "json", renderJson(input))
  emit("html", "html", html)

  if (formats.includes("pdf")) {
    const pdfPath = join(dir, `${base}.pdf`)
    const res = htmlToPdf(html, pdfPath)
    out.pdf = res.ok ? { ok: true } : { ok: false, reason: res.reason, hint: res.hint }
    if (res.ok) files.push({ format: "pdf", path: pdfPath })
  }

  out.markdownPath = files.find((f) => f.format === "md")?.path
  out.jsonPath = files.find((f) => f.format === "json")?.path
  return out
}

