/**
 * Report generation and export.
 *
 * Produces a structured markdown report plus a machine-readable JSON export,
 * covering the Stage F requirements: severity, affected asset/endpoint,
 * evidence + reproduction, confidence/verification status, impact, remediation,
 * evidence references, and explicit limitations / untested areas.
 */

import { chmodSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { ensureDir } from "./paths.ts"
import { htmlToPdf, COPYRIGHT_TEXT } from "./pdf.ts"
import { closureSummary, severitySummary } from "./findings.ts"
import { redactSecrets } from "./redact.ts"
import { collectCredentials, renderCredentialsMarkdown } from "./credentials.ts"
import type { CredentialRecord } from "./credentials.ts"
import type { EvidenceRecord } from "./evidence.ts"
import type { Finding, Severity } from "./types.ts"

/**
 * Vendor and model identifiers must never reach a deliverable. The report is a
 * client-facing artifact: naming the harness or the model that produced it is a
 * branding leak and an information disclosure, and the operator has said so
 * explicitly. Enforced at render time, so it holds no matter what a caller
 * passes in `provenance`.
 *
 * Deliberately narrow. It strips provider/model slugs (`opencode/deepseek-...`),
 * bare vendor and model-family names, and the punctuation left behind — but it
 * does not touch finding content, because a target that happens to be called
 * "opencode" is evidence, not branding.
 */
const VENDOR_SLUG =
  /\b(?:opencode|anthropic|openai|google|deepseek|gemini|meta|mistral(?:ai)?|qwen|xai|cohere|ollama|azure|vertex|bedrock|perplexity|copilot|groq|fireworks|together)\/[\w.\-]+/gi
const VENDOR_NAME =
  /\b(?:gpt-?[\w.\-]+|(?:opencode|anthropic|openai|deepseek|gemini|chatgpt|claude|llama|mistral|qwen|grok|cohere|ollama|bedrock|vertex|perplexity|copilot|groq)(?:[\s\-]+v?[\d][\w.\-]*)?)\b/gi

/** Strip vendor/model identifiers from a provenance string. */
export function sanitizeProvenance(raw: string): string {
  let s = raw.replace(VENDOR_SLUG, "").replace(VENDOR_NAME, "")
  s = s.replace(/\(\s*\)/g, "").replace(/\[\s*\]/g, "") // brackets emptied by a removed slug
  s = s.replace(/\s{2,}/g, " ")
  s = s.replace(/\s+([,;.])/g, "$1") // " ," -> ","
  s = s.replace(/([,;])\s*(?=[,;])/g, "") // collapse duplicate separators
  s = s.replace(/\bvia\s*$/i, "") // a dangling "via" after a removed slug
  s = s.replace(/^[\s\-–—:;,./]+/, "")
  s = s.replace(/[\s\-–—:;,./]+$/, "")
  return s.replace(/\s{2,}/g, " ").trim()
}

/** The provenance line, or undefined when nothing identifiable survives. */
function cleanProvenance(input: ReportInput): string | undefined {
  const raw = input.provenance?.trim()
  if (!raw) return undefined
  return sanitizeProvenance(raw) || undefined
}

export interface ReportInput {
  engagement: string
  scopeSummary: string
  sessionID: string
  findings: Finding[]
  evidence: EvidenceRecord[]
  /** id -> raw artifact text, when the caller asked for full evidence */
  evidenceContent?: Record<string, string>
  /** true when redaction was deliberately skipped — adds a warning banner */
  unredacted?: boolean
  /** what this report covers (session/target), and what selection excluded */
  selectionNote?: string
  limitations?: string
  generatedAt?: string
  /** tool/agent provenance for the report header */
  provenance?: string
  /** document version, e.g. "1.0" */
  version?: string
  /** why the engagement happened; a default is stated when absent */
  background?: string
  /** what the engagement set out to answer; a default is stated when absent */
  objectives?: string
  /** operator-supplied testing window; activity timestamps are derived when absent */
  testWindow?: string
}

const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
}

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

const EFFORT_RANK: Record<string, number> = { trivial: 0, low: 1, medium: 2, high: 3 }

/**
 * Emitted when the caller deliberately disabled redaction. The report is a
 * credential dump at that point; anyone holding the file can use what is in it.
 */
const UNREDACTED_WARNING =
  "UNREDACTED — this report contains live secrets (credentials, tokens, keys) exactly as captured. " +
  "It is a sensitive deliverable: restrict distribution, do not commit it to version control, and rotate " +
  "every credential it discloses once the engagement closes."

const UNREDACTED_BANNER_MD = [
  "> [!WARNING]",
  `> **${UNREDACTED_WARNING}**`,
  "",
]

function esc(s: string | undefined): string {
  if (!s) return "_(not recorded)_"
  return s.replace(/\r/g, "")
}

/**
 * Markdown table cell. A retest method is usually a shell command, and a command
 * containing a pipe would otherwise split the row into extra columns.
 */
function cell(s: string | undefined, max = 200): string {
  const t = esc(s).replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ")
  return t.length > max ? `${t.slice(0, max - 1)}…` : t
}

/* ------------------------------------------------------- derived structure --- */

/** First sentence of a block of prose, for one-line roll-ups. */
function firstSentence(s: string | undefined): string {
  if (!s) return ""
  const flat = s.replace(/\s+/g, " ").trim()
  const m = flat.match(/^.*?[.!?](\s|$)/)
  return (m ? m[0] : flat).trim()
}

interface Timeline {
  first?: string
  last?: string
  hours?: number
  events: number
}

/**
 * Derive the activity window from recorded timestamps.
 *
 * This is the window of *records*, not necessarily the window of testing — a
 * quiet period with no findings leaves no trace. It is labelled as such.
 */
function timelineOf(input: ReportInput): Timeline {
  const stamps: string[] = []
  for (const f of input.findings) {
    if (f.created_at) stamps.push(f.created_at)
    if (f.updated_at) stamps.push(f.updated_at)
  }
  for (const e of input.evidence) if (e.created_at) stamps.push(e.created_at)
  const times = stamps.map((s) => Date.parse(s)).filter((n) => !Number.isNaN(n))
  if (times.length === 0) return { events: 0 }
  const first = Math.min(...times)
  const last = Math.max(...times)
  return {
    first: new Date(first).toISOString(),
    last: new Date(last).toISOString(),
    hours: Math.round(((last - first) / 3_600_000) * 10) / 10,
    events: times.length,
  }
}

/** Findings ordered for remediation: severity first, then cheapest fix. */
function remediationRoadmap(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEV_RANK[b.severity] - SEV_RANK[a.severity] ||
      (EFFORT_RANK[a.fix_effort ?? ""] ?? 2) - (EFFORT_RANK[b.fix_effort ?? ""] ?? 2) ||
      a.title.localeCompare(b.title),
  )
}

/**
 * The executive summary is a roll-up of what was recorded — counts, the
 * highest-risk findings and their own stated impact. It invents no business
 * context it was not given.
 */
function executiveSummaryLines(
  input: ReportInput,
  counts: Record<Severity, number>,
  closures: ReturnType<typeof closureSummary>,
): string[] {
  const lines: string[] = []
  const total = input.findings.length
  const top = input.findings
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity])

  lines.push(
    `This assessment covered **${input.engagement}** within the authorized scope below. ` +
      (total === 0
        ? "No findings were recorded."
        : `${total} finding${total === 1 ? "" : "s"} were recorded: ${counts.critical} critical, ${counts.high} high, ` +
          `${counts.medium} medium, ${counts.low} low, ${counts.info} info.`),
  )
  lines.push("")

  if (top.length) {
    lines.push("The highest-risk issues are:")
    lines.push("")
    for (const f of top.slice(0, 5)) {
      const impact = firstSentence(f.impact)
      const asset = f.target ? ` (${f.target}${f.endpoint ? f.endpoint : ""})` : ""
      lines.push(`- **${SEV_LABEL[f.severity]} — ${f.title}**${asset}${impact ? `: ${impact}` : ""}`)
    }
    lines.push("")
  } else if (total > 0) {
    lines.push("No critical or high severity issues were confirmed within scope.")
    lines.push("")
  }

  lines.push(
    `Closure: **${closures.confirmed}** confirmed, **${closures.open_proof_gap}** open proof gap, ` +
      `**${closures.ruled_out}** ruled out. A proof gap is not a dismissal — the candidate was plausible and ` +
      `neither confirmed nor excluded within this engagement.`,
  )
  lines.push("")
  lines.push(
    "This summary is bounded by the scope and the limitations recorded below. Anything listed as untested was not " +
      "exercised, and absence of findings there is not evidence of absence.",
  )
  return lines
}

function backgroundLines(input: ReportInput): string[] {
  return [
    input.background ??
      `The engagement **${input.engagement}** was conducted to identify and verify security weaknesses in the systems ` +
        `named under Authorized scope, and to record each one with reproducible evidence.`,
    "",
    "**Objectives**",
    "",
    input.objectives ??
      "Determine whether the authorized assets expose exploitable weaknesses; confirm each candidate with evidence " +
        "before reporting it; and state plainly what was not tested.",
    "",
  ]
}

function timelineLines(input: ReportInput): string[] {
  const t = timelineOf(input)
  const lines: string[] = []
  if (input.testWindow) lines.push(`- **Testing window (operator-supplied):** ${input.testWindow}`)
  if (t.events === 0) {
    lines.push("- No timestamped activity was recorded, so the engagement window cannot be derived.")
  } else {
    lines.push(`- **First recorded activity:** ${t.first}`)
    lines.push(`- **Last recorded activity:** ${t.last}`)
    lines.push(`- **Elapsed between first and last record:** ${t.hours} hours across ${t.events} timestamped records`)
  }
  lines.push("")
  lines.push(
    "_This window reflects the records the engagement kept, not necessarily every hour spent testing: a quiet period " +
      "that produced no finding and no evidence leaves no timestamp._",
  )
  return lines
}

/** Static: how a severity, closure, confidence and verification value is earned. */
const RISK_RATING_MD = [
  "Severity is derived from **CVSS 3.1 base metrics**, never asserted by hand when metrics are available. The numeric " +
    "score maps onto the standard bands:",
  "",
  "| Band | CVSS 3.1 base score |",
  "| --- | --- |",
  "| Critical | 9.0 – 10.0 |",
  "| High | 7.0 – 8.9 |",
  "| Medium | 4.0 – 6.9 |",
  "| Low | 0.1 – 3.9 |",
  "| Info | 0.0 |",
  "",
  "**Closure states**",
  "",
  "- `confirmed` — the behaviour was reproduced and is supported by evidence.",
  "- `ruled_out` — the candidate was tested and a specific control makes it safe; the control and where it was observed are recorded.",
  "- `open_proof_gap` — the candidate was plausible and neither confirmed nor excluded within this engagement. This is not a dismissal.",
  "",
  "**Confidence** (`low` / `medium` / `high`) describes how sure the operator is of the finding given the evidence.",
  "**Verification** (`unverified` / `verified` / `refuted` / `inconclusive`) records whether the claim was independently checked.",
  "",
  "**Fix effort** (`trivial` / `low` / `medium` / `high`) is the operator's estimate of remediation cost and drives the " +
    "ordering of the remediation roadmap below.",
  "",
  "**Redaction posture** — this deployment is configured for **full disclosure**: captured credentials are recorded " +
    "verbatim and reproduced in full in the Credentials section. This deliberately departs from PTES " +
    "Post-Exploitation and OWASP APTS (APTS-MR-019 / APTS-TP-013), which call for plaintext credentials to be kept " +
    "out of reports. See `docs/PENTEST.md`. When `redact: true` is passed, every credential value is replaced with " +
    "`[REDACTED:credential]` — but a value redacted at capture cannot be recovered by a later report.",
]

const DISCLAIMER =
  "This report records the state of the authorized systems during the testing window only. It is bounded by the scope " +
  "and limitations stated above: systems, paths, roles or times not covered were not tested, and their absence from " +
  "this report is not a statement that they are secure. Security posture changes; findings may not hold after the " +
  "window. The contents are confidential to the engagement's stakeholders — and, under the full-disclosure posture, " +
  "include live credentials that must be rotated once the engagement closes."


export function renderMarkdown(input: ReportInput): string {
  const generatedAt = input.generatedAt ?? new Date().toISOString()
  const counts = severitySummary(input.findings)
  const credentials = collectCredentials(input)
  const lines: string[] = []

  lines.push(`# Security Assessment — ${input.engagement}`)
  lines.push("")
  lines.push(`- Generated: ${generatedAt}`)
  lines.push(`- Session: ${input.sessionID}`)
  lines.push(`- Document version: ${input.version ?? "1.0"}`)
  const provenance = cleanProvenance(input)
  if (provenance) lines.push(`- Produced by: ${provenance}`)
  lines.push(`- Findings: ${input.findings.length}`)
  if (input.selectionNote) lines.push(`- Coverage: ${input.selectionNote}`)
  lines.push("")
  if (input.unredacted) lines.push(...UNREDACTED_BANNER_MD)

  const closures = closureSummary(input.findings)

  lines.push("## Executive summary")
  lines.push("")
  lines.push(...executiveSummaryLines(input, counts, closures))
  lines.push("")

  lines.push("## Background and objectives")
  lines.push("")
  lines.push(...backgroundLines(input))
  lines.push("")

  lines.push("## Authorized scope")
  lines.push("")
  lines.push("```")
  lines.push(esc(input.scopeSummary))
  lines.push("```")
  lines.push("")

  lines.push("## Timeline")
  lines.push("")
  lines.push(...timelineLines(input))
  lines.push("")

  lines.push("## Summary")
  lines.push("")
  lines.push("| Severity | Count |")
  lines.push("| --- | --- |")
  for (const sev of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    lines.push(`| ${SEV_LABEL[sev]} | ${counts[sev]} |`)
  }
  lines.push("")
  lines.push(
    `Closure: **${closures.confirmed}** confirmed, **${closures.open_proof_gap}** open proof gap, ` +
      `**${closures.ruled_out}** ruled out. A proof gap is not a dismissal — it means the candidate was ` +
      `plausible and neither confirmed nor excluded within this engagement.`,
  )
  lines.push("")

  if (input.findings.length) {
    lines.push("### Findings index")
    lines.push("")
    lines.push("| ID | Finding | Severity | Closure | Asset |")
    lines.push("| --- | --- | --- | --- | --- |")
    for (const f of [...input.findings].sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity])) {
      lines.push(`| ${f.id} | ${esc(f.title)} | ${SEV_LABEL[f.severity]} | ${f.closure} | ${esc(f.target)} |`)
    }
    lines.push("")
  }

  if (input.findings.length === 0) {
    lines.push("No findings were recorded. This is not evidence of absence: see Limitations.")
    lines.push("")
  }

  lines.push("## Credentials")
  lines.push("")
  lines.push(...renderCredentialsMarkdown(credentials).replace(/\n$/, "").split("\n"))
  lines.push("")

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
    if (f.retests?.length) {
      lines.push("**Retest history**")
      lines.push("")
      lines.push("| When | Verification | Method | Observed |")
      lines.push("| --- | --- | --- | --- |")
      for (const r of f.retests) {
        const method = r.command ?? r.method
        lines.push(
          `| ${cell(r.at)} | ${cell(r.before)} → ${cell(r.after)}${r.reopened ? " (reopened)" : ""} | \`${cell(method, 120)}\` | ${cell(r.observed)} |`,
        )
      }
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

  lines.push("## Remediation roadmap")
  lines.push("")
  if (input.findings.length === 0) {
    lines.push("_No findings to remediate._")
  } else {
    lines.push("Ordered by severity, then by cheapest fix first. Remediation detail is under each finding above.")
    lines.push("")
    lines.push("| Priority | Finding | Severity | Fix effort | Asset |")
    lines.push("| --- | --- | --- | --- | --- |")
    remediationRoadmap(input.findings).forEach((f, i) => {
      lines.push(
        `| ${i + 1} | ${f.id} — ${esc(f.title)} | ${SEV_LABEL[f.severity]}${
          f.cvss_score !== undefined ? ` (${f.cvss_score.toFixed(1)})` : ""
        } | ${f.fix_effort ?? "—"} | ${esc(f.target)}${f.endpoint ? esc(f.endpoint) : ""} |`,
      )
    })
  }
  lines.push("")

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

  if (input.evidenceContent && input.evidence.length > 0) {
    lines.push("## Evidence artifacts")
    lines.push("")
    lines.push(
      "Full content of every stored artifact, as captured. Where an artifact is marked `redacted: yes` above, " +
        "the secret-like material was removed at capture time and cannot be recovered from this report.",
    )
    lines.push("")
    for (const e of input.evidence) {
      lines.push(`### ${e.id} — ${e.label}`)
      lines.push("")
      lines.push(`- **Source:** ${e.source}`)
      if (e.target) lines.push(`- **Target:** ${e.target}`)
      lines.push(`- **Captured:** ${e.created_at}`)
      lines.push(`- **Bytes:** ${e.bytes}`)
      lines.push(`- **Redacted at capture:** ${e.redacted ? "yes" : "no"}`)
      lines.push(`- **SHA-256:** \`${e.sha256}\``)
      lines.push("")
      const body = input.evidenceContent[e.id]
      if (body === undefined) {
        lines.push("_(artifact file is missing from the evidence store)_")
      } else {
        lines.push("```")
        lines.push(esc(body))
        lines.push("```")
      }
      lines.push("")
    }
  }

  lines.push("## Limitations and untested areas")
  lines.push("")
  lines.push(esc(input.limitations ?? "No limitations were recorded by the operator."))
  lines.push("")

  lines.push("## Appendix A — Risk rating methodology")
  lines.push("")
  lines.push(...RISK_RATING_MD)
  lines.push("")

  lines.push("## Appendix B — Revision history")
  lines.push("")
  lines.push(`- Document version ${input.version ?? "1.0"}, generated ${generatedAt}.`)
  if (input.findings.length) {
    lines.push("")
    lines.push("| Finding | Revision | Last updated |")
    lines.push("| --- | --- | --- |")
    for (const f of input.findings) {
      lines.push(`| ${f.id} — ${esc(f.title)} | ${f.revision} | ${f.updated_at} |`)
    }
  }
  lines.push("")

  lines.push("## Disclaimer")
  lines.push("")
  lines.push(DISCLAIMER)
  lines.push("")

  lines.push("---")
  lines.push("")
  lines.push("_Generated by the NullByte security capability layer. Findings are bounded by the authorized scope above; nothing outside it was tested._")
  lines.push("")
  lines.push(COPYRIGHT_TEXT)

  return lines.join("\n")
}

export function renderJson(input: ReportInput): string {
  const counts = severitySummary(input.findings)
  const closures = closureSummary(input.findings)
  return JSON.stringify(
    {
      engagement: input.engagement,
      version: input.version ?? "1.0",
      generated_at: input.generatedAt ?? new Date().toISOString(),
      session: input.sessionID,
      provenance: cleanProvenance(input),
      unredacted: input.unredacted ?? false,
      scope: input.scopeSummary,
      background: input.background ?? null,
      objectives: input.objectives ?? null,
      timeline: timelineOf(input),
      summary: counts,
      closure_summary: closures,
      executive_summary: {
        total: input.findings.length,
        counts,
        top_risks: input.findings
          .filter((f) => f.severity === "critical" || f.severity === "high")
          .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity])
          .slice(0, 5)
          .map((f) => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            asset: f.target ?? null,
            endpoint: f.endpoint ?? null,
            impact: firstSentence(f.impact),
          })),
      },
      credentials: collectCredentials(input),
      findings: input.findings,
      remediation_roadmap: remediationRoadmap(input.findings).map((f, i) => ({
        priority: i + 1,
        id: f.id,
        title: f.title,
        severity: f.severity,
        cvss_score: f.cvss_score ?? null,
        fix_effort: f.fix_effort ?? null,
        asset: f.target ?? null,
        endpoint: f.endpoint ?? null,
      })),
      revision_history: input.findings.map((f) => ({ id: f.id, title: f.title, revision: f.revision, updated_at: f.updated_at })),
      risk_rating: {
        source: "CVSS 3.1 base metrics",
        severity_bands: { critical: "9.0-10.0", high: "7.0-8.9", medium: "4.0-6.9", low: "0.1-3.9", info: "0.0" },
        closure_states: ["confirmed", "ruled_out", "open_proof_gap"],
        confidence: ["low", "medium", "high"],
        verification: ["unverified", "verified", "refuted", "inconclusive"],
        fix_effort: ["trivial", "low", "medium", "high"],
        redaction_posture: "full-disclosure",
      },
      disclaimer: DISCLAIMER,
      evidence: input.evidence,
      evidence_artifacts: input.evidenceContent
        ? input.evidence.map((e) => ({
            id: e.id,
            label: e.label,
            source: e.source,
            target: e.target ?? null,
            redacted_at_capture: e.redacted,
            sha256: e.sha256,
            content: input.evidenceContent?.[e.id] ?? null,
          }))
        : undefined,
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

/** One card per disclosed credential, value verbatim. */
function renderCredentialsHtml(records: CredentialRecord[]): string {
  if (records.length === 0) return "<p><em>No credentials were captured in the material covered by this report.</em></p>"
  return `<p><strong>${records.length} credential${records.length === 1 ? "" : "s"} disclosed below in full, verbatim.</strong> Treat this section as the most sensitive part of the deliverable: rotate every value once the engagement closes.</p>
${records
  .map((c) => {
    const hosts = [...new Set(c.sources.map((s) => s.host).filter(Boolean))]
    const obs = c.sources
      .map((s) => `${escHtml(s.kind === "finding" ? "finding" : "evidence")} <code>${escHtml(s.id)}</code> — ${escHtml(s.where)}`)
      .join("<br>")
    return `<article class="finding cred">
<h2><span class="num">${escHtml(c.id)}</span> ${escHtml(c.label)}</h2>
<div class="meta">
  <div class="cell"><span class="k">Type</span><span class="v">${escHtml(c.kind)}</span></div>
  ${hosts.length ? `<div class="cell"><span class="k">Host</span><span class="v">${escHtml(hosts.join(", "))}</span></div>` : ""}
  <div class="cell"><span class="k">Observed in</span><span class="v">${obs}</span></div>
</div>
<pre class="value">${escHtml(c.value)}</pre>
${c.context ? `<pre>${escHtml(c.context)}</pre>` : ""}
</article>`
  })
  .join("\n")}`
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
  const credentials = collectCredentials(input)
  const provenance = cleanProvenance(input)
  const ordered = [...input.findings].sort(
    (a, b) => ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 })[b.severity] - ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 })[a.severity],
  )

  const findingHtml = ordered
    .map((f, i) => {
      const meta: string[] = [
        `<div class="cell"><span class="k">ID</span><span class="v">${escHtml(f.id)}</span></div>`,
        `<div class="cell"><span class="k">Severity</span><span class="v"><span class="badge ${SEV_CLASS[f.severity]}">${escHtml(SEV_LABEL[f.severity])}</span>${
          f.cvss_score !== undefined ? ` CVSS 3.1 ${f.cvss_score.toFixed(1)}` : ""
        }</span></div>`,
        f.cvss_vector ? `<div class="cell"><span class="k">CVSS vector</span><span class="v"><code>${escHtml(f.cvss_vector)}</code></span></div>` : "",
        `<div class="cell"><span class="k">Status</span><span class="v">${escHtml(f.status)}</span></div>`,
        `<div class="cell"><span class="k">Closure</span><span class="v">${escHtml(f.closure)}${
          f.closure_downgraded ? " <em>(downgraded — the claim was not supported)</em>" : ""
        }</span></div>`,
        `<div class="cell"><span class="k">Confidence</span><span class="v">${escHtml(f.confidence)}</span></div>`,
        `<div class="cell"><span class="k">Verification</span><span class="v">${escHtml(f.verification)}</span></div>`,
        f.fix_effort ? `<div class="cell"><span class="k">Fix effort</span><span class="v">${escHtml(f.fix_effort)}</span></div>` : "",
        `<div class="cell"><span class="k">Affected asset</span><span class="v">${escHtml(f.target)}${f.endpoint ? ` → ${escHtml(f.endpoint)}` : ""}${
          f.method ? ` (${escHtml(f.method)})` : ""
        }</span></div>`,
        f.cve ? `<div class="cell"><span class="k">CVE</span><span class="v">${escHtml(f.cve)}</span></div>` : "",
        f.cwe ? `<div class="cell"><span class="k">CWE</span><span class="v">${escHtml(f.cwe)}</span></div>` : "",
        `<div class="cell"><span class="k">Detected by</span><span class="v">${escHtml(f.source)}</span></div>`,
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
${f.retests?.length ? `<section><h3>Retest history</h3><table class="retests"><thead><tr><th>When</th><th>Verification</th><th>Method</th><th>Observed</th></tr></thead><tbody>${f.retests
  .map(
    (r) =>
      `<tr><td>${escHtml(r.at)}</td><td>${escHtml(r.before)} → ${escHtml(r.after)}${r.reopened ? " <em>(reopened)</em>" : ""}</td>` +
      `<td><code>${escHtml(r.command ?? r.method)}</code></td><td>${escHtml(r.observed)}</td></tr>`,
  )
  .join("")}</tbody></table></section>` : ""}
${block("Remediation", f.remediation)}
${block("Counterevidence considered", f.counterevidence)}
${block("Severity changes if", f.severity_change_conditions)}
${block("Assumptions", f.assumptions)}
${block("Limitations", f.limitations)}
${refs}
</article>`
    })
    .join("\n")

  const credentialsHtml = renderCredentialsHtml(credentials)

  const timeline = timelineOf(input)
  const topRisks = input.findings
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity])

  const execHtml = `<p>This assessment covered <strong>${escHtml(input.engagement)}</strong> within the authorized scope below. ${
    input.findings.length === 0
      ? "No findings were recorded."
      : `${input.findings.length} finding${input.findings.length === 1 ? "" : "s"} were recorded: ${counts.critical} critical, ${
          counts.high
        } high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info.`
  }</p>
${
  topRisks.length
    ? `<p>The highest-risk issues are:</p><ul>${topRisks
        .slice(0, 5)
        .map(
          (f) =>
            `<li><strong>${escHtml(SEV_LABEL[f.severity])} — ${escHtml(f.title)}</strong>${
              f.target ? ` (${escHtml(f.target)}${f.endpoint ? escHtml(f.endpoint) : ""})` : ""
            }${firstSentence(f.impact) ? `: ${escHtml(firstSentence(f.impact))}` : ""}</li>`,
        )
        .join("")}</ul>`
    : input.findings.length
      ? "<p>No critical or high severity issues were confirmed within scope.</p>"
      : ""
}
<p>Closure: <strong>${closures.confirmed}</strong> confirmed, <strong>${closures.open_proof_gap}</strong> open proof gap, <strong>${
    closures.ruled_out
  }</strong> ruled out. A proof gap is not a dismissal — the candidate was plausible and neither confirmed nor excluded within this engagement.</p>
<p>This summary is bounded by the scope and the limitations recorded below. Anything listed as untested was not exercised, and absence of findings there is not evidence of absence.</p>`

  const backgroundHtml = `<p>${escHtml(
    input.background ??
      `The engagement ${input.engagement} was conducted to identify and verify security weaknesses in the systems named under Authorized scope, and to record each one with reproducible evidence.`,
  )}</p>
<h3>Objectives</h3>
<p>${escHtml(
    input.objectives ??
      "Determine whether the authorized assets expose exploitable weaknesses; confirm each candidate with evidence before reporting it; and state plainly what was not tested.",
  )}</p>`

  const timelineHtml = `<ul>${
    input.testWindow ? `<li><strong>Testing window (operator-supplied):</strong> ${escHtml(input.testWindow)}</li>` : ""
  }${
    timeline.events === 0
      ? "<li>No timestamped activity was recorded, so the engagement window cannot be derived.</li>"
      : `<li><strong>First recorded activity:</strong> ${escHtml(timeline.first!)}</li>` +
        `<li><strong>Last recorded activity:</strong> ${escHtml(timeline.last!)}</li>` +
        `<li><strong>Elapsed between first and last record:</strong> ${timeline.hours} hours across ${timeline.events} timestamped records</li>`
  }</ul>
<p><em>This window reflects the records the engagement kept, not necessarily every hour spent testing: a quiet period that produced no finding and no evidence leaves no timestamp.</em></p>`

  const roadmapHtml =
    input.findings.length === 0
      ? "<p><em>No findings to remediate.</em></p>"
      : `<p>Ordered by severity, then by cheapest fix first. Remediation detail is under each finding above.</p>
<table><thead><tr><th>Priority</th><th>Finding</th><th>Severity</th><th>Fix effort</th><th>Asset</th></tr></thead><tbody>${remediationRoadmap(
          input.findings,
        )
          .map(
            (f, i) =>
              `<tr><td>${i + 1}</td><td><code>${escHtml(f.id)}</code> ${escHtml(f.title)}</td><td>${escHtml(
                SEV_LABEL[f.severity],
              )}${f.cvss_score !== undefined ? ` (${f.cvss_score.toFixed(1)})` : ""}</td><td>${escHtml(
                f.fix_effort ?? "—",
              )}</td><td>${escHtml(f.target)}${f.endpoint ? escHtml(f.endpoint) : ""}</td></tr>`,
          )
          .join("")}</tbody></table>`

  const findingsIndexHtml = input.findings.length
    ? `<h3>Findings index</h3>
<table><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Closure</th><th>Asset</th></tr></thead><tbody>${[...input.findings]
        .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity])
        .map(
          (f) =>
            `<tr><td><code>${escHtml(f.id)}</code></td><td>${escHtml(f.title)}</td><td>${escHtml(
              SEV_LABEL[f.severity],
            )}</td><td>${escHtml(f.closure)}</td><td>${escHtml(f.target)}</td></tr>`,
        )
        .join("")}</tbody></table>`
    : ""

  const appendixHtml = `<h2>Appendix A — Risk rating methodology</h2>
<p>Severity is derived from <strong>CVSS 3.1 base metrics</strong>, never asserted by hand when metrics are available.</p>
<table class="summary"><thead><tr><th>Band</th><th>CVSS 3.1 base score</th></tr></thead><tbody>
<tr><td><span class="badge sev-critical">Critical</span></td><td>9.0 – 10.0</td></tr>
<tr><td><span class="badge sev-high">High</span></td><td>7.0 – 8.9</td></tr>
<tr><td><span class="badge sev-medium">Medium</span></td><td>4.0 – 6.9</td></tr>
<tr><td><span class="badge sev-low">Low</span></td><td>0.1 – 3.9</td></tr>
<tr><td><span class="badge sev-info">Info</span></td><td>0.0</td></tr>
</tbody></table>
<h3>Closure states</h3>
<ul>
<li><code>confirmed</code> — the behaviour was reproduced and is supported by evidence.</li>
<li><code>ruled_out</code> — the candidate was tested and a specific control makes it safe; the control and where it was observed are recorded.</li>
<li><code>open_proof_gap</code> — the candidate was plausible and neither confirmed nor excluded within this engagement. This is not a dismissal.</li>
</ul>
<p><strong>Confidence</strong> (<code>low</code> / <code>medium</code> / <code>high</code>) is how sure the operator is of the finding given the evidence. <strong>Verification</strong> (<code>unverified</code> / <code>verified</code> / <code>refuted</code> / <code>inconclusive</code>) records whether the claim was independently checked. <strong>Fix effort</strong> (<code>trivial</code> / <code>low</code> / <code>medium</code> / <code>high</code>) drives the roadmap ordering.</p>
<p><strong>Redaction posture</strong> — this deployment is configured for <strong>full disclosure</strong>: captured credentials are recorded verbatim and reproduced in full above. This deliberately departs from PTES Post-Exploitation and OWASP APTS (APTS-MR-019 / APTS-TP-013), which call for plaintext credentials to be kept out of reports. See <code>docs/PENTEST.md</code>.</p>

<h2>Appendix B — Revision history</h2>
<p>Document version ${escHtml(input.version ?? "1.0")}, generated ${escHtml(generatedAt)}.</p>
${
  input.findings.length
    ? `<table><thead><tr><th>Finding</th><th>Revision</th><th>Last updated</th></tr></thead><tbody>${input.findings
        .map(
          (f) =>
            `<tr><td><code>${escHtml(f.id)}</code> ${escHtml(f.title)}</td><td>${f.revision}</td><td>${escHtml(f.updated_at)}</td></tr>`,
        )
        .join("")}</tbody></table>`
    : ""
}

<h2>Disclaimer</h2>
<p>${escHtml(DISCLAIMER)}</p>`

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

  const evidenceArtifactsHtml =
    input.evidenceContent && input.evidence.length
      ? `<h2>Evidence artifacts</h2>
<p>Full content of every stored artifact, as captured. Where an artifact is marked <code>redacted: yes</code> above, the secret-like material was removed at capture time and cannot be recovered from this report.</p>
${input.evidence
  .map((e) => {
    const body = input.evidenceContent?.[e.id]
    return `<article class="finding">
<h2><code>${escHtml(e.id)}</code> ${escHtml(e.label)}</h2>
<div class="meta">
  <div class="cell"><span class="k">Source</span><span class="v">${escHtml(e.source)}</span></div>
  ${e.target ? `<div class="cell"><span class="k">Target</span><span class="v">${escHtml(e.target)}</span></div>` : ""}
  <div class="cell"><span class="k">Captured</span><span class="v">${escHtml(e.created_at)}</span></div>
  <div class="cell"><span class="k">Bytes</span><span class="v">${e.bytes}</span></div>
  <div class="cell"><span class="k">Redacted at capture</span><span class="v">${e.redacted ? "yes" : "no"}</span></div>
  <div class="cell"><span class="k">SHA-256</span><span class="v"><code>${escHtml(e.sha256)}</code></span></div>
</div>
${
  body === undefined
    ? "<p><em>(artifact file is missing from the evidence store)</em></p>"
    : `<pre>${escHtml(body)}</pre>`
}
</article>`
  })
  .join("\n")}`
      : ""

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="author" content="EliTechWiz">
<meta name="generator" content="NullByte">
<title>Security Assessment — ${escHtml(input.engagement)}</title>
<style>
  :root { --ink:#111; --muted:#666; --line:#ddd; --bg:#fff; --box:#f8f8f8; }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font: 14px/1.55 -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
    color: var(--ink); background: var(--bg);
    width: 100%; max-width: 900px; margin: 0 auto;
    padding: 40px 48px;              /* uniform left and right page margin */
    overflow-wrap: break-word;
  }
  /* nothing may exceed the container */
  h1, h2, h3, p, ul, ol, table, pre, article, section { max-width: 100%; }
  h1 { font-size: 26px; margin: 0 0 6px; }
  h2 { font-size: 18px; margin: 28px 0 10px; border-bottom: 2px solid var(--line); padding-bottom: 6px; }
  h3 { font-size: 12.5px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin: 0 0 4px; }
  .sub { color: var(--muted); margin-bottom: 24px; }
  .sub span { margin-right: 14px; white-space: nowrap; }
  table { border-collapse: collapse; width: 100%; margin: 8px 0 20px; table-layout: fixed; }
  th, td { border: 1px solid var(--line); padding: 6px 8px; text-align: left; font-size: 13px; overflow-wrap: anywhere; word-break: break-word; }
  th { background: #f6f6f6; }

  /* ---- finding card: full width, never shifts, never splits ---- */
  .finding {
    width: 100%; max-width: 100%; box-sizing: border-box;
    border: 1px solid var(--line); border-left-width: 5px; border-radius: 5px;
    padding: 16px 18px; margin: 0 0 22px;
    page-break-inside: avoid; break-inside: avoid;
  }
  .finding > * { min-width: 0; max-width: 100%; }
  .finding .num { color: var(--muted); font-weight: 400; }

  /* ---- metadata grid: stacked label over value, no horizontal overflow ---- */
  .meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 8px 16px;
    align-items: start;
    width: 100%; max-width: 100%;
    margin: 10px 0 6px;
  }
  .meta .cell { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
  .meta .k { color: var(--muted); font-size: 12px; }
  .meta .v { min-width: 0; overflow-wrap: anywhere; word-break: break-word; }

  /* ---- content boxes ---- */
  section { min-width: 0; page-break-inside: avoid; break-inside: avoid; }
  pre {
    width: 100%; max-width: 100%; box-sizing: border-box;
    background: var(--box); border: 1px solid var(--line); border-radius: 4px;
    padding: 10px; margin: 0 0 6px;
    white-space: pre-wrap; word-break: break-word; overflow-wrap: anywhere;
    font-size: 12.5px; line-height: 1.5;
    page-break-inside: avoid; break-inside: avoid;
  }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; overflow-wrap: anywhere; word-break: break-word; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; color: #fff; }
  /* the badge carries the severity class itself, so these must be compound
     selectors — a descendant selector only ever matched inside the finding
     card and left the summary table's labels white-on-white */
  .sev-critical { border-left-color: #b00020; } .badge.sev-critical { background: #b00020; }
  .sev-high     { border-left-color: #d9480f; } .badge.sev-high     { background: #d9480f; }
  .sev-medium   { border-left-color: #b8860b; } .badge.sev-medium   { background: #b8860b; }
  .sev-low      { border-left-color: #2b6cb0; } .badge.sev-low      { background: #2b6cb0; }
  .sev-info     { border-left-color: #666; }    .badge.sev-info     { background: #666; }
  .cred { border-left-color: #7a0015; }
  .cred pre.value { background: #fff5f5; border-color: #e6b3bd; font-weight: 600; }
  table.summary { max-width: 420px; }
  table.summary th:last-child, table.summary td:last-child { width: 90px; }
  footer { margin-top: 36px; padding-top: 14px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12.5px; }
  footer .copyright { margin-top: 8px; font-weight: 600; color: #333; }
  .warn { border: 2px solid #b00020; background: #fff5f5; color: #7a0015; border-radius: 5px; padding: 12px 14px; margin: 0 0 20px; font-weight: 600; overflow-wrap: anywhere; }
  @page {
    size: A4; margin: 14mm;
    /* Stamps the copyright and page numbers onto every page of the PDF.
       Rendered by WeasyPrint and by current Chrome (verified 151). */
    @bottom-left { content: "${COPYRIGHT_TEXT}"; font-size: 9px; color: #666; }
    @bottom-right { content: "Page " counter(page) " of " counter(pages); font-size: 9px; color: #666; }
  }
  @media print {
    body { padding: 0; max-width: none; }
    .finding, pre, section { page-break-inside: avoid; break-inside: avoid; }
    .finding { border-left-width: 4px; }
  }
</style>
</head>
<body>
<h1>Security Assessment — ${escHtml(input.engagement)}</h1>
<div class="sub">
  <span>Generated: ${escHtml(generatedAt)}</span>
  <span>Session: ${escHtml(input.sessionID)}</span>
  <span>Version: ${escHtml(input.version ?? "1.0")}</span>
  <span>Findings: ${input.findings.length}</span>
</div>
${provenance ? `<p class="sub">Produced by: ${escHtml(provenance)}</p>` : ""}
${input.selectionNote ? `<p class="sub">Coverage: ${escHtml(input.selectionNote)}</p>` : ""}
${input.unredacted ? `<div class="warn">${escHtml(UNREDACTED_WARNING)}</div>` : ""}

<h2>Executive summary</h2>
${execHtml}

<h2>Background and objectives</h2>
${backgroundHtml}

<h2>Authorized scope</h2>
<pre>${escHtml(input.scopeSummary)}</pre>

<h2>Timeline</h2>
${timelineHtml}

<h2>Summary</h2>
<table class="summary"><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>
${(["critical", "high", "medium", "low", "info"] as Severity[])
  .map((s) => `<tr><td><span class="badge ${SEV_CLASS[s]}">${escHtml(SEV_LABEL[s])}</span></td><td>${counts[s]}</td></tr>`)
  .join("")}
</tbody></table>
<p>Closure: <strong>${closures.confirmed}</strong> confirmed, <strong>${closures.open_proof_gap}</strong> open proof gap, <strong>${
    closures.ruled_out
  }</strong> ruled out. A proof gap is not a dismissal — it means the candidate was plausible and neither confirmed nor excluded within this engagement.</p>
${findingsIndexHtml}

<h2>Credentials</h2>
${credentialsHtml}

<h2>Findings</h2>
${input.findings.length === 0 ? "<p>No findings were recorded. This is not evidence of absence: see Limitations.</p>" : findingHtml}

<h2>Remediation roadmap</h2>
${roadmapHtml}

<h2>Evidence index</h2>
${evidenceHtml}
${evidenceArtifactsHtml}

<h2>Limitations and untested areas</h2>
<p>${escHtml(input.limitations ?? "No limitations were recorded by the operator.")}</p>

${appendixHtml}

<footer>
<div>Generated by the NullByte security capability layer. Findings are bounded by the authorized scope above; nothing outside it was tested.</div>
<div class="copyright">${escHtml(COPYRIGHT_TEXT)}</div>
</footer>
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
  /**
   * Redact secret-like material from every text format. Defaults to false: the
   * operator's posture is full disclosure, so the artifacts carry credentials
   * verbatim. Pass true only to scrub a deliverable that must not contain them.
   */
  redact?: boolean
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
 * Scrub a rendered report.
 *
 * `redactSecrets` catches self-describing shapes (`db_password: x`), but the
 * Credentials section prints a bare value with no key in front of it, which no
 * shape rule matches. So every collected credential is also replaced literally,
 * guaranteeing the section cannot leak when `redact: true` was asked for.
 */
export function scrubReport(input: ReportInput, text: string): string {
  let out = redactSecrets(text)
  for (const c of collectCredentials(input)) out = out.split(c.value).join("[REDACTED:credential]")
  return out
}

/**
 * Write the report. By default every emitted text artifact is verbatim — the
 * operator's posture is full disclosure, so a credential in a finding reaches
 * the deliverable in full. Pass `redact: true` to scrub every text format first
 * (including the HTML that feeds the PDF).
 */
export function writeReport(root: string, input: ReportInput, opts: WriteReportOptions = {}): WriteReportResult {
  const dir = ensureDir(opts.outDir ?? join(root, "reports"))
  const stamp = (input.generatedAt ?? new Date().toISOString()).replace(/[:.]/g, "-")
  const base = (opts.name ?? `report-${stamp}`).replace(/[^A-Za-z0-9._-]/g, "_")
  const formats = opts.formats?.length ? opts.formats : ALL_FORMATS
  const redact = opts.redact === true
  const clean = (s: string) => (redact ? scrubReport(input, s) : s)

  const markdown = clean(renderMarkdown(input))
  const html = clean(renderHtml(input))
  const json = clean(renderJson(input))
  const files: WrittenFile[] = []
  const out: WriteReportResult = { dir, files, markdown, html }

  const emit = (format: ReportFormat, ext: string, body: string) => {
    if (!formats.includes(format)) return
    const path = join(dir, `${base}.${ext}`)
    writeFileSync(path, body, { mode: 0o600 })
    files.push({ format, path })
  }

  emit("md", "md", markdown)
  emit("json", "json", json)
  emit("html", "html", html)

  if (formats.includes("pdf")) {
    const pdfPath = join(dir, `${base}.pdf`)
    const res = htmlToPdf(html, pdfPath)
    out.pdf = res.ok ? { ok: true } : { ok: false, reason: res.reason, hint: res.hint }
    if (res.ok) {
      // the converter writes with its own umask; an unredacted report is the
      // most sensitive file in the tree, so force owner-only
      try {
        chmodSync(pdfPath, 0o600)
      } catch {
        /* best effort — the file is already written */
      }
      files.push({ format: "pdf", path: pdfPath })
    }
  }

  out.markdownPath = files.find((f) => f.format === "md")?.path
  out.jsonPath = files.find((f) => f.format === "json")?.path
  return out
}

