/**
 * Credential collection and presentation.
 *
 * The operator's standing posture is full disclosure: a leaked credential is
 * the finding, so the report states it verbatim. This module gathers every
 * credential-shaped value out of the findings and the stored evidence, folds
 * duplicates, and renders one dedicated section — Metasploit's Credentials
 * Report is the model. Nothing is masked.
 *
 * This deliberately deviates from PTES Post-Exploitation ("Passwords ... will
 * not be included in the final report") and OWASP APTS APTS-MR-019 / APTS-TP-013
 * (MUST NOT appear in plaintext). The deviation is the operator's decision and
 * is recorded in docs/PENTEST.md.
 */

import { extractCredentials } from "./redact.ts"
import type { Finding } from "./types.ts"
import type { EvidenceRecord } from "./evidence.ts"

/** Where a credential was observed. */
export interface CredentialSource {
  kind: "finding" | "evidence"
  /** finding id or evidence id */
  id: string
  /** the finding field, or the artifact label */
  where: string
  host?: string
}

export interface CredentialRecord {
  /** report-facing id, e.g. `C-01` */
  id: string
  /** the key the value was assigned to, or the shape's name (e.g. `aws-akid`) */
  label: string
  kind: string
  /** the credential, verbatim */
  value: string
  /** the line the credential first appeared on */
  context?: string
  sources: CredentialSource[]
}

export interface CollectCredentialsInput {
  findings: Finding[]
  evidence: EvidenceRecord[]
  /** id -> raw artifact text, when the caller asked for full evidence */
  evidenceContent?: Record<string, string>
}

/** Finding fields that can carry an inline credential. */
const FINDING_FIELDS: (keyof Finding)[] = [
  "evidence",
  "reproduction",
  "description",
  "impact",
  "demonstrated_by",
  "counterevidence",
  "assumptions",
  "limitations",
]

/**
 * Gather every credential in the report's inputs, deduplicated by value.
 *
 * A value seen in several places becomes one record with several sources, so
 * the same secret is not listed three times but its provenance is not lost.
 */
export function collectCredentials(input: CollectCredentialsInput): CredentialRecord[] {
  const groups = new Map<
    string,
    { labeled?: { label: string; kind: string }; bare?: string; context?: string; sources: CredentialSource[] }
  >()

  const scan = (text: string | undefined, source: CredentialSource) => {
    if (!text) return
    for (const hit of extractCredentials(text)) {
      let g = groups.get(hit.value)
      if (!g) {
        g = { sources: [] }
        groups.set(hit.value, g)
      }
      if (g.context === undefined && hit.context) g.context = hit.context
      if (hit.label) {
        if (!g.labeled) g.labeled = { label: hit.label, kind: hit.kind }
      } else if (!g.bare) {
        g.bare = hit.kind
      }
      const seen = g.sources.some((s) => s.kind === source.kind && s.id === source.id && s.where === source.where)
      if (!seen) g.sources.push(source)
    }
  }

  for (const f of input.findings) {
    for (const field of FINDING_FIELDS) {
      const value = f[field]
      if (typeof value !== "string") continue
      scan(value, { kind: "finding", id: f.id, where: String(field), host: f.target })
    }
  }

  for (const e of input.evidence) {
    const content = input.evidenceContent?.[e.id]
    if (content === undefined) continue
    scan(content, { kind: "evidence", id: e.id, where: e.label, host: e.target })
  }

  const records: CredentialRecord[] = []
  for (const [value, g] of groups) {
    const best = g.labeled ?? { label: g.bare ?? "credential", kind: g.bare ?? "credential" }
    records.push({ id: "", label: best.label, kind: best.kind, value, context: g.context, sources: g.sources })
  }

  // stable, readable order: by label, then by value
  records.sort((a, b) => a.label.localeCompare(b.label) || a.value.localeCompare(b.value))
  records.forEach((r, i) => {
    r.id = `C-${String(i + 1).padStart(2, "0")}`
  })
  return records
}

/* --------------------------------------------------------------- markdown --- */

/** Render a value so it survives as a single markdown token, even multi-line. */
function mdValue(value: string): string {
  if (!value.includes("\n") && !value.includes("`")) return `\`${value}\``
  return `\n\`\`\`\n${value}\n\`\`\`\n`
}

export function renderCredentialsMarkdown(records: CredentialRecord[]): string {
  const lines: string[] = []

  if (records.length === 0) {
    lines.push("_No credentials were captured in the material covered by this report._")
    lines.push("")
    return lines.join("\n")
  }

  lines.push(
    `**${records.length} credential${records.length === 1 ? "" : "s"} disclosed below in full, verbatim.** ` +
      "Treat this section as the most sensitive part of the deliverable: rotate every value once the engagement closes.",
  )
  lines.push("")

  for (const c of records) {
    lines.push(`### ${c.id} — ${c.label}`)
    lines.push("")
    lines.push(`- **Value:** ${mdValue(c.value)}`)
    lines.push(`- **Type:** ${c.kind}`)
    const hosts = [...new Set(c.sources.map((s) => s.host).filter(Boolean))]
    if (hosts.length) lines.push(`- **Host:** ${hosts.join(", ")}`)
    if (c.context) lines.push(`- **Context:** ${mdValue(c.context)}`)
    lines.push(`- **Observed in:**`)
    for (const s of c.sources) {
      lines.push(`  - ${s.kind === "finding" ? "finding" : "evidence"} \`${s.id}\` — ${s.where}`)
    }
    lines.push("")
  }

  return lines.join("\n")
}
