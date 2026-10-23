/**
 * Interop exports — SARIF and CSV.
 *
 * The markdown/HTML/PDF/JSON set is for humans and for the engagement archive.
 * These two are for machines: SARIF so the findings land in a code-scanning or
 * security dashboard without a bespoke parser, and CSV in DefectDojo's Generic
 * Findings Import shape so they can be pushed into a defect tracker.
 *
 * Both are derived from the same findings as every other format, so a corrected
 * finding cannot diverge between them.
 *
 * Deliberate mapping decisions, because the seams are where these get wrong:
 *
 *  - SARIF `level` is a four-value enum with no notion of our severity ladder.
 *    Critical and high both become `error`; information disclosure that is
 *    merely noted becomes `none`, not `warning`, so it does not fail a build.
 *  - A finding with no file/line still gets a location: SARIF requires one, and
 *    the honest answer for a network finding is a logical location naming the
 *    asset, not a fabricated file path.
 *  - CSV carries `Active`/`Verified`/`FalsePositive` as separate booleans
 *    because DefectDojo treats them as independent axes; deriving one from
 *    another silently loses the distinction between "fixed" and "not proven".
 */

import { SEVERITY_ORDER, type Severity } from "./types.ts"
import type { ReportInput } from "./report.ts"
import { coverageSummary } from "./coverage.ts"

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
const TOOL_NAME = "NullByte Security"

/** critical/high fail a gate; medium warns; low/info are notes. */
const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note" | "none"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
}

/** DefectDojo accepts these labels case-insensitively. */
const DD_SEVERITY: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
}

/** `path/to/file.ts:120` or `path/to/file.ts:120-140` → a SARIF region. */
function parseLocation(ref: string | undefined): { uri: string; startLine?: number; endLine?: number } | undefined {
  if (!ref) return undefined
  const m = /^(.+?):(\d+)(?:-(\d+))?$/.exec(ref.trim())
  if (!m) return undefined
  return { uri: m[1]!, startLine: Number(m[2]), endLine: m[3] ? Number(m[3]) : undefined }
}

/** The first readable local evidence reference, if any. */
function localRef(input: ReportInput, refs: string[] | undefined): { uri: string; startLine?: number; endLine?: number } | undefined {
  for (const ref of refs ?? []) {
    // E-… ids are evidence-store artifacts, not source locations
    if (/^E-[0-9a-f]/i.test(ref)) continue
    const loc = parseLocation(ref)
    if (loc) return loc
  }
  return undefined
}

export function renderSarif(input: ReportInput): string {
  const generated = input.generatedAt ?? new Date().toISOString()
  const coverage =
    input.coverage === undefined
      ? undefined
      : input.coverageSummary ?? coverageSummary(input.coverage, input.findings)

  // one rule per distinct identity, so a dashboard groups rather than repeats
  const rules = new Map<string, { id: string; name: string; description: string; level: string; tags: string[] }>()
  const results = input.findings.map((f) => {
    const ruleId = f.cwe ?? f.id
    const loc = localRef(input, f.evidence_refs)

    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: f.title,
        description: f.description,
        level: SARIF_LEVEL[f.severity],
        tags: [f.severity, f.closure, f.confidence, ...(f.cwe ? [f.cwe] : []), ...(f.cve ? [f.cve] : [])],
      })
    }

    const physical = loc
      ? {
          physicalLocation: {
            artifactLocation: { uri: loc.uri },
            ...(loc.startLine ? { region: { startLine: loc.startLine, ...(loc.endLine ? { endLine: loc.endLine } : {}) } } : {}),
          },
        }
      : {
          // a network finding has no file; name the asset rather than invent one
          logicalLocations: [{ fullyQualifiedName: f.endpoint ? `${f.target}${f.endpoint}` : f.target, kind: "resource" }],
        }

    return {
      ruleId,
      level: SARIF_LEVEL[f.severity],
      // the id and closure travel with the message: SARIF has nowhere else for them
      message: {
        text: `${f.title} [${f.id}, ${f.closure}, verification=${f.verification}, status=${f.status}]`,
        markdown: [
          `**${f.title}**`,
          "",
          f.description,
          "",
          `- Finding: \`${f.id}\` (revision ${f.revision})`,
          `- Asset: \`${f.target}${f.endpoint ? ` → ${f.endpoint}` : ""}\``,
          `- Severity: ${f.severity}${f.cvss_score !== undefined ? ` (CVSS 3.1 ${f.cvss_score.toFixed(1)}${f.cvss_vector ? ` ${f.cvss_vector}` : ""})` : ""}`,
          `- Closure: ${f.closure} — confidence ${f.confidence}, verification ${f.verification}`,
          `- Impact: ${f.impact}`,
          "",
          `**Remediation.** ${f.remediation}`,
          ...(f.evidence_refs?.length ? ["", `**Evidence.** ${f.evidence_refs.join(", ")}`] : []),
        ].join("\n"),
      },
      locations: [physical],
      properties: {
        id: f.id,
        severity: f.severity,
        status: f.status,
        closure: f.closure,
        confidence: f.confidence,
        verification: f.verification,
        revision: f.revision,
        ...(f.cvss_score !== undefined ? { cvss31Score: f.cvss_score } : {}),
        ...(f.cvss_vector ? { cvss31Vector: f.cvss_vector } : {}),
        ...(f.cve ? { cve: f.cve } : {}),
        ...(f.cwe ? { cwe: f.cwe } : {}),
        ...(f.fix_effort ? { fixEffort: f.fix_effort } : {}),
        ...(f.retests?.length ? { retests: f.retests.length } : {}),
      },
    }
  })

  const sarif = {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            ...(input.version ? { version: input.version } : {}),
            informationUri: "https://github.com/Eliahhango/nullbyte-security",
            rules: [...rules.values()].map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.name },
              fullDescription: { text: r.description },
              defaultConfiguration: { level: r.level },
              properties: { tags: r.tags },
            })),
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: generated,
            // state plainly what this run covered, so a dashboard does not read
            // the absence of results as an absence of issues
            toolExecutionNotifications: [
              {
                level: "note",
                message: {
                  text: `engagement '${input.engagement}'; ${input.selectionNote ?? "all findings in scope"}`,
                },
              },
              ...(coverage
                ? [
                    {
                      level: coverage.needs_follow_up > 0 || coverage.findings_without_coverage.length > 0 ? "warning" : "note",
                      message: {
                        text: coverage.empty
                          ? "coverage ledger empty — the absence of results is not evidence that the target was tested"
                          : `coverage: ${coverage.total} observation(s); ${coverage.needs_follow_up} need follow-up; ` +
                            `${coverage.findings_without_coverage.length} finding(s) have no linked coverage entry`,
                      },
                    },
                  ]
                : []),
            ],
            properties: coverage
              ? {
                  coverage: {
                    total: coverage.total,
                    byOutcome: coverage.by_outcome,
                    needsFollowUp: coverage.needs_follow_up,
                    findingsWithoutCoverage: coverage.findings_without_coverage.length,
                  },
                }
              : undefined,
          },
        ],
        results,
      },
    ],
  }

  return `${JSON.stringify(sarif, null, 2)}\n`
}

/* ------------------------------------------------------------------- csv --- */

/** RFC 4180: quote when the value contains a delimiter, a quote or a newline. */
export function csvCell(value: string | number | boolean | undefined): string {
  if (value === undefined) return ""
  const s = String(value)
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

const CSV_COLUMNS = [
  "Title",
  "Date",
  "Severity",
  "Description",
  "Mitigation",
  "Impact",
  "References",
  "Active",
  "Verified",
  "FalsePositive",
  "Endpoint",
  "Component",
  "CWE",
  "CVE",
  "CVSSv3",
  "CVSSv3Vector",
  "FindingID",
  "Closure",
  "Confidence",
  "Verification",
  "Remediated",
] as const

const csvUrl = (target: string, endpoint: string | undefined, method: string | undefined): string => {
  const scheme = /^https?:\/\//.test(target) ? "" : "https://"
  const path = endpoint ? (endpoint.startsWith("/") ? endpoint : `/${endpoint}`) : ""
  return `${scheme}${target}${path}`
}

export function renderCsv(input: ReportInput): string {
  const rows: string[] = [CSV_COLUMNS.join(",")]

  for (const f of input.findings) {
    const refs = [
      ...(f.cwe ? [f.cwe] : []),
      ...(f.cve ? [f.cve] : []),
      ...(f.evidence_refs ?? []),
      `nullbyte:${f.id}`,
    ].join(" ")

    const described = [
      f.description,
      "",
      f.reproduction ? `Reproduction:\n${f.reproduction}` : "",
      f.counterevidence ? `Counterevidence considered:\n${f.counterevidence}` : "",
      f.evidence ? `Evidence:\n${f.evidence}` : "",
      f.retests?.length
        ? `Retests (${f.retests.length}):\n${f.retests
            .map((r) => `${r.at} ${r.before}→${r.after} via ${r.command ?? r.method} — ${r.observed}`)
            .join("\n")}`
        : "",
      f.limitations ? `Limitations: ${f.limitations}` : "",
    ]
      .filter(Boolean)
      .join("\n")

    const row: Record<(typeof CSV_COLUMNS)[number], string | number | boolean | undefined> = {
      Title: f.title,
      // DefectDojo expects YYYY-MM-DD
      Date: (f.created_at ?? "").slice(0, 10),
      Severity: DD_SEVERITY[f.severity],
      Description: described,
      Mitigation: f.remediation,
      Impact: f.impact,
      References: refs,
      // three independent axes, not derived from one another
      Active: !(f.status === "false-positive" || f.status === "remediated" || f.status === "accepted-risk"),
      Verified: f.verification === "verified",
      FalsePositive: f.status === "false-positive",
      Endpoint: csvUrl(f.target, f.endpoint, f.method),
      Component: f.endpoint ? `${f.method ? `${f.method} ` : ""}${f.endpoint}` : f.target,
      CWE: f.cwe,
      CVE: f.cve,
      CVSSv3: f.cvss_score !== undefined ? f.cvss_score.toFixed(1) : undefined,
      CVSSv3Vector: f.cvss_vector,
      FindingID: f.id,
      Closure: f.closure,
      Confidence: f.confidence,
      Verification: f.verification,
      Remediated: f.status === "remediated",
    }

    rows.push(CSV_COLUMNS.map((c) => csvCell(row[c])).join(","))
  }

  return `${rows.join("\n")}\n`
}

/** Highest severity present, for a one-line export summary. */
export function worstSeverity(findings: { severity: Severity }[]): Severity | undefined {
  return findings.reduce<Severity | undefined>(
    (worst, f) => (worst === undefined || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst] ? f.severity : worst),
    undefined,
  )
}
