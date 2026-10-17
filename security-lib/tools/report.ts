/**
 * sec_report — render and export the assessment.
 * Produces markdown for humans and JSON for tooling, in the engagement dir.
 */

import { tool } from "@opencode-ai/plugin"
import { resolve } from "node:path"
import { loadScope } from "../config.ts"
import { resolveProjectRoot } from "../paths.ts"
import { describeScope, authorize } from "../scope.ts"
import { readAllFindings, severitySummary } from "../findings.ts"
import { selectReportData, describeDrops, hostOf } from "../report-selection.ts"
import { listEvidence, readEvidence } from "../evidence.ts"
import { redactSecrets } from "../redact.ts"
import { renderMarkdown, renderJson, writeReport, ALL_FORMATS, type ReportFormat, type ReportInput } from "../report.ts"
import { writeAudit } from "../audit.ts"
import type { ToolCtxLike } from "./shared.ts"

const FORMATS = [...ALL_FORMATS, "all"] as const

export const secReport = tool({
  description:
    "Generate the security assessment report from the findings and evidence already recorded. " +
    "action=preview returns the markdown without writing anything; action=export writes the report to disk. " +
    `format selects the output: ${ALL_FORMATS.join(", ")}, or 'all' (default). Files are written to the directory the agent ` +
    "was run in unless out_dir says otherwise. HTML is self-contained; PDF needs a converter (weasyprint, chrome or chromium) " +
    "and is reported honestly when none is installed. " +
    "evidence=full embeds the full stored content of every artifact, not just the index. " +
    "coverage controls which findings are included and defaults to 'session' — only what this scan session recorded. " +
    "The store is engagement-wide, so 'engagement' would mix every earlier session and every other target into the " +
    "report; use it deliberately, not by accident. Findings on a host outside the authorized scope are always excluded. " +
    "redact=false emits the deliverables verbatim, including any credentials the evidence holds — use it only when the " +
    "operator has asked for an unredacted report. Redaction can only remove secrets that are still present: an artifact " +
    "stored with sec_evidence include_secrets=false was already redacted at capture and cannot be recovered here. " +
    "Always pass limitations describing what was not tested, what was " +
    "blocked and what remains unverified — a report without limitations overstates coverage.",
  args: {
    action: tool.schema.enum(["preview", "export"]).describe("preview = render only, export = write to disk"),
    format: tool.schema
      .enum(FORMATS as unknown as [string, ...string[]])
      .optional()
      .describe(`output format(s): ${ALL_FORMATS.join("|")}|all (default all)`),
    name: tool.schema.string().optional().describe("base filename for the export (sanitized)"),
    out_dir: tool.schema.string().optional().describe("directory to write into; defaults to the project the agent was run in"),
    coverage: tool.schema
      .enum(["session", "engagement", "target"])
      .optional()
      .describe("session = only this scan session (default); engagement = every session in the store; target = only this target host"),
    target: tool.schema.string().optional().describe("host to restrict to when coverage=target (host, host:port or URL)"),
    evidence: tool.schema
      .enum(["none", "index", "full"])
      .optional()
      .describe("none = omit evidence entirely; index = table of artifacts (default); full = embed every artifact's content"),
    redact: tool.schema.boolean().optional().describe("redact secrets from the deliverables (default true); false emits verbatim"),
    limitations: tool.schema.string().optional().describe("what was not tested / blocked / unverified"),
    provenance: tool.schema.string().optional().describe("agent and tools used, for the report header"),
    min_severity: tool.schema.enum(["info", "low", "medium", "high", "critical"]).optional().describe("exclude findings below this severity"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const loaded = loadScope(c.worktree)
    const root = loaded.paths.root

    const evidenceMode = args.evidence ?? "index"
    const redact = args.redact !== false
    const coverage = args.coverage ?? "session"

    // Selection runs before anything is rendered. The store is engagement-wide,
    // so an unfiltered read would mix other sessions and other targets into
    // this report.
    const selection = selectReportData(readAllFindings(root), listEvidence(root), {
      sessionID: coverage === "session" ? c.sessionID : undefined,
      host: coverage === "target" && args.target ? hostOf(args.target) ?? undefined : undefined,
      isAuthorized: (host) => authorize(loaded.scope, { host }, "passive", { skipPrivateCheck: true }).allowed,
    })

    let findings = selection.findings
    if (args.min_severity) {
      const order = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }
      findings = findings.filter((f) => order[f.severity] >= order[args.min_severity as keyof typeof order])
    }
    const evidence = evidenceMode === "none" ? [] : selection.evidence
    const counts = severitySummary(findings)

    const dropped = describeDrops(selection.drops, selection.foreignHosts)
    const covered =
      coverage === "session"
        ? `this scan session (${c.sessionID})`
        : coverage === "target"
          ? `target ${args.target ?? "(unset)"}`
          : "every session in the engagement store"
    const selectionNote = [covered, dropped].filter(Boolean).join(" — ")

    const evidenceContent: Record<string, string> | undefined =
      evidenceMode === "full"
        ? Object.fromEntries(
            evidence.map((e) => {
              const body = readEvidence(root, e.id)
              return [e.id, body ?? "_(artifact file is missing from the evidence store)_"]
            }),
          )
        : undefined

    const input: ReportInput = {
      engagement: loaded.scope.engagement,
      scopeSummary: describeScope(loaded.scope, loaded.source, loaded.warnings),
      sessionID: c.sessionID,
      findings,
      evidence,
      evidenceContent,
      unredacted: !redact,
      selectionNote,
      limitations: args.limitations,
      provenance: args.provenance ?? `agent=${c.agent} via NullByte security capability layer`,
    }

    if (args.action === "preview") {
      const md = renderMarkdown(input)
      return redact ? redactSecrets(md) : md
    }

    const formats: ReportFormat[] = !args.format || args.format === "all" ? [...ALL_FORMATS] : [args.format as ReportFormat]
    // default destination: the directory the agent was run in, not a system dir
    const outDir = args.out_dir ? resolve(args.out_dir) : resolveProjectRoot(c.worktree)

    const res = writeReport(root, input, { name: args.name, formats, outDir, redact })
    writeAudit(root, {
      sessionID: c.sessionID,
      agent: c.agent,
      tool: "sec_report",
      decision: "allow",
      code: redact ? "report.export" : "report.export.unredacted",
      reason: `exported ${findings.length} findings as ${formats.join("+")}; coverage=${coverage}; evidence=${evidenceMode}; redact=${redact}`,
      args: outDir,
    })

    const untested = findings.filter((f) => f.verification !== "verified").length
    const lines = [
      `report exported to ${res.dir}`,
      ...res.files.map((f) => `  ${f.format.padEnd(4)} ${f.path}`),
    ]
    if (res.pdf && !res.pdf.ok) {
      lines.push(`  pdf  NOT WRITTEN — ${res.pdf.reason}`)
      if (res.pdf.hint) lines.push(`       ${res.pdf.hint}`)
    }
    lines.push(
      `  coverage: ${covered}`,
      `  findings: ${findings.length} (critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info})`,
      `  evidence artifacts: ${evidence.length}${evidenceMode === "full" ? " (content embedded)" : ""}`,
    )
    if (dropped) lines.push(`  ${dropped}`)
    if (coverage === "session" && findings.length === 0 && selection.drops.otherSession > 0) {
      lines.push(
        `  note: this session recorded no findings, but ${selection.drops.otherSession} exist from other sessions — ` +
          `pass coverage=engagement if the report is meant to cover the whole engagement`,
      )
    }
    if (coverage === "target" && !args.target) lines.push("  WARNING: coverage=target was requested without a target; no host filter was applied")
    if (!redact) lines.push("  UNREDACTED — these files contain live secrets; restrict distribution and rotate what they disclose")
    const alreadyRedacted = evidence.filter((e) => e.redacted).length
    if (evidenceMode === "full" && alreadyRedacted) {
      lines.push(
        `  note: ${alreadyRedacted} artifact(s) were redacted at capture (include_secrets=false) — their secrets are not in this report and cannot be recovered`,
      )
    }
    if (untested) lines.push(`  note: ${untested} finding(s) are not marked verified — they are reported as unverified/inconclusive`)
    if (!args.limitations) lines.push("  WARNING: no limitations were supplied; the report will state that coverage was not qualified")
    return lines.join("\n")
  },
})

export const _json = renderJson

