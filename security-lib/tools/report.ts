/**
 * sec_report — render and export the assessment.
 * Produces markdown for humans and JSON for tooling, in the engagement dir.
 */

import { tool } from "@opencode-ai/plugin"
import { resolve } from "node:path"
import { loadScope } from "../config.ts"
import { resolveProjectRoot } from "../paths.ts"
import { describeScope } from "../scope.ts"
import { readAllFindings, severitySummary } from "../findings.ts"
import { listEvidence } from "../evidence.ts"
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
    "and is reported honestly when none is installed. Always pass limitations describing what was not tested, what was " +
    "blocked and what remains unverified — a report without limitations overstates coverage.",
  args: {
    action: tool.schema.enum(["preview", "export"]).describe("preview = render only, export = write to disk"),
    format: tool.schema
      .enum(FORMATS as unknown as [string, ...string[]])
      .optional()
      .describe(`output format(s): ${ALL_FORMATS.join("|")}|all (default all)`),
    name: tool.schema.string().optional().describe("base filename for the export (sanitized)"),
    out_dir: tool.schema.string().optional().describe("directory to write into; defaults to the project the agent was run in"),
    limitations: tool.schema.string().optional().describe("what was not tested / blocked / unverified"),
    provenance: tool.schema.string().optional().describe("agent and tools used, for the report header"),
    min_severity: tool.schema.enum(["info", "low", "medium", "high", "critical"]).optional().describe("exclude findings below this severity"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const loaded = loadScope(c.worktree)
    const root = loaded.paths.root

    let findings = readAllFindings(root)
    if (args.min_severity) {
      const order = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }
      findings = findings.filter((f) => order[f.severity] >= order[args.min_severity as keyof typeof order])
    }
    const evidence = listEvidence(root)
    const counts = severitySummary(findings)

    const input: ReportInput = {
      engagement: loaded.scope.engagement,
      scopeSummary: describeScope(loaded.scope, loaded.source, loaded.warnings),
      sessionID: c.sessionID,
      findings,
      evidence,
      limitations: args.limitations,
      provenance: args.provenance ?? `agent=${c.agent} via NullByte security capability layer`,
    }

    if (args.action === "preview") {
      return renderMarkdown(input)
    }

    const formats: ReportFormat[] = !args.format || args.format === "all" ? [...ALL_FORMATS] : [args.format as ReportFormat]
    // default destination: the directory the agent was run in, not a system dir
    const outDir = args.out_dir ? resolve(args.out_dir) : resolveProjectRoot(c.worktree)

    const res = writeReport(root, input, { name: args.name, formats, outDir })
    writeAudit(root, {
      sessionID: c.sessionID,
      agent: c.agent,
      tool: "sec_report",
      decision: "allow",
      code: "report.export",
      reason: `exported ${findings.length} findings as ${formats.join("+")}`,
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
      `  findings: ${findings.length} (critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info})`,
      `  evidence artifacts: ${evidence.length}`,
    )
    if (untested) lines.push(`  note: ${untested} finding(s) are not marked verified — they are reported as unverified/inconclusive`)
    if (!args.limitations) lines.push("  WARNING: no limitations were supplied; the report will state that coverage was not qualified")
    return lines.join("\n")
  },
})

export const _json = renderJson

