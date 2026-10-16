/**
 * sec_report — render and export the assessment.
 * Produces markdown for humans and JSON for tooling, in the engagement dir.
 */

import { tool } from "@opencode-ai/plugin"
import { loadScope } from "../config.ts"
import { describeScope } from "../scope.ts"
import { readAllFindings, severitySummary } from "../findings.ts"
import { listEvidence } from "../evidence.ts"
import { renderMarkdown, renderJson, writeReport, type ReportInput } from "../report.ts"
import { writeAudit } from "../audit.ts"
import type { ToolCtxLike } from "./shared.ts"

export const secReport = tool({
  description:
    "Generate the security assessment report from the findings and evidence already recorded. " +
    "action=preview returns the markdown without writing anything; action=export writes both markdown and JSON into the " +
    "engagement reports directory and returns the paths. Always pass limitations describing what was not tested, what was " +
    "blocked and what remains unverified — a report without limitations overstates coverage.",
  args: {
    action: tool.schema.enum(["preview", "export"]).describe("preview = render only, export = write markdown + JSON"),
    name: tool.schema.string().optional().describe("base filename for the export (sanitized)"),
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

    const res = writeReport(root, input, args.name)
    writeAudit(root, {
      sessionID: c.sessionID,
      agent: c.agent,
      tool: "sec_report",
      decision: "allow",
      code: "report.export",
      reason: `exported ${findings.length} findings`,
    })

    const untested = findings.filter((f) => f.verification !== "verified").length
    return [
      `report exported`,
      `  markdown: ${res.markdownPath}`,
      `  json:     ${res.jsonPath}`,
      `  findings: ${findings.length} (critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info})`,
      `  evidence artifacts: ${evidence.length}`,
      untested ? `  note: ${untested} finding(s) are not marked verified — they are reported as unverified/inconclusive` : "",
      args.limitations ? "" : "  WARNING: no limitations were supplied; the report will state that coverage was not qualified",
    ]
      .filter(Boolean)
      .join("\n")
  },
})

export const _json = renderJson
