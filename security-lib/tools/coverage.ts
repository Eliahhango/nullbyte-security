/**
 * sec_coverage — record what was tested, not just what was found.
 *
 * The ledger exists so a report can say "this surface was exercised and found
 * sound" or "this risk area still needs a follow-up". Without it, an empty
 * findings list is indistinguishable from an untested target.
 */

import { tool } from "@opencode-ai/plugin"
import { loadScope } from "../config.ts"
import { readAllFindings } from "../findings.ts"
import { writeAudit } from "../audit.ts"
import {
  COVERAGE_OUTCOMES,
  coverageSummary,
  listCoverage,
  recordCoverage,
  updateCoverage,
  type CoverageOutcome,
} from "../coverage.ts"
import type { ToolCtxLike } from "./shared.ts"

const OUTCOMES = COVERAGE_OUTCOMES

export const secCoverage = tool({
  description:
    "Record the negative space of the assessment: which surface × risk area was exercised and what was concluded. " +
    "action=record adds one entry (rejects a duplicate surface+risk pair and returns the existing id); action=update corrects " +
    "or advances an entry; action=list filters the ledger; action=summary shows outcome counts, unresolved follow-ups and " +
    "findings that have no linked coverage. Outcomes: reported (linked to a finding), no_issue_found, ruled_out, " +
    "not_applicable, needs_follow_up. Every outcome except reported requires evidence explaining the conclusion. " +
    "Record coverage after testing each surface — a report can only claim negative space that the ledger actually holds.",
  args: {
    action: tool.schema.enum(["record", "update", "list", "summary"]).describe("operation"),
    target: tool.schema.string().optional().describe("asset this entry belongs to (host, URL or repository path)"),
    surface: tool.schema.string().optional().describe("concrete endpoint, parameter, component or file exercised"),
    risk_area: tool.schema.string().optional().describe("class of weakness considered, e.g. 'authorization', 'SQL injection'"),
    outcome: tool.schema.enum(OUTCOMES).optional().describe("conclusion for this surface/risk pair"),
    evidence: tool.schema.string().optional().describe("why this conclusion was reached; required unless outcome=reported"),
    finding_id: tool.schema.string().optional().describe("linked finding id; required when outcome=reported"),
    entry_id: tool.schema.string().optional().describe("coverage entry id (update)"),
    outcome_filter: tool.schema.enum(OUTCOMES).optional().describe("filter for action=list"),
    session_only: tool.schema.boolean().optional().describe("list only entries from this scan session (default false)"),
    search: tool.schema.string().optional().describe("free-text filter for action=list"),
    limit: tool.schema.number().optional().describe("max rows for action=list (default 100)"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const root = loadScope(c.worktree).paths.root
    const by = c.agent || "unknown"

    if (args.action === "record") {
      const res = recordCoverage(root, c.sessionID, {
        target: args.target,
        surface: args.surface ?? "",
        risk_area: args.risk_area ?? "",
        outcome: (args.outcome ?? "not_applicable") as CoverageOutcome,
        evidence: args.evidence,
        finding_id: args.finding_id,
        recorded_by: by,
      })
      if (res.existing) {
        return [
          `coverage already recorded: ${res.existing.id} — ${res.existing.surface} / ${res.existing.risk_area} → ${res.existing.outcome}`,
          `Use action=update entry_id=${res.existing.id} to change the conclusion instead of recording a second entry.`,
        ].join("\n")
      }
      if (!res.entry) return `coverage rejected:\n${res.problems.map((p) => `  - ${p}`).join("\n")}`
      const e = res.entry
      writeAudit(root, {
        sessionID: c.sessionID,
        agent: by,
        tool: "sec_coverage",
        decision: "allow",
        code: "coverage.record",
        reason: `${e.id} ${e.outcome}: ${e.surface} / ${e.risk_area}`,
        args: e.target,
      })
      return [
        `recorded ${e.id}: ${e.surface} / ${e.risk_area} → ${e.outcome}`,
        e.target ? `target: ${e.target}` : "target: not recorded",
        e.finding_id ? `linked finding: ${e.finding_id}` : "",
      ]
        .filter(Boolean)
        .join("\n")
    }

    if (args.action === "update") {
      if (!args.entry_id) return "error: action=update requires entry_id"
      const patch: Record<string, unknown> = { recorded_by: by }
      if (args.target !== undefined) patch.target = args.target
      if (args.surface !== undefined) patch.surface = args.surface
      if (args.risk_area !== undefined) patch.risk_area = args.risk_area
      if (args.outcome !== undefined) patch.outcome = args.outcome
      if (args.evidence !== undefined) patch.evidence = args.evidence
      if (args.finding_id !== undefined) patch.finding_id = args.finding_id
      const res = updateCoverage(root, args.entry_id, patch)
      if (!res.entry) return `coverage update rejected:\n${res.problems.map((p) => `  - ${p}`).join("\n")}`
      const e = res.entry
      writeAudit(root, {
        sessionID: c.sessionID,
        agent: by,
        tool: "sec_coverage",
        decision: "allow",
        code: "coverage.update",
        reason: `${e.id} revised to ${e.outcome} (rev ${e.revision})`,
        args: e.target,
      })
      return `updated ${e.id} (revision ${e.revision}): ${e.surface} / ${e.risk_area} → ${e.outcome}`
    }

    if (args.action === "summary") {
      const entries = listCoverage(root, { limit: 1000 })
      const summary = coverageSummary(entries, readAllFindings(root))
      const lines = [
        `coverage entries: ${summary.total}`,
        ...OUTCOMES.map((o) => `  ${o.padEnd(16)} ${summary.by_outcome[o]}`),
      ]
      if (summary.empty) {
        lines.push("", "No coverage has been recorded. An empty findings list does not mean the target was tested.")
      }
      if (summary.findings_without_coverage.length) {
        lines.push("", `findings without linked coverage: ${summary.findings_without_coverage.length}`)
        for (const gap of summary.findings_without_coverage.slice(0, 20)) {
          lines.push(`  ${gap.id} ${gap.title}`)
        }
      }
      return lines.join("\n")
    }

    const entries = listCoverage(root, {
      outcome: args.outcome_filter as CoverageOutcome | undefined,
      sessionID: args.session_only ? c.sessionID : undefined,
      search: args.search,
      limit: args.limit ?? 100,
    })
    if (!entries.length) return "no coverage entries match"
    return entries
      .map(
        (e) =>
          `${e.id} [${e.outcome}] ${e.target ?? "-"} ${e.surface} / ${e.risk_area} — rev ${e.revision}` +
          (e.finding_id ? ` → ${e.finding_id}` : ""),
      )
      .join("\n")
  },
})
