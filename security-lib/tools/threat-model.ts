/**
 * sec_threat_model — save and amend the shared threat model.
 *
 * The model is per target, not per agent: every agent working the same host or
 * repository reads the same reasoning. Amendments are append-only so the final
 * report shows how the model changed as the assessment learned.
 */

import { tool } from "@opencode-ai/plugin"
import { loadScope } from "../config.ts"
import { writeAudit } from "../audit.ts"
import {
  amendThreatModel,
  getThreatModel,
  listThreatModels,
  renderThreatModelMarkdown,
  saveThreatModel,
  threatModelKey,
} from "../threat-model.ts"
import type { ToolCtxLike } from "./shared.ts"

export const secThreatModel = tool({
  description:
    "Maintain the shared threat model for a target. action=save replaces the base model (actors, assets, trust boundaries, " +
    "entry points, hypotheses, out-of-scope assumptions) and keeps its revision history; action=amend appends a dated " +
    "amendment without rewriting the original; action=get returns the base model plus amendments; action=list shows all " +
    "models in the engagement. Save the model before testing, and amend it when reconnaissance changes an assumption. " +
    "Agents on the same target share one model, keyed by host or repository path.",
  args: {
    action: tool.schema.enum(["save", "amend", "get", "list"]).describe("operation"),
    target: tool.schema.string().optional().describe("host, URL or repository path (save/amend/get)"),
    content: tool.schema.string().optional().describe("full threat model in Markdown (save)"),
    addendum: tool.schema.string().optional().describe("dated addition to the existing model (amend)"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const root = loadScope(c.worktree).paths.root
    const by = c.agent || "unknown"
    const baseDir = c.directory || c.worktree

    if (args.action === "save") {
      if (!args.target) return "error: action=save requires target"
      const res = saveThreatModel(root, args.target, args.content ?? "", by, baseDir)
      if (!res.entry) return `threat model rejected:\n${res.problems.map((p) => `  - ${p}`).join("\n")}`
      const e = res.entry
      writeAudit(root, {
        sessionID: c.sessionID,
        agent: by,
        tool: "sec_threat_model",
        decision: "allow",
        code: "threat_model.save",
        reason: `saved ${e.key} (revision ${e.revision})`,
        args: e.target,
      })
      return `saved threat model for ${e.target} (${e.key}, revision ${e.revision})`
    }

    if (args.action === "amend") {
      if (!args.target) return "error: action=amend requires target"
      const res = amendThreatModel(root, args.target, args.addendum ?? "", by, baseDir)
      if (!res.entry) return `threat model amendment rejected:\n${res.problems.map((p) => `  - ${p}`).join("\n")}`
      const e = res.entry
      writeAudit(root, {
        sessionID: c.sessionID,
        agent: by,
        tool: "sec_threat_model",
        decision: "allow",
        code: "threat_model.amend",
        reason: `amended ${e.key} (revision ${e.revision})`,
        args: e.target,
      })
      return `amended threat model for ${e.target} (revision ${e.revision}, ${e.amendments.length} amendment(s))`
    }

    if (args.action === "list") {
      const rows = listThreatModels(root)
      if (!rows.length) return "no threat models saved"
      return rows
        .map((e) => `${e.target} — revision ${e.revision}, updated ${e.updated_at} by ${e.updated_by} (${e.key})`)
        .join("\n")
    }

    if (!args.target) return "error: action=get requires target"
    const key = threatModelKey(args.target, baseDir)
    const entry = getThreatModel(root, args.target, baseDir)
    if (!entry) return `no threat model saved for ${args.target} (${key.key})`
    return renderThreatModelMarkdown(entry)
  },
})
