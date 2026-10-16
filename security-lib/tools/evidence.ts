/**
 * sec_evidence — persist and retrieve raw supporting artifacts.
 * Content is redacted for secrets before it touches disk.
 */

import { tool } from "@opencode-ai/plugin"
import { listEvidence, readEvidence, resolveEvidence, saveEvidence } from "../evidence.ts"
import { loadScope } from "../config.ts"
import type { ToolCtxLike } from "./shared.ts"

export const secEvidence = tool({
  description:
    "Store or retrieve raw evidence supporting a finding. action=save persists output (HTTP transcripts, scanner output, " +
    "banners) and returns an id to reference from sec_finding; secrets are redacted before storage and a SHA-256 is recorded. " +
    "action=list shows stored artifacts; action=get returns one. Prefer storing the minimal artifact that demonstrates the issue.",
  args: {
    action: tool.schema.enum(["save", "list", "get"]).describe("operation"),
    label: tool.schema.string().optional().describe("short description of what this evidence shows (save)"),
    content: tool.schema.string().optional().describe("raw artifact content (save)"),
    target: tool.schema.string().optional().describe("asset this evidence relates to (save)"),
    source: tool.schema.string().optional().describe("tool that produced it (save)"),
    id: tool.schema.string().optional().describe("evidence id (get)"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const root = loadScope(c.worktree).paths.root

    if (args.action === "save") {
      const res = saveEvidence(root, {
        sessionID: c.sessionID,
        source: args.source ?? "manual",
        label: args.label ?? "evidence",
        content: args.content ?? "",
        target: args.target,
      })
      if (!res.record) return `evidence rejected:\n${res.problems.map((p) => `  - ${p}`).join("\n")}`
      const r = res.record
      return `stored ${r.id} (${r.bytes} bytes, sha256 ${r.sha256.slice(0, 16)}…)${r.redacted ? " — secrets redacted before storage" : ""}`
    }

    if (args.action === "list") {
      const rows = listEvidence(root)
      if (!rows.length) return "no evidence stored yet"
      return rows.map((r) => `${r.id} [${r.source}] ${r.label} — ${r.target ?? "n/a"}, ${r.bytes} bytes, ${r.redacted ? "redacted" : "verbatim"}`).join("\n")
    }

    if (!args.id) return "error: action=get requires id"
    const content = readEvidence(root, args.id)
    if (content === undefined) {
      const { missing } = resolveEvidence(root, [args.id])
      return `evidence ${args.id} not found${missing.length ? "" : " (index entry exists but file is missing)"}`
    }
    return content
  },
})
