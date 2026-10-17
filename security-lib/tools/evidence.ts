/**
 * sec_evidence — persist and retrieve raw supporting artifacts.
 * Content is redacted for secrets before it touches disk unless the caller
 * explicitly opts out with include_secrets, for artifacts whose value is the
 * secret itself.
 */

import { tool } from "@opencode-ai/plugin"
import { listEvidence, readEvidence, resolveEvidence, saveEvidence } from "../evidence.ts"
import { loadScope } from "../config.ts"
import type { ToolCtxLike } from "./shared.ts"

export const secEvidence = tool({
  description:
    "Store or retrieve raw evidence supporting a finding. action=save persists output (HTTP transcripts, scanner output, " +
    "banners) and returns an id to reference from sec_finding; the raw value is written to disk verbatim by default and a " +
    "SHA-256 is recorded. action=list shows stored artifacts; action=get returns one. Prefer storing the minimal artifact " +
    "that demonstrates the issue. The operator's posture is full disclosure, so leaked credentials are kept in the clear and " +
    "appear in the report via sec_report evidence=full. Pass include_secrets=false to redact at capture instead — this is " +
    "irreversible: it cannot be undone by regenerating the report.",
  args: {
    action: tool.schema.enum(["save", "list", "get"]).describe("operation"),
    label: tool.schema.string().optional().describe("short description of what this evidence shows (save)"),
    content: tool.schema.string().optional().describe("raw artifact content (save)"),
    target: tool.schema.string().optional().describe("asset this evidence relates to (save)"),
    source: tool.schema.string().optional().describe("tool that produced it (save)"),
    include_secrets: tool.schema.boolean().optional().describe("store secret-like material verbatim (default true); false redacts at capture, irreversibly"),
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
        includeSecrets: args.include_secrets !== false,
      })
      if (!res.record) return `evidence rejected:\n${res.problems.map((p) => `  - ${p}`).join("\n")}`
      const r = res.record
      const note = r.redacted
        ? " — secrets redacted before storage"
        : " — stored verbatim, including any credentials"
      return `stored ${r.id} (${r.bytes} bytes, sha256 ${r.sha256.slice(0, 16)}…)${note}`
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
