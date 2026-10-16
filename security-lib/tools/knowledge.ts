/**
 * sec_methodology and sec_audit — shared knowledge access and the audit trail.
 */

import { tool } from "@opencode-ai/plugin"
import { listFragments, loadFragment, searchFragments } from "../methodology.ts"
import { readAudit } from "../audit.ts"
import { loadScope } from "../config.ts"
import type { ToolCtxLike } from "./shared.ts"

export const secMethodology = tool({
  description:
    "Shared pentest methodology fragments — the agent-agnostic knowledge base. action=search finds fragments by keyword " +
    "(xss, sqli, ssrf, idor, rce, lfi, jwt, scope, recon, tls, headers, scanners, verification, evidence, reporting, " +
    "prompt-injection); action=load returns one fragment in full; action=list shows everything available. Consult these " +
    "instead of improvising process or payloads.",
  args: {
    action: tool.schema.enum(["search", "load", "list"]).describe("operation"),
    query: tool.schema.string().optional().describe("search terms (action=search)"),
    id: tool.schema.string().optional().describe("fragment id (action=load)"),
    limit: tool.schema.number().optional().describe("max fragments to return for action=search (default 3)"),
  },
  async execute(args) {
    if (args.action === "list") {
      return listFragments()
        .map((f) => `${f.id} — ${f.title} [${f.tags.join(", ")}]`)
        .join("\n")
    }
    if (args.action === "load") {
      if (!args.id) return "error: action=load requires id"
      const f = loadFragment(args.id)
      return f ? `# ${f.title} (${f.id})\ntags: ${f.tags.join(", ")}\n\n${f.body}` : `no fragment matching '${args.id}'`
    }
    if (!args.query) return "error: action=search requires a query"
    const limit = Math.max(1, Math.min(Math.trunc(args.limit ?? 3), listFragments().length))
    const hits = searchFragments(args.query, limit)
    if (!hits.length) return `no methodology fragment matched '${args.query}'. Available:\n${listFragments().map((f) => `  ${f.id}`).join("\n")}`
    return hits.map((f) => `# ${f.title} (${f.id})\n${f.body}`).join("\n\n---\n\n")
  },
})

export const secAudit = tool({
  description:
    "Review the audit trail of security tool decisions for this engagement: which targets were authorized or refused, which " +
    "operations required approval, and when. Use it to verify that nothing ran outside scope, and to quote the decision " +
    "history in the report's limitations.",
  args: {
    limit: tool.schema.number().optional().describe("how many recent records to return (default 50)"),
    decisions: tool.schema.enum(["all", "deny", "ask"]).optional().describe("filter to refusals or approval requests"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const root = loadScope(c.worktree).paths.root
    const records = readAudit(root, args.limit ?? 50)
    const filtered = !args.decisions || args.decisions === "all" ? records : records.filter((r) => r.decision === args.decisions)
    if (!filtered.length) return "audit trail is empty (no security tool calls recorded yet)"
    return filtered
      .map((r) => `${r.ts} ${r.decision.toUpperCase()} ${r.tool} [${r.code}] ${r.reason}${r.targets?.length ? ` targets=${r.targets.join(",")}` : ""}`)
      .join("\n")
  },
})
