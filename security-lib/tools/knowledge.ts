/**
 * sec_methodology and sec_audit — shared knowledge access and the audit trail.
 *
 * sec_methodology uses progressive disclosure: `search` returns metadata only
 * (cheap, safe to call repeatedly), `load` returns the full content of up to
 * MAX_SELECTED_FRAGMENTS fragments under a byte budget. Loaded content is
 * wrapped in a non-grant notice and its class-specific precision requirements,
 * so methodology can inform the work without granting scope or authority.
 */

import { tool } from "@opencode-ai/plugin"
import {
  MAX_SELECTED_FRAGMENTS,
  categorySummary,
  listFragments,
  renderKnowledge,
  searchCatalog,
} from "../methodology.ts"
import { readAudit } from "../audit.ts"
import { loadScope } from "../config.ts"
import type { ToolCtxLike } from "./shared.ts"

export const secMethodology = tool({
  description:
    "Shared pentest methodology — the agent-agnostic knowledge base, 23 fragments across process, vulnerability and " +
    "analysis categories. action=search returns matching fragments as metadata (id, category, title, description) without " +
    "loading content; call it with no query to get category counts. action=load returns the full content of up to " +
    `${MAX_SELECTED_FRAGMENTS} fragments by id (bare like 'xss', category-qualified like 'vulnerability/xss', or a partial id). ` +
    "action=list shows every id. Vulnerability fragments ship with precision requirements that override the fragment text, " +
    "so load them before testing a class rather than improvising payloads.",
  args: {
    action: tool.schema.enum(["search", "load", "list"]).describe("operation"),
    query: tool.schema.string().optional().describe("search terms, e.g. xss, sqli, ssrf, idor, rce, lfi, jwt, recon (action=search)"),
    category: tool.schema.enum(["process", "vulnerability", "analysis"]).optional().describe("restrict search to a category (action=search)"),
    limit: tool.schema.number().optional().describe("max results for action=search (default 8)"),
    id: tool.schema.string().optional().describe("single fragment id (action=load)"),
    ids: tool.schema.array(tool.schema.string()).optional().describe("fragment ids to load together (action=load)"),
  },
  async execute(args) {
    if (args.action === "list") {
      const cats = categorySummary()
      return [
        `categories: ${cats.map((c) => `${c.category} (${c.count})`).join(", ")}`,
        "",
        ...listFragments().map((f) => `${f.id} — ${f.title} [${f.tags.join(", ")}]`),
      ].join("\n")
    }

    if (args.action === "load") {
      const requested = args.ids?.length ? args.ids : args.id ? [args.id] : []
      if (!requested.length) return "error: action=load requires id or ids"
      const rendered = renderKnowledge(requested)
      if (!rendered.ok) return `load refused:\n${rendered.problems.map((p) => `  - ${p}`).join("\n")}`
      return rendered.content
    }

    if (!args.query && !args.category) {
      const catalog = searchCatalog(undefined, undefined)
      return catalog.hint ?? "no fragments available"
    }
    const catalog = searchCatalog(args.query, args.category, args.limit ?? 8)
    if (!catalog.results.length) {
      return [
        `no methodology fragment matched${args.query ? ` '${args.query}'` : ""}${args.category ? ` in category ${args.category}` : ""}.`,
        catalog.hint ?? "",
        `available: ${listFragments().map((f) => f.id).join(", ")}`,
      ]
        .filter(Boolean)
        .join("\n")
    }
    return [
      `${catalog.total_matches} match(es)${catalog.has_more ? `, showing ${catalog.results.length} — narrow the query or raise limit` : ""}:`,
      "",
      ...catalog.results.map(
        (r) =>
          `${r.qualified_id}${r.has_precision_note ? " [precision rules]" : ""} — ${r.description}`,
      ),
      "",
      "Load the ones you need with action=load ids=[...].",
    ].join("\n")
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
