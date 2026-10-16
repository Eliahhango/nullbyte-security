/**
 * sec_sast — local static analysis: secret discovery, code smells, dependency audit.
 * Operates on the local project only; no network scope is required.
 */

import { tool } from "@opencode-ai/plugin"
import { auditDependencies, scanSource } from "../sast.ts"
import { loadScope } from "../config.ts"
import { saveEvidence } from "../evidence.ts"
import { writeAudit } from "../audit.ts"
import type { ToolCtxLike } from "./shared.ts"

export const secSast = tool({
  description:
    "Static review of the LOCAL project tree (no network): action=secrets finds credential-shaped strings and reports their " +
    "location and kind WITHOUT printing the value; action=smells flags risky code patterns (eval, shell interpolation, SQL " +
    "concatenation, disabled TLS verification); action=deps audits dependencies via the project's lockfile; action=all runs " +
    "everything. Use this before or alongside dynamic testing for source-visible issues.",
  args: {
    action: tool.schema.enum(["secrets", "smells", "deps", "all"]).describe("which analysis to run"),
    path: tool.schema.string().optional().describe("subdirectory to scan (defaults to the project root)"),
    max_files: tool.schema.number().optional().describe("cap the number of files scanned (default 4000)"),
    only: tool.schema.array(tool.schema.string()).optional().describe("restrict secret kinds, e.g. ['aws-access-key-id']"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const loaded = loadScope(c.worktree)
    const root = args.path ? `${c.worktree}/${args.path}`.replace(/\/+/g, "/") : c.worktree

    c.metadata?.({ title: `sec_sast ${args.action}` })
    writeAudit(loaded.paths.root, {
      sessionID: c.sessionID,
      agent: c.agent,
      tool: "sec_sast",
      decision: "allow",
      code: "sast.run",
      reason: `${args.action} over ${root}`,
    })

    const out: string[] = []

    if (args.action === "secrets" || args.action === "all") {
      const res = scanSource(root, { maxFiles: args.max_files, only: args.only })
      out.push(`secret scan: ${res.filesScanned} files scanned, ${res.secrets.length} candidate secret(s)`)
      if (res.truncated) out.push(`  note: file cap reached; results are partial`)
      const byKind = new Map<string, number>()
      for (const s of res.secrets) byKind.set(s.kind, (byKind.get(s.kind) ?? 0) + 1)
      if (byKind.size) out.push(`  kinds: ${[...byKind].map(([k, n]) => `${k}×${n}`).join(", ")}`)
      for (const s of res.secrets.slice(0, 60)) out.push(`  ${s.file}:${s.line} [${s.kind}] ${s.preview}`)
      if (res.secrets.length > 60) out.push(`  ... ${res.secrets.length - 60} more (see evidence)`)
      if (res.secrets.length) {
        const ev = saveEvidence(loaded.paths.root, {
          sessionID: c.sessionID,
          source: "sec_sast",
          label: `secret scan ${root}`,
          content: res.secrets.map((s) => `${s.file}:${s.line} [${s.kind}] ${s.preview}`).join("\n"),
        })
        if (ev.record) out.push(`  evidence: ${ev.record.id}`)
      }
      if (!res.secrets.length) out.push("  no credential-shaped strings found (absence here is not proof of no secrets)")
    }

    if (args.action === "smells" || args.action === "all") {
      const res = scanSource(root, { maxFiles: args.max_files })
      const high = res.smells.filter((s) => s.severity === "high")
      out.push(`code smells: ${res.smells.length} pattern hit(s) (${high.length} high)`)
      for (const s of res.smells.slice(0, 40)) out.push(`  [${s.severity}] ${s.file}:${s.line} ${s.rule} — ${s.detail}`)
      if (res.smells.length > 40) out.push(`  ... ${res.smells.length - 40} more`)
    }

    if (args.action === "deps" || args.action === "all") {
      const audit = await auditDependencies(c.worktree)
      if (!audit.ok) {
        out.push(`dependency audit: unavailable — ${audit.problems.join("; ")}`)
      } else {
        const v = audit.vulnerabilities ?? {}
        out.push(
          `dependency audit (${audit.manager}, ${audit.lockfile}): ${audit.advisories.length} advisory record(s) ` +
            `[critical ${v.critical ?? 0}, high ${v.high ?? 0}, moderate ${v.moderate ?? 0}, low ${v.low ?? 0}]`,
        )
        for (const a of audit.advisories.slice(0, 40)) out.push(`  [${a.severity}] ${a.package}${a.range ? ` ${a.range}` : ""} — ${a.title}`)
        if (audit.advisories.length > 40) out.push(`  ... ${audit.advisories.length - 40} more`)
      }
    }

    return out.join("\n")
  },
})
