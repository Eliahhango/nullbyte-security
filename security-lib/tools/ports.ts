/**
 * sec_ports — bounded TCP connect scanning.
 * Active but non-destructive: requires at least safe-active intensity.
 */

import { tool } from "@opencode-ai/plugin"
import { COMMON_PORTS, parsePortSpec, scanPorts } from "../net/ports.ts"
import { loadScope } from "../config.ts"
import { saveEvidence } from "../evidence.ts"
import { enforce, splitTarget, type ToolCtxLike } from "./shared.ts"

export const secPorts = tool({
  description:
    "TCP connect port scan against an AUTHORIZED target. Bounded: explicit ports, concurrency and per-port timeouts, and a " +
    "hard cap on how many ports one call may probe. Optionally grabs service banners. This is a connect scan (no raw sockets, " +
    "no stealth) and requires at least safe-active intensity; raw SYN/OS-detection scanning belongs to the nmap adapter " +
    "(sec_scan profile=intrusive) which requires approval. Results are hints, not verified vulnerabilities.",
  args: {
    target: tool.schema.string().describe("authorized host or IP"),
    ports: tool.schema.string().optional().describe("port spec like '80,443,8000-8010'; default is a curated common set"),
    top: tool.schema.enum(["common", "extended"]).optional().describe("preset when ports is omitted"),
    concurrency: tool.schema.number().optional().describe("parallel connections (default 64, max 256)"),
    timeout_ms: tool.schema.number().optional().describe("per-port timeout (default 1500ms, max 10000)"),
    grab_banner: tool.schema.boolean().optional().describe("read a service banner (slower, more revealing)"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const target = splitTarget(args.target)

    let ports = args.ports ? parsePortSpec(args.ports) : [...COMMON_PORTS]
    if (args.ports && !ports.length) return `error: could not parse port spec '${args.ports}'`
    const MAX_PORTS = 4096
    let capped = false
    if (ports.length > MAX_PORTS) {
      ports = ports.slice(0, MAX_PORTS)
      capped = true
    }
    if (!ports.length) return "error: no ports to scan"

    await enforce({
      ctx: c,
      tool: "sec_ports",
      target,
      intensity: "safe-active",
      purpose: `connect scan of ${ports.length} ports`,
    })

    const root = loadScope(c.worktree).paths.root
    c.metadata?.({ title: `sec_ports ${target.host} (${ports.length} ports)` })

    const started = Date.now()
    const open = await scanPorts(target.host, ports, {
      concurrency: args.concurrency,
      timeoutMs: args.timeout_ms,
      grabBanner: args.grab_banner,
    })
    const durationMs = Date.now() - started

    const report = [
      `connect scan ${target.host} — ${ports.length} ports probed in ${durationMs}ms, ${open.length} open`,
      capped ? `note: port list capped at ${MAX_PORTS} entries for this call` : "",
      ...open.map(
        (p) => `  ${p.port}/tcp open  ${p.service ?? "unknown"}${p.banner ? `  banner: ${p.banner.slice(0, 120)}` : ""}  (${p.latencyMs}ms)`,
      ),
    ]
      .filter(Boolean)
      .join("\n")

    const ev = saveEvidence(root, {
      sessionID: c.sessionID,
      source: "sec_ports",
      label: `connect scan ${target.host}`,
      target: target.host,
      content: report,
    })
    return ev.record ? `${report}\nraw evidence: ${ev.record.id}` : report
  },
})
