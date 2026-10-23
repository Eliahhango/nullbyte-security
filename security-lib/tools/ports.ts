/**
 * sec_ports — bounded TCP connect scanning.
 * Active but non-destructive. Targets are authorized by default; metadata and
 * link-local addresses are still refused.
 */

import { tool } from "@opencode-ai/plugin"
import { COMMON_PORTS, parsePortSpec, scanPorts } from "../net/ports.ts"
import { loadScope } from "../config.ts"
import { configureLimits, describeLimits, isPaced } from "../ratelimit.ts"
import { startProgress } from "../progress.ts"
import { saveEvidence } from "../evidence.ts"
import { enforcePorts, splitTarget, type ToolCtxLike } from "./shared.ts"

export const secPorts = tool({
  description:
    "TCP connect port scan against a target. Bounded: explicit ports, concurrency and per-port timeouts, and a " +
    "hard cap on how many ports one call may probe. Optionally grabs service banners. This is a connect scan (no raw " +
    "sockets, no stealth). Targets are authorized by default; scope allow-lists do not gate scans and there is no " +
    "approval prompt. Raw SYN/OS-detection scanning belongs to the nmap adapter (sec_scan profile=intrusive). " +
    "Results are hints, not verified vulnerabilities.",
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

    await enforcePorts({
      ctx: c,
      tool: "sec_ports",
      host: target.host,
      ports,
      intensity: "safe-active",
      purpose: `connect scan of ${ports.length} ports`,
    })

    const loaded = loadScope(c.worktree)
    const limits = configureLimits(loaded.scope.limits)
    const root = loaded.paths.root
    c.metadata?.({ title: `sec_ports ${target.host} (${ports.length} ports)` })

    const progress = startProgress(`tcp ${target.host}`, { timer: true })
    try {
      const started = Date.now()
      const open = await scanPorts(target.host, ports, {
        concurrency: args.concurrency,
        timeoutMs: args.timeout_ms,
        grabBanner: args.grab_banner,
        onProgress: (state) => {
          progress.update(`tcp ${target.host} · ${state.done}/${state.total} ports · ${state.open} open`)
        },
      })
      const durationMs = Date.now() - started

      const report = [
        `connect scan ${target.host} — ${ports.length} ports probed in ${durationMs}ms, ${open.length} open`,
        capped ? `note: port list capped at ${MAX_PORTS} entries for this call` : "",
        isPaced(limits) ? `pacing: ${describeLimits()}` : "",
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
      progress.succeed(`tcp ${target.host} · ${open.length} open · ${(durationMs / 1000).toFixed(1)}s`)
      return ev.record ? `${report}\nraw evidence: ${ev.record.id}` : report
    } catch (error) {
      progress.fail(`tcp ${target.host} failed`)
      throw error
    } finally {
      progress.stop()
    }
  },
})
