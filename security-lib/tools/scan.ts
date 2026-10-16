/**
 * sec_scan — controlled adapters over external scanners.
 *
 * Adapters verify availability first, build argv vectors (never shell strings),
 * enforce timeouts, parse structured output, and persist raw output as evidence.
 * A missing scanner yields install guidance, never a fabricated result.
 */

import { tool } from "@opencode-ai/plugin"
import { capabilityReport, requireTool } from "../adapters/registry.ts"
import {
  buildNucleiArgs,
  buildNmapArgs,
  parseNiktoJson,
  parseNmapXml,
  parseNucleiJsonl,
  parseWhatWebJson,
  readTempfile,
  runArgv,
  runNmap,
  runWithTempfile,
} from "../adapters/scanners.ts"
import { saveEvidence } from "../evidence.ts"
import { parsePortSpec } from "../net/ports.ts"
import { portAllowance } from "../scope.ts"
import { enforce, enforcePorts, scopeFor, splitTarget, type ToolCtxLike } from "./shared.ts"
import type { Intensity, Severity } from "../types.ts"

const ADAPTERS = ["nmap", "nuclei", "nikto", "whatweb", "sslscan", "sqlmap"] as const
const SEV = ["info", "low", "medium", "high", "critical"] as const

export const secScan = tool({
  description:
    "Run an external security scanner through a controlled adapter, or list which scanners are installed. " +
    "Adapters: nmap (port/service, profiles connect|service|intrusive), nuclei (template scan), nikto (web misconfig), " +
    "whatweb (tech fingerprint), sslscan (TLS config). Every adapter checks the binary exists first and returns install " +
    "guidance if it does not; raw output is saved as evidence. Intrusive profiles require operator approval. " +
    "Scanner output is a lead, not a finding — verify before reporting.",
  args: {
    action: tool.schema.enum(["capabilities", "run"]).describe("capabilities = list installed scanners; run = execute one"),
    adapter: tool.schema.enum(ADAPTERS).optional().describe("which scanner (required for action=run)"),
    target: tool.schema.string().optional().describe("authorized host/IP/URL (required for action=run)"),
    profile: tool.schema.enum(["connect", "service", "intrusive"]).optional().describe("nmap profile; intrusive needs approval"),
    ports: tool.schema.string().optional().describe("port spec, e.g. '80,443,8000-8010'"),
    severity: tool.schema.array(tool.schema.enum(SEV)).optional().describe("nuclei severity filter"),
    timeout_ms: tool.schema.number().optional().describe("hard timeout (default 300000)"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike

    if (args.action === "capabilities") {
      return `${capabilityReport()}\n\nAdapters run with argv arrays (no shell), bounded timeouts, capped output, and scope validation.`
    }

    if (!args.adapter) return "error: action=run requires an adapter"
    if (!args.target) return "error: action=run requires a target"

    const toolId = args.adapter
    const avail = requireTool(toolId)
    if (!avail.ok) return `capability unavailable: ${avail.problem}`
    const bin = avail.tool.path!

    const target = splitTarget(args.target)
    const intensity: Intensity =
      toolId === "nmap" && args.profile === "intrusive" ? "intrusive" : toolId === "sqlmap" ? "intrusive" : "safe-active"

    const loaded = scopeFor(c.worktree)
    let ports = args.ports ? parsePortSpec(args.ports) : undefined

    // A scanner with no explicit port list falls back to an implicit default set
    // the operator never authorized. When the scope entry restricts ports, pin
    // the scan to the authorized set instead of trusting the scanner's default.
    if (!ports?.length) {
      const allowance = portAllowance(loaded.scope, target.host)
      if (allowance?.length) ports = allowance
    }
    if (!ports?.length && target.port) ports = [target.port]

    // A port supplied in the target (`host:port`) must be authorized too, even
    // when it is not part of the explicit list — otherwise it is a way around
    // the per-port check.
    if (ports?.length && target.port && !ports.includes(target.port)) ports = [...ports, target.port]

    if (ports?.length) {
      await enforcePorts({
        ctx: c,
        tool: `sec_scan:${toolId}`,
        host: target.host,
        ports,
        intensity,
        purpose: `${toolId} scan`,
      })
    } else {
      await enforce({
        ctx: c,
        tool: `sec_scan:${toolId}`,
        target,
        intensity,
        purpose: `${toolId} scan`,
      })
    }

    const root = loaded.paths.root
    const timeoutMs = Math.max(5000, Math.min(args.timeout_ms ?? 300000, 900000))

    c.metadata?.({ title: `sec_scan ${toolId} ${target.host}` })

    if (toolId === "nmap") {
      const profile = args.profile ?? "connect"
      const { run, result } = await runNmap(target.host, profile, ports, bin, { timeoutMs })
      const ev = saveEvidence(root, {
        sessionID: c.sessionID,
        source: "nmap",
        label: `nmap ${profile} ${target.host}`,
        target: target.host,
        content: run.stdout || run.stderr,
      })
      const lines = [`nmap ${profile} ${target.host} — exit ${run.exitCode} in ${run.durationMs}ms`]
      lines.push(`command: ${run.command}`)
      if (ev.record) lines.push(`raw evidence: ${ev.record.id}`)
      if (run.problems.length) lines.push(`problems: ${run.problems.join("; ")}`)
      if (result) {
        const open = result.ports.filter((p) => p.state === "open")
        lines.push(`addresses: ${result.addresses.join(", ") || "n/a"}`)
        if (open.length) {
          lines.push("open ports:")
          for (const p of open) {
            lines.push(`  ${p.port}/${p.protocol} ${p.service ?? "unknown"}${p.product ? ` — ${p.product}${p.version ? ` ${p.version}` : ""}` : ""}`)
          }
        } else lines.push("open ports: none observed")
        if (result.osMatches.length) lines.push(`os guesses: ${result.osMatches.join("; ")}`)
        if (result.scriptOutput.length) lines.push(`nse output:\n${result.scriptOutput.map((s) => `  ${s}`).join("\n")}`)
      } else {
        lines.push("no XML output to parse; see raw evidence")
      }
      return lines.join("\n")
    }

    if (toolId === "nuclei") {
      const url = target.scheme ? args.target! : `https://${target.host}${target.port ? `:${target.port}` : ""}`
      const argv = buildNucleiArgs(url, intensity, args.severity as Severity[] | undefined)
      const run = await runArgv(bin, argv, { timeoutMs })
      const findings = parseNucleiJsonl(run.stdout)
      const ev = saveEvidence(root, { sessionID: c.sessionID, source: "nuclei", label: `nuclei ${url}`, target: target.host, content: run.stdout || run.stderr })
      const lines = [`nuclei ${url} — exit ${run.exitCode} in ${run.durationMs}ms, ${findings.length} template hits`]
      lines.push(`command: ${run.command}`)
      if (ev.record) lines.push(`raw evidence: ${ev.record.id}`)
      if (run.problems.length) lines.push(`problems: ${run.problems.join("; ")}`)
      for (const f of findings) {
        lines.push(`  [${f.severity}] ${f.templateId}: ${f.name} @ ${f.matchedAt}`)
        if (f.description) lines.push(`      ${f.description.slice(0, 300)}`)
        if (f.extracted?.length) lines.push(`      extracted: ${f.extracted.join(", ").slice(0, 300)}`)
      }
      if (!findings.length) lines.push("no template hits (this is not proof of absence — check coverage and limitations)")
      return lines.join("\n")
    }

    if (toolId === "nikto") {
      const port = target.port ?? (target.scheme === "http" ? 80 : 443)
      const { run, file } = await runWithTempfile(
        bin,
        (tmp) => ["-h", target.host, "-p", String(port), "-Format", "json", "-output", tmp, "-nointeractive", "-maxtime", "120s"],
        { timeoutMs },
      )
      const text = readTempfile(file)
      const items = parseNiktoJson(text)
      const ev = saveEvidence(root, { sessionID: c.sessionID, source: "nikto", label: `nikto ${target.host}:${port}`, target: target.host, content: text || run.stdout || run.stderr })
      const lines = [`nikto ${target.host}:${port} — exit ${run.exitCode} in ${run.durationMs}ms, ${items.length} items`]
      lines.push(`command: ${run.command}`)
      if (ev.record) lines.push(`raw evidence: ${ev.record.id}`)
      if (run.problems.length) lines.push(`problems: ${run.problems.join("; ")}`)
      for (const i of items.slice(0, 100)) lines.push(`  ${i.id}: ${i.msg}${i.url ? ` (${i.url})` : ""}`)
      if (!items.length) lines.push("no parseable nikto items; inspect raw evidence")
      return lines.join("\n")
    }

    if (toolId === "whatweb") {
      const url = target.scheme ? args.target! : `http://${target.host}${target.port ? `:${target.port}` : ""}`
      const run = await runArgv(bin, ["--log-json=-", "--no-errors", "-a", "1", url], { timeoutMs: Math.min(timeoutMs, 120000) })
      const hits = parseWhatWebJson(run.stdout)
      const ev = saveEvidence(root, { sessionID: c.sessionID, source: "whatweb", label: `whatweb ${url}`, target: target.host, content: run.stdout || run.stderr })
      const lines = [`whatweb ${url} — exit ${run.exitCode} in ${run.durationMs}ms`]
      if (ev.record) lines.push(`raw evidence: ${ev.record.id}`)
      for (const h of hits) lines.push(`  ${h.target}: ${Object.keys(h.plugins).join(", ")}`)
      if (!hits.length) lines.push("no parseable whatweb output")
      return lines.join("\n")
    }

    if (toolId === "sslscan") {
      const port = target.port ?? 443
      const run = await runArgv(bin, ["--no-colour", `${target.host}:${port}`], { timeoutMs: Math.min(timeoutMs, 180000) })
      const ev = saveEvidence(root, { sessionID: c.sessionID, source: "sslscan", label: `sslscan ${target.host}:${port}`, target: target.host, content: run.stdout || run.stderr })
      const interesting = run.stdout
        .split("\n")
        .filter((l) => /SSLv|TLSv|Accepted|Enabled|Certificate|Signature Algorithm|RSA Key|Expired|Self-signed/i.test(l))
        .slice(0, 80)
      return [
        `sslscan ${target.host}:${port} — exit ${run.exitCode} in ${run.durationMs}ms`,
        ev.record ? `raw evidence: ${ev.record.id}` : "",
        ...interesting.map((l) => `  ${l.trim()}`),
      ]
        .filter(Boolean)
        .join("\n")
    }

    // sqlmap: detection only; injection runs are intrusive and must be driven
    // deliberately by the operator through bash under intrusive policy.
    return [
      `sqlmap is installed at ${bin} but this adapter intentionally does not auto-run injection testing.`,
      "Injection testing is intrusive: request intrusive intensity in the engagement scope and drive it explicitly,",
      "or run it through bash (which is scope-guarded) with the operator's approval.",
    ].join("\n")
  },
})
