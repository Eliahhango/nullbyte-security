/**
 * sec_recon — DNS, HTTP, TLS, header and technology reconnaissance.
 *
 * Passive by default: read-only requests that do not mutate target state.
 * Redirect hops are re-validated against scope inside the HTTP prober.
 */

import { tool } from "@opencode-ai/plugin"
import { dnsRecon } from "../net/dns.ts"
import { httpProbe } from "../net/http.ts"
import { tlsInspect } from "../net/tls.ts"
import { analyzeSecurityHeaders } from "../net/headers.ts"
import { fingerprint } from "../net/fingerprint.ts"
import { authorize } from "../scope.ts"
import { saveEvidence } from "../evidence.ts"
import { loadScope } from "../config.ts"
import { configureLimits, describeLimits, isPaced } from "../ratelimit.ts"
import { startProgress } from "../progress.ts"
import { enforce, splitTarget, type ToolCtxLike } from "./shared.ts"

const CHECKS = ["dns", "http", "tls", "headers", "fingerprint", "all"] as const

function fmtDns(r: Awaited<ReturnType<typeof dnsRecon>>): string {
  const lines = [`dns ${r.host} (${r.durationMs}ms)`]
  if (r.a.length) lines.push(`  A: ${r.a.join(", ")}`)
  if (r.aaaa.length) lines.push(`  AAAA: ${r.aaaa.join(", ")}`)
  if (r.cname.length) lines.push(`  CNAME: ${r.cname.join(", ")}`)
  if (r.mx.length) lines.push(`  MX: ${r.mx.map((m) => `${m.exchange}(${m.priority})`).join(", ")}`)
  if (r.ns.length) lines.push(`  NS: ${r.ns.join(", ")}`)
  if (r.txt.length) lines.push(`  TXT: ${r.txt.map((t) => t.join("")).join(" | ").slice(0, 1000)}`)
  if (r.ptr.length) lines.push(`  PTR: ${r.ptr.join(", ")}`)
  if (r.errors.length) lines.push(`  notes: ${r.errors.join("; ")}`)
  return lines.join("\n")
}

function fmtHeaders(a: ReturnType<typeof analyzeSecurityHeaders>): string {
  const lines = [`security headers grade: ${a.grade} (${a.score}/100)`]
  for (const c of a.checks) lines.push(`  [${c.status}] ${c.header}${c.value ? `: ${c.value}` : ""} — ${c.detail}`)
  if (a.cookies.length) {
    lines.push("  cookies:")
    for (const ck of a.cookies) lines.push(`    [${ck.status}] ${ck.name} — ${ck.detail}`)
  }
  return lines.join("\n")
}

function fmtTls(r: Awaited<ReturnType<typeof tlsInspect>>): string {
  if (!r.connected) return `tls ${r.host}:${r.port} — no handshake (${r.errors.join("; ") || "unknown error"})`
  const lines = [
    `tls ${r.host}:${r.port} (${r.durationMs}ms)`,
    `  protocol: ${r.protocol}  cipher: ${r.cipher}`,
    `  certificate trusted: ${r.authorized}${r.authorizationError ? ` (${r.authorizationError})` : ""}`,
  ]
  if (r.cert) {
    lines.push(`  subject: ${r.cert.subject}`)
    lines.push(`  issuer: ${r.cert.issuer}`)
    lines.push(`  validity: ${r.cert.validFrom} → ${r.cert.validTo}`)
    lines.push(`  days until expiry: ${r.daysUntilExpiry}${r.expired ? " (EXPIRED)" : r.expiringSoon ? " (expiring soon)" : ""}`)
    lines.push(`  self-signed: ${r.cert.selfSigned}  hostname mismatch: ${r.hostnameMismatch}`)
    if (r.cert.san.length) lines.push(`  SAN: ${r.cert.san.slice(0, 20).join(", ")}`)
    lines.push(`  sha256: ${r.cert.fingerprint256}`)
  }
  if (r.chain.length > 1) lines.push(`  chain length: ${r.chain.length}`)
  return lines.join("\n")
}

export const secRecon = tool({
  description:
    "Read-only reconnaissance against an AUTHORIZED target. Checks: dns (A/AAAA/CNAME/MX/NS/TXT/PTR), " +
    "http (status, headers, title, redirect chain — every hop re-validated against scope), " +
    "tls (protocol, cipher, certificate subject/issuer/validity/SAN, self-signed and expiry), " +
    "headers (security-header grading + cookie flags), fingerprint (technology detection with cited evidence), " +
    "or all. Passive: sends normal GET/HEAD requests and never mutates target state. " +
    "Out-of-scope targets are refused by the tool layer. The raw HTTP response is archived as an evidence artifact by " +
    "default and its id is returned, so a finding about a response can cite the response itself; pass archive=false to skip it.",
  args: {
    target: tool.schema.string().describe("authorized host, IP or URL (e.g. https://lab.local:8443)"),
    check: tool.schema.enum(CHECKS).describe("which reconnaissance to run"),
    port: tool.schema.number().optional().describe("override port for http/tls checks"),
    timeout_ms: tool.schema.number().optional().describe("per-request timeout in ms (default 10000)"),
    insecure: tool.schema.boolean().optional().describe("accept untrusted TLS certificates (authorized labs only)"),
    archive: tool.schema
      .boolean()
      .optional()
      .describe("save the raw HTTP response as an evidence artifact and return its id (default true for http checks); pass false for a probe you do not want in the store"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const target = splitTarget(args.target)
    const timeoutMs = Math.max(1000, Math.min(args.timeout_ms ?? 10000, 60000))
    const root = loadScope(c.worktree).paths.root

    await enforce({ ctx: c, tool: "sec_recon", target, intensity: "passive", purpose: `${args.check} reconnaissance` })

    const scheme = target.scheme ?? (target.port === 80 ? "http" : "https")
    const port = args.port ?? target.port ?? (scheme === "http" ? 80 : 443)
    const url = `${scheme}://${target.host}${port && port !== (scheme === "http" ? 80 : 443) ? `:${port}` : ""}${target.path ?? "/"}`
    const out: string[] = []

    const validateHop = (hopUrl: string) => {
      try {
        const u = new URL(hopUrl)
        const d = authorize(scope, { host: u.hostname, port: u.port ? Number(u.port) : undefined }, "passive")
        return { allowed: d.allowed, reason: d.reason }
      } catch {
        return { allowed: false, reason: "unparseable redirect target" }
      }
    }
    const scope = loadScope(c.worktree).scope
    const limits = configureLimits(scope.limits)

    const wantDns = args.check === "dns" || args.check === "all"
    const wantHttp = args.check === "http" || args.check === "headers" || args.check === "fingerprint" || args.check === "all"
    const wantTls = args.check === "tls" || args.check === "all"

    const progress = startProgress(`recon ${args.check} ${target.host}`, { timer: true })
    try {
      if (wantDns) {
        progress.update(`recon ${target.host} · resolving DNS`)
        out.push(fmtDns(await dnsRecon(target.host, { timeoutMs: Math.min(timeoutMs, 8000), reverse: true })))
      }

      if (wantHttp) {
        progress.update(`recon ${target.host} · probing HTTP`)
        const res = await httpProbe(url, { timeoutMs, insecure: args.insecure, validate: validateHop, allowBody: true })

        // Archive before reporting, so the artifact exists by the time the caller
        // cites it. A claim about a response is checkable only if the response was
        // kept: the summary below is already a lossy view of it.
        let archiveLine = ""
        if (res.transcript && args.archive !== false) {
          const saved = saveEvidence(root, {
            sessionID: c.sessionID,
            source: "sec_recon",
            label: `${args.check} ${res.finalUrl}`,
            content:
              `# sec_recon ${args.check} — ${res.requestedUrl}\n` +
              `# reconstructed transcript (headers preserved verbatim; body as decoded by the client)\n\n` +
              res.transcript,
            target: `${target.host}${port ? `:${port}` : ""}`,
          })
          archiveLine = saved.record
            ? `archived HTTP transcript: ${saved.record.id} (${saved.record.bytes} bytes, sha256 ${saved.record.sha256.slice(0, 16)}…)`
            : `HTTP transcript not archived: ${saved.problems.join("; ")}`
        }

        if (res.stopped) {
          out.push(`http: STOPPED at ${res.stopped.at} — ${res.stopped.reason}`)
        } else {
          const lines = [
            `http ${res.requestedUrl} → ${res.finalUrl}`,
            `  status: ${res.status} ${res.statusText}  (${res.durationMs}ms, ${res.bodyBytes} bytes)`,
          ]
          if (res.hops.length > 1) {
            lines.push(`  redirect chain:`)
            for (const hop of res.hops) lines.push(`    ${hop.status} ${hop.url}${hop.location ? ` → ${hop.location}` : ""}`)
          }
          if (res.title) lines.push(`  title: ${res.title}`)
          const interesting = ["server", "x-powered-by", "content-type", "strict-transport-security", "content-security-policy", "location", "set-cookie", "x-frame-options", "referrer-policy", "permissions-policy", "access-control-allow-origin"]
          lines.push("  headers:")
          for (const [k, v] of Object.entries(res.headers)) {
            if (interesting.includes(k.toLowerCase())) lines.push(`    ${k}: ${v.slice(0, 300)}`)
          }
          if (res.errors.length) lines.push(`  errors: ${res.errors.join("; ")}`)
          out.push(lines.join("\n"))

          if (args.check === "headers" || args.check === "all") {
            progress.update(`recon ${target.host} · grading headers`)
            out.push(fmtHeaders(analyzeSecurityHeaders(res.headers)))
          }
          if (args.check === "fingerprint" || args.check === "all") {
            progress.update(`recon ${target.host} · fingerprinting`)
            const hits = fingerprint({ headers: res.headers, body: res.bodySnippet ?? "", cookies: res.headers["set-cookie"] ?? "", url: res.finalUrl })
            out.push(
              hits.length
                ? `technologies:\n${hits.map((h) => `  - ${h.name} [${h.category}] confidence=${h.confidence} — ${h.evidence}`).join("\n")}`
                : "technologies: none detected from the observed response",
            )
          }
        }
        if (archiveLine) out.push(archiveLine)
      }

      if (wantTls) {
        progress.update(`recon ${target.host} · inspecting TLS`)
        out.push(fmtTls(await tlsInspect(target.host, port, { timeoutMs, insecure: args.insecure })))
      }

      c.metadata?.({ title: `sec_recon ${args.check} ${target.host}` })
      if (isPaced(limits)) out.push(`pacing: ${describeLimits()}`)
      progress.succeed(`recon ${args.check} ${target.host} complete`)
      return out.join("\n\n")
    } catch (error) {
      progress.fail(`recon ${args.check} ${target.host} failed`)
      throw error
    } finally {
      progress.stop()
    }
  },
})
