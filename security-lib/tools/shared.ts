/**
 * Shared plumbing for the sec_* tools: scope loading, enforcement, audit and
 * result formatting.
 *
 * Every network-touching tool funnels through `enforce()` so the authorization
 * decision is identical whether it comes from a direct tool call or from the
 * `tool.execute.before` hook guarding bash/webfetch.
 */

import { loadScope, type LoadedScope } from "../config.ts"
import { authorize, authorizeResolved, describeScope } from "../scope.ts"
import { resolveAddresses } from "../net/dns.ts"
import { isIp } from "../netsafe.ts"
import { writeAudit } from "../audit.ts"
import type { Decision, Intensity, Target } from "../types.ts"

export interface ToolCtxLike {
  sessionID: string
  agent: string
  directory: string
  worktree: string
  abort?: AbortSignal
  metadata?: (input: { title?: string; metadata?: Record<string, unknown> }) => void
  ask?: (input: { permission: string; patterns: string[]; always: string[]; metadata: Record<string, unknown> }) => Promise<void>
}

export class SecurityDenied extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(`[sec] ${message}`)
    this.name = "SecurityDenied"
    this.code = code
  }
}

export function scopeFor(worktree: string): LoadedScope {
  return loadScope(worktree)
}

function fail(ctx: ToolCtxLike, root: string, tool: string, decision: Decision, target: Target): never {
  writeAudit(root, {
    sessionID: ctx.sessionID,
    agent: ctx.agent,
    tool,
    decision: "deny",
    code: decision.code,
    reason: decision.reason,
    args: `${target.host}${target.port ? `:${target.port}` : ""}`,
    targets: [target.host],
  })
  throw new SecurityDenied(decision.code, decision.reason)
}

export interface EnforceArgs {
  ctx: ToolCtxLike
  tool: string
  target: Target
  intensity: Intensity
  /** resolve the hostname and re-validate every address (default true) */
  resolve?: boolean
  purpose?: string
}

export interface EnforceResult {
  loaded: LoadedScope
  decision: Decision
}

/**
 * Authorize a target or throw. Performs DNS re-validation so a scoped name
 * cannot be used to reach out-of-scope or metadata infrastructure, and raises
 * an interactive approval request for intrusive operations.
 */
export async function enforce(args: EnforceArgs): Promise<EnforceResult> {
  const { ctx, tool, target, intensity } = args
  const loaded = scopeFor(ctx.worktree)
  const root = loaded.paths.root

  if (ctx.abort?.aborted) throw new SecurityDenied("aborted", "operation cancelled before it started")

  let decision = authorize(loaded.scope, target, intensity)
  if (decision.allowed && !loaded.scope.authorized_all && args.resolve !== false && !isIp(target.host)) {
    const ips = await resolveAddresses(target.host, 5000)
    if (ips.length) {
      const resolved = authorizeResolved(loaded.scope, target, ips)
      if (!resolved.allowed) decision = resolved
      else decision = { ...decision, reason: `${decision.reason} (resolves to ${ips.join(", ")})` }
    } else if (!loaded.scope.allow_private) {
      // cannot resolve: refuse rather than guess
      decision = { allowed: false, code: "dns.unresolved", reason: `'${target.host}' did not resolve; cannot confirm it stays inside scope` }
    }
  }

  if (!decision.allowed) fail(ctx, root, tool, decision, target)

  if (decision.requiresApproval) {
    writeAudit(root, {
      sessionID: ctx.sessionID,
      agent: ctx.agent,
      tool,
      decision: "ask",
      code: "policy.approval",
      reason: `${intensity} operation requires operator approval`,
      targets: [target.host],
    })
    if (!ctx.ask) {
      fail(
        ctx,
        root,
        tool,
        { allowed: false, code: "policy.no-approval-channel", reason: `'${intensity}' operations require approval but no approval channel is available in this context` },
        target,
      )
    }
    await ctx.ask({
      permission: "sec.intrusive",
      patterns: [`${tool}:${target.host}`],
      always: [],
      metadata: {
        tool,
        target: target.host,
        port: target.port,
        intensity,
        purpose: args.purpose ?? "intrusive security test",
      },
    })
  }

  writeAudit(root, {
    sessionID: ctx.sessionID,
    agent: ctx.agent,
    tool,
    decision: "allow",
    code: decision.code,
    reason: decision.reason,
    args: `${target.host}${target.port ? `:${target.port}` : ""}`,
    targets: [target.host],
  })

  return { loaded, decision }
}

export function scopeBanner(loaded: LoadedScope): string {
  return describeScope(loaded.scope, loaded.source, loaded.warnings)
}

/** Split a target string into host + optional port without touching the network. */
export function splitTarget(input: string): Target {
  const raw = input.trim()
  const urlMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/\s]+)(\/\S*)?$/.exec(raw)
  if (urlMatch) {
    const scheme = urlMatch[1].toLowerCase()
    const authority = urlMatch[2]
    const path = urlMatch[3]
    const [host, port] = authority.includes("]:")
      ? [authority.slice(1, authority.indexOf("]")), Number(authority.split("]:")[1])]
      : authority.includes(":") && !authority.includes("::")
        ? [authority.split(":")[0], Number(authority.split(":")[1])]
        : [authority, undefined]
    return { host, port: port && !Number.isNaN(port) ? port : undefined, scheme, path }
  }
  const m = /^\[(.+)\]:(\d+)$/.exec(raw)
  if (m) return { host: m[1], port: Number(m[2]) }
  const idx = raw.lastIndexOf(":")
  if (idx > 0 && /^\d{1,5}$/.test(raw.slice(idx + 1)) && !raw.includes("::")) {
    return { host: raw.slice(0, idx), port: Number(raw.slice(idx + 1)) }
  }
  return { host: raw }
}

export function defaultPortFor(scheme: string | undefined, target: Target): number {
  if (target.port) return target.port
  if (scheme === "https") return 443
  if (scheme === "http") return 80
  return 443
}

export function bullet(lines: string[]): string {
  return lines.filter(Boolean).join("\n")
}
