/**
 * Scope matching and the central authorization decision.
 *
 * Enforcement is deliberately synchronous and pure so it can be unit tested and
 * called from the `tool.execute.before` hook without I/O. DNS-dependent
 * validation (rebinding / resolved-IP checks) is a separate async step that
 * tools run before touching the network.
 */

import {
  hostFromUrl,
  ipv4InCidr,
  isIp,
  isPrivateAddress,
  isUnconditionallyDenied,
  parseCidrV4,
} from "./netsafe.ts"
import { atLeastIntensity, type Decision, type Intensity, type Scope, type Target } from "./types.ts"

/** Lowercase, strip scheme/path/port/brackets/trailing dot. */
export function normalizeHost(input: string): string {
  let h = (input ?? "").trim()
  if (!h) return ""
  const fromUrl = hostFromUrl(h)
  if (fromUrl && /:\/\//.test(h)) h = fromUrl.host
  return h
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "")
    .toLowerCase()
}

/** True when `host` is authorized by scope entry string `entry`. */
export function hostMatchesEntry(entry: string, host: string): boolean {
  const e = normalizeHost(entry)
  const h = normalizeHost(host)
  if (!e || !h) return false

  // CIDR entry: target must be a literal IPv4 inside the range
  if (parseCidrV4(e)) {
    return isIp(h) && ipv4InCidr(h, e)
  }

  // wildcard: subdomains only
  if (e.startsWith("*.")) {
    const suffix = e.slice(2)
    return h.endsWith(`.${suffix}`) && h !== suffix
  }

  // IP entry: exact only
  if (isIp(e)) return h === e

  // domain entry: the domain itself and any subdomain of it
  return h === e || h.endsWith(`.${e}`)
}

export interface AuthorizeOptions {
  /** skip the private-address refusal (used for already-validated resolutions) */
  skipPrivateCheck?: boolean
}

/**
 * Decide whether `target` may be touched at the requested intensity.
 * Order matters: unconditional denies, then excludes, then includes.
 */
export function authorize(
  scope: Scope,
  target: Target,
  requiredIntensity: Intensity,
  opts: AuthorizeOptions = {},
): Decision {
  const host = normalizeHost(target.host)
  if (!host) {
    return { allowed: false, code: "target.empty", reason: "no target host was provided" }
  }

  // 0. authorized-by-default: the operator is the authorizer, so there is no
  //    scope ceremony. Everything is permitted, at every intensity, unless the
  //    engagement explicitly switched on allow-list enforcement.
  if (scope.authorized_all) {
    return {
      allowed: true,
      code: "scope.authorized-all",
      reason: `'${host}' is permitted (authorized_all: the operator has authorized this work)`,
      matched: "*",
      requiresApproval: false,
      intensity: requiredIntensity,
    }
  }

  // 1. never-permitted addresses (metadata / link-local / non-routable)
  const denied = isUnconditionallyDenied(host)
  if (denied.denied) {
    return { allowed: false, code: "net.metadata", reason: denied.reason!, intensity: requiredIntensity }
  }

  // 2. explicit exclusions always win
  for (const ex of scope.exclude) {
    if (hostMatchesEntry(ex, host)) {
      return { allowed: false, code: "scope.excluded", reason: `'${host}' is explicitly excluded by '${ex}'`, intensity: requiredIntensity }
    }
  }

  // 3. private/loopback space requires explicit opt-in
  if (!opts.skipPrivateCheck && isIp(host) && isPrivateAddress(host) && !scope.allow_private) {
    return {
      allowed: false,
      code: "net.private",
      reason: `'${host}' is private/loopback space and allow_private is false`,
      intensity: requiredIntensity,
    }
  }

  // 4. must match an include entry
  let matched: string | undefined
  let portRestricted: number[] | undefined
  for (const entry of scope.include) {
    if (hostMatchesEntry(entry.host, host)) {
      matched = entry.host
      portRestricted = entry.ports
      break
    }
  }
  if (!matched) {
    return {
      allowed: false,
      code: "scope.miss",
      reason: `'${host}' is not covered by any authorized scope entry`,
      intensity: requiredIntensity,
    }
  }

  // 5. port must be inside the entry's allowance when the entry restricts ports
  if (portRestricted && target.port !== undefined && !portRestricted.includes(target.port)) {
    return {
      allowed: false,
      code: "scope.port",
      reason: `port ${target.port} on '${host}' is outside the authorized ports [${portRestricted.join(", ")}] for '${matched}'`,
      matched,
      intensity: requiredIntensity,
    }
  }

  // 6. intensity ceiling
  if (!atLeastIntensity(scope.intensity, requiredIntensity)) {
    return {
      allowed: false,
      code: "policy.intensity",
      reason: `operation needs '${requiredIntensity}' intensity but the engagement authorizes only '${scope.intensity}'`,
      matched,
      intensity: requiredIntensity,
    }
  }

  const requiresApproval =
    atLeastIntensity(requiredIntensity, "intrusive") && scope.require_approval_for_intrusive

  return {
    allowed: true,
    code: "scope.match",
    reason: `'${host}'${target.port ? `:${target.port}` : ""} is authorized by '${matched}'`,
    matched,
    requiresApproval,
    intensity: requiredIntensity,
  }
}

/**
 * The port allowance for `host`, if the matched include entry restricts ports.
 * Returns `undefined` when the host is unrestricted (or covered by an
 * `authorized_all` engagement). Used by scanners that would otherwise fall back
 * to an implicit default port set the operator never authorized.
 */
export function portAllowance(scope: Scope, host: string): number[] | undefined {
  if (scope.authorized_all) return undefined
  const h = normalizeHost(host)
  if (!h) return undefined
  for (const entry of scope.include) {
    if (hostMatchesEntry(entry.host, h)) return entry.ports
  }
  return undefined
}

/**
 * Authorize a *set* of ports on one host.
 *
 * The port scanner probes many ports on a single host, so `target.port` is
 * undefined and the per-entry port allowance in step 5 of `authorize` would
 * never be consulted. This closes that hole: every port is checked against the
 * matched entry, and the scan is refused if any port falls outside it.
 */
export function authorizePorts(
  scope: Scope,
  host: string,
  ports: readonly number[],
  requiredIntensity: Intensity,
): { allowed: boolean; decision: Decision; deniedPorts: number[] } {
  const deniedPorts: number[] = []
  let firstDeny: Decision | undefined
  let allowed: Decision | undefined

  for (const port of ports) {
    const d = authorize(scope, { host, port }, requiredIntensity)
    if (d.allowed) {
      allowed ??= d
    } else {
      deniedPorts.push(port)
      firstDeny ??= d
    }
  }

  if (firstDeny) {
    const listed = deniedPorts.slice(0, 8).join(", ")
    const more = deniedPorts.length > 8 ? ` and ${deniedPorts.length - 8} more` : ""
    return {
      allowed: false,
      deniedPorts,
      decision: {
        ...firstDeny,
        reason: `${deniedPorts.length} of ${ports.length} port(s) are outside scope (${listed}${more}). ${firstDeny.reason}`,
      },
    }
  }

  return {
    allowed: true,
    deniedPorts: [],
    decision: allowed ?? authorize(scope, { host }, requiredIntensity),
  }
}

/**
 * After resolving a hostname, re-check every resolved address. This closes the
 * DNS-rebinding / scope-laundering hole where a scoped name points at
 * out-of-scope or metadata infrastructure.
 */
export function authorizeResolved(
  scope: Scope,
  target: Target,
  resolvedIps: string[],
): Decision {
  if (scope.authorized_all) {
    return {
      allowed: true,
      code: "scope.authorized-all",
      reason: `'${target.host}' is permitted (authorized_all)`,
      matched: "*",
      requiresApproval: false,
    }
  }
  const base = authorize(scope, target, "passive", { skipPrivateCheck: true })
  if (!base.allowed) return base

  for (const ip of resolvedIps) {
    const denied = isUnconditionallyDenied(ip)
    if (denied.denied) {
      return { allowed: false, code: "net.metadata", reason: `${target.host} resolves to ${ip}: ${denied.reason}` }
    }
    if (isPrivateAddress(ip) && !scope.allow_private) {
      return { allowed: false, code: "net.private", reason: `${target.host} resolves to private address ${ip} and allow_private is false` }
    }
  }
  return base
}

/** Human/model readable summary of the active authorization. */
export function describeScope(scope: Scope, source: string, warnings: string[] = []): string {
  const lines: string[] = []
  lines.push(`engagement: ${scope.engagement}`)
  if (scope.authorized_by) lines.push(`authorized_by: ${scope.authorized_by}`)
  if (scope.authorized_at) lines.push(`authorized_at: ${scope.authorized_at}`)
  lines.push(
    scope.authorized_all
      ? "authorization: AUTHORIZED-ALL — every target is permitted, no scope entry required (default mode)"
      : "authorization: allow-list — only the include entries below are permitted",
  )
  lines.push(`intensity: ${scope.intensity}${scope.authorized_all ? " (unrestricted)" : ""}`)
  lines.push(`block_destructive: ${scope.block_destructive}`)
  lines.push(`allow_private: ${scope.allow_private}`)
  lines.push(`model_may_edit_scope: ${scope.allow_model_scope_edit}`)
  lines.push(`source: ${source}`)
  lines.push("include:")
  if (scope.include.length === 0) {
    lines.push(scope.authorized_all ? "  (not needed — authorized_all is on)" : "  (none — all network actions will be denied)")
  }
  for (const e of scope.include) {
    lines.push(`  - ${e.host}${e.ports ? ` ports=[${e.ports.join(",")}]` : ""}${e.note ? ` (${e.note})` : ""}`)
  }
  lines.push("exclude:")
  if (scope.exclude.length === 0) lines.push("  (none)")
  for (const e of scope.exclude) lines.push(`  - ${e}`)
  if (warnings.length) {
    lines.push("warnings:")
    for (const w of warnings) lines.push(`  ! ${w}`)
  }
  return lines.join("\n")
}
