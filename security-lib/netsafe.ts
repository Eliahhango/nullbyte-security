/**
 * Network safety primitives: IP parsing, CIDR matching, and classification of
 * addresses that must never be touched (cloud metadata, link-local) regardless
 * of what the user scoped.
 *
 * Adapted from the guard posture in HackerAI's sandbox/authorization layer:
 * scope is validated at call time, and a small set of addresses is
 * unconditionally refused.
 */

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/** Addresses that must be denied even when a scope entry would match them. */
export const METADATA_HOSTNAMES = [
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
  "metadata",
]

export const METADATA_IPS = [
  "169.254.169.254", // AWS/GCP/Azure IMDS, OpenStack
  "169.254.170.2", // AWS ECS task metadata
  "100.100.100.200", // Alibaba Cloud
  "192.0.0.192", // Oracle Cloud
  "fd00:ec2::254", // AWS IMDS over IPv6
]

export function parseIpv4(s: string): number[] | null {
  const m = IPV4_RE.exec(s.trim())
  if (!m) return null
  const parts = m.slice(1, 5).map((x) => Number(x))
  if (parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null
  return parts
}

export function ipv4ToInt(parts: number[]): number {
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
}

export function intToIpv4(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".")
}

export function isIpv4(s: string): boolean {
  return parseIpv4(s) !== null
}

/** Very small IPv6 sanity check — enough to classify, not to fully validate. */
export function isIpv6(s: string): boolean {
  const v = s.trim()
  if (!v.includes(":")) return false
  return /^[0-9a-fA-F:%.]+$/.test(v)
}

export function isIp(s: string): boolean {
  return isIpv4(s) || isIpv6(s)
}

/** true when the string is `a.b.c.d/len` with a valid mask. */
export function parseCidrV4(s: string): { base: number; bits: number } | null {
  const [addr, lenStr] = s.split("/")
  if (lenStr === undefined) return null
  const parts = parseIpv4(addr)
  if (!parts) return null
  const bits = Number(lenStr)
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  return { base: (ipv4ToInt(parts) & mask) >>> 0, bits }
}

export function ipv4InCidr(ip: string, cidr: string): boolean {
  const parsed = parseCidrV4(cidr)
  const parts = parseIpv4(ip)
  if (!parsed || !parts) return false
  const mask = parsed.bits === 0 ? 0 : (0xffffffff << (32 - parsed.bits)) >>> 0
  return ((ipv4ToInt(parts) & mask) >>> 0) === parsed.base
}

export interface IpClass {
  loopback: boolean
  private: boolean
  linkLocal: boolean
  metadata: boolean
  multicast: boolean
  unspecified: boolean
  reserved: boolean
}

export function classifyIpv4(ip: string): IpClass | null {
  const parts = parseIpv4(ip)
  if (!parts) return null
  const n = ipv4ToInt(parts)
  const inRange = (cidr: string) => ipv4InCidr(ip, cidr)
  return {
    loopback: inRange("127.0.0.0/8"),
    private:
      inRange("10.0.0.0/8") ||
      inRange("172.16.0.0/12") ||
      inRange("192.168.0.0/16") ||
      inRange("100.64.0.0/10"), // CGNAT
    linkLocal: inRange("169.254.0.0/16"),
    metadata: METADATA_IPS.includes(ip),
    multicast: inRange("224.0.0.0/4"),
    unspecified: n === 0,
    reserved: inRange("240.0.0.0/4"),
  }
}

export function classifyIpv6(ip: string): IpClass | null {
  const v = ip.trim().toLowerCase()
  if (!isIpv6(v)) return null
  return {
    loopback: v === "::1",
    private: v.startsWith("fc") || v.startsWith("fd"), // ULA
    linkLocal: v.startsWith("fe80"),
    metadata: METADATA_IPS.includes(v),
    multicast: v.startsWith("ff"),
    unspecified: v === "::",
    reserved: false,
  }
}

export function classifyIp(ip: string): IpClass | null {
  return classifyIpv4(ip) ?? classifyIpv6(ip)
}

/**
 * Addresses refused regardless of scope. Metadata endpoints and link-local
 * space are the classic SSRF pivot points; we never allow them.
 */
export function isUnconditionallyDenied(host: string): { denied: boolean; reason?: string } {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "")
  if (METADATA_HOSTNAMES.includes(h)) {
    return { denied: true, reason: `cloud metadata hostname '${h}' is never permitted` }
  }
  const cls = classifyIp(h)
  if (cls?.metadata) {
    return { denied: true, reason: `cloud metadata address '${h}' is never permitted` }
  }
  if (cls?.linkLocal) {
    return { denied: true, reason: `link-local address '${h}' is never permitted` }
  }
  if (cls?.multicast || cls?.reserved || cls?.unspecified) {
    return { denied: true, reason: `address '${h}' is not a routable test target` }
  }
  return { denied: false }
}

export function isPrivateAddress(ip: string): boolean {
  const cls = classifyIp(ip)
  return !!(cls && (cls.private || cls.loopback))
}

/**
 * Extract the host from a URL-ish string without throwing.
 * Returns null when the string has no host at all.
 */
export function hostFromUrl(input: string): { host: string; port?: number; scheme?: string; path?: string } | null {
  const s = input.trim()
  if (!s) return null
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s) ? s : `http://${s}`
  try {
    const u = new URL(withScheme)
    if (!u.hostname) return null
    const port = u.port ? Number(u.port) : undefined
    return {
      host: u.hostname.replace(/^\[|\]$/g, ""),
      port,
      scheme: u.protocol.replace(":", ""),
      path: `${u.pathname}${u.search}`,
    }
  } catch {
    return null
  }
}
