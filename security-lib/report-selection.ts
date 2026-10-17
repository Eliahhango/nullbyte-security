/**
 * Report data selection.
 *
 * A report must describe one scan session on one target. The findings store is
 * engagement-wide and append-only, so an unfiltered read silently absorbs every
 * earlier session's findings — including findings that belong to a different
 * host. That is the data-mixing failure this module exists to prevent.
 *
 * Selection is a filter, not a convenience: it runs before rendering, and what
 * it drops is reported rather than hidden.
 */

import { hostFromUrl } from "./netsafe.ts"
import type { EvidenceRecord } from "./evidence.ts"
import type { Finding } from "./types.ts"

export interface SelectionOptions {
  /** keep only records written by this scan session */
  sessionID?: string
  /** keep only records whose host matches this host */
  host?: string
  /** authorized-host predicate; records outside it are dropped */
  isAuthorized?: (host: string) => boolean
}

export interface SelectionDrops {
  /** findings from a different scan session */
  otherSession: number
  /** findings from a different host */
  otherHost: number
  /** findings on a host the scope does not authorize */
  outOfScope: number
  /** evidence records excluded by the same filters */
  evidence: number
}

export interface SelectionResult {
  findings: Finding[]
  evidence: EvidenceRecord[]
  drops: SelectionDrops
  /** hosts seen only in dropped findings, for the report's warning line */
  foreignHosts: string[]
}

/**
 * Best-effort host extraction from a finding's `target`, which may be a bare
 * host, `host:port`, or a full URL.
 */
export function hostOf(target: string | undefined | null): string | null {
  if (!target) return null
  const trimmed = target.trim()
  if (!trimmed) return null
  const parsed = hostFromUrl(trimmed)
  if (parsed?.host) return parsed.host.toLowerCase()
  return trimmed.toLowerCase()
}

function keepHost(host: string | null, opts: SelectionOptions): boolean {
  if (opts.host && host !== opts.host.toLowerCase()) return false
  if (opts.isAuthorized && host && !opts.isAuthorized(host)) return false
  return true
}

/**
 * Narrow an engagement-wide findings/evidence set to one report.
 *
 * The post-condition is the point: every finding returned is from the requested
 * session, on the requested host, inside the authorized scope. The final pass
 * re-asserts that rather than trusting the loop above.
 */
export function selectReportData(
  findings: Finding[],
  evidence: EvidenceRecord[],
  opts: SelectionOptions = {},
): SelectionResult {
  const drops: SelectionDrops = { otherSession: 0, otherHost: 0, outOfScope: 0, evidence: 0 }
  const foreign = new Set<string>()
  const kept: Finding[] = []

  for (const f of findings) {
    const host = hostOf(f.target)
    if (opts.sessionID && f.sessionID !== opts.sessionID) {
      drops.otherSession++
      foreign.add(host ?? f.target)
      continue
    }
    if (opts.host && host !== opts.host.toLowerCase()) {
      drops.otherHost++
      foreign.add(host ?? f.target)
      continue
    }
    if (opts.isAuthorized && host && !opts.isAuthorized(host)) {
      drops.outOfScope++
      foreign.add(host)
      continue
    }
    kept.push(f)
  }

  const keptEvidence = evidence.filter((e) => {
    if (opts.sessionID && e.sessionID !== opts.sessionID) {
      drops.evidence++
      return false
    }
    const host = hostOf(e.target)
    if ((opts.host || opts.isAuthorized) && host && !keepHost(host, opts)) {
      drops.evidence++
      return false
    }
    return true
  })

  // Re-assert the invariant. If a finding ever survived the filters without
  // matching the requested target, drop it here instead of shipping it.
  const verified = kept.filter((f) => {
    const host = hostOf(f.target)
    if (opts.host && host !== opts.host.toLowerCase()) {
      drops.otherHost++
      return false
    }
    if (opts.isAuthorized && host && !opts.isAuthorized(host)) {
      drops.outOfScope++
      return false
    }
    return true
  })

  return {
    findings: verified,
    evidence: keptEvidence,
    drops,
    foreignHosts: [...foreign].filter(Boolean).sort(),
  }
}

/** One-line summary of what selection excluded, or "" when nothing was. */
export function describeDrops(drops: SelectionDrops, foreignHosts: string[]): string {
  const parts: string[] = []
  if (drops.otherSession) parts.push(`${drops.otherSession} from another scan session`)
  if (drops.otherHost) parts.push(`${drops.otherHost} from another host`)
  if (drops.outOfScope) parts.push(`${drops.outOfScope} outside the authorized scope`)
  if (drops.evidence) parts.push(`${drops.evidence} evidence record(s)`)
  if (!parts.length) return ""
  const hosts = foreignHosts.length ? ` (hosts: ${foreignHosts.join(", ")})` : ""
  return `Excluded from this report: ${parts.join(", ")}${hosts}.`
}
