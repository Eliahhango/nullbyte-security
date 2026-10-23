/**
 * Coverage ledger — the negative space of an assessment.
 *
 * Findings answer "what was wrong". They do not answer "what was tested and
 * found sound", "what was ruled out", or "what still needs a follow-up". Without
 * that record, an empty report is indistinguishable from an untested target, and
 * a later assessor repeats work or mistakes absence for safety.
 *
 * An entry is one surface × one risk area. Duplicate pairs are rejected rather
 * than silently merged: the analyst must update the existing entry with the
 * correct outcome. That keeps a single, reviewable history per surface instead of
 * a pile of contradictory observations.
 */

import { randomUUID } from "node:crypto"
import { join } from "node:path"
import { existsSync } from "node:fs"
import { atomicWriteFile } from "./atomic.ts"
import { readProtectedFile, writeProtectedFile } from "./secure-io.ts"
import { getFinding } from "./findings.ts"
import type { Finding } from "./types.ts"
import { hostOf } from "./report-selection.ts"

export const COVERAGE_OUTCOMES = [
  "reported",
  "no_issue_found",
  "ruled_out",
  "not_applicable",
  "needs_follow_up",
] as const

export type CoverageOutcome = (typeof COVERAGE_OUTCOMES)[number]

export interface CoverageEntry {
  id: string
  /** normalized target, when known */
  target?: string
  /** the concrete endpoint, parameter, component or file that was exercised */
  surface: string
  /** the class of weakness that was considered */
  risk_area: string
  outcome: CoverageOutcome
  /** why this outcome was reached; required when the outcome is not "reported" */
  evidence?: string
  /** linked finding id when outcome=reported */
  finding_id?: string
  /** agent/user that recorded the entry */
  recorded_by: string
  sessionID: string
  created_at: string
  updated_at: string
  revision: number
  history: CoverageRevision[]
}

export interface CoverageRevision {
  at: string
  by: string
  outcome: CoverageOutcome
  evidence?: string
  finding_id?: string
}

export interface CoverageInput {
  target?: string
  surface: string
  risk_area: string
  outcome: CoverageOutcome
  evidence?: string
  finding_id?: string
  recorded_by?: string
}

export interface CoverageRecordResult {
  entry?: CoverageEntry
  problems: string[]
  /** the existing entry when the same surface/risk pair was already recorded */
  existing?: CoverageEntry
}

export interface CoverageUpdateResult {
  entry?: CoverageEntry
  problems: string[]
}

export interface CoverageListOptions {
  outcome?: CoverageOutcome
  sessionID?: string
  host?: string
  search?: string
  limit?: number
}

export interface CoverageSummary {
  total: number
  by_outcome: Record<CoverageOutcome, number>
  /** entries that still need work */
  needs_follow_up: number
  /** findings with no linked coverage entry */
  findings_without_coverage: Array<{ id: string; title: string; target?: string; detail: string }>
  /** true when nothing at all was recorded */
  empty: boolean
}

export interface CoverageStore {
  version: 1
  entries: CoverageEntry[]
}

const MAX_SURFACE = 500
const MAX_RISK = 200
const MAX_TARGET = 1000
const MAX_EVIDENCE = 4000

const normalize = (s: string) => s.normalize("NFKC").trim().replace(/\s+/g, " ").toLowerCase()

function storePath(root: string): string {
  return join(root, "coverage.json")
}

function emptyStore(): CoverageStore {
  return { version: 1, entries: [] }
}

export class CoverageStoreCorruptError extends Error {
  readonly path: string
  readonly detail: string

  constructor(path: string, detail: string) {
    super(`coverage store is corrupt: ${path} (${detail})`)
    this.path = path
    this.detail = detail
  }
}

export function readCoverageStore(root: string): CoverageStore {
  const path = storePath(root)
  if (!existsSync(path)) return emptyStore()
  const raw = readProtectedFile(path)
  if (raw === undefined) return emptyStore()
  try {
    const parsed = JSON.parse(raw) as CoverageStore
    if (!parsed || !Array.isArray(parsed.entries)) throw new Error("missing entries array")
    return { version: 1, entries: parsed.entries }
  } catch (err) {
    throw new CoverageStoreCorruptError(path, err instanceof Error ? err.message : String(err))
  }
}

function writeStore(root: string, store: CoverageStore): void {
  writeProtectedFile(storePath(root), `${JSON.stringify(store, null, 2)}\n`)
}

function bareTarget(target: string | undefined): string | undefined {
  if (!target) return undefined
  const trimmed = target.trim()
  return trimmed || undefined
}

function coverageKey(target: string | undefined, surface: string, risk: string): string {
  return `${normalize(target ?? "")}\u0000${normalize(surface)}\u0000${normalize(risk)}`
}

function validate(input: CoverageInput): { problems: string[] } {
  const problems: string[] = []
  const surface = input.surface?.trim() ?? ""
  const risk = input.risk_area?.trim() ?? ""
  if (!surface) problems.push("surface is required")
  if (surface.length > MAX_SURFACE) problems.push(`surface exceeds ${MAX_SURFACE} characters`)
  if (!risk) problems.push("risk_area is required")
  if (risk.length > MAX_RISK) problems.push(`risk_area exceeds ${MAX_RISK} characters`)
  if (input.target && input.target.length > MAX_TARGET) problems.push(`target exceeds ${MAX_TARGET} characters`)
  if (input.evidence && input.evidence.length > MAX_EVIDENCE) problems.push(`evidence exceeds ${MAX_EVIDENCE} characters`)
  if (!COVERAGE_OUTCOMES.includes(input.outcome)) problems.push(`unknown outcome '${input.outcome}'`)

  if (input.outcome === "reported" && !input.finding_id?.trim()) {
    problems.push("outcome=reported requires finding_id")
  }
  if (input.outcome !== "reported" && input.finding_id?.trim()) {
    problems.push(`finding_id is only valid with outcome=reported (got '${input.outcome}')`)
  }
  if (input.outcome !== "reported" && !input.evidence?.trim()) {
    problems.push(`outcome=${input.outcome} requires evidence explaining the conclusion`)
  }

  return { problems }
}

export function recordCoverage(
  root: string,
  sessionID: string,
  input: CoverageInput,
): CoverageRecordResult {
  const { problems } = validate(input)
  if (problems.length) return { problems }

  const findingID = input.finding_id?.trim()
  if (findingID && !getFinding(root, findingID)) {
    return { problems: [`finding '${findingID}' does not exist`] }
  }

  const store = readCoverageStore(root)
  const target = bareTarget(input.target)
  const key = coverageKey(target, input.surface, input.risk_area)
  const existing = store.entries.find(
    (entry) => coverageKey(entry.target, entry.surface, entry.risk_area) === key,
  )
  if (existing) {
    return { problems: [], existing }
  }

  const now = new Date().toISOString()
  const entry: CoverageEntry = {
    id: `COV-${randomUUID().slice(0, 8)}`,
    ...(target ? { target } : {}),
    surface: input.surface.trim(),
    risk_area: input.risk_area.trim(),
    outcome: input.outcome,
    ...(input.evidence?.trim() ? { evidence: input.evidence.trim() } : {}),
    ...(findingID ? { finding_id: findingID } : {}),
    recorded_by: input.recorded_by?.trim() || "unknown",
    sessionID,
    created_at: now,
    updated_at: now,
    revision: 1,
    history: [
      {
        at: now,
        by: input.recorded_by?.trim() || "unknown",
        outcome: input.outcome,
        ...(input.evidence?.trim() ? { evidence: input.evidence.trim() } : {}),
        ...(findingID ? { finding_id: findingID } : {}),
      },
    ],
  }
  store.entries.push(entry)
  writeStore(root, store)
  return { entry, problems: [] }
}

export function updateCoverage(
  root: string,
  id: string,
  patch: Partial<CoverageInput> & { recorded_by?: string },
): CoverageUpdateResult {
  const store = readCoverageStore(root)
  const entry = store.entries.find((e) => e.id === id)
  if (!entry) return { problems: [`coverage entry '${id}' does not exist`] }

  const outcome = patch.outcome ?? entry.outcome
  const next: CoverageInput = {
    target: patch.target ?? entry.target,
    surface: patch.surface ?? entry.surface,
    risk_area: patch.risk_area ?? entry.risk_area,
    outcome,
    evidence: patch.evidence ?? entry.evidence,
    finding_id: patch.finding_id !== undefined ? patch.finding_id : outcome === "reported" ? entry.finding_id : undefined,
    recorded_by: patch.recorded_by,
  }
  const { problems } = validate(next)
  if (problems.length) return { problems }

  if (next.finding_id?.trim() && !getFinding(root, next.finding_id.trim())) {
    return { problems: [`finding '${next.finding_id}' does not exist`] }
  }

  const key = coverageKey(next.target, next.surface, next.risk_area)
  const collision = store.entries.find(
    (candidate) => candidate.id !== entry.id && coverageKey(candidate.target, candidate.surface, candidate.risk_area) === key,
  )
  if (collision) return { problems: [`another coverage entry already records this surface/risk pair: ${collision.id}`] }

  const by = patch.recorded_by?.trim() || "unknown"
  const now = new Date().toISOString()
  entry.target = bareTarget(next.target)
  entry.surface = next.surface.trim()
  entry.risk_area = next.risk_area.trim()
  entry.outcome = next.outcome
  entry.evidence = next.evidence?.trim() || undefined
  entry.finding_id = next.finding_id?.trim() || undefined
  entry.updated_at = now
  entry.revision += 1
  entry.history.push({
    at: now,
    by,
    outcome: entry.outcome,
    ...(entry.evidence ? { evidence: entry.evidence } : {}),
    ...(entry.finding_id ? { finding_id: entry.finding_id } : {}),
  })
  writeStore(root, store)
  return { entry, problems: [] }
}

export function listCoverage(root: string, opts: CoverageListOptions = {}): CoverageEntry[] {
  let entries = readCoverageStore(root).entries
  if (opts.outcome) entries = entries.filter((e) => e.outcome === opts.outcome)
  if (opts.sessionID) entries = entries.filter((e) => e.sessionID === opts.sessionID)
  if (opts.host) {
    const host = opts.host.toLowerCase()
    entries = entries.filter((e) => {
      const h = hostOf(e.target ?? e.surface)
      return h === host
    })
  }
  if (opts.search) {
    const needle = opts.search.toLowerCase()
    entries = entries.filter((e) =>
      [e.id, e.target, e.surface, e.risk_area, e.evidence, e.finding_id]
        .filter(Boolean)
        .some((value) => value!.toLowerCase().includes(needle)),
    )
  }
  const limit = Math.max(1, Math.min(opts.limit ?? 200, 1000))
  return entries.slice(-limit)
}

/** Coverage entries that belong to one report's scope. */
export function selectCoverage(
  entries: CoverageEntry[],
  opts: { sessionID?: string; host?: string } = {},
): CoverageEntry[] {
  return entries.filter((entry) => {
    if (opts.sessionID && entry.sessionID !== opts.sessionID) return false
    if (opts.host) {
      const host = hostOf(entry.target ?? entry.surface)
      if (host !== opts.host.toLowerCase()) return false
    }
    return true
  })
}

/**
 * Summarise what the ledger says, and what it still omits relative to findings.
 *
 * `findings_without_coverage` is deliberately conservative: a finding may be
 * linked by `finding_id` or matched on the same `surface`+`risk_area` pair. If
 * neither exists, the report says so rather than implying the ledger is complete.
 */
export function coverageSummary(entries: CoverageEntry[], findings: Finding[] = []): CoverageSummary {
  const by_outcome = Object.fromEntries(COVERAGE_OUTCOMES.map((o) => [o, 0])) as Record<CoverageOutcome, number>
  for (const entry of entries) by_outcome[entry.outcome] += 1

  const linked = new Set<string>()
  const pairs = new Set<string>()
  for (const entry of entries) {
    if (entry.finding_id) linked.add(entry.finding_id)
    pairs.add(coverageKey(entry.target, entry.surface, entry.risk_area))
  }

  const findings_without_coverage = findings
    .filter((f) => {
      if (linked.has(f.id)) return false
      const key = coverageKey(f.target, f.endpoint ?? f.target ?? f.title, f.cwe ?? f.title)
      return !pairs.has(key)
    })
    .map((f) => ({
      id: f.id,
      title: f.title,
      ...(f.target ? { target: f.target } : {}),
      detail: "finding has no linked coverage entry — the ledger may be incomplete",
    }))

  return {
    total: entries.length,
    by_outcome,
    needs_follow_up: by_outcome.needs_follow_up,
    findings_without_coverage,
    empty: entries.length === 0,
  }
}

/** Machine-readable sidecar; written next to the report when coverage exists. */
export function renderCoverageJson(entries: CoverageEntry[], findings: Finding[] = []): string {
  return `${JSON.stringify(
    {
      schema_version: 1,
      generated_at: new Date().toISOString(),
      summary: coverageSummary(entries, findings),
      entries,
    },
    null,
    2,
  )}\n`
}

/** Atomic write of the coverage sidecar. */
export function writeCoverageJson(path: string, entries: CoverageEntry[], findings: Finding[] = []): void {
  atomicWriteFile(path, renderCoverageJson(entries, findings))
}
