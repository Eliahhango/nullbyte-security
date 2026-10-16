/**
 * Finding store: creation, validation, normalization, deterministic dedupe and
 * severity derivation.
 *
 * Mirrors HackerAI's `create_vulnerability_report` / `list_reports` /
 * `get_report` / `update_vulnerability_report` surface, minus the database: the
 * store is a JSON document inside the engagement directory so an assessment is
 * portable and reviewable.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { randomUUID } from "node:crypto"
import { calculateCvss31, validateCvssBreakdown } from "./cvss31.ts"
import { ensureDir } from "./paths.ts"
import { redactSecrets } from "./redact.ts"
import { SEVERITY_ORDER, type Finding, type FindingInput, type FindingStatus, type Severity } from "./types.ts"

const STORE_VERSION = 1

interface Store {
  version: number
  findings: Finding[]
}

function storePath(root: string): string {
  return join(root, "findings.json")
}

function readStore(root: string): Store {
  const p = storePath(root)
  if (!existsSync(p)) return { version: STORE_VERSION, findings: [] }
  try {
    const parsed = JSON.parse(readFileSync(p, "utf8")) as Store
    if (!parsed || !Array.isArray(parsed.findings)) return { version: STORE_VERSION, findings: [] }
    return { version: parsed.version ?? STORE_VERSION, findings: parsed.findings }
  } catch {
    return { version: STORE_VERSION, findings: [] }
  }
}

function writeStore(root: string, store: Store): void {
  ensureDir(root)
  writeFileSync(storePath(root), JSON.stringify(store, null, 2), { mode: 0o600 })
}

function norm(v: string | undefined): string {
  return (v ?? "").normalize("NFKC").trim().toLowerCase().replace(/\s+/g, " ")
}

/**
 * Deterministic dedupe fingerprint. Same as HackerAI's
 * `createFindingDedupeKey`: normalized target|endpoint|method|cwe|title.
 */
export function createFindingFingerprint(input: {
  target: string
  endpoint?: string
  method?: string
  cwe?: string
  title: string
}): string {
  return [norm(input.target), norm(input.endpoint), norm(input.method), norm(input.cwe), norm(input.title)].join("|")
}

export interface ValidationResult {
  ok: boolean
  problems: string[]
}

/** Validate a finding payload before it is persisted. */
export function validateFindingInput(input: Partial<FindingInput>): ValidationResult {
  const problems: string[] = []
  const req: Array<[keyof FindingInput, number]> = [
    ["title", 200],
    ["description", 4000],
    ["impact", 4000],
    ["target", 1000],
    ["remediation", 8000],
    ["evidence", 16000],
  ]
  for (const [field, max] of req) {
    const v = input[field]
    if (typeof v !== "string" || !v.trim()) problems.push(`${field} is required and must be non-empty`)
    else if (v.length > max) problems.push(`${field} exceeds ${max} characters`)
  }
  if (!input.source || !String(input.source).trim()) problems.push("source is required (which tool produced this)")
  if (!input.confidence || !["low", "medium", "high"].includes(input.confidence)) {
    problems.push("confidence must be low|medium|high")
  }
  if (input.confidence && input.confidence !== "high" && !input.limitations?.trim()) {
    problems.push("limitations must explain the uncertainty when confidence is not high")
  }
  if (input.cvss_breakdown) problems.push(...validateCvssBreakdown(input.cvss_breakdown))
  if (input.cve && !/^CVE-\d{4}-\d{4,}$/.test(input.cve)) problems.push("cve must look like CVE-YYYY-NNNN")
  if (input.cwe && !/^CWE-\d+$/.test(input.cwe)) problems.push("cwe must look like CWE-NNN")
  if (!input.cvss_breakdown && !input.severity) {
    problems.push("provide either cvss_breakdown (preferred) or an explicit severity")
  }
  return { ok: problems.length === 0, problems }
}

export interface CreateResult {
  finding?: Finding
  problems: string[]
  duplicateOf?: Finding
}

/**
 * Create a finding. When a finding with the same fingerprint exists it is
 * returned as `duplicateOf` and the store is left untouched, which is the
 * deterministic half of HackerAI's two-layer dedupe.
 */
export function createFinding(root: string, sessionID: string, input: FindingInput): CreateResult {
  const validation = validateFindingInput(input)
  if (!validation.ok) return { problems: validation.problems }

  const store = readStore(root)
  const fingerprint = createFindingFingerprint(input)
  const existing = store.findings.find((f) => f.fingerprint === fingerprint)
  if (existing) return { problems: [], duplicateOf: existing }

  let severity: Severity = input.severity ?? "info"
  let cvss_score: number | undefined
  let cvss_vector: string | undefined
  if (input.cvss_breakdown) {
    const cvss = calculateCvss31(input.cvss_breakdown)
    severity = cvss.severity
    cvss_score = cvss.score
    cvss_vector = cvss.vector
  }

  const now = new Date().toISOString()
  const finding: Finding = {
    ...input,
    evidence: redactSecrets(input.evidence),
    reproduction: input.reproduction ? redactSecrets(input.reproduction) : undefined,
    id: `F-${randomUUID().slice(0, 8)}`,
    sessionID,
    created_at: now,
    updated_at: now,
    status: input.verification === "verified" ? "confirmed" : "open",
    severity,
    cvss_score,
    cvss_vector,
    fingerprint,
    revision: 1,
  }

  store.findings.push(finding)
  writeStore(root, store)
  return { finding, problems: [] }
}

export interface ListOptions {
  status?: FindingStatus
  minSeverity?: Severity
  search?: string
  limit?: number
}

export function listFindings(root: string, opts: ListOptions = {}): Finding[] {
  const store = readStore(root)
  let out = store.findings
  if (opts.status) out = out.filter((f) => f.status === opts.status)
  if (opts.minSeverity) out = out.filter((f) => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[opts.minSeverity!])
  if (opts.search) {
    const q = norm(opts.search)
    out = out.filter((f) => norm(`${f.title} ${f.target} ${f.endpoint ?? ""} ${f.description}`).includes(q))
  }
  out = [...out].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity])
  if (opts.limit && opts.limit > 0) out = out.slice(0, opts.limit)
  return out
}

export function getFinding(root: string, id: string): Finding | undefined {
  return readStore(root).findings.find((f) => f.id === id)
}

export interface UpdateResult {
  finding?: Finding
  problems: string[]
}

/** Correct an existing finding (HackerAI's update_vulnerability_report analogue). */
export function updateFinding(
  root: string,
  id: string,
  changes: Partial<Pick<Finding, "title" | "description" | "impact" | "remediation" | "severity" | "status" | "confidence" | "verification" | "limitations" | "evidence">>,
  reason: string,
): UpdateResult {
  if (!reason || !reason.trim()) return { problems: ["a reason is required for every finding update"] }
  const store = readStore(root)
  const idx = store.findings.findIndex((f) => f.id === id)
  if (idx === -1) return { problems: [`finding ${id} not found`] }

  const current = store.findings[idx]
  const next: Finding = { ...current, ...changes, updated_at: new Date().toISOString(), revision: current.revision + 1 }
  if (changes.evidence) next.evidence = redactSecrets(changes.evidence)
  next.fingerprint = createFindingFingerprint(next)

  store.findings[idx] = next
  writeStore(root, store)
  return { finding: next, problems: [] }
}

/** Severity histogram for reporting. */
export function severitySummary(findings: Finding[]): Record<Severity, number> {
  const base: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) base[f.severity]++
  return base
}

export function readAllFindings(root: string): Finding[] {
  return readStore(root).findings
}
