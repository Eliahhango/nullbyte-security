/**
 * Finding store: creation, validation, closure discipline, dedupe and severity.
 *
 * The store is a JSON document inside the engagement directory, so an
 * assessment is portable and reviewable without a database.
 *
 * Two properties matter more than the storage:
 *
 *  1. A finding's `status` is DERIVED, never asserted. The caller proposes a
 *     closure state; it is granted only when the supporting evidence is present.
 *     A model saying "confirmed" is not evidence, so an unproven claim is
 *     downgraded to `open_proof_gap` and the reason is recorded.
 *  2. Evidence references are checked against reality. A reference that the
 *     filesystem explicitly reports as absent contradicts the finding; a
 *     reference we merely could not read does not.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { randomUUID } from "node:crypto"
import { calculateCvss31, validateCvssBreakdown } from "./cvss31.ts"
import { ensureDir } from "./paths.ts"
import { redactSecrets } from "./redact.ts"
import { validateClosure, type ClosureState } from "./precision.ts"
import { verifyEvidenceRefs, MAX_EVIDENCE_REFS } from "./evidence-refs.ts"
import {
  SEVERITY_ORDER,
  type Finding,
  type FindingInput,
  type FindingStatus,
  type Severity,
  type FixEffort,
} from "./types.ts"

const STORE_VERSION = 1

/** Fields a caller may change. Lifecycle is derived; provenance is server-owned. */
export interface FindingChanges {
  title?: string
  description?: string
  impact?: string
  remediation?: string
  severity?: Severity
  confidence?: FindingInput["confidence"]
  verification?: FindingInput["verification"]
  limitations?: string
  evidence?: string
  reproduction?: string
  counterevidence?: string
  severity_change_conditions?: string
  assumptions?: string
  fix_effort?: FixEffort
  closure?: ClosureState
  demonstrated_by?: string
  ruled_out_by?: string
  ruled_out_at?: string
  /**
   * Operator-only lifecycle states. `confirmed` and `false-positive` are NOT
   * settable here — they are derived from closure, so they must be earned.
   */
  status_override?: Extract<FindingStatus, "remediated" | "accepted-risk">
}

/** Fields the store owns. A caller can never write these. */
export const PROTECTED_FIELDS = [
  "id",
  "sessionID",
  "created_at",
  "updated_at",
  "status",
  "closure",
  "severity",
  "cvss_score",
  "cvss_vector",
  "fingerprint",
  "evidence_check",
  "revision",
] as const

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

/** Deterministic dedupe fingerprint: normalized target|endpoint|method|cwe|title. */
export function createFindingFingerprint(input: {
  target: string
  endpoint?: string
  method?: string
  cwe?: string
  title: string
}): string {
  return [norm(input.target), norm(input.endpoint), norm(input.method), norm(input.cwe), norm(input.title)].join("|")
}

/* ------------------------------------------------------------- similarity --- */

const STOP_WORDS = new Set([
  "the", "and", "for", "with", "that", "this", "from", "into", "not", "are", "was", "were",
  "can", "may", "via", "use", "used", "using", "allows", "allow", "when", "which", "does",
  "any", "its", "his", "her", "their", "they", "you", "your", "our", "has", "have", "had",
])

function tokenize(value: string): Set<string> {
  return new Set(
    norm(value)
      .split(/[^a-z0-9]+/)
      .filter((t) => t.length > 2 && !STOP_WORDS.has(t)),
  )
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (!a.size || !b.size) return 0
  let intersection = 0
  for (const t of a) if (b.has(t)) intersection++
  return intersection / (a.size + b.size - intersection)
}

/** Above this, two findings are treated as the same underlying issue. */
export const SEMANTIC_DUPLICATE_THRESHOLD = 0.72
/** Above this (but below the duplicate threshold), surface a warning. */
export const SEMANTIC_SIMILAR_THRESHOLD = 0.45

export interface SemanticMatch {
  finding: Finding
  similarity: number
  duplicate: boolean
}

/**
 * Deterministic local similarity, the counterpart to HackerAI's model-based
 * comparison. No provider call: token overlap over title and description, gated
 * on the endpoint and CWE agreeing (or both being absent) so that a shared
 * symptom on a different surface is never merged.
 */
export function findSemanticMatches(root: string, input: FindingInput): SemanticMatch[] {
  const candidates = readStore(root).findings.filter(
    (f) => norm(f.endpoint) === norm(input.endpoint) && norm(f.cwe) === norm(input.cwe),
  )
  if (!candidates.length) return []
  const target = tokenize(`${input.title} ${input.description}`)
  return candidates
    .map((f) => ({ finding: f, similarity: jaccard(target, tokenize(`${f.title} ${f.description}`)), duplicate: false }))
    .filter((m) => m.similarity >= SEMANTIC_SIMILAR_THRESHOLD)
    .map((m) => ({ ...m, duplicate: m.similarity >= SEMANTIC_DUPLICATE_THRESHOLD }))
    .sort((a, b) => b.similarity - a.similarity)
}

/* ------------------------------------------------------------- validation --- */

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
  if (input.evidence_refs && input.evidence_refs.length > MAX_EVIDENCE_REFS) {
    problems.push(`at most ${MAX_EVIDENCE_REFS} evidence references`)
  }
  if (input.fix_effort && !["trivial", "low", "medium", "high"].includes(input.fix_effort)) {
    problems.push("fix_effort must be trivial|low|medium|high")
  }
  return { ok: problems.length === 0, problems }
}

/* ----------------------------------------------------------------- create --- */

export interface CreateOptions {
  /** project directory that relative evidence references resolve against */
  baseDir?: string
  /**
   * Scrub secret-like material from `evidence`, `reproduction` and
   * `counterevidence` on write. Defaults to false: the posture is full
   * disclosure, and a finding that quotes a leaked credential must keep it so
   * the report can reproduce it. Irreversible once written.
   */
  redactEvidence?: boolean
}

export interface CreateResult {
  finding?: Finding
  problems: string[]
  duplicateOf?: Finding
  /** "fingerprint" is a deterministic match; "semantic" is token similarity */
  duplicateReason?: "fingerprint" | "semantic"
  /** near-matches that were NOT treated as duplicates */
  similar?: SemanticMatch[]
  /** set when the requested closure was not granted */
  closureDowngraded?: boolean
  /** the closure that was requested, when it differs from the granted one */
  requestedClosure?: ClosureState
}

/**
 * Derive the lifecycle status from the closure state. This is the only place a
 * status is decided, so no caller can promote its own finding.
 */
export function deriveStatus(closure: ClosureState, override?: FindingChanges["status_override"]): FindingStatus {
  if (override === "remediated" || override === "accepted-risk") return override
  if (closure === "confirmed") return "confirmed"
  if (closure === "ruled_out") return "false-positive"
  return "open"
}

export function createFinding(root: string, sessionID: string, input: FindingInput, opts: CreateOptions = {}): CreateResult {
  const validation = validateFindingInput(input)
  if (!validation.ok) return { problems: validation.problems }

  // 1. deterministic duplicate — refuse, never merge silently
  const store = readStore(root)
  const fingerprint = createFindingFingerprint(input)
  const existing = store.findings.find((f) => f.fingerprint === fingerprint)
  if (existing) return { problems: [], duplicateOf: existing, duplicateReason: "fingerprint" }

  // 2. evidence references are checked against reality
  const refs = input.evidence_refs ?? []
  const refReport = refs.length ? verifyEvidenceRefs(root, opts.baseDir ?? root, refs) : undefined

  // 3. closure is granted only when the evidence supports the claim
  const requested: ClosureState = input.closure ?? "open_proof_gap"
  const verdict = validateClosure(
    {
      state: requested,
      demonstrated_by: input.demonstrated_by,
      ruled_out_by: input.ruled_out_by,
      ruled_out_at: input.ruled_out_at,
    },
    {
      hasReproduction: Boolean(input.reproduction?.trim()),
      hasVerifiedEvidence: Boolean(refReport?.verified.length),
      unverifiedEvidenceRefs: refReport?.missing.length ?? 0,
    },
  )

  // 4. local semantic duplicate — a separate flaw on a different surface is not merged
  const similar = findSemanticMatches(root, input)
  const semanticDuplicate = similar.find((m) => m.duplicate)
  if (semanticDuplicate) {
    return { problems: [], duplicateOf: semanticDuplicate.finding, duplicateReason: "semantic", similar }
  }

  let severity: Severity = input.severity ?? "info"
  let cvss_score: number | undefined
  let cvss_vector: string | undefined
  if (input.cvss_breakdown) {
    const cvss = calculateCvss31(input.cvss_breakdown)
    severity = cvss.severity
    cvss_score = cvss.score
    cvss_vector = cvss.vector
  }

  const scrub = (s: string | undefined) => (s && opts.redactEvidence ? redactSecrets(s) : s)
  const now = new Date().toISOString()
  const finding: Finding = {
    ...input,
    evidence: scrub(input.evidence),
    reproduction: scrub(input.reproduction),
    counterevidence: scrub(input.counterevidence),
    id: `F-${randomUUID().slice(0, 8)}`,
    sessionID,
    created_at: now,
    updated_at: now,
    closure: verdict.state,
    status: deriveStatus(verdict.state),
    severity,
    cvss_score,
    cvss_vector,
    fingerprint,
    evidence_check: refReport?.checked.map((c) => ({ ref: c.ref, state: c.state })),
    revision: 1,
    closure_downgraded: verdict.downgraded || undefined,
  }

  store.findings.push(finding)
  writeStore(root, store)

  return {
    finding,
    problems: verdict.downgraded ? verdict.problems : [],
    similar: similar.length ? similar : undefined,
    closureDowngraded: verdict.downgraded || undefined,
    requestedClosure: verdict.downgraded ? requested : undefined,
  }
}

/* ------------------------------------------------------------------- read --- */

export interface ListOptions {
  status?: FindingStatus
  closure?: ClosureState
  minSeverity?: Severity
  search?: string
  limit?: number
}

export function listFindings(root: string, opts: ListOptions = {}): Finding[] {
  const store = readStore(root)
  let out = store.findings
  if (opts.status) out = out.filter((f) => f.status === opts.status)
  if (opts.closure) out = out.filter((f) => f.closure === opts.closure)
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

/* ----------------------------------------------------------------- update --- */

export interface UpdateResult {
  finding?: Finding
  problems: string[]
  closureDowngraded?: boolean
  /** true when the update was refused because the revision moved */
  conflict?: boolean
  current?: Finding
}

export interface UpdateOptions {
  /** optimistic concurrency: refuse the write if the stored revision differs */
  expectedRevision?: number
  baseDir?: string
  /** scrub secret-like material from the updated fields; defaults to false */
  redactEvidence?: boolean
}

/**
 * Correct an existing finding.
 *
 * `changes` deliberately cannot carry `status`, `closure`, `severity`,
 * `fingerprint` or provenance: those are derived or store-owned. Lifecycle
 * moves only through closure (evidence-gated) or an explicit operator override
 * to `remediated`/`accepted-risk`.
 */
export function updateFinding(
  root: string,
  id: string,
  changes: FindingChanges,
  reason: string,
  opts: UpdateOptions = {},
): UpdateResult {
  if (!reason || !reason.trim()) return { problems: ["a reason is required for every finding update"] }

  const store = readStore(root)
  const idx = store.findings.findIndex((f) => f.id === id)
  if (idx === -1) return { problems: [`finding ${id} not found`] }
  const current = store.findings[idx]

  if (opts.expectedRevision !== undefined && opts.expectedRevision !== current.revision) {
    return {
      problems: [
        `conflict: expected revision ${opts.expectedRevision} but the stored finding is at revision ${current.revision}. Re-read it and retry.`,
      ],
      conflict: true,
      current,
    }
  }

  const problems: string[] = []
  const next: Finding = { ...current }
  let applied = false

  // report fields — freely correctable
  if (changes.title !== undefined) { next.title = changes.title; applied = true }
  if (changes.description !== undefined) { next.description = changes.description; applied = true }
  if (changes.impact !== undefined) { next.impact = changes.impact; applied = true }
  if (changes.remediation !== undefined) { next.remediation = changes.remediation; applied = true }
  if (changes.limitations !== undefined) { next.limitations = changes.limitations; applied = true }
  if (changes.confidence !== undefined) { next.confidence = changes.confidence; applied = true }
  if (changes.verification !== undefined) { next.verification = changes.verification; applied = true }
  if (changes.counterevidence !== undefined) { next.counterevidence = opts.redactEvidence ? redactSecrets(changes.counterevidence) : changes.counterevidence; applied = true }
  if (changes.severity_change_conditions !== undefined) { next.severity_change_conditions = changes.severity_change_conditions; applied = true }
  if (changes.assumptions !== undefined) { next.assumptions = changes.assumptions; applied = true }
  if (changes.fix_effort !== undefined) { next.fix_effort = changes.fix_effort; applied = true }
  if (changes.evidence !== undefined) { next.evidence = opts.redactEvidence ? redactSecrets(changes.evidence) : changes.evidence; applied = true }
  if (changes.reproduction !== undefined) { next.reproduction = opts.redactEvidence ? redactSecrets(changes.reproduction) : changes.reproduction; applied = true }
  if (changes.demonstrated_by !== undefined) { next.demonstrated_by = changes.demonstrated_by; applied = true }
  if (changes.ruled_out_by !== undefined) { next.ruled_out_by = changes.ruled_out_by; applied = true }
  if (changes.ruled_out_at !== undefined) { next.ruled_out_at = changes.ruled_out_at; applied = true }
  if (changes.status_override !== undefined) applied = true
  if (changes.closure !== undefined) applied = true
  if (changes.severity !== undefined) {
    // severity stays derivable from CVSS; an explicit value is allowed only without metrics
    if (current.cvss_breakdown) problems.push("severity is derived from cvss_breakdown and cannot be overridden; update the metrics instead")
    else { next.severity = changes.severity; applied = true }
  }

  // Nothing writable changed: refuse rather than churn a revision. This is what
  // makes a bare `status` write a no-op instead of a silent promotion attempt.
  if (!applied && !problems.length) {
    return { problems: ["no effective change: none of the supplied fields are writable (status and closure are derived)"] }
  }

  // closure is re-validated against the merged record, never taken on trust
  const requested: ClosureState = changes.closure ?? current.closure
  const refReport = next.evidence_refs?.length
    ? verifyEvidenceRefs(root, opts.baseDir ?? root, next.evidence_refs)
    : undefined
  const verdict = validateClosure(
    { state: requested, demonstrated_by: next.demonstrated_by, ruled_out_by: next.ruled_out_by, ruled_out_at: next.ruled_out_at },
    {
      hasReproduction: Boolean(next.reproduction?.trim()),
      hasVerifiedEvidence: Boolean(refReport?.verified.length),
      unverifiedEvidenceRefs: refReport?.missing.length ?? 0,
    },
  )
  next.closure = verdict.state
  next.closure_downgraded = verdict.downgraded || undefined
  if (refReport) next.evidence_check = refReport.checked.map((c) => ({ ref: c.ref, state: c.state }))
  next.status = deriveStatus(verdict.state, changes.status_override)

  if (problems.length) return { problems }

  next.updated_at = new Date().toISOString()
  next.revision = current.revision + 1
  next.fingerprint = createFindingFingerprint(next)
  store.findings[idx] = next
  writeStore(root, store)
  return {
    finding: next,
    problems: verdict.downgraded ? verdict.problems : [],
    closureDowngraded: verdict.downgraded || undefined,
  }
}

/** Severity histogram for reporting. */
export function severitySummary(findings: Finding[]): Record<Severity, number> {
  const base: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) base[f.severity]++
  return base
}

/** Closure histogram — how many findings are actually proven, and how many are not. */
export function closureSummary(findings: Finding[]): Record<ClosureState, number> {
  const base: Record<ClosureState, number> = { confirmed: 0, ruled_out: 0, open_proof_gap: 0 }
  for (const f of findings) base[f.closure]++
  return base
}

export function readAllFindings(root: string): Finding[] {
  return readStore(root).findings
}
