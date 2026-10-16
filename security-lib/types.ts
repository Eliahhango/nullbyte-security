/**
 * Shared types for the NullByte security capability layer.
 * Pure types + tiny helpers only; no runtime dependencies so this module is
 * importable from both the OpenCode (Bun) plugin runtime and Node's test runner.
 */

export type Intensity = "passive" | "safe-active" | "intrusive" | "exploit"

export type Severity = "info" | "low" | "medium" | "high" | "critical"

export type Confidence = "low" | "medium" | "high"

export type VerificationStatus = "unverified" | "verified" | "refuted" | "inconclusive"

export type FindingStatus = "open" | "confirmed" | "remediated" | "accepted-risk" | "false-positive"

/** A concrete network target derived from user input or tool output. */
export interface Target {
  /** hostname, IP literal, or CIDR as written */
  host: string
  port?: number
  scheme?: string
  path?: string
}

/** One authorized asset. `host` supports: exact host, `*.example.com`, IP, CIDR, or URL. */
export interface ScopeEntry {
  host: string
  /** when omitted the entry authorizes any port */
  ports?: number[]
  note?: string
}

export interface Scope {
  engagement: string
  authorized_by?: string
  /** ISO date the authorization was granted */
  authorized_at?: string
  /**
   * DEFAULT MODE. When true every target is authorized at every intensity and
   * no scope entry is required. The operator is the authorizer; this tool does
   * not gate work behind a scope ceremony. Set to false (plus an `include`
   * list) to switch on allow-list enforcement for engagements that need it.
   */
  authorized_all: boolean
  /** refuse unmistakably destructive local commands (rm -rf /, mkfs, dd to a device) */
  block_destructive: boolean
  include: ScopeEntry[]
  /** always wins over include; same grammar as include.host */
  exclude: string[]
  intensity: Intensity
  /** allow targets that resolve to RFC1918/loopback/ULA space (needed for local labs) */
  allow_private: boolean
  /** allow a model to write scope entries; default false, user-authored only */
  allow_model_scope_edit: boolean
  /** per-engagement override of destructive-operation approval */
  require_approval_for_intrusive: boolean
}

export interface Decision {
  allowed: boolean
  /** machine-readable code, e.g. scope.miss, policy.intensity, net.metadata */
  code: string
  /** human/model readable explanation */
  reason: string
  /** matched scope entry, when allowed */
  matched?: string
  /** true when the operation needs interactive approval even if in scope */
  requiresApproval?: boolean
  /** intensity class the operation was classified as */
  intensity?: Intensity
}

export interface AuditRecord {
  ts: string
  sessionID?: string
  agent?: string
  tool: string
  decision: "allow" | "deny" | "ask" | "error"
  code: string
  reason: string
  /** redacted, truncated representation of the arguments */
  args?: string
  targets?: string[]
}

export interface CvssBreakdown {
  attack_vector: "N" | "A" | "L" | "P"
  attack_complexity: "L" | "H"
  privileges_required: "N" | "L" | "H"
  user_interaction: "N" | "R"
  scope: "U" | "C"
  confidentiality: "N" | "L" | "H"
  integrity: "N" | "L" | "H"
  availability: "N" | "L" | "H"
}

export interface FindingInput {
  title: string
  description: string
  impact: string
  target: string
  endpoint?: string
  method?: string
  /** one of the sec_* tool names or a scanner id that produced the evidence */
  source: string
  severity?: Severity
  cvss_breakdown?: CvssBreakdown
  cve?: string
  cwe?: string
  confidence: Confidence
  verification: VerificationStatus
  evidence: string
  evidence_refs?: string[]
  reproduction?: string
  remediation: string
  limitations?: string
}

export interface Finding extends FindingInput {
  id: string
  sessionID: string
  created_at: string
  updated_at: string
  status: FindingStatus
  /** derived from CVSS when cvss_breakdown is present */
  severity: Severity
  cvss_score?: number
  cvss_vector?: string
  /** deterministic dedupe fingerprint */
  fingerprint: string
  /** ids of findings this one duplicates */
  duplicate_of?: string
  revision: number
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

export const INTENSITY_ORDER: Record<Intensity, number> = {
  passive: 0,
  "safe-active": 1,
  intrusive: 2,
  exploit: 3,
}

/** Clamp a value into the ordering of an intensity ladder. */
export function atLeastIntensity(configured: Intensity, required: Intensity): boolean {
  return INTENSITY_ORDER[configured] >= INTENSITY_ORDER[required]
}
