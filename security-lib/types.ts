/**
 * Shared types for the NullByte security capability layer.
 * Pure types + tiny helpers only; no runtime dependencies so this module is
 * importable from both the NullByte (Bun) plugin runtime and Node's test runner.
 */

export type Intensity = "passive" | "safe-active" | "intrusive" | "exploit"

export type Severity = "info" | "low" | "medium" | "high" | "critical"

export type Confidence = "low" | "medium" | "high"

export type VerificationStatus = "unverified" | "verified" | "refuted" | "inconclusive"

/**
 * Lifecycle status. DERIVED from the closure state and remediation, never set
 * directly by a caller: a model cannot promote its own finding to `confirmed`.
 * See `closure` below.
 */
export type FindingStatus = "open" | "confirmed" | "remediated" | "accepted-risk" | "false-positive"

/** How much work the fix is expected to be. */
export type FixEffort = "trivial" | "low" | "medium" | "high"

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
  /** 1-based position in the tamper-evident chain */
  seq?: number
  /** hash of the preceding record, or the genesis hash for the first */
  prev?: string
  /** sha256 over this record with `hash` omitted; see audit.ts */
  hash?: string
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

  // ---- closure discipline (see precision.ts) ----------------------------
  /**
   * The state the caller believes applies. It is a CLAIM: the recorded closure
   * is granted only if the supporting evidence is actually present, otherwise
   * it is downgraded to `open_proof_gap`.
   */
  closure?: ClosureState
  /** required for closure=confirmed: what demonstrates the behaviour */
  demonstrated_by?: string
  /** required for closure=ruled_out: the specific control that makes it safe */
  ruled_out_by?: string
  /** required for closure=ruled_out: where that control lives or was observed */
  ruled_out_at?: string

  // ---- report quality ---------------------------------------------------
  /** what would disprove this, and what was checked and did not */
  counterevidence?: string
  /** conditions that would raise or lower the severity */
  severity_change_conditions?: string
  /** explicit assumptions the finding depends on */
  assumptions?: string
  fix_effort?: FixEffort
}

/** The evidence-backed state of a finding. */
export type ClosureState = "confirmed" | "ruled_out" | "open_proof_gap"

/** Per-reference result of checking the finding's evidence against reality. */
export interface EvidenceRefCheck {
  ref: string
  state: "exists" | "missing" | "forbidden" | "unavailable" | "invalid"
}

/**
 * One re-execution of a finding's reproduction.
 *
 * Retests are appended, never overwritten: the point is a dated record of what
 * was checked and what it showed, so a finding that was confirmed and later
 * refuted carries both facts. `before`/`after` make the change explicit rather
 * than leaving it to be inferred from the current verification field.
 */
export interface RetestRecord {
  at: string
  /** who performed the retest */
  by: string
  /** how it was performed — a command, an HTTP request, a manual check */
  method: string
  /** the verification status the finding carried before this retest */
  before: VerificationStatus
  /** the status this retest establishes */
  after: VerificationStatus
  /** what was observed */
  observed: string
  command?: string
  /** evidence artifact captured by an action=run retest */
  evidence_id?: string
  exit_code?: number
  /** revision of the finding the retest was performed against */
  revision: number
  /** set when this retest contradicted the recorded closure, forcing a reopen */
  reopened?: boolean
}

export interface Finding extends FindingInput {
  id: string
  sessionID: string
  created_at: string
  updated_at: string
  /** DERIVED from closure + remediation; not caller-settable */
  status: FindingStatus
  /** the granted closure state (may differ from the requested one) */
  closure: ClosureState
  /** derived from CVSS when cvss_breakdown is present */
  severity: Severity
  cvss_score?: number
  cvss_vector?: string
  /** deterministic dedupe fingerprint */
  fingerprint: string
  /** ids of findings this one duplicates */
  duplicate_of?: string
  /** result of verifying evidence_refs against the filesystem/evidence store */
  evidence_check?: EvidenceRefCheck[]
  revision: number
  /** set when the closure claim was not granted */
  closure_downgraded?: boolean
  /** append-only history of reproduction re-checks, oldest first */
  retests?: RetestRecord[]
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
