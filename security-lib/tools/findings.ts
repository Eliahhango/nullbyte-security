/**
 * sec_finding — create, list, inspect and correct findings.
 *
 * Two guarantees the model cannot talk its way around:
 *
 *  - `status` is DERIVED. The caller proposes a closure state and the store
 *    grants it only when the supporting evidence is actually present. An
 *    unproven "confirmed" is downgraded to `open_proof_gap`, not trusted.
 *  - `evidence_refs` are CHECKED. A reference the filesystem reports as absent
 *    contradicts the finding; one we merely could not read does not.
 *
 * Severity is derived from CVSS 3.1 base metrics when supplied, and a
 * deterministic fingerprint plus a local token-similarity check prevent the
 * same issue being filed repeatedly.
 */

import { tool } from "@opencode-ai/plugin"
import {
  createFinding,
  getFinding,
  listFindings,
  updateFinding,
  readAllFindings,
  severitySummary,
  closureSummary,
  type FindingChanges,
} from "../findings.ts"
import { CLOSURE_GUIDANCE } from "../precision.ts"
import { loadScope } from "../config.ts"
import { writeAudit } from "../audit.ts"
import type { FindingInput, Severity, VerificationStatus } from "../types.ts"
import type { ToolCtxLike } from "./shared.ts"

const SEV = ["info", "low", "medium", "high", "critical"] as const
const CONF = ["low", "medium", "high"] as const
const VERIF = ["unverified", "verified", "refuted", "inconclusive"] as const
const CLOSURE = ["confirmed", "ruled_out", "open_proof_gap"] as const
const EFFORT = ["trivial", "low", "medium", "high"] as const

const cvssShape = {
  attack_vector: tool.schema.enum(["N", "A", "L", "P"]).describe("N network, A adjacent, L local, P physical"),
  attack_complexity: tool.schema.enum(["L", "H"]).describe("L low, H high"),
  privileges_required: tool.schema.enum(["N", "L", "H"]).describe("N none, L low, H high"),
  user_interaction: tool.schema.enum(["N", "R"]).describe("N none, R required"),
  scope: tool.schema.enum(["U", "C"]).describe("U unchanged, C changed"),
  confidentiality: tool.schema.enum(["N", "L", "H"]),
  integrity: tool.schema.enum(["N", "L", "H"]),
  availability: tool.schema.enum(["N", "L", "H"]),
}

export const secFinding = tool({
  description:
    "Manage assessment findings. action=create records ONE distinct issue with its evidence and remediation; " +
    "action=list summarizes findings by severity and closure; action=get reads one; action=update corrects one (a reason " +
    "is required). Prefer supplying cvss_breakdown (the 8 CVSS 3.1 base metrics) over a hand-picked severity. " +
    CLOSURE_GUIDANCE +
    " Supply counterevidence and severity_change_conditions whenever you can — they are what make a finding reviewable. " +
    "Evidence is stored verbatim (the posture is full disclosure) and evidence_refs are verified to exist. Duplicate findings are refused.",
  args: {
    action: tool.schema.enum(["create", "list", "get", "update"]).describe("operation to perform"),
    title: tool.schema.string().optional().describe("short, specific finding title (create)"),
    description: tool.schema.string().optional().describe("what the issue is and how it was observed (create)"),
    impact: tool.schema.string().optional().describe("security impact in business terms (create)"),
    target: tool.schema.string().optional().describe("affected asset (create)"),
    endpoint: tool.schema.string().optional().describe("affected endpoint/URL path (create)"),
    method: tool.schema.string().optional().describe("HTTP method if applicable (create)"),
    source: tool.schema.string().optional().describe("which tool produced this (e.g. sec_recon, nuclei) (create)"),
    severity: tool.schema.enum(SEV).optional().describe("explicit severity; ignored when cvss_breakdown is supplied (create)"),
    cvss_breakdown: tool.schema.object(cvssShape).optional().describe("CVSS 3.1 base metrics (create)"),
    cve: tool.schema.string().optional().describe("CVE id if known (create)"),
    cwe: tool.schema.string().optional().describe("CWE id if known, e.g. CWE-79 (create)"),
    confidence: tool.schema.enum(CONF).optional().describe("how strong the evidence is (create)"),
    verification: tool.schema.enum(VERIF).optional().describe("descriptive verification note; does NOT set status (create)"),
    evidence: tool.schema.string().optional().describe("raw supporting evidence, stored verbatim (create)"),
    redact_evidence: tool.schema
      .boolean()
      .optional()
      .describe("scrub secret-like material from evidence/reproduction/counterevidence on write (default false — verbatim, irreversible)"),
    evidence_refs: tool.schema
      .array(tool.schema.string())
      .optional()
      .describe("sec_evidence ids (E-xxxxxxxx) or file paths (./src/auth.ts:42) backing this finding; each is verified to exist (create)"),
    reproduction: tool.schema.string().optional().describe("reproduction steps or PoC (create)"),
    remediation: tool.schema.string().optional().describe("specific, actionable remediation (create)"),
    limitations: tool.schema.string().optional().describe("limitations/assumptions; required when confidence is not high (create)"),
    closure: tool.schema.enum(CLOSURE).optional().describe(`proposed closure state (create/update). ${CLOSURE_GUIDANCE}`),
    demonstrated_by: tool.schema.string().optional().describe("closure=confirmed: what demonstrates the behaviour (create/update)"),
    ruled_out_by: tool.schema.string().optional().describe("closure=ruled_out: the specific control that makes it safe (create/update)"),
    ruled_out_at: tool.schema.string().optional().describe("closure=ruled_out: where that control lives or was observed (create/update)"),
    counterevidence: tool.schema.string().optional().describe("what would disprove this, and what you checked that did not (create/update)"),
    severity_change_conditions: tool.schema.string().optional().describe("conditions that would raise or lower the severity (create/update)"),
    assumptions: tool.schema.string().optional().describe("explicit assumptions this finding depends on (create/update)"),
    fix_effort: tool.schema.enum(EFFORT).optional().describe("expected remediation effort (create/update)"),
    id: tool.schema.string().optional().describe("finding id (get/update)"),
    reason: tool.schema.string().optional().describe("why this correction is being made (update)"),
    expected_revision: tool.schema.number().optional().describe("update: refuse the write if the stored revision differs (concurrency guard)"),
    status_override: tool.schema
      .enum(["remediated", "accepted-risk"])
      .optional()
      .describe("update: operator-only lifecycle state. confirmed/false-positive are earned via closure, not set here"),
    closure_filter: tool.schema.enum(CLOSURE).optional().describe("filter for action=list"),
    min_severity: tool.schema.enum(SEV).optional().describe("filter for action=list"),
    limit: tool.schema.number().optional().describe("max rows for action=list (default 50)"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const root = loadScope(c.worktree).paths.root
    const baseDir = c.directory || c.worktree

    if (args.action === "create") {
      const input: FindingInput = {
        title: args.title ?? "",
        description: args.description ?? "",
        impact: args.impact ?? "",
        target: args.target ?? "",
        endpoint: args.endpoint,
        method: args.method,
        source: args.source ?? "",
        severity: args.severity as Severity | undefined,
        cvss_breakdown: args.cvss_breakdown,
        cve: args.cve,
        cwe: args.cwe,
        confidence: (args.confidence ?? "low") as FindingInput["confidence"],
        verification: (args.verification ?? "unverified") as VerificationStatus,
        evidence: args.evidence ?? "",
        evidence_refs: args.evidence_refs,
        reproduction: args.reproduction,
        remediation: args.remediation ?? "",
        limitations: args.limitations,
        closure: args.closure,
        demonstrated_by: args.demonstrated_by,
        ruled_out_by: args.ruled_out_by,
        ruled_out_at: args.ruled_out_at,
        counterevidence: args.counterevidence,
        severity_change_conditions: args.severity_change_conditions,
        assumptions: args.assumptions,
        fix_effort: args.fix_effort,
      }
      const res = createFinding(root, c.sessionID, input, { baseDir, redactEvidence: args.redact_evidence === true })

      if (res.duplicateOf) {
        const how = res.duplicateReason === "semantic" ? "likely duplicate (similar wording and surface)" : "duplicate"
        return [
          `${how}: matches existing finding ${res.duplicateOf.id} ("${res.duplicateOf.title}", ${res.duplicateOf.severity}, closure ${res.duplicateOf.closure}).`,
          `Use action=update on ${res.duplicateOf.id} if it needs correcting, or add the detail that makes this a distinct flaw (different endpoint, method, CWE or root cause).`,
        ].join("\n")
      }
      if (!res.finding) return `finding rejected:\n${res.problems.map((p) => `  - ${p}`).join("\n")}`

      const f = res.finding
      const lines = [
        `recorded ${f.id}: ${f.title}`,
        `severity: ${f.severity}${f.cvss_score !== undefined ? ` (CVSS 3.1 ${f.cvss_score.toFixed(1)} ${f.cvss_vector})` : ""}`,
        `closure: ${f.closure}  status: ${f.status}  confidence: ${f.confidence}`,
        `target: ${f.target}${f.endpoint ? ` ${f.endpoint}` : ""}`,
      ]
      if (res.closureDowngraded) {
        lines.push("", `closure downgraded from '${res.requestedClosure}' to '${f.closure}':`)
        lines.push(...res.problems.map((p) => `  - ${p}`))
      }
      if (f.precision_notes?.length) {
        lines.push("", "precision checks:")
        lines.push(...f.precision_notes.map((n) => `  - ${n.class_id} (${n.trigger}): ${n.note}`))
      }
      const check = f.evidence_check
      if (check?.length) {
        lines.push("", `evidence refs: ${check.map((r) => `${r.ref}=${r.state}`).join(", ")}`)
        const absent = check.filter((r) => r.state === "missing")
        if (absent.length) {
          lines.push(`  warning: ${absent.map((r) => r.ref).join(", ")} did not resolve — a reference that does not exist is not evidence`)
        }
        const unchecked = check.filter((r) => r.state === "forbidden" || r.state === "unavailable")
        if (unchecked.length) {
          lines.push(`  note: ${unchecked.map((r) => r.ref).join(", ")} could not be read (permission or I/O) — not treated as absent`)
        }
      }
      if (res.similar?.length) {
        lines.push("", `similar existing findings (not merged): ${res.similar.map((s) => `${s.finding.id} ${(s.similarity * 100).toFixed(0)}%`).join(", ")}`)
      }
      writeAudit(root, {
        sessionID: c.sessionID,
        agent: c.agent,
        tool: "sec_finding",
        decision: "allow",
        code: "finding.create",
        reason: `recorded ${f.id} (${f.severity}, closure ${f.closure})`,
        args: f.id,
        targets: f.target ? [f.target] : undefined,
      })
      return lines.join("\n")
    }

    if (args.action === "list") {
      const all = readAllFindings(root)
      const rows = listFindings(root, {
        minSeverity: args.min_severity as Severity | undefined,
        closure: args.closure_filter,
        limit: args.limit ?? 50,
      })
      if (!rows.length) return all.length ? "no findings match the filter" : "no findings recorded yet"
      const counts = severitySummary(all)
      const closures = closureSummary(all)
      return [
        `findings: ${all.length} (critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info})`,
        `closure: confirmed ${closures.confirmed}, ruled_out ${closures.ruled_out}, open_proof_gap ${closures.open_proof_gap}`,
        "",
        ...rows.map(
          (f) =>
            `${f.id} [${f.severity}] ${f.title} — ${f.target}${f.endpoint ? f.endpoint : ""} (${f.status}/${f.closure}${f.closure_downgraded ? ", downgraded" : ""})`,
        ),
      ].join("\n")
    }

    if (args.action === "get") {
      if (!args.id) return "error: action=get requires id"
      const f = getFinding(root, args.id)
      if (!f) return `finding ${args.id} not found`
      return JSON.stringify(f, null, 2)
    }

    // update
    if (!args.id) return "error: action=update requires id"
    if (!args.reason) return "error: action=update requires a reason"
    const changes: FindingChanges = {}
    if (args.title) changes.title = args.title
    if (args.description) changes.description = args.description
    if (args.impact) changes.impact = args.impact
    if (args.remediation) changes.remediation = args.remediation
    if (args.severity) changes.severity = args.severity as Severity
    if (args.confidence) changes.confidence = args.confidence as FindingChanges["confidence"]
    if (args.verification) changes.verification = args.verification as VerificationStatus
    if (args.limitations) changes.limitations = args.limitations
    if (args.evidence) changes.evidence = args.evidence
    if (args.reproduction) changes.reproduction = args.reproduction
    if (args.closure) changes.closure = args.closure
    if (args.demonstrated_by) changes.demonstrated_by = args.demonstrated_by
    if (args.ruled_out_by) changes.ruled_out_by = args.ruled_out_by
    if (args.ruled_out_at) changes.ruled_out_at = args.ruled_out_at
    if (args.counterevidence) changes.counterevidence = args.counterevidence
    if (args.severity_change_conditions) changes.severity_change_conditions = args.severity_change_conditions
    if (args.assumptions) changes.assumptions = args.assumptions
    if (args.fix_effort) changes.fix_effort = args.fix_effort
    if (args.status_override) changes.status_override = args.status_override
    if (!Object.keys(changes).length) return "error: no fields to change were supplied"

    const res = updateFinding(root, args.id, changes, args.reason, {
      expectedRevision: args.expected_revision,
      baseDir,
      redactEvidence: args.redact_evidence === true,
    })
    if (res.conflict) {
      return `update refused: ${res.problems.join("; ")}\ncurrent: revision ${res.current?.revision}, closure ${res.current?.closure}, status ${res.current?.status}`
    }
    if (!res.finding) return `update rejected:\n${res.problems.map((p) => `  - ${p}`).join("\n")}`
    const lines = [
      `updated ${res.finding.id} (revision ${res.finding.revision}): ${res.finding.title} [${res.finding.severity}]`,
      `closure: ${res.finding.closure}  status: ${res.finding.status}`,
    ]
    if (res.closureDowngraded) {
      lines.push("", "closure downgraded:")
      lines.push(...res.problems.map((p) => `  - ${p}`))
    }
    if (res.finding.precision_notes?.length) {
      lines.push("", "precision checks:")
      lines.push(...res.finding.precision_notes.map((n) => `  - ${n.class_id} (${n.trigger}): ${n.note}`))
    }
    writeAudit(root, {
      sessionID: c.sessionID,
      agent: c.agent,
      tool: "sec_finding",
      decision: "allow",
      code: "finding.update",
      reason: `updated ${res.finding.id} to revision ${res.finding.revision}: ${args.reason}`,
      args: res.finding.id,
      targets: res.finding.target ? [res.finding.target] : undefined,
    })
    return lines.join("\n")
  },
})
