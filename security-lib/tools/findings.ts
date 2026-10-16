/**
 * sec_finding — create, list, inspect and correct findings.
 *
 * Severity is derived from CVSS 3.1 base metrics when supplied (the model only
 * provides the eight metrics), and a deterministic fingerprint prevents the same
 * issue being filed repeatedly.
 */

import { tool } from "@opencode-ai/plugin"
import { createFinding, getFinding, listFindings, updateFinding, readAllFindings, severitySummary } from "../findings.ts"
import { loadScope } from "../config.ts"
import type { FindingInput, Severity, VerificationStatus } from "../types.ts"
import type { ToolCtxLike } from "./shared.ts"

const SEV = ["info", "low", "medium", "high", "critical"] as const
const CONF = ["low", "medium", "high"] as const
const VERIF = ["unverified", "verified", "refuted", "inconclusive"] as const
const STATUS = ["open", "confirmed", "remediated", "accepted-risk", "false-positive"] as const

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
    "action=list summarizes findings by severity; action=get reads one; action=update corrects one (a reason is required). " +
    "Prefer supplying cvss_breakdown (the 8 CVSS 3.1 base metrics) over a hand-picked severity — the score, vector and " +
    "severity band are computed from the metrics. Evidence is redacted for secrets on write. Duplicate fingerprints are refused.",
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
    verification: tool.schema.enum(VERIF).optional().describe("verification status (create)"),
    evidence: tool.schema.string().optional().describe("raw supporting evidence, redacted on write (create)"),
    evidence_refs: tool.schema.array(tool.schema.string()).optional().describe("sec_evidence ids supporting this finding (create)"),
    reproduction: tool.schema.string().optional().describe("reproduction steps (create)"),
    remediation: tool.schema.string().optional().describe("specific, actionable remediation (create)"),
    limitations: tool.schema.string().optional().describe("limitations/assumptions; required when confidence is not high (create)"),
    id: tool.schema.string().optional().describe("finding id (get/update)"),
    reason: tool.schema.string().optional().describe("why this correction is being made (update)"),
    status: tool.schema.enum(STATUS).optional().describe("new status (update)"),
    min_severity: tool.schema.enum(SEV).optional().describe("filter for action=list"),
    limit: tool.schema.number().optional().describe("max rows for action=list (default 50)"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const root = loadScope(c.worktree).paths.root

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
      }
      const res = createFinding(root, c.sessionID, input)
      if (res.duplicateOf) {
        return `duplicate: this matches existing finding ${res.duplicateOf.id} ("${res.duplicateOf.title}", ${res.duplicateOf.severity}). Use action=update on ${res.duplicateOf.id} if it needs correcting.`
      }
      if (!res.finding) return `finding rejected:\n${res.problems.map((p) => `  - ${p}`).join("\n")}`
      const f = res.finding
      return [
        `recorded ${f.id}: ${f.title}`,
        `severity: ${f.severity}${f.cvss_score !== undefined ? ` (CVSS 3.1 ${f.cvss_score.toFixed(1)} ${f.cvss_vector})` : ""}`,
        `status: ${f.status}  confidence: ${f.confidence}  verification: ${f.verification}`,
        `target: ${f.target}${f.endpoint ? ` ${f.endpoint}` : ""}`,
      ].join("\n")
    }

    if (args.action === "list") {
      const all = readAllFindings(root)
      const rows = listFindings(root, { minSeverity: args.min_severity as Severity | undefined, limit: args.limit ?? 50 })
      if (!rows.length) return all.length ? "no findings match the filter" : "no findings recorded yet"
      const counts = severitySummary(all)
      return [
        `findings: ${all.length} (critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info})`,
        "",
        ...rows.map((f) => `${f.id} [${f.severity}] ${f.title} — ${f.target}${f.endpoint ? f.endpoint : ""} (${f.status}, ${f.verification})`),
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
    const changes: Parameters<typeof updateFinding>[2] = {}
    if (args.title) changes.title = args.title
    if (args.description) changes.description = args.description
    if (args.impact) changes.impact = args.impact
    if (args.remediation) changes.remediation = args.remediation
    if (args.severity) changes.severity = args.severity as Severity
    if (args.status) changes.status = args.status as NonNullable<typeof changes.status>
    if (args.confidence) changes.confidence = args.confidence as NonNullable<typeof changes.confidence>
    if (args.verification) changes.verification = args.verification as VerificationStatus
    if (args.limitations) changes.limitations = args.limitations
    if (args.evidence) changes.evidence = args.evidence
    if (!Object.keys(changes).length) return "error: no fields to change were supplied"
    const res = updateFinding(root, args.id, changes, args.reason)
    if (!res.finding) return `update rejected:\n${res.problems.map((p) => `  - ${p}`).join("\n")}`
    return `updated ${res.finding.id} (revision ${res.finding.revision}): ${res.finding.title} [${res.finding.severity}]`
  },
})
