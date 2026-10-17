/**
 * Assembles every sec_* tool into the record the plugin registers.
 */

import { secScope } from "./scope.ts"
import { secRecon } from "./recon.ts"
import { secPorts } from "./ports.ts"
import { secScan } from "./scan.ts"
import { secSast } from "./sast.ts"
import { secEvidence } from "./evidence.ts"
import { secFinding } from "./findings.ts"
import { secRetest } from "./retest.ts"
import { secReport } from "./report.ts"
import { secMethodology, secAudit } from "./knowledge.ts"

export const SECURITY_TOOL_IDS = [
  "sec_scope",
  "sec_recon",
  "sec_ports",
  "sec_scan",
  "sec_sast",
  "sec_evidence",
  "sec_finding",
  "sec_retest",
  "sec_report",
  "sec_methodology",
  "sec_audit",
] as const

export type SecurityToolId = (typeof SECURITY_TOOL_IDS)[number]

export function buildSecurityTools(): Record<string, any> {
  return {
    sec_scope: secScope,
    sec_recon: secRecon,
    sec_ports: secPorts,
    sec_scan: secScan,
    sec_sast: secSast,
    sec_evidence: secEvidence,
    sec_finding: secFinding,
    sec_retest: secRetest,
    sec_report: secReport,
    sec_methodology: secMethodology,
    sec_audit: secAudit,
  }
}
