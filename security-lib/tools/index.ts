/**
 * Assembles every sec_* tool into the record the plugin registers.
 */

import { createSecAgents } from "./agents.ts"
import { secScope } from "./scope.ts"
import { secRecon, SEC_RECON_MINIMUM_INTENSITY } from "./recon.ts"
import { secPorts, SEC_PORTS_MINIMUM_INTENSITY } from "./ports.ts"
import { secScan, SEC_SCAN_MINIMUM_INTENSITY } from "./scan.ts"
import { secSast } from "./sast.ts"
import { secEvidence } from "./evidence.ts"
import { secFinding } from "./findings.ts"
import { secRetest } from "./retest.ts"
import { secReport } from "./report.ts"
import { secCoverage } from "./coverage.ts"
import { secThreatModel } from "./threat-model.ts"
import { secMethodology, secAudit } from "./knowledge.ts"
import type { AgentClient } from "../agents.ts"
import type { Intensity } from "../types.ts"

export const SECURITY_TOOL_IDS = [
  "sec_scope",
  "sec_agents",
  "sec_recon",
  "sec_ports",
  "sec_scan",
  "sec_sast",
  "sec_evidence",
  "sec_finding",
  "sec_coverage",
  "sec_threat_model",
  "sec_retest",
  "sec_report",
  "sec_methodology",
  "sec_audit",
] as const

export type SecurityToolId = (typeof SECURITY_TOOL_IDS)[number]

/**
 * Declared intensity floors for tools that reach the network. Kept here next to
 * the registry so a test can compare every entry instead of trusting a comment.
 */
export const NETWORK_INTENSITY_FLOORS = {
  sec_recon: SEC_RECON_MINIMUM_INTENSITY,
  sec_ports: SEC_PORTS_MINIMUM_INTENSITY,
  sec_scan: SEC_SCAN_MINIMUM_INTENSITY,
} as const satisfies Partial<Record<SecurityToolId, Intensity>>

export interface BuildSecurityToolsOptions {
  client?: AgentClient
}

export function buildSecurityTools(options: BuildSecurityToolsOptions = {}): Record<string, any> {
  return {
    sec_scope: secScope,
    sec_agents: createSecAgents(options.client),
    sec_recon: secRecon,
    sec_ports: secPorts,
    sec_scan: secScan,
    sec_sast: secSast,
    sec_evidence: secEvidence,
    sec_finding: secFinding,
    sec_coverage: secCoverage,
    sec_threat_model: secThreatModel,
    sec_retest: secRetest,
    sec_report: secReport,
    sec_methodology: secMethodology,
    sec_audit: secAudit,
  }
}
