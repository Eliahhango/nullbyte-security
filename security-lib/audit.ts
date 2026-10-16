/**
 * Append-only JSONL audit trail for every security-relevant tool decision.
 *
 * Ported from HackerAI's posture of keeping an explicit, inspectable record of
 * tool execution authorization. Never blocks the caller: audit failures are
 * reported but do not abort a tool.
 */

import { appendFileSync, existsSync, readFileSync } from "node:fs"
import { ensureDir } from "./paths.ts"
import { redactAndTruncate } from "./redact.ts"
import type { AuditRecord } from "./types.ts"

export function auditPath(root: string): string {
  return `${root}/audit.jsonl`
}

export function writeAudit(root: string, rec: Omit<AuditRecord, "ts"> & { ts?: string }): void {
  try {
    ensureDir(root)
    const full: AuditRecord = {
      ts: rec.ts ?? new Date().toISOString(),
      sessionID: rec.sessionID,
      agent: rec.agent,
      tool: rec.tool,
      decision: rec.decision,
      code: rec.code,
      reason: rec.reason,
      args: rec.args ? redactAndTruncate(rec.args, 2048) : undefined,
      targets: rec.targets,
    }
    appendFileSync(auditPath(root), `${JSON.stringify(full)}\n`, { mode: 0o600 })
  } catch {
    /* auditing must never break a tool call */
  }
}

export function readAudit(root: string, limit = 100): AuditRecord[] {
  const p = auditPath(root)
  if (!existsSync(p)) return []
  const lines = readFileSync(p, "utf8").split("\n").filter(Boolean)
  const slice = limit > 0 ? lines.slice(-limit) : lines
  const out: AuditRecord[] = []
  for (const l of slice) {
    try {
      out.push(JSON.parse(l) as AuditRecord)
    } catch {
      /* skip corrupt line */
    }
  }
  return out
}
