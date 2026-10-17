/**
 * Append-only JSONL audit trail for every security-relevant tool decision.
 *
 * Ported from HackerAI's posture of keeping an explicit, inspectable record of
 * tool execution authorization.
 *
 * The trail is hash-chained: each record carries its 1-based `seq`, the hash of
 * the record before it, and its own hash over everything else. That turns the
 * record from a log into a control — editing or dropping a line in the middle is
 * detectable, and the report's coverage claims become checkable rather than
 * asserted. `readAudit` stays lenient for display; `verifyAudit` is the strict
 * checker.
 *
 * A write failure is fatal. The trail is load-bearing — report coverage and the
 * record of what was refused both derive from it — so silently continuing
 * without one is worse than stopping.
 */

import { closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs"
import { createHash } from "node:crypto"
import { ensureDir } from "./paths.ts"
import { redactAndTruncate } from "./redact.ts"
import type { AuditRecord } from "./types.ts"

/** `prev` value for the first record in the chain. */
export const AUDIT_GENESIS = "0".repeat(64)

export class AuditWriteError extends Error {
  readonly root: string
  readonly detail: string

  constructor(root: string, detail: string) {
    super(
      `the audit trail at ${root}/audit.jsonl could not be written (${detail}). ` +
        `The action was NOT recorded, so it has been refused rather than allowed unlogged. ` +
        `Fix the filesystem (permissions, free space) and retry.`,
    )
    this.name = "AuditWriteError"
    this.root = root
    this.detail = detail
  }
}

export class AuditCorruptError extends Error {
  readonly line: number

  constructor(path: string, line: number, detail: string) {
    super(
      `the audit trail at ${path} is unreadable at line ${line} (${detail}). ` +
        `Appending would fork the hash chain and make the record unverifiable, so nothing was written. ` +
        `Repair or move the file aside, then retry.`,
    )
    this.name = "AuditCorruptError"
    this.line = line
  }
}

export function auditPath(root: string): string {
  return `${root}/audit.jsonl`
}

/**
 * Canonical bytes for hashing: the record with `hash` removed, undefined values
 * dropped and the remaining keys sorted, so the digest depends neither on JSON
 * key order nor on keys that JSON.stringify would have omitted anyway — a parsed
 * record must hash to the same value as the object it was written from.
 */
export function auditRecordHash(rec: AuditRecord): string {
  const entries = Object.entries(rec)
    .filter(([k, v]) => k !== "hash" && v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return createHash("sha256").update(JSON.stringify(entries)).digest("hex")
}

/** The last parseable record, or undefined for an absent/empty trail. */
function lastRecord(root: string): AuditRecord | undefined {
  const p = auditPath(root)
  if (!existsSync(p)) return undefined
  const lines = readFileSync(p, "utf8").split("\n")
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i]!
    if (!line) continue
    try {
      return JSON.parse(line) as AuditRecord
    } catch (e: any) {
      throw new AuditCorruptError(p, i + 1, `not valid JSON: ${e?.message ?? e}`)
    }
  }
  return undefined
}

export function writeAudit(root: string, rec: Omit<AuditRecord, "ts"> & { ts?: string }): void {
  try {
    ensureDir(root)
  } catch (e: any) {
    throw new AuditWriteError(root, `cannot create the security directory: ${e?.message ?? e}`)
  }

  const prev = lastRecord(root)
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
    seq: (prev?.seq ?? 0) + 1,
    prev: prev?.hash ?? AUDIT_GENESIS,
  }
  full.hash = auditRecordHash(full)

  try {
    const fd = openSync(auditPath(root), "a", 0o600)
    try {
      writeSync(fd, `${JSON.stringify(full)}\n`)
      // durable before returning: a record that only reached the page cache is
      // not a record, and losing it silently is what this trail exists to prevent
      fsyncSync(fd)
    } finally {
      closeSync(fd)
    }
  } catch (e: any) {
    throw new AuditWriteError(root, e?.message ?? String(e))
  }
}

/** Lenient read for display. Corrupt lines are skipped; use verifyAudit to detect them. */
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

export interface AuditProblem {
  line: number
  kind: "unparseable" | "sequence" | "broken-link" | "altered"
  detail: string
}

export interface AuditVerification {
  records: number
  ok: boolean
  /** sha256 of the final record — a seal over the whole trail */
  head?: string
  problems: AuditProblem[]
  /** records written before chaining was added, which cannot be verified */
  unchained: number
}

/**
 * Recompute the chain from the start and report every break. Detects edits
 * (a record whose hash no longer matches), deletions and reordering (a `seq`
 * gap or a `prev` that points at the wrong hash), and partial writes.
 */
export function verifyAudit(root: string): AuditVerification {
  const p = auditPath(root)
  if (!existsSync(p)) return { records: 0, ok: true, problems: [], unchained: 0 }

  const lines = readFileSync(p, "utf8").split("\n").filter(Boolean)
  const problems: AuditProblem[] = []
  let expectedPrev = AUDIT_GENESIS
  let expectedSeq = 1
  let head: string | undefined
  let unchained = 0

  lines.forEach((line, i) => {
    const at = i + 1
    let rec: AuditRecord
    try {
      rec = JSON.parse(line) as AuditRecord
    } catch (e: any) {
      problems.push({ line: at, kind: "unparseable", detail: `not valid JSON: ${e?.message ?? e}` })
      return
    }

    // pre-chaining records: legible, but not verifiable
    if (rec.hash === undefined) {
      unchained++
      return
    }

    if (rec.seq !== expectedSeq) {
      problems.push({ line: at, kind: "sequence", detail: `seq ${rec.seq} where ${expectedSeq} was expected — records were dropped or reordered` })
    }
    if (rec.prev !== expectedPrev) {
      problems.push({
        line: at,
        kind: "broken-link",
        detail: `prev ${rec.prev?.slice(0, 16) ?? "missing"}… does not match the preceding record's hash ${expectedPrev.slice(0, 16)}…`,
      })
    }
    const recomputed = auditRecordHash(rec)
    if (recomputed !== rec.hash) {
      problems.push({ line: at, kind: "altered", detail: `record hash ${rec.hash.slice(0, 16)}… does not match its contents (${recomputed.slice(0, 16)}…)` })
    }

    head = rec.hash
    expectedPrev = rec.hash
    expectedSeq = (rec.seq ?? expectedSeq) + 1
  })

  return { records: lines.length, ok: problems.length === 0, head, problems, unchained }
}
