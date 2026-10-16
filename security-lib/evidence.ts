/**
 * Evidence store.
 *
 * Tool output that supports a finding is persisted verbatim-ish (secrets are
 * redacted before it touches disk) and referenced by id, so reports can cite
 * reproducible artifacts instead of restating them from model memory.
 */

import { createHash, randomUUID } from "node:crypto"
import { existsSync, readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { ensureDir } from "./paths.ts"
import { redactSecrets } from "./redact.ts"

export interface EvidenceRecord {
  id: string
  sha256: string
  sessionID: string
  /** tool that produced this evidence, e.g. sec_recon or nmap */
  source: string
  label: string
  target?: string
  created_at: string
  bytes: number
  /** true when secret-like material was removed before storage */
  redacted: boolean
  file: string
}

const MAX_EVIDENCE_BYTES = 256 * 1024

function indexPath(root: string): string {
  return join(root, "evidence", "index.json")
}

function readIndex(root: string): EvidenceRecord[] {
  const p = indexPath(root)
  if (!existsSync(p)) return []
  try {
    const parsed = JSON.parse(readFileSync(p, "utf8"))
    return Array.isArray(parsed) ? (parsed as EvidenceRecord[]) : []
  } catch {
    return []
  }
}

function writeIndex(root: string, records: EvidenceRecord[]): void {
  ensureDir(join(root, "evidence"))
  writeFileSync(indexPath(root), JSON.stringify(records, null, 2), { mode: 0o600 })
}

export interface SaveEvidenceInput {
  sessionID: string
  source: string
  label: string
  content: string
  target?: string
  /** store secret-like material unredacted (default false) */
  includeSecrets?: boolean
}

export interface SaveEvidenceResult {
  record?: EvidenceRecord
  problems: string[]
}

export function saveEvidence(root: string, input: SaveEvidenceInput): SaveEvidenceResult {
  if (!input.content || !input.content.trim()) return { problems: ["evidence content is empty"] }
  if (!input.label?.trim()) return { problems: ["evidence label is required"] }

  const redactedText = input.includeSecrets ? input.content : redactSecrets(input.content)
  const wasRedacted = redactedText !== input.content
  let text = redactedText
  let truncated = false
  if (Buffer.byteLength(text, "utf8") > MAX_EVIDENCE_BYTES) {
    text = Buffer.from(text, "utf8").subarray(0, MAX_EVIDENCE_BYTES).toString("utf8")
    truncated = true
  }

  const id = `E-${randomUUID().slice(0, 8)}`
  const file = `${id}.txt`
  const dir = ensureDir(join(root, "evidence"))
  writeFileSync(join(dir, file), truncated ? `${text}\n...[truncated by evidence store]...\n` : text, { mode: 0o600 })

  const record: EvidenceRecord = {
    id,
    sha256: createHash("sha256").update(text).digest("hex"),
    sessionID: input.sessionID,
    source: input.source,
    label: input.label,
    target: input.target,
    created_at: new Date().toISOString(),
    bytes: Buffer.byteLength(text, "utf8"),
    redacted: wasRedacted,
    file,
  }
  const index = readIndex(root)
  index.push(record)
  writeIndex(root, index)
  return { record, problems: [] }
}

export function listEvidence(root: string): EvidenceRecord[] {
  return readIndex(root)
}

export function readEvidence(root: string, id: string): string | undefined {
  const rec = readIndex(root).find((r) => r.id === id)
  if (!rec) return undefined
  const p = join(root, "evidence", rec.file)
  if (!existsSync(p)) return undefined
  return readFileSync(p, "utf8")
}

/** Resolve a set of evidence ids, reporting any that are missing. */
export function resolveEvidence(root: string, ids: string[]): { found: EvidenceRecord[]; missing: string[] } {
  const index = readIndex(root)
  const found: EvidenceRecord[] = []
  const missing: string[] = []
  for (const id of ids) {
    const rec = index.find((r) => r.id === id)
    if (rec) found.push(rec)
    else missing.push(id)
  }
  return { found, missing }
}
