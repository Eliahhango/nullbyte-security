/**
 * Evidence store.
 *
 * Tool output that supports a finding is persisted verbatim-ish (secrets are
 * redacted before it touches disk) and referenced by id, so reports can cite
 * reproducible artifacts instead of restating them from model memory.
 */

import { createHash, randomUUID } from "node:crypto"
import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { atomicWriteFile, atomicWriteJson } from "./atomic.ts"
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
  /** true when the content exceeded the store limit and was cut short */
  truncated?: boolean
  file: string
}

const MAX_EVIDENCE_BYTES = 256 * 1024

function indexPath(root: string): string {
  return join(root, "evidence", "index.json")
}

/**
 * Thrown when the evidence index exists but cannot be read.
 *
 * Fatal on purpose. `saveEvidence` reads the index, appends and rewrites it, so
 * an index that reads as empty is an index that the next save erases — orphaning
 * every artifact already stored and dropping them from the report.
 */
export class EvidenceIndexCorruptError extends Error {
  readonly path: string
  readonly detail: string

  constructor(path: string, detail: string) {
    super(
      `the evidence index at ${path} could not be read (${detail}). ` +
        `It has been left untouched and nothing was written — an unreadable index must never be ` +
        `overwritten, because that would orphan every artifact already stored. ` +
        `Inspect the file, repair or move it aside, then retry.`,
    )
    this.name = "EvidenceIndexCorruptError"
    this.path = path
    this.detail = detail
  }
}

function readIndex(root: string): EvidenceRecord[] {
  const p = indexPath(root)
  if (!existsSync(p)) return []

  let raw: string
  try {
    raw = readFileSync(p, "utf8")
  } catch (e: any) {
    throw new EvidenceIndexCorruptError(p, `unreadable: ${e?.message ?? e}`)
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (e: any) {
    throw new EvidenceIndexCorruptError(p, `not valid JSON: ${e?.message ?? e}`)
  }

  if (!Array.isArray(parsed)) throw new EvidenceIndexCorruptError(p, "the index is not an array")
  return parsed as EvidenceRecord[]
}

function writeIndex(root: string, records: EvidenceRecord[]): void {
  ensureDir(join(root, "evidence"))
  atomicWriteJson(indexPath(root), records)
}

export interface SaveEvidenceInput {
  sessionID: string
  source: string
  label: string
  content: string
  target?: string
  /**
   * Store secret-like material verbatim. Defaults to true: a leaked credential
   * is the artifact's whole value, and the operator's posture is full
   * disclosure. Pass false to redact at capture instead — irreversible.
   */
  includeSecrets?: boolean
}

export interface SaveEvidenceResult {
  record?: EvidenceRecord
  problems: string[]
}

export function saveEvidence(root: string, input: SaveEvidenceInput): SaveEvidenceResult {
  if (!input.content || !input.content.trim()) return { problems: ["evidence content is empty"] }
  if (!input.label?.trim()) return { problems: ["evidence label is required"] }

  const redactedText = input.includeSecrets === false ? redactSecrets(input.content) : input.content
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

  // Hash exactly what lands on disk, marker included. Hashing the in-memory text
  // instead would make the recorded hash unverifiable for any artifact large
  // enough to be truncated — the check would report tampering on a file nobody
  // had touched.
  const body = truncated ? `${text}\n...[truncated by evidence store]...\n` : text
  atomicWriteFile(join(dir, file), body)

  const record: EvidenceRecord = {
    id,
    sha256: createHash("sha256").update(body).digest("hex"),
    sessionID: input.sessionID,
    source: input.source,
    label: input.label,
    target: input.target,
    created_at: new Date().toISOString(),
    bytes: Buffer.byteLength(text, "utf8"),
    redacted: wasRedacted,
    truncated,
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
