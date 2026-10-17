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
import { readProtectedFile, writeProtectedFile } from "./secure-io.ts"
import { StoreKeyError } from "./crypto.ts"
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
    raw = readProtectedFile(p)!
  } catch (e: any) {
    // a missing key is not corruption: the index is intact, we cannot read it
    if (e instanceof StoreKeyError) throw e
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
  writeProtectedFile(indexPath(root), `${JSON.stringify(records, null, 2)}\n`)
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
  // the hash covers the plaintext payload, so it survives a re-encrypt; and with
  // encryption off that is still exactly the bytes on disk
  writeProtectedFile(join(dir, file), body)

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

/**
 * Thrown when a stored artifact does not match the hash recorded for it.
 *
 * The hash is the only thing that distinguishes evidence from a file someone
 * edited afterwards, so a mismatch is fatal rather than a warning: embedding it
 * in a report would launder an altered artifact into a formal deliverable.
 */
export class EvidenceIntegrityError extends Error {
  readonly id: string
  readonly path: string
  readonly expected: string
  readonly actual: string

  constructor(id: string, path: string, expected: string, actual: string) {
    super(
      `evidence ${id} at ${path} does not match the SHA-256 recorded for it ` +
        `(expected ${expected}, found ${actual}). The artifact has been modified or corrupted since ` +
        `it was stored, so it cannot be relied on as evidence. Re-capture it, or remove it from the ` +
        `findings that cite it.`,
    )
    this.name = "EvidenceIntegrityError"
    this.id = id
    this.path = path
    this.expected = expected
    this.actual = actual
  }
}

export type EvidenceIntegrity = "ok" | "modified" | "missing" | "unhashed"

export interface EvidenceVerification {
  id: string
  label: string
  target?: string
  /** ok | modified | missing | unhashed — see verifyEvidenceStore */
  state: EvidenceIntegrity
  expected?: string
  actual?: string
}

/** Re-hash one stored artifact and compare it against the recorded digest. */
export function verifyEvidence(root: string, id: string): EvidenceVerification {
  const rec = readIndex(root).find((r) => r.id === id)
  if (!rec) return { id, label: id, state: "missing" }

  const p = join(root, "evidence", rec.file)
  if (!existsSync(p)) return { id, label: rec.label, target: rec.target, state: "missing", expected: rec.sha256 }

  // decrypt first: the digest is over the artifact's content, not its encoding
  const actual = createHash("sha256").update(readProtectedFile(p)!).digest("hex")
  if (!rec.sha256) return { id, label: rec.label, target: rec.target, state: "unhashed", actual }
  return {
    id,
    label: rec.label,
    target: rec.target,
    state: actual === rec.sha256 ? "ok" : "modified",
    expected: rec.sha256,
    actual,
  }
}

/**
 * Verify every artifact in the store. Cheap enough to run on demand: the store
 * is bounded by the evidence limit, and this is the check that decides whether
 * the evidence base can be trusted at all.
 */
export function verifyEvidenceStore(root: string): EvidenceVerification[] {
  return readIndex(root).map((r) => verifyEvidence(root, r.id))
}

/** True when every artifact verifies. */
export function storeIntegrityOk(root: string): boolean {
  return verifyEvidenceStore(root).every((v) => v.state === "ok")
}

export function readEvidence(root: string, id: string): string | undefined {
  const rec = readIndex(root).find((r) => r.id === id)
  if (!rec) return undefined
  const p = join(root, "evidence", rec.file)
  if (!existsSync(p)) return undefined

  const text = readProtectedFile(p)!
  // verify BEFORE returning: an artifact that fails its hash must never reach a
  // report, or the deliverable launders an altered file as evidence
  if (rec.sha256) {
    const actual = createHash("sha256").update(text).digest("hex")
    if (actual !== rec.sha256) throw new EvidenceIntegrityError(id, p, rec.sha256, actual)
  }
  return text
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
