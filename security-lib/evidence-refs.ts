/**
 * Evidence reference verification.
 *
 * A finding is only as good as the artifact behind it, so references are
 * checked against reality instead of being taken on trust. Two reference forms
 * are accepted:
 *
 *   - `E-xxxxxxxx`  — an id in this engagement's evidence store
 *   - a file path   — absolute, or relative to the project root, optionally
 *                     suffixed with `:line` or `:line:col` (the file is checked,
 *                     not the line)
 *
 * Four outcomes, and the distinction matters:
 *
 *   exists      the artifact is really there
 *   missing     the filesystem said so explicitly (ENOENT / ENOTDIR)
 *   forbidden   we were not allowed to look (EACCES / EPERM)
 *   unavailable anything else (I/O error, bad output, timeout)
 *
 * Only `missing` contradicts a reference. A permission or transport failure is
 * `forbidden`/`unavailable` and must never be reported as absence, because that
 * would silently invalidate a finding that is actually sound.
 */

import { statSync } from "node:fs"
import { isAbsolute, resolve } from "node:path"
import { resolveEvidence } from "./evidence.ts"

export const MAX_EVIDENCE_REFS = 40
export const MAX_EVIDENCE_REF_LENGTH = 500

export type EvidenceRefState = "exists" | "missing" | "forbidden" | "unavailable"

export type EvidenceRefKind = "evidence-id" | "path" | "invalid"

export interface ClassifiedRef {
  ref: string
  kind: EvidenceRefKind
  /** filesystem path for kind=path, evidence id for kind=evidence-id */
  value?: string
  /** why it was rejected, for kind=invalid */
  reason?: string
}

export interface CheckedRef extends ClassifiedRef {
  state: EvidenceRefState
}

export interface EvidenceRefReport {
  checked: CheckedRef[]
  /** refs that resolved to a real artifact */
  verified: string[]
  /** refs that the filesystem explicitly reported as absent */
  missing: string[]
  /** refs we could not check (permission or I/O) — never treated as absent */
  unchecked: string[]
  /** refs rejected as malformed before any check */
  invalid: string[]
  /** true when nothing contradicts the references */
  ok: boolean
}

/**
 * Classify a reference. Rejects anything that is not a plain path or evidence id:
 * UNC prefixes, control characters, URL schemes and Windows drive letters are
 * not valid evidence references here.
 */
export function classifyEvidenceRef(raw: string): ClassifiedRef {
  const ref = (raw ?? "").trim()
  if (!ref) return { ref, kind: "invalid", reason: "empty reference" }
  if (ref.length > MAX_EVIDENCE_REF_LENGTH) {
    return { ref, kind: "invalid", reason: `longer than ${MAX_EVIDENCE_REF_LENGTH} characters` }
  }
  if (/^E-[0-9a-fA-F]{4,}$/.test(ref)) return { ref, kind: "evidence-id", value: ref }

  const body = ref.startsWith("file:") ? ref.slice(5) : ref
  if (!body) return { ref, kind: "invalid", reason: "empty path after file: prefix" }
  if (/[\x00-\x1f]/.test(body)) return { ref, kind: "invalid", reason: "contains control characters" }
  if (body.startsWith("//") || body.startsWith("\\\\")) {
    return { ref, kind: "invalid", reason: "UNC-style path is not a local artifact" }
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(body)) {
    return { ref, kind: "invalid", reason: "URLs are not evidence artifacts; store the response instead" }
  }
  if (/^[A-Za-z]:[\\/]/.test(body)) {
    return { ref, kind: "invalid", reason: "drive-letter paths are not supported" }
  }
  if (!ref.startsWith("file:") && !isAbsolute(body) && !/^\.\.?\//.test(body)) {
    return { ref, kind: "invalid", reason: "relative references must start with ./ or ../, or use file:" }
  }
  // file:src/auth.ts:42  →  check src/auth.ts
  const path = ref.startsWith("file:") ? body.replace(/(?::\d+(?::\d+)?|#L\d+(?:-L?\d+)?)$/, "") : body
  return { ref, kind: "path", value: path }
}

function classifyStatError(error: unknown): EvidenceRefState {
  const code = (error as { code?: unknown } | null)?.code
  if (code === "ENOENT" || code === "ENOTDIR") return "missing"
  if (code === "EACCES" || code === "EPERM") return "forbidden"
  return "unavailable"
}

/** Check one classified path reference against the filesystem. */
export function checkPathRef(baseDir: string, value: string): EvidenceRefState {
  const target = isAbsolute(value) ? value : resolve(baseDir, value)
  try {
    const info = statSync(target)
    return info.isFile() ? "exists" : "missing"
  } catch (error) {
    return classifyStatError(error)
  }
}

/**
 * Verify a set of evidence references.
 *
 * Never throws: an unreadable reference is `unchecked`, not a failure, so a
 * broken filesystem cannot invalidate an otherwise sound finding.
 */
export function verifyEvidenceRefs(
  engagementRoot: string,
  baseDir: string,
  refs: readonly string[],
): EvidenceRefReport {
  const unique = [...new Set((refs ?? []).map((r) => (r ?? "").trim()).filter(Boolean))]
  const checked: CheckedRef[] = []
  const verified: string[] = []
  const missing: string[] = []
  const unchecked: string[] = []
  const invalid: string[] = []

  const evidenceIds = unique.filter((r) => /^E-[0-9a-fA-F]{4,}$/.test(r))
  let foundIds = new Set<string>()
  if (evidenceIds.length) {
    try {
      foundIds = new Set(resolveEvidence(engagementRoot, evidenceIds).found.map((e) => e.id))
    } catch {
      foundIds = new Set()
    }
  }

  for (const raw of unique) {
    const classified = classifyEvidenceRef(raw)
    if (classified.kind === "invalid") {
      checked.push({ ...classified, state: "missing" })
      invalid.push(raw)
      continue
    }
    if (classified.kind === "evidence-id") {
      const state: EvidenceRefState = foundIds.has(classified.value!) ? "exists" : "missing"
      checked.push({ ...classified, state })
      ;(state === "exists" ? verified : missing).push(raw)
      continue
    }
    const state = checkPathRef(baseDir, classified.value!)
    checked.push({ ...classified, state })
    if (state === "exists") verified.push(raw)
    else if (state === "missing") missing.push(raw)
    else unchecked.push(raw)
  }

  return {
    checked,
    verified,
    missing,
    unchecked,
    invalid,
    ok: missing.length === 0 && invalid.length === 0,
  }
}

/** One-line summary for tool output and reports. */
export function summarizeEvidenceRefs(report: EvidenceRefReport): string {
  if (!report.checked.length) return "no evidence references supplied"
  const parts = [`${report.verified.length}/${report.checked.length} references resolved`]
  if (report.missing.length) parts.push(`unresolved: ${report.missing.join(", ")}`)
  if (report.unchecked.length) parts.push(`could not be checked (permission or I/O): ${report.unchecked.join(", ")}`)
  return parts.join("; ")
}
