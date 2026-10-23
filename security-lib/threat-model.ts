/**
 * Shared threat model — the reasoning that makes the rest of a test legible.
 *
 * A list of endpoints is not a threat model. The model records the target's
 * actors, trust boundaries, assets and the hypotheses worth testing. It is
 * written once, then amended as the assessment learns something; amendments are
 * kept rather than overwritten, so the final report shows how the model evolved.
 *
 * One model is shared by every agent working the same target. The store is keyed
 * by a normalized target (host or repository path) so two agents cannot create
 * slightly different models for the same asset.
 */

import { existsSync } from "node:fs"
import { homedir } from "node:os"
import { isAbsolute, join, resolve } from "node:path"
import { readProtectedFile, writeProtectedFile } from "./secure-io.ts"
import { hostOf } from "./report-selection.ts"

export interface ThreatModelAmendment {
  at: string
  by: string
  content: string
}

export interface ThreatModelEntry {
  /** canonical key; also returned so callers can show what was matched */
  key: string
  /** target as supplied by the operator */
  target: string
  content: string
  created_at: string
  updated_at: string
  updated_by: string
  revision: number
  amendments: ThreatModelAmendment[]
}

export interface ThreatModelStore {
  version: 1
  models: Record<string, ThreatModelEntry>
}

export interface ThreatModelSaveResult {
  entry?: ThreatModelEntry
  problems: string[]
}

const MAX_CONTENT = 32_000
const MAX_AMENDMENT = 8_000

function storePath(root: string): string {
  return join(root, "threat-models.json")
}

function emptyStore(): ThreatModelStore {
  return { version: 1, models: {} }
}

export class ThreatModelStoreCorruptError extends Error {
  readonly path: string
  readonly detail: string

  constructor(path: string, detail: string) {
    super(`threat model store is corrupt: ${path} (${detail})`)
    this.path = path
    this.detail = detail
  }
}

export function readThreatModelStore(root: string): ThreatModelStore {
  const path = storePath(root)
  if (!existsSync(path)) return emptyStore()
  const raw = readProtectedFile(path)
  if (raw === undefined) return emptyStore()
  try {
    const parsed = JSON.parse(raw) as ThreatModelStore
    if (!parsed || typeof parsed.models !== "object" || Array.isArray(parsed.models)) {
      throw new Error("missing models object")
    }
    return { version: 1, models: parsed.models }
  } catch (err) {
    throw new ThreatModelStoreCorruptError(path, err instanceof Error ? err.message : String(err))
  }
}

function writeStore(root: string, store: ThreatModelStore): void {
  writeProtectedFile(storePath(root), `${JSON.stringify(store, null, 2)}\n`)
}

function expandHome(path: string): string {
  if (path === "~") return homedir()
  if (path.startsWith("~/")) return join(homedir(), path.slice(2))
  return path
}

/**
 * Resolve a target to a stable key. URLs and bare hosts collapse to the host;
 * filesystem paths are made absolute. This is intentionally the same identity
 * the report and scope checks use, so "the same target" means one thing.
 */
export function threatModelKey(target: string, baseDir = process.cwd()): { key: string; target: string } {
  const raw = target.trim()
  const looksLikePath =
    /^(?:~|\.{1,2}\/|\/)/.test(raw) ||
    (!raw.includes("://") && raw.includes("/") && existsSync(resolve(baseDir, expandHome(raw))))
  if (looksLikePath) {
    const abs = isAbsolute(expandHome(raw)) ? expandHome(raw) : resolve(baseDir, expandHome(raw))
    return { key: `path:${abs}`, target: raw }
  }
  const host = hostOf(raw)
  return { key: `host:${host ?? raw.toLowerCase()}`, target: raw }
}

export function getThreatModel(root: string, target: string, baseDir = process.cwd()): ThreatModelEntry | undefined {
  const { key } = threatModelKey(target, baseDir)
  return readThreatModelStore(root).models[key]
}

export function listThreatModels(root: string): ThreatModelEntry[] {
  return Object.values(readThreatModelStore(root).models).sort((a, b) => a.target.localeCompare(b.target))
}

export function saveThreatModel(
  root: string,
  target: string,
  content: string,
  by = "unknown",
  baseDir = process.cwd(),
): ThreatModelSaveResult {
  const trimmed = content.trim()
  if (!trimmed) return { problems: ["content is required"] }
  if (trimmed.length > MAX_CONTENT) return { problems: [`content exceeds ${MAX_CONTENT} characters`] }

  const { key, target: displayTarget } = threatModelKey(target, baseDir)
  if (!displayTarget) return { problems: ["target is required"] }

  const store = readThreatModelStore(root)
  const existing = store.models[key]
  const now = new Date().toISOString()
  const entry: ThreatModelEntry = {
    key,
    target: displayTarget,
    content: trimmed,
    created_at: existing?.created_at ?? now,
    updated_at: now,
    updated_by: by.trim() || "unknown",
    revision: (existing?.revision ?? 0) + 1,
    amendments: [],
  }
  store.models[key] = entry
  writeStore(root, store)
  return { entry, problems: [] }
}

export function amendThreatModel(
  root: string,
  target: string,
  addendum: string,
  by = "unknown",
  baseDir = process.cwd(),
): ThreatModelSaveResult {
  const trimmed = addendum.trim()
  if (!trimmed) return { problems: ["addendum is required"] }
  if (trimmed.length > MAX_AMENDMENT) return { problems: [`addendum exceeds ${MAX_AMENDMENT} characters`] }

  const { key } = threatModelKey(target, baseDir)
  const store = readThreatModelStore(root)
  const entry = store.models[key]
  if (!entry) return { problems: [`no threat model exists for '${target}' — save one first`] }

  const now = new Date().toISOString()
  entry.amendments.push({ at: now, by: by.trim() || "unknown", content: trimmed })
  entry.updated_at = now
  entry.updated_by = by.trim() || "unknown"
  entry.revision += 1
  writeStore(root, store)
  return { entry, problems: [] }
}

/** Render a model (base + amendments) as one Markdown block. */
export function renderThreatModelMarkdown(entry: ThreatModelEntry): string {
  const lines = [
    `**Target:** \`${entry.target}\` (revision ${entry.revision}, updated ${entry.updated_at} by ${entry.updated_by})`,
    "",
    entry.content,
  ]
  if (entry.amendments.length) {
    lines.push("", "**Amendments**", "")
    entry.amendments.forEach((amendment, i) => {
      lines.push(`${i + 1}. ${amendment.at} — ${amendment.by}`, "", amendment.content, "")
    })
  }
  return lines.join("\n").trim()
}
