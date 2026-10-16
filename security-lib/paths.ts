/**
 * Engagement + global path resolution.
 *
 * Two layers:
 *  - CODE lives in the user's config dir (`~/.config/nullbyte/security-lib`).
 *  - ENGAGEMENT STATE lives with the project (`<worktree>/.nullbyte/security`)
 *    so an assessment is reviewable, resumable and exportable alongside the
 *    code it concerns. `NULLBYTE_SECURITY_DIR` overrides it.
 */

import { homedir } from "node:os"
import { join, resolve } from "node:path"
import { existsSync, mkdirSync } from "node:fs"

export const CONFIG_HOME = join(homedir(), ".config", "nullbyte")

/** Global (machine-wide) security policy file, user-authored. */
export function globalPolicyPath(): string {
  return process.env.NULLBYTE_SECURITY_POLICY ?? join(CONFIG_HOME, "security.json")
}

/**
 * The runtime project root, registered by the plugin at init.
 *
 * Why this exists: in a single-file CLI runtime `worktree` can resolve to the
 * filesystem root ("/") while `directory`/`cwd` hold the real project path.
 * Verified on this build: PluginInput.worktree === "/" and
 * ToolContext.worktree === "/", while PluginInput.directory === ToolContext.directory === cwd.
 * So we never trust `worktree` alone; we resolve a chain and skip "/".
 */
let RUNTIME_ROOT: string | null = null

export function setRuntimeRoot(dir: string | undefined | null): void {
  if (!dir) return
  const r = resolve(dir)
  if (r !== "/") RUNTIME_ROOT = r
}

export function runtimeRoot(): string | null {
  return RUNTIME_ROOT
}

function usable(dir: string | undefined | null): string | null {
  if (!dir) return null
  const r = resolve(dir)
  if (r === "/") return null
  return existsSync(r) ? r : null
}

/**
 * Best-effort project root. Order: an explicit worktree/directory, then the
 * root registered by the plugin, then the process cwd. "/" is never accepted.
 */
export function resolveProjectRoot(worktree?: string | null): string {
  for (const candidate of [worktree, RUNTIME_ROOT, process.cwd()]) {
    const u = usable(candidate)
    if (u) return u
  }
  return process.cwd()
}

/** Directory holding all engagement state for a project. */
export function engagementDir(worktree?: string | null): string {
  if (process.env.NULLBYTE_SECURITY_DIR) return resolve(process.env.NULLBYTE_SECURITY_DIR)
  return join(resolveProjectRoot(worktree), ".nullbyte", "security")
}

export interface EngagementPaths {
  root: string
  scope: string
  findings: string
  evidenceDir: string
  reportsDir: string
  audit: string
}

export function engagementPaths(worktree: string): EngagementPaths {
  const root = engagementDir(worktree)
  return {
    root,
    scope: join(root, "scope.json"),
    findings: join(root, "findings.json"),
    evidenceDir: join(root, "evidence"),
    reportsDir: join(root, "reports"),
    audit: join(root, "audit.jsonl"),
  }
}

export function ensureDir(dir: string): string {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 })
  return dir
}

export function ensureEngagement(p: EngagementPaths): EngagementPaths {
  ensureDir(p.root)
  ensureDir(p.evidenceDir)
  ensureDir(p.reportsDir)
  return p
}
