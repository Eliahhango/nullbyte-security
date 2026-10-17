/**
 * Policy + scope loading and validation.
 *
 * The authorized scope is USER-AUTHORED. The model can read and test against it
 * but cannot silently expand it: `allow_model_scope_edit` defaults to false and
 * `sec_scope` refuses mutations unless the user opted in.
 */

import { existsSync, readFileSync } from "node:fs"
import type { Intensity, Scope, ScopeEntry } from "./types.ts"
import { globalPolicyPath, engagementPaths, type EngagementPaths } from "./paths.ts"

export interface LoadedScope {
  scope: Scope
  /** where the scope came from, for auditability */
  source: string
  warnings: string[]
  paths: EngagementPaths
}

export const DEFAULT_SCOPE: Scope = {
  engagement: "default",
  authorized_all: true,
  block_destructive: true,
  include: [],
  exclude: [],
  intensity: "exploit",
  allow_private: true,
  allow_model_scope_edit: false,
  require_approval_for_intrusive: false,
}

function asArray(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string")
  if (typeof v === "string" && v.trim()) return [v.trim()]
  return []
}

function normalizeEntry(raw: unknown): ScopeEntry | null {
  if (typeof raw === "string") {
    const host = raw.trim()
    return host ? { host } : null
  }
  if (raw && typeof raw === "object") {
    const o = raw as Record<string, unknown>
    const host = typeof o.host === "string" ? o.host.trim() : ""
    if (!host) return null
    const ports = Array.isArray(o.ports)
      ? o.ports.map(Number).filter((p) => Number.isInteger(p) && p > 0 && p < 65536)
      : undefined
    return { host, ports: ports && ports.length ? ports : undefined, note: typeof o.note === "string" ? o.note : undefined }
  }
  return null
}

const INTENSITIES: Intensity[] = ["passive", "safe-active", "intrusive", "exploit"]

/** Validate a raw scope object; returns human-readable problems. */
export function validateScope(raw: unknown): string[] {
  const problems: string[] = []
  if (!raw || typeof raw !== "object") return ["scope must be a JSON object"]
  const o = raw as Record<string, unknown>
  if (o.intensity !== undefined && !INTENSITIES.includes(o.intensity as Intensity)) {
    problems.push(`intensity must be one of ${INTENSITIES.join(", ")}`)
  }
  if (o.include !== undefined && !Array.isArray(o.include)) problems.push("include must be an array")
  if (o.exclude !== undefined && !Array.isArray(o.exclude)) problems.push("exclude must be an array")
  if (o.allow_private !== undefined && typeof o.allow_private !== "boolean") {
    problems.push("allow_private must be a boolean")
  }
  if (o.allow_model_scope_edit !== undefined && typeof o.allow_model_scope_edit !== "boolean") {
    problems.push("allow_model_scope_edit must be a boolean")
  }
  if (Array.isArray(o.include) && o.include.length === 0 && o.authorized_all === false) {
    problems.push("include is empty while authorized_all is false: no target is authorized, every network action will be denied")
  }
  for (const [i, e] of (Array.isArray(o.include) ? o.include : []).entries()) {
    if (!normalizeEntry(e)) problems.push(`include[${i}] is not a usable host entry`)
  }
  return problems
}

/** Parse a raw JSON scope object into a complete Scope with defaults applied. */
export function normalizeScope(raw: unknown): Scope {
  const o = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>
  return {
    engagement: typeof o.engagement === "string" && o.engagement.trim() ? o.engagement.trim() : DEFAULT_SCOPE.engagement,
    authorized_by: typeof o.authorized_by === "string" ? o.authorized_by : undefined,
    authorized_at: typeof o.authorized_at === "string" ? o.authorized_at : undefined,
    authorized_all: typeof o.authorized_all === "boolean" ? o.authorized_all : DEFAULT_SCOPE.authorized_all,
    block_destructive: typeof o.block_destructive === "boolean" ? o.block_destructive : DEFAULT_SCOPE.block_destructive,
    include: (Array.isArray(o.include) ? o.include : []).map(normalizeEntry).filter((e): e is ScopeEntry => !!e),
    exclude: asArray(o.exclude).map((s) => s.trim()).filter(Boolean),
    intensity: INTENSITIES.includes(o.intensity as Intensity) ? (o.intensity as Intensity) : DEFAULT_SCOPE.intensity,
    allow_private: typeof o.allow_private === "boolean" ? o.allow_private : DEFAULT_SCOPE.allow_private,
    allow_model_scope_edit:
      typeof o.allow_model_scope_edit === "boolean" ? o.allow_model_scope_edit : DEFAULT_SCOPE.allow_model_scope_edit,
    require_approval_for_intrusive:
      typeof o.require_approval_for_intrusive === "boolean"
        ? o.require_approval_for_intrusive
        : DEFAULT_SCOPE.require_approval_for_intrusive,
  }
}

function readJson(path: string): { value: unknown; error?: string } {
  try {
    return { value: JSON.parse(readFileSync(path, "utf8")) }
  } catch (e) {
    return { value: null, error: e instanceof Error ? e.message : String(e) }
  }
}

/**
 * Load the effective scope: global policy file provides the baseline, the
 * per-project engagement file overrides it.
 */
export function loadScope(worktree: string): LoadedScope {
  const paths = engagementPaths(worktree)
  const warnings: string[] = []
  let scope = { ...DEFAULT_SCOPE }
  let source = "defaults (authorized_all: every target permitted, no scope file present)"

  const globalPath = globalPolicyPath()
  if (existsSync(globalPath)) {
    const { value, error } = readJson(globalPath)
    if (error) warnings.push(`global policy ${globalPath} is unreadable: ${error}`)
    else {
      scope = { ...scope, ...normalizeScope(value) }
      source = globalPath
    }
  }

  if (existsSync(paths.scope)) {
    const { value, error } = readJson(paths.scope)
    if (error) {
      warnings.push(`engagement scope ${paths.scope} is unreadable: ${error}`)
    } else {
      const problems = validateScope(value)
      warnings.push(...problems.map((p) => `scope: ${p}`))
      const normalized = normalizeScope(value)
      // engagement overrides global, but never silently enables model edits
      scope = { ...scope, ...normalized, allow_model_scope_edit: scope.allow_model_scope_edit && normalized.allow_model_scope_edit }
      source = paths.scope
    }
  }

  return { scope, source, warnings, paths }
}

/**
 * Plugin-level policy from the global policy file. Kept separate from the
 * engagement scope so a project file cannot turn enforcement off.
 */
export interface PluginPolicy {
  /** inject the shared workflow block into system prompts (default true) */
  inject_workflow: boolean
  /** refuse to read/write known local credential stores (default true) */
  protect_local_secrets: boolean
  /** add destructive command patterns to the native permission rules (default true) */
  inject_permission_rules: boolean
  /** additionally prompt for intrusive scanners — off by default so non-interactive runs never stall */
  ask_intrusive_commands: boolean
  /**
   * Give each contacted target its own directory in the project root, holding
   * the reports and any raw scanner logs (default true). Off falls back to the
   * single flat engagement directory.
   */
  target_dirs: boolean
  /**
   * Require the engagement store to be encrypted at rest (default false).
   *
   * The key itself comes from NULLBYTE_STORE_KEY or the key file, never from
   * this file — a passphrase in a config file that gets committed is not
   * encryption. With this true and no key, the tools refuse to write rather than
   * silently storing plaintext. See security-lib/crypto.ts.
   */
  encrypt_store: boolean
}

export function loadPluginPolicy(): PluginPolicy {
  const policy: PluginPolicy = {
    inject_workflow: true,
    protect_local_secrets: true,
    inject_permission_rules: true,
    ask_intrusive_commands: false,
    target_dirs: true,
    encrypt_store: false,
  }
  const path = globalPolicyPath()
  if (!existsSync(path)) return policy
  const { value } = readJson(path)
  if (!value || typeof value !== "object") return policy
  const plugins = (value as Record<string, unknown>).plugins
  if (!plugins || typeof plugins !== "object") return policy
  const p = plugins as Record<string, unknown>
  if (typeof p.inject_workflow === "boolean") policy.inject_workflow = p.inject_workflow
  if (typeof p.protect_local_secrets === "boolean") policy.protect_local_secrets = p.protect_local_secrets
  if (typeof p.inject_permission_rules === "boolean") policy.inject_permission_rules = p.inject_permission_rules
  if (typeof p.ask_intrusive_commands === "boolean") policy.ask_intrusive_commands = p.ask_intrusive_commands
  if (typeof p.target_dirs === "boolean") policy.target_dirs = p.target_dirs
  if (typeof p.encrypt_store === "boolean") policy.encrypt_store = p.encrypt_store
  return policy
}

export function scopeTemplate(): Scope {
  return {
    engagement: "example-local-lab",
    authorized_by: "self (owner of the lab environment)",
    authorized_at: new Date().toISOString().slice(0, 10),
    authorized_all: false,
    block_destructive: true,
    include: [
      { host: "127.0.0.1", ports: [8080, 8443], note: "local deliberately vulnerable lab" },
      { host: "localhost", ports: [8080, 8443] },
    ],
    exclude: [],
    intensity: "safe-active",
    allow_private: true,
    allow_model_scope_edit: false,
    require_approval_for_intrusive: true,
  }
}
