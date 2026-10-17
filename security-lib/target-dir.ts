/**
 * Per-target working directory.
 *
 * A run from ~/Desktop against app.acme.test produces:
 *
 *   ~/Desktop/app.acme.test/reports/   <- deliverables
 *   ~/Desktop/app.acme.test/logs/      <- raw scanner stdout/stderr
 *
 * The directory is created the first time an authorized target is contacted, so
 * pointing at a new target produces a new directory and returning to an old one
 * reuses it. A DENIED target creates nothing — the directory is a side effect of
 * authorization, never of the attempt.
 *
 * Only deliverables are sharded per target. The store — findings.json,
 * evidence/, audit.jsonl — stays engagement-wide, because sharding it would
 * break the closure gate, semantic dedupe and cross-session continuity.
 */

import { createHash } from "node:crypto"
import { existsSync, writeFileSync } from "node:fs"
import { join, resolve, sep } from "node:path"
import { ensureDir } from "./paths.ts"
import { redactSecrets } from "./redact.ts"
import { loadPluginPolicy } from "./config.ts"

/** Longest directory name we will create, before adding a collision hash. */
const MAX_SLUG = 100

/** The per-target directory holds raw tool output; keep it out of git. */
const GITIGNORE_BODY = "# created by nullbyte-security — raw target output, do not commit\n*\n"

/**
 * Reduce anything target-shaped to a bare host, so `https://app.acme.test/x`,
 * `app.acme.test:8443` and `app.acme.test` cannot produce three directories for
 * one target. A CIDR keeps its slash — that slash is part of the identity, not a
 * path separator, and the slug converts it below.
 */
function normalizeHostInput(input: string): string {
  let h = (input ?? "").trim().toLowerCase()
  const scheme = /^[a-z][a-z0-9+.-]*:\/\//.exec(h)
  if (scheme) {
    h = h.slice(scheme[0].length).replace(/^[^@/]*@/, "")
    h = h.split(/[/?#]/)[0] // authority only
  }
  // A trailing numeric port is not part of the host's identity. Never strip it
  // from an IPv6 literal (`::`) or from a CIDR.
  const withPort = /^(.+?):(\d{1,5})$/.exec(h)
  if (withPort && !h.includes("::") && !h.includes("/")) h = withPort[1]
  return h
}

/**
 * Filesystem-safe directory name for a target host.
 *
 * This is a SECURITY boundary, not cosmetics. The host string arrives from user
 * input and from tool output, and it is used to build a path, so everything
 * outside [a-z0-9._-] is replaced: `/`, `\`, `:`, NUL and control characters
 * cannot survive, and `..` runs collapse, so no host can escape the project
 * root. `10.20.0.0/24` -> `10.20.0.0_24`, `[::1]` -> `__1`,
 * `../../etc/passwd` -> `etc_passwd`.
 */
export function targetSlug(host: string): string {
  const slug = normalizeHostInput(host)
    .replace(/^\[|\]$/g, "") // an IPv6 literal is bracketed when it carries a port
    .replace(/[/\\:]/g, "_") // CIDR and IPv6 separators are path separators on some systems
    .replace(/[^a-z0-9._-]/g, "_") // whitelist: drops NUL, control chars, shell metacharacters
    .replace(/\.{2,}/g, "_") // no parent traversal
    .replace(/^[._-]+/, "") // no hidden directories, no leading separator
    .replace(/[._-]+$/, "") // no trailing dot or dash (Windows rejects both)

  if (!slug) return "target"
  if (slug.length > MAX_SLUG) {
    // Keep the readable prefix and append a digest so two long hosts that share
    // a prefix cannot land in the same directory.
    const digest = createHash("sha256").update(slug).digest("hex").slice(0, 8)
    return `${slug.slice(0, MAX_SLUG - 9)}-${digest}`
  }
  return slug
}

/**
 * Absolute path of a target's directory inside the project root.
 *
 * Re-asserts containment after building the path. `targetSlug` already makes
 * escape impossible; this is the belt to that pair of braces, so a future edit
 * to the slug rules cannot silently introduce a traversal.
 */
export function targetDir(projectRoot: string, host: string): string {
  const base = resolve(projectRoot)
  const dir = join(base, targetSlug(host))
  if (!dir.startsWith(base + sep)) {
    throw new Error(`refusing to resolve a target directory outside ${base}`)
  }
  return dir
}

export interface TargetPaths {
  host: string
  slug: string
  root: string
  reports: string
  logs: string
}

/** Where a target's deliverables and logs belong. Does not touch the disk. */
export function targetPaths(projectRoot: string, host: string): TargetPaths {
  const root = targetDir(projectRoot, host)
  return {
    host,
    slug: targetSlug(host),
    root,
    reports: join(root, "reports"),
    logs: join(root, "logs"),
  }
}

/**
 * Create a target's directory tree. Returns undefined when per-target
 * directories are switched off in the global policy.
 *
 * Best-effort by design: callers treat a filesystem failure as "no directory"
 * rather than as a failure of the operation being authorized.
 */
export function ensureTarget(projectRoot: string, host: string): TargetPaths | undefined {
  if (!loadPluginPolicy().target_dirs) return undefined
  const paths = targetPaths(projectRoot, host)
  ensureDir(paths.root)
  ensureDir(paths.reports)
  ensureDir(paths.logs)
  const ignore = join(paths.root, ".gitignore")
  if (!existsSync(ignore)) writeFileSync(ignore, GITIGNORE_BODY, { mode: 0o644 })
  return paths
}

/** Best-effort wrapper: a target directory is a convenience, never a precondition. */
export function ensureTargetQuietly(projectRoot: string, host: string): TargetPaths | undefined {
  try {
    return ensureTarget(projectRoot, host)
  } catch {
    return undefined
  }
}

function sanitizeToken(s: string): string {
  const t = (s ?? "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, "_")
    .replace(/^[._-]+/, "")
  return t || "tool"
}

/**
 * A free path for `base` in `dir`. Two runs that start in the same millisecond
 * would otherwise collide and the second would silently destroy the first's log.
 */
function uniquePath(dir: string, base: string): string {
  let candidate = join(dir, `${base}.log`)
  let n = 1
  while (existsSync(candidate)) {
    n++
    candidate = join(dir, `${base}-${n}.log`)
  }
  return candidate
}

export interface TargetLogInput {
  sessionID: string
  /** producing tool, e.g. an adapter id */
  source: string
  /** host the log belongs to */
  target: string
  command?: string
  exitCode?: number
  durationMs?: number
  stdout?: string
  stderr?: string
  problems?: string[]
  /**
   * Store the log verbatim. Defaults to true, matching the evidence store: the
   * operator's posture is full disclosure, so raw scanner output that carries a
   * credential is kept. Pass false to redact at capture instead.
   */
  includeSecrets?: boolean
}

export interface TargetLogResult {
  path: string
  bytes: number
  redacted: boolean
}

/**
 * Write a scanner's raw stdout/stderr to `<target>/logs/<source>-<timestamp>.log`.
 *
 * Stored verbatim by default, matching the evidence store: raw scanner output
 * routinely carries credentials, and the operator's posture is full disclosure.
 * `includeSecrets=false` redacts at capture — the same escape hatch, in reverse,
 * that `sec_evidence` exposes, so the two behave identically.
 */
export function writeTargetLog(projectRoot: string, input: TargetLogInput): TargetLogResult | undefined {
  const paths = ensureTarget(projectRoot, input.target)
  if (!paths) return undefined

  const startedAt = new Date().toISOString()
  const stamp = startedAt.replace(/[:.]/g, "-")
  const path = uniquePath(paths.logs, `${sanitizeToken(input.source)}-${stamp}`)

  const header = [
    `# ${input.source} — ${input.target}`,
    `session:  ${input.sessionID}`,
    `started:  ${startedAt}`,
    input.command ? `command:  ${input.command}` : "",
    input.exitCode !== undefined ? `exit:     ${input.exitCode}` : "",
    input.durationMs !== undefined ? `duration: ${input.durationMs}ms` : "",
    input.problems?.length ? `problems: ${input.problems.join("; ")}` : "",
  ].filter(Boolean)

  const body = [
    ...header,
    "",
    "## stdout",
    input.stdout?.trimEnd() || "_(empty)_",
    "",
    "## stderr",
    input.stderr?.trimEnd() || "_(empty)_",
    "",
  ].join("\n")

  const text = input.includeSecrets === false ? redactSecrets(body) : body
  const redacted = text !== body
  writeFileSync(path, text, { mode: 0o600 })
  return { path, bytes: Buffer.byteLength(text, "utf8"), redacted }
}
