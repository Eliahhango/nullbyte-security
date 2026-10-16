/**
 * Local static analysis: secret discovery and dependency auditing.
 *
 * Read-only over the project tree. Secrets are reported by location and kind —
 * never by value — so running the scanner does not itself leak credentials.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs"
import { join, relative } from "node:path"
import { runArgv } from "./adapters/scanners.ts"

export interface SecretHit {
  file: string
  line: number
  kind: string
  /** redacted, short preview proving the match without disclosing it */
  preview: string
}

export interface CodeSmell {
  file: string
  line: number
  rule: string
  detail: string
  severity: "low" | "medium" | "high"
}

const IGNORE_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "out", ".next", "target", "vendor",
  "__pycache__", ".venv", "venv", ".cache", "coverage", ".nullbyte",
])

const SKIP_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar",
  ".7z", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".so", ".dll", ".dylib",
  ".exe", ".bin", ".class", ".jar", ".wasm", ".db", ".sqlite",
])

const MAX_FILE_BYTES = 512 * 1024
const MAX_FILES = 4000

interface SecretRule {
  kind: string
  re: RegExp
  /** capture group to preview (redacted); 0 = whole match */
  group?: number
}

const SECRET_RULES: SecretRule[] = [
  { kind: "private-key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { kind: "aws-access-key-id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { kind: "openai-key", re: /\bsk-[A-Za-z0-9_\-]{20,}\b/ },
  { kind: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/ },
  { kind: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/ },
  { kind: "gitlab-token", re: /\bglpat-[A-Za-z0-9_\-]{16,}\b/ },
  { kind: "slack-token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { kind: "google-api-key", re: /\bAIza[0-9A-Za-z_\-]{30,}\b/ },
  { kind: "jwt", re: /\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/ },
  { kind: "npm-token", re: /\bnpm_[A-Za-z0-9]{30,}\b/ },
  { kind: "stripe-key", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/ },
  { kind: "sendgrid-key", re: /\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b/ },
  { kind: "twilio-key", re: /\bSK[0-9a-fA-F]{32}\b/ },
  { kind: "db-uri-with-password", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s/]+:[^@\s/]{3,}@/ },
  { kind: "hardcoded-password", re: /\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*["'][^"'\n]{8,}["']/i },
]

const SMELL_RULES: Array<{ rule: string; re: RegExp; detail: string; severity: CodeSmell["severity"] }> = [
  { rule: "eval", re: /\beval\s*\(/, detail: "Dynamic code execution; review whether input can reach it.", severity: "high" },
  { rule: "child-process-interpolation", re: /(?:exec|execSync)\s*\(\s*[`"'][^`"']*\$\{/, detail: "Shell command built from interpolated input.", severity: "high" },
  { rule: "sql-string-concat", re: /(?:SELECT|INSERT|UPDATE|DELETE)[^;]{0,120}(?:\+\s*\w+|\$\{)/i, detail: "SQL assembled by concatenation; check for parameterisation.", severity: "high" },
  { rule: "innerhtml", re: /\.innerHTML\s*=/, detail: "Assignment to innerHTML; check for untrusted input (XSS).", severity: "medium" },
  { rule: "dangerously-set-innerhtml", re: /dangerouslySetInnerHTML/, detail: "React raw HTML injection point.", severity: "medium" },
  { rule: "verify-disabled", re: /(?:rejectUnauthorized|verify)\s*[:=]\s*false/, detail: "TLS verification disabled.", severity: "medium" },
  { rule: "debug-enabled", re: /\bDEBUG\s*[:=]\s*(?:true|1)\b/, detail: "Debug mode enabled in a committed file.", severity: "low" },
  { rule: "cors-wildcard-credentials", re: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']/, detail: "Wildcard CORS origin.", severity: "medium" },
  { rule: "weak-hash", re: /\b(?:md5|sha1)\s*\(/i, detail: "Weak hash primitive; not suitable for passwords or integrity.", severity: "low" },
]

function* walk(root: string, opts: { maxFiles?: number; followSymlinks?: boolean } = {}): Generator<string> {
  const maxFiles = opts.maxFiles ?? MAX_FILES
  let count = 0
  const stack = [root]
  while (stack.length) {
    const dir = stack.pop()!
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      continue
    }
    for (const name of entries) {
      if (count >= maxFiles) return
      const p = join(dir, name)
      let st
      try {
        st = statSync(p)
      } catch {
        continue
      }
      if (st.isDirectory()) {
        if (IGNORE_DIRS.has(name)) continue
        stack.push(p)
        continue
      }
      if (!st.isFile()) continue
      const dot = name.lastIndexOf(".")
      const ext = dot === -1 ? "" : name.slice(dot).toLowerCase()
      if (SKIP_EXT.has(ext)) continue
      if (st.size > MAX_FILE_BYTES) continue
      count++
      yield p
    }
  }
}

export interface SastOptions {
  maxFiles?: number
  /** only report these kinds (empty = all) */
  only?: string[]
}

export interface SastResult {
  root: string
  filesScanned: number
  secrets: SecretHit[]
  smells: CodeSmell[]
  truncated: boolean
  problems: string[]
}

export function scanSource(root: string, opts: SastOptions = {}): SastResult {
  const secrets: SecretHit[] = []
  const smells: CodeSmell[] = []
  let filesScanned = 0
  let truncated = false
  const problems: string[] = []

  for (const file of walk(root, { maxFiles: opts.maxFiles })) {
    if (filesScanned >= (opts.maxFiles ?? MAX_FILES)) {
      truncated = true
      break
    }
    let text: string
    try {
      text = readFileSync(file, "utf8")
    } catch {
      continue
    }
    filesScanned++
    const rel = relative(root, file)
    const lines = text.split("\n")
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      for (const rule of SECRET_RULES) {
        if (opts.only?.length && !opts.only.includes(rule.kind)) continue
        const m = rule.re.exec(line)
        if (!m) continue
        const value = m[rule.group ?? 0]
        secrets.push({
          file: rel,
          line: i + 1,
          kind: rule.kind,
          preview: `${value.slice(0, 4)}${"*".repeat(Math.max(4, Math.min(value.length - 4, 20)))} (redacted, ${value.length} chars)`,
        })
      }
      for (const rule of SMELL_RULES) {
        if (rule.re.test(line)) {
          smells.push({ file: rel, line: i + 1, rule: rule.rule, detail: rule.detail, severity: rule.severity })
        }
      }
    }
  }

  if (!existsSync(root)) problems.push(`scan root ${root} does not exist`)
  return { root, filesScanned, secrets, smells, truncated, problems }
}

/* --------------------------------------------------------- dependencies --- */

export interface DependencyAudit {
  ok: boolean
  manager?: string
  lockfile?: string
  total?: number
  vulnerabilities?: Record<string, number>
  advisories: Array<{ package: string; severity: string; title: string; url?: string; range?: string }>
  problems: string[]
}

/**
 * Audit project dependencies using the project's own package manager.
 * Requires a lockfile; if absent we say so rather than guessing.
 */
export async function auditDependencies(root: string, timeoutMs = 120000): Promise<DependencyAudit> {
  const candidates: Array<{ manager: string; lock: string }> = [
    { manager: "npm", lock: "package-lock.json" },
    { manager: "pnpm", lock: "pnpm-lock.yaml" },
    { manager: "yarn", lock: "yarn.lock" },
  ]
  const found = candidates.find((c) => existsSync(join(root, c.lock)))
  if (!found) {
    return {
      ok: false,
      advisories: [],
      problems: [
        "no lockfile found (package-lock.json / pnpm-lock.yaml / yarn.lock); dependency auditing needs a locked dependency graph",
      ],
    }
  }
  if (found.manager !== "npm") {
    return {
      ok: false,
      manager: found.manager,
      lockfile: found.lock,
      advisories: [],
      problems: [`${found.manager} auditing is not automated here; run \`${found.manager} audit\` manually for a full report`],
    }
  }

  const run = await runArgv("npm", ["audit", "--json", "--audit-level=low"], { timeoutMs, cwd: root })
  // npm audit exits non-zero when vulnerabilities exist — that is not a failure
  let parsed: Record<string, unknown> | null = null
  try {
    parsed = JSON.parse(run.stdout) as Record<string, unknown>
  } catch {
    return { ok: false, manager: "npm", lockfile: found.lock, advisories: [], problems: ["npm audit did not return parseable JSON"] }
  }

  const vulns = (parsed.vulnerabilities ?? {}) as Record<string, Record<string, unknown>>
  const advisories: DependencyAudit["advisories"] = []
  for (const [pkg, v] of Object.entries(vulns)) {
    const via = Array.isArray(v.via) ? v.via : []
    for (const item of via) {
      if (typeof item !== "object" || item === null) continue
      const a = item as Record<string, unknown>
      advisories.push({
        package: pkg,
        severity: String(v.severity ?? a.severity ?? "unknown"),
        title: String(a.title ?? "advisory"),
        url: a.url ? String(a.url) : undefined,
        range: a.range ? String(a.range) : undefined,
      })
    }
    if (!via.length) advisories.push({ package: pkg, severity: String(v.severity ?? "unknown"), title: "vulnerable dependency" })
  }

  const meta = (parsed.metadata ?? {}) as Record<string, unknown>
  const counts = (meta.vulnerabilities ?? {}) as Record<string, number>
  return {
    ok: true,
    manager: "npm",
    lockfile: found.lock,
    total: typeof meta.dependencies === "number" ? (meta.dependencies as number) : undefined,
    vulnerabilities: counts,
    advisories,
    problems: run.problems,
  }
}
