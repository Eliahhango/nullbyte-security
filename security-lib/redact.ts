/**
 * Secret handling for anything that leaves a tool and lands in model context,
 * evidence files, reports, or the audit log.
 *
 * Two operations share one table of patterns, so a shape can never be redacted
 * by one and missed by the other:
 *
 *   - `redactSecrets` scrubs a string (the opt-in posture: `redact: true`,
 *     `includeSecrets: false`).
 *   - `extractCredentials` pulls the same shapes out verbatim, with their
 *     context, so a report can present leaked credentials in full — the
 *     operator's standing posture is full disclosure.
 */

interface CredentialValue {
  /** the key the value was assigned to, when the shape has one */
  label?: string
  /** the credential value, verbatim */
  value: string
}

interface Rule {
  name: string
  re: RegExp
  replace?: (m: string) => string
  /** pull the credential out of a match; absent = redact-only shape */
  extract?: (m: RegExpMatchArray) => CredentialValue | undefined
}

function unquote(s: string): string {
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) return s.slice(1, -1)
  return s
}

const RULES: Rule[] = [
  // PEM blocks (private keys) — collapse entirely
  {
    name: "private-key",
    re: /(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)/g,
    replace: () => "[REDACTED:private-key]",
    extract: (m) => ({ value: m[1] }),
  },
  // Authorization headers / bearer tokens
  {
    name: "bearer",
    re: /\b(?:bearer|token)\s+([A-Za-z0-9._\-+/=]{12,})/gi,
    replace: () => "Bearer [REDACTED:token]",
    extract: (m) => ({ label: "bearer", value: m[1] }),
  },
  {
    name: "basic-auth",
    re: /\bbasic\s+([A-Za-z0-9+/=]{12,})/gi,
    replace: () => "Basic [REDACTED:basic]",
    extract: (m) => ({ label: "basic", value: m[1] }),
  },
  // Cookies
  {
    name: "cookie",
    re: /\b(?:set-)?cookie\s*:\s*([^\r\n]+)/gi,
    replace: () => "Cookie: [REDACTED:cookie]",
    extract: (m) => ({ label: "cookie", value: m[1].trim() }),
  },
  // userinfo embedded in a URL: https://user:pass@host
  {
    name: "url-userinfo",
    re: /\b[a-zA-Z][a-zA-Z0-9+.\-]*:\/\/([^/\s:@]+:[^/\s@]+)@/g,
    replace: () => "://[REDACTED:userinfo]@",
    extract: (m) => ({ label: "url-userinfo", value: m[1] }),
  },
  // Well-known provider key shapes
  {
    name: "aws-akid",
    re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g,
    replace: () => "[REDACTED:aws-key-id]",
    extract: (m) => ({ value: m[1] }),
  },
  {
    name: "openai",
    re: /\b(sk-[A-Za-z0-9_\-]{20,})\b/g,
    replace: () => "[REDACTED:sk-key]",
    extract: (m) => ({ value: m[1] }),
  },
  {
    name: "anthropic",
    re: /\b(sk-ant-[A-Za-z0-9_\-]{20,})\b/g,
    replace: () => "[REDACTED:sk-ant-key]",
    extract: (m) => ({ value: m[1] }),
  },
  {
    name: "github",
    re: /\b(gh[pousr]_[A-Za-z0-9]{20,})\b/g,
    replace: () => "[REDACTED:github-token]",
    extract: (m) => ({ value: m[1] }),
  },
  {
    name: "gitlab",
    re: /\b(glpat-[A-Za-z0-9_\-]{16,})\b/g,
    replace: () => "[REDACTED:gitlab-token]",
    extract: (m) => ({ value: m[1] }),
  },
  {
    name: "slack",
    re: /\b(xox[abprs]-[A-Za-z0-9-]{10,})\b/g,
    replace: () => "[REDACTED:slack-token]",
    extract: (m) => ({ value: m[1] }),
  },
  {
    name: "google-api",
    re: /\b(AIza[0-9A-Za-z_\-]{30,})\b/g,
    replace: () => "[REDACTED:google-api-key]",
    extract: (m) => ({ value: m[1] }),
  },
  {
    name: "jwt",
    re: /\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b/g,
    replace: () => "[REDACTED:jwt]",
    extract: (m) => ({ value: m[1] }),
  },
  {
    name: "npm",
    re: /\b(npm_[A-Za-z0-9]{30,})\b/g,
    replace: () => "[REDACTED:npm-token]",
    extract: (m) => ({ value: m[1] }),
  },
  // key=value / key: value credential assignments. The leading prefix group is
  // deliberate: `db_password`, `mysql_pwd`, `client_secret` are the common
  // shapes in a leaked .env, and a plain \b would never match them because `_`
  // is a word character.
  {
    name: "assignment",
    re: /\b([A-Za-z0-9_-]*(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|password|passwd|pwd|private[_-]?key))\b\s*[:=]\s*("[^"\n]{6,}"|'[^'\n]{6,}'|[^\s,;"'\n]{6,})/gi,
    replace: (m) => {
      const sep = m.includes(":") && !m.includes("=") ? ": " : "="
      const key = m.split(/[:=]/)[0].trim()
      return `${key}${sep}[REDACTED:credential]`
    },
    extract: (m) => ({ label: m[1], value: unquote(m[2]) }),
  },
]

/** Redact known secret shapes. Idempotent. */
export function redactSecrets(input: string): string {
  if (!input) return input
  let out = input
  for (const rule of RULES) {
    out = out.replace(rule.re, (m) => (rule.replace ? rule.replace(m) : "[REDACTED]"))
  }
  return out
}

/** Redact then bound the length, keeping head and tail (scanner output is tail-heavy). */
export function redactAndTruncate(input: string, maxBytes = 16 * 1024): string {
  const red = redactSecrets(input)
  const buf = Buffer.from(red, "utf8")
  if (buf.length <= maxBytes) return red
  const headLen = Math.floor(maxBytes * 0.6)
  const tailLen = maxBytes - headLen
  const head = buf.subarray(0, headLen).toString("utf8")
  const tail = buf.subarray(buf.length - tailLen).toString("utf8")
  return `${head}\n...[truncated ${buf.length - maxBytes} bytes]...\n${tail}`
}

/** Best-effort scrub of credentials embedded in URLs (`https://user:pass@host`). */
export function stripUrlCredentials(url: string): string {
  return url.replace(/\/\/[^/@\s]+:[^/@\s]+@/g, "//[REDACTED:userinfo]@")
}

/** A credential pulled out of a blob of text, verbatim. */
export interface CredentialHit {
  /** rule family, e.g. `assignment`, `aws-akid`, `bearer` */
  kind: string
  /** the key the value was assigned to, when the shape has one (e.g. `db_password`) */
  label?: string
  /** the credential value, verbatim */
  value: string
  /** the trimmed line the credential appeared on */
  context: string
}

function lineAt(text: string, index: number): string {
  const start = text.lastIndexOf("\n", index - 1) + 1
  let end = text.indexOf("\n", index)
  if (end === -1) end = text.length
  return text.slice(start, end).trim()
}

/**
 * Pull every credential-shaped value out of a blob of text, verbatim.
 *
 * This is the inverse of `redactSecrets` and shares its patterns. It does not
 * dedupe — the same value can legitimately appear on several lines; the
 * collector in `credentials.ts` folds duplicates for presentation.
 */
export function extractCredentials(text: string): CredentialHit[] {
  if (!text) return []
  const hits: CredentialHit[] = []
  for (const rule of RULES) {
    if (!rule.extract) continue
    for (const m of text.matchAll(rule.re)) {
      const got = rule.extract(m)
      if (!got?.value) continue
      hits.push({ kind: rule.name, label: got.label, value: got.value, context: lineAt(text, m.index ?? 0) })
    }
  }
  return hits
}
