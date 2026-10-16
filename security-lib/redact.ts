/**
 * Secret redaction for anything that leaves a tool and lands in model context,
 * evidence files, reports, or the audit log.
 *
 * HackerAI keeps credentials out of analytics and report payloads; the same
 * discipline is applied here at the boundary instead of relying on prompts.
 */

interface Rule {
  name: string
  re: RegExp
  replace?: (m: string) => string
}

const RULES: Rule[] = [
  // PEM blocks (private keys) — collapse entirely
  {
    name: "private-key",
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    replace: () => "[REDACTED:private-key]",
  },
  // Authorization headers / bearer tokens
  { name: "bearer", re: /\b(?:bearer|token)\s+[A-Za-z0-9._\-+/=]{12,}/gi, replace: () => "Bearer [REDACTED:token]" },
  { name: "basic-auth", re: /\bbasic\s+[A-Za-z0-9+/=]{12,}/gi, replace: () => "Basic [REDACTED:basic]" },
  // Cookies
  {
    name: "cookie",
    re: /\b(?:set-)?cookie\s*:\s*[^\r\n]+/gi,
    replace: () => "Cookie: [REDACTED:cookie]",
  },
  // Well-known provider key shapes
  { name: "aws-akid", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, replace: () => "[REDACTED:aws-key-id]" },
  { name: "openai", re: /\bsk-[A-Za-z0-9_\-]{20,}\b/g, replace: () => "[REDACTED:sk-key]" },
  { name: "anthropic", re: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g, replace: () => "[REDACTED:sk-ant-key]" },
  { name: "github", re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, replace: () => "[REDACTED:github-token]" },
  { name: "gitlab", re: /\bglpat-[A-Za-z0-9_\-]{16,}\b/g, replace: () => "[REDACTED:gitlab-token]" },
  { name: "slack", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, replace: () => "[REDACTED:slack-token]" },
  { name: "google-api", re: /\bAIza[0-9A-Za-z_\-]{30,}\b/g, replace: () => "[REDACTED:google-api-key]" },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/g, replace: () => "[REDACTED:jwt]" },
  { name: "npm", re: /\bnpm_[A-Za-z0-9]{30,}\b/g, replace: () => "[REDACTED:npm-token]" },
  // key=value / key: value credential assignments
  {
    name: "assignment",
    re: /\b(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|password|passwd|pwd|private[_-]?key)\b\s*[:=]\s*("[^"\n]{6,}"|'[^'\n]{6,}'|[^\s,;"'\n]{6,})/gi,
    replace: (m) => {
      const sep = m.includes(":") && !m.includes("=") ? ": " : "="
      const key = m.split(/[:=]/)[0].trim()
      return `${key}${sep}[REDACTED:credential]`
    },
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
