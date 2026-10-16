/**
 * Static analysis of shell commands for the `bash` scope guard.
 *
 * Modelled on HackerAI's `parseStaticCommandArgv` posture: a command is only
 * treated as statically analyzable when it contains no shell metacharacters or
 * expansion. Anything dynamic cannot be scope-checked, so it is escalated to an
 * approval requirement instead of being silently trusted.
 */

import type { Intensity } from "./types.ts"

export interface CommandAnalysis {
  /** hosts / URLs / IPs / CIDRs found in the command */
  targets: string[]
  /** shell wrappers that defeat static analysis (sh -c, sudo, xargs, eval, ...) */
  wrappers: string[]
  /** destructive patterns detected (data loss / host damage) */
  destructive: string[]
  /** intrusive tool or flag usage detected */
  intrusive: string[]
  /** command contains expansion / metacharacters that make analysis unreliable */
  dynamic: boolean
  /** inferred intensity requirement */
  risk: Intensity
  reasons: string[]
}

/** Shell wrappers that hide the real command from static analysis. */
const WRAPPERS = new Set([
  "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "ash", "busybox",
  "env", "eval", "exec", "xargs", "sudo", "doas", "su", "command", "nohup",
  "time", "watch", "parallel", "ssh", "wsl", "powershell", "pwsh", "cmd",
])

/** Commands that speak to the network; bare hostnames are only harvested for these. */
const NETWORK_TOOLS = new Set([
  "nmap", "masscan", "curl", "wget", "dig", "host", "nslookup", "whois", "ping",
  "traceroute", "openssl", "nc", "netcat", "ncat", "socat", "httpx", "whatweb",
  "nikto", "nuclei", "gobuster", "ffuf", "dirb", "wfuzz", "feroxbuster", "sqlmap",
  "wpscan", "joomscan", "sslscan", "testssl.sh", "amass", "subfinder", "assetfinder",
  "dnsx", "dnsrecon", "fierce", "hydra", "medusa", "patator", "msfconsole", "searchsploit",
  "smbclient", "enum4linux", "snmpwalk", "ldapsearch", "redis-cli", "mongosh",
])

/** Destructive patterns: refuse regardless of scope. */
const DESTRUCTIVE: Array<[RegExp, string]> = [
  [/\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)*\/(?:\s|$)/, "rm targeting filesystem root"],
  [/\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?[a-zA-Z]*\s+~\//, "recursive delete inside home directory"],
  [/\bmkfs(\.\w+)?\b/, "filesystem format"],
  [/\bdd\s+[^|;]*\bof=\/dev\//, "raw write to a block device"],
  [/>\s*\/dev\/sd[a-z]/, "write to raw block device"],
  [/\b(shutdown|reboot|halt|poweroff)\b/, "host shutdown/reboot"],
  [/\b:\(\)\s*\{.*\}\s*;?\s*:/, "fork bomb"],
  [/\biptables\s+(-F|--flush)\b/, "firewall flush"],
  [/\bnft\s+flush\s+ruleset\b/, "firewall flush"],
  [/\bchmod\s+-R\s+777\s+\//, "recursive world-writable on root"],
  [/\bkill(all)?\s+-9\s+-1\b/, "kill every process"],
  [/\bmv\s+\/\S*\s+\/dev\/null/, "move filesystem into /dev/null"],
  [/\btruncate\s+-s\s*0\s+\/(etc|bin|usr|var)\//, "truncate system files"],
  [/\b(userdel|groupdel)\b/, "delete system account"],
  [/\bcrontab\s+-r\b/, "remove all cron jobs"],
  [/\bgit\s+push\b.*--force/, "force push"],
  [/\bDROP\s+(TABLE|DATABASE)\b/i, "destructive SQL DDL"],
  [/\bDELETE\s+FROM\b(?!.*\bWHERE\b)/i, "unbounded SQL DELETE"],
]

/** Intrusive tool/flag signatures → minimum intensity. */
const INTRUSIVE: Array<[RegExp, Intensity, string]> = [
  [/\bsqlmap\b/, "intrusive", "sqlmap (injection testing)"],
  [/\b(hydra|medusa|patator|crowbar|ncrack)\b/, "exploit", "credential attack tool"],
  [/\b(john|hashcat)\b/, "exploit", "password cracking"],
  [/\b(msfconsole|msfvenom)\b/, "exploit", "Metasploit framework"],
  [/\bnmap\b[^|;]*--script\b/, "intrusive", "nmap NSE scripts"],
  [/\bnmap\b[^|;]*\s-(sS|sU|sN|sF|sX|O|A)\b/, "intrusive", "nmap raw/OS-detection scan"],
  [/\bmasscan\b/, "intrusive", "masscan high-rate scanning"],
  [/\b(nikto|whatweb|wpscan|joomscan)\b/, "safe-active", "web vulnerability scanner"],
  [/\b(gobuster|ffuf|dirb|wfuzz|feroxbuster)\b/, "safe-active", "content discovery (noisy)"],
  [/\bnuclei\b/, "safe-active", "nuclei template scan"],
  [/\bnmap\b/, "safe-active", "nmap port scan"],
  [/\bcurl\b[^|;]*\s(-X|--request)\s*(POST|PUT|PATCH|DELETE)\b/, "intrusive", "state-changing HTTP method"],
  [/\bcurl\b[^|;]*\s(--data|--data-raw|--data-binary|-d)\s/, "intrusive", "HTTP request body (may mutate state)"],
  [/\bcurl\b[^|;]*\s(-F|--form)\s/, "intrusive", "multipart upload"],
  [/\bhttpie\b|\bhttp\s+(POST|PUT|PATCH|DELETE)\b/, "intrusive", "state-changing HTTP method"],
  [/\b(redis-cli|mongosh|psql|mysql)\b/, "intrusive", "direct datastore client"],
  [/\b(smbclient|enum4linux|snmpwalk|ldapsearch)\b/, "intrusive", "internal service enumeration"],
]

const URL_RE = /\bhttps?:\/\/[^\s'"`|;)>]+/gi
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?(?::\d{1,5})?\b/g
const IPV6_RE = /\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?::\d{1,5})?\b/g
const BARE_HOST_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i
/** file-ish extensions that should never be mistaken for a hostname */
const FILE_EXT = new Set([
  "txt", "json", "xml", "html", "htm", "js", "ts", "py", "sh", "md", "log", "csv",
  "yaml", "yml", "conf", "cfg", "ini", "pem", "crt", "key", "zip", "tar", "gz",
  "php", "rb", "go", "rs", "java", "class", "jar", "db", "sql", "bak", "tmp",
])

function stripPort(token: string): { host: string; port?: number } {
  const m = /^\[(.+)\]:(\d{1,5})$/.exec(token)
  if (m) return { host: m[1], port: Number(m[2]) }
  const idx = token.lastIndexOf(":")
  if (idx > 0 && /^\d{1,5}$/.test(token.slice(idx + 1)) && !token.includes("::")) {
    return { host: token.slice(0, idx), port: Number(token.slice(idx + 1)) }
  }
  return { host: token }
}

/** Tokenize without executing: split on whitespace but keep quoted spans together. */
export function tokenize(cmd: string): string[] {
  const out: string[] = []
  let cur = ""
  let quote: string | null = null
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]
    if (quote) {
      if (c === quote) quote = null
      else cur += c
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      continue
    }
    if (/\s/.test(c)) {
      if (cur) out.push(cur)
      cur = ""
      continue
    }
    cur += c
  }
  if (cur) out.push(cur)
  return out
}

/** Extract candidate network targets from a command string. */
export function extractTargets(cmd: string): string[] {
  const found = new Set<string>()

  for (const m of cmd.match(URL_RE) ?? []) {
    found.add(m.replace(/[.,;:]+$/, ""))
  }
  for (const m of cmd.match(IPV4_RE) ?? []) found.add(m)
  for (const m of cmd.match(IPV6_RE) ?? []) {
    // avoid capturing time-like or ratio-like fragments
    if (m.split(":").length >= 3) found.add(m)
  }

  const tokens = tokenize(cmd)
  const firstCmd = tokens.find((t) => !t.startsWith("-"))
  const invoked = firstCmd ? firstCmd.split("/").pop()!.toLowerCase() : ""
  if (NETWORK_TOOLS.has(invoked)) {
    for (const t of tokens) {
      if (t.startsWith("-")) continue
      if (t === invoked) continue
      if (t.includes("://")) continue
      const { host } = stripPort(t)
      if (!BARE_HOST_RE.test(host)) continue
      const ext = host.split(".").pop()!.toLowerCase()
      if (FILE_EXT.has(ext)) continue
      found.add(t)
    }
  }

  // drop obvious non-targets
  const cleaned = [...found].filter((t) => {
    if (/^\d+$/.test(t)) return false
    if (t.startsWith("/")) return false
    return true
  })
  return cleaned
}

export function analyzeCommand(cmd: string): CommandAnalysis {
  const reasons: string[] = []
  const wrappers: string[] = []
  const destructive: string[] = []
  const intrusive: string[] = []
  let risk: Intensity = "passive"

  const tokens = tokenize(cmd)
  const first = tokens.find((t) => !t.startsWith("-"))
  const invoked = first ? first.split("/").pop()!.toLowerCase() : ""
  if (WRAPPERS.has(invoked)) {
    wrappers.push(invoked)
    reasons.push(`command is wrapped in '${invoked}', which hides the real operation`)
  }
  for (const t of tokens) {
    const base = t.split("/").pop()!.toLowerCase()
    if (WRAPPERS.has(base) && base !== invoked) wrappers.push(base)
  }

  for (const [re, why] of DESTRUCTIVE) {
    if (re.test(cmd)) destructive.push(why)
  }

  for (const [re, level, why] of INTRUSIVE) {
    if (re.test(cmd)) {
      intrusive.push(why)
      const order: Intensity[] = ["passive", "safe-active", "intrusive", "exploit"]
      if (order.indexOf(level) > order.indexOf(risk)) risk = level
    }
  }

  const dynamic = /\$\(|`|\$\{|<\(|>\s*\(/.test(cmd) || /\|\s*(sh|bash|zsh|python3?|perl|ruby|node)\b/.test(cmd)
  if (dynamic) reasons.push("command uses expansion or pipes into an interpreter; it cannot be statically scope-checked")

  // A command that touches the network but matched no known tool still needs at
  // least safe-active treatment once targets are present.
  const targets = extractTargets(cmd)
  if (targets.length && risk === "passive" && !/^(dig|host|nslookup|whois)\b/.test(cmd.trim())) {
    risk = "safe-active"
  }

  return { targets, wrappers, destructive, intrusive, dynamic, risk, reasons }
}
