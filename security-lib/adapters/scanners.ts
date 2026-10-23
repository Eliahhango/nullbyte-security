/**
 * Scanner adapters.
 *
 * Commands are always built as an argv array and executed with spawn() — never
 * through a shell string — so a hostile hostname or scope entry cannot inject
 * flags. Every run has a hard timeout, capped output, and normalized errors.
 * Structured output (nmap XML, nuclei JSONL) is parsed into findings; anything
 * unparseable is preserved as raw evidence rather than guessed at.
 */

import { spawn } from "node:child_process"
import { withExclusiveHostSlot } from "../ratelimit.ts"
import { formatElapsed, startProgress } from "../progress.ts"
import { readFileSync, unlinkSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { Intensity, Severity } from "../types.ts"
import { redactSecrets } from "../redact.ts"

export interface ScanRunResult {
  ok: boolean
  command: string
  exitCode: number | null
  stdout: string
  stderr: string
  durationMs: number
  timedOut: boolean
  truncated: boolean
  problems: string[]
}

const MAX_STDOUT = 2 * 1024 * 1024

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
}

export interface RunOptions {
  timeoutMs?: number
  maxOutputBytes?: number
  cwd?: string
  /**
   * Return stdout/stderr verbatim. Defaults to true: the operator's standing
   * posture is full disclosure, so scanner output that carries a leaked
   * credential is kept verbatim and the report can show it.
   *
   * Redaction happens HERE, at the capture boundary, so it cannot be undone
   * downstream. Pass false only to suppress secret-like material from this run;
   * an artifact redacted here can never be recovered by a later report.
   */
  includeSecrets?: boolean
  /**
   * Target host, when this run contacts one. Set, the run takes the host's
   * exclusive slot: scanners are long, loud, and the thing an IPS reacts to, so
   * two at once against one host is never the intent.
   */
  host?: string
  /** Show the Clack-style live progress line while the scanner runs. */
  progress?: boolean | string
}

/**
 * Run an argv vector with a hard timeout and output caps. No shell involved.
 *
 * When `opts.host` is set the run is paced under the engagement's host budget and
 * taken exclusively, so two scanners never hammer one target at once.
 */
export function runArgv(bin: string, args: string[], opts: RunOptions = {}): Promise<ScanRunResult> {
  const started = Date.now()
  const run = () => runArgvRaw(bin, args, opts, started)
  return opts.host ? withExclusiveHostSlot(opts.host, run) : run()
}

function runArgvRaw(bin: string, args: string[], opts: RunOptions, started: number): Promise<ScanRunResult> {
  const timeoutMs = opts.timeoutMs ?? 120000
  const maxBytes = opts.maxOutputBytes ?? MAX_STDOUT
  const printable = [bin, ...args].map((a) => (/[^\w@%+=:,./-]/.test(a) ? JSON.stringify(a) : a)).join(" ")

  return new Promise<ScanRunResult>((resolve) => {
    let stdout = ""
    let stderr = ""
    let truncated = false
    let timedOut = false
    let settled = false

    let child: ReturnType<typeof spawn>
    try {
      child = spawn(bin, args, { shell: false, cwd: opts.cwd, env: { ...process.env, LC_ALL: "C" } })
    } catch (e) {
      resolve({
        ok: false,
        command: printable,
        exitCode: null,
        stdout: "",
        stderr: "",
        durationMs: Date.now() - started,
        timedOut: false,
        truncated: false,
        problems: [`failed to spawn ${bin}: ${e instanceof Error ? e.message : String(e)}`],
      })
      return
    }

    const label = typeof opts.progress === "string" ? opts.progress : opts.progress ? `${bin.split(/[\\/]/).pop() ?? bin}${opts.host ? ` ${opts.host}` : ""}` : ""
    const live = label ? startProgress(label, { timer: true }) : undefined
    let received = 0
    const updateLive = (bytes: number) => {
      if (!live) return
      received += bytes
      live.update(`${label} · ${formatBytes(received)} received`)
    }

    const timer = setTimeout(() => {
      timedOut = true
      try {
        child.kill("SIGKILL")
      } catch {
        /* already dead */
      }
    }, timeoutMs)

    const finish = (exitCode: number | null, problems: string[]) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (live) {
        if (exitCode === 0 && !timedOut) live.succeed(`${label} · ${formatElapsed(Date.now() - started).slice(1, -1)}`)
        else live.fail(`${label} · ${timedOut ? "timed out" : `exit ${exitCode}`}`)
      }
      resolve({
        ok: exitCode === 0 && !timedOut,
        command: printable,
        exitCode,
        stdout: opts.includeSecrets === false ? redactSecrets(stdout) : stdout,
        stderr: opts.includeSecrets === false ? redactSecrets(stderr) : stderr,
        durationMs: Date.now() - started,
        timedOut,
        truncated,
        problems,
      })
    }

    child.stdout?.on("data", (d: Buffer) => {
      updateLive(d.length)
      if (stdout.length + d.length > maxBytes) {
        truncated = true
        stdout += d.toString("utf8").slice(0, Math.max(0, maxBytes - stdout.length))
        return
      }
      stdout += d.toString("utf8")
    })
    child.stderr?.on("data", (d: Buffer) => {
      updateLive(d.length)
      if (stderr.length > 64 * 1024) return
      stderr += d.toString("utf8")
    })
    child.on("error", (e) => finish(null, [`${bin} failed: ${e.message}`]))
    child.on("close", (code) => {
      const problems: string[] = []
      if (timedOut) problems.push(`scan exceeded ${timeoutMs}ms and was killed`)
      if (truncated) problems.push(`output exceeded ${maxBytes} bytes and was truncated`)
      if (code !== 0 && !timedOut) problems.push(`${bin} exited with code ${code}`)
      finish(code, problems)
    })
  })
}

/* ------------------------------------------------------------------ nmap --- */

export interface NmapPort {
  port: number
  protocol: string
  state: string
  service?: string
  product?: string
  version?: string
  extraInfo?: string
}

export interface NmapResult {
  host: string
  addresses: string[]
  hostnames: string[]
  ports: NmapPort[]
  osMatches: string[]
  scriptOutput: string[]
  raw: string
}

export type NmapProfile = "connect" | "service" | "intrusive"

export function buildNmapArgs(host: string, profile: NmapProfile, ports?: number[]): string[] {
  const args = ["-Pn", "-oX", "-", "--host-timeout", "300s"]
  if (profile === "connect") args.push("-sT")
  if (profile === "service") args.push("-sT", "-sV", "--version-light")
  if (profile === "intrusive") args.push("-sS", "-sV", "-O", "--script", "safe")
  if (ports && ports.length) args.push("-p", ports.join(","))
  else args.push("--top-ports", "200")
  // host is always the final, separate argv element — never concatenated
  args.push("--", host)
  return args
}

export function parseNmapXml(xml: string): NmapResult {
  const out: NmapResult = { host: "", addresses: [], hostnames: [], ports: [], osMatches: [], scriptOutput: [], raw: xml }
  const addrRe = /<address addr="([^"]+)" addrtype="([^"]+)"/g
  for (const m of xml.matchAll(addrRe)) out.addresses.push(m[1])
  const hostnameRe = /<hostname name="([^"]+)"/g
  for (const m of xml.matchAll(hostnameRe)) out.hostnames.push(m[1])

  const portRe = /<port protocol="([^"]+)" portid="(\d+)">([\s\S]*?)<\/port>/g
  for (const m of xml.matchAll(portRe)) {
    const body = m[3]
    const state = /<state state="([^"]+)"/.exec(body)?.[1] ?? "unknown"
    const svc = /<service name="([^"]*)"(?:[^>]*product="([^"]*)")?(?:[^>]*version="([^"]*)")?/.exec(body)
    const extra = /<service[^>]*extrainfo="([^"]*)"/.exec(body)?.[1]
    out.ports.push({
      protocol: m[1],
      port: Number(m[2]),
      state,
      service: svc?.[1] || undefined,
      product: svc?.[2] || undefined,
      version: svc?.[3] || undefined,
      extraInfo: extra || undefined,
    })
  }
  const osRe = /<osmatch name="([^"]+)" accuracy="(\d+)"/g
  for (const m of xml.matchAll(osRe)) out.osMatches.push(`${m[1]} (${m[2]}%)`)
  const scriptRe = /<script id="([^"]+)"[^>]*output="([^"]*)"/g
  for (const m of xml.matchAll(scriptRe)) out.scriptOutput.push(`${m[1]}: ${m[2].replace(/&#xa;/g, "\n").slice(0, 2000)}`)
  return out
}

export async function runNmap(
  host: string,
  profile: NmapProfile,
  ports: number[] | undefined,
  bin: string,
  opts: RunOptions = {},
): Promise<{ run: ScanRunResult; result?: NmapResult }> {
  const args = buildNmapArgs(host, profile, ports)
  const run = await runArgv(bin, args, { ...opts, timeoutMs: opts.timeoutMs ?? 300000, host })
  if (!run.stdout.trim()) return { run }
  return { run, result: parseNmapXml(run.stdout) }
}

/* --------------------------------------------------------------- nuclei --- */

export interface NucleiFinding {
  templateId: string
  name: string
  severity: Severity
  matchedAt: string
  description?: string
  reference?: string[]
  tags?: string[]
  extracted?: string[]
}

export function parseNucleiJsonl(text: string): NucleiFinding[] {
  const out: NucleiFinding[] = []
  for (const line of text.split("\n")) {
    const t = line.trim()
    if (!t.startsWith("{")) continue
    try {
      const j = JSON.parse(t) as Record<string, unknown>
      const info = (j.info ?? {}) as Record<string, unknown>
      const sev = String(info.severity ?? "info").toLowerCase()
      out.push({
        templateId: String(j["template-id"] ?? j.templateID ?? "unknown"),
        name: String(info.name ?? j["template-id"] ?? "unknown"),
        severity: (["info", "low", "medium", "high", "critical"].includes(sev) ? sev : "info") as Severity,
        matchedAt: String(j["matched-at"] ?? j.host ?? ""),
        description: info.description ? String(info.description) : undefined,
        reference: Array.isArray(info.reference) ? info.reference.map(String) : undefined,
        tags: Array.isArray(info.tags) ? info.tags.map(String) : undefined,
        extracted: Array.isArray(j["extracted-results"]) ? j["extracted-results"].map(String) : undefined,
      })
    } catch {
      /* skip malformed line */
    }
  }
  return out
}

export function buildNucleiArgs(url: string, intensity: Intensity, severity?: Severity[]): string[] {
  const args = ["-u", url, "-jsonl", "-silent", "-nc", "-timeout", "10", "-no-color"]
  if (severity?.length) args.push("-severity", severity.join(","))
  if (intensity === "passive" || intensity === "safe-active") {
    // read-only template families only; no fuzzing or brute force
    args.push("-tags", "cve,misconfig,exposure,default-login,tech")
  } else {
    args.push("-tags", "cve,misconfig,exposure,default-login,tech,vuln,fuzz")
  }
  args.push("-rl", intensity === "exploit" ? "150" : "50")
  return args
}

/* ------------------------------------------------------- generic tempfile --- */

/** Adapters whose CLI only writes structured output to a file (nikto). */
export async function runWithTempfile(
  bin: string,
  buildArgs: (tmp: string) => string[],
  opts: RunOptions = {},
): Promise<{ run: ScanRunResult; file: string }> {
  const tmp = join(tmpdir(), `nullbyte-${Date.now()}-${Math.floor(Math.random() * 1e6)}.json`)
  const run = await runArgv(bin, buildArgs(tmp), opts)
  return { run, file: tmp }
}

export function readTempfile(path: string): string {
  try {
    return readFileSync(path, "utf8")
  } catch {
    return ""
  } finally {
    try {
      unlinkSync(path)
    } catch {
      /* already gone */
    }
  }
}

/** nikto JSON output is an array of objects with `id`, `msg`, `url`, `method`. */
export interface NiktoFinding {
  id: string
  msg: string
  url?: string
  method?: string
}

export function parseNiktoJson(text: string): NiktoFinding[] {
  try {
    const parsed = JSON.parse(text)
    const items = Array.isArray(parsed) ? parsed : Array.isArray((parsed as Record<string, unknown>).vulnerabilities) ? ((parsed as Record<string, unknown>).vulnerabilities as unknown[]) : []
    return items.map((i) => {
      const o = i as Record<string, unknown>
      return {
        id: String(o.id ?? o.OSVDB ?? "unknown"),
        msg: String(o.msg ?? o.message ?? ""),
        url: o.url ? String(o.url) : undefined,
        method: o.method ? String(o.method) : undefined,
      }
    })
  } catch {
    return []
  }
}

/** WhatWeb `--log-json=-` emits one JSON object per line. */
export interface WhatWebFinding {
  target: string
  plugins: Record<string, unknown>
}

export function parseWhatWebJson(text: string): WhatWebFinding[] {
  const out: WhatWebFinding[] = []
  for (const line of text.split("\n")) {
    const t = line.trim()
    if (!t.startsWith("{")) continue
    try {
      const j = JSON.parse(t) as Record<string, unknown>
      out.push({ target: String(j.target ?? ""), plugins: (j.plugins ?? {}) as Record<string, unknown> })
    } catch {
      /* skip */
    }
  }
  return out
}
