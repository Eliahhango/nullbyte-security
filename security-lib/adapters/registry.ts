/**
 * External security tool detection.
 *
 * Nothing is assumed to be installed. Every adapter checks availability and
 * version up front and degrades to an explicit capability warning with install
 * guidance instead of crashing or inventing results.
 */

import { spawnSync } from "node:child_process"
import { accessSync, constants } from "node:fs"

export interface ToolAvailability {
  id: string
  name: string
  available: boolean
  path?: string
  version?: string
  capabilities: string[]
  installHint: string
}

interface ToolSpec {
  id: string
  name: string
  versionArgs: string[]
  capabilities: string[]
  installHint: string
}

export const TOOL_SPECS: ToolSpec[] = [
  {
    id: "nmap",
    name: "Nmap",
    versionArgs: ["--version"],
    capabilities: ["port-scan", "service-detect", "os-detect", "nse-scripts"],
    installHint: "sudo apt-get install -y nmap",
  },
  {
    id: "nuclei",
    name: "Nuclei",
    versionArgs: ["-version"],
    capabilities: ["template-scan", "cve-detection", "misconfig-detection"],
    installHint: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
  },
  {
    id: "nikto",
    name: "Nikto",
    versionArgs: ["-Version"],
    capabilities: ["web-misconfig-scan"],
    installHint: "sudo apt-get install -y nikto",
  },
  {
    id: "whatweb",
    name: "WhatWeb",
    versionArgs: ["--version"],
    capabilities: ["tech-fingerprint"],
    installHint: "sudo apt-get install -y whatweb",
  },
  {
    id: "sslscan",
    name: "sslscan",
    versionArgs: ["--version"],
    capabilities: ["tls-config-audit"],
    installHint: "sudo apt-get install -y sslscan",
  },
  {
    id: "sqlmap",
    name: "sqlmap",
    versionArgs: ["--version"],
    capabilities: ["injection-testing"],
    installHint: "sudo apt-get install -y sqlmap",
  },
]

function which(bin: string): string | undefined {
  const r = spawnSync("sh", ["-c", `command -v ${JSON.stringify(bin)}`], { encoding: "utf8", timeout: 4000 })
  const p = (r.stdout ?? "").trim().split("\n")[0]
  return p && r.status === 0 ? p : undefined
}

function firstLine(s: string): string | undefined {
  const l = s.split("\n").map((x) => x.trim()).find(Boolean)
  return l ? l.slice(0, 160) : undefined
}

let cache: Record<string, ToolAvailability> | null = null

/** Detect every known external tool. Cached per process. */
export function detectTools(force = false): Record<string, ToolAvailability> {
  if (cache && !force) return cache
  const out: Record<string, ToolAvailability> = {}
  for (const spec of TOOL_SPECS) {
    const path = which(spec.id)
    let version: string | undefined
    let available = false
    if (path) {
      available = true
      try {
        accessSync(path, constants.X_OK)
      } catch {
        available = false
      }
      if (available) {
        const r = spawnSync(path, spec.versionArgs, { encoding: "utf8", timeout: 8000 })
        const text = `${r.stdout ?? ""}\n${r.stderr ?? ""}`
        // strip ANSI colour codes and collapse whitespace: several scanners
        // colourise their version banner or pad it with tabs
        version = firstLine(text)
          ?.replace(/\u001b\[[0-9;]*[A-Za-z]/g, "")
          .replace(/\s+/g, " ")
          .trim()
      }
    }
    out[spec.id] = {
      id: spec.id,
      name: spec.name,
      available,
      path,
      version,
      capabilities: spec.capabilities,
      installHint: spec.installHint,
    }
  }
  cache = out
  return out
}

export function requireTool(id: string): { ok: true; tool: ToolAvailability } | { ok: false; problem: string } {
  const tools = detectTools()
  const t = tools[id]
  if (!t) return { ok: false, problem: `unknown tool adapter '${id}'` }
  if (!t.available) {
    return {
      ok: false,
      problem: `${t.name} is not installed, so this capability is unavailable. Install it with: ${t.installHint}`,
    }
  }
  return { ok: true, tool: t }
}

/** Human-readable capability report for the model. */
export function capabilityReport(): string {
  const tools = detectTools()
  const lines = ["external tool availability:"]
  for (const t of Object.values(tools)) {
    lines.push(
      t.available
        ? `  [x] ${t.name}${t.version ? ` — ${t.version}` : ""} (${t.capabilities.join(", ")})`
        : `  [ ] ${t.name} — missing; install with: ${t.installHint}`,
    )
  }
  return lines.join("\n")
}

/** Reset the detection cache (used by tests). */
export function resetToolCache(): void {
  cache = null
}
