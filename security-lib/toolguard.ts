/**
 * The enforcement hook (`tool.execute.before`).
 *
 * Verified against the OpenCode runtime: this hook is awaited *inside* the tool
 * executor, so throwing here aborts the call before the tool body runs. That
 * makes scope and policy enforcement a property of the execution path rather
 * than a promise made in a system prompt.
 *
 * Responsibilities:
 *   - bash: static analysis, out-of-scope target refusal, destructive refusal
 *   - webfetch: target authorization
 *   - read/write/edit: refusal to touch local credential stores
 *   - everything: audit record
 *
 * Interactive approval for intrusive operations is delegated to OpenCode's own
 * permission system (rules injected by the plugin's `config` hook, and
 * `ToolContext.ask()` inside the sec_* tools) so the native model is preserved.
 */

import { analyzeCommand } from "./cmdsafe.ts"
import { loadScope } from "./config.ts"
import { authorize } from "./scope.ts"
import { resolveAddresses } from "./net/dns.ts"
import { writeAudit } from "./audit.ts"
import { hostFromUrl, isIp, isUnconditionallyDenied } from "./netsafe.ts"
import type { Decision, Intensity, Target } from "./types.ts"

export interface GuardDeps {
  /** project worktree the plugin was initialised for */
  worktree: string
  /** disable the local-credential protection (default: enabled) */
  protectLocalSecrets?: boolean
}

/** Paths that hold credentials and must not be read by a model by default. */
const SENSITIVE_PATTERNS: Array<{ re: RegExp; why: string }> = [
  { re: /(^|\/)\.ssh\/(id_|.*_rsa$|.*_ed25519$|.*_ecdsa$|.*_dsa$)/, why: "SSH private key" },
  { re: /(^|\/)\.ssh\/.*\.pub$/, why: "SSH public key (low risk, blocked for consistency)" },
  { re: /(^|\/)\.aws\/credentials$/, why: "AWS credentials file" },
  { re: /(^|\/)\.config\/gcloud\//, why: "gcloud credentials" },
  { re: /(^|\/)\.kube\/config$/, why: "Kubernetes client config" },
  { re: /(^|\/)\.docker\/config\.json$/, why: "Docker registry credentials" },
  { re: /(^|\/)\.netrc$/, why: "netrc credentials" },
  { re: /(^|\/)\.git-credentials$/, why: "stored git credentials" },
  { re: /(^|\/)\.npmrc$/, why: "npm auth token" },
  { re: /(^|\/)\.pypirc$/, why: "PyPI credentials" },
  { re: /(^|\/)\.gnupg\//, why: "GnuPG keyring" },
  { re: /(^|\/)\.config\/nullbyte\/auth\.json$/, why: "NullByte provider credentials" },
  { re: /(^|\/)\.local\/share\/nullbyte\/auth\.json$/, why: "NullByte provider credentials" },
  { re: /(^|\/)\.config\/gh\/hosts\.yml$/, why: "GitHub CLI token" },
  { re: /(^|\/)Cookies?($|\/)/, why: "browser cookie database" },
  { re: /(^|\/)Login Data$/, why: "browser saved-password database" },
  { re: /(^|\/)\.config\/nullbyte\/security\.json$/, why: "security policy (blocked from model edits)" },
  { re: /(^|\/)\.nullbyte\/security\/scope\.json$/, why: "engagement scope (operator-authored, not model-editable)" },
]

export function isSensitivePath(path: string): { sensitive: boolean; why?: string } {
  const p = path.replace(/\\/g, "/")
  const expanded = p.startsWith("~/") ? p.slice(2) : p
  for (const rule of SENSITIVE_PATTERNS) {
    if (rule.re.test(expanded)) return { sensitive: true, why: rule.why }
  }
  return { sensitive: false }
}

export class GuardBlocked extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(`[sec] ${message}`)
    this.name = "GuardBlocked"
    this.code = code
  }
}

export interface GuardInput {
  tool: string
  sessionID: string
  callID: string
}

export interface GuardOutput {
  args: any
}

/** Build the `tool.execute.before` handler. */
export function createToolGuard(deps: GuardDeps) {
  return async (input: GuardInput, output: GuardOutput): Promise<void> => {
    const tool = input.tool
    const protect = deps.protectLocalSecrets !== false
    const loaded = loadScope(deps.worktree)
    const root = loaded.paths.root

    const deny = (code: string, reason: string, extra?: { args?: string; targets?: string[] }): never => {
      writeAudit(root, {
        sessionID: input.sessionID,
        tool,
        decision: "deny",
        code,
        reason,
        args: extra?.args,
        targets: extra?.targets,
      })
      throw new GuardBlocked(code, reason)
    }

    // ---- local credential protection (read/write/edit and friends) ----
    if (protect && ["read", "write", "edit", "list", "glob", "grep", "patch"].includes(tool)) {
      const p = output.args?.filePath ?? output.args?.path ?? output.args?.file ?? ""
      if (typeof p === "string" && p) {
        const hit = isSensitivePath(p)
        if (hit.sensitive) {
          deny(
            "local.secret",
            `refusing to touch ${p}: it looks like a ${hit.why}. Ask the operator to share the specific value if it is genuinely needed, ` +
              `or set protect_local_secrets=false in the security policy if this engagement requires it.`,
            { args: p },
          )
        }
      }
    }

    // ---- webfetch ----
    if (tool === "webfetch") {
      const url = String(output.args?.url ?? "")
      const parsed = hostFromUrl(url)
      if (!parsed) {
        writeAudit(root, { sessionID: input.sessionID, tool, decision: "allow", code: "webfetch.unparsed", reason: `no host in '${url}'` })
        return
      }
      if (loaded.scope.authorized_all) {
        writeAudit(root, {
          sessionID: input.sessionID,
          tool,
          decision: "allow",
          code: "scope.authorized-all",
          reason: `'${parsed.host}' is permitted (authorized_all)`,
          args: url,
          targets: [parsed.host],
        })
        return
      }
      const target: Target = { host: parsed.host, port: parsed.port, scheme: parsed.scheme }
      const decision = authorize(loaded.scope, target, "passive")
      if (!decision.allowed) {
        deny(decision.code, `${decision.reason}. webfetch to '${parsed.host}' is not authorized; only declared scope may be contacted.`, {
          args: url,
          targets: [parsed.host],
        })
      }
      writeAudit(root, {
        sessionID: input.sessionID,
        tool,
        decision: "allow",
        code: decision.code,
        reason: decision.reason,
        args: url,
        targets: [parsed.host],
      })
      return
    }

    // ---- bash ----
    if (tool !== "bash") return
    const cmd = String(output.args?.command ?? "")
    if (!cmd.trim()) return

    const analysis = analyzeCommand(cmd)

    // 1. destructive operations (only when the operator left the guard on)
    if (analysis.destructive.length && loaded.scope.block_destructive) {
      deny(
        "policy.destructive",
        `refusing to run a destructive command (${analysis.destructive.join("; ")}). This guard protects the machine you are ` +
          `operating from and is unrelated to target authorization. Set "block_destructive": false in ` +
          `${root}/scope.json (or ~/.config/nullbyte/security.json) to disable it.`,
        { args: cmd },
      )
    }

    // 2. authorized-by-default: no scope ceremony, just record what ran
    if (loaded.scope.authorized_all) {
      writeAudit(root, {
        sessionID: input.sessionID,
        tool,
        decision: "allow",
        code: "cmd.authorized-all",
        reason: `authorized_all: ${analysis.targets.length ? analysis.targets.join(", ") : "no network target"}`,
        args: cmd,
        targets: analysis.targets,
      })
      return
    }

    // 3. allow-list mode: every extracted target must be authorized
    const refused: string[] = []
    const refusedCodes: string[] = []
    let maxRisk: Intensity = analysis.risk
    for (const raw of analysis.targets) {
      const target = parseTargetToken(raw)
      if (!target) continue
      const decision: Decision = authorize(loaded.scope, target, analysis.risk)
      if (!decision.allowed) {
        refused.push(`${target.host}${target.port ? `:${target.port}` : ""} (${decision.reason})`)
        refusedCodes.push(decision.code)
      } else if (decision.intensity && decision.intensity === "intrusive") maxRisk = "intrusive"
    }
    if (refused.length) {
      deny(
        refusedCodes.length === 1 ? refusedCodes[0] : "scope.miss",
        `refusing to run: ${refused.length} target(s) are outside the authorized scope — ${refused.join("; ")}. ` +
          `Authorized assets are listed by sec_scope. Do not retry with a rewritten command; ask the operator to extend scope if this target is legitimate.`,
        { args: cmd, targets: analysis.targets },
      )
    }

    // 4. shell wrappers / dynamic expansion defeat static scope checking
    if (analysis.wrappers.length || analysis.dynamic) {
      const why = analysis.wrappers.length
        ? `command is wrapped in '${analysis.wrappers.join("/")}', which hides the real operation from scope checking`
        : "command uses expansion or pipes into an interpreter, so its real targets cannot be determined statically"
      deny(
        "policy.unanalyzable",
        `refusing to run: ${why}. Issue the underlying command directly (for example, call the target tool with the host as an ` +
          `argument) so it can be scope-checked. If the operator has approved this specific command, they can run it themselves.`,
        { args: cmd },
      )
    }

    // 5. otherwise allowed — record it. Intrusive-but-in-scope commands are
    //    surfaced to the operator by the permission rules injected in config().
    writeAudit(root, {
      sessionID: input.sessionID,
      tool,
      decision: maxRisk === "intrusive" || maxRisk === "exploit" ? "ask" : "allow",
      code: `cmd.${maxRisk}`,
      reason: analysis.intrusive.length ? `intrusive: ${analysis.intrusive.join("; ")}` : "no intrusive indicators",
      args: cmd,
      targets: analysis.targets,
    })
  }
}

/** Turn a raw token from a command into a Target without network I/O. */
export function parseTargetToken(raw: string): Target | null {
  const t = raw.trim()
  if (!t) return null
  if (t.includes("://")) {
    const parsed = hostFromUrl(t)
    if (!parsed) return null
    const denied = isUnconditionallyDenied(parsed.host)
    if (denied.denied) return { host: parsed.host }
    return { host: parsed.host, port: parsed.port, scheme: parsed.scheme, path: parsed.path }
  }
  const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(t)
  if (cidr) return { host: t }
  const withPort = /^(\[[^\]]+\]|[^:\s]+):(\d{1,5})$/.exec(t)
  if (withPort) {
    const host = withPort[1].replace(/^\[|\]$/g, "")
    return { host, port: Number(withPort[2]) }
  }
  if (isIp(t) || /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(t)) return { host: t }
  return null
}

/**
 * Native permission rules injected into OpenCode's own permission model.
 *
 * DENY rules are always safe to inject: they are defence in depth for the same
 * destructive patterns the guard already refuses.
 *
 * ASK rules are OPT-IN. Prompting for intrusive scanners stalls non-interactive
 * runs (`nullbyte run`), which defeats the point of an agentic CLI, so they are
 * only injected when the operator sets `plugins.ask_intrusive_commands: true`.
 */
export function securityDenyRules(): Record<string, string> {
  return {
    "rm -rf *": "deny",
    "rm -fr *": "deny",
    "mkfs*": "deny",
    "dd *": "deny",
    "shutdown *": "deny",
    "reboot *": "deny",
  }
}

export function securityAskRules(): Record<string, string> {
  return {
    "nmap *": "ask",
    "masscan *": "ask",
    "sqlmap *": "ask",
    "hydra *": "ask",
    "medusa *": "ask",
    "ncrack *": "ask",
    "patator *": "ask",
    "john *": "ask",
    "hashcat *": "ask",
    "msfconsole *": "ask",
    "msfvenom *": "ask",
    "nuclei *": "ask",
    "nikto *": "ask",
    "wpscan *": "ask",
    "gobuster *": "ask",
    "ffuf *": "ask",
    "dirb *": "ask",
    "wfuzz *": "ask",
  }
}

/** Full rule set (deny + ask). Used by tests and by the opt-in policy. */
export function securityPermissionRules(): Record<string, string> {
  return { ...securityDenyRules(), ...securityAskRules() }
}

/** Resolve a hostname and re-validate; exported for tests. */
export async function revalidateResolved(host: string, ips: string[]): Promise<string[]> {
  const resolved = ips.length ? ips : await resolveAddresses(host, 3000)
  return resolved
}
