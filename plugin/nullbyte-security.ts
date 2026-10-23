/**
 * NullByte security capability layer — plugin entry point.
 *
 * Auto-discovered from ~/.config/nullbyte/plugin/. It adds a security
 * assessment toolset to whatever agents already exist, enforces scope at the
 * tool-execution boundary, and injects the shared methodology. It does not
 * replace the agent system, providers, TUI, sessions or configuration.
 *
 * Enforcement layers, outermost first:
 *   1. config()                — native permission rules for intrusive/destructive commands
 *   2. tool.execute.before     — hard refusal: out-of-scope targets, destructive commands, local secrets
 *   3. sec_* tool bodies       — per-call authorization, DNS re-validation, ToolContext.ask() approval
 *   4. experimental.chat.system.transform — shared methodology (advisory, not enforcement)
 */

import type { Plugin } from "@opencode-ai/plugin"
import { buildSecurityTools } from "../security-lib/tools/index.ts"
import { createToolGuard, securityDenyRules, securityPermissionRules } from "../security-lib/toolguard.ts"
import { SECURITY_WORKFLOW, SECURITY_REMINDER } from "../security-lib/workflow.ts"
import { loadPluginPolicy, loadScope } from "../security-lib/config.ts"
import { setRuntimeRoot } from "../security-lib/paths.ts"
import { writeAudit } from "../security-lib/audit.ts"

/** Internal agents that never need the security methodology. */
const INTERNAL_AGENT = /^(title|summary|compaction|generate|task)/i

/** sessionID -> agent name, learned from chat.message. */
const sessionAgent = new Map<string, string | undefined>()
/** sessions that already received the full workflow block. */
const primed = new Set<string>()

export const NullByteSecurity: Plugin = async (input) => {
  // `directory` is the reliable project path on this build; `worktree` can be "/".
  const worktree = input.directory || input.worktree || process.cwd()
  setRuntimeRoot(worktree)
  const policy = loadPluginPolicy()

  const auditRoot = (() => {
    try {
      return loadScope(worktree).paths.root
    } catch {
      return ""
    }
  })()

  return {
    // ---- capability: the sec_* toolset ----
    tool: buildSecurityTools({ client: input.client as any }),

    // ---- layer 1: native permission rules for destructive commands ----
    config: async (cfg) => {
      if (!policy.inject_permission_rules) return
      const config = cfg as Record<string, any>
      const permission = (config.permission ??= {}) as Record<string, any>
      // Deny rules always; ask rules only when the operator opted in, because
      // prompting for intrusive scanners stalls non-interactive runs.
      const rules = policy.ask_intrusive_commands
        ? securityPermissionRules()
        : securityDenyRules()
      const bash = permission.bash
      if (bash === undefined || bash === "ask" || bash === "allow") {
        // no explicit map: install ours. Anything not listed keeps the default behaviour.
        permission.bash = { ...rules }
      } else if (bash && typeof bash === "object") {
        // operator-authored rules win over ours
        permission.bash = { ...rules, ...bash }
      }
    },

    // ---- layer 2: hard enforcement before any tool body runs ----
    "tool.execute.before": createToolGuard({
      worktree,
      protectLocalSecrets: policy.protect_local_secrets,
    }),

    // ---- approval observability: record what the operator was asked ----
    "permission.ask": async (permission, output) => {
      if (!auditRoot) return
      const p = permission as Record<string, any>
      writeAudit(auditRoot, {
        sessionID: p.sessionID,
        tool: p.type ?? "permission",
        decision: output.status === "deny" ? "deny" : output.status === "allow" ? "allow" : "ask",
        code: "permission.ask",
        reason: p.message ?? `permission requested for ${p.pattern ?? "unknown pattern"}`,
        args: typeof p.pattern === "string" ? p.pattern : undefined,
      })
    },

    // ---- remember which agent a session belongs to ----
    "chat.message": async (msg) => {
      if (msg.sessionID) sessionAgent.set(msg.sessionID, msg.agent)
    },

    // ---- layer 4: shared methodology ----
    "experimental.chat.system.transform": async (hinput, output) => {
      if (!policy.inject_workflow) return
      const sid = hinput.sessionID
      const agent = sid ? sessionAgent.get(sid) : undefined
      if (agent && INTERNAL_AGENT.test(agent)) return
      const first = !sid || !primed.has(sid)
      if (sid) primed.add(sid)
      output.system.push(first ? SECURITY_WORKFLOW : SECURITY_REMINDER)
    },

    dispose: async () => {
      sessionAgent.clear()
      primed.clear()
    },
  }
}

// NOTE: every export of a plugin file must be a function — the loader walks
// Object.values(module) and throws "Plugin export is not a function" otherwise.
// Do not add non-function exports here.
export default NullByteSecurity
