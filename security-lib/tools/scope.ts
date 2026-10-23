/**
 * sec_scope — read, validate and test the authorized scope.
 *
 * The model can inspect and test scope but cannot create or widen it: `init`
 * refuses unless the operator explicitly enabled `allow_model_scope_edit`.
 */

import { tool } from "@opencode-ai/plugin"
import { existsSync, readFileSync, writeFileSync } from "node:fs"
import { loadScope, scopeTemplate, validateScope } from "../config.ts"
import { authorize, describeScope } from "../scope.ts"
import { describeLimitsOf } from "../ratelimit.ts"
import { writeAudit } from "../audit.ts"
import { splitTarget, projectRootFor, type ToolCtxLike } from "./shared.ts"
import { ensureTargetQuietly } from "../target-dir.ts"
import type { Intensity } from "../types.ts"

const INTENSITIES = ["passive", "safe-active", "intrusive", "exploit"] as const

export const secScope = tool({
  description:
    "Read, validate or test the authorized engagement scope. Call this FIRST in any security assessment. " +
    "Returns the authorized assets, exclusions, permitted intensity and the scope file location. " +
    "Use action=check with a target to test whether a specific host is authorized before touching it. " +
    "The model cannot create or widen scope: action=init is refused unless the operator enabled allow_model_scope_edit.",
  args: {
    action: tool.schema.enum(["show", "check", "init"]).describe("show = read scope, check = test one target, init = write a starter scope file (usually refused)"),
    target: tool.schema.string().optional().describe("host, IP, CIDR or URL to test (action=check)"),
    intensity: tool.schema.enum(INTENSITIES).optional().describe("intensity to test against (action=check), default passive"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const loaded = loadScope(c.worktree)

    if (args.action === "init") {
      if (!loaded.scope.allow_model_scope_edit) {
        return [
          "refused: scope is operator-authored and this engagement does not allow the model to write it.",
          "",
          `Ask the operator to create: ${loaded.paths.scope}`,
          "",
          "Suggested content for an authorized local lab:",
          "```json",
          JSON.stringify(scopeTemplate(), null, 2),
          "```",
          "",
          "Scope is deliberately not writable by the agent so a generated plan can never widen authorization.",
        ].join("\n")
      }
      if (existsSync(loaded.paths.scope)) return `scope file already exists at ${loaded.paths.scope}; not overwriting`
      writeFileSync(loaded.paths.scope, JSON.stringify(scopeTemplate(), null, 2), { mode: 0o600 })
      writeAudit(loaded.paths.root, { sessionID: c.sessionID, agent: c.agent, tool: "sec_scope", decision: "allow", code: "scope.init", reason: "wrote starter scope file" })
      return `wrote starter scope to ${loaded.paths.scope}`
    }

    if (args.action === "check") {
      if (!args.target) return "error: action=check requires a target"
      const target = splitTarget(args.target)
      const intensity = (args.intensity ?? "passive") as Intensity
      const decision = authorize(loaded.scope, target, intensity)
      writeAudit(loaded.paths.root, {
        sessionID: c.sessionID,
        agent: c.agent,
        tool: "sec_scope",
        decision: decision.allowed ? "allow" : "deny",
        code: decision.code,
        reason: decision.reason,
        targets: [target.host],
      })
      // Naming an authorized target is enough to give it a directory, so the
      // operator can see where its output will land before anything runs. A
      // denied target gets nothing — the directory is a consequence of
      // authorization, not of the request.
      const targetDirLine = decision.allowed
        ? (() => {
            const paths = ensureTargetQuietly(projectRootFor(c), target.host)
            return paths ? `target directory: ${paths.root}` : ""
          })()
        : ""
      return [
        `target: ${target.host}${target.port ? `:${target.port}` : ""}`,
        `requested intensity: ${intensity}`,
        `decision: ${decision.allowed ? "AUTHORIZED" : "DENIED"}`,
        `code: ${decision.code}`,
        `reason: ${decision.reason}`,
        decision.matched ? `matched entry: ${decision.matched}` : "",
        targetDirLine,
        decision.requiresApproval ? "note: this operation additionally requires interactive operator approval" : "",
      ]
        .filter(Boolean)
        .join("\n")
    }

    let raw: unknown = {}
    const hasFile = existsSync(loaded.paths.scope)
    if (hasFile) {
      try {
        raw = JSON.parse(readFileSync(loaded.paths.scope, "utf8"))
      } catch {
        raw = {}
      }
    }
    const problems = validateScope(raw)
    return [
      describeScope(loaded.scope, loaded.source, loaded.warnings),
      "",
      `pacing: ${describeLimitsOf(loaded.scope.limits)}`,
      "",
      hasFile
        ? problems.length
          ? `validation problems:\n${problems.map((p) => `  ! ${p}`).join("\n")}`
          : "scope document is structurally valid"
        : "no scope file present — operating in the default authorized-all mode (nothing to declare)",
      "",
      `scope file: ${loaded.paths.scope}`,
      `engagement dir: ${loaded.paths.root}`,
    ].join("\n")
  },
})
