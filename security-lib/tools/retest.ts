/**
 * sec_retest — re-check a finding's reproduction and record what happened.
 *
 * A finding is a claim about a running system, and systems change: a fix lands,
 * a WAF is added, a parameter is sanitised. Without a retest the engagement
 * store only ever records the first observation, so a report can describe as
 * confirmed something that stopped being true weeks ago.
 *
 * action=run re-executes a command under the same scope and destructive-command
 * guards as every other tool, captures the output as evidence, and records the
 * result. action=record records a re-check the operator performed by hand.
 */

import { spawnSync } from "node:child_process"
import { tool } from "@opencode-ai/plugin"
import { analyzeCommand, tokenize } from "../cmdsafe.ts"
import { saveEvidence } from "../evidence.ts"
import { getFinding, recordRetest } from "../findings.ts"
import type { Intensity, VerificationStatus } from "../types.ts"
import { enforce, scopeFor, splitTarget, type ToolCtxLike } from "./shared.ts"

const STATUSES = ["verified", "refuted", "inconclusive"] as const
const MAX_OUTPUT = 64 * 1024

export const secRetest = tool({
  description:
    "Re-execute a finding's reproduction and record the result, so the store reflects whether the issue still reproduces " +
    "rather than only what was seen the first time. action=run executes a command under the same scope, destructive-command " +
    "and audit guards as the other tools, saves its output as evidence, and appends a dated retest entry; action=record logs " +
    "a re-check you performed by hand. Every retest is appended, never overwritten, and records the verification status " +
    "before and after. A retest that contradicts the recorded closure (a refuted on a confirmed finding, a verified on a " +
    "ruled-out one) reopens the finding to open_proof_gap instead of leaving the store asserting two incompatible things.",
  args: {
    id: tool.schema.string().describe("finding id to retest"),
    action: tool.schema.enum(["run", "record"]).describe("run a command, or record a manual re-check"),
    command: tool.schema.string().optional().describe("command to re-execute (action=run)"),
    method: tool.schema.string().optional().describe("how the check was performed, e.g. 'curl -s /search?q=...' (action=record)"),
    status: tool.schema.enum(STATUSES).optional().describe("verification status this retest establishes (action=record; action=run derives it from the exit code and output unless given)"),
    observed: tool.schema.string().optional().describe("what was observed (action=record; action=run fills it from the output unless given)"),
    intensity: tool.schema.enum(["passive", "safe-active", "intrusive", "exploit"]).optional().describe("operation intensity to authorize (action=run)"),
    timeout_ms: tool.schema.number().optional().describe("command timeout in milliseconds (action=run, default 60000)"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const root = scopeFor(c.worktree).paths.root

    const finding = getFinding(root, args.id)
    if (!finding) return `error: finding ${args.id} not found`

    if (args.action === "record") {
      if (!args.status) return "error: action=record requires status (verified | refuted | inconclusive)"
      if (!args.method) return "error: action=record requires method — how was the check performed?"
      if (!args.observed) return "error: action=record requires observed — what did you see?"
      const res = recordRetest(root, args.id, {
        by: c.agent,
        method: args.method,
        status: args.status as VerificationStatus,
        observed: args.observed,
      })
      if (!res.finding) return `retest rejected:\n${(res.problems ?? []).map((p) => `  - ${p}`).join("\n")}`
      const notes = (res.problems ?? []).map((p) => `\nnote: ${p}`).join("")
      return (
        `recorded retest of ${res.finding.id} — verification ${res.entry!.before} → ${res.entry!.after}` +
        `\nstatus: ${res.finding.status}, closure: ${res.finding.closure}, revision ${res.finding.revision}` +
        notes
      )
    }

    // ---- action=run -------------------------------------------------------
    if (!args.command) return "error: action=run requires command"

    const analysis = analyzeCommand(args.command)
    if (analysis.destructive.length) {
      return `refused: the command is destructive (${analysis.destructive.join("; ")}). A retest re-runs a reproduction; it does not modify or damage the target.`
    }
    if (analysis.wrappers.length) {
      return (
        `refused: the command is wrapped in ${analysis.wrappers.map((w) => `'${w}'`).join(", ")}, which hides what it actually does ` +
        `from static analysis. Run the real command directly, or use action=record for a check you perform yourself.`
      )
    }
    if (analysis.dynamic) {
      return (
        "refused: the command uses expansion or pipes into an interpreter, so the hosts it will contact cannot be determined " +
        "before running it. A retest is authorized per host, and authorizing a command whose destination is unknown would " +
        "defeat that. Write the literal command, or use action=record for a check you perform yourself."
      )
    }

    const intensity: Intensity = args.intensity ?? analysis.risk

    // Authorize every host the command names, not just the finding's target. The
    // command is free text and may point somewhere else entirely — with an
    // allow-list scope, checking only the finding's target would authorize a
    // command aimed at a host the operator never included.
    const hosts = new Set<string>([finding.target, ...analysis.targets])
    const authorized: string[] = []
    for (const h of hosts) {
      const target = splitTarget(h)
      await enforce({
        ctx: c,
        tool: "sec_retest",
        target,
        intensity,
        purpose: `retest ${args.id}: ${args.command}`,
      })
      authorized.push(target.host)
    }

    const argv = tokenize(args.command)
    if (!argv.length) return "error: no executable found in command"
    const timeout = args.timeout_ms ?? 60_000

    const r = spawnSync(argv[0]!, argv.slice(1), {
      encoding: "utf8",
      timeout,
      maxBuffer: 8 * 1024 * 1024,
      cwd: c.worktree,
    })
    if (r.error) {
      const e = r.error as NodeJS.ErrnoException
      if (e.code === "ENOENT") return `refused: '${argv[0]}' is not installed or not on PATH`
      return `retest failed to run: ${e.message}`
    }

    const exit = r.status ?? (r.signal ? 128 : -1)
    const body = [r.stdout ?? "", r.stderr ? `\n--- stderr ---\n${r.stderr}` : ""].join("").slice(0, MAX_OUTPUT)
    const header = `$ ${args.command}\nexit ${exit}\n# retest of ${finding.id} (${finding.title}) — authorized: ${authorized.join(", ")}\n\n`
    const transcript = header + body

    // capture output as evidence so the retest is quotable, keeping the same
    // verbatim-by-default posture as every other capture path
    const saved = saveEvidence(root, {
      sessionID: c.sessionID,
      source: "sec_retest",
      label: `retest ${finding.id}: ${args.command}`.slice(0, 200),
      content: transcript,
      target: finding.target,
    })

    const status: VerificationStatus =
      (args.status as VerificationStatus | undefined) ??
      (exit === 0 && body.trim() ? "verified" : exit === 0 ? "inconclusive" : "refuted")

    const res = recordRetest(root, args.id, {
      by: c.agent,
      method: args.command,
      command: args.command,
      status,
      observed: args.observed ?? `exit ${exit}${body.trim() ? "" : " (no output)"}`,
      evidenceId: saved.record?.id,
      exitCode: exit,
    })
    if (!res.finding) return `retest rejected:\n${(res.problems ?? []).map((p) => `  - ${p}`).join("\n")}`

    const lines = [
      `$ ${args.command}`,
      `exit ${exit}${r.signal ? ` (signal ${r.signal})` : ""}`,
      "",
      body.trim() ? body.slice(0, 4000) : "(no output)",
      "",
      `authorized: ${authorized.join(", ")}`,
      `retest recorded: ${res.entry!.before} → ${res.entry!.after}` +
        (saved.record ? `, evidence ${saved.record.id}` : ", evidence not saved") +
        `\nstatus: ${res.finding.status}, closure: ${res.finding.closure}, revision ${res.finding.revision}`,
    ]
    for (const p of res.problems ?? []) lines.push(`\nnote: ${p}`)
    return lines.join("\n")
  },
})
