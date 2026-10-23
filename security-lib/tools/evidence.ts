/**
 * sec_evidence — persist and retrieve raw supporting artifacts.
 * Content is redacted for secrets before it touches disk unless the caller
 * explicitly opts out with include_secrets, for artifacts whose value is the
 * secret itself.
 */

import { tool } from "@opencode-ai/plugin"
import {
  evidenceStoreStats,
  listEvidence,
  readEvidence,
  resolveEvidence,
  saveEvidence,
  verifyEvidenceStore,
  MAX_EVIDENCE_ARTIFACTS,
  MAX_EVIDENCE_STORE_BYTES,
} from "../evidence.ts"
import { loadScope } from "../config.ts"
import type { ToolCtxLike } from "./shared.ts"

export const secEvidence = tool({
  description:
    "Store or retrieve raw evidence supporting a finding. action=save persists output (HTTP transcripts, scanner output, " +
    "banners) and returns an id to reference from sec_finding; the raw value is written to disk verbatim by default and a " +
    "SHA-256 is recorded. action=list shows stored artifacts; action=stats reports retention usage; action=get returns one, " +
    "and refuses if the artifact no longer matches its recorded hash. action=verify re-hashes every artifact so tampering or " +
    "corruption is detected rather than silently reported as evidence. Prefer storing the minimal artifact " +
    "that demonstrates the issue. The operator's posture is full disclosure, so leaked credentials are kept in the clear and " +
    "appear in the report via sec_report evidence=full. Pass include_secrets=false to redact at capture instead — this is " +
    "irreversible: it cannot be undone by regenerating the report.",
  args: {
    action: tool.schema.enum(["save", "list", "get", "verify", "stats"]).describe("operation"),
    label: tool.schema.string().optional().describe("short description of what this evidence shows (save)"),
    content: tool.schema.string().optional().describe("raw artifact content (save)"),
    target: tool.schema.string().optional().describe("asset this evidence relates to (save)"),
    source: tool.schema.string().optional().describe("tool that produced it (save)"),
    include_secrets: tool.schema.boolean().optional().describe("store secret-like material verbatim (default true); false redacts at capture, irreversibly"),
    id: tool.schema.string().optional().describe("evidence id (get)"),
  },
  async execute(args, ctx: any) {
    const c = ctx as ToolCtxLike
    const root = loadScope(c.worktree).paths.root

    if (args.action === "save") {
      const res = saveEvidence(root, {
        sessionID: c.sessionID,
        source: args.source ?? "manual",
        label: args.label ?? "evidence",
        content: args.content ?? "",
        target: args.target,
        includeSecrets: args.include_secrets !== false,
      })
      if (!res.record) return `evidence rejected:\n${res.problems.map((p) => `  - ${p}`).join("\n")}`
      const r = res.record
      const note = r.redacted
        ? " — secrets redacted before storage"
        : " — stored verbatim, including any credentials"
      return `stored ${r.id} (${r.bytes} bytes, sha256 ${r.sha256.slice(0, 16)}…)${note}`
    }

    if (args.action === "stats") {
      const s = evidenceStoreStats(root)
      return [
        `evidence store: ${s.artifacts}/${MAX_EVIDENCE_ARTIFACTS} artifacts, ${s.bytes}/${MAX_EVIDENCE_STORE_BYTES} bytes`,
        s.full
          ? "AT LEAST ONE RETENTION BOUND IS REACHED — new captures will be refused until uncited artifacts are pruned."
          : "within retention bounds; new captures are accepted.",
        "Pruning is manual and deliberate: remove a file and its index entry together, only after detaching it from every finding that cites it. The report cannot cite an artifact that no longer exists.",
      ].join("\n")
    }

    if (args.action === "list") {
      const rows = listEvidence(root)
      if (!rows.length) return "no evidence stored yet"
      const s = evidenceStoreStats(root)
      return [
        `store: ${s.artifacts}/${MAX_EVIDENCE_ARTIFACTS} artifacts, ${s.bytes}/${MAX_EVIDENCE_STORE_BYTES} bytes${s.full ? " — FULL" : ""}`,
        ...rows.map((r) => `${r.id} [${r.source}] ${r.label} — ${r.target ?? "n/a"}, ${r.bytes} bytes, ${r.redacted ? "redacted" : "verbatim"}`),
      ].join("\n")
    }

    if (args.action === "verify") {
      const results = verifyEvidenceStore(root)
      if (!results.length) return "no evidence stored yet"
      const bad = results.filter((r) => r.state !== "ok")
      const head = `${results.length} artifact(s) checked: ${results.length - bad.length} verified${bad.length ? `, ${bad.length} FAILED` : ""}`
      if (!bad.length) return `${head}.\nEvery artifact matches the SHA-256 recorded when it was stored.`
      return [
        head + ".",
        ...bad.map((r) => {
          if (r.state === "missing") return `  ${r.id} MISSING — ${r.label} (indexed, but the file is gone)`
          if (r.state === "unhashed") return `  ${r.id} UNHASHED — ${r.label} (stored without a digest; cannot be verified)`
          return `  ${r.id} MODIFIED — ${r.label}\n    expected ${r.expected}\n    found    ${r.actual}`
        }),
        "An artifact that does not match its hash cannot be relied on as evidence. Re-capture it, and correct or close any finding that cites it.",
      ].join("\n")
    }

    if (!args.id) return "error: action=get requires id"
    const content = readEvidence(root, args.id)
    if (content === undefined) {
      const { missing } = resolveEvidence(root, [args.id])
      return `evidence ${args.id} not found${missing.length ? "" : " (index entry exists but file is missing)"}`
    }
    return content
  },
})
