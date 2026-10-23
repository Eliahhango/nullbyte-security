/**
 * sec_audit action=reconcile — findings must have passed through the audited
 * tool layer. A direct store write is the case this exists to surface.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { secAudit } from "../tools/knowledge.ts"
import { secFinding } from "../tools/findings.ts"
import { createFinding } from "../findings.ts"
import type { FindingInput } from "../types.ts"

function project() {
  const worktree = mkdtempSync(join(tmpdir(), "nb-audit-reconcile-"))
  const root = join(worktree, ".nullbyte", "security")
  const ctx = { sessionID: "s1", agent: "void", directory: worktree, worktree } as any
  return { worktree, root, ctx }
}

const input = (title: string): FindingInput => ({
  title,
  description: "A distinct test issue.",
  impact: "Test impact.",
  target: "app.example.com",
  source: "manual",
  severity: "low",
  confidence: "high",
  verification: "unverified",
  evidence: "Observed during the test.",
  remediation: "Fix the control.",
})

test("a finding written directly to the store has no creation audit record", async () => {
  const p = project()
  createFinding(p.root, "s1", input("Direct store write"))
  const out = await secAudit.execute({ action: "reconcile" }, p.ctx)
  assert.match(out, /1\/1 finding\(s\) have no creation allow record/)
  assert.match(out, /Direct store write/)
})

test("a finding created through sec_finding reconciles cleanly", async () => {
  const p = project()
  createFinding(p.root, "s1", input("Direct store write"))
  const created = await secFinding.execute(
    {
      action: "create",
      title: "Created through the tool",
      description: "This finding passed through the audited tool layer.",
      impact: "Test impact.",
      target: "app.example.com",
      source: "manual",
      severity: "low",
      confidence: "high",
      verification: "unverified",
      evidence: "Observed during the test.",
      remediation: "Fix the control.",
    },
    p.ctx,
  )
  assert.match(created, /recorded F-/)

  const out = await secAudit.execute({ action: "reconcile" }, p.ctx)
  assert.match(out, /1\/2 finding\(s\) have no creation allow record/)
  assert.doesNotMatch(out, /Created through the tool/)
})
