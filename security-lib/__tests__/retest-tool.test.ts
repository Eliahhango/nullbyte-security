/**
 * sec_retest action=run — the guards around re-executing a command.
 *
 * A retest runs a real command against a real host, so it goes through the same
 * scope and destructive-command enforcement as every other tool. The interesting
 * case is that the command is free text: the finding says one target, and the
 * command can point anywhere. Authorizing only the finding's target would let an
 * off-scope command run under an in-scope finding.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { secRetest } from "../tools/retest.ts"
import { createFinding, getFinding } from "../findings.ts"
import { listEvidence } from "../evidence.ts"
import type { FindingInput } from "../types.ts"

/** A project whose scope allows only 127.0.0.1:8080 (allow-list mode). */
function project(scope: Record<string, unknown> = {}) {
  const worktree = mkdtempSync(join(tmpdir(), "nb-retest-tool-"))
  const root = join(worktree, ".nullbyte", "security")
  mkdirSync(root, { recursive: true })
  writeFileSync(
    join(root, "scope.json"),
    JSON.stringify({
      engagement: "t",
      authorized_all: false,
      block_destructive: true,
      include: [{ host: "127.0.0.1", ports: [8080] }],
      exclude: [],
      intensity: "intrusive",
      allow_private: true,
      allow_model_scope_edit: false,
      ...scope,
    }),
  )
  const ctx = { sessionID: "s1", agent: "void", directory: worktree, worktree } as any
  const f = createFinding(root, "s1", {
    title: "Verbose banner",
    description: "d",
    impact: "i",
    target: "127.0.0.1:8080",
    source: "manual",
    severity: "low",
    confidence: "high",
    verification: "unverified",
    evidence: "Server: Apache/2.4.49",
    remediation: "r",
  } as FindingInput).finding!
  return { worktree, root, ctx, finding: f }
}

const run = (p: ReturnType<typeof project>, args: Record<string, unknown>) =>
  secRetest.execute({ id: p.finding.id, action: "run", ...args } as any, p.ctx)

/* ------------------------------------------------------------- refusals --- */

test("a destructive command is refused before any scope work", async () => {
  const p = project({ authorized_all: true })
  const out = await run(p, { command: "rm -rf /" })
  assert.match(out, /^refused: the command is destructive/)
  assert.equal(getFinding(p.root, p.finding.id)!.retests, undefined)
})

test("a shell-wrapped command is refused", async () => {
  const p = project({ authorized_all: true })
  const out = await run(p, { command: "bash -c 'nmap 127.0.0.1'" })
  assert.match(out, /wrapped in 'bash'/)
})

test("a command whose destination cannot be determined is refused", async () => {
  const p = project({ authorized_all: true })
  const out = await run(p, { command: "curl -s http://$(echo 127.0.0.1):8080/" })
  assert.match(out, /cannot be determined/)
})

test("a command aimed off-scope is denied even when the finding is in scope", async () => {
  const p = project()
  await assert.rejects(() => run(p, { command: "curl -s http://198.51.100.7:8080/" }), /not covered by any authorized scope entry/)
  assert.equal(getFinding(p.root, p.finding.id)!.retests, undefined, "a denied run records no retest")
})

test("an unauthorised port on an authorised host is denied", async () => {
  const p = project()
  await assert.rejects(() => run(p, { command: "curl -s http://127.0.0.1:9999/" }), /outside the authorized ports/)
})

test("an unknown finding is a clean error", async () => {
  const p = project({ authorized_all: true })
  const out = await secRetest.execute({ id: "F-nope", action: "run", command: "echo hi" } as any, p.ctx)
  assert.match(out, /finding F-nope not found/)
})

test("action=record requires status, method and observed", async () => {
  const p = project()
  assert.match(await secRetest.execute({ id: p.finding.id, action: "record" } as any, p.ctx), /requires status/)
  assert.match(await secRetest.execute({ id: p.finding.id, action: "record", status: "verified" } as any, p.ctx), /requires method/)
  assert.match(
    await secRetest.execute({ id: p.finding.id, action: "record", status: "verified", method: "curl" } as any, p.ctx),
    /requires observed/,
  )
})

/* ---------------------------------------------------------------- running --- */

test("an authorized run captures evidence and records the retest", async () => {
  const p = project()
  const out = await run(p, { command: "printf 'Server: Apache/2.4.49\\n'", intensity: "safe-active" })
  assert.match(out, /^authorized: 127\.0\.0\.1/m)

  const after = getFinding(p.root, p.finding.id)!
  assert.equal(after.verification, "verified", "exit 0 with output counts as reproducing")
  assert.equal(after.retests!.length, 1)
  assert.equal(after.retests![0]!.exit_code, 0)
  assert.ok(after.retests![0]!.evidence_id, "the output is stored as evidence")

  const artifact = listEvidence(p.root).find((e) => e.id === after.retests![0]!.evidence_id)!
  assert.equal(artifact.source, "sec_retest")
  assert.equal(artifact.target, "127.0.0.1:8080")
})

test("a non-zero exit is recorded as refuted", async () => {
  const p = project()
  // note: `sh -c ...` would be refused as a wrapper, which is the point of that guard
  const out = await run(p, { command: "false", status: "refuted" })
  const after = getFinding(p.root, p.finding.id)!
  assert.equal(after.retests![0]!.exit_code, 1)
  assert.equal(after.verification, "refuted")
  assert.match(out, /exit 1/)
})

test("successful-but-silent output is inconclusive, not verified", async () => {
  const p = project()
  await run(p, { command: "true" })
  assert.equal(getFinding(p.root, p.finding.id)!.verification, "inconclusive")
})

test("a missing binary is refused rather than recorded as a failure", async () => {
  const p = project()
  const out = await run(p, { command: "definitely-not-a-real-binary --version" })
  assert.match(out, /not installed or not on PATH/)
  assert.equal(getFinding(p.root, p.finding.id)!.retests, undefined)
})
