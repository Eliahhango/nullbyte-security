import test from "node:test"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  amendThreatModel,
  getThreatModel,
  listThreatModels,
  renderThreatModelMarkdown,
  saveThreatModel,
  threatModelKey,
} from "../threat-model.ts"
import { renderMarkdown } from "../report.ts"

const root = () => mkdtempSync(join(tmpdir(), "nb-threat-"))

test("URLs and bare hosts resolve to one shared host model", () => {
  const dir = root()
  const saved = saveThreatModel(
    dir,
    "https://App.Example.com/login",
    "# Model\n\n- Actor: anonymous internet user\n- Asset: admin API",
    "agent-a",
  )
  assert.equal(saved.problems.length, 0)
  assert.equal(saved.entry?.key, "host:app.example.com")

  const byHost = getThreatModel(dir, "app.example.com")
  assert.equal(byHost?.revision, 1)
  assert.match(byHost?.content ?? "", /Actor/)
})

test("amendments are append-only and a new save clears them", () => {
  const dir = root()
  saveThreatModel(dir, "app.example.com", "base model", "agent-a")
  const amended = amendThreatModel(dir, "app.example.com", "new trust boundary found", "agent-b")
  assert.equal(amended.problems.length, 0)
  assert.equal(amended.entry?.revision, 2)
  assert.equal(amended.entry?.content, "base model")
  assert.equal(amended.entry?.amendments.length, 1)
  assert.equal(amended.entry?.amendments[0]?.by, "agent-b")

  const replaced = saveThreatModel(dir, "app.example.com", "rewritten model", "agent-c")
  assert.equal(replaced.entry?.revision, 3)
  assert.equal(replaced.entry?.content, "rewritten model")
  assert.equal(replaced.entry?.amendments.length, 0)
  assert.equal(replaced.entry?.created_at, amended.entry?.created_at)
})

test("amend requires an existing model and paths use an absolute key", () => {
  const dir = root()
  const missing = amendThreatModel(dir, "app.example.com", "more")
  assert.ok(missing.problems.some((p) => /save one first/.test(p)))

  const repo = join(dir, "repo")
  mkdirSync(repo)
  const saved = saveThreatModel(dir, "./repo", "repository model", "agent-a", dir)
  assert.equal(saved.entry?.key, `path:${repo}`)
  assert.equal(getThreatModel(dir, repo)?.content, "repository model")

  const key = threatModelKey("./repo", dir)
  assert.equal(key.key, `path:${repo}`)
})

test("models render into the report and list by target", () => {
  const dir = root()
  saveThreatModel(dir, "app.example.com", "assets and trust boundaries", "agent-a")
  assert.equal(listThreatModels(dir).length, 1)
  const entry = listThreatModels(dir)[0]!
  const rendered = renderThreatModelMarkdown(entry)
  assert.match(rendered, /Target:/)
  assert.match(rendered, /trust boundaries/)

  const md = renderMarkdown({
    engagement: "test",
    scopeSummary: "app.example.com",
    sessionID: "s1",
    findings: [],
    evidence: [],
    threatModels: [entry],
  })
  assert.match(md, /## Threat model/)
  assert.match(md, /assets and trust boundaries/)
})
