/**
 * Static analysis, secret redaction, methodology access and tool detection.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { scanSource } from "../sast.ts"
import { redactSecrets, redactAndTruncate, stripUrlCredentials } from "../redact.ts"
import { listFragments, loadFragment, searchFragments } from "../methodology.ts"
import { capabilityReport, detectTools, requireTool, resetToolCache } from "../adapters/registry.ts"

function fixture(): string {
  const dir = mkdtempSync(join(tmpdir(), "nb-sast-"))
  mkdirSync(join(dir, "src"), { recursive: true })
  writeFileSync(
    join(dir, "src", "app.js"),
    [
      'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
      "function run(userInput) { return eval(userInput) }",
      'const password = "hunter2hunter2"',
      "element.innerHTML = req.query.name",
    ].join("\n"),
  )
  writeFileSync(join(dir, ".env"), "DB_URI=postgres://user:passw0rd@db.internal:5432/app\n")
  return dir
}

test("secret scan finds credentials by kind without printing them", () => {
  const res = scanSource(fixture())
  assert.ok(res.filesScanned >= 2)
  const kinds = new Set(res.secrets.map((s) => s.kind))
  assert.ok(kinds.has("aws-access-key-id"), [...kinds].join(","))
  assert.ok(kinds.has("db-uri-with-password") || kinds.has("hardcoded-password"), [...kinds].join(","))
  for (const s of res.secrets) {
    assert.doesNotMatch(s.preview, /AKIAIOSFODNN7EXAMPLE/)
    assert.match(s.preview, /redacted/)
  }
})

test("code smells flag eval, innerHTML and hardcoded passwords", () => {
  const res = scanSource(fixture())
  const rules = new Set(res.smells.map((s) => s.rule))
  assert.ok(rules.has("eval"), [...rules].join(","))
  assert.ok(rules.has("innerhtml"), [...rules].join(","))
  assert.ok(res.smells.some((s) => s.severity === "high"))
})

test("secret scan can be narrowed by kind", () => {
  const res = scanSource(fixture(), { only: ["aws-access-key-id"] })
  assert.ok(res.secrets.length >= 1)
  assert.ok(res.secrets.every((s) => s.kind === "aws-access-key-id"))
})

test("scanning a missing directory reports a problem rather than throwing", () => {
  const res = scanSource("/tmp/nb-does-not-exist-xyz")
  assert.ok(res.problems.length > 0)
  assert.equal(res.secrets.length, 0)
})

/* --------------------------------------------------------------- redact --- */

test("redaction covers assignments, bearer tokens and url userinfo", () => {
  assert.match(redactSecrets("api_key=supersecretvalue123"), /REDACTED/)
  assert.match(redactSecrets("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij"), /REDACTED/)
  assert.equal(stripUrlCredentials("https://user:pass@host/path"), "https://[REDACTED:userinfo]@host/path")
  assert.doesNotMatch(redactSecrets('password = "hunter2hunter2"'), /hunter2hunter2/)
})

test("redaction catches prefixed credential keys — the shapes a leaked .env uses", () => {
  // `_` is a word character, so a bare \b never matched `db_password`. These are
  // the most common credential lines in a leaked environment file.
  for (const line of [
    "db_password: S3cr3tPr0d!Pass",
    "mysql_pwd=supersecretvalue",
    "DB_PASSWORD=supersecretvalue",
    "client_secret=abcdef123456",
    "app_api_key=abcdef123456",
    "my_access_token=abcdef123456",
  ]) {
    const out = redactSecrets(line)
    assert.match(out, /REDACTED/, `not redacted: ${line}`)
    assert.doesNotMatch(out, /supersecretvalue|S3cr3tPr0d|abcdef123456/, `value survived: ${line}`)
  }
})

test("redactAndTruncate keeps head and tail and is bounded", () => {
  const big = `HEAD${"x".repeat(50000)}TAIL`
  const out = redactAndTruncate(big, 1024)
  assert.ok(Buffer.byteLength(out, "utf8") < 1400)
  assert.match(out, /HEAD/)
  assert.match(out, /TAIL/)
  assert.match(out, /truncated/)
})

/* ---------------------------------------------------------- methodology --- */

test("methodology exposes the fragment set", () => {
  const list = listFragments()
  assert.ok(list.length >= 8)
  assert.ok(list.some((f) => f.id === "scope-and-authorization"))
  const frag = loadFragment("recon-web")
  assert.ok(frag && frag.body.length > 100)
  assert.equal(loadFragment("nope"), undefined)
})

test("methodology search returns relevant fragments", () => {
  assert.ok(searchFragments("tls certificate", 3).length > 0)
  assert.ok(searchFragments("reporting findings", 3).length > 0)
  assert.equal(searchFragments("zzzznomatchzzzz", 3).length, 0)
})

/* ------------------------------------------------------------- adapters --- */

test("tool detection reports availability and install hints", () => {
  resetToolCache()
  const tools = detectTools(true)
  assert.ok(tools.nmap)
  assert.equal(typeof tools.nmap.available, "boolean")
  assert.ok(tools.nmap.installHint.length > 0)
  const report = capabilityReport()
  assert.match(report, /external tool availability/)
  assert.match(report, /nmap/i)
  assert.match(report, /\[x\]|\[ \]/)
  // version banners must be sanitised (no ANSI escapes leaking into the model's context)
  assert.doesNotMatch(report, /\u001b\[/)
})

test("requireTool explains how to install a missing tool", () => {
  const missing = requireTool("definitely-not-a-real-scanner")
  assert.equal(missing.ok, false)
  if (!missing.ok) assert.match(missing.problem, /unknown tool/)
})
