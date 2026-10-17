/**
 * Report evidence embedding and redaction control.
 *
 * The operator asked to see everything that was found — including leaked
 * credentials — in every format. These tests pin both halves of that contract:
 * redaction is on by default and applies to every text format, and the explicit
 * opt-out emits verbatim content while marking the artifact as sensitive.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, readFileSync, statSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { renderHtml, renderMarkdown, renderJson, writeReport, type ReportInput } from "../report.ts"
import { saveEvidence, readEvidence } from "../evidence.ts"
import type { EvidenceRecord } from "../evidence.ts"

const tmp = () => mkdtempSync(join(tmpdir(), "nb-evidence-"))

const SECRET = "hunter2secret"
const LEAK = `db_password: ${SECRET}`

function artifact(over: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return {
    id: "E-deadbeef",
    sha256: "a".repeat(64),
    sessionID: "s1",
    source: "sec_recon",
    label: "leaked .env",
    target: "127.0.0.1:8080",
    created_at: "2026-01-01T00:00:00.000Z",
    bytes: LEAK.length,
    redacted: false,
    file: "E-deadbeef.txt",
    ...over,
  }
}

function input(over: Partial<ReportInput> = {}): ReportInput {
  return {
    engagement: "unit",
    scopeSummary: "authorized_all",
    sessionID: "s1",
    findings: [],
    evidence: [],
    ...over,
  }
}

/* ----------------------------------------------------------- redaction --- */

test("redaction is on by default in every text format", () => {
  const dir = tmp()
  const res = writeReport(
    dir,
    input({
      findings: [
        {
          id: "F-1",
          title: "Exposed .env",
          severity: "high",
          status: "confirmed",
          closure: "confirmed",
          confidence: "high",
          verification: "verified",
          source: "manual",
          evidence: LEAK,
          created_at: "2026-01-01T00:00:00.000Z",
          updated_at: "2026-01-01T00:00:00.000Z",
          revision: 1,
          sessionID: "s1",
        } as any,
      ],
    }),
    { name: "r" },
  )

  for (const f of res.files) {
    const body = readFileSync(f.path, "utf8")
    assert.equal(body.includes(SECRET), false, `${f.format} leaked the secret`)
  }
  assert.match(res.markdown, /\[REDACTED:credential\]/)
  assert.equal(res.html.includes(SECRET), false)
})

test("json is redacted too — it is a deliverable like any other", () => {
  const dir = tmp()
  const res = writeReport(dir, input({ evidence: [artifact()] }), { name: "r", formats: ["json"] })
  const body = readFileSync(res.files[0].path, "utf8")
  assert.equal(body.includes(SECRET), false)
})

/* -------------------------------------------------- unredacted opt-out --- */

test("redact:false emits the secret verbatim in md, json and html", () => {
  const dir = tmp()
  const res = writeReport(
    dir,
    input({ evidenceContent: { "E-deadbeef": LEAK }, evidence: [artifact()], unredacted: true }),
    { name: "r", redact: false, formats: ["md", "json", "html"] },
  )
  for (const f of res.files) {
    const body = readFileSync(f.path, "utf8")
    assert.ok(body.includes(SECRET), `${f.format} did not carry the secret`)
  }
})

test("an unredacted report carries a warning banner in md and html", () => {
  const md = renderMarkdown(input({ unredacted: true }))
  const html = renderHtml(input({ unredacted: true }))
  assert.match(md, /UNREDACTED/)
  assert.match(html, /UNREDACTED/)
  assert.match(html, /class="warn"/)
})

test("a redacted report carries no unredacted banner", () => {
  assert.equal(renderMarkdown(input()).includes("UNREDACTED"), false)
  assert.equal(renderHtml(input()).includes("UNREDACTED"), false)
})

/* ----------------------------------------------------- evidence content --- */

test("evidence content is embedded in md and html when supplied", () => {
  const inp = input({ evidence: [artifact()], evidenceContent: { "E-deadbeef": LEAK } })
  assert.match(renderMarkdown(inp), /## Evidence artifacts/)
  assert.match(renderMarkdown(inp), /db_password/)
  assert.match(renderHtml(inp), /Evidence artifacts/)
  assert.match(renderHtml(inp), /db_password/)
})

test("evidence content is omitted when not supplied — index only", () => {
  const inp = input({ evidence: [artifact()] })
  assert.equal(renderMarkdown(inp).includes("## Evidence artifacts"), false)
  assert.equal(renderHtml(inp).includes("Evidence artifacts"), false)
  // the index still lists the artifact
  assert.match(renderMarkdown(inp), /E-deadbeef/)
})

test("evidence content reaches the json export as structured artifacts", () => {
  const parsed = JSON.parse(renderJson(input({ evidence: [artifact()], evidenceContent: { "E-deadbeef": LEAK } })))
  assert.equal(parsed.evidence_artifacts[0].id, "E-deadbeef")
  assert.equal(parsed.evidence_artifacts[0].content, LEAK)
  assert.equal(parsed.evidence_artifacts[0].redacted_at_capture, false)
})

test("a missing artifact file is reported, not silently dropped", () => {
  const inp = input({ evidence: [artifact()], evidenceContent: { "E-deadbeef": "_(artifact file is missing from the evidence store)_" } })
  assert.match(renderMarkdown(inp), /artifact file is missing/)
})

/* ------------------------------------------------------ capture boundary --- */

test("sec_evidence default redacts the secret before it touches disk", () => {
  const root = tmp()
  const res = saveEvidence(root, { sessionID: "s1", source: "manual", label: "env", content: LEAK })
  assert.equal(res.record?.redacted, true)
  assert.equal(readEvidence(root, res.record!.id)!.includes(SECRET), false)
})

test("sec_evidence includeSecrets stores the credential verbatim", () => {
  const root = tmp()
  const res = saveEvidence(root, { sessionID: "s1", source: "manual", label: "env", content: LEAK, includeSecrets: true })
  assert.equal(res.record?.redacted, false)
  assert.ok(readEvidence(root, res.record!.id)!.includes(SECRET))
})

test("capture-time redaction is irreversible from the report", () => {
  // an artifact redacted at capture cannot be recovered by asking for full evidence
  const root = tmp()
  const res = saveEvidence(root, { sessionID: "s1", source: "manual", label: "env", content: LEAK })
  const stored = readEvidence(root, res.record!.id)!
  const md = renderMarkdown(input({ evidence: [res.record!], evidenceContent: { [res.record!.id]: stored } }))
  assert.equal(md.includes(SECRET), false)
})

/* ------------------------------------------------------------ file mode --- */

test("every emitted artifact is owner-only, including the PDF", async () => {
  const { findPdfConverter } = await import("../pdf.ts")
  const dir = tmp()
  const res = writeReport(dir, input({ evidence: [artifact()], evidenceContent: { "E-deadbeef": LEAK }, unredacted: true }), {
    name: "r",
    redact: false,
    formats: ["md", "json", "html", "pdf"],
  })
  for (const f of res.files) {
    const mode = statSync(f.path).mode & 0o777
    assert.equal(mode, 0o600, `${f.format} is ${mode.toString(8)}`)
  }
  if (!findPdfConverter()) return // no converter: nothing else to assert
  assert.ok(res.files.some((f) => f.format === "pdf"))
})
