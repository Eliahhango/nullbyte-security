/**
 * Report export: destination directory, format selection, HTML safety, and the
 * honest-degradation path for PDF.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { existsSync, mkdtempSync, readFileSync, readdirSync } from "node:fs"
import { spawnSync } from "node:child_process"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { renderHtml, writeReport, ALL_FORMATS, type ReportInput } from "../report.ts"
import { createFinding, readAllFindings } from "../findings.ts"
import { findPdfConverter, htmlToPdf, pdfCapabilityLine } from "../pdf.ts"
import type { FindingInput } from "../types.ts"

const tmp = () => mkdtempSync(join(tmpdir(), "nb-report-"))

function input(overrides: Partial<ReportInput> = {}): ReportInput {
  return {
    engagement: "unit",
    scopeSummary: "authorized_all",
    sessionID: "s1",
    findings: [],
    evidence: [],
    limitations: "Only the /search endpoint was tested.",
    ...overrides,
  }
}

const baseFinding: FindingInput = {
  title: "Reflected XSS in search parameter",
  description: "the q parameter is reflected without encoding",
  impact: "session theft",
  target: "127.0.0.1:8080",
  source: "manual",
  severity: "high",
  confidence: "high",
  evidence: "payload returned verbatim",
  remediation: "encode output",
}

/* ------------------------------------------------------------- location --- */

test("export defaults to the run directory, not a system path", () => {
  const project = tmp()
  const engagement = join(project, ".nullbyte", "security")
  const res = writeReport(engagement, input(), { name: "r", formats: ["md"] })
  // the caller supplies outDir; writeReport must honour it verbatim
  assert.equal(res.dir, join(engagement, "reports"))
  assert.equal(res.files[0].path, join(engagement, "reports", "r.md"))
})

test("outDir overrides the default destination", () => {
  const runDir = tmp()
  const engagement = tmp()
  const res = writeReport(engagement, input(), { name: "r", formats: ["md", "html"], outDir: runDir })
  assert.equal(res.dir, runDir)
  for (const f of res.files) assert.equal(f.path.startsWith(runDir), true)
})

test("writeReport defaults to every format when none is named", () => {
  const dir = tmp()
  const res = writeReport(dir, input(), { name: "r" })
  const formats = res.files.map((f) => f.format)
  for (const want of ALL_FORMATS) {
    if (want === "pdf") continue // pdf depends on an installed converter
    assert.ok(formats.includes(want), `missing ${want}`)
  }
})

test("format selection writes only the requested artifacts", () => {
  const dir = tmp()
  const res = writeReport(dir, input(), { name: "only", formats: ["json"] })
  assert.deepEqual(res.files.map((f) => f.format), ["json"])
  const onDisk = readdirSync(res.dir).filter((f) => f.startsWith("only."))
  assert.deepEqual(onDisk, ["only.json"])
})

/* ----------------------------------------------------------------- html --- */

test("html escapes finding content — a payload cannot become live markup", () => {
  const html = renderHtml(
    input({
      findings: [
        {
          ...createFinding(tmp(), "s1", {
            ...baseFinding,
            title: "<script>alert(1)</script>",
            evidence: "<img src=x onerror=alert(2)>",
          }).finding!,
        },
      ],
    }),
  )
  assert.equal(html.includes("<script>alert(1)</script>"), false)
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/)
  assert.equal(html.includes("<img src=x onerror=alert(2)>"), false)
  assert.match(html, /&lt;img src=x onerror=alert\(2\)&gt;/)
})

test("html is self-contained: no scripts and no external fetches", () => {
  const html = renderHtml(input())
  assert.equal(/<script/i.test(html), false)
  assert.equal(/(src|href)\s*=\s*["']https?:/i.test(html), false)
  assert.match(html, /<!doctype html>/i)
})

test("html carries the closure summary and limitations", () => {
  const html = renderHtml(input())
  assert.match(html, /Closure:/)
  assert.match(html, /Only the \/search endpoint was tested\./)
})

/* ------------------------------------------------------------------ pdf --- */

test("pdf: produces a real PDF, or degrades honestly — never a stub", () => {
  const converter = findPdfConverter()
  const out = join(tmp(), "out.pdf")
  const res = htmlToPdf(renderHtml(input()), out)

  if (!converter) {
    assert.equal(res.ok, false)
    assert.match((res as any).reason, /no HTML-to-PDF converter/)
    assert.ok((res as any).hint)
    assert.equal(existsSync(out), false)
    return
  }

  assert.equal(res.ok, true, (res as any).reason)
  assert.equal(existsSync(out), true)
  const head = readFileSync(out).subarray(0, 5).toString("latin1")
  assert.equal(head, "%PDF-")
  assert.ok(readFileSync(out).length > 512)
})

test("pdf capability line names the converter or the install options", () => {
  assert.match(pdfCapabilityLine(), /^pdf: /)
})

test("pdf: reports honestly when no converter is on PATH", () => {
  // run in a child with an empty PATH so every candidate is absent
  const emptyPath = mkdtempSync(join(tmpdir(), "nb-nopath-"))
  const script = `
    import { htmlToPdf, findPdfConverter } from ${JSON.stringify(join(import.meta.dirname, "..", "pdf.ts"))};
    const r = htmlToPdf("<html></html>", ${JSON.stringify(join(emptyPath, "x.pdf"))});
    console.log(JSON.stringify({ converter: findPdfConverter(true)?.id ?? null, ok: r.ok, reason: r.reason ?? null, hint: r.hint ?? null }));
  `
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "-e", script], {
    encoding: "utf8",
    env: { ...process.env, PATH: emptyPath },
    timeout: 30_000,
  })
  const line = (r.stdout ?? "").trim().split("\n").pop() ?? ""
  const parsed = JSON.parse(line)
  assert.equal(parsed.converter, null)
  assert.equal(parsed.ok, false)
  assert.match(parsed.reason, /no HTML-to-PDF converter/)
  assert.ok(parsed.hint)
  assert.equal(existsSync(join(emptyPath, "x.pdf")), false)
})
