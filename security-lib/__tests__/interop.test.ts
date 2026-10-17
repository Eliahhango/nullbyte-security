/**
 * Interop exports — SARIF 2.1.0 and DefectDojo-shaped CSV.
 *
 * These are the formats another tool parses, so a wrong value is not a cosmetic
 * bug: a bad `level` fails a build that should have passed (or passes one that
 * should have failed), and a bad CSV row makes an importer drop a finding. The
 * tests below check the mapping decisions and the CSV's well-formedness, not
 * just that the strings are non-empty.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, readFileSync, readdirSync, statSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { renderCsv, renderSarif, csvCell } from "../interop.ts"
import { writeReport } from "../report.ts"
import type { Finding } from "../types.ts"

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: "F-0001",
  sessionID: "s1",
  created_at: "2026-03-04T10:00:00.000Z",
  updated_at: "2026-03-04T10:00:00.000Z",
  title: "Reflected XSS in search",
  description: "the q parameter is reflected without encoding",
  impact: "session theft",
  target: "app.acme.test",
  endpoint: "/search",
  method: "GET",
  source: "sec_scan",
  severity: "high",
  confidence: "high",
  verification: "verified",
  evidence: "payload returned verbatim",
  remediation: "encode output",
  status: "confirmed",
  closure: "confirmed",
  fingerprint: "fp",
  revision: 1,
  ...over,
})

const report = (findings: Finding[]) =>
  ({ engagement: "acme", scopeSummary: "s", sessionID: "s1", findings, evidence: [] }) as any

/** Minimal RFC 4180 reader, to prove the output round-trips. */
function parseCsv(text: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let field = ""
  let quoted = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"'
          i++
        } else quoted = false
      } else field += c
      continue
    }
    if (c === '"') quoted = true
    else if (c === ",") {
      row.push(field)
      field = ""
    } else if (c === "\n") {
      row.push(field)
      rows.push(row)
      row = []
      field = ""
    } else field += c
  }
  if (field || row.length) {
    row.push(field)
    rows.push(row)
  }
  return rows
}

/* ------------------------------------------------------------------ sarif --- */

test("sarif is valid 2.1.0 with one result per finding", () => {
  const s = JSON.parse(renderSarif(report([finding(), finding({ id: "F-0002", title: "Other", cwe: "CWE-89" })])))
  assert.equal(s.version, "2.1.0")
  assert.equal(s.$schema, "https://json.schemastore.org/sarif-2.1.0.json")
  assert.equal(s.runs.length, 1)
  assert.equal(s.runs[0].results.length, 2)
  assert.equal(s.runs[0].tool.driver.name, "NullByte Security")
})

test("severity maps to sarif levels without collapsing the ladder", () => {
  const levels = (sev: Finding["severity"]) => JSON.parse(renderSarif(report([finding({ severity: sev })]))).runs[0].results[0].level
  assert.equal(levels("critical"), "error")
  assert.equal(levels("high"), "error")
  assert.equal(levels("medium"), "warning")
  assert.equal(levels("low"), "note")
  // info must not fail a gate — `none`, not `warning`
  assert.equal(levels("info"), "none")
})

test("rules are deduplicated by CWE, not repeated per finding", () => {
  const s = JSON.parse(
    renderSarif(
      report([
        finding({ id: "F-1", cwe: "CWE-79", title: "XSS" }),
        finding({ id: "F-2", cwe: "CWE-79", title: "XSS again" }),
        finding({ id: "F-3", cwe: "CWE-89", title: "SQLi" }),
      ]),
    ),
  )
  assert.deepEqual(s.runs[0].tool.driver.rules.map((r: any) => r.id), ["CWE-79", "CWE-89"])
  assert.deepEqual(s.runs[0].results.map((r: any) => r.ruleId), ["CWE-79", "CWE-79", "CWE-89"])
})

test("a network finding gets a logical location, never a fabricated file path", () => {
  const s = JSON.parse(renderSarif(report([finding()])))
  const loc = s.runs[0].results[0].locations[0]
  assert.equal(loc.physicalLocation, undefined)
  assert.deepEqual(loc.logicalLocations, [{ fullyQualifiedName: "app.acme.test/search", kind: "resource" }])
})

test("a file:line evidence reference becomes a physical location", () => {
  const s = JSON.parse(renderSarif(report([finding({ evidence_refs: ["src/api/search.ts:120"] })])))
  const pl = s.runs[0].results[0].locations[0].physicalLocation
  assert.equal(pl.artifactLocation.uri, "src/api/search.ts")
  assert.equal(pl.region.startLine, 120)
})

test("a line range is carried through, and an evidence-store id is not a path", () => {
  const ranged = JSON.parse(renderSarif(report([finding({ evidence_refs: ["src/x.ts:10-24"] })])))
  assert.equal(ranged.runs[0].results[0].locations[0].physicalLocation.region.endLine, 24)

  // E-… is an evidence artifact, not a source file
  const store = JSON.parse(renderSarif(report([finding({ evidence_refs: ["E-09ec37d5"] })])))
  assert.equal(store.runs[0].results[0].locations[0].physicalLocation, undefined)
})

test("sarif properties carry what the format has no field for", () => {
  const f = finding({ cve: "CVE-2021-41773", cwe: "CWE-22", cvss_score: 9.8, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", retests: [{ at: "t" } as any] })
  const s = JSON.parse(renderSarif(report([f])))
  const p = s.runs[0].results[0].properties
  assert.equal(p.id, "F-0001")
  assert.equal(p.closure, "confirmed")
  assert.equal(p.cvss31Score, 9.8)
  assert.equal(p.cve, "CVE-2021-41773")
  assert.equal(p.retests, 1)
  assert.match(s.runs[0].results[0].message.text, /F-0001/)
})

test("sarif states the coverage so absence of results is not read as absence of issues", () => {
  const input = { ...report([finding()]), selectionNote: "session ses_1 only" }
  const s = JSON.parse(renderSarif(input))
  assert.match(s.runs[0].invocations[0].toolExecutionNotifications[0].message.text, /session ses_1 only/)
})

/* -------------------------------------------------------------------- csv --- */

test("csv has a stable header and one row per finding", () => {
  const rows = parseCsv(renderCsv(report([finding(), finding({ id: "F-2" })])))
  assert.equal(rows.length, 3)
  assert.deepEqual(rows[0]!.slice(0, 4), ["Title", "Date", "Severity", "Description"])
  assert.ok(rows[0]!.includes("Active"))
  assert.ok(rows[0]!.includes("FalsePositive"))
  assert.equal(rows[1]![0], "Reflected XSS in search")
})

test("every row has exactly one cell per column, so the import cannot skew", () => {
  const rows = parseCsv(
    renderCsv(
      report([
        finding({ title: 'a, b "quoted" c' }),
        finding({ id: "F-2", description: "line one\nline two, with comma" }),
        finding({ id: "F-3", evidence: 'contains "quotes", commas, and\nnewlines' }),
      ]),
    ),
  )
  const width = rows[0]!.length
  for (const r of rows) assert.equal(r.length, width, `ragged row: ${JSON.stringify(r)}`)
  assert.ok(rows.some((r) => r[0] === 'a, b "quoted" c'), "quoting round-trips")
})

test("csv quoting follows RFC 4180", () => {
  assert.equal(csvCell("plain"), "plain")
  assert.equal(csvCell("a,b"), '"a,b"')
  assert.equal(csvCell('say "hi"'), '"say ""hi"""')
  assert.equal(csvCell("a\nb"), '"a\nb"')
  assert.equal(csvCell(undefined), "")
  assert.equal(csvCell(9.8), "9.8")
})

test("Active, Verified and FalsePositive are independent axes", () => {
  const rows = parseCsv(
    renderCsv(
      report([
        finding({ id: "A", status: "confirmed", verification: "verified" }),
        finding({ id: "B", status: "false-positive", verification: "refuted" }),
        finding({ id: "C", status: "remediated", verification: "verified" }),
        finding({ id: "D", status: "open", verification: "inconclusive" }),
      ]),
    ),
  )
  const idx = (name: string) => rows[0]!.indexOf(name)
  const row = (id: string) => rows.slice(1).find((r) => r[idx("FindingID")] === id)!

  assert.deepEqual([row("A")[idx("Active")], row("A")[idx("Verified")], row("A")[idx("FalsePositive")]], ["true", "true", "false"])
  assert.deepEqual([row("B")[idx("Active")], row("B")[idx("Verified")], row("B")[idx("FalsePositive")]], ["false", "false", "true"])
  // remediated is still "verified" — the check was true when it was made
  assert.deepEqual([row("C")[idx("Active")], row("C")[idx("Verified")], row("C")[idx("Remediated")]], ["false", "true", "true"])
  assert.deepEqual([row("D")[idx("Active")], row("D")[idx("Verified")]], ["true", "false"])
})

test("csv carries the endpoint as a URL and the date as a date", () => {
  const rows = parseCsv(renderCsv(report([finding()])))
  const idx = (n: string) => rows[0]!.indexOf(n)
  assert.equal(rows[1]![idx("Endpoint")], "https://app.acme.test/search")
  assert.equal(rows[1]![idx("Date")], "2026-03-04")
  assert.equal(rows[1]![idx("Severity")], "High")
  assert.equal(rows[1]![idx("CVSSv3")], "")
})

test("retests and reproduction travel in the description", () => {
  const f = finding({
    reproduction: "GET /search?q=<script>",
    retests: [{ at: "2026-03-05T00:00:00.000Z", before: "verified", after: "refuted", method: "curl -s /search?q=x", observed: "escaped" } as any],
  })
  const rows = parseCsv(renderCsv(report([f])))
  const desc = rows[1]![rows[0]!.indexOf("Description")]!
  assert.match(desc, /Reproduction:/)
  assert.match(desc, /Retests \(1\)/)
  assert.match(desc, /verified→refuted/)
})

/* -------------------------------------------------------------- pipeline --- */

test("interop formats are opt-in: a default export still writes four files", () => {
  const dir = mkdtempSync(join(tmpdir(), "nb-interop-"))
  const res = writeReport(dir, report([finding()]), { name: "r", outDir: dir })
  assert.deepEqual(res.files.map((f) => f.format).sort(), ["html", "json", "md", "pdf"])
  assert.equal(readdirSync(dir).filter((f) => f.endsWith(".sarif")).length, 0)
  assert.equal(readdirSync(dir).filter((f) => f.endsWith(".csv")).length, 0)
})

test("sarif only writes sarif, and it is a valid document on disk", () => {
  const dir = mkdtempSync(join(tmpdir(), "nb-interop-"))
  const res = writeReport(dir, report([finding()]), { name: "r", outDir: dir, formats: ["sarif"] })
  assert.deepEqual(res.files.map((f) => f.format), ["sarif"])
  assert.equal(res.sarifPath, join(dir, "r.sarif"))
  const doc = JSON.parse(readFileSync(res.sarifPath!, "utf8"))
  assert.equal(doc.runs[0].results.length, 1)
})

test("interop exports are owner-only, like every other deliverable", () => {
  const dir = mkdtempSync(join(tmpdir(), "nb-interop-"))
  const res = writeReport(dir, report([finding()]), { name: "r", outDir: dir, formats: ["sarif", "csv"] })
  assert.equal(res.csvPath, join(dir, "r.csv"))
  for (const f of res.files) assert.equal(statSync(f.path).mode & 0o777, 0o600, `${f.path} should be 0600`)
})

test("redaction applies to the interop formats too", () => {
  const secret = "AKIAIOSFODNN7EXAMPLE"
  const f = finding({ evidence: `leaked key ${secret}`, evidence_refs: [] })
  const res = writeReport(mkdtempSync(join(tmpdir(), "nb-interop-")), report([f]), {
    name: "r",
    outDir: mkdtempSync(join(tmpdir(), "nb-interop-out-")),
    formats: ["sarif", "csv"],
    redact: true,
  })
  const sarifText = readFileSync(res.sarifPath!, "utf8")
  const csvText = readFileSync(res.csvPath!, "utf8")
  assert.doesNotMatch(sarifText, new RegExp(secret))
  assert.doesNotMatch(csvText, new RegExp(secret))
})
