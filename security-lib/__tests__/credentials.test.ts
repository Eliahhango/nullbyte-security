/**
 * Credential extraction, collection and the report sections that carry them.
 *
 * The operator's posture is full disclosure: a leaked credential is reproduced
 * verbatim in a dedicated Credentials section. These tests pin the extractor,
 * the dedupe, the section's presence in every format, and the explicit scrub.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { extractCredentials } from "../redact.ts"
import { collectCredentials, renderCredentialsMarkdown } from "../credentials.ts"
import { renderHtml, renderJson, renderMarkdown, scrubReport, type ReportInput } from "../report.ts"

const BLOB = [
  "GET /.env HTTP/1.1",
  "DB_HOST=127.0.0.1",
  "db_password=hunter2secret",
  "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
  "api_key=sk-abcdefghijklmnopqrstuvwx",
  "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij",
  "DATABASE_URL=postgres://admin:s3cr3t@db.internal:5432/app",
].join("\n")

function finding(over: Record<string, unknown> = {}): any {
  return {
    id: "F-01",
    title: "Exposed .env",
    severity: "critical",
    status: "open",
    closure: "confirmed",
    confidence: "high",
    verification: "verified",
    source: "sec_recon",
    target: "127.0.0.1:8080",
    endpoint: "/.env",
    evidence: BLOB,
    description: "The .env is served verbatim.",
    impact: "Full database and cloud access.",
    remediation: "Deny dotfiles at the web root.",
    fix_effort: "low",
    cvss_score: 9.8,
    created_at: "2026-01-02T10:00:00.000Z",
    updated_at: "2026-01-02T12:00:00.000Z",
    revision: 2,
    sessionID: "s1",
    ...over,
  }
}

function input(over: Partial<ReportInput> = {}): ReportInput {
  return {
    engagement: "unit",
    scopeSummary: "127.0.0.1/32",
    sessionID: "s1",
    findings: [finding()],
    evidence: [],
    ...over,
  }
}

/* ------------------------------------------------------------ extraction --- */

test("extractCredentials pulls each shape out verbatim, with context", () => {
  const hits = extractCredentials(BLOB)
  const byKind = new Map(hits.map((h) => [h.kind, h]))

  assert.equal(byKind.get("aws-akid")?.value, "AKIAIOSFODNN7EXAMPLE")
  assert.equal(byKind.get("openai")?.value, "sk-abcdefghijklmnopqrstuvwx")
  assert.equal(byKind.get("url-userinfo")?.value, "admin:s3cr3t")
  assert.equal(byKind.get("bearer")?.value, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij")

  const assignment = hits.find((h) => h.kind === "assignment" && h.label === "db_password")
  assert.equal(assignment?.value, "hunter2secret")
  assert.equal(assignment?.context, "db_password=hunter2secret")
})

test("extractCredentials reads a private key block whole", () => {
  const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
  const hit = extractCredentials(pem).find((h) => h.kind === "private-key")
  assert.equal(hit?.value, pem)
})

test("extractCredentials returns nothing for clean text", () => {
  assert.deepEqual(extractCredentials("PORT 80/tcp open http"), [])
})

/* -------------------------------------------------------------- collect --- */

test("collectCredentials dedupes a value seen under two shapes, keeping the label", () => {
  // `sk-...` matches both the openai shape and the `api_key=` assignment
  const records = collectCredentials({ findings: [finding()], evidence: [] })
  const sk = records.filter((r) => r.value === "sk-abcdefghijklmnopqrstuvwx")
  assert.equal(sk.length, 1, "the same value was listed more than once")
  assert.equal(sk[0].label, "api_key")
  assert.equal(sk[0].kind, "assignment")
})

test("collectCredentials assigns stable C- ids and folds multiple sources", () => {
  const records = collectCredentials({
    findings: [finding(), finding({ id: "F-02", evidence: "db_password=hunter2secret" })],
    evidence: [],
  })
  const pw = records.find((r) => r.value === "hunter2secret")!
  assert.match(pw.id, /^C-\d\d$/)
  assert.deepEqual(
    pw.sources.map((s) => s.id).sort(),
    ["F-01", "F-02"],
  )
})

test("collectCredentials records the host and the line it came from", () => {
  const pw = collectCredentials({ findings: [finding()], evidence: [] }).find((r) => r.value === "hunter2secret")!
  assert.equal(pw.sources[0].host, "127.0.0.1:8080")
  assert.equal(pw.context, "db_password=hunter2secret")
})

test("collectCredentials finds credentials in evidence artifacts when content is supplied", () => {
  const records = collectCredentials({
    findings: [],
    evidence: [
      {
        id: "E-1",
        sha256: "a".repeat(64),
        sessionID: "s1",
        source: "sec_recon",
        label: "leaked .env",
        target: "127.0.0.1:8080",
        created_at: "2026-01-01T00:00:00.000Z",
        bytes: 10,
        redacted: false,
        file: "E-1.txt",
      },
    ],
    evidenceContent: { "E-1": "db_password=hunter2secret" },
  })
  assert.equal(records.length, 1)
  assert.equal(records[0].sources[0].kind, "evidence")
  assert.equal(records[0].sources[0].id, "E-1")
})

test("renderCredentialsMarkdown states the value in full and cites the source", () => {
  const md = renderCredentialsMarkdown(collectCredentials({ findings: [finding()], evidence: [] }))
  assert.match(md, /hunter2secret/)
  assert.match(md, /AKIAIOSFODNN7EXAMPLE/)
  assert.match(md, /### C-\d\d — db_password/)
  assert.match(md, /finding `F-01` — evidence/)
})

test("renderCredentialsMarkdown says so when there is nothing to disclose", () => {
  assert.match(renderCredentialsMarkdown([]), /No credentials were captured/)
})

/* ------------------------------------------------------- report sections --- */

test("markdown carries every standards section", () => {
  const md = renderMarkdown(input({ unredacted: true, limitations: "loopback only" }))
  for (const heading of [
    "## Executive summary",
    "## Background and objectives",
    "## Authorized scope",
    "## Timeline",
    "## Summary",
    "### Findings index",
    "## Credentials",
    "## Findings",
    "## Remediation roadmap",
    "## Evidence index",
    "## Limitations and untested areas",
    "## Appendix A — Risk rating methodology",
    "## Appendix B — Revision history",
    "## Disclaimer",
  ]) {
    assert.ok(md.includes(heading), `missing section: ${heading}`)
  }
})

test("the executive summary names the top risks and their own impact", () => {
  const md = renderMarkdown(input())
  assert.match(md, /1 critical, 0 high, 0 medium, 0 low, 0 info/)
  assert.match(md, /\*\*Critical — Exposed \.env\*\* \(127\.0\.0\.1:8080\/\.env\): Full database and cloud access\./)
})

test("the executive summary says so when nothing high or critical was found", () => {
  const md = renderMarkdown(input({ findings: [finding({ severity: "low" })] }))
  assert.match(md, /No critical or high severity issues were confirmed/)
})

test("the timeline is derived from recorded activity and labelled as such", () => {
  const md = renderMarkdown(input())
  assert.match(md, /First recorded activity:\*\* 2026-01-02T10:00:00\.000Z/)
  assert.match(md, /Elapsed between first and last record:\*\* 2 hours/)
  assert.match(md, /reflects the records the engagement kept/)
})

test("operator-supplied background, objectives and window are used when given", () => {
  const md = renderMarkdown(
    input({ background: "Client asked for a retest.", objectives: "Confirm the fix.", testWindow: "Jan 2–3" }),
  )
  assert.match(md, /Client asked for a retest\./)
  assert.match(md, /Confirm the fix\./)
  assert.match(md, /Testing window \(operator-supplied\):\*\* Jan 2–3/)
})

test("the remediation roadmap orders by severity then cheapest fix", () => {
  const md = renderMarkdown(
    input({
      findings: [
        finding({ id: "F-02", title: "Headers", severity: "low", fix_effort: "trivial" }),
        finding({ id: "F-01", title: "Exposed .env", severity: "critical", fix_effort: "low" }),
      ],
    }),
  )
  const roadmap = md.slice(md.indexOf("## Remediation roadmap"))
  assert.ok(roadmap.indexOf("F-01") < roadmap.indexOf("F-02"), "critical finding was not prioritised first")
  assert.match(roadmap, /\| 1 \| F-01 — Exposed \.env \| Critical \(9\.8\) \| low \|/)
})

test("the risk-rating appendix documents the bands and the disclosure posture", () => {
  const md = renderMarkdown(input())
  assert.match(md, /CVSS 3\.1 base metrics/)
  assert.match(md, /\| Critical \| 9\.0 – 10\.0 \|/)
  assert.match(md, /full disclosure/i)
  assert.match(md, /APTS-MR-019/)
})

test("revision history lists each finding's revision and last update", () => {
  const md = renderMarkdown(input())
  assert.match(md, /\| F-01 — Exposed \.env \| 2 \| 2026-01-02T12:00:00\.000Z \|/)
})

test("json exposes the new structure as data", () => {
  const parsed = JSON.parse(renderJson(input()))
  assert.equal(parsed.version, "1.0")
  assert.equal(parsed.executive_summary.total, 1)
  assert.equal(parsed.executive_summary.top_risks[0].severity, "critical")
  assert.equal(parsed.credentials[0].value !== undefined, true)
  assert.equal(parsed.remediation_roadmap[0].priority, 1)
  assert.equal(parsed.risk_rating.redaction_posture, "full-disclosure")
  assert.equal(parsed.revision_history[0].revision, 2)
  assert.equal(typeof parsed.timeline.hours, "number")
  assert.match(parsed.disclaimer, /not a statement that they are secure/)
})

test("html carries every standards section", () => {
  const html = renderHtml(input())
  for (const heading of [
    "Executive summary",
    "Background and objectives",
    "Timeline",
    "Findings index",
    "Credentials",
    "Remediation roadmap",
    "Appendix A",
    "Appendix B",
    "Disclaimer",
  ]) {
    assert.ok(html.includes(heading), `missing html section: ${heading}`)
  }
})

test("html renders each credential in full with its source", () => {
  const html = renderHtml(input())
  assert.match(html, /hunter2secret/)
  assert.match(html, /class="finding cred"/)
})

/* ------------------------------------------------------------- scrubbing --- */

test("scrubReport removes a bare credential value no shape rule would catch", () => {
  const md = renderMarkdown(input())
  assert.ok(md.includes("hunter2secret"))
  const scrubbed = scrubReport(input(), md)
  assert.equal(scrubbed.includes("hunter2secret"), false, "a bare value survived the scrub")
  assert.match(scrubbed, /\[REDACTED:credential\]/)
})

test("scrubReport also removes credentials held in evidence artifacts", () => {
  const inp = input({ evidenceContent: { "E-1": "db_password=hunter2secret" } })
  const scrubbed = scrubReport(inp, renderMarkdown(inp))
  assert.equal(scrubbed.includes("hunter2secret"), false)
})
