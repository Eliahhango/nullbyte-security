/**
 * sec_recon — archiving the raw HTTP response.
 *
 * The recon summary picks six interesting headers and 4 KB of body, so it is a
 * lossy view of a response. A finding that says "the server discloses its
 * version" or "the cookie is missing HttpOnly" is only checkable if the response
 * itself is kept. These tests run against a real loopback server, so the
 * transcript is compared with what was actually sent.
 */

import test from "node:test"
import assert from "node:assert/strict"
import http from "node:http"
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { secRecon } from "../tools/recon.ts"
import { listEvidence, readEvidence, verifyEvidenceStore } from "../evidence.ts"
import { httpProbe } from "../net/http.ts"

/** Start a loopback server with the given handler; returns base url + a stop fn. */
async function serve(handler: http.RequestListener) {
  const server = http.createServer(handler)
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r))
  const port = (server.address() as any).port
  return { url: `http://127.0.0.1:${port}`, port, stop: () => new Promise<void>((r) => server.close(() => r())) }
}

function project(scope: Record<string, unknown> = {}) {
  const worktree = mkdtempSync(join(tmpdir(), "nb-recon-arch-"))
  const root = join(worktree, ".nullbyte", "security")
  mkdirSync(root, { recursive: true })
  writeFileSync(
    join(root, "scope.json"),
    JSON.stringify({
      engagement: "t",
      authorized_all: true,
      block_destructive: true,
      include: [],
      exclude: [],
      intensity: "passive",
      allow_private: true,
      allow_model_scope_edit: false,
      ...scope,
    }),
  )
  return { worktree, root, ctx: { sessionID: "s1", agent: "void", directory: worktree, worktree } as any }
}

/* --------------------------------------------------------- the transcript --- */

test("a response is archived with its status line and headers in wire order", async () => {
  const s = await serve((_req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/html",
      "X-Powered-By": "PHP/7.4.0",
      "Set-Cookie": "sid=abc; Path=/",
    })
    res.end("<html><head><title>T</title></head><body>hello</body></html>")
  })
  const p = project()
  try {
    const out = await secRecon.execute({ target: `${s.url}/`, check: "http" }, p.ctx)
    assert.match(out, /archived HTTP transcript: E-[0-9a-f]{8}/)

    const rec = listEvidence(p.root)[0]!
    assert.equal(rec.source, "sec_recon")
    assert.equal(rec.target, `127.0.0.1:${s.port}`)

    const body = readEvidence(p.root, rec.id)!
    assert.match(body, /^# sec_recon http — /)
    assert.match(body, /HTTP\/1\.1 200 OK\r\n/)
    assert.match(body, /X-Powered-By: PHP\/7\.4\.0/)
    assert.match(body, /Set-Cookie: sid=abc; Path=\//)
    // header order is preserved: Content-Type was written first
    assert.ok(body.indexOf("Content-Type") < body.indexOf("X-Powered-By"), "wire order should survive")
    assert.match(body, /<title>T<\/title>/)

    // the artifact is stored under the same integrity regime as any other
    assert.deepEqual(verifyEvidenceStore(p.root).map((v) => v.state), ["ok"])
  } finally {
    await s.stop()
  }
})

test("the archived transcript is faithful to what the client received", async () => {
  const s = await serve((_req, res) => {
    res.writeHead(404, { "X-Marker": "unique-value-12345" })
    res.end("not found")
  })
  const p = project()
  try {
    await secRecon.execute({ target: `${s.url}/missing`, check: "http" }, p.ctx)
    const body = readEvidence(p.root, listEvidence(p.root)[0]!.id)!
    assert.match(body, /HTTP\/1\.1 404 Not Found\r\n/)
    assert.match(body, /X-Marker: unique-value-12345/)
    assert.match(body, /not found$/)
  } finally {
    await s.stop()
  }
})

test("archive=false leaves the store empty", async () => {
  const s = await serve((_req, res) => res.end("ok"))
  const p = project()
  try {
    const out = await secRecon.execute({ target: `${s.url}/`, check: "http", archive: false }, p.ctx)
    assert.doesNotMatch(out, /archived HTTP transcript/)
    assert.deepEqual(listEvidence(p.root), [])
  } finally {
    await s.stop()
  }
})

test("a redirect chain archives every hop, not just the last response", async () => {
  const s = await serve((req, res) => {
    if (req.url === "/start") {
      res.writeHead(302, { Location: "/landing" })
      res.end()
      return
    }
    res.writeHead(200, { "X-Final": "yes" })
    res.end("arrived")
  })
  const p = project()
  try {
    await secRecon.execute({ target: `${s.url}/start`, check: "http" }, p.ctx)
    const body = readEvidence(p.root, listEvidence(p.root)[0]!.id)!
    assert.match(body, /HTTP\/1\.1 302 Found\r\n/)
    assert.match(body, /Location: \/landing/)
    assert.match(body, /HTTP\/1\.1 200 OK\r\n/)
    assert.match(body, /X-Final: yes/)
  } finally {
    await s.stop()
  }
})

/* ------------------------------------------------------------- truncation --- */

test("a body larger than the capture limit is marked as truncated, not silently cut", async () => {
  const s = await serve((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain" })
    res.end("A".repeat(200 * 1024))
  })
  try {
    const res = await httpProbe(`${s.url}/big`, { allowBody: true })
    assert.equal(res.bodyBytes, 200 * 1024)
    assert.ok(res.transcript!.includes("[body truncated:"), "the transcript must say it is incomplete")
    assert.match(res.transcript!, /of 204800 bytes retained/)
  } finally {
    await s.stop()
  }
})

test("a truncated archive is still stored whole, without hitting the evidence limit", async () => {
  const s = await serve((_req, res) => {
    res.writeHead(200)
    res.end("B".repeat(200 * 1024))
  })
  const p = project()
  try {
    await secRecon.execute({ target: `${s.url}/`, check: "http" }, p.ctx)
    const rec = listEvidence(p.root)[0]!
    assert.equal(rec.truncated, false, "the recon archive already caps the body, so the store does not re-truncate it")
    assert.deepEqual(verifyEvidenceStore(p.root).map((v) => v.state), ["ok"])
  } finally {
    await s.stop()
  }
})

test("recon scans a target even when the allow-list excludes it", async () => {
  const s = await serve((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" })
    res.end("<title>still scanning</title>")
  })
  const p = project({ authorized_all: false, include: [{ host: "example.com" }], exclude: ["127.0.0.1"] })
  try {
    const out = await secRecon.execute({ target: `${s.url}/`, check: "headers" }, p.ctx)
    assert.match(out, /security headers grade/)
    assert.doesNotMatch(out, /not covered by any authorized scope entry|explicitly excluded/)
  } finally {
    await s.stop()
  }
})

test("a metadata redirect is refused and the archive says where it stopped", async () => {
  const s = await serve((_req, res) => {
    res.writeHead(302, { Location: "http://169.254.169.254/latest/meta-data/" })
    res.end()
  })
  // Scans ignore the allow-list, but metadata/link-local is an absolute refusal.
  const p = project({ authorized_all: false, include: [{ host: "127.0.0.1" }] })
  try {
    const out = await secRecon.execute({ target: `${s.url}/`, check: "http" }, p.ctx)
    assert.match(out, /STOPPED at/)
    const body = readEvidence(p.root, listEvidence(p.root)[0]!.id)!
    assert.match(body, /HTTP\/1\.1 302 Found\r\n/)
    // the Location header is the allowed hop's own evidence and must survive…
    assert.match(body, /Location: http:\/\/169\.254\.169\.254\/latest\/meta-data\//)
    // …but the refused hop itself was never fetched, so there is only one response
    assert.equal((body.match(/HTTP\/1\.1 /g) ?? []).length, 1, "only the authorized hop was fetched")
  } finally {
    await s.stop()
  }
})
