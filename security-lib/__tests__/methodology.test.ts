/**
 * Methodology knowledge base.
 *
 * Regression: scoring used plain substring matching, so the shorthand `rce`
 * matched the "fo(rce)d" in "forced-browsing" and ranked `access-control` above
 * `command-injection`. Matching is now word-boundary aware.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { FRAGMENTS, listFragments, loadFragment, searchFragments } from "../methodology.ts"

test("every fragment is well formed and uniquely identified", () => {
  const ids = new Set<string>()
  for (const f of FRAGMENTS) {
    assert.ok(f.id.length > 0, "fragment id must not be empty")
    assert.ok(!ids.has(f.id), `duplicate fragment id: ${f.id}`)
    ids.add(f.id)
    assert.ok(f.title.length > 0, `${f.id}: title must not be empty`)
    assert.ok(f.tags.length > 0, `${f.id}: needs at least one tag`)
    assert.ok(f.body.split("\n").length >= 3, `${f.id}: body is too thin to be useful`)
  }
  assert.equal(listFragments().length, FRAGMENTS.length)
})

test("shorthand queries resolve to the right fragment first", () => {
  const cases: Array<[string, string]> = [
    ["xss", "xss"],
    ["cross-site scripting", "xss"],
    ["sqli", "sqli"],
    ["sql injection", "sqli"],
    ["ssrf", "ssrf"],
    ["server-side request forgery", "ssrf"],
    ["idor", "idor"],
    ["bola", "idor"],
    ["rce", "command-injection"],
    ["command injection", "command-injection"],
    ["jwt", "auth-session"],
    ["csrf", "auth-session"],
    ["path traversal", "path-traversal"],
    ["lfi", "path-traversal"],
    ["file upload", "file-upload"],
    ["graphql", "api-testing"],
    ["mass assignment", "api-testing"],
    ["metadata", "ssrf"],
    ["exploit safety", "exploit-discipline"],
    ["recon", "recon-web"],
    ["evidence", "evidence-capture"],
    ["scope", "scope-and-authorization"],
  ]
  for (const [query, expected] of cases) {
    const hits = searchFragments(query, 3)
    assert.ok(hits.length > 0, `no fragment matched "${query}"`)
    assert.equal(hits[0].id, expected, `"${query}" should rank ${expected} first, got ${hits.map((h) => h.id).join(", ")}`)
  }
})

test("shorthand must not match on a substring inside another word", () => {
  // "rce" lives inside "forced" — that must not count.
  const hits = searchFragments("rce", 3).map((f) => f.id)
  assert.equal(hits[0], "command-injection")
  assert.ok(!hits.includes("access-control") || hits.indexOf("access-control") > 0, "access-control must not outrank command-injection")
})

test("nonsense returns nothing rather than a guess", () => {
  assert.deepEqual(searchFragments("zzzznope"), [])
  assert.deepEqual(searchFragments("   "), [])
})

test("loadFragment accepts an exact id and a partial id", () => {
  assert.equal(loadFragment("xss")?.id, "xss")
  assert.equal(loadFragment("  SSRF  ")?.id, "ssrf")
  assert.equal(loadFragment("command-inj")?.id, "command-injection")
  assert.equal(loadFragment("no-such-fragment"), undefined)
})

test("vulnerability classes are actually covered", () => {
  const ids = new Set(FRAGMENTS.map((f) => f.id))
  for (const required of ["xss", "sqli", "ssrf", "idor", "auth-session", "access-control", "path-traversal", "command-injection", "file-upload", "api-testing"]) {
    assert.ok(ids.has(required), `knowledge base is missing the ${required} fragment`)
  }
})

test("safety guidance is present in the offensive fragments", () => {
  const xss = loadFragment("xss")!
  assert.match(xss.body, /canary|marker/i, "xss fragment should require a confirmation marker")
  const cmd = loadFragment("command-injection")!
  assert.match(cmd.body, /read-only|never run/i, "command-injection must state the read-only rule")
  const exploit = loadFragment("exploit-discipline")!
  assert.match(exploit.body, /never run destructive|destructive/i)
})
