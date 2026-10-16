/**
 * Scope, network-safety and path resolution.
 *
 * The important regression here is the DEFAULT POSTURE: authorized-by-default.
 * An earlier build denied everything until an operator wrote a scope file,
 * which made the tool unusable as an agentic CLI.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { join } from "node:path"
import { homedir } from "node:os"
import { authorize, authorizeResolved, describeScope } from "../scope.ts"
import { DEFAULT_SCOPE, normalizeScope, validateScope, scopeTemplate } from "../config.ts"
import { hostFromUrl, ipv4InCidr, isIp, isPrivateAddress, isUnconditionallyDenied } from "../netsafe.ts"
import { engagementDir, resolveProjectRoot, setRuntimeRoot } from "../paths.ts"

const AUTHORIZED_ALL = { ...DEFAULT_SCOPE }

test("default posture: every target is authorized at every intensity", () => {
  for (const host of ["example.com", "10.0.0.5", "127.0.0.1", "203.0.113.10", "sub.deep.example.org"]) {
    for (const intensity of ["passive", "safe-active", "intrusive", "exploit"] as const) {
      const d = authorize(AUTHORIZED_ALL, { host }, intensity)
      assert.equal(d.allowed, true, `${host} @ ${intensity} should be allowed`)
      assert.equal(d.code, "scope.authorized-all")
      assert.equal(d.requiresApproval, false)
    }
  }
})

test("default posture: no scope file, no include list, no denial", () => {
  assert.equal(AUTHORIZED_ALL.authorized_all, true)
  assert.equal(AUTHORIZED_ALL.include.length, 0)
  assert.equal(AUTHORIZED_ALL.intensity, "exploit")
})

test("default posture: resolved-address re-check does not deny either", () => {
  const d = authorizeResolved(AUTHORIZED_ALL, { host: "example.com" }, ["169.254.169.254"])
  assert.equal(d.allowed, true)
})

test("authorized_all still reports a target it cannot parse", () => {
  const d = authorize(AUTHORIZED_ALL, { host: "   " }, "passive")
  assert.equal(d.allowed, false)
  assert.equal(d.code, "target.empty")
})

/* ------------------------------------------------------- allow-list mode --- */

const LIST_MODE = normalizeScope({
  engagement: "unit-allow-list",
  authorized_all: false,
  intensity: "safe-active",
  allow_private: true,
  include: [{ host: "127.0.0.1", ports: [8080, 8443] }, { host: "*.example.com" }, { host: "10.0.0.0/24" }],
  exclude: ["secret.example.com"],
})

test("allow-list: exact host, wildcard subdomain and CIDR match", () => {
  assert.equal(authorize(LIST_MODE, { host: "127.0.0.1", port: 8080 }, "safe-active").allowed, true)
  assert.equal(authorize(LIST_MODE, { host: "api.example.com" }, "passive").allowed, true)
  assert.equal(authorize(LIST_MODE, { host: "10.0.0.42" }, "safe-active").allowed, true)
})

test("allow-list: wildcard does not cover the bare domain", () => {
  const d = authorize(LIST_MODE, { host: "example.com" }, "passive")
  assert.equal(d.allowed, false)
  assert.equal(d.code, "scope.miss")
})

test("allow-list: unlisted host is refused", () => {
  assert.equal(authorize(LIST_MODE, { host: "evil.test" }, "passive").code, "scope.miss")
})

test("allow-list: exclusions beat inclusions", () => {
  const d = authorize(LIST_MODE, { host: "secret.example.com" }, "passive")
  assert.equal(d.allowed, false)
  assert.equal(d.code, "scope.excluded")
})

test("allow-list: port outside the entry allowance is refused", () => {
  const d = authorize(LIST_MODE, { host: "127.0.0.1", port: 22 }, "safe-active")
  assert.equal(d.allowed, false)
  assert.equal(d.code, "scope.port")
})

test("allow-list: intensity ceiling is enforced", () => {
  const d = authorize(LIST_MODE, { host: "api.example.com" }, "intrusive")
  assert.equal(d.allowed, false)
  assert.equal(d.code, "policy.intensity")
})

test("allow-list: cloud metadata is never permitted", () => {
  for (const host of ["169.254.169.254", "metadata.google.internal"]) {
    const d = authorize(LIST_MODE, { host }, "passive")
    assert.equal(d.allowed, false, host)
    assert.equal(d.code, "net.metadata")
  }
})

test("allow-list: private space requires allow_private", () => {
  const strict = normalizeScope({ ...LIST_MODE, allow_private: false, include: [{ host: "192.168.1.10" }] })
  const d = authorize(strict, { host: "192.168.1.10" }, "passive")
  assert.equal(d.allowed, false)
  assert.equal(d.code, "net.private")
})

test("allow-list: DNS re-validation catches a scoped name pointing at metadata", () => {
  const d = authorizeResolved(LIST_MODE, { host: "api.example.com" }, ["169.254.169.254"])
  assert.equal(d.allowed, false)
  assert.equal(d.code, "net.metadata")
})

/* -------------------------------------------------------------- config --- */

test("normalizeScope defaults to authorized_all when the file omits it", () => {
  const s = normalizeScope({ engagement: "partial", include: [{ host: "a.test" }] })
  assert.equal(s.authorized_all, true)
  assert.equal(s.block_destructive, true)
})

test("an explicit authorized_all:false is honoured", () => {
  const s = normalizeScope({ authorized_all: false, include: [{ host: "a.test" }] })
  assert.equal(s.authorized_all, false)
})

test("validateScope only complains about an empty include in allow-list mode", () => {
  assert.deepEqual(validateScope({ authorized_all: false, include: [] }).filter((p) => p.includes("include is empty")), [
    "include is empty while authorized_all is false: no target is authorized, every network action will be denied",
  ])
  assert.deepEqual(validateScope({ authorized_all: true, include: [] }), [])
  assert.equal(validateScope({ intensity: "nonsense" }).length, 1)
})

test("scopeTemplate is the opt-in restrictive document, not the default", () => {
  const t = scopeTemplate()
  assert.equal(t.authorized_all, false)
  assert.ok(t.include.length > 0)
})

test("describeScope states the mode plainly", () => {
  const all = describeScope(AUTHORIZED_ALL, "defaults")
  assert.match(all, /AUTHORIZED-ALL/)
  assert.match(all, /block_destructive: true/)
  const list = describeScope(LIST_MODE, "file")
  assert.match(list, /allow-list/)
  assert.doesNotMatch(list, /AUTHORIZED-ALL/)
})

/* --------------------------------------------------------------- paths --- */

test("resolveProjectRoot never returns the filesystem root", () => {
  setRuntimeRoot("/tmp")
  assert.equal(resolveProjectRoot("/"), "/tmp")
  assert.equal(engagementDir("/"), join("/tmp", ".nullbyte", "security"))
})

test("resolveProjectRoot prefers a usable explicit directory", () => {
  setRuntimeRoot("/tmp")
  assert.equal(resolveProjectRoot("/home"), "/home")
})

test("NULLBYTE_SECURITY_DIR overrides everything", () => {
  const prev = process.env.NULLBYTE_SECURITY_DIR
  process.env.NULLBYTE_SECURITY_DIR = "/tmp/nb-override"
  try {
    assert.equal(engagementDir("/home"), "/tmp/nb-override")
  } finally {
    if (prev === undefined) delete process.env.NULLBYTE_SECURITY_DIR
    else process.env.NULLBYTE_SECURITY_DIR = prev
  }
})

/* -------------------------------------------------------------- netsafe --- */

test("address classification", () => {
  assert.equal(isIp("127.0.0.1"), true)
  assert.equal(isIp("::1"), true)
  assert.equal(isIp("example.com"), false)
  assert.equal(ipv4InCidr("10.0.0.5", "10.0.0.0/24"), true)
  assert.equal(ipv4InCidr("10.0.1.5", "10.0.0.0/24"), false)
  assert.equal(isPrivateAddress("192.168.1.1"), true)
  assert.equal(isPrivateAddress("8.8.8.8"), false)
  assert.equal(isUnconditionallyDenied("169.254.169.254").denied, true)
  assert.equal(isUnconditionallyDenied("example.com").denied, false)
})

test("hostFromUrl handles ports, ipv6 and paths", () => {
  assert.deepEqual(hostFromUrl("https://h.example:8443/a/b"), { host: "h.example", port: 8443, scheme: "https", path: "/a/b" })
  assert.equal(hostFromUrl("http://[::1]:8080/")?.host, "::1")
  assert.equal(hostFromUrl("not a url"), null)
})

test("homedir sanity: the default project root is never the filesystem root", () => {
  assert.notEqual(homedir(), "/")
})
