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
import { authorize, authorizeOpen, authorizePorts, authorizeResolved, describeScope, portAllowance } from "../scope.ts"
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

test("default posture: metadata is still refused, before resolution", () => {
  for (const host of ["169.254.169.254", "metadata.google.internal"]) {
    const d = authorize(AUTHORIZED_ALL, { host }, "passive")
    assert.equal(d.allowed, false, host)
    assert.equal(d.code, "net.metadata")
  }
})

test("default posture: resolved-address re-check still refuses metadata", () => {
  const d = authorizeResolved(AUTHORIZED_ALL, { host: "example.com" }, ["169.254.169.254"])
  assert.equal(d.allowed, false)
  assert.equal(d.code, "net.metadata")
})

test("authorizeOpen ignores allow-lists but keeps the absolute metadata guard", () => {
  for (const host of ["evil.test", "127.0.0.1", "10.0.0.5"]) {
    const d = authorizeOpen({ host, port: 8081 }, "intrusive")
    assert.equal(d.allowed, true, host)
    assert.equal(d.code, "scope.authorized-all")
    assert.equal(d.requiresApproval, false)
  }
  const denied = authorizeOpen({ host: "169.254.169.254" }, "passive")
  assert.equal(denied.allowed, false)
  assert.equal(denied.code, "net.metadata")
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
  assert.match(all, /scan_authorization: unrestricted/)
  const list = describeScope(LIST_MODE, "file")
  assert.match(list, /allow-list/)
  assert.match(list, /scan_authorization: unrestricted/)
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

/* ---------------------------------------------- multi-port scan regression --- */

// Regression: sec_ports/sec_scan called authorize() with a host-only target, so
// `target.port` was undefined and the entry's port allowance was never checked.
// A scoped engagement that authorized only 127.0.0.1:8080 still scanned 8081.

test("authorizePorts: refuses a scan containing a port outside the entry's allowance", () => {
  const r = authorizePorts(LIST_MODE, "127.0.0.1", [8080, 8081], "safe-active")
  assert.equal(r.allowed, false)
  assert.deepEqual(r.deniedPorts, [8081])
  assert.equal(r.decision.code, "scope.port")
  assert.match(r.decision.reason, /8081/)
})

test("authorizePorts: allows a scan whose ports are all inside the allowance", () => {
  const r = authorizePorts(LIST_MODE, "127.0.0.1", [8080, 8443], "safe-active")
  assert.equal(r.allowed, true)
  assert.deepEqual(r.deniedPorts, [])
})

test("authorizePorts: an unrestricted entry allows any port", () => {
  const r = authorizePorts(LIST_MODE, "10.0.0.42", [22, 443, 65535], "safe-active")
  assert.equal(r.allowed, true)
})

test("authorizePorts: authorized_all still permits everything", () => {
  assert.equal(authorizePorts(AUTHORIZED_ALL, "anything.test", [1, 2, 3], "intrusive").allowed, true)
})

test("authorizePorts: an excluded host is refused for every port", () => {
  const r = authorizePorts(LIST_MODE, "secret.example.com", [443], "passive")
  assert.equal(r.allowed, false)
  assert.equal(r.decision.code, "scope.excluded")
})

test("authorizePorts: intensity ceiling still applies", () => {
  const r = authorizePorts(LIST_MODE, "10.0.0.42", [443], "intrusive")
  assert.equal(r.allowed, false)
  assert.equal(r.decision.code, "policy.intensity")
})

test("authorizePorts: metadata address is refused regardless of ports", () => {
  const r = authorizePorts(LIST_MODE, "169.254.169.254", [80], "passive")
  assert.equal(r.allowed, false)
  assert.equal(r.decision.code, "net.metadata")
})

test("portAllowance: reports the entry's port restriction, or undefined when unrestricted", () => {
  assert.deepEqual(portAllowance(LIST_MODE, "127.0.0.1"), [8080, 8443])
  assert.equal(portAllowance(LIST_MODE, "10.0.0.42"), undefined)
  assert.equal(portAllowance(LIST_MODE, "unlisted.test"), undefined)
  assert.equal(portAllowance(AUTHORIZED_ALL, "anything.test"), undefined)
})

