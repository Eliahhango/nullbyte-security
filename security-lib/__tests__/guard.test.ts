/**
 * The enforcement hook.
 *
 * Two postures are covered:
 *   - default (authorized_all): the agent must be able to just work. Only
 *     unmistakable self-destruction and local credential theft are refused.
 *   - allow-list: opt-in, and then scope is enforced hard.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import { createToolGuard, isSensitivePath, parseTargetToken, securityAskRules, securityDenyRules, securityPermissionRules } from "../toolguard.ts"

function lab(scope?: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "nb-guard-"))
  if (scope !== undefined) {
    const sec = join(dir, ".nullbyte", "security")
    mkdirSync(sec, { recursive: true })
    writeFileSync(join(sec, "scope.json"), JSON.stringify(scope))
  }
  return dir
}

async function run(guard: ReturnType<typeof createToolGuard>, tool: string, args: any): Promise<{ allowed: boolean; code?: string }> {
  try {
    await guard({ tool, sessionID: "s", callID: "c" }, { args })
    return { allowed: true }
  } catch (e: any) {
    const m = /\[sec\] (\S+)/.exec(String(e.message))
    return { allowed: false, code: e.code ?? m?.[1] }
  }
}

/* --------------------------------------------------- default posture --- */

test("default posture: ordinary network commands run", async () => {
  const guard = createToolGuard({ worktree: lab() })
  for (const command of [
    "curl -s http://example.com",
    "nmap -sS -p 1-1000 10.0.0.5",
    "dig example.com",
    "bash -c 'curl http://example.com'",
    "cat scan.json | jq .",
    "ls -la",
  ]) {
    assert.deepEqual(await run(guard, "bash", { command }), { allowed: true }, command)
  }
})

test("default posture: webfetch is not gated", async () => {
  const guard = createToolGuard({ worktree: lab() })
  assert.deepEqual(await run(guard, "webfetch", { url: "https://anything.test/path" }), { allowed: true })
})

test("default posture: local source files are readable", async () => {
  const guard = createToolGuard({ worktree: lab() })
  assert.deepEqual(await run(guard, "read", { filePath: "/tmp/whatever/index.js" }), { allowed: true })
})

test("default posture: unmistakable destruction is still refused", async () => {
  const guard = createToolGuard({ worktree: lab() })
  for (const command of ["rm -rf /", "mkfs.ext4 /dev/sda1", "dd if=/dev/zero of=/dev/sda"]) {
    const r = await run(guard, "bash", { command })
    assert.equal(r.allowed, false, command)
    assert.equal(r.code, "policy.destructive")
  }
})

test("default posture: local credential stores are refused", async () => {
  const guard = createToolGuard({ worktree: lab() })
  for (const p of [join(homedir(), ".ssh", "id_rsa"), join(homedir(), ".aws", "credentials"), join(homedir(), ".config", "nullbyte", "auth.json")]) {
    const r = await run(guard, "read", { filePath: p })
    assert.equal(r.allowed, false, p)
    assert.equal(r.code, "local.secret")
  }
})

test("the credential guard can be switched off by the operator", async () => {
  const guard = createToolGuard({ worktree: lab(), protectLocalSecrets: false })
  assert.deepEqual(await run(guard, "read", { filePath: join(homedir(), ".ssh", "id_rsa") }), { allowed: true })
})

test("block_destructive:false is an explicit escape hatch", async () => {
  const guard = createToolGuard({ worktree: lab({ authorized_all: true, block_destructive: false }) })
  assert.deepEqual(await run(guard, "bash", { command: "rm -rf /" }), { allowed: true })
})

/* ----------------------------------------------------- allow-list mode --- */

const ALLOW_LIST = {
  engagement: "guard-unit",
  authorized_all: false,
  intensity: "safe-active",
  allow_private: true,
  include: [{ host: "example.com" }, { host: "127.0.0.1" }],
  exclude: ["bad.example.com"],
}

test("allow-list: in-scope target passes, out-of-scope target is refused", async () => {
  const guard = createToolGuard({ worktree: lab(ALLOW_LIST) })
  assert.deepEqual(await run(guard, "bash", { command: "curl -s http://example.com/" }), { allowed: true })
  const denied = await run(guard, "bash", { command: "curl -s http://evil.test/" })
  assert.equal(denied.allowed, false)
  assert.equal(denied.code, "scope.miss")
})

test("allow-list: exclusions and webfetch are enforced", async () => {
  const guard = createToolGuard({ worktree: lab(ALLOW_LIST) })
  assert.equal((await run(guard, "bash", { command: "curl http://bad.example.com/" })).code, "scope.excluded")
  assert.equal((await run(guard, "webfetch", { url: "https://evil.test/" })).code, "scope.miss")
  assert.deepEqual(await run(guard, "webfetch", { url: "https://example.com/" }), { allowed: true })
})

test("allow-list: command wrappers are refused because targets cannot be checked", async () => {
  const guard = createToolGuard({ worktree: lab(ALLOW_LIST) })
  const r = await run(guard, "bash", { command: "bash -c 'curl http://example.com'" })
  assert.equal(r.allowed, false)
  assert.equal(r.code, "policy.unanalyzable")
})

/* ------------------------------------------------------------- helpers --- */

test("isSensitivePath classifies credential stores", () => {
  assert.equal(isSensitivePath("/home/x/.ssh/id_ed25519").sensitive, true)
  assert.equal(isSensitivePath("/home/x/.config/nullbyte/auth.json").sensitive, true)
  assert.equal(isSensitivePath("/home/x/.nullbyte/security/scope.json").sensitive, true)
  assert.equal(isSensitivePath("/home/x/project/README.md").sensitive, false)
})

test("parseTargetToken handles urls, host:port, cidr and bare hosts", () => {
  assert.equal(parseTargetToken("http://h.example:8080/a")?.host, "h.example")
  assert.equal(parseTargetToken("h.example:8443")?.port, 8443)
  assert.equal(parseTargetToken("10.0.0.0/24")?.host, "10.0.0.0/24")
  assert.equal(parseTargetToken("h.example")?.host, "h.example")
  assert.equal(parseTargetToken("--flag"), null)
})

test("permission rules: destructive always denied, intrusive scanners opt-in", () => {
  const deny = securityDenyRules()
  assert.equal(deny["rm -rf *"], "deny")
  assert.equal(deny["mkfs*"], "deny")
  assert.equal(deny["nmap *"], undefined)

  const ask = securityAskRules()
  assert.equal(ask["nmap *"], "ask")
  assert.equal(ask["sqlmap *"], "ask")

  const all = securityPermissionRules()
  assert.equal(all["nmap *"], "ask")
  assert.equal(all["rm -rf *"], "deny")
})
