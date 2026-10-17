/**
 * Per-target directories.
 *
 * The host string reaches targetSlug from user input and from tool output, and
 * it is then used to build a path. Two properties matter and are pinned here:
 * a host can never produce a path outside the project root, and one target
 * always maps to exactly one directory — otherwise "revisit a target" silently
 * creates a second one.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve, sep } from "node:path"
import { targetSlug, targetDir, targetPaths, ensureTarget, writeTargetLog } from "../target-dir.ts"

// Point the global policy at a file that does not exist, so the tests see the
// defaults rather than whatever the operator has configured machine-wide.
const policyDir = mkdtempSync(join(tmpdir(), "nb-policy-"))
process.env.NULLBYTE_SECURITY_POLICY = join(policyDir, "security.json")

const tmp = () => mkdtempSync(join(tmpdir(), "nb-target-"))

function setPolicy(body: unknown): void {
  writeFileSync(process.env.NULLBYTE_SECURITY_POLICY!, JSON.stringify(body), "utf8")
}

function clearPolicy(): void {
  rmSync(process.env.NULLBYTE_SECURITY_POLICY!, { force: true })
}

/* ------------------------------------------------------------------ slug --- */

test("targetSlug: a hostile host cannot escape the project root", () => {
  const hostile = [
    "../../etc/passwd",
    "..",
    ".",
    "/etc/passwd",
    "a/b/c",
    "..\\..\\windows\\system32",
    "app.acme.test/../../../../tmp",
    "\u0000null",
    "app\u0000.acme.test",
    " ",
    "",
  ]
  const root = resolve("/tmp/project")
  for (const host of hostile) {
    const slug = targetSlug(host)
    assert.ok(slug.length > 0, `empty slug for ${JSON.stringify(host)}`)
    assert.ok(!slug.includes("/"), `slug contains a separator: ${JSON.stringify(slug)}`)
    assert.ok(!slug.includes("\\"), `slug contains a backslash: ${JSON.stringify(slug)}`)
    assert.notEqual(slug, ".", `slug is the current directory for ${JSON.stringify(host)}`)
    assert.notEqual(slug, "..", `slug is the parent directory for ${JSON.stringify(host)}`)
    assert.ok(!slug.startsWith("."), `slug would be a hidden directory: ${JSON.stringify(slug)}`)
    const full = resolve(root, slug)
    assert.ok(
      full === root || full.startsWith(root + sep),
      `slug escaped the root: ${JSON.stringify(host)} -> ${full}`,
    )
  }
})

test("targetSlug: one target maps to exactly one directory", () => {
  // A URL, a host:port and a bare hostname are the same target. If they produced
  // different slugs, revisiting a target would silently create a second folder.
  for (const form of [
    "app.acme.test",
    "APP.ACME.TEST",
    "  app.acme.test  ",
    "app.acme.test:8443",
    "https://app.acme.test/",
    "https://app.acme.test/login?next=/admin",
    "https://user:pw@app.acme.test:8443/x",
  ]) {
    assert.equal(targetSlug(form), "app.acme.test", `wrong slug for ${JSON.stringify(form)}`)
  }
})

test("targetSlug: distinct targets stay distinct", () => {
  const slugs = [
    targetSlug("app.acme.test"),
    targetSlug("api.acme.test"),
    targetSlug("acme.test"),
    targetSlug("10.20.0.1"),
    targetSlug("10.20.0.2"),
  ]
  assert.equal(new Set(slugs).size, slugs.length, `collision among ${slugs.join(", ")}`)
})

test("targetSlug: CIDR and IPv6 keep their identity without becoming paths", () => {
  assert.equal(targetSlug("10.20.0.0/24"), "10.20.0.0_24")
  assert.equal(targetSlug("10.20.0.0/24").includes("/"), false)
  // A bracketed IPv6 literal is not treated as a path or a hidden file.
  const v6 = targetSlug("[::1]")
  assert.equal(v6.includes("/"), false)
  assert.ok(!v6.startsWith("."))
})

test("targetSlug: a very long host still yields a usable, unique name", () => {
  const a = `${"a".repeat(200)}.one.test`
  const b = `${"a".repeat(200)}.two.test`
  const sa = targetSlug(a)
  const sb = targetSlug(b)
  assert.ok(sa.length <= 100, `slug too long: ${sa.length}`)
  assert.notEqual(sa, sb, "two long hosts sharing a prefix collided")
})

/* ------------------------------------------------------------- directory --- */

test("targetDir: always resolves inside the project root", () => {
  const root = tmp()
  for (const host of ["app.acme.test", "../../etc/passwd", "10.20.0.0/24"]) {
    const dir = targetDir(root, host)
    assert.ok(dir.startsWith(root + sep), `${host} resolved outside the root: ${dir}`)
  }
})

test("ensureTarget: creates reports/ and logs/, and ignores itself in git", () => {
  const root = tmp()
  const paths = ensureTarget(root, "app.acme.test")
  assert.ok(paths, "expected a target directory")
  assert.ok(existsSync(paths!.reports), "reports/ was not created")
  assert.ok(existsSync(paths!.logs), "logs/ was not created")
  // A target directory holds raw tool output, which routinely contains
  // credentials; the self-ignore keeps a run inside a repo from committing it.
  assert.ok(existsSync(join(paths!.root, ".gitignore")))
  assert.match(readFileSync(join(paths!.root, ".gitignore"), "utf8"), /^\*/m)
})

test("ensureTarget: the same target reuses its directory, a new target gets a new one", () => {
  const root = tmp()
  const first = ensureTarget(root, "app.acme.test")
  const again = ensureTarget(root, "app.acme.test")
  assert.equal(first!.root, again!.root, "revisiting a target created a second directory")

  const other = ensureTarget(root, "api.acme.test")
  assert.notEqual(first!.root, other!.root, "two targets shared one directory")

  // And a URL form of an already-seen target lands in the same place.
  const viaUrl = ensureTarget(root, "https://app.acme.test/admin")
  assert.equal(viaUrl!.root, first!.root)

  assert.deepEqual(readdirSync(root).sort(), ["api.acme.test", "app.acme.test"])
})

test("targetPaths: is a pure lookup and does not touch the disk", () => {
  const root = tmp()
  const paths = targetPaths(root, "app.acme.test")
  assert.equal(paths.slug, "app.acme.test")
  assert.ok(!existsSync(paths.root), "targetPaths created a directory")
  assert.deepEqual(readdirSync(root), [])
})

test("ensureTarget: returns undefined when target_dirs is switched off", () => {
  setPolicy({ plugins: { target_dirs: false } })
  try {
    const root = tmp()
    assert.equal(ensureTarget(root, "app.acme.test"), undefined)
    assert.deepEqual(readdirSync(root), [], "a directory was created while the feature was off")
  } finally {
    clearPolicy()
  }
})

/* ------------------------------------------------------------------ logs --- */

test("writeTargetLog: lands under the target's logs/ and stores verbatim by default", () => {
  const root = tmp()
  const res = writeTargetLog(root, {
    sessionID: "s1",
    source: "nmap",
    target: "app.acme.test",
    command: "nmap -sT -- app.acme.test",
    exitCode: 0,
    durationMs: 12,
    stdout: "PORT 80/tcp open\ndb_password: S3cr3tPr0d\n",
    stderr: "",
  })
  assert.ok(res, "expected a log to be written")
  assert.equal(res!.redacted, false)
  assert.ok(res!.path.startsWith(join(root, "app.acme.test", "logs") + sep), `log outside the target dir: ${res!.path}`)
  const body = readFileSync(res!.path, "utf8")
  assert.ok(body.includes("S3cr3tPr0d"), "the credential was hidden from the log")
  assert.ok(body.includes("nmap -sT -- app.acme.test"), "the command was not recorded")
  assert.ok(body.includes("## stdout"), "stdout section missing")
  // Logs can hold credentials, so they are not world-readable.
  assert.equal(statSync(res!.path).mode & 0o777, 0o600)
})

test("writeTargetLog: includeSecrets:false redacts the log at capture", () => {
  const root = tmp()
  const res = writeTargetLog(root, {
    sessionID: "s1",
    source: "nuclei",
    target: "app.acme.test",
    stdout: "db_password: S3cr3tPr0d\n",
    includeSecrets: false,
  })
  assert.ok(res)
  assert.equal(res!.redacted, true)
  assert.ok(!readFileSync(res!.path, "utf8").includes("S3cr3tPr0d"), "a credential survived into the log")
})

test("writeTargetLog: two runs produce two logs, and nothing is overwritten", () => {
  const root = tmp()
  const input = { sessionID: "s1", source: "nmap", target: "app.acme.test", stdout: "a" }
  const a = writeTargetLog(root, input)
  const b = writeTargetLog(root, { ...input, stdout: "b" })
  assert.ok(a && b)
  assert.notEqual(a!.path, b!.path, "the second log overwrote the first")
  assert.equal(readdirSync(join(root, "app.acme.test", "logs")).length, 2)
})

test("writeTargetLog: returns undefined when target_dirs is switched off", () => {
  setPolicy({ plugins: { target_dirs: false } })
  try {
    const root = tmp()
    const res = writeTargetLog(root, { sessionID: "s1", source: "nmap", target: "app.acme.test", stdout: "x" })
    assert.equal(res, undefined)
    assert.deepEqual(readdirSync(root), [])
  } finally {
    clearPolicy()
  }
})
