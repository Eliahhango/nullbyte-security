/**
 * Installer safety.
 *
 * Regression: install.sh linked the plugin before running tests. A single
 * environment-sensitive test then aborted the run after the live installation
 * had already been changed, so users saw "test failed" and a half-applied
 * install. Validation must happen first, and a failed validation must leave the
 * previous installation byte-for-byte intact.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

const repo = fileURLToPath(new URL("../../", import.meta.url))
const installer = join(repo, "install.sh")

function fakeNpm(dir: string): string {
  const bin = join(dir, "bin")
  mkdirSync(bin, { recursive: true })
  const npm = join(bin, "npm")
  writeFileSync(
    npm,
    [
      "#!/bin/sh",
      "echo \"simulated test failure: $*\" >&2",
      "exit 1",
      "",
    ].join("\n"),
  )
  chmodSync(npm, 0o755)
  return bin
}

function runInstaller(config: string, args: string[], pathPrefix?: string) {
  return spawnSync("bash", [installer, ...args], {
    cwd: repo,
    encoding: "utf8",
    timeout: 30_000,
    env: {
      ...process.env,
      NULLBYTE_CONFIG: config,
      PATH: pathPrefix ? `${pathPrefix}:${process.env.PATH ?? ""}` : process.env.PATH,
    },
  })
}

test("a failed smoke test does not modify an existing installation", () => {
  const work = mkdtempSync(join(tmpdir(), "nb-install-fail-"))
  const config = join(work, "config")
  const pluginDir = join(config, "plugin")
  mkdirSync(pluginDir, { recursive: true })
  const oldLib = join(config, "security-lib")
  const oldPlugin = join(pluginDir, "nullbyte-security.ts")
  writeFileSync(oldLib, "old-lib")
  writeFileSync(oldPlugin, "old-plugin")
  const bin = fakeNpm(work)

  const result = runInstaller(config, ["--no-deps"], bin)
  const output = `${result.stdout}\n${result.stderr}`

  assert.notEqual(result.status, 0, "the installer must fail when its smoke test fails")
  assert.match(output, /install smoke test failed/i)
  assert.match(output, /installed links were not changed/i)
  assert.equal(readFileSync(oldLib, "utf8"), "old-lib", "the old security-lib was changed")
  assert.equal(readFileSync(oldPlugin, "utf8"), "old-plugin", "the old plugin was changed")
  assert.equal(
    readdirSync(config).some((name) => name.includes(".bak.")),
    false,
    "a failed validation must not start the backup/replace phase",
  )
})

test("a successful validation installs the links", () => {
  const work = mkdtempSync(join(tmpdir(), "nb-install-ok-"))
  const config = join(work, "config")

  const result = runInstaller(config, ["--no-deps", "--no-test"])
  const output = `${result.stdout}\n${result.stderr}`

  assert.equal(result.status, 0, output)
  assert.match(output, /Installation verified/)
  assert.equal(existsSync(join(config, "security-lib")), true)
  assert.equal(existsSync(join(config, "plugin", "nullbyte-security.ts")), true)
  assert.equal(readlinkSync(join(config, "security-lib")), join(repo, "security-lib"))
  assert.equal(
    readlinkSync(join(config, "plugin", "nullbyte-security.ts")),
    join(repo, "plugin", "nullbyte-security.ts"),
  )
})
