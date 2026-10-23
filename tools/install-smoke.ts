/**
 * Deterministic install gate.
 *
 * The full suite includes timing, optional PDF converters, local sockets and
 * POSIX permission checks. Those are valuable, but a device without a working
 * converter or with different mode-bit semantics should not be told that the
 * plugin failed to install. This smoke test checks the things an installation
 * actually needs: the plugin module loads, every security tool is registered
 * with an executable body, and the knowledge base is present.
 *
 * `npm test` remains the full suite. `install.sh --full-test` runs it
 * explicitly; the default install runs this file.
 */

import assert from "node:assert/strict"
import { resolve } from "node:path"
import { pathToFileURL } from "node:url"
import { NullByteSecurity } from "../plugin/nullbyte-security.ts"
import { FRAGMENTS } from "../security-lib/methodology.ts"
import { SECURITY_TOOL_IDS, buildSecurityTools } from "../security-lib/tools/index.ts"
import { SECURITY_REMINDER, SECURITY_WORKFLOW } from "../security-lib/workflow.ts"

export function installSmoke(): { tools: number; fragments: number } {
  assert.equal(typeof NullByteSecurity, "function", "plugin entry point did not load")

  const tools = buildSecurityTools()
  for (const id of SECURITY_TOOL_IDS) {
    const tool = tools[id]
    assert.ok(tool, `tool ${id} is not registered`)
    assert.equal(typeof tool.execute, "function", `tool ${id} has no execute function`)
    assert.equal(typeof tool.description, "string", `tool ${id} has no description`)
    assert.ok(tool.description.length > 20, `tool ${id} description is too thin`)
  }

  assert.ok(FRAGMENTS.length >= 30, "knowledge base is unexpectedly small")
  assert.ok(FRAGMENTS.some((f) => f.id === "scope-and-authorization"), "security methodology is missing")
  assert.ok(FRAGMENTS.some((f) => f.id === "debugging"), "coding skills are missing")
  assert.match(SECURITY_WORKFLOW, /sec_recon/, "workflow is missing recon")
  assert.match(SECURITY_REMINDER, /sec_/, "reminder is missing the security toolset")

  return { tools: SECURITY_TOOL_IDS.length, fragments: FRAGMENTS.length }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = installSmoke()
  console.log(`install smoke ok: ${result.tools} tools, ${result.fragments} fragments`)
}
