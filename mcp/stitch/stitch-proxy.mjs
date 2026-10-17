#!/usr/bin/env node
/**
 * Stitch MCP stdio bridge for the NullByte CLI.
 *
 * Google Stitch (https://stitch.googleapis.com/mcp) is a remote MCP server.
 * NullByte's `mcp` config can point at a local stdio server, so this thin
 * wrapper bridges the two: it starts a StitchProxy on a StdioServerTransport
 * and lets the agent call Stitch's design tools directly —
 *
 *   create_project, list_projects, get_project, delete_project
 *   list_screens, get_screen, generate_screen_from_text, edit_screens,
 *   generate_variants, upload_design_md
 *   create_design_system, create_design_system_from_design_md,
 *   update_design_system, list_design_systems, apply_design_system
 *   download_assets
 *
 * Auth resolution order:
 *   1. STITCH_API_KEY            (env)
 *   2. ~/.config/nullbyte/stitch.key   (chmod 600, one line, no trailing junk)
 *   -- or OAuth: STITCH_ACCESS_TOKEN + GOOGLE_CLOUD_PROJECT
 *
 * Host override: STITCH_HOST (default https://stitch.googleapis.com/mcp)
 *
 * NOTE: stdout is reserved for the MCP protocol. All logging goes to stderr —
 * anything printed to stdout corrupts the JSON-RPC stream.
 */
import { StitchProxy } from "@google/stitch-sdk"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

let apiKey = process.env.STITCH_API_KEY
if (!apiKey) {
  try {
    apiKey = readFileSync(join(homedir(), ".config/nullbyte/stitch.key"), "utf8").trim()
  } catch {
    /* fall through to the auth check below */
  }
}

const accessToken = process.env.STITCH_ACCESS_TOKEN
const quotaProjectId = process.env.GOOGLE_CLOUD_PROJECT

if (!apiKey && !accessToken) {
  console.error(
    "[stitch-proxy] missing auth: set STITCH_API_KEY, or STITCH_ACCESS_TOKEN (+ GOOGLE_CLOUD_PROJECT)"
  )
  process.exit(1)
}

const proxy = new StitchProxy({
  apiKey,
  accessToken,
  quotaProjectId,
  url: process.env.STITCH_HOST || "https://stitch.googleapis.com/mcp",
})

await proxy.start(new StdioServerTransport())
console.error("[stitch-proxy] online")
