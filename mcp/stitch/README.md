# mcp/stitch

Stitch MCP stdio bridge for the NullByte CLI.

[Google Stitch](https://stitch.withgoogle.com) (`https://stitch.googleapis.com/mcp`,
listed in Google Cloud MCP as **Stitch (Beta)**) is a *remote* MCP server. NullByte
connects to *local* stdio MCP servers, so this wrapper bridges the two: it starts a
`StitchProxy` on a `StdioServerTransport` and hands the agent Stitch's design tools.

## Tools exposed

| Tool | Purpose |
|---|---|
| `create_project` / `get_project` / `list_projects` / `delete_project` | manage Stitch projects |
| `list_screens` / `get_screen` | read existing screens |
| `generate_screen_from_text` | generate a screen from a prompt |
| `edit_screens` | iterate a screen in place |
| `generate_variants` | layout / colour / font / copy variations |
| `upload_design_md` | import a DESIGN.md |
| `create_design_system` / `create_design_system_from_design_md` / `update_design_system` / `list_design_systems` / `apply_design_system` | design systems / theming |
| `download_assets` | pull generated HTML + screenshots |

## Setup

1. **API key** — Stitch → Settings → API keys → create one, then:

   ```bash
   umask 077
   printf '%s' 'YOUR_KEY' > ~/.config/nullbyte/stitch.key
   chmod 600 ~/.config/nullbyte/stitch.key
   ```

   The key is never written into any config file. It is gitignored (`*.key`).

2. **Dependencies** for the bridge:

   ```bash
   cd mcp/stitch && npm install
   ```

3. **Register the server** in `~/.config/nullbyte/nullbyte.jsonc`:

   ```jsonc
   {
     "mcp": {
       "stitch": {
         "type": "local",
         "command": ["node", "/absolute/path/to/nullbyte-security/mcp/stitch/stitch-proxy.mjs"],
         "enabled": true,
         "environment": {
           "STITCH_API_KEY": "{file:~/.config/nullbyte/stitch.key}"
         }
       }
     }
   }
   ```

   `command` must be an **absolute** path to the proxy. The env entry is optional —
   the proxy also reads `~/.config/nullbyte/stitch.key` itself.

4. **Restart NullByte.** Config is read once at startup and is not hot-reloaded, so
   the Stitch tools do not exist until the CLI is relaunched.

## Auth alternatives

| Variable | Notes |
|---|---|
| `STITCH_API_KEY` | API key (env; takes precedence over the key file) |
| `STITCH_ACCESS_TOKEN` + `GOOGLE_CLOUD_PROJECT` | OAuth instead of an API key |
| `STITCH_HOST` | override the endpoint (default `https://stitch.googleapis.com/mcp`) |

## Caveats

- `@google/stitch-sdk` carries Google's own *"not an officially supported Google
  product"* disclaimer; the endpoint itself is **Beta**. Beta tools move — if the
  bridge breaks after a Stitch update, suspect the SDK first.
- stdout is the MCP transport. Never `console.log` in this process; log to stderr.
- `generate` / `edit` / `variants` can end with a clarifying question instead of
  screens — the SDK surfaces that as a recoverable `CLARIFICATION_REQUIRED` error.
