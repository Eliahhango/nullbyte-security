# nullbyte-security

Security capability layer for the [NullByte](https://github.com/Eliahhango) CLI.
Adds an agentic pentesting toolset — scope enforcement, recon, port scanning,
scanner orchestration, secret scanning, evidence handling, CVSS-scored findings
and reporting — as a **plugin**, without touching the host CLI.

- 10 `sec_*` tools available to every agent
- Authorized by default, with opt-in perimeter lockdown for real engagements
- Findings, evidence, audit trail and reports persisted per project
- 25-fragment methodology knowledge base
- 154 unit tests

> Authorized testing only. Point it at systems you own or have written permission
> to test.

## Install

```bash
git clone https://github.com/Eliahhango/nullbyte-security.git ~/nullbyte-security
cd ~/nullbyte-security && ./install.sh
```

`install.sh` symlinks the plugin into `~/.config/nullbyte/`, so `git pull` updates
the live install. Verify with `npm test`.

Config is read once at startup and is **not** hot-reloaded — restart nullbyte
after changing a plugin, agent or config file.

## Usage

Run nullbyte from the directory of the project you are assessing. All engagement
state lives in `<project>/.nullbyte/security/`, next to the code it concerns.

```bash
nullbyte                          # TUI, default agent
nullbyte run "recon app.acme.test and record what you find"
nullbyte run --continue           # resume the last session
nullbyte run -s <sessionID>       # resume a specific session
nullbyte run --agent plan "plan an assessment of app.acme.test"
nullbyte run --agent build "write a fuzzer for the login endpoint"
```

Talk to it in plain language — the agent selects the tools. Naming a tool
directly also works:

```
sec_scope  action=check target=app.acme.test
sec_recon  check=http target=https://app.acme.test
sec_ports  target=app.acme.test ports=80,443,8443
sec_report action=export format=all
```

### Modes

| Agent | Use |
|---|---|
| `void` (default) | full operator — plans and executes |
| `plan` | read-only strategist; produces a plan and cannot write files |
| `build` | executor; writes tooling and runs the operation |

Switch inside the TUI, or per run with `--agent`. The modes live in
`~/.config/nullbyte/agent/*.md` — edit those to change behaviour, then restart.

### CLI commands

| Command | Does |
|---|---|
| `nullbyte upgrade` | update the CLI. `--method curl\|npm\|pnpm\|bun\|brew\|choco\|scoop`, or pin a version: `nullbyte upgrade v1.2.3` |
| `nullbyte run [message]` | one-shot run. `-c` continue last, `-s <id>` session, `-m provider/model`, `--agent`, `-f <file>`, `--format json` |
| `nullbyte models [provider]` | list available models (`--refresh`, `--verbose`) |
| `nullbyte providers login` | manage credentials — `list`, `login [url]`, `logout [provider]` |
| `nullbyte agent list` | list agents. `agent create --description "..."` generates one |
| `nullbyte session list` | list sessions; `session delete <sessionID>` |
| `nullbyte plugin <module>` | install an npm plugin (`-g` global, `-f` force) |
| `nullbyte export [sessionID]` | export a session as JSON (`--sanitize` redacts) |
| `nullbyte stats` | token usage and cost |
| `nullbyte uninstall` | remove nullbyte and its files |

## Tools

| Tool | Purpose |
|---|---|
| `sec_scope` | authorization mode; `check` a target; `init` writes a starter scope |
| `sec_recon` | `dns\|http\|tls\|headers\|fingerprint` — real network calls |
| `sec_ports` | bounded TCP connect scan + banner grab |
| `sec_scan` | adapters: nmap, nuclei, nikto, whatweb, sslscan, sqlmap |
| `sec_sast` | local: `secrets`, `smells`, `deps` — secrets reported by location, never by value |
| `sec_evidence` | store/retrieve raw artifacts, redacted on write, SHA-256 indexed; `include_secrets=true` stores verbatim |
| `sec_finding` | findings; status derived, never asserted; closure gate; CVSS 3.1 severity; dedupe; evidence-reference checks |
| `sec_report` | preview or export as markdown, JSON, HTML or PDF into the run directory; `coverage=session` (default) stops one target's findings mixing into another's; `evidence=full` embeds artifact content, `redact=false` emits it verbatim |
| `sec_methodology` | search/load shared knowledge fragments |
| `sec_audit` | review every allow/deny/ask decision the tool layer made |

`bash`, `read`, `write`, `edit`, `webfetch` and `todowrite` are reused as-is.

## Posture

No scope ceremony by default: the operator is the authorizer, so targets are
permitted at every intensity. Two guards stay on because they protect *your*
machine, not the target — destructive commands (`rm -rf /`, `mkfs`, `dd` to a raw
device) and local credential files. Both are switchable off in config.

For a real engagement with a defined perimeter, write
`.nullbyte/security/scope.json`:

```json
{
  "engagement": "acme-q4",
  "authorized_all": false,
  "intensity": "safe-active",
  "allow_private": false,
  "include": [
    { "host": "app.acme.test", "ports": [443, 8443] },
    { "host": "*.acme.test" },
    { "host": "10.20.0.0/24" }
  ],
  "exclude": ["billing.acme.test"]
}
```

Grammar: `host`, `*.domain` (subdomains only), `domain` (domain + subdomains), IP,
CIDR, URL. `exclude` always wins. Scope is operator-authored — the agent cannot
widen it unless you explicitly allow it.

Enforcement runs in four layers — permission rules, the tool boundary, the tool
bodies, and an advisory system prompt — with every decision appended to the
project's audit log. The full breakdown is in
[docs/PENTEST.md](docs/PENTEST.md#4-enforcement).

## Lab

`node tools/lab/vulnerable-server.mjs` starts a deliberately vulnerable target on
loopback only — 8080 (reflected XSS, served `/.env`, missing headers), 8081
(HTTP Basic admin/admin, `/debug` env dump), 8443 (self-signed, no HSTS). Never
bind it to a public interface.

## Known limitations

- Connect scans only (no raw SYN/OS detection) — use the nmap adapter for that.
- Redirects on `webfetch` are validated by the tool, not the guard.
- Evidence is redacted before storage, so a stored artifact is not byte-exact when
  it contained secrets — unless it was captured with `include_secrets=true`.
- Redaction is best-effort pattern matching, not a guarantee. A report exported
  with `redact=false` is a credential dump by design; treat it as one.
- CVSS is base score only (no temporal/environmental).

## Docs

- [docs/PENTEST.md](docs/PENTEST.md) — full reference: tools, closure discipline, enforcement, gotchas
- [docs/HACKERAI_GAP_ANALYSIS.md](docs/HACKERAI_GAP_ANALYSIS.md) — capability comparison and non-adoptions
- [docs/IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md) — what is next

## License

MIT — see [LICENSE](LICENSE).
