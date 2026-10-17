# nullbyte-security

Security capability layer for the [NullByte](https://github.com/Eliahhango) CLI
(an OpenCode-based terminal agent). Adds an agentic pentesting toolset — scope
enforcement, recon, port scanning, scanner orchestration, secret scanning,
evidence handling, CVSS-scored findings and reporting — as a **plugin**, without
touching the host CLI.

- 10 `sec_*` tools available to every agent
- Authorized by default, with opt-in perimeter lockdown for real engagements
- Findings, evidence, audit trail and reports persisted per project
- 25-fragment methodology knowledge base covering the common vulnerability classes
- 124 unit tests

> Built for authorized security testing. Point it at systems you own or have
> written permission to test.

## Install

```bash
git clone https://github.com/Eliahhango/nullbyte-security.git ~/nullbyte-security
cd ~/nullbyte-security && ./install.sh
```

Symlinks the plugin into `~/.config/nullbyte/`, so `git pull` updates the live
install. Verify with `npm test`.

## Tools

| Tool | Purpose |
|---|---|
| `sec_scope` | authorization mode; `check` a target; `init` writes a starter scope |
| `sec_recon` | `dns\|http\|tls\|headers\|fingerprint` — real network calls |
| `sec_ports` | bounded TCP connect scan + banner grab |
| `sec_scan` | adapters: nmap, nuclei, nikto, whatweb, sslscan, sqlmap |
| `sec_sast` | local: `secrets`, `smells`, `deps` — secrets reported by location, never by value |
| `sec_evidence` | store/retrieve raw artifacts, redacted on write, SHA-256 indexed |
| `sec_finding` | findings; status derived, never asserted; closure gate; CVSS 3.1 severity; dedupe; evidence-reference checks |
| `sec_report` | preview or export as markdown, JSON, HTML or PDF, written to the directory the agent was run in |
| `sec_methodology` | search/load shared knowledge fragments |
| `sec_audit` | review every allow/deny/ask decision the tool layer made |

`bash`, `read`, `write`, `edit`, `webfetch` and `todowrite` are reused as-is.

## Posture

No scope ceremony by default: the operator is the authorizer, so targets are
permitted at every intensity. Two guards stay on because they protect *your*
machine, not the target — destructive commands (`rm -rf /`, `mkfs`, `dd` to a raw
device) and local credential files. Both are switchable off in config.

### Locking it down

For a real engagement with a defined perimeter, create
`.nullbyte/security/scope.json` in the project:

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

Grammar: `host`, `*.domain` (subdomains only), `domain` (domain + subdomains),
IP, CIDR, URL. `exclude` always wins. Scope is operator-authored — the agent
cannot widen it unless you explicitly allow it.

## Enforcement

Four layers, outermost first:

1. **Permission rules** — destructive patterns deny always; intrusive scanners
   prompt only when you opt in, since prompting by default would stall
   non-interactive runs. Operator rules win.
2. **Tool boundary** — aborts the call before the body runs. Enforces
   destructive refusal, the credential guard, and target authorization for
   `bash`/`webfetch` in allow-list mode.
3. **Tool bodies** — per-call authorization, DNS re-validation, and an approval
   hook for intrusive operations. Port scanners authorize the host **and every
   individual port**: an entry allowing only `127.0.0.1:8080` refuses `8081`, and
   refuses the whole call if a port list mixes authorized and unauthorized ports.
4. **System prompt** — injects the shared workflow (advisory only).

Every decision is appended to the project's audit log with redacted arguments.
Engagement state lives with the project, so an assessment is reviewable and
resumable next to the code it concerns.

## Lab

`node tools/lab/vulnerable-server.mjs` starts a deliberately vulnerable target on
loopback only — 8080 (reflected XSS, served `/.env`, missing headers), 8081
(HTTP Basic admin/admin, `/debug` env dump), 8443 (self-signed, no HSTS). Never
bind it to a public interface.

## Known limitations

- Connect scans only (no raw SYN/OS detection) — use the nmap adapter for that.
- Redirects on `webfetch` are validated by the tool, not the guard.
- Evidence is redacted before storage, so a stored artifact is not byte-exact
  when it contained secrets.
- CVSS is base score only (no temporal/environmental).

## License

MIT — see [LICENSE](LICENSE).
