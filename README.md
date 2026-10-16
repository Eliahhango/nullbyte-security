# nullbyte-security

Security capability layer for the [NullByte](https://github.com/Eliahhango) CLI
(an OpenCode-based terminal agent). It adds an agentic pentesting toolset —
scope enforcement, recon, port scanning, scanner orchestration, secret scanning,
evidence handling, CVSS-scored findings and reporting — as a **plugin**, without
touching the host CLI.

- 10 `sec_*` tools available to every agent
- Authorized by default, with opt-in perimeter lockdown for real engagements
- Findings, evidence, audit trail and reports persisted per project
- 21-fragment methodology knowledge base covering the common vulnerability classes
- 75 unit tests

> Built for authorized security testing. Point it at systems you own or have
> written permission to test.

---

## Install

```bash
git clone https://github.com/Eliahhango/nullbyte-security.git ~/nullbyte-security
cd ~/nullbyte-security && ./install.sh
```

`install.sh` links `plugin/` and `security-lib/` into `~/.config/nullbyte/`
(symlinking, so `git pull` updates the live install) and installs dev
dependencies. Override the target with `NULLBYTE_CONFIG=/path/to/.config/nullbyte`.

Verify:

```bash
cd ~/nullbyte-security && npm test        # 75 tests
nullbyte models                            # native surface unchanged
```

---

## Tools

| Tool | Purpose |
|---|---|
| `sec_scope` | authorization mode; `check` a single target; `init` writes a starter scope file |
| `sec_recon` | `check=dns\|http\|tls\|headers\|fingerprint` — real network calls, manual redirect validation |
| `sec_ports` | bounded TCP connect scan + banner grab |
| `sec_scan` | external adapters: nmap, nuclei, nikto, whatweb, sslscan, sqlmap (argv-only, availability-checked) |
| `sec_sast` | local: `secrets`, `smells`, `deps` — secrets reported by location, values never printed |
| `sec_evidence` | store/retrieve raw artifacts, redacted on write, SHA-256 indexed |
| `sec_finding` | create/list/get/update findings; status derived, never asserted; closure gate (confirmed / ruled_out / open_proof_gap); severity from CVSS 3.1 metrics; semantic dedupe; evidence-reference checks |
| `sec_report` | preview or export the assessment as markdown + JSON, with closure summary |
| `sec_methodology` | search/load shared knowledge fragments (25, covering XSS, SQLi, SSRF, IDOR, auth/session, access control, path traversal, command injection, file upload, API testing, SSTI, insecure deserialization, subdomain takeover, open redirect, exploitation discipline) |
| `sec_audit` | review every allow/deny/ask decision the tool layer made |

`bash`, `read`, `write`, `edit`, `webfetch` and `todowrite` are reused as-is —
nothing is duplicated.

---

## Posture

There is no scope ceremony. Targets are permitted at every intensity because the
operator is the authorizer. Two guards stay on because they protect *your*
machine, not the target:

| Guard | Default | Turn off |
|---|---|---|
| `block_destructive` (`rm -rf /`, `mkfs`, `dd` to raw device) | on | `"block_destructive": false` |
| local credential protection (`~/.ssh/id_*`, `~/.aws/credentials`, `auth.json`, browser cookie DBs) | on | `plugins.protect_local_secrets: false` |

### Locking it down

For a real engagement with a defined perimeter, create
`<project>/.nullbyte/security/scope.json`:

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
cannot widen it unless you set `allow_model_scope_edit: true`.

Machine-wide defaults and plugin switches live in
`~/.config/nullbyte/security.json` — see `examples/security.json`.

---

## Enforcement

Four layers, outermost first:

1. **`config()`** — injects native permission rules. Destructive patterns map to
   `deny` always. Intrusive scanners map to `ask` **only** under
   `plugins.ask_intrusive_commands: true`; prompting by default would stall
   non-interactive runs. Operator-authored rules win.
2. **`tool.execute.before`** — awaited inside the executor, so throwing aborts
   before the tool body runs. Enforces destructive refusal, the credential
   guard, and (in allow-list mode) target authorization for `bash`/`webfetch`.
3. **Tool bodies** — per-call authorization, DNS re-validation, and an approval
   hook for intrusive operations. Port scanners authorize the host **and every
   individual port**: a scope entry that allows only `127.0.0.1:8080` refuses a
   scan of `8081`, and refuses the whole call if a port list mixes authorized
   and unauthorized ports.
4. **`experimental.chat.system.transform`** — injects the shared workflow
   (advisory only).

Every decision is appended to `<project>/.nullbyte/security/audit.jsonl` with
redacted arguments.

---

## Layout

```
plugin/nullbyte-security.ts    single auto-discovered entry point
security-lib/
  config.ts paths.ts scope.ts  posture, project resolution, authorization
  netsafe.ts redact.ts         SSRF guard, secret redaction
  toolguard.ts cmdsafe.ts      tool-boundary policy, shell parsing
  cvss31.ts findings.ts        scoring, dedupe, lifecycle
  evidence.ts report.ts        redacted artifacts, markdown/JSON export
  methodology.ts workflow.ts   knowledge base + injected workflow
  sast.ts                      secrets / smells / deps
  net/                         dns http tls headers fingerprint ports
  adapters/                    scanner registry + argv builders
  tools/                       the 10 sec_* tools
  __tests__/                   75 tests
<project>/.nullbyte/security/  engagement state (scope, findings, audit, evidence, reports)
```

Code lives in the config dir; **engagement state lives with the project**, so an
assessment is reviewable and resumable next to the code it concerns.
`NULLBYTE_SECURITY_DIR` overrides that location.

---

## Lab

`node tools/lab/vulnerable-server.mjs` starts a deliberately vulnerable target
on loopback only — 8080 (reflected XSS, served `/.env`, missing headers), 8081
(HTTP Basic admin/admin, `/debug` env dump), 8443 (self-signed, no HSTS). Never
bind it to a public interface.

---

## Known limitations

- Connect scans only (no raw SYN/OS detection) — use the nmap adapter for that.
- `webfetch` redirects are validated by the tool, not the guard; `sec_recon
  check=http` validates every hop itself.
- Evidence is redacted before storage, so a stored artifact is not byte-exact
  when it contained secrets.
- CVSS is base score only (no temporal/environmental).

## License

MIT — see [LICENSE](LICENSE).
