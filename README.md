# nullbyte-security

Security capability layer for the [NullByte](https://github.com/Eliahhango) CLI.
Adds an agentic pentesting toolset — scope enforcement, recon, port scanning,
scanner orchestration, secret scanning, evidence handling, CVSS-scored findings
and reporting — as a **plugin**, without touching the host CLI.

- 10 `sec_*` tools available to every agent
- Authorized by default, with opt-in perimeter lockdown for real engagements
- Findings, evidence, audit trail and reports persisted per project
- 25-fragment methodology knowledge base
- Standards-shaped reports: executive summary, timeline, credentials, remediation
  roadmap, risk-rating and revision-history appendices
- 290 unit tests

> Authorized testing only. Point it at systems you own or have written permission
> to test.

## Install

```bash
git clone https://github.com/Eliahhango/nullbyte-security.git ~/nullbyte-security
cd ~/nullbyte-security && ./install.sh
```

`install.sh` starts by inspecting the checkout and the installed files. It
checks required source files, the config tree, both symlinks, dependencies and
the CLI, then automatically repairs anything missing or broken before installing
dependencies and running the test suite. Because the code is symlinked,
`git pull` updates the live install.

It is also the repair command. Re-run it after a failed or partial install: it
recreates missing directories, replaces stale or broken symlinks, backs up
conflicting files with a timestamp, and leaves existing configuration and
engagement data untouched. Use `./install.sh --no-test` or
`./install.sh --no-deps` to skip those steps, or `./install.sh --check` for an
inspection-only pass that changes nothing and exits non-zero if repairs are
needed.

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

### Target directories

Contacting a target creates a directory for it, named after the host, in the
directory you ran nullbyte from:

```
~/Desktop/
  app.acme.test/
    reports/    report.md | .json | .html | .pdf
    logs/       nmap-2026-10-17T02-00-05-311Z.log
  api.acme.test/
    reports/
    logs/
```

- Created the moment a target is first **authorized**. A denied target gets
  nothing — the directory is a consequence of authorization, not of the attempt.
- One directory per host: `app.acme.test:443`, `app.acme.test:8080` and
  `https://app.acme.test/x` all resolve to `app.acme.test/`.
- Revisiting a target reuses its directory, so a second target never overwrites
  the first one's output.
- `sec_report` files there automatically. A report spanning several hosts cannot
  live in any single one, so it goes to `reports/` in the project root instead.
- `sec_scan logs=true` keeps the scanner's raw stdout/stderr. Logs are stored
  verbatim by default; pass `include_secrets=false` to redact at capture.
- The directory ignores itself in git — it contains raw tool output, which
  routinely carries credentials.
- The findings store, evidence and audit trail stay engagement-wide under
  `.nullbyte/security/`. Only deliverables are split per target, because
  sharding the store would break the closure gate and cross-session continuity.
- Turn it off with `"plugins": { "target_dirs": false }` in
  `~/.config/nullbyte/security.json`.

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
| `sec_recon` | `dns\|http\|tls\|headers\|fingerprint` — real network calls; the raw HTTP response is archived as an evidence artifact and its id returned (`archive=false` opts out) |
| `sec_ports` | bounded TCP connect scan + banner grab |
| `sec_scan` | adapters: nmap, nuclei, nikto, whatweb, sslscan, sqlmap; `logs=true` keeps the raw stdout/stderr in the target's `logs/` |
| `sec_sast` | local: `secrets`, `smells`, `deps` — secrets reported by location, never by value |
| `sec_evidence` | store/retrieve raw artifacts, SHA-256 indexed and re-checked on read (`action=verify` audits the whole store); stored verbatim by default, `include_secrets=false` redacts at capture |
| `sec_finding` | findings; status derived, never asserted; closure gate; CVSS 3.1 severity; dedupe; evidence-reference checks |
| `sec_retest` | re-check a finding's reproduction: `action=run` re-executes a command under the same scope/destructive guards and captures the output, `action=record` logs a manual re-check; append-only history, and a retest that contradicts the closure reopens the finding |
| `sec_report` | preview or export as markdown, JSON, HTML or PDF (plus opt-in SARIF/CSV for tooling) into the target's own `reports/`; `coverage=session` (default) stops one target's findings mixing into another's; `evidence=full` embeds artifact content; verbatim by default, `redact=true` scrubs |
| `sec_methodology` | search/load shared knowledge fragments |
| `sec_audit` | review every allow/deny/ask decision the tool layer made; `action=verify` recomputes the trail's hash chain to prove it was not edited |

`bash`, `read`, `write`, `edit`, `webfetch` and `todowrite` are reused as-is.

## Credentials and disclosure

The default posture is **full disclosure**. A leaked credential is often the
finding itself, so it is recorded verbatim at capture and reproduced in full in a
dedicated **Credentials** section of the report — one entry per value, with its
type, host, the line it came from and where it was observed. Nothing is masked.

- **Capture is verbatim.** `sec_evidence` and `sec_scan` store secret-like
  material as-is unless you pass `include_secrets=false`.
- **Reports are verbatim.** `sec_report` emits every text format unmasked unless
  you pass `redact=true`.
- **`redact=true`** replaces each collected value with `[REDACTED:credential]`,
  and the shape rules scrub anything else that looks like a secret.
- **Evidence is verified before it is trusted.** Every artifact carries a
  SHA-256 of exactly the bytes written. `action=get` and `evidence=full`
  re-hash before returning, and refuse an artifact that no longer matches, so an
  edited or corrupted file cannot be laundered into a deliverable as evidence.
  `action=verify` audits the whole store.

This is a deliberate departure from the usual guidance. PTES Post-Exploitation
says passwords "will not be included in the final report"; OWASP APTS
(`APTS-MR-019`, `APTS-TP-013`) says plaintext credentials **MUST NOT** appear in
reports. This build follows the Metasploit Credentials-Report model instead —
values present in full — and treats the deliverable as credential-grade
sensitive: every file is written `0600`, an unredacted report carries an
`UNREDACTED` banner in md/html and `unredacted: true` in json, and the export is
audited under `report.export.unredacted`. Rotate every disclosed value once the
engagement closes.

Redaction at the capture boundary is **irreversible**. A value stored with
`include_secrets=false` cannot be recovered by regenerating the report: the
record says `redacted: yes` and the secret is gone.

## Report presentation

Every export is stamped with the copyright mark
`© @EliTechWiz 2026 All Rights Reserved`.

- **Markdown and HTML** close with a footer carrying the copyright; the HTML
  `<head>` names `EliTechWiz` as author and `NullByte` as generator.
- **PDF** carries the copyright and `Page N of M` in the bottom margin of
  *every* page. That footer comes from the `@page` margin boxes in the report
  stylesheet, which both WeasyPrint and current Chrome render — so it survives
  whichever converter is installed. If no converter is installed the PDF is
  skipped with an install hint; the other three formats are still written.
- **Provenance is sanitised.** The `provenance` field names the agent and the
  tools only. Provider, model and harness identifiers are stripped at render
  time, in every format, so a deliverable cannot disclose the stack that
  produced it.

### Interop exports

Two formats are for other tools rather than a reader, and are requested
explicitly (`format=sarif`, `format=csv`, or `format=interop` for both) so a
normal export does not litter the engagement directory with them:

- **SARIF 2.1.0** for code-scanning and security dashboards. Critical and high
  map to `error`, medium to `warning`, low to `note`, and info to `none` — so an
  informational note cannot fail a build. A network finding gets a SARIF
  *logical* location naming the asset; a `file:line` evidence reference becomes a
  real physical location. Findings with the same CWE share one rule.
- **CSV** in DefectDojo's Generic Findings Import shape. `Active`, `Verified`,
  `FalsePositive` and `Remediated` are written as independent columns rather than
  derived from one another, because "fixed" and "not proven" are different
  things. Quoting follows RFC 4180, so a title with a comma, quote or newline
  round-trips.

Both are derived from the same findings as every other format, and both honour
`redact=true`.

## Scope enforcement

Authorization is enforced by the tool layer; it is not delegated to the agent's
judgement.

### Default posture

With no scope file present, the operator is treated as the authorizer and every
target is permitted at every intensity. Two guards remain active regardless,
because they protect the operator's own host rather than the target:

- **Destructive commands** — `rm -rf /`, `mkfs`, and `dd` to a raw device.
- **Local credential material** — `~/.ssh/id_*`, `~/.aws/credentials`,
  `auth.json` and browser cookie stores.

Both can be disabled, but they are configured in separate files on purpose:
`block_destructive` sits in the engagement scope, while
`plugins.protect_local_secrets` sits in the global policy file
(`~/.config/nullbyte/security.json`). Keeping the latter out of the project scope
means a project file cannot switch off the guard that protects the operator's own
host.

### Defining a perimeter

For an engagement with a defined boundary, author
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

`include` accepts a hostname, `*.domain` (subdomains only), `domain` (the domain
and its subdomains), an IP address, a CIDR range, or a URL. `exclude` takes
precedence over every `include` entry. Scope is authored by the operator: the
agent cannot widen it unless that is explicitly permitted, via
`allow_model_scope_edit` in the same file.

### Enforcement layers

Authorization is applied in four independent layers — permission rules, the tool
boundary, the tool bodies, and an advisory system prompt. Every `allow`, `deny`
and `ask` decision is appended to the project's audit trail and can be reviewed
with `sec_audit`. The trail is hash-chained: each record carries its position,
the hash of the record before it and its own hash, so editing, dropping or
reordering a line is detectable with `sec_audit action=verify` instead of
trusted. Records written before chaining was added are reported as unverifiable
rather than assumed good. The full breakdown is in
[docs/PENTEST.md](docs/PENTEST.md#4-enforcement).

## Encryption at rest

**Off by default.** With no key configured the store is plaintext, exactly as
before, and every existing engagement still reads.

The store holds scanner output, HTTP transcripts and — by deliberate policy —
live credentials in the clear. That is the right call inside the engagement
directory and the wrong thing to leave on a disk that gets imaged, stolen or
synced to a backup you do not control. Point the tools at a key and the engagement
state is sealed with AES-256-GCM:

```bash
export NULLBYTE_STORE_KEY='a long passphrase'      # or write it to
                                                    # ~/.config/nullbyte/security.key (chmod 600)
```

- **What gets sealed:** `findings.json`, every evidence artifact, the evidence
  index, and the audit trail — per line, so it stays appendable. The hash chain
  is computed over the *plaintext* records, so `sec_audit action=verify` still
  works.
- **Keys are derived with scrypt** (N=2¹⁵, r=8, p=1) using a per-value salt, so
  the same plaintext seals differently every time and two identical findings do
  not look identical on disk. Each value carries its own algorithm and KDF
  parameters in an envelope, so a reader can tell ciphertext from plaintext, and
  the parameters can be raised later without a migration.
- **Enabling it is non-destructive.** Reads accept both plaintext and an envelope,
  so a half-migrated store reads correctly: old records stay plaintext and new
  ones are sealed.
- **The key is never in the config file.** It comes from `NULLBYTE_STORE_KEY` or
  the key file. Set `plugins.encrypt_store: true` to *require* encryption — with
  no key present, the tools then refuse to write rather than silently storing
  plaintext, which is the one failure worth refusing to make.
- **The reported hash still means what it says.** Evidence digests cover the
  plaintext payload, so with encryption off that is exactly the bytes on disk,
  and with it on the digest survives a re-encrypt or a key rotation.

Honest scope: this protects data **at rest** — a lost laptop, a copied directory,
a backup. It does not protect against a process running as the same user, and it
cannot, because the key has to be readable for the tools to work. Lose the key
and the data is gone; there is no recovery path, by design.

## Lab

`node tools/lab/vulnerable-server.mjs` starts a deliberately vulnerable target on
loopback only — 8080 (reflected XSS, served `/.env`, missing headers), 8081
(HTTP Basic admin/admin, `/debug` env dump), 8443 (self-signed, no HSTS). Never
bind it to a public interface.

## Known limitations

- Connect scans only (no raw SYN/OS detection) — use the nmap adapter for that.
- Redirects on `webfetch` are validated by the tool, not the guard.
- Evidence is stored verbatim by default, so a captured artifact is byte-exact.
  Capturing with `include_secrets=false` redacts before storage and is
  irreversible.
- Redaction is best-effort pattern matching, not a guarantee. Reports are
  verbatim by default by design — treat every export as credential-grade
  sensitive. `redact=true` removes the shapes it knows; it cannot remove a secret
  it does not recognise, and it cannot undo capture-time redaction.
- CVSS is base score only (no temporal/environmental).
- Encryption at rest must be enabled deliberately (see
  [Encryption at rest](#encryption-at-rest)); it is off until a key is configured.
  It also does not protect against a process running as the same user — see that
  section for the honest scope.
- **A failed audit write refuses the action.** The trail is a control, not a
  log, so if it cannot be written the tool call stops with `AuditWriteError`
  rather than proceeding unlogged. On a read-only or full filesystem this stops
  security tools until the store is writable again — that is deliberate.
- The audit chain proves internal consistency, not authorship: it detects edits
  to an existing trail, but someone with write access to the store can rebuild a
  whole chain from scratch. Sealing the head hash outside the store (a signed
  copy, a commit, a ticket) is what defeats that.

## Docs

- [docs/PENTEST.md](docs/PENTEST.md) — full reference: tools, closure discipline, enforcement, gotchas
- [docs/HACKERAI_GAP_ANALYSIS.md](docs/HACKERAI_GAP_ANALYSIS.md) — capability comparison and non-adoptions
- [docs/IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md) — what is next

## License

MIT — see [LICENSE](LICENSE).
