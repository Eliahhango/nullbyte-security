<div align="center">
  <img src=".github/assets/banner.svg" alt="nullbyte-security" width="100%" />
</div>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=21&duration=2600&pause=800&color=4ADE80&center=true&vCenter=true&width=820&lines=Scope-locked+by+default;Recon+%E2%86%92+ports+%E2%86%92+scanners;Evidence+hashed+before+trust;Findings+that+survive+closure" alt="Scope-locked, evidence-backed, agentic" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/AUTHORIZED_USE_ONLY-ff2d55?style=for-the-badge&labelColor=05070a" alt="Authorized use only" />
  <img src="https://img.shields.io/badge/OFFENSIVE_SECURITY-22d3ee?style=for-the-badge&labelColor=05070a" alt="Offensive security" />
  <img src="https://img.shields.io/badge/AI_AGENT-4ade80?style=for-the-badge&labelColor=05070a" alt="AI agent" />
  <img src="https://img.shields.io/badge/SCOPE_LOCKED-4ade80?style=for-the-badge&labelColor=05070a" alt="Scope locked" />
  <img src="https://img.shields.io/badge/AUDIT_CHAINED-a78bfa?style=for-the-badge&labelColor=05070a" alt="Audit chained" />
</p>

<p align="center">
  <a href="https://github.com/Eliahhango/nullbyte-security/actions/workflows/test.yml"><img src="https://github.com/Eliahhango/nullbyte-security/actions/workflows/test.yml/badge.svg" alt="tests" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-22d3ee?style=flat-square" alt="license" /></a>
  <img src="https://img.shields.io/badge/node-%3E%3D22.6-4ade80?style=flat-square&logo=node.js&logoColor=white" alt="node" />
</p>

<p align="center">
  <img src="https://skillicons.dev/icons?i=ts,nodejs,bash,linux,git,github" alt="TypeScript, Node.js, Bash, Linux, Git" />
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="#arsenal">Arsenal</a> ·
  <a href="#scope-lock">Scope lock</a> ·
  <a href="#intel">Intel</a> ·
  <a href="#docs">Docs</a>
</p>

> **AUTHORIZED USE ONLY.** Point this at systems you own or have written
> permission to test. Everything else is a crime scene with extra steps.

## `MISSION`

Security capability layer for the [NullByte](https://github.com/Eliahhango) CLI.
An agentic offensive-security toolset that thinks in targets, but is held down
by scope checks, evidence hashes and an audit chain — not by vibes.

`sec_*` tools cover the full loop: scope, recon, ports, scanners, SAST, evidence,
findings, retesting, reporting, methodology and audit.

## `DEMO`

<div align="center">
  <img src=".github/assets/demo.svg" alt="Animated NullByte security session" width="100%" />
  <sub>Illustrative session. No live target is contacted.</sub>
</div>

## `WHY`

- **Scope is enforced by the tool layer**, not the prompt. Out-of-scope targets are refused before a packet moves.
- **Every decision is audited.** Allow, deny and ask decisions land in a hash-chained trail.
- **Evidence is checked before it is trusted.** Artifacts carry SHA-256 digests and are re-hashed on read.
- **Findings cannot be closed without proof.** The closure gate is code, not a suggestion.
- **Reports are deliverables**, not chat transcripts: markdown, JSON, HTML, PDF, SARIF and DefectDojo CSV.

## `QUICKSTART`

```bash
curl -fsSL https://github.com/Eliahhango/nullbyte-security/raw/main/install.sh | bash
```

One command. The installer clones or updates the repo in
`~/.local/share/nullbyte-security` (or reuses `~/nullbyte-security`), repairs
missing files and links, installs dependencies and runs the tests. Re-run the
same command to update or repair.

Inspect without touching anything:

```bash
curl -fsSL https://github.com/Eliahhango/nullbyte-security/raw/main/install.sh | bash -s -- --check
```

Requirements: Linux or macOS, `git`, Node.js >= 22.6, and the NullByte CLI.
Set `NULLBYTE_SECURITY_HOME=/path` to use a different checkout location.

## `KILL CHAIN`

```text
  scope ──▶ recon ──▶ scan ──▶ evidence ──▶ findings ──▶ report
    │                                                       ▲
    └────────────── hash-chained audit trail ───────────────┘
```

## `ARSENAL`

| Tool | Function |
|---|---|
| `sec_scope` | authorization mode; check a target; write a starter scope |
| `sec_recon` | DNS, HTTP, TLS, headers and fingerprinting; archives raw responses as evidence |
| `sec_ports` | bounded TCP connect scan and banner grab |
| `sec_scan` | nmap, nuclei, nikto, whatweb, sslscan and sqlmap adapters |
| `sec_sast` | local secrets, code smells and dependency checks |
| `sec_evidence` | store and verify raw artifacts by SHA-256 |
| `sec_finding` | findings, CVSS severity, dedupe and closure checks |
| `sec_retest` | re-run or record a finding's reproduction |
| `sec_report` | export markdown, JSON, HTML, PDF, SARIF or CSV |
| `sec_methodology` | search and load shared knowledge fragments |
| `sec_audit` | review allow/deny decisions and verify the audit chain |

`bash`, `read`, `write`, `edit`, `webfetch` and `todowrite` are reused as-is.

## `SCOPE LOCK`

With no scope file, every target is allowed and two guards stay active:
destructive commands and local credential files. For a real engagement, create
`.nullbyte/security/scope.json`:

```json
{
  "engagement": "acme-q4",
  "authorized_all": false,
  "intensity": "safe-active",
  "include": [
    { "host": "app.acme.test", "ports": [443, 8443] },
    { "host": "*.acme.test" }
  ],
  "exclude": ["billing.acme.test"]
}
```

`include` accepts hosts, wildcards, IPs, CIDRs and URLs. `exclude` wins. Scope is
operator-owned unless `allow_model_scope_edit` is enabled.

## `INTEL`

- Captures are verbatim by default, including secrets. Use
  `include_secrets=false` to redact at capture; this is irreversible.
- Reports are verbatim unless `redact=true`. Treat every export as
  credential-grade sensitive.
- Evidence is hash-checked on read; corrupted artifacts are refused.
- Encryption at rest is optional: set `NULLBYTE_STORE_KEY` or
  `~/.config/nullbyte/security.key`, or require it with
  `plugins.encrypt_store: true`.

<p align="center">
  <img src="https://github-readme-stats.vercel.app/api/pin/?username=Eliahhango&repo=nullbyte-security&theme=tokyonight&hide_border=true&bg_color=05070a&title_color=4ade80&icon_color=22d3ee&text_color=c9d1d9" alt="nullbyte-security repository card" />
</p>

## `DOCS`

- [docs/PENTEST.md](docs/PENTEST.md) — tools, enforcement, pacing, encryption and gotchas
- [docs/HACKERAI_GAP_ANALYSIS.md](docs/HACKERAI_GAP_ANALYSIS.md) — capability comparison
- [docs/IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md) — what is next
- [SECURITY.md](SECURITY.md) — vulnerability reporting

## `LICENSE`

MIT — see [LICENSE](LICENSE).

<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:05070a,100:0b1220&height=110&section=footer" alt="" />
</div>
