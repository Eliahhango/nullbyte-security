# Implementation roadmap

Follows `docs/HACKERAI_GAP_ANALYSIS.md`. Constraint throughout: no cloud infra,
no competing reasoning engine, no mocks outside tests, existing public tool
interfaces preserved, the host CLI touched only where unavoidable.

## Shipped in this pass

| Area | Change | Files |
|---|---|---|
| Closure discipline | `confirmed` / `ruled_out` / `open_proof_gap`; downgrade on unproven claims | `precision.ts` (new) |
| Evidence verification | four-state reference check; only ENOENT/ENOTDIR = missing | `evidence-refs.ts` (new) |
| Finding lifecycle | status derived, not asserted; `reason`-gated updates; optimistic concurrency | `findings.ts` |
| Knowledge base | 25 fragments, category-qualified ids, budgeted load, boundary escaping, non-grant notice | `methodology.ts` |
| Tool surfaces | progressive-disclosure `sec_methodology`; closure-aware `sec_finding` | `tools/knowledge.ts`, `tools/findings.ts` |
| Reporting | closure summary, counterevidence, assumptions, fix effort, evidence states | `report.ts` |
| Scan authorization | `sec_recon` / `sec_ports` / `sec_scan` authorized by default; allow-list retained for shell, webfetch and retest | `scope.ts`, `tools/shared.ts`, `tools/recon.ts`, `tools/ports.ts`, `tools/scan.ts` |
| Chat-safe progress | live spinner auto-suppressed in chat/TUI harnesses, terminal remains opt-in | `progress.ts` |
| Coverage ledger | surface × risk outcomes, duplicate rejection, revision history, report section, JSON sidecar and SARIF summary | `coverage.ts`, `tools/coverage.ts` |
| Threat model | shared per-target model, save/amend with append-only amendments, report embedding | `threat-model.ts`, `tools/threat-model.ts` |
| Agent resilience | transient provider/TLS/socket retry in a fresh child session, shared deadline, configurable attempts | `agents.ts`, `tools/agents.ts` |
| Reporting | coverage and threat-model sections; `*.coverage.json`; SARIF coverage notification | `report.ts`, `interop.ts` |
| Tests | 331 → 348 | `__tests__/*` |

## Strix adoption roadmap

`usestrix/strix` is a Python/LiteLLM/Docker harness, so the runtime is not
portable. The useful part is its control-plane design. Adopt the concepts, not
the deployment model.

| Priority | Capability | Gap in NullByte | Status |
|---|---|---|---|
| 1 | Coverage ledger | Reports could not distinguish "tested and sound" from "never tested" | **Shipped** |
| 2 | Shared threat model | No per-target actors/assets/trust-boundary record shared across agents | **Shipped** |
| 3 | Transport retry | A dropped provider socket failed a whole child; broken IPv6 made this frequent | **Shipped** |
| 4 | Persistent agent graph | `sec_agents` runs one batch and returns; no create/send/wait/stop/view across turns | Next |
| 5 | Scan modes and budgets | No quick/deep mode, token/step budget or cost guardrail | Next |
| 6 | Session resume | A long assessment cannot be paused and resumed from the same plan state | Next |
| 7 | API-spec testing | No OpenAPI/GraphQL-driven endpoint and authz matrix | Next |
| 8 | Web intelligence | No search/fetch research loop with provenance | Later |
| 9 | Proxy/browser/MCP | No browser or proxy integration; would add large dependencies | Later |

The next batch should land items 4-6 together: a persisted plan/agent graph,
bounded execution budgets, and resume state. API-spec testing can follow
independently.

Not planned: a separate engagement notes/todos store. Keep that state in the
existing transcript/todowrite rather than adding another persisted surface.

## Next

Ordered by risk removed per unit of work. Each item names the file it lands in
and the test that proves it.

### 1. Carry closure discipline into `sec_report` (small)

`report.ts` renders closure but does not yet refuse a report that contains
`open_proof_gap` findings presented at `critical`. Add a preflight that warns
when a `critical`/`high` finding is not `confirmed`.

- **File:** `report.ts`
- **Test:** report containing an unconfirmed critical emits the warning.

### 2. Attach evidence references to the finding that cites them (medium)

`sec_finding` accepts `evidence_refs` and classifies them, but does not check
that an `E-…` id exists in the evidence store. Wire `sec_evidence` ids through
the same classifier so a cited-but-absent evidence id is reported as `missing`.

- **Files:** `tools/findings.ts`, `evidence-refs.ts`
- **Test:** a finding citing an unknown `E-…` id is flagged.

### 3. Per-class false-positive suppressors surfaced at verify time (medium)

`PRECISION_NOTES` exists but is only rendered into methodology text. When a
finding matches a class with a known false-positive shape (PHP8 phar, OAuth
state/PKCE, kubelet 401/403, Django `SECRET_KEY`, NoSQL
`security.javascriptEnabled`), attach the note to the finding itself.

- **Files:** `precision.ts`, `tools/findings.ts`
- **Test:** a phar-flagged finding carries the PHP8 suppressant note.

### 4. Scope `intensity` per-tool defaults audit (medium)

Confirm every network tool requires an intensity at least as strong as its
effect: `sec_recon` passive, `sec_ports` safe-active, nmap connect
safe-active, nmap intrusive / sqlmap intrusive. Add a test that walks the tool
registry and asserts the declared intensity.

- **Files:** `tools/*`, `__tests__/`
- **Test:** registry intensity table matches the declared minimums.

### 5. Evidence store retention and size bounds (small)

`MAX_EVIDENCE_REFS` bounds citations but not the store itself. Add a per-project
cap and a documented pruning path so a long engagement cannot fill the disk.

- **Files:** `evidence.ts`
- **Test:** exceeding the cap is reported, never silently dropped.

### 6. Cross-check `sec_audit` against the finding store (medium)

`audit.jsonl` records every allow/deny/ask. Add a `sec_audit action=reconcile`
that reports findings whose creation has no corresponding allow record — a
signal of a bypassed tool layer.

- **Files:** `audit.ts`, `tools/audit.ts`
- **Test:** a hand-written finding with no audit record is reported.

## Explicitly not doing

- Model-based semantic dedupe — non-deterministic, and a guardrail should be
  auditable. Jaccard stays.
- Hosted multi-tenant isolation, Convex-style persistence, sandboxed execution —
  different deployment model; local execution is the design.
- A second agent loop — NullByte's runtime is the only reasoning engine.
