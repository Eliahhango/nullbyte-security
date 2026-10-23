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
| Knowledge base | 39 fragments, playbooks and coding skills, category-qualified ids, budgeted load, boundary escaping, non-grant notice | `methodology.ts` |
| Tool surfaces | progressive-disclosure `sec_methodology`; closure-aware `sec_finding` | `tools/knowledge.ts`, `tools/findings.ts` |
| Reporting | closure summary, counterevidence, assumptions, fix effort, evidence states | `report.ts` |
| Scan authorization | `sec_recon` / `sec_ports` / `sec_scan` authorized by default; allow-list retained for shell, webfetch and retest | `scope.ts`, `tools/shared.ts`, `tools/recon.ts`, `tools/ports.ts`, `tools/scan.ts` |
| Chat-safe progress | live spinner auto-suppressed in chat/TUI harnesses, terminal remains opt-in | `progress.ts` |
| Own skill playbooks | CTF, agentic orchestration, secure code review, remediation, CI gate and application assessment | `methodology.ts`, `tools/knowledge.ts` |
| Own coding skills | Feature delivery, debugging, test strategy, refactoring, performance, dependency upgrade, code review and API contract; exported as standalone packages | `coding-skills.ts`, `tools/export-skills.ts`, `skills/` |
| Output branding | runtime identifiers stay functional; tool titles, output and metadata present as NullByte | `brand.ts`, `plugin/nullbyte-security.ts` |
| Report preflight | warns when a high/critical finding is still `open_proof_gap`, without blocking the export | `report.ts`, `tools/report.ts` |
| Precision attachments | class-specific false-positive notes are derived at write time and rendered with the finding | `precision.ts`, `findings.ts`, `report.ts` |
| Evidence retention | per-project artifact/byte bounds; `sec_evidence action=stats`; refused captures explain the pruning path | `evidence.ts`, `tools/evidence.ts` |
| Audit reconciliation | `sec_audit action=reconcile` cross-checks finding creation against allow records | `audit.ts`, `tools/findings.ts`, `tools/knowledge.ts` |
| Intensity floors | network tools and scanner adapters declare a tested minimum intensity | `tools/recon.ts`, `tools/ports.ts`, `tools/scan.ts`, `tools/index.ts` |
| Installer safety | deterministic smoke test runs before links are touched; full suite is opt-in; failed validation preserves the previous installation | `install.sh`, `tools/install-smoke.ts` |
| Coverage ledger | surface × risk outcomes, duplicate rejection, revision history, report section, JSON sidecar and SARIF summary | `coverage.ts`, `tools/coverage.ts` |
| Threat model | shared per-target model, save/amend with append-only amendments, report embedding | `threat-model.ts`, `tools/threat-model.ts` |
| Agent resilience | transient provider/TLS/socket retry in a fresh child session, shared deadline, configurable attempts | `agents.ts`, `tools/agents.ts` |
| Reporting | coverage and threat-model sections; `*.coverage.json`; SARIF coverage notification | `report.ts`, `interop.ts` |
| Tests | 331 → 365 | `__tests__/*` |

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

The verification batch is complete. The next work is the Strix batch described
above: a persisted agent graph (item 4), scan modes and budgets (item 5), and
session resume (item 6). Those land together because the graph and resume state
share the same persisted plan.

## Explicitly not doing

- Model-based semantic dedupe — non-deterministic, and a guardrail should be
  auditable. Jaccard stays.
- Hosted multi-tenant isolation, Convex-style persistence, sandboxed execution —
  different deployment model; local execution is the design.
- A second agent loop — NullByte's runtime is the only reasoning engine.
