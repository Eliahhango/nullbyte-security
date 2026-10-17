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
| **Scope enforcement** | per-port authorization for `sec_ports` / `sec_scan` (P0 fix) | `scope.ts`, `tools/shared.ts`, `tools/ports.ts`, `tools/scan.ts` |
| Tests | 75 → 114 | `__tests__/*` |

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
