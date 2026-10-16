# HackerAI gap analysis

Source-level comparison of `hackerai-tech/hackerai` against this repository's
security layer. Read-only audit; HackerAI was never modified.

- **Reference clone:** `/tmp/opencode/audit/hackerai` (Apache-2.0)
- **Vendored skills:** `third_party/strix-skills/` — Apache-2.0,
  Copyright 2025 OmniSecure Inc., from `usestrix/strix@d8c00a8f4ebadec265582fb777081067a35f79d3`
- **Our baseline:** `main` @ `b955740`, 75/75 tests

## 1. What each thing is

HackerAI is a hosted SaaS: Next.js + Convex + Trigger.dev + E2B sandboxes, a
web product with a database, background jobs and per-user accounts. This
repository is a **plugin** that runs inside an existing agent runtime and adds
security capability to it. They are not the same class of software, so most of
HackerAI is not a gap — it is a different deployment model we deliberately do
not have (no cloud infra, no competing reasoning engine).

What *is* transferable is the **methodology and the guardrails** — the parts
that decide what an agent is allowed to claim and how it earns that claim.
Those were audited line by line.

## 2. Gap matrix

Verdicts: **Adopted** (implemented here), **Adapted** (same intent, local
implementation), **N/A** (deployment-model difference), **Rejected** (would
weaken us or violate a constraint).

| # | Capability | HackerAI evidence | Our state before | Verdict | Action taken |
|---|---|---|---|---|---|
| 1 | Two-tier skill registry (cheap catalog, budgeted content) | `lib/ai/subagents/skills/index.ts` | flat list of 21 fragments, no ids, no budget | **Adopted** | `methodology.ts`: category-qualified ids, `searchCatalog`, `resolveFragments`, `MAX_SELECTED_FRAGMENTS = 5`, `MAX_SELECTED_BYTES = 96*1024` |
| 2 | Ambiguity / unknown id is an error, not silence | `skills/index.ts` (`error: Choose at most …`, near-miss list) | returned empty silently | **Adopted** | `resolveFragments` returns near-miss candidates |
| 3 | Prompt-boundary escaping on loaded content | `lib/ai/subagents/skills/knowledge.ts` → `escapeReservedPromptBoundaries()` | none | **Adopted** | `escapeReservedBoundaries()` wraps output in `<nullbyte_methodology>` |
| 4 | Non-grant framing ("does not grant tools, permissions, authorization, or additional scope") | `skills/knowledge.ts`; `subagent-skill-tools.ts:150` | none | **Adopted** | `NON_GRANT_NOTICE` in every rendered fragment |
| 5 | Closure states: confirmed / ruled_out / open_proof_gap | `third_party/strix-skills/skills/analysis/counterevidence.md` | `verified`→`confirmed`, model-asserted | **Adopted** | `precision.ts`: `ClosureState`, `validateClosure()` |
| 6 | `ruled_out` must name a control *and* a location | `counterevidence.md` | none | **Adopted** | `validateClosure()` refuses `ruled_out` without `ruled_out_by` |
| 7 | Status is server-owned, never model-settable | `lib/findings/lifecycle.ts` (`active`\|`closed` + closure reason only) | **model set `status` directly** | **Adopted** | `findings.ts`: `PROTECTED_FIELDS`, `deriveStatus`; `status`/`closure` not writable |
| 8 | Confidence ≠ high forces a rationale | `lib/findings/quality.ts` | none | **Adopted** | `precision.ts` precision notes; downgrade reported |
| 9 | Evidence references are verified, four-state | `lib/ai/subagents/evidence-references.ts` | none | **Adopted** | `evidence-refs.ts`: `exists`/`missing`/`forbidden`/`unavailable` |
| 10 | Only ENOENT/ENOTDIR means "missing" | `evidence-references.ts` | — | **Adopted** | permission/IO error never reported as missing |
| 11 | Rich finding fields (counterevidence, severity-change conditions, assumptions, fix effort) | `lib/findings/validation.ts` | none | **Adopted** | added to `FindingInput`/`Finding` |
| 12 | Update requires a reason; only report fields merge | `validation.ts` (`reason` mandatory; lifecycle/provenance server-owned) | free-form patch | **Adopted** | `updateFinding(..., reason)`, `PROTECTED_FIELDS` |
| 13 | Optimistic concurrency on updates | `validation.ts` (`expected_updated_at`) | none | **Adapted** | `expectedRevision` (we have no clock authority) |
| 14 | Per-class false-positive suppressors | `lib/ai/subagents/skills/safety-overrides.ts` | none | **Adopted** | `PRECISION_NOTES` (12 entries) |
| 15 | Semantic dedupe of findings | model-based (LLM call) | fingerprint only | **Adapted** | deterministic token-Jaccard, 0.72 dup / 0.45 similar — no model call |
| 16 | Payload size ceiling | `FINDING_PAYLOAD_MAX_BYTES = 128 * 1024` | none | **Adopted** | `MAX_EVIDENCE_REFS = 40`, `MAX_EVIDENCE_REF_LENGTH = 500` |
| 17 | Canonical ordering for prompt-cache stability | `skills/index.ts` canonical sort | — | **Adopted** | stable fragment ordering |
| 18 | Convex DB / accounts / multi-tenant isolation | `convex/` | N/A | **N/A** | deployment model |
| 19 | Trigger.dev background jobs | `trigger/` | N/A | **N/A** | deployment model |
| 20 | E2B sandbox execution | `lib/` sandbox client | N/A | **N/A** | we run locally by design |
| 21 | LLM-based semantic dedupe | model call per finding | — | **Rejected** | adds a model call and non-determinism to a guardrail; Jaccard is auditable |
| 22 | Second reasoning engine / orchestrator | HackerAI's own agent loop | — | **Rejected** | we use OpenCode's runtime; a competing engine is out of scope |
| 23 | Hosted multi-user permission model | per-user accounts | — | **Rejected** | our operator *is* the authorizer |

## 3. Bugs this audit found in our own code

The audit's value was mostly in what it revealed about us.

### 3.1 Model self-certification (P0)

`findings.ts` did:

```ts
status: input.verification === "verified" ? "confirmed" : "open"
```

The model could mark its own work confirmed. HackerAI's `lifecycle.ts` shows
the correct shape: status is a server-owned derivation, and the model only ever
supplies *evidence* for it. Rewritten: status is derived from closure, and
`confirmed` requires a reproduction or a resolvable evidence reference.
Anything else is downgraded to `open_proof_gap` and the downgrade is reported.

### 3.2 Port-level scope bypass (P0)

`sec_ports` and `sec_scan` authorized the **host** and then probed their own
port list. `authorize()` only inspects `target.port`, which is `undefined` for a
multi-port scan — so an engagement that authorized only `127.0.0.1:8080` still
scanned `8081`.

Reproduced live against the loopback lab with `include: [{host: "127.0.0.1",
ports: [8080]}]`: `sec_ports target=127.0.0.1 ports=8081` scanned and returned a
banner. Fixed by `authorizePorts()` + `enforcePorts()`; re-tested:

```
sec_ports 127.0.0.1 ports=8080  → scanned
sec_ports 127.0.0.1 ports=8081  → [sec] 1 of 1 port(s) are outside scope (8081)…
sec_ports 127.0.0.1 ports=8080,8081,22 → refuses; only 8080 probed
```

Denials are written to `audit.jsonl` with code `scope.port`. The nmap adapter
now pins itself to the authorized port set when the entry restricts ports,
rather than falling back to nmap's implicit default.

## 4. Licensing

HackerAI and the vendored Strix skills are Apache-2.0. No HackerAI code was
copied into this repository. The Strix `counterevidence.md` three-state model
informed the *design* of `precision.ts`; our implementation is independent and
carries its own tests. If any Strix-derived text is ever copied verbatim,
`third_party/` attribution must accompany it.
