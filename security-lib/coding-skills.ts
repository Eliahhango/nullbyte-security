/**
 * Original NullByte engineering skill packs.
 *
 * These are written for this tool, not imported from another skill collection.
 * They cover the daily programming work the runtime is used for as well as the
 * security work it was originally built around: delivering a feature, debugging,
 * testing, refactoring, performance, dependency upgrades, code review and API
 * contracts.
 *
 * `tools/export-skills.ts` renders the same records into `skills/<id>/SKILL.md`
 * so the packs are usable by other agents without duplicating the source.
 */

export interface CodingSkill {
  id: string
  title: string
  description: string
  tags: string[]
  body: string
}

export const CODING_SKILLS: CodingSkill[] = [
  {
    id: "feature-delivery",
    title: "Feature delivery: turn a request into working, verified code",
    description:
      "Implement a requested change in an existing codebase: clarify acceptance, find the real seams, build the smallest end-to-end slice, test it and report honestly.",
    tags: ["coding", "feature", "implementation", "planning", "acceptance", "verification"],
    body: [
      "Turn the request into explicit acceptance criteria and a bounded plan before editing. Name the user-visible behaviour, inputs, failure modes and non-goals; ask only when a missing answer changes the implementation.",
      "Read the surrounding code first: framework, module boundaries, error handling, test conventions, build commands and migration style. Follow them instead of introducing a parallel style.",
      "Implement the smallest vertical slice that exercises the real path end to end. Keep unrelated cleanup out of the change so the diff has one purpose.",
      "Handle the edges the happy path hides: empty input, duplicate submission, timeout, partial failure, permissions, cancellation and concurrency.",
      "Add or update tests at the cheapest layer that can catch the regression. Run the project's existing checks before claiming completion.",
      "Report files changed, behaviour verified, commands run and anything deliberately left out. Do not describe intent as if it were verified behaviour.",
    ].join("\n"),
  },
  {
    id: "debugging",
    title: "Debugging: reproduce, reduce and fix the root cause",
    description:
      "Diagnose a defect or unexpected behaviour by reproducing it, reducing the case, tracing the data and proving the fix with a regression test.",
    tags: ["coding", "debugging", "bug", "reproduction", "bisect", "root-cause", "regression"],
    body: [
      "Reproduce before changing code. Record the exact command, input, environment and observed output; a bug you cannot reproduce is a hypothesis, not a fix target.",
      "Reduce the case: remove unrelated data, narrow the input and disable optional layers. A minimal reproduction is the fastest path to the cause.",
      "Follow the data. Inspect the value at the boundary before and after each transform; do not assume the failure is where the stack trace ends.",
      "Use version control as a tool: bisect commits, diff working trees, or temporarily instrument one path. Change one variable per experiment.",
      "Fix the cause, not the symptom. If the fault is shared, patch the shared control point and check every caller.",
      "Add a regression test that fails on the old code. Re-run the original reproduction and the affected test suite.",
      "If the bug is environmental, state what differs and how to verify it. Do not close it as 'works on my machine'.",
    ].join("\n"),
  },
  {
    id: "test-strategy",
    title: "Test strategy: prove behaviour at the cheapest useful layer",
    description:
      "Choose the right tests for a change, write diagnostic failures, handle legacy code and flaky suites, and report coverage gaps honestly.",
    tags: ["coding", "testing", "tdd", "unit", "integration", "e2e", "regression", "flaky"],
    body: [
      "Test observable behaviour and contracts, not private structure. A test that breaks on every refactor without catching a behaviour change is a maintenance tax.",
      "Choose the cheapest layer that gives confidence: a pure unit test for logic, an integration test for a boundary, end-to-end only for a small number of critical journeys.",
      "For a bug, write the failing test first. For legacy code, add characterization tests around the current behaviour before changing it.",
      "Cover the edges that matter: empty, invalid, unauthorized, duplicate, timeout, partial failure and retry. One test per behaviour, not one per line.",
      "Make failures diagnostic: assert the important value and include the input in the failure. Avoid sleeps, shared mutable state and dependence on execution order.",
      "Treat a flaky test as a defect. Quarantine, reproduce and fix the source; do not retry until green.",
      "Report coverage gaps honestly. A high percentage does not prove the risky paths were tested.",
    ].join("\n"),
  },
  {
    id: "refactoring",
    title: "Refactoring: change structure without changing behaviour",
    description:
      "Improve an existing codebase safely by establishing a behaviour baseline, finding seams and moving in small reviewable steps.",
    tags: ["coding", "refactor", "legacy", "maintainability", "seams", "incremental"],
    body: [
      "Refactoring changes structure without changing behaviour. State the behaviour that must stay fixed and establish a test or characterization baseline first.",
      "Work in small, reviewable steps. Separate moves from behaviour changes so a regression has one obvious cause.",
      "Find seams: inject a dependency, extract a pure function, or isolate I/O behind an interface. Do not rewrite the world to test one branch.",
      "Keep the public interface stable unless the task explicitly changes it. Update every caller in the same change.",
      "Delete dead code only when you can prove it is unreachable; check reflection, configuration and external consumers first.",
      "Run the tests after each step. If behaviour changes, stop and decide whether that change belongs in this task.",
      "Report the structural change, the preserved behaviour and the tests that prove it.",
    ].join("\n"),
  },
  {
    id: "performance",
    title: "Performance: measure, profile, optimise, re-measure",
    description:
      "Improve latency, throughput, memory or bundle size with a defined metric, a repeatable baseline and evidence that the change helped.",
    tags: ["coding", "performance", "profiling", "latency", "memory", "benchmark"],
    body: [
      "Define the metric before optimising: latency percentile, throughput, memory, query count or bundle size. 'Feels slow' is not a target.",
      "Measure a representative baseline with a repeatable workload. Record environment, dataset size and variance; one fast run is noise.",
      "Profile before guessing. Find the dominant cost and optimise that, not the line that looks expensive.",
      "Change one thing at a time. Keep correctness tests green and re-measure with the same workload.",
      "Prefer algorithmic and I/O improvements over micro-tuning. Cache only with a clear invalidation rule and a measured hit rate.",
      "Check the tradeoffs: memory for speed, complexity for latency, staleness for freshness. State which one you accepted.",
      "Verify the improvement is outside normal variance and that no other metric regressed.",
    ].join("\n"),
  },
  {
    id: "dependency-upgrade",
    title: "Dependency upgrade: move versions without breaking the runtime",
    description:
      "Plan and execute a dependency or framework upgrade with migration notes, isolated changes, full verification and a rollback path.",
    tags: ["coding", "dependencies", "upgrade", "breaking-changes", "lockfile", "compatibility"],
    body: [
      "Read the release notes and migration guide before changing the lockfile. Identify breaking changes, dropped runtime support and security fixes.",
      "Upgrade one dependency family at a time. Keep application changes and lockfile churn in separate commits when possible.",
      "Use the project's package manager and lockfile exactly; do not mix managers or hand-edit generated files.",
      "Run the full test and build matrix, including type checks and the oldest supported runtime. Fix deprecations rather than suppressing them.",
      "Check transitive changes and peer constraints. A green install is not proof that the runtime path still works.",
      "For a security upgrade, identify the vulnerable range, the fixed version and whether the vulnerable path is actually reachable.",
      "Record the version delta, migration steps, test evidence and rollback plan.",
    ].join("\n"),
  },
  {
    id: "code-review",
    title: "Code review: find the defect before the style debate",
    description:
      "Review a diff for correctness, edge cases, regressions and maintainability, with blocking findings separated from suggestions.",
    tags: ["coding", "review", "diff", "correctness", "maintainability", "regression"],
    body: [
      "Read the change's intent first, then the diff. A correct patch in the wrong place is still a defect.",
      "Check correctness before style: boundary conditions, error paths, null or empty input, authorization, concurrency and data consistency.",
      "Trace the changed data through its callers and callees. Look for behaviour that changed outside the edited lines.",
      "Demand tests for new behaviour and regressions. A test that only asserts the implementation exists is not enough.",
      "Review naming, structure and duplication only where they affect comprehension or future change; do not relitigate preferences.",
      "Flag security-sensitive changes explicitly and hand them to the secure review playbook rather than improvising a security audit.",
      "Separate blocking defects from suggestions. State the evidence and the smallest acceptable fix.",
    ].join("\n"),
  },
  {
    id: "api-contract",
    title: "API contract: design the stable boundary first",
    description:
      "Design or change an HTTP or RPC API with explicit resources, errors, idempotency, authorization, versioning and contract tests.",
    tags: ["coding", "api", "contract", "rest", "graphql", "versioning", "compatibility"],
    body: [
      "Model resources and operations before writing handlers. Name the stable identifiers, ownership rules and lifecycle transitions.",
      "Define success and error shapes once. Use consistent status codes and a machine-readable error code; do not leak stack traces.",
      "Make retries safe: idempotency keys for creates, predictable pagination, and no side effects on GET.",
      "Specify authentication and object-level authorization for every operation, including list and export paths.",
      "Version compatibility deliberately. Additive changes first; deprecate with a window and a migration path.",
      "Write contract tests against the schema and the authorization matrix, not just the happy-path response.",
      "Document limits, timeouts and rate-limit behaviour where clients can observe them.",
    ].join("\n"),
  },
]

/** Render a standalone skill package for another agent host. */
export function renderSkillFile(skill: CodingSkill): string {
  return [
    "---",
    `name: ${skill.id}`,
    `description: ${skill.description}`,
    "---",
    "",
    `# ${skill.title}`,
    "",
    skill.body
      .split("\n")
      .filter(Boolean)
      .map((line) => `- ${line}`)
      .join("\n"),
    "",
    "---",
    "",
    "_NullByte skill pack. Original guidance for this tool; no third-party skill text is bundled._",
    "",
  ].join("\n")
}
