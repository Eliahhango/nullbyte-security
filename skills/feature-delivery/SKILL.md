---
name: feature-delivery
description: Implement a requested change in an existing codebase: clarify acceptance, find the real seams, build the smallest end-to-end slice, test it and report honestly.
---

# Feature delivery: turn a request into working, verified code

- Turn the request into explicit acceptance criteria and a bounded plan before editing. Name the user-visible behaviour, inputs, failure modes and non-goals; ask only when a missing answer changes the implementation.
- Read the surrounding code first: framework, module boundaries, error handling, test conventions, build commands and migration style. Follow them instead of introducing a parallel style.
- Implement the smallest vertical slice that exercises the real path end to end. Keep unrelated cleanup out of the change so the diff has one purpose.
- Handle the edges the happy path hides: empty input, duplicate submission, timeout, partial failure, permissions, cancellation and concurrency.
- Add or update tests at the cheapest layer that can catch the regression. Run the project's existing checks before claiming completion.
- Report files changed, behaviour verified, commands run and anything deliberately left out. Do not describe intent as if it were verified behaviour.

---

_NullByte skill pack. Original guidance for this tool; no third-party skill text is bundled._
