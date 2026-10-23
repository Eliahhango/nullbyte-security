# NullByte skill packs

Original engineering guidance for NullByte, covering the programming work the
runtime handles alongside security assessments. These files are generated from
`security-lib/coding-skills.ts`; that module is the source of truth and is also
loaded by `sec_methodology`.

| Skill | Use it for |
| --- | --- |
| `feature-delivery` | Turning a request into a tested, end-to-end change |
| `debugging` | Reproducing, reducing and fixing the root cause |
| `test-strategy` | Choosing test layers and handling legacy or flaky suites |
| `refactoring` | Behavior-preserving structural change |
| `performance` | Measuring, profiling and proving an improvement |
| `dependency-upgrade` | Migrating versions without breaking the runtime |
| `code-review` | Reviewing a diff for correctness and regressions |
| `api-contract` | Designing stable, authorized API boundaries |

Regenerate the packages after editing the TypeScript source:

```sh
node --experimental-strip-types tools/export-skills.ts
```

The content here was written for NullByte. No third-party skill text is bundled.
