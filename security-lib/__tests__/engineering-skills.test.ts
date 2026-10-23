/**
 * Original NullByte engineering skill packs.
 *
 * The TypeScript records power `sec_methodology`; the Markdown packages are for
 * hosts that discover `skills/<id>/SKILL.md`. Both must stay in sync, and both
 * must remain original NullByte content rather than bundled third-party text.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { CODING_SKILLS, renderSkillFile } from "../coding-skills.ts"
import { FRAGMENTS, categoryOf, loadFragment, searchFragments } from "../methodology.ts"

const skillsRoot = fileURLToPath(new URL("../../skills/", import.meta.url))
const expected = [
  "feature-delivery",
  "debugging",
  "test-strategy",
  "refactoring",
  "performance",
  "dependency-upgrade",
  "code-review",
  "api-contract",
]

test("the coding pack has distinct, substantive skills in one category", () => {
  assert.deepEqual(
    CODING_SKILLS.map((s) => s.id).sort(),
    [...expected].sort(),
  )
  const seen = new Set<string>()
  for (const skill of CODING_SKILLS) {
    assert.ok(!seen.has(skill.id), `duplicate coding skill: ${skill.id}`)
    seen.add(skill.id)
    assert.ok(skill.description.length >= 40, `${skill.id}: description is too thin`)
    assert.ok(skill.tags.includes("coding"), `${skill.id}: must carry the coding tag`)
    assert.ok(skill.body.split("\n").length >= 5, `${skill.id}: body needs actionable steps`)
    assert.equal(loadFragment(skill.id)?.body, skill.body, `${skill.id}: methodology lost the body`)
    assert.equal(categoryOf(skill.id), "coding", `${skill.id}: wrong category`)
  }
  assert.equal(FRAGMENTS.filter((f) => categoryOf(f.id) === "coding").length, expected.length)
})

test("daily engineering queries route to the matching coding skill", () => {
  assert.equal(searchFragments("feature delivery", 3)[0]?.id, "feature-delivery")
  assert.equal(searchFragments("debugging", 3)[0]?.id, "debugging")
  assert.equal(searchFragments("test strategy", 3)[0]?.id, "test-strategy")
  assert.equal(searchFragments("refactor legacy", 3)[0]?.id, "refactoring")
  assert.equal(searchFragments("performance profiling", 3)[0]?.id, "performance")
  assert.equal(searchFragments("dependency upgrade", 3)[0]?.id, "dependency-upgrade")
  assert.equal(searchFragments("review diff", 3)[0]?.id, "code-review")
  assert.equal(searchFragments("api contract", 3)[0]?.id, "api-contract")
})

test("standalone skill packages match the source and carry no borrowed text", () => {
  for (const skill of CODING_SKILLS) {
    const file = readFileSync(`${skillsRoot}${skill.id}/SKILL.md`, "utf8")
    assert.equal(file, renderSkillFile(skill), `${skill.id}: SKILL.md is stale; run tools/export-skills.ts`)
    assert.match(file, new RegExp(`^---\\nname: ${skill.id}\\n`), `${skill.id}: missing frontmatter`)
    assert.match(file, /_NullByte skill pack\./, `${skill.id}: missing NullByte provenance`)
    assert.doesNotMatch(file, /ComposioHQ|awesome-claude-skills/i, `${skill.id}: borrowed third-party text`)
  }
})
