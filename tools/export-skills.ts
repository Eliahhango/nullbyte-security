/**
 * Render the original NullByte coding skill packs into standalone `skills/`
 * packages. The TypeScript records are the source of truth; the generated
 * Markdown is for hosts that discover `skills/<id>/SKILL.md` directly.
 *
 * Usage: node --experimental-strip-types tools/export-skills.ts
 */

import { mkdirSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { CODING_SKILLS, renderSkillFile } from "../security-lib/coding-skills.ts"

const root = dirname(dirname(fileURLToPath(import.meta.url)))
for (const skill of CODING_SKILLS) {
  const target = join(root, "skills", skill.id, "SKILL.md")
  mkdirSync(dirname(target), { recursive: true })
  writeFileSync(target, renderSkillFile(skill))
  console.log(`wrote ${target}`)
}
