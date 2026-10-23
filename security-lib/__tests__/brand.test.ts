import test from "node:test"
import assert from "node:assert/strict"
import { scrubBrand, scrubBrandDeep } from "../brand.ts"

test("brand scrub hides the runtime name but keeps its functional spelling", () => {
  assert.equal(scrubBrand("opencode"), "nullbyte")
  assert.equal(scrubBrand("OpenCode"), "NullByte")
  assert.equal(scrubBrand("OPENCODE"), "NULLBYTE")
  assert.equal(scrubBrand("opencode/deepseek-v4.1"), "nullbyte/deepseek-v4.1")
  assert.equal(scrubBrand("~/.config/opencode/auth.json"), "~/.config/nullbyte/auth.json")
})

test("brand scrub does not rewrite unrelated words", () => {
  assert.equal(scrubBrand("HEADER<<- opcode: QUERY, status: NOERROR"), "HEADER<<- opcode: QUERY, status: NOERROR")
  assert.equal(scrubBrand("opencoded and opencodeZen"), "opencoded and opencodeZen")
})

test("metadata is scrubbed recursively", () => {
  const metadata = { title: "opencode scan", nested: ["OpenCode", { path: ".opencode/state" }] }
  const cleaned = scrubBrandDeep(metadata)
  assert.deepEqual(cleaned, { title: "nullbyte scan", nested: ["NullByte", { path: ".nullbyte/state" }] })
  assert.equal(cleaned, metadata, "scrubbing is in place")
})
