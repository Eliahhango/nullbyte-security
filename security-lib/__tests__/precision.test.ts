/**
 * Precision discipline: class-specific false-positive suppression and the
 * finding closure gate.
 *
 * The behaviour under test is the thing that stops a model from certifying its
 * own work: a requested closure state is a claim, and it is only granted when
 * the evidence supports it.
 */

import test from "node:test"
import assert from "node:assert/strict"
import {
  CLOSURE_STATES,
  PRECISION_NOTES,
  getPrecisionNote,
  listPrecisionNoteIds,
  precisionAttachmentsFor,
  validateClosure,
  type ClosureClaim,
  type ClosureContext,
} from "../precision.ts"
import { FRAGMENTS } from "../methodology.ts"

const noProof: ClosureContext = { hasReproduction: false, hasVerifiedEvidence: false, unverifiedEvidenceRefs: 0 }
const withRepro: ClosureContext = { hasReproduction: true, hasVerifiedEvidence: false, unverifiedEvidenceRefs: 0 }
const withEvidence: ClosureContext = { hasReproduction: false, hasVerifiedEvidence: true, unverifiedEvidenceRefs: 0 }

const check = (claim: ClosureClaim, ctx: ClosureContext = noProof) => validateClosure(claim, ctx)

test("an unproven confirmation claim is downgraded, not trusted", () => {
  const v = check({ state: "confirmed", demonstrated_by: "the scanner flagged it" })
  assert.equal(v.ok, false)
  assert.equal(v.state, "open_proof_gap")
  assert.equal(v.downgraded, true)
  assert.equal(v.requested, "confirmed")
  assert.ok(v.problems.some((p) => /reproduction|evidence reference/i.test(p)))
})

test("confirmation is granted with a reproduction or a resolving evidence ref", () => {
  assert.equal(check({ state: "confirmed", demonstrated_by: "response contained the payload" }, withRepro).state, "confirmed")
  assert.equal(check({ state: "confirmed", demonstrated_by: "captured transcript" }, withEvidence).state, "confirmed")
  // ...but still needs to say WHAT demonstrates it
  assert.equal(check({ state: "confirmed" }, withRepro).state, "open_proof_gap")
})

test("ruled_out requires a named control at a location", () => {
  assert.equal(check({ state: "ruled_out" }).state, "open_proof_gap")
  assert.equal(check({ state: "ruled_out", ruled_out_by: "output encoding" }).state, "open_proof_gap")
  assert.equal(check({ state: "ruled_out", ruled_out_by: "output encoding", ruled_out_at: "src/view.ts:12" }).state, "ruled_out")
  // a vague control name is not checkable
  assert.equal(check({ state: "ruled_out", ruled_out_by: "safe", ruled_out_at: "src/view.ts:12" }).state, "open_proof_gap")
})

test("open_proof_gap is always accepted — an unresolved candidate is a valid outcome", () => {
  const v = check({ state: "open_proof_gap" })
  assert.equal(v.ok, true)
  assert.equal(v.state, "open_proof_gap")
  assert.equal(v.downgraded, false)
  assert.deepEqual(v.problems, [])
})

test("an invalid closure state is refused", () => {
  const v = check({ state: "totally_fixed" as never })
  assert.equal(v.ok, false)
  assert.equal(v.state, "open_proof_gap")
})

test("exactly three closure states exist and every one is reachable", () => {
  assert.deepEqual([...CLOSURE_STATES], ["confirmed", "ruled_out", "open_proof_gap"])
  const reachable = new Set([
    check({ state: "confirmed", demonstrated_by: "x" }, withRepro).state,
    check({ state: "ruled_out", ruled_out_by: "a real control", ruled_out_at: "a.ts:1" }).state,
    check({ state: "open_proof_gap" }).state,
  ])
  assert.deepEqual([...reachable].sort(), ["confirmed", "open_proof_gap", "ruled_out"])
})

test("every precision note is substantive and attached to a real fragment", () => {
  const ids = new Set(FRAGMENTS.map((f) => f.id))
  assert.ok(listPrecisionNoteIds().length >= 10, "expected broad class coverage")
  for (const id of listPrecisionNoteIds()) {
    const note = getPrecisionNote(id)!
    assert.ok(ids.has(id), `precision note '${id}' does not match any methodology fragment`)
    assert.ok(note.instructions.length > 120, `precision note '${id}' is too thin to change behaviour`)
  }
})

test("false-positive shapes attach their class note to the finding", () => {
  const phar = precisionAttachmentsFor({
    title: "PHP phar:// metadata deserialization",
    evidence: "The upload wrapper accepts phar:// paths.",
  })
  assert.deepEqual(phar.map((n) => n.class_id), ["insecure-deserialization"])
  assert.match(phar[0]!.note, /Phar metadata/i)

  assert.deepEqual(
    precisionAttachmentsFor({ title: "OAuth callback accepts a missing state parameter" }).map((n) => n.class_id),
    ["auth-session"],
  )
  assert.deepEqual(precisionAttachmentsFor({ title: "Kubelet 401 on the pods endpoint" }).map((n) => n.class_id), [
    "access-control",
  ])
  assert.deepEqual(
    precisionAttachmentsFor({ title: "Django SECRET_KEY disclosed in the debug page" }).map((n) => n.class_id),
    ["recon-web"],
  )
  assert.deepEqual(
    precisionAttachmentsFor({ title: "NoSQL injection when security.javascriptEnabled is true" }).map((n) => n.class_id),
    ["sqli"],
  )
})

test("precision notes say what is NOT proof, not just what to do", () => {
  // These classes are the classic over-claiming traps; each note must push back.
  assert.match(getPrecisionNote("ssti")!.instructions, /not automatically remote code execution/i)
  assert.match(getPrecisionNote("ssrf")!.instructions, /echoes the URL is not SSRF/i)
  assert.match(getPrecisionNote("auth-session")!.instructions, /does not establish login CSRF/i)
  assert.match(getPrecisionNote("subdomain-takeover")!.instructions, /not independently critical/i)
  assert.match(getPrecisionNote("file-upload")!.instructions, /headers alone are not an executable upload/i)
})
