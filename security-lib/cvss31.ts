/**
 * CVSS 3.1 base score, vector and severity.
 *
 * Ported from HackerAI's `lib/findings/cvss31.ts` + `lib/findings/validation.ts`:
 * the model supplies only the eight base metrics, and the score, vector string
 * and severity band are computed here so they can never be hallucinated.
 */

import type { CvssBreakdown, Severity } from "./types.ts"

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const AC: Record<string, number> = { L: 0.77, H: 0.44 }
const PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 }
const PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 }
const UI: Record<string, number> = { N: 0.85, R: 0.62 }
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 }

/** CVSS 3.1 roundup: round up to one decimal without floating point drift. */
export function roundUp(input: number): number {
  const intInput = Math.round(input * 100000)
  if (intInput % 10000 === 0) return intInput / 100000
  return (Math.floor(intInput / 10000) + 1) / 10
}

/** Map a numeric base score onto the standard severity bands. */
export function getCvss31Severity(score: number): Severity {
  if (score >= 9) return "critical"
  if (score >= 7) return "high"
  if (score >= 4) return "medium"
  if (score > 0) return "low"
  return "info"
}

export function calculateCvss31BaseScore(m: CvssBreakdown): number {
  const iss = 1 - (1 - CIA[m.confidentiality]) * (1 - CIA[m.integrity]) * (1 - CIA[m.availability])
  const scopeChanged = m.scope === "C"
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss
  const exploitability =
    8.22 *
    AV[m.attack_vector] *
    AC[m.attack_complexity] *
    (scopeChanged ? PR_C[m.privileges_required] : PR_U[m.privileges_required]) *
    UI[m.user_interaction]

  if (impact <= 0) return 0
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10)
  return roundUp(raw)
}

export function getCvss31Vector(m: CvssBreakdown): string {
  return [
    "CVSS:3.1",
    `AV:${m.attack_vector}`,
    `AC:${m.attack_complexity}`,
    `PR:${m.privileges_required}`,
    `UI:${m.user_interaction}`,
    `S:${m.scope}`,
    `C:${m.confidentiality}`,
    `I:${m.integrity}`,
    `A:${m.availability}`,
  ].join("/")
}

export interface CvssResult {
  score: number
  severity: Severity
  vector: string
}

export function calculateCvss31(m: CvssBreakdown): CvssResult {
  const score = calculateCvss31BaseScore(m)
  return { score, severity: getCvss31Severity(score), vector: getCvss31Vector(m) }
}

const VALID: Record<keyof CvssBreakdown, string[]> = {
  attack_vector: ["N", "A", "L", "P"],
  attack_complexity: ["L", "H"],
  privileges_required: ["N", "L", "H"],
  user_interaction: ["N", "R"],
  scope: ["U", "C"],
  confidentiality: ["N", "L", "H"],
  integrity: ["N", "L", "H"],
  availability: ["N", "L", "H"],
}

/** Validate the metric set; returns problems (empty array == valid). */
export function validateCvssBreakdown(m: unknown): string[] {
  const problems: string[] = []
  if (!m || typeof m !== "object") return ["cvss_breakdown must be an object with the 8 base metrics"]
  const o = m as Record<string, unknown>
  for (const [key, allowed] of Object.entries(VALID)) {
    const v = o[key]
    if (v === undefined) {
      problems.push(`cvss_breakdown.${key} is required`)
      continue
    }
    if (!allowed.includes(String(v))) {
      problems.push(`cvss_breakdown.${key} must be one of ${allowed.join("/")}`)
    }
  }
  for (const k of Object.keys(o)) {
    if (!(k in VALID)) problems.push(`cvss_breakdown.${k} is not a CVSS 3.1 base metric`)
  }
  return problems
}
