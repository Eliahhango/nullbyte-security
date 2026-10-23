/**
 * Precision discipline: class-specific false-positive suppression and finding
 * closure rules.
 *
 * Two distinct mechanisms, both server-side (the model cannot opt out):
 *
 *  1. `PRECISION_NOTES` — per vulnerability class, the things that are commonly
 *     mistaken for proof but are not. Attached to a methodology fragment when it
 *     is loaded, so the agent sees the correction next to the technique.
 *
 *  2. `validateClosure` — the closure gate. A finding may only be called
 *     `confirmed` when something actually demonstrates it, and only `ruled_out`
 *     when a specific control at a specific place was checked. A model asserting
 *     "confirmed" is not evidence, so the claim is downgraded rather than
 *     trusted.
 *
 * The failure this exists to prevent, in both directions:
 *  - a false positive ships because "the scanner said so" was treated as proof;
 *  - a real bug is dropped because an uncertain agent quietly closed a candidate
 *    it could not disprove. `open_proof_gap` is the honest third state.
 */

import type { PrecisionAttachment } from "./types.ts"

export type ClosureState = "confirmed" | "ruled_out" | "open_proof_gap"

export const CLOSURE_STATES: readonly ClosureState[] = ["confirmed", "ruled_out", "open_proof_gap"]

export interface ClosureClaim {
  state: ClosureState
  /** confirmed: what demonstrates the behaviour (PoC, trace, observed effect) */
  demonstrated_by?: string
  /** ruled_out: the specific control that makes it safe */
  ruled_out_by?: string
  /** ruled_out: where that control lives or was observed */
  ruled_out_at?: string
}

export interface ClosureContext {
  /** a reproduction/PoC was supplied */
  hasReproduction: boolean
  /** at least one evidence reference resolved to a real artifact */
  hasVerifiedEvidence: boolean
  /** number of evidence references that failed to resolve */
  unverifiedEvidenceRefs: number
}

export interface ClosureVerdict {
  ok: boolean
  /** the state that will actually be recorded */
  state: ClosureState
  /** what the caller asked for, when it differs */
  requested?: ClosureState
  /** true when the requested state was not granted */
  downgraded: boolean
  problems: string[]
}

/** Per-class precision rules. Keys are methodology fragment ids. */
export interface PrecisionNote {
  /** sharper one-line description for the catalog */
  catalogNote?: string
  /** what is NOT proof, and what must be verified instead */
  instructions: string
}

export const PRECISION_NOTES: Record<string, PrecisionNote> = {
  ssti: {
    instructions:
      "Template injection is not automatically remote code execution. Claim RCE only when the deployed engine and a reachable template context expose an execution primitive AND you observe an execution side effect. Otherwise report only the verified lower-impact template behaviour (arithmetic or string evaluation).",
  },
  "path-traversal": {
    instructions:
      "Separate reading from executing. Traversal that reaches a file the process already owns is lower severity than traversal that reaches credentials or configuration. php://filter, php://input, data:// and log poisoning are RCE paths: report the file-read finding and stop, do not detonate.",
  },
  ssrf: {
    instructions:
      "A parameter that merely echoes the URL is not SSRF; prove server-side reachability from a listener you control. A media or image renderer is not full-read SSRF without verifying the deployed version, the endpoint behaviour, and observable access to a scoped internal resource. Do not generalise one renderer issue to every deployment.",
  },
  "auth-session": {
    instructions:
      "Missing OAuth state alone does not establish login CSRF: transaction-bound PKCE or an OIDC nonce can supply equivalent protection, so verify binding to the initiating client and user-agent session, including cross-session callback and PKCE downgrade. Public-client refresh tokens must be sender-constrained OR rotated; absence of rotation alone is not a finding when sender constraint prevents replay. For password policy, missing composition rules or history are not vulnerabilities under NIST SP 800-63B-4, which prohibits mandatory composition and periodic resets absent compromise evidence: assess against the target's stated baseline and require length, breach screening and online-guessing resistance instead.",
  },
  "access-control": {
    instructions:
      "A kubelet 401 or 403 is not proof of anonymous access or an authorization bypass: the endpoint may simply require a client certificate or token. Verify the exact path and method, whether authentication is genuinely skipped rather than rejected, and whether the unauthenticated response exposes workload data or exec. A default-deny response is counterevidence, not a finding.",
  },
  "recon-web": {
    instructions:
      "A Django SECRET_KEY in a debug page, settings dump or repository is a disclosure of signing material, not automatically an authentication bypass. Verify it is the deployed key and that it signs a reachable session, token or signed URL; a placeholder, a non-deployed settings module, or an unusable key is lower severity. Report the disclosure and rotate it, but do not claim session forgery without demonstrating a forged artifact the application accepts.",
  },
  "file-upload": {
    instructions:
      "Response headers alone are not an executable upload. Require evidence that the stored object reaches an active renderer and produces script execution, content-type confusion with concrete impact, or another cross-user effect. A safely rendered image response is counterevidence even when attachment and nosniff headers are absent.",
  },
  "command-injection": {
    instructions:
      "Establish which boundary is crossed. A value beginning with a dash is argument injection, not necessarily shell injection. Client calls that preserve argument boundaries are not command injection: claim it only when input reaches raw protocol text, a shell, or another boundary that reparses commands.",
  },
  idor: {
    instructions:
      "Changing a client-side flag is not proof; confirm the server acted on the substituted identifier. A 403 on GET does not establish absence of the same object on POST, PUT or PATCH. Report horizontal and vertical escalation separately.",
  },
  sqli: {
    instructions:
      "For document stores, gate server-side JavaScript probes on the effective engine setting rather than the product version, and never use unbounded loops, catastrophic regexes or heavy aggregations against a non-disposable service. For relational stores, a single differing response is noise: require a repeatable, proportional difference.",
  },
  xss: {
    instructions:
      "Content-Security-Policy, X-Content-Type-Options and cookie flags change impact, not existence. Report the source and the sink, and record the exact character set that survived the filter; a payload without that detail is not reproducible.",
  },
  "insecure-deserialization": {
    instructions:
      "A phar:// file operation is not automatic metadata deserialization: modern PHP runtimes stopped unserializing Phar metadata implicitly. Resolve the installed runtime and trace the explicit metadata accessor, its allowed-classes option, and the reachable instantiation path. Require the actual deserialization sink and an observable effect before claiming execution.",
  },
  "subdomain-takeover": {
    instructions:
      "An expired or unclaimed nameserver domain is a high-priority lead, not independently critical. Require verified delegation, successful authoritative control of the resource, and material scoped impact before assigning critical severity.",
  },
  "open-redirect": {
    instructions:
      "A properly anchored wildcard rule matches subdomains of the trusted domain, not a lookalike that merely contains it. Report a bypass only when the implementation uses an unsafe substring, suffix, normalisation or parsing check, and keep a correct wildcard rule distinct from naive matching.",
  },
}

export function getPrecisionNote(id: string): PrecisionNote | undefined {
  return PRECISION_NOTES[id]
}

export function listPrecisionNoteIds(): string[] {
  return Object.keys(PRECISION_NOTES)
}

/** The fields that can carry a false-positive shape. */
export interface PrecisionSubject {
  title?: string
  description?: string
  impact?: string
  evidence?: string
  reproduction?: string
  demonstrated_by?: string
  counterevidence?: string
  cwe?: string
}

interface PrecisionTrigger {
  class_id: string
  /** the phrase that demonstrates the shape, for the attachment record */
  trigger: string
  match: (text: string) => boolean
}

const PRECISION_TRIGGERS: readonly PrecisionTrigger[] = [
  {
    class_id: "insecure-deserialization",
    trigger: "PHP Phar metadata",
    match: (t) => /\bphar:\/\/|\bphar\b/i.test(t),
  },
  {
    class_id: "auth-session",
    trigger: "OAuth/OIDC flow",
    match: (t) => /\b(?:oauth|oidc|openid|pkce)\b/i.test(t),
  },
  {
    class_id: "auth-session",
    trigger: "OAuth state parameter",
    match: (t) => /\bstate\b[^\n]{0,100}\b(?:callback|redirect|parameter|param|token)\b/i.test(t),
  },
  {
    class_id: "access-control",
    trigger: "kubelet endpoint",
    match: (t) => /\bkubelet\b/i.test(t),
  },
  {
    class_id: "recon-web",
    trigger: "Django SECRET_KEY",
    match: (t) => /\bdjango\b/i.test(t) && /\bsecret[_-]?key\b/i.test(t),
  },
  {
    class_id: "sqli",
    trigger: "NoSQL JavaScript setting",
    match: (t) => /security\.javascriptEnabled|javascriptEnabled/i.test(t),
  },
]

/**
 * Attach every class-specific false-positive note whose shape appears in the
 * finding text. Deterministic and local: no model call, no caller opt-out.
 */
export function precisionAttachmentsFor(subject: PrecisionSubject): PrecisionAttachment[] {
  const text = [
    subject.title,
    subject.description,
    subject.impact,
    subject.evidence,
    subject.reproduction,
    subject.demonstrated_by,
    subject.counterevidence,
    subject.cwe,
  ]
    .filter((v): v is string => typeof v === "string" && v.trim().length > 0)
    .join("\n")

  const seen = new Set<string>()
  const out: PrecisionAttachment[] = []
  for (const trigger of PRECISION_TRIGGERS) {
    if (seen.has(trigger.class_id) || !trigger.match(text)) continue
    const note = getPrecisionNote(trigger.class_id)
    if (!note) continue
    seen.add(trigger.class_id)
    out.push({ class_id: trigger.class_id, trigger: trigger.trigger, note: note.instructions })
  }
  return out
}

/**
 * Decide which closure state a finding may actually be recorded with.
 *
 * The model's requested state is a claim, not a fact. It is granted only when
 * the accompanying evidence supports it, and otherwise downgraded to
 * `open_proof_gap` with the reason attached.
 */
export function validateClosure(claim: ClosureClaim, ctx: ClosureContext): ClosureVerdict {
  const problems: string[] = []
  const requested = claim.state

  if (!CLOSURE_STATES.includes(requested)) {
    return {
      ok: false,
      state: "open_proof_gap",
      downgraded: true,
      problems: [`closure state must be one of ${CLOSURE_STATES.join(" | ")}`],
    }
  }

  // A real bug is never lost: an unresolved candidate is always acceptable.
  if (requested === "open_proof_gap") {
    return { ok: true, state: "open_proof_gap", downgraded: false, problems }
  }

  if (requested === "confirmed") {
    const demonstrated = claim.demonstrated_by?.trim()
    if (!demonstrated) {
      problems.push("confirmed requires demonstrated_by: what actually demonstrates the behaviour")
    }
    if (!ctx.hasReproduction && !ctx.hasVerifiedEvidence) {
      problems.push(
        "confirmed requires a reproduction or at least one evidence reference that resolves to a real artifact; an assertion is not evidence",
      )
    }
    if (problems.length) {
      return {
        ok: false,
        state: "open_proof_gap",
        requested,
        downgraded: true,
        problems: [...problems, "recorded as open_proof_gap instead"],
      }
    }
    return { ok: true, state: "confirmed", downgraded: false, problems }
  }

  // ruled_out — the state that hides real bugs when it is used to tidy up.
  const control = claim.ruled_out_by?.trim()
  const location = claim.ruled_out_at?.trim()
  if (!control) {
    problems.push(
      "ruled_out requires ruled_out_by: name the specific control that makes it safe, not a general assurance",
    )
  }
  if (!location) {
    problems.push("ruled_out requires ruled_out_at: the file:line or observed behaviour where that control runs")
  }
  if (control && location && control.length < 8) {
    problems.push("ruled_out_by is too vague to be checkable; state what the control does")
  }
  if (problems.length) {
    return {
      ok: false,
      state: "open_proof_gap",
      requested,
      downgraded: true,
      problems: [
        ...problems,
        "if you cannot name the control and where it runs, the honest state is open_proof_gap",
      ],
    }
  }
  return { ok: true, state: "ruled_out", downgraded: false, problems }
}

/** Human-readable closure guidance for the agent, used in tool descriptions. */
export const CLOSURE_GUIDANCE =
  "Closure states: confirmed (needs demonstrated_by plus a reproduction or resolving evidence), " +
  "ruled_out (needs the specific control and where it runs), open_proof_gap (always allowed — use it " +
  "instead of quietly closing something you could not disprove)."
