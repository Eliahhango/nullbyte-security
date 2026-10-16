/**
 * Security header + cookie analysis. Pure functions over observed headers so
 * they are trivially testable and never invent values.
 */

export type CheckStatus = "ok" | "weak" | "missing" | "info" | "high-risk"

export interface HeaderCheck {
  header: string
  status: CheckStatus
  value?: string
  detail: string
  recommendation?: string
}

export interface CookieCheck {
  name: string
  status: CheckStatus
  detail: string
  flags: { secure: boolean; httpOnly: boolean; sameSite?: string; domain?: string; path?: string; expires?: string }
}

export interface HeaderAnalysis {
  grade: string
  score: number
  checks: HeaderCheck[]
  cookies: CookieCheck[]
}

function h(headers: Record<string, string>, name: string): string | undefined {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase())
  return key ? headers[key] : undefined
}

export function analyzeSecurityHeaders(headers: Record<string, string>): HeaderAnalysis {
  const checks: HeaderCheck[] = []
  let score = 0
  const maxScore = 8

  // Strict-Transport-Security
  const hsts = h(headers, "strict-transport-security")
  if (!hsts) {
    checks.push({
      header: "Strict-Transport-Security",
      status: "missing",
      detail: "HSTS absent; downgrade to plaintext HTTP is possible for returning visitors.",
      recommendation: "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.",
    })
  } else {
    const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0)
    const ok = maxAge >= 15552000
    if (ok) score++
    checks.push({
      header: "Strict-Transport-Security",
      status: ok ? "ok" : "weak",
      value: hsts,
      detail: ok ? `HSTS enforced for ${maxAge}s.` : `HSTS max-age is only ${maxAge}s (< 180 days).`,
      recommendation: ok ? undefined : "Increase max-age to at least 15552000 and add includeSubDomains.",
    })
  }

  // Content-Security-Policy
  const csp = h(headers, "content-security-policy")
  if (!csp) {
    checks.push({
      header: "Content-Security-Policy",
      status: "missing",
      detail: "No CSP; injected script executes with full page privileges.",
      recommendation: "Deploy a restrictive CSP (`default-src 'self'`) and remove inline script.",
    })
  } else {
    const weak = /unsafe-inline|unsafe-eval/i.test(csp)
    if (!weak) score++
    checks.push({
      header: "Content-Security-Policy",
      status: weak ? "weak" : "ok",
      value: csp,
      detail: weak ? "CSP allows 'unsafe-inline' or 'unsafe-eval', which defeats most of its value." : "CSP present without unsafe-inline/unsafe-eval.",
      recommendation: weak ? "Replace unsafe-inline with nonces or hashes." : undefined,
    })
  }

  // X-Content-Type-Options
  const xcto = h(headers, "x-content-type-options")
  if (xcto && /nosniff/i.test(xcto)) {
    score++
    checks.push({ header: "X-Content-Type-Options", status: "ok", value: xcto, detail: "MIME sniffing disabled." })
  } else {
    checks.push({
      header: "X-Content-Type-Options",
      status: "missing",
      detail: "MIME sniffing is not disabled.",
      recommendation: "Send `X-Content-Type-Options: nosniff`.",
    })
  }

  // Frame protection
  const xfo = h(headers, "x-frame-options")
  const frameAncestors = csp && /frame-ancestors/i.test(csp)
  if (frameAncestors || (xfo && /deny|sameorigin/i.test(xfo))) {
    score++
    checks.push({
      header: "X-Frame-Options / CSP frame-ancestors",
      status: "ok",
      value: xfo ?? "CSP frame-ancestors",
      detail: "Framing restricted; clickjacking mitigated.",
    })
  } else {
    checks.push({
      header: "X-Frame-Options / CSP frame-ancestors",
      status: "missing",
      detail: "Page may be framed by any origin.",
      recommendation: "Send `X-Frame-Options: DENY` or a CSP `frame-ancestors 'none'`.",
    })
  }

  // Referrer-Policy
  const rp = h(headers, "referrer-policy")
  if (rp && !/unsafe-url|no-referrer-when-downgrade/i.test(rp)) {
    score++
    checks.push({ header: "Referrer-Policy", status: "ok", value: rp, detail: "Referrer leakage limited." })
  } else {
    checks.push({
      header: "Referrer-Policy",
      status: rp ? "weak" : "missing",
      value: rp,
      detail: rp ? "Policy still leaks full URLs on downgrade." : "No Referrer-Policy set.",
      recommendation: "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
    })
  }

  // Permissions-Policy
  const pp = h(headers, "permissions-policy")
  if (pp) {
    score++
    checks.push({ header: "Permissions-Policy", status: "ok", value: pp, detail: "Powerful features restricted." })
  } else {
    checks.push({
      header: "Permissions-Policy",
      status: "info",
      detail: "No Permissions-Policy; browser features default to permissive.",
      recommendation: "Disable unused features explicitly.",
    })
  }

  // Information disclosure
  const server = h(headers, "server")
  if (server && /\d+\.\d+/.test(server)) {
    checks.push({
      header: "Server",
      status: "info",
      value: server,
      detail: "Server banner discloses a version.",
      recommendation: "Suppress or genericise the Server banner.",
    })
  } else if (server) {
    score++
    checks.push({ header: "Server", status: "ok", value: server, detail: "Server banner present without version." })
  }

  const powered = h(headers, "x-powered-by")
  if (powered) {
    checks.push({
      header: "X-Powered-By",
      status: "info",
      value: powered,
      detail: "Technology stack disclosed.",
      recommendation: "Remove the X-Powered-By header.",
    })
  } else {
    score++
  }

  // CORS wildcard with credentials
  const acao = h(headers, "access-control-allow-origin")
  const acac = h(headers, "access-control-allow-credentials")
  if (acao === "*" && acac && /true/i.test(acac)) {
    checks.push({
      header: "Access-Control-Allow-Origin",
      status: "high-risk",
      value: `${acao} with credentials ${acac}`,
      detail: "Wildcard origin combined with credentials is a high-risk misconfiguration (and invalid per spec, but some stacks honour it).",
      recommendation: "Reflect an explicit allow-list of origins and drop the wildcard.",
    })
  } else if (acao === "*") {
    checks.push({
      header: "Access-Control-Allow-Origin",
      status: "weak",
      value: acao,
      detail: "Any origin may read unauthenticated responses.",
      recommendation: "Restrict to known origins if the data is not public.",
    })
  }

  const pct = Math.round((score / maxScore) * 100)
  const grade = pct >= 90 ? "A" : pct >= 75 ? "B" : pct >= 55 ? "C" : pct >= 35 ? "D" : "F"
  return { grade, score: pct, checks, cookies: analyzeCookies(h(headers, "set-cookie")) }
}

function parseSetCookie(raw: string): CookieCheck["flags"] & { name: string } {
  const parts = raw.split(";").map((p) => p.trim())
  const [nameValue, ...attrs] = parts
  const name = nameValue.split("=")[0] ?? ""
  const flags: CookieCheck["flags"] = {
    secure: attrs.some((a) => /^secure$/i.test(a)),
    httpOnly: attrs.some((a) => /^httponly$/i.test(a)),
  }
  for (const a of attrs) {
    const [k, v] = a.split("=")
    if (/^samesite$/i.test(k)) flags.sameSite = v
    if (/^domain$/i.test(k)) flags.domain = v
    if (/^path$/i.test(k)) flags.path = v
    if (/^expires$/i.test(k)) flags.expires = v
  }
  return Object.assign(flags, { name })
}

/** Analyze a Set-Cookie header value (may contain multiple cookies). */
export function analyzeCookies(setCookie: string | undefined): CookieCheck[] {
  if (!setCookie) return []
  const out: CookieCheck[] = []
  // Set-Cookie can be comma-joined by some clients; split conservatively on ", " followed by name=
  const raws = setCookie.split(/,(?=\s*[^;=,\s]+=)/)
  for (const raw of raws) {
    const parsed = parseSetCookie(raw)
    const problems: string[] = []
    if (!parsed.secure) problems.push("missing Secure")
    if (!parsed.httpOnly) problems.push("missing HttpOnly")
    if (!parsed.sameSite) problems.push("missing SameSite")
    const looksSessiony = /sess|token|auth|jwt|sid|login/i.test(parsed.name)
    let status: CheckStatus = "ok"
    if (problems.length && looksSessiony) status = "weak"
    else if (problems.length) status = "info"
    out.push({
      name: parsed.name,
      status,
      flags: parsed,
      detail:
        problems.length === 0
          ? "Cookie sets Secure, HttpOnly and SameSite."
          : `Cookie is missing: ${problems.join(", ")}.`,
    })
  }
  return out
}
