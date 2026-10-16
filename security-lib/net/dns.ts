/**
 * DNS reconnaissance (read-only, passive by nature).
 * Real resolution via node:dns — no shelling out, no fabricated records.
 */

import { Resolver } from "node:dns/promises"

export interface DnsResult {
  host: string
  a: string[]
  aaaa: string[]
  cname: string[]
  mx: Array<{ exchange: string; priority: number }>
  ns: string[]
  txt: string[][]
  ptr: string[]
  errors: string[]
  durationMs: number
}

function withTimeout<T>(p: Promise<T>, ms: number, onTimeout: () => T): Promise<T> {
  return new Promise<T>((resolve) => {
    let done = false
    const t = setTimeout(() => {
      if (done) return
      done = true
      resolve(onTimeout())
    }, ms)
    p.then((v) => {
      if (done) return
      done = true
      clearTimeout(t)
      resolve(v)
    }).catch(() => {
      if (done) return
      done = true
      clearTimeout(t)
      resolve(onTimeout())
    })
  })
}

export interface DnsOptions {
  timeoutMs?: number
  /** resolve PTR for discovered addresses (reverse DNS) */
  reverse?: boolean
}

export async function dnsRecon(host: string, opts: DnsOptions = {}): Promise<DnsResult> {
  const timeoutMs = opts.timeoutMs ?? 5000
  const started = Date.now()
  const r = new Resolver({ timeout: timeoutMs, tries: 1 })
  const errors: string[] = []

  const empty = <T>(fallback: T) => () => fallback

  const [a, aaaa, cname, mx, ns, txt] = await Promise.all([
    withTimeout(r.resolve4(host), timeoutMs, empty([] as string[])).catch(() => [] as string[]),
    withTimeout(r.resolve6(host), timeoutMs, empty([] as string[])).catch(() => [] as string[]),
    withTimeout(r.resolveCname(host), timeoutMs, empty([] as string[])).catch(() => [] as string[]),
    withTimeout(r.resolveMx(host), timeoutMs, empty([] as Array<{ exchange: string; priority: number }>)).catch(() => []),
    withTimeout(r.resolveNs(host), timeoutMs, empty([] as string[])).catch(() => []),
    withTimeout(r.resolveTxt(host), timeoutMs, empty([] as string[][])).catch(() => []),
  ])

  let ptr: string[] = []
  if (opts.reverse) {
    const addrs = [...a, ...aaaa]
    const resolved = await Promise.all(
      addrs.slice(0, 10).map((ip) => withTimeout(r.reverse(ip), timeoutMs, empty([] as string[])).catch(() => [])),
    )
    ptr = resolved.flat()
  }

  if (!a.length && !aaaa.length && !cname.length) errors.push(`no A/AAAA/CNAME records resolved for ${host}`)

  return {
    host,
    a: [...new Set(a)],
    aaaa: [...new Set(aaaa)],
    cname: [...new Set(cname)],
    mx,
    ns: [...new Set(ns)],
    txt,
    ptr: [...new Set(ptr)],
    errors,
    durationMs: Date.now() - started,
  }
}

/** Convenience for the scope guard: all addresses a name currently resolves to. */
export async function resolveAddresses(host: string, timeoutMs = 5000): Promise<string[]> {
  const r = new Resolver({ timeout: timeoutMs, tries: 1 })
  const out: string[] = []
  try {
    out.push(...(await r.resolve4(host)))
  } catch {
    /* not an A name */
  }
  try {
    out.push(...(await r.resolve6(host)))
  } catch {
    /* not an AAAA name */
  }
  return [...new Set(out)]
}
