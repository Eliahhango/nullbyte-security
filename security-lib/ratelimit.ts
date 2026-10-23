/**
 * Pacing for everything that talks to a target.
 *
 * Bounded concurrency already exists *inside* one scan, but nothing bounds the
 * engagement as a whole. A real assessment runs recon, a port scan and two
 * scanners against the same host, often several hosts at once, and an agent that
 * does that in a loop will saturate a production service or trip its IDS — and a
 * scanner tripping an IDS produces findings about the IDS, not about the target.
 *
 * Two independent budgets, both process-wide:
 *
 *  - **global** — how many operations may be in flight at once anywhere, so five
 *    concurrent targets cannot add up to five hundred sockets.
 *  - **per host** — how many may be in flight against one host, plus a minimum
 *    spacing between starts. A host is the unit a target notices.
 *
 * Scanners are additionally exclusive per host: two long-running scanners against
 * one host is the case most likely to be read as an attack.
 *
 * Defaults preserve the previous behaviour (concurrency 64, no pacing), so this
 * only changes anything once an operator asks for it. Limits come from the
 * engagement scope file — pacing is an engagement decision, not a global one.
 */

export interface RateLimits {
  /** max operations in flight across the whole process */
  globalConcurrency: number
  /** max operations in flight against one host */
  perHostConcurrency: number
  /** minimum spacing between two operations against one host, ms */
  perHostIntervalMs: number
  /** optional requests-per-second cap per host; 0 disables. */
  perHostRps: number
}

export const DEFAULT_LIMITS: RateLimits = {
  globalConcurrency: 64,
  perHostConcurrency: 64,
  perHostIntervalMs: 0,
  perHostRps: 0,
}

const ABSOLUTE_MAX_CONCURRENCY = 256
const ABSOLUTE_MAX_INTERVAL_MS = 60_000

let limits: RateLimits = { ...DEFAULT_LIMITS }

/* ------------------------------------------------------------ module state --- */

let globalActive = 0
let globalWaiters: (() => void)[] = []

const hostActive = new Map<string, number>()
/** last start time per host, for the interval */
const hostLastStart = new Map<string, number>()
const hostWaiters = new Map<string, (() => void)[]>()
/** hosts currently running an exclusive (scanner) operation */
const hostExclusive = new Set<string>()

/** Window of recent start times per host, for the rps cap. */
const hostStarts = new Map<string, number[]>()

function clampConcurrency(n: number | undefined, fallback: number): number {
  if (typeof n !== "number" || !Number.isFinite(n)) return fallback
  return Math.max(1, Math.min(Math.floor(n), ABSOLUTE_MAX_CONCURRENCY))
}

function clampInterval(n: number | undefined, fallback: number): number {
  if (typeof n !== "number" || !Number.isFinite(n)) return fallback
  return Math.max(0, Math.min(Math.floor(n), ABSOLUTE_MAX_INTERVAL_MS))
}

/**
 * Fill a partial set of limits out to a complete, clamped one.
 *
 * Pure: the scope file is operator input, so it is clamped rather than trusted,
 * and asking what the limits would be must not change what they are.
 */
export function resolveLimits(next?: Partial<RateLimits>): RateLimits {
  return {
    globalConcurrency: clampConcurrency(next?.globalConcurrency, DEFAULT_LIMITS.globalConcurrency),
    perHostConcurrency: clampConcurrency(next?.perHostConcurrency, DEFAULT_LIMITS.perHostConcurrency),
    perHostIntervalMs: clampInterval(next?.perHostIntervalMs, DEFAULT_LIMITS.perHostIntervalMs),
    perHostRps: clampInterval(next?.perHostRps, DEFAULT_LIMITS.perHostRps),
  }
}

/** Apply engagement limits. Unknown or nonsense values fall back to the default. */
export function configureLimits(next?: Partial<RateLimits>): RateLimits {
  limits = resolveLimits(next)
  return { ...limits }
}

export function currentLimits(): RateLimits {
  return { ...limits }
}

/** The effective spacing for a host: the explicit interval, or the rps cap. */
export function effectiveIntervalMs(): number {
  const fromRps = limits.perHostRps > 0 ? Math.ceil(1000 / limits.perHostRps) : 0
  return Math.max(limits.perHostIntervalMs, fromRps)
}

/** How many connections a caller may still open against one host. */
export function hostConcurrencyCap(requested?: number): number {
  const want = clampConcurrency(requested, limits.perHostConcurrency)
  return Math.min(want, limits.perHostConcurrency)
}

/** Reset all pacing state. Tests only — a reset mid-engagement would unpace it. */
export function resetRateLimiter(): void {
  limits = { ...DEFAULT_LIMITS }
  globalActive = 0
  globalWaiters = []
  hostActive.clear()
  hostLastStart.clear()
  hostWaiters.clear()
  hostExclusive.clear()
  hostStarts.clear()
}

/* ------------------------------------------------------------- primitives --- */

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))

/**
 * Both semaphores hand the slot straight to the next waiter instead of
 * decrementing and letting it re-check. Re-checking races: two waiters woken by
 * one release can both find room and overshoot the cap.
 */
async function acquireGlobal(): Promise<void> {
  if (globalActive < limits.globalConcurrency) {
    globalActive++
    return
  }
  await new Promise<void>((resolve) => globalWaiters.push(resolve))
}

function releaseGlobal(): void {
  const next = globalWaiters.shift()
  if (next) {
    next() // the slot is transferred, so the count does not change
    return
  }
  globalActive = Math.max(0, globalActive - 1)
}

async function acquireHost(host: string): Promise<void> {
  const active = hostActive.get(host) ?? 0
  if (active < limits.perHostConcurrency) {
    hostActive.set(host, active + 1)
    return
  }
  await new Promise<void>((resolve) => {
    const queue = hostWaiters.get(host) ?? []
    queue.push(resolve)
    hostWaiters.set(host, queue)
  })
}

function releaseHost(host: string): void {
  const queue = hostWaiters.get(host)
  const next = queue?.shift()
  if (queue && queue.length === 0) hostWaiters.delete(host)
  if (next) {
    next() // slot transferred; the active count is unchanged
    return
  }
  const active = Math.max(0, (hostActive.get(host) ?? 1) - 1)
  if (active === 0) hostActive.delete(host)
  else hostActive.set(host, active)
}

/** Wait until this host may start another operation, then reserve it. */
async function paceHost(host: string): Promise<void> {
  const interval = effectiveIntervalMs()
  if (interval <= 0) {
    hostStarts.set(host, [Date.now()])
    return
  }
  for (;;) {
    const now = Date.now()
    const recent = (hostStarts.get(host) ?? []).filter((t) => now - t < 1000)
    // rps is enforced as a sliding one-second window on top of the fixed interval
    if (limits.perHostRps > 0 && recent.length >= limits.perHostRps) {
      const oldest = recent[0]!
      await sleep(Math.max(1, oldest + 1000 - now))
      continue
    }
    const last = hostLastStart.get(host)
    const wait = last === undefined ? 0 : last + interval - now
    if (wait > 0) {
      await sleep(wait)
      continue
    }
    hostLastStart.set(host, Date.now())
    hostStarts.set(host, [...recent, Date.now()])
    return
  }
}

/* --------------------------------------------------------------- public API --- */

/**
 * Run `fn` under the global and per-host budgets.
 *
 * `host` is the pacing key; callers pass the name as it appears in the scope so
 * that `app.acme.test` and `app.acme.test:8443` share one budget.
 */
export async function withHostSlot<T>(host: string, fn: () => Promise<T>): Promise<T> {
  await acquireGlobal()
  try {
    await acquireHost(host)
    try {
      await paceHost(host)
      return await fn()
    } finally {
      releaseHost(host)
    }
  } finally {
    releaseGlobal()
  }
}

/**
 * Run `fn` as the only operation against this host.
 *
 * For scanners: they are long, loud and the ones an IPS is most likely to act
 * on, so two at once against one host is never the intent.
 */
export async function withExclusiveHostSlot<T>(host: string, fn: () => Promise<T>): Promise<T> {
  // wait out any scanner already running on this host, then take the marker
  while (hostExclusive.has(host)) await sleep(25)
  hostExclusive.add(host)
  try {
    return await withHostSlot(host, fn)
  } finally {
    hostExclusive.delete(host)
  }
}

export interface RateLimitSnapshot {
  globalActive: number
  globalConcurrency: number
  perHostConcurrency: number
  intervalMs: number
  perHostRps: number
  hosts: { host: string; active: number; exclusive: boolean }[]
}

/** Current pacing state, for reporting what the engagement was actually run at. */
export function rateLimitSnapshot(): RateLimitSnapshot {
  const hosts = new Set([...hostActive.keys(), ...hostExclusive])
  return {
    globalActive,
    globalConcurrency: limits.globalConcurrency,
    perHostConcurrency: limits.perHostConcurrency,
    intervalMs: effectiveIntervalMs(),
    perHostRps: limits.perHostRps,
    hosts: [...hosts].map((host) => ({
      host,
      active: hostActive.get(host) ?? 0,
      exclusive: hostExclusive.has(host),
    })),
  }
}

/**
 * True when these limits actually change anything. Tools use it to mention the
 * pacing only when there is pacing to mention — an engagement run at defaults
 * should not carry a line about limits nobody set.
 */
export function isPaced(l: Partial<RateLimits> = currentLimits()): boolean {
  const r = resolveLimits(l)
  return (
    r.perHostIntervalMs > 0 ||
    r.perHostRps > 0 ||
    r.globalConcurrency < DEFAULT_LIMITS.globalConcurrency ||
    r.perHostConcurrency < DEFAULT_LIMITS.perHostConcurrency
  )
}

/** One-line description of a set of limits, pure — for showing a scope's intent. */
export function describeLimitsOf(partial?: Partial<RateLimits>): string {
  const l = resolveLimits(partial)
  const parts = [`${l.globalConcurrency} concurrent total`, `${l.perHostConcurrency} per host`]
  const interval = Math.max(l.perHostIntervalMs, l.perHostRps > 0 ? Math.ceil(1000 / l.perHostRps) : 0)
  if (interval > 0) parts.push(`${interval}ms between requests per host`)
  if (l.perHostRps > 0) parts.push(`${l.perHostRps} req/s per host`)
  if (l.perHostIntervalMs === 0 && l.perHostRps === 0) parts.push("no added delay")
  return parts.join(", ")
}

/** One-line description of the pacing currently in force. */
export function describeLimits(): string {
  return describeLimitsOf(currentLimits())
}
