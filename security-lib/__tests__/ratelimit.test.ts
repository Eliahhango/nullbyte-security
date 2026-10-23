/**
 * Rate limiting and the concurrency budget.
 *
 * The failure this guards against is not a crash: it is an engagement that
 * quietly ignores its own pacing and hammers a monitored host. So the tests
 * assert observed concurrency and observed timing, not that a function was
 * called.
 */

import { strict as assert } from "node:assert"
import { test } from "node:test"
import {
  DEFAULT_LIMITS,
  configureLimits,
  currentLimits,
  describeLimits,
  describeLimitsOf,
  effectiveIntervalMs,
  hostConcurrencyCap,
  rateLimitSnapshot,
  resetRateLimiter,
  resolveLimits,
  withExclusiveHostSlot,
  withHostSlot,
} from "../ratelimit.ts"
import { normalizeLimits, normalizeScope, scopeTemplate, DEFAULT_SCOPE } from "../config.ts"
import { runArgv } from "../adapters/scanners.ts"

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/* ------------------------------------------------------------- defaults --- */

test("defaults reproduce the pre-existing behaviour", () => {
  resetRateLimiter()
  const l = currentLimits()
  assert.equal(l.globalConcurrency, 64)
  assert.equal(l.perHostConcurrency, 64)
  assert.equal(l.perHostIntervalMs, 0)
  assert.equal(effectiveIntervalMs(), 0, "no pacing unless asked for")
  resetRateLimiter()
})

test("nonsense limits never disable the budget", () => {
  // a value that is not a number at all is treated as absent
  const absent = resolveLimits({ globalConcurrency: NaN, perHostConcurrency: Infinity as number })
  assert.equal(absent.globalConcurrency, DEFAULT_LIMITS.globalConcurrency)
  assert.equal(absent.perHostConcurrency, DEFAULT_LIMITS.perHostConcurrency)
  // a finite but out-of-range value is clamped to the most conservative reading
  const clamped = resolveLimits({ globalConcurrency: -5, perHostIntervalMs: -1 })
  assert.equal(clamped.globalConcurrency, 1, "a negative pool cannot mean an unbounded one")
  assert.equal(clamped.perHostIntervalMs, 0)
})

test("concurrency cannot be raised past the hard ceiling", () => {
  assert.equal(resolveLimits({ globalConcurrency: 100_000 }).globalConcurrency, 256)
  assert.equal(resolveLimits({ perHostIntervalMs: 10_000_000 }).perHostIntervalMs, 60_000)
})

test("resolveLimits does not change the limits in force", () => {
  resetRateLimiter()
  configureLimits({ perHostConcurrency: 2 })
  resolveLimits({ perHostConcurrency: 99 })
  assert.equal(currentLimits().perHostConcurrency, 2, "asking must not be the same as setting")
  resetRateLimiter()
})

/* ---------------------------------------------------------- concurrency --- */

test("per-host concurrency is enforced across separate calls", async () => {
  resetRateLimiter()
  configureLimits({ perHostConcurrency: 2, globalConcurrency: 8 })
  let active = 0
  let peak = 0
  const work = async () => {
    active++
    peak = Math.max(peak, active)
    await sleep(20)
    active--
  }
  await Promise.all(Array.from({ length: 10 }, () => withHostSlot("a.test", work)))
  assert.ok(peak <= 2, `expected at most 2 in flight against one host, saw ${peak}`)
  assert.equal(active, 0, "every slot is released")
  resetRateLimiter()
})

test("two hosts get their own budget", async () => {
  resetRateLimiter()
  configureLimits({ perHostConcurrency: 2, globalConcurrency: 8 })
  const peak = new Map<string, number>([["a.test", 0], ["b.test", 0]])
  const seen = new Map<string, number>([["a.test", 0], ["b.test", 0]])
  const work = (host: string) => async () => {
    const n = (seen.get(host) ?? 0) + 1
    seen.set(host, n)
    peak.set(host, Math.max(peak.get(host) ?? 0, n))
    await sleep(15)
    seen.set(host, n - 1)
  }
  await Promise.all([
    ...Array.from({ length: 6 }, () => withHostSlot("a.test", work("a.test"))),
    ...Array.from({ length: 6 }, () => withHostSlot("b.test", work("b.test"))),
  ])
  assert.ok((peak.get("a.test") ?? 0) <= 2)
  assert.ok((peak.get("b.test") ?? 0) <= 2)
  resetRateLimiter()
})

test("the global budget caps the total, not just each host", async () => {
  resetRateLimiter()
  configureLimits({ perHostConcurrency: 10, globalConcurrency: 3 })
  let active = 0
  let peak = 0
  const work = async () => {
    active++
    peak = Math.max(peak, active)
    await sleep(15)
    active--
  }
  const hosts = ["a.test", "b.test", "c.test", "d.test", "e.test"]
  await Promise.all(hosts.flatMap((h) => [0, 1].map(() => withHostSlot(h, work))))
  assert.ok(peak <= 3, `expected the global cap of 3 to hold, saw ${peak}`)
  resetRateLimiter()
})

test("a release hands the slot to a waiter, so the cap is never overshot", async () => {
  resetRateLimiter()
  configureLimits({ perHostConcurrency: 1, globalConcurrency: 1 })
  const order: number[] = []
  const work = (i: number) => async () => {
    order.push(i)
    await sleep(5)
  }
  await Promise.all(Array.from({ length: 8 }, (_, i) => withHostSlot("a.test", work(i))))
  assert.equal(order.length, 8)
  assert.deepEqual([...order].sort((a, b) => a - b), [0, 1, 2, 3, 4, 5, 6, 7])
  resetRateLimiter()
})

test("a throwing operation still releases its slots", async () => {
  resetRateLimiter()
  configureLimits({ perHostConcurrency: 1, globalConcurrency: 1 })
  await assert.rejects(
    withHostSlot("a.test", async () => {
      throw new Error("boom")
    }),
    /boom/,
  )
  // if the slot leaked this would hang
  await withHostSlot("a.test", async () => undefined)
  const snap = rateLimitSnapshot()
  assert.equal(snap.globalActive, 0)
  assert.equal(snap.hosts.length, 0)
  resetRateLimiter()
})

/* --------------------------------------------------------------- pacing --- */

test("per-host interval spaces consecutive operations against one host", async () => {
  resetRateLimiter()
  configureLimits({ perHostConcurrency: 1, globalConcurrency: 4, perHostIntervalMs: 60 })
  const starts: number[] = []
  const work = async () => {
    starts.push(Date.now())
  }
  // The guarantee is on when operations are *permitted*, not on when the body
  // happens to get scheduled, so assert the span rather than each gap: three
  // operations at one per 60ms cannot complete inside 120ms.
  for (let i = 0; i < 3; i++) await withHostSlot("a.test", work)
  const span = starts[starts.length - 1]! - starts[0]!
  assert.ok(span >= 115, `expected ~120ms of spacing across 3 operations, saw ${span}ms`)
  resetRateLimiter()
})

test("rps is enforced as a sliding window", async () => {
  resetRateLimiter()
  configureLimits({ perHostConcurrency: 4, globalConcurrency: 4, perHostRps: 5 })
  assert.equal(effectiveIntervalMs(), 200, "5/s is 200ms apart")
  const starts: number[] = []
  const t0 = Date.now()
  await Promise.all(
    Array.from({ length: 5 }, () =>
      withHostSlot("a.test", async () => {
        starts.push(Date.now())
      }),
    ),
  )
  // 5 requests at 5/s cannot all land inside one second
  const span = starts[starts.length - 1]! - t0
  assert.ok(span >= 600, `5 requests at 5/s should span >= ~800ms, saw ${span}ms`)
  resetRateLimiter()
})

test("hostConcurrencyCap never exceeds the per-host limit", () => {
  resetRateLimiter()
  configureLimits({ perHostConcurrency: 4 })
  assert.equal(hostConcurrencyCap(64), 4, "a caller asking for 64 gets the engagement's 4")
  assert.equal(hostConcurrencyCap(2), 2)
  assert.equal(hostConcurrencyCap(undefined), 4)
  resetRateLimiter()
})

test("an exclusive host slot runs alone", async () => {
  resetRateLimiter()
  configureLimits({ perHostConcurrency: 8, globalConcurrency: 16 })
  let active = 0
  let peak = 0
  const scanner = async () => {
    active++
    peak = Math.max(peak, active)
    await sleep(25)
    active--
  }
  await Promise.all(Array.from({ length: 4 }, () => withExclusiveHostSlot("a.test", scanner)))
  assert.equal(peak, 1, "two scanners against one host is never the intent")
  resetRateLimiter()
})

test("an exclusive slot on one host does not block another host", async () => {
  resetRateLimiter()
  configureLimits({ perHostConcurrency: 4, globalConcurrency: 8 })
  const done: string[] = []
  await Promise.all([
    withExclusiveHostSlot("a.test", async () => {
      await sleep(30)
      done.push("a")
    }),
    withExclusiveHostSlot("b.test", async () => {
      await sleep(30)
      done.push("b")
    }),
  ])
  assert.equal(done.length, 2)
  resetRateLimiter()
})

/* ------------------------------------------------------------- reporting --- */

test("the snapshot reports what is actually in force", async () => {
  resetRateLimiter()
  configureLimits({ globalConcurrency: 3, perHostConcurrency: 2, perHostRps: 10 })
  const snap = rateLimitSnapshot()
  assert.equal(snap.globalConcurrency, 3)
  assert.equal(snap.perHostConcurrency, 2)
  assert.equal(snap.perHostRps, 10)
  assert.equal(snap.intervalMs, 100)
  resetRateLimiter()
})

test("describeLimits says when nothing is paced", () => {
  assert.match(describeLimitsOf(undefined), /no added delay/)
  assert.match(describeLimitsOf({ perHostRps: 2 }), /2 req\/s per host/)
})

test("describeLimits reports the limits in force", () => {
  resetRateLimiter()
  configureLimits({ globalConcurrency: 6, perHostConcurrency: 3, perHostIntervalMs: 500 })
  const text = describeLimits()
  assert.match(text, /6 concurrent total/)
  assert.match(text, /3 per host/)
  assert.match(text, /500ms between requests per host/)
  resetRateLimiter()
})

/* ------------------------------------------------------- scope plumbing --- */

test("normalizeLimits keeps only numeric pacing keys", () => {
  assert.equal(normalizeLimits(undefined), undefined)
  assert.equal(normalizeLimits("nope"), undefined)
  assert.equal(normalizeLimits({}), undefined)
  assert.deepEqual(normalizeLimits({ perHostRps: 2, junk: "x", perHostConcurrency: "4" }), { perHostRps: 2 })
})

test("a partial limits block stays partial, so one field can be overridden alone", () => {
  const one = normalizeScope({ limits: { perHostRps: 1 } } as Record<string, unknown>)
  assert.deepEqual(one.limits, { perHostRps: 1 })
  const merged = { ...DEFAULT_SCOPE.limits, ...one.limits }
  assert.deepEqual(merged, { perHostRps: 1 }, "nothing else is dragged in")
})

test("the scope template ships a conservative example", () => {
  const limits = scopeTemplate().limits!
  assert.ok(limits.globalConcurrency! < DEFAULT_LIMITS.globalConcurrency)
  assert.ok(limits.perHostIntervalMs! > 0)
  assert.ok(resolveLimits(limits).perHostConcurrency <= resolveLimits(limits).globalConcurrency)
})

test("scope limits survive a round trip through JSON", () => {
  const scope = { ...DEFAULT_SCOPE, limits: { globalConcurrency: 2, perHostIntervalMs: 1000 } }
  const parsed = normalizeScope(JSON.parse(JSON.stringify(scope)))
  assert.deepEqual(parsed.limits, { globalConcurrency: 2, perHostIntervalMs: 1000 })
})

test("resetRateLimiter clears in-flight state and limits", async () => {
  configureLimits({ globalConcurrency: 2 })
  await withHostSlot("a.test", async () => undefined)
  resetRateLimiter()
  assert.deepEqual(currentLimits(), DEFAULT_LIMITS)
  assert.equal(rateLimitSnapshot().hosts.length, 0)
})

/* ------------------------------------------------------------- wiring --- */

test("a scanner run takes the host's exclusive slot", async () => {
  resetRateLimiter()
  configureLimits({ globalConcurrency: 8, perHostConcurrency: 8 })
  const started = Date.now()
  // two 80ms processes against the same host must not overlap
  await Promise.all([
    runArgv("sh", ["-c", "sleep 0.08"], { host: "a.test", timeoutMs: 5000 }),
    runArgv("sh", ["-c", "sleep 0.08"], { host: "a.test", timeoutMs: 5000 }),
  ])
  const elapsed = Date.now() - started
  assert.ok(elapsed >= 150, `scanners should serialise per host, both finished in ${elapsed}ms`)
  resetRateLimiter()
})

test("an unserialised run stays parallel, so the slot is opt-in", async () => {
  resetRateLimiter()
  configureLimits({ globalConcurrency: 8, perHostConcurrency: 8 })
  // Compare against the same two commands run back-to-back. An absolute
  // millisecond ceiling is flaky on slow devices where process startup alone
  // can take longer than the command.
  const command = [process.execPath, ["-e", "setTimeout(() => {}, 200)"]] as const
  const serialStart = Date.now()
  await runArgv(command[0], [...command[1]], { timeoutMs: 5000 })
  await runArgv(command[0], [...command[1]], { timeoutMs: 5000 })
  const serial = Date.now() - serialStart

  const parallelStart = Date.now()
  await Promise.all([
    runArgv(command[0], [...command[1]], { timeoutMs: 5000 }),
    runArgv(command[0], [...command[1]], { timeoutMs: 5000 }),
  ])
  const parallel = Date.now() - parallelStart

  assert.ok(
    parallel < serial * 0.9,
    `runs without a host should overlap: serial ${serial}ms, parallel ${parallel}ms`,
  )
  resetRateLimiter()
})
