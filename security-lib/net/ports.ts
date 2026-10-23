/**
 * TCP connect port scanning with bounded concurrency and hard timeouts.
 *
 * This is a connect() scan: it opens a full TCP connection, which is noisier
 * than a SYN scan but needs no raw sockets or elevated privileges, and it can
 * never be mistaken for exploitation. Raw/stealth scanning is delegated to the
 * nmap adapter where the engagement authorizes it.
 */

import net from "node:net"
import { hostConcurrencyCap, withHostSlot } from "../ratelimit.ts"

export interface PortResult {
  port: number
  open: boolean
  service?: string
  banner?: string
  latencyMs: number
}

export interface ScanOptions {
  concurrency?: number
  timeoutMs?: number
  grabBanner?: boolean
  onProgress?: (state: { done: number; total: number; open: number }) => void
}

export const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
  3306, 3389, 5432, 5900, 5985, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
  9090, 9200, 10000, 11211, 27017, 5000, 5001, 7001, 8161,
]

const SERVICE_BY_PORT: Record<number, string> = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
  111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https",
  445: "smb", 993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
  3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 5985: "winrm",
  6379: "redis", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
  8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
  9090: "http-alt", 9200: "elasticsearch", 10000: "webmin", 11211: "memcached",
  27017: "mongodb", 5000: "http-alt", 5001: "https-alt", 7001: "weblogic",
  8161: "activemq",
}

const HTTP_LIKE = new Set([80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 10000, 5000, 5001, 7001, 8161])

/**
 * Services that speak first, so an HTTP probe would only confuse them (and us).
 * Everywhere else we send a HEAD request, because HTTP turns up on arbitrary
 * ports far more often than not and a bare connect tells us nothing.
 */
const SPEAKS_FIRST = new Set([21, 22, 23, 25, 110, 143, 993, 995, 1433, 3306, 5432, 5900, 6379, 27017])

export function shouldProbeHttp(port: number): boolean {
  return HTTP_LIKE.has(port) || !SPEAKS_FIRST.has(port)
}

/** Parse "80,443,8000-8010" into a sorted unique port list, bounded to 1..65535. */
export function parsePortSpec(spec: string): number[] {
  const out = new Set<number>()
  for (const part of spec.split(",")) {
    const p = part.trim()
    if (!p) continue
    const range = /^(\d{1,5})\s*-\s*(\d{1,5})$/.exec(p)
    if (range) {
      const lo = Number(range[1])
      const hi = Number(range[2])
      if (lo < 1 || hi > 65535 || hi < lo) continue
      const cap = Math.min(hi, lo + 4095) // never let a single token explode into a full sweep
      for (let i = lo; i <= cap; i++) out.add(i)
      continue
    }
    const n = Number(p)
    if (Number.isInteger(n) && n >= 1 && n <= 65535) out.add(n)
  }
  return [...out].sort((a, b) => a - b)
}

export function guessService(port: number, banner?: string): string | undefined {
  if (banner) {
    const b = banner.toLowerCase()
    if (/^ssh-/.test(b)) return "ssh"
    if (/^http\/1\.[01]/.test(b)) return port === 443 || port === 8443 ? "https" : "http"
    if (/smtp/.test(b)) return "smtp"
    if (/imap/.test(b)) return "imap"
    if (/pop3/.test(b)) return "pop3"
    if (/mysql/.test(b)) return "mysql"
    if (/redis/.test(b)) return "redis"
    if (/elastic/.test(b)) return "elasticsearch"
    if (/mongo/.test(b)) return "mongodb"
    if (/-ERR|denied/i.test(b)) return "unknown (responded)"
  }
  return SERVICE_BY_PORT[port]
}

function probePort(host: string, port: number, timeoutMs: number, grabBanner: boolean): Promise<PortResult> {
  const started = Date.now()
  return new Promise<PortResult>((resolve) => {
    let settled = false
    // Declared before the socket so `done` can always clear it.
    let timer: ReturnType<typeof setTimeout>
    const done = (r: PortResult) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        socket.destroy()
      } catch {
        /* ignore */
      }
      resolve(r)
    }

    // Listeners are attached BEFORE connect() is called. Attaching them after
    // net.connect() is a race: some runtimes (Bun) can complete a loopback
    // connection and emit "connect" before the handler is registered, which
    // made every port look closed.
    const socket = new net.Socket()
    socket.setNoDelay(true)
    let connected = false
    socket.once("connect", () => {
      connected = true
      const latencyMs = Date.now() - started
      if (!grabBanner) {
        done({ port, open: true, service: guessService(port), latencyMs })
        return
      }
      let banner = ""
      const bannerTimer = setTimeout(() => {
        done({ port, open: true, service: guessService(port, banner), banner: banner.trim() || undefined, latencyMs })
      }, Math.min(1500, timeoutMs))

      socket.on("data", (d: Buffer) => {
        banner += d.toString("utf8").slice(0, 512)
        if (banner.length > 32) {
          clearTimeout(bannerTimer)
          done({ port, open: true, service: guessService(port, banner), banner: banner.trim().slice(0, 512), latencyMs })
        }
      })
      socket.on("error", () => {
        clearTimeout(bannerTimer)
        done({ port, open: true, service: guessService(port), latencyMs })
      })

      if (shouldProbeHttp(port)) {
        try {
          socket.write(`HEAD / HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: NullByte-Security/1.0\r\n\r\n`)
        } catch {
          /* best effort */
        }
      }
    })
    // Once the TCP handshake succeeded the port IS open: a later error (e.g. a
    // TLS server rejecting our plaintext probe) or a banner timeout must not
    // downgrade that verdict to "closed".
    socket.once("error", () => done({ port, open: connected, service: connected ? guessService(port) : undefined, latencyMs: Date.now() - started }))
    socket.once("timeout", () => done({ port, open: connected, latencyMs: Date.now() - started }))

    timer = setTimeout(
      () => done({ port, open: connected, service: connected ? guessService(port) : undefined, latencyMs: Date.now() - started }),
      timeoutMs,
    )
    socket.connect({ host, port })
  })
}

/**
 * Scan `ports` on `host` with bounded concurrency. Returns only open ports.
 *
 * Each probe goes through the engagement's per-host budget, so a port scan and a
 * concurrent recon against the same host share one allowance rather than each
 * politely limiting itself.
 */
export async function scanPorts(host: string, ports: number[], opts: ScanOptions = {}): Promise<PortResult[]> {
  const concurrency = hostConcurrencyCap(opts.concurrency ?? 64)
  const timeoutMs = Math.max(200, Math.min(opts.timeoutMs ?? 1500, 10000))
  const grabBanner = opts.grabBanner ?? false
  const queue = [...ports]
  const results: PortResult[] = []
  let done = 0

  async function worker(): Promise<void> {
    for (;;) {
      const port = queue.shift()
      if (port === undefined) return
      const r = await withHostSlot(host, () => probePort(host, port, timeoutMs, grabBanner))
      if (r.open) results.push(r)
      done += 1
      opts.onProgress?.({ done, total: ports.length, open: results.length })
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, ports.length) }, () => worker()))
  return results.sort((a, b) => a.port - b.port)
}
