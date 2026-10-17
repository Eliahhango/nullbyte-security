/**
 * HTTP/HTTPS probing with MANUAL redirect handling.
 *
 * Redirects are followed one hop at a time so every hop can be re-validated
 * against the authorized scope. A redirect to an out-of-scope host stops the
 * probe instead of silently fetching third-party infrastructure — this is the
 * "redirect and out-of-scope handling" control.
 *
 * Built on node:http/node:https rather than fetch so TLS verification can be
 * relaxed only for explicitly authorized local labs.
 */

import http from "node:http"
import https from "node:https"

export interface HttpHop {
  url: string
  status: number
  location?: string
}

export interface HttpProbeResult {
  requestedUrl: string
  finalUrl: string
  status: number
  statusText: string
  headers: Record<string, string>
  hops: HttpHop[]
  title?: string
  bodySnippet?: string
  bodyBytes: number
  durationMs: number
  /** set when a hop was refused by policy */
  stopped?: { at: string; reason: string }
  errors: string[]
  /**
   * Reconstructed HTTP transcript for every hop, status line through body.
   *
   * Reconstructed, not the literal wire bytes: header order and duplicates come
   * from `rawHeaders`, which is faithful, but a chunked or gzip body is decoded
   * by Node before we see it. Used to archive a response as evidence, and
   * labelled as a reconstruction wherever it is stored.
   */
  transcript?: string
}

export interface HttpProbeOptions {
  timeoutMs?: number
  maxRedirects?: number
  method?: string
  userAgent?: string
  allowBody?: boolean
  maxBodyBytes?: number
  /** relax TLS verification — only pass true for authorized local labs */
  insecure?: boolean
  /** per-hop authorization; returning allowed:false aborts the probe */
  validate?: (url: string) => { allowed: boolean; reason: string }
}

const DEFAULT_UA = "NullByte-Security/1.0 (authorized assessment)"

interface RawResponse {
  status: number
  statusText: string
  headers: Record<string, string>
  body: string
  bytes: number
  transcript: string
}

function requestOnce(urlStr: string, opts: HttpProbeOptions): Promise<RawResponse> {
  const u = new URL(urlStr)
  const isHttps = u.protocol === "https:"
  const lib = isHttps ? https : http
  const timeoutMs = opts.timeoutMs ?? 10000
  const maxBodyBytes = opts.maxBodyBytes ?? 64 * 1024
  const allowBody = opts.allowBody ?? true

  return new Promise<RawResponse>((resolve, reject) => {
    const req = lib.request(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (isHttps ? 443 : 80),
        path: `${u.pathname}${u.search}`,
        method: opts.method ?? "GET",
        headers: {
          "User-Agent": opts.userAgent ?? DEFAULT_UA,
          Accept: "*/*",
          Connection: "close",
        },
        rejectUnauthorized: opts.insecure ? false : true,
        timeout: timeoutMs,
      },
      (res) => {
        const headers: Record<string, string> = {}
        for (const [k, v] of Object.entries(res.headers)) {
          headers[k] = Array.isArray(v) ? v.join(", ") : String(v ?? "")
        }
        let body = ""
        let bytes = 0
        res.on("data", (chunk: Buffer) => {
          bytes += chunk.length
          if (allowBody && bytes <= maxBodyBytes) body += chunk.toString("utf8")
        })
        res.on("end", () => {
          const status = res.statusCode ?? 0
          const statusText = res.statusMessage ?? ""
          // rawHeaders preserves wire order and duplicate headers, which the
          // joined `headers` object destroys — worth keeping for a transcript
          const pairs: string[] = []
          const raw = res.rawHeaders ?? []
          for (let i = 0; i < raw.length; i += 2) pairs.push(`${raw[i]}: ${raw[i + 1]}`)
          const truncated = bytes > body.length
          const transcript =
            `HTTP/1.1 ${status} ${statusText}\r\n${pairs.join("\r\n")}\r\n\r\n${body}` +
            (truncated ? `\n\n... [body truncated: ${body.length} of ${bytes} bytes retained] ...\n` : "")
          resolve({ status, statusText, headers, body, bytes, transcript })
        })
        res.on("error", reject)
      },
    )
    req.on("timeout", () => {
      req.destroy(new Error(`timeout after ${timeoutMs}ms`))
    })
    req.on("error", reject)
    req.end()
  })
}

function extractTitle(html: string): string | undefined {
  const m = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(html)
  return m ? m[1].replace(/\s+/g, " ").trim() : undefined
}

export async function httpProbe(url: string, opts: HttpProbeOptions = {}): Promise<HttpProbeResult> {
  const started = Date.now()
  const maxRedirects = opts.maxRedirects ?? 5
  const hops: HttpHop[] = []
  const errors: string[] = []
  let current = url
  let last: RawResponse | null = null
  const transcripts: string[] = []

  for (let i = 0; i <= maxRedirects; i++) {
    const check = opts.validate?.(current)
    if (check && !check.allowed) {
      return {
        requestedUrl: url,
        finalUrl: current,
        status: 0,
        statusText: "blocked",
        headers: {},
        hops,
        bodyBytes: 0,
        durationMs: Date.now() - started,
        stopped: { at: current, reason: check.reason },
        errors,
        transcript: transcripts.length ? transcripts.join("\n\n") : undefined,
      }
    }

    let res: RawResponse
    try {
      res = await requestOnce(current, opts)
    } catch (e) {
      errors.push(`${current}: ${e instanceof Error ? e.message : String(e)}`)
      return {
        requestedUrl: url,
        finalUrl: current,
        status: 0,
        statusText: "error",
        headers: {},
        hops,
        bodyBytes: 0,
        durationMs: Date.now() - started,
        errors,
        transcript: transcripts.length ? transcripts.join("\n\n") : undefined,
      }
    }
    last = res
    transcripts.push(res.transcript)

    const location = res.headers.location
    hops.push({ url: current, status: res.status, location })
    if (res.status >= 300 && res.status < 400 && location) {
      let next: string
      try {
        next = new URL(location, current).toString()
      } catch {
        errors.push(`unparseable redirect target: ${location}`)
        break
      }
      if (i === maxRedirects) {
        errors.push(`exceeded ${maxRedirects} redirects`)
        break
      }
      current = next
      continue
    }
    break
  }

  const final = last
  return {
    requestedUrl: url,
    finalUrl: current,
    status: final?.status ?? 0,
    statusText: final?.statusText ?? "",
    headers: final?.headers ?? {},
    hops,
    title: final ? extractTitle(final.body) : undefined,
    bodySnippet: final && opts.allowBody !== false ? final.body.slice(0, 4096) : undefined,
    bodyBytes: final?.bytes ?? 0,
    durationMs: Date.now() - started,
    errors,
    transcript: transcripts.length ? transcripts.join("\n\n") : undefined,
  }
}
