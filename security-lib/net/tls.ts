/**
 * TLS inspection: negotiated protocol/cipher, certificate chain, validity and
 * SAN coverage. Uses node:tls directly so a self-signed certificate still
 * yields usable data (verification result is reported, not fatal).
 */

import tls from "node:tls"
import type { PeerCertificate } from "node:tls"

export interface CertInfo {
  subject: string
  issuer: string
  validFrom: string
  validTo: string
  serialNumber: string
  fingerprint256: string
  san: string[]
  selfSigned: boolean
}

export interface TlsResult {
  host: string
  port: number
  connected: boolean
  protocol?: string
  cipher?: string
  authorized?: boolean
  authorizationError?: string
  cert?: CertInfo
  daysUntilExpiry?: number
  expired?: boolean
  expiringSoon?: boolean
  hostnameMismatch?: boolean
  chain: Array<{ subject: string; issuer: string }>
  durationMs: number
  errors: string[]
}

function nameToString(name: Record<string, unknown> | undefined): string {
  if (!name) return ""
  return Object.entries(name)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("+") : String(v)}`)
    .join(", ")
}

function collectChain(leaf: PeerCertificate | undefined): Array<{ subject: string; issuer: string }> {
  const out: Array<{ subject: string; issuer: string }> = []
  let node = leaf
  const seen = new Set<string>()
  while (node && node.subject) {
    const s = nameToString(node.subject as unknown as Record<string, unknown>)
    if (seen.has(s)) break
    seen.add(s)
    out.push({ subject: s, issuer: nameToString(node.issuer as unknown as Record<string, unknown>) })
    const next = (node as unknown as { issuerCertificate?: PeerCertificate }).issuerCertificate
    if (!next || next === node) break
    node = next
  }
  return out
}

export interface TlsOptions {
  timeoutMs?: number
  /** accept untrusted certificates (authorized local labs) */
  insecure?: boolean
  servername?: string
}

export function tlsInspect(host: string, port = 443, opts: TlsOptions = {}): Promise<TlsResult> {
  const timeoutMs = opts.timeoutMs ?? 10000
  const started = Date.now()
  const errors: string[] = []

  return new Promise<TlsResult>((resolve) => {
    let settled = false
    const finish = (r: TlsResult) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        socket.destroy()
      } catch {
        /* already gone */
      }
      resolve(r)
    }

    const base: TlsResult = { host, port, connected: false, chain: [], durationMs: 0, errors }

    const socket = tls.connect(
      {
        host,
        port,
        servername: opts.servername ?? host,
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      () => {
        const cert = socket.getPeerCertificate(true) as PeerCertificate | undefined
        const authorized = socket.authorized
        const authorizationError = socket.authorizationError ? String(socket.authorizationError) : undefined

        let info: CertInfo | undefined
        let daysUntilExpiry: number | undefined
        let expired: boolean | undefined
        if (cert && cert.subject) {
          const validFrom = cert.valid_from ? new Date(cert.valid_from) : undefined
          const validTo = cert.valid_to ? new Date(cert.valid_to) : undefined
          daysUntilExpiry = validTo ? Math.floor((validTo.getTime() - Date.now()) / 86400000) : undefined
          expired = validTo ? validTo.getTime() < Date.now() : undefined
          info = {
            subject: nameToString(cert.subject as unknown as Record<string, unknown>),
            issuer: nameToString(cert.issuer as unknown as Record<string, unknown>),
            validFrom: validFrom ? validFrom.toISOString() : "",
            validTo: validTo ? validTo.toISOString() : "",
            serialNumber: cert.serialNumber ?? "",
            fingerprint256: cert.fingerprint256 ?? "",
            san: (cert.subjectaltname ?? "")
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
            selfSigned: nameToString(cert.subject as unknown as Record<string, unknown>) === nameToString(cert.issuer as unknown as Record<string, unknown>),
          }
        }

        const sanNames = (info?.san ?? [])
          .map((s) => s.replace(/^DNS:/, "").replace(/^IP Address:/, ""))
          .filter(Boolean)
        const hostnameMismatch =
          !!sanNames.length && !sanNames.some((n) => n === host || (n.startsWith("*.") && host.endsWith(n.slice(1))))

        finish({
          ...base,
          connected: true,
          protocol: socket.getProtocol() ?? undefined,
          cipher: socket.getCipher()?.name,
          authorized,
          authorizationError,
          cert: info,
          daysUntilExpiry,
          expired,
          expiringSoon: daysUntilExpiry !== undefined && daysUntilExpiry >= 0 && daysUntilExpiry <= 30,
          hostnameMismatch,
          chain: collectChain(cert),
          durationMs: Date.now() - started,
        })
      },
    )

    const timer = setTimeout(() => {
      errors.push(`TLS handshake timed out after ${timeoutMs}ms`)
      finish({ ...base, durationMs: Date.now() - started })
    }, timeoutMs)

    socket.on("error", (e) => {
      errors.push(e.message)
      finish({ ...base, durationMs: Date.now() - started })
    })
  })
}
