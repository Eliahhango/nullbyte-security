#!/usr/bin/env node
/**
 * Deliberately vulnerable lab target for exercising the NullByte security layer.
 *
 * Everything here is intentional and unsafe. It binds to loopback only.
 *   127.0.0.1:8080  "VulnerableApp" — reflected XSS, served .env, missing headers,
 *                   spoofed Server banner, directory listing, non-HttpOnly cookie
 *   127.0.0.1:8081  "admin" panel  — HTTP Basic (admin/admin), /debug env dump
 *   127.0.0.1:8443  HTTPS          — self-signed cert, no HSTS, legacy TLS allowed
 *
 * Usage:  node vulnerable-server.mjs        (Ctrl-C to stop)
 */

import http from "node:http"
import https from "node:https"
import { execFileSync } from "node:child_process"
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const HERE = dirname(fileURLToPath(import.meta.url))
const CERT_DIR = join(HERE, "certs")

/* ------------------------------------------------------------------ pages --- */

const PAGE = (title, body) => `<!doctype html>
<html><head><title>${title}</title></head>
<body><h1>${title}</h1>${body}
<hr><footer>VulnerableApp 1.0 — intentionally insecure lab target</footer></body></html>`

function app(req, res, port) {
  const url = new URL(req.url, `http://127.0.0.1:${port}`)
  const p = url.pathname

  // Spoofed, outdated banner + no security headers on purpose.
  res.setHeader("Server", "Apache/2.4.49 (Unix)")
  res.setHeader("X-Powered-By", "PHP/7.4.0")
  res.setHeader("Set-Cookie", `sid=${Math.random().toString(36).slice(2)}; Path=/`)

  if (p === "/") {
    res.writeHead(200, { "Content-Type": "text/html" })
    return res.end(
      PAGE(
        "VulnerableApp",
        `<ul>
           <li><a href="/search?q=hello">/search?q=</a> — reflected, unencoded</li>
           <li><a href="/api/user?id=1">/api/user?id=</a> — string-built query</li>
           <li><a href="/login">/login</a> — admin/admin123</li>
           <li><a href="/.env">/.env</a> — secrets in the webroot</li>
           <li><a href="/backup/">/backup/</a> — directory listing</li>
           <li><a href="/debug">/debug</a> — phpinfo-style leak</li>
         </ul>`,
      ),
    )
  }

  // Reflected XSS: the parameter is echoed into an HTML attribute and body.
  if (p === "/search") {
    const q = url.searchParams.get("q") ?? ""
    res.writeHead(200, { "Content-Type": "text/html" })
    return res.end(PAGE("Search", `<p>Results for <input value="${q}"></p><p>No results for ${q}.</p>`))
  }

  // Simulated SQL injection: the "query" is shown in the error text.
  if (p === "/api/user") {
    const id = url.searchParams.get("id") ?? "1"
    if (/['"]/.test(id)) {
      res.writeHead(500, { "Content-Type": "application/json" })
      return res.end(
        JSON.stringify({
          error: "SQLSTATE[42000]: Syntax error or access violation",
          query: `SELECT id,email,password_hash FROM users WHERE id = ${id}`,
          hint: "unhandled exception at /var/www/app/api/user.php:41",
        }),
      )
    }
    res.writeHead(200, { "Content-Type": "application/json" })
    return res.end(JSON.stringify({ id: Number(id) || 1, email: "admin@vulnerable.test", role: "admin" }))
  }

  // Credentials in the webroot.
  if (p === "/.env") {
    res.writeHead(200, { "Content-Type": "text/plain" })
    return res.end(
      [
        "APP_ENV=production",
        "APP_DEBUG=true",
        "DB_URI=postgres://appuser:S3cretLabPass@db.internal:5432/vulnerable",
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "STRIPE_SECRET_KEY=sk_live_51H8xxxxxxxxxxxxxxxxxxxxxxxx",
        "",
      ].join("\n"),
    )
  }

  if (p === "/login") {
    res.writeHead(200, { "Content-Type": "text/html" })
    return res.end(PAGE("Login", `<form method="post"><input name="u"><input name="p" type="password"><button>Sign in</button></form>`))
  }

  if (p === "/debug") {
    res.writeHead(200, { "Content-Type": "text/html" })
    return res.end(
      PAGE(
        "phpinfo()",
        `<pre>PHP Version 7.4.0
System: Linux vulnerable 5.10.0 #1 SMP
DOCUMENT_ROOT: /var/www/app
allow_url_include: On
disable_functions: (none)
SMTP: mail.vulnerable.test</pre>`,
      ),
    )
  }

  // Directory listing with a juicy filename.
  if (p === "/backup/") {
    res.writeHead(200, { "Content-Type": "text/html" })
    return res.end(
      PAGE(
        "Index of /backup/",
        `<pre><a href="db-dump-2026-09.sql">db-dump-2026-09.sql</a>
<a href="users.csv">users.csv</a>
<a href="app.tar.gz">app.tar.gz</a></pre>`,
      ),
    )
  }

  if (p === "/robots.txt") {
    res.writeHead(200, { "Content-Type": "text/plain" })
    return res.end("User-agent: *\nDisallow: /backup/\nDisallow: /.env\nDisallow: /debug\n")
  }

  res.writeHead(404, { "Content-Type": "text/html" })
  res.end(PAGE("404", `<p>Not found: ${p}</p>`))
}

/* ------------------------------------------------------------ admin :8081 --- */

function admin(req, res) {
  res.setHeader("Server", "nginx/1.14.0 (Ubuntu)")
  const auth = Buffer.from(String(req.headers.authorization ?? "").replace(/^Basic /, ""), "base64").toString()
  if (auth !== "admin:admin") {
    res.writeHead(401, { "WWW-Authenticate": 'Basic realm="admin"', "Content-Type": "text/html" })
    return res.end(PAGE("401", "<p>Authentication required (try admin/admin)</p>"))
  }
  if (req.url === "/debug") {
    res.writeHead(200, { "Content-Type": "application/json" })
    return res.end(JSON.stringify({ env: process.env, pid: process.pid, cwd: process.cwd(), node: process.version }, null, 2))
  }
  res.writeHead(200, { "Content-Type": "text/html" })
  res.end(PAGE("Admin console", "<p>Welcome, admin. <a href='/debug'>/debug</a></p>"))
}

/* ------------------------------------------------------------------ tls ----- */

function ensureCert() {
  const key = join(CERT_DIR, "lab.key")
  const crt = join(CERT_DIR, "lab.crt")
  if (existsSync(key) && existsSync(crt)) return { key: readFileSync(key), cert: readFileSync(crt) }
  mkdirSync(CERT_DIR, { recursive: true })
  execFileSync(
    "openssl",
    [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
      "-subj", "/CN=vulnerable.local/O=NullByte Lab",
      "-keyout", key, "-out", crt,
    ],
    { stdio: "ignore" },
  )
  return { key: readFileSync(key), cert: readFileSync(crt) }
}

/* ---------------------------------------------------------------- start ----- */

const httpServer = http.createServer((req, res) => app(req, res, 8080))
const adminServer = http.createServer(admin)
const tls = ensureCert()
const httpsServer = https.createServer({ ...tls, minVersion: "TLSv1.2" }, (req, res) => app(req, res, 8443))

httpServer.listen(8080, "127.0.0.1", () => console.log("http   → http://127.0.0.1:8080"))
adminServer.listen(8081, "127.0.0.1", () => console.log("admin  → http://127.0.0.1:8081 (admin/admin)"))
httpsServer.listen(8443, "127.0.0.1", () => console.log("https  → https://127.0.0.1:8443 (self-signed)"))

const shutdown = () => {
  console.log("\nstopping lab")
  for (const s of [httpServer, adminServer, httpsServer]) s.close()
  process.exit(0)
}
process.on("SIGINT", shutdown)
process.on("SIGTERM", shutdown)

// keep a copy of the leaked-looking artifacts on disk for sec_sast to find
try {
  writeFileSync(join(HERE, "leaked-config.php.bak"), "<?php $db_pass = 'S3cretLabPass'; $aws = 'AKIAIOSFODNN7EXAMPLE';\n")
} catch {
  /* non-fatal */
}
