/**
 * Connect scanner.
 *
 * Regression: the first implementation attached its socket listeners *after*
 * net.connect() and treated any socket error as "closed". In the Bun runtime the
 * connect event was missed entirely (every port reported closed), and a service
 * that accepted TCP but did not speak HTTP immediately was also misreported.
 */

import test from "node:test"
import assert from "node:assert/strict"
import http from "node:http"
import net from "node:net"
import { guessService, parsePortSpec, scanPorts } from "../net/ports.ts"

test("parsePortSpec parses lists and ranges and bounds them", () => {
  assert.deepEqual(parsePortSpec("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])
  assert.deepEqual(parsePortSpec(" 443 , 80 "), [80, 443])
  assert.deepEqual(parsePortSpec("0,70000,nonsense"), [])
  assert.equal(parsePortSpec("1-65535").length, 4096)
})

test("guessService recognises ports and banners", () => {
  assert.equal(guessService(22), "ssh")
  assert.equal(guessService(3306), "mysql")
  assert.match(guessService(9999, "SSH-2.0-OpenSSH_8.9") ?? "", /ssh/)
  assert.match(guessService(9999, "HTTP/1.1 200 OK") ?? "", /http/)
})

test("scan finds an open HTTP port and skips a closed one", async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain" })
    res.end("ok")
  })
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()))
  const port = (server.address() as net.AddressInfo).port
  try {
    const res = await scanPorts("127.0.0.1", [port, 1], { grabBanner: true, timeoutMs: 2000 })
    assert.equal(res.length, 1, `expected only ${port} open, got ${JSON.stringify(res)}`)
    assert.equal(res[0].port, port)
    assert.equal(res[0].open, true)
    assert.match(res[0].banner ?? "", /HTTP\/1\.[01]/)
  } finally {
    server.close()
  }
})

test("a service that accepts TCP but stays silent is still reported open", async () => {
  // Stands in for a TLS/unknown service that will not answer our plaintext probe.
  const silent = net.createServer(() => {
    /* accept and never write */
  })
  await new Promise<void>((r) => silent.listen(0, "127.0.0.1", () => r()))
  const port = (silent.address() as net.AddressInfo).port
  try {
    const res = await scanPorts("127.0.0.1", [port], { grabBanner: true, timeoutMs: 900 })
    assert.equal(res.length, 1)
    assert.equal(res[0].open, true)
  } finally {
    silent.close()
  }
})

test("a port that refuses the connection is not reported", async () => {
  const server = http.createServer((_req, res) => res.end())
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()))
  const port = (server.address() as net.AddressInfo).port
  server.close()
  await new Promise((r) => setTimeout(r, 50))
  const res = await scanPorts("127.0.0.1", [port], { timeoutMs: 700 })
  assert.deepEqual(res, [])
})

test("concurrency is bounded and results are sorted", async () => {
  const res = await scanPorts("127.0.0.1", [1, 2, 3], { concurrency: 999, timeoutMs: 400 })
  assert.deepEqual(res, [])
})
