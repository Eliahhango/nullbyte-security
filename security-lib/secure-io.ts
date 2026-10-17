/**
 * The store's read/write boundary, made encryption-aware.
 *
 * Everything that persists engagement state goes through here so encryption is a
 * property of the store rather than of each caller. Reads accept both an
 * envelope and plaintext, which is what makes enabling encryption
 * non-destructive: a half-migrated store still reads.
 *
 * What the hash in an evidence record covers is decided here. It is taken over
 * the **plaintext payload**, so:
 *   - with encryption off it is still exactly the bytes on disk, as before;
 *   - with encryption on it survives a re-encrypt or a key rotation, which
 *     hashing the ciphertext would not — a new IV would make every stored
 *     artifact look tampered with.
 */

import { appendFileSync, closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs"
import { atomicWriteFile } from "./atomic.ts"
import { open as openValue, seal } from "./crypto.ts"

/** Read a store file, decrypting if it is sealed. Absent files yield undefined. */
export function readProtectedFile(path: string): string | undefined {
  if (!existsSync(path)) return undefined
  return openValue(readFileSync(path, "utf8"))
}

/** Read a store file that must exist, with the caller's error for absence. */
export function readProtectedFileOrThrow(path: string, missing: () => Error): string {
  const text = readProtectedFile(path)
  if (text === undefined) throw missing()
  return text
}

/** Atomically write a store file, sealing it when a key is configured. */
export function writeProtectedFile(path: string, plaintext: string, mode = 0o600): void {
  atomicWriteFile(path, seal(plaintext), mode)
}

/** Append one sealed line to an append-only store. Durable before returning. */
export function appendProtectedLine(path: string, plaintextLine: string, mode = 0o600): void {
  const line = seal(plaintextLine.replace(/\n+$/, ""))
  const fd = openSync(path, "a", mode)
  try {
    writeSync(fd, `${line}\n`)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}

/**
 * Read an append-only store line by line, decrypting each line independently.
 *
 * Lines are returned with their 1-based position so a caller can report which
 * one failed rather than "the file is corrupt".
 */
export function readProtectedLines(path: string): { line: number; text: string }[] {
  if (!existsSync(path)) return []
  const out: { line: number; text: string }[] = []
  readFileSync(path, "utf8")
    .split("\n")
    .forEach((raw, i) => {
      if (!raw) return
      out.push({ line: i + 1, text: openValue(raw) })
    })
  return out
}
