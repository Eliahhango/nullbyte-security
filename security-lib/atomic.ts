/**
 * Crash-safe file writes.
 *
 * A direct `writeFileSync` onto a live file is not atomic. A crash, a full
 * disk, or a killed process can leave a truncated file behind — and for
 * engagement state that is unrecoverable, because the partial file fails to
 * parse and any reader that treats "unparseable" as "empty" will then overwrite
 * whatever survived.
 *
 * Every writer of engagement state goes through here instead: write a sibling
 * temporary file, flush it to disk, then `rename(2)` over the target.
 * `rename(2)` is atomic within a filesystem, so a reader sees either the
 * complete old file or the complete new one, and never a partial one.
 */

import { closeSync, fsyncSync, openSync, renameSync, unlinkSync, writeSync } from "node:fs"
import { basename, dirname, join } from "node:path"

/**
 * Replace `path` with `data`, atomically.
 *
 * The temp file is created in the same directory as the target so the rename
 * cannot cross a filesystem boundary. `fsync` before the rename is what makes
 * this durable as well as atomic: without it the rename can land while the
 * contents are still only in the page cache, and a power loss leaves a
 * correctly-named zero-length file.
 */
export function atomicWriteFile(path: string, data: string, mode = 0o600): void {
  const tmp = join(
    dirname(path),
    `.${basename(path)}.tmp-${process.pid}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
  )

  let fd: number | undefined
  try {
    fd = openSync(tmp, "w", mode)
    writeSync(fd, data)
    fsyncSync(fd)
    closeSync(fd)
    fd = undefined
    renameSync(tmp, path)
  } catch (e) {
    if (fd !== undefined) {
      try {
        closeSync(fd)
      } catch {
        /* the original error is the one that matters */
      }
    }
    try {
      unlinkSync(tmp)
    } catch {
      /* best effort: never mask the original error with a cleanup failure */
    }
    throw e
  }
}

/** Serialise `value` as indented JSON and replace `path` atomically. */
export function atomicWriteJson(path: string, value: unknown, mode = 0o600): void {
  atomicWriteFile(path, `${JSON.stringify(value, null, 2)}\n`, mode)
}
