/**
 * HTML -> PDF via a detected external converter.
 *
 * Degrades honestly: when no converter works the caller gets the reason and an
 * install hint, never a .html file renamed to .pdf. A converter that is present
 * but broken (a CLI whose module is missing, a browser that cannot start) is
 * probed and skipped rather than trusted — presence on PATH is not capability.
 *
 * Conversion shells out with an argv array and no shell interpolation, so report
 * content can never reach a command line.
 */

import { spawnSync } from "node:child_process"
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

export interface PdfConverter {
  id: string
  path: string
  installHint: string
  /** cheap liveness probe; exit 0 means the tool actually runs */
  probeArgs: string[]
  /** the ARGUMENTS only (the binary is `path`), so nothing is shell-interpolated */
  argv(htmlPath: string, pdfPath: string, profileDir: string): string[]
}

/**
 * The copyright line stamped into the bottom of every page of every deliverable.
 * It reaches the PDF through the CSS `@page` margin boxes in `report.ts`, which
 * both WeasyPrint and current Chrome render.
 */
export const COPYRIGHT_TEXT = "© @EliTechWiz 2026 All Rights Reserved"

function which(bin: string): string | undefined {
  const r = spawnSync("sh", ["-c", `command -v ${JSON.stringify(bin)}`], { encoding: "utf8", timeout: 4000 })
  const p = (r.stdout ?? "").trim().split("\n")[0]
  return p && r.status === 0 ? p : undefined
}

/**
 * Priority order. weasyprint first: purpose-built HTML->PDF renderer with full
 * print CSS and no browser sandbox to fight. Chrome is the fallback; it needs a
 * throwaway profile and `--no-sandbox` to run headless as root, and it renders
 * the report's `@page` margin boxes, so the per-page footer survives.
 */
const CANDIDATES: Omit<PdfConverter, "path">[] = [
  {
    id: "weasyprint",
    installHint: "pipx install weasyprint   (or: apt-get install -y weasyprint)",
    probeArgs: ["--version"],
    argv: (html, pdf) => [html, pdf],
  },
  {
    id: "google-chrome",
    installHint: "apt-get install -y google-chrome-stable",
    probeArgs: ["--version"],
    argv: (html, pdf, profile) => [
      "--headless=new",
      "--disable-gpu",
      "--no-sandbox",
      "--no-pdf-header-footer",
      "--virtual-time-budget=5000",
      `--user-data-dir=${profile}`,
      `--print-to-pdf=${pdf}`,
      `file://${html}`,
    ],
  },
  {
    id: "chromium",
    installHint: "apt-get install -y chromium",
    probeArgs: ["--version"],
    argv: (html, pdf, profile) => [
      "--headless=new",
      "--disable-gpu",
      "--no-sandbox",
      "--no-pdf-header-footer",
      "--virtual-time-budget=5000",
      `--user-data-dir=${profile}`,
      `--print-to-pdf=${pdf}`,
      `file://${html}`,
    ],
  },
]

/** Every candidate whose binary exists on PATH. */
function present(): PdfConverter[] {
  const out: PdfConverter[] = []
  for (const c of CANDIDATES) {
    const p = which(c.id)
    if (p && existsSync(p)) out.push({ ...c, path: p })
  }
  return out
}

const probeCache = new Map<string, boolean>()

/** Does the binary actually run? (presence is not capability) */
export function converterWorks(c: PdfConverter): boolean {
  const hit = probeCache.get(c.path)
  if (hit !== undefined) return hit
  const r = spawnSync(c.path, c.probeArgs, { encoding: "utf8", timeout: 15_000 })
  const ok = r.status === 0
  probeCache.set(c.path, ok)
  return ok
}

const renderCache = new Map<string, boolean>()

/**
 * Does the converter actually render a PDF, not just print a version?
 *
 * A stale Chromium that answers `--version` but cannot start headless used to
 * make the PDF test fail on an otherwise healthy device. Presence and a version
 * banner are not capability; probe the real output once and cache it.
 */
function converterRenders(c: PdfConverter): boolean {
  const hit = renderCache.get(c.path)
  if (hit !== undefined) return hit

  let work: string | undefined
  let ok = false
  try {
    work = mkdtempSync(join(tmpdir(), "nullbyte-pdf-probe-"))
    const res = tryConvert(
      c,
      "<!doctype html><html><body><h1>NullByte PDF probe</h1><p>render capability check</p></body></html>",
      join(work, "probe.pdf"),
    )
    ok = res.ok
  } catch {
    ok = false
  } finally {
    if (work) {
      try {
        rmSync(work, { recursive: true, force: true })
      } catch {
        /* best effort */
      }
    }
  }
  renderCache.set(c.path, ok)
  return ok
}

/** The first converter that is installed, runs, and renders a real PDF. */
export function findPdfConverter(force = false): PdfConverter | null {
  if (force) {
    probeCache.clear()
    renderCache.clear()
  }
  for (const c of present()) {
    if (converterWorks(c) && converterRenders(c)) return c
  }
  return null
}

export function pdfCapabilityLine(): string {
  const c = findPdfConverter()
  if (c) return `pdf: ${c.id} (${c.path})`
  const broken = present().map((x) => x.id)
  const tail = broken.length ? ` — installed but not working: ${broken.join(", ")}` : ""
  return `pdf: unavailable — install one of: ${CANDIDATES.map((x) => x.id).join(", ")}${tail}`
}

export type PdfResult =
  | { ok: true; path: string; converter: string }
  | { ok: false; reason: string; hint?: string }

/**
 * Render `html` to `pdfPath`, trying each working converter in order. Returns a
 * discriminated result; never throws for an environmental problem.
 */
export function htmlToPdf(html: string, pdfPath: string): PdfResult {
  const installed = present()
  if (!installed.length) {
    return {
      ok: false,
      reason: "no HTML-to-PDF converter is installed",
      hint: `install one of: ${CANDIDATES.map((c) => `${c.id} (${c.installHint})`).join("; ")}`,
    }
  }

  const failures: string[] = []
  for (const converter of installed) {
    if (!converterWorks(converter)) {
      failures.push(`${converter.id}: present at ${converter.path} but does not run`)
      continue
    }
    const res = tryConvert(converter, html, pdfPath)
    if (res.ok) return res
    failures.push(res.reason)
  }

  return {
    ok: false,
    reason: failures.join(" | "),
    hint: `install one of: ${CANDIDATES.map((c) => `${c.id} (${c.installHint})`).join("; ")}`,
  }
}

function tryConvert(converter: PdfConverter, html: string, pdfPath: string): PdfResult {
  let work: string
  try {
    work = mkdtempSync(join(tmpdir(), "nullbyte-pdf-"))
  } catch (e: any) {
    return { ok: false, reason: `could not create a temp dir: ${e?.message ?? e}` }
  }

  const htmlPath = join(work, "report.html")
  const profile = join(work, "profile")
  try {
    writeFileSync(htmlPath, html, { mode: 0o600 })
    const r = spawnSync(converter.path, converter.argv(htmlPath, pdfPath, profile), { encoding: "utf8", timeout: 120_000 })

    if (!existsSync(pdfPath)) {
      const detail = `${r.stderr ?? ""}`.trim().split("\n").slice(-3).join(" | ").slice(0, 300)
      return {
        ok: false,
        reason: `${converter.id} did not produce a PDF (exit ${r.status ?? "null"}${r.error ? `, ${r.error.message}` : ""})${detail ? `: ${detail}` : ""}`,
      }
    }
    // a converter can exit 0 and still emit a stub; reject implausibly small output
    const size = statSync(pdfPath).size
    if (size < 512) {
      rmSync(pdfPath, { force: true })
      return { ok: false, reason: `${converter.id} produced a ${size}-byte PDF (not a real render)` }
    }
    const head = readFileSync(pdfPath).subarray(0, 5).toString("latin1")
    if (head !== "%PDF-") {
      rmSync(pdfPath, { force: true })
      return { ok: false, reason: `${converter.id} output is not a PDF (bad magic bytes)` }
    }
    return { ok: true, path: pdfPath, converter: converter.id }
  } finally {
    try {
      rmSync(work, { recursive: true, force: true })
    } catch {
      /* best effort */
    }
  }
}
