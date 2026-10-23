/**
 * Display branding. The runtime depends on `opencode` identifiers, provider
 * ids and package names, so the internal name is never renamed. Every string
 * that reaches the operator — tool titles, tool output, permission prompts and
 * report provenance — passes through here first.
 */
export const BRAND = "NullByte"
export const BRAND_LOWER = "nullbyte"

const BRAND_WORD = /\bopencode\b/gi

export function scrubBrand(text: string): string {
  return text.replace(BRAND_WORD, (word) => {
    if (word === word.toUpperCase()) return BRAND_LOWER.toUpperCase()
    if (word[0] === word[0]?.toUpperCase()) return BRAND
    return BRAND_LOWER
  })
}

/** Scrub strings inside metadata objects without changing their shape. */
export function scrubBrandDeep<T>(value: T): T {
  if (typeof value === "string") return scrubBrand(value) as T
  if (Array.isArray(value)) return value.map((entry) => scrubBrandDeep(entry)) as T
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>
    for (const key of Object.keys(record)) record[key] = scrubBrandDeep(record[key])
  }
  return value
}
