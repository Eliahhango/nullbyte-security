type ProgressStream = Pick<NodeJS.WriteStream, "write" | "isTTY">

export interface ProgressOptions {
  stream?: ProgressStream
  enabled?: boolean
  intervalMs?: number
  timer?: boolean
  now?: () => number
  noColor?: boolean
}

export interface Progress {
  readonly enabled: boolean
  update(message: string): void
  succeed(message?: string): void
  fail(message?: string): void
  stop(): void
}

const UNICODE_FRAMES = ["◒", "◐", "◓", "◑"]
const ASCII_FRAMES = ["•", "o", "O", "0"]

function localeSupportsUnicode(): boolean {
  const locale = (process.env.LC_ALL || process.env.LC_CTYPE || process.env.LANG || "").toLowerCase()
  if (process.env.NULLBYTE_ASCII === "1") return false
  if (!locale) return true
  return locale.includes("utf")
}

function colorEnabled(opts: ProgressOptions): boolean {
  if (opts.noColor || process.env.NO_COLOR) return false
  if ((process.env.TERM || "") === "dumb") return false
  return true
}

export function formatElapsed(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000))
  const mins = Math.floor(seconds / 60)
  const rest = seconds % 60
  return mins > 0 ? `[${mins}m ${rest}s]` : `[${rest}s]`
}

class LiveProgress implements Progress {
  readonly enabled: boolean
  private readonly stream: ProgressStream
  private readonly intervalMs: number
  private readonly timer: boolean
  private readonly now: () => number
  private readonly frames: string[]
  private readonly color: boolean
  private readonly startedAt: number
  private message: string
  private frame = 0
  private interval?: ReturnType<typeof setInterval>
  private finished = false
  private readonly onExit = () => this.stop()

  constructor(message: string, opts: ProgressOptions = {}) {
    this.stream = opts.stream ?? process.stderr
    this.enabled = opts.enabled ?? (Boolean(this.stream.isTTY) && process.env.NULLBYTE_NO_PROGRESS !== "1")
    this.intervalMs = opts.intervalMs ?? 80
    this.timer = opts.timer ?? false
    this.now = opts.now ?? Date.now
    this.frames = localeSupportsUnicode() ? UNICODE_FRAMES : ASCII_FRAMES
    this.color = colorEnabled(opts)
    this.startedAt = this.now()
    this.message = message

    if (!this.enabled) return
    process.once("exit", this.onExit)
    this.write(`${this.gray()}│${this.reset()}\n`)
    this.render()
    this.interval = setInterval(() => this.render(), this.intervalMs)
    this.interval.unref?.()
  }

  update(message: string): void {
    if (this.finished) return
    this.message = message
  }

  succeed(message = this.message): void {
    this.finish("◇", "32", message)
  }

  fail(message = this.message): void {
    this.finish("■", "31", message)
  }

  stop(): void {
    if (this.finished) return
    this.finished = true
    if (this.interval) clearInterval(this.interval)
    process.removeListener("exit", this.onExit)
    if (this.enabled) this.write("\r\x1b[2K")
  }

  private finish(symbol: string, color: string, message: string): void {
    if (this.finished) return
    this.finished = true
    if (this.interval) clearInterval(this.interval)
    process.removeListener("exit", this.onExit)
    if (!this.enabled) return
    this.write(`\r\x1b[2K${this.wrap(color, symbol)}  ${message}\n`)
  }

  private render(): void {
    if (!this.enabled || this.finished) return
    const frame = this.frames[this.frame % this.frames.length]
    const dots = this.timer ? "" : ".".repeat(this.frame % 4)
    const elapsed = this.timer ? ` ${this.gray()}${formatElapsed(this.now() - this.startedAt)}${this.reset()}` : ""
    this.write(`\r\x1b[2K${this.wrap("35", frame)}  ${this.message}${dots}${elapsed}`)
    this.frame += 1
  }

  private write(chunk: string): void {
    try {
      this.stream.write(chunk)
    } catch {
      /* the terminal may have gone away; scanning must continue */
    }
  }

  private wrap(color: string, value: string): string {
    if (!this.color) return value
    return `\x1b[${color}m${value}${this.reset()}`
  }

  private gray(): string {
    return this.color ? "\x1b[90m" : ""
  }

  private reset(): string {
    return this.color ? "\x1b[0m" : ""
  }
}

export function startProgress(message: string, opts: ProgressOptions = {}): Progress {
  return new LiveProgress(message, opts)
}
