import test from "node:test"
import assert from "node:assert/strict"
import { formatElapsed, startProgress } from "../progress.ts"

function fakeStream(isTTY = true) {
  let output = ""
  return {
    isTTY,
    write(chunk: string) {
      output += chunk
      return true
    },
    get output() {
      return output
    },
  }
}

test("progress renders the Clack guide, spinner and success marker", () => {
  const stream = fakeStream()
  const progress = startProgress("nuclei app.test", {
    stream: stream as unknown as NodeJS.WriteStream,
    enabled: true,
    now: () => 1000,
    intervalMs: 100_000,
  })
  progress.update("nuclei app.test · 2 hits")
  progress.succeed("nuclei app.test · 2 hits · 12s")
  progress.stop()

  assert.match(stream.output, /│/)
  assert.match(stream.output, /nuclei app\.test/)
  assert.match(stream.output, /◇/)
})

test("progress renders failures with the error marker", () => {
  const stream = fakeStream()
  const progress = startProgress("nmap app.test", {
    stream: stream as unknown as NodeJS.WriteStream,
    enabled: true,
    intervalMs: 100_000,
  })
  progress.fail("nmap app.test · timed out")
  progress.stop()

  assert.match(stream.output, /■/)
  assert.match(stream.output, /timed out/)
})

test("progress is silent when disabled or not a TTY", () => {
  for (const [enabled, isTTY] of [[false, true], [true, false], [false, false]] as const) {
    const stream = fakeStream(isTTY)
    const progress = startProgress("quiet", {
      stream: stream as unknown as NodeJS.WriteStream,
      enabled: enabled && isTTY,
      intervalMs: 100_000,
    })
    progress.update("quiet")
    progress.succeed("quiet")
    progress.stop()
    assert.equal(stream.output, "")
  }
})

test("NULLBYTE_NO_PROGRESS disables the live line", () => {
  const stream = fakeStream()
  process.env.NULLBYTE_NO_PROGRESS = "1"
  try {
    const progress = startProgress("quiet", {
      stream: stream as unknown as NodeJS.WriteStream,
      intervalMs: 100_000,
    })
    progress.succeed("quiet")
    assert.equal(stream.output, "")
  } finally {
    delete process.env.NULLBYTE_NO_PROGRESS
  }
})

test("a chat harness suppresses the live line by default, even on a TTY", () => {
  const previous = process.env.OPENCODE
  process.env.OPENCODE = "1"
  try {
    const stream = fakeStream()
    const progress = startProgress("recon example.com", {
      stream: stream as unknown as NodeJS.WriteStream,
      intervalMs: 100_000,
    })
    progress.update("recon example.com · probing HTTP")
    progress.succeed("recon example.com complete")
    progress.stop()
    assert.equal(stream.output, "", "stderr animation must not pollute the chat interface")
  } finally {
    if (previous === undefined) delete process.env.OPENCODE
    else process.env.OPENCODE = previous
  }
})

test("NULLBYTE_PROGRESS=1 forces the live line on when explicitly requested", () => {
  const previous = process.env.NULLBYTE_PROGRESS
  process.env.NULLBYTE_PROGRESS = "1"
  try {
    const stream = fakeStream()
    const progress = startProgress("forced", {
      stream: stream as unknown as NodeJS.WriteStream,
      intervalMs: 100_000,
    })
    progress.succeed("forced")
    assert.match(stream.output, /forced/)
  } finally {
    if (previous === undefined) delete process.env.NULLBYTE_PROGRESS
    else process.env.NULLBYTE_PROGRESS = previous
  }
})

test("formatElapsed shows seconds and minutes", () => {
  assert.equal(formatElapsed(999), "[0s]")
  assert.equal(formatElapsed(12_000), "[12s]")
  assert.equal(formatElapsed(61_000), "[1m 1s]")
})
