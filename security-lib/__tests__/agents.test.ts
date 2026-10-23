import test from "node:test"
import assert from "node:assert/strict"
import {
  formatAgentPlan,
  parseAgentPlan,
  runAgentPlan,
  validateAgentTasks,
  type AgentClient,
  type AgentInfo,
} from "../agents.ts"
import { SECURITY_TOOL_IDS, buildSecurityTools } from "../tools/index.ts"

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

type Behaviour = {
  output?: string
  error?: string
  delay?: number
  hang?: boolean
  /** fail this many times before returning output */
  failFirst?: number
}

function fakeClient(options: {
  agents?: AgentInfo[]
  behaviour?: Record<string, Behaviour>
  parentModel?: { providerID: string; modelID: string }
} = {}) {
  const created: Array<{ id: string; title: string; parentID?: string }> = []
  const prompts: Array<{ id: string; title: string; agent?: string; prompt: string; tools?: Record<string, boolean>; model?: unknown }> = []
  const aborts: string[] = []
  const behaviour = options.behaviour ?? {}
  let sequence = 0
  let active = 0
  let maxActive = 0
  const attempts = new Map<string, number>()

  const client: AgentClient = {
    app: {
      async agents() {
        return { data: options.agents ?? [{ name: "general", mode: "subagent" }] }
      },
    },
    session: {
      async messages() {
        return options.parentModel ? { data: [{ info: { role: "user", model: options.parentModel } }] } : { data: [] }
      },
      async create(input: any) {
        sequence += 1
        const id = `ses_${sequence}`
        created.push({ id, title: input.body?.title ?? "", parentID: input.body?.parentID })
        return { data: { id } }
      },
      async prompt(input: any) {
        const parent = created.find((entry) => entry.id === input.path.id)!
        const part = input.body?.parts?.[0]
        prompts.push({
          id: parent.id,
          title: parent.title,
          agent: input.body?.agent,
          prompt: part?.text ?? "",
          tools: input.body?.tools,
          model: input.body?.model,
        })
        const spec = behaviour[parent.title] ?? {}
        const seen = (attempts.get(parent.title) ?? 0) + 1
        attempts.set(parent.title, seen)
        active += 1
        maxActive = Math.max(maxActive, active)
        try {
          if (spec.hang) await new Promise<never>(() => {})
          await delay(spec.delay ?? 5)
          if (spec.error && seen <= (spec.failFirst ?? 0)) return { error: { message: spec.error } }
          if (spec.error && spec.failFirst === undefined) return { error: { message: spec.error } }
          return { data: { parts: [{ type: "text", text: spec.output ?? `result:${parent.title}` }] } }
        } finally {
          active -= 1
        }
      },
      async abort(input: any) {
        aborts.push(input.path.id)
        return { data: true }
      },
    },
  }

  return { client, created, prompts, aborts, stats: () => ({ maxActive }) }
}

const task = (id: string, over: Record<string, unknown> = {}) => ({
  id,
  title: id.toUpperCase(),
  prompt: `do ${id}`,
  ...over,
})

test("validation rejects duplicate ids, unknown dependencies, cycles and primary agents", () => {
  const agents: AgentInfo[] = [
    { name: "general", mode: "subagent" },
    { name: "build", mode: "primary" },
  ]
  const base = validateAgentTasks([task("a"), task("b", { depends_on: ["missing"] })], agents)
  assert.match(base.problems.join("\n"), /unknown dependency 'missing'/)

  const duplicate = validateAgentTasks([task("a"), task("a")], agents)
  assert.match(duplicate.problems.join("\n"), /duplicate task id 'a'/)

  const cycle = validateAgentTasks(
    [task("a", { depends_on: ["b"] }), task("b", { depends_on: ["a"] })],
    agents,
  )
  assert.match(cycle.problems.join("\n"), /cycle/)

  const primary = validateAgentTasks([task("a", { agent: "build" })], agents)
  assert.match(primary.problems.join("\n"), /cannot run as a subagent/)

  const unknownAgent = validateAgentTasks([task("a", { agent: "nope" })], agents)
  assert.match(unknownAgent.problems.join("\n"), /unknown agent 'nope'/)
})

test("validation supplies positional ids and clamps the plan to the task ceiling", () => {
  const ok = validateAgentTasks([{ title: "A", prompt: "x" }])
  assert.equal(ok.problems.length, 0)
  assert.equal(ok.tasks[0].id, "task-1")

  const tooMany = validateAgentTasks(Array.from({ length: 9 }, (_, i) => task(`t${i}`)))
  assert.match(tooMany.problems.join("\n"), /at most 8 tasks/)
})

test("independent tasks run in parallel and report outputs", async () => {
  const fake = fakeClient({
    behaviour: {
      A: { delay: 30, output: "alpha" },
      B: { delay: 30, output: "bravo" },
      C: { delay: 30, output: "charlie" },
    },
  })
  const result = await runAgentPlan({
    client: fake.client,
    parentID: "parent",
    directory: "/tmp/project",
    objective: "parallel work",
    tasks: [task("a"), task("b"), task("c")],
    concurrency: 3,
  })

  assert.equal(result.planned, false)
  assert.deepEqual(result.tasks.map((entry) => entry.status), ["completed", "completed", "completed"])
  assert.deepEqual(result.tasks.map((entry) => entry.output), ["alpha", "bravo", "charlie"])
  assert.ok(fake.stats().maxActive >= 2, `expected parallel execution, max active was ${fake.stats().maxActive}`)
  assert.ok(fake.created.every((entry) => entry.parentID === "parent"))
  assert.ok(
    fake.prompts.every(
      (entry) =>
        entry.tools?.sec_agents === false && entry.tools?.task === false && entry.tools?.subagent === false && entry.tools?.question === false,
    ),
  )
  assert.match(formatAgentPlan(result), /results:/)
})

test("depends_on serialises work instead of starting the dependent early", async () => {
  const fake = fakeClient({
    behaviour: {
      A: { delay: 10, output: "first" },
      B: { delay: 5, output: "second" },
    },
  })
  const result = await runAgentPlan({
    client: fake.client,
    parentID: "parent",
    directory: "/tmp/project",
    objective: "ordered work",
    tasks: [task("b", { depends_on: ["a"] }), task("a")],
    concurrency: 2,
  })

  assert.deepEqual(fake.prompts.map((entry) => entry.title), ["A", "B"])
  assert.deepEqual(result.tasks.map((entry) => entry.id), ["b", "a"])
  assert.equal(result.tasks[0].status, "completed")
})

test("a failed dependency blocks its dependants while independent work continues", async () => {
  const fake = fakeClient({
    behaviour: {
      A: { error: "boom" },
      B: { output: "b" },
      C: { output: "c" },
    },
  })
  const result = await runAgentPlan({
    client: fake.client,
    parentID: "parent",
    directory: "/tmp/project",
    objective: "failure handling",
    tasks: [task("a"), task("b", { depends_on: ["a"] }), task("c")],
    concurrency: 2,
  })

  const statuses = Object.fromEntries(result.tasks.map((entry) => [entry.id, entry.status]))
  assert.equal(statuses.a, "failed")
  assert.equal(statuses.b, "blocked")
  assert.equal(statuses.c, "completed")
  assert.match(result.tasks.find((entry) => entry.id === "b")?.error ?? "", /dependency 'a'/)
})

test("a planner subagent can write the plan that then executes", async () => {
  const plan = JSON.stringify({
    tasks: [
      { id: "recon", title: "Recon", prompt: "recon the target", agent: "general" },
      { id: "report", title: "Report", prompt: "write it up", depends_on: ["recon"] },
    ],
  })
  const fake = fakeClient({
    behaviour: {
      "agent plan": { output: `\`\`\`json\n${plan}\n\`\`\`` },
      Recon: { output: "recon done" },
      Report: { output: "report done" },
    },
  })
  const result = await runAgentPlan({
    client: fake.client,
    parentID: "parent",
    directory: "/tmp/project",
    objective: "assess the target",
  })

  assert.equal(result.planned, true)
  assert.deepEqual(result.tasks.map((entry) => entry.id), ["recon", "report"])
  assert.deepEqual(result.tasks.map((entry) => entry.status), ["completed", "completed"])
  assert.deepEqual(result.tasks.map((entry) => entry.agent), ["general", "general"])
})

test("children inherit the parent session model", async () => {
  const fake = fakeClient({
    parentModel: { providerID: "provider", modelID: "model" },
    behaviour: { A: { output: "ok" } },
  })
  await runAgentPlan({
    client: fake.client,
    parentID: "parent",
    directory: "/tmp/project",
    objective: "model inheritance",
    tasks: [task("a")],
  })
  assert.deepEqual(fake.prompts[0].model, { providerID: "provider", modelID: "model" })
})

test("a hanging agent is timed out and its session is aborted", async () => {
  const fake = fakeClient({ behaviour: { A: { hang: true } } })
  const result = await runAgentPlan({
    client: fake.client,
    parentID: "parent",
    directory: "/tmp/project",
    objective: "timeout",
    tasks: [task("a")],
    timeoutMs: 30,
  })

  assert.equal(result.tasks[0].status, "timeout")
  assert.equal(fake.aborts.length, 1)
})

test("sec_agents is registered as a security tool", () => {
  const fake = fakeClient()
  const tools = buildSecurityTools({ client: fake.client })
  assert.ok(SECURITY_TOOL_IDS.includes("sec_agents"))
  assert.equal(typeof tools.sec_agents.execute, "function")
  assert.match(tools.sec_agents.description, /multi-agent plan/i)
})

test("the sec_agents tool runs a plan and returns a monitor report", async () => {
  const fake = fakeClient({ behaviour: { A: { output: "alpha" } } })
  const tools = buildSecurityTools({ client: fake.client })
  const ctx: any = {
    sessionID: "parent",
    agent: "void",
    directory: "/tmp/project",
    worktree: "/tmp/project",
    abort: new AbortController().signal,
    metadata() {},
  }
  const result = await tools.sec_agents.execute({ objective: "do it", tasks: [task("a")] }, ctx)
  assert.equal(typeof result, "object")
  assert.match(result.output, /a — A \[general\]/)
  assert.match(result.output, /alpha/)
  assert.equal(result.metadata.tasks[0].status, "completed")
})

test("plan parsing accepts fenced JSON and object or array plans", () => {
  assert.deepEqual(parseAgentPlan('```json\n{"tasks":[]}\n```'), { tasks: [] })
  assert.deepEqual(parseAgentPlan('prefix [{"id":"a"}] suffix'), [{ id: "a" }])
  assert.throws(() => parseAgentPlan("not json"), /parseable JSON/)
})


test("transient provider failures are retried in a fresh child session", async () => {
  const fake = fakeClient({
    behaviour: {
      A: { error: "The socket connection was closed unexpectedly", failFirst: 1, output: "recovered" },
    },
  })
  const result = await runAgentPlan({
    client: fake.client,
    parentID: "parent",
    directory: "/tmp/project",
    objective: "retry transport",
    tasks: [task("a")],
    retries: 1,
  })

  assert.equal(result.tasks[0]?.status, "completed")
  assert.equal(result.tasks[0]?.output, "recovered")
  assert.equal(fake.created.length, 2, "one failed attempt plus one fresh session")
  assert.ok(fake.aborts.includes(fake.created[0]!.id), "the failed child is aborted before the retry")
})

test("non-transient child errors are not retried", async () => {
  const fake = fakeClient({ behaviour: { A: { error: "tool rejected the request" } } })
  const result = await runAgentPlan({
    client: fake.client,
    parentID: "parent",
    directory: "/tmp/project",
    objective: "no retry",
    tasks: [task("a")],
    retries: 5,
  })

  assert.equal(result.tasks[0]?.status, "failed")
  assert.equal(fake.created.length, 1)
})

test("retries=0 disables the transport retry", async () => {
  const fake = fakeClient({ behaviour: { A: { error: "unknown certificate verification error" } } })
  const result = await runAgentPlan({
    client: fake.client,
    parentID: "parent",
    directory: "/tmp/project",
    objective: "retry disabled",
    tasks: [task("a")],
    retries: 0,
  })

  assert.equal(result.tasks[0]?.status, "failed")
  assert.equal(fake.created.length, 1)
  assert.match(result.tasks[0]?.error ?? "", /certificate verification/)
})
