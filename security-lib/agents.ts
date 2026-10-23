export interface AgentModel {
  providerID: string
  modelID: string
}

export interface AgentInfo {
  name: string
  description?: string
  mode?: string
  model?: AgentModel
}

export interface AgentTask {
  id: string
  title: string
  prompt: string
  agent?: string
  depends_on?: string[]
}

export type AgentTaskStatus = "completed" | "failed" | "timeout" | "cancelled" | "blocked"

export interface AgentTaskResult {
  id: string
  title: string
  agent?: string
  sessionID?: string
  status: AgentTaskStatus
  output: string
  error?: string
  durationMs: number
}

export interface AgentPlanResult {
  objective: string
  planned: boolean
  durationMs: number
  tasks: AgentTaskResult[]
}

export interface AgentProgress {
  total: number
  running: number
  completed: number
  failed: number
}

export interface AgentPlanHooks {
  onPlanStart?: () => void
  onPlanFinish?: (tasks: AgentTask[]) => void
  onTaskStart?: (task: AgentTask, progress: AgentProgress) => void
  onTaskFinish?: (result: AgentTaskResult, progress: AgentProgress) => void
}

export interface AgentClient {
  session: {
    create(options: any): Promise<any>
    prompt(options: any): Promise<any>
    abort(options: any): Promise<any>
    messages?(options: any): Promise<any>
  }
  app: {
    agents(options?: any): Promise<any>
  }
}

export interface RunAgentPlanOptions {
  client: AgentClient
  parentID: string
  directory: string
  objective: string
  tasks?: unknown
  agent?: string
  model?: AgentModel
  concurrency?: number
  timeoutMs?: number
  signal?: AbortSignal
  hooks?: AgentPlanHooks
}

export interface PlanValidation {
  tasks: AgentTask[]
  problems: string[]
}

export const MAX_AGENT_TASKS = 8
export const MAX_AGENT_CONCURRENCY = 8
export const DEFAULT_AGENT_CONCURRENCY = 4
export const DEFAULT_AGENT_TIMEOUT_MS = 900_000
const MAX_TASK_OUTPUT = 16_000

const TASK_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/
const CHILD_DIRECTIVE =
  "You are a child agent working autonomously. Do not ask the user questions; " +
  "make reasonable assumptions and finish with the requested deliverable."

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : ""
}

function describeError(error: unknown): string {
  if (!error) return ""
  if (typeof error === "string") return error
  if (typeof error === "object") {
    const e = error as Record<string, unknown>
    if (typeof e.message === "string" && e.message) return e.message
    try {
      return JSON.stringify(error)
    } catch {
      return String(error)
    }
  }
  return String(error)
}

function resultError(result: any): string {
  if (!result) return "no response"
  if (result.error) return describeError(result.error)
  if (result.data === undefined) {
    const status = result.response?.status
    return status ? `request failed with HTTP ${status}` : "request failed"
  }
  return ""
}

function responseText(data: any): string {
  const parts = Array.isArray(data?.parts) ? data.parts : []
  return parts
    .filter((part: any) => part?.type === "text" && typeof part.text === "string")
    .map((part: any) => part.text as string)
    .filter(Boolean)
    .join("\n\n")
    .trim()
}

function truncate(value: string, limit = MAX_TASK_OUTPUT): string {
  if (value.length <= limit) return value
  return `${value.slice(0, limit)}\n\n[truncated at ${limit} characters]`
}

function formatDuration(ms: number): string {
  const seconds = Math.max(0, ms) / 1000
  return seconds < 10 ? `${seconds.toFixed(1)}s` : `${Math.round(seconds)}s`
}

export async function loadParentModel(
  client: AgentClient,
  parentID: string,
  directory: string,
  signal?: AbortSignal,
): Promise<AgentModel | undefined> {
  if (!client.session.messages) return undefined
  try {
    const result = await client.session.messages({
      path: { id: parentID },
      query: directory ? { directory } : undefined,
      signal,
    })
    if (result?.error || !Array.isArray(result?.data)) return undefined
    for (const message of [...result.data].reverse()) {
      const info = message?.info
      if (info?.model?.providerID && info?.model?.modelID) {
        return { providerID: String(info.model.providerID), modelID: String(info.model.modelID) }
      }
    }
  } catch {}
  return undefined
}

export function pickDefaultAgent(agents: AgentInfo[]): string | undefined {
  const available = agents.filter((agent) => agent.name && agent.mode !== "primary")
  for (const preferred of ["general", "explore"]) {
    if (available.some((agent) => agent.name === preferred)) return preferred
  }
  return available[0]?.name
}

export async function loadAvailableAgents(
  client: AgentClient,
  directory: string,
  signal?: AbortSignal,
): Promise<AgentInfo[]> {
  try {
    const result = await client.app.agents({ query: directory ? { directory } : undefined, signal })
    if (result?.error || !Array.isArray(result?.data)) return []
    return result.data.filter((agent: any) => agent && typeof agent.name === "string")
  } catch {
    return []
  }
}

export function validateAgentTasks(raw: unknown, available: AgentInfo[] = []): PlanValidation {
  const problems: string[] = []
  if (!Array.isArray(raw)) {
    return { tasks: [], problems: ["tasks must be an array"] }
  }
  if (raw.length === 0) problems.push("at least one task is required")
  if (raw.length > MAX_AGENT_TASKS) problems.push(`at most ${MAX_AGENT_TASKS} tasks are allowed`)

  const tasks: AgentTask[] = []
  const seen = new Set<string>()
  for (const [index, item] of raw.entries()) {
    if (!item || typeof item !== "object") {
      problems.push(`tasks[${index}] must be an object`)
      continue
    }
    const value = item as Record<string, unknown>
    const id = text(value.id) || `task-${index + 1}`
    const title = text(value.title)
    const prompt = text(value.prompt)
    const agent = text(value.agent) || undefined
    const depends_on = Array.isArray(value.depends_on)
      ? [...new Set(value.depends_on.map(text).filter(Boolean))]
      : []

    if (!TASK_ID.test(id)) problems.push(`task '${id}': id must be 1-40 letters, digits, dots, dashes or underscores`)
    if (seen.has(id)) problems.push(`duplicate task id '${id}'`)
    seen.add(id)
    if (!title) problems.push(`task '${id}': title is required`)
    if (title.length > 160) problems.push(`task '${id}': title is too long (max 160)`)
    if (!prompt) problems.push(`task '${id}': prompt is required`)
    if (prompt.length > 20_000) problems.push(`task '${id}': prompt is too long (max 20000)`)
    if (depends_on.includes(id)) problems.push(`task '${id}' cannot depend on itself`)

    if (agent && available.length > 0) {
      const match = available.find((candidate) => candidate.name === agent)
      if (!match) problems.push(`task '${id}': unknown agent '${agent}'`)
      else if (match.mode === "primary") problems.push(`task '${id}': agent '${agent}' cannot run as a subagent`)
    }

    tasks.push({ id, title, prompt, ...(agent ? { agent } : {}), ...(depends_on.length ? { depends_on } : {}) })
  }

  const ids = new Map(tasks.map((task) => [task.id, task]))
  for (const task of tasks) {
    for (const dependency of task.depends_on ?? []) {
      if (!ids.has(dependency)) problems.push(`task '${task.id}': unknown dependency '${dependency}'`)
    }
  }

  const state = new Map<string, 0 | 1 | 2>()
  const hasCycle = (id: string): boolean => {
    const current = state.get(id) ?? 0
    if (current === 1) return true
    if (current === 2) return false
    state.set(id, 1)
    for (const dependency of ids.get(id)?.depends_on ?? []) {
      if (ids.has(dependency) && hasCycle(dependency)) return true
    }
    state.set(id, 2)
    return false
  }
  for (const task of tasks) {
    if (hasCycle(task.id)) {
      problems.push("task dependencies contain a cycle")
      break
    }
  }

  return { tasks, problems }
}

export function parseAgentPlan(output: string): unknown {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(output)
  const candidates = [output.trim(), fenced?.[1]?.trim() ?? ""].filter(Boolean)
  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate)
    } catch {
      const starts = [candidate.indexOf("{"), candidate.indexOf("[")].filter((index) => index >= 0)
      const start = starts.length ? Math.min(...starts) : -1
      const end = Math.max(candidate.lastIndexOf("}"), candidate.lastIndexOf("]"))
      if (start >= 0 && end > start) {
        try {
          return JSON.parse(candidate.slice(start, end + 1))
        } catch {
          continue
        }
      }
    }
  }
  throw new Error("planner did not return parseable JSON")
}

interface ChildRunResult {
  sessionID: string
  output: string
  error?: string
  timedOut?: boolean
  cancelled?: boolean
  durationMs: number
}

async function runChild(
  client: AgentClient,
  options: {
    parentID: string
    directory: string
    title: string
    agent?: string
    model?: AgentModel
    prompt: string
    timeoutMs: number
    signal?: AbortSignal
  },
): Promise<ChildRunResult> {
  const started = Date.now()
  if (options.signal?.aborted) {
    return { sessionID: "", output: "", error: "cancelled", cancelled: true, durationMs: 0 }
  }

  let created: any
  try {
    created = await client.session.create({
      body: { parentID: options.parentID, title: options.title },
      query: options.directory ? { directory: options.directory } : undefined,
      signal: options.signal,
    })
  } catch (error) {
    if (options.signal?.aborted) {
      return { sessionID: "", output: "", error: "cancelled", cancelled: true, durationMs: Date.now() - started }
    }
    return { sessionID: "", output: "", error: describeError(error), durationMs: Date.now() - started }
  }

  const createError = resultError(created)
  const sessionID = text(created?.data?.id)
  if (createError || !sessionID) {
    if (options.signal?.aborted) {
      return { sessionID, output: "", error: "cancelled", cancelled: true, durationMs: Date.now() - started }
    }
    return { sessionID, output: "", error: createError || "session was not created", durationMs: Date.now() - started }
  }

  const controller = new AbortController()
  let timedOut = false
  let cancelled = false
  const abortChild = () => {
    try {
      void Promise.resolve(
        client.session.abort({
          path: { id: sessionID },
          query: options.directory ? { directory: options.directory } : undefined,
        }),
      ).catch(() => {})
    } catch {}
  }
  const onAbort = () => {
    cancelled = true
    controller.abort()
    abortChild()
  }
  if (options.signal?.aborted) onAbort()
  else options.signal?.addEventListener("abort", onAbort, { once: true })

  const timer = setTimeout(
    () => {
      timedOut = true
      controller.abort()
      abortChild()
    },
    Math.max(1, options.timeoutMs),
  )

  const aborted = new Promise<never>((_, reject) => {
    if (controller.signal.aborted) {
      reject(new Error(timedOut ? "timed out" : "cancelled"))
      return
    }
    controller.signal.addEventListener(
      "abort",
      () => reject(new Error(timedOut ? "timed out" : "cancelled")),
      { once: true },
    )
  })

  try {
    const result = await Promise.race([
      client.session.prompt({
        path: { id: sessionID },
        query: options.directory ? { directory: options.directory } : undefined,
        signal: controller.signal,
        body: {
          ...(options.agent ? { agent: options.agent } : {}),
          ...(options.model ? { model: options.model } : {}),
          tools: { sec_agents: false, task: false, subagent: false, question: false },
          parts: [{ type: "text", text: `${CHILD_DIRECTIVE}\n\n${options.prompt}` }],
        },
      }),
      aborted,
    ])
    const durationMs = Date.now() - started
    if (timedOut) return { sessionID, output: "", error: "timed out", timedOut: true, durationMs }
    if (cancelled) return { sessionID, output: "", error: "cancelled", cancelled: true, durationMs }
    const error = resultError(result)
    if (error) return { sessionID, output: "", error, durationMs }
    return { sessionID, output: responseText(result?.data), durationMs }
  } catch (error) {
    const durationMs = Date.now() - started
    if (timedOut) return { sessionID, output: "", error: "timed out", timedOut: true, durationMs }
    if (cancelled) return { sessionID, output: "", error: "cancelled", cancelled: true, durationMs }
    return { sessionID, output: "", error: describeError(error), durationMs }
  } finally {
    clearTimeout(timer)
    options.signal?.removeEventListener("abort", onAbort)
  }
}

async function planTasks(
  options: RunAgentPlanOptions,
  available: AgentInfo[],
  defaultAgent: string | undefined,
  model: AgentModel | undefined,
): Promise<AgentTask[]> {
  const agents = available
    .filter((agent) => agent.mode !== "primary")
    .map((agent) => `- ${agent.name}${agent.description ? `: ${agent.description}` : ""}`)
    .join("\n")
  const prompt = [
    "You are the planning agent for a multi-agent security assessment.",
    "",
    `Objective: ${options.objective}`,
    "",
    "Decompose the objective into non-overlapping tasks. Return ONLY a JSON object, no prose:",
    '{"tasks":[{"id":"short-id","title":"short title","prompt":"self-contained instructions","agent":"agent-name","depends_on":[]}]}',
    "",
    `Rules: return 2-${MAX_AGENT_TASKS} tasks; use one only when the work is indivisible.`,
    "Independent tasks may run in parallel. Set depends_on only where order is required.",
    "Do not put two tasks that edit the same files in the same parallel stage.",
    "Each prompt must include the target, constraints, and the expected deliverable.",
    "Use only an available agent. Omit agent only if no subagent is listed.",
    "",
    "Available subagents:",
    agents || "- (let the runtime choose)",
  ].join("\n")

  const child = await runChild(options.client, {
    parentID: options.parentID,
    directory: options.directory,
    title: "agent plan",
    agent: defaultAgent,
    prompt,
    model: available.find((agent) => agent.name === defaultAgent)?.model ?? model,
    timeoutMs: options.timeoutMs ?? DEFAULT_AGENT_TIMEOUT_MS,
    signal: options.signal,
  })
  if (child.error) throw new Error(`planner failed: ${child.error}`)

  const parsed = parseAgentPlan(child.output)
  const raw = parsed && typeof parsed === "object" && "tasks" in parsed ? (parsed as { tasks: unknown }).tasks : parsed
  const validation = validateAgentTasks(raw, available)
  if (validation.problems.length) {
    throw new Error(`planner returned an invalid plan:\n- ${validation.problems.join("\n- ")}`)
  }
  return validation.tasks
}

function progressState(tasks: AgentTask[], results: Map<string, AgentTaskResult>, running: Map<string, unknown>): AgentProgress {
  let completed = 0
  let failed = 0
  for (const result of results.values()) {
    if (result.status === "completed") completed++
    else failed++
  }
  return { total: tasks.length, running: running.size, completed, failed }
}

export async function runAgentPlan(options: RunAgentPlanOptions): Promise<AgentPlanResult> {
  const objective = text(options.objective)
  if (!objective) throw new Error("objective is required")

  const started = Date.now()
  const available = await loadAvailableAgents(options.client, options.directory, options.signal)
  const model = options.model ?? (await loadParentModel(options.client, options.parentID, options.directory, options.signal))
  let defaultAgent = options.agent
  if (defaultAgent && available.length > 0) {
    const match = available.find((agent) => agent.name === defaultAgent)
    if (!match) throw new Error(`unknown default agent '${defaultAgent}'`)
    if (match.mode === "primary") throw new Error(`agent '${defaultAgent}' cannot run as a subagent`)
  }
  defaultAgent ??= pickDefaultAgent(available)

  const planning = options.tasks === undefined || (Array.isArray(options.tasks) && options.tasks.length === 0)
  let tasks: AgentTask[]
  if (planning) {
    options.hooks?.onPlanStart?.()
    tasks = await planTasks(options, available, defaultAgent, model)
    options.hooks?.onPlanFinish?.(tasks)
  } else {
    const validation = validateAgentTasks(options.tasks, available)
    if (validation.problems.length) {
      throw new Error(`invalid agent plan:\n- ${validation.problems.join("\n- ")}`)
    }
    tasks = validation.tasks
  }

  for (const task of tasks) {
    if (!task.agent && defaultAgent) task.agent = defaultAgent
  }

  const concurrency = Math.max(
    1,
    Math.min(options.concurrency ?? DEFAULT_AGENT_CONCURRENCY, MAX_AGENT_CONCURRENCY),
  )
  const pending = new Map(tasks.map((task) => [task.id, task]))
  const results = new Map<string, AgentTaskResult>()
  const running = new Map<string, Promise<AgentTaskResult>>()

  const finishBlocked = (task: AgentTask, reason: string) => {
    const result: AgentTaskResult = {
      id: task.id,
      title: task.title,
      ...(task.agent ? { agent: task.agent } : {}),
      status: "blocked",
      output: "",
      error: reason,
      durationMs: 0,
    }
    results.set(task.id, result)
    options.hooks?.onTaskFinish?.(result, progressState(tasks, results, running))
  }

  const execute = async (task: AgentTask): Promise<AgentTaskResult> => {
    const child = await runChild(options.client, {
      parentID: options.parentID,
      directory: options.directory,
      title: task.title,
      agent: task.agent,
      model: available.find((agent) => agent.name === task.agent)?.model ?? model,
      prompt: task.prompt,
      timeoutMs: options.timeoutMs ?? DEFAULT_AGENT_TIMEOUT_MS,
      signal: options.signal,
    })
    const status: AgentTaskStatus = child.cancelled
      ? "cancelled"
      : child.timedOut
        ? "timeout"
        : child.error
          ? "failed"
          : "completed"
    return {
      id: task.id,
      title: task.title,
      ...(task.agent ? { agent: task.agent } : {}),
      ...(child.sessionID ? { sessionID: child.sessionID } : {}),
      status,
      output: child.output,
      ...(child.error ? { error: child.error } : {}),
      durationMs: child.durationMs,
    }
  }

  while (pending.size > 0 || running.size > 0) {
    if (options.signal?.aborted) {
      for (const task of pending.values()) {
        const result: AgentTaskResult = {
          id: task.id,
          title: task.title,
          ...(task.agent ? { agent: task.agent } : {}),
          status: "cancelled",
          output: "",
          error: "cancelled",
          durationMs: 0,
        }
        results.set(task.id, result)
        options.hooks?.onTaskFinish?.(result, progressState(tasks, results, running))
      }
      pending.clear()
    }

    for (const task of [...pending.values()]) {
      const failedDependency = (task.depends_on ?? []).find((dependency) => {
        const result = results.get(dependency)
        return result && result.status !== "completed"
      })
      if (failedDependency) {
        pending.delete(task.id)
        finishBlocked(task, `dependency '${failedDependency}' did not complete`)
      }
    }

    while (running.size < concurrency && !options.signal?.aborted) {
      const task = [...pending.values()].find((candidate) =>
        (candidate.depends_on ?? []).every((dependency) => results.get(dependency)?.status === "completed"),
      )
      if (!task) break
      pending.delete(task.id)
      const promise = execute(task).then((result) => {
        running.delete(task.id)
        results.set(task.id, result)
        options.hooks?.onTaskFinish?.(result, progressState(tasks, results, running))
        return result
      })
      running.set(task.id, promise)
      options.hooks?.onTaskStart?.(task, progressState(tasks, results, running))
    }

    if (running.size === 0) {
      for (const task of pending.values()) finishBlocked(task, "dependencies could not be resolved")
      pending.clear()
      break
    }

    await Promise.race(running.values())
  }

  const ordered = tasks.map(
    (task): AgentTaskResult =>
      results.get(task.id) ?? {
        id: task.id,
        title: task.title,
        ...(task.agent ? { agent: task.agent } : {}),
        status: "blocked",
        output: "",
        error: "task did not run",
        durationMs: 0,
      },
  )

  return { objective, planned: planning, durationMs: Date.now() - started, tasks: ordered }
}

export function formatAgentPlan(result: AgentPlanResult): string {
  const count = (status: AgentTaskStatus) => result.tasks.filter((task) => task.status === status).length
  const lines = [
    `agent plan — ${result.tasks.length} task(s), ${count("completed")} completed, ${count("failed")} failed, ${count("timeout")} timed out, ${count("blocked")} blocked`,
    `objective: ${result.objective}`,
    `wall time: ${formatDuration(result.durationMs)}${result.planned ? " (planned by a subagent)" : ""}`,
    "",
  ]

  const icon: Record<AgentTaskStatus, string> = {
    completed: "✓",
    failed: "✗",
    timeout: "!",
    cancelled: "-",
    blocked: "…",
  }

  for (const task of result.tasks) {
    const agent = task.agent ? ` [${task.agent}]` : ""
    const session = task.sessionID ? ` session=${task.sessionID}` : ""
    const error = task.error ? ` — ${task.error}` : ""
    lines.push(`${icon[task.status]} ${task.id} — ${task.title}${agent}${session} (${formatDuration(task.durationMs)})${error}`)
  }

  const withOutput = result.tasks.filter((task) => task.status === "completed" && task.output)
  if (withOutput.length) {
    lines.push("", "results:")
    for (const task of withOutput) {
      lines.push("", `### ${task.id} — ${task.title}`, truncate(task.output))
    }
  }

  return lines.join("\n")
}
