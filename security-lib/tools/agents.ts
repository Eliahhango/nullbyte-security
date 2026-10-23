import { tool } from "@opencode-ai/plugin"
import {
  formatAgentPlan,
  runAgentPlan,
  type AgentClient,
  type AgentProgress,
  type AgentTask,
  type AgentTaskResult,
} from "../agents.ts"
import { startProgress } from "../progress.ts"

export function createSecAgents(client?: AgentClient) {
  return tool({
    description:
      "Run a multi-agent plan. Give an objective and 1-8 non-overlapping tasks; each task gets its own child " +
      "session/agent, independent tasks run in parallel up to the concurrency limit, and depends_on gates the " +
      "order. If tasks are omitted, a planner subagent decomposes the objective first. The tool monitors every " +
      "agent, aborts on timeout/cancel, and returns each task's output and session id. Transient provider " +
      "network/TLS failures are retried in a fresh child session. Use this for large assessments; use the normal " +
      "tools for small work.",
    args: {
      objective: tool.schema.string().describe("the overall outcome the plan must achieve"),
      tasks: tool.schema
        .array(
          tool.schema.object({
            id: tool.schema.string().describe("short unique id used by depends_on"),
            title: tool.schema.string().describe("3-8 word label shown in the monitor"),
            prompt: tool.schema.string().describe("self-contained instructions for the child agent"),
            agent: tool.schema.string().optional().describe("subagent name; omit to use the default subagent"),
            depends_on: tool.schema.array(tool.schema.string()).optional().describe("ids that must complete first"),
          }),
        )
        .optional()
        .describe("the plan; omit to have a planner subagent write it"),
      agent: tool.schema.string().optional().describe("default subagent for tasks that do not name one"),
      concurrency: tool.schema.number().int().min(1).max(8).optional().describe("parallel agents (default 4)"),
      timeout_ms: tool.schema.number().int().min(1000).optional().describe("per-task timeout (default 15 minutes)"),
      retries: tool.schema
        .number()
        .int()
        .min(0)
        .max(5)
        .optional()
        .describe("additional attempts after a transient provider network/TLS failure (default 2)"),
    },
    async execute(args, c) {
      if (!client) throw new Error("multi-agent orchestration is unavailable: the plugin was built without its runtime client")

      const label = args.objective.length > 60 ? `${args.objective.slice(0, 57)}...` : args.objective
      const progress = startProgress(`agents ${args.tasks?.length ?? "planning"} · ${label}`, { timer: true })
      const update = (p: AgentProgress) => {
        progress.update(`agents ${p.completed + p.failed}/${p.total} · ${p.running} running`)
      }
      try {
        const result = await runAgentPlan({
          client,
          parentID: c.sessionID,
          directory: c.directory || c.worktree,
          objective: args.objective,
          tasks: args.tasks,
          agent: args.agent,
          concurrency: args.concurrency,
          timeoutMs: args.timeout_ms,
          retries: args.retries,
          signal: c.abort,
          hooks: {
            onPlanStart: () => progress.update(`agents · planning ${label}`),
            onPlanFinish: (tasks: AgentTask[]) => progress.update(`agents 0/${tasks.length} · plan ready`),
            onTaskStart: (task, p) => {
              update(p)
              c.metadata?.({
                title: `sec_agents ${p.completed + p.failed}/${p.total} · ${task.id}`,
                metadata: { running: task.id, agent: task.agent, ...p },
              })
            },
            onTaskFinish: (task: AgentTaskResult, p) => {
              update(p)
              c.metadata?.({
                title: `sec_agents ${p.completed + p.failed}/${p.total} · ${task.id} ${task.status}`,
                metadata: { task: task.id, status: task.status, sessionID: task.sessionID, ...p },
              })
            },
          },
        })

        const failed = result.tasks.filter((task) => task.status !== "completed").length
        if (failed === 0) progress.succeed(`agents · ${result.tasks.length} completed`)
        else progress.fail(`agents · ${failed}/${result.tasks.length} did not complete`)
        c.metadata?.({
          title: `sec_agents ${result.tasks.length - failed}/${result.tasks.length} completed`,
          metadata: { objective: result.objective, tasks: result.tasks.map((task) => ({ id: task.id, status: task.status, sessionID: task.sessionID })) },
        })
        return {
          title: `sec_agents ${result.tasks.length - failed}/${result.tasks.length} completed`,
          output: formatAgentPlan(result),
          metadata: {
            objective: result.objective,
            planned: result.planned,
            tasks: result.tasks.map(({ id, title, agent, sessionID, status, durationMs, error }) => ({
              id,
              title,
              agent,
              sessionID,
              status,
              durationMs,
              error,
            })),
          },
        }
      } catch (error) {
        progress.fail(`agents failed`)
        throw error
      } finally {
        progress.stop()
      }
    },
  })
}
