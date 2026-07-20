import axios, { type AxiosInstance } from "axios";
import type { AgentContext, Logger, PluginRuntimeConfig, ToolCallEvent } from "./types.js";

export interface RuntimeActionDecision {
  decision: "allow" | "block" | "ask-user";
  risk_level: "low" | "medium" | "high" | "critical";
  reasons: string[];
  categories: string[];
  action_type: string;
  target_summary: string;
  redacted_summary: string;
  should_block: boolean;
  block_reason?: string | null;
  audit_recorded: boolean;
}

export interface RuntimeActionFailure {
  decision: "block";
  risk_level: "critical";
  reasons: string[];
  categories: string[];
  action_type: string;
  target_summary: string;
  redacted_summary: string;
  should_block: true;
  block_reason: string;
  audit_recorded: false;
}

export type RuntimeActionResult = RuntimeActionDecision | RuntimeActionFailure;

export class RuntimeActionClient {
  private readonly http: AxiosInstance;

  constructor(
    private readonly config: PluginRuntimeConfig,
    private readonly logger: Logger,
  ) {
    this.http = axios.create({
      baseURL: config.clawvaultUrl.replace(/\/+$/, ""),
      timeout: config.requestTimeoutMs,
    });
  }

  supports(event: ToolCallEvent): boolean {
    const toolName = event.toolName.toLowerCase();
    return toolName === "bash" || toolName === "read" || toolName === "write";
  }

  async evaluate(
    event: ToolCallEvent,
    ctx: AgentContext,
  ): Promise<RuntimeActionResult> {
    try {
      const res = await this.http.post("/api/openclaw/runtime-action", {
        tool_name: event.toolName,
        params: event.params ?? {},
        agent_id: ctx?.agentId,
        session_id: ctx?.sessionId ?? ctx?.sessionKey,
      });
      return parseDecision(res.data, event.toolName);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`runtime action guard unavailable: ${msg}`);
      return failClosed(event.toolName, "Runtime Action Guard unavailable");
    }
  }
}

function parseDecision(data: unknown, toolName: string): RuntimeActionDecision {
  if (!data || typeof data !== "object") {
    throw new Error("malformed runtime action decision");
  }
  const value = data as Partial<RuntimeActionDecision>;
  if (
    !isDecision(value.decision) ||
    !isRiskLevel(value.risk_level) ||
    !Array.isArray(value.reasons) ||
    !Array.isArray(value.categories) ||
    typeof value.action_type !== "string" ||
    typeof value.target_summary !== "string" ||
    typeof value.redacted_summary !== "string" ||
    typeof value.should_block !== "boolean" ||
    typeof value.audit_recorded !== "boolean"
  ) {
    throw new Error("malformed runtime action decision");
  }
  if (value.decision !== "allow" && value.should_block !== true) {
    throw new Error("unsafe runtime action decision");
  }
  return {
    decision: value.decision,
    risk_level: value.risk_level,
    reasons: value.reasons.filter((item): item is string => typeof item === "string"),
    categories: value.categories.filter((item): item is string => typeof item === "string"),
    action_type: value.action_type,
    target_summary: value.target_summary,
    redacted_summary: value.redacted_summary,
    should_block: value.should_block,
    block_reason: value.block_reason,
    audit_recorded: value.audit_recorded,
  };
}

function failClosed(toolName: string, reason: string): RuntimeActionFailure {
  return {
    decision: "block",
    risk_level: "critical",
    reasons: [reason],
    categories: ["runtime_action_guard_unavailable"],
    action_type: toolName.toLowerCase() === "bash" ? "shell.execute" : `tool.${toolName.toLowerCase()}`,
    target_summary: "",
    redacted_summary: "",
    should_block: true,
    block_reason: `ClawVault Runtime Action Guard unavailable for ${toolName}`,
    audit_recorded: false,
  };
}

function isDecision(value: unknown): value is RuntimeActionDecision["decision"] {
  return value === "allow" || value === "block" || value === "ask-user";
}

function isRiskLevel(value: unknown): value is RuntimeActionDecision["risk_level"] {
  return value === "low" || value === "medium" || value === "high" || value === "critical";
}
