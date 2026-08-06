import { ConfigClient } from "./src/config-client.js";
import { RuntimeActionClient } from "./src/runtime-action-client.js";
import { Reporter } from "./src/reporter.js";
import { parseSanitizeIntent } from "./src/sanitize-intent.js";
import { detect } from "./src/path-detector.js";
import type {
  AgentContext,
  AgentRunEvent,
  ExternalEvent,
  GuardMode,
  OpenClawPluginApi,
  PluginRuntimeConfig,
  ToolCallEvent,
} from "./src/types.js";

function readConfig(api: OpenClawPluginApi): PluginRuntimeConfig {
  // OpenClaw passes plugin-specific config via `pluginConfig` (from
  // openclaw.json's plugins.entries.<id>.config). `api.config` is the global
  // runtime config — only used as a last-resort fallback.
  const raw: Record<string, unknown> = {
    ...(api.config ?? {}),
    ...(api.pluginConfig ?? {}),
  };
  const get = <T>(key: string, fallback: T): T =>
    raw[key] !== undefined ? (raw[key] as T) : fallback;

  return {
    clawvaultUrl: get("clawvaultUrl", "http://127.0.0.1:8766"),
    mode: get<GuardMode>("mode", "log"),
    localSanitize: get("localSanitize", true),
    extraPaths: get<string[]>("extraPaths", []),
    extraExtensions: get<string[]>("extraExtensions", [
      ".pem",
      ".key",
      ".p12",
      ".pfx",
      ".kdbx",
    ]),
    refreshIntervalSeconds: get("refreshIntervalSeconds", 30),
    requestTimeoutMs: get("requestTimeoutMs", 2000),
  };
}

export default function register(api: OpenClawPluginApi): void {
  const logger = api.logger;
  const runtimeCfg = readConfig(api);

  logger.info(
    `[file-guard] starting, clawvault=${runtimeCfg.clawvaultUrl} mode=${runtimeCfg.mode}`,
  );

  const configClient = new ConfigClient(runtimeCfg, logger);
  const runtimeActionClient = new RuntimeActionClient(runtimeCfg, logger);
  const reporter = new Reporter(runtimeCfg, logger);

  api.on("gateway_start", async () => {
    configClient.start();
    logger.info("[file-guard] ready");
  });

  api.on(
    "before_agent_run",
    async (rawEvent: unknown, ctx: AgentContext) => {
      if (!runtimeCfg.localSanitize) return;
      const event = rawEvent as AgentRunEvent;
      const prompt = typeof event?.prompt === "string" ? event.prompt : "";
      const intent = parseSanitizeIntent(prompt);
      if (intent.action === "none") return;

      if (intent.action === "usage") {
        return {
          outcome: "block" as const,
          reason: "clawvault_sanitize_usage",
          message: "Usage: @clawvault sanitize <text>",
        };
      }

      return undefined;
    },
    { priority: 100, timeoutMs: Math.max(runtimeCfg.requestTimeoutMs + 500, 2500) },
  );

  api.on(
    "before_tool_call",
    async (rawEvent: unknown, ctx: AgentContext) => {
      try {
        const event = rawEvent as ToolCallEvent;
        if (!event || typeof event.toolName !== "string") return;
        const params = (event.params ?? {}) as Record<string, unknown>;

        if (runtimeActionClient.supports(event)) {
          const decision = await runtimeActionClient.evaluate(event, ctx);
          if (decision) {
            if (decision.should_block) {
              logger.warn(
                `[runtime-action] BLOCK ${event.toolName} (${decision.risk_level})`,
              );
              return {
                block: true,
                blockReason:
                  decision.block_reason ??
                  `ClawVault Runtime Action Guard: ${decision.decision}`,
              };
            }
            logger.info(
              `[runtime-action] ALLOW ${event.toolName} (${decision.risk_level})`,
            );
          }
        }

        const rules = configClient.getRules();
        const hit = detect(event.toolName, params, rules);
        if (!hit) return;

        const action: "log" | "block" =
          runtimeCfg.mode === "strict" ? "block" : "log";
        const severity: ExternalEvent["threat_level"] =
          action === "block" ? "high" : "medium";
        const message =
          action === "block"
            ? `Blocked tool call '${event.toolName}' targeting sensitive path`
            : `Logged tool call '${event.toolName}' targeting sensitive path`;

        void reporter.report({
          source: "openclaw-file-guard",
          category:
            action === "block" ? "file_access_blocked" : "file_access_logged",
          threat_level: severity,
          action,
          tool_name: event.toolName,
          file_path: hit.path,
          matched_rule: hit.matchedRule,
          agent_id: ctx?.agentId,
          session_id: ctx?.sessionId ?? ctx?.sessionKey,
          message,
          risk_score: action === "block" ? 8.5 : 6.0,
        });

        if (action === "block") {
          logger.warn(
            `[file-guard] BLOCK ${event.toolName} ${hit.path} (rule=${hit.matchedRule})`,
          );
          return {
            block: true,
            blockReason: `ClawVault file-guard: sensitive path '${hit.path}' (rule ${hit.matchedRule})`,
          };
        }
        logger.info(
          `[file-guard] LOG ${event.toolName} ${hit.path} (rule=${hit.matchedRule})`,
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error(`[file-guard] handler error: ${msg}`);
        const event = rawEvent as Partial<ToolCallEvent>;
        if (typeof event?.toolName === "string" && runtimeActionClient.supports(event as ToolCallEvent)) {
          return {
            block: true,
            blockReason: `ClawVault Runtime Action Guard unavailable for ${event.toolName}`,
          };
        }
      }
    },
  );
}
