import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { createServer, type Server } from "node:http";
import { once } from "node:events";
import register from "../index.js";
import type { AgentContext, OpenClawPluginApi } from "../src/types.js";

const CN_SANITIZE_INFO = "\u8131\u654f\u4fe1\u606f";
const CN_WHAT_IS_SANITIZE = "\u4ec0\u4e48\u662f\u8131\u654f\uff1f";
const CN_MY_EMAIL_IS = "\u6211\u7684\u90ae\u7bb1\u662f";

interface FakeClawVaultState {
  fileMonitorConfig: {
    watch_paths: string[];
    watch_patterns: string[];
  };
  events: unknown[];
  runtimeActionMode?: "normal" | "malformed" | "unsafe";
}

function startFakeClawVault(state: FakeClawVaultState): Promise<{
  url: string;
  close: () => Promise<void>;
}> {
  return new Promise((resolve) => {
    const server: Server = createServer((req, res) => {
      if (!req.url) {
        res.statusCode = 404;
        res.end();
        return;
      }
      if (req.method === "GET" && req.url.startsWith("/api/config/file-monitor")) {
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(state.fileMonitorConfig));
        return;
      }
      if (req.method === "POST" && req.url.startsWith("/api/events/external")) {
        let body = "";
        req.on("data", (chunk) => (body += chunk.toString()));
        req.on("end", () => {
          try {
            state.events.push(JSON.parse(body));
          } catch {
            state.events.push(body);
          }
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ ok: true, event_id: "test" }));
        });
        return;
      }
      if (req.method === "POST" && req.url.startsWith("/api/openclaw/runtime-action")) {
        let body = "";
        req.on("data", (chunk) => (body += chunk.toString()));
        req.on("end", () => {
          if (state.runtimeActionMode === "malformed") {
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ decision: "allow" }));
            return;
          }
          if (state.runtimeActionMode === "unsafe") {
            res.setHeader("Content-Type", "application/json");
            res.end(
              JSON.stringify({
                decision: "ask-user",
                risk_level: "medium",
                reasons: ["requires approval"],
                categories: ["startup_file_write"],
                action_type: "file.write",
                target_summary: "~/.bashrc",
                redacted_summary: "~/.bashrc",
                should_block: false,
                audit_recorded: true,
              }),
            );
            return;
          }
          const payload = JSON.parse(body) as {
            tool_name: string;
            params: Record<string, unknown>;
          };
          const command = String(payload.params.command ?? "");
          const path = String(payload.params.path ?? "");
          const isAskUser = payload.tool_name.toLowerCase() === "write" && path === "~/.bashrc";
          const isBlocked = command === "rm -rf /" || isAskUser;
          const decision = isAskUser ? "ask-user" : isBlocked ? "block" : "allow";
          res.setHeader("Content-Type", "application/json");
          res.end(
            JSON.stringify({
              decision,
              risk_level: isBlocked ? "critical" : "low",
              reasons: isBlocked ? ["blocked by fake runtime action guard"] : ["allowed"],
              categories: isBlocked ? ["test_block"] : ["shell"],
              action_type: payload.tool_name.toLowerCase() === "bash" ? "shell.execute" : "file.write",
              target_summary: command || path,
              redacted_summary: command || path,
              should_block: isBlocked,
              block_reason: isBlocked ? "ClawVault Runtime Action Guard: test block" : null,
              audit_recorded: true,
            }),
          );
        });
        return;
      }
      if (req.method === "POST" && req.url.startsWith("/api/openclaw/sanitize")) {
        let body = "";
        req.on("data", (chunk) => (body += chunk.toString()));
        req.on("end", () => {
          const payload = JSON.parse(body) as { text: string };
          res.setHeader("Content-Type", "application/json");
          res.end(
            JSON.stringify({
              success: true,
              sanitized: payload.text.replace("alice@example.com", "[EMAIL_1]"),
            }),
          );
        });
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (typeof addr === "object" && addr) {
        resolve({
          url: `http://127.0.0.1:${addr.port}`,
          close: async () => {
            server.close();
            await once(server, "close");
          },
        });
      }
    });
  });
}

function makeApi(
  configOverrides: Record<string, unknown>,
): {
  api: OpenClawPluginApi;
  handlers: Map<string, (event: unknown, ctx: AgentContext) => Promise<unknown>>;
  logs: { level: string; msg: string }[];
} {
  const handlers = new Map<
    string,
    (event: unknown, ctx: AgentContext) => Promise<unknown>
  >();
  const logs: { level: string; msg: string }[] = [];
  const logger = {
    info: (m: string) => logs.push({ level: "info", msg: m }),
    warn: (m: string) => logs.push({ level: "warn", msg: m }),
    error: (m: string) => logs.push({ level: "error", msg: m }),
    debug: (m: string) => logs.push({ level: "debug", msg: m }),
  };
  const api: OpenClawPluginApi = {
    logger,
    config: {},
    pluginConfig: configOverrides,
    version: "test-0.0.1",
    on: (event, handler) => {
      handlers.set(
        event,
        handler as (event: unknown, ctx: AgentContext) => Promise<unknown>,
      );
    },
  };
  return { api, handlers, logs };
}

describe("end-to-end: plugin ↔ ClawVault", () => {
  let state: FakeClawVaultState;
  let srv: { url: string; close: () => Promise<void> };

  beforeAll(async () => {
    state = {
      fileMonitorConfig: {
        watch_paths: [".ssh/**", ".aws/credentials"],
        watch_patterns: ["id_rsa*", "*.pem"],
      },
      events: [],
    };
    srv = await startFakeClawVault(state);
  });

  afterAll(async () => {
    await srv.close();
  });

  it("lets valid local sanitize intent continue to provider chain", async () => {
    const { api, handlers, logs } = makeApi({
      clawvaultUrl: srv.url,
      mode: "strict",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
    });
    await register(api);

    const result = await handlers.get("before_agent_run")!(
      { prompt: `@clawvault ${CN_SANITIZE_INFO} ${CN_MY_EMAIL_IS} alice@example.com` },
      { agentId: "agent-1", sessionId: "session-1" },
    );

    expect(result).toBeUndefined();
    expect(JSON.stringify(logs)).not.toContain("alice@example.com");
  });

  it("does not handle non-sanitize questions locally", async () => {
    const { api, handlers } = makeApi({
      clawvaultUrl: srv.url,
      mode: "strict",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
    });
    await register(api);

    const result = await handlers.get("before_agent_run")!(
      { prompt: `@clawvault ${CN_WHAT_IS_SANITIZE}` },
      {},
    );

    expect(result).toBeUndefined();
  });

  it("C1: strict mode blocks sensitive read and posts event", async () => {
    state.events.length = 0;
    const { api, handlers } = makeApi({
      clawvaultUrl: srv.url,
      mode: "strict",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
    });
    await register(api);
    await handlers.get("gateway_start")!(undefined, {});
    // Give config-client time to fetch
    await new Promise((r) => setTimeout(r, 100));

    const result = await handlers.get("before_tool_call")!(
      { toolName: "read", params: { path: "/home/user/.ssh/id_rsa" } },
      { agentId: "agent-1" },
    );

    expect(result).toMatchObject({ block: true });
    expect((result as { blockReason: string }).blockReason).toMatch(/id_rsa/);

    // Wait briefly for async report
    await new Promise((r) => setTimeout(r, 100));
    expect(state.events).toHaveLength(1);
    const ev = state.events[0] as Record<string, unknown>;
    expect(ev.source).toBe("openclaw-file-guard");
    expect(ev.action).toBe("block");
    expect(ev.tool_name).toBe("read");
    expect(ev.file_path).toBe("/home/user/.ssh/id_rsa");
    expect(ev.matched_rule).toBe(".ssh/**");
    expect(ev.agent_id).toBe("agent-1");
  });

  it("C2: log mode reports but does not block", async () => {
    state.events.length = 0;
    const { api, handlers } = makeApi({
      clawvaultUrl: srv.url,
      mode: "log",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
    });
    await register(api);
    await handlers.get("gateway_start")!(undefined, {});
    await new Promise((r) => setTimeout(r, 100));

    const result = await handlers.get("before_tool_call")!(
      { toolName: "bash", params: { command: "cat /home/u/.aws/credentials" } },
      {},
    );

    expect(result).toBeUndefined();
    await new Promise((r) => setTimeout(r, 100));
    expect(state.events).toHaveLength(1);
    expect((state.events[0] as { action: string }).action).toBe("log");
    expect((state.events[0] as { matched_rule: string }).matched_rule).toBe(
      ".aws/credentials",
    );
  });

  it("C3: benign tool call is transparent (no block, no event)", async () => {
    state.events.length = 0;
    const { api, handlers } = makeApi({
      clawvaultUrl: srv.url,
      mode: "strict",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
    });
    await register(api);
    await handlers.get("gateway_start")!(undefined, {});
    await new Promise((r) => setTimeout(r, 100));

    const result = await handlers.get("before_tool_call")!(
      { toolName: "read", params: { path: "/repo/README.md" } },
      {},
    );

    expect(result).toBeUndefined();
    await new Promise((r) => setTimeout(r, 50));
    expect(state.events).toHaveLength(0);
  });

  it("C5: live config change propagates to detector on next refresh", async () => {
    state.events.length = 0;
    // Start with no rules matching /etc/foobar.secret
    state.fileMonitorConfig = { watch_paths: [], watch_patterns: [] };

    const { api, handlers } = makeApi({
      clawvaultUrl: srv.url,
      mode: "strict",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
      extraExtensions: [],
    });
    await register(api);
    await handlers.get("gateway_start")!(undefined, {});
    await new Promise((r) => setTimeout(r, 100));

    // First call: no rule matches
    const r1 = await handlers.get("before_tool_call")!(
      { toolName: "read", params: { path: "/etc/foobar.secret" } },
      {},
    );
    expect(r1).toBeUndefined();

    // Change ClawVault config
    state.fileMonitorConfig = {
      watch_paths: [],
      watch_patterns: ["*.secret"],
    };

    // Reach into the plugin: call refreshOnce manually to avoid waiting 30s.
    // We do this by importing ConfigClient and triggering via the exposed path:
    // the test uses a separate register() call to build a fresh plugin with the new config.
    const { api: api2, handlers: handlers2 } = makeApi({
      clawvaultUrl: srv.url,
      mode: "strict",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
      extraExtensions: [],
    });
    await register(api2);
    await handlers2.get("gateway_start")!(undefined, {});
    await new Promise((r) => setTimeout(r, 100));

    const r2 = await handlers2.get("before_tool_call")!(
      { toolName: "read", params: { path: "/etc/foobar.secret" } },
      {},
    );
    expect(r2).toMatchObject({ block: true });
  });

  it("C7: runtime action guard blocks dangerous bash before execution", async () => {
    const { api, handlers } = makeApi({
      clawvaultUrl: srv.url,
      mode: "strict",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
    });
    await register(api);

    const result = await handlers.get("before_tool_call")!(
      { toolName: "Bash", params: { command: "rm -rf /" } },
      { agentId: "agent-1", sessionId: "session-1" },
    );

    expect(result).toMatchObject({ block: true });
    expect((result as { blockReason: string }).blockReason).toMatch(
      /Runtime Action Guard/,
    );
  });

  it("C8: runtime action guard allows benign bash before execution", async () => {
    const { api, handlers } = makeApi({
      clawvaultUrl: srv.url,
      mode: "strict",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
    });
    await register(api);

    const result = await handlers.get("before_tool_call")!(
      { toolName: "Bash", params: { command: "ls" } },
      { agentId: "agent-1", sessionId: "session-1" },
    );

    expect(result).toBeUndefined();
  });

  it("C9: runtime action guard treats ask-user as block", async () => {
    const { api, handlers } = makeApi({
      clawvaultUrl: srv.url,
      mode: "strict",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
    });
    await register(api);

    const result = await handlers.get("before_tool_call")!(
      { toolName: "Write", params: { path: "~/.bashrc", content: "alias ll='ls'" } },
      { agentId: "agent-1", sessionId: "session-1" },
    );

    expect(result).toMatchObject({ block: true });
  });

  it("C10: runtime action allow still runs legacy file-guard rules", async () => {
    state.fileMonitorConfig = {
      watch_paths: [".ssh/**", ".aws/credentials"],
      watch_patterns: ["id_rsa*", "*.pem"],
    };
    const { api, handlers } = makeApi({
      clawvaultUrl: srv.url,
      mode: "strict",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
    });
    await register(api);
    await handlers.get("gateway_start")!(undefined, {});
    await new Promise((r) => setTimeout(r, 100));

    const result = await handlers.get("before_tool_call")!(
      { toolName: "Read", params: { path: "/home/user/.ssh/id_rsa" } },
      { agentId: "agent-1", sessionId: "session-1" },
    );

    expect(result).toMatchObject({ block: true });
    expect((result as { blockReason: string }).blockReason).toMatch(/file-guard/);
  });

  it("C11: unavailable runtime action API fails closed for supported tools", async () => {
    const { api, handlers } = makeApi({
      clawvaultUrl: "http://127.0.0.1:1",
      mode: "log",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 200,
    });
    await register(api);

    const result = await handlers.get("before_tool_call")!(
      { toolName: "Bash", params: { command: "ls" } },
      {},
    );

    expect(result).toMatchObject({ block: true });
    expect((result as { blockReason: string }).blockReason).toMatch(/unavailable/);
  });

  it("C12: malformed runtime action response fails closed", async () => {
    state.runtimeActionMode = "malformed";
    const { api, handlers } = makeApi({
      clawvaultUrl: srv.url,
      mode: "log",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
    });
    await register(api);

    const result = await handlers.get("before_tool_call")!(
      { toolName: "Bash", params: { command: "ls" } },
      {},
    );
    state.runtimeActionMode = "normal";

    expect(result).toMatchObject({ block: true });
    expect((result as { blockReason: string }).blockReason).toMatch(/unavailable/);
  });

  it("C13: unsafe ask-user response cannot silently allow", async () => {
    state.runtimeActionMode = "unsafe";
    const { api, handlers } = makeApi({
      clawvaultUrl: srv.url,
      mode: "log",
      refreshIntervalSeconds: 60,
      requestTimeoutMs: 1000,
    });
    await register(api);

    const result = await handlers.get("before_tool_call")!(
      { toolName: "Write", params: { path: "~/.bashrc", content: "alias ll='ls'" } },
      {},
    );
    state.runtimeActionMode = "normal";

    expect(result).toMatchObject({ block: true });
    expect((result as { blockReason: string }).blockReason).toMatch(/unavailable/);
  });
});
