// src/config-client.ts
import axios from "axios";
var DEFAULT_WATCH_PATHS = [
  ".ssh/**",
  ".aws/credentials",
  ".aws/config",
  ".gnupg/**",
  ".kube/config"
];
var DEFAULT_WATCH_PATTERNS = ["id_rsa*", "id_ed25519*", "*.pem", ".env*"];
var ConfigClient = class {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.http = axios.create({
      baseURL: config.clawvaultUrl.replace(/\/+$/, ""),
      timeout: config.requestTimeoutMs
    });
    this.rules = {
      watchPaths: [...DEFAULT_WATCH_PATHS, ...config.extraPaths],
      watchPatterns: [...DEFAULT_WATCH_PATTERNS],
      extensions: [...config.extraExtensions]
    };
  }
  config;
  logger;
  rules;
  timer = null;
  http;
  getRules() {
    return this.rules;
  }
  async refreshOnce() {
    try {
      const res = await this.http.get("/api/config/file-monitor");
      const data = res.data ?? {};
      const watchPaths = Array.isArray(data.watch_paths) ? data.watch_paths.filter((s) => typeof s === "string") : [];
      const watchPatterns = Array.isArray(data.watch_patterns) ? data.watch_patterns.filter((s) => typeof s === "string") : [];
      this.rules = {
        watchPaths: [...watchPaths, ...this.config.extraPaths],
        watchPatterns,
        extensions: [...this.config.extraExtensions]
      };
      this.logger.debug(
        `config refreshed: ${watchPaths.length} paths, ${watchPatterns.length} patterns`
      );
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`config refresh failed, keeping previous rules: ${msg}`);
      return false;
    }
  }
  start() {
    void this.refreshOnce();
    if (this.timer) return;
    const intervalMs = Math.max(5e3, this.config.refreshIntervalSeconds * 1e3);
    this.timer = setInterval(() => void this.refreshOnce(), intervalMs);
    if (typeof this.timer.unref === "function") this.timer.unref();
  }
  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
};

// src/runtime-action-client.ts
import axios2 from "axios";
var RuntimeActionClient = class {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.http = axios2.create({
      baseURL: config.clawvaultUrl.replace(/\/+$/, ""),
      timeout: config.requestTimeoutMs
    });
  }
  config;
  logger;
  http;
  supports(event) {
    const toolName = event.toolName.toLowerCase();
    return toolName === "bash" || toolName === "read" || toolName === "write";
  }
  async evaluate(event, ctx) {
    try {
      const res = await this.http.post("/api/openclaw/runtime-action", {
        tool_name: event.toolName,
        params: event.params ?? {},
        agent_id: ctx?.agentId,
        session_id: ctx?.sessionId ?? ctx?.sessionKey
      });
      return parseDecision(res.data, event.toolName);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`runtime action guard unavailable: ${msg}`);
      return failClosed(event.toolName, "Runtime Action Guard unavailable");
    }
  }
};
function parseDecision(data, toolName) {
  if (!data || typeof data !== "object") {
    throw new Error("malformed runtime action decision");
  }
  const value = data;
  if (!isDecision(value.decision) || !isRiskLevel(value.risk_level) || !Array.isArray(value.reasons) || !Array.isArray(value.categories) || typeof value.action_type !== "string" || typeof value.target_summary !== "string" || typeof value.redacted_summary !== "string" || typeof value.should_block !== "boolean" || typeof value.audit_recorded !== "boolean") {
    throw new Error("malformed runtime action decision");
  }
  if (value.decision !== "allow" && value.should_block !== true) {
    throw new Error("unsafe runtime action decision");
  }
  return {
    decision: value.decision,
    risk_level: value.risk_level,
    reasons: value.reasons.filter((item) => typeof item === "string"),
    categories: value.categories.filter((item) => typeof item === "string"),
    action_type: value.action_type,
    target_summary: value.target_summary,
    redacted_summary: value.redacted_summary,
    should_block: value.should_block,
    block_reason: value.block_reason,
    audit_recorded: value.audit_recorded
  };
}
function failClosed(toolName, reason) {
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
    audit_recorded: false
  };
}
function isDecision(value) {
  return value === "allow" || value === "block" || value === "ask-user";
}
function isRiskLevel(value) {
  return value === "low" || value === "medium" || value === "high" || value === "critical";
}

// src/reporter.ts
import axios3 from "axios";
var Reporter = class {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.http = axios3.create({
      baseURL: config.clawvaultUrl.replace(/\/+$/, ""),
      timeout: config.requestTimeoutMs
    });
  }
  config;
  logger;
  http;
  async report(event) {
    try {
      await this.http.post("/api/events/external", event);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`report to ClawVault failed: ${msg}`);
    }
  }
};

// src/sanitize-intent.ts
var SANITIZE_PATTERNS = [
  /^(?:\u8bf7)?(?:\u5e2e\u6211)?(?:\u8131\u654f\u4fe1\u606f|\u654f\u611f\u4fe1\u606f\u8131\u654f|\u4fe1\u606f\u8131\u654f|\u8131\u654f)[\uff1a:\s]+(?<text>[\s\S]+)$/u,
  /^(?:sanitize|redact|mask)[\uff1a:\s]+(?<text>[\s\S]+)$/iu
];
var SANITIZE_USAGE_TERMS = /* @__PURE__ */ new Set([
  "\u8131\u654F",
  "\u8131\u654F\u4FE1\u606F",
  "\u654F\u611F\u4FE1\u606F\u8131\u654F",
  "\u4FE1\u606F\u8131\u654F",
  "sanitize",
  "redact",
  "mask"
]);
var SANITIZE_QUESTION_RE = /(?:\u4ec0\u4e48\u662f|\u662f\u4ec0\u4e48\u610f\u601d|what is|explain|\u4ecb\u7ecd).*(?:\u8131\u654f|sanitize|redact|mask)/iu;
function stripTimestampPrefix(text) {
  return text.replace(/^\[[^\]]{1,80}\]\s*/u, "");
}
function parseSanitizeIntent(prompt) {
  const text = stripTimestampPrefix(prompt.trim());
  if (!text) return { action: "none" };
  const mentionPrefix = "@clawvault";
  if (!text.toLowerCase().startsWith(mentionPrefix)) return { action: "none" };
  const normalized = text.slice(mentionPrefix.length).trim();
  if (!normalized) return { action: "none" };
  if (SANITIZE_QUESTION_RE.test(normalized)) return { action: "none" };
  if (SANITIZE_USAGE_TERMS.has(normalized.toLowerCase())) {
    return { action: "usage" };
  }
  for (const pattern of SANITIZE_PATTERNS) {
    const match = pattern.exec(normalized);
    const payload = match?.groups?.text?.trim();
    if (payload) return { action: "sanitize", text: payload };
  }
  return { action: "none" };
}

// src/path-detector.ts
import * as path from "path";
import os from "os";
import picomatch from "picomatch";
var CANDIDATE_PARAM_KEYS = [
  "path",
  "file",
  "file_path",
  "filename",
  "filepath",
  "src",
  "source",
  "target",
  "dst",
  "destination",
  "input_file",
  "output_file",
  "input",
  "output"
];
var SHELL_LIKE_TOOLS = /* @__PURE__ */ new Set([
  "bash",
  "shell",
  "sh",
  "exec",
  "execute",
  "run_command",
  "run",
  "cmd",
  "terminal",
  "process",
  "computer"
]);
var FILE_READ_TOOLS = /* @__PURE__ */ new Set([
  "read",
  "read_file",
  "open",
  "cat",
  "view",
  "view_file",
  "load",
  "fetch_file"
]);
var FILE_WRITE_TOOLS = /* @__PURE__ */ new Set([
  "write",
  "write_file",
  "edit",
  "edit_file",
  "append",
  "save"
]);
function normalizeHome(p) {
  if (p.startsWith("~/") || p === "~") {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}
function looksLikePath(token) {
  if (!token) return false;
  if (token.length < 2) return false;
  if (token.startsWith("-")) return false;
  return token.startsWith("/") || token.startsWith("~/") || token.startsWith("./") || token.startsWith("../") || /\.[A-Za-z0-9]{1,8}$/.test(token) || /\/[^\s]+/.test(token);
}
function splitShellArgs(cmd) {
  const tokens = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(cmd)) !== null) {
    tokens.push(m[1] ?? m[2] ?? m[3] ?? "");
  }
  return tokens;
}
function extractCandidatePaths(toolName, params) {
  const out = /* @__PURE__ */ new Set();
  const lowerTool = (toolName || "").toLowerCase();
  for (const key of CANDIDATE_PARAM_KEYS) {
    const v = params[key];
    if (typeof v === "string" && v.trim()) out.add(normalizeHome(v.trim()));
    if (Array.isArray(v)) {
      for (const item of v) {
        if (typeof item === "string" && item.trim()) {
          out.add(normalizeHome(item.trim()));
        }
      }
    }
  }
  if (SHELL_LIKE_TOOLS.has(lowerTool)) {
    const cmd = params.command ?? params.cmd ?? params.script ?? "";
    if (typeof cmd === "string" && cmd) {
      for (const tok of splitShellArgs(cmd)) {
        if (looksLikePath(tok)) out.add(normalizeHome(tok));
      }
    }
  }
  if (FILE_READ_TOOLS.has(lowerTool) || FILE_WRITE_TOOLS.has(lowerTool)) {
    for (const v of Object.values(params)) {
      if (typeof v === "string" && looksLikePath(v)) {
        out.add(normalizeHome(v.trim()));
      }
    }
  }
  return [...out];
}
function basename(p) {
  const idx = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  return idx >= 0 ? p.slice(idx + 1) : p;
}
function matchPath(candidate, rules) {
  const lower = candidate.toLowerCase();
  for (const ext of rules.extensions) {
    if (!ext) continue;
    const e = ext.startsWith(".") ? ext.toLowerCase() : "." + ext.toLowerCase();
    if (lower.endsWith(e)) return `ext:${e}`;
  }
  const globs = [...rules.watchPaths, ...rules.watchPatterns];
  for (const g of globs) {
    if (!g) continue;
    const hasSlash = g.includes("/");
    const anchored = g.startsWith("/") || g.startsWith("**");
    const opts = { dot: true, basename: !hasSlash };
    const matchers = [picomatch(g, opts)];
    if (hasSlash && !anchored) {
      matchers.push(picomatch("**/" + g, opts));
    }
    const base = basename(candidate);
    for (const m of matchers) {
      if (m(candidate) || m(base)) return g;
    }
  }
  return null;
}
function detect(toolName, params, rules) {
  for (const candidate of extractCandidatePaths(toolName, params)) {
    const matched = matchPath(candidate, rules);
    if (matched) return { path: candidate, matchedRule: matched };
  }
  return null;
}

// index.ts
function readConfig(api) {
  const raw = {
    ...api.config ?? {},
    ...api.pluginConfig ?? {}
  };
  const get = (key, fallback) => raw[key] !== void 0 ? raw[key] : fallback;
  return {
    clawvaultUrl: get("clawvaultUrl", "http://127.0.0.1:8766"),
    mode: get("mode", "log"),
    localSanitize: get("localSanitize", true),
    extraPaths: get("extraPaths", []),
    extraExtensions: get("extraExtensions", [
      ".pem",
      ".key",
      ".p12",
      ".pfx",
      ".kdbx"
    ]),
    refreshIntervalSeconds: get("refreshIntervalSeconds", 30),
    requestTimeoutMs: get("requestTimeoutMs", 2e3)
  };
}
function register(api) {
  const logger = api.logger;
  const runtimeCfg = readConfig(api);
  logger.info(
    `[file-guard] starting, clawvault=${runtimeCfg.clawvaultUrl} mode=${runtimeCfg.mode}`
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
    async (rawEvent, ctx) => {
      if (!runtimeCfg.localSanitize) return;
      const event = rawEvent;
      const prompt = typeof event?.prompt === "string" ? event.prompt : "";
      const intent = parseSanitizeIntent(prompt);
      if (intent.action === "none") return;
      if (intent.action === "usage") {
        return {
          outcome: "block",
          reason: "clawvault_sanitize_usage",
          message: "Usage: @clawvault sanitize <text>"
        };
      }
      return void 0;
    },
    { priority: 100, timeoutMs: Math.max(runtimeCfg.requestTimeoutMs + 500, 2500) }
  );
  api.on(
    "before_tool_call",
    async (rawEvent, ctx) => {
      try {
        const event = rawEvent;
        if (!event || typeof event.toolName !== "string") return;
        const params = event.params ?? {};
        if (runtimeActionClient.supports(event)) {
          const decision = await runtimeActionClient.evaluate(event, ctx);
          if (decision) {
            if (decision.should_block) {
              logger.warn(
                `[runtime-action] BLOCK ${event.toolName} (${decision.risk_level})`
              );
              return {
                block: true,
                blockReason: decision.block_reason ?? `ClawVault Runtime Action Guard: ${decision.decision}`
              };
            }
            logger.info(
              `[runtime-action] ALLOW ${event.toolName} (${decision.risk_level})`
            );
          }
        }
        const rules = configClient.getRules();
        const hit = detect(event.toolName, params, rules);
        if (!hit) return;
        const action = runtimeCfg.mode === "strict" ? "block" : "log";
        const severity = action === "block" ? "high" : "medium";
        const message = action === "block" ? `Blocked tool call '${event.toolName}' targeting sensitive path` : `Logged tool call '${event.toolName}' targeting sensitive path`;
        void reporter.report({
          source: "openclaw-file-guard",
          category: action === "block" ? "file_access_blocked" : "file_access_logged",
          threat_level: severity,
          action,
          tool_name: event.toolName,
          file_path: hit.path,
          matched_rule: hit.matchedRule,
          agent_id: ctx?.agentId,
          session_id: ctx?.sessionId ?? ctx?.sessionKey,
          message,
          risk_score: action === "block" ? 8.5 : 6
        });
        if (action === "block") {
          logger.warn(
            `[file-guard] BLOCK ${event.toolName} ${hit.path} (rule=${hit.matchedRule})`
          );
          return {
            block: true,
            blockReason: `ClawVault file-guard: sensitive path '${hit.path}' (rule ${hit.matchedRule})`
          };
        }
        logger.info(
          `[file-guard] LOG ${event.toolName} ${hit.path} (rule=${hit.matchedRule})`
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error(`[file-guard] handler error: ${msg}`);
        const event = rawEvent;
        if (typeof event?.toolName === "string" && runtimeActionClient.supports(event)) {
          return {
            block: true,
            blockReason: `ClawVault Runtime Action Guard unavailable for ${event.toolName}`
          };
        }
      }
    }
  );
}
export {
  register as default
};
