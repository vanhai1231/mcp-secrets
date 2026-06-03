import path from "node:path";
import { createFinding, getLineInfo, redactValue } from "./util.js";
import { isPlaceholder, isSensitiveName } from "./secrets.js";

export function analyzeMcpConfig(filePath, content) {
  if (!looksLikeMcpConfig(filePath, content)) {
    return [];
  }

  const parsed = parseJson(content);
  if (!parsed) {
    return [];
  }

  const servers = collectServers(parsed);
  const findings = [];

  for (const server of servers) {
    findings.push(...analyzeServer(filePath, content, server));
  }

  return findings;
}

function looksLikeMcpConfig(filePath, content) {
  const normalized = filePath.toLowerCase();
  return (
    normalized.endsWith(".json") &&
    (normalized.includes("mcp") ||
      normalized.includes("claude") ||
      content.includes('"mcpServers"') ||
      content.includes('"servers"'))
  );
}

function parseJson(content) {
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}

function collectServers(value) {
  const servers = [];

  if (isPlainObject(value.mcpServers)) {
    for (const [name, config] of Object.entries(value.mcpServers)) {
      if (isPlainObject(config)) {
        servers.push({ name, config });
      }
    }
  }

  if (isPlainObject(value.servers)) {
    for (const [name, config] of Object.entries(value.servers)) {
      if (isPlainObject(config)) {
        servers.push({ name, config });
      }
    }
  }

  return servers;
}

function analyzeServer(filePath, content, server) {
  return [
    ...analyzeEnv(filePath, content, server),
    ...analyzeCommand(filePath, content, server),
    ...analyzeRemoteUrl(filePath, content, server)
  ];
}

function analyzeEnv(filePath, content, server) {
  const findings = [];

  for (const field of ["env", "envs"]) {
    const env = server.config[field];
    if (!isPlainObject(env)) {
      continue;
    }

    for (const [name, value] of Object.entries(env)) {
      if (!isSensitiveName(name) || typeof value !== "string" || isPlaceholder(value)) {
        continue;
      }

      const index = findKeyIndex(content, name);
      findings.push(
        createFinding({
          ruleId: "mcp.hardcoded-env-secret",
          title: `Hardcoded secret in MCP env: ${server.name}.${name}`,
          severity: "high",
          path: filePath,
          ...getLineInfo(content, index),
          excerpt: redactLine(content, index, value),
          remediation: "Use an environment variable reference or a secret store, then rotate the exposed value."
        })
      );
    }
  }

  return findings;
}

function analyzeCommand(filePath, content, server) {
  const findings = [];
  const command = typeof server.config.command === "string" ? server.config.command : "";
  const args = Array.isArray(server.config.args) ? server.config.args.map(String) : [];
  const commandName = path.basename(command).toLowerCase();

  if (commandName === "npx" && hasArg(args, "-y")) {
    const packageName = firstPackageArg(args);
    if (packageName && !isPinnedPackage(packageName)) {
      const index = findValueIndex(content, packageName);
      findings.push(
        createFinding({
          ruleId: "mcp.unpinned-npx-package",
          title: `Unpinned MCP package: ${packageName}`,
          severity: "medium",
          path: filePath,
          ...getLineInfo(content, index),
          excerpt: getLineInfo(content, index).lineText,
          remediation: "Pin the package version so the MCP server cannot change unexpectedly."
        })
      );
    }
  }

  if (["sh", "bash", "zsh", "cmd", "powershell", "pwsh"].includes(commandName) && hasShellExecutionArg(args)) {
    const joinedArgs = args.join(" ");
    const severity = /(?:curl|wget).*(?:\||&&|\bsh\b|\bbash\b)/i.test(joinedArgs) ? "high" : "medium";
    const index = findValueIndex(content, command);
    findings.push(
      createFinding({
        ruleId: "mcp.shell-command",
        title: `Shell command used by MCP server: ${server.name}`,
        severity,
        path: filePath,
        ...getLineInfo(content, index),
        excerpt: getLineInfo(content, index).lineText,
        remediation: "Prefer a direct executable with fixed arguments. Review any shell pipeline before enabling it."
      })
    );
  }

  if (looksLikeFilesystemServer(server, command, args) && grantsBroadFilesystemAccess(args)) {
    const index = findValueIndex(content, args.find((arg) => arg === "/" || arg === "~") ?? command);
    findings.push(
      createFinding({
        ruleId: "mcp.broad-filesystem-access",
        title: `Broad filesystem access for MCP server: ${server.name}`,
        severity: "medium",
        path: filePath,
        ...getLineInfo(content, index),
        excerpt: getLineInfo(content, index).lineText,
        remediation: "Limit filesystem MCP servers to the smallest directories the agent needs."
      })
    );
  }

  return findings;
}

function analyzeRemoteUrl(filePath, content, server) {
  if (typeof server.config.url !== "string") {
    return [];
  }

  const index = findValueIndex(content, server.config.url);
  const insecure = server.config.url.startsWith("http://");

  return [
    createFinding({
      ruleId: insecure ? "mcp.insecure-remote-url" : "mcp.remote-server",
      title: insecure ? `Insecure MCP remote URL: ${server.name}` : `Remote MCP server: ${server.name}`,
      severity: insecure ? "high" : "low",
      path: filePath,
      ...getLineInfo(content, index),
      excerpt: getLineInfo(content, index).lineText,
      remediation: insecure
        ? "Use HTTPS and review the remote server before enabling it."
        : "Review remote MCP servers before granting tool access."
    })
  ];
}

function hasArg(args, expected) {
  return args.some((arg) => arg === expected);
}

function firstPackageArg(args) {
  return args.find((arg) => !arg.startsWith("-") && !arg.includes("="));
}

function isPinnedPackage(packageName) {
  if (packageName.startsWith("@")) {
    const parts = packageName.split("@");
    return parts.length >= 3 && parts[2].length > 0;
  }

  return packageName.includes("@");
}

function hasShellExecutionArg(args) {
  return args.some((arg) => arg === "-c" || arg === "/c" || arg === "-Command");
}

function looksLikeFilesystemServer(server, command, args) {
  const text = [server.name, command, ...args].join(" ").toLowerCase();
  return text.includes("filesystem") || text.includes("file-system");
}

function grantsBroadFilesystemAccess(args) {
  return args.some((arg) => arg === "/" || arg === "~" || arg === "$HOME" || arg === "%USERPROFILE%");
}

function findKeyIndex(content, key) {
  const quoted = `"${key}"`;
  const index = content.indexOf(quoted);
  return index >= 0 ? index : 0;
}

function findValueIndex(content, value) {
  const index = content.indexOf(value);
  return index >= 0 ? index : 0;
}

function redactLine(content, index, value) {
  const { lineText } = getLineInfo(content, index);
  return lineText.replace(value, redactValue(value));
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
