import fs from "node:fs/promises";
import path from "node:path";
import { detectSecrets } from "./secrets.js";
import { analyzeMcpConfig } from "./mcp.js";

const EXCLUDED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "coverage",
  ".next",
  ".turbo",
  ".cache"
]);

const TARGET_BASENAMES = new Set([
  ".mcp.json",
  "mcp.json",
  "claude_desktop_config.json",
  "agents.md",
  "claude.md",
  "gemini.md",
  "codex.md"
]);

const TEXT_EXTENSIONS = new Set([
  ".json",
  ".jsonc",
  ".md",
  ".toml",
  ".yaml",
  ".yml",
  ".env",
  ".txt",
  ".js",
  ".ts",
  ".mjs",
  ".cjs"
]);

const MAX_FILE_BYTES = 1024 * 1024;

export async function scan(inputPaths = ["."], options = {}) {
  const cwd = options.cwd ?? process.cwd();
  const files = await collectFiles(inputPaths, {
    cwd,
    allFiles: options.allFiles ?? false,
    maxDepth: options.maxDepth ?? 8
  });

  const findings = [];
  let scannedFiles = 0;

  for (const filePath of files) {
    const content = await readSmallTextFile(filePath);
    if (content === null) {
      continue;
    }

    scannedFiles += 1;
    const relativePath = path.relative(cwd, filePath) || path.basename(filePath);
    findings.push(...detectSecrets(relativePath, content));
    findings.push(...analyzeMcpConfig(relativePath, content));
  }

  findings.sort(compareFindings);

  return {
    scannedFiles,
    findings,
    summary: summarize(findings)
  };
}

async function collectFiles(inputPaths, options) {
  const files = [];

  for (const inputPath of inputPaths) {
    const absolutePath = path.resolve(options.cwd, inputPath);
    let stat;
    try {
      stat = await fs.stat(absolutePath);
    } catch {
      continue;
    }

    if (stat.isDirectory()) {
      await walkDirectory(absolutePath, files, options, 0);
    } else if (stat.isFile() && shouldScanFile(absolutePath, options.allFiles)) {
      files.push(absolutePath);
    }
  }

  return [...new Set(files)].sort();
}

async function walkDirectory(directory, files, options, depth) {
  if (depth > options.maxDepth) {
    return;
  }

  let entries;
  try {
    entries = await fs.readdir(directory, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (!EXCLUDED_DIRECTORIES.has(entry.name)) {
        await walkDirectory(entryPath, files, options, depth + 1);
      }
    } else if (entry.isFile() && shouldScanFile(entryPath, options.allFiles)) {
      files.push(entryPath);
    }
  }
}

function shouldScanFile(filePath, allFiles) {
  if (allFiles) {
    return isTextLike(filePath);
  }

  const normalized = filePath.split(path.sep).join("/");
  const basename = path.basename(filePath).toLowerCase();

  if (TARGET_BASENAMES.has(basename)) {
    return true;
  }

  if (basename === ".env" || basename.startsWith(".env.")) {
    return true;
  }

  if (normalized.includes("/.cursor/rules/") && [".md", ".mdc", ".txt"].includes(path.extname(filePath))) {
    return true;
  }

  if (normalized.includes("/.claude/") && [".json", ".md"].includes(path.extname(filePath))) {
    return true;
  }

  if (normalized.includes("/.codex/") && [".toml", ".md", ".json"].includes(path.extname(filePath))) {
    return true;
  }

  if (basename.includes("mcp") && [".json", ".jsonc", ".toml", ".yaml", ".yml", ".md"].includes(path.extname(filePath))) {
    return true;
  }

  return false;
}

function isTextLike(filePath) {
  const basename = path.basename(filePath);
  const extension = path.extname(filePath).toLowerCase();
  return TEXT_EXTENSIONS.has(extension) || basename.startsWith(".env");
}

async function readSmallTextFile(filePath) {
  let stat;
  try {
    stat = await fs.stat(filePath);
  } catch {
    return null;
  }

  if (stat.size > MAX_FILE_BYTES) {
    return null;
  }

  const buffer = await fs.readFile(filePath);
  if (buffer.includes(0)) {
    return null;
  }

  return buffer.toString("utf8");
}

function summarize(findings) {
  return findings.reduce(
    (summary, finding) => {
      summary[finding.severity] += 1;
      return summary;
    },
    { critical: 0, high: 0, medium: 0, low: 0 }
  );
}

function compareFindings(a, b) {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  return (
    severityOrder[a.severity] - severityOrder[b.severity] ||
    a.path.localeCompare(b.path) ||
    a.line - b.line ||
    a.ruleId.localeCompare(b.ruleId)
  );
}
