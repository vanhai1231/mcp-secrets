import { scan } from "./scanner.js";
import { formatTextReport } from "./report.js";
import { formatSarifReport } from "./sarif.js";

const SEVERITIES = ["low", "medium", "high", "critical"];

export async function runCli(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const cwd = io.cwd ?? process.cwd();

  if (argv.includes("--help") || argv.includes("-h")) {
    stdout.write(`${helpText()}\n`);
    return 0;
  }

  if (argv.includes("--version") || argv.includes("-v")) {
    stdout.write("mcp-secrets 0.1.0\n");
    return 0;
  }

  const args = [...argv];
  const command = args[0] && !args[0].startsWith("-") ? args.shift() : "scan";
  if (command !== "scan") {
    stderr.write(`Unknown command: ${command}\n\n${helpText()}\n`);
    return 2;
  }

  const options = parseScanArgs(args);
  const result = await scan(options.paths, {
    cwd,
    allFiles: options.allFiles,
    maxDepth: options.maxDepth
  });

  if (options.format === "json") {
    stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else if (options.format === "sarif") {
    stdout.write(`${JSON.stringify(formatSarifReport(result), null, 2)}\n`);
  } else {
    stdout.write(formatTextReport(result));
  }

  return shouldFail(result.findings, options.failOn) ? 1 : 0;
}

function parseScanArgs(args) {
  const options = {
    paths: [],
    format: "text",
    failOn: "high",
    allFiles: false,
    maxDepth: 8
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];

    if (arg === "--json") {
      options.format = "json";
    } else if (arg === "--sarif") {
      options.format = "sarif";
    } else if (arg === "--format") {
      const value = args[++index];
      if (!["text", "json", "sarif"].includes(value)) {
        throw new Error("--format must be one of: text, json, sarif");
      }
      options.format = value;
    } else if (arg === "--fail-on") {
      const value = args[++index];
      if (![...SEVERITIES, "none"].includes(value)) {
        throw new Error("--fail-on must be one of: low, medium, high, critical, none");
      }
      options.failOn = value;
    } else if (arg === "--all-files") {
      options.allFiles = true;
    } else if (arg === "--max-depth") {
      const value = Number.parseInt(args[++index], 10);
      if (!Number.isInteger(value) || value < 0) {
        throw new Error("--max-depth must be a non-negative integer");
      }
      options.maxDepth = value;
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      options.paths.push(arg);
    }
  }

  if (options.paths.length === 0) {
    options.paths.push(".");
  }

  return options;
}

function shouldFail(findings, failOn) {
  if (failOn === "none") {
    return false;
  }

  const threshold = SEVERITIES.indexOf(failOn);
  return findings.some((finding) => SEVERITIES.indexOf(finding.severity) >= threshold);
}

function helpText() {
  return `mcp-secrets

Find leaked secrets and risky patterns in MCP and AI agent configs.

Usage:
  mcp-secrets scan [paths...] [options]

Options:
  --format <text|json|sarif>  Output format. Defaults to text.
  --json                      Alias for --format json.
  --sarif                     Alias for --format sarif.
  --fail-on <severity>        Exit 1 at or above severity. Defaults to high.
  --all-files                 Scan every text-like file, not only known config files.
  --max-depth <number>        Directory recursion depth. Defaults to 8.
  -h, --help                  Show help.
  -v, --version               Show version.`;
}
