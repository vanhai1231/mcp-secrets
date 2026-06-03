const SEVERITY_LABELS = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW"
};

export function formatTextReport(result) {
  const lines = [];
  const count = result.findings.length;

  lines.push("mcp-secrets");
  lines.push(`Scanned ${result.scannedFiles} file${result.scannedFiles === 1 ? "" : "s"}.`);

  if (count === 0) {
    lines.push("No leaked secrets or risky MCP patterns found.");
    return `${lines.join("\n")}\n`;
  }

  lines.push(`Found ${count} finding${count === 1 ? "" : "s"}.`);
  lines.push("");

  for (const finding of result.findings) {
    lines.push(`${SEVERITY_LABELS[finding.severity]} ${finding.ruleId}`);
    lines.push(`${finding.path}:${finding.line}:${finding.column}`);
    lines.push(finding.title);

    if (finding.excerpt) {
      lines.push(`  ${finding.excerpt}`);
    }

    lines.push(`Fix: ${finding.remediation}`);
    lines.push("");
  }

  return lines.join("\n");
}
