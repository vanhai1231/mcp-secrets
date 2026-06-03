export function createFinding(input) {
  return {
    ruleId: input.ruleId,
    title: input.title,
    severity: input.severity,
    path: input.path,
    line: input.line,
    column: input.column,
    excerpt: input.excerpt.trim(),
    remediation: input.remediation
  };
}

export function getLineInfo(content, index) {
  const safeIndex = Math.max(0, index ?? 0);
  const before = content.slice(0, safeIndex);
  const line = before.split("\n").length;
  const lineStart = content.lastIndexOf("\n", safeIndex - 1) + 1;
  const lineEnd = content.indexOf("\n", safeIndex);
  const end = lineEnd === -1 ? content.length : lineEnd;

  return {
    line,
    column: safeIndex - lineStart + 1,
    lineText: content.slice(lineStart, end)
  };
}

export function redactValue(value) {
  const text = String(value);

  if (text.includes("://") && text.includes("@")) {
    return text.replace(/:\/\/([^:\s]+):([^@\s]+)@/, "://$1:***@");
  }

  if (text.length <= 10) {
    return "***";
  }

  return `${text.slice(0, 6)}...${text.slice(-4)}`;
}
