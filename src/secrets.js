import { createFinding, getLineInfo, redactValue } from "./util.js";

const SECRET_RULES = [
  {
    ruleId: "secret.openai-api-key",
    title: "OpenAI API key",
    severity: "high",
    regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g,
    remediation: "Move the key to a secret manager or environment variable, then rotate it."
  },
  {
    ruleId: "secret.anthropic-api-key",
    title: "Anthropic API key",
    severity: "high",
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    remediation: "Move the key to a secret manager or environment variable, then rotate it."
  },
  {
    ruleId: "secret.github-token",
    title: "GitHub token",
    severity: "high",
    regex: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/g,
    remediation: "Revoke the token, create a scoped replacement, and reference it through the environment."
  },
  {
    ruleId: "secret.google-api-key",
    title: "Google API key",
    severity: "high",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    remediation: "Restrict and rotate the key, then load it from a secure runtime source."
  },
  {
    ruleId: "secret.aws-access-key",
    title: "AWS access key ID",
    severity: "high",
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    remediation: "Disable the key pair and replace it with scoped, short-lived credentials."
  },
  {
    ruleId: "secret.slack-token",
    title: "Slack token",
    severity: "high",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
    remediation: "Revoke the token in Slack and inject the replacement through the environment."
  },
  {
    ruleId: "secret.stripe-key",
    title: "Stripe secret key",
    severity: "high",
    regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    remediation: "Roll the key in Stripe and remove it from committed configuration."
  },
  {
    ruleId: "secret.huggingface-token",
    title: "Hugging Face token",
    severity: "high",
    regex: /\bhf_[A-Za-z0-9]{20,}\b/g,
    remediation: "Revoke the token and reference the new value through the environment."
  },
  {
    ruleId: "secret.database-url",
    title: "Database URL with embedded credentials",
    severity: "high",
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>:]+:[^\s"'<>@]+@[^\s"'<>]+/gi,
    remediation: "Move the URL to a secret store and rotate the embedded credential."
  },
  {
    ruleId: "secret.private-key",
    title: "Private key block",
    severity: "critical",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
    remediation: "Remove the private key from the repository and rotate any dependent certificate or credential."
  }
];

const GENERIC_ASSIGNMENT =
  /\b([A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASS|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)[A-Z0-9_]*)\b\s*[:=]\s*["']?([^"',\s;}]{12,})/gi;

export function detectSecrets(filePath, content) {
  const findings = [];

  for (const rule of SECRET_RULES) {
    for (const match of content.matchAll(rule.regex)) {
      const value = match[0];
      if (isPlaceholder(value)) {
        continue;
      }

      findings.push(
        createFinding({
          ruleId: rule.ruleId,
          title: rule.title,
          severity: rule.severity,
          path: filePath,
          ...getLineInfo(content, match.index ?? 0),
          excerpt: redactLine(content, match.index ?? 0, value),
          remediation: rule.remediation
        })
      );
    }
  }

  for (const match of content.matchAll(GENERIC_ASSIGNMENT)) {
    const [, name, value] = match;
    if (isPlaceholder(value) || looksLikePublicIdentifier(name, value)) {
      continue;
    }

    findings.push(
      createFinding({
        ruleId: "secret.generic-assignment",
        title: `Potential hardcoded secret: ${name}`,
        severity: "medium",
        path: filePath,
        ...getLineInfo(content, match.index ?? 0),
        excerpt: redactLine(content, match.index ?? 0, value),
        remediation: "Replace the literal value with an environment variable or a secret manager reference."
      })
    );
  }

  return dedupeFindings(findings);
}

export function isSensitiveName(name) {
  return /(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASS|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|DATABASE_URL|DB_URL|CONNECTION_STRING)/i.test(
    name
  );
}

export function isPlaceholder(value) {
  const normalized = String(value).trim();
  if (!normalized) {
    return true;
  }

  return (
    /^\$\{?[A-Z0-9_]+\}?$/i.test(normalized) ||
    /^%[A-Z0-9_]+%$/i.test(normalized) ||
    /^<[^>]+>$/.test(normalized) ||
    /\b(your|example|sample|dummy|test|changeme|replace_me|placeholder|token_here|api_key_here)\b/i.test(normalized)
  );
}

function looksLikePublicIdentifier(name, value) {
  if (/PUBLIC|PUBLISHABLE|CLIENT/i.test(name)) {
    return true;
  }

  return value.length < 16;
}

function redactLine(content, index, value) {
  const { lineText } = getLineInfo(content, index);
  return lineText.replace(value, redactValue(value));
}

function dedupeFindings(findings) {
  const seen = new Set();
  const result = [];

  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.path}:${finding.line}:${finding.column}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(finding);
    }
  }

  return result;
}
