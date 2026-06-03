import assert from "node:assert/strict";
import test from "node:test";
import { detectSecrets } from "../src/secrets.js";

test("detects and redacts common provider secrets", () => {
  const content = [
    'OPENAI_API_KEY="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDE"',
    'DATABASE_URL="postgres://agent:password123@localhost:5432/app"'
  ].join("\n");

  const findings = detectSecrets(".env", content);

  assert.ok(findings.length >= 2);
  assert.ok(findings.some((finding) => finding.ruleId === "secret.openai-api-key"));
  assert.ok(findings.some((finding) => finding.ruleId === "secret.database-url"));
  assert.ok(findings.every((finding) => !finding.excerpt.includes("password123")));
  assert.ok(findings.every((finding) => !finding.excerpt.includes("1234567890ABCDE")));
});

test("ignores environment variable references", () => {
  const content = 'GITHUB_TOKEN="${GITHUB_TOKEN}"';
  const findings = detectSecrets(".env", content);
  assert.equal(findings.length, 0);
});
