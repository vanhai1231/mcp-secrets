import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { scan } from "../src/scanner.js";

const cwd = path.resolve("fixtures");

test("scans known MCP config files", async () => {
  const result = await scan(["vulnerable"], { cwd });
  const ruleIds = result.findings.map((finding) => finding.ruleId);

  assert.ok(ruleIds.includes("mcp.hardcoded-env-secret"));
  assert.ok(ruleIds.includes("mcp.unpinned-npx-package"));
  assert.ok(ruleIds.includes("secret.github-token"));
  assert.ok(result.summary.high >= 1);
});

test("does not flag placeholder-based config", async () => {
  const result = await scan(["safe"], { cwd });
  assert.equal(result.findings.length, 0);
});
