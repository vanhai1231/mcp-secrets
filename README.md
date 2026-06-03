# mcp-secrets

Find and fix leaked secrets in MCP and AI agent configs.

AI agents now read local config, start MCP servers, call tools, and inherit credentials from developer machines. `mcp-secrets` is a small CLI for checking those files before they land in a repository.

It focuses on the places where agent credentials usually leak:

- MCP server configs
- Claude, Codex, Cursor, and Gemini agent files
- `.env` files
- Markdown instructions such as `AGENTS.md` and `CLAUDE.md`

## Install

Until the npm package is published, run it from the repository:

```sh
git clone https://github.com/vanhai1231/mcp-secrets.git
cd mcp-secrets
npm test
node ./bin/mcp-secrets.js scan fixtures/safe
```

After npm publishing:

```sh
npx mcp-secrets scan
```

## Usage

Scan the current repository:

```sh
mcp-secrets scan
```

Scan specific paths:

```sh
mcp-secrets scan .mcp.json .claude AGENTS.md
```

Return JSON:

```sh
mcp-secrets scan --json
```

Return SARIF for code scanning tools:

```sh
mcp-secrets scan --sarif
```

Control CI failure behavior:

```sh
mcp-secrets scan --fail-on medium
```

By default, the command fails on `high` and `critical` findings.

## What it detects

The first rule set detects:

- provider keys such as OpenAI, Anthropic, GitHub, Google, Slack, Stripe, and Hugging Face tokens
- database URLs with embedded credentials
- private key blocks
- generic secret assignments such as `API_KEY=...`
- hardcoded secret values inside MCP `env` blocks
- unpinned `npx -y` MCP packages
- shell-based MCP commands that should be reviewed
- broad filesystem MCP access
- remote MCP URLs, especially insecure `http://` endpoints

The scanner redacts matched values in its output.

## GitHub Actions

This repository includes a composite action:

```yaml
name: mcp-secrets

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vanhai1231/mcp-secrets@main
        with:
          path: .
          fail-on: high
```

## Development

```sh
npm test
npm run scan -- fixtures --fail-on critical
```

The project intentionally has no runtime dependencies. Tests use the built-in Node test runner.

## License

Apache-2.0
