# Rules

`mcp-secrets` reports static findings. It does not call any external service, validate whether a secret is active, or upload file contents.

## Secret rules

Provider-specific rules detect common token formats for OpenAI, Anthropic, GitHub, Google, Slack, Stripe, Hugging Face, database URLs, and private key blocks.

Generic assignment rules catch likely hardcoded values where the variable name contains words such as `API_KEY`, `TOKEN`, `SECRET`, `PASSWORD`, or `DATABASE_URL`.

Placeholder values such as `${GITHUB_TOKEN}`, `<your-token>`, `example`, and `changeme` are ignored.

## MCP rules

MCP config analysis currently checks JSON files containing `mcpServers` or `servers`.

The scanner reports:

- hardcoded secret values in `env` and `envs`
- unpinned `npx -y` packages
- shell execution through `sh`, `bash`, `zsh`, `cmd`, `powershell`, or `pwsh`
- broad filesystem access such as `/` or `~`
- insecure remote MCP URLs

## Severity

`critical` is reserved for private key material.

`high` usually means a credential value is present or an MCP config can expose a credential directly.

`medium` means a risky configuration should be reviewed before enabling the server.

`low` is informational and usually points to a trust boundary, such as a remote MCP server.
