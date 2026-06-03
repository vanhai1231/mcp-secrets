# Contributing

Thanks for helping improve `mcp-secrets`.

Please keep the project small and predictable:

- prefer rules that explain a concrete risk
- avoid network calls in the scanner
- redact matched values in all human-readable output
- add a fixture and a test for every new rule

Run the checks before opening a pull request:

```sh
npm test
npm run scan -- fixtures --fail-on critical
```
