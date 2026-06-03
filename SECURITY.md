# Security

Please report security issues privately to the repository owner before opening a public issue.

`mcp-secrets` is a static scanner. It does not upload file contents, call external APIs, or validate whether a detected credential is live.

If the tool reports a real secret, rotate it. Removing the value from the latest commit is not enough if it already exists in Git history.
