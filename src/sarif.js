export function formatSarifReport(result) {
  const rules = new Map();

  for (const finding of result.findings) {
    if (!rules.has(finding.ruleId)) {
      rules.set(finding.ruleId, {
        id: finding.ruleId,
        shortDescription: { text: finding.title },
        help: { text: finding.remediation },
        defaultConfiguration: {
          level: sarifLevel(finding.severity)
        }
      });
    }
  }

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-secrets",
            informationUri: "https://github.com/vanhai1231/mcp-secrets",
            rules: [...rules.values()]
          }
        },
        results: result.findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: sarifLevel(finding.severity),
          message: {
            text: `${finding.title}. ${finding.remediation}`
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.path
                },
                region: {
                  startLine: finding.line,
                  startColumn: finding.column
                }
              }
            }
          ]
        }))
      }
    ]
  };
}

function sarifLevel(severity) {
  if (severity === "critical" || severity === "high") {
    return "error";
  }

  if (severity === "medium") {
    return "warning";
  }

  return "note";
}
