# Good first issues

Small, self-contained pieces of work, each with existing tests or a pattern to copy. They are open in the issue
tracker: [good first issues](https://github.com/cipherfort/fortproof/issues?q=is%3Aopen+label%3A%22good+first+issue%22)
and [help wanted](https://github.com/cipherfort/fortproof/issues?q=is%3Aopen+label%3A%22help+wanted%22). Comment on one to
take it; a maintainer will help. The Prometheus metrics and AWS identity items are now on the
[roadmap](../../ROADMAP.md) (0.3).

| Issue | Where to start | Pattern to copy |
|---|---|---|
| A ServiceNow ticketing plugin | `examples/plugins/aap-plugin-jsonl`, [plugin guide](../develop/plugins.md) | `connectors/issues.py` (GitLabIssues) |
| A Prowler import plugin (cloud posture) | `services/cloud_sync.py` | `connectors/cloud.py` |
| GitHub Advisory Database as a vulnerability feed | `connectors/vuln_feeds.py` | `OsvClient` |
| More end-of-life product mappings | `config/eol-products.yaml` | existing entries |
| A `financial-services` classification profile | `config/profiles/` | `generic/` |
| Container scanning component for GitLab with verified inputs | `pipelines/gitlab/`, ADR-033 | `connectors/gitlab.render_component` |
| Prometheus metrics endpoint (then a ServiceMonitor in the chart) | `api/app.py` | — |
| Implement a `designed` API operation (e.g. `listTickets`) | `schemas/api/openapi.yaml` (`x-status: designed`) | `api/app.py` list endpoints |
| AWS Security Hub with the platform's own AWS identity (IRSA) instead of an Azure token | `worker/connectors.py` (`aws`) | `connectors/cloud.py` (`SecurityHubClient` takes any boto3 session) |
| Accept SPDX SBOMs by converting them to CycloneDX on ingest | `services/sbom_sync.py`, [ADR-010](../../adr/ADR-010-cyclonedx-vs-spdx.md) | the CycloneDX path |
