# Roadmap

The goal of 1.0: any organization can deploy the platform on its own infrastructure, connect GitHub or GitLab, onboard
a real application, and see verified evidence turn into control verdicts and prioritised findings, without help.
Decision: [ADR-032](adr/ADR-032-open-source-product.md).

**Where it stands (October 2026).** The platform is released ([latest](https://github.com/cipherfort/fortproof/releases/latest)),
documented ([fortproof.dev](https://fortproof.dev)) and tested end to end on a real GitHub organization. The next three
releases are about the first teams using it on their own code: removing what stops them after the demo, then what an
operator needs to run it, then what their auditors ask for.

Plans assume one maintainer working part-time; contributors shorten them. Every item is an issue with what "done"
means; anything marked `good first issue` or `help wanted` is open for contributors.

## Now: 0.2 "Adopt it" (target 23 November 2026)

[Milestone 0.2.0](https://github.com/cipherfort/fortproof/milestone/1)

- **Your own rules without building an image** ([#81](https://github.com/cipherfort/fortproof/issues/81)): the Helm chart and Compose take your rules
  (trusted producers, organization, classification) directly, instead of a custom image.
- **From the demo to your own GitHub on one machine** ([#82](https://github.com/cipherfort/fortproof/issues/82)): a tested way to connect the Compose stack to a
  real organization.
- **A 2-3 minute walkthrough video** ([#83](https://github.com/cipherfort/fortproof/issues/83)) on the README and fortproof.dev.
- **A place to say how it went** ([#84](https://github.com/cipherfort/fortproof/issues/84)): an adopter feedback form and the first Discussions posts.
- **First-run polish** ([#85](https://github.com/cipherfort/fortproof/issues/85)), **the review rule while there is one maintainer** ([#86](https://github.com/cipherfort/fortproof/issues/86)), and
  **OpenSSF Baseline level 2** ([#87](https://github.com/cipherfort/fortproof/issues/87)).

## Next: 0.3 "Run it with confidence" (target 21 December 2026)

[Milestone 0.3.0](https://github.com/cipherfort/fortproof/milestone/2)

- **Metrics and alerts** ([#88](https://github.com/cipherfort/fortproof/issues/88)): a Prometheus endpoint, ServiceMonitor, alert rules and a dashboard.
- **Capacity and sizing** ([#89](https://github.com/cipherfort/fortproof/issues/89)): a synthetic large organization, measured limits, a sizing guide.
- **AWS with its own identity** ([#90](https://github.com/cipherfort/fortproof/issues/90)): Security Hub from EKS without an Azure identity.
- **The audit log for auditors** ([#91](https://github.com/cipherfort/fortproof/issues/91)) and **upgrade notes plus a restore drill** ([#92](https://github.com/cipherfort/fortproof/issues/92)).

## Then: 0.4 "Prove it to auditors" (target 29 January 2027)

[Milestone 0.4.0](https://github.com/cipherfort/fortproof/milestone/3)

- **NIST SSDF evidence pack** ([#93](https://github.com/cipherfort/fortproof/issues/93)) for the CISA Secure Software Development Attestation: practice → controls
  → verdicts → evidence, from what FortProof already verifies (40 of the 48 controls map to SSDF).
- **ASVS status per requirement** ([#94](https://github.com/cipherfort/fortproof/issues/94)).
- **FortProof's own assurance report** ([#95](https://github.com/cipherfort/fortproof/issues/95)), produced by running it on this repository.
- **An application for an independent security review** ([#96](https://github.com/cipherfort/fortproof/issues/96)).

## How we will know it is working

Checked at each release: the first three organizations running it on their own source control, 25 stars, the first
external pull request, and a `good first issue` taken by a contributor. If 0.2 brings no sign of adoption, 0.3 shrinks
and the time goes to outreach (talks, OWASP chapters, articles) instead.

## 1.0

The gate, unchanged: the independent security review closed out, OpenSSF Best Practices passing, Scorecard 7 or higher,
a co-maintainer, and a new user reaching the demo from "Getting started" on a clean machine within 15 minutes, without
help ([RELEASING.md](RELEASING.md#before-tagging-10)). Then an application to become an OWASP project ([#97](https://github.com/cipherfort/fortproof/issues/97)).

## Later (not scheduled)

Issues labelled [`later`](https://github.com/cipherfort/fortproof/issues?q=is%3Aopen+label%3Alater): EU Cyber Resilience
Act mapping and OSCAL export ([#98](https://github.com/cipherfort/fortproof/issues/98)), VEX ([#99](https://github.com/cipherfort/fortproof/issues/99)), Azure DevOps ([#100](https://github.com/cipherfort/fortproof/issues/100)) and Bitbucket
([#101](https://github.com/cipherfort/fortproof/issues/101)), Scorecard-visible fuzzing ([#102](https://github.com/cipherfort/fortproof/issues/102)), multiple organizations per installation ([#103](https://github.com/cipherfort/fortproof/issues/103)) and a
hosted demo ([#104](https://github.com/cipherfort/fortproof/issues/104)), each only if adopters need it. Contributions welcome on the
[good first issues](https://github.com/cipherfort/fortproof/issues?q=is%3Aopen+label%3A%22good+first+issue%22):
ServiceNow, Prowler, GitHub Advisory Database, SPDX SBOMs and more.

## What works today

- **Working:** the engine, API, web UI and sign-in; GitHub and GitLab; Jira, GitHub Issues and GitLab Issues; Dependency-Track, DefectDojo, Defender for Cloud, Security Hub, Sentinel, SIEM over HTTPS or syslog, chat webhooks; S3, Azure Blob or disk evidence storage. Every change runs more than 360 backend tests and more than 80 browser tests; opt-in tests run against real services, and GitLab CE runs end to end nightly.
- **Maturity over time:** monthly posture and SAMM snapshots (the current month in progress, earlier months published and never changed), trends per application and organization unit, and an organization-wide roll-up shown as a distribution, not a ranking.
- **Registration works:** a team registers its application from `.security/application.yaml` (web UI, API or `aap apps register`). Tier 1/2 waits for an AppSec engineer outside the owning team; Tier 3/4 is auto-approved; the decision becomes evidence and controls are evaluated.
- **Shipped pipelines:** nine reusable GitHub workflows (CodeQL, OSV-Scanner, gitleaks, Checkov, Syft, Trivy, zizmor, security-test and deploy evidence) with the `aap-evidence` manifest tool inlined, rendered by `aap pipelines export` and trusted by `aap pipelines approve`. They run on a real GitHub organization, and the platform's verifier accepts what they write (tested).
- **Built in, no accounts needed:** OSV, CISA KEV, FIRST EPSS and endoflife.date feeds; all 48 control evaluators; exceptions (approval matrix, co-signature, expiry); manual assessments (M1/M2); admin screens; CSV export; chat notifications.
- **Contract:** the OpenAPI document matches the implementation in both directions (test), UI types are generated from it, and Schemathesis fuzzes every implemented read operation in CI.

## Done

| Milestone | What it delivers | Estimate | Status |
|---|---|---|---|
| **M0 Open-source foundations** | Licence, community files, CI security checks, licence gate, organization-specific content removed, documents split into product docs and an adoption kit | 2 weeks | **Done.** Public repository with branch and tag rulesets, CodeQL, Scorecard, secret scanning with push protection, private vulnerability reporting; OpenSSF Best Practices **passing** and **Baseline level 1** |
| **M1 Provider-neutral core** | Database baseline without GitHub/Entra-specific columns; configurable organization hierarchy and classification profiles; plugin registry and interfaces; one settings file; S3-compatible evidence store; per-process database logins | 4 weeks | **Done** (GitLab-ready schema, profiles, plugins, settings, S3/mounted secrets, per-process logins) |
| **M2 A real team can onboard** | Application registration (UI + CLI); the `aap-evidence` tool; shipped security pipelines for GitHub; built-in vulnerability feeds (OSV, CISA KEV, EPSS); exceptions, assessments and admin screens; the 9 missing control evaluators; report export; OpenAPI-generated UI types | 5 weeks | **Done.** Tested end to end on a real GitHub organization ([guide](docs/guides/github-e2e.md)): evidence from the shipped workflows accepted at C3, a vulnerable dependency raised as a finding, and the fix closing it; the run found and fixed six defects |
| **M3 GitLab** | Evidence trust spike (ADR-033), GitLab adapter (auth, webhooks, artifacts, settings), GitLab CI components, live tests against GitLab CE | 5 weeks | **Done.** Spike → [ADR-033](adr/ADR-033-gitlab-evidence-trust.md); adapter, components, webhooks/polling, GitLab Issues; tested end to end on GitLab CE with a real runner (nightly CI). Outstanding: a run against gitlab.com (needs a group you own) |
| **M4 Packaging** | Signed multi-arch images with SBOMs and provenance; Helm chart; Compose evaluate/full profiles; Azure and AWS Terraform examples; upgrade testing | 3 weeks | **Done.** Helm chart installed and upgraded on kind in CI; Compose evaluation stack run with Keycloak sign-in and RustFS Object Lock; AWS and Azure Terraform examples validated and scanned; upgrades from every earlier migration tested with data. First release published (v0.1.3): the multi-arch image with SBOM, SLSA provenance and a cosign signature, and the signed chart, verified and installed from GHCR on kind |
| **M5 Assurance** | Product threat model refresh, parser fuzzing, independent security review, OpenSSF Best Practices badge | 2 weeks + review | **Done in-house; external parts prepared.** Threat model refreshed (T-19…T-30); property-based fuzzing of every untrusted-input parser (found and fixed two crash classes; nightly 5,000 examples); dependency audits in CI; release-please, signed release pipeline, [RELEASING.md](RELEASING.md). Best Practices **passing** and Baseline level 1 earned ([self-assessment](docs/security/openssf-best-practices.md)); rulesets in place. REQUIRES HUMAN ACTION: commission the [independent review](docs/security/review-scope.md) |
| **M6 Docs and adoption kit** | Documentation site (getting started, install, configure, user and admin guides, plugin developer guide, API reference); adoption kit as templates | 3 weeks | **Done.** Live at [fortproof.dev](https://fortproof.dev) with a screen-by-screen [tour](docs/tour.md); documentation licensed CC BY-SA 4.0. Sections: [getting started](docs/getting-started.md), install (Helm, Compose, Terraform examples), [configure](docs/configure/index.md), [user guide](docs/guide/user-guide.md), [plugin guide](docs/develop/plugins.md) with a CI-tested [example plugin](examples/plugins/aap-plugin-jsonl/README.md), generated [settings](docs/reference/settings.md) and [API](docs/reference/api.md) reference, [security model](docs/security/security-model.md); adoption kit [templates](adoption-kit/templates/) and a 90-day playbook |
| **M6b Web UI** | An application security console: overview dashboard, application pages, evidence explorer with the verification chain, findings, supply chain, control catalogue, maturity trends, leadership report, exceptions and assessments, integrations set-up, administration; monthly posture snapshots behind the trends | 6 weeks | **Done.** Every page tested in a browser against the real API and Content Security Policy, for every role, with WCAG 2.2 AA checks in both themes, keyboard paths and a bundle-size budget; launch screenshots regenerated from the demo by `npm run screenshots` |
| **M7 Community** | Public roadmap, `good first issue` labels, discussions, 0.x previews | Ongoing | **Started:** public repository, Discussions, [labels](.github/labels.yml), [seed issues](docs/roadmap/good-first-issues.md), release-please, documentation site. First 0.x release out (v0.1.3). Next: a public Project board and a co-maintainer |
| **1.0** | Release; then an application to become an OWASP project | | |
