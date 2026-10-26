# External interfaces

Every way the released software (the container image and the Helm chart) talks to people and other systems. Each
entry links to its full reference. Anything not listed here is internal and may change without notice.

## What the platform serves

| Interface | Who uses it | Reference |
|---|---|---|
| Web UI (`/`, port 8000, process `aap api`) | People, through a browser; sign-in through OpenID Connect (`/auth/login`, `/auth/callback`) | [User guide](../guide/user-guide.md) |
| REST API (`/api/v1/...`, same process) | The web UI and your own scripts; every operation is in the OpenAPI 3.1 contract, with the permission it needs | [API reference](api.md) · [OpenAPI](https://github.com/cipherfort/fortproof/blob/main/schemas/api/openapi.yaml) |
| Health (`/api/v1/health/live`, `/api/v1/health/ready`) | Kubernetes probes, load balancers | [API reference](api.md#platform) |
| Webhook receiver (`/github/webhook`, `/gitlab/webhook`, port 8001, process `aap hook`) | GitHub and GitLab; deliveries must carry a valid signature (GitHub HMAC) or secret token (GitLab) | [Connect your organization](../guide/connect-your-organization.md) · [GitLab](../guides/gitlab-guide.md) |

## What the platform reads

| Interface | Format | Reference |
|---|---|---|
| Settings | `aap.yaml` (JSON Schema) or `AAP_*` environment variables | [Settings](settings.md) |
| Rules | YAML in `config/` and `catalogue/`: the image's defaults, replaced file by file by yours (`AAP_RULES_DIR`, Helm `rules.files`) | [Configure](../configure/index.md) |
| Secrets | One file per secret (mounted Kubernetes or Docker secrets), or Azure Key Vault | [Settings](settings.md) · [chart README](https://github.com/cipherfort/fortproof/blob/main/charts/fortproof/README.md) |
| Application contract | `.security/application.yaml`, `asvs.yaml` and threat models in each application repository | [Schemas](https://github.com/cipherfort/fortproof/tree/main/schemas/repo-contract) · [template](https://github.com/cipherfort/fortproof/tree/main/templates/repo-contract) |
| Evidence | `evidence-manifest.json` written by the shipped pipelines, optionally signed as an in-toto statement | [Manifest schema](https://github.com/cipherfort/fortproof/blob/main/schemas/evidence/evidence-manifest.schema.json) · [Evidence type v1](../attestation/evidence/v1.md) · [Evidence model](../architecture/04-evidence-model.md) |
| Helm values | `values.yaml`, validated by `values.schema.json` | [chart README](https://github.com/cipherfort/fortproof/blob/main/charts/fortproof/README.md) |

## What the platform calls

All outbound calls are HTTPS, read-only unless stated, and each is optional unless your settings switch it on.

| System | Why | Reference |
|---|---|---|
| Your OpenID Connect identity provider | Sign-in | [Settings](settings.md) |
| GitHub (through a read-only GitHub App) or GitLab (read-only group token) | Repository settings, workflow runs and evidence artifacts; GitHub Issues or GitLab Issues when switched on (write) | [Connect your organization](../guide/connect-your-organization.md) |
| Sigstore (the public-good trust root, shipped with the image) and GitHub's attestation API | Verifying signed evidence | [Evidence model](../architecture/04-evidence-model.md) |
| OSV, CISA KEV, FIRST EPSS, endoflife.date | Vulnerability and end-of-life data; no account needed | [Configure](../configure/index.md) |
| Evidence storage: S3 (Object Lock) or Azure Blob (immutability policy) | Writing and reading evidence, write-once | [Settings](settings.md) |
| Jira, Dependency-Track, DefectDojo, Defender for Cloud, Security Hub, Sentinel, a SIEM over HTTPS or syslog, chat webhooks | Optional plugins | [Integrations](../operations/integration-bootstrap.md) · [Writing a plugin](../develop/plugins.md) |

## The command line

The image's `aap` command (also installed as `fortproof`). Operators run it inside the deployment
(`kubectl exec deploy/fortproof-worker -- aap ...`) or from a checkout (`uv run aap ...`).

| Command | What it does |
|---|---|
| `aap api` · `aap hook` · `aap worker` | Run the web UI and API, the webhook receiver, or the background worker |
| `aap migrate` | Apply database migrations and create partitions |
| `aap config load` | Load the rules (catalogue and config) into the database, with their versions |
| `aap config check` · `aap config chart-values` | Show which rules files are yours and which are defaults; print your rules as Helm values |
| `aap settings check <file>` | Validate an `aap.yaml` and show the settings it maps to |
| `aap db provision-logins` | Set the per-process database logins' passwords from the secret store |
| `aap integrations status` · `aap integrations run <name>` | What is configured and missing, with the last runs; run one integration now |
| `aap bootstrap github-app` · `gitlab` · `jira` · `dependency-track` · `defectdojo` | Create an integration's least-privilege credentials from nothing |
| `aap bootstrap trust-root` | Refresh the Sigstore trust root used to verify signatures |
| `aap apps register <owner/repo>` | Register an application from its repository's `.security/application.yaml` |
| `aap pipelines export` · `approve` · `caller` | Render the shipped workflows, trust a released commit of them, print an application's caller workflow |
| `aap secrets put <name>` | Store a secret in the secret store |
| `aap storage init-s3` | Evaluation only: create an evidence bucket with Object Lock |
| `aap snapshots backfill` | Compute earlier months' posture snapshots from the evidence on record |
| `aap demo seed` | Load the demo world |

`aap <command> --help` prints each command's options.

## Plugins

A plugin is a Python package that publishes an `aap.plugins.Plugin` record through the `aap.plugins` entry-point
group: [Writing a plugin](../develop/plugins.md).
