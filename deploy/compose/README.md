# Evaluate with Docker Compose

The whole platform on one machine in about 15 minutes, with real sign-in (OpenID Connect via Keycloak), S3 evidence
storage with Object Lock (RustFS) and the demo world. Tested end to end (`setup.sh`).

<!-- x-release-please-start-version -->
```bash
AAP_IMAGE=ghcr.io/cipherfort/fortproof:v0.2.0 deploy/compose/setup.sh   # a released image (match your checkout's tag)
deploy/compose/setup.sh            # or build the image from this checkout; both generate secrets, start, load the demo
# open http://localhost:8000 and sign in as appsec, lead, admin or dev (the script prints the password)
docker compose -f deploy/compose/compose.yaml --profile full up -d   # + Dependency-Track
docker compose -f deploy/compose/compose.yaml down -v                # stop and delete everything
```
<!-- x-release-please-end -->

| Service | Purpose |
|---|---|
| `api`, `worker` (`hook` with `--profile webhooks`) | The platform, each process on its own database login, read-only root filesystem, no capabilities |
| `migrate` | Runs once: migrations, governed configuration, per-process login passwords, the evidence bucket |
| `postgres` | PostgreSQL 16 |
| `rustfs` | S3-compatible storage with Object Lock (COMPLIANCE, 30 days): evidence cannot be deleted or overwritten |
| `keycloak` | Sign-in. Users `appsec` (AppSec engineer), `lead` (security leadership), `admin` (platform admin), `dev` (engineer) |
| `secrets` | Copies `deploy/compose/secrets/` into a volume readable only by the platform's user |

Users with only the `engineer` role see nothing until a platform admin puts them in a team (Admin → Members) or grants
a scoped role. The demo applications belong to the demo teams (`claims-team`, ...).

Evaluation, not production: `env: development`, HTTP on localhost, one PostgreSQL container without backups. For
production use the [Helm chart](../../charts/fortproof/README.md) with managed PostgreSQL and S3 (or Azure Blob) with
immutability.
