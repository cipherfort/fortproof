# FortProof Helm chart

Status: IMPLEMENTED. Linted, validated with kubeconform (Kubernetes 1.27 and 1.31), and installed and then upgraded
on kind in CI (`ci/smoke.sh`).

## What it deploys

| Object | Notes |
|---|---|
| Deployments `api`, `worker`, `hook` | One image, three processes, each on its own database login. Non-root (UID 10001), read-only root filesystem, no capabilities, seccomp `RuntimeDefault`, no service-account token |
| Job `migrate` (pre-install and pre-upgrade hook) | `aap migrate`, `aap config load`, and `aap db provision-logins all --from-store` (sets each login's password from its `database-url-<process>` secret) |
| Services, optional Ingress | The `hook` service (webhook receiver) is the only one meant for the internet; give it its own host (`ingress.hookHost`, exact paths `/github/webhook`, `/gitlab/webhook`) |
| NetworkPolicies | Default deny; DNS, PostgreSQL and HTTPS out; never the cloud metadata endpoint; ingress only from the ingress controller's namespace |
| PodDisruptionBudgets, optional HPA (api) | |

Not included: PostgreSQL (use a managed service or an operator such as CloudNativePG) and the evidence bucket (S3 with
Object Lock, or Azure Blob with an immutability policy: `examples/terraform/`). A ServiceMonitor is not shipped: the
platform does not expose metrics yet.

## Install

```bash
# 1. Verify the chart and the image you are about to run (both are signed by the release workflow)
cosign verify ghcr.io/cipherfort/charts/fortproof:<version> \
  --certificate-identity-regexp '^https://github.com/cipherfort/fortproof/.github/workflows/release.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/cipherfort/fortproof@<digest> --repo cipherfort/fortproof

# 2. Credentials: one Secret (or an ExternalSecret) with these keys; each process mounts only its own
kubectl -n aap create secret generic aap-secrets \
  --from-literal=database-url='postgresql+psycopg://admin:...@db:5432/aap' \
  --from-literal=database-url-api='postgresql+psycopg://aap_api_login:<random>@db:5432/aap' \
  --from-literal=database-url-worker='postgresql+psycopg://aap_worker_login:<random>@db:5432/aap' \
  --from-literal=database-url-hook='postgresql+psycopg://aap_hook_login:<random>@db:5432/aap' \
  --from-literal=database-url-reporting='postgresql+psycopg://aap_reporting_login:<random>@db:5432/aap' \
  --from-literal=oidc-client-secret='...'          # plus the keys your plugins need (values.yaml: secrets.keys)

# 3. Install with your settings (values.yaml → settings is your aap.yaml)
helm install fortproof oci://ghcr.io/cipherfort/charts/fortproof --version <version> -n fortproof -f my-values.yaml
```

The commands for the latest release, with its version filled in: [docs/install/helm.md](../../docs/install/helm.md).

`settings` is the platform's `aap.yaml` (`schemas/settings/aap.schema.json`): public URL, OIDC issuer and client, the
evidence store and plugin settings. It must not contain secrets.

Production (`env: production`) refuses development sign-in and the file secret store, and requires write-once
evidence storage.

The image carries the default rules (`config/`, `catalogue/`). Your own (needed before your security workflows'
evidence is accepted) go in `rules.files`, by their path in the repository; only the files you change. The chart
mounts them at `AAP_RULES_DIR` in every process and the migration job loads them. `aap config chart-values` writes the
values from a rules directory ([how](../../docs/guide/connect-your-organization.md#2-your-rules)).

For S3 on EKS, annotate the service account for IRSA (`serviceAccount.annotations`); on AKS use Azure workload identity.
No storage keys in the Secret.

## Upgrade, rotate, back up

- **Upgrade:** `helm upgrade` runs the migration job first (forward-only; each release upgrades from the previous
  minor). If the job fails, the upgrade stops before any pod changes; read `kubectl logs job/fortproof-migrate` (release `fortproof`).
- **Rotate database passwords:** change the `database-url-*` values in the Secret, `helm upgrade` (the job sets the new
  passwords), then `kubectl rollout restart deploy` (processes read the URL at start-up).
- **Back up:** PostgreSQL with your provider's point-in-time recovery; the evidence bucket is write-once and keeps
  its own versions (Object Lock). Configuration is in git. Restoring the database alone is enough to bring the
  platform back; evidence integrity is re-checked against the bucket (`aap` verifies hashes on read).

## Values

See [`values.yaml`](values.yaml) (commented) and [`values.schema.json`](values.schema.json): the schema refuses settings
that weaken the security context (root, writable root filesystem, privilege escalation) and image digests that are not
`sha256:`.
