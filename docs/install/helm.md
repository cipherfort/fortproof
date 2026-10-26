# Install on Kubernetes (Helm)

The supported production path. Each release publishes a multi-arch image and a Helm chart to GitHub Container
Registry, both signed by the project's release workflow; the chart pins the image by digest. The full procedure
(credentials, values, upgrade, rotation, backup) is with the chart:
[charts/fortproof/README.md](../../charts/fortproof/README.md).

Before you start you need:
- a Kubernetes cluster (1.27 or later) and an ingress controller;
- PostgreSQL 16, managed or operated (CloudNativePG works);
- an evidence bucket with write-once retention: S3 with Object Lock, or Azure Blob with an immutability policy
  ([examples/terraform](../../examples/terraform/README.md) creates either);
- an OpenID Connect identity provider (Entra ID, Okta, Keycloak, ...) with an app registration for the platform.

## Verify, then install

<!-- x-release-please-start-version -->
```bash
# the chart: signed by release.yml in cipherfort/fortproof
cosign verify ghcr.io/cipherfort/charts/fortproof:0.2.0 \
  --certificate-identity-regexp '^https://github.com/cipherfort/fortproof/.github/workflows/release.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# the image the chart pins: SLSA provenance from the same workflow
gh attestation verify oci://ghcr.io/cipherfort/fortproof:v0.2.0 --repo cipherfort/fortproof

# the Secret with the database URLs and plugin credentials comes first (chart README, step 2)
helm install fortproof oci://ghcr.io/cipherfort/charts/fortproof --version 0.2.0 -n fortproof -f my-values.yaml
```
<!-- x-release-please-end -->

The release notes on [GitHub](https://github.com/cipherfort/fortproof/releases/latest) give the image digest and
the same commands. `my-values.yaml` holds your settings (`settings:` is your `aap.yaml`: public URL, sign-in,
evidence store, plugins). It must not contain secrets.

## Your rules

The image carries the default rules (`config/`, `catalogue/`). To run with your own, which you need before evidence
from your security workflows is accepted, build an image on top of the release with your rules copied in and point
`image.repository` and `image.digest` at it: [Connect your organization, step 2](../guide/connect-your-organization.md#2-your-rules).

## Upgrade

`helm upgrade` with the new `--version`. The chart's migration job runs first (forward-only; each release upgrades
from the previous minor) and loads the rules; if it fails, no pod changes. Read the release notes before upgrading
across a minor version.
