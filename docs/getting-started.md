# Getting started

Goal: the platform running on your machine with the demo world, in a few minutes, with nothing but Docker. This
runs the latest signed release:

<!-- x-release-please-start-version -->
```bash
git clone --branch v0.2.0 https://github.com/cipherfort/fortproof && cd fortproof
AAP_IMAGE=ghcr.io/cipherfort/fortproof:v0.2.0 deploy/compose/setup.sh
```
<!-- x-release-please-end -->

Open http://localhost:8000. You are sent to the sign-in page (Keycloak, part of the evaluation stack). Sign in as
**appsec** with the password the script printed. Without `AAP_IMAGE`, the script builds the image from your checkout
instead (for trying unreleased changes on `main`; it takes longer).

## A ten-minute tour

The demo is an example organization with four applications and a year of history, built by the same code a real
deployment runs. Press **⌘K** (Ctrl+K) at any time to jump to an application, a page or a CVE.

1. **Overview.** Mandatory controls proven by verified evidence, open P1 findings, findings past their deadline and
   rejected evidence, each with twelve months of history. Below: SAMM maturity by business function, recent activity,
   coverage by control domain and the most urgent findings.
2. **Applications → Claims API.** "Needs attention" lists each mandatory control that current evidence doesn't prove,
   with the reason. "Why Tier 1?" explains the classification. On **Controls**, open any control to see its state in
   every scope and the evidence behind it.
3. **Evidence.** Open a *Static analysis* record: the chain shows the pipeline run and commit that produced it, the file
   hashes, each verification check, its place in the hash-chained ledger and the confidence it earned. Then open the
   **Rejected** tab: a scan result from a copy of the security workflow kept in the application's own repository was
   refused as an *untrusted producer*.
4. **Findings.** Open one: its priority is explained (exploited in the wild? internet-facing? which data?). Closing is
   not a button: only a re-scan that no longer reports it closes it.
5. **Are we affected?** Type `CVE-2021-44228`: which applications contain the vulnerable component, and which can only
   be reported as *possibly affected* because their SBOM is missing or stale.
6. **Sign in as `lead`.** The **Leadership** report and **Maturity**: monthly trends and how each SAMM practice spreads
   across applications.
7. **Sign in as `dev`, then as `admin`.** An engineer in no team sees nothing. As `admin`, on **Admin**, add `dev` to the
   Claims team; signed in again, `dev` sees Claims API only.

More screens, with what each one shows: the [tour](tour.md).

When you are done: `docker compose -f deploy/compose/compose.yaml down -v` stops the stack and deletes its data.

## Next

| You want to | Read |
|---|---|
| Understand the model (evidence, confidence, controls) | [Security model](security/security-model.md) |
| Use it day to day | [User guide](guide/user-guide.md) |
| Connect your GitHub or GitLab and onboard an application | [Connect your organization](guide/connect-your-organization.md), [GitLab](guides/gitlab-guide.md) |
| Fit it to your organization | [Configure](configure/index.md) |
| Run it in production | [Install with Helm](install/helm.md) |
| Run a security programme around it | [Adoption kit](../adoption-kit/README.md) |
