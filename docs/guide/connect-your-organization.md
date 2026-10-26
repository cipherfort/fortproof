# Connect your organization

From an installed platform to your first application with verified evidence, on GitHub. Plan on an afternoon,
most of it waiting for workflows to run. The same steps were run on a real organization:
[GitHub end to end](../guides/github-e2e.md) shows what to expect at each one. For GitLab, steps 3 and 4 differ:
[GitLab](../guides/gitlab-guide.md).

```text
1 install → 2 your rules → 3 security workflows → 4 GitHub App → 5 onboard an application → 6 evidence and findings
```

You need:
- a GitHub organization you administer. Public repositories get signed evidence (C3); private ones need GitHub
  Enterprise Cloud for that, otherwise their evidence stays at C2 ([why](../architecture/04-evidence-model.md));
- a fork (or private copy) of this repository, where your rules live (step 2);
- a workstation with git, [uv](https://docs.astral.sh/uv/) and Docker. The set-up commands run from your fork,
  checked out at the release you deploy:

<!-- x-release-please-start-version -->
```bash
git clone https://github.com/<you>/fortproof && cd fortproof
git fetch https://github.com/cipherfort/fortproof tag v0.2.0   # if your fork predates the release
git switch -c rules v0.2.0
cd backend && uv sync
```
<!-- x-release-please-end -->

## 1. Install

| | |
|---|---|
| Production | [Helm](../install/helm.md): Kubernetes, managed PostgreSQL, write-once evidence storage, your identity provider |
| Evaluation | [Docker Compose](../install/compose.md): one machine, Keycloak sign-in, the demo world |

The steps below are written for Helm. To try your organization on one machine first, without a cluster,
[GitHub end to end](../guides/github-e2e.md#repeat-it-on-your-organization) runs the platform from your checkout.

To receive webhooks, the `hook` service needs a public HTTPS address of its own (chart: `ingress.hookHost`). Without
one the platform still works: it polls GitHub for finished runs on its schedule.

## 2. Your rules

The rules are files in your fork: `config/` (organization levels, classification, risk model, exception policy,
trusted producers) and `catalogue/` (the controls). Change them by pull request ([Configure](../configure/index.md)).
At the least, set:

- `config/organization.yaml`: your organization levels and the classification profile;
- `config/trusted-producers.yaml`: `workflow_repository: <org>/security-workflows` (step 3 adds the approved commit).

The platform reads the rules from its image when it starts, and every upgrade loads them into the database with the
version that produced each verdict. To run the released platform with your rules, build an image on top of the
release in your fork's CI, and sign it as you would any image you deploy:

```dockerfile
FROM ghcr.io/cipherfort/fortproof@sha256:<digest of the release you run>
COPY config/ /app/config/
COPY catalogue/ /app/catalogue/
```

Then point the chart at it (`image.repository`, `image.digest`). The organization units themselves (business units,
teams, members) are managed on the **Admin** page, not in files.

## 3. Security workflows

The scans run in **your** `security-workflows` repository, so you decide which code may produce evidence
([shipped pipelines](../../pipelines/README.md)).

1. Create `<org>/security-workflows` (internal or public) and allow the organization's repositories to use it:
   **Settings → Actions → General → Access → Accessible from repositories in the organization**.
2. Clone it next to your `fortproof` checkout, render the workflows into it, review, commit, tag and push:

   ```bash
   # from fortproof/backend
   uv run aap pipelines export --to ../../security-workflows
   (cd ../../security-workflows && git add . && git commit -s -m "security workflows v1.0.0" \
     && git tag v1.0.0 && git push && git push --tags && git rev-parse HEAD)   # prints the commit SHA
   ```

3. Trust that commit. This edits `config/trusted-producers.yaml` in your fork; merge it through review, then rebuild
   your rules image and `helm upgrade` (step 2):

   ```bash
   uv run aap pipelines approve --repository <org>/security-workflows --sha <full commit SHA> --release v1.0.0
   ```

Evidence from any other commit, or from a copy of a workflow kept in an application's repository, is refused as an
*untrusted producer*, and the refusal is shown under **Evidence → Rejected**.

## 4. GitHub App

The platform reads repositories through a read-only GitHub App that you create in your organization. On the
workstation:

```bash
# from fortproof/backend; the App's credentials are written to ./fortproof-secrets (mode 700)
AAP_SECRETS_BACKEND=file AAP_SECRETS_DIR=./fortproof-secrets \
  uv run aap bootstrap github-app --org <org> --public-url https://<hook host>   # omit --public-url to poll only
```

A browser opens on GitHub: click **Create GitHub App**. The command prints `AAP_GITHUB_APP_CLIENT_ID` and an
`install_url`.

1. Open `install_url` and install the App on the repositories to onboard, plus `security-workflows`
   (**Only select repositories** is fine).
2. Give the platform the App: on Helm, add the two files to the platform's Secret and the two settings to your values,
   then `helm upgrade`:

   ```bash
   kubectl -n fortproof create secret generic aap-secrets ... \
     --from-file=github-app-private-key=./fortproof-secrets/github-app-private-key \
     --from-file=github-webhook-secret=./fortproof-secrets/github-webhook-secret
   ```

   ```yaml
   settings:
     plugins:
       github: { org: <org>, app_client_id: <printed client id> }
   ```

   The `...` are the database keys you created at install ([chart README](../../charts/fortproof/README.md#install)).
   Then delete `./fortproof-secrets`.
3. Check: **Integrations → GitHub** shows the App as configured, or
   `kubectl -n fortproof exec deploy/fortproof-worker -- aap integrations status`. A *partial* run lists what the App
   cannot read; that is a permission gap to fix, never a pass.

## 5. Onboard an application

In the application's repository:

1. Add `.security/application.yaml`, the application's owners, classification and environments. Start from the
   [template](../../templates/repo-contract/.security/application.yaml); the classification answers must be labels
   from your profile, and `owners.org_unit` must name a unit that exists (**Admin**).
2. Add the caller workflow, which runs the approved security workflows on pull requests, on pushes to `main` and
   weekly (so evidence stays fresh). If your default branch has another name, change `branches` in it:

   ```bash
   # from fortproof/backend
   uv run aap pipelines caller --repository <org>/security-workflows --sha <full commit SHA> --release v1.0.0 \
     > .github/workflows/aap-security.yml     # write it into the application repository
   ```

3. Register it: **Applications → Register an application** reads the contract from the repository. Tier 3 and 4 are
   approved automatically; Tier 1 and 2 wait for an AppSec engineer outside the owning team (**Why Tier N? → Approve**).

## 6. Evidence and findings

After the next workflow run on the default branch, the application page shows:
- **Controls**: each mandatory control satisfied, partial, not satisfied or without evidence, with the reason and the
  evidence behind it;
- **Evidence**: how each record was verified, step by step, and the confidence it earned (C3 for a public repository
  on GitHub-hosted runners);
- **Findings**: vulnerable dependencies from the SBOM and scan results, each with a priority and a deadline;
- **Supply chain**: the current SBOM, component by component.

A finding closes only when a later scan no longer reports it. From here, day-to-day use is in the
[user guide](user-guide.md); tickets, vulnerability feeds, cloud posture and SIEM are optional integrations on the
**Integrations** page.

## If something doesn't show up

| Symptom | Look at |
|---|---|
| Registration is refused | The reason is listed. Common: `owners.org_unit` is not a unit yet, or a classification answer is not a label in your profile |
| No evidence after a run | **Evidence → Rejected** for the reason. *Untrusted producer*: the run used a commit that is not in `trusted-producers.yaml`, or your rules image is older than the approval |
| Evidence at C2, not C3 | A private repository without GitHub Enterprise Cloud, or a self-hosted runner |
| Nothing at all from GitHub | **Integrations → GitHub**: is the App installed on that repository? Without a webhook, runs arrive at the next scheduled sync (`kubectl -n fortproof exec deploy/fortproof-worker -- aap integrations run github` runs one now) |
| The application is not visible to its team | **Admin**: add the people to the unit that owns it (`owners.org_unit`) |
