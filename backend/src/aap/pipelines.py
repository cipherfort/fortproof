# SPDX-License-Identifier: Apache-2.0
"""Shipped security pipelines (pipelines/github/): render them for an adopter's own `security-workflows` repository,
and approve a released commit as a trusted evidence producer.

    export   pipelines/github/.github/workflows/*.yml → <dir>/.github/workflows/, with pipelines/aap_evidence.py inlined
             (so the approved workflow SHA covers the manifest tool too; nothing is fetched at run time)
    approve  append a released commit SHA to config/trusted-producers.yaml for every shipped workflow; the previous
             release gets retire_after = today + overlap days. The change still goes through review (CODEOWNERS).
    caller   the one workflow file an application repository adds (templates/repo-contract/.github/workflows/)

The platform never pushes to the adopter's GitHub: the adopter creates the repository, reviews, pushes and tags.
"""

from __future__ import annotations

import re
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import yaml

from aap.config import repo_root, rules_dir

MARKER = "      # @@aap-evidence-tool@@"
HEREDOC_END = "AAP_EVIDENCE_EOF"
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
# evidence type each shipped workflow produces (config/trusted-producers.yaml paths)
SHIPPED = {
    "sast.yml": ["scan.sast"],
    "sca.yml": ["scan.sca"],
    "secrets.yml": ["scan.secrets"],
    "iac.yml": ["scan.iac"],
    "sbom.yml": ["sbom"],
    "container.yml": ["scan.container"],
    "workflow-lint.yml": ["scan.workflow_hardening"],
    "test-evidence.yml": ["test.security"],
    "deploy-evidence.yml": ["deploy.record"],
}


GITLAB_MARKER = "    # @@aap-evidence-tool@@"
# component name → evidence types (config/trusted-producers.yaml, gitlab:); job name is aap-<name>
GITLAB_SHIPPED = {
    "sast": ["scan.sast"],
    "sca": ["scan.sca", "scan.malicious_package"],
    "secrets": ["scan.secrets"],
    "iac": ["scan.iac"],
    "sbom": ["sbom"],
}


class PipelineError(ValueError):
    pass


class _IndentedDumper(yaml.SafeDumper):
    """List items indented under their key, as in the hand-written config files."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> Any:
        return super().increase_indent(flow, False)


def source_dir() -> Path:
    return repo_root() / "pipelines" / "github" / ".github" / "workflows"


def tool_step() -> str:
    tool = (repo_root() / "pipelines" / "aap_evidence.py").read_text()
    if HEREDOC_END in tool:
        raise PipelineError(f"aap_evidence.py must not contain {HEREDOC_END}")
    body = "\n".join(("          " + line) if line else "" for line in tool.rstrip("\n").split("\n"))
    return (
        "      - name: Write the aap-evidence tool (inlined by aap pipelines export)\n"
        "        if: ${{ !cancelled() }}\n"
        "        shell: bash\n"
        "        run: |\n"
        f"          cat > \"$RUNNER_TEMP/aap_evidence.py\" <<'{HEREDOC_END}'\n"
        f"{body}\n"
        f"          {HEREDOC_END}"
    )


def render(name: str) -> str:
    src = (source_dir() / name).read_text()
    if src.count(MARKER) != 1:
        raise PipelineError(f"{name}: expected exactly one '{MARKER.strip()}' marker")
    out = src.replace(MARKER, tool_step())
    doc = yaml.safe_load(out)  # the rendered file must still be valid YAML
    if "workflow_call" not in (doc.get(True) or doc.get("on") or {}):
        raise PipelineError(f"{name}: not a reusable workflow")
    return out


def gitlab_source_dir() -> Path:
    return repo_root() / "pipelines" / "gitlab" / "templates"


def render_gitlab(name: str) -> str:
    src = (gitlab_source_dir() / f"{name}.yml").read_text()
    if src.count(GITLAB_MARKER) != 1:
        raise PipelineError(f"{name}.yml: expected exactly one '{GITLAB_MARKER.strip()}' marker")
    tool = (repo_root() / "pipelines" / "aap_evidence.py").read_text()
    if HEREDOC_END in tool:
        raise PipelineError(f"aap_evidence.py must not contain {HEREDOC_END}")
    body = "\n".join(("      " + line) if line else "" for line in tool.rstrip("\n").split("\n"))
    step = f"    - |\n      cat > /tmp/aap_evidence.py <<'{HEREDOC_END}'\n{body}\n      {HEREDOC_END}"
    out = src.replace(GITLAB_MARKER, step)
    docs = list(yaml.safe_load_all(out))
    if len(docs) != 2 or f"aap-{name}" not in (docs[1] or {}):
        raise PipelineError(f"{name}.yml: not a component defining job aap-{name}")
    return out


def export_gitlab(target: Path) -> list[Path]:
    tpl = target / "templates"
    tpl.mkdir(parents=True, exist_ok=True)
    written = []
    for name in sorted(GITLAB_SHIPPED):
        path = tpl / f"{name}.yml"
        path.write_text(render_gitlab(name))
        written.append(path)
    readme = target / "README.md"
    readme.write_text(GITLAB_README)
    written.append(readme)
    return written


def _trusted_producers_path() -> Path:
    """The trusted-producers.yaml an approval edits: the deployment's own copy under AAP_RULES_DIR (started from the
    shipped default the first time), else the repository's."""
    rel = "config/trusted-producers.yaml"
    override = rules_dir()
    if override is None:
        return repo_root() / rel
    target = override / rel
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((repo_root() / rel).read_text())
    return target


def approve_gitlab(
    sha: str,
    release: str,
    project: str | None = None,
    path: Path | None = None,
    today: date | None = None,
    overlap_days: int = 90,
) -> dict[str, Any]:
    """Edit the `gitlab:` block of trusted-producers.yaml (ADR-033): one entry per shipped component."""
    if not SHA.match(sha):
        raise PipelineError("--sha must be a full 40-character commit SHA (tags are mutable)")
    path = path or _trusted_producers_path()
    text = path.read_text()
    doc = yaml.safe_load(text)
    today = today or date.today()
    gl = doc.get("gitlab") or {"components_project": project or "example-org/security-components", "components": []}
    if project:
        gl["components_project"] = project
    by_name = {c["name"]: c for c in gl.get("components") or []}
    for name, types in GITLAB_SHIPPED.items():
        entry = by_name.get(name) or {"name": name, "job": f"aap-{name}", "evidence_types": types, "approved_shas": []}
        by_name[name] = entry
        shas = entry.get("approved_shas") or []
        if any((s["sha"] if isinstance(s, dict) else s) == sha for s in shas):
            continue
        for s in shas:
            if isinstance(s, dict) and not s.get("retire_after") and not s.get("revoked_at"):
                s["retire_after"] = (today + timedelta(days=overlap_days)).isoformat()
        shas.append(
            {"sha": sha, "release": release, "approved_at": today.isoformat(), "retire_after": None, "revoked_at": None}
        )
        entry["approved_shas"] = shas
    gl["components"] = list(by_name.values())
    block = yaml.dump(
        {"gitlab": gl}, Dumper=_IndentedDumper, sort_keys=False, default_flow_style=None, width=120
    ).rstrip()
    lines = text.split("\n")
    if any(line.startswith("gitlab:") for line in lines):
        start = next(i for i, line in enumerate(lines) if line.startswith("gitlab:"))
        end = next(
            (
                i
                for i in range(start + 1, len(lines))
                if lines[i] and not lines[i][0].isspace() and not lines[i].startswith("#")
            ),
            len(lines),
        )
        while end > start + 1 and not lines[end - 1].strip():
            end -= 1
        lines[start:end] = block.split("\n")
    else:
        lines += [
            "",
            "# GitLab CI/CD components (ADR-033): evidence capped at C2. Edited by `aap pipelines approve",
            "# --provider gitlab`; changes through review.",
            *block.split("\n"),
        ]
    new = "\n".join(lines)
    yaml.safe_load(new)
    path.write_text(new if new.endswith("\n") else new + "\n")
    return {"path": str(path), "sha": sha, "release": release, "workflows": len(GITLAB_SHIPPED)}


def gitlab_include(host: str, project: str, sha: str) -> str:
    """The `include:` an application project adds to its .gitlab-ci.yml (components pinned to the approved SHA)."""
    if not SHA.match(sha):
        raise PipelineError("sha must be a full commit SHA")
    lines = [
        "# FortProof security components (approved commit; do not override their jobs)",
        "include:",
    ]
    lines += [f"  - component: {host}/{project}/{name}@{sha}" for name in sorted(GITLAB_SHIPPED)]
    return "\n".join(lines) + "\n"


def export(target: Path) -> list[Path]:
    wf = target / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    written = []
    for name in sorted(SHIPPED):
        path = wf / name
        path.write_text(render(name))
        written.append(path)
    readme = target / "README.md"
    readme.write_text(README)
    written.append(readme)
    return written


def approve(
    sha: str,
    release: str,
    repository: str | None = None,
    path: Path | None = None,
    today: date | None = None,
    overlap_days: int = 90,
) -> dict[str, Any]:
    """Edit trusted-producers.yaml in place: only the `workflow_repository` line and the `workflows:` block change."""
    if not SHA.match(sha):
        raise PipelineError("--sha must be a full 40-character commit SHA (tags are mutable)")
    if repository is not None and not REPO.match(repository):
        raise PipelineError("--repository must be owner/name")
    path = path or _trusted_producers_path()
    text = path.read_text()
    doc = yaml.safe_load(text)
    today = today or date.today()
    workflows: list[dict[str, Any]] = doc["workflows"]
    by_path = {w["path"]: w for w in workflows}
    for name, types in SHIPPED.items():
        key = f".github/workflows/{name}"
        entry = by_path.get(key)
        if entry is None:
            entry = {"path": key, "evidence_types": types, "approved_shas": []}
            workflows.append(entry)
            by_path[key] = entry
        shas = entry.get("approved_shas") or []
        if any((s["sha"] if isinstance(s, dict) else s) == sha for s in shas):
            continue
        for s in shas:
            if isinstance(s, dict) and not s.get("retire_after") and not s.get("revoked_at"):
                s["retire_after"] = (today + timedelta(days=overlap_days)).isoformat()
        shas.append(
            {"sha": sha, "release": release, "approved_at": today.isoformat(), "retire_after": None, "revoked_at": None}
        )
        entry["approved_shas"] = shas

    lines = text.split("\n")
    start = next(i for i, line in enumerate(lines) if line.startswith("workflows:"))
    end = next(
        (
            i
            for i in range(start + 1, len(lines))
            if lines[i] and not lines[i][0].isspace() and not lines[i].startswith("#")
        ),
        len(lines),
    )
    # keep trailing comments that belong to the next section (e.g. the "Example of a populated entry" block)
    while end > start + 1 and lines[end - 1].startswith("#"):
        end -= 1
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    block = yaml.dump(
        {"workflows": workflows}, Dumper=_IndentedDumper, sort_keys=False, default_flow_style=None, width=120
    ).rstrip()
    lines[start:end] = block.split("\n")
    if repository is not None:
        lines = [
            f"workflow_repository: {repository}" if line.startswith("workflow_repository:") else line for line in lines
        ]
    new = "\n".join(lines)
    yaml.safe_load(new)
    path.write_text(new)
    return {"path": str(path), "sha": sha, "release": release, "workflows": len(SHIPPED)}


def caller(repository: str, sha: str, release: str) -> str:
    if not REPO.match(repository) or not SHA.match(sha):
        raise PipelineError("repository must be owner/name and sha a full commit SHA")
    tpl = (repo_root() / "templates" / "repo-contract" / ".github" / "workflows" / "aap-security.yml").read_text()
    return (
        tpl.replace("example-org/security-workflows", repository)
        .replace("0" * 40, sha)
        .replace("v0.0.0 (placeholder until first release)", release)
    )


README = """# security-workflows

The approved security pipelines for FortProof, rendered by `aap pipelines export`.
Application repositories call these workflows with one small file (`aap pipelines caller`); each workflow scans,
writes an evidence manifest, signs it, and uploads it as an `aap-evidence-*` artifact the platform pulls and verifies.

## Release procedure

1. Change the sources in the platform repository (`pipelines/github/`), not these copies; re-run
   `aap pipelines export --to <this repository>` and open a pull request here. Two reviewers (CODEOWNERS).
2. Merge, then tag the merge commit (`v1.2.0`). Protect tags (`v*`) with a ruleset.
3. Approve the commit in the platform: `aap pipelines approve --sha <full commit SHA> --release v1.2.0` and merge
   that change to `config/trusted-producers.yaml` through review. The previous release stays valid for 90 days.
4. Application repositories move to the new SHA through Dependabot (or `aap pipelines caller`).

Evidence produced by any commit that is not approved is rejected (`UNAPPROVED_WORKFLOW_REF`); evidence produced
outside these workflows is rejected (`UNTRUSTED_PRODUCER`).

## Repository settings

- Visibility internal or public, and Settings → Actions → General → Access: "Accessible from repositories in the
  organization" (otherwise application repositories cannot call these workflows).
- Branch ruleset on the default branch: pull request with 2 approvals, code owner review, no force push.
"""


GITLAB_README = """# security-components

The approved GitLab CI/CD components of FortProof, rendered by
`aap pipelines export --provider gitlab`. Application projects include them pinned to an approved commit SHA
(`aap pipelines caller --provider gitlab ...`). Do not override the included jobs in a project's .gitlab-ci.yml: the
platform compares the merged job with this repository at the approved commit and rejects evidence from a job that
differs (ADR-033). Evidence from GitLab is capped at C2.

## Release procedure

1. Change the sources in the platform repository (`pipelines/gitlab/`), re-run the export into this project, merge
   through a merge request with two approvals (on GitLab Free, enforce this by process: the tier cannot require it).
2. Approve the merge commit: `aap pipelines approve --provider gitlab --repository <group>/security-components
   --sha <commit> --release vX.Y.Z`, and merge that change to `config/trusted-producers.yaml` through review.
3. Projects move to the new SHA. The previous release stays trusted for 90 days.

Semgrep (sast) fetches the `p/default` rules from the Semgrep registry at run time (Semgrep Rules License); to pin the
rules, vendor them into this project and change `--config` in templates/sast.yml.
"""
