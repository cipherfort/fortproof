# SPDX-License-Identifier: Apache-2.0
"""Integration registry: what each external system needs, whether it is configured, and how to run its sync.

Nothing is assumed to exist. An integration is "configured" only when its endpoint settings (environment, from
Terraform outputs) and credentials (Key Vault / dev file store, written by `aap bootstrap <name>`) are present.
Unconfigured integrations are skipped by the scheduler and shown as such in `aap integrations status` and the UI;
the evidence they would produce stays NO_EVIDENCE.

Every run is recorded in `connector_runs` (ok | partial | failed, items, gaps): a connector failure produces no
evidence, never "observed: ok".
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Connection, Engine, text

from aap.config import ConfigBundle, rules_file
from aap.db import transaction
from aap.ids import uuid7
from aap.plugins import Plugin, registry
from aap.plugins import RunResult as PluginRunResult
from aap.secrets import SecretError, SecretStore, azure_credential, secret_store

Spec = Plugin  # backwards-compatible name


def specs() -> list[Plugin]:
    """Installed plugins (built-in and third-party), in a stable order."""
    return sorted(registry().plugins.values(), key=lambda p: (p.kind != "scm", p.kind, p.key))


DURATION = re.compile(r"^(\d+)([smhd])$")


def parse_interval(value: str | None) -> timedelta | None:
    m = DURATION.match(str(value or ""))
    if not m:
        return None
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m[2]]: int(m[1])})


def _policy_value(bundle: ConfigBundle, path: str | None) -> Any:
    node: Any = bundle.doc("integrations")
    for part in (path or "").split("."):
        if not part:
            return None
        node = (node or {}).get(part)
    return node


@dataclass
class Status:
    key: str
    name: str
    purpose: str
    configured: bool
    missing: list[str]
    bootstrap: str
    evidence: list[str]
    interval: str | None
    last_run: dict[str, Any] | None = None
    check: dict[str, Any] = field(default_factory=dict)
    kind: str = ""
    source: str = "builtin"


def _missing(spec: Spec, store: SecretStore | None) -> list[str]:
    missing = [v for v in spec.env if not os.environ.get(v)]
    for name in spec.secrets:
        try:
            if store is None or not store.get(name):
                missing.append(f"secret:{name}")
        except SecretError as e:
            missing.append(f"secret:{name} ({e})")
    return missing


def last_runs(conn: Connection) -> dict[str, dict[str, Any]]:
    rows = (
        conn.execute(
            text("""SELECT DISTINCT ON (connector) connector, started_at, finished_at, status, items, gaps, error
                                FROM connector_runs ORDER BY connector, started_at DESC""")
        )
        .mappings()
        .all()
    )
    return {r["connector"]: dict(r) for r in rows}


def status(
    engine: Engine, bundle: ConfigBundle, store: SecretStore | None = None, role: str = "aap_worker"
) -> list[Status]:
    try:
        store = store or secret_store()
    except SecretError:
        store = None
    with transaction(engine, role) as conn:
        runs = last_runs(conn)
    out = []
    for s in specs():
        missing = _missing(s, store)
        out.append(
            Status(
                s.key,
                s.name,
                s.purpose,
                not missing,
                missing,
                s.bootstrap,
                list(s.evidence),
                _policy_value(bundle, s.interval),
                runs.get(s.key),
                kind=s.kind,
                source=s.source,
            )
        )
    return out


def load_errors() -> dict[str, str]:
    """Plugins that are installed but failed to load (entry point name → error)."""
    return dict(registry().load_errors)


# ------------------------------------------------------------------------------------------ run bookkeeping


RunResult = PluginRunResult  # moved to aap.plugins


def record_run(engine: Engine, connector: str, target: str, fn: Callable[[], RunResult]) -> RunResult:
    run_id = uuid7()
    with transaction(engine, "aap_worker") as conn:
        conn.execute(
            text("INSERT INTO connector_runs (id, connector, target) VALUES (:id, :c, :t)"),
            {"id": run_id, "c": connector, "t": target},
        )
    started = time.monotonic()
    try:
        result = fn()
        state = "ok" if not result.errors and not result.gaps else "partial"
        error = "; ".join(result.errors)[:2000] or None
    except Exception as e:
        result, state, error = RunResult(), "failed", f"{type(e).__name__}: {str(e)[:500]}"
    import json

    with transaction(engine, "aap_worker") as conn:
        conn.execute(
            text("""UPDATE connector_runs SET finished_at = now(), status = :s, items = :n, gaps = CAST(:g AS jsonb),
                    error = :e WHERE id = :id"""),
            {
                "s": state,
                "n": result.items,
                "g": json.dumps({**result.gaps, "duration_s": round(time.monotonic() - started, 1)}, default=str),
                "e": error,
                "id": run_id,
            },
        )
    if state == "failed":
        raise RuntimeError(error)
    return result


def due(engine: Engine, bundle: ConfigBundle, store: SecretStore | None, now: datetime | None = None) -> list[str]:
    """Configured, scheduled integrations whose interval has elapsed since their last run."""
    now = now or datetime.now(UTC)
    out = []
    with transaction(engine, "aap_worker") as conn:
        runs = last_runs(conn)
    for s in specs():
        every = parse_interval(_policy_value(bundle, s.interval))
        if every is None or _missing(s, store):
            continue
        last = runs.get(s.key)
        if last is None or last["started_at"] + every <= now:
            out.append(s.key)
    return out


# ------------------------------------------------------------------------------------------ client builders


def github_auth(store: SecretStore, permissions: dict[str, str] | None = None) -> Any:
    from aap.connectors.github_app import TOKEN_PERMISSIONS, GitHubAppAuth, KeyVaultSigner, PemSigner

    key_id = os.environ.get("AAP_GITHUB_APP_KEY_ID")  # Key Vault key (non-exportable) in deployed environments
    signer = (
        KeyVaultSigner(key_id, azure_credential()) if key_id else PemSigner(store.get("github-app-private-key") or "")
    )
    return GitHubAppAuth(
        os.environ["AAP_GITHUB_APP_CLIENT_ID"],
        signer,
        base_url=os.environ.get("AAP_GITHUB_API", "https://api.github.com"),
        permissions=permissions or TOKEN_PERMISSIONS,
    )


def github_client(store: SecretStore, bundle: ConfigBundle) -> Any:
    from aap.connectors.attestation import AttestationVerifier
    from aap.connectors.github import RestGitHubClient

    auth = github_auth(store)
    att_cfg = _policy_value(bundle, "github.attestation") or {}
    root = rules_file(str(att_cfg.get("trusted_root", "config/sigstore/trusted_root.jsonl")))
    verifier = None
    if root.exists():
        import shutil

        gh = shutil.which("gh") if att_cfg.get("gh_backend") else None
        verifier = AttestationVerifier.from_trust_root_file(str(root), gh)
    return RestGitHubClient(auth.token_provider(os.environ["AAP_GITHUB_ORG"]), attestation=verifier)


def gitlab_client(store: SecretStore) -> Any:
    from aap.connectors.gitlab import GitLabRest

    token = store.get("gitlab-token") or ""  # group access token: Reporter, read_api + read_repository
    return GitLabRest(lambda: token, base_url=os.environ["AAP_GITLAB_URL"])


def jira_client(store: SecretStore) -> Any:
    from aap.connectors.jira import JiraClient

    return JiraClient(
        os.environ["AAP_JIRA_URL"], email=os.environ["AAP_JIRA_EMAIL"], api_token=store.get("jira-api-token")
    )


def dt_client(store: SecretStore) -> Any:
    from aap.connectors.dependency_track import DependencyTrackClient

    return DependencyTrackClient(os.environ["AAP_DT_URL"], store.get("dependency-track-api-key") or "")


def dd_client(store: SecretStore) -> Any:
    from aap.connectors.defectdojo import DefectDojoClient

    return DefectDojoClient(os.environ["AAP_DD_URL"], store.get("defectdojo-api-token") or "")


def sentinel_client() -> Any:
    from aap.connectors.sentinel import LogsIngestionClient, monitor_token

    return LogsIngestionClient(
        os.environ["AAP_SENTINEL_DCE"], os.environ["AAP_SENTINEL_DCR_ID"], monitor_token(azure_credential())
    )


def csv_env(name: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]
