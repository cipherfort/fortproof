# SPDX-License-Identifier: Apache-2.0
"""Deployment settings: one `aap.yaml` (schemas/settings/aap.schema.json) instead of dozens of environment variables.

`AAP_CONFIG_FILE=/etc/aap/aap.yaml` selects the file. Every value maps to one AAP_* variable (MAPPING below);
a variable already set in the environment wins, so containers can still override single values. The file holds no
secrets (the schema has no secret fields): credentials come from the secret store, and the database URL may come
from a mounted file (`database.url_file` → AAP_DATABASE_URL_FILE).

The rules (catalogue, risk model, organization, integration policy) are NOT settings: they are governed config in
config/ and catalogue/, changed by pull request.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from aap.config import repo_root

MAPPING: dict[str, str] = {
    "env": "AAP_ENV",
    "public_url": "AAP_PUBLIC_URL",
    "database.url_file": "AAP_DATABASE_URL_FILE",
    "auth.mode": "AAP_AUTH_MODE",
    "auth.oidc.issuer": "AAP_OIDC_ISSUER",
    "auth.oidc.client_id": "AAP_OIDC_CLIENT_ID",
    "auth.oidc.tenant_id": "AAP_OIDC_TENANT_ID",
    "auth.oidc.api_audience": "AAP_OIDC_API_AUDIENCE",
    "auth.oidc.client_auth": "AAP_OIDC_CLIENT_AUTH",
    "auth.oidc.internal_url": "AAP_OIDC_INTERNAL_URL",
    "secrets.backend": "AAP_SECRETS_BACKEND",
    "secrets.dir": "AAP_SECRETS_DIR",
    "secrets.keyvault_url": "AAP_KEYVAULT_URL",
    "rules.dir": "AAP_RULES_DIR",
    "worker.scheduler_interval": "AAP_SCHEDULER_INTERVAL",
    "evidence_store.kind": "AAP_BLOB_KIND",
    "evidence_store.root": "AAP_BLOB_ROOT",
    "evidence_store.container": "AAP_BLOB_CONTAINER",
    "evidence_store.account_url": "AAP_BLOB_ACCOUNT_URL",
    "evidence_store.bucket": "AAP_BLOB_S3_BUCKET",
    "evidence_store.prefix": "AAP_BLOB_S3_PREFIX",
    "evidence_store.endpoint_url": "AAP_BLOB_S3_ENDPOINT",
    "evidence_store.region": "AAP_BLOB_S3_REGION",
    "azure.client_id": "AAP_AZURE_CLIENT_ID",
    "plugins.github.org": "AAP_GITHUB_ORG",
    "plugins.github.app_client_id": "AAP_GITHUB_APP_CLIENT_ID",
    "plugins.github.app_key_id": "AAP_GITHUB_APP_KEY_ID",
    "plugins.github.api_url": "AAP_GITHUB_API",
    "plugins.jira.url": "AAP_JIRA_URL",
    "plugins.jira.email": "AAP_JIRA_EMAIL",
    "plugins.dependency_track.url": "AAP_DT_URL",
    "plugins.defectdojo.url": "AAP_DD_URL",
    "plugins.azure_defender.subscriptions": "AAP_AZURE_SUBSCRIPTIONS",
    "plugins.aws_securityhub.role_arn": "AAP_AWS_ROLE_ARN",
    "plugins.aws_securityhub.accounts": "AAP_AWS_ACCOUNTS",
    "plugins.aws_securityhub.web_identity_audience": "AAP_AWS_WEB_IDENTITY_AUDIENCE",
    "plugins.sentinel.dce": "AAP_SENTINEL_DCE",
    "plugins.sentinel.dcr_id": "AAP_SENTINEL_DCR_ID",
    "plugins.siem_http.url": "AAP_SIEM_HTTP_URL",
    "plugins.siem_http.format": "AAP_SIEM_HTTP_FORMAT",
    "plugins.syslog.address": "AAP_SIEM_SYSLOG",
    "plugins.syslog.ca_file": "AAP_SIEM_SYSLOG_CA",
    "plugins.gitlab.url": "AAP_GITLAB_URL",
    "plugins.gitlab.group": "AAP_GITLAB_GROUP",
    "plugins.github_issues.enabled": "AAP_GITHUB_ISSUES",
}


class SettingsError(ValueError):
    pass


def _schema() -> dict[str, Any]:
    return dict(json.loads((repo_root() / "schemas" / "settings" / "aap.schema.json").read_text()))


def flatten(doc: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in doc.items():
        path = f"{prefix}{k}"
        if isinstance(v, Mapping):
            out |= flatten(v, path + ".")
        else:
            out[path] = v
    return out


def load(path: str | Path) -> dict[str, str]:
    """Validate the file and return {AAP_* variable: value}. Lists become comma-separated."""
    doc = yaml.safe_load(Path(path).read_text()) or {}
    errors = sorted(jsonschema.Draft202012Validator(_schema()).iter_errors(doc), key=lambda e: list(e.path))
    if errors:
        raise SettingsError("; ".join(f"{'.'.join(map(str, e.path)) or '(root)'}: {e.message}" for e in errors[:10]))
    out: dict[str, str] = {}
    for key, value in flatten(doc).items():
        if key == "version":
            continue
        out[MAPPING[key]] = ",".join(map(str, value)) if isinstance(value, list) else str(value)
    return out


def apply(environ: dict[str, str] | None = None) -> dict[str, str]:
    """Load AAP_CONFIG_FILE (if set) into the environment without overriding variables already set.
    Returns what was applied (names → values; nothing here is secret)."""
    env = os.environ if environ is None else environ
    path = env.get("AAP_CONFIG_FILE")
    if not path:
        return {}
    applied = {k: v for k, v in load(path).items() if k not in env}
    env.update(applied)
    return applied
