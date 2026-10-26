# SPDX-License-Identifier: Apache-2.0
"""Connector runs (queue `connector`). One function per integration; each returns a RunResult for connector_runs."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Engine, text

from aap.blobstore import EvidenceBlobStore
from aap.config import ConfigBundle
from aap.db import transaction
from aap.integrations import (
    RunResult,
    _policy_value,
    csv_env,
    dd_client,
    dt_client,
    github_auth,
    jira_client,
    sentinel_client,
)
from aap.secrets import SecretStore, azure_credential


def github(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    from aap.connectors.github_settings import GitHubRest, Unavailable, collect_repository
    from aap.services.github_sync import sync_repository

    org = os.environ["AAP_GITHUB_ORG"]
    api = GitHubRest(
        github_auth(store).token_provider(org), base_url=os.environ.get("AAP_GITHUB_API", "https://api.github.com")
    )
    paths = _policy_value(bundle, "github.sensitive_paths") or [".github/workflows/", ".security/"]
    with transaction(engine, "aap_worker") as conn:
        repos = [
            r.full_name
            for r in conn.execute(
                text("SELECT full_name FROM repositories WHERE NOT archived AND full_name LIKE :o ORDER BY full_name"),
                {"o": f"{org}/%"},
            )
        ]
    if p.get("repo"):  # a webhook (push, settings change, alert) refreshes just that repository
        repos = [str(p["repo"])]
    else:  # discovery: every repository the installation can see is recorded (unregistered ones get no evidence)
        for r in api.pages("/installation/repositories", key="repositories"):
            if r["full_name"] not in repos:
                repos.append(r["full_name"])
    result = RunResult()
    for name in repos:
        try:
            snap = collect_repository(api, name, paths)
        except Unavailable as e:
            result.gaps[name] = str(e)
            continue
        with transaction(engine, "aap_worker") as conn:
            out = sync_repository(conn, bundle, snap, datetime.now(UTC), api)
        result.items += len(out.written)
        if out.gaps:
            result.gaps[name] = out.gaps
    if not p.get("repo"):  # a full run also picks up workflow runs whose webhook never arrived
        result.items += _reconcile_github_runs(engine, api, org, result)
    return result


def _reconcile_github_runs(engine: Engine, api: Any, org: str, result: RunResult) -> int:
    from aap.connectors.github_settings import Unavailable
    from aap.services.github_sync import reconcile_runs, registered_repositories

    now = datetime.now(UTC)
    with transaction(engine, "aap_worker") as conn:
        last = conn.execute(
            text(  # full runs only (empty target): a one-repository sync after a webhook does not reconcile
                "SELECT max(started_at) FROM connector_runs WHERE connector = 'github' AND target = ''"
                " AND status IN ('ok', 'partial')"
            )
        ).scalar()
        repos = registered_repositories(conn, org)
    # since the last good run (an hour of overlap), at most 7 days back; 3 days on the first run
    since = max(now - timedelta(days=7), (last - timedelta(hours=1)) if last else now - timedelta(days=3))
    queued = 0
    for name, external_id in repos:
        try:
            with transaction(engine, "aap_worker") as conn:
                queued += reconcile_runs(conn, api, name, external_id, since)
        except Unavailable as e:
            result.gaps[f"{name} (workflow runs)"] = str(e)
    return queued


def jira(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    from aap.services import ticketing

    with transaction(engine, "aap_worker") as conn:
        rep = ticketing.sync(
            conn,
            jira_client(store),
            bundle.doc("integrations")["jira"],
            os.environ.get("AAP_PUBLIC_URL", ""),
            datetime.now(UTC),
        )
    gaps = {"findings_without_project": rep.skipped_no_project} if rep.skipped_no_project else {}
    return RunResult(
        len(rep.created) + rep.fix_pending + len(rep.closed_tickets) + len(rep.reopened_tickets), gaps, rep.errors
    )


def dependency_track(
    engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any], blobs: EvidenceBlobStore
) -> RunResult:
    from aap.services import sbom_sync

    dt, rep = dt_client(store), sbom_sync.DtReport()
    with transaction(engine, "aap_worker") as conn:
        sbom_sync.upload_current(conn, dt, blobs, rep)
    with transaction(engine, "aap_worker") as conn:
        sbom_sync.pull_findings(conn, dt, datetime.now(UTC), rep)
    return RunResult(rep.uploaded + rep.findings_raised, {}, rep.errors)


def defectdojo(
    engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any], blobs: EvidenceBlobStore
) -> RunResult:
    """Forward the given accepted evidence (payload `evidence_ids`) whose type DefectDojo should receive."""
    from aap.connectors.defectdojo import DefectDojoError

    policy = bundle.doc("integrations")["defectdojo"]
    if not policy.get("enabled"):
        return RunResult(gaps={"disabled": True})
    scan_types: dict[str, str] = policy.get("forward_scan_types") or {}
    dd, result = dd_client(store), RunResult()
    with transaction(engine, "aap_worker") as conn:
        rows = conn.execute(
            text("""SELECT e.evidence_id, e.evidence_type, e.scope_ref, e.raw_location, a.app_key
                    FROM evidence e JOIN applications a ON a.id = e.application_id
                    WHERE e.evidence_id = ANY(CAST(:ids AS uuid[])) AND e.evidence_type = ANY(:types)"""),
            {"ids": list(p.get("evidence_ids") or []), "types": list(scan_types)},
        ).all()
    for r in rows:
        manifest = json.loads(blobs.get(r.raw_location))
        for f in manifest["files"]:
            if f["media_type"] not in ("application/sarif+json", "application/xml", "application/json"):
                continue
            try:
                dd.reimport(
                    scan_type=scan_types[r.evidence_type],
                    data=blobs.get(f"blob://sha256/{f['sha256']}"),
                    filename=f["path"].rsplit("/", 1)[-1],
                    product=r.app_key,
                    engagement=f"CI/CD {r.scope_ref}",
                    test_title=f"{r.evidence_type} {r.scope_ref}",
                )
                result.items += 1
            except DefectDojoError as e:
                result.errors.append(str(e))
    return result


def azure(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    from aap.connectors.cloud import DefenderClient, azure_token
    from aap.services import cloud_sync

    findings = list(DefenderClient(azure_token(azure_credential())).unhealthy(csv_env("AAP_AZURE_SUBSCRIPTIONS")))
    with transaction(engine, "aap_worker") as conn:
        rep = cloud_sync.sync(conn, "azure", "defender", findings, datetime.now(UTC))
    return RunResult(rep.findings, cloud_sync.unmapped_summary(rep))


def aws(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    from aap.connectors.cloud import SecurityHubClient, entra_web_identity_token, web_identity_session
    from aap.services import cloud_sync

    regions = _policy_value(bundle, "cloud.aws.regions") or ["eu-west-2"]
    token = entra_web_identity_token(
        azure_credential(), os.environ.get("AAP_AWS_WEB_IDENTITY_AUDIENCE", "api://AzureADTokenExchange")
    )
    hub = SecurityHubClient(web_identity_session(os.environ["AAP_AWS_ROLE_ARN"], token, regions[0]), regions)
    findings = list(hub.active(csv_env("AAP_AWS_ACCOUNTS")))
    with transaction(engine, "aap_worker") as conn:
        rep = cloud_sync.sync(conn, "aws", "security_hub", findings, datetime.now(UTC))
    return RunResult(rep.findings, cloud_sync.unmapped_summary(rep))


def other_siem_sinks(key: str) -> list[str]:
    """Every other installed SIEM plugin (built in or third party) whose settings are present."""
    from aap.plugins import registry

    return sorted(
        p.key
        for p in registry().plugins.values()
        if p.kind == "siem" and p.key != key and p.env and all(os.environ.get(e) for e in p.env)
    )


def _siem(engine: Engine, bundle: ConfigBundle, key: str, client: Callable[[], Any]) -> RunResult:
    """Events leave once, through one sink: two configured sinks would each take a share of the outbox."""
    from aap.services import siem_export

    others = other_siem_sinks(key)
    if others:
        return RunResult(errors=[f"more than one SIEM sink is configured ({key}, {', '.join(others)}): keep one"])
    with transaction(engine, "aap_worker") as conn:
        siem_export.derive(conn, bundle.doc("siem_events"), datetime.now(UTC), os.environ.get("AAP_PUBLIC_URL", ""))
    with transaction(engine, "aap_worker") as conn:
        sent, error = siem_export.dispatch(conn, client(), int(_policy_value(bundle, "siem.batch_max_events") or 500))
    return RunResult(sent, {}, [error] if error else [])


def sentinel(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    return _siem(engine, bundle, "sentinel", sentinel_client)


def siem_http(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    from aap.connectors.siem_sinks import HttpSink

    return _siem(
        engine,
        bundle,
        "siem_http",
        lambda: HttpSink(
            os.environ["AAP_SIEM_HTTP_URL"],
            store.get("siem-http-token") or "",
            os.environ.get("AAP_SIEM_HTTP_FORMAT", "json"),
        ),
    )


def syslog(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    from aap.connectors.siem_sinks import SyslogSink

    return _siem(
        engine,
        bundle,
        "syslog",
        lambda: SyslogSink(os.environ["AAP_SIEM_SYSLOG"], os.environ.get("AAP_SIEM_SYSLOG_CA") or None),
    )


def _feeds_enabled(bundle: ConfigBundle) -> bool:
    return bool((bundle.doc("integrations").get("vuln_feeds") or {}).get("enabled", True))


def _feed_result(rep: Any) -> RunResult:
    gaps = {"errors": len(rep.errors)} if rep.errors else {}
    return RunResult(rep.links_added + rep.changed + rep.findings_raised, gaps, rep.errors[:20])


def osv(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    from aap.connectors.vuln_feeds import OsvClient
    from aap.services import vuln_feeds

    if not _feeds_enabled(bundle):
        return RunResult(gaps={"disabled": True})
    with transaction(engine, "aap_worker") as conn:
        return _feed_result(vuln_feeds.osv_sync(conn, OsvClient(), datetime.now(UTC)))


def cisa_kev(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    from aap.connectors.vuln_feeds import KevClient
    from aap.services import vuln_feeds

    if not _feeds_enabled(bundle):
        return RunResult(gaps={"disabled": True})
    with transaction(engine, "aap_worker") as conn:
        return _feed_result(vuln_feeds.kev_sync(conn, KevClient()))


def epss(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    from aap.connectors.vuln_feeds import EpssClient
    from aap.services import vuln_feeds

    if not _feeds_enabled(bundle):
        return RunResult(gaps={"disabled": True})
    with transaction(engine, "aap_worker") as conn:
        return _feed_result(vuln_feeds.epss_sync(conn, EpssClient()))


def endoflife(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    import yaml

    from aap.config import rules_file
    from aap.connectors.eol import EolClient
    from aap.services import eol

    if not _feeds_enabled(bundle):
        return RunResult(gaps={"disabled": True})
    policy = yaml.safe_load(rules_file("config/eol-products.yaml").read_text())
    with transaction(engine, "aap_worker") as conn:
        out = eol.eol_sync(conn, EolClient(), policy, datetime.now(UTC))
    return RunResult(
        out["applications"], {"unreadable_products": out["errors"]} if out["errors"] else {}, out["errors"]
    )


def webhook(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    """Deliver queued notifications to the incoming webhook (secret `notify-webhook-url`, https only)."""
    import httpx

    from aap.services import notifications

    url = store.get("notify-webhook-url") or ""
    if not url.startswith("https://"):
        return RunResult(errors=["notify-webhook-url must be an https:// URL"])
    result = RunResult()
    with httpx.Client(timeout=15.0, follow_redirects=False) as http, transaction(engine, "aap_worker") as conn:
        notifications.collect(conn, bundle, datetime.now(UTC), os.environ.get("AAP_PUBLIC_URL", ""))
        for event in notifications.pending(conn):
            try:
                r = http.post(url, json=notifications.message(event))
            except httpx.HTTPError as e:
                result.errors.append(f"{event['key']}: {type(e).__name__}")
                break  # endpoint down: keep the rest queued for the next run
            if r.status_code >= 300:
                result.errors.append(f"{event['key']}: HTTP {r.status_code}")
                break
            notifications.mark_sent(conn, int(event["id"]))
            result.items += 1
    return result


def gitlab(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    """Settings evidence for GitLab projects: every project in the group (discovery), or one after a webhook."""
    from aap.connectors.github_settings import Unavailable
    from aap.connectors.gitlab import GitLabComponents, GitLabRest
    from aap.connectors.gitlab_settings import collect_project, group_exists
    from aap.integrations import gitlab_client
    from aap.services.github_sync import sync_repository
    from aap.store import jobs

    api = gitlab_client(store)
    trusted = GitLabComponents.from_config(bundle.doc("trusted_producers"))
    group = os.environ["AAP_GITLAB_GROUP"]
    if p.get("project_id"):
        projects: list[str | int] = [int(p["project_id"])]
    else:
        projects = [
            pr["id"]
            for pr in api.pages(
                f"/groups/{GitLabRest.pid(group)}/projects", {"include_subgroups": "true", "archived": "false"}
            )
        ]
    result = RunResult()
    teams = group_exists(api)
    for project in projects:
        try:
            snap = collect_project(api, project, trusted)
        except Unavailable as e:
            result.gaps[str(project)] = str(e)
            continue
        with transaction(engine, "aap_worker") as conn:
            out = sync_repository(conn, bundle, snap, datetime.now(UTC), None, teams)
            if out.registered:  # GitLab Free has no group webhooks: poll the component jobs that finished lately
                latest = api.get(
                    f"/projects/{snap.github_id}/jobs", {"scope[]": ["success", "failed"], "per_page": 100}
                )
                for job in latest:
                    if str(job.get("name", "")).startswith("aap-") and _recent(job.get("finished_at")):
                        jobs.enqueue(
                            conn,
                            "gitlab-ingest",
                            {"provider": "gitlab", "project_id": snap.github_id, "job_id": job["id"]},
                            dedup_key=f"glrun:{snap.github_id}:{job['id']}",
                        )
        result.items += len(out.written)
        if out.gaps:
            result.gaps[snap.full_name] = out.gaps
    return result


def _recent(ts: str | None, days: int = 2) -> bool:
    from datetime import timedelta

    if not ts:
        return False
    return datetime.fromisoformat(ts.replace("Z", "+00:00")) > datetime.now(UTC) - timedelta(days=days)


def _issue_sync(engine: Engine, bundle: ConfigBundle, client: Any, section: str) -> RunResult:
    from aap.services import ticketing

    with transaction(engine, "aap_worker") as conn:
        rep = ticketing.sync(
            conn, client, bundle.doc("integrations")[section], os.environ.get("AAP_PUBLIC_URL", ""), datetime.now(UTC)
        )
    gaps = {"findings_without_project": rep.skipped_no_project} if rep.skipped_no_project else {}
    return RunResult(
        len(rep.created) + rep.fix_pending + len(rep.closed_tickets) + len(rep.reopened_tickets), gaps, rep.errors
    )


def github_issues(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    from aap.connectors.issues import GitHubIssues

    # a token that can only write issues (and read metadata): the read-only connectors never hold write access
    auth = github_auth(store, {"issues": "write", "metadata": "read"})
    client = GitHubIssues(
        lambda owner: auth.token_provider(owner)(), os.environ.get("AAP_GITHUB_API", "https://api.github.com")
    )
    return _issue_sync(engine, bundle, client, "github_issues")


def gitlab_issues(engine: Engine, bundle: ConfigBundle, store: SecretStore, p: Mapping[str, Any]) -> RunResult:
    from aap.connectors.issues import GitLabIssues

    token = store.get("gitlab-issues-token") or ""
    return _issue_sync(engine, bundle, GitLabIssues(lambda: token, os.environ["AAP_GITLAB_URL"]), "gitlab_issues")
