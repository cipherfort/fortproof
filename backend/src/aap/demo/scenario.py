# SPDX-License-Identifier: Apache-2.0
"""The demo world: four applications that exercise the engine end to end.

| App                | Tier | Story                                                                                      |
|--------------------|------|--------------------------------------------------------------------------------------------|
| Claims API         | 1    | Mature: verified SAST/SBOM, reviews done; but log4j-core 2.14.1 (KEV) → P1; IaC repo unscanned |
| Payments Portal    | 2    | SAST misses Go (partial); an exposed, still-valid secret (P1); a forged evidence attempt    |
| HR Leave Tracker   | 3    | Code scanning "enabled" (C1) but never ran → no evidence; SBOM 120 days old → stale         |
| Team Wiki Helper   | 4    | Prototype: almost nothing, and no SBOM → "possibly affected" in the CVE query              |

Pipeline evidence goes through the REAL ingestion and verification path (FakeGitHub stands in for the GitHub App).
Connector/manual evidence uses the same summaries the GitHub connector and workflow engine will produce.
Everything else (classification, risk, freshness, evaluation, maturity) is the production code.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import Connection, text

from aap.blobstore import EvidenceBlobStore
from aap.config import ConfigBundle
from aap.connectors.github import FakeGitHub, FakeRun
from aap.demo import bundles
from aap.demo.seed import AppSpec, RepoSpec, connector_evidence, demo_trusted, good_repo_settings, register
from aap.domain.evidence import RunInfo
from aap.ingest.pipeline import ingest_workflow_run
from aap.services import assessments, evaluation, exceptions, risk_service, snapshots, vuln_service
from aap.store import config_store, findings_store, registry, supply_chain

LOG4SHELL = {
    "id": "CVE-2021-44228",
    "aliases": ["GHSA-jfh8-c2jp-5v3q"],
    "source": "osv",
    "title": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP endpoints (Log4Shell)",
    "cwe": [502, 917],
    "cvss_v3_score": 10.0,
    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "epss_score": 0.944,
    "epss_percentile": 0.999,
    "epss_date": "2026-10-06",
    "in_kev": True,
    "kev_added_at": "2021-12-10",
    "exploit_public": True,
    "affected": [
        {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core", "ranges": [{"introduced": "2.0", "fixed": "2.15.0"}]}
    ],
}


def sha(seed: str) -> str:
    return hashlib.sha1(seed.encode(), usedforsecurity=False).hexdigest()


HEADS = {  # default-branch HEAD per demo repository
    "example-org/claims-api": sha("claims-api@main"),
    "example-org/claims-infra": sha("claims-infra@main"),
    "example-org/payments-portal": sha("payments@main"),
    "example-org/leave-tracker": sha("leave@main"),
    "example-org/wiki-helper": sha("wiki@main"),
}


@dataclass
class DemoResult:
    applications: dict[str, str]  # name → app id
    users: dict[str, str]  # login → user id
    rejections: list[tuple[str, str]]


def seed(conn: Connection, bundle: ConfigBundle, blobs: EvidenceBlobStore, now: datetime | None = None) -> DemoResult:
    now = now or datetime.now(UTC)
    config_store.load(conn, bundle, git_sha="demo")

    # ---------------------------------------------------------------- organisation & people
    org = registry.upsert_org_unit(conn, "example-org", "Example Organisation", "organisation", None)
    benefits = registry.upsert_org_unit(conn, "benefits", "Benefits", "business_unit", org)
    corporate = registry.upsert_org_unit(conn, "corporate", "Corporate Services", "business_unit", org)
    claims_team = registry.upsert_org_unit(conn, "claims-team", "Claims team", "team", benefits)
    payments_team = registry.upsert_org_unit(conn, "payments-team", "Payments team", "team", benefits)
    people_team = registry.upsert_org_unit(conn, "people-systems", "People Systems team", "team", corporate)

    users = {
        "ajones": registry.upsert_user(conn, "Amira Jones", "ajones"),  # champion, Claims
        "bsmith": registry.upsert_user(conn, "Ben Smith", "bsmith"),  # tech owner, Claims
        "cpatel": registry.upsert_user(conn, "Chandra Patel", "cpatel"),  # AppSec engineer
        "dlee": registry.upsert_user(conn, "Dana Lee", "dlee"),  # Benefits security lead
        "ekim": registry.upsert_user(conn, "Eun Kim", "ekim"),  # engineer, Payments
        "fwong": registry.upsert_user(conn, "Farah Wong", "fwong"),  # executive
        "gokafor": registry.upsert_user(conn, "Grace Okafor", "gokafor"),  # engineer, People Systems
        "nhaddad": registry.upsert_user(conn, "Noor Haddad", "nhaddad"),  # engineer in no team yet: sees nothing
        "padmin": registry.upsert_user(conn, "Pat Admin", "padmin"),  # platform administrator (no data access)
    }
    for login, team in (
        ("ajones", claims_team),
        ("bsmith", claims_team),
        ("ekim", payments_team),
        ("gokafor", people_team),
    ):
        registry.add_member(conn, team, users[login])
    registry.grant_role(conn, users["ajones"], "champion", claims_team)
    registry.grant_role(conn, users["cpatel"], "appsec_engineer")
    registry.grant_role(conn, users["dlee"], "unit_lead", benefits)
    registry.grant_role(conn, users["fwong"], "executive")
    registry.grant_role(conn, users["padmin"], "platform_admin")

    # ---------------------------------------------------------------- applications
    apps: dict[str, str] = {}
    apps["Claims API"], _ = register(
        conn,
        bundle,
        AppSpec(
            name="Claims API",
            description="Customers submit and track their claims.",
            team_slug="claims-team",
            lifecycle="production",
            classification={
                "data_classification": "confidential",
                "personal_data": "customer_personal",
                "exposure": "internet_authenticated",
                "user_population": "public_large",
                "business_criticality": "major",
                "privileged_integration": "limited",
                "regulatory": ["GDPR"],
            },
            profile={
                "languages": ["java", "javascript"],
                "has_api": True,
                "has_web_frontend": True,
                "container_images": ["exampleacr.azurecr.io/claims-api"],
                "github_environments": ["test", "production"],
            },
            owners={"business": users["dlee"], "technical": users["bsmith"], "champion": users["ajones"]},
            repos=[
                RepoSpec(
                    "example-org/claims-api",
                    7001,
                    "primary",
                    sha("claims-api@main"),
                    {
                        "languages": ["java", "javascript"],
                        "ecosystems": ["maven", "npm"],
                        "workflows": True,
                        "dockerfiles": True,
                    },
                ),
                RepoSpec(
                    "example-org/claims-infra",
                    7002,
                    "iac",
                    sha("claims-infra@main"),
                    {"languages": ["hcl"], "ecosystems": ["terraform"], "iac": True, "workflows": True},
                ),
            ],
        ),
        claims_team,
        users["cpatel"],
    )
    apps["Payments Portal"], _ = register(
        conn,
        bundle,
        AppSpec(
            name="Payments Portal",
            description="Caseworkers authorise benefit payments.",
            team_slug="payments-team",
            lifecycle="production",
            classification={
                "data_classification": "confidential",
                "personal_data": "customer_personal",
                "exposure": "internal",
                "user_population": "organisation",
                "business_criticality": "moderate",
                "privileged_integration": "limited",
                "regulatory": ["GDPR"],
            },
            profile={"languages": ["java", "go"], "has_api": True, "has_web_frontend": True},
            owners={"champion": users["ekim"]},
            repos=[
                RepoSpec(
                    "example-org/payments-portal",
                    7101,
                    "primary",
                    sha("payments@main"),
                    {"languages": ["java", "go"], "ecosystems": ["maven", "gomod"], "workflows": True},
                )
            ],
        ),
        payments_team,
        users["cpatel"],
    )
    apps["HR Leave Tracker"], _ = register(
        conn,
        bundle,
        AppSpec(
            name="HR Leave Tracker",
            description="Staff request and approve leave.",
            team_slug="people-systems",
            lifecycle="production",
            classification={
                "data_classification": "internal",
                "personal_data": "limited",
                "exposure": "internal",
                "user_population": "organisation",
                "business_criticality": "moderate",
                "privileged_integration": "none",
            },
            profile={"languages": ["python"], "has_api": False, "has_web_frontend": True},
            owners={"business": users["gokafor"], "technical": users["gokafor"]},
            repos=[
                RepoSpec(
                    "example-org/leave-tracker",
                    7201,
                    "primary",
                    sha("leave@main"),
                    {"languages": ["python"], "ecosystems": ["pypi"], "workflows": True},
                )
            ],
        ),
        people_team,
        users["cpatel"],
    )
    apps["Team Wiki Helper"], _ = register(
        conn,
        bundle,
        AppSpec(
            name="Team Wiki Helper",
            description="Prototype bot that summarises wiki pages.",
            team_slug="people-systems",
            lifecycle="pilot",
            classification={
                "data_classification": "public",
                "personal_data": "none",
                "exposure": "internal",
                "user_population": "team",
                "business_criticality": "minimal",
                "privileged_integration": "none",
            },
            profile={"languages": ["typescript"]},
            repos=[
                RepoSpec(
                    "example-org/wiki-helper",
                    7301,
                    "primary",
                    sha("wiki@main"),
                    {"languages": ["typescript"], "ecosystems": ["npm"], "workflows": False},
                )
            ],
        ),
        people_team,
        users["cpatel"],
    )

    # ---------------------------------------------------------------- pipeline evidence (real verification path)
    gh = FakeGitHub()
    trusted = demo_trusted(bundle, bundles.DEMO_WORKFLOW_SHA)
    run_id = iter(range(9000, 10000))

    def pipeline(
        repo: str,
        gid: int,
        etype: str,
        files: dict[str, bytes],
        tool: str,
        version: str,
        summary: dict[str, object] | None = None,
        refs: tuple[str, ...] | None = None,
        produced: datetime | None = None,
        result: str = "findings",
    ) -> list[tuple[str, str]]:
        rid = next(run_id)
        head = HEADS[repo]
        zipped = bundles.build(
            evidence_type=etype,
            repo_full_name=repo,
            repo_id=gid,
            commit_sha=head,
            run_id=rid,
            tool=tool,
            tool_version=version,
            files=files,
            summary=summary,
            produced_at=produced,
            result=result,
        )
        gh.add_run(
            repo,
            FakeRun(
                RunInfo(rid, 1, gid, head, "push", "success", refs or (bundles.workflow_ref(etype),)),
                {f"aap-evidence-{etype}": zipped},
            ),
        )
        out = ingest_workflow_run(
            conn,
            github=gh,
            blobs=blobs,
            bundle=bundle,
            trusted=trusted,
            repo_full_name=repo,
            repo_external_id=gid,
            run_id=rid,
        )
        return out.rejected

    codeql = {"query_suite": "security-extended"}

    # ---------------------------------------------------------------- a year of history (for the trend charts)
    # Earlier scans and settings syncs, ingested in date order through the same verification pipeline: a few days
    # before each month end (as regular CI runs and the daily settings sync would), from the month after each
    # application was onboarded. Each scan reports a slightly different set of issues, so findings are found and
    # then fixed (a later scan that no longer reports one closes it, as of that scan). Every month is later computed
    # as of its last day by snapshots.backfill: the trends come from the engine, nothing is drawn by hand.
    onboarded_days_ago = {"Claims API": 330, "Payments Portal": 260, "HR Leave Tracker": 190, "Team Wiki Helper": 100}
    pools = {
        "example-org/claims-api": [
            (
                "java/xxe",
                "XML external entity expansion",
                9.1,
                611,
                "src/main/java/org/example/claims/ImportService.java",
            ),
            (
                "java/path-injection",
                "Uncontrolled data used in path expression",
                7.5,
                22,
                "src/main/java/org/example/claims/Files.java",
            ),
            ("js/prototype-pollution", "Prototype-polluting assignment", 7.3, 1321, "web/src/util/merge.ts"),
            (
                "java/log-injection",
                "Log entries created from user input",
                5.0,
                117,
                "src/main/java/org/example/claims/Audit.java",
            ),
            (
                "java/weak-cryptographic-algorithm",
                "Use of a broken cryptographic algorithm",
                7.5,
                327,
                "src/main/java/org/example/claims/Tokens.java",
            ),
            ("js/reflected-xss", "Reflected cross-site scripting", 6.1, 79, "web/src/pages/Search.tsx"),
            ("java/ssrf", "Server-side request forgery", 9.1, 918, "src/main/java/org/example/claims/Fetcher.java"),
        ],
        "example-org/payments-portal": [
            (
                "go/sql-injection",
                "Database query built from user-controlled sources",
                8.8,
                89,
                "internal/ledger/query.go",
            ),
            (
                "java/insecure-cookie",
                "Cookie without the Secure flag",
                4.3,
                614,
                "src/main/java/org/example/pay/Session.java",
            ),
            ("go/clear-text-logging", "Clear-text logging of sensitive information", 7.5, 312, "internal/audit/log.go"),
        ],
        "example-org/leave-tracker": [
            ("py/flask-debug", "Flask app run in debug mode", 7.5, 215, "app/main.py"),
            ("py/reflective-xss", "Reflected server-side cross-site scripting", 6.1, 79, "app/views.py"),
        ],
    }
    # month index after onboarding → which issues of the pool that month's scan still reports
    plans = {
        "example-org/claims-api": [
            [0, 1, 2, 3],
            [0, 1, 2, 3, 4],
            [1, 2, 4],
            [2, 4, 5],
            [4, 5, 6],
            [5, 6],
            [6],
            [6],
            [],
        ],
        "example-org/payments-portal": [[0, 1], [0, 1, 2], [0, 2], [2], [2], [2], [2]],
        "example-org/leave-tracker": [[0, 1], [1], [1], [], []],
    }
    repos_of = {
        "Claims API": [
            ("example-org/claims-api", 7001, ["java", "javascript"], ["maven", "npm"]),
            ("example-org/claims-infra", 7002, [], ["terraform"]),
        ],
        "Payments Portal": [("example-org/payments-portal", 7101, ["java", "go"], ["maven", "gomod"])],
        "HR Leave Tracker": [("example-org/leave-tracker", 7201, ["python"], ["pypi"])],
        "Team Wiki Helper": [],
    }
    sboms = {
        "example-org/claims-api": [
            ("spring-boot", "3.3.4", "pkg:maven/org.springframework.boot/spring-boot@3.3.4", "Apache-2.0")
        ],
        "example-org/payments-portal": [("gin", "1.10.0", "pkg:golang/github.com/gin-gonic/gin@v1.10.0", "MIT")],
        "example-org/leave-tracker": [("django", "4.2.16", "pkg:pypi/django@4.2.16", "BSD-3-Clause")],
    }

    def latest(app_id: str, etype: str) -> tuple[dict[str, object], str] | None:
        row = conn.execute(
            text(
                "SELECT summary, confidence::text AS c FROM evidence WHERE application_id = :a AND evidence_type = :t "
                "ORDER BY observed_at DESC LIMIT 1"
            ),
            {"a": app_id, "t": etype},
        ).first()
        return (dict(row.summary or {}), row.c) if row else None

    current_month = snapshots.month_start(now)
    month_ends: list[datetime] = []
    for i in range(11, 0, -1):
        month_ends.append(snapshots.month_end(snapshots.add_months(current_month, -i)))
    for end in month_ends:
        for name, days in onboarded_days_ago.items():
            onboarded = now - timedelta(days=days)
            if end - timedelta(days=3) <= onboarded:
                continue
            k = sum(1 for e in month_ends if onboarded < e - timedelta(days=3) <= end) - 1  # months since onboarding
            synced = end - timedelta(hours=2)  # the daily connector sync, within its re-confirmation window
            app_key = conn.execute(
                text("SELECT app_key FROM applications WHERE id = :a"), {"a": apps[name]}
            ).scalar_one()
            for etype in ("registry.application", "registry.classification"):
                prior = latest(apps[name], etype)
                if prior:
                    connector_evidence(conn, apps[name], app_key, synced, {etype: prior[0]}, confidence=prior[1])
            if name == "Claims API":
                connector_evidence(
                    conn,
                    apps[name],
                    app_key,
                    synced,
                    {
                        "siem.log_source_health": {"events": 9000 + 700 * k},
                        "training.completion": {"courses": ["champion-onboarding"]},
                    },
                    confidence="C3",
                )
                if k == 3:  # the first independent reviews, three months after onboarding
                    connector_evidence(
                        conn,
                        apps[name],
                        app_key,
                        end - timedelta(days=5),
                        {
                            "assessment.threat_model": {
                                "reviewer": "Chandra Patel (AppSec)",
                                "model_commit": sha("claims-api@main"),
                            },
                            "assessment.pentest": {"reviewer": "External tester (CREST)", "outcome": "approved"},
                        },
                        confidence="M2",
                    )
            for repo, gid, languages, ecosystems in repos_of[name]:
                connector_evidence(conn, apps[name], repo, synced, good_repo_settings())
                connector_evidence(
                    conn, apps[name], repo, synced, {"scan.secrets": {"open_alerts": 0}}, confidence="C3"
                )
                if not languages:
                    continue  # infrastructure repository: settings and secrets only
                plan = plans[repo]
                issues = [pools[repo][j] for j in plan[min(k, len(plan) - 1)]]
                tag = repo.split("/")[1]
                pipeline(
                    repo,
                    gid,
                    "scan.sast",
                    {
                        "results.sarif": bundles.sarif(
                            "CodeQL",
                            "2.18.4",
                            [
                                {
                                    "rule": r,
                                    "message": m,
                                    "score": sc,
                                    "cwe": cwe,
                                    "file": fl,
                                    "line": 10 + j,
                                    "fp": f"{tag}-h{j}",
                                }
                                for j, (r, m, sc, cwe, fl) in enumerate(pools[repo])
                                if (r, m, sc, cwe, fl) in issues
                            ],
                        )
                    },
                    "CodeQL",
                    "2.18.4",
                    {"languages": languages, "languages_detected": languages, **codeql},
                    produced=end - timedelta(days=3),
                    result="findings" if issues else "pass",
                )
                pipeline(
                    repo,
                    gid,
                    "scan.sca",
                    {"osv.json": b'{"results": []}'},
                    "osv-scanner",
                    "1.8.5",
                    {"ecosystems": ecosystems, "ecosystems_detected": ecosystems},
                    produced=end - timedelta(days=3),
                )
                # the HR team's SBOM job stopped 120 days ago (its last SBOM, below, is the stale one)
                if not (repo == "example-org/leave-tracker" and end - timedelta(days=3) > now - timedelta(days=121)):
                    pipeline(
                        repo,
                        gid,
                        "sbom",
                        {"bom.json": bundles.cyclonedx(sboms[repo])},
                        "syft",
                        "1.14.0",
                        produced=end - timedelta(days=3),
                        result="pass",
                    )
            risk_service.score_application(conn, bundle, apps[name])  # findings are scored while they are open
            risk_service.publish_posture(conn, apps[name], synced)

    pipeline(
        "example-org/claims-api",
        7001,
        "scan.sast",
        {
            "results.sarif": bundles.sarif(
                "CodeQL",
                "2.19.1",
                [
                    {
                        "rule": "java/sql-injection",
                        "message": "Query built from user-controlled sources",
                        "score": 8.8,
                        "cwe": 89,
                        "file": "src/main/java/org/example/claims/ClaimsRepository.java",
                        "line": 118,
                        "fp": "c1aa01",
                    },
                    {
                        "rule": "js/xss-through-dom",
                        "message": "DOM text reinterpreted as HTML",
                        "score": 6.1,
                        "cwe": 79,
                        "file": "web/src/components/ClaimSummary.tsx",
                        "line": 42,
                        "fp": "c1aa02",
                    },
                ],
            )
        },
        "CodeQL",
        "2.19.1",
        {"languages": ["java", "javascript"], "languages_detected": ["java", "javascript"], **codeql},
    )
    pipeline(
        "example-org/claims-api",
        7001,
        "sbom",
        {
            "bom.json": bundles.cyclonedx(
                [
                    ("log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "Apache-2.0"),
                    ("spring-boot", "3.3.4", "pkg:maven/org.springframework.boot/spring-boot@3.3.4", "Apache-2.0"),
                    (
                        "jackson-databind",
                        "2.17.2",
                        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.2",
                        "Apache-2.0",
                    ),
                    ("react", "18.3.1", "pkg:npm/react@18.3.1", "MIT"),
                ]
            )
        },
        "cdxgen",
        "10.10.0",
        result="pass",
    )
    pipeline(
        "example-org/claims-api",
        7001,
        "scan.sca",
        {"osv.json": b'{"results": []}'},
        "osv-scanner",
        "1.9.0",
        {"ecosystems": ["maven", "npm"], "ecosystems_detected": ["maven", "npm"]},
    )
    pipeline(
        "example-org/claims-api",
        7001,
        "scan.dast",
        {"zap.json": b'{"site": []}'},
        "zap",
        "2.15.0",
        {"target": "https://claims-test.example.org", "authenticated": True, "urls_crawled": 214},
    )
    pipeline(
        "example-org/claims-api",
        7001,
        "test.security",
        {"junit.xml": b"<testsuite tests='14'/>"},
        "junit",
        "5",
        {"tests": 14, "failed": 0},
        result="pass",
    )

    pipeline(
        "example-org/payments-portal",
        7101,
        "scan.sast",
        {
            "results.sarif": bundles.sarif(
                "CodeQL",
                "2.19.1",
                [
                    {
                        "rule": "java/path-injection",
                        "message": "Uncontrolled data used in path expression",
                        "score": 7.5,
                        "cwe": 22,
                        "file": "src/main/java/org/example/payments/ExportController.java",
                        "line": 77,
                        "fp": "p1bb01",
                    }
                ],
            )
        },
        "CodeQL",
        "2.19.1",
        {"languages": ["java"], "languages_detected": ["java", "go"], **codeql},
    )
    pipeline(
        "example-org/payments-portal",
        7101,
        "sbom",
        {
            "bom.json": bundles.cyclonedx(
                [
                    ("log4j-core", "2.17.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", "Apache-2.0"),
                    ("chi", "5.1.0", "pkg:golang/github.com/go-chi/chi/v5@v5.1.0", "MIT"),
                ]
            )
        },
        "cdxgen",
        "10.10.0",
        result="pass",
    )
    # AC-01 in the demo: the Payments team tries to submit "clean" SAST evidence from their own workflow
    forged = pipeline(
        "example-org/payments-portal",
        7101,
        "scan.sast",
        {"results.sarif": bundles.sarif("CodeQL", "2.19.1", [])},
        "CodeQL",
        "2.19.1",
        {"languages": ["java", "go"], "languages_detected": ["java", "go"], **codeql},
        refs=(f"example-org/payments-portal/.github/workflows/quick-scan.yml@{sha('forged')}",),
    )

    pipeline(
        "example-org/leave-tracker",
        7201,
        "sbom",
        {"bom.json": bundles.cyclonedx([("django", "4.2.16", "pkg:pypi/django@4.2.16", "BSD-3-Clause")])},
        "cdxgen",
        "10.10.0",
        produced=now - timedelta(days=120),
        result="pass",
    )

    # ---------------------------------------------------------------- connector & manual evidence
    claims_repo, infra_repo = "example-org/claims-api", "example-org/claims-infra"
    for repo in (claims_repo, infra_repo):
        connector_evidence(conn, apps["Claims API"], repo, now - timedelta(hours=2), good_repo_settings())
    connector_evidence(
        conn,
        apps["Claims API"],
        "APP-claims",
        now - timedelta(hours=2),
        {
            "registry.application": {
                "schema_valid": True,
                "unresolved_owners": [],
                "unlinked_repos": 0,
                "security_policy": True,
                "security_contact": True,
                "asvs_target_level": 3,
                "asvs_required_level": 3,
                "asvs_version": "5.0.0",
            },
            "repo.environments": {
                "production": {"required_reviewers": 1, "branch_policy": True},
                "static_cloud_secret_names": [],
            },
        },
    )
    connector_evidence(
        conn,
        apps["Claims API"],
        claims_repo,
        now - timedelta(days=20),
        {"repo.threat_model": {"schema_valid": True, "high_threats": 2, "high_threats_unmitigated": []}},
        subject_extra={"commit_sha": sha("claims-api@main")},
    )
    connector_evidence(
        conn,
        apps["Claims API"],
        "APP-claims",
        now - timedelta(days=18),
        {
            "assessment.threat_model": {"reviewer": "Chandra Patel (AppSec)", "model_commit": sha("claims-api@main")},
            "assessment.architecture_review": {
                "reviewer": "Chandra Patel (AppSec)",
                "outcome": "approved_with_conditions",
            },
            "assessment.pentest": {"reviewer": "External tester (CREST)", "outcome": "approved"},
        },
        confidence="M2",
    )
    connector_evidence(
        conn,
        apps["Claims API"],
        "APP-claims",
        now - timedelta(hours=3),
        {
            "siem.log_source_health": {"events": 18234},
            "training.completion": {"courses": ["champion-onboarding", "secure-development"]},
        },
        confidence="C3",
    )
    for repo in (claims_repo, infra_repo):
        connector_evidence(
            conn,
            apps["Claims API"],
            repo,
            now - timedelta(hours=2),
            {"scan.secrets": {"open_alerts": 0}},
            confidence="C3",
        )

    pay_repo = "example-org/payments-portal"
    pay_settings = good_repo_settings()
    pay_settings["repo.ruleset"]["required_approvals"] = 1
    connector_evidence(conn, apps["Payments Portal"], pay_repo, now - timedelta(hours=1), pay_settings)
    connector_evidence(
        conn,
        apps["Payments Portal"],
        pay_repo,
        now - timedelta(hours=1),
        {"scan.secrets": {"open_alerts": 1}},
        confidence="C3",
    )
    findings_store.observe(
        conn,
        findings_store.NewFinding(
            fingerprint=f"secret:demo:{sha('payments-azure-sp')}",
            application_id=apps["Payments Portal"],
            repository_id=None,
            scope_type="repository",
            scope_ref=pay_repo,
            finding_type="secret",
            source_system="ghas",
            title="Azure Entra ID client secret committed in config/application-prod.yaml",
            description="GHAS secret scanning, validity check: active. Rotate the credential, then close the alert as revoked.",
            location={"uri": "config/application-prod.yaml", "line": 12, "validity": "active"},
            tool_severity="critical",
            source_refs=[{"system": "ghas", "id": "secret-scanning-alert-17"}],
        ),
        None,
        now - timedelta(days=3),
    )

    leave_repo = "example-org/leave-tracker"
    connector_evidence(
        conn,
        apps["HR Leave Tracker"],
        leave_repo,
        now - timedelta(hours=1),
        {
            "scan.sast": {"code_scanning_default_setup": "configured", "analyses": 0},  # configured ≠ executed
            **{k: v for k, v in good_repo_settings().items() if k != "repo.codeowners"},
        },
    )

    # ---------------------------------------------------------------- vulnerability intelligence → findings
    vuln_id = supply_chain.upsert_vulnerability(conn, LOG4SHELL)
    supply_chain.match_advisory(conn, LOG4SHELL, vuln_id)
    vuln_service.raise_dependency_findings(conn, vuln_id, now)

    # ---------------------------------------------------------------- exceptions and assessments, through their workflows
    # Each one goes through the same service calls the API makes, so segregation of duties and the approval matrix
    # apply: the requester never decides, Tier 1/2 needs the business owner's co-signature, the approver's role must
    # be high enough for the residual risk.
    hr = apps["HR Leave Tracker"]
    accepted = exceptions.create(
        conn,
        bundle,
        application_id=hr,
        target_type="control",
        target_ref="ASC-SRC-02",
        justification="The repository is maintained by one engineer until the team grows next quarter; there is nobody to own reviews.",
        risk_description="Changes to security-sensitive paths are merged without a second reviewer.",
        compensating_controls="Branch protection requires a pull request; AppSec reviews releases monthly.",
        residual_priority="P3",
        remediation_plan="Add CODEOWNERS for the auth and data-access modules when the second engineer joins.",
        requested_by=users["gokafor"],
    )
    exceptions.submit(conn, bundle, accepted, users["gokafor"])
    exceptions.decide(
        conn,
        bundle,
        accepted,
        approver=users["dlee"],
        approver_roles=["unit_lead"],
        outcome="approve",
        comment="Accepted for one quarter with the monthly release review in place.",
    )
    log4j = conn.execute(
        text("""SELECT id FROM findings WHERE application_id = :a AND finding_type = 'dependency'
                AND title ILIKE '%log4j%' ORDER BY first_seen_at LIMIT 1"""),
        {"a": apps["Claims API"]},
    ).first()
    if log4j is not None:
        waiting = exceptions.create(
            conn,
            bundle,
            application_id=apps["Claims API"],
            target_type="finding",
            target_ref=str(log4j.id),
            justification="The upgrade to log4j 2.17 needs a framework upgrade that is scheduled for the next release train.",
            risk_description="Remote code execution through JNDI lookups in logged user input.",
            compensating_controls="log4j2.formatMsgNoLookups=true is set and the WAF blocks JNDI patterns.",
            residual_priority="P2",
            remediation_plan="Upgrade the framework and log4j in release 4.2, due within 30 days.",
            requested_by=users["bsmith"],
        )
        exceptions.submit(conn, bundle, waiting, users["bsmith"])  # waits for the business owner's co-signature
    exceptions.create(
        conn,
        bundle,
        application_id=apps["Payments Portal"],
        target_type="control",
        target_ref="ASC-SRC-01",
        justification="The team has two engineers; requiring two approvals would block every change.",
        risk_description="A single reviewer can approve a change to the default branch.",
        residual_priority="P3",
        remediation_plan="Require two approvals once the team has three engineers.",
        requested_by=users["ekim"],
    )

    review = assessments.create(
        conn, bundle, kind="architecture_review", application_id=apps["Claims API"], lead_assessor=users["ajones"]
    )
    assessments.record(
        conn,
        bundle,
        review,
        users["ajones"],
        {
            "outcome": "approved_with_conditions",
            "findings_summary": "Move session storage out of the API pods before the next major release.",
        },
    )
    assessments.submit(conn, bundle, review, users["ajones"])
    assessments.decide(
        conn,
        review,
        approver=users["cpatel"],
        outcome="approve",
        comment="Reviewed the design and the data flows with the team.",
    )
    assessments.write_evidence(conn, review, now)  # what the worker does on approval
    tm = assessments.create(conn, bundle, kind="threat_model_review", application_id=hr, lead_assessor=users["gokafor"])
    assessments.record(conn, bundle, tm, users["gokafor"], {"model_commit": sha("leave@main"), "outcome": "approved"})
    assessments.submit(conn, bundle, tm, users["gokafor"])  # waits for someone else to review it
    samm = assessments.create(
        conn, bundle, kind="samm_application", application_id=apps["Payments Portal"], lead_assessor=users["ekim"]
    )
    assessments.record(
        conn, bundle, samm, users["ekim"], {"answers": {"D-TA-A:1": 0.5, "D-SR-A:1": 0.25, "V-ST-A:1": 0.5}}
    )

    # ---------------------------------------------------------------- score, publish posture, evaluate
    for app_id in apps.values():
        risk_service.score_application(conn, bundle, app_id)
        risk_service.publish_posture(conn, app_id, now)
        evaluation.evaluate_application(conn, bundle, app_id, now, gap_grace=None)

    # ---------------------------------------------------------------- history for the trend charts
    # The applications joined over the year, so the portfolio grows. Each month is then computed as of its last day by
    # the real evaluator, from the evidence and findings that existed then (snapshots.backfill): nothing is invented.
    for name, days in onboarded_days_ago.items():
        conn.execute(
            text("UPDATE applications SET created_at = :t WHERE id = :a"),
            {"t": now - timedelta(days=days), "a": apps[name]},
        )
    snapshots.backfill(conn, bundle, 12, now)
    return DemoResult(apps, users, forged)
