# SPDX-License-Identifier: Apache-2.0
"""Concrete evaluators, one per `evaluator:` name used in catalogue/controls/controls.yaml.

Each reads the normalised `summary` its evidence types carry. The summary contract per evidence type is written
by the connector or ingestion code that produces it (see `aap.ingest.summaries`). Evaluators never see stale or
under-confident evidence (the framework filters it), so "nothing usable" always means NO_EVIDENCE here.
"""

from __future__ import annotations

from collections.abc import Sequence

from aap.domain.controls import ControlState, EvidenceView
from aap.evaluators.base import EvaluationInput, EvaluationResult, FindingView, evaluator, latest

S = ControlState
SEVERITY = ("info", "low", "medium", "high", "critical")
QUERY_SUITES = ("default", "security-extended", "security-and-quality")
OPEN = frozenset({"new", "triaged", "ticketed", "fix_pending", "reopened"})


def _short(sha: object) -> str:
    return str(sha)[:7] if sha else "?"


def _ids(*evidence: EvidenceView | None) -> tuple[str, ...]:
    return tuple(e.id for e in evidence if e is not None)


def _none(what: str) -> EvaluationResult:
    return EvaluationResult(S.NO_EVIDENCE, f"no current {what} evidence")


def _bool_checks(ev: EvidenceView, checks: dict[str, bool], ok: str) -> EvaluationResult:
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return EvaluationResult(S.NOT_SATISFIED, "not met: " + "; ".join(failed), _ids(ev))
    return EvaluationResult(S.SATISFIED, ok, _ids(ev))


# ------------------------------------------------------------------------------------------ registry & GOV


@evaluator("registry_complete@1")
def registry_complete(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "registry.application")
    if ev is None:
        return _none("application.yaml")
    s = ev.summary
    unresolved = list(s.get("unresolved_owners") or [])
    return _bool_checks(
        ev,
        {
            "application.yaml is schema-valid": bool(s.get("schema_valid")),
            f"owners resolve to active identities (unresolved: {', '.join(unresolved) or 'none'})": not unresolved,
            "all implementing repositories linked": int(s.get("unlinked_repos", 0))
            <= int(i.params.get("max_unlinked_repos", 0)),
        },
        "application registered; owners resolve to active identities",
    )


@evaluator("classification_current@1")
def classification_current(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "registry.classification")
    if ev is None:
        return _none("approved classification")
    if ev.summary.get("decision") in ("approved", "auto_approved"):
        return EvaluationResult(S.SATISFIED, f"Tier {ev.summary.get('tier')} approved ({ev.confidence})", _ids(ev))
    return EvaluationResult(S.NOT_SATISFIED, f"classification {ev.summary.get('decision', 'pending')}", _ids(ev))


@evaluator("champion_assigned@1")
def champion_assigned(i: EvaluationInput) -> EvaluationResult:
    reg = latest(i.evidence, "registry.application")
    training = latest(i.evidence, "training.completion")
    if reg is None:
        return _none("application.yaml")
    champion = reg.summary.get("champion")
    if not champion:
        return EvaluationResult(S.NOT_SATISFIED, "no security champion named in application.yaml", _ids(reg))
    course = str(i.params.get("training_course", "champion-onboarding"))
    if training is None or course not in (training.summary.get("courses") or []):
        return EvaluationResult(
            S.PARTIAL, f"{champion} named, but no current '{course}' completion", _ids(reg), {"fraction": 0.5}
        )
    return EvaluationResult(S.SATISFIED, f"{champion} is champion; '{course}' completed", _ids(reg, training))


@evaluator("security_policy_present@1")
def security_policy_present(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "registry.application")
    if ev is None:
        return _none("repository profile")
    return _bool_checks(
        ev,
        {
            "SECURITY.md (repo or org default)": bool(ev.summary.get("security_policy")),
            "monitored security contact": bool(ev.summary.get("security_contact")),
        },
        "security policy and contact published",
    )


@evaluator("asvs_profile_valid@1")
def asvs_profile_valid(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "registry.application")
    if ev is None or "asvs_target_level" not in ev.summary:
        return _none("asvs.yaml")
    declared, needed = int(ev.summary["asvs_target_level"]), int(ev.summary.get("asvs_required_level", 1))
    if declared < needed:
        return EvaluationResult(S.NOT_SATISFIED, f"ASVS target L{declared} below tier requirement L{needed}", _ids(ev))
    return EvaluationResult(S.SATISFIED, f"ASVS {ev.summary.get('asvs_version', '5.0')} L{declared} declared", _ids(ev))


# ------------------------------------------------------------------------------------------ repository config


@evaluator("security_feature_enabled@1")
def security_feature_enabled(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "repo.security_settings")
    if ev is None:
        return _none("repository security settings")
    features = ev.summary.get("features") or {}
    return _bool_checks(
        ev,
        {f: bool(features.get(f)) for f in i.params.get("features", [])},
        "enabled: " + ", ".join(i.params.get("features", [])),
    )


@evaluator("branch_protection@1")
def branch_protection(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "repo.ruleset")
    if ev is None:
        return _none("branch rules")
    s = ev.summary
    need_approvals = int(i.params.get("required_approvals") or 1)
    missing_checks = sorted(set(i.params.get("required_checks", [])) - set(s.get("required_checks") or []))
    return _bool_checks(
        ev,
        {
            "pull request required": bool(s.get("requires_pr")),
            f"≥{need_approvals} approvals (has {s.get('required_approvals', 0)})": int(s.get("required_approvals", 0))
            >= need_approvals,
            "code-owner review": bool(s.get("require_code_owner_review"))
            or not i.params.get("require_code_owner_review"),
            f"required checks (missing: {', '.join(missing_checks)})": not missing_checks,
            "force-push blocked": bool(s.get("blocks_force_push")),
            "deletion blocked": bool(s.get("blocks_deletion")),
        },
        f"default branch protected; {s.get('required_approvals')} approvals, security checks required",
    )


@evaluator("codeowners_coverage@1")
def codeowners_coverage(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "repo.codeowners")
    if ev is None:
        return _none("CODEOWNERS")
    covered = set(ev.summary.get("covered_paths") or [])
    missing = [p for p in i.params.get("required_paths", []) if p not in covered]
    return _bool_checks(
        ev,
        {
            "CODEOWNERS has no errors": int(ev.summary.get("errors", 0)) == 0,
            f"owners for {', '.join(missing)}": not missing,
        },
        "CODEOWNERS valid and covers security-sensitive paths",
    )


@evaluator("repo_access_policy@1")
def repo_access_policy(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "repo.access")
    if ev is None:
        return _none("repository access")
    s = ev.summary
    public_ok = s.get("visibility") != "public" or bool(s.get("open_source_approval"))
    return _bool_checks(
        ev,
        {
            "no outside collaborators with write/admin": int(s.get("outside_writers", 0)) == 0,
            f"≤{i.params.get('max_admin_users', 3)} direct admins (has {s.get('admin_users', 0)})": int(
                s.get("admin_users", 0)
            )
            <= int(i.params.get("max_admin_users", 3)),
            "public visibility approved": public_ok,
        },
        "least-privilege access; visibility approved",
    )


@evaluator("environment_protection@1")
def environment_protection(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "repo.environments")
    if ev is None:
        return _none("deployment environment")
    prod = ev.summary.get("production") or {}
    need = int(i.params.get("required_reviewers") or 0)
    return _bool_checks(
        ev,
        {
            "production environment exists": bool(prod),
            f"≥{need} required reviewers": int(prod.get("required_reviewers", 0)) >= need,
            "deployment branches restricted": bool(prod.get("branch_policy")),
        },
        "production deploys only through a protected environment",
    )


@evaluator("no_static_cloud_credentials@1")
def no_static_cloud_credentials(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "repo.environments")
    if ev is None:
        return _none("secret inventory")
    found = list(ev.summary.get("static_cloud_secret_names") or [])
    if found:
        return EvaluationResult(
            S.NOT_SATISFIED, f"static cloud credentials stored as secrets: {', '.join(found)}", _ids(ev)
        )
    return EvaluationResult(S.SATISFIED, "no static cloud credentials; OIDC federation only", _ids(ev))


# ------------------------------------------------------------------------------------------ build activities


@evaluator("scan_executed@1")
def scan_executed(i: EvaluationInput) -> EvaluationResult:
    """The scan RAN on current code with adequate coverage. Findings are judged elsewhere (VUL controls)."""
    types = i.control["assessment"]["evidence_types"]
    ev = latest(i.evidence)
    if ev is None:
        return EvaluationResult(S.NO_EVIDENCE, f"no execution evidence ({', '.join(types)}) for current code")
    s = ev.summary
    where = f"{s.get('tool', '?')} {s.get('tool_version', '')} on commit {_short(ev.subject.get('commit_sha'))}"
    if ev.result in ("error", "inconclusive"):
        return EvaluationResult(S.NOT_SATISFIED, f"last run ended {ev.result}: {where}", _ids(ev))

    gaps: list[str] = []
    fraction = 1.0
    if i.params.get("language_coverage") == "all_detected" or i.params.get("ecosystem_coverage") == "all_detected":
        analysed = set(s.get("languages") or s.get("ecosystems") or [])
        detected = set(s.get("languages_detected") or s.get("ecosystems_detected") or analysed)
        missing = sorted(detected - analysed)
        if missing:
            gaps.append(f"not analysed: {', '.join(missing)}")
            fraction = len(analysed & detected) / len(detected) if detected else 0.0
    suite = i.params.get("query_suite")
    if (
        suite
        and s.get("query_suite") in QUERY_SUITES
        and QUERY_SUITES.index(s["query_suite"]) < QUERY_SUITES.index(suite)
    ):
        gaps.append(f"suite {s['query_suite']} weaker than required {suite}")
        fraction = min(fraction, 0.5)
    if gaps:
        state = S.PARTIAL if fraction > 0 else S.NOT_SATISFIED
        return EvaluationResult(state, f"{where}; " + "; ".join(gaps), _ids(ev), {"fraction": round(fraction, 2)})
    covered = ", ".join(s.get("languages") or s.get("ecosystems") or []) or "repository"
    return EvaluationResult(S.SATISFIED, f"{where} analysed {covered} ({ev.confidence})", _ids(ev))


@evaluator("scan_clean@1")
def scan_clean(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence)
    if ev is None:
        return _none("scan")
    worst = str(ev.summary.get("max_severity") or "info")
    limit = str(i.params.get("max_severity") or "medium")
    if SEVERITY.index(worst) > SEVERITY.index(limit):
        return EvaluationResult(S.NOT_SATISFIED, f"{worst} issues present (allowed up to {limit})", _ids(ev))
    return EvaluationResult(S.SATISFIED, f"no issues above {limit}", _ids(ev))


@evaluator("sbom_current@1")
def sbom_current(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "sbom")
    if ev is None:
        return _none("SBOM")
    s = ev.summary
    bound = ev.subject.get("artifact_digest") or ev.subject.get("commit_sha")
    return _bool_checks(
        ev,
        {
            f"≥{i.params.get('min_components', 1)} components": int(s.get("component_count", 0))
            >= int(i.params.get("min_components", 1)),
            f"purl coverage ≥{i.params.get('require_purl_pct', 95)}% (has {s.get('purl_coverage_pct', 0)}%)": float(
                s.get("purl_coverage_pct", 0)
            )
            >= float(i.params.get("require_purl_pct", 95)),
            "ingested into Dependency-Track": bool(s.get("dtrack_processed", True)),
        },
        f"CycloneDX SBOM with {s.get('component_count')} components bound to {_short(bound)}",
    )


@evaluator("provenance_verified@1")
def provenance_verified(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "provenance.attestation")
    if ev is None:
        return _none("provenance attestation")
    if ev.result != "pass":
        return EvaluationResult(S.NOT_SATISFIED, "provenance did not verify", _ids(ev))
    return EvaluationResult(
        S.SATISFIED, f"SLSA provenance verified for {_short(ev.subject.get('artifact_digest'))}", _ids(ev)
    )


@evaluator("required_check_configured_and_executing@1")
def required_check(i: EvaluationInput) -> EvaluationResult:
    rules = latest(i.evidence, "repo.ruleset")
    runs = [e for e in i.evidence if e.type != "repo.ruleset"]
    check = i.params.get("check_name")
    configured = bool(rules and check in (rules.summary.get("required_checks") or []))
    if not configured:
        return EvaluationResult(S.NOT_SATISFIED, f"'{check}' is not a required check", _ids(rules))
    executed = sum(int(e.summary.get("pr_executions_30d", 0)) for e in runs)
    if executed < int(i.params.get("min_executions_30d", 1)):
        return EvaluationResult(
            S.PARTIAL, f"'{check}' required but not executed on any PR in 30 days", _ids(rules), {"fraction": 0.5}
        )
    return EvaluationResult(S.SATISFIED, f"'{check}' required and ran on {executed} PRs in 30 days", _ids(rules, *runs))


@evaluator("licence_policy@1")
def licence_policy(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "scan.licence")
    if ev is None:
        return _none("licence evaluation")
    denied = list(ev.summary.get("denied") or [])
    unknown_pct = float(ev.summary.get("unknown_pct", 0))
    return _bool_checks(
        ev,
        {
            f"no denied licences (found: {', '.join(denied)})": not denied,
            f"unknown licences ≤{i.params.get('max_unknown_pct', 5)}% (has {unknown_pct}%)": unknown_pct
            <= float(i.params.get("max_unknown_pct", 5)),
        },
        "licences comply with policy",
    )


# ------------------------------------------------------------------------------------------ testing


@evaluator("tests_executed@1")
def tests_executed(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "test.security")
    if ev is None:
        return _none("security test")
    total, failed = int(ev.summary.get("tests", 0)), int(ev.summary.get("failed", 0))
    if total < int(i.params.get("min_tests", 1)):
        return EvaluationResult(S.PARTIAL, f"only {total} tagged security tests", _ids(ev), {"fraction": 0.5})
    if failed:
        return EvaluationResult(S.NOT_SATISFIED, f"{failed} of {total} security tests failing", _ids(ev))
    return EvaluationResult(S.SATISFIED, f"{total} ASVS-tagged security tests passing", _ids(ev))


@evaluator("dast_executed@1")
def dast_executed(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "scan.dast")
    if ev is None:
        return _none("DAST")
    s = ev.summary
    if int(s.get("urls_crawled", 0)) < int(i.params.get("min_urls_crawled", 10)):
        return EvaluationResult(S.NOT_SATISFIED, f"inconclusive: crawled {s.get('urls_crawled', 0)} URLs", _ids(ev))
    if i.params.get("authenticated") and not s.get("authenticated"):
        return EvaluationResult(
            S.PARTIAL, "scan ran unauthenticated; authenticated scan required", _ids(ev), {"fraction": 0.5}
        )
    return EvaluationResult(
        S.SATISFIED, f"DAST against {s.get('target', 'test environment')} ({s.get('urls_crawled')} URLs)", _ids(ev)
    )


# ------------------------------------------------------------------------------------------ threat model & manual


@evaluator("threat_model_reviewed@1")
def threat_model_reviewed(i: EvaluationInput) -> EvaluationResult:
    structure = latest(i.evidence, "repo.threat_model")
    review = latest(i.evidence, "assessment.threat_model")
    if structure is None and review is None:
        return _none("threat model")
    if structure is None or not structure.summary.get("schema_valid"):
        return EvaluationResult(S.NOT_SATISFIED, "threat model missing or schema-invalid", _ids(structure, review))
    if review is None:
        return EvaluationResult(
            S.PARTIAL,
            f"model present at {_short(structure.subject.get('commit_sha'))}, not reviewed",
            _ids(structure),
            {"fraction": 0.5},
        )
    if review.summary.get("model_commit") and review.summary["model_commit"] != structure.subject.get("commit_sha"):
        return EvaluationResult(
            S.PARTIAL, "model changed since it was reviewed", _ids(structure, review), {"fraction": 0.5}
        )
    return EvaluationResult(
        S.SATISFIED,
        f"reviewed by {review.summary.get('reviewer', 'reviewer')} ({review.confidence})",
        _ids(structure, review),
    )


@evaluator("threat_mitigation_linkage@1")
def threat_mitigation_linkage(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "repo.threat_model")
    if ev is None:
        return _none("threat model")
    unlinked = list(ev.summary.get("high_threats_unmitigated") or [])
    if unlinked:
        return EvaluationResult(
            S.NOT_SATISFIED, f"high threats without resolvable mitigation: {', '.join(unlinked)}", _ids(ev)
        )
    return EvaluationResult(
        S.SATISFIED, f"all {ev.summary.get('high_threats', 0)} high threats mitigated or accepted", _ids(ev)
    )


@evaluator("evidence_fresh@1")
def evidence_fresh(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence)
    if ev is None:
        return _none(", ".join(i.control["assessment"]["evidence_types"]))
    return EvaluationResult(
        S.SATISFIED, f"current ({ev.type}, {ev.confidence}, observed {ev.observed_at:%Y-%m-%d})", _ids(ev)
    )


@evaluator("manual_attestation@1")
def manual_attestation(i: EvaluationInput) -> EvaluationResult:
    # a manual attestation names the control it attests; one written for another control never counts here
    own = str(i.control.get("id", ""))
    ev = latest([e for e in i.evidence if e.type != "assessment.manual_control" or e.summary.get("control_key") == own])
    if ev is None:
        return EvaluationResult(S.NO_EVIDENCE, f"no current {i.required_confidence} assessment recorded")
    if ev.result in ("fail", "findings") and ev.summary.get("outcome") == "rejected":
        return EvaluationResult(S.NOT_SATISFIED, f"assessment outcome rejected ({ev.type})", _ids(ev))
    who = ev.summary.get("reviewer", "reviewer")
    return EvaluationResult(
        S.SATISFIED,
        f"{ev.type.split('.')[-1].replace('_', ' ')} by {who} ({ev.confidence}, {ev.observed_at:%Y-%m-%d})",
        _ids(ev),
    )


@evaluator("periodic_process@1")
def periodic_process(i: EvaluationInput) -> EvaluationResult:
    return manual_attestation(i)


@evaluator("log_source_healthy@1")
def log_source_healthy(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "siem.log_source_health")
    if ev is None:
        return _none("SIEM log-source health")
    events = int(ev.summary.get("events", 0))
    if events <= 0:
        return EvaluationResult(
            S.NOT_SATISFIED, f"no security events received in {i.params.get('window_hours', 24)}h", _ids(ev)
        )
    return EvaluationResult(
        S.SATISFIED, f"{events} security events received in {i.params.get('window_hours', 24)}h", _ids(ev)
    )


# ------------------------------------------------------------------------------------------ outcomes (findings)


def _matching(findings: Sequence[FindingView], params: dict[str, object] | object) -> list[FindingView]:
    p = params if isinstance(params, dict) else {}
    ftype, source = p.get("finding_type"), p.get("source")
    sources = set(source) if isinstance(source, list) else ({source} if source else None)
    return [
        f for f in findings if (ftype is None or f.finding_type == ftype) and (sources is None or f.source in sources)
    ]


@evaluator("no_open_findings@1")
def no_open_findings(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence)
    if ev is None:
        return _none(", ".join(i.control["assessment"]["evidence_types"]))
    open_ = [f for f in _matching(i.findings, dict(i.params)) if f.status in OPEN]
    validity = i.params.get("validity")
    if validity:
        open_ = [f for f in open_ if f.details.get("validity", "unknown") in validity]
    if open_:
        return EvaluationResult(
            S.NOT_SATISFIED,
            f"{len(open_)} open {i.params.get('finding_type', '')} finding(s)",
            _ids(ev),
            {"finding_ids": [f.id for f in open_]},
        )
    return EvaluationResult(
        S.SATISFIED,
        f"no open {i.params.get('finding_type', '')} findings (checked {ev.observed_at:%Y-%m-%d %H:%M})",
        _ids(ev),
    )


@evaluator("findings_within_sla@1")
def findings_within_sla(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence)
    if ev is None:
        return _none(", ".join(i.control["assessment"]["evidence_types"]))
    pool = [f for f in _matching(i.findings, dict(i.params)) if f.status in OPEN]
    max_overdue = i.params.get("max_overdue") or {"P1": 0, "P2": 0}
    breaches = {p: [f for f in pool if f.priority == p and f.sla_breached] for p in max_overdue}
    over = {p: len(v) for p, v in breaches.items() if len(v) > int(max_overdue[p])}
    if over:
        return EvaluationResult(
            S.NOT_SATISFIED,
            "past SLA: " + ", ".join(f"{n}×{p}" for p, n in over.items()),
            _ids(ev),
            {"finding_ids": [f.id for v in breaches.values() for f in v]},
        )
    return EvaluationResult(S.SATISFIED, f"{len(pool)} open finding(s), none of P1/P2 past SLA", _ids(ev))


@evaluator("triage_within_sla@1")
def triage_within_sla(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence)
    if ev is None:
        return _none("vulnerability posture")
    overdue = [f for f in i.findings if f.status == "new" and f.details.get("triage_overdue")]
    if len(overdue) > int(i.params.get("max_breaches", 0)):
        return EvaluationResult(S.NOT_SATISFIED, f"{len(overdue)} finding(s) untriaged past triage SLA", _ids(ev))
    return EvaluationResult(S.SATISFIED, "all findings owned and triaged within SLA", _ids(ev))


@evaluator("exceptions_governed@1")
def exceptions_governed(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence)
    if ev is None:
        return _none("vulnerability posture")
    expired = [f for f in i.findings if f.finding_type == "exception_expired" and f.status in OPEN]
    if expired:
        return EvaluationResult(S.NOT_SATISFIED, f"{len(expired)} expired exception(s) not remediated", _ids(ev))
    return EvaluationResult(S.SATISFIED, "all exceptions approved, current and within limits", _ids(ev))


# ------------------------------------------------------------------------------------------ M2: the remaining nine
# Summary contracts (config/evidence-types.yaml documents each): training.completion {engineers, completed, course},
# test.security {tests, failures, asvs: {id: pass|fail}, threats: {id: pass|fail}}, assessment.manual_control
# {asvs_verified: [id]}, sbom.eol {snapshot, checked, eol: [...]}, deploy.record subject {artifact_digest,
# environment} + summary {verified, image_created_at}, scan.container subject {artifact_digest}.


def _pct(part: int, whole: int) -> float:
    return 100.0 * part / whole if whole else 0.0


@evaluator("team_training_coverage@1")
def team_training_coverage(i: EvaluationInput) -> EvaluationResult:
    ev = latest([e for e in i.evidence if "engineers" in e.summary], "training.completion")
    if ev is None:
        return _none("team training coverage (LMS connector)")
    engineers, done = int(ev.summary.get("engineers", 0)), int(ev.summary.get("completed", 0))
    threshold = float(i.params.get("threshold_pct", 90))
    pct = _pct(done, engineers)
    text = f"{done}/{engineers} recent contributors ({pct:.0f}%) completed {ev.summary.get('course', 'the course')}"
    if engineers == 0:
        return EvaluationResult(S.NOT_SATISFIED, "no contributors in the window to measure", _ids(ev))
    if pct >= threshold:
        return EvaluationResult(S.SATISFIED, text, _ids(ev))
    state = S.PARTIAL if done else S.NOT_SATISFIED
    return EvaluationResult(state, f"{text}; target {threshold:.0f}%", _ids(ev), {"fraction": round(pct / 100, 2)})


_ASVS_CACHE: dict[str, list[tuple[str, str, int]]] = {}


def asvs_requirements(version: str = "5.0.0") -> list[tuple[str, str, int]]:
    """(id, chapter, level) from the imported official ASVS index (tools/catalogue/import_asvs.py)."""
    if version not in _ASVS_CACHE:
        import yaml

        from aap.config import rules_file

        path = rules_file(f"catalogue/frameworks/asvs-{version}-requirements.yaml")
        doc = yaml.safe_load(path.read_text()) if path.exists() else {"requirements": []}
        _ASVS_CACHE[version] = [(r["id"], r["chapter"], int(r["level"])) for r in doc["requirements"]]
    return _ASVS_CACHE[version]


def asvs_chapter_applies(rule: str, caps: dict[str, object]) -> bool:
    """Chapter conditions of catalogue/frameworks/asvs-applicability.yaml. Unknown forms keep the chapter applicable."""
    import re

    rule = rule.strip()
    if rule == "always":
        return True
    if m := re.fullmatch(r"capabilities\.(\w+)", rule):
        return bool(caps.get(m.group(1), True))
    if m := re.fullmatch(r"capabilities\.(\w+) != '(\w+)'", rule):
        return caps.get(m.group(1), "unknown") != m.group(2)
    if m := re.fullmatch(r"size\(capabilities\.(\w+)\) > 0", rule):
        v = caps.get(m.group(1), [None])
        return bool(v) if isinstance(v, list | dict) else True
    return True


def _asvs_chapters(caps: dict[str, object]) -> set[str]:
    import yaml

    from aap.config import rules_file

    doc = yaml.safe_load(rules_file("catalogue/frameworks/asvs-applicability.yaml").read_text())
    return {c["id"] for c in doc["chapters"] if asvs_chapter_applies(str(c["applies_when"]), caps)}


@evaluator("asvs_coverage@1")
def asvs_coverage(i: EvaluationInput) -> EvaluationResult:
    level_raw = i.app.profile.get("asvs_target_level")
    if not level_raw:
        return EvaluationResult(S.NO_EVIDENCE, "no ASVS target level declared (.security/asvs.yaml)")
    level = int(str(level_raw).lstrip("L")[:1] or 1)
    caps = dict(i.app.profile.get("asvs_capabilities") or {})
    chapters = _asvs_chapters(caps)
    applicable = {rid for rid, ch, lvl in asvs_requirements() if ch in chapters and lvl <= level}
    if not applicable:
        return EvaluationResult(S.ERROR, "ASVS requirement index not imported (tools/catalogue/import_asvs.py)")
    verified: set[str] = set()
    failing: set[str] = set()
    used = []
    for ev in i.evidence:
        if ev.type == "test.security":
            for rid, outcome in (ev.summary.get("asvs") or {}).items():
                (verified if outcome == "pass" else failing).add(str(rid))
            used.append(ev)
        elif ev.type == "assessment.manual_control":
            verified |= {str(r) for r in ev.summary.get("asvs_verified") or []}
            used.append(ev)
    verified = (verified - failing) & applicable
    target = float(i.params.get("verified_pct") or 80)
    pct = _pct(len(verified), len(applicable))
    text = f"{len(verified)} of {len(applicable)} applicable ASVS L{level} requirements verified ({pct:.0f}%)"
    if not used:
        return EvaluationResult(S.NO_EVIDENCE, f"no security test or manual verification evidence; {text}")
    ids = tuple(e.id for e in used)
    extra = f"; {len(failing & applicable)} failing" if failing & applicable else ""
    if pct >= target and not failing & applicable:
        return EvaluationResult(S.SATISFIED, text, ids)
    state = S.PARTIAL if verified else S.NOT_SATISFIED
    return EvaluationResult(state, f"{text}{extra}; target {target:.0f}%", ids, {"fraction": round(pct / 100, 2)})


@evaluator("eol_components@1")
def eol_components(i: EvaluationInput) -> EvaluationResult:
    ev = latest(i.evidence, "sbom.eol")
    if ev is None:
        return _none("end-of-life check (SBOM components against endoflife.date)")
    eol = list(ev.summary.get("eol") or [])
    snap = ev.summary.get("snapshot", "?")
    if not eol:
        soon = len(ev.summary.get("eol_soon") or [])
        warn = f"; {soon} reach end of life within 180 days" if soon else ""
        return EvaluationResult(
            S.SATISFIED, f"{ev.summary.get('checked', 0)} components checked (data {snap}){warn}", _ids(ev)
        )
    names = ", ".join(f"{e.get('product')} {e.get('cycle')} (EOL {e.get('eol')})" for e in eol[:5])
    return EvaluationResult(S.NOT_SATISFIED, f"{len(eol)} end-of-life: {names}", _ids(ev), {"eol": eol[:20]})


def _deployed(evidence: Sequence[EvidenceView]) -> dict[str, EvidenceView]:
    """Latest deploy.record per environment."""
    out: dict[str, EvidenceView] = {}
    for e in sorted((e for e in evidence if e.type == "deploy.record"), key=lambda e: e.observed_at):
        out[str(e.subject.get("environment") or e.scope_ref)] = e
    return out


@evaluator("artifact_scanned@1")
def artifact_scanned(i: EvaluationInput) -> EvaluationResult:
    deployed = _deployed(i.evidence)
    digests = {str(e.subject["artifact_digest"]) for e in deployed.values() if e.subject.get("artifact_digest")}
    source = "deployed"
    if not digests:
        builds = [e for e in i.evidence if e.type == "sbom" and e.subject.get("artifact_digest")]
        if builds:
            digests, source = {str(max(builds, key=lambda e: e.observed_at).subject["artifact_digest"])}, "latest build"
    if not digests:
        return EvaluationResult(S.NO_EVIDENCE, "no image digest known (no deploy records or image SBOMs)")
    scans = {str(e.subject.get("artifact_digest")): e for e in i.evidence if e.type == "scan.container"}
    missing = sorted(d for d in digests if d not in scans)
    ids = tuple(scans[d].id for d in digests if d in scans)
    if not missing:
        return EvaluationResult(S.SATISFIED, f"all {len(digests)} {source} image digest(s) scanned", ids)
    short = ", ".join(d[:19] for d in missing[:3])
    state = S.PARTIAL if ids else S.NOT_SATISFIED
    return EvaluationResult(state, f"{len(missing)} of {len(digests)} {source} digest(s) not scanned: {short}", ids)


@evaluator("deploy_verification_executed@1")
def deploy_verification_executed(i: EvaluationInput) -> EvaluationResult:
    deployed = _deployed(i.evidence)
    if not deployed:
        return _none("deployment record")
    unverified = sorted(env for env, e in deployed.items() if e.summary.get("verified") is not True)
    ids = tuple(e.id for e in deployed.values())
    if not unverified:
        return EvaluationResult(
            S.SATISFIED, f"attestation verified before deploying to {', '.join(sorted(deployed))}", ids
        )
    return EvaluationResult(S.NOT_SATISFIED, f"deployed without a verified attestation: {', '.join(unverified)}", ids)


@evaluator("threat_test_linkage@1")
def threat_test_linkage(i: EvaluationInput) -> EvaluationResult:
    tm = latest(i.evidence, "repo.threat_model")
    if tm is None or "high_threat_ids" not in tm.summary:
        return _none("threat model with threat ids")
    high = set(tm.summary.get("high_threat_ids") or [])
    if not high:
        return EvaluationResult(S.SATISFIED, "the threat model has no high or critical threats", _ids(tm))
    tests = [e for e in i.evidence if e.type == "test.security"]
    passing = {str(t) for e in tests for t, outcome in (e.summary.get("threats") or {}).items() if outcome == "pass"}
    tested = high & passing
    pct = _pct(len(tested), len(high))
    target = float(i.params.get("min_pct_high_threats_tested", 60))
    ids = _ids(tm) + tuple(e.id for e in tests)
    text = f"{len(tested)} of {len(high)} high threats have passing tests ({pct:.0f}%)"
    if pct >= target:
        return EvaluationResult(S.SATISFIED, text, ids)
    untested = ", ".join(sorted(high - tested)[:5])
    state = S.PARTIAL if tested else S.NOT_SATISFIED
    return EvaluationResult(state, f"{text}; untested: {untested}", ids, {"fraction": round(pct / 100, 2)})


@evaluator("image_patch_age@1")
def image_patch_age(i: EvaluationInput) -> EvaluationResult:
    from datetime import datetime

    deployed = _deployed(i.evidence)
    if not deployed:
        return _none("deployment record")
    max_age = int(i.params.get("max_age_days") or 30)
    ages: dict[str, int] = {}
    for env, e in deployed.items():
        created = e.summary.get("image_created_at")
        if not created:
            return EvaluationResult(
                S.NO_EVIDENCE, f"deploy record for {env} has no image build time (image_created_at)", _ids(e)
            )
        ages[env] = (i.now - datetime.fromisoformat(str(created).replace("Z", "+00:00"))).days
    old = {env: age for env, age in ages.items() if age > max_age}
    ids = tuple(e.id for e in deployed.values())
    if not old:
        return EvaluationResult(
            S.SATISFIED, f"deployed images at most {max(ages.values())} days old (limit {max_age})", ids
        )
    detail = ", ".join(f"{env} {age}d" for env, age in sorted(old.items()))
    return EvaluationResult(S.NOT_SATISFIED, f"images older than {max_age} days: {detail}", ids)


@evaluator("data_store_baseline@1")
def data_store_baseline(i: EvaluationInput) -> EvaluationResult:
    reg = latest(i.evidence, "registry.application")
    clouds = [e for e in i.evidence if e.type == "cloud.posture" and "data_stores" in e.summary]
    if reg is None:
        return _none("application.yaml")
    if not clouds:
        return EvaluationResult(
            S.NO_EVIDENCE,
            "no cloud data-store inventory: the cloud plugins do not collect it yet (PROPOSED)",
            _ids(reg),
        )
    declared = {str(n).lower() for n in reg.summary.get("data_stores") or []}
    stores = [s for e in clouds for s in e.summary["data_stores"]]
    problems = [f"{s['name']} undeclared" for s in stores if str(s.get("name", "")).lower() not in declared]
    problems += [f"{s['name']} not encrypted" for s in stores if s.get("encrypted") is False]
    problems += [f"{s['name']} no backup" for s in stores if s.get("backup") is False]
    ids = _ids(reg) + tuple(e.id for e in clouds)
    if problems:
        return EvaluationResult(S.NOT_SATISFIED, "; ".join(problems[:6]), ids)
    return EvaluationResult(S.SATISFIED, f"{len(stores)} data store(s) declared, encrypted and backed up", ids)


@evaluator("decommission_complete@1")
def decommission_complete(i: EvaluationInput) -> EvaluationResult:
    access = [e for e in i.evidence if e.type == "repo.access" and "archived" in e.summary]
    if not access:
        return _none("repository archive status")
    by_repo: dict[str, EvidenceView] = {}
    for e in sorted(access, key=lambda e: e.observed_at):
        by_repo[e.scope_ref] = e
    live = sorted(r for r, e in by_repo.items() if not e.summary.get("archived"))
    cloud = [e for e in i.evidence if e.type == "cloud.posture"]
    remaining = [e for e in cloud if int(e.summary.get("resources", e.summary.get("open", 0)) or 0) > 0]
    ids = tuple(e.id for e in by_repo.values()) + tuple(e.id for e in cloud)
    problems = [f"repository not archived: {', '.join(live)}"] if live else []
    if remaining:
        problems.append("cloud scope still has resources or open findings")
    if problems:
        return EvaluationResult(S.NOT_SATISFIED, "; ".join(problems), ids)
    if i.app.facts.get("has_cloud_scope") and not cloud:
        return EvaluationResult(S.PARTIAL, "repositories archived; no cloud evidence for the mapped scopes", ids)
    return EvaluationResult(S.SATISFIED, f"{len(by_repo)} repositories archived; nothing left running", ids)
