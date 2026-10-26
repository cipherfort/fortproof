# SPDX-License-Identifier: Apache-2.0
"""A deployment's own rules (AAP_RULES_DIR) replace only the files it provides; the rest are the image's defaults."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import pytest
import yaml

from aap import cli, pipelines
from aap.config import ConfigBundle, digest, repo_root, rules_file


@pytest.fixture
def rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("AAP_RULES_DIR", str(tmp_path))
    return tmp_path


def _put(rules: Path, rel: str, content: str) -> None:
    (rules / rel).parent.mkdir(parents=True, exist_ok=True)
    (rules / rel).write_text(content)


def test_without_a_rules_directory_everything_is_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AAP_RULES_DIR", raising=False)
    bundle = ConfigBundle.load()
    assert {d.source for d in bundle.documents.values()} == {"default"}
    assert rules_file("config/risk-model.yaml") == repo_root() / "config/risk-model.yaml"


def test_a_provided_file_replaces_the_default_and_nothing_else(rules: Path) -> None:
    default = yaml.safe_load((repo_root() / "config/trusted-producers.yaml").read_text())
    default["workflow_repository"] = "acme/security-workflows"
    _put(rules, "config/trusted-producers.yaml", yaml.safe_dump(default))
    bundle = ConfigBundle.load()
    tp = bundle.documents["trusted_producers"]
    assert tp.source == "deployment" and tp.path == "config/trusted-producers.yaml"
    assert tp.content["workflow_repository"] == "acme/security-workflows"
    others = {d.source for k, d in bundle.documents.items() if k != "trusted_producers"}
    assert others == {"default"}
    # different content is a different configuration version, so every verdict records which rules produced it
    shipped = yaml.safe_load((repo_root() / "config/trusted-producers.yaml").read_text())
    assert tp.sha256 != digest(shipped)


def test_the_profile_and_its_classification_can_both_come_from_the_deployment(rules: Path) -> None:
    org = yaml.safe_load((repo_root() / "config/organization.yaml").read_text())
    org["profile"] = "acme"
    _put(rules, "config/organization.yaml", yaml.safe_dump(org))
    classification = (repo_root() / "config/profiles/generic/classification.yaml").read_text()
    _put(rules, "config/profiles/acme/classification.yaml", classification)
    bundle = ConfigBundle.load()
    assert bundle.profile == "acme"
    assert bundle.documents["classification"].path == "config/profiles/acme/classification.yaml"
    assert bundle.documents["classification"].source == "deployment"


def test_a_rules_file_must_be_a_mapping(rules: Path) -> None:
    _put(rules, "config/risk-model.yaml", "- not\n- a mapping\n")
    with pytest.raises(ValueError, match=r"risk-model\.yaml.*deployment.*mapping"):
        ConfigBundle.load()


def test_rules_paths_cannot_leave_the_rules_directory(rules: Path) -> None:
    for bad in ("../secrets/x.yaml", "/etc/passwd", "config/../../x.yaml"):
        with pytest.raises(ValueError):
            rules_file(bad)


def test_an_approval_edits_the_deployments_copy_and_never_the_shipped_default(rules: Path) -> None:
    shipped = (repo_root() / "config/trusted-producers.yaml").read_text()
    pipelines.approve("1" * 40, "v1.0.0", "acme/security-workflows")
    own = rules / "config/trusted-producers.yaml"
    assert own.exists() and (repo_root() / "config/trusted-producers.yaml").read_text() == shipped
    doc = yaml.safe_load(own.read_text())
    assert doc["workflow_repository"] == "acme/security-workflows"
    assert ConfigBundle.load().documents["trusted_producers"].source == "deployment"


def test_chart_values_carry_each_file_unchanged(rules: Path, capsys: pytest.CaptureFixture[str]) -> None:
    shutil.copy(repo_root() / "config/trusted-producers.yaml", rules / "tp.tmp")
    _put(rules, "config/trusted-producers.yaml", (rules / "tp.tmp").read_text())
    (rules / "tp.tmp").unlink()
    _put(rules, "config/sigstore/trusted_root.jsonl", '{"a": 1}\n{"b": 2}\n')
    cli.cmd_config_chart_values(argparse.Namespace())
    values = yaml.safe_load(capsys.readouterr().out)
    files = values["rules"]["files"]
    assert set(files) == {"config/trusted-producers.yaml", "config/sigstore/trusted_root.jsonl"}
    for rel, content in files.items():
        assert content.rstrip("\n") == (rules / rel).read_text().rstrip("\n")


def test_check_fails_on_a_file_the_platform_never_reads(rules: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _put(rules, "config/trusted-producer.yaml", "workflows: []\n")  # typo: the real file is trusted-producers.yaml
    with pytest.raises(SystemExit) as stop:
        cli.cmd_config_check(argparse.Namespace())
    assert stop.value.code == 1
    assert "config/trusted-producer.yaml" in capsys.readouterr().err
