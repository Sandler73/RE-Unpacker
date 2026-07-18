"""
.. module:: tests.test_cli
    :synopsis: CLI parser surface, defaults, and mutual-exclusion behavior.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import pytest

from re_unpacker import cli
from re_unpacker.constants import (
    DEFAULT_JOBS,
    DEFAULT_MAX_DEPTH,
    DEFAULT_TIMEOUT_SECONDS,
)


def _parse(argv):
    return cli._build_parser().parse_args(argv)


def test_parser_builds():
    p = cli._build_parser()
    assert p.prog == "re-unpacker"


def test_defaults():
    ns = _parse(["sample.deb"])
    assert str(ns.input) == "sample.deb"
    assert ns.max_depth == DEFAULT_MAX_DEPTH
    assert ns.jobs == DEFAULT_JOBS
    assert ns.timeout == DEFAULT_TIMEOUT_SECONDS
    # Feature flags default ON.
    assert ns.binwalk is True
    assert ns.resources is True
    assert ns.hash is True
    assert ns.dedup is True


def test_no_flags_toggle_off():
    ns = _parse(["x", "--no-binwalk", "--no-resources", "--no-hash", "--no-dedup"])
    assert ns.binwalk is False
    assert ns.resources is False
    assert ns.hash is False
    assert ns.dedup is False


def test_output_and_jobs():
    ns = _parse(["x", "-o", "out", "-j", "4", "-d", "3"])
    assert str(ns.output) == "out"
    assert ns.jobs == 4
    assert ns.max_depth == 3


def test_enrichment_flags():
    ns = _parse([
        "x", "--no-yara", "--no-fuzzy-hash", "--no-exif", "--no-entropy",
        "--yara-rules", "/tmp/rules", "--enrich-timeout", "10",
    ])
    assert ns.enable_yara is False
    assert ns.enable_fuzzy_hash is False
    assert ns.enable_exif is False
    assert ns.enable_entropy is False
    assert ns.yara_rules == "/tmp/rules"
    assert ns.enrich_timeout == 10


def test_filters_repeatable():
    ns = _parse(["x", "--include", "*.deb", "--include", "*.rpm", "--exclude", "*.iso"])
    assert ns.include == ["*.deb", "*.rpm"]
    assert ns.exclude == ["*.iso"]


def test_modes_present():
    for flag, attr in (
        ("--tools-check", "tools_check"),
        ("--dry-run", "dry_run"),
        ("--install", "install"),
        ("--uninstall", "uninstall"),
        ("--repair", "repair"),
        ("--dry-run-install", "dry_run_install"),
    ):
        ns = _parse([flag])
        assert getattr(ns, attr) is True, flag


def test_install_missing_is_alias_for_install():
    ns = _parse(["--install-missing"])
    assert ns.install is True


def test_verbose_and_quiet_mutually_exclusive():
    with pytest.raises(SystemExit):
        _parse(["x", "-v", "-q"])


def test_verbose_counts():
    ns = _parse(["x", "-vv"])
    assert ns.verbose == 2


def test_log_level_choices_enforced():
    with pytest.raises(SystemExit):
        _parse(["x", "--log-level", "TRACE"])
    ns = _parse(["x", "--log-level", "DEBUG"])
    assert ns.log_level == "DEBUG"


def test_version_action_exits(capsys):
    with pytest.raises(SystemExit) as ei:
        _parse(["--version"])
    assert ei.value.code == 0
    out = capsys.readouterr().out
    assert "re-unpacker" in out


def test_input_optional_for_non_extract_modes():
    # --tools-check does not require a positional input.
    ns = _parse(["--tools-check"])
    assert ns.input is None
