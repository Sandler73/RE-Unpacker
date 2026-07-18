"""
.. module:: tests.test_docs_consistency
    :synopsis: Keep README badges and counts synchronized with the source.

Description
-----------
The audit that preceded these tests found two stale numbers in the README
("registered extractor classes: 58" when the registry held 69, and "CLI flags:
28 (UNCHANGED)" when the parser exposed 37). Those went unnoticed because
nothing recomputed them. This module closes that gap: every numeric claim in
the README that can be derived from the code is derived here and compared, so
a count that drifts fails the build instead of quietly misinforming a reader.

The same applies to the shields at the top of the README. A badge that states
a version or a count is a factual claim, and a stale badge is a documentation
defect, so the version, schema, and format-count badges are checked too.

Notes
-----
- Only claims that can be computed from the source are asserted here.
  Prose, tool names, and platform notes are reviewed by a human.
- If a count legitimately changes, update the README; do not relax the test.
  The failure message names the value the code actually produces.
- Badges whose value is served dynamically by GitHub or shields.io (CI status,
  release, last commit, open issues, license) are intentionally not checked:
  they cannot go stale, which is precisely why they are preferred.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from re_unpacker import cli
from re_unpacker.classifiers.base import build_default_classifier_registry
from re_unpacker.constants import (
    SCHEMA_VERSION,
    TOOL_PACKAGE_HINTS_LINUX,
    TOOL_PACKAGE_HINTS_WINDOWS,
    VERSION,
)
from re_unpacker.detection import FileKind
from re_unpacker.extractors.base import build_default_registry
from re_unpacker.verifiers.base import build_default_verifier_registry

README = pathlib.Path(__file__).resolve().parent.parent / "README.md"


@pytest.fixture(scope="module")
def readme() -> str:
    return README.read_text(encoding="utf-8")


def _glance_value(readme_text: str, label: str) -> str:
    """Return the value cell of an 'At a glance' row whose label matches."""
    pattern = re.compile(
        rf"^\|\s*{re.escape(label)}\s*\|\s*(?P<v>[^|]+?)\s*\|\s*$", re.MULTILINE
    )
    m = pattern.search(readme_text)
    assert m, f"README has no 'At a glance' row labelled {label!r}"
    return m.group("v")


def _leading_int(value: str) -> int:
    m = re.match(r"\**(\d+)", value.strip())
    assert m, f"expected a leading integer in {value!r}"
    return int(m.group(1))


# --------------------------------------------------------------------------- #
# Badges
# --------------------------------------------------------------------------- #

def test_version_badge_matches_framework(readme):
    m = re.search(r"!\[Version\]\(https://img\.shields\.io/badge/version-([\d.]+)-", readme)
    assert m, "README is missing the version badge"
    assert m.group(1) == VERSION, (
        f"version badge says {m.group(1)}, framework is {VERSION}"
    )


def test_schema_badge_matches_schema_version(readme):
    m = re.search(
        r"!\[Manifest schema\]\(https://img\.shields\.io/badge/manifest%20schema-([\d.]+)-",
        readme,
    )
    assert m, "README is missing the manifest-schema badge"
    assert m.group(1) == SCHEMA_VERSION, (
        f"schema badge says {m.group(1)}, SCHEMA_VERSION is {SCHEMA_VERSION}"
    )


def test_current_release_line_matches_framework(readme):
    m = re.search(r"\*\*Current release: ([\d.]+)\*\*", readme)
    assert m, "README is missing the 'Current release' line"
    assert m.group(1) == VERSION


def test_formats_badge_matches_extractable_kinds(readme):
    m = re.search(r"formats-(\d+)%20extractable%20kinds", readme)
    assert m, "README is missing the formats badge"
    reg = build_default_registry()
    actual = len([k for k in reg.known_kinds() if reg.primary_for_kind(k)])
    assert int(m.group(1)) == actual, (
        f"formats badge says {m.group(1)}, registry dispatches {actual}"
    )


# --------------------------------------------------------------------------- #
# "At a glance" counts
# --------------------------------------------------------------------------- #

def test_filekind_count(readme):
    assert _leading_int(_glance_value(readme, "FileKind enum entries")) == len(list(FileKind))


def test_extractable_kind_count(readme):
    reg = build_default_registry()
    actual = len([k for k in reg.known_kinds() if reg.primary_for_kind(k)])
    assert _leading_int(_glance_value(readme, "Extractable kinds")) == actual


def test_registered_extractor_class_count(readme):
    reg = build_default_registry()
    label = "Registered extractor classes (primary + secondary)"
    assert _leading_int(_glance_value(readme, label)) == len(list(reg.all()))


def test_verifier_count(readme):
    reg = build_default_verifier_registry()
    assert _leading_int(_glance_value(readme, "Verifiers")) == len(list(reg.all()))


def test_classifier_count(readme):
    reg = build_default_classifier_registry()
    assert _leading_int(_glance_value(readme, "Classifiers")) == len(list(reg.all()))


def test_tracked_tool_counts(readme):
    assert _leading_int(_glance_value(readme, "Tracked external tools (Linux)")) == len(
        TOOL_PACKAGE_HINTS_LINUX
    )
    assert _leading_int(_glance_value(readme, "Tracked external tools (Windows)")) == len(
        TOOL_PACKAGE_HINTS_WINDOWS
    )


def test_cli_flag_count(readme):
    parser = cli._build_parser()
    actual = len([a for a in parser._actions if a.option_strings and a.dest != "help"])
    assert _leading_int(_glance_value(readme, "CLI flags (argparse actions)")) == actual


def test_manifest_schema_row(readme):
    assert SCHEMA_VERSION in _glance_value(readme, "Manifest schema version")
