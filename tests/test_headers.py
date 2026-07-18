"""
.. module:: tests.test_headers
    :synopsis: Enforce module-header structure, version sync, and clean prose.

Description
-----------
Header drift is the defect class these tests exist to prevent. Previously the
52 package modules carried a mix of header shapes, per-file version strings
that had fallen behind the framework version, and release annotations
("added in v0.3.2") scattered through comments and docstrings.

These tests make each of those states a build failure rather than something
that has to be caught by review:

- every module carries the full header skeleton;
- every module header's version equals :data:`re_unpacker.constants.VERSION`,
  so a release bump that misses a file fails immediately;
- no comment or docstring reintroduces a release annotation.

Notes
-----
- The version-annotation scan deliberately allows manifest SCHEMA versions
  (``1.0.0`` / ``1.1.0``). Those describe a live data contract that manifest
  consumers must branch on, not the release something was built in.
- ``tools/normalize_headers.py`` applies these conventions in bulk; these
  tests are the gate that keeps them applied.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import ast
import io
import pathlib
import re
import tokenize

import pytest

from re_unpacker.constants import VERSION

PKG_ROOT = pathlib.Path(__file__).resolve().parent.parent / "src" / "re_unpacker"
MODULES = sorted(PKG_ROOT.rglob("*.py"))

# A release annotation: "v0.3.2", "added in 0.4.0", and similar. Manifest
# schema versions (1.0.0 / 1.1.0) are a data contract, not build history.
RELEASE_ANNOTATION = re.compile(
    r"\bv\d+\.\d+\.\d+\b"
    r"|\b(?:added|introduced|new|changed|fixed|removed|deprecated)\s+in\s+\d+\.\d+\.\d+\b",
    re.IGNORECASE,
)
# The canonical header version line is the one legitimate version mention.
CANONICAL_VERSION_LINE = re.compile(r"Part of re-unpacker \d+\.\d+\.\d+")


def _module_id(path: pathlib.Path) -> str:
    return str(path.relative_to(PKG_ROOT))


def _docstring(path: pathlib.Path) -> str | None:
    return ast.get_docstring(ast.parse(path.read_text(encoding="utf-8")))


assert MODULES, "no package modules discovered; check PKG_ROOT"


@pytest.mark.parametrize("path", MODULES, ids=_module_id)
def test_module_has_docstring(path):
    assert _docstring(path), f"{_module_id(path)} has no module docstring"


@pytest.mark.parametrize("path", MODULES, ids=_module_id)
def test_module_header_structure(path):
    doc = _docstring(path) or ""
    assert ".. module::" in doc, f"{_module_id(path)}: missing '.. module::' directive"
    assert ":synopsis:" in doc, f"{_module_id(path)}: missing ':synopsis:'"
    for section in ("Description", "Notes", "Version"):
        assert re.search(rf"(?m)^{section}\n-{{3,}}", doc), (
            f"{_module_id(path)}: missing '{section}' section"
        )


@pytest.mark.parametrize("path", MODULES, ids=_module_id)
def test_module_header_version_matches_framework(path):
    doc = _docstring(path) or ""
    found = CANONICAL_VERSION_LINE.search(doc)
    assert found, f"{_module_id(path)}: header has no 'Part of re-unpacker X.Y.Z' line"
    declared = found.group(0).split()[-1]
    assert declared == VERSION, (
        f"{_module_id(path)}: header version {declared} != framework {VERSION}. "
        f"Run: python tools/normalize_headers.py {VERSION}"
    )


@pytest.mark.parametrize("path", MODULES, ids=_module_id)
def test_no_release_annotations_in_comments_or_docstrings(path):
    """No comment or docstring may state the release something appeared in."""
    source = path.read_text(encoding="utf-8")
    offenders: list[str] = []
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        text = tok.string
        # Ignore the single canonical header version line.
        text = CANONICAL_VERSION_LINE.sub("", text)
        for m in RELEASE_ANNOTATION.finditer(text):
            offenders.append(f"line {tok.start[0]}: {m.group(0)}")
    assert not offenders, (
        f"{_module_id(path)}: release annotations found: {offenders}. "
        "State fact-of behavior instead; version history belongs in CHANGELOG.md."
    )


def test_no_release_annotations_in_runtime_strings():
    """User-facing output must not carry release annotations either."""
    offenders: list[str] = []
    for path in MODULES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
                if (node.body and isinstance(node.body[0], ast.Expr)
                        and isinstance(node.body[0].value, ast.Constant)):
                    docstrings.add(id(node.body[0].value))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in docstrings):
                if RELEASE_ANNOTATION.search(node.value):
                    offenders.append(f"{_module_id(path)}:{node.lineno}")
    assert not offenders, f"release annotations in runtime strings: {offenders}"


def test_package_version_is_single_source_of_truth():
    import re_unpacker

    assert re_unpacker.__version__ == VERSION
