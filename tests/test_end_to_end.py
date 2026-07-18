"""
.. module:: tests.test_end_to_end
    :synopsis: Full-pipeline extraction through the public ``main()`` entry.

Description
-----------
Builds a real nested archive on disk (a tar containing a gzip-compressed inner
file) and runs the complete CLI pipeline via :func:`re_unpacker.main`. Asserts
the run succeeds, the standard output artifacts are produced, and the manifest
records the expected schema, tool, and version. Skips when the ``tar`` or
``gzip`` binaries are absent, so the suite still passes on a bare host.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import gzip
import json
import shutil
import tarfile
from pathlib import Path

import pytest

from re_unpacker import main as cli_main
from re_unpacker.constants import SCHEMA_VERSION, VERSION

_HAVE_TAR = shutil.which("tar") is not None
_HAVE_GZIP = shutil.which("gzip") is not None

pytestmark = pytest.mark.skipif(
    not (_HAVE_TAR and _HAVE_GZIP),
    reason="requires the tar and gzip binaries",
)


def _make_nested_targz(tmp_path: Path) -> Path:
    # inner.txt -> inner.txt.gz -> bundle.tar (contains the .gz) -> bundle.tar.gz
    inner = tmp_path / "inner.txt"
    inner.write_bytes(b"top secret payload for extraction test\n" * 8)

    inner_gz = tmp_path / "inner.txt.gz"
    with open(inner, "rb") as fi, gzip.open(inner_gz, "wb") as fo:
        shutil.copyfileobj(fi, fo)

    bundle_tar = tmp_path / "bundle.tar"
    with tarfile.open(bundle_tar, "w") as tf:
        tf.add(inner_gz, arcname="inner.txt.gz")

    bundle_targz = tmp_path / "bundle.tar.gz"
    with open(bundle_tar, "rb") as fi, gzip.open(bundle_targz, "wb") as fo:
        shutil.copyfileobj(fi, fo)

    return bundle_targz


def test_end_to_end_extraction(tmp_path):
    sample = _make_nested_targz(tmp_path)
    out = tmp_path / "out"

    rc = cli_main([str(sample), "-o", str(out), "--log-level", "WARNING"])
    assert rc == 0, f"expected clean run, got exit code {rc}"

    # Standard output artifacts.
    manifest_json = out / "manifest.json"
    manifest_jsonl = out / "manifest.jsonl"
    assert manifest_json.exists(), "manifest.json must be written"
    assert manifest_jsonl.exists(), "manifest.jsonl must be written"
    assert (out / "summary.txt").exists()
    assert (out / "tree.txt").exists()

    data = json.loads(manifest_json.read_text(encoding="utf-8"))
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["tool"] == "re-unpacker"
    assert data["tool_version"] == VERSION
    assert "files" in data and isinstance(data["files"], list)
    # The nested payload should have been recursed into and recorded.
    assert data["stats"]["files_extracted"] >= 1


def test_end_to_end_dry_run_extracts_nothing(tmp_path):
    sample = _make_nested_targz(tmp_path)
    out = tmp_path / "out_dry"

    rc = cli_main([str(sample), "-o", str(out), "--dry-run", "--log-level", "WARNING"])
    assert rc == 0
    # Dry-run detects but must not create an extracted tree of children.
    extracted = out / "extracted"
    if extracted.exists():
        # No nested .unpacked directories should have been produced.
        nested = list(extracted.rglob("*.unpacked"))
        assert not nested, nested


def test_tools_check_runs(capsys):
    rc = cli_main(["--tools-check"])
    # 0 if every known tool is present, 3 if some are missing. Both are valid
    # outcomes depending on the host; only a crash (nonzero-and-not-3) is bad.
    assert rc in (0, 3), rc
    out = capsys.readouterr().out
    assert "TOOL" in out or "tool" in out
