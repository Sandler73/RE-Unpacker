"""
.. module:: tests.test_safety
    :synopsis: Safety-layer tests: name sanitization, hashing, quotas, audit.

Description
-----------
The path-traversal audit is the highest-value security control in the tool, so
it gets a real filesystem test: an escaping symlink is created inside a fake
extraction directory and the audit must neutralize it. Quota ceilings are
tested at their boundaries.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import logging
import os

import pytest

from re_unpacker import safety
from re_unpacker.exceptions import PathTraversalError, SafetyLimitExceeded

# --------------------------------------------------------------------------- #
# sanitize_name
# --------------------------------------------------------------------------- #

def test_sanitize_strips_path_separators():
    assert "/" not in safety.sanitize_name("a/b/c")
    assert "\\" not in safety.sanitize_name("a\\b\\c")


def test_sanitize_removes_nul():
    assert "\x00" not in safety.sanitize_name("bad\x00name")


def test_sanitize_replaces_shell_specials():
    out = safety.sanitize_name("evil; rm -rf $HOME `id`")
    for bad in ";$`":
        assert bad not in out
    assert " " not in out


def test_sanitize_empty_becomes_unnamed():
    assert safety.sanitize_name("") == "unnamed"
    assert safety.sanitize_name("...") == "unnamed"


def test_sanitize_preserves_extension_on_truncation():
    long_stem = "a" * 500
    out = safety.sanitize_name(long_stem + ".bin", max_len=32)
    assert out.endswith(".bin")
    assert len(out) <= 32


# --------------------------------------------------------------------------- #
# hashing
# --------------------------------------------------------------------------- #

def test_compute_hashes_known_values(tmp_path):
    p = tmp_path / "hello.txt"
    p.write_bytes(b"abc")
    h = safety.compute_hashes(p)
    # Well-known digests of b"abc".
    assert h.sha256 == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert h.md5 == "900150983cd24fb0d6963f7d28e17f72"
    assert h.size == 3


# --------------------------------------------------------------------------- #
# is_inside / assert_inside
# --------------------------------------------------------------------------- #

def test_is_inside_true_for_child(tmp_path):
    child = tmp_path / "sub" / "file"
    assert safety.is_inside(child, tmp_path)


def test_is_inside_false_for_escape(tmp_path):
    outside = tmp_path.parent / "elsewhere"
    assert not safety.is_inside(outside, tmp_path)


def test_assert_inside_raises_on_escape(tmp_path):
    with pytest.raises(PathTraversalError):
        safety.assert_inside(tmp_path.parent / "x", tmp_path)


# --------------------------------------------------------------------------- #
# QuotaTracker
# --------------------------------------------------------------------------- #

def _tracker(**over):
    kw = dict(
        max_total_bytes=1000,
        max_archive_bytes=500,
        max_files_per_archive=3,
    )
    kw.update(over)
    return safety.QuotaTracker(**kw)


def test_quota_allows_under_ceiling():
    q = _tracker()
    q.add_bytes(400, archive_bytes_so_far=0)
    q.add_file(archive_files_so_far=0)
    snap = q.snapshot()
    assert snap["total_bytes"] == 400
    assert snap["total_files"] == 1


def test_quota_total_bytes_ceiling():
    q = _tracker(max_total_bytes=100, max_archive_bytes=1000)
    with pytest.raises(SafetyLimitExceeded) as ei:
        q.add_bytes(101)
    assert ei.value.limit_name == "max_total_bytes"


def test_quota_archive_bytes_ceiling():
    q = _tracker(max_archive_bytes=100)
    with pytest.raises(SafetyLimitExceeded) as ei:
        q.add_bytes(101, archive_bytes_so_far=0)
    assert ei.value.limit_name == "max_archive_bytes"


def test_quota_files_ceiling():
    q = _tracker(max_files_per_archive=2)
    with pytest.raises(SafetyLimitExceeded) as ei:
        q.add_file(archive_files_so_far=2)
    assert ei.value.limit_name == "max_files_per_archive"


# --------------------------------------------------------------------------- #
# audit_extracted_tree (path-traversal neutralization)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(os.name == "nt", reason="symlink creation is restricted on Windows CI")
def test_audit_neutralizes_escaping_symlink(tmp_path):
    output_root = tmp_path / "out"
    extract_dir = output_root / "extracted" / "sample.unpacked"
    extract_dir.mkdir(parents=True)

    # A symlink pointing outside the output root (classic archive escape).
    secret = tmp_path / "secret.txt"
    secret.write_text("do not exfiltrate")
    evil = extract_dir / "link_to_secret"
    evil.symlink_to(secret)

    log = logging.getLogger("test.audit")
    quarantined, symlink_fixed = safety.audit_extracted_tree(
        extract_dir, output_root, logger=log
    )

    assert symlink_fixed >= 1
    # The escaping symlink must be gone, replaced by a placeholder record.
    assert not evil.is_symlink()
    placeholder = evil.with_suffix(evil.suffix + ".escaping_symlink.txt")
    assert placeholder.exists()


def test_audit_leaves_benign_tree_untouched(tmp_path):
    output_root = tmp_path / "out"
    extract_dir = output_root / "extracted" / "sample.unpacked"
    extract_dir.mkdir(parents=True)
    (extract_dir / "ok.txt").write_text("benign")

    log = logging.getLogger("test.audit")
    quarantined, symlink_fixed = safety.audit_extracted_tree(
        extract_dir, output_root, logger=log
    )
    assert quarantined == 0
    assert symlink_fixed == 0
    assert (extract_dir / "ok.txt").read_text() == "benign"
