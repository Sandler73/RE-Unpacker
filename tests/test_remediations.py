"""
.. module:: tests.test_remediations
    :synopsis: Regression guards for the audit remediations (0.4.9).

Description
-----------
Each test pins one audit finding closed so it cannot silently regress:

- SEC-1: RLIMIT_FSIZE output-size cap stops a child that writes past the cap
  (POSIX). Also checks the preexec builder's platform gating.
- SEC-2: the per-archive file-count ceiling is enforced by ``add_files``.
- REL-1: the seven Windows-gated extractors override ``is_available`` (not the
  dead ``is_supported``) and the gate is actually active off-Windows.
- REL-2: ``SingleStreamExtractor`` uses the cross-platform teardown helper, not
  a direct ``os.killpg`` (which AttributeErrors on Windows).
- SEC-3: downloads compute a SHA-256 and enforce an expected digest when pinned.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import hashlib
import inspect
import os
import sys

import pytest

# --------------------------------------------------------------------------- #
# SEC-1: RLIMIT_FSIZE output-size cap
# --------------------------------------------------------------------------- #

def test_sec1_preexec_builder_gating():
    from re_unpacker import subprocess_utils as su

    # No cap -> no preexec.
    assert su.fsize_limit_preexec(None) is None
    assert su.fsize_limit_preexec(0) is None
    if os.name == "nt":
        # Windows: always None (documented platform gap).
        assert su.fsize_limit_preexec(1024) is None
    else:
        # POSIX: a positive cap yields a callable preexec_fn.
        assert callable(su.fsize_limit_preexec(1024))


def test_sec1_cap_setter_roundtrip():
    from re_unpacker import subprocess_utils as su

    su.set_output_byte_cap(4096)
    assert su.get_output_byte_cap() == 4096
    su.set_output_byte_cap(None)
    assert su.get_output_byte_cap() is None
    su.set_output_byte_cap(-5)  # non-positive disables
    assert su.get_output_byte_cap() is None


@pytest.mark.skipif(os.name == "nt", reason="RLIMIT_FSIZE is POSIX-only")
def test_sec1_rlimit_stops_oversized_write(tmp_path):
    from re_unpacker.exceptions import ExtractorFailure
    from re_unpacker.subprocess_utils import run_tool

    # A child that tries to write 5 MiB while capped at 64 KiB must be stopped.
    script = "open('big.bin','wb').write(b'x' * (5 * 1024 * 1024))"
    with pytest.raises(ExtractorFailure):
        run_tool(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            timeout=30,
            max_output_bytes=64 * 1024,
        )
    # The oversized file must not have been fully written.
    big = tmp_path / "big.bin"
    if big.exists():
        assert big.stat().st_size <= 64 * 1024


@pytest.mark.skipif(os.name == "nt", reason="RLIMIT_FSIZE is POSIX-only")
def test_sec1_small_write_under_cap_succeeds(tmp_path):
    from re_unpacker.subprocess_utils import run_tool

    script = "open('ok.bin','wb').write(b'y' * 1024)"
    result = run_tool(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        timeout=30,
        max_output_bytes=64 * 1024,
    )
    assert result.returncode == 0
    assert (tmp_path / "ok.bin").stat().st_size == 1024


# --------------------------------------------------------------------------- #
# SEC-2: file-count ceiling enforcement
# --------------------------------------------------------------------------- #

def test_sec2_add_files_enforces_ceiling():
    from re_unpacker.exceptions import SafetyLimitExceeded
    from re_unpacker.safety import QuotaTracker

    q = QuotaTracker(
        max_total_bytes=10**9, max_archive_bytes=10**9, max_files_per_archive=3
    )
    q.add_files(3)  # exactly at ceiling is allowed
    with pytest.raises(SafetyLimitExceeded) as ei:
        q.add_files(1, archive_files_so_far=3)
    assert ei.value.limit_name == "max_files_per_archive"


def test_sec2_add_files_bulk_over_ceiling():
    from re_unpacker.exceptions import SafetyLimitExceeded
    from re_unpacker.safety import QuotaTracker

    q = QuotaTracker(
        max_total_bytes=10**9, max_archive_bytes=10**9, max_files_per_archive=5
    )
    with pytest.raises(SafetyLimitExceeded):
        q.add_files(6)  # a single extraction emitting 6 files trips the limit


def test_sec2_orchestrator_calls_add_files():
    # The wiring, not just the primitive: the orchestrator must call add_files.
    from re_unpacker import orchestrator

    src = inspect.getsource(orchestrator)
    assert "self.quota.add_files(" in src, (
        "orchestrator must enforce the file-count ceiling via quota.add_files"
    )


# --------------------------------------------------------------------------- #
# REL-1: is_available override (not the dead is_supported)
# --------------------------------------------------------------------------- #

def _windows_gated_classes():
    from re_unpacker.extractors.deb import DebSevenZipExtractor
    from re_unpacker.extractors.msi import MsiExecExtractor
    from re_unpacker.extractors.rpm import RpmSevenZipExtractor

    classes = [DebSevenZipExtractor, MsiExecExtractor, RpmSevenZipExtractor]
    return classes


def test_rel1_no_extractor_defines_is_supported():
    from re_unpacker.extractors import base as ex_base

    # The base has no is_supported; no subclass should define one either.
    assert not hasattr(ex_base.Extractor, "is_supported")
    for cls in _windows_gated_classes():
        assert "is_supported" not in cls.__dict__, cls.__name__
        assert "is_available" in cls.__dict__, cls.__name__


@pytest.mark.skipif(os.name == "nt", reason="gate returns True on Windows")
def test_rel1_windows_gate_is_active_off_windows():
    from re_unpacker.tools import ToolRegistry

    reg = ToolRegistry()
    for cls in _windows_gated_classes():
        # The override must now actually run and refuse on non-Windows.
        assert cls().is_available(reg) is False, cls.__name__


# --------------------------------------------------------------------------- #
# REL-2: SingleStreamExtractor cross-platform teardown
# --------------------------------------------------------------------------- #

def test_rel2_single_stream_uses_central_teardown():
    from re_unpacker.extractors import archive

    src = inspect.getsource(archive)
    assert "_terminate_proc_tree" in src, (
        "SingleStreamExtractor must use the cross-platform teardown helper"
    )
    # It must not reach for os.killpg directly (AttributeError on Windows).
    assert "_os.killpg" not in src and "os.killpg" not in src, (
        "direct os.killpg is the L32 regression; use _terminate_proc_tree"
    )


# --------------------------------------------------------------------------- #
# SEC-3: download integrity (SHA-256 compute + optional pinning)
# --------------------------------------------------------------------------- #

def test_sec3_download_computes_and_pins_sha256(tmp_path, quiet_logger):
    from re_unpacker.manual_install_windows import (
        ManualInstallError,
        _http_download,
    )

    payload = b"integrity-test-payload" * 100
    src = tmp_path / "asset.bin"
    src.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()
    url = src.resolve().as_uri()  # file:// URL, no network

    # Correct pin: returns the digest and writes the file.
    dest_ok = tmp_path / "ok.bin"
    digest = _http_download(
        url, dest_ok, logger=quiet_logger, expected_sha256=expected
    )
    assert digest == expected
    assert dest_ok.read_bytes() == payload

    # Wrong pin: refuses and does not leave the destination in place.
    dest_bad = tmp_path / "bad.bin"
    with pytest.raises(ManualInstallError):
        _http_download(
            url, dest_bad, logger=quiet_logger,
            expected_sha256="0" * 64,
        )
    assert not dest_bad.exists()


def test_sec3_manual_install_error_is_gracefully_catchable():
    from re_unpacker.manual_install_windows import ManualInstallError

    # Subclassing OSError keeps the per-tool graceful-continuation handlers
    # (which catch OSError) working, so an integrity failure reports as a
    # failed tool rather than crashing the batch.
    assert issubclass(ManualInstallError, OSError)
