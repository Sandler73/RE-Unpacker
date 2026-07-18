"""
.. module:: tests.test_detection
    :synopsis: FileKind enum invariants and detect_file synthetic-input behavior.

Description
-----------
Exercises the three-layer detector against small synthetic files whose leading
bytes are crafted to match known magic signatures. These tests do not require
the external ``file`` binary: when it is absent the detector falls back to the
magic and extension layers, which is exactly what these cases assert on.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from pathlib import Path

from re_unpacker.detection import FileKind, detect_file


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_filekind_is_str_enum():
    assert issubclass(FileKind, str)
    # Every member's value equals its own string form for stable manifests.
    for member in FileKind:
        assert member.value == str(member.value)


def test_filekind_has_core_members():
    for name in (
        "DEB", "RPM", "MSI", "CAB", "ELF", "PE_EXECUTABLE", "ISO",
        "ZIP", "TAR", "GZIP", "PDF", "SQUASHFS", "EMPTY", "UNKNOWN_BINARY",
    ):
        assert hasattr(FileKind, name), name


def test_empty_file_detected(tmp_path, tool_registry):
    p = _write(tmp_path, "empty.bin", b"")
    result = detect_file(p, tool_registry)
    assert result.kind == FileKind.EMPTY
    assert "size:0" in result.signals


def test_gzip_magic_detected(tmp_path, tool_registry):
    # gzip magic 1f 8b, minimal but valid-looking header.
    data = b"\x1f\x8b\x08\x00" + b"\x00" * 16
    p = _write(tmp_path, "blob.gz", data)
    result = detect_file(p, tool_registry)
    assert any(s.startswith("magic:GZIP") for s in result.signals), result.signals


def test_elf_magic_detected(tmp_path, tool_registry):
    data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
    p = _write(tmp_path, "prog.elf", data)
    result = detect_file(p, tool_registry)
    assert result.kind == FileKind.ELF, result.signals


def test_pe_magic_detected(tmp_path, tool_registry):
    data = b"MZ" + b"\x90" * 62 + b"\x00" * 64
    p = _write(tmp_path, "prog.exe", data)
    result = detect_file(p, tool_registry)
    # Generic PE family; exact sub-kind may depend on file(1), but the MZ
    # magic must at least surface in the signals.
    assert any("PE" in s or "magic:PE" in s for s in result.signals), result.signals


def test_zip_magic_detected(tmp_path, tool_registry):
    data = b"PK\x03\x04" + b"\x00" * 30
    p = _write(tmp_path, "archive.zip", data)
    result = detect_file(p, tool_registry)
    assert any("ZIP" in s for s in result.signals), result.signals


def test_detected_file_carries_signals(tmp_path, tool_registry):
    p = _write(tmp_path, "x.pdf", b"%PDF-1.7\n" + b"\x00" * 32)
    result = detect_file(p, tool_registry)
    assert isinstance(result.signals, list)
    assert result.signals, "detection must always record why it decided"
