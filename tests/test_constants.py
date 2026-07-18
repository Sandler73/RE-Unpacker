"""
.. module:: tests.test_constants
    :synopsis: Version, schema, magic-table, and policy-constant invariants.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import re

from re_unpacker import constants as C

_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def test_version_is_semver():
    assert _SEMVER.match(C.VERSION), C.VERSION


def test_schema_version_is_semver():
    assert _SEMVER.match(C.SCHEMA_VERSION), C.SCHEMA_VERSION


def test_package_version_matches_public_export():
    import re_unpacker

    assert re_unpacker.__version__ == C.VERSION
    assert re_unpacker.VERSION == C.VERSION
    assert re_unpacker.SCHEMA_VERSION == C.SCHEMA_VERSION


def test_project_name_stable():
    assert C.PROJECT_NAME == "re-unpacker"


def test_default_limits_are_positive_ints():
    for name in (
        "DEFAULT_MAX_DEPTH",
        "DEFAULT_JOBS",
        "DEFAULT_MAX_EXTRACTED_SIZE",
        "DEFAULT_MAX_TOTAL_SIZE",
        "DEFAULT_MAX_FILES_PER_ARCHIVE",
        "DEFAULT_TIMEOUT_SECONDS",
        "DEFAULT_READ_CHUNK_SIZE",
    ):
        value = getattr(C, name)
        assert isinstance(value, int) and value > 0, name


def test_archive_ceiling_below_total_ceiling():
    # A single archive should never be allowed to exceed the run-wide ceiling.
    assert C.DEFAULT_MAX_EXTRACTED_SIZE <= C.DEFAULT_MAX_TOTAL_SIZE


def test_protected_tools_and_packages_are_frozensets():
    assert isinstance(C.PROTECTED_TOOLS, frozenset)
    assert isinstance(C.PROTECTED_PACKAGES, frozenset)
    # The package manager itself must be protected from uninstall/repair.
    assert "apt" in C.PROTECTED_PACKAGES
    assert "dpkg" in C.PROTECTED_PACKAGES
    assert "apt-get" in C.PROTECTED_TOOLS
    assert "dpkg-query" in C.PROTECTED_TOOLS


def test_tool_package_hints_resolves_to_a_platform_dict():
    assert isinstance(C.TOOL_PACKAGE_HINTS, dict)
    assert C.TOOL_PACKAGE_HINTS in (
        C.TOOL_PACKAGE_HINTS_LINUX,
        C.TOOL_PACKAGE_HINTS_WINDOWS,
    )


def test_magic_signatures_are_bytes_with_int_offsets():
    assert C.MAGIC_SIGNATURES
    for fmt, entries in C.MAGIC_SIGNATURES.items():
        assert entries, fmt
        for magic, offset in entries:
            assert isinstance(magic, (bytes, bytearray)), fmt
            assert isinstance(offset, int), fmt


def test_known_magic_values_are_correct():
    # Spot-check a few well-known signatures against their specifications.
    assert (b"\x1f\x8b", 0) in C.MAGIC_SIGNATURES["GZIP"]
    assert (b"\x7fELF", 0) in C.MAGIC_SIGNATURES["ELF"]
    assert (b"MZ", 0) in C.MAGIC_SIGNATURES["PE"]
    assert (b"%PDF-", 0) in C.MAGIC_SIGNATURES["PDF"]
    assert (b"7z\xbc\xaf\x27\x1c", 0) in C.MAGIC_SIGNATURES["SEVENZ"]


def test_extension_hints_lowercase_keys():
    for ext in C.EXTENSION_HINTS:
        assert ext == ext.lower(), ext
        assert ext.startswith("."), ext


def test_no_em_dash_in_constants_docstrings():
    import re_unpacker.constants as mod

    assert "\u2014" not in (mod.__doc__ or "")
