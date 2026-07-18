"""
.. module:: tests.test_regressions
    :synopsis: Regression guards for documented field-bug lessons.

Description
-----------
These tests encode two specific, previously-shipped bugs so they cannot recur:

- L40 (v0.4.5): a redundant function-local import made
  ``build_and_probe_registry`` a local variable inside ``cli._run_install``,
  producing an ``UnboundLocalError`` before any install work began. The guard
  inspects the compiled code object rather than running the platform-specific
  path.
- L45 (v0.4.8): ``WingetBackend`` lacked ``is_essential_package``, which the
  Linux ``AptBackend`` had, causing an ``AttributeError`` on Windows
  ``--dry-run-install``. The fix put a default on the base class. The guard
  asserts every backend satisfies the shared contract.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import inspect

import re_unpacker.cli as cli
from re_unpacker.pkg_manager import (
    AptBackend,
    PackageManagerBackend,
    WingetBackend,
)


def test_L40_build_and_probe_registry_not_function_local():
    # If any function-local import rebinds this name inside _run_install, it
    # becomes a local and the earlier module-level reference raises
    # UnboundLocalError at runtime. Fail here, at import/compile time, instead.
    local_names = set(cli._run_install.__code__.co_varnames)
    assert "build_and_probe_registry" not in local_names, (
        "build_and_probe_registry must resolve to the module-level import, "
        "not a function-local rebinding (L40 / v0.4.5 regression)."
    )


def test_L45_all_backends_share_is_essential_package():
    for backend_cls in (PackageManagerBackend, AptBackend, WingetBackend):
        assert hasattr(backend_cls, "is_essential_package"), backend_cls.__name__
        method = backend_cls.is_essential_package
        # Signature must accept (self, package).
        sig = inspect.signature(method)
        params = [p for p in sig.parameters if p != "self"]
        assert params, backend_cls.__name__


def test_L45_winget_backend_inherits_sensible_default():
    # WingetBackend does not override the method; it should inherit the base
    # default, which returns False (winget has no Essential:yes concept).
    assert (
        WingetBackend.is_essential_package is PackageManagerBackend.is_essential_package
    ), "WingetBackend should inherit the base is_essential_package default."


def test_apt_backend_overrides_is_essential_package():
    # AptBackend has real dpkg-query-backed behavior, so it must override.
    assert (
        AptBackend.is_essential_package is not PackageManagerBackend.is_essential_package
    ), "AptBackend must override is_essential_package with dpkg-query logic."
