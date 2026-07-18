"""
.. module:: re_unpacker.pkg_manager
    :synopsis: Package-manager abstraction (install / uninstall / repair / query).

Description
-----------
Thin wrapper over the system package manager so the CLI's ``--install``,
``--uninstall``, and ``--repair`` modes can ask "which packages are
present?", "install these", "remove these", "reinstall these" without
caring whether the underlying tool is ``apt-get``, ``dnf``, ``pacman``, etc.

For v0.2.0 only the Debian/Ubuntu/Kali ``apt-get`` backend is implemented.
The shape of the API leaves room for additional backends later (one
class per backend, selected via :func:`detect_backend`).

Notes
-----
- Every privileged operation streams the package manager's output live to
  stdout so long-running ``apt-get update`` and ``apt-get install`` calls
  do not look hung. We do *not* capture and replay; the user sees the
  manager's own progress meter directly.
- ``is_package_installed`` queries via ``dpkg-query -W -f='${Status}'``
  rather than looking for binaries on PATH. The Status string starts with
  ``install ok installed`` for a complete install.
- We never run ``apt-get`` with ``shell=True`` and never interpolate
  package names into a shell string. Packages are always passed as
  separate argv tokens.

Execution parameters
--------------------
- All operations require root privilege. The CLI layer is responsible for
  the uid==0 check before calling these functions; this module does not
  re-check.

Examples
--------
::

    from re_unpacker.pkg_manager import detect_backend
    backend = detect_backend()
    if backend.is_package_installed("p7zip-full"):
        ...
    backend.install_packages(["p7zip-full", "cabextract"])

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, Sequence

from .exceptions import UnpackerError


# =============================================================================
# Exceptions
# =============================================================================

class PackageManagerError(UnpackerError):
    """Raised when a package-manager operation fails."""

    def __init__(
        self,
        operation: str,
        backend: str,
        *,
        returncode: int | None = None,
        context: dict | None = None,
    ) -> None:
        msg = f"Package manager operation '{operation}' failed via backend '{backend}'"
        if returncode is not None:
            msg += f" (rc={returncode})"
        super().__init__(msg, context=context)
        self.operation: str = operation
        self.backend: str = backend
        self.returncode: int | None = returncode


# =============================================================================
# Result type
# =============================================================================

@dataclass
class PkgOpResult:
    """Outcome of a single package-manager operation."""
    operation: str
    backend: str
    argv: list[str]
    returncode: int
    duration_seconds: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0


# =============================================================================
# Backend interface
# =============================================================================

class PackageManagerBackend:
    """Abstract base. Concrete subclasses implement the four operations."""

    name: str = "abstract"

    def is_package_installed(self, package: str) -> bool:
        raise NotImplementedError

    def installed_packages(self, packages: Sequence[str]) -> dict[str, bool]:
        """Return ``{pkg: True/False}`` for each package in ``packages``."""
        return {p: self.is_package_installed(p) for p in packages}

    def install_packages(
        self, packages: Sequence[str], *, logger: logging.Logger | None = None,
    ) -> PkgOpResult:
        raise NotImplementedError

    def remove_packages(
        self, packages: Sequence[str], *, logger: logging.Logger | None = None,
    ) -> PkgOpResult:
        raise NotImplementedError

    def reinstall_packages(
        self, packages: Sequence[str], *, logger: logging.Logger | None = None,
    ) -> PkgOpResult:
        raise NotImplementedError

    def is_essential_package(self, package: str) -> bool:
        """True iff the package is flagged as essential by the OS package
        manager and should not be uninstalled / reinstalled.

        Default implementation returns False (no concept of "essential" in
        the backend). Subclasses override where the package manager
        supports the notion. apt/dpkg has Essential:yes for packages like
        tar, gzip, dpkg, libc6 that cannot be removed without breaking the
        system; winget has no equivalent flag, so the default applies.
        """
        return False


# =============================================================================
# apt backend (Debian / Ubuntu / Kali)
# =============================================================================

class AptBackend(PackageManagerBackend):
    """Debian/Ubuntu/Kali apt-get backend."""

    name = "apt"

    # Class-level toggle: set False to skip the `apt-get update` step in
    # tests or repeated runs where it would just add latency.
    refresh_index: bool = True

    def __init__(self, *, refresh_index: bool = True) -> None:
        super().__init__()
        self.refresh_index = refresh_index
        self._dpkg_query = shutil.which("dpkg-query")
        self._apt_get = shutil.which("apt-get")
        if self._dpkg_query is None or self._apt_get is None:
            raise PackageManagerError(
                operation="init",
                backend=self.name,
                context={
                    "reason": "apt-get and/or dpkg-query not found on PATH",
                    "dpkg_query": self._dpkg_query,
                    "apt_get": self._apt_get,
                },
            )

    # ---------------- query

    def is_package_installed(self, package: str) -> bool:
        """True iff dpkg-query reports the package as fully installed.

        We accept ``install ok installed`` as the only "yes" answer; partial
        states (``half-installed``, ``config-files``, ``deinstall``) all
        count as not-installed for our purposes.
        """
        if not package:
            return False
        try:
            r = subprocess.run(
                [self._dpkg_query or "dpkg-query", "-W",
                 "-f=${Status}", "--", package],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                start_new_session=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
        if r.returncode != 0:
            return False
        status = r.stdout.decode("utf-8", errors="replace").strip()
        return status.startswith("install ok installed")

    def is_essential_package(self, package: str) -> bool:
        """True iff dpkg flags the package as Essential:yes.

        Essential packages cannot be removed by apt (apt errors out with
        rc=100). We check this so that ``--uninstall`` and ``--repair``
        can pre-filter the package list rather than handing apt a doomed
        request. Examples on Debian/Ubuntu: tar, gzip, dpkg, libc6.
        """
        if not package:
            return False
        try:
            r = subprocess.run(
                [self._dpkg_query or "dpkg-query", "-W",
                 "-f=${Essential}", "--", package],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                start_new_session=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
        if r.returncode != 0:
            return False
        return r.stdout.decode("utf-8", errors="replace").strip() == "yes"

    # ---------------- streaming-output runner

    def _run_streaming(
        self,
        operation: str,
        argv: Sequence[str],
        *,
        logger: logging.Logger | None = None,
    ) -> PkgOpResult:
        """Run ``argv`` and stream stdout+stderr live to the terminal."""
        import time
        argv = list(argv)
        if logger is not None:
            logger.info("%s: %s", operation, " ".join(argv))

        # Live streaming: we let stdout / stderr flow straight to the
        # terminal so apt's own progress display works.
        env = dict(os.environ)
        # DEBIAN_FRONTEND=noninteractive avoids debconf prompts mid-install,
        # which would otherwise hang a non-TTY session.
        env.setdefault("DEBIAN_FRONTEND", "noninteractive")

        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=None,            # inherit -> direct to terminal
                stderr=None,
                env=env,
                start_new_session=True,
            )
        except FileNotFoundError as e:
            raise PackageManagerError(
                operation=operation,
                backend=self.name,
                context={"reason": "executable not found", "argv": argv},
            ) from e

        try:
            rc = proc.wait()
        except KeyboardInterrupt:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            raise
        duration = time.monotonic() - start

        result = PkgOpResult(
            operation=operation,
            backend=self.name,
            argv=argv,
            returncode=rc,
            duration_seconds=round(duration, 2),
        )
        if rc != 0:
            raise PackageManagerError(
                operation=operation,
                backend=self.name,
                returncode=rc,
                context={"argv": argv, "duration_seconds": result.duration_seconds},
            )
        return result

    # ---------------- mutators

    def is_package_available(self, package: str) -> bool:
        """True iff ``apt-cache show <package>`` succeeds, meaning the
        package exists in some configured apt source. False if the package
        name is unknown to apt entirely.

        This is the cheap pre-flight that prevents one bad TOOL_PACKAGE_HINTS
        entry from poisoning a whole apt-get install batch (rc=100). v0.3.0
        added this after the libfsfat-utils incident: the libyal FAT mounter
        package is not in every Debian/Ubuntu release, and v0.2.0's all-or-
        nothing apt invocation would fail the whole install because of that
        single missing package.
        """
        if not package:
            return False
        try:
            r = subprocess.run(
                ["apt-cache", "show", "--", package],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                start_new_session=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
        return r.returncode == 0

    def filter_available(
        self, packages: Sequence[str], *, logger: logging.Logger | None = None,
    ) -> tuple[list[str], list[str]]:
        """Split ``packages`` into ``(available, unavailable)`` per apt-cache.

        Logs a message for each unavailable package so the user sees what was
        skipped and why. Packages listed in
        :data:`re_unpacker.constants.KNOWN_UNAVAILABLE_PACKAGES` get an
        INFO-level message with the documented explanation; otherwise we log
        a WARNING (because an unexpected unavailability suggests a
        misconfiguration or stale apt sources).
        """
        from .constants import KNOWN_UNAVAILABLE_PACKAGES
        available: list[str] = []
        unavailable: list[str] = []
        for p in packages:
            if self.is_package_available(p):
                available.append(p)
            else:
                unavailable.append(p)
                if logger is not None:
                    if p in KNOWN_UNAVAILABLE_PACKAGES:
                        logger.info(
                            "Skipping known-unavailable package %s: %s",
                            p, KNOWN_UNAVAILABLE_PACKAGES[p],
                        )
                    else:
                        logger.warning(
                            "Package %s is not available in the apt cache; "
                            "skipping. (Update apt sources or check the "
                            "package name in TOOL_PACKAGE_HINTS.)",
                            p,
                        )
        return available, unavailable

    def install_packages(
        self, packages: Sequence[str], *, logger: logging.Logger | None = None,
    ) -> PkgOpResult:
        if not packages:
            raise ValueError("install_packages: package list is empty")
        if self.refresh_index:
            self._run_streaming(
                "apt-get update",
                [self._apt_get or "apt-get", "update"],
                logger=logger,
            )
        # Filter against apt-cache to drop unavailable packages cleanly
        # rather than letting a single bad name kill the whole batch (rc=100).
        available, unavailable = self.filter_available(packages, logger=logger)
        if not available:
            raise PackageManagerError(
                operation="apt-get install",
                backend=self.name,
                returncode=None,
                context={
                    "reason": "all requested packages are unavailable in apt",
                    "requested": list(packages),
                    "unavailable": unavailable,
                },
            )
        return self._run_streaming(
            "apt-get install",
            [self._apt_get or "apt-get", "install",
             "-y", "--no-install-recommends", "--", *available],
            logger=logger,
        )

    def remove_packages(
        self, packages: Sequence[str], *, logger: logging.Logger | None = None,
    ) -> PkgOpResult:
        if not packages:
            raise ValueError("remove_packages: package list is empty")
        return self._run_streaming(
            "apt-get remove",
            [self._apt_get or "apt-get", "remove", "-y", "--", *packages],
            logger=logger,
        )

    def reinstall_packages(
        self, packages: Sequence[str], *, logger: logging.Logger | None = None,
    ) -> PkgOpResult:
        if not packages:
            raise ValueError("reinstall_packages: package list is empty")
        # apt-get install --reinstall handles already-broken installs too.
        return self._run_streaming(
            "apt-get install --reinstall",
            [self._apt_get or "apt-get", "install",
             "--reinstall", "-y", "--", *packages],
            logger=logger,
        )


# =============================================================================
# winget backend (Windows; v0.4.0)
# =============================================================================

class WingetBackend(PackageManagerBackend):
    """Microsoft Windows ``winget`` backend.

    Wraps the Windows Package Manager CLI for install / remove /
    reinstall operations. winget is delivered as part of the App
    Installer system component on Windows 10 1809+ and Windows 11; we
    assume it's present and probe-find it on PATH at construction time.

    Conventions
    -----------
    - Package identifiers are winget Package Identifier strings (e.g.
      ``7zip.7zip``, ``OliverBetz.ExifTool``, ``Microsoft.Sysinternals.Sigcheck``)
      verified against the microsoft/winget-pkgs manifest repository.
    - Empty-string entries in TOOL_PACKAGE_HINTS_WINDOWS are silently
      skipped: those tools are either built-in to Windows (expand,
      msiexec, tar, powershell) or require manual install (libyal
      binaries, signtool when not via Windows SDK auto-install). The
      KNOWN_UNAVAILABLE_PACKAGES_WINDOWS dict carries human-readable
      install instructions for the manual ones.
    - All winget invocations include the canonical agreement-acceptance
      flags so they're non-interactive: ``--silent
      --accept-source-agreements --accept-package-agreements``.
    - winget runs one install per package id. The install_packages
      method loops; the first failure raises PackageManagerError
      consistent with AptBackend's batch-fails-as-one semantics.
    """

    name = "winget"

    refresh_index: bool = True

    def __init__(self, *, refresh_index: bool = True) -> None:
        super().__init__()
        self.refresh_index = refresh_index
        self._winget = shutil.which("winget")
        if self._winget is None:
            raise PackageManagerError(
                operation="init",
                backend=self.name,
                context={
                    "reason": "winget not found on PATH",
                    "fix": (
                        "winget ships as part of the App Installer system "
                        "component on Windows 10 1809+ and Windows 11. "
                        "Install or update from the Microsoft Store: "
                        "https://www.microsoft.com/en-us/p/app-installer/9nblggh4nns1"
                    ),
                },
            )

    # ------------------------------------------------------------------
    # _run_streaming: same contract as AptBackend's helper
    # ------------------------------------------------------------------
    def _run_streaming(
        self,
        operation: str,
        argv: Sequence[str],
        *,
        logger: logging.Logger | None = None,
    ) -> PkgOpResult:
        """Run ``argv`` and stream stdout+stderr live to the terminal."""
        import time
        argv = list(argv)
        if logger is not None:
            logger.info("%s: %s", operation, " ".join(argv))

        env = dict(os.environ)
        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=None,            # inherit -> direct to terminal
                stderr=None,
                env=env,
            )
        except FileNotFoundError as e:
            raise PackageManagerError(
                operation=operation,
                backend=self.name,
                context={"reason": "executable not found", "argv": argv},
            ) from e

        try:
            rc = proc.wait()
        except KeyboardInterrupt:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            raise
        duration = time.monotonic() - start

        result = PkgOpResult(
            operation=operation,
            backend=self.name,
            argv=argv,
            returncode=rc,
            duration_seconds=round(duration, 2),
        )
        if rc != 0:
            # v0.4.1: detect 0x80071130 Fast Cache error specifically.
            # Decimal: 2147946800 (unsigned) or -147020496 (signed). winget
            # returns this when its source cache is corrupted or has never
            # been initialized -- common on fresh Windows installs and
            # freshly-provisioned VMs. Surface a clear remediation message
            # rather than just an opaque return code.
            ctx: dict = {"argv": argv, "duration_seconds": result.duration_seconds}
            if rc in (2147946800, -147020496):
                ctx["fix"] = (
                    "winget source cache is corrupted or uninitialized "
                    "(error 0x80071130 'Fast Cache data not found'). "
                    "Try one of the following: "
                    "(1) winget source update --source winget; "
                    "(2) winget source reset --force; "
                    "(3) reinstall App Installer from the Microsoft Store. "
                    "After resolving, re-run the install. See Usage Guide "
                    "playbook 21.39 for full details."
                )
            raise PackageManagerError(
                operation=operation,
                backend=self.name,
                returncode=rc,
                context=ctx,
            )
        return result

    # ------------------------------------------------------------------
    # _refresh_source: winget analog of `apt-get update`
    # ------------------------------------------------------------------
    def _refresh_source(
        self, *, logger: logging.Logger | None = None,
    ) -> None:
        """Run ``winget source update`` to initialize / refresh the source cache.

        Mirrors AptBackend.install_packages's `apt-get update` step. Required
        on fresh Windows installs and freshly-provisioned VMs where winget's
        source cache hasn't been populated yet -- without this, install_packages
        fails with 0x80071130 Fast Cache error before ever reaching the
        download step (see L30 in tasks/lessons.md).

        Defensive: if the refresh itself fails (e.g. no network), we log a
        warning and proceed; install_packages may still succeed against an
        already-populated cache, OR fail with the same error and let the
        user run `winget source reset --force` per the remediation hint.
        """
        if logger is not None:
            logger.info("winget source update (initializing source cache)")
        try:
            # v0.4.3 (lesson L35): `winget source update` does NOT accept
            # `--accept-source-agreements`. That flag is only valid for
            # the install / uninstall / upgrade subcommands. Including it
            # produces the red error: "Argument name was not recognized
            # for the current command: '--accept-source-agreements'".
            # Source agreements are accepted via the agreements prompt
            # path, which `--silent`-style operation handles implicitly
            # for source-update purposes (no agreement is required for
            # `source update` against an already-configured source).
            subprocess.run(
                [self._winget or "winget", "source", "update"],
                stdin=subprocess.DEVNULL,
                stdout=None,    # stream to terminal so user sees progress
                stderr=None,
                timeout=120,
                check=False,    # tolerate failure; logged + proceed
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            if logger is not None:
                logger.warning(
                    "winget source update failed (%s); proceeding "
                    "with potentially stale source cache. If subsequent "
                    "installs hit Fast Cache errors, run 'winget source "
                    "reset --force' manually.", e,
                )

    # ------------------------------------------------------------------
    # is_package_installed
    # ------------------------------------------------------------------
    def is_package_installed(self, package: str) -> bool:
        """Return True iff winget reports ``package`` as installed.

        Empty-string ``package`` (a built-in or manual-install tool with
        no winget hint) returns True unconditionally because winget
        cannot manage these and the orchestrator should not attempt to
        install / remove them.
        """
        if not package:
            return True  # cannot manage; treat as already-installed

        # winget list --id <id> --exact returns rc=0 if installed,
        # non-zero (typically -1978335212 / 0x8a15002b NO_INSTALLED_PACKAGE)
        # if not found.
        try:
            result = subprocess.run(
                [self._winget or "winget", "list",
                 "--id", package, "--exact",
                 "--accept-source-agreements"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    # ------------------------------------------------------------------
    # install_packages / remove_packages / reinstall_packages
    # ------------------------------------------------------------------
    def install_packages(
        self, packages: Sequence[str], *, logger: logging.Logger | None = None,
    ) -> PkgOpResult:
        """Install ``packages`` via ``winget install``.

        winget doesn't have a single-batch install primitive; we run
        one ``winget install`` per package id. This is slower than apt's
        batch install but mirrors winget's design (each package has its
        own installer to invoke).

        Empty-string entries are silently skipped (tools without a
        winget Package ID -- built-ins or manual-install). Returns the
        result of the LAST successful install for batch return-value
        consistency with AptBackend (or raises PackageManagerError on
        first failure).
        """
        if not packages:
            raise ValueError("install_packages: package list is empty")

        ids = filter_distinct_packages(p for p in packages if p)
        if not ids:
            raise PackageManagerError(
                operation="winget install",
                backend=self.name,
                returncode=None,
                context={
                    "reason": (
                        "no winget Package Identifiers in request "
                        "(all entries were empty -- built-ins or "
                        "manual-install tools)"
                    ),
                    "requested": list(packages),
                },
            )

        # v0.4.1: refresh the source cache before installing. Mirrors
        # AptBackend's `apt-get update` discipline. Required on fresh
        # Windows systems where the winget source hasn't been initialized
        # (see L30 in tasks/lessons.md and bug WIN-01 in tasks/todo.md).
        if self.refresh_index:
            self._refresh_source(logger=logger)

        last_result: PkgOpResult | None = None
        for pkg in ids:
            # --scope machine forces machine-scope (Program Files) install
            # rather than user-scope (LocalAppData). All re-unpacker
            # binaries must land in C:\Program Files\... per the project
            # security policy: no user-scope installs to AppData. Some
            # winget packages (notably MSIX-only Microsoft Store apps like
            # Microsoft.PowerShell when not the MSI variant) cannot do
            # machine scope and will error; we let those errors surface
            # to the user with a clear log message rather than silently
            # falling back to user scope.
            last_result = self._run_streaming(
                f"winget install {pkg}",
                [self._winget or "winget", "install",
                 "--id", pkg, "--exact",
                 "--scope", "machine",
                 "--silent",
                 "--accept-source-agreements",
                 "--accept-package-agreements"],
                logger=logger,
            )
        # The loop's final iteration's result represents the batch.
        # If any prior call raised PackageManagerError, we never get here.
        assert last_result is not None
        return last_result

    def remove_packages(
        self, packages: Sequence[str], *, logger: logging.Logger | None = None,
    ) -> PkgOpResult:
        """Remove ``packages`` via ``winget uninstall``."""
        if not packages:
            raise ValueError("remove_packages: package list is empty")

        ids = filter_distinct_packages(p for p in packages if p)
        if not ids:
            raise PackageManagerError(
                operation="winget uninstall",
                backend=self.name,
                returncode=None,
                context={
                    "reason": "no winget Package Identifiers in request",
                    "requested": list(packages),
                },
            )

        last_result: PkgOpResult | None = None
        for pkg in ids:
            last_result = self._run_streaming(
                f"winget uninstall {pkg}",
                [self._winget or "winget", "uninstall",
                 "--id", pkg, "--exact",
                 "--silent",
                 "--accept-source-agreements"],
                logger=logger,
            )
        assert last_result is not None
        return last_result

    def reinstall_packages(
        self, packages: Sequence[str], *, logger: logging.Logger | None = None,
    ) -> PkgOpResult:
        """Reinstall ``packages``. winget has no atomic reinstall; do
        uninstall + install. If a given uninstall fails (e.g. partial
        earlier install), we still proceed with the install so the end
        state is correct.
        """
        if not packages:
            raise ValueError("reinstall_packages: package list is empty")

        # Uninstall first; suppress individual failures so a partial
        # earlier install doesn't block the install half.
        try:
            self.remove_packages(packages, logger=logger)
        except PackageManagerError:
            pass
        return self.install_packages(packages, logger=logger)


# =============================================================================
# Backend detection
# =============================================================================

def detect_backend(
    *, refresh_index: bool = True, logger: logging.Logger | None = None,
) -> PackageManagerBackend:
    """Return a backend matching the host's package manager.

    v0.4.0 dispatch:
      - Windows -> :class:`WingetBackend`
      - Linux (apt-get + dpkg-query on PATH) -> :class:`AptBackend`

    Raises :class:`PackageManagerError` if neither matches.
    """
    from .platform_compat import is_windows
    if is_windows():
        if logger is not None:
            logger.debug("Detected winget backend")
        return WingetBackend(refresh_index=refresh_index)
    if shutil.which("apt-get") and shutil.which("dpkg-query"):
        if logger is not None:
            logger.debug("Detected apt backend")
        return AptBackend(refresh_index=refresh_index)
    raise PackageManagerError(
        operation="detect_backend",
        backend="(none)",
        context={
            "reason": "no supported package manager found",
            "supported": ["apt", "winget"],
        },
    )


# =============================================================================
# Helpers used by the CLI
# =============================================================================

def is_root() -> bool:
    """True iff the current process is running with elevated privileges.

    Linux / macOS: real root via ``os.geteuid() == 0``.
    Windows (v0.4.0+): elevated administrator via the Win32 API
    ``IsUserAnAdmin()`` from shell32 (wrapped in
    :func:`re_unpacker.platform_compat.is_admin`).
    """
    from .platform_compat import is_admin
    return is_admin()


def confirm(prompt: str, *, default_no: bool = True) -> bool:
    """Interactive y/N prompt. Defaults to NO on empty input."""
    suffix = " [y/N] " if default_no else " [Y/n] "
    try:
        ans = input(prompt + suffix).strip().lower()
    except EOFError:
        return False
    if not ans:
        return not default_no
    return ans in ("y", "yes")


def filter_distinct_packages(packages: Iterable[str]) -> list[str]:
    """Return ``packages`` with duplicates removed, original order preserved."""
    seen: set[str] = set()
    out: list[str] = []
    for p in packages:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def packages_for_tools(tools: Iterable[tuple[str, str | None]]) -> list[str]:
    """Map a sequence of ``(tool_name, package_hint)`` to a deduplicated
    package list. Tools whose ``package_hint`` is ``None`` are silently
    dropped (they are tools we do not know how to install).
    """
    out: list[str] = []
    seen: set[str] = set()
    for _name, pkg in tools:
        if pkg and pkg not in seen:
            seen.add(pkg)
            out.append(pkg)
    return out
