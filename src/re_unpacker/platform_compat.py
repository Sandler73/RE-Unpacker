"""
.. module:: re_unpacker.platform_compat
    :synopsis: Cross-platform abstraction layer for Linux + Windows execution.

Description
-----------
Single source of truth for any code path that differs between Linux and
Windows. Runtime platform detection (no install-time configuration); the
same package runs on either OS by querying ``current_platform()`` or one
of the boolean helpers (``is_linux()``, ``is_windows()``).

What lives here:

- Platform detection (``is_windows``, ``is_linux``, ``is_macos``, ``current_platform``)
- Filesystem / cache directory resolution (XDG vs %LOCALAPPDATA%)
- Admin / root detection (``os.geteuid() == 0`` vs ``IsUserAnAdmin()``)
- Mode string synthesis (octal "0755" on Linux; synthesized from file
  attributes on Windows so the manifest field stays consistent across
  platforms)
- Tool name resolution with platform-aware extension fallbacks
  (``shutil.which`` on Linux just searches PATH; on Windows it looks for
  ``<name>.exe``, ``<name>.cmd``, ``<name>.bat`` etc. via PATHEXT)
- Default YARA rule directories (``/etc/yara/`` etc. on Linux;
  ``%PROGRAMDATA%\\yara`` etc. on Windows)

What does NOT live here:

- Per-extractor tool dispatch (lives in each extractor module; queries
  ``is_windows()`` when needed)
- Tool inventory and winget Package IDs (live in ``constants.py``)
- Verifier applies_to() platform filtering (lives in each verifier)

Why a single module: keeping platform-specific code in one place makes
it easy to audit, easy to test, and prevents the same conditional from
being re-derived in multiple call sites with subtle drift.

Notes
-----
- This module is designed to be imported VERY EARLY in the package load
  order. It must not pull in anything that itself depends on platform
  detection. The only stdlib imports are ``os``, ``sys``, ``platform``,
  ``ctypes`` (Windows-only branch), ``shutil``, and ``pathlib``.
- All functions in this module are pure where possible. Functions that
  consult environment variables or ctypes APIs are documented inline.
- Windows-specific helpers fall through gracefully on non-Windows: e.g.
  ``is_admin()`` on Linux returns the result of ``os.geteuid() == 0``;
  the ``ctypes.windll`` access is gated behind ``is_windows()`` so the
  module imports cleanly on Linux even though ``ctypes.windll`` doesn't
  exist there.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import sys
from pathlib import Path
from typing import Iterable

# =============================================================================
# Platform detection
# =============================================================================

# These constants are computed once at module import. They DON'T depend on
# environment variables, so caching is safe; the platform doesn't change
# during a process lifetime.
_PLATFORM_SYSTEM: str = platform.system().lower()
_IS_WINDOWS: bool = _PLATFORM_SYSTEM == "windows"
_IS_LINUX: bool = _PLATFORM_SYSTEM == "linux"
_IS_MACOS: bool = _PLATFORM_SYSTEM == "darwin"


def is_windows() -> bool:
    """Return True iff running on Windows."""
    return _IS_WINDOWS


def is_linux() -> bool:
    """Return True iff running on Linux."""
    return _IS_LINUX


def is_macos() -> bool:
    """Return True iff running on macOS.

    Note: re-unpacker doesn't officially support macOS as of;
    this helper exists for future use and so callers can write three-way
    branches if needed. Most macOS systems can run the Linux code path
    successfully because they're Unix-based.
    """
    return _IS_MACOS


def current_platform() -> str:
    """Return the canonical platform string: 'linux' / 'windows' / 'macos' / 'other'.

    Used in log lines, manifest provenance fields, and error messages
    where a single human-readable identifier is preferred over a stack
    of boolean checks.
    """
    if _IS_WINDOWS:
        return "windows"
    if _IS_LINUX:
        return "linux"
    if _IS_MACOS:
        return "macos"
    return "other"


# =============================================================================
# Filesystem layout
# =============================================================================

def cache_dir() -> Path:
    """Return the per-user cache directory for re-unpacker.

    Linux:
      - $XDG_CACHE_HOME/re-unpacker/ if XDG_CACHE_HOME is set
      - ~/.cache/re-unpacker/ otherwise

    Windows:
      - %LOCALAPPDATA%\\re-unpacker\\ if LOCALAPPDATA is set
      - %USERPROFILE%\\AppData\\Local\\re-unpacker\\ as fallback

    The directory is NOT created here; callers are responsible for
    creating it (typically via ``parents=True, exist_ok=True``).
    """
    if _IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            userprofile = os.environ.get("USERPROFILE")
            if userprofile:
                base = str(Path(userprofile) / "AppData" / "Local")
            else:
                # Last resort -- shouldn't happen on a properly-configured
                # Windows install, but fall through to home dir.
                base = str(Path.home() / "AppData" / "Local")
        return Path(base) / "re-unpacker"

    # Linux / macOS
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "re-unpacker"
    return Path.home() / ".cache" / "re-unpacker"


def config_dir() -> Path:
    """Return the per-user config directory for re-unpacker.

    Linux:
      - $XDG_CONFIG_HOME/re-unpacker/ if XDG_CONFIG_HOME is set
      - ~/.config/re-unpacker/ otherwise

    Windows:
      - %APPDATA%\\re-unpacker\\ if APPDATA is set
      - %USERPROFILE%\\AppData\\Roaming\\re-unpacker\\ as fallback

    Used primarily for per-user YARA rule auto-discovery.
    """
    if _IS_WINDOWS:
        base = os.environ.get("APPDATA")
        if not base:
            userprofile = os.environ.get("USERPROFILE")
            if userprofile:
                base = str(Path(userprofile) / "AppData" / "Roaming")
            else:
                base = str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "re-unpacker"

    # Linux / macOS
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "re-unpacker"
    return Path.home() / ".config" / "re-unpacker"


# =============================================================================
# Admin / root detection
# =============================================================================

def is_admin() -> bool:
    """Return True iff the current process has elevated privileges.

    Linux: ``os.geteuid() == 0`` (real root or equivalent capability).
    Windows: ``IsUserAnAdmin()`` from shell32 via ctypes (returns True
    iff the process token is in the BUILTIN\\Administrators group AND
    elevation is active, i.e. UAC was approved or it's a non-UAC install).

    Defensive: returns False on any exception. This function is queried
    by the installer/uninstaller/repair subsystem to gate elevated ops;
    a False return triggers the same "must run as root/admin" error
    path on both platforms.
    """
    if _IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    # Linux / macOS
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


# =============================================================================
# File mode synthesis
# =============================================================================

def format_mode_string(stat_result: os.stat_result) -> str:
    """Return a stable 4-char octal-mode string for ``stat_result``.

    On Linux, this is the standard octal mode bits formatted to 4 digits
    (e.g. "0755", "0644", "0700", "1777" with sticky bit). Matches the
    project-wide convention ``f"{st.st_mode & 0o7777:04o}"``.

    On Windows, the mode field is much less expressive: most files are
    0666 or 0777 with the read-only attribute set when applicable. To
    keep the manifest's ``mode`` field meaningful across platforms, we
    synthesize a Linux-compatible mode string from Windows file
    attributes:

      - Directory: "0755"
      - Read-only file: "0444"
      - Regular file (read+write): "0644"

    This is a heuristic, NOT an exact ACL translation. Downstream
    consumers reading the manifest should not interpret the Windows
    mode field as a precise permission descriptor; it's a coarse signal
    that lets the same downstream code work without branching.

    The function never raises; on any unexpected error it returns
    "0000" so the manifest field remains a valid string.
    """
    try:
        mode = stat_result.st_mode

        if _IS_WINDOWS:
            # Synthesize from file attributes
            if stat.S_ISDIR(mode):
                return "0755"
            # On Windows, st_mode encodes read/write/execute via the IRWXU
            # bits but it's coarse. Use the read-only check as primary
            # signal: stat module exposes FILE_ATTRIBUTE_READONLY indirectly
            # via stat.S_IWRITE bit (set when writable, cleared when RO).
            is_writable = bool(mode & stat.S_IWRITE)
            return "0644" if is_writable else "0444"

        # Linux / macOS: standard 4-char zero-padded octal
        return f"{mode & 0o7777:04o}"
    except Exception:
        return "0000"


# =============================================================================
# Tool name resolution
# =============================================================================

def executable_suffix() -> str:
    """Return the conventional executable extension for the platform.

    Linux: empty string (executables have no extension).
    Windows: ".exe".

    Not all Windows binaries are .exe (.bat, .cmd, .ps1 also work), but
    .exe is the most common and is what tool installers typically place
    on PATH. Use ``which_tool()`` for full PATHEXT-aware resolution.
    """
    return ".exe" if _IS_WINDOWS else ""


def which_tool(name: str) -> Path | None:
    """Resolve ``name`` to a full path or return None if not found.

    Wraps ``shutil.which()`` with platform-aware extension probing:

    - On Linux, just looks for the bare name on PATH.
    - On Windows, ``shutil.which()`` already consults PATHEXT and tries
      ``.exe``, ``.bat``, ``.cmd``, etc. automatically when the input
      name has no extension. We accept both forms (caller may pass either
      "exiftool" or "exiftool.exe") and normalize to the resolved path.
    - On Windows (; lesson L33), if PATH lookup misses, fall back
      to a curated set of well-known install directories. Several common
      winget packages (7-Zip, GnuPG, Sysinternals/Sigcheck, YARA, QPDF)
      install to fixed locations under Program Files but don't reliably
      add themselves to system PATH. Without this fallback, the
      install-then-detect cycle fails on freshly-installed Windows
      systems (the user's complaint after running --install on a fresh
      Windows 11 Pro deployment).

    Returns a ``Path`` on success, ``None`` on miss. Callers can rely on
    the result being a real, existing file.

    Performance note: this function is cheap (one filesystem scan of
    PATH directories plus, on Windows, a small set of stat calls against
    well-known directories). Don't bother caching results across calls;
    the OS already does this efficiently and PATH can change at runtime
    (e.g. after winget install).
    """
    found = shutil.which(name)
    if found is not None:
        return Path(found)

    # Lesson L33: Windows fallback to well-known install dirs.
    if _IS_WINDOWS:
        candidate = _windows_well_known_lookup(name)
        if candidate is not None:
            return candidate

    return None


# -----------------------------------------------------------------------------
# Windows well-known install directories (; lesson L33)
# -----------------------------------------------------------------------------
# Maps a tool name (canonical lowercase, no .exe) to a list of known
# absolute install paths under Program Files. Used as a fallback when
# shutil.which fails because the package didn't add itself to PATH or the
# current process's PATH was captured before a winget install.
#
# Curated list -- only tools whose canonical install path is stable
# across versions. For libyal binaries (variable user install location),
# manual-install tools like binwalk/upx/apktool, etc., we don't include
# entries; the user is expected to add their bin dir to PATH manually
# OR follow the install hint from KNOWN_UNAVAILABLE_PACKAGES_WINDOWS.
#
# Path-resolution order:
# 1. Try each absolute candidate in the list.
# 2. First file that exists wins.
#
# The %ProgramFiles% and %ProgramFiles(x86)% env vars are both queried so
# this works on both 32-bit and 64-bit Windows.

def _windows_program_files_dirs() -> list[Path]:
    """Return the set of Program Files roots to probe.

    Returns paths from %ProgramFiles%, %ProgramFiles(x86)%, and
    %ProgramW6432% (the 64-bit Program Files dir as seen from a 32-bit
    process). Filters to dirs that actually exist; returns at minimum
    the C:\\Program Files default if env-var resolution fails.
    """
    seen: set[str] = set()
    out: list[Path] = []
    for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        val = os.environ.get(var)
        if val and val not in seen:
            seen.add(val)
            p = Path(val)
            if p.exists():
                out.append(p)
    if not out:
        # Defensive default
        for fallback in (r"C:\Program Files", r"C:\Program Files (x86)"):
            p = Path(fallback)
            if p.exists():
                out.append(p)
    return out


def _windows_well_known_lookup(name: str) -> Path | None:
    """Probe well-known install directories for ``name`` on Windows.

    Returns a ``Path`` on success, ``None`` on miss. Caller is
    ``which_tool`` after shutil.which has already failed.

    Lesson L36: expanded coverage for winget's portable-package
    installation pattern. winget categorizes installer types:

    - ``inno`` / ``msi`` / ``wix`` installers: traditional Program Files
      layout (``%ProgramFiles%\\<Vendor>\\``) or user-scope under
      ``%LocalAppData%\\Programs\\<Vendor>\\``.
    - ``portable`` / ``archive`` (zip etc.) installers: winget-managed
      directories under ``%LOCALAPPDATA%\\Microsoft\\WinGet\\Packages\\``
      (user) or ``C:\\Program Files\\WinGet\\Packages\\`` (machine).
    - All winget-managed packages create shim links at
      ``%LOCALAPPDATA%\\Microsoft\\WinGet\\Links\\`` or
      ``C:\\Program Files\\WinGet\\Links\\``.

    Probe order:
    1. WinGet Links directories first (catch-all for portable packages
       via shim links; works regardless of PackageId).
    2. Per-tool hardcoded path map covering traditional Program Files
       installs and user-scope ``%LocalAppData%\\Programs\\``.
    3. Glob-based fallback for version-stamped install directories
       (e.g. QPDF Inno installer creates ``%ProgramFiles%\\qpdf X.Y.Z\\bin\\``).
    """
    # Lower-case for the lookup key; preserve original case for the
    # filename sub-component (Windows is case-insensitive but we want
    # to produce a normalized path either way).
    canonical = name.lower().removesuffix(".exe")

    # ---- Pass 0 (, lesson L41): re-unpacker's own manual-install dir.
    # Tools auto-installed by re-unpacker --install on Windows land at
    # C:\Program Files\re-unpacker\bin\ (per the manual_install_windows
    # subsystem). We must probe this directory directly rather than relying on
    # PATH propagation, because Windows propagates HKLM PATH updates to new
    # processes only after WM_SETTINGCHANGE broadcast; even then, child
    # processes of an already-running shell inherit the OLD PATH unless the
    # shell itself processes the broadcast. Probing the install dir directly
    # is deterministic and works regardless of PATH state.
    for re_unpacker_bin_dir in _re_unpacker_install_dirs():
        candidate = re_unpacker_bin_dir / f"{canonical}.exe"
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            pass

    # ---- Pass 1: winget Links dirs (single rule covers all portable packages)
    for links_dir in _winget_links_dirs():
        for ext in (".exe", ".cmd", ".bat"):
            candidate = links_dir / f"{canonical}{ext}"
            try:
                if candidate.is_file():
                    return candidate
            except OSError:
                continue

    # Tool -> list of relative subpaths under each Program Files root.
    # Include both 32-bit and 64-bit conventional locations; the caller's
    # _windows_program_files_dirs() handles the root-dir variation.
    KNOWN_LOCATIONS: dict[str, list[str]] = {
        # 7-Zip family: 7z.exe is the canonical CLI; 7zG.exe is GUI.
        "7z":           [r"7-Zip\7z.exe"],
        "7zz":          [r"7-Zip\7z.exe"],   # alias name; same binary
        # GnuPG: gpg + gpgv. Older Win-builds put under "GnuPG\bin",
        # Gpg4win uses "GnuPG\bin" too.
        "gpg":          [r"GnuPG\bin\gpg.exe", r"Gpg4win\..\GnuPG\bin\gpg.exe"],
        "gpgv":         [r"GnuPG\bin\gpgv.exe"],
        # QPDF: typically version-stamped dir; also try non-versioned
        "qpdf":         [r"qpdf\bin\qpdf.exe"],
        # Sysinternals: Sigcheck. winget Sysinternals.Sigcheck installs
        # under WinGet\Packages\<id>\sigcheck.exe (covered by Pass 1's
        # Links shim) but also occasionally to traditional locations.
        "sigcheck":     [r"Sysinternals\sigcheck.exe",
                         r"Sysinternals Suite\sigcheck.exe"],
        # ExifTool (OliverBetz packaging) -- Inno installer. Machine
        # scope: %ProgramFiles%\ExifTool\exiftool.exe. User scope:
        # %LocalAppData%\Programs\ExifTool\exiftool.exe (handled in pass 4).
        "exiftool":     [r"ExifTool\exiftool.exe",
                         r"OliverBetz\ExifTool\exiftool.exe"],
        # YARA: winget portable, covered by Pass 1 Links shim.
        # Listed here for non-winget installs.
        "yara":         [r"YARA\yara.exe",
                         r"VirusTotal\YARA\yara.exe",
                         r"YARA\bin\yara.exe"],
        "yarac":        [r"YARA\yarac.exe",
                         r"VirusTotal\YARA\yarac.exe",
                         r"YARA\bin\yarac.exe"],
    }

    # ---- Pass 2: hardcoded per-tool paths under Program Files roots
    if canonical in KNOWN_LOCATIONS:
        for root in _windows_program_files_dirs():
            for relpath in KNOWN_LOCATIONS[canonical]:
                candidate = root / relpath
                try:
                    if candidate.is_file():
                        return candidate
                except OSError:
                    continue

    # ---- Pass 3: per-tool glob patterns (version-stamped install dirs)
    GLOB_PATTERNS: dict[str, list[str]] = {
        # QPDF Inno installer creates `qpdf X.Y.Z\bin\qpdf.exe` typically
        "qpdf":         [r"qpdf*\bin\qpdf.exe"],
    }
    if canonical in GLOB_PATTERNS:
        for root in _windows_program_files_dirs():
            for pattern in GLOB_PATTERNS[canonical]:
                try:
                    matches = sorted(root.glob(pattern))
                    if matches:
                        # Last match (lexicographic) usually = highest version
                        return matches[-1]
                except (OSError, ValueError):
                    continue

    # ---- Pass 4: %LocalAppData%\Programs\ for user-scope Inno installers
    USER_SCOPE_LOCATIONS: dict[str, list[str]] = {
        "exiftool":     [r"ExifTool\exiftool.exe"],
        # ExifTool user-scope install per OliverBetz docs:
        # https://oliverbetz.de/pages/Artikel/ExifTool-for-Windows
        # ("for me only" install path defaults to %LocalAppData%\Programs\ExifTool)
    }
    if canonical in USER_SCOPE_LOCATIONS:
        local_programs = _local_appdata_programs_dir()
        if local_programs is not None:
            for relpath in USER_SCOPE_LOCATIONS[canonical]:
                candidate = local_programs / relpath
                try:
                    if candidate.is_file():
                        return candidate
                except OSError:
                    continue

    # ---- Pass 5: winget Packages dirs (per-package portable layout fallback)
    # Layout: <pkg-root>\<PackageId>_Microsoft.Winget.Source_8wekyb3d8bbwe\<tool>.exe
    # If the Links shim missed (e.g. exposed-name differs), this catches it.
    for pkg_root in _winget_packages_dirs():
        try:
            for subdir in pkg_root.iterdir():
                if not subdir.is_dir():
                    continue
                # Direct match first
                candidate = subdir / f"{canonical}.exe"
                try:
                    if candidate.is_file():
                        return candidate
                except OSError:
                    continue
                # Some packages nest one level deeper
                for sub in subdir.iterdir() if subdir.is_dir() else []:
                    if sub.is_dir():
                        nested = sub / f"{canonical}.exe"
                        try:
                            if nested.is_file():
                                return nested
                        except OSError:
                            continue
        except (OSError, PermissionError):
            continue

    # ---- Pass 6 (, lesson L43): Python Scripts directories.
    # pip-installed CLI tools (binwalk, etc.) place their entry-point .exe
    # at <python_install_root>\Scripts\<tool>.exe. Whether this directory is
    # on PATH depends on whether Python's installer registered it AND whether
    # the user has restarted their shell. Probing it directly removes both
    # dependencies. We glob across multiple Python versions (Python311,
    # Python312, Python313) and check both system-wide and user-scope Python
    # install roots.
    for scripts_dir in _python_scripts_dirs():
        for ext in (".exe", ".cmd", ".bat"):
            candidate = scripts_dir / f"{canonical}{ext}"
            try:
                if candidate.is_file():
                    return candidate
            except OSError:
                continue

    return None


def _re_unpacker_install_dirs() -> list[Path]:
    """Return existing re-unpacker manual-install directories.

    Used by Pass 0 of ``_windows_well_known_lookup`` to discover tools that
    re-unpacker itself installed via the manual-install handler subsystem
    (see ``manual_install_windows.py``). Per the user-confirmed Q1
    answer, the only valid install location is machine-scope under
    ``C:\\Program Files\\re-unpacker\\bin\\``. NEVER ``%LOCALAPPDATA%``.

    Returns existing dirs only; if re-unpacker has never been used to
    --install on this system, the dir won't exist and probing skips
    immediately.
    """
    out: list[Path] = []
    p = Path(r"C:\Program Files\re-unpacker\bin")
    if p.exists() and p.is_dir():
        out.append(p)
    return out


def _python_scripts_dirs() -> list[Path]:
    """Return existing Python Scripts directories for pip entry-point lookup.

    pip installs CLI tools as .exe wrappers in Python's Scripts dir. Locations
    we probe (in priority order):

    - ``%ProgramFiles%\\Python*\\Scripts`` -- system-wide Python
    - ``%ProgramFiles(x86)%\\Python*\\Scripts`` -- 32-bit Python
    - ``%LocalAppData%\\Programs\\Python\\Python*\\Scripts`` -- user-scope Python (Microsoft Store / installer "for me")

    Glob handles multiple Python versions (Python311, Python312, Python313).
    Returns sorted list, latest version last (so newer takes precedence on tie).
    """
    out: list[Path] = []

    # Pattern 1: system-wide installs (machine scope)
    for root in _windows_program_files_dirs():
        try:
            for python_dir in sorted(root.glob("Python*")):
                if not python_dir.is_dir():
                    continue
                scripts = python_dir / "Scripts"
                if scripts.exists() and scripts.is_dir():
                    out.append(scripts)
        except (OSError, ValueError):
            continue

    # Pattern 2: per-user installs (Programs subdir under LocalAppData)
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        user_python_root = Path(local_appdata) / "Programs" / "Python"
        if user_python_root.exists() and user_python_root.is_dir():
            try:
                for python_dir in sorted(user_python_root.glob("Python*")):
                    if not python_dir.is_dir():
                        continue
                    scripts = python_dir / "Scripts"
                    if scripts.exists() and scripts.is_dir():
                        out.append(scripts)
            except (OSError, ValueError):
                pass

    return out


def _winget_links_dirs() -> list[Path]:
    """Return existing winget Links directories (user + machine scope).

    These directories contain shim .exe files for every portable winget
    package's exposed commands. Probing here is the single best fallback
    for portable winget packages -- one rule covers all of them
    regardless of PackageId.

    The Links directories are:
    - User scope: ``%LOCALAPPDATA%\\Microsoft\\WinGet\\Links``
    - Machine scope: ``C:\\Program Files\\WinGet\\Links``

    Confirmed by winget's own ``winget --info`` output across versions.
    """
    out: list[Path] = []
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        p = Path(local_appdata) / "Microsoft" / "WinGet" / "Links"
        if p.exists() and p.is_dir():
            out.append(p)
    for root in _windows_program_files_dirs():
        p = root / "WinGet" / "Links"
        if p.exists() and p.is_dir():
            out.append(p)
    return out


def _winget_packages_dirs() -> list[Path]:
    """Return existing winget Packages root directories.

    Per-package portable contents are stored here. Each subdirectory is
    named ``<PackageId>_Microsoft.Winget.Source_8wekyb3d8bbwe``.

    The Packages directories are:
    - User scope: ``%LOCALAPPDATA%\\Microsoft\\WinGet\\Packages``
    - Machine scope: ``C:\\Program Files\\WinGet\\Packages``
    - x86 machine: ``C:\\Program Files (x86)\\WinGet\\Packages``
    """
    out: list[Path] = []
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        p = Path(local_appdata) / "Microsoft" / "WinGet" / "Packages"
        if p.exists() and p.is_dir():
            out.append(p)
    for root in _windows_program_files_dirs():
        p = root / "WinGet" / "Packages"
        if p.exists() and p.is_dir():
            out.append(p)
    return out


def _local_appdata_programs_dir() -> Path | None:
    """Return ``%LocalAppData%\\Programs`` if it exists, else None.

    This is the canonical per-user install root for Inno Setup
    installers run with ``/CURRENTUSER`` (user scope). Used by ExifTool
    (OliverBetz packaging) when winget chooses user scope, and by other
    Inno installers under similar conditions.
    """
    local_appdata = os.environ.get("LOCALAPPDATA")
    if not local_appdata:
        return None
    p = Path(local_appdata) / "Programs"
    return p if p.exists() and p.is_dir() else None


def refresh_path_from_registry() -> bool:
    """Re-read PATH from the Windows registry into ``os.environ['PATH']``.

    Returns True on success, False on no-op (non-Windows or error).
    Used after a winget install batch to pick up new entries that
    winget added to the system or user PATH but that the current
    process's environment snapshot didn't see.

    Reads HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\
    Environment\\Path (system PATH) and HKCU\\Environment\\Path (user
    PATH), concatenates them, and writes the result to os.environ['PATH'].

    Defensive: any registry-access exception is swallowed and returns
    False. The caller's worst case is "PATH wasn't refreshed; some
    tools may still appear missing"; the well-known-directory fallback
    in ``which_tool`` covers most cases regardless.

    """
    if not _IS_WINDOWS:
        return False

    try:
        import winreg  # type: ignore
    except ImportError:
        return False

    parts: list[str] = []
    # System PATH
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ) as key:
            value, _type = winreg.QueryValueEx(key, "Path")
            if value:
                parts.append(value)
    except OSError:
        pass

    # User PATH (HKCU)
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Environment",
        ) as key:
            value, _type = winreg.QueryValueEx(key, "Path")
            if value:
                parts.append(value)
    except OSError:
        pass

    if not parts:
        return False

    # Expand %VAR% references winget may have written; deduplicate while
    # preserving order.
    new_path = os.path.expandvars(";".join(parts))
    seen: set[str] = set()
    deduped: list[str] = []
    for entry in new_path.split(";"):
        entry = entry.strip()
        if entry and entry.lower() not in seen:
            seen.add(entry.lower())
            deduped.append(entry)
    os.environ["PATH"] = ";".join(deduped)
    return True


# =============================================================================
# YARA rule auto-discovery
# =============================================================================

def default_yara_rule_dirs() -> list[tuple[str, str]]:
    """Return the platform-appropriate YARA rule auto-discovery directories.

    Each entry is a (path, namespace_prefix) tuple. Paths are returned as
    strings (NOT expanded -- callers must call ``os.path.expanduser`` and
    ``os.path.expandvars`` as needed) so test code can override the
    expansion mechanism.

    Linux directories:
      - /etc/yara/ -> namespace "etc"
      - ~/.config/re-unpacker/yara/ -> namespace "user"
      - /var/lib/yara-forge/packages/full/ -> namespace "forge"

    Windows directories:
      - %PROGRAMDATA%\\yara\\ -> namespace "etc"
      - %APPDATA%\\re-unpacker\\yara\\ -> namespace "user"
      - %PROGRAMDATA%\\yara-forge\\packages\\full\\ -> namespace "forge"

    The semantic mapping is consistent across platforms:
      - "etc" = system-wide rules installed by package manager / admin
      - "user" = per-user custom rules
      - "forge" = YARA Forge stock rule package, when installed

    YARA rule files (.yar / .yara) found in any of these dirs are loaded
    as a UNION at run start, namespaced by source-dir prefix so duplicate
    rule names across dirs resolve cleanly. See the locked-in design
    decision in tasks/todo.md.
    """
    if _IS_WINDOWS:
        # Use forward-slash style here for cross-tool consistency; Path()
        # handles Windows path separators when these strings are passed
        # into pathlib later. os.path.expandvars expands %FOO% syntax.
        return [
            (r"%PROGRAMDATA%\yara",                          "etc"),
            (r"%APPDATA%\re-unpacker\yara",                  "user"),
            (r"%PROGRAMDATA%\yara-forge\packages\full",      "forge"),
        ]
    # Linux / macOS
    return [
        ("/etc/yara",                                        "etc"),
        ("~/.config/re-unpacker/yara",                       "user"),
        ("/var/lib/yara-forge/packages/full",                "forge"),
    ]


def expand_path(path_template: str) -> str:
    """Expand env vars and user-home in ``path_template`` for current platform.

    Cross-platform-aware: handles both ``$VAR`` (POSIX) and ``%VAR%``
    (Windows) syntax via ``os.path.expandvars``, then applies
    ``os.path.expanduser`` for ``~`` and ``~user`` forms.

    Used primarily by the YARA rule auto-discovery code to expand the
    templates returned by ``default_yara_rule_dirs()`` into concrete
    filesystem paths.
    """
    return os.path.expanduser(os.path.expandvars(path_template))


# =============================================================================
# Path safety
# =============================================================================

def long_path_supported() -> bool:
    r"""Return True iff long path support is enabled on this platform.

    Linux: always True (filesystem-dependent, but PATH_MAX is typically
    4096 which is far above what re-unpacker generates).

    Windows: True iff ``LongPathsEnabled`` registry value is set under
    HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem (Windows 10
    1607+). False otherwise (limit is 260 characters per legacy MAX_PATH).

    re-unpacker uses this to decide whether to prefix paths with ``\\?\``
    when path length approaches MAX_PATH. The prefix unlocks long-path
    support for individual operations even if the system-wide setting
    isn't enabled.
    """
    if not _IS_WINDOWS:
        return True

    try:
        import winreg  # type: ignore
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\FileSystem",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "LongPathsEnabled")
            return bool(value)
    except Exception:
        return False


def normalize_long_path(path: Path) -> Path:
    r"""If on Windows and the path approaches MAX_PATH, prefix with ``\\?\``.

    The prefix bypasses the legacy 260-char limit per-operation. Linux
    paths are returned unchanged.

    re-unpacker generates deeply-nested paths (depth-N extraction trees);
    the unpacked-suffix convention can push paths past MAX_PATH on
    pathological inputs. Calling this on every path passed to subprocess
    invocations is cheap insurance.
    """
    if not _IS_WINDOWS:
        return path

    s = str(path)
    if len(s) < 240:  # comfortably below MAX_PATH; no need
        return path

    # Already has the prefix, leave alone
    if s.startswith("\\\\?\\") or s.startswith("//?/"):
        return path

    # Resolve to absolute first; \\?\ requires absolute paths
    absolute = path.resolve() if not path.is_absolute() else path
    return Path("\\\\?\\" + str(absolute))


# =============================================================================
# Public API surface for ``from .platform_compat import *``
# =============================================================================

__all__ = [
    # Platform detection
    "is_windows",
    "is_linux",
    "is_macos",
    "current_platform",
    # Filesystem layout
    "cache_dir",
    "config_dir",
    # Admin / root detection
    "is_admin",
    # File mode synthesis
    "format_mode_string",
    # Tool name resolution
    "executable_suffix",
    "which_tool",
    # YARA rule auto-discovery
    "default_yara_rule_dirs",
    "expand_path",
    # Path safety
    "long_path_supported",
    "normalize_long_path",
    # PATH refresh after winget install
    "refresh_path_from_registry",
]
