"""
.. module:: re_unpacker.manual_install_windows
    :synopsis: Auto-install handlers for Windows tools with no winget package.

Provides install handlers for Windows tools whose canonical distribution channel
is a GitHub release ZIP, a pip package, or a vendor installer (rather than a
winget Package ID). Wired into the cli.py ``--install`` flow on Windows; runs
after the winget batch completes.

Description
-----------
The Windows tool inventory in TOOL_PACKAGE_HINTS_WINDOWS marks ~30 tools with an
empty hint, indicating "no winget package -- manual install required".
Without the handlers in this module such tools are skipped entirely by
`--install`, leaving a partial install batch and a list of names to track
down by hand. The subsystem scope is:

    Q1 (where to install) -> C:\\Program Files\\re-unpacker\\bin\\
                              (machine scope, requires admin; never %LOCALAPPDATA%
                              per the user's security/policy stance)
    Q2 (how to source) -> auto-download at install time from each tool's
                              canonical upstream release (no bundled binaries;
                              tarball stays small, version is always current)
    Q3 (which tools) -> everything except signtool (user has SDK already),
                              apksigner / apktool / aapt2 (Android SDK; user
                              chose to skip)
    Q4 (failure mode) -> log + notify per-tool failure, continue with the
                              rest of the batch; non-zero exit code at end if
                              any handler failed

The architecture is a registry of per-tool handler functions. Each handler is
responsible for downloading the upstream release, extracting binaries, copying
them into the install dir, and verifying the result. Failures are caught,
logged with actionable diagnostics, and reported in the end-of-batch summary
without aborting the rest of the batch.

Notes
-----
- Stdlib only: urllib, ssl, zipfile, hashlib, tempfile, shutil, subprocess.
  No external pip dependencies (consistent with the project-wide rule).
- Admin required: writes to C:\\Program Files\\... and updates HKLM\\SYSTEM\\
  CurrentControlSet\\Control\\Session Manager\\Environment\\Path. The
  `_run_install` flow already calls `_ensure_root()` before invoking us, so
  we assume admin and fail loudly if we don't have it.
- Network failures are caught and reported per-tool. The `--install` flow does
  not abort if one handler fails network access; it reports and continues.
- The libyal toolset (16 binaries: ewf*, vmdk*, vhdi*, qcow*, fs{apfs,ntfs,
  ext,fat,hfs,xfs}{info,export}, vshadow*, vslvm*, luksde*, smraw*, phdi*) is
  partially covered: ewfinfo / ewfexport are auto-installable via the
  alpine-sec/ewf-tools third-party Windows binary mirror. The remaining libyal
  binaries have no upstream Windows binary distribution from joachimmetz; their
  handlers explicitly log "no upstream Windows binaries published; build from
  source required" rather than silently failing or downloading from untrusted
  third-party sources.

Execution Parameters
--------------------
- ``install_missing_tools_windows(tool_names, *, logger)`` -- top-level entry
  point. ``tool_names`` is the iterable of MISSING tool names (filtered by the
  caller from the post-winget probe pass). Returns a ``ManualInstallSummary``
  with succeeded / failed / skipped lists.
- ``_INSTALL_DIR`` -- module constant: ``Path(r"C:\\Program Files\\re-unpacker\\bin")``
- ``_DOWNLOAD_TIMEOUT`` -- 300 seconds per HTTP transfer; tunable via
  ``RE_UNPACKER_DOWNLOAD_TIMEOUT`` env var if the user has a slow link.

Examples
--------
::

    from re_unpacker.manual_install_windows import install_missing_tools_windows
    summary = install_missing_tools_windows(
        ["binwalk", "upx", "ewfinfo", "vmdkinfo"],
        logger=logger,
    )
    # summary.succeeded == ["binwalk", "upx", "ewfinfo"]
    # summary.failed == []
    # summary.skipped == [("vmdkinfo", "no upstream Windows binaries")]

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


class ManualInstallError(OSError):
    """Raised when a manual-install download fails an integrity check (SEC-3).

    Subclasses ``OSError`` so it is caught by the existing per-tool
    graceful-continuation handlers (which catch ``OSError``), turning an
    integrity failure into a reported ``failed`` result rather than crashing
    the whole install batch.
    """

from .constants import VERSION
from .platform_compat import is_admin, is_windows


# =============================================================================
# Module constants
# =============================================================================

#: Absolute install directory for all manually-installed binaries on Windows.
#: Single dir keeps PATH simple (one entry) and groups our managed binaries
#: under a clearly-named root that an admin can audit, lock down, or delete.
#: Per the user-confirmed Q1 answer: machine-scope, never user scope.
_INSTALL_DIR: Path = Path(r"C:\Program Files\re-unpacker\bin")

#: Timeout for HTTP downloads (seconds). Some libyal mirrors are slow; default
#: of 300s (5 min) handles the largest libewf release zip on consumer broadband.
#: Override via env var ``RE_UNPACKER_DOWNLOAD_TIMEOUT`` if needed.
_DOWNLOAD_TIMEOUT: int = int(os.environ.get("RE_UNPACKER_DOWNLOAD_TIMEOUT", "300"))

#: Timeout for the GitHub API JSON fetch (release metadata). Quicker than asset
#: download because it's small JSON.
_API_TIMEOUT: int = 30

#: User-Agent header. GitHub API requires a non-empty UA on every request.
#: Derived from the single source of truth so it can never report a stale
#: version to the remote host.
_USER_AGENT: str = f"re-unpacker/{VERSION} (manual-install)"

#: GitHub release API URL template.
_GITHUB_LATEST_RELEASE_URL: str = "https://api.github.com/repos/{repo}/releases/latest"


# =============================================================================
# Result types
# =============================================================================

@dataclass
class ManualInstallResult:
    """Outcome of one tool's install attempt.

    Fields:
        tool: the tool name (e.g. ``"binwalk"``, ``"upx"``).
        status: one of ``"succeeded"``, ``"failed"``, ``"skipped"``.
        message: human-readable detail. For failures, includes which step
            (download / extract / verify) failed and the underlying exception
            text. For skipped, includes the upstream-availability reason.
        artifacts: list of paths created on disk (for diagnostic purposes;
            empty if status != "succeeded").
    """
    tool: str
    status: str
    message: str
    artifacts: list[Path] = field(default_factory=list)


@dataclass
class ManualInstallSummary:
    """End-of-batch report. Returned by ``install_missing_tools_windows``."""
    succeeded: list[ManualInstallResult] = field(default_factory=list)
    failed: list[ManualInstallResult] = field(default_factory=list)
    skipped: list[ManualInstallResult] = field(default_factory=list)

    @property
    def any_failed(self) -> bool:
        """True if any handler returned status='failed' (Q4 exit-code signal)."""
        return bool(self.failed)

    def format_human(self) -> str:
        """Format a human-readable summary block for end-of-batch printing."""
        lines: list[str] = []
        lines.append("=" * 72)
        lines.append("Manual install summary (Windows non-winget tools)")
        lines.append("=" * 72)
        lines.append(f"  Succeeded:  {len(self.succeeded):>3}")
        lines.append(f"  Failed:     {len(self.failed):>3}")
        lines.append(f"  Skipped:    {len(self.skipped):>3}")
        if self.succeeded:
            lines.append("")
            lines.append("Succeeded:")
            for r in self.succeeded:
                lines.append(f"  + {r.tool:<16} {r.message}")
        if self.failed:
            lines.append("")
            lines.append("Failed (you may need to install these manually):")
            for r in self.failed:
                lines.append(f"  - {r.tool:<16} {r.message}")
        if self.skipped:
            lines.append("")
            lines.append("Skipped (no auto-install available):")
            for r in self.skipped:
                lines.append(f"  ~ {r.tool:<16} {r.message}")
        lines.append("=" * 72)
        return "\n".join(lines)


# =============================================================================
# HTTP / archive helpers
# =============================================================================

def _http_get_json(url: str, *, logger: logging.Logger) -> dict | list:
    """Fetch ``url`` and return parsed JSON.

    Wraps urllib.request with sensible defaults (User-Agent header, TLS context,
    timeout). Raises urllib.error.URLError or json.JSONDecodeError on failure;
    callers should catch broadly and log.
    """
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    ctx = ssl.create_default_context()
    logger.debug("HTTP GET (json): %s", url)
    with urllib.request.urlopen(req, timeout=_API_TIMEOUT, context=ctx) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body)


def _http_download(
    url: str,
    dest: Path,
    *,
    logger: logging.Logger,
    expected_sha256: str | None = None,
) -> str:
    """Stream-download ``url`` to ``dest`` with progress and integrity logging.

    Uses urlretrieve-equivalent stream pattern. Dest's parent must exist;
    download is written to dest+".part" then moved atomically to dest on
    success.

    Integrity (SEC-3): the SHA-256 of the downloaded bytes is computed during
    streaming and logged, so every install of an unverified upstream binary is
    at least auditable and reproducible. When ``expected_sha256`` is supplied,
    it is enforced: a mismatch raises :class:`ManualInstallError` and the
    partial file is discarded, so a caller that knows the good digest can pin
    it. TLS is verified by ``ssl.create_default_context`` (cert + hostname),
    which defends the transport; the digest defends against a substituted or
    tampered upstream asset that TLS alone cannot catch. Returns the hex digest.
    """
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    ctx = ssl.create_default_context()
    tmp = dest.with_suffix(dest.suffix + ".part")
    logger.info("Downloading %s -> %s", url, dest.name)
    hasher = hashlib.sha256()
    try:
        with urllib.request.urlopen(req, timeout=_DOWNLOAD_TIMEOUT, context=ctx) as resp:
            total_size = int(resp.headers.get("Content-Length", "0") or 0)
            bytes_done = 0
            with open(tmp, "wb") as f:
                while True:
                    chunk = resp.read(65536)  # 64KB chunks
                    if not chunk:
                        break
                    f.write(chunk)
                    hasher.update(chunk)
                    bytes_done += len(chunk)
        digest = hasher.hexdigest()

        # Enforce pinning when an expected digest was provided.
        if expected_sha256 is not None:
            if digest.lower() != expected_sha256.strip().lower():
                if tmp.exists():
                    try:
                        tmp.unlink()
                    except OSError:
                        pass
                raise ManualInstallError(
                    f"Integrity check failed for {dest.name}: expected SHA-256 "
                    f"{expected_sha256.strip().lower()} but downloaded content "
                    f"hashes to {digest}. Refusing to install a mismatched "
                    f"binary."
                )

        tmp.replace(dest)
        # Always record the digest so installs are auditable even when no
        # expected value was pinned.
        logger.info("Download SHA-256 %s: %s", dest.name, digest)
        logger.debug(
            "Download complete: %s (%d bytes%s)",
            dest.name, bytes_done,
            f" of {total_size}" if total_size else "",
        )
        return digest
    except Exception:
        # Cleanup partial file on any error
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        raise


def _extract_zip(
    zip_path: Path,
    dest_dir: Path,
    *,
    logger: logging.Logger,
) -> None:
    """Extract ``zip_path`` into ``dest_dir`` (created if absent).

    Defensive against zip-slip path-traversal: rejects entries whose resolved
    target is outside ``dest_dir``.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    logger.debug("Extracting %s -> %s", zip_path.name, dest_dir)
    dest_resolved = dest_dir.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            target = (dest_dir / member).resolve()
            try:
                target.relative_to(dest_resolved)
            except ValueError:
                logger.warning(
                    "Refusing zip member with path-traversal: %s in %s",
                    member, zip_path.name,
                )
                continue
            zf.extract(member, dest_dir)


def _find_executables(
    root: Path,
    *,
    names: list[str] | None = None,
) -> list[Path]:
    """Walk ``root`` recursively and return paths to .exe files.

    If ``names`` is given (case-insensitive list), filter to only those.
    Returns sorted list (deterministic for testing).
    """
    out: list[Path] = []
    name_set = {n.lower() for n in names} if names else None
    for path in root.rglob("*.exe"):
        if not path.is_file():
            continue
        if name_set is not None:
            stem = path.stem.lower()
            if stem not in name_set:
                continue
        out.append(path)
    return sorted(out)


# =============================================================================
# Install dir setup + PATH update
# =============================================================================

def _ensure_install_dir(*, logger: logging.Logger) -> Path:
    """Ensure ``_INSTALL_DIR`` exists; create if absent.

    Returns the install dir path. Caller must have admin (writes to Program
    Files); we don't elevate from inside.
    """
    if not _INSTALL_DIR.exists():
        logger.info("Creating install directory: %s", _INSTALL_DIR)
        _INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    return _INSTALL_DIR


def _add_install_dir_to_system_path(*, logger: logging.Logger) -> bool:
    """Add ``_INSTALL_DIR`` to the SYSTEM PATH via HKLM registry, idempotently
    AND length-safely.

    Windows shows a modal "PATH env variable too big"
    dialog when a process writes an HKLM PATH value that pushes the environment
    variable over the legacy 2047-char REG_SZ buffer limit. Across multiple
    RE-Unpacker --install runs on the same machine, cumulative PATH growth
    (winget per-package additions + our install dir + whatever else the user
    has accumulated) can cross this threshold. We must:

    1. Always update the current Python process's PATH (process-local; safe;
       enables current-run tool discovery).
    2. Normalize entries for idempotency check (handle trailing slashes,
       mixed path separators, case variation).
    3. Length-check the proposed new PATH value before writing the registry.
    4. Skip the registry write with a clear warning if it would exceed the
       safe threshold (1900 chars leaves margin under 2047).
    5. Continue gracefully -- RE-Unpacker's Pass 0 well-known lookup (added
       ) finds our installed tools regardless of PATH state, so
       installation success doesn't depend on the registry update.

    Returns True if HKLM PATH was updated (or was already correct); False if
    we skipped the registry write due to length / error. The current
    process's PATH is always updated.
    """
    install_dir_str = str(_INSTALL_DIR)
    install_norm = os.path.normpath(install_dir_str).lower()

    # ---- Always update current-process PATH first (idempotent, process-local).
    # This is safe -- it only affects this Python invocation; it never writes
    # to the registry and so cannot trigger the Windows "PATH too big" dialog.
    cur_proc_path = os.environ.get("PATH", "")
    proc_entries_norm = [
        os.path.normpath(e).lower()
        for e in cur_proc_path.split(";") if e
    ]
    if install_norm not in proc_entries_norm:
        sep = ";" if cur_proc_path and not cur_proc_path.endswith(";") else ""
        os.environ["PATH"] = cur_proc_path + sep + install_dir_str
        logger.debug("Added to current-process PATH: %s", install_dir_str)

    # ---- Try to update HKLM PATH for persistence across processes/shells.
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("winreg not available; can't update system PATH")
        return False

    # Soft limit chosen with margin under the Windows 2047-char REG_SZ env-var
    # buffer limit. Crossing 2047 triggers a modal "PATH env variable too big"
    # dialog from Windows' environment broadcast mechanism.
    PATH_SAFE_LIMIT = 1900

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            0,
            winreg.KEY_READ | winreg.KEY_WRITE,
        ) as key:
            try:
                current_value, value_type = winreg.QueryValueEx(key, "Path")
            except OSError:
                current_value, value_type = "", winreg.REG_EXPAND_SZ

            # Normalized idempotency check: handles trailing slashes, mixed
            # path separators (`/` vs `\`), and case variation. Without
            # normalization, `C:\\Program Files\\re-unpacker\\bin\\` and
            # `C:\\Program Files\\re-unpacker\\bin` get treated as different
            # entries even though they're the same directory.
            existing_entries = [e for e in current_value.split(";") if e]
            existing_norm = [os.path.normpath(e).lower() for e in existing_entries]
            if install_norm in existing_norm:
                logger.debug(
                    "Install dir already in system PATH (idempotent skip): %s",
                    install_dir_str,
                )
                return True

            # Length check BEFORE write. Append separator if needed.
            sep_len = 0 if current_value.endswith(";") or not current_value else 1
            new_path_len = len(current_value) + sep_len + len(install_dir_str)
            if new_path_len > PATH_SAFE_LIMIT:
                # Compute cleanup analysis: duplicates, dead entries, savings
                norm_seen: dict[str, str] = {}
                duplicate_pairs: list[tuple[str, str]] = []
                for entry in existing_entries:
                    n = os.path.normpath(entry).lower()
                    if n in norm_seen:
                        duplicate_pairs.append((norm_seen[n], entry))
                    else:
                        norm_seen[n] = entry

                dead_entries: list[str] = []
                for entry in existing_entries:
                    try:
                        expanded = os.path.expandvars(entry)
                        if not Path(expanded).exists():
                            dead_entries.append(entry)
                    except (OSError, ValueError):
                        dead_entries.append(entry)

                # Compute proposed-cleanup PATH (drops duplicates and dead
                # entries; preserves order of first occurrence)
                kept: list[str] = []
                kept_norm: set[str] = set()
                for entry in existing_entries:
                    n = os.path.normpath(entry).lower()
                    if n in kept_norm:
                        continue
                    try:
                        if not Path(os.path.expandvars(entry)).exists():
                            continue
                    except (OSError, ValueError):
                        continue
                    kept.append(entry)
                    kept_norm.add(n)
                cleaned_len = sum(len(e) for e in kept) + max(0, len(kept) - 1)
                savings = len(current_value) - cleaned_len

                # Send the diagnostic to BOTH the log AND stdout. The log line
                # is for the diagnostic record; stdout is for the user who
                # may not be reading the log file in real-time.
                msg_lines = [
                    "",
                    "=" * 72,
                    "WARNING: System PATH is over the Windows-safe limit",
                    "=" * 72,
                    f"  Current system PATH:   {len(current_value)} chars",
                    f"  Adding install dir:    {len(install_dir_str)} chars",
                    f"  Resulting total:       {new_path_len} chars",
                    f"  Windows-safe limit:    {PATH_SAFE_LIMIT} chars (legacy 2047 buffer)",
                    f"  Total entries:         {len(existing_entries)}",
                    f"  Duplicate entries:     {len(duplicate_pairs)}",
                    f"  Dead entries:          {len(dead_entries)} (point to non-existent dirs)",
                    "",
                    "Skipping HKLM PATH update to avoid the 'PATH env variable",
                    "too big' Windows dialog. re-unpacker still finds its own",
                    f"installed tools at {install_dir_str}",
                    "via Pass 0 of the well-known directory lookup, so",
                    "re-unpacker continues to work. External shells will not",
                    "see those tools on PATH until system PATH is cleaned up.",
                ]
                if duplicate_pairs:
                    msg_lines.append("")
                    msg_lines.append("Duplicate entries (same dir, multiple times):")
                    for first, second in duplicate_pairs[:10]:
                        msg_lines.append(f"  - {first}")
                        msg_lines.append(f"      duplicate: {second}")
                    if len(duplicate_pairs) > 10:
                        msg_lines.append(f"  ... and {len(duplicate_pairs) - 10} more")
                if dead_entries:
                    msg_lines.append("")
                    msg_lines.append("Dead entries (point to non-existent directories):")
                    for entry in dead_entries[:10]:
                        msg_lines.append(f"  - {entry}")
                    if len(dead_entries) > 10:
                        msg_lines.append(f"  ... and {len(dead_entries) - 10} more")
                if savings > 0:
                    msg_lines.append("")
                    msg_lines.append(
                        f"Removing duplicates and dead entries would save "
                        f"{savings} chars (PATH would shrink from "
                        f"{len(current_value)} to {cleaned_len} chars)."
                    )
                msg_lines.append("")
                msg_lines.append("To clean up:")
                msg_lines.append("  1. Open System Properties > Environment Variables")
                msg_lines.append("     (run 'SystemPropertiesAdvanced' from a shell, or")
                msg_lines.append("      open Settings > System > About > Advanced > Environment Variables).")
                msg_lines.append("  2. Edit the system PATH variable.")
                msg_lines.append("  3. Remove duplicate and dead entries listed above.")
                msg_lines.append("  4. Re-run 're-unpacker --install --yes' afterward.")
                msg_lines.append("=" * 72)

                for line in msg_lines:
                    print(line)
                    logger.warning(line)
                return False

            # Safe to append.
            new_value = current_value
            if new_value and not new_value.endswith(";"):
                new_value += ";"
            new_value += install_dir_str
            winreg.SetValueEx(key, "Path", 0, value_type, new_value)
            logger.info(
                "Added to system PATH: %s (PATH length now %d chars)",
                install_dir_str, new_path_len,
            )
            return True
    except OSError as e:
        logger.error("Failed to update system PATH: %s", e)
        return False


# =============================================================================
# Per-tool install handlers
# =============================================================================
#
# Each handler:
# - takes (logger) and returns ManualInstallResult
# - downloads or pip-installs the upstream binary
# - copies the binary into _INSTALL_DIR
# - returns succeeded / failed / skipped contract
#
# Failures (network, extraction, missing asset) are caught and converted to
# status='failed' with actionable message. Tools whose upstream doesn't
# publish Windows binaries return status='skipped'.

def _handler_pip_install(
    pip_package: str,
    tool_name: str,
    *,
    logger: logging.Logger,
) -> ManualInstallResult:
    """Generic pip-install handler.

    Used for binwalk (PyPI publishes a working Windows package). After pip
    install, the entry-point script lands in the active Python's Scripts
    directory which is typically already on PATH.
    """
    try:
        cmd = [sys.executable, "-m", "pip", "install", "--upgrade", pip_package]
        logger.info("Running: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if result.returncode != 0:
            return ManualInstallResult(
                tool=tool_name,
                status="failed",
                message=(
                    f"pip install failed (rc={result.returncode}). "
                    f"stderr tail: {result.stderr.strip().splitlines()[-1] if result.stderr else 'no output'}. "
                    f"Run manually: {' '.join(cmd)}"
                ),
            )
        return ManualInstallResult(
            tool=tool_name,
            status="succeeded",
            message=f"pip install {pip_package} OK",
        )
    except subprocess.TimeoutExpired:
        return ManualInstallResult(
            tool=tool_name,
            status="failed",
            message=f"pip install {pip_package} timed out (300s). Check network.",
        )
    except (OSError, FileNotFoundError) as e:
        return ManualInstallResult(
            tool=tool_name,
            status="failed",
            message=f"pip install failed at process launch: {e}",
        )


def _handler_github_release_zip(
    *,
    repo: str,
    asset_name_hint: str,
    expected_binaries: list[str],
    tool_names: list[str],
    logger: logging.Logger,
) -> list[ManualInstallResult]:
    """Generic GitHub-release-ZIP handler.

    Fetches the latest release JSON for ``repo``, finds the asset whose name
    contains ``asset_name_hint`` (case-insensitive substring match), downloads
    the zip, extracts to a temp dir, copies any of ``expected_binaries`` it
    finds into the install dir, and returns one result per name in
    ``tool_names``.

    A single ZIP often provides multiple tools (libewf zip provides ewfinfo +
    ewfexport + 5 others); this handler is invoked once per tool name but
    detects when the binary is already extracted from a prior call within the
    same batch and short-circuits the download.
    """
    results: list[ManualInstallResult] = []

    # 1) Fetch release metadata
    try:
        api_url = _GITHUB_LATEST_RELEASE_URL.format(repo=repo)
        release_data = _http_get_json(api_url, logger=logger)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError) as e:
        msg = (
            f"GitHub API fetch failed for {repo}: {e}. "
            f"You can manually download from https://github.com/{repo}/releases/latest"
        )
        for tn in tool_names:
            results.append(ManualInstallResult(tool=tn, status="failed", message=msg))
        return results

    if not isinstance(release_data, dict):
        for tn in tool_names:
            results.append(ManualInstallResult(
                tool=tn, status="failed",
                message=f"unexpected GitHub API response shape for {repo}",
            ))
        return results

    assets = release_data.get("assets") or []
    matching_asset = None
    for a in assets:
        name = a.get("name", "")
        if asset_name_hint.lower() in name.lower():
            matching_asset = a
            break

    if matching_asset is None:
        msg = (
            f"No release asset matching '{asset_name_hint}' on latest release "
            f"of {repo}. The project may not publish Windows binaries; check "
            f"https://github.com/{repo}/releases/latest manually."
        )
        for tn in tool_names:
            results.append(ManualInstallResult(tool=tn, status="failed", message=msg))
        return results

    asset_url = matching_asset.get("browser_download_url")
    asset_name = matching_asset.get("name", "release.zip")
    if not asset_url:
        for tn in tool_names:
            results.append(ManualInstallResult(
                tool=tn, status="failed",
                message=f"asset on {repo} has no download URL",
            ))
        return results

    # 2) Download + extract
    install_dir = _ensure_install_dir(logger=logger)
    with tempfile.TemporaryDirectory(prefix="reunpacker-install-") as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        zip_path = tmpdir / asset_name
        try:
            _http_download(asset_url, zip_path, logger=logger)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as e:
            msg = (
                f"Download failed for {repo} asset {asset_name}: {e}. "
                f"You can manually download from {asset_url}"
            )
            for tn in tool_names:
                results.append(ManualInstallResult(tool=tn, status="failed", message=msg))
            return results

        try:
            extract_dir = tmpdir / "extracted"
            _extract_zip(zip_path, extract_dir, logger=logger)
        except (zipfile.BadZipFile, OSError) as e:
            msg = f"ZIP extract failed for {asset_name}: {e}"
            for tn in tool_names:
                results.append(ManualInstallResult(tool=tn, status="failed", message=msg))
            return results

        # 3) Find each expected binary and copy to install dir
        found_binaries = _find_executables(extract_dir, names=expected_binaries)
        copied_artifacts: dict[str, Path] = {}  # binary stem -> final install path
        for binary_path in found_binaries:
            target = install_dir / binary_path.name
            try:
                shutil.copy2(binary_path, target)
                copied_artifacts[binary_path.stem.lower()] = target
                logger.debug("Installed: %s -> %s", binary_path.name, target)
            except OSError as e:
                logger.warning("Copy failed for %s: %s", binary_path.name, e)

        # Also copy any DLL files alongside the binaries (libyal pattern: each
        # libxxx-X.Y.Z.dll alongside libxxxinfo.exe is required at runtime)
        for dll_path in extract_dir.rglob("*.dll"):
            if not dll_path.is_file():
                continue
            target = install_dir / dll_path.name
            try:
                shutil.copy2(dll_path, target)
                logger.debug("Installed DLL: %s -> %s", dll_path.name, target)
            except OSError:
                # DLL copy is best-effort; don't fail the whole tool if a DLL is locked
                pass

    # 4) Build results per requested tool name
    for tn in tool_names:
        if tn.lower() in copied_artifacts:
            results.append(ManualInstallResult(
                tool=tn,
                status="succeeded",
                message=f"installed from {repo}: {copied_artifacts[tn.lower()]}",
                artifacts=[copied_artifacts[tn.lower()]],
            ))
        else:
            results.append(ManualInstallResult(
                tool=tn,
                status="failed",
                message=(
                    f"Asset {asset_name} from {repo} did not contain {tn}.exe. "
                    f"Asset contents: {[p.name for p in found_binaries[:8]]}"
                ),
            ))
    return results


def _handler_no_upstream_binaries(
    tool_name: str,
    upstream_repo: str,
    *,
    logger: logging.Logger,
) -> ManualInstallResult:
    """Skipped-handler for tools whose upstream doesn't publish Windows binaries.

    Used for the libyal toolset members beyond libewf (libvmdk, libvhdi,
    libqcow, libfsapfs, libfsntfs, libfsext, libfsfat, libfshfs, libfsxfs,
    libvshadow, libvslvm, libluksde, libsmraw, libphdi). Returns a clear
    'skipped' result so the user sees the upstream-unavailability rather
    than a confusing 404 download failure.
    """
    return ManualInstallResult(
        tool=tool_name,
        status="skipped",
        message=(
            f"upstream ({upstream_repo}) publishes source-only releases; "
            f"no pre-built Windows binaries available. Build from source "
            f"(requires Visual Studio C++, Python, autotools) or skip this tool."
        ),
    )


def _handler_libewf_via_alpine_sec(
    tool_names: list[str],
    *,
    logger: logging.Logger,
) -> list[ManualInstallResult]:
    """libewf binaries via the alpine-sec/ewf-tools third-party Windows mirror.

    alpine-sec/ewf-tools publishes pre-compiled libewf Windows binaries
    (ewfinfo, ewfexport, ewfacquire, ewfacquirestream, ewfverify, ewfmount,
    ewfdebug, ewfrecover). The mirror is a community-maintained build of
    libyal/libewf source. Trust requires accepting that supply chain.
    """
    return _handler_github_release_zip(
        repo="alpine-sec/ewf-tools",
        asset_name_hint="x64",
        expected_binaries=[
            "ewfinfo", "ewfexport", "ewfacquire", "ewfacquirestream",
            "ewfverify", "ewfmount", "ewfdebug", "ewfrecover",
        ],
        tool_names=tool_names,
        logger=logger,
    )


# =============================================================================
# Tool -> handler registry
# =============================================================================
#
# Maps a tool name (must match an entry in TOOL_PACKAGE_HINTS_WINDOWS) to the
# handler function that installs it. Tools NOT in this dict have no auto-install
# handler -- they're either built-in (skipped earlier in --install) or genuinely
# Manual install only.
#
# IMPLEMENTED: tools below have working handlers
# DEFERRED: tools listed in _DEFERRED_NO_UPSTREAM never had upstream Windows
# binaries published; they're explicitly skipped with a clear
# message rather than failed silently
# OUT-OF-SCOPE: signtool (user has SDK), apksigner / apktool / aapt2 (Android)


# Tools whose upstream simply doesn't publish Windows binaries.
# Mapped to (upstream_repo) for the diagnostic message.
_DEFERRED_NO_UPSTREAM: dict[str, str] = {
    # libyal toolset beyond libewf
    "vmdkinfo":       "libyal/libvmdk",
    "vmdkexport":     "libyal/libvmdk",
    "vhdiinfo":       "libyal/libvhdi",
    "vhdiexport":     "libyal/libvhdi",
    "qcowinfo":       "libyal/libqcow",
    "qcowexport":     "libyal/libqcow",
    "fsapfsinfo":     "libyal/libfsapfs",
    "fsapfsexport":   "libyal/libfsapfs",
    "fsntfsinfo":     "libyal/libfsntfs",
    "fsntfsexport":   "libyal/libfsntfs",
    "fsextinfo":      "libyal/libfsext",
    "fsextexport":    "libyal/libfsext",
    "fsfatinfo":      "libyal/libfsfat",
    "fsfatexport":    "libyal/libfsfat",
    "fshfsinfo":      "libyal/libfshfs",
    "fshfsexport":    "libyal/libfshfs",
    "fsxfsinfo":      "libyal/libfsxfs",
    "fsxfsexport":    "libyal/libfsxfs",
    "vshadowinfo":    "libyal/libvshadow",
    "vshadowexport":  "libyal/libvshadow",
    "vslvminfo":      "libyal/libvslvm",
    "vslvmexport":    "libyal/libvslvm",
    "luksdeinfo":     "libyal/libluksde",
    "smrawinfo":      "libyal/libsmraw",
    "smrawverify":    "libyal/libsmraw",
    "phdiinfo":       "libyal/libphdi",
    "phdiexport":     "libyal/libphdi",
    # ent: no canonical Windows distribution; J. Walker's site (fourmilab.ch)
    # publishes source only.
    "ent":            "fourmilab.ch (source only)",
}


# Tools the user explicitly excluded (Q3 answer): signtool + Android tools.
_OUT_OF_SCOPE: dict[str, str] = {
    "signtool":  "Windows SDK (user has SDK installed; out-of-scope)",
    "apksigner": "Android SDK (out-of-scope)",
    "apktool":   "Android SDK (out-of-scope)",
}


def _dispatch_handler(
    tool_name: str,
    *,
    logger: logging.Logger,
) -> list[ManualInstallResult]:
    """Dispatch ``tool_name`` to the appropriate handler.

    Returns a list (handlers that install multiple tools from one ZIP return
    multiple results; single-tool handlers return a list of one).
    """
    name_l = tool_name.lower()

    # Out-of-scope per user direction
    if name_l in _OUT_OF_SCOPE:
        return [ManualInstallResult(
            tool=tool_name,
            status="skipped",
            message=_OUT_OF_SCOPE[name_l],
        )]

    # Upstream doesn't publish Windows binaries
    if name_l in _DEFERRED_NO_UPSTREAM:
        return [_handler_no_upstream_binaries(
            tool_name, _DEFERRED_NO_UPSTREAM[name_l], logger=logger,
        )]

    # libewf family via alpine-sec mirror
    if name_l in ("ewfinfo", "ewfexport"):
        # (efficiency fix): pass BOTH ewfinfo and ewfexport in one call.
        # The alpine-sec/ewf-tools zip contains both binaries (plus 5 more);
        # downloading and extracting it twice (once per tool dispatched) was
        # 14MB of redundant transfer per the field log. Returning
        # results for both tools at once means the dispatcher's
        # `already_handled` set blocks the second download.
        return _handler_libewf_via_alpine_sec(
            ["ewfinfo", "ewfexport"], logger=logger,
        )

    # binwalk via pip
    if name_l == "binwalk":
        return [_handler_pip_install("binwalk", tool_name, logger=logger)]

    # upx via GitHub release
    if name_l == "upx":
        return _handler_github_release_zip(
            repo="upx/upx",
            asset_name_hint="win64",
            expected_binaries=["upx"],
            tool_names=[tool_name],
            logger=logger,
        )

    # ssdeep -- ssdeep-project no longer publishes Windows binaries reliably;
    # use pip's ssdeep package as fallback (provides Python bindings; the
    # `ssdeep` CLI may not result, so this is best-effort).
    if name_l == "ssdeep":
        return [_handler_pip_install("ssdeep", tool_name, logger=logger)]

    # osslsigncode via mtrojnar/osslsigncode releases
    if name_l == "osslsigncode":
        return _handler_github_release_zip(
            repo="mtrojnar/osslsigncode",
            asset_name_hint="windows",
            expected_binaries=["osslsigncode"],
            tool_names=[tool_name],
            logger=logger,
        )

    # innoextract via dscharrer/innoextract releases
    if name_l == "innoextract":
        return _handler_github_release_zip(
            repo="dscharrer/innoextract",
            asset_name_hint="windows",
            expected_binaries=["innoextract"],
            tool_names=[tool_name],
            logger=logger,
        )

    # qemu-img: QEMU project Windows builds at https://qemu.weilnetz.de/
    # Not a GitHub release; would need a separate handler. Skip with clear
    # diagnostic for now.
    if name_l == "qemu-img":
        return [ManualInstallResult(
            tool=tool_name,
            status="skipped",
            message=(
                "QEMU Windows builds are at https://qemu.weilnetz.de/w64/ "
                "(not a GitHub release; requires custom installer handler "
                "not yet implemented). Download qemu-w64-setup-X.Y.Z.exe "
                "and run silently with /S, then add the install dir to PATH."
            ),
        )]

    # plistutil via libimobiledevice-win32/imobiledevice-net releases.
    # asset_name_hint MUST be 'win-x64' not 'x64'.
    # The libimobiledevice-win32 project publishes multi-platform release
    # assets including OSX (osx-x64) and Linux variants; using 'x64' alone
    # substring-matches 'osx-x64' first and downloads a Mach-O archive that
    # has no Windows binaries.
    if name_l == "plistutil":
        return _handler_github_release_zip(
            repo="libimobiledevice-win32/imobiledevice-net",
            asset_name_hint="win-x64",
            expected_binaries=["plistutil"],
            tool_names=[tool_name],
            logger=logger,
        )

    # pdfdetach via oschwartz10612/poppler-windows
    if name_l == "pdfdetach":
        return _handler_github_release_zip(
            repo="oschwartz10612/poppler-windows",
            asset_name_hint="Release-",
            expected_binaries=["pdfdetach"],
            tool_names=[tool_name],
            logger=logger,
        )

    # file: from Git for Windows (file.exe is shipped under usr/bin/file.exe).
    # If git isn't installed via winget, suggest install.
    if name_l == "file":
        return [ManualInstallResult(
            tool=tool_name,
            status="skipped",
            message=(
                "file.exe ships with Git for Windows (Git.Git winget package). "
                "Install via 'winget install Git.Git' to get C:\\Program Files\\"
                "Git\\usr\\bin\\file.exe; this is not yet auto-installed by "
                "re-unpacker --install."
            ),
        )]

    # No handler registered
    return [ManualInstallResult(
        tool=tool_name,
        status="skipped",
        message="no auto-install handler registered for this tool",
    )]


# =============================================================================
# Top-level entry point
# =============================================================================

def install_missing_tools_windows(
    tool_names,
    *,
    logger: logging.Logger,
) -> ManualInstallSummary:
    """Run manual-install handlers for each name in ``tool_names``.

    Per Q4 (graceful failure): each handler is invoked in its own try/except;
    failures are recorded but don't abort the batch. Returns a summary with
    succeeded / failed / skipped lists.

    Caller (cli.py _run_install) is expected to:
      1. Have already run the winget batch
      2. Re-probe the tool registry to identify what's STILL missing
      3. Pass those still-missing tool names to this function
      4. Print summary.format_human() and exit non-zero if summary.any_failed

    Pre-conditions:
      - is_windows() returns True
      - is_admin() returns True (writes to Program Files)
    """
    summary = ManualInstallSummary()

    if not is_windows():
        logger.warning(
            "install_missing_tools_windows called on non-Windows; no-op"
        )
        return summary

    if not is_admin():
        logger.error(
            "install_missing_tools_windows requires admin (writes to "
            "Program Files). Aborting manual-install batch."
        )
        for tn in tool_names:
            summary.failed.append(ManualInstallResult(
                tool=tn,
                status="failed",
                message="admin elevation required for manual install batch",
            ))
        return summary

    # Set up install dir + PATH update once at start
    try:
        _ensure_install_dir(logger=logger)
        _add_install_dir_to_system_path(logger=logger)
    except Exception as e:
        logger.error(
            "Failed to set up install dir / PATH: %s. "
            "Aborting manual-install batch.", e,
        )
        for tn in tool_names:
            summary.failed.append(ManualInstallResult(
                tool=tn,
                status="failed",
                message=f"install dir setup failed: {e}",
            ))
        return summary

    # Track which tools we've already handled (some handlers cover multiple
    # tools from a single download; e.g. libewf zip covers both ewfinfo and
    # ewfexport, so processing 'ewfinfo' also installs 'ewfexport').
    already_handled: set[str] = set()

    for tool_name in tool_names:
        if tool_name.lower() in already_handled:
            logger.debug("Skipping %s (already handled by family-aware handler)", tool_name)
            continue

        logger.info("--- Manual install: %s ---", tool_name)
        try:
            results = _dispatch_handler(tool_name, logger=logger)
        except Exception as e:
            # Handler crashed unexpectedly. Log + continue.
            logger.exception("Handler crashed for %s: %s", tool_name, e)
            results = [ManualInstallResult(
                tool=tool_name,
                status="failed",
                message=f"handler crashed: {type(e).__name__}: {e}",
            )]

        for r in results:
            already_handled.add(r.tool.lower())
            # log per-tool result so the
            # log file alone tells the full story. Status determines log
            # level: succeeded -> info, failed -> warning, skipped -> debug.
            if r.status == "succeeded":
                logger.info("  [OK]  %s: %s", r.tool, r.message)
                summary.succeeded.append(r)
            elif r.status == "failed":
                logger.warning("  [FAIL] %s: %s", r.tool, r.message)
                summary.failed.append(r)
            else:
                logger.debug("  [SKIP] %s: %s", r.tool, r.message)
                summary.skipped.append(r)

    # Final PATH refresh: makes the new binaries visible to subsequent
    # which_tool() calls within this same Python process
    from .platform_compat import refresh_path_from_registry
    refresh_path_from_registry()

    # also log the summary so the log file is self-contained for
    # remote diagnosis. The print() in cli.py covers the console; this
    # covers the file.
    logger.info(
        "Manual install batch complete: %d succeeded, %d failed, %d skipped",
        len(summary.succeeded),
        len(summary.failed),
        len(summary.skipped),
    )
    for line in summary.format_human().split("\n"):
        logger.info(line)

    return summary
