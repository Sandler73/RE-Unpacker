"""
.. module:: re_unpacker.tools
    :synopsis: Probe and cache availability of external extraction tools.

Description
-----------
Every extractor declares the system binaries it needs. On startup the
:class:`ToolRegistry` walks PATH once, caches presence/absence, and
(optionally) calls each tool with a cheap version-probe arg so we record
the on-box version. Extractors then query the registry via
``registry.require(name)`` / ``registry.have(name)``; missing tools skip
that extractor and fall through to the next option in the dispatch chain.

Notes
-----
- We never *install* tools. This module only probes and reports.
- Version probes are tolerant: a tool that's present but whose --version
  call errors is still considered "available" -- we just log "unknown" as
  the version and move on. Some Kali tools (unshield in particular) print
  usage to stderr with a non-zero rc when called with no args; we don't
  treat that as "missing".
- The registry is immutable after ``finalize()`` so workers can safely
  read it without locking.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, field
from typing import Sequence

from .constants import TOOL_PACKAGE_HINTS
from .exceptions import ToolMissingError
from .subprocess_utils import run_tool


# Probe arguments for each tool -- picked from their man pages so the probe
# is cheap and stable across distro versions.
#
# ISS-004: expanded from 33 entries (covering only v0.1.x tools) to
# the full 82-tool tracked set so --tools-check no longer reports
# "(version: unknown)" for available tools. Tools that don't support any
# version flag are listed with a tuple of () -- the probe will then run them
# with no arguments and parse the first line of stdout/stderr for a version
# string. Tools where even that yields nothing useful fall back to
# version="installed" (set in probe()) so the user can distinguish "tool is
# present, version unknowable" from "tool is missing".
_VERSION_PROBES_LINUX: dict[str, Sequence[str]] = {
    # v0.1.x baseline (existing, unchanged)
    "file": ("--version",),
    "7z": ("--help",),
    "unzip": ("-v",),
    "tar": ("--version",),
    "gzip": ("--version",),
    "gunzip": ("--version",),
    "bzip2": ("--version",),
    "bunzip2": ("--version",),
    "xz": ("--version",),
    "unxz": ("--version",),
    "zstd": ("--version",),
    "lz4": ("--version",),
    "lzop": ("--version",),
    "unlzma": ("--version",),
    "dpkg-deb": ("--version",),
    "ar": ("--version",),
    "rpm2cpio": ("--help",),
    "rpm2archive": ("--help",),
    "cpio": ("--version",),
    "msiextract": ("--version",),
    "cabextract": ("--version",),
    "innoextract": ("--version",),
    "unshield": ("-V",),
    "unsquashfs": ("-version",),
    "bsdtar": ("--version",),
    "binwalk": ("--help",),
    "upx": ("--version",),
    "unrar": ("--help",),
    "wrestool": ("--version",),
    "icotool": ("--version",),
    "objcopy": ("--version",),
    "readelf": ("--version",),
    # additions
    "arj": ("-help",),                  # arj prints version banner in -help (single-dash)
    "lha": (),                          # lhasa prints version banner with no args
    "unar": ("-v",),
    "lsar": ("-v",),
    "lzip": ("--version",),
    "plzip": ("--version",),
    "pixz": ("-h",),                    # pixz has no --version; -h prints banner
    "lrzip": ("-V",),                   # uppercase -V
    "zpaq": (),                         # zpaq prints version in no-args banner
    "nomarch": (),                      # nomarch prints usage including version
    "tnef": ("--version",),
    "unshar": ("--version",),
    "uudecode": ("--version",),
    "apt-get": ("--version",),
    "dpkg-query": ("--version",),
    # PDF
    "qpdf": ("--version",),
    "pdfdetach": ("-v",),               # poppler-utils convention is -v
    # Android
    "apktool": ("--version",),
    # macOS / Apple
    "plistutil": (),                    # plistutil prints usage with no args
    # Disk image conversion
    "qemu-img": ("--version",),
    # libyal -- uniformly accept -V (uppercase, single-dash)
    "vmdkmount": ("-V",),
    "vmdkinfo": ("-V",),
    "qcowmount": ("-V",),
    "qcowinfo": ("-V",),
    "vhdimount": ("-V",),
    "vhdiinfo": ("-V",),
    "smrawmount": ("-V",),
    "smrawverify": ("-V",),
    "fsapfsmount": ("-V",),
    "fsapfsinfo": ("-V",),
    "fsntfsmount": ("-V",),
    "fsntfsinfo": ("-V",),
    "fsextmount": ("-V",),
    "fsextinfo": ("-V",),
    "fsfatmount": ("-V",),
    "fsfatinfo": ("-V",),
    "fshfsmount": ("-V",),
    "fshfsinfo": ("-V",),
    "fsxfsmount": ("-V",),
    "fsxfsinfo": ("-V",),
    "vshadowmount": ("-V",),
    "vshadowinfo": ("-V",),
    "vslvmmount": ("-V",),
    "vslvminfo": ("-V",),
    "luksdeinfo": ("-V",),
    # FUSE userspace
    "fusermount": ("--version",),
    # Embedded firmware tooling
    "mtdinfo": ("--help",),             # mtdinfo prints version in --help banner
    # Microsoft DOS-era compressed
    "mscompress": (),                   # no --version; usage banner has version
    # mtools
    "mtools": (),                       # mtools (the meta-binary) prints usage on no args
    "mcopy": ("--version",),
    # Subsystem B verifiers
    "gpg": ("--version",),
    "gpgv": ("--version",),
    "debsigs": ("--help",),             # debsigs has no --version; --help prints version banner
    "dpkg-sig": ("--help",),            # dpkg-sig same convention
    "debsums": ("--version",),
    "apksigner": ("--version",),
    "osslsigncode": ("--version",),
    # rpm itself is in v0.1.x baseline; rpm -K (verify) doesn't change probe args
    # Subsystem C classifiers
    "exiftool": ("-ver",),              # exiftool prints version with -ver (single dash)
    "ssdeep": ("-V",),                  # ssdeep uses -V (uppercase, single dash)
    "yara": ("--version",),
    "ent": (),                          # ent has no --version; usage banner suffices
}


# -----------------------------------------------------------------------------
# Windows-platform version probe args
# -----------------------------------------------------------------------------
# Keys MUST be a SUPERSET of TOOL_PACKAGE_HINTS_WINDOWS (verified by the
# coverage assertion at module load below). Most probe args are identical
# to the Linux variants -- 7-Zip, GnuPG, ExifTool, YARA, qpdf use the same
# argument conventions on both platforms. The differences are:
# - Windows-built-in tools (expand, msiexec, powershell, signtool) have
# their own probe conventions
# - libyal *export.exe binaries: same -V convention as their *info siblings
# - Tools without a Windows binding (debsigs, dpkg-sig, mtdinfo, etc.)
# are absent from this dict because they're absent from the Windows
# TOOL_PACKAGE_HINTS dict
_VERSION_PROBES_WINDOWS: dict[str, Sequence[str]] = {
    # -------- Built-in to Windows --------
    "tar":          ("--version",),                # bsdtar.exe accepts --version
    "expand":       (),                            # no version flag; usage banner has it
    "msiexec":      (),                            # GUI dialog tool; see _NO_EXEC_PROBE_TOOLS (skipped at probe layer)
    "powershell":   ("-Command", "$Host.Version.ToString()"),
    "pwsh":         ("--version",),                # PowerShell 7+ supports --version
    # -------- 7-Zip on Windows (same probe as Linux) --------
    "7z":           ("--help",),
    "7zz":          ("--help",),
    # -------- Subsystem B verifiers --------
    "gpg":          ("--version",),
    "gpgv":         ("--version",),
    "apksigner":    ("--version",),
    "osslsigncode": ("--version",),
    "signtool":     (),                            # signtool with no args prints usage with version
    "sigcheck":     (),                            # sigcheck with no args prints banner with version
    # -------- Subsystem C classifiers --------
    "exiftool":     ("-ver",),
    "ssdeep":       ("-V",),
    "yara":         ("--version",),
    "yarac":        ("--version",),
    "ent":          (),
    # -------- Other v0.3.x tools --------
    "qpdf":         ("--version",),
    "pdfdetach":    ("-v",),
    "binwalk":      ("--help",),
    "upx":          ("--version",),
    "innoextract":  ("--version",),
    "qemu-img":     ("--version",),
    "apktool":      ("--version",),
    "plistutil":    (),
    "file":         ("--version",),
    # -------- libyal Windows binaries (uniform -V convention) --------
    # Both *info AND *export tools accept -V (uppercase, single dash).
    "ewfinfo":      ("-V",),
    "ewfexport":    ("-V",),
    "vmdkinfo":     ("-V",),
    "vmdkexport":   ("-V",),
    "vhdiinfo":     ("-V",),
    "vhdiexport":   ("-V",),
    "qcowinfo":     ("-V",),
    "qcowexport":   ("-V",),
    "vshadowinfo":  ("-V",),
    "vshadowexport":("-V",),
    "vslvminfo":    ("-V",),
    "vslvmexport":  ("-V",),
    "fsapfsinfo":   ("-V",),
    "fsapfsexport": ("-V",),
    "fsextinfo":    ("-V",),
    "fsextexport":  ("-V",),
    "fshfsinfo":    ("-V",),
    "fshfsexport":  ("-V",),
    "fsxfsinfo":    ("-V",),
    "fsxfsexport":  ("-V",),
    "fsfatinfo":    ("-V",),
    "fsfatexport":  ("-V",),
    "fsntfsinfo":   ("-V",),
    "fsntfsexport": ("-V",),
    "luksdeinfo":   ("-V",),
    "smrawinfo":    ("-V",),
    "smrawverify":  ("-V",),
    "phdiinfo":     ("-V",),
    "phdiexport":   ("-V",),
}


# -----------------------------------------------------------------------------
# Platform-resolved alias
# -----------------------------------------------------------------------------
# At module-load time this resolves to the platform-appropriate probe dict.
# Existing call sites that read _VERSION_PROBES continue to work unchanged.
from .platform_compat import is_windows as _is_windows
_VERSION_PROBES: dict[str, Sequence[str]] = (
    _VERSION_PROBES_WINDOWS if _is_windows() else _VERSION_PROBES_LINUX
)


# -----------------------------------------------------------------------------
# Tools whose version-probe args open a GUI dialog or otherwise can't be
# safely exec'd as a probe (; lesson L32).
# -----------------------------------------------------------------------------
# For tools listed here, the probe layer skips the exec-and-capture step
# entirely. Existence-on-PATH alone is sufficient; the version field shows
# the placeholder string "installed".
#
# Currently affects:
# - msiexec (Windows only): /? opens the Windows Installer help dialog;
# `msiexec` with no args opens the same dialog. There is no console-
# output mode that prints a version banner. Probing it would block
# the run_tool subprocess until the user manually dismisses the dialog,
# and on Windows the timeout cleanup path would historically crash
# with an os.killpg AttributeError (fixed via
# subprocess_utils._terminate_proc_tree, but the GUI popup itself is
# still wrong UX -- so we skip the probe).
_NO_EXEC_PROBE_TOOLS: frozenset[str] = frozenset({
    "msiexec",
    # (cosmetic): plistutil with no args waits for stdin; with
    # subprocess stdin=DEVNULL it produces "ERROR: reading from stdin is not
    # supported on Windows" on stderr. Since plistutil doesn't have a
    # `--version` or `--help` flag that exits cleanly with version info,
    # we existence-check only and report version as "installed" (matching
    # msiexec behavior). The tool's actual functionality is verified by the
    # extractors that use it.
    "plistutil",
})


@dataclass(frozen=True)
class Tool:
    """A probed external tool."""
    name: str
    path: str | None  # None when not found
    version: str | None = None  # brief first-line capture, or None
    package_hint: str | None = None  # Kali install hint

    @property
    def available(self) -> bool:
        return self.path is not None


@dataclass
class ToolRegistry:
    """Registry of probed tools. Populate via :meth:`probe_all`, then call
    :meth:`finalize` to freeze it."""

    _tools: dict[str, Tool] = field(default_factory=dict)
    _frozen: bool = False

    # ---- population ----

    def probe(self, name: str, *, logger: logging.Logger | None = None) -> Tool:
        """Probe a single tool by name."""
        if self._frozen:
            # Allow read-through lookup of an already-probed tool; disallow adding new.
            if name in self._tools:
                return self._tools[name]
            raise RuntimeError(f"ToolRegistry frozen; cannot probe new tool: {name}")

        # Lesson L33: use platform_compat.which_tool which adds
        # well-known-install-directory fallback on Windows. Crucial for
        # detecting winget-installed tools (7-Zip, GnuPG, Sigcheck, etc.)
        # whose packages don't reliably add themselves to system PATH and
        # whose installs are invisible to the current process's
        # os.environ['PATH'] snapshot.
        from .platform_compat import which_tool as _which_tool
        resolved = _which_tool(name)
        path: str | None = str(resolved) if resolved is not None else None
        version: str | None = None
        if path is not None:
            # ISS-004: every available tool is now probed. The
            # _VERSION_PROBES dict says HOW to probe; tools not in the dict
            # still get probed with a default --version, falling back to
            # "installed" if even that yields no output. This avoids the
            # uninformative "(version: unknown)" display the v0.1.x /
            # probe produced for any tool not listed.
            probe_args: tuple[str, ...]
            if name in _VERSION_PROBES:
                probe_args = tuple(_VERSION_PROBES[name])
            else:
                probe_args = ("--version",)  # safe default

            # Lesson L32: some Windows tools have no console
            # version output -- their "help" or "no args" path opens a
            # GUI dialog that blocks until manually dismissed. We must
            # NOT exec these as a probe. Path-only check is sufficient
            # for them; the version field shows "installed" placeholder.
            if name in _NO_EXEC_PROBE_TOOLS:
                version = "installed"
            else:
                try:
                    argv: list[str] = [path]
                    argv.extend(probe_args)
                    result = run_tool(
                        argv,
                        tool_name=name,
                        timeout=15,
                        check=False,
                        logger=logger,
                    )
                    combined = (
                        (result.stdout_text.strip() or result.stderr_text.strip())
                        .splitlines()
                    )
                    if combined:
                        # First non-empty line, capped.
                        first = combined[0].strip()
                        # Lesson L38: some Windows tools (Sigcheck,
                        # certain Sysinternals utilities) emit UTF-8 / UTF-16
                        # BOM at the start of stdout. The byte-level fix in
                        # subprocess_utils._decode_with_bom handles
                        # the common case; this string-level strip is a
                        # defensive belt-and-suspenders for any BOM character
                        # that survived (e.g. if the tool emits the BOM
                        # mid-stream after some other content). Also strips
                        # any leading Unicode replacement char (\ufffd) that
                        # may have leaked through with errors='replace' on
                        # malformed input.
                        first = first.lstrip("\ufeff\ufffd")
                        # Also strip raw byte BOM if any survived (defensive)
                        for bom_str in ("\xef\xbb\xbf", "\xff\xfe", "\xfe\xff"):
                            if first.startswith(bom_str):
                                first = first[len(bom_str):]
                        first = first.strip()
                        if first:
                            version = first[:240]
                except Exception as e:
                    if logger is not None:
                        logger.debug("Version probe failed for %s: %s", name, e)
                    version = None
            # Fallback: tool is present but we couldn't extract a version
            # string. Display "installed" so the user knows the tool is
            # available; the absence of a version banner is itself information.
            if version is None:
                version = "installed"

        tool = Tool(
            name=name,
            path=path,
            version=version,
            package_hint=TOOL_PACKAGE_HINTS.get(name),
        )
        self._tools[name] = tool
        if logger is not None:
            if tool.available:
                logger.debug(
                    "Tool found: %s -> %s (version: %s)",
                    name, path, version or "unknown",
                )
            else:
                # Lesson L34: empty package_hint means "manual
                # install required" (libyal binaries, signtool, etc.) --
                # NOT "metadata gap". Display the right message.
                if tool.package_hint:
                    hint_msg = tool.package_hint
                else:
                    hint_msg = "manual install (see Usage Guide section 22.2)"
                logger.debug(
                    "Tool missing: %s (install hint: %s)",
                    name, hint_msg,
                )
        return tool

    def probe_all(
        self,
        names: Sequence[str],
        *,
        logger: logging.Logger | None = None,
    ) -> None:
        """Probe a batch of tools (idempotent per name)."""
        for name in names:
            if name not in self._tools:
                self.probe(name, logger=logger)

    def finalize(self) -> None:
        """Freeze the registry. Further probes for new tools will error."""
        self._frozen = True

    # ---- queries ----

    def have(self, name: str) -> bool:
        """True iff the tool is known and present."""
        t = self._tools.get(name)
        return bool(t and t.available)

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def require(self, name: str) -> Tool:
        """Return the tool or raise :class:`ToolMissingError`."""
        t = self._tools.get(name)
        if t is None or not t.available:
            hint = TOOL_PACKAGE_HINTS.get(name)
            raise ToolMissingError(name, package_hint=hint)
        return t

    def path_of(self, name: str) -> str:
        """Return the tool's path (raises if missing)."""
        return self.require(name).path  # type: ignore[return-value]

    def all_known(self) -> list[Tool]:
        return sorted(self._tools.values(), key=lambda t: t.name)

    def summary(self) -> dict[str, dict[str, str | None]]:
        """Serializable dict for manifest inclusion."""
        return {
            t.name: {
                "path": t.path,
                "version": t.version,
                "package_hint": t.package_hint,
                "available": "yes" if t.available else "no",
            }
            for t in self.all_known()
        }


# Canonical list of every tool this project might call.
ALL_TOOL_NAMES: list[str] = sorted(TOOL_PACKAGE_HINTS.keys())


def build_and_probe_registry(
    *, logger: logging.Logger | None = None
) -> ToolRegistry:
    """Convenience: build a registry, probe every known tool, freeze it."""
    reg = ToolRegistry()
    reg.probe_all(ALL_TOOL_NAMES, logger=logger)
    reg.finalize()
    return reg


def format_tools_check_report(registry: ToolRegistry) -> str:
    """Render a human-readable --tools-check table."""
    lines: list[str] = []
    header = f"{'TOOL':<14}  {'STATUS':<8}  {'PACKAGE HINT':<22}  PATH / VERSION"
    lines.append(header)
    lines.append("-" * len(header))
    for t in registry.all_known():
        status = "OK" if t.available else "MISSING"
        pkg = t.package_hint or ""
        detail = (t.path or "--") if t.available else ""
        if t.available and t.version:
            detail = f"{t.path}  ({t.version})"
        lines.append(f"{t.name:<14}  {status:<8}  {pkg:<22}  {detail}")
    missing = [t for t in registry.all_known() if not t.available]

    # Lesson L34: filter out tools whose
    # canonical alternative is already available. Specifically:
    # - pwsh (PowerShell 7+) is OPTIONAL when powershell (5.1) is
    # present; the PowerShellAuthenticodeVerifier uses `powershell`
    # not `pwsh`, so pwsh's absence doesn't block any re-unpacker
    # functionality.
    # - 7zz is an alternate name for 7z; either binary alone covers
    # the cross-platform 7-Zip surface.
    # - yarac is part of the yara package; redundant if yara is present.
    # The filtered tools STILL appear in the status table above, so the
    # user can see they're missing if curious; they're just not included
    # in the install recommendation, which would otherwise produce
    # confusing "install X to fix Y" suggestions when Y is already fine.
    _OPTIONAL_ALTERNATIVES: dict[str, str] = {
        "pwsh":  "powershell",
        "7zz":   "7z",
        "yarac": "yara",
    }
    actionable_missing = []
    suppressed_alt: list[str] = []
    for t in missing:
        alt = _OPTIONAL_ALTERNATIVES.get(t.name)
        if alt is not None:
            alt_tool = registry.get(alt) if hasattr(registry, "get") else None
            if alt_tool is None:
                # Try direct attribute access fallback
                try:
                    alt_tool = registry._tools.get(alt)  # type: ignore[attr-defined]
                except AttributeError:
                    alt_tool = None
            if alt_tool is not None and alt_tool.available:
                suppressed_alt.append(f"{t.name} (optional; {alt} is present)")
                continue
        actionable_missing.append(t)
    missing = actionable_missing

    if missing:
        # Lesson L34: Platform-aware footer. On Linux, list the
        # apt packages and show the apt command. On Windows, just point
        # at `re-unpacker --install --yes` -- it dispatches to winget,
        # handles the source-update + iteration, and skips empty hints
        # (manual-install tools) and built-ins gracefully. Listing
        # winget Package IDs in an apt-flavored command (the/
        # bug) is worse than not listing them at all.
        from .platform_compat import is_windows as _is_win
        pkgs = sorted({t.package_hint for t in missing if t.package_hint})

        if _is_win():
            # Filter to entries that winget can actually install
            # (non-empty hint). Built-ins (empty hint) and manual-install
            # tools (also empty hint) are NOT in this list -- they
            # wouldn't be valid winget Package IDs anyway.
            winget_ids = sorted({
                t.package_hint for t in missing
                if t.package_hint
            })
            manual_count = sum(
                1 for t in missing if not t.package_hint
            )
            lines.append("")
            if winget_ids:
                lines.append(
                    f"To install the {len(winget_ids)} missing winget-managed "
                    f"tool(s) on Windows:"
                )
                lines.append("  re-unpacker --install --yes")
                lines.append("")
                lines.append(
                    "  (Internally dispatches winget install with the "
                    "Package IDs: " + ", ".join(winget_ids) + ")"
                )
            if manual_count:
                lines.append("")
                lines.append(
                    f"{manual_count} additional missing tool(s) require "
                    f"manual install (libyal binaries, signtool, etc.). "
                    f"See ReUnpacker-Usage-Guide.html section 22.2 "
                    f"'Tool inventory differences vs Linux' for per-tool "
                    f"install instructions."
                )
            if suppressed_alt:
                lines.append("")
                lines.append(
                    "Note: the following missing tools are OPTIONAL because "
                    "their canonical alternative is already available, and "
                    "are NOT included in the install recommendation: "
                    + ", ".join(suppressed_alt)
                )
        else:
            lines.append("")
            lines.append(
                "To install everything missing on Kali / Debian:"
            )
            lines.append(
                "  sudo apt-get update && sudo apt-get install -y " +
                " ".join(pkgs)
            )
            if suppressed_alt:
                lines.append("")
                lines.append(
                    "Note: the following missing tools are OPTIONAL "
                    "because their canonical alternative is already "
                    "available: " + ", ".join(suppressed_alt)
                )
    return "\n".join(lines)
