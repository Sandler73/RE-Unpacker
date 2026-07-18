"""
.. module:: re_unpacker.extractors.disk_image
    :synopsis: VM disk image extractors (cross-platform: VMDK, QCOW2, VHD, VHDX, RAW).

Description
-----------
Three extraction strategies for VM disk images:

1. **Universal conversion path** (:class:`QemuImgExtractor`): convert any
   format to raw via ``qemu-img convert``. The raw output is then itself
   recursable -- the orchestrator's BFS will treat it as a RAW_DISK kind
   and dispatch to libyal forensic-FS extractors based on what filesystem
   the raw image contains. Works without root. Cross-platform (qemu-img
   has Windows binaries).

2. **Format-specific FUSE mount** (Linux only -- :class:`VmdkExtractor`,
   :class:`QcowExtractor`, :class:`VhdiExtractor`): use libyal's
   ``<fmt>mount`` tool to expose the disk image as a FUSE filesystem,
   then copy out the contents. Requires root for the FUSE mount. Filtered
   out on Windows because the libyal ``*mount`` tools require FUSE which
   is not available without WinFsp; the offline export path below is
   preferred on Windows.

3. **Format-specific offline export** (Windows):
   :class:`WindowsSevenZipDiskExtractor` uses 7-Zip's native disk-image
   support (the 7-Zip FileExtensions manifest lists vmdk, qcow2, vhd,
   vhdx). :class:`WindowsLibyalExportDiskExtractor` provides a fallback
   path via libyal's offline ``*export`` tools for cases where the
   user has installed libyal Windows binaries manually.

The orchestrator dispatches based on priority. On Linux: when running
as root, the libyal FUSE extractors win; otherwise qemu-img wins. On
Windows: WindowsSevenZipDiskExtractor wins (highest priority among
Windows-active extractors), with libyal export as fallback.

For RAW_DISK kind, only the libyal forensic-FS extractors apply
(no extractor "extracts" a raw image -- it gets fed to filesystem
detection on its first 4 KiB to decide what FS it contains).

Notes
-----
- ``qemu-img convert`` produces an unencumbered raw image. Encrypted
  VMDKs / encrypted QCOW2 fail the convert with a recognizable error;
  treat as encrypted-terminal.
- libyal mounters use FUSE userspace; the ``<fmt>mount`` invocation
  needs to be paired with an unmount on cleanup. We use a context
  manager pattern (``try`` / ``finally`` with ``fusermount -u``).
- The libyal mounters expose a single virtual file representing the
  full raw image (e.g. ``vmdk1`` inside the mountpoint) -- we then copy
  that out as the conversion result. We do NOT recurse into the FUSE
  mountpoint while it's live because that would re-trigger the same
  extractor on every nested file.
- libyal ``*export`` tools (Windows path) write the underlying raw image
  data to a target path: ``<tool> -t <target_basename> <source>``.

Execution parameters
--------------------
- All extractors honor ``ctx.timeout_seconds``.
- libyal FUSE extractors set ``requires_root = True``.
- Windows extractors do NOT require admin (offline tools).

Examples
--------
::

    re-unpacker malware.vmdk -o /scratch/vmdk/ # qemu-img path on non-root
    sudo re-unpacker forensic.qcow2 -o /scratch/qcow/ # libyal FUSE path on Linux
    re-unpacker.ps1 malware.vmdk -o C:/scratch/vmdk/ # 7z path on Windows

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from ..detection import FileKind
from ..exceptions import ExtractorFailure, ExtractorNotApplicable
from ..platform_compat import is_windows
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


# =============================================================================
# Universal conversion via qemu-img (cross-platform)
# =============================================================================

class QemuImgExtractor(Extractor):
    """Convert any QEMU-supported disk image to raw via ``qemu-img convert``.

    The raw output is then recursable -- the orchestrator dispatches it
    to the appropriate filesystem extractor based on first-block detection.
    Cross-platform: qemu-img has both Linux apt packaging (qemu-utils) and
    Windows binaries (qemu.org distribution).
    """

    name = "qemu-img"
    handles_kinds = frozenset({
        FileKind.VMDK, FileKind.QCOW2, FileKind.VHD, FileKind.VHDX,
    })
    required_tools = ("qemu-img",)
    # Lower priority than libyal mounters (which run direct without
    # intermediate raw conversion). When non-root, libyal mounters are
    # filtered out and this is the canonical path.
    priority = 70

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        outfile = ctx.dest_dir / (ctx.source_path.stem + ".raw")
        argv = [
            ctx.tools.path_of("qemu-img"), "convert",
            "-O", "raw",                       # output format
            str(ctx.source_path),
            str(outfile),
        ]
        run_tool(
            argv, tool_name="qemu-img",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            files_produced=1,
            notes=[
                "qemu-img produced a raw disk image; the recursion engine "
                "will dispatch it to the appropriate filesystem extractor.",
            ],
        )


# =============================================================================
# libyal FUSE-mount path (Linux only; root required)
# =============================================================================

class _LibyalFuseExtractor(Extractor):
    """Common FUSE-mount workflow shared by VMDK / QCOW / VHDI / SMRAW.

    Linux-only: the libyal ``*mount`` tools require the Linux FUSE
    kernel module and the ``fusermount`` userspace helper. On Windows,
    these tools are absent from TOOL_PACKAGE_HINTS_WINDOWS, so
    ``is_available()`` returns False automatically. The Windows path is
    handled by :class:`WindowsSevenZipDiskExtractor` and
    :class:`WindowsLibyalExportDiskExtractor` below.

    Subclasses set ``mount_tool``, ``info_tool``, and ``handles_kinds``.
    """

    requires_root = True
    priority = 90

    # Subclasses override:
    mount_tool: str = ""
    info_tool: str = ""

    def __init__(self) -> None:
        super().__init__()
        # Make required_tools track the subclass's tool names automatically.
        if self.mount_tool and self.info_tool:
            self.required_tools = (self.mount_tool, self.info_tool, "fusermount")

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        mountpoint = ctx.dest_dir / "_libyal_mount"
        mountpoint.mkdir(exist_ok=True)
        try:
            # Mount the disk image as a FUSE filesystem.
            mount_argv = [
                ctx.tools.path_of(self.mount_tool),
                "-X", "allow_other",   # Common FUSE option for cross-user reads
                str(ctx.source_path),
                str(mountpoint),
            ]
            try:
                run_tool(
                    mount_argv, tool_name=self.mount_tool,
                    timeout=ctx.timeout_seconds, check=True,
                    logger=ctx.logger, source_for_error=str(ctx.source_path),
                )
            except ExtractorFailure as e:
                # Some libyal mounters require -X to be omitted on certain
                # platforms; fall back to the bare invocation once.
                ctx.logger.debug(
                    "%s with -X allow_other failed (%s); retrying without -X",
                    self.mount_tool, e,
                )
                run_tool(
                    [ctx.tools.path_of(self.mount_tool),
                     str(ctx.source_path), str(mountpoint)],
                    tool_name=self.mount_tool,
                    timeout=ctx.timeout_seconds, check=True,
                    logger=ctx.logger, source_for_error=str(ctx.source_path),
                )

            # libyal exposes the disk as one or more virtual files inside the
            # mountpoint (typically named like vmdk1, qcow1, vhdi1 -- one per
            # extent). Copy each out to dest_dir as <name>.raw.
            files_out = 0
            try:
                entries = sorted(mountpoint.iterdir())
            except OSError as e:
                # ENOSYS = "Function not implemented" -- FUSE userspace or
                # kernel module not available even though the mount binary
                # ran successfully. NOT an extraction failure: surface as
                # not-applicable so the next extractor (typically qemu-img)
                # gets a turn.
                if e.errno == 38:  # ENOSYS
                    raise ExtractorNotApplicable(
                        f"{self.mount_tool}: FUSE not functional (errno=ENOSYS) "
                        f"for {ctx.source_path.name}",
                        context={"reason": "fuse_enosys", "source": str(ctx.source_path)},
                    ) from e
                raise
            for entry in entries:
                if not entry.is_file():
                    continue
                outfile = ctx.dest_dir / (entry.name + ".raw")
                shutil.copyfile(entry, outfile)
                files_out += 1

            if files_out == 0:
                raise ExtractorFailure(
                    extractor=self.name, source=str(ctx.source_path),
                    returncode=None,
                    stderr=(
                        f"{self.mount_tool} mounted but produced no virtual "
                        f"files in {mountpoint}"
                    ),
                )

            return ExtractionResult(
                extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
                files_produced=files_out,
                notes=[
                    f"{self.mount_tool} (libyal) FUSE-mounted the image and "
                    f"copied out {files_out} virtual extent file(s).",
                ],
            )
        finally:
            # Always unmount, even on error. Wait briefly for filesystem
            # buffers to flush before unmounting.
            time.sleep(0.2)
            try:
                subprocess.run(
                    ["fusermount", "-u", str(mountpoint)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
            except (subprocess.TimeoutExpired, OSError) as e:
                ctx.logger.warning(
                    "fusermount -u failed on %s: %s", mountpoint, e,
                )
            # Try to remove the empty mountpoint dir; ignore errors.
            try:
                mountpoint.rmdir()
            except OSError:
                pass


class VmdkExtractor(_LibyalFuseExtractor):
    """VMware VMDK extractor via libyal's vmdkmount (Linux only)."""
    name = "vmdkmount"
    handles_kinds = frozenset({FileKind.VMDK})
    mount_tool = "vmdkmount"
    info_tool = "vmdkinfo"


class QcowExtractor(_LibyalFuseExtractor):
    """QEMU QCOW/QCOW2 extractor via libyal's qcowmount (Linux only)."""
    name = "qcowmount"
    handles_kinds = frozenset({FileKind.QCOW2})
    mount_tool = "qcowmount"
    info_tool = "qcowinfo"


class VhdiExtractor(_LibyalFuseExtractor):
    """Microsoft VHD/VHDX extractor via libyal's vhdimount (Linux only)."""
    name = "vhdimount"
    handles_kinds = frozenset({FileKind.VHD, FileKind.VHDX})
    mount_tool = "vhdimount"
    info_tool = "vhdiinfo"


# =============================================================================
# Windows-only paths
# =============================================================================

class WindowsSevenZipDiskExtractor(Extractor):
    """Windows-only disk-image extractor using 7-Zip.

    7-Zip natively handles VMDK, QCOW2, VHD, and VHDX disk image formats
    (verified against microsoft/winget-pkgs/manifests/7/7zip/7zip.installer.yaml
    FileExtensions list). A single ``7z x`` invocation extracts the
    underlying filesystem contents directly into ``ctx.dest_dir``; the
    BFS orchestrator then dispatches the extracted contents to filesystem
    extractors as appropriate.

    This is the primary Windows path for disk images. It runs without
    admin elevation and produces output equivalent to libyal FUSE
    mount + copy on Linux.
    """

    name = "7z (disk-image, windows)"
    handles_kinds = frozenset({
        FileKind.VMDK, FileKind.QCOW2, FileKind.VHD, FileKind.VHDX,
    })
    required_tools = ("7z",)
    priority = 85  # below libyal FUSE(90) on Linux for cross-platform priority parity;
                   # but libyal FUSE is filtered out on Windows so this wins there

    def is_available(self, tools) -> bool:
        # Windows-only: on Linux the canonical libyal FUSE path or
        # qemu-img path is preferred. 7z is sufficient on Windows
        # because we lack the FUSE userspace stack.
        if not is_windows():
            return False
        return super().is_available(tools)

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("7z"),
            "x", "-y",
            f"-o{ctx.dest_dir}",
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="7z",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            notes=[
                "7-Zip extracted the disk image's filesystem contents; "
                "the BFS orchestrator will dispatch any nested archives "
                "or filesystem images discovered in the output.",
            ],
        )


class _WindowsLibyalExportExtractor(Extractor):
    """Common offline-export workflow for libyal disk images on Windows.

    The libyal Windows binary distributions ship ``*info.exe`` and
    ``*export.exe`` per library (no FUSE; that's a Linux concept). The
    ``*export`` tools write the underlying raw image to a target path,
    bypassing the mount-and-copy workflow entirely.

    Standard CLI convention (uniform across libewf, libvmdk, libvhdi,
    libqcow, libsmraw, libphdi):
        ``<lib>export -t <target_basename> <source>``

    The ``-t`` flag specifies the basename for output files. Some libs
    write multiple outputs (e.g. multi-extent VMDKs); the basename is
    suffixed with extent numbers automatically.

    Subclasses set ``export_tool``, ``info_tool``, ``handles_kinds``.
    Filtered out on Linux because the equivalent FUSE-mount path
    (in :class:`_LibyalFuseExtractor`) is preferred there.
    """

    priority = 75  # below WindowsSevenZipDiskExtractor(85); secondary path

    # Subclasses override:
    export_tool: str = ""
    info_tool: str = ""

    def __init__(self) -> None:
        super().__init__()
        if self.export_tool and self.info_tool:
            self.required_tools = (self.export_tool, self.info_tool)

    def is_available(self, tools) -> bool:
        if not is_windows():
            return False
        return super().is_available(tools)

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # Use the source's stem as the output basename; libyal will
        # produce <basename>.raw or <basename>.NNN files.
        target_base = ctx.dest_dir / ctx.source_path.stem
        argv = [
            ctx.tools.path_of(self.export_tool),
            "-t", str(target_base),
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name=self.export_tool,
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )

        # Count produced output files for the result. libyal writes
        # files to the parent of target_base.
        files_out = 0
        for entry in ctx.dest_dir.iterdir():
            if entry.is_file() and entry.name.startswith(ctx.source_path.stem):
                files_out += 1

        if files_out == 0:
            raise ExtractorFailure(
                extractor=self.name, source=str(ctx.source_path),
                returncode=None,
                stderr=(
                    f"{self.export_tool} returned 0 but produced no output "
                    f"files matching pattern '{ctx.source_path.stem}*' "
                    f"in {ctx.dest_dir}"
                ),
            )

        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            files_produced=files_out,
            notes=[
                f"{self.export_tool} (libyal) offline-exported {files_out} "
                f"raw image file(s).",
            ],
        )


class WindowsVmdkExportExtractor(_WindowsLibyalExportExtractor):
    """VMware VMDK extractor via libyal's vmdkexport (Windows only)."""
    name = "vmdkexport (windows)"
    handles_kinds = frozenset({FileKind.VMDK})
    export_tool = "vmdkexport"
    info_tool = "vmdkinfo"


class WindowsQcowExportExtractor(_WindowsLibyalExportExtractor):
    """QEMU QCOW/QCOW2 extractor via libyal's qcowexport (Windows only)."""
    name = "qcowexport (windows)"
    handles_kinds = frozenset({FileKind.QCOW2})
    export_tool = "qcowexport"
    info_tool = "qcowinfo"


class WindowsVhdiExportExtractor(_WindowsLibyalExportExtractor):
    """Microsoft VHD/VHDX extractor via libyal's vhdiexport (Windows only)."""
    name = "vhdiexport (windows)"
    handles_kinds = frozenset({FileKind.VHD, FileKind.VHDX})
    export_tool = "vhdiexport"
    info_tool = "vhdiinfo"
