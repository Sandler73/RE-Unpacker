"""
.. module:: re_unpacker.extractors.forensic_fs
    :synopsis: Forensic filesystem extractors (NTFS, ext, XFS, APFS, HFS+, FAT, VSS, LVM2).

Description
-----------
libyal-based readers for native filesystems found inside disk images.
Each extractor uses ``<fs>mount`` (libyal FUSE mounter) to expose the
filesystem read-only, walks the mount point with ``shutil.copytree``,
and unmounts.

All FUSE mount operations require root (``requires_root = True``). When
running as non-root, the orchestrator skips these extractors with a
clear log message; the run continues without a fatal error.

Notes
-----
- Each libyal mounter has its own quirks. We collapse them into a
  shared helper :class:`_LibyalFsExtractor` that takes the mount-tool
  name and adapts.
- Read-only mount: every libyal FS mounter is read-only by design.
- We copy out the entire tree under the mount point. This can be
  large -- the orchestrator's quota tracker will trip if the FS is
  bigger than ``--max-extracted-size``.
- File metadata (mtime, mode bits) are preserved via shutil.copytree's
  default behavior; we do NOT preserve owner / group (would require
  CAP_CHOWN and rarely matters for triage).
- Symlinks inside the FS are followed during the copy (we want the
  target content, not a symlink to a path that won't exist outside the
  mount). Path-traversal audit at the orchestrator level catches any
  escaping symlinks that would otherwise cause issues.

Execution parameters
--------------------
- All extractors honor ``ctx.timeout_seconds``.
- All extractors set ``requires_root = True``.

Examples
--------
::

    sudo re-unpacker disk.raw -o /scratch/raw/ # libyal will dispatch by FS magic

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


class _LibyalFsExtractor(Extractor):
    """Common workflow for libyal-based read-only filesystem extractors.

    Subclasses set ``mount_tool``, ``info_tool``, ``handles_kinds``.
    Each calls ``<mount_tool> <source> <mountpoint>``, copies the tree
    out, and unmounts via fusermount -u.
    """

    requires_root = True
    priority = 90

    mount_tool: str = ""
    info_tool: str = ""

    def __init__(self) -> None:
        super().__init__()
        if self.mount_tool and self.info_tool:
            self.required_tools = (self.mount_tool, self.info_tool, "fusermount")

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        mountpoint = ctx.dest_dir / "_libyal_fs_mount"
        copy_root = ctx.dest_dir / "files"
        mountpoint.mkdir(exist_ok=True)
        copy_root.mkdir(exist_ok=True)

        try:
            mount_argv = [
                ctx.tools.path_of(self.mount_tool),
                str(ctx.source_path),
                str(mountpoint),
            ]
            run_tool(
                mount_argv, tool_name=self.mount_tool,
                timeout=ctx.timeout_seconds, check=True,
                logger=ctx.logger, source_for_error=str(ctx.source_path),
            )

            # libyal FS mounters expose the FS contents under a numbered
            # subdir (the "file" entry) -- typically the first numbered
            # entry contains the root filesystem. Walk every immediate
            # subdir and copy out its contents.
            try:
                entries = sorted(mountpoint.iterdir())
            except OSError as e:
                # ENOSYS = "Function not implemented" -- FUSE userspace or
                # kernel module not available even though the mount binary
                # ran successfully. Surface as not-applicable so the orchestrator
                # records this and falls through cleanly. (No higher-priority
                # forensic-FS extractors exist for these kinds; the run will
                # record "no available primary" in the manifest. This is fine
                # because the user explicitly opted into FUSE mounts via root.)
                if e.errno == 38:  # ENOSYS
                    raise ExtractorNotApplicable(
                        f"{self.mount_tool}: FUSE not functional (errno=ENOSYS) "
                        f"for {ctx.source_path.name}; install fuse package "
                        f"and ensure /dev/fuse is accessible",
                        context={"reason": "fuse_enosys", "source": str(ctx.source_path)},
                    ) from e
                raise
            files_out = 0
            for entry in entries:
                if not entry.is_dir():
                    continue
                target = copy_root / entry.name
                try:
                    shutil.copytree(
                        entry, target,
                        symlinks=False,           # follow symlinks; orchestrator
                                                  # audit catches escapes
                        ignore_dangling_symlinks=True,
                        dirs_exist_ok=True,
                    )
                    # Count files we successfully copied.
                    for _ in target.rglob("*"):
                        files_out += 1
                except (OSError, shutil.Error) as e:
                    # Filesystem-level error during copy -- log but continue
                    # on remaining entries. The path-traversal audit on the
                    # orchestrator side handles dangerous symlinks; this
                    # branch handles things like missing FUSE permissions.
                    ctx.logger.warning(
                        "Partial copy from %s: %s", entry, e,
                    )

            if files_out == 0:
                raise ExtractorFailure(
                    extractor=self.name, source=str(ctx.source_path),
                    returncode=None,
                    stderr=(
                        f"{self.mount_tool} mounted but no files were "
                        f"successfully copied out of {mountpoint}"
                    ),
                )

            return ExtractionResult(
                extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
                files_produced=files_out,
                notes=[
                    f"{self.mount_tool} (libyal) FUSE-mounted the filesystem "
                    f"read-only and copied out {files_out} files to "
                    f"{copy_root.name}/.",
                ],
            )
        finally:
            time.sleep(0.2)  # Let buffers flush before unmount.
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
            try:
                mountpoint.rmdir()
            except OSError:
                pass


class ApfsExtractor(_LibyalFsExtractor):
    """macOS APFS extractor via libyal's fsapfsmount."""
    name = "fsapfsmount"
    handles_kinds = frozenset({FileKind.APFS})
    mount_tool = "fsapfsmount"
    info_tool = "fsapfsinfo"


class NtfsExtractor(_LibyalFsExtractor):
    """Windows NTFS extractor via libyal's fsntfsmount."""
    name = "fsntfsmount"
    handles_kinds = frozenset({FileKind.NTFS})
    mount_tool = "fsntfsmount"
    info_tool = "fsntfsinfo"


class ExtFsExtractor(_LibyalFsExtractor):
    """Linux ext{2,3,4} extractor via libyal's fsextmount."""
    name = "fsextmount"
    handles_kinds = frozenset({FileKind.EXT_FS})
    mount_tool = "fsextmount"
    info_tool = "fsextinfo"


class XfsExtractor(_LibyalFsExtractor):
    """Linux XFS extractor via libyal's fsxfsmount."""
    name = "fsxfsmount"
    handles_kinds = frozenset({FileKind.XFS})
    mount_tool = "fsxfsmount"
    info_tool = "fsxfsinfo"


class HfsplusExtractor(_LibyalFsExtractor):
    """macOS HFS+ extractor via libyal's fshfsmount."""
    name = "fshfsmount"
    handles_kinds = frozenset({FileKind.HFSPLUS})
    mount_tool = "fshfsmount"
    info_tool = "fshfsinfo"


class FatExtractor(_LibyalFsExtractor):
    """FAT12/16/32/exFAT extractor via libyal's fsfatmount."""
    name = "fsfatmount"
    handles_kinds = frozenset({FileKind.FAT})
    mount_tool = "fsfatmount"
    info_tool = "fsfatinfo"


class VssExtractor(_LibyalFsExtractor):
    """Windows VSS shadow copy extractor via libyal's vshadowmount."""
    name = "vshadowmount"
    handles_kinds = frozenset({FileKind.VSS})
    mount_tool = "vshadowmount"
    info_tool = "vshadowinfo"


class Lvm2Extractor(_LibyalFsExtractor):
    """Linux LVM2 extractor via libyal's vslvmmount."""
    name = "vslvmmount"
    handles_kinds = frozenset({FileKind.LVM2})
    mount_tool = "vslvmmount"
    info_tool = "vslvminfo"


# =============================================================================
# Windows-only paths
# =============================================================================

class WindowsSevenZipForensicFsExtractor(Extractor):
    """Windows-only filesystem extractor using 7-Zip.

    7-Zip natively handles NTFS, APFS, HFS+, EXT (ext2/3/4), and FAT
    filesystems (verified against the 7-Zip FileExtensions manifest at
    microsoft/winget-pkgs/manifests/7/7zip/7zip.installer.yaml). A
    single ``7z x`` invocation extracts the filesystem contents directly
    into ``ctx.dest_dir``.

    This is the primary Windows path for the well-supported filesystem
    kinds. It runs without admin elevation. For XFS, VSS, and LVM2 (less
    common, not in the 7-Zip manifest), :class:`WindowsLibyalExportFsExtractor`
    subclasses provide a libyal *export-based fallback path; users must
    install libyal Windows binaries manually (see
    KNOWN_UNAVAILABLE_PACKAGES_WIN in constants.py for instructions).
    """

    name = "7z (forensic-fs, windows)"
    handles_kinds = frozenset({
        FileKind.NTFS, FileKind.APFS, FileKind.HFSPLUS,
        FileKind.EXT_FS, FileKind.FAT,
    })
    required_tools = ("7z",)
    priority = 85  # below libyal FUSE(90) on Linux for cross-platform priority parity;
                   # libyal FUSE filtered out on Windows, so this is the primary

    def is_available(self, tools) -> bool:
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
                "7-Zip extracted the filesystem contents; the BFS "
                "orchestrator will dispatch any nested archives or "
                "filesystem images discovered in the output.",
            ],
        )


class _WindowsLibyalFsExportExtractor(Extractor):
    """Common offline-export workflow for libyal filesystem libs on Windows.

    Used as fallback for filesystems not covered by 7-Zip on Windows
    (XFS, VSS, LVM2). The libyal Windows binary distributions ship
    ``*info.exe`` and ``*export.exe`` per library. The ``*export``
    tools recursively export the filesystem contents to a target dir.

    Standard CLI convention (uniform across libfsxfs, libvshadow,
    libvslvm, libfsapfs, libfsntfs, libfsext, libfshfs, libfsfat,
    libluksde):
        ``<lib>export -t <target_directory> <source>``

    Subclasses set ``export_tool``, ``info_tool``, ``handles_kinds``.
    Filtered out on Linux because the FUSE-mount path
    (in :class:`_LibyalFsExtractor`) is preferred there.
    """

    priority = 75  # below WindowsSevenZipForensicFsExtractor(85); secondary path

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
        # libyal *export writes to a target directory (the -t arg).
        target = ctx.dest_dir / "files"
        target.mkdir(exist_ok=True)
        argv = [
            ctx.tools.path_of(self.export_tool),
            "-t", str(target),
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name=self.export_tool,
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )

        # Count files written under target/.
        files_out = sum(1 for _ in target.rglob("*") if _.is_file())

        if files_out == 0:
            raise ExtractorFailure(
                extractor=self.name, source=str(ctx.source_path),
                returncode=None,
                stderr=(
                    f"{self.export_tool} returned 0 but produced no output "
                    f"files in {target}"
                ),
            )

        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            files_produced=files_out,
            notes=[
                f"{self.export_tool} (libyal) offline-exported {files_out} "
                f"file(s) from the filesystem.",
            ],
        )


class WindowsXfsExportExtractor(_WindowsLibyalFsExportExtractor):
    """Windows-only XFS extractor via libyal's fsxfsexport."""
    name = "fsxfsexport (windows)"
    handles_kinds = frozenset({FileKind.XFS})
    export_tool = "fsxfsexport"
    info_tool = "fsxfsinfo"


class WindowsVssExportExtractor(_WindowsLibyalFsExportExtractor):
    """Windows-only VSS shadow-copy extractor via libyal's vshadowexport."""
    name = "vshadowexport (windows)"
    handles_kinds = frozenset({FileKind.VSS})
    export_tool = "vshadowexport"
    info_tool = "vshadowinfo"


class WindowsLvm2ExportExtractor(_WindowsLibyalFsExportExtractor):
    """Windows-only LVM2 extractor via libyal's vslvmexport."""
    name = "vslvmexport (windows)"
    handles_kinds = frozenset({FileKind.LVM2})
    export_tool = "vslvmexport"
    info_tool = "vslvminfo"
