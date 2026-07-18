"""
.. module:: re_unpacker.extractors.embedded_fs
    :synopsis: Embedded firmware filesystems and DOS-era compressed format extractors.

Description
-----------
Three groups in v0.3.0:

1. **JFFS2 / UBI / MTD** -- embedded firmware filesystems often found
   inside vendor firmware bundles. We use ``binwalk -e`` for these as a
   pragmatic universal extractor; specialized tools like ``unjffs2``
   and ``ubireader_extract_files`` are not in standard Debian/Kali repos
   (jefferson would need pip-install). Binwalk's plug-in architecture
   handles JFFS2 / UBI / SquashFS-in-firmware reasonably well.

2. **MS KWAJ / SZDD** (DOS-era compressed files) -- ``mscompress``
   provides ``msexpand`` to decompress these. Show up inside CABs and
   old install media.

3. **macOS binary plist (BPLIST)** -- TERMINAL CLASSIFY ONLY. We never
   "extract" a bplist (it's a serialized data structure, not a
   container), but :class:`BplistConverter` runs as a SECONDARY
   extractor on BPLIST-kind files, converting the binary to readable
   XML alongside the original. The converted XML is left in
   ``_secondary_plistutil/<name>.xml.plist`` so analysts have a
   readable view without modifying the source.

Notes
-----
- BPLIST is in EXTRACTABLE_KINDS=False (terminal); it has NO primary
  extractor. The secondary BplistConverter still runs because it's
  registered as a secondary, which is independent of EXTRACTABLE_KINDS.
- ``msexpand`` produces a single decompressed output file with the
  original (uncompressed) name. We accept whatever it produces.
- Binwalk for JFFS2 / UBI surfaces with the same caveats as the
  existing :class:`BinwalkExtractor` (last-resort, returns rc=3 for
  no-signatures-found which we treat as ExtractorNotApplicable).

Execution parameters
--------------------
- All extractors honor ``ctx.timeout_seconds``.

Examples
--------
::

    re-unpacker firmware.bin -o /scratch/firmware/   # binwalk dispatched on JFFS2
    re-unpacker setup.kwaj -o /scratch/kwaj/         # msexpand dispatched

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from ..detection import FileKind
from ..exceptions import ExtractorFailure, ExtractorNotApplicable
from ..platform_compat import is_windows
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


# =============================================================================
# Embedded firmware filesystems via binwalk
# =============================================================================

class FirmwareFsBinwalkExtractor(Extractor):
    """Embedded firmware filesystem extractor via ``binwalk -e``.

    Handles JFFS2, UBI, and generic MTD images. Binwalk's signature
    plugins extract embedded SquashFS / JFFS2 / UBI / cpio / etc. into
    a ``_<basename>.extracted/`` directory in the cwd.
    """

    name = "binwalk-firmware"
    handles_kinds = frozenset({FileKind.JFFS2, FileKind.UBI, FileKind.MTD})
    required_tools = ("binwalk",)
    priority = 80  # Above generic binwalk's 20; below format-specific tools.

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("binwalk"),
            "-e",                      # extract
            "-q",                      # quiet (less stdout noise)
            "--directory", str(ctx.dest_dir),
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="binwalk-firmware",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        # Binwalk returns 0 even when nothing was extracted. Check for
        # produced files; if none, the file isn't a firmware blob we know
        # how to crack.
        produced = list(ctx.dest_dir.rglob("*"))
        if not produced:
            raise ExtractorNotApplicable(
                f"binwalk-firmware: no output ({ctx.source_path.name})",
                context={"reason": "no_firmware_signatures", "source": str(ctx.source_path)},
            )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            files_produced=len(produced),
            notes=["binwalk -e extracted embedded filesystem(s)"],
        )


# =============================================================================
# Microsoft KWAJ / SZDD compressed files
# =============================================================================

class MsCompressExtractor(Extractor):
    """Decompress MS KWAJ / SZDD archives (cross-platform).

    Cross-platform behavior:

    - **Linux**: ``msexpand`` (from the ``mscompress`` apt package).
      The mscompress package provides both ``msexpand`` and
      ``mscompress`` binaries. We invoke ``msexpand`` directly with
      a filename argument; the decompressed file is produced in the
      cwd, so we chdir into ``dest_dir`` before invocation.
    - **Windows**: native ``expand.exe`` handles both KWAJ and SZDD
      formats out-of-the-box. Invoked as
      ``expand -R <file> <dest>`` (the -R flag is "rename" mode that
      strips the trailing underscore convention used by KWAJ/SZDD).

    Both produce the same output: the original uncompressed file
    written under ``ctx.dest_dir``.
    """

    name = "msexpand"
    handles_kinds = frozenset({FileKind.KWAJ, FileKind.SZDD})
    # Platform-aware: 'mscompress' is the apt package name (Linux) and
    # also the tool-registry key; 'expand' is the Windows built-in.
    required_tools: tuple[str, ...] = (
        ("expand",) if is_windows() else ("mscompress",)
    )
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)

        if is_windows():
            # Windows expand.exe handles KWAJ and SZDD natively. The -R
            # flag asks expand to rename the output by stripping any
            # trailing underscore from the original filename
            # (Microsoft's KWAJ/SZDD convention is to suffix the
            # compressed file with an underscore, e.g. README.TX_ ->
            # README.TXT).
            argv = [
                ctx.tools.path_of("expand"),
                "-R",
                str(ctx.source_path),
                str(ctx.dest_dir),
            ]
            tool_name = "expand"
            run_tool(
                argv, tool_name=tool_name,
                timeout=ctx.timeout_seconds, check=True,
                logger=ctx.logger, source_for_error=str(ctx.source_path),
            )
        else:
            # Linux: msexpand reads from stdin or from a filename argument;
            # we use the filename form. By default it produces a file with
            # the original decompressed name in the cwd. We chdir into
            # dest_dir. The actual binary name on Debian/Ubuntu is
            # "msexpand" (the package is mscompress but provides msexpand
            # and mscompress binaries). We probe via tool 'mscompress'
            # which we know is available.
            argv = ["msexpand", str(ctx.source_path)]
            run_tool(
                argv, tool_name="msexpand",
                cwd=ctx.dest_dir,
                timeout=ctx.timeout_seconds, check=True,
                logger=ctx.logger, source_for_error=str(ctx.source_path),
            )

        # Both paths: msexpand and expand.exe are silent on success;
        # check for produced file.
        produced = list(ctx.dest_dir.iterdir())
        if not produced:
            raise ExtractorFailure(
                extractor=self.name, source=str(ctx.source_path),
                returncode=0,
                stderr=("msexpand returned 0 but produced no output file"
                        if not is_windows()
                        else "expand.exe returned 0 but produced no output file"),
            )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            files_produced=len(produced),
        )


# =============================================================================
# macOS binary plist converter (SECONDARY extractor)
# =============================================================================

class BplistConverter(Extractor):
    """macOS bplist -> readable XML converter via ``plistutil``.

    Registered as a SECONDARY extractor. BPLIST is a terminal kind
    (no primary extractor), but this secondary still runs whenever a
    BPLIST file is encountered, producing a sibling XML representation
    that the analyst can read.
    """

    name = "plistutil"
    handles_kinds = frozenset({FileKind.BPLIST})
    required_tools = ("plistutil",)
    is_secondary = True
    priority = 30

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        # Secondary extractors land in dest_dir/_secondary_<name>/ already
        # (handled by the orchestrator). We just produce <stem>.xml.plist
        # in there.
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        outfile = ctx.dest_dir / (ctx.source_path.stem + ".xml.plist")
        # plistutil -i <input> -o <output> -f xml
        argv = [
            ctx.tools.path_of("plistutil"),
            "-i", str(ctx.source_path),
            "-o", str(outfile),
            "-f", "xml",
        ]
        run_tool(
            argv, tool_name="plistutil",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            files_produced=1,
            notes=[
                "plistutil converted binary plist -> XML; original bplist "
                "preserved in the source location.",
            ],
        )
