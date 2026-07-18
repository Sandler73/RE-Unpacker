"""
.. module:: re_unpacker.extractors.msi
    :synopsis: Microsoft Installer (.msi / .msp) extractor (cross-platform).

Description
-----------
MSI files are OLE2 compound documents holding an installer database.

Cross-platform extractor strategy
---------------------------------
- **Linux**: ``msiextract`` from the ``msitools`` apt package; unpacks
  the embedded cabinet and file streams into a usable tree.
- **Windows** (new in v0.4.0): ``msiexec /a "<file>" /qn TARGETDIR=<dir>``
  performs an "administrative install" which is Microsoft's official
  unpack mechanism for MSI files. /a means admin install (extracts the
  files); /qn means quiet (no UI); TARGETDIR specifies the destination.
  This is the canonical Windows MSI unpack and produces a clean tree
  matching what the installer would have placed under
  Program Files. ``msiexec.exe`` is built-in to every Windows install.

Both extractors produce equivalent output: the MSI's payload files
written under ``ctx.dest_dir``.

If neither primary extractor is available, 7-Zip can also crack MSI
files (it treats them as CFBF / compound files), but the file tree
isn't as clean as msiextract or msiexec /a output. This fallback is
implicit via the SevenZipExtractor for general PE-like containers.

Version
-------
See :data:`re_unpacker.constants.VERSION`. Cross-platform support added
in v0.4.0.
"""

from __future__ import annotations

from ..detection import FileKind
from ..platform_compat import is_windows
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


class MsiExtractor(Extractor):
    """Primary MSI extractor using ``msiextract`` (Linux only).

    Filtered out on Windows because ``msiextract`` (msitools) is
    Linux-only; MsiExecExtractor below covers the Windows case.
    """

    name = "msiextract"
    handles_kinds = frozenset({FileKind.MSI})
    required_tools = ("msiextract",)
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("msiextract"),
            "--directory", str(ctx.dest_dir),
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="msiextract",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


class MsiExecExtractor(Extractor):
    """Windows-only MSI extractor using native ``msiexec /a``.

    Performs an administrative install: extracts the MSI's payload
    files into TARGETDIR without actually installing the package
    (no registry writes, no shortcuts, no Start menu entries). This
    is Microsoft's official unpack mechanism for MSI files.

    Note: msiexec.exe expects an ABSOLUTE path for TARGETDIR; Python's
    ``Path.resolve()`` provides this. We run with /qn (quiet, no UI)
    to suppress all dialogs; if the MSI has a custom action that
    blocks even with /qn, the timeout will catch it.
    """

    name = "msiexec /a (msi, windows)"
    handles_kinds = frozenset({FileKind.MSI})
    required_tools = ("msiexec",)
    priority = 100  # primary on Windows; same priority as Linux msiextract

    def is_supported(self, tools) -> bool:  # type: ignore[override]
        if not is_windows():
            return False
        return super().is_supported(tools)

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # msiexec.exe TARGETDIR must be absolute.
        target = ctx.dest_dir.resolve()
        source = ctx.source_path.resolve()
        argv = [
            ctx.tools.path_of("msiexec"),
            "/a", str(source),
            "/qn",  # quiet, no UI
            f"TARGETDIR={target}",
        ]
        run_tool(
            argv, tool_name="msiexec",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )
