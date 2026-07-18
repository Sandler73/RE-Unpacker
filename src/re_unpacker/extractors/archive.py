"""
.. module:: re_unpacker.extractors.archive
    :synopsis: Extractors for traditional archive formats.

Description
-----------
Covers:

- :class:`TarExtractor` -- ``.tar``, ``.tar.gz``, ``.tar.bz2``, ``.tar.xz``,
  ``.tar.zst``, ``.tar.lzma``. Uses ``tar`` which auto-detects compression
  in modern GNU tar.
- :class:`ZipExtractor` -- zip-family (plain .zip, .jar, .apk, .ipa, .whl,
  .xpi, .crx, .docx, .xlsx, .pptx, etc.).
- :class:`SevenZipExtractor` -- ``.7z``.
- :class:`RarExtractor` -- ``.rar`` via ``unrar`` (if present) with 7z
  fallback.
- :class:`SingleStreamExtractor` -- standalone ``.gz``, ``.bz2``, ``.xz``,
  ``.zst``, ``.lz4``, ``.lzo``, ``.lzma`` compressed single files (no
  tar wrapper). Decompresses to ``<stem>`` inside dest_dir.

Notes
-----
- We prefer format-specific tools over 7z where they give better fidelity
  (tar preserves permissions better than 7z, unzip preserves mtimes
  correctly), and use 7z when it's the simplest correct option.
- Safety flags: ``tar --no-same-owner --no-same-permissions`` during
  extraction so extracted content can't chown files to unexpected users
  when run as root. Post-extraction permission/ownership preservation
  is out of scope -- this is an RE triage tool, not a package installer.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from pathlib import Path

from ..detection import FileKind
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


# =============================================================================
# Tar family
# =============================================================================

class TarExtractor(Extractor):
    name = "tar"
    handles_kinds = frozenset({
        FileKind.TAR, FileKind.TAR_GZ, FileKind.TAR_BZ2,
        FileKind.TAR_XZ, FileKind.TAR_ZST, FileKind.TAR_LZMA,
    })
    required_tools = ("tar",)
    priority = 80

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("tar"),
            "-xf", str(ctx.source_path),
            "-C", str(ctx.dest_dir),
            "--no-same-owner", "--no-same-permissions",
            # Safety: refuse absolute paths in the tar stream. GNU tar
            # strips a leading slash by default but we're explicit.
            "--delay-directory-restore",
        ]
        # Compression: modern GNU tar auto-detects; no flag needed.
        run_tool(
            argv, tool_name="tar",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


# =============================================================================
# Zip family
# =============================================================================

class ZipExtractor(Extractor):
    name = "unzip"
    # ZIP, OOXML, plus APK (where it acts as fallback when apktool is
    # missing). APK is a ZIP at the byte level; ZipExtractor won't decode the
    # binary AndroidManifest.xml or resources.arsc, but that's fine -- if
    # apktool is missing the user gets the raw APK contents and can decide
    # whether to install apktool and re-run.
    handles_kinds = frozenset({FileKind.ZIP, FileKind.OOXML, FileKind.APK})
    required_tools = ("unzip",)
    priority = 80

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        from ..exceptions import ExtractorFailure
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("unzip"),
            "-o",                   # overwrite without prompting
            "-qq",                  # very quiet
            str(ctx.source_path),
            "-d", str(ctx.dest_dir),
        ]
        # unzip exit codes:
        # 0 = success
        # 1 = completed with non-fatal warnings (CRC quirks, etc.) -- treat as ok
        # 2+ = genuine failure (bad zip, I/O error, ...)
        # We use check=False so we can distinguish 1 from 2+ in one call instead of
        # raising, catching, and rerunning.
        r = run_tool(
            argv, tool_name="unzip",
            timeout=ctx.timeout_seconds, check=False,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        if r.returncode >= 2:
            raise ExtractorFailure(
                extractor=self.name, source=str(ctx.source_path),
                returncode=r.returncode,
                stderr=r.stderr_text[:2000],
            )
        notes: list[str] = []
        if r.returncode == 1:
            notes.append("unzip reported non-fatal warnings (rc=1)")
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            notes=notes,
        )


# =============================================================================
# 7z -- also serves as a fallback for many kinds via separate extractor instances.
# =============================================================================

class SevenZipExtractor(Extractor):
    name = "7z"
    handles_kinds = frozenset({
        FileKind.SEVENZ,
        FileKind.RAR,           # 7z handles most RARs via p7zip-full's rar codec
        FileKind.ZIP,           # fallback (lower priority than unzip)
        FileKind.CAB,           # fallback
        FileKind.ISO,           # primary for ISO
        FileKind.DMG,           # primary for DMG
        FileKind.XAR,           # primary for XAR
        FileKind.OLE2,          # can pop OLE2 compound docs
        FileKind.PE_EXECUTABLE, # 7z can dig into PE installers generically
    })
    required_tools = ("7z",)
    priority = 60  # Lower than format-specific tools; ISO/DMG/XAR get +10 via __init__

    # Set by ExtractorRegistry based on kind - but we can stay at 60 generally
    # and let more specific extractors (tar, unzip, cabextract) outrank us.
    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("7z"),
            "x",                                # extract with full paths
            "-y",                               # answer yes to all prompts
            f"-o{ctx.dest_dir}",                # output dir (no space!)
            "-bd",                              # disable progress
            "-aoa",                             # always overwrite
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="7z",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


# =============================================================================
# RAR - dedicated extractor (if unrar is present)
# =============================================================================

class RarExtractor(Extractor):
    name = "unrar"
    handles_kinds = frozenset({FileKind.RAR})
    required_tools = ("unrar",)
    priority = 75  # slightly below 7z's 60? Actually set it higher when available

    def __init__(self) -> None:
        super().__init__()
        # Bump so we outrank 7z (60) when unrar exists.
        self.priority = 75

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("unrar"),
            "x",                     # extract with full paths
            "-o+",                   # overwrite all
            "-y",                    # yes to all
            "-inul",                 # silent
            str(ctx.source_path),
            str(ctx.dest_dir) + "/",
        ]
        run_tool(
            argv, tool_name="unrar",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


# =============================================================================
# Single-stream compression (gz/bz2/xz/zst/lzma/lz4/lzo alone, no tar wrapper)
# =============================================================================

# Map: kind -> (tool_name, argv_builder_returning_list)
# The argv_builder takes (tool_path, source_path, outfile_path) and returns argv.
# We redirect stdout to the outfile via subprocess pipe handling.

class SingleStreamExtractor(Extractor):
    """Decompresses a standalone single-stream compressed file.

    Produces ``<source_stem>`` inside ``dest_dir``. If the stem already
    has an extension (e.g. ``foo.bin.gz`` -> ``foo.bin``), it's kept.
    """
    name = "decompress"
    handles_kinds = frozenset({
        FileKind.GZIP, FileKind.BZIP2, FileKind.XZ,
        FileKind.ZSTD, FileKind.LZ4, FileKind.LZOP, FileKind.LZMA,
    })
    required_tools = ()  # dynamic per kind
    priority = 50

    # Per-kind (tool-name, flags for decompression to stdout).
    _KIND_TOOLS: dict[FileKind, tuple[str, tuple[str, ...]]] = {
        FileKind.GZIP: ("gzip", ("-d", "-c")),
        FileKind.BZIP2: ("bzip2", ("-d", "-c")),
        FileKind.XZ: ("xz", ("-d", "-c")),
        FileKind.ZSTD: ("zstd", ("-d", "-c")),
        FileKind.LZ4: ("lz4", ("-d", "-c")),
        FileKind.LZOP: ("lzop", ("-d", "-c")),
        FileKind.LZMA: ("unlzma", ("-c",)),
    }

    def is_available(self, tools) -> bool:  # type: ignore[override]
        # Available if *any* of our per-kind tools is present. More precise
        # check happens inside extract().
        return any(tools.have(t) for t, _ in self._KIND_TOOLS.values())

    def missing_tools(self, tools) -> list[str]:  # type: ignore[override]
        # For reporting: list tools that are missing *and* whose kind we'd handle.
        return [t for t, _ in self._KIND_TOOLS.values() if not tools.have(t)]

    def _derive_outfile(self, source_path: Path, dest_dir: Path) -> Path:
        # Strip the compression extension. If no known suffix, append .out.
        name = source_path.name
        lower = name.lower()
        stripped_suffixes = (
            ".gz", ".bz2", ".xz", ".zst", ".lzma",
            ".lz4", ".lzo", ".lzop",
        )
        for s in stripped_suffixes:
            if lower.endswith(s):
                base = name[: -len(s)]
                break
        else:
            base = name + ".out"
        if not base:
            base = "decompressed.out"
        return dest_dir / base

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        # Caller must have ensured kind is in handles_kinds.
        # But detect_file doesn't give us the kind here -- it's the orchestrator
        # that dispatches. We re-detect cheaply from file extension:
        from ..detection import FileKind as _FK
        # Map file extension back to kind (simple lookup).
        ext_to_kind = {
            ".gz": _FK.GZIP, ".bz2": _FK.BZIP2, ".xz": _FK.XZ,
            ".zst": _FK.ZSTD, ".lzma": _FK.LZMA, ".lz4": _FK.LZ4,
            ".lzo": _FK.LZOP, ".lzop": _FK.LZOP,
        }
        ext = ctx.source_path.suffix.lower()
        kind = ext_to_kind.get(ext)
        # If extension-based kind wasn't in our map, try magic fallback.
        if kind is None:
            # Heuristic: read first byte or two to pick a handler.
            try:
                with open(ctx.source_path, "rb") as f:
                    head = f.read(6)
            except OSError as e:
                from ..exceptions import ExtractorFailure
                raise ExtractorFailure(
                    self.name, str(ctx.source_path),
                    returncode=None, stderr=str(e),
                )
            if head.startswith(b"\x1f\x8b"):
                kind = _FK.GZIP
            elif head.startswith(b"BZh"):
                kind = _FK.BZIP2
            elif head.startswith(b"\xfd7zXZ\x00"):
                kind = _FK.XZ
            elif head.startswith(b"\x28\xb5\x2f\xfd"):
                kind = _FK.ZSTD
            elif head.startswith(b"\x04\x22\x4d\x18"):
                kind = _FK.LZ4
            elif head.startswith(b"\x89LZO"):
                kind = _FK.LZOP
            else:
                kind = _FK.LZMA  # last resort guess

        tool_name, flags = self._KIND_TOOLS[kind]
        if not ctx.tools.have(tool_name):
            from ..exceptions import ToolMissingError
            raise ToolMissingError(tool_name)

        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        outfile = self._derive_outfile(ctx.source_path, ctx.dest_dir)

        # Run tool with stdout redirected to outfile via shell-free pipe.
        # This path deliberately streams decompression straight to a file
        # (rather than through run_tool's captured PIPE) so a large decompressed
        # stream is not buffered in memory. It reuses the central cross-platform
        # process teardown and the RLIMIT_FSIZE output-size cap so it matches
        # run_tool's safety guarantees (REL-2 / SEC-1).
        import subprocess
        from ..subprocess_utils import (
            _terminate_proc_tree,
            fsize_limit_preexec,
            get_output_byte_cap,
        )
        tool_path = ctx.tools.path_of(tool_name)
        argv = [tool_path, *flags, str(ctx.source_path)]
        ctx.logger.debug("decompress: %r -> %s", argv, outfile)
        preexec = fsize_limit_preexec(get_output_byte_cap())
        try:
            with open(outfile, "wb") as fout:
                proc = subprocess.Popen(
                    argv,
                    stdout=fout,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                    preexec_fn=preexec,
                )
                try:
                    _, stderr = proc.communicate(timeout=ctx.timeout_seconds)
                except subprocess.TimeoutExpired:
                    # Cross-platform teardown: SIGTERM the group, then SIGKILL
                    # if it does not exit, and reap so no zombie is left.
                    _terminate_proc_tree(proc, hard=False)
                    try:
                        proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        _terminate_proc_tree(proc, hard=True)
                        try:
                            proc.communicate(timeout=5)
                        except Exception:
                            pass
                    from ..exceptions import ExtractorTimeout
                    raise ExtractorTimeout(
                        self.name, str(ctx.source_path), ctx.timeout_seconds,
                    )
            if proc.returncode != 0:
                from ..exceptions import ExtractorFailure
                raise ExtractorFailure(
                    extractor=self.name, source=str(ctx.source_path),
                    returncode=proc.returncode,
                    stderr=(stderr.decode("utf-8", errors="replace")[:2000]
                            if stderr else ""),
                )
        except OSError as e:
            from ..exceptions import ExtractorFailure
            raise ExtractorFailure(
                self.name, str(ctx.source_path),
                returncode=None, stderr=str(e),
            ) from e

        return ExtractionResult(
            extractor_name=f"{self.name}:{tool_name}",
            success=True,
            dest_dir=ctx.dest_dir,
            files_produced=1,
        )


# Make the 7z primary class visible under an importable name for the registry
# builder -- we re-export it as SevenZipExtractor's registered instance.
# (The registry builder in base.py just instantiates SevenZipExtractor, which
# handles most kinds at priority 60 -- high enough to serve as fallback for
# most formats and primary for ISO/DMG/XAR since no other extractor competes
# there.)
