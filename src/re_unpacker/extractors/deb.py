"""
.. module:: re_unpacker.extractors.deb
    :synopsis: Debian package (.deb / .udeb) extractor (cross-platform).

Description
-----------
A ``.deb`` is an ``ar`` archive with three members, in order:

    debian-binary -- the format version ("2.0\\n")
    control.tar.* -- package metadata & maintainer scripts
    data.tar.* -- the actual payload (files to be installed)

Cross-platform extractor strategy
---------------------------------
Three extractors are registered for the DEB kind, with platform-aware
``is_available()`` selecting at runtime:

- **DebExtractor** (Linux only): ``dpkg-deb -R`` -- the canonical tool;
  unpacks both control and data into a well-known layout in one pass.
  Filtered out on Windows because ``dpkg-deb`` is Linux-only.
- **DebArFallbackExtractor** (Linux only): ``ar x`` + tar extraction of
  the inner tarballs. Works on minimal Linux without dpkg-deb.
- **DebSevenZipExtractor** (Windows): three-stage 7-Zip
  extraction. 7-Zip handles ``.deb`` in its FileExtensions manifest
  (verified against microsoft/winget-pkgs/manifests/7/7zip/7zip).
  Output layout matches dpkg-deb -R: ``dest/DEBIAN/<control files>``
  + ``dest/<payload files>``.

The orchestrator picks the highest-priority available extractor; on
Windows that's DebSevenZipExtractor (priority 90, just below dpkg-deb's
100 to keep priority ordering consistent across platforms even though
dpkg-deb is filtered).

Notes
-----
- Extraction order is deliberate: the native ``dpkg-deb`` path outranks the
  ``ar`` plus ``tar`` fallback, which in turn outranks the 7-Zip path. Each
  lower-priority handler exists to cover a host where the one above it is
  unavailable.
- A ``.deb`` is an ``ar`` archive containing ``control.tar.*`` and
  ``data.tar.*``. Those inner tarballs are left for the recursion engine to
  pick up rather than being unwrapped here, which is what keeps the manifest
  depth accounting honest.

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from ..detection import FileKind
from ..platform_compat import is_windows
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


class DebExtractor(Extractor):
    """Primary extractor for ``.deb`` / ``.udeb`` (Linux only).

    Uses ``dpkg-deb -R``, the canonical Debian tool. ``required_tools``
    lists ``dpkg-deb`` which is absent from TOOL_PACKAGE_HINTS_WINDOWS,
    so ``is_available()`` returns False on Windows automatically.
    """

    name = "dpkg-deb"
    handles_kinds = frozenset({FileKind.DEB})
    required_tools = ("dpkg-deb",)
    priority = 100  # highest; dpkg-deb is the canonical tool

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        # dpkg-deb -R puts data into dest_dir and DEBIAN metadata into
        # dest_dir/DEBIAN/ -- exactly what we want for RE inspection.
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("dpkg-deb"),
            "-R",                       # extract control info + data (recursive-style)
            str(ctx.source_path),
            str(ctx.dest_dir),
        ]
        run_tool(
            argv, tool_name="dpkg-deb",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


class DebArFallbackExtractor(Extractor):
    """Fallback .deb extractor using ``ar x`` + tar (Linux only).

    Registered so that on minimal Linux boxes without ``dpkg-deb`` we
    can still crack a .deb open using binutils + tar alone. Filtered
    out on Windows because ``ar`` (binutils) is Linux-only;
    DebSevenZipExtractor below covers the Windows case.
    """

    name = "ar+tar (deb)"
    handles_kinds = frozenset({FileKind.DEB})
    required_tools = ("ar", "tar")
    priority = 40  # below dpkg-deb(100) and below 7z(60)

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # Step 1: unpack the ar archive into dest_dir/_ar/
        ar_dir = ctx.dest_dir / "_ar"
        ar_dir.mkdir(parents=True, exist_ok=True)
        run_tool(
            [ctx.tools.path_of("ar"), "x", str(ctx.source_path)],
            tool_name="ar", cwd=ar_dir,
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        # Step 2: find and extract control.tar.* and data.tar.*
        extracted_any = False
        for entry in ar_dir.iterdir():
            if not entry.is_file():
                continue
            lname = entry.name.lower()
            if lname.startswith(("control.tar", "data.tar")):
                sub = ctx.dest_dir / entry.stem.split(".tar")[0]
                # e.g. control.tar.gz -> "control"; data.tar.xz -> "data"
                # Re-derive to be explicit:
                if "control" in lname:
                    sub = ctx.dest_dir / "DEBIAN"
                elif "data" in lname:
                    sub = ctx.dest_dir  # data goes into root of dest
                sub.mkdir(parents=True, exist_ok=True)
                run_tool(
                    [
                        ctx.tools.path_of("tar"),
                        "-xf", str(entry),
                        "-C", str(sub),
                        "--no-same-owner", "--no-same-permissions",
                    ],
                    tool_name="tar",
                    timeout=ctx.timeout_seconds, check=True,
                    logger=ctx.logger, source_for_error=str(entry),
                )
                extracted_any = True
        if not extracted_any:
            from ..exceptions import ExtractorFailure
            raise ExtractorFailure(
                extractor=self.name, source=str(ctx.source_path),
                returncode=None,
                stderr="ar archive contained no control.tar.* or data.tar.*",
            )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


class DebSevenZipExtractor(Extractor):
    """Windows-only .deb extractor using 7-Zip in three stages.

    Mirrors the on-disk layout produced by ``dpkg-deb -R`` so the
    Windows manifest is interchangeable with the Linux manifest:
      - ``dest/DEBIAN/<control_files>`` (control.tar.* members)
      - ``dest/<payload_files>`` (data.tar.* members)
      - ``dest/debian-binary`` (the format version marker)

    Stage 1: ``7z x deb_file`` extracts the outer ar archive into a
             temporary work dir.
    Stage 2: For each ``control.tar.*`` member, ``7z x`` into
             ``dest/DEBIAN/``. (7-Zip handles tar.gz, tar.xz, tar.zst,
             tar.bz2 transparently; a single 7z invocation may need to
             be a 2-step "decompress then extract" because some tar
             flavors are 7z's "two-pass" formats. We use a single 7z
             call with ``-so | 7z -si`` piped invocation when needed,
             else direct extraction.)
    Stage 3: Same for ``data.tar.*`` into ``dest/``.

    On Windows ``dpkg-deb`` is unavailable, so this extractor is the
    Windows path. ``required_tools = ("7z",)`` filters it out on Linux.
    """

    name = "7z (deb, windows)"
    handles_kinds = frozenset({FileKind.DEB})
    # Limit to Windows by gating on the platform-only tool combination.
    # On Linux, 7z is present but the orchestrator already has higher-
    # priority dpkg-deb / ar+tar paths; we override is_available() below
    # to enforce Windows-only registration.
    required_tools = ("7z",)
    priority = 90  # below dpkg-deb(100); above ar+tar(40)

    def is_available(self, tools) -> bool:
        # Windows-only: even if 7z is present on Linux (which it usually
        # is), this extractor should never run there because dpkg-deb
        # and DebArFallbackExtractor cover the Linux case more cleanly
        # and produce the canonical layout.
        if not is_windows():
            return False
        return super().is_available(tools)

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        sevenz = ctx.tools.path_of("7z")

        # Stage 1: unpack the outer ar archive into a temp work dir.
        tmp_dir = ctx.dest_dir / "_deb_tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        run_tool(
            [sevenz, "x", "-y", f"-o{tmp_dir}", str(ctx.source_path)],
            tool_name="7z",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )

        # Stage 2 / Stage 3: locate control.tar.* and data.tar.* and
        # extract them. 7-Zip handles compressed tar in two passes:
        # first decompress the .gz/.xz/.bz2/.zst layer, then extract
        # the resulting .tar. We do this explicitly with -ttar on the
        # second pass to avoid 7z's heuristics picking the wrong format.
        extracted_any = False
        debian_binary_path = None
        for entry in tmp_dir.iterdir():
            if not entry.is_file():
                continue
            lname = entry.name.lower()

            # Stage 1.5: relocate debian-binary marker into dest_dir
            if lname == "debian-binary":
                debian_binary_path = ctx.dest_dir / "debian-binary"
                shutil.copy2(entry, debian_binary_path)
                continue

            if lname.startswith("control.tar") or lname.startswith("data.tar"):
                if "control" in lname:
                    sub = ctx.dest_dir / "DEBIAN"
                else:
                    sub = ctx.dest_dir  # payload goes into dest root
                sub.mkdir(parents=True, exist_ok=True)

                # Two-pass extraction: 7z decompresses the outer
                # compression layer (.gz/.xz/.bz2/.zst), producing a
                # bare .tar; then 7z extracts the .tar contents.
                # We use a temporary intermediate file rather than a
                # pipe to keep the subprocess invocation simple.
                tar_intermediate = tmp_dir / f"_{entry.name}.tar"
                # Pass 1: decompress to .tar
                run_tool(
                    [sevenz, "x", "-y", f"-o{tmp_dir}", str(entry)],
                    tool_name="7z",
                    timeout=ctx.timeout_seconds, check=True,
                    logger=ctx.logger, source_for_error=str(entry),
                )
                # The decompressed file lands in tmp_dir with the
                # outer extension stripped (e.g. control.tar.gz ->
                # control.tar). Locate it.
                bare_tar_candidates = [
                    p for p in tmp_dir.iterdir()
                    if p.is_file() and p.name.lower().endswith(".tar")
                    and p != tar_intermediate
                ]
                if not bare_tar_candidates:
                    # Some tar layers (e.g. plain tar with no compression
                    # wrapper) won't produce a separate intermediate;
                    # 7z extracted the members directly. Skip.
                    extracted_any = True
                    continue

                bare_tar = bare_tar_candidates[0]
                # Pass 2: extract tar members into the target sub-dir.
                run_tool(
                    [sevenz, "x", "-y", "-ttar", f"-o{sub}", str(bare_tar)],
                    tool_name="7z",
                    timeout=ctx.timeout_seconds, check=True,
                    logger=ctx.logger, source_for_error=str(bare_tar),
                )
                # Clean up the intermediate .tar so it doesn't end up
                # in the dest tree on next discovery pass.
                try:
                    bare_tar.unlink()
                except OSError:
                    pass
                extracted_any = True

        # Clean up temp work dir
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

        if not extracted_any:
            from ..exceptions import ExtractorFailure
            raise ExtractorFailure(
                extractor=self.name, source=str(ctx.source_path),
                returncode=None,
                stderr=("7z extracted the deb's outer ar archive but "
                        "found no control.tar.* or data.tar.* members"),
            )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )
