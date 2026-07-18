"""
.. module:: re_unpacker.classifiers.exif
    :synopsis: Format-aware metadata extraction via ``exiftool``.

Description
-----------
Wraps ``exiftool -j -G -n <file>`` to extract every metadata tag exiftool
recognizes for the file's format. Output is JSON; we parse it and store
the result as a nested dict in :attr:`FileEntry.exif_metadata`.

Despite its name, ``exiftool`` is a misnomer -- it handles far more than
EXIF: PE / Mach-O / ELF metadata, PDF document properties, MP3 / FLAC /
audio tags, archive metadata, and more. Useful for many of the kinds
extended into.

The ``-G`` flag prefixes each tag with its group (e.g. ``EXIF:Make``
becomes ``"EXIF:Make"`` in the JSON), avoiding key collisions when a
file has multiple metadata containers. ``-n`` disables print conversion
so tags retain their machine-readable form.

Notes
-----
- Some exiftool tags can be very large (embedded thumbnails, JFIF
  comments, etc.). We trim per-value to 4096 chars to keep manifests
  manageable.
- Tags whose names start with a known-noisy group (``ExifTool:`` itself,
  ``System:``) are filtered out -- they're either redundant with what we
  already record (file size, mtime) or describe exiftool itself.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from pathlib import Path

from ..manifest import FileEntry
from ..subprocess_utils import run_tool
from ..exceptions import ExtractorTimeout, ExtractorFailure
from .base import Classifier


# Tags we drop because they duplicate FileEntry fields or describe
# exiftool itself rather than the file.
_FILTERED_TAG_PREFIXES: tuple[str, ...] = (
    "ExifTool:",
    "System:FileName",
    "System:Directory",
    "System:FilePermissions",
    "System:FileModifyDate",
    "System:FileAccessDate",
    "System:FileInodeChangeDate",
    "System:FileSize",      # we track size separately
    "File:FileName",
    "File:Directory",
    "File:FileSize",
    "SourceFile",
)

# Per-value length cap. Embedded thumbnails / large comments otherwise
# bloat the manifest.
_MAX_VALUE_LENGTH: int = 4096


class ExifClassifier(Classifier):
    """exiftool-based metadata extraction."""

    name = "exif"
    required_tools = ("exiftool",)
    required_python_modules = ()

    def classify(
        self,
        file_entry: FileEntry,
        *,
        timeout_seconds: int,
        logger: logging.Logger,
    ) -> None:
        path = Path(file_entry.path)

        try:
            result = run_tool(
                ["exiftool", "-j", "-G", "-n", "-q", str(path)],
                tool_name="exiftool",
                timeout=timeout_seconds,
                check=False,
                logger=logger,
            )
        except ExtractorTimeout:
            logger.debug("exiftool timed out for %s", path)
            return
        except (ExtractorFailure, subprocess.SubprocessError, OSError) as e:
            logger.debug("exiftool invocation failed for %s: %s", path, e)
            return

        if result.returncode != 0:
            return

        # exiftool -j returns a JSON array with one object per file.
        try:
            payload = json.loads(
                (result.stdout or b"").decode("utf-8", errors="replace")
            )
        except json.JSONDecodeError as e:
            logger.debug("exiftool JSON parse failed for %s: %s", path, e)
            return

        if not isinstance(payload, list) or not payload:
            return
        raw = payload[0]
        if not isinstance(raw, dict):
            return

        # Filter and length-cap.
        filtered: dict = {}
        for key, value in raw.items():
            if any(key.startswith(p) for p in _FILTERED_TAG_PREFIXES):
                continue
            if key == "SourceFile":
                continue
            # Stringify and cap.
            if isinstance(value, (dict, list)):
                # Nested structures -- compact-serialize then cap.
                try:
                    s = json.dumps(value, ensure_ascii=False)
                except (TypeError, ValueError):
                    s = str(value)
                if len(s) > _MAX_VALUE_LENGTH:
                    s = s[:_MAX_VALUE_LENGTH] + "...[truncated]"
                filtered[key] = s
            else:
                if isinstance(value, str) and len(value) > _MAX_VALUE_LENGTH:
                    value = value[:_MAX_VALUE_LENGTH] + "...[truncated]"
                filtered[key] = value

        file_entry.exif_metadata = filtered
