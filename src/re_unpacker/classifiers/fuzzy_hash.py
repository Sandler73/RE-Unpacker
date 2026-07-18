"""
.. module:: re_unpacker.classifiers.fuzzy_hash
    :synopsis: ssdeep + TLSH fuzzy hashing.

Description
-----------
Computes two fuzzy hash values per file:

- **ssdeep**: Context-Triggered Piecewise Hashing. Useful for identifying
  similar-but-not-identical files (different versions of the same binary,
  files with embedded metadata changes, etc.). Format: ``<chunksize>:<hash1>:<hash2>``.
- **TLSH**: Trend Locality Sensitive Hash. Robust against minor changes;
  good for malware family clustering. Format: ``T1<70-hex-char>``.

Implementation strategy:
- Prefer the Python bindings (``ssdeep`` Python module, ``tlsh`` Python
  module) for performance -- subprocess overhead dominates per-file
  enrichment cost when running across hundreds of files.
- Fall back to the CLI tools (``ssdeep`` binary) when bindings are
  missing. There is no canonical CLI for TLSH on Debian/Kali, so when
  the Python binding is missing, we just leave ``tlsh=None``.

Notes
-----
- ssdeep requires a minimum file size (typically 4096 bytes) to produce
  a meaningful hash. Below that, the binding raises and we record None.
- TLSH requires a minimum file size of 50 bytes AND minimum entropy /
  diversity. The binding returns None for inputs that don't meet these.

Version
-------
Added in 0.3.2.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from pathlib import Path

from ..manifest import FileEntry
from ..subprocess_utils import run_tool
from ..exceptions import ExtractorTimeout, ExtractorFailure
from .base import Classifier


# ssdeep CLI output format:
#   ssdeep,1.1--blocksize:hash:hash,"filename"
#   192:abcdef...:xyz...,"/path/to/file"
_SSDEEP_LINE_PATTERN = re.compile(
    rb'^(\d+:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+)', re.MULTILINE
)


class FuzzyHashClassifier(Classifier):
    """ssdeep + TLSH fuzzy hashing for FileEntry."""

    name = "fuzzy_hash"
    required_tools = ()  # tools optional; bindings preferred
    # Don't list as required_python_modules at the registry level, because
    # we want the classifier to be "available" if EITHER Python bindings
    # OR the CLI tool is present. is_available() does the OR check.
    required_python_modules = ()

    def is_available(self, tools) -> bool:
        # Available if any of: ssdeep CLI, ssdeep Python binding, or TLSH
        # Python binding is present. The classifier produces partial
        # results gracefully if some are missing.
        import importlib.util
        if tools.have("ssdeep"):
            return True
        if importlib.util.find_spec("ssdeep") is not None:
            return True
        if importlib.util.find_spec("tlsh") is not None:
            return True
        return False

    def classify(
        self,
        file_entry: FileEntry,
        *,
        timeout_seconds: int,
        logger: logging.Logger,
    ) -> None:
        path = Path(file_entry.path)

        # ----- ssdeep -----
        ssdeep_hash = self._compute_ssdeep(path, timeout_seconds, logger)
        if ssdeep_hash is not None:
            file_entry.ssdeep = ssdeep_hash

        # ----- TLSH -----
        tlsh_hash = self._compute_tlsh(path, logger)
        if tlsh_hash is not None:
            file_entry.tlsh = tlsh_hash

    def _compute_ssdeep(
        self,
        path: Path,
        timeout_seconds: int,
        logger: logging.Logger,
    ) -> str | None:
        # Try Python binding first.
        try:
            import ssdeep as ssdeep_lib  # type: ignore
            try:
                return ssdeep_lib.hash_from_file(str(path))
            except Exception as e:
                # ssdeep raises for files below the min-size threshold;
                # not an error worth logging at WARNING.
                logger.debug("ssdeep binding failed for %s: %s", path, e)
        except ImportError:
            pass

        # Fall back to CLI.
        try:
            result = run_tool(
                ["ssdeep", "-c", str(path)],
                tool_name="ssdeep",
                timeout=timeout_seconds,
                check=False,
                logger=logger,
            )
            if result.returncode == 0:
                m = _SSDEEP_LINE_PATTERN.search(result.stdout or b"")
                if m:
                    return m.group(1).decode("ascii", errors="replace")
        except (FileNotFoundError, ExtractorTimeout, ExtractorFailure,
                subprocess.SubprocessError, OSError) as e:
            logger.debug("ssdeep CLI failed for %s: %s", path, e)

        return None

    def _compute_tlsh(
        self,
        path: Path,
        logger: logging.Logger,
    ) -> str | None:
        # TLSH is Python-binding-only on Debian/Kali (no canonical CLI).
        try:
            import tlsh as tlsh_lib  # type: ignore
        except ImportError:
            return None

        try:
            with path.open("rb") as f:
                # TLSH bindings accept either hash(bytes) or hash_filename.
                # Some versions only have hash() taking bytes; use it.
                data = f.read()
                if hasattr(tlsh_lib, "hash"):
                    h = tlsh_lib.hash(data)
                elif hasattr(tlsh_lib, "Tlsh"):
                    t = tlsh_lib.Tlsh()
                    t.update(data)
                    t.final()
                    h = t.hexdigest()
                else:
                    return None
                # Empty hash means the input didn't meet TLSH minimums.
                if not h or h == "TNULL":
                    return None
                return h
        except Exception as e:
            logger.debug("TLSH computation failed for %s: %s", path, e)
            return None
