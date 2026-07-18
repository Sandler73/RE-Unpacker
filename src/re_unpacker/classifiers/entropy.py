"""
.. module:: re_unpacker.classifiers.entropy
    :synopsis: Shannon entropy via ``ent`` (or pure-Python fallback).

Description
-----------
Computes a single Shannon-entropy value (bits per byte, range 0.0 to
8.0) for each file. High entropy (>= 7.5) is a strong signal of
encryption or already-compressed content; downstream pipelines use this
to flag suspicious-looking blobs in extracted output.

Implementation strategy: prefer the ``ent`` CLI tool because it's well-
calibrated and matches industry practice. Fall back to a pure-Python
implementation when ``ent`` is missing -- entropy is cheap enough to
compute in-process even for hundreds of files at the 256MB cap.

Also populates the ``encrypted`` and ``encryption_scheme`` fields based
on a combined heuristic of:
- Entropy >= 7.5 (very high)
- Magic bytes match a known encrypted-format pattern (LUKS, encrypted
  ZIP, encrypted RAR, etc.)
- Existing kind already a known encrypted classification (LUKS_ENCRYPTED,
  ENCRYPTED_GENERIC) -- short-circuits the heuristic

Version
-------
Added in 0.3.2.
"""

from __future__ import annotations

import logging
import math
import re
import subprocess
import time
from collections import Counter
from pathlib import Path

from ..manifest import FileEntry
from ..subprocess_utils import run_tool
from ..exceptions import ExtractorTimeout, ExtractorFailure
from .base import Classifier


_ENT_ENTROPY_PATTERN = re.compile(
    rb"Entropy = ([0-9.]+) bits per byte", re.IGNORECASE
)

# Threshold for the entropy-based encryption heuristic. Empirical values:
# - Plain text: 4.0 to 5.0
# - Compressed (gzip / zip): 7.8 to 7.95
# - Encrypted: 7.95 to 7.999
# - Random: ~8.0
# We use 7.5 as a permissive threshold so compressed content also flags;
# the magic-byte check then narrows to actual encryption schemes.
_ENCRYPTION_ENTROPY_THRESHOLD: float = 7.5

# FileKinds that are already classified as encrypted; we just propagate.
_ALREADY_ENCRYPTED_KINDS = frozenset({
    "LUKS_ENCRYPTED",
    "ENCRYPTED_GENERIC",
})


class EntropyClassifier(Classifier):
    """Shannon entropy + encryption-heuristic classification."""

    name = "entropy"
    required_tools = ()  # ent is preferred but not strictly required
    required_python_modules = ()

    def is_available(self, tools) -> bool:
        # Always available -- we have a pure-Python fallback. The CLI tool
        # is preferred but optional.
        return True

    def classify(
        self,
        file_entry: FileEntry,
        *,
        timeout_seconds: int,
        logger: logging.Logger,
    ) -> None:
        path = Path(file_entry.path)

        # Short-circuit for already-classified encrypted kinds.
        if file_entry.kind in _ALREADY_ENCRYPTED_KINDS:
            file_entry.encrypted = True
            if file_entry.kind == "LUKS_ENCRYPTED":
                file_entry.encryption_scheme = "luks"
            else:
                file_entry.encryption_scheme = "generic"
            # Still compute entropy for the manifest record.

        try:
            entropy = self._compute_entropy(
                path, timeout_seconds=timeout_seconds, logger=logger,
            )
        except Exception as e:
            logger.debug(
                "Entropy computation failed for %s: %s", path, e,
            )
            return

        if entropy is None:
            return
        file_entry.entropy = round(entropy, 4)

        # Encryption heuristic for files NOT already classified.
        if file_entry.kind not in _ALREADY_ENCRYPTED_KINDS:
            if entropy >= _ENCRYPTION_ENTROPY_THRESHOLD:
                # High entropy alone isn't proof of encryption (could be
                # compressed). Cross-check magic bytes for actual encrypted
                # signatures.
                scheme = self._detect_encryption_scheme(path)
                if scheme is not None:
                    file_entry.encrypted = True
                    file_entry.encryption_scheme = scheme
                else:
                    # High entropy but no encrypted signature -> probably
                    # already compressed; not flagged as encrypted.
                    file_entry.encrypted = False
            else:
                file_entry.encrypted = False

    def _compute_entropy(
        self,
        path: Path,
        *,
        timeout_seconds: int,
        logger: logging.Logger,
    ) -> float | None:
        """Try ``ent`` CLI first; fall back to pure-Python on failure."""
        # CLI path
        try:
            result = run_tool(
                ["ent", str(path)],
                tool_name="ent",
                timeout=timeout_seconds,
                check=False,
                logger=logger,
            )
            if result.returncode == 0:
                m = _ENT_ENTROPY_PATTERN.search(result.stdout or b"")
                if m:
                    return float(m.group(1))
        except (FileNotFoundError, ExtractorTimeout, ExtractorFailure,
                subprocess.SubprocessError, OSError):
            pass

        # Pure-Python fallback
        try:
            counts: Counter[int] = Counter()
            total = 0
            with path.open("rb") as f:
                # Stream in chunks to avoid loading multi-hundred-MB files.
                while True:
                    chunk = f.read(1 << 20)  # 1 MiB
                    if not chunk:
                        break
                    counts.update(chunk)
                    total += len(chunk)
            if total == 0:
                return 0.0
            entropy = 0.0
            for count in counts.values():
                p = count / total
                entropy -= p * math.log2(p)
            return entropy
        except OSError:
            return None

    @staticmethod
    def _detect_encryption_scheme(path: Path) -> str | None:
        """Inspect magic bytes for known encryption signatures.

        Returns a short scheme name ("zip-aes", "rar5-encrypted", "gpg",
        etc.) or None if no encrypted signature is detected.
        """
        try:
            with path.open("rb") as f:
                head = f.read(64)
        except OSError:
            return None
        if not head:
            return None

        # GPG / OpenPGP: octet 0x85 / 0x95 / 0xC1 / 0xD1 (variable based
        # on packet tag); the most common is 0x85 0x01 (public-key-encrypted
        # session key, packet tag 1).
        if head[0:1] in (b"\x85", b"\x95", b"\xC1", b"\xD1"):
            # Heuristic; could refine by parsing the OpenPGP packet header.
            return "gpg"
        # ZIP with AE-x encryption: ZIP signature with encryption flag set.
        # Detection requires parsing the central directory; defer to v0.4+.
        # RAR 5 with encryption: signature 52 61 72 21 1A 07 01 00 followed
        # by encryption header marker 04 01 (CRYPT block).
        if head[0:8] == b"Rar!\x1a\x07\x01\x00" and b"\x04\x01" in head[8:32]:
            return "rar5-encrypted"
        # Encrypted 7z files start with the standard 7z magic but have the
        # encryption flag in the header; cheap detection requires header
        # parsing. Defer.
        # Age (modern encrypted file format): "age-encryption.org/v1"
        if head.startswith(b"age-encryption.org/v1"):
            return "age"
        return None
