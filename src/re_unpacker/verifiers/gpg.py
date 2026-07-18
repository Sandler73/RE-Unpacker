"""
.. module:: re_unpacker.verifiers.gpg
    :synopsis: GpgVerifier -- detached signature verification.

Description
-----------
Detects the presence of a detached signature companion (``.sig`` or
``.asc``) for any file in the output tree and runs ``gpgv`` (preferred
over ``gpg --verify`` for being more deterministic and not consulting the
agent / pinentry path).

Notes
-----
- Only checks against the user's existing keyring. does NOT manage
  GPG keys (no key import / refresh). If the signing key isn't already in
  the keyring, the result records ``signed=true, valid=false,
  error="no_pubkey"``.
- A file ``foo.deb`` triggers verification iff ``foo.deb.sig`` or
  ``foo.deb.asc`` exists alongside it.

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
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
from .base import Verifier, VerifierResult


_SIG_SUFFIXES = (".sig", ".asc")
_GPGV_GOOD_SIG_PATTERN = re.compile(rb'Good signature from "([^"]+)"')


class GpgVerifier(Verifier):
    """Detached-signature verification via ``gpgv``."""

    name = "gpgv"
    required_tools = ("gpgv",)

    def applies_to(self, file_entry: FileEntry) -> bool:
        # Trigger only when a sibling .sig or .asc exists for this file.
        path = Path(file_entry.path)
        return any(
            path.with_name(path.name + suffix).exists()
            for suffix in _SIG_SUFFIXES
        )

    def verify(
        self,
        file_entry: FileEntry,
        *,
        timeout_seconds: int,
        logger: logging.Logger,
    ) -> VerifierResult:
        result = VerifierResult(
            verifier_name=self.name, performed=True, applicable=True,
        )
        start = time.monotonic()

        path = Path(file_entry.path)
        sig_path: Path | None = None
        for suffix in _SIG_SUFFIXES:
            candidate = path.with_name(path.name + suffix)
            if candidate.exists():
                sig_path = candidate
                break
        if sig_path is None:
            # Should not happen if applies_to was honored, but be defensive.
            result.applicable = False
            result.performed = False
            result.duration_seconds = time.monotonic() - start
            return result

        try:
            run_result = run_tool(
                ["gpgv", str(sig_path), str(path)],
                tool_name="gpgv",
                timeout=timeout_seconds,
                check=False,
                logger=logger,
            )
        except ExtractorTimeout:
            result.error = "timeout"
            result.duration_seconds = time.monotonic() - start
            return result
        except (ExtractorFailure, subprocess.SubprocessError, OSError) as e:
            result.error = type(e).__name__
            logger.debug("gpgv invocation failed for %s: %s", path, e)
            result.duration_seconds = time.monotonic() - start
            return result

        # gpgv exit code semantics:
        # 0 = signature valid
        # 1 = signature invalid (or no public key, or other "signed but
        # can't fully verify" condition)
        # 2 = error (file not found, bad invocation, etc.)
        result.signed = True  # a .sig/.asc file was present, so it's signed
        if run_result.returncode == 0:
            result.valid = True
            # Try to extract signer identity from stderr.
            match = _GPGV_GOOD_SIG_PATTERN.search(run_result.stderr or b"")
            if match:
                result.signer = match.group(1).decode("utf-8", errors="replace")
        else:
            result.valid = False
            # Common failure modes worth distinguishing in the error field.
            stderr = (run_result.stderr or b"").decode(
                "utf-8", errors="replace"
            )
            if "No public key" in stderr or "no pubkey" in stderr.lower():
                result.error = "no_pubkey"
            elif "BAD signature" in stderr:
                result.error = "bad_signature"
            else:
                result.error = f"rc={run_result.returncode}"

        result.duration_seconds = time.monotonic() - start
        return result
