"""
.. module:: re_unpacker.verifiers.deb
    :synopsis: Debian-package signature/integrity verifiers.

Description
-----------
Three distinct verification mechanisms exist for ``.deb`` files; runs all that are available against any DEB kind file.

- :class:`DebsigsVerifier` -- embedded signatures inside the .deb
  container itself (rare in practice; mostly Debian-internal).
- :class:`DpkgSigVerifier` -- alternative signature scheme using detached
  signatures stored inside the .deb's ``debian-binary`` member structure.
  Even rarer than debsigs.
- :class:`DebsumsVerifier` -- post-install md5sum integrity check. Only
  meaningful AFTER a deb has been extracted; runs against the
  extracted ``DEBIAN/md5sums`` companion if present.

All three are best-effort: missing tools or unsupported deb structures
record ``performed=false``.

Notes
-----
- Three mechanisms exist for Debian packages and they check different things:
  ``debsigs`` and ``dpkg-sig`` validate an embedded package signature, while
  ``debsums`` compares installed files against recorded digests.
- ``debsums`` fundamentally operates on installed packages, so it cannot
  verify a loose ``.deb`` on disk; it is registered but disabled rather than
  silently reporting a misleading result.
- Most distribution ``.deb`` files carry no embedded signature at all, since
  Debian's trust model signs the repository index rather than each package.
  An unsigned result is therefore normal, not suspicious.

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


_DEBSIGS_VALID_PATTERN = re.compile(rb"Good signature found")
_DEBSIGS_BAD_PATTERN = re.compile(rb"BAD signature|Could not verify")


class DebsigsVerifier(Verifier):
    """Verify embedded signatures in .deb files via ``debsigs --verify``."""

    name = "debsigs"
    required_tools = ("debsigs",)

    def applies_to(self, file_entry: FileEntry) -> bool:
        return file_entry.kind == "DEB"

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

        try:
            run_result = run_tool(
                ["debsigs", "--verify", file_entry.path],
                tool_name="debsigs",
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
            result.duration_seconds = time.monotonic() - start
            return result

        # debsigs exit codes:
        # 0 -> at least one good signature
        # non-zero -> no valid signature found (could be unsigned OR
        # could be signed-but-invalid)
        stdout_stderr = (
            (run_result.stdout or b"") + (run_result.stderr or b"")
        )

        if run_result.returncode == 0 and _DEBSIGS_VALID_PATTERN.search(stdout_stderr):
            result.signed = True
            result.valid = True
            # debsigs doesn't always print the signer in a parseable form;
            # leave signer=None unless we can extract it cleanly.
        elif _DEBSIGS_BAD_PATTERN.search(stdout_stderr):
            result.signed = True
            result.valid = False
            result.error = "bad_signature"
        else:
            # No signature at all, or unrecognized output -- treat as
            # unsigned (the more conservative interpretation).
            result.signed = False
            result.valid = None

        result.duration_seconds = time.monotonic() - start
        return result


class DpkgSigVerifier(Verifier):
    """Verify alternative deb signature scheme via ``dpkg-sig --verify``."""

    name = "dpkg-sig"
    required_tools = ("dpkg-sig",)

    def applies_to(self, file_entry: FileEntry) -> bool:
        return file_entry.kind == "DEB"

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

        try:
            run_result = run_tool(
                ["dpkg-sig", "--verify", file_entry.path],
                tool_name="dpkg-sig",
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
            result.duration_seconds = time.monotonic() - start
            return result

        stdout = (run_result.stdout or b"").decode(
            "utf-8", errors="replace"
        )

        # dpkg-sig output format: one line per signature attempt, e.g.
        # "Processing <file>...
        # GOODSIG _gpgbuilder 0x12345678 1234567890"
        if "GOODSIG" in stdout:
            result.signed = True
            result.valid = True
        elif "BADSIG" in stdout:
            result.signed = True
            result.valid = False
            result.error = "bad_signature"
        elif "NOSIG" in stdout or run_result.returncode != 0:
            result.signed = False
            result.valid = None

        result.duration_seconds = time.monotonic() - start
        return result


class DebsumsVerifier(Verifier):
    """Verify deb integrity via ``debsums``.

    NOTE: debsums fundamentally operates on INSTALLED packages
    (it consults /var/lib/dpkg/info/<pkg>.md5sums on a live system), not
    on .deb files at rest. RE-Unpacker's typical use case is .deb files
    that have not been installed -- so for, this verifier is
    registered for completeness and tool-tracking purposes but always
    returns applicable=False (does not produce a manifest entry).

    A future version may revisit this with a different code path that
    extracts md5sums from the .deb's DEBIAN/md5sums entry directly and
    verifies the embedded files against it -- a useful integrity check
    that doesn't require installation. Out of scope for.
    """

    name = "debsums"
    required_tools = ("debsums",)

    def applies_to(self, file_entry: FileEntry) -> bool:
        # Disabled -- see class docstring.
        return False

    def verify(
        self,
        file_entry: FileEntry,
        *,
        timeout_seconds: int,
        logger: logging.Logger,
    ) -> VerifierResult:
        # Should never be called because applies_to() returns False, but
        # implement defensively in case the orchestrator's filter logic
        # is bypassed in a future change.
        result = VerifierResult(
            verifier_name=self.name, performed=False, applicable=False,
        )
        return result
