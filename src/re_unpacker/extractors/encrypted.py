"""
.. module:: re_unpacker.extractors.encrypted
    :synopsis: Encrypted-formats terminal classifier.

Description
-----------
Encrypted formats are **terminal-classify only**. RE-Unpacker never:

- Prompt for passwords (would break automation)
- Try empty / dictionary passwords (out of scope)
- Guess passwords (out of scope)

This module exists for documentation / completeness; it does NOT register
any extractor against EXTRACTABLE encrypted kinds, because the kinds
``LUKS_ENCRYPTED`` and ``ENCRYPTED_GENERIC`` are already excluded from
:data:`re_unpacker.detection.EXTRACTABLE_KINDS`. The orchestrator's
recursion engine will not invoke any extractor on them, and the manifest
records them with their kind tag plus a ``terminal:encrypted`` signal.

A future opt-in keyfile/passphrase mechanism (``--keys FILE``) would
carry its keyed extractors here. The module's present purpose is purely
documentary.

Notes
-----
- A future encrypted-but-keyed extractor would set
  ``handles_kinds = frozenset({FileKind.LUKS_ENCRYPTED})`` and the
  orchestrator's dispatch would need to be paired with adding that kind
  back into EXTRACTABLE_KINDS conditionally.
- Detection of encryption happens at the magic / file(1) layer (see
  :mod:`re_unpacker.detection`); this module never runs.

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

# Intentional: no extractors are registered here.
# The classification is done in detection.py and surfaces in the manifest
# via the FileKind value (LUKS_ENCRYPTED / ENCRYPTED_GENERIC) and the
# 'terminal:encrypted' signal.

__all__ = ()
