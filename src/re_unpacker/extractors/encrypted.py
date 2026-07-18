"""
.. module:: re_unpacker.extractors.encrypted
    :synopsis: Encrypted-formats terminal classifier.

Description
-----------
Per the v0.3.0 user decision, encrypted formats are **terminal-classify
only**. We never:

- Prompt for passwords (would break automation)
- Try empty / dictionary passwords (out of scope)
- Guess passwords (out of scope)

This module exists for documentation / completeness; it does NOT register
any extractor against EXTRACTABLE encrypted kinds, because the kinds
``LUKS_ENCRYPTED`` and ``ENCRYPTED_GENERIC`` are already excluded from
:data:`re_unpacker.detection.EXTRACTABLE_KINDS`. The orchestrator's
recursion engine will not invoke any extractor on them, and the manifest
records them with their kind tag plus a ``terminal:encrypted`` signal.

Future v0.4.x or later may add an opt-in keyfile/passphrase mechanism
(``--keys FILE``); this module would then carry the keyed extractors.
For v0.3.0, the purpose is purely documentary.

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
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

# Intentional: no extractors registered in v0.3.0.
# The classification is done in detection.py and surfaces in the manifest
# via the FileKind value (LUKS_ENCRYPTED / ENCRYPTED_GENERIC) and the
# 'terminal:encrypted' signal.

__all__ = ()
