"""
.. module:: re_unpacker.classifiers
    :synopsis: Subsystem C: per-file enrichment (entropy / fuzzy hash / EXIF / YARA).

Description
-----------
Classifiers run AFTER extraction (and after verifiers) on each file in
the output tree, populating new optional fields on
:class:`FileEntry`. Each classifier can be disabled individually via
``--no-entropy`` / ``--no-fuzzy-hash`` / ``--no-exif`` / ``--no-yara``.

All classifiers honor:
- ``--enrich-timeout SEC`` per-pass per-file
- ``ENRICHMENT_SIZE_CAP_BYTES`` (256MB hard cap; larger files skip ALL
  classification with ``enrichment_skipped="size_exceeds_cap"``)

Pipeline order:
1. Entropy (``ent``) -- cheap; runs first
2. Encryption detection -- combines entropy threshold + magic-byte
   inspection; populates ``encrypted`` and ``encryption_scheme``
3. Fuzzy hashes -- ssdeep + TLSH (Python bindings preferred over CLI)
4. EXIF metadata -- exiftool, JSON-parsed
5. YARA -- runs last; loads rules from ``--yara-rules PATH`` or
   auto-discovery union of ``/etc/yara/``,
   ``~/.config/re-unpacker/yara/``, and YARA Forge default

Architecture mirrors verifiers and extractors:
- :mod:`base` -- :class:`Classifier` ABC + :class:`ClassificationOutcome` + registry
- :mod:`entropy` -- Shannon entropy via ``ent``
- :mod:`fuzzy_hash` -- ssdeep + TLSH via Python bindings (CLI fallback)
- :mod:`exif` -- exiftool with JSON output
- :mod:`yara_match` -- YARA rule matching (Python binding preferred)

Version
-------
Added in 0.3.2 (Subsystem C; coupled with schema bump to 1.1.0).
"""

from .base import (
    Classifier,
    ClassifierRegistry,
    build_default_classifier_registry,
)

__all__ = [
    "Classifier",
    "ClassifierRegistry",
    "build_default_classifier_registry",
]
