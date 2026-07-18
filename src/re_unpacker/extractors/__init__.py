"""
.. module:: re_unpacker.extractors
    :synopsis: Extractor subsystem: format handlers and the dispatch registry.

Description
-----------
Package namespace for every format-specific extractor plus the registry that
the orchestrator dispatches through. One module per format family (archive,
deb, rpm, msi, cab, disk_image, forensic_fs, embedded_fs, android, pdf,
resources, upx, encrypted, and so on); :mod:`re_unpacker.extractors.base`
holds the abstract :class:`~re_unpacker.extractors.base.Extractor` contract,
the :class:`~re_unpacker.extractors.base.ExtractorRegistry`, and
:func:`~re_unpacker.extractors.base.build_default_registry`, which assembles
the shipped extractor set.

This package intentionally exports nothing at the namespace level. Importing
every extractor module here would create import cycles (extractors import
:mod:`re_unpacker.manifest` and :mod:`re_unpacker.tools`, which in turn import
detection) and would pay the cost of loading all handlers even for a run that
touches one format. Consumers import the specific module they need, or call
``build_default_registry()`` for the assembled set.

Notes
-----
- An extractor is selected by declared :class:`~re_unpacker.detection.FileKind`
  coverage and ``priority``, and is filtered out when its ``required_tools``
  are absent from the tool registry. That filtering is how platform-specific
  handlers coexist in one source tree.
- Extractors signal "not my job" with ``ExtractorNotApplicable`` (silent, the
  dispatcher tries the next candidate) and genuine failure with
  ``ExtractorFailure`` (recorded in the manifest). Honoring that distinction
  is what keeps the manifest error list meaningful.
- Secondary extractors (PE resources, ELF sections) run alongside the primary
  extraction rather than instead of it, and set ``is_secondary = True``.

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""
