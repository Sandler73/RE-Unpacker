"""
.. module:: re_unpacker
    :synopsis: Recursive package / installer / archive / binary extractor.

Description
-----------
A tool for reverse engineers: hand it a file or a directory of files,
and it will recursively pull apart every archive, package, installer,
filesystem image, compressed stream, and packed binary it can recognize,
writing a structured tree of extracted content plus a manifest describing
everything it found.

The package is pure standard-library Python. Extraction itself is performed
by external system binaries, which are probed at runtime; a missing tool
disables the handlers that need it rather than failing the run.

Public API
----------
Most users interact via the command line; programmatic use is also
supported:

    from re_unpacker import main as cli_main
    exit_code = cli_main(["./sample.deb", "-o", "./out"])

For direct use of the orchestrator::

    from re_unpacker.orchestrator import RecursiveUnpacker
    # See cli._run_normal for the full construction pattern.

Notes
-----
- This module deliberately exports a small surface (``main``,
  ``PROJECT_NAME``, ``SCHEMA_VERSION``, ``VERSION``). Subsystems are imported
  from their own modules so that importing the package does not pull in every
  extractor, verifier, and classifier.
- ``VERSION`` is the single source of truth for the framework version and is
  re-exported here as ``__version__``. Module headers quote it but never
  redefine it.
- ``SCHEMA_VERSION`` versions the manifest data contract and moves
  independently of the tool version; consumers should key compatibility
  checks off the schema, not the release.

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from .cli import main
from .constants import PROJECT_NAME, SCHEMA_VERSION, VERSION

__all__ = ["main", "PROJECT_NAME", "SCHEMA_VERSION", "VERSION"]
__version__ = VERSION
