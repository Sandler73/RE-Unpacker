"""
re-unpacker -- recursive package / installer / archive / binary extractor.

A tool for reverse engineers: hand it a file or a directory of files,
and it will recursively pull apart every archive, package, installer,
filesystem image, compressed stream, and packed binary it can recognize,
writing a structured tree of extracted content plus a manifest describing
everything it found.

Public API
----------
Most users interact via the command line; programmatic use is also
supported:

    from re_unpacker import main as cli_main
    exit_code = cli_main(["./sample.deb", "-o", "./out"])

For direct use of the orchestrator::

    from re_unpacker.orchestrator import RecursiveUnpacker
    # See cli._run_normal for the full construction pattern.

Version
-------
See :data:`VERSION`.
"""

from __future__ import annotations

from .cli import main
from .constants import PROJECT_NAME, SCHEMA_VERSION, VERSION

__all__ = ["main", "PROJECT_NAME", "SCHEMA_VERSION", "VERSION"]
__version__ = VERSION
