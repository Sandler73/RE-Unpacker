"""
.. module:: tests.conftest
    :synopsis: Shared pytest fixtures and import-path setup for the suite.

Description
-----------
Prepends the bundled ``src/`` directory to ``sys.path`` so the ``re_unpacker``
package imports without an editable install, mirroring what the bundled
wrappers do at runtime. Provides small shared fixtures (a probed tool registry
and a throwaway logger) used across the unit tests.

Notes
-----
The suite is written to pass without the external extraction binaries present.
Detection and registry behavior degrade gracefully when a tool is absent, and
tests assert on that degraded-but-correct behavior rather than requiring a
fully provisioned host.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

# Make the package importable straight from the clone (no install required).
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="session")
def tool_registry():
    """A probed, frozen tool registry. Tools absent on the host are simply
    reported unavailable; nothing here requires a specific binary."""
    from re_unpacker.tools import build_and_probe_registry

    return build_and_probe_registry(logger=logging.getLogger("test.tools"))


@pytest.fixture()
def quiet_logger():
    """A logger that discards output, for functions that require one."""
    log = logging.getLogger("test.quiet")
    log.addHandler(logging.NullHandler())
    log.propagate = False
    return log
