"""
.. module:: re_unpacker.__main__
    :synopsis: ``python -m re_unpacker`` entry point.

Description
-----------
Thin shim that forwards to :func:`re_unpacker.cli.main`. Kept separate
so ``python -m re_unpacker`` works without re-running CLI code at import
time (the ``if __name__ == '__main__'`` guard inside ``cli.py`` would
not fire when imported by ``runpy``).

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import sys

from .cli import main


if __name__ == "__main__":
    sys.exit(main())
