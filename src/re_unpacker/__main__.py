"""
.. module:: re_unpacker.__main__
    :synopsis: ``python -m re_unpacker`` entry point.

Description
-----------
Thin shim that forwards to :func:`re_unpacker.cli.main`. Kept separate
so ``python -m re_unpacker`` works without re-running CLI code at import
time (the ``if __name__ == '__main__'`` guard inside ``cli.py`` would
not fire when imported by ``runpy``).

Notes
-----
- Keep this shim free of logic. Anything added here is invisible to the
  console-script entry point (``RE-Unpacker``) and to direct
  ``re_unpacker.main()`` calls, so behavior would diverge between the three
  documented invocation paths.
- The integer returned by :func:`re_unpacker.cli.main` is propagated as the
  process exit status, preserving the documented exit-code contract.

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import sys

from .cli import main


if __name__ == "__main__":
    sys.exit(main())
