"""
.. module:: tests.test_exceptions
    :synopsis: Exception-hierarchy and attribute invariants.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from re_unpacker import exceptions as E


def test_hierarchy():
    assert issubclass(E.ValidationError, E.UnpackerError)
    assert issubclass(E.ToolMissingError, E.UnpackerError)
    assert issubclass(E.ExtractionError, E.UnpackerError)
    assert issubclass(E.ExtractorNotApplicable, E.ExtractionError)
    assert issubclass(E.ExtractorFailure, E.ExtractionError)
    assert issubclass(E.ExtractorTimeout, E.ExtractionError)
    assert issubclass(E.SafetyLimitExceeded, E.UnpackerError)
    assert issubclass(E.PathTraversalError, E.UnpackerError)


def test_not_applicable_and_failure_are_distinct():
    # The dispatch chain relies on these being catchable separately.
    assert not issubclass(E.ExtractorNotApplicable, E.ExtractorFailure)
    assert not issubclass(E.ExtractorFailure, E.ExtractorNotApplicable)


def test_safety_limit_exceeded_attributes():
    exc = E.SafetyLimitExceeded("max_total_bytes", 100, 150)
    assert exc.limit_name == "max_total_bytes"
    assert exc.limit_value == 100
    assert exc.observed == 150
    assert "max_total_bytes" in str(exc)


def test_path_traversal_error_attributes():
    exc = E.PathTraversalError(path="/evil/../etc/passwd", output_root="/out")
    assert exc.path == "/evil/../etc/passwd"
    assert exc.output_root == "/out"
    assert "escapes output root" in str(exc)


def test_all_derive_from_base():
    for name in dir(E):
        obj = getattr(E, name)
        if isinstance(obj, type) and issubclass(obj, Exception) and obj is not Exception:
            if obj.__module__ == E.__name__ and obj is not E.UnpackerError:
                assert issubclass(obj, E.UnpackerError), name
