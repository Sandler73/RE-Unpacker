<!--
Thanks for contributing to re-unpacker. Fill out the sections below and check
every box in the checklist. Security issues must not be submitted as a public
pull request; see SECURITY.md.
-->

## Summary

<!-- What does this change do, and why? -->

## Related issue

<!-- e.g. Closes #123 -->

## Type of change

- [ ] Bug fix
- [ ] New file format / extractor
- [ ] New verifier or classifier
- [ ] CLI / usability
- [ ] Documentation
- [ ] Packaging / CI
- [ ] Other

## How was this tested?

<!-- Commands run, sample inputs used (synthetic, not live malware), results. -->

## Checklist

- [ ] `python -m pytest` passes locally.
- [ ] `ruff check src tests` and `mypy src/re_unpacker` are clean (or deviations are justified below).
- [ ] No em-dash (U+2014) anywhere in the diff.
- [ ] No new runtime Python dependency added to `pyproject.toml`.
- [ ] Every subprocess call is argv-only, with no `shell=True`.
- [ ] New extractors / verifiers / classifiers are registered and declare `required_tools`.
- [ ] Module header blocks are present and accurate.
- [ ] Documentation (`docs/` plus the mirrored `wiki/` page) and `CHANGELOG.md` are updated.
- [ ] Magic bytes, package names, and tool flags are verified against an authoritative source.
- [ ] Security implications are considered and described.

## Notes for reviewers

<!-- Anything that needs explaining, tradeoffs made, follow-ups deferred. -->
