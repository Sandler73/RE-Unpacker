# Security Policy

re-unpacker is a triage tool that deliberately operates on untrusted,
potentially malicious input. Security is a primary design concern, and reports
of vulnerabilities are taken seriously.

## Supported versions

Security fixes are applied to the latest released version. Users should track
the most recent release; older versions do not receive backported fixes.

| Version | Supported |
|---------|-----------|
| 0.4.x (latest) | Yes |
| < 0.4.0 | No |

## Reporting a vulnerability

Please report security vulnerabilities **privately**. Do not open a public
issue, pull request, or discussion for a suspected vulnerability, because doing
so discloses the issue before a fix is available.

Preferred channel:

- Use GitHub's private vulnerability reporting for this repository
  ("Security" tab, then "Report a vulnerability"), which opens a private
  advisory visible only to the maintainers and you.

If private reporting is unavailable to you, contact the maintainers through the
repository's listed contact rather than a public channel.

When reporting, please include as much of the following as you can:

- A clear description of the vulnerability and its impact.
- The affected version (`re-unpacker --version`) and platform.
- Step-by-step reproduction, including a minimal sample input if applicable.
  Do not attach live malware; describe the input characteristics or provide a
  synthetic reproducer instead.
- Any relevant log output (`extraction.log` / `errors.log`), with sensitive
  paths redacted.
- A suggested remediation if you have one.

## What to expect

- Acknowledgement of your report as promptly as the maintainers are able.
- An initial assessment of validity and severity.
- Coordination with you on a fix and a disclosure timeline. We aim to fix and
  disclose responsibly; please give us reasonable time to remediate before any
  public disclosure.
- Credit for the report in the release notes if you wish.

## Scope

In scope for a security report:

- Sandbox or containment escapes: an extraction that writes, executes, or reads
  outside the intended output tree despite the path-traversal audit.
- Command or argument injection reaching a subprocess.
- Denial of service that bypasses the timeout, quota, or bounded-output-capture
  controls (for example an extractor that hangs past its timeout, or an
  extraction that exceeds the byte / file-count ceilings without tripping
  `SafetyLimitExceeded`).
- Any code path that runs a sample's payload with the analyst's privileges
  rather than merely extracting it.

Out of scope:

- Vulnerabilities in the external extraction tools themselves (dpkg-deb,
  7-Zip, binwalk, qpdf, yara, exiftool, gpg, the libyal toolset, and so on).
  Report those to their respective upstream projects. re-unpacker's
  responsibility is to invoke them safely, not to fix them.
- The inherent risk of analyzing malicious input. Extracted artifacts may be
  malicious; that is expected, and handling them safely is the operator's
  responsibility.
- Findings that require the operator to run re-unpacker in an environment it is
  explicitly documented not to support.

## Security model summary

re-unpacker implements the following controls. A report that any of these can
be bypassed is in scope.

- **No shell.** Every extractor invocation is an `argv` list; command strings
  are never constructed from filenames, and `shell=True` is never used.
- **Per-extractor timeout.** Default 1800 seconds. On timeout, the process
  group receives `SIGTERM`, then `SIGKILL` after a short grace period.
- **Bounded output capture.** Subprocess stdout / stderr is capped (1 MiB per
  stream); truncation is flagged in the manifest.
- **Path-traversal audit.** After every extraction, extracted symlinks are
  resolved against the output root. Escaping symlinks are replaced with a
  placeholder recording the original target; escaping regular files are moved
  to a `_quarantine/` directory. Counts are surfaced in the run statistics.
- **Quota tracker.** Per-archive and run-wide byte and file-count ceilings are
  enforced; tripping one raises `SafetyLimitExceeded` and preserves partial
  output.
- **Non-mutating packer handling.** UPX and similar always operate on a copy;
  the source is never modified.
- **No privileged execution of samples.** AppImage and installer handling
  avoid executing the sample with install privileges wherever possible.

## Safe operation guidance

Operate re-unpacker in an isolated analysis environment (a disposable virtual
machine or container without access to sensitive networks or data). Treat every
extracted artifact as potentially malicious, and handle, store, and dispose of
extracted content securely.
