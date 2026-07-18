# RE-Unpacker Troubleshooting Guide

Symptom-to-fix playbooks for common problems, plus exit-code triage. For install
help see [SETUP_GUIDE.md](SETUP_GUIDE.md); for usage see
[USAGE_GUIDE.md](USAGE_GUIDE.md).

## Table of contents

1. [First steps](#first-steps)
2. [Exit-code triage](#exit-code-triage)
3. [Nothing extracted / kind detected as unknown](#nothing-extracted--kind-detected-as-unknown)
4. [A tool shows as missing](#a-tool-shows-as-missing)
5. [Extraction hangs or times out](#extraction-hangs-or-times-out)
6. [Run stops with a safety-limit error](#run-stops-with-a-safety-limit-error)
7. [Permission and privilege errors](#permission-and-privilege-errors)
8. [Windows: PATH env variable too big](#windows-path-env-variable-too-big)
9. [Windows: installed tools not detected](#windows-installed-tools-not-detected)
10. [Windows: install goes to the wrong location](#windows-install-goes-to-the-wrong-location)
11. [Windows: tool version shows as garbled text](#windows-tool-version-shows-as-garbled-text)
12. [Encrypted archives](#encrypted-archives)
13. [Reading the logs](#reading-the-logs)
14. [Filing a good bug report](#filing-a-good-bug-report)

## First steps

Before diving into a specific symptom, gather the basics:

```bash
re-unpacker --version # confirm you are on 0.5.0
re-unpacker --tools-check # confirm the toolset is present
re-unpacker --dry-run <input> # confirm the file is being detected correctly
```

Re-run the failing command with `-vv` (DEBUG) so the console shows the full
detection and dispatch trace. The file log (`extraction.log`) always records at
DEBUG regardless of console verbosity.

## Exit-code triage

| Code | Meaning | First thing to check |
|------|---------|----------------------|
| 0 | Success. Per-file errors, if any, are in the manifest. | Look at `errors.log` and the manifest `errors` list for individual extractor failures. |
| 1 | Input path invalid or unreadable. | Check the path exists and is readable; check for typos and quoting of paths with spaces. |
| 2 | A safety limit tripped. | See [safety-limit error](#run-stops-with-a-safety-limit-error). |
| 3 | `--tools-check`: one or more tools missing. | Run `--install`, or install the flagged packages manually. |
| 4 | Unexpected fatal error. | This is a bug. Capture the traceback and file an issue. |
| 5 | Privilege required. | Re-run install / uninstall / repair with root (Linux) or Administrator (Windows). |
| 6 | Package-manager error. | See the package-manager output in the log; try `--repair` or the manual apt / winget command. |

## Nothing extracted / kind detected as unknown

A run that completes with code 0 but produces little or no extracted content
usually means the file was classified as a terminal kind or the responsible
extractor was filtered out.

1. Run `re-unpacker --dry-run <input> -vv` and read the `signals` for the file.
   The signals show exactly why it was classified as it was (magic, file
   description, extension).
2. If the kind is correct but no extraction happened, the extractor for that
   kind likely needs a tool that is not installed. Run `--tools-check` and
   install the tool named in the format's row of the README supported-formats
   table.
3. If the kind is `UNKNOWN_BINARY`, the built-in binwalk fallback runs by
   default. Confirm binwalk is installed; if it declined (no embedded
   signatures), there is genuinely nothing to carve.
4. If the kind is `LUKS_ENCRYPTED` or `ENCRYPTED_GENERIC`, see
   [encrypted archives](#encrypted-archives). These are classify-only by design.

## A tool shows as missing

`--tools-check` reports a tool as MISSING when its binary is not found on PATH
(and, on Windows, not found in the well-known install directories RE-Unpacker
probes).

- **Linux:** install the package. `--tools-check` prints the exact apt package
  name, or run `sudo re-unpacker --install --yes` to install everything missing.
- **Windows:** run `.\re-unpacker.ps1 --install --yes` from an elevated shell.
  Tools with no winget package are handled by the manual-install handlers;
  tools with no Windows distribution at all are shown with a manual-install hint
  and are expected to remain missing.

A missing tool is not fatal to an extraction run. The orchestrator filters
extractors whose required tools are absent and continues with what is present.

## Extraction hangs or times out

Each extraction is bounded by `--timeout` (default 1800 seconds). On timeout,
the process group is sent `SIGTERM`, then `SIGKILL` after a short grace period,
and the next candidate extractor is tried. A recorded `ExtractorTimeout` in the
manifest is the expected, safe outcome, not a crash.

- If a specific large disk image legitimately needs more time, raise
  `--timeout`.
- If a malicious archive is designed to hang, the timeout is doing its job;
  the run continues and the timeout is recorded.

## Run stops with a safety-limit error

Exit code 2 with `SafetyLimitExceeded` means a byte or file-count ceiling was
tripped. The partial output and manifest are preserved.

- Raise the relevant ceiling if the input is legitimately large:
  `--max-extracted-size`, `--max-total-size`, or `--max-files`.
- Keep the ceilings low when triaging untrusted input on a constrained rig; a
  decompression bomb tripping the limit is the intended behavior.

## Permission and privilege errors

Exit code 5 means an install, uninstall, or repair was invoked without the
required privilege.

- **Linux:** prefix with `sudo`.
- **Windows:** run the launcher from an elevated (Administrator) PowerShell or
  cmd session. Machine-scope installs write to `Program Files`, which requires
  elevation.

Extract mode itself does not require root. Some Linux forensic-filesystem
extractors that FUSE-mount images do require root; when run unprivileged, those
extractors are filtered and other extractors for the same kind (or the
qemu-img conversion path) are used instead.

## Windows: PATH env variable too big

If you see a modal Windows dialog reading "PATH env variable too big", your
system PATH has grown past the legacy 2047-character REG_SZ limit, usually from
cumulative additions across many installs (not just RE-Unpacker's).

RE-Unpacker 0.4.7+ detects this and refuses to write to the registry PATH,
printing a diagnostic instead of triggering the dialog. RE-Unpacker still finds
its own tools because it probes `C:\Program Files\re-unpacker\bin\` directly.

To let external shells see the tools again, clean up PATH:

1. Open System Properties, then Environment Variables (or run
   `SystemPropertiesAdvanced` and click Environment Variables).
2. Edit the system `Path`. Remove duplicate entries and entries that point to
   directories that no longer exist. The diagnostic RE-Unpacker printed lists
   examples of both.
3. Ensure `C:\Program Files\re-unpacker\bin` is present.
4. Re-run `.\re-unpacker.ps1 --install` if needed.

RE-Unpacker only self-cleans PATH entries it created; it will not remove other
software's entries automatically, but it identifies them so you can act.

## Windows: installed tools not detected

Immediately after an install, a following `--tools-check` in the same shell may
report just-installed tools as missing. This is a Windows PATH-propagation
timing issue: HKLM PATH updates reach only new processes after a settings-change
broadcast, and children of an already-running shell inherit the old PATH.

RE-Unpacker 0.4.6+ works around this by probing the install directory and the
Python Scripts directories directly, so its own runs find the tools regardless.
If an external shell still cannot see a tool, open a fresh shell (or sign out
and back in) so it inherits the updated PATH.

## Windows: install goes to the wrong location

If winget-installed tools land under `%LocalAppData%` instead of `Program
Files`, you are on a version before 0.4.8. RE-Unpacker 0.4.8 added
`--scope machine` to winget installs so tools land in `Program Files`. Update to
the latest release. Tools that genuinely cannot install machine-scope will surface an explicit
error rather than silently falling back to user scope.

## Windows: tool version shows as garbled text

If `--tools-check` shows a tool version as replacement characters or mojibake
(for example for Sysinternals sigcheck), you are on a version before the
byte-level BOM decoder landed. RE-Unpacker 0.4.6+ detects UTF-16 / UTF-32 / UTF-8
BOMs at the byte level before decoding subprocess output. Update to the latest
release.

## Encrypted archives

RE-Unpacker detects encrypted content and classifies it, but does not attempt
password recovery. Kinds `LUKS_ENCRYPTED` and `ENCRYPTED_GENERIC` (encrypted
RAR / 7z / DMG) are terminal: they are recorded in the manifest with the
detected encryption scheme, and recursion stops there. Decrypt the content out
of band with the correct key, then run RE-Unpacker on the decrypted result.

## Reading the logs

Every run writes two logs to the output root:

- `extraction.log` -- full DEBUG trace of detection, dispatch, and per-file
  results. This is the first place to look for why a specific file behaved as it
  did.
- `errors.log` -- warnings and above only, for quick triage of what went wrong
  without the DEBUG noise.

The `manifest.jsonl` is the structured record. To pull just the errors:

```bash
jq -c 'select(.record_type == "error")' out/manifest.jsonl
```

## Filing a good bug report

Open an issue with the bug-report template and include:

- `re-unpacker --version` output and your platform.
- The exact command you ran.
- The relevant `extraction.log` / `errors.log` excerpt (redact sensitive
  paths).
- A description of the input (kind, source), or a synthetic reproducer. Do not
  attach live malware.
- What you expected versus what happened.

For a suspected security vulnerability, do not open a public issue; follow
[SECURITY.md](../SECURITY.md) instead.
