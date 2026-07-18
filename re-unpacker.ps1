<#
.SYNOPSIS
    re-unpacker PowerShell wrapper for Windows.

.DESCRIPTION
    Adds the bundled 'src/' directory to PYTHONPATH and runs
    `python -m re_unpacker`. Mirrors the Linux bash wrapper's behavior
    so the tool's CLI surface is identical across platforms.

    Cross-platform context (v0.4.0):
      - re-unpacker          : bash wrapper for Linux / macOS
      - re-unpacker.ps1      : this PowerShell wrapper for Windows
      - re-unpacker.cmd      : cmd.exe shim for users without PowerShell

    All three forward arguments verbatim to the Python entry point. The
    Python module itself runs identically on Linux and Windows; this
    wrapper just ensures src/ is on PYTHONPATH so the package imports
    cleanly without `pip install`.

    Requires:
      - Python 3.10 or newer on PATH (winget install Python.Python.3.12,
        or any equivalent install)
      - PowerShell 5.1 (built into Windows 10+) or PowerShell 7+

.PARAMETER Args
    All arguments are forwarded verbatim to the Python entry point.
    See `re-unpacker.ps1 --help` for the full CLI surface (37 argparse actions;
    identical to the Linux bash wrapper's surface).

.EXAMPLE
    PS> .\re-unpacker.ps1 sample.cab
    Extract a single Microsoft Cabinet file using the default output
    directory (./re-unpacked/).

.EXAMPLE
    PS> .\re-unpacker.ps1 .\samples\ -o C:\scratch\out -j 4
    Extract every recognized archive in .\samples\ to C:\scratch\out
    using 4 parallel workers.

.EXAMPLE
    PS> .\re-unpacker.ps1 --tools-check
    Print the platform-appropriate tool inventory (56 Windows tools)
    showing which are present, missing, or have version-probe errors.

.EXAMPLE
    PS> .\re-unpacker.ps1 --install
    Run winget to install all missing winget-managed tools. Requires
    Administrator elevation.

.NOTES
    Requires Python 3.10+ on PATH.
    Author: Anthropic / re-unpacker contributors.
    Version: 0.4.9

.LINK
    See README.md and ReUnpacker-Usage-Guide.html for full documentation.
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

# Resolve the script's own directory so the wrapper works from any cwd.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$SrcDir    = Join-Path $ScriptDir 'src'

if (-not (Test-Path -LiteralPath (Join-Path $SrcDir 're_unpacker') -PathType Container)) {
    Write-Error "cannot find package source at $SrcDir\re_unpacker"
    exit 4
}

# Locate Python on PATH. Prefer 'python' (winget convention); fall back
# to 'python3' for users with mixed environments.
$PythonExe = $null
foreach ($candidate in @('python', 'python3', 'py')) {
    $resolved = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($resolved) {
        $PythonExe = $resolved.Source
        break
    }
}
if (-not $PythonExe) {
    Write-Error @"
Python 3.10+ not found on PATH.

Install one of:
  - Microsoft Store Python (search 'Python' in the Store)
  - winget install Python.Python.3.12
  - https://www.python.org/downloads/windows/
"@
    exit 4
}

# Prepend, don't overwrite, any user PYTHONPATH. Use ';' separator on
# Windows (vs ':' on POSIX); pathlib handles both transparently.
$existingPP = [Environment]::GetEnvironmentVariable('PYTHONPATH', 'Process')
if ($existingPP) {
    $env:PYTHONPATH = "$SrcDir;$existingPP"
} else {
    $env:PYTHONPATH = $SrcDir
}

# Forward arguments. PowerShell arg-passing semantics differ from POSIX
# shells; using the splat operator (@Arguments) preserves quoting for
# arguments containing spaces (e.g. paths with whitespace).
& $PythonExe '-m' 're_unpacker' @Arguments
exit $LASTEXITCODE
