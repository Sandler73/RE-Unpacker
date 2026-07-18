@echo off
REM ============================================================================
REM  re-unpacker -- cmd.exe shim for Windows
REM
REM  SYNOPSIS
REM    re-unpacker.cmd [OPTIONS] INPUT
REM
REM  DESCRIPTION
REM    Minimal cmd.exe wrapper for users who don't run PowerShell. Sets
REM    PYTHONPATH to point at the bundled src\re_unpacker package and
REM    invokes `python -m re_unpacker` with all arguments forwarded.
REM
REM    Prefer re-unpacker.ps1 when possible -- the PowerShell wrapper has
REM    richer error messages and Get-Help integration. This cmd shim is
REM    for environments where PowerShell is unavailable or restricted by
REM    execution policy.
REM
REM  EXECUTION PARAMETERS
REM    All arguments after the script name are forwarded verbatim to the
REM    Python entry point. See `re-unpacker.cmd --help` for full CLI.
REM
REM  EXAMPLES
REM    re-unpacker.cmd sample.cab
REM    re-unpacker.cmd .\samples -o C:\scratch\out -j 4
REM    re-unpacker.cmd --tools-check
REM
REM  NOTES
REM    - Requires Python 3.10+ on PATH (python or python3).
REM    - Does not alter your PYTHONPATH outside this child process.
REM
REM  VERSION
REM    0.4.8
REM ============================================================================

setlocal enableextensions

REM Resolve the script's own directory so the wrapper works from any cwd.
set "SCRIPT_DIR=%~dp0"
REM Strip trailing backslash for cleaner path concatenation.
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "SRC_DIR=%SCRIPT_DIR%\src"

if not exist "%SRC_DIR%\re_unpacker\__init__.py" (
    echo error: cannot find package source at %SRC_DIR%\re_unpacker 1>&2
    exit /b 4
)

REM Prepend src/ to PYTHONPATH, preserving any existing user value.
if defined PYTHONPATH (
    set "PYTHONPATH=%SRC_DIR%;%PYTHONPATH%"
) else (
    set "PYTHONPATH=%SRC_DIR%"
)

REM Locate python.exe. Prefer 'python', fall back to 'py' (Python launcher).
where /q python
if not errorlevel 1 (
    python -m re_unpacker %*
    exit /b %ERRORLEVEL%
)
where /q py
if not errorlevel 1 (
    py -3 -m re_unpacker %*
    exit /b %ERRORLEVEL%
)

echo error: Python 3.10+ not found on PATH. 1>&2
echo install via:                          1>&2
echo   winget install Python.Python.3.12   1>&2
echo or download from python.org           1>&2
exit /b 4
