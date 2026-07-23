@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

REM NetScan first-time setup for Windows.
REM
REM Installs the Python dependencies and offers to install a non-buggy nmap
REM (>= 7.90) straight from nmap.org. winget's "Insecure.Nmap" package is
REM stuck at 7.80, which has a known crash-on-large-scans bug
REM (nmap/nmap#1764, fixed upstream in 7.90) -- "winget upgrade Insecure.Nmap"
REM CANNOT fix this, so nmap is installed directly from nmap.org instead.
REM
REM Safe to re-run any time. Never installs anything without asking first
REM (unless -y/--yes is passed). See setup.sh for the Linux/macOS equivalent.

REM Bump NMAP_TARGET after checking https://nmap.org/dist/ for the current
REM version -- anything >= 7.90 fixes nmap/nmap#1764. If you bump it, ALSO
REM update NMAP_SHA256 (get it from https://nmap.org/dist/sigs/nmap-<ver>-setup.exe.digest
REM or `Get-FileHash -Algorithm SHA256` on a copy you've verified another
REM way) and re-verify NMAP_SIGNER_MATCH still matches the new installer's
REM Get-AuthenticodeSignature signer subject (it was "Nmap Software LLC" as
REM of nmap 7.99 -- older releases were signed as "Insecure.Com LLC", so a
REM version jump could change this).
REM
REM Both checks matter: Authenticode alone trusts *any* validly-chained cert
REM whose subject contains "Nmap Software" (in principle a same-name cert
REM from a different, confusable entity), and by itself doesn't stop an
REM attacker who can win the download path from serving an OLDER genuine
REM signed installer (a downgrade back to a buggy version). Pinning the
REM exact expected hash of THIS version closes both gaps and makes the
REM download tamper-evident even against a compromised nmap.org.
set "NMAP_TARGET=7.99"
set "NMAP_MIN_MAJOR=7"
set "NMAP_MIN_MINOR=90"
set "NMAP_SIGNER_MATCH=Nmap Software"
set "NMAP_SHA256=FDA839F35D9F8F18A11670E17D0332CE9D05A3556C5A20E91B0B56C57774F611"

REM Resolved once, at top level: expanding %ProgramFiles(x86)% *inside* an
REM if-block truncates at the ')' in the variable name and silently breaks.
set "NMAP_EXE64=%ProgramFiles%\Nmap\nmap.exe"
set "NMAP_EXE86=%ProgramFiles(x86)%\Nmap\nmap.exe"

REM Prefer PowerShell 7 (pwsh) if present: on machines that have both PS7
REM and Windows PowerShell installed, PS7 can leave a stale/conflicting
REM Microsoft.PowerShell.Security module on PSModulePath that breaks
REM Get-AuthenticodeSignature under plain "powershell.exe" (observed
REM directly while building this script). pwsh doesn't have that problem.
set "PWSH_EXE=powershell"
where pwsh >nul 2>&1 && set "PWSH_EXE=pwsh"

set "ASSUME_YES=0"
set "STATUS_PYTHON=skipped"
set "STATUS_DEPS=skipped"
set "STATUS_NMAP=skipped"
set "STATUS_CONFIG=skipped"
set "STATUS_SMOKE=skipped"

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="-y" (
    set "ASSUME_YES=1"
    shift
    goto parse_args
)
if /i "%~1"=="--yes" (
    set "ASSUME_YES=1"
    shift
    goto parse_args
)
if /i "%~1"=="-h" goto usage
if /i "%~1"=="--help" goto usage
echo Unknown option: %~1
goto usage
:args_done

echo ============================================
echo   NetScan setup (Windows)
echo ============================================
echo.
echo Running from: %cd%
echo.

call :ensure_python
call :install_deps
call :ensure_nmap
call :ensure_config
call :smoke_test

echo.
echo ============================================
echo   Setup summary
echo ============================================
echo   Python              : !STATUS_PYTHON!
echo   Python dependencies : !STATUS_DEPS!
echo   nmap                : !STATUS_NMAP!
echo   config.yaml         : !STATUS_CONFIG!
echo   Smoke test          : !STATUS_SMOKE!
echo.

echo !STATUS_NMAP!| findstr /c:"upgraded" >nul
if not errorlevel 1 (
    echo IMPORTANT: nmap was just installed/upgraded. Close this window and
    echo open a NEW terminal before running NetScan, so it picks up the
    echo updated PATH.
    echo.
)

echo Next steps:
echo   1. Edit config.yaml -- set 'targets:' to what you're authorized to scan.
echo   2. Run run.bat, then choose option 3.
echo   3. Open http://127.0.0.1:8000
echo.
pause
exit /b 0

:usage
echo Usage: setup.bat [-y^|--yes]
echo.
echo   -y, --yes   Answer yes to installing nmap without prompting.
exit /b 0

REM ===========================================================================
:ensure_python
where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: python not found on PATH.
    echo   Install it: https://python.org  or  winget install Python.Python.3.12
    set "STATUS_PYTHON=failed"
    exit /b 1
)
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: 'python' on PATH doesn't run -- likely the Microsoft Store alias.
    echo   Install real Python: https://python.org  or  winget install Python.Python.3.12
    set "STATUS_PYTHON=failed"
    exit /b 1
)
for /f "usebackq tokens=*" %%v in (`python --version 2^>^&1`) do echo Found %%v
set "STATUS_PYTHON=ok"
exit /b 0

REM ===========================================================================
:install_deps
if not "!STATUS_PYTHON!"=="ok" (
    echo Skipping dependency install -- Python not available.
    exit /b 1
)
echo.
echo Installing Python dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo WARNING: pip install failed.
    set "STATUS_DEPS=failed"
    exit /b 1
)
python -c "import flask, yaml, requests, nmap" >nul 2>&1
if errorlevel 1 (
    echo WARNING: one or more core dependencies failed to import after install.
    set "STATUS_DEPS=failed"
    exit /b 1
)
echo Core dependencies (flask, yaml, requests, python-nmap^) import cleanly.
set "STATUS_DEPS=ok"
exit /b 0

REM ===========================================================================
REM Sets NMAP_FOUND_CMD to a runnable nmap path/name, or leaves it empty.
:locate_nmap
set "NMAP_FOUND_CMD="
where nmap >nul 2>&1
if not errorlevel 1 set "NMAP_FOUND_CMD=nmap"
if not defined NMAP_FOUND_CMD if exist "!NMAP_EXE64!" set "NMAP_FOUND_CMD=!NMAP_EXE64!"
if not defined NMAP_FOUND_CMD if exist "!NMAP_EXE86!" set "NMAP_FOUND_CMD=!NMAP_EXE86!"
exit /b 0

REM %1 = nmap command/path. Sets NMAP_VER_STR ("7.80" or "unknown"),
REM NMAP_VER_MAJ/NMAP_VER_MIN (only valid if NMAP_VER_STR != "unknown"), and
REM NMAP_VER_OK (1 if >= the configured floor).
REM Captures the raw "Nmap version X.Y (...)" line via a plain batch for/f
REM (no nested PowerShell call-operator gymnastics), then hands ONLY that
REM text to PowerShell via an environment variable for the regex -- passing
REM values through $env: instead of splicing them into -Command strings
REM sidesteps cmd.exe's very sharp quoting/escaping edges.
:read_nmap_version
set "NMAP_VER_OK=0"
set "NMAP_VER_STR=unknown"
set "NMAP_RAW_LINE="
for /f "usebackq tokens=*" %%v in (`"%~1" --version 2^>nul`) do (
    echo(%%v| findstr /b /c:"Nmap version" >nul && set "NMAP_RAW_LINE=%%v"
)
if not defined NMAP_RAW_LINE exit /b 0

REM NOTE: !PWSH_EXE! must be UNQUOTED here -- quoting it breaks usebackq's
REM backtick command parsing (verified: quoting it makes for/f mis-split the
REM command and silently capture nothing, which previously left
REM NMAP_VER_STR at its "unknown" default -- see the guard below for why
REM that used to be misread as "version OK").
for /f "usebackq delims=" %%v in (`!PWSH_EXE! -NoProfile -Command "if ($env:NMAP_RAW_LINE -match 'Nmap version ([0-9]+)\.([0-9]+)') { $Matches[1] + '.' + $Matches[2] } else { 'NONE' }"`) do set "NMAP_VER_STR=%%v"
if "!NMAP_VER_STR!"=="NONE" set "NMAP_VER_STR=unknown"
if "!NMAP_VER_STR!"=="unknown" exit /b 0

REM Guard is load-bearing: batch's IF GTR/GEQ silently falls back to a
REM lexicographic STRING compare when an operand isn't a valid integer, and
REM "unknown" GTR "7" is TRUE as a string compare -- so without the "unknown"
REM exit above, any unparseable version would be misreported as OK instead
REM of prompting to fix the known-buggy nmap.
for /f "tokens=1,2 delims=." %%a in ("!NMAP_VER_STR!") do (
    set "NMAP_VER_MAJ=%%a"
    set "NMAP_VER_MIN=%%b"
)
if !NMAP_VER_MAJ! GTR %NMAP_MIN_MAJOR% set "NMAP_VER_OK=1"
if !NMAP_VER_MAJ! EQU %NMAP_MIN_MAJOR% if !NMAP_VER_MIN! GEQ %NMAP_MIN_MINOR% set "NMAP_VER_OK=1"
exit /b 0

REM ===========================================================================
:ensure_nmap
echo.
call :locate_nmap
if not defined NMAP_FOUND_CMD (
    echo nmap not found. This is optional: NetScan falls back to a
    echo pure-Python scanner without it, with limited fingerprinting and no
    echo CPE-based CVE correlation.
    call :offer_nmap_install
    exit /b 0
)

call :read_nmap_version "!NMAP_FOUND_CMD!"
if "!NMAP_VER_OK!"=="1" (
    echo nmap found: !NMAP_FOUND_CMD! ^(!NMAP_VER_STR!^) -- OK, ^>= %NMAP_MIN_MAJOR%.%NMAP_MIN_MINOR%.
    set "STATUS_NMAP=ok (!NMAP_VER_STR!)"
    exit /b 0
)

echo nmap found: !NMAP_FOUND_CMD! ^(!NMAP_VER_STR!^)
echo This version has a known crash bug on large scans (nmap/nmap#1764),
echo fixed in nmap 7.90+. NOTE: 'winget upgrade Insecure.Nmap' will NOT fix
echo this -- winget's own Insecure.Nmap package is itself stuck at 7.80.
call :offer_nmap_install
exit /b 0

REM ===========================================================================
:offer_nmap_install
REM Npcap's free edition has no silent installer -- if it's not already
REM present, nmap's own installer pops a message box and quits when given
REM /S (confirmed against nmap's NSIS installer source). Checked up front
REM (rather than after download+verify) so the "a window will pop up" heads
REM -up is part of the single confirmation prompt, and so there's no idle
REM gap -- previously an interactive-install "press a key when ready" pause
REM sat AFTER the installer was already downloaded and verified, needlessly
REM widening the window in which something else with write access to
REM %TEMP% could swap the file before it runs.
set "NPCAP_FOUND=0"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" /v DisplayVersion >nul 2>&1 && set "NPCAP_FOUND=1"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" /v DisplayVersion >nul 2>&1 && set "NPCAP_FOUND=1"

echo.
echo This will download and install nmap %NMAP_TARGET% from nmap.org:
echo   1. Download https://nmap.org/dist/nmap-%NMAP_TARGET%-setup.exe (~35 MB^) to %%TEMP%%
echo   2. Verify its SHA-256 hash and Authenticode (digital^) signature
echo   3. Run the installer (a Windows admin/UAC prompt will appear^)
if "!NPCAP_FOUND!"=="0" (
    echo   Npcap ^(the packet-capture driver nmap needs^) isn't installed yet.
    echo   Its free edition has no silent installer, so after the checks above
    echo   the nmap setup window will open for you to click through --
    echo   accept the license pages and keep the defaults.
)
echo.
if "!ASSUME_YES!"=="1" (
    set "NMAP_CONFIRM=y"
) else (
    set /p "NMAP_CONFIRM=Proceed? [y/N] "
)
if /i not "!NMAP_CONFIRM!"=="y" (
    echo Skipped. Install manually from https://nmap.org/download.html if you want it.
    set "STATUS_NMAP=skipped (declined)"
    exit /b 0
)

set "NMAP_INSTALLER=%TEMP%\nmap-%NMAP_TARGET%-setup.exe"
set "DL_URL=https://nmap.org/dist/nmap-%NMAP_TARGET%-setup.exe"
set "DL_OUT=!NMAP_INSTALLER!"
echo.
echo Downloading nmap %NMAP_TARGET%...
"!PWSH_EXE!" -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri $env:DL_URL -OutFile $env:DL_OUT -UseBasicParsing } catch { Write-Host $_.Exception.Message; exit 1 }"
if errorlevel 1 (
    echo Download failed. Check https://nmap.org/dist/ for the current
    echo version and update NMAP_TARGET at the top of setup.bat if it changed.
    del "!NMAP_INSTALLER!" >nul 2>&1
    set "STATUS_NMAP=failed (download)"
    exit /b 1
)

echo Verifying installer hash...
set "HASH_FILE=!NMAP_INSTALLER!"
set "HASH_EXPECT=%NMAP_SHA256%"
"!PWSH_EXE!" -NoProfile -ExecutionPolicy Bypass -Command "$h = (Get-FileHash -Algorithm SHA256 -Path $env:HASH_FILE).Hash; Write-Host ('  SHA-256 (got)      : ' + $h); Write-Host ('  SHA-256 (expected)  : ' + $env:HASH_EXPECT); if ($h -ne $env:HASH_EXPECT) { exit 1 }"
if errorlevel 1 (
    echo Hash verification FAILED -- refusing to run this installer. If you
    echo intentionally bumped NMAP_TARGET without updating NMAP_SHA256 in
    echo setup.bat, that's why -- see the comment above NMAP_TARGET.
    del "!NMAP_INSTALLER!" >nul 2>&1
    set "STATUS_NMAP=failed (hash)"
    exit /b 1
)

echo Verifying installer signature...
set "SIG_FILE=!NMAP_INSTALLER!"
set "SIG_MATCH=%NMAP_SIGNER_MATCH%"
"!PWSH_EXE!" -NoProfile -ExecutionPolicy Bypass -Command "$s = Get-AuthenticodeSignature -FilePath $env:SIG_FILE; Write-Host ('  Signature status : ' + $s.Status); Write-Host ('  Signed by        : ' + $s.SignerCertificate.Subject); if ($s.Status -ne 'Valid') { exit 1 }; if ($s.SignerCertificate.Subject -notmatch [regex]::Escape($env:SIG_MATCH)) { exit 2 }"
if errorlevel 1 (
    echo Signature verification FAILED -- refusing to run this installer.
    del "!NMAP_INSTALLER!" >nul 2>&1
    set "STATUS_NMAP=failed (signature)"
    exit /b 1
)
"!PWSH_EXE!" -NoProfile -Command "Unblock-File -Path $env:SIG_FILE" >nul 2>&1

set "RUN_FILE=!NMAP_INSTALLER!"
if "!NPCAP_FOUND!"=="1" (
    echo Installing silently...
    "!PWSH_EXE!" -NoProfile -Command "try { $p = Start-Process -FilePath $env:RUN_FILE -ArgumentList '/S','/NPCAP=NO' -Verb RunAs -Wait -PassThru; exit $p.ExitCode } catch { exit 999 }"
) else (
    echo Opening the nmap setup window -- accept the license pages and keep
    echo the defaults.
    "!PWSH_EXE!" -NoProfile -Command "try { $p = Start-Process -FilePath $env:RUN_FILE -Verb RunAs -Wait -PassThru; exit $p.ExitCode } catch { exit 999 }"
)
set "NMAP_INSTALL_RC=!errorlevel!"
del "!NMAP_INSTALLER!" >nul 2>&1

if "!NMAP_INSTALL_RC!"=="999" (
    echo Install was not run -- the admin/UAC prompt was declined.
    set "STATUS_NMAP=failed (UAC declined)"
    exit /b 1
)
if not "!NMAP_INSTALL_RC!"=="0" (
    echo Installer exited with code !NMAP_INSTALL_RC!. If your antivirus
    echo flagged/removed the file, that's a common cause with nmap/Npcap.
    set "STATUS_NMAP=failed (installer exit !NMAP_INSTALL_RC!)"
    exit /b 1
)

REM Re-check via the absolute install paths -- this shell's PATH predates
REM the install, so `where nmap` would still miss it.
set "NMAP_FOUND_CMD="
if exist "!NMAP_EXE64!" set "NMAP_FOUND_CMD=!NMAP_EXE64!"
if not defined NMAP_FOUND_CMD if exist "!NMAP_EXE86!" set "NMAP_FOUND_CMD=!NMAP_EXE86!"
if not defined NMAP_FOUND_CMD (
    echo Installer finished but nmap.exe wasn't found afterward -- something
    echo went wrong. Try installing manually: https://nmap.org/download.html
    set "STATUS_NMAP=failed (not found post-install)"
    exit /b 1
)
call :read_nmap_version "!NMAP_FOUND_CMD!"
echo nmap installed: !NMAP_FOUND_CMD! ^(!NMAP_VER_STR!^)
set "STATUS_NMAP=ok (upgraded to !NMAP_VER_STR!)"
exit /b 0

REM ===========================================================================
:ensure_config
if exist config.yaml (
    echo config.yaml already exists.
    set "STATUS_CONFIG=ok (existing)"
    exit /b 0
)
if not exist config.example.yaml (
    echo WARNING: neither config.yaml nor config.example.yaml found.
    set "STATUS_CONFIG=failed"
    exit /b 1
)
echo config.yaml not found. Copying from config.example.yaml...
copy config.example.yaml config.yaml >nul
echo A default config.yaml was created. Edit it to set your real network
echo targets before scanning.
set "STATUS_CONFIG=ok (created)"
exit /b 0

REM ===========================================================================
:smoke_test
if not "!STATUS_DEPS!"=="ok" (
    set "STATUS_SMOKE=skipped"
    exit /b 1
)
echo.
echo Running smoke test (python run.py profiles^)...
python run.py profiles >nul 2>&1
if errorlevel 1 (
    echo WARNING: smoke test failed -- this suggests a broken source tree,
    echo not a missing dependency (already verified above^).
    set "STATUS_SMOKE=failed"
    exit /b 1
)
echo Smoke test passed.
set "STATUS_SMOKE=ok"
exit /b 0
