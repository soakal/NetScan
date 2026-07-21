@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

:menu
cls
echo ============================================
echo   NetScan
echo ============================================
echo.
echo   1. Scan your network
echo   2. Serve the report (http://127.0.0.1:8000)
echo   3. Scan, then serve the report
echo   4. Demo mode (no network needed, sample data)
echo   5. List scan profiles
echo   0. Exit
echo.
set "choice="
set /p choice="Choose an option: "

if "!choice!"=="1" goto scan
if "!choice!"=="2" goto serve
if "!choice!"=="3" goto scanserve
if "!choice!"=="4" goto demo
if "!choice!"=="5" goto profiles
if "!choice!"=="0" goto end
echo Invalid choice.
pause
goto menu

:checkconfig
if exist config.yaml exit /b 0
if not exist config.example.yaml (
    echo.
    echo ERROR: Neither config.yaml nor config.example.yaml was found.
    echo Restore config.example.yaml or re-download the app, then try again.
    pause
    exit /b 1
)
echo.
echo config.yaml not found. Copying from config.example.yaml...
copy config.example.yaml config.yaml >nul
echo A default config.yaml was created. Edit it to set your real
echo network targets before scanning, then re-run this option.
pause
exit /b 1

:scan
call :checkconfig
if errorlevel 1 goto menu
echo.
echo Running scan...
python run.py scan -c config.yaml
echo.
pause
goto menu

:serve
call :checkconfig
if errorlevel 1 goto menu
echo.
echo Starting report server at http://127.0.0.1:8000
echo Press Ctrl+C to stop.
python run.py serve -c config.yaml
goto menu

:scanserve
call :checkconfig
if errorlevel 1 goto menu
echo.
echo Running scan...
python run.py scan -c config.yaml
echo.
echo Starting report server at http://127.0.0.1:8000
echo Press Ctrl+C to stop.
python run.py serve -c config.yaml
goto menu

:demo
echo.
echo Seeding demo data...
python run.py demo
echo Starting report server at http://127.0.0.1:8000
echo Press Ctrl+C to stop.
python run.py serve
goto menu

:profiles
echo.
python run.py profiles
echo.
pause
goto menu

:end
endlocal
