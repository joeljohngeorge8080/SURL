@echo off
setlocal

:: Get directory where this batch file is located
set "SCRIPT_DIR=%~dp0"
set "ROOT_DIR=%SCRIPT_DIR%.."

:: Determine Python executable
where python >nul 2>&1
if %ERRORLEVEL%==0 (
    set "PY_EXE=python"
) else if exist "%ROOT_DIR%\venv\Scripts\python.exe" (
    set "PY_EXE=%ROOT_DIR%\venv\Scripts\python.exe"
) else (
    set "PY_EXE=python"
)

:: Run surl.py with all passed arguments
"%PY_EXE%" "%SCRIPT_DIR%surl.py" %*

:: If launched by double-clicking (no arguments and no calling prompt), pause
if "%~1"=="" if "%PROMPT%"=="$P$G" goto :done
if "%~1"=="" if not defined PROMPT pause

:done
endlocal
