@echo off
setlocal
echo ========================================================
echo   SURL CMD — Add to User PATH
echo ========================================================
echo.
set "BIN_DIR=%~dp0"
:: Strip trailing backslash
if "%BIN_DIR:~-1%"=="\" set "BIN_DIR=%BIN_DIR:~0,-1%"

echo Adding directory to User PATH:
echo   %BIN_DIR%
echo.

powershell -NoProfile -Command ^
    "$target = '%BIN_DIR%';" ^
    "$current = [Environment]::GetEnvironmentVariable('Path', 'User');" ^
    "if ($current -split ';' -contains $target) {" ^
    "    Write-Host '[✓] Already in User PATH.' -ForegroundColor Green;" ^
    "} else {" ^
    "    $newPath = $current.TrimEnd(';') + ';' + $target;" ^
    "    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User');" ^
    "    Write-Host '[✓] Successfully added to User PATH!' -ForegroundColor Green;" ^
    "    Write-Host 'You can now open a new CMD window anywhere and type: surl <url>' -ForegroundColor Cyan;" ^
    "}"

echo.
pause
endlocal
