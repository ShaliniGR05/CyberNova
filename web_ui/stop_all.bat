@echo off
echo Stopping all Security Monitoring Dashboard services...
echo.

REM Kill all Python processes (be careful - this kills ALL Python processes)
echo Stopping Python processes...
taskkill /F /IM python.exe /T >nul 2>&1

REM Alternative: Kill by window title (if started with the batch file)
taskkill /FI "WindowTitle eq Dashboard*" /T >nul 2>&1
taskkill /FI "WindowTitle eq Sysmon*" /T >nul 2>&1
taskkill /FI "WindowTitle eq Security*" /T >nul 2>&1
taskkill /FI "WindowTitle eq DNS*" /T >nul 2>&1
taskkill /FI "WindowTitle eq File*" /T >nul 2>&1
taskkill /FI "WindowTitle eq Packet*" /T >nul 2>&1

echo.
echo All services stopped.
echo.
pause
