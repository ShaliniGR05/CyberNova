@echo off
echo Starting Security Monitoring Dashboard...
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Install requirements if needed
echo Installing dependencies...
pip install -r requirements.txt

echo.
echo Starting all monitoring services...
echo.

REM Start Dashboard (Port 5000)
start "Dashboard" cmd /k "echo Dashboard - http://localhost:5000 && python dashboard.py"

REM Wait a moment
timeout /t 2 /nobreak >nul

REM Start Sysmon Application Monitor (Port 5001)
start "Sysmon App Monitor" cmd /k "echo Sysmon App Monitor - http://localhost:5001 && python sysmon_app.py"

REM Start Security Audit Monitor (Port 5002)
start "Security Audit" cmd /k "echo Security Audit Monitor - http://localhost:5002 && python security_audit.py"

REM Start DNS Monitor (Port 5003)
start "DNS Monitor" cmd /k "echo DNS Monitor - http://localhost:5003 && python dns_monitor.py"

REM Start File Monitor (Port 5004)
start "File Monitor" cmd /k "echo File Monitor - http://localhost:5004 && python file_monitor.py"

REM Start Packet Sniffer (Port 5005)
start "Packet Sniffer" cmd /k "echo Packet Sniffer - http://localhost:5005 && python packet_sniffer.py"

REM Start Sysmon Logs (Port 5006)
start "Sysmon Logs" cmd /k "echo Sysmon Logs Monitor - http://localhost:5006 && python sysmon_logs.py"

echo.
echo All services are starting...
echo.
echo Main Dashboard: http://localhost:5000
echo Sysmon App Monitor: http://localhost:5001
echo Security Audit Monitor: http://localhost:5002
echo DNS Monitor: http://localhost:5003
echo File Monitor: http://localhost:5004
echo Packet Sniffer: http://localhost:5005
echo Sysmon Logs Monitor: http://localhost:5006
echo.
echo Press any key to open the main dashboard in your browser...
pause >nul

REM Open main dashboard
start http://localhost:5000
