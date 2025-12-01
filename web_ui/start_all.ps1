# Security Monitoring Dashboard - PowerShell Launcher
Write-Host "Starting Security Monitoring Dashboard..." -ForegroundColor Green
Write-Host ""

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Python is not installed or not in PATH" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Install requirements
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

Write-Host ""
Write-Host "Starting all monitoring services..." -ForegroundColor Green
Write-Host ""

# Define services
$services = @(
    @{Name="Dashboard"; Port=5000; Script="dashboard.py"},
    @{Name="Sysmon App Monitor"; Port=5001; Script="sysmon_app.py"},
    @{Name="Security Audit"; Port=5002; Script="security_audit.py"},
    @{Name="DNS Monitor"; Port=5003; Script="dns_monitor.py"},
    @{Name="File Monitor"; Port=5004; Script="file_monitor.py"},
    @{Name="Packet Sniffer"; Port=5005; Script="packet_sniffer.py"},
    @{Name="Sysmon Logs"; Port=5006; Script="sysmon_logs.py"}
)

# Start each service
foreach ($service in $services) {
    $title = $service.Name
    $url = "http://localhost:$($service.Port)"
    $script = $service.Script
    
    Write-Host "Starting $title on port $($service.Port)..." -ForegroundColor Cyan
    
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host '$title - $url' -ForegroundColor Green; python $script"
    
    Start-Sleep -Seconds 1
}

Write-Host ""
Write-Host "All services are starting..." -ForegroundColor Green
Write-Host ""
Write-Host "Service URLs:" -ForegroundColor Yellow
foreach ($service in $services) {
    Write-Host "  $($service.Name): http://localhost:$($service.Port)" -ForegroundColor White
}

Write-Host ""
Write-Host "Press any key to open the main dashboard in your browser..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Open main dashboard
Start-Process "http://localhost:5000"
