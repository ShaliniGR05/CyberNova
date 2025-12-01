# Stop all Security Monitoring Dashboard services
Write-Host "Stopping all Security Monitoring Dashboard services..." -ForegroundColor Red
Write-Host ""

try {
    # Kill Python processes
    Write-Host "Stopping Python processes..." -ForegroundColor Yellow
    Get-Process -Name "python" -ErrorAction SilentlyContinue | Stop-Process -Force
    
    # Kill PowerShell windows with our titles
    $processesToKill = @("Dashboard", "Sysmon", "Security", "DNS", "File", "Packet")
    
    foreach ($process in $processesToKill) {
        Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Where-Object {
            $_.MainWindowTitle -like "*$process*"
        } | Stop-Process -Force
    }
    
    Write-Host ""
    Write-Host "All services stopped successfully." -ForegroundColor Green
} catch {
    Write-Host "Error stopping services: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to exit"
