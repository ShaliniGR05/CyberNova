# Security Monitoring Dashboard

A comprehensive web-based security monitoring dashboard for Windows systems that provides real-time monitoring of various security events and activities.

## Features

### **Main Dashboard (Port 5000)**
- Central hub for all monitoring services

### **Sysmon Application Monitor (Port 5001)**
- Application-specific filtering

### **Security Audit Monitor (Port 5002)**
- Authentication event tracking (logon success/failure)

### **DNS Traffic Monitor (Port 5003)**
- DNS query and response monitoring
- Domain resolution tracking

### **File System Monitor (Port 5004)**
- Real-time file system change monitoring
- Ransomware detection capabilities
- Hash-based change detection

### **Network Packet Sniffer (Port 5005)**
- Network packet capture and analysis
- Security protocol classification (secure/insecure)

### **Sysmon Event Logs (Port 5006)**
- Focused Sysmon event monitoring
- Process creation, network connections, DNS queries

## Requirements

- Windows 10/11 or Windows Server 2016+
- Python 3.7 or higher
- Administrator privileges (required for some monitoring features)
- PowerShell (for the PowerShell launcher)

## Installation

1. **Clone or download the project files**
2. **Navigate to the web_ui directory**
   ```
   cd d:\Dashboard\web_ui
   ```

3. **Install Python dependencies**
   ```
   pip install -r requirements.txt
   ```

## Usage

### Quick Start (Recommended)

#### Option 1: PowerShell (Recommended)
```powershell
# Run as Administrator for full functionality
.\start_all.ps1
```

#### Option 2: Batch File
```cmd
# Run as Administrator for full functionality
start_all.bat
```

### Manual Start
You can also start individual services manually:

```bash
# Main Dashboard
python dashboard.py

# Individual services
python sysmon_app.py
python security_audit.py
python dns_monitor.py
python file_monitor.py
python packet_sniffer.py
python sysmon_logs.py
```

## Service Ports

| Service | Port | URL |
|---------|------|-----|
| Main Dashboard | 5000 | http://localhost:5000 |
| Sysmon App Monitor | 5001 | http://localhost:5001 |
| Security Audit | 5002 | http://localhost:5002 |
| DNS Monitor | 5003 | http://localhost:5003 |
| File Monitor | 5004 | http://localhost:5004 |
| Packet Sniffer | 5005 | http://localhost:5005 |
| Sysmon Logs | 5006 | http://localhost:5006 |

## Configuration

### Sysmon Configuration
- Ensure Sysmon is installed and configured on your system
- Update the `SYSMON_CONFIG_PATH` in `sysmon_app.py` to point to your Sysmon configuration file
- Default path: `d:\Dashboard\sysmon_config.xml`

### File Monitoring Paths
- File monitor watches common user directories by default:
  - Downloads folder
  - Documents folder
  - Desktop folder
  - Current working directory

## API Endpoints

Each service provides REST API endpoints:

- `/api/start` - Start monitoring
- `/api/stop` - Stop monitoring  
- `/api/events` - Get recent events
- `/api/clear` - Clear event buffer
- `/api/status` - Get service status
