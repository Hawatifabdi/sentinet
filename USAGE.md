# SentiNet - Network Security Scanner

## Quick Start

### 1. Configure NVD API (Optional but Recommended)

Edit `.env` file and add your NVD API key:

```bash
# Get your free API key from: https://services.nvd.nist.gov/rest/json/cves/2.0
# Edit .env file:
NVD_API_KEY="your-api-key-here"
SENTINET_ORG="Your Organization Name"
```

Once you have a `.env` file, the API key is **automatically loaded** every time you start the app. No need to export it manually!

### 2. Start the Application

```bash
cd /home/kali/Desktop/sentinet
source venv/bin/activate
python app.py
```

The app will automatically load settings from `.env` file.

### 3. Open Dashboard

Navigate to: http://127.0.0.1:5000

## Features

### Dashboard
- **Scan Network**: Enter IP range and scan for devices
- **Device Cards**: View detailed security info for each device
- **Live Filters**: Filter by device type, risk level, IoT/Non-IoT
- **Deep NVD Integration**: Optional cross-reference with NIST vulnerability database

### Reports & Analytics
- **Risk Distribution**: Bar chart of high/medium/low risk devices
- **Device Mix**: Donut chart of device types (cameras, printers, WAPs, computers)
- **Scan History**: Complete log of all network scans

### PDF Report Export
- **Download**: Click "Download PDF" button on Reports page
- **Content**: Full device inventory with:
  - Executive summary
  - Scan history
  - Device details (firmware, credentials, vulnerabilities, ports)
  - Multi-page support for large networks

## Dashboard Behavior

- **Fresh Start**: Dashboard is blank on page load
- **After Scan**: Click "Scan Network" to populate with results
- **Data Persistence**: Results are saved in database
- **Multiple Scans**: Scan different networks; latest scan shows on dashboard
- **Reports**: All historical scans appear in Reports page

## Environment Variables

### .env File (Recommended)
```
NVD_API_KEY="your-api-key"
SENTINET_ORG="Organization Name"
```

### Manual Export (Alternative)
```bash
export NVD_API_KEY="your-api-key"
python app.py
```

## Troubleshooting

### Issue: Slow scans
- **Cause**: NVD API key not set
- **Fix**: Add `NVD_API_KEY` to `.env` file and restart

### Issue: Vulnerabilities not found
- **Cause**: NVD API connection issue
- **Fix**: Check internet connection and API key validity

### Issue: Database connection error
- **Fix**: Ensure MySQL/XAMPP is running

## Device Details Shown

Each device card displays:
- **Basic Info**: IP, MAC, hostname, type, manufacturer
- **Security Status**: Risk level, firmware status, password security
- **Network**: Open ports with service names
- **Vulnerabilities**: CVE IDs, severity levels, CVSS scores
- **ML Confidence**: Device classification confidence percentage

## Deployment Notes

- `.env` file is read on app startup
- No need to export variables before running
- Perfect for Docker/cloud deployment
- Settings persist across app restarts
