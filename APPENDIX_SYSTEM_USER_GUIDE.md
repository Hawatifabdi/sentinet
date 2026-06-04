# Appendix A: SentiNet System User Guide

## A.1 Purpose of the System

SentiNet is a network security scanning system designed to help small and medium-sized organizations identify connected devices, classify IoT devices, assess security risks, and generate reports. The system scans an IP range, discovers active devices, identifies device types, checks open ports, reviews firmware and credential status, cross-references known vulnerabilities from the National Vulnerability Database (NVD), and stores scan results for later reporting.

The system is intended for IT administrators, security officers, network managers, and other authorized users responsible for monitoring devices on an organizational network.

**Screenshot placeholder:**  
[Insert screenshot here: SentiNet landing page showing the system name and Get Started button.]

## A.2 Downloading and Installing the System

Before using SentiNet, the project files must be downloaded and the local environment must be prepared. This section explains the setup process from the beginning.

### A.2.1 Downloading the Project from GitHub

Open a terminal and move to the folder where the project should be stored. For example:

```bash
cd /home/kali/Desktop
```

Clone the project from GitHub:

```bash
git clone <your-github-repository-url> sentinet
```

Move into the project folder:

```bash
cd sentinet
```

If the project is downloaded as a ZIP file instead, extract the ZIP file and open the extracted `sentinet` folder in the terminal.

**Screenshot placeholder:**  
[Insert screenshot here: GitHub repository page or terminal showing the project being cloned.]

### A.2.2 Creating the Python Virtual Environment

A virtual environment keeps the project dependencies separate from the rest of the computer.

Inside the project folder, create a virtual environment:

```bash
python3 -m venv venv
```

Activate the virtual environment:

```bash
source venv/bin/activate
```

When the virtual environment is active, the terminal usually shows `(venv)` before the command prompt.

**Screenshot placeholder:**  
[Insert screenshot here: Terminal showing the activated virtual environment.]

### A.2.3 Installing Python Requirements

Install all backend dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

This installs the Python packages required by the Flask backend, scanner modules, database connector, and machine learning components.

**Screenshot placeholder:**  
[Insert screenshot here: Terminal showing successful installation of requirements.txt.]

### A.2.4 Installing Frontend Dependencies

If the `node_modules` folder is missing, install the frontend dependency listed in `package.json`:

```bash
npm install
```

This installs Firebase and any JavaScript dependencies required by the frontend.

**Screenshot placeholder:**  
[Insert screenshot here: Terminal showing npm install completed successfully.]

### A.2.5 Setting Up the MySQL Database

Start MySQL using XAMPP or the local MySQL service. Then create the SentiNet database.

Open MySQL:

```bash
mysql -u root
```

Create the database:

```sql
CREATE DATABASE sentinet;
```

Exit MySQL:

```sql
EXIT;
```

Import the database schema:

```bash
mysql -u root sentinet < database/schema.sql
```

The schema creates the tables used to store scan history, devices, ports, credentials, firmware data, vulnerabilities, alerts, and users.

**Screenshot placeholder:**  
[Insert screenshot here: MySQL or phpMyAdmin showing the `sentinet` database and tables.]

### A.2.6 Configuring Firebase

SentiNet uses Firebase for sign in and account creation. The frontend configuration file is located at:

```bash
frontend/firebase-config.js
```

If the configuration file is not yet created, copy the example file:

```bash
cp frontend/firebase-config.example.js frontend/firebase-config.js
```

Then open `frontend/firebase-config.js` and add the Firebase project configuration values from the Firebase console.

Firebase Authentication must have email and password sign-in enabled. The local domains `localhost` and `127.0.0.1` should also be allowed in Firebase Authentication settings.

**Screenshot placeholder:**  
[Insert screenshot here: Firebase Authentication settings showing Email/Password enabled.]

**Screenshot placeholder:**  
[Insert screenshot here: `frontend/firebase-config.js` with sensitive values hidden or blurred.]

### A.2.7 Configuring Optional Environment Variables

Create or edit the `.env` file in the project root:

```bash
nano .env
```

Add the organization name and optional NVD API key:

```bash
NVD_API_KEY="your-api-key-here"
SENTINET_ORG="Your Organization Name"
```

The NVD API key is optional, but it improves vulnerability lookup speed and reliability.

**Screenshot placeholder:**  
[Insert screenshot here: `.env` file showing `NVD_API_KEY` and `SENTINET_ORG` values with the actual key hidden or blurred.]

### A.2.8 Confirming the Application URL

After setup, the backend runs locally on:

```bash
http://127.0.0.1:5000
```

## A.3 Starting the System

Open a terminal and navigate to the project folder:

```bash
cd /home/kali/Desktop/sentinet
```

Activate the Python virtual environment:

```bash
source venv/bin/activate
```

Start the Flask application:

```bash
python app.py
```

When the application starts successfully, open a browser and go to:

```bash
http://127.0.0.1:5000
```

**Screenshot placeholder:**  
[Insert screenshot here: Terminal showing the Flask server running on http://127.0.0.1:5000.]

## A.4 Configuring the NVD API Key

SentiNet can scan without an NVD API key, but vulnerability lookups may be slower because the public NVD API is rate-limited. For better performance, add the API key to the `.env` file in the project root.

Example `.env` configuration:

```bash
NVD_API_KEY="your-api-key-here"
SENTINET_ORG="Your Organization Name"
```

After editing the `.env` file, restart the application so the key is loaded.

**Screenshot placeholder:**  
[Insert screenshot here: `.env` file showing `NVD_API_KEY` and `SENTINET_ORG` values with the actual key hidden or blurred.]

## A.5 Accessing the System

When the system opens, the user first sees the SentiNet landing page. Click **Get Started** or **Sign In** to access the authentication page.

**Steps:**

1. Open `http://127.0.0.1:5000`.
2. Click **Get Started**.
3. The system redirects to the sign-in page.

**Screenshot placeholder:**  
[Insert screenshot here: Landing page with the Sign In or Get Started button visible.]

## A.6 Creating a New Account

New users must create an account before accessing the dashboard.

**Steps:**

1. Open the sign-in page.
2. Click the **Create Account** tab.
3. Enter the full name.
4. Enter the organization name.
5. Select the user role.
6. Enter the email address.
7. Enter and confirm the password.
8. Click **Create Account**.

After successful registration, the system displays an account creation confirmation screen. Click **Go to Dashboard** to continue.

**Screenshot placeholder:**  
[Insert screenshot here: Create Account form before submission.]

**Screenshot placeholder:**  
[Insert screenshot here: Account created success screen.]

## A.7 Signing In

Registered users can sign in using their email and password.

**Steps:**

1. Open the sign-in page.
2. Select the **Sign In** tab.
3. Enter the registered email address.
4. Enter the password.
5. Click **Sign In**.

If the credentials are correct, the system redirects the user to the dashboard.

**Screenshot placeholder:**  
[Insert screenshot here: Sign In form with email and password fields.]

## A.8 Dashboard Overview

The dashboard is the main workspace for scanning networks and reviewing device security status. It contains:

- A network scanner input field.
- A **Scan Network** button.
- Summary statistics for total devices, IoT devices, high-risk devices, and findings.
- Filter controls for device categories.
- Device cards showing device-level security information.
- Sidebar navigation to the dashboard and reports page.

When the dashboard first loads, it shows an empty state until the user runs a scan.

**Screenshot placeholder:**  
[Insert screenshot here: Empty dashboard before running a scan.]

## A.9 Running a Network Scan

To scan a network, enter the IP range in CIDR format and start the scan.

Example IP range:

```bash
172.20.0.0/24
```

**Steps:**

1. Open the dashboard.
2. Enter the network range in the scanner input field.
3. Click **Scan Network**.
4. Wait for the progress bar to complete.
5. Review the detected devices and risk summary.

During scanning, SentiNet performs host discovery, device fingerprinting, port checking, firmware checking, credential checking, vulnerability lookup, and risk scoring.

**Screenshot placeholder:**  
[Insert screenshot here: Dashboard with IP range entered before clicking Scan Network.]

**Screenshot placeholder:**  
[Insert screenshot here: Scan progress bar while the scan is running.]

**Screenshot placeholder:**  
[Insert screenshot here: Dashboard after scan completion showing device cards and statistics.]

## A.10 Understanding Dashboard Statistics

After a scan completes, the dashboard displays four main statistics:

| Statistic | Meaning |
| --- | --- |
| Total Devices | Number of devices detected in the scanned network range. |
| IoT Devices | Number of devices classified as IoT, such as cameras, printers, or wireless access points. |
| High Risk | Number of devices requiring immediate attention. |
| NVD Findings | Number of detected vulnerabilities and security findings. |

These values help the user quickly understand the overall security state of the scanned network.

**Screenshot placeholder:**  
[Insert screenshot here: Dashboard statistics row after a completed scan.]

## A.11 Filtering Devices

The dashboard includes filter buttons that allow the user to narrow the displayed devices.

Available filters include:

- **All**: Shows every detected device.
- **IoT**: Shows all detected IoT devices.
- **IP Camera**: Shows camera devices.
- **Printer**: Shows printer devices.
- **WAP**: Shows wireless access points.
- **Non-IoT**: Shows computers and other non-IoT devices.

**Steps:**

1. Run a network scan.
2. Click one of the filter chips above the device grid.
3. Review the filtered device list.

**Screenshot placeholder:**  
[Insert screenshot here: Dashboard filter bar with one filter selected.]

## A.12 Reading Device Cards

Each device card displays security information about one detected device.

Typical device card details include:

- Device name or IP address.
- MAC address.
- Manufacturer or vendor.
- Device type.
- IoT classification.
- Risk level.
- Firmware status.
- Credential status.
- Open ports and services.
- CVE findings from NVD.
- Local findings such as weak credentials or outdated firmware.
- Machine learning classification confidence.

Risk levels are shown as low, medium, or high. High-risk devices should be reviewed first.

**Screenshot placeholder:**  
[Insert screenshot here: Device card showing IP address, risk level, ports, firmware status, and findings.]

**Screenshot placeholder:**  
[Insert screenshot here: Expanded device card showing CVE findings and local security checks.]

## A.13 Understanding Security Findings

SentiNet uses both local checks and external vulnerability lookups.

Local checks include:

- Default credential detection.
- Weak credential detection.
- Outdated firmware detection.
- Risky open port identification.

NVD findings include:

- CVE identifier.
- CVSS score.
- Severity level.
- Vulnerability description.

Example CVE format:

```text
CVE-2021-12345 - CVSS 8.8 - High severity
```

Devices with default credentials, outdated firmware, risky ports, or high CVSS vulnerabilities may be marked as high risk.

**Screenshot placeholder:**  
[Insert screenshot here: Device findings section showing CVE IDs and CVSS scores.]

## A.14 Reports and Analytics Page

The Reports and Analytics page summarizes scan results and historical activity. It contains:

- Risk distribution chart.
- Device mix chart.
- Scan history table.
- PDF report download button.

To open the page, click **Reports & Analytics** in the sidebar.

**Screenshot placeholder:**  
[Insert screenshot here: Reports and Analytics page overview.]

## A.15 Viewing Risk Distribution

The risk distribution chart shows how many devices are categorized as high, medium, or low risk.

**Steps:**

1. Run at least one scan.
2. Open **Reports & Analytics**.
3. Review the risk distribution chart.

This chart helps identify whether most devices are safe or whether urgent remediation is required.

**Screenshot placeholder:**  
[Insert screenshot here: Risk Distribution chart.]

## A.16 Viewing Device Mix

The device mix chart shows the device categories discovered during the latest scan. Categories include IP cameras, printers, wireless access points, and computers.

**Screenshot placeholder:**  
[Insert screenshot here: Device Mix donut chart and legend.]

## A.17 Viewing Scan History

The scan history table stores previous scan summaries. Each row shows:

- Organization.
- Network range.
- Date and time of scan.
- Total devices.
- IoT devices.
- High-risk devices.

This allows the user to compare scan results over time and track changes in the network.

**Screenshot placeholder:**  
[Insert screenshot here: Scan History table showing previous scans.]

## A.18 Downloading a PDF Report

SentiNet can generate a PDF report from the available scan data.

**Steps:**

1. Open **Reports & Analytics**.
2. Click **Download PDF**.
3. Save or open the downloaded `sentinet-report.pdf` file.
4. Review the executive summary, device inventory, open ports, CVE findings, and local checks.

**Screenshot placeholder:**  
[Insert screenshot here: Download PDF button on the Reports page.]

**Screenshot placeholder:**  
[Insert screenshot here: Generated PDF report opened in a PDF viewer.]

## A.19 Signing Out

To end the session, click **Sign Out** in the sidebar. The system signs the user out and returns them to the sign-in flow.

**Screenshot placeholder:**  
[Insert screenshot here: Sidebar showing the Sign Out button.]

## A.20 Troubleshooting

| Problem | Possible Cause | Solution |
| --- | --- | --- |
| The dashboard does not load | Flask server is not running | Start the server using `python app.py`. |
| Database error appears | MySQL or XAMPP is not running | Start MySQL/XAMPP and confirm the `sentinet` database exists. |
| Sign in fails | Firebase configuration is missing or incorrect | Check `frontend/firebase-config.js` and Firebase Authentication settings. |
| Scan is very slow | NVD API key is missing or rate-limited | Add `NVD_API_KEY` to `.env` and restart the app. |
| No devices are found | Wrong IP range or unreachable network | Confirm the IP range and network connectivity. |
| CVE findings are empty | NVD lookup failed or no matching vulnerabilities were found | Check internet connection, NVD API key, and device model/firmware information. |
| PDF report is empty | No scan has been run for the current account | Run a scan first, then download the report. |

## A.21 Recommended Screenshot Checklist

Use the following checklist when preparing the final appendix:

- Landing page.
- Terminal showing Flask server running.
- `.env` configuration with sensitive values hidden.
- Sign-in page.
- Create account page.
- Account created confirmation.
- Empty dashboard before scan.
- Dashboard with IP range entered.
- Scan progress indicator.
- Dashboard after scan results appear.
- Device card overview.
- Expanded device card with CVEs.
- Filtered device list.
- Reports and Analytics page.
- Risk distribution chart.
- Device mix chart.
- Scan history table.
- PDF download button.
- Generated PDF report.
- Sign out button.

## A.22 Summary

This appendix explains how to start, configure, access, and use the SentiNet system. It also describes how users can scan a network, interpret device security results, view analytics, download reports, and troubleshoot common issues. The screenshot placeholders should be replaced with actual system screenshots during final documentation preparation.
