# ============================================================
#  SentiNet — test_pipeline.py
#  Run this from your sentinet/ root folder:
#      sudo python3 test_pipeline.py
#
#  What it does:
#  1. Trains the ML model
#  2. Scans the Docker simulation network
#  3. Classifies each device
#  4. Saves everything to MySQL
#  5. Prints a full report
# ============================================================

import sys
import os

# Make sure Python can find your folders
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner.scanner       import scan_network
from scanner.classifier         import train_model, classify_all, load_model
from database.db                import (
    connect, create_scan, finish_scan,
    save_device, save_ports, save_credential,
    save_firmware, save_alert, get_dashboard_stats
)

# ── The Docker simulation subnet ──
NETWORK = "172.20.0.0/24"

# ── Ports we consider risky ──
RISKY_PORTS = {21, 23, 80, 554, 1080, 3389, 5900, 8080}


def determine_risk(device):
    """
    Simple risk scoring:
      - Default creds found  → high
      - Risky port open      → medium
      - Otherwise            → low
    """
    ports      = {p["port"] for p in device.get("ports", [])}
    has_risky  = bool(ports & RISKY_PORTS)
    dev_type   = device.get("device_type", "unknown")

    # Default credentials heuristic
    # (cameras and WAPs with port 80 open are likely to have default creds)
    default_creds = dev_type in ("camera", "wap") and 80 in ports

    if default_creds:
        return "high"
    elif has_risky:
        return "medium"
    else:
        return "low"


def run_pipeline():

    print()
    print("=" * 60)
    print("  SentiNet — Full Pipeline Test")
    print("=" * 60)

    # ────────────────────────────────────────
    #  STEP 1: Train ML model
    # ────────────────────────────────────────
    print("\n[STEP 1] Training ML model on synthetic data...")
    model, le = train_model()

    if model is None:
        print("[!] Model training failed. Check classifier.py")
        return

    # ────────────────────────────────────────
    #  STEP 2: Test database connection
    # ────────────────────────────────────────
    print("\n[STEP 2] Testing database connection...")
    try:
        conn = connect()
        if conn.is_connected():
            print("[+] MySQL connected successfully")
            conn.close()
        else:
            print("[!] Could not connect to MySQL")
            print("    Make sure XAMPP MySQL is running")
            return
    except Exception as e:
        print(f"[!] Database error: {e}")
        print("    Make sure XAMPP MySQL is running and sentinet database exists")
        return

    # ────────────────────────────────────────
    #  STEP 3: Scan Docker network
    # ────────────────────────────────────────
    print(f"\n[STEP 3] Scanning Docker network: {NETWORK}")
    print("         (make sure Docker containers are running)")
    print("         Run: cd simulation && docker compose up -d\n")

    raw_devices = scan_network(NETWORK)

    if not raw_devices:
        print("[!] No devices found.")
        print("    Check that Docker containers are running:")
        print("    cd simulation && docker compose up -d")
        return

    print(f"[+] Found {len(raw_devices)} devices")

    # ────────────────────────────────────────
    #  STEP 4: Classify with ML
    # ────────────────────────────────────────
    print(f"\n[STEP 4] Running ML classification...")
    classified = classify_all(raw_devices, model, le)

    # ────────────────────────────────────────
    #  STEP 5: Save to database
    # ────────────────────────────────────────
    print(f"\n[STEP 5] Saving results to MySQL...")

    # Count stats for scan summary
    iot_count  = sum(1 for d in classified if d.get("is_iot"))
    high_count = sum(1 for d in classified if determine_risk(d) == "high")

    # Create scan record
    scan_id = create_scan(NETWORK)
    print(f"[+] Scan record created (scan_id={scan_id})")

    for device in classified:
        ip          = device.get("ip")
        mac         = device.get("mac")
        vendor      = device.get("vendor")
        hostname    = device.get("hostname") or device.get("ip")
        is_iot      = device.get("is_iot", False)
        device_type = device.get("device_type", "unknown")
        confidence  = device.get("ml_confidence", 0.0)
        risk_level  = determine_risk(device)

        # Save device
        device_id = save_device(
            scan_id, ip, mac, vendor, hostname,
            is_iot, device_type, confidence, risk_level
        )

        # Save ports
        if device.get("ports"):
            save_ports(device_id, device["ports"])

        # Save credential guess
        # Heuristic: cameras/WAPs with port 80 likely have default creds
        ports = {p["port"] for p in device.get("ports", [])}
        if device_type in ("camera", "wap") and 80 in ports:
            save_credential(device_id, "default", "admin/admin likely active (port 80 open)")
        elif device_type == "printer":
            save_credential(device_id, "weak",    "Printer web interface accessible")
        else:
            save_credential(device_id, "unknown", "Manual check required")

        # Save firmware (from banner/version if available)
        version = device.get("version") or "Unknown"
        save_firmware(device_id, version, is_outdated=False)

        # Save alert if high risk
        if risk_level == "high":
            save_alert(
                device_id,
                alert_type="default_credentials",
                message=f"{device_type.upper()} at {ip} likely has default credentials active",
                severity="high"
            )
        elif risk_level == "medium":
            save_alert(
                device_id,
                alert_type="risky_port",
                message=f"Risky port open on {device_type} at {ip}",
                severity="medium"
            )

    # Update scan totals
    finish_scan(scan_id, len(classified), iot_count, high_count)
    print(f"[+] All {len(classified)} devices saved to database")

    # ────────────────────────────────────────
    #  STEP 6: Print final report
    # ────────────────────────────────────────
    print()
    print("=" * 60)
    print("  SCAN REPORT")
    print("=" * 60)
    print(f"  Network scanned : {NETWORK}")
    print(f"  Total devices   : {len(classified)}")
    print(f"  IoT devices     : {iot_count}")
    print(f"  High risk       : {high_count}")
    print()
    print(f"  {'IP':<18} {'Type':<12} {'Confidence':<12} {'Risk':<10} {'IoT'}")
    print(f"  {'-'*18} {'-'*12} {'-'*12} {'-'*10} {'-'*5}")

    for d in classified:
        ip   = d.get("ip", "?")
        typ  = d.get("device_type", "unknown")
        conf = f"{d.get('ml_confidence', 0)}%"
        risk = determine_risk(d)
        iot  = "Yes" if d.get("is_iot") else "No"
        print(f"  {ip:<18} {typ:<12} {conf:<12} {risk:<10} {iot}")

    print()

    # Dashboard stats from DB
    print("=" * 60)
    print("  DATABASE CHECK")
    print("=" * 60)
    stats = get_dashboard_stats()
    print(f"  Total devices in DB : {stats['total_devices']}")
    print(f"  IoT devices in DB   : {stats['iot_devices']}")
    print(f"  High risk in DB     : {stats['high_risk']}")
    print(f"  Total scans in DB   : {stats['total_scans']}")
    print()
    print("[+] Pipeline test complete!")
    print("[+] Open phpMyAdmin to see your data:")
    print("    http://localhost/phpmyadmin → sentinet database")
    print()


if __name__ == "__main__":
    run_pipeline()