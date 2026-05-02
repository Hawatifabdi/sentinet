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
from scanner.credential_checker import check_default_credentials
from scanner.firmware_checker   import check_firmware
from scanner.nvd_client         import NVD_API_KEY_ENV, find_device_vulnerabilities
from scanner.risk_scorer        import score_device_risk
from database.db                import (
    connect, create_scan, finish_scan,
    save_device, save_ports, save_credential,
    save_firmware, save_vulnerabilities, save_alert, get_dashboard_stats
)

# ── The Docker simulation subnet ──
NETWORK = "172.20.0.0/24"

# ── Ports we consider risky ──
RISKY_PORTS = {21, 23, 80, 554, 1080, 3389, 5900, 8080}


def determine_risk(device):
    return score_device_risk(
        device,
        device.get("vulnerabilities", []),
        device.get("credential_status"),
    )["level"]


def determine_credential_status(device):
    result = check_default_credentials(device)
    return result["status"], result["detail"]


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
    #  STEP 5: Check NVD and score risk
    # ────────────────────────────────────────
    print(f"\n[STEP 5] Checking NVD vulnerabilities and scoring risk...")
    if os.getenv(NVD_API_KEY_ENV):
        print("[+] NVD API key loaded from environment")
    else:
        print("[!] No NVD_API_KEY set. NVD lookups still work, but are rate limited.")

    for device in classified:
        print(f"[*] Checking {device.get('ip', '?')} ({device.get('device_type', 'unknown')})")
        credential = check_default_credentials(device)
        firmware = check_firmware(device)
        vulnerabilities = find_device_vulnerabilities(device)

        device["credential_status"] = credential["status"]
        device["credential_detail"] = credential["detail"]
        device["firmware_status"] = firmware
        device["firmware"] = firmware["version"]

        risk = score_device_risk(device, vulnerabilities, credential["status"])
        device["vulnerabilities"] = vulnerabilities
        device["risk_level"] = risk["level"]
        device["risk_score"] = risk["score"]
        device["risk_reasons"] = risk["reasons"]

        print(
            f"    Risk: {risk['level']} ({risk['score']}/100), "
            f"CVEs found: {len(vulnerabilities)}, "
            f"firmware: {firmware['version']} ({'outdated' if firmware['is_outdated'] else 'current'})"
        )

    # ────────────────────────────────────────
    #  STEP 6: Save to database
    # ────────────────────────────────────────
    print(f"\n[STEP 6] Saving results to MySQL...")

    # Count stats for scan summary
    iot_count  = sum(1 for d in classified if d.get("is_iot"))
    high_count = sum(1 for d in classified if d.get("risk_level") == "high")

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
        risk_level  = device.get("risk_level", "low")

        # Save device
        device_id = save_device(
            scan_id, ip, mac, vendor, hostname,
            is_iot, device_type, confidence, risk_level
        )

        # Save ports
        if device.get("ports"):
            save_ports(device_id, device["ports"])

        # Save credential guess
        save_credential(
            device_id,
            device.get("credential_status", "unknown"),
            device.get("credential_detail", "Manual check required"),
        )

        # Save firmware (from banner/version if available)
        firmware = device.get("firmware_status", {})
        save_firmware(
            device_id,
            firmware.get("version") or device.get("firmware") or "Unknown",
            is_outdated=firmware.get("is_outdated", False),
        )

        # Save NVD vulnerabilities
        if device.get("vulnerabilities"):
            save_vulnerabilities(device_id, device["vulnerabilities"])

        # Save alert if high risk
        if risk_level == "high":
            save_alert(
                device_id,
                alert_type="high_risk_device",
                message=f"{device_type.upper()} at {ip}: {'; '.join(device.get('risk_reasons', []))}",
                severity="high"
            )
        elif risk_level == "medium":
            save_alert(
                device_id,
                alert_type="medium_risk_device",
                message=f"{device_type.upper()} at {ip}: {'; '.join(device.get('risk_reasons', []))}",
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
        risk = d.get("risk_level", determine_risk(d))
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
