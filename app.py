import html
import io
import os
from datetime import datetime

from flask import Flask, Response, jsonify, request, send_from_directory
from mysql.connector import Error as MySQLError

from database.db import connect, get_dashboard_stats, get_scan_summaries
from scanner.pipeline import run_scan_pipeline


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
DEFAULT_ORGANIZATION = os.getenv("SENTINET_ORG", "Default Organization")

# Load NVD API key from .env file if exists
ENV_FILE = os.path.join(BASE_DIR, ".env")
if os.path.exists(ENV_FILE):
    with open(ENV_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip().strip('"')

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")


def ensure_schema():
    try:
        conn = connect()
        cur = conn.cursor()
        additions = [
            (
                "organization",
                "ALTER TABLE scan_history "
                "ADD COLUMN organization VARCHAR(200) DEFAULT 'Default Organization' AFTER network_range",
            ),
            (
                "user_email",
                "ALTER TABLE scan_history ADD COLUMN user_email VARCHAR(255) AFTER organization",
            ),
            (
                "firebase_uid",
                "ALTER TABLE scan_history ADD COLUMN firebase_uid VARCHAR(128) AFTER user_email",
            ),
        ]
        for column, sql in additions:
            cur.execute("SHOW COLUMNS FROM scan_history LIKE %s", (column,))
            if cur.fetchone() is None:
                cur.execute(sql)
        conn.commit()
        conn.close()
    except MySQLError as exc:
        print(f"[!] Schema check skipped: {exc}")


def rows(sql, params=None):
    conn = connect()
    cur = conn.cursor(dictionary=True)
    cur.execute(sql, params or ())
    data = cur.fetchall()
    conn.close()
    return data


def row(sql, params=None):
    conn = connect()
    cur = conn.cursor(dictionary=True)
    cur.execute(sql, params or ())
    data = cur.fetchone()
    conn.close()
    return data


def normalize_risk(value):
    risk = (value or "low").lower()
    if risk == "critical":
        return "high"
    return "med" if risk == "medium" else risk


def device_payload(device):
    device_id = device["device_id"]
    ports = rows("SELECT * FROM ports WHERE device_id=%s ORDER BY port_number", (device_id,))
    credentials = row("SELECT * FROM credentials WHERE device_id=%s ORDER BY cred_id DESC LIMIT 1", (device_id,))
    firmware = row("SELECT * FROM firmware WHERE device_id=%s ORDER BY firmware_id DESC LIMIT 1", (device_id,))
    vulnerabilities = rows(
        "SELECT * FROM vulnerabilities WHERE device_id=%s ORDER BY cvss_score DESC, cve_id",
        (device_id,),
    )

    dtype = device.get("device_type") or "unknown"
    frontend_type = dtype if dtype in {"camera", "printer", "wap"} else "non-iot"
    type_labels = {
        "camera": "IP Camera",
        "printer": "Printer",
        "wap": "Wireless AP",
        "non-iot": "Computer",
    }

    safe_ports = {22, 443, 631}
    port_items = [
        {
            "port": p["port_number"],
            "service": (p.get("service_name") or "unknown").upper(),
            "safe": p["port_number"] in safe_ports and not p.get("is_risky"),
        }
        for p in ports
    ]

    vuln_items = [
        {
            "source": "nvd",
            "sev": normalize_risk(v.get("severity")),
            "title": v.get("cve_id") or "NVD finding",
            "desc": v.get("description") or "No description available.",
            "cvss": float(v.get("cvss_score") or 0),
        }
        for v in vulnerabilities
    ]

    if credentials:
        sev = "high" if credentials["status"] == "default" else "med"
        if credentials["status"] in {"default", "weak"}:
            vuln_items.append({
                "source": "local",
                "sev": sev,
                "title": f"{credentials['status'].title()} credentials",
                "desc": credentials.get("detail") or "Credential review required.",
                "cvss": 0,
            })

    if firmware and firmware.get("is_outdated"):
        vuln_items.append({
            "source": "local",
            "sev": "med",
            "title": "Outdated firmware",
            "desc": firmware.get("version_string") or "Firmware is marked outdated.",
            "cvss": 0,
        })

    return {
        "id": device_id,
        "name": device.get("hostname") or device.get("ip_address"),
        "mac": device.get("mac_address") or "Unknown",
        "ip": device.get("ip_address"),
        "type": frontend_type,
        "typeLabel": type_labels.get(frontend_type, "Device"),
        "isIot": bool(device.get("is_iot")),
        "risk": normalize_risk(device.get("risk_level")),
        "status": "online",
        "manufacturer": device.get("vendor") or "Unknown",
        "firmware": (firmware or {}).get("version_string") or "Unknown",
        "firmwareStatus": "outdated" if (firmware or {}).get("is_outdated") else "current",
        "password": (credentials or {}).get("status") or "unknown",
        "ports": port_items,
        "vulnerabilities": vuln_items,
        "mlConfidence": float(device.get("ml_confidence") or 0),
    }


def scan_devices(scan_id=None):
    if scan_id is None:
        latest = row("SELECT scan_id FROM scan_history ORDER BY scanned_at DESC LIMIT 1")
        if not latest:
            return []
        scan_id = latest["scan_id"]

    devices = rows(
        "SELECT * FROM devices WHERE scan_id=%s ORDER BY risk_level='high' DESC, ip_address",
        (scan_id,),
    )
    return [device_payload(device) for device in devices]


def analytics_payload(organization=None, user_email=None, firebase_uid=None):
    scans = get_scan_summaries(organization, user_email, firebase_uid)
    devices = scan_devices(scans[0]["scan_id"]) if scans else []
    risk_counts = {"high": 0, "med": 0, "low": 0}
    type_counts = {"camera": 0, "printer": 0, "wap": 0, "non-iot": 0}

    for device in devices:
        risk_counts[device["risk"]] = risk_counts.get(device["risk"], 0) + 1
        type_counts[device["type"]] = type_counts.get(device["type"], 0) + 1

    return {
        "stats": get_dashboard_stats(),
        "scans": scans,
        "devices": devices,
        "riskCounts": risk_counts,
        "typeCounts": type_counts,
    }


def pdf_bytes(report):
    def pdf_escape(value):
        if not isinstance(value, str):
            value = str(value)
        return html.escape(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    devices = report["devices"]
    cve_total = sum(
        1
        for device in devices
        for vuln in device.get("vulnerabilities", [])
        if vuln.get("source") == "nvd" or str(vuln.get("title", "")).startswith("CVE-")
    )
    latest_scan = report["scans"][0] if report["scans"] else {}

    lines = [
        "SentiNet Scan Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "SUMMARY",
        f"Organization: {latest_scan.get('organization', 'Default Organization')}",
        f"Network: {latest_scan.get('network_range', 'No scan recorded')}",
        f"Devices found: {len(devices)}",
        f"IoT devices: {sum(1 for d in devices if d.get('isIot'))}",
        f"High risk devices: {sum(1 for d in devices if d.get('risk') == 'high')}",
        f"NVD CVEs found: {cve_total}",
        "",
        "DEVICES",
        "-" * 60,
    ]

    for idx, device in enumerate(report["devices"], 1):
        ports = ", ".join(f"{p['port']}/{p['service']}" for p in device.get("ports", [])[:6]) or "None"
        cves = [
            vuln for vuln in device.get("vulnerabilities", [])
            if vuln.get("source") == "nvd" or str(vuln.get("title", "")).startswith("CVE-")
        ]
        local_findings = [
            vuln for vuln in device.get("vulnerabilities", [])
            if vuln.get("source") != "nvd" and not str(vuln.get("title", "")).startswith("CVE-")
        ]

        lines.append(f"{idx}. {device['name']} ({device['ip']})")
        lines.append(f"   Type: {device['typeLabel']} | Risk: {device['risk'].upper()} | IoT: {'Yes' if device['isIot'] else 'No'}")
        lines.append(f"   Manufacturer: {device['manufacturer']} | Firmware: {device['firmware']}")
        lines.append(f"   Open ports: {ports}")
        if cves:
            top_cves = ", ".join(f"{v['title']} CVSS {v['cvss']}" for v in cves[:3])
            lines.append(f"   NVD CVEs: {top_cves}")
        else:
            lines.append("   NVD CVEs: None found")
        if local_findings:
            checks = ", ".join(v["title"] for v in local_findings[:3])
            lines.append(f"   Local checks: {checks}")
        lines.append("")

    escaped = [pdf_escape(line) for line in lines]
    
    # Split into pages (45 lines per page)
    page_height = 45
    pages = []
    current_page = []
    
    for line in escaped:
        current_page.append(line)
        if len(current_page) >= page_height:
            pages.append(current_page)
            current_page = []
    
    if current_page:
        pages.append(current_page)
    
    # Build multi-page PDF
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>"]
    
    # Pages object
    page_kids = " ".join([f"{3 + i} 0 R" for i in range(len(pages))])
    objects.append(b"<< /Type /Pages /Kids [" + page_kids.encode() + b"] /Count " + str(len(pages)).encode() + b" >>")
    
    # Stream objects for each page
    streams = []
    for page_lines in pages:
        content = "BT /F1 9 Tf 40 750 Td 11 TL " + " T* ".join(f"({line}) Tj" for line in page_lines) + " ET"
        stream = content.encode("latin-1", "replace")
        streams.append(stream)
    
    # Page objects
    stream_obj_start = 3 + len(pages)
    for i in range(len(pages)):
        stream_ref = stream_obj_start + i
        font_ref = stream_obj_start + len(pages)
        page_obj = (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 " + str(font_ref).encode() + b" 0 R >> >> "
            b"/Contents " + str(stream_ref).encode() + b" 0 R >>"
        )
        objects.append(page_obj)
    
    # Stream objects
    for stream in streams:
        objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
    
    # Font object
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    pdf = io.BytesIO()
    pdf.write(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, 1):
        offsets.append(pdf.tell())
        pdf.write(f"{i} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = pdf.tell()
    pdf.write(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        pdf.write(f"{offset:010d} 00000 n \n".encode())
    pdf.write(
        f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return pdf.getvalue()


@app.route("/")
def root():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/dashboard")
def dashboard():
    return send_from_directory(FRONTEND_DIR, "dashboard.html")


@app.route("/signin")
def signin():
    return send_from_directory(FRONTEND_DIR, "signin.html")


@app.route("/reports")
def reports():
    return send_from_directory(FRONTEND_DIR, "reports.html")


@app.route("/api/latest")
def api_latest():
    return jsonify({"devices": []})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        payload = request.get_json(silent=True) or {}
        network = payload.get("network") or "172.20.0.0/24"
        organization = payload.get("organization") or DEFAULT_ORGANIZATION
        user_email = payload.get("userEmail")
        firebase_uid = payload.get("firebaseUid")
        use_nvd = payload.get("useNvd", True)
        scan_id, devices = run_scan_pipeline(
            network,
            organization,
            use_nvd=bool(use_nvd),
            user_email=user_email,
            firebase_uid=firebase_uid,
        )
        return jsonify({"scanId": scan_id, "devices": scan_devices(scan_id)})
    except MySQLError as exc:
        app.logger.error("Database error during scan: %s", exc)
        return jsonify({
            "error": "Database unavailable",
            "detail": "MySQL server is not running or unreachable",
            "hint": "Start MySQL/XAMPP and try again",
        }), 503
    except Exception as exc:
        app.logger.exception("Scan failed")
        return jsonify({
            "error": "Scan failed",
            "detail": str(exc),
            "hint": "Check that MySQL is running, Docker containers are up, and the scan range is reachable.",
        }), 500


@app.route("/api/analytics")
def api_analytics():
    try:
        organization = request.args.get("organization") or None
        user_email = request.args.get("userEmail") or None
        firebase_uid = request.args.get("firebaseUid") or None
        return jsonify(analytics_payload(organization, user_email, firebase_uid))
    except MySQLError as exc:
        app.logger.error("Database error in analytics: %s", exc)
        return jsonify({
            "stats": {"total_devices": 0, "iot_devices": 0, "high_risk": 0, "total_scans": 0},
            "scans": [],
            "devices": [],
            "riskCounts": {"high": 0, "med": 0, "low": 0},
            "typeCounts": {"camera": 0, "printer": 0, "wap": 0, "non-iot": 0},
            "error": "Database unavailable",
        }), 503


@app.route("/api/report.pdf")
def api_report_pdf():
    organization = request.args.get("organization") or None
    user_email = request.args.get("userEmail") or None
    firebase_uid = request.args.get("firebaseUid") or None
    data = analytics_payload(organization, user_email, firebase_uid)
    return Response(
        pdf_bytes(data),
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=sentinet-report.pdf"},
    )


if __name__ == "__main__":
    ensure_schema()
    app.run(host="127.0.0.1", port=5000, debug=True)
