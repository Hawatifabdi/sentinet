import html
import io
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime

from flask import Flask, Response, jsonify, redirect, request, send_from_directory
from mysql.connector import Error as MySQLError

from database.db import connect, get_dashboard_stats, get_scan_summaries
from scanner.pipeline import run_scan_pipeline


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
DEFAULT_ORGANIZATION = os.getenv("SENTINET_ORG", "Default Organization")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

# Load NVD API key from .env file if exists
ENV_FILE = os.path.join(BASE_DIR, ".env")
if os.path.exists(ENV_FILE):
    with open(ENV_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip().strip('"')

OPENAI_MODEL = os.getenv("OPENAI_MODEL", OPENAI_MODEL)
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


def fallback_security_explanation(title, description=None):
    summary = description or "This finding means the device may have a known security weakness."
    return {
        "explanation": summary[:260],
        "why_it_matters": "Attackers can use known weaknesses, exposed services, or weak configuration to access the device or move deeper into the network.",
        "steps": [
            "Confirm the affected device, model, firmware version, and exposed service.",
            "Apply the vendor firmware update or security patch if one is available.",
            "Disable unnecessary services and restrict device access to trusted administrators.",
            "Change default or weak passwords, then rescan the device to confirm the issue is resolved.",
        ],
        "source": "local",
    }


def call_openai_text(prompt, max_tokens=420):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None

    payload = {
        "model": OPENAI_MODEL,
        "input": prompt,
        "max_output_tokens": max_tokens,
        "text": {"verbosity": "low"},
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=18) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as exc:
        app.logger.warning("OpenAI request failed: %s", exc)
        return None

    if data.get("output_text"):
        return data["output_text"].strip()

    chunks = []
    for item in data.get("output", []):
        for content in item.get("content", []):
            text = content.get("text")
            if text:
                chunks.append(text)
    return "\n".join(chunks).strip() or None


def json_from_openai(prompt, fallback):
    text = call_openai_text(prompt)
    if not text:
        return fallback
    match = re.search(r"\{.*\}", text, re.S)
    try:
        parsed = json.loads(match.group(0) if match else text)
        parsed["source"] = "openai"
        return parsed
    except (ValueError, AttributeError):
        fallback["explanation"] = text[:500]
        return fallback


def vulnerability_fix(vuln):
    title = (vuln.get("title") or "").lower()
    desc = (vuln.get("desc") or "").lower()
    if "default" in title or "credential" in title:
        return "Change Password"
    if "firmware" in title:
        return "Update Firmware"
    if "telnet" in title or "telnet" in desc:
        return "Disable Telnet"
    if str(vuln.get("title", "")).startswith("CVE-"):
        return "Apply Vendor Patch"
    return "Review Configuration"


def build_security_center_payload(organization=None, user_email=None, firebase_uid=None):
    data = analytics_payload(organization, user_email, firebase_uid)
    devices = data.get("devices", [])
    recommendations = []
    incidents = []

    for device in devices:
        for port in device.get("ports", []):
            service = str(port.get("service") or "").lower()
            if port.get("port") == 23 or service == "telnet" or not port.get("safe"):
                title = "Telnet Open" if port.get("port") == 23 or service == "telnet" else f"Risky Port {port.get('port')}"
                recommendations.append({
                    "device": device.get("name"),
                    "ip": device.get("ip"),
                    "severity": "high" if port.get("port") == 23 else "med",
                    "issue": title,
                    "fix": "Disable Telnet" if title == "Telnet Open" else "Restrict Port",
                    "explanation": "An exposed management or service port increases the device attack surface.",
                    "why": "Internet-connected and internal attackers often scan for open services before attempting compromise.",
                    "steps": ["Confirm the service owner.", "Disable the service if unused.", "Restrict access using firewall rules.", "Rescan the device."],
                })

        for vuln in device.get("vulnerabilities", []):
            title = vuln.get("title") or "Security issue"
            fix = vulnerability_fix(vuln)
            fallback = fallback_security_explanation(title, vuln.get("desc"))
            recommendations.append({
                "device": device.get("name"),
                "ip": device.get("ip"),
                "severity": vuln.get("sev") or device.get("risk"),
                "issue": title,
                "fix": fix,
                "explanation": fallback["explanation"],
                "why": fallback["why_it_matters"],
                "steps": fallback["steps"],
            })
            if (vuln.get("sev") or "low") in {"high", "med"}:
                incidents.append({
                    "id": len(incidents) + 1,
                    "device": device.get("name"),
                    "ip": device.get("ip"),
                    "severity": vuln.get("sev") or "med",
                    "status": "Open",
                    "issue": title,
                    "assignedAction": fix,
                })

    return {
        **data,
        "recommendations": recommendations,
        "incidents": incidents,
        "awareness": [
            {
                "category": "Passwords",
                "level": "5 min",
                "title": "Replace Default Device Passwords",
                "body": "Factory passwords are often public. Any camera, printer, or access point using a default login should be treated as exposed.",
                "points": ["Use a unique password per device.", "Store credentials in an approved password manager.", "Disable shared admin accounts where possible."],
                "links": [
                    {"label": "NIST IoT cybersecurity baseline", "url": "https://www.nist.gov/itl/applied-cybersecurity/nist-cybersecurity-iot-program/nistir-8259-series"},
                    {"label": "CISA IoT security guidance", "url": "https://www.cisa.gov/news-events/news/securing-internet-things-iot"},
                ],
            },
            {
                "category": "Remote Access",
                "level": "5 min",
                "title": "Disable Telnet and Prefer SSH",
                "body": "Telnet is unsafe for administration because it does not provide modern protection for management traffic.",
                "points": ["Turn off Telnet on IoT devices.", "Use SSH only for trusted admins.", "Restrict admin ports by firewall or VLAN."],
                "links": [
                    {"label": "CISA exposure reduction guidance", "url": "https://www.cisa.gov/resources-tools/resources/exposure-reduction"},
                    {"label": "NIST IoT capability catalogs", "url": "https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/"},
                ],
            },
            {
                "category": "Patching",
                "level": "10 min",
                "title": "Keep Firmware Updated",
                "body": "Firmware updates close known vulnerabilities and can remove weaknesses that attackers already know how to exploit.",
                "points": ["Check vendor firmware pages monthly.", "Patch high-risk devices first.", "Rescan after updates to confirm improvement."],
                "links": [
                    {"label": "NISTIR 8259 series", "url": "https://www.nist.gov/itl/applied-cybersecurity/nist-cybersecurity-iot-program/nistir-8259-series"},
                    {"label": "NIST CSF 2.0 for small business", "url": "https://www.nist.gov/itl/smallbusinesscyber/nist-cybersecurity-framework-0"},
                ],
            },
            {
                "category": "Network Design",
                "level": "10 min",
                "title": "Separate IoT from Office Systems",
                "body": "IoT devices should not sit on the same network as sensitive laptops, servers, or finance systems.",
                "points": ["Place IoT devices on their own VLAN.", "Allow only required traffic.", "Block device-to-device access where unnecessary."],
                "links": [
                    {"label": "CISA IoT acquisition guidance", "url": "https://www.cisa.gov/resources-tools/resources/internet-things-iot-acquisition-guidance-document"},
                    {"label": "NIST CSF 2.0 quick start guides", "url": "https://www.nist.gov/cyberframework/quick-start-guides"},
                ],
            },
            {
                "category": "Phishing",
                "level": "5 min",
                "title": "Be Careful with Vendor Update Links",
                "body": "Attackers may send fake firmware or support links that look like they come from a device vendor.",
                "points": ["Use official vendor websites.", "Avoid firmware links from random emails.", "Ask IT before installing device tools."],
                "links": [
                    {"label": "NIST small business cybersecurity", "url": "https://www.nist.gov/itl/smallbusinesscyber"},
                    {"label": "CISA secure our world", "url": "https://www.cisa.gov/secure-our-world"},
                ],
            },
            {
                "category": "Physical Security",
                "level": "5 min",
                "title": "Protect Devices in Public Areas",
                "body": "Printers, cameras, and access points in shared spaces can be reset, unplugged, or tampered with.",
                "points": ["Mount devices securely.", "Limit access to reset buttons.", "Report unexpected device reboots or changes."],
                "links": [
                    {"label": "CISA IoT acquisition guidance", "url": "https://www.cisa.gov/resources-tools/resources/internet-things-iot-acquisition-guidance-document"},
                    {"label": "NIST IoT cybersecurity program", "url": "https://www.nist.gov/itl/applied-cybersecurity/nist-cybersecurity-iot-program"},
                ],
            },
            {
                "category": "Data Privacy",
                "level": "8 min",
                "title": "Know What Cameras and Printers Store",
                "body": "IoT devices can store images, documents, logs, and credentials. That data should be protected like any other business data.",
                "points": ["Clear printer queues when needed.", "Limit camera access to authorized staff.", "Review device storage settings."],
                "links": [
                    {"label": "NISTIR 8259B supporting capabilities", "url": "https://www.nist.gov/itl/applied-cybersecurity/nist-cybersecurity-iot-program/nistir-8259-series"},
                    {"label": "NIST IoT requirement catalogs", "url": "https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/"},
                ],
            },
            {
                "category": "Incident Reporting",
                "level": "5 min",
                "title": "Report Strange Device Behavior",
                "body": "A device that reboots often, opens new services, or stops responding may need security review.",
                "points": ["Report unknown devices quickly.", "Share screenshots or times of suspicious behavior.", "Do not ignore repeated alerts."],
                "links": [
                    {"label": "NIST CSF 2.0 quick start guides", "url": "https://www.nist.gov/cyberframework/quick-start-guides"},
                    {"label": "CISA incident reporting", "url": "https://www.cisa.gov/report"},
                ],
            },
        ],
    }


def local_assistant_answer(question, devices):
    q = question.lower()
    devices = devices or []
    high_risk = [d for d in devices if d.get("risk") == "high"]
    findings = [
        (device, vuln)
        for device in devices
        for vuln in device.get("vulnerabilities", [])
    ]
    cves = [
        (device, vuln)
        for device, vuln in findings
        if str(vuln.get("title", "")).startswith("CVE-") or vuln.get("source") == "nvd"
    ]

    if not devices:
        return "I do not have scan data yet. Run a network scan first, then I can identify risky devices, explain CVEs, and suggest fixes."

    if "most vulnerable" in q or "riskiest" in q or "highest risk" in q:
        ranked = sorted(
            devices,
            key=lambda d: (
                d.get("risk") != "high",
                d.get("risk") != "med",
                -len(d.get("vulnerabilities", [])),
            ),
        )
        top = ranked[0]
        issues = ", ".join(v.get("title", "finding") for v in top.get("vulnerabilities", [])[:3]) or "risk signals from the scan"
        return f"{top.get('name')} ({top.get('ip')}) is the device I would review first. It is marked {top.get('risk')} risk and the main findings are: {issues}."

    if "secure" in q or "protect" in q or "fix" in q or "recommend" in q:
        actions = []
        if any(d.get("password") == "default" for d in devices):
            actions.append("change default passwords")
        if any(d.get("firmwareStatus") == "outdated" for d in devices):
            actions.append("update outdated firmware")
        if any(any(p.get("port") == 23 for p in d.get("ports", [])) for d in devices):
            actions.append("disable Telnet")
        if any(any(not p.get("safe") for p in d.get("ports", [])) for d in devices):
            actions.append("restrict risky open ports")
        if cves:
            actions.append("apply vendor patches for the listed CVEs")
        return "Recommended order: " + "; ".join(actions or ["keep current controls, monitor changes, and rescan regularly"]) + ". After changes, run another scan to prove the risk score improved."

    if "cve" in q:
        if not cves:
            return "I do not see NVD CVEs in the latest scan context. If a CVE appears after scanning, use the Explain button on the dashboard card for a simpler explanation and fix steps."
        device, vuln = sorted(cves, key=lambda item: float(item[1].get("cvss") or 0), reverse=True)[0]
        return f"The most serious CVE I see is {vuln.get('title')} on {device.get('name')} with CVSS {vuln.get('cvss')}. In simple terms: {vuln.get('desc', 'it is a known weakness')[:220]} Review the vendor advisory, patch the device, and restrict access until fixed."

    if "compliance" in q or "policy" in q:
        weak_passwords = sum(1 for d in devices if d.get("password") != "strong")
        outdated = sum(1 for d in devices if d.get("firmwareStatus") == "outdated")
        telnet = sum(1 for d in devices if any(p.get("port") == 23 for p in d.get("ports", [])))
        return f"Compliance concerns: {weak_passwords} devices need stronger password evidence, {outdated} devices have outdated firmware, and {telnet} devices expose Telnet. Those are the policies I would address first."

    if "incident" in q:
        return f"I would generate incidents for {len(high_risk)} high-risk devices and any medium-risk CVEs that need tracking. Start with high severity items, assign an action, then move each item from Open to In Progress to Resolved after rescanning."

    if "monitor" in q or "online" in q or "live" in q:
        return f"The latest scan includes {len(devices)} devices. To keep visibility current, run a new scan after connecting new equipment or changing device settings."

    if "password" in q or "credential" in q:
        default_devices = [d for d in devices if d.get("password") == "default"]
        names = ", ".join(d.get("name") for d in default_devices[:5])
        return f"{len(default_devices)} devices show default credentials. Change passwords first on: {names or 'none listed'}. Use long unique passwords and disable shared admin accounts where possible."

    if "firmware" in q or "update" in q:
        outdated = [d for d in devices if d.get("firmwareStatus") == "outdated"]
        names = ", ".join(d.get("name") for d in outdated[:5])
        return f"{len(outdated)} devices have outdated firmware. Prioritize: {names or 'none listed'}. Download firmware only from the vendor and rescan after updating."

    if "telnet" in q or "ssh" in q:
        telnet_devices = [d for d in devices if any(p.get("port") == 23 for p in d.get("ports", []))]
        names = ", ".join(d.get("name") for d in telnet_devices[:5])
        return f"Telnet should be disabled because it is not secure for management traffic. I found Telnet exposure on: {names or 'no devices in this context'}. Use SSH and restrict admin access."

    return f"I reviewed {len(devices)} devices and {len(findings)} findings. The safest next step is to handle high-risk devices first, then fix default passwords, outdated firmware, Telnet, risky ports, and CVEs in that order."


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


@app.route("/security")
def security_center():
    return redirect("/recommendations")


@app.route("/recommendations")
@app.route("/sentinet-ai")
@app.route("/incidents")
@app.route("/awareness")
def security_module_page():
    return send_from_directory(FRONTEND_DIR, "security.html")


@app.route("/compliance")
def removed_compliance():
    return redirect("/recommendations")


@app.route("/monitoring")
def removed_monitoring():
    return redirect("/recommendations")


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
        return jsonify({
            "scanId": scan_id,
            "devices": scan_devices(scan_id),
        })
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


@app.route("/api/security-center")
def api_security_center():
    try:
        organization = request.args.get("organization") or None
        user_email = request.args.get("userEmail") or None
        firebase_uid = request.args.get("firebaseUid") or None
        return jsonify(build_security_center_payload(organization, user_email, firebase_uid))
    except MySQLError as exc:
        app.logger.error("Database error in security center: %s", exc)
        return jsonify({
            "devices": [],
            "recommendations": [],
            "incidents": [],
            "awareness": [],
            "error": "Database unavailable",
        }), 503


@app.route("/api/ai/explain-cve", methods=["POST"])
def api_explain_cve():
    payload = request.get_json(silent=True) or {}
    cve_id = payload.get("cveId") or "CVE finding"
    description = payload.get("description") or ""
    device = payload.get("device") or "this device"
    fallback = fallback_security_explanation(cve_id, description)
    prompt = f"""
Return only JSON with keys explanation, why_it_matters, steps.
Explain this cybersecurity finding in simple student-friendly language.
Device: {device}
Finding: {cve_id}
Known description: {description}
Use 1-2 short sentences for explanation and why_it_matters.
Use exactly 4 practical step-by-step fixes.
"""
    return jsonify(json_from_openai(prompt, fallback))


@app.route("/api/ai/status")
def api_ai_status():
    configured = bool(os.getenv("OPENAI_API_KEY"))
    return jsonify({
        "configured": configured,
        "model": OPENAI_MODEL if configured else None,
        "mode": "openai" if configured else "local-fallback",
    })


@app.route("/api/ai/assistant", methods=["POST"])
def api_ai_assistant():
    payload = request.get_json(silent=True) or {}
    question = (payload.get("question") or "").strip()
    devices = (payload.get("devices") or [])[:20]
    if not question:
        return jsonify({"answer": "Ask a security question about the latest scan.", "source": "local"})

    context = json.dumps(devices, indent=2)[:6000]
    fallback = local_assistant_answer(question, devices)

    prompt = f"""
You are SentiNet AI, a concise cybersecurity assistant for an IoT network scanner.
Answer in simple language, using only the scan context when possible.
Question: {question}
Latest scan devices JSON:
{context}
"""
    openai_answer = call_openai_text(prompt, max_tokens=360)
    if openai_answer:
        return jsonify({"answer": openai_answer, "source": "openai"})
    return jsonify({"answer": fallback, "source": "local"})


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
