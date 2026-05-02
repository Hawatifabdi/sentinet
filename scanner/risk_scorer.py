RISKY_PORTS = {
    21: "FTP is open",
    23: "Telnet is open",
    80: "Unencrypted web interface is open",
    554: "RTSP camera stream is open",
    1080: "SOCKS proxy port is open",
    3389: "RDP is open",
    5900: "VNC is open",
    8080: "Alternate web interface is open",
}

CRITICAL_PORTS = {23, 3389, 5900}
HIGH_SEVERITIES = {"critical", "high"}
MEDIUM_SEVERITIES = {"medium"}


def _normalise_severity(value):
    return (value or "").strip().lower()


def _credential_risk(device, credential_status=None):
    if credential_status:
        return credential_status

    ports = {p.get("port") for p in device.get("ports", [])}
    device_type = device.get("device_type", "unknown")

    if device_type in ("camera", "wap") and 80 in ports:
        return "default"
    if device_type == "printer" and 80 in ports:
        return "weak"
    return "unknown"


def score_device_risk(device, vulnerabilities=None, credential_status=None):
    """
    Returns a risk decision for one classified device.

    The score blends simple exposure signals:
    - known CVEs from NVD
    - risky open ports
    - default/weak credential heuristics
    - IoT classification confidence
    """
    vulnerabilities = vulnerabilities or []
    ports = {p.get("port") for p in device.get("ports", [])}
    score = 0
    reasons = []

    for vuln in vulnerabilities:
        severity = _normalise_severity(vuln.get("severity"))
        cvss = float(vuln.get("cvss_score") or 0)
        cve_id = vuln.get("cve_id", "CVE")

        if severity == "critical" or cvss >= 9.0:
            score += 45
            reasons.append(f"{cve_id} is critical")
        elif severity == "high" or cvss >= 7.0:
            score += 35
            reasons.append(f"{cve_id} is high severity")
        elif severity in MEDIUM_SEVERITIES or cvss >= 4.0:
            score += 18
            reasons.append(f"{cve_id} is medium severity")
        elif cvss > 0:
            score += 8
            reasons.append(f"{cve_id} is low severity")

    risky_ports = ports & set(RISKY_PORTS)
    for port in sorted(risky_ports):
        score += 20 if port in CRITICAL_PORTS else 10
        reasons.append(RISKY_PORTS[port])

    credential_status = _credential_risk(device, credential_status)
    if credential_status == "default":
        score += 40
        reasons.append("Default credentials are likely")
    elif credential_status == "weak":
        score += 20
        reasons.append("Weak credentials are possible")

    firmware = device.get("firmware_status") or {}
    if firmware.get("is_outdated"):
        score += 25
        reasons.append(f"Outdated firmware: {firmware.get('version', 'Unknown')}")

    if device.get("is_iot") and device.get("ml_confidence", 0) >= 80:
        score += 5
        reasons.append("Device is confidently classified as IoT")

    if score >= 70:
        level = "high"
    elif score >= 35:
        level = "medium"
    else:
        level = "low"

    return {
        "level": level,
        "score": min(score, 100),
        "reasons": reasons or ["No major risk signals found"],
    }


def determine_risk(device, vulnerabilities=None, credential_status=None):
    return score_device_risk(device, vulnerabilities, credential_status)["level"]
