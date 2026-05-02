
import mysql.connector
from mysql.connector import Error as MySQLError
from datetime import datetime

# XAMPP connection settings 
DB = {
    "host":     "127.0.0.1",
    "user":     "root",
    "password": "",           # XAMPP default is blank
    "database": "sentinet"
}

def connect():
    try:
        return mysql.connector.connect(**DB)
    except mysql.connector.Error as err:
        print(f"[!] Database connection failed: {err}")
        raise


# ════════════════════════════════════════
#  SCAN HISTORY
# ════════════════════════════════════════

def create_scan(network_range, organization="Default Organization", user_email=None, firebase_uid=None):
    """Call this before scanning. Returns the scan_id."""
    conn = connect()
    cur  = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO scan_history (network_range, organization, user_email, firebase_uid)
            VALUES (%s, %s, %s, %s)
            """,
            (network_range, organization, user_email, firebase_uid)
        )
    except MySQLError as exc:
        if exc.errno != 1054:
            raise
        try:
            cur.execute(
                "INSERT INTO scan_history (network_range, organization) VALUES (%s, %s)",
                (network_range, organization)
            )
        except MySQLError as fallback_exc:
            if fallback_exc.errno != 1054:
                raise
            cur.execute(
                "INSERT INTO scan_history (network_range) VALUES (%s)",
                (network_range,)
            )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def finish_scan(scan_id, total, iot, high_risk):
    """Call this after scanning to update the totals."""
    conn = connect()
    cur  = conn.cursor()
    cur.execute(
        "UPDATE scan_history SET total_devices=%s, iot_devices=%s, high_risk=%s WHERE scan_id=%s",
        (total, iot, high_risk, scan_id)
    )
    conn.commit()
    conn.close()


def get_scan_history():
    """Returns all past scans for the dashboard."""
    conn = connect()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM scan_history ORDER BY scanned_at DESC")
    rows = cur.fetchall()
    conn.close()
    return rows


def get_latest_scan():
    conn = connect()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM scan_history ORDER BY scanned_at DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row


def get_scan_summaries(organization=None, user_email=None, firebase_uid=None):
    try:
        conn = connect()
        cur = conn.cursor(dictionary=True)
        params = ()
        where = ""
        if firebase_uid and organization:
            where = "WHERE firebase_uid = %s OR (firebase_uid IS NULL AND user_email IS NULL AND organization = %s)"
            params = (firebase_uid, organization)
        elif user_email and organization:
            where = "WHERE user_email = %s OR (firebase_uid IS NULL AND user_email IS NULL AND organization = %s)"
            params = (user_email, organization)
        elif firebase_uid:
            where = "WHERE firebase_uid = %s"
            params = (firebase_uid,)
        elif user_email:
            where = "WHERE user_email = %s"
            params = (user_email,)
        elif organization:
            where = "WHERE organization = %s"
            params = (organization,)
        try:
            cur.execute(f"""
                SELECT
                    scan_id,
                    network_range,
                    COALESCE(organization, 'Default Organization') AS organization,
                    user_email,
                    firebase_uid,
                    scanned_at,
                    total_devices,
                    iot_devices,
                    high_risk
                FROM scan_history
                {where}
                ORDER BY scanned_at DESC
                LIMIT 25
            """, params)
        except MySQLError as exc:
            if exc.errno != 1054:
                raise
            cur.execute("""
                SELECT
                    scan_id,
                    network_range,
                    'Default Organization' AS organization,
                    scanned_at,
                    total_devices,
                    iot_devices,
                    high_risk
                FROM scan_history
                ORDER BY scanned_at DESC
                LIMIT 25
            """)
        rows = cur.fetchall()
        conn.close()
        return rows
    except MySQLError:
        return []


# ════════════════════════════════════════
#  DEVICES
# ════════════════════════════════════════

def save_device(scan_id, ip, mac, vendor, hostname, is_iot, device_type, ml_confidence, risk_level):
    """Saves one device. Returns device_id."""
    conn = connect()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO devices
            (scan_id, ip_address, mac_address, vendor, hostname,
             is_iot, device_type, ml_confidence, risk_level)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (scan_id, ip, mac, vendor, hostname,
          1 if is_iot else 0, device_type, ml_confidence, risk_level))
    conn.commit()
    device_id = cur.lastrowid
    conn.close()
    return device_id


def get_all_devices():
    """Returns all devices for the dashboard."""
    conn = connect()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM devices ORDER BY first_seen DESC")
    rows = cur.fetchall()
    conn.close()
    return rows


def get_devices_by_scan(scan_id):
    """Returns devices from one specific scan."""
    conn = connect()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM devices WHERE scan_id = %s", (scan_id,))
    rows = cur.fetchall()
    conn.close()
    return rows


# ════════════════════════════════════════
#  PORTS
# ════════════════════════════════════════

# Ports that are considered risky
RISKY_PORTS = {21, 23, 80, 554, 1080, 3389, 5900, 8080}

def save_ports(device_id, ports):
    """
    ports = list of dicts from nmap_scanner.py
    e.g. [{"port": 80, "protocol": "tcp", "service": "http"}, ...]
    """
    conn = connect()
    cur  = conn.cursor()
    for p in ports:
        risky = 1 if p["port"] in RISKY_PORTS else 0
        cur.execute("""
            INSERT INTO ports (device_id, port_number, protocol, service_name, is_risky)
            VALUES (%s, %s, %s, %s, %s)
        """, (device_id, p["port"], p.get("protocol", "tcp"), p.get("service", ""), risky))
    conn.commit()
    conn.close()


def get_ports(device_id):
    conn = connect()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM ports WHERE device_id = %s", (device_id,))
    rows = cur.fetchall()
    conn.close()
    return rows


# ════════════════════════════════════════
#  CREDENTIALS
# ════════════════════════════════════════

def save_credential(device_id, status, detail=None):
    """
    status = 'default' | 'weak' | 'strong' | 'unknown'
    """
    conn = connect()
    cur  = conn.cursor()
    cur.execute(
        "INSERT INTO credentials (device_id, status, detail) VALUES (%s, %s, %s)",
        (device_id, status, detail)
    )
    conn.commit()
    conn.close()


# ════════════════════════════════════════
#  FIRMWARE
# ════════════════════════════════════════

def save_firmware(device_id, version, is_outdated=False):
    conn = connect()
    cur  = conn.cursor()
    cur.execute(
        "INSERT INTO firmware (device_id, version_string, is_outdated) VALUES (%s, %s, %s)",
        (device_id, version, 1 if is_outdated else 0)
    )
    conn.commit()
    conn.close()


# ════════════════════════════════════════
#  VULNERABILITIES
# ════════════════════════════════════════

def save_vulnerabilities(device_id, vulns):
    """
    vulns = list of dicts from nvd_client.py
    e.g. [{"cve_id": "CVE-2021-36260", "cvss_score": 9.8, "severity": "critical", "description": "..."}]
    """
    conn = connect()
    cur  = conn.cursor()
    for v in vulns:
        cur.execute("""
            INSERT INTO vulnerabilities (device_id, cve_id, cvss_score, severity, description)
            VALUES (%s, %s, %s, %s, %s)
        """, (device_id, v["cve_id"], v.get("cvss_score", 0), v.get("severity", "low"), v.get("description", "")))
    conn.commit()
    conn.close()


def get_vulnerabilities(device_id):
    conn = connect()
    cur  = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT * FROM vulnerabilities WHERE device_id = %s ORDER BY cvss_score DESC",
        (device_id,)
    )
    rows = cur.fetchall()
    conn.close()
    return rows


# ════════════════════════════════════════
#  ALERTS
# ════════════════════════════════════════

def save_alert(device_id, alert_type, message, severity="medium"):
    conn = connect()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO alerts (device_id, alert_type, severity, message)
        VALUES (%s, %s, %s, %s)
    """, (device_id, alert_type, severity, message))
    conn.commit()
    conn.close()


def get_alerts():
    conn = connect()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT a.*, d.ip_address
        FROM alerts a
        JOIN devices d ON d.device_id = a.device_id
        ORDER BY a.created_at DESC
        LIMIT 50
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


# ════════════════════════════════════════
#  USERS
# ════════════════════════════════════════

def create_user(full_name, email, password_hash, organization, role="operator"):
    conn = connect()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO admin_users (full_name, email, password_hash, organization, role)
        VALUES (%s, %s, %s, %s, %s)
    """, (full_name, email, password_hash, organization, role))
    conn.commit()
    conn.close()


def get_user_by_email(email):
    conn = connect()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM admin_users WHERE email = %s", (email,))
    user = cur.fetchone()
    conn.close()
    return user


# ════════════════════════════════════════
#  DASHBOARD STATS
# ════════════════════════════════════════

def get_dashboard_stats():
    """Returns the numbers shown at the top of the dashboard."""
    try:
        conn = connect()
        cur  = conn.cursor(dictionary=True)

        cur.execute("SELECT COUNT(*) AS total FROM devices")
        total = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) AS iot FROM devices WHERE is_iot = 1")
        iot = cur.fetchone()["iot"]

        cur.execute("SELECT COUNT(*) AS high FROM devices WHERE risk_level IN ('high', 'critical')")
        high = cur.fetchone()["high"]

        cur.execute("SELECT COUNT(*) AS scans FROM scan_history")
        scans = cur.fetchone()["scans"]

        conn.close()
        return {
            "total_devices": total,
            "iot_devices":   iot,
            "high_risk":     high,
            "total_scans":   scans
        }
    except MySQLError:
        return {"total_devices": 0, "iot_devices": 0, "high_risk": 0, "total_scans": 0}
