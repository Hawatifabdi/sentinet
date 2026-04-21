#main vendors info
CAMERA_VENDORS  = ["hikvision", "dahua", "axis", "hanwha", "uniview", "reolink", "amcrest"]
PRINTER_VENDORS = ["hp", "canon", "epson", "brother", "xerox", "ricoh", "lexmark"]
WAP_VENDORS     = ["tp-link", "cisco", "netgear", "ubiquiti", "asus", "d-link", "mikrotik", "linksys"]

#main ports info
CAMERA_PORTS  = {554, 8554, 37777, 34567}
PRINTER_PORTS = {9100, 631, 515}
WAP_PORTS     = {1900}

#highly risky and safe ports
RISKY_PORTS   = {21, 23, 80, 110, 135, 139, 161, 445, 1080, 3389, 5900, 8080}
SAFE_PORTS    = {443, 22, 53, 8443}

 #non iot ports for computers
NON_IOT_PORTS = {3389, 445, 139, 135}

#main function
def extract_features(device: dict) -> dict:
    open_ports = {p["port"] for p in device.get("ports", [])}
    services = {p["service"].lower() for p in device.get("ports", [])}
    vendor_str = (device.get("vendor") or "").lower()
    os_str = (device.get("os") or "").lower()

    features = {
        
        "ip": device.get("ip"),   #ip is just kept for reference and will not be fed into the ml

        #  individual port flags
        "has_port_80":   1 if 80   in open_ports else 0,
        "has_port_443":  1 if 443  in open_ports else 0,
        "has_port_554":  1 if 554  in open_ports else 0,   # RTSP - camera
        "has_port_9100": 1 if 9100 in open_ports else 0,   # RAW print - printer
        "has_port_631":  1 if 631  in open_ports else 0,   # IPP - printer
        "has_port_515":  1 if 515  in open_ports else 0,   # LPD - printer
        "has_port_23":   1 if 23   in open_ports else 0,   # Telnet - risky IoT
        "has_port_21":   1 if 21   in open_ports else 0,   # FTP - risky
        "has_port_22":   1 if 22   in open_ports else 0,   # SSH
        "has_port_1900": 1 if 1900 in open_ports else 0,   # UPnP - WAP/IoT
        "has_port_3389": 1 if 3389 in open_ports else 0,   # RDP - computer
        "has_port_445":  1 if 445  in open_ports else 0,   # SMB - computer

        # ── service name flags ──
        "has_rtsp_service": 1 if "rtsp" in services else 0,
        "has_ipp_service":  1 if "ipp"  in services else 0,
        "has_raw_service":  1 if "raw"  in services else 0,
        "has_upnp_service": 1 if "upnp" in services or "ssdp" in services else 0,
        "has_http_service": 1 if "http" in services else 0,
        "has_ftp_service":  1 if "ftp"  in services else 0,

        # ── port count features ──
        "total_open_ports": len(open_ports),
        "risky_port_count": len(open_ports & RISKY_PORTS),
        "camera_port_hits": len(open_ports & CAMERA_PORTS),
        "printer_port_hits":len(open_ports & PRINTER_PORTS),

        # ── vendor flags ──
        "is_camera_vendor":  1 if any(v in vendor_str for v in CAMERA_VENDORS)  else 0,
        "is_printer_vendor": 1 if any(v in vendor_str for v in PRINTER_VENDORS) else 0,
        "is_wap_vendor":     1 if any(v in vendor_str for v in WAP_VENDORS)     else 0,

        # ── OS flags ──
        "has_linux_os":   1 if "linux" in os_str or "embedded" in os_str else 0,
        "has_windows_os": 1 if "windows" in os_str else 0,
        "has_macos_os":   1 if "mac" in os_str or "apple" in os_str else 0,

        # ── non-IoT signal ──
        "has_non_iot_ports": 1 if open_ports & NON_IOT_PORTS else 0,
    }

    return features

def extract_features_batch(devices: list) -> list:
    return [extract_features(d) for d in devices]

def features_to_vector(feature_dict: dict) -> list:
    EXCLUDE = {"ip"}
    return [v for k, v in feature_dict.items() if k not in EXCLUDE]


def get_feature_names() -> list:
    dummy = extract_features({
        "ip": "0.0.0.0", "mac": None, "vendor": None,
        "os": None, "ports": []
    })
    return [k for k in dummy.keys() if k != "ip"]
