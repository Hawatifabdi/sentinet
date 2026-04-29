
#  Generates labelled training data from scan results

from database.scanner.feature_extraction import extract_features, features_to_vector
import csv



def label_device(device: dict) -> str:
 
    ports    = {p["port"]            for p in device.get("ports", [])}
    services = {p["service"].lower() for p in device.get("ports", [])}
    vendor   = (device.get("vendor") or "").lower()
    os_str   = (device.get("os")     or "").lower()

    
    # RTSP port or service is the strongest camera signal
    if 554 in ports or "rtsp" in services:
        return "camera"
    # Known camera vendors
    if any(v in vendor for v in [
        "hikvision", "dahua", "axis", "reolink",
        "amcrest", "hanwha", "uniview"
    ]):
        return "camera"

    # Port 9100 (RAW print) and 515 (LPD) are printer-only
    if 9100 in ports or 515 in ports:
        return "printer"
    # Port 631 (IPP) — only if RTSP is not also open
    if 631 in ports and 554 not in ports:
        return "printer"
    # Known printer vendors
    if any(v in vendor for v in [
        "hp", "canon", "epson", "brother",
        "xerox", "ricoh", "lexmark"
    ]):
        return "printer"


    # RDP (3389) or both SMB (445) + NetBIOS (139) = Windows computer
    if 3389 in ports or (445 in ports and 139 in ports):
        return "computer"
    if "windows" in os_str:
        return "computer"

    # UPnP/SSDP discovery port is a strong WAP/router signal
    if 1900 in ports or "upnp" in services or "ssdp" in services:
        return "wap"
    # Known WAP/router vendors
    if any(v in vendor for v in [
        "tp-link", "cisco", "netgear", "ubiquiti",
        "d-link", "asus", "mikrotik", "linksys"
    ]):
        return "wap"

    return "unknown"



#  BUILD DATASET FROM REAL SCANS


def build_dataset(devices: list) -> tuple:
    X       = []
    y       = []
    skipped = 0

    for device in devices:
        label = label_device(device)

        if label == "unknown":
            skipped += 1
            continue

        vector = features_to_vector(extract_features(device))
        X.append(vector)
        y.append(label)

    print(f"[+] Dataset built: {len(X)} labelled samples, {skipped} skipped (unknown)")
    return X, y



def save_dataset_csv(devices: list, filepath: str = "dataset.csv"):
    from database.scanner.feature_extraction import get_feature_names

    feature_names = get_feature_names()
    rows          = []

    for device in devices:
        label    = label_device(device)
        features = extract_features(device)
        row      = {"ip": device.get("ip"), "label": label}
        for name in feature_names:
            row[name] = features.get(name, 0)
        rows.append(row)

    fieldnames = ["ip", "label"] + feature_names

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Dataset saved → {filepath}  (open to verify labels)")


def _make_ports(port_list: list) -> list:
    """Helper — turns a list of port numbers into port dicts."""
    SERVICE_NAMES = {
        80:    "http",
        443:   "https",
        22:    "ssh",
        23:    "telnet",
        21:    "ftp",
        554:   "rtsp",
        8554:  "rtsp",
        37777: "unknown",
        9100:  "raw",
        631:   "ipp",
        515:   "printer",
        1900:  "upnp",
        3389:  "ms-wbt-server",
        445:   "microsoft-ds",
        139:   "netbios-ssn",
        135:   "msrpc",
        8000:  "http",
        8080:  "http",
    }
    return [
        {"port": p, "service": SERVICE_NAMES.get(p, "unknown"),
         "product": "", "version": ""}
        for p in port_list
    ]


def generate_synthetic_data() -> tuple:
    """
    Returns (X, y) of hand-crafted training examples.
    Each entry simulates a realistic device profile.
    Runs through the same label_device() + extract_features()
    pipeline as real devices — so training is consistent.
    """

    synthetic_devices = [

        # ════════ CAMERAS ════════
        {
            "ip": "s1", "mac": None,
            "vendor": "Hikvision Digital Technology",
            "os": "Linux 3.x",
            "ports": _make_ports([80, 554, 8000])
        },
        {
            "ip": "s2", "mac": None,
            "vendor": "Dahua Technology",
            "os": "Linux",
            "ports": _make_ports([80, 554, 37777])
        },
        {
            "ip": "s3", "mac": None,
            "vendor": "Axis Communications",
            "os": "Linux",
            "ports": _make_ports([80, 443, 554])
        },
        {
            "ip": "s4", "mac": None,
            "vendor": "Amcrest Technologies",
            "os": "Linux",
            "ports": _make_ports([80, 554])
        },
        {
            "ip": "s5", "mac": None,
            "vendor": "Reolink Innovation",
            "os": "Linux",
            "ports": _make_ports([443, 554])
        },
        {
            "ip": "s6", "mac": None,
            "vendor": "Hanwha Vision",
            "os": "Linux",
            "ports": _make_ports([80, 443, 554, 8554])
        },
        {
            "ip": "s7", "mac": None,
            "vendor": "Uniview Technologies",
            "os": "Linux",
            "ports": _make_ports([80, 554])
        },
        # Camera with Telnet open (high risk scenario)
        {
            "ip": "s8", "mac": None,
            "vendor": "Hikvision Digital Technology",
            "os": "Linux",
            "ports": _make_ports([80, 554, 23])
        },
        # Camera with only RTSP (minimal exposure)
        {
            "ip": "s9", "mac": None,
            "vendor": "Dahua Technology",
            "os": "Linux",
            "ports": _make_ports([554])
        },
        # Camera identified by vendor only (port 80 shared)
        {
            "ip": "s10", "mac": None,
            "vendor": "Axis Communications",
            "os": "Linux",
            "ports": _make_ports([80, 443])
        },

        # ════════ PRINTERS ════════
        {
            "ip": "s11", "mac": None,
            "vendor": "HP Inc",
            "os": "embedded",
            "ports": _make_ports([80, 443, 9100, 631])
        },
        {
            "ip": "s12", "mac": None,
            "vendor": "Canon Inc",
            "os": "embedded",
            "ports": _make_ports([80, 631, 9100])
        },
        {
            "ip": "s13", "mac": None,
            "vendor": "Epson Corporation",
            "os": "embedded",
            "ports": _make_ports([80, 9100])
        },
        {
            "ip": "s14", "mac": None,
            "vendor": "Brother Industries",
            "os": "embedded",
            "ports": _make_ports([515, 9100, 631])
        },
        {
            "ip": "s15", "mac": None,
            "vendor": "Xerox Corporation",
            "os": "embedded",
            "ports": _make_ports([80, 443, 9100])
        },
        {
            "ip": "s16", "mac": None,
            "vendor": "Ricoh Company",
            "os": "embedded",
            "ports": _make_ports([80, 9100, 631])
        },
        {
            "ip": "s17", "mac": None,
            "vendor": "Lexmark International",
            "os": "embedded",
            "ports": _make_ports([80, 443, 515, 9100])
        },
        # Printer with only IPP
        {
            "ip": "s18", "mac": None,
            "vendor": "HP Inc",
            "os": "embedded",
            "ports": _make_ports([631])
        },
        # Printer with RAW print only
        {
            "ip": "s19", "mac": None,
            "vendor": "Canon Inc",
            "os": "embedded",
            "ports": _make_ports([9100])
        },
        # Printer with FTP open (misconfigured)
        {
            "ip": "s20", "mac": None,
            "vendor": "Epson Corporation",
            "os": "embedded",
            "ports": _make_ports([80, 9100, 21])
        },

        # ════════ WAPs ════════
        {
            "ip": "s21", "mac": None,
            "vendor": "TP-Link Technologies",
            "os": "Linux",
            "ports": _make_ports([80, 443, 1900])
        },
        {
            "ip": "s22", "mac": None,
            "vendor": "Cisco Systems",
            "os": "IOS",
            "ports": _make_ports([22, 443, 1900])
        },
        {
            "ip": "s23", "mac": None,
            "vendor": "Netgear Inc",
            "os": "Linux",
            "ports": _make_ports([80, 443, 1900])
        },
        {
            "ip": "s24", "mac": None,
            "vendor": "Ubiquiti Networks",
            "os": "Linux",
            "ports": _make_ports([22, 80, 443])
        },
        {
            "ip": "s25", "mac": None,
            "vendor": "D-Link Corporation",
            "os": "Linux",
            "ports": _make_ports([80, 1900])
        },
        {
            "ip": "s26", "mac": None,
            "vendor": "ASUSTeK Computer",
            "os": "Linux",
            "ports": _make_ports([80, 443, 1900])
        },
        {
            "ip": "s27", "mac": None,
            "vendor": "MikroTik",
            "os": "RouterOS",
            "ports": _make_ports([22, 80, 443, 1900])
        },
        # WAP with Telnet still open (old firmware)
        {
            "ip": "s28", "mac": None,
            "vendor": "TP-Link Technologies",
            "os": "Linux",
            "ports": _make_ports([80, 23, 1900])
        },
        # WAP identified by UPnP only
        {
            "ip": "s29", "mac": None,
            "vendor": "Unknown",
            "os": "Linux",
            "ports": _make_ports([80, 1900])
        },
        # WAP — Linksys
        {
            "ip": "s30", "mac": None,
            "vendor": "Linksys",
            "os": "Linux",
            "ports": _make_ports([80, 443, 22, 1900])
        },

        # ════════ COMPUTERS ════════
        {
            "ip": "s31", "mac": None,
            "vendor": "Dell Inc",
            "os": "Windows 10",
            "ports": _make_ports([135, 445, 3389])
        },
        {
            "ip": "s32", "mac": None,
            "vendor": "Lenovo",
            "os": "Windows 11",
            "ports": _make_ports([445, 139])
        },
        {
            "ip": "s33", "mac": None,
            "vendor": "Apple Inc",
            "os": "macOS Ventura",
            "ports": _make_ports([22, 443])
        },
        {
            "ip": "s34", "mac": None,
            "vendor": "ASUSTeK Computer",
            "os": "Windows 10",
            "ports": _make_ports([3389, 445])
        },
        {
            "ip": "s35", "mac": None,
            "vendor": "Microsoft",
            "os": "Windows Server 2019",
            "ports": _make_ports([80, 135, 445, 3389])
        },
        {
            "ip": "s36", "mac": None,
            "vendor": "HP Inc",
            "os": "Windows 10",
            "ports": _make_ports([135, 139, 445])
        },
        {
            "ip": "s37", "mac": None,
            "vendor": "Acer",
            "os": "Windows 11",
            "ports": _make_ports([445, 3389])
        },
        # Linux workstation
        {
            "ip": "s38", "mac": None,
            "vendor": "Dell Inc",
            "os": "Ubuntu Linux",
            "ports": _make_ports([22, 445])
        },
        # Computer with RDP only
        {
            "ip": "s39", "mac": None,
            "vendor": "Lenovo",
            "os": "Windows 10",
            "ports": _make_ports([3389])
        },
        # Server
        {
            "ip": "s40", "mac": None,
            "vendor": "HPE",
            "os": "Windows Server 2022",
            "ports": _make_ports([80, 443, 135, 445, 3389])
        },
    ]

    X, y = build_dataset(synthetic_devices)
    print(f"[+] Synthetic data: {len(X)} samples across classes {set(y)}")
    return X, y