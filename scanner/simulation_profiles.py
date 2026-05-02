SIMULATION_PROFILES = {
    "172.20.0.101": {
        "hostname": "hikvision-cam-01",
        "vendor": "Hikvision",
        "model": "Hikvision DS-2CD2143",
        "firmware": "V5.4.0 build 160401",
        "device_type": "camera",
        "default_credentials": ("admin", "admin"),
    },
    "172.20.0.102": {
        "hostname": "dahua-cam-01",
        "vendor": "Dahua",
        "model": "Dahua IPC-HDW2831T",
        "firmware": "V2.800.0000000.34",
        "device_type": "camera",
        "default_credentials": ("admin", "admin"),
    },
    "172.20.0.103": {
        "hostname": "axis-cam-01",
        "vendor": "Axis",
        "model": "Axis M3106-L Mk II",
        "firmware": "9.80.1",
        "device_type": "camera",
        "default_credentials": ("root", "pass"),
    },
    "172.20.0.104": {
        "hostname": "reolink-cam-01",
        "vendor": "Reolink",
        "model": "Reolink RLC-810A",
        "firmware": "v3.0.0.136_20121103",
        "device_type": "camera",
        "default_credentials": ("admin", "admin"),
    },
    "172.20.0.111": {
        "hostname": "hp-printer-01",
        "vendor": "HP",
        "model": "HP LaserJet Pro M404",
        "firmware": "002.1931B",
        "device_type": "printer",
        "default_credentials": ("admin", "admin"),
    },
    "172.20.0.112": {
        "hostname": "canon-printer-01",
        "vendor": "Canon",
        "model": "Canon imageRUNNER 2630",
        "firmware": "03.07",
        "device_type": "printer",
        "default_credentials": ("admin", "admin"),
    },
    "172.20.0.113": {
        "hostname": "epson-printer-01",
        "vendor": "Epson",
        "model": "Epson WorkForce Pro WF-4830",
        "firmware": "FL21I4",
        "device_type": "printer",
        "default_credentials": ("admin", "admin"),
    },
    "172.20.0.121": {
        "hostname": "tplink-wap-01",
        "vendor": "TP-Link",
        "model": "TP-Link EAP245",
        "firmware": "2.0.0 build 20190118",
        "device_type": "wap",
        "default_credentials": ("admin", "admin"),
    },
    "172.20.0.122": {
        "hostname": "cisco-wap-01",
        "vendor": "Cisco",
        "model": "Cisco WAP371",
        "firmware": "1.3.0.6",
        "device_type": "wap",
        "default_credentials": ("cisco", "cisco"),
    },
    "172.20.0.131": {
        "hostname": "dell-laptop-01",
        "vendor": "Dell",
        "model": "Dell Latitude 5540",
        "firmware": "Windows 11",
        "device_type": "computer",
        "default_credentials": None,
    },
    "172.20.0.132": {
        "hostname": "lenovo-laptop-01",
        "vendor": "Lenovo",
        "model": "Lenovo ThinkPad E15",
        "firmware": "Windows 10",
        "device_type": "computer",
        "default_credentials": None,
    },
}


def enrich_simulated_device(device):
    profile = SIMULATION_PROFILES.get(device.get("ip"))
    if not profile:
        return device

    enriched = {**device}
    enriched["simulation_profile"] = True
    enriched["hostname"] = enriched.get("hostname") or profile["hostname"]
    enriched["vendor"] = enriched.get("vendor") or profile["vendor"]
    enriched["model"] = profile["model"]
    enriched["firmware"] = profile["firmware"]
    enriched["expected_device_type"] = profile["device_type"]
    enriched["default_credentials"] = profile["default_credentials"]
    return enriched


def get_simulation_profile(ip):
    return SIMULATION_PROFILES.get(ip)
