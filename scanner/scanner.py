import nmap
from scanner.simulation_profiles import SIMULATION_PROFILES, enrich_simulated_device


SIMULATION_PORTS = sorted({
    21, 22, 23, 80, 443, 554, 631, 1900, 3389, 37777, 445, 9100
})


def _scan_targets(network_range):
    if network_range.strip() == "172.20.0.0/24":
        return " ".join(SIMULATION_PROFILES.keys())
    return network_range


def _scan_arguments(network_range):
    common = "-Pn -sT -sV --open -T4 --max-retries 1 --host-timeout 20s"
    if network_range.strip() == "172.20.0.0/24":
        return f"{common} -p {','.join(str(p) for p in SIMULATION_PORTS)}"
    return common

def scan_network(network_range):
    nm = nmap.PortScanner()
    print(f"[+] Scanning network: {network_range}")

    try:
        nm.scan(hosts=_scan_targets(network_range), arguments=_scan_arguments(network_range))
    except Exception as e:
        print(f"[!] Scan Failed: {e}")
        return []

    devices = []

    for host in nm.all_hosts():

        device = {
            "ip": host,
            "mac": None,
            "vendor": None,
            "os": None,
            "ports": []
        }

        # MAC address
        if "addresses" in nm[host]:
            device["mac"] = nm[host]["addresses"].get("mac", None)

        # Vendor
        if "vendor" in nm[host]:
            for mac, vendor in nm[host]["vendor"].items():
                device["vendor"] = vendor

        # OS detection
        if "osmatch" in nm[host] and nm[host]["osmatch"]:
            device["os"] = nm[host]["osmatch"][0]["name"]

        # Ports
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                service = nm[host][proto][port]

                device["ports"].append({
                    "port": port,
                    "protocol": proto,
                    "state": service["state"],
                    "service": service["name"],
                    "product": service.get("product", ""),
                    "version": service.get("version", "")
                })

        devices.append(enrich_simulated_device(device))

    print(f"[+] Found {len(devices)} devices")
    return devices
if __name__ == "__main__":
    results = scan_network("172.20.0.0/24")
    for d in results:
        print(d)
