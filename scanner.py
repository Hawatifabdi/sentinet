import nmap

def scan_network(network_range):
    nm = nmap.PortScanner()
    print(f"[+] Scanning network: {network_range}")

    try:
        nm.scan(hosts=network_range, arguments="-sT -sV --open -T4")
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

        devices.append(device)

    print(f"[+] Found {len(devices)} devices")
    return devices
results = scan_network("192.168.1.0/24")

for d in results:
    print(d)