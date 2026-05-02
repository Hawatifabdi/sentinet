from scanner.simulation_profiles import get_simulation_profile


def check_default_credentials(device):
    profile = get_simulation_profile(device.get("ip"))
    if profile and profile.get("default_credentials"):
        username, password = profile["default_credentials"]
        return {
            "status": "default",
            "detail": f"Simulation default credentials active: {username}/{password}",
            "username": username,
            "password": password,
        }

    if profile:
        return {
            "status": "strong",
            "detail": "Simulation computer has no default device credential",
            "username": None,
            "password": None,
        }

    ports = {p.get("port") for p in device.get("ports", [])}
    device_type = device.get("device_type", "unknown")

    if device_type in ("camera", "wap") and 80 in ports:
        return {
            "status": "default",
            "detail": "Default credentials likely because web admin is exposed",
            "username": "admin",
            "password": "admin",
        }
    if device_type == "printer" and 80 in ports:
        return {
            "status": "weak",
            "detail": "Printer web interface is exposed; manual credential check recommended",
            "username": None,
            "password": None,
        }

    return {
        "status": "unknown",
        "detail": "Manual credential check required",
        "username": None,
        "password": None,
    }
