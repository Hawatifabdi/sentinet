from scanner.simulation_profiles import get_simulation_profile


OUTDATED_SIMULATION_FIRMWARE = {
    "172.20.0.101": "Old Hikvision firmware used in the lab image",
    "172.20.0.104": "Old Reolink firmware used in the lab image",
    "172.20.0.121": "Old TP-Link firmware build from 2019",
    "172.20.0.122": "Old Cisco WAP371 firmware branch",
}


def check_firmware(device):
    version = device.get("firmware") or device.get("version") or "Unknown"
    reason = "No firmware age signal found"
    is_outdated = False

    profile = get_simulation_profile(device.get("ip"))
    if profile:
        version = profile["firmware"]
        reason = OUTDATED_SIMULATION_FIRMWARE.get(device["ip"], "Simulation firmware is treated as current")
        is_outdated = device["ip"] in OUTDATED_SIMULATION_FIRMWARE

    return {
        "version": version,
        "is_outdated": is_outdated,
        "reason": reason,
    }
