from scanner.classifier import classify_all, load_model, train_model
from scanner.credential_checker import check_default_credentials
from scanner.firmware_checker import check_firmware
from scanner.nvd_client import find_device_vulnerabilities
from scanner.risk_scorer import score_device_risk
from scanner.scanner import scan_network
from database.db import (
    create_scan,
    finish_scan,
    save_alert,
    save_credential,
    save_device,
    save_firmware,
    save_ports,
    save_vulnerabilities,
)


def run_scan_pipeline(
    network_range,
    organization="Default Organization",
    use_nvd=True,
    user_email=None,
    firebase_uid=None,
):
    model, label_encoder = load_model()
    if model is None or label_encoder is None:
        model, label_encoder = train_model()
    raw_devices = scan_network(network_range)
    classified = classify_all(raw_devices, model, label_encoder)

    for device in classified:
        credential = check_default_credentials(device)
        firmware = check_firmware(device)
        vulnerabilities = find_device_vulnerabilities(device) if use_nvd else []

        device["credential_status"] = credential["status"]
        device["credential_detail"] = credential["detail"]
        device["firmware_status"] = firmware
        device["firmware"] = firmware["version"]
        device["vulnerabilities"] = vulnerabilities

        risk = score_device_risk(device, vulnerabilities, credential["status"])
        device["risk_level"] = risk["level"]
        device["risk_score"] = risk["score"]
        device["risk_reasons"] = risk["reasons"]

    scan_id = create_scan(network_range, organization, user_email, firebase_uid)
    iot_count = sum(1 for d in classified if d.get("is_iot"))
    high_count = sum(1 for d in classified if d.get("risk_level") == "high")

    for device in classified:
        device_id = save_device(
            scan_id,
            device.get("ip"),
            device.get("mac"),
            device.get("vendor"),
            device.get("hostname") or device.get("model") or device.get("ip"),
            device.get("is_iot", False),
            device.get("device_type", "unknown"),
            device.get("ml_confidence", 0.0),
            device.get("risk_level", "low"),
        )
        device["device_id"] = device_id

        if device.get("ports"):
            save_ports(device_id, device["ports"])

        save_credential(
            device_id,
            device.get("credential_status", "unknown"),
            device.get("credential_detail", "Manual check required"),
        )

        firmware = device.get("firmware_status", {})
        save_firmware(
            device_id,
            firmware.get("version") or "Unknown",
            is_outdated=firmware.get("is_outdated", False),
        )

        if device.get("vulnerabilities"):
            save_vulnerabilities(device_id, device["vulnerabilities"])

        if device.get("risk_level") in {"high", "medium"}:
            save_alert(
                device_id,
                alert_type=f"{device['risk_level']}_risk_device",
                message=f"{device.get('device_type', 'UNKNOWN').upper()} at {device.get('ip')}: "
                        f"{'; '.join(device.get('risk_reasons', []))}",
                severity=device["risk_level"],
            )

    finish_scan(scan_id, len(classified), iot_count, high_count)
    return scan_id, classified
