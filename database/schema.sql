
--  SentiNet — MySQL Database
USE sentinet;

-- ── 1. Scan History ──
-- Stores every time you run a scan
CREATE TABLE scan_history (
    scan_id       INT AUTO_INCREMENT PRIMARY KEY,
    network_range VARCHAR(50)  NOT NULL,
    scanned_at    DATETIME     DEFAULT NOW(),
    total_devices INT          DEFAULT 0,
    iot_devices   INT          DEFAULT 0,
    high_risk     INT          DEFAULT 0
);

-- ── 2. Devices ──
-- One row per device found in a scan
CREATE TABLE devices (
    device_id     INT AUTO_INCREMENT PRIMARY KEY,
    scan_id       INT          NOT NULL,
    ip_address    VARCHAR(45)  NOT NULL,
    mac_address   VARCHAR(17),
    vendor        VARCHAR(150),
    hostname      VARCHAR(255),
    is_iot        TINYINT(1)   DEFAULT 0,
    device_type   VARCHAR(50)  DEFAULT 'unknown',
    ml_confidence DECIMAL(5,2) DEFAULT 0.00,
    risk_level    VARCHAR(20)  DEFAULT 'low',
    first_seen    DATETIME     DEFAULT NOW(),
    FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id) ON DELETE CASCADE
);

-- ── 3. Open Ports ──
-- Ports found open on each device
CREATE TABLE ports (
    port_id      INT AUTO_INCREMENT PRIMARY KEY,
    device_id    INT          NOT NULL,
    port_number  INT          NOT NULL,
    protocol     VARCHAR(10)  DEFAULT 'tcp',
    service_name VARCHAR(100),
    is_risky     TINYINT(1)   DEFAULT 0,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- ── 4. Credentials ──
-- Was the default password found on the device?
CREATE TABLE credentials (
    cred_id   INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT         NOT NULL,
    status    VARCHAR(20) DEFAULT 'unknown',
    detail    TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- ── 5. Firmware ──
-- Firmware version info per device
CREATE TABLE firmware (
    firmware_id    INT AUTO_INCREMENT PRIMARY KEY,
    device_id      INT          NOT NULL,
    version_string VARCHAR(200),
    is_outdated    TINYINT(1)   DEFAULT 0,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- ── 6. Vulnerabilities ──
-- CVEs from NVD linked to each device
CREATE TABLE vulnerabilities (
    vuln_id      INT AUTO_INCREMENT PRIMARY KEY,
    device_id    INT          NOT NULL,
    cve_id       VARCHAR(25)  NOT NULL,
    cvss_score   DECIMAL(4,1) DEFAULT 0.0,
    severity     VARCHAR(20)  DEFAULT 'low',
    description  TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- ── 7. Alerts ──
-- Security alerts shown on the dashboard
CREATE TABLE alerts (
    alert_id   INT AUTO_INCREMENT PRIMARY KEY,
    device_id  INT          NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    severity   VARCHAR(20)  DEFAULT 'medium',
    message    TEXT         NOT NULL,
    is_read    TINYINT(1)   DEFAULT 0,
    created_at DATETIME     DEFAULT NOW(),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- ── 8. Users ──
-- Dashboard login accounts
CREATE TABLE admin_users (
    admin_id      INT AUTO_INCREMENT PRIMARY KEY,
    full_name     VARCHAR(150) NOT NULL,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    organization  VARCHAR(200),
    role          VARCHAR(50)  DEFAULT 'operator',
    created_at    DATETIME     DEFAULT NOW()
);