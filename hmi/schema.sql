CREATE TABLE IF NOT EXISTS telemetry (
    id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    node           VARCHAR(255) NOT NULL,
    seq            INT UNSIGNED NOT NULL, 
    edge_ts        DATETIME(3)  NOT NULL,
    hmi_rx_ts      DATETIME(3)  NOT NULL,
    temp_c         DECIMAL(5, 2) NOT NULL,
    humidity       DECIMAL(5, 2) NOT NULL,
    pressure_hpa   DECIMAL(5, 2) NOT NULL, 
    INDEX idx_telemetry_rx (hmi_rx_ts)
);

CREATE TABLE IF NOT EXISTS security_events (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_uid     CHAR(36)      NOT NULL,
    event_type    VARCHAR(32)   NOT NULL,
    node          VARCHAR(32)   NOT NULL,
    src_ip        VARCHAR(45)   NULL,
    src_port      INT UNSIGNED  NULL,
    edge_ts       DATETIME(3)   NULL,
    hmi_rx_ts     DATETIME(3)   NOT NULL,
    details       JSON          NULL,
    INDEX idx_events_src (src_ip),
    INDEX idx_events_rx (hmi_rx_ts)
);

CREATE TABLE IF NOT EXISTS quarantine_actions (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    order_id      VARCHAR(32)   NOT NULL UNIQUE,
    action        ENUM('quarantine', 'release') NOT NULL,
    target_ip     VARCHAR(45)   NOT NULL,
    reason        VARCHAR(64)   NOT NULL,
    trigger_event_uid CHAR(36)  NULL,
    status        ENUM('applied', 'refused', 'error') NOT NULL,
    detail        VARCHAR(255)  NULL,
    ordered_at    DATETIME(3)   NOT NULL,
    confirmed_at  DATETIME(3)   NOT NULL,
    INDEX idx_actions_target (target_ip)
);