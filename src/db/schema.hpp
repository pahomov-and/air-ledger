#pragma once

// SQL schema for the air-ledger database.
// Apply with sqlite3_exec(db, SCHEMA_SQL, nullptr, nullptr, nullptr).

inline constexpr const char* SCHEMA_SQL = R"SQL(
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS clients (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    mac               TEXT    NOT NULL UNIQUE,
    is_random         INTEGER NOT NULL DEFAULT 0,
    vendor            TEXT    NOT NULL DEFAULT '',
    alias             TEXT    NOT NULL DEFAULT '',
    first_seen        INTEGER NOT NULL,
    last_seen         INTEGER NOT NULL,
    last_rssi         INTEGER NOT NULL DEFAULT -100,
    seen_count        INTEGER NOT NULL DEFAULT 1,
    radio_fingerprint TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ssids (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS aps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid       TEXT    NOT NULL UNIQUE,
    ssid_id     INTEGER REFERENCES ssids(id),
    channel     INTEGER NOT NULL DEFAULT 0,
    security    TEXT    NOT NULL DEFAULT 'Open',
    vendor      TEXT    NOT NULL DEFAULT '',
    alias       TEXT    NOT NULL DEFAULT '',
    password    TEXT    NOT NULL DEFAULT '',
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    last_rssi   INTEGER NOT NULL DEFAULT -100,
    seen_count  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS client_ssid (
    client_id   INTEGER NOT NULL REFERENCES clients(id),
    ssid_id     INTEGER NOT NULL REFERENCES ssids(id),
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    last_rssi   INTEGER NOT NULL DEFAULT -100,
    probe_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (client_id, ssid_id)
);

CREATE TABLE IF NOT EXISTS client_ap (
    client_id   INTEGER NOT NULL REFERENCES clients(id),
    ap_id       INTEGER NOT NULL REFERENCES aps(id),
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    PRIMARY KEY (client_id, ap_id)
);

CREATE TABLE IF NOT EXISTS client_similarity (
    client_a    INTEGER NOT NULL REFERENCES clients(id),
    client_b    INTEGER NOT NULL REFERENCES clients(id),
    score       REAL    NOT NULL DEFAULT 0.0,
    common_ssids INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (client_a, client_b),
    CHECK (client_a < client_b)
);

CREATE TABLE IF NOT EXISTS observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_us       INTEGER NOT NULL,
    kind        TEXT    NOT NULL,
    src_mac     TEXT    NOT NULL DEFAULT '',
    dst_mac     TEXT    NOT NULL DEFAULT '',
    bssid_mac   TEXT    NOT NULL DEFAULT '',
    ssid        TEXT    NOT NULL DEFAULT '',
    rssi        INTEGER NOT NULL DEFAULT -100,
    channel     INTEGER NOT NULL DEFAULT 0,
    security    TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ap_passwords (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid     TEXT    NOT NULL,
    password  TEXT    NOT NULL,
    found_at  INTEGER NOT NULL,
    UNIQUE(bssid, password)
);

CREATE INDEX IF NOT EXISTS idx_observations_ts  ON observations(ts_us);
CREATE INDEX IF NOT EXISTS idx_clients_mac       ON clients(mac);
CREATE INDEX IF NOT EXISTS idx_ssids_name        ON ssids(name);
CREATE INDEX IF NOT EXISTS idx_aps_bssid         ON aps(bssid);
CREATE INDEX IF NOT EXISTS idx_client_ssid_cli   ON client_ssid(client_id);
CREATE INDEX IF NOT EXISTS idx_client_ssid_ssid  ON client_ssid(ssid_id);
CREATE INDEX IF NOT EXISTS idx_ap_passwords_bssid ON ap_passwords(bssid);

CREATE TABLE IF NOT EXISTS handshakes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid       TEXT    NOT NULL,
    ssid        TEXT    NOT NULL DEFAULT '',
    captured_at INTEGER NOT NULL,
    ap_mac      BLOB    NOT NULL,   -- 6 bytes
    client_mac  BLOB    NOT NULL,   -- 6 bytes
    anonce      BLOB    NOT NULL,   -- 32 bytes
    snonce      BLOB    NOT NULL,   -- 32 bytes
    mic         BLOB    NOT NULL,   -- 16 bytes
    eapol_frame BLOB    NOT NULL,   -- variable length EAPOL frame body
    pcap_path    TEXT    NOT NULL DEFAULT '',
    crack_status TEXT    NOT NULL DEFAULT '',   -- ''/queued/running/found/not_found
    password     TEXT    NOT NULL DEFAULT '',   -- filled when crack_status='found'
    UNIQUE(bssid, snonce)           -- unique per 4-way exchange (client nonce is random)
);

CREATE INDEX IF NOT EXISTS idx_handshakes_bssid ON handshakes(bssid);

CREATE TABLE IF NOT EXISTS anomalies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_us       INTEGER NOT NULL,
    type        TEXT    NOT NULL,
    severity    INTEGER NOT NULL DEFAULT 2,
    src_mac     TEXT    NOT NULL DEFAULT '',
    target_mac  TEXT    NOT NULL DEFAULT '',
    ssid        TEXT    NOT NULL DEFAULT '',
    description TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_anomalies_ts     ON anomalies(ts_us);
CREATE INDEX IF NOT EXISTS idx_anomalies_srcmac ON anomalies(src_mac);
)SQL";
