#include "db.hpp"
#include "schema.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>

// Parse "AA:BB:CC:DD:EE:FF" into MacAddr
static MacAddr mac_from_str(const char* s) {
    MacAddr m;
    if (!s) return m;
    unsigned v[6] = {};
    if (std::sscanf(s, "%02X:%02X:%02X:%02X:%02X:%02X",
                    &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) == 6) {
        for (int i = 0; i < 6; ++i) m.bytes[i] = static_cast<uint8_t>(v[i]);
    }
    return m;
}

// Helper: log sqlite errors
static void sql_err(const char* ctx, sqlite3* db) {
    std::fprintf(stderr, "[db] %s: %s\n", ctx, sqlite3_errmsg(db));
}

static int exec_sql(sqlite3* db, const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::fprintf(stderr, "[db] exec error: %s\n", err ? err : "?");
        sqlite3_free(err);
    }
    return rc;
}

Db::~Db() {
    flush_batch();
    finalize_statements();
    close();
}

bool Db::open(const std::string& path) {
    // Create parent directories (mkdir -p) if they don't exist
    auto slash = path.rfind('/');
    if (slash != std::string::npos && slash > 0) {
        std::string dir = path.substr(0, slash);
        // Walk the path component by component and create each level
        for (size_t i = 1; i <= dir.size(); ++i) {
            if (i == dir.size() || dir[i] == '/') {
                std::string part = dir.substr(0, i);
                ::mkdir(part.c_str(), 0755); // EEXIST is fine
            }
        }
    }

    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::fprintf(stderr, "[db] Cannot open %s: %s\n", path.c_str(), sqlite3_errmsg(db_));
        return false;
    }
    // Performance pragmas
    exec_sql(db_, "PRAGMA journal_mode=WAL;");
    exec_sql(db_, "PRAGMA synchronous=NORMAL;");
    exec_sql(db_, "PRAGMA cache_size=4096;");
    exec_sql(db_, "PRAGMA temp_store=MEMORY;");
    return true;
}

void Db::create_schema() {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, SCHEMA_SQL, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::fprintf(stderr, "[db] Schema error: %s\n", err ? err : "?");
        sqlite3_free(err);
        return;
    }
    // Migrations for existing DBs (ALTER TABLE ignores error if column already exists)
    exec_sql(db_, "ALTER TABLE clients    ADD COLUMN radio_fingerprint TEXT NOT NULL DEFAULT '';");
    exec_sql(db_, "ALTER TABLE aps        ADD COLUMN password          TEXT NOT NULL DEFAULT '';");
    exec_sql(db_, "ALTER TABLE handshakes ADD COLUMN crack_status      TEXT NOT NULL DEFAULT '';");
    exec_sql(db_, "ALTER TABLE handshakes ADD COLUMN password          TEXT NOT NULL DEFAULT '';");
    // Migrate existing single passwords into ap_passwords multi-table
    exec_sql(db_,
        "INSERT OR IGNORE INTO ap_passwords (bssid, password, found_at)"
        " SELECT bssid, password, strftime('%s','now') FROM aps WHERE password != '';");
    prepare_statements();
}

void Db::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool Db::prepare_statements() {
    auto prep = [&](sqlite3_stmt*& stmt, const char* sql) -> bool {
        int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            sql_err(sql, db_);
            return false;
        }
        return true;
    };

    bool ok = true;
    ok &= prep(stmt_upsert_client_,
        "INSERT INTO clients (mac, is_random, vendor, first_seen, last_seen, last_rssi, seen_count)"
        " VALUES (?,?,?,?,?,?,1)"
        " ON CONFLICT(mac) DO UPDATE SET"
        "  last_seen=MAX(last_seen,excluded.last_seen),"
        "  last_rssi=excluded.last_rssi,"
        "  seen_count=seen_count+1;");

    ok &= prep(stmt_upsert_ssid_,
        "INSERT INTO ssids (name, first_seen, last_seen)"
        " VALUES (?,?,?)"
        " ON CONFLICT(name) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen);");

    ok &= prep(stmt_upsert_ap_,
        "INSERT INTO aps (bssid, ssid_id, channel, security, vendor, first_seen, last_seen, last_rssi, seen_count)"
        " VALUES (?,?,?,?,?,?,?,?,1)"
        " ON CONFLICT(bssid) DO UPDATE SET"
        "  ssid_id=excluded.ssid_id,"
        "  channel=excluded.channel,"
        "  security=excluded.security,"
        "  last_seen=MAX(last_seen,excluded.last_seen),"
        "  last_rssi=excluded.last_rssi,"
        "  seen_count=seen_count+1;");

    ok &= prep(stmt_upsert_probe_,
        "INSERT INTO client_ssid (client_id, ssid_id, first_seen, last_seen, last_rssi, probe_count)"
        " VALUES (?,?,?,?,?,1)"
        " ON CONFLICT(client_id,ssid_id) DO UPDATE SET"
        "  last_seen=MAX(last_seen,excluded.last_seen),"
        "  last_rssi=excluded.last_rssi,"
        "  probe_count=probe_count+1;");

    ok &= prep(stmt_insert_obs_,
        "INSERT INTO observations (ts_us, kind, src_mac, dst_mac, bssid_mac, ssid, rssi, channel, security)"
        " VALUES (?,?,?,?,?,?,?,?,?);");

    ok &= prep(stmt_upsert_assoc_,
        "INSERT INTO client_ap (client_id, ap_id, first_seen, last_seen)"
        " VALUES (?,?,?,?)"
        " ON CONFLICT(client_id,ap_id) DO UPDATE SET"
        "  last_seen=MAX(last_seen,excluded.last_seen);");

    ok &= prep(stmt_upsert_sim_,
        "INSERT INTO client_similarity (client_a, client_b, score, common_ssids, updated_at)"
        " VALUES (?,?,?,?,?)"
        " ON CONFLICT(client_a,client_b) DO UPDATE SET"
        "  score=excluded.score,"
        "  common_ssids=excluded.common_ssids,"
        "  updated_at=excluded.updated_at;");

    ok &= prep(stmt_set_alias_,
        "UPDATE clients SET alias=? WHERE mac=?;");

    ok &= prep(stmt_get_alias_,
        "SELECT alias FROM clients WHERE mac=?;");

    return ok;
}

void Db::finalize_statements() {
    auto fin = [](sqlite3_stmt*& s) {
        if (s) { sqlite3_finalize(s); s = nullptr; }
    };
    fin(stmt_upsert_client_);
    fin(stmt_upsert_ssid_);
    fin(stmt_upsert_ap_);
    fin(stmt_upsert_probe_);
    fin(stmt_upsert_assoc_);
    fin(stmt_insert_obs_);
    fin(stmt_upsert_sim_);
    fin(stmt_set_alias_);
    fin(stmt_get_alias_);
}

// Helper: bind and step a statement, then reset it
static bool exec_stmt(sqlite3_stmt* stmt, sqlite3* db) {
    int rc = sqlite3_step(stmt);
    sqlite3_reset(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        sql_err("step", db);
        return false;
    }
    return true;
}

int64_t Db::upsert_client(const MacAddr& mac, bool is_randomized,
                           uint64_t ts, int8_t rssi, const std::string& vendor) {
    if (!stmt_upsert_client_) return -1;
    std::string mac_str = mac.to_string();
    sqlite3_bind_text(stmt_upsert_client_, 1, mac_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt_upsert_client_, 2, is_randomized ? 1 : 0);
    sqlite3_bind_text(stmt_upsert_client_, 3, vendor.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt_upsert_client_, 4, static_cast<int64_t>(ts));
    sqlite3_bind_int64(stmt_upsert_client_, 5, static_cast<int64_t>(ts));
    sqlite3_bind_int (stmt_upsert_client_, 6, rssi);
    exec_stmt(stmt_upsert_client_, db_);

    // Get row id
    sqlite3_stmt* sel{};
    sqlite3_prepare_v2(db_, "SELECT id FROM clients WHERE mac=?;", -1, &sel, nullptr);
    sqlite3_bind_text(sel, 1, mac_str.c_str(), -1, SQLITE_TRANSIENT);
    int64_t rid = -1;
    if (sqlite3_step(sel) == SQLITE_ROW)
        rid = sqlite3_column_int64(sel, 0);
    sqlite3_finalize(sel);
    return rid;
}

int64_t Db::upsert_ssid(const std::string& ssid, uint64_t ts) {
    if (!stmt_upsert_ssid_) return -1;
    sqlite3_bind_text (stmt_upsert_ssid_, 1, ssid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt_upsert_ssid_, 2, static_cast<int64_t>(ts));
    sqlite3_bind_int64(stmt_upsert_ssid_, 3, static_cast<int64_t>(ts));
    exec_stmt(stmt_upsert_ssid_, db_);

    sqlite3_stmt* sel{};
    sqlite3_prepare_v2(db_, "SELECT id FROM ssids WHERE name=?;", -1, &sel, nullptr);
    sqlite3_bind_text(sel, 1, ssid.c_str(), -1, SQLITE_TRANSIENT);
    int64_t rid = -1;
    if (sqlite3_step(sel) == SQLITE_ROW)
        rid = sqlite3_column_int64(sel, 0);
    sqlite3_finalize(sel);
    return rid;
}

int64_t Db::upsert_ap(const MacAddr& bssid, int64_t ssid_id, int channel,
                      const std::string& security, const std::string& vendor,
                      uint64_t ts, int8_t rssi) {
    if (!stmt_upsert_ap_) return -1;
    std::string bssid_str = bssid.to_string();
    sqlite3_bind_text (stmt_upsert_ap_, 1, bssid_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt_upsert_ap_, 2, ssid_id);
    sqlite3_bind_int  (stmt_upsert_ap_, 3, channel);
    sqlite3_bind_text (stmt_upsert_ap_, 4, security.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt_upsert_ap_, 5, vendor.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt_upsert_ap_, 6, static_cast<int64_t>(ts));
    sqlite3_bind_int64(stmt_upsert_ap_, 7, static_cast<int64_t>(ts));
    sqlite3_bind_int  (stmt_upsert_ap_, 8, rssi);
    exec_stmt(stmt_upsert_ap_, db_);

    sqlite3_stmt* sel{};
    sqlite3_prepare_v2(db_, "SELECT id FROM aps WHERE bssid=?;", -1, &sel, nullptr);
    sqlite3_bind_text(sel, 1, bssid_str.c_str(), -1, SQLITE_TRANSIENT);
    int64_t rid = -1;
    if (sqlite3_step(sel) == SQLITE_ROW)
        rid = sqlite3_column_int64(sel, 0);
    sqlite3_finalize(sel);
    return rid;
}

void Db::upsert_probe(int64_t client_id, int64_t ssid_id, uint64_t ts, int8_t rssi) {
    if (!stmt_upsert_probe_) return;
    sqlite3_bind_int64(stmt_upsert_probe_, 1, client_id);
    sqlite3_bind_int64(stmt_upsert_probe_, 2, ssid_id);
    sqlite3_bind_int64(stmt_upsert_probe_, 3, static_cast<int64_t>(ts));
    sqlite3_bind_int64(stmt_upsert_probe_, 4, static_cast<int64_t>(ts));
    sqlite3_bind_int  (stmt_upsert_probe_, 5, rssi);
    exec_stmt(stmt_upsert_probe_, db_);
}

void Db::upsert_association(int64_t client_id, int64_t ap_id, uint64_t ts) {
    if (!stmt_upsert_assoc_) return;
    sqlite3_bind_int64(stmt_upsert_assoc_, 1, client_id);
    sqlite3_bind_int64(stmt_upsert_assoc_, 2, ap_id);
    sqlite3_bind_int64(stmt_upsert_assoc_, 3, static_cast<int64_t>(ts));
    sqlite3_bind_int64(stmt_upsert_assoc_, 4, static_cast<int64_t>(ts));
    exec_stmt(stmt_upsert_assoc_, db_);
}

void Db::insert_observation(const ParsedFrame& frame) {
    obs_batch_.push_back(frame);
    if (static_cast<int>(obs_batch_.size()) >= BATCH_SIZE)
        flush_batch();
}

void Db::flush_batch() {
    if (obs_batch_.empty()) return;
    flush_observations(obs_batch_);
    obs_batch_.clear();
}

void Db::flush_observations(const std::vector<ParsedFrame>& frames) {
    if (!stmt_insert_obs_) return;
    exec_sql(db_, "BEGIN;");
    for (auto& f : frames) {
        sqlite3_bind_int64(stmt_insert_obs_, 1, static_cast<int64_t>(f.ts_us));
        sqlite3_bind_text (stmt_insert_obs_, 2, frame_kind_name(f.kind), -1, SQLITE_STATIC);
        std::string src  = f.src.to_string();
        std::string dst  = f.dst.to_string();
        std::string bss  = f.bssid.to_string();
        std::string ssid = f.ssid.value_or("");
        sqlite3_bind_text (stmt_insert_obs_, 3, src.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt_insert_obs_, 4, dst.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt_insert_obs_, 5, bss.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt_insert_obs_, 6, ssid.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int  (stmt_insert_obs_, 7, f.rssi);
        sqlite3_bind_int  (stmt_insert_obs_, 8, f.channel);
        sqlite3_bind_text (stmt_insert_obs_, 9, f.security.c_str(), -1, SQLITE_TRANSIENT);
        exec_stmt(stmt_insert_obs_, db_);
    }
    exec_sql(db_, "COMMIT;");
}

void Db::upsert_similarity(int64_t a, int64_t b, float score, int common) {
    if (!stmt_upsert_sim_) return;
    if (a > b) std::swap(a, b);
    sqlite3_bind_int64(stmt_upsert_sim_, 1, a);
    sqlite3_bind_int64(stmt_upsert_sim_, 2, b);
    sqlite3_bind_double(stmt_upsert_sim_, 3, score);
    sqlite3_bind_int   (stmt_upsert_sim_, 4, common);
    sqlite3_bind_int64 (stmt_upsert_sim_, 5, static_cast<int64_t>(0));
    exec_stmt(stmt_upsert_sim_, db_);
}

void Db::set_alias(const std::string& mac, const std::string& alias) {
    if (!stmt_set_alias_) return;
    sqlite3_bind_text(stmt_set_alias_, 1, alias.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_set_alias_, 2, mac.c_str(), -1, SQLITE_TRANSIENT);
    exec_stmt(stmt_set_alias_, db_);
}

std::string Db::get_alias(const std::string& mac) {
    if (!stmt_get_alias_) return "";
    sqlite3_bind_text(stmt_get_alias_, 1, mac.c_str(), -1, SQLITE_TRANSIENT);
    std::string result;
    if (sqlite3_step(stmt_get_alias_) == SQLITE_ROW) {
        const char* txt = reinterpret_cast<const char*>(sqlite3_column_text(stmt_get_alias_, 0));
        if (txt) result = txt;
    }
    sqlite3_reset(stmt_get_alias_);
    return result;
}

void Db::set_ap_password(const std::string& bssid, const std::string& password) {
    if (!db_) return;
    sqlite3_stmt* st{};
    sqlite3_prepare_v2(db_,
        "UPDATE aps SET password=? WHERE bssid=?;",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, password.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, bssid.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
    add_ap_password(bssid, password); // also insert into multi-password table
}

void Db::add_ap_password(const std::string& bssid, const std::string& password) {
    if (!db_) return;
    sqlite3_stmt* st{};
    sqlite3_prepare_v2(db_,
        "INSERT OR IGNORE INTO ap_passwords (bssid, password, found_at)"
        " VALUES (?, ?, strftime('%s','now'));",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, bssid.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, password.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

std::vector<std::string> Db::get_ap_passwords(const std::string& bssid) {
    std::vector<std::string> result;
    if (!db_) return result;
    sqlite3_stmt* st{};
    sqlite3_prepare_v2(db_,
        "SELECT password FROM ap_passwords WHERE bssid=? ORDER BY found_at;",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, bssid.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char* pw = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        if (pw) result.emplace_back(pw);
    }
    sqlite3_finalize(st);
    return result;
}

void Db::save_handshake(const std::string& bssid, const std::string& ssid,
                         const WpaHandshake& hs, const std::string& pcap_path) {
    if (!db_) return;
    if (!hs.valid()) return;

    sqlite3_stmt* st{};
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR IGNORE INTO handshakes"
        " (bssid, ssid, captured_at, ap_mac, client_mac, anonce, snonce, mic, eapol_frame, pcap_path)"
        " VALUES (?, ?, strftime('%s','now'), ?, ?, ?, ?, ?, ?, ?);",
        -1, &st, nullptr);
    if (rc != SQLITE_OK) { sql_err("save_handshake prepare", db_); return; }

    sqlite3_bind_text(st, 1, bssid.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ssid.c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, hs.ap_mac,     6,      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 4, hs.client_mac, 6,      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 5, hs.anonce,    32,      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 6, hs.snonce,    32,      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 7, hs.mic,       16,      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 8,
        hs.eapol_frame.data(),
        static_cast<int>(hs.eapol_frame.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, pcap_path.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE)
        std::fprintf(stderr, "[db] handshake saved: %s (%s)\n", bssid.c_str(), ssid.c_str());
    else if (rc != SQLITE_CONSTRAINT) // CONSTRAINT = duplicate snonce, that's fine
        sql_err("save_handshake step", db_);

    sqlite3_finalize(st);
}

int Db::handshake_count(const std::string& bssid) {
    if (!db_) return 0;
    sqlite3_stmt* st{};
    sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM handshakes WHERE bssid=?;",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, bssid.c_str(), -1, SQLITE_TRANSIENT);
    int count = 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return count;
}

void Db::update_handshake_crack(const std::string& bssid,
                                const std::string& status,
                                const std::string& password) {
    if (!db_) return;
    sqlite3_stmt* st{};
    sqlite3_prepare_v2(db_,
        "UPDATE handshakes SET crack_status=?, password=? WHERE bssid=?;",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, status.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, password.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, bssid.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

bool Db::get_handshake_crack(const std::string& bssid,
                              std::string& out_status, std::string& out_password) {
    if (!db_) return false;
    sqlite3_stmt* st{};
    // Pick the most informative result: prefer 'found', then 'not_found', then any
    sqlite3_prepare_v2(db_,
        "SELECT crack_status, password FROM handshakes"
        " WHERE bssid=? AND crack_status != ''"
        " ORDER BY CASE crack_status WHEN 'found' THEN 0 WHEN 'not_found' THEN 1 ELSE 2 END"
        " LIMIT 1;",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, bssid.c_str(), -1, SQLITE_TRANSIENT);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char* s = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        const char* p = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
        out_status   = s ? s : "";
        out_password = p ? p : "";
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

void Db::save_anomaly(const AnomalyEvent& ev) {
    if (!db_) return;
    sqlite3_stmt* st{};
    sqlite3_prepare_v2(db_,
        "INSERT INTO anomalies(ts_us,type,severity,src_mac,target_mac,ssid,description)"
        " VALUES(?,?,?,?,?,?,?);",
        -1, &st, nullptr);
    sqlite3_bind_int64(st, 1, static_cast<int64_t>(ev.ts_us));
    sqlite3_bind_text(st, 2, anomaly_type_name(ev.type), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st,  3, ev.severity);
    sqlite3_bind_text(st, 4, ev.src_mac.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, ev.target_mac.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, ev.ssid.c_str(),       -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, ev.description.c_str(),-1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

static AnomalyEvent row_to_anomaly(sqlite3_stmt* st) {
    AnomalyEvent ev;
    ev.ts_us      = static_cast<uint64_t>(sqlite3_column_int64(st, 0));
    const char* type_s = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
    // Map string back to enum
    std::string ts = type_s ? type_s : "";
    if      (ts == "DeauthFlood")      ev.type = AnomalyType::DeauthFlood;
    else if (ts == "ProbeFlood")       ev.type = AnomalyType::ProbeFlood;
    else if (ts == "AuthFlood")        ev.type = AnomalyType::AuthFlood;
    else if (ts == "EvilTwin")         ev.type = AnomalyType::EvilTwin;
    else if (ts == "UnexpectedDeauth") ev.type = AnomalyType::UnexpectedDeauth;
    ev.severity   = sqlite3_column_int(st, 2);
    const char* s;
    if ((s = reinterpret_cast<const char*>(sqlite3_column_text(st, 3)))) ev.src_mac    = s;
    if ((s = reinterpret_cast<const char*>(sqlite3_column_text(st, 4)))) ev.target_mac = s;
    if ((s = reinterpret_cast<const char*>(sqlite3_column_text(st, 5)))) ev.ssid       = s;
    if ((s = reinterpret_cast<const char*>(sqlite3_column_text(st, 6)))) ev.description= s;
    return ev;
}

std::vector<AnomalyEvent> Db::get_recent_anomalies(int limit) {
    std::vector<AnomalyEvent> out;
    if (!db_) return out;
    sqlite3_stmt* st{};
    sqlite3_prepare_v2(db_,
        "SELECT ts_us,type,severity,src_mac,target_mac,ssid,description"
        " FROM anomalies ORDER BY ts_us DESC LIMIT ?;",
        -1, &st, nullptr);
    sqlite3_bind_int(st, 1, limit);
    while (sqlite3_step(st) == SQLITE_ROW)
        out.push_back(row_to_anomaly(st));
    sqlite3_finalize(st);
    return out;
}

std::vector<AnomalyEvent> Db::get_anomalies_for_mac(const std::string& mac, int limit) {
    std::vector<AnomalyEvent> out;
    if (!db_) return out;
    sqlite3_stmt* st{};
    sqlite3_prepare_v2(db_,
        "SELECT ts_us,type,severity,src_mac,target_mac,ssid,description"
        " FROM anomalies WHERE src_mac=? OR target_mac=?"
        " ORDER BY ts_us DESC LIMIT ?;",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, mac.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, mac.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st,  3, limit);
    while (sqlite3_step(st) == SQLITE_ROW)
        out.push_back(row_to_anomaly(st));
    sqlite3_finalize(st);
    return out;
}

void Db::load_graph(Graph& graph) {
    if (!db_) return;
    sqlite3_stmt* st{};
    int n_clients = 0, n_aps = 0, n_ssids = 0, n_probes = 0;

    // 1. SSIDs
    sqlite3_prepare_v2(db_,
        "SELECT name, first_seen, last_seen FROM ssids;", -1, &st, nullptr);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        uint64_t ts = static_cast<uint64_t>(sqlite3_column_int64(st, 2));
        if (name) { graph.get_or_create_ssid(name, ts); ++n_ssids; }
    }
    sqlite3_finalize(st);

    // 2. APs (with beacon to link AP→SSID and set channel/security)
    sqlite3_prepare_v2(db_,
        "SELECT a.bssid, s.name, a.channel, a.security, a.vendor,"
        "       a.first_seen, a.last_seen, a.last_rssi, a.alias, a.password"
        " FROM aps a LEFT JOIN ssids s ON a.ssid_id = s.id;",
        -1, &st, nullptr);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char* bssid_s = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        const char* ssid_s  = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
        int         channel = sqlite3_column_int(st, 2);
        const char* sec_s   = reinterpret_cast<const char*>(sqlite3_column_text(st, 3));
        const char* vend_s  = reinterpret_cast<const char*>(sqlite3_column_text(st, 4));
        uint64_t    ts      = static_cast<uint64_t>(sqlite3_column_int64(st, 6));
        int8_t      rssi    = static_cast<int8_t>(sqlite3_column_int(st, 7));
        const char* alias_s = reinterpret_cast<const char*>(sqlite3_column_text(st, 8));
        const char* pass_s  = reinterpret_cast<const char*>(sqlite3_column_text(st, 9));
        if (!bssid_s) continue;

        MacAddr bssid = mac_from_str(bssid_s);
        NodeId apid = graph.get_or_create_ap(bssid, ts, rssi);
        if (Node* n = graph.get_node(apid)) {
            if (vend_s)  n->vendor = vend_s;
            if (pass_s && pass_s[0]) n->password = pass_s;
            n->is_active = true;
            n->passwords = get_ap_passwords(bssid_s); // load all known passwords
            // Restore crack_not_found flag
            if (n->passwords.empty()) {
                std::string cs, cp;
                if (get_handshake_crack(bssid_s, cs, cp) && cs == "not_found")
                    n->crack_not_found = true;
            }
        }
        if (alias_s && alias_s[0]) graph.set_alias(apid, alias_s);

        if (ssid_s) {
            NodeId sid = graph.get_or_create_ssid(ssid_s, ts);
            graph.add_beacon(apid, sid, channel, 0, sec_s ? sec_s : "", ts);
        }
        ++n_aps;
    }
    sqlite3_finalize(st);

    // 3. Clients
    sqlite3_prepare_v2(db_,
        "SELECT mac, is_random, vendor, first_seen, last_seen, last_rssi,"
        "       seen_count, alias, radio_fingerprint FROM clients;",
        -1, &st, nullptr);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char* mac_s  = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        int8_t      rssi   = static_cast<int8_t>(sqlite3_column_int(st, 5));
        uint64_t    ts     = static_cast<uint64_t>(sqlite3_column_int64(st, 4));
        const char* alias_s = reinterpret_cast<const char*>(sqlite3_column_text(st, 7));
        const char* fp_s    = reinterpret_cast<const char*>(sqlite3_column_text(st, 8));
        if (!mac_s) continue;

        MacAddr mac = mac_from_str(mac_s);
        NodeId cid = graph.get_or_create_client(mac, ts, rssi);
        Node* n = graph.get_node(cid);
        if (n) {
            n->first_seen  = static_cast<uint64_t>(sqlite3_column_int64(st, 3));
            n->seen_count  = static_cast<uint32_t>(sqlite3_column_int(st, 6));
            n->is_active   = true;
            if (fp_s && fp_s[0]) n->radio_fingerprint = fp_s;
        }
        if (alias_s && alias_s[0]) graph.set_alias(cid, alias_s);
        ++n_clients;
    }
    sqlite3_finalize(st);

    // 4. Probe edges (client→ssid)
    sqlite3_prepare_v2(db_,
        "SELECT c.mac, s.name, cs.last_seen, cs.last_rssi"
        " FROM client_ssid cs"
        " JOIN clients c ON cs.client_id = c.id"
        " JOIN ssids   s ON cs.ssid_id   = s.id;",
        -1, &st, nullptr);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char* mac_s  = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        const char* ssid_s = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
        uint64_t    ts     = static_cast<uint64_t>(sqlite3_column_int64(st, 2));
        int8_t      rssi   = static_cast<int8_t>(sqlite3_column_int(st, 3));
        if (!mac_s || !ssid_s) continue;

        MacAddr mac = mac_from_str(mac_s);
        NodeId cid = graph.get_or_create_client(mac, ts, rssi);
        NodeId sid = graph.get_or_create_ssid(ssid_s, ts);
        graph.add_probe(cid, sid, ts, rssi);
        ++n_probes;
    }
    sqlite3_finalize(st);

    // 5. AssociatedWith edges (client ↔ ap)
    int n_assoc = 0;
    sqlite3_prepare_v2(db_,
        "SELECT c.mac, a.bssid, ca.last_seen"
        " FROM client_ap ca"
        " JOIN clients c ON ca.client_id = c.id"
        " JOIN aps     a ON ca.ap_id     = a.id;",
        -1, &st, nullptr);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char* mac_s   = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        const char* bssid_s = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
        uint64_t    ts      = static_cast<uint64_t>(sqlite3_column_int64(st, 2));
        if (!mac_s || !bssid_s) continue;
        MacAddr mac   = mac_from_str(mac_s);
        MacAddr bssid = mac_from_str(bssid_s);
        NodeId cid  = graph.get_or_create_client(mac, ts, -100);
        NodeId apid = graph.get_or_create_ap(bssid, ts, -100);
        graph.add_associated(cid, apid, ts);
        ++n_assoc;
    }
    sqlite3_finalize(st);

    // 6. Restore has_handshake / handshake_aps from handshakes table; also restore crack status to AP
    sqlite3_prepare_v2(db_,
        "SELECT bssid, client_mac, crack_status, password FROM handshakes;",
        -1, &st, nullptr);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char* bssid_s  = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        const void* cm_blob  = sqlite3_column_blob(st, 1);
        int         cm_len   = sqlite3_column_bytes(st, 1);
        const char* status_s = reinterpret_cast<const char*>(sqlite3_column_text(st, 2));
        const char* pass_s   = reinterpret_cast<const char*>(sqlite3_column_text(st, 3));
        if (!bssid_s || !cm_blob || cm_len != 6) continue;

        std::string crack_status = status_s ? status_s : "";
        std::string password     = pass_s   ? pass_s   : "";

        // Convert client_mac blob → MAC string
        const uint8_t* b = static_cast<const uint8_t*>(cm_blob);
        std::string client_mac_s = std::format(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            b[0], b[1], b[2], b[3], b[4], b[5]);

        // Find AP node by bssid label
        NodeId apid = 0;
        for (auto& [id, n] : graph.nodes()) {
            if (n.type == NodeType::AP && n.label == bssid_s) { apid = id; break; }
        }

        // Find client node by MAC label and mark
        for (auto& [id, n] : graph.nodes()) {
            if (n.type == NodeType::Client && n.label == client_mac_s) {
                n.has_handshake = true;
                if (apid != 0) n.handshake_aps.insert(apid);
                break;
            }
        }
    }
    sqlite3_finalize(st);

    std::fprintf(stderr,
        "[db] loaded: %d APs  %d SSIDs  %d clients  %d probes  %d assoc\n",
        n_aps, n_ssids, n_clients, n_probes, n_assoc);
}

void Db::save_graph(const Graph& graph) {
    if (!db_) return;

    std::unordered_map<NodeId, int64_t> ssid_db_id;
    std::unordered_map<NodeId, int64_t> client_db_id;

    exec_sql(db_, "BEGIN;");

    // 1. SSIDs
    {
        sqlite3_stmt* st{};
        sqlite3_prepare_v2(db_,
            "INSERT INTO ssids(name,first_seen,last_seen) VALUES(?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen);",
            -1, &st, nullptr);
        for (auto& [id, n] : graph.nodes()) {
            if (n.type != NodeType::SSID || n.label.empty()) continue;
            uint64_t ts = n.last_seen ? n.last_seen : n.first_seen;
            sqlite3_bind_text (st, 1, n.label.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, static_cast<int64_t>(n.first_seen));
            sqlite3_bind_int64(st, 3, static_cast<int64_t>(ts));
            sqlite3_step(st); sqlite3_reset(st);
        }
        sqlite3_finalize(st);
    }

    // Fetch SSID DB ids (inside same transaction)
    {
        sqlite3_stmt* sel{};
        sqlite3_prepare_v2(db_, "SELECT id FROM ssids WHERE name=?;", -1, &sel, nullptr);
        for (auto& [id, n] : graph.nodes()) {
            if (n.type != NodeType::SSID || n.label.empty()) continue;
            sqlite3_bind_text(sel, 1, n.label.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(sel) == SQLITE_ROW)
                ssid_db_id[id] = sqlite3_column_int64(sel, 0);
            sqlite3_reset(sel);
        }
        sqlite3_finalize(sel);
    }

    // 2. APs
    {
        sqlite3_stmt* st{};
        sqlite3_prepare_v2(db_,
            "INSERT INTO aps(bssid,ssid_id,channel,security,vendor,first_seen,last_seen,last_rssi,seen_count)"
            " VALUES(?,?,?,?,?,?,?,?,0)"
            " ON CONFLICT(bssid) DO UPDATE SET"
            "  ssid_id=COALESCE(excluded.ssid_id,ssid_id),"
            "  channel=CASE WHEN excluded.channel!=0 THEN excluded.channel ELSE channel END,"
            "  security=CASE WHEN excluded.security!='' THEN excluded.security ELSE security END,"
            "  last_seen=MAX(last_seen,excluded.last_seen),"
            "  last_rssi=excluded.last_rssi;",
            -1, &st, nullptr);

        for (auto& [id, n] : graph.nodes()) {
            if (n.type != NodeType::AP || n.label.empty()) continue;
            int64_t ssid_id = -1;
            auto sit = ssid_db_id.find(n.ssid_id);
            if (sit != ssid_db_id.end()) ssid_id = sit->second;
            uint64_t ts = n.last_seen ? n.last_seen : n.first_seen;

            sqlite3_bind_text (st, 1, n.label.c_str(), -1, SQLITE_TRANSIENT);
            if (ssid_id >= 0) sqlite3_bind_int64(st, 2, ssid_id);
            else              sqlite3_bind_null (st, 2);
            sqlite3_bind_int  (st, 3, n.channel);
            sqlite3_bind_text (st, 4, n.security.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st, 5, n.vendor.c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 6, static_cast<int64_t>(n.first_seen));
            sqlite3_bind_int64(st, 7, static_cast<int64_t>(ts));
            sqlite3_bind_int  (st, 8, n.last_rssi);
            sqlite3_step(st); sqlite3_reset(st);
        }
        sqlite3_finalize(st);
    }

    // 3. Clients
    {
        sqlite3_stmt* st{};
        sqlite3_prepare_v2(db_,
            "INSERT INTO clients(mac,is_random,vendor,first_seen,last_seen,last_rssi,seen_count,radio_fingerprint)"
            " VALUES(?,?,?,?,?,?,?,?)"
            " ON CONFLICT(mac) DO UPDATE SET"
            "  last_seen=MAX(last_seen,excluded.last_seen),"
            "  last_rssi=excluded.last_rssi,"
            "  seen_count=MAX(seen_count,excluded.seen_count),"
            "  radio_fingerprint=CASE WHEN length(excluded.radio_fingerprint)>length(radio_fingerprint)"
            "                    THEN excluded.radio_fingerprint ELSE radio_fingerprint END;",
            -1, &st, nullptr);

        for (auto& [id, n] : graph.nodes()) {
            if (n.type != NodeType::Client || n.label.empty()) continue;
            uint64_t ts = n.last_seen ? n.last_seen : n.first_seen;
            sqlite3_bind_text (st, 1, n.label.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (st, 2, n.is_randomized ? 1 : 0);
            sqlite3_bind_text (st, 3, n.vendor.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 4, static_cast<int64_t>(n.first_seen));
            sqlite3_bind_int64(st, 5, static_cast<int64_t>(ts));
            sqlite3_bind_int  (st, 6, n.last_rssi);
            sqlite3_bind_int  (st, 7, static_cast<int32_t>(n.seen_count));
            sqlite3_bind_text (st, 8, n.radio_fingerprint.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(st); sqlite3_reset(st);
        }
        sqlite3_finalize(st);

        sqlite3_stmt* sel{};
        sqlite3_prepare_v2(db_, "SELECT id FROM clients WHERE mac=?;", -1, &sel, nullptr);
        for (auto& [id, n] : graph.nodes()) {
            if (n.type != NodeType::Client || n.label.empty()) continue;
            sqlite3_bind_text(sel, 1, n.label.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(sel) == SQLITE_ROW)
                client_db_id[id] = sqlite3_column_int64(sel, 0);
            sqlite3_reset(sel);
        }
        sqlite3_finalize(sel);
    }

    // 4. ProbesFor edges (client → ssid)
    {
        sqlite3_stmt* st{};
        sqlite3_prepare_v2(db_,
            "INSERT INTO client_ssid(client_id,ssid_id,first_seen,last_seen,last_rssi,probe_count)"
            " VALUES(?,?,?,?,?,?)"
            " ON CONFLICT(client_id,ssid_id) DO UPDATE SET"
            "  last_seen=MAX(last_seen,excluded.last_seen),"
            "  probe_count=MAX(probe_count,excluded.probe_count);",
            -1, &st, nullptr);

        for (auto& e : graph.edges()) {
            if (e.type != EdgeType::ProbesFor) continue;
            auto cit = client_db_id.find(e.a);
            auto sit = ssid_db_id.find(e.b);
            if (cit == client_db_id.end() || sit == ssid_db_id.end()) continue;
            sqlite3_bind_int64(st, 1, cit->second);
            sqlite3_bind_int64(st, 2, sit->second);
            sqlite3_bind_int64(st, 3, static_cast<int64_t>(e.last_seen));
            sqlite3_bind_int64(st, 4, static_cast<int64_t>(e.last_seen));
            sqlite3_bind_int  (st, 5, -70);
            sqlite3_bind_int  (st, 6, static_cast<int32_t>(e.count));
            sqlite3_step(st); sqlite3_reset(st);
        }
        sqlite3_finalize(st);
    }

    // 5. AssociatedWith edges (client ↔ ap)
    {
        // Build ap_db_id map (bssid → db row id) for edge save
        std::unordered_map<NodeId, int64_t> ap_db_id;
        sqlite3_stmt* sel{};
        sqlite3_prepare_v2(db_, "SELECT id FROM aps WHERE bssid=?;", -1, &sel, nullptr);
        for (auto& [id, n] : graph.nodes()) {
            if (n.type != NodeType::AP || n.label.empty()) continue;
            sqlite3_bind_text(sel, 1, n.label.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(sel) == SQLITE_ROW)
                ap_db_id[id] = sqlite3_column_int64(sel, 0);
            sqlite3_reset(sel);
        }
        sqlite3_finalize(sel);

        sqlite3_stmt* st{};
        sqlite3_prepare_v2(db_,
            "INSERT INTO client_ap(client_id,ap_id,first_seen,last_seen)"
            " VALUES(?,?,?,?)"
            " ON CONFLICT(client_id,ap_id) DO UPDATE SET"
            "  last_seen=MAX(last_seen,excluded.last_seen);",
            -1, &st, nullptr);

        for (auto& e : graph.edges()) {
            if (e.type != EdgeType::AssociatedWith) continue;
            auto cit = client_db_id.find(e.a);
            auto ait = ap_db_id.find(e.b);
            if (cit == client_db_id.end() || ait == ap_db_id.end()) continue;
            sqlite3_bind_int64(st, 1, cit->second);
            sqlite3_bind_int64(st, 2, ait->second);
            sqlite3_bind_int64(st, 3, static_cast<int64_t>(e.last_seen));
            sqlite3_bind_int64(st, 4, static_cast<int64_t>(e.last_seen));
            sqlite3_step(st); sqlite3_reset(st);
        }
        sqlite3_finalize(st);
    }

    exec_sql(db_, "COMMIT;");

    int n_nodes = static_cast<int>(graph.nodes().size());
    std::fprintf(stderr, "[db] save_graph: persisted %d nodes\n", n_nodes);
}
