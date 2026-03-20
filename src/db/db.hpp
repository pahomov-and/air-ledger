#pragma once
#include "parser/types.hpp"
#include "entity/graph.hpp"
#include "capture/wpa_crack.hpp"
#include "analytics/anomaly_detector.hpp"
#include <sqlite3.h>
#include <string>
#include <vector>
#include <cstdint>

class Db {
public:
    Db() = default;
    ~Db();

    bool open(const std::string& path);
    void create_schema();
    void close();

    // Insert/update entities — return row id, or -1 on error
    int64_t upsert_client(const MacAddr& mac, bool is_randomized,
                          uint64_t ts, int8_t rssi, const std::string& vendor);
    int64_t upsert_ssid(const std::string& ssid, uint64_t ts);
    int64_t upsert_ap(const MacAddr& bssid, int64_t ssid_id, int channel,
                      const std::string& security, const std::string& vendor,
                      uint64_t ts, int8_t rssi);
    void upsert_probe(int64_t client_id, int64_t ssid_id, uint64_t ts, int8_t rssi);
    void upsert_association(int64_t client_id, int64_t ap_id, uint64_t ts);
    void insert_observation(const ParsedFrame& frame);
    void upsert_similarity(int64_t a, int64_t b, float score, int common);

    // Aliases
    void set_alias(const std::string& mac, const std::string& alias);
    std::string get_alias(const std::string& mac);

    // Cracked WPA passwords for an AP (multiple supported)
    void set_ap_password(const std::string& bssid, const std::string& password); // compat
    void add_ap_password(const std::string& bssid, const std::string& password);
    std::vector<std::string> get_ap_passwords(const std::string& bssid);

    // WPA handshakes — save for offline cracking on another machine
    void save_handshake(const std::string& bssid, const std::string& ssid,
                        const WpaHandshake& hs, const std::string& pcap_path);
    int  handshake_count(const std::string& bssid); // how many stored for this AP
    // Update crack result for all handshakes of a given AP
    void update_handshake_crack(const std::string& bssid,
                                const std::string& status,   // "found"/"not_found"
                                const std::string& password); // empty if not found
    // Get crack_status and password for a bssid (latest non-empty result)
    bool get_handshake_crack(const std::string& bssid,
                             std::string& out_status, std::string& out_password);

    // Anomaly events
    void save_anomaly(const AnomalyEvent& ev);
    // Return last N anomaly events, newest first
    std::vector<AnomalyEvent> get_recent_anomalies(int limit = 50);
    // Return anomaly events involving a specific MAC
    std::vector<AnomalyEvent> get_anomalies_for_mac(const std::string& mac, int limit = 20);

    // Load previously saved graph state from DB into graph on startup
    void load_graph(Graph& graph);

    // Persist current graph nodes/edges to DB (called periodically)
    void save_graph(const Graph& graph);

    // Batch flush
    void flush_batch();

private:
    sqlite3* db_{nullptr};
    std::vector<ParsedFrame> obs_batch_;
    static constexpr int BATCH_SIZE = 50;

    // Prepared statements
    sqlite3_stmt* stmt_upsert_client_{nullptr};
    sqlite3_stmt* stmt_upsert_ssid_{nullptr};
    sqlite3_stmt* stmt_upsert_ap_{nullptr};
    sqlite3_stmt* stmt_upsert_probe_{nullptr};
    sqlite3_stmt* stmt_insert_obs_{nullptr};
    sqlite3_stmt* stmt_upsert_assoc_{nullptr};
    sqlite3_stmt* stmt_upsert_sim_{nullptr};
    sqlite3_stmt* stmt_set_alias_{nullptr};
    sqlite3_stmt* stmt_get_alias_{nullptr};

    bool prepare_statements();
    void finalize_statements();

    // Execute a batch of observations in a single transaction
    void flush_observations(const std::vector<ParsedFrame>& frames);
};
