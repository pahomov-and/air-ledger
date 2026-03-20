#pragma once
#include "parser/types.hpp"
#include "entity/graph.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

enum class AnomalyType : uint8_t {
    DeauthFlood,       // Flood of deauth/disassoc frames from one source
    ProbeFlood,        // Probe request storm from a single device
    AuthFlood,         // Auth request storm — possible WPS or 4-way brute-force
    EvilTwin,          // Same SSID, different BSSID, different security type
    UnexpectedDeauth,  // Deauth targeting an actively-associated client
};

inline const char* anomaly_type_name(AnomalyType t) {
    switch (t) {
        case AnomalyType::DeauthFlood:      return "DeauthFlood";
        case AnomalyType::ProbeFlood:       return "ProbeFlood";
        case AnomalyType::AuthFlood:        return "AuthFlood";
        case AnomalyType::EvilTwin:         return "EvilTwin";
        case AnomalyType::UnexpectedDeauth: return "UnexpectedDeauth";
        default: return "Unknown";
    }
}

struct AnomalyEvent {
    uint64_t    ts_us{0};
    AnomalyType type{AnomalyType::DeauthFlood};
    int         severity{2};    // 1=info, 2=warn, 3=critical
    std::string src_mac;
    std::string target_mac;
    std::string ssid;
    std::string description;
};

class AnomalyDetector {
public:
    // Feed a parsed frame; may generate new events
    void process(const ParsedFrame& frame, const Graph& graph, uint64_t ts_us);

    // Drain all accumulated events since last call
    std::vector<AnomalyEvent> drain();

    // Per-MAC total anomaly event count (for graph visual markers)
    int anomaly_count(const std::string& mac) const;

private:
    // Thresholds
    static constexpr uint32_t DEAUTH_THRESH  = 10;
    static constexpr uint64_t DEAUTH_WIN_US  = 5'000'000ULL;   // 5s
    static constexpr uint32_t PROBE_THRESH   = 50;
    static constexpr uint64_t PROBE_WIN_US   = 10'000'000ULL;  // 10s
    static constexpr uint32_t AUTH_THRESH    = 20;
    static constexpr uint64_t AUTH_WIN_US    = 30'000'000ULL;  // 30s
    // Re-emit cooldown per (type, mac)
    static constexpr uint64_t COOLDOWN_US    = 30'000'000ULL;  // 30s

    struct Counter {
        uint64_t window_start_us{0};
        uint32_t count{0};
    };

    struct KnownAP {
        std::string bssid;
        std::string security;
    };

    std::unordered_map<std::string, Counter> deauth_ctr_;
    std::unordered_map<std::string, Counter> probe_ctr_;
    std::unordered_map<std::string, Counter> auth_ctr_;

    // SSID → list of known APs broadcasting it (for evil-twin detection)
    std::unordered_map<std::string, std::vector<KnownAP>> ssid_aps_;

    // Dedup: key = "<type>:<mac>", value = last emit time
    std::unordered_map<std::string, uint64_t> last_emit_;

    // Per-MAC cumulative anomaly count
    std::unordered_map<std::string, int> anomaly_counts_;

    std::vector<AnomalyEvent> pending_;

    // Returns true if counter ticked (false on window reset)
    bool inc_counter(Counter& c, uint64_t ts_us, uint64_t window_us);
    bool can_emit(AnomalyType type, const std::string& mac, uint64_t ts_us);
    void emit(AnomalyEvent ev);
};
