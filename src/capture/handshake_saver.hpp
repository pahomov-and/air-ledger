#pragma once
#include "parser/types.hpp"
#include "capture/wpa_crack.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

struct HandshakeConfig {
    std::string capture_dir;
    std::vector<std::string> wordlists;
    bool auto_crack{true};
    CrackEngine crack_engine{CrackEngine::Builtin};
    std::string passwords_file; // plain-text log: BSSID\tSSID\tPASSWORD (empty = no file)
};

// One crack attempt per BSSID, managed as a queue.
struct CrackJob {
    std::string bssid;
    std::string ssid;
    std::string pcap_path;
    std::string log_path;
    WpaHandshake handshake;

    enum class Status { Queued, Running, Found, NotFound };
    Status status{Status::Queued};

    std::string password;              // filled on Found
    std::string actual_engine;         // "CPU", "GPU", "air" — actual engine launched
    std::string requested_engine;      // requested engine before fallbacks
    bool force_builtin{false};         // true = this job must run builtin engine (GPU backend failed)
    std::string verify_wordlist_path;  // non-empty = verification run (single-password wordlist)
    std::string last_reason;           // latest transition/fallback reason
    std::string last_handshake_id;     // used to detect same/new handshake on same BSSID
    int handshake_count{0};            // how many complete HS captured
    int spin_frame{0};                 // spinner animation (0-3, only when Running)

    mutable uint64_t last_speed_check_s{0};
    mutable uint64_t cached_speed_kps{0};
    uint64_t started_at_s{0};  // time_t when job started (for empty-log timeout)
};

class HandshakeSaver {
public:
    void configure(const HandshakeConfig& cfg);
    bool is_active() const { return !config_.capture_dir.empty(); }
    void set_auto_crack(bool enabled) { config_.auto_crack = enabled; }
    bool auto_crack_enabled() const { return config_.auto_crack; }

    void update_ssid(const std::string& bssid, const std::string& ssid);
    void feed(const RawFrame& raw, const ParsedFrame& parsed);

    // Old-style result struct (kept for app.cpp compat)
    struct CrackResult {
        std::string bssid;
        std::string ssid;
        std::string password;
        bool        found{false};
    };

    struct RuntimeEvent {
        enum class Level { Info, Warning, Error } level{Level::Info};
        std::string text;
    };

    struct CrackStatus {
        std::string bssid;
        std::string ssid;
        uint64_t    speed_kps{0};
        bool        active{false};
        std::string engine_label;  // "CPU", "GPU", "air"
    };

    // New handshake event — returned by drain_new_handshakes() for DB persistence
    struct NewHandshake {
        std::string bssid;
        std::string ssid;
        std::string pcap_path;
        WpaHandshake hs;
    };

    // Poll for newly completed jobs. Call periodically from main loop.
    std::vector<CrackResult> poll_results();

    // Drain newly captured handshakes (for saving to DB). Call periodically.
    std::vector<NewHandshake> drain_new_handshakes();

    // Drain crack/runtime events for GUI toast + event log.
    std::vector<RuntimeEvent> drain_runtime_events();


    // For legacy UI (crack indicator top-left)
    CrackStatus current_crack_status() const;

    // Full job list for the crack list overlay
    const std::vector<CrackJob>& crack_jobs() const { return jobs_; }

    // Read-only job lookup (for aggressive mode skip logic)
    const CrackJob* find_job_ro(const std::string& bssid) const {
        for (const auto& j : jobs_) if (j.bssid == bssid) return &j;
        return nullptr;
    }

    // Advance spinner for Running job (call ~every 300ms)
    void tick_spinners();

private:
    struct BssidState {
        std::string ssid;
        std::string dir;
        bool has_m1{false};
        bool has_m2{false};
        bool has_m3{false};
        bool has_m4{false};
        int  pcap_fd{-1};
        WpaHandshake handshake;
    };

    HandshakeConfig config_;
    std::unordered_map<std::string, BssidState> states_;
    std::vector<CrackJob> jobs_; // ordered queue; at most one Running at a time
    std::vector<NewHandshake> new_hs_events_; // drain_new_handshakes() returns these
    std::vector<RuntimeEvent> runtime_events_;

    // Find job for bssid, or nullptr
    CrackJob* find_job(const std::string& bssid);

    // Start the next Queued job if none is Running
    void advance_queue();

    std::string resolve_dir(const std::string& bssid, const std::string& ssid);
    bool ensure_pcap(const std::string& bssid, BssidState& s);
    static void append_pcap_frame(int fd, const RawFrame& raw);
    static void write_pcap_header(int fd);
    static bool is_crackable(const BssidState& s);
    static std::string safe_name(const std::string& s, size_t max_len = 32);
    void emit_event(RuntimeEvent::Level level, const std::string& text);
};
