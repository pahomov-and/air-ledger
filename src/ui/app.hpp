#pragma once
#include "entity/graph.hpp"
#include "db/db.hpp"
#include "analytics/relation_builder.hpp"
#include "analytics/anomaly_detector.hpp"
#include "capture/pcap_source.hpp"
#include "capture/channel_hopper.hpp"
#include "capture/handshake_saver.hpp"
#include "capture/deauth_sender.hpp"
#include "ui/graph_view.hpp"
#include "ui/layout.hpp"
#include "ui/sidebar.hpp"
#include "ui/filter_state.hpp"

#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>

#include <atomic>
#include <fstream>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <string>

enum class DeauthEngine { Builtin, Aireplay };
enum class UiProfile { Auto, Beepy };

class App {
public:
    App() = default;
    ~App();

    bool init(const std::string& iface, const std::string& db_path);
    void init_handshake(const HandshakeConfig& cfg);
    void set_deauth_engine(DeauthEngine e) { deauth_engine_ = e; }
    void set_ui_profile(UiProfile p) { ui_profile_ = p; }
    void run();
    void stop();

private:
    // SDL
    SDL_Window*   window_{nullptr};
    SDL_Renderer* renderer_{nullptr};
    TTF_Font*     font_{nullptr};
    int           font_size_{12};
    std::string   font_path_;

    // Core
    Graph           graph_;
    Db              db_;
    LayoutEngine    layout_;
    GraphView       graph_view_;
    Sidebar         sidebar_;

    // Handshake capture
    HandshakeSaver handshake_saver_;
    std::string    passwords_file_;   // plain-text log: BSSID\tSSID\tPASSWORD
    uint32_t       pw_count_{0};      // passwords found so far (for on-screen counter)
    uint64_t       deauth_flash_until_us_{0};
    DeauthEngine   deauth_engine_{DeauthEngine::Builtin};

    struct AppNotif {
        std::string text;
        bool        is_error{false};
        uint64_t    until_us{0};
    };
    std::vector<AppNotif> notifications_;
    void push_error(const std::string& msg);
    void push_warning(const std::string& msg);
    void push_notice(const std::string& msg, uint64_t ttl_us = 4'000'000ULL);
    void add_event_log(const std::string& msg, SDL_Color color);

    // Capture
    std::unique_ptr<PcapSource> capture_;
    std::thread     capture_thread_;
    std::mutex      frame_queue_mutex_;
    std::queue<RawFrame> frame_queue_;
    std::atomic<bool>    running_{false};

    // Timing
    uint64_t last_analytics_us_{0};
    uint64_t last_db_flush_us_{0};
    uint64_t last_active_mark_us_{0};

    // Window layout constants
    static constexpr int WIN_W    = 1280;
    static constexpr int WIN_H    = 720;
    int sidebar_w_{320};  // recalculated from font_size_ on resize

    // Channel hopping
    std::unique_ptr<ChannelHopper> hopper_;
    bool hopping_enabled_{false};
    std::string iface_name_;  // stored for hopper
    int hop_dwell_ms_{500};   // ms per channel, adjustable with +/-
    uint64_t deauth_ch_unlock_us_{0}; // when to restore channel after deauth lock

    // Alias input mode
    bool alias_mode_{false};
    std::string alias_buf_;
    NodeId alias_target_{0};

    // Search mode
    bool search_mode_{false};

    // Filters
    FilterState filter_;

    // Stats
    uint64_t total_frames_{0};
    uint32_t stats_beacon_{0};
    uint32_t stats_probe_req_{0};
    uint32_t stats_probe_resp_{0};
    uint32_t stats_data_tods_{0};
    uint32_t stats_data_fromds_{0};
    uint32_t stats_data_other_{0};
    uint32_t stats_auth_{0};
    uint32_t stats_deauth_{0};
    uint32_t stats_assoc_req_{0};
    uint32_t stats_assoc_resp_{0};
    uint32_t stats_assoc_edges_{0};
    uint32_t stats_unparsed_{0};
    bool initial_resize_done_{false}; // Wayland: window starts 1×1, real size comes on first RESIZED
    bool prev_dragging_{false};   // for drag-release velocity reset
    NodeId prev_selected_{0};    // for channel-lock on selection change
    size_t last_saved_node_count_{0};
    UiProfile ui_profile_{UiProfile::Auto};
    uint64_t last_iface_diag_us_{0};
    int      iface_diag_channel_{0};
    std::string iface_diag_type_{"?"};
    std::string iface_diag_txpower_{"?"};

    void process_pending_frames();
    void run_analytics();
    void update_iface_diagnostics();
    void render_action_bar(int w, int h);
    void apply_selection_channel_lock(NodeId selected); // switch to AP's channel
    static uint64_t now_us();

    bool load_font();
    void resize_font(int delta);
    void handle_click(int sx, int sy);

    // Startup diagnostic dialog
    std::vector<std::string> startup_warnings_;
    std::vector<std::string> startup_wordlists_; // copy of wordlist paths for startup check
    bool startup_dialog_open_{false};
    void check_startup();
    void render_startup_dialog(int w, int h);

    // Anomaly detection
    AnomalyDetector anomaly_detector_;
    std::vector<AnomalyEvent> anomaly_log_;  // last 100 events (newest first)
    static constexpr size_t ANOMALY_LOG_MAX = 100;
    std::vector<GraphView::EventLogEntry> event_log_; // newest first
    static constexpr size_t EVENT_LOG_MAX = 300;

    // Aggressive mode — cyclic deauth → handshake harvest
    bool     aggressive_mode_{false};
    int      aggr_ap_idx_{0};          // index into sorted AP list
    uint64_t aggr_next_us_{0};         // when to fire next action
    std::string aggr_target_label_;    // label of current target (for UI)
    uint64_t aggr_arm_until_us_{0};    // double-press window for enabling aggressive mode

    static constexpr uint64_t AGGR_DWELL_US = 8'000'000ULL; // 8s per AP

    void toggle_aggressive_mode();
    void tick_aggressive_mode();
    void run_inject_diagnostics(NodeId ap_id);

    void toggle_channel_hopping();
    void reset_iface();
    void send_deauth(NodeId ap_id);
    void start_alias_input(NodeId target);
    void confirm_alias();
    void cancel_alias();
    void toggle_filter_active();
    void toggle_filter_randomized();
    void toggle_filter_probe_only();
    void export_json(NodeId focus);  // 0 = full graph
    void start_search();
    void cancel_search();
    void refresh_hs_list();  // rebuild handshake list for overlay
    void toggle_auto_crack();
};
