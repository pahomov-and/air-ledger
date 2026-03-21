#pragma once
#include "entity/graph.hpp"
#include "ui/filter_state.hpp"
#include "analytics/anomaly_detector.hpp"
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include <vector>
#include <string>
#include <unordered_set>

class GraphView {
public:
    bool init(SDL_Renderer* renderer, TTF_Font* font);
    void set_font(TTF_Font* font) { font_ = font; }
    void set_renderer(SDL_Renderer* r) { renderer_ = r; }
    void toggle_labels() { labels_full_ = !labels_full_; }
    void toggle_help() { show_help_ = !show_help_; help_scroll_ = 0; }
    void help_page_next() { help_move(font_ ? std::max(1, (vp_h_ - 16) / (TTF_FontHeight(font_) + 2)) : 1); }
    void help_move(int delta) { help_scroll_ = std::max(0, help_scroll_ + delta); }
    bool help_visible() const { return show_help_; }

    // AP list overlay
    void toggle_ap_list() { show_ap_list_ = !show_ap_list_; ap_list_cursor_ = 0; show_crack_list_ = false; }
    void close_ap_list()  { show_ap_list_ = false; }
    bool ap_list_visible() const { return show_ap_list_; }
    void ap_list_move(int delta, const Graph& g);
    NodeId ap_list_cursor_node(const Graph& g) const;

    // Handshake list overlay (j key)
    struct HandshakeListEntry {
        NodeId client_id{0};       // for graph selection via Enter
        NodeId ap_id{0};
        std::string client_mac;    // short display MAC
        std::string ap_bssid;      // full BSSID
        std::string ap_ssid;
        uint64_t captured_at{0};   // unix seconds
        enum class Status { Saved, Queued, Running, Found, NotFound } status{Status::Saved};
        std::string password;
        int spin_frame{0};
    };
    void toggle_hs_list() { show_hs_list_ = !show_hs_list_; hs_list_cursor_ = 0; show_ap_list_ = false; show_crack_list_ = false; }
    void close_hs_list()  { show_hs_list_ = false; }
    bool hs_list_visible() const { return show_hs_list_; }
    void hs_list_move(int delta);
    void set_hs_list(const std::vector<HandshakeListEntry>& entries) { hs_list_entries_ = entries; }
    NodeId hs_list_select_client() const;  // returns client NodeId of current cursor row

    // Crack list overlay
    struct CrackListEntry {
        std::string bssid;       // full BSSID string
        std::string ssid;
        int handshake_count{0};
        int spin_frame{0};       // 0-3 for spinner animation
        enum class Status { Queued, Running, Found, NotFound } status{Status::Queued};
        std::string password;    // filled when Found
        uint64_t speed_kps{0};  // crack speed, k/s (0 = unknown)
    };
    void toggle_crack_list() { show_crack_list_ = !show_crack_list_; crack_list_cursor_ = 0; show_ap_list_ = false; }
    void close_crack_list()  { show_crack_list_ = false; }
    bool crack_list_visible() const { return show_crack_list_; }
    void crack_list_move(int delta);
    void set_crack_list(const std::vector<CrackListEntry>& entries) { crack_list_entries_ = entries; }
    const CrackListEntry* crack_list_current() const;

    // Anomaly log overlay (w key)
    void toggle_anomaly_log() { show_anomaly_log_ = !show_anomaly_log_; anomaly_cursor_ = 0; }
    void close_anomaly_log()  { show_anomaly_log_ = false; }
    bool anomaly_log_visible() const { return show_anomaly_log_; }
    void anomaly_log_move(int delta);
    const AnomalyEvent* anomaly_log_current() const;
    void set_anomaly_log(const std::vector<AnomalyEvent>& log) { anomaly_log_ = log; }

    // Event log overlay (y key)
    struct EventLogEntry {
        std::string text;
        SDL_Color   color{200, 200, 200, 255};
        uint32_t    repeats{1};
    };
    void toggle_event_log() { show_event_log_ = !show_event_log_; event_log_cursor_ = 0; }
    void close_event_log()  { show_event_log_ = false; }
    bool event_log_visible() const { return show_event_log_; }
    void event_log_move(int delta);
    void set_event_log(const std::vector<EventLogEntry>& entries) { event_log_entries_ = entries; }
    const EventLogEntry* event_log_current() const;
    NodeId sidebar_focus_node(const Graph& graph) const;

    // AP group focus / collapse
    void set_ap_focus(NodeId id) { ap_focus_id_ = id; }
    void toggle_ap_collapse(NodeId ap_id);
    bool is_ap_collapsed(NodeId id) const { return collapsed_aps_.count(id) > 0; }
    void set_pw_count(uint32_t n) { pw_count_ = n; }

    struct CrackInfo {
        std::string ssid;            // empty = no active cracking
        uint64_t speed_kps{0};
        bool aggressive{false};      // aggressive mode is active
        std::string aggr_target;     // current deauth target label
        std::string engine_label;    // "CPU", "GPU", "air"
    };
    void set_crack_info(const CrackInfo& ci) { crack_info_ = ci; }
    void set_deauth_state(bool can_deauth, bool flash) {
        can_deauth_ = can_deauth;
        deauth_flash_ = flash;
    }

    struct Notification {
        std::string text;
        SDL_Color   color;  // {255,0,0} = error, {255,255,0} = warning
    };
    void set_notifications(const std::vector<Notification>& n) { notifications_ = n; }
    void render(const Graph& graph, int viewport_w, int viewport_h);
    void handle_event(const SDL_Event& e);
    NodeId selected_node() const { return selected_; }
    void   deselect()            { selected_ = 0; }
    void   select_and_focus(NodeId id, const Graph& g);
    void set_viewport(int x, int y, int w, int h);
    void set_filter(const FilterState& f) { filter_ = f; }

    // Public accessors for drag state (used by App)
    bool  is_dragging()      const { return dragging_ && drag_valid_; }
    float drag_x()           const { return drag_offset_x_; }
    float drag_y()           const { return drag_offset_y_; }

    // Called by App to seed drag position with node's current world coords,
    // preventing snap-to-origin on the first frame of a new drag.
    void init_drag_pos(float wx, float wy) {
        drag_offset_x_ = wx;
        drag_offset_y_ = wy;
        drag_valid_ = true;
    }

    // True on the frame drag transitions false → true (used by App to call init_drag_pos)
    bool drag_just_started() const { return drag_started_this_frame_; }

    // Keyboard-driven camera controls
    void zoom_center(float factor);
    void pan_keyboard(float sdx, float sdy);
    void fit_view(const Graph& graph);   // fit all nodes into viewport (key 0)

    // Expose node_at for app-side click handling
    NodeId node_at_public(const Graph& g, int sx, int sy) const { return node_at(g, sx, sy); }

private:
    SDL_Renderer* renderer_{nullptr};
    TTF_Font* font_{nullptr};

    float scale_{1.0f};
    float pan_x_{0.0f};
    float pan_y_{0.0f};

    NodeId selected_{0};
    NodeId hovered_{0};
    bool dragging_{false};
    bool panning_{false};

    int last_mouse_x_{0}, last_mouse_y_{0};
    int press_x_{0}, press_y_{0};  // position at MOUSEBUTTONDOWN for click vs drag
    float drag_offset_x_{0}, drag_offset_y_{0};
    bool drag_valid_{false};           // false until App seeds the position via init_drag_pos()
    bool drag_started_this_frame_{false}; // one-frame pulse on drag start
    bool prev_dragging_{false};        // for edge detection

    bool pending_click_{false};    // set on short MOUSEBUTTONUP, resolved in render()
    int pending_click_x_{0}, pending_click_y_{0};

    bool labels_full_{false};  // false = SSID names only; true = all labels
    bool show_help_{false};    // true = show full help overlay
    int  help_scroll_{0};     // first visible line index in help overlay
    bool show_ap_list_{false}; // true = show AP picker overlay
    int  ap_list_cursor_{0};  // highlighted row in AP list
    bool show_crack_list_{false}; // true = show crack queue overlay
    int  crack_list_cursor_{0};
    std::vector<CrackListEntry> crack_list_entries_;
    bool show_hs_list_{false};    // true = show handshake list overlay
    int  hs_list_cursor_{0};
    std::vector<HandshakeListEntry> hs_list_entries_;
    NodeId ap_focus_id_{0};   // selected AP — force-show its active clients
    std::unordered_set<NodeId> collapsed_aps_; // APs whose client groups are hidden
    mutable std::unordered_set<NodeId> collapsed_clients_cache_; // rebuilt each render
    mutable std::unordered_set<NodeId> focus_clients_cache_;     // active clients of focused AP
    uint32_t pw_count_{0};    // cracked passwords counter, shown top-right
    CrackInfo crack_info_;    // active cracking status, shown top-left
    bool can_deauth_{false};
    bool deauth_flash_{false};
    std::vector<Notification> notifications_;
    bool show_anomaly_log_{false};
    std::vector<AnomalyEvent> anomaly_log_;
    int  anomaly_cursor_{0};
    bool show_event_log_{false};
    int  event_log_cursor_{0};
    std::vector<EventLogEntry> event_log_entries_;

    // Viewport rect in window coords
    int vp_x_{0}, vp_y_{0}, vp_w_{1200}, vp_h_{900};

    FilterState filter_;

    SDL_FPoint world_to_screen(float wx, float wy) const;
    SDL_FPoint screen_to_world(float sx, float sy) const;

    bool is_visible_node(const Node& n) const;
    void draw_node(const Node& n, bool sel, bool hov, uint8_t alpha = 255);
    void draw_edge(const Edge& e, const Graph& graph, uint8_t alpha = 255);
    void draw_label(const Node& n, const Graph& graph, uint8_t alpha = 255);
    void draw_circle_filled(int cx, int cy, int r, SDL_Color col);
    void draw_circle_outline(int cx, int cy, int r, SDL_Color col);
    void draw_ap_list(const Graph& graph);
    void draw_crack_list();
    void draw_hs_list();
    void draw_anomaly_log();
    void draw_event_log();

    float node_radius(const Node& n) const;
    SDL_Color node_color(const Node& n, bool active_boost, uint8_t alpha_override = 255) const;

    // Filter helper: returns true if node should be shown normally
    bool node_matches_filter(const Node& n, const Graph& graph) const;

    // Find node at screen coords
    NodeId node_at(const Graph& graph, int sx, int sy) const;
};
