#include "sidebar.hpp"
#include <chrono>
#include <format>
#include <algorithm>
#include <vector>

bool Sidebar::init(SDL_Renderer* renderer, TTF_Font* font) {
    renderer_ = renderer;
    font_ = font;
    return renderer_ != nullptr;
}

uint64_t Sidebar::now_us() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<microseconds>(system_clock::now().time_since_epoch()).count());
}

std::string Sidebar::format_age(uint64_t ts_us, uint64_t now_ust) const {
    if (ts_us == 0) return "never";
    uint64_t diff_us = (now_ust >= ts_us) ? (now_ust - ts_us) : 0;
    uint64_t secs = diff_us / 1'000'000;
    if (secs < 60)         return std::format("{}s ago", secs);
    if (secs < 3600)       return std::format("{}m ago", secs / 60);
    if (secs < 86400)      return std::format("{}h ago", secs / 3600);
    return std::format("{}d ago", secs / 86400);
}

void Sidebar::draw_text(const std::string& text, int x, int& y, SDL_Color color) {
    if (!font_ || text.empty()) { y += 18; return; }
    SDL_Surface* surf = TTF_RenderUTF8_Blended(font_, text.c_str(), color);
    if (!surf) { y += 18; return; }
    SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer_, surf);
    SDL_FreeSurface(surf);
    if (!tex) { y += 18; return; }

    int tw, th;
    SDL_QueryTexture(tex, nullptr, nullptr, &tw, &th);
    SDL_Rect dst{x, y, tw, th};
    SDL_RenderCopy(renderer_, tex, nullptr, &dst);
    SDL_DestroyTexture(tex);
    y += th + 2;
}

void Sidebar::draw_separator(int x, int y, int w) {
    SDL_SetRenderDrawColor(renderer_, 255, 255, 255, 255);
    SDL_RenderDrawLine(renderer_, x, y, x + w, y);
}

void Sidebar::render_empty(int x, int& y) {
    SDL_Color dim{180, 180, 180, 255};
    draw_text("No selection", x, y, dim);
}

void Sidebar::render_client(const Node& n, const Graph& graph, int x, int& y) {
    uint64_t now = now_us();
    int sw = w_ - 20;

    SDL_Color header{0, 255, 255, 255};   // cyan
    SDL_Color key{200, 200, 200, 255};
    SDL_Color val{255, 255, 255, 255};

    draw_text("CLIENT", x, y, header);

    const std::string& name = n.alias.empty() ? n.label : n.alias;
    draw_text(name, x, y, val);
    draw_text(std::format("Rnd:{} Act:{} RSSI:{}",
        n.is_randomized ? "y" : "n",
        n.is_active ? "y" : "n",
        n.last_rssi), x, y, key);
    if (n.anomaly_count > 0)
        draw_text(std::format("Anomalies:{}", n.anomaly_count), x, y, {255, 140, 0, 255});
    draw_text(std::format("Seen:{} Last:{}", n.seen_count, format_age(n.last_seen, now)), x, y, key);

    draw_separator(x, y, sw); y += 4;

    // Associated APs — all, sorted by edge count, handshake APs marked with [hs]
    std::vector<std::pair<uint32_t, NodeId>> assoc_aps;
    for (auto& e : graph.edges()) {
        if (e.type != EdgeType::AssociatedWith) continue;
        NodeId other = (e.a == n.id) ? e.b : (e.b == n.id) ? e.a : 0;
        if (other == 0) continue;
        const Node* an = graph.get_node(other);
        if (an && an->type == NodeType::AP)
            assoc_aps.emplace_back(e.count, other);
    }
    std::sort(assoc_aps.begin(), assoc_aps.end(), [](auto& a, auto& b){ return a.first > b.first; });

    draw_text(std::format("APs({}):", assoc_aps.size()), x, y, header);
    int count = 0;
    for (auto& [cnt, apid] : assoc_aps) {
        if (count++ >= 4) { draw_text("..more", x, y, key); break; }
        const Node* an = graph.get_node(apid);
        if (!an) continue;
        const std::string& lbl = an->alias.empty() ? an->label : an->alias;
        bool hs = n.handshake_aps.count(apid) > 0;
        SDL_Color c = hs ? SDL_Color{0, 255, 255, 255} : SDL_Color{0, 255, 0, 255};
        draw_text(std::format("{}{}", lbl, hs ? " [hs]" : ""), x, y, c);
    }

    draw_separator(x, y, sw); y += 4;

    // Probed SSIDs
    draw_text(std::format("Probed({}):", n.probed_ssids.size()), x, y, header);
    int pcount = 0;
    for (NodeId sid : n.probed_ssids) {
        if (pcount++ >= 4) { draw_text("..more", x, y, key); break; }
        const Node* sn = graph.get_node(sid);
        if (sn) draw_text(sn->label, x, y, val);
    }
}

void Sidebar::render_ssid(const Node& n, const Graph& graph, int x, int& y) {
    uint64_t now = now_us();
    int sw = w_ - 20;
    SDL_Color key{200, 200, 200, 255};
    SDL_Color val{255, 255, 255, 255};
    SDL_Color header = n.is_ghost ? SDL_Color{255, 0, 255, 255}   // magenta
                                  : SDL_Color{0, 255, 0, 255};     // green

    draw_text(n.is_ghost ? "GHOST SSID" : "SSID", x, y, header);
    draw_text(n.label, x, y, val);
    draw_text(std::format("Last:{}", format_age(n.last_seen, now)), x, y, key);

    draw_separator(x, y, sw); y += 4;

    std::vector<NodeId> probers;
    for (auto& e : graph.edges()) {
        if (e.type == EdgeType::ProbesFor && e.b == n.id)
            probers.push_back(e.a);
    }
    draw_text(std::format("Clients({}):", probers.size()), x, y, header);
    int cnt = 0;
    for (NodeId cid : probers) {
        if (cnt++ >= 4) { draw_text("..more", x, y, key); break; }
        const Node* cn = graph.get_node(cid);
        if (cn) draw_text(cn->alias.empty() ? cn->label : cn->alias, x, y, val);
    }

    draw_separator(x, y, sw); y += 4;

    std::vector<NodeId> aps;
    for (auto& e : graph.edges()) {
        if (e.type == EdgeType::Broadcasts && e.b == n.id) aps.push_back(e.a);
    }
    draw_text(std::format("APs({}):", aps.size()), x, y, header);
    cnt = 0;
    for (NodeId apid : aps) {
        if (cnt++ >= 3) { draw_text("..more", x, y, key); break; }
        const Node* an = graph.get_node(apid);
        if (an) {
            const std::string& lbl = an->alias.empty() ? an->label : an->alias;
            draw_text(std::format("ch{} {}", an->channel, lbl), x, y, val);
        }
    }
}

void Sidebar::render_ap(const Node& n, const Graph& graph, int x, int& y) {
    uint64_t now = now_us();
    int sw = w_ - 20;
    SDL_Color header{255, 0, 0, 255};   // red
    SDL_Color key{200, 200, 200, 255};
    SDL_Color val{255, 255, 255, 255};

    draw_text("AP", x, y, header);

    const std::string& name = n.alias.empty() ? n.label : n.alias;
    draw_text(name, x, y, val);

    std::string ssid_str = "?";
    if (n.ssid_id != 0) {
        const Node* sn = graph.get_node(n.ssid_id);
        if (sn) ssid_str = sn->label;
    }
    draw_text(std::format("SSID:{}", ssid_str), x, y, val);
    draw_text(std::format("ch:{} RSSI:{}", n.channel, n.last_rssi), x, y, key);
    draw_text(std::format("Sec:{}", n.security.empty() ? "Open" : n.security), x, y, key);
    if (!n.passwords.empty()) {
        for (const auto& pw : n.passwords)
            draw_text(std::format("PW:{}", pw), x, y, {0, 255, 0, 255});
    } else if (!n.password.empty()) {
        draw_text(std::format("PW:{}", n.password), x, y, {0, 255, 0, 255});
    } else if (n.crack_not_found) {
        draw_text("PW: not found", x, y, {255, 80, 80, 255});
    }
    draw_text(std::format("Act:{} Seen:{}", n.is_active ? "y" : "n", n.seen_count), x, y, key);
    if (n.anomaly_count > 0)
        draw_text(std::format("Anomalies:{}", n.anomaly_count), x, y, {255, 140, 0, 255});
    draw_text(std::format("Last:{}", format_age(n.last_seen, now)), x, y, key);

    draw_separator(x, y, sw); y += 4;

    std::vector<std::pair<uint32_t, NodeId>> assoc_clients;
    for (auto& e : graph.edges()) {
        if (e.type != EdgeType::AssociatedWith) continue;
        NodeId other = (e.a == n.id) ? e.b : (e.b == n.id) ? e.a : 0;
        if (other == 0) continue;
        const Node* cn = graph.get_node(other);
        if (cn && cn->type == NodeType::Client)
            assoc_clients.emplace_back(e.count, other);
    }
    std::sort(assoc_clients.begin(), assoc_clients.end(),
              [](auto& a, auto& b){ return a.first > b.first; });
    draw_text(std::format("Clients({}):", assoc_clients.size()), x, y, header);
    int cc = 0;
    for (auto& [cnt, cid] : assoc_clients) {
        if (cc++ >= 4) { draw_text("..more", x, y, key); break; }
        const Node* cn = graph.get_node(cid);
        if (cn) {
            const std::string& lbl = cn->alias.empty() ? cn->label : cn->alias;
            draw_text(std::format("{}({}x)", lbl, cnt), x, y, val);
        }
    }
}

void Sidebar::render(const Graph& graph, NodeId selected,
                     int sidebar_x, int w, int h,
                     const FilterState& filter, bool alias_mode,
                     const std::string& alias_buf, NodeId alias_target,
                     uint64_t total_frames, uint32_t beacons, uint32_t probe_reqs,
                     bool hopping, int current_channel, int dwell_ms,
                     bool search_mode, bool has_5ghz, int total_channels,
                     bool ch_locked, int locked_ch)
{
    if (!renderer_) return;
    w_ = w;  // store for sub-render functions

    // Clip to sidebar area to prevent text overflow
    SDL_Rect clip{sidebar_x, 0, w, h};
    SDL_RenderSetClipRect(renderer_, &clip);

    // Background: black
    SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 255);
    SDL_RenderFillRect(renderer_, &clip);

    // Border: white vertical line
    SDL_SetRenderDrawColor(renderer_, 255, 255, 255, 255);
    SDL_RenderDrawLine(renderer_, sidebar_x, 0, sidebar_x, h);

    int x = sidebar_x + 4;
    int y = 4;
    int sw = w - 8;

    draw_separator(x, y, sw); y += 4;

    // Hopping status
    if (!hopping) {
        SDL_Color warn{255, 255, 0, 255};   // yellow
        draw_text("HOP:OFF (H)", x, y, warn);
    } else if (ch_locked) {
        SDL_Color lock_col{255, 255, 0, 255};
        draw_text(std::format("LOCK ch:{}", locked_ch), x, y, lock_col);
    } else {
        SDL_Color hop_col{0, 255, 0, 255};  // green
        const char* band = has_5ghz ? "2.4+5G" : "2.4G";
        draw_text(std::format("HOP ch:{} {}", current_channel, band), x, y, hop_col);
    }

    // Filter status (compact)
    if (!filter.is_empty()) {
        SDL_Color fc{255, 255, 0, 255};
        if (filter.handshake_clients_only) draw_text("C:hs-only",    x, y, fc);
        if (filter.probe_only)             draw_text("C:probe-only", x, y, fc);
        if (filter.active_only)            draw_text("F:active",     x, y, fc);
        if (filter.randomized_only)        draw_text("F:rand",       x, y, fc);
    }

    // Stats
    SDL_Color stat_col{200, 200, 200, 255};
    int client_count = 0, ap_count = 0, ssid_count = 0;
    for (auto& [id, n] : graph.nodes()) {
        if (n.type == NodeType::Client) ++client_count;
        else if (n.type == NodeType::AP) ++ap_count;
        else if (n.type == NodeType::SSID) ++ssid_count;
    }
    draw_text(std::format("C:{} A:{} S:{}", client_count, ap_count, ssid_count), x, y, stat_col);
    draw_text(std::format("F:{} B:{} P:{}", total_frames, beacons, probe_reqs), x, y, stat_col);

    draw_separator(x, y, sw); y += 4;

    int line_h = font_ ? TTF_FontHeight(font_) : 14;
    int box_h  = line_h + 10;  // text height + padding

    if (search_mode) {
        // Search overlay replaces node info
        SDL_Rect box{x, y, w - 8, box_h};
        SDL_SetRenderDrawColor(renderer_, 40, 35, 15, 255);
        SDL_RenderFillRect(renderer_, &box);
        SDL_SetRenderDrawColor(renderer_, 255, 220, 60, 255);
        SDL_RenderDrawRect(renderer_, &box);
        int ty = y + 5;
        bool show_cursor = (SDL_GetTicks() % 1000) < 500;
        std::string display = "/ " + filter.search_query + (show_cursor ? "_" : " ");
        draw_text(display, x + 4, ty, {255, 220, 60, 255});
    } else if (alias_mode && alias_target == selected && selected != 0) {
        // Alias overlay replaces node info
        SDL_Rect box{x, y, w - 8, box_h};
        SDL_SetRenderDrawColor(renderer_, 30, 30, 50, 255);
        SDL_RenderFillRect(renderer_, &box);
        SDL_SetRenderDrawColor(renderer_, 100, 160, 255, 255);
        SDL_RenderDrawRect(renderer_, &box);
        int ty = y + 5;
        bool show_cursor = (SDL_GetTicks() % 1000) < 500;
        std::string display = "Alias:[" + alias_buf + (show_cursor ? "_" : " ") + "]";
        draw_text(display, x + 4, ty, {220, 220, 255, 255});
    } else {
        // Scrollable node detail area — clip to below the fixed header
        int content_top = y;
        SDL_Rect content_clip{sidebar_x, content_top, w, h - content_top};
        SDL_RenderSetClipRect(renderer_, &content_clip);

        // Apply scroll offset
        y = content_top - scroll_px_;

        if (selected == 0) {
            render_empty(x, y);
        } else {
            const Node* n = graph.get_node(selected);
            if (!n) {
                render_empty(x, y);
            } else {
                switch (n->type) {
                    case NodeType::Client:   render_client(*n, graph, x, y); break;
                    case NodeType::SSID:     render_ssid(*n, graph, x, y);   break;
                    case NodeType::AP:       render_ap(*n, graph, x, y);     break;
                    default: render_empty(x, y); break;
                }
            }
        }

        // Scroll indicator: small arrow at bottom if content overflows
        if (y > h) {
            SDL_Color arr{200, 200, 200, 255};
            int ay = h - line_h - 2;
            draw_text("v", x, ay, arr);
        }
        if (scroll_px_ > 0) {
            SDL_Color arr{200, 200, 200, 255};
            draw_text("^", x, content_top, arr);
        }
    }

    SDL_RenderSetClipRect(renderer_, nullptr);
}
