#include "graph_view.hpp"
#include <cmath>
#include <algorithm>
#include <string>
#include <format>
#include <cctype>
#include <chrono>

// Regular (non-ghost) SSID nodes are hidden — the AP label carries the SSID name.
// Clients belonging to collapsed AP groups are also hidden.
bool GraphView::is_visible_node(const Node& n) const {
    if (n.type == NodeType::SSID && !n.is_ghost) return false;
    if (n.type == NodeType::Client && collapsed_clients_cache_.count(n.id)) return false;
    return true;
}

void GraphView::toggle_ap_collapse(NodeId ap_id) {
    if (collapsed_aps_.count(ap_id))
        collapsed_aps_.erase(ap_id);
    else
        collapsed_aps_.insert(ap_id);
}

bool GraphView::init(SDL_Renderer* renderer, TTF_Font* font) {
    renderer_ = renderer;
    font_ = font;
    return renderer_ != nullptr;
}

void GraphView::set_viewport(int x, int y, int w, int h) {
    vp_x_ = x; vp_y_ = y; vp_w_ = w; vp_h_ = h;
}

SDL_FPoint GraphView::world_to_screen(float wx, float wy) const {
    return {
        (wx + pan_x_) * scale_ + vp_x_,
        (wy + pan_y_) * scale_ + vp_y_
    };
}

SDL_FPoint GraphView::screen_to_world(float sx, float sy) const {
    return {
        (sx - vp_x_) / scale_ - pan_x_,
        (sy - vp_y_) / scale_ - pan_y_
    };
}

float GraphView::node_radius(const Node& n) const {
    // Scale radius to viewport: smaller screen → smaller nodes.
    // On Beepy 240px: base≈2px range≈5px → radius 2-7px
    // On desktop 1080px: base≈8px range≈22px → radius 8-30px
    float ref  = static_cast<float>(std::min(vp_w_, vp_h_));
    float base = ref * 0.018f;
    float span = ref * 0.022f;
    float t    = std::clamp((static_cast<float>(n.last_rssi) + 100.0f) / 80.0f, 0.0f, 1.0f);
    return (base + t * span) * scale_;
}

SDL_Color GraphView::node_color(const Node& n, bool active_boost, uint8_t alpha_override) const {
    // 8-color Memory LCD palette: {0,0,0} {255,255,255} {255,0,0} {0,255,0}
    //   {0,0,255} {0,255,255} {255,0,255} {255,255,0}
    // Inactive nodes rendered at half-alpha so they remain distinguishable but dimmer.
    uint8_t a = (active_boost && !n.is_active) ? static_cast<uint8_t>(alpha_override / 3)
                                                : alpha_override;
    switch (n.type) {
        case NodeType::Client:  return {  0,   0, 255, a};  // blue
        case NodeType::AP:      return {255,   0,   0, a};  // red
        case NodeType::SSID:
            if (n.is_ghost)     return {255,   0, 255, a};  // magenta
            return              {  0, 255,   0, a};          // green
        case NodeType::Location:return {255, 255,   0, a};  // yellow
    }
    return {255, 255, 255, alpha_override};
}

// Bresenham filled circle using horizontal scan lines
void GraphView::draw_circle_filled(int cx, int cy, int r, SDL_Color col) {
    if (!renderer_) return;
    SDL_SetRenderDrawColor(renderer_, col.r, col.g, col.b, col.a);
    for (int y = -r; y <= r; ++y) {
        int half_w = static_cast<int>(std::sqrt(static_cast<float>(r * r - y * y)));
        SDL_RenderDrawLine(renderer_, cx - half_w, cy + y, cx + half_w, cy + y);
    }
}

void GraphView::draw_circle_outline(int cx, int cy, int r, SDL_Color col) {
    if (!renderer_) return;
    SDL_SetRenderDrawColor(renderer_, col.r, col.g, col.b, col.a);
    // Midpoint circle algorithm
    int x = r, y = 0;
    int err = 0;
    while (x >= y) {
        SDL_RenderDrawPoint(renderer_, cx + x, cy + y);
        SDL_RenderDrawPoint(renderer_, cx + y, cy + x);
        SDL_RenderDrawPoint(renderer_, cx - y, cy + x);
        SDL_RenderDrawPoint(renderer_, cx - x, cy + y);
        SDL_RenderDrawPoint(renderer_, cx - x, cy - y);
        SDL_RenderDrawPoint(renderer_, cx - y, cy - x);
        SDL_RenderDrawPoint(renderer_, cx + y, cy - x);
        SDL_RenderDrawPoint(renderer_, cx + x, cy - y);
        y++;
        if (err <= 0) {
            err += 2 * y + 1;
        } else {
            x--;
            err += 2 * (y - x) + 1;
        }
    }
}

void GraphView::draw_node(const Node& n, bool sel, bool hov, uint8_t alpha) {
    SDL_FPoint sp = world_to_screen(n.x, n.y);
    int cx = static_cast<int>(sp.x);
    int cy = static_cast<int>(sp.y);
    int r  = static_cast<int>(node_radius(n));

    SDL_Color col = node_color(n, true, alpha);
    if (n.type == NodeType::SSID && n.is_ghost) {
        // Ghost SSID: hollow circle (outline only) — no AP in range
        SDL_Color ghost_col = {0, 255, 0, alpha};
        draw_circle_outline(cx, cy, r,     ghost_col);
        draw_circle_outline(cx, cy, r - 1, ghost_col);
    } else {
        draw_circle_filled(cx, cy, r, col);
        // Inactive AP: draw a solid outline (no alpha) so it's visible on Memory LCD
        if (n.type == NodeType::AP && !n.is_active) {
            SDL_Color outline_col = {col.r, col.g, col.b, 255};
            draw_circle_outline(cx, cy, r,     outline_col);
            draw_circle_outline(cx, cy, r - 1, outline_col);
        }
    }

    // Purple ring for clients seen at multiple APs (roaming / multi-network)
    if (n.type == NodeType::Client && n.assoc_ap_count > 1) {
        uint8_t ma = static_cast<uint8_t>(180 * alpha / 255);
        draw_circle_outline(cx, cy, r + 7, {180, 0, 255, ma});
        draw_circle_outline(cx, cy, r + 8, {180, 0, 255, static_cast<uint8_t>(ma / 2)});
    }

    // Cyan ring for clients that contributed a handshake
    if (n.type == NodeType::Client && n.has_handshake) {
        uint8_t ha = static_cast<uint8_t>(200 * alpha / 255);
        draw_circle_outline(cx, cy, r + 2, {0, 220, 220, ha});
        draw_circle_outline(cx, cy, r + 3, {0, 220, 220, static_cast<uint8_t>(ha / 2)});
    }

    // Gold ring for stationary (regularly-present) devices
    if (n.is_stationary) {
        uint8_t ga = static_cast<uint8_t>(160 * alpha / 255);
        draw_circle_outline(cx, cy, r + 5, {220, 180, 40, ga});
        draw_circle_outline(cx, cy, r + 6, {220, 180, 40, static_cast<uint8_t>(ga / 2)});
    }

    if (sel) {
        draw_circle_outline(cx, cy, r + 3, {255, 255, 255, alpha});
        draw_circle_outline(cx, cy, r + 4, {255, 255, 255, static_cast<uint8_t>(alpha * 200 / 255)});
    } else if (hov) {
        draw_circle_outline(cx, cy, r + 2, {200, 200, 200, static_cast<uint8_t>(alpha * 200 / 255)});
    }

    // Orange ring for nodes with detected anomalies
    if (n.anomaly_count > 0) {
        uint8_t oa = static_cast<uint8_t>(200 * alpha / 255);
        bool blink = (SDL_GetTicks() / 400) % 2 == 0;
        uint8_t ob = blink ? oa : static_cast<uint8_t>(oa / 2);
        draw_circle_outline(cx, cy, r + 10, {255, 140, 0, ob});
        draw_circle_outline(cx, cy, r + 11, {255, 140, 0, static_cast<uint8_t>(ob / 2)});
    }

    // Red X for APs where crack exhausted wordlist and no password found
    if (n.type == NodeType::AP && n.crack_not_found && n.passwords.empty()) {
        SDL_Color xc{255, 60, 60, alpha};
        int d = r - 1;
        SDL_SetRenderDrawColor(renderer_, xc.r, xc.g, xc.b, xc.a);
        SDL_RenderDrawLine(renderer_, cx - d, cy - d, cx + d, cy + d);
        SDL_RenderDrawLine(renderer_, cx - d, cy - d + 1, cx + d - 1, cy + d);
        SDL_RenderDrawLine(renderer_, cx - d + 1, cy - d, cx + d, cy + d - 1);
        SDL_RenderDrawLine(renderer_, cx + d, cy - d, cx - d, cy + d);
        SDL_RenderDrawLine(renderer_, cx + d - 1, cy - d, cx - d, cy + d - 1);
        SDL_RenderDrawLine(renderer_, cx + d, cy - d + 1, cx - d + 1, cy + d);
    }
}

void GraphView::draw_label(const Node& n, const Graph& graph, uint8_t alpha) {
    if (!font_) return;
    // Default mode: show AP labels (SSID name) and ghost-SSID labels.
    // Full mode (labels_full_): show all labels including Client MACs.
    bool is_ghost_ssid = (n.type == NodeType::SSID && n.is_ghost);
    if (!labels_full_ && n.type != NodeType::AP && !is_ghost_ssid) return;

    // For APs: prefer alias, then the SSID name from the connected SSID node,
    // then fall back to BSSID string.
    std::string resolved;
    if (!n.alias.empty()) {
        resolved = n.alias;
    } else if (n.type == NodeType::AP && n.ssid_id != 0) {
        const Node* ssid_node = graph.get_node(n.ssid_id);
        resolved = (ssid_node && !ssid_node->label.empty()) ? ssid_node->label : n.label;
    } else {
        resolved = n.label;
    }
    if (resolved.empty()) return;
    const std::string& lbl = resolved;

    // Truncate long labels — keep short for small screens
    std::string txt = lbl;
    if (txt.size() > 12) txt = txt.substr(0, 10) + "..";

    SDL_FPoint sp = world_to_screen(n.x, n.y);
    int r = static_cast<int>(node_radius(n));

    SDL_Color col = {255, 255, 255, alpha};
    SDL_Surface* surf = TTF_RenderUTF8_Blended(font_, txt.c_str(), col);
    if (!surf) return;
    SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer_, surf);
    SDL_FreeSurface(surf);
    if (!tex) return;

    SDL_SetTextureAlphaMod(tex, alpha);
    int tw, th;
    SDL_QueryTexture(tex, nullptr, nullptr, &tw, &th);
    SDL_Rect dst{static_cast<int>(sp.x) - tw / 2,
                 static_cast<int>(sp.y) + r + 2,
                 tw, th};
    SDL_RenderCopy(renderer_, tex, nullptr, &dst);
    SDL_DestroyTexture(tex);
}

void GraphView::draw_edge(const Edge& e, const Graph& graph, uint8_t alpha) {
    const Node* na = graph.get_node(e.a);
    const Node* nb = graph.get_node(e.b);
    if (!na || !nb) return;

    SDL_FPoint pa = world_to_screen(na->x, na->y);
    SDL_FPoint pb = world_to_screen(nb->x, nb->y);

    // Edge colors from 8-color Memory LCD palette
    SDL_Color col;
    switch (e.type) {
        case EdgeType::ProbesFor:         col = {  0,   0, 255, alpha}; break;  // blue
        case EdgeType::Broadcasts:        col = {255,   0,   0, alpha}; break;  // red
        case EdgeType::SeenNear: {
            const Node* na = graph.get_node(e.a);
            const Node* nb = graph.get_node(e.b);
            if (na && nb && na->type == NodeType::AP && nb->type == NodeType::AP)
                col = {0, 255, 255, alpha};   // cyan — AP-AP co-location
            else
                col = {255, 255, 255, static_cast<uint8_t>(alpha / 2)};  // white dim
            break;
        }
        case EdgeType::SimilarTo:         col = {255,   0, 255, alpha}; break;  // magenta
        case EdgeType::AssociatedWith:    col = {  0, 255,   0, alpha}; break;  // green
        case EdgeType::FingerprintMatch:  col = {255, 255,   0, alpha}; break;  // yellow
        default:                          col = {255, 255, 255, static_cast<uint8_t>(alpha / 3)}; break;
    }

    SDL_SetRenderDrawColor(renderer_, col.r, col.g, col.b, col.a);
    SDL_RenderDrawLine(renderer_,
        static_cast<int>(pa.x), static_cast<int>(pa.y),
        static_cast<int>(pb.x), static_cast<int>(pb.y));

    // For heavier edges draw extra parallel lines
    int thickness = static_cast<int>(std::clamp(e.weight, 1.0f, 4.0f));
    for (int t = 1; t < thickness; ++t) {
        SDL_RenderDrawLine(renderer_,
            static_cast<int>(pa.x) + t, static_cast<int>(pa.y),
            static_cast<int>(pb.x) + t, static_cast<int>(pb.y));
    }
}

NodeId GraphView::node_at(const Graph& graph, int sx, int sy) const {
    NodeId best = 0;
    float best_dist = 1e9f;
    for (auto& [id, n] : graph.nodes()) {
        if (!is_visible_node(n)) continue;
        SDL_FPoint sp = world_to_screen(n.x, n.y);
        float r = node_radius(n);
        float dx = sp.x - sx, dy = sp.y - sy;
        float dist = std::sqrt(dx * dx + dy * dy);
        if (dist <= r && dist < best_dist) {
            best_dist = dist;
            best = id;
        }
    }
    return best;
}

bool GraphView::node_matches_filter(const Node& n, const Graph& graph) const {
    // Force-show active clients of the focused AP (set built once per render)
    if (focus_clients_cache_.count(n.id)) return true;

    if (filter_.is_empty()) return true;

    // handshake_clients_only: hide Client nodes without a captured handshake;
    // also hide edges between hidden clients (handled via alpha in render)
    if (filter_.handshake_clients_only && n.type == NodeType::Client && !n.has_handshake)
        return false;

    // active_only: non-SSID nodes must be active; SSIDs always pass
    if (filter_.active_only) {
        if (n.type != NodeType::SSID) {
            if (!n.is_active) {
                // Check if connected to an active node
                bool connected_active = false;
                for (auto& e : graph.edges()) {
                    NodeId other = 0;
                    if (e.a == n.id) other = e.b;
                    else if (e.b == n.id) other = e.a;
                    else continue;
                    const Node* on = graph.get_node(other);
                    if (on && on->is_active) { connected_active = true; break; }
                }
                if (!connected_active) return false;
            }
        }
    }

    // randomized_only: only Client nodes with is_randomized pass; non-Client always pass
    if (filter_.randomized_only) {
        if (n.type == NodeType::Client && !n.is_randomized) return false;
    }

    // probe_only: show only Client nodes with no AssociatedWith edges (pure probers)
    if (filter_.probe_only && n.type == NodeType::Client) {
        bool has_assoc = false;
        for (auto& e : graph.edges()) {
            if (e.type != EdgeType::AssociatedWith) continue;
            if (e.a == n.id || e.b == n.id) { has_assoc = true; break; }
        }
        if (has_assoc) return false;
    }

    // ssid_filter: case-insensitive substring match
    if (!filter_.ssid_filter.empty()) {
        // Convert filter to lowercase for comparison
        std::string filt_lower = filter_.ssid_filter;
        std::transform(filt_lower.begin(), filt_lower.end(), filt_lower.begin(),
                       [](unsigned char c){ return std::tolower(c); });

        if (n.type == NodeType::SSID) {
            std::string label_lower = n.label;
            std::transform(label_lower.begin(), label_lower.end(), label_lower.begin(),
                           [](unsigned char c){ return std::tolower(c); });
            if (label_lower.find(filt_lower) == std::string::npos) return false;
        } else if (n.type == NodeType::Client || n.type == NodeType::AP) {
            // Must have edge to a matching SSID
            bool found = false;
            for (auto& e : graph.edges()) {
                NodeId ssid_id = 0;
                if (n.type == NodeType::Client && e.type == EdgeType::ProbesFor && e.a == n.id)
                    ssid_id = e.b;
                else if (n.type == NodeType::AP && e.type == EdgeType::Broadcasts && e.a == n.id)
                    ssid_id = e.b;
                if (ssid_id == 0) continue;
                const Node* sn = graph.get_node(ssid_id);
                if (!sn) continue;
                std::string slabel_lower = sn->label;
                std::transform(slabel_lower.begin(), slabel_lower.end(), slabel_lower.begin(),
                               [](unsigned char c){ return std::tolower(c); });
                if (slabel_lower.find(filt_lower) != std::string::npos) { found = true; break; }
            }
            if (!found) return false;
        }
        // Location nodes always pass ssid_filter
    }

    // vendor_filter: case-insensitive substring match; non-Client/AP always pass
    if (!filter_.vendor_filter.empty()) {
        if (n.type == NodeType::Client || n.type == NodeType::AP) {
            std::string vfilt_lower = filter_.vendor_filter;
            std::transform(vfilt_lower.begin(), vfilt_lower.end(), vfilt_lower.begin(),
                           [](unsigned char c){ return std::tolower(c); });
            std::string vendor_lower = n.vendor;
            std::transform(vendor_lower.begin(), vendor_lower.end(), vendor_lower.begin(),
                           [](unsigned char c){ return std::tolower(c); });
            if (vendor_lower.find(vfilt_lower) == std::string::npos) return false;
        }
    }

    // search_query: substring match on label, alias, or vendor (case-insensitive)
    if (!filter_.search_query.empty()) {
        auto ci_contains = [](const std::string& hay, const std::string& needle) {
            if (needle.empty()) return true;
            std::string h = hay, nd = needle;
            std::transform(h.begin(),  h.end(),  h.begin(),  [](unsigned char c){ return std::tolower(c); });
            std::transform(nd.begin(), nd.end(), nd.begin(), [](unsigned char c){ return std::tolower(c); });
            return h.find(nd) != std::string::npos;
        };
        bool match = ci_contains(n.label, filter_.search_query)
                  || ci_contains(n.alias, filter_.search_query)
                  || ci_contains(n.vendor, filter_.search_query);
        if (!match) return false;
    }

    return true;
}

void GraphView::render(const Graph& graph, int /*viewport_w*/, int /*viewport_h*/) {
    if (!renderer_) return;

    // Update drag-start pulse (one-frame signal for App to call init_drag_pos)
    drag_started_this_frame_ = (dragging_ && !prev_dragging_);
    prev_dragging_ = dragging_;

    // Resolve pending click: update selection now that we have graph access
    if (pending_click_) {
        pending_click_ = false;
        NodeId clicked = node_at(graph, pending_click_x_, pending_click_y_);
        selected_ = clicked; // deselect if click on empty space (clicked == 0)
    }

    // Rebuild per-frame caches in a single edge pass
    collapsed_clients_cache_.clear();
    focus_clients_cache_.clear();
    for (auto& e : graph.edges()) {
        if (e.type != EdgeType::AssociatedWith) continue;
        // Collapsed AP cache
        for (NodeId ap_id : collapsed_aps_) {
            NodeId cid = 0;
            if (e.a == ap_id) cid = e.b;
            else if (e.b == ap_id) cid = e.a;
            if (!cid) continue;
            const Node* cn = graph.get_node(cid);
            if (cn && cn->type == NodeType::Client) collapsed_clients_cache_.insert(cid);
        }
        // Focus AP cache: active clients of selected AP
        if (ap_focus_id_ != 0) {
            NodeId cid = 0;
            if (e.a == ap_focus_id_) cid = e.b;
            else if (e.b == ap_focus_id_) cid = e.a;
            if (cid) {
                const Node* cn = graph.get_node(cid);
                if (cn && cn->type == NodeType::Client && cn->is_active)
                    focus_clients_cache_.insert(cid);
            }
        }
    }

    // Set clip rect to viewport
    SDL_Rect clip{vp_x_, vp_y_, vp_w_, vp_h_};
    SDL_RenderSetClipRect(renderer_, &clip);

    // Background: black (Memory LCD palette)
    SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 255);
    SDL_RenderFillRect(renderer_, &clip);

    // Build ssid_id → ap_id map from Broadcasts edges (AP broadcasts SSID).
    // Used to redirect ProbesFor edges: Client→hidden_SSID becomes Client→AP.
    // Built from edges (not n.ssid_id) so ALL ever-seen SSIDs per AP are covered.
    std::unordered_map<NodeId, NodeId> ssid_to_ap;
    for (auto& e : graph.edges()) {
        if (e.type != EdgeType::Broadcasts) continue;
        const Node* ap_node = graph.get_node(e.a);
        const Node* ss_node = graph.get_node(e.b);
        if (!ap_node || !ss_node) continue;
        if (ap_node->type == NodeType::AP && !is_visible_node(*ss_node))
            ssid_to_ap[e.b] = e.a;   // hidden SSID → AP that broadcasts it
    }

    // Draw edges first
    SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_BLEND);
    for (auto& e : graph.edges()) {
        const Node* na = graph.get_node(e.a);
        const Node* nb = graph.get_node(e.b);
        if (!na || !nb) continue;

        // ProbesFor (Client → SSID): if SSID is hidden, draw the line to its AP instead.
        // This preserves the Client↔AP relationship after SSID nodes were removed.
        if (e.type == EdgeType::ProbesFor) {
            const Node* client = na;
            const Node* ssid   = nb;
            // Determine which of e.a/e.b is the SSID (could be either side in theory)
            if (client->type == NodeType::SSID) std::swap(client, ssid);
            if (!is_visible_node(*ssid)) {
                // SSID is hidden — find AP via Broadcasts map
                auto it = ssid_to_ap.find(ssid->id);
                if (it == ssid_to_ap.end()) continue;
                const Node* ap_node = graph.get_node(it->second);
                if (!ap_node || !is_visible_node(*ap_node)) continue;

                bool mc = node_matches_filter(*client, graph);
                bool ma = node_matches_filter(*ap_node, graph);
                if (!mc && filter_.handshake_clients_only) continue;
                uint8_t alpha = (mc && ma) ? 255 : 255 / 6;

                SDL_SetRenderDrawColor(renderer_, 0, 0, 255, alpha);
                SDL_FPoint pc = world_to_screen(client->x, client->y);
                SDL_FPoint pa = world_to_screen(ap_node->x, ap_node->y);
                SDL_RenderDrawLine(renderer_,
                    static_cast<int>(pc.x), static_cast<int>(pc.y),
                    static_cast<int>(pa.x), static_cast<int>(pa.y));
            }
            // Ghost (visible) SSID: fall through to normal draw_edge below
            else {
                if (!is_visible_node(*na) || !is_visible_node(*nb)) continue;
                bool ma = node_matches_filter(*na, graph);
                bool mb = node_matches_filter(*nb, graph);
                uint8_t alpha = (ma && mb) ? 255
                              : filter_.handshake_clients_only ? 0 : 255 / 6;
                if (alpha > 0) draw_edge(e, graph, alpha);
            }
            continue;
        }

        // Skip edges to/from hidden nodes (non-ghost SSIDs)
        if (!is_visible_node(*na) || !is_visible_node(*nb)) continue;

        bool ma = node_matches_filter(*na, graph);
        bool mb = node_matches_filter(*nb, graph);
        uint8_t edge_alpha;
        if (ma && mb) {
            edge_alpha = 255;
        } else if (filter_.handshake_clients_only) {
            continue;  // hide edges involving filtered-out clients entirely
        } else {
            edge_alpha = 255 / 6;
        }
        draw_edge(e, graph, edge_alpha);
    }

    // Draw nodes
    for (auto& [id, n] : graph.nodes()) {
        if (!is_visible_node(n)) continue;
        bool matches = node_matches_filter(n, graph);
        // When handshake filter is on: completely hide non-handshake clients
        if (!matches && filter_.handshake_clients_only && n.type == NodeType::Client)
            continue;
        uint8_t alpha = matches ? 255 : 40;
        draw_node(n, id == selected_, id == hovered_, alpha);
    }

    // Draw labels (on top)
    for (auto& [id, n] : graph.nodes()) {
        if (!is_visible_node(n)) continue;
        uint8_t alpha = node_matches_filter(n, graph) ? 255 : 40;
        draw_label(n, graph, alpha);
    }

    // AP list overlay (takes over the whole graph view)
    if (show_ap_list_) {
        draw_ap_list(graph);
        return;
    }

    // Crack list overlay
    if (show_crack_list_) {
        draw_crack_list();
        return;
    }

    // Handshake list overlay
    if (show_hs_list_) {
        draw_hs_list();
        return;
    }

    // Anomaly log overlay
    if (show_anomaly_log_) {
        draw_anomaly_log();
        return;
    }

    // Aggressive mode indicator — top-left, red/orange (blinks)
    if (font_ && crack_info_.aggressive) {
        bool blink_on = (SDL_GetTicks() / 500) % 2 == 0;
        SDL_Color acol = blink_on ? SDL_Color{255, 80, 0, 255} : SDL_Color{180, 40, 0, 255};
        std::string agg_trunc = crack_info_.aggr_target.size() > 10
            ? crack_info_.aggr_target.substr(0, 9) + "~" : crack_info_.aggr_target;
        std::string agg_txt = agg_trunc.empty()
            ? "AGG:ON" : std::format("AGG>{}", agg_trunc);
        SDL_Surface* as = TTF_RenderUTF8_Blended(font_, agg_txt.c_str(), acol);
        if (as) {
            SDL_Texture* at = SDL_CreateTextureFromSurface(renderer_, as);
            int tw = as->w, th = as->h;
            SDL_FreeSurface(as);
            if (at) {
                SDL_Rect dst{vp_x_ + 4, vp_y_ + 4, tw, th};
                SDL_RenderCopy(renderer_, at, nullptr, &dst);
                SDL_DestroyTexture(at);
            }
        }
    }

    // Active cracking status — below AGG indicator (or top-left if AGG off), yellow
    int crk_y_offset = (crack_info_.aggressive && font_) ? TTF_FontHeight(font_) + 6 : 4;
    if (font_ && !crack_info_.ssid.empty()) {
        std::string ssid_trunc = crack_info_.ssid.size() > 10
            ? crack_info_.ssid.substr(0, 9) + "~" : crack_info_.ssid;
        std::string crk_txt = crack_info_.speed_kps > 0
            ? std::format("Crk:{} {} {}k/s", ssid_trunc, crack_info_.engine_label, crack_info_.speed_kps)
            : std::format("Crk:{} {}", ssid_trunc, crack_info_.engine_label);
        SDL_Surface* cs = TTF_RenderUTF8_Blended(font_, crk_txt.c_str(), {255, 255, 0, 255});
        if (cs) {
            SDL_Texture* ct = SDL_CreateTextureFromSurface(renderer_, cs);
            int tw = cs->w, th = cs->h;
            SDL_FreeSurface(cs);
            if (ct) {
                SDL_Rect dst{vp_x_ + 4, vp_y_ + crk_y_offset, tw, th};
                SDL_RenderCopy(renderer_, ct, nullptr, &dst);
                SDL_DestroyTexture(ct);
            }
        }
    }

    // Cracked password counter — top-right, green
    if (font_ && pw_count_ > 0) {
        std::string pw_txt = std::format("PW:{}", pw_count_);
        SDL_Surface* ps = TTF_RenderUTF8_Blended(font_, pw_txt.c_str(), {0, 255, 0, 255});
        if (ps) {
            SDL_Texture* pt = SDL_CreateTextureFromSurface(renderer_, ps);
            int tw = ps->w, th = ps->h;
            SDL_FreeSurface(ps);
            if (pt) {
                SDL_Rect dst{vp_x_ + vp_w_ - tw - 4, vp_y_ + 4, tw, th};
                SDL_RenderCopy(renderer_, pt, nullptr, &dst);
                SDL_DestroyTexture(pt);
            }
        }
    }

    // Help: always show "?=help" hint at bottom-left; full overlay on show_help_
    if (font_) {
        auto draw_line = [&](const char* txt, int x, int y, SDL_Color col) {
            SDL_Surface* s = TTF_RenderUTF8_Blended(font_, txt, col);
            if (!s) return;
            SDL_Texture* t = SDL_CreateTextureFromSurface(renderer_, s);
            int tw = s->w, th = s->h;
            SDL_FreeSurface(s);
            if (!t) return;
            SDL_Rect dst{x, y, tw, th};
            SDL_RenderCopy(renderer_, t, nullptr, &dst);
            SDL_DestroyTexture(t);
        };

        int lh = TTF_FontHeight(font_);

        if (show_help_) {
            // Semi-transparent dark background covering the graph area
            SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_BLEND);
            SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 220);
            SDL_RenderFillRect(renderer_, &clip);

            // Single-column help, scrollable with Space
            // Prefix chars:
            //   '=' header (cyan)
            //   '-' separator line
            //   ' ' normal white line
            //   '~' colored legend line: second char = R/G/O/Y/P/C/M/W
            static const char* HELP[] = {
                "=KEYBOARD",
                " z / x      zoom in / out",
                " arrows     pan view",
                " 0          fit all nodes",
                " h          channel hop on/off",
                " + / -      hop dwell +/- 50ms",
                " l          labels toggle",
                " Tab        cycle nodes",
                " Esc        deselect",
                "-",
                " p          AP list overlay",
                " k          crack queue overlay",
                " j          handshake list",
                " w          anomaly log",
                " i          help toggle",
                " [space]    next page",
                "-",
                " d          deauth selected AP",
                " g          aggressive mode",
                "            (cyclic deauth harvest)",
                " Ctrl+R     reset WiFi interface",
                "-",
                " f          filter: active only",
                " r          filter: rand MAC only",
                " o          filter: probe-only",
                " c          collapse AP group",
                " a          set alias",
                " e          export JSON",
                " /          search",
                " q          quit",
                "-",
                "=NODE COLORS",
                "~W o  White   — client device",
                "~Y o  Yellow  — access point (AP)",
                "~G o  Green   — known SSID",
                "~M o  Magenta — ghost SSID (no AP)",
                "-",
                "=RING COLORS",
                "~C ~  Cyan    — client has WPA handshake",
                "~O ~  Orange  — anomaly detected",
                "~P ~  Purple  — client at 2+ APs (roaming)",
                "~A ~  Gold    — stationary device",
                "~B ~  White   — selected node",
                "-",
                "=AP MARKERS",
                "~G [pw]       — password cracked",
                "~R [not found]— wordlist exhausted",
                "~R X          — crack failed (on node)",
                "-",
                "=ANOMALY TYPES  (w key)",
                "~R DeauthFlood — >10 deauth in 5s",
                "~Y ProbeFlood  — >50 probes in 10s",
                "~Y AuthFlood   — >20 auth in 30s",
                "~R EvilTwin    — same SSID diff BSSID+sec",
                "~Y UnexpDeauth — deauth to active client",
                "-",
                "=SIDEBAR",
                " HOP ch:N     channel hopping active",
                " LOCK ch:N    channel locked",
                " APs(N)       associated access points",
                " Probed(N)    probed SSIDs",
                " Anomalies:N  anomaly event count",
                " PW:xxx       cracked password",
                " PW: not found crack exhausted wordlist",
                " Rnd:y/n      randomized MAC",
                " Act:y/n      active in last 5 min",
                nullptr
            };

            int total = 0;
            for (int i = 0; HELP[i]; ++i) ++total;

            int visible = (vp_h_ - 16) / (lh + 2);
            if (help_scroll_ >= total) help_scroll_ = 0;

            SDL_Color white  {255, 255, 255, 255};
            SDL_Color cyan_c {  0, 255, 255, 255};
            SDL_Color dim    {120, 120, 120, 255};

            // Color table for '~X' legend lines
            auto legend_color = [](char code) -> SDL_Color {
                switch (code) {
                    case 'R': return {255,  60,  60, 255};   // red
                    case 'G': return {  0, 255,  80, 255};   // green
                    case 'O': return {255, 140,   0, 255};   // orange
                    case 'Y': return {255, 220,  40, 255};   // yellow
                    case 'P': return {180,   0, 255, 255};   // purple
                    case 'C': return {  0, 220, 220, 255};   // cyan
                    case 'M': return {255,   0, 200, 255};   // magenta
                    case 'A': return {220, 180,  40, 255};   // gold
                    case 'B': return {255, 255, 255, 255};   // white
                    default:  return {200, 200, 200, 255};
                }
            };

            int y = vp_y_ + 8;
            int shown = 0;
            for (int i = help_scroll_; HELP[i] && shown < visible; ++i, ++shown) {
                const char* line = HELP[i];
                char kind = line[0];
                if (kind == '=') {
                    draw_line(line + 1, vp_x_ + 4, y, cyan_c);
                } else if (kind == '-') {
                    SDL_SetRenderDrawColor(renderer_, dim.r, dim.g, dim.b, dim.a);
                    SDL_RenderDrawLine(renderer_, vp_x_ + 4, y + lh/2,
                                       vp_x_ + vp_w_ - 4, y + lh/2);
                } else if (kind == '~' && line[1] != '\0') {
                    // Colored legend line: ~X text
                    SDL_Color col = legend_color(line[1]);
                    draw_line(line + 2, vp_x_ + 8, y, col);
                } else {
                    draw_line(line + 1, vp_x_ + 8, y, white);
                }
                y += lh + 2;
            }

            // Page indicator bottom-right
            int page = help_scroll_ / std::max(1, visible) + 1;
            int pages = (total + visible - 1) / std::max(1, visible);
            std::string pg = std::format("{}/{}", page, pages);
            draw_line(pg.c_str(), vp_x_ + vp_w_ - static_cast<int>(pg.size()) * (lh/2) - 4,
                      vp_y_ + vp_h_ - lh - 4, {180, 180, 180, 255});
        } else {
            // Notifications stack above the hint line (newest at bottom)
            if (font_ && !notifications_.empty()) {
                int ny = vp_y_ + vp_h_ - lh - 2 - static_cast<int>(notifications_.size()) * (lh + 2);
                for (auto& notif : notifications_) {
                    SDL_Surface* ns = TTF_RenderUTF8_Blended(font_, notif.text.c_str(), notif.color);
                    if (ns) {
                        SDL_Texture* nt = SDL_CreateTextureFromSurface(renderer_, ns);
                        int tw = ns->w, th = ns->h;
                        SDL_FreeSurface(ns);
                        if (nt) {
                            // Dark background behind text for readability
                            SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_BLEND);
                            SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 180);
                            SDL_Rect bg{vp_x_ + 2, ny - 1, tw + 4, th + 2};
                            SDL_RenderFillRect(renderer_, &bg);
                            SDL_Rect dst{vp_x_ + 4, ny, tw, th};
                            SDL_RenderCopy(renderer_, nt, nullptr, &dst);
                            SDL_DestroyTexture(nt);
                        }
                    }
                    ny += lh + 2;
                }
            }

            int hint_y = vp_y_ + vp_h_ - lh - 2;
            SDL_Color dim{200, 200, 200, 255};
            draw_line("i=help p=ap k=crk j=hs w=warn g=agg", vp_x_ + 4, hint_y, dim);

            // c=collapse/expand hint when an AP is focused
            if (ap_focus_id_ != 0) {
                bool collapsed = collapsed_aps_.count(ap_focus_id_) > 0;
                const char* ctxt = collapsed ? "c=expand" : "c=collapse";
                SDL_Color ccol = collapsed ? SDL_Color{0, 255, 255, 255}
                                           : SDL_Color{255, 255, 0, 255};
                SDL_Surface* cs = TTF_RenderUTF8_Blended(font_, ctxt, ccol);
                if (cs) {
                    SDL_Texture* ct = SDL_CreateTextureFromSurface(renderer_, cs);
                    int tw = cs->w, th = cs->h;
                    SDL_FreeSurface(cs);
                    if (ct) {
                        SDL_Rect dst{vp_x_ + vp_w_ / 2 - tw / 2, hint_y, tw, th};
                        SDL_RenderCopy(renderer_, ct, nullptr, &dst);
                        SDL_DestroyTexture(ct);
                    }
                }
            }

            if (can_deauth_) {
                SDL_Color dcol = deauth_flash_
                    ? SDL_Color{255, 0, 0, 255}
                    : SDL_Color{255, 255, 0, 255};
                const char* dtxt = deauth_flash_ ? "DEAUTH SENT!" : "d=deauth";
                SDL_Surface* ds = TTF_RenderUTF8_Blended(font_, dtxt, dcol);
                if (ds) {
                    SDL_Texture* dt = SDL_CreateTextureFromSurface(renderer_, ds);
                    int tw = ds->w, th = ds->h;
                    SDL_FreeSurface(ds);
                    if (dt) {
                        SDL_Rect dst{vp_x_ + vp_w_ - tw - 4, hint_y, tw, th};
                        SDL_RenderCopy(renderer_, dt, nullptr, &dst);
                        SDL_DestroyTexture(dt);
                    }
                }
            }
        }
    }

    // Search query overlay at bottom of viewport
    if (!filter_.search_query.empty() && font_) {
        bool show_cursor = (SDL_GetTicks() % 1000) < 500;
        std::string txt = std::string("/ ") + filter_.search_query + (show_cursor ? "_" : " ");
        SDL_Color col{255, 220, 60, 220};
        SDL_Surface* surf = TTF_RenderUTF8_Blended(font_, txt.c_str(), col);
        if (surf) {
            SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer_, surf);
            SDL_FreeSurface(surf);
            if (tex) {
                int tw, th;
                SDL_QueryTexture(tex, nullptr, nullptr, &tw, &th);
                SDL_Rect dst{vp_x_ + 8, vp_y_ + vp_h_ - th - 6, tw, th};
                SDL_RenderCopy(renderer_, tex, nullptr, &dst);
                SDL_DestroyTexture(tex);
            }
        }
    }

    SDL_RenderSetClipRect(renderer_, nullptr);
}

void GraphView::handle_event(const SDL_Event& e) {
    switch (e.type) {
    case SDL_MOUSEMOTION: {
        int mx = e.motion.x, my = e.motion.y;
        if (mx < vp_x_ || mx >= vp_x_ + vp_w_ || my < vp_y_ || my >= vp_y_ + vp_h_) break;

        if (dragging_ && selected_ != 0) {
            // Move selected node in world coords
            SDL_FPoint wp = screen_to_world(static_cast<float>(mx), static_cast<float>(my));
            // (App will update position via separate call if needed)
            // Store offset for app to read
            drag_offset_x_ = wp.x;
            drag_offset_y_ = wp.y;
        } else if (panning_) {
            int dx = mx - last_mouse_x_;
            int dy = my - last_mouse_y_;
            pan_x_ += static_cast<float>(dx) / scale_;
            pan_y_ += static_cast<float>(dy) / scale_;
        }
        last_mouse_x_ = mx;
        last_mouse_y_ = my;
        break;
    }
    case SDL_MOUSEBUTTONDOWN: {
        int mx = e.button.x, my = e.button.y;
        if (mx < vp_x_ || mx >= vp_x_ + vp_w_ || my < vp_y_ || my >= vp_y_ + vp_h_) break;
        last_mouse_x_ = mx;
        last_mouse_y_ = my;

        if (e.button.button == SDL_BUTTON_MIDDLE) {
            panning_ = true;
        } else if (e.button.button == SDL_BUTTON_LEFT) {
            if (!dragging_) {
                // Fresh drag start: invalidate position until App seeds it
                drag_valid_ = false;
            }
            dragging_ = true;
            press_x_ = mx;
            press_y_ = my;
        }
        break;
    }
    case SDL_MOUSEBUTTONUP: {
        if (e.button.button == SDL_BUTTON_MIDDLE) panning_ = false;
        if (e.button.button == SDL_BUTTON_LEFT) {
            dragging_ = false;
            // Distinguish click from drag: delta < 5px = click
            int dx = e.button.x - press_x_;
            int dy = e.button.y - press_y_;
            if (dx * dx + dy * dy < 25) {
                // Queue a click to be resolved in render() when we have graph access
                pending_click_ = true;
                pending_click_x_ = e.button.x;
                pending_click_y_ = e.button.y;
            }
        }
        break;
    }
    case SDL_MOUSEWHEEL: {
        int mx, my;
        SDL_GetMouseState(&mx, &my);
        if (mx < vp_x_ || mx >= vp_x_ + vp_w_ || my < vp_y_ || my >= vp_y_ + vp_h_) break;
        float zoom = (e.wheel.y > 0) ? 1.1f : 0.9f;
        // Zoom towards mouse position
        SDL_FPoint wp = screen_to_world(static_cast<float>(mx), static_cast<float>(my));
        scale_ *= zoom;
        scale_ = std::clamp(scale_, 0.1f, 10.0f);
        // Adjust pan so mouse position stays fixed
        SDL_FPoint wp2 = screen_to_world(static_cast<float>(mx), static_cast<float>(my));
        pan_x_ += wp2.x - wp.x;
        pan_y_ += wp2.y - wp.y;
        break;
    }
    default: break;
    }
}


void GraphView::zoom_center(float factor) {
    float cx = vp_x_ + vp_w_ * 0.5f;
    float cy = vp_y_ + vp_h_ * 0.5f;
    SDL_FPoint wp = screen_to_world(cx, cy);
    scale_ *= factor;
    scale_ = std::clamp(scale_, 0.1f, 10.0f);
    SDL_FPoint wp2 = screen_to_world(cx, cy);
    pan_x_ += wp2.x - wp.x;
    pan_y_ += wp2.y - wp.y;
}

void GraphView::pan_keyboard(float sdx, float sdy) {
    pan_x_ += sdx / scale_;
    pan_y_ += sdy / scale_;
}

void GraphView::select_and_focus(NodeId id, const Graph& /*g*/) {
    selected_ = id;
}

// Build a sorted list of AP node IDs (by label) from the graph
static std::vector<NodeId> build_ap_list(const Graph& graph) {
    std::vector<std::pair<std::string, NodeId>> aps;
    for (auto& [id, n] : graph.nodes()) {
        if (n.type != NodeType::AP) continue;
        std::string key = n.alias.empty() ? n.label : n.alias;
        aps.emplace_back(key, id);
    }
    std::sort(aps.begin(), aps.end());
    std::vector<NodeId> ids;
    ids.reserve(aps.size());
    for (auto& [k, id] : aps) ids.push_back(id);
    return ids;
}

void GraphView::ap_list_move(int delta, const Graph& g) {
    auto ids = build_ap_list(g);
    if (ids.empty()) return;
    ap_list_cursor_ = static_cast<int>(
        (static_cast<int>(ids.size()) + ap_list_cursor_ + delta) % static_cast<int>(ids.size()));
}

NodeId GraphView::ap_list_cursor_node(const Graph& g) const {
    auto ids = build_ap_list(g);
    if (ids.empty()) return 0;
    int i = std::clamp(ap_list_cursor_, 0, static_cast<int>(ids.size()) - 1);
    return ids[i];
}

void GraphView::draw_ap_list(const Graph& graph) {
    if (!font_ || !renderer_) return;
    auto ids = build_ap_list(graph);

    SDL_Rect clip{vp_x_, vp_y_, vp_w_, vp_h_};
    SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_BLEND);
    SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 220);
    SDL_RenderFillRect(renderer_, &clip);

    int lh   = TTF_FontHeight(font_);
    int pad  = 4;
    int row  = lh + 2;
    int y    = vp_y_ + 8;

    // Header
    auto draw_text = [&](const char* txt, int x, int yy, SDL_Color col) {
        SDL_Surface* s = TTF_RenderUTF8_Blended(font_, txt, col);
        if (!s) return;
        SDL_Texture* t = SDL_CreateTextureFromSurface(renderer_, s);
        int tw = s->w, th = s->h;
        SDL_FreeSurface(s);
        if (!t) return;
        SDL_Rect dst{x, yy, tw, th};
        SDL_RenderCopy(renderer_, t, nullptr, &dst);
        SDL_DestroyTexture(t);
    };

    draw_text("AP LIST", vp_x_ + pad, y, {0, 255, 255, 255});
    y += row;
    SDL_SetRenderDrawColor(renderer_, 80, 80, 80, 255);
    SDL_RenderDrawLine(renderer_, vp_x_ + pad, y, vp_x_ + vp_w_ - pad, y);
    y += 4;

    int footer_h = (lh + 2) * 2 + 2; // two hint lines
    int visible = (vp_y_ + vp_h_ - y - footer_h) / row;
    if (visible < 1) visible = 1;

    // Scroll so cursor stays in view
    int cursor = std::clamp(ap_list_cursor_, 0, (int)ids.size() - 1);
    int scroll  = 0;
    if (cursor >= visible) scroll = cursor - visible + 1;

    for (int i = scroll; i < (int)ids.size() && (i - scroll) < visible; ++i) {
        const Node* n = graph.get_node(ids[i]);
        if (!n) continue;

        bool is_cur = (i == cursor);
        if (is_cur) {
            SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_NONE);
            SDL_SetRenderDrawColor(renderer_, 40, 60, 40, 255);
            SDL_Rect hl{vp_x_, y - 1, vp_w_, lh + 2};
            SDL_RenderFillRect(renderer_, &hl);
        }

        // Prefer alias, then SSID (via Broadcasts edge), then last 8 chars of BSSID
        std::string ssid_str;
        for (auto& e : graph.edges()) {
            if (e.type != EdgeType::Broadcasts || e.a != ids[i]) continue;
            const Node* sn = graph.get_node(e.b);
            if (sn) { ssid_str = sn->label; break; }
        }
        // Short MAC: last 8 chars of BSSID (e.g. "5B:54:E8")
        std::string mac_short = n->label.size() >= 8
            ? n->label.substr(n->label.size() - 8) : n->label;
        std::string name = !n->alias.empty() ? n->alias : ssid_str;
        // Shorter truncation to leave room for password suffix
        if (name.size() > 11) name = name.substr(0, 10) + "~";

        // Build password suffix: "[pw1/pw2]" for all distinct cracked passwords
        std::string pw_suffix;
        const auto& pws = n->passwords;
        if (!pws.empty()) {
            pw_suffix = "[";
            for (size_t pi = 0; pi < pws.size(); ++pi) {
                if (pi) pw_suffix += '/';
                pw_suffix += pws[pi];
            }
            pw_suffix += "]";
        } else if (!n->password.empty()) {
            pw_suffix = "[" + n->password + "]";
        }

        // Format: ">XX:XX:XX name ch [pw]"
        std::string line = (is_cur ? ">" : " ");
        line += mac_short;
        if (!name.empty()) line += " " + name;
        if (n->channel > 0) line += " " + std::to_string(n->channel);
        if (!pw_suffix.empty()) line += " " + pw_suffix;

        bool has_pw = !pw_suffix.empty();
        SDL_Color col = is_cur  ? SDL_Color{255, 255,   0, 255}   // yellow cursor
                      : has_pw  ? SDL_Color{  0, 255,   0, 255}   // green = cracked
                      :           SDL_Color{255, 255, 255, 255};
        draw_text(line.c_str(), vp_x_ + pad, y, col);
        y += row;
    }

    // Footer hints — solid black background so text is fully readable over the list
    {
        int footer_y = vp_y_ + vp_h_ - (lh + 2) * 2 - 2;
        SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_NONE);
        SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 255);
        SDL_Rect bg{vp_x_, footer_y, vp_w_, vp_h_ - footer_y + vp_y_};
        SDL_RenderFillRect(renderer_, &bg);
        // Separator line
        SDL_SetRenderDrawColor(renderer_, 60, 60, 60, 255);
        SDL_RenderDrawLine(renderer_, vp_x_, footer_y, vp_x_ + vp_w_, footer_y);
    }
    SDL_Color hint_col{160, 160, 160, 255};
    draw_text("Tab/sTab=nav  Ent=sel", vp_x_ + pad, vp_y_ + vp_h_ - (lh + 2) * 2, hint_col);
    draw_text("d=deauth  Esc=close",   vp_x_ + pad, vp_y_ + vp_h_ - (lh + 2),     hint_col);
}

void GraphView::crack_list_move(int delta) {
    if (crack_list_entries_.empty()) return;
    crack_list_cursor_ = static_cast<int>(
        (crack_list_cursor_ + delta + crack_list_entries_.size()) % crack_list_entries_.size());
}

void GraphView::draw_crack_list() {
    if (!font_ || !renderer_) return;

    SDL_Rect clip{vp_x_, vp_y_, vp_w_, vp_h_};
    SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_BLEND);
    SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 220);
    SDL_RenderFillRect(renderer_, &clip);

    int lh  = TTF_FontHeight(font_);
    int pad = 4;
    int row = lh + 2;
    int y   = vp_y_ + 8;

    auto draw_text = [&](const char* txt, int x, int yy, SDL_Color col) {
        SDL_Surface* s = TTF_RenderUTF8_Blended(font_, txt, col);
        if (!s) return;
        SDL_Texture* t = SDL_CreateTextureFromSurface(renderer_, s);
        int tw = s->w, th = s->h;
        SDL_FreeSurface(s);
        if (!t) return;
        SDL_Rect dst{x, yy, tw, th};
        SDL_RenderCopy(renderer_, t, nullptr, &dst);
        SDL_DestroyTexture(t);
    };

    draw_text("CRACK QUEUE", vp_x_ + pad, y, {255, 100, 0, 255});
    y += row;
    SDL_SetRenderDrawColor(renderer_, 80, 80, 80, 255);
    SDL_RenderDrawLine(renderer_, vp_x_ + pad, y, vp_x_ + vp_w_ - pad, y);
    y += 4;

    // Spinner chars
    static const char* SPIN[4] = {"\\", "-", "/", "|"};

    int footer_h = (lh + 2) * 2 + 2;
    int visible  = (vp_y_ + vp_h_ - y - footer_h) / row;
    if (visible < 1) visible = 1;

    if (crack_list_entries_.empty()) {
        draw_text("(no handshakes captured)", vp_x_ + pad, y, {160, 160, 160, 255});
    } else {
        int cursor = std::clamp(crack_list_cursor_, 0, (int)crack_list_entries_.size() - 1);
        int scroll = (cursor >= visible) ? cursor - visible + 1 : 0;

        for (int i = scroll; i < (int)crack_list_entries_.size() && (i - scroll) < visible; ++i) {
            const auto& e = crack_list_entries_[i];
            bool is_cur = (i == cursor);

            if (is_cur) {
                SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_NONE);
                SDL_SetRenderDrawColor(renderer_, 40, 40, 60, 255);
                SDL_Rect hl{vp_x_, y - 1, vp_w_, lh + 2};
                SDL_RenderFillRect(renderer_, &hl);
            }

            // Short MAC: last 8 chars (AA:BB:CC)
            std::string mac_short = e.bssid.size() >= 8
                ? e.bssid.substr(e.bssid.size() - 8) : e.bssid;

            // Status indicator
            std::string status_str;
            SDL_Color   status_col{200, 200, 200, 255};
            using S = CrackListEntry::Status;
            switch (e.status) {
                case S::Queued:
                    status_str = "QUEUE";
                    status_col = {160, 160, 160, 255};
                    break;
                case S::Running:
                    status_str = std::string("RUN ") + SPIN[e.spin_frame & 3];
                    status_col = {255, 255, 0, 255};
                    break;
                case S::Found:
                    status_str = "FOUND";
                    status_col = {0, 255, 0, 255};
                    break;
                case S::NotFound:
                    status_str = "DONE-";
                    status_col = {255, 60, 60, 255};
                    break;
            }

            // Row: "> MAC  SSID  hs:N  STATUS"
            std::string prefix = is_cur ? ">" : " ";
            std::string ssid_trunc = e.ssid.size() > 10 ? e.ssid.substr(0, 9) + "~" : e.ssid;
            std::string line = prefix + mac_short
                + "  " + ssid_trunc
                + "  hs:" + std::to_string(e.handshake_count)
                + "  " + status_str;
            if (e.status == S::Found && !e.password.empty())
                line += "=" + e.password;

            SDL_Color row_col = is_cur ? SDL_Color{255, 255, 0, 255} : status_col;
            draw_text(line.c_str(), vp_x_ + pad, y, row_col);
            y += row;
        }
    }

    // Footer with solid background
    {
        int footer_y = vp_y_ + vp_h_ - (lh + 2) * 2 - 2;
        SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_NONE);
        SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 255);
        SDL_Rect bg{vp_x_, footer_y, vp_w_, vp_h_ - footer_y + vp_y_};
        SDL_RenderFillRect(renderer_, &bg);
        SDL_SetRenderDrawColor(renderer_, 60, 60, 60, 255);
        SDL_RenderDrawLine(renderer_, vp_x_, footer_y, vp_x_ + vp_w_, footer_y);
    }
    SDL_Color hint_col{160, 160, 160, 255};
    draw_text("Tab/sTab=nav", vp_x_ + pad, vp_y_ + vp_h_ - (lh + 2) * 2, hint_col);
    draw_text("Esc=close", vp_x_ + pad, vp_y_ + vp_h_ - (lh + 2), hint_col);
}

void GraphView::hs_list_move(int delta) {
    if (hs_list_entries_.empty()) return;
    int n = static_cast<int>(hs_list_entries_.size());
    hs_list_cursor_ = (hs_list_cursor_ + delta % n + n) % n;
}

NodeId GraphView::hs_list_select_client() const {
    if (hs_list_entries_.empty()) return 0;
    int cursor = std::clamp(hs_list_cursor_, 0, (int)hs_list_entries_.size() - 1);
    return hs_list_entries_[cursor].client_id;
}

void GraphView::draw_hs_list() {
    if (!font_ || !renderer_) return;

    SDL_Rect clip{vp_x_, vp_y_, vp_w_, vp_h_};
    SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_BLEND);
    SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 220);
    SDL_RenderFillRect(renderer_, &clip);

    int lh  = TTF_FontHeight(font_);
    int pad = 4;
    int row = lh + 2;
    int y   = vp_y_ + 8;

    auto draw_text = [&](const char* txt, int x, int yy, SDL_Color col) {
        SDL_Surface* s = TTF_RenderUTF8_Blended(font_, txt, col);
        if (!s) return;
        SDL_Texture* t = SDL_CreateTextureFromSurface(renderer_, s);
        int tw = s->w, th = s->h;
        SDL_FreeSurface(s);
        if (!t) return;
        SDL_Rect dst{x, yy, tw, th};
        SDL_RenderCopy(renderer_, t, nullptr, &dst);
        SDL_DestroyTexture(t);
    };

    draw_text("HANDSHAKES", vp_x_ + pad, y, {0, 200, 255, 255});
    y += row;
    SDL_SetRenderDrawColor(renderer_, 80, 80, 80, 255);
    SDL_RenderDrawLine(renderer_, vp_x_ + pad, y, vp_x_ + vp_w_ - pad, y);
    y += 4;

    static const char* SPIN[4] = {"\\", "-", "/", "|"};

    int footer_h = (lh + 2) * 2 + 2;
    int visible  = (vp_y_ + vp_h_ - y - footer_h) / row;
    if (visible < 1) visible = 1;

    if (hs_list_entries_.empty()) {
        draw_text("(no handshakes in DB)", vp_x_ + pad, y, {160, 160, 160, 255});
    } else {
        int cursor = std::clamp(hs_list_cursor_, 0, (int)hs_list_entries_.size() - 1);
        int scroll = (cursor >= visible) ? cursor - visible + 1 : 0;

        for (int i = scroll; i < (int)hs_list_entries_.size() && (i - scroll) < visible; ++i) {
            const auto& e = hs_list_entries_[i];
            bool is_cur = (i == cursor);

            if (is_cur) {
                SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_NONE);
                SDL_SetRenderDrawColor(renderer_, 30, 40, 60, 255);
                SDL_Rect hl{vp_x_, y - 1, vp_w_, lh + 2};
                SDL_RenderFillRect(renderer_, &hl);
            }

            using S = HandshakeListEntry::Status;
            std::string status_str;
            SDL_Color   status_col{200, 200, 200, 255};
            switch (e.status) {
                case S::Saved:
                    status_str = "SAVED";
                    status_col = {160, 160, 200, 255};
                    break;
                case S::Queued:
                    status_str = "QUEUE";
                    status_col = {160, 160, 160, 255};
                    break;
                case S::Running:
                    status_str = std::string("RUN ") + SPIN[e.spin_frame & 3];
                    status_col = {255, 255, 0, 255};
                    break;
                case S::Found:
                    status_str = "FOUND";
                    status_col = {0, 255, 0, 255};
                    break;
                case S::NotFound:
                    status_str = "DONE-";
                    status_col = {255, 60, 60, 255};
                    break;
            }

            // Short MACs: last 8 chars
            std::string cli_short = e.client_mac.size() >= 8
                ? e.client_mac.substr(e.client_mac.size() - 8) : e.client_mac;
            std::string ap_short = e.ap_bssid.size() >= 8
                ? e.ap_bssid.substr(e.ap_bssid.size() - 8) : e.ap_bssid;
            std::string ssid_trunc = e.ap_ssid.size() > 9 ? e.ap_ssid.substr(0, 8) + "~" : e.ap_ssid;

            // Line 1: "> CLI↔AP  SSID  STATUS"
            std::string prefix = is_cur ? ">" : " ";
            std::string line = prefix + cli_short + "<>" + ap_short
                + "  " + ssid_trunc
                + "  " + status_str;
            if (e.status == S::Found && !e.password.empty())
                line += "=" + e.password;

            SDL_Color row_col = is_cur ? SDL_Color{255, 255, 0, 255} : status_col;
            draw_text(line.c_str(), vp_x_ + pad, y, row_col);
            y += row;
        }
    }

    // Footer
    {
        int footer_y = vp_y_ + vp_h_ - (lh + 2) * 2 - 2;
        SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_NONE);
        SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 255);
        SDL_Rect bg{vp_x_, footer_y, vp_w_, vp_h_ - footer_y + vp_y_};
        SDL_RenderFillRect(renderer_, &bg);
        SDL_SetRenderDrawColor(renderer_, 60, 60, 60, 255);
        SDL_RenderDrawLine(renderer_, vp_x_, footer_y, vp_x_ + vp_w_, footer_y);
    }
    SDL_Color hint_col{160, 160, 160, 255};
    draw_text("Up/Dn=nav  Enter=select client", vp_x_ + pad, vp_y_ + vp_h_ - (lh + 2) * 2, hint_col);
    draw_text("Esc=close", vp_x_ + pad, vp_y_ + vp_h_ - (lh + 2), hint_col);
}

void GraphView::fit_view(const Graph& graph) {
    if (graph.nodes().empty()) {
        scale_ = 1.0f; pan_x_ = 0.0f; pan_y_ = 0.0f;
        return;
    }
    float min_x = 1e9f, max_x = -1e9f, min_y = 1e9f, max_y = -1e9f;
    for (auto& [id, n] : graph.nodes()) {
        if (!is_visible_node(n)) continue;
        min_x = std::min(min_x, n.x); max_x = std::max(max_x, n.x);
        min_y = std::min(min_y, n.y); max_y = std::max(max_y, n.y);
    }
    if (min_x > max_x) { scale_ = 1.0f; pan_x_ = 0.0f; pan_y_ = 0.0f; return; }
    float gw = max_x - min_x; if (gw < 1.0f) gw = 1.0f;
    float gh = max_y - min_y; if (gh < 1.0f) gh = 1.0f;
    float sx = (vp_w_ * 0.8f) / gw;
    float sy = (vp_h_ * 0.8f) / gh;
    scale_ = std::clamp(std::min(sx, sy), 0.1f, 10.0f);
    float cx = (min_x + max_x) * 0.5f;
    float cy = (min_y + max_y) * 0.5f;
    pan_x_ = vp_w_ / (2.0f * scale_) - cx;
    pan_y_ = vp_h_ / (2.0f * scale_) - cy;
}

void GraphView::draw_anomaly_log() {
    if (!font_ || !renderer_) return;

    // Semi-transparent dark background
    SDL_Rect clip{vp_x_, vp_y_, vp_w_, vp_h_};
    SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_BLEND);
    SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 220);
    SDL_RenderFillRect(renderer_, &clip);

    int lh  = TTF_FontHeight(font_);
    int pad = 4;
    int row = lh + 2;
    int y   = vp_y_ + 8;

    auto draw_text = [&](const char* txt, int x, int yy, SDL_Color col) {
        SDL_Surface* s = TTF_RenderUTF8_Blended(font_, txt, col);
        if (!s) return;
        SDL_Texture* t = SDL_CreateTextureFromSurface(renderer_, s);
        int tw = s->w, th = s->h;
        SDL_FreeSurface(s);
        if (!t) return;
        SDL_Rect dst{x, yy, tw, th};
        SDL_RenderCopy(renderer_, t, nullptr, &dst);
        SDL_DestroyTexture(t);
    };

    // Header
    std::string hdr = std::format("ANOMALY LOG  ({})", anomaly_log_.size());
    draw_text(hdr.c_str(), vp_x_ + pad, y, {255, 140, 0, 255});
    y += row;
    SDL_SetRenderDrawColor(renderer_, 80, 80, 80, 255);
    SDL_RenderDrawLine(renderer_, vp_x_ + pad, y, vp_x_ + vp_w_ - pad, y);
    y += 4;

    if (anomaly_log_.empty()) {
        draw_text("No anomalies detected yet.", vp_x_ + pad, y, {180, 180, 180, 255});
    } else {
        int footer_h = row + 4;
        int visible  = (vp_y_ + vp_h_ - y - footer_h) / row;
        if (visible < 1) visible = 1;

        for (int i = 0; i < (int)anomaly_log_.size() && i < visible; ++i) {
            const auto& ev = anomaly_log_[i];

            // Severity color: critical=red, warn=yellow, info=white
            SDL_Color col = ev.severity >= 3 ? SDL_Color{255,  60,  60, 255}
                          : ev.severity == 2 ? SDL_Color{255, 200,  40, 255}
                          :                    SDL_Color{200, 200, 200, 255};

            // Format timestamp as relative age (seconds ago) using ts_us
            uint64_t now = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            uint64_t age_s = (now >= ev.ts_us) ? (now - ev.ts_us) / 1'000'000 : 0;
            std::string age_str = age_s < 60   ? std::format("{}s", age_s)
                                : age_s < 3600 ? std::format("{}m", age_s / 60)
                                :                std::format("{}h", age_s / 3600);

            // "[type] src → description  (age)"
            std::string line = std::format("[{}] {} {}",
                anomaly_type_name(ev.type),
                ev.src_mac.size() >= 8 ? ev.src_mac.substr(ev.src_mac.size() - 8) : ev.src_mac,
                age_str);
            draw_text(line.c_str(), vp_x_ + pad, y, col);
            y += row;

            // Description on next line, dimmer
            std::string desc = ev.description;
            if (desc.size() > 50) desc = desc.substr(0, 48) + "..";
            draw_text(("  " + desc).c_str(), vp_x_ + pad, y, {160, 160, 160, 255});
            y += row;

            i++;  // each entry takes 2 lines
            if (i >= visible) break;
        }
    }

    // Footer
    SDL_SetRenderDrawColor(renderer_, 60, 60, 60, 255);
    SDL_RenderDrawLine(renderer_, vp_x_, vp_y_ + vp_h_ - row - 6,
                       vp_x_ + vp_w_, vp_y_ + vp_h_ - row - 6);
    draw_text("w=close  Orange ring=anomalous  Purple ring=multi-AP",
              vp_x_ + pad, vp_y_ + vp_h_ - row - 4, {160, 160, 160, 255});
}
