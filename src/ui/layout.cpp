#include "layout.hpp"
#include <cmath>
#include <algorithm>
#include <cstdio>
#include <vector>

static constexpr float PI = 3.14159265f;

void LayoutEngine::set_bounds(float w, float h) {
    width_ = w;
    height_ = h;
    if (ap_slot_count_ > 0)
        reassign_ap_anchors();
}

void LayoutEngine::recalc_k(int n) {
    if (n <= 0) n = 1;
    float area = width_ * height_;
    k_ = 0.75f * std::sqrt(area / static_cast<float>(n));
    k_ = std::min(k_, 90.0f); // cap repulsion so gravity can win near edges
}

void LayoutEngine::pin(NodeId id, float x, float y) {
    pinned_.insert(id);
    pin_x_[id] = x;
    pin_y_[id] = y;
}

void LayoutEngine::unpin(NodeId id) {
    pinned_.erase(id);
    pin_x_.erase(id);
    pin_y_.erase(id);
}

void LayoutEngine::reassign_ap_anchors() {
    size_t n = ap_slot_count_;
    anchor_x_.resize(n);
    anchor_y_.resize(n);

    // Grid layout: divide canvas into cells, place AP anchors at cell centers.
    // Margin keeps anchors away from the edges.
    const float margin_x = width_  * 0.12f;
    const float margin_y = height_ * 0.12f;
    const float usable_w = width_  - 2.0f * margin_x;
    const float usable_h = height_ - 2.0f * margin_y;

    size_t cols = static_cast<size_t>(std::ceil(std::sqrt(static_cast<float>(n))));
    size_t rows = (n + cols - 1) / cols;

    for (size_t i = 0; i < n; ++i) {
        size_t col = i % cols;
        size_t row = i / cols;

        // Center of each cell; for the last (possibly partial) row, center horizontally
        size_t cols_in_row = (row == rows - 1) ? (n - row * cols) : cols;
        float cell_w = usable_w / static_cast<float>(cols_in_row);
        float cell_h = usable_h / static_cast<float>(rows);

        anchor_x_[i] = margin_x + cell_w * (static_cast<float>(col) + 0.5f);
        anchor_y_[i] = margin_y + cell_h * (static_cast<float>(row) + 0.5f);
    }
}

void LayoutEngine::update(std::unordered_map<NodeId, Node>& nodes,
                          const std::vector<Edge>& edges)
{
    if (nodes.empty()) return;

    recalc_k(static_cast<int>(nodes.size()));

    // Register new APs and reassign anchors if the set changed.
    // Co-located APs (same physical device, SeenNear edge) share the same anchor slot.
    bool slots_changed = false;
    for (auto& [id, n] : nodes) {
        if (n.type != NodeType::AP || ap_slot_.find(id) != ap_slot_.end()) continue;

        // Check if any already-registered AP is co-located with this one
        size_t shared = SIZE_MAX;
        for (auto& e : edges) {
            if (e.type != EdgeType::SeenNear) continue;
            NodeId other = 0;
            if (e.a == id) other = e.b;
            else if (e.b == id) other = e.a;
            else continue;
            auto sit = ap_slot_.find(other);
            if (sit == ap_slot_.end()) continue;
            auto oit = nodes.find(other);
            if (oit == nodes.end() || oit->second.type != NodeType::AP) continue;
            shared = sit->second;
            break;
        }

        if (shared != SIZE_MAX) {
            ap_slot_[id] = shared; // share anchor with co-located AP
        } else {
            ap_slot_[id] = ap_slot_count_++;
            slots_changed = true;
        }
    }
    if (slots_changed)
        reassign_ap_anchors();

    // Hard-fix APs at their anchors FIRST — before any force computation.
    // This ensures orbital forces always use the correct anchor as orbit center.
    // Co-located APs share a slot → spread them on a small circle so they don't overlap.
    {
        // Count how many APs occupy each slot and assign per-slot index.
        std::unordered_map<size_t, int> slot_total;
        std::unordered_map<NodeId, int> slot_idx;
        for (auto& [id, n] : nodes) {
            if (n.type != NodeType::AP || pinned_.count(id)) continue;
            auto sit = ap_slot_.find(id);
            if (sit == ap_slot_.end()) continue;
            int idx = slot_total[sit->second]++;
            slot_idx[id] = idx;
        }
        constexpr float COLOC_R = 22.0f; // spread radius (world units)
        for (auto& [id, n] : nodes) {
            if (n.type != NodeType::AP) continue;
            if (pinned_.count(id)) continue;
            auto slot_it = ap_slot_.find(id);
            if (slot_it == ap_slot_.end()) continue;
            size_t slot = slot_it->second;
            int total = slot_total[slot];
            int idx   = slot_idx[id];
            float ax  = anchor_x_[slot];
            float ay  = anchor_y_[slot];
            if (total > 1) {
                float angle = idx * (2.0f * PI / static_cast<float>(total));
                ax += COLOC_R * std::cos(angle);
                ay += COLOC_R * std::sin(angle);
            }
            n.x  = ax;
            n.y  = ay;
            n.vx = 0;
            n.vy = 0;
        }
    }

    // Apply pinned positions
    for (auto id : pinned_) {
        auto it = nodes.find(id);
        if (it != nodes.end()) {
            it->second.x  = pin_x_.at(id);
            it->second.y  = pin_y_.at(id);
            it->second.vx = 0;
            it->second.vy = 0;
        }
    }

    // Non-ghost SSID nodes are hidden in the UI — exclude from physics entirely.
    auto layout_visible = [](const Node& n) {
        return !(n.type == NodeType::SSID && !n.is_ghost);
    };

    std::vector<Node*> ns;
    ns.reserve(nodes.size());
    for (auto& [id, n] : nodes)
        if (layout_visible(n)) ns.push_back(&n);

    const float k2       = k_ * k_;
    // Hard cap on per-frame displacement prevents sharp visual jumps.
    // k_*2 could reach 180 world units — way too much for a stable sim.
    const float max_disp = std::min(k_ * 0.4f, 18.0f);

    std::vector<float> dx(ns.size(), 0.0f);
    std::vector<float> dy(ns.size(), 0.0f);

    // Build index map
    std::unordered_map<NodeId, size_t> idx_map;
    for (size_t i = 0; i < ns.size(); ++i)
        idx_map[ns[i]->id] = i;

    // AP-SSID (Broadcasts) pairs: collect pairs to skip global repulsion.
    // The orbital spring below handles both attraction AND minimum separation,
    // so global repulsion would just push them apart uncontrollably.
    std::unordered_set<uint64_t> ap_ssid_pairs;
    for (auto& e : edges) {
        if (e.type != EdgeType::Broadcasts) continue;
        auto ia = idx_map.find(e.a);
        auto ib = idx_map.find(e.b);
        if (ia == idx_map.end() || ib == idx_map.end()) continue;
        size_t pi = ia->second, pj = ib->second;
        if (pi > pj) std::swap(pi, pj);
        ap_ssid_pairs.insert((uint64_t)pi << 32 | pj);
    }

    // Repulsion: spatial hash grid — O(n) average instead of O(n²).
    // Cell size = 2*k_ so nodes beyond 2 cells apart exert negligible force.
    float cell_size = std::max(k_ * 2.0f, 40.0f);
    int new_cols = std::max(1, static_cast<int>(std::ceil(width_  / cell_size)));
    int new_rows = std::max(1, static_cast<int>(std::ceil(height_ / cell_size)));
    int total_cells = new_cols * new_rows;

    // Resize and clear grid (reuses memory from previous frame)
    if (static_cast<int>(grid_cells_.size()) != total_cells) {
        grid_cells_.assign(total_cells, {});
        grid_cols_ = new_cols;
        grid_rows_ = new_rows;
    } else {
        for (auto& cell : grid_cells_) cell.clear();
    }

    // Insert each node into its grid cell
    for (size_t i = 0; i < ns.size(); ++i) {
        int cx = std::clamp(static_cast<int>(ns[i]->x / cell_size), 0, grid_cols_ - 1);
        int cy = std::clamp(static_cast<int>(ns[i]->y / cell_size), 0, grid_rows_ - 1);
        grid_cells_[cy * grid_cols_ + cx].push_back(i);
    }

    // For each node repel only against nodes in the same + neighboring cells
    for (size_t i = 0; i < ns.size(); ++i) {
        int cx = std::clamp(static_cast<int>(ns[i]->x / cell_size), 0, grid_cols_ - 1);
        int cy = std::clamp(static_cast<int>(ns[i]->y / cell_size), 0, grid_rows_ - 1);

        for (int oy = -1; oy <= 1; ++oy) {
            for (int ox = -1; ox <= 1; ++ox) {
                int nx = cx + ox, ny = cy + oy;
                if (nx < 0 || nx >= grid_cols_ || ny < 0 || ny >= grid_rows_) continue;
                for (size_t j : grid_cells_[ny * grid_cols_ + nx]) {
                    if (j <= i) continue; // process each pair once
                    uint64_t pkey = (uint64_t)i << 32 | j;
                    if (ap_ssid_pairs.count(pkey)) continue;

                    float ddx   = ns[i]->x - ns[j]->x;
                    float ddy   = ns[i]->y - ns[j]->y;
                    float dist2 = ddx * ddx + ddy * ddy + 0.01f;
                    float dist  = std::sqrt(dist2);
                    float force = k2 / dist;
                    float fx    = (ddx / dist) * force;
                    float fy    = (ddy / dist) * force;
                    dx[i] += fx;  dy[i] += fy;
                    dx[j] -= fx;  dy[j] -= fy;
                }
            }
        }
    }

    // Attraction along edges.
    // For Broadcasts (AP↔SSID) / AssociatedWith (AP↔Client) edges,
    // use an orbital spring: satellite settles at ORBIT_R from the AP.
    // For AP-SSID pairs global repulsion is skipped (above), so the
    // orbital spring alone determines the equilibrium — stable at ORBIT_R.
    constexpr float ORBIT_R    = 60.0f;  // target AP-satellite distance (world units)
    constexpr float ORBIT_K    = 0.35f;  // spring stiffness
    constexpr float MIN_SEP    = 8.0f;   // hard minimum to avoid divide-by-zero singularity

    for (auto& e : edges) {
        auto ia = idx_map.find(e.a);
        auto ib = idx_map.find(e.b);
        // Skip edges involving hidden nodes (non-ghost SSIDs not in idx_map)
        if (ia == idx_map.end() || ib == idx_map.end()) continue;

        size_t i = ia->second, j = ib->second;
        float ddx  = ns[i]->x - ns[j]->x;
        float ddy  = ns[i]->y - ns[j]->y;
        float dist = std::sqrt(ddx * ddx + ddy * ddy + 0.01f);

        // Detect AP-satellite pair for Broadcasts / AssociatedWith
        bool is_orbital = false;
        size_t ap_idx = 0, sat_idx = 0;
        if (e.type == EdgeType::Broadcasts || e.type == EdgeType::AssociatedWith) {
            if (ns[i]->type == NodeType::AP) {
                ap_idx = i; sat_idx = j; is_orbital = true;
            } else if (ns[j]->type == NodeType::AP) {
                ap_idx = j; sat_idx = i; is_orbital = true;
            }
        }

        if (is_orbital) {
            float sat_dx = ns[sat_idx]->x - ns[ap_idx]->x;
            float sat_dy = ns[sat_idx]->y - ns[ap_idx]->y;
            float r      = std::sqrt(sat_dx * sat_dx + sat_dy * sat_dy);

            if (r < MIN_SEP) {
                // Nodes nearly coincident — push satellite out with a fixed nudge
                // using a deterministic direction based on IDs to avoid oscillation.
                uint64_t seed = ns[sat_idx]->id ^ (ns[ap_idx]->id * 2654435761ULL);
                float angle = static_cast<float>(seed & 0xFFFF) * (2.0f * PI / 65536.0f);
                dx[sat_idx] += std::cos(angle) * ORBIT_K * ORBIT_R;
                dy[sat_idx] += std::sin(angle) * ORBIT_K * ORBIT_R;
            } else {
                // Radial spring: positive delta → too far → attract; negative → too close → repel
                float delta = r - ORBIT_R;
                float force = delta * ORBIT_K;
                float fx    = (sat_dx / r) * force;
                float fy    = (sat_dy / r) * force;
                dx[sat_idx] -= fx;  dy[sat_idx] -= fy;
                dx[ap_idx]  += fx;  dy[ap_idx]  += fy;
            }
        } else {
            // Regular spring for all other edge types
            float weight_scale = (e.type == EdgeType::SimilarTo
                               || e.type == EdgeType::FingerprintMatch) ? 0.5f : 0.1f;
            float att = (dist * dist / k_) * std::min(e.weight, 5.0f) * weight_scale;
            float fx  = (ddx / dist) * att;
            float fy  = (ddy / dist) * att;
            dx[i] -= fx;  dy[i] -= fy;
            dx[j] += fx;  dy[j] += fy;
        }
    }

    // Quadratic gravity toward center: weak near center, strong near edges.
    // With k capped at 90, gravity wins over repulsion beyond ~250px from center.
    constexpr float GQ = 0.00015f;
    float cx = width_ * 0.5f, cy = height_ * 0.5f;
    for (size_t i = 0; i < ns.size(); ++i) {
        float ex = ns[i]->x - cx, ey = ns[i]->y - cy;
        dx[i] -= GQ * ex * std::abs(ex);
        dy[i] -= GQ * ey * std::abs(ey);
    }

    // Viscosity (velocity-proportional drag): F = -viscosity * v.
    // Unlike multiplicative damping, this is proportional to current speed,
    // so fast-oscillating nodes are braked much harder than slow-moving ones.
    constexpr float VISCOSITY = 16.0f;
    for (size_t i = 0; i < ns.size(); ++i) {
        dx[i] -= VISCOSITY * ns[i]->vx;
        dy[i] -= VISCOSITY * ns[i]->vy;
    }

    // APs are hard-placed at their anchor slots — they don't participate in physics.
    // Handled below after velocity integration.

    // Apply displacement with velocity + damping
    for (size_t i = 0; i < ns.size(); ++i) {
        if (pinned_.count(ns[i]->id)) continue;

        float fx = dx[i] * dt_;
        float fy = dy[i] * dt_;

        float disp = std::sqrt(fx * fx + fy * fy);
        if (disp > max_disp) { fx = fx / disp * max_disp; fy = fy / disp * max_disp; }

        ns[i]->vx = (ns[i]->vx + fx) * damping_;
        ns[i]->vy = (ns[i]->vy + fy) * damping_;

        ns[i]->vx = std::clamp(ns[i]->vx, -max_disp, max_disp);
        ns[i]->vy = std::clamp(ns[i]->vy, -max_disp, max_disp);

        ns[i]->x += ns[i]->vx;
        ns[i]->y += ns[i]->vy;

        // Hard clamp — no node can leave the canvas
        constexpr float B = 20.0f;
        ns[i]->x = std::clamp(ns[i]->x, B, width_  - B);
        ns[i]->y = std::clamp(ns[i]->y, B, height_ - B);
        // At wall: redirect velocity toward canvas center
        bool hit_wall = false;
        if (ns[i]->x <= B)           { ns[i]->vx =  std::abs(ns[i]->vx); hit_wall = true; }
        if (ns[i]->x >= width_  - B) { ns[i]->vx = -std::abs(ns[i]->vx); hit_wall = true; }
        if (ns[i]->y <= B)           { ns[i]->vy =  std::abs(ns[i]->vy); hit_wall = true; }
        if (ns[i]->y >= height_ - B) { ns[i]->vy = -std::abs(ns[i]->vy); hit_wall = true; }
        if (hit_wall) {
            // Steer velocity vector toward canvas center
            float tx = cx - ns[i]->x, ty = cy - ns[i]->y;
            float tlen = std::sqrt(tx * tx + ty * ty);
            if (tlen > 0.1f) {
                float speed = std::sqrt(ns[i]->vx * ns[i]->vx + ns[i]->vy * ns[i]->vy);
                ns[i]->vx = (tx / tlen) * speed;
                ns[i]->vy = (ty / tlen) * speed;
            }
        }
    }

}
