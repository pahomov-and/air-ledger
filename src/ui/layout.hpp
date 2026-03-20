#pragma once
#include "entity/graph.hpp"
#include <unordered_map>
#include <unordered_set>
#include <vector>

class LayoutEngine {
public:
    void set_bounds(float w, float h);
    void update(std::unordered_map<NodeId, Node>& nodes, const std::vector<Edge>& edges);
    void pin(NodeId id, float x, float y);
    void unpin(NodeId id);
    bool is_pinned(NodeId id) const { return pinned_.count(id) > 0; }

private:
    float width_{1200.0f};
    float height_{800.0f};
    float k_{100.0f};
    float damping_{0.7f};
    float dt_{0.05f};

    std::unordered_set<NodeId> pinned_;
    std::unordered_map<NodeId, float> pin_x_, pin_y_;

    // AP zone anchors: each AP gets a persistent slot on a ring
    std::unordered_map<NodeId, size_t> ap_slot_;   // AP id → slot index
    size_t ap_slot_count_{0};                       // total slots assigned
    // Anchor positions recomputed when slot count changes
    std::vector<float> anchor_x_, anchor_y_;

    void recalc_k(int n);
    void reassign_ap_anchors(); // redistribute ring positions for all slots

    // Spatial hash grid for O(n) repulsion (reused across frames, no alloc)
    std::vector<std::vector<size_t>> grid_cells_;
    int grid_cols_{0};
    int grid_rows_{0};
};
