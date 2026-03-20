#include "similarity.hpp"

float jaccard_weighted(
    const std::unordered_set<NodeId>& a_ssids,
    const std::unordered_set<NodeId>& b_ssids,
    const std::unordered_map<NodeId, float>& ssid_weights)
{
    if (a_ssids.empty() && b_ssids.empty()) return 0.0f;

    float intersection = 0.0f;
    float union_weight = 0.0f;

    auto weight_of = [&](NodeId sid) -> float {
        auto it = ssid_weights.find(sid);
        return (it != ssid_weights.end()) ? it->second : 1.0f;
    };

    // Accumulate union and intersection
    for (NodeId sid : a_ssids) {
        float w = weight_of(sid);
        union_weight += w;
        if (b_ssids.count(sid)) {
            intersection += w;
        }
    }
    for (NodeId sid : b_ssids) {
        if (!a_ssids.count(sid)) {
            union_weight += weight_of(sid);
        }
    }

    if (union_weight <= 0.0f) return 0.0f;
    return intersection / union_weight;
}
