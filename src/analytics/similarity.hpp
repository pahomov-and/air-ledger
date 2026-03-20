#pragma once
#include <unordered_map>
#include <unordered_set>
#include <cstdint>

// NodeId is defined in entity/graph.hpp; re-define locally only if not already defined
#ifndef NODEID_DEFINED
#define NODEID_DEFINED
using NodeId = uint64_t;
#endif

// Compute weighted Jaccard similarity between two sets of SSID node IDs.
// ssid_weights maps each SSID NodeId to its rarity weight (1/frequency).
// Returns a score in [0, 1].
float jaccard_weighted(
    const std::unordered_set<NodeId>& a_ssids,
    const std::unordered_set<NodeId>& b_ssids,
    const std::unordered_map<NodeId, float>& ssid_weights
);
