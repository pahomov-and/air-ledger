#pragma once
#include "parser/types.hpp"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <cstdint>

#ifndef NODEID_DEFINED
#define NODEID_DEFINED
using NodeId = uint64_t;
#endif

enum class NodeType { Client, AP, SSID, Location };
enum class EdgeType { ProbesFor, Broadcasts, SeenNear, SimilarTo, AssociatedWith, FingerprintMatch };

struct Node {
    NodeId id{0};
    NodeType type{NodeType::Client};
    std::string label;    // MAC string or SSID name
    std::string alias;    // user-assigned name
    std::string vendor;   // from OUI
    bool is_randomized{false};
    bool is_active{false};     // seen in last 5 min
    bool is_stationary{false}; // seen many times over long span
    bool is_ghost{false};      // SSID only: probed by clients but no AP is broadcasting it
    bool has_handshake{false}; // client: EAPOL 4-way handshake was captured
    std::unordered_set<NodeId> handshake_aps; // client: AP node IDs from which handshake was captured
    float x{0}, y{0};    // layout position
    float vx{0}, vy{0};  // velocity for force layout
    uint64_t first_seen{0};
    uint64_t last_seen{0};
    uint32_t seen_count{0};
    int8_t last_rssi{-100};
    // radio capability fingerprint (from ProbeRequest/AssocRequest IEs)
    std::string radio_fingerprint;
    // for clients
    std::unordered_set<NodeId> probed_ssids;
    // for APs
    int channel{0};
    uint8_t chan_ht_oper{0}; // HT Operation secondary ch offset: 0=HT20, 1=HT40+, 3=HT40-
    std::string security;
    std::string password;               // latest cracked password (compat)
    std::vector<std::string> passwords; // all cracked passwords for this AP
    bool crack_not_found{false};        // cracker exhausted wordlist, no key
    bool crack_running{false};          // crack job currently active (queued or running)
    uint64_t crack_speed_kps{0};        // last known crack speed (k/s), 0 = unknown
    int  anomaly_count{0};              // total anomaly events involving this MAC
    int  assoc_ap_count{0};            // number of distinct APs this client associated with
    NodeId ssid_id{0};
};

struct Edge {
    NodeId a{0}, b{0};
    EdgeType type{EdgeType::ProbesFor};
    float weight{1.0f};
    uint64_t last_seen{0};
    uint32_t count{0};
};

class Graph {
public:
    NodeId get_or_create_client(const MacAddr& mac, uint64_t ts_us, int8_t rssi);
    NodeId get_or_create_ssid(const std::string& ssid, uint64_t ts_us);
    NodeId get_or_create_ap(const MacAddr& bssid, uint64_t ts_us, int8_t rssi);

    void add_probe(NodeId client, NodeId ssid, uint64_t ts_us, int8_t rssi);
    void add_beacon(NodeId ap, NodeId ssid, int channel, uint8_t ht_oper, const std::string& security, uint64_t ts_us);
    void add_associated(NodeId client, NodeId ap, uint64_t ts_us);
    void update_similarity(NodeId a, NodeId b, float score);
    void mark_colocated(NodeId a, NodeId b);       // SeenNear edge: same physical device
    void add_fingerprint_match(NodeId a, NodeId b); // FingerprintMatch edge

    void process_frame(const ParsedFrame& frame);

    Node* get_node(NodeId id);
    const Node* get_node(NodeId id) const;
    const std::unordered_map<NodeId, Node>& nodes() const { return nodes_; }
    std::unordered_map<NodeId, Node>& nodes() { return nodes_; }
    const std::vector<Edge>& edges() const { return edges_; }
    uint32_t assoc_edge_count() const {
        uint32_t n = 0;
        for (auto& e : edges_) if (e.type == EdgeType::AssociatedWith) ++n;
        return n;
    }

    // Alias management
    void set_alias(NodeId id, const std::string& alias);

    // Analytics
    std::vector<std::pair<NodeId, NodeId>> compute_similarities();
    void mark_active(uint64_t now_us, uint64_t window_us = 300'000'000ULL);
    size_t prune_stale_clients(uint64_t now_us, uint64_t window_us = 300'000'000ULL,
                               NodeId preserve_id = 0);

    // Per-SSID frequency across clients (for Jaccard weighting)
    std::unordered_map<NodeId, uint32_t> ssid_probe_frequency() const;

private:
    std::unordered_map<NodeId, Node> nodes_;
    std::vector<Edge> edges_;
    std::unordered_map<std::string, NodeId> mac_to_id_;
    std::unordered_map<std::string, NodeId> ssid_to_id_;
    // Edge lookup: sorted pair -> index in edges_
    std::unordered_map<uint64_t, size_t> edge_index_; // key = a<<32 | b (with a<b for symmetric types)
    NodeId next_id_{1};

    NodeId alloc_id() { return next_id_++; }

    // Find or create edge; returns reference
    Edge& get_or_create_edge(NodeId a, NodeId b, EdgeType type);
    static uint64_t edge_key(NodeId a, NodeId b, EdgeType type) {
        // Combine a, b, type into a single key
        // Ensure a <= b for symmetric types
        if (a > b) std::swap(a, b);
        return (a << 20) ^ (b << 4) ^ static_cast<uint64_t>(type);
    }
};
