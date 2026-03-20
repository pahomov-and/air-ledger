#include "graph.hpp"
#include "oui.hpp"
#include <cmath>
#include <algorithm>
#include <cstdio>
#include <format>

// Build a band-normalized fingerprint string from ProbeRequest/AssocRequest IEs.
//
// The same device advertises different capabilities depending on which band it scans:
//   2.4 GHz: includes CCK rates (1/2/5.5/11 Mbps), no VHT, HT flags show 20MHz-only
//   5 GHz:   OFDM rates only, has VHT, HT flags show 20/40MHz support
//
// Normalization:
//   - Strip CCK rates (02 04 0B 16 = 1/2/5.5/11 Mbps) — 2.4 GHz only
//   - Exclude VHT — 5 GHz only, would break cross-band matching
//   - Mask HT bits that vary per band:
//       bit 1 (Supported Channel Width: 0=20MHz / 1=20/40MHz)
//       bit 6 (Short GI for 40MHz — only relevant when 40MHz capable)
//     Mask = ~0x0042
//
// After normalization DA (2.4 GHz) and 3E (5 GHz) of the same device give identical fp.
static std::string build_fingerprint(const ParsedFrame& f) {
    // Strip CCK rates; keep OFDM rates only
    static constexpr uint8_t CCK[] = {0x02, 0x04, 0x0B, 0x16};
    std::vector<uint8_t> ofdm;
    for (uint8_t r : f.rates) {
        bool is_cck = false;
        for (auto c : CCK) if (r == c) { is_cck = true; break; }
        if (!is_cck) ofdm.push_back(r);
    }

    // Require at least HT or 4+ OFDM rates to produce a meaningful fingerprint
    if (!f.has_ht && !f.has_he && ofdm.size() < 4) return "";

    std::string s = "R:";
    for (auto r : ofdm) s += std::format("{:02X}", r);
    if (f.has_ht) {
        // Mask out band-variable bits: bit1 (channel width), bit6 (SGI-40)
        uint16_t masked = f.ht_cap_info & static_cast<uint16_t>(~0x0042u);
        s += std::format("|HT:{:04X}", masked);
    }
    // VHT intentionally excluded (5 GHz only)
    if (f.has_he) s += "|HE";
    return s;
}

static constexpr float INITIAL_SPREAD = 400.0f;

// Deterministic initial position based on id and type
static std::pair<float, float> initial_pos(NodeId id, NodeType type) {
    float base_x = 600.0f, base_y = 400.0f;
    switch (type) {
        case NodeType::Client:   base_x = 200.0f; base_y = 400.0f; break;
        case NodeType::SSID:     base_x = 600.0f; base_y = 150.0f; break;
        case NodeType::AP:       base_x = 1000.0f; base_y = 400.0f; break;
        case NodeType::Location: base_x = 600.0f; base_y = 650.0f; break;
    }
    // Spread using pseudo-random offset based on id
    float angle = static_cast<float>(id * 2654435761ULL % 1000) / 1000.0f * 6.2832f;
    float r = static_cast<float>(id * 1013904223ULL % 1000) / 1000.0f * INITIAL_SPREAD * 0.5f;
    return {base_x + r * std::cos(angle), base_y + r * std::sin(angle)};
}

NodeId Graph::get_or_create_client(const MacAddr& mac, uint64_t ts_us, int8_t rssi) {
    std::string key = mac.to_string();
    auto it = mac_to_id_.find(key);
    if (it != mac_to_id_.end()) {
        auto& n = nodes_[it->second];
        n.last_seen = ts_us;
        n.last_rssi = rssi;
        ++n.seen_count;
        return it->second;
    }
    NodeId id = alloc_id();
    mac_to_id_[key] = id;
    Node n;
    n.id = id;
    n.type = NodeType::Client;
    n.label = key;
    n.is_randomized = mac.is_locally_administered();
    n.vendor = lookup_oui(mac);
    n.first_seen = ts_us;
    n.last_seen = ts_us;
    n.seen_count = 1;
    n.last_rssi = rssi;
    auto [x, y] = initial_pos(id, NodeType::Client);
    n.x = x; n.y = y;
    nodes_[id] = std::move(n);
    std::fprintf(stderr, "[new_client] id=%llu  mac=%s  vendor=%s  random=%s\n",
                 (unsigned long long)id, key.c_str(),
                 n.vendor.empty() ? "?" : n.vendor.c_str(),
                 n.is_randomized ? "yes" : "no");
    return id;
}

NodeId Graph::get_or_create_ssid(const std::string& ssid, uint64_t ts_us) {
    auto it = ssid_to_id_.find(ssid);
    if (it != ssid_to_id_.end()) {
        nodes_[it->second].last_seen = ts_us;
        return it->second;
    }
    NodeId id = alloc_id();
    ssid_to_id_[ssid] = id;
    Node n;
    n.id = id;
    n.type = NodeType::SSID;
    n.label = ssid.empty() ? "<hidden>" : ssid;
    n.is_ghost = true; // ghost until an AP beacon confirms it
    n.first_seen = ts_us;
    n.last_seen = ts_us;
    n.seen_count = 1;
    auto [x, y] = initial_pos(id, NodeType::SSID);
    n.x = x; n.y = y;
    nodes_[id] = std::move(n);
    return id;
}

NodeId Graph::get_or_create_ap(const MacAddr& bssid, uint64_t ts_us, int8_t rssi) {
    std::string key = bssid.to_string();
    auto it = mac_to_id_.find(key);
    if (it != mac_to_id_.end()) {
        auto& n = nodes_[it->second];
        n.last_seen = ts_us;
        n.last_rssi = rssi;
        ++n.seen_count;
        return it->second;
    }
    NodeId id = alloc_id();
    mac_to_id_[key] = id;
    Node n;
    n.id = id;
    n.type = NodeType::AP;
    n.label = key;
    n.vendor = lookup_oui(bssid);
    n.first_seen = ts_us;
    n.last_seen = ts_us;
    n.seen_count = 1;
    n.last_rssi = rssi;
    auto [x, y] = initial_pos(id, NodeType::AP);
    n.x = x; n.y = y;
    nodes_[id] = std::move(n);
    std::fprintf(stderr, "[new_ap] id=%llu  bssid=%s  vendor=%s\n",
                 (unsigned long long)id, key.c_str(),
                 n.vendor.empty() ? "?" : n.vendor.c_str());
    return id;
}

Edge& Graph::get_or_create_edge(NodeId a, NodeId b, EdgeType type) {
    uint64_t key = edge_key(a, b, type);
    auto it = edge_index_.find(key);
    if (it != edge_index_.end()) {
        return edges_[it->second];
    }
    size_t idx = edges_.size();
    edge_index_[key] = idx;
    Edge e;
    e.a = a; e.b = b; e.type = type;
    edges_.push_back(e);
    return edges_[idx];
}

void Graph::add_probe(NodeId client, NodeId ssid, uint64_t ts_us, int8_t /*rssi*/) {
    // Update client's probed set
    if (auto it = nodes_.find(client); it != nodes_.end())
        it->second.probed_ssids.insert(ssid);

    Edge& e = get_or_create_edge(client, ssid, EdgeType::ProbesFor);
    e.last_seen = ts_us;
    ++e.count;
    e.weight = std::min(1.0f + std::log1p(static_cast<float>(e.count)) * 0.2f, 5.0f);
}

void Graph::add_beacon(NodeId ap, NodeId ssid, int channel, uint8_t ht_oper, const std::string& security, uint64_t ts_us) {
    if (auto it = nodes_.find(ap); it != nodes_.end()) {
        it->second.channel = channel;
        it->second.chan_ht_oper = ht_oper;
        it->second.security = security;
        it->second.ssid_id = ssid;
    }
    // This SSID is actively broadcast by an AP — not a ghost
    if (auto it = nodes_.find(ssid); it != nodes_.end())
        it->second.is_ghost = false;

    Edge& e = get_or_create_edge(ap, ssid, EdgeType::Broadcasts);
    e.last_seen = ts_us;
    ++e.count;
}

void Graph::add_associated(NodeId client, NodeId ap, uint64_t ts_us) {
    bool is_new = (edge_index_.find(edge_key(client, ap, EdgeType::AssociatedWith))
                   == edge_index_.end());
    Edge& e = get_or_create_edge(client, ap, EdgeType::AssociatedWith);
    e.last_seen = ts_us;
    ++e.count;
    e.weight = std::min(1.0f + std::log1p(static_cast<float>(e.count)) * 0.15f, 4.0f);

    if (is_new) {
        const Node* cn = get_node(client);
        const Node* an = get_node(ap);
        std::fprintf(stderr, "[new_assoc] client=%s  <-->  ap=%s\n",
                     cn ? cn->label.c_str() : "?",
                     an ? an->label.c_str() : "?");
    }
}

void Graph::update_similarity(NodeId a, NodeId b, float score) {
    if (a == b) return;
    Edge& e = get_or_create_edge(a, b, EdgeType::SimilarTo);
    e.weight = score;
    e.last_seen = 0; // not time-based
}

void Graph::add_fingerprint_match(NodeId a, NodeId b) {
    if (a == b) return;
    bool is_new = (edge_index_.find(edge_key(a, b, EdgeType::FingerprintMatch)) == edge_index_.end());
    Edge& e = get_or_create_edge(a, b, EdgeType::FingerprintMatch);
    e.weight = 3.0f;
    if (is_new) {
        const Node* na = get_node(a);
        const Node* nb = get_node(b);
        std::fprintf(stderr, "[fingerprint_match] %s  <-->  %s  fp=%s\n",
                     na ? na->label.c_str() : "?",
                     nb ? nb->label.c_str() : "?",
                     na ? na->radio_fingerprint.c_str() : "?");
    }
}

void Graph::mark_colocated(NodeId a, NodeId b) {
    if (a == b) return;
    bool is_new = (edge_index_.find(edge_key(a, b, EdgeType::SeenNear)) == edge_index_.end());
    Edge& e = get_or_create_edge(a, b, EdgeType::SeenNear);
    e.weight = 2.0f;
    ++e.count;
    if (is_new) {
        const Node* na = get_node(a);
        const Node* nb = get_node(b);
        std::fprintf(stderr, "[colocated] %s  <-->  %s\n",
                     na ? na->label.c_str() : "?",
                     nb ? nb->label.c_str() : "?");
    }
}

void Graph::process_frame(const ParsedFrame& frame) {
    switch (frame.kind) {
    case FrameKind::ProbeRequest: {
        if (frame.src.is_zero() || frame.src.is_multicast()) break;
        NodeId cid = get_or_create_client(frame.src, frame.ts_us, frame.rssi);
        if (frame.ssid.has_value() && !frame.ssid->empty()) {
            NodeId sid = get_or_create_ssid(*frame.ssid, frame.ts_us);
            add_probe(cid, sid, frame.ts_us, frame.rssi);
        }
        // Update radio fingerprint — upgrade if new one has more capabilities (longer string)
        if (Node* cn = get_node(cid)) {
            std::string new_fp = build_fingerprint(frame);
            if (new_fp.size() > cn->radio_fingerprint.size()) {
                cn->radio_fingerprint = new_fp;
                std::fprintf(stderr, "[fp] %s  rates=%u  ht=%d  vht=%d  he=%d  fp='%s'\n",
                             cn->label.c_str(),
                             static_cast<unsigned>(frame.rates.size()),
                             frame.has_ht, frame.has_vht, frame.has_he,
                             cn->radio_fingerprint.c_str());
            }
        }
        break;
    }
    case FrameKind::Beacon:
    case FrameKind::ProbeResponse: {
        if (frame.bssid.is_zero() || frame.bssid.is_multicast()) break;
        NodeId apid = get_or_create_ap(frame.bssid, frame.ts_us, frame.rssi);
        {
            // Use SSID from frame or "<hidden>" placeholder so AP always gets
            // a Broadcasts edge and its channel/security are recorded.
            const std::string ssid_str = (frame.ssid.has_value() && !frame.ssid->empty())
                                       ? *frame.ssid : "<hidden>";
            NodeId sid = get_or_create_ssid(ssid_str, frame.ts_us);
            add_beacon(apid, sid, frame.channel, frame.ht_oper_offset, frame.security, frame.ts_us);
        }
        // For ProbeResponse: the client dst
        if (frame.kind == FrameKind::ProbeResponse &&
            !frame.dst.is_zero() && !frame.dst.is_multicast()) {
            NodeId cid = get_or_create_client(frame.dst, frame.ts_us, -100);
            if (frame.ssid.has_value() && !frame.ssid->empty()) {
                NodeId sid = get_or_create_ssid(*frame.ssid, frame.ts_us);
                add_probe(cid, sid, frame.ts_us, frame.rssi);
            }
        }
        break;
    }
    case FrameKind::Auth:
    case FrameKind::Deauth:
    case FrameKind::Disassoc:
    case FrameKind::AssocRequest:
    case FrameKind::AssocResponse: {
        // Auth/Deauth/Assoc frames link a client directly to an AP (src ↔ bssid)
        if (!frame.src.is_zero() && !frame.src.is_multicast()
            && !frame.bssid.is_zero() && !frame.bssid.is_multicast()) {
            NodeId cid  = get_or_create_client(frame.src,   frame.ts_us, frame.rssi);
            NodeId apid = get_or_create_ap(frame.bssid, frame.ts_us, -100);
            add_associated(cid, apid, frame.ts_us);
            // AssocRequest carries client capabilities — upgrade if better
            if (frame.kind == FrameKind::AssocRequest) {
                if (Node* cn = get_node(cid)) {
                    std::string new_fp = build_fingerprint(frame);
                    if (new_fp.size() > cn->radio_fingerprint.size())
                        cn->radio_fingerprint = new_fp;
                }
            }
        }
        break;
    }
    case FrameKind::Data: {
        // Only handle infrastructure mode (ToDS or FromDS)
        if (frame.ds_flags == 0) break;
        if (frame.bssid.is_zero() || frame.bssid.is_multicast()) break;

        NodeId apid = get_or_create_ap(frame.bssid, frame.ts_us, frame.rssi);

        if (frame.ds_flags == 1) {
            // ToDS: src is the client sending to AP
            if (!frame.src.is_zero() && !frame.src.is_multicast()) {
                NodeId cid = get_or_create_client(frame.src, frame.ts_us, frame.rssi);
                add_associated(cid, apid, frame.ts_us);
            }
        } else {
            // FromDS: dst is the client receiving from AP
            if (!frame.dst.is_zero() && !frame.dst.is_multicast()) {
                NodeId cid = get_or_create_client(frame.dst, frame.ts_us, -100);
                add_associated(cid, apid, frame.ts_us);
            }
        }
        break;
    }
    default:
        break;
    }
}

void Graph::mark_active(uint64_t now_us, uint64_t window_us) {
    // Device is "stationary" (regularly present) if seen many times over ≥10 minutes
    constexpr uint32_t STATIONARY_MIN_COUNT   = 20;
    constexpr uint64_t STATIONARY_MIN_SPAN_US = 10ULL * 60 * 1'000'000; // 10 min

    for (auto& [id, n] : nodes_) {
        n.is_active = (now_us - n.last_seen) <= window_us;
        n.is_stationary = (n.seen_count >= STATIONARY_MIN_COUNT)
                       && (n.last_seen - n.first_seen >= STATIONARY_MIN_SPAN_US);
    }
}

std::unordered_map<NodeId, uint32_t> Graph::ssid_probe_frequency() const {
    std::unordered_map<NodeId, uint32_t> freq;
    for (auto& [id, n] : nodes_) {
        if (n.type == NodeType::Client) {
            for (NodeId sid : n.probed_ssids)
                ++freq[sid];
        }
    }
    return freq;
}

std::vector<std::pair<NodeId, NodeId>> Graph::compute_similarities() {
    // Collect clients
    std::vector<NodeId> clients;
    for (auto& [id, n] : nodes_)
        if (n.type == NodeType::Client && !n.probed_ssids.empty())
            clients.push_back(id);

    auto freq = ssid_probe_frequency();
    // Build rarity weights: w(ssid) = 1 / freq[ssid]
    std::unordered_map<NodeId, float> weights;
    for (auto& [sid, f] : freq)
        weights[sid] = f > 0 ? 1.0f / static_cast<float>(f) : 1.0f;

    std::vector<std::pair<NodeId, NodeId>> result;

    for (size_t i = 0; i < clients.size(); ++i) {
        for (size_t j = i + 1; j < clients.size(); ++j) {
            NodeId a = clients[i], b = clients[j];
            const auto& sa = nodes_.at(a).probed_ssids;
            const auto& sb = nodes_.at(b).probed_ssids;

            // Weighted Jaccard
            float inter = 0.0f, union_w = 0.0f;
            for (NodeId sid : sa) {
                float w = weights.count(sid) ? weights.at(sid) : 1.0f;
                union_w += w;
                if (sb.count(sid)) inter += w;
            }
            for (NodeId sid : sb) {
                if (!sa.count(sid)) {
                    float w = weights.count(sid) ? weights.at(sid) : 1.0f;
                    union_w += w;
                }
            }

            float score = (union_w > 0.0f) ? inter / union_w : 0.0f;
            if (score > 0.3f) {
                update_similarity(a, b, score);
                result.emplace_back(a, b);
            }
        }
    }
    return result;
}

Node* Graph::get_node(NodeId id) {
    auto it = nodes_.find(id);
    return (it != nodes_.end()) ? &it->second : nullptr;
}

const Node* Graph::get_node(NodeId id) const {
    auto it = nodes_.find(id);
    return (it != nodes_.end()) ? &it->second : nullptr;
}

void Graph::set_alias(NodeId id, const std::string& alias) {
    auto it = nodes_.find(id);
    if (it != nodes_.end()) it->second.alias = alias;
}
