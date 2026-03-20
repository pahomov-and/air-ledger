#include "relation_builder.hpp"
#include "similarity.hpp"
#include <vector>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <unordered_map>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static bool parse_mac6(const std::string& s, uint8_t out[6]) {
    unsigned v[6] = {};
    if (std::sscanf(s.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
                    &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) != 6)
        return false;
    for (int i = 0; i < 6; ++i) out[i] = static_cast<uint8_t>(v[i]);
    return true;
}

// Two AP BSSIDs are co-located if they share the same first 4 bytes (OUI + 1 extra).
// This means the last 2 bytes are free to differ — covers dual/tri-band routers
// where each radio gets a nearby but not necessarily consecutive BSSID.
// Example: 40:EE:15:5B:54:E8 (2.4G) and 40:EE:15:5B:54:E4 (5G) → first 4 = 40:EE:15:5B ✓
static bool bssid_colocated(const std::string& a, const std::string& b) {
    uint8_t va[6], vb[6];
    if (!parse_mac6(a, va) || !parse_mac6(b, vb)) return false;
    return va[0] == vb[0] && va[1] == vb[1] && va[2] == vb[2] && va[3] == vb[3];
}

static std::string to_lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Strip a known band suffix and return the base name (empty if no suffix found).
static std::string ssid_strip_band(const std::string& name) {
    static const char* const SUFFIXES[] = {
        "_5ghz", "_5g", "-5ghz", "-5g", " 5ghz", " 5g",
        "_2.4ghz", "_2.4g", "_2g", "-2.4ghz", "-2.4g", "-2g", " 2.4ghz", " 2.4g",
        "_6ghz", "_6g", "-6ghz", "-6g",
        nullptr
    };
    std::string low = to_lower(name);
    for (int i = 0; SUFFIXES[i]; ++i) {
        size_t slen = std::strlen(SUFFIXES[i]);
        if (low.size() > slen && low.substr(low.size() - slen) == SUFFIXES[i])
            return name.substr(0, name.size() - slen);
    }
    return "";
}

RelationBuilder::RelationBuilder(Graph& graph) : graph_(graph) {}

int RelationBuilder::compute_all_similarities(float threshold) {
    // Collect client node IDs that have at least one probed SSID
    std::vector<NodeId> clients;
    for (auto& [id, n] : graph_.nodes()) {
        if (n.type == NodeType::Client && !n.probed_ssids.empty())
            clients.push_back(id);
    }

    // Build SSID rarity weights: w(ssid) = 1 / frequency_across_clients
    auto freq_map = graph_.ssid_probe_frequency();
    std::unordered_map<NodeId, float> weights;
    for (auto& [sid, f] : freq_map)
        weights[sid] = (f > 0) ? 1.0f / static_cast<float>(f) : 1.0f;

    int found = 0;
    for (size_t i = 0; i < clients.size(); ++i) {
        for (size_t j = i + 1; j < clients.size(); ++j) {
            NodeId a = clients[i];
            NodeId b = clients[j];

            const auto* na = graph_.get_node(a);
            const auto* nb = graph_.get_node(b);
            if (!na || !nb) continue;

            float score = jaccard_weighted(na->probed_ssids, nb->probed_ssids, weights);
            if (score > threshold) {
                graph_.update_similarity(a, b, score);
                ++found;
            }
        }
    }

    // Also run structural correlations
    compute_ap_colocation();
    compute_ssid_bandpairs();
    // found += compute_client_handoffs(); // temporal handoff — too many false positives
    found += compute_fingerprint_matches();

    return found;
}

int RelationBuilder::compute_ap_colocation() {
    std::vector<NodeId> aps;
    for (auto& [id, n] : graph_.nodes())
        if (n.type == NodeType::AP) aps.push_back(id);

    int found = 0;
    for (size_t i = 0; i < aps.size(); ++i) {
        for (size_t j = i + 1; j < aps.size(); ++j) {
            const Node* na = graph_.get_node(aps[i]);
            const Node* nb = graph_.get_node(aps[j]);
            if (!na || !nb) continue;
            if (bssid_colocated(na->label, nb->label)) {
                graph_.mark_colocated(aps[i], aps[j]);
                ++found;
            }
        }
    }
    return found;
}

int RelationBuilder::compute_ssid_bandpairs() {
    std::vector<NodeId> ssids;
    for (auto& [id, n] : graph_.nodes())
        if (n.type == NodeType::SSID) ssids.push_back(id);

    int found = 0;
    for (size_t i = 0; i < ssids.size(); ++i) {
        for (size_t j = i + 1; j < ssids.size(); ++j) {
            const Node* na = graph_.get_node(ssids[i]);
            const Node* nb = graph_.get_node(ssids[j]);
            if (!na || !nb) continue;

            std::string la = to_lower(na->label);
            std::string lb = to_lower(nb->label);

            // Match if one is the stripped base of the other,
            // or both share the same stripped base.
            std::string ba = to_lower(ssid_strip_band(na->label));
            std::string bb = to_lower(ssid_strip_band(nb->label));

            bool match = (!ba.empty() && ba == lb)
                      || (!bb.empty() && bb == la)
                      || (!ba.empty() && !bb.empty() && ba == bb);
            if (match) {
                graph_.mark_colocated(ssids[i], ssids[j]);
                ++found;
            }
        }
    }
    return found;
}

int RelationBuilder::compute_fingerprint_matches() {
    // Only use strong fingerprints — must contain HT or HE capabilities.
    // Rate-only fingerprints are too generic (all 802.11n devices share basic OFDM rates).
    auto is_strong = [](const std::string& fp) {
        return fp.find("|HT:") != std::string::npos
            || fp.find("|HE")  != std::string::npos;
    };

    std::unordered_map<std::string, std::vector<NodeId>> by_fp;
    for (auto& [id, n] : graph_.nodes()) {
        if (n.type != NodeType::Client) continue;
        if (!is_strong(n.radio_fingerprint)) continue;
        by_fp[n.radio_fingerprint].push_back(id);
    }

    int found = 0;
    for (auto& [fp, ids] : by_fp) {
        if (ids.size() < 2) continue;
        // All pairs with this fingerprint get a FingerprintMatch edge
        for (size_t i = 0; i < ids.size(); ++i) {
            for (size_t j = i + 1; j < ids.size(); ++j) {
                graph_.add_fingerprint_match(ids[i], ids[j]);
                ++found;
            }
        }
    }
    return found;
}

int RelationBuilder::compute_client_handoffs(uint64_t window_us) {
    // Find co-located AP pairs via SeenNear edges
    std::vector<std::pair<NodeId, NodeId>> coloc;
    for (auto& e : graph_.edges()) {
        if (e.type != EdgeType::SeenNear) continue;
        const Node* na = graph_.get_node(e.a);
        const Node* nb = graph_.get_node(e.b);
        if (na && nb && na->type == NodeType::AP && nb->type == NodeType::AP)
            coloc.emplace_back(e.a, e.b);
    }
    if (coloc.empty()) return 0;

    // ap_id → list of (client_id, last_seen_ts)
    std::unordered_map<NodeId, std::vector<std::pair<NodeId, uint64_t>>> ap_clients;
    for (auto& e : graph_.edges()) {
        if (e.type != EdgeType::AssociatedWith) continue;
        const Node* na = graph_.get_node(e.a);
        const Node* nb = graph_.get_node(e.b);
        if (!na || !nb) continue;
        NodeId cid = 0, apid = 0;
        if (na->type == NodeType::Client && nb->type == NodeType::AP)
            { cid = e.a; apid = e.b; }
        else if (nb->type == NodeType::Client && na->type == NodeType::AP)
            { cid = e.b; apid = e.a; }
        else continue;
        ap_clients[apid].emplace_back(cid, e.last_seen);
    }

    int found = 0;
    for (auto& [ap1, ap2] : coloc) {
        auto it1 = ap_clients.find(ap1);
        auto it2 = ap_clients.find(ap2);
        if (it1 == ap_clients.end() || it2 == ap_clients.end()) continue;

        for (auto& [c1, t1] : it1->second) {
            for (auto& [c2, t2] : it2->second) {
                if (c1 == c2) continue;
                uint64_t delta = (t1 > t2) ? (t1 - t2) : (t2 - t1);
                if (delta > window_us) continue;
                // Score: 0.9 at delta=0, 0.5 at delta=window
                float score = 0.5f + 0.4f * (1.0f - static_cast<float>(delta)
                                              / static_cast<float>(window_us));
                graph_.update_similarity(c1, c2, score);
                ++found;
            }
        }
    }
    return found;
}
