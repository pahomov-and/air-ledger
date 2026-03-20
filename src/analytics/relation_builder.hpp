#pragma once
#include "entity/graph.hpp"

// RelationBuilder analyzes the graph and updates similarity edges between clients.
class RelationBuilder {
public:
    explicit RelationBuilder(Graph& graph);

    // Compute pairwise Jaccard-weighted similarity for all client pairs.
    // Updates SimilarTo edges in graph for pairs with score > threshold.
    // Returns count of similar pairs found.
    int compute_all_similarities(float threshold = 0.3f);

    // Detect co-located APs (same physical router, adjacent BSSIDs).
    // Adds SeenNear edges between them.
    int compute_ap_colocation();

    // Detect band-paired SSIDs ("Net" / "Net_5G" → same network).
    // Adds SeenNear edges between them.
    int compute_ssid_bandpairs();

    // Detect client handoffs between co-located APs within a time window.
    // Adds SimilarTo edges between clients that switched between radios.
    int compute_client_handoffs(uint64_t window_us = 60'000'000ULL);

    // Detect clients with identical radio capability fingerprints.
    // Adds FingerprintMatch edges between them.
    int compute_fingerprint_matches();

private:
    Graph& graph_;
};
