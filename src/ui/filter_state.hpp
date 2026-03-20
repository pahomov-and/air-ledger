#pragma once
#include <string>

// Active filter constraints for graph rendering and sidebar.
// All fields are additive (AND logic).
struct FilterState {
    bool active_only{false};          // only nodes seen in last 5 min
    bool randomized_only{false};      // only randomized MACs (clients)
    bool handshake_clients_only{true}; // clients: hide all except those with captured handshake
    bool probe_only{false};           // clients: show only those with NO AssociatedWith edges (pure probers)
    std::string ssid_filter;          // empty = show all; substring match on SSID name
    std::string vendor_filter;        // empty = show all; substring match on vendor
    std::string search_query;         // empty = no search; substring match on any text field

    bool is_empty() const {
        return !active_only && !randomized_only && !handshake_clients_only && !probe_only
            && ssid_filter.empty() && vendor_filter.empty()
            && search_query.empty();
    }
};
