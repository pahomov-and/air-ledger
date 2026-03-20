#pragma once
#include "parser/types.hpp"
#include <string>

// Look up OUI vendor string for a MAC address.
// Returns empty string if unknown.
std::string lookup_oui(const MacAddr& mac);
