#pragma once
#include "types.hpp"
#include <cstdint>
#include <cstddef>

// Parse an 802.11 frame (without radiotap header).
// data points to the first byte of the 802.11 frame control field.
// Returns true if the frame was successfully parsed into out.
bool parse_dot11(const uint8_t* data, size_t len, ParsedFrame& out);
