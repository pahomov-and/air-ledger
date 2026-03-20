#pragma once
#include <cstdint>
#include <cstddef>

// Parse radiotap header and extract signal/frequency info.
// Returns true on success.
// radiotap_len is set to the total length of the radiotap header.
bool parse_radiotap(const uint8_t* data, size_t len,
                    int8_t& rssi, uint16_t& freq_mhz, uint16_t& radiotap_len);
