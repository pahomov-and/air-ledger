#include "radiotap.hpp"
#include <cstring>

// Radiotap field indices in the present bitmap
namespace rt {
    static constexpr uint32_t TSFT         = (1u << 0);
    static constexpr uint32_t FLAGS        = (1u << 1);
    static constexpr uint32_t RATE         = (1u << 2);
    static constexpr uint32_t CHANNEL      = (1u << 3);
    static constexpr uint32_t FHSS         = (1u << 4);
    static constexpr uint32_t ANT_SIGNAL   = (1u << 5);
    static constexpr uint32_t ANT_NOISE    = (1u << 6);
    static constexpr uint32_t LOCK_QUAL    = (1u << 7);
    static constexpr uint32_t TX_ATTEN    = (1u << 8);
    static constexpr uint32_t DB_TX_ATTEN = (1u << 9);
    static constexpr uint32_t DBM_TX_POWER= (1u << 10);
    static constexpr uint32_t ANTENNA      = (1u << 11);
    static constexpr uint32_t DB_ANT_SIG   = (1u << 12);
    static constexpr uint32_t DB_ANT_NOISE = (1u << 13);
    static constexpr uint32_t EXT          = (1u << 31); // more present words follow
}

static inline uint16_t read_le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}
static inline uint32_t read_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

// Align offset to given alignment (power of two)
static inline size_t align_to(size_t offset, size_t alignment) {
    return (offset + alignment - 1) & ~(alignment - 1);
}

bool parse_radiotap(const uint8_t* data, size_t len,
                    int8_t& rssi, uint16_t& freq_mhz, uint16_t& radiotap_len)
{
    rssi = -100;
    freq_mhz = 0;
    radiotap_len = 0;

    // Minimum radiotap header: 8 bytes (version, pad, len, present)
    if (len < 8) return false;
    if (data[0] != 0) return false; // version must be 0

    uint16_t hdr_len = read_le16(data + 2);
    if (hdr_len < 8 || hdr_len > len) return false;
    radiotap_len = hdr_len;

    // Collect all present words (they can be chained via EXT bit)
    // We only need the first present word for the standard fields.
    // Chained words describe additional vendor namespaces; we walk only word 0.
    size_t present_offset = 4;
    uint32_t present = read_le32(data + present_offset);
    // Count how many present words there are so we know where fields start
    size_t field_start = 4;
    {
        uint32_t pw = present;
        while (pw & rt::EXT) {
            field_start += 4;
            if (field_start + 4 > hdr_len) break;
            pw = read_le32(data + field_start);
        }
        field_start += 4; // skip the last present word
    }

    size_t pos = field_start;

    // Walk fields in the order defined by bit position in present word 0
    // We only need TSFT, FLAGS, RATE, CHANNEL, ANT_SIGNAL

    if (present & rt::TSFT) {
        pos = align_to(pos, 8);
        pos += 8;
    }
    if (present & rt::FLAGS) {
        if (pos >= hdr_len) return true;
        pos += 1;
    }
    if (present & rt::RATE) {
        if (pos >= hdr_len) return true;
        pos += 1;
    }
    if (present & rt::CHANNEL) {
        pos = align_to(pos, 2);
        if (pos + 4 > hdr_len) return true;
        freq_mhz = read_le16(data + pos);
        pos += 4; // freq(2) + flags(2)
    }
    if (present & rt::FHSS) {
        if (pos + 2 > hdr_len) return true;
        pos += 2;
    }
    if (present & rt::ANT_SIGNAL) {
        if (pos >= hdr_len) return true;
        rssi = static_cast<int8_t>(data[pos]);
        pos += 1;
    }

    return true;
}
