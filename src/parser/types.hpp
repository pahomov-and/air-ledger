#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <span>
#include <format>

struct MacAddr {
    std::array<uint8_t, 6> bytes{};

    bool is_zero() const {
        for (auto b : bytes) if (b != 0) return false;
        return true;
    }

    bool is_multicast() const {
        return (bytes[0] & 0x01) != 0;
    }

    // locally administered bit = bit 1 of first octet
    bool is_locally_administered() const {
        return (bytes[0] & 0x02) != 0;
    }

    std::string to_string() const {
        return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    }

    bool operator==(const MacAddr&) const = default;
};

struct MacAddrHash {
    std::size_t operator()(const MacAddr& m) const noexcept {
        uint64_t v = 0;
        for (int i = 0; i < 6; ++i)
            v = v * 257 + m.bytes[i];
        return std::hash<uint64_t>{}(v);
    }
};

struct RawFrame {
    uint64_t ts_us{0};
    int8_t rssi{-100};
    uint16_t freq_mhz{0};
    uint16_t channel{0};
    std::vector<uint8_t> data; // full frame including radiotap
};

enum class FrameKind : uint8_t {
    Beacon,
    ProbeRequest,
    ProbeResponse,
    AssocRequest,
    AssocResponse,
    Auth,
    Deauth,
    Disassoc,
    Data,
    Unknown
};

inline const char* frame_kind_name(FrameKind k) {
    switch (k) {
        case FrameKind::Beacon:        return "Beacon";
        case FrameKind::ProbeRequest:  return "ProbeRequest";
        case FrameKind::ProbeResponse: return "ProbeResponse";
        case FrameKind::AssocRequest:  return "AssocRequest";
        case FrameKind::AssocResponse: return "AssocResponse";
        case FrameKind::Auth:          return "Auth";
        case FrameKind::Deauth:        return "Deauth";
        case FrameKind::Disassoc:      return "Disassoc";
        case FrameKind::Data:          return "Data";
        default:                       return "Unknown";
    }
}

struct ParsedFrame {
    uint64_t ts_us{0};
    FrameKind kind{FrameKind::Unknown};
    MacAddr src;
    MacAddr dst;
    MacAddr bssid;
    std::optional<std::string> ssid;
    int8_t rssi{-100};
    uint16_t channel{0};
    // Data frame DS direction: 1=ToDS (client→AP), 2=FromDS (AP→client), 0=other
    uint8_t ds_flags{0};
    // capability fingerprint from IEs
    uint8_t supported_rates_count{0};
    bool has_ht{false};
    bool has_vht{false};
    bool has_he{false};
    std::vector<uint8_t> rates;   // actual rate bytes (masked, sorted) from IE1+IE50
    uint16_t ht_cap_info{0};      // HT Capabilities Info field (0 if no HT)
    uint32_t vht_cap_info{0};     // VHT Capabilities Info field (0 if no VHT)
    uint8_t  ht_oper_offset{0};   // HT Operation IE secondary ch offset: 0=HT20, 1=HT40+, 3=HT40-
    // for APs
    uint16_t beacon_interval{0};
    std::string security; // Open/WEP/WPA/WPA2/WPA3
    // EAPOL (WPA 4-way handshake, detected in Data frames)
    bool    is_eapol{false};
    uint8_t eapol_msg{0};  // 1=M1(AP→CLI, ANonce) 2=M2(CLI→AP, MIC) 3=M3 4=M4
};
