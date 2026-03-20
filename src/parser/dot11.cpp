#include "dot11.hpp"
#include <cstring>
#include <algorithm>

static inline uint16_t read_le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

static MacAddr read_mac(const uint8_t* p) {
    MacAddr m;
    std::copy(p, p + 6, m.bytes.begin());
    return m;
}

// Information Element IDs
namespace ie {
    static constexpr uint8_t SSID           = 0;
    static constexpr uint8_t SUPPORTED_RATES= 1;
    static constexpr uint8_t CHANNEL       = 3;
    static constexpr uint8_t HT_CAP        = 45;
    static constexpr uint8_t RSN           = 48;
    static constexpr uint8_t EXT_SUPP_RATES= 50;
    static constexpr uint8_t HT_OPER       = 61;
    static constexpr uint8_t VHT_CAP       = 191;
    static constexpr uint8_t VENDOR        = 221;
    static constexpr uint8_t EXT_TAG       = 255;
}

// RSN cipher / AKM suite selectors
namespace rsn {
    // AKM suites
    static constexpr uint32_t PSK   = 0x000FAC02;
    static constexpr uint32_t SAE   = 0x000FAC08;
    static constexpr uint32_t EAP   = 0x000FAC01;
}

static inline uint32_t read_oui_type(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24)
         | (static_cast<uint32_t>(p[1]) << 16)
         | (static_cast<uint32_t>(p[2]) << 8)
         |  static_cast<uint32_t>(p[3]);
}

struct IEWalker {
    const uint8_t* base;
    size_t total;
    size_t pos;

    bool next(uint8_t& id, uint8_t& elen, const uint8_t*& edata) {
        if (pos + 2 > total) return false;
        id    = base[pos];
        elen  = base[pos + 1];
        if (pos + 2 + elen > total) return false;
        edata = base + pos + 2;
        pos  += 2 + elen;
        return true;
    }
};

// Parse IEs and fill security, SSID, rates, HT/VHT/HE flags
static void parse_ies(const uint8_t* data, size_t len, ParsedFrame& out) {
    bool has_rsn = false;
    bool has_wpa_vendor = false;
    bool has_wpa3 = false;

    IEWalker w{data, len, 0};
    uint8_t id, elen;
    const uint8_t* edata;

    while (w.next(id, elen, edata)) {
        switch (id) {
        case ie::SSID:
            if (elen > 0) {
                // Validate: sometimes SSIDs are binary; we accept anything printable + null
                out.ssid = std::string(reinterpret_cast<const char*>(edata), elen);
            }
            break;

        case ie::SUPPORTED_RATES:
            out.supported_rates_count += elen;
            for (uint8_t i = 0; i < elen; ++i)
                out.rates.push_back(edata[i] & 0x7F); // strip basic-rate bit
            break;

        case ie::EXT_SUPP_RATES:
            out.supported_rates_count += elen;
            for (uint8_t i = 0; i < elen; ++i)
                out.rates.push_back(edata[i] & 0x7F);
            break;

        case ie::CHANNEL:
            if (elen >= 1)
                out.channel = edata[0]; // IE always wins over radiotap frequency
            break;

        case ie::HT_CAP:
            out.has_ht = true;
            if (elen >= 2)
                out.ht_cap_info = read_le16(edata);
            break;

        case ie::HT_OPER:
            // byte 0: primary channel, byte 1: HT Info subset 1
            // bits 0-1 = secondary channel offset: 0=none(HT20), 1=above(HT40+), 3=below(HT40-)
            if (elen >= 2)
                out.ht_oper_offset = edata[1] & 0x03;
            break;

        case ie::VHT_CAP:
            out.has_vht = true;
            if (elen >= 4)
                out.vht_cap_info = static_cast<uint32_t>(edata[0])
                                 | (static_cast<uint32_t>(edata[1]) << 8)
                                 | (static_cast<uint32_t>(edata[2]) << 16)
                                 | (static_cast<uint32_t>(edata[3]) << 24);
            break;

        case ie::RSN: {
            has_rsn = true;
            // Parse AKM suites to distinguish WPA2/WPA3
            // RSN element: version(2) + group_cipher(4) + pairwise_count(2) + pairwise[n*4]
            //              + akm_count(2) + akm[n*4]
            size_t off = 0;
            if (off + 2 > elen) break;
            off += 2; // version
            if (off + 4 > elen) break;
            off += 4; // group cipher
            if (off + 2 > elen) break;
            uint16_t pair_count = read_le16(edata + off);
            off += 2;
            if (off + pair_count * 4u > elen) break;
            off += pair_count * 4u;
            if (off + 2 > elen) break;
            uint16_t akm_count = read_le16(edata + off);
            off += 2;
            for (uint16_t i = 0; i < akm_count && off + 4 <= elen; ++i, off += 4) {
                uint32_t suite = read_oui_type(edata + off);
                if (suite == rsn::SAE) has_wpa3 = true;
            }
            break;
        }

        case ie::VENDOR: {
            // WPA vendor IE: OUI=00:50:f2 type=1
            if (elen >= 4) {
                if (edata[0] == 0x00 && edata[1] == 0x50 && edata[2] == 0xf2 && edata[3] == 0x01)
                    has_wpa_vendor = true;
            }
            break;
        }

        case ie::EXT_TAG: {
            // HE capabilities: ext tag id = 35
            if (elen >= 1 && edata[0] == 35)
                out.has_he = true;
            break;
        }

        default:
            break;
        }
    }

    // Determine security string
    if (has_wpa3) {
        out.security = has_rsn ? "WPA3" : "WPA3";
    } else if (has_rsn) {
        out.security = "WPA2";
    } else if (has_wpa_vendor) {
        out.security = "WPA";
    } else {
        out.security = "Open";
    }
}

bool parse_dot11(const uint8_t* data, size_t len, ParsedFrame& out) {
    // Minimum 802.11 header: FC(2) + Duration(2) + Addr1(6) = 10 bytes minimum
    // For management frames: FC(2) + Dur(2) + Addr1(6) + Addr2(6) + Addr3(6) + SeqCtrl(2) = 24 bytes
    if (len < 10) return false;

    uint16_t fc = read_le16(data);
    uint8_t type    = (fc >> 2) & 0x03;
    uint8_t subtype = (fc >> 4) & 0x0F;

    // We handle management frames (type=0) and peek at data frames (type=2)
    if (type == 0) {
        // Management frame — need full 24-byte header
        if (len < 24) return false;

        MacAddr addr1 = read_mac(data + 4);
        MacAddr addr2 = read_mac(data + 10);
        MacAddr addr3 = read_mac(data + 16);

        out.src   = addr2;
        out.dst   = addr1;
        out.bssid = addr3;

        size_t fixed_offset = 24;

        switch (subtype) {
        case 0: out.kind = FrameKind::AssocRequest;  break;
        case 1: out.kind = FrameKind::AssocResponse; break;
        case 4: out.kind = FrameKind::ProbeRequest;  break;
        case 5: out.kind = FrameKind::ProbeResponse; break;
        case 8: out.kind = FrameKind::Beacon;        break;
        case 10: out.kind = FrameKind::Disassoc;     break;
        case 11: out.kind = FrameKind::Auth;         break;
        case 12: out.kind = FrameKind::Deauth;       break;
        default: out.kind = FrameKind::Unknown;      break;
        }

        // Frames with fixed fields before IEs:
        // Beacon / ProbeResponse: timestamp(8) + beacon_interval(2) + capability(2) = 12 bytes
        // ProbeRequest: no fixed fields before IEs
        // AssocRequest: capability(2) + listen_interval(2) = 4 bytes
        // AssocResponse: capability(2) + status(2) + assoc_id(2) = 6 bytes

        size_t ie_offset = fixed_offset;

        if (out.kind == FrameKind::Beacon || out.kind == FrameKind::ProbeResponse) {
            if (fixed_offset + 12 > len) return false;
            out.beacon_interval = read_le16(data + fixed_offset + 8);
            ie_offset = fixed_offset + 12;
        } else if (out.kind == FrameKind::AssocRequest) {
            ie_offset = fixed_offset + 4;
        } else if (out.kind == FrameKind::AssocResponse) {
            ie_offset = fixed_offset + 6;
        }
        // ProbeRequest, Auth, Deauth, Disassoc: no fixed fields

        if (ie_offset <= len) {
            parse_ies(data + ie_offset, len - ie_offset, out);
            std::sort(out.rates.begin(), out.rates.end());
        }

        return true;

    } else if (type == 2) {
        // Data frame — decode addresses based on ToDS/FromDS bits
        if (len < 24) return false;
        out.kind = FrameKind::Data;

        // ToDS = bit 8 of FC, FromDS = bit 9
        uint8_t to_ds   = (fc >> 8) & 1;
        uint8_t from_ds = (fc >> 9) & 1;

        MacAddr addr1 = read_mac(data + 4);
        MacAddr addr2 = read_mac(data + 10);
        MacAddr addr3 = read_mac(data + 16);

        if (to_ds && !from_ds) {
            // Client → AP: addr1=BSSID(AP), addr2=SA(client), addr3=DA
            out.bssid    = addr1;
            out.src      = addr2; // client (transmitter)
            out.dst      = addr3;
            out.ds_flags = 1;     // ToDS
        } else if (!to_ds && from_ds) {
            // AP → Client: addr1=DA(client), addr2=BSSID(AP), addr3=SA
            out.bssid    = addr2;
            out.src      = addr3; // original source
            out.dst      = addr1; // client (receiver)
            out.ds_flags = 2;     // FromDS
        } else {
            // IBSS or WDS — addr3 is BSSID
            out.dst      = addr1;
            out.src      = addr2;
            out.bssid    = addr3;
            out.ds_flags = 0;
        }

        // EAPOL detection (WPA 4-way handshake).
        // Skip encrypted frames — EAPOL key exchange is always plaintext (Protected=0).
        bool protected_frame = (fc >> 14) & 1;
        if (!protected_frame) {
            // 802.11 header: 24 bytes for Data, 26 for QoS Data (subtype & 0x08),
            // +4 if both ToDS and FromDS (Addr4). Protected frames already excluded above.
            size_t hdr = 24u;
            if (subtype & 0x08) hdr += 2; // QoS Control
            if (to_ds && from_ds) hdr += 6; // Addr4

            // LLC/SNAP: AA AA 03 | OUI 00 00 00 | EtherType (2)
            if (hdr + 8 <= len
                    && data[hdr]   == 0xAA && data[hdr+1] == 0xAA && data[hdr+2] == 0x03
                    && data[hdr+3] == 0x00 && data[hdr+4] == 0x00 && data[hdr+5] == 0x00) {
                uint16_t etype = (static_cast<uint16_t>(data[hdr+6]) << 8) | data[hdr+7];
                if (etype == 0x888E) {
                    out.is_eapol = true;
                    // EAPOL header: version(1) type(1) length(2) — type 0x03 = Key
                    size_t ep = hdr + 8;
                    if (ep + 4 <= len && data[ep+1] == 0x03 /*EAPOL-Key*/) {
                        size_t kp = ep + 4; // key body starts here
                        // Descriptor(1) | KeyInfo(2 BE) | KeyLen(2) | Replay(8) | Nonce(32)
                        if (kp + 13 + 32 <= len) {
                            uint16_t ki = (static_cast<uint16_t>(data[kp+1]) << 8)
                                         | data[kp+2];
                            bool key_ack = (ki >> 7) & 1;  // bit 7
                            bool key_mic = (ki >> 8) & 1;  // bit 8
                            bool nonce_zero = true;
                            for (int i = 0; i < 32 && nonce_zero; ++i)
                                if (data[kp + 13 + i]) nonce_zero = false;
                            if      ( key_ack && !key_mic)                out.eapol_msg = 1;
                            else if (!key_ack &&  key_mic && !nonce_zero) out.eapol_msg = 2;
                            else if ( key_ack &&  key_mic)                out.eapol_msg = 3;
                            else if (!key_ack &&  key_mic &&  nonce_zero) out.eapol_msg = 4;
                        }
                    }
                }
            }
        }

        return true;
    }

    // Control frames etc. — not interesting
    return false;
}
