#pragma once
#include <string>

// Sends 802.11 deauthentication frames directly via pcap_inject() on a
// monitor-mode interface.  No external tools required.
//
// Frame layout (34 bytes):
//   8  bytes  minimal radiotap header (version=0, len=8, present=0)
//   26 bytes  802.11 deauth: FC=0xC0 | DA=broadcast | SA=BSSID | BSSID | reason=7
class DeauthSender {
public:
    // Inject `count` broadcast deauth frames (from AP `bssid`) on `iface`.
    // Returns true if all frames were sent without pcap error.
    static bool send(const std::string& iface,
                     const std::string& bssid,
                     int count = 5);
};
