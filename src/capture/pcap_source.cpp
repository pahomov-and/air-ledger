#include "pcap_source.hpp"
#include "parser/radiotap.hpp"
#include <cstring>
#include <cstdio>
#include <string>

PcapSource::~PcapSource() {
    stop();
}

bool PcapSource::open(const std::string& iface, std::function<void(RawFrame)> callback) {
    callback_ = std::move(callback);

    char errbuf[PCAP_ERRBUF_SIZE]{};

    // Detect if it's a file (ends with .pcap or .pcapng)
    bool is_file = (iface.size() > 5 &&
                    (iface.substr(iface.size() - 5) == ".pcap" ||
                     iface.substr(iface.size() - 7) == ".pcapng"));

    if (is_file) {
        handle_ = pcap_open_offline(iface.c_str(), errbuf);
        if (!handle_) {
            std::fprintf(stderr, "[pcap] Cannot open file %s: %s\n", iface.c_str(), errbuf);
            return false;
        }
    } else {
        handle_ = pcap_open_live(iface.c_str(), 65535, 1, 100 /*ms timeout*/, errbuf);
        if (!handle_) {
            std::fprintf(stderr, "[pcap] Cannot open interface %s: %s\n", iface.c_str(), errbuf);
            return false;
        }

        // Set non-blocking so we can check running_ flag
        if (pcap_setnonblock(handle_, 1, errbuf) < 0) {
            std::fprintf(stderr, "[pcap] setnonblock warning: %s\n", errbuf);
        }
    }

    int dlt = pcap_datalink(handle_);
    if (dlt != DLT_IEEE802_11_RADIO && dlt != DLT_IEEE802_11) {
        std::fprintf(stderr, "[pcap] Warning: unexpected DLT %d (%s). Expected radiotap (127) or raw 802.11 (105).\n",
                     dlt, pcap_datalink_val_to_name(dlt));
        // Don't fail — maybe the user knows what they're doing
    }

    return true;
}

void PcapSource::start() {
    if (!handle_) return;
    running_.store(true);

    while (running_.load()) {
        int rc = pcap_dispatch(handle_, 64,
                               &PcapSource::packet_handler,
                               reinterpret_cast<u_char*>(this));
        if (rc == PCAP_ERROR_BREAK) break;
        if (rc == PCAP_ERROR) {
            std::fprintf(stderr, "[pcap] Error: %s\n", pcap_geterr(handle_));
            break;
        }
        if (rc == 0) {
            // No packets — small sleep to avoid busy spin in non-blocking mode
            struct timespec ts{0, 5'000'000}; // 5 ms
            nanosleep(&ts, nullptr);
        }
    }
    running_.store(false);
}

void PcapSource::stop() {
    running_.store(false);
    if (handle_) {
        pcap_breakloop(handle_);
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

void PcapSource::packet_handler(u_char* user,
                                const struct pcap_pkthdr* h,
                                const u_char* bytes)
{
    auto* self = reinterpret_cast<PcapSource*>(user);
    if (!self->running_.load()) return;

    size_t cap_len = h->caplen;
    if (cap_len == 0) return;

    RawFrame frame;
    frame.ts_us = static_cast<uint64_t>(h->ts.tv_sec) * 1'000'000
                + static_cast<uint64_t>(h->ts.tv_usec);
    frame.data.assign(bytes, bytes + cap_len);

    // Try to extract rssi/freq from radiotap header up front
    // so the main thread doesn't need to re-parse it later
    uint16_t rt_len = 0;
    int8_t rssi = -100;
    uint16_t freq = 0;
    if (cap_len >= 8 && bytes[0] == 0) {
        parse_radiotap(bytes, cap_len, rssi, freq, rt_len);
    }
    frame.rssi = rssi;
    frame.freq_mhz = freq;
    // Simple channel from frequency
    if (freq >= 2412 && freq <= 2484) {
        frame.channel = (freq == 2484) ? 14 : (freq - 2407) / 5;
    } else if (freq >= 5180 && freq <= 5885) {
        frame.channel = (freq - 5000) / 5;
    }

    self->callback_(std::move(frame));
}
