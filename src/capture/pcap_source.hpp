#pragma once
#include "capture_source.hpp"
#include "parser/types.hpp"
#include <atomic>
#include <functional>
#include <pcap/pcap.h>

class PcapSource : public CaptureSource {
public:
    PcapSource() = default;
    ~PcapSource() override;

    // Open live capture on iface or open a pcap file if iface ends in ".pcap"/".pcapng"
    bool open(const std::string& iface, std::function<void(RawFrame)> callback) override;
    void start() override; // blocking; call from dedicated thread
    void stop() override;

    bool is_running() const { return running_.load(); }

private:
    pcap_t* handle_{nullptr};
    std::function<void(RawFrame)> callback_;
    std::atomic<bool> running_{false};

    static void packet_handler(u_char* user,
                               const struct pcap_pkthdr* h,
                               const u_char* bytes);
};
