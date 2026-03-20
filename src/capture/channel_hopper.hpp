#pragma once
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// Cycles through 2.4 GHz (and optionally 5 GHz) channels on a monitor-mode
// interface using `iw`. Runs in its own thread; call start() after capture is open.
class ChannelHopper {
public:
    ~ChannelHopper() { stop(); }

    // dwell_ms: how many ms to stay on each channel before switching
    bool start(const std::string& iface, int dwell_ms = 250);
    void stop();

    bool        is_running()      const { return running_.load(); }
    int         current_channel() const { return current_ch_.load(); }
    int         dwell_ms()        const { return dwell_ms_.load(); }
    bool        has_5ghz()        const { return has_5ghz_; }
    int         channel_count()   const { return static_cast<int>(active_channels_.size()); }

    // Set interface name without starting the hop thread (for channel-lock-only use)
    void set_iface(const std::string& iface) { iface_ = iface; }

    // Change dwell time on the fly (takes effect on next channel switch)
    void set_dwell_ms(int ms) { dwell_ms_.store(std::max(100, std::min(5000, ms))); }

    // Lock to a specific channel (0 = unlock, resume hopping).
    // ht_oper: HT Operation IE secondary ch offset (0=HT20, 1=HT40+, 3=HT40-).
    bool lock_channel(int ch, uint8_t ht_oper = 0);
    bool unlock() { return lock_channel(0); }
    bool is_locked()     const { return locked_ch_.load() != 0; }
    int  locked_channel() const { return locked_ch_.load(); }

    static const std::vector<int> CHANNELS_2GHZ;
    static const std::vector<int> CHANNELS_5GHZ;

private:
    std::string        iface_;
    std::atomic<int>   dwell_ms_{500};
    std::atomic<int>   current_ch_{1};
    std::atomic<bool>  running_{false};
    std::atomic<int>   locked_ch_{0};
    std::atomic<uint8_t> locked_ht_oper_{0}; // HT oper for locked channel
    std::thread        thread_;
    std::mutex         ch_mutex_;  // serialises concurrent set_channel() calls
    bool               has_5ghz_{false};
    std::vector<int>   active_channels_; // built at start() time

    bool set_channel(int ch, uint8_t ht_oper = 0);
    bool iface_on_channel(int ch) const;
    void loop();

    // Returns true if the phy backing iface supports 5 GHz frequencies.
    static bool probe_5ghz_support(const std::string& iface);
};
