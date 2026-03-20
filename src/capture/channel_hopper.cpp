#include "channel_hopper.hpp"
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>
#include <signal.h>

// Run a shell command safely even when SIGCHLD=SIG_IGN.
// system() calls waitpid() internally; with SIGCHLD=SIG_IGN the child is
// auto-reaped and waitpid returns ECHILD → system returns -1.
// Workaround: temporarily reset SIGCHLD to SIG_DFL around the system() call.
static int safe_system(const char* cmd) {
    struct sigaction sa_dfl{}, sa_old{};
    sa_dfl.sa_handler = SIG_DFL;
    sigaction(SIGCHLD, &sa_dfl, &sa_old);
    int rc = system(cmd); // NOLINT
    sigaction(SIGCHLD, &sa_old, nullptr);
    return rc;
}

// Non-overlapping order: hit 1/6/11 first, then fill the rest
const std::vector<int> ChannelHopper::CHANNELS_2GHZ = {
    1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13
};

// Non-DFS first (most common home/office use), DFS last
const std::vector<int> ChannelHopper::CHANNELS_5GHZ = {
    // UNII-1 (non-DFS)
    36, 40, 44, 48,
    // UNII-3 (non-DFS, very popular)
    149, 153, 157, 161, 165,
    // UNII-2A (DFS — may be restricted by regulatory domain)
    52, 56, 60, 64,
    // UNII-2C (DFS)
    100, 104, 108, 112, 116, 132, 136, 140
};

// Returns the iw HT-mode string for a given HT Operation secondary ch offset.
// ht_oper=0 means "no HT info / HT20" — we intentionally don't add any flag
// so that the hopper works without HT20 (which some drivers reject when hopping).
// Only HT40+ / HT40- are set explicitly, as they change which frequencies are used.
static const char* ht_mode_str(int ch, uint8_t ht_oper) {
    if (ch > 14) return "";   // 5 GHz: let iw decide width
    if (ht_oper == 1) return "HT40+";
    if (ht_oper == 3) return "HT40-";
    return "";                // HT20 or unknown: no flag needed, adapter receives HT20 fine
}

void ChannelHopper::set_channel(int ch, uint8_t ht_oper) {
    std::lock_guard<std::mutex> lk(ch_mutex_);
    char cmd[128];
    const char* ht = ht_mode_str(ch, ht_oper);
    if (ht[0])
        std::snprintf(cmd, sizeof(cmd),
            "iw dev %s set channel %d %s 2>/dev/null", iface_.c_str(), ch, ht);
    else
        std::snprintf(cmd, sizeof(cmd),
            "iw dev %s set channel %d 2>/dev/null", iface_.c_str(), ch);
    int rc = safe_system(cmd);
    if (rc != 0)
        std::fprintf(stderr, "[hopper] iw failed ch=%d ht=%s rc=%d\n", ch, ht, rc);
    current_ch_.store(ch);
}

bool ChannelHopper::probe_5ghz_support(const std::string& iface) {
    // Step 1: get the phy name via sysfs (most reliable, works in monitor mode too)
    char phy_path[128];
    std::snprintf(phy_path, sizeof(phy_path),
                  "/sys/class/net/%s/phy80211/name", iface.c_str());
    FILE* f = std::fopen(phy_path, "r");
    if (!f) {
        std::fprintf(stderr, "[hopper] cannot read %s\n", phy_path);
        return false;
    }
    char phy_name[32] = {};
    bool got = (std::fgets(phy_name, sizeof(phy_name), f) != nullptr);
    std::fclose(f);
    if (!got || phy_name[0] == '\0') return false;
    // Strip trailing newline
    phy_name[std::strcspn(phy_name, "\n\r")] = '\0';

    // Step 2: check if that phy lists any 5 GHz frequency.
    // iw formats them as "5180.0 MHz" — match the decimal form.
    char cmd[256];
    std::snprintf(cmd, sizeof(cmd),
        "iw phy %s info 2>/dev/null | grep -q '5[0-9][0-9][0-9]\\.'", phy_name);
    int rc = safe_system(cmd);
    bool supported = (rc == 0);
    std::fprintf(stderr, "[hopper] %s 5 GHz support: %s\n",
                 phy_name, supported ? "YES" : "no");
    return supported;
}

void ChannelHopper::lock_channel(int ch, uint8_t ht_oper) {
    locked_ht_oper_.store(ht_oper);
    locked_ch_.store(ch);
    if (ch != 0) {
        set_channel(ch, ht_oper);
        std::fprintf(stderr, "[hopper] locked to ch=%d %s\n", ch, ht_mode_str(ch, ht_oper));
    } else {
        std::fprintf(stderr, "[hopper] unlocked — resuming hop\n");
    }
}

void ChannelHopper::loop() {
    size_t idx = 0;
    while (running_.load()) {
        int lock = locked_ch_.load();
        if (lock != 0) {
            // Stay on locked channel, just sleep and re-apply in case iw was reset
            set_channel(lock, locked_ht_oper_.load());
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }
        int ch = active_channels_[idx % active_channels_.size()];
        set_channel(ch);
        std::this_thread::sleep_for(std::chrono::milliseconds(dwell_ms_.load()));
        ++idx;
    }
}

bool ChannelHopper::start(const std::string& iface, int dwell_ms) {
    if (running_.load()) return true;
    iface_    = iface;
    dwell_ms_ = dwell_ms;

    // Build channel list: always 2.4 GHz; add 5 GHz if the phy supports it
    active_channels_ = CHANNELS_2GHZ;
    has_5ghz_ = probe_5ghz_support(iface);
    if (has_5ghz_) {
        active_channels_.insert(active_channels_.end(),
                                CHANNELS_5GHZ.begin(), CHANNELS_5GHZ.end());
        std::fprintf(stderr, "[hopper] 5 GHz enabled — %zu total channels\n",
                     active_channels_.size());
    } else {
        std::fprintf(stderr, "[hopper] 2.4 GHz only — %zu channels\n",
                     active_channels_.size());
    }

    running_.store(true);
    thread_ = std::thread([this] { loop(); });
    return true;
}

void ChannelHopper::stop() {
    running_.store(false);
    if (thread_.joinable()) thread_.join();
}
