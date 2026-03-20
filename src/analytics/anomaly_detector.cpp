#include "anomaly_detector.hpp"
#include <algorithm>
#include <format>
#include <cstdio>

bool AnomalyDetector::inc_counter(Counter& c, uint64_t ts_us, uint64_t window_us) {
    if (ts_us - c.window_start_us > window_us) {
        c.window_start_us = ts_us;
        c.count = 1;
        return false;
    }
    ++c.count;
    return true;
}

bool AnomalyDetector::can_emit(AnomalyType type, const std::string& mac, uint64_t ts_us) {
    std::string key = std::to_string(static_cast<int>(type)) + ":" + mac;
    auto it = last_emit_.find(key);
    if (it != last_emit_.end() && ts_us - it->second < COOLDOWN_US) return false;
    last_emit_[key] = ts_us;
    return true;
}

void AnomalyDetector::emit(AnomalyEvent ev) {
    if (!ev.src_mac.empty()) anomaly_counts_[ev.src_mac]++;
    if (!ev.target_mac.empty()) anomaly_counts_[ev.target_mac]++;
    std::fprintf(stderr, "[anomaly/%s] sev=%d  src=%s  %s\n",
        anomaly_type_name(ev.type), ev.severity,
        ev.src_mac.c_str(), ev.description.c_str());
    pending_.push_back(std::move(ev));
}

std::vector<AnomalyEvent> AnomalyDetector::drain() {
    std::vector<AnomalyEvent> out;
    std::swap(out, pending_);
    return out;
}

int AnomalyDetector::anomaly_count(const std::string& mac) const {
    auto it = anomaly_counts_.find(mac);
    return it != anomaly_counts_.end() ? it->second : 0;
}

void AnomalyDetector::process(const ParsedFrame& f, const Graph& graph, uint64_t ts_us) {
    const std::string src = f.src.to_string();

    // ── DeauthFlood / UnexpectedDeauth ───────────────────────────────────────
    if (f.kind == FrameKind::Deauth || f.kind == FrameKind::Disassoc) {
        inc_counter(deauth_ctr_[src], ts_us, DEAUTH_WIN_US);
        if (deauth_ctr_[src].count >= DEAUTH_THRESH
                && can_emit(AnomalyType::DeauthFlood, src, ts_us)) {
            AnomalyEvent ev;
            ev.ts_us      = ts_us;
            ev.type       = AnomalyType::DeauthFlood;
            ev.severity   = 3;
            ev.src_mac    = src;
            ev.target_mac = f.dst.to_string();
            ev.description = std::format("{} deauth/disassoc from {} in 5s",
                deauth_ctr_[src].count, src);
            emit(std::move(ev));
        }

        // Unicast deauth targeting a known-associated client
        if (f.kind == FrameKind::Deauth && !f.dst.is_multicast()) {
            const std::string dst = f.dst.to_string();
            for (auto& [id, n] : graph.nodes()) {
                if (n.type == NodeType::Client && n.label == dst
                        && !n.handshake_aps.empty()
                        && can_emit(AnomalyType::UnexpectedDeauth, src, ts_us)) {
                    AnomalyEvent ev;
                    ev.ts_us      = ts_us;
                    ev.type       = AnomalyType::UnexpectedDeauth;
                    ev.severity   = 2;
                    ev.src_mac    = src;
                    ev.target_mac = dst;
                    ev.description = std::format(
                        "Deauth targeting active client {} from {}", dst, src);
                    emit(std::move(ev));
                    break;
                }
            }
        }
    }

    // ── ProbeFlood ────────────────────────────────────────────────────────────
    if (f.kind == FrameKind::ProbeRequest) {
        inc_counter(probe_ctr_[src], ts_us, PROBE_WIN_US);
        if (probe_ctr_[src].count >= PROBE_THRESH
                && can_emit(AnomalyType::ProbeFlood, src, ts_us)) {
            AnomalyEvent ev;
            ev.ts_us      = ts_us;
            ev.type       = AnomalyType::ProbeFlood;
            ev.severity   = 2;
            ev.src_mac    = src;
            ev.description = std::format(
                "{} probe requests from {} in 10s", probe_ctr_[src].count, src);
            emit(std::move(ev));
        }
    }

    // ── AuthFlood ─────────────────────────────────────────────────────────────
    if (f.kind == FrameKind::Auth) {
        inc_counter(auth_ctr_[src], ts_us, AUTH_WIN_US);
        if (auth_ctr_[src].count >= AUTH_THRESH
                && can_emit(AnomalyType::AuthFlood, src, ts_us)) {
            AnomalyEvent ev;
            ev.ts_us      = ts_us;
            ev.type       = AnomalyType::AuthFlood;
            ev.severity   = 2;
            ev.src_mac    = src;
            ev.target_mac = f.bssid.to_string();
            ev.description = std::format(
                "{} auth frames from {} in 30s — possible WPS/brute-force",
                auth_ctr_[src].count, src);
            emit(std::move(ev));
        }
    }

    // ── EvilTwin ──────────────────────────────────────────────────────────────
    if ((f.kind == FrameKind::Beacon || f.kind == FrameKind::ProbeResponse)
            && f.ssid.has_value() && !f.ssid->empty()) {
        const std::string ssid  = *f.ssid;
        const std::string bssid = f.bssid.to_string();
        const std::string& sec  = f.security;

        auto& known = ssid_aps_[ssid];
        bool already_known = false;
        for (auto& ka : known) {
            if (ka.bssid == bssid) { already_known = true; break; }
            // Same SSID, different BSSID, different security → evil twin candidate
            if (!sec.empty() && !ka.security.empty() && sec != ka.security
                    && can_emit(AnomalyType::EvilTwin, bssid, ts_us)) {
                AnomalyEvent ev;
                ev.ts_us      = ts_us;
                ev.type       = AnomalyType::EvilTwin;
                ev.severity   = 3;
                ev.src_mac    = bssid;
                ev.target_mac = ka.bssid;
                ev.ssid       = ssid;
                ev.description = std::format(
                    "Evil twin? '{}' on {} ({}) vs {} ({})",
                    ssid, bssid, sec, ka.bssid, ka.security);
                emit(std::move(ev));
            }
        }
        if (!already_known)
            known.push_back({bssid, sec});
    }
}
