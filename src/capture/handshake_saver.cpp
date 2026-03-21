#include "handshake_saver.hpp"
#include "capture/wpa_crack.hpp"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

// ---------------------------------------------------------------------------
// PCAP constants
// ---------------------------------------------------------------------------
static constexpr uint32_t PCAP_MAGIC       = 0xA1B2C3D4; // microsecond precision
static constexpr uint16_t PCAP_VER_MAJOR   = 2;
static constexpr uint16_t PCAP_VER_MINOR   = 4;
static constexpr uint32_t PCAP_SNAPLEN     = 65535;
static constexpr uint32_t PCAP_LINKTYPE    = 127; // LINKTYPE_IEEE802_11_RADIOTAP

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void write_u16le(int fd, uint16_t v) {
    uint8_t b[2] = {static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8)};
    write(fd, b, 2);
}
static void write_u32le(int fd, uint32_t v) {
    uint8_t b[4] = {
        static_cast<uint8_t>(v),
        static_cast<uint8_t>(v >> 8),
        static_cast<uint8_t>(v >> 16),
        static_cast<uint8_t>(v >> 24)
    };
    write(fd, b, 4);
}

// Scan log file for "KEY FOUND! [ password ]" line. Returns password or "".
static std::string scan_log_for_key(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "r");
    if (!f) return "";
    char line[4096];
    std::string result;
    while (std::fgets(line, sizeof(line), f)) {
        const char* kf = std::strstr(line, "KEY FOUND! [ ");
        if (kf) {
            const char* start = kf + 13;
            const char* end   = std::strstr(start, " ]");
            if (end && end > start) {
                result = std::string(start, static_cast<size_t>(end - start));
                break;
            }
        }
    }
    std::fclose(f);
    return result;
}

// Check log file for terminal "not found" lines from aircrack-ng or builtin.
static bool scan_log_for_not_found(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "r");
    if (!f) return false;
    char line[256];
    bool found = false;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strstr(line, "KEY NOT FOUND")
                || std::strstr(line, "No valid WPA handshakes found")
                || std::strstr(line, "no EAPOL data")
                || std::strstr(line, "0 handshake")) {
            found = true; break;
        }
    }
    std::fclose(f);
    return found;
}

// Detect hashcat backend/runtime failures that should trigger CPU fallback.
static bool scan_log_for_hashcat_error(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "r");
    if (!f) return false;
    char line[1024];
    bool found = false;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strstr(line, "HIPRTC_ERROR")
                || (std::strstr(line, "Kernel") && std::strstr(line, "build failed"))
                || std::strstr(line, "No devices found/left")
                || std::strstr(line, "clBuildProgram")
                || std::strstr(line, "Aborting session due to kernel build")
                || std::strstr(line, "No OpenCL-compatible, HIP-compatible or CUDA-compatible")
                || std::strstr(line, "ATTENTION! No OpenCL or CUDA installation found.")
                || std::strstr(line, "HASHCAT BACKEND ERROR")) {
            found = true;
            break;
        }
    }
    std::fclose(f);
    return found;
}

static std::string handshake_id(const WpaHandshake& hs) {
    static const char* HX = "0123456789ABCDEF";
    auto hex_append = [&](std::string& out, const uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            out.push_back(HX[p[i] >> 4]);
            out.push_back(HX[p[i] & 0x0F]);
        }
    };
    std::string out;
    out.reserve(6 * 2 + 6 * 2 + 32 * 2 + 32 * 2 + 16 * 2 + 16);
    hex_append(out, hs.ap_mac, 6);
    out.push_back(':');
    hex_append(out, hs.client_mac, 6);
    out.push_back(':');
    hex_append(out, hs.anonce, 32);
    out.push_back(':');
    hex_append(out, hs.snonce, 32);
    out.push_back(':');
    hex_append(out, hs.mic, 16);
    out.push_back(':');
    out += std::to_string(hs.eapol_frame.size());
    return out;
}

// Scan log for most recent speed line: "[00:00:15] 12345 keys tested (1234.5 k/s)"
static uint64_t scan_log_for_speed(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "r");
    if (!f) return 0;
    char line[512];
    uint64_t speed = 0;
    while (std::fgets(line, sizeof(line), f)) {
        const char* ks = std::strstr(line, "k/s)");
        if (!ks) continue;
        const char* p = ks;
        while (p > line && *p != '(') --p;
        if (*p == '(') {
            double s = 0.0;
            if (std::sscanf(p + 1, "%lf", &s) == 1)
                speed = static_cast<uint64_t>(s);
        }
    }
    std::fclose(f);
    return speed;
}

// Create a single-entry wordlist file for password verification.
// Returns the file path, or "" on failure.
static std::string make_verify_wordlist(const std::string& dir, const std::string& password) {
    std::string path = dir + "/verify.wl";
    FILE* f = std::fopen(path.c_str(), "w");
    if (!f) return "";
    std::fprintf(f, "%s\n", password.c_str());
    std::fclose(f);
    return path;
}

// Delete the verify wordlist temp file and clear the path.
static void clear_verify_wordlist(CrackJob& j) {
    if (!j.verify_wordlist_path.empty()) {
        ::unlink(j.verify_wordlist_path.c_str());
        j.verify_wordlist_path.clear();
    }
}

// ---------------------------------------------------------------------------
// HandshakeSaver public API
// ---------------------------------------------------------------------------

void HandshakeSaver::configure(const HandshakeConfig& cfg) {
    config_ = cfg;
    // Auto-reap zombie cracker processes.
    if (cfg.auto_crack && !cfg.wordlists.empty())
        signal(SIGCHLD, SIG_IGN);
}

void HandshakeSaver::update_ssid(const std::string& bssid, const std::string& ssid) {
    if (ssid.empty()) return;
    auto& s = states_[bssid];
    if (s.ssid.empty()) s.ssid = ssid;
    // Also propagate to existing job if present
    CrackJob* job = find_job(bssid);
    if (job && job->ssid.empty()) job->ssid = ssid;
}

void HandshakeSaver::feed(const RawFrame& raw, const ParsedFrame& parsed) {
    if (!is_active()) return;

    const std::string bssid = parsed.bssid.to_string();
    if (bssid.empty() || parsed.bssid.is_zero()) return;

    // Update SSID from beacons / probe responses
    if ((parsed.kind == FrameKind::Beacon || parsed.kind == FrameKind::ProbeResponse)
            && parsed.ssid && !parsed.ssid->empty()) {
        update_ssid(bssid, *parsed.ssid);
        // Write first beacon per AP to pcap for SSID context
        auto& s = states_[bssid];
        if (!s.has_m1 && !s.has_m2) {
            if (ensure_pcap(bssid, s))
                append_pcap_frame(s.pcap_fd, raw);
        }
        return;
    }

    // Only interested in EAPOL frames from here
    if (!parsed.is_eapol || parsed.eapol_msg == 0) return;

    auto& s = states_[bssid];
    if (!ensure_pcap(bssid, s)) return;

    append_pcap_frame(s.pcap_fd, raw);

    bool was_crackable = is_crackable(s);

    switch (parsed.eapol_msg) {
        case 1:
            s.has_m1 = true;
            s.handshake.ssid = s.ssid;
            extract_eapol_fields(raw.data.data(), raw.data.size(), 1, s.handshake);
            break;
        case 2:
            s.has_m2 = true;
            s.handshake.ssid = s.ssid;
            extract_eapol_fields(raw.data.data(), raw.data.size(), 2, s.handshake);
            break;
        case 3:
            s.has_m3 = true;
            // M3 carries the ANonce at the same field position as M1 — extract it
            // so that M2+M3 can be cracked without ever having seen M1.
            if (!s.has_m1)
                extract_eapol_fields(raw.data.data(), raw.data.size(), 1, s.handshake);
            break;
        case 4: s.has_m4 = true; break;
        default: break;
    }

    std::fprintf(stderr, "[hs] %s  M%u  m1=%d m2=%d m3=%d m4=%d  hs_valid=%d\n",
        bssid.c_str(), parsed.eapol_msg,
        s.has_m1, s.has_m2, s.has_m3, s.has_m4, s.handshake.valid() ? 1 : 0);

    if (!was_crackable && is_crackable(s)) {
        std::fprintf(stderr, "[hs] %s  COMPLETE HANDSHAKE\n", bssid.c_str());

        // Emit for DB persistence (regardless of auto_crack setting).
        // Store pcap_path relative to capture_dir for portability across machines.
        {
            NewHandshake ev;
            ev.bssid = bssid;
            ev.ssid  = s.ssid;
            ev.hs    = s.handshake;

            // Strip capture_dir prefix → e.g. "MyNet_AA-BB-CC/handshake.pcap"
            std::string rel = s.dir;
            const std::string& base = config_.capture_dir;
            if (!base.empty() && rel.size() > base.size()
                    && rel.compare(0, base.size(), base) == 0) {
                rel = rel.substr(base.size());
                if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
            }
            ev.pcap_path = rel + "/handshake.pcap";

            new_hs_events_.push_back(std::move(ev));
        }

        // Capture completed handshake before resetting state
        WpaHandshake completed_hs = s.handshake;

        // Reset EAPOL state so future handshakes (e.g. after password change) are captured fresh.
        s.has_m1 = s.has_m2 = s.has_m3 = s.has_m4 = false;
        s.handshake = WpaHandshake{};

        if (config_.auto_crack && !config_.wordlists.empty()) {
            CrackJob* job = find_job(bssid);
            const std::string new_hs_id = handshake_id(completed_hs);
            if (!job) {
                // New job
                CrackJob j;
                j.bssid           = bssid;
                j.ssid            = s.ssid;
                j.pcap_path       = s.dir + "/handshake.pcap";
                j.handshake       = completed_hs;
                j.last_handshake_id = new_hs_id;
                j.handshake_count = 1;
                j.status          = CrackJob::Status::Queued;
                j.last_reason     = "new handshake captured";
                emit_event(RuntimeEvent::Level::Info,
                           "Handshake queued: " + (s.ssid.empty() ? bssid : s.ssid));
                jobs_.push_back(std::move(j));
                advance_queue();
            } else {
                job->handshake_count++;
                job->ssid = s.ssid;
                bool same_handshake = !job->last_handshake_id.empty()
                                   && job->last_handshake_id == new_hs_id;

                if (same_handshake) {
                    // Already have this exact exchange — skip re-crack.
                    const char* prev =
                        job->status == CrackJob::Status::Found    ? "found"     :
                        job->status == CrackJob::Status::NotFound ? "not_found" :
                        job->status == CrackJob::Status::Running  ? "running"   : "queued";
                    std::fprintf(stderr, "[hs] %s  same handshake (prev=%s) — skip\n",
                                 bssid.c_str(), prev);
                } else {
                    // New exchange on the same BSSID. This must not be skipped:
                    // password may have changed while keeping the same AP.
                    job->handshake = completed_hs;
                    job->last_handshake_id = new_hs_id;
                    if (job->status == CrackJob::Status::Found) {
                        // New handshake (different client or reconnect).
                        // Verify known password against it: same password → skip,
                        // different → AP was re-keyed → re-crack with full wordlist.
                        std::string dir;
                        auto sit = states_.find(bssid);
                        if (sit != states_.end()) dir = sit->second.dir;
                        std::string vwl = dir.empty() ? "" :
                            make_verify_wordlist(dir, job->password);
                        if (vwl.empty()) {
                            // Can't create temp file — just skip to be safe.
                            std::fprintf(stderr, "[hs] %s  new SNonce, cannot create verify wordlist — skip\n",
                                bssid.c_str());
                            emit_event(RuntimeEvent::Level::Warning,
                                       "Handshake changed for " + bssid
                                       + ", but verify wordlist could not be created");
                        } else {
                            std::fprintf(stderr, "[hs] %s  new handshake, verifying known password '%s'\n",
                                bssid.c_str(), job->password.c_str());
                            clear_verify_wordlist(*job);
                            job->verify_wordlist_path = vwl;
                            job->handshake = completed_hs;
                            job->status    = CrackJob::Status::Queued;
                            job->last_reason = "handshake changed; verifying known password";
                            emit_event(RuntimeEvent::Level::Info,
                                       "Handshake changed for " + bssid
                                       + " — verifying previous password");
                            advance_queue();
                        }
                    } else if (job->status == CrackJob::Status::NotFound) {
                        // Previous wordlist exhausted — retry with fresh handshake.
                        std::fprintf(stderr, "[hs] %s  new handshake, re-queuing (prev=not_found)\n",
                            bssid.c_str());
                        job->status = CrackJob::Status::Queued;
                        job->last_reason = "fresh handshake after previous not_found";
                        emit_event(RuntimeEvent::Level::Info,
                                   "Fresh handshake re-queued: " + bssid);
                        advance_queue();
                    } else if (job->status == CrackJob::Status::Running) {
                        job->last_reason = "new handshake captured while previous crack still running";
                        emit_event(RuntimeEvent::Level::Info,
                                   "Fresh handshake captured while crack still running: " + bssid);
                    } else {
                        job->last_reason = "new handshake updated queued job";
                    }
                    // If Queued/Running: nonces updated, let current job finish first.
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Queue management
// ---------------------------------------------------------------------------

CrackJob* HandshakeSaver::find_job(const std::string& bssid) {
    for (auto& j : jobs_)
        if (j.bssid == bssid) return &j;
    return nullptr;
}

void HandshakeSaver::advance_queue() {
    // Don't start a new job if one is already running
    for (auto& j : jobs_)
        if (j.status == CrackJob::Status::Running) return;

    // Find first Queued job
    for (auto& j : jobs_) {
        if (j.status != CrackJob::Status::Queued) continue;

        char ts_buf[32];
        time_t now = time(nullptr);
        strftime(ts_buf, sizeof(ts_buf), "%Y%m%d_%H%M%S", localtime(&now));

        // Build log path next to the pcap
        std::string dir;
        auto it = states_.find(j.bssid);
        if (it != states_.end()) dir = it->second.dir;
        if (dir.empty()) {
            // Derive dir from pcap_path
            size_t slash = j.pcap_path.rfind('/');
            dir = (slash != std::string::npos) ? j.pcap_path.substr(0, slash) : ".";
        }
        j.log_path = dir + "/crack_" + ts_buf + ".log";

        // Verification run uses a single-entry wordlist; otherwise full wordlist.
        std::vector<std::string> verify_wl_vec;
        const std::vector<std::string>& wordlists =
            j.verify_wordlist_path.empty()
                ? config_.wordlists
                : (verify_wl_vec = {j.verify_wordlist_path}, verify_wl_vec);

        CrackEngine engine = j.force_builtin ? CrackEngine::Builtin : config_.crack_engine;
        j.requested_engine.clear();
        switch (config_.crack_engine) {
#ifdef HAVE_GPU_CRACK
            case CrackEngine::Hashcat:  j.requested_engine = "GPU"; break;
#endif
            case CrackEngine::Aircrack: j.requested_engine = "air"; break;
            default:                    j.requested_engine = "CPU"; break;
        }
        bool ok = launch_crack_job(engine, j.handshake,
                                   j.pcap_path, wordlists, j.log_path);
        if (ok) {
            j.status       = CrackJob::Status::Running;
            j.spin_frame   = 0;
            j.started_at_s = static_cast<uint64_t>(time(nullptr));
            // Track actual engine: if no M1 in memory, builtin/hashcat fall back to aircrack
            bool fallback_to_air = !j.handshake.has_m1;
            if (fallback_to_air) {
                j.actual_engine = "air";
            } else {
                switch (engine) {
#ifdef HAVE_GPU_CRACK
                    case CrackEngine::Hashcat:  j.actual_engine = "GPU"; break;
#endif
                    case CrackEngine::Aircrack: j.actual_engine = "air"; break;
                    default:                    j.actual_engine = "CPU"; break;
                }
            }
            std::fprintf(stderr, "[hs] %s  crack STARTED  engine=%s  log=%s\n",
                         j.bssid.c_str(), j.actual_engine.c_str(), j.log_path.c_str());
            if (j.force_builtin && !j.last_reason.empty()) {
                emit_event(RuntimeEvent::Level::Warning,
                           "Crack fallback for " + j.bssid + ": " + j.last_reason);
            } else {
                emit_event(RuntimeEvent::Level::Info,
                           "Crack started: " + j.bssid + " [" + j.actual_engine + "]");
            }
        } else {
            std::fprintf(stderr, "[hs] %s  crack launch FAILED\n", j.bssid.c_str());
            emit_event(RuntimeEvent::Level::Error,
                       "Crack launch failed: " + j.bssid);
        }
        return; // only start one at a time
    }
}

// ---------------------------------------------------------------------------
// Result polling
// ---------------------------------------------------------------------------

std::vector<HandshakeSaver::CrackResult> HandshakeSaver::poll_results() {
    std::vector<CrackResult> out;
    bool need_advance = false;

    for (auto& j : jobs_) {
        if (j.status != CrackJob::Status::Running) continue;
        if (j.log_path.empty()) continue;

        std::string pw = scan_log_for_key(j.log_path);
        if (!pw.empty()) {
            if (!j.verify_wordlist_path.empty()) {
                // Verification run: known password still valid — keep Found, skip re-crack.
                clear_verify_wordlist(j);
                j.status = CrackJob::Status::Found;
                std::fprintf(stderr, "[hs] VERIFY OK  bssid=%s  pw='%s' still valid — skip re-crack\n",
                             j.bssid.c_str(), j.password.c_str());
            } else {
                j.status   = CrackJob::Status::Found;
                j.password = pw;
                std::fprintf(stderr, "[hs] KEY FOUND  bssid=%s  ssid=%s  pw='%s'\n",
                             j.bssid.c_str(), j.ssid.c_str(), pw.c_str());
                out.push_back({j.bssid, j.ssid, pw, true});
            }
            need_advance = true;
            continue;
        }

        if (scan_log_for_not_found(j.log_path)) {
            if (j.actual_engine == "GPU" && scan_log_for_hashcat_error(j.log_path)) {
                // Hashcat backend failed (driver/runtime/compiler). Re-queue this
                // job and force builtin CPU engine to avoid false "not found".
                std::string reason = hashcat_error_reason_from_log(j.log_path);
                if (reason.empty()) reason = "unknown hashcat backend error";
                std::fprintf(stderr,
                             "[hs] hashcat backend error for bssid=%s (%s) — switching job to builtin CPU\n",
                             j.bssid.c_str(), reason.c_str());
                clear_verify_wordlist(j);
                j.force_builtin = true;
                j.last_reason = reason;
                j.status = CrackJob::Status::Queued;
                j.log_path.clear();
                j.cached_speed_kps = 0;
                j.started_at_s = 0;
                need_advance = true;
                continue;
            }
            if (!j.verify_wordlist_path.empty()) {
                // Verification run: known password no longer valid — AP re-keyed, start full crack.
                clear_verify_wordlist(j);
                std::fprintf(stderr, "[hs] VERIFY FAIL  bssid=%s  known pw invalid — AP re-keyed, re-cracking\n",
                             j.bssid.c_str());
                j.password.clear();
                j.last_reason = "known password invalid for fresh handshake";
                j.status = CrackJob::Status::Queued;
                emit_event(RuntimeEvent::Level::Warning,
                           "Password changed on " + j.bssid + " — re-cracking");
            } else {
                j.status = CrackJob::Status::NotFound;
                std::fprintf(stderr, "[hs] KEY NOT FOUND  bssid=%s  ssid=%s\n",
                             j.bssid.c_str(), j.ssid.c_str());
                j.last_reason = "wordlists exhausted";
                out.push_back({j.bssid, j.ssid, "", false});
            }
            need_advance = true;
            continue;
        }

        // Detect silent crash: log is still empty 15 seconds after job started
        {
            uint64_t now = static_cast<uint64_t>(time(nullptr));
            if (j.started_at_s > 0 && now - j.started_at_s > 15) {
                FILE* f = std::fopen(j.log_path.c_str(), "r");
                bool empty = true;
                if (f) {
                    char buf[1];
                    empty = (std::fread(buf, 1, 1, f) == 0);
                    std::fclose(f);
                }
                if (empty) {
                    std::fprintf(stderr, "[hs] crack log empty after 15s — engine failed silently, re-queuing\n");
                    clear_verify_wordlist(j);
                    j.last_reason = "engine failed silently (empty log after 15s)";
                    j.status = CrackJob::Status::Queued;
                    j.log_path.clear();
                    j.cached_speed_kps = 0;
                    j.started_at_s = 0;
                    need_advance = true;
                }
            }
        }
    }

    if (need_advance) advance_queue();
    return out;
}

// ---------------------------------------------------------------------------
// Spinner animation
// ---------------------------------------------------------------------------

void HandshakeSaver::tick_spinners() {
    for (auto& j : jobs_)
        if (j.status == CrackJob::Status::Running) {
            j.spin_frame = (j.spin_frame + 1) % 4;
            // Update cached speed every ~3 ticks (tick is called ~300ms)
            uint64_t now = static_cast<uint64_t>(time(nullptr));
            if (!j.log_path.empty() && now - j.last_speed_check_s >= 3) {
                j.cached_speed_kps   = scan_log_for_speed(j.log_path);
                j.last_speed_check_s = now;
            }
        }
}

// ---------------------------------------------------------------------------
// Drain new handshake events for DB persistence
// ---------------------------------------------------------------------------

std::vector<HandshakeSaver::NewHandshake> HandshakeSaver::drain_new_handshakes() {
    std::vector<NewHandshake> out;
    out.swap(new_hs_events_);
    return out;
}

std::vector<HandshakeSaver::RuntimeEvent> HandshakeSaver::drain_runtime_events() {
    std::vector<RuntimeEvent> out;
    out.swap(runtime_events_);
    return out;
}

// ---------------------------------------------------------------------------
// Legacy crack status (for top-left "Crk:" indicator in app.cpp)
// ---------------------------------------------------------------------------

HandshakeSaver::CrackStatus HandshakeSaver::current_crack_status() const {
    for (auto& j : jobs_) {
        if (j.status == CrackJob::Status::Running) {
            CrackStatus st;
            st.active    = true;
            st.bssid     = j.bssid;
            st.ssid      = j.ssid;
            st.speed_kps    = j.cached_speed_kps;
            st.engine_label = j.actual_engine;
            return st;
        }
    }
    return CrackStatus{};
}

void HandshakeSaver::emit_event(RuntimeEvent::Level level, const std::string& text) {
    runtime_events_.push_back({level, text});
}

// ---------------------------------------------------------------------------
// Private: directory and pcap management
// ---------------------------------------------------------------------------

std::string HandshakeSaver::safe_name(const std::string& s, size_t max_len) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.')
            out += static_cast<char>(c);
        else
            out += '_';
    }
    if (out.size() > max_len) out.resize(max_len);
    return out;
}

std::string HandshakeSaver::resolve_dir(const std::string& bssid, const std::string& ssid) {
    std::string sname = ssid.empty() ? "unknown" : safe_name(ssid, 32);
    std::string bid   = bssid;
    std::replace(bid.begin(), bid.end(), ':', '-');
    std::string dir = config_.capture_dir + "/" + sname + "_" + bid;
    ::mkdir(config_.capture_dir.c_str(), 0755);
    if (::mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST) {
        std::fprintf(stderr, "[hs] mkdir failed: %s (%s)\n", dir.c_str(), strerror(errno));
        return "";
    }
    return dir;
}

bool HandshakeSaver::ensure_pcap(const std::string& bssid, BssidState& s) {
    if (s.pcap_fd >= 0) return true;

    if (s.dir.empty()) {
        s.dir = resolve_dir(bssid, s.ssid);
        if (s.dir.empty()) return false;
    }

    std::string path = s.dir + "/handshake.pcap";
    bool is_new = (::access(path.c_str(), F_OK) != 0);
    s.pcap_fd   = ::open(path.c_str(), O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (s.pcap_fd < 0) {
        std::fprintf(stderr, "[hs] open pcap failed: %s (%s)\n", path.c_str(), strerror(errno));
        return false;
    }
    if (is_new) write_pcap_header(s.pcap_fd);
    return true;
}

// ---------------------------------------------------------------------------
// Private: pcap writing
// ---------------------------------------------------------------------------

void HandshakeSaver::write_pcap_header(int fd) {
    write_u32le(fd, PCAP_MAGIC);
    write_u16le(fd, PCAP_VER_MAJOR);
    write_u16le(fd, PCAP_VER_MINOR);
    write_u32le(fd, 0);
    write_u32le(fd, 0);
    write_u32le(fd, PCAP_SNAPLEN);
    write_u32le(fd, PCAP_LINKTYPE);
}

void HandshakeSaver::append_pcap_frame(int fd, const RawFrame& raw) {
    if (fd < 0 || raw.data.empty()) return;

    uint32_t ts_sec  = static_cast<uint32_t>(raw.ts_us / 1'000'000ULL);
    uint32_t ts_usec = static_cast<uint32_t>(raw.ts_us % 1'000'000ULL);
    uint32_t len     = static_cast<uint32_t>(
        std::min(raw.data.size(), static_cast<size_t>(PCAP_SNAPLEN)));

    write_u32le(fd, ts_sec);
    write_u32le(fd, ts_usec);
    write_u32le(fd, len);
    write_u32le(fd, len);
    write(fd, raw.data.data(), len);
}

// ---------------------------------------------------------------------------
// Private: crackability check
// ---------------------------------------------------------------------------

bool HandshakeSaver::is_crackable(const BssidState& s) {
    return (s.has_m1 && s.has_m2)
        || (s.has_m2 && s.has_m3)
        || (s.has_m1 && s.has_m4)
        || (s.has_m2 && s.has_m4);  // M1 may already be in pcap from a previous session
}
