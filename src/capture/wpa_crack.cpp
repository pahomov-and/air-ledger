#include "wpa_crack.hpp"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <thread>
#include <atomic>
#include <mutex>
#include <fstream>
#include <memory>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifdef HAVE_OPENSSL
#  include <openssl/evp.h>
#  include <openssl/hmac.h>
#endif

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void fmt_bssid(const uint8_t mac[6], char out[18]) {
    std::snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Check file exists and is readable; return false + print error if not.
static bool check_file_readable(const char* path, const char* label) {
    if (::access(path, R_OK) != 0) {
        std::fprintf(stderr, "[crack] ERROR: %s not found or not readable: %s\n", label, path);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// EAPOL field extraction
// ---------------------------------------------------------------------------

static uint16_t radiotap_len(const uint8_t* d, size_t len) {
    if (len < 4) return 0;
    return static_cast<uint16_t>(d[2]) | (static_cast<uint16_t>(d[3]) << 8);
}

bool extract_eapol_fields(const uint8_t* raw, size_t raw_len,
                           uint8_t msg_num, WpaHandshake& hs) {
    if (raw_len < 10) {
        std::fprintf(stderr, "[crack] extract_eapol: frame too short (%zu bytes)\n", raw_len);
        return false;
    }

    uint16_t rt = radiotap_len(raw, raw_len);
    if (rt >= raw_len) {
        std::fprintf(stderr, "[crack] extract_eapol: radiotap len %u >= frame len\n", rt);
        return false;
    }

    const uint8_t* d = raw + rt;
    size_t len = raw_len - rt;
    if (len < 24) return false;

    uint16_t fc      = static_cast<uint16_t>(d[0]) | (static_cast<uint16_t>(d[1]) << 8);
    uint8_t  type    = (fc >> 2) & 3;
    uint8_t  subtype = (fc >> 4) & 0xF;
    uint8_t  to_ds   = (fc >> 8)  & 1;
    uint8_t  from_ds = (fc >> 9)  & 1;
    if (type != 2) {
        std::fprintf(stderr, "[crack] extract_eapol: M%u is not a Data frame (type=%u)\n",
                     msg_num, type);
        return false;
    }

    size_t hdr = 24u;
    if (subtype & 0x08) hdr += 2; // QoS Control
    if (to_ds && from_ds) hdr += 6; // Addr4

    // ToDS (Client→AP):   addr1=BSSID, addr2=SA(client)
    // FromDS (AP→Client): addr1=DA(client), addr2=BSSID
    if (msg_num == 1) {
        memcpy(hs.ap_mac,     d + 10, 6);
        memcpy(hs.client_mac, d +  4, 6);
    } else if (msg_num == 2) {
        memcpy(hs.ap_mac,     d +  4, 6);
        memcpy(hs.client_mac, d + 10, 6);
    }

    if (hdr + 8 > len) {
        std::fprintf(stderr, "[crack] extract_eapol: M%u too short for LLC/SNAP\n", msg_num);
        return false;
    }
    const uint8_t* llc = d + hdr;
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) {
        std::fprintf(stderr, "[crack] extract_eapol: M%u missing LLC/SNAP header\n", msg_num);
        return false;
    }
    uint16_t etype = (static_cast<uint16_t>(llc[6]) << 8) | llc[7];
    if (etype != 0x888E) {
        std::fprintf(stderr, "[crack] extract_eapol: M%u ethertype=0x%04X (expected 0x888E)\n",
                     msg_num, etype);
        return false;
    }

    const uint8_t* ep = llc + 8;
    size_t ep_avail = len - hdr - 8;

    if (ep_avail < 4 || ep[1] != 0x03) {
        std::fprintf(stderr, "[crack] extract_eapol: M%u not an EAPOL-Key frame\n", msg_num);
        return false;
    }

    uint16_t eapol_body_len = (static_cast<uint16_t>(ep[2]) << 8) | ep[3];
    size_t eapol_total = 4u + eapol_body_len;
    if (eapol_total > ep_avail) eapol_total = ep_avail;

    const uint8_t* kp = ep + 4;
    size_t kp_avail = eapol_total - 4;

    if (kp_avail < 45) {
        std::fprintf(stderr, "[crack] extract_eapol: M%u key body too short (%zu bytes)\n",
                     msg_num, kp_avail);
        return false;
    }

    if (msg_num == 1) {
        memcpy(hs.anonce, kp + 13, 32);
        hs.has_m1 = true;
    } else if (msg_num == 2) {
        memcpy(hs.snonce, kp + 13, 32);
        if (kp_avail < 93) {
            std::fprintf(stderr, "[crack] extract_eapol: M2 too short to contain MIC (%zu bytes)\n",
                         kp_avail);
            return false;
        }
        memcpy(hs.mic, kp + 77, 16);

        hs.eapol_frame.assign(ep, ep + eapol_total);
        if (hs.eapol_frame.size() > 96)
            memset(hs.eapol_frame.data() + 81, 0, 16); // zero MIC for re-computation
        hs.has_m2 = true;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Aircrack-ng engine
// ---------------------------------------------------------------------------

static bool run_aircrack(const WpaHandshake& hs,
                          const std::string& pcap_path,
                          const std::vector<std::string>& wordlists,
                          const std::string& log_path) {
    // Validate inputs before forking
    if (!check_file_readable(pcap_path.c_str(), "pcap")) return false;

    bool any_wl = false;
    for (auto& wl : wordlists)
        if (check_file_readable(wl.c_str(), "wordlist")) { any_wl = true; break; }
    if (!any_wl) {
        std::fprintf(stderr, "[crack] aircrack: no readable wordlists found — aborting\n");
        return false;
    }

    // Find aircrack-ng in PATH
    if (::access("/usr/bin/aircrack-ng", X_OK) != 0 &&
        ::access("/usr/local/bin/aircrack-ng", X_OK) != 0) {
        std::fprintf(stderr, "[crack] ERROR: aircrack-ng not found in /usr/bin or /usr/local/bin\n");
        return false;
    }

    std::string wlists;
    for (size_t i = 0; i < wordlists.size(); ++i) { if (i) wlists += ','; wlists += wordlists[i]; }

    char bssid[18]; fmt_bssid(hs.ap_mac, bssid);

    std::fprintf(stderr, "[crack] aircrack  AP: %s (%s)  pcap: %s\n",
                 hs.ssid.empty() ? "<unknown>" : hs.ssid.c_str(), bssid, pcap_path.c_str());

    signal(SIGCHLD, SIG_IGN);
    pid_t pid = fork();
    if (pid < 0) { perror("[crack] fork"); return false; }
    if (pid == 0) {
        int fd = open(log_path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) { dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO); close(fd); }
        for (int i = 3; i < 256; ++i) close(i);
        const char* av[] = { "aircrack-ng", "-w", wlists.c_str(), "-b", bssid, pcap_path.c_str(), nullptr };
        execvp("aircrack-ng", const_cast<char* const*>(av));
        dprintf(STDOUT_FILENO, "ERROR: exec aircrack-ng failed: %s\n", strerror(errno));
        _exit(1);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Built-in engine (requires OpenSSL)
// ---------------------------------------------------------------------------

#ifdef HAVE_OPENSSL

static void prf512(const uint8_t* key, size_t keylen,
                   const uint8_t* prefix, size_t pfx_len,
                   const uint8_t* data,   size_t data_len,
                   uint8_t out[64]) {
    std::vector<uint8_t> inp(pfx_len + 1 + data_len + 1);
    memcpy(inp.data(), prefix, pfx_len);
    inp[pfx_len] = 0x00;
    memcpy(inp.data() + pfx_len + 1, data, data_len);
    for (uint8_t i = 0; i < 4; ++i) {
        inp.back() = i;
        unsigned int hlen = 20;
        HMAC(EVP_sha1(), key, static_cast<int>(keylen), inp.data(), inp.size(), out + i*20, &hlen);
    }
}

static void derive_ptk(const uint8_t pmk[32],
                        const uint8_t ap[6], const uint8_t sta[6],
                        const uint8_t anonce[32], const uint8_t snonce[32],
                        uint8_t ptk[64]) {
    static const char PREFIX[] = "Pairwise key expansion";
    uint8_t b[76];
    if (memcmp(ap, sta, 6) < 0) { memcpy(b, ap, 6);      memcpy(b+6,  sta,    6); }
    else                         { memcpy(b, sta, 6);     memcpy(b+6,  ap,     6); }
    if (memcmp(anonce, snonce, 32) < 0) { memcpy(b+12, anonce, 32); memcpy(b+44, snonce, 32); }
    else                                { memcpy(b+12, snonce, 32); memcpy(b+44, anonce, 32); }
    prf512(pmk, 32, reinterpret_cast<const uint8_t*>(PREFIX), sizeof(PREFIX)-1, b, 76, ptk);
}

static bool verify_mic(const uint8_t ptk[64],
                        const uint8_t captured_mic[16],
                        const std::vector<uint8_t>& eapol_frame) {
    if (eapol_frame.size() < 97) return false;
    uint8_t computed[20]; unsigned int len = 20;
    HMAC(EVP_sha1(), ptk, 16, eapol_frame.data(), eapol_frame.size(), computed, &len);
    return memcmp(computed, captured_mic, 16) == 0;
}

// Worker: reads lines from shared ifstream, computes PMK→PTK→MIC.
// Uses total_tried counter for progress display.
static void crack_worker(const WpaHandshake& hs,
                          std::ifstream& file,
                          std::mutex& file_mutex,
                          std::atomic<bool>& found,
                          std::atomic<uint64_t>& total_tried,
                          std::mutex& result_mutex,
                          std::string& result) {
    uint8_t pmk[32], ptk[64];
    std::string line;
    while (!found.load(std::memory_order_relaxed)) {
        {
            std::lock_guard<std::mutex> lk(file_mutex);
            if (!std::getline(file, line)) return; // EOF
        }
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() < 8 || line.size() > 63) continue;

        total_tried.fetch_add(1, std::memory_order_relaxed);

        PKCS5_PBKDF2_HMAC(line.c_str(), static_cast<int>(line.size()),
                           reinterpret_cast<const unsigned char*>(hs.ssid.c_str()),
                           static_cast<int>(hs.ssid.size()),
                           4096, EVP_sha1(), 32, pmk);
        derive_ptk(pmk, hs.ap_mac, hs.client_mac, hs.anonce, hs.snonce, ptk);

        if (verify_mic(ptk, hs.mic, hs.eapol_frame)) {
            std::lock_guard<std::mutex> lk(result_mutex);
            if (!found.exchange(true)) result = line;
            return;
        }
    }
}

// Runs in the child process (after fork).
static void run_builtin_child(const WpaHandshake& hs,
                               const std::vector<std::string>& wordlists,
                               const std::string& log_path) {
    unsigned int n_threads = std::max(1u, std::thread::hardware_concurrency());
    std::atomic<bool>     found{false};
    std::atomic<uint64_t> total_tried{0};
    std::mutex result_mutex;
    std::string result;

    char bssid_str[18]; fmt_bssid(hs.ap_mac, bssid_str);
    const char* ssid_str = hs.ssid.empty() ? "<unknown>" : hs.ssid.c_str();

    // Open log file at start so progress lines are readable by scan_log_for_speed()
    FILE* log = std::fopen(log_path.c_str(), "w");

    std::fprintf(stderr, "[crack] builtin  AP: %s (%s)  threads: %u  wordlists: %zu\n",
                 ssid_str, bssid_str, n_threads, wordlists.size());

    // Progress thread: writes speed in aircrack-ng format to log + stderr every 3 seconds
    std::thread progress_thread([&]() {
        auto t0 = std::chrono::steady_clock::now();
        while (!found.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            if (found.load()) break;
            double elapsed = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - t0).count();
            uint64_t tried = total_tried.load();
            uint64_t rate  = elapsed > 0.5 ? static_cast<uint64_t>(tried / elapsed) : 0;
            int mins = static_cast<int>(elapsed) / 60;
            int secs = static_cast<int>(elapsed) % 60;
            // aircrack-ng-compatible format so scan_log_for_speed() can parse it
            if (log) {
                std::fprintf(log, "[%02d:%02d:%02d] %llu keys tested (%llu k/s)\n",
                    0, mins, secs,
                    static_cast<unsigned long long>(tried),
                    static_cast<unsigned long long>(rate / 1000 + 1));
                std::fflush(log);
            }
            std::fprintf(stderr,
                "[crack] AP: %-24s (%s)  speed: %5llu PMK/s  tried: %9llu  elapsed: %dm%02ds\n",
                ssid_str, bssid_str,
                static_cast<unsigned long long>(rate),
                static_cast<unsigned long long>(tried),
                mins, secs);
            std::fflush(stderr);
        }
    });
    progress_thread.detach(); // killed automatically when _exit() is called

    for (auto& wl : wordlists) {
        if (found.load()) break;
        if (!check_file_readable(wl.c_str(), "wordlist")) continue; // skip bad paths

        auto file  = std::make_shared<std::ifstream>(wl);
        auto fmut  = std::make_shared<std::mutex>();

        std::vector<std::thread> threads;
        threads.reserve(n_threads);
        for (unsigned int t = 0; t < n_threads; ++t) {
            threads.emplace_back(crack_worker,
                                 std::cref(hs),
                                 std::ref(*file), std::ref(*fmut),
                                 std::ref(found), std::ref(total_tried),
                                 std::ref(result_mutex), std::ref(result));
        }
        for (auto& t : threads) t.join();
    }

    // Final status line
    uint64_t tried = total_tried.load();
    if (found.load())
        std::fprintf(stderr, "[crack] KEY FOUND  AP: %s  tried: %llu\n",
                     bssid_str, static_cast<unsigned long long>(tried));
    else
        std::fprintf(stderr, "[crack] KEY NOT FOUND  AP: %s  tried: %llu\n",
                     bssid_str, static_cast<unsigned long long>(tried));

    // Write final result to log (poll_results() reads this)
    if (!log) log = std::fopen(log_path.c_str(), "w");
    if (!log) {
        std::fprintf(stderr, "[crack] ERROR: cannot write log: %s\n", log_path.c_str());
        _exit(1);
    }
    if (found.load())
        std::fprintf(log, "KEY FOUND! [ %s ]\n", result.c_str());
    else
        std::fprintf(log, "KEY NOT FOUND.\n");
    std::fclose(log);
    _exit(0);
}

static bool run_builtin(const WpaHandshake& hs,
                         const std::vector<std::string>& wordlists,
                         const std::string& log_path) {
    signal(SIGCHLD, SIG_IGN);
    pid_t pid = fork();
    if (pid < 0) { perror("[crack] fork"); return false; }
    if (pid != 0) return true; // parent: fork succeeded
    run_builtin_child(hs, wordlists, log_path);
    return true; // unreachable; child calls _exit()
}

#endif // HAVE_OPENSSL

// ---------------------------------------------------------------------------
// Hashcat engine  (compiled in only when HAVE_GPU_CRACK is defined)
// ---------------------------------------------------------------------------

#ifdef HAVE_GPU_CRACK

static void hex_bytes(const uint8_t* data, size_t len, std::string& out) {
    static const char* HX = "0123456789abcdef";
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = HX[data[i] >> 4];
        out[i * 2 + 1] = HX[data[i] & 0x0f];
    }
}

// Write a single hc22000 WPA*02 line for the captured handshake.
// Returns true on success.
static bool write_hc22000(const WpaHandshake& hs, const std::string& path) {
    if (!hs.has_m1 || !hs.has_m2 || hs.eapol_frame.empty()) {
        std::fprintf(stderr, "[hashcat] write_hc22000: incomplete handshake\n");
        return false;
    }

    std::string mic_h, ap_h, sta_h, ssid_h, anonce_h, eapol_h;
    hex_bytes(hs.mic, 16, mic_h);
    hex_bytes(hs.ap_mac, 6, ap_h);
    hex_bytes(hs.client_mac, 6, sta_h);
    // SSID as hex (handles non-ASCII SSIDs)
    ssid_h.resize(hs.ssid.size() * 2);
    static const char* HX = "0123456789abcdef";
    for (size_t i = 0; i < hs.ssid.size(); ++i) {
        uint8_t c = static_cast<uint8_t>(hs.ssid[i]);
        ssid_h[i * 2]     = HX[c >> 4];
        ssid_h[i * 2 + 1] = HX[c & 0x0f];
    }
    hex_bytes(hs.anonce, 32, anonce_h);
    hex_bytes(hs.eapol_frame.data(), hs.eapol_frame.size(), eapol_h);

    // messagepair = 0x02  →  M1 nonce + M2 EAPOL, no replay-counter check
    std::string line = "WPA*02*" + mic_h + "*" + ap_h + "*" + sta_h + "*"
                     + ssid_h + "*" + anonce_h + "*" + eapol_h + "*02";

    FILE* f = std::fopen(path.c_str(), "w");
    if (!f) {
        std::fprintf(stderr, "[hashcat] cannot write hc22000: %s\n", path.c_str());
        return false;
    }
    std::fprintf(f, "%s\n", line.c_str());
    std::fclose(f);
    return true;
}

// Executed inside the forked child:  runs hashcat, writes aircrack-ng-compatible
// log lines (so the existing poll_results() / scan_log_* machinery works).
static void run_hashcat_child(const WpaHandshake& hs,
                               const std::string& hash_path,   // .hc22000 file
                               const std::string& result_path, // where hashcat writes password
                               const std::vector<std::string>& wordlists,
                               const std::string& log_path) {
    char bssid_str[18]; fmt_bssid(hs.ap_mac, bssid_str);
    const char* ssid_str = hs.ssid.empty() ? "<unknown>" : hs.ssid.c_str();

    FILE* log = std::fopen(log_path.c_str(), "w");

    std::fprintf(stderr, "[hashcat] starting  AP: %s (%s)  wordlists: %zu\n",
                 ssid_str, bssid_str, wordlists.size());

    // Find hashcat binary
    const char* hashcat_bin = nullptr;
    for (auto p : {"/usr/bin/hashcat", "/usr/local/bin/hashcat"}) {
        if (::access(p, X_OK) == 0) { hashcat_bin = p; break; }
    }
    if (!hashcat_bin) {
        // Try PATH via execvp later; we still need the path for the check here.
        // Use "hashcat" and let execvp resolve it.
        hashcat_bin = "hashcat";
    }

    bool found = false;
    std::string password;

    for (const auto& wl : wordlists) {
        if (!check_file_readable(wl.c_str(), "wordlist")) continue;

        // Build argv:
        //   hashcat -m 22000 -a 0
        //     --potfile-disable
        //     --outfile <result_path> --outfile-format 2
        //     --status --status-timer 3 --machine-readable
        //     --quiet   (suppress banner)
        //     <hash.hc22000> <wordlist>
        std::vector<std::string> args_s = {
            hashcat_bin,
            "-m", "22000", "-a", "0",
            "--potfile-disable",
            "--outfile", result_path, "--outfile-format", "2",
            "--status", "--status-timer", "3", "--machine-readable",
            "--quiet",
            hash_path, wl
        };
        std::vector<const char*> argv;
        argv.reserve(args_s.size() + 1);
        for (auto& a : args_s) argv.push_back(a.c_str());
        argv.push_back(nullptr);

        // Pipe hashcat's stdout so we can parse SPEED= lines
        int pipefd[2];
        if (pipe(pipefd) != 0) { perror("[hashcat] pipe"); continue; }

        pid_t pid = fork();
        if (pid < 0) { perror("[hashcat] fork"); close(pipefd[0]); close(pipefd[1]); continue; }

        if (pid == 0) {
            // ── grandchild: hashcat ──
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            // stderr → /dev/null to suppress GPU init noise
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
            close(pipefd[1]);
            for (int i = 3; i < 256; ++i) close(i);
            execvp(argv[0], const_cast<char* const*>(argv.data()));
            // execvp failed
            dprintf(STDOUT_FILENO, "EXEC_FAILED\n");
            _exit(127);
        }

        // ── child: read hashcat output ──
        close(pipefd[1]);
        FILE* pipe_in = fdopen(pipefd[0], "r");

        auto t0 = std::chrono::steady_clock::now();
        char line[1024];
        uint64_t speed_kps = 0;
        uint64_t total_tried = 0;

        while (pipe_in && std::fgets(line, sizeof(line), pipe_in)) {
            // Parse machine-readable SPEED= and PROGRESS= lines
            if (std::strncmp(line, "SPEED=", 6) == 0) {
                // SPEED=<exec_count> <hashes_per_sec>
                unsigned long long exec_cnt = 0, hps = 0;
                std::sscanf(line + 6, "%llu %llu", &exec_cnt, &hps);
                speed_kps = hps / 1000;
                total_tried += exec_cnt;

                // Write aircrack-ng-compatible speed line to log
                double elapsed = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - t0).count();
                int mins = static_cast<int>(elapsed) / 60;
                int secs = static_cast<int>(elapsed) % 60;
                if (log) {
                    std::fprintf(log, "[00:%02d:%02d] %llu keys tested (%llu k/s)\n",
                        mins, secs,
                        static_cast<unsigned long long>(total_tried),
                        static_cast<unsigned long long>(speed_kps));
                    std::fflush(log);
                }
            }
            // Check for exec failure
            if (std::strstr(line, "EXEC_FAILED")) {
                std::fprintf(stderr, "[hashcat] ERROR: hashcat not found in PATH\n");
            }
        }
        if (pipe_in) std::fclose(pipe_in);

        int wstatus = 0;
        waitpid(pid, &wstatus, 0);
        int exit_code = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
        // hashcat exit codes: 0=cracked, 1=exhausted, 2+=error
        std::fprintf(stderr, "[hashcat] exit_code=%d\n", exit_code);

        if (exit_code == 0) {
            // Read password from outfile
            FILE* rf = std::fopen(result_path.c_str(), "r");
            if (rf) {
                char pw[256] = {};
                if (std::fgets(pw, sizeof(pw), rf)) {
                    size_t n = std::strlen(pw);
                    while (n > 0 && (pw[n-1] == '\n' || pw[n-1] == '\r')) pw[--n] = '\0';
                    password = pw;
                    found = true;
                }
                std::fclose(rf);
            }
            if (found) break;
        } else if (exit_code == 1) {
            // Exhausted this wordlist, continue to next
        } else {
            std::fprintf(stderr, "[hashcat] non-zero exit %d — skipping wordlist\n", exit_code);
        }
    }

    // Write final result in aircrack-ng format (parsed by handshake_saver.cpp)
    if (found) {
        std::fprintf(stderr, "[hashcat] KEY FOUND  AP: %s  password: %s\n",
                     bssid_str, password.c_str());
        if (log) std::fprintf(log, "KEY FOUND! [ %s ]\n", password.c_str());
    } else {
        std::fprintf(stderr, "[hashcat] KEY NOT FOUND  AP: %s\n", bssid_str);
        if (log) std::fprintf(log, "KEY NOT FOUND.\n");
    }
    if (log) std::fclose(log);
    _exit(0);
}

static bool run_hashcat(const WpaHandshake& hs,
                         const std::vector<std::string>& wordlists,
                         const std::string& log_path) {
    if (!hs.has_m1 || !hs.has_m2 || hs.ssid.empty()) {
        std::fprintf(stderr,
            "[hashcat] incomplete handshake (m1=%d m2=%d ssid='%s') — falling back to aircrack\n",
            hs.has_m1, hs.has_m2, hs.ssid.c_str());
        return false;
    }

    // Derive side-car paths from log_path (share the same directory)
    std::string dir = log_path;
    auto slash = dir.rfind('/');
    if (slash != std::string::npos) dir.resize(slash + 1); else dir = "./";

    std::string hash_path   = dir + "hashcat.hc22000";
    std::string result_path = dir + "hashcat_result.txt";

    if (!write_hc22000(hs, hash_path)) return false;

    signal(SIGCHLD, SIG_IGN);
    pid_t pid = fork();
    if (pid < 0) { perror("[hashcat] fork"); return false; }
    if (pid != 0) return true; // parent: fork succeeded
    run_hashcat_child(hs, hash_path, result_path, wordlists, log_path);
    return true; // unreachable; child calls _exit()
}

#endif // HAVE_GPU_CRACK

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool builtin_cracker_available() {
#ifdef HAVE_OPENSSL
    return true;
#else
    return false;
#endif
}

bool hashcat_cracker_available() {
#ifdef HAVE_GPU_CRACK
    for (auto p : {"/usr/bin/hashcat", "/usr/local/bin/hashcat"}) {
        if (::access(p, X_OK) == 0) return true;
    }
    // Also check PATH via access on bare name (non-standard but common)
    return false;
#else
    return false;
#endif
}

bool launch_crack_job(CrackEngine engine,
                      const WpaHandshake& hs,
                      const std::string& pcap_path,
                      const std::vector<std::string>& wordlists,
                      const std::string& log_path) {
    if (wordlists.empty()) {
        std::fprintf(stderr, "[crack] ERROR: no wordlists specified\n");
        return false;
    }

#ifdef HAVE_GPU_CRACK
    if (engine == CrackEngine::Hashcat) {
        bool ok = run_hashcat(hs, wordlists, log_path);
        if (!ok) {
            std::fprintf(stderr, "[crack] hashcat launch failed — falling back to builtin/aircrack\n");
            // Fall through to CPU engines below
        } else {
            return true;
        }
    }
#endif

#ifdef HAVE_OPENSSL
    if (engine == CrackEngine::Builtin
#ifdef HAVE_GPU_CRACK
            || engine == CrackEngine::Hashcat  // fallback from failed hashcat
#endif
    ) {
        if (!hs.has_m1 || !hs.has_m2) {
            std::fprintf(stderr, "[crack] ERROR: handshake incomplete (m1=%d m2=%d) — "
                         "need both M1 and M2 for builtin engine\n", hs.has_m1, hs.has_m2);
            std::fprintf(stderr, "[crack] falling back to aircrack-ng\n");
            return run_aircrack(hs, pcap_path, wordlists, log_path);
        }
        if (hs.ssid.empty()) {
            std::fprintf(stderr, "[crack] WARNING: SSID unknown — "
                         "PBKDF2 requires SSID as salt, result may be incorrect\n");
        }
        if (hs.eapol_frame.size() < 97) {
            std::fprintf(stderr, "[crack] ERROR: EAPOL frame too short (%zu bytes) — "
                         "MIC verification not possible\n", hs.eapol_frame.size());
            return false;
        }
        return run_builtin(hs, wordlists, log_path);
    }
#else
    if (engine == CrackEngine::Builtin) {
        std::fprintf(stderr, "[crack] ERROR: builtin engine requires OpenSSL "
                     "(recompile with OpenSSL installed) — switching to aircrack\n");
    }
#endif

    return run_aircrack(hs, pcap_path, wordlists, log_path);
}
