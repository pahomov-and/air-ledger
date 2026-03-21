#include "ui/app.hpp"
#include "capture/handshake_saver.hpp"
#include "capture/wpa_crack.hpp"
#include "capture/deauth_sender.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

static void print_usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s <interface> [options]\n"
        "\n"
        "  interface              Wireless interface in monitor mode (e.g. wlan0, mon0)\n"
        "                         Or a pcap file path (*.pcap, *.pcapng) for offline analysis\n"
        "\n"
        "General options:\n"
        "  --db <path>            SQLite database path\n"
        "                         Default: air-ledger.db in the CURRENT DIRECTORY\n"
        "                         (i.e. wherever you run the binary from)\n"
        "                         Use an absolute path to pin the location, e.g.:\n"
        "                           --db /var/lib/air-ledger/session.db\n"
        "  -h, --help             Show this help\n"
        "\n"
        "Handshake capture options:\n"
        "  --capture-dir <dir>    Directory to store per-AP handshake captures\n"
        "                         Subdirectories are created automatically:\n"
        "                           <dir>/<ssid>_<bssid>/handshake.pcap\n"
        "                           <dir>/<ssid>_<bssid>/crack_<ts>.log\n"
        "  --wordlist <file>      Wordlist for WPA cracking (can be repeated).\n"
        "                         Requires --capture-dir. Cracker is launched\n"
        "                         automatically in the background when a complete\n"
        "                         WPA 4-way handshake is captured.\n"
        "  --passwords <file>     Append found passwords to this file\n"
        "                         Default: <capture-dir>/passwords.txt\n"
        "                         Format: BSSID<TAB>SSID<TAB>PASSWORD\n"
        "  --no-crack             Save handshakes but do not run any cracker\n"
        "  --cracker <engine>     Cracking engine:\n"
        "                           builtin  — OpenSSL PBKDF2+PRF-512 (CPU, default)\n"
        "                           aircrack — external aircrack-ng subprocess (CPU)\n"
#ifdef HAVE_GPU_CRACK
        "                           hashcat  — hashcat GPU/CPU subprocess (-m 22000)\n"
        "                                      Uses AMD/NVIDIA/Intel GPU when available,\n"
        "                                      falls back to CPU automatically.\n"
        "                                      Requires hashcat in PATH.\n"
        "  --hashcat-bin <path>    Path to hashcat binary (overrides PATH lookup)\n"
        "                         Example: --hashcat-bin /tmp/hashcat-7.1.2/hashcat.bin\n"
#else
        "                           (hashcat disabled at build time; reconfigure with -DENABLE_GPU_CRACK=ON)\n"
#endif
        "  --aircrack-bin <path>   Path to aircrack-ng binary\n"
        "  --aireplay-bin <path>   Path to aireplay-ng binary\n"
        "  --iw-bin <path>         Path to iw binary (hopper/reset iface)\n"
        "  --deauth-engine <e>    Deauth engine: builtin (default) or aireplay\n"
        "                           builtin  — pcap_inject(), no external tools\n"
        "                           aireplay — external aireplay-ng subprocess\n"
        "  --ui-profile <p>       UI tuning profile: auto (default), beepy, beepy-window\n"
        "\n"
        "Controls:\n"
        "  Left click             Select node\n"
        "  Scroll / z / x         Zoom in/out\n"
        "  Arrow keys             Pan view\n"
        "  F11                    Toggle fullscreen (auto profile only)\n"
        "  Middle drag            Pan view with mouse\n"
        "  h                      Toggle channel hopping\n"
        "  +/-                    Dwell time ±100ms\n"
        "  Tab / Shift+Tab        Cycle selected node\n"
        "  Ctrl+Tab / Ctrl+Shift+Tab  Circular sidebar scroll\n"
        "  a                      Set alias for selected node\n"
        "  d                      Send deauth to selected AP\n"
        "  t                      Toggle auto-crack for new handshakes\n"
        "  g                      Aggressive mode (cyclic deauth+harvest)\n"
        "  f / r                  Filter active / random-MAC nodes\n"
        "  p                      AP list overlay\n"
        "  k                      Crack queue overlay\n"
        "  j                      Handshake list\n"
        "  w                      Anomaly log\n"
        "  y                      Event log\n"
        "  /                      Search by MAC / SSID / vendor\n"
        "  e                      Export JSON\n"
        "  Ctrl+R                 Reset WiFi interface (if card hangs)\n"
        "  i                      In-app help\n"
        "  Q / Escape             Quit\n"
        "\n",
        prog);
}

int main(int argc, char* argv[]) {
    std::string iface;
    std::string db_path = "air-ledger.db";

    HandshakeConfig hs_cfg;
    hs_cfg.auto_crack = true;
    DeauthEngine deauth_engine = DeauthEngine::Builtin;
    UiProfile ui_profile = UiProfile::Auto;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--db") {
            if (++i >= argc) { std::fprintf(stderr, "--db requires an argument\n"); return 1; }
            db_path = argv[i];
        } else if (arg == "--capture-dir") {
            if (++i >= argc) { std::fprintf(stderr, "--capture-dir requires an argument\n"); return 1; }
            hs_cfg.capture_dir = argv[i];
        } else if (arg == "--wordlist") {
            if (++i >= argc) { std::fprintf(stderr, "--wordlist requires an argument\n"); return 1; }
            hs_cfg.wordlists.push_back(argv[i]);
        } else if (arg == "--passwords") {
            if (++i >= argc) { std::fprintf(stderr, "--passwords requires an argument\n"); return 1; }
            hs_cfg.passwords_file = argv[i];
        } else if (arg == "--no-crack") {
            hs_cfg.auto_crack = false;
        } else if (arg == "--cracker") {
            if (++i >= argc) { std::fprintf(stderr, "--cracker requires an argument\n"); return 1; }
            std::string eng = argv[i];
            if (eng == "aircrack") {
                hs_cfg.crack_engine = CrackEngine::Aircrack;
            } else if (eng == "builtin") {
                hs_cfg.crack_engine = CrackEngine::Builtin;
#ifdef HAVE_GPU_CRACK
            } else if (eng == "hashcat") {
                hs_cfg.crack_engine = CrackEngine::Hashcat;
#endif
            } else {
                std::fprintf(stderr,
                    "Unknown cracker engine '%s'. Use: builtin, aircrack"
#ifdef HAVE_GPU_CRACK
                    ", hashcat"
#endif
                    "\n", eng.c_str());
                return 1;
            }
#ifdef HAVE_GPU_CRACK
        } else if (arg == "--hashcat-bin") {
            if (++i >= argc) { std::fprintf(stderr, "--hashcat-bin requires an argument\n"); return 1; }
            if (::setenv("AIR_LEDGER_HASHCAT_BIN", argv[i], 1) != 0) {
                std::fprintf(stderr, "Failed to set AIR_LEDGER_HASHCAT_BIN to '%s'\n", argv[i]);
                return 1;
            }
#endif
        } else if (arg == "--aircrack-bin") {
            if (++i >= argc) { std::fprintf(stderr, "--aircrack-bin requires an argument\n"); return 1; }
            if (::setenv("AIR_LEDGER_AIRCRACK_BIN", argv[i], 1) != 0) {
                std::fprintf(stderr, "Failed to set AIR_LEDGER_AIRCRACK_BIN to '%s'\n", argv[i]);
                return 1;
            }
        } else if (arg == "--aireplay-bin") {
            if (++i >= argc) { std::fprintf(stderr, "--aireplay-bin requires an argument\n"); return 1; }
            if (::setenv("AIR_LEDGER_AIREPLAY_BIN", argv[i], 1) != 0) {
                std::fprintf(stderr, "Failed to set AIR_LEDGER_AIREPLAY_BIN to '%s'\n", argv[i]);
                return 1;
            }
        } else if (arg == "--iw-bin") {
            if (++i >= argc) { std::fprintf(stderr, "--iw-bin requires an argument\n"); return 1; }
            if (::setenv("AIR_LEDGER_IW_BIN", argv[i], 1) != 0) {
                std::fprintf(stderr, "Failed to set AIR_LEDGER_IW_BIN to '%s'\n", argv[i]);
                return 1;
            }
        } else if (arg == "--deauth-engine") {
            if (++i >= argc) { std::fprintf(stderr, "--deauth-engine requires an argument\n"); return 1; }
            std::string eng = argv[i];
            if (eng == "aireplay") {
                deauth_engine = DeauthEngine::Aireplay;
            } else if (eng == "builtin") {
                deauth_engine = DeauthEngine::Builtin;
            } else {
                std::fprintf(stderr, "Unknown deauth engine '%s'. Use: builtin, aireplay\n", eng.c_str());
                return 1;
            }
        } else if (arg == "--ui-profile") {
            if (++i >= argc) { std::fprintf(stderr, "--ui-profile requires an argument\n"); return 1; }
            std::string p = argv[i];
            if (p == "auto") ui_profile = UiProfile::Auto;
            else if (p == "beepy") ui_profile = UiProfile::Beepy;
            else if (p == "beepy-window") ui_profile = UiProfile::BeepyWindow;
            else {
                std::fprintf(stderr, "Unknown ui profile '%s'. Use: auto, beepy, beepy-window\n", p.c_str());
                return 1;
            }
        } else if (arg[0] != '-') {
            if (iface.empty())
                iface = arg;
            else {
                // Legacy positional: second positional arg = db_path
                db_path = arg;
            }
        } else {
            std::fprintf(stderr, "Unknown option: %s\n", arg.c_str());
            print_usage(argv[0]);
            return 1;
        }
    }

    if (iface.empty()) {
        std::fprintf(stderr, "Error: no interface specified.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    if (ui_profile == UiProfile::Beepy || ui_profile == UiProfile::BeepyWindow) {
        ::setenv("AIR_LEDGER_UI_PROFILE", "beepy", 1);
    } else {
        ::setenv("AIR_LEDGER_UI_PROFILE", "auto", 1);
    }

    // Default passwords file: <capture-dir>/passwords.txt
    if (!hs_cfg.capture_dir.empty() && hs_cfg.passwords_file.empty())
        hs_cfg.passwords_file = hs_cfg.capture_dir + "/passwords.txt";

    // Validate: --wordlist without --capture-dir is pointless
    if (!hs_cfg.wordlists.empty() && hs_cfg.capture_dir.empty()) {
        std::fprintf(stderr,
            "Warning: --wordlist has no effect without --capture-dir. "
            "Ignoring wordlists.\n");
        hs_cfg.wordlists.clear();
    }

    std::fprintf(stderr, "[air-ledger] Interface: %s  DB: %s\n",
                 iface.c_str(), db_path.c_str());

    if (!hs_cfg.capture_dir.empty()) {
        std::fprintf(stderr, "[air-ledger] Handshake capture: %s  wordlists=%zu  auto-crack=%s\n",
                     hs_cfg.capture_dir.c_str(),
                     hs_cfg.wordlists.size(),
                     hs_cfg.auto_crack ? "yes" : "no");
        for (auto& w : hs_cfg.wordlists)
            std::fprintf(stderr, "[air-ledger]   wordlist: %s\n", w.c_str());
        if (!hs_cfg.passwords_file.empty())
            std::fprintf(stderr, "[air-ledger]   passwords: %s\n", hs_cfg.passwords_file.c_str());
    }

    App app;
    app.set_deauth_engine(deauth_engine);
    app.set_ui_profile(ui_profile);
    if (!app.init(iface, db_path)) {
        std::fprintf(stderr, "[air-ledger] Initialization failed.\n");
        return 1;
    }

    if (!hs_cfg.capture_dir.empty())
        app.init_handshake(hs_cfg);

    app.run();
    return 0;
}
