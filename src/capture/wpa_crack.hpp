#pragma once
#include <cstdint>
#include <string>
#include <vector>

enum class CrackEngine {
    Builtin,   // built-in PBKDF2+PRF-512 implementation via OpenSSL
    Aircrack,  // external aircrack-ng subprocess
#ifdef HAVE_GPU_CRACK
    Hashcat,   // hashcat GPU/CPU subprocess (-m 22000, hc22000 format)
#endif
};

// WPA 4-way handshake parameters extracted from captured EAPOL frames.
// Populated incrementally: ap_mac/anonce from M1, client_mac/snonce/mic/eapol_frame from M2.
struct WpaHandshake {
    uint8_t ap_mac[6]{};
    uint8_t client_mac[6]{};
    std::string ssid;

    uint8_t anonce[32]{};        // Key Nonce from M1 (AP → Client)
    uint8_t snonce[32]{};        // Key Nonce from M2 (Client → AP)
    uint8_t mic[16]{};           // MIC from M2

    // M2 EAPOL frame body (starting at EAPOL version byte, MIC field zeroed).
    // Used as input for MIC re-computation.
    std::vector<uint8_t> eapol_frame;

    bool has_m1{false};
    bool has_m2{false};
    bool valid() const { return has_m1 && has_m2 && !ssid.empty(); }
};

// Extract handshake fields from a raw captured frame (includes radiotap header).
// msg_num: 1=M1, 2=M2 (only these two are needed for cracking).
// Returns true on success and updates 'hs'.
bool extract_eapol_fields(const uint8_t* raw_data, size_t raw_len,
                           uint8_t msg_num, WpaHandshake& hs);

// Launch a cracking job in the background (non-blocking).
// Writes aircrack-compatible output to log_path:
//   "KEY FOUND! [ password ]" on success
//   "KEY NOT FOUND." on exhaustion
// pcap_path is used only by the Aircrack engine.
// Returns true if a process was successfully forked, false if launch failed.
bool launch_crack_job(CrackEngine engine,
                      const WpaHandshake& hs,
                      const std::string& pcap_path,
                      const std::vector<std::string>& wordlists,
                      const std::string& log_path);

// Returns true if the builtin engine is available (compiled with OpenSSL).
bool builtin_cracker_available();

// Returns true if hashcat was found in PATH (runtime check).
// Always returns false when HAVE_GPU_CRACK is not defined.
bool hashcat_cracker_available();

// Returns short human-readable reason for a hashcat backend/runtime failure
// found in the given log. Empty string means no known backend error signature.
std::string hashcat_error_reason_from_log(const std::string& log_path);

// Verify a known password against a (possibly new) handshake.
// Returns true if the password still matches the handshake MIC.
// Used to detect password change: if false, the AP was re-keyed.
// Requires OpenSSL; always returns false if not compiled with HAVE_BUILTIN_CRACK.
bool verify_wpa_password(const std::string& password, const WpaHandshake& hs);
