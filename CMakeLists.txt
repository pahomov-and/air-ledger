cmake_minimum_required(VERSION 3.20)
project(air-ledger LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(SDL2 REQUIRED sdl2)
pkg_check_modules(SDL2_TTF REQUIRED SDL2_ttf)

# Optional SDL2_gfx - we implement our own circle drawing if absent
pkg_check_modules(SDL2_GFX SDL2_gfx)

# ── GPU cracking via hashcat ─────────────────────────────────────────────────
# Enabled by default on x86/x86_64; disabled automatically when cross-compiling
# for ARM (RPi). Override with -DENABLE_GPU_CRACK=ON/OFF.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm|aarch64|armv[0-9])")
    set(_GPU_CRACK_DEFAULT OFF)
else()
    set(_GPU_CRACK_DEFAULT ON)
endif()
# Also honour cross-toolchain ARM target files
if(CMAKE_CROSSCOMPILING AND (CMAKE_SYSTEM_PROCESSOR MATCHES "arm|aarch64"
        OR (DEFINED CMAKE_TOOLCHAIN_FILE AND CMAKE_TOOLCHAIN_FILE MATCHES "arm")))
    set(_GPU_CRACK_DEFAULT OFF)
endif()
option(ENABLE_GPU_CRACK "GPU cracking via hashcat (auto-disabled on ARM)" ${_GPU_CRACK_DEFAULT})

if(ENABLE_GPU_CRACK)
    message(STATUS "GPU cracking: ENABLED  (hashcat subprocess, -m 22000)")
    # hashcat is found/used at runtime; no compile-time library needed.
else()
    message(STATUS "GPU cracking: DISABLED  (ARM/RPi build)")
endif()

# SQLite3
find_package(SQLite3 QUIET)
if(NOT SQLite3_FOUND)
    message(STATUS "System SQLite3 not found, looking for bundled sqlite3.c")
    if(EXISTS "${CMAKE_SOURCE_DIR}/sqlite3.c")
        add_library(sqlite3_bundled STATIC sqlite3.c)
        target_compile_definitions(sqlite3_bundled PUBLIC SQLITE_THREADSAFE=1)
        set(SQLITE3_LIBRARIES sqlite3_bundled)
        set(SQLITE3_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}")
    else()
        message(FATAL_ERROR "SQLite3 not found and no bundled sqlite3.c present. "
            "Install libsqlite3-dev or place sqlite3.c in the project root.")
    endif()
else()
    set(SQLITE3_LIBRARIES SQLite::SQLite3)
    set(SQLITE3_INCLUDE_DIRS "")
endif()

set(SOURCES
    src/main.cpp
    src/capture/pcap_source.cpp
    src/capture/channel_hopper.cpp
    src/capture/handshake_saver.cpp
    src/capture/wpa_crack.cpp
    src/capture/deauth_sender.cpp
    src/parser/radiotap.cpp
    src/parser/dot11.cpp
    src/entity/graph.cpp
    src/entity/oui.cpp
    src/analytics/relation_builder.cpp
    src/analytics/similarity.cpp
    src/analytics/anomaly_detector.cpp
    src/db/db.cpp
    src/ui/app.cpp
    src/ui/graph_view.cpp
    src/ui/layout.cpp
    src/ui/sidebar.cpp
)

add_executable(air-ledger ${SOURCES})

target_include_directories(air-ledger PRIVATE
    src
    ${PCAP_INCLUDE_DIRS}
    ${SDL2_INCLUDE_DIRS}
    ${SDL2_TTF_INCLUDE_DIRS}
    ${SQLITE3_INCLUDE_DIRS}
)

if(SDL2_GFX_FOUND)
    target_include_directories(air-ledger PRIVATE ${SDL2_GFX_INCLUDE_DIRS})
    target_compile_definitions(air-ledger PRIVATE HAVE_SDL2_GFX=1)
    target_link_libraries(air-ledger PRIVATE ${SDL2_GFX_LIBRARIES})
endif()

target_link_libraries(air-ledger PRIVATE
    ${PCAP_LIBRARIES}
    ${SDL2_LIBRARIES}
    ${SDL2_TTF_LIBRARIES}
    ${SQLITE3_LIBRARIES}
)

# OpenSSL — optional, needed for built-in WPA cracker
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    message(STATUS "OpenSSL found: builtin WPA cracker enabled")
    target_compile_definitions(air-ledger PRIVATE HAVE_OPENSSL=1)
    target_link_libraries(air-ledger PRIVATE OpenSSL::Crypto)
else()
    message(STATUS "OpenSSL not found: builtin WPA cracker disabled, using aircrack-ng fallback")
endif()

target_compile_options(air-ledger PRIVATE -O2 -Wall -Wextra -Wpedantic)

if(ENABLE_GPU_CRACK)
    target_compile_definitions(air-ledger PRIVATE HAVE_GPU_CRACK=1)
endif()

# ── ARM: hardware SHA1/SHA256 crypto extensions ──────────────────────────────
# Cortex-A53 (RPi Zero 2W) supports armv8-a+crypto — gives ~10x speedup to
# the builtin PBKDF2 cracker when OpenSSL uses the SHA1 hardware instruction.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm|aarch64|armv[0-9])" OR
   (CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm|aarch64"))
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-march=armv8-a+crypto" COMPILER_SUPPORTS_ARM_CRYPTO)
    if(COMPILER_SUPPORTS_ARM_CRYPTO)
        target_compile_options(air-ledger PRIVATE -march=armv8-a+crypto)
        target_compile_definitions(air-ledger PRIVATE HAVE_ARM_CRYPTO=1)
        message(STATUS "ARM crypto extensions: ENABLED  (-march=armv8-a+crypto)")
    else()
        message(STATUS "ARM crypto extensions: not supported by compiler")
    endif()
endif()

# Link pthreads for std::jthread / std::thread
find_package(Threads REQUIRED)
target_link_libraries(air-ledger PRIVATE Threads::Threads)

install(TARGETS air-ledger RUNTIME DESTINATION bin)
