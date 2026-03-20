#pragma once
#include "parser/types.hpp"
#include <functional>

// Abstract base for capture sources (pcap, pcapng file replay, etc.)
class CaptureSource {
public:
    virtual ~CaptureSource() = default;
    virtual bool open(const std::string& source, std::function<void(RawFrame)> cb) = 0;
    virtual void start() = 0; // blocking loop
    virtual void stop() = 0;
};
