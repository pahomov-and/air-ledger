#pragma once
#include "entity/graph.hpp"
#include "ui/filter_state.hpp"
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include <string>

class Sidebar {
public:
    bool init(SDL_Renderer* renderer, TTF_Font* font);
    void set_font(TTF_Font* font) { font_ = font; }
    void set_renderer(SDL_Renderer* r) { renderer_ = r; }
    void scroll_up()   { int s = step(); scroll_px_ = std::max(0, scroll_px_ - s); }
    void scroll_down() { int s = step(); scroll_px_ = std::min(max_scroll_, scroll_px_ + s); }
    void reset_scroll() { scroll_px_ = 0; }
    void cycle_scroll(bool backward) {
        int s = std::max(step() * 4, 40);
        if (backward) {
            if (scroll_px_ <= 0) scroll_px_ = max_scroll_;
            else scroll_px_ = std::max(0, scroll_px_ - s);
        } else {
            if (scroll_px_ >= max_scroll_) scroll_px_ = 0;
            else scroll_px_ = std::min(max_scroll_, scroll_px_ + s);
        }
    }
    void render(const Graph& graph, NodeId selected, int sidebar_x, int w, int h,
                const FilterState& filter, bool alias_mode,
                const std::string& alias_buf, NodeId alias_target,
                uint64_t total_frames, uint32_t beacons, uint32_t probe_reqs,
                bool hopping, int current_channel, int dwell_ms,
                bool search_mode, bool has_5ghz, int total_channels,
                bool ch_locked, int locked_ch);

private:
    SDL_Renderer* renderer_{nullptr};
    TTF_Font* font_{nullptr};
    int sidebar_x_{0};
    int w_{200};  // current sidebar width, set each render()
    int scroll_px_{0};
    int max_scroll_{0};

    int step() const { return font_ ? TTF_FontHeight(font_) + 2 : 16; }

    void draw_text(const std::string& text, int x, int& y,
                   SDL_Color color = {220, 220, 220, 255},
                   int continuation_indent = 2);
    void draw_separator(int x, int y, int w);

    void render_client(const Node& n, const Graph& graph, int x, int& y);
    void render_ssid(const Node& n, const Graph& graph, int x, int& y);
    void render_ap(const Node& n, const Graph& graph, int x, int& y);
    void render_empty(int x, int& y);

    std::string format_age(uint64_t ts_us, uint64_t now_us) const;
    static uint64_t now_us();
};
